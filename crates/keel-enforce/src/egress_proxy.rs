//! Localhost HTTP CONNECT proxy that enforces an egress allowlist.
//!
//! Child processes are steered here via `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
//! and (when kernel net isolation is available) can only dial `localhost:port`.

use crate::error::{EnforceError, EnforceResult};
use keel_policy::{check_egress, EgressDecision, NetworkPolicy};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, warn};

/// Env var: proxy port written for child pre_exec / kernel ProxyOnly mode.
pub const EGRESS_PROXY_PORT_ENV: &str = "KEEL_EGRESS_PROXY_PORT";

/// Running egress proxy bound to 127.0.0.1.
pub struct EgressProxy {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    join: tokio::task::JoinHandle<()>,
}

impl EgressProxy {
    /// Bind and serve until dropped / [`Self::shutdown`].
    pub async fn start(network: NetworkPolicy) -> EnforceResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| EnforceError::ApplyFailed(format!("bind egress proxy: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| EnforceError::ApplyFailed(format!("proxy local_addr: {e}")))?;
        let shutdown = Arc::new(Notify::new());
        let shutdown_bg = shutdown.clone();
        let network = Arc::new(network);

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_bg.notified() => break,
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                let network = network.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(stream, &network).await {
                                        debug!(?peer, error = %e, "egress proxy client error");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "egress proxy accept failed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            join,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port())
    }

    /// Environment variables so proxy-aware tools use this proxy.
    pub fn env_vars(&self) -> Vec<(String, String)> {
        let url = self.proxy_url();
        vec![
            ("HTTP_PROXY".into(), url.clone()),
            ("HTTPS_PROXY".into(), url.clone()),
            ("ALL_PROXY".into(), url.clone()),
            ("http_proxy".into(), url.clone()),
            ("https_proxy".into(), url.clone()),
            ("all_proxy".into(), url.clone()),
            ("NO_PROXY".into(), String::new()),
            ("no_proxy".into(), String::new()),
            (EGRESS_PROXY_PORT_ENV.into(), self.port().to_string()),
        ]
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        self.join.abort();
    }
}

async fn handle_client(mut client: TcpStream, network: &NetworkPolicy) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut client);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if request_line.is_empty() {
        return Ok(());
    }

    // Drain headers until blank line.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_http_error(&mut client, 400, "Bad Request").await?;
        return Ok(());
    }
    let method = parts[0].to_ascii_uppercase();
    let target = parts[1];

    let (host, port) = if method == "CONNECT" {
        parse_host_port(target, 443)
    } else if let Some(hp) = parse_absolute_http_uri(target) {
        hp
    } else {
        write_http_error(&mut client, 400, "Absolute URI or CONNECT required").await?;
        return Ok(());
    };

    let decision = check_egress(network, &host, port);
    if !decision.is_allowed() {
        let reason = match &decision {
            EgressDecision::Deny { reason } => reason.as_str(),
            EgressDecision::Allow => "denied",
        };
        debug!(%host, port, %reason, "egress proxy denied");
        write_http_error(&mut client, 403, reason).await?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            write_http_error(&mut client, 502, &format!("Bad Gateway: {e}")).await?;
            return Ok(());
        }
    };

    if method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    } else {
        // Minimal absolute-URI → origin-form replay (headers already consumed).
        let path = absolute_uri_path(target);
        let intro = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        upstream.write_all(intro.as_bytes()).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    }

    Ok(())
}

async fn write_http_error(stream: &mut TcpStream, code: u16, msg: &str) -> std::io::Result<()> {
    let body = format!("{msg}\n");
    let resp = format!(
        "HTTP/1.1 {code} Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await
}

fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = target.rsplit_once(':') {
        // Avoid splitting IPv6 without brackets incorrectly: require numeric port.
        if let Ok(port) = p.parse::<u16>() {
            let host = h.trim_matches(|c| c == '[' || c == ']').to_string();
            return (host, port);
        }
    }
    (target.to_string(), default_port)
}

fn parse_absolute_http_uri(uri: &str) -> Option<(String, u16)> {
    let (rest, default_port) = if let Some(r) = uri.strip_prefix("https://") {
        (r, 443u16)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (r, 80u16)
    } else {
        return None;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    Some(parse_host_port(authority, default_port))
}

fn absolute_uri_path(uri: &str) -> String {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri);
    if let Some(idx) = rest.find('/') {
        rest[idx..].to_string()
    } else {
        "/".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::NetworkRule;

    #[tokio::test]
    async fn proxy_binds() {
        let policy = NetworkPolicy::Allowlist(vec![NetworkRule::host_port("example.com", 80)]);
        let proxy = EgressProxy::start(policy).await.unwrap();
        assert!(proxy.port() > 0);
        proxy.shutdown();
    }

    #[tokio::test]
    async fn connect_denied_for_metadata() {
        use tokio::io::AsyncReadExt;
        let policy = NetworkPolicy::Unrestricted;
        let proxy = EgressProxy::start(policy).await.unwrap();
        let mut stream = TcpStream::connect(proxy.addr()).await.unwrap();
        stream
            .write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("403"), "resp={resp}");
        proxy.shutdown();
    }
}
