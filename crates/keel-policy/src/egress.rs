//! Egress allowlist evaluation (host/port).
//!
//! This is the pure policy check used by enforce backends and proxies.
//! Cloud metadata / link-local destinations are always denied.

use crate::net::{NetworkPolicy, NetworkRule};
use std::net::IpAddr;

/// Hard-denied hostnames (cloud instance metadata etc.).
const DENY_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
];

/// Result of an egress decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny {
        reason: String,
    },
}

impl EgressDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Evaluate whether a dial to `host:port` is permitted.
///
/// `host` may be a hostname or IP string (no brackets). Port is required for
/// matching rules that specify a port; if a rule has `port: None`, any port
/// on that host is allowed (subject to metadata denials).
pub fn check_egress(policy: &NetworkPolicy, host: &str, port: u16) -> EgressDecision {
    let host = normalize_host(host);

    if host.is_empty() {
        return EgressDecision::Deny {
            reason: "empty host".into(),
        };
    }

    // Hard denials first.
    if is_denied_metadata_host(&host) {
        return EgressDecision::Deny {
            reason: format!("host {host} is a cloud metadata endpoint"),
        };
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_link_local(&ip) {
            return EgressDecision::Deny {
                reason: format!("IP {ip} is link-local (metadata / rebinding protection)"),
            };
        }
    }

    match policy {
        NetworkPolicy::Unrestricted => EgressDecision::Allow,
        NetworkPolicy::DenyAll => EgressDecision::Deny {
            reason: "network policy is deny-all".into(),
        },
        NetworkPolicy::Allowlist(rules) => {
            if rules.is_empty() {
                return EgressDecision::Deny {
                    reason: "empty allowlist".into(),
                };
            }
            if rules.iter().any(|r| rule_matches(r, &host, port)) {
                EgressDecision::Allow
            } else {
                EgressDecision::Deny {
                    reason: format!("host {host}:{port} is not in the egress allowlist"),
                }
            }
        }
    }
}

fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_matches(|c| c == '[' || c == ']');
    // Strip trailing dot from FQDN.
    let h = h.trim_end_matches('.');
    h.to_ascii_lowercase()
}

fn is_denied_metadata_host(host: &str) -> bool {
    DENY_HOSTS.iter().any(|d| host == *d)
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // fe80::/10
            (segs[0] & 0xffc0) == 0xfe80
                // IPv4-mapped 169.254.x.x
                || (v6.to_ipv4_mapped().is_some_and(|v4| {
                    v4.octets()[0] == 169 && v4.octets()[1] == 254
                }))
        }
    }
}

fn rule_matches(rule: &NetworkRule, host: &str, port: u16) -> bool {
    if let Some(rp) = rule.port {
        if rp != port {
            return false;
        }
    }
    host_matches(&rule.host, host)
}

/// Match host against a rule pattern.
///
/// - `*` matches any host
/// - `*.example.com` matches one or more subdomain labels under example.com
/// - exact match otherwise (case-insensitive; already normalized)
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // *.example.com matches a.example.com and a.b.example.com, not example.com
        if host == suffix {
            return false;
        }
        host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

/// Collect distinct ports mentioned in an allowlist (for diagnostics).
pub fn allowlist_ports(rules: &[NetworkRule]) -> Vec<u16> {
    let mut ports: Vec<u16> = rules.iter().filter_map(|r| r.port).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetworkRule;

    #[test]
    fn unrestricted_allows() {
        assert!(check_egress(&NetworkPolicy::Unrestricted, "example.com", 443).is_allowed());
    }

    #[test]
    fn deny_all_blocks() {
        assert!(!check_egress(&NetworkPolicy::DenyAll, "example.com", 443).is_allowed());
    }

    #[test]
    fn allowlist_exact() {
        let p = NetworkPolicy::Allowlist(vec![NetworkRule::host_port("api.x.ai", 443)]);
        assert!(check_egress(&p, "api.x.ai", 443).is_allowed());
        assert!(!check_egress(&p, "api.x.ai", 80).is_allowed());
        assert!(!check_egress(&p, "evil.com", 443).is_allowed());
    }

    #[test]
    fn allowlist_any_port() {
        let p = NetworkPolicy::Allowlist(vec![NetworkRule::host("api.x.ai")]);
        assert!(check_egress(&p, "api.x.ai", 443).is_allowed());
        assert!(check_egress(&p, "api.x.ai", 80).is_allowed());
    }

    #[test]
    fn wildcard_subdomain() {
        let p = NetworkPolicy::Allowlist(vec![NetworkRule::host("*.github.com")]);
        assert!(check_egress(&p, "api.github.com", 443).is_allowed());
        assert!(!check_egress(&p, "raw.githubusercontent.com", 443).is_allowed());
        assert!(!check_egress(&p, "github.com", 443).is_allowed());
    }

    #[test]
    fn metadata_always_denied() {
        let p = NetworkPolicy::Unrestricted;
        assert!(!check_egress(&p, "169.254.169.254", 80).is_allowed());
        assert!(!check_egress(&p, "metadata.google.internal", 80).is_allowed());
    }

    #[test]
    fn star_allows_any_non_metadata() {
        let p = NetworkPolicy::Allowlist(vec![NetworkRule::host("*")]);
        assert!(check_egress(&p, "example.com", 443).is_allowed());
        assert!(!check_egress(&p, "169.254.169.254", 80).is_allowed());
    }
}
