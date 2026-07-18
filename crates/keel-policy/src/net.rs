use serde::{Deserialize, Serialize};

/// Network reach for the execution space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No restriction at the Keel boundary (agent host may still apply its own limits).
    Unrestricted,
    /// Block all outbound network for child processes (where the backend supports it).
    DenyAll,
    /// Allow only listed destinations (host:port or host).
    Allowlist(Vec<NetworkRule>),
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::Unrestricted
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Hostname, IP, or `*` for any host (only meaningful inside an allowlist of other rules).
    pub host: String,
    /// Optional port. `None` means any port on that host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl NetworkRule {
    pub fn host(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
        }
    }

    pub fn host_port(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port: Some(port),
        }
    }
}
