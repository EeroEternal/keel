use crate::error::{PolicyError, PolicyResult};
use crate::ids::{PolicyId, TaskId};
use crate::net::NetworkPolicy;
use crate::paths::{FsAccess, FsRule};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Whether the agent may spawn subprocesses / shells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecPolicy {
    /// No subprocess execution.
    Deny,
    /// Subprocesses allowed subject to FS/network policy (default).
    #[default]
    Allow,
}

/// Just-in-time credential handle (opaque to the agent; injected by Keel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGrant {
    pub name: String,
    /// Where the secret is sourced from (env name, vault path, etc.). Never the secret itself.
    pub source: String,
    /// Env var name presented inside the space, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_as_env: Option<String>,
}

/// Bound execution policy. Immutable after space creation (v0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    /// Optional task this policy was issued for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    /// Human label (e.g. profile name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// If true, paths not listed in `fs` are readable (write still needs an explicit rule).
    #[serde(default)]
    pub default_read: bool,
    /// Filesystem rules. Deny wins over allow when backends support it.
    #[serde(default)]
    pub fs: Vec<FsRule>,
    pub network: NetworkPolicy,
    #[serde(default)]
    pub exec: ExecPolicy,
    #[serde(default)]
    pub credentials: Vec<CredentialGrant>,
    pub created_at: DateTime<Utc>,
    /// Absolute deadline after which the space should refuse new work and revoke creds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Workspace root the policy is anchored to (usually agent cwd).
    pub workspace: PathBuf,
}

impl Policy {
    pub fn builder(workspace: impl Into<PathBuf>) -> PolicyBuilder {
        PolicyBuilder::new(workspace)
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }

    pub fn read_write_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.fs
            .iter()
            .filter(|r| r.access == FsAccess::ReadWrite && !r.glob)
            .map(|r| &r.path)
    }

    pub fn read_only_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.fs
            .iter()
            .filter(|r| r.access == FsAccess::Read && !r.glob)
            .map(|r| &r.path)
    }

    pub fn deny_paths(&self) -> impl Iterator<Item = &FsRule> {
        self.fs.iter().filter(|r| r.access == FsAccess::Deny)
    }

    pub fn to_toml(&self) -> PolicyResult<String> {
        toml::to_string_pretty(self).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    pub fn from_toml(s: &str) -> PolicyResult<Self> {
        toml::from_str(s).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    pub fn to_json(&self) -> PolicyResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    pub fn from_json(s: &str) -> PolicyResult<Self> {
        serde_json::from_str(s).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    /// Validate structural constraints (not OS capability).
    pub fn validate(&self) -> PolicyResult<()> {
        if self.workspace.as_os_str().is_empty() {
            return Err(PolicyError::Invalid("workspace path is empty".into()));
        }
        if let NetworkPolicy::Allowlist(rules) = &self.network {
            if rules.is_empty() {
                return Err(PolicyError::Invalid(
                    "network allowlist must not be empty (use DenyAll or Unrestricted)".into(),
                ));
            }
            for r in rules {
                if r.host.trim().is_empty() {
                    return Err(PolicyError::Invalid(
                        "network rule host must not be empty".into(),
                    ));
                }
            }
        }
        for c in &self.credentials {
            if c.name.trim().is_empty() || c.source.trim().is_empty() {
                return Err(PolicyError::Invalid(
                    "credential grant name/source must not be empty".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PolicyBuilder {
    id: PolicyId,
    task_id: Option<TaskId>,
    label: Option<String>,
    default_read: bool,
    fs: Vec<FsRule>,
    network: NetworkPolicy,
    exec: ExecPolicy,
    credentials: Vec<CredentialGrant>,
    expires_at: Option<DateTime<Utc>>,
    workspace: PathBuf,
}

impl PolicyBuilder {
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        Self {
            id: PolicyId::new(),
            task_id: None,
            label: None,
            default_read: false,
            fs: Vec::new(),
            network: NetworkPolicy::Unrestricted,
            exec: ExecPolicy::Allow,
            credentials: Vec::new(),
            expires_at: None,
            workspace: workspace.into(),
        }
    }

    pub fn id(mut self, id: PolicyId) -> Self {
        self.id = id;
        self
    }

    pub fn task_id(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn default_read(mut self, yes: bool) -> Self {
        self.default_read = yes;
        self
    }

    pub fn fs_rule(mut self, rule: FsRule) -> Self {
        self.fs.push(rule);
        self
    }

    pub fn read_write(self, path: impl Into<PathBuf>) -> Self {
        self.fs_rule(FsRule::read_write(path))
    }

    pub fn read_only(self, path: impl Into<PathBuf>) -> Self {
        self.fs_rule(FsRule::read(path))
    }

    pub fn deny(self, path: impl Into<PathBuf>) -> Self {
        self.fs_rule(FsRule::deny(path))
    }

    pub fn deny_glob(self, pattern: impl Into<PathBuf>) -> Self {
        self.fs_rule(FsRule::deny_glob(pattern))
    }

    pub fn network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    pub fn exec(mut self, exec: ExecPolicy) -> Self {
        self.exec = exec;
        self
    }

    pub fn credential(mut self, grant: CredentialGrant) -> Self {
        self.credentials.push(grant);
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.expires_at = Some(Utc::now() + ttl);
        self
    }

    pub fn expires_at(mut self, at: DateTime<Utc>) -> Self {
        self.expires_at = Some(at);
        self
    }

    pub fn build(self) -> PolicyResult<Policy> {
        let policy = Policy {
            id: self.id,
            task_id: self.task_id,
            label: self.label,
            default_read: self.default_read,
            fs: self.fs,
            network: self.network,
            exec: self.exec,
            credentials: self.credentials,
            created_at: Utc::now(),
            expires_at: self.expires_at,
            workspace: self.workspace,
        };
        policy.validate()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetworkRule;
    use std::path::Path;

    #[test]
    fn workspace_profile_roundtrip_json() {
        let p = Policy::builder("/tmp/proj")
            .label("workspace")
            .default_read(true)
            .read_write("/tmp/proj")
            .read_write("/tmp")
            .network(NetworkPolicy::Unrestricted)
            .build()
            .unwrap();
        let s = p.to_json().unwrap();
        let p2 = Policy::from_json(&s).unwrap();
        assert_eq!(p.id.as_str(), p2.id.as_str());
        assert!(p2.default_read);
        assert_eq!(p2.workspace, Path::new("/tmp/proj"));
    }

    #[test]
    fn empty_allowlist_rejected() {
        let err = Policy::builder("/ws")
            .network(NetworkPolicy::Allowlist(vec![]))
            .build()
            .unwrap_err();
        assert!(matches!(err, PolicyError::Invalid(_)));
    }

    #[test]
    fn allowlist_ok() {
        let p = Policy::builder("/ws")
            .network(NetworkPolicy::Allowlist(vec![NetworkRule::host_port(
                "api.x.ai",
                443,
            )]))
            .build()
            .unwrap();
        assert!(matches!(p.network, NetworkPolicy::Allowlist(ref r) if r.len() == 1));
    }
}
