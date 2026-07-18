//! Per-task policy narrowing: a child policy may only *reduce* reach.

use crate::error::{PolicyError, PolicyResult};
use crate::ids::TaskId;
use crate::net::{NetworkPolicy, NetworkRule};
use crate::paths::FsRule;
use crate::policy::Policy;
use chrono::{Duration, Utc};
use std::collections::HashSet;
use std::path::PathBuf;

/// Requested changes when forking a space for a subtask.
///
/// All fields are optional tightenings. Anything that would expand reach
/// relative to `parent` is rejected.
#[derive(Debug, Clone, Default)]
pub struct TaskSpec {
    pub task_id: TaskId,
    pub label: Option<String>,
    /// Optional network override (must be ⊆ parent).
    pub network: Option<NetworkPolicy>,
    /// Extra deny paths (always allowed — denies only shrink reach).
    pub extra_deny: Vec<PathBuf>,
    /// Optional credential subset (by name). `None` = inherit all; `Some(vec![])` = none.
    pub credential_names: Option<Vec<String>>,
    /// Optional shorter TTL from now.
    pub ttl: Option<Duration>,
    /// If set, replace workspace root (must be under parent workspace or equal).
    pub workspace: Option<PathBuf>,
}

/// Build a child policy from `parent` + `spec`. Fails if the child would expand reach.
pub fn narrow_policy(parent: &Policy, spec: TaskSpec) -> PolicyResult<Policy> {
    let mut child = parent.clone();
    child.id = crate::ids::PolicyId::new();
    child.task_id = Some(spec.task_id);
    child.created_at = Utc::now();
    if let Some(label) = spec.label {
        child.label = Some(label);
    }

    if let Some(ws) = spec.workspace {
        ensure_workspace_under_parent(&parent.workspace, &ws)?;
        child.workspace = ws;
    }

    if let Some(net) = spec.network {
        ensure_network_subseteq(&parent.network, &net)?;
        child.network = net;
    }

    for path in spec.extra_deny {
        child.fs.push(FsRule::deny(path));
    }

    if let Some(names) = spec.credential_names {
        let allowed: HashSet<&str> = parent
            .credentials
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        let mut next = Vec::new();
        for name in names {
            if !allowed.contains(name.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "credential '{name}' is not granted by the parent policy"
                )));
            }
            if let Some(g) = parent.credentials.iter().find(|c| c.name == name) {
                next.push(g.clone());
            }
        }
        child.credentials = next;
    }

    if let Some(ttl) = spec.ttl {
        let expires = Utc::now() + ttl;
        match parent.expires_at {
            Some(parent_exp) if expires > parent_exp => {
                return Err(PolicyError::Invalid(
                    "child TTL cannot expire after the parent policy".into(),
                ));
            }
            _ => child.expires_at = Some(expires),
        }
    }

    // Child cannot flip default_read off→on or expand exec.
    if child.default_read && !parent.default_read {
        return Err(PolicyError::Invalid(
            "child cannot enable default_read when parent has it disabled".into(),
        ));
    }

    child.validate()?;
    Ok(child)
}

fn ensure_workspace_under_parent(parent: &PathBuf, child: &PathBuf) -> PolicyResult<()> {
    if child == parent {
        return Ok(());
    }
    // Best-effort prefix check (canonicalization is caller's job when possible).
    if child.starts_with(parent) {
        return Ok(());
    }
    Err(PolicyError::Invalid(format!(
        "child workspace {} is not under parent workspace {}",
        child.display(),
        parent.display()
    )))
}

fn ensure_network_subseteq(parent: &NetworkPolicy, child: &NetworkPolicy) -> PolicyResult<()> {
    match (parent, child) {
        (NetworkPolicy::Unrestricted, _) => Ok(()),
        (NetworkPolicy::DenyAll, NetworkPolicy::DenyAll) => Ok(()),
        (NetworkPolicy::DenyAll, _) => Err(PolicyError::Invalid(
            "child cannot expand network beyond parent DenyAll".into(),
        )),
        (NetworkPolicy::Allowlist(_), NetworkPolicy::DenyAll) => Ok(()),
        (NetworkPolicy::Allowlist(p_rules), NetworkPolicy::Allowlist(c_rules)) => {
            for r in c_rules {
                if !allowlist_covers(p_rules, r) {
                    return Err(PolicyError::Invalid(format!(
                        "child allowlist rule {}:{} is not covered by parent",
                        r.host,
                        r.port.map(|p| p.to_string()).unwrap_or_else(|| "*".into())
                    )));
                }
            }
            Ok(())
        }
        (NetworkPolicy::Allowlist(_), NetworkPolicy::Unrestricted) => Err(PolicyError::Invalid(
            "child cannot expand network to Unrestricted".into(),
        )),
    }
}

fn allowlist_covers(parent_rules: &[NetworkRule], child: &NetworkRule) -> bool {
    parent_rules.iter().any(|p| {
        // Parent host must match child host (parent can be broader wildcard).
        let host_ok = crate::egress::host_matches(&p.host, &child.host)
            || (p.host == child.host)
            || (p.host == "*");
        // Also allow parent wildcard covering child exact.
        let host_ok = host_ok || host_pattern_covers(&p.host, &child.host);
        if !host_ok {
            return false;
        }
        match (p.port, child.port) {
            (_, None) => p.port.is_none(), // child any-port needs parent any-port
            (None, Some(_)) => true,       // parent any-port covers specific
            (Some(pp), Some(cp)) => pp == cp,
        }
    })
}

fn host_pattern_covers(parent_pat: &str, child_host: &str) -> bool {
    crate::egress::host_matches(parent_pat, child_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{NetworkPolicy, NetworkRule};
    use crate::policy::{CredentialGrant, Policy};

    #[test]
    fn can_narrow_network() {
        let parent = Policy::builder("/tmp/ws")
            .network(NetworkPolicy::Allowlist(vec![
                NetworkRule::host_port("api.x.ai", 443),
                NetworkRule::host_port("example.com", 443),
            ]))
            .build()
            .unwrap();
        let child = narrow_policy(
            &parent,
            TaskSpec {
                task_id: TaskId::from_string("tsk-1"),
                network: Some(NetworkPolicy::Allowlist(vec![NetworkRule::host_port(
                    "api.x.ai",
                    443,
                )])),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(child.network, NetworkPolicy::Allowlist(ref r) if r.len() == 1));
    }

    #[test]
    fn cannot_expand_network() {
        let parent = Policy::builder("/tmp/ws")
            .network(NetworkPolicy::DenyAll)
            .build()
            .unwrap();
        let err = narrow_policy(
            &parent,
            TaskSpec {
                task_id: TaskId::from_string("tsk-1"),
                network: Some(NetworkPolicy::Unrestricted),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::Invalid(_)));
    }

    #[test]
    fn extra_deny_ok() {
        let parent = Policy::builder("/tmp/ws").build().unwrap();
        let child = narrow_policy(
            &parent,
            TaskSpec {
                task_id: TaskId::from_string("tsk-1"),
                extra_deny: vec![PathBuf::from("/tmp/ws/secrets")],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(child.deny_paths().any(|r| r.path.ends_with("secrets")));
    }

    #[test]
    fn credential_subset() {
        let parent = Policy::builder("/tmp/ws")
            .credential(CredentialGrant {
                name: "a".into(),
                source: "env:A".into(),
                inject_as_env: None,
            })
            .credential(CredentialGrant {
                name: "b".into(),
                source: "env:B".into(),
                inject_as_env: None,
            })
            .build()
            .unwrap();
        let child = narrow_policy(
            &parent,
            TaskSpec {
                task_id: TaskId::from_string("tsk-1"),
                credential_names: Some(vec!["a".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(child.credentials.len(), 1);
        assert_eq!(child.credentials[0].name, "a");
    }
}
