//! Just-in-time credential resolution and injection.
//!
//! Grants in a [`Policy`] name *sources*, never secret material. Keel resolves
//! them at spawn time, injects into the child environment, and records issue /
//! revoke events. Secrets are not written to the event log.

use crate::error::{EnforceError, EnforceResult};
use keel_policy::{CredentialGrant, Policy};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

/// How a grant source is interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSourceKind {
    /// `env:VAR_NAME` or bare `VAR_NAME` — read from the parent environment.
    Env(String),
    /// `file:/path` or `file:./relative` — read file contents (trimmed).
    File(String),
    /// Unknown / unsupported scheme.
    Unsupported(String),
}

impl CredentialSourceKind {
    pub fn parse(source: &str) -> Self {
        let s = source.trim();
        if let Some(rest) = s.strip_prefix("env:") {
            return Self::Env(rest.to_string());
        }
        if let Some(rest) = s.strip_prefix("file:") {
            return Self::File(rest.to_string());
        }
        // Bare name → env var (common DX).
        if !s.contains(':') && !s.contains('/') {
            return Self::Env(s.to_string());
        }
        if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
            return Self::File(s.to_string());
        }
        Self::Unsupported(s.to_string())
    }
}

/// A resolved secret ready to inject (kept out of Debug).
pub struct ResolvedCredential {
    pub name: String,
    pub env_key: String,
    pub value: String,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("name", &self.name)
            .field("env_key", &self.env_key)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Resolve all grants on a policy. Missing optional sources are skipped with a warning
/// unless `strict` is true.
pub fn resolve_credentials(policy: &Policy, strict: bool) -> EnforceResult<Vec<ResolvedCredential>> {
    let mut out = Vec::new();
    for grant in &policy.credentials {
        match resolve_one(grant, &policy.workspace) {
            Ok(Some(r)) => out.push(r),
            Ok(None) => {
                if strict {
                    return Err(EnforceError::Denied(format!(
                        "credential '{}' source empty or missing: {}",
                        grant.name, grant.source
                    )));
                }
                warn!(
                    name = %grant.name,
                    source = %grant.source,
                    "credential source empty; skipping"
                );
            }
            Err(e) if strict => return Err(e),
            Err(e) => {
                warn!(name = %grant.name, error = %e, "credential resolve failed; skipping");
            }
        }
    }
    Ok(out)
}

fn resolve_one(
    grant: &CredentialGrant,
    workspace: &Path,
) -> EnforceResult<Option<ResolvedCredential>> {
    let env_key = grant
        .inject_as_env
        .clone()
        .unwrap_or_else(|| grant.name.clone());
    if env_key.is_empty() {
        return Err(EnforceError::Denied("credential env key is empty".into()));
    }

    let value = match CredentialSourceKind::parse(&grant.source) {
        CredentialSourceKind::Env(var) => match std::env::var(&var) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) | Err(_) => return Ok(None),
        },
        CredentialSourceKind::File(path) => {
            let p = if Path::new(&path).is_absolute() {
                Path::new(&path).to_path_buf()
            } else {
                workspace.join(&path)
            };
            match std::fs::read_to_string(&p) {
                Ok(v) => {
                    let v = v.trim_end_matches(['\r', '\n']).to_string();
                    if v.is_empty() {
                        return Ok(None);
                    }
                    v
                }
                Err(e) => {
                    return Err(EnforceError::Io(e));
                }
            }
        }
        CredentialSourceKind::Unsupported(s) => {
            return Err(EnforceError::Denied(format!(
                "unsupported credential source '{s}' (use env:NAME or file:PATH)"
            )));
        }
    };

    debug!(name = %grant.name, env_key = %env_key, "credential resolved");
    Ok(Some(ResolvedCredential {
        name: grant.name.clone(),
        env_key,
        value,
    }))
}

/// Merge resolved credentials into a spawn env list (does not overwrite existing keys).
pub fn inject_into_env(
    env: &mut Vec<(String, String)>,
    creds: &[ResolvedCredential],
) -> Vec<String> {
    let mut issued = Vec::new();
    for c in creds {
        if env.iter().any(|(k, _)| k == &c.env_key) {
            warn!(
                env_key = %c.env_key,
                "spawn env already has key; not overwriting with credential"
            );
            continue;
        }
        env.push((c.env_key.clone(), c.value.clone()));
        issued.push(c.name.clone());
    }
    issued
}

/// Zeroize-ish drop helper: overwrite strings then drop.
pub fn revoke_resolved(mut creds: Vec<ResolvedCredential>) {
    for c in &mut creds {
        // Overwrite heap bytes best-effort (not formal zeroize crate).
        let len = c.value.len();
        c.value = "\0".repeat(len);
        c.value.clear();
    }
    drop(creds);
}

/// Snapshot grant names for recording without secret values.
pub fn grant_names(policy: &Policy) -> Vec<String> {
    policy.credentials.iter().map(|c| c.name.clone()).collect()
}

/// Build a redacted map of grant → source for diagnostics.
#[allow(dead_code)]
pub fn grant_sources(policy: &Policy) -> HashMap<String, String> {
    policy
        .credentials
        .iter()
        .map(|c| (c.name.clone(), c.source.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::Policy;

    #[test]
    fn parse_sources() {
        assert!(matches!(
            CredentialSourceKind::parse("env:FOO"),
            CredentialSourceKind::Env(s) if s == "FOO"
        ));
        assert!(matches!(
            CredentialSourceKind::parse("TOKEN"),
            CredentialSourceKind::Env(s) if s == "TOKEN"
        ));
        assert!(matches!(
            CredentialSourceKind::parse("file:/tmp/x"),
            CredentialSourceKind::File(s) if s == "/tmp/x"
        ));
    }

    #[test]
    fn resolve_env_grant() {
        unsafe {
            std::env::set_var("KEEL_TEST_SECRET_XYZ", "s3cr3t");
        }
        let policy = Policy::builder("/tmp")
            .credential(keel_policy::CredentialGrant {
                name: "api".into(),
                source: "env:KEEL_TEST_SECRET_XYZ".into(),
                inject_as_env: Some("API_TOKEN".into()),
            })
            .build()
            .unwrap();
        let resolved = resolve_credentials(&policy, true).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].env_key, "API_TOKEN");
        assert_eq!(resolved[0].value, "s3cr3t");
        unsafe {
            std::env::remove_var("KEEL_TEST_SECRET_XYZ");
        }
    }

    #[test]
    fn inject_does_not_overwrite() {
        let creds = vec![ResolvedCredential {
            name: "a".into(),
            env_key: "K".into(),
            value: "new".into(),
        }];
        let mut env = vec![("K".into(), "old".into())];
        let issued = inject_into_env(&mut env, &creds);
        assert!(issued.is_empty());
        assert_eq!(env[0].1, "old");
    }
}
