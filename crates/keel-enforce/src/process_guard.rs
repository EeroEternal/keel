//! Soft process-level policy checks (no kernel). Used by all backends as a
//! first line; kernel backends will fail closed even if this has bugs.

use crate::backend::{base_command, BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
use crate::error::{EnforceError, EnforceResult};
use async_trait::async_trait;
use chrono::Utc;
use keel_policy::{ExecPolicy, FsAccess, NetworkPolicy, Policy, SpaceId};
use keel_record::{EventKind, RecordEvent, RecordSink};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tracing::info;

/// Normalize for prefix checks (best-effort; not a security boundary alone).
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

/// Resolve `path` against the policy workspace when it is relative.
pub fn resolve_against_workspace(policy: &Policy, path: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize(path)
    } else {
        normalize(&policy.workspace.join(path))
    }
}

/// Resolve a path for SpaceFs-style I/O: workspace-relative join, then
/// canonicalize existing paths (follows symlinks). For new paths, canonicalize
/// the nearest existing parent when possible.
///
/// Callers must still run [`soft_fs_allowed`] on the result (and ideally on the
/// logical path) so symlink escape outside write roots is denied.
pub fn soft_fs_resolve(policy: &Policy, path: &Path, _write: bool) -> Result<PathBuf, String> {
    let joined = resolve_against_workspace(policy, path);
    if joined.exists() {
        return dunce::canonicalize(&joined)
            .map(|p| normalize(&p))
            .map_err(|e| format!("canonicalize {}: {e}", joined.display()));
    }

    // New path: resolve parent chain.
    let mut parent = joined.parent().map(Path::to_path_buf);
    let file_name = joined
        .file_name()
        .ok_or_else(|| format!("invalid path: {}", joined.display()))?
        .to_os_string();

    while let Some(ref p) = parent {
        if p.as_os_str().is_empty() {
            break;
        }
        if p.exists() {
            let canon = dunce::canonicalize(p)
                .map(|x| normalize(&x))
                .unwrap_or_else(|_| normalize(p));
            return Ok(canon.join(file_name));
        }
        parent = p.parent().map(Path::to_path_buf);
    }

    Ok(joined)
}

/// Soft filesystem allow check.
///
/// Rules:
/// - Any matching `Deny` (prefix or exact) → deny
/// - Write requires a `ReadWrite` prefix match
/// - Read allowed if `default_read` or any Read/ReadWrite prefix match
///
/// Relative paths are resolved against `policy.workspace`.
pub fn soft_fs_allowed(policy: &Policy, path: &Path, write: bool) -> bool {
    let path = resolve_against_workspace(policy, path);
    let path_str = path.to_string_lossy();

    for rule in policy.deny_paths() {
        if rule.glob {
            // v0: simple suffix / contains heuristics for `**/.env` style.
            let pat = rule.path.to_string_lossy();
            let leaf = pat.rsplit('/').next().unwrap_or("");
            if leaf.starts_with('.') || leaf.contains('*') {
                let cleaned = leaf.trim_start_matches('*').trim_start_matches('/');
                if !cleaned.is_empty() && path_str.contains(cleaned) {
                    return false;
                }
            }
            continue;
        }
        let deny = resolve_against_workspace(policy, &rule.path);
        if path.starts_with(&deny) || path == deny {
            return false;
        }
    }

    // Deny globs (soft).
    if crate::deny_glob::path_matches_deny_glob(policy, &path) {
        return false;
    }

    if write {
        for p in policy.read_write_paths() {
            let allow = resolve_against_workspace(policy, p);
            if path.starts_with(&allow) || path == allow {
                return true;
            }
        }
        return false;
    }

    if policy.default_read {
        return true;
    }
    for rule in &policy.fs {
        if matches!(rule.access, FsAccess::Read | FsAccess::ReadWrite) && !rule.glob {
            let allow = resolve_against_workspace(policy, &rule.path);
            if path.starts_with(&allow) || path == allow {
                return true;
            }
        }
    }
    false
}

pub struct ProcessGuardBackend {
    /// When true, refuse spawn if network is DenyAll (cannot hard-block; documents intent).
    pub soft_block_on_deny_all_net: bool,
}

impl ProcessGuardBackend {
    pub fn new() -> Self {
        Self {
            soft_block_on_deny_all_net: false,
        }
    }
}

impl Default for ProcessGuardBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforceBackend for ProcessGuardBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "process-guard",
            kernel_fs: false,
            child_network: false,
        }
    }

    async fn apply(&self, policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        if policy.is_expired(Utc::now()) {
            return Err(EnforceError::PolicyExpired);
        }
        policy.validate()?;
        info!(
            policy_id = %policy.id,
            backend = "process-guard",
            "policy applied (soft process guard)"
        );
        Ok(())
    }

    async fn check_fs(&self, policy: &Policy, path: &Path, write: bool) -> EnforceResult<bool> {
        Ok(soft_fs_allowed(policy, path, write))
    }

    async fn spawn(
        &self,
        space_id: &SpaceId,
        policy: &Policy,
        req: SpawnRequest,
        sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<SpawnedProcess> {
        if policy.is_expired(Utc::now()) {
            return Err(EnforceError::PolicyExpired);
        }
        let (audit_args, args_redacted) = req.audit_args_for_event();
        if matches!(policy.exec, ExecPolicy::Deny) {
            let _ = sink
                .emit(RecordEvent::new(
                    space_id.clone(),
                    policy.id.clone(),
                    policy.task_id.clone(),
                    EventKind::Exec {
                        program: req.program.clone(),
                        args: audit_args,
                        allowed: false,
                        args_redacted,
                    },
                ))
                .await;
            return Err(EnforceError::Denied("exec denied by policy".into()));
        }

        if self.soft_block_on_deny_all_net && matches!(policy.network, NetworkPolicy::DenyAll) {
            // We cannot hard-block network without seccomp/Seatbelt; optional fail-closed for demos.
            tracing::warn!("process-guard: DenyAll network is advisory without kernel backend");
        }

        if let Some(cwd) = &req.cwd {
            if !soft_fs_allowed(policy, cwd, false) {
                return Err(EnforceError::Denied(format!(
                    "cwd not allowed: {}",
                    cwd.display()
                )));
            }
        }

        // Program path soft-check when absolute.
        let prog = Path::new(&req.program);
        if prog.is_absolute() && !soft_fs_allowed(policy, prog, false) {
            return Err(EnforceError::Denied(format!(
                "program path not readable under policy: {}",
                prog.display()
            )));
        }

        let _ = sink
            .emit(RecordEvent::new(
                space_id.clone(),
                policy.id.clone(),
                policy.task_id.clone(),
                EventKind::Exec {
                    program: req.program.clone(),
                    args: audit_args,
                    allowed: true,
                    args_redacted,
                },
            ))
            .await;

        let process_group = req.process_group;
        let child = base_command(&req).spawn()?;
        Ok(SpawnedProcess::new(child, process_group))
    }

    async fn destroy(&self, _policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::profile_workspace;
    use std::path::Path;

    #[test]
    fn workspace_write_rules() {
        let p = profile_workspace(Path::new("/tmp/proj")).unwrap();
        assert!(soft_fs_allowed(&p, Path::new("/tmp/proj/a.rs"), true));
        assert!(soft_fs_allowed(&p, Path::new("/etc/passwd"), false)); // default_read
        assert!(!soft_fs_allowed(&p, Path::new("/etc/passwd"), true));
    }

    #[test]
    fn deny_wins() {
        let p = Policy::builder("/tmp/proj")
            .default_read(true)
            .read_write("/tmp/proj")
            .deny("/tmp/proj/secrets")
            .build()
            .unwrap();
        assert!(!soft_fs_allowed(&p, Path::new("/tmp/proj/secrets/key"), false));
        assert!(soft_fs_allowed(&p, Path::new("/tmp/proj/src"), true));
    }

    #[test]
    fn relative_paths_resolve_to_workspace() {
        let p = profile_workspace(Path::new("/tmp/proj")).unwrap();
        assert!(soft_fs_allowed(&p, Path::new("README.md"), true));
        assert!(soft_fs_allowed(&p, Path::new("src/main.rs"), true));
    }
}
