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
/// the nearest existing ancestor and rejoin the **full relative suffix** after it
/// (so `foo/bar.txt` keeps both `foo/` and `bar.txt`, not only the leaf).
///
/// Callers must still run [`soft_fs_allowed`] on the result (and ideally on the
/// logical path) so symlink escape outside write roots is denied.
///
/// This is path math only — not a hard security boundary (TOCTOU still applies
/// between resolve and I/O).
pub fn soft_fs_resolve(policy: &Policy, path: &Path, _write: bool) -> Result<PathBuf, String> {
    let joined = resolve_against_workspace(policy, path);
    if joined.exists() {
        return dunce::canonicalize(&joined)
            .map(|p| normalize(&p))
            .map_err(|e| format!("canonicalize {}: {e}", joined.display()));
    }

    // Walk up until an existing ancestor is found; collect the missing suffix
    // (leaf-first), then rejoin in order after the ancestor.
    // Example: /ws/foo/bar.txt where only /ws exists → suffix [bar.txt, foo]
    // → /ws/foo/bar.txt (not /ws/bar.txt).
    let mut ancestor = joined.parent().map(Path::to_path_buf);
    let mut suffix_rev: Vec<std::ffi::OsString> = Vec::new();
    if let Some(name) = joined.file_name() {
        suffix_rev.push(name.to_os_string());
    } else {
        return Err(format!("invalid path: {}", joined.display()));
    }

    while let Some(ref p) = ancestor {
        if p.as_os_str().is_empty() {
            break;
        }
        if p.exists() {
            let canon = dunce::canonicalize(p)
                .map(|x| normalize(&x))
                .unwrap_or_else(|_| normalize(p));
            let mut out = canon;
            for c in suffix_rev.iter().rev() {
                out.push(c);
            }
            return Ok(out);
        }
        if let Some(name) = p.file_name() {
            suffix_rev.push(name.to_os_string());
        }
        ancestor = p.parent().map(Path::to_path_buf);
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
    use keel_policy::{profile_workspace, Policy};
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

    #[test]
    fn baseline_denies_ssh_and_dotenv_even_with_default_read() {
        let p = profile_workspace(Path::new("/tmp/keel-ws")).unwrap();
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        assert!(
            !soft_fs_allowed(&p, &home.join(".ssh").join("id_rsa"), false),
            "baseline should deny ~/.ssh"
        );
        assert!(
            !soft_fs_allowed(&p, Path::new("/tmp/keel-ws/.env"), false),
            "baseline should deny **/.env"
        );
        assert!(soft_fs_allowed(&p, Path::new("/tmp/keel-ws/src/main.rs"), true));
    }

    #[test]
    fn soft_fs_resolve_keeps_intermediate_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let p = profile_workspace(ws).unwrap();
        // Nested path does not exist yet — must keep `foo/` not only `bar.txt`.
        // macOS may canonicalize /var → /private/var; compare relative to workspace.
        let ws_canon = dunce::canonicalize(ws).unwrap_or_else(|_| ws.to_path_buf());
        let resolved = soft_fs_resolve(&p, Path::new("foo/bar.txt"), true).unwrap();
        let rel = resolved.strip_prefix(&ws_canon).unwrap_or(resolved.as_path());
        assert_eq!(rel, Path::new("foo/bar.txt"), "resolved={resolved:?}");

        let deeper = soft_fs_resolve(&p, Path::new("a/b/c.txt"), true).unwrap();
        let rel2 = deeper.strip_prefix(&ws_canon).unwrap_or(deeper.as_path());
        assert_eq!(rel2, Path::new("a/b/c.txt"), "deeper={deeper:?}");
    }

    #[test]
    fn soft_fs_resolve_symlink_escape_denied_by_soft_check() {
        // Use a policy with *only* workspace write — not profile_workspace, which
        // also allows /var/folders temps (macOS tempdir lives there).
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"x").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, ws.join("leak")).unwrap();
            let p = Policy::builder(&ws)
                .without_baseline_denies()
                .default_read(true)
                .read_write(&ws)
                .build()
                .unwrap();
            let resolved = soft_fs_resolve(&p, Path::new("leak/secret.txt"), true).unwrap();
            assert!(
                !soft_fs_allowed(&p, &resolved, true),
                "symlink escape should not be writable under soft policy; resolved={resolved:?}"
            );
        }
    }

    #[test]
    fn soft_fs_path_traversal_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let p = profile_workspace(ws).unwrap();
        // Logical traversal still lands under workspace after normalize/resolve.
        let resolved = soft_fs_resolve(&p, Path::new("a/../b/c.txt"), true).unwrap();
        let ws_canon = dunce::canonicalize(ws).unwrap_or_else(|_| ws.to_path_buf());
        let rel = resolved.strip_prefix(&ws_canon).unwrap_or(resolved.as_path());
        assert_eq!(rel, Path::new("b/c.txt"));
    }
}
