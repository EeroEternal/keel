//! `local-worktree` backend: isolate agent writes in a git worktree or directory copy.
//!
//! ## Behavior
//!
//! 1. On `apply`, create an isolated workspace under `~/.keel/worktrees/<id>/`.
//! 2. Prefer `git worktree add` when `workspace` is inside a git repo.
//! 3. Fall back to a lightweight directory overlay (copy of essential layout / empty root).
//! 4. Spawns run with `cwd` rewritten into the worktree; soft FS checks use remapped paths.
//! 5. Optionally wraps an inner backend (`ProcessGuard` or `LocalProcess`) for extra enforcement.

use crate::backend::{BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
use crate::error::{EnforceError, EnforceResult};
use crate::process_guard::{self, ProcessGuardBackend};
use async_trait::async_trait;
use chrono::Utc;
use keel_policy::{Policy, SpaceId};
use keel_record::{EventKind, RecordEvent, RecordSink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Options for [`WorktreeBackend`].
#[derive(Debug, Clone)]
pub struct WorktreeOptions {
    /// Directory root for worktrees (`$KEEL_HOME/worktrees` by default).
    pub worktrees_root: Option<PathBuf>,
    /// If true, remove the worktree on destroy (default true for ephemeral tasks).
    pub cleanup_on_destroy: bool,
    /// Prefer git worktree when possible (default true).
    pub prefer_git: bool,
}

impl Default for WorktreeOptions {
    fn default() -> Self {
        Self {
            worktrees_root: None,
            cleanup_on_destroy: true,
            prefer_git: true,
        }
    }
}

#[derive(Debug, Clone)]
struct WorktreeState {
    /// Isolated path agents should use as cwd / write root.
    path: PathBuf,
    /// Original workspace from the policy.
    origin: PathBuf,
    /// Whether we used `git worktree add`.
    git: bool,
    /// Branch/ref name for git worktrees.
    branch: Option<String>,
}

/// Worktree isolation backend (optionally layered on another backend).
pub struct WorktreeBackend {
    opts: WorktreeOptions,
    inner: Arc<dyn EnforceBackend>,
    state: Mutex<Option<WorktreeState>>,
    applied: AtomicBool,
}

impl WorktreeBackend {
    pub fn new() -> Self {
        Self::with_inner(Arc::new(ProcessGuardBackend::new()), WorktreeOptions::default())
    }

    pub fn with_options(opts: WorktreeOptions) -> Self {
        Self::with_inner(Arc::new(ProcessGuardBackend::new()), opts)
    }

    pub fn with_inner(inner: Arc<dyn EnforceBackend>, opts: WorktreeOptions) -> Self {
        Self {
            opts,
            inner,
            state: Mutex::new(None),
            applied: AtomicBool::new(false),
        }
    }

    pub fn worktree_path(&self) -> Option<PathBuf> {
        self.state.lock().ok()?.as_ref().map(|s| s.path.clone())
    }

    fn worktrees_root(&self) -> PathBuf {
        self.opts.worktrees_root.clone().unwrap_or_else(|| {
            if let Ok(h) = std::env::var("KEEL_HOME") {
                return PathBuf::from(h).join("worktrees");
            }
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".keel")
                .join("worktrees")
        })
    }

    fn remap_to_worktree(&self, path: &Path) -> PathBuf {
        let guard = self.state.lock().unwrap();
        let Some(st) = guard.as_ref() else {
            return path.to_path_buf();
        };
        if path.is_absolute() {
            if let Ok(rel) = path.strip_prefix(&st.origin) {
                return st.path.join(rel);
            }
            return path.to_path_buf();
        }
        st.path.join(path)
    }

    fn create_worktree(&self, policy: &Policy, space_tag: &str) -> EnforceResult<WorktreeState> {
        let origin = if policy.workspace.is_absolute() {
            policy.workspace.clone()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(&policy.workspace)
        };
        let origin = dunce::canonicalize(&origin).unwrap_or(origin);

        let root = self.worktrees_root();
        std::fs::create_dir_all(&root)?;
        let dir_name = format!(
            "{}-{}",
            space_tag.chars().take(24).collect::<String>(),
            std::process::id()
        );
        let path = root.join(dir_name);

        if self.opts.prefer_git {
            if let Some(state) = try_git_worktree(&origin, &path)? {
                return Ok(state);
            }
        }

        // Fallback: empty isolated directory (agent starts clean; can still read
        // origin via soft default_read / system paths depending on policy).
        std::fs::create_dir_all(&path)?;
        // Drop a pointer file so tools/humans can find the origin.
        let _ = std::fs::write(
            path.join(".keel-worktree-origin"),
            format!("{}\n", origin.display()),
        );
        info!(
            path = %path.display(),
            origin = %origin.display(),
            "created directory worktree (non-git fallback)"
        );
        Ok(WorktreeState {
            path,
            origin,
            git: false,
            branch: None,
        })
    }
}

impl Default for WorktreeBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn try_git_worktree(origin: &Path, path: &Path) -> EnforceResult<Option<WorktreeState>> {
    // Find git top-level for origin.
    let out = Command::new("git")
        .args(["-C", &origin.to_string_lossy(), "rev-parse", "--show-toplevel"])
        .output();
    let Ok(out) = out else {
        return Ok(None);
    };
    if !out.status.success() {
        return Ok(None);
    }
    let toplevel = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if toplevel.is_empty() {
        return Ok(None);
    }

    let branch = format!(
        "keel/{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("task")
    );

    // git worktree add -b branch path HEAD
    let status = Command::new("git")
        .args([
            "-C",
            &toplevel,
            "worktree",
            "add",
            "-b",
            &branch,
            &path.to_string_lossy(),
            "HEAD",
        ])
        .status()
        .map_err(|e| EnforceError::ApplyFailed(format!("git worktree add: {e}")))?;

    if !status.success() {
        warn!(
            path = %path.display(),
            "git worktree add failed; will use directory fallback"
        );
        // Clean partial path if created.
        let _ = std::fs::remove_dir_all(path);
        return Ok(None);
    }

    info!(
        path = %path.display(),
        branch = %branch,
        "created git worktree"
    );
    Ok(Some(WorktreeState {
        path: path.to_path_buf(),
        origin: PathBuf::from(toplevel),
        git: true,
        branch: Some(branch),
    }))
}

fn cleanup_worktree(st: &WorktreeState) {
    if st.git {
        if let Some(branch) = &st.branch {
            let _ = Command::new("git")
                .args([
                    "-C",
                    &st.origin.to_string_lossy(),
                    "worktree",
                    "remove",
                    "--force",
                    &st.path.to_string_lossy(),
                ])
                .status();
            let _ = Command::new("git")
                .args(["-C", &st.origin.to_string_lossy(), "branch", "-D", branch])
                .status();
        }
    }
    let _ = std::fs::remove_dir_all(&st.path);
}

#[async_trait]
impl EnforceBackend for WorktreeBackend {
    fn info(&self) -> BackendInfo {
        let inner = self.inner.info();
        BackendInfo {
            name: "local-worktree",
            kernel_fs: inner.kernel_fs,
            child_network: inner.child_network,
        }
    }

    async fn apply(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        if policy.is_expired(Utc::now()) {
            return Err(EnforceError::PolicyExpired);
        }
        policy.validate()?;

        let tag = policy
            .task_id
            .as_ref()
            .map(|t| t.as_str().to_string())
            .unwrap_or_else(|| policy.id.as_str().to_string());
        let st = self.create_worktree(policy, &tag)?;

        // Policy for the inner backend: rewrite workspace to the worktree path.
        let mut inner_policy = policy.clone();
        inner_policy.workspace = st.path.clone();
        // Ensure the worktree itself is writable in soft rules.
        if !inner_policy
            .fs
            .iter()
            .any(|r| r.path == st.path && r.access == keel_policy::FsAccess::ReadWrite)
        {
            inner_policy
                .fs
                .push(keel_policy::FsRule::read_write(st.path.clone()));
        }

        *self.state.lock().unwrap() = Some(st.clone());
        self.inner.apply(&inner_policy, sink.clone()).await?;
        self.applied.store(true, Ordering::Release);

        let _ = sink
            .emit(RecordEvent::new(
                SpaceId::from_string("pending"),
                policy.id.clone(),
                policy.task_id.clone(),
                EventKind::Note {
                    message: format!(
                        "worktree ready at {} (git={}, origin={})",
                        st.path.display(),
                        st.git,
                        st.origin.display()
                    ),
                },
            ))
            .await;
        Ok(())
    }

    async fn check_fs(&self, policy: &Policy, path: &Path, write: bool) -> EnforceResult<bool> {
        let mapped = self.remap_to_worktree(path);
        // Soft check against a policy whose workspace is the worktree when applied.
        let mut p = policy.clone();
        if let Some(st) = self.state.lock().unwrap().as_ref() {
            p.workspace = st.path.clone();
        }
        let allowed = process_guard::soft_fs_allowed(&p, &mapped, write);
        Ok(allowed)
    }

    async fn spawn(
        &self,
        space_id: &SpaceId,
        policy: &Policy,
        mut req: SpawnRequest,
        sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<SpawnedProcess> {
        let mut inner_policy = policy.clone();
        if let Some(st) = self.state.lock().unwrap().as_ref() {
            inner_policy.workspace = st.path.clone();
            // Default cwd to worktree unless caller set one under the worktree.
            match &req.cwd {
                None => req.cwd = Some(st.path.clone()),
                Some(cwd) => {
                    if let Ok(rel) = cwd.strip_prefix(&st.origin) {
                        req.cwd = Some(st.path.join(rel));
                    } else if !cwd.starts_with(&st.path) && !cwd.is_absolute() {
                        req.cwd = Some(st.path.join(cwd));
                    }
                }
            }
        }
        self.inner
            .spawn(space_id, &inner_policy, req, sink)
            .await
    }

    async fn destroy(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        let _ = self.inner.destroy(policy, sink).await;
        if self.opts.cleanup_on_destroy {
            if let Ok(mut guard) = self.state.lock() {
                if let Some(st) = guard.take() {
                    cleanup_worktree(&st);
                    info!(path = %st.path.display(), "worktree cleaned up");
                }
            }
        }
        self.applied.store(false, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::profile_workspace;
    use keel_record::MemorySink;

    #[tokio::test]
    async fn creates_directory_worktree() {
        let origin = tempfile::tempdir().unwrap();
        // Not a git repo → directory fallback.
        let policy = profile_workspace(origin.path()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let backend = WorktreeBackend::with_options(WorktreeOptions {
            worktrees_root: Some(root.path().to_path_buf()),
            cleanup_on_destroy: true,
            prefer_git: true,
        });
        let sink = Arc::new(MemorySink::new());
        backend.apply(&policy, sink.clone()).await.unwrap();
        let wt = backend.worktree_path().unwrap();
        assert!(wt.is_dir());
        assert!(wt.join(".keel-worktree-origin").is_file());
        backend.destroy(&policy, sink).await.unwrap();
        assert!(!wt.exists() || !self_exists(&wt));
    }

    fn self_exists(p: &Path) -> bool {
        p.exists()
    }
}
