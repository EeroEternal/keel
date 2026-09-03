//! AgentCell enforce backend: unprivileged Linux sandbox leveraging raw kernel
//! namespaces, pivot_root, cgroup v2, Landlock, Seccomp-BPF, and eBPF LSM/tracepoints.

use crate::backend::{BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
use crate::error::{EnforceError, EnforceResult};
use async_trait::async_trait;
use keel_policy::{NetworkPolicy, Policy, SpaceId};
use keel_record::RecordSink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;

const AGENTCELL_MARKER: &str = "__KEEL_INSIDE_AGENTCELL";

/// True if running inside an AgentCell sandbox.
pub fn is_inside_agentcell() -> bool {
    std::env::var_os(AGENTCELL_MARKER).is_some()
}

/// True if the AgentCell `sand` executable is discoverable.
pub fn agentcell_available() -> bool {
    which_agentcell().is_some()
}

/// Find the `sand` executable from `KEEL_AGENTCELL_BIN` or system `PATH`.
pub fn which_agentcell() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KEEL_AGENTCELL_BIN") {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("sand");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    })
}

/// Configuration options for [`AgentCellBackend`].
#[derive(Debug, Clone)]
pub struct AgentCellOptions {
    /// Explicit path to the `sand` binary. If None, resolved automatically.
    pub sand_bin: Option<PathBuf>,
    /// cgroup v2 memory limit (e.g. "2G", "512M").
    pub memory_limit: Option<String>,
    /// cgroup v2 CPU count limit.
    pub cpu_limit: Option<u32>,
    /// cgroup v2 maximum process/thread count (default 256).
    pub pids_limit: Option<u32>,
    /// Custom packed rootfs tree directory.
    pub rootfs: Option<PathBuf>,
}

impl Default for AgentCellOptions {
    fn default() -> Self {
        Self {
            sand_bin: None,
            memory_limit: None,
            cpu_limit: None,
            pids_limit: Some(256),
            rootfs: None,
        }
    }
}

/// Enforce backend backed by AgentCell (`sand`).
pub struct AgentCellBackend {
    options: AgentCellOptions,
}

impl AgentCellBackend {
    pub fn new() -> Self {
        Self::with_options(AgentCellOptions::default())
    }

    pub fn with_options(options: AgentCellOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &AgentCellOptions {
        &self.options
    }
}

impl Default for AgentCellBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforceBackend for AgentCellBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "agentcell",
            kernel_fs: true,
            child_network: true,
        }
    }

    async fn apply(&self, _policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        if self.options.sand_bin.is_none() && which_agentcell().is_none() {
            return Err(EnforceError::ApplyFailed(
                "AgentCell executable (`sand`) not found in PATH or KEEL_AGENTCELL_BIN".into(),
            ));
        }
        Ok(())
    }

    async fn check_fs(&self, policy: &Policy, path: &Path, write: bool) -> EnforceResult<bool> {
        Ok(crate::process_guard::soft_fs_allowed(policy, path, write))
    }

    async fn spawn(
        &self,
        _space_id: &SpaceId,
        policy: &Policy,
        req: SpawnRequest,
        _sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<SpawnedProcess> {
        let sand_bin = self
            .options
            .sand_bin
            .clone()
            .or_else(which_agentcell)
            .ok_or_else(|| {
                EnforceError::ApplyFailed(
                    "AgentCell executable (`sand`) not found in PATH or KEEL_AGENTCELL_BIN".into(),
                )
            })?;

        let mut cmd = Command::new(sand_bin);

        // 1. Working directory
        let cwd = req.cwd.as_deref().unwrap_or(&policy.workspace);
        cmd.arg("--workdir").arg(cwd);

        // 2. Resource limits (cgroup v2)
        if let Some(mem) = &self.options.memory_limit {
            cmd.arg("--mem").arg(mem);
        }
        if let Some(cpu) = self.options.cpu_limit {
            cmd.arg("--cpu").arg(cpu.to_string());
        }
        if let Some(pids) = self.options.pids_limit {
            cmd.arg("--pids").arg(pids.to_string());
        }

        // 3. Network policy
        match &policy.network {
            NetworkPolicy::Unrestricted => {
                cmd.arg("--net").arg("host");
            }
            NetworkPolicy::DenyAll => {
                cmd.arg("--net").arg("none");
            }
            NetworkPolicy::Allowlist(_) => {
                // In allowlist mode, child attaches to host net with proxy environment variables
                cmd.arg("--net").arg("host");
            }
        }

        // 4. Deny paths (Landlock & BPF LSM)
        for deny in policy.deny_paths() {
            if !deny.glob {
                let abs = if deny.path.is_absolute() {
                    deny.path.clone()
                } else {
                    policy.workspace.join(&deny.path)
                };
                cmd.arg("--deny").arg(abs);
            }
        }

        // 5. Optional rootfs
        if let Some(rootfs) = &self.options.rootfs {
            cmd.arg("--rootfs").arg(rootfs);
        }

        // 6. Child program and arguments
        cmd.arg("--").arg(&req.program).args(&req.args);

        // Inherit or pipe stdio
        cmd.stdin(req.stdin.to_std())
            .stdout(req.stdout.to_std())
            .stderr(req.stderr.to_std());

        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        cmd.env(AGENTCELL_MARKER, "1");

        #[cfg(unix)]
        if req.process_group {
            cmd.process_group(0);
        }
        cmd.kill_on_drop(true);

        let child = cmd.spawn()?;
        Ok(SpawnedProcess::new(child, req.process_group))
    }

    async fn destroy(&self, _policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agentcell_backend_info() {
        let backend = AgentCellBackend::new();
        let info = backend.info();
        assert_eq!(info.name, "agentcell");
        assert!(info.kernel_fs);
        assert!(info.child_network);
    }

    #[test]
    fn agentcell_options_defaults() {
        let opts = AgentCellOptions::default();
        assert!(opts.sand_bin.is_none());
        assert_eq!(opts.pids_limit, Some(256));
        assert!(opts.memory_limit.is_none());
        assert!(opts.cpu_limit.is_none());
    }

    #[tokio::test]
    async fn check_fs_delegates_to_soft_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = keel_policy::profile_workspace(tmp.path()).unwrap();

        let backend = AgentCellBackend::new();
        let allowed = backend
            .check_fs(&policy, &tmp.path().join("normal.txt"), false)
            .await
            .unwrap();
        assert!(allowed);

        let denied = backend
            .check_fs(&policy, &tmp.path().join(".env"), false)
            .await
            .unwrap();
        assert!(!denied);
    }
}
