//! `local-process` backend: Landlock (Linux) / Seatbelt (macOS) via nono.
//!
//! ## Semantics
//!
//! - Applies a **process-wide, irreversible** kernel FS sandbox on `apply()`.
//! - Does **not** block parent-process network by default (agent needs LLM/MCP).
//! - When `NetworkPolicy::DenyAll`, child processes get Linux seccomp net filter
//!   in `pre_exec` (no-op on macOS for child net).
//! - Only one kernel apply per process; a second `apply` with a different policy
//!   returns [`EnforceError::AlreadyApplied`].

use crate::backend::{base_command, BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
use crate::error::{EnforceError, EnforceResult};
use crate::process_guard;
use async_trait::async_trait;
use chrono::Utc;
use keel_policy::{ExecPolicy, NetworkPolicy, Policy, SpaceId};
use keel_record::{EventKind, RecordEvent, RecordSink};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::{info, warn};

#[cfg(all(unix, feature = "kernel"))]
use crate::map_caps::{policy_to_capability_set, MapOptions};

/// Process-global: policy id that was applied (kernel sandbox is one-shot).
static KERNEL_APPLIED_POLICY: OnceLock<String> = OnceLock::new();

/// Options for [`LocalProcessBackend`].
#[derive(Debug, Clone)]
pub struct LocalProcessOptions {
    /// Fail if the platform cannot enforce kernel FS (default true).
    pub require_kernel: bool,
    /// Block network for the entire process via nono (default false).
    pub block_process_network: bool,
}

impl Default for LocalProcessOptions {
    fn default() -> Self {
        Self {
            require_kernel: true,
            block_process_network: false,
        }
    }
}

/// Landlock / Seatbelt enforce backend.
pub struct LocalProcessBackend {
    opts: LocalProcessOptions,
    applied: AtomicBool,
    restrict_child_net: AtomicBool,
}

impl LocalProcessBackend {
    pub fn new() -> Self {
        Self::with_options(LocalProcessOptions::default())
    }

    pub fn with_options(opts: LocalProcessOptions) -> Self {
        Self {
            opts,
            applied: AtomicBool::new(false),
            restrict_child_net: AtomicBool::new(false),
        }
    }

    /// Whether this process has a kernel sandbox applied (any backend instance).
    pub fn process_has_kernel_sandbox() -> bool {
        KERNEL_APPLIED_POLICY.get().is_some()
    }

    pub fn is_applied(&self) -> bool {
        self.applied.load(Ordering::Acquire)
    }

    pub fn restricts_child_network(&self) -> bool {
        self.restrict_child_net.load(Ordering::Acquire)
    }
}

impl Default for LocalProcessBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforceBackend for LocalProcessBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "local-process",
            kernel_fs: cfg!(all(
                feature = "kernel",
                any(target_os = "linux", target_os = "macos")
            )),
            child_network: cfg!(target_os = "linux"),
        }
    }

    async fn apply(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        if policy.is_expired(Utc::now()) {
            return Err(EnforceError::PolicyExpired);
        }
        policy.validate()?;

        #[cfg(all(unix, feature = "kernel"))]
        {
            return self.apply_kernel(policy, sink).await;
        }

        #[cfg(not(all(unix, feature = "kernel")))]
        {
            let msg = "local-process kernel backend requires unix + feature `kernel`";
            if self.opts.require_kernel {
                return Err(EnforceError::Unsupported(msg.into()));
            }
            warn!("{msg}; soft process-guard only");
            let _ = sink;
            self.applied.store(true, Ordering::Release);
            Ok(())
        }
    }

    async fn check_fs(&self, policy: &Policy, path: &Path, write: bool) -> EnforceResult<bool> {
        // Soft check always; kernel is the hard boundary after apply.
        Ok(process_guard::soft_fs_allowed(policy, path, write))
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
        if matches!(policy.exec, ExecPolicy::Deny) {
            let _ = sink
                .emit(RecordEvent::new(
                    space_id.clone(),
                    policy.id.clone(),
                    policy.task_id.clone(),
                    EventKind::Exec {
                        program: req.program.clone(),
                        args: req.args.clone(),
                        allowed: false,
                    },
                ))
                .await;
            return Err(EnforceError::Denied("exec denied by policy".into()));
        }

        if let Some(cwd) = &req.cwd {
            if !process_guard::soft_fs_allowed(policy, cwd, false) {
                return Err(EnforceError::Denied(format!(
                    "cwd not allowed: {}",
                    cwd.display()
                )));
            }
        }

        let _ = sink
            .emit(RecordEvent::new(
                space_id.clone(),
                policy.id.clone(),
                policy.task_id.clone(),
                EventKind::Exec {
                    program: req.program.clone(),
                    args: req.args.clone(),
                    allowed: true,
                },
            ))
            .await;

        let mut cmd = base_command(&req);

        let restrict_net = self.restrict_child_net.load(Ordering::Acquire)
            || matches!(policy.network, NetworkPolicy::DenyAll);

        #[cfg(target_os = "linux")]
        {
            if restrict_net {
                use std::os::unix::process::CommandExt;
                // SAFETY: pre_exec runs in child after fork.
                unsafe {
                    cmd.pre_exec(|| crate::child_net::install_child_network_filter());
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = restrict_net;

        let child = cmd.spawn()?;
        Ok(SpawnedProcess { child })
    }

    async fn destroy(&self, _policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        // Kernel FS sandbox cannot be undone until process exit.
        Ok(())
    }
}

#[cfg(all(unix, feature = "kernel"))]
impl LocalProcessBackend {
    async fn apply_kernel(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        use nono::Sandbox;

        let support = Sandbox::support_info();
        if !support.is_supported {
            let details = support.details.clone();
            if self.opts.require_kernel {
                return Err(EnforceError::Unsupported(details));
            }
            warn!(details = %details, "kernel sandbox unsupported; continuing soft-only");
            self.applied.store(true, Ordering::Release);
            return Ok(());
        }

        if let Some(existing) = KERNEL_APPLIED_POLICY.get() {
            if existing != policy.id.as_str() {
                return Err(EnforceError::AlreadyApplied {
                    applied: existing.clone(),
                    requested: policy.id.to_string(),
                });
            }
            // Same policy id re-apply: treat as idempotent success.
            self.applied.store(true, Ordering::Release);
            if matches!(policy.network, NetworkPolicy::DenyAll) {
                self.restrict_child_net.store(true, Ordering::Release);
            }
            return Ok(());
        }

        let map_opts = MapOptions {
            block_process_network: self.opts.block_process_network,
        };
        let caps = policy_to_capability_set(policy, map_opts)?;

        match Sandbox::apply(&caps) {
            Ok(_) => {
                let _ = KERNEL_APPLIED_POLICY.set(policy.id.to_string());
                self.applied.store(true, Ordering::Release);
                if matches!(policy.network, NetworkPolicy::DenyAll)
                    || self.opts.block_process_network
                {
                    self.restrict_child_net.store(true, Ordering::Release);
                }
                info!(
                    policy_id = %policy.id,
                    platform = support.platform,
                    "local-process kernel sandbox applied (irreversible)"
                );
                let _ = sink
                    .emit(RecordEvent::new(
                        SpaceId::from_string("pending"),
                        policy.id.clone(),
                        policy.task_id.clone(),
                        EventKind::Note {
                            message: format!(
                                "kernel sandbox applied via nono ({})",
                                support.platform
                            ),
                        },
                    ))
                    .await;
                Ok(())
            }
            Err(e) => {
                if self.opts.require_kernel {
                    Err(EnforceError::ApplyFailed(e.to_string()))
                } else {
                    warn!(error = %e, "kernel apply failed; soft-only");
                    self.applied.store(true, Ordering::Release);
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::profile_workspace;
    use keel_record::MemorySink;
    use std::sync::Arc;

    #[tokio::test]
    async fn maps_and_reports_info() {
        let b = LocalProcessBackend::new();
        let info = b.info();
        assert_eq!(info.name, "local-process");
    }

    /// Apply is process-wide and irreversible — only run when explicitly requested.
    #[tokio::test]
    async fn optional_kernel_apply_smoke() {
        if std::env::var("KEEL_KERNEL_TEST").ok().as_deref() != Some("1") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let policy = profile_workspace(dir.path()).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = LocalProcessBackend::with_options(LocalProcessOptions {
            require_kernel: true,
            block_process_network: false,
        });
        backend.apply(&policy, sink).await.unwrap();
        assert!(backend.is_applied());
    }
}
