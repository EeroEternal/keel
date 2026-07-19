//! Null backend: no kernel isolation. Still records and soft-checks policy.

use crate::backend::{base_command, BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
use crate::error::{EnforceError, EnforceResult};
use crate::process_guard;
use async_trait::async_trait;
use chrono::Utc;
use keel_policy::{ExecPolicy, Policy, SpaceId};
use keel_record::{EventKind, RecordEvent, RecordSink};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

pub struct NullBackend;

impl NullBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforceBackend for NullBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "null",
            kernel_fs: false,
            child_network: false,
        }
    }

    async fn apply(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        if policy.is_expired(Utc::now()) {
            return Err(EnforceError::PolicyExpired);
        }
        policy.validate()?;
        info!(
            policy_id = %policy.id,
            backend = "null",
            "policy applied (soft only — no kernel isolation)"
        );
        // Core records SpaceCreated/PolicyBound with the real space id.
        let _ = sink;
        let _ = policy;
        Ok(())
    }

    async fn check_fs(&self, policy: &Policy, path: &Path, write: bool) -> EnforceResult<bool> {
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
        let (audit_args, args_redacted) = req.audit_args_for_event();
        if matches!(policy.exec, ExecPolicy::Deny) {
            sink.emit(RecordEvent::new(
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
            .await?;
            return Err(EnforceError::Denied("exec denied by policy".into()));
        }

        // Soft path checks against cwd when present.
        if let Some(cwd) = &req.cwd {
            if !process_guard::soft_fs_allowed(policy, cwd, false) {
                return Err(EnforceError::Denied(format!(
                    "cwd not readable under policy: {}",
                    cwd.display()
                )));
            }
        }

        sink.emit(RecordEvent::new(
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
        .await?;

        let process_group = req.process_group;
        let mut cmd = base_command(&req);
        let child = cmd.spawn()?;
        Ok(SpawnedProcess::new(child, process_group))
    }

    async fn destroy(&self, _policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        Ok(())
    }
}
