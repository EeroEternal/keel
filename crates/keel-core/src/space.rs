use crate::error::{KeelError, KeelResult};
use chrono::Utc;
use keel_enforce::{EnforceBackend, SpawnRequest, SpawnedProcess};
use keel_policy::{Policy, SpaceId};
use keel_record::{EventKind, RecordEvent, RecordSink};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceState {
    Creating,
    Open,
    Destroying,
    Destroyed,
}

/// Live execution space: one policy, one backend, one record stream.
pub struct Space {
    id: SpaceId,
    policy: Policy,
    backend: Arc<dyn EnforceBackend>,
    sink: Arc<dyn RecordSink>,
    state: RwLock<SpaceState>,
}

/// Public handle returned after create.
#[derive(Clone)]
pub struct SpaceHandle {
    inner: Arc<Space>,
}

impl SpaceHandle {
    pub fn id(&self) -> &SpaceId {
        &self.inner.id
    }

    pub fn policy(&self) -> &Policy {
        &self.inner.policy
    }

    pub fn backend_info(&self) -> keel_enforce::BackendInfo {
        self.inner.backend.info()
    }

    pub async fn state(&self) -> SpaceState {
        *self.inner.state.read().await
    }

    /// Soft FS check (and kernel check when backend supports it).
    pub async fn check_fs(&self, path: &Path, write: bool) -> KeelResult<bool> {
        self.inner.ensure_open().await?;
        if self.inner.policy.is_expired(Utc::now()) {
            return Err(keel_enforce::EnforceError::PolicyExpired.into());
        }
        let allowed = self
            .inner
            .backend
            .check_fs(&self.inner.policy, path, write)
            .await?;
        self.inner
            .emit(EventKind::FsAccess {
                path: path.to_path_buf(),
                operation: if write { "write" } else { "read" }.into(),
                allowed,
            })
            .await?;
        Ok(allowed)
    }

    /// Spawn a process under this space's policy.
    pub async fn spawn(&self, req: SpawnRequest) -> KeelResult<SpawnedProcess> {
        self.inner.ensure_open().await?;
        let child = self
            .inner
            .backend
            .spawn(
                &self.inner.id,
                &self.inner.policy,
                req,
                self.inner.sink.clone(),
            )
            .await?;
        Ok(child)
    }

    /// Run a command to completion, capturing stdout/stderr (UTF-8 lossy).
    pub async fn run_capture(
        &self,
        program: &str,
        args: &[&str],
    ) -> KeelResult<std::process::Output> {
        let req = SpawnRequest::new(program).args(args.iter().map(|s| s.to_string()));
        let spawned = self.spawn(req).await?;
        let output = spawned.child.wait_with_output().await?;
        Ok(output)
    }

    /// Destroy the space: revoke credentials (future), backend teardown, final record.
    pub async fn destroy(self) -> KeelResult<()> {
        self.inner.destroy_inner().await
    }
}

impl Space {
    /// Create and apply a new space.
    pub async fn create(
        policy: Policy,
        backend: Arc<dyn EnforceBackend>,
        sink: Arc<dyn RecordSink>,
    ) -> KeelResult<SpaceHandle> {
        policy.validate()?;
        if policy.is_expired(Utc::now()) {
            return Err(keel_enforce::EnforceError::PolicyExpired.into());
        }

        let id = SpaceId::new();
        let space = Arc::new(Space {
            id: id.clone(),
            policy: policy.clone(),
            backend: backend.clone(),
            sink: sink.clone(),
            state: RwLock::new(SpaceState::Creating),
        });

        space
            .emit(EventKind::SpaceCreated {
                backend: backend.info().name.to_string(),
                label: policy.label.clone(),
            })
            .await?;
        space
            .emit(EventKind::PolicyBound {
                label: policy.label.clone(),
            })
            .await?;

        backend.apply(&policy, sink.clone()).await?;

        *space.state.write().await = SpaceState::Open;
        info!(
            space_id = %id,
            policy_id = %policy.id,
            backend = backend.info().name,
            "keel space open"
        );

        Ok(SpaceHandle { inner: space })
    }

    async fn ensure_open(&self) -> KeelResult<()> {
        match *self.state.read().await {
            SpaceState::Open => Ok(()),
            SpaceState::Creating => Err(KeelError::NotOpen("creating")),
            SpaceState::Destroying => Err(KeelError::NotOpen("destroying")),
            SpaceState::Destroyed => Err(KeelError::NotOpen("destroyed")),
        }
    }

    async fn emit(&self, event: EventKind) -> KeelResult<()> {
        self.sink
            .emit(RecordEvent::new(
                self.id.clone(),
                self.policy.id.clone(),
                self.policy.task_id.clone(),
                event,
            ))
            .await?;
        Ok(())
    }

    async fn destroy_inner(self: &Arc<Self>) -> KeelResult<()> {
        {
            let mut st = self.state.write().await;
            if matches!(*st, SpaceState::Destroyed | SpaceState::Destroying) {
                return Ok(());
            }
            *st = SpaceState::Destroying;
        }

        for cred in &self.policy.credentials {
            let _ = self
                .emit(EventKind::CredentialRevoked {
                    name: cred.name.clone(),
                })
                .await;
        }

        if let Err(e) = self.backend.destroy(&self.policy, self.sink.clone()).await {
            warn!(error = %e, "backend destroy failed");
        }

        self.emit(EventKind::SpaceDestroyed {
            reason: "explicit".into(),
        })
        .await?;
        let _ = self.sink.flush().await;

        *self.state.write().await = SpaceState::Destroyed;
        info!(space_id = %self.id, "keel space destroyed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_enforce::ProcessGuardBackend;
    use keel_policy::profile_workspace;
    use keel_record::MemorySink;
    use std::path::Path;
    use std::sync::Arc;

    #[tokio::test]
    async fn create_check_destroy() {
        let policy = profile_workspace(Path::new("/tmp/keel-test-ws")).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create(policy, backend, sink.clone())
            .await
            .unwrap();

        assert!(space
            .check_fs(Path::new("/tmp/keel-test-ws/foo.rs"), true)
            .await
            .unwrap());
        assert!(!space
            .check_fs(Path::new("/etc/shadow"), true)
            .await
            .unwrap());

        space.destroy().await.unwrap();
        assert!(sink.len().await >= 3);
    }

    #[tokio::test]
    async fn spawn_echo() {
        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create(policy, backend, sink).await.unwrap();

        let out = space.run_capture("echo", &["keel-ok"]).await.unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("keel-ok"));
        space.destroy().await.unwrap();
    }
}
