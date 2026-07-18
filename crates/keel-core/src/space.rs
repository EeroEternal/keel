use crate::error::{KeelError, KeelResult};
use chrono::Utc;
use keel_enforce::{EnforceBackend, SpawnRequest, SpawnedProcess};
use keel_policy::{Policy, SpaceId};
use keel_record::{
    default_space_sink, space_policy_path, EventKind, MemorySink, MultiSink, RecordEvent,
    RecordSink,
};
use std::path::{Path, PathBuf};
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

/// Options for opening a space.
#[derive(Debug, Clone)]
pub struct SpaceOptions {
    /// Persist events to `~/.keel/spaces/<id>/events.jsonl` (default true).
    pub persist_events: bool,
    /// Also keep an in-memory copy of events (default false; true when useful for tests/CLI --trace).
    pub memory_events: bool,
    /// Write `policy.json` next to events (default true when persist_events).
    pub persist_policy: bool,
}

impl Default for SpaceOptions {
    fn default() -> Self {
        Self {
            persist_events: true,
            memory_events: false,
            persist_policy: true,
        }
    }
}

/// Live execution space: one policy, one backend, one record stream.
pub struct Space {
    id: SpaceId,
    policy: Policy,
    backend: Arc<dyn EnforceBackend>,
    sink: Arc<dyn RecordSink>,
    events_path: Option<PathBuf>,
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

    /// Path to JSONL events when persistence is enabled.
    pub fn events_path(&self) -> Option<&Path> {
        self.inner.events_path.as_deref()
    }

    pub fn backend_info(&self) -> keel_enforce::BackendInfo {
        self.inner.backend.info()
    }

    pub async fn state(&self) -> SpaceState {
        *self.inner.state.read().await
    }

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

    pub async fn destroy(self) -> KeelResult<()> {
        self.inner.destroy_inner().await
    }
}

impl Space {
    /// Create a space with default persistence (`~/.keel/spaces/<id>/events.jsonl`).
    pub async fn create(
        policy: Policy,
        backend: Arc<dyn EnforceBackend>,
    ) -> KeelResult<SpaceHandle> {
        Self::create_with(policy, backend, SpaceOptions::default()).await
    }

    /// Create with explicit options and optional pre-built sink override.
    pub async fn create_with(
        policy: Policy,
        backend: Arc<dyn EnforceBackend>,
        opts: SpaceOptions,
    ) -> KeelResult<SpaceHandle> {
        Self::create_with_sink(policy, backend, opts, None).await
    }

    /// Full constructor: optional sink override (e.g. tests inject `MemorySink` only).
    pub async fn create_with_sink(
        policy: Policy,
        backend: Arc<dyn EnforceBackend>,
        opts: SpaceOptions,
        sink_override: Option<Arc<dyn RecordSink>>,
    ) -> KeelResult<SpaceHandle> {
        policy.validate()?;
        if policy.is_expired(Utc::now()) {
            return Err(keel_enforce::EnforceError::PolicyExpired.into());
        }

        let id = SpaceId::new();
        let mut events_path = None;

        let sink: Arc<dyn RecordSink> = if let Some(s) = sink_override {
            s
        } else {
            let mut parts: Vec<Arc<dyn RecordSink>> = Vec::new();
            if opts.memory_events {
                parts.push(Arc::new(MemorySink::new()));
            }
            if opts.persist_events {
                let jsonl = default_space_sink(&id).await?;
                events_path = Some(jsonl.path().to_path_buf());
                parts.push(Arc::new(jsonl));
            }
            if parts.is_empty() {
                // Always have at least a memory sink so events are not dropped.
                parts.push(Arc::new(MemorySink::new()));
            }
            if parts.len() == 1 {
                parts.pop().unwrap()
            } else {
                Arc::new(MultiSink::new(parts))
            }
        };

        if opts.persist_policy && opts.persist_events {
            let path = space_policy_path(&id);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = policy.to_json() {
                let _ = std::fs::write(&path, json);
            }
        }

        let space = Arc::new(Space {
            id: id.clone(),
            policy: policy.clone(),
            backend: backend.clone(),
            sink: sink.clone(),
            events_path,
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
            events = ?space.events_path,
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
    use std::sync::Arc;

    #[tokio::test]
    async fn create_check_destroy_memory_only() {
        let policy = profile_workspace(Path::new("/tmp/keel-test-ws")).unwrap();
        let sink: Arc<dyn RecordSink> = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with_sink(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
            },
            Some(sink.clone()),
        )
        .await
        .unwrap();

        assert!(space
            .check_fs(Path::new("/tmp/keel-test-ws/foo.rs"), true)
            .await
            .unwrap());
        space.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn create_persists_events() {
        let dir = tempfile::tempdir().unwrap();
        // Isolate home for this test.
        // SAFETY: test-only env mutation, single-threaded for this var.
        unsafe {
            std::env::set_var("KEEL_HOME", dir.path());
        }
        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create(policy, backend).await.unwrap();
        let path = space.events_path().unwrap().to_path_buf();
        space
            .check_fs(Path::new("/tmp/x"), false)
            .await
            .unwrap();
        space.destroy().await.unwrap();
        assert!(path.is_file());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"kind\""));
        unsafe {
            std::env::remove_var("KEEL_HOME");
        }
    }

    #[tokio::test]
    async fn spawn_echo() {
        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let sink: Arc<dyn RecordSink> = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with_sink(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
            },
            Some(sink),
        )
        .await
        .unwrap();

        let out = space.run_capture("echo", &["keel-ok"]).await.unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("keel-ok"));
        space.destroy().await.unwrap();
    }
}
