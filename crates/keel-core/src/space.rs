use crate::error::{KeelError, KeelResult};
use crate::managed::ManagedProcess;
use crate::space_fs::SpaceFs;
use chrono::Utc;
use keel_enforce::{EnforceBackend, SpawnRequest};
use keel_policy::{Policy, SpaceId};
use keel_record::{
    default_space_sink, space_policy_path, EventKind, HashChainSink, MemorySink, MultiSink,
    RecordEvent, RecordSink,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
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
    /// If true, missing credential sources fail spawn (default false).
    pub strict_credentials: bool,
    /// If true, emit `Violation` events when check_fs / check_egress denies (default true).
    pub record_violations: bool,
    /// Wrap the record sink in a SHA-256 hash chain (`prev_hash` / `event_hash`, default true).
    pub integrity_chain: bool,
}

impl Default for SpaceOptions {
    fn default() -> Self {
        Self {
            persist_events: true,
            memory_events: false,
            persist_policy: true,
            strict_credentials: false,
            record_violations: true,
            integrity_chain: true,
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
    opts: SpaceOptions,
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

    /// Soft / **advisory** FS probe for UI hints and preflight messages.
    ///
    /// **Not a security boundary** when the host process is unconfined: a caller
    /// that does `check_fs` then raw `tokio::fs::write` still runs I/O outside
    /// Keel (TOCTOU + host bypass). Prefer [`Self::fs`] for tool Read/Write/Edit.
    ///
    /// For hard host isolation use [`Space::create_confined`] (Landlock/Seatbelt
    /// on this process, irreversible).
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
        let op = if write { "write" } else { "read" };
        self.inner
            .emit(EventKind::FsAccess {
                path: path.to_path_buf(),
                operation: format!("check_{op}"),
                allowed,
                content_sha256: None,
            })
            .await?;
        if !allowed && self.inner.opts.record_violations {
            self.inner
                .emit(EventKind::Violation {
                    operation: format!("check_{op}"),
                    target: path.display().to_string(),
                    detail: Some("advisory soft deny (use SpaceFs for real I/O)".into()),
                })
                .await?;
        }
        Ok(allowed)
    }

    /// Alias for [`Self::check_fs`] — name stresses advisory-only use.
    pub async fn check_fs_advisory(&self, path: &Path, write: bool) -> KeelResult<bool> {
        self.check_fs(path, write).await
    }

    /// Check whether dialing `host:port` is allowed by the space network policy.
    pub async fn check_egress(&self, host: &str, port: u16) -> KeelResult<bool> {
        self.inner.ensure_open().await?;
        if self.inner.policy.is_expired(Utc::now()) {
            return Err(keel_enforce::EnforceError::PolicyExpired.into());
        }
        let decision = keel_policy::check_egress(&self.inner.policy.network, host, port);
        let allowed = decision.is_allowed();
        self.inner
            .emit(EventKind::NetDial {
                host: host.to_string(),
                port: Some(port),
                allowed,
            })
            .await?;
        if !allowed && self.inner.opts.record_violations {
            let detail = match &decision {
                keel_policy::EgressDecision::Deny { reason } => Some(reason.clone()),
                keel_policy::EgressDecision::Allow => None,
            };
            self.inner
                .emit(EventKind::Violation {
                    operation: "connect".into(),
                    target: format!("{host}:{port}"),
                    detail,
                })
                .await?;
        }
        Ok(allowed)
    }

    /// **Preferred** filesystem API for host tools (Read / Write / Edit / Delete).
    ///
    /// Performs I/O under policy with resolve + audit. Still a **soft** boundary on an
    /// unconfined host — pair with [`Space::create_confined`] when the agent process
    /// itself must be sandboxed. See [`SpaceFs`] docs for TOCTOU guidance.
    pub fn fs(&self) -> SpaceFs {
        SpaceFs::new(self.clone())
    }

    /// Spawn under the space. Returns a [`ManagedProcess`] with stdio access, process-group
    /// kill on timeout/cancel, and `ExecFinished` audit events.
    pub async fn spawn(&self, mut req: SpawnRequest) -> KeelResult<ManagedProcess> {
        self.inner.ensure_open().await?;
        if self.inner.policy.is_expired(Utc::now()) {
            return Err(keel_enforce::EnforceError::PolicyExpired.into());
        }

        // JIT credentials: resolve from parent env/files, inject into child env.
        let resolved = keel_enforce::resolve_credentials(
            &self.inner.policy,
            self.inner.opts.strict_credentials,
        )?;
        let issued = keel_enforce::inject_into_env(&mut req.env, &resolved);
        for name in &issued {
            self.inner
                .emit(EventKind::CredentialIssued {
                    name: name.clone(),
                })
                .await?;
        }
        // Drop secret material from this task asap (child already has env copy).
        keel_enforce::revoke_resolved(resolved);

        let program = req.program.clone();
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
        Ok(ManagedProcess {
            inner: child,
            space: self.inner.clone(),
            program,
        })
    }

    /// Spawn and wait with a timeout (kills the process group on expiry).
    pub async fn spawn_timeout(
        &self,
        req: SpawnRequest,
        timeout: Duration,
    ) -> KeelResult<keel_enforce::ProcessExit> {
        self.spawn(req).await?.wait_timeout(timeout).await
    }

    /// Open a **new** space for a subtask with a policy that can only shrink reach.
    ///
    /// This is the per-task rebind primitive: never mutates the parent space.
    pub async fn open_task(
        &self,
        spec: keel_policy::TaskSpec,
        backend: Arc<dyn EnforceBackend>,
        opts: SpaceOptions,
    ) -> KeelResult<SpaceHandle> {
        self.inner.ensure_open().await?;
        let child_policy = keel_policy::narrow_policy(&self.inner.policy, spec)?;
        Space::create_with(child_policy, backend, opts).await
    }

    /// Convenience: open a task in a git/directory worktree under the parent workspace.
    pub async fn open_task_in_worktree(
        &self,
        spec: keel_policy::TaskSpec,
        opts: SpaceOptions,
    ) -> KeelResult<SpaceHandle> {
        let backend = Arc::new(keel_enforce::WorktreeBackend::new());
        self.open_task(spec, backend, opts).await
    }

    pub async fn run_capture(
        &self,
        program: &str,
        args: &[&str],
    ) -> KeelResult<std::process::Output> {
        let req = SpawnRequest::new(program).args(args.iter().map(|s| s.to_string()));
        let spawned = self.spawn(req).await?;
        let (_exit, output) = spawned.wait_with_output().await?;
        Ok(output)
    }

    pub async fn destroy(self) -> KeelResult<()> {
        self.inner.destroy_inner().await
    }
}

impl Space {
    /// Create a space with default persistence (`~/.keel/spaces/<id>/events.jsonl`).
    ///
    /// Default backends (when you pass `LocalProcessBackend::default`) keep the **host
    /// clean** and sandbox **children** only. For Grok-style whole-process confinement
    /// use [`Self::create_confined`].
    pub async fn create(
        policy: Policy,
        backend: Arc<dyn EnforceBackend>,
    ) -> KeelResult<SpaceHandle> {
        Self::create_with(policy, backend, SpaceOptions::default()).await
    }

    /// Create a space and apply Landlock/Seatbelt to **this process** (irreversible).
    ///
    /// This is the Grok-style model: one policy per OS process; agent host tools and
    /// accidental `std::fs` / sockets are constrained, not only `spawn` children.
    ///
    /// **Trade-offs**
    /// - Cannot open a second space with a different kernel policy in this process.
    /// - Requires unix + `local-process` kernel support (`require_kernel = true`).
    /// - `NetworkPolicy::DenyAll` also blocks host process network via nono options.
    ///
    /// Prefer the default [`Self::create`] + child isolate when embedding multiple
    /// concurrent spaces or when the host must keep unrestricted LLM/MCP sockets.
    pub async fn create_confined(
        policy: Policy,
        opts: SpaceOptions,
    ) -> KeelResult<SpaceHandle> {
        use keel_enforce::{LocalProcessBackend, LocalProcessOptions};
        use keel_policy::NetworkPolicy;

        // Only DenyAll fully blocks host net. Allowlist still needs host→LLM and
        // host→local proxy; children use ProxyOnly + CONNECT.
        let block_process_network = matches!(policy.network, NetworkPolicy::DenyAll);

        let backend = Arc::new(LocalProcessBackend::with_options(LocalProcessOptions {
            isolate_apply: false,
            require_kernel: true,
            block_process_network,
            ..LocalProcessOptions::default()
        }));
        Self::create_with(policy, backend, opts).await
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

        let base_sink: Arc<dyn RecordSink> = if let Some(s) = sink_override {
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
        let sink: Arc<dyn RecordSink> = if opts.integrity_chain {
            HashChainSink::wrap(base_sink)
        } else {
            base_sink
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
            opts: opts.clone(),
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

    pub(crate) async fn emit(&self, event: EventKind) -> KeelResult<()> {
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

        for name in keel_enforce::grant_names(&self.policy) {
            let _ = self
                .emit(EventKind::CredentialRevoked { name })
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

impl SpaceHandle {
    pub(crate) async fn emit_kind(&self, event: EventKind) -> KeelResult<()> {
        self.inner.emit(event).await
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
                ..Default::default()
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
    async fn integrity_chain_on_space_events() {
        use keel_record::verify_chain;

        let policy = profile_workspace(Path::new("/tmp/keel-chain-ws")).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with_sink(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                integrity_chain: true,
                ..Default::default()
            },
            Some(sink.clone()),
        )
        .await
        .unwrap();
        let _ = space
            .check_fs(Path::new("/tmp/keel-chain-ws/x"), false)
            .await
            .unwrap();
        space.destroy().await.unwrap();
        let events = sink.events().await;
        assert!(events.len() >= 2);
        assert!(events.iter().all(|e| e.event_hash.is_some()));
        assert!(verify_chain(&events).is_ok());
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
                ..Default::default()
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

    #[tokio::test]
    async fn spawn_timeout_kills_sleep() {
        use keel_enforce::{SpawnRequest, TerminationReason};
        use std::time::Duration;

        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with_sink(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                ..Default::default()
            },
            Some(sink.clone()),
        )
        .await
        .unwrap();

        // Shell that would outlive a direct kill of the shell without process group.
        let req = SpawnRequest::new("sh").args(["-c", "sleep 30"]);
        let exit = space
            .spawn(req)
            .await
            .unwrap()
            .wait_timeout(Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(exit.termination_reason, TerminationReason::TimedOut);

        let events = sink.events().await;
        assert!(events.iter().any(|e| matches!(
            &e.event,
            EventKind::ExecFinished {
                termination_reason,
                ..
            } if termination_reason == "timed_out"
        )));
        space.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn space_fs_write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = profile_workspace(ws).unwrap();
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let path = ws.join("note.txt");
        space.fs().write(&path, b"hello-zene").await.unwrap();
        let body = space.fs().read_to_string(&path).await.unwrap();
        assert_eq!(body, "hello-zene");

        // Outside workspace write should fail.
        let denied = space.fs().write("/etc/keel-should-not-write", b"x").await;
        assert!(denied.is_err());
        space.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn wait_with_output_timeout_collects_and_kills() {
        use keel_enforce::{SpawnRequest, TerminationReason};
        use std::time::Duration;

        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with_sink(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                ..Default::default()
            },
            Some(sink),
        )
        .await
        .unwrap();

        let req = SpawnRequest::new("sh").args(["-c", "echo hello-out; sleep 30"]);
        let (exit, out) = space
            .spawn(req)
            .await
            .unwrap()
            .wait_with_output_timeout(Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(exit.termination_reason, TerminationReason::TimedOut);
        assert!(String::from_utf8_lossy(&out.stdout).contains("hello-out"));
        space.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn wait_with_output_cancel_token() {
        use keel_enforce::{SpawnRequest, TerminationReason};
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let token = CancellationToken::new();
        let token2 = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            token2.cancel();
        });

        let req = SpawnRequest::new("sh").args(["-c", "sleep 30"]);
        let (exit, _out) = space
            .spawn(req)
            .await
            .unwrap()
            .wait_with_output_cancel(&token, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(exit.termination_reason, TerminationReason::Cancelled);
        space.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn space_fs_nested_create_path() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = profile_workspace(ws).unwrap();
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let nested = ws.join("foo").join("bar.txt");
        space.fs().write("foo/bar.txt", b"nested-ok").await.unwrap();
        assert_eq!(std::fs::read_to_string(&nested).unwrap(), "nested-ok");
        space.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn audit_args_false_redacts_exec_event() {
        use keel_enforce::SpawnRequest;

        let policy = profile_workspace(Path::new("/tmp")).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = Arc::new(ProcessGuardBackend::new());
        let space = Space::create_with_sink(
            policy,
            backend,
            SpaceOptions {
                persist_events: false,
                memory_events: true,
                persist_policy: false,
                ..Default::default()
            },
            Some(sink.clone()),
        )
        .await
        .unwrap();

        let req = SpawnRequest::new("echo")
            .args(["token=super-secret"])
            .audit_args(false);
        let (_exit, out) = space.spawn(req).await.unwrap().wait_with_output().await.unwrap();
        assert!(out.status.success());

        let events = sink.events().await;
        let exec = events.iter().find_map(|e| match &e.event {
            EventKind::Exec {
                args,
                args_redacted,
                ..
            } => Some((args.clone(), *args_redacted)),
            _ => None,
        });
        let (args, redacted) = exec.expect("Exec event");
        assert!(redacted);
        assert!(args.is_empty());
        assert!(!format!("{events:?}").contains("super-secret"));
        space.destroy().await.unwrap();
    }
}
