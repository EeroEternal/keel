//! `local-process` backend: OS-level child isolation.
//!
//! | Platform | Mechanism |
//! |----------|-----------|
//! | Linux | Landlock + optional bwrap + seccomp (via nono) |
//! | macOS | Seatbelt (via nono) |
//! | Windows | **Job Objects** (`KILL_ON_JOB_CLOSE`) + soft FS policy; restricted-token probe |
//!
//! ## Default semantics (`isolate_apply = true`)
//!
//! - Host process is **not** sandboxed (Unix kernel / Windows host token unchanged).
//! - On `spawn`, children are isolated (Unix pre_exec sandbox / Windows Job).
//! - On Linux, deny paths are enforced with **bubblewrap** bind-over (read-deny).
//! - Parent keeps network for LLM/MCP.
//! - `DenyAll`: child net blocked (kernel Blocked / Linux seccomp).
//! - `Allowlist`: parent runs a localhost CONNECT proxy; children get proxy env
//!   and kernel `ProxyOnly` so they may only dial the proxy port.
//!
//! ## Legacy / confined (`isolate_apply = false`)
//!
//! - Unix: `apply()` sandboxes the **current** process (irreversible).
//! - Windows: host cannot be put in a Job that kills itself usefully; apply records
//!   Job capability and still isolates **children**.

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
use crate::sandbox_child;

/// Process-global: policy id when host-applied (isolate_apply = false only).
static KERNEL_APPLIED_POLICY: OnceLock<String> = OnceLock::new();

/// Options for [`LocalProcessBackend`].
#[derive(Debug, Clone)]
pub struct LocalProcessOptions {
    /// Fail if the platform cannot enforce kernel FS / Job isolation (default true).
    pub require_kernel: bool,
    /// Block network for the sandboxed process via nono (default false). Unix mainly.
    pub block_process_network: bool,
    /// If true (default), apply kernel sandbox only in children, not the host.
    pub isolate_apply: bool,
    /// On Linux, when deny paths/globs are present, use bubblewrap automatically
    /// if available (default true). When denials exist, bwrap is missing, and
    /// [`Self::require_kernel`] is true, apply fails closed.
    pub auto_bwrap: bool,
    /// Windows: place each child in a Job Object (default true).
    pub windows_job: bool,
    /// Windows: probe/create restricted tokens (default true; spawn still Job-based).
    pub windows_restricted_token: bool,
}

impl Default for LocalProcessOptions {
    fn default() -> Self {
        Self {
            require_kernel: true,
            block_process_network: false,
            isolate_apply: true,
            auto_bwrap: true,
            windows_job: true,
            windows_restricted_token: true,
        }
    }
}

impl LocalProcessOptions {
    /// Host-applied kernel sandbox (irreversible). Same as `isolate_apply: false`.
    pub fn confine_host() -> Self {
        Self {
            isolate_apply: false,
            require_kernel: true,
            ..Self::default()
        }
    }
}

/// Landlock / Seatbelt enforce backend.
pub struct LocalProcessBackend {
    opts: LocalProcessOptions,
    applied: AtomicBool,
    restrict_child_net: AtomicBool,
    /// Active egress proxy when policy is an allowlist.
    egress: tokio::sync::Mutex<Option<Arc<crate::egress_proxy::EgressProxy>>>,
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
            egress: tokio::sync::Mutex::new(None),
        }
    }

    pub fn process_has_kernel_sandbox() -> bool {
        KERNEL_APPLIED_POLICY.get().is_some()
    }

    pub fn is_applied(&self) -> bool {
        self.applied.load(Ordering::Acquire)
    }

    pub fn restricts_child_network(&self) -> bool {
        self.restrict_child_net.load(Ordering::Acquire)
    }

    pub fn options(&self) -> &LocalProcessOptions {
        &self.opts
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
            // Unix Landlock/Seatbelt only. Windows Jobs are process-tree isolation
            // (soft FS policy still applies); full AppContainer FS ACLs are deferred.
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
            if self.opts.isolate_apply {
                return self.apply_isolated_prepare(policy, sink).await;
            }
            return self.apply_on_host(policy, sink).await;
        }

        #[cfg(all(windows, feature = "kernel"))]
        {
            return self.apply_windows(policy, sink).await;
        }

        #[cfg(not(any(
            all(unix, feature = "kernel"),
            all(windows, feature = "kernel")
        )))]
        {
            let msg = "local-process kernel backend requires unix/windows + feature `kernel`";
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
                    args: audit_args,
                    allowed: true,
                    args_redacted,
                },
            ))
            .await;

        #[cfg(all(unix, feature = "kernel"))]
        {
            return self.spawn_sandboxed(policy, req).await;
        }

        #[cfg(all(windows, feature = "kernel"))]
        {
            return self.spawn_windows(policy, req).await;
        }

        #[cfg(not(any(
            all(unix, feature = "kernel"),
            all(windows, feature = "kernel")
        )))]
        {
            let process_group = req.process_group;
            let mut cmd = base_command(&req);
            let child = cmd.spawn()?;
            Ok(SpawnedProcess::new(child, process_group))
        }
    }

    async fn destroy(&self, _policy: &Policy, _sink: Arc<dyn RecordSink>) -> EnforceResult<()> {
        let mut guard = self.egress.lock().await;
        if let Some(proxy) = guard.take() {
            proxy.shutdown();
        }
        Ok(())
    }
}

#[cfg(all(windows, feature = "kernel"))]
impl LocalProcessBackend {
    async fn apply_windows(
        &self,
        policy: &Policy,
        sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<()> {
        let win_opts = crate::windows_sandbox::WindowsSandboxOptions {
            use_job: self.opts.windows_job,
            use_restricted_token: self.opts.windows_restricted_token,
        };

        if self.opts.windows_job {
            match crate::windows_sandbox::Job::create() {
                Ok(job) => {
                    // Probe only — per-child jobs are created at spawn.
                    drop(job);
                }
                Err(e) => {
                    let msg = format!("Windows Job Object unavailable: {e}");
                    if self.opts.require_kernel {
                        return Err(EnforceError::Unsupported(msg));
                    }
                    warn!("{msg}; soft process-guard only");
                }
            }
        }

        if self.opts.windows_restricted_token {
            match crate::windows_sandbox::try_create_restricted_token() {
                Ok(_tok) => {
                    info!("Windows restricted token API available");
                }
                Err(e) => {
                    warn!(error = %e, "Windows restricted token probe failed (continuing with jobs)");
                }
            }
        }

        // Optional egress proxy for allowlists (proxy-aware tools).
        let mut egress_note = String::new();
        if matches!(policy.network, NetworkPolicy::Allowlist(_)) {
            let proxy =
                crate::egress_proxy::EgressProxy::start(policy.network.clone()).await?;
            egress_note = format!("egress proxy on {}", proxy.proxy_url());
            *self.egress.lock().await = Some(Arc::new(proxy));
        }

        if matches!(policy.network, NetworkPolicy::DenyAll) || self.opts.block_process_network {
            self.restrict_child_net.store(true, Ordering::Release);
        }

        self.applied.store(true, Ordering::Release);
        let caps = crate::windows_sandbox::capability_summary(&win_opts);
        let msg = if egress_note.is_empty() {
            format!("local-process Windows: {caps}")
        } else {
            format!("local-process Windows: {caps}; {egress_note}")
        };
        info!(policy_id = %policy.id, "{msg}");
        let _ = sink
            .emit(RecordEvent::new(
                SpaceId::from_string("pending"),
                policy.id.clone(),
                policy.task_id.clone(),
                EventKind::Note { message: msg },
            ))
            .await;
        Ok(())
    }

    async fn spawn_windows(
        &self,
        policy: &Policy,
        mut req: SpawnRequest,
    ) -> EnforceResult<SpawnedProcess> {
        // Soft FS: program path when absolute.
        let prog = Path::new(&req.program);
        if prog.is_absolute() && !process_guard::soft_fs_allowed(policy, prog, false) {
            return Err(EnforceError::Denied(format!(
                "program path not readable under policy: {}",
                prog.display()
            )));
        }

        // Inject egress proxy env for allowlisted spaces.
        {
            let guard = self.egress.lock().await;
            if let Some(proxy) = guard.as_ref() {
                for (k, v) in proxy.env_vars() {
                    if !req.env.iter().any(|(ek, _)| ek == &k) {
                        req.env.push((k, v));
                    }
                }
            }
        }

        let process_group = req.process_group;
        let mut cmd = base_command(&req);
        let child = cmd.spawn()?;

        if self.opts.windows_job {
            match crate::windows_sandbox::Job::create() {
                Ok(job) => {
                    if let Some(pid) = child.id() {
                        if let Err(e) = job.assign_pid(pid) {
                            warn!(error = %e, pid, "AssignProcessToJobObject failed");
                            if self.opts.require_kernel {
                                // Best-effort kill the orphaned child.
                                let mut orphan = SpawnedProcess::new(child, process_group);
                                let _ = orphan.kill_tree();
                                return Err(EnforceError::ApplyFailed(format!(
                                    "failed to assign child to Job Object: {e}"
                                )));
                            }
                            return Ok(SpawnedProcess::new(child, process_group));
                        }
                    }
                    return Ok(SpawnedProcess::with_job(child, process_group, job));
                }
                Err(e) => {
                    if self.opts.require_kernel {
                        let mut orphan = SpawnedProcess::new(child, process_group);
                        let _ = orphan.kill_tree();
                        return Err(EnforceError::ApplyFailed(format!(
                            "CreateJobObject failed: {e}"
                        )));
                    }
                    warn!(error = %e, "CreateJobObject failed; child without job");
                    return Ok(SpawnedProcess::new(child, process_group));
                }
            }
        }

        Ok(SpawnedProcess::new(child, process_group))
    }
}

#[cfg(all(unix, feature = "kernel"))]
impl LocalProcessBackend {
    /// Prepare only: validate mapping; start egress proxy for allowlists.
    async fn apply_isolated_prepare(
        &self,
        policy: &Policy,
        sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<()> {
        // Start egress proxy before prepare_kernel so ProxyOnly port can be known
        // at spawn time (injected via env for child pre_exec).
        let mut egress_note = String::new();
        if matches!(policy.network, NetworkPolicy::Allowlist(_)) {
            let proxy =
                crate::egress_proxy::EgressProxy::start(policy.network.clone()).await?;
            egress_note = format!("egress proxy on {}", proxy.proxy_url());
            info!(%egress_note, "started egress allowlist proxy");
            *self.egress.lock().await = Some(Arc::new(proxy));
        }

        // prepare_kernel without proxy env still validates FS mapping.
        match sandbox_child::prepare_kernel(policy, self.opts.block_process_network) {
            Ok(()) => {}
            Err(e) if !self.opts.require_kernel => {
                warn!(error = %e, "kernel prepare failed; children will soft-check only");
                self.applied.store(true, Ordering::Release);
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        #[cfg(target_os = "linux")]
        {
            let mut denies = crate::bwrap::deny_paths_for_bwrap(policy);
            if let Ok(extra) = crate::deny_glob::expand_deny_globs(policy) {
                denies.extend(extra);
            }
            if !denies.is_empty() {
                if crate::bwrap::bwrap_available() && self.opts.auto_bwrap {
                    info!(
                        deny_count = denies.len(),
                        "Linux bwrap auto-enabled for read-deny paths/globs"
                    );
                } else if !crate::bwrap::bwrap_available() {
                    let msg = "Linux read-deny requires bubblewrap (bwrap) when deny paths/globs \
                         are present (baseline credential denies included); install bwrap \
                         or set require_kernel=false / clear denies";
                    if self.opts.require_kernel {
                        return Err(EnforceError::ApplyFailed(msg.into()));
                    }
                    warn!("{msg}");
                }
            }
        }

        // DenyAll → child net blocked via seccomp. Allowlist uses ProxyOnly + proxy env
        // (direct connect bypass is blocked where ProxyOnly is applied in the child).
        if matches!(policy.network, NetworkPolicy::DenyAll) || self.opts.block_process_network {
            self.restrict_child_net.store(true, Ordering::Release);
        }
        if matches!(policy.network, NetworkPolicy::Allowlist(_)) {
            // Ensure callers see enforcement model in the audit stream.
            egress_note = if egress_note.is_empty() {
                "allowlist: CONNECT proxy + child ProxyOnly (install proxy-aware tools)".into()
            } else {
                format!(
                    "{egress_note}; allowlist enforces ProxyOnly on sandboxed children"
                )
            };
        }
        self.applied.store(true, Ordering::Release);
        info!(
            policy_id = %policy.id,
            isolate = true,
            "local-process ready (kernel apply deferred to children)"
        );
        let msg = if egress_note.is_empty() {
            "local-process isolate_apply: host unsandboxed; children apply kernel FS".into()
        } else {
            format!(
                "local-process isolate_apply: host unsandboxed; children apply kernel FS; {egress_note}"
            )
        };
        let _ = sink
            .emit(RecordEvent::new(
                SpaceId::from_string("pending"),
                policy.id.clone(),
                policy.task_id.clone(),
                EventKind::Note { message: msg },
            ))
            .await;
        Ok(())
    }

    /// Legacy: sandbox the host process.
    async fn apply_on_host(
        &self,
        policy: &Policy,
        sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<()> {
        use nono::Sandbox;

        let support = Sandbox::support_info();
        if !support.is_supported {
            let details = support.details.clone();
            if self.opts.require_kernel {
                return Err(EnforceError::Unsupported(details));
            }
            warn!(details = %details, "kernel sandbox unsupported; soft-only");
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
            self.applied.store(true, Ordering::Release);
            return Ok(());
        }

        sandbox_child::apply_kernel_here(policy, self.opts.block_process_network)?;
        let _ = KERNEL_APPLIED_POLICY.set(policy.id.to_string());
        self.applied.store(true, Ordering::Release);
        if matches!(policy.network, NetworkPolicy::DenyAll) || self.opts.block_process_network {
            self.restrict_child_net.store(true, Ordering::Release);
        }
        let _ = sink
            .emit(RecordEvent::new(
                SpaceId::from_string("pending"),
                policy.id.clone(),
                policy.task_id.clone(),
                EventKind::Note {
                    message: format!(
                        "kernel sandbox applied on host via nono ({})",
                        support.platform
                    ),
                },
            ))
            .await;
        Ok(())
    }

    async fn spawn_sandboxed(
        &self,
        policy: &Policy,
        mut req: SpawnRequest,
    ) -> EnforceResult<SpawnedProcess> {
        // Full block only for DenyAll; allowlist uses ProxyOnly + CONNECT proxy.
        let restrict_net = self.restrict_child_net.load(Ordering::Acquire)
            || matches!(policy.network, NetworkPolicy::DenyAll);
        let isolate = self.opts.isolate_apply;
        let block_net = self.opts.block_process_network;
        let require_kernel = self.opts.require_kernel;

        // Inject egress proxy env for allowlisted spaces (proxy-aware tools).
        let proxy_port = {
            let guard = self.egress.lock().await;
            if let Some(proxy) = guard.as_ref() {
                for (k, v) in proxy.env_vars() {
                    if !req.env.iter().any(|(ek, _)| ek == &k) {
                        req.env.push((k, v));
                    }
                }
                Some(proxy.port())
            } else {
                None
            }
        };

        // Validate mapping early (parent).
        if isolate {
            if let Err(e) = sandbox_child::prepare_kernel(policy, block_net) {
                if require_kernel {
                    return Err(e);
                }
                warn!(error = %e, "spawn without kernel apply");
            }
        }

        let policy_file = if isolate {
            Some(sandbox_child::write_spawn_policy_file(policy)?)
        } else {
            None
        };

        // Prefer bwrap outer command when Linux deny paths exist.
        #[cfg(target_os = "linux")]
        let mut cmd = {
            let mut deny_paths = crate::bwrap::deny_paths_for_bwrap(policy);
            // Phase 2: expand deny globs into concrete paths for bwrap.
            match crate::deny_glob::expand_deny_globs(policy) {
                Ok(extra) => deny_paths.extend(extra),
                Err(e) if require_kernel => return Err(e),
                Err(e) => warn!(error = %e, "deny glob expand failed"),
            }
            deny_paths.sort();
            deny_paths.dedup();
            if let Some(mut bwrap_cmd) = crate::bwrap::wrap_command(
                &req.program,
                &req.args,
                &deny_paths,
                req.cwd.as_deref(),
                &req.env,
            )? {
                crate::backend::apply_stdio_std(&mut bwrap_cmd, &req);
                let mut cmd = tokio::process::Command::from(bwrap_cmd);
                #[cfg(unix)]
                if req.process_group {
                    cmd.process_group(0);
                }
                cmd.kill_on_drop(true);
                attach_child_hooks(
                    &mut cmd,
                    isolate,
                    policy_file.clone(),
                    block_net,
                    restrict_net,
                    proxy_port,
                );
                cmd
            } else {
                let mut cmd = base_command(&req);
                attach_child_hooks(
                    &mut cmd,
                    isolate,
                    policy_file.clone(),
                    block_net,
                    restrict_net,
                    proxy_port,
                );
                cmd
            }
        };
        #[cfg(not(target_os = "linux"))]
        let mut cmd = {
            let mut cmd = base_command(&req);
            attach_child_hooks(
                &mut cmd,
                isolate,
                policy_file.clone(),
                block_net,
                restrict_net,
                proxy_port,
            );
            cmd
        };

        let process_group = req.process_group;
        let child = cmd.spawn().map_err(|e| {
            if let Some(pf) = &policy_file {
                let _ = std::fs::remove_file(pf);
            }
            e
        })?;

        Ok(SpawnedProcess::new(child, process_group))
    }
}

#[cfg(all(unix, feature = "kernel"))]
fn attach_child_hooks(
    cmd: &mut tokio::process::Command,
    isolate: bool,
    policy_file: Option<std::path::PathBuf>,
    block_net: bool,
    restrict_net: bool,
    proxy_port: Option<u16>,
) {
    // tokio::process::Command::pre_exec requires the Unix CommandExt trait.
    #[allow(unused_imports)]
    use std::os::unix::process::CommandExt as _;
    if isolate {
        if let Some(pf) = policy_file {
            unsafe {
                cmd.pre_exec(move || {
                    if let Some(port) = proxy_port {
                        // SAFETY: child-only; configures ProxyOnly for apply_kernel_here.
                        std::env::set_var(
                            crate::egress_proxy::EGRESS_PROXY_PORT_ENV,
                            port.to_string(),
                        );
                    }
                    match sandbox_child::apply_policy_file_and_ready(&pf, block_net) {
                        Ok(_) => {}
                        Err(e) => return Err(std::io::Error::other(e.to_string())),
                    }
                    // DenyAll: full network seccomp. Allowlist: ProxyOnly (kernel) +
                    // server-block seccomp (no bind/listen); connect kept for HTTP_PROXY.
                    if restrict_net {
                        crate::child_net::install_child_network_filter()?;
                    } else if proxy_port.is_some() {
                        crate::child_net::install_child_server_block_filter()?;
                    }
                    let _ = std::fs::remove_file(&pf);
                    Ok(())
                });
            }
        }
    } else if restrict_net {
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(|| crate::child_net::install_child_network_filter());
        }
        #[cfg(not(target_os = "linux"))]
        let _ = restrict_net;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::profile_workspace;
    use keel_record::MemorySink;
    use std::sync::Arc;

    #[tokio::test]
    async fn isolate_prepare_does_not_mark_host_kernel() {
        let dir = tempfile::tempdir().unwrap();
        let policy = profile_workspace(dir.path()).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = LocalProcessBackend::new(); // isolate_apply default true
        // On macOS/Linux with kernel support this succeeds without host apply.
        let result = backend.apply(&policy, sink).await;
        // May fail on unsupported platforms in CI — only assert structure when ok.
        if result.is_ok() {
            assert!(backend.is_applied());
            // Host should not have KERNEL_APPLIED_POLICY set in isolate mode.
            assert!(!LocalProcessBackend::process_has_kernel_sandbox());
        }
    }

    #[tokio::test]
    async fn maps_and_reports_info() {
        let b = LocalProcessBackend::new();
        assert_eq!(b.info().name, "local-process");
        assert!(b.options().isolate_apply);
    }

    /// Host apply path — only when explicitly requested.
    #[tokio::test]
    async fn optional_host_kernel_apply_smoke() {
        if std::env::var("KEEL_KERNEL_TEST").ok().as_deref() != Some("1") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let policy = profile_workspace(dir.path()).unwrap();
        let sink = Arc::new(MemorySink::new());
        let backend = LocalProcessBackend::with_options(LocalProcessOptions {
            require_kernel: true,
            block_process_network: false,
            isolate_apply: false,
            ..Default::default()
        });
        backend.apply(&policy, sink).await.unwrap();
        assert!(backend.is_applied());
        assert!(LocalProcessBackend::process_has_kernel_sandbox());
    }
}
