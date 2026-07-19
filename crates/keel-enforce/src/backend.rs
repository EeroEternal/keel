use crate::error::EnforceResult;
use async_trait::async_trait;
use keel_policy::{Policy, SpaceId};
use keel_record::RecordSink;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: &'static str,
    /// True if the backend applies kernel-level FS isolation.
    pub kernel_fs: bool,
    /// True if the backend can restrict child process network.
    pub child_network: bool,
}

/// How to connect a child's standard stream.
///
/// Defaults match historical Keel CLI capture (`stdin` null, `stdout`/`stderr` piped).
/// MCP stdio servers need `stdin` (and usually `stdout`) set to [`StdioMode::Piped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StdioMode {
    /// Connected to `/dev/null` (or equivalent).
    #[default]
    Null,
    /// Inherit the parent process stream.
    Inherit,
    /// Create a pipe; available via [`tokio::process::Child`]'s stdio fields.
    Piped,
}

impl StdioMode {
    pub fn to_std(self) -> Stdio {
        match self {
            StdioMode::Null => Stdio::null(),
            StdioMode::Inherit => Stdio::inherit(),
            StdioMode::Piped => Stdio::piped(),
        }
    }
}

/// Why a managed process stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    /// Process called exit / returned normally.
    Exited,
    /// Wait timed out; Keel sent kill to the process group (when enabled).
    TimedOut,
    /// Host asked to cancel / kill the tree.
    Cancelled,
    /// Explicit kill without a prior timeout classification.
    Killed,
    /// Terminated by a signal (Unix); `signal` is the signal number when known.
    Signal,
    /// Could not classify.
    Unknown,
}

impl TerminationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TerminationReason::Exited => "exited",
            TerminationReason::TimedOut => "timed_out",
            TerminationReason::Cancelled => "cancelled",
            TerminationReason::Killed => "killed",
            TerminationReason::Signal => "signal",
            TerminationReason::Unknown => "unknown",
        }
    }
}

/// Result of waiting on a [`SpawnedProcess`].
#[derive(Debug, Clone)]
pub struct ProcessExit {
    pub status: ExitStatus,
    pub exit_code: Option<i32>,
    pub duration: Duration,
    pub termination_reason: TerminationReason,
    /// Unix signal number when termination was via signal (best-effort).
    pub signal: Option<i32>,
}

impl ProcessExit {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    fn from_status(status: ExitStatus, started: Instant, reason: TerminationReason) -> Self {
        let (exit_code, signal, reason) = classify_status(status, reason);
        Self {
            status,
            exit_code,
            duration: started.elapsed(),
            termination_reason: reason,
            signal,
        }
    }
}

fn classify_status(
    status: ExitStatus,
    preferred: TerminationReason,
) -> (Option<i32>, Option<i32>, TerminationReason) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            let reason = if preferred == TerminationReason::TimedOut
                || preferred == TerminationReason::Cancelled
                || preferred == TerminationReason::Killed
            {
                preferred
            } else {
                TerminationReason::Signal
            };
            return (None, Some(sig), reason);
        }
    }
    let code = status.code();
    let reason = if preferred == TerminationReason::TimedOut
        || preferred == TerminationReason::Cancelled
        || preferred == TerminationReason::Killed
    {
        preferred
    } else if code.is_some() {
        TerminationReason::Exited
    } else {
        TerminationReason::Unknown
    };
    (code, None, reason)
}

#[derive(Debug, Clone)]
pub struct SpawnRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
    pub env: Vec<(String, String)>,
    /// Child stdin mode (default [`StdioMode::Null`]).
    pub stdin: StdioMode,
    /// Child stdout mode (default [`StdioMode::Piped`]).
    pub stdout: StdioMode,
    /// Child stderr mode (default [`StdioMode::Piped`]).
    pub stderr: StdioMode,
    /// When true (default), put the child in its own process group (Unix) so
    /// timeout/cancel can kill the whole tree (shells, grandchildren).
    pub process_group: bool,
    /// When true (default), record `args` on `Exec` events. Set false when
    /// spawning `bash -lc <full command>` that may embed secrets.
    pub audit_args: bool,
}

impl SpawnRequest {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            stdin: StdioMode::Null,
            stdout: StdioMode::Piped,
            stderr: StdioMode::Piped,
            process_group: true,
            audit_args: true,
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn cwd(mut self, cwd: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn stdin(mut self, mode: StdioMode) -> Self {
        self.stdin = mode;
        self
    }

    pub fn stdout(mut self, mode: StdioMode) -> Self {
        self.stdout = mode;
        self
    }

    pub fn stderr(mut self, mode: StdioMode) -> Self {
        self.stderr = mode;
        self
    }

    pub fn process_group(mut self, enabled: bool) -> Self {
        self.process_group = enabled;
        self
    }

    /// When `false`, Exec audit events omit argument values (see [`audit_args_for_event`]).
    pub fn audit_args(mut self, enabled: bool) -> Self {
        self.audit_args = enabled;
        self
    }

    /// Args suitable for an `Exec` audit event, plus whether they were redacted.
    pub fn audit_args_for_event(&self) -> (Vec<String>, bool) {
        if self.audit_args {
            (self.args.clone(), false)
        } else {
            (Vec::new(), true)
        }
    }
}

/// Low-level child handle with process-group aware wait/kill.
///
/// Prefer [`keel_core::ManagedProcess`] from a [`Space`] so exit is audited.
pub struct SpawnedProcess {
    pub child: tokio::process::Child,
    started_at: Instant,
    process_group: bool,
}

impl SpawnedProcess {
    pub fn new(child: tokio::process::Child, process_group: bool) -> Self {
        Self {
            child,
            started_at: Instant::now(),
            process_group,
        }
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    pub fn process_group_enabled(&self) -> bool {
        self.process_group
    }

    /// Kill the process group (Unix) or the direct child. Does not wait.
    pub fn kill_tree(&mut self) -> std::io::Result<()> {
        kill_tree_of(&mut self.child, self.process_group)
    }

    /// Wait until exit; does not kill.
    pub async fn wait(mut self) -> std::io::Result<ProcessExit> {
        let started = self.started_at;
        let status = self.child.wait().await?;
        Ok(ProcessExit::from_status(
            status,
            started,
            TerminationReason::Exited,
        ))
    }

    /// Wait with timeout; on timeout, kill the process group then wait.
    pub async fn wait_timeout(mut self, timeout: Duration) -> std::io::Result<ProcessExit> {
        let started = self.started_at;
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(status)) => Ok(ProcessExit::from_status(
                status,
                started,
                TerminationReason::Exited,
            )),
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => {
                let _ = kill_tree_of(&mut self.child, self.process_group);
                let status = self.child.wait().await?;
                Ok(ProcessExit::from_status(
                    status,
                    started,
                    TerminationReason::TimedOut,
                ))
            }
        }
    }

    /// Cancel: kill process group, wait, mark reason cancelled.
    pub async fn cancel(mut self) -> std::io::Result<ProcessExit> {
        let started = self.started_at;
        let _ = kill_tree_of(&mut self.child, self.process_group);
        let status = self.child.wait().await?;
        Ok(ProcessExit::from_status(
            status,
            started,
            TerminationReason::Cancelled,
        ))
    }

    /// Wait and collect stdout/stderr when piped (same as `Child::wait_with_output`).
    pub async fn wait_with_output(self) -> std::io::Result<(ProcessExit, std::process::Output)> {
        let started = self.started_at;
        let process_group = self.process_group;
        let _ = process_group; // reserved for future timeout variants
        let output = self.child.wait_with_output().await?;
        let exit = ProcessExit::from_status(output.status, started, TerminationReason::Exited);
        Ok((exit, output))
    }
}

fn kill_tree_of(child: &mut tokio::process::Child, process_group: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if process_group {
            if let Some(pid) = child.id() {
                // Child is group leader when spawned with process_group(0).
                let rc = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                if rc == 0 {
                    return Ok(());
                }
                // Fall through to start_kill if killpg failed (e.g. already dead).
            }
        }
    }
    child.start_kill()
}

/// A live enforcement context for one space.
#[async_trait]
pub trait EnforceBackend: Send + Sync {
    fn info(&self) -> BackendInfo;

    /// Apply policy for this space. May be irreversible for kernel backends.
    async fn apply(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()>;

    /// Check whether a path operation would be allowed (best-effort soft check).
    async fn check_fs(
        &self,
        policy: &Policy,
        path: &Path,
        write: bool,
    ) -> EnforceResult<bool>;

    /// Spawn a subprocess under the policy (soft or hard depending on backend).
    async fn spawn(
        &self,
        space_id: &SpaceId,
        policy: &Policy,
        req: SpawnRequest,
        sink: Arc<dyn RecordSink>,
    ) -> EnforceResult<SpawnedProcess>;

    /// Tear down enforcement for this space (revoke, unmount, etc.).
    async fn destroy(&self, policy: &Policy, sink: Arc<dyn RecordSink>) -> EnforceResult<()>;
}

/// Shared helper: build a tokio Command with stdio / env / process group.
pub(crate) fn base_command(req: &SpawnRequest) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&req.program);
    cmd.args(&req.args)
        .stdin(req.stdin.to_std())
        .stdout(req.stdout.to_std())
        .stderr(req.stderr.to_std());
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    if req.process_group {
        cmd.process_group(0);
    }
    // On Unix, kill_on_drop only kills the direct child; hosts should use
    // SpawnedProcess::cancel / wait_timeout for process-group cleanup.
    cmd.kill_on_drop(true);
    cmd
}

/// Apply stdio modes from the request onto a std Command (e.g. bwrap outer).
#[cfg_attr(not(all(feature = "kernel", target_os = "linux")), allow(dead_code))]
pub(crate) fn apply_stdio_std(cmd: &mut std::process::Command, req: &SpawnRequest) {
    cmd.stdin(req.stdin.to_std())
        .stdout(req.stdout.to_std())
        .stderr(req.stderr.to_std());
}
