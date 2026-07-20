//! Host-facing process handle: process-group kill + audited wait.

use crate::error::KeelResult;
use crate::space::Space;
use keel_enforce::{ProcessExit, SpawnedProcess, TerminationReason};
use keel_record::EventKind;
use std::process::Output;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio_util::sync::CancellationToken;

/// Process spawned under a space: stdio access + tree kill + audit on wait.
///
/// Dropping without wait/cancel kills the process group / Job (via
/// [`SpawnedProcess`]'s `Drop`), not only the direct child.
pub struct ManagedProcess {
    pub(crate) inner: SpawnedProcess,
    pub(crate) space: Arc<Space>,
    pub(crate) program: String,
}

impl ManagedProcess {
    /// Tokio child when present (not Windows AppContainer native spawn).
    pub fn child(&self) -> Option<&Child> {
        self.inner.child_ref()
    }

    pub fn child_mut(&mut self) -> Option<&mut Child> {
        self.inner.child_mut()
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.inner.child_mut().and_then(|c| c.stdin.take())
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.inner.child_mut().and_then(|c| c.stdout.take())
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.inner.child_mut().and_then(|c| c.stderr.take())
    }

    /// Drop into the low-level handle (no further automatic ExecFinished from this type).
    pub fn into_spawned(self) -> SpawnedProcess {
        self.inner
    }

    /// Kill the process group / Job; does not wait or audit.
    pub fn kill_tree(&mut self) -> std::io::Result<()> {
        self.inner.kill_tree()
    }

    pub async fn wait(self) -> KeelResult<ProcessExit> {
        let program = self.program;
        let space = self.space;
        let exit = self.inner.wait().await?;
        emit_finished(&space, &program, &exit).await?;
        Ok(exit)
    }

    pub async fn wait_timeout(self, timeout: Duration) -> KeelResult<ProcessExit> {
        let program = self.program;
        let space = self.space;
        let exit = self.inner.wait_timeout(timeout).await?;
        emit_finished(&space, &program, &exit).await?;
        Ok(exit)
    }

    pub async fn cancel(self) -> KeelResult<ProcessExit> {
        let program = self.program;
        let space = self.space;
        let exit = self.inner.cancel().await?;
        emit_finished(&space, &program, &exit).await?;
        Ok(exit)
    }

    pub async fn wait_with_output(self) -> KeelResult<(ProcessExit, Output)> {
        let program = self.program;
        let space = self.space;
        let (exit, output) = self.inner.wait_with_output().await?;
        emit_finished(&space, &program, &exit).await?;
        Ok((exit, output))
    }

    pub async fn wait_with_output_timeout(
        self,
        timeout: Duration,
    ) -> KeelResult<(ProcessExit, Output)> {
        let program = self.program;
        let space = self.space;
        let (exit, output) = self.inner.wait_with_output_timeout(timeout).await?;
        emit_finished(&space, &program, &exit).await?;
        Ok((exit, output))
    }

    pub async fn wait_with_output_cancel(
        self,
        token: &CancellationToken,
        timeout: Duration,
    ) -> KeelResult<(ProcessExit, Output)> {
        let program = self.program;
        let space = self.space;
        let (exit, output) = self
            .inner
            .wait_with_output_cancel(token, timeout)
            .await?;
        emit_finished(&space, &program, &exit).await?;
        Ok((exit, output))
    }
}

async fn emit_finished(space: &Space, program: &str, exit: &ProcessExit) -> KeelResult<()> {
    let reason = match exit.termination_reason {
        TerminationReason::Exited => "exited",
        TerminationReason::TimedOut => "timed_out",
        TerminationReason::Cancelled => "cancelled",
        TerminationReason::Killed => "killed",
        TerminationReason::Signal => "signal",
        TerminationReason::Unknown => "unknown",
    };
    space
        .emit(EventKind::ExecFinished {
            program: program.to_string(),
            exit_code: exit.exit_code,
            duration_ms: exit.duration.as_millis() as u64,
            termination_reason: reason.into(),
            signal: exit.signal,
        })
        .await
}
