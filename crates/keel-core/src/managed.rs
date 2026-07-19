//! Host-facing process handle: process-group kill + audited wait.

use crate::error::KeelResult;
use crate::space::Space;
use keel_enforce::{ProcessExit, SpawnedProcess, TerminationReason};
use keel_record::EventKind;
use std::process::Output;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

/// Process spawned under a space: stdio access + tree kill + audit on wait.
pub struct ManagedProcess {
    pub(crate) inner: SpawnedProcess,
    pub(crate) space: Arc<Space>,
    pub(crate) program: String,
}

impl ManagedProcess {
    pub fn child(&self) -> &tokio::process::Child {
        &self.inner.child
    }

    pub fn child_mut(&mut self) -> &mut tokio::process::Child {
        &mut self.inner.child
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.inner.child.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.inner.child.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.inner.child.stderr.take()
    }

    /// Drop into the low-level handle (no further automatic ExecFinished from this type).
    pub fn into_spawned(self) -> SpawnedProcess {
        self.inner
    }

    /// Kill the process group (Unix) or the child; does not wait or audit.
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

    /// On timeout, kill the whole process group, wait, audit as `timed_out`.
    pub async fn wait_timeout(self, timeout: Duration) -> KeelResult<ProcessExit> {
        let program = self.program;
        let space = self.space;
        let exit = self.inner.wait_timeout(timeout).await?;
        emit_finished(&space, &program, &exit).await?;
        Ok(exit)
    }

    /// Cancel / host abort: kill tree, audit as `cancelled`.
    pub async fn cancel(self) -> KeelResult<ProcessExit> {
        let program = self.program;
        let space = self.space;
        let exit = self.inner.cancel().await?;
        emit_finished(&space, &program, &exit).await?;
        Ok(exit)
    }

    /// Wait and collect piped stdout/stderr (CLI-style capture).
    pub async fn wait_with_output(self) -> KeelResult<(ProcessExit, Output)> {
        let program = self.program;
        let space = self.space;
        let (exit, output) = self.inner.wait_with_output().await?;
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
