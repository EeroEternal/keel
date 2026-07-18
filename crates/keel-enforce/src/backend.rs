use crate::error::EnforceResult;
use async_trait::async_trait;
use keel_policy::{Policy, SpaceId};
use keel_record::RecordSink;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: &'static str,
    /// True if the backend applies kernel-level FS isolation.
    pub kernel_fs: bool,
    /// True if the backend can restrict child process network.
    pub child_network: bool,
}

#[derive(Debug, Clone)]
pub struct SpawnRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
    pub env: Vec<(String, String)>,
}

impl SpawnRequest {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
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
}

pub struct SpawnedProcess {
    pub child: tokio::process::Child,
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

/// Shared helper: build a tokio Command with basic fields.
pub(crate) fn base_command(req: &SpawnRequest) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&req.program);
    cmd.args(&req.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    cmd
}
