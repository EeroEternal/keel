//! Policy-constrained filesystem operations for agent hosts (soft enforce + audit).
//!
//! Unlike [`crate::SpaceHandle::check_fs`], these methods **perform** the I/O when allowed,
//! resolve paths (including symlink targets where possible), and emit `FsAccess` events.
//!
//! This is still a **soft** boundary for host-side tools: kernel isolation for child
//! processes is separate. Hosts (e.g. Zene) should route Read/Write/Edit tools here
//! instead of calling raw `std::fs` after a soft check.

use crate::error::{KeelError, KeelResult};
use crate::space::SpaceHandle;
use keel_enforce::{soft_fs_allowed, soft_fs_resolve};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Filesystem facade bound to an open space.
pub struct SpaceFs {
    space: SpaceHandle,
}

impl SpaceFs {
    pub(crate) fn new(space: SpaceHandle) -> Self {
        Self { space }
    }

    pub async fn read(&self, path: impl AsRef<Path>) -> KeelResult<Vec<u8>> {
        let resolved = self.authorize(path.as_ref(), false).await?;
        tokio::fs::read(&resolved)
            .await
            .map_err(|e| KeelError::Msg(format!("read {}: {e}", resolved.display())))
    }

    pub async fn read_to_string(&self, path: impl AsRef<Path>) -> KeelResult<String> {
        let bytes = self.read(path).await?;
        String::from_utf8(bytes).map_err(|e| KeelError::Msg(format!("utf-8: {e}")))
    }

    pub async fn write(&self, path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> KeelResult<()> {
        let resolved = self.authorize(path.as_ref(), true).await?;
        if let Some(parent) = resolved.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                KeelError::Msg(format!("create_dir_all {}: {e}", parent.display()))
            })?;
        }
        tokio::fs::write(&resolved, data.as_ref())
            .await
            .map_err(|e| KeelError::Msg(format!("write {}: {e}", resolved.display())))
    }

    /// Create a new file; fails if it already exists.
    pub async fn create(&self, path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> KeelResult<()> {
        let resolved = self.authorize(path.as_ref(), true).await?;
        if resolved.exists() {
            return Err(KeelError::Msg(format!(
                "create: path already exists: {}",
                resolved.display()
            )));
        }
        if let Some(parent) = resolved.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                KeelError::Msg(format!("create_dir_all {}: {e}", parent.display()))
            })?;
        }
        tokio::fs::write(&resolved, data.as_ref())
            .await
            .map_err(|e| KeelError::Msg(format!("create {}: {e}", resolved.display())))
    }

    pub async fn delete(&self, path: impl AsRef<Path>) -> KeelResult<()> {
        let resolved = self.authorize(path.as_ref(), true).await?;
        let meta = tokio::fs::metadata(&resolved)
            .await
            .map_err(|e| KeelError::Msg(format!("metadata {}: {e}", resolved.display())))?;
        if meta.is_dir() {
            tokio::fs::remove_dir_all(&resolved)
                .await
                .map_err(|e| KeelError::Msg(format!("delete dir {}: {e}", resolved.display())))?;
        } else {
            tokio::fs::remove_file(&resolved)
                .await
                .map_err(|e| KeelError::Msg(format!("delete {}: {e}", resolved.display())))?;
        }
        Ok(())
    }

    pub async fn rename(
        &self,
        from: impl AsRef<Path>,
        to: impl AsRef<Path>,
    ) -> KeelResult<()> {
        let from_r = self.authorize(from.as_ref(), true).await?;
        let to_r = self.authorize(to.as_ref(), true).await?;
        if let Some(parent) = to_r.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                KeelError::Msg(format!("create_dir_all {}: {e}", parent.display()))
            })?;
        }
        tokio::fs::rename(&from_r, &to_r).await.map_err(|e| {
            KeelError::Msg(format!(
                "rename {} → {}: {e}",
                from_r.display(),
                to_r.display()
            ))
        })
    }

    pub async fn metadata(&self, path: impl AsRef<Path>) -> KeelResult<SpacePathMeta> {
        let path = path.as_ref();
        let resolved = self.authorize(path, false).await?;
        let meta = tokio::fs::metadata(&resolved)
            .await
            .map_err(|e| KeelError::Msg(format!("metadata {}: {e}", resolved.display())))?;
        let is_symlink = tokio::fs::symlink_metadata(&resolved)
            .await
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        Ok(SpacePathMeta {
            path: resolved,
            len: meta.len(),
            is_file: meta.is_file(),
            is_dir: meta.is_dir(),
            is_symlink,
            modified: meta.modified().ok(),
        })
    }

    async fn authorize(&self, path: &Path, write: bool) -> KeelResult<PathBuf> {
        let policy = self.space.policy();
        let resolved =
            soft_fs_resolve(policy, path, write).map_err(KeelError::Msg)?;
        // Soft check on both the request path and the resolved target (symlink escape).
        if !soft_fs_allowed(policy, path, write) || !soft_fs_allowed(policy, &resolved, write) {
            // Emit audit via check_fs (records deny).
            let _ = self.space.check_fs(&resolved, write).await?;
            return Err(KeelError::Msg(format!(
                "fs {} denied by policy: {}",
                if write { "write" } else { "read" },
                path.display()
            )));
        }
        let allowed = self.space.check_fs(&resolved, write).await?;
        if !allowed {
            return Err(KeelError::Msg(format!(
                "fs {} denied by policy: {}",
                if write { "write" } else { "read" },
                path.display()
            )));
        }
        Ok(resolved)
    }
}

#[derive(Debug, Clone)]
pub struct SpacePathMeta {
    pub path: PathBuf,
    pub len: u64,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub modified: Option<SystemTime>,
}
