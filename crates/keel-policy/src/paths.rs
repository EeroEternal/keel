use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How a path may be accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    Read,
    ReadWrite,
    /// Kernel-enforced deny (read + write/rename where the backend supports it).
    Deny,
}

/// A single filesystem rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: FsAccess,
    /// If true, `path` is treated as a glob (e.g. `**/.env`).
    #[serde(default)]
    pub glob: bool,
}

impl FsRule {
    pub fn read(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: FsAccess::Read,
            glob: false,
        }
    }

    pub fn read_write(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: FsAccess::ReadWrite,
            glob: false,
        }
    }

    pub fn deny(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: FsAccess::Deny,
            glob: false,
        }
    }

    pub fn deny_glob(pattern: impl Into<PathBuf>) -> Self {
        Self {
            path: pattern.into(),
            access: FsAccess::Deny,
            glob: true,
        }
    }
}

/// Path pattern helpers for policy authors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathPattern(String);

impl PathPattern {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}
