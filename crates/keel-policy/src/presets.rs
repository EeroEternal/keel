//! Built-in profiles inspired by common coding-agent sandboxes.
//!
//! These are **policy templates**, not kernel enforcement. The enforce backend
//! maps them to Landlock / Seatbelt / worktree / etc.

use crate::error::PolicyResult;
use crate::net::NetworkPolicy;
use crate::paths::FsRule;
use crate::policy::{ExecPolicy, Policy};
use std::path::{Path, PathBuf};

fn temp_paths() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
    if let Ok(t) = std::env::var("TMPDIR") {
        let p = PathBuf::from(t);
        if !v.contains(&p) {
            v.push(p);
        }
    }
    // macOS private temp roots (exist check left to enforce backend).
    for p in ["/private/tmp", "/private/var/tmp", "/private/var/folders"] {
        v.push(PathBuf::from(p));
    }
    v
}

fn keel_home() -> PathBuf {
    if let Ok(h) = std::env::var("KEEL_HOME") {
        return PathBuf::from(h);
    }
    dirs_path().join(".keel")
}

fn dirs_path() -> PathBuf {
    // Avoid hard dep on `dirs` in policy crate; home is best-effort.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Everyday coding: broad read, write limited to workspace + keel home + temps.
pub fn profile_workspace(workspace: &Path) -> PolicyResult<Policy> {
    let mut b = Policy::builder(workspace)
        .label("workspace")
        .default_read(true)
        .read_write(workspace)
        .read_write(keel_home())
        .exec(ExecPolicy::Allow)
        .network(NetworkPolicy::Unrestricted);
    for t in temp_paths() {
        b = b.fs_rule(FsRule::read_write(t));
    }
    b.build()
}

/// Explore without modifying the project tree. Writes only to keel home + temps.
pub fn profile_read_only(workspace: &Path) -> PolicyResult<Policy> {
    let mut b = Policy::builder(workspace)
        .label("read-only")
        .default_read(true)
        .read_write(keel_home())
        .exec(ExecPolicy::Allow)
        .network(NetworkPolicy::DenyAll);
    for t in temp_paths() {
        b = b.fs_rule(FsRule::read_write(t));
    }
    b.build()
}

/// Narrower reach: no default world-read; workspace + essential system paths only.
pub fn profile_strict(workspace: &Path) -> PolicyResult<Policy> {
    let system_read = [
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/dev", "/proc", "/sys", "/tmp", "/run",
        "/var", "/System", "/Library", "/private",
    ];
    let mut b = Policy::builder(workspace)
        .label("strict")
        .default_read(false)
        .read_write(workspace)
        .read_write(keel_home())
        .exec(ExecPolicy::Allow)
        .network(NetworkPolicy::DenyAll);
    for p in system_read {
        b = b.read_only(p);
    }
    for t in temp_paths() {
        b = b.fs_rule(FsRule::read_write(t));
    }
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetworkPolicy;

    #[test]
    fn presets_build() {
        let ws = Path::new("/tmp/keel-ws");
        let w = profile_workspace(ws).unwrap();
        assert!(w.default_read);
        assert!(matches!(w.network, NetworkPolicy::Unrestricted));

        let r = profile_read_only(ws).unwrap();
        assert!(matches!(r.network, NetworkPolicy::DenyAll));

        let s = profile_strict(ws).unwrap();
        assert!(!s.default_read);
    }
}
