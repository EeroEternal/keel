//! Linux bubblewrap helpers for read-deny (Landlock cannot deny subpaths).

use crate::error::{EnforceError, EnforceResult};
use keel_policy::Policy;
use std::path::{Path, PathBuf};
use tracing::warn;

const BWRAP_MARKER: &str = "__KEEL_INSIDE_BWRAP";

pub fn is_inside_bwrap() -> bool {
    std::env::var_os(BWRAP_MARKER).is_some()
}

pub fn bwrap_available() -> bool {
    which_bwrap().is_some()
}

fn which_bwrap() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KEEL_BWRAP") {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("bwrap");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    })
}

/// Collect absolute deny paths (non-glob) from policy.
pub fn deny_paths_for_bwrap(policy: &Policy) -> Vec<PathBuf> {
    policy
        .deny_paths()
        .filter(|r| !r.glob)
        .map(|r| {
            if r.path.is_absolute() {
                r.path.clone()
            } else {
                policy.workspace.join(&r.path)
            }
        })
        .collect()
}

/// Build a `bwrap` command that runs `program` + `args` with deny paths
/// bound over unreadable placeholders.
///
/// Returns `None` when already inside bwrap or there is nothing to deny.
pub fn wrap_command(
    program: &str,
    args: &[String],
    deny_read: &[PathBuf],
    cwd: Option<&Path>,
    env: &[(String, String)],
) -> EnforceResult<Option<std::process::Command>> {
    if is_inside_bwrap() || deny_read.is_empty() {
        return Ok(None);
    }

    let bwrap = which_bwrap().ok_or_else(|| {
        EnforceError::ApplyFailed(
            "bubblewrap (bwrap) required for Linux read-deny paths; install bubblewrap \
             or set KEEL_BWRAP"
                .into(),
        )
    })?;

    let mut cmd = std::process::Command::new(bwrap);
    cmd.arg("--bind").arg("/").arg("/");
    cmd.arg("--dev-bind").arg("/dev").arg("/dev");
    cmd.arg("--proc").arg("/proc");

    for path in deny_read {
        if !path.exists() {
            // Bind-over missing paths with a placeholder so later creates under
            // that name still hit the mount when parent existed — for missing
            // leaf files, create parent-safe file bind if parent exists.
            warn!(path = %path.display(), "deny path does not exist; binding placeholder");
        }
        let placeholder = blocked_placeholder(path).map_err(|e| {
            EnforceError::ApplyFailed(format!(
                "bwrap placeholder for {}: {e}",
                path.display()
            ))
        })?;
        cmd.arg("--ro-bind").arg(&placeholder).arg(path);
    }

    cmd.env(BWRAP_MARKER, "1");
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.arg("--").arg(program).args(args);
    Ok(Some(cmd))
}

fn blocked_placeholder(target: &Path) -> std::io::Result<PathBuf> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::PermissionsExt;

    let base = crate_keel_tmp();
    std::fs::create_dir_all(&base)?;
    let want_dir = target.is_dir() || target.to_string_lossy().ends_with('/');
    let name = if want_dir {
        format!("blocked-dir.{}", std::process::id())
    } else {
        format!("blocked.{}", std::process::id())
    };
    // Unique per target to avoid cross-path races within one spawn batch.
    let hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        target.hash(&mut h);
        h.finish()
    };
    let path = base.join(format!("{name}.{hash:x}"));

    if path.exists() {
        if path.is_dir() == want_dir {
            chmod_000(&path)?;
            return Ok(path);
        }
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }

    if want_dir {
        std::fs::create_dir(&path)?;
    } else {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
    }
    chmod_000(&path)?;
    Ok(path)
}

fn chmod_000(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(path, perms)
}

fn crate_keel_tmp() -> PathBuf {
    // Avoid depending on keel-record from enforce for path layout: mirror convention.
    if let Ok(h) = std::env::var("KEEL_HOME") {
        return PathBuf::from(h).join("tmp");
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".keel")
        .join("tmp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::Policy;

    #[test]
    fn no_wrap_without_deny() {
        let dir = tempfile::tempdir().unwrap();
        let p = Policy::builder(dir.path()).default_read(true).build().unwrap();
        let denies = deny_paths_for_bwrap(&p);
        assert!(denies.is_empty());
        let w = wrap_command("echo", &["hi".into()], &denies, None, &[]).unwrap();
        assert!(w.is_none());
    }
}
