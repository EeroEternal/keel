//! Map a Keel [`Policy`] into a nono [`CapabilitySet`].

use crate::error::{EnforceError, EnforceResult};
use keel_policy::{NetworkPolicy, Policy};
use nono::{AccessMode, CapabilitySet, NetworkMode};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Device files tools commonly need (git, compilers, PTY, RNG).
const DEVICE_FILES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/fd",
];

const DEVICE_DIRS: &[&str] = &["/dev/pts"];

/// Seatbelt write sub-actions so deny wins over broad workspace write grants.
#[cfg(target_os = "macos")]
const SEATBELT_WRITE_DENY_ACTIONS: &[&str] = &[
    "file-write-data",
    "file-write-create",
    "file-write-unlink",
    "file-write-mode",
    "file-write-owner",
    "file-write-flags",
    "file-write-times",
    "file-write-setugid",
];

/// Options when mapping policy → kernel capabilities.
#[derive(Debug, Clone, Copy)]
pub struct MapOptions {
    /// If true, force `NetworkMode::Blocked` regardless of policy.
    pub block_process_network: bool,
    /// When set with an allowlist policy, restrict the process to
    /// `localhost:proxy_port` only (`NetworkMode::ProxyOnly`).
    pub egress_proxy_port: Option<u16>,
}

impl Default for MapOptions {
    fn default() -> Self {
        Self {
            block_process_network: false,
            egress_proxy_port: None,
        }
    }
}

/// Build a nono capability set from a Keel policy.
pub fn policy_to_capability_set(policy: &Policy, opts: MapOptions) -> EnforceResult<CapabilitySet> {
    let mut caps = CapabilitySet::new();

    if policy.default_read {
        caps = allow_dir(caps, Path::new("/"), AccessMode::Read)?;
    }

    for path in policy.read_only_paths() {
        let path = resolve_ws(policy, path);
        caps = grant_existing(caps, &path, AccessMode::Read)?;
    }

    for path in policy.read_write_paths() {
        let path = resolve_ws(policy, path);
        if !path.exists() {
            if let Err(e) = std::fs::create_dir_all(&path) {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "read_write path missing and could not be created; skipping"
                );
                continue;
            }
        }
        caps = grant_existing(caps, &path, AccessMode::ReadWrite)?;
    }

    for dev in DEVICE_FILES {
        let p = Path::new(dev);
        if p.exists() {
            if let Err(e) = caps.allow_file_mut(p, AccessMode::ReadWrite) {
                warn!(path = dev, error = %e, "allow_file failed; skipping");
            }
        }
    }
    for dev in DEVICE_DIRS {
        let p = Path::new(dev);
        if p.is_dir() {
            caps = allow_dir(caps, p, AccessMode::ReadWrite)?;
        }
    }

    for rule in policy.deny_paths() {
        if rule.glob {
            warn!(
                pattern = %rule.path.display(),
                "deny globs not kernel-enforced in local-process v0"
            );
            continue;
        }
        let path = resolve_ws(policy, &rule.path);
        apply_deny_path(&mut caps, &path)?;
    }

    // Network mode for the sandboxed process (typically the child).
    if opts.block_process_network {
        caps = caps.block_network();
    } else {
        match &policy.network {
            NetworkPolicy::Unrestricted => {
                // AllowAll is nono default.
            }
            NetworkPolicy::DenyAll => {
                caps = caps.block_network();
            }
            NetworkPolicy::Allowlist(_) => {
                if let Some(port) = opts.egress_proxy_port {
                    caps = caps.set_network_mode(NetworkMode::ProxyOnly {
                        port,
                        bind_ports: Vec::new(),
                    });
                } else {
                    // Allowlist without a proxy port: do not open unrestricted net
                    // at the kernel layer; fail soft to Blocked and rely on proxy
                    // injection when the backend starts one.
                    warn!(
                        "allowlist policy mapped without egress_proxy_port; blocking process network"
                    );
                    caps = caps.block_network();
                }
            }
        }
    }

    Ok(caps)
}

fn resolve_ws(policy: &Policy, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        policy.workspace.join(path)
    }
}

fn grant_existing(
    caps: CapabilitySet,
    path: &Path,
    mode: AccessMode,
) -> EnforceResult<CapabilitySet> {
    if !path.exists() {
        return Ok(caps);
    }
    if path.is_dir() {
        allow_dir(caps, path, mode)
    } else {
        // allow_file_mut needs &mut — convert via temporary
        let mut caps = caps;
        if let Err(e) = caps.allow_file_mut(path, mode) {
            warn!(path = %path.display(), error = %e, "allow_file failed; skipping");
        }
        Ok(caps)
    }
}

fn allow_dir(caps: CapabilitySet, path: &Path, mode: AccessMode) -> EnforceResult<CapabilitySet> {
    // Pre-check so we never lose `caps` on nono validation errors.
    if !path.is_dir() {
        warn!(path = %path.display(), "not a directory; skipping allow_path");
        return Ok(caps);
    }
    caps.allow_path(path, mode)
        .map_err(|e| EnforceError::ApplyFailed(format!("allow_path({}): {e}", path.display())))
}

fn apply_deny_path(caps: &mut CapabilitySet, path: &Path) -> EnforceResult<()> {
    #[cfg(target_os = "macos")]
    {
        emit_macos_deny(caps, path)
    }
    #[cfg(target_os = "linux")]
    {
        warn!(
            path = %path.display(),
            "Linux Landlock cannot deny subpaths of allowed trees; deny is advisory until bwrap"
        );
        let _ = (caps, path);
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (caps, path);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn emit_macos_deny(caps: &mut CapabilitySet, path: &Path) -> EnforceResult<()> {
    let canonical = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let use_subpath = canonical.is_dir() || path.is_dir();
    for form in macos_deny_aliases(path, &canonical) {
        let Some(escaped) = escape_seatbelt_path(&form) else {
            return Err(EnforceError::ApplyFailed(format!(
                "cannot escape deny path {} for Seatbelt",
                form.display()
            )));
        };
        let filter = if use_subpath {
            format!("(subpath \"{escaped}\")")
        } else {
            format!("(literal \"{escaped}\")")
        };
        emit_seatbelt_deny(caps, &filter)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn emit_seatbelt_deny(caps: &mut CapabilitySet, filter: &str) -> EnforceResult<()> {
    caps.add_platform_rule(format!("(deny file-read* {filter})"))
        .map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    caps.add_platform_rule(format!("(deny file-write* {filter})"))
        .map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    for action in SEATBELT_WRITE_DENY_ACTIONS {
        caps.add_platform_rule(format!("(deny {action} {filter})"))
            .map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn escape_seatbelt_path(path: &Path) -> Option<String> {
    let s = path.to_str()?;
    if s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "macos")]
fn macos_deny_aliases(path: &Path, canonical: &Path) -> Vec<PathBuf> {
    let mut forms = vec![path.to_path_buf()];
    if canonical != path {
        forms.push(canonical.to_path_buf());
    }
    for form in forms.clone() {
        if let Some(alias) = toggle_private_prefix(&form) {
            if !forms.contains(&alias) {
                forms.push(alias);
            }
        }
    }
    forms
}

#[cfg(target_os = "macos")]
fn toggle_private_prefix(path: &Path) -> Option<PathBuf> {
    let s = path.to_str()?;
    for dir in ["tmp", "var", "etc"] {
        if let Some(rest) = s.strip_prefix(&format!("/private/{dir}")) {
            if rest.is_empty() || rest.starts_with('/') {
                return Some(PathBuf::from(format!("/{dir}{rest}")));
            }
        }
        if let Some(rest) = s.strip_prefix(&format!("/{dir}")) {
            if rest.is_empty() || rest.starts_with('/') {
                return Some(PathBuf::from(format!("/private/{dir}{rest}")));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::profile_workspace;

    #[test]
    fn maps_workspace_profile() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile_workspace(dir.path()).unwrap();
        let caps = policy_to_capability_set(&p, MapOptions::default()).unwrap();
        let _ = caps;
    }

    #[test]
    fn deny_path_maps() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::create_dir_all(&secret).unwrap();
        let p = Policy::builder(dir.path())
            .default_read(true)
            .read_write(dir.path())
            .deny(&secret)
            .build()
            .unwrap();
        let caps = policy_to_capability_set(&p, MapOptions::default()).unwrap();
        #[cfg(target_os = "macos")]
        {
            assert!(
                !caps.platform_rules().is_empty(),
                "expected Seatbelt deny rules"
            );
        }
        let _ = caps;
    }
}
