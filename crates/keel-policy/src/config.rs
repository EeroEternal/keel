//! Load named sandbox profiles from `sandbox.toml` (optimization plan Phase 5).
//!
//! Search order:
//! 1. `$KEEL_HOME/sandbox.toml` or `~/.keel/sandbox.toml` (global)
//! 2. `<workspace>/.keel/sandbox.toml` (project — **additive only** for new names)
//!
//! Project files cannot redefine a profile name already present globally
//! (prevents a malicious workspace from hollowing out a trusted profile).

use crate::error::{PolicyError, PolicyResult};
use crate::net::{NetworkPolicy, NetworkRule};
use crate::paths::FsRule;
use crate::policy::{ExecPolicy, Policy};
use crate::presets::{profile_read_only, profile_strict, profile_workspace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// On-disk profile entry under `[profiles.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct ProfileConfig {
    /// Built-in or custom profile to extend: `workspace`, `read-only`, `strict`, or another name.
    #[serde(default)]
    pub extends: Option<String>,
    /// If true, set network to DenyAll (unless `allow_hosts` is also set → allowlist).
    #[serde(default)]
    pub restrict_network: Option<bool>,
    /// Explicit network mode: `unrestricted` | `deny-all` | `allowlist`.
    #[serde(default)]
    pub network: Option<String>,
    /// Hosts for allowlist (`host` or `host:port`).
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    /// Deny paths; entries containing `*` or `**` become deny globs.
    #[serde(default)]
    pub deny: Vec<String>,
    /// If set, force `ExecPolicy::Deny`.
    #[serde(default)]
    pub deny_exec: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SandboxConfigFile {
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

/// Merged view of global + project sandbox config.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    pub profiles: HashMap<String, ProfileConfig>,
    /// Profile names present in project config that conflicted with global (ignored).
    pub ignored_project_overrides: Vec<String>,
}

impl SandboxConfig {
    pub fn load(workspace: &Path) -> Self {
        Self::load_from(keel_home().join("sandbox.toml"), workspace.join(".keel").join("sandbox.toml"))
    }

    /// Load from explicit paths (tests / custom layouts).
    pub fn load_from(global_path: PathBuf, project_path: PathBuf) -> Self {
        let mut cfg = SandboxConfig::default();
        if let Some(g) = load_file(&global_path) {
            cfg.profiles = g.profiles;
        }
        if let Some(p) = load_file(&project_path) {
            for (name, profile) in p.profiles {
                if cfg.profiles.contains_key(&name) {
                    cfg.ignored_project_overrides.push(name);
                } else {
                    cfg.profiles.insert(name, profile);
                }
            }
        }
        if !cfg.ignored_project_overrides.is_empty() {
            tracing::warn!(
                names = ?cfg.ignored_project_overrides,
                "project sandbox.toml tried to redefine global profile names; ignored"
            );
        }
        cfg
    }

    /// Resolve a built-in or custom profile name into a Policy for `workspace`.
    pub fn resolve_policy(&self, name: &str, workspace: &Path) -> PolicyResult<Policy> {
        resolve_named_profile(self, name, workspace, 0)
    }

    pub fn profile_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.profiles.keys().cloned().collect();
        names.sort();
        names
    }
}

fn load_file(path: &Path) -> Option<SandboxConfigFile> {
    let text = std::fs::read_to_string(path).ok()?;
    match toml::from_str(&text) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "failed to parse sandbox.toml");
            None
        }
    }
}

fn keel_home() -> PathBuf {
    if let Ok(h) = std::env::var("KEEL_HOME") {
        return PathBuf::from(h);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".keel")
}

fn resolve_named_profile(
    cfg: &SandboxConfig,
    name: &str,
    workspace: &Path,
    depth: u8,
) -> PolicyResult<Policy> {
    if depth > 8 {
        return Err(PolicyError::Invalid(format!(
            "profile extends chain too deep (at '{name}')"
        )));
    }

    // Built-ins first unless a custom profile shadows them only via extends base.
    match name {
        "workspace" | "read-only" | "readonly" | "strict" | "off" | "none"
            if !cfg.profiles.contains_key(name) =>
        {
            return builtin(name, workspace);
        }
        _ => {}
    }

    if let Some(pc) = cfg.profiles.get(name) {
        let base_name = pc.extends.as_deref().unwrap_or("workspace");
        // If extends points at the same custom name, fall back to built-in workspace.
        let mut policy = if base_name == name {
            profile_workspace(workspace)?
        } else if cfg.profiles.contains_key(base_name)
            || matches!(
                base_name,
                "workspace" | "read-only" | "readonly" | "strict"
            )
        {
            resolve_named_profile(cfg, base_name, workspace, depth + 1)?
        } else {
            return Err(PolicyError::Invalid(format!(
                "profile '{name}' extends unknown base '{base_name}'"
            )));
        };
        apply_profile_config(&mut policy, pc, workspace)?;
        policy.label = Some(name.to_string());
        policy.validate()?;
        return Ok(policy);
    }

    // Bare built-in names even if not in map.
    builtin(name, workspace)
}

fn builtin(name: &str, workspace: &Path) -> PolicyResult<Policy> {
    match name {
        "workspace" => profile_workspace(workspace),
        "read-only" | "readonly" => profile_read_only(workspace),
        "strict" => profile_strict(workspace),
        "off" | "none" => Err(PolicyError::Invalid(
            "profile 'off' is not a resolvable base; omit sandbox instead".into(),
        )),
        other => Err(PolicyError::Invalid(format!(
            "unknown sandbox profile '{other}' (define in sandbox.toml or use workspace|read-only|strict)"
        ))),
    }
}

fn apply_profile_config(
    policy: &mut Policy,
    pc: &ProfileConfig,
    workspace: &Path,
) -> PolicyResult<()> {
    for p in &pc.read_only {
        policy.fs.push(FsRule::read(resolve_path(workspace, p)));
    }
    for p in &pc.read_write {
        policy.fs.push(FsRule::read_write(resolve_path(workspace, p)));
    }
    for p in &pc.deny {
        if p.contains('*') {
            policy.fs.push(FsRule::deny_glob(p.clone()));
        } else {
            policy.fs.push(FsRule::deny(resolve_path(workspace, p)));
        }
    }

    if let Some(mode) = pc.network.as_deref() {
        policy.network = parse_network_mode(mode, &pc.allow_hosts)?;
    } else if !pc.allow_hosts.is_empty() {
        policy.network = NetworkPolicy::Allowlist(parse_allow_hosts(&pc.allow_hosts)?);
    } else if pc.restrict_network == Some(true) {
        policy.network = NetworkPolicy::DenyAll;
    } else if pc.restrict_network == Some(false) {
        policy.network = NetworkPolicy::Unrestricted;
    }

    if pc.deny_exec == Some(true) {
        policy.exec = ExecPolicy::Deny;
    }
    Ok(())
}

fn resolve_path(workspace: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        workspace.join(pb)
    }
}

fn parse_network_mode(mode: &str, allow_hosts: &[String]) -> PolicyResult<NetworkPolicy> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "unrestricted" | "allow-all" | "open" => Ok(NetworkPolicy::Unrestricted),
        "deny-all" | "deny_all" | "blocked" | "none" => Ok(NetworkPolicy::DenyAll),
        "allowlist" | "allow-list" => {
            if allow_hosts.is_empty() {
                return Err(PolicyError::Invalid(
                    "network = \"allowlist\" requires allow_hosts".into(),
                ));
            }
            Ok(NetworkPolicy::Allowlist(parse_allow_hosts(allow_hosts)?))
        }
        other => Err(PolicyError::Invalid(format!(
            "unknown network mode '{other}'"
        ))),
    }
}

fn parse_allow_hosts(hosts: &[String]) -> PolicyResult<Vec<NetworkRule>> {
    let mut rules = Vec::new();
    for h in hosts {
        if let Some((host, port_s)) = h.rsplit_once(':') {
            if let Ok(port) = port_s.parse::<u16>() {
                rules.push(NetworkRule::host_port(host, port));
                continue;
            }
        }
        rules.push(NetworkRule::host(h.as_str()));
    }
    if rules.is_empty() {
        return Err(PolicyError::Invalid("allow_hosts is empty".into()));
    }
    Ok(rules)
}

/// Load config for workspace and resolve a profile name.
pub fn load_policy_from_sandbox_toml(
    workspace: &Path,
    profile_name: &str,
) -> PolicyResult<Policy> {
    let cfg = SandboxConfig::load(workspace);
    cfg.resolve_policy(profile_name, workspace)
}

/// Resolve policy: optional explicit file path overrides name lookup.
pub fn resolve_policy_with_files(
    workspace: &Path,
    profile_name: Option<&str>,
    profile_file: Option<&Path>,
) -> PolicyResult<Policy> {
    if let Some(path) = profile_file {
        let text = std::fs::read_to_string(path).map_err(PolicyError::Io)?;
        // File may be either a full Policy JSON/TOML or a single ProfileConfig table.
        if let Ok(p) = Policy::from_json(&text) {
            return Ok(p);
        }
        if let Ok(p) = Policy::from_toml(&text) {
            return Ok(p);
        }
        // Treat as ProfileConfig fragment.
        let pc: ProfileConfig = toml::from_str(&text)
            .map_err(|e| PolicyError::Parse(format!("profile file: {e}")))?;
        let mut base = profile_workspace(workspace)?;
        apply_profile_config(&mut base, &pc, workspace)?;
        base.label = Some(
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("custom")
                .to_string(),
        );
        base.validate()?;
        return Ok(base);
    }

    let name = profile_name.unwrap_or("workspace");
    // Built-in without file.
    if matches!(name, "workspace" | "read-only" | "readonly" | "strict") {
        let cfg = SandboxConfig::load(workspace);
        // Still allow custom override of built-in name only if defined globally first.
        if cfg.profiles.contains_key(name) {
            return cfg.resolve_policy(name, workspace);
        }
        return builtin(name, workspace);
    }
    load_policy_from_sandbox_toml(workspace, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn project_cannot_clobber_global() {
        let home = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        fs::write(
            home.path().join("sandbox.toml"),
            r#"
[profiles.team]
extends = "workspace"
deny = [".env"]
"#,
        )
        .unwrap();
        fs::create_dir_all(ws.path().join(".keel")).unwrap();
        fs::write(
            ws.path().join(".keel/sandbox.toml"),
            r#"
[profiles.team]
extends = "workspace"
deny = []
[profiles.localonly]
extends = "strict"
"#,
        )
        .unwrap();

        let cfg = SandboxConfig::load_from(
            home.path().join("sandbox.toml"),
            ws.path().join(".keel/sandbox.toml"),
        );
        assert!(
            cfg.ignored_project_overrides.contains(&"team".into()),
            "ignored={:?}",
            cfg.ignored_project_overrides
        );
        assert!(cfg.profiles.contains_key("localonly"));
        let team = cfg.resolve_policy("team", ws.path()).unwrap();
        assert!(team.deny_paths().any(|r| r.path.ends_with(".env")));
    }

    #[test]
    fn extends_and_allowlist() {
        let home = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        fs::write(
            home.path().join("sandbox.toml"),
            r#"
[profiles.api]
extends = "workspace"
network = "allowlist"
allow_hosts = ["api.x.ai:443"]
deny = ["**/.env"]
"#,
        )
        .unwrap();
        let cfg = SandboxConfig::load_from(
            home.path().join("sandbox.toml"),
            ws.path().join(".keel/sandbox.toml"),
        );
        let p = cfg.resolve_policy("api", ws.path()).unwrap();
        assert!(matches!(p.network, NetworkPolicy::Allowlist(ref r) if r.len() == 1));
        assert!(p
            .fs
            .iter()
            .any(|r| r.glob && r.access == crate::paths::FsAccess::Deny));
    }
}
