//! Baseline deny rules applied to every policy unless opted out.
//!
//! Protects common credential and secret locations even when `default_read` is
//! true (e.g. workspace profile). Hosts may call
//! [`PolicyBuilder::without_baseline_denies`] for tests or rare break-glass cases.

use crate::paths::FsRule;
use std::path::PathBuf;

/// Credential / secret path prefixes that are always denied (read + write).
pub fn baseline_credential_path_denies() -> Vec<FsRule> {
    let home = home_dir();
    let mut rules = Vec::new();

    let dir_suffixes = [
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".config/gcloud",
        ".config/gh",
        ".netrc",
        // macOS key material (best-effort; may not exist)
        "Library/Keychains",
        "Library/IdentityServices",
    ];
    for s in dir_suffixes {
        rules.push(FsRule::deny(home.join(s)));
    }

    // Absolute well-known system secrets (Unix).
    for p in [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/master.passwd",
    ] {
        rules.push(FsRule::deny(p));
    }

    rules
}

/// Glob patterns denied by default (gitignore-style `**` where soft/kernel map supports it).
pub fn baseline_secret_glob_denies() -> Vec<FsRule> {
    [
        "**/.env",
        "**/.env.*",
        "**/.env.local",
        "**/*.pem",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/id_rsa",
        "**/id_ed25519",
        "**/id_ecdsa",
        "**/credentials.json",
        "**/.netrc",
        "**/secrets.yaml",
        "**/secrets.yml",
    ]
    .into_iter()
    .map(FsRule::deny_glob)
    .collect()
}

/// Full baseline deny set (paths + globs).
pub fn baseline_deny_rules() -> Vec<FsRule> {
    let mut v = baseline_credential_path_denies();
    v.extend(baseline_secret_glob_denies());
    v
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_includes_ssh_and_env_glob() {
        let rules = baseline_deny_rules();
        assert!(rules.iter().any(|r| r.path.ends_with(".ssh") && !r.glob));
        assert!(rules.iter().any(|r| {
            r.glob && r.path.to_string_lossy().contains(".env")
        }));
    }
}
