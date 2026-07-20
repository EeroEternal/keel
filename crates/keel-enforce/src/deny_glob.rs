//! Deny-glob expansion and Seatbelt regex translation (optimization plan Phase 2).

use crate::error::{EnforceError, EnforceResult};
use keel_policy::{FsAccess, Policy};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Maximum matches per glob (fail closed if exceeded under require_kernel).
pub const DENY_GLOB_MAX_MATCHES: usize = 10_000;

/// Expand policy deny globs to concrete paths under the workspace (and absolute roots).
pub fn expand_deny_globs(policy: &Policy) -> EnforceResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    for rule in policy.fs.iter().filter(|r| r.access == FsAccess::Deny && r.glob) {
        let pattern = rule.path.to_string_lossy();
        let matches = expand_one(policy, &pattern)?;
        if matches.is_empty() {
            warn!(
                pattern = %pattern,
                "deny glob matched zero paths at expand time (later creates may not be covered on Linux)"
            );
        }
        out.extend(matches);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn expand_one(policy: &Policy, pattern: &str) -> EnforceResult<Vec<PathBuf>> {
    // Relative patterns anchor at workspace; absolute at filesystem root.
    let (base, rel_pat) = if pattern.starts_with('/') {
        (PathBuf::from("/"), pattern.trim_start_matches('/').to_string())
    } else {
        (policy.workspace.clone(), pattern.to_string())
    };

    // Use globset against a walk of base (depth-capped).
    let glob = globset::Glob::new(&rel_pat)
        .map_err(|e| EnforceError::ApplyFailed(format!("invalid deny glob '{pattern}': {e}")))?;
    let matcher = globset::GlobSetBuilder::new()
        .add(glob)
        .build()
        .map_err(|e| EnforceError::ApplyFailed(format!("globset build: {e}")))?;

    let mut matches = Vec::new();
    let walker = ignore::WalkBuilder::new(&base)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .max_depth(Some(32))
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        let rel = match path.strip_prefix(&base) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if matcher.is_match(rel) {
            matches.push(path.to_path_buf());
            if matches.len() > DENY_GLOB_MAX_MATCHES {
                return Err(EnforceError::ApplyFailed(format!(
                    "deny glob '{pattern}' exceeded {DENY_GLOB_MAX_MATCHES} matches"
                )));
            }
        }
    }
    Ok(matches)
}

/// Translate a gitignore-style glob to a Seatbelt-oriented regex (anchored).
///
/// Dialect (documented):
/// - `*` — one path segment (no `/`)
/// - `**` — any path segments
/// - `?` — one character except `/`
/// - other characters literal (regex-escaped)
pub fn glob_to_seatbelt_regex(workspace: &Path, pattern: &str) -> EnforceResult<String> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(EnforceError::ApplyFailed("empty deny glob".into()));
    }

    let (prefix, body) = if pattern.starts_with('/') {
        (String::new(), pattern)
    } else {
        let ws = workspace
            .to_str()
            .ok_or_else(|| EnforceError::ApplyFailed("workspace not utf-8".into()))?;
        let ws = ws.trim_end_matches('/');
        (format!("^{}", regex_escape(ws)), pattern)
    };

    let mut re = if prefix.is_empty() {
        String::from("^")
    } else {
        prefix
    };

    // Ensure path separator after workspace when relative.
    if !pattern.starts_with('/') {
        re.push('/');
    }

    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                // ** optionally followed by /
                i += 2;
                if i < chars.len() && chars[i] == '/' {
                    i += 1;
                    re.push_str("(.*/)?");
                } else {
                    re.push_str(".*");
                }
            }
            '*' => {
                re.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                re.push_str("[^/]");
                i += 1;
            }
            c => {
                re.push_str(&regex_escape(&c.to_string()));
                i += 1;
            }
        }
    }
    re.push('$');
    Ok(re)
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Emit macOS Seatbelt deny rules for glob patterns on a CapabilitySet.
#[cfg(all(unix, feature = "kernel", target_os = "macos"))]
pub fn apply_deny_globs_seatbelt(
    caps: &mut nono::CapabilitySet,
    policy: &Policy,
) -> EnforceResult<usize> {
    let mut n = 0;
    for rule in policy.fs.iter().filter(|r| r.access == FsAccess::Deny && r.glob) {
        let pattern = rule.path.to_string_lossy();
        let re = glob_to_seatbelt_regex(&policy.workspace, &pattern)?;
        let filter = format!("(regex \"{}\")", escape_sexp_string(&re));
        emit_seatbelt_deny_filter(caps, &filter)?;
        n += 1;
        info!(pattern = %pattern, regex = %re, "seatbelt deny glob applied");
    }
    Ok(n)
}

#[cfg(all(unix, feature = "kernel", target_os = "macos"))]
fn escape_sexp_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(all(unix, feature = "kernel", target_os = "macos"))]
fn emit_seatbelt_deny_filter(caps: &mut nono::CapabilitySet, filter: &str) -> EnforceResult<()> {
    const WRITE_ACTIONS: &[&str] = &[
        "file-write-data",
        "file-write-create",
        "file-write-unlink",
        "file-write-mode",
        "file-write-owner",
        "file-write-flags",
        "file-write-times",
        "file-write-setugid",
    ];
    caps.add_platform_rule(format!("(deny file-read* {filter})"))
        .map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    caps.add_platform_rule(format!("(deny file-write* {filter})"))
        .map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    for action in WRITE_ACTIONS {
        caps.add_platform_rule(format!("(deny {action} {filter})"))
            .map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    }
    Ok(())
}

/// Soft check: does path match any deny glob in the policy?
pub fn path_matches_deny_glob(policy: &Policy, path: &Path) -> bool {
    let path_s = path.to_string_lossy();
    for rule in policy.fs.iter().filter(|r| r.access == FsAccess::Deny && r.glob) {
        let pattern = rule.path.to_string_lossy();
        if let Ok(re) = glob_to_seatbelt_regex(&policy.workspace, &pattern) {
            // Strip anchors for a loose contains-style check via simple glob matcher.
            if let Ok(g) = globset::Glob::new(pattern.trim_start_matches('/')) {
                let set = globset::GlobSetBuilder::new().add(g).build();
                if let Ok(set) = set {
                    let rel = path
                        .strip_prefix(&policy.workspace)
                        .unwrap_or(path);
                    if set.is_match(rel) || set.is_match(path) {
                        return true;
                    }
                }
            }
            let _ = re;
            let _ = path_s;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_policy::Policy;
    use std::fs;

    #[test]
    fn glob_to_regex_relative() {
        let re = glob_to_seatbelt_regex(Path::new("/ws"), "**/.env").unwrap();
        assert!(re.contains(".env"));
        assert!(re.starts_with('^'));
    }

    #[test]
    fn expand_finds_env_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "X=1").unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/.env"), "Y=1").unwrap();
        let policy = Policy::builder(dir.path())
            .deny_glob("**/.env")
            .build()
            .unwrap();
        let m = expand_deny_globs(&policy).unwrap();
        assert!(m.len() >= 2, "matches={m:?}");
    }

    #[test]
    fn soft_match_env() {
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy::builder(dir.path())
            .deny_glob("**/.env")
            .build()
            .unwrap();
        assert!(path_matches_deny_glob(
            &policy,
            &dir.path().join("a/.env")
        ));
    }
}
