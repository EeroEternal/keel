//! Standard on-disk layout for Keel state.
//!
//! ```text
//! $KEEL_HOME or ~/.keel/
//!   spaces/<space_id>/
//!     events.jsonl
//!     policy.json      (optional, written by core)
//!   tmp/               (ephemeral policy files for sandboxed spawn)
//! ```

use keel_policy::SpaceId;
use std::path::PathBuf;

/// Keel state directory (`$KEEL_HOME` or `~/.keel`).
pub fn keel_home() -> PathBuf {
    if let Ok(h) = std::env::var("KEEL_HOME") {
        let p = PathBuf::from(h);
        if !p.as_os_str().is_empty() {
            return p;
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".keel")
}

/// Directory for one space: `~/.keel/spaces/<id>/`.
pub fn space_dir(space_id: &SpaceId) -> PathBuf {
    keel_home().join("spaces").join(space_id.as_str())
}

/// Default event log path: `~/.keel/spaces/<id>/events.jsonl`.
pub fn space_events_path(space_id: &SpaceId) -> PathBuf {
    space_dir(space_id).join("events.jsonl")
}

/// Optional persisted policy snapshot path.
pub fn space_policy_path(space_id: &SpaceId) -> PathBuf {
    space_dir(space_id).join("policy.json")
}

/// Ephemeral dir for spawn-time policy files.
pub fn keel_tmp_dir() -> PathBuf {
    keel_home().join("tmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join() {
        let id = SpaceId::from_string("spc-test");
        let ev = space_events_path(&id);
        assert!(ev.ends_with("spaces/spc-test/events.jsonl") || ev.to_string_lossy().contains("spc-test"));
    }
}
