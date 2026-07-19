//! SHA-256 hash chain for audit integrity.
//!
//! Each event carries `prev_hash` (previous event's `event_hash`) and its own
//! `event_hash`. Tampering with a middle line breaks the chain on verify.
//!
//! This does **not** stop an attacker who can replace the entire log file or
//! disable recording — it supports post-hoc integrity checks and enterprise
//! "policy pinned" evidence workflows.

use crate::event::{EventKind, RecordEvent};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Genesis previous-hash for the first event in a chain.
pub const GENESIS_PREV: &str = "keel-genesis-v1";

/// Body hashed for integrity (excludes `event_hash` itself).
#[derive(Serialize)]
struct HashBody<'a> {
    timestamp: &'a chrono::DateTime<chrono::Utc>,
    space_id: &'a str,
    policy_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<&'a str>,
    prev_hash: &'a str,
    event: &'a EventKind,
}

/// Compute SHA-256 hex of the canonical hash body for an event.
pub fn compute_event_hash(event: &RecordEvent) -> Result<String, String> {
    let prev = event
        .prev_hash
        .as_deref()
        .unwrap_or(GENESIS_PREV);
    let body = HashBody {
        timestamp: &event.timestamp,
        space_id: event.space_id.as_str(),
        policy_id: event.policy_id.as_str(),
        task_id: event.task_id.as_ref().map(|t| t.as_str()),
        prev_hash: prev,
        event: &event.event,
    };
    let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let digest = Sha256::digest(&bytes);
    Ok(hex_encode(&digest))
}

/// Attach `prev_hash` + `event_hash` using the previous hash in the chain.
pub fn seal_event(mut event: RecordEvent, prev_hash: Option<&str>) -> Result<RecordEvent, String> {
    event.prev_hash = Some(
        prev_hash
            .unwrap_or(GENESIS_PREV)
            .to_string(),
    );
    event.event_hash = None;
    let h = compute_event_hash(&event)?;
    event.event_hash = Some(h);
    Ok(event)
}

/// SHA-256 hex of arbitrary bytes (e.g. file contents written via SpaceFs).
pub fn content_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Result of verifying a sequence of chained events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerifyError {
    /// Event at index is missing hashes.
    MissingHash { index: usize },
    /// Recomputed hash does not match stored `event_hash`.
    HashMismatch { index: usize },
    /// `prev_hash` does not match previous event's `event_hash`.
    LinkBroken { index: usize },
}

/// Verify an ordered event list forms a valid hash chain.
pub fn verify_chain(events: &[RecordEvent]) -> Result<(), ChainVerifyError> {
    let mut expected_prev = GENESIS_PREV.to_string();
    for (index, ev) in events.iter().enumerate() {
        let Some(prev) = ev.prev_hash.as_deref() else {
            return Err(ChainVerifyError::MissingHash { index });
        };
        let Some(stored) = ev.event_hash.as_deref() else {
            return Err(ChainVerifyError::MissingHash { index });
        };
        if prev != expected_prev {
            return Err(ChainVerifyError::LinkBroken { index });
        }
        let recomputed = compute_event_hash(ev).map_err(|_| ChainVerifyError::HashMismatch { index })?;
        if recomputed != stored {
            return Err(ChainVerifyError::HashMismatch { index });
        }
        expected_prev = stored.to_string();
    }
    Ok(())
}

/// Load JSONL from a string and verify the chain.
pub fn verify_jsonl(text: &str) -> Result<Vec<RecordEvent>, String> {
    let mut events = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ev: RecordEvent = serde_json::from_str(line)
            .map_err(|e| format!("line {}: parse: {e}", i + 1))?;
        events.push(ev);
    }
    verify_chain(&events).map_err(|e| format!("{e:?}"))?;
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;
    use keel_policy::{PolicyId, SpaceId};

    fn note(msg: &str) -> RecordEvent {
        RecordEvent::new(
            SpaceId::from_string("spc"),
            PolicyId::from_string("pol"),
            None,
            EventKind::Note {
                message: msg.into(),
            },
        )
    }

    #[test]
    fn chain_seals_and_verifies() {
        let e1 = seal_event(note("a"), None).unwrap();
        let e2 = seal_event(note("b"), e1.event_hash.as_deref()).unwrap();
        let e3 = seal_event(note("c"), e2.event_hash.as_deref()).unwrap();
        assert!(verify_chain(&[e1.clone(), e2.clone(), e3.clone()]).is_ok());

        let mut bad = e2.clone();
        bad.event = EventKind::Note {
            message: "tampered".into(),
        };
        assert!(matches!(
            verify_chain(&[e1, bad, e3]),
            Err(ChainVerifyError::HashMismatch { index: 1 })
        ));
    }

    #[test]
    fn content_hash_stable() {
        assert_eq!(content_sha256(b"hello"), content_sha256(b"hello"));
        assert_ne!(content_sha256(b"hello"), content_sha256(b"world"));
    }
}
