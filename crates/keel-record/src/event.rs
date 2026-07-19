use chrono::{DateTime, Utc};
use keel_policy::{PolicyId, SpaceId, TaskId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    SpaceCreated {
        backend: String,
        label: Option<String>,
    },
    SpaceDestroyed {
        reason: String,
    },
    PolicyBound {
        label: Option<String>,
    },
    FsAccess {
        path: PathBuf,
        operation: String,
        allowed: bool,
        /// Optional SHA-256 of written/read payload (host SpaceFs writes).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_sha256: Option<String>,
    },
    NetDial {
        host: String,
        port: Option<u16>,
        allowed: bool,
    },
    Exec {
        program: String,
        /// Empty when [`args_redacted`] is true.
        args: Vec<String>,
        allowed: bool,
        /// When true, `args` were intentionally omitted (secrets / long shell -c).
        #[serde(default)]
        args_redacted: bool,
    },
    /// Process finished (exit, timeout, cancel, signal).
    ExecFinished {
        program: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        duration_ms: u64,
        /// `exited` | `timed_out` | `cancelled` | `killed` | `signal` | `unknown`
        termination_reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },
    CredentialIssued {
        name: String,
    },
    CredentialRevoked {
        name: String,
    },
    Violation {
        operation: String,
        target: String,
        detail: Option<String>,
    },
    Note {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEvent {
    pub timestamp: DateTime<Utc>,
    pub space_id: SpaceId,
    pub policy_id: PolicyId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    pub event: EventKind,
    /// SHA-256 hex of previous event's `event_hash` (or genesis marker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    /// SHA-256 hex of this event's integrity body (see `chain` module).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

impl RecordEvent {
    pub fn new(
        space_id: SpaceId,
        policy_id: PolicyId,
        task_id: Option<TaskId>,
        event: EventKind,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            space_id,
            policy_id,
            task_id,
            event,
            prev_hash: None,
            event_hash: None,
        }
    }
}
