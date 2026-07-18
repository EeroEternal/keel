//! Record: ground-truth events for a Keel space.
//!
//! Distinct from agent framework logs: these describe FS / net / exec / lifecycle
//! as observed or enacted by Keel, always tagged with policy and space ids.

mod event;
mod paths;
mod sink;

pub use event::{EventKind, RecordEvent};
pub use paths::{keel_home, keel_tmp_dir, space_dir, space_events_path, space_policy_path};
pub use sink::{JsonlSink, MemorySink, MultiSink, RecordSink, default_space_sink};
