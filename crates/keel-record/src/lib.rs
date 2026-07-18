//! Record: ground-truth events for a Keel space.
//!
//! Distinct from agent framework logs: these describe FS / net / exec / lifecycle
//! as observed or enacted by Keel, always tagged with policy and space ids.

mod event;
mod sink;

pub use event::{EventKind, RecordEvent};
pub use sink::{JsonlSink, MemorySink, MultiSink, RecordSink};
