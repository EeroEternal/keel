//! Record: ground-truth events for a Keel space.
//!
//! Distinct from agent framework logs: these describe FS / net / exec / lifecycle
//! as observed or enacted by Keel, always tagged with policy and space ids.
//!
//! Optional **hash chain** integrity: see [`HashChainSink`] and [`verify_chain`].

mod chain;
mod event;
mod paths;
mod sink;

pub use chain::{
    compute_event_hash, content_sha256, seal_event, verify_chain, verify_jsonl, ChainVerifyError,
    GENESIS_PREV,
};
pub use event::{EventKind, RecordEvent};
pub use paths::{keel_home, keel_tmp_dir, space_dir, space_events_path, space_policy_path};
pub use sink::{
    default_space_sink, HashChainSink, JsonlSink, MemorySink, MultiSink, RecordSink,
};
