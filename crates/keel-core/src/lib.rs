//! Keel core: bind a [`Policy`] to an [`EnforceBackend`] and a [`RecordSink`]
//! as a durable **execution space**.

mod error;
mod space;

pub use error::{KeelError, KeelResult};
pub use space::{Space, SpaceHandle, SpaceState};

pub use keel_enforce::{
    BackendInfo, EnforceBackend, NullBackend, ProcessGuardBackend, SpawnRequest, SpawnedProcess,
};
pub use keel_policy::{
    profile_read_only, profile_strict, profile_workspace, CredentialGrant, ExecPolicy, FsAccess,
    FsRule, NetworkPolicy, NetworkRule, Policy, PolicyBuilder, PolicyId, SpaceId, TaskId,
};
pub use keel_record::{
    EventKind, JsonlSink, MemorySink, MultiSink, RecordEvent, RecordSink,
};
