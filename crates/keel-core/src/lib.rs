//! Keel core: bind a [`Policy`] to an [`EnforceBackend`] and a [`RecordSink`]
//! as a durable **execution space**.

mod error;
mod space;

pub use error::{KeelError, KeelResult};
pub use space::{Space, SpaceHandle, SpaceOptions, SpaceState};

pub use keel_enforce::{
    BackendInfo, EnforceBackend, LocalProcessBackend, LocalProcessOptions, NullBackend,
    ProcessGuardBackend, SpawnRequest, SpawnedProcess,
};

#[cfg(unix)]
pub use keel_enforce::{apply_policy_file_and_ready, prepare_kernel};
pub use keel_policy::{
    check_egress, profile_read_only, profile_strict, profile_workspace, CredentialGrant,
    EgressDecision, ExecPolicy, FsAccess, FsRule, NetworkPolicy, NetworkRule, Policy,
    PolicyBuilder, PolicyId, SpaceId, TaskId,
};
pub use keel_record::{
    default_space_sink, keel_home, space_dir, space_events_path, space_policy_path, EventKind,
    JsonlSink, MemorySink, MultiSink, RecordEvent, RecordSink,
};
