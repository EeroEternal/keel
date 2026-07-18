//! Keel core: bind a [`Policy`] to an [`EnforceBackend`] and a [`RecordSink`]
//! as a durable **execution space**.

mod error;
mod space;

pub use error::{KeelError, KeelResult};
pub use space::{Space, SpaceHandle, SpaceOptions, SpaceState};

pub use keel_enforce::{
    local_process as backend_local_process, process_guard as backend_process_guard,
    worktree_sandboxed, worktree_soft, BackendInfo, EnforceBackend, LocalProcessBackend,
    LocalProcessOptions, NullBackend, ProcessGuardBackend, SpawnRequest, SpawnedProcess,
    WorktreeBackend, WorktreeOptions,
};

#[cfg(unix)]
pub use keel_enforce::{apply_policy_file_and_ready, prepare_kernel};
pub use keel_policy::{
    check_egress, load_policy_from_sandbox_toml, narrow_policy, profile_read_only, profile_strict,
    profile_workspace, resolve_policy_with_files, CredentialGrant, EgressDecision, ExecPolicy,
    FsAccess, FsRule, NetworkPolicy, NetworkRule, Policy, PolicyBuilder, PolicyId, SandboxConfig,
    SpaceId, TaskId, TaskSpec,
};
pub use keel_record::{
    default_space_sink, keel_home, space_dir, space_events_path, space_policy_path, EventKind,
    JsonlSink, MemorySink, MultiSink, RecordEvent, RecordSink,
};
