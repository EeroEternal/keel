//! Enforce: turn a [`keel_policy::Policy`] into a real execution boundary.
//!
//! Backends:
//! - [`NullBackend`] — records + soft checks only
//! - [`ProcessGuardBackend`] — soft process spawn / FS guard
//! - [`LocalProcessBackend`] — Landlock (Linux) / Seatbelt (macOS) via nono;
//!   default **isolate_apply** sandboxes children only (host stays clean).
//!   Linux read-deny uses bubblewrap bind-over.

mod backend;
mod compose;
mod credentials;
mod deny_glob;
mod egress_proxy;
mod error;
mod null;
mod process_guard;
mod worktree;

#[cfg(all(unix, feature = "kernel"))]
mod child_net;
#[cfg(all(unix, feature = "kernel"))]
mod map_caps;
#[cfg(all(unix, feature = "kernel"))]
mod sandbox_child;

#[cfg(all(feature = "kernel", target_os = "linux"))]
mod bwrap;

mod local_process;

pub use backend::{BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
pub use compose::{local_process, process_guard, worktree_sandboxed, worktree_soft};
pub use credentials::{
    grant_names, inject_into_env, resolve_credentials, revoke_resolved, CredentialSourceKind,
    ResolvedCredential,
};
pub use deny_glob::{
    expand_deny_globs, glob_to_seatbelt_regex, path_matches_deny_glob, DENY_GLOB_MAX_MATCHES,
};
pub use egress_proxy::{EgressProxy, EGRESS_PROXY_PORT_ENV};
pub use error::{EnforceError, EnforceResult};
pub use local_process::{LocalProcessBackend, LocalProcessOptions};
pub use null::NullBackend;
pub use process_guard::ProcessGuardBackend;
pub use worktree::{WorktreeBackend, WorktreeOptions};

#[cfg(all(unix, feature = "kernel"))]
pub use map_caps::{policy_to_capability_set, MapOptions};

#[cfg(all(unix, feature = "kernel"))]
pub use sandbox_child::{
    apply_kernel_here, apply_policy_file_and_ready, prepare_kernel, write_spawn_policy_file,
};
