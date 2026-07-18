//! Enforce: turn a [`keel_policy::Policy`] into a real execution boundary.
//!
//! Backends:
//! - [`NullBackend`] — records + soft checks only
//! - [`ProcessGuardBackend`] — soft process spawn / FS guard
//! - [`LocalProcessBackend`] — Landlock (Linux) / Seatbelt (macOS) via nono;
//!   default **isolate_apply** sandboxes children only (host stays clean).
//!   Linux read-deny uses bubblewrap bind-over.

mod backend;
mod error;
mod null;
mod process_guard;

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
pub use error::{EnforceError, EnforceResult};
pub use local_process::{LocalProcessBackend, LocalProcessOptions};
pub use null::NullBackend;
pub use process_guard::ProcessGuardBackend;

#[cfg(all(unix, feature = "kernel"))]
pub use map_caps::{policy_to_capability_set, MapOptions};

#[cfg(all(unix, feature = "kernel"))]
pub use sandbox_child::{
    apply_kernel_here, apply_policy_file_and_ready, prepare_kernel, write_spawn_policy_file,
};
