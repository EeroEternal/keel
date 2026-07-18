//! Enforce: turn a [`keel_policy::Policy`] into a real execution boundary.
//!
//! Backends:
//! - [`NullBackend`] — records + soft checks only
//! - [`ProcessGuardBackend`] — soft process spawn / FS guard
//! - [`LocalProcessBackend`] — Landlock (Linux) / Seatbelt (macOS) via nono

mod backend;
mod error;
mod null;
mod process_guard;

#[cfg(all(unix, feature = "kernel"))]
mod child_net;
#[cfg(all(unix, feature = "kernel"))]
mod map_caps;

mod local_process;

pub use backend::{BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
pub use error::{EnforceError, EnforceResult};
pub use local_process::{LocalProcessBackend, LocalProcessOptions};
pub use null::NullBackend;
pub use process_guard::ProcessGuardBackend;

#[cfg(all(unix, feature = "kernel"))]
pub use map_caps::{policy_to_capability_set, MapOptions};
