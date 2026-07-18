//! Enforce: turn a [`keel_policy::Policy`] into a real execution boundary.
//!
//! Backends:
//! - [`NullBackend`] — records + soft checks only (default, portable)
//! - [`ProcessGuardBackend`] — soft process spawn guard (OS kernel sandbox is later)

mod backend;
mod error;
mod null;
mod process_guard;

pub use backend::{BackendInfo, EnforceBackend, SpawnRequest, SpawnedProcess};
pub use error::{EnforceError, EnforceResult};
pub use null::NullBackend;
pub use process_guard::ProcessGuardBackend;
