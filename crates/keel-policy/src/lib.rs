//! Execution policy: what an agent space may reach.
//!
//! Policy is bound before the agent runs and cannot be expanded by the agent.
//! Enforce backends turn a [`Policy`] into real OS / workspace constraints.

mod egress;
mod error;
mod ids;
mod net;
mod paths;
mod policy;
mod presets;

pub use egress::{
    allowlist_ports, check_egress, host_matches, EgressDecision,
};
pub use error::{PolicyError, PolicyResult};
pub use ids::{PolicyId, SpaceId, TaskId};
pub use net::{NetworkPolicy, NetworkRule};
pub use paths::{FsAccess, FsRule, PathPattern};
pub use policy::{CredentialGrant, ExecPolicy, Policy, PolicyBuilder};
pub use presets::{profile_read_only, profile_strict, profile_workspace};
