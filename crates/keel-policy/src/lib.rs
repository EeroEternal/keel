//! Execution policy: what an agent space may reach.
//!
//! Policy is bound before the agent runs and cannot be expanded by the agent.
//! Enforce backends turn a [`Policy`] into real OS / workspace constraints.

mod baseline;
mod config;
mod egress;
mod error;
mod ids;
mod narrow;
mod net;
mod paths;
mod policy;
mod presets;

pub use baseline::{
    baseline_credential_path_denies, baseline_deny_rules, baseline_secret_glob_denies,
};
pub use config::{
    load_policy_from_sandbox_toml, resolve_policy_with_files, ProfileConfig, SandboxConfig,
    SandboxConfigFile,
};
pub use egress::{allowlist_ports, check_egress, host_matches, EgressDecision};
pub use error::{PolicyError, PolicyResult};
pub use ids::{PolicyId, SpaceId, TaskId};
pub use narrow::{narrow_policy, TaskSpec};
pub use net::{NetworkPolicy, NetworkRule};
pub use paths::{FsAccess, FsRule, PathPattern};
pub use policy::{CredentialGrant, ExecPolicy, Policy, PolicyBuilder};
pub use presets::{profile_read_only, profile_strict, profile_workspace};
