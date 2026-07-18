//! Apply kernel sandbox in the **child** process (pre_exec / helper), not the host.

use crate::error::{EnforceError, EnforceResult};
use crate::map_caps::{policy_to_capability_set, MapOptions};
use keel_policy::Policy;
use nono::Sandbox;
use std::path::Path;
use tracing::info;

/// Validate that the policy can be mapped and the platform supports sandboxing.
pub fn prepare_kernel(policy: &Policy, block_process_network: bool) -> EnforceResult<()> {
    let support = Sandbox::support_info();
    if !support.is_supported {
        return Err(EnforceError::Unsupported(support.details));
    }
    let proxy_port = std::env::var(crate::egress_proxy::EGRESS_PROXY_PORT_ENV)
        .ok()
        .and_then(|s| s.parse().ok());
    let _ = policy_to_capability_set(
        policy,
        MapOptions {
            block_process_network,
            egress_proxy_port: proxy_port,
        },
    )?;
    Ok(())
}

/// Apply Landlock/Seatbelt for the **current** process (call only in child / helper).
pub fn apply_kernel_here(policy: &Policy, block_process_network: bool) -> EnforceResult<()> {
    let support = Sandbox::support_info();
    if !support.is_supported {
        return Err(EnforceError::Unsupported(support.details));
    }
    let proxy_port = std::env::var(crate::egress_proxy::EGRESS_PROXY_PORT_ENV)
        .ok()
        .and_then(|s| s.parse().ok());
    let caps = policy_to_capability_set(
        policy,
        MapOptions {
            block_process_network,
            egress_proxy_port: proxy_port,
        },
    )?;
    Sandbox::apply(&caps).map_err(|e| EnforceError::ApplyFailed(e.to_string()))?;
    info!(
        policy_id = %policy.id,
        platform = support.platform,
        proxy_port = ?proxy_port,
        "kernel sandbox applied in child process"
    );
    Ok(())
}

/// Load policy JSON from path and apply (used by `keel sandbox-exec`).
pub fn apply_policy_file_and_ready(
    path: &Path,
    block_process_network: bool,
) -> EnforceResult<Policy> {
    let raw = std::fs::read_to_string(path)?;
    let policy = Policy::from_json(&raw).map_err(EnforceError::from)?;
    apply_kernel_here(&policy, block_process_network)?;
    Ok(policy)
}

/// Write policy JSON for child spawn; returns path.
pub fn write_spawn_policy_file(policy: &Policy) -> EnforceResult<std::path::PathBuf> {
    let dir = {
        if let Ok(h) = std::env::var("KEEL_HOME") {
            std::path::PathBuf::from(h).join("tmp")
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                .join(".keel")
                .join("tmp")
        }
    };
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "policy-{}-{}.json",
        policy.id.as_str(),
        std::process::id()
    ));
    std::fs::write(&path, policy.to_json().map_err(EnforceError::from)?)?;
    Ok(path)
}
