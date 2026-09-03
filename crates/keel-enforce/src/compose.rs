//! Backend composition factories (optimization plan Phase 1).

use crate::local_process::{LocalProcessBackend, LocalProcessOptions};
use crate::process_guard::ProcessGuardBackend;
use crate::worktree::{WorktreeBackend, WorktreeOptions};
use crate::backend::EnforceBackend;
use std::sync::Arc;

/// Worktree isolation only (soft process-guard inside).
pub fn worktree_soft(opts: WorktreeOptions) -> Arc<dyn EnforceBackend> {
    Arc::new(WorktreeBackend::with_options(opts))
}

/// Worktree + LocalProcess (kernel FS on children) — closest to Grok's
/// "isolated tree + OS sandbox" stack for coding agents.
pub fn worktree_sandboxed(
    worktree: WorktreeOptions,
    local: LocalProcessOptions,
) -> Arc<dyn EnforceBackend> {
    let inner = Arc::new(LocalProcessBackend::with_options(local));
    Arc::new(WorktreeBackend::with_inner(inner, worktree))
}

/// Local-process only (no worktree).
pub fn local_process(opts: LocalProcessOptions) -> Arc<dyn EnforceBackend> {
    Arc::new(LocalProcessBackend::with_options(opts))
}

/// Local-process with **host** Landlock/Seatbelt (`isolate_apply = false`).
/// Prefer [`keel_core::Space::create_confined`] for the full Space lifecycle.
pub fn local_process_confined() -> Arc<dyn EnforceBackend> {
    Arc::new(LocalProcessBackend::with_options(
        LocalProcessOptions::confine_host(),
    ))
}

/// Soft process-guard only.
pub fn process_guard() -> Arc<dyn EnforceBackend> {
    Arc::new(ProcessGuardBackend::new())
}

/// AgentCell unprivileged Linux sandbox backend.
pub fn agentcell(opts: crate::agentcell::AgentCellOptions) -> Arc<dyn EnforceBackend> {
    Arc::new(crate::agentcell::AgentCellBackend::with_options(opts))
}

/// Worktree + AgentCell sandbox backend.
pub fn worktree_agentcell(
    worktree: WorktreeOptions,
    agentcell_opts: crate::agentcell::AgentCellOptions,
) -> Arc<dyn EnforceBackend> {
    let inner = Arc::new(crate::agentcell::AgentCellBackend::with_options(agentcell_opts));
    Arc::new(WorktreeBackend::with_inner(inner, worktree))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_names() {
        let soft = worktree_soft(WorktreeOptions::default());
        assert_eq!(soft.info().name, "local-worktree");

        let sandboxed = worktree_sandboxed(
            WorktreeOptions::default(),
            LocalProcessOptions::default(),
        );
        assert_eq!(sandboxed.info().name, "local-worktree");
        // Kernel flag comes from inner LocalProcess on unix+kernel.
        let _ = sandboxed.info().kernel_fs;

        assert_eq!(local_process(LocalProcessOptions::default()).info().name, "local-process");
        assert_eq!(process_guard().info().name, "process-guard");

        let ac = agentcell(crate::agentcell::AgentCellOptions::default());
        assert_eq!(ac.info().name, "agentcell");
        assert!(ac.info().kernel_fs);

        let wt_ac = worktree_agentcell(
            WorktreeOptions::default(),
            crate::agentcell::AgentCellOptions::default(),
        );
        assert_eq!(wt_ac.info().name, "local-worktree");
    }
}
