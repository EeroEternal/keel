# Integrating Keel into an agent host

Keel is an **execution layer**: your agent still owns prompts, tools, and UX.
Keel owns **reach** (FS / network / credentials / worktree) when side effects run.

## Dependency

On crates.io the packages are named **`keel-exec-*`** (see root README). Library
imports still use `keel_core` / `keel_policy` / etc.

```toml
[dependencies]
keel-exec-core = "0.0.8"
```

```bash
# CLI
cargo install keel-exec-cli
```

## Minimal embed

```rust
use std::sync::Arc;
use keel_core::{
    profile_workspace, worktree_sandboxed, LocalProcessOptions, Space, SpaceOptions,
    SpawnRequest, WorktreeOptions,
};

# async fn example() -> anyhow::Result<()> {
let cwd = std::env::current_dir()?;
let mut policy = profile_workspace(&cwd)?;
// Optional: tighten egress
// policy.network = NetworkPolicy::Allowlist(vec![NetworkRule::host_port("api.x.ai", 443)]);

let backend = worktree_sandboxed(
    WorktreeOptions::default(),
    LocalProcessOptions::default(), // isolate_apply = true
);

let space = Space::create_with(
    policy,
    backend,
    SpaceOptions {
        persist_events: true,
        strict_credentials: false,
        record_violations: true,
        ..Default::default()
    },
)
.await?;

// Before a tool call (optional preflight):
// assert!(space.check_fs(Path::new("src/main.rs"), true).await?);
// assert!(space.check_egress("api.x.ai", 443).await?);

let mut child = space
    .spawn(SpawnRequest::new("cargo").args(["test"]))
    .await?;
let status = child.child.wait().await?;

if let Some(path) = space.events_path() {
    eprintln!("keel audit log: {}", path.display());
}
space.destroy().await?;
# let _ = status;
# Ok(())
# }
```

## Per-task child space

```rust
use keel_core::{TaskId, TaskSpec, NetworkPolicy};

# async fn task_example(parent: &keel_core::SpaceHandle) -> anyhow::Result<()> {
let child = parent
    .open_task_in_worktree(
        TaskSpec {
            task_id: TaskId::from_string("tsk-review"),
            network: Some(NetworkPolicy::DenyAll),
            extra_deny: vec![std::path::PathBuf::from(".env")],
            ..Default::default()
        },
        Default::default(),
    )
    .await?;
// run read-only / offline work in `child`, then:
child.destroy().await?;
# Ok(())
# }
```

Child policies **cannot expand** parent reach (`narrow_policy`). For glob denials, set `FsRule::deny_glob` on the child policy after narrow, or add them on the parent.

## What the host still owns

| Host | Keel |
|------|------|
| Model prompts / tool schemas | Policy reach |
| Permission prompts / YOLO modes | Soft + kernel enforcement |
| MCP server processes | Spawned child env (proxy, creds) |
| Session transcript | `events.jsonl` audit trail |

## Environment contract

| Variable | Purpose |
|----------|---------|
| `KEEL_HOME` | State root (default `~/.keel`) |
| `KEEL_BWRAP` | Override bubblewrap binary (Linux deny) |
| `KEEL_KERNEL_TEST` | Enable kernel e2e tests (`=1`) |
| `KEEL_EGRESS_PROXY_PORT` | Set by Keel for sandboxed children (do not set manually) |
| `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` | Injected for allowlisted spaces |

See also [`testing.md`](./testing.md) and [`optimization-plan.md`](./optimization-plan.md).
