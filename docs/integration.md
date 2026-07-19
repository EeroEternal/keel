# Integrating Keel into an agent host

Keel is an **execution layer**: your agent still owns prompts, tools, and UX.
Keel owns **reach** (FS / network / credentials / worktree) when side effects run.

## Dependency

On crates.io the packages are named **`eero-keel-*`** (owner EeroEternal; see root README).
Library imports still use `keel_core` / `keel_policy` / etc.

```toml
[dependencies]
eero-keel-core = "0.0.11"
```

```bash
# CLI
cargo install eero-keel-cli
```

## Minimal embed

```rust
use std::sync::Arc;
use std::time::Duration;
use keel_core::{
    profile_workspace, worktree_sandboxed, LocalProcessOptions, Space, SpaceOptions,
    SpawnRequest, StdioMode, WorktreeOptions,
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

// Host tools: prefer SpaceFs over raw std::fs + check_fs.
// space.fs().write("src/main.rs", code).await?;

// MCP stdio: pipe stdin/stdout into the child
// let mut mcp = space.spawn(
//     SpawnRequest::new("my-mcp-server")
//         .stdin(StdioMode::Piped)
//         .stdout(StdioMode::Piped)
//         .stderr(StdioMode::Inherit),
// ).await?;
// let stdin = mcp.take_stdin();
// let stdout = mcp.take_stdout();

// Shell with secrets in -c: do not audit args
let exit = space
    .spawn(
        SpawnRequest::new("bash")
            .args(["-lc", "curl -H \"Authorization: Bearer …\" …"])
            .audit_args(false),
    )
    .await?
    .wait_timeout(Duration::from_secs(120))
    .await?;
// exit.exit_code / exit.duration / exit.termination_reason

if let Some(path) = space.events_path() {
    eprintln!("keel audit log: {}", path.display());
}
space.destroy().await?;
# let _ = exit;
# Ok(())
# }
```

## Zene-oriented APIs (v0.0.11+)

| Need | API |
|------|-----|
| MCP / stdio servers | `SpawnRequest::stdin/stdout/stderr(StdioMode::…)` + `ManagedProcess::take_stdin/out` |
| Timeout + collect output | `wait_with_output_timeout(dur)` |
| CancellationToken + timeout + output | `wait_with_output_cancel(&token, dur)` |
| No zombie shell grandchildren | process-group kill on timeout/cancel/**Drop** (Unix) |
| Exit audit | `EventKind::ExecFinished` + `ProcessExit` |
| Secret-safe exec logs | `.audit_args(false)` → `Exec { args_redacted: true, args: [] }` |
| Read/Write/Edit tools | `space.fs().read/write/create/delete/rename/metadata` |

### SpaceFs soft boundary (keep host defenses)

SpaceFs authorizes then performs I/O — there is a **TOCTOU** window. It is **not** a sealed
sandbox for the host agent process. Zene should **retain** `O_NOFOLLOW`, post-open path
re-checks, and similar controls; do not remove them solely because SpaceFs exists.

`check_fs` remains a soft preflight for hosts that still do their own I/O; **SpaceFs**
performs I/O under policy and records `FsAccess`.

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
