# Integrating Keel into an agent host

Keel is an **execution layer**: your agent still owns prompts, tools, and UX.
Keel owns **reach** (FS / network / credentials / worktree) when side effects run.

## Dependency

On crates.io the packages are named **`eero-keel-*`** (owner EeroEternal; see root README).
Library imports still use `keel_core` / `keel_policy` / etc.

```toml
[dependencies]
eero-keel-core = "0.0.14"
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

// Host tools: ALWAYS use SpaceFs for Read/Write/Edit — not check_fs + raw tokio::fs.
space.fs().write("src/main.rs", b"// code").await?;
// check_fs is advisory only (UI hints).

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

## Threat levels (pick deliberately)

| Level | Model | Use when |
|-------|--------|----------|
| **L0** | Soft policy + **`space.fs()`** | Cooperative host tools; not a hard boundary |
| **L1** | Child OS isolation (`LocalProcess`, default `isolate_apply`) — Unix Landlock/Seatbelt, Windows Job | Shell/tool subprocesses / process trees |
| **L2** | **`Space::create_confined`** (host Landlock/Seatbelt) | Dedicated agent process; no second policy in-process |
| **L3** | Worktree / netns / microVM (partial / future) | Stronger multi-tenant isolation |

Default embed = **L1** (host stays clean). Call `Space::create_confined(policy, opts)` for **L2**.

Baseline **always-deny** (`~/.ssh`, `**/.env`, …) applies to all builder-built policies unless
`Policy::builder(ws).without_baseline_denies()`.

## Zene-oriented APIs (v0.0.13+)

| Need | API |
|------|-----|
| File tools (required path) | **`space.fs().read/write/create/delete/rename/metadata`** |
| UI “would this path be allowed?” | `check_fs` / `check_fs_advisory` only — **do not** pair with raw `tokio::fs` |
| MCP / stdio servers | `SpawnRequest::stdin/stdout/stderr(StdioMode::…)` + `take_stdin/out` |
| Timeout + collect output | `wait_with_output_timeout(dur)` |
| CancellationToken + timeout + output | `wait_with_output_cancel(&token, dur)` |
| Process-group cleanup | timeout / cancel / **Drop** (Unix) |
| Whole-process sandbox | `Space::create_confined` |
| Secret-safe exec logs | `.audit_args(false)` |
| Audit integrity | default `integrity_chain`; `verify_chain` / `verify_jsonl` on `events.jsonl` |

Disable hash chain only if needed: `SpaceOptions { integrity_chain: false, .. }`.

### SpaceFs soft boundary (keep host defenses)

SpaceFs authorizes then performs I/O — there is a **TOCTOU** window on an unconfined host.
It is **not** a sealed sandbox for the agent process. **Retain** `O_NOFOLLOW`, post-open path
re-checks, and similar controls. For host-level enforcement use **L2** `create_confined`.

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
