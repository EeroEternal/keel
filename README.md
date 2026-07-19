# Keel

**The execution layer under AI agents.**

Agents decide *what* to do. Keel decides *what is allowed to become real* — filesystem access, subprocesses, network egress, and credentials — without trusting the model’s story about what it “needs.”

```text
┌─────────────────────────────┐
│  Agent runtime              │  Grok · Codex · Zene · custom hosts
│  (plans, tools, prompts)    │
└──────────────┬──────────────┘
               │ policy · spawn · SpaceFs · events
┌──────────────▼──────────────┐
│  Keel                       │  Policy · Enforce · Record · Lifecycle
│  Secure execution space     │
└─────────────────────────────┘
```

Named after a ship’s **keel**: the structural spine underneath. The agent rides on top; Keel keeps real host access from tearing things apart.

> **One line:** Keel is the landing gate under the agent — bind reach first, execute under policy, audit what actually happened.

## What Keel does

| Capability | What you get |
|------------|----------------|
| **Policy-bound commands** | `spawn` under a `Space`; configure stdin/stdout/stderr (including MCP stdio pipes). |
| **Process-tree lifecycle** | Timeout / cancel kills the **process group** (Unix) so shell grandchildren are less likely to leak; collect exit code, duration, and termination reason. |
| **Policy-bound file I/O** | **`space.fs()` (preferred)** — read / write / create / delete / rename / metadata + audit. `check_fs` is advisory UI only. |
| **Baseline secret denies** | Every policy (unless opted out) denies `~/.ssh`, `~/.aws`, `**/.env`, `**/*.pem`, … even when `default_read` is true. |
| **Egress control** | Allowlists, local CONNECT proxy, and kernel ProxyOnly on children (DenyAll → seccomp block). |
| **Credentials** | JIT inject at spawn; redact exec args in audit logs when needed (`audit_args: false`). |
| **Worktree isolation** | Optional git worktree or directory under `~/.keel/worktrees/`. |
| **Task narrowing** | Child policies can only **shrink** parent reach — the model cannot expand its own rights. |
| **Optional host confine** | `Space::create_confined` applies Landlock/Seatbelt to **this process** (irreversible; Grok-style). Default keeps the host clean and sandboxes children only. |
| **Audit integrity** | Default hash chain (`prev_hash` / `event_hash`); SpaceFs can attach `content_sha256` digests. Verify with `verify_chain`. |

### Four pillars

| Pillar | Plain language |
|--------|----------------|
| **Policy** | Up front: what may be read, written, executed, dialed, and which credentials exist (plus TTL). |
| **Enforce** | At runtime: soft checks and/or kernel sandboxes (Landlock / Seatbelt) map policy to boundaries. |
| **Record** | Ground truth: events tagged with `space_id` / `policy_id` (optional `events.jsonl` under `~/.keel`). |
| **Lifecycle** | A **Space**: create → use → destroy. |

### What Keel is *not*

- Not a chat UI or planning framework (not a replacement for Grok / Codex / your agent host).
- Not a full desktop app.
- Soft checks alone are **not** VM-grade isolation — use kernel backends when you need stronger FS/net enforcement. `SpaceFs` is a **soft** host-side API (TOCTOU still exists); hosts should keep `O_NOFOLLOW` and path re-checks where they already have them.

## Status

**v0.0.13** on [crates.io](https://crates.io) as **`eero-keel-*`** (owner [EeroEternal](https://crates.io/users/EeroEternal)).

Baseline denies, SpaceFs-first, `create_confined`, process-group lifecycle, **hash-chain audit**, content digests, allowlist server-block seccomp.

See [CHANGELOG.md](CHANGELOG.md), [design](docs/design.md), and [host integration](docs/integration.md).

## Install

Requires **Rust 1.93+**.

### CLI

```bash
cargo install eero-keel-cli
keel info
```

### Library

```toml
[dependencies]
eero-keel-core = "0.0.13"
```

Rust imports use short crate names (`keel_core`, `keel_policy`, …), not the crates.io package prefix:

```rust
use keel_core::{
    profile_workspace, ProcessGuardBackend, Space, SpawnRequest, StdioMode,
};
```

### crates.io package names

| crates.io package | Rust lib / binary | Role |
|-------------------|-------------------|------|
| [`eero-keel-policy`](https://crates.io/crates/eero-keel-policy) | `keel_policy` | Policy, presets, IDs, serde |
| [`eero-keel-record`](https://crates.io/crates/eero-keel-record) | `keel_record` | Events + sinks (memory, JSONL) |
| [`eero-keel-enforce`](https://crates.io/crates/eero-keel-enforce) | `keel_enforce` | Backends (null, process-guard, kernel, worktree) |
| [`eero-keel-core`](https://crates.io/crates/eero-keel-core) | `keel_core` | `Space` orchestration |
| [`eero-keel-cli`](https://crates.io/crates/eero-keel-cli) | binary `keel` | CLI |

Notes:

- Plain names `keel` / `keel-core` / `keel-cli` / `keel-enforce` are taken by unrelated crates.
- Historical `keel-exec-*` is **not** maintained from this repo.
- Source directories remain `crates/keel-*`; use package names with `cargo -p eero-keel-cli`.

## Quick start

### From source

```bash
cargo build -p eero-keel-cli --release
./target/release/keel info

cargo run -p eero-keel-cli -- policy --profile workspace
cargo run -p eero-keel-cli -- check --profile workspace --write ./README.md
cargo run -p eero-keel-cli -- run --profile workspace -- echo hello
```

### Library sketch

```rust
use std::sync::Arc;
use std::time::Duration;
use keel_core::{
    profile_workspace, MemorySink, ProcessGuardBackend, Space, SpaceOptions, SpawnRequest,
};

# async fn demo() -> anyhow::Result<()> {
let policy = profile_workspace(std::env::current_dir()?.as_path())?;
let sink = Arc::new(MemorySink::new());
let backend = Arc::new(ProcessGuardBackend::new());
let space = Space::create_with_sink(
    policy,
    backend,
    SpaceOptions {
        persist_events: false,
        memory_events: true,
        ..Default::default()
    },
    Some(sink),
)
.await?;

// Files under policy (prefer SpaceFs over raw std::fs + check_fs alone):
// space.fs().write("foo/bar.txt", b"ok").await?;

let exit = space
    .spawn(SpawnRequest::new("echo").args(["keel"]))
    .await?
    .wait_timeout(Duration::from_secs(5))
    .await?;
assert!(exit.success());

// Timeout + collect stdout/stderr:
// .wait_with_output_timeout(Duration::from_secs(30)).await?;

// MCP-style stdio:
// SpawnRequest::new("server").stdin(StdioMode::Piped).stdout(StdioMode::Piped)

space.destroy().await?;
# Ok(())
# }
```

Typical host flow:

```text
open Space (bind policy)
  → space.fs() for file tools  /  space.spawn() for commands
  → wait with timeout or CancellationToken
  → destroy  →  keep audit log if needed
```

## Backends

| Backend | Isolation | Status |
|---------|-----------|--------|
| `null` | Record only; accept policy | done |
| `process-guard` | Soft FS / exec checks | done |
| `local-process` | Landlock (Linux) / Seatbelt (macOS) via nono; children sandboxed by default | done |
| `local-worktree` | Git worktree or directory under `~/.keel/worktrees/` | done |
| `remote-microvm` | Guest microVM | future — [docs](docs/future-remote-microvm.md) |

```bash
# Kernel FS on children; events under ~/.keel/spaces/
cargo run -p eero-keel-cli -- run --backend local-process --profile workspace -- echo hello

# Egress allowlist (CONNECT proxy + ProxyOnly where supported)
cargo run -p eero-keel-cli -- check-egress evil.com --allow-host api.x.ai:443
cargo run -p eero-keel-cli -- run --backend local-process --allow-host example.com:80 -- \
  curl -sI http://example.com/

# Worktree + credential injection
cargo run -p eero-keel-cli -- run --worktree --cred API_TOKEN=env:MY_TOKEN -- echo ok
```

On Linux, true read-deny for nested paths often needs **bubblewrap** (`bwrap` on `PATH` or `KEEL_BWRAP`).

## Policy profiles

| Profile | Read | Write | Network (policy intent) |
|---------|------|-------|-------------------------|
| `workspace` | world (default) | workspace + `~/.keel` + temps | unrestricted |
| `read-only` | world | `~/.keel` + temps | deny-all |
| `strict` | system + workspace | workspace + `~/.keel` + temps | deny-all |

Custom profiles: builder API, JSON/TOML, or `sandbox.toml` (`~/.keel/sandbox.toml` and project `.keel/sandbox.toml`).

## Links

- Repository: [github.com/EeroEternal/keel](https://github.com/EeroEternal/keel)
- [Design](docs/design.md) · [Integration](docs/integration.md) · [Testing](docs/testing.md) · [Changelog](CHANGELOG.md)

## License

Apache-2.0
