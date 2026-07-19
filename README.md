# Keel

**The execution layer under agents.**

Agents decide *what* to do at runtime. Keel governs *what is allowed to become real* — filesystem, network, credentials, and process execution — without trusting the agent’s own account of its intent.

```text
┌─────────────────────────────┐
│  Agent runtime              │  Grok · Codex · custom ACP hosts
│  (plans, tools, prompts)    │
└──────────────┬──────────────┘
               │ spawn(policy) / enforce / events
┌──────────────▼──────────────┐
│  Keel                       │  Policy · Enforce · Record · Lifecycle
│  Secure execution space     │
└─────────────────────────────┘
```

Named after a ship’s **keel**: the structural spine underneath. The agent rides on top; the keel keeps real access from tearing the host (or the user) apart.

## Status

**v0.0.10** — published on [crates.io](https://crates.io) as **`eero-keel-*`** (owner [EeroEternal](https://crates.io/users/EeroEternal)).  
Stdio modes + process-group lifecycle + `SpaceFs` + `audit_args` (host/MCP integration).  
See [CHANGELOG.md](CHANGELOG.md) and [integration guide](docs/integration.md).

## Install

### CLI binary

```bash
cargo install eero-keel-cli
keel info
```

Requires **Rust 1.93+**.

### Library (Cargo.toml)

```toml
[dependencies]
eero-keel-core = "0.0.10"
# optional direct deps:
# eero-keel-policy = "0.0.10"
# eero-keel-enforce = "0.0.10"
# eero-keel-record = "0.0.10"
```

Rust imports keep the short crate names (`keel_core`, `keel_policy`, …):

```rust
use keel_core::{
    profile_workspace, ProcessGuardBackend, Space, SpawnRequest, StdioMode,
};
```

### crates.io naming

- Plain `keel` / `keel-core` / `keel-cli` / `keel-enforce` are taken by unrelated projects.
- Historical `keel-exec-*` (0.0.8) was published under another crates.io account and is **not** used going forward.
- This repository publishes as **`eero-keel-*`** under **EeroEternal**:

| crates.io package | Rust lib / binary | Role |
|-------------------|-------------------|------|
| [`eero-keel-policy`](https://crates.io/crates/eero-keel-policy) | `keel_policy` | Policy, presets, IDs, serde |
| [`eero-keel-record`](https://crates.io/crates/eero-keel-record) | `keel_record` | Events + sinks (memory, JSONL) |
| [`eero-keel-enforce`](https://crates.io/crates/eero-keel-enforce) | `keel_enforce` | `EnforceBackend` + null / process-guard / kernel |
| [`eero-keel-core`](https://crates.io/crates/eero-keel-core) | `keel_core` | `Space` lifecycle orchestration |
| [`eero-keel-cli`](https://crates.io/crates/eero-keel-cli) | binary `keel` | CLI |

Repo paths remain `crates/keel-*` for local development.

## Quick start (from source)

```bash
# Requires Rust 1.93+
cargo build -p eero-keel-cli --release
./target/release/keel info

# Print a workspace policy as JSON
cargo run -p eero-keel-cli -- policy --profile workspace

# Soft-check a path
cargo run -p eero-keel-cli -- check --profile workspace --write ./README.md

# Run a command inside a temporary space
cargo run -p eero-keel-cli -- run --profile workspace -- echo hello
cargo run -p eero-keel-cli -- run --trace --profile read-only -- /bin/ls /
```

### Library example

```rust
use std::sync::Arc;
use std::time::Duration;
use keel_core::{
    profile_workspace, MemorySink, ProcessGuardBackend, Space, SpaceOptions, SpawnRequest,
    StdioMode,
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

// Tool FS under policy (not just a soft check):
// space.fs().write("out.txt", b"ok").await?;

let exit = space
    .spawn(SpawnRequest::new("echo").args(["keel"]))
    .await?
    .wait_timeout(Duration::from_secs(5))
    .await?;
assert!(exit.success());

// MCP-style stdio:
// SpawnRequest::new("server").stdin(StdioMode::Piped).stdout(StdioMode::Piped)

space.destroy().await?;
# Ok(())
# }
```

Design notes: [`docs/design.md`](docs/design.md). Host integration: [`docs/integration.md`](docs/integration.md).

## Pillars

| Pillar | Role |
|--------|------|
| **Policy** | Task/session reach: FS, net, exec, credentials, TTL. Model cannot expand policy. |
| **Enforce** | Backends map policy to soft checks today; kernel/VM backends next. |
| **Record** | What actually happened, bound to `space_id` / `policy_id`. |
| **Lifecycle** | Create → use → revoke → destroy. |

## Backends

| Backend | Isolation | Status |
|---------|-----------|--------|
| `null` | Record + accept policy | done |
| `process-guard` | Soft FS/exec checks | done |
| `local-process` | Landlock (Linux) / Seatbelt (macOS) via nono | done |
| `local-worktree` | Git worktree or directory under `~/.keel/worktrees/` | done |
| `remote-microvm` | Guest microVM (stronger isolation) | future — [docs](docs/future-remote-microvm.md) |

```bash
# Kernel FS on children only (host stays clean); events under ~/.keel/spaces/
cargo run -p eero-keel-cli -- run --backend local-process --profile workspace -- echo hello

# Egress allowlist: only listed hosts (via local CONNECT proxy + ProxyOnly)
cargo run -p eero-keel-cli -- check-egress evil.com --allow-host api.x.ai:443
cargo run -p eero-keel-cli -- run --backend local-process --allow-host example.com:80 -- \
  curl -sI http://example.com/

# Worktree isolation + credential injection
cargo run -p eero-keel-cli -- run --worktree --cred API_TOKEN=env:MY_TOKEN -- echo ok

# Linux: FS deny paths need bubblewrap for true read-deny
```

## Profiles

| Profile | Read | Write | Network (policy intent) |
|---------|------|-------|-------------------------|
| `workspace` | world (default) | workspace + `~/.keel` + temps | unrestricted |
| `read-only` | world | `~/.keel` + temps | deny-all |
| `strict` | system + workspace | workspace + `~/.keel` + temps | deny-all |

## Non-goals (v0)

- Replacing agent frameworks or model providers  
- Chat UI  
- Claiming Firecracker-level isolation before a real backend exists  

## Links

- Repository: [github.com/EeroEternal/keel](https://github.com/EeroEternal/keel)
- Docs: [design](docs/design.md) · [integration](docs/integration.md) · [testing](docs/testing.md) · [changelog](CHANGELOG.md)

## License

Apache-2.0
