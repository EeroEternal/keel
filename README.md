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

**v0.0.8** — published on [crates.io](https://crates.io) under the **`keel-exec-*`** package names (see below).  
`sandbox.toml` profiles, composition (`--worktree --sandbox`), deny globs, egress allowlist, worktree, credentials.  
See [CHANGELOG.md](CHANGELOG.md) and [optimization plan](docs/optimization-plan.md).

## Install

### CLI binary

```bash
cargo install keel-exec-cli
keel info
```

Requires **Rust 1.93+**.

### Library (Cargo.toml)

```toml
[dependencies]
keel-exec-core = "0.0.8"
# optional direct deps:
# keel-exec-policy = "0.0.8"
# keel-exec-enforce = "0.0.8"
# keel-exec-record = "0.0.8"
```

Rust imports keep the short crate names (`keel_core`, `keel_policy`, …):

```rust
use keel_core::{profile_workspace, MemorySink, ProcessGuardBackend, Space, SpawnRequest};
```

### crates.io naming

The plain names `keel`, `keel-core`, `keel-cli`, and `keel-enforce` are **already taken** by unrelated projects on crates.io. This repository therefore publishes as:

| crates.io package | Rust lib / binary | Role |
|-------------------|-------------------|------|
| [`keel-exec-policy`](https://crates.io/crates/keel-exec-policy) | `keel_policy` | Policy, presets, IDs, serde |
| [`keel-exec-record`](https://crates.io/crates/keel-exec-record) | `keel_record` | Events + sinks (memory, JSONL) |
| [`keel-exec-enforce`](https://crates.io/crates/keel-exec-enforce) | `keel_enforce` | `EnforceBackend` + null / process-guard / kernel |
| [`keel-exec-core`](https://crates.io/crates/keel-exec-core) | `keel_core` | `Space` lifecycle orchestration |
| [`keel-exec-cli`](https://crates.io/crates/keel-exec-cli) | binary `keel` | CLI |

Repo paths remain `crates/keel-*` for local development.

## Quick start (from source)

```bash
# Requires Rust 1.93+
cargo build -p keel-exec-cli --release
./target/release/keel info

# Print a workspace policy as JSON
cargo run -p keel-exec-cli -- policy --profile workspace

# Soft-check a path
cargo run -p keel-exec-cli -- check --profile workspace --write ./README.md

# Run a command inside a temporary space
cargo run -p keel-exec-cli -- run --profile workspace -- echo hello
cargo run -p keel-exec-cli -- run --trace --profile read-only -- /bin/ls /
```

### Library example

```rust
use std::sync::Arc;
use keel_core::{
    profile_workspace, MemorySink, ProcessGuardBackend, Space, SpawnRequest,
};

# async fn demo() -> anyhow::Result<()> {
let policy = profile_workspace(std::env::current_dir()?.as_path())?;
let sink = Arc::new(MemorySink::new());
let backend = Arc::new(ProcessGuardBackend::new());
let space = Space::create(policy, backend, sink).await?;

assert!(space.check_fs(std::path::Path::new("README.md"), true).await?);
let mut child = space
    .spawn(SpawnRequest::new("echo").args(["keel"]))
    .await?;
let _status = child.child.wait().await?;
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
cargo run -p keel-exec-cli -- run --backend local-process --profile workspace -- echo hello

# Egress allowlist: only listed hosts (via local CONNECT proxy + ProxyOnly)
cargo run -p keel-exec-cli -- check-egress evil.com --allow-host api.x.ai:443
cargo run -p keel-exec-cli -- run --backend local-process --allow-host example.com:80 -- \
  curl -sI http://example.com/

# Worktree isolation + credential injection
cargo run -p keel-exec-cli -- run --worktree --cred API_TOKEN=env:MY_TOKEN -- echo ok

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
