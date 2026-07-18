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

**v0.0.3** — **egress allowlist** (CONNECT proxy + kernel ProxyOnly), plus isolated child apply, Linux bwrap read-deny, and `~/.keel/spaces/<id>/events.jsonl`.

## Quick start

```bash
# Requires Rust 1.93+
cargo build -p keel-cli --release
./target/release/keel info

# Print a workspace policy as JSON
cargo run -p keel-cli -- policy --profile workspace

# Soft-check a path
cargo run -p keel-cli -- check --profile workspace --write ./README.md

# Run a command inside a temporary space
cargo run -p keel-cli -- run --profile workspace -- echo hello
cargo run -p keel-cli -- run --trace --profile read-only -- /bin/ls /
```

### Library

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

## Workspace layout

| Crate | Role |
|-------|------|
| `keel-policy` | Policy, presets, IDs, serde |
| `keel-record` | Events + sinks (memory, JSONL) |
| `keel-enforce` | `EnforceBackend` + null / process-guard |
| `keel-core` | `Space` lifecycle orchestration |
| `keel-cli` | `keel` binary |

Design notes: [`docs/design.md`](docs/design.md).

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
| `local-worktree` | Git worktree / overlay | planned |
| `remote-microvm` | Strong isolation | planned |

```bash
# Kernel FS on children only (host stays clean); events under ~/.keel/spaces/
cargo run -p keel-cli -- run --backend local-process --profile workspace -- echo hello

# Egress allowlist: only listed hosts (via local CONNECT proxy + ProxyOnly)
cargo run -p keel-cli -- check-egress evil.com --allow-host api.x.ai:443
cargo run -p keel-cli -- run --backend local-process --allow-host example.com:80 -- \
  curl -sI -x "$HTTP_PROXY" http://example.com/   # proxy env injected automatically

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

## License

Apache-2.0
