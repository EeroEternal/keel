# Keel Design

## Thesis

Agents decide at runtime. Traditional perimeters (gateways, WAFs) assume software paths are fixed when written. A production agent needs an **execution layer under it**: policy bound before work starts, enforcement when side effects become real, and a record of what actually happened.

Keel is that layer. Agent frameworks (Grok, Codex, custom ACP hosts) stay free to plan and call tools; Keel governs reach.

## Pillars

```text
Policy  →  what this task may reach (FS, net, exec, creds, TTL)
Enforce →  make violations fail at the boundary (soft → kernel → VM)
Record  →  ground-truth events tagged with space_id + policy_id
Lifecycle → create / use / revoke / destroy
```

The unit of isolation is a **Space**: one policy, one backend, one record stream.

## Trust model

| Trusted | Untrusted |
|---------|-----------|
| Policy author / orchestrator | Model output, tool arguments, untrusted tool results |
| Keel control plane | Agent’s self-description of “what I need” |
| Enforce backend | Guest code / shell spawned inside the space |

The agent **cannot expand** its own policy. At most it can operate within the reach already granted for this task.

## API surface (v0)

```rust
let policy = profile_workspace(cwd)?;
let sink = Arc::new(MemorySink::new());
let backend = Arc::new(ProcessGuardBackend::new());
let space = Space::create(policy, backend, sink).await?;

space.check_fs(path, write).await?;
space.spawn(SpawnRequest::new("rg").args(["TODO", "."])).await?;
space.destroy().await?;
```

CLI:

```bash
keel info
keel policy --profile workspace
keel check --profile workspace --write /tmp/proj/a.rs
keel run --profile read-only -- echo hello
```

## Backends

| Name | FS | Child net | Status |
|------|----|-----------|--------|
| `null` | soft checks only | no | **done** |
| `process-guard` | soft prefix/deny rules | advisory | **done** |
| `local-process` | Landlock / Seatbelt via a sandbox stack | seccomp (Linux) | planned |
| `local-worktree` | git worktree / overlay cwd | inherits | planned |
| `remote-microvm` | guest FS | guest net policy | planned |

v0 ships portable soft enforcement so the Policy/Record/Lifecycle loop is usable on every host. Kernel backends are additive and must remain **fail-closed** when a profile requires hard isolation they cannot provide.

## Policy presets

Inspired by common coding-agent sandboxes (e.g. Grok Build):

| Profile | default_read | write | network |
|---------|--------------|-------|---------|
| `workspace` | yes | workspace + `~/.keel` + temps | unrestricted |
| `read-only` | yes | `~/.keel` + temps | deny-all |
| `strict` | no (system + workspace) | workspace + `~/.keel` + temps | deny-all |

Custom policies: builder API + JSON/TOML serde.

## Record events

Every event carries `space_id`, `policy_id`, optional `task_id`, timestamp.

Kinds (v0): `space_created`, `space_destroyed`, `policy_bound`, `fs_access`, `net_dial`, `exec`, `credential_issued`, `credential_revoked`, `violation`, `note`.

Sinks: `MemorySink`, `JsonlSink`, `MultiSink`.

## Roadmap

1. **v0** — types, soft backends, CLI, design (this tree)
2. **v0.1** — `JsonlSink` default path under `~/.keel/spaces/<id>/`, credential inject/revoke stubs
3. **v0.2** — Linux Landlock + optional bwrap re-exec; macOS Seatbelt path
4. **v0.3** — worktree backend; per-task policy rebind (new space, not in-place expand)
5. **v0.4** — egress allowlist enforcement; model-call Consume hooks
6. **v1** — stable SDK + ACP/session adapters for coding agents

## Non-goals

- Replacing agent frameworks or model providers
- Shipping a chat UI
- Claiming microVM isolation before a real backend exists

## Relationship to Grok Build

Grok’s sandbox + permission pipeline is a **product-embedded** instance of the same ideas. Keel extracts the execution-layer contract so any agent can bind a task to a Space without forking Grok. Kernel techniques (Landlock/Seatbelt) may be reused or re-implemented behind `EnforceBackend`; the public API stays Keel’s.
