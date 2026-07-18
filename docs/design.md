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
| `local-process` | Landlock / Seatbelt via **nono** | seccomp on spawn (Linux); parent net kept | **done (v0)** |
| `local-worktree` | git worktree or `~/.keel/worktrees/` dir | inherits inner backend | **done** |
| `remote-microvm` | guest FS (Firecracker-class) | guest NIC / gateway | **future** — see [`future-remote-microvm.md`](./future-remote-microvm.md) |

### `local-process` notes

- **Default `isolate_apply = true`**: host stays unsandboxed; each `spawn` applies Landlock/Seatbelt in the **child** (`pre_exec` after fork).
- **Legacy** `isolate_apply = false`: sandboxes the host process (irreversible, one policy per process).
- Parent network stays open; `NetworkPolicy::DenyAll` → Linux child **seccomp** (macOS: no child-net filter yet).
- **Linux read-deny**: **bubblewrap** bind-over of mode-000 placeholders (Landlock cannot deny subpaths). Requires `bwrap` on `PATH` or `KEEL_BWRAP`.
- **macOS deny**: Seatbelt platform rules (including write sub-actions and `/private` aliases).
- Optional host-apply smoke: `KEEL_KERNEL_TEST=1` with `isolate_apply = false`.
- Dependency: `nono = 0.53.0` (rustc 1.93-compatible).

### Egress allowlist

`NetworkPolicy::Allowlist` is enforced as:

1. **Policy check** — `check_egress(host, port)` (wildcards, port rules; always deny link-local / cloud metadata).
2. **Localhost CONNECT proxy** — parent starts `EgressProxy`; children get `HTTP(S)_PROXY` / `ALL_PROXY`.
3. **Kernel ProxyOnly** — sandboxed children may only dial `localhost:<proxy_port>` (Seatbelt / Landlock+seccomp), so direct egress bypass is blocked where the platform supports it.

Tools that ignore proxy env still cannot dial arbitrary hosts when ProxyOnly is applied. Always-denied: `169.254.0.0/16`, `metadata.google.internal`, etc.

CLI:

```bash
keel check-egress api.x.ai --port 443 --allow-host api.x.ai:443
keel run --backend local-process --allow-host api.x.ai:443 -- curl -I https://api.x.ai
```

### Event persistence

Default space layout:

```text
~/.keel/spaces/<space_id>/
  events.jsonl
  policy.json
```

Override root with `$KEEL_HOME`. CLI: `--no-persist` to skip disk logs.

Portable soft backends remain the default for casual CLI demos; use `--backend local-process` for kernel FS.

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

1. **v0** — types, soft backends, CLI, design
2. **v0.1** — `local-process` Landlock/Seatbelt (nono); child seccomp on Linux
3. **v0.2** — isolate_apply children; Linux bwrap read-deny; `~/.keel/spaces/<id>/events.jsonl`
4. **v0.3** — egress allowlist (CONNECT proxy + ProxyOnly kernel mode)
5. **v0.4** — worktree backend; per-task `open_task` / `narrow_policy`; JIT credentials
6. **v0.5+** — model-call Consume hooks; agent SDK / ACP adapters; polish local backends
7. **Future (not near-term)** — `remote-microvm` (documented only: [`future-remote-microvm.md`](./future-remote-microvm.md))

### Worktree

`WorktreeBackend` creates an isolated tree on `apply`:

1. Prefer `git worktree add -b keel/<id> <path> HEAD` when the policy workspace is a git repo.
2. Else create `~/.keel/worktrees/<id>/` with a `.keel-worktree-origin` pointer.
3. Spawns default `cwd` into the worktree; soft FS checks remap origin-relative paths.
4. `destroy` removes the worktree (and deletes the temp branch when git-based).

### Credentials (JIT)

`CredentialGrant { name, source, inject_as_env }`:

- `source`: `env:VAR`, bare `VAR`, or `file:PATH`
- Resolved at **spawn** (not stored in events); injected into child env
- `CredentialIssued` / `CredentialRevoked` events record names only
- CLI: `--cred NAME=env:VAR`

### Per-task rebind

`narrow_policy(parent, TaskSpec)` + `SpaceHandle::open_task`:

- Always creates a **new** space/policy id (parent unchanged)
- Child may only shrink network, drop credentials, add denies, shorten TTL
- Expanding reach returns `PolicyError::Invalid`

## Non-goals

- Replacing agent frameworks or model providers
- Shipping a chat UI
- Claiming microVM isolation before a real backend exists

## Relationship to Grok Build

Grok’s sandbox + permission pipeline is a **product-embedded** instance of the same ideas. Keel extracts the execution-layer contract so any agent can bind a task to a Space without forking Grok. Kernel techniques (Landlock/Seatbelt) may be reused or re-implemented behind `EnforceBackend`; the public API stays Keel’s.
