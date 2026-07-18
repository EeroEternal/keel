# Future direction: `remote-microvm` backend

**Status:** design only — **not scheduled for near-term implementation.**  
**Audience:** maintainers deciding whether / when to invest in stronger isolation than process sandboxes.

This note records the intended meaning of the `remote-microvm` backend name, how it would fit Keel’s architecture, and what problems it solves that current backends deliberately do not. No code is required until product demand justifies it.

---

## One-line summary

Run agent-spawned work inside a **micro-virtual machine** (often **remote** or otherwise off the agent host process), so Policy / Record stay in Keel while **Enforce** uses a **guest kernel** boundary instead of Landlock / Seatbelt on the host.

---

## Motivation

| Current backends | Strength | Weakness |
|------------------|----------|----------|
| `process-guard` | Portable soft checks | Not a security boundary |
| `local-process` | Host kernel FS (Landlock / Seatbelt) + child net tricks | Same host kernel; rule gaps (e.g. Linux subpath deny needs bwrap) |
| `local-worktree` | File isolation for parallel tasks | Still same machine / user |

Process-level sandboxes are the right default for a **laptop coding agent**: low latency, native cwd, IDE-friendly.

They are **not** enough when:

- Workload is **untrusted** (arbitrary model output, third-party plugins, multi-tenant SaaS).
- You need a **hardware virtualization** boundary (independent guest kernel).
- You want **disposable, poolable** execution environments in the cloud.
- Compliance / audit requires “this ran in an attested sandbox VM,” not “this process had Landlock.”

That is the niche for `remote-microvm`.

---

## What “microvm” and “remote” mean here

### MicroVM

A lightweight VM designed for fast boot and dense packing, e.g.:

- [Firecracker](https://firecracker-microvm.github.io/)
- Cloud Hypervisor / other microvm profiles

Compared with a full desktop VM: smaller attack surface, second-scale (or sub-second) start, typically one workload per guest.

### Remote

Execution is **not** applied by restricting the agent host PID. Instead:

1. Keel (or a control plane) allocates a guest.
2. Workspace is **mounted, synced, or snapshotted** into the guest.
3. Commands run **inside** the guest under guest policy (disk, NIC, cgroup).
4. Stdout, artifacts, and audit records stream back to the host space.

“Remote” may mean a cloud pool, an on-prem worker, or even a local hypervisor; the important property is **separate machine abstraction**, not geography.

---

## Fit in Keel’s model

Keel’s unit of isolation remains a **Space**: one Policy, one Enforce backend, one Record stream.

```text
┌─────────────────────────────┐
│  Agent host (TUI / ACP)     │  unsandboxed or lightly restricted
└──────────────┬──────────────┘
               │ Space::spawn(policy, cmd)
┌──────────────▼──────────────┐
│  Keel control plane         │  Policy · lifecycle · Record
└──────────────┬──────────────┘
               │ allocate / RPC
┌──────────────▼──────────────┐
│  MicroVM guest              │  Enforce backend = remote-microvm
│  - workspace snapshot       │
│  - egress allowlist on NIC  │
│  - ephemeral disk           │
└─────────────────────────────┘
```

**Stable contracts (already exist today):**

- `Policy` (FS, network, exec, credentials, TTL, task_id)
- `EnforceBackend` trait (`apply` / `spawn` / `check_fs` / `destroy`)
- `RecordEvent` stream (`space_id`, `policy_id`, …)

**New pieces (future):**

| Piece | Role |
|-------|------|
| Guest image / rootfs | Minimal OS + tooling for coding agents |
| Provisioner | Create/destroy Firecracker (or similar) instances |
| Workspace bridge | Sync or block-mount host tree ↔ guest path |
| Control channel | Authenticated RPC for spawn, stream, cancel |
| Guest agent | Small process inside VM that applies policy and runs commands |
| Attestation hooks (optional) | Prove which image / policy was used |

Host-side `LocalProcessBackend` stays the default for interactive coding. `remote-microvm` would be an **opt-in** backend for high-risk or multi-tenant modes.

---

## How it would map Policy → guest

Illustrative only:

| Policy field | Guest enforcement idea |
|--------------|------------------------|
| `workspace` + FS rules | Bind/snapshot only allowed trees; read-only mounts for system paths |
| `deny` paths | Simply omit from the guest mount (stronger than Landlock subpath tricks) |
| `NetworkPolicy::DenyAll` | Guest NIC down or default-deny firewall |
| `NetworkPolicy::Allowlist` | Guest egress gateway / security group = allowlist (no host CONNECT proxy required) |
| `credentials` | Inject into guest via sealed channel; revoke by destroying the guest |
| `expires_at` | Hard kill / reclaim the VM |

Record should still emit host-visible events (`exec`, `net_dial`, `space_destroyed`, …), preferably with a `backend: "remote-microvm"` note and guest identifiers.

---

## Non-goals (for this future track)

- Replacing laptop-local backends for day-to-day `keel run`
- Requiring every user to run a hypervisor
- Claiming microVM isolation before a real provisioner exists
- Building a full multi-tenant cloud product inside this repo on day one

---

## When to pick this up

Consider implementing only when several of these are true:

1. Product needs isolation **stronger than same-kernel Landlock/Seatbelt**.
2. There is a clear **runtime** (Firecracker pool, managed sandbox API, etc.).
3. Workspace sync cost is acceptable for the target UX (batch / CI / remote agent, not every keystroke).
4. Maintainers can own **image builds, networking, and lifecycle** ops.

Until then: keep this document as the north star; extend `EnforceBackend` carefully so a future `RemoteMicrovmBackend` can plug in without rewriting Policy/Record.

---

## Suggested phased approach (if resumed)

| Phase | Deliverable |
|-------|-------------|
| A | Trait + config surface only (`backend = "remote-microvm"`, feature flag, no hypervisor) |
| B | Local Firecracker smoke (one VM, one command, manual rootfs) |
| C | Workspace sync + event streaming |
| D | Pool, reuse, TTL reclaim, allowlist NIC |
| E | Production hardening (auth, resource limits, attestation) |

---

## Related reading

- Keel overall design: [`design.md`](./design.md)
- Process sandboxes in production coding agents (e.g. Landlock / Seatbelt patterns in Grok Build) — same Policy ideas, weaker Enforce
- Industry framing of an “execution layer under agents” (e.g. product narratives around dedicated agent runtimes / microVMs) — problem statement only; Keel remains independent

---

## Decision log

| Date | Decision |
|------|----------|
| 2026-07-18 | Document only; **do not implement** remote-microvm in the near term. Prefer polish of local backends, worktree, egress, credentials, and agent integration. |
