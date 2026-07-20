# Optimization review (Fable) — status as of v0.0.15

This document records external optimization suggestions (from **Fable**), Keel’s
acceptance judgment, and delivery status. All prose is English per [AGENTS.md](../AGENTS.md).

**Related:** [optimization-plan.md](./optimization-plan.md), [design.md](./design.md),
[integration.md](./integration.md), [CHANGELOG.md](../CHANGELOG.md).

**Baseline release:** **v0.0.15** (`eero-keel-*` on crates.io, owner EeroEternal).

---

## Threat model layers (shared vocabulary)

| Level | Meaning | Default? |
|-------|---------|----------|
| **L0** | Soft policy + cooperative `SpaceFs` | Host tools must opt in |
| **L1** | Child OS isolation (`isolate_apply` default) | **Yes** — host stays clean |
| **L2** | Whole-process confine (`Space::create_confined`) | Optional (Grok-style) |
| **L3** | Stronger multi-tenant (netns / microVM) | Future / partial |

Do **not** silently make L2 the only mode: Keel is a library embeddable in long-lived agents.

---

## Suggestion tracker

| # | Suggestion | Judgment | Status | Version |
|---|------------|----------|--------|---------|
| 1 | `Space::confine_self` / host Landlock–Seatbelt | Accept as **optional L2**, keep L1 default | **Done** (`create_confined`, `LocalProcessOptions::confine_host`) | 0.0.12 |
| 2 | Prefer `SpaceFs`; mark `check_fs` advisory only | Accept; still soft on unconfined host | **Done** (API docs + `check_fs_advisory`) | 0.0.12 |
| 3 | Always-deny credential paths + secret globs | Accept (P0 policy) | **Done** (`baseline_deny_rules`, opt-out `without_baseline_denies`) | 0.0.12 |
| 4 | Auto-enable bwrap when denies present; fail closed | Accept with conditions | **Done** (`auto_bwrap` + `require_kernel`) | 0.0.12 |
| 5 | Force egress beyond proxy env (seccomp / ProxyOnly) | Accept subset; sockaddr allowlist later | **Partial** — DenyAll seccomp; allowlist ProxyOnly + server-block | 0.0.12–0.0.13 |
| 6 | Linux netns for allowlist | Accept as L3, not default | **Deferred** | — |
| 7 | Windows Job Objects | Accept | **Done** | 0.0.14 |
| 8 | Windows AppContainer + path grants | Accept | **Done** (profile + `icacls` + CreateProcess; minimal capabilities) | 0.0.15 |
| 9 | Audit hash chain + content digests | Accept as integrity-assisted audit | **Done** (`HashChainSink`, `content_sha256`, `verify_chain`) | 0.0.13 |
| 10 | Lower MSRV below 1.93 | Rejected by project owner | **Won’t do** — keep `rust-version = "1.93"` | — |
| 11 | Cold-start benchmark / warm pool | Reasonable engineering | **Deferred** | — |
| 12 | Path fuzz + Landlock multi-kernel CI | Reasonable engineering | **Deferred** (unit edge tests exist) | — |

---

## Delivered detail (this program of work)

### Policy (0.0.12)

- Every `PolicyBuilder::build()` merges baseline denials unless `without_baseline_denies()`.
- Paths: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.kube`, … plus system secret files.
- Globs: `**/.env`, `**/*.pem`, `**/id_rsa`, …

### Host API (0.0.12+)

- **Preferred FS:** `space.fs()` for Read/Write/Edit.
- **Advisory only:** `check_fs` / `check_fs_advisory` (UI / preflight; TOCTOU if paired with raw `std::fs`).
- **L2:** `Space::create_confined(policy, opts)`.

### Record (0.0.13)

- Default `SpaceOptions.integrity_chain = true`.
- Events: `prev_hash`, `event_hash`; optional `FsAccess.content_sha256`.
- Verify: `verify_chain`, `verify_jsonl`.

### Windows (0.0.14–0.0.15)

| Feature | Behavior |
|---------|----------|
| Job Object | `KILL_ON_JOB_CLOSE`; cancel/timeout/Drop terminate the job tree |
| Restricted token | API probe for future `CreateProcessAsUser` |
| AppContainer | Per-policy profile; `icacls` grants on workspace / RW roots; spawn with `SECURITY_CAPABILITIES` |
| Fallback | If AppContainer fails and `require_kernel == false` → Job-only Tokio spawn |

**Honest limits:** AppContainer capability set is minimal (`internetClient` when network is not DenyAll). Not a full Landlock twin. Cross-compiled on macOS; **Windows runtime e2e still thin**.

### Unix network (0.0.12–0.0.13)

- **DenyAll:** child seccomp blocks connect/bind/listen/…  
- **Allowlist:** CONNECT proxy + kernel ProxyOnly + Linux server-block seccomp (bind/listen/accept denied; `connect` kept for proxy clients).  
- **Not done:** connect allowlist by sockaddr; dedicated netns.

---

## Explicit non-goals for this freeze

- Lowering MSRV below 1.93.  
- Replacing L1 default with L2 host confine.  
- Claiming Firecracker / full multi-tenant isolation without remote-microvm.  
- Building a full coding agent (tools UI, ACP session, etc.).

---

## Recommended next backlog (not scheduled)

1. **Windows runtime e2e** (Job + AppContainer on real Windows CI).  
2. **Linux:** sockaddr-aware allowlist seccomp and/or optional netns.  
3. **AppContainer stdio** parity with Tokio `Child` (`ManagedProcess::child_mut` is `Option` for native spawns).  
4. **Warm pool** / create latency benchmarks.  
5. **Fuzz** path resolve + multi-kernel Landlock matrix.

---

## Release map

| Version | Theme |
|---------|--------|
| 0.0.12 | Baseline denies, SpaceFs-first, `create_confined`, bwrap fail-closed |
| 0.0.13 | Hash chain, content digests, allowlist server-block, path tests |
| 0.0.14 | Windows Job Objects |
| 0.0.15 | Windows AppContainer + path grants + native spawn |

**Freeze point for this review:** ship and document at **v0.0.15**; further work tracks the backlog above.
