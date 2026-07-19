# Keel optimization plan

**Goal:** Close the gap with Grok Build’s **execution-boundary** capabilities (sandbox / reach / audit), without turning Keel into a full coding agent.

**Non-goals:** ACP session runtime, tool implementations (read/edit/bash UX), permission TUI, hooks engine, remote-microvm (see [`future-remote-microvm.md`](./future-remote-microvm.md)).

**Related:** [`design.md`](./design.md), [CHANGELOG.md](../CHANGELOG.md).

---

## Current baseline (v0.0.13)

| Area | Status |
|------|--------|
| Policy + presets + **baseline always-deny** | Done |
| `process-guard` / `local-process` / `local-worktree` | Done |
| Isolate child apply (default) + **`create_confined`** | Done |
| Linux bwrap read-deny (auto when denies present) | Done |
| Egress allowlist + CONNECT proxy + ProxyOnly | Done (seccomp loopback-only still open) |
| JIT credentials (env/file) | Done |
| Per-task `narrow_policy` / `open_task` | Done |
| Space event JSONL | Done |
| **SpaceFs preferred**; `check_fs` advisory | Done (docs + API) |
| Deny **glob** soft + kernel map | Partial → improved with baseline globs |
| Worktree **+** kernel composed | Done (API + CLI `--sandbox`) |
| Real kernel e2e | Thin |
| `sandbox.toml` | Done |
| Host integration guide | Done |
| Hash-chain audit / Windows Job / netns | Not started |

---

## Principles

1. **Fail closed** when the user asked for hard isolation and the platform cannot provide it.
2. **Host stays clean** by default (`isolate_apply`); never require host Landlock for normal library use.
3. **Child policy may only shrink** parent reach (`narrow_policy`).
4. **English** for all committed content ([AGENTS.md](../AGENTS.md)).
5. Ship in **small versions** (`0.0.x`) with CHANGELOG entries.

---

## Phases

### Phase 1 — Composition & defaults (P0)

**Outcome:** One command / one API path that matches Grok’s “isolated tree + kernel FS” stack.

| ID | Work item | Acceptance |
|----|-----------|------------|
| P1.1 | Factory `composed_backend(worktree, local_process)` | `WorktreeBackend::with_inner(LocalProcessBackend)` documented + unit test |
| P1.2 | CLI `--worktree` stacks local-process when `--backend local-process` or new `--sandbox` | `keel run --worktree --backend local-process` works |
| P1.3 | CLI convenience flag `--sandbox` = local-process (+ optional worktree) | Help text clear; default remains process-guard for demos |

**Exit:** Documented composition path; smoke test green on macOS (and Linux when available).

---

### Phase 2 — Deny glob completeness (P0)

**Outcome:** `FsRule { glob: true, access: Deny }` is enforced, not advisory-only.

| ID | Work item | Acceptance |
|----|-----------|------------|
| P2.1 | Shared glob dialect (document: gitignore-ish `**` / `*`) | Same patterns accepted on macOS & Linux or rejected with clear error |
| P2.2 | macOS: translate globs → Seatbelt `(regex …)` denials | Unit tests on rule emission; optional `KEEL_KERNEL_TEST=1` |
| P2.3 | Linux: expand globs at spawn (caps) + bwrap bind-over | Missing `bwrap` + non-empty deny glob → fail closed when `require_kernel` |
| P2.4 | Record note when globs expand to zero matches | Event or log; no silent “feel secure” |

**Exit:** Policy with `**/.env` deny blocks read of matching files under kernel/bwrap path.

---

### Phase 3 — Enforcement e2e & matrix (P0)

**Outcome:** Real OS checks, not only soft_fs unit tests.

| ID | Work item | Acceptance |
|----|-----------|------------|
| P3.1 | `tests/e2e_local_process.rs` gated by `KEEL_KERNEL_TEST=1` | Write outside workspace fails inside sandboxed child |
| P3.2 | Linux-only e2e for bwrap deny (if `bwrap` present) | Read of denied path fails |
| P3.3 | Egress e2e: proxy denies metadata / allows listed host | Uses local proxy + CONNECT |
| P3.4 | CI doc: which jobs run which gates | `docs/testing.md` short note |

**Exit:** Maintainers can run one env-gated suite and trust kernel paths.

---

### Phase 4 — Egress hardening (P1)

| ID | Work item | Acceptance |
|----|-----------|------------|
| P4.1 | Proxy lifecycle tied to space (start on apply, stop on destroy) | Already partial; add leak test |
| P4.2 | Document tool limitations (non-proxy-aware binaries) | README / design section |
| P4.3 | Optional `strict_child_net` for allowlist (ProxyOnly always on child) | Default on for local-process isolate |
| P4.4 | Improve plain-HTTP proxy path or explicitly unsupported | Tests or documented CONNECT-only |

---

### Phase 5 — Config surface (P1)

| ID | Work item | Acceptance |
|----|-----------|------------|
| P5.1 | `~/.keel/sandbox.toml` + project `.keel/sandbox.toml` | Load named profiles |
| P5.2 | `extends` + additive project profiles (no global name clobber) | Match Grok safety rule |
| P5.3 | CLI `--profile-file` / `--sandbox-profile NAME` | Resolves to `Policy` |

---

### Phase 6 — Credentials, TTL, audit polish (P1)

| ID | Work item | Acceptance |
|----|-----------|------------|
| P6.1 | Credential `strict` mode on space options | Missing source → fail spawn |
| P6.2 | Enforce `expires_at` on every spawn/check | Already partial; unify |
| P6.3 | Auto `Violation` events on soft deny paths | When check_fs/egress returns false |
| P6.4 | Redaction helpers for logs | No secret substrings in notes |

---

### Phase 7 — Host integration (P2)

| ID | Work item | Acceptance |
|----|-----------|------------|
| P7.1 | `docs/integration.md` — embed Keel in an agent | Copy-paste Rust example |
| P7.2 | Example crate or `examples/agent_host.rs` | Builds in workspace |
| P7.3 | Env contract (`KEEL_HOME`, `KEEL_BWRAP`, `KEEL_KERNEL_TEST`) | Single table in docs |

---

### Deferred

| Item | Where |
|------|--------|
| remote-microvm | [`future-remote-microvm.md`](./future-remote-microvm.md) |
| Full tool suite / ACP / permission TUI | Out of scope (agent host) |
| Consume / token accounting | Later product track |

---

## Execution order (this program of work)

```text
Phase 1 (composition)  →  Phase 2 (deny glob)  →  Phase 3 (e2e)
        →  Phase 4 (egress)  →  Phase 5 (config)  →  Phase 6 (polish)  →  Phase 7 (integration)
```

Ship after each phase (or sub-batch) as `0.0.x` with CHANGELOG.

---

## Progress log

| Date | Phase | Notes |
|------|-------|-------|
| 2026-07-18 | Plan written | Start Phase 1 |
| 2026-07-18 | Phase 1 | `compose::{worktree_sandboxed,worktree_soft}`; CLI `--sandbox` + `--worktree` composition |
| 2026-07-18 | Phase 2 | Deny glob expand + soft match; macOS Seatbelt regex; Linux expand→bwrap; zero-match warn |
| 2026-07-18 | Phase 3 | `tests/e2e_enforce.rs` + `docs/testing.md`; kernel tests env-gated |
| 2026-07-18 | Phase 4 (partial) | Proxy destroy on space teardown (existing); CONNECT docs in design/integration |
| 2026-07-18 | Phase 6 (partial) | `strict_credentials`, `record_violations` on SpaceOptions |
| 2026-07-18 | Phase 7 (partial) | `docs/integration.md` host embed guide + env table |
| 2026-07-18 | Phase 5 | `sandbox.toml` load/extends/additive project; CLI `--profile` / `--profile-file` / `profiles` |
| 2026-07-18 | Phase 4/6 | CONNECT-only egress docs; CLI `--strict-credentials`; violation events |

---

## Success metric

An agent host can:

1. Open a Space with **worktree + local-process**.
2. Deny `**/.env` (or equivalent) under real kernel/bwrap enforcement.
3. Restrict child egress to an allowlist with proxy + ProxyOnly.
4. Inject credentials without logging values.
5. Rely on documented e2e gates for regression confidence.

When (1)–(5) hold on macOS and Linux, Keel’s **execution-boundary** parity with Grok’s sandbox stack is “production-aligned” for library use—not full agent parity.
