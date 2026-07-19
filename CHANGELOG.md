# Changelog

All notable changes to Keel are documented in this file.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)-style, versions follow SemVer for the `0.0.x` series.

---

## [0.0.10] — 2026-07-19

### Changed

- **crates.io packages renamed to `eero-keel-*`**, published as crates.io user **[EeroEternal](https://crates.io/users/EeroEternal)** (Eero).
  - `eero-keel-policy`, `eero-keel-record`, `eero-keel-enforce`, `eero-keel-core`, `eero-keel-cli`
  - Install: `cargo install eero-keel-cli` / `eero-keel-core = "0.0.10"`.
- **Why not `keel-exec-*`?** Version 0.0.8 was published under account **lipish**. Only that owner can push further versions of those names. This project standardizes on **Eero / EeroEternal**.
- Legacy `keel-exec-*` crates on crates.io are **not** maintained from this repository.
- Rust lib names unchanged (`keel_core`, …); binary still `keel`.

### Includes (from 0.0.9 code line)

- Stdio modes, process-group lifecycle, `ManagedProcess`, `SpaceFs`, `audit_args` / `ExecFinished` (Zene host APIs).

---

## [0.0.9] — 2026-07-19

### Added (Zene / host integration)

- **`StdioMode`** on `SpawnRequest` — `null` / `inherit` / `piped` for stdin, stdout, stderr.
- **Process-tree lifecycle** — process group kill on timeout/cancel; `ProcessExit` + `ExecFinished`.
- **`audit_args: false`** — redact Exec args in audit log.
- **`SpaceFs`** — policy-constrained host FS I/O + audit.
- `SpaceHandle::spawn` → **`ManagedProcess`**.

### Note

- GitHub tag `v0.0.9` exists; crates.io publish under `keel-exec-*` was blocked (owner mismatch). Superseded by **0.0.10** (`eero-keel-*`).

---

## [0.0.8] — 2026-07-19

### Changed

- **First crates.io publish** under the **`keel-exec-*`** package names (account **lipish** — historical).
  - Rust **library crate names** remain `keel_policy`, `keel_record`, `keel_enforce`, `keel_core`.
  - CLI binary remains `keel`.
- Documented crates.io naming collision with plain `keel` / `keel-core` / etc.

---

## [0.0.7] — 2026-07-18

### Added

- **`sandbox.toml` profiles** (Phase 5) — `~/.keel/sandbox.toml` + project `.keel/sandbox.toml` (additive only; no global name clobber); `extends`, `network`, `allow_hosts`, `deny` globs.
- CLI: `keel profiles`, `--profile <name>`, `--profile-file <path>`, `--strict-credentials`.
- Example: `examples/sandbox.toml`.
- SpaceOptions: `strict_credentials`, `record_violations` (deny → `Violation` events).
- Host guide: `docs/integration.md`; e2e: `tests/e2e_enforce.rs`.

---

## [0.0.6] — 2026-07-18

### Added

- **Optimization plan** — `docs/optimization-plan.md` (phases 1–7, progress log).
- **Backend composition** — `worktree_sandboxed` / `worktree_soft` factories; CLI `--sandbox` stacks with `--worktree`.
- **Deny glob enforcement (Phase 2)** — expand globs for Linux bwrap; Seatbelt regex denials on macOS; soft FS match for process-guard.
- **Testing guide** — `docs/testing.md` (default suite vs `KEEL_KERNEL_TEST`).

---

## [0.0.5] — 2026-07-18

### Documentation

- Document **`remote-microvm`** as a **future-only** direction (`docs/future-remote-microvm.md`): motivation, architecture sketch, phased plan; **not** scheduled for near-term implementation.
- Link the future note from `docs/design.md` and `README.md`; roadmap no longer treats microVM as a v0.5 deliverable.

### Notes

This release packages the post-`0.0.4` documentation decision so the public tree has a clear semver pointer for “local execution layer is the product focus.”

---

## [0.0.4] — 2026-07-18

### Added

- **`local-worktree` backend** — prefer `git worktree add`, else directory under `~/.keel/worktrees/`; spawn cwd isolation; cleanup on destroy.
- **JIT credentials** — resolve `env:` / `file:` grants at spawn, inject into child env; `CredentialIssued` / `CredentialRevoked` (names only); CLI `--cred NAME=env:VAR`.
- **Per-task policy narrowing** — `narrow_policy` + `SpaceHandle::open_task` / `open_task_in_worktree`; child may only shrink reach (network, creds, deny, TTL).
- CLI: `--worktree`, `--task-id`, backend `worktree`.

---

## [0.0.3] — 2026-07-18

### Added

- **Egress allowlist** — `check_egress(host, port)` with wildcards (`*`, `*.example.com`); always deny link-local / cloud metadata.
- **Localhost HTTP CONNECT proxy** for allowlisted spaces; inject `HTTP(S)_PROXY` / `ALL_PROXY` into children.
- **Kernel ProxyOnly** for sandboxed children so direct egress is blocked where the platform supports it.
- CLI: `check-egress`, `run --allow-host host[:port]`.

---

## [0.0.2] — 2026-07-18

### Added

- **`isolate_apply` (default true)** — Landlock/Seatbelt applied in the **child** (`pre_exec`), host agent process stays clean.
- **Linux bwrap read-deny** — bind-over mode-000 placeholders for policy deny paths (Landlock cannot deny subpaths of allowed trees).
- **Default event persistence** — `~/.keel/spaces/<id>/events.jsonl` (+ `policy.json`); `$KEEL_HOME` override; CLI `--no-persist`.
- CLI: `sandbox-exec` helper path for advanced hosts.

---

## [0.0.1] — 2026-07-18

### Added

- Initial scaffold: Policy · Enforce · Record · Lifecycle.
- Backends: `null`, `process-guard`, `local-process` (Landlock/Seatbelt via **nono** 0.53).
- Presets: `workspace`, `read-only`, `strict`.
- CLI: `info`, `policy`, `check`, `run`.
- AGENTS.md (English-only commits); Rust 1.93 / edition 2024.

---

## Summary of this optimization arc (0.0.1 → 0.0.5)

| Area | What improved |
|------|----------------|
| Host safety | Kernel sandbox no longer applied to the agent host by default |
| Linux deny | Real read-deny via bubblewrap, not Landlock-only soft notes |
| Observability | Space event JSONL on disk by default |
| Egress | Host/port allowlist + proxy + ProxyOnly (not only all-or-nothing) |
| Task isolation | Worktree + non-expanding child policies |
| Secrets | JIT inject at spawn; never logged as values |
| Roadmap clarity | MicroVM documented as future; local execution layer is the focus |

Grok Build alignment (execution/sandbox ideas) is intentional; Keel remains an **execution layer**, not a full coding agent (no ACP session context, tool loop, or permission TUI).
