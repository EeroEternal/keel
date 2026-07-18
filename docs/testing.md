# Testing Keel

## Default suite

```bash
cargo test --workspace
```

Runs unit tests only (soft FS, policy, proxy unit, worktree dir fallback, etc.).  
Does **not** require Landlock/Seatbelt privileges beyond what macOS/Linux grant by default for mapping tests.

## Kernel / enforcement gates

| Env | Effect |
|-----|--------|
| `KEEL_KERNEL_TEST=1` | Enables host-apply smoke (`isolate_apply = false`) and e2e that need real OS sandbox |
| `KEEL_BWRAP` | Override `bwrap` binary path (Linux read-deny) |
| `KEEL_HOME` | Isolate state under a temp dir for tests |

```bash
# macOS / Linux with kernel support
KEEL_KERNEL_TEST=1 cargo test -p keel-enforce -- --nocapture

# Linux with bubblewrap installed
KEEL_KERNEL_TEST=1 cargo test -p keel-enforce -- --nocapture
```

## Manual smoke

```bash
# Soft demo
cargo run -p keel-cli -- run --no-persist -- echo ok

# Composition (worktree ⊕ local-process) — optimization plan Phase 1
cargo run -p keel-cli -- run --worktree --sandbox --no-persist -- echo sandboxed-wt

# Egress policy check
cargo run -p keel-cli -- check-egress evil.com --allow-host api.x.ai:443
```

## CI recommendations

| Job | Command |
|-----|---------|
| PR (all OS) | `cargo test --workspace` |
| Nightly macOS | `KEEL_KERNEL_TEST=1 cargo test --workspace` |
| Nightly Linux | install `bubblewrap`; `KEEL_KERNEL_TEST=1 cargo test --workspace` |

Do not fail default PR CI on missing bwrap or sandbox support.
