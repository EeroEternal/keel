# Agent and contributor rules

Instructions for humans and coding agents working in this repository.

## Language

**All committed content must be in English.**

This applies to:

- Source code comments and documentation comments (`//`, `///`, `//!`)
- Commit messages and PR titles/descriptions
- `README.md`, design docs, changelogs, and other markdown under the repo
- User-facing strings (CLI help, errors, log messages intended for operators)
- Issue templates, PR templates, and review comments left in-repo
- Generated docs that we check in (if any)

Exceptions (do not treat as a license to write prose in other languages):

- Proper nouns, product names, and third-party identifiers (e.g. Landlock, Seatbelt, Grok)
- Code identifiers and file paths that are not natural language
- Quotes or sample data that must preserve original language for correctness
- License text that is required to remain unchanged

When chatting with a user in another language is fine; **anything that lands in git must still be English.**

## Project purpose

Keel is the **execution layer under AI agents**: Policy · Enforce · Record · Lifecycle.

- Do not claim kernel isolation (Landlock / Seatbelt / microVM) unless the backend implements it and tests cover it.
- Prefer extending `EnforceBackend` over forking soft-check logic in callers.
- Policy must not be expandable by the agent at runtime; grant reach before the space opens.

## Engineering conventions

- Prefer targeted `cargo test -p <crate>` / `cargo check -p <crate>`; full workspace builds are fine but slower.
- Keep the public API small: `Policy`, `Space`, `EnforceBackend`, `RecordSink`.
- Soft backends (`null`, `process-guard`) are not a security boundary; document that clearly in user-facing text.
- Match existing Rust style in this tree (edition 2021, workspace deps, Apache-2.0 headers where present).

## Commits

- Write clear, complete-sentence commit messages in **English**.
- Do not commit secrets, local paths with credentials, or `target/` artifacts.
- Do not amend or force-push shared history unless explicitly requested.

## Scope discipline

- Only change what the task requires; avoid drive-by refactors and unrelated files.
- Do not add markdown docs the user did not ask for, except this file and docs they request.
