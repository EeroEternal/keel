.PHONY: build test check fmt clippy run-info

build:
	cargo build -p eero-keel-cli

test:
	cargo test --workspace

check:
	cargo check --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

run-info:
	cargo run -p eero-keel-cli -- info
