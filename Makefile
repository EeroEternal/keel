.PHONY: build test check fmt clippy run-info

build:
	cargo build -p keel-exec-cli

test:
	cargo test --workspace

check:
	cargo check --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

run-info:
	cargo run -p keel-exec-cli -- info
