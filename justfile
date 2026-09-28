set shell := ["bash", "-cu"]

default:
    @just --list

fmt:
    cargo fmt
    shfmt -i 2 -s -w scripts/*.sh openwrt/*.init

check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    shfmt -i 2 -s -d scripts/*.sh openwrt/*.init
    shellcheck scripts/*.sh openwrt/*.init

test:
    cargo test
    cargo build --release
    uv run --python 3.13 python scripts/test-integration.py "${CARGO_TARGET_DIR:-target}/release/filter-merge"

build-router:
    bash scripts/build-router.sh

install:
    cargo install --path . --locked

deps:
    cargo fetch --locked

alias format := fmt
alias fix := fmt
alias lint := check
alias get-deps := deps
