# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`llm_context_shield` is a UNIX-style Rust CLI tool that scans text for LLM context injection threats — prompt injection, jailbreaks, data exfiltration, hidden content, delimiter manipulation, and instruction overrides.

## Build & Test Commands

- **Build**: `cargo build`
- **Run**: `cargo run -- scan` (reads stdin) or `cargo run -- scan <file>`
- **Test**: `cargo test`
- **Single test**: `cargo test test_name`
- **Integration tests only**: `cargo test --test integration`
- **Lint**: `cargo clippy`
- **Format**: `cargo fmt`
- **Check (fast compile check)**: `cargo check`

## Architecture

**Data flow**: `stdin/file → input::read() → normalize → scanners::build() → scan → report::output() → stdout/stderr`

**Key abstractions**:
- `Scanner` trait (`src/scanner.rs`) — all scanners implement `name()` + `scan(&str) -> Vec<Finding>`
- `RegexScanner` helper (`src/scanner.rs`) — shared logic for regex-pattern-list scanners
- Scanner registry (`src/scanners/mod.rs`) — builds `Vec<Box<dyn Scanner>>`, supports `--disable` filtering

**Exit codes**: 0 = clean, 1 = findings detected, 2 = error

**Output modes**: `text` (human-readable, details to stderr, summary to stdout), `json` (structured to stdout), `quiet` (exit code only)

**Adding a new scanner**: Create `src/scanners/new_scanner.rs`, implement `Scanner` trait (use `RegexScanner` helper), register in `src/scanners/mod.rs::build()`, add `Category` variant in `src/scanner.rs`.
