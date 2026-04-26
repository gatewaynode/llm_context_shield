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

## Local CLI Optimizations

- `lst` is aliased to `lsd --tree --depth 2` for showing a shallow tree project and file layouts
- `lsf` is aliased to `find . -type f -print0 | xargs -0 wc -l | sort -n` to show file word counts in a directory
- `tokei` is available for broad quick project composition inspection
- `fzf` and `ripgrep` are available, but often `tilth` is better


## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep the main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One tack per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behaviour between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Write tests that provide real demonstration of working code, no mock tests, no always true tests.
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "Is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over engineer
- Challenge your work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to `tasks/todo.md`
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.

## Development Guidelines

- **Small and Modular**: Try to keep individual files 500 lines of code or less and use thoughtful composition with these smaller files.
- **Follow the UNIX philosophy**:
    - "Make it easy to write, test, and run programs."
    - "Interactive instead of batch processing."
    - "Economy and elegance of design due to size constraints (assume limited resources of all types)."
    - "Self supporting system: avoid dependencies when possible, make our own helper functions and libraries."

## Security

- **Security First**: Always consider the security implications of code decisions and strongly bias towards secure code.
- **Never Use Latest Dependencies**: Try to keep to N - 1, and never use packages that are less than 30 days old.
- **Pin Dependencies**: When using dependencies always pin and use the verification hash if possible.
- **Thoroughly Review Everything**: Run security reviews, style reviews, architecture reviews and run tests regularly.

## MCP Tools to Prioritize

**tilth** Smarter code reading for agents


## Context Management

- **Continuity Maintenance**: The file `tasks/CONTINUITY.md` is for taking additional notes in preparation for compact.  Rewrite every time it is used.
- **Optimal Context**: For the 256K models optimal context is < 120k, for the 1M models the optimal context is < 240k.
- **Pause on Optimal Context Exhaustion**: Pause the dialogue and recommend preparing continuity notes and compacting when over the optimal levels mentioned above.
