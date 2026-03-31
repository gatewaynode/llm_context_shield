# Project TODO

Generated from initial code review (2026-03-31).

## Backlog

- [x] **[HIGH BUG]** Fix panic on multi-byte UTF-8 input in `src/scanners/hidden_content.rs:92`
  - `&s[..max_len]` slices at a fixed byte offset — panics when `max_len` falls inside a multi-byte char
  - Fix: use `s.floor_char_boundary(max_len)` (stable since Rust 1.78) or a char-index walk
  - Reproducer: 59 ASCII bytes + any Cyrillic char → exit 101 (SIGABRT) instead of 0/1
  - Breaks the documented exit code contract

- [ ] **[MINOR]** Fix `cargo fmt` diff in `src/main.rs:52–55`
  - Multi-line chain format rejected by `cargo fmt --check`; CONTRIBUTING.md requires clean fmt

- [ ] **[TESTS]** Add missing test coverage
  - Multi-byte character in `hidden_content` truncation path (>60 bytes, non-ASCII)
  - Empty input / zero-byte stdin
  - Leading BOM is silently stripped (document or test the behavior)
  - `--disable` with multiple comma-separated values
  - Mid-sentence `SYSTEM:` prefix (line-anchor false-negative in `instruction_override`)

- [ ] **[USABILITY]** Add `list` subcommand to enumerate valid scanner names for `--disable`
  - Currently no way to discover scanner names without reading source

- [ ] **[DESIGN]** Document line-anchor scope limitation in `src/scanners/instruction_override.rs`
  - `(?im)^` patterns intentionally skip mid-sentence keywords; should be a visible comment

- [ ] **[DESIGN]** Decide on deduplication policy for overlapping scanner findings
  - `SYSTEM: Ignore all previous instructions.` → 2 findings (prompt_injection + instruction_override)
  - Inflates `finding_count`; worth an explicit product decision

## Review Notes

See `tasks/report.md` for the full initial review.
