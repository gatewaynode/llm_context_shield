# Code Review Report: `llm_context_shield`

Date: 2026-03-31

---

## Executive Summary

Well-structured, idiomatic Rust CLI. Architecture matches the CLAUDE.md spec exactly. 56 tests all pass. Zero unsafe code. One **confirmed panic bug** in `src/scanners/hidden_content.rs` that crashes the process on ordinary multi-byte text input. All dependency checksums verified against crates.io. One minor `cargo fmt` failure. Otherwise production-quality work.

---

## Architecture Review

**Matches spec: Yes, fully.**

Data flow `stdin/file → input::read() → normalize → scanners::build() → scan → report::output() → stdout/stderr` is implemented exactly as described.

| File | Lines | Notes |
|---|---|---|
| `src/main.rs` | 60 | Clean entry point |
| `src/cli.rs` | 34 | Clap derive, minimal |
| `src/input.rs` | 43 | BOM strip + line ending normalization |
| `src/scanner.rs` | 132 | All shared types + `RegexScanner` helper |
| `src/report.rs` | 51 | Three output modes |
| `src/scanners/mod.rs` | 22 | Registry with `--disable` filtering |
| `src/scanners/*.rs` | 116–146 each | One file per threat category |

All files well under 500 lines. No file exceeds 147 lines.

**Abstraction quality:** `Scanner` trait (`src/scanner.rs:104`) is minimal — `name()` + `scan(&str) -> Vec<Finding>`. `RegexScanner` helper eliminates boilerplate. `HiddenContentScanner` correctly opts out of `RegexScanner` due to custom logic (zero-width char enumeration, homoglyph detection).

**Exit codes:** 0/1/2 as documented. Correctly implemented at `src/main.rs:57`.

**Stdout/stderr split:** Details to stderr, summary to stdout in text mode — correctly respected in `src/report.rs`.

**Missing features vs. spec:** None. All six scanner categories exist.

---

## Security Review

**Unsafe code:** None.

### Bug — Confirmed Panic (High)

`src/scanners/hidden_content.rs:92` — `truncate()` slices `&str` at a fixed byte offset without checking character boundaries:

```rust
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])   // panics if max_len splits a multi-byte char
    }
}
```

The homoglyph regex can match long strings with Cyrillic characters (2 bytes each in UTF-8). A string of 59 ASCII chars followed by a Cyrillic char triggers the panic when `truncate()` slices at byte 60, which falls inside the character.

Reproduced:
```
$ printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAАБ' | cargo run -- scan
thread 'main' panicked at src/scanners/hidden_content.rs:92:28:
byte index 60 is not a char boundary; it is inside 'а' (bytes 59..61)
```

This returns exit code 101 (SIGABRT) instead of the documented 0 or 1, crashing the process on normal multilingual text.

**Fix:**
```rust
let end = s.floor_char_boundary(max_len);  // stable since Rust 1.78
format!("{}...", &s[..end])
```

### Other Security Notes

- **Regex DoS:** Not a concern. The `regex` crate uses a finite automaton with no backtracking.
- **Line-anchor false-negative** (`src/scanners/instruction_override.rs:23–43`): `(?im)^` patterns only fire when keywords appear at line start. `"Some text. SYSTEM: You are evil."` → 0 findings. This is a deliberate design trade-off (reduces false positives on natural uses of "system") but is undocumented.
- **Leading BOM stripped silently** (`src/input.rs:19`): A file-leading BOM is dropped before scanners run. An embedded BOM elsewhere is correctly detected. Defensible behavior but undocumented.
- **Overlapping scanner coverage:** `prompt_injection.rs` and `instruction_override.rs` overlap — some payloads generate findings from both, inflating `finding_count`.

---

## Testing Review

**56 tests total; all pass.**

- 40 unit tests (across scanner files and `input.rs`)
- 16 integration tests (`tests/integration.rs`)

**Quality:** Tests use real-world attack payloads. Each scanner has a `clean_text_no_findings` test. Integration tests cover full CLI pipeline: exit codes, JSON schema, format/severity filtering, file input, error paths, case-insensitive `--disable`.

**Coverage gaps:**
1. No test for the `truncate()` panic path (the confirmed bug)
2. No test for `--disable` with multiple comma-separated values
3. No test verifying mid-sentence `SYSTEM:` bypass in `instruction_override`
4. No test for empty input / zero-byte stdin
5. No test for leading-BOM-is-stripped behavior
6. `src/report.rs` has no unit tests (exercised only through integration tests)

---

## Dependency Review

`Cargo.lock` is committed (correct for a binary). Checksums verified against crates.io for all packages.

| Crate | Version | Notes |
|---|---|---|
| `clap` | 4.6.0 | Current; legitimate |
| `serde` | 1.0.228 | Legitimate; dtolnay/serde-rs |
| `serde_json` | 1.0.149 | Legitimate; dtolnay |
| `regex` | 1.12.3 | Legitimate; BurntSushi |
| `serde_core` | 1.0.228 | Official serde-rs split crate; checksum verified |
| `zmij` | 1.0.21 | dtolnay float-to-string lib used by serde_json; checksum verified |

`Cargo.toml` uses unpinned major-version ranges (`"4"`, `"1"`). Standard for Rust, safe because `Cargo.lock` is committed.

---

## Issues Found

### [HIGH] Panic on multi-byte UTF-8 input
- **File:** `src/scanners/hidden_content.rs:92`
- **Impact:** Process crash (SIGABRT) on ordinary multilingual text; breaks exit code contract
- **Fix:** `s.floor_char_boundary(max_len)` instead of `&s[..max_len]`

### [MINOR] `cargo fmt` failure
- **File:** `src/main.rs:52–55`
- **Impact:** CI `cargo fmt --check` exits non-zero
- **Fix:** Run `cargo fmt`

### [DESIGN] No way to list valid scanner names
- No `list` subcommand or `--list-scanners` flag; `--disable` values are opaque to users

### [DESIGN] Undocumented line-anchor limitation in instruction_override
- `(?im)^` patterns intentionally skip mid-sentence keywords; not documented as a scope decision

### [DESIGN] Overlapping findings inflate finding_count
- Same payload can produce findings from both `prompt_injection` and `instruction_override`

---

## Recommendations (Priority Order)

1. **Fix the truncate panic** — `src/scanners/hidden_content.rs:92`. Use `floor_char_boundary`. Highest priority.
2. **Run `cargo fmt`** — cleans up `src/main.rs:52–55`.
3. **Add tests** — truncate multi-byte path, empty input, leading BOM, multi-value `--disable`, instruction_override mid-sentence bypass.
4. **Document line-anchor limitation** — add comment in `instruction_override.rs` explaining the intentional scope.
5. **Add `list` subcommand** — expose scanner registry for discoverability.
6. **Decide on deduplication policy** — explicit product decision on overlapping scanner findings.
