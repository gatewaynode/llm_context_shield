# Contributing to llm_context_shield

This project welcomes contributions from both humans and LLM coding assistants. This document is written to be useful to both.

## Project context

`llm_context_shield` is a Rust CLI tool that scans text for LLM context injection threats. The scanner design is intentionally modular: each threat category is an isolated file implementing a single `Scanner` trait. Adding new detection capability should not require touching existing code.

## How to add a new scanner

1. Create `src/scanners/<name>.rs` following the pattern of any existing scanner (e.g. `prompt_injection.rs`).
2. Implement the `Scanner` trait:
   ```rust
   pub struct MyScanner { inner: RegexScanner }

   impl Scanner for MyScanner {
       fn name(&self) -> &'static str { "my_scanner" }
       fn scan(&self, input: &str) -> Vec<Finding> { self.inner.scan(input) }
   }
   ```
3. Add a `Category` variant to the `Category` enum in `src/scanner.rs` and update its `Display` impl.
4. Register it in `src/scanners/mod.rs::build()`.
5. Add unit tests in `#[cfg(test)] mod tests` at the bottom of your new file. Each test should:
   - Use a real malicious payload as input, not a synthetic always-true string.
   - Assert on both presence of findings and their severity.
   - Include at least one `clean_text_no_findings` test to guard against false positives.

## How to improve existing patterns

Pattern files are in `src/scanners/*.rs`. Each scanner holds a `Vec<(Regex, Severity, &'static str)>`. To add a new pattern:

- Add a `(Regex::new(r"...").unwrap(), Severity::X, "description")` tuple.
- Note: the `regex` crate does **not** support look-ahead or look-behind. Use alternatives (e.g. match a broader pattern and accept some false positives, or split into two patterns).
- Run `cargo test` and verify your new pattern is covered by a unit test.

## Severity guidelines

| Severity | Use when |
|----------|---------|
| `Critical` | Unambiguous, high-confidence attack with direct impact (e.g. explicit instruction override, ChatML token injection) |
| `High` | Strong signal, low false-positive risk (e.g. identity reassignment, system prompt extraction) |
| `Medium` | Moderate signal or context-dependent (e.g. authority keyword directives, URL-encoded markdown images) |
| `Low` | Weak signal, potentially noisy — use sparingly |

## Development workflow

```bash
cargo check          # fast syntax/type check
cargo test           # run all unit + integration tests
cargo clippy         # lint — zero warnings expected
cargo fmt            # format
```

All PRs must pass `cargo test` and `cargo clippy` with zero warnings.

## Architecture reference

```
src/
  main.rs            Entry point: parse CLI, read input, run scanners, report
  cli.rs             Clap arg definitions
  input.rs           Read from stdin/file, normalize (BOM, line endings)
  scanner.rs         Scanner trait, Finding/Severity/Category types, RegexScanner helper
  report.rs          Output formatting (json / text / quiet)
  scanners/
    mod.rs           Registry: build() -> Vec<Box<dyn Scanner>>
    *.rs             One file per threat category
tests/
  integration.rs     Full CLI pipeline tests using assert_cmd
```

**Key design decisions:**
- Scanners are trait objects (`Box<dyn Scanner>`). The allocation overhead is negligible for a CLI tool.
- Regex patterns are compiled once in `new()` and reused across scans.
- Severity filtering happens at report time, not scan time — all findings are always collected.
- Structured output goes to stdout; diagnostic text goes to stderr. This preserves stdout for piping.

## Notes for LLM contributors

- Read `src/scanner.rs` first — it defines all shared types.
- The `RegexScanner` helper in `src/scanner.rs` eliminates boilerplate; use it for regex-based scanners.
- Do not use look-ahead (`(?=...)`) or look-behind (`(?<=...)`) — the `regex` crate does not support them.
- Prefer broader patterns with clearly documented scope over narrow patterns that miss variants.
- Keep each scanner file self-contained: patterns, struct, `Scanner` impl, and `#[cfg(test)]` all in one file.
- After any change: `cargo test && cargo clippy` must both pass clean before the work is done.
