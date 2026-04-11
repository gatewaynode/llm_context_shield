# Project TODO

Phased implementation plan for YARA-X and SYARA-X engine integration.
See `tasks/ARCHITECTURE.md` for full design and diagrams.

---

## Phase 1: Foundation (no new dependencies)

- [x] Add `Category::from_str_loose()` to `src/scanner.rs`
- [x] Add `RulesConfig` and `SyaraConfig` structs to `src/config.rs`
- [x] Update `Config` struct to include `rules` and `syara` fields
- [x] Update `DEFAULT_CONFIG` string with commented `[rules]` and `[syara]` sections
- [x] Create `src/rules.rs` — rule discovery module
  - [x] Bundled rule loading via `include_str!`
  - [x] XDG data dir discovery (`~/.local/share/llm_context_shield/rules/{engine}/`)
  - [x] Config `[rules] dir` override support
- [x] Change `engines::build()` return type from `Option` to `Result<Box<dyn Engine>, String>`
  - [x] Add `#[cfg]`-gated match arms with clear error messages for missing features
- [x] Update `src/main.rs` call site for new `build()` signature
- [x] Add `src/rules.rs` to `src/lib.rs` module declarations
- [x] Unit tests for `Category::from_str_loose` (all variants + unknown)
- [x] `cargo test` — all existing tests still pass
- [x] `cargo clippy` — no warnings

## Phase 2: YARA-X Engine

- [x] Add `yara-x = { version = "1.14", optional = true }` to `Cargo.toml`
- [x] Add `[features]` section with `yara = ["dep:yara-x"]`
- [x] Write bundled `.yar` rule files in `rules/yara/`
  - [x] `prompt_injection.yar` — port patterns from `src/scanners/prompt_injection.rs`
  - [x] `jailbreak.yar` — port from `src/scanners/jailbreak.rs`
  - [x] `data_exfiltration.yar` — port from `src/scanners/data_exfiltration.rs`
  - [x] `hidden_content.yar` — port from `src/scanners/hidden_content.rs`
  - [x] `delimiter_manipulation.yar` — port from `src/scanners/delimiter_manipulation.rs`
  - [x] `instruction_override.yar` — port from `src/scanners/instruction_override.rs`
- [x] Implement `YaraEngine::new()` — compile bundled + discovered rules
- [x] Implement `YaraEngine::run()` — scan, metadata→Finding mapping, disable filtering
- [x] Gate `engines::yara` module with `#[cfg(feature = "yara")]`
- [x] Unit tests (inline rule compilation, finding mapping, missing metadata handling)
- [x] Integration tests (`#[cfg(feature = "yara")]`) — same payloads as simple engine
- [x] Verify: `cargo test --features yara` — all tests pass
- [x] Verify: `cargo clippy --features yara` — no warnings
- [x] Verify: `cargo run --features yara -- scan -e yara` detects known payloads

## Phase 3: SYARA-X Engine

- [x] Add `syara-x = { path = "../syara-x/syara", optional = true }` to `Cargo.toml`
- [x] Add feature flags: `syara`, `syara-sbert`, `syara-classifier`, `syara-llm`
- [x] Write bundled `.syara` rule files in `rules/syara/`
  - [x] String-only rules mirroring the YARA rules (no Ollama dependency)
- [x] Implement `SyaraEngine::new()` — configure Registry from `[syara]` config, compile rules
- [x] Implement `SyaraEngine::run()` — scan, Match→Finding mapping, disable filtering
- [x] Gate `engines::syara` module with `#[cfg(feature = "syara")]`
- [x] Unit tests (string-only rules, finding mapping, MatchDetail sentinel handling)
- [x] Integration tests (`#[cfg(feature = "syara")]`) — string-only, CI-friendly
- [x] Semantic integration tests gated with `#[ignore]` (require Ollama)
- [x] Verify: `cargo test --features syara` — all tests pass
- [x] Verify: `cargo clippy --features syara` — no warnings

## Phase 4: Polish

- [x] Extend `lcs list` to show rule names when using yara/syara engines
- [x] Add `lcs init --rules` to scaffold XDG rules directory structure
- [x] Write rule-authoring guide (how to write custom `.yar`/`.syara` rules)
- [x] Write migration guide (simple engine regex → YARA rule equivalents)
- [x] Full integration test suite: `cargo test --features yara,syara` — all pass
- [x] Security review of rule loading (path traversal, symlink handling)

## Phase 5: Cross-platform release builds

Extend `Makefile.toml` (currently: macOS arm64, Linux x86-64 musl, Linux aarch64 musl) to cover Windows and the remaining reasonable architectures so `cargo make release` produces a full multi-arch artifact set.

- [ ] Add `release-windows-x86` target — `x86_64-pc-windows-gnu` via `cargo-zigbuild` (avoid MSVC toolchain requirement)
- [ ] Add `release-windows-arm` target — `aarch64-pc-windows-gnullvm` (or document as unsupported if zig toolchain coverage is insufficient)
- [ ] Add `release-macos-x86` target — `x86_64-apple-darwin` for Intel Mac coverage (pair with existing aarch64 for a universal-2 story)
- [ ] Add `release-freebsd-x86` target — `x86_64-unknown-freebsd` (optional; gate behind a separate `release-extras` task if it complicates CI)
- [ ] Wire all new targets into the top-level `[tasks.release]` `dependencies` list
- [ ] Add `[tasks.release-checksums]` — emit `sha256sum`s of every produced binary into `target/release-manifest.txt`
- [ ] Verify each target builds clean with `--features yara,syara` (yara-x/syara-x must cross-compile; flag any that don't)
- [ ] Document the supported target matrix in `README.md` under a new "Release builds" subsection, including the `cargo make release` one-liner
- [ ] Smoke-test the Windows binary end-to-end (`lcs.exe scan` under Wine or a real Windows host) before tagging a release
