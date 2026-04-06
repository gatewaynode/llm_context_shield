# Project TODO

Phased implementation plan for YARA-X and SYARA-X engine integration.
See `tasks/ARCHITECTURE.md` for full design and diagrams.

---

## Phase 1: Foundation (no new dependencies)

- [ ] Add `Category::from_str_loose()` to `src/scanner.rs`
- [ ] Add `RulesConfig` and `SyaraConfig` structs to `src/config.rs`
- [ ] Update `Config` struct to include `rules` and `syara` fields
- [ ] Update `DEFAULT_CONFIG` string with commented `[rules]` and `[syara]` sections
- [ ] Create `src/rules.rs` — rule discovery module
  - [ ] Bundled rule loading via `include_str!`
  - [ ] XDG data dir discovery (`~/.local/share/llm_context_shield/rules/{engine}/`)
  - [ ] Config `[rules] dir` override support
- [ ] Change `engines::build()` return type from `Option` to `Result<Box<dyn Engine>, String>`
  - [ ] Add `#[cfg]`-gated match arms with clear error messages for missing features
- [ ] Update `src/main.rs` call site for new `build()` signature
- [ ] Add `src/rules.rs` to `src/lib.rs` module declarations
- [ ] Unit tests for `Category::from_str_loose` (all variants + unknown)
- [ ] `cargo test` — all existing tests still pass
- [ ] `cargo clippy` — no warnings

## Phase 2: YARA-X Engine

- [ ] Add `yara-x = { version = "1.14", optional = true }` to `Cargo.toml`
- [ ] Add `[features]` section with `yara = ["dep:yara-x"]`
- [ ] Write bundled `.yar` rule files in `rules/yara/`
  - [ ] `prompt_injection.yar` — port patterns from `src/scanners/prompt_injection.rs`
  - [ ] `jailbreak.yar` — port from `src/scanners/jailbreak.rs`
  - [ ] `data_exfiltration.yar` — port from `src/scanners/data_exfiltration.rs`
  - [ ] `hidden_content.yar` — port from `src/scanners/hidden_content.rs`
  - [ ] `delimiter_manipulation.yar` — port from `src/scanners/delimiter_manipulation.rs`
  - [ ] `instruction_override.yar` — port from `src/scanners/instruction_override.rs`
- [ ] Implement `YaraEngine::new()` — compile bundled + discovered rules
- [ ] Implement `YaraEngine::run()` — scan, metadata→Finding mapping, disable filtering
- [ ] Gate `engines::yara` module with `#[cfg(feature = "yara")]`
- [ ] Unit tests (inline rule compilation, finding mapping, missing metadata handling)
- [ ] Integration tests (`#[cfg(feature = "yara")]`) — same payloads as simple engine
- [ ] Verify: `cargo test --features yara` — all tests pass
- [ ] Verify: `cargo clippy --features yara` — no warnings
- [ ] Verify: `cargo run --features yara -- scan -e yara` detects known payloads

## Phase 3: SYARA-X Engine

- [ ] Add `syara-x = { path = "../syara-x/syara", optional = true }` to `Cargo.toml`
- [ ] Add feature flags: `syara`, `syara-sbert`, `syara-classifier`, `syara-llm`
- [ ] Write bundled `.syara` rule files in `rules/syara/`
  - [ ] String-only rules mirroring the YARA rules (no Ollama dependency)
- [ ] Implement `SyaraEngine::new()` — configure Registry from `[syara]` config, compile rules
- [ ] Implement `SyaraEngine::run()` — scan, Match→Finding mapping, disable filtering
- [ ] Gate `engines::syara` module with `#[cfg(feature = "syara")]`
- [ ] Unit tests (string-only rules, finding mapping, MatchDetail sentinel handling)
- [ ] Integration tests (`#[cfg(feature = "syara")]`) — string-only, CI-friendly
- [ ] Semantic integration tests gated with `#[ignore]` (require Ollama)
- [ ] Verify: `cargo test --features syara` — all tests pass
- [ ] Verify: `cargo clippy --features syara` — no warnings

## Phase 4: Polish

- [ ] Extend `lcs list` to show rule names when using yara/syara engines
- [ ] Add `lcs init --rules` to scaffold XDG rules directory structure
- [ ] Write rule-authoring guide (how to write custom `.yar`/`.syara` rules)
- [ ] Write migration guide (simple engine regex → YARA rule equivalents)
- [ ] Full integration test suite: `cargo test --features yara,syara` — all pass
- [ ] Security review of rule loading (path traversal, symlink handling)
