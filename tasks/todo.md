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
- [ ] Add `release-openbsd-x86` target — `x86_64-unknown-openbsd` (Rust tier 3, no host tools; requires `-Z build-std` on nightly or a local BSD build host — document the path, don't block on it)
- [ ] Add `release-netbsd-x86` target — `x86_64-unknown-netbsd` (Rust tier 2 without host tools; cross-compile via `cargo-zigbuild` or a NetBSD cross-sysroot)
- [ ] Wire all new targets into the top-level `[tasks.release]` `dependencies` list
- [ ] Add `[tasks.release-checksums]` — emit `sha256sum`s of every produced binary into `target/release-manifest.txt`
- [ ] Verify each target builds clean with `--features yara,syara` (yara-x/syara-x must cross-compile; flag any that don't)
- [ ] Document the supported target matrix in `README.md` under a new "Release builds" subsection, including the `cargo make release` one-liner
- [ ] Smoke-test the Windows binary end-to-end (`lcs.exe scan` under Wine or a real Windows host) before tagging a release

## Phase 6: Library crate

`src/lib.rs` already re-exports every module (`cli`, `config`, `engines`, `input`, `logging`, `report`, `rules`, `scanner`, `scanners`), so the binary is a thin wrapper over the library — but the surface is ad-hoc and unversioned. This phase turns `llm_context_shield` into a proper crate that downstream Rust apps can depend on without pulling in `clap`, `tracing`, or the CLI wiring.

- [ ] Audit the public API surface — identify what should stay `pub` (`Scanner`, `Finding`, `Category`, `Severity`, `Engine`, `ScanReport`), what should become `pub(crate)` (internal helpers, CLI glue), and what should move behind a `cli` feature flag
- [ ] Add a top-level `Shield` (or `Scanner`) builder API — programmatic equivalent of the CLI: `Shield::builder().engine("yara").min_severity(Severity::High).disable([...]).build()?.scan(text)` — so callers don't have to construct `Config` by hand
- [ ] Split `Cargo.toml` into `[lib]` + `[[bin]]`; gate CLI-only deps (`clap`) and the `src/cli.rs` / `src/main.rs` path behind a default-on `cli` feature so library consumers can `default-features = false`
- [ ] Write rustdoc for every public item — module-level docs on `lib.rs`, doctest examples for `Shield::scan`, link to `docs/rule-authoring.md` from the `rules` module
- [ ] Add an `examples/` directory with at least: `examples/embed.rs` (library usage from another Rust program) and `examples/custom_engine.rs` (implementing the `Engine` trait outside the crate)
- [ ] Commit to a semver policy — document in `README.md` and `CONTRIBUTING.md` which items are stable, which are `#[doc(hidden)]` escape hatches, and the MSRV
- [ ] Set up `cargo doc --no-deps --all-features` in CI and fail on broken intra-doc links (`RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links"`)
- [ ] Publish dry-run: `cargo publish --dry-run` with all feature combinations; resolve any `path = "../syara-x/syara"` dependencies before a real publish (vendor, fork, or make syara a hard-optional `[dependencies]` entry with a `git` fallback)
- [ ] Add a `README.md` "Library usage" section with a minimal embedding snippet and a link to `docs.rs/llm_context_shield`

## Phase 7: Heuristic threat scoring

Replace the current single-pass "run everything, collect findings" model with a multi-pass, threshold-gated scanning system. Rules declare how much threat they contribute and how much ambient threat must exist before they are worth evaluating. This lets us add sensitive rules that would be noisy on their own but become meaningful when earlier, cheaper rules have already raised suspicion — and lays the groundwork for branching heuristic paths that can go deep on specific threat classes without over-scanning clean input.

### 7a — Metadata schema

Extend rule metadata with three new fields. Existing `category` and `severity` are unchanged — severity remains the user-facing "what to do when positive" signal, while the new fields drive the engine's internal evaluation order.

- [ ] Define the metadata fields:
  - `threat_level` (integer) — score this rule contributes to accumulators when it matches (e.g. 1 for a weak signal, 10 for a near-certain indicator)
  - `threshold` (integer, default 0) — minimum accumulated score in this rule's threat class before the rule is evaluated; threshold-0 rules always run
  - `threat_class` (string) — heuristic branch this rule belongs to (e.g. `social_engineering`, `data_exfiltration`, `prompt_hijack`, `obfuscation`); one rule = one class
- [ ] Update `extract_meta` in `src/engines/yara.rs` to parse `threat_level`, `threshold`, and `threat_class` from YARA rule metadata; fall back to sensible defaults (`threat_level = 1`, `threshold = 0`, `threat_class = category name`) so existing rules work unmodified
- [ ] Update `extract_meta` equivalent in `src/engines/syara.rs` for parity
- [ ] Assign `threat_level`, `threshold`, and `threat_class` metadata to all bundled `.yar` rules in `rules/yara/` — initial values: current threshold-0 rules keep `threshold = 0`; no high-threshold rules yet (those come with real-world tuning)
- [ ] Mirror metadata assignments to bundled `.syara` rules in `rules/syara/`
- [ ] Add a `ThreatMeta` struct (or extend `Finding`) to carry the parsed fields through the pipeline so the scoring engine can consume them
- [ ] Unit tests: `extract_meta` round-trips all three new fields; missing fields get defaults; invalid values produce warnings

### 7b — Scoring engine

Build the accumulator system that tracks per-class and cumulative threat scores as rules match.

- [ ] Create `src/scoring.rs` — the `ThreatScoreboard` struct:
  - Per-class accumulators: `HashMap<String, i32>` keyed by `threat_class`
  - Global cumulative accumulator: sum of all class scores
  - `record(threat_class, threat_level)` — updates both the class and cumulative accumulators
  - `class_score(threat_class) -> i32` — current score for one class
  - `cumulative_score() -> i32` — global total
  - `should_run(threshold, threat_class) -> bool` — returns true when the class accumulator meets or exceeds the rule's threshold
- [ ] Add a per-class cumulative weight factor (`f32`, default 1.0) to `ThreatScoreboard` — controls how much a class's score contributes to the global accumulator (future lever for dampening false-positive-heavy classes; all weights start at 1.0, no config surface yet)
- [ ] Wire `ThreatScoreboard` into the `Engine::run` pipeline (pass as mutable context alongside `disabled`)
- [ ] Add `src/scoring.rs` to `src/lib.rs` module declarations
- [ ] Unit tests: accumulator arithmetic, `should_run` gating, weight dampening math, independent class tracking

### 7c — Multi-pass scanner

Restructure the YARA/SYARA engine `run()` to execute rules in threshold-ordered passes.

- [ ] Feasibility study: investigate pre-compiling YARA rulesets grouped by `(threshold, threat_class)` at engine construction time — one compiled `Rules` object per group, avoiding recompilation at scan time; document findings and trade-offs in `tasks/ARCHITECTURE.md`
- [ ] If pre-compilation is feasible: restructure `YaraEngine::new()` to compile rules into a `Vec<CompiledPass>` ordered by threshold, where each `CompiledPass` holds a compiled ruleset and the threshold it requires
- [ ] If pre-compilation is not feasible (YARA-X limitations): implement post-filter approach as fallback — compile all rules in one pass, run all, but only emit findings from rules whose threshold is met; document the limitation
- [ ] Implement the multi-pass scan loop in `YaraEngine::run()`:
  1. Run threshold-0 pass (always runs)
  2. Update `ThreatScoreboard` with matches
  3. For each subsequent threshold tier: check `should_run` per-class, run the pass if eligible, update scoreboard
  4. Collect all findings across passes
- [ ] Implement cross-branch escalation: when a class accumulator exceeds a configurable escalation threshold, lower the effective threshold for other classes (so deep suspicion in one branch triggers deeper investigation in adjacent branches)
- [ ] Mirror multi-pass logic in `SyaraEngine::run()` for parity
- [ ] Update `SimpleEngine::run()` — the simple engine iterates Rust scanners sequentially, so threshold gating can be applied between scanner invocations without multi-pass; adapt the loop to check `ThreatScoreboard` before each scanner
- [ ] Integration tests: craft a payload that only triggers a high-threshold rule when low-threshold rules fire first; verify the high-threshold finding appears. Craft a clean-ish payload where low-threshold rules don't fire and verify the high-threshold rule is skipped.
- [ ] Performance benchmark: compare single-pass vs multi-pass on a representative corpus; document the overhead in `tasks/ARCHITECTURE.md`

### 7d — Config surface and observability

- [ ] Add `[scoring]` section to `Config` / `DEFAULT_CONFIG` — fields: `escalation_threshold` (integer, default high enough to be inert until tuned), `class_weights` (optional table of `threat_class -> f32`)
- [ ] Expose per-class and cumulative scores in `ScanReport` so they appear in JSON output (`-f json`) — consumers can use these for their own thresholding or dashboards
- [ ] Add a `--threat-scores` flag (or fold into `-f json`) to include the full `ThreatScoreboard` state in output
- [ ] Update docs: rule-authoring guide (`docs/rule-authoring.md`) with new metadata fields, guidance on choosing `threat_level` and `threshold` values

### Future (out of scope for Phase 7)

- Kill chain ordering: explicit `order` / `priority` metadata for sequencing rules within a threshold tier; only if real-world attack chains demand it
- Per-class cumulative weight tuning from real-world false-positive data — the `class_weights` config hook is ready but values are all 1.0 until we have data
- Adaptive thresholds: adjust escalation behavior based on input length, source trust level, or prior scan history
