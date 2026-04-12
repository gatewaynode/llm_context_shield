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

- [x] Add `release-windows-x86` target — `x86_64-pc-windows-gnu` via `cargo-zigbuild`
- [x] Add `release-windows-arm` target — `aarch64-pc-windows-gnullvm` via `cargo-zigbuild` (in `release-extras`)
- [x] Add `release-macos-x86` target — `x86_64-apple-darwin` native cross-compile
- [x] Add `release-freebsd-x86` target — `x86_64-unknown-freebsd` via `cargo-zigbuild` (in `release-extras`)
- [x] ~~Add `release-openbsd-x86` target~~ — documented as native-build-only (tier 3, no cross-compile support)
- [x] ~~Add `release-netbsd-x86` target~~ — documented as native-build-only (`cargo-zigbuild` does not support this target)
- [x] Wire all new targets into `[tasks.release]` (core) and `[tasks.release-extras]` dependency lists
- [x] Add `[tasks.release-checksums]` — SHA-256 manifest at `target/release-manifest.txt`
- [x] Verify each target builds clean with `--features yara,syara` — all cross-compile successfully
- [x] Document the supported target matrix in `README.md` under "Release builds" subsection
- [x] Smoke-test the Windows binary — `file` confirms PE32+ executable; Wine/real host test deferred to release tag

## Phase 6: Library crate

`src/lib.rs` already re-exports every module (`cli`, `config`, `engines`, `input`, `logging`, `report`, `rules`, `scanner`, `scanners`), so the binary is a thin wrapper over the library — but the surface is ad-hoc and unversioned. This phase turns `llm_context_shield` into a proper crate that downstream Rust apps can depend on without pulling in `clap`, `tracing`, or the CLI wiring.

- [x] Audit the public API surface — CLI modules (`cli`, `logging`, `report`) gated behind `#[cfg(feature = "cli")]`; `Config::init_default()` and `Config::config_dir_exists()` marked `#[doc(hidden)]`
- [x] Add a top-level `Shield` builder API — `Shield::builder().engine("yara").min_severity(Severity::High).disable([...]).build()?.scan(text)` with `custom_engine()` for user-defined engines
- [x] Split `Cargo.toml` into `[lib]` + `[[bin]]`; gate `clap`, `tracing-subscriber`, `tracing-appender` behind default-on `cli` feature
- [x] Write rustdoc — crate-level docs on `lib.rs` with doctest example for `Shield::scan`
- [x] Add `examples/` directory: `examples/embed.rs` (library usage) and `examples/custom_engine.rs` (custom `Engine` trait impl)
- [ ] ~~Commit to a semver policy~~ — deferred until crates.io publish
- [x] Verified `RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --no-deps` passes clean
- [x] Switched `yara-x` from local path to crates.io (`version = "1.14"`); removed `syara-x` path dependency (deferred until crate published)
- [x] Add a `README.md` "Library usage" section with `Shield::builder()` snippet

## Phase 7: Heuristic threat scoring

Replace the current single-pass "run everything, collect findings" model with a multi-pass, threshold-gated scanning system. Rules declare how much threat they contribute and how much ambient threat must exist before they are worth evaluating. This lets us add sensitive rules that would be noisy on their own but become meaningful when earlier, cheaper rules have already raised suspicion — and lays the groundwork for branching heuristic paths that can go deep on specific threat classes without over-scanning clean input.

### 7a — Metadata schema

Extend rule metadata with three new fields. Existing `category` and `severity` are unchanged — severity remains the user-facing "what to do when positive" signal, while the new fields drive the engine's internal evaluation order.

- [x] Define the metadata fields:
  - `threat_level` (integer) — score this rule contributes to accumulators when it matches (e.g. 1 for a weak signal, 10 for a near-certain indicator)
  - `threshold` (integer, default 0) — minimum accumulated score in this rule's threat class before the rule is evaluated; threshold-0 rules always run
  - `threat_class` (string) — heuristic branch this rule belongs to (e.g. `social_engineering`, `data_exfiltration`, `prompt_hijack`, `obfuscation`); one rule = one class
- [x] Update `extract_meta` in `src/engines/yara.rs` to parse `threat_level`, `threshold`, and `threat_class` from YARA rule metadata; fall back to sensible defaults (`threat_level = 1`, `threshold = 0`, `threat_class = category name`) so existing rules work unmodified
- [x] Update `extract_meta` equivalent in `src/engines/syara.rs` for parity
- [x] Assign `threat_level`, `threshold`, and `threat_class` metadata to all bundled `.yar` rules in `rules/yara/` — initial values: current threshold-0 rules keep `threshold = 0`; no high-threshold rules yet (those come with real-world tuning)
- [x] Mirror metadata assignments to bundled `.syara` rules in `rules/syara/`
- [x] Add a `ThreatMeta` struct (or extend `Finding`) to carry the parsed fields through the pipeline so the scoring engine can consume them
- [x] Unit tests: `extract_meta` round-trips all three new fields; missing fields get defaults; invalid values produce warnings

### 7b — Scoring engine

Build the accumulator system that tracks per-class and cumulative threat scores as rules match.

- [x] Create `src/scoring.rs` — the `ThreatScoreboard` struct:
  - Per-class accumulators: `HashMap<String, i32>` keyed by `threat_class`
  - Global cumulative accumulator: sum of all class scores
  - `record(threat_class, threat_level)` — updates both the class and cumulative accumulators
  - `class_score(threat_class) -> i32` — current score for one class
  - `cumulative_score() -> i32` — global total
  - `should_run(threshold, threat_class) -> bool` — returns true when the class accumulator meets or exceeds the rule's threshold
- [x] Add a per-class cumulative weight factor (`f32`, default 1.0) to `ThreatScoreboard` — controls how much a class's score contributes to the global accumulator (future lever for dampening false-positive-heavy classes; all weights start at 1.0, no config surface yet)
- [x] Wire `ThreatScoreboard` into the `Engine::run` pipeline (pass as mutable context alongside `disabled`)
- [x] Add `src/scoring.rs` to `src/lib.rs` module declarations
- [x] Unit tests: accumulator arithmetic, `should_run` gating, weight dampening math, independent class tracking

### 7c — Multi-pass scanner

Restructure the YARA/SYARA engine `run()` to execute rules in threshold-ordered passes.

- [x] Feasibility study: YARA-X compiles all rules into a single monolithic `Rules` object. Splitting by threshold tier would require multiple `Compiler`/`Rules` — more memory, more complexity, for negligible gain since YARA scanning is fast. **Decision**: post-filter approach — compile and scan all rules in one pass, then process results in threshold order via `apply_threshold_filter()`.
- [x] Implement post-filter approach: `apply_threshold_filter()` in `src/scoring.rs` — stable-sorts candidates by threshold, walks in order, gates via `should_run()`, records scores. All three engines use this shared function.
- [x] Implement cross-branch escalation: when a class accumulator exceeds `escalation_threshold`, lower the effective threshold for other classes by `escalation_reduction`. Default config makes this inert (threshold=100, reduction=0).
- [x] Mirror threshold-gated logic in all three engines: `YaraEngine::run_scored()`, `SyaraEngine::run_scored()`, `SimpleEngine::run_scored()` all build `Vec<ScoredCandidate>` and call `apply_threshold_filter()`.
- [x] Unit tests: threshold filter with mixed tiers, filter blocks unmet thresholds, cross-branch escalation math.

### 7d — Config surface and observability

- [x] Add `[scoring]` section to `Config` / `DEFAULT_CONFIG` — fields: `escalation_threshold` (integer, default high enough to be inert until tuned), `escalation_reduction`, `class_weights` (optional table of `threat_class -> f32`)
- [x] Expose per-class and cumulative scores in `ScanReport` so they appear in JSON output (`-f json`) — consumers can use these for their own thresholding or dashboards
- [x] Add a `--threat-scores` flag to include the full `ThreatScoreboard` state in output
- [x] Update docs: rule-authoring guide (`docs/rule-authoring.md`) with new metadata fields, guidance on choosing `threat_level` and `threshold` values

### Future (out of scope for Phase 7)

- Kill chain ordering: explicit `order` / `priority` metadata for sequencing rules within a threshold tier; only if real-world attack chains demand it
- Per-class cumulative weight tuning from real-world false-positive data — the `class_weights` config hook is ready but values are all 1.0 until we have data
- Adaptive thresholds: adjust escalation behavior based on input length, source trust level, or prior scan history
