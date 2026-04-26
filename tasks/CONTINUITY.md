# Continuity

Session-state notes. Updated at session end so the next session can pick up without re-reading the full transcript. Replaces the old "Session Handoff" section that lived at the top of `todo.md` before the 2026-04-25 truncation.

---

## State as of 2026-04-26 (Phase 11.5a–c complete and uncommitted; v0.5.1 installed; 11.6 spec landed; 11.6a planned, not started)

**Released:** `v0.5.0` (commit `d511008`). Tagged `v0.5.0`, pushed to `origin/main`.

**Active local install:** `~/.local/bin/lcs` → `~/.local/share/llm_context_shield/lcs-0.5.1`. Rebuilt with `cargo build --release --all-features` and copied in 2026-04-26 session. `lcs --version` confirms `0.5.1`. The install carries every uncommitted 11.5a/b/c addition. Note: `--all-features` adds ONNX/wasmtime/syara-* runtime requirements — the binary is 29 MB (was 25 MB pre-bump under `cli,yara,syara` only) and the prior `lcs-0.5.0` artifact remains on disk for rollback.

**Working tree:** **Phases 11.5a + 11.5b + 11.5c all fully implemented and uncommitted; Cargo.toml version bumped 0.5.0 → 0.5.1 (uncommitted); `tasks/todo.md` now carries the Phase 11.6 spec (uncommitted).** `cargo test --features cli,yara,syara` → 350/350 passing (283 lib + 61 integration + 4 syara_rules + 2 doctests; was 344 pre-11.5c, +6 new). `cargo clippy --features cli,yara,syara --all-targets -- -D warnings` clean. Manual smokes validated for all three phases including the 11.5c per-finding provenance text-output line and JSON-key emission. **Still 1 commit ahead of `origin/main` from before** — `1bb893a` ("Out of band feature request from first consumer app") — push pending; the 11.5a + 11.5b + 11.5c + version-bump + 11.6-spec changes are on top of it, also uncommitted. Decide commit strategy before starting 11.6a: a) bundle 11.5a/b/c + bump + spec into one PR; b) split into `1bb893a` push → 11.5a commit → 11.5b commit → 11.5c commit → bump+spec commit. Splitting keeps the diff readable; bundling is faster.

**Phase status:**
- Phases 1–11 shipped.
- **Phase 11.5a complete (uncommitted).** TaskList #164–171 all completed.
- **Phase 11.5b complete (uncommitted).** TaskList #172–177 all completed. `lcs rules` subcommand + `--show-fingerprint` flag + scan-output fingerprint embedding live and passing.
- **Phase 11.5c complete (uncommitted).** TaskList #178–185 all completed. `Finding.{rule_name, engine}` widened; per-engine stamping live; text output gains conditional `  rule: <name> (engine: <eng>)` line; cross-tool consistency confirmed (`findings[].rule_name` ∈ `lcs rules --json | .rules[].name`).
- **Phase 11.6 spec landed in `tasks/todo.md`** (between 11.5 and 12; uncommitted). Two-axis scope: 11.6a per-rule scoring metadata (`version`, `threat_level`, `threshold` on `RuleMeta`); 11.6b cross-engine `lcs rules -a/--all` JSON view; 11.6c docs + harness hand-off.
- **Phase 11.6a — planned, not started.** Plan at `~/.claude/plans/humble-dancing-falcon.md` (current; 6-step plan approved 2026-04-26 in plan-mode). Spec at `tasks/todo.md` Phase 11.6a section. Holding off on implementation pending session compact.
- Phases 11.5d, 11.6b, 11.6c, 12, 13, 14 unchanged.

---

## Phase 11.5a progress

**Plan file:** `~/.claude/plans/humble-dancing-falcon.md` (approved 2026-04-26).

**Tasks (TaskList) — all completed:**
- ✅ #164 Step 1 — `RuleMeta` + `Engine::rule_metadata()` trait extension + `Category::ALL`
- ✅ #165 Step 2 — `Scanner::category()` + 6 overrides + `SimpleEngine::rule_metadata`
- ✅ #166 Step 5 — `RuleSetFingerprint` module + `sha2 = "=0.10.9"` dependency
- ✅ #167 Step 6 — `ShieldError::NoRulesLoaded` + tracing warn
- ✅ #168 Step 7 — Shield fingerprint plumbing + `ScanReport.rule_set_fingerprint` + `with_rule_set_fingerprint`
- ✅ #169 Step 3 — `YaraEngine::rule_metadata` (cached at construction; shared `parse_meta` helper)
- ✅ #170 Step 4 — `SyaraEngine` source parser + cached `rule_metadata`
- ✅ #171 Step 8 — Verification: 335/335 tests pass, clippy clean, fingerprint smoke validated

**Net code touched:**
- `src/scanner.rs` — `Category` derives `PartialOrd, Ord, Hash`; `Category::ALL` const; `Scanner::category()` trait method (default `None`); `ScanReport.rule_set_fingerprint` field + `with_rule_set_fingerprint` builder.
- `src/engines/mod.rs` — `RuleMeta` struct; `Engine` trait extension (`rule_metadata`, `categories`, `threat_classes` with default impls); `engines::build` warns on zero loaded rules; `pub mod fingerprint`; re-exports `RuleSetFingerprint`, `compute_fingerprint`.
- `src/engines/fingerprint.rs` — **new module.** `RuleSetFingerprint` newtype + `compute()` over canonical-JSON sort of `(engine_name, RuleMeta)` tuples → SHA-256 → hex. 7 unit tests.
- `src/engines/simple.rs` — `SimpleEngine::rule_metadata` walks `scanners::build(&[])` (full registry, severity `None`, threat_class = category string).
- `src/engines/yara.rs` — split `extract_meta` via shared `parse_meta`/`ParsedYaraMeta`; new `extract_rule_meta` for introspection; `YaraEngine.rule_metadata_cache: Vec<RuleMeta>` populated at construction. 4 new tests.
- `src/engines/syara.rs` — new `parse_source_meta` parser (line-comment stripping, brace-balanced rule-body walker that skips strings + regex literals, meta-block kv extraction); `build_rule_metadata` validation projection; `SyaraEngine.rule_metadata_cache: Vec<RuleMeta>` populated at construction. 9 new parser tests.
- `src/scanners/{prompt_injection,instruction_override,jailbreak,delimiter_manipulation,data_exfiltration,hidden_content}.rs` — `category()` override (one line each).
- `src/shield.rs` — `ShieldError::NoRulesLoaded { engine }` variant; build-time check (factory path only — `custom_engine` path exempt by design); `Shield.rule_set_fingerprint` cached; `Shield::rule_set_fingerprint()` accessor; `Shield::scan` stamps the fingerprint onto every `ScanReport`. 4 new tests.
- `Cargo.toml` — `sha2 = "=0.10.9"`.
- `examples/fingerprint_smoke.rs` — **new file.** Cross-engine sensitivity smoke (simple/yara/syara fingerprints all distinct; simple deterministic across rebuilds; ScanReport carries the fingerprint).

**Verification artefacts:**
- `cargo test --features cli,yara,syara` → 335/335 pass.
- `cargo clippy --features cli,yara,syara -- -D warnings` → clean.
- `cargo run --example fingerprint_smoke --features cli,yara,syara` → all assertions hold.
- `--all-features` test run shows 6 pre-existing failures in `tests/semantic_rules.rs` that require ONNX runtime + MiniLM model files; **unrelated** to 11.5a.

**Behavioural note on `NoRulesLoaded`:** the check uses `rule_names().is_empty() && rule_metadata().is_empty()` — both signals must agree before the hard error fires. This intentionally never trips for SimpleEngine (its `rule_metadata` returns the full registry regardless of `--disable`, since the plan dictates introspection describes the full registry not the per-scan subset). The check fires for YARA/SYARA when both `rule_names` and `rule_metadata` are empty — the realistic "no rules loaded" state.

---

## What this session settled (so far)

1. **Plan-mode dialogue resolved two architecture questions.**
   - **Scanner trait surface**: extend `Scanner` with `fn category() -> Option<Category>` (default `None`). Trait-level, single source of truth.
   - **Zero-rules-loaded handling**: scanner errs out with a clear, descriptive message for any scan or rule-data request (`ShieldError::NoRulesLoaded { engine }`); other code paths emit `tracing::warn!`.

2. **Architectural clarification (user pushback during Q&A).** Introspection lives in `lcs` as the composer. We do **not** add introspection upstream to `yara-x` or `syara-x`. For YARA we use the public `Rule::metadata()` already exposed; for SYARA we parse the source text ourselves before/after `compile_str` since `CompiledRules.rules` is `pub(crate)`. Same machinery scales to correlation- and session-rule introspection later — `lcs` owns the layer.

3. **Plan file overwritten** at `~/.claude/plans/humble-dancing-falcon.md` (was the prior PRD/Phase-12 plan). New content covers all 8 implementation steps for 11.5a.

---

## Open decisions carried forward

- **BUGS.md #4** — `CrossEngine` symmetric pair fires twice. Recommended fix is **option (a)**: canonicalize the pair lexically. Awaits sign-off before patching.
- **BUGS.md #6** — `Shield::scan` and `report::output` both filter by `min_severity`; redundant in CLI use. Decide whether output-time re-filter is the contract or vestigial.
- **`install.sh` is broken.** Looks for `target/release/llm_context_shield` but Cargo.toml renames the binary to `lcs`; hardcodes `--features yara` only.
- **`~/.cargo/bin/lcs` cargo-install stub** from earlier mistaken install path. Harmless (shadowed by `~/.local/bin/lcs` in PATH). Optional housekeeping.

---

## Phase 11.5b summary — `lcs rules` CLI surface (complete, uncommitted)

**Spec:** `tasks/todo.md:56–77`. **Plan archived:** the 11.5b plan was overwritten in `~/.claude/plans/humble-dancing-falcon.md` by the 11.5c plan; if you need the 11.5b record, this section is the canonical post-mortem.

**Tasks (TaskList) — all completed:**
- ✅ #172 Step 1 — `Command::Rules` CLI variant + `--show-fingerprint` on `Command::Scan`
- ✅ #173 Step 2 — fingerprint embedding in scan output (JSON always, text gated)
- ✅ #174 Step 3 — `Shield::engine() -> &dyn Engine` accessor
- ✅ #175 Step 4 — `Command::Rules` handler with inline `RuleEntry` DTO
- ✅ #176 Step 5 — 9 new integration tests (rules + scan-output regressions)
- ✅ #177 Step 6 — verification (344/344 tests, clippy clean, full smoke battery)

**Net code touched:**
- `src/cli.rs` — `Command::Rules { engine, categories, threat_classes, json, fingerprint }` with clap `group = "rules_view"` for mutual exclusion. `Command::Scan` gains `show_fingerprint: bool`.
- `src/shield.rs` — `pub fn engine(&self) -> &dyn Engine` accessor. No other API change.
- `src/report.rs` — `output()` signature gains `show_fingerprint: bool` (last arg). JSON path always inserts `rule_set_fingerprint`. Text path emits `rule_set_fingerprint: <hex>` to stderr when flag is set.
- `src/main.rs` — passes `show_fingerprint` through to `output()`. New `Command::Rules` handler (~50 lines) with inline `#[derive(serde::Serialize)] struct RuleEntry<'a> { engine: &'a str, #[serde(flatten)] meta: &'a RuleMeta }`. Resolves engine via `Shield::builder()` (mirrors Scan path so config flow matches per Priori 2). Sorts rules by name before emit. Mutually-exclusive flags branched in priority order: `--fingerprint` → `--categories` → `--threat-classes` → `--json` → default rule list.
- `tests/integration.rs` — 9 new tests appended after the existing `list_*` block:
  1. `rules_default_lists_engine_prefixed_rules` — checks `simple:prompt_injection  [prompt_injection]` line
  2. `rules_categories_emits_simple_set` — substring checks on category lines
  3. `rules_categories_simple_engine_has_six_lines` — exact line-count assertion
  4. `rules_json_has_fingerprint_and_rules` — parses JSON, checks shape + 64-hex fingerprint
  5. `rules_fingerprint_is_single_hex_line` — verifies single-line hex output
  6. `rules_fingerprint_matches_scan_json_fingerprint` — cross-tool determinism
  7. `rules_unknown_engine_exits_two` — exit code 2 + "Unknown engine" stderr
  8. `scan_show_fingerprint_emits_to_stderr` — stderr line `rule_set_fingerprint: <hex>` when `--show-fingerprint`
  9. `scan_json_unconditionally_includes_fingerprint` — regression: top-level fingerprint key always present

**Verification artefacts:**
- `cargo test --features cli,yara,syara` → 344/344 pass (279 lib + 59 integration + 4 syara_rules + 2 doctests; was 335).
- `cargo clippy --features cli,yara,syara --all-targets -- -D warnings` → clean.
- Manual smokes (all green): `lcs rules`, `lcs rules --categories`, `lcs rules --categories -e yara` (15 categories), `lcs rules --threat-classes -e syara` (4 classes incl. `data_exfiltration`, `obfuscation`, `prompt_hijack`, `social_engineering`), `lcs rules --fingerprint` (deterministic), `lcs rules -e bogus` (exit 2), `lcs rules --json` (correct shape), cross-tool fingerprint match between `rules --fingerprint` and `scan -f json | rule_set_fingerprint`, `lcs scan --show-fingerprint` (stderr line present).

**Behavioural notes:**
- `lcs rules` does **not** honour `--disable` — by design (introspection always describes the full configured registry). If a "filtered/effective view" is ever wanted it'd be a separate flag.
- Default rule-list view sorts purely by `name` (today engine label is constant per Shield; sort is a no-op on engine but forward-compatible with multi-engine future).
- JSON entries flatten `RuleMeta` and prepend `engine`. `severity: null` is correct for SimpleEngine rules (per-pattern severity is scan-time).
- Text-mode fingerprint goes to stderr (matches `--threat-scores` / `--correlations` placement).

---

## Phase 11.5c summary — Per-finding rule provenance (complete, uncommitted)

**Spec:** `tasks/todo.md:79–94`. **Plan archived:** the 11.5c plan was overwritten in `~/.claude/plans/humble-dancing-falcon.md` by the 11.6a plan; this section is the canonical 11.5c post-mortem.

**Tasks (TaskList) — all completed:**
- ✅ #178 Step 1 — widen `Finding` (`rule_name: String`, `engine: String` fields + `with_rule_name`/`with_engine` builders, `Finding::new` keeps signature, defaults both empty)
- ✅ #179 Step 2 — `RegexScanner::scan` chains `.with_rule_name(self.name)`; `HiddenContentScanner` stamps `RULE_NAME = "hidden_content"` on 3 sites
- ✅ #180 Step 3 — `SimpleEngine::run_scored` chains `.with_engine("simple")` in the per-scanner loop
- ✅ #181 Step 4 — `YaraEngine` populates both fields in two struct literals (`rule_name: ident.to_string(), engine: "yara".to_string()`)
- ✅ #182 Step 5 — `SyaraEngine` populates both fields in two scan-time struct literals + one test-fixture literal at line 1699 (`rule_name: m.rule_name.clone(), engine: "syara".to_string()`)
- ✅ #183 Step 6 — `src/report.rs` text-output stderr per-finding block gains `if !f.rule_name.is_empty() { writeln!(err, "  rule: {} (engine: {})", ...) }`
- ✅ #184 Step 7 — 6 new tests: per-engine provenance (simple/yara/syara), `hidden_content_scanner` stamping check, integration test for `findings[].rule_name` + `engine` in scan JSON, integration test for text-output provenance line, correlation-propagation test using `FixedEngine` confirming `Vec<Finding>` transparency
- ✅ #185 Step 8 — verification (350/350 tests, clippy clean, full smoke battery green)

**Net code touched:**
- `src/scanner.rs` — `Finding` widened with `rule_name: String, engine: String`; `with_rule_name`/`with_engine` builders; `RegexScanner::scan` chains `.with_rule_name(self.name)`. Empty-string is the documented "no provenance" sentinel for test fixtures and custom engines.
- `src/scanners/hidden_content.rs` — `const RULE_NAME: &str = "hidden_content"` at module top; three `Finding::new` calls chain `.with_rule_name(RULE_NAME)`.
- `src/engines/simple.rs` — `run_scored` stamps `let finding = finding.with_engine("simple")` before `ScoredCandidate` wrap; existing test extended.
- `src/engines/yara.rs` — both `Finding { ... }` struct literals add `rule_name: ident.to_string(), engine: "yara".to_string()`.
- `src/engines/syara.rs` — both scan-time struct literals + the test fixture at line 1699 add `rule_name: m.rule_name.clone(), engine: "syara".to_string()`.
- `src/report.rs` — provenance line emitted in text mode only when `rule_name` non-empty; JSON path automatic via existing `Serialize` derive.
- `src/shield.rs` — new `correlation_propagates_finding_provenance` test using `FixedEngine` fixture: stamps `rule_name`/`engine` via builders, asserts the values flow through `MatchCorrelation.findings[].{rule_name, engine}`. (Hit one snag: initial test used `disable_correlations()` which suppresses *all* correlations including user rules — fixed by removing the call. The `disable_correlations` semantics are absolute, not "bundled-only"; see the existing `correlation_fires_when_rule_matches` test for the additive-rule path.)
- `tests/integration.rs` — `scan_json_findings_carry_rule_name_and_engine` (parses JSON, asserts non-empty `rule_name`, `engine == "simple"`, cross-consistency with `lcs rules --json`); `scan_text_emits_provenance_line` (asserts stderr contains `(engine: simple)`).

**Verification artefacts:**
- `cargo test --features cli,yara,syara` → 350/350 pass (283 lib + 61 integration + 4 syara_rules + 2 doctests; was 344).
- `cargo clippy --features cli,yara,syara --all-targets -- -D warnings` → clean.
- Manual smokes (all green): all three engines emit non-empty `rule_name` + correct `engine` field through `lcs scan -f json`. Text mode shows the new `  rule: <name> (engine: <eng>)` indented line. Cross-consistency confirmed: `findings[].rule_name` appears in `lcs rules --json | .rules[].name` for the same engine.

**Behavioural notes:**
- Empty-string sentinel: built-in engines always populate both fields. Empty strings indicate a manually-constructed `Finding` (test fixture, custom engine that opts out, pre-1.5c artefact). JSON always emits both keys; text mode skips the provenance line entirely when empty.
- `MatchCorrelation` propagation is automatic — its `Vec<Finding>` carries the widened fields without any correlation-engine code change.
- The split (scanner stamps `rule_name`; engine stamps `engine`) lets YARA / SYARA short-circuit by populating both inline at the construction point where both are in scope. SimpleEngine cannot — scanners don't know which engine wraps them — so it post-stamps in the merge loop.

---

## v0.5.1 install update (2026-04-26 session)

After 11.5c verified green:
1. Cargo.toml version bumped 0.5.0 → 0.5.1 (uncommitted).
2. `cargo build --release --all-features` (38 s cold; pulled in ONNX, wasmtime, cranelift, etc.).
3. `cp target/release/lcs ~/.local/share/llm_context_shield/lcs-0.5.1` and `ln -sfn .../lcs-0.5.1 ~/.local/bin/lcs`.
4. Smoke confirmed: `lcs --version` → `0.5.1`; `lcs scan -f json` shows the 11.5c `rule_name`/`engine` keys; fingerprint `2d7806f739539dfd740d9ceb53bc60947607957d768f6ab045246d0e1751e5d3` (will change after 11.6a — intentional, see plan).
5. Prior `lcs-0.5.0` (25 MB, `cli,yara,syara` only) retained on disk for rollback.

---

## Phase 11.6a prep — Extend `RuleMeta` with `version`, `threat_level`, `threshold`

**Spec:** `tasks/todo.md` Phase 11.6a section (uncommitted, just added). **Plan file:** `~/.claude/plans/humble-dancing-falcon.md` (current; 6-step plan approved 2026-04-26 in plan-mode, **not yet implemented** — user requested holdoff for compact).

**Status:** Approved plan; ready to implement after compact. Next session can pick up Step 1 directly without re-planning.

**What 11.6a ships (high level):**
1. Widen `RuleMeta` (`src/engines/mod.rs:38–44`) with `version: Option<String>`, `threat_level: i32`, `threshold: i32`. Existing derives cover the new types; no derive changes.
2. `SimpleEngine::rule_metadata` hardcodes `version: None, threat_level: 1, threshold: 0` for every regex scanner.
3. `YaraEngine`: extend `ParsedYaraMeta` (line 140) with `version: Option<String>`; add `"version"` arm to `parse_meta` (line 149); project all three fields in `extract_rule_meta` (line 216).
4. `SyaraEngine`: extend `build_rule_metadata` (line 70) with three `HashMap::get` lookups + `i32::parse` (mirrors the parse-with-default pattern from scan-time `extract_meta` at lines 670–697, minus the `tracing::warn!` since scan time already logs).
5. ~9 new tests: 3 fingerprint-sensitivity (in `src/engines/fingerprint.rs::tests`), 2 yara round-trip + defaults, 2 syara round-trip + defaults, 1 simple-engine assertion (extending existing test), 1 integration test for `lcs rules --json` keys.

**Critical scope-shrinking discovery from plan-mode exploration:**
- **Every bundled YARA + SYARA rule already declares `version`, `threat_level`, AND `threshold` in its `meta:` block.** 79 rules across 32 files, all complete. Audited via `grep -c version= / threat_level= / threshold=` per file vs. `rule` count per file — counts match exactly (modulo two `semantic_*.syara` files where `threshold=` count is higher, likely meta-block + body matches; meta-block is what gets parsed).
- **The original spec called for a bulk rule-edit pass to add `version = "0.5"` lines; that step is dropped.** Existing values (`"1"` and `"2"`) become the introspection-time payload as-is. Bundled rule files are NOT modified by 11.6a.

**Substrate already in place (no new lib infra needed):**
- `ParsedYaraMeta` already captures `threat_level` + `threshold`. Only `version` is a new struct field.
- `parse_source_meta` (syara) returns raw `HashMap<String, String>` containing every meta key. No parser change needed for SYARA.
- Fingerprint module hashes `serde_json::to_string(&(engine, RuleMeta))` — adding fields to `RuleMeta` automatically widens the canonical form. **No fingerprint code change required.** The fingerprint hex value WILL change post-11.6a (intentional; auditors should see the rule-set change).

**Architectural decisions already settled in plan-mode (2026-04-26):**
1. `version: Option<String>` (NOT `String`) — distinguishes "no version declared" from "declared as empty string." SimpleEngine emits `None`; YARA/SYARA emit `Some("1")` or `Some("2")` from existing rule meta.
2. `threat_level: i32`, `threshold: i32` (non-Optional) — defaults `1` and `0` mirror `ThreatMeta::with_defaults`. Surfacing `Some(1)` vs `None` would be leaky.
3. No bundled rule edits.
4. Reshape parsers, don't duplicate — single source of truth per engine.
5. Fingerprint sensitivity desired and automatic.
6. Text shape unchanged (`engine:rule [category]` stays minimal); new fields are JSON-only.
7. JSON shape is additive — existing keys unchanged.

**Concrete entry points (file:line refs from plan):**
- `src/engines/mod.rs:38–44` — widen `RuleMeta`.
- `src/engines/simple.rs:32–47` — append three field defaults to `RuleMeta` literal in `rule_metadata`.
- `src/engines/yara.rs:140` — `ParsedYaraMeta` gets `version: Option<String>`.
- `src/engines/yara.rs:149` — `parse_meta` initialises `version: None`; new `"version"` match arm.
- `src/engines/yara.rs:216` — `extract_rule_meta` projects three new fields into `RuleMeta`.
- `src/engines/syara.rs:70–89` — `build_rule_metadata` adds three HashMap projections + appends fields to RuleMeta literal.
- `src/engines/fingerprint.rs:78` — test-only `meta(...)` helper updated to set the new fields.
- `tests/integration.rs` — append `rules_json_includes_version_threat_level_threshold` test.

**Verification expectations:**
- `cargo test --features cli,yara,syara` → 350 + ~9 new = ~359 pass.
- `cargo clippy --features cli,yara,syara --all-targets -- -D warnings` → clean.
- Manual smokes:
  ```sh
  lcs rules --json | jq '.rules[0] | {name, version, threat_level, threshold}'
  # simple: {version: null, threat_level: 1, threshold: 0}
  # yara/syara: {version: "1" or "2", threat_level: <int>, threshold: <int>}

  lcs rules --fingerprint
  # New 64-char hex (DIFFERENT from pre-11.6a value 2d7806…1751e5d3 — intentional).
  ```
- Cross-tool fingerprint determinism via existing tests (`rules_fingerprint_matches_scan_json_fingerprint`) continues to pass; they assert equality, not specific hex values.

**Other pending (housekeeping; not blocking 11.6a):**
- **Push `1bb893a`** to origin (still 1 ahead).
- **Commit decision:** 11.5a + 11.5b + 11.5c + Cargo.toml bump + 11.6 spec are all uncommitted on top of `1bb893a`. Squash-or-split call before starting 11.6a (state-header strategy note covers options).
- **Resolve BUGS.md #4 / #6** when convenient.
- **Fix `install.sh`** as a small infra task.

---

## File map (where things live)

- **`tasks/todo.md`** — current phase plan. Phase 11.5 at top; 12, 13, 14 follow. Out-of-band feature requests at the bottom.
- **`tasks/BUGS.md`** — bug tracker. Resolved entries kept with `RESOLVED` markers + verification refs. Task candidates appended at bottom.
- **`tasks/BACKLOG.md`** — deferred research / speculative ideas. Not commitments.
- **`tasks/ARCHITECTURE.md`** — design diagrams and pipeline flow.
- **`tasks/lessons.md`** — empty stub. Task candidate E proposes either backfilling or removing the workflow's reliance on it.
- **`tasks/04-25-2026__todo.md`** — archive of the pre-truncation `todo.md` from 2026-04-25. Reference if you need the older Phase 1–11 spec history.
- **`tasks/MANUAL-HANDOFF-task-8d-encodings.md`** — task-specific handoff for the Phase 8d encoding rules. Historical; preserved.
- **`tasks/SYARA-X-WISHLIST.md`** — feature requests for the upstream `syara-x` crate. (Note: 11.5a does **not** add to this — introspection lives in `lcs`.)
- **`PRD.md`** — product requirements document; the "what / why" anchor.
- **`README.md`** — install + CLI usage. Points at PRD for vision, todo.md for phase plan.
- **`CLAUDE.md`** — project workflow rules and Claude Code guidance.
- **`~/.claude/plans/humble-dancing-falcon.md`** — currently holds the **approved-but-unimplemented 11.6a plan** (6 steps, scope shrunk by plan-mode discovery that bundled rules already declare every required meta field). Next session: read, then start at Step 1 (widen `RuleMeta`). 11.5c plan content was overwritten when 11.6a was drafted; the `Phase 11.5c summary` section above is the canonical post-mortem for 11.5c. The `Phase 11.5b summary` section remains the canonical 11.5b post-mortem.
