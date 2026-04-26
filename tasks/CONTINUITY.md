# Continuity

Session-state notes. Updated at session end so the next session can pick up without re-reading the full transcript. Replaces the old "Session Handoff" section that lived at the top of `todo.md` before the 2026-04-25 truncation.

---

## State as of 2026-04-26 (Phase 11.5a complete and uncommitted; 11.5b is next)

**Released:** `v0.5.0` (commit `d511008`). Tagged `v0.5.0`, pushed to `origin/main`.

**Active local install:** `~/.local/bin/lcs` → `~/.local/share/llm_context_shield/lcs-0.5.0`. Built with `--features cli,yara,syara`. `lcs --version` confirms `0.5.0`. The local install reflects `v0.5.0`, **not** the uncommitted 11.5a additions — rebuild + reinstall once 11.5a (and probably 11.5b) ships.

**Working tree:** **Phase 11.5a fully implemented and uncommitted.** All 8 plan steps land cleanly. `cargo test --features cli,yara,syara` → 335/335 passing. `cargo clippy --features cli,yara,syara -- -D warnings` clean. Manual smokes validated: cross-engine fingerprint sensitivity confirmed via `examples/fingerprint_smoke.rs`. **Still 1 commit ahead of `origin/main` from before** — `1bb893a` ("Out of band feature request from first consumer app") — push pending; the 11.5a changes are on top of it, also uncommitted. Decide commit strategy before starting 11.5b: bundle, or split (`1bb893a` push → 11.5a commit → 11.5b commits) — splitting keeps the diff readable.

**Phase status:**
- Phases 1–11 shipped.
- **Phase 11.5a complete (uncommitted).** Plan at `~/.claude/plans/humble-dancing-falcon.md` (now stale — was 11.5a). TaskList #164–171 all completed.
- **Phase 11.5b — next up.** Spec at `tasks/todo.md:56–77`. Library substrate is in place; this phase is mostly CLI plumbing.
- Phases 11.5c, 11.5d, 12, 13, 14 unchanged.

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

## Phase 11.5b prep — `lcs rules` CLI surface

**Spec:** `tasks/todo.md:56–77` (full checkbox list — read this first; it's the source of truth).

**Plan file slot:** `~/.claude/plans/humble-dancing-falcon.md` is currently 11.5a content; overwrite as the user did at the start of 11.5a. Same pattern: enter plan-mode, draft the 11.5b plan, get sign-off via `ExitPlanMode`.

**What 11.5b ships (high level):**
1. New `lcs rules` subcommand with flag combinations — see todo.md spec.
2. Embed `rule_set_fingerprint` in scan output: JSON always; text gated behind `--show-fingerprint`.
3. Integration tests in `tests/integration.rs`.

**Library substrate already in place from 11.5a (no new lib code needed):**
- `Engine::rule_metadata() -> Vec<RuleMeta>` — every built-in engine populates it (`SimpleEngine` walks the full registry; `YaraEngine` and `SyaraEngine` cache at construction).
- `Engine::categories() -> BTreeSet<Category>` and `Engine::threat_classes() -> BTreeSet<String>` — default-impl helpers derived from `rule_metadata`.
- `engines::compute_fingerprint(&[(engine_name, &[RuleMeta])])` and `Shield::rule_set_fingerprint() -> &RuleSetFingerprint` — pre-computed, cheap to read.
- `ScanReport.rule_set_fingerprint: RuleSetFingerprint` — already populated on every `Shield::scan` return value; `report::output` doesn't yet read it.

**Concrete entry points:**
- **CLI declaration:** `src/cli.rs:21` — `Command` enum. Add `Rules { engine: Option<String>, categories: bool, threat_classes: bool, json: bool, fingerprint: bool }`. Mirror `Command::List` shape.
- **CLI handler:** `src/main.rs:184` — `Command::List { engine }` is the closest analogue (15 lines; constructs a Shield via `engines::build` and prints `engine.rule_names()`). The `Rules` handler will:
  - Resolve engine name with the same precedence (CLI flag → `[scan].engine` config → `"simple"`).
  - Build a `Shield` (not raw `engines::build` — Priori 2 says config-load path matters; mirror `lcs scan`'s ShieldBuilder usage in `src/main.rs` around the scan handler).
  - Branch on flags. `--fingerprint` short-circuits to a single `println!`. `--json` builds `{"fingerprint": ..., "rules": [...]}`. `--categories` / `--threat-classes` print sorted set, one per line. Default prints `<engine>:<rule_name>  [<category>]`.
  - Sort rules by `(engine, name)`; categories follow `Category::ALL` declaration order (already sorted that way by `BTreeSet<Category>` because `Category` derives `Ord` in declaration order).
- **Scan-output fingerprint plumbing:** `src/report.rs:24` — `report::output`. JSON path at line 39: add `"rule_set_fingerprint": report.rule_set_fingerprint.as_str()` to the top-level object. Text path at line 60: emit fingerprint only when a new `show_fingerprint: bool` arg is true. Handler in `src/main.rs` (the scan path) passes the flag from the CLI.
- **CLI flag for scan:** `src/cli.rs` — add `#[arg(long)] show_fingerprint: bool` to `Command::Scan`.
- **Integration tests:** `tests/integration.rs` — pattern is `assert_cmd::Command::cargo_bin("lcs")...assert()`. Existing tests in that file demonstrate the shape; add the seven cases listed in todo.md:70–77.

**Open architectural decisions for plan-mode:**
1. **Does `lcs rules` honour `--disable`?** Per the 11.5a design ("introspection always describes the full registry, not the per-scan filtered subset"), **no** — and the spec at todo.md:64 reinforces this ("schema is a property of the configured instance"). But a user might reasonably ask "what will my Shield ACTUALLY emit?" — that's a different concept. Recommended: 11.5b stays full-registry; if the filtered view is useful, add it in 11.5c+ as `--effective` or similar. Confirm in plan-mode.
2. **Multi-engine union for `--categories` / `--threat-classes`:** todo.md:60 says "without `-e`, the union across all loaded engines." Today a `Shield` carries exactly one engine, so "union" today reduces to "that one engine's set." Spec is forward-looking — implement as a union helper that accepts a slice and is correct for the multi-engine future, even though today it iterates a slice of length 1.
3. **JSON shape for `--json`:** todo.md:62 says `{"fingerprint": "<hex>", "rules": [<RuleMeta+engine>...]}`. `RuleMeta` is `Serialize` (added in 11.5a) but doesn't carry the engine name — needs a wrapping struct or inline anonymous JSON (`json!({ "engine": ..., "name": ..., "category": ..., ... })`). Plan-mode decision: dedicated DTO vs ad-hoc `json!`.
4. **Exit codes:** todo.md:66 says `2` for unrecognised engine / config error — matches existing `lcs list -e <bad>` (`src/main.rs:199` already exits 2 via `process::exit(2)`). Reuse the same path.

**Verification expectations (Step N of the 11.5b plan):**
- `cargo test --features cli,yara,syara` stays green; new integration tests added.
- `cargo clippy --features cli,yara,syara -- -D warnings` clean.
- Manual: `lcs rules`, `lcs rules --json`, `lcs rules --fingerprint`, `lcs rules -e yara --categories`, `lcs scan --show-fingerprint`, all behave per spec.
- Determinism: `lcs rules --fingerprint` and a `lcs scan -f json | jq .rule_set_fingerprint` produce identical hex strings for the same config.

**Other pending (housekeeping; not blocking 11.5b):**
- **Push `1bb893a`** to origin (still 1 ahead).
- Commit 11.5a (uncommitted).
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
- **`~/.claude/plans/humble-dancing-falcon.md`** — currently holds the (now-implemented) 11.5a plan. Overwrite with 11.5b plan when next session enters plan-mode; same workflow as the 11.5a → 11.5a transition.
