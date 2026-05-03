# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-03 (Phase 13.5a complete)

**Branch:** `main`. Phase 13.5a is fully landed in this commit; the simple engine, its module tree, the `Scanner` trait, the `RegexScanner` helper, and `docs/migration-from-simple.md` are all gone. YARA-X is the default engine; `Cargo.toml` `default = ["cli", "yara"]`. Version 0.5.5 (interim — 0.6.0 reserved for 13.5b's asymmetric rescale).

**Test count:** 265 passing (190 lib + 72 integration + 3 doctest). The drop from 384 (end of 13c) reflects deleted simple-engine + scanners-module unit tests; no regressions, all preserved coverage runs against YARA now.

**Working tree (after the user's 13.5a commit + push):** expected clean except for `CLAUDE.md` (sub-agent rubric note carried forward from a prior session) — left unstaged on purpose; not a 13.5a concern. If the working tree shows anything else, treat it as the user's in-flight work and ask before touching.

**`~/.cargo/bin/lcs` is at 0.5.5** as of this session (refreshed via `cargo install --path .`). `~/.local/bin/lcs` may still be older — user-managed, do not touch.

---

## Phase 13.5a — locked decisions (preserved as record)

From `tasks/rule_widening_discussion.md` §8 and the plan-mode Q&A:

- **Q1 = B (pragmatic).** Migrate cleanly, log gaps in `tasks/RULE_FIXES.md` later (deferred to 13.5c).
- **Q2 = α (inspection-only).** No fixture-driven verification.
- **Q3 = iii.** Delete simple-internal tests; public-API failures get a new/expanded YARA rule.
- **Q4 = a.** `default = ["cli", "yara"]`. Feature flag stays.
- **Q5 = b.** Delete `src/scanners/` + `Scanner` trait + `RegexScanner` helper + `SimpleEngine` wrapper.

Audit result: 100% YARA coverage; no migration work required. Tasks #225/#226 deleted as no-ops. `RULE_FIXES.md` deferred to 13.5c.

Two real repair items surfaced and were fixed in 13.5a (not 13.5c):
1. `YaraEngine::run_scored` `--disable` was rule-name-only — extended to also match category names so the existing `--disable jailbreak`-style usage works.
2. `rules/yara/instruction_override.yar` line 30 missed the simple engine's `(?im)^` line anchor — added `(?m)^` so mid-sentence `SYSTEM:` no longer fires `instruction_override_high`.

See `tasks/todo.md` "Phase 13.5a" section for the full shipped checklist.

---

## Resume targets after Phase 13.5a (queued)

| Track | Item | Priority |
|---|---|---|
| lcs roadmap | **Phase 13.5b — asymmetric rescale + new metadata fields, tag 0.6.0** | **NEXT** |
| lcs roadmap | Phase 13.5c — populate `tasks/RULE_FIXES.md`, walk `tasks/TUNING.md` entries | After 13.5b |
| lcs roadmap | Phase 14a–d (single-scan ensemble / `ConfidenceScore`) | After 13.5 |
| lcs hygiene | `~/.local/bin/lcs` user-managed; not lcs's problem | — |
| lcs research | Custom engine direction (Leibniz / *characteristica universalis*) | Future, user-seeded |
| lcs research | Persisted FP suppression / dynamic tuning | After custom engine |
| aegis bootstrap | Read imports → draft PRD → draft ARCHITECTURE → re-scope phases | When user pivots |

---

## Phase 13.5b plan (locked numbers — DO NOT re-derive)

Per `tasks/rule_widening_discussion.md` and the user's earlier walked-back-from-flat decision:

- **`threat_level` × 20** — per-rule integer scaling. Touches every rule's `threat_level = N` meta line in `rules/yara/*.yar` and (if SYARA feature ships) `rules/syara/*.syara`.
- **`composite_threat_level` × 40** — correlation rule output scaling. Touches `src/correlation/bundled.rs` (and any user-supplied YAML correlation rules; document the migration).
- **Gating thresholds × 60** — `threshold` field on rules, `escalation_threshold`, `escalation_reduction` (these last two live in scoring config / `Config::scoring`).
- **Severity stays manual** — categorical (`low`/`medium`/`high`/`critical`); not rescaled.
- **Tag 0.6.0** at the 13.5b commit (the major-minor bump lands when the rescale ships).
- **Do not switch to flat ×20** — user explicitly walked back the flat version.
- **New metadata fields to add:** `context_taxonomy`, `provenance`. Wire through `RuleMeta`, the fingerprint canonicalisation, and the JSON output. Exact field shapes (open vocabulary vs. enum, optional vs. required) to be revisited at the 13.5b plan-mode entry — do not pre-commit a shape from this CONTINUITY note.

**13.5b sequencing suggestion (not locked):** rescale rules first → re-baseline tests → add metadata fields → fingerprint regenerates → docs in `docs/rule-authoring.md` get the rescale + new fields. The asymmetric multipliers will shift gating math, so expect a wave of test churn around `class_score(...)` thresholds in `src/engines/yara.rs` tests.

---

## Sticky reminders for the next session

- **Read `git status` first** — user committed and pushed 13.5a; the working tree should be clean (modulo the pre-existing `CLAUDE.md` un-staged note). Anything else = user's in-flight work; ask before touching.
- **Run `cargo test` first** to confirm the 265-test baseline before any 13.5b edits — this is the floor to defend against.
- **Sentrux scan is owed:** modularity uplift expected from the `src/scanners/` deletion. Run on next session start; record the new `quality_signal` value in this CONTINUITY for trend tracking.
- **`tasks/RULE_FIXES.md` does not yet exist** — create at start of 13.5c, not earlier.
- **`tasks/TUNING.md` is user-maintained.** Don't restructure without asking.
- **`~/.local/bin/lcs` is older.** User maintains separately. Don't try to "fix".
- **Before recommending: verify.** A memory mentioning a file or rule is stale until re-checked against the current tree.
- **`~/.claude/plans/humble-dancing-falcon.md` is stale (was 13c).** Overwrite at next plan-mode entry.
- **The simple engine is gone.** Any reference in older docs/memory to `simple` engine, `Scanner` trait, `RegexScanner`, or `src/scanners/` is stale — verify against current source before acting on it.

---

## Memory state

`~/.claude/projects/-Users-john-code-llm-context-shield/memory/feedback_imperfect_defense.md` is the load-bearing memory introduced by this work, indexed in `MEMORY.md`. Triggered by Q2: "Do not let perfection be the enemy of good enough."

Triggered without modification:
- `feedback_simpler_path.md` — drove recommendation defaults at every Q.
- `feedback_one_question_at_a_time.md` — Q1→Q5 sequenced.
- `feedback_quote_seeding.md` — user has poetry queued for the custom-engine direction; not engaged this session.

---

## Sentrux baseline (carried forward)

`quality_signal = 6615` at end of 13c. 13.5a *removes* a module subtree (whole `src/scanners/` + `src/engines/simple.rs` + `Scanner` trait + `RegexScanner` helper) → modularity uplift expected. Sentrux not run this session (paused for compact before bookkeeping). **Run sentrux at the start of the next session** and record the new value here. Re-plan threshold: qs floor ~6300 (re-plan if 13.5a *dropped* qs below that).

---

## What was NOT done this session (deferred / out of scope)

- **Sentrux scan after 13.5a landing** — deferred to next session start.
- **`tasks/RULE_FIXES.md`** — defer to 13.5c; no parity gaps surfaced in 13.5a.
- **Removing the `regex` crate dep** — verified still used by `src/correlation/mod.rs:158-178`. Keep.
- **Asymmetric rescale (×20 / ×40 / ×60)** — that's 13.5b, locked but not applied.
- **Tagging 0.6.0** — happens at the 13.5b commit, not 13.5a.
- **Rewriting `docs/rule-authoring.md`** — the rescale + new metadata fields land in 13.5b; doc rewrite goes with that commit.
- **`docs/scan-data-flow-simple.md`, `docs/scan-group-data-flow-simple.md`** — these describe the *simple data flow*, not the simple engine. Filenames are misleading post-13.5a but contents stand. Optional rename when the user wants ("simple" no longer disambiguates anything).
