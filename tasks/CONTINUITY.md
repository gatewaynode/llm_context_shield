# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-01 (compact-prep, end of Phase 13a session)

**Branch:** `main`. Phase 13a shipped, committed, pushed. Bug #4 (CrossEngine symmetric-pair doubling) fixed earlier in the same session as a Phase 13a prerequisite. Working tree clean. About to compact and start Phase 13b planning.

**Test count:** 378/378 (was 366 pre-13a). Clippy clean.
**Cargo version:** 0.5.3. Installed binary still predates current head. Optional bump.

**Phase status (lcs):**
- Phases 1–11, 11.5a–d, 11.6a–c — **complete**.
- Phase 12 — **transferred to aegis** at `../aegis/` on 2026-04-30.
- Phase 13a (Scan-group types + `Shield::scan_group`) — **complete 2026-05-01**.
- Phase 13b (CLI surface) — **next workstream**.
- Phase 13c (docs + example) — after 13b.
- Phase 14a–d (single-scan ensemble) — after 13.

**Sentrux:** quality_signal 6626 (was 6630 before 13a). Drift −4. Modularity unchanged at 4115 (raw 0.117, 24/26 cross-module). Well within the ~6300 watch threshold.

---

## Phase 13a — what shipped

New module `src/scan_group.rs`:
- `ScanGroup` — chainable `new`/`add`/`add_file` builder, plus `len`/`is_empty`/`iter`.
- `GroupReport` — `per_input: Vec<(String, ScanReport)>`, `aggregate_scoreboard: ThreatScoreboard`, `cross_input_correlations: Vec<MatchCorrelation>`, `summary: GroupSummary`.
- `GroupSummary` — `total_findings`, `distinct_threat_classes`, `worst_offender_label`, `worst_offender_cumulative`.
- `impl Shield { pub fn scan_group(&self, group: &ScanGroup) -> GroupReport }`.

Companion changes:
- `src/scoring.rs` — added narrow `ThreatScoreboard::merge(&mut self, other: &Self)` so the aggregate inherits per-input config weights without double-applying them.
- `src/shield.rs` — `correlation_rules` field bumped to `pub(crate)` so the scan-group impl can read it from a sibling module.
- `src/lib.rs` — `pub mod scan_group;` + re-exports of `ScanGroup`/`GroupReport`/`GroupSummary`.

Decisions enacted (recorded for 13b/13c context):
- **D1.** Module placement: own `src/scan_group.rs`, `impl Shield` block split across modules. shield.rs already at 653 lines; not adding more.
- **D2.** Cross-input pass filters to `CrossEngine` rules only. `Ordered`/`Proximate`/`Combined` have byte-position semantics that don't generalize across distinct inputs.
- **D3.** Synthetic engine label `"input:<label>"`. Findings cloned into the cross-input bucket carry the synthetic engine via `Finding::with_engine`. Per-input `ScanReport`s keep original engine names ("yara"/"syara"). User signed off on the JSON-bleed: cross-input correlation findings will show `engine: "input:<label>"` in JSON output.
- **D4 (deferred).** `[scan_group]` config section not added in 13a; revisit in 13b only if the CLI needs it. Per `feedback_simpler_path.md`.
- **Aggregate weight inheritance.** First non-empty per-input scoreboard cloned as the seed; subsequent ones merged via `merge` (which sums class scores + cumulative without re-applying weights). Cross-input correlation composite scores recorded via `record` so they get the inherited weights.
- **Worst-offender tie-break.** Lex-earlier label wins on cumulative ties.
- **Cross-input pass guard.** Skipped if fewer than two inputs have findings (no cross-input pairs to evaluate).

Bug #4 prerequisite (resolved earlier this session, separate commit): `CorrelationEngine::evaluate` now canonicalizes symmetric-ref CrossEngine pairs (`eng_a > eng_b` suppressed when both refs share category, rule_name_pattern, and engine_filter). Six bundled `multi_engine_corroboration_*` tests + the engine-level test flipped from `out.len() == 2` to `out.len() == 1`. BUGS.md #4 marked RESOLVED.

---

## Next session: Phase 13b plan

CLI surface for scan groups. Spec at `tasks/todo.md:237-247`.

### Open architectural choice (Q4)

**Q4.** `--group` flag on `Command::Scan` vs new `Command::ScanGroup` subcommand?

Preview-recommendation from the 13a session: **subcommand `lcs scan-group <files>...`**. Reasoning:
- Output shape is structurally different (`per_input` + `aggregate_scoreboard` + `cross_input_correlations` + `summary`) — overloading `scan` requires a discriminator anyway.
- Existing `Command::Scan` takes `file: Option<PathBuf>` (single positional). Multi-file would either need `Vec<PathBuf>` (breaking the single-file ergonomic) or a separate `--group <list>` flag (awkward for shell glob expansion).
- Cleaner separation for future evolution (group-specific flags don't pollute the base `scan` namespace).

Re-derive Q4 in plan-mode entry. Per `feedback_one_question_at_a_time.md`: surface as a discrete question, resolve before any code.

### Sub-steps (assuming subcommand path)

1. **Add `Command::ScanGroup` to `src/cli.rs`.** Positional `files: Vec<PathBuf>`, plus the existing per-scan flags that still apply: `format` (text/json/quiet), `severity`, `disable`, `engine`, `correlations` (per-input + cross-input detail in text), `show_fingerprint`. Reject `safe_only_passthrough`/`output` — those are single-input concepts. Likely also add `--max-inputs <N>` (default 1000) as the guardrail mentioned in spec D7; defer the `[scan_group]` config section unless a real consumer wants it.
2. **Implement handler in `src/main.rs`.** Build inputs via `ScanGroup::new().add_file(path)?` per positional. Apply `--max-inputs` guardrail. Run `shield.scan_group(&group)`. Emit output:
   - **text:** per-input block (label + finding count + worst severity + per-input correlations under `--correlations`), then aggregate scoreboard, then `cross_input_correlations` (under `--correlations`).
   - **json:** `{"per_input": [{"label": ..., "report": {...}}, ...], "aggregate_scoreboard": {...}, "cross_input_correlations": [...], "summary": {...}, "rule_set_fingerprint": "..."}`. Note: `ScanReport` doesn't derive `Serialize` (existing report.rs builds JSON manually via `serde_json::json!` to handle severity-filtering at output time). 13b's handler will need the same pattern — build the per-input `report` JSON object explicitly with filtered findings, scores, correlations, fingerprint. Refactor opportunity: extract a `render_scan_report_json(&ScanReport, min_severity) -> serde_json::Value` helper if both `report::output` and the new group handler want it.
   - **quiet:** exit 0 if every per-input is clean AND no cross-input correlations; exit 1 if any per-input has findings or any cross-input correlation fires; exit 2 on error.
3. **Integration tests in `tests/integration.rs`.** Multi-file fixtures (write to `tempdir`-style temp paths via `assert_cmd`'s patterns — note: no `tempfile` dev-dep, use the project's existing fixture pattern). Cases: clean batch (exit 0), mixed batch (per-input distinguishes, aggregate reflects), cross-input multi_engine_corroboration_prompt_injection fires once across two PI-bearing files, JSON shape matches the documented contract, --max-inputs rejects oversized groups, quiet mode exit codes correct.

### Constraints carried into 13b

- Per `feedback_simpler_path.md`: don't add the `[scan_group]` config section unless CLI needs it. The `--max-inputs` flag with a CLI default is the thinner shape than a config section. Don't add `enable_cross_input_correlation` config — `correlation.enabled = false` already disables all correlation.
- Per `feedback_one_question_at_a_time.md`: resolve Q4 first. After Q4 lands, re-derive any sub-questions about the per-input JSON helper extraction.
- `ScanReport` is intentionally not `Serialize`-derived (per the comment at `src/scanner.rs:177-180`). Don't change that — match the existing pattern of building JSON via `serde_json::json!`.
- Per CLAUDE.md: run sentrux scan + health after 13b. Watch modularity (current 4115). If 13b's CLI handler bloat pushes equality (currently 5861) further, consider extracting the JSON-render helper to its own module.

### Test count

378 baseline → ~384 after 13b (~6 integration tests).

### Bug #4 sanity

Now that scan_group exercises the CrossEngine rules across synthetic engine buckets, the bug #4 fix is validated end-to-end (`cross_input_multi_engine_corroboration_fires_once` test in `src/scan_group.rs`). 13b integration tests will cover it again at the CLI level.

---

## Open work after Phase 13b

| Track | Item | Priority |
|---|---|---|
| lcs roadmap | Phase 13c (docs, README, `examples/batch_scan.rs`, PRD §6.4 `engine: "input:<label>"` provenance note) | After 13b |
| lcs roadmap | Phase 14a–d (single-scan ensemble) | After 13c |
| lcs bug | #5 misleading fast-path comment | Low cosmetic |
| lcs bug | #6 redundant severity filter | Low |
| lcs ops | Cargo 0.5.3 → 0.5.4 + reinstall | Trivial |
| lcs backlog | Sentrux modularity bottleneck deeper-dive | Hygiene |
| lcs backlog | Cumulative-scoring inflation | Medium |
| lcs backlog | Synonym-aware prescan, multilingual model swap, latency benchmark, threshold-tuning corpus, encrypted bundled rules | Research/hygiene |
| aegis bootstrap | Read imports → draft `PRD.md` → draft `ARCHITECTURE.md` → re-scope phases | Phase 0 (when user pivots to aegis) |

---

## File map

- `tasks/todo.md` — phase plan. Phase 13a marker still says "next workstream"; **needs update** to mark 13a complete. Phase 13b spec at lines 237-247 is the read-target for next session.
- `tasks/BUGS.md` — #1, #2, #3, #4 resolved. #5, #6 still open.
- `tasks/CONTINUITY.md` — this file.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `tasks/SYARA-X-WISHLIST.md` — pre-existing, untouched.
- `tasks/ARCHITECTURE.md`, `tasks/lessons.md` — unchanged this session.
- `tasks/BACKLOG.md` — unchanged.
- `~/.claude/plans/humble-dancing-falcon.md` — stale (still holds shipped 11.6b plan). Overwrite when planning Phase 13b.
- `~/.claude/skills/safe-fetch/SKILL.md` — current with project version (synced 2026-05-01).
- `PRD.md` — 13a didn't touch it. The §6.4 `engine: "input:<label>"` provenance note is a 13c task.
- `src/scan_group.rs` — NEW, all of 13a.
- `src/scoring.rs` — `merge` method added.
- `src/shield.rs` — `correlation_rules` field is now `pub(crate)`.
- `src/lib.rs` — `pub mod scan_group;` + re-exports.
- `src/correlation/mod.rs` — bug #4 fix (canonicalization).
- `src/correlation/bundled.rs` — bug #4 test updates.
- `../aegis/` — sister project. Untouched this session.

---

## Memory state

No new memories captured this session. Existing memories that applied:
- `feedback_simpler_path.md` — drove decision to defer `[scan_group]` config section (D4) and to not derive Serialize on `GroupReport`.
- `feedback_one_question_at_a_time.md` — drove the Q4 deferral to its own 13b plan-mode entry.
- `project_yarax.md`, `project_syara.md` — context for engine bucket labels in cross-input correlation tests.
- `feedback_quote_seeding.md` — not triggered this session.

---

## Sticky reminders for the next session

- **Per CLAUDE.md (lcs):** run sentrux scan + health after 13b. Watch modularity (4115) and equality (5861) — equality dropped slightly in 13a; if 13b's main.rs handler grows substantially, consider extracting JSON rendering into a helper module.
- **Per CLAUDE.md:** plan-mode for 13b before any code. The flag-vs-subcommand decision (Q4) is the single architectural question to resolve first.
- **Per `feedback_simpler_path.md`:** thin shape for 13b. CLI flag default for `--max-inputs` over a config section. No `[scan_group]` config unless a current consumer needs it.
- **Per `feedback_one_question_at_a_time.md`:** Q4 first. Then any sub-questions (JSON helper extraction, --max-inputs default).
- **Spec quirk:** `ScanReport` is intentionally not `Serialize`. Don't change. Build the per-input JSON via `serde_json::json!` like `src/report.rs::output` does today. The pattern is already in the codebase to copy.
- **Bug #4 is fixed.** Phase 14 calibration concerns are resolved; no need to revisit before 14.

---

## Sentrux baseline

Last scan (2026-05-01, post-13a): `quality_signal = 6626`. Bottleneck: **modularity (4115)**, raw 0.117, with 24/26 cross-module edges. Secondary: equality (5861, raw 0.414).

13a added one new module (`scan_group.rs`) but didn't shift modularity raw — sentrux's module detection didn't penalize. Equality dropped 24 points (5885 → 5861). Run scan + health before planning 13b (baseline) and after each 13b sub-step (catch drift).
