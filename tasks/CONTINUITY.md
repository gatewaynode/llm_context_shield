# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-03 (compact-prep, end of Phase 13c + Phase 13.5 framing session)

**Branch:** `main`. Phases 13b and 13c are committed. Today's session also worked through `tasks/TUNING.md` (FP reports from a sister project using `safe-fetch`) and produced `tasks/rule_widening_discussion.md` — an itemized discussion doc that locks the decisions for **Phase 13.5** (drop `simple` engine + asymmetric rescale + new rule metadata).

**Test count:** 384/384 unchanged from 13b. Clippy clean. Sentrux quality_signal **6615** (no drift across 13b/13c — examples are excluded from the module graph as expected).

**Cargo version:** 0.5.4 (bumped at end of 13c). Local `~/.cargo/bin/lcs` refreshed via `cargo install --path .`. NB: `~/.local/bin/lcs` precedes on `PATH` and is a separate user-managed release build at older version — out of scope for `cargo install`.

**Working tree:** only `tasks/rule_widening_discussion.md` is untracked (will be committed after compact). Everything else from 13c (Cargo bump, examples/batch_scan.rs, README, PRD, docs, todo.md) is in commit `bc82b44`.

**Phase status (lcs):**
- Phases 1–11, 11.5a–d, 11.6a–c — complete.
- Phase 12 — transferred to aegis 2026-04-30.
- Phase 13a — complete 2026-05-01 (`Shield::scan_group` library API).
- Phase 13b — complete 2026-05-02 (`lcs scan-group` CLI surface; commit 697f75a).
- Phase 13c — complete 2026-05-02 (library docs + example; commit bc82b44).
- **Phase 13.5 — newly framed today, awaiting plan-mode entry.** Three-step phase: drop `simple` engine → rescale + new metadata → tune per TUNING.md.
- Phase 14a–d — single-scan ensemble / `ConfidenceScore`. After 13.5.

---

## Phase 13c — what shipped today (post-compact-1)

Commit `bc82b44` ("feat: wrap up scan groups and document"):

- **`examples/batch_scan.rs`** (NEW, ~80 lines after clippy fix). Path arg, file-or-dir, dotfile filter, null-byte binary skip with `// TODO(future): real binary analysis hook` stub, exit 2 on empty. User-directed shape: file → group of 1; dir → non-recursive `read_dir`; binary detected via null-byte sniff in first 8 KiB.
- **`docs/rule-authoring.md:283`** — corrected the "Currently dormant" sentence on `cross_engine` (now stale after 13a/b). Replacement notes scan-group activation with synthetic `input:<label>` engine bucketing; cross-links to `docs/scan-group-data-flow-simple.md`.
- **`README.md`** — appended a 13-line `Shield::scan_group` snippet after the existing scan example, with pointer to `examples/batch_scan.rs`.
- **`PRD.md` §4.3** — Scan groups row flipped 📅 Roadmap → ✅ Shipped; description folds in the `engine: "input:<label>"` provenance note.
- **`Cargo.toml`** — version 0.5.3 → 0.5.4.
- **`tasks/todo.md`** — 13c checkboxes flipped, completion bullet appended.

Verification on 13c: 384/384 tests, clippy clean (after one `is_some_and` fix in batch_scan.rs), sentrux qs 6615 unchanged. Manual smokes confirmed: mixed dir → cross-input correlation fires once + worst-offender named; single file → group-of-1; nonexistent path → clean error message.

---

## Phase 13.5 — framing decided today (in `rule_widening_discussion.md` §8)

User-driven discussion off `tasks/TUNING.md` (4 FP reports from sister project using `safe-fetch` skill: GitHub Releases API JSON tripping `data_exfiltration` on PR titles, hex digests tripping `hidden_content`, ZWS in Docusaurus HTML tripping `hidden_content` HIGH 25+/page, URL paths tripping base64 detector). Resulted in the locked decisions below.

### Decisions (D1–D9 from rule_widening_discussion.md §8)

- **D1. Drop the `simple` engine.** Hand-coded regex+Rust scanners introduce a class of bug (logic errors in glue code) that interpreted/compiled rules with strong validation avoid. All future tuning happens at the rule-file layer.
- **D2. Asymmetric multiplicative rescale.**
  - `threat_level` × **20** (1–5 → 20–100)
  - `composite_threat_level` × **40** (6–8 → 240–320)
  - Gating thresholds (`ThreatMeta.threshold`) × **60** (0/5/10 → 0/300/600)
  - `escalation_threshold` × **60** (default 100 → 6000)
  - `escalation_reduction` × **60** (0 → 0)
  - Severity buckets stay manual.
  - **Implication accepted:** composites become more dominant (ratio composite-max / single-max grows from ~1.6× to ~3.2×). Gating becomes harder to unlock (threshold-300 needs 15× threshold-0 hits at level 20).
- **D3. Add new rule-metadata fields alongside the rescale** (single commit, tag 0.6.0):
  - `context_taxonomy: Vec<String>` — placeholder for option C from the discussion. Populated as contexts get identified (`"html:body"`, `"json:value"`, etc.). No runtime behavior in 13.5b; hook for later.
  - `provenance: String` — optional. Ties a rule to the fixture/FP that motivated its current tuning. Tuning archaeology aid.
- **D4. Severity stays per-rule manual baseline.** Hybrid model is what we already have (we set baselines; downstream consumers override via `--disable` and future confidence overrides). Confirmed not a change request.
- **D5. Two-axis severity × confidence** (option B from discussion) — defer to Phase 14.
- **D6. f32 probability scale** (option D from discussion) — defer to Phase 14.
- **D7. New `tasks/RULE_FIXES.md`** log for applied fixes — separate from `TUNING.md` (FP reports stay there; fixes accumulate in RULE_FIXES for future pattern-mining).
- **D8. Single commit per phase**, tagged at meaningful boundaries. Rescale + metadata commit tagged **0.6.0**.
- **D9. Future-scope flagged but out of 13.5:** custom engine direction (Leibniz / *characteristica universalis*; divergence from pure Boolean rule logic — user has poetry to seed this when we get to it), and persisted FP suppression / per-deployment override files (dynamic tuning).

### Order of operations (Phase 13.5)

- **13.5a — Drop the `simple` engine.** Migrate viable simple rules to YARA. Document gaps (rules without clean YARA equivalent — accept loss or note as RULE_FIXES). Remove `src/scanners/` simple-engine code + registry hooks. **Bigger task than the rescale itself.** Plan-mode entry should resolve the open question: aggressive (every simple rule needs YARA equivalent before removal) vs. pragmatic (migrate what migrates cleanly; gaps logged as RULE_FIXES). User's "tuning at the rule-file layer" preference leans pragmatic.
- **13.5b — Rescale + new metadata.** Mechanical multiplicative pass over `.yar` / `.syara` / `correlation/bundled.rs`. Add `context_taxonomy` and `provenance` fields to the rule metadata schema. Update `docs/rule-authoring.md` composite-must-exceed-individual guidance with new bounds. Tag **0.6.0**.
- **13.5c — Begin tuning.** Spin up `tasks/RULE_FIXES.md`. Walk `TUNING.md` entry by entry; for each, propose a rule fix using the wider scale and (where ready) a `context_taxonomy` annotation. Tag 0.6.x increments per fix batch.

---

## Working tree at session end

Untracked:
```
?? tasks/rule_widening_discussion.md
```

This is the only working-tree change beyond what's in `bc82b44`. CONTINUITY.md after this rewrite will appear as ` M tasks/CONTINUITY.md`.

User will commit after compact.

---

## File map

- `tasks/todo.md` — phase plan. 13a/b/c marked complete. Phase 13.5 not yet recorded as a plan section in todo.md (will be added at 13.5a plan-mode entry; spec is in `rule_widening_discussion.md` §8).
- `tasks/BUGS.md` — #1, #2, #3, #4 resolved. #5 (cosmetic), #6 (acknowledged-by-design in `scan-data-flow-simple.md`) still open.
- `tasks/CONTINUITY.md` — this file.
- `tasks/TUNING.md` — committed; user-maintained FP report log. 4 entries (2026-05-02): GitHub Releases API JSON × 2, OpenTofu HTML × 2.
- `tasks/rule_widening_discussion.md` — NEW, untracked. Itemized discussion + locked decisions for Phase 13.5. §8 is the canonical decisions log.
- `tasks/RULE_FIXES.md` — NOT YET CREATED. Will be created at start of 13.5c.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `tasks/SYARA-X-WISHLIST.md`, `tasks/ARCHITECTURE.md`, `tasks/lessons.md`, `tasks/BACKLOG.md` — unchanged this session.
- `~/.claude/plans/humble-dancing-falcon.md` — Phase 13c plan (just shipped). Overwrite at next plan-mode entry.
- `docs/scan-data-flow-simple.md`, `docs/scan-group-data-flow-simple.md` — committed in 13c.
- `docs/rule-authoring.md` — `cross_engine` paragraph corrected at line 283. Will need further updates in 13.5b (composite bounds with new scale, new metadata field docs).
- `PRD.md` §4.3 — Scan groups row updated. No changes pending until 13.5b.
- `examples/batch_scan.rs` — NEW in 13c.
- `Cargo.toml` — at 0.5.4. Will bump to 0.6.0 at 13.5b commit.
- `src/scoring.rs`, `src/scanner.rs` — unchanged. Will be touched in 13.5b for new metadata fields and (potentially) the rescale defaults.
- `src/scanners/` (simple engine module tree) — to be **removed** in 13.5a.
- `src/correlation/bundled.rs` — composite levels need ×40 in 13.5b.
- All `.yar` / `.syara` rule files — `threat_level` ×20, `threshold` ×60 in 13.5b.
- `~/.claude/projects/-Users-john-code-llm-context-shield/memory/` — no new memories this session.
- `../aegis/` — sister project. Untouched this session. Phase 12 (sessions) lives there.

---

## Memory state

No new or modified memories this session. Triggered:
- `feedback_dataflow_docs.md` — would have triggered if user had asked for a dataflow walkthrough; they didn't this session.
- `feedback_simpler_path.md` — drove the 13c "thin shape" decisions and the discussion-doc structure.
- `feedback_one_question_at_a_time.md` — drove the Q1/Q2 framing in §5 of the discussion doc and the asymmetric-vs-flat ambiguity surface.
- `feedback_quote_seeding.md` — user offered "more original poetry" to seed thinking on the engine-direction question; declined for the immediate rescale task, accepted in principle for the longer-arc custom-engine discussion.

---

## Sticky reminders for the next session

- **User will commit `tasks/rule_widening_discussion.md` and updated `CONTINUITY.md` after compact.** Read `git status` first; don't assume anything about staging order.
- **Phase 13.5a is the next plan-mode entry.** It's bigger than 13c — dropping a whole engine + migrating its rules. Per `feedback_simpler_path.md`, the pragmatic migration option (gaps logged, not blocking) is the lighter path; surface this as the first question at plan-mode entry.
- **Asymmetric rescale numbers are LOCKED:**
  - `threat_level` × 20, `composite_threat_level` × 40, gating × 60, `escalation_threshold` × 60, `escalation_reduction` × 60. Severity stays manual.
- **Don't quietly switch to flat ×20 in 13.5b** — the user explicitly walked back the flat version after I surfaced the asymmetric/flat ambiguity. Composite dominance and harder gating are *intended* signals of the rescale.
- **Tag 0.6.0 at the 13.5b commit** — that's the meaning-preserving-but-value-changing tag the user asked for.
- **`tasks/RULE_FIXES.md` does not yet exist.** Create it at the start of 13.5c, not earlier.
- **`tasks/TUNING.md` is user-maintained.** FP reports go in there; they may add more between sessions. Don't restructure it without asking.
- **Per `feedback_quote_seeding.md`:** the user has poetry queued for seeding the custom-engine direction (Leibniz / *characteristica universalis*). Don't engage that direction until they offer the framing.
- **`~/.local/bin/lcs` is older than `~/.cargo/bin/lcs`.** User maintains the `~/.local` build separately. Don't try to "fix" it.

---

## Sentrux baseline (carried from 13b)

`quality_signal = 6615`. Bottleneck: **modularity (4077, raw 0.111)**, 26 cross-module edges. Secondary: equality (5789, raw 0.421). 13.5a will *remove* a module (the simple engine), which should improve modularity — watch for qs uplift. 13.5b adds two metadata fields but no new modules; should be neutral.

Watch threshold: re-plan if qs drifts below ~6300 or modularity raw drops below ~3800 during 13.5.

---

## Open work after Phase 13c

| Track | Item | Priority |
|---|---|---|
| lcs roadmap | **Phase 13.5a — drop simple engine** | Next |
| lcs roadmap | **Phase 13.5b — rescale + metadata fields, tag 0.6.0** | After 13.5a |
| lcs roadmap | **Phase 13.5c — populate RULE_FIXES.md, tune per TUNING.md** | After 13.5b |
| lcs roadmap | Phase 14a–d (single-scan ensemble / `ConfidenceScore`) | After 13.5 |
| lcs hygiene | `tasks/TUNING.md` integration into rule-authoring workflow | Ongoing through 13.5c |
| lcs bug | #5 cosmetic comment fix | Low |
| lcs bug | #6 redundant severity filter (acknowledged by-design) | Low |
| lcs ops | Sentrux modularity bottleneck deeper-dive | After 13.5 (modularity may shift) |
| lcs research | Custom engine direction (Leibniz / *characteristica universalis*) | Future, user-seeded |
| lcs research | Persisted FP suppression / dynamic tuning | After custom engine |
| lcs hygiene | `~/.local/bin/lcs` user-managed; not lcs's problem | — |
| aegis bootstrap | Read imports → draft PRD → draft ARCHITECTURE → re-scope phases | When user pivots |
