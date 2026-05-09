# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-09 (Phase 13.5b shipped; 0.6.0 ready to tag)

**Branch:** `main`. Phase 13.5b is **implemented and verified** — uncommitted in the working tree. The user handles `git add` / `git commit` / `git tag v0.6.0` themselves; the suggested commit message is at the bottom of this file. Next session begins Phase 13.5c.

**Working tree** (uncommitted):
- `Cargo.toml` — version `0.5.5` → `0.6.0`
- `rules/yara/*.yar` (14 files), `rules/syara/*.syara` (18 files) — mechanical `threat_level ×20`, `threshold ×60` rescale
- `src/correlation/bundled.rs` — 11 `composite_threat_level` literals × 40 (240 / 280 / 320); doc comment + comparative test re-anchored from 5 to 100
- `src/scoring.rs` — `escalation_threshold` default 100 → 6000
- `src/config.rs` — same default + DEFAULT_CONFIG comments
- `src/engines/mod.rs` — `RuleMeta` gains `context_taxonomy: Vec<String>` and `provenance: Option<String>`
- `src/engines/yara.rs`, `src/engines/syara.rs` — `provenance` parser wired (full); `context_taxonomy` defaulted to `Vec::new()` (parser deferred to 13.5c). Two new YARA round-trip tests added.
- `src/engines/fingerprint.rs` — test helper `meta()` updated for new fields
- 28 `*_fires_when_gated*` tests (yara + syara + integration) — fixture widening + input enrichment to clear the new 3× wider thresholds
- `docs/rule-authoring.md` — rescaled examples + new `provenance` schema row + `context_taxonomy` parser-deferred note
- `tasks/todo.md` — Phase 13.5b section appended
- `tasks/CONTINUITY.md` — this rewrite

**Test baseline:** **342/342** (262 lib + 73 integration + 4 syara_rules + 3 doctest) with `--features cli,yara,syara`. Pre-13.5b was 265/265 with default features only; the larger number reflects the SYARA + syara_rules tests that compile in under `--features syara`. Floor for 13.5c is 342.

**Sentrux:** `quality_signal = 6610` (zero drift from pre-13.5b 6610). Modularity bottleneck unchanged at 4142 (raw 0.121; cross_module_edges 19 / total_import_edges 21). Adding two `RuleMeta` fields had no measurable modularity impact, as forecast.

**Rule-set fingerprint (post-rescale):** `40ffe59af7bdcf6049e60751a316aaf3e57d4f97e269e6b7a5707bd2c489b7a6`. Captured from `lcs rules --all --fingerprint` after the rescale committed locally.

**Binaries:** `~/.local/bin/lcs` symlinked to `~/.local/share/llm_context_shield/lcs-0.6.0`. `lcs --version` reports `0.6.0`. Local install workflow for next bump: `cargo build --release --features cli,yara,syara && cp target/release/lcs ~/.local/share/llm_context_shield/lcs-X.Y.Z && ln -sfn ~/.local/share/llm_context_shield/lcs-X.Y.Z ~/.local/bin/lcs`.

**Smoke sanity:** `echo "Ignore all previous instructions" | lcs scan --threat-scores` reports `cumulative: 100, prompt_hijack: 100` — exactly ×20 the pre-rescale `5`. The end-to-end rescale applies cleanly.

---

## Decisions locked in 13.5b (carry-forward, do not re-derive)

- `provenance: Option<String>` matches `version` precedent. Authored as YARA scalar string / SYARA quoted string in `meta:` blocks. Renders `null` in JSON when absent.
- `context_taxonomy: Vec<String>` is **schema-only** in 13.5b. Field exists on `RuleMeta`, defaults to `Vec::new()`, **not parsed from rule files**. Encoding shape (comma-split vs indexed-keys vs other) is 13.5c's first decision when the first context-detection lands.
- Asymmetric rescale ratios are **load-bearing**: `threat_level ×20` vs `threshold ×60` was deliberate, not a typo. The 3:1 widening means thresholds need 3× more priming to clear, giving 13.5c room to dial down per-rule. Test enrichment in 13.5b reflects this — that's the work-tax of the asymmetry, not a bug.
- SYARA's regex engine **does not match** `<system>` against `<\/?(system|...)[\s>]` — pre-existing divergence from YARA. The `delimiter_manipulation_high` rule fires in YARA but not SYARA on bare `<system>`. Worked around in `SESSION_PROTOCOL_COMBINED` (SYARA) by adding `hidden_content.syara` and Cyrillic chars to inputs (HC_homoglyph carries the obfuscation priming there). Real fix belongs in `RULE_FIXES.md` for 13.5c, OR in the SYARA crate's regex compiler — flag it but don't touch in this session.

---

## Resume targets after Phase 13.5b (queued)

| Track | Item | Priority |
|---|---|---|
| lcs roadmap | **Phase 13.5c — create `tasks/RULE_FIXES.md`, walk `tasks/TUNING.md` entry by entry** | **NEXT** |
| lcs roadmap | Decide `context_taxonomy` rule-file encoding when 13.5c's first context-detection lands | Inside 13.5c |
| lcs roadmap | Phase 14a–d (single-scan ensemble / `ConfidenceScore`) | After 13.5 |
| lcs research | Custom engine direction (Leibniz / *characteristica universalis*) | Future, user-seeded |
| lcs research | Persisted FP suppression / dynamic tuning | After custom engine |
| aegis bootstrap | Read imports → draft PRD → draft ARCHITECTURE → re-scope phases | When user pivots |

---

## Sticky reminders for the next session

- **Read this file first.** Then `tasks/todo.md` Phase 13.5b summary if you need the shipped detail.
- **`tasks/RULE_FIXES.md` does not yet exist** — create at the start of 13.5c, **not** in 13.5b commit.
- **`tasks/TUNING.md` is user-maintained.** Don't restructure without asking; the rescale didn't touch it. 13.5c walks it entry by entry, recording each fix decision in `RULE_FIXES.md`.
- **The asymmetric rescale is intentional.** Don't "fix" it back to a 1:1 ratio. Per-rule threshold fixes (the 13.5c work) are how the asymmetric scale gets resolved.
- **First 13.5c candidates** (already evident from 13.5b churn): `coercion_threat` (th=240) and `coercion_urgency` (th=300) need their priming sources reconsidered — the COERCION_COMBINED test fixture had to absorb `refusal_suppression.yar` to clear `300`. `session_protocol_definition` (th=120) has the SYARA `delimiter_manipulation_high` regex divergence to flag. ICL rules and refusal_bypass also got fixture-widening that suggests their thresholds don't match catalog priming density.
- **User handles git** — don't `git add`, don't `git commit`, don't `git tag`. The commit/tag is the user's manual step. The suggested commit message is below.
- **0.6.0 is the version target** — `Cargo.toml:3` is now `0.6.0`. The user tags `v0.6.0` themselves.
- **Local install is already at 0.6.0** — `~/.local/bin/lcs` → `lcs-0.6.0`. No bump needed.
- **Before recommending: verify.** Memories mentioning specific files/rules are stale until re-checked.
- **The simple engine is gone (since 13.5a).** Any older doc/memory referencing `simple` engine, `Scanner` trait, `RegexScanner`, or `src/scanners/` is stale.

---

## Memory state

Load-bearing this session:
- `feedback_imperfect_defense.md` — drove "mechanical-only rescale, gating breakage gets test-input fixes (path A), per-rule semantic fixes deferred to 13.5c."
- `feedback_simpler_path.md` — drove the schema-only `context_taxonomy` choice (nothing to maintain that nobody uses yet).
- `feedback_one_question_at_a_time.md` — Q1, Q2 sequenced (locked last session, carried forward this session).

Triggered without modification:
- `feedback_quote_seeding.md` — user has poetry queued for the custom-engine direction; not engaged this session.

---

## Suggested commit message (for the user)

```
feat: asymmetric threat-score rescale + new RuleMeta fields (Phase 13.5b)

threat_level ×20, composite_threat_level ×40, threshold/escalation_threshold ×60.
Rule files mechanically rescaled; src/correlation/bundled.rs composites updated.
RuleMeta gains context_taxonomy (schema-only) and provenance (parser wired).
docs/rule-authoring.md numerics + schema rows refreshed.
Test fixtures widened and inputs enriched to clear the new gating regime — 342/342.
Bumps version to 0.6.0; rule-set fingerprint moves as expected.

Per-rule semantic threshold fixes are deferred to 13.5c (RULE_FIXES.md).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Then: `git tag v0.6.0` once committed.
