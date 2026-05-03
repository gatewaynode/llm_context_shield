# Rule scale widening — discussion

Working doc for deciding how to widen the threat-scoring scale before tuning individual rules from `tasks/TUNING.md`. Mark up inline; nothing here is decided yet.

Started: 2026-05-03.

---

## 1. What we see in TUNING.md

Four FP patterns, all on `simple` engine:

- [ ] **FP-1.** Generic English phrase `"Add API endpoint to request"` trips `data_exfiltration` HIGH on GitHub Releases JSON release-notes.
- [ ] **FP-2.** SHA-256 hex digests trip `hidden_content` MEDIUM (~140 hits per Releases response).
- [ ] **FP-3.** Zero-width space `U+200B` in Docusaurus-rendered HTML trips `hidden_content` HIGH (25+ per page).
- [ ] **FP-4.** URL paths and KMS/GitHub resource paths trip `hidden_content` MEDIUM (base64 detector).

None is purely a threshold problem. Each wants some combination of: regex tightening, charset exclusion, or content-context awareness. But the *prerequisite* for any of those fixes is having enough cardinal room in the scoring scale to describe a noise gradient. Right now everything lives in `threat_level ∈ 1..=5` with composites `6..=8` — too compressed to express "noisy but real" vs "tight" vs "near-certain."

#### Response

I think it is time to drop the simple engine.  Modifying code to tune engine rules should be a last resort after all modifications to rules files fails. the "simple" engine always breaks this.  Too much risk in causing a bug, the types of bugs we can avoid with interpreted/compiled rules and strong validation.

## 2. The word "threshold" is overloaded

Five distinct knobs in `src/scoring.rs` and rule metadata. Worth picking which axis we're widening before debating how:

- [ ] **2.a `ThreatMeta.threat_level`** — how much a single match contributes to its class accumulator. Current range observed: **1–5**.
- [ ] **2.b `ThreatMeta.threshold`** — class score required *before* a rule is even evaluated (threshold-gated multi-pass). Current observed: **0 / 5 / 10**.
- [ ] **2.c `composite_threat_level`** (correlation rules) — score recorded when a correlation fires. Currently must exceed max individual; observed: **6–8**.
- [ ] **2.d `escalation_threshold`** — cross-class spillover trigger (when *any* other class hits this, this class's `threshold` is reduced by `escalation_reduction`). Default: **100**.
- [ ] **2.e Severity bucket boundaries** — LOW/MEDIUM/HIGH/CRITICAL is currently per-rule manual annotation, not derived from `threat_level`. So widening `threat_level` doesn't automatically reshape severity unless we say it does.

If "widen the thresholds" means **all of 2.a–2.d in proportion**, option A below is the move. If it means **add a new dimension**, option B. If it means **change how severity maps to numbers**, that's a separate question (see §6).

#### Response

Since we have to touch every rule anyway in prep for tuning, maybe it's time to add these additional diminesions.  I'll admit they sound correct, but I'm not clear on how to apply them right away.  If that path is clear to you, this is a good time to refactor our rules and add in the additional dimensions to the metadata (I understand this means in depth rules and scoring rework).

## 3. Options

### A. Multiplicative rescale (×10 or ×20)

- [ ] All `threat_level` → 10–50 (or 20–100). Composites → 60–150 (or 120–300). Gating thresholds → 50 / 100 / 200. Escalation → 1000.
- [ ] Pure i32; type unchanged everywhere.
- [ ] Mechanical pass over rule files: every `.yar` / `.syara` / bundled correlation rule, plus `correlation/bundled.rs`.
- [ ] Existing tests stay semantically correct after a parallel rescale (test assertions on absolute values would need updating; assertions on relative ordering would not).
- [ ] **Buys:** rank space. We can say "this rule contributes 35, that one 50, this composite 120" and have the gradient mean something.
- [ ] **Doesn't buy:** any structural fix for the four FPs above. They're still per-rule problems.
- [ ] **Risk:** the wider numbers tempt over-precision. Nobody actually has the data to distinguish 35 from 38. Easy to confuse "more digits" with "more confidence."

#### Response

This is the approach I was envisioning.  I was thinking just 10x the whole set of numbers, but your scaled multipicative approach, might be better.  So:

- threat_level = * 20
- composites = * 40
- gating thresholds * 60

Would have been my first pass suggestion.

### B. Two-axis: severity × confidence

- [ ] Add `confidence: Low | Medium | High` to rule metadata, alongside existing severity.
- [ ] Severity = *if real, how bad*. Confidence = *how often this is wrong on benign content*.
- [ ] Noisy rules dial confidence down without losing severity (FP-1 stays HIGH severity but flips to LOW confidence; reporting layer can suppress LOW-confidence HIGH unless corroborated).
- [ ] **Buys:** maps directly to the TUNING cause. The hex-digest detector is "high severity if real, very low confidence on JSON" — that's exactly what confidence says.
- [ ] **Doesn't buy:** doesn't directly widen the score. Confidence is a presentation/gating dimension, not a score multiplier.
- [ ] **Risk:** competes with Phase 14's calibrated-confidence work — we'd be defining "confidence" twice with different shapes. And the user-facing UI question (does the reader see both severity and confidence? how?) is real and untrivial.

#### Response

This seems redundant to just adjusting rule meta values, especially if we add more fields to cover different angles and universally raise all the levels so we have more adjustability.  We'll tackle this in 14 if it looks necessary.

### C. Context modifiers

- [ ] Keep the scale; add per-rule `context_modifiers` that scale `threat_level` when the match sits inside HTML attributes, JSON string fields, framework-injected nodes, code fences, etc.
- [ ] Each TUNING.md entry has an obvious modifier: FP-2 → "value of JSON key matching `/digest|sha|checksum|hash/`"; FP-3 → "inside `<code>`/`<pre>` or class `.menu/.breadcrumb/.token`"; FP-4 → "inside `href=` or with `/`-density > 1/8"; FP-1 → "inside Markdown bullet or JSON `body`/`description`/`title`".
- [ ] **Buys:** actually resolves the four FPs.
- [ ] **Doesn't buy:** the cardinal room. We'd still be working in 1–5.
- [ ] **Risk:** content-type detection is its own rabbit hole. We'd need a content sniffer (HTML / JSON / Markdown / plain) and a way for rules to declare context constraints without becoming mini-parsers. Probably the right shape long-term but it's a real design surface.

We might need this anyway.  Some file and web sources are naturally going to be very false positive heavy.  So maybe another another metadata field that matches a string from a taxonomy we build when we can identify context (a future scope feature).

### D. f32 probability scale

- [ ] Switch `threat_level` and `threshold` from `i32` to `f32` (or named `Probability` newtype) in `0.0..=1.0`.
- [ ] Aligns with Phase 14's planned `ConfidenceScore` (calibrated probabilities).
- [ ] **Buys:** right long-term shape; arbitrary granularity.
- [ ] **Doesn't buy:** anything we can't get from A short-term. Type change across every rule, every test, every JSON shape, every config.
- [ ] **Risk:** premature. We don't have calibration data yet. Phase 14 is the natural home; doing it now competes with that work and bakes in a shape we might want to revisit when we have real labeled data.

## 4. Recommendation

**A first, then C as the per-rule follow-up.** B and D held for Phase 14.

Reasoning:

- A is one mechanical pass. Buys the rank space we need to *describe* noise gradients. Doesn't pretend to be more than that.
- C is where each TUNING entry actually gets resolved. Wider scale gives the dial; context modifier turns it.
- B duplicates Phase 14's confidence work. If we add a `confidence` field now, we'll either rename or fold it later.
- D is correct eventually but premature without calibration data.

**Order of operations matters.** A is the *prerequisite*, not the cure. If we ship A and stop, FPs are still loud — just in bigger numbers. C is where the quiet comes from.

## 5. Open questions

- [ ] **Q1.** When you said "change our threat thresholds," did you mean all five knobs in §2 in proportion, or specifically one of them (most likely 2.a `threat_level` + 2.c composite, since those are the ones rule authors set)?

### Answer

Yes.  Let's move all of them up in magnitude, so we have more room to find what works.

- [ ] **Q2.** ×10 or ×20? ×10 keeps numbers two-digit and easy to read; ×20 gives more headroom to express "noisy but corroborated" tiers (10 / 25 / 50 / 80 / 120 levels feel different).

### Answer
20 seems like it might give enough room.

- [ ] **Q3.** Should severity boundaries become *derived* from `threat_level` after the rescale (e.g., `LOW=1..=20, MEDIUM=21..=50, HIGH=51..=80, CRITICAL=81+`), or stay manually annotated per rule? Deriving would let A also tighten the severity story; staying manual leaves rule authors in control.

### Answer

Threat level should let the rule authors feel in control.  Should stay manual.

- [ ] **Q4.** Do we want the rescale to be a single commit (mechanical, reviewable, tagged 0.6.0 since it's a meaning-preserving but value-changing pass), or staged engine-by-engine (riskier merge ordering, but smaller diffs)?

### Answer

I see this as one quick flat pass, so yes one commit.  I'm hoping this doesn't have to be done again.

- [ ] **Q5.** Is `tasks/TUNING.md` the canonical place for the per-rule fix log going forward, or do we want a parallel `tasks/RULE_FIXES.md` once we start landing them so the FP report list stays clean?

### Answer

I think the TUNING.md file is fine to get started.  Maybe it is a good idea to have another file to track fixes so we can study it later and try to find patterns?

- [ ] **Q6.** B (two-axis) — confirm we want to defer this to Phase 14, or is there a reason to land it sooner? It maps to the TUNING causes more cleanly than A does.

### Answer

Yes, defer to 14.

## 6. Severity-mapping side question

Currently severity (LOW/MEDIUM/HIGH/CRITICAL) is set per-rule by hand and is *not* derived from `threat_level`. After a rescale, we could either:

- [ ] Keep severity manual. Rule authors set both. Independence is preserved (a rule can be "low contribution but if real it's CRITICAL" — useful for low-precision detectors of high-impact threats).
- [ ] Derive severity from `threat_level` ranges. Simpler mental model. Loses the "low contribution / high impact" expressiveness.
- [ ] Hybrid: derive by default, allow per-rule override. Probably the right shape but adds a config knob.

This is a separate decision from "widen the scale" but it's the natural moment to ask.

### Answer

Ah, you framed it differently with the hybrid mention here.  I think that is what we have by default.  We define the base criticallity, but implementors of our app can adjust the rules as they feel fit.  We just provide the baseline.

## 7. Out of scope for this discussion

- Per-FP rule fixes from TUNING.md (those are option C, post-rescale).
- Phase 14 calibrated confidence (option D).
- Whether the `simple` engine should be split into per-category sub-engines.
- Any new engine.

#### Response

Don't worru, there are more interesting engines to come.  YARA and SYARA just let us use what security folks are familiar with, I intend to take us into the Leibniz rabbit hole by following theories in "characteristica univeralis" that diverge from Boole but m,ay have been right after all.

- Persisting tuning data across runs.

### Answer

Are you referring to dynamic tuning?  That might be something we can approach if we write our own engine (not a far fetch considering the work we did in a different project to re-write SYARA in Rust).

## References

- `src/scoring.rs` — `ThreatMeta`, `ThreatScoreboard`, `apply_threshold_filter`.
- `src/scanner.rs` — `Severity` enum, `Finding`, `Category`.
- `docs/rule-authoring.md:303` — current "composites should exceed max individual (5)" guidance.
- `tasks/TUNING.md` — the FP report log.

---

## 8. Decisions and order of operations (locked 2026-05-03)

### Decisions

- **D1.** **Drop the `simple` engine.** Hand-coded regex + Rust scanners introduce a class of bug (logic errors in glue code) that interpreted / compiled rules with strong validation avoid. All future tuning happens at the rule-file layer, not the source-code layer.
- **D2.** **Asymmetric multiplicative rescale.** Per-knob factors:
  - `threat_level` **× 20** (range 1–5 → 20–100)
  - `composite_threat_level` **× 40** (range 6–8 → 240–320)
  - Gating thresholds (`ThreatMeta.threshold`) **× 60** (0 / 5 / 10 → 0 / 300 / 600)
  - `escalation_threshold` **× 60** (default 100 → 6000) — same units as gating, preserves the existing ratio
  - `escalation_reduction` **× 60** (default 0 → 0)
  - Severity buckets stay manual per-rule (Q3 answer).
  - **Implication, signed off:** composites become more dominant under this scale — ratio composite-max / single-max grows from ~1.6× to ~3.2×. Corroboration outweighs single hits more decisively. Gating becomes harder to unlock (a threshold-300 rule needs 15 threshold-0 hits at level 20, vs. previous 5 hits at level 1).
- **D3.** **Add new metadata dimensions alongside the rescale** (one commit, tag 0.6.0):
  - `context_taxonomy: Vec<String>` — placeholder for option C. Populated as contexts get identified (e.g., `["html:body", "json:value", "markdown:list"]`). Empty by default. No runtime behavior in 13.5b; future-scope hook for option C.
  - `provenance: String` — optional. Ties a rule to the fixture / FP that motivated its current tuning. Tuning archaeology aid.
- **D4.** **Severity remains per-rule manual annotation, baseline-only.** Downstream consumers can override / disable via existing `--disable` and (future) confidence overrides. Hybrid model is what we already have — confirmed not a change request.
- **D5.** **Defer two-axis severity × confidence** (option B) to Phase 14.
- **D6.** **Defer f32 probability scale** (option D) to Phase 14.
- **D7.** **New `tasks/RULE_FIXES.md` log** for tracking applied fixes — separate from `TUNING.md` (FP reports stay in TUNING; fixes accumulate in RULE_FIXES; future pattern-mining target).
- **D8.** **Single commit per phase**, tagged at meaningful boundaries. The rescale + metadata commit is tagged **0.6.0** (meaning-preserving but value-changing).
- **D9.** **Future-scope flagged but out of 13.5:** the custom engine direction (Leibniz / *characteristica universalis* — divergence from pure Boolean rule logic) and persisted FP suppression / per-deployment override files. Both will get their own discussion when we approach them.

### Order of operations

- **Phase 13.5a — Drop the `simple` engine.** Migrate viable simple rules to YARA where possible. Document gaps (rules without a clean YARA equivalent — accept the loss or note them as RULE_FIXES candidates). Remove `src/scanners/` simple-engine code and registry hooks. Bigger task than the rescale itself; warrants its own plan-mode session.
- **Phase 13.5b — Rescale + new metadata.** Mechanical multiplicative pass over `.yar` / `.syara` / `correlation/bundled.rs` (post-13.5a, surface is smaller because simple is gone). Add `context_taxonomy` and `provenance` fields to the rule metadata schema. Update `docs/rule-authoring.md` composite-must-exceed-individual guidance (still true under new scale, with new numeric bounds). Tag 0.6.0.
- **Phase 13.5c — Begin tuning.** Spin up `tasks/RULE_FIXES.md`. Walk `TUNING.md` entry by entry; for each, propose a rule fix that uses the wider scale and (where ready) a `context_taxonomy` annotation. Tag 0.6.x increments per fix batch.

### Open question for 13.5a entry

Before plan-mode for 13.5a, one question worth surfacing: how aggressive on the simple-engine rule migration?

- **Aggressive:** every simple rule must have a YARA equivalent before simple is removed; gaps block the phase.
- **Pragmatic:** migrate what migrates cleanly; gaps get logged as `RULE_FIXES.md` entries to backfill in 13.5c or later. Simple is removed even if a few categories lose coverage temporarily.

The pragmatic option ships faster and matches the user's "tuning at the rule-file layer" preference; the aggressive option preserves coverage. To resolve at 13.5a plan-mode entry.
