# Bugs

Known issues and deferred fixes.

---

## 1. Integer overflow in ThreatScoreboard::record() — RESOLVED

**Priority**: High
**File**: `src/scoring.rs`, line 84-86
**Found**: Phase 7 review (2026-04-12)
**Resolved**: 2026-04-25 — verified `saturating_add()` on both class and cumulative paths (`src/scoring.rs:86,89`).

Two accumulation paths originally had no overflow protection:

1. `class_scores` entry: direct `+= threat_level` on `i32`. In debug builds, overflow panics. In release builds, it wraps silently (2,147,483,647 + 1 becomes -2,147,483,648).
2. Weighted cumulative: `threat_level as f32 * weight` cast back to `i32` and accumulated via `+=`. Same overflow risk, plus `f32` loses precision for values > 2^24.

**Fix**: Used `i32::saturating_add()` for both paths. Zero-cost, clamps at `i32::MAX` instead of panicking or wrapping.

---

## 2. SYARA extract_meta silently swallows parse failures — RESOLVED

**Priority**: Medium
**File**: `src/engines/syara.rs`
**Found**: Phase 7 review (2026-04-12)
**Resolved**: 2026-04-25 — verified `tracing::warn!` on parse failure for both `threat_level` and `threshold` (`src/engines/syara.rs:274-301`).

SYARA rules store `threat_level` and `threshold` as quoted strings (e.g., `threat_level = "3"`). The parsing path used `.parse::<i32>().ok()`, which silently fell back to defaults when the string was malformed.

**Fix**: Replaced `.ok()` with a match that logs `tracing::warn!` on parse failure before falling back to the default.

---

## 3. `ShieldBuilder::engine()` doc string omits `syara` — RESOLVED

**Priority**: Low
**File**: `src/shield.rs:128`
**Found**: 2026-04-25 codebase review
**Resolved**: 2026-05-01 — docstring updated to `("simple", "yara", "syara")` in `src/shield.rs:128`. One-line fix.

---

## 4. CrossEngine correlations fire twice for symmetric category pairs — RESOLVED

**Priority**: Medium
**File**: `src/correlation/mod.rs`, bundled rules in `src/correlation/bundled.rs`
**Found**: 2026-04-25 codebase review
**Resolved**: 2026-05-01 — applied option (a) with a sharper predicate. `CorrelationEngine::evaluate` now suppresses the descending ordering when the rule's two `MatchRef`s describe the *same* constraint (same `category`, same `rule_name_pattern`, same `engine_filter`) under `CrossEngine`. Six bundled `multi_engine_corroboration_*` rules (PI, Jailbreak, InstructionOverride, DataExfiltration, RefusalSuppression, ResponseSteering) all hit this shape — each now fires once per unordered pair of distinct buckets. The full-equality predicate (vs the BUGS.md text's "symmetric category" phrasing) preserves asymmetric same-category rules where the two refs differ by `rule_name_pattern` or `engine_filter`. Tests updated: `correlation/mod.rs::cross_engine_requires_distinct_buckets` and the six `bundled.rs::multi_engine_corroboration_*_fires_across_buckets` cases all flip `out.len() == 2` → `out.len() == 1`.

---

## 5. `input::normalize_unicode_whitespace` fast-path comment is misleading

**Priority**: Low (cosmetic)
**File**: `src/input.rs:53-56`
**Found**: 2026-04-25 codebase review

The comment reads: `// Fast path: skip allocation when the input is pure ASCII.` But the fast-path body is `return input.to_string();` — which *does* allocate a fresh `String`. What's actually skipped is the per-`char` iteration and second `String::with_capacity` in the slow path. The comment mis-describes the optimization.

**Fix**: Reword to `// Fast path: skip the per-char rewrite loop when the input is pure ASCII.` Or, if the goal really is zero-allocation, change the function to return `Cow<'_, str>` and propagate that up through `normalize`.

---

## 6. Redundant severity filter in CLI output path

**Priority**: Low
**File**: `src/shield.rs:67-70` and `src/report.rs:32-36`
**Found**: 2026-04-25 codebase review

`Shield::scan` filters findings by `min_severity` before returning the report (`src/shield.rs:67-70`). `report::output` then filters the *already-filtered* report by another `min_severity` parameter (`src/report.rs:32-36`). In the CLI invocation path, both receive the same threshold from `main.rs:113,130`, so the second filter is a no-op iteration.

The pattern presumably exists so library callers can re-filter at output time with a tighter threshold than was used at scan time. That's defensible, but the dead pass in CLI use is mildly wasteful and the API contract isn't documented anywhere.

**Fix**: Either document the design (output-time filter is for callers who want a tighter view than scan time) and accept the redundancy, or change `report::output` to trust the report's filtering and only filter when the caller passes an explicit override. See task candidate B below.

---

# Task candidates

Larger changes flagged by the 2026-04-25 review. Not bugs; would benefit from their own plan-mode entry.

## A. Reduce Finding cloning in correlation evaluate

**Scope**: `src/correlation/mod.rs:137`, `src/shield.rs:77`. Currently every fired correlation deep-clones both contributing findings, and `Shield::scan` clones the entire filtered findings vector to build the bucket. On scans with many findings and correlations this is measurable; on typical inputs it's noise.

**Why**: Cleanup. No observed regression. M.

## B. Reconcile severity filtering between Shield and output

**Scope**: `src/shield.rs:scan`, `src/report.rs:output`, `src/main.rs`. Decide whether output-time re-filtering is the contract or vestigial; document or remove. S.

## C. Resolve CrossEngine symmetric-pair semantics (bug 4) — DONE 2026-05-01

Resolved as part of Phase 13 prep. See bug #4 entry above.

## D. Extract `DEFAULT_PROXIMITY_WINDOW` constant

**Scope**: `src/correlation/bundled.rs`, `src/shield.rs:165`, `src/config.rs:114` doc, `src/correlation/bundled.rs:36`. Currently the value 500 appears inline in code, in a docstring, and in a config default. Centralize as `pub const DEFAULT_PROXIMITY_WINDOW: usize = 500;`. S.

## E. Capture lessons in `tasks/lessons.md`

**Scope**: `tasks/lessons.md`. The file exists as a stub but has no entries; the CLAUDE.md workflow leans on it heavily. Either backfill the two resolved bugs above as lessons (overflow → `saturating_add` everywhere; silent metadata parse → log-then-default everywhere) or remove the workflow's reliance on it. S.
