# Bugs

Known issues and deferred fixes.

---

## 1. Integer overflow in ThreatScoreboard::record()

**Priority**: High  
**File**: `src/scoring.rs`, line 84-86  
**Found**: Phase 7 review (2026-04-12)

Two accumulation paths have no overflow protection:

1. `class_scores` entry: direct `+= threat_level` on `i32`. In debug builds, overflow panics. In release builds, it wraps silently (2,147,483,647 + 1 becomes -2,147,483,648).
2. Weighted cumulative: `threat_level as f32 * weight` cast back to `i32` and accumulated via `+=`. Same overflow risk, plus `f32` loses precision for values > 2^24.

**Fix**: Use `i32::saturating_add()` for both paths. Zero-cost, clamps at `i32::MAX` instead of panicking or wrapping.

---

## 2. SYARA extract_meta silently swallows parse failures

**Priority**: Medium  
**File**: `src/engines/syara.rs`  
**Found**: Phase 7 review (2026-04-12)

SYARA rules store `threat_level` and `threshold` as quoted strings (e.g., `threat_level = "3"`). The parsing path uses `.parse::<i32>().ok()`, which silently falls back to defaults when the string is malformed (e.g., `threat_level = "not_a_number"`).

YARA's `extract_meta` logs `tracing::warn!` for missing metadata, but SYARA doesn't log when numeric parsing fails — the rule silently gets `threat_level=1, threshold=0`. Rule authors get no feedback that their metadata is being ignored.

**Fix**: Replace `.ok()` with a match that logs `tracing::warn!` on parse failure before falling back to the default.
