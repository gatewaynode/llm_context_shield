# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-01

**Branch:** `main`. The post-2026-04-30-compact session resolved the three open architectural questions queued in the previous CONTINUITY. The user is about to capture this session's bookkeeping edits in a commit.

**Test count:** 366/366 (last known good — no source code touched this session). Clippy clean.
**Cargo version:** 0.5.3. Installed binary still predates 11.6b. Optional: bump to 0.5.4 + reinstall when convenient.

**Phase status (lcs):**
- Phases 1–11, 11.5a–d, 11.6a–c — **complete**.
- Phase 12 — **transferred to aegis** at `../aegis/` on 2026-04-30.
- Phase 13 (Scan groups) — **confirmed in lcs (2026-05-01)**, ready to plan.
- Phase 14 (Confidence ensemble) — **confirmed in lcs as single-scan ensemble (2026-05-01)**; aegis owns a separate multi-scan ensemble layer.

---

## Three architectural decisions resolved 2026-05-01

### Q1 — aegis composes lcs via **subprocess** (not library)

aegis spawns `lcs` and parses JSON. Library option deferred to a future productized aegis. Rationale: UNIX composition, decoupled release cadences, sidesteps lcs's optional-feature combinatorics, matches the contracts already pinned in PRD §6.4. Cost (~ms CLI startup + JSON parse per call) is noise for session-aware orchestration where one scan = one user turn.

**Implementation hint for aegis-side:** lcs adapter is one module — spawn → stdin → JSON → typed struct, ~100 LOC, no `lcs` Cargo dep. Versioning via `lcs --version` + rule fingerprint, not `^x.y` Cargo constraint.

### Q2 — Phase 13 stays in lcs

Cross-input correlation reuse via the existing `CorrelationEngine::evaluate` is the load-bearing feature. With subprocess (Q1), keeping 13 in lcs means aegis makes one `lcs scan-group --json` call and gets per-input + aggregate. Moving 13 to aegis would force either N spawns + a new `lcs correlate-only` CLI, or duplicating correlation logic.

**Boundary:** lcs takes a list of paths/strings, returns per-input + aggregate. Anything that *produces* the input list — directory walking, tarball expansion, git plumbing, URL fetching — is aegis territory. No persistence, no temporal semantics, no streaming.

### Q3 — Phase 14 split: single-scan ensemble in lcs, multi-scan ensemble in aegis

lcs owns 14a–14d as scoped (string + similarity + classifier + LLM verdict + correlation evidence types). Calibration functions live where the raw scores are produced. aegis owns a *separate* multi-scan ensemble layer that combines lcs's per-scan `ConfidenceScore` with session-signal evidence. Two ensemble layers, different evidence sets, no shared calibration code. The aegis layer is designed when aegis's PRD lands.

**The clean handoff statement:** lcs returns calibrated per-scan confidence for the evidence it produced. aegis combines lcs's per-scan confidence with session-signal evidence to produce session-aware confidence.

---

## What's queued: pick the next workstream

The architecture conversation is settled. The natural next moves, in order of independence:

1. **Plan Phase 13 in lcs.** All inputs ready. Spec at `tasks/todo.md` §Phase 13. Single-process, one-shot, reuses existing `CorrelationEngine` — the smallest concrete next chunk.
2. **Plan Phase 14a in lcs.** `ConfidenceScore` struct + `EvidenceType` enum (no `SessionSignal`) + module wiring. Larger surface than 13.
3. **Drive aegis's PRD/ARCHITECTURE derivation interactively.** Per `aegis/CLAUDE.md`, both files are still 1-line stubs by design. Open questions Q3–Q6 in `aegis/tasks/imports/IMPORT-NOTES.md` need answers (types boundary, session semantics, encryption/multi-tenancy threat model, bundled rule format).

The user may want to alternate: ship Phase 13 in lcs (tightens the JSON contract aegis will compose against), then start aegis's PRD with that contract concrete. Or ship 13 + 14 first to get the full lcs JSON shape stable, then do aegis. User's call when the next session starts.

---

## Bookkeeping completed this session (uncommitted at note time)

Four files updated to reflect the Q1/Q2/Q3 decisions. No code changes.

- `tasks/todo.md` — Phase 13 "Open question" paragraph → "Decision" paragraph; Phase 14 same; Phase 12 transfer-pointer line trimmed (open questions list).
- `PRD.md` — six edits: §3 UC-5 pinned subprocess (was "library or subprocess"); §4.3 capabilities table updated (Session tracking marked ↗️ aegis; Phase 13 row tightened with 2026-05-01 confirmation; Phase 14 row scoped to *single-scan* with multi-scan layer noted as aegis); §5.2 dropped stale `ScanSummary` (Phase 12) reference; §6.4 added "Integration mode" paragraph pinning subprocess composition with rationale; §8 roadmap rows 13/14 updated; §9 changelog gained a 2026-05-01 entry.
- `../aegis/tasks/imports/IMPORT-NOTES.md` — open questions 1 and 2 marked resolved with full rationale and an implementation hint for the lcs adapter; question 3 (types boundary) re-framed under the subprocess decision.
- `../aegis/tasks/TODO.md` — Phase 0 first two bullets struck through with resolution pointers into IMPORT-NOTES.md.

---

## Memory updates this session

One new feedback memory captured: `feedback_one_question_at_a_time.md`. The user's lesson: when multiple architectural questions are queued, answer them sequentially and re-derive each remaining question's framing after a decision lands — don't carry forward pre-baked recommendations from before the upstream call. (Q2's answer would have been miscalled if I'd stuck with my CONTINUITY draft from before Q1 resolved.)

`feedback_simpler_path.md` continued to apply throughout (recommended subprocess as the thinner shape; recommended keeping 13 and 14 in lcs as the thinner shape).

---

## File map

- `tasks/todo.md` — phase plan. 11.5/11.6 green; Phase 12 transferred; Phase 13/14 confirmed in lcs.
- `tasks/BACKLOG.md` — sentrux deeper-dive entry from 2026-04-28 still standing.
- `tasks/BUGS.md` — #4, #6 still open.
- `tasks/CONTINUITY.md` — this file.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `tasks/SYARA-X-WISHLIST.md` — pre-existing, untouched this session.
- `tasks/ARCHITECTURE.md`, `tasks/lessons.md` — unchanged.
- `~/.claude/plans/humble-dancing-falcon.md` — stale (still holds shipped 11.6b plan). Overwrite next time we plan.
- `PRD.md` — §8 roadmap + §9 changelog modified this session.
- `../aegis/` — sister project. PRD.md/ARCHITECTURE.md still stubs by design. `tasks/imports/IMPORT-NOTES.md` and `tasks/TODO.md` updated this session with Q1/Q2 resolutions.

---

## Sentrux baseline

Last scan (2026-04-28): `quality_signal = 6630`. Bottleneck: **modularity (4115)**. No code touched this session, so no movement. Run sentrux on aegis as new modules land. Re-baseline lcs after Phase 13 lands.

---

## Sticky reminders for the next session

- **Per CLAUDE.md (lcs)**: run sentrux scan + health after each sub-phase to catch architectural drift early.
- **Per CLAUDE.md (aegis-side)**: PRD/ARCHITECTURE are derived interactively — don't pre-shape them; let the user steer.
- **Per `feedback_simpler_path.md`**: bias toward thin shapes. Both Phase 13 and Phase 14 plans should strip helpers, consts, DTOs, soft-fail policies unless a current consumer needs them.
- **Per `feedback_one_question_at_a_time.md` (new this session)**: when planning Phase 13 or 14, surface architectural choices as discrete questions and resolve them sequentially. Don't pre-bake combined recommendations.
