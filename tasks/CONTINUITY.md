# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-01 (compact-prep, end of architecture session)

**Branch:** `main`. The post-2026-04-30-compact session resolved the three open architectural questions queued in the previous CONTINUITY (Q1 subprocess, Q2 Phase 13 in lcs, Q3 Phase 14 split), captured the decisions across both repos, then knocked out one quick bug fix. About to compact and dive into Phase 13 planning.

**Working tree at compact time:** uncommitted edits — the bug #3 docstring fix in `src/shield.rs:128` (one-line) and the BUGS.md / CONTINUITY.md updates for it. The rest of the session's bookkeeping (PRD, todo.md, aegis IMPORT-NOTES, aegis TODO) was committed and pushed earlier.

**Test count:** 366/366 (last known good — `cargo check` clean after bug #3). Clippy clean as of last full run.
**Cargo version:** 0.5.3. Installed binary still predates 11.6b. Optional: bump to 0.5.4 + reinstall when convenient.

**Phase status (lcs):**
- Phases 1–11, 11.5a–d, 11.6a–c — **complete**.
- Phase 12 — **transferred to aegis** at `../aegis/` on 2026-04-30.
- Phase 13 (Scan groups) — **confirmed in lcs (2026-05-01); next workstream**.
- Phase 14 (Confidence ensemble) — **confirmed in lcs as single-scan ensemble (2026-05-01)**; aegis owns separate multi-scan layer.

---

## Three architectural decisions (resolved 2026-05-01)

### Q1 — aegis composes lcs via **subprocess**

aegis spawns `lcs`, pipes stdin, parses JSON. Library wrap deferred to a future productized aegis where in-process latency matters. Rationale: UNIX composition, decoupled release cadences, sidesteps lcs's optional-feature combinatorics, matches the contract surface in PRD §6.4.

**Implementation hint for aegis-side:** lcs adapter is one module — spawn → stdin → JSON → typed struct, ~100 LOC, no `lcs` Cargo dep. Versioning via `lcs --version` + rule fingerprint.

### Q2 — Phase 13 stays in lcs

Cross-input correlation reuse via the existing `CorrelationEngine::evaluate` is the load-bearing feature. With subprocess (Q1), keeping 13 in lcs means aegis makes one `lcs scan-group --json` call. **Boundary:** lcs takes a list of paths/strings, returns per-input + aggregate. Anything that *produces* the input list (directory walking, tarball expansion, git plumbing, URL fetching) is aegis territory.

### Q3 — Phase 14 split

lcs owns 14a–14d as scoped (string + similarity + classifier + LLM verdict + correlation evidence types — *no SessionSignal*). aegis owns a separate multi-scan ensemble layer that combines lcs's per-scan `ConfidenceScore` with session-signal evidence. Two ensemble layers, different evidence sets, no shared calibration code.

---

## Next session: Phase 13 plan

Per the task review the user asked for at end-of-session, the chosen next workstream is **Phase 13: Scan groups**. Spec is fully laid out in `tasks/todo.md:206`–`tasks/todo.md:255` with the boundary statement now embedded (added this session as the Q2 resolution).

**Sub-phases to plan:**
- **13a** — `ScanGroup` + `GroupReport` types in new `src/scan_group.rs`. `Shield::scan_group()` method. The novel work is bundling each input's findings as a synthetic `EngineFindings` bucket so the existing `CorrelationEngine::evaluate` produces cross-input correlations for free.
- **13b** — CLI surface. Choice point: `--group` flag on `Command::Scan` vs new `Command::ScanGroup` subcommand. Decide in plan mode based on shell glob composability (the spec defers this).
- **13c** — `examples/batch_scan.rs`, `docs/rule-authoring.md` cross-input correlation note, README "Library Usage" 5-line snippet.

**Constraints from this session's decisions:**
- No persistence, no temporal semantics, no streaming. Single-process one-shot.
- lcs takes paths/strings; no directory walking, tarball expansion, git plumbing, URL fetching.
- Per `feedback_simpler_path.md` (already pinned): bias toward thin shapes — strip helpers, consts, DTOs, soft-fail policies unless a current consumer needs them.
- Per `feedback_one_question_at_a_time.md` (saved this session): when planning surfaces architectural choices (e.g., 13b's flag-vs-subcommand), resolve them sequentially and re-derive each remaining question's framing after a decision lands.

**Prerequisites for the plan:**
- Read `tasks/todo.md` Phase 13 section in full (lines 206–255).
- Re-read `src/correlation/mod.rs` `CorrelationEngine::evaluate` to confirm the `&[EngineFindings]` surface accepts arbitrary bucket count (it does — that's what makes 13's "synthetic per-input bucket" approach free).
- Sentrux scan baseline before planning (check current `quality_signal` and bottleneck dimension; new module risks adding to modularity bottleneck).

**Bug #4 caveat for Phase 14 readiness:** the CrossEngine symmetric-pair doubling bug (`src/correlation/mod.rs:99-142`) currently double-counts composite scores. It would corrupt Phase 14 calibration data if left until later. Recommend fixing between 13 and 14.

---

## Work completed this session

### Bookkeeping (already committed)

Q1/Q2/Q3 decisions captured across both repos:

- `tasks/todo.md` — Phase 13 + 14 "Open question" → "Decision"; Phase 12 transfer-pointer trimmed.
- `PRD.md` — six edits: §3 UC-5 pinned subprocess; §4.3 capabilities table updated; §5.2 dropped stale `ScanSummary` reference; §6.4 added "Integration mode" paragraph; §8 roadmap rows 13/14 updated; §9 changelog 2026-05-01 entry.
- `../aegis/tasks/imports/IMPORT-NOTES.md` — Q1, Q2 marked resolved with rationale; Q3 (types boundary) re-framed under subprocess.
- `../aegis/tasks/TODO.md` — Phase 0 first two bullets struck through with pointers.

### Bug fix (uncommitted at compact time)

- **Bug #3 — RESOLVED.** `src/shield.rs:128` — `ShieldBuilder::engine()` docstring updated from `("simple", "yara")` to `("simple", "yara", "syara")`. One-line. `cargo check --features cli,yara,syara` clean. BUGS.md updated.

### Skill housekeeping

- Reviewed project-local `safe-fetch` SKILL.md against current `src/cli.rs`. **No CLI drift** — every flag and command (`scan -p`, `-o`, `-s`, `-f`, `--disable`, `-e`, `lcs list -e yara`) is accurate.
- Installed (copied) project version to user-global `~/.claude/skills/safe-fetch/SKILL.md`. User-global was older — missing `--disable <rule_name>` row, expanded `-e yara`/`-e syara` descriptions, and the engine-availability fallback note. Now byte-identical.

---

## Memory updates this session

One new feedback memory captured: `feedback_one_question_at_a_time.md`. Lesson: when multiple architectural questions are queued, answer them sequentially and re-derive each remaining question's framing after a decision lands. The Q2 answer would have been miscalled if I'd carried forward the CONTINUITY draft from before Q1 resolved.

`feedback_simpler_path.md` continued to apply throughout (recommended subprocess as the thinner shape; recommended keeping 13 + 14 in lcs as the thinner shape).

---

## Open work after Phase 13

| Track | Item | Priority |
|---|---|---|
| lcs roadmap | Phase 14a–d (single-scan ensemble) | After 13 |
| lcs bug | #4 CrossEngine symmetric-pair doubling | Medium — fix before 14 (would corrupt calibration data) |
| lcs bug | #5 misleading fast-path comment | Low cosmetic |
| lcs bug | #6 redundant severity filter | Low |
| lcs ops | Cargo 0.5.3 → 0.5.4 + reinstall | Trivial |
| lcs backlog | Sentrux modularity bottleneck deeper-dive | Hygiene |
| lcs backlog | Cumulative-scoring inflation (per-pattern-match candidate emission) | Medium |
| lcs backlog | Synonym-aware prescan, multilingual model swap, latency benchmark, threshold-tuning corpus, encrypted bundled rules | Research/hygiene |
| aegis bootstrap | Read imports → draft `PRD.md` → draft `ARCHITECTURE.md` → re-scope phases | Phase 0 (when user pivots to aegis) |

---

## File map

- `tasks/todo.md` — phase plan. 11.5/11.6 green; Phase 12 transferred; Phase 13 next, fully spec'd; Phase 14 split confirmed.
- `tasks/BACKLOG.md` — sentrux deeper-dive entry from 2026-04-28; other research/hygiene items.
- `tasks/BUGS.md` — bugs #4, #5, #6 still open; #1, #2, #3 resolved.
- `tasks/CONTINUITY.md` — this file.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `tasks/SYARA-X-WISHLIST.md` — pre-existing, untouched.
- `tasks/ARCHITECTURE.md`, `tasks/lessons.md` — unchanged this session.
- `~/.claude/plans/humble-dancing-falcon.md` — stale (still holds shipped 11.6b plan). Overwrite when planning Phase 13.
- `~/.claude/skills/safe-fetch/SKILL.md` — updated this session to match project version.
- `PRD.md` — six edits this session (committed).
- `src/shield.rs:128` — bug #3 docstring fix (uncommitted at compact time).
- `../aegis/` — sister project. PRD.md/ARCHITECTURE.md still 1-line stubs by design. `tasks/imports/IMPORT-NOTES.md` and `tasks/TODO.md` updated this session (committed).

---

## Sentrux baseline

Last scan (2026-04-28): `quality_signal = 6630`. Bottleneck: **modularity (4115)**, raw 0.117, with 24/26 cross-module edges. Secondary: equality (5885, raw 0.412).

Phase 13 will add `src/scan_group.rs` — a new module against an already-fragmented module landscape. Run `mcp__plugin_sentrux_sentrux__scan` + `health` before planning 13 (baseline) and after each sub-phase (catch drift).

---

## Sticky reminders for the next session

- **Per CLAUDE.md (lcs)**: run sentrux scan + health after each sub-phase to catch architectural drift early. Watch movement in modularity (current bottleneck) — if 13a's new module pushes it down, re-plan rather than continue.
- **Per CLAUDE.md (aegis-side)** (when that pivot happens): PRD/ARCHITECTURE are derived interactively — don't pre-shape.
- **Per `feedback_simpler_path.md`**: thin shapes for Phase 13. The 13b CLI flag-vs-subcommand call is exactly the kind of choice this principle answers.
- **Per `feedback_one_question_at_a_time.md`**: surface 13's architectural choices as discrete questions; resolve sequentially.
- **Bug #4 is a Phase 14 prerequisite.** Composite-score doubling would corrupt calibration data. Fix between 13 and 14, not after.
