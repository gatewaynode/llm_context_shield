# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-04-30 (compact-prep)

**Branch:** `main`. The user is about to capture this session's work in a commit before compacting. By the time the next session starts, expect the working tree to be **clean** (or close to it), with the new commits visible in `git log`. Two distinct workstreams from this session:

1. **11.5d + 11.6c bundled doc pass** — already committed as `eeacba4 Documentation update before persistence phases.` *before* this session's later work. No action needed.
2. **Phase 12 → aegis transfer** — uncommitted at the moment this note is being written. About to land in two commits (one per repo, since `lcs` and `aegis` are separate `.git` roots).

**Test count:** 366/366 (last known good — no source code changed this session). Clippy clean.
**Cargo version:** 0.5.3. Installed binary still predates 11.6b. Optional: bump to 0.5.4 + reinstall when convenient.

**Phase status (lcs):**
- Phases 1–11, 11.5a–d, 11.6a–c — **complete**.
- Phase 12 (Session-aware scanning) — **TRANSFERRED to aegis** at `../aegis/` on 2026-04-30.
- Phase 13 (Scan groups), Phase 14 (Confidence ensemble) — spec preserved in lcs, but flagged with open questions about whether they also transfer to aegis. **This is the next conversation.**

---

## What's queued: three open architectural questions

The user signalled the next session should pick up here. These are the questions in priority order:

### Q1. Library or subprocess wrap for aegis-over-lcs?

aegis can either depend on `llm_context_shield` as a Cargo crate (calling `Shield` directly) or shell out to `lcs scan --json` per call. Tradeoff:

- **Library**: fast, type-safe, no process spawn cost. Couples aegis releases to lcs releases. Forces aegis to handle lcs's optional-feature combinatorics (`yara`, `syara`, `syara-llm`, etc.).
- **Subprocess**: true UNIX composition. aegis drives whatever `lcs` is on `$PATH`. Lets aegis evolve independently. Loses type safety at boundary; pays JSON parse cost + CLI startup overhead per call (~ms-scale).

The user's "UNIX pattern of small composable apps" framing during the Phase 12 transfer decision suggests bias toward **subprocess**. But that's not a foregone conclusion — library wrap can still respect UNIX composability if aegis exposes its own clean CLI.

This question shapes everything downstream (Q2 and Q3 partly hinge on it).

### Q2. Does Phase 13 (scan groups) also transfer to aegis?

The same argument that drove Phase 12 to aegis applies here: scan groups introduce multi-input collection types and group-level aggregation that are orchestration concerns. Counter-argument: the current Phase 13 spec is intentionally *single-process, one-shot, no persistent state* — that's still UNIX-composable.

If 13 stays in lcs, lcs's contract widens to `lcs scan-group <files...>` or similar. If 13 moves, aegis composes lcs scans into a group locally.

### Q3. Does Phase 14's cross-scan ensemble portion transfer?

Phase 14 is confidence calibration / ensemble scoring across evidence types. The clean split:

- **Single-scan ensemble** (string + similarity + classifier + llm + correlation evidence on one input) — naturally in lcs because it operates on outputs already produced by lcs's engines in one pass.
- **Cross-scan ensemble** (adding session signals from aegis) — naturally in aegis because session signals only exist there.

This split is referenced in lcs's todo.md and PRD already. Decision pending.

---

## Reference material for the discussion

If the user wants to revisit any of the lcs Phase 12 thinking during the q1–q3 conversation, the canonical artifacts are now in aegis:

- `../aegis/tasks/imports/lcs-phase-12-spec.md` — full Phase 12a–d spec.
- `../aegis/tasks/imports/lcs-phase-12-discussions.md` — three-thread architectural discussion (trait shape, privacy, introspection).
- `../aegis/tasks/imports/IMPORT-NOTES.md` — Q1 and Q2 are already enumerated there as "open questions" with deeper notes than this CONTINUITY.

aegis's project skeleton:
- `aegis/CLAUDE.md` — preamble dated and project overview added 2026-04-30.
- `aegis/tasks/TODO.md` — seeded with Phase 0 vision-derivation steps.
- `aegis/PRD.md`, `aegis/ARCHITECTURE.md` — still 1-line stubs, deliberately so (CLAUDE.md says derive interactively).
- `aegis/src/main.rs` — bare 45-byte stub. Untouched.

---

## Memory updates this session

- No new memories. The 2026-04-28 `feedback_simpler_path.md` continued to apply (e.g., bundling 11.5d+11.6c instead of two separate doc passes; tier 1/2/3 scope discipline in the Phase 12 architectural reply).

---

## File map

- `tasks/todo.md` — phase plan. 11.5/11.6 all green; Phase 12 marked transferred to aegis; Phase 13 + 14 carry open questions.
- `tasks/BACKLOG.md` — sentrux deeper-dive entry added this session.
- `tasks/BUGS.md` — #4, #6 still open.
- `tasks/CONTINUITY.md` — this file.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `tasks/SYARA-X-WISHLIST.md` — pre-existing, untouched this session.
- `tasks/ARCHITECTURE.md`, `tasks/lessons.md` — unchanged.
- `~/.claude/plans/humble-dancing-falcon.md` — stale (still holds shipped 11.6b plan). Overwrite next time we plan.
- `PRD.md`, `README.md`, `CLAUDE.md`, `docs/rule-introspection.md`, `docs/rule-authoring.md` — modified (in `eeacba4` for the doc-pass changes; PRD.md has further uncommitted changes from the Phase 12 transfer).
- `../aegis/` — sister project root. PRD/ARCHITECTURE still stubs; `tasks/TODO.md` seeded; `tasks/imports/` holds the three Phase 12 transfer artifacts.

---

## Sentrux baseline

Last scan (2026-04-28, end of doc pass): `quality_signal = 6630`. Bottleneck: **modularity (4115)**, raw 0.117, with 24/26 cross-module edges. Secondary: equality (5885, raw 0.412) — file-size variance, likely driven by `src/main.rs` and large engine files.

Phase 12 transfer doesn't move sentrux on lcs (no code was ever written for it). The BACKLOG entry on the modularity bottleneck stands; revisit with `dsm` + `git_stats` after the q1–q3 discussion settles into a code direction. Run sentrux on aegis as new modules land there.

---

## Sticky reminders for the next session

- **Per CLAUDE.md (aegis-side)**: "Run sentrux scan + health after each sub-phase to catch architectural drift early." This applies to aegis from day one.
- **Per CLAUDE.md (aegis-side)**: PRD/ARCHITECTURE are derived interactively. Don't pre-shape them; let the user steer during the q1–q3 discussion.
- **Per `feedback_simpler_path.md`**: bias toward thin shapes. The library-vs-subprocess decision (Q1) is the perfect place to apply this — both options are valid; pick the thinner one for the first ship.
