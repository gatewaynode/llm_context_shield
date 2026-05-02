# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-05-02 (compact-prep, end of Phase 13b session)

**Branch:** `main`. Phase 13b shipped (CLI surface for `scan-group`); also added two dataflow docs and a new feedback memory. Working tree has uncommitted changes — **user will commit after the compact**.

**Test count:** 384/384 (was 378 pre-13b). Clippy clean with `--features cli,yara,syara`.
**Cargo version:** still 0.5.3. Installed binary still predates current head. Optional bump.

**Phase status (lcs):**
- Phases 1–11, 11.5a–d, 11.6a–c — **complete**.
- Phase 12 — **transferred to aegis** at `../aegis/` on 2026-04-30.
- Phase 13a (Scan-group types + `Shield::scan_group`) — **complete 2026-05-01**.
- Phase 13b (CLI surface) — **complete 2026-05-02**.
- Phase 13c (docs + example) — **next workstream** (or skip to Phase 14 if user prefers).
- Phase 14a–d (single-scan ensemble) — after 13.

**Sentrux:** quality_signal 6615 (was 6626 before 13b). Drift −11. Modularity 4077 (was 4115, raw 0.111). Equality 5789 (was 5861, raw 0.421). Well within the ~6300 watch threshold.

---

## Phase 13b — what shipped

**`src/cli.rs`:** new `Command::ScanGroup` variant. Positional `files: Vec<PathBuf>` (`required=true, num_args=1..`), plus `format`/`severity`/`disable`/`engine`/`threat_scores`/`correlations`/`show_fingerprint` carried over from `Scan`, plus `--max-inputs <N>` (default 1000). Excludes `safe_only_passthrough`/`output` (D9 — multi-input passthrough has no coherent semantics).

**`src/main.rs`:** new handler arm at line 167. Mirrors `Command::Scan`'s config-merge + severity/format validation, then enforces `--max-inputs` *before* any I/O (D8: shell-glob fail-fast), opens a `tracing::info_span!("scan_group", ...)`, builds the Shield, constructs the `ScanGroup` (rebinding in the loop because `add_file` consumes self), calls `shield.scan_group()`, dispatches by format. Exit 0 if all clean and no cross-input correlations; 1 if any findings or any cross-input fire; 2 on error.

**`src/report.rs`:** three new helpers.
- `render_scan_report_json(report, min_severity, include_fingerprint)` — extracted from `output()`. Existing single-scan JSON path now routes through this. Two consumers now (D4).
- `render_group_json(group, min_severity)` — top-level group JSON document. Lifts fingerprint to top level (all per-input share it), embeds each per-input `ScanReport` via `render_scan_report_json(... false)`.
- `output_group_text(group, scores, correlations, fingerprint)` — text emission. Per-input headers + correlations to stderr, aggregate scoreboard to stderr (under `--threat-scores`), cross-input correlation detail to stderr (under `--correlations`), summary line to stdout. Mirrors single-scan stderr-details / stdout-summary split.

**`tests/integration.rs`:** `TempFiles` RAII fixture (Drop-based cleanup, per-test pid+name+index isolation) + six new tests. All passing:
- `scan_group_clean_batch_exits_zero`
- `scan_group_mixed_batch_exits_one_per_input_distinguishes`
- `scan_group_cross_input_multi_engine_corroboration_fires_once` (validates bug #4 at CLI level)
- `scan_group_max_inputs_rejects_oversized_batch`
- `scan_group_quiet_mode_clean_exits_zero`
- `scan_group_json_top_level_shape`

**`tasks/todo.md`:** Phase 13a and 13b checkboxes flipped to `[x]` with completion-date headers and detailed bullet summaries of what shipped vs. what was deferred (`[scan_group]` config section deferred per D2; `enable_cross_input_correlation` not added because `correlation.enabled = false` already covers it).

Decisions enacted (recorded for 13c context):
- **D1.** New subcommand `Command::ScanGroup`, not a `--group` flag on `Scan`. User: "I prefer extra subcommand over excessive options."
- **D2.** `--max-inputs <N>` is a CLI flag, default 1000. No `[scan_group]` config section. Per `feedback_simpler_path.md`.
- **D3.** Synthetic engine label `"input:<label>"` (enacted in 13a) bleeds into JSON output. User signed off in 13a.
- **D4.** `render_scan_report_json` extracted because two consumers exist (single-scan + scan-group). Drift risk would be real otherwise.
- **D5.** Scan-group handler stays inline in main.rs (~110 lines added, total main.rs ~460, under 500 threshold). Defer extraction speculation per `feedback_simpler_path.md`.
- **D6.** Raw path-as-label. `add_file` uses `path.to_string_lossy()`; CLI passes `PathBuf` through unchanged.
- **D7.** No stdin sentinel (`lcs scan-group -` not supported). Required positional with `num_args=1..` rejects empty invocation.
- **D8.** `--max-inputs` enforced before any I/O.
- **D9.** No passthrough mode for scan-group.
- **D10.** Tracing parity with single-scan (`scan_group` span shape mirrors `scan`).

---

## Also this session: dataflow docs + new feedback memory

**`docs/scan-data-flow-simple.md`** (NEW, 141 lines). Renamed from `scan-data-flow.md`. Single-scan walkthrough for `lcs scan -p`: mermaid `flowchart TD` at top with file:line refs in node labels, numbered steps with letter sub-points, exit-code table, variations table, "Key invariants" section (normalize is the only mutation, severity filter runs twice by design, the `-p` two-stream contract).

**`docs/scan-group-data-flow-simple.md`** (NEW, 265 lines). Companion walkthrough for `lcs scan-group A.txt B.txt -f json`. Cross-references `scan-data-flow-simple.md` at unchanged steps; focuses on what scan-group *adds*: the per-input loop, the aggregate-scoreboard-with-weight-inheritance pattern (clone first non-empty + merge rest, no double-weighting), the cross-input pass with synthetic `"input:<label>"` engine bucketing, the lex-tie-break worst-offender, the bug #4 canonicalization invariant, the no-passthrough decision.

**`~/.claude/projects/-Users-john-code-llm-context-shield/memory/feedback_dataflow_docs.md`** (NEW). Captures the format as a feedback memory so future sessions default to writing `docs/<feature>-data-flow.md` for any "walk me through X" request rather than answering chat-only. Format spec:
1. Mermaid `flowchart TD` at top with file:line refs in node labels.
2. Numbered walkthrough; sub-points use **A.**, **B.**, **C.** letters; each sub-point cites file:line.
3. Tables for exit codes + variations.
4. "Key invariants" section at the end with gotchas.
5. For features built on top of others, cross-reference rather than duplicate.

`MEMORY.md` index line added. Note: this memory is project-scoped (lcs only). If the same default is wanted in aegis or elsewhere, copy the file into that project's memory dir when working there.

---

## Working tree at session end

Uncommitted changes (user will commit after compact):

```
 M src/cli.rs
 M src/main.rs
 M src/report.rs
 M tasks/todo.md
 M tests/integration.rs
?? docs/scan-data-flow-simple.md
?? docs/scan-group-data-flow-simple.md
?? tasks/TUNING.md          ← NOT from this session; user-created earlier on 2026-05-02 (05:40)
```

`tasks/TUNING.md` is a real-world rule-tuning notebook the user created externally before this session started — leave it as untracked unless user pulls it into the commit explicitly.

This `tasks/CONTINUITY.md` rewrite is the only change made *after* the working-tree snapshot was taken; will appear as ` M tasks/CONTINUITY.md` once written.

---

## Next session: Phase 13c plan (preview)

Spec at `tasks/todo.md:249-254`. Three deliverables:

1. **`examples/batch_scan.rs`** — minimal end-to-end demo of `Shield::scan_group` from a directory of files, showing the `GroupReport` shape. Should compile under `cargo build --examples`. Reference the new `docs/scan-group-data-flow-simple.md` for the conceptual map.
2. **`docs/rule-authoring.md`** — short note that the existing `CrossEngine` correlation type doubles as cross-input correlation in scan-group mode. Cross-link to `docs/scan-group-data-flow-simple.md` rather than re-explaining.
3. **README "Library Usage"** — 5-line `Shield::scan_group` snippet alongside the existing `Shield::scan` example.

Plus a few orphan items flagged for 13c-or-later:
- **PRD §6.4** — note that cross-input correlation findings carry `engine: "input:<label>"` (D3).
- **`docs/scan-data-flow.md` index** — consider a small `docs/README.md` or a section in the main README that lists the dataflow docs (will grow as more features get the treatment).
- **Cargo bump 0.5.3 → 0.5.4** + `cargo install --path .` to refresh the binary.

If user prefers to skip 13c and jump to Phase 14 (single-scan ensemble), 13c can defer indefinitely — the load-bearing surface (CLI + library API) is shipped.

---

## Open work after Phase 13b

| Track | Item | Priority |
|---|---|---|
| lcs roadmap | Phase 13c (examples/, docs polish, PRD §6.4 note) | After this compact |
| lcs roadmap | Phase 14a–d (single-scan ensemble / ConfidenceScore) | After 13c (or skip 13c) |
| lcs bug | #5 misleading fast-path comment | Low cosmetic |
| lcs bug | #6 redundant severity filter | Low (acknowledged in `docs/scan-data-flow-simple.md` invariants section as "by design") |
| lcs ops | Cargo 0.5.3 → 0.5.4 + reinstall | Trivial |
| lcs hygiene | `tasks/TUNING.md` integration into rule-authoring workflow | User-driven |
| lcs backlog | Sentrux modularity bottleneck deeper-dive | Hygiene |
| lcs backlog | Cumulative-scoring inflation | Medium |
| lcs backlog | Synonym-aware prescan, multilingual model swap, latency benchmark, threshold-tuning corpus, encrypted bundled rules | Research/hygiene |
| aegis bootstrap | Read imports → draft `PRD.md` → draft `ARCHITECTURE.md` → re-scope phases | Phase 0 (when user pivots to aegis) |

---

## File map

- `tasks/todo.md` — phase plan. Phases 13a/13b marked DONE; 13c spec at lines 249-254 is the read-target for next session.
- `tasks/BUGS.md` — #1, #2, #3, #4 resolved. #5, #6 still open.
- `tasks/CONTINUITY.md` — this file.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `tasks/SYARA-X-WISHLIST.md` — pre-existing, untouched.
- `tasks/TUNING.md` — NEW (user-created externally on 2026-05-02). Real-world rule-tuning notebook.
- `tasks/ARCHITECTURE.md`, `tasks/lessons.md` — unchanged this session.
- `tasks/BACKLOG.md` — unchanged.
- `~/.claude/plans/humble-dancing-falcon.md` — current 13b plan (just shipped). Overwrite when planning 13c.
- `docs/scan-data-flow-simple.md` — NEW. Single-scan dataflow walkthrough.
- `docs/scan-group-data-flow-simple.md` — NEW. Scan-group dataflow walkthrough.
- `docs/rule-authoring.md` — needs 13c update (cross-input correlation note).
- `docs/rule-introspection.md`, `docs/migration-from-simple.md`, `docs/semantic-rules.md` — untouched.
- `PRD.md` — needs 13c update (§6.4 `engine: "input:<label>"` provenance).
- `src/scan_group.rs` — unchanged this session (13a's API still complete).
- `src/scoring.rs`, `src/shield.rs`, `src/correlation/*` — unchanged this session.
- `src/cli.rs`, `src/main.rs`, `src/report.rs`, `tests/integration.rs` — modified by 13b.
- `~/.claude/projects/-Users-john-code-llm-context-shield/memory/feedback_dataflow_docs.md` — NEW.
- `~/.claude/projects/-Users-john-code-llm-context-shield/memory/MEMORY.md` — index line added.
- `../aegis/` — sister project. Untouched this session.

---

## Memory state

- **NEW:** `feedback_dataflow_docs.md` — for "walk me through X" / dataflow / command-trace requests, default to writing `docs/<feature>-data-flow.md` with mermaid + numbered walkthrough + invariants. Project-scoped to lcs.
- `feedback_simpler_path.md` — drove D2 (no `[scan_group]` config), D5 (no premature handler extraction).
- `feedback_one_question_at_a_time.md` — drove Q4 surfacing as a discrete question before plan-mode entry.
- `project_yarax.md`, `project_syara.md` — context for engine bucket labels in cross-input correlation tests.
- `feedback_quote_seeding.md` — not triggered this session.

---

## Sticky reminders for the next session

- **User will commit the working tree first.** Don't pre-empt: the next session opens with a clean working tree assumed (or the user may have staged/split the commit). Read `git status` before assuming anything.
- **Per `feedback_dataflow_docs.md`:** any "walk me through X" / dataflow request → write `docs/<feature>-data-flow.md` by default. Cross-reference simpler docs rather than duplicating content.
- **Per CLAUDE.md:** plan-mode for 13c before any code (it's three deliverables — examples, docs, README — borderline trivial but worth a quick plan). Sentrux scan + health post-13c.
- **Per `feedback_simpler_path.md`:** thin shape for 13c. The README "Library Usage" snippet is 5 lines, not a tutorial. The rule-authoring note is a paragraph + cross-link, not a section. The example should be one self-contained ~30-line `main()`, not a framework.
- **Per `feedback_one_question_at_a_time.md`:** if 13c surfaces architectural choices (e.g., "should the example use the bundled rules or a custom config?"), surface them sequentially before the plan.
- **Spec quirks unchanged from 13b:** `ScanReport` is intentionally not `Serialize`; build per-scan JSON via `render_scan_report_json`. `MatchCorrelation` is `Serialize`-derived. `ThreatScoreboard` is `Serialize`-derived.
- **Bug #4 is fixed and validated end-to-end at the CLI level.** Phase 14 calibration concerns are resolved.

---

## Sentrux baseline

Last scan (2026-05-02, post-13b): `quality_signal = 6615`. Bottleneck: **modularity (4077)**, raw 0.111, with 26 cross-module edges (was 24 before 13b — the `report.rs ↔ scan_group.rs` import added in 13b accounts for the bump). Secondary: equality (5789, raw 0.421).

Drift since 13a baseline (qs 6626): −11. Within phase-completion noise. If 13c adds substantial cross-module wiring, watch for modularity drift below ~3800 or qs drift below ~6300.
