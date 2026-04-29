# Continuity

Session-state notes. Rewritten at session end so the next session can pick up without re-reading the full transcript.

---

## State as of 2026-04-28 (Phase 11.5 + 11.6a + 11.6b shipped, committed, pushed; installed binary predates 11.6b)

**Branch:** `main`, working tree **clean**, **up to date with `origin/main`**. The big uncommitted backlog from the prior session (11.5a/b/c + 11.6a + threat_scores fix + 11.6 spec) all landed as four commits on top of `1bb893a`, all pushed:

```
15cdf54 Simplified the cross engine fingerprinting after discussion.   ← 11.6b
fd5b1b9 bug: lcs 0.5.2 omits threat_scores from the JSON ... Fixed.    ← threat_scores bug fix
75e005c Added missing metadata fields to JSON output.                  ← 11.6a
4bd38ec Restructuring rule handing to be dynamically introspective.    ← 11.5a/b/c bundled
1bb893a Out of band feature request from first consumer app.           ← (was already committed)
```

**Cargo version:** 0.5.3. **Installed binary:** `~/.local/bin/lcs → ~/.local/share/llm_context_shield/lcs-0.5.3`. **Built before 11.6b**, so the installed binary does **not** carry `--all`. To pick that up: `cargo build --release --all-features && cp target/release/lcs ~/.local/share/llm_context_shield/lcs-0.5.4` (with a 0.5.4 version bump) and repoint the symlink. The user did not explicitly ask for this — flag it next session before doing it.

**Test count:** 366/366 (`291 lib + 69 integration + 4 syara_rules + 2 doctests`). Clippy clean under `--features cli,yara,syara --all-targets -- -D warnings`.

**Phase status:**
- Phases 1–11, 11.5a/b/c, 11.6a, 11.6b — **complete + committed + pushed**.
- Phase 11.5d, 11.6c — pending (docs + harness hand-off, no code changes).
- Phases 12, 13, 14 — unchanged, unscheduled.

---

## Phase 11.6b summary — `lcs rules --all` cross-engine view (complete, committed)

**Spec:** `tasks/todo.md` Phase 11.6b (post-checkmark refresh + post-commit). **Commit:** `15cdf54`. **Plan archived:** `~/.claude/plans/humble-dancing-falcon.md` holds the now-shipped thin-shape plan; will be overwritten when 11.6c planning starts.

**Plan-mode story this session.** First plan was over-architected: `BUILTIN_ENGINE_NAMES` const, `try_build_all_engines` helper, `AllEnginesBuild` struct, soft-fail per engine with `errors` map in JSON, deferred unit test for the soft-fail path. User pushback ("most of this bothers me", "the simpler path is almost always preferred") → second-pass plan stripped all of that. Final shipped shape: 3 files touched, 6 integration tests, 5 simpler decisions (D1 build via `engines::build`, D2 cross-engine union for category/threat-class, D3 cross-engine fingerprint distinct by design, D4 hard-fail on engine error, D5 inline `["simple", "syara", "yara"]` slice).

**Spec correction.** The original 11.6b spec bullet on cross-engine fingerprint claimed `--all`'s fingerprint "is the same value as `lcs rules --fingerprint` provided the configured Shield covers the same engine set." User caught that this is wrong — different engine sets hash to different values, so they must differ by design. Fixed in `tasks/todo.md` Phase 11.6b cross-engine-fingerprint bullet (now reads "distinct by design, both valid audit signals at different scopes"). Documentation in 11.6c.

**Net code touched:**
- `src/cli.rs` — `Command::Rules.all: bool` with `conflicts_with = "engine"`. Not in `rules_view` group (combines with `--fingerprint` / `--categories` / `--threat-classes` to switch output shape). Doc-comment updated.
- `src/main.rs` — `if all { ... } else { /* existing per-engine */ }` in the `Command::Rules` handler. Inline `["simple", "syara", "yara"]`, three engines built via `engines::build`, hard-fail on any build error. Sub-mode dispatch: default JSON via `serde_json::json!` (no DTO), `--fingerprint` single-hex-line, `--categories` cross-engine union in `Category::ALL` order, `--threat-classes` lex-sorted `BTreeSet<String>`. New imports: `BTreeMap`, `BTreeSet`, `Category`.
- `tests/integration.rs` — 6 new tests after `scan_json_clean_includes_empty_threat_scores`: `rules_all_long_and_short_flags_match`, `rules_all_default_json_has_fingerprint_and_engines`, `rules_all_engines_keys_are_alphabetical`, `rules_all_with_engine_flag_exits_two`, `rules_all_fingerprint_emits_single_hex_line`, `rules_all_categories_emits_cross_engine_union`. New import `BTreeSet` at file top.

**Behavioural notes / fingerprint values (default config):**
- Per-engine simple fingerprint (`lcs rules --fingerprint`): `4c6cd18ac803ea92cb145a143b6e1629b30ee655e59afa6f60a65f150c11469a` (unchanged from 11.6a).
- Cross-engine combined (`lcs rules --all --fingerprint`): `2851f3adff02be2a9ae2076b7910cae190a707c9cc70812bfe8ee25fc90321eb`. Distinct from any single-engine value by design.
- `engines` JSON keys alphabetical via `BTreeMap` (`simple, syara, yara`).
- `--all --categories` outputs 15 categories in `Category::ALL` declaration order.

---

## What's queued next

**Phase 11.6c — docs + harness hand-off (no new code).** Spec at `tasks/todo.md` Phase 11.6c section. Touchpoints:
- `docs/rule-introspection.md` — needs creating (was seeded in 11.5d, never written). Should cover: `RuleMeta` shape, `lcs rules` CLI surface, fingerprint contract (per-engine vs cross-engine distinction landed in 11.6b), `--all` cross-engine view.
- `docs/rule-authoring.md` — the `version = "..."` meta convention; `threat_level` / `threshold` introspection.
- `shield-harness` hand-off note — `--all` for per-run snapshots in `meta.json`.
- PRD §6.2 — widened `RuleMeta` shape mention.

**User flagged for after Phase 11.6 wraps:** a tree-sitter–based tool to try out. (Tool not named yet; user will introduce it when we get there.)

**Optional housekeeping (not blocking):**
- Bump Cargo to 0.5.4 + rebuild + reinstall to capture `--all` in the installed binary. Confirm with user first.
- BUGS.md #4 (CrossEngine symmetric pair fires twice) and #6 (`Shield::scan` redundant `min_severity` filter) — both still open.
- `install.sh` is broken (looks for `target/release/llm_context_shield`; hardcodes `--features yara`).
- `~/.cargo/bin/lcs` cargo-install stub from earlier mistaken install path. Harmless (shadowed in PATH).

---

## Memory updates this session

- New feedback memory: `feedback_simpler_path.md` ("The simpler path is almost always preferred"). Captured directly from user's pushback on the over-architected 11.6b plan + their explicit phrase. Linked from `MEMORY.md`.

---

## File map (where things live)

- `tasks/todo.md` — phase plan. 11.5/11.6a/11.6b checkmarks all green; 11.5d/11.6c checkmarks open.
- `tasks/BUGS.md` — bug tracker. #4 + #6 still open.
- `tasks/CONTINUITY.md` — this file.
- `tasks/BACKLOG.md`, `tasks/ARCHITECTURE.md`, `tasks/lessons.md` — unchanged.
- `tasks/04-25-2026__todo.md` — pre-truncation archive.
- `~/.claude/plans/humble-dancing-falcon.md` — currently holds the shipped 11.6b thin-shape plan. Stale until overwritten on 11.6c (or whatever's next) planning.
- `PRD.md`, `README.md`, `CLAUDE.md` — unchanged.
