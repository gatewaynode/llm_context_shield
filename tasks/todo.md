# Project TODO

Phased implementation plan for YARA-X and SYARA-X engine integration.
See `tasks/ARCHITECTURE.md` for full design and diagrams.

---

## Phase 11.5: Loaded-rule introspection

Expose the **currently loaded rule set** of a built `Shield` instance — categories, threat classes, per-rule metadata, plus a fingerprint that audit-trails the exact rule set active at scan time. Wire that provenance into individual findings so every emitted finding can be traced back to the rule that fired it.

**Reframing — two priors that drive the design.**

*Priori 1: External consumers (programmatic and human) cannot see anything about the rules inside `lcs`.* `lcs list` exposes rule **names** only; the JSON output exposes categories but no rule provenance per finding. A harness can't validate sidecar categories programmatically; a human reading a finding can't tell which rule fired without string-matching the description.

*Priori 2: The rule set is highly mutable from outside `lcs` — even `lcs` itself only knows what's loaded into the running engine instance.* Bundled rules are compiled in. YARA / SYARA rules are discovered from `[rules] dir` (XDG default or config override). Custom correlation rules load from `[correlation] custom_rules`. Future hot-reload, custom engines (PRD §6.2), and per-deployment overrides extend this further. Two `lcs 0.5.0` installs against the same input can emit different findings. The binary version alone cannot answer "what was the active rule set for this scan?"

**Implications.**

- Schema is **per-instance**, not per-binary. `lcs rules` (the new surface) must consume the same `Config` flow as `lcs scan` — same `[rules] dir`, same `disable` list, same `custom_rules` path. Otherwise validators check schema X while runs use schema Y.
- The audit trail needs a **rule-set fingerprint**, not just `lcs --version`. A hash over the sorted `(engine_name, RuleMeta)` set lets the harness record "run R used this exact rule set" and detect drift between runs.
- The category vocabulary is the only **bounded** vocabulary (15-variant enum). Rule names and threat classes are inherently unbounded under Priori 2 — anyone can mint a new threat class via custom rule metadata. The introspection surface should be honest about this asymmetry: categories enumerate statically, rule names and threat classes only enumerate against the running instance.
- Priori 1 implicates **findings output too**, not just a separate schema query. Widen `Finding` with `rule_name` and `engine` so the schema query and the per-finding provenance describe the same rule set from two angles.

**Scope.** Engine-level introspection (YARA, SYARA, simple), CLI `lcs rules` surface, rule-set fingerprint plumbed through `ScanReport`, `Finding` widened with rule provenance. **Correlation and session rules deferred** — they need a different mutability story (likely YAML reformat, hot-reload contract) and will adopt the same introspection pattern when their phases land. Seeded as forward references in 11.5d.

### 11.5a — `Engine::rule_metadata` and rule-set fingerprint

**✅ Complete (uncommitted on top of `1bb893a`).** 335/335 tests pass at 11.5a freeze; canonical post-mortem in `tasks/CONTINUITY.md` "Phase 11.5a progress". Note: `RuleMeta` derives `Serialize, Clone, Debug, PartialEq, Eq` — `Hash` was dropped from the spec because the fingerprint hashes canonical JSON rather than sorting `Hash` outputs (deterministic across rustc updates, more auditable). `Engine::build` warns on zero loaded rules; the hard `ShieldError::NoRulesLoaded` lives at `ShieldBuilder::build` per the architectural-decision log.

- [x] Add `RuleMeta` struct in `src/engines/mod.rs`:
  - `name: String` — rule name, matching `Engine::rule_names()`.
  - `category: Category` — category emitted when this rule fires.
  - `severity: Option<Severity>` — when statically determinable from rule metadata; `None` for rules whose severity is decided at match time (document the convention in 11.5d).
  - `threat_class: String` — scoreboard class string (defaults to `category.to_string()` when not overridden in rule metadata).
  - Derive `Serialize`, `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash` (the last two so the fingerprint computation can sort and hash deterministically).
- [x] Extend `Engine` trait with `fn rule_metadata(&self) -> Vec<RuleMeta>`:
  - **Default impl** returns `Vec::new()` — preserves source compatibility for custom engines (PRD §6.2). Custom engines opt in by overriding.
  - `SimpleEngine`: walk `scanners::build(&[])`, emit one `RuleMeta` per active scanner. `category` from the scanner; `threat_class` from `category.to_string()`; `severity` left `None` (regex scanners assign per-pattern severity at match time).
  - `YaraEngine`: walk loaded `Rules`, run existing `extract_meta` per rule, build `RuleMeta`. The data already exists — this is a reshape, not new parsing.
  - `SyaraEngine`: same as yara via its `extract_meta`.
- [x] Default-impl helpers on `Engine`:
  - `fn categories(&self) -> BTreeSet<Category>` — derived from `rule_metadata`.
  - `fn threat_classes(&self) -> BTreeSet<String>` — derived from `rule_metadata`.
- [x] Extend `Category` with `pub const ALL: &[Category]` — enumerate without instantiating an engine. Order is the existing enum declaration order.
- [x] Add `RuleSetFingerprint` (newtype around `String`, hex-encoded SHA-256):
  - Computed by collecting every loaded engine's `rule_metadata()`, sorting tuples of `(engine_name, RuleMeta)` deterministically by `(engine_name, name)`, serialising to a stable canonical form, hashing.
  - One combined fingerprint covers the whole `Shield` instance. Per-engine breakdown can be added non-breakingly later if real audit needs surface it.
  - Add `sha2` dependency (mature, widely used, satisfies CLAUDE.md N-1 and 30-day-minimum stance).
- [x] Add `rule_set_fingerprint: RuleSetFingerprint` to `ScanReport` — populated by `Shield::scan` from the configured engine. Empty-string-fingerprint sentinel for the rare case of an engine with zero loaded rules; document the sentinel.
- [x] Unit tests:
  - `SimpleEngine::categories()` returns the 6 simple-scanner categories.
  - `YaraEngine::categories()` (feature-gated) matches the bundled yara rule set's declared categories.
  - `Engine::rule_metadata().iter().map(|r| &r.name).eq(Engine::rule_names().iter())` — order and names align.
  - `Category::ALL.len() == 15`, every variant present, declaration order preserved.
  - Fingerprint determinism — two `Shield` instances built from identical config produce identical fingerprints; mutating one rule's metadata changes the fingerprint.

### 11.5b — `lcs rules` CLI surface

**✅ Complete (uncommitted).** 344/344 tests at 11.5b freeze; post-mortem in `tasks/CONTINUITY.md` "Phase 11.5b summary". `Command::Rules` uses clap `group = "rules_view"` for mutual-exclusion of `--categories | --threat-classes | --json | --fingerprint`. `Shield::engine()` accessor added to expose the resolved engine to the rules handler. `--show-fingerprint` is a flag on `Command::Scan` (text path); JSON path always emits `rule_set_fingerprint`.

- [x] New subcommand `lcs rules [-e <engine>] [--categories | --threat-classes | --json] [--fingerprint]`:
  - **`lcs rules`** (no flags): print every loaded rule, one per line, formatted as `<engine>:<rule_name>  [<category>]`. Default human-friendly view.
  - **`--categories`**: print the category set the configured shield can emit, snake_case, one per line. Without `-e`, the union across all loaded engines; with `-e`, that engine's subset.
  - **`--threat-classes`**: same shape but threat classes.
  - **`--json`**: emit `{"fingerprint": "<hex>", "rules": [<RuleMeta+engine>...]}`. Scoped by `-e` if provided.
  - **`--fingerprint`**: print just the rule-set fingerprint as a single hex line. Cheap audit-trail capture for shell scripts.
- [x] **Config flow consistency**: `lcs rules` constructs the same `Shield` that `lcs scan` would (same `Config` load path, same `--config` overrides, same `[rules] dir`, same `[correlation] custom_rules`). The whole point of Priori 2 is that schema is a property of the configured instance — `lcs rules` cannot bypass that flow without lying.
- [x] Output ordering: deterministic. Rules sorted by `(engine, name)`. Categories follow `Category::ALL` declaration order.
- [x] Exit codes: `0` on success, `2` on unrecognised engine or config error (matches existing `lcs list -e <bad>` behaviour).
- [x] Embed fingerprint in scan output too:
  - JSON: top-level `"rule_set_fingerprint": "<hex>"` on every `lcs scan` output.
  - Text: optional, gated behind `--show-fingerprint` flag (off by default — keeps human output uncluttered).
- [x] Integration tests in `tests/integration.rs`:
  - `lcs rules` lists loaded rules with engine prefix.
  - `lcs rules --categories` returns the union of loaded engines' categories.
  - `lcs rules --categories -e simple` returns the 6-category simple subset.
  - `lcs rules --json` parses as `{fingerprint, rules}` with the right shape.
  - `lcs rules --fingerprint` returns a single 64-char hex line.
  - `lcs rules` and `lcs scan` emit the same fingerprint for the same config.
  - `lcs rules -e bogus` exits 2.

### 11.5c — Finding provenance: rule_name + engine on Finding

**✅ Complete (uncommitted).** 350/350 tests at 11.5c freeze; post-mortem in `tasks/CONTINUITY.md` "Phase 11.5c summary". `Finding::new` keeps its existing signature; new fields default to empty-string and the `with_rule_name` / `with_engine` builders chain on. The text output emits an indented `rule: <name> (engine: <eng>)` line in the per-finding stderr block, but only when `rule_name` is non-empty (preserves shape for legacy / custom-engine fixtures). `MatchCorrelation` propagation is automatic — its `Vec<Finding>` carries the widened fields without code change; verified by the new `correlation_propagates_finding_provenance` test.

The harness can validate categories against `lcs rules`, but per-finding traceability still requires string-matching the description. Widening `Finding` closes Priori 1 at the per-result level.

- [x] Add to `Finding` (`src/scanner.rs:106`):
  - `rule_name: String` — the rule that fired (matches `RuleMeta.name`).
  - `engine: String` — the engine that produced this finding (matches `EngineFindings.engine`).
- [x] Update construction sites:
  - `RegexScanner::scan` — pass scanner name as `rule_name`; engine is `"simple"` (or `Finding::new` takes it from a constructor parameter; design choice in plan-mode).
  - `YaraEngine` — already iterates rules, plumb `rule.identifier()` and `"yara"` through.
  - `SyaraEngine` — same with `"syara"`.
  - Custom engines using `Finding::new` get a sensible default or are required to populate (the trait default keeps source compatibility, but JSON output will surface empty strings; document).
- [x] JSON output: additive — every existing field stays; `rule_name` and `engine` are new fields per finding. No consumer that reads `category` / `severity` / `description` breaks.
- [x] Text output: include `rule_name` in the per-finding stderr block, optional in summary. Decide formatting in plan-mode.
- [x] Update existing tests in `src/scanner.rs`, `src/engines/yara.rs`, `src/engines/syara.rs`, `tests/integration.rs` to assert the new fields are populated and consistent with `Engine::rule_metadata()`.
- [x] Update `MatchCorrelation` carriers — they hold `Vec<Finding>` already, so the widened fields propagate without further work; just verify the JSON output of correlations now includes per-contributing-finding rule provenance.

### 11.5d — Documentation, hand-offs, and forward seeding

**✅ Complete (bundled with 11.6c).** Doc pass merged with 11.6c since both phases targeted the same files (rule-introspection.md was created here, not "updated" by 11.6c — the file didn't exist yet). One coherent doc covers identity (11.5d) + scoring metadata (11.6a) + cross-engine view (11.6b). Phase 12b session-rule introspection seed deferred — the upcoming Phase 12 architecture discussion will produce the actual design, so a pre-emptive checkbox would be wasted ink.

- [x] Update README "Scanner Categories" table to mark it as **informational** and point readers at `lcs rules --categories` for the programmatic source of truth scoped to their actual install.
- [x] Add `docs/rule-introspection.md` covering: the `RuleMeta` shape; the `lcs rules` CLI surface and flag combinations; the fingerprint contract (what it covers, what it doesn't, when it changes); the per-instance vs per-binary distinction.
- [x] Add a section to `docs/rule-authoring.md` explaining how `category`, `severity`, and `threat_class` rule metadata feed into `Engine::rule_metadata()` and through to `lcs rules` — relevant for custom YARA / SYARA rule authors.
- [x] Update PRD §6.2 (Library embedding contract): mention `Engine::rule_metadata()`, the fingerprint, and the default-impl-empty contract for source compatibility.
- [x] Resolve OOB request — marked "External request from `shield-harness`" below as **Resolved** with a back-reference to Phase 11.5/11.6. The harness wires `--check-lcs-categories` to call `lcs rules --categories -e <engine>` and records the per-run fingerprint in `meta.json`.
- [x] Phase 14 hand-off: Phase 14a's evidence-attribution design now references `Engine::rule_metadata()` for per-rule provenance and the rule-set fingerprint as part of the calibration audit trail (see hand-off note in 14a).
- [x] **Forward seeding for correlation-rule introspection** — note added to Phase 13 entry below (when correlation rules grow a mutable format, they must adopt the same introspection pattern declared in 11.5).
- [~] **Forward seeding for session-rule introspection** — **deferred.** The upcoming Phase 12 architecture discussion will design the introspection contract live rather than carrying a checkbox forward. Reason: Phase 12 was about to be planned in the same session; pre-seeding a design for a phase about to be designed is unnecessary friction.

**Non-goals for Phase 11.5**:
- No checked-in `schema.json` artifact — `lcs rules --json` is the per-instance source of truth; a static file would lie under Priori 2.
- No correlation-rule introspection in 11.5 — deferred per scope above. The seed lives in 11.5d so the next phase that touches correlation rules picks it up.
- No session-rule introspection in 11.5 — Phase 12 owns it, with the seed planted in 11.5d.
- No version-stamping inside the rule payload itself — `lcs --version` plus the fingerprint is the audit pair. Fingerprint changes are the substantive signal; version is the binary identity.
- No fingerprint of the **input** — only of the rule set. The harness owns input fingerprinting in its sidecar metadata.

---

## Phase 11.6: Extended rule introspection — version/threat_level/threshold + cross-engine `--all`

Phase 11.5 surfaced rule **identity** (name, category, severity, threat_class) and a rule-set fingerprint. Phase 11.6 extends the introspection surface along two axes:

1. **Per-rule scoring metadata** — add `version`, `threat_level`, and `threshold` to `RuleMeta` and the `lcs rules --json` output. Today consumers asking "what does this rule contribute to the scoreboard?" or "what version of this rule am I running?" still have to read source. Surfacing the scoring trio aligns introspection with what the scorer actually uses at scan time and gives audit pipelines a per-rule version stamp that complements the rule-set fingerprint.
2. **Cross-engine view** — `lcs rules -a / --all` emits a single JSON document covering every built-in engine (simple, yara, syara) so an external consumer can capture the full per-instance picture without invoking `lcs rules` three times. Same `Config` flow as today's `-e`-scoped path (each engine is constructed identically, just collected into one report).

**Reframing.** Per 11.5 Priori 2, schema is per-instance. `--all` describes the union of engines **as currently configured** (XDG rules dir, custom_rules, disabled list) — not a static "everything that ships." The combined fingerprint already reported by `lcs rules --fingerprint` continues to be the single audit value; `--all` is the structural companion to that scalar.

### 11.6a — Extend `RuleMeta` with version/threat_level/threshold

**✅ Complete (uncommitted; ships as `lcs 0.5.2` globally installed 2026-04-26).** 359/359 tests at 11.6a freeze (was 350; +9 new — 3 fingerprint sensitivity, 2 yara round-trip + defaults, 2 syara round-trip + defaults, 1 simple defaults, 1 integration JSON shape). Clippy clean. New default-config fingerprint `4c6cd18ac803ea92cb145a143b6e1629b30ee655e59afa6f60a65f150c11469a` (was `2d7806f7…1751e5d3`); the change is the desired audit signal, see fingerprint contract below. Per the 11.6a plan-mode discovery, **the bundled rule-edit pass was dropped**: every YARA + SYARA rule already declared `version`, `threat_level`, and `threshold` in its `meta:` block (audited by counting meta-key occurrences vs. rule count across all 32 files). Existing values (`"1"` and `"2"`) round-trip into `RuleMeta.version` as-is — no rule files modified by this phase.

- [x] Add three fields to `RuleMeta` (`src/engines/mod.rs`):
  - `version: Option<String>` — `Some("...")` when the rule's metadata declares it, `None` otherwise. Convention is semver but the field is opaque to lcs (string round-trip only).
  - `threat_level: i32` — what one match contributes to the rule's `threat_class` score. Default `1` (matches `ThreatMeta::with_defaults`).
  - `threshold: i32` — minimum accumulated class score required for the rule to fire. Default `0` (always-fire).
- [x] Update introspection construction sites:
  - `SimpleEngine::rule_metadata` — `version = None`, `threat_level = 1`, `threshold = 0` for every regex scanner. Document: simple-engine rules are compiled in; per-rule version is meaningless.
  - `YaraEngine::extract_rule_meta` — extend `ParsedYaraMeta` to capture `version`; reshape so introspection reads `version`/`threat_level`/`threshold` from the same `parse_meta` output the scan-time `extract_meta` uses. Single parsing path.
  - `SyaraEngine::build_rule_metadata` — extend `parse_source_meta` similarly so introspection and scan-time both project from one parser.
- [x] ~~Bundled rule edits (one line each):~~ **Dropped — every bundled rule already declares `version`, `threat_level`, and `threshold`** (audit during plan-mode confirmed 79 rules across 32 files, all complete). Existing values (`"1"`, `"2"`) preserved verbatim. Author convention to be captured in 11.6c docs against the existing meta shape.
- [x] Fingerprint contract: the new fields participate in the canonical-JSON sort fed to `RuleSetFingerprint::compute`. Bumping `threshold` in any rule changes the fingerprint — that is the desired behaviour (audit trails should be sensitive to scoring-metadata changes, not just identity).
- [x] JSON shape (`lcs rules --json` and `lcs scan`-side per-finding payload remain stable): `RuleMeta` gains three additive keys. No existing consumer breaks; `version` is `null` for SimpleEngine and any rule that didn't opt in.
- [x] Text shape (`lcs rules` default view): unchanged — keeps the human view minimal. Authors who want the full picture pipe through `--json`.
- [x] Unit tests:
  - YARA + SYARA rules with explicit `version`/`threat_level`/`threshold` round-trip into `RuleMeta`.
  - Defaults: rules without these meta keys produce `version: None`, `threat_level: 1`, `threshold: 0`.
  - `SimpleEngine::rule_metadata` always emits the documented defaults.
  - Fingerprint sensitivity: mutating `threshold` (or adding/removing a `version` key) on any rule changes the fingerprint.

### 11.6b — `lcs rules --all`

**✅ Complete (uncommitted).** 366/366 tests at 11.6b freeze (was 360; +6 integration). Clippy clean. Plan-mode chose the thin shape — hard-fail per D4, inline engine names per D5, no `BUILTIN_ENGINE_NAMES` const, no `try_build_all_engines` helper, no `errors` map in JSON. Architecturally: walk three names, build via `engines::build`, dispatch on view flags. Cross-engine fingerprint confirmed distinct from per-engine (`2851f3adff02be2a9ae2076b7910cae190a707c9cc70812bfe8ee25fc90321eb` vs default-config simple `4c6cd18a…11469a`).

- [x] Add `--all` (`-a`) flag to `Command::Rules` (`src/cli.rs`): `conflicts_with = "engine"`, **not** in `rules_view` group — combines with `--fingerprint` / `--categories` / `--threat-classes` to switch the cross-engine output shape.
- [x] Default `--all` JSON shape: `{"fingerprint": "<cross-engine hex>", "engines": {"simple": [...], "syara": [...], "yara": [...]}}`. No `errors` map (hard-fail per D4). Keys alphabetical via `BTreeMap`.
- [x] Engine construction in `--all` mode: each of `simple`, `syara`, `yara` is built from the same loaded `Config` via `engines::build` directly (bypasses `Shield::builder()` to avoid correlation-rule loading we don't use). The configured `[scan] engine` is ignored.
- [x] Error handling: hard-fail on any engine build error (D4 chose this over the soft-fail+errors-map proposed in the original spec). Realistic failure modes are config errors that already hard-fail in the per-engine path; mirroring keeps `--all` predictable. If a consumer ever requests partial output, add `--strict`-style flags then.
- [x] Cross-engine fingerprint: `compute_fingerprint(&[("simple", &m1), ("syara", &m2), ("yara", &m3)])`. Distinct from any per-engine `lcs rules --fingerprint` by design. Documentation in 11.6c.
- [x] Integration tests (6 new in `tests/integration.rs`):
  - `rules_all_long_and_short_flags_match` — `--all` and `-a` byte-identical.
  - `rules_all_default_json_has_fingerprint_and_engines` — JSON shape + per-rule keys (`engine`, `name`, `category`, `version`, `threat_level`, `threshold`); all three engine arrays non-empty under `cli,yara,syara` features.
  - `rules_all_engines_keys_are_alphabetical` — regression-proofs the `BTreeMap` choice.
  - `rules_all_with_engine_flag_exits_two` — clap mutual-exclusion error + exit 2.
  - `rules_all_fingerprint_emits_single_hex_line` — single 64-char lowercase hex line.
  - `rules_all_categories_emits_cross_engine_union` — superset of `rules --categories -e simple`.

### 11.6c — Documentation and harness hand-off

**✅ Complete (bundled with 11.5d as one doc pass).** No code changes. `docs/rule-introspection.md` was created (not updated — 11.5d never shipped it). Per-field section on `version` / `threat_level` / `threshold` lives in the `RuleMeta` shape table; `--all` cross-engine view has its own section with sample JSON and the per-engine vs cross-engine fingerprint distinction. `rule-authoring.md` gained a "How metadata feeds introspection" subsection cross-linking to the new doc. PRD §6.2 paragraph mentions `Engine::rule_metadata()`, the fingerprint, the default-impl-empty contract, and the widened `RuleMeta` shape. README "Scanner Categories" marked informational and points at `lcs rules --categories`. OOB shield-harness request below marked Resolved with `meta.json` per-run snapshot guidance.

- [x] Add `docs/rule-introspection.md` (was: update — file didn't exist yet):
  - Per-field section on `version` / `threat_level` / `threshold` (semantics, defaults, fingerprint participation).
  - "Cross-engine view (`--all`)" section with sample JSON and the configured-engine vs `--all` distinction.
- [x] Update `docs/rule-authoring.md`:
  - `version = "..."` meta convention noted in the introspection cross-link section.
  - `threat_level` / `threshold` introspection mention — fingerprint participation called out for authors.
- [x] Update `shield-harness` hand-off — `--all --json` snapshot for per-run `meta.json` covered in the OOB Resolved section below; `meta.json` can now snapshot per-rule `version` + `threshold` alongside the fingerprint, pinpointing recall regressions caused by metadata edits.
- [x] Update PRD §6.2 (Library embedding contract) to reflect the widened `RuleMeta` shape and the introspection surface.

**Non-goals for Phase 11.6**:
- No version-bump enforcement — `version` is opaque metadata; lcs does not warn or refuse when authors leave the field unchanged across edits.
- No per-engine fingerprint — the existing combined fingerprint stays; `--all` reports the same single value.
- No CLI shape change to `--json` for `-e <engine>` — that path stays as-is. Cross-engine view is exclusively under `--all`.
- No write / edit / template surface — `lcs rules --all` is read-only introspection. Authoring still happens in `.yar` / `.syara` source files.
- No correlation-rule or session-rule introspection — those still live behind the 11.5d forward seeds for future phases. `--all` covers built-in scan engines only.

---

## Phase 12: Session-aware scanning — TRANSFERRED TO AEGIS (2026-04-30)

**Status:** removed from lcs scope. Session-aware scanning was transferred to a separate orchestrator project (`../aegis/`) on 2026-04-30 to keep lcs UNIX-composable as a single-shot scanner. The full Phase 12 spec, the architectural discussion, and the open questions for the new project live at:

- `../aegis/tasks/imports/lcs-phase-12-spec.md` (verbatim copy of the original Phase 12a–d spec)
- `../aegis/tasks/imports/lcs-phase-12-discussions.md` (verbatim copy of the trait-shape / privacy / introspection discussion)
- `../aegis/tasks/imports/IMPORT-NOTES.md` (open questions for the next aegis session — Q1 library-vs-subprocess and Q2 Phase 13/14 placement resolved 2026-05-01; Q3–Q6 still open)

**Implications for lcs.** lcs's contract is now firmly: read input, emit findings, exit. No session state, no cross-scan memory, no temporal pattern detection. Anything that needed `Shield::scan_with_session` or `SessionStore` is aegis's problem. The introspection surface shipped in Phase 11.5 / 11.6 (`lcs rules --all --json`, `lcs rules --all --fingerprint`) is the contract aegis composes against.

---

## Phase 13: Scan groups

Add a one-shot, *orderless* multi-input scanning surface. A scan group is a related set of inputs (multi-file batch, prompt-history snapshot, ingested document corpus) processed in a single invocation. The group has no temporal semantics — there is no "first" or "last" input, no crescendo, no expiry. The output is per-input results plus group-level aggregations: combined threat scoreboard, cross-input correlations, worst-offender summary.

**Scope boundary.** Phase 13 covers *orderless snapshots*. *Temporal sessions* (per-user state across requests, crescendo detection) were the original Phase 12 — transferred to the aegis orchestrator project on 2026-04-30 (see Phase 12 marker above). See [PRD.md](../PRD.md) UC-3 for the use-case framing.

**Decision (2026-05-01).** Phase 13 stays in lcs. With aegis composing lcs via subprocess (Q1 decided 2026-05-01), the load-bearing feature of Phase 13 — cross-input correlation reuse via the existing `CorrelationEngine::evaluate` — is best served by a single `lcs scan-group --json` subprocess call returning per-input + aggregate. Moving 13 to aegis would force either N spawns + a new `lcs correlate-only` CLI surface, or duplicating correlation logic across two repos. **Boundary:** lcs takes a list of paths/strings, returns per-input + aggregate. Anything that *produces* the input list — directory walking, tarball expansion, git plumbing, URL fetching — is aegis territory. No persistence, no temporal semantics, no streaming.

Phase 13 is intentionally smaller than the original Phase 12 — it reuses the existing single-scan and correlation infrastructure rather than introducing new abstractions. The novel surface is the input-collection type, the group-level report, and the choice to bucket per-input findings into the existing correlation evaluator (which already accepts `&[EngineFindings]`) so cross-input correlation falls out for free.

**Forward seed from Phase 11.5 (rule introspection):** if Phase 13 reshapes the correlation-rule loader (TOML → YAML, hot-reload, etc.), the new format must adopt the introspection pattern from 11.5 from day one — declarative metadata, contribute to a fingerprint when loaded, surface through a CLI view (`lcs correlations` or `lcs rules --kind=correlation`). No second-pass retrofit; design the contract before shipping.

### 13a — `ScanGroup` and `GroupReport` types — **DONE 2026-05-01**

- [x] Create new module `src/scan_group.rs`:
  - `pub struct ScanGroup` — collection of `(label: String, input: String)` pairs. Builder-ish API: `ScanGroup::new()`, `.add(label, input)`, `.add_file(path) -> io::Result<Self>` convenience (chainable; consumes self).
  - `pub struct GroupReport`:
    - `per_input: Vec<(String, ScanReport)>` — per-input results, label-keyed.
    - `aggregate_scoreboard: ThreatScoreboard` — class scores summed across all inputs (via new `ThreatScoreboard::merge`; first non-empty per-input scoreboard cloned as the seed so config weights inherit without double-application).
    - `cross_input_correlations: Vec<MatchCorrelation>` — correlations that fired across distinct inputs (each input becomes a separate `EngineFindings` bucket with synthetic engine name `"input:<label>"`).
    - `summary: GroupSummary` — total findings, distinct threat classes, worst-offender (lex-earlier label wins on cumulative ties).
- [x] Extend `Shield`: `Shield::scan_group(&self, group: &ScanGroup) -> GroupReport`. Cross-input pass filters to `CorrelationType::CrossEngine` (only constraint that generalises across distinct inputs); skipped if fewer than two inputs have findings.
- [x] Add `pub mod scan_group;` to `src/lib.rs` and re-export `ScanGroup`, `GroupReport`, `GroupSummary`.
- [x] Unit tests (11 passing): empty group, single-input parity, multi-input distinguishes, cross-input MEC fires once (validates bug #4 fix), cross-input proximate doesn't fire, scoreboard aggregation, worst-offender lex tie-break, synthetic engine label preservation.

### 13b — CLI surface — **DONE 2026-05-02**

- [x] New subcommand `lcs scan-group <files>...` (D1: subcommand path chosen over `--group` flag — divergent output shape, no positional conflict with `Command::Scan`'s `Option<PathBuf>`).
- [x] Output formats:
  - `text`: per-input summary blocks → stderr; aggregate (under `--threat-scores`) → stderr; cross-input correlations (under `--correlations`) → stderr; summary line → stdout. Mirrors single-scan stderr-details / stdout-summary split.
  - `json`: top-level `rule_set_fingerprint` + `per_input: [{label, report}]` + `aggregate_scoreboard` + `cross_input_correlations` + `summary`. Per-input `report` shape matches single-scan `lcs scan --json` (via shared `render_scan_report_json` helper) minus the fingerprint, which is lifted to the top.
  - `quiet`: exit code only (0 if all clean and no cross-input correlations; 1 if findings or cross-input fire; 2 on error).
- [x] `--max-inputs <N>` CLI flag, default 1000. Enforced before any I/O. **No `[scan_group]` config section** — D2 deferred per `feedback_simpler_path.md`; the CLI flag is the thinner shape.
- [x] `enable_cross_input_correlation` not added — `correlation.enabled = false` already disables all correlation flow, including cross-input.
- [x] Integration tests (6 passing): clean batch, mixed batch with per-input distinction, cross-input MEC fires once, max-inputs guardrail rejects oversized batch, quiet mode exit codes, JSON top-level shape validation.
- [x] Helpers: `render_scan_report_json(report, min_severity, include_fingerprint)`, `render_group_json(group, min_severity)`, `output_group_text(group, scores, correlations, fingerprint)` in `src/report.rs`. Single-scan `output()` routed through the shared per-scan helper.

### 13c — Library docs and example ✅ Complete (2026-05-02)

- [x] New `examples/batch_scan.rs` showing `ScanGroup` construction from a directory of files, `Shield::scan_group` invocation, and printing the `GroupReport`.
- [x] Extend `docs/rule-authoring.md` with a short note that the existing `CrossEngine` correlation type doubles as cross-input correlation in scan-group mode.
- [x] Update README "Library Usage" section with a 5-line `Shield::scan_group` snippet.

**Shipped 2026-05-02:**
- `examples/batch_scan.rs` (~70 lines) — accepts a path arg; file → group of 1; directory → non-recursive read with dotfile + null-byte-binary skip; empty after filtering → exit 2 with clear error. Binary detection is a null-byte sniff in the first 8 KiB with a stub comment marking the future binary-analysis hook (per user direction).
- `docs/rule-authoring.md:283` — corrected the now-obsolete "Currently dormant" sentence on `cross_engine` to describe scan-group activation, with a cross-link to `docs/scan-group-data-flow-simple.md`.
- `README.md` — appended a 13-line `Shield::scan_group` snippet after the existing scan example, with a pointer to `examples/batch_scan.rs`.
- `PRD.md` §4.3 — Scan groups row flipped from 📅 Roadmap to ✅ Shipped; description folds in the `engine: "input:<label>"` provenance note.
- `Cargo.toml` — version 0.5.3 → 0.5.4. Local binary refreshed via `cargo install --path .` (the `~/.local/bin/lcs` distribution build is managed by the user separately and is out of scope for `cargo install`).
- Verification: 384/384 tests pass, clippy clean, sentrux quality_signal 6615 (no drift from 13b baseline — examples are excluded from the module graph). Manual smoke against `/tmp/lcs_batch/` confirmed the mixed-dir, single-file, and nonexistent-path code paths.

**Non-goals for Phase 13**: no persistence (a group is a one-shot in-memory aggregation), no cross-process state (use Phase 12 sessions for that), no temporal rules (the order of inputs in a group is meaningless), no `Shield::builder().scan_groups_enabled` flag (the feature is always available; the cost is paid only when `scan_group` is called).

---

## Phase 14: Confidence calibration and ensemble scoring

Replace the current integer-accumulator threat scoring with calibrated probability estimates that combine evidence from string matches, semantic similarity, LLM verdicts, correlation findings, and session analysis into a unified confidence score. This is the orchestrator's job because it combines signals from multiple engines and analysis layers that no single engine can see.

Phase 7's `ThreatScoreboard` continues to work as-is for integer-based threshold gating. This phase adds a parallel probability-based scoring track that sits on top.

### 14a — Confidence model

- [ ] Design `ConfidenceScore` struct in `src/confidence.rs` (new module):
  - `probability`: f64 (0.0–1.0) — calibrated probability that the input contains the indicated threat
  - `evidence`: Vec of (source, raw_score, calibrated_score) tuples — audit trail showing how each piece of evidence contributed
  - `threat_class`: String — what class of threat this probability represents
- [ ] Design `EvidenceType` enum: `StringMatch`, `Similarity`, `Classifier`, `LlmVerdict`, `Correlation`. (Originally included `SessionSignal`; that evidence source moved to aegis along with Phase 12 on 2026-04-30. If lcs Phase 14 ships as in-crate ensemble scoring, sessions are not an evidence input. If aegis ends up owning ensemble scoring instead, the variant returns there with a different shape.)
- [ ] Add `pub mod confidence` to `src/lib.rs`
- [ ] Unit tests for score construction and display

**Hand-off from Phase 11.5/11.6 (introspection):** the `evidence` audit trail should consume `Engine::rule_metadata()` for per-rule provenance — `(rule_name, engine, version, threat_level, threshold)` per evidence entry, not just `(source, raw_score, calibrated_score)`. The rule-set fingerprint (`Shield::rule_set_fingerprint()`) should be recorded once per `ConfidenceScore` (or once per scan in the `ScanReport`-level wrapper) so a calibration audit trail can attribute each calibrated probability to a specific rule-set state. When calibration parameters drift across deployments, the fingerprint is the join key that ties an evidence entry back to the rule version that produced it.

**Decision (2026-05-01).** lcs owns single-scan ensemble (this Phase 14, all sub-phases as scoped). aegis owns a *separate* multi-scan ensemble layer that combines lcs's per-scan `ConfidenceScore` with session-signal evidence, designed when aegis's PRD lands. Two ensemble layers, different evidence sets, no shared calibration code. Calibration functions live where the raw scores are produced: string `threat_level` integers, similarity cosine values, LLM verdict shapes, and correlation `composite_threat_level` are all lcs-internal; session-signal calibration is aegis-internal. The subprocess JSON contract (Q1 decided 2026-05-01) widens cleanly: `lcs scan --json` grows a `confidence` field; aegis parses it and folds in session-signal calibration on top.

### 14b — Calibration functions

Map raw scores from each evidence type to calibrated probabilities.

- [ ] Implement `CalibrationConfig` struct:
  - Per-evidence-type calibration parameters (slope, intercept for logistic calibration, or isotonic regression lookup table)
  - Default parameters: string match = 0.85 base (high precision), similarity = logistic mapping from cosine score, LLM = 0.75 base (known imprecision), correlation = configurable boost
- [ ] Implement calibration functions:
  - `calibrate_string_match(threat_level) -> f64` — map integer threat_level to probability
  - `calibrate_similarity(cosine_score, threshold) -> f64` — logistic curve mapping similarity to probability
  - `calibrate_llm_verdict(is_match, explanation) -> f64` — binary with confidence discount
  - `calibrate_correlation(composite_threat_level, correlation_type) -> f64` — compound evidence boost
  - `calibrate_session_signal(pattern_type, frequency) -> f64` — session-level confidence
- [ ] Add `[confidence]` section to `Config` / `DEFAULT_CONFIG` with default calibration parameters
- [ ] Provide a `lcs calibrate` subcommand (future) that accepts a labeled dataset and outputs tuned parameters
- [ ] Unit tests: verify calibration curves are monotonic, boundary values are correct, default parameters produce reasonable outputs

### 14c — Ensemble combiner

Combine calibrated evidence into per-class and overall threat probabilities.

- [ ] Implement `EnsembleCombiner`:
  - Input: Vec of `(EvidenceType, calibrated_probability, threat_class)` from all sources
  - Output: per-class `ConfidenceScore` + overall `ConfidenceScore`
  - Combination method: configurable — default is **noisy-OR** (P_combined = 1 - product of (1 - p_i)) which models independent evidence sources
  - Alternative: weighted average, max, or Bayesian update (configurable in `[confidence]` config)
  - Per-evidence-type weights: configurable multipliers that scale each evidence type's contribution before combination
- [ ] Wire into scan pipeline: after all findings, correlations, and session analysis are complete, run the ensemble combiner
- [ ] Add `confidence_scores` field to `ScanReport`: per-class probabilities + overall probability
- [ ] Decision thresholds: configurable in `[confidence]` config — `flag_threshold` (default 0.5), `block_threshold` (default 0.9) — allows consumers to make risk-appropriate decisions
- [ ] Unit tests: noisy-OR arithmetic, weight scaling, independence assumption verification, degenerate cases (no evidence, single evidence, conflicting evidence)

### 14d — Output and API surface

- [ ] JSON output: include `"confidence"` key with per-class and overall probabilities, evidence audit trail
- [ ] Text output: one-line confidence summary — `"Threat confidence: prompt_hijack=0.92, social_engineering=0.34, overall=0.94"`
- [ ] Add `--confidence` flag to show detailed confidence breakdown
- [ ] Extend `Shield` API: `ScanResult` includes `.confidence()` accessor returning the ensemble scores
- [ ] Document confidence scoring in `docs/confidence-scoring.md` — what the numbers mean, how to tune thresholds for different use cases (high-security vs. user-facing), how to provide calibration data
- [ ] Update `docs/rule-authoring.md` — explain how rule threat_level values feed into the calibration pipeline

### Future (out of scope for Phase 11–14)

- **Online calibration** — update calibration parameters in real-time as labeled feedback arrives; requires a feedback loop API
- **Per-deployment calibration profiles** — different calibration curves for different deployment contexts (chatbot vs. RAG pipeline vs. agent system)
- **Confidence-based routing** — use confidence scores to decide which downstream action to take (allow / flag for review / block) at the orchestrator level rather than relying on exit codes
- **Adversarial robustness testing** — systematically test whether an attacker can craft inputs that produce low confidence scores despite containing real attacks

### Future (deferred from Phase 11d — correlation extensions)

Captured 2026-04-25 during 11d planning. All marked "out of scope" in the 11d plan but worth revisiting once the core correlation surface has settled.

- **Multi-engine `Shield` orchestration** — today's `Shield` holds one engine. Multi-engine support (Shield holds `Vec<Box<dyn Engine>>`, runs each, evaluator gets one bucket per engine) lights up the 6 `CrossEngine` bundled rules that currently ship forward-compat-only. Likely a Phase 14+ chunk because it touches engine lifecycle, config (engine list), and CLI (engine override semantics).
- **N-ary correlations** — current `CorrelationEngine` enforces `match_refs.len() == 2`. Some attack patterns naturally decompose into 3-way or 4-way constraints (e.g. context-shift + delimiter-spoof + payload). Add an N-ary evaluation path; the bundled catalog would gain at least one true 3-way rule (combined setup-payload with delimiter spoofing).
- **Widening `Finding` with engine identity / rule_name** — every D-decision so far has resisted this. If `rule_name_pattern` becomes load-bearing for custom correlations or multi-engine attribution drifts past description-matching, add `engine: String` and `rule_name: String` fields to `Finding` directly. Plan migration carefully (JSON shape change).
- **Per-correlation finding-back-references in JSON** — currently each `MatchCorrelation` serializes its full contributing `Finding`s. For large reports an index-based reference scheme (`"finding_indices": [0, 4]` pointing into the top-level `findings` array) would shrink output. Worth doing only if real-world reports hit size pain.
- **Custom rule hot-reload** — load custom correlation rules at process start only today. A file-watcher or config-reload signal would let long-running embeddings (server mode, future Phase 12+ session work) pick up rule changes without restart.
- **Custom rule discovery directory** — mirror the YARA/SYARA pattern (XDG data dir for bundled, config dir override) for correlation rules. Today only the explicit `[correlation] custom_rules = "..."` path loads.
- **Per-rule disable for correlations** — extend the existing `--disable` flag (today scoped to scanner / engine rule names) to recognise correlation rule names. Useful when a bundled correlation rule produces too many false positives in a specific deployment.
- **Composite scoring via class weights** — composite_threat_level values are hard-coded in the bundled catalog. Surface them through `[scoring.class_weights]` so users can tune the relative weight of `sandwich_attack`, `multi_engine_corroboration`, etc. without forking.

---

## Housekeeping: test coverage gaps

Test coverage gaps identified during Phase 7 review (2026-04-12). Not bugs — the code is correct, but these paths lack direct test verification.

- [ ] Add SYARA threat field parsing tests — mirror `extract_meta_parses_threat_fields` and `extract_meta_defaults_threat_fields` from `src/engines/yara.rs` into `src/engines/syara.rs` for the string-based parsing path
- [ ] Add `SimpleEngine::run_scored()` unit test — call `run_scored()` on known-bad input, assert `ThreatScoreboard` has non-zero class scores and cumulative
- [ ] Add integration test with adversarial scoring config — extreme weights, NaN, negative values; verify validation clamps correctly
- [ ] Add input size limit test — verify `read_input` rejects files and stdin exceeding 100 MiB cap

---

# Out of Band Feature Requests

## External request from `shield-harness`: expose the category vocabulary distinct from rule names

**✅ Resolved (2026-04-28, Phase 11.5 + 11.6).** The introspection surface that landed across Phase 11.5a–c (rule identity + fingerprint), 11.6a (extended `RuleMeta`), 11.6b (cross-engine `--all`), and 11.6c (docs) covers and exceeds the original ask:

- **Category vocabulary by engine:** `lcs rules --categories -e <engine>` prints one snake-case category name per line — exactly the typo-catcher shape the harness wanted. `lcs rules --all --categories` prints the cross-engine union for matrix runs.
- **Per-run snapshot for `meta.json`:** the harness can persist `lcs rules --all --json` (or `--all --fingerprint` for just the scalar) once per run. The fingerprint is sensitive to per-rule `threshold` / `threat_level` / `version` edits, so a recall regression caused by a metadata bump pinpoints in seconds — no need to diff the whole rule set. See [`docs/rule-introspection.md`](../docs/rule-introspection.md) for the full contract.
- **Threat-class vocabulary:** bonus surface — `lcs rules --threat-classes [-e <engine>]` and `lcs rules --all --threat-classes` enumerate the unbounded threat-class strings. Useful if the harness ever wants to validate against `expected_threat_classes` sidecar fields too.

The harness should switch `--check-lcs-categories` from its non-blocking notice mode to real validation, calling `lcs rules --categories -e <engine>` per engine and `lcs rules --all --categories` for cross-engine sidecar checks. Record `lcs rules --all --fingerprint` in `meta.json` per scan run; pair with `lcs --version` for the full audit pair.

---

**Captured:** 2026-04-25 — surfaced during Phase 2 design of the external benchmarking harness (`../shield-harness`).
**Filed by:** harness consumer; `shield-harness/tasks/CONTINUITY.md` references this entry.

### Context

The harness owns a labelled corpus where each sample's sidecar declares an `expected_categories: Vec<String>` field that should match the JSON `findings[].category` values lcs emits during a scan. To validate sidecars at corpus-load time, the harness wants to ask lcs *"what is the legal set of category names?"* and refuse sidecars referencing a category lcs doesn't know about — a typo-catcher that fails fast at validate-time instead of producing silent zero-recall buckets in the metrics report after a full run.

### Problem

`lcs list` (and `lcs list -e <engine>`) returns **rule names**, not categories. Concretely:

- `lcs list` (default = simple) → 6 lines: `prompt_injection`, `instruction_override`, `jailbreak`, `delimiter_manipulation`, `data_exfiltration`, `hidden_content`. These happen to coincide with category names because the simple engine's rule set is one rule per category.
- `lcs list -e yara` → 34 lines like `prompt_injection_critical`, `prompt_injection_high`, `prompt_injection_identity`, …  Three distinct rule names that all map to the single category `prompt_injection` in `findings[].category`.
- `lcs list -e syara` → 40 lines (same as yara plus 6 `semantic_*` rules), still rule names.

The README's "Scanner Categories" table documents 15 categories, but that documentation isn't programmatically queryable, and the actual category set varies by engine (simple emits 6; yara/syara add more via richer rule sets that map back to the broader taxonomy).

### What the harness would use

Two reasonable shapes (pick whichever fits the existing CLI grammar better):

- `lcs list --categories [-e <engine>]` — augments the existing `list` subcommand. Without `-e`, prints the full canonical taxonomy. With `-e`, prints the subset that engine can emit. One name per line, same shape as today's rule-name output.
- `lcs categories [-e <engine>]` — standalone subcommand alongside `scan`/`init`/`list`/`help`. Same output semantics as above.

Per-engine scoping is the more valuable form because it lets the harness flag a sidecar that claims `expected_categories = ["context_shift"]` while only ever being run against the `simple` engine (which doesn't emit that category) — a different class of error than a typo.

### Why it matters for the harness

A typo'd category in a sidecar produces a 0% recall bucket in the metrics report rather than an error at corpus-load. Catching the typo at validate-time saves operator time and keeps the metrics report clean. The harness can also use the per-engine view to surface "this sample's expected categories are unreachable on this engine matrix" warnings before the run starts.

### Workaround in shield-harness today

The validator's `--check-lcs-categories` flag is wired but emits a non-blocking notice referencing this request. Real validation is deferred until lcs grows the API. Sidecars treat `expected_categories` as free-form strings; metric buckets surface typos as zero-recall after a full run.

### Suggested next step

Scope decision: standalone subcommand vs. flag on existing `list`. The data is structurally present already — every bundled rule has a category metadata field — so the work is wiring up a CLI surface and a thin aggregation pass. Likely a small phase, not a full one.

When this lands, the harness will wire the validator to call it during `validate` and record the lcs version that backed each run's vocabulary check in `meta.json` for audit.
