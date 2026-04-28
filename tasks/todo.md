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

- [ ] Update README "Scanner Categories" table to mark it as **informational** and point readers at `lcs rules --categories` for the programmatic source of truth scoped to their actual install.
- [ ] Add `docs/rule-introspection.md` covering: the `RuleMeta` shape; the `lcs rules` CLI surface and flag combinations; the fingerprint contract (what it covers, what it doesn't, when it changes); the per-instance vs per-binary distinction.
- [ ] Add a section to `docs/rule-authoring.md` explaining how `category`, `severity`, and `threat_class` rule metadata feed into `Engine::rule_metadata()` and through to `lcs rules` — relevant for custom YARA / SYARA rule authors.
- [ ] Update PRD §6.2 (Library embedding contract): mention `Engine::rule_metadata()`, the fingerprint, and the default-impl-empty contract for source compatibility.
- [ ] Resolve OOB request — mark "External request from `shield-harness`" below as **Resolved** with a back-reference to Phase 11.5. The harness wires `--check-lcs-categories` to call `lcs rules --categories -e <engine>` and records the per-run fingerprint in `meta.json`.
- [ ] Phase 14 hand-off: update Phase 14a's evidence-attribution design to consume `Engine::rule_metadata()` for per-rule provenance and use the rule-set fingerprint as part of the calibration audit trail.
- [ ] **Forward seeding for correlation-rule introspection** (deferred — likely Phase 13.5 or merged into Phase 13/Phase 12 finalisation). Note in `tasks/todo.md` Phase 11d follow-ups (the correlation-rule TOML loader at `src/correlation/loader.rs`) and the Phase 13 scan-group entry: when correlation rules grow a new mutable format (YAML is on the table), they must adopt the same loaded-rule introspection pattern — declarative metadata, fingerprint contribution, exposed through a `lcs correlations` (or `lcs rules --kind=correlation`) surface.
- [ ] **Forward seeding for session-rule introspection** (Phase 12). Add a checkbox in Phase 12b: any session rule format (YAML, TOML, or in-code declarative) must support introspection from day one — declarative metadata, contribute to the fingerprint when loaded, surface through `lcs rules --kind=session`. No second-pass retrofit; design the contract before shipping.

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

- [ ] Add `--all` (`-a`) flag to `Command::Rules` (`src/cli.rs`):
  - Mutually exclusive with `-e <engine>` (clap `conflicts_with`).
  - Always emits JSON. Combining with `--categories` / `--threat-classes` / `--fingerprint` is a plan-mode decision — recommended: allow them and emit cross-engine **union** semantics for those views.
- [ ] Default `--all` JSON shape:
  ```json
  {
    "fingerprint": "<combined-rule-set fingerprint, same value `lcs rules --fingerprint` already returns>",
    "engines": {
      "simple": [<RuleMeta+engine>...],
      "yara":   [<RuleMeta+engine>...],
      "syara":  [<RuleMeta+engine>...]
    }
  }
  ```
- [ ] Engine construction in `--all` mode: each of `simple`, `yara`, `syara` is built from the same loaded `Config` (rules dir, custom_rules, disable list). The configured `[scan] engine` is **ignored** in `--all` mode — `--all` is "the full picture" by definition.
- [ ] Error handling: if an engine fails to build (e.g. malformed YARA rule in the rules dir), report the error inline at top-level under an `"errors": {"<engine>": "<msg>"}` map and continue collecting from the others. Do not fail the whole command unless every engine errors. Decide hard-fail-vs-soft-fail in plan-mode.
- [ ] Cross-engine fingerprint: confirm the existing `RuleSetFingerprint` already hashes the union (it does — 11.5a sorts by `(engine_name, rule_name)`). `--all`'s `"fingerprint"` is the same value as `lcs rules --fingerprint` provided the configured `Shield` covers the same engine set; document the relationship.
- [ ] Integration tests:
  - `lcs rules --all` and `lcs rules -a` produce identical JSON.
  - Each of the three engine keys is present and contains a non-empty array (assuming bundled rules ship for each).
  - `lcs rules --all -e simple` exits 2 with a clear "mutually exclusive" message.
  - `lcs rules --all` JSON parses cleanly and the `fingerprint` key is 64-char lower-hex.
  - Per-rule fields include `version`, `threat_level`, `threshold` (the 11.6a payload).
  - For the configured engine, `lcs rules --json` and the matching engine subarray of `lcs rules --all` agree on rule names and metadata content.

### 11.6c — Documentation and harness hand-off

- [ ] Update `docs/rule-introspection.md` (created in 11.5d):
  - Add a per-field section on `version` / `threat_level` / `threshold` (semantics, defaults, fingerprint participation).
  - Add a "Cross-engine view (`--all`)" section with sample JSON and the configured-engine vs `--all` distinction.
- [ ] Update `docs/rule-authoring.md`:
  - Show the `version = "..."` meta convention for YARA and SYARA rules.
  - Mention `threat_level` and `threshold` are now exposed via introspection (the fields themselves were already part of authoring; this phase reshapes them for read-out).
- [ ] Update `shield-harness` hand-off note (Phase 11.5d's resolved-OOB section): per-run `meta.json` can now snapshot per-rule `version` + `threshold` alongside the fingerprint. Useful for diagnosing recall regressions caused by metadata edits (e.g. someone bumped a threshold and a sample silently stopped firing — the per-rule snapshot pinpoints the change in seconds).
- [ ] Update PRD §6.2 (Library embedding contract) to reflect the widened `RuleMeta` shape — additive change, but the embedding contract should mention what's exposed.

**Non-goals for Phase 11.6**:
- No version-bump enforcement — `version` is opaque metadata; lcs does not warn or refuse when authors leave the field unchanged across edits.
- No per-engine fingerprint — the existing combined fingerprint stays; `--all` reports the same single value.
- No CLI shape change to `--json` for `-e <engine>` — that path stays as-is. Cross-engine view is exclusively under `--all`.
- No write / edit / template surface — `lcs rules --all` is read-only introspection. Authoring still happens in `.yar` / `.syara` source files.
- No correlation-rule or session-rule introspection — those still live behind the 11.5d forward seeds for future phases. `--all` covers built-in scan engines only.

---

## Phase 12: Session-aware scanning

Add optional *temporal* per-session state to detect multi-turn attack patterns — crescendo attacks (taxonomy §8.1), gradual steering (§8.1), and in-session protocol accumulation (§8.3). The session module lives in `llm_context_shield` as the orchestrator, not in the engine libraries, because it requires cross-scan memory that individual engines shouldn't own.

The core single-scan architecture remains stateless and fast. Session awareness is strictly opt-in and adds a second analysis pass on top of the existing pipeline.

**Scope boundary.** Phase 12 covers *temporal* per-session state — ordered scan history with crescendo / frequency / spread / spike detection. *Orderless* multi-input correlation (multi-file batch, prompt-history snapshot review) is **Phase 13: Scan groups** — a sibling feature that shares no implementation with sessions. Use Phase 12 when the inputs come from the same caller-identified session over time (e.g. a chatbot user, a gateway client). Use Phase 13 when the inputs are a one-shot snapshot of related material (e.g. all `.md` files in a PR diff). See [PRD.md](../PRD.md) UC-4 and UC-5 for the use-case framing.

**Backend posture.** The trait shape is designed for out-of-process backends from day one (Redis, SQLite, PostgreSQL) even though Phase 12a only ships `InMemorySessionStore`. Trait shape changes after operators are integrating against it are unacceptable; the time to design for multi-process is now, not after the in-memory implementation has shipped and locked in a `&mut self` API.

### 12a — Session store abstraction

- [ ] Design `SessionStore` trait in `src/session.rs` (new module):
  - **Trait bounds**: `pub trait SessionStore: Send + Sync` — required for multi-threaded embeddings (a single `Shield` instance scanning concurrent requests in a server) and for the `Shield` to remain `Send + Sync`.
  - **Method receiver**: all methods take `&self`. Backends with mutable internals (the in-memory `HashMap`, a connection pool) wrap the mutability behind interior-mutability primitives (`Mutex`, `RwLock`) or backend-native pools. This keeps the API ergonomic for shared `Arc<dyn SessionStore>` use across threads.
  - **`session_id: &str`** — opaque to the trait. The caller defines what a session means (per-user ID, per-API-key, per-conversation UUID, per-tab cookie). Phase 12 makes no normalisation assumptions and stores the raw bytes the caller provides.
  - Methods:
    - `record_scan(&self, session_id: &str, summary: ScanSummary) -> Result<(), SessionError>`
    - `get_history(&self, session_id: &str, window: usize) -> Result<Vec<ScanSummary>, SessionError>`
    - `clear(&self, session_id: &str) -> Result<(), SessionError>`
    - `expire(&self, max_age: Duration) -> Result<usize, SessionError>` — returns number of sessions purged
  - **`SessionError`**: enum with variants for backend-specific errors (`StoreUnavailable`, `EncodingError`, `Other(String)`). Returning `Result` from day one means Redis/network backends don't need an API change later.
- [ ] Design `ScanSummary` struct — privacy-safe metadata only:
  - `timestamp: SystemTime` — `SystemTime` not `Instant` so it survives serialisation when backends store on disk or over the wire.
  - `categories: BTreeSet<Category>` — categories detected in this scan (presence set, no counts).
  - `threat_classes: BTreeSet<String>` — threat classes detected (presence set).
  - `cumulative_score: i32` — the `ThreatScoreboard::cumulative_score()` value at end of scan.
  - `severity_histogram: [u32; 4]` — counts indexed by `Low/Medium/High/Critical`. Fixed-size, copyable, cheap.
  - **Explicitly NOT stored**: input text, finding descriptions, matched substrings, byte ranges. This is a hard privacy boundary — operators embedding the scanner in a WAF or gateway must be able to enable session tracking without paying a privacy or memory tax for retaining content.
  - `Serialize` + `Deserialize` derives — required for any backend that persists across processes.
- [ ] Implement `InMemorySessionStore`:
  - Internal type: `Mutex<HashMap<String, VecDeque<ScanSummary>>>`.
  - Constructor: `InMemorySessionStore::with_capacity(max_window: usize, max_sessions: usize)` — bounds both per-session window and total session count to prevent unbounded memory growth.
  - Eviction: on `record_scan`, if `max_sessions` is exceeded, evict the session with the oldest most-recent activity (LRU-on-write, cheap to implement with the existing `VecDeque` timestamps).
  - `expire(max_age)` — walks all sessions, drops those whose newest summary is older than `max_age`, returns count.
- [ ] Add `pub mod session;` to `src/lib.rs`. Re-export `SessionStore`, `ScanSummary`, `SessionError`, `InMemorySessionStore` from the crate root.
- [ ] Unit tests:
  - CRUD round-trip on `InMemorySessionStore`.
  - Window sizing — `get_history(id, 5)` returns at most 5 even when more are stored.
  - Per-session window bound — recording 100 summaries with `max_window=10` retains only the last 10.
  - `max_sessions` LRU eviction.
  - `expire(Duration::from_secs(60))` correctly purges old sessions only.
  - Concurrency smoke test — spawn N threads each calling `record_scan` on the same store; assert no panics, no data loss within the window bound. Validates `Send + Sync` shape.
  - Serialisation round-trip on `ScanSummary` — `serde_json` to a string and back, confirm field equality. Validates the future-backend contract.
- [ ] **Non-goals for 12a**: no async API surface, no Redis/SQLite implementations, no CLI surface, no `Shield::scan_with_session` wiring.

### 12b — Session analysis rules

Rules that operate on session history rather than individual scan content. Severity-filter ordering carries forward from Phase 11 — session rules see the same filtered findings the user sees.

- [ ] Design `SessionRule` struct (declarative shape, no free-form pattern strings):
  - `name: String` — rule identifier for output.
  - `pattern: SessionPattern` — what to detect (enum, see below).
  - `window: usize` — number of prior scans to consider.
  - `threshold: i32` — minimum session-level score to trigger.
  - `threat_level: i32`, `threat_class: String` — scoring metadata, mirrors `CorrelationRule`.
- [ ] Design `SessionPattern` enum:
  - `Crescendo { min_increases: usize }` — `cumulative_score` is monotonically increasing across at least `min_increases` consecutive summaries (or accelerating; decide in plan-mode).
  - `FrequencyOfClass { threat_class: String, n: usize, m: usize }` — `threat_class` appears in `n` of the last `m` summaries.
  - `CategorySpread { min_distinct_categories: usize }` — at least N distinct categories appear across the window (probing-for-weak-spots).
  - `Spike { multiplier: f32 }` — current scan's `cumulative_score` is ≥ `multiplier` × session average.
- [ ] Implement `SessionAnalyzer::evaluate(&self, current: &ScanReport, history: &[ScanSummary], rules: &[SessionRule]) -> Vec<SessionFinding>`:
  - One `SessionFinding` per fired rule (mirrors `MatchCorrelation` shape: rule metadata + which summaries contributed).
  - Pure function — no I/O, easy to unit-test with synthetic histories.
- [ ] Add `session_findings: Vec<SessionFinding>` to `ScanReport` (separate field, mirroring how Phase 11 added `correlations`).
- [ ] Bundled session rules: ship 2-3 default rules covering the most obvious patterns (crescendo on `prompt_hijack`, frequency on `social_engineering`, spike on cumulative). Pattern mirrors Phase 11c's bundled correlation catalog.
- [ ] Unit tests with synthetic session histories — at minimum one positive + one negative per `SessionPattern` variant.

### 12c — Session API surface

Expose session scanning to both library and CLI consumers.

- [ ] Extend `Shield` builder API:
  - `.session_store(store: Arc<dyn SessionStore>)` — attach a session store. `Arc` not `Box` so the same store can be shared across multiple `Shield` instances (a real concern for server embeddings; one engine config per route, one session store across all of them).
  - `.session_rules(rules: Vec<SessionRule>)` — additive over bundled, mirroring Phase 11d's `.correlation_rules` semantics.
  - `.disable_session_analysis()` — opt-out for callers who only want session *recording* without the analysis pass.
- [ ] Extend `Shield` scan API:
  - `Shield::scan_with_session(&self, session_id: &str, input: &str) -> ScanReport` — scan + record summary + run session analysis. `session_id` first to match `record_scan` argument ordering.
  - Error handling: if no session store is attached, return `ScanReport` with `session_findings = vec![]` and a `tracing::warn!`. (Don't panic — calling `scan_with_session` on a Shield without a store is a misconfiguration, not a programming bug; the existing scan still produces meaningful output.)
- [ ] Extend CLI:
  - `--session-id <ID>` flag on `lcs scan` — enables session tracking for this scan. Without `--session-id`, behaviour is identical to today.
  - `--session-window <N>` — override the per-session window for this scan (default from `[session] default_window`).
  - **Out of scope for 12c**: `--session-store <path>` — that's 12d (with the SQLite/Redis backends).
- [ ] JSON output: top-level `"session_findings"` key emitted whenever non-empty, mirroring Phase 11d's `"correlations"` shape.
- [ ] Text output: `--session` flag (mirroring `--correlations` and `--threat-scores`) gates the per-session-finding detail block on stderr. Summary line always includes count when session findings fired.
- [ ] Add `[session]` section to `Config` / `DEFAULT_CONFIG`:
  - `enabled: bool` (default `false` — session tracking is opt-in even when a session_id is provided).
  - `default_window: usize` (default 10).
  - `max_sessions: usize` (default 1000 — caps in-memory store; backends may ignore).
  - `expiry_seconds: u64` (default 3600 — auto-expire idle sessions).
  - `custom_rules: Option<String>` (path to TOML file with custom `SessionRule` definitions, mirroring `[correlation] custom_rules`).
- [ ] Integration tests: multi-scan sequences in `tests/integration.rs` that simulate a crescendo attack and a frequency attack, verifying both library and CLI surfaces produce the expected session findings. Use `InMemorySessionStore` directly (no on-disk backend yet).
- [ ] Documentation: new `docs/session-scanning.md` covering session_id semantics (caller-defined opacity), the four bundled patterns, custom-rule TOML format, store choice guidance (in-memory for single-process, deferred backends for multi-process).

### 12d — Pluggable session backends

Two backends ship in 12d, positioned as a **scaling axis** rather than alternatives. Operators start embedded (single binary, no infrastructure) and switch to decoupled (shared Redis) when load or multi-host deployment demands it. The switch is a config change (`[session] backend = "redb" | "redis"`), not a code change — both backends implement the same `SessionStore` trait.

- [ ] Confirm `SessionStore` trait shape held up under real backend implementation pressure. If not, fix the trait *before* shipping a second backend.
- [ ] Implement `RedbSessionStore` — embedded persistent session state for single-process deployments. Use `redb` (pure-Rust, MVCC, no FFI, well-maintained). Schema: a single multimap table keyed on `session_id` with `(timestamp, ScanSummary)` entries; `redb`'s ordered iteration serves the time-windowed `get_history` naturally. `expire(max_age)` walks all sessions in a write transaction.
  - Gate behind feature flag `session-redb`.
  - Construction: `RedbSessionStore::open(path: impl AsRef<Path>) -> Result<Self, SessionError>`.
- [ ] Implement `RedisSessionStore` — decoupled persistent session state for multi-host service deployments. Use the `redis` crate (`redis = "0.x"`; confirm version under CLAUDE.md's N-1 dependency rule at plan-mode time). Use a `LIST` per session (`LPUSH` on record, `LRANGE` on history, `EXPIRE` for TTL). Connection management: `r2d2` or `redis::Client::get_connection_with_timeout` pooled behind a `Mutex`/`RwLock` inside the store; the store presents the same `&self` interior-mutability shape as `InMemorySessionStore`.
  - Gate behind feature flag `session-redis`.
  - Construction: `RedisSessionStore::connect(url: &str) -> Result<Self, SessionError>`.
  - Why the `redis` crate over `redis-protocol`: `redis-protocol` is just the RESP codec — using it directly means owning connection management, pooling, retry, and command building. The `redis` crate gives all of that and is well-maintained. `fred` is a future-async option; deferred unless an async wrapper trait lands.
  - Why not `sled`: similar embedded-KV shape but development is widely treated as paused (long-stalled 1.0 beta), which conflicts with CLAUDE.md's conservative dependency stance. `redb` covers the same use case with active maintenance.
- [ ] Wire backend selection through `[session]` config: `backend = "memory" | "redb" | "redis"` (default `"memory"`), plus backend-specific fields (`redb_path`, `redis_url`). `Shield::builder().build()` resolves the config to construct the appropriate `Arc<dyn SessionStore>`.
- [ ] Document both backends in `docs/session-scanning.md` — connection-string format, feature flag, eviction semantics, operational concerns (Redis `MEMORY` / `maxmemory-policy`, redb on-disk file growth + `compact()`).
- [ ] Migration story: include a short "starting embedded, growing decoupled" section in `docs/session-scanning.md` covering how to drain and migrate sessions from `redb` to Redis without losing in-flight history. (Phase-13-style scope cap: a manual one-shot migration, not a live replication shim.)
- [ ] Acknowledge in the document that an HTTP / MCP front end (a future, unscheduled phase — see [PRD.md](../PRD.md) §6.4) will use the Redis backend to share session state across processes. This is the load-bearing reason 12a designed the trait for out-of-process backends.

---

## Phase 13: Scan groups

Add a one-shot, *orderless* multi-input scanning surface. A scan group is a related set of inputs (multi-file batch, prompt-history snapshot, ingested document corpus) processed in a single invocation. The group has no temporal semantics — there is no "first" or "last" input, no crescendo, no expiry. The output is per-input results plus group-level aggregations: combined threat scoreboard, cross-input correlations, worst-offender summary.

**Scope boundary.** Phase 13 covers *orderless snapshots*. *Temporal sessions* (per-user state across requests, crescendo detection) are **Phase 12** — a sibling feature with no shared implementation. See [PRD.md](../PRD.md) UC-3 and UC-4 for the use-case framing.

Phase 13 is intentionally smaller than Phase 12 — it reuses the existing single-scan and correlation infrastructure rather than introducing new abstractions. The novel surface is the input-collection type, the group-level report, and the choice to bucket per-input findings into the existing correlation evaluator (which already accepts `&[EngineFindings]`) so cross-input correlation falls out for free.

### 13a — `ScanGroup` and `GroupReport` types

- [ ] Create new module `src/scan_group.rs`:
  - `pub struct ScanGroup` — collection of `(label: String, input: String)` pairs. Builder-ish API: `ScanGroup::new()`, `.add(label, input)`, `.add_file(path) -> io::Result<()>` convenience.
  - `pub struct GroupReport`:
    - `per_input: Vec<(String, ScanReport)>` — per-input results, label-keyed.
    - `aggregate_scoreboard: ThreatScoreboard` — class scores summed across all inputs.
    - `cross_input_correlations: Vec<MatchCorrelation>` — correlations that fired across distinct inputs (each input becomes a separate `EngineFindings` bucket; the existing `CorrelationEngine::evaluate` does the rest).
    - `summary: GroupSummary` — high-level aggregates (total findings, distinct threat classes, worst-offender input by cumulative score).
- [ ] Extend `Shield`:
  - `Shield::scan_group(&self, group: &ScanGroup) -> GroupReport` — scans each input via the existing `scan()` path, collects per-input reports, runs cross-input correlation, builds aggregates.
  - The cross-input correlation step bundles each input's findings as a labelled `EngineFindings` bucket with a synthetic engine name (`"input:<label>"`). Same correlation rules that fire across engines today fire across inputs in this mode.
- [ ] Add `pub mod scan_group;` to `src/lib.rs` and re-export `ScanGroup`, `GroupReport`, `GroupSummary`.
- [ ] Unit tests:
  - Empty group → empty report.
  - Single-input group → behaves like `Shield::scan` wrapped in a group.
  - Multi-input group with one bad + one clean input → per-input distinguishes correctly, aggregate scoreboard reflects only the bad one.
  - Multi-input group where two inputs each contain one half of a `sandwich_attack` pair → cross-input correlation fires (delimiter manipulation in input A + prompt injection in input B).

### 13b — CLI surface

- [ ] Add `--group` flag (or `lcs scan-group` subcommand — decide in plan-mode for 13b based on which composes better with shell glob expansion). Accepts multiple file paths.
- [ ] Output formats:
  - `text`: per-input summary block (label + finding count + worst severity), then aggregate scoreboard, then cross-input correlations under `--correlations`.
  - `json`: top-level `"per_input": [{"label": "...", "report": {...}}, ...]`, `"aggregate_scoreboard": {...}`, `"cross_input_correlations": [...]`, `"summary": {...}`.
  - `quiet`: exit code only — `0` if every input is clean, `1` if any input has findings or any cross-input correlation fires, `2` on error.
- [ ] Add `[scan_group]` section to `Config` / `DEFAULT_CONFIG`:
  - `enable_cross_input_correlation: bool` (default `true`).
  - `max_inputs: usize` (default 1000 — guardrail against unintended directory-recursion blow-ups).
- [ ] Integration tests: multi-file fixtures in `tests/`, both clean-batch and mixed-batch cases.

### 13c — Library docs and example

- [ ] New `examples/batch_scan.rs` showing `ScanGroup` construction from a directory of files, `Shield::scan_group` invocation, and printing the `GroupReport`.
- [ ] Extend `docs/rule-authoring.md` with a short note that the existing `CrossEngine` correlation type doubles as cross-input correlation in scan-group mode.
- [ ] Update README "Library Usage" section with a 5-line `Shield::scan_group` snippet.

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
- [ ] Design `EvidenceType` enum: `StringMatch`, `Similarity`, `Classifier`, `LlmVerdict`, `Correlation`, `SessionSignal`
- [ ] Add `pub mod confidence` to `src/lib.rs`
- [ ] Unit tests for score construction and display

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
