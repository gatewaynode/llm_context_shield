# Rule Introspection

How to ask a running `lcs` install what rules it has loaded — and how to use the answer for audit, validation, and drift detection.

## Why this exists

Two priorities drive the introspection surface:

1. **Findings are useful only when traceable.** Every `Finding` carries `category`, `severity`, `description` — but until you know which rule produced it, root-cause analysis is guesswork. The scanner's findings output and the rule introspection surface describe the same rule set from two angles.
2. **The rule set is highly mutable.** Bundled rules are compiled in. YARA / SYARA rules are discovered from `[rules] dir` (XDG default or a config override). Custom correlation rules load from `[correlation] custom_rules`. Two `lcs` installs at the same version against the same input can emit different findings. The binary version alone cannot answer "what was the active rule set for this scan?"

Implications:

- Schema is **per-instance**, not per-binary. `lcs rules` reads the same `Config` that `lcs scan` does — same rules dir, same disable list, same custom rules path. There's no static `schema.json` artifact in the repo: it would lie under per-instance mutability.
- The audit trail needs a **rule-set fingerprint** in addition to `lcs --version`. A SHA-256 hash over the sorted `(engine_name, RuleMeta)` set lets the harness record "run R used this exact rule set" and detect drift between runs.
- The category vocabulary is the only **bounded** vocabulary (15-variant `Category` enum). Rule names and threat classes are inherently unbounded — anyone can mint a new threat class via custom rule metadata. The introspection surface is honest about this asymmetry: categories enumerate statically, rule names and threat classes only enumerate against the running instance.

## The `RuleMeta` shape

Every introspectable engine exposes one `RuleMeta` per loaded rule:

| Field          | Type                | Meaning |
|----------------|---------------------|---------|
| `name`         | `String`            | Rule identifier as users see it in `lcs list -e <engine>` and as they pass to `--disable`. Unique per engine. |
| `category`     | `Category`          | Bounded enum (15 variants). Drives `--severity` filtering and per-category aggregation. |
| `severity`     | `Option<Severity>`  | `Some(_)` when statically determinable from rule metadata; `None` for rules whose severity is decided at match time (`SimpleEngine` regex scanners assign per-pattern severity at match time, so the rule itself doesn't carry one). |
| `threat_class` | `String`            | Scoreboard class string. Defaults to `category.to_string()` when not overridden. Multiple rules sharing a `threat_class` accumulate scores together. |
| `version`      | `Option<String>`    | `Some("...")` when the rule's metadata declares it, `None` otherwise. Convention is semver; the field is opaque to lcs (string round-trip only). `SimpleEngine` always emits `None` — bundled rules are compiled in, per-rule version is meaningless. |
| `threat_level` | `i32`               | What one match contributes to the rule's `threat_class` score. Default `1`. |
| `threshold`    | `i32`               | Minimum accumulated class score required for the rule to fire. Default `0` (always-fire). |

The `version` / `threat_level` / `threshold` trio surfaces the scoring metadata the engine actually uses at scan time. Audit pipelines that want a per-rule version stamp pair these with the rule-set fingerprint described below.

## CLI surface: `lcs rules`

Builds the same `Shield` that `lcs scan` would use (same config flow, same rules dir, same engine selection), then projects the loaded rule set through one of several view flags. Default is a human-readable rule list.

### Per-engine view (`-e <engine>` or configured default)

```sh
# Default: human rule list, one rule per line, "<engine>:<name>  [<category>]"
lcs rules                       # uses [scan] engine from config (default: simple)
lcs rules -e yara
lcs rules -e syara

# Structural views — mutually exclusive
lcs rules --json                # {"fingerprint": "<hex>", "rules": [<rule>...]}
lcs rules --categories          # one Category name per line, in declaration order
lcs rules --threat-classes      # one threat-class string per line, lex-sorted
lcs rules --fingerprint         # single 64-char lowercase hex line
```

### Cross-engine view (`--all` / `-a`)

`--all` builds every built-in engine (simple, syara, yara) from the same `Config` and emits the union. Mutually exclusive with `-e <engine>`. Combines with each view flag to switch the cross-engine output shape:

```sh
lcs rules --all                              # JSON: {"fingerprint": "<hex>", "engines": {...}}
lcs rules --all --fingerprint                # cross-engine combined hash, single hex line
lcs rules --all --categories                 # cross-engine union, one Category per line
lcs rules --all --threat-classes             # cross-engine union, one threat-class per line
```

`--all` ignores the `[scan] engine` config setting — it always covers the three built-in engines as currently configured (XDG rules dir, custom rules, disabled list). Hard-fails (exit 2) if any engine fails to construct.

### Default `--all` JSON shape

```json
{
  "fingerprint": "2851f3adff02be2a9ae2076b7910cae190a707c9cc70812bfe8ee25fc90321eb",
  "engines": {
    "simple": [
      {
        "engine": "simple",
        "name": "prompt_injection",
        "category": "prompt_injection",
        "severity": null,
        "threat_class": "prompt_hijack",
        "version": null,
        "threat_level": 1,
        "threshold": 0
      }
    ],
    "syara": [/* ... */],
    "yara":  [/* ... */]
  }
}
```

Engine keys are alphabetical (`simple`, `syara`, `yara`). Within each array, rules are sorted by `name`. Every per-rule entry has all seven `RuleMeta` keys plus an `engine` discriminator (so an entry remains self-describing if a consumer flattens the arrays).

## The fingerprint contract

`Shield::rule_set_fingerprint()` returns a `RuleSetFingerprint` (newtype around a 64-char lowercase hex SHA-256). The same value is what `lcs rules --fingerprint` prints.

### What it covers

The fingerprint is computed over a canonical-JSON sort of `(engine_name, RuleMeta)` pairs. It changes when **any** of the following changes:

- A rule is added, removed, or renamed.
- A rule's `category`, `severity`, `threat_class`, `version`, `threat_level`, or `threshold` changes.
- A rule's pattern body changes only **if** that change is reflected in `RuleMeta` (it usually is not — pattern bodies are not part of `RuleMeta`).

### What it doesn't cover

- **Pattern bodies.** Two YARA rules with identical metadata but different `strings:` blocks produce the same fingerprint. `RuleMeta` describes identity and scoring, not content. If you need content-level integrity, hash the rule files directly.
- **The input being scanned.** The fingerprint is a property of the rule set, not the scan. The harness owns input fingerprinting in its sidecar metadata.
- **Engine implementation.** A bug fix in the YARA-X regex engine that changes match behaviour does not change the fingerprint. Pair with `lcs --version` for the binary identity.

### When it changes

Bumping a rule's `threshold` from 0 to 5 changes the fingerprint. This is the **desired** behaviour — audit trails should be sensitive to scoring-metadata changes, not just identity. A silent threshold bump that prevented a rule from firing on a benchmark sample would otherwise be invisible to the harness; with the fingerprint in `meta.json`, a recall regression pinpoints the metadata edit in seconds.

### Per-engine vs cross-engine fingerprint

`lcs rules --fingerprint` (without `--all`) hashes the configured engine's rule set only. `lcs rules --all --fingerprint` hashes all three built-in engines as configured. **The two values are distinct by design** — they hash different engine sets, so they must differ. Both are valid audit signals at different scopes:

- Per-engine fingerprint: "did the rule set the configured engine sees change?" — typical CI / harness use.
- Cross-engine fingerprint: "did the rule set across every built-in engine change?" — useful when a deployment runs multiple engines against the same input or when capturing a complete per-instance snapshot in `meta.json`.

Default-config example values for orientation (these change when bundled rules update):

```
lcs rules --fingerprint            → 4c6cd18ac803ea92cb145a143b6e1629b30ee655e59afa6f60a65f150c11469a
lcs rules --all --fingerprint      → 2851f3adff02be2a9ae2076b7910cae190a707c9cc70812bfe8ee25fc90321eb
```

## Per-instance vs per-binary

Two `lcs 0.5.3` installs on different machines can emit different findings because:

- One has user-authored rules at `$XDG_DATA_HOME/llm_context_shield/rules/`.
- The other has `[rules] bundled = false` and only loads custom rules.
- One disables `hidden_content` via `[scan] disable`.
- One's `[correlation] custom_rules` points at a TOML file with extra rules.

The introspection surface answers "what does *this* install have loaded right now?" — not "what does lcs ship?" That second question doesn't have a stable answer once custom rules and overrides enter the picture.

For the harness use case, this means:

- Run `lcs rules --all --fingerprint` once per scan run and persist the value in `meta.json`. A diff in fingerprint between two runs explains a diff in findings.
- Run `lcs rules --all --json` once per scan run for the full per-instance snapshot — every rule the engines could have fired, with its scoring metadata. Useful for diagnosing recall regressions caused by metadata edits (someone bumped a threshold and a sample silently stopped firing — the per-rule snapshot pinpoints the change).
- Use `lcs rules --all --categories` to validate sidecar `expected_categories` lists against the actual category vocabulary the configured install can emit. A typo'd category name surfaces at validate-time instead of producing a 0% recall bucket after a full run.

## Library API

Embedding hosts have direct access to the same data without invoking a subprocess:

```rust
use llm_context_shield::shield::Shield;
use llm_context_shield::config::Config;

let config = Config::load().unwrap_or_default();
let shield = Shield::builder()
    .engine("yara")
    .config(config)
    .build()?;

// Per-rule introspection.
let metas = shield.engine().rule_metadata(); // Vec<RuleMeta>
for m in &metas {
    println!("{}  category={:?}  threshold={}", m.name, m.category, m.threshold);
}

// Categories the loaded rule set can emit.
let cats = shield.engine().categories();          // BTreeSet<Category>

// Rule-set fingerprint — same value lcs rules --fingerprint prints.
let fp = shield.rule_set_fingerprint();           // RuleSetFingerprint (Display = hex)
println!("{fp}");
```

`Engine::rule_metadata()` has a default impl that returns `Vec::new()` to preserve source compatibility for custom `Engine` implementors. Custom engines opt in by overriding. Built-in engines override and cache the metadata at construction time, so calling `rule_metadata()` is cheap.

For the cross-engine view used by `lcs rules --all`, see `engines::compute_fingerprint(&[(name, &[RuleMeta])])` — the public primitive that takes a multi-engine slice and returns a combined `RuleSetFingerprint`.

## Author convention: declaring `version`

Authors of YARA / SYARA rules can declare a `version = "..."` meta field. The string is opaque to lcs — it round-trips into `RuleMeta.version` but is not parsed or validated:

```yara
rule my_custom_prompt_leak {
    meta:
        category     = "prompt_injection"
        severity     = "high"
        description  = "..."
        version      = "1.2.0"
        threat_level = 3
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /reveal\s+(the\s+)?hidden\s+directive/i
    condition:
        any of them
}
```

Recommendation: bump `version` whenever the rule's pattern, scoring, or threat-class semantics change. Two rules with the same name and different `version` strings produce different fingerprints — that's the audit signal. Authors who don't care about per-rule versioning can omit the field; `RuleMeta.version` will be `None` and the rule still fingerprint-attributes via its other metadata.

`threat_level` and `threshold` are part of `RuleMeta` regardless of whether the author declared them — they default to `1` and `0` respectively. See [`docs/rule-authoring.md`](rule-authoring.md) for the authoring side of these fields.

## Non-goals

- **No checked-in `schema.json`.** The per-instance source of truth is `lcs rules --json` (or `lcs rules --all --json`). A static file would lie under custom rules and disabled scanners.
- **No version-bump enforcement.** `version` is opaque metadata; lcs does not warn or refuse when authors leave the field unchanged across edits. Authors decide what counts as a versioning event.
- **No correlation- or session-rule introspection (yet).** `lcs rules` covers built-in scan engines (simple, yara, syara) only. Correlation rules and (📅 Phase 12) session rules will adopt the same introspection pattern when their phases land.
- **No input fingerprinting.** The rule-set fingerprint is a property of the rule set, not the scan. Sidecar metadata owns input identity.
