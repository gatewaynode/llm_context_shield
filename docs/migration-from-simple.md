# Migration Guide: Simple Engine → YARA Rules

The `simple` engine hard-codes regex patterns in Rust source (`src/scanners/*.rs`). The `yara` engine loads the same patterns from `.yar` files that can be edited, extended, and shipped without rebuilding the binary.

This guide shows how each simple-engine scanner maps to its bundled YARA equivalent and how to fork a rule for a local override.

## Why migrate

- **Editable without recompiling**: drop a `.yar` file under `~/.local/share/llm_context_shield/rules/yara/` and it loads on next run.
- **Named rules**: `lcs list -e yara` shows every rule by name; `--disable prompt_injection_critical` silences one rule without dropping the whole category.
- **Composable conditions**: YARA supports boolean logic (`$s1 and not $s2`, `2 of them`) that plain regex lists cannot express.

Trade-off: the `simple` engine has zero feature-flag cost and no YARA-X dependency. Keep it for minimal builds or embedded use.

## Engine-to-engine equivalence

Every simple-engine category has a 1:1 bundled YARA rule file. The regex patterns are byte-for-byte ports (`(?i)foo` in Rust ↔ `/foo/i` in YARA). Severity levels are preserved.

| Simple scanner                              | YARA rule file                  | Bundled rules                                                  |
|---------------------------------------------|---------------------------------|----------------------------------------------------------------|
| `src/scanners/prompt_injection.rs`          | `rules/yara/prompt_injection.yar`        | `prompt_injection_critical`, `prompt_injection_high`         |
| `src/scanners/jailbreak.rs`                 | `rules/yara/jailbreak.yar`               | `jailbreak_critical`, `jailbreak_high`, `jailbreak_medium`   |
| `src/scanners/data_exfiltration.rs`         | `rules/yara/data_exfiltration.yar`       | `data_exfiltration_*`                                         |
| `src/scanners/hidden_content.rs`            | `rules/yara/hidden_content.yar`          | `hidden_content_*`                                            |
| `src/scanners/delimiter_manipulation.rs`    | `rules/yara/delimiter_manipulation.yar`  | `delimiter_manipulation_*`                                    |
| `src/scanners/instruction_override.rs`      | `rules/yara/instruction_override.yar`    | `instruction_override_*`                                      |

Run `lcs list -e yara` for the authoritative live list.

## Switching over

Per-invocation:

```sh
lcs scan -e yara              # instead of: lcs scan  (defaults to simple)
```

Persistent, via `config.toml`:

```toml
[scan]
engine = "yara"
```

Build with the feature flag:

```sh
cargo build --release --features yara
```

## Worked example: porting a regex

Simple engine (`src/scanners/prompt_injection.rs`):

```rust
Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)")
    .expect("static regex pattern is valid"),
Severity::Critical,
"Instruction override: ignore previous instructions",
```

YARA equivalent (`rules/yara/prompt_injection.yar`):

```yara
rule prompt_injection_critical {
    meta:
        category    = "prompt_injection"
        severity    = "critical"
        description = "Instruction override attempting to bypass previous context"
    strings:
        $s1 = /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)/i
    condition:
        any of them
}
```

Translation rules:
- Rust `(?i)...` becomes YARA `/.../i`.
- Rust `Severity::Critical` becomes `severity = "critical"` in `meta`.
- Rust `Category::PromptInjection` becomes `category = "prompt_injection"` in `meta`.
- The human-readable message in the Rust `(regex, severity, "msg")` tuple becomes the `description` field.

## Forking a bundled rule

To override a bundled rule without patching the source:

1. `lcs init --rules` to scaffold the XDG directory tree.
2. `lcs list -e yara` to find the rule name you want to replace.
3. `lcs scan -e yara --disable prompt_injection_critical` to silence the bundled version.
4. Drop a new rule with a different name (e.g. `prompt_injection_critical_v2`) into `~/.local/share/llm_context_shield/rules/yara/custom.yar`.

Or, drop bundled rules entirely and start fresh:

```toml
[rules]
bundled = false
dir     = "/etc/lcs/rules"  # optional explicit override
```

## Parity checklist

Before switching a pipeline from `simple` to `yara` in production, verify:

- [ ] `cargo test --features yara` — all tests pass.
- [ ] `lcs scan -e yara` detects every payload your existing `simple`-engine regression suite covers.
- [ ] `lcs scan -e yara` produces the same exit codes (0/1/2) as `simple` on your representative inputs.
- [ ] `lcs list -e yara` output matches the rule set your ops team expects.

See `docs/rule-authoring.md` for how to extend the rule set with your own patterns.
