# Rule Authoring Guide

How to write custom rules for the `yara` and `syara` engines in `llm_context_shield`.

## Where rules live

Bundled rules ship inside the binary. Custom rules are loaded from:

1. `[rules] dir = "..."` in `config.toml`, if set — `<dir>/yara/*.yar` and `<dir>/syara/*.syara`.
2. Otherwise `$XDG_DATA_HOME/llm_context_shield/rules/<engine>/` (falls back to `~/.local/share/llm_context_shield/rules/<engine>/`).

Scaffold the tree with:

```sh
lcs init --rules
```

This creates `yara/` and `syara/` subdirectories and a README stub.

To disable bundled rules (use only your own), set:

```toml
[rules]
bundled = false
```

## Minimum viable rule

Both engines accept YARA-dialect DSL. A rule must declare `meta`, `strings`, and `condition`:

```yara
rule my_custom_prompt_leak {
    meta:
        category    = "prompt_injection"
        severity    = "high"
        description = "Detects attempts to surface the system prompt via roleplay"
    strings:
        $s1 = /reveal\s+(the\s+)?hidden\s+directive/i
        $s2 = /what\s+were\s+you\s+told\s+before\s+this\s+chat/i
    condition:
        any of them
}
```

Save as `my_rules.yar` under `yara/` (or `.syara` under `syara/`) and run:

```sh
lcs list -e yara      # confirm the rule was compiled
lcs scan -e yara      # scan stdin with it active
```

## Required metadata

The engine reads three `meta:` fields. Missing fields fall back to sentinel values.

| Field         | Required | Values                                           | Used for                              |
|---------------|----------|--------------------------------------------------|---------------------------------------|
| `category`    | yes      | `prompt_injection`, `jailbreak`, `data_exfiltration`, `hidden_content`, `delimiter_manipulation`, `instruction_override` | Finding category, severity filtering |
| `severity`    | yes      | `low`, `medium`, `high`, `critical`              | `--severity` threshold filtering     |
| `description` | yes      | free text                                        | Finding message shown to the user    |
| `author`      | no       | free text                                        | Attribution only                     |
| `version`     | no       | free text                                        | Attribution only                     |

Unknown `category` values are rejected at compile time. Unknown `severity` values default to `low`.

## Rule naming

The rule identifier (`rule my_custom_prompt_leak`) is what users see in `lcs list -e yara` and what they pass to `--disable`. Pick stable, descriptive names — renaming breaks user configs.

Convention: `<category>_<qualifier>` — e.g. `prompt_injection_critical`, `jailbreak_high`, `hidden_content_zero_width`.

## String patterns

Supports the YARA-X string dialect:

- **Text strings**: `$s1 = "literal"`
- **Regex**: `$s1 = /pattern/i` (case-insensitive flag supported; regex syntax per YARA-X)
- **Hex**: `$h1 = { 48 65 6C 6C 6F }`

Use `nocase` for plain strings and `/.../i` for regex. Anchor with `^` / `$` at line start/end when you want to reduce false positives on mid-sentence matches.

## Conditions

Common patterns:

```yara
condition: any of them                  // match if any string hits
condition: all of them                  // match only if every string hits
condition: 2 of ($s*)                   // match if at least 2 of $s1..$sN hit
condition: $s1 and not $s2              // combine with boolean logic
```

## YARA vs SYARA

Both engines compile the same DSL. Today, bundled SYARA rules are string-only and behave identically to YARA — the SYARA engine is wired up for future semantic extensions (embedding similarity, classifier gates, LLM verification) controlled via the `[syara]` config section. Write string-only rules today; semantic features will layer on without breaking existing rules.

## Testing a rule

1. Drop the file under the appropriate engine subdirectory.
2. `lcs list -e yara` — confirm the rule name appears.
3. `lcs scan -e yara <<< "your test payload"` — confirm it fires.
4. `lcs scan -e yara <<< "benign payload"` — confirm it does **not** fire.
5. Run the full suite once more: `cargo test --features yara,syara`.

## Troubleshooting

- **Rule does not appear in `lcs list`**: file extension wrong (`.yar` vs `.syara`), file lives in the wrong engine subdirectory, or file exceeds the 1 MiB size cap (`warn` in logs).
- **Rule fires on benign input**: tighten the regex; add line anchors; require `N of them` instead of `any of them`.
- **Rule never fires**: check you haven't shadowed it with `--disable`; enable `--log` and re-scan to see compile warnings.
- **Symlinks are ignored**: intentional — drop real files, not symlinks. Symlinked rule files are skipped with a warning.
