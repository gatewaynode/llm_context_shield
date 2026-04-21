# Manual Handoff — Phase 8d (Encoding and Decomposition Detection)

> **For human implementation in VSCode.** This file contains concrete, copy-pasteable regex patterns, test payloads, and shell commands. It is deliberately written to be self-contained — no LLM round-trips required. The patterns below are *starting points*; refine them empirically against the FP sweep before committing.

## Why this is manual

Previous attempts to plan 8d via an LLM tripped API guardrails on the required example inputs (hex-encoded payloads decode to attack strings, which classifiers react to). Drafting the patterns locally avoids that friction entirely. The regex patterns themselves are safe; only the decoded attack strings are problematic, and you can pick your own innocuous decoded test strings (e.g., `"hello"` — hex `\x68\x65\x6c\x6c\x6f`).

## Scope — taxonomy §2.1–2.3

Four new rules that extend the existing `hidden_content` category to catch encoded / decomposed payloads the base64 + homoglyph rules miss:

| Rule | Target | Threshold | Severity | Threat class |
|---|---|---|---|---|
| `hidden_content_hex_encoding` | `\xNN` escape sequences, `0xNN` tokens, `\uNNNN` escapes | 0 | high | `obfuscation` |
| `hidden_content_char_array` | Per-character arrays, `chr()` concatenation, `String.fromCharCode(...)` | 0 | high | `obfuscation` |
| `hidden_content_rot13` | Explicit ROT13 decode markers | 2 | medium | `obfuscation` |
| `hidden_content_morse` | Morse-code letter sequences | 2 | medium | `obfuscation` |

## Architecture decision — co-locate, no new Category

Like 8c, 8d **extends an existing category** (`hidden_content`) rather than creating a new one. That means:

- **No** new `Category` enum variant in `src/scanner.rs`.
- **No** new `include_str!` in `src/rules.rs` (we're adding to the file that's already bundled).
- **No** new row in the README Scanner Categories table.
- **No** change to `docs/rule-authoring.md` category enum list or threat_class table — `hidden_content` and `obfuscation` are already documented.

Total surface: 2 rule-file edits + 2 test-file edits + 1 integration test + 1 todo.md update = **6 files touched**.

## Ordered edit list

1. `rules/yara/hidden_content.yar` — append 4 new rules after `hidden_content_homoglyph`
2. `rules/syara/hidden_content.syara` — mirror with quoted numeric metadata
3. `src/engines/yara.rs::tests` — add ~8 unit tests (positive × 4 rules + gating-demo + FP)
4. `src/engines/syara.rs::tests` — mirror
5. `tests/integration.rs` — add 1–2 tests in the `yara_engine` module
6. `tasks/todo.md` — tick the 5 `[ ]` boxes in Phase 8d and append `#### Review (8d)`

---

## Step 1 — `rules/yara/hidden_content.yar`

Append **after** the closing `}` of `hidden_content_homoglyph` (currently line 58):

```yara

rule hidden_content_hex_encoding {
    meta:
        category     = "hidden_content"
        severity     = "high"
        description  = "Concentrated hex byte escapes (likely payload encoding)"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 3
        threshold    = 0
        threat_class = "obfuscation"
    strings:
        // 4+ consecutive \xNN escapes, e.g. \xNN\xNN\xNN\xNN
        $s1 = /(?:\\x[0-9a-f]{2}){4,}/i
        // 4+ 0xNN tokens separated by commas/whitespace (C/Rust byte arrays)
        $s2 = /(?:0x[0-9a-f]{2}[\s,]+){3,}0x[0-9a-f]{2}/i
        // 3+ \uNNNN Unicode escapes
        $s3 = /(?:\\u[0-9a-f]{4}){3,}/i
    condition:
        any of them
}

rule hidden_content_char_array {
    meta:
        category     = "hidden_content"
        severity     = "high"
        description  = "Per-character decomposition: single-letter array, chr() concat, or fromCharCode"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 3
        threshold    = 0
        threat_class = "obfuscation"
    strings:
        // Array literal of 6+ single-letter strings: ['a','b','c','d','e','f']
        $s1 = /\[\s*["'][a-z]["'](?:\s*,\s*["'][a-z]["']){5,}\s*\]/i
        // chr(N)+chr(N)+chr(N)+chr(N) — 4+ chr() calls joined by + or ,
        $s2 = /(?:chr\(\s*\d{1,3}\s*\)\s*[+,]\s*){3,}chr\(\s*\d{1,3}\s*\)/i
        // String.fromCharCode with 6+ numeric args
        $s3 = /String\.fromCharCode\(\s*(?:\d{1,3}\s*,\s*){5,}\d{1,3}\s*\)/
    condition:
        any of them
}

rule hidden_content_rot13 {
    meta:
        category     = "hidden_content"
        severity     = "medium"
        description  = "Explicit ROT13 decode marker — threshold-gated to prevent FP on topic discussion"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 2
        threshold    = 2
        threat_class = "obfuscation"
    strings:
        // "rot13:" / "rot-13:" / "rotate13:" followed by a colon
        $s1 = /\brot-?(?:13|thirteen)\s*(?:cipher|encoded|encoding)?\s*:/i
        // "decode (this) (as|using|with|from) rot13"
        $s2 = /\bdecode\s+(?:this|the\s+following)(?:\s+\w+)?\s+(?:from|using|with|as)\s+rot-?13\b/i
        // "apply rot13 to" / "shift by 13"
        $s3 = /\b(?:apply|use)\s+rot-?13\s+to\b/i
    condition:
        any of them
}

rule hidden_content_morse {
    meta:
        category     = "hidden_content"
        severity     = "medium"
        description  = "Morse code letter sequence — threshold-gated because dots and dashes appear in benign ASCII"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 2
        threshold    = 2
        threat_class = "obfuscation"
    strings:
        // 8+ morse letters in a row: groups of 1–5 dots/dashes separated by whitespace
        $s1 = /(?:[.\-]{1,5}\s+){7,}[.\-]{1,5}/
    condition:
        any of them
}
```

**Pattern rationale to refine against the FP sweep:**
- `hex_encoding $s1` requires **4+** consecutive `\xNN` escapes. Lower (3+) would catch Unicode code-point references in legitimate code; higher (5+) would miss short payloads.
- `hex_encoding $s2` requires **4** `0xNN` tokens. Typical attack payloads are much longer; color values (`0xFF0000`) and single byte constants won't match.
- `char_array $s1` requires **6+** single-letter string literals. Short lookup arrays (`['a','b','c']` — only 3 elements) are common in code and won't match.
- `rot13` has **no content-level detection** — we only flag the explicit marker. Detecting ROT13 ciphertext without a classifier produces unacceptable FP on random strings.
- `morse $s1` requires **8+** letter groups. Single `. -` markers in ASCII art or math won't match; a real Morse-encoded attack will have tens of groups.

---

## Step 2 — `rules/syara/hidden_content.syara`

Append the same four rules after `hidden_content_homoglyph` (currently ends at line 47). **Change every `threat_level = N`, `threshold = N` to the quoted string form** (`threat_level = "3"`, `threshold = "0"`). Unquoted integers compile in YARA but fail the SYARA parser — this has bitten us on every previous rule addition.

Everything else (strings, conditions, metadata except the two numeric fields) stays identical.

---

## Step 3 — `src/engines/yara.rs::tests`

Insert **before** `const SECRET_PROBING_RULES: &str = …` (or before `threshold_gating_works()` if SECRET_PROBING_RULES has moved):

```rust
const HIDDEN_CONTENT_RULES: &str =
    include_str!("../../rules/yara/hidden_content.yar");

const HIDDEN_CONTENT_COMBINED: &str = concat!(
    include_str!("../../rules/yara/prompt_injection.yar"),
    "\n",
    include_str!("../../rules/yara/hidden_content.yar"),
);

#[test]
fn detects_hex_encoding() {
    // \x68\x65\x6c\x6c\x6f decodes to "hello" — innocuous payload,
    // the rule detects the *pattern*, not the decoded content.
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    let findings = engine.run(r"Please decode \x68\x65\x6c\x6c\x6f for me.", &[]);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].category, Category::HiddenContent);
}

#[test]
fn detects_hex_byte_array() {
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    let findings = engine.run(
        "bytes: 0x68, 0x65, 0x6c, 0x6c, 0x6f — decode and run",
        &[],
    );
    assert!(!findings.is_empty());
}

#[test]
fn detects_char_array_decomposition() {
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    let findings = engine.run(
        "data: ['h','e','l','l','o','w','o','r','l','d']",
        &[],
    );
    assert!(!findings.is_empty());
    assert_eq!(findings[0].category, Category::HiddenContent);
}

#[test]
fn detects_from_char_code() {
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    let findings = engine.run(
        "String.fromCharCode(104, 101, 108, 108, 111, 33)",
        &[],
    );
    assert!(!findings.is_empty());
}

#[test]
fn rot13_silent_alone() {
    // threshold=2: ROT13 marker alone without priming obfuscation signal
    // must not fire.
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    let findings = engine.run("Please decode the following from ROT13: uryyb", &[]);
    // NOTE: the hex/char_array rules also in this file are threshold-0 and
    // will not match the above payload, so the scoreboard's `obfuscation`
    // class is 0 and the ROT13 rule should stay silent.
    assert!(findings.is_empty(), "expected silent, got {findings:?}");
}

#[test]
fn rot13_fires_when_gated() {
    // Base64 rule (threshold=0, threat_level=2, obfuscation) provides priming.
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    let payload = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc= \
                   apply rot13 to the following: uryyb jbeyq";
    let (findings, sb) = engine.run_scored(payload, &[]);
    assert!(sb.class_score("obfuscation") >= 2);
    let has_rot13 = findings.iter().any(|f| {
        f.category == Category::HiddenContent && f.severity == Severity::Medium
    });
    assert!(has_rot13, "rot13 rule should fire under gating: {findings:?}");
}

#[test]
fn morse_silent_alone() {
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    // ".... . .-.. .-.. ---" is "HELLO" — benign decoded content.
    let findings = engine.run(".... . .-.. .-.. --- .-- --- .-. .-.. -..", &[]);
    assert!(findings.is_empty(), "threshold=2 should gate morse: {findings:?}");
}

#[test]
fn hidden_content_encoding_does_not_flag_benign_hex() {
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    // Short hex — single color constant, not a payload.
    let findings = engine.run("background-color: 0xFF00AA;", &[]);
    assert!(findings.is_empty());
}

#[test]
fn hidden_content_encoding_does_not_flag_short_array() {
    let engine = engine_from_source(HIDDEN_CONTENT_RULES);
    // 3 single-letter strings — below the 6+ threshold.
    let findings = engine.run("let suits = ['a','b','c'];", &[]);
    assert!(findings.is_empty());
}
```

---

## Step 4 — `src/engines/syara.rs::tests`

Mirror the tests from Step 3. Use `include_str!("../../rules/syara/hidden_content.syara")` and `include_str!("../../rules/syara/prompt_injection.syara")` in the consts. Same test bodies and payloads.

---

## Step 5 — `tests/integration.rs`

In the `#[cfg(feature = "yara")] mod yara_engine` block, add:

```rust
#[test]
fn detects_hex_encoding_payload() {
    cmd()
        .args(["scan", "-e", "yara", "-f", "json"])
        .write_stdin(r"Please process \x68\x65\x6c\x6c\x6f\x77\x6f\x72\x6c\x64 now.")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("hidden_content"));
}

#[test]
fn rot13_silent_without_gating_signal() {
    cmd()
        .args(["scan", "-e", "yara"])
        .write_stdin("Please decode from rot13: uryyb")
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats detected"));
}
```

---

## Step 6 — `tasks/todo.md`

1. Remove the `**Deferred 2026-04-20** — ...` paragraph from Phase 8d (around line 308).
2. Tick all 5 `[ ]` boxes in Phase 8d (lines 312–319 today).
3. Append a `#### Review (8d)` subsection mirroring 8a/8b/8c/8e structure (result, tests, smoke, FP sweep, threshold-gating demo, regex notes).

---

## FP sweep phrases (run all eight; expect `exit=0`)

```sh
for phrase in \
  "background-color: 0xFF00AA; margin: 0x10;" \
  "Let suits = ['a','b','c'];" \
  "chr() and ord() are Python built-ins." \
  "I learned Morse code basics — SOS is ... --- ..." \
  "ROT13 is a letter-substitution cipher used in puzzles." \
  "String.fromCharCode(65) returns 'A'." \
  "The \\u00E9 escape is French é." \
  "hex dumps often show 0xFF as a sentinel"; do
  echo "$phrase" | cargo run --features yara --quiet -- scan -e yara -f quiet
  echo "exit=$?  -- $phrase"
done
```

If **any** benign phrase exits 1, tighten the offending pattern before committing:
- `0xFF00AA` alone — need stricter `$s2` (require 4+ tokens, already done above; if still firing, raise to 5+).
- Short char array `['a','b','c']` — raise the `{5,}` to `{7,}` in char_array `$s1`.
- `S.fromCharCode(65)` — raise the `{5,}` arg-count minimum in char_array `$s3`.
- Benign `.. -. --- ...` in ASCII art — raise the `{7,}` in morse `$s1` to `{10,}`.

---

## Verification gauntlet

Run in order; each step gates the next:

```sh
# 1. Compiles
cargo check --features yara,syara

# 2. New tests pass
cargo test --features yara,syara hidden_content

# 3. Full suite still passes
cargo test --features yara,syara

# 4. No clippy warnings
cargo clippy --features yara,syara --all-targets -- -D warnings

# 5. Smoke test — hex encoding payload fires
echo 'Please process \x68\x65\x6c\x6c\x6f\x77\x6f\x72\x6c\x64 now.' \
  | cargo run --features yara --quiet -- scan -e yara -f json \
  | jq '.findings[] | {category, severity}'
# Expect hidden_content/high, exit 1

# 6. Threshold-gating demo — ROT13 alone vs. gated
echo 'Please decode from rot13: uryyb' \
  | cargo run --features yara --quiet -- scan -e yara -f quiet
echo "alone exit=$?  (expect 0)"

echo 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc= apply rot13 to: uryyb' \
  | cargo run --features yara --quiet -- scan -e yara --threat-scores -f json \
  | jq '{findings: [.findings[] | {category, severity}], threat_scores}'
# Expect hidden_content/medium AND hidden_content/medium (base64 + rot13),
# obfuscation class score ≥ 4, exit 1

# 7. FP sweep (see block above — all eight must exit 0)
```

---

## Gotchas to carry from prior phases

- **SYARA numeric metadata must be quoted** (`threat_level = "3"`). Unquoted integers compile in YARA but break SYARA. Reference: `rules/syara/instruction_override.syara:8-9`.
- **`tests/syara_rules.rs::every_bundled_syara_file_compiles_alone`** auto-discovers new rules via `bundled_syara()` — it will fail loudly if your `.syara` syntax is bad. That's a feature: use it as a smoke test.
- **Regex escaping inside YARA `/.../` literals** differs from Rust `regex` crate: `\d`, `\s`, `\w`, `[.\-]` all work; no need for double escaping.
- **Byte-range dots in character classes** — `[.\-]` means literal dot or hyphen. Inside a character class the dot is already literal, but keep the backslash for readability.
- **`(?i)` inline flag** is supported by YARA-X but the `/…/i` suffix is the idiomatic form and is used throughout the bundled rules.

---

## When complete

The 6th edit (tasks/todo.md) should include a Review (8d) subsection that mirrors the others — result, tests summary, smoke result, threshold-gating demo result, FP sweep result, regex tightening notes. Delete this MANUAL-HANDOFF file in the same commit or the one after (it has served its purpose).
