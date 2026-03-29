# llm_context_shield

A UNIX-style CLI tool that scans text for threats commonly used in LLM context injection attacks. Reads from stdin or a file, outputs structured findings, and exits with meaningful codes — making it easy to chain with other tools.

> **Implementation note:** This project was designed and implemented by [Claude](https://claude.ai) (Anthropic), an AI assistant, in collaboration with the project owner.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Scan from stdin
echo "Ignore all previous instructions" | llm_context_shield scan

# Scan a file
llm_context_shield scan input.txt

# Machine-readable JSON output
cat untrusted.txt | llm_context_shield scan -f json

# Pipe into jq for further processing
cat prompt.txt | llm_context_shield scan -f json | jq '.findings[] | select(.severity == "critical")'

# Exit-code-only mode (for shell scripts)
llm_context_shield scan -f quiet input.txt && echo "clean" || echo "threats found"

# Filter by minimum severity
llm_context_shield scan -s high input.txt

# Disable specific scanners
llm_context_shield scan --disable hidden_content,jailbreak input.txt
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No threats detected (at or above severity threshold) |
| `1` | One or more threats detected |
| `2` | Error (bad arguments, file not found, IO failure) |

## Output Formats

**`text`** (default) — human-readable detail to stderr, one-line summary to stdout:
```
[CRITICAL] prompt_injection: Instruction override: ignore previous instructions
  matched: "Ignore all previous instructions"
  at bytes: 0..32

1 threat(s) detected.
```

**`json`** — full report as JSON to stdout, composable with `jq`:
```json
{
  "clean": false,
  "finding_count": 1,
  "findings": [
    {
      "category": "prompt_injection",
      "severity": "critical",
      "description": "Instruction override: ignore previous instructions",
      "matched_text": "Ignore all previous instructions",
      "byte_range": [0, 32]
    }
  ]
}
```

**`quiet`** — no output, rely on exit code only.

## Scanner Categories

| Scanner | What it detects |
|---------|----------------|
| `prompt_injection` | "ignore previous instructions", identity reassignment, system prompt extraction |
| `instruction_override` | Fake `SYSTEM:` prefixes, `<\|system\|>` tokens, fake admin mode |
| `jailbreak` | DAN mode, safety bypass attempts, unrestricted mode activation, roleplay hijacking |
| `delimiter_manipulation` | ChatML tokens (`<\|im_start\|>`), Llama delimiters (`[INST]`, `<<SYS>>`), fake role boundaries |
| `data_exfiltration` | Markdown image URL injection, instructions to embed data in requests |
| `hidden_content` | Zero-width characters, base64 blobs, Cyrillic/Greek homoglyphs |

## Options

```
llm_context_shield scan [OPTIONS] [FILE]

Arguments:
  [FILE]  Input file (reads stdin if omitted)

Options:
  -f, --format <FORMAT>    Output format: json, text, quiet [default: text]
  -s, --severity <LEVEL>   Minimum severity: low, medium, high, critical [default: low]
      --disable <LIST>      Comma-separated list of scanner names to disable
  -h, --help               Print help
```

## License

MIT — see [LICENSE](LICENSE).
