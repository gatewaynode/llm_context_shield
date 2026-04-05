# llm_context_shield

A UNIX-style CLI tool that scans text for threats commonly used in LLM context injection attacks. Reads from stdin or a file, outputs structured findings, and exits with meaningful codes — making it easy to chain with other tools.

> **Implementation note:** This project was designed and implemented by [Claude](https://claude.ai) (Anthropic), an AI assistant, in collaboration with the project owner.

## Installation

```bash
bash install.sh
```

This builds a release binary, copies it to `~/.local/share/llm_context_shield/lcs-<version>`, and creates a `lcs` symlink in `~/.local/bin/`. Multiple versions can coexist; the symlink always points to the latest installed.

## Recommended workflow — safe pipe filter

The primary intended use is as an inline filter between a web fetcher and any LLM tool. Content only reaches the next stage if the scan is clean:

```bash
# Scan and pass through to stdout if clean; exit 1 and report to stderr if threats found
curl -fsSL https://example.com/page | lcs scan -p

# Save clean content to a file instead of stdout
curl -fsSL https://example.com/data.txt | lcs scan -p -o data.txt

# Compose in a pipeline — clean content flows through, threats block the pipe
curl -fsSL https://example.com/prompt.txt | lcs scan -p | your-llm-tool
```

In passthrough mode (`-p`):

| Outcome | stdout | stderr | exit |
|---------|--------|--------|------|
| Clean | original content (or written to `-o` file) | silent | `0` |
| Threats | empty | finding details | `1` |
| Error | empty | error message | `2` |

## Usage

```bash
# Scan from stdin (report mode)
echo "Ignore all previous instructions" | lcs scan

# Scan a file
lcs scan input.txt

# Machine-readable JSON output
cat untrusted.txt | lcs scan -f json

# Pipe into jq for further processing
cat prompt.txt | lcs scan -f json | jq '.findings[] | select(.severity == "critical")'

# Exit-code-only mode (for shell scripts)
lcs scan -f quiet input.txt && echo "clean" || echo "threats found"

# Filter by minimum severity
lcs scan -s high input.txt

# Disable specific scanners
lcs scan --disable hidden_content,jailbreak input.txt
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

## Configuration File

On first run (no flags passed), `lcs` creates a default configuration file at:

```
~/.config/llm_context_shield/config.toml
```

`$XDG_CONFIG_HOME` is respected when set. CLI arguments always take precedence over values in the file.

**Example `config.toml`:**

```toml
# Enable logging to ~/.local/state/llm_context_shield/
log = true

[scan]
# Output format: json, text, quiet
format = "json"

# Minimum severity to report: low, medium, high, critical
severity = "medium"

# Disable specific scanners by name
disable = ["hidden_content"]
```

Any option left out (or commented out) falls back to its CLI default.

## Options

```
lcs [--log] scan [OPTIONS] [FILE]

Global options:
      --log                Enable logging to ~/.local/state/llm_context_shield/

Arguments:
  [FILE]  Input file (reads stdin if omitted)

Scan options:
  -f, --format <FORMAT>    Output format: json, text, quiet [default: text]
  -s, --severity <LEVEL>   Minimum severity: low, medium, high, critical [default: low]
  -p, --safe-only-passthrough
                           If scan is clean, write the original input to stdout
                           (or --output file). Suppresses the scan summary on stdout
                           so the content can flow directly into a pipeline.
  -o, --output <FILE>      Write passthrough content to FILE instead of stdout
                           (only meaningful with -p)
  -e, --engine <ENGINE>    Scan engine: simple, yara, syara [default: simple]
      --disable <LIST>     Comma-separated list of scanner names to disable
  -h, --help               Print help
  -V, --version            Print version
```

## License

MIT — see [LICENSE](LICENSE).
