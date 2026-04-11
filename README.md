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

## Scan Engines

`lcs` ships with three interchangeable scan engines. Select one with `-e` or set `[scan] engine = "..."` in `config.toml`.

| Engine   | Build flag             | How it works                                                                  |
|----------|------------------------|-------------------------------------------------------------------------------|
| `simple` | (default, no feature)  | Hardcoded Rust regex patterns. Zero runtime dependencies. Fastest.            |
| `yara`   | `--features yara`      | YARA-X rule engine ([VirusTotal's pure-Rust YARA](https://github.com/VirusTotal/yara-x)). Rules live in `.yar` files, editable without recompiling. |
| `syara`  | `--features syara`     | SYARA-X (Super YARA), extending YARA with optional semantic matchers (SBERT, classifier, LLM via Ollama). String-only rules are CI-friendly; semantic features are additive. |

```bash
cargo build --release --features yara,syara
lcs scan -e yara <<< "Ignore all previous instructions"
```

## Rules and Customization

The `yara` and `syara` engines load rules from two places, in order:

1. **Bundled rules** — compiled into the binary, covering the same six categories as the `simple` engine.
2. **User rules** — `.yar` / `.syara` files under `$XDG_DATA_HOME/llm_context_shield/rules/{yara,syara}/` (falls back to `~/.local/share/...`). Override the discovery path with `[rules] dir` in `config.toml`; disable bundled rules with `[rules] bundled = false`.

Helpful commands:

```bash
lcs init                    # create config.toml on first run
lcs init --rules            # scaffold the user rules directory tree
lcs list                    # list simple-engine scanner names
lcs list -e yara            # list compiled YARA rule names
lcs scan -e yara --disable prompt_injection_critical   # silence one rule
```

See [docs/rule-authoring.md](docs/rule-authoring.md) for how to write custom rules and [docs/migration-from-simple.md](docs/migration-from-simple.md) for the `simple → yara` mapping.

## Claude Code Integration

The `skill/safe-fetch.md` file is a [Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills) that wires `lcs` into Claude's web-fetching workflow so external content passes through a scan before reaching the model. Install it with:

```bash
bash install-skill.sh
```

This copies the skill to `~/.claude/skills/safe-fetch/SKILL.md` (user-level, available across all projects).

## Architecture

> See [tasks/ARCHITECTURE.md](tasks/ARCHITECTURE.md) for detailed design and Mermaid diagrams.

## License

MIT — see [LICENSE](LICENSE).
