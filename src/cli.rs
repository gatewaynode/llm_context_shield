use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "lcs",
    about = "Scan text for LLM context injection threats",
    version
)]
pub struct Cli {
    /// Enable logging to ~/.local/state/llm_context_shield/llm_context_shield.log
    #[arg(long)]
    pub log: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan input text for threats
    Scan {
        /// Input file (reads stdin if omitted)
        file: Option<PathBuf>,

        /// Output format: json, text, quiet  [default: text]
        #[arg(short, long)]
        format: Option<String>,

        /// Minimum severity to report: low, medium, high, critical  [default: low]
        #[arg(short, long)]
        severity: Option<String>,

        /// Disable specific scanners or rules (comma-separated)
        #[arg(long, value_delimiter = ',')]
        disable: Vec<String>,

        /// Scan engine: simple, yara, syara  [default: simple]
        #[arg(short = 'e', long)]
        engine: Option<String>,

        /// If scan is clean, write the original input to stdout (or --output file)
        #[arg(short = 'p', long)]
        safe_only_passthrough: bool,

        /// Write passthrough content to FILE instead of stdout (requires --safe-only-passthrough)
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Include threat scores in output (always included with -f json when scores are present)
        #[arg(long)]
        threat_scores: bool,

        /// Show per-correlation detail in text output (correlations are always present in JSON)
        #[arg(long)]
        correlations: bool,

        /// Append the rule-set fingerprint to text output (always present in JSON output)
        #[arg(long)]
        show_fingerprint: bool,
    },

    /// Scaffold config and/or rules directories under XDG paths.
    ///
    /// With no flags, ensures the config dir and default `config.toml` exist.
    /// With `--rules`, additionally scaffolds `<rules_dir>/{yara,syara}/` and
    /// writes a README stub explaining how to drop custom rule files.
    Init {
        /// Also create the rules directory tree (`yara/`, `syara/`) with a README stub.
        #[arg(long)]
        rules: bool,
    },

    /// List available scanner or rule names (for use with --disable)
    ///
    /// With no engine flag, lists the built-in `simple` scanner names.
    /// With `-e yara` or `-e syara`, lists rule names compiled into the
    /// corresponding engine (bundled + discovered).
    List {
        /// Engine whose rule names should be listed: simple, yara, syara
        #[arg(short = 'e', long)]
        engine: Option<String>,
    },

    /// Inspect the loaded rule set: rule list, categories, threat classes, fingerprint.
    ///
    /// Builds the same `Shield` `lcs scan` would use (same config flow, same
    /// rules dir, same engine selection) so the rule set described here is
    /// the one a scan would actually run against. View flags
    /// (`--categories`, `--threat-classes`, `--json`, `--fingerprint`) are
    /// mutually exclusive; default is the human-readable rule list.
    Rules {
        /// Engine to inspect: simple, yara, syara
        #[arg(short = 'e', long)]
        engine: Option<String>,

        /// Print the category set the configured shield can emit, one per line
        #[arg(long, group = "rules_view")]
        categories: bool,

        /// Print the threat-class set the configured shield can emit, one per line
        #[arg(long = "threat-classes", group = "rules_view")]
        threat_classes: bool,

        /// Emit JSON: {"fingerprint": "<hex>", "rules": [<rule>...]}
        #[arg(long, group = "rules_view")]
        json: bool,

        /// Print just the rule-set fingerprint as a single hex line
        #[arg(long, group = "rules_view")]
        fingerprint: bool,
    },
}
