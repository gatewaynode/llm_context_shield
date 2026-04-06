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
    },

    /// List available scanner names (for use with --disable)
    List,
}
