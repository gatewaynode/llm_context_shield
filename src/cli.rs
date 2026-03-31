use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "llm_context_shield",
    about = "Scan text for LLM context injection threats"
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

        /// Disable specific scanners (comma-separated)
        #[arg(long, value_delimiter = ',')]
        disable: Vec<String>,
    },
}
