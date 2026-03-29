use std::process;

use clap::Parser;

use llm_context_shield::cli::{Cli, Command};
use llm_context_shield::input::read_input;
use llm_context_shield::report::output;
use llm_context_shield::scanner::{ScanReport, Severity};
use llm_context_shield::scanners;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            file,
            format,
            severity,
            disable,
        } => {
            let min_severity = Severity::from_str_loose(&severity).unwrap_or_else(|| {
                eprintln!("Invalid severity: {severity}. Use: low, medium, high, critical");
                process::exit(2);
            });

            if !matches!(format.as_str(), "json" | "text" | "quiet") {
                eprintln!("Invalid format: {format}. Use: json, text, quiet");
                process::exit(2);
            }

            let input = match read_input(file.as_deref()) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("Error reading input: {e}");
                    process::exit(2);
                }
            };

            let scanners = scanners::build(&disable);
            let mut findings = Vec::new();
            for scanner in &scanners {
                findings.extend(scanner.scan(&input));
            }

            let report = ScanReport::from_findings(findings);

            if let Err(e) = output(&report, &format, min_severity) {
                eprintln!("Error writing output: {e}");
                process::exit(2);
            }

            let has_findings = report
                .findings
                .iter()
                .any(|f| f.severity >= min_severity);

            process::exit(if has_findings { 1 } else { 0 });
        }
    }
}
