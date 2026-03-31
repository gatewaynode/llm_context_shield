use std::process;

use clap::Parser;
use tracing::{debug, error, info};

use llm_context_shield::cli::{Cli, Command};
use llm_context_shield::input::read_input;
use llm_context_shield::report::output;
use llm_context_shield::scanner::{ScanReport, Severity};
use llm_context_shield::scanners;

fn main() {
    let cli = Cli::parse();

    if cli.log
        && let Err(e) = llm_context_shield::logging::init()
    {
        eprintln!("Warning: could not initialise log: {e}");
    }

    info!(version = env!("CARGO_PKG_VERSION"), "starting");

    match cli.command {
        Command::Scan {
            file,
            format,
            severity,
            disable,
        } => {
            let _scan =
                tracing::info_span!("scan", file = ?file, format = %format, severity = %severity)
                    .entered();

            let min_severity = Severity::from_str_loose(&severity).unwrap_or_else(|| {
                error!(value = %severity, "invalid severity");
                eprintln!("Invalid severity: {severity}. Use: low, medium, high, critical");
                process::exit(2);
            });

            if !matches!(format.as_str(), "json" | "text" | "quiet") {
                error!(value = %format, "invalid format");
                eprintln!("Invalid format: {format}. Use: json, text, quiet");
                process::exit(2);
            }

            let input = match read_input(file.as_deref()) {
                Ok(text) => text,
                Err(e) => {
                    error!(error = %e, "failed to read input");
                    eprintln!("Error reading input: {e}");
                    process::exit(2);
                }
            };

            let scanners = scanners::build(&disable);
            info!(
                scanners = ?scanners.iter().map(|s| s.name()).collect::<Vec<_>>(),
                "scanners active"
            );

            let mut findings = Vec::new();
            for scanner in &scanners {
                let before = findings.len();
                let _s = tracing::debug_span!("scanner", name = scanner.name()).entered();
                findings.extend(scanner.scan(&input));
                debug!(findings = findings.len() - before, "complete");
            }

            info!(total = findings.len(), "scan complete");

            let filtered_count = findings
                .iter()
                .filter(|f| f.severity >= min_severity)
                .count();
            info!(
                format = %format,
                min_severity = %min_severity,
                filtered = filtered_count,
                "output"
            );

            let report = ScanReport::from_findings(findings);

            if let Err(e) = output(&report, &format, min_severity) {
                error!(error = %e, "failed to write output");
                eprintln!("Error writing output: {e}");
                process::exit(2);
            }

            let has_findings = report.findings.iter().any(|f| f.severity >= min_severity);
            let exit_code = if has_findings { 1 } else { 0 };
            info!(exit_code, "exit");
            process::exit(exit_code);
        }
    }
}
