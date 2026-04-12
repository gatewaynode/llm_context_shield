use std::io::{self, Write};
use std::path::Path;

use crate::scanner::{ScanReport, Severity};

/// Write `input` to `output_file` (or stdout if `None`). Called only when scan is clean.
pub fn write_passthrough(input: &str, output_file: Option<&Path>) -> io::Result<()> {
    match output_file {
        Some(path) => std::fs::write(path, input)?,
        None => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            write!(out, "{input}")?;
        }
    }
    Ok(())
}

/// `passthrough_mode`: when true, suppress the stdout summary line so the pipe stays clean.
/// `show_scores`: when true, include threat scores in output.
/// Findings details are still written to stderr in text format.
pub fn output(
    report: &ScanReport,
    format: &str,
    min_severity: Severity,
    passthrough_mode: bool,
    show_scores: bool,
) -> io::Result<()> {
    let filtered: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();

    match format {
        "json" => {
            let mut filtered_report = serde_json::json!({
                "clean": filtered.is_empty(),
                "finding_count": filtered.len(),
                "findings": filtered,
            });
            if let Some(scores) = &report.scores {
                filtered_report["threat_scores"] =
                    serde_json::to_value(scores).unwrap_or_default();
            }
            let stdout = io::stdout();
            let mut out = stdout.lock();
            serde_json::to_writer_pretty(&mut out, &filtered_report)
                .map_err(|e| io::Error::other(format!("JSON serialisation failed: {e}")))?;
            writeln!(out)?;
        }
        "quiet" => {}
        _ => {
            // text format: findings details to stderr, summary to stdout
            // In passthrough mode the summary is suppressed to keep stdout clean for piping.
            let stderr = io::stderr();
            let mut err = stderr.lock();
            for f in &filtered {
                writeln!(
                    err,
                    "[{severity}] {category}: {desc}",
                    severity = f.severity,
                    category = f.category,
                    desc = f.description,
                )?;
                writeln!(err, "  matched: {:?}", f.matched_text)?;
                writeln!(err, "  at bytes: {}..{}", f.byte_range.0, f.byte_range.1)?;
                writeln!(err)?;
            }
            if show_scores
                && let Some(scores) = &report.scores
            {
                writeln!(err, "Threat scores:")?;
                writeln!(err, "  cumulative: {}", scores.cumulative_score())?;
                for (class, score) in scores.class_scores() {
                    writeln!(err, "  {class}: {score}")?;
                }
                writeln!(err)?;
            }
            if !passthrough_mode {
                let stdout = io::stdout();
                let mut out = stdout.lock();
                if filtered.is_empty() {
                    writeln!(out, "No threats detected.")?;
                } else {
                    writeln!(out, "{} threat(s) detected.", filtered.len())?;
                }
            }
        }
    }
    Ok(())
}
