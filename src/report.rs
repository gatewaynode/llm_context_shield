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
/// `show_correlations`: when true, include per-correlation detail blocks in text output.
/// `show_fingerprint`: when true, append the rule-set fingerprint to text-format
/// stderr output. JSON output always includes the fingerprint.
/// JSON output always includes correlations when present, regardless of this flag.
/// Findings details are still written to stderr in text format.
pub fn output(
    report: &ScanReport,
    format: &str,
    min_severity: Severity,
    passthrough_mode: bool,
    show_scores: bool,
    show_correlations: bool,
    show_fingerprint: bool,
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
                "rule_set_fingerprint": report.rule_set_fingerprint.as_str(),
            });
            if let Some(scores) = &report.scores {
                filtered_report["threat_scores"] =
                    serde_json::to_value(scores).unwrap_or_default();
            }
            if !report.correlations.is_empty() {
                filtered_report["correlations"] =
                    serde_json::to_value(&report.correlations).unwrap_or_default();
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
            if show_correlations && !report.correlations.is_empty() {
                for c in &report.correlations {
                    writeln!(
                        err,
                        "[CORRELATION] {name} (level {level}, class {class})",
                        name = c.rule_name,
                        level = c.composite_threat_level,
                        class = c.composite_threat_class,
                    )?;
                    writeln!(err, "  {}", c.explanation)?;
                    writeln!(err, "  contributing findings:")?;
                    for f in &c.findings {
                        writeln!(
                            err,
                            "    [{severity}] {category} at bytes {a}..{b}",
                            severity = f.severity,
                            category = f.category,
                            a = f.byte_range.0,
                            b = f.byte_range.1,
                        )?;
                    }
                    writeln!(err)?;
                }
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
            if show_fingerprint {
                writeln!(err, "rule_set_fingerprint: {}", report.rule_set_fingerprint)?;
            }
            if !passthrough_mode {
                let stdout = io::stdout();
                let mut out = stdout.lock();
                let n_corr = report.correlations.len();
                if filtered.is_empty() {
                    if n_corr == 0 {
                        writeln!(out, "No threats detected.")?;
                    } else {
                        writeln!(out, "No threats detected, {n_corr} correlation(s).")?;
                    }
                } else if n_corr == 0 {
                    writeln!(out, "{} threat(s) detected.", filtered.len())?;
                } else {
                    writeln!(
                        out,
                        "{} threat(s) detected, {n_corr} correlation(s).",
                        filtered.len()
                    )?;
                }
            }
        }
    }
    Ok(())
}
