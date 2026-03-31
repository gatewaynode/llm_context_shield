use std::io::{self, Write};

use crate::scanner::{ScanReport, Severity};

pub fn output(report: &ScanReport, format: &str, min_severity: Severity) -> io::Result<()> {
    let filtered: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();

    match format {
        "json" => {
            let filtered_report = serde_json::json!({
                "clean": filtered.is_empty(),
                "finding_count": filtered.len(),
                "findings": filtered,
            });
            let stdout = io::stdout();
            let mut out = stdout.lock();
            serde_json::to_writer_pretty(&mut out, &filtered_report)
                .map_err(|e| io::Error::other(format!("JSON serialisation failed: {e}")))?;
            writeln!(out)?;
        }
        "quiet" => {}
        _ => {
            // text format: details to stderr, summary to stdout
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
            let stdout = io::stdout();
            let mut out = stdout.lock();
            if filtered.is_empty() {
                writeln!(out, "No threats detected.")?;
            } else {
                writeln!(out, "{} threat(s) detected.", filtered.len())?;
            }
        }
    }
    Ok(())
}
