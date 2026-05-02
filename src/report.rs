use std::io::{self, Write};
use std::path::Path;

use crate::scan_group::GroupReport;
use crate::scanner::{ScanReport, Severity};
use crate::scoring::ThreatScoreboard;

/// Build the per-scan JSON shape: `clean`, `finding_count`, `findings`,
/// `threat_scores`, plus optional `correlations` and `rule_set_fingerprint`.
///
/// Used by both the single-scan `output` path and the scan-group handler's
/// per-input embedding. `include_fingerprint = true` matches the single-scan
/// shape; the scan-group caller passes `false` because the fingerprint is
/// lifted to the top-level group document (all per-input reports share the
/// same Shield).
pub fn render_scan_report_json(
    report: &ScanReport,
    min_severity: Severity,
    include_fingerprint: bool,
) -> serde_json::Value {
    let filtered: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();
    let mut json = serde_json::json!({
        "clean": filtered.is_empty(),
        "finding_count": filtered.len(),
        "findings": filtered,
    });
    if include_fingerprint {
        json["rule_set_fingerprint"] =
            serde_json::Value::String(report.rule_set_fingerprint.as_str().to_string());
    }
    let scores_owned;
    let scores = match &report.scores {
        Some(s) => s,
        None => {
            scores_owned = ThreatScoreboard::default();
            &scores_owned
        }
    };
    json["threat_scores"] = serde_json::to_value(scores).unwrap_or_default();
    if !report.correlations.is_empty() {
        json["correlations"] = serde_json::to_value(&report.correlations).unwrap_or_default();
    }
    json
}

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
            let json = render_scan_report_json(report, min_severity, true);
            let stdout = io::stdout();
            let mut out = stdout.lock();
            serde_json::to_writer_pretty(&mut out, &json)
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
                if !f.rule_name.is_empty() {
                    writeln!(err, "  rule: {} (engine: {})", f.rule_name, f.engine)?;
                }
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

/// Build the top-level JSON document for a scan-group invocation.
///
/// Lifts the rule-set fingerprint to the top level (all per-input reports
/// share the same Shield, so emitting it once is the right shape), and
/// embeds each per-input `ScanReport` under a `{"label", "report"}` object
/// using [`render_scan_report_json`] with `include_fingerprint=false`.
pub fn render_group_json(group: &GroupReport, min_severity: Severity) -> serde_json::Value {
    let per_input: Vec<serde_json::Value> = group
        .per_input
        .iter()
        .map(|(label, report)| {
            serde_json::json!({
                "label": label,
                "report": render_scan_report_json(report, min_severity, false),
            })
        })
        .collect();

    let fingerprint = group
        .per_input
        .first()
        .map(|(_, r)| r.rule_set_fingerprint.as_str().to_string())
        .unwrap_or_default();

    serde_json::json!({
        "rule_set_fingerprint": fingerprint,
        "per_input": per_input,
        "aggregate_scoreboard":
            serde_json::to_value(&group.aggregate_scoreboard).unwrap_or_default(),
        "cross_input_correlations":
            serde_json::to_value(&group.cross_input_correlations).unwrap_or_default(),
        "summary": {
            "total_findings": group.summary.total_findings,
            "distinct_threat_classes": group.summary.distinct_threat_classes,
            "worst_offender_label": group.summary.worst_offender_label,
            "worst_offender_cumulative": group.summary.worst_offender_cumulative,
        },
    })
}

/// Write the human-readable scan-group report to stderr (per-input blocks,
/// aggregate scores, cross-input correlations, fingerprint) and the summary
/// line to stdout. Mirrors the stderr-details / stdout-summary split of
/// [`output`] in single-scan mode.
pub fn output_group_text(
    group: &GroupReport,
    show_scores: bool,
    show_correlations: bool,
    show_fingerprint: bool,
) -> io::Result<()> {
    let stderr = io::stderr();
    let mut err = stderr.lock();

    for (label, report) in &group.per_input {
        let n = report.findings.len();
        match report.findings.iter().map(|f| f.severity).max() {
            Some(worst) => writeln!(err, "[{label}] {n} finding(s), worst severity: {worst}")?,
            None => writeln!(err, "[{label}] 0 finding(s)")?,
        }
        if show_correlations && !report.correlations.is_empty() {
            for c in &report.correlations {
                writeln!(
                    err,
                    "  [CORRELATION] {} (level {}, class {})",
                    c.rule_name, c.composite_threat_level, c.composite_threat_class,
                )?;
                writeln!(err, "    {}", c.explanation)?;
            }
        }
    }
    writeln!(err)?;

    if show_scores && !group.aggregate_scoreboard.is_empty() {
        writeln!(err, "Aggregate:")?;
        writeln!(
            err,
            "  cumulative: {}",
            group.aggregate_scoreboard.cumulative_score()
        )?;
        for (class, score) in group.aggregate_scoreboard.class_scores() {
            writeln!(err, "  {class}: {score}")?;
        }
        writeln!(err)?;
    }

    if show_correlations && !group.cross_input_correlations.is_empty() {
        writeln!(err, "Cross-input correlations:")?;
        for c in &group.cross_input_correlations {
            writeln!(
                err,
                "  [CORRELATION] {} (level {}, class {})",
                c.rule_name, c.composite_threat_level, c.composite_threat_class,
            )?;
            writeln!(err, "    {}", c.explanation)?;
            writeln!(err, "    contributing findings:")?;
            for f in &c.findings {
                writeln!(
                    err,
                    "      [{}] {} (engine: {}) at bytes {}..{}",
                    f.severity, f.category, f.engine, f.byte_range.0, f.byte_range.1,
                )?;
            }
        }
        writeln!(err)?;
    }

    if show_fingerprint
        && let Some((_, first)) = group.per_input.first()
    {
        writeln!(err, "rule_set_fingerprint: {}", first.rule_set_fingerprint)?;
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let n_inputs = group.per_input.len();
    let total = group.summary.total_findings;
    let n_cross = group.cross_input_correlations.len();
    if total == 0 && n_cross == 0 {
        writeln!(
            out,
            "Summary: No threats detected across {n_inputs} input(s)."
        )?;
    } else {
        let mut line = format!("Summary: {total} total finding(s) across {n_inputs} input(s)");
        if n_cross > 0 {
            line.push_str(&format!(", {n_cross} cross-input correlation(s)"));
        }
        if let Some(label) = &group.summary.worst_offender_label {
            line.push_str(&format!(
                "; worst offender: {label} (cumulative {})",
                group.summary.worst_offender_cumulative
            ));
        }
        line.push('.');
        writeln!(out, "{line}")?;
    }
    Ok(())
}
