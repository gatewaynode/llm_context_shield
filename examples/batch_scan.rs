use llm_context_shield::scan_group::ScanGroup;
use llm_context_shield::Shield;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn collect_inputs(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    if !root.is_dir() {
        return Err(format!("{}: not a file or directory", root.display()).into());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(root)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !n.starts_with('.'))
        })
        .filter(|p| !is_likely_binary(p))
        .collect();
    paths.sort();
    Ok(paths)
}

fn is_likely_binary(path: &Path) -> bool {
    // TODO(future): real binary analysis hook — for now, null-byte sniff in first 8 KiB.
    let Ok(bytes) = fs::read(path) else {
        return true;
    };
    bytes.iter().take(8192).any(|&b| b == 0)
}

fn main() -> Result<(), Box<dyn Error>> {
    let arg = std::env::args()
        .nth(1)
        .ok_or("usage: batch_scan <file-or-directory>")?;
    let root = PathBuf::from(arg);

    let paths = collect_inputs(&root)?;
    if paths.is_empty() {
        eprintln!(
            "Error: no scannable text files found at {}",
            root.display()
        );
        std::process::exit(2);
    }

    let shield = Shield::builder().build()?;
    let mut group = ScanGroup::new();
    for p in &paths {
        group = group.add_file(p)?;
    }

    let report = shield.scan_group(&group);
    for (label, scan) in &report.per_input {
        println!("[{label}] {} finding(s)", scan.findings.len());
    }
    for corr in &report.cross_input_correlations {
        println!(
            "CROSS-INPUT: {} (level {}, class {})",
            corr.rule_name, corr.composite_threat_level, corr.composite_threat_class
        );
    }
    if let Some(label) = &report.summary.worst_offender_label {
        println!(
            "Worst offender: {label} (cumulative {})",
            report.summary.worst_offender_cumulative
        );
    } else {
        println!(
            "No threats detected across {} input(s).",
            report.per_input.len()
        );
    }
    Ok(())
}
