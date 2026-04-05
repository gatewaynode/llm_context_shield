use tracing::{debug, info};

use super::Engine;
use crate::scanner::Finding;
use crate::scanners;

/// Regex-based scanner engine — the original scan strategy.
///
/// Builds the full set of regex scanners (minus any listed in `disabled`),
/// runs each one in sequence, and collects all findings.
pub struct SimpleEngine;

impl Engine for SimpleEngine {
    fn name(&self) -> &'static str {
        "simple"
    }

    fn run(&self, input: &str, disabled: &[String]) -> Vec<Finding> {
        let scanners = scanners::build(disabled);
        info!(
            scanners = ?scanners.iter().map(|s| s.name()).collect::<Vec<_>>(),
            "scanners active"
        );
        let mut findings = Vec::new();
        for scanner in &scanners {
            let before = findings.len();
            let _s = tracing::debug_span!("scanner", name = scanner.name()).entered();
            findings.extend(scanner.scan(input));
            debug!(findings = findings.len() - before, "complete");
        }
        findings
    }
}
