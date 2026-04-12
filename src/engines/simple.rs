use tracing::{debug, info};

use super::Engine;
use crate::config::{Config, ScoringConfig};
use crate::scanner::Finding;
use crate::scoring::{apply_threshold_filter, ScoredCandidate, ThreatMeta, ThreatScoreboard};
use crate::scanners;

/// Regex-based scanner engine — the original scan strategy.
///
/// Builds the full set of regex scanners (minus any listed in `disabled`),
/// runs each one in sequence, and collects all findings. All SimpleEngine
/// findings use threshold-0 (always run), so scoring accumulates but never
/// gates — the simple engine is not the place for threshold sophistication.
pub struct SimpleEngine {
    scoring: ScoringConfig,
}

impl SimpleEngine {
    pub fn new(config: &Config) -> Self {
        Self {
            scoring: config.scoring.clone().unwrap_or_default(),
        }
    }
}

impl Engine for SimpleEngine {
    fn name(&self) -> &'static str {
        "simple"
    }

    fn run(&self, input: &str, disabled: &[String]) -> Vec<Finding> {
        self.run_scored(input, disabled).0
    }

    fn run_scored(&self, input: &str, disabled: &[String]) -> (Vec<Finding>, ThreatScoreboard) {
        let scanners = scanners::build(disabled);
        info!(
            scanners = ?scanners.iter().map(|s| s.name()).collect::<Vec<_>>(),
            "scanners active"
        );
        let mut candidates = Vec::new();
        for scanner in &scanners {
            let before = candidates.len();
            let _s = tracing::debug_span!("scanner", name = scanner.name()).entered();
            for finding in scanner.scan(input) {
                let meta = ThreatMeta::with_defaults(&finding.category.to_string());
                candidates.push(ScoredCandidate { finding, meta });
            }
            debug!(findings = candidates.len() - before, "complete");
        }
        apply_threshold_filter(candidates, ThreatScoreboard::from_config(&self.scoring))
    }
}
