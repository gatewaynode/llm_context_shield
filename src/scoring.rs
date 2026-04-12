//! Threat scoring engine for multi-pass, threshold-gated scanning.
//!
//! Rules declare a [`ThreatMeta`] that controls when they activate and how
//! much they contribute to the cumulative threat score. The
//! [`ThreatScoreboard`] tracks per-class and global accumulators as rules
//! match. `apply_threshold_filter` processes candidates in threshold order,
//! emitting only those whose class has accumulated enough suspicion.

use std::collections::BTreeMap;
use std::collections::HashMap;

use serde::Serialize;

use crate::config::ScoringConfig;
use crate::scanner::Finding;

/// Metadata parsed from rule `meta:` blocks that drives the scoring engine.
///
/// Not part of the public [`Finding`] type — used internally during engine
/// execution via `ScoredCandidate`.
#[derive(Debug, Clone)]
pub struct ThreatMeta {
    /// Score this rule contributes to accumulators when it matches.
    pub threat_level: i32,
    /// Minimum accumulated score in this rule's threat class before the rule
    /// is evaluated. Threshold-0 rules always run.
    pub threshold: i32,
    /// Heuristic branch this rule belongs to (e.g. `prompt_hijack`,
    /// `obfuscation`). One rule = one class.
    pub threat_class: String,
}

impl ThreatMeta {
    /// Construct with sensible defaults for rules that lack the new metadata.
    pub fn with_defaults(category_name: &str) -> Self {
        Self {
            threat_level: 1,
            threshold: 0,
            threat_class: category_name.to_string(),
        }
    }
}

/// Accumulates threat scores per-class and globally during a scan.
///
/// Serializes to JSON with `class_scores` and `cumulative` fields.
/// Internal configuration (weights, escalation) is excluded from output.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatScoreboard {
    class_scores: BTreeMap<String, i32>,
    cumulative: i32,
    #[serde(skip)]
    class_weights: HashMap<String, f32>,
    #[serde(skip)]
    escalation_threshold: i32,
    #[serde(skip)]
    escalation_reduction: i32,
}

impl ThreatScoreboard {
    /// Create a scoreboard with default settings (escalation inert).
    pub fn new() -> Self {
        Self {
            class_scores: BTreeMap::new(),
            cumulative: 0,
            class_weights: HashMap::new(),
            escalation_threshold: 100,
            escalation_reduction: 0,
        }
    }

    /// Create a scoreboard from user configuration.
    pub fn from_config(config: &ScoringConfig) -> Self {
        Self {
            class_scores: BTreeMap::new(),
            cumulative: 0,
            class_weights: config.class_weights.clone().unwrap_or_default(),
            escalation_threshold: config.escalation_threshold.unwrap_or(100),
            escalation_reduction: config.escalation_reduction.unwrap_or(0),
        }
    }

    /// Record a match: update the class accumulator and the weighted global.
    pub fn record(&mut self, threat_class: &str, threat_level: i32) {
        let entry = self.class_scores.entry(threat_class.to_string()).or_insert(0);
        *entry = entry.saturating_add(threat_level);
        let weight = self.class_weights.get(threat_class).copied().unwrap_or(1.0);
        let weighted = (threat_level as f32 * weight).round() as i32;
        self.cumulative = self.cumulative.saturating_add(weighted);
    }

    /// Current score for one threat class.
    pub fn class_score(&self, threat_class: &str) -> i32 {
        self.class_scores.get(threat_class).copied().unwrap_or(0)
    }

    /// Global weighted total across all classes.
    pub fn cumulative_score(&self) -> i32 {
        self.cumulative
    }

    /// Whether a rule with the given threshold and class should be included.
    pub fn should_run(&self, threshold: i32, threat_class: &str) -> bool {
        if threshold == 0 {
            return true;
        }
        let effective = self.effective_threshold(threshold, threat_class);
        self.class_score(threat_class) >= effective
    }

    /// True when no scores have been recorded.
    pub fn is_empty(&self) -> bool {
        self.cumulative == 0
    }

    /// Iterator over `(class_name, score)` pairs for display/reporting.
    pub fn class_scores(&self) -> impl Iterator<Item = (&str, i32)> {
        self.class_scores.iter().map(|(k, &v)| (k.as_str(), v))
    }

    /// Cross-branch escalation: if any *other* class exceeds
    /// `escalation_threshold`, reduce this rule's effective threshold.
    fn effective_threshold(&self, threshold: i32, threat_class: &str) -> i32 {
        let any_escalated = self
            .class_scores
            .iter()
            .any(|(cls, &score)| cls != threat_class && score >= self.escalation_threshold);
        if any_escalated {
            (threshold - self.escalation_reduction).max(0)
        } else {
            threshold
        }
    }
}

impl Default for ThreatScoreboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal pairing of a [`Finding`] with its [`ThreatMeta`], used during
/// scoring inside engine `run_scored()` implementations.
pub(crate) struct ScoredCandidate {
    pub finding: Finding,
    pub meta: ThreatMeta,
}

/// Process candidates in threshold order: threshold-0 matches score first,
/// unlocking higher tiers. Returns the filtered findings and the final
/// scoreboard state.
pub(crate) fn apply_threshold_filter(
    mut candidates: Vec<ScoredCandidate>,
    mut scoreboard: ThreatScoreboard,
) -> (Vec<Finding>, ThreatScoreboard) {
    // Stable sort preserves rule order within the same threshold tier.
    candidates.sort_by_key(|c| c.meta.threshold);

    let mut findings = Vec::new();
    for candidate in candidates {
        if scoreboard.should_run(candidate.meta.threshold, &candidate.meta.threat_class) {
            scoreboard.record(&candidate.meta.threat_class, candidate.meta.threat_level);
            findings.push(candidate.finding);
        }
    }

    (findings, scoreboard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_meta_defaults() {
        let meta = ThreatMeta::with_defaults("prompt_injection");
        assert_eq!(meta.threat_level, 1);
        assert_eq!(meta.threshold, 0);
        assert_eq!(meta.threat_class, "prompt_injection");
    }

    #[test]
    fn scoreboard_record_and_query() {
        let mut sb = ThreatScoreboard::new();
        assert!(sb.is_empty());
        assert_eq!(sb.class_score("prompt_hijack"), 0);

        sb.record("prompt_hijack", 5);
        assert_eq!(sb.class_score("prompt_hijack"), 5);
        assert_eq!(sb.cumulative_score(), 5);
        assert!(!sb.is_empty());

        sb.record("prompt_hijack", 3);
        assert_eq!(sb.class_score("prompt_hijack"), 8);
        assert_eq!(sb.cumulative_score(), 8);
    }

    #[test]
    fn scoreboard_independent_classes() {
        let mut sb = ThreatScoreboard::new();
        sb.record("prompt_hijack", 5);
        sb.record("obfuscation", 2);
        assert_eq!(sb.class_score("prompt_hijack"), 5);
        assert_eq!(sb.class_score("obfuscation"), 2);
        assert_eq!(sb.cumulative_score(), 7);
    }

    #[test]
    fn scoreboard_weight_dampening() {
        let config = ScoringConfig {
            escalation_threshold: None,
            escalation_reduction: None,
            class_weights: Some(HashMap::from([("noisy".into(), 0.5)])),
        };
        let mut sb = ThreatScoreboard::from_config(&config);
        sb.record("noisy", 10);
        // Class score is raw (unweighted)
        assert_eq!(sb.class_score("noisy"), 10);
        // Cumulative is weighted: round(10 * 0.5) = 5
        assert_eq!(sb.cumulative_score(), 5);
    }

    #[test]
    fn should_run_threshold_zero_always() {
        let sb = ThreatScoreboard::new();
        assert!(sb.should_run(0, "anything"));
    }

    #[test]
    fn should_run_gating() {
        let mut sb = ThreatScoreboard::new();
        assert!(!sb.should_run(5, "prompt_hijack"));

        sb.record("prompt_hijack", 3);
        assert!(!sb.should_run(5, "prompt_hijack"));

        sb.record("prompt_hijack", 2);
        assert!(sb.should_run(5, "prompt_hijack"));
    }

    #[test]
    fn cross_branch_escalation() {
        let config = ScoringConfig {
            escalation_threshold: Some(10),
            escalation_reduction: Some(3),
            class_weights: None,
        };
        let mut sb = ThreatScoreboard::from_config(&config);

        // obfuscation class hasn't escalated — threshold 5 stays 5
        sb.record("obfuscation", 5);
        assert!(!sb.should_run(5, "prompt_hijack"));

        // obfuscation exceeds escalation_threshold=10
        sb.record("obfuscation", 6);
        // prompt_hijack effective threshold: max(0, 5 - 3) = 2
        // prompt_hijack class score is 0 — still not enough
        assert!(!sb.should_run(5, "prompt_hijack"));

        // give prompt_hijack a score of 2
        sb.record("prompt_hijack", 2);
        // effective threshold = 2, class score = 2 → should run
        assert!(sb.should_run(5, "prompt_hijack"));
    }

    #[test]
    fn apply_threshold_filter_basic() {
        use crate::scanner::{Category, Severity};

        let make = |desc: &str, threshold: i32, level: i32, class: &str| ScoredCandidate {
            finding: Finding::new(Category::PromptInjection, Severity::High, desc, "x", 0..1),
            meta: ThreatMeta {
                threat_level: level,
                threshold,
                threat_class: class.into(),
            },
        };

        let candidates = vec![
            make("low-t", 0, 3, "a"),
            make("high-t", 5, 1, "a"),
            make("another-low", 0, 2, "a"),
        ];

        let (findings, sb) = apply_threshold_filter(candidates, ThreatScoreboard::new());

        // Both threshold-0 rules fire (3 + 2 = 5), unlocking the threshold-5 rule
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].description, "low-t");
        assert_eq!(findings[1].description, "another-low");
        assert_eq!(findings[2].description, "high-t");
        assert_eq!(sb.class_score("a"), 6); // 3 + 2 + 1
    }

    #[test]
    fn apply_threshold_filter_blocks_unmet() {
        use crate::scanner::{Category, Severity};

        let make = |desc: &str, threshold: i32, level: i32, class: &str| ScoredCandidate {
            finding: Finding::new(Category::PromptInjection, Severity::High, desc, "x", 0..1),
            meta: ThreatMeta {
                threat_level: level,
                threshold,
                threat_class: class.into(),
            },
        };

        let candidates = vec![
            make("low-t", 0, 2, "a"),
            make("high-t", 10, 1, "a"), // threshold 10, only 2 accumulated
        ];

        let (findings, sb) = apply_threshold_filter(candidates, ThreatScoreboard::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].description, "low-t");
        assert_eq!(sb.class_score("a"), 2);
    }

    #[test]
    fn record_saturates_instead_of_overflowing() {
        let mut sb = ThreatScoreboard::new();
        sb.record("a", i32::MAX);
        sb.record("a", 1);
        assert_eq!(sb.class_score("a"), i32::MAX);
        assert_eq!(sb.cumulative_score(), i32::MAX);
    }
}
