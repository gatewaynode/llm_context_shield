//! Cross-rule and cross-engine correlation data model.
//!
//! Defines the carriers that the correlation engine (11b) populates and the
//! declarative rules that drive it (11c). This module ships the types only;
//! evaluation and scan-pipeline integration land in subsequent sub-phases.

use serde::Serialize;

use crate::scanner::{Category, Finding};

/// Correlation flavour. Determines how the engine evaluates a rule's
/// `match_refs` against the set of findings produced by a single scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// First match strictly precedes the second by byte offset.
    Ordered,
    /// Both matches present within `proximity_bytes` of each other (any order).
    Proximate { proximity_bytes: usize },
    /// Both matches present in the same scan (position-agnostic).
    Combined,
    /// Matches sourced from two distinct engines. Resolution of engine
    /// identity is deferred to 11b.
    CrossEngine,
}

/// Declarative reference to a finding the correlation rule wants to match
/// against. Resolution semantics for `rule_name_pattern` and `engine_filter`
/// are defined in 11b.
#[derive(Debug, Clone)]
pub struct MatchRef {
    pub category: Category,
    pub rule_name_pattern: Option<String>,
    pub engine_filter: Option<String>,
}

/// Declarative correlation rule. Authored in code (bundled rules in 11c) or
/// loaded from a config file (11d). 11a only ships the type.
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub explanation: String,
    pub match_refs: Vec<MatchRef>,
    pub constraint: CorrelationType,
    pub composite_threat_level: i32,
    pub composite_threat_class: String,
}

/// A fired correlation: links the contributing findings, the rule that
/// matched, and the composite scoring metadata.
#[derive(Debug, Clone, Serialize)]
pub struct MatchCorrelation {
    pub rule_name: String,
    pub correlation_type: CorrelationType,
    pub findings: Vec<Finding>,
    pub composite_threat_level: i32,
    pub composite_threat_class: String,
    pub explanation: String,
}

impl MatchCorrelation {
    pub fn new(rule: &CorrelationRule, findings: Vec<Finding>) -> Self {
        Self {
            rule_name: rule.name.clone(),
            correlation_type: rule.constraint,
            findings,
            composite_threat_level: rule.composite_threat_level,
            composite_threat_class: rule.composite_threat_class.clone(),
            explanation: rule.explanation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Severity;

    fn finding(cat: Category, desc: &str, range: std::ops::Range<usize>) -> Finding {
        Finding::new(cat, Severity::High, desc, "x", range)
    }

    #[test]
    fn match_correlation_inherits_metadata_from_rule() {
        let rule = CorrelationRule {
            name: "sandwich".into(),
            explanation: "delimiter spoof + injection within 500 bytes".into(),
            match_refs: vec![
                MatchRef {
                    category: Category::DelimiterManipulation,
                    rule_name_pattern: None,
                    engine_filter: None,
                },
                MatchRef {
                    category: Category::PromptInjection,
                    rule_name_pattern: None,
                    engine_filter: None,
                },
            ],
            constraint: CorrelationType::Proximate {
                proximity_bytes: 500,
            },
            composite_threat_level: 7,
            composite_threat_class: "compound_attack".into(),
        };
        let f1 = finding(Category::DelimiterManipulation, "fake boundary", 0..13);
        let f2 = finding(Category::PromptInjection, "ignore previous", 20..35);
        let corr = MatchCorrelation::new(&rule, vec![f1, f2]);

        assert_eq!(corr.rule_name, "sandwich");
        assert_eq!(
            corr.correlation_type,
            CorrelationType::Proximate {
                proximity_bytes: 500
            }
        );
        assert_eq!(corr.findings.len(), 2);
        assert_eq!(corr.composite_threat_level, 7);
        assert_eq!(corr.composite_threat_class, "compound_attack");
        assert!(corr.explanation.contains("delimiter"));
    }

    #[test]
    fn correlation_serializes_to_expected_shape() {
        let rule = CorrelationRule {
            name: "test".into(),
            explanation: "x".into(),
            match_refs: vec![],
            constraint: CorrelationType::Combined,
            composite_threat_level: 1,
            composite_threat_class: "correlation".into(),
        };
        let corr = MatchCorrelation::new(&rule, vec![]);
        let json = serde_json::to_value(&corr).expect("serialize");
        assert_eq!(json["rule_name"], "test");
        assert_eq!(json["correlation_type"], "combined");
        assert_eq!(json["composite_threat_level"], 1);
        assert_eq!(json["composite_threat_class"], "correlation");
        assert!(json["findings"].is_array());
    }

    #[test]
    fn correlation_type_variants_serialize_distinctly() {
        let make = |t: CorrelationType| {
            serde_json::to_value(MatchCorrelation {
                rule_name: "r".into(),
                correlation_type: t,
                findings: vec![],
                composite_threat_level: 0,
                composite_threat_class: "c".into(),
                explanation: "e".into(),
            })
            .unwrap()["correlation_type"]
                .clone()
        };

        assert_eq!(make(CorrelationType::Ordered), "ordered");
        assert_eq!(make(CorrelationType::Combined), "combined");
        assert_eq!(make(CorrelationType::CrossEngine), "cross_engine");

        // Proximate carries data → externally tagged form
        let prox = make(CorrelationType::Proximate {
            proximity_bytes: 100,
        });
        assert!(prox.is_object(), "Proximate should serialize as an object");
        assert_eq!(prox["proximate"]["proximity_bytes"], 100);
    }

    #[test]
    fn match_ref_optional_filters_default_to_none() {
        let r = MatchRef {
            category: Category::Jailbreak,
            rule_name_pattern: None,
            engine_filter: None,
        };
        assert!(r.rule_name_pattern.is_none());
        assert!(r.engine_filter.is_none());
        assert_eq!(r.category, Category::Jailbreak);
    }

    #[test]
    fn rule_clone_preserves_match_refs() {
        let rule = CorrelationRule {
            name: "r".into(),
            explanation: "e".into(),
            match_refs: vec![MatchRef {
                category: Category::Coercion,
                rule_name_pattern: Some("guilt.*".into()),
                engine_filter: Some("syara".into()),
            }],
            constraint: CorrelationType::Ordered,
            composite_threat_level: 3,
            composite_threat_class: "correlation".into(),
        };
        let cloned = rule.clone();
        assert_eq!(cloned.match_refs.len(), 1);
        assert_eq!(cloned.match_refs[0].category, Category::Coercion);
        assert_eq!(
            cloned.match_refs[0].rule_name_pattern.as_deref(),
            Some("guilt.*")
        );
        assert_eq!(cloned.match_refs[0].engine_filter.as_deref(), Some("syara"));
    }
}
