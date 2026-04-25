//! Bundled correlation rules — high-confidence compound attack patterns.
//!
//! Each rule pairs two finding categories with a [`CorrelationType`] constraint.
//! Composite scores are sized to exceed any individual rule's `threat_level`
//! (max 5 across the bundled YARA/SYARA catalog), so a fired correlation
//! always represents a stronger signal than its contributing findings alone.

use crate::correlation::{CorrelationRule, CorrelationType, MatchRef};
use crate::scanner::Category;

fn ref_for(category: Category) -> MatchRef {
    MatchRef {
        category,
        rule_name_pattern: None,
        engine_filter: None,
    }
}

fn rule(
    name: &str,
    explanation: &str,
    a: Category,
    b: Category,
    constraint: CorrelationType,
    composite_threat_level: i32,
    composite_threat_class: &str,
) -> CorrelationRule {
    CorrelationRule {
        name: name.into(),
        explanation: explanation.into(),
        match_refs: vec![ref_for(a), ref_for(b)],
        constraint,
        composite_threat_level,
        composite_threat_class: composite_threat_class.into(),
    }
}

/// Returns the bundled correlation rule catalog with the default 500-byte
/// proximity window. Equivalent to `bundled_rules_with_window(500)`.
pub fn bundled_rules() -> Vec<CorrelationRule> {
    bundled_rules_with_window(500)
}

/// Returns the bundled correlation rule catalog with a configurable proximity
/// window applied to the two `Proximate` rules (`sandwich_attack`,
/// `encode_and_inject`). Other rule constraints are unaffected.
pub fn bundled_rules_with_window(proximity_bytes: usize) -> Vec<CorrelationRule> {
    vec![
        rule(
            "sandwich_attack",
            "Delimiter manipulation paired with prompt injection within the \
             proximity window — attacker faked a context boundary then injected.",
            Category::DelimiterManipulation,
            Category::PromptInjection,
            CorrelationType::Proximate { proximity_bytes },
            6,
            "sandwich_attack",
        ),
        rule(
            "setup_payload_instruction_override",
            "Context shift establishing a fictional frame followed by an instruction \
             override — attacker built a hypothetical context then exploited it.",
            Category::ContextShift,
            Category::InstructionOverride,
            CorrelationType::Ordered,
            7,
            "setup_payload",
        ),
        rule(
            "setup_payload_jailbreak",
            "Context shift establishing a fictional frame followed by a jailbreak \
             attempt — attacker built a hypothetical context then exploited it.",
            Category::ContextShift,
            Category::Jailbreak,
            CorrelationType::Ordered,
            7,
            "setup_payload",
        ),
        rule(
            "encode_and_inject",
            "Hidden / encoded content proximate to a prompt injection within the \
             proximity window — attacker concealed part of the payload.",
            Category::HiddenContent,
            Category::PromptInjection,
            CorrelationType::Proximate { proximity_bytes },
            7,
            "encode_and_inject",
        ),
        rule(
            "probe_then_extract",
            "Secret-probing finding followed by a data-exfiltration finding — \
             attacker confirmed a secret exists then attempted extraction.",
            Category::SecretProbing,
            Category::DataExfiltration,
            CorrelationType::Ordered,
            8,
            "probe_then_extract",
        ),
        rule(
            "multi_engine_corroboration_prompt_injection",
            "Two distinct engines independently flagged prompt injection on the \
             same scan — independent evidence agrees.",
            Category::PromptInjection,
            Category::PromptInjection,
            CorrelationType::CrossEngine,
            8,
            "multi_engine_corroboration",
        ),
        rule(
            "multi_engine_corroboration_jailbreak",
            "Two distinct engines independently flagged a jailbreak attempt on \
             the same scan — independent evidence agrees.",
            Category::Jailbreak,
            Category::Jailbreak,
            CorrelationType::CrossEngine,
            8,
            "multi_engine_corroboration",
        ),
        rule(
            "multi_engine_corroboration_instruction_override",
            "Two distinct engines independently flagged instruction override on \
             the same scan — independent evidence agrees.",
            Category::InstructionOverride,
            Category::InstructionOverride,
            CorrelationType::CrossEngine,
            8,
            "multi_engine_corroboration",
        ),
        rule(
            "multi_engine_corroboration_data_exfiltration",
            "Two distinct engines independently flagged data exfiltration on the \
             same scan — independent evidence agrees.",
            Category::DataExfiltration,
            Category::DataExfiltration,
            CorrelationType::CrossEngine,
            8,
            "multi_engine_corroboration",
        ),
        rule(
            "multi_engine_corroboration_refusal_suppression",
            "Two distinct engines independently flagged refusal suppression on the \
             same scan — independent evidence agrees.",
            Category::RefusalSuppression,
            Category::RefusalSuppression,
            CorrelationType::CrossEngine,
            8,
            "multi_engine_corroboration",
        ),
        rule(
            "multi_engine_corroboration_response_steering",
            "Two distinct engines independently flagged response steering on the \
             same scan — independent evidence agrees.",
            Category::ResponseSteering,
            Category::ResponseSteering,
            CorrelationType::CrossEngine,
            8,
            "multi_engine_corroboration",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::{CorrelationEngine, EngineFindings};
    use crate::scanner::{Finding, Severity};
    use std::collections::HashSet;

    fn finding(cat: Category, range: std::ops::Range<usize>) -> Finding {
        Finding::new(cat, Severity::High, "desc", "x", range)
    }

    fn find_rule(name: &str) -> CorrelationRule {
        bundled_rules()
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("bundled rule '{name}' not found"))
    }

    fn single_bucket(findings: Vec<Finding>) -> Vec<EngineFindings> {
        vec![EngineFindings {
            engine: "syara".into(),
            findings,
        }]
    }

    fn two_buckets(a: Vec<Finding>, b: Vec<Finding>) -> Vec<EngineFindings> {
        vec![
            EngineFindings {
                engine: "yara".into(),
                findings: a,
            },
            EngineFindings {
                engine: "syara".into(),
                findings: b,
            },
        ]
    }

    // ── Catalog smoke ─────────────────────────────────────────────

    #[test]
    fn bundled_rules_returns_expected_catalog() {
        let names: HashSet<String> = bundled_rules().into_iter().map(|r| r.name).collect();
        let expected: HashSet<String> = [
            "sandwich_attack",
            "setup_payload_instruction_override",
            "setup_payload_jailbreak",
            "encode_and_inject",
            "probe_then_extract",
            "multi_engine_corroboration_prompt_injection",
            "multi_engine_corroboration_jailbreak",
            "multi_engine_corroboration_instruction_override",
            "multi_engine_corroboration_data_exfiltration",
            "multi_engine_corroboration_refusal_suppression",
            "multi_engine_corroboration_response_steering",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(names, expected);
        assert_eq!(bundled_rules().len(), 11);
    }

    #[test]
    fn proximity_window_propagates_to_bundled_proximate_rules() {
        let rules = bundled_rules_with_window(123);
        for r in rules {
            if matches!(r.name.as_str(), "sandwich_attack" | "encode_and_inject") {
                match r.constraint {
                    CorrelationType::Proximate { proximity_bytes } => {
                        assert_eq!(
                            proximity_bytes, 123,
                            "rule {} did not pick up the configured window",
                            r.name
                        );
                    }
                    other => panic!("rule {} should be Proximate, got {:?}", r.name, other),
                }
            }
        }
    }

    #[test]
    fn every_bundled_rule_composite_exceeds_max_individual_threat_level() {
        // Max individual threat_level across YARA/SYARA bundled rules is 5.
        for r in bundled_rules() {
            assert!(
                r.composite_threat_level > 5,
                "rule {} has composite_threat_level={} which does not exceed 5",
                r.name,
                r.composite_threat_level
            );
        }
    }

    // ── Positive: non-CrossEngine rules ───────────────────────────

    #[test]
    fn sandwich_attack_fires_when_delim_and_pi_within_window() {
        let r = find_rule("sandwich_attack");
        let bs = single_bucket(vec![
            finding(Category::DelimiterManipulation, 0..10),
            finding(Category::PromptInjection, 100..110),
        ]);
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_name, "sandwich_attack");
        assert_eq!(out[0].composite_threat_class, "sandwich_attack");
    }

    #[test]
    fn setup_payload_instruction_override_fires_when_cs_precedes_io() {
        let r = find_rule("setup_payload_instruction_override");
        let bs = single_bucket(vec![
            finding(Category::ContextShift, 0..10),
            finding(Category::InstructionOverride, 50..60),
        ]);
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].composite_threat_class, "setup_payload");
    }

    #[test]
    fn setup_payload_jailbreak_fires_when_cs_precedes_jb() {
        let r = find_rule("setup_payload_jailbreak");
        let bs = single_bucket(vec![
            finding(Category::ContextShift, 0..10),
            finding(Category::Jailbreak, 50..60),
        ]);
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].composite_threat_class, "setup_payload");
    }

    #[test]
    fn encode_and_inject_fires_when_hidden_content_proximate_to_pi() {
        let r = find_rule("encode_and_inject");
        let bs = single_bucket(vec![
            finding(Category::HiddenContent, 0..20),
            finding(Category::PromptInjection, 100..120),
        ]);
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].composite_threat_class, "encode_and_inject");
    }

    #[test]
    fn probe_then_extract_fires_when_probing_precedes_exfil() {
        let r = find_rule("probe_then_extract");
        let bs = single_bucket(vec![
            finding(Category::SecretProbing, 0..15),
            finding(Category::DataExfiltration, 100..120),
        ]);
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].composite_threat_class, "probe_then_extract");
    }

    // ── Positive: CrossEngine rules (each requires distinct buckets) ──

    #[test]
    fn multi_engine_corroboration_prompt_injection_fires_across_buckets() {
        let r = find_rule("multi_engine_corroboration_prompt_injection");
        let bs = two_buckets(
            vec![finding(Category::PromptInjection, 0..10)],
            vec![finding(Category::PromptInjection, 50..60)],
        );
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        // CrossEngine fires for both ordered pairings of distinct buckets.
        assert_eq!(out.len(), 2);
        assert!(
            out.iter().all(|c| c.composite_threat_class == "multi_engine_corroboration"),
        );
    }

    #[test]
    fn multi_engine_corroboration_jailbreak_fires_across_buckets() {
        let r = find_rule("multi_engine_corroboration_jailbreak");
        let bs = two_buckets(
            vec![finding(Category::Jailbreak, 0..10)],
            vec![finding(Category::Jailbreak, 50..60)],
        );
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn multi_engine_corroboration_instruction_override_fires_across_buckets() {
        let r = find_rule("multi_engine_corroboration_instruction_override");
        let bs = two_buckets(
            vec![finding(Category::InstructionOverride, 0..10)],
            vec![finding(Category::InstructionOverride, 50..60)],
        );
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn multi_engine_corroboration_data_exfiltration_fires_across_buckets() {
        let r = find_rule("multi_engine_corroboration_data_exfiltration");
        let bs = two_buckets(
            vec![finding(Category::DataExfiltration, 0..10)],
            vec![finding(Category::DataExfiltration, 50..60)],
        );
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn multi_engine_corroboration_refusal_suppression_fires_across_buckets() {
        let r = find_rule("multi_engine_corroboration_refusal_suppression");
        let bs = two_buckets(
            vec![finding(Category::RefusalSuppression, 0..10)],
            vec![finding(Category::RefusalSuppression, 50..60)],
        );
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn multi_engine_corroboration_response_steering_fires_across_buckets() {
        let r = find_rule("multi_engine_corroboration_response_steering");
        let bs = two_buckets(
            vec![finding(Category::ResponseSteering, 0..10)],
            vec![finding(Category::ResponseSteering, 50..60)],
        );
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 2);
    }

    // ── FP: a single ref present (without its partner) does not fire ──

    #[test]
    fn sandwich_attack_does_not_fire_with_only_pi() {
        let r = find_rule("sandwich_attack");
        let bs = single_bucket(vec![finding(Category::PromptInjection, 0..10)]);
        assert!(CorrelationEngine::evaluate(&bs, &[r]).is_empty());
    }

    #[test]
    fn setup_payload_instruction_override_does_not_fire_with_only_io() {
        let r = find_rule("setup_payload_instruction_override");
        let bs = single_bucket(vec![finding(Category::InstructionOverride, 0..10)]);
        assert!(CorrelationEngine::evaluate(&bs, &[r]).is_empty());
    }

    #[test]
    fn setup_payload_jailbreak_does_not_fire_with_only_jb() {
        let r = find_rule("setup_payload_jailbreak");
        let bs = single_bucket(vec![finding(Category::Jailbreak, 0..10)]);
        assert!(CorrelationEngine::evaluate(&bs, &[r]).is_empty());
    }

    #[test]
    fn encode_and_inject_does_not_fire_with_only_hidden_content() {
        let r = find_rule("encode_and_inject");
        let bs = single_bucket(vec![finding(Category::HiddenContent, 0..10)]);
        assert!(CorrelationEngine::evaluate(&bs, &[r]).is_empty());
    }

    #[test]
    fn probe_then_extract_does_not_fire_with_only_secret_probing() {
        let r = find_rule("probe_then_extract");
        let bs = single_bucket(vec![finding(Category::SecretProbing, 0..10)]);
        assert!(CorrelationEngine::evaluate(&bs, &[r]).is_empty());
    }

    // ── FP: CrossEngine rules do not fire when both findings come from the same bucket ──

    #[test]
    fn cross_engine_rules_do_not_fire_in_single_bucket() {
        // For each CrossEngine rule, two same-category findings in a single
        // bucket must not produce a correlation.
        let rules: Vec<CorrelationRule> = bundled_rules()
            .into_iter()
            .filter(|r| matches!(r.constraint, CorrelationType::CrossEngine))
            .collect();
        assert!(!rules.is_empty(), "test pre-condition: catalog has CrossEngine rules");

        for r in rules {
            let cat = r.match_refs[0].category;
            let bs = single_bucket(vec![finding(cat, 0..10), finding(cat, 50..60)]);
            let out = CorrelationEngine::evaluate(&bs, std::slice::from_ref(&r));
            assert!(
                out.is_empty(),
                "rule {} fired in a single-bucket scenario; CrossEngine should require distinct buckets",
                r.name,
            );
        }
    }
}
