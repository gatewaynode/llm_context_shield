//! Cross-rule and cross-engine correlation data model.
//!
//! Defines the carriers populated by [`CorrelationEngine`] (11b) and the
//! declarative rules that drive it. The bundled-rule catalog (11c) lives in
//! the [`bundled`] submodule.

pub mod bundled;

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

/// Findings produced by a single engine, paired with the engine's name.
///
/// `CorrelationEngine::evaluate` takes a slice of these to preserve engine
/// identity across the bucket boundary — required for `CrossEngine`
/// correlation and for resolving `MatchRef::engine_filter`.
#[derive(Debug, Clone)]
pub struct EngineFindings {
    pub engine: String,
    pub findings: Vec<Finding>,
}

/// Stateless evaluator for [`CorrelationRule`]s against a set of bucketed
/// findings. The engine itself carries no state — `evaluate` is a pure
/// function over its inputs.
pub struct CorrelationEngine;

impl CorrelationEngine {
    /// Evaluate every rule against every pair of findings drawn from
    /// `buckets`. Returns one [`MatchCorrelation`] per satisfying pair (per
    /// rule). Rules whose `match_refs.len() != 2` are skipped with a
    /// `tracing::warn!` on first encounter — N-ary correlations are
    /// deferred to a future sub-phase.
    pub fn evaluate(
        buckets: &[EngineFindings],
        rules: &[CorrelationRule],
    ) -> Vec<MatchCorrelation> {
        let flat: Vec<(&str, &Finding)> = buckets
            .iter()
            .flat_map(|b| b.findings.iter().map(move |f| (b.engine.as_str(), f)))
            .collect();

        let mut out = Vec::new();
        for rule in rules {
            if rule.match_refs.len() != 2 {
                tracing::warn!(
                    rule = %rule.name,
                    refs = rule.match_refs.len(),
                    "correlation rule skipped: only pair (2-ref) correlations are supported in 11b"
                );
                continue;
            }
            let ref_a = &rule.match_refs[0];
            let ref_b = &rule.match_refs[1];
            let pat_a = compile_rule_name_pattern(ref_a, &rule.name);
            let pat_b = compile_rule_name_pattern(ref_b, &rule.name);

            for (i, (eng_a, fa)) in flat.iter().enumerate() {
                if !match_ref_matches(ref_a, eng_a, fa, pat_a.as_ref()) {
                    continue;
                }
                for (j, (eng_b, fb)) in flat.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    if !match_ref_matches(ref_b, eng_b, fb, pat_b.as_ref()) {
                        continue;
                    }
                    if !constraint_satisfied(rule.constraint, eng_a, fa, eng_b, fb) {
                        continue;
                    }
                    out.push(MatchCorrelation::new(rule, vec![(*fa).clone(), (*fb).clone()]));
                }
            }
        }
        out
    }
}

/// Result of compiling a `MatchRef::rule_name_pattern`:
/// - `None` — no pattern was set; ignore name matching for this ref.
/// - `Some(Ok(re))` — pattern compiled; use it to filter `Finding::description`.
/// - `Some(Err(()))` — pattern was set but failed to compile; treat as never-match
///   so the rule does not silently fire when its author intended a filter.
fn compile_rule_name_pattern(r: &MatchRef, rule_name: &str) -> Option<Result<regex::Regex, ()>> {
    let pat = r.rule_name_pattern.as_deref()?;
    match regex::Regex::new(pat) {
        Ok(re) => Some(Ok(re)),
        Err(e) => {
            tracing::warn!(
                rule = %rule_name,
                pattern = %pat,
                error = %e,
                "correlation MatchRef rule_name_pattern is not a valid regex; treating as no-match"
            );
            Some(Err(()))
        }
    }
}

fn match_ref_matches(
    r: &MatchRef,
    bucket: &str,
    f: &Finding,
    name_re: Option<&Result<regex::Regex, ()>>,
) -> bool {
    if f.category != r.category {
        return false;
    }
    if let Some(filter) = &r.engine_filter
        && filter != bucket
    {
        return false;
    }
    match name_re {
        None => true,
        Some(Err(())) => false,
        Some(Ok(re)) => re.is_match(&f.description),
    }
}

fn constraint_satisfied(
    c: CorrelationType,
    eng_a: &str,
    a: &Finding,
    eng_b: &str,
    b: &Finding,
) -> bool {
    match c {
        CorrelationType::Ordered => a.byte_range.0 < b.byte_range.0,
        CorrelationType::Proximate { proximity_bytes } => byte_gap(a, b) <= proximity_bytes,
        CorrelationType::Combined => true,
        CorrelationType::CrossEngine => eng_a != eng_b,
    }
}

fn byte_gap(a: &Finding, b: &Finding) -> usize {
    let (a_start, a_end) = a.byte_range;
    let (b_start, b_end) = b.byte_range;
    let outer_start = a_start.max(b_start);
    let inner_end = a_end.min(b_end);
    outer_start.saturating_sub(inner_end)
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

    // ── 11b: CorrelationEngine::evaluate ──

    fn rule(name: &str, cat_a: Category, cat_b: Category, c: CorrelationType) -> CorrelationRule {
        CorrelationRule {
            name: name.into(),
            explanation: "test".into(),
            match_refs: vec![
                MatchRef {
                    category: cat_a,
                    rule_name_pattern: None,
                    engine_filter: None,
                },
                MatchRef {
                    category: cat_b,
                    rule_name_pattern: None,
                    engine_filter: None,
                },
            ],
            constraint: c,
            composite_threat_level: 5,
            composite_threat_class: "correlation".into(),
        }
    }

    fn bucket(engine: &str, findings: Vec<Finding>) -> EngineFindings {
        EngineFindings {
            engine: engine.into(),
            findings,
        }
    }

    #[test]
    fn ordered_pair_fires_when_a_precedes_b() {
        let r = rule(
            "ord",
            Category::DelimiterManipulation,
            Category::PromptInjection,
            CorrelationType::Ordered,
        );
        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::DelimiterManipulation, "delim", 0..5),
                finding(Category::PromptInjection, "ignore prev", 10..20),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_name, "ord");
        assert_eq!(out[0].findings.len(), 2);
    }

    #[test]
    fn ordered_pair_does_not_fire_when_b_precedes_a() {
        let r = rule(
            "ord",
            Category::DelimiterManipulation,
            Category::PromptInjection,
            CorrelationType::Ordered,
        );
        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::PromptInjection, "ignore prev", 0..10),
                finding(Category::DelimiterManipulation, "delim", 15..20),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert!(out.is_empty(), "ordered should not fire when B precedes A");
    }

    #[test]
    fn proximate_within_window_fires() {
        let r = rule(
            "prox",
            Category::DelimiterManipulation,
            Category::PromptInjection,
            CorrelationType::Proximate { proximity_bytes: 50 },
        );
        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::DelimiterManipulation, "delim", 0..10),
                finding(Category::PromptInjection, "inj", 30..40),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1, "gap=20 should fire with window=50");
    }

    #[test]
    fn proximate_outside_window_does_not_fire() {
        let r = rule(
            "prox",
            Category::DelimiterManipulation,
            Category::PromptInjection,
            CorrelationType::Proximate { proximity_bytes: 50 },
        );
        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::DelimiterManipulation, "delim", 0..10),
                finding(Category::PromptInjection, "inj", 200..210),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert!(out.is_empty(), "gap=190 should not fire with window=50");
    }

    #[test]
    fn combined_fires_regardless_of_position() {
        let r = rule(
            "comb",
            Category::Jailbreak,
            Category::Coercion,
            CorrelationType::Combined,
        );
        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::Coercion, "guilt", 0..5),
                finding(Category::Jailbreak, "DAN", 1000..1010),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn cross_engine_requires_distinct_buckets() {
        let r = rule(
            "xe",
            Category::PromptInjection,
            Category::PromptInjection,
            CorrelationType::CrossEngine,
        );

        // Two findings in the same bucket → should NOT fire.
        let single = vec![bucket(
            "syara",
            vec![
                finding(Category::PromptInjection, "a", 0..5),
                finding(Category::PromptInjection, "b", 100..105),
            ],
        )];
        assert!(
            CorrelationEngine::evaluate(&single, std::slice::from_ref(&r)).is_empty(),
            "CrossEngine should not fire within a single bucket"
        );

        // One finding in each bucket → SHOULD fire (twice — symmetric pairs).
        let pair = vec![
            bucket("yara", vec![finding(Category::PromptInjection, "a", 0..5)]),
            bucket(
                "syara",
                vec![finding(Category::PromptInjection, "b", 100..105)],
            ),
        ];
        let out = CorrelationEngine::evaluate(&pair, &[r]);
        assert_eq!(
            out.len(),
            2,
            "CrossEngine should fire for both ordered pairings of distinct buckets"
        );
    }

    #[test]
    fn engine_filter_excludes_wrong_bucket() {
        let mut r = rule(
            "filter",
            Category::PromptInjection,
            Category::PromptInjection,
            CorrelationType::Combined,
        );
        r.match_refs[0].engine_filter = Some("yara".into());

        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::PromptInjection, "a", 0..5),
                finding(Category::PromptInjection, "b", 100..105),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert!(
            out.is_empty(),
            "engine_filter='yara' should exclude all findings from a 'syara' bucket"
        );
    }

    #[test]
    fn mismatched_categories_do_not_fire() {
        let r = rule(
            "mismatch",
            Category::PromptInjection,
            Category::DelimiterManipulation,
            CorrelationType::Combined,
        );
        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::PromptInjection, "a", 0..5),
                finding(Category::PromptInjection, "b", 100..105),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r]);
        assert!(
            out.is_empty(),
            "rule wants PI + DM, only PI present — no fire"
        );
    }

    #[test]
    fn rule_with_non_pair_match_refs_skipped() {
        let mut r_empty = rule(
            "empty",
            Category::PromptInjection,
            Category::PromptInjection,
            CorrelationType::Combined,
        );
        r_empty.match_refs.clear();

        let mut r_three = rule(
            "three",
            Category::PromptInjection,
            Category::PromptInjection,
            CorrelationType::Combined,
        );
        r_three.match_refs.push(MatchRef {
            category: Category::Jailbreak,
            rule_name_pattern: None,
            engine_filter: None,
        });

        let bs = vec![bucket(
            "syara",
            vec![
                finding(Category::PromptInjection, "a", 0..5),
                finding(Category::PromptInjection, "b", 10..15),
                finding(Category::Jailbreak, "j", 20..25),
            ],
        )];
        let out = CorrelationEngine::evaluate(&bs, &[r_empty, r_three]);
        assert!(
            out.is_empty(),
            "rules with match_refs.len() != 2 should be skipped"
        );
    }
}
