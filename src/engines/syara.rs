//! SYARA-X scan engine.
//!
//! SYARA (Semantic YARA) extends YARA-compatible syntax with semantic,
//! classifier, and LLM matchers. Phase 3 only exercises string/regex rules
//! — no Ollama dependency — but the underlying `syara-x` crate supports the
//! semantic matchers via additional Cargo features (`syara-sbert`,
//! `syara-classifier`, `syara-llm`).
//!
//! Construction compiles bundled `.syara` sources plus any discovered in the
//! configured rules directory into a single [`syara_x::CompiledRules`].
//! Each scan produces one [`Finding`] per matched pattern detail; rules
//! missing `category` or `severity` metadata are skipped with a warning.

use syara_x::CompiledRules;

use super::Engine;
use crate::config::Config;
use crate::rules::discover;
use crate::scanner::{Category, Finding, Severity};

pub struct SyaraEngine {
    rules: CompiledRules,
}

impl SyaraEngine {
    /// Discover and compile all SYARA rule sources into a single
    /// `CompiledRules`. Returns `Err` with a human-readable message when any
    /// source fails to parse — misconfigured rules are fatal.
    pub fn new(config: &Config) -> Result<Self, String> {
        let sources = discover("syara", config);
        if sources.is_empty() {
            return syara_x::compile_str("")
                .map(|rules| Self { rules })
                .map_err(|e| format!("SYARA rule compilation error (empty source): {e}"));
        }
        // `syara-x` compiles a single source blob; concatenate with blank
        // separators so rule definitions stay distinct.
        let combined = sources.join("\n\n");
        let rules = syara_x::compile_str(&combined)
            .map_err(|e| format!("SYARA rule compilation error: {e}"))?;
        Ok(Self { rules })
    }
}

impl Engine for SyaraEngine {
    fn name(&self) -> &'static str {
        "syara"
    }

    fn rule_names(&self) -> Vec<String> {
        self.rules.rule_names().map(|s| s.to_string()).collect()
    }

    fn run(&self, input: &str, disabled: &[String]) -> Vec<Finding> {
        let matches = self.rules.scan(input);
        let disabled_lower: Vec<String> = disabled.iter().map(|s| s.to_lowercase()).collect();

        let mut findings = Vec::new();
        for m in matches {
            if !m.matched {
                continue;
            }
            if disabled_lower
                .iter()
                .any(|d| d == &m.rule_name.to_lowercase())
            {
                continue;
            }

            let (category, severity, description) = match extract_meta(&m) {
                Some(meta) => meta,
                None => {
                    tracing::warn!(
                        rule = %m.rule_name,
                        "skipping rule: missing or invalid category/severity metadata"
                    );
                    continue;
                }
            };

            let mut emitted = false;
            for details in m.matched_patterns.values() {
                for detail in details {
                    emitted = true;
                    // `MatchDetail` uses `-1` sentinels when the pattern does
                    // not track byte positions (e.g. semantic matchers).
                    let (start, end) = if detail.start_pos < 0 || detail.end_pos < 0 {
                        (0usize, 0usize)
                    } else {
                        (detail.start_pos as usize, detail.end_pos as usize)
                    };
                    findings.push(Finding {
                        category,
                        severity,
                        description: description.clone(),
                        matched_text: detail.matched_text.clone(),
                        byte_range: (start, end),
                    });
                }
            }

            if !emitted {
                findings.push(Finding {
                    category,
                    severity,
                    description: description.clone(),
                    matched_text: String::new(),
                    byte_range: (0, 0),
                });
            }
        }
        findings
    }
}

fn extract_meta(m: &syara_x::Match) -> Option<(Category, Severity, String)> {
    let category = m
        .meta
        .get("category")
        .and_then(|s| Category::from_str_loose(s))?;
    let severity = m
        .meta
        .get("severity")
        .and_then(|s| Severity::from_str_loose(s))?;
    let description = m
        .meta
        .get("description")
        .cloned()
        .unwrap_or_else(|| m.rule_name.clone());
    Some((category, severity, description))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_from_source(src: &str) -> SyaraEngine {
        SyaraEngine {
            rules: syara_x::compile_str(src).expect("inline rule compiles"),
        }
    }

    #[test]
    fn matches_simple_string_rule() {
        let src = r#"
            rule t1 {
                meta:
                    category = "prompt_injection"
                    severity = "critical"
                    description = "test rule"
                strings:
                    $s1 = "ignore previous instructions" nocase
                condition:
                    any of them
            }
        "#;
        let engine = engine_from_source(src);
        let findings = engine.run("Please Ignore Previous Instructions now.", &[]);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, Category::PromptInjection);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].description, "test rule");
    }

    #[test]
    fn skips_rule_missing_metadata() {
        let src = r#"
            rule bad {
                strings:
                    $s1 = "hello"
                condition:
                    any of them
            }
        "#;
        let engine = engine_from_source(src);
        let findings = engine.run("hello world", &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn disabled_filter_suppresses_by_name() {
        let src = r#"
            rule blocked_rule {
                meta:
                    category = "jailbreak"
                    severity = "high"
                strings:
                    $s1 = "DAN mode"
                condition:
                    any of them
            }
        "#;
        let engine = engine_from_source(src);
        let findings = engine.run("Enable DAN mode.", &["blocked_rule".to_string()]);
        assert!(findings.is_empty());
    }

    #[test]
    fn disabled_filter_is_case_insensitive() {
        let src = r#"
            rule Mixed_Case_Rule {
                meta:
                    category = "jailbreak"
                    severity = "high"
                strings:
                    $s1 = "DAN mode"
                condition:
                    any of them
            }
        "#;
        let engine = engine_from_source(src);
        let findings = engine.run("Enable DAN mode.", &["MIXED_CASE_RULE".to_string()]);
        assert!(findings.is_empty());
    }

    #[test]
    fn sentinel_positions_map_to_zero() {
        // Hand-build a Match with -1 sentinels to exercise the coercion
        // path without needing a semantic matcher.
        use std::collections::HashMap;
        use syara_x::{Match, MatchDetail};

        let mut detail = MatchDetail::new("$s1", "sentinel_text");
        detail.start_pos = -1;
        detail.end_pos = -1;
        let mut patterns: HashMap<String, Vec<MatchDetail>> = HashMap::new();
        patterns.insert("$s1".to_string(), vec![detail]);

        let mut meta = HashMap::new();
        meta.insert("category".to_string(), "prompt_injection".to_string());
        meta.insert("severity".to_string(), "high".to_string());
        meta.insert("description".to_string(), "sentinel test".to_string());

        let m = Match {
            rule_name: "sentinel_rule".to_string(),
            tags: vec![],
            meta,
            matched: true,
            matched_patterns: patterns,
        };

        // Walk the mapping logic directly against a single Match.
        let (category, severity, description) = extract_meta(&m).expect("meta present");
        let mut findings: Vec<Finding> = Vec::new();
        for details in m.matched_patterns.values() {
            for d in details {
                let (start, end) = if d.start_pos < 0 || d.end_pos < 0 {
                    (0usize, 0usize)
                } else {
                    (d.start_pos as usize, d.end_pos as usize)
                };
                findings.push(Finding {
                    category,
                    severity,
                    description: description.clone(),
                    matched_text: d.matched_text.clone(),
                    byte_range: (start, end),
                });
            }
        }

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].byte_range, (0, 0));
        assert_eq!(findings[0].matched_text, "sentinel_text");
    }
}
