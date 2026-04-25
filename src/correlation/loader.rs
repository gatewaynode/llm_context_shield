//! TOML loader for user-defined correlation rules.
//!
//! See `docs/rule-authoring.md` for the file format. Authoring constraints:
//! exactly two `match_refs` per rule (D8: pair-only), one of four
//! `constraint_type` values, and `proximity_bytes` is required iff the
//! constraint is `proximate`.

use std::fs;
use std::io;
use std::path::Path;

use serde::Deserialize;

use crate::correlation::{CorrelationRule, CorrelationType, MatchRef};
use crate::scanner::Category;

#[derive(Deserialize, Default)]
struct CorrelationRulesFile {
    #[serde(default)]
    rules: Vec<CorrelationRuleToml>,
}

#[derive(Deserialize)]
struct CorrelationRuleToml {
    name: String,
    explanation: String,
    match_refs: Vec<MatchRefToml>,
    constraint_type: String,
    proximity_bytes: Option<usize>,
    composite_threat_level: i32,
    composite_threat_class: String,
}

#[derive(Deserialize)]
struct MatchRefToml {
    category: String,
    rule_name_pattern: Option<String>,
    engine_filter: Option<String>,
}

/// Read `path` as TOML and return the deserialized correlation rules.
///
/// Errors on missing/unreadable files, malformed TOML, unknown
/// `constraint_type`, unknown `category`, mismatched `proximity_bytes` /
/// `constraint_type` combinations, or rules whose `match_refs.len()` is not
/// exactly 2 (D8).
pub fn load_custom_rules(path: &Path) -> io::Result<Vec<CorrelationRule>> {
    let text = fs::read_to_string(path).map_err(|e| {
        io::Error::other(format!(
            "cannot read correlation rules {}: {e}",
            path.display()
        ))
    })?;
    let parsed: CorrelationRulesFile = toml::from_str(&text).map_err(|e| {
        io::Error::other(format!(
            "invalid correlation rules TOML {}: {e}",
            path.display()
        ))
    })?;
    parsed
        .rules
        .into_iter()
        .map(|r| convert_rule(r, path))
        .collect()
}

fn convert_rule(r: CorrelationRuleToml, path: &Path) -> io::Result<CorrelationRule> {
    let display_path = path.display();
    if r.match_refs.len() != 2 {
        return Err(io::Error::other(format!(
            "{display_path}: rule {:?} must have exactly 2 match_refs (got {})",
            r.name,
            r.match_refs.len()
        )));
    }
    let constraint = match r.constraint_type.as_str() {
        "ordered" => {
            require_no_proximity(&r, path)?;
            CorrelationType::Ordered
        }
        "proximate" => {
            let proximity_bytes = r.proximity_bytes.ok_or_else(|| {
                io::Error::other(format!(
                    "{display_path}: rule {:?} has constraint_type=\"proximate\" but proximity_bytes is missing",
                    r.name
                ))
            })?;
            CorrelationType::Proximate { proximity_bytes }
        }
        "combined" => {
            require_no_proximity(&r, path)?;
            CorrelationType::Combined
        }
        "cross_engine" => {
            require_no_proximity(&r, path)?;
            CorrelationType::CrossEngine
        }
        other => {
            return Err(io::Error::other(format!(
                "{display_path}: rule {:?} has unknown constraint_type {:?} (expected ordered, proximate, combined, or cross_engine)",
                r.name, other
            )));
        }
    };

    let mut match_refs = Vec::with_capacity(2);
    for mr in r.match_refs {
        let category = Category::from_str_loose(&mr.category).ok_or_else(|| {
            io::Error::other(format!(
                "{display_path}: rule {:?} has unknown category {:?}",
                r.name, mr.category
            ))
        })?;
        match_refs.push(MatchRef {
            category,
            rule_name_pattern: mr.rule_name_pattern,
            engine_filter: mr.engine_filter,
        });
    }

    Ok(CorrelationRule {
        name: r.name,
        explanation: r.explanation,
        match_refs,
        constraint,
        composite_threat_level: r.composite_threat_level,
        composite_threat_class: r.composite_threat_class,
    })
}

fn require_no_proximity(r: &CorrelationRuleToml, path: &Path) -> io::Result<()> {
    if r.proximity_bytes.is_some() {
        Err(io::Error::other(format!(
            "{}: rule {:?} has constraint_type={:?} but proximity_bytes was set (only valid for \"proximate\")",
            path.display(),
            r.name,
            r.constraint_type
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Write `body` to a unique file in the system temp dir and return the
    /// path. The file is left in place when the test ends — temp dir cleanup
    /// is the OS's responsibility. Each call returns a fresh path.
    fn temp_file(body: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "lcs_correlation_loader_test_{}_{}.toml",
            std::process::id(),
            n
        ));
        fs::write(&path, body).expect("write temp file");
        path
    }

    #[test]
    fn loads_valid_proximate_rule() {
        let body = r#"
[[rules]]
name = "custom_sandwich"
explanation = "tighter sandwich"
constraint_type = "proximate"
proximity_bytes = 200
composite_threat_level = 7
composite_threat_class = "sandwich_attack"

[[rules.match_refs]]
category = "delimiter_manipulation"

[[rules.match_refs]]
category = "prompt_injection"
"#;
        let path = temp_file(body);
        let rules = load_custom_rules(&path).expect("load");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "custom_sandwich");
        assert_eq!(
            rules[0].constraint,
            CorrelationType::Proximate {
                proximity_bytes: 200
            }
        );
        assert_eq!(rules[0].match_refs[0].category, Category::DelimiterManipulation);
        assert_eq!(rules[0].match_refs[1].category, Category::PromptInjection);
    }

    #[test]
    fn loads_each_constraint_type() {
        let body = r#"
[[rules]]
name = "ord"
explanation = ""
constraint_type = "ordered"
composite_threat_level = 6
composite_threat_class = "x"
[[rules.match_refs]]
category = "context_shift"
[[rules.match_refs]]
category = "jailbreak"

[[rules]]
name = "comb"
explanation = ""
constraint_type = "combined"
composite_threat_level = 6
composite_threat_class = "x"
[[rules.match_refs]]
category = "coercion"
[[rules.match_refs]]
category = "jailbreak"

[[rules]]
name = "xe"
explanation = ""
constraint_type = "cross_engine"
composite_threat_level = 8
composite_threat_class = "x"
[[rules.match_refs]]
category = "prompt_injection"
[[rules.match_refs]]
category = "prompt_injection"
"#;
        let path = temp_file(body);
        let rules = load_custom_rules(&path).expect("load");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].constraint, CorrelationType::Ordered);
        assert_eq!(rules[1].constraint, CorrelationType::Combined);
        assert_eq!(rules[2].constraint, CorrelationType::CrossEngine);
    }

    #[test]
    fn empty_file_returns_empty_list() {
        let path = temp_file("");
        let rules = load_custom_rules(&path).expect("load");
        assert!(rules.is_empty());
    }

    #[test]
    fn missing_file_errors() {
        let path = std::env::temp_dir().join("does_not_exist_lcs_correlation_loader_test.toml");
        let err = load_custom_rules(&path).expect_err("missing file should error");
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn malformed_toml_errors() {
        let path = temp_file("not valid TOML [[[");
        let err = load_custom_rules(&path).expect_err("malformed TOML should error");
        assert!(err.to_string().contains("invalid correlation rules TOML"));
    }

    #[test]
    fn unknown_constraint_type_errors() {
        let body = r#"
[[rules]]
name = "bogus"
explanation = ""
constraint_type = "telepathic"
composite_threat_level = 5
composite_threat_class = "x"
[[rules.match_refs]]
category = "prompt_injection"
[[rules.match_refs]]
category = "jailbreak"
"#;
        let path = temp_file(body);
        let err = load_custom_rules(&path).expect_err("unknown constraint_type should error");
        assert!(err.to_string().contains("unknown constraint_type"));
    }

    #[test]
    fn proximate_without_bytes_errors() {
        let body = r#"
[[rules]]
name = "bad"
explanation = ""
constraint_type = "proximate"
composite_threat_level = 5
composite_threat_class = "x"
[[rules.match_refs]]
category = "prompt_injection"
[[rules.match_refs]]
category = "jailbreak"
"#;
        let path = temp_file(body);
        let err = load_custom_rules(&path).expect_err("missing proximity_bytes should error");
        assert!(err.to_string().contains("proximity_bytes is missing"));
    }

    #[test]
    fn ordered_with_bytes_errors() {
        let body = r#"
[[rules]]
name = "bad"
explanation = ""
constraint_type = "ordered"
proximity_bytes = 100
composite_threat_level = 5
composite_threat_class = "x"
[[rules.match_refs]]
category = "prompt_injection"
[[rules.match_refs]]
category = "jailbreak"
"#;
        let path = temp_file(body);
        let err = load_custom_rules(&path).expect_err("ordered + proximity_bytes should error");
        assert!(err.to_string().contains("proximity_bytes was set"));
    }

    #[test]
    fn wrong_match_ref_count_errors() {
        let body = r#"
[[rules]]
name = "bad"
explanation = ""
constraint_type = "combined"
composite_threat_level = 5
composite_threat_class = "x"
[[rules.match_refs]]
category = "prompt_injection"
"#;
        let path = temp_file(body);
        let err = load_custom_rules(&path).expect_err("1 match_ref should error");
        assert!(err.to_string().contains("must have exactly 2 match_refs"));
    }

    #[test]
    fn unknown_category_errors() {
        let body = r#"
[[rules]]
name = "bad"
explanation = ""
constraint_type = "combined"
composite_threat_level = 5
composite_threat_class = "x"
[[rules.match_refs]]
category = "imaginary_category"
[[rules.match_refs]]
category = "jailbreak"
"#;
        let path = temp_file(body);
        let err = load_custom_rules(&path).expect_err("unknown category should error");
        assert!(err.to_string().contains("unknown category"));
    }
}
