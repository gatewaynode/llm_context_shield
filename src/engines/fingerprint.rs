//! Rule-set fingerprint — a stable, hex-encoded SHA-256 over the loaded rule
//! metadata, scoped to a single `Shield` instance.
//!
//! Per Priori 2 (rules are mutable outside `lcs` — filesystem-discovered,
//! custom-config), the schema of any given install is **per-instance**, not
//! per-binary. The fingerprint exists so two installs of the same `lcs`
//! version can be compared cheaply ("are we running the same rule set?")
//! without exchanging the rules themselves.
//!
//! Determinism contract:
//! - Input is sorted by `(engine_name, rule_name)` before hashing.
//! - Each `(engine_name, RuleMeta)` tuple is serialised as canonical JSON via
//!   `serde_json` (`RuleMeta` field order is fixed by struct declaration).
//! - Tuples are joined with `\n` and SHA-256-hashed; the digest is hex-encoded
//!   lowercase.

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::RuleMeta;

/// Hex-encoded SHA-256 over the canonicalised `(engine, rule_metadata)` set.
///
/// Empty string is the zero-state used internally before [`compute`] runs;
/// `Shield` always overwrites it before returning a `ScanReport`, so external
/// consumers never observe the empty value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RuleSetFingerprint(pub String);

impl RuleSetFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for RuleSetFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Compute a fingerprint over a slice of `(engine_name, rule_metadata)` pairs.
///
/// Today every `Shield` carries one engine, so the slice has length 1; the
/// API is shaped for the multi-engine future without forcing a rewrite.
pub fn compute(engines: &[(&str, &[RuleMeta])]) -> RuleSetFingerprint {
    let mut tuples: Vec<(String, &RuleMeta)> = Vec::new();
    for (engine_name, metas) in engines {
        for meta in *metas {
            tuples.push(((*engine_name).to_string(), meta));
        }
    }
    tuples.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name))
    });

    let mut hasher = Sha256::new();
    for (i, (engine_name, meta)) in tuples.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        let line = serde_json::to_string(&(engine_name, meta))
            .expect("RuleMeta is always serialisable");
        hasher.update(line.as_bytes());
    }
    RuleSetFingerprint(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Category, Severity};

    fn meta(name: &str, category: Category, threat_class: &str) -> RuleMeta {
        RuleMeta {
            name: name.to_string(),
            category,
            severity: Some(Severity::High),
            threat_class: threat_class.to_string(),
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let metas = vec![
            meta("rule_a", Category::PromptInjection, "prompt_injection"),
            meta("rule_b", Category::Jailbreak, "jailbreak"),
        ];
        let fp1 = compute(&[("simple", &metas)]);
        let fp2 = compute(&[("simple", &metas)]);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.0.len(), 64);
        assert!(fp1.0.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn order_invariant() {
        let metas_ordered = vec![
            meta("rule_a", Category::PromptInjection, "prompt_injection"),
            meta("rule_b", Category::Jailbreak, "jailbreak"),
        ];
        let metas_shuffled = vec![
            meta("rule_b", Category::Jailbreak, "jailbreak"),
            meta("rule_a", Category::PromptInjection, "prompt_injection"),
        ];
        assert_eq!(
            compute(&[("simple", &metas_ordered)]),
            compute(&[("simple", &metas_shuffled)]),
        );
    }

    #[test]
    fn threat_class_change_changes_fingerprint() {
        let m1 = vec![meta("rule_a", Category::PromptInjection, "old_class")];
        let m2 = vec![meta("rule_a", Category::PromptInjection, "new_class")];
        assert_ne!(compute(&[("simple", &m1)]), compute(&[("simple", &m2)]));
    }

    #[test]
    fn category_change_changes_fingerprint() {
        let m1 = vec![meta("rule_a", Category::PromptInjection, "x")];
        let m2 = vec![meta("rule_a", Category::Jailbreak, "x")];
        assert_ne!(compute(&[("simple", &m1)]), compute(&[("simple", &m2)]));
    }

    #[test]
    fn severity_change_changes_fingerprint() {
        let mut m1 = meta("rule_a", Category::PromptInjection, "x");
        let mut m2 = m1.clone();
        m1.severity = Some(Severity::Low);
        m2.severity = Some(Severity::Critical);
        assert_ne!(
            compute(&[("simple", std::slice::from_ref(&m1))]),
            compute(&[("simple", std::slice::from_ref(&m2))]),
        );
    }

    #[test]
    fn engine_name_change_changes_fingerprint() {
        let metas = vec![meta("rule_a", Category::PromptInjection, "x")];
        assert_ne!(
            compute(&[("simple", &metas)]),
            compute(&[("yara", &metas)]),
        );
    }

    #[test]
    fn empty_rule_set_still_hashes() {
        let fp = compute(&[("simple", &[])]);
        assert_eq!(fp.0.len(), 64);
    }
}
