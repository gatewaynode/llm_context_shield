use std::fmt;
use std::ops::Range;

use serde::Serialize;

use crate::correlation::MatchCorrelation;
use crate::engines::RuleSetFingerprint;
use crate::scoring::ThreatScoreboard;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str_loose(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PromptInjection,
    HiddenContent,
    DataExfiltration,
    Jailbreak,
    DelimiterManipulation,
    InstructionOverride,
    RefusalSuppression,
    ResponseSteering,
    SecretProbing,
    ContextShift,
    IclExploitation,
    Coercion,
    RefusalBypass,
    SessionProtocol,
    Obfuscation,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::PromptInjection => write!(f, "prompt_injection"),
            Category::HiddenContent => write!(f, "hidden_content"),
            Category::DataExfiltration => write!(f, "data_exfiltration"),
            Category::Jailbreak => write!(f, "jailbreak"),
            Category::DelimiterManipulation => write!(f, "delimiter_manipulation"),
            Category::InstructionOverride => write!(f, "instruction_override"),
            Category::RefusalSuppression => write!(f, "refusal_suppression"),
            Category::ResponseSteering => write!(f, "response_steering"),
            Category::SecretProbing => write!(f, "secret_probing"),
            Category::ContextShift => write!(f, "context_shift"),
            Category::IclExploitation => write!(f, "icl_exploitation"),
            Category::Coercion => write!(f, "coercion"),
            Category::RefusalBypass => write!(f, "refusal_bypass"),
            Category::SessionProtocol => write!(f, "session_protocol"),
            Category::Obfuscation => write!(f, "obfuscation"),
        }
    }
}

impl Category {
    /// Every `Category` variant, in declaration order. The category vocabulary
    /// is the only **bounded** vocabulary — rule names and threat classes are
    /// unbounded (custom rule metadata can mint new threat classes). Consumers
    /// can enumerate categories without instantiating an engine.
    pub const ALL: &'static [Category] = &[
        Category::PromptInjection,
        Category::HiddenContent,
        Category::DataExfiltration,
        Category::Jailbreak,
        Category::DelimiterManipulation,
        Category::InstructionOverride,
        Category::RefusalSuppression,
        Category::ResponseSteering,
        Category::SecretProbing,
        Category::ContextShift,
        Category::IclExploitation,
        Category::Coercion,
        Category::RefusalBypass,
        Category::SessionProtocol,
        Category::Obfuscation,
    ];

    pub fn from_str_loose(s: &str) -> Option<Category> {
        match s.to_lowercase().as_str() {
            "prompt_injection" => Some(Category::PromptInjection),
            "hidden_content" => Some(Category::HiddenContent),
            "data_exfiltration" => Some(Category::DataExfiltration),
            "jailbreak" => Some(Category::Jailbreak),
            "delimiter_manipulation" => Some(Category::DelimiterManipulation),
            "instruction_override" => Some(Category::InstructionOverride),
            "refusal_suppression" => Some(Category::RefusalSuppression),
            "response_steering" => Some(Category::ResponseSteering),
            "secret_probing" => Some(Category::SecretProbing),
            "context_shift" => Some(Category::ContextShift),
            "icl_exploitation" => Some(Category::IclExploitation),
            "coercion" => Some(Category::Coercion),
            "refusal_bypass" => Some(Category::RefusalBypass),
            "session_protocol" => Some(Category::SessionProtocol),
            "obfuscation" => Some(Category::Obfuscation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub description: String,
    pub matched_text: String,
    pub byte_range: (usize, usize),
}

impl Finding {
    pub fn new(
        category: Category,
        severity: Severity,
        description: &str,
        matched_text: &str,
        range: Range<usize>,
    ) -> Self {
        Self {
            category,
            severity,
            description: description.to_string(),
            matched_text: matched_text.to_string(),
            byte_range: (range.start, range.end),
        }
    }
}

/// Raw (unfiltered) scan results. Severity filtering happens at report time.
/// Do not serialize this struct directly — `finding_count` and `clean` reflect
/// unfiltered findings and will be inconsistent with any severity threshold applied
/// during output. Use `report::output()` which builds filtered JSON.
#[derive(Debug)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    /// Threat scores accumulated during scanning. `None` when the engine does
    /// not implement scoring (e.g. custom engines via the default `run_scored`).
    pub scores: Option<ThreatScoreboard>,
    /// Cross-rule and cross-engine correlations fired during this scan.
    /// Empty when no correlation rules are configured or none matched.
    pub correlations: Vec<MatchCorrelation>,
    /// Hex-encoded SHA-256 over the rule metadata of every loaded engine.
    /// Empty for custom-engine `Shield`s and for raw constructor calls;
    /// always populated when the scan went through `Shield::scan`.
    pub rule_set_fingerprint: RuleSetFingerprint,
}

impl ScanReport {
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            scores: None,
            correlations: Vec::new(),
            rule_set_fingerprint: RuleSetFingerprint::default(),
        }
    }

    /// Construct a report with both findings and the scoring state.
    pub fn from_scored(findings: Vec<Finding>, scores: ThreatScoreboard) -> Self {
        Self {
            findings,
            scores: if scores.is_empty() { None } else { Some(scores) },
            correlations: Vec::new(),
            rule_set_fingerprint: RuleSetFingerprint::default(),
        }
    }

    /// Attach correlation results to an existing report.
    pub fn with_correlations(mut self, correlations: Vec<MatchCorrelation>) -> Self {
        self.correlations = correlations;
        self
    }

    /// Attach the rule-set fingerprint to an existing report. Mirrors
    /// [`Self::with_correlations`] — `Shield::scan` calls this last so the
    /// returned report always carries a populated fingerprint.
    pub fn with_rule_set_fingerprint(mut self, fp: RuleSetFingerprint) -> Self {
        self.rule_set_fingerprint = fp;
        self
    }

    /// Returns `true` when no findings are present.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` when at least one correlation fired.
    pub fn has_correlations(&self) -> bool {
        !self.correlations.is_empty()
    }
}

pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, input: &str) -> Vec<Finding>;

    /// The single `Category` this scanner emits, when one applies.
    ///
    /// Default `None` so future scanners that don't have a single bound
    /// category (e.g. multi-category heuristic scanners) need not override.
    /// The 6 bundled regex-backed scanners override and return
    /// `Some(self.inner.category)` so `SimpleEngine::rule_metadata` can
    /// surface category provenance without downcasting `Box<dyn Scanner>`.
    fn category(&self) -> Option<Category> {
        None
    }
}

/// Helper for scanners that are just a list of regex patterns.
pub struct RegexScanner {
    pub name: &'static str,
    pub category: Category,
    pub patterns: Vec<(regex::Regex, Severity, &'static str)>,
}

impl RegexScanner {
    pub fn scan(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (regex, severity, desc) in &self.patterns {
            for m in regex.find_iter(input) {
                findings.push(Finding::new(
                    self.category,
                    *severity,
                    desc,
                    m.as_str(),
                    m.range(),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_from_str_loose_all_variants() {
        assert_eq!(
            Category::from_str_loose("prompt_injection"),
            Some(Category::PromptInjection)
        );
        assert_eq!(
            Category::from_str_loose("hidden_content"),
            Some(Category::HiddenContent)
        );
        assert_eq!(
            Category::from_str_loose("data_exfiltration"),
            Some(Category::DataExfiltration)
        );
        assert_eq!(
            Category::from_str_loose("jailbreak"),
            Some(Category::Jailbreak)
        );
        assert_eq!(
            Category::from_str_loose("delimiter_manipulation"),
            Some(Category::DelimiterManipulation)
        );
        assert_eq!(
            Category::from_str_loose("instruction_override"),
            Some(Category::InstructionOverride)
        );
        assert_eq!(
            Category::from_str_loose("refusal_suppression"),
            Some(Category::RefusalSuppression)
        );
        assert_eq!(
            Category::from_str_loose("response_steering"),
            Some(Category::ResponseSteering)
        );
        assert_eq!(
            Category::from_str_loose("secret_probing"),
            Some(Category::SecretProbing)
        );
        assert_eq!(
            Category::from_str_loose("context_shift"),
            Some(Category::ContextShift)
        );
        assert_eq!(
            Category::from_str_loose("icl_exploitation"),
            Some(Category::IclExploitation)
        );
        assert_eq!(
            Category::from_str_loose("coercion"),
            Some(Category::Coercion)
        );
        assert_eq!(
            Category::from_str_loose("refusal_bypass"),
            Some(Category::RefusalBypass)
        );
        assert_eq!(
            Category::from_str_loose("session_protocol"),
            Some(Category::SessionProtocol)
        );
        assert_eq!(
            Category::from_str_loose("obfuscation"),
            Some(Category::Obfuscation)
        );
    }

    #[test]
    fn category_from_str_loose_case_insensitive() {
        assert_eq!(
            Category::from_str_loose("PROMPT_INJECTION"),
            Some(Category::PromptInjection)
        );
        assert_eq!(
            Category::from_str_loose("Jailbreak"),
            Some(Category::Jailbreak)
        );
    }

    #[test]
    fn category_round_trip_display() {
        for cat in [
            Category::PromptInjection,
            Category::HiddenContent,
            Category::DataExfiltration,
            Category::Jailbreak,
            Category::DelimiterManipulation,
            Category::InstructionOverride,
            Category::RefusalSuppression,
            Category::ResponseSteering,
            Category::SecretProbing,
            Category::ContextShift,
            Category::IclExploitation,
            Category::Coercion,
            Category::RefusalBypass,
            Category::SessionProtocol,
            Category::Obfuscation,
        ] {
            assert_eq!(Category::from_str_loose(&cat.to_string()), Some(cat));
        }
    }

    #[test]
    fn category_from_str_loose_unknown() {
        assert_eq!(Category::from_str_loose("not_a_category"), None);
        assert_eq!(Category::from_str_loose(""), None);
    }
}
