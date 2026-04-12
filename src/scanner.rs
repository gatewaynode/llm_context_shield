use std::fmt;
use std::ops::Range;

use serde::Serialize;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PromptInjection,
    HiddenContent,
    DataExfiltration,
    Jailbreak,
    DelimiterManipulation,
    InstructionOverride,
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
        }
    }
}

impl Category {
    pub fn from_str_loose(s: &str) -> Option<Category> {
        match s.to_lowercase().as_str() {
            "prompt_injection" => Some(Category::PromptInjection),
            "hidden_content" => Some(Category::HiddenContent),
            "data_exfiltration" => Some(Category::DataExfiltration),
            "jailbreak" => Some(Category::Jailbreak),
            "delimiter_manipulation" => Some(Category::DelimiterManipulation),
            "instruction_override" => Some(Category::InstructionOverride),
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
}

impl ScanReport {
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self { findings }
    }

    /// Returns `true` when no findings are present.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, input: &str) -> Vec<Finding>;
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
