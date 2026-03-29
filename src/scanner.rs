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
