use crate::scanner::Scanner;

pub mod data_exfiltration;
pub mod delimiter_manipulation;
pub mod hidden_content;
pub mod instruction_override;
pub mod jailbreak;
pub mod prompt_injection;

/// All registered scanner names in declaration order.
/// Scanners are independent — a single payload may produce findings from multiple
/// scanners, and that overlap is intentional: each category carries distinct signal.
pub const NAMES: &[&str] = &[
    "prompt_injection",
    "instruction_override",
    "jailbreak",
    "delimiter_manipulation",
    "data_exfiltration",
    "hidden_content",
];

pub fn build(disabled: &[String]) -> Vec<Box<dyn Scanner>> {
    let all: Vec<Box<dyn Scanner>> = vec![
        Box::new(prompt_injection::PromptInjectionScanner::new()),
        Box::new(instruction_override::InstructionOverrideScanner::new()),
        Box::new(jailbreak::JailbreakScanner::new()),
        Box::new(delimiter_manipulation::DelimiterManipulationScanner::new()),
        Box::new(data_exfiltration::DataExfiltrationScanner::new()),
        Box::new(hidden_content::HiddenContentScanner::new()),
    ];
    all.into_iter()
        .filter(|s| !disabled.iter().any(|d| d.to_lowercase() == s.name()))
        .collect()
}
