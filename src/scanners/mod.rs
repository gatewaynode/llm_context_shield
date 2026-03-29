use crate::scanner::Scanner;

pub mod data_exfiltration;
pub mod delimiter_manipulation;
pub mod hidden_content;
pub mod instruction_override;
pub mod jailbreak;
pub mod prompt_injection;

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
