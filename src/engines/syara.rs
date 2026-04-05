use super::Engine;
use crate::scanner::Finding;

/// SYARA engine — not yet implemented.
///
/// SYARA (Semantic YARA) extends YARA-compatible rule syntax with semantic
/// matching strategies: embedding-based similarity (SBERT), fine-tuned
/// classifiers, and LLM evaluation. This enables high-recall detection of
/// malicious intent expressed in natural language — prompt injection,
/// jailbreaks, phishing, etc. — where exhaustive regex coverage is
/// impractical.
///
/// When implemented, this engine will load `.syara` rule files and dispatch
/// each rule's conditions through the appropriate matcher pipeline
/// (strings → similarity → classifier → LLM), ordered cheapest-first.
///
/// The `disabled` slice will be used to skip rules by name.
pub struct SyaraEngine;

impl Engine for SyaraEngine {
    fn name(&self) -> &'static str {
        "syara"
    }

    fn run(&self, _input: &str, _disabled: &[String]) -> Vec<Finding> {
        tracing::warn!("SYARA engine is not yet implemented; no findings produced");
        eprintln!("Warning: SYARA engine is not yet implemented; no findings produced.");
        vec![]
    }
}
