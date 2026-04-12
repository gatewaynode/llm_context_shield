use llm_context_shield::{Category, Engine, Finding, Severity, Shield};

/// A trivial engine that flags any input containing the word "banana".
struct BananaDetector;

impl Engine for BananaDetector {
    fn name(&self) -> &'static str {
        "banana"
    }

    fn run(&self, input: &str, _disabled: &[String]) -> Vec<Finding> {
        let lower = input.to_lowercase();
        let mut findings = Vec::new();
        let mut start = 0;
        while let Some(pos) = lower[start..].find("banana") {
            let abs = start + pos;
            findings.push(Finding::new(
                Category::PromptInjection,
                Severity::High,
                "Banana detected",
                &input[abs..abs + 6],
                abs..abs + 6,
            ));
            start = abs + 6;
        }
        findings
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shield = Shield::builder()
        .custom_engine(Box::new(BananaDetector))
        .build()?;

    let report = shield.scan("I would like a banana split please");
    if report.is_clean() {
        println!("Clean");
    } else {
        for f in &report.findings {
            println!("[{:?}] {}", f.severity, f.description);
        }
    }

    Ok(())
}
