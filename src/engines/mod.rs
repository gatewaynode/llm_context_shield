use std::collections::BTreeSet;

use serde::Serialize;

use crate::config::Config;
use crate::scanner::{Category, Finding, Severity};
use crate::scoring::ThreatScoreboard;

pub mod fingerprint;

#[cfg(feature = "syara")]
pub mod syara;

#[cfg(feature = "yara")]
pub mod yara;

pub use fingerprint::{compute as compute_fingerprint, RuleSetFingerprint};

#[cfg(feature = "syara")]
pub use syara::SyaraEngine;

#[cfg(feature = "yara")]
pub use yara::YaraEngine;

/// Introspection-shaped per-rule metadata.
///
/// A reshape of the data each engine already extracts from rule sources at
/// scan time, surfaced through [`Engine::rule_metadata`] so external consumers
/// (the `lcs rules` CLI surface, the rule-set fingerprint, programmatic
/// harnesses) can describe the loaded rule set without running a scan.
///
/// `severity: None` means the rule does not declare a single bound severity.
/// YARA / SYARA rules with a `severity = "..."` meta field always emit
/// `Some(_)`; rules that omit the field surface as `None`.
///
/// `version: None` means the rule does not declare a `version` meta field.
/// `threat_level` and `threshold` are non-Optional and mirror the scan-time
/// effective defaults (`1` and `0`) when the rule does not declare them, so
/// introspection matches what the scoring path actually uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMeta {
    pub name: String,
    pub category: Category,
    pub severity: Option<Severity>,
    pub threat_class: String,
    pub version: Option<String>,
    pub context_taxonomy: Vec<String>,
    pub threat_level: i32,
    pub threshold: i32,
    pub provenance: Option<String>,
}

/// Common interface for all scan engines.
///
/// Each engine is responsible for consuming the normalised input text and
/// returning a flat list of `Finding`s. The `disabled` slice carries the
/// scanner/rule names passed via `--disable`; individual engines interpret
/// (or ignore) it as appropriate for their matching strategy.
pub trait Engine: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, input: &str, disabled: &[String]) -> Vec<Finding>;

    /// Names of every rule loaded by this engine, in compilation order.
    ///
    /// The default is empty — engines without an addressable rule concept
    /// do not need to override. Used by `lcs list -e <engine>`.
    fn rule_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Per-rule introspection metadata for every rule loaded by this engine,
    /// in the same order as [`rule_names`](Engine::rule_names).
    ///
    /// Default returns an empty vec for source compatibility with custom
    /// engines (PRD §6.2). Built-in engines override and cache the metadata
    /// at construction time so this is cheap to call.
    fn rule_metadata(&self) -> Vec<RuleMeta> {
        Vec::new()
    }

    /// Categories this engine can emit, derived from [`rule_metadata`].
    ///
    /// Returns the **union** across all loaded rules, sorted in `Category`
    /// declaration order (matches [`Category::ALL`]).
    fn categories(&self) -> BTreeSet<Category> {
        self.rule_metadata().into_iter().map(|r| r.category).collect()
    }

    /// Threat classes this engine can emit, derived from [`rule_metadata`].
    ///
    /// Threat classes are an unbounded vocabulary — rule authors mint them
    /// freely via the `threat_class` meta field — so the only honest answer
    /// is what the running instance has loaded.
    fn threat_classes(&self) -> BTreeSet<String> {
        self.rule_metadata().into_iter().map(|r| r.threat_class).collect()
    }

    /// Run scan and return both findings and threat scores.
    ///
    /// The default calls [`run`](Engine::run) and returns an empty scoreboard.
    /// Built-in engines override this to perform threshold-gated scoring.
    fn run_scored(&self, input: &str, disabled: &[String]) -> (Vec<Finding>, ThreatScoreboard) {
        (self.run(input, disabled), ThreatScoreboard::new())
    }
}

/// Build a boxed engine from its name string.
///
/// Returns `Err` with a human-readable message for unrecognised names or
/// engines whose Cargo feature is not compiled in. The `config` is consumed
/// by engines that need it (rule discovery, Ollama URLs); `simple` ignores it.
///
/// Emits a `tracing::warn!` when the constructed engine has zero rules
/// loaded. The hard error path lives at `ShieldBuilder::build` (per user
/// decision); this warn is the soft signal for code paths that bypass
/// `ShieldBuilder` (currently none in-tree; insurance for library consumers).
pub fn build(name: &str, #[allow(unused_variables)] config: &Config) -> Result<Box<dyn Engine>, String> {
    let engine: Box<dyn Engine> = match name {
        #[cfg(feature = "yara")]
        "yara" => YaraEngine::new(config).map(|e| Box::new(e) as Box<dyn Engine>)?,

        #[cfg(not(feature = "yara"))]
        "yara" => return Err("Engine 'yara' requires the 'yara' Cargo feature. \
                        Rebuild with: cargo build --features yara"
            .into()),

        #[cfg(feature = "syara")]
        "syara" => SyaraEngine::new(config).map(|e| Box::new(e) as Box<dyn Engine>)?,

        #[cfg(not(feature = "syara"))]
        "syara" => return Err("Engine 'syara' requires the 'syara' Cargo feature. \
                         Rebuild with: cargo build --features syara"
            .into()),

        other => return Err(format!("Unknown engine: {other}. Use: yara, syara")),
    };

    if engine.rule_names().is_empty() && engine.rule_metadata().is_empty() {
        tracing::warn!(
            engine = %engine.name(),
            "engine constructed with zero loaded rules"
        );
    }

    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "yara")]
    #[test]
    fn build_yara_engine() {
        let cfg = Config::default();
        assert_eq!(build("yara", &cfg).ok().unwrap().name(), "yara");
    }

    #[cfg(not(feature = "yara"))]
    #[test]
    fn build_yara_without_feature_errors() {
        let cfg = Config::default();
        let err = match build("yara", &cfg) {
            Ok(_) => panic!("expected feature-gated Err"),
            Err(e) => e,
        };
        assert!(err.contains("yara"));
        assert!(err.contains("feature"));
    }

    #[cfg(feature = "syara")]
    #[test]
    fn build_syara_engine() {
        let cfg = Config::default();
        assert_eq!(build("syara", &cfg).ok().unwrap().name(), "syara");
    }

    #[cfg(not(feature = "syara"))]
    #[test]
    fn build_syara_without_feature_errors() {
        let cfg = Config::default();
        let err = match build("syara", &cfg) {
            Ok(_) => panic!("expected feature-gated Err"),
            Err(e) => e,
        };
        assert!(err.contains("syara"));
        assert!(err.contains("feature"));
    }

    #[test]
    fn build_unknown_engine() {
        let cfg = Config::default();
        let err = match build("bogus", &cfg) {
            Ok(_) => panic!("expected Err for unknown engine"),
            Err(e) => e,
        };
        assert!(err.contains("bogus"));
        assert!(err.contains("yara"));
    }
}
