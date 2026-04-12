use crate::config::Config;
use crate::scanner::Finding;

pub mod simple;

#[cfg(feature = "syara")]
pub mod syara;

#[cfg(feature = "yara")]
pub mod yara;

pub use simple::SimpleEngine;

#[cfg(feature = "syara")]
pub use syara::SyaraEngine;

#[cfg(feature = "yara")]
pub use yara::YaraEngine;

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
    /// The default is empty — engines that have no addressable rule concept
    /// (e.g. `simple`, whose scanners are enumerated by `scanners::NAMES`)
    /// do not need to override. Used by `lcs list -e <engine>`.
    fn rule_names(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Build a boxed engine from its name string.
///
/// Returns `Err` with a human-readable message for unrecognised names or
/// engines whose Cargo feature is not compiled in. The `config` is consumed
/// by engines that need it (rule discovery, Ollama URLs); `simple` ignores it.
pub fn build(name: &str, #[allow(unused_variables)] config: &Config) -> Result<Box<dyn Engine>, String> {
    match name {
        "simple" => Ok(Box::new(SimpleEngine)),

        #[cfg(feature = "yara")]
        "yara" => YaraEngine::new(config).map(|e| Box::new(e) as Box<dyn Engine>),

        #[cfg(not(feature = "yara"))]
        "yara" => Err("Engine 'yara' requires the 'yara' Cargo feature. \
                        Rebuild with: cargo build --features yara"
            .into()),

        #[cfg(feature = "syara")]
        "syara" => SyaraEngine::new(config).map(|e| Box::new(e) as Box<dyn Engine>),

        #[cfg(not(feature = "syara"))]
        "syara" => Err("Engine 'syara' requires the 'syara' Cargo feature. \
                         Rebuild with: cargo build --features syara"
            .into()),

        other => Err(format!("Unknown engine: {other}. Use: simple, yara, syara")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_simple_engine() {
        let cfg = Config::default();
        assert_eq!(build("simple", &cfg).ok().unwrap().name(), "simple");
    }

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
        assert!(err.contains("simple"));
    }
}
