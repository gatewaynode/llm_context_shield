use crate::scanner::Finding;

pub mod simple;
pub mod syara;
pub mod yara;

pub use simple::SimpleEngine;
pub use syara::SyaraEngine;
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
}

/// Build a boxed engine from its name string.
///
/// Returns `None` for unrecognised names so the caller can emit a clean
/// error and exit(2) rather than panicking.
pub fn build(name: &str) -> Option<Box<dyn Engine>> {
    match name {
        "simple" => Some(Box::new(SimpleEngine)),
        "yara" => Some(Box::new(YaraEngine)),
        "syara" => Some(Box::new(SyaraEngine)),
        _ => None,
    }
}
