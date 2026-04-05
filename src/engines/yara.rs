use super::Engine;
use crate::scanner::Finding;

/// YARA engine — not yet implemented.
///
/// Uses YARA-X (`yara-x` crate, VirusTotal's pure-Rust YARA re-implementation)
/// for pattern matching. YARA-X is a drop-in successor to classic YARA with
/// improved safety, speed, and a native Rust API.
///
/// When implemented, this engine will compile `.yar` rule files from a
/// configurable rules directory and evaluate each rule against the input
/// text, emitting one `Finding` per match.
///
/// The `disabled` slice will be used to skip rules by name, mirroring the
/// behaviour of `--disable` for the simple engine's regex scanners.
pub struct YaraEngine;

impl Engine for YaraEngine {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn run(&self, _input: &str, _disabled: &[String]) -> Vec<Finding> {
        tracing::warn!("YARA engine is not yet implemented; no findings produced");
        eprintln!("Warning: YARA engine is not yet implemented; no findings produced.");
        vec![]
    }
}
