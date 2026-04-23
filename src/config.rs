use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use serde::Deserialize;

/// Top-level configuration file structure.
///
/// All fields are optional; CLI arguments take precedence over config values,
/// which take precedence over built-in defaults.
#[derive(Deserialize, Default)]
pub struct Config {
    /// Enable logging (mirrors `--log`).
    pub log: Option<bool>,
    /// Scan subcommand defaults.
    pub scan: Option<ScanConfig>,
    /// Rule discovery configuration (for yara/syara engines).
    pub rules: Option<RulesConfig>,
    /// SYARA engine semantic matcher configuration.
    pub syara: Option<SyaraConfig>,
    /// Threat scoring configuration.
    pub scoring: Option<ScoringConfig>,
}

/// Rule-file discovery configuration.
#[derive(Deserialize, Default)]
pub struct RulesConfig {
    /// Override the rules directory. When unset, falls back to the XDG data dir.
    pub dir: Option<String>,
    /// Whether to load bundled (built-in) rules. Default: true.
    pub bundled: Option<bool>,
}

/// SYARA engine semantic matcher configuration.
#[derive(Deserialize, Default)]
pub struct SyaraConfig {
    pub ollama_url: Option<String>,
    pub embed_model: Option<String>,
    pub llm_model: Option<String>,
    /// Path to the directory containing `model.onnx` + `tokenizer.json` for the
    /// ONNX-local `sbert` matcher (used by the `syara-sbert` / `syara-classifier`
    /// features). Not required when using HTTP-endpoint matchers.
    pub onnx_model_dir: Option<String>,
}

/// Threat scoring configuration.
#[derive(Deserialize, Default, Clone)]
pub struct ScoringConfig {
    /// Minimum class score that triggers cross-branch escalation.
    /// Default: 100 (effectively inert until tuned).
    pub escalation_threshold: Option<i32>,
    /// Amount to reduce other classes' thresholds when escalation fires.
    /// Default: 0 (no reduction until tuned).
    pub escalation_reduction: Option<i32>,
    /// Per-class weight factors controlling contribution to the cumulative
    /// score. Classes not listed default to 1.0.
    pub class_weights: Option<HashMap<String, f32>>,
}

impl ScoringConfig {
    /// Validate scoring configuration values. Returns a list of warnings for
    /// invalid values that were clamped to safe defaults.
    pub fn validate(&mut self) -> Vec<String> {
        let mut warnings = Vec::new();
        if let Some(t) = self.escalation_threshold
            && t < 0
        {
            warnings.push(format!(
                "scoring.escalation_threshold is negative ({t}), clamping to 0"
            ));
            self.escalation_threshold = Some(0);
        }
        if let Some(r) = self.escalation_reduction
            && r < 0
        {
            warnings.push(format!(
                "scoring.escalation_reduction is negative ({r}), clamping to 0"
            ));
            self.escalation_reduction = Some(0);
        }
        if let Some(ref mut weights) = self.class_weights {
            weights.retain(|class, weight| {
                if weight.is_nan() || weight.is_infinite() {
                    warnings.push(format!(
                        "scoring.class_weights.{class} is {weight}, removing"
                    ));
                    return false;
                }
                if *weight < 0.0 {
                    warnings.push(format!(
                        "scoring.class_weights.{class} is negative ({weight}), clamping to 0.0"
                    ));
                    *weight = 0.0;
                }
                true
            });
        }
        warnings
    }
}

/// Configuration defaults for the `scan` subcommand.
#[derive(Deserialize, Default)]
pub struct ScanConfig {
    /// Output format: json, text, quiet.
    pub format: Option<String>,
    /// Minimum severity to report: low, medium, high, critical.
    pub severity: Option<String>,
    /// Scanners or rules to disable (list of names).
    pub disable: Option<Vec<String>>,
    /// Scan engine to use: simple, yara, syara.
    pub engine: Option<String>,
}

impl Config {
    /// Load config from the XDG config path.
    ///
    /// Returns `Default` when the file does not exist; propagates errors on
    /// I/O failure or malformed TOML.
    pub fn load() -> io::Result<Self> {
        let path = config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| io::Error::other(format!("cannot read config {}: {e}", path.display())))?;
        let mut config: Self = toml::from_str(&text)
            .map_err(|e| io::Error::other(format!("invalid config {}: {e}", path.display())))?;
        if let Some(ref mut scoring) = config.scoring {
            for warning in scoring.validate() {
                eprintln!("Warning: {warning}");
            }
        }
        Ok(config)
    }

    #[doc(hidden)]
    pub fn config_dir_exists() -> bool {
        xdg_config_dir().exists()
    }

    #[doc(hidden)]
    pub fn init_default() -> io::Result<()> {
        let dir = xdg_config_dir();
        fs::create_dir_all(&dir).map_err(|e| {
            io::Error::other(format!("cannot create config dir {}: {e}", dir.display()))
        })?;
        let path = dir.join("config.toml");
        fs::write(&path, DEFAULT_CONFIG)
            .map_err(|e| io::Error::other(format!("cannot write config {}: {e}", path.display())))
    }
}

/// Return the path to the config file (`<config_dir>/config.toml`).
pub fn config_path() -> PathBuf {
    xdg_config_dir().join("config.toml")
}

/// Resolve `~/.config/llm_context_shield`, honouring `$XDG_CONFIG_HOME`.
fn xdg_config_dir() -> PathBuf {
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(config_home).join("llm_context_shield")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("llm_context_shield")
    } else {
        PathBuf::from(".config").join("llm_context_shield")
    }
}

const DEFAULT_CONFIG: &str = r#"# llm_context_shield configuration
# File: ~/.config/llm_context_shield/config.toml
#
# All CLI flags can be set here as defaults.
# CLI arguments always take precedence over values in this file.

# Enable logging to ~/.local/state/llm_context_shield/llm_context_shield.log
# log = false

[scan]
# Output format: json, text, quiet
# format = "text"

# Minimum severity to report: low, medium, high, critical
# severity = "low"

# Disable specific scanners by name
# disable = []

# Scan engine: simple (regex), yara, syara
# engine = "simple"

[rules]
# Override the default rules directory.
# Default: $XDG_DATA_HOME/llm_context_shield/rules/
# dir = "/path/to/custom/rules"

# Whether to load bundled (built-in) rules. Default: true.
# bundled = true

[syara]
# Ollama base URL for semantic matchers.
# Default: http://localhost:11434
# ollama_url = "http://localhost:11434"

# Model name for embedding-based matchers (sbert, classifier).
# embed_model = "all-minilm"

# Model name for LLM evaluator.
# llm_model = "llama3.2"

# Directory containing model.onnx + tokenizer.json for the ONNX-local sbert
# matcher (used when building with --features syara-sbert). The default path
# is searched when this is unset. See docs/semantic-rules.md.
# onnx_model_dir = "./models/all-MiniLM-L6-v2"

[scoring]
# Cross-branch escalation: when any threat class accumulates this score,
# thresholds for other classes are reduced by escalation_reduction.
# Default: 100 (inert until tuned with real-world data)
# escalation_threshold = 100

# Amount to reduce other classes' thresholds when escalation fires.
# Default: 0 (no reduction until tuned)
# escalation_reduction = 0

# Per-class weight factors (float). Controls how much a class contributes
# to the global cumulative score. Unlisted classes default to 1.0.
# [scoring.class_weights]
# obfuscation = 0.5
"#;
