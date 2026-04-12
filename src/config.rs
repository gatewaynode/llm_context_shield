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
        toml::from_str(&text)
            .map_err(|e| io::Error::other(format!("invalid config {}: {e}", path.display())))
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
"#;
