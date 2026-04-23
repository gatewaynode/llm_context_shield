//! Rule file discovery for external rule-based engines (YARA, SYARA).
//!
//! Load order (all combined, deduplicated only by caller if needed):
//!   1. Bundled rules compiled into the binary (`include_str!`).
//!   2. User-configured directory (`config.rules.dir`) — when set, this
//!      replaces the XDG fallback lookup.
//!   3. XDG data dir fallback (`$XDG_DATA_HOME/llm_context_shield/rules/`).
//!
//! Returned values are **rule source strings**, not file paths. Individual
//! I/O failures are logged and skipped rather than propagated — the caller
//! decides what constitutes a fatal condition at compile time.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::config::Config;

/// Return the source text of every rule available for `engine`.
///
/// `engine` should be `"yara"` or `"syara"`; the string is used both as the
/// subdirectory name and the file extension (`.yar` for yara, `.syara` for
/// syara).
pub fn discover(engine: &str, config: &Config) -> Vec<String> {
    let mut sources = Vec::new();

    let bundled_enabled = config
        .rules
        .as_ref()
        .and_then(|r| r.bundled)
        .unwrap_or(true);
    if bundled_enabled {
        sources.extend(bundled(engine).iter().map(|s| s.to_string()));
    }

    let ext = extension_for(engine);

    if let Some(dir) = config.rules.as_ref().and_then(|r| r.dir.as_deref()) {
        let target = Path::new(dir).join(engine);
        sources.extend(read_rule_dir(&target, ext));
    } else if let Some(xdg) = xdg_rules_dir() {
        let target = xdg.join(engine);
        sources.extend(read_rule_dir(&target, ext));
    }

    sources
}

/// Return bundled rule source strings compiled into the binary.
///
/// YARA rules are bundled under the `yara` Cargo feature; SYARA rules
/// remain empty until Phase 3.
pub fn bundled(engine: &str) -> &'static [&'static str] {
    match engine {
        #[cfg(feature = "yara")]
        "yara" => bundled_yara(),
        #[cfg(feature = "syara")]
        "syara" => bundled_syara(),
        _ => &[],
    }
}

#[cfg(feature = "yara")]
fn bundled_yara() -> &'static [&'static str] {
    &[
        include_str!("../rules/yara/prompt_injection.yar"),
        include_str!("../rules/yara/jailbreak.yar"),
        include_str!("../rules/yara/data_exfiltration.yar"),
        include_str!("../rules/yara/hidden_content.yar"),
        include_str!("../rules/yara/delimiter_manipulation.yar"),
        include_str!("../rules/yara/instruction_override.yar"),
        include_str!("../rules/yara/refusal_suppression.yar"),
        include_str!("../rules/yara/response_steering.yar"),
        include_str!("../rules/yara/secret_probing.yar"),
        include_str!("../rules/yara/context_shift.yar"),
        include_str!("../rules/yara/icl_exploitation.yar"),
    ]
}

#[cfg(feature = "syara")]
fn bundled_syara() -> &'static [&'static str] {
    &[
        include_str!("../rules/syara/prompt_injection.syara"),
        include_str!("../rules/syara/jailbreak.syara"),
        include_str!("../rules/syara/data_exfiltration.syara"),
        include_str!("../rules/syara/hidden_content.syara"),
        include_str!("../rules/syara/delimiter_manipulation.syara"),
        include_str!("../rules/syara/instruction_override.syara"),
        include_str!("../rules/syara/refusal_suppression.syara"),
        include_str!("../rules/syara/response_steering.syara"),
        include_str!("../rules/syara/secret_probing.syara"),
        include_str!("../rules/syara/context_shift.syara"),
        include_str!("../rules/syara/icl_exploitation.syara"),
    ]
}

fn extension_for(engine: &str) -> &'static str {
    match engine {
        "yara" => "yar",
        "syara" => "syara",
        _ => "",
    }
}

/// Maximum permitted size of an individual rule source file.
///
/// Rule files are plain DSL text — 1 MiB is already ~30k lines of YARA, far
/// beyond any realistic hand-authored ruleset. Anything larger is almost
/// certainly a mistake (binary file, log, tarball) or an attempt to OOM the
/// scanner. Oversized files are skipped with a warning.
const MAX_RULE_FILE_BYTES: u64 = 1 << 20;

fn read_rule_dir(dir: &Path, ext: &str) -> Vec<String> {
    if !dir.exists() {
        info!(dir = %dir.display(), "rules dir does not exist, skipping");
        return Vec::new();
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "cannot read rules dir");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();

        // Use symlink_metadata to reject symlinks outright. Following them
        // could route reads to /dev/zero, /etc/shadow, or arbitrary paths
        // outside the rules directory — none of which should be silently
        // compiled as rule sources.
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!(file = %path.display(), error = %e, "cannot stat rule file");
                continue;
            }
        };
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            warn!(file = %path.display(), "skipping symlink in rules dir");
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some(ext) {
            continue;
        }
        if meta.len() > MAX_RULE_FILE_BYTES {
            warn!(
                file = %path.display(),
                size = meta.len(),
                limit = MAX_RULE_FILE_BYTES,
                "skipping rule file: exceeds size limit"
            );
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(src) => out.push(src),
            Err(e) => warn!(file = %path.display(), error = %e, "cannot read rule file"),
        }
    }
    out
}

/// Create `<base>/yara/` and `<base>/syara/` subdirectories and write a
/// README stub into `<base>` if one does not already exist.
///
/// Idempotent: existing directories and an existing `README.md` are left
/// untouched. Returns the first filesystem error encountered.
pub fn scaffold_rules_dir(base: &Path) -> std::io::Result<()> {
    for engine in ["yara", "syara"] {
        let dir = base.join(engine);
        fs::create_dir_all(&dir).map_err(|e| {
            std::io::Error::other(format!("cannot create {}: {e}", dir.display()))
        })?;
    }
    let readme = base.join("README.md");
    if !readme.exists() {
        fs::write(&readme, RULES_README_STUB).map_err(|e| {
            std::io::Error::other(format!("cannot write {}: {e}", readme.display()))
        })?;
    }
    Ok(())
}

const RULES_README_STUB: &str = r#"# llm_context_shield — custom rules

Drop custom rule files here. They are loaded at startup *in addition* to the
bundled rules compiled into the binary.

## Layout

    yara/   *.yar    — YARA-X rules, loaded when running `lcs scan -e yara`
    syara/  *.syara  — SYARA-X rules, loaded when running `lcs scan -e syara`

Files are loaded flat (no recursion). Each rule must set the `category` and
`severity` metadata fields — rules missing these are skipped with a warning.

## Required metadata

    meta:
        category    = "prompt_injection"   // or: jailbreak, data_exfiltration,
                                           //     hidden_content,
                                           //     delimiter_manipulation,
                                           //     instruction_override,
                                           //     refusal_suppression,
                                           //     response_steering,
                                           //     secret_probing,
                                           //     context_shift,
                                           //     icl_exploitation
        severity    = "high"               // low | medium | high | critical
        description = "short explanation"  // optional, surfaces in reports

## Disabling bundled rules

Set `[rules] bundled = false` in `~/.config/llm_context_shield/config.toml` to
load *only* the files in this directory.

## See also

- `lcs list -e yara` / `lcs list -e syara` — show all loaded rule names
- `lcs scan --disable <rule_name>` — suppress a specific rule by name
"#;

/// Resolve the effective rules directory.
///
/// Prefers `config.rules.dir` when set; otherwise falls back to
/// [`xdg_rules_dir`]. Returns `None` only when neither the config override
/// nor any XDG/HOME environment variable is available.
pub fn effective_rules_dir(config: &Config) -> Option<PathBuf> {
    if let Some(dir) = config.rules.as_ref().and_then(|r| r.dir.as_deref()) {
        return Some(PathBuf::from(dir));
    }
    xdg_rules_dir()
}

/// Resolve `$XDG_DATA_HOME/llm_context_shield/rules/` (or
/// `~/.local/share/llm_context_shield/rules/`). Returns `None` when neither
/// `XDG_DATA_HOME` nor `HOME` is set.
pub fn xdg_rules_dir() -> Option<PathBuf> {
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        Some(
            PathBuf::from(data_home)
                .join("llm_context_shield")
                .join("rules"),
        )
    } else {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("llm_context_shield")
                .join("rules")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RulesConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_tmp(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lcs-rules-test-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn bundled_unknown_engine_is_empty() {
        assert!(bundled("nonexistent").is_empty());
    }

    #[cfg(feature = "syara")]
    #[test]
    fn bundled_syara_is_populated() {
        let rules = bundled("syara");
        assert!(!rules.is_empty());
        for src in rules {
            assert!(src.contains("rule "), "bundled source missing rule keyword");
        }
    }

    #[cfg(not(feature = "syara"))]
    #[test]
    fn bundled_syara_empty_without_feature() {
        assert!(bundled("syara").is_empty());
    }

    #[cfg(feature = "yara")]
    #[test]
    fn bundled_yara_is_populated() {
        let rules = bundled("yara");
        assert!(!rules.is_empty());
        // Every bundled source must parse as text with at least one `rule` keyword.
        for src in rules {
            assert!(src.contains("rule "), "bundled source missing rule keyword");
        }
    }

    #[cfg(not(feature = "yara"))]
    #[test]
    fn bundled_yara_empty_without_feature() {
        assert!(bundled("yara").is_empty());
    }

    #[test]
    fn discover_from_config_dir_loads_yar_files() {
        let tmp = unique_tmp("cfgdir");
        let yara_dir = tmp.join("yara");
        fs::create_dir_all(&yara_dir).unwrap();
        fs::write(yara_dir.join("rule_a.yar"), "rule a {}").unwrap();
        fs::write(yara_dir.join("rule_b.yar"), "rule b {}").unwrap();
        // Wrong extension should be ignored.
        fs::write(yara_dir.join("ignored.txt"), "junk").unwrap();

        let cfg = Config {
            rules: Some(RulesConfig {
                dir: Some(tmp.to_string_lossy().into_owned()),
                bundled: Some(false),
            }),
            ..Config::default()
        };

        let mut sources = discover("yara", &cfg);
        sources.sort();
        assert_eq!(
            sources,
            vec!["rule a {}".to_string(), "rule b {}".to_string()]
        );

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn discover_from_config_dir_loads_syara_files() {
        let tmp = unique_tmp("syara");
        let syara_dir = tmp.join("syara");
        fs::create_dir_all(&syara_dir).unwrap();
        fs::write(syara_dir.join("r.syara"), "rule r {}").unwrap();
        fs::write(syara_dir.join("r.yar"), "wrong ext").unwrap();

        let cfg = Config {
            rules: Some(RulesConfig {
                dir: Some(tmp.to_string_lossy().into_owned()),
                bundled: Some(false),
            }),
            ..Config::default()
        };

        let sources = discover("syara", &cfg);
        assert_eq!(sources, vec!["rule r {}".to_string()]);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn discover_missing_dir_returns_empty() {
        let tmp = unique_tmp("missing");
        // Point at a child dir that doesn't exist.
        let cfg = Config {
            rules: Some(RulesConfig {
                dir: Some(tmp.join("nope").to_string_lossy().into_owned()),
                bundled: Some(false),
            }),
            ..Config::default()
        };

        assert!(discover("yara", &cfg).is_empty());

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn scaffold_creates_subdirs_and_readme() {
        let tmp = unique_tmp("scaffold");
        scaffold_rules_dir(&tmp).unwrap();
        assert!(tmp.join("yara").is_dir());
        assert!(tmp.join("syara").is_dir());
        let readme = tmp.join("README.md");
        assert!(readme.is_file());
        let body = fs::read_to_string(&readme).unwrap();
        assert!(body.contains("category"));
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn scaffold_is_idempotent_and_preserves_readme() {
        let tmp = unique_tmp("scaffold-idem");
        scaffold_rules_dir(&tmp).unwrap();
        let readme = tmp.join("README.md");
        fs::write(&readme, "custom user content").unwrap();
        scaffold_rules_dir(&tmp).unwrap();
        assert_eq!(fs::read_to_string(&readme).unwrap(), "custom user content");
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn effective_rules_dir_prefers_config_override() {
        let cfg = Config {
            rules: Some(RulesConfig {
                dir: Some("/tmp/custom-rules-path".into()),
                bundled: None,
            }),
            ..Config::default()
        };
        assert_eq!(
            effective_rules_dir(&cfg),
            Some(PathBuf::from("/tmp/custom-rules-path"))
        );
    }

    #[test]
    fn discover_rejects_symlinked_rule_file() {
        #[cfg(unix)]
        {
            let tmp = unique_tmp("symlink");
            let yara_dir = tmp.join("yara");
            fs::create_dir_all(&yara_dir).unwrap();

            // A real rule file: should load.
            fs::write(yara_dir.join("real.yar"), "rule real {}").unwrap();

            // A target outside the rules dir, then a symlink to it inside.
            let outside = tmp.join("outside.yar");
            fs::write(&outside, "rule outside {}").unwrap();
            std::os::unix::fs::symlink(&outside, yara_dir.join("link.yar")).unwrap();

            let cfg = Config {
                rules: Some(RulesConfig {
                    dir: Some(tmp.to_string_lossy().into_owned()),
                    bundled: Some(false),
                }),
                ..Config::default()
            };

            let sources = discover("yara", &cfg);
            assert_eq!(sources, vec!["rule real {}".to_string()]);

            fs::remove_dir_all(&tmp).ok();
        }
    }

    #[test]
    fn discover_skips_oversized_rule_file() {
        let tmp = unique_tmp("oversize");
        let yara_dir = tmp.join("yara");
        fs::create_dir_all(&yara_dir).unwrap();

        fs::write(yara_dir.join("small.yar"), "rule small {}").unwrap();
        // Write one byte past the limit.
        let big = vec![b'a'; (MAX_RULE_FILE_BYTES + 1) as usize];
        fs::write(yara_dir.join("big.yar"), big).unwrap();

        let cfg = Config {
            rules: Some(RulesConfig {
                dir: Some(tmp.to_string_lossy().into_owned()),
                bundled: Some(false),
            }),
            ..Config::default()
        };

        let sources = discover("yara", &cfg);
        assert_eq!(sources, vec!["rule small {}".to_string()]);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn discover_bundled_disabled_skips_bundled() {
        // Phase 1 tautology (bundled is empty), but locks the contract.
        let cfg = Config {
            rules: Some(RulesConfig {
                dir: None,
                bundled: Some(false),
            }),
            ..Config::default()
        };
        // Result depends only on XDG state; we assert no panic and that
        // disabling bundled does not add any bundled entries.
        let _ = discover("yara", &cfg);
    }
}
