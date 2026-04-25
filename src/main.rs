use std::process;

use clap::Parser;
use tracing::{error, info};

use llm_context_shield::cli::{Cli, Command};
use llm_context_shield::config::Config;
use llm_context_shield::engines;
use llm_context_shield::input::read_input;
use llm_context_shield::report::{output, write_passthrough};
use llm_context_shield::scanner::Severity;
use llm_context_shield::scanners;
use llm_context_shield::shield::Shield;

fn main() {
    let cli = Cli::parse();

    // First-run bootstrap: if invoked with no scan flags and the config dir is
    // absent, create the directory and write a commented default config file.
    let no_explicit_args = std::env::args().len() == 2; // binary + subcommand only
    if no_explicit_args
        && !Config::config_dir_exists()
        && let Err(e) = Config::init_default()
    {
        eprintln!("Warning: could not initialise config: {e}");
    }

    // Load config; fall back to defaults on missing file, warn on parse error.
    let config = Config::load().unwrap_or_else(|e| {
        eprintln!("Warning: could not load config: {e}");
        Config::default()
    });

    // --log flag OR config log = true enables logging.
    let logging_enabled = cli.log || config.log.unwrap_or(false);
    if logging_enabled && let Err(e) = llm_context_shield::logging::init() {
        eprintln!("Warning: could not initialise log: {e}");
    }

    info!(version = env!("CARGO_PKG_VERSION"), "starting");

    match cli.command {
        Command::Scan {
            file,
            format,
            severity,
            disable,
            engine,
            safe_only_passthrough,
            output: output_file,
            threat_scores,
            correlations,
        } => {
            // Merge: CLI arg > config > built-in default.
            let scan_cfg = config.scan.as_ref();
            let format = format
                .or_else(|| scan_cfg.and_then(|s| s.format.clone()))
                .unwrap_or_else(|| "text".to_string());
            let severity = severity
                .or_else(|| scan_cfg.and_then(|s| s.severity.clone()))
                .unwrap_or_else(|| "low".to_string());
            let disable = if disable.is_empty() {
                scan_cfg.and_then(|s| s.disable.clone()).unwrap_or_default()
            } else {
                disable
            };
            let engine_name = engine
                .or_else(|| scan_cfg.and_then(|s| s.engine.clone()))
                .unwrap_or_else(|| "simple".to_string());

            let _scan = tracing::info_span!(
                "scan",
                file = ?file,
                format = %format,
                severity = %severity,
                engine = %engine_name,
            )
            .entered();

            let min_severity = Severity::from_str_loose(&severity).unwrap_or_else(|| {
                error!(value = %severity, "invalid severity");
                eprintln!("Invalid severity: {severity}. Use: low, medium, high, critical");
                process::exit(2);
            });

            if !matches!(format.as_str(), "json" | "text" | "quiet") {
                error!(value = %format, "invalid format");
                eprintln!("Invalid format: {format}. Use: json, text, quiet");
                process::exit(2);
            }

            let shield = Shield::builder()
                .engine(&engine_name)
                .min_severity(min_severity)
                .disable(disable)
                .config(config)
                .build()
                .unwrap_or_else(|err| {
                    error!(value = %engine_name, "invalid engine");
                    eprintln!("{err}");
                    process::exit(2);
                });

            let input = match read_input(file.as_deref()) {
                Ok(text) => text,
                Err(e) => {
                    error!(error = %e, "failed to read input");
                    eprintln!("Error reading input: {e}");
                    process::exit(2);
                }
            };

            let report = shield.scan(&input);
            info!(
                total = report.findings.len(),
                correlations = report.correlations.len(),
                "scan complete"
            );

            info!(
                format = %format,
                min_severity = %min_severity,
                filtered = report.findings.len(),
                "output"
            );

            if let Err(e) = output(
                &report,
                &format,
                min_severity,
                safe_only_passthrough,
                threat_scores,
                correlations,
            ) {
                error!(error = %e, "failed to write output");
                eprintln!("Error writing output: {e}");
                process::exit(2);
            }

            let has_findings = !report.findings.is_empty();

            if safe_only_passthrough
                && !has_findings
                && let Err(e) = write_passthrough(&input, output_file.as_deref())
            {
                error!(error = %e, "failed to write passthrough");
                eprintln!("Error writing passthrough: {e}");
                process::exit(2);
            }

            let exit_code = if has_findings { 1 } else { 0 };
            info!(exit_code, "exit");
            process::exit(exit_code);
        }
        Command::Init { rules } => {
            if !Config::config_dir_exists()
                && let Err(e) = Config::init_default()
            {
                error!(error = %e, "could not initialise config");
                eprintln!("Error initialising config: {e}");
                process::exit(2);
            }
            println!("Config: {}", llm_context_shield::config::config_path().display());

            if rules {
                match llm_context_shield::rules::effective_rules_dir(&config) {
                    Some(dir) => {
                        if let Err(e) = llm_context_shield::rules::scaffold_rules_dir(&dir) {
                            error!(error = %e, "could not scaffold rules dir");
                            eprintln!("Error scaffolding rules dir: {e}");
                            process::exit(2);
                        }
                        println!("Rules: {}", dir.display());
                    }
                    None => {
                        eprintln!(
                            "Error: cannot resolve rules directory — set $XDG_DATA_HOME, $HOME, or [rules] dir in config.toml"
                        );
                        process::exit(2);
                    }
                }
            }
        }
        Command::List { engine } => {
            let engine_name = engine
                .or_else(|| config.scan.as_ref().and_then(|s| s.engine.clone()))
                .unwrap_or_else(|| "simple".to_string());

            match engine_name.as_str() {
                "simple" => {
                    for name in scanners::NAMES {
                        println!("{name}");
                    }
                }
                other => {
                    let engine = engines::build(other, &config).unwrap_or_else(|err| {
                        error!(value = %other, "invalid engine");
                        eprintln!("{err}");
                        process::exit(2);
                    });
                    for name in engine.rule_names() {
                        println!("{name}");
                    }
                }
            }
        }
    }
}
