use std::fs;
use std::io;
use std::path::PathBuf;

use tracing_appender::rolling;

/// Initialise tracing to a daily-rotating log file under the XDG state directory.
///
/// Files are written to:
///   `~/.local/state/llm_context_shield/llm_context_shield.log.YYYY-MM-DD`
///
/// `$XDG_STATE_HOME` is respected when set. One file is created per calendar day;
/// older files are not automatically deleted.
///
/// Returns an error if the log directory cannot be created, or if a global
/// tracing subscriber is already registered.
pub fn init() -> io::Result<()> {
    let dir = xdg_state_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| io::Error::other(format!("cannot create log dir {}: {e}", dir.display())))?;

    let appender = rolling::daily(&dir, "llm_context_shield.log");

    let subscriber = tracing_subscriber::fmt()
        .with_writer(appender)
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| io::Error::other(format!("cannot set tracing subscriber: {e}")))?;

    Ok(())
}

/// Resolve the XDG state directory for this tool.
/// Respects `$XDG_STATE_HOME`; falls back to `~/.local/state`.
fn xdg_state_dir() -> PathBuf {
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(state_home).join("llm_context_shield")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("llm_context_shield")
    } else {
        PathBuf::from(".local")
            .join("state")
            .join("llm_context_shield")
    }
}
