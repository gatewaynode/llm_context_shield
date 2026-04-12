use std::fs;
use std::io::{self, Read};
use std::path::Path;

/// Maximum input size: 100 MiB. Anything larger is almost certainly not a
/// single LLM context payload and risks OOM on machines with limited memory.
const MAX_INPUT_BYTES: u64 = 100 * 1024 * 1024;

pub fn read_input(file: Option<&Path>) -> io::Result<String> {
    let raw = match file {
        Some(path) => {
            let meta = fs::metadata(path)?;
            if meta.len() > MAX_INPUT_BYTES {
                return Err(io::Error::other(format!(
                    "input file exceeds {} MiB limit ({} bytes)",
                    MAX_INPUT_BYTES / (1024 * 1024),
                    meta.len(),
                )));
            }
            fs::read_to_string(path)?
        }
        None => {
            let mut buf = String::new();
            io::stdin().take(MAX_INPUT_BYTES + 1).read_to_string(&mut buf)?;
            if buf.len() as u64 > MAX_INPUT_BYTES {
                return Err(io::Error::other(format!(
                    "stdin input exceeds {} MiB limit",
                    MAX_INPUT_BYTES / (1024 * 1024),
                )));
            }
            buf
        }
    };
    Ok(normalize(&raw))
}

fn normalize(input: &str) -> String {
    // Strip UTF-8 BOM
    let s = input.strip_prefix('\u{FEFF}').unwrap_or(input);
    // Normalize line endings to \n
    s.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_strips_bom() {
        let input = "\u{FEFF}hello";
        assert_eq!(normalize(input), "hello");
    }

    #[test]
    fn test_normalize_line_endings() {
        assert_eq!(normalize("a\r\nb\rc"), "a\nb\nc");
    }

    #[test]
    fn test_normalize_clean_input() {
        assert_eq!(normalize("hello\nworld"), "hello\nworld");
    }
}
