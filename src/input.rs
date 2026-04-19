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
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    // Normalize Unicode whitespace to ASCII equivalents so regex \s
    // catches exotic spaces (non-breaking space, em space, etc.)
    normalize_unicode_whitespace(&s)
}

/// Replace non-ASCII whitespace with ASCII equivalents.
///
/// Line/paragraph separators (U+2028, U+2029) become `\n`; all other
/// Unicode whitespace becomes a regular space. ASCII whitespace (space,
/// tab, newline, etc.) is left untouched.
fn normalize_unicode_whitespace(input: &str) -> String {
    // Fast path: skip allocation when the input is pure ASCII.
    if input.is_ascii() {
        return input.to_string();
    }
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_whitespace() && !c.is_ascii() {
            match c {
                '\u{2028}' | '\u{2029}' => result.push('\n'),
                _ => result.push(' '),
            }
        } else {
            result.push(c);
        }
    }
    result
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

    #[test]
    fn test_normalize_unicode_whitespace_nbsp() {
        // Non-breaking space (U+00A0) → regular space
        let input = "ignore\u{00A0}previous\u{00A0}instructions";
        assert_eq!(normalize(input), "ignore previous instructions");
    }

    #[test]
    fn test_normalize_unicode_whitespace_em_space() {
        // Em space (U+2003) → regular space
        let input = "ignore\u{2003}previous\u{2003}instructions";
        assert_eq!(normalize(input), "ignore previous instructions");
    }

    #[test]
    fn test_normalize_unicode_line_separator() {
        // Line separator (U+2028) → newline
        assert_eq!(normalize("a\u{2028}b"), "a\nb");
    }

    #[test]
    fn test_normalize_unicode_paragraph_separator() {
        // Paragraph separator (U+2029) → newline
        assert_eq!(normalize("a\u{2029}b"), "a\nb");
    }

    #[test]
    fn test_normalize_ascii_fast_path() {
        // Pure ASCII input takes the fast path — no allocation beyond to_string
        let input = "hello world";
        assert_eq!(normalize_unicode_whitespace(input), "hello world");
    }
}
