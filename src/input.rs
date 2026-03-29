use std::fs;
use std::io::{self, Read};
use std::path::Path;

pub fn read_input(file: Option<&Path>) -> io::Result<String> {
    let raw = match file {
        Some(path) => fs::read_to_string(path)?,
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
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
