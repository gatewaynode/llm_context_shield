use regex::Regex;

use crate::scanner::{Category, Finding, Scanner, Severity};

pub struct HiddenContentScanner {
    zero_width_chars: Vec<(char, &'static str)>,
    base64_pattern: Regex,
    homoglyph_pattern: Regex,
}

impl Default for HiddenContentScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl HiddenContentScanner {
    pub fn new() -> Self {
        Self {
            zero_width_chars: vec![
                ('\u{200B}', "Zero-width space"),
                ('\u{200C}', "Zero-width non-joiner"),
                ('\u{200D}', "Zero-width joiner"),
                ('\u{2060}', "Word joiner (invisible)"),
                ('\u{FEFF}', "Zero-width no-break space / BOM in body"),
                ('\u{00AD}', "Soft hyphen (invisible)"),
                ('\u{180E}', "Mongolian vowel separator"),
                ('\u{2062}', "Invisible times"),
                ('\u{2063}', "Invisible separator"),
                ('\u{2064}', "Invisible plus"),
            ],
            // Matches suspicious base64-like strings (40+ chars, padding optional)
            base64_pattern: Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").expect("static regex pattern is valid"),
            // Common Cyrillic/Greek homoglyphs of Latin letters mixed with ASCII
            homoglyph_pattern: Regex::new(r"[\x00-\x7F]*[\u{0400}-\u{04FF}\u{0370}-\u{03FF}][\x00-\x7F]*[\u{0400}-\u{04FF}\u{0370}-\u{03FF}]").expect("static regex pattern is valid"),
        }
    }
}

impl Scanner for HiddenContentScanner {
    fn name(&self) -> &'static str {
        "hidden_content"
    }

    fn scan(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for zero-width characters
        for (ch, desc) in &self.zero_width_chars {
            for (idx, _) in input.match_indices(*ch) {
                let end = idx + ch.len_utf8();
                findings.push(Finding::new(
                    Category::HiddenContent,
                    Severity::High,
                    desc,
                    &format!("U+{:04X}", *ch as u32),
                    idx..end,
                ));
            }
        }

        // Check for suspicious base64 blobs
        for m in self.base64_pattern.find_iter(input) {
            findings.push(Finding::new(
                Category::HiddenContent,
                Severity::Medium,
                "Suspicious base64-encoded content",
                &truncate(m.as_str(), 60),
                m.range(),
            ));
        }

        // Check for homoglyph mixing (Cyrillic/Greek chars in otherwise Latin text)
        for m in self.homoglyph_pattern.find_iter(input) {
            findings.push(Finding::new(
                Category::HiddenContent,
                Severity::High,
                "Mixed script homoglyphs (possible visual spoofing)",
                &truncate(m.as_str(), 60),
                m.range(),
            ));
        }

        findings
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let end = s.floor_char_boundary(max_len);
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(input: &str) -> Vec<Finding> {
        HiddenContentScanner::new().scan(input)
    }

    #[test]
    fn detects_zero_width_space() {
        let input = "hello\u{200B}world";
        let findings = scan(input);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description == "Zero-width space"));
    }

    #[test]
    fn detects_zero_width_joiner() {
        let input = "test\u{200D}string";
        let findings = scan(input);
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_base64_blob() {
        let input = "Normal text then SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc= more text";
        let findings = scan(input);
        assert!(findings.iter().any(|f| f.description.contains("base64")));
    }

    #[test]
    fn detects_cyrillic_homoglyphs() {
        // Mix of Latin 'a' and Cyrillic 'а' (U+0430) and 'e' -> 'е' (U+0435)
        let input = "p\u{0430}ssw\u{043E}rd";
        let findings = scan(input);
        assert!(findings.iter().any(|f| f.description.contains("homoglyph")));
    }

    #[test]
    fn clean_text_no_findings() {
        let findings = scan("Just a normal English sentence with no tricks.");
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_short_alphanumeric() {
        // Short base64-like strings should not trigger
        let findings = scan("The product ID is ABC123def456.");
        assert!(findings.is_empty());
    }

    #[test]
    fn truncate_multibyte_no_panic() {
        // 59 ASCII bytes followed by a Cyrillic char — homoglyph match truncation
        // previously panicked because byte offset 60 falls inside the 2-byte Cyrillic char.
        let mut input = "A".repeat(59);
        input.push('\u{0430}'); // Cyrillic 'а' (2 bytes in UTF-8)
        input.push('\u{0435}'); // Cyrillic 'е' — need two non-Latin chars for homoglyph pattern
        let findings = scan(&input);
        // Must not panic; homoglyph finding should be present
        assert!(findings.iter().any(|f| f.description.contains("homoglyph")));
    }
}
