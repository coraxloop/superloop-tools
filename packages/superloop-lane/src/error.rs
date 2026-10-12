use std::fmt;

#[derive(Debug)]
pub struct LaneError {
    pub status: u8,
    pub kind: &'static str,
    pub detail: String,
}

impl LaneError {
    pub fn input(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: 2,
            kind,
            detail: detail.into(),
        }
    }

    pub fn operation(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: 1,
            kind,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn line(&self) -> String {
        let mut escaped = String::new();
        for character in self.detail.chars() {
            if matches!(character, '\'' | '"' | '\\') {
                escaped.push(character);
            } else {
                escaped.extend(character.escape_debug());
            }
        }
        format!("{}: {escaped}", self.kind)
    }
}

impl fmt::Display for LaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.line())
    }
}

impl std::error::Error for LaneError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:refusal-escapes-invisible-unicode-with-literal-path-punctuation´
    #[test]
    fn refusal_escapes_invisible_unicode_with_literal_path_punctuation() {
        let error = LaneError::input("fixture", "é '\"\\\u{202e}\u{200b}\u{2028}\u{2029}");
        assert_eq!(
            error.line(),
            "fixture: é '\"\\\\u{202e}\\u{200b}\\u{2028}\\u{2029}"
        );
    }
}
