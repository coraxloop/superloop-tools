//! Pure registered compute frame and learned-key derivation.

/// Validate the bounded argv frame shared by registered compute observations.
///
/// # Errors
/// Returns the existing words refusal for a malformed frame.
pub fn validate_words(words: &[String]) -> Result<(), &'static str> {
    if words.is_empty()
        || words.len() > 64
        || words.iter().map(String::len).sum::<usize>() + words.len() > 4096
        || words.iter().any(|word| {
            word.is_empty()
                || word.len() > 256
                || !word
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./:=+,-".contains(&b))
        })
    {
        return Err("door-compute-words-refusal");
    }
    Ok(())
}

/// Derive the exact learned key from validated compute argv.
#[must_use]
pub fn shape(words: &[String]) -> String {
    if let [cargo, locked, verb, ..] = words
        && cargo == "cargo"
        && locked == "--locked"
    {
        return format!("compute:cargo {verb}");
    }
    format!(
        "compute:{}",
        words.iter().take(2).cloned().collect::<Vec<_>>().join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:compute-frame-admits-unlisted-command-families´
    #[test]
    fn compute_frame_admits_unlisted_command_families() {
        for argv in [
            vec!["make", "check"],
            vec!["cargo", "update"],
            vec!["cargo", "test"],
            vec![
                "env",
                "CARGO_NET_OFFLINE=false",
                "cargo",
                "fetch",
                "--locked",
            ],
        ] {
            let words: Vec<_> = argv.into_iter().map(str::to_owned).collect();
            assert_eq!(validate_words(&words), Ok(()), "{words:?}");
        }
        for argv in [
            vec!["make", "check;id"],
            vec!["cargo", ""],
            vec!["sh", "-c", "x y"],
        ] {
            let words: Vec<_> = argv.into_iter().map(str::to_owned).collect();
            assert_eq!(validate_words(&words), Err("door-compute-words-refusal"));
        }
    }
}
