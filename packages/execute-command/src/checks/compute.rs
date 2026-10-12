//! Pure registered compute grammar and learned-key derivation.

/// Validate the closed argv grammar shared by registered compute observations.
///
/// # Errors
/// Returns the existing words, locked or command refusal.
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
    let words: Vec<_> = words.iter().map(String::as_str).collect();
    let valid = match words.as_slice() {
        ["git", "diff"]
        | ["git", "diff", "--stat"]
        | ["git", "status", "--short"]
        | ["cargo", "fmt", "--all"]
        | ["cargo", "fmt", "--all", "--check"]
        | ["cargo", "fmt", "--all", "--", "--check"] => true,
        [
            "cargo",
            verb @ ("check" | "clippy" | "doc" | "test" | "run"),
            rest @ ..,
        ]
        | [
            "cargo",
            "--locked",
            verb @ ("check" | "clippy" | "doc" | "test" | "run"),
            rest @ ..,
        ] => {
            let mut locked = words[1] == "--locked";
            let split = rest
                .iter()
                .position(|word| *word == "--")
                .unwrap_or(rest.len());
            let options = &rest[..split];
            if !locked && !options.contains(&"--locked") {
                return Err("door-compute-locked-refusal");
            }
            let suffix = &rest[split..];
            let mut parameter = None;
            let mut valid = true;
            for option in options {
                if let Some(name) = parameter.take() {
                    let strict_name = name == "--package"
                        || (matches!(*verb, "check" | "clippy" | "test")
                            && matches!(name, "--bin" | "--test"));
                    valid &= !option.is_empty()
                        && (!strict_name || !option.starts_with('-'))
                        && (name == "--features"
                            || option
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)));
                } else if *option == "-p"
                    || (matches!(*verb, "check" | "clippy" | "test")
                        && matches!(*option, "--package" | "--bin" | "--test"))
                    || (*verb == "run" && matches!(*option, "--bin" | "--features"))
                {
                    parameter = Some(*option);
                } else {
                    locked |= *option == "--locked";
                    valid &= matches!(*option, "--locked" | "--workspace" | "--release")
                        || (matches!(*verb, "check" | "clippy" | "test")
                            && matches!(*option, "--lib" | "--bins" | "--tests"))
                        || (matches!(*verb, "check" | "test")
                            && *option == "--no-default-features")
                        || (matches!(*verb, "run" | "clippy" | "test")
                            && *option == "--all-features")
                        || (*verb == "clippy" && *option == "--all-targets")
                        || (*verb == "doc" && *option == "--no-deps")
                        || (*verb == "test" && *option == "--doc");
                }
            }
            if !locked {
                return Err("door-compute-locked-refusal");
            }
            valid
                && parameter.is_none()
                && match *verb {
                    "clippy" => suffix == ["--", "-D", "warnings"],
                    "run" => suffix.len() <= 17,
                    _ => suffix.is_empty(),
                }
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("door-compute-command-refusal")
    }
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
