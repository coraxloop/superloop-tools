use std::fs;
use std::io;
use std::path::PathBuf;

use crate::error::ProvisionError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyLine {
    pub(crate) source: String,
    pub(crate) number: usize,
    pub(crate) text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MergeLine {
    pub(crate) source: String,
    pub(crate) number: usize,
    pub(crate) text: String,
    pub(crate) added: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MergeResult {
    pub(crate) content: String,
    pub(crate) lines: Vec<MergeLine>,
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decodable_base64(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || bytes[..bytes.len() - padding].contains(&b'=') {
        return false;
    }
    if padding > 0 && !bytes.len().is_multiple_of(4) {
        return false;
    }
    let unpadded = &bytes[..bytes.len() - padding];
    if unpadded.is_empty() || unpadded.len() % 4 == 1 {
        return false;
    }
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for byte in unpadded {
        let Some(digit) = base64_value(*byte) else {
            return false;
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            accumulator &= (1_u32 << bits).saturating_sub(1);
        }
    }
    accumulator == 0
}

pub(crate) fn validate_key_line(
    source: &str,
    number: usize,
    line: &str,
) -> Result<KeyLine, ProvisionError> {
    if line.trim() != line || line.is_empty() {
        return Err(ProvisionError::refusal(
            "public_key_malformed",
            format!("{source} line {number}: expected an OpenSSH public-key line"),
        ));
    }
    let mut fields = line.split_ascii_whitespace();
    let key_type = fields.next();
    let payload = fields.next();
    if key_type.is_none()
        || payload.is_none()
        || !key_type.is_some_and(|token| {
            token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'=')
        })
        || !payload.is_some_and(decodable_base64)
    {
        return Err(ProvisionError::refusal(
            "public_key_malformed",
            format!("{source} line {number}: expected type token plus decodable base64"),
        ));
    }
    Ok(KeyLine {
        source: source.to_owned(),
        number,
        text: line.to_owned(),
    })
}

pub(crate) fn parse_key_text(source: &str, text: &str) -> Result<Vec<KeyLine>, ProvisionError> {
    let keys = text
        .lines()
        .enumerate()
        .map(|(index, line)| validate_key_line(source, index + 1, line))
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(ProvisionError::refusal(
            "public_key_missing",
            format!("{source} contains no public-key lines"),
        ));
    }
    Ok(keys)
}

pub(crate) fn load_key_files(paths: &[PathBuf]) -> Result<Vec<KeyLine>, ProvisionError> {
    let mut keys = Vec::new();
    for path in paths {
        let source = path.display().to_string();
        let text = fs::read_to_string(path).map_err(|error| {
            ProvisionError::refusal("input_failure", format!("{source}: {error}"))
        })?;
        keys.extend(parse_key_text(&source, &text)?);
    }
    Ok(keys)
}

pub(crate) fn load_admit_keys<R: io::Read>(
    paths: &[PathBuf],
    input: &mut R,
) -> Result<Vec<KeyLine>, ProvisionError> {
    if !paths.is_empty() {
        return load_key_files(paths);
    }
    let mut text = String::new();
    input.read_to_string(&mut text).map_err(|error| {
        ProvisionError::refusal("input_failure", format!("standard input: {error}"))
    })?;
    parse_key_text("standard input", &text)
}

pub(crate) fn merge_keys(existing: &str, keys: &[KeyLine]) -> MergeResult {
    let mut seen = existing.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut content = existing.to_owned();
    let mut lines = Vec::new();
    for key in keys {
        let added = !seen.iter().any(|line| line == &key.text);
        if added {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&key.text);
            content.push('\n');
            seen.push(key.text.clone());
        }
        lines.push(MergeLine {
            source: key.source.clone(),
            number: key.number,
            text: key.text.clone(),
            added,
        });
    }
    MergeResult { content, lines }
}
