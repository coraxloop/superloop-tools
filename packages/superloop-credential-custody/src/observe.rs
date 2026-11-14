//! Metadata row validation; the reviewed payload owns the length computation.
use crate::{
    identity, process, receipt,
    record::{Discovery, Parameters, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub name: String,
    pub input_length: u64,
    pub content: String,
    pub file_bytes: u64,
    pub wrap: u64,
    pub final_lf: bool,
    pub base64_chars: u64,
    pub padding: u64,
    pub decoded: u64,
    pub offset: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Constant {
    pub name: String,
    pub constant: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compared {
    pub id: String,
    pub equal: bool,
}

fn number(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("payload-row-number");
    }
    value.parse().map_err(|_| "payload-row-number")
}

fn rows(bytes: &[u8]) -> Result<(Vec<Row>, Vec<Constant>, Vec<Compared>)> {
    let text = std::str::from_utf8(bytes).map_err(|_| "payload-row-encoding")?;
    if !text.ends_with('\n') {
        return Err("payload-row-framing");
    }
    let mut rows = Vec::new();
    let mut constants = Vec::new();
    let mut comparisons = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split(' ').collect();
        match fields.as_slice() {
            [
                name,
                length,
                content,
                "file-bytes",
                size,
                "wrap",
                wrap,
                "final-lf",
                lf,
                "base64-chars",
                count,
                "padding",
                padding,
                "decoded",
                decoded,
                "offset",
                offset,
            ] => {
                let lf = match *lf {
                    "0" => false,
                    "1" => true,
                    _ => return Err("payload-row-form"),
                };
                rows.push(Row {
                    name: (*name).into(),
                    input_length: number(length)?,
                    content: (*content).into(),
                    file_bytes: number(size)?,
                    wrap: number(wrap)?,
                    final_lf: lf,
                    base64_chars: number(count)?,
                    padding: number(padding)?,
                    decoded: number(decoded)?,
                    offset: offset.parse().map_err(|_| "payload-row-number")?,
                });
            }
            [name, "constant", offset] => constants.push(Constant {
                name: (*name).into(),
                constant: offset.parse().map_err(|_| "payload-row-number")?,
            }),
            [id, "same-constant-both-names", equal] => comparisons.push(Compared {
                id: (*id).into(),
                equal: match *equal {
                    "True" => true,
                    "False" => false,
                    _ => return Err("payload-row-comparison"),
                },
            }),
            _ => return Err("payload-row-shape"),
        }
    }
    Ok((rows, constants, comparisons))
}

pub fn validate(
    record: &Parameters,
    rows: &[Row],
    constants: &[Constant],
    comparisons: &[Compared],
) -> Result<()> {
    if rows.len() != record.samples.len()
        || constants.len() != record.names.len()
        || comparisons.len() != record.comparisons.len()
    {
        return Err("payload-missing-rows");
    }
    let mut seen = BTreeSet::new();
    let mut offsets = BTreeMap::new();
    for row in rows {
        if !seen.insert((&row.name, row.input_length, &row.content))
            || !record.samples.iter().any(|s| {
                s.name == row.name && s.input_length == row.input_length && s.content == row.content
            })
            || row.wrap != record.identity.form.wrap
            || row.final_lf != record.identity.form.final_lf
            || row.file_bytes > record.limits.file_bytes
            || row.base64_chars == 0
            || row.base64_chars > row.file_bytes
            || row.base64_chars % 4 != 0
            || row.padding > 2
            || row.file_bytes
                != row.base64_chars
                    + u64::from(row.final_lf)
                    + (row.base64_chars - 1).checked_div(row.wrap).unwrap_or(0)
            || row.decoded != 3 * (row.base64_chars / 4) - row.padding
            || i64::try_from(row.decoded)
                .ok()
                .and_then(|n| i64::try_from(row.input_length).ok().map(|input| n - input))
                != Some(row.offset)
        {
            return Err("payload-row-inconsistent");
        }
        if offsets
            .insert(&row.name, row.offset)
            .is_some_and(|old| old != row.offset)
        {
            return Err("length-condition-refused");
        }
    }
    let mut seen = BTreeSet::new();
    for constant in constants {
        if !seen.insert(&constant.name) || offsets.get(&constant.name) != Some(&constant.constant) {
            return Err("payload-constant");
        }
    }
    let mut seen = BTreeSet::new();
    for comparison in comparisons {
        let pair = record
            .comparisons
            .iter()
            .find(|p| p.id == comparison.id)
            .ok_or("payload-comparison")?;
        if !seen.insert(&comparison.id)
            || comparison.equal != (offsets.get(&pair.left) == offsets.get(&pair.right))
        {
            return Err("payload-comparison");
        }
    }
    Ok(())
}

fn payload(record: &Parameters) -> Result<Vec<u8>> {
    let installed = receipt::read(&record.payload.path, 262_144, false)?;
    if identity::hash(&installed) != record.payload.sha256 {
        return Err("payload-digest");
    }
    let _repository = receipt::repository(&record.payload.repository)?;
    let mut command = Command::new("/usr/bin/git");
    command
        .arg("--no-pager")
        .arg("--no-replace-objects")
        .args(["-c", "protocol.allow=never"])
        .arg("-C")
        .arg(&record.payload.repository)
        .arg("show")
        .arg(format!(
            "{}:{}",
            record.payload.source_commit,
            record.payload.document.display()
        ));
    let document = process::capture_git(command, &record.limits)?;
    let text = std::str::from_utf8(&document).map_err(|_| "payload-source-encoding")?;
    let mut matches = 0;
    let lines: Vec<_> = text.split_inclusive('\n').collect();
    for (index, line) in lines.iter().enumerate() {
        // Extract only complete, single-quoted heredoc bodies. The full digest,
        // not a document label or configurable command string, selects the body.
        let Some((_, suffix)) = line.split_once("<<'") else {
            continue;
        };
        let Some(marker) = suffix.strip_suffix("'\n") else {
            continue;
        };
        if !crate::record::name(marker) {
            continue;
        }
        let mut body = Vec::new();
        for line in &lines[index + 1..] {
            if line.trim_end_matches('\n') == marker {
                if identity::hash(&body) == record.payload.sha256 && body == installed {
                    matches += 1;
                }
                break;
            }
            body.extend_from_slice(line.as_bytes());
            if body.len() > 262_144 {
                break;
            }
        }
    }
    if matches != 1 {
        return Err("payload-source-identity");
    }
    Ok(installed)
}

fn sample_bytes(record: &Parameters) -> Result<BTreeMap<(String, u64, String), u64>> {
    let mut sizes = BTreeMap::new();
    for sample in &record.samples {
        let path = record
            .sealed_root
            .join(&sample.name)
            .join(format!("{}-{}.sealed", sample.input_length, sample.content));
        let bytes = receipt::read(&path, record.limits.file_bytes, true)?;
        if identity::hash(&bytes) != sample.completion.sealed_sha256 {
            return Err("sealed-completion-identity");
        }
        sizes.insert(
            (
                sample.name.clone(),
                sample.input_length,
                sample.content.clone(),
            ),
            bytes.len() as u64,
        );
    }
    Ok(sizes)
}

pub fn discover(record: &Discovery) -> Result<Value> {
    let parent = record.input.parent().ok_or("discovery-path")?;
    let _directory = receipt::sealed_directory(parent)?;
    let bytes = receipt::read(&record.input, record.file_bytes, true)?;
    let final_lf = bytes.ends_with(b"\n");
    let body = if final_lf {
        &bytes[..bytes.len() - 1]
    } else {
        &bytes
    };
    let widths: Vec<_> = body.split(|b| *b == b'\n').map(<[u8]>::len).collect();
    let alphabet = body
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || b"+/=\n".contains(b));
    let wrap = if widths.len() == 1 {
        Some(0)
    } else {
        let first = widths[0];
        (first > 0
            && widths[..widths.len() - 1].iter().all(|n| *n == first)
            && widths.last().is_some_and(|n| *n > 0 && *n <= first))
        .then_some(first)
    };
    Ok(
        json!({"discovery": true, "line_count": widths.len(), "wrap_width": wrap,
            "final_newline": final_lf, "alphabet_conformity": alphabet}),
    )
}

pub fn run(record: &Parameters) -> Result<Value> {
    // Other accounts cannot replace any directory component while the reviewed
    // payload rereads these paths. Concurrent mutation by the effective user is
    // still excluded by the caller's observation protocol.
    let _root = receipt::sealed_directory(&record.sealed_root)?;
    let _names: Vec<_> = record
        .names
        .iter()
        .map(|name| receipt::sealed_directory(&record.sealed_root.join(name)))
        .collect::<Result<_>>()?;
    let source = payload(record)?;
    let live = identity::live(record)?;
    let sizes = sample_bytes(record)?;
    let mut command = Command::new("/usr/bin/python3");
    command
        .arg("-I")
        .arg("-")
        .arg(&record.sealed_root)
        .arg(record.identity.form.wrap.to_string())
        .arg(if record.identity.form.final_lf {
            "1"
        } else {
            "0"
        });
    let output = process::capture_matching(command, &source, &record.limits, &live.interpreter)?;
    let (rows, constants, comparisons) = rows(&output)?;
    validate(record, &rows, &constants, &comparisons)?;
    for row in &rows {
        if sizes.get(&(row.name.clone(), row.input_length, row.content.clone()))
            != Some(&row.file_bytes)
        {
            return Err("payload-file-size");
        }
    }
    if sizes != sample_bytes(record)? {
        return Err("sealed-changed");
    }
    // Re-read identities after the observation; deployment exclusion remains an
    // operator prerequisite, not something a successful digest check establishes.
    if live.identity != identity::live(record)?.identity {
        return Err("identity-drift");
    }
    Ok(
        json!({"identity": live.identity, "config_digest": record.config_digest, "code_digest": record.code_digest,
        "rows": rows, "constants": constants, "comparisons": comparisons}),
    )
}
