//! Closed compute grammar and operation-specific evidence.

use serde_json::{Value, json};

pub(super) const DEADLINE_MS: u64 = 1_800_000;
pub(super) const NODE_SCRIPT: &str = include_str!("compute_node.py");

pub(super) fn candidate(args: &[Vec<u8>]) -> bool {
    args.len() == 2 && !args[1].starts_with(b"git-")
}

pub(super) fn parse(
    args: &[Vec<u8>],
    alias: &str,
    declared_wrapper: &str,
) -> Result<Vec<String>, &'static str> {
    if args.len() != 2 || args[0] != alias.as_bytes() {
        return Err("door-caller-authority-refusal");
    }
    let command = std::str::from_utf8(&args[1]).map_err(|_| "door-compute-words-refusal")?;
    let (wrapper, tail) = command.split_once(' ').unwrap_or((command, ""));
    if wrapper != declared_wrapper {
        return Err("door-compute-wrapper-refusal");
    }
    let words: Vec<_> = tail.split(' ').map(str::to_owned).collect();
    if command.len() > 4096
        || words.len() > 64
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
    validate_words(&words)?;
    Ok(words)
}

pub use execute_command::checks::compute::shape;
use execute_command::checks::compute::validate_words;

pub(super) fn pending(words: &[String]) -> Value {
    json!({"words":words,"checkout_path":null,"checkout_ref":null,"checkout_commit":null,
        "wrapper_exit_status":null,"wrapper_wall_seconds":null,"preparation_wall_seconds":null,
        "tree_clean":null,"tree_change_count":null,"discarded":null})
}

pub fn valid_detail(value: &Value) -> bool {
    let keys = [
        "words",
        "checkout_path",
        "checkout_ref",
        "checkout_commit",
        "wrapper_exit_status",
        "wrapper_wall_seconds",
        "preparation_wall_seconds",
        "tree_clean",
        "tree_change_count",
        "discarded",
    ];
    if value.as_object().is_none_or(|object| {
        object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key))
    }) {
        return false;
    }
    let Some(words) = value["words"].as_array().and_then(|words| {
        words
            .iter()
            .map(|word| word.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    }) else {
        return false;
    };
    validate_words(&words).is_ok()
        && (value["tree_clean"].is_null() || value["tree_clean"].as_bool().is_some())
        && (value["tree_change_count"].is_null() || value["tree_change_count"].as_u64().is_some())
        && (value["tree_clean"].is_null() == value["tree_change_count"].is_null())
        && (value["tree_clean"].is_null()
            || value["tree_clean"].as_bool() == Some(value["tree_change_count"] == 0))
        && (value["discarded"].is_null()
            || value["discarded"].as_object().is_some_and(|object| {
                object.len() == 2
                    && object.get("tracked").is_some_and(|v| v.as_u64().is_some())
                    && object
                        .get("untracked")
                        .is_some_and(|v| v.as_u64().is_some())
            }))
        && (value["checkout_path"].is_null()
            || value["checkout_path"]
                .as_str()
                .is_some_and(|s| s.starts_with('/') && s.len() <= 4096))
        && (value["checkout_ref"].is_null()
            || value["checkout_ref"]
                .as_str()
                .is_some_and(|s| s.starts_with("refs/heads/lane/") && s.len() <= 160))
        && (value["checkout_commit"].is_null()
            || value["checkout_commit"].as_str().is_some_and(|s| {
                [40, 64].contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
            }))
        && (value["wrapper_exit_status"].is_null()
            || value["wrapper_exit_status"].as_i64().is_some())
        && ["wrapper_wall_seconds", "preparation_wall_seconds"]
            .iter()
            .all(|key| {
                value[*key].is_null()
                    || value[*key]
                        .as_f64()
                        .is_some_and(|wall| wall.is_finite() && wall >= 0.0)
            })
}

pub(super) fn finish(reply: &mut Value, words: &[String], bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    let metadata = text
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("DOOR-COMPUTE "))
        .and_then(|line| serde_json::from_str::<Value>(line).ok());
    let mut detail = pending(words);
    if reply["reason"] == "door-complete" {
        if let Some(metadata) =
            metadata.filter(|m| valid_detail(&m["detail"]) && m["detail"]["words"] == json!(words))
        {
            detail = metadata["detail"].clone();
            let reason = metadata["reason"].as_str().unwrap_or_default();
            if matches!(
                reason,
                "door-complete"
                    | "door-compute-root-refusal"
                    | "door-compute-refresh-refusal"
                    | "door-compute-lane-ref-absent"
                    | "door-compute-tool-refusal"
                    | "door-compute-retired-run"
                    | "door-request-deadline"
            ) {
                reply["reason"] = json!(reason);
            } else {
                reply["reason"] = json!("door-compute-evidence-refusal");
            }
            if reason == "door-complete" {
                let report = text
                    .lines()
                    .rev()
                    .find_map(|line| line.strip_prefix("RUN-REPORT "));
                let wall = report.and_then(|line| {
                    line.split_whitespace().find_map(|word| {
                        word.strip_prefix("wall=")?
                            .strip_suffix('s')?
                            .parse::<f64>()
                            .ok()
                    })
                });
                let exit = report.and_then(|line| {
                    line.split_whitespace()
                        .find_map(|word| word.strip_prefix("exit=")?.parse::<i64>().ok())
                });
                if wall.is_some_and(|wall| wall.is_finite() && wall >= 0.0)
                    && exit == reply["compute_exit_status"].as_i64()
                {
                    detail["wrapper_wall_seconds"] = json!(wall);
                } else {
                    reply["reason"] = json!("door-compute-evidence-refusal");
                }
            }
        } else if matches!(reply["compute_exit_status"].as_i64(), Some(126 | 127))
            || text.lines().any(|line| line == "DOOR-COMPUTE-TOOL-REFUSAL")
        {
            reply["reason"] = json!("door-compute-tool-refusal");
        } else {
            reply["reason"] = json!("door-compute-evidence-refusal");
        }
        if reply["reason"] != "door-complete" {
            reply["status"] = json!(125);
        }
    }
    reply["compute"] = detail;
}
