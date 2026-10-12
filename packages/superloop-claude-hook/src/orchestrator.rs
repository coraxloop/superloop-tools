use serde::Serialize;
use serde_json::Value;
pub use session_core::orchestrator::{
    Effect, EventClass, Guard, State, Transition, injection_graph, record_panic,
};
use session_core::orchestrator::{SessionInput, SessionKind};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
const TRANSCRIPT_TAIL_BYTES: u64 = 1_048_576;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookResponse<'a> {
    hook_specific_output: HookSpecificOutput<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput<'a> {
    hook_event_name: &'a str,
    additional_context: &'a str,
}

fn decode(input: &[u8]) -> SessionInput {
    let parsed = serde_json::from_slice::<Value>(input).ok();
    let payload = parsed
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let malformed = payload.is_empty()
        && serde_json::from_slice::<Value>(input).map_or(true, |value| !value.is_object());
    let event = payload
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let source = payload
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let event_class = if malformed {
        EventClass::Malformed
    } else if !matches!(event.as_str(), "SessionStart" | "UserPromptSubmit") {
        EventClass::Unsupported
    } else if event == "SessionStart" && matches!(source.as_str(), "startup" | "clear" | "compact")
    {
        EventClass::Fresh
    } else if event == "SessionStart" && matches!(source.as_str(), "resume" | "fork") {
        EventClass::Resumed
    } else {
        EventClass::Tracked
    };
    let cwd = payload.get("cwd").and_then(Value::as_str).map_or_else(
        || {
            std::env::current_dir().map_or_else(
                |_| String::from("."),
                |path| path.to_string_lossy().into_owned(),
            )
        },
        str::to_owned,
    );
    let session_id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let transcript_path = payload
        .get("transcript_path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(str::to_owned);
    let refused_audience = payload.get("agent_id").is_some_and(json_truthy)
        || transcript_path
            .as_deref()
            .is_some_and(|path| path.contains("/subagents/"));
    let prompt_id = payload
        .get("prompt_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    SessionInput {
        kind: match event.as_str() {
            "SessionStart" => SessionKind::Start,
            "UserPromptSubmit" => SessionKind::Prompt,
            _ => SessionKind::Other,
        },
        event_class,
        event,
        session_id,
        cwd,
        source,
        prompt_id,
        transcript_path,
        refused_audience,
    }
}

pub fn run(input: &[u8]) -> Option<Vec<u8>> {
    let input = decode(input);
    let context = session_core::orchestrator::run(&input, transcript_has_marker)?;
    serde_json::to_vec(&HookResponse {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: &input.event,
            additional_context: &context,
        },
    })
    .ok()
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn transcript_has_marker(path: &str, digest: &str) -> bool {
    let marker = format!("ORCHESTRATION_SCOPE_MARKER v1 sha256={digest}");
    let Ok(mut file) = File::open(expand_home(Path::new(path))) else {
        return false;
    };
    let Ok(size) = file.seek(SeekFrom::End(0)) else {
        return false;
    };
    if file
        .seek(SeekFrom::Start(size.saturating_sub(TRANSCRIPT_TAIL_BYTES)))
        .is_err()
    {
        return false;
    }
    let mut tail = Vec::new();
    file.take(TRANSCRIPT_TAIL_BYTES)
        .read_to_end(&mut tail)
        .is_ok()
        && tail
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
}

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::{EventClass, decode, json_truthy};
    use serde_json::{Value, json};
    /// ´test:unit:derived-agent-truthiness-matches-python-payload-truthiness´
    #[test]
    fn derived_agent_truthiness_matches_python_payload_truthiness() {
        for falsey in [
            Value::Null,
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(!json_truthy(&falsey), "falsey value {falsey}");
        }
        for truthy in [
            json!(true),
            json!(1),
            json!(-1.5),
            json!("agent"),
            json!([0]),
            json!({"id": null}),
        ] {
            assert!(json_truthy(&truthy), "truthy value {truthy}");
        }
    }

    /// ´test:unit:malformed-unsupported-and-source-classes-are-distinct´
    #[test]
    fn malformed_unsupported_and_source_classes_are_distinct() {
        let cases = [
            (b"not-json".as_slice(), EventClass::Malformed),
            (
                br#"{"hook_event_name":"Stop"}"#.as_slice(),
                EventClass::Unsupported,
            ),
            (
                br#"{"hook_event_name":"SessionStart","source":"compact"}"#.as_slice(),
                EventClass::Fresh,
            ),
            (
                br#"{"hook_event_name":"SessionStart","source":"fork"}"#.as_slice(),
                EventClass::Resumed,
            ),
            (
                br#"{"hook_event_name":"SessionStart","source":7}"#.as_slice(),
                EventClass::Tracked,
            ),
            (
                br#"{"hook_event_name":"UserPromptSubmit"}"#.as_slice(),
                EventClass::Tracked,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(decode(input).event_class, expected);
        }
    }
}
