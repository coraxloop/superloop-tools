use serde_json::{Map, Value, json};
pub use session_core::heartbeat::{
    Effect, Guard, State, Timing, Transition, heartbeat_graph, parse_timestamp,
    record_letters_listing_failure, record_panic, record_payload_failure,
};
use session_core::heartbeat::{Entry, FailureClass, Observations, StopFields, StopInput, Timer};
use std::fs;
use std::path::{Path, PathBuf};
const FEEDBACK_PREFIX: &str = "Stop hook feedback:";
const BLOCK_REASON: &str = "HEARTBEAT GUARD: no wakeup is currently armed and the heartbeat toggle is ON. did you use ListAgents, are all your watchers happy? Please set the ScheduleWakeup now (the turn then ends naturally on its result), or - if this turn genuinely ends blocked on the user with nothing in flight - run `superloop heartbeat off` first, then end the turn.";

const UNPROMPTED_MESSAGE: &str = "HEARTBEAT GUARD EXCEPTION (unprompted arm): ScheduleWakeup was armed UNPROMPTED this turn (before any guard block). Protocol: never arm unprompted - work, reply in text, and arm only when this hook prompts (or run `heartbeat off` when genuinely blocked on the user).";

const LAPSE_MESSAGE: &str = "HEARTBEAT GUARD EXCEPTION (lapse): the guard prompted 3 times this turn and the agent took neither legal exit (re-arm ScheduleWakeup / stop the heartbeat). The stop is allowed and the heartbeat has LAPSED - no wakeup is armed.";

/// Captured semantic and process result for one evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookResult {
    /// Harness process status: zero for allow and two for block.
    pub status: u8,
    /// Hook-protocol response bytes for a lapse allow.
    pub stdout: Vec<u8>,
    /// Agent-directed reason bytes for an intentional block.
    pub stderr: Vec<u8>,
    /// Reached composed terminal verdict node.
    pub state: State,
    /// Complete direct-graph path, including semantic nodes.
    pub path: Vec<State>,
    /// Number of controlled flush-race retries.
    pub retry_count: u8,
}

struct ClaudeObservations;
impl Observations for ClaudeObservations {
    fn load(&self, path: &Path) -> Result<Vec<Entry>, FailureClass> {
        Ok(load_entries(path)?.iter().map(decode_entry).collect())
    }
    fn letters(&self, cwd: &str, home: &Path) -> super::letters::Listing {
        super::letters::inspect(cwd, home).1
    }
}

fn decode_entry(entry: &Map<String, Value>) -> Entry {
    let results = message_content(entry).map(|blocks| {
        blocks
            .iter()
            .filter_map(|block| {
                let block = block.as_object()?;
                (block.get("type").and_then(Value::as_str) == Some("tool_result")).then(|| {
                    (
                        required_identifier(block.get("tool_use_id")),
                        !json_truthy(block.get("is_error")),
                    )
                })
            })
            .collect()
    });
    let timers = message_content(entry).map(|blocks| {
        blocks
            .iter()
            .filter_map(|block| {
                let block = block.as_object()?;
                (block.get("type").and_then(Value::as_str) == Some("tool_use")
                    && block.get("name").and_then(Value::as_str) == Some("ScheduleWakeup"))
                .then(|| Timer {
                    id: required_identifier(block.get("id")),
                    parameters: object_or_empty(block.get("input")).map(|params| {
                        (
                            json_truthy(params.get("stop")),
                            params.get("delaySeconds").and_then(Value::as_f64),
                        )
                    }),
                })
            })
            .collect()
    });
    Entry {
        sidechain: json_truthy(entry.get("isSidechain")),
        timestamp: entry_timestamp(entry),
        user: entry.get("type").and_then(Value::as_str) == Some("user"),
        assistant: entry.get("type").and_then(Value::as_str) == Some("assistant"),
        real_user: is_real_user_turn(entry),
        feedback: is_guard_feedback(entry),
        results,
        timers,
    }
}

fn decode(input: &[u8]) -> StopInput {
    let parsed = serde_json::from_slice::<Value>(input).ok();
    let payload = parsed.and_then(|value| value.as_object().cloned());
    let cwd = payload.as_ref().and_then(|object| {
        let event_valid = match object.get("hook_event_name") {
            None => true,
            Some(Value::String(event)) => event == "Stop",
            Some(_) => false,
        };
        if !event_valid {
            return None;
        }
        match object.get("cwd") {
            None | Some(Value::Null) => Some(String::new()),
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => None,
        }
    });
    let fields = (|| {
        let payload = payload.as_ref().ok_or(FailureClass::Payload)?;
        let transcript_path = match payload.get("transcript_path") {
            None | Some(Value::Null) => PathBuf::new(),
            Some(Value::String(value)) => PathBuf::from(value),
            Some(_) => return Err(FailureClass::Payload),
        };
        let session = match payload.get("session_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => return Err(FailureClass::Payload),
        };
        let retry = match payload.get("stop_hook_active") {
            None | Some(Value::Null | Value::Bool(false)) => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(FailureClass::Payload),
        };
        Ok(StopFields {
            transcript_path,
            session,
            retry,
        })
    })();
    StopInput { cwd, fields }
}

#[must_use]
pub fn run(input: &[u8], state_dir: &Path, timing: Timing) -> HookResult {
    run_with_listing(input, state_dir, timing, super::letters::Listing::Empty)
}

#[must_use]
pub fn run_with_listing(
    input: &[u8],
    state_dir: &Path,
    timing: Timing,
    listing: super::letters::Listing,
) -> HookResult {
    let result = session_core::heartbeat::run(
        &decode(input),
        state_dir,
        timing,
        &ClaudeObservations,
        listing,
    );
    terminal_result(
        result.state,
        result.path,
        result.retry_count,
        &result.feedback,
    )
}

fn terminal_result(state: State, path: Vec<State>, retry_count: u8, feedback: &str) -> HookResult {
    match state {
        State::AllowSilent => silent_result(state, path, retry_count),
        State::BlockPrompt => block_result(state, BLOCK_REASON, path, retry_count),
        State::BlockViolation => block_result(state, UNPROMPTED_MESSAGE, path, retry_count),
        State::BlockViolationAndPrompt => block_result(
            state,
            &format!("{UNPROMPTED_MESSAGE}\n\n{BLOCK_REASON}"),
            path,
            retry_count,
        ),
        State::AllowLapseAlarm => response_result(state, LAPSE_MESSAGE, path, retry_count),
        State::AllowLapseAndViolationAlarm => response_result(
            state,
            &format!("{LAPSE_MESSAGE}\n{UNPROMPTED_MESSAGE}"),
            path,
            retry_count,
        ),
        State::BlockLetters => block_result(state, feedback, path, retry_count),
        State::BlockLettersAndPrompt => block_result(
            state,
            &letters_reason(feedback, BLOCK_REASON),
            path,
            retry_count,
        ),
        State::BlockLettersAndViolation => block_result(
            state,
            &letters_reason(feedback, UNPROMPTED_MESSAGE),
            path,
            retry_count,
        ),
        State::BlockLettersAndViolationAndPrompt => block_result(
            state,
            &letters_reason(feedback, &format!("{UNPROMPTED_MESSAGE}\n{BLOCK_REASON}")),
            path,
            retry_count,
        ),
        State::AllowLettersFeedback => response_result(state, feedback, path, retry_count),
        State::AllowLettersLapse => response_result(
            state,
            &format!("{LAPSE_MESSAGE}\n{feedback}"),
            path,
            retry_count,
        ),
        State::AllowLettersLapseAndViolation => response_result(
            state,
            &format!("{LAPSE_MESSAGE}\n{UNPROMPTED_MESSAGE}\n{feedback}"),
            path,
            retry_count,
        ),
        State::BlockPromptFeedback => {
            json_block_result(state, BLOCK_REASON, feedback, path, retry_count)
        }
        State::BlockViolationFeedback => {
            json_block_result(state, UNPROMPTED_MESSAGE, feedback, path, retry_count)
        }
        State::BlockViolationAndPromptFeedback => json_block_result(
            state,
            &format!("{UNPROMPTED_MESSAGE}\n{BLOCK_REASON}"),
            feedback,
            path,
            retry_count,
        ),
        _ => silent_result(State::AllowSilent, path, retry_count),
    }
}

fn letters_reason(feedback: &str, heartbeat: &str) -> String {
    let (header, entries) = feedback.split_once('\n').unwrap_or((feedback, ""));
    format!("{header}\n{heartbeat}\n{entries}")
}

const fn silent_result(state: State, path: Vec<State>, retry_count: u8) -> HookResult {
    HookResult {
        status: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
        state,
        path,
        retry_count,
    }
}

fn block_result(state: State, reason: &str, path: Vec<State>, retry_count: u8) -> HookResult {
    HookResult {
        status: 2,
        stdout: Vec::new(),
        stderr: reason.as_bytes().to_vec(),
        state,
        path,
        retry_count,
    }
}

fn response_result(state: State, message: &str, path: Vec<State>, retry_count: u8) -> HookResult {
    let stdout = serde_json::to_vec(&json!({"systemMessage": message})).unwrap_or_default();
    HookResult {
        status: 0,
        stdout,
        stderr: Vec::new(),
        state,
        path,
        retry_count,
    }
}

fn json_block_result(
    state: State,
    reason: &str,
    feedback: &str,
    path: Vec<State>,
    retry_count: u8,
) -> HookResult {
    let mut result = silent_result(state, path, retry_count);
    result.stdout = serde_json::to_vec(
        &json!({"decision": "block", "reason": reason, "systemMessage": feedback}),
    )
    .unwrap_or_default();
    result
}

fn load_entries(path: &Path) -> Result<Vec<Map<String, Value>>, FailureClass> {
    let source = fs::read_to_string(path).map_err(|_| FailureClass::TranscriptRead)?;
    let mut entries = Vec::new();
    for line in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Ok(Value::Object(entry)) = serde_json::from_str::<Value>(line) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn is_real_user_turn(entry: &Map<String, Value>) -> Result<bool, FailureClass> {
    if entry.get("type").and_then(Value::as_str) != Some("user")
        || json_truthy(entry.get("isSidechain"))
    {
        return Ok(false);
    }
    if is_guard_feedback(entry)? {
        return Ok(false);
    }
    let Some(message) = message_object(entry)? else {
        return Ok(false);
    };
    match message.get("content") {
        Some(Value::Array(content)) => Ok(!content.iter().any(|block| {
            block.as_object().is_some_and(|object| {
                object.get("type").and_then(Value::as_str) == Some("tool_result")
            })
        })),
        Some(Value::String(_)) => Ok(true),
        _ => Ok(false),
    }
}

fn is_guard_feedback(entry: &Map<String, Value>) -> Result<bool, FailureClass> {
    if entry.get("type").and_then(Value::as_str) != Some("user")
        || json_truthy(entry.get("isSidechain"))
    {
        return Ok(false);
    }
    let Some(message) = message_object(entry)? else {
        return Ok(false);
    };
    Ok(match message.get("content") {
        Some(Value::String(content)) => content.starts_with(FEEDBACK_PREFIX),
        Some(Value::Array(content)) => content.iter().any(|block| {
            block.as_object().is_some_and(|object| {
                object.get("type").and_then(Value::as_str) == Some("text")
                    && object
                        .get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.starts_with(FEEDBACK_PREFIX))
            })
        }),
        _ => false,
    })
}

fn message_content(entry: &Map<String, Value>) -> Result<&[Value], FailureClass> {
    let Some(message) = message_object(entry)? else {
        return Ok(&[]);
    };
    Ok(message
        .get("content")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice))
}

fn message_object(entry: &Map<String, Value>) -> Result<Option<&Map<String, Value>>, FailureClass> {
    match entry.get("message") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(message)) => Ok(Some(message)),
        Some(value) if !json_truthy(Some(value)) => Ok(None),
        Some(_) => Err(FailureClass::TranscriptStructure),
    }
}

fn object_or_empty(value: Option<&Value>) -> Result<&Map<String, Value>, FailureClass> {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    match value {
        None | Some(Value::Null) => Ok(&EMPTY),
        Some(Value::Object(object)) => Ok(object),
        Some(candidate) if !json_truthy(Some(candidate)) => Ok(&EMPTY),
        Some(_) => Err(FailureClass::TranscriptStructure),
    }
}

fn required_identifier(value: Option<&Value>) -> Result<String, FailureClass> {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(FailureClass::TranscriptStructure)
}

fn entry_timestamp(entry: &Map<String, Value>) -> Option<f64> {
    entry
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
}

fn json_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_none_or(|number| number != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
    }
}
