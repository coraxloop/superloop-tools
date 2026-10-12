#![doc = include_str!("../README.md")]

pub mod heartbeat;
pub mod orchestrator;
mod permission;

use std::ffi::OsString;
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;

use serde_json::Value;

#[derive(Default)]
struct Reply {
    status: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Reply {
    fn context(stdout: Option<Vec<u8>>) -> Self {
        Self {
            stdout: stdout.unwrap_or_default(),
            ..Self::default()
        }
    }

    fn refusal(reason: &str) -> Self {
        let reason = format!("infrastructure-failure: {reason}; no policy judgment was made");
        let quoted = serde_json::to_string(&reason).unwrap_or_default();
        Self {
            status: 2,
            stdout: format!("{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":{quoted},\"additionalContext\":{quoted}}}}}\n").into_bytes(),
            stderr: format!("{reason}\n").into_bytes(),
        }
    }

    fn publish(self) -> u8 {
        let mut stdout = io::stdout().lock();
        let mut stderr = io::stderr().lock();
        let output_failed = stdout
            .write_all(&self.stdout)
            .and_then(|()| stdout.flush())
            .is_err();
        let error_failed = stderr
            .write_all(&self.stderr)
            .and_then(|()| stderr.flush())
            .is_err();
        if output_failed || error_failed {
            2
        } else {
            self.status
        }
    }
}

/// Run a strict Claude callback command, validating its event before state access.
#[must_use]
pub fn execute(arguments: &[OsString]) -> u8 {
    let event = match arguments {
        [command] if command == "stop" => "Stop",
        [command] if command == "pre-tool-use" => "PreToolUse",
        [command] if command == "session-start" => "SessionStart",
        [command] if command == "user-prompt-submit" => "UserPromptSubmit",
        _ => return Reply {
            status: 2,
            stderr:
                b"usage: superloop-claude-hook stop|pre-tool-use|session-start|user-prompt-submit\n"
                    .to_vec(),
            ..Reply::default()
        }
        .publish(),
    };
    let mut input = Vec::new();
    if io::stdin()
        .lock()
        .take(1_048_577)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > 1_048_576
    {
        return failure(event, "hook input unavailable or oversized", false).publish();
    }
    let payload = serde_json::from_slice::<Value>(&input).ok();
    if payload
        .as_ref()
        .and_then(|value| value.get("hook_event_name"))
        .and_then(Value::as_str)
        != Some(event)
    {
        return Reply::refusal("hook-event-mismatch").publish();
    }
    let result = std::panic::catch_unwind(|| evaluate(event, &input));
    result
        .unwrap_or_else(|_| failure(event, "adapter internal error", true))
        .publish()
}

fn failure(event: &str, reason: &str, panic: bool) -> Reply {
    if event == "PreToolUse" {
        return Reply::refusal(reason);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let state = PathBuf::from(home).join(".local/state/superloop-tools/hook");
        if panic {
            if event == "Stop" {
                heartbeat::machine::record_panic(&state);
            } else {
                orchestrator::record_panic();
            }
        } else {
            heartbeat::machine::record_payload_failure(&state);
        }
    }
    Reply::default()
}

fn evaluate(event: &str, input: &[u8]) -> Reply {
    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("SUPERLOOP_CLAUDE_HOOK_TEST_PANIC").is_none(),
        "injected adapter panic"
    );
    let state = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/state/superloop-tools/hook"));
    match event {
        "Stop" => state.map_or_else(Reply::default, |state| {
            let result =
                heartbeat::machine::run(input, &state, session_core::heartbeat::Timing::system());
            Reply {
                status: result.status,
                stdout: result.stdout,
                stderr: result.stderr,
            }
        }),
        "PreToolUse" => {
            let heartbeat = state.map_or_else(Reply::default, |state| {
                if heartbeat::pre_tool::dispatch(input)
                    != heartbeat::pre_tool::Dispatch::ScheduleWakeup
                {
                    return Reply::default();
                }
                match heartbeat::pre_tool::schedule_wakeup(input, &state) {
                    session_core::pre_tool::ScheduleDecision::Allow => Reply::default(),
                    session_core::pre_tool::ScheduleDecision::Warn => Reply {
                        status: 1,
                        stderr: heartbeat::pre_tool::OFF_WARNING.to_vec(),
                        ..Reply::default()
                    },
                    session_core::pre_tool::ScheduleDecision::Refuse => Reply {
                        status: 2,
                        stderr: heartbeat::pre_tool::REFUSAL_REASON.to_vec(),
                        ..Reply::default()
                    },
                }
            });
            let permission = permission::invoke(input);
            compose_pre_tool(heartbeat, permission)
        }
        _ => {
            let rulebook = orchestrator::run(input);
            let letters = state.and_then(|state| heartbeat::letters_context::run(input, &state));
            combine_context(event, rulebook, letters)
        }
    }
}

fn compose_pre_tool(heartbeat: Reply, mut permission: Reply) -> Reply {
    // Infrastructure refusal takes precedence, then heartbeat refusal, then
    // structured policy denial. Warnings cannot turn any refusal into allow.
    if permission.status != 0 {
        return permission;
    }
    if heartbeat.status == 2 {
        return heartbeat;
    }
    let deny = serde_json::from_slice::<Value>(&permission.stdout)
        .is_ok_and(|value| value["hookSpecificOutput"]["permissionDecision"] == "deny");
    if !deny && heartbeat.status == 1 && !permission.stdout.is_empty() {
        let mut value: Value = serde_json::from_slice(&permission.stdout).unwrap_or_default();
        let warning = String::from_utf8_lossy(&heartbeat.stderr);
        let message = value
            .get("systemMessage")
            .and_then(Value::as_str)
            .map_or_else(
                || warning.to_string(),
                |message| format!("{message}\n{warning}"),
            );
        value["systemMessage"] = Value::String(message);
        permission.stdout = serde_json::to_vec(&value).unwrap_or_default();
        permission.stdout.push(b'\n');
    } else if !deny {
        permission.status = heartbeat.status;
    }
    permission.stderr.extend_from_slice(&heartbeat.stderr);
    permission
}

fn combine_context(event: &str, rulebook: Option<Vec<u8>>, letters: Option<Vec<u8>>) -> Reply {
    let (Some(rulebook), Some(letters)) = (rulebook.as_ref(), letters.as_ref()) else {
        return Reply::context(rulebook.or(letters));
    };
    let context = |bytes: &[u8]| {
        serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|value| {
                value["hookSpecificOutput"]["additionalContext"]
                    .as_str()
                    .map(str::to_owned)
            })
    };
    match (context(rulebook), context(letters)) {
        (Some(rulebook), Some(letters)) => {
            let combined =
                serde_json::to_string(&format!("{rulebook}\n\n{letters}")).unwrap_or_default();
            Reply::context(Some(format!("{{\"hookSpecificOutput\":{{\"hookEventName\":\"{event}\",\"additionalContext\":{combined}}}}}").into_bytes()))
        }
        _ => Reply::refusal("invalid context response"),
    }
}
