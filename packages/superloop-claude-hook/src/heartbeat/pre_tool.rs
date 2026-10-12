//! `PreToolUse` dispatch and the `ScheduleWakeup` arm authorization.
//!
//! The Stop hook writes one arm-prompt marker per session, so a machine
//! running several sessions at once cannot let the first arm consume every
//! other session's prompt. A call is authorized by the marker named for the
//! session in its own payload, and only the file actually consulted is
//! consumed.
//!
//! A payload carrying no usable session identity fails open without hook
//! output or marker access and records the payload failure internally.

use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::machine;

pub const REFUSAL_REASON: &[u8] = b"HEARTBEAT GUARD: unprompted ScheduleWakeup arming is refused. End the turn and arm only when the heartbeat guard's Stop prompt asks. If this turn is genuinely ending blocked on the user, run `superloop heartbeat off` first, then end the turn.";
pub const OFF_WARNING: &[u8] = b"HEARTBEAT GUARD WARNING: this ScheduleWakeup call may be a legitimate deliberate timer while the heartbeat is OFF. If the session is reaching for heartbeat behavior instead, run `superloop heartbeat on` and arm only when the heartbeat guard's Stop prompt asks.";

pub use session_core::pre_tool::ScheduleDecision;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dispatch {
    Stop,
    LettersContext,
    Passthrough,
    ScheduleWakeup,
}

pub fn dispatch(input: &[u8]) -> Dispatch {
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(input) else {
        return Dispatch::Stop;
    };
    let event = payload.get("hook_event_name").and_then(Value::as_str);
    if matches!(event, Some("SessionStart" | "UserPromptSubmit")) {
        return Dispatch::LettersContext;
    }
    if event != Some("PreToolUse") {
        return Dispatch::Stop;
    }
    if payload.get("tool_name").and_then(Value::as_str) == Some("ScheduleWakeup") {
        Dispatch::ScheduleWakeup
    } else {
        Dispatch::Passthrough
    }
}

pub fn schedule_wakeup(input: &[u8], state_dir: &Path) -> ScheduleDecision {
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(input) else {
        return ScheduleDecision::Allow;
    };
    let session = match payload.get("session_id") {
        Some(Value::String(session)) if !session.is_empty() => session.as_str(),
        _ => {
            machine::record_payload_failure(state_dir);
            return ScheduleDecision::Allow;
        }
    };
    let cwd = match payload.get("cwd") {
        None | Some(Value::Null) => "",
        Some(Value::String(cwd)) => cwd,
        Some(_) => return ScheduleDecision::Allow,
    };
    let home = env::var_os("HOME").map(PathBuf::from);
    session_core::pre_tool::schedule_wakeup(state_dir, session, cwd, home.as_deref())
}
