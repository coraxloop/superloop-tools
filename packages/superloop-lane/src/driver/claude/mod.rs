#![doc = include_str!("README.md")]

mod home;

use std::ffi::OsString;
use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use lane_lifecycle::Backend;
pub use lane_lifecycle::{
    BudgetMonitor, ClockSample, Config, DEFAULT_POOL_THRESHOLD, LaneResult, MonitorDecision,
    RUNAWAY_MULTIPLIER, RateLimitRejection, RateLimitState, STALL_WINDOW_SECONDS,
    SUSPEND_GAP_THRESHOLD_SECONDS, SuspendDetector, TerminalResult, UsageError, Verdict,
    fallback_report, fallback_result, internal_diagnostic, publication_diagnostic, publish,
    read_prompt, runtime_diagnostic, usage_diagnostic,
};
use lane_lifecycle::{
    json_strings, last_complete_line, object_value, top_level_bool_value, top_level_f64_value,
    top_level_string_value, top_level_u64_value, validate_resume,
};

/// Claude CLI command and event-stream backend.
#[derive(Clone, Debug, Default)]
pub struct ClaudeBackend {
    home: Option<PathBuf>,
}

/// A shared argument refusal or a Claude home-selection refusal.
#[derive(Debug)]
pub enum ClaudeUsageError {
    /// Shared lifecycle argument or resume validation.
    Shared(UsageError),
    /// Home selection failed before spawning or allocating a run.
    Home(String, u64),
}

impl ClaudeUsageError {
    /// Reporting budget retained on refusal.
    #[must_use]
    pub const fn budget(&self) -> u64 {
        match self {
            Self::Shared(error) => error.budget(),
            Self::Home(_, budget) => *budget,
        }
    }

    /// Named diagnostic suitable for the driver's stderr.
    #[must_use]
    pub fn refusal_diagnostic(&self, backend: &str) -> Option<Vec<u8>> {
        match self {
            Self::Shared(error) => error.refusal_diagnostic(backend),
            Self::Home(error, _) => Some(format!("{backend}: {error}\n").into_bytes()),
        }
    }
}

impl Backend for ClaudeBackend {
    fn name(&self) -> &'static str {
        "claude-lane"
    }

    fn program(&self) -> Option<OsString> {
        lane_lifecycle::execution_settings::command("claude")
            .ok()
            .map(|command| command.get_program().to_owned())
    }

    fn execution_evidence(&self) -> Result<Option<serde_json::Value>, String> {
        lane_lifecycle::execution_settings::evidence("claude").map(Some)
    }

    fn command(&self, config: &Config, _run_dir: &Path) -> Result<Command, String> {
        let mut command = lane_lifecycle::execution_settings::command("claude")?;
        command
            .args(["-p", "--output-format", "stream-json", "--verbose"])
            .current_dir(config.workdir())
            .env(
                "CLAUDE_CONFIG_DIR",
                self.home.as_ref().ok_or("claude-home-unregistered-loop")?,
            );
        if config.pure() {
            command.args([
                "--tools",
                "",
                "--setting-sources",
                "",
                "--permission-mode",
                "plan",
            ]);
        } else {
            match config.sandbox().to_str().ok_or("sandbox is not UTF-8")? {
                "read-only" => {
                    command.args(["--permission-mode", "plan"]);
                }
                "workspace-write" => {
                    command.args(["--permission-mode", "acceptEdits"]);
                }
                "danger-full-access" => {
                    command.args([
                        "--permission-mode",
                        "bypassPermissions",
                        "--dangerously-skip-permissions",
                    ]);
                }
                _ => return Err("sandbox is unsupported".into()),
            }
        }
        if let Some(model) = config.model() {
            command.arg("--model").arg(model);
        }
        if let Some(effort) = config.effort() {
            command.arg("--effort").arg(effort);
        }
        if let Some(session) = config.session() {
            command.arg("--resume").arg(session);
        }
        for (name, _value) in std::env::vars_os() {
            if name == "CLAUDECODE" || name.as_encoded_bytes().starts_with(b"CLAUDE_CODE_") {
                command.env_remove(name);
            }
        }
        if config.pure() {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or("HOME is absent")?;
            command.env("CLAUDE_CONFIG_DIR", home.join(".claude-pure"));
        }
        Ok(command)
    }

    fn thread_id(&self, events: &[u8]) -> Option<String> {
        events.split(|byte| *byte == b'\n').find_map(|line| {
            (top_level_string_value(line, "type").as_deref() == Some("system")
                && top_level_string_value(line, "subtype").as_deref() == Some("init"))
            .then(|| top_level_string_value(line, "session_id"))
            .flatten()
        })
    }

    fn last_message(&self, events: &[u8]) -> Option<Vec<u8>> {
        let mut result = None;
        let mut assistant = None;
        for line in events.split(|byte| *byte == b'\n') {
            match top_level_string_value(line, "type").as_deref() {
                Some("result") => result = Some(top_level_string_value(line, "result")),
                Some("assistant") => {
                    if let Some(strings) = json_strings(line) {
                        for block in strings.windows(4) {
                            if block[0] == "type"
                                && block[1] == "text"
                                && block[2] == "text"
                                && !block[3].is_empty()
                            {
                                assistant = Some(block[3].as_bytes().to_vec());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        result
            .flatten()
            .filter(|message| !message.is_empty())
            .map(String::into_bytes)
            .or(assistant)
    }

    fn terminal_result(&self, events: &[u8]) -> Option<TerminalResult> {
        let line = last_complete_line(events)?;
        if top_level_string_value(line, "type").as_deref() != Some("result") {
            return None;
        }
        Some(TerminalResult::new(
            top_level_bool_value(line, "is_error")?,
            top_level_u64_value(line, "duration_ms"),
        ))
    }

    /// The last refusal in the region, so this reader and the pool-state
    /// reader describe the same moment: the one the step ended on. An earlier
    /// refusal in the same region has already been superseded, and its reset
    /// time would send the next dispatch back before the window it names.
    fn rate_limit_rejection(&self, events: &[u8]) -> Option<RateLimitRejection> {
        events
            .split(|byte| *byte == b'\n')
            .filter_map(decode_rate_limit_line)
            .rfind(RateLimitState::rejected)
            .and_then(RateLimitRejection::from_state)
    }

    fn rate_limit_state(&self, events: &[u8]) -> Option<RateLimitState> {
        events
            .split(|byte| *byte == b'\n')
            .filter_map(decode_rate_limit_line)
            .next_back()
    }

    fn config_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }

    fn lock_file(&self) -> &'static str {
        ".claude-lane.lock"
    }

    fn configure_pure(&self, config: &mut Config, run_dir: &Path) -> Result<(), ()> {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or(())?;
        let pure_home = home.join(".claude-pure");
        fs::create_dir_all(&pure_home).map_err(|_error| ())?;
        if pure_home.join("CLAUDE.md").exists() {
            return Err(());
        }
        let credentials = pure_home.join(".credentials.json");
        if fs::symlink_metadata(&credentials).is_err() {
            let source_home = self.home.as_ref().ok_or(())?;
            symlink(source_home.join(".credentials.json"), &credentials).map_err(|_error| ())?;
        }
        let settings = pure_home.join("settings.json");
        if !settings.exists() {
            File::create(&settings).map_err(|_error| ())?;
        }
        if !settings.is_file() {
            return Err(());
        }
        let cwd = run_dir.join("cwd");
        fs::create_dir_all(&cwd).map_err(|_error| ())?;
        if fs::read_dir(&cwd).map_err(|_error| ())?.next().is_some() {
            return Err(());
        }
        config.force_pure_workdir(cwd);
        Ok(())
    }
}

/// Decode one `rate_limit_event` line's nested pool state.
///
/// `rate_limit_info` is a nested object, so its members are read through that
/// object's own span rather than from the line as a whole: a reader that
/// searched the whole line would answer from whichever object happened to
/// carry the key. Utilization is the `five_hour` window's when the event
/// carries the window table, and the status's own reading otherwise.
fn decode_rate_limit_line(line: &[u8]) -> Option<RateLimitState> {
    if top_level_string_value(line, "type").as_deref() != Some("rate_limit_event") {
        return None;
    }
    let info = object_value(line, "rate_limit_info")?;
    let utilization = object_value(info, "unifiedWindows")
        .and_then(|windows| object_value(windows, "five_hour"))
        .and_then(|window| top_level_f64_value(window, "utilization"))
        .or_else(|| top_level_f64_value(info, "utilization"));
    Some(RateLimitState::new(
        top_level_string_value(info, "status")?,
        top_level_string_value(info, "rateLimitType"),
        utilization,
        top_level_u64_value(info, "resetsAt"),
    ))
}

/// Parse a Claude lane invocation and validate any durable resume boundary.
///
/// # Errors
///
/// Returns a classed usage error for invalid arguments or resume state.
pub fn parse_args<I, A>(arguments: I) -> Result<(Config, ClaudeBackend), ClaudeUsageError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let arguments = arguments
        .into_iter()
        .map(Into::into)
        .collect::<Vec<OsString>>();
    let budget = home::option_value(&arguments, b't')
        .and_then(|value| value.to_str()?.parse().ok())
        .unwrap_or(0);
    let home = home::resolve(&arguments).map_err(|error| ClaudeUsageError::Home(error, budget))?;
    let backend = ClaudeBackend { home: Some(home) };
    let mut config = lane_lifecycle::parse_args(arguments).map_err(ClaudeUsageError::Shared)?;
    validate_resume(&backend, &mut config).map_err(ClaudeUsageError::Shared)?;
    Ok((config, backend))
}

/// Execute one Claude lane step and settle its durable marker.
#[must_use]
pub fn execute(backend: &ClaudeBackend, config: &Config, prompt: &[u8]) -> LaneResult {
    lane_lifecycle::execute(backend, config, prompt)
}

#[cfg(test)]
mod tests {
    use super::{Backend as _, ClaudeBackend};

    const SESSION: &str = "22222222-2222-4222-8222-222222222222";

    /// The event a refused dispatch writes, as one transcript carried it.
    const REJECTED_EVENT: &str = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1789820400,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"org_level_disabled","isUsingOverage":false,"unifiedWindows":{"five_hour":{"utilization":1,"resetsAt":1789820400},"seven_day":{"utilization":0.28,"resetsAt":1790301600}}},"uuid":"33333333-3333-4333-8333-333333333333","session_id":"22222222-2222-4222-8222-222222222222"}"#;

    /// A second refusal in the same region, whose window resets later.
    const LATER_REJECTED_EVENT: &str = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1789838400,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"org_level_disabled","isUsingOverage":false,"unifiedWindows":{"five_hour":{"utilization":1,"resetsAt":1789838400},"seven_day":{"utilization":0.31,"resetsAt":1790301600}}},"uuid":"44444444-4444-4444-8444-444444444444","session_id":"22222222-2222-4222-8222-222222222222"}"#;

    /// The same event when the window is merely close to its limit.
    const WARNING_EVENT: &str = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","surpassedThreshold":0.9,"resetsAt":1789820400,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"org_level_disabled","isUsingOverage":false,"unifiedWindows":{"five_hour":{"utilization":0.97,"resetsAt":1789820400},"seven_day":{"utilization":0.28,"resetsAt":1790301600}}},"uuid":"33333333-3333-4333-8333-333333333333","session_id":"22222222-2222-4222-8222-222222222222"}"#;

    /// ´claim:claudelane:thread-identity-comes-only-from-the-first-system-init-line´
    /// ´test:unit:captured-init-line-yields-session-id´
    #[test]
    fn captured_init_line_yields_session_id() {
        let line = br#"{"type":"system","subtype":"init","cwd":"/x","session_id":"22222222-2222-4222-8222-222222222222","tools":[],"mcp_servers":[],"model":"claude-haiku-4-5-20251001","permissionMode":"auto"}"#;
        assert_eq!(
            ClaudeBackend::default().thread_id(line).as_deref(),
            Some(SESSION)
        );
    }

    /// ´claim:claudelane:result-key-order-cannot-confuse-terminal-message-extraction´
    /// ´test:unit:captured-result-line-yields-final-text´
    #[test]
    fn captured_result_line_yields_final_text() {
        let line = br#"{"duration_api_ms":0,"stop_reason":"stop_sequence","session_id":"22222222-2222-4222-8222-222222222222","total_cost_usd":0,"type":"result","subtype":"success","is_error":true,"duration_ms":415,"num_turns":1,"result":"final text"}"#;
        assert_eq!(
            ClaudeBackend::default().last_message(line),
            Some(b"final text".to_vec())
        );
    }

    /// ´claim:claudelane:a-terminal-result-line-carries-the-finish-a-dead-driver-never-recorded´
    /// ´test:unit:captured-result-line-yields-the-terminal-result´
    #[test]
    fn captured_result_line_yields_the_terminal_result() {
        let events = br#"{"type":"system","subtype":"init","session_id":"22222222-2222-4222-8222-222222222222"}
{"duration_api_ms":0,"session_id":"22222222-2222-4222-8222-222222222222","type":"result","subtype":"success","is_error":false,"duration_ms":415,"result":"final text"}
"#;
        let terminal = ClaudeBackend::default()
            .terminal_result(events)
            .expect("terminal result");

        assert!(!terminal.is_error());
        assert_eq!(terminal.duration_ms(), Some(415));
    }

    /// ´claim:claudelane:a-transcript-whose-last-complete-line-is-not-a-result-has-no-finish´
    /// ´test:unit:a-trailing-assistant-line-has-no-terminal-result´
    #[test]
    fn a_trailing_assistant_line_has_no_terminal_result() {
        let events = br#"{"type":"result","subtype":"success","is_error":false,"duration_ms":415,"result":"final text"}
{"type":"assistant","message":{"content":[{"type":"text","text":"still working"}]}}
"#;

        assert_eq!(ClaudeBackend::default().terminal_result(events), None);
        assert_eq!(ClaudeBackend::default().terminal_result(b""), None);
    }

    /// ´claim:claudelane:a-nested-rejection-status-carries-the-window-and-its-reset´
    /// ´test:unit:a-captured-rejection-event-yields-its-window-and-reset´
    #[test]
    fn a_captured_rejection_event_yields_its_window_and_reset() {
        let events = format!("{REJECTED_EVENT}\n");
        let rejection = ClaudeBackend::default()
            .rate_limit_rejection(events.as_bytes())
            .expect("rejection");

        assert_eq!(rejection.state().status(), "rejected");
        assert_eq!(rejection.state().rate_limit_type(), Some("five_hour"));
        assert_eq!(rejection.state().resets_at(), Some(1_789_820_400));
        assert_eq!(rejection.state().utilization(), Some(1.0));
    }

    /// ´claim:claudelane:the-last-rejection-in-a-region-is-the-one-that-ended-the-step´
    /// ´test:unit:the-last-rejection-in-the-region-describes-the-step´
    #[test]
    fn the_last_rejection_in_the_region_describes_the_step() {
        let events = format!("{REJECTED_EVENT}\n{LATER_REJECTED_EVENT}\n");
        let rejection = ClaudeBackend::default()
            .rate_limit_rejection(events.as_bytes())
            .expect("rejection");
        let state = ClaudeBackend::default()
            .rate_limit_state(events.as_bytes())
            .expect("pool state");

        assert_eq!(rejection.state().resets_at(), Some(1_789_838_400));
        assert_eq!(rejection.state().resets_at(), state.resets_at());
    }

    /// ´claim:claudelane:an-allowed-warning-is-pool-state-and-never-a-rejection´
    /// ´test:unit:a-captured-warning-event-is-the-last-pool-state´
    #[test]
    fn a_captured_warning_event_is_the_last_pool_state() {
        let events = format!("{REJECTED_EVENT}\n{WARNING_EVENT}\n");

        assert!(
            ClaudeBackend::default()
                .rate_limit_rejection(format!("{WARNING_EVENT}\n").as_bytes())
                .is_none()
        );
        let state = ClaudeBackend::default()
            .rate_limit_state(events.as_bytes())
            .expect("pool state");
        assert_eq!(state.status(), "allowed_warning");
        assert_eq!(state.utilization(), Some(0.97));
        assert_eq!(state.resets_at(), Some(1_789_820_400));
    }

    /// ´claim:claudelane:a-line-without-the-nested-object-carries-no-pool-state´
    /// ´test:unit:a-line-without-rate-limit-info-has-no-state´
    #[test]
    fn a_line_without_rate_limit_info_has_no_state() {
        let events = b"{\"type\":\"rate_limit_event\",\"status\":\"rejected\",\"resetsAt\":1789820400}\n{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"final text\"}\n";

        assert_eq!(ClaudeBackend::default().rate_limit_rejection(events), None);
        assert_eq!(ClaudeBackend::default().rate_limit_state(events), None);
    }

    /// ´claim:claudelane:assistant-text-is-the-fallback-for-an-empty-terminal-result´
    /// ´test:unit:captured-assistant-line-survives-empty-result´
    #[test]
    fn captured_assistant_line_survives_empty_result() {
        let events = br#"{"type":"assistant","message":{"id":"m1","role":"assistant","type":"message","content":[{"type":"text","text":"kept answer"}]},"session_id":"22222222-2222-4222-8222-222222222222"}
{"duration_api_ms":0,"type":"result","result":""}"#;
        assert_eq!(
            ClaudeBackend::default().last_message(events),
            Some(b"kept answer".to_vec())
        );
    }
}

mod entry;

pub(super) use entry::main as command;
