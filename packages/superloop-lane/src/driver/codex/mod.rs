#![doc = include_str!("README.md")]

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use lane_lifecycle::Backend;
pub use lane_lifecycle::{
    BudgetMonitor, ClockSample, Config, ContextUse, DEFAULT_POOL_THRESHOLD, LaneResult,
    MonitorDecision, RUNAWAY_MULTIPLIER, RateLimitRejection, RateLimitState, STALL_WINDOW_SECONDS,
    SUSPEND_GAP_THRESHOLD_SECONDS, SuspendDetector, TerminalResult, UsageError, Verdict,
    fallback_report, fallback_result, internal_diagnostic, publication_diagnostic, publish,
    read_prompt, runtime_diagnostic, usage_diagnostic,
};
use lane_lifecycle::{
    contains_pair, json_strings, last_complete_line, object_value, top_level_has_key,
    top_level_string_value, top_level_u64_value, value_after_key,
};

/// Codex CLI command and event-stream backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodexBackend;

fn record_bound_roots(config: &Config, run_dir: &Path) -> Result<(), String> {
    let mut roots = std::collections::BTreeSet::new();
    let path = run_dir.join("bound-roots.json");
    if path.exists() {
        let prior: serde_json::Value = serde_json::from_slice(
            &fs::read(&path).map_err(|error| format!("bound-roots-read: {error}"))?,
        )
        .map_err(|error| format!("bound-roots-read: {error}"))?;
        let object = prior.as_object().ok_or("bound-roots-shape")?;
        if object.len() != 2 || prior["schema"].as_u64() != Some(1) {
            return Err("bound-roots-shape".into());
        }
        for root in prior["roots"].as_array().ok_or("bound-roots-shape")? {
            let root = root.as_str().ok_or("bound-roots-shape")?;
            if !Path::new(root).is_absolute() {
                return Err("bound-roots-shape".into());
            }
            roots.insert(root.to_owned());
        }
    }
    let home = CodexBackend.config_dir();
    if let Some(home) = home {
        let source = match fs::read_to_string(home.join("config.toml")) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("bound-roots-config: {error}")),
        };
        let value: toml::Value =
            toml::from_str(&source).map_err(|error| format!("bound-roots-config: {error}"))?;
        if let Some(configured) = value
            .get("sandbox_workspace_write")
            .and_then(|table| table.get("writable_roots"))
        {
            for root in configured.as_array().ok_or("bound-roots-config-shape")? {
                let root = root.as_str().ok_or("bound-roots-config-shape")?;
                if !Path::new(root).is_absolute() {
                    return Err("bound-roots-config-relative".into());
                }
                roots.insert(root.to_owned());
            }
        }
    }
    roots.insert(
        std::path::absolute(config.workdir())
            .map_err(|error| format!("bound-roots-workdir: {error}"))?
            .to_string_lossy()
            .into_owned(),
    );
    let record = serde_json::json!({"schema":1,"roots":roots});
    let bytes =
        serde_json::to_vec(&record).map_err(|error| format!("bound-roots-write: {error}"))?;
    let staged = run_dir.join(".bound-roots.json.tmp");
    fs::write(&staged, bytes).map_err(|error| format!("bound-roots-write: {error}"))?;
    fs::rename(staged, path).map_err(|error| format!("bound-roots-write: {error}"))
}

fn runtime_command(bytes: &[u8]) -> Result<Command, String> {
    if bytes.is_empty() || bytes.len() > 65_536 || bytes.last() != Some(&0) {
        return Err("runtime.argv is empty, oversized, or lacks its final NUL".into());
    }
    let words = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(|word| {
            std::str::from_utf8(word).map_err(|error| format!("runtime.argv UTF-8: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (program, args) = words.split_first().ok_or("runtime.argv has no program")?;
    if program.is_empty() || args.iter().any(|arg| arg.is_empty()) {
        return Err("runtime.argv has an empty program or argument".into());
    }
    let mut command = Command::new(program);
    command.args(args);
    Ok(command)
}

fn runtime_environment(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    if bytes.is_empty() || bytes.len() > 65_536 || bytes.last() != Some(&0) {
        return Err("runtime.env is empty, oversized, or lacks its final NUL".into());
    }
    let mut values = Vec::new();
    for entry in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        let entry =
            std::str::from_utf8(entry).map_err(|error| format!("runtime.env UTF-8: {error}"))?;
        let (key, value) = entry.split_once('=').ok_or("runtime.env entry lacks '='")?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
            || values.iter().any(|(prior, _)| prior == key)
        {
            return Err("runtime.env has an invalid or duplicate key".into());
        }
        values.push((key.to_owned(), value.to_owned()));
    }
    if !values.iter().any(|(key, _)| key == "HOME") {
        return Err("runtime.env lacks HOME".into());
    }
    Ok(values)
}

impl Backend for CodexBackend {
    fn name(&self) -> &'static str {
        "codex-lane"
    }

    fn program(&self) -> Option<OsString> {
        lane_lifecycle::execution_settings::command("codex")
            .ok()
            .map(|command| command.get_program().to_owned())
    }

    fn execution_evidence(&self) -> Result<Option<serde_json::Value>, String> {
        lane_lifecycle::execution_settings::evidence("codex").map(Some)
    }

    fn boxed_runtime(&self) -> bool {
        std::env::var("LANE_BOXED_RUNTIME").as_deref() == Ok("1")
    }

    fn command(&self, config: &Config, run_dir: &Path) -> Result<Command, String> {
        if self.boxed_runtime() {
            let run_root = std::env::var_os("LANE_RUN_DIR")
                .ok_or("LANE_RUN_DIR is absent for boxed runtime")?;
            let argv_path = PathBuf::from(run_root).join("launch/runtime.argv");
            let mut bytes = Vec::new();
            File::open(&argv_path)
                .map_err(|error| format!("runtime argv {}: {error}", argv_path.display()))?
                .take(65_537)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("runtime argv {}: {error}", argv_path.display()))?;
            let mut command = runtime_command(&bytes)
                .map_err(|error| format!("{}: {error}", argv_path.display()))?;
            let environment_path = argv_path.with_file_name("runtime.env");
            let mut environment_bytes = Vec::new();
            File::open(&environment_path)
                .map_err(|error| {
                    format!(
                        "runtime environment {}: {error}",
                        environment_path.display()
                    )
                })?
                .take(65_537)
                .read_to_end(&mut environment_bytes)
                .map_err(|error| {
                    format!(
                        "runtime environment {}: {error}",
                        environment_path.display()
                    )
                })?;
            command.env_clear().envs(
                runtime_environment(&environment_bytes)
                    .map_err(|error| format!("{}: {error}", environment_path.display()))?,
            );
            return Ok(command);
        }
        self.config_dir()
            .ok_or("CODEX_HOME is required for a host Codex start or resume")?;
        record_bound_roots(config, run_dir)?;
        let mut command = lane_lifecycle::execution_settings::command("codex")?;
        command
            .args(["exec", "--json", "--skip-git-repo-check"])
            .arg("-C")
            .arg(config.workdir())
            .arg("-s")
            .arg(config.sandbox())
            .arg("-o")
            .arg(run_dir.join("last-message.txt"));
        if let Some(model) = config.model() {
            command.arg("-m").arg(model);
        }
        if let Some(effort) = config.effort() {
            command.arg("-c").arg(format!(
                "model_reasoning_effort={}",
                effort.to_str().ok_or("effort is not UTF-8")?
            ));
        }
        if let Some(session) = config.session() {
            command.arg("resume").arg(session);
        }
        command.arg("-");
        Ok(command)
    }

    fn thread_id(&self, events: &[u8]) -> Option<String> {
        let mut last = None;
        for line in events.split(|byte| *byte == b'\n') {
            let Some(strings) = json_strings(line) else {
                continue;
            };
            if contains_pair(&strings, "type", "thread.started") {
                last = value_after_key(&strings, "thread_id").map(str::to_owned);
            }
        }
        last
    }

    fn last_message(&self, events: &[u8]) -> Option<Vec<u8>> {
        let mut last = None;
        for line in events.split(|byte| *byte == b'\n') {
            let Some(strings) = json_strings(line) else {
                continue;
            };
            if !contains_pair(&strings, "type", "agent_message") {
                continue;
            }
            let message =
                value_after_key(&strings, "text").or_else(|| value_after_key(&strings, "message"));
            if let Some(message) = message.filter(|message| !message.is_empty()) {
                last = Some(message.as_bytes().to_vec());
            }
        }
        last
    }

    /// The turn event a finished Codex turn ends on.
    ///
    /// Every completed turn in the captured transcripts closes with a
    /// `turn.completed` line carrying the turn's usage, written immediately
    /// after the last `item.completed`, and a turn the provider ended closes
    /// with `turn.failed` carrying the error it reported. Either is the finish
    /// the step reached, so a region ending in one states what an interrupted
    /// driver never published. The shape carries no duration of its own, so
    /// nothing in a Codex transcript measures the step and a reconstruction
    /// from one reports the wall it can defend: none.
    fn terminal_result(&self, events: &[u8]) -> Option<TerminalResult> {
        let line = last_complete_line(events)?;
        match top_level_string_value(line, "type").as_deref() {
            Some("turn.completed") => Some(TerminalResult::new(false, None)),
            Some("turn.failed") => Some(TerminalResult::new(true, None)),
            _ => None,
        }
    }

    fn context_use(&self, event: &[u8]) -> Option<ContextUse> {
        match top_level_string_value(event, "type")?.as_str() {
            "turn.failed" => Some(ContextUse::unknown("codex-exec-json", "turn-failed")),
            "turn.completed" => {
                let Some(usage) = object_value(event, "usage") else {
                    let reason = if top_level_has_key(event, "usage") {
                        "usage-malformed"
                    } else {
                        "usage-absent"
                    };
                    return Some(ContextUse::unknown("codex-exec-json", reason));
                };
                if [
                    "input_tokens",
                    "cached_input_tokens",
                    "cache_write_input_tokens",
                    "output_tokens",
                    "reasoning_output_tokens",
                ]
                .iter()
                .any(|key| top_level_u64_value(usage, key).is_none())
                {
                    return Some(ContextUse::unknown("codex-exec-json", "usage-malformed"));
                }
                Some(ContextUse::unknown("codex-exec-json", "window-unreported"))
            }
            _ => None,
        }
    }

    fn rate_limit_rejection(&self, _events: &[u8]) -> Option<RateLimitRejection> {
        // No recorded Codex transcript carries an event for the vendor's
        // usage limit, so this shape is not known to state a refusal.
        // Answering None keeps a refused Codex dispatch a FAILED step, which
        // is a worse report than the Claude driver's but a true one; the
        // alternative is to invent a shape and classify on a guess.
        None
    }

    fn rate_limit_state(&self, _events: &[u8]) -> Option<RateLimitState> {
        None
    }

    fn retryable_capacity(&self, events: &[u8]) -> bool {
        events.split(|byte| *byte == b'\n').any(|line| {
            let Some(strings) = json_strings(line) else {
                return false;
            };
            if !contains_pair(&strings, "type", "error")
                && !contains_pair(&strings, "type", "turn.failed")
            {
                return false;
            }
            value_after_key(&strings, "message").is_some_and(|message| {
                let lower = message.to_ascii_lowercase();
                lower.contains("model") && lower.contains("at capacity")
            })
        })
    }

    fn config_dir(&self) -> Option<PathBuf> {
        if self.boxed_runtime() {
            return std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".codex"));
        }
        std::env::var_os("CODEX_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    fn lock_file(&self) -> &'static str {
        ".codex-lane.lock"
    }

    fn configure_pure(&self, _config: &mut Config, _run_dir: &Path) -> Result<(), ()> {
        Err(())
    }
}

/// Parse a Codex lane invocation and validate any durable resume boundary.
///
/// # Errors
///
/// Returns a classed usage error for invalid arguments or resume state.
pub fn parse_args<I, A>(arguments: I) -> Result<Config, UsageError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let mut config = lane_lifecycle::parse_args(arguments)?;
    lane_lifecycle::validate_resume(&CodexBackend, &mut config)?;
    Ok(config)
}

/// Execute one Codex lane step and settle its durable marker.
#[must_use]
pub fn execute(config: &Config, prompt: &[u8]) -> LaneResult {
    lane_lifecycle::execute(&CodexBackend, config, prompt)
}

#[cfg(test)]
mod tests {
    use super::{Backend as _, CodexBackend, runtime_command, runtime_environment};

    /// ´test:unit:boxed-command-keeps-every-planned-argument-and-refuses-broken-records´
    #[test]
    fn boxed_command_keeps_every_planned_argument_and_refuses_broken_records() {
        let command =
            runtime_command(b"/usr/bin/podman\0run\0--network=none\0image\0codex\0exec\0-\0")
                .expect("argv");
        assert_eq!(command.get_program(), "/usr/bin/podman");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["run", "--network=none", "image", "codex", "exec", "-"]
        );
        for invalid in [
            b"".as_slice(),
            b"podman",
            b"podman\0\0",
            b"podman\0bad\xff\0",
        ] {
            assert!(runtime_command(invalid).is_err());
        }
    }

    /// ´test:unit:boxed-runtime-uses-one-pinned-container-environment´
    #[test]
    fn boxed_runtime_uses_one_pinned_container_environment() {
        let values = runtime_environment(
            b"HOME=/home/owner\0PATH=/usr/bin:/bin\0XDG_RUNTIME_DIR=/run/user/1000\0",
        )
        .expect("container environment");
        assert_eq!(values[0], ("HOME".into(), "/home/owner".into()));
        assert_eq!(
            values[2],
            ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into())
        );
        for invalid in [
            b"".as_slice(),
            b"HOME=/home/owner",
            b"PATH=/usr/bin\0",
            b"HOME=/home/owner\0HOME=/elsewhere\0",
            b"bad-key=value\0HOME=/home/owner\0",
        ] {
            assert!(runtime_environment(invalid).is_err());
        }
    }

    /// ´test:unit:only-a-model-capacity-error-is-retryable´
    #[test]
    fn only_a_model_capacity_error_is_retryable() {
        let backend = CodexBackend;
        assert!(backend.retryable_capacity(
            b"{\"type\":\"error\",\"message\":\"The selected model is at capacity\"}\n"
        ));
        assert!(backend.retryable_capacity(
            b"{\"type\":\"turn.failed\",\"error\":{\"message\":\"Model is at capacity\"}}\n"
        ));
        assert!(
            !backend
                .retryable_capacity(b"{\"type\":\"error\",\"message\":\"model access denied\"}\n")
        );
        assert!(!backend.retryable_capacity(
            b"{\"type\":\"item.completed\",\"message\":\"model is at capacity\"}\n"
        ));
    }

    /// The line every completed turn in the captured transcripts ends on.
    const TURN_COMPLETED: &str = r#"{"type":"turn.completed","usage":{"input_tokens":17338944,"cached_input_tokens":17018496,"cache_write_input_tokens":0,"output_tokens":65375,"reasoning_output_tokens":26970}}"#;

    /// The line a turn the provider ended carries instead.
    const TURN_FAILED: &str =
        r#"{"type":"turn.failed","error":{"message":"You've hit your usage limit."}}"#;

    /// ´test:unit:codex-exec-usage-never-claims-a-context-window´
    #[test]
    fn codex_exec_usage_never_claims_a_context_window() {
        let backend = CodexBackend;
        for (event, reason) in [
            (TURN_COMPLETED, "window-unreported"),
            (r#"{"type":"turn.completed"}"#, "usage-absent"),
            (
                r#"{"type":"turn.completed","note":"usage"}"#,
                "usage-absent",
            ),
            (
                r#"{"type":"turn.completed","nested":{"usage":4}}"#,
                "usage-absent",
            ),
            (
                r#"{"type":"turn.completed","usage":{"input_tokens":"bad"}}"#,
                "usage-malformed",
            ),
            (TURN_FAILED, "turn-failed"),
        ] {
            let state = backend.context_use(event.as_bytes()).expect("turn state");
            assert_eq!(state.reason, reason);
            assert_eq!(state.source, "codex-exec-json");
            assert_eq!(state.used, None);
            assert_eq!(state.window, None);
            assert_eq!(state.fraction(), None);
        }
        assert_eq!(backend.context_use(br#"{"type":"turn.started"}"#), None);
    }

    /// ´test:unit:the-codex-turn-event-carries-the-terminal-result´
    #[test]
    fn the_codex_turn_event_carries_the_terminal_result() {
        let message =
            r#"{"type":"item.completed","item":{"type":"agent_message","text":"final answer"}}"#;
        let completed = format!("{message}\n{TURN_COMPLETED}\n");
        let failed = format!("{message}\n{TURN_FAILED}\n");

        let terminal = CodexBackend
            .terminal_result(completed.as_bytes())
            .expect("terminal result");
        assert!(!terminal.is_error());
        assert_eq!(terminal.duration_ms(), None);
        assert_eq!(
            CodexBackend.last_message(completed.as_bytes()),
            Some(b"final answer".to_vec())
        );

        let terminal = CodexBackend
            .terminal_result(failed.as_bytes())
            .expect("terminal result");
        assert!(terminal.is_error());
        assert_eq!(terminal.duration_ms(), None);
    }

    /// ´test:unit:an-unfinished-codex-region-has-no-terminal-result´
    #[test]
    fn an_unfinished_codex_region_has_no_terminal_result() {
        let events = include_bytes!(
            "../../../tests/driver_codex/fixtures/expected/normal-completion.events"
        );
        let interrupted = format!(
            "{TURN_COMPLETED}\n{{\"type\":\"item.started\",\"item\":{{\"type\":\"agent_message\"}}}}\n"
        );

        assert_eq!(
            CodexBackend.last_message(events),
            Some(b"final answer".to_vec())
        );
        assert_eq!(CodexBackend.terminal_result(events), None);
        assert_eq!(CodexBackend.terminal_result(interrupted.as_bytes()), None);
        assert_eq!(CodexBackend.terminal_result(b""), None);
    }
}

mod entry;

pub(super) use entry::main as command;
