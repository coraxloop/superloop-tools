#![allow(dead_code)]

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use superloop_claude_hook::heartbeat::HookResult;

pub const NOW: &str = "2027-01-02T02:00:00Z";

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static NEXT_TRANSCRIPT: AtomicUsize = AtomicUsize::new(0);

pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub fn new(label: &str) -> Self {
        let root = std::env::var_os("TMPDIR")
            .map_or_else(std::env::temp_dir, PathBuf::from)
            .join(format!(
                "heartbeat-guard-{label}-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).expect("create isolated fixture root");
        Self { path: root }
    }

    pub fn state_dir(&self) -> PathBuf {
        self.path.join("home/.local/state/superloop-tools/hook")
    }

    pub fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn project(&self, name: &str) -> PathBuf {
        let project = self.home().join(name);
        let marker = project.join(".git");
        fs::create_dir_all(&marker).expect("create fixture project marker");
        fs::write(marker.join("HEAD"), "ref: refs/heads/main\n")
            .expect("create fixture project HEAD");
        project
    }

    pub fn state_path(&self, name: &str) -> PathBuf {
        self.state_dir().join(name)
    }

    pub fn write_state(&self, name: &str, bytes: impl AsRef<[u8]>) {
        fs::create_dir_all(self.state_dir()).expect("create fixture state directory");
        fs::write(self.state_path(name), bytes).expect("write fixture state");
    }

    pub fn write_transcript(&self, name: &str, entries: &[Value]) -> PathBuf {
        let path = self.path.join(name);
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend(serde_json::to_vec(entry).expect("serialize transcript entry"));
            bytes.push(b'\n');
        }
        fs::write(&path, bytes).expect("write named fixture transcript");
        path
    }

    pub fn enable(&self, cwd: &str) {
        fs::create_dir_all(self.state_dir()).expect("create fixture state directory");
        fs::write(self.state_path(&format!("heartbeat{}", fold(cwd))), [])
            .expect("enable fixture heartbeat");
    }

    pub fn payload(transcript: &std::path::Path, cwd: &str, session: &str) -> Value {
        json!({
            "transcript_path": transcript,
            "cwd": cwd,
            "session_id": session,
            "stop_hook_active": false,
            "hook_event_name": "Stop"
        })
    }

    pub fn run_python(&self, payload: &Value) -> Output {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("reference/heartbeat/heartbeat-guard.py");
        let mut child = Command::new("python3")
            .arg(script)
            .env("HOME", self.home())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn deployed Python guard");
        write_payload(
            child.stdin.take().expect("Python stdin"),
            &serde_json::to_vec(payload).expect("serialize Python payload"),
            "write Python payload",
        );
        child.wait_with_output().expect("wait for Python guard")
    }

    pub fn run(&self, entries: &[Value], options: RunOptions<'_>) -> HookResult {
        fs::create_dir_all(self.state_dir()).expect("create fixture state directory");
        let default_cwd = self.project("project");
        let default_cwd_text = default_cwd.to_string_lossy();
        let cwd = options.cwd.unwrap_or_else(|| default_cwd_text.as_ref());
        let transcript = self.path.join(format!(
            "transcript-{}.jsonl",
            NEXT_TRANSCRIPT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend(serde_json::to_vec(entry).expect("serialize transcript entry"));
            bytes.push(b'\n');
        }
        fs::write(&transcript, bytes).expect("write fixture transcript");
        if options.missing_transcript {
            fs::remove_file(&transcript).expect("remove fixture transcript");
        }
        if options.toggle_on {
            fs::write(self.state_path(&format!("heartbeat{}", fold(cwd))), [])
                .expect("enable fixture heartbeat");
        }
        let input = options.raw_input.map_or_else(
            || {
                serde_json::to_vec(&json!({
                    "transcript_path": transcript,
                    "cwd": cwd,
                    "session_id": options.session,
                    "stop_hook_active": options.stop_hook_active,
                    "hook_event_name": "Stop"
                }))
                .expect("serialize fixture payload")
            },
            |raw| raw.as_bytes().to_vec(),
        );
        superloop_claude_hook::heartbeat::fixture_evaluate(&input, &self.state_dir(), NOW, NOW)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Copy)]
pub struct RunOptions<'a> {
    pub toggle_on: bool,
    pub session: &'a str,
    pub raw_input: Option<&'a str>,
    pub missing_transcript: bool,
    pub stop_hook_active: bool,
    pub cwd: Option<&'a str>,
}

impl Default for RunOptions<'static> {
    fn default() -> Self {
        Self {
            toggle_on: true,
            session: "reference-session",
            raw_input: None,
            missing_transcript: false,
            stop_hook_active: false,
            cwd: None,
        }
    }
}

/// Hand a payload to a spawned child, accepting a child that exits before reading.
///
/// A child is entitled to exit without draining its stdin: the injected panic leaves
/// the guard ahead of its read, a toggle argument never reaches one, and an
/// interpreter that dies in startup never runs the script that would. The write then
/// fails with `BrokenPipe` whatever the payload's size, and that failure says nothing
/// about the case — the child's exit status, streams, and state directory remain the
/// verdict. Any other write failure is a fault of the harness itself and must be
/// seen. Taking the pipe by value keeps the close where the caller expects it, so the
/// child still reads end-of-file the moment the payload is complete.
///
/// # Panics
///
/// Panics with the context and the error for every write failure other than a read
/// end the child has already closed.
pub fn write_payload(mut stdin: ChildStdin, payload: &[u8], context: &str) {
    if let Err(error) = stdin.write_all(payload) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "{context}: {error}"
        );
    }
}

pub fn fold(cwd: &str) -> String {
    cwd.replace('/', "-")
}

// Model the harness contract: transcript timestamps are ISO 8601 UTC with a
// trailing Z for calls and results alike; retained naive/offset inputs are refused.
pub fn ts(seconds_ago: i64) -> String {
    let seconds = 7_200 - seconds_ago;
    let hour = seconds.div_euclid(3_600);
    let minute = seconds.rem_euclid(3_600) / 60;
    let second = seconds.rem_euclid(60);
    format!("2027-01-02T{hour:02}:{minute:02}:{second:02}Z")
}

pub fn user(text: &str, age: i64) -> Value {
    json!({
        "type": "user",
        "timestamp": ts(age),
        "message": {"role": "user", "content": text}
    })
}

pub fn feedback(age: i64) -> Value {
    user("Stop hook feedback:\nHEARTBEAT GUARD: ...", age)
}

#[allow(clippy::struct_excessive_bools)]
pub struct ArmOptions<'a> {
    pub delay: Option<Value>,
    pub age: i64,
    pub id: &'a str,
    pub stop: bool,
    pub error: bool,
    pub no_result: bool,
    pub sidechain: bool,
}

impl ArmOptions<'_> {
    pub fn pending(age: i64) -> Self {
        Self {
            delay: Some(json!(1_800)),
            age,
            id: "t1",
            stop: false,
            error: false,
            no_result: false,
            sidechain: false,
        }
    }
}

pub fn arm(options: ArmOptions<'_>) -> Vec<Value> {
    let input = options.delay.map_or_else(
        || json!({"noop": true}),
        |delay| json!({"delaySeconds": delay, "noop": true, "prompt": "tick", "reason": "r"}),
    );
    let input = if options.stop {
        json!({"stop": true})
    } else {
        input
    };
    let mut call = json!({
        "type": "assistant",
        "timestamp": ts(options.age),
        "message": {"role": "assistant", "content": [{
            "type": "tool_use", "id": options.id,
            "name": "ScheduleWakeup", "input": input
        }]}
    });
    if options.sidechain {
        call["isSidechain"] = json!(true);
    }
    let mut entries = vec![call];
    if !options.no_result {
        let mut result = json!({
            "type": "user",
            "timestamp": ts(options.age - 1),
            "message": {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": options.id,
                "is_error": options.error,
                "content": if options.stop {"Loop stopped."} else {"Next wakeup scheduled..."}
            }]}
        });
        if options.sidechain {
            result["isSidechain"] = json!(true);
        }
        entries.push(result);
    }
    entries
}

pub fn append(mut left: Vec<Value>, right: impl IntoIterator<Item = Value>) -> Vec<Value> {
    left.extend(right);
    left
}

pub fn assert_silent_allow(result: &HookResult) {
    assert_eq!(result.status, 0);
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert_eq!(result.stderr, [] as [u8; 0]);
}

pub fn assert_block(result: &HookResult) {
    assert_eq!(result.status, 2);
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert_ne!(result.stderr, [] as [u8; 0]);
}

pub fn system_message(result: &HookResult) -> String {
    assert_eq!(result.status, 0);
    assert_eq!(result.stderr, [] as [u8; 0]);
    serde_json::from_slice::<Value>(&result.stdout)
        .expect("system-message response JSON")["systemMessage"]
        .as_str()
        .expect("system-message string")
        .to_owned()
}

pub fn count_path(session: &str) -> String {
    format!("guard-count-{session}")
}

pub fn warning_path(session: &str) -> String {
    format!("guard-warn-{session}")
}

pub fn prompt_path(session: &str) -> String {
    format!("guard-prompt-{session}")
}

pub fn event_command(input: &[u8]) -> &'static str {
    let value: Value = serde_json::from_slice(input).unwrap_or_default();
    match value["hook_event_name"].as_str() {
        Some("PreToolUse") => "pre-tool-use",
        Some("SessionStart") => "session-start",
        Some("UserPromptSubmit") => "user-prompt-submit",
        _ => "stop",
    }
}

pub fn toggle_command() -> Command {
    let mut command =
        Command::new(std::env::var_os("SUPERLOOP_TEST_BINARY").expect("SUPERLOOP_TEST_BINARY"));
    command.arg("heartbeat");
    command
}
