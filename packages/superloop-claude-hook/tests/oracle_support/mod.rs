#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::Value;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub const OLD_MTIME_NS: u64 = 1_700_000_000_123_456_789;
pub const NEW_MTIME_NS: u64 = 1_700_000_010_987_654_321;
pub const THIRD_MTIME_NS: u64 = 1_700_000_020_333_222_111;
pub const OLD_RULEBOOK: &str = "# Fixture rules\n\nKeep evidence exact.\n";
pub const NEW_RULEBOOK: &str = "# Fixture rules\n\nKeep evidence exact and bounded.\n";

pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    #[must_use]
    pub fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "claude-adapter-oracle-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    #[must_use]
    pub fn project(&self) -> PathBuf {
        let project = self.home().join("project");
        let marker = project.join(".git");
        fs::create_dir_all(&marker).expect("create fixture repository marker");
        fs::write(marker.join("HEAD"), "ref: refs/heads/main\n")
            .expect("create fixture repository HEAD");
        project
    }

    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.path.join("state")
    }

    #[must_use]
    pub fn rulebook(&self) -> PathBuf {
        self.path.join("ORCHESTRATION.md")
    }

    #[must_use]
    pub fn transcript(&self) -> PathBuf {
        self.path.join("transcript.jsonl")
    }

    pub fn write(&self, name: impl AsRef<OsStr>, bytes: &[u8]) {
        fs::write(self.path.join(name.as_ref()), bytes).expect("write test file");
    }

    pub fn mkdir(&self, name: impl AsRef<OsStr>) {
        fs::create_dir_all(self.path.join(name.as_ref())).expect("create test directory");
    }

    #[must_use]
    pub fn read(&self, name: impl AsRef<OsStr>) -> Vec<u8> {
        fs::read(self.path.join(name.as_ref())).expect("read test file")
    }

    #[must_use]
    pub fn read_string(&self, name: impl AsRef<OsStr>) -> String {
        String::from_utf8(self.read(name)).expect("test file is UTF-8")
    }

    #[must_use]
    pub fn exists(&self, name: impl AsRef<OsStr>) -> bool {
        self.path.join(name.as_ref()).exists()
    }

    #[must_use]
    pub fn state(&self, session: &str) -> Value {
        let key = session.replace(['/', '\0'], "-");
        let bytes = fs::read(
            self.state_dir()
                .join(format!("orchestrator-scope-{key}.json")),
        )
        .expect("read state JSON");
        serde_json::from_slice(&bytes).expect("parse state JSON")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "remove isolated test directory: {error}"
            );
        }
    }
}

pub fn write_rulebook(path: &Path, text: &str, mtime_ns: u64) {
    fs::write(path, text).expect("write rulebook");
    let file = File::options()
        .write(true)
        .open(path)
        .expect("open rulebook");
    file.set_modified(UNIX_EPOCH + Duration::from_nanos(mtime_ns))
        .expect("set deterministic rulebook mtime");
}

fn localized_fixture_payload(directory: &TestDir, payload: &Value) -> Value {
    let mut localized = payload.clone();
    if let Some(cwd) = localized.get("cwd").and_then(Value::as_str) {
        if cwd == "/fixture/project" {
            localized["cwd"] = Value::String(directory.project().to_string_lossy().into_owned());
        } else {
            let path = Path::new(cwd);
            assert!(
                path.is_absolute() && path.starts_with(directory.path()),
                "string fixture cwd must be the literal /fixture/project or a path under TestDir: {cwd}"
            );
        }
    }
    localized
}

#[must_use]
pub fn run_hook(directory: &TestDir, payload: &Value) -> Output {
    let payload = localized_fixture_payload(directory, payload);
    run_hook_bytes(
        directory,
        &serde_json::to_vec(&payload).expect("serialize payload"),
        [],
    )
}

/// Hand a payload to a spawned child, accepting a child that exits before reading.
///
/// A child is entitled to exit without draining its stdin: an injected panic leaves
/// the hook ahead of its read, and an interpreter that dies in startup never reaches
/// one. The write then fails with `BrokenPipe` whatever the payload's size, and that
/// failure says nothing about the case — the child's exit status, streams, and log
/// remain the verdict. Any other write failure is a fault of the harness itself and
/// must be seen. Taking the pipe by value keeps the close where the caller expects
/// it, so the child still reads end-of-file the moment the payload is complete.
///
/// The whole payload is written before the child's streams are drained, which bounds
/// what a case may ask for: a child that emits more than a pipe holds while a large
/// payload is still going in would fill its own output pipe, stop reading, and leave
/// both sides blocked. Cases that pair a large payload with a large output need a
/// helper that drains the child's streams while it writes.
///
/// # Panics
///
/// Panics with the context and the error for every write failure other than a read
/// end the child has already closed.
fn write_payload(mut stdin: ChildStdin, payload: &[u8], context: &str) {
    if let Err(error) = stdin.write_all(payload) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "{context}: {error}"
        );
    }
}

#[must_use]
pub fn run_hook_bytes<const N: usize>(
    directory: &TestDir,
    input: &[u8],
    environment: [(OsString, OsString); N],
) -> Output {
    let project = directory.project();
    let binary = env!("CARGO_BIN_EXE_superloop-claude-hook");
    let event: Value = serde_json::from_slice(input).unwrap_or_default();
    let argument = match event["hook_event_name"].as_str() {
        Some("SessionStart") => "session-start",
        Some("UserPromptSubmit") => "user-prompt-submit",
        _ => "stop",
    };
    let mut command = Command::new(binary);
    command
        .arg(argument)
        .env("HOME", directory.home())
        .env("ORCHESTRATOR_STATE_DIR", directory.state_dir())
        .env("ORCHESTRATION_FILE", directory.rulebook())
        .env("PWD", &project)
        .current_dir(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.envs(environment);
    let mut child = command.spawn().expect("spawn orchestrator hook");
    write_payload(
        child.stdin.take().expect("hook stdin"),
        input,
        "write hook payload",
    );
    child.wait_with_output().expect("wait for hook")
}
