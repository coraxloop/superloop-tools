mod support;

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Instant;
use support::{TestDir, write_payload};

struct Fixture {
    dir: TestDir,
    root: PathBuf,
    inbox: PathBuf,
    entry: PathBuf,
    registry: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = TestDir::new("mail-notice");
        let root = dir.project("project");
        let inbox = dir.home().join(".var/loops/alpha/mail/inbox");
        fs::create_dir_all(&inbox).expect("inbox");
        fs::create_dir_all(inbox.with_file_name("read")).expect("history");
        let entry = dir.home().join(".local/bin/superloop");
        fs::create_dir_all(entry.parent().expect("bin")).expect("entry directory");
        fs::write(&entry, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CALL\"\n[ \"$1\" = enter ] && [ \"$2\" = alpha ] && [ \"$3\" = -- ] || exit 2\nshift 3\nexec \"$@\"\n").expect("ordinary entry fixture");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("entry mode");
        let registry = dir.path().join("registry.toml");
        fs::write(&registry, format!("namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{{name='alpha',uid=41001,launch={}}}]\n", serde_json::to_string(root.strip_prefix(dir.home()).expect("relative root")).expect("path"))).expect("registry");
        Self {
            dir,
            root,
            inbox,
            entry,
            registry,
        }
    }
    fn run(&self, event: &str) -> Output {
        let transcript = self.dir.write_transcript("transcript.jsonl", &[]);
        let payload = serde_json::to_vec(&json!({"hook_event_name":event,"cwd":self.root,"session_id":"fixture","transcript_path":transcript})).expect("payload");
        let command = match event {
            "Stop" => "stop",
            "SessionStart" => "session-start",
            _ => "user-prompt-submit",
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_superloop-claude-hook"))
            .arg(command)
            .env_clear()
            .env("HOME", self.dir.home())
            .env("PATH", "/usr/bin:/bin")
            .env("ENTER_LOOP_REGISTRY", &self.registry)
            .env("CALL", self.dir.path().join("call"))
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("hook");
        write_payload(child.stdin.take().expect("stdin"), &payload, "payload");
        child.wait_with_output().expect("hook exit")
    }
}
fn notice(output: &Output, event: &str) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("context");
    if event == "Stop" {
        value["systemMessage"].as_str().expect("notice").into()
    } else {
        value["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("context")
            .into()
    }
}

/// ´claim:superloopclaudehook:mail-context-is-presence-only-at-all-three-events´
/// ´test:integration:mail-context-is-presence-only-at-all-three-events´
#[test]
fn mail_context_is_presence_only_at_all_three_events() {
    let fixture = Fixture::new();
    fs::write(
        fixture.inbox.with_file_name("read").join("history"),
        b"old envelope\0\xff",
    )
    .expect("history");
    for event in ["SessionStart", "UserPromptSubmit", "Stop"] {
        let empty = fixture.run(event);
        assert_eq!(empty.status.code(), Some(0));
        assert_eq!(
            empty.stdout,
            [] as [u8; 0],
            "read history is not an arrival"
        );
        let letter = fixture.inbox.join(".opaque-entry");
        fs::write(&letter, b"private body\0\xff\nsubject=not context").expect("opaque bytes");
        fs::set_permissions(&letter, fs::Permissions::from_mode(0o000)).expect("body unreadable");
        assert_eq!(notice(&fixture.run(event), event), "You've got mail.");
        assert_eq!(notice(&fixture.run(event), event), "You've got mail.");
        let call = fs::read_to_string(fixture.dir.path().join("call")).expect("entry words");
        assert!(call.starts_with("enter\nalpha\n--\n/bin/sh\n-c\n"));
        assert!(!call.contains("letters\nlist"));
        fs::remove_file(&letter).expect("read externally");
    }
    assert!(
        !fixture
            .dir
            .state_path("guard-count-66697874757265")
            .exists(),
        "notice grants no blocking or resume authority"
    );
}

/// ´claim:superloopclaudehook:mail-notice-retains-five-second-fail-open-entry-bound´
/// ´test:integration:mail-notice-retains-five-second-fail-open-entry-bound´
#[test]
fn mail_notice_retains_five_second_fail_open_entry_bound() {
    let fixture = Fixture::new();
    fs::write(&fixture.entry, "#!/bin/sh\nexec /bin/sleep 20\n").expect("hung entry");
    let started = Instant::now();
    let output = fixture.run("SessionStart");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(
        started.elapsed().as_secs_f64() < 7.0,
        "five-second entry bound"
    );
    fs::write(
        &fixture.entry,
        "#!/bin/sh\nprintf 'not a presence marker\\n'\n",
    )
    .expect("invalid presence");
    let output = fixture.run("SessionStart");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
}
