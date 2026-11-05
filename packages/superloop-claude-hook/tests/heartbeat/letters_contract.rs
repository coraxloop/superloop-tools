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
    bin: PathBuf,
    payload: Vec<u8>,
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
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).expect("path fixtures");
        let transcript = dir.write_transcript("transcript.jsonl", &[]);
        let payload = serde_json::to_vec(&json!({"hook_event_name":"Stop","cwd":root,"session_id":"fixture","transcript_path":transcript})).expect("payload");
        Self {
            dir,
            root,
            inbox,
            entry,
            registry,
            bin,
            payload,
        }
    }
    fn run(&self, event: &str) -> Output {
        let mut payload: Value = serde_json::from_slice(&self.payload).expect("payload");
        payload["hook_event_name"] = json!(event);
        let payload = serde_json::to_vec(&payload).expect("payload");
        let command = match event {
            "Stop" => "stop",
            "SessionStart" => "session-start",
            _ => "user-prompt-submit",
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_superloop-claude-hook"))
            .arg(command)
            .env_clear()
            .env("HOME", self.dir.home())
            .env("PATH", &self.bin)
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

/// ´test:integration:non-loop-stops-keep-the-heartbeat-contract-without-listing´
#[test]
fn non_loop_stops_keep_the_heartbeat_contract_without_listing() {
    for missing in [false, true] {
        let f = Fixture::new();
        if missing {
            fs::remove_file(&f.registry).expect("missing registry");
        } else {
            let source = fs::read_to_string(&f.registry).expect("registry");
            fs::write(&f.registry, source.replace("project", "another-project"))
                .expect("nonmatching launch key");
        }
        let off = f.run("Stop");
        assert_eq!(off.status.code(), Some(0));
        assert_eq!(off.stdout, [] as [u8; 0]);
        assert_eq!(off.stderr, [] as [u8; 0]);
        f.dir.enable(&f.root.to_string_lossy());
        let on = f.run("Stop");
        assert_eq!(on.status.code(), Some(2));
        assert_eq!(on.stdout, [] as [u8; 0]);
        let reason = String::from_utf8(on.stderr).expect("heartbeat reason");
        assert!(reason.starts_with("HEARTBEAT GUARD:"));
        assert!(reason.contains("ScheduleWakeup"));
        assert!(!reason.contains("You've got mail."));
        assert!(!f.dir.path().join("call").exists());
    }
}

/// ´test:integration:mail-presence-deadline-kills-the-entry-group-and-keeps-the-heartbeat-prompt´
#[test]
fn mail_presence_deadline_kills_the_entry_group_and_keeps_the_heartbeat_prompt() {
    let f = Fixture::new();
    f.dir.enable(&f.root.to_string_lossy());
    fs::write(
        &f.entry,
        "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$CALL\"\nwait\n",
    )
    .expect("sleeping entry");
    let started = std::time::Instant::now();
    let output = f.run("Stop");
    assert!(started.elapsed() >= std::time::Duration::from_secs(5));
    assert!(started.elapsed() < std::time::Duration::from_secs(9));
    assert_eq!(output.status.code(), Some(0));
    let response: Value = serde_json::from_slice(&output.stdout).expect("response");
    assert_eq!(response["decision"], "block");
    assert!(
        response["reason"]
            .as_str()
            .expect("reason")
            .starts_with("HEARTBEAT GUARD:")
    );
    assert!(message(&output).contains("listing timed out after 5 s"));
    assert!(message(&output).contains(&f.entry.display().to_string().escape_debug().to_string()));
    assert_eq!(
        fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
        "None 1"
    );
    assert!(f.dir.state_path("guard-prompt-fixture").exists());
    for pid in fs::read_to_string(f.dir.path().join("call"))
        .expect("group pids")
        .split_whitespace()
    {
        loop {
            let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => stat,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(nix::errno::Errno::ESRCH as i32) =>
                {
                    break;
                }
                Err(error) => panic!("read entry-chain pid {pid}: {error}"),
            };
            let state = stat.rsplit_once(") ").expect("stat").1.chars().next();
            if state == Some('Z') {
                break;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(9),
                "entry group member still running: {pid}: {stat}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(9));
}

/// ´test:integration:mail-notice-composes-with-heartbeat-prompts-counters-and-lapse´
#[test]
fn mail_notice_composes_with_heartbeat_prompts_counters_and_lapse() {
    let f = Fixture::new();
    fs::write(f.inbox.join("arrival"), b"opaque").expect("arrival");
    f.dir.enable(&f.root.to_string_lossy());
    for count in 1..=3 {
        let output = f.run("Stop");
        assert_eq!(output.status.code(), Some(0));
        let response: Value = serde_json::from_slice(&output.stdout).expect("composed response");
        assert_eq!(response["decision"], "block");
        assert!(
            response["reason"]
                .as_str()
                .expect("heartbeat reason")
                .contains("HEARTBEAT GUARD:")
        );
        assert_eq!(message(&output), "You've got mail.");
        assert_eq!(
            fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
            format!("None {count}")
        );
    }
    let lapse = f.run("Stop");
    assert_eq!(lapse.status.code(), Some(0));
    assert_eq!(lapse.stderr, [] as [u8; 0]);
    assert!(message(&lapse).contains("LAPSED"));
    assert!(message(&lapse).contains("You've got mail."));
    assert!(
        serde_json::from_slice::<Value>(&lapse.stdout)
            .expect("json")
            .get("decision")
            .is_none()
    );
    fs::write(
        &f.entry,
        "#!/bin/sh\nprintf 'entry refusal\\n' >&2\nexit 2\n",
    )
    .expect("refusing entry");
    let failure = f.run("Stop");
    assert_eq!(failure.status.code(), Some(0));
    assert!(message(&failure).contains("entry refusal"));
    assert!(message(&failure).contains("LAPSED"));
    assert_eq!(
        fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
        "None 3"
    );
}

/// ´test:integration:every-composed-verdict-is-a-reached-graph-terminal´
#[test]
fn every_composed_verdict_is_a_reached_graph_terminal() {
    use superloop_claude_hook::heartbeat::State;
    for (expected, enabled, continuation, count, arm_age) in [
        (State::AllowLettersFeedback, false, false, 0, None),
        (State::AllowLettersFeedback, false, true, 0, None),
        (State::BlockPromptFeedback, true, false, 0, None),
        (State::BlockPromptFeedback, true, true, 0, None),
        (State::BlockViolationFeedback, true, false, 0, Some(10)),
        (State::BlockViolationFeedback, true, true, 0, Some(10)),
        (
            State::BlockViolationAndPromptFeedback,
            true,
            false,
            0,
            Some(2000),
        ),
        (
            State::BlockViolationAndPromptFeedback,
            true,
            true,
            0,
            Some(2000),
        ),
        (State::AllowLettersLapse, true, false, 3, None),
        (
            State::AllowLettersLapseAndViolation,
            true,
            false,
            3,
            Some(2000),
        ),
    ] {
        let f = Fixture::new();
        fs::write(f.inbox.join("arrival"), b"opaque").expect("arrival");
        if enabled {
            f.dir.enable(&f.root.to_string_lossy());
        }
        let mut entries = vec![support::user("question", 3000)];
        if let Some(age) = arm_age {
            entries.extend(support::arm(support::ArmOptions::pending(age)));
        }
        f.dir.write_transcript("transcript.jsonl", &entries);
        f.dir
            .write_state("guard-count-fixture", format!("0 {count}"));
        let mut payload: Value = serde_json::from_slice(&f.payload).expect("payload");
        payload["stop_hook_active"] = json!(continuation);
        let result = superloop_claude_hook::heartbeat::fixture_evaluate_with_letters(
            &serde_json::to_vec(&payload).expect("payload"),
            &f.dir.state_dir(),
            support::NOW,
            b"1\n",
        );
        assert_eq!(result.state, expected);
        assert_eq!(result.path.last(), Some(&expected));
        assert!(expected.is_terminal());
        assert!(!matches!(
            result.state,
            State::BlockLetters
                | State::BlockLettersAndPrompt
                | State::BlockLettersAndViolation
                | State::BlockLettersAndViolationAndPrompt
        ));
        assert_eq!(result.status, 0);
        let response: Value = serde_json::from_slice(&result.stdout).expect("composed response");
        if enabled && count < 3 {
            assert_eq!(response["decision"], "block");
        } else {
            assert!(response.get("decision").is_none());
        }
    }
}

fn message(output: &Output) -> String {
    serde_json::from_slice::<Value>(&output.stdout).expect("feedback")["systemMessage"]
        .as_str()
        .expect("message")
        .into()
}

/// ´test:integration:mail-presence-deployed-entry-precedes-path-and-path-remains-a-fallback´
#[test]
fn mail_presence_deployed_entry_precedes_path_and_path_remains_a_fallback() {
    let f = Fixture::new();
    fs::write(f.inbox.join("arrival"), b"opaque").expect("arrival");
    let fallback = f.bin.join("superloop");
    fs::write(&fallback, "#!/bin/sh\nexit 77\n").expect("fallback");
    fs::set_permissions(&fallback, fs::Permissions::from_mode(0o700)).expect("mode");
    assert_eq!(notice(&f.run("Stop"), "Stop"), "You've got mail.");
    fs::remove_file(&f.entry).expect("undeploy");
    let output = f.run("Stop");
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("exit status: 77"));
    assert!(message(&output).contains(&fallback.display().to_string()));
}

/// ´test:integration:mail-presence-failures-report-without-blocking´
#[test]
fn mail_presence_failures_report_without_blocking() {
    let f = Fixture::new();
    fs::write(
        &f.entry,
        "#!/bin/sh\nprintf 'entry refusal\\n' >&2\nexit 2\n",
    )
    .expect("refusal");
    let output = f.run("Stop");
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("entry refusal"));
    assert!(
        serde_json::from_slice::<Value>(&output.stdout)
            .expect("feedback")
            .get("decision")
            .is_none()
    );
    fs::remove_file(&f.entry).expect("absent entry");
    let output = f.run("Stop");
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("entry unavailable:"));
    assert!(message(&output).contains(".local/bin/superloop"));
    assert!(
        serde_json::from_slice::<Value>(&output.stdout)
            .expect("feedback")
            .get("decision")
            .is_none()
    );
    fs::write(
        &f.registry,
        "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n",
    )
    .expect("empty registry");
    for absent in [false, true] {
        if absent {
            fs::remove_file(&f.registry).expect("absent registry");
        }
        let output = f.run("Stop");
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}

/// ´test:integration:mail-notice-reports-an-unavailable-inbox-as-a-failure´
#[test]
fn mail_notice_reports_an_unavailable_inbox_as_a_failure() {
    for mode in [None, Some(0o000), Some(0o100), Some(0o400)] {
        // Root bypasses access permissions; the node exercises these as its user.
        if mode.is_some() && nix::unistd::geteuid().is_root() {
            continue;
        }
        let f = Fixture::new();
        if let Some(mode) = mode {
            fs::set_permissions(&f.inbox, fs::Permissions::from_mode(mode))
                .expect("unreadable inbox");
        } else {
            fs::remove_dir(&f.inbox).expect("missing inbox");
        }
        for event in ["SessionStart", "UserPromptSubmit"] {
            let output = f.run(event);
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(output.stdout, [] as [u8; 0]);
            let failures = fs::read_dir(f.dir.state_dir())
                .expect("state")
                .filter_map(Result::ok)
                .filter_map(|entry| fs::read_to_string(entry.path()).ok())
                .collect::<String>();
            assert!(failures.contains("LettersListingFailed"));
        }
        let output = f.run("Stop");
        assert_eq!(output.status.code(), Some(0));
        assert!(message(&output).contains("mail inbox is missing or unreadable"));
        assert!(!message(&output).contains("You've got mail."));
        if mode.is_some() {
            fs::set_permissions(&f.inbox, fs::Permissions::from_mode(0o700))
                .expect("restore inbox for cleanup");
        }
    }
}
