mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use support::{TestDir, write_payload};

fn produced(directory: &str, sender: &str, instant: u64) -> String {
    let name = format!("{sender}.{instant:020}.0123456789abcdef0123456789abcdef");
    let record = format!(
        "LOOP-LETTER 1\nsender={sender}\nreceiver=alpha\nposted_ns={instant}\nsubject_hex=68656c6c6f\nbody_bytes=6\n\nsecret"
    );
    let mut line =
        loop_home::letter_metadata(directory, &name, record.as_bytes()).expect("producer");
    line.push('\n');
    line
}

fn first() -> String {
    produced("new", "beta", 1)
}
fn second() -> String {
    produced("new", "beta", 2)
}

struct Fixture {
    dir: TestDir,
    root: PathBuf,
    registry: PathBuf,
    bin: PathBuf,
    payload: Vec<u8>,
}

impl Fixture {
    fn event(&mut self, event: &str, source: &str, prompt: Option<&str>) {
        let mut payload: Value = serde_json::from_slice(&self.payload).expect("payload");
        payload["hook_event_name"] = json!(event);
        payload["source"] = json!(source);
        payload["prompt_id"] = json!(prompt);
        self.payload = serde_json::to_vec(&payload).expect("payload");
    }

    fn receipt(&self) -> PathBuf {
        self.dir.state_path("guard-letters-66697874757265.json")
    }

    fn turn(&self, number: usize) {
        let entries = (0..number)
            .map(|_| support::user("real prompt", 0))
            .collect::<Vec<_>>();
        self.dir.write_transcript("transcript.jsonl", &entries);
    }

    fn new() -> Self {
        let dir = TestDir::new("letters-callback");
        let root = dir.project("project");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("nested cwd");
        let registry = dir.path().join("registry.toml");
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).expect("bin");
        let transcript = dir.write_transcript("transcript.jsonl", &[]);
        let payload = serde_json::to_vec(&json!({
            "hook_event_name": "Stop", "cwd": nested, "session_id": "fixture",
            "transcript_path": transcript
        }))
        .expect("payload");
        let f = Self {
            dir,
            root,
            registry,
            bin,
            payload,
        };
        f.registry("alpha");
        fs::write(f.bin.join("superloop"), "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$CALL\"\n/bin/cat \"$LISTING\"\n/bin/cat \"$FAILURE\" >&2\nexit \"$STATUS\"\n").expect("stub entry");
        fs::set_permissions(f.bin.join("superloop"), fs::Permissions::from_mode(0o700))
            .expect("executable");
        f
    }

    fn registry(&self, name: &str) {
        fs::write(&self.registry, format!(
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\n[[loops]]\nname = \"{name}\"\nuid = 41001\nlaunch = {}\n",
            serde_json::to_string(&self.root.strip_prefix(self.dir.home()).expect("relative launch")).expect("launch")
        )).expect("registry");
    }

    fn run(&self, listing: &[u8], failure: &str, status: u8) -> Output {
        let listing_file = self.dir.path().join("listing");
        let failure_file = self.dir.path().join("failure");
        fs::write(&listing_file, listing).expect("listing");
        fs::write(&failure_file, failure).expect("failure");
        let mut child = Command::new(env!("CARGO_BIN_EXE_superloop-claude-hook"))
            .arg(support::event_command(&self.payload))
            .env_clear()
            .env("HOME", self.dir.home())
            .env("PATH", &self.bin)
            .env("ENTER_LOOP_REGISTRY", &self.registry)
            .env("LISTING", listing_file)
            .env("FAILURE", failure_file)
            .env("STATUS", status.to_string())
            .env("CALL", self.dir.path().join("call"))
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("hook");
        write_payload(child.stdin.take().expect("stdin"), &self.payload, "payload");
        child.wait_with_output().expect("hook exit")
    }
}

fn message(output: &Output) -> String {
    serde_json::from_slice::<Value>(&output.stdout).expect("hook feedback")["systemMessage"]
        .as_str()
        .expect("message")
        .to_owned()
}

fn context(output: &Output, event: &str) -> String {
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    let response: Value = serde_json::from_slice(&output.stdout).expect("context response");
    assert_eq!(response.as_object().expect("object").len(), 1);
    assert_eq!(response["hookSpecificOutput"]["hookEventName"], event);
    response["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context")
        .to_owned()
}

fn silent(output: &Output) {
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
}

///
/// # Panics
/// Panics only if fixture setup fails or the hook violates the asserted contract.
/// ´test:integration:unkeyed-stop-with-old-receipt-logs-unreadable-transcript´
#[test]
fn unkeyed_stop_with_old_receipt_logs_unreadable_transcript() {
    let mut f = Fixture::new();
    f.dir.enable(&f.root.to_string_lossy());
    fs::create_dir_all(f.receipt().parent().expect("state")).expect("state");
    fs::write(f.receipt(), b"obsolete receipt").expect("old receipt");
    let mut payload: Value = serde_json::from_slice(&f.payload).expect("payload");
    payload["session_id"] = Value::Null;
    payload["prompt_id"] = Value::Null;
    fs::remove_file(
        payload["transcript_path"]
            .as_str()
            .expect("transcript path"),
    )
    .expect("unreadable transcript");
    f.payload = serde_json::to_vec(&payload).expect("payload");
    let output = f.run(first().as_bytes(), "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("unread=1"));
    let log = fs::read_to_string(f.dir.state_path("orchestrator.log")).expect("internal log");
    assert!(log.contains("TranscriptRead"), "{log}");
    assert_eq!(
        fs::read(f.receipt()).expect("retained receipt"),
        b"obsolete receipt"
    );
}

/// ´test:integration:letters-context-is-stateless-across-events-and-old-receipts´
#[test]
fn letters_context_is_stateless_across_events_and_old_receipts() {
    let mut f = Fixture::new();
    f.turn(1);
    f.dir.enable(&f.root.to_string_lossy());
    fs::create_dir_all(f.receipt().parent().expect("state")).expect("state");
    fs::write(f.receipt(), b"obsolete malformed receipt").expect("old receipt");
    for event in ["SessionStart", "UserPromptSubmit", "SessionStart"] {
        f.event(event, "compact", Some("p1"));
        let a = context(&f.run(first().as_bytes(), "", 0), event);
        let b = context(&f.run(first().as_bytes(), "", 0), event);
        assert_eq!(a, b);
        assert!(a.contains("unread=1"));
        assert!(!a.contains("secret"));
        for marker in [
            "guard-count-fixture",
            "guard-warn-fixture",
            "guard-prompt-fixture",
        ] {
            assert!(!f.dir.state_path(marker).exists());
        }
    }
    f.event("Stop", "", Some("p1"));
    assert_eq!(f.run(first().as_bytes(), "", 0).status.code(), Some(2));
    assert_eq!(
        fs::read(f.receipt()).expect("old receipt"),
        b"obsolete malformed receipt"
    );
}

/// ´test:integration:letters-context-is-silent-but-malformed-events-refuse´
#[test]
fn letters_context_is_silent_but_malformed_events_refuse() {
    for event in ["SessionStart", "UserPromptSubmit"] {
        let mut f = Fixture::new();
        f.event(event, "startup", None);
        silent(&f.run(b"", "", 0));
        let mut payload: Value = serde_json::from_slice(&f.payload).expect("payload");
        for cwd in [json!(7), json!("/unmatched")] {
            payload["cwd"] = cwd;
            f.payload = serde_json::to_vec(&payload).expect("payload");
            silent(&f.run(first().as_bytes(), "", 0));
        }
        f.payload = b"malformed".to_vec();
        let output = f.run(first().as_bytes(), "", 0);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("hook-event-mismatch"));
    }
}

/// ´test:integration:letters-history-is-newest-first-and-never-blocks-alone´
#[test]
fn letters_history_is_newest_first_and_never_blocks_alone() {
    let mut f = Fixture::new();
    let listing = format!("{}{}{}", first(), produced("cur", "beta", 3), second());
    f.event("UserPromptSubmit", "", Some("p1"));
    let text = context(&f.run(listing.as_bytes(), "", 0), "UserPromptSubmit");
    assert!(text.starts_with("LETTERS unread=2 loop=alpha"));
    let lines = text.lines().collect::<Vec<_>>();
    assert!(lines[1].contains("posted_ns=3 unread=false"));
    assert!(lines[2].contains("posted_ns=2 unread=true"));
    assert!(lines[3].contains("posted_ns=1 unread=true"));
    f.event("Stop", "", None);
    let output = f.run(produced("cur", "beta", 3).as_bytes(), "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("unread=0"));
    assert!(!f.dir.state_path("guard-count-fixture").exists());
}

/// ´test:integration:letters-tail-bounds-entries-bytes-and-composed-lines´
#[test]
fn letters_tail_bounds_entries_bytes_and_composed_lines() {
    let mut f = Fixture::new();
    f.event("UserPromptSubmit", "", Some("p1"));
    let sender = "b".repeat(201);
    let listing = (1..=30)
        .map(|i| produced("new", &sender, i))
        .collect::<String>();
    let output = f.run(listing.as_bytes(), "", 0);
    let text = context(&output, "UserPromptSubmit");
    assert!(text.len() <= 4096);
    assert!(text.matches(" sender=").count() <= 8);
    assert!(text.contains("unread=30"));
    assert!(text.contains("MORE ENTRIES"));
    assert!(text.contains("posted_ns=30"));
    assert!(!text.contains("posted_ns=1 "));
    assert!(
        output.stdout.len() <= 8192,
        "serialized response remains bounded"
    );
    f.registry(&"l".repeat(800));
    let text = context(&f.run(listing.as_bytes(), "", 0), "UserPromptSubmit");
    assert!(text.len() <= 4096);
    assert!(
        text.matches(" sender=").count() < 8,
        "byte bound limits the tail"
    );
    assert!(text.contains("MORE ENTRIES"));
    f.registry("alpha");
    f.event("Stop", "", None);
    let text = message(&f.run(b"", &"界".repeat(2000), 2));
    assert!(text.len() <= 4096);
    assert!(text.ends_with("..."));
}

/// ´test:integration:letters-context-failure-is-silent-and-retries-without-state´
#[test]
fn letters_context_failure_is_silent_and_retries_without_state() {
    for event in ["SessionStart", "UserPromptSubmit"] {
        let mut f = Fixture::new();
        f.event(event, "startup", None);
        for (listing, failure, status) in [
            (first(), "failed entry", 2),
            ("bad output".to_owned(), "", 0),
        ] {
            silent(&f.run(listing.as_bytes(), failure, status));
            assert!(
                fs::read_to_string(f.dir.state_path("orchestrator.log"))
                    .expect("log")
                    .contains("LettersListingFailed")
            );
            fs::remove_file(f.dir.state_path("orchestrator.log")).expect("clear log");
            for marker in [
                "guard-count-fixture",
                "guard-warn-fixture",
                "guard-prompt-fixture",
            ] {
                assert!(!f.dir.state_path(marker).exists());
            }
        }
        assert!(!f.receipt().exists());
        assert!(context(&f.run(first().as_bytes(), "", 0), event).contains("unread=1"));
        assert!(!f.receipt().exists());
        fs::remove_file(&f.registry).expect("unmatched");
        silent(&f.run(first().as_bytes(), "", 0));
    }
}

/// ´test:integration:letters-callback-zero-one-and-burst-use-full-unread-listings´
#[test]
fn letters_callback_zero_one_and_burst_use_full_unread_listings() {
    let f = Fixture::new();
    for (count, listing) in [
        (0, String::new()),
        (1, first()),
        (2, format!("{}{}", first(), second())),
    ] {
        let output = f.run(listing.as_bytes(), "", 0);
        if count == 0 {
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(output.stdout, [] as [u8; 0]);
            assert_eq!(output.stderr, [] as [u8; 0]);
        } else {
            assert_eq!(output.status.code(), Some(2));
            assert_eq!(output.stdout, [] as [u8; 0]);
            let feedback = String::from_utf8(output.stderr).expect("feedback");
            assert!(feedback.starts_with(&format!("LETTERS unread={count} loop=alpha\n")));
            assert_eq!(feedback.matches(" sender=").count(), count);
        }
    }
    let call = fs::read_to_string(f.dir.path().join("call")).expect("call");
    assert_eq!(
        call,
        format!(
            "{}\nenter\nalpha\n--\nletters\nlist\n",
            f.dir.path().display()
        )
    );
    assert_eq!(
        fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("shared count"),
        "None 2"
    );
}

/// ´test:integration:letters-arriving-between-turn-ends-appear-until-taken´
#[test]
fn letters_arriving_between_turn_ends_appear_until_taken() {
    let f = Fixture::new();
    assert_eq!(f.run(b"", "", 0).status.code(), Some(0));
    let initial = f.run(first().as_bytes(), "", 0);
    assert_eq!(initial.status.code(), Some(2));
    assert_eq!(f.run(first().as_bytes(), "", 0).stderr, initial.stderr);
    let burst = f.run(format!("{}{}", first(), second()).as_bytes(), "", 0);
    assert!(
        String::from_utf8(burst.stderr)
            .expect("burst")
            .starts_with("LETTERS unread=2")
    );
    assert_eq!(f.run(b"", "", 0).status.code(), Some(0));
}

/// ´test:integration:letters-failed-entry-registry-and-follower-report-without-blocking´
#[test]
fn letters_failed_entry_registry_and_follower_report_without_blocking() {
    let f = Fixture::new();
    for reason in [
        "unknown loop: alpha",
        "letters inbox owner, group or mode mismatch: inbox/new",
        "letters unsafe path: inbox/new: No such file or directory",
    ] {
        let output = f.run(b"", reason, 2);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert!(message(&output).contains(reason));
    }
    fs::remove_file(f.bin.join("superloop")).expect("absent entry");
    let output = f.run(b"", "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("entry unavailable:"));
    assert!(message(&output).contains(".local/bin/superloop"));
    fs::write(
        &f.registry,
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = []\n",
    )
    .expect("unregistered");
    let output = f.run(b"", "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    fs::remove_file(&f.registry).expect("absent registry");
    let output = f.run(b"", "", 0);
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
        let off = f.run(first().as_bytes(), "", 0);
        assert_eq!(off.status.code(), Some(0));
        assert_eq!(off.stdout, [] as [u8; 0]);
        assert_eq!(off.stderr, [] as [u8; 0]);
        f.dir.enable(&f.root.to_string_lossy());
        let on = f.run(first().as_bytes(), "", 0);
        assert_eq!(on.status.code(), Some(2));
        assert_eq!(on.stdout, [] as [u8; 0]);
        let reason = String::from_utf8(on.stderr).expect("heartbeat reason");
        assert!(reason.starts_with("HEARTBEAT GUARD:"));
        assert!(reason.contains("ScheduleWakeup"));
        assert!(!reason.contains("LETTERS"));
        assert!(!f.dir.path().join("call").exists());
    }
}

/// ´test:integration:letters-malformed-output-and-entry-refusals-fail-open-by-name´
#[test]
fn letters_malformed_output_and_entry_refusals_fail_open_by_name() {
    let f = Fixture::new();
    for (bytes, reason) in [
        (&b"\xff"[..], "invalid UTF-8"),
        (b"other\n", "expected five letter fields"),
        (b"new/name wrong\n", "expected five letter fields"),
        (
            b"new/bad refused reason=\"malformed letter\"\n",
            "refused=1",
        ),
    ] {
        let output = f.run(bytes, "", 0);
        assert_eq!(output.status.code(), Some(0));
        assert!(message(&output).contains(reason));
    }
    let source = fs::read_to_string(&f.registry).expect("registry");
    fs::write(
        &f.registry,
        format!(
            "{source}\n[[loops]]\nname = \"beta\"\nuid = 41002\nlaunch = {}\n",
            serde_json::to_string(&f.root.strip_prefix(f.dir.home()).expect("relative launch"))
                .expect("launch")
        ),
    )
    .expect("ambiguous");
    let output = f.run(b"", "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("ambiguous loop for cwd:"));
}

/// ´test:integration:letters-feedback-preserves-heartbeat-prompts-counters-and-lapse´
#[test]
fn letters_feedback_preserves_heartbeat_prompts_counters_and_lapse() {
    let f = Fixture::new();
    f.dir.enable(&f.root.to_string_lossy());
    for count in 1..=3 {
        let output = f.run(first().as_bytes(), "", 0);
        assert_eq!(output.status.code(), Some(2));
        let reason = String::from_utf8(output.stderr).expect("reason");
        assert!(reason.starts_with("LETTERS unread=1 loop=alpha\n"));
        assert!(reason.contains("HEARTBEAT GUARD:"));
        assert_eq!(
            fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
            format!("None {count}")
        );
    }
    let lapse = f.run(first().as_bytes(), "", 0);
    assert_eq!(lapse.status.code(), Some(0));
    assert_eq!(lapse.stderr, [] as [u8; 0]);
    assert!(message(&lapse).contains("LAPSED"));
    assert!(message(&lapse).contains("LETTERS unread=1"));
    assert!(
        serde_json::from_slice::<Value>(&lapse.stdout)
            .expect("json")
            .get("decision")
            .is_none()
    );
    let failure = f.run(b"", "entry refusal", 2);
    assert_eq!(failure.status.code(), Some(0));
    assert!(message(&failure).contains("entry refusal"));
    assert!(message(&failure).contains("LAPSED"));
    assert_eq!(
        fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
        "None 3"
    );
}

/// ´test:integration:letters-continuation-notifies-without-a-new-letters-block´
#[test]
fn letters_continuation_notifies_without_a_new_letters_block() {
    let mut f = Fixture::new();
    let mut payload: Value = serde_json::from_slice(&f.payload).expect("payload");
    payload["stop_hook_active"] = json!(true);
    f.payload = serde_json::to_vec(&payload).expect("continuation");
    let output = f.run(first().as_bytes(), "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(message(&output).starts_with("LETTERS unread=1"));
    assert!(!f.dir.state_path("guard-count-fixture").exists());

    // A heartbeat block still reaches the model; letters stay in systemMessage.
    f.dir.enable(&f.root.to_string_lossy());
    let output = f.run(first().as_bytes(), "", 0);
    assert_eq!(output.status.code(), Some(0));
    let response: Value = serde_json::from_slice(&output.stdout).expect("response");
    assert_eq!(response["decision"], "block");
    assert!(
        response["reason"]
            .as_str()
            .expect("reason")
            .starts_with("HEARTBEAT GUARD:")
    );
    assert!(
        response["systemMessage"]
            .as_str()
            .expect("feedback")
            .starts_with("LETTERS unread=1")
    );
    assert_eq!(
        fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
        "None 1"
    );
}

/// ´test:integration:letters-never-taken-reach-the-shared-turn-bound´
#[test]
fn letters_never_taken_reach_the_shared_turn_bound() {
    let f = Fixture::new();
    for count in 1..=3 {
        assert_eq!(f.run(first().as_bytes(), "", 0).status.code(), Some(2));
        assert_eq!(
            fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
            format!("None {count}")
        );
    }
    for _ in 0..3 {
        let output = f.run(first().as_bytes(), "", 0);
        assert_eq!(output.status.code(), Some(0));
        assert!(message(&output).starts_with("LETTERS unread=1"));
    }
    assert_eq!(
        fs::read_to_string(f.dir.state_path("guard-count-fixture")).expect("count"),
        "None 3"
    );
}

/// # Panics
/// Panics only if fixture setup fails or the entry group survives the original observation bound.
/// ´test:integration:letters-deadline-kills-the-entry-group-and-keeps-the-heartbeat-prompt´
#[test]
fn letters_deadline_kills_the_entry_group_and_keeps_the_heartbeat_prompt() {
    let f = Fixture::new();
    f.dir.enable(&f.root.to_string_lossy());
    fs::write(
        f.bin.join("superloop"),
        "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$CALL\"\nwait\n",
    )
    .expect("sleeping entry");
    let started = std::time::Instant::now();
    let output = f.run(b"", "", 0);
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
    assert!(
        message(&output).contains(
            &f.bin
                .join("superloop")
                .display()
                .to_string()
                .escape_debug()
                .to_string()
        )
    );
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

/// ´test:integration:letters-deployed-entry-precedes-path-and-path-remains-a-fallback´
#[test]
fn letters_deployed_entry_precedes_path_and_path_remains_a_fallback() {
    let f = Fixture::new();
    let deployed = f.dir.home().join(".local/bin/superloop");
    fs::create_dir_all(deployed.parent().expect("bin parent")).expect("deployed bin");
    fs::rename(f.bin.join("superloop"), &deployed).expect("deploy entry");
    fs::write(f.bin.join("superloop"), "#!/bin/sh\nexit 77\n").expect("wrong path entry");
    fs::set_permissions(f.bin.join("superloop"), fs::Permissions::from_mode(0o700))
        .expect("path mode");
    assert_eq!(f.run(first().as_bytes(), "", 0).status.code(), Some(2));
    fs::remove_file(&deployed).expect("undeploy");
    let output = f.run(b"", "", 0);
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).contains("exit status: 77"));
    assert!(
        message(&output).contains(
            &f.bin
                .join("superloop")
                .display()
                .to_string()
                .escape_debug()
                .to_string()
        )
    );
}

/// ´test:integration:letters-reason-caps-lines-and-retains-the-exact-total´
#[test]
fn letters_reason_caps_lines_and_retains_the_exact_total() {
    let f = Fixture::new();
    let output = f.run(first().repeat(25).as_bytes(), "", 0);
    assert_eq!(output.status.code(), Some(2));
    let reason = String::from_utf8(output.stderr).expect("reason");
    assert!(reason.lines().count() <= 20);
    assert!(reason.starts_with("LETTERS unread=25 loop=alpha\n"));
    assert!(reason.ends_with("MORE ENTRIES n=17; use letters list for the full listing"));
    f.dir.enable(&f.root.to_string_lossy());
    let output = f.run(first().repeat(25).as_bytes(), "", 0);
    let reason = String::from_utf8(output.stderr).expect("reason");
    assert!(reason.lines().count() <= 20);
    assert!(reason.ends_with("MORE ENTRIES n=17; use letters list for the full listing"));
    assert!(reason.contains("HEARTBEAT GUARD:"));
}

/// ´test:integration:every-composed-verdict-is-a-reached-graph-terminal´
#[test]
fn every_composed_verdict_is_a_reached_graph_terminal() {
    use superloop_claude_hook::heartbeat::State;
    for (expected, enabled, continuation, count, arm_age) in [
        (State::BlockLetters, false, false, 0, None),
        (State::AllowLettersFeedback, false, true, 0, None),
        (State::BlockLettersAndPrompt, true, false, 0, None),
        (State::BlockPromptFeedback, true, true, 0, None),
        (State::BlockLettersAndViolation, true, false, 0, Some(10)),
        (State::BlockViolationFeedback, true, true, 0, Some(10)),
        (
            State::BlockLettersAndViolationAndPrompt,
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
            first().as_bytes(),
        );
        assert_eq!(result.state, expected);
        assert_eq!(result.path.last(), Some(&expected));
        assert!(expected.is_terminal());
        if continuation || count == 3 {
            assert_eq!(result.status, 0);
        } else {
            assert_eq!(result.status, 2);
        }
    }
}

/// ´test:integration:letters-counter-failures-notify-without-an-unrecorded-block´
#[test]
fn letters_counter_failures_notify_without_an_unrecorded_block() {
    // Exec closes sibling fixture writers before this child creates its entry.
    // Merely giving each fixture a separate pathname does not isolate the
    // descriptor table inherited by concurrent forks in the parent test binary.
    if std::env::var_os("HEARTBEAT_COUNTER_FIXTURE_CHILD").is_none() {
        let executable = std::env::current_exe().expect("test executable");
        let output = Command::new(executable)
            .args([
                "--exact",
                "letters_counter_failures_notify_without_an_unrecorded_block",
                "--nocapture",
            ])
            .env("HEARTBEAT_COUNTER_FIXTURE_CHILD", "1")
            .output()
            .expect("isolated counter fixture");
        assert!(
            output.status.success(),
            "isolated counter fixture: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    for fail_read in [true, false] {
        let f = Fixture::new();
        if fail_read {
            fs::create_dir_all(f.dir.state_path("guard-count-fixture")).expect("unreadable count");
        } else {
            fs::create_dir_all(f.dir.state_dir()).expect("state directory");
            fs::set_permissions(f.dir.state_dir(), fs::Permissions::from_mode(0o555))
                .expect("unwritable counter directory");
        }
        let output = f.run(first().as_bytes(), "", 0);
        if !fail_read {
            fs::set_permissions(f.dir.state_dir(), fs::Permissions::from_mode(0o755))
                .expect("restore state directory");
        }
        assert_eq!(output.status.code(), Some(0));
        assert!(
            message(&output).starts_with("LETTERS unread=1"),
            "counter failure fail_read={fail_read}: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// ´test:integration:letters-counter-directory-creation-failure-only-notifies´
#[test]
fn letters_counter_directory_creation_failure_only_notifies() {
    let f = Fixture::new();
    let parent = f.dir.state_dir().parent().expect("parent").to_owned();
    fs::create_dir_all(&parent).expect("state parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o555)).expect("readonly parent");
    let output = f.run(first().as_bytes(), "", 0);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("restore parent");
    assert_eq!(output.status.code(), Some(0));
    assert!(message(&output).starts_with("LETTERS unread=1"));
    assert!(!f.dir.state_dir().exists());
}

/// ´test:integration:letters-context-deadline-fits-the-eight-second-harness-timeout´
#[test]
fn letters_context_deadline_fits_the_eight_second_harness_timeout() {
    for event in ["SessionStart", "UserPromptSubmit"] {
        let mut f = Fixture::new();
        f.event(event, "compact", Some("p1"));
        fs::write(
            f.bin.join("superloop"),
            "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$CALL\"\nwait\n",
        )
        .expect("sleeping entry");
        let started = std::time::Instant::now();
        silent(&f.run(b"", "", 0));
        let elapsed = started.elapsed();
        assert!(elapsed >= std::time::Duration::from_secs(5));
        assert!(elapsed < std::time::Duration::from_secs(8));
        assert!(
            fs::read_to_string(f.dir.state_path("orchestrator.log"))
                .expect("log")
                .contains("LettersListingFailed")
        );
        let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        for pid in fs::read_to_string(f.dir.path().join("call"))
            .expect("pids")
            .split_whitespace()
        {
            loop {
                let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
                    Ok(stat) => stat,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(error) => panic!("read entry-chain pid {pid}: {error}"),
                };
                let state = stat.rsplit_once(") ").expect("stat").1.chars().next();
                if state == Some('Z') {
                    break;
                }
                assert!(
                    std::time::Instant::now() < cleanup_deadline,
                    "{event}: entry-chain pid {pid} did not exit after SIGKILL: state={state:?}, stat={stat}"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// ´test:integration:letters-refused-history-preserves-unread-notification´
#[test]
fn letters_refused_history_preserves_unread_notification() {
    let mut f = Fixture::new();
    let refusal = "cur/retired.00000000000000000001.0123456789abcdef0123456789abcdef refused reason=\"letters sender uid matches no registry row\"\n";
    let listing = format!("{refusal}{}", first());
    let output = f.run(listing.as_bytes(), "", 0);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stderr).expect("feedback");
    assert!(text.contains("unread=1 loop=alpha refused=1"));
    assert!(text.contains("beta.00000000000000000001."));
    assert!(!text.contains("listing failed"));
    for event in ["SessionStart", "UserPromptSubmit"] {
        f.event(event, "startup", None);
        assert!(context(&f.run(listing.as_bytes(), "", 0), event).contains("refused=1"));
    }
    f.event("Stop", "", None);
    assert!(message(&f.run(refusal.as_bytes(), "", 0)).contains("unread=0 loop=alpha refused=1"));
}
