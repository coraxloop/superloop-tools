//! # `worker-monitor` subprocess contract matrix
//!
//! These tests pin the complete stdout document, superloop-cli-common control records on
//! stderr, exit classes, redaction, stream invariance, and state ownership.

mod support;

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write as _;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

use support::TestDir;

const USAGE_DIAGNOSTIC: &str = "superloop-lane: usage_error: invalid command-line arguments\n";
const CONTINUITY_DIAGNOSTIC: &str =
    "superloop-lane: evidence_continuity_failure: event source regressed behind follower offset\n";
const EVENT_SOURCE_DIAGNOSTIC: &str =
    "superloop-lane: event_source_failure: event source inspection failed\n";
const REPORT_READ_DIAGNOSTIC: &str =
    "superloop-lane: report_read_failure: completion report could not be read\n";
const OFFSET_STATE_DIAGNOSTIC: &str =
    "superloop-lane: offset_state_failure: accepted event offset could not be stored\n";

const HEARTBEAT_LINE: &str = "{\"type\":\"tool_progress\",\"tool_use_id\":\"toolu-heartbeat-0\",\"tool_name\":\"Bash\",\"parent_tool_use_id\":\"toolu-parent\",\"elapsed_time_seconds\":30,\"heartbeat\":true,\"session_id\":\"session\",\"uuid\":\"uuid\"}";
const ASSISTANT_LINE: &str = "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\"}}";

// Longest a released delta may take to arrive. It sits far below the thirty-second
// bounce window these cases select, so a feeder that merely waits the window out
// cannot pass by waiting.
const RELEASE_DEADLINE: Duration = Duration::from_secs(10);

// How long a held delta is watched for. Three one-second poll intervals with an
// empty stdout is a hold, and the bounce window outlasts the observation.
const HOLD_OBSERVATION: Duration = Duration::from_secs(3);

const WAIT_PAUSE: Duration = Duration::from_millis(50);

// Longest the running reading may take to answer for a process that is already
// a corpse. Deciding an entry that is present and dead is one read of that
// entry, so the answer lands before even a single `WAIT_PAUSE`; twenty pauses
// leaves a loaded machine room to be slow about scheduling the reader and is
// still a tenth of `RELEASE_DEADLINE`, so a reading that waited its window out
// instead of discriminating the corpse cannot pass under it.
const CORPSE_VERDICT_BOUND: Duration = WAIT_PAUSE.saturating_mul(20);

// A collection window too short for any release, so a collection over a held
// feeder can only end in the kill-and-reap branch.
const KILL_WINDOW: Duration = Duration::from_millis(500);

fn worker_monitor() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
    command.args(["driver", "follow", "--save-offset"]);
    command
}

fn run<I, A>(arguments: I) -> Output
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    worker_monitor()
        .args(arguments)
        .output()
        .expect("worker-monitor subprocess runs")
}

// Run the feeder until it publishes a document or the deadline passes, whichever
// comes first. A held feeder polls forever, so the wait is bounded here rather
// than in the fixture, and a hold is reported as an absent document.
fn run_until<I, A>(arguments: I, deadline: Duration) -> Option<Output>
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    collect_within(Feeder::spawn(arguments), deadline)
}

// A running feeder its scope owns: whatever leaves that scope, a value or a
// panic, takes the process with it.
//
// `std::process::Child` neither stops nor reaps its process when it is dropped,
// so a case that held a bare child across an assertion left a feeder polling a
// directory `TestDir`'s own drop had already removed whenever that assertion
// failed — the run reported one failing case and kept a process. Collecting the
// child hands the duty back to the caller; every other way out kills and reaps
// here.
struct Feeder {
    child: Option<Child>,
    pid: u32,
}

impl Feeder {
    // Start the feeder with its streams captured and leave it running, so a case
    // can watch one process hold and then release as the fixture changes under it.
    fn spawn<I, A>(arguments: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        Self::spawn_command(worker_monitor().args(arguments))
    }

    // Start `command` with the captured streams and the ownership every feeder
    // runs under. A case that has to reach the feeder by some other route — a
    // shell that execs it after a delay, say — gets a process this guard still
    // kills and reaps, so no route out of a case leaks one.
    fn spawn_command(command: &mut Command) -> Self {
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("worker-monitor subprocess spawns");
        Self {
            pid: child.id(),
            child: Some(child),
        }
    }

    // The identifier a case watches the process table for. It is kept beside the
    // child because the guard consumes the handle it was read from.
    const fn pid(&self) -> u32 {
        self.pid
    }

    const fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("the feeder is still held")
    }

    // Hand the child back for collection: reaping it is the caller's from here.
    fn into_child(mut self) -> Child {
        self.child.take().expect("the feeder is still held")
    }
}

impl Drop for Feeder {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // A panic here would replace the report of the case that is already
        // failing with an abort, so both outcomes are swallowed; the witnesses
        // below are what prove the kill and the reap actually happen.
        let _killed = child.kill();
        let _reaped = child.wait();
    }
}

// Watch a running feeder for `window` and report whether it exited inside it. An
// exit is a publication; a feeder still polling at the end of the window is a
// hold.
fn exits_within(child: &mut Child, window: Duration) -> bool {
    let start = Instant::now();
    loop {
        match child
            .try_wait()
            .expect("poll the worker-monitor subprocess")
        {
            Some(_status) => return true,
            None if start.elapsed() >= window => return false,
            None => std::thread::sleep(WAIT_PAUSE),
        }
    }
}

// Take the document a feeder publishes inside `window`, or nothing for a hold,
// leaving no subprocess behind either way.
fn collect_within(mut feeder: Feeder, window: Duration) -> Option<Output> {
    if exits_within(feeder.child(), window) {
        return Some(
            feeder
                .into_child()
                .wait_with_output()
                .expect("collect worker-monitor output"),
        );
    }
    // A feeder still polling when the window closes is stopped by the guard's
    // drop, so the kill and the reap have one implementation for every exit.
    drop(feeder);
    None
}

// Whether the process that was `pid` has left the process table inside `window`.
//
// The observation is `/proc` rather than a second handle: only one handle may
// reap a child and the guard owns it, and the process table answers the sharper
// question anyway, because a child that was killed without being reaped keeps
// its entry until someone waits on it. A guard that killed but did not reap
// therefore fails here exactly as one that did neither. The command name is read
// alongside the entry, so a recycled identifier reads as a different program
// instead of a survivor.
fn process_ends_within(pid: u32, window: Duration) -> bool {
    let start = Instant::now();
    loop {
        if feeder_is_gone(pid) {
            return true;
        }
        if start.elapsed() >= window {
            return false;
        }
        std::thread::sleep(WAIT_PAUSE);
    }
}

fn feeder_is_gone(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).map_or(true, |command| {
        !command.trim_end().starts_with("superloop-lane")
    })
}

// Whether the feeder that was `pid` is running under its own name inside
// `window`.
//
// This is not the negation of the reading above, and what sits between them is
// the interval a spawned child spends before its own image is installed. The
// child holds its place in the process table from the first instant, but it
// carries the spawning program's command name until its exec lands, so a name
// sampled the moment the spawn call returns reads a live feeder as an absent
// one — seldom on an idle machine, readily on a loaded one, where a child can
// lose the processor exactly there. The name is therefore waited for rather
// than sampled, in the poll shape and under the deadline the ending observation
// already uses.
//
// Waiting cannot mistake a dead feeder for a slow one, because what ends the
// wait early is the entry rather than the name: no entry at all, or an entry
// that is a corpse, is an answer of no, and only a live entry that does not yet
// carry the name is waited on.
fn feeder_runs_within(pid: u32, window: Duration) -> bool {
    let start = Instant::now();
    loop {
        if process_is_absent_or_dead(pid) {
            return false;
        }
        if !feeder_is_gone(pid) {
            return true;
        }
        if start.elapsed() >= window {
            return false;
        }
        std::thread::sleep(WAIT_PAUSE);
    }
}

// Whether the process table holds no live entry for `pid`: no entry at all, or
// one reported `Z`, killed and awaiting its reaper, or `X`, being torn down. A
// corpse keeps the name it ran under, so the name cannot tell a survivor from a
// remnant and the state is what decides.
//
// The state is read from behind the command field's closing parenthesis. That
// field is parenthesised and may itself contain spaces and parentheses, which
// counting fields from the left does not survive.
fn process_is_absent_or_dead(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true;
    };
    let Some((_command, state_onwards)) = stat.rsplit_once(')') else {
        return true;
    };
    matches!(state_onwards.split_whitespace().next(), Some("Z" | "X"))
}

// Whether `pid`'s entry is present and reported `Z`, a process that has exited
// and not yet been reaped.
//
// The state field is parsed here a second time rather than through the reading
// above, because a case that asked that reading whether the corpse was in place
// would be asking the very thing it means to witness: an inverted reading would
// answer yes for a process that was still alive, and the case would then stage
// its condition out of the same defect it is meant to catch. Reading the field
// here keeps the condition and the verdict independent. `Z` is matched alone:
// what the case stands on is a corpse that is present, not an entry that has
// gone.
fn entry_is_a_corpse(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_command, state_onwards)) = stat.rsplit_once(')') else {
        return false;
    };
    state_onwards.split_whitespace().next() == Some("Z")
}

fn corpse_appears_within(pid: u32, window: Duration) -> bool {
    let start = Instant::now();
    loop {
        if entry_is_a_corpse(pid) {
            return true;
        }
        if start.elapsed() >= window {
            return false;
        }
        std::thread::sleep(WAIT_PAUSE);
    }
}

fn parse_document(bytes: &[u8]) -> Value {
    let parsed: Value = serde_json::from_slice(bytes).expect("stdout JSON document");
    assert_eq!(parsed["schema"], 2);
    assert_ne!(
        parsed["records"]
            .as_array()
            .expect("records array")
            .as_slice(),
        &[] as &[Value]
    );
    parsed
}

fn data_document(output: &Output) -> Value {
    parse_document(&output.stdout)
}

fn only_record(output: &Output) -> Value {
    let parsed = data_document(output);
    let records = parsed["records"].as_array().expect("records array");
    if records[0]["kind"] == "state" {
        assert_eq!(records.len(), 2);
        records[1].clone()
    } else {
        assert_eq!(records.len(), 1);
        records[0].clone()
    }
}

fn control_record(output: &Output) -> Value {
    let line = output
        .stderr
        .strip_suffix(b"\n")
        .expect("control record ends in LF");
    assert!(!line.contains(&b'\n'));
    serde_json::from_slice(&output.stderr).expect("stderr control-plane JSON")
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    let parsed = data_document(output);
    let state = &parsed["records"][0];
    assert_eq!(state["kind"], "state");
    let at = state["at"].as_str().expect("UTC sample instant");
    assert_eq!(at.len(), 20);
    assert!(at.ends_with('Z'));
    for name in ["wall_seconds", "offset"] {
        assert!(state[name].is_null() || state[name].is_number(), "{name}");
    }
    if !state["events"].is_null() {
        assert!(state["events"]["bytes"].is_u64());
        assert!(
            state["events"]["age_seconds"].is_null() || state["events"]["age_seconds"].is_u64()
        );
    }
}

fn assert_failure(output: &Output, exit: i32, kind: &str, message: &str, control_kind: &str) {
    assert_eq!(output.status.code(), Some(exit));
    let record = only_record(output);
    assert_eq!(record["kind"], kind);
    assert_eq!(record["message"], message);

    let control = control_record(output);
    assert_eq!(control["schema"], 1);
    assert_eq!(control["command"], "superloop-lane");
    assert_eq!(control["kind"], control_kind);
}

/// ´test:integration:immediate-empty-growth-document-is-exact´
#[test]
fn immediate_empty_growth_document_is_exact() {
    let directory = TestDir::new("immediate-empty-growth");
    directory.write("events.jsonl", b"growth");

    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--cap=0"),
        OsString::from("--bounce=0"),
    ]);

    assert_success(&output);
    assert_eq!(
        only_record(&output),
        json!({"kind":"delta","bytes":0,"events":[],"truncated":true})
    );
    assert_eq!(directory.read(".feed-offset"), b"6\n");
}

/// ´test:integration:immediate-parsed-delta-document-is-exact´
#[test]
fn immediate_parsed_delta_document_is_exact() {
    let directory = TestDir::new("immediate-plain-delta");
    directory.write("events.jsonl", b"{\"event\":\"one\"}\n");

    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=0"),
    ]);

    assert_success(&output);
    assert_eq!(
        only_record(&output),
        json!({"kind":"delta","bytes":16,"events":[{"event":"one"}],"truncated":false})
    );
    assert_eq!(directory.read(".feed-offset"), b"16\n");
}

/// ´test:integration:immediate-capped-delta-document-is-exact´
#[test]
fn immediate_capped_delta_document_is_exact() {
    let directory = TestDir::new("immediate-capped-delta");
    directory.write("events.jsonl", b"0123456789");

    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--cap"),
        OsString::from("5"),
        OsString::from("--bounce"),
        OsString::from("0"),
    ]);

    assert_success(&output);
    assert_eq!(
        only_record(&output),
        json!({"kind":"delta","bytes":5,"events":[56789],"truncated":true})
    );
    assert_eq!(directory.read(".feed-offset"), b"10\n");
}

/// ´test:integration:finished-without-last-message-document-is-exact´
#[test]
fn finished_without_last_message_document_is_exact() {
    let directory = TestDir::new("finished-no-last");
    directory.write("run-report.txt", b"RUN-REPORT exit=0\n");

    let output = run([directory.path()]);

    assert_success(&output);
    assert_eq!(
        only_record(&output),
        json!({"kind":"finished","last_message":null,"report":"RUN-REPORT exit=0\n"})
    );
    assert!(!directory.exists(".feed-offset"));
}

/// ´test:integration:finished-with-last-message-document-is-exact´
#[test]
fn finished_with_last_message_document_is_exact() {
    let directory = TestDir::new("finished-last");
    directory.write("run-report.txt", b"RUN-REPORT exit=0");
    directory.write("last-message.txt", b"final answer");

    let output = run([directory.path()]);

    assert_success(&output);
    assert_eq!(
        only_record(&output),
        json!({"kind":"finished","last_message":"final answer","report":"RUN-REPORT exit=0"})
    );
}

/// ´test:integration:combined-delta-and-finished-call-has-one-document-in-order´
#[test]
fn combined_delta_and_finished_call_has_one_document_in_order() {
    let directory = TestDir::new("combined");
    directory.write("events.jsonl", b"{\"event\":1}\n");
    directory.write("run-report.txt", b"DONE\n");
    directory.write("last-message.txt", b"last");

    let output = run([directory.path()]);
    let parsed = data_document(&output);
    let records = parsed["records"].as_array().expect("records array");

    assert_success(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["kind"], "state");
    assert_eq!(records[1]["kind"], "delta");
    assert_eq!(records[2]["kind"], "finished");
    assert_eq!(records[2]["report"], "DONE\n");
    assert_eq!(records[2]["last_message"], "last");
}

/// ´test:integration:quiet-log-with-default-bounce-serves-immediately-on-call´
#[test]
fn quiet_log_with_default_bounce_serves_immediately_on_call() {
    let directory = TestDir::new("quiet-default");
    directory.write("events.jsonl", b"quiet");
    directory.set_modified("events.jsonl", SystemTime::now() - Duration::from_secs(31));

    let output = run([directory.path()]);

    assert_success(&output);
    assert_eq!(only_record(&output)["kind"], "delta");
}

/// ´test:integration:regressed-source-is-a-data-and-control-plane-failure´
#[test]
fn regressed_source_is_a_data_and_control_plane_failure() {
    let directory = TestDir::new("regressed-source");
    directory.write("events.jsonl", b"abc");
    directory.write(".feed-offset", b"9\n");
    directory.write("run-report.txt", b"DONE\n");

    let output = run([directory.path()]);

    assert_failure(
        &output,
        1,
        "evidence_continuity_failure",
        CONTINUITY_DIAGNOSTIC,
        "diagnostic",
    );
    assert_eq!(directory.read(".feed-offset"), b"9\n");
}

/// ´test:integration:missing-arguments-use-cli-exit-and-usage-envelope´
#[test]
fn missing_arguments_use_cli_exit_and_usage_envelope() {
    let output = run(Vec::<OsString>::new());

    assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
    let control = control_record(&output);
    assert_eq!(control["message"], "invalid command-line arguments");
    assert_eq!(control["fields"]["exit_code"], 2);
    assert_eq!(control["fields"]["clap_error_kind"], "invalid_arguments");
}

/// ´test:integration:invalid-run-directory-is-redacted-by-omission´
#[test]
fn invalid_run_directory_is_redacted_by_omission() {
    let directory = TestDir::new("usage-path");
    let secret_path = directory.path().join("SHOULD_NOT_APPEAR-secret-path");

    let output = run([secret_path]);

    assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SHOULD_NOT_APPEAR"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SHOULD_NOT_APPEAR"));
}

/// ´test:integration:invalid-cap-is-usage-failure-without-echoing-value´
#[test]
fn invalid_cap_is_usage_failure_without_echoing_value() {
    let directory = TestDir::new("usage-cap");
    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--cap=SHOULD_NOT_APPEAR-secret-cap"),
    ]);

    assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SHOULD_NOT_APPEAR"));
}

/// ´test:integration:invalid-bounce-is-usage-failure-without-echoing-value´
#[test]
fn invalid_bounce_is_usage_failure_without_echoing_value() {
    let directory = TestDir::new("usage-bounce");
    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=SHOULD_NOT_APPEAR-secret-bounce"),
    ]);

    assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SHOULD_NOT_APPEAR"));
}

/// ´test:integration:unknown-option-is-usage-failure´
#[test]
fn unknown_option_is_usage_failure() {
    let directory = TestDir::new("usage-option");
    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--help"),
    ]);

    assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
}

/// ´test:integration:event-source-failure-has-one-document-and-one-control-record´
#[test]
fn event_source_failure_has_one_document_and_one_control_record() {
    let directory = TestDir::new("runtime-event-source");
    directory.mkdir("events.jsonl");

    let output = run([directory.path()]);

    assert_failure(
        &output,
        1,
        "event_source_failure",
        EVENT_SOURCE_DIAGNOSTIC,
        "diagnostic",
    );
    assert!(!directory.exists(".feed-offset"));
}

/// ´test:integration:report-read-failure-has-one-document-and-one-control-record´
#[test]
fn report_read_failure_has_one_document_and_one_control_record() {
    let directory = TestDir::new("runtime-report-read");
    directory.mkdir("run-report.txt");

    let output = run([directory.path()]);

    assert_failure(
        &output,
        1,
        "report_read_failure",
        REPORT_READ_DIAGNOSTIC,
        "diagnostic",
    );
    assert!(!directory.exists(".feed-offset"));
}

/// ´test:integration:offset-state-failure-is-detected-before-failure-document´
#[test]
fn offset_state_failure_is_detected_before_failure_document() {
    let directory = TestDir::new("runtime-offset-state");
    directory.write("events.jsonl", b"abc");
    directory.mkdir(".feed-offset");

    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=0"),
    ]);

    assert_failure(
        &output,
        1,
        "offset_state_failure",
        OFFSET_STATE_DIAGNOSTIC,
        "diagnostic",
    );
    assert!(directory.path().join(".feed-offset").is_dir());
}

/// ´test:integration:stdout-pipe-and-regular-file-receive-same-document-except-clock´
#[test]
fn stdout_pipe_and_regular_file_receive_same_document_except_clock() {
    let piped_directory = TestDir::new("stream-pipe");
    piped_directory.write("events.jsonl", b"same bytes");
    let piped = run([
        piped_directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=0"),
    ]);
    assert_success(&piped);

    let file_directory = TestDir::new("stream-file");
    file_directory.write("events.jsonl", b"same bytes");
    let capture_directory = TestDir::new("stream-capture");
    let capture = capture_directory.path().join("stdout.json");
    let stdout_file = File::create(&capture).expect("create stdout capture");
    let file_output = worker_monitor()
        .arg(file_directory.path())
        .arg("--bounce=0")
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::piped())
        .output()
        .expect("worker-monitor with file stdout runs");

    assert_eq!(file_output.status.code(), Some(0));
    assert_eq!(file_output.stdout, [] as [u8; 0]);
    assert_eq!(file_output.stderr, [] as [u8; 0]);
    let file_bytes = std::fs::read(capture).expect("read capture");
    let piped_document = data_document(&piped);
    let file_document = parse_document(&file_bytes);
    let mut piped_state = piped_document["records"][0].clone();
    let mut file_state = file_document["records"][0].clone();
    for state in [&mut piped_state, &mut file_state] {
        assert_eq!(state["kind"], "state");
        assert!(state["at"].is_string());
        assert!(state["events"]["age_seconds"].is_u64());
        state["at"] = json!("fixed");
        state["wall_seconds"] = json!(0);
        state["events"]["age_seconds"] = json!(0);
    }
    assert_eq!(piped_state, file_state);

    // Replace only the three sampled values in the original byte streams.
    // Parsing and reserializing the documents would hide changes in key order.
    let without_clock = |bytes: &[u8], document: &Value| {
        let state = &document["records"][0];
        let mut raw = std::str::from_utf8(bytes)
            .expect("UTF-8 document")
            .to_owned();
        for (key, value, fixed) in [
            ("at", &state["at"], json!("fixed")),
            ("wall_seconds", &state["wall_seconds"], json!(0)),
            ("age_seconds", &state["events"]["age_seconds"], json!(0)),
        ] {
            let original = format!(
                "\"{key}\":{}",
                serde_json::to_string(value).expect("serialize sampled value")
            );
            let replacement = format!(
                "\"{key}\":{}",
                serde_json::to_string(&fixed).expect("serialize fixed value")
            );
            assert!(raw.contains(&original), "sampled field {key} in document");
            raw = raw.replacen(&original, &replacement, 1);
        }
        raw
    };
    assert_eq!(
        without_clock(&piped.stdout, &piped_document),
        without_clock(&file_bytes, &file_document)
    );
}

/// ´test:integration:successful-delta-adds-only-its-offset-state´
#[test]
fn successful_delta_adds_only_its_offset_state() {
    let directory = TestDir::new("state-ownership");
    directory.write("events.jsonl", b"abc");

    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=0"),
    ]);
    let mut entries = std::fs::read_dir(directory.path())
        .expect("read run directory")
        .map(|entry| {
            entry
                .expect("read run entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    entries.sort();

    assert_success(&output);
    assert_eq!(
        entries,
        [String::from(".feed-offset"), String::from("events.jsonl")]
    );
}

/// ´test:integration:every-success-and-failure-case-has-nonempty-records´
#[test]
fn every_success_and_failure_case_has_nonempty_records() {
    let success_directory = TestDir::new("nonempty-success");
    success_directory.write("run-report.txt", b"DONE");
    let success = run([success_directory.path()]);

    let failure = run(Vec::<OsString>::new());

    assert_ne!(
        data_document(&success)["records"]
            .as_array()
            .expect("success records")
            .as_slice(),
        &[] as &[Value]
    );
    assert_ne!(
        data_document(&failure)["records"]
            .as_array()
            .expect("failure records")
            .as_slice(),
        &[] as &[Value]
    );
}

/// ´test:integration:unparseable-line-stays-between-parseable-neighbors´
#[test]
fn unparseable_line_stays_between_parseable_neighbors() {
    let directory = TestDir::new("raw-order");
    directory.write("events.jsonl", b"{\"n\":1}\nbroken\n{\"n\":3}\n");

    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=0"),
    ]);

    assert_success(&output);
    assert_eq!(
        only_record(&output)["events"],
        json!([{ "n": 1 }, { "raw": "broken" }, { "n": 3 }])
    );
}

/// ´test:integration:heartbeat-tailed-delta-is-released-inside-the-bounce-window´
#[test]
fn heartbeat_tailed_delta_is_released_inside_the_bounce_window() {
    let directory = TestDir::new("heartbeat-tail");
    directory.write(
        "events.jsonl",
        format!("{ASSISTANT_LINE}\n{HEARTBEAT_LINE}\n").as_bytes(),
    );
    directory.set_modified("events.jsonl", SystemTime::now());

    let output = run_until(
        [
            directory.path().as_os_str().to_os_string(),
            OsString::from("--bounce=30"),
        ],
        RELEASE_DEADLINE,
    )
    .expect("a heartbeat-tailed delta is released without waiting the bounce window out");

    assert_success(&output);
    let record = only_record(&output);
    assert_eq!(record["kind"], "delta");
    assert_eq!(record["events"][0]["type"], "assistant");
    assert_eq!(record["events"][1]["type"], "tool_progress");
    assert_eq!(record["events"][1]["heartbeat"], true);
}

/// ´test:integration:ordinary-fresh-tail-still-waits-out-the-bounce-window´
#[test]
fn ordinary_fresh_tail_still_waits_out_the_bounce_window() {
    let directory = TestDir::new("ordinary-tail");
    directory.write(
        "events.jsonl",
        format!("{HEARTBEAT_LINE}\n{ASSISTANT_LINE}\n").as_bytes(),
    );
    directory.set_modified("events.jsonl", SystemTime::now());

    let mut feeder = Feeder::spawn([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=30"),
    ]);

    assert!(
        !exits_within(feeder.child(), HOLD_OBSERVATION),
        "a fresh ordinary tail must stay held"
    );
    assert!(!directory.exists(".feed-offset"));

    // The same feeder, the same fixture, one condition changed: the log's own
    // timestamp now sits outside the window it selected, which is the release a
    // held ordinary tail is waiting for.
    directory.set_modified(
        "events.jsonl",
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    );
    let output = collect_within(feeder, RELEASE_DEADLINE)
        .expect("an ordinary tail is served once its bounce window is out");

    assert_success(&output);
    let record = only_record(&output);
    assert_eq!(record["kind"], "delta");
    assert_eq!(record["events"][0]["type"], "tool_progress");
    assert_eq!(record["events"][1]["type"], "assistant");
}

/// ´test:integration:torn-heartbeat-line-does-not-release-the-delta´
#[test]
fn torn_heartbeat_line_does_not_release_the_delta() {
    let directory = TestDir::new("torn-heartbeat");
    directory.write(
        "events.jsonl",
        format!("{ASSISTANT_LINE}\n{HEARTBEAT_LINE}").as_bytes(),
    );
    directory.set_modified("events.jsonl", SystemTime::now());

    let mut feeder = Feeder::spawn([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=30"),
    ]);

    assert!(
        !exits_within(feeder.child(), HOLD_OBSERVATION),
        "a torn heartbeat is not the region's last complete line"
    );
    assert!(!directory.exists(".feed-offset"));

    // The same feeder, the same fixture, one condition changed: the heartbeat
    // gains its terminator. The append also refreshes the modification time, so
    // the window stays open and only the completed line can explain a release.
    File::options()
        .append(true)
        .open(directory.path().join("events.jsonl"))
        .expect("open the event source to finish its line")
        .write_all(b"\n")
        .expect("complete the torn heartbeat line");
    let output = collect_within(feeder, RELEASE_DEADLINE)
        .expect("a completed heartbeat line releases the delta inside the bounce window");

    assert_success(&output);
    let record = only_record(&output);
    assert_eq!(record["kind"], "delta");
    assert_eq!(record["events"][0]["type"], "assistant");
    assert_eq!(record["events"][1]["type"], "tool_progress");
    assert_eq!(record["events"][1]["heartbeat"], true);
}

/// ´test:integration:a-feeder-still-reaching-its-exec-is-not-a-feeder-that-ended´
#[test]
fn a_feeder_still_reaching_its_exec_is_not_a_feeder_that_ended() {
    let directory = TestDir::new("delayed-exec");
    directory.write(
        "events.jsonl",
        format!("{HEARTBEAT_LINE}\n{ASSISTANT_LINE}\n").as_bytes(),
    );
    directory.set_modified("events.jsonl", SystemTime::now());

    // A fractional `sleep` operand is a coreutils extension rather than a shell
    // guarantee. Where the runner's `sleep` rejects it, the shell below reaches
    // its exec at once, the window this case is built on never opens, and the
    // reading would be asserted against a condition nothing staged — a pass that
    // witnesses nothing. The operand is therefore tried first, so such a runner
    // fails the case and names the reason instead of passing it vacuously.
    //
    // The alternative — asserting that the feeder's name had not appeared at the
    // first sample — would read the staged window directly but could not be
    // relied on: a machine loaded enough to deschedule this thread past the
    // delay would fail a case that nothing is wrong with. A preflight is the
    // same question asked where the answer does not depend on scheduling.
    let fractional_sleep = Command::new("sh")
        .arg("-c")
        .arg("sleep 0.3")
        .output()
        .expect("the fractional-sleep preflight runs");
    assert!(
        fractional_sleep.status.success(),
        "this runner's `sleep` rejects the fractional operand the delayed exec is staged with: {}",
        String::from_utf8_lossy(&fractional_sleep.stderr).trim_end()
    );

    // A child holds a place in the process table from the moment it is forked,
    // but it carries the spawning program's command name until its own image is
    // installed, so the feeder's name appears some time after the spawn call
    // returns. Losing the processor inside that window is what a loaded machine
    // does and what no case can stage on demand, so the window is held open
    // deliberately instead: a shell that sleeps before exec'ing the same feeder,
    // spawned in the same shape and owned by the same guard, is alive the whole
    // time and reads under a name that is not the feeder's until the exec lands.
    // It is the load race's model, not the race itself.
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("sleep 0.3; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["driver", "follow", "--save-offset"])
        .arg(directory.path())
        .arg("--bounce=30");
    let feeder = Feeder::spawn_command(&mut command);
    let pid = feeder.pid();

    assert!(
        feeder_runs_within(pid, RELEASE_DEADLINE),
        "a feeder still reaching its exec was read as one that had ended"
    );

    // The delay moves when the feeder's name appears, not who owns the process:
    // the guard kills and reaps this one exactly as it does a direct spawn.
    //
    // The order of the two readings is this case's substance rather than its
    // arrangement. The ending reading answers yes for any entry that does not
    // carry the feeder's name, a live one included, so on its own it would have
    // been satisfied by the shell that had not reached its exec yet — an answer
    // about the delay instead of about the drop. What rules that reading out is
    // the reading above, which has already waited the feeder's own name into the
    // table: from here, only a process that leaves it can answer yes.
    drop(feeder);
    assert!(
        process_ends_within(pid, RELEASE_DEADLINE),
        "the dropped guard left the delayed feeder {pid} in the process table"
    );
}

/// ´test:integration:an-unreaped-corpse-is-not-a-feeder-still-reaching-its-exec´
#[test]
fn an_unreaped_corpse_is_not_a_feeder_still_reaching_its_exec() {
    // A child that exits the moment it starts, spawned in the fixture's own
    // shape so the guard owns it and nothing reaps it until that guard is
    // dropped: its entry therefore stays in the process table as a corpse for
    // the whole reading below, carrying `sh` rather than the feeder's name —
    // which is what a child that has not reached its exec yet also reads as.
    // Only the entry's state separates the two, and that state is what this
    // case witnesses.
    let mut command = Command::new("sh");
    command.arg("-c").arg("exit 0");
    let feeder = Feeder::spawn_command(&mut command);
    let pid = feeder.pid();

    assert!(
        corpse_appears_within(pid, RELEASE_DEADLINE),
        "the child {pid} never became the unreaped corpse this case reads"
    );

    let start = Instant::now();
    let running = feeder_runs_within(pid, RELEASE_DEADLINE);
    let verdict = start.elapsed();

    assert!(
        !running,
        "an unreaped corpse {pid} was read as a feeder that is running"
    );
    // Waiting the corpse out to the deadline would answer no as well, so the
    // answer alone witnesses nothing: it is the promptness that says the entry's
    // state decided the reading, rather than a window that merely ran out.
    assert!(
        verdict < CORPSE_VERDICT_BOUND,
        "the reading took {verdict:?} over an entry that was already a corpse, past the {CORPSE_VERDICT_BOUND:?} deciding a present and dead entry may cost"
    );
}

/// ´test:integration:a-dropped-guard-kills-and-reaps-the-feeder-it-held´
#[test]
fn a_dropped_guard_kills_and_reaps_the_feeder_it_held() {
    let directory = TestDir::new("guard-drop");
    directory.write(
        "events.jsonl",
        format!("{HEARTBEAT_LINE}\n{ASSISTANT_LINE}\n").as_bytes(),
    );
    directory.set_modified("events.jsonl", SystemTime::now());

    // A fresh ordinary tail holds, so this feeder is still polling when its
    // guard goes out of scope uncollected — the state a hold assertion that
    // failed used to leave behind.
    let pid = {
        let feeder = Feeder::spawn([
            directory.path().as_os_str().to_os_string(),
            OsString::from("--bounce=30"),
        ]);
        assert!(
            feeder_runs_within(feeder.pid(), RELEASE_DEADLINE),
            "the held feeder is running before its guard is dropped"
        );
        feeder.pid()
    };

    assert!(
        process_ends_within(pid, RELEASE_DEADLINE),
        "the dropped guard left worker-monitor {pid} in the process table"
    );
}

/// ´test:integration:a-closed-collection-window-kills-and-reaps-the-held-feeder´
#[test]
fn a_closed_collection_window_kills_and_reaps_the_held_feeder() {
    let directory = TestDir::new("collection-window-kill");
    directory.write(
        "events.jsonl",
        format!("{HEARTBEAT_LINE}\n{ASSISTANT_LINE}\n").as_bytes(),
    );
    directory.set_modified("events.jsonl", SystemTime::now());

    let feeder = Feeder::spawn([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=30"),
    ]);
    let pid = feeder.pid();

    // Nothing releases this fixture inside so short a window, so collection can
    // only take its kill-and-reap branch.
    assert!(
        collect_within(feeder, KILL_WINDOW).is_none(),
        "a held feeder published a document inside the kill window"
    );
    assert!(
        process_ends_within(pid, RELEASE_DEADLINE),
        "the closed collection window left worker-monitor {pid} in the process table"
    );
}

/// ´test:integration:state-record-pins-keys-order-and-sampled-types´
#[test]
fn state_record_pins_keys_order_and_sampled_types() {
    let boot_before = test_boot_seconds();
    let directory = TestDir::new("state-keys");
    directory.write(".step-name", b"work\n");
    directory.write(".started-at", b"2026-01-01T00:00:00Z\n");
    directory.write(
        ".codex-lane.lock",
        format!("{}\n", std::process::id()).as_bytes(),
    );
    directory.write(
        format!(".monitor-{}-0", std::process::id()),
        b"quiet=1s wall=2s event_size=4 boot=3s awake=2s awaiting=gw:7 context_state=unknown context_used=unknown context_window=unknown context_fraction=unknown context_source=codex-exec-json context_reason=window-unreported context_turn=1 context_at=2026-10-07T00:00:00Z\n",
    );
    directory.write("events.jsonl", b"one\n");
    let output = run([directory.path().as_os_str(), OsStr::new("--bounce=0")]);
    let boot_after = test_boot_seconds();
    assert_success(&output);
    let raw = std::str::from_utf8(&output.stdout).expect("UTF-8 document");
    assert!(raw.starts_with("{\"schema\":2,\"records\":[{\"kind\":\"state\","));
    assert!(raw.ends_with("}\n"));
    let mut position = 0;
    for key in [
        "\"kind\":",
        "\"at\":",
        "\"step\":",
        "\"started_at\":",
        "\"wall_seconds\":",
        "\"driver\":",
        "\"lock\":",
        "\"pid\":",
        "\"child\":",
        "\"alive\":",
        "\"events\":",
        "\"bytes\":",
        "\"age_seconds\":",
        "\"monitor\":",
        "\"quiet\":",
        "\"wall\":",
        "\"event_size\":",
        "\"boot\":",
        "\"awake\":",
        "\"awaiting\":",
        "\"context\":",
        "\"report\":",
        "\"last_message\":",
        "\"offset\":",
    ] {
        let next = raw[position..]
            .find(key)
            .expect("state field in declared order");
        position += next + key.len();
    }
    let state = &data_document(&output)["records"][0];
    assert_eq!(state["step"], "work");
    assert_eq!(state["started_at"], "2026-01-01T00:00:00Z");
    assert!(
        state["wall_seconds"]
            .as_i64()
            .is_some_and(|seconds| (0..315_360_000).contains(&seconds))
    );
    assert_eq!(state["driver"]["pid"], std::process::id());
    assert_eq!(state["driver"]["alive"], true);
    assert_eq!(state["events"]["bytes"], 4);
    assert!(
        state["events"]["age_seconds"]
            .as_u64()
            .is_some_and(
                |seconds| (boot_before.saturating_sub(2)..=boot_after.saturating_sub(2))
                    .contains(&seconds)
            )
    );
    assert_eq!(state["monitor"]["awaiting"], "gw:7");
    assert_eq!(state["monitor"]["context"]["state"], "unknown");
    assert_eq!(state["monitor"]["context"]["source"], "codex-exec-json");
    assert_eq!(state["monitor"]["context"]["turn"], 1);
    assert_eq!(state["report"], false);
    assert_eq!(state["last_message"], false);
    assert_eq!(state["offset"], 0);
}

fn test_boot_seconds() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .expect("boot clock")
        .split_whitespace()
        .next()
        .expect("uptime")
        .split('.')
        .next()
        .expect("whole seconds")
        .parse()
        .expect("boot seconds")
}

/// # Panics
/// Panics only if fixture setup fails or unusable evidence overrides file age.
/// ´test:integration:unusable-awake-evidence-falls-back-on-the-real-producer-output´
#[test]
fn unusable_awake_evidence_falls_back_on_the_real_producer_output() {
    for (pid, boot, report) in [
        (std::process::id(), u64::MAX, false),
        (u32::MAX, 0, false),
        (std::process::id(), 0, true),
    ] {
        let directory = TestDir::new("awake-fallback");
        directory.write(".codex-lane.lock", format!("{pid}\n").as_bytes());
        directory.write(
            format!(".monitor-{pid}-0"),
            format!("quiet=900s wall=901s event_size=4 boot={boot}s awake=901s\n").as_bytes(),
        );
        directory.write("events.jsonl", b"one\n");
        if report {
            directory.write(
                "run-report.txt",
                b"RUN-REPORT lane=work exit=0 wall=1s budget=60s verdict=ok dir=/fixture\n",
            );
        }
        let output = run([directory.path().as_os_str(), OsStr::new("--bounce=0")]);
        assert_success(&output);
        assert!(
            data_document(&output)["records"][0]["events"]["age_seconds"]
                .as_u64()
                .is_some_and(|seconds| seconds < 5)
        );
    }
}

/// ´test:integration:budget-expiry-cli-hands-back-once-and-rearms´
#[test]
fn budget_expiry_cli_hands_back_once_and_rearms() {
    let directory = TestDir::new("budget-expiry-cli");
    let pid = std::process::id();
    directory.write(".codex-lane.lock", format!("{pid}\n").as_bytes());
    let sidecar = format!(".monitor-{pid}-0");
    directory.write(&sidecar, b"quiet=1s wall=21s event_size=0 boot=300s awake=20s budget=20s last_growth=20s state=growing expired_wall=21s expired_event_size=0 expired_last_growth=20s expired_quiet=1s expired_state=growing\n");
    let first = run([directory.path().as_os_str(), OsStr::new("--bounce=0")]);
    assert_success(&first);
    let doc = data_document(&first);
    assert_eq!(
        doc["records"][0]["monitor"],
        json!({
            "quiet":1,"wall":21,"event_size":0,"boot":300,"awake":20,
            "awaiting":null,"context":null,"budget":20,"last_growth":20,
            "state":"growing","expiry":{"wall":21,"event_size":0,"last_growth":20,"quiet":1,"state":"growing"}
        })
    );
    assert_eq!(
        doc["records"][1],
        json!({
            "kind":"budget_expired","budget":20,"wall":21,"event_size":0,
            "last_growth":20,"quiet":1,"expiry_state":"growing","state":"growing",
            "current_wall":21,"current_quiet":1,"current_last_growth":20
        })
    );
    directory.write(&sidecar, b"quiet=123s wall=143s event_size=0 boot=300s awake=142s budget=20s last_growth=20s state=stalled expired_wall=21s expired_event_size=0 expired_last_growth=20s expired_quiet=1s expired_state=growing\n");
    let second = run([directory.path().as_os_str(), OsStr::new("--bounce=0")]);
    assert_success(&second);
    let doc = data_document(&second);
    assert_eq!(
        doc["records"][0]["monitor"],
        json!({
            "quiet":123,"wall":143,"event_size":0,"boot":300,"awake":142,
            "awaiting":null,"context":null,"budget":20,"last_growth":20,
            "state":"stalled","expiry":{"wall":21,"event_size":0,"last_growth":20,"quiet":1,"state":"growing"}
        })
    );
    assert_eq!(
        doc["records"][1],
        json!({
            "kind":"budget_state","budget":20,"wall":143,"state":"stalled",
            "quiet":123,"last_growth":20,"event_size":0
        })
    );
}

/// ´test:integration:bounded-wait-emits-state-only-and-keeps-offset´
#[test]
fn bounded_wait_emits_state_only_and_keeps_offset() {
    let directory = TestDir::new("state-only");
    directory.write(".feed-offset", b"0\n");
    let start = Instant::now();
    let output = run([directory.path().as_os_str(), OsStr::new("--wait=1")]);
    assert_success(&output);
    assert!((1..=3).contains(&start.elapsed().as_secs()));
    let parsed = data_document(&output);
    let records = parsed["records"].as_array().expect("records array");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "state");
    assert_eq!(records[0]["offset"], 0);
    assert_eq!(directory.read(".feed-offset"), b"0\n");
}

/// ´test:integration:wait-usage-errors-keep-the-failure-envelope´
#[test]
fn wait_usage_errors_keep_the_failure_envelope() {
    let directory = TestDir::new("wait-usage");
    for value in ["--wait=-1", "--wait=bad", "--wait="] {
        let output = run([directory.path().as_os_str(), OsStr::new(value)]);
        assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
    }
    let output = run([directory.path().as_os_str(), OsStr::new("--wait")]);
    assert_failure(&output, 2, "usage_error", USAGE_DIAGNOSTIC, "usage_error");
}

/// ´test:integration:retired-mail-sidecars-do-not-enter-follow-output´
#[test]
fn retired_mail_sidecars_do_not_enter_follow_output() {
    let directory = TestDir::new("retired-sidecars");
    directory.write("plan.json", b"{");
    directory.write("letters.jsonl", b"malformed legacy metadata");
    directory.write("events.jsonl", b"{\"event\":1}\n");
    directory.write("run-report.txt", b"DONE\n");
    let output = run([directory.path().as_os_str()]);
    assert!(output.status.success());
    let capture = data_document(&output);
    let records = capture["records"].as_array().expect("records");
    assert!(records.iter().any(|record| record["kind"] == "delta"));
    assert!(records.iter().any(|record| record["kind"] == "finished"));
    assert!(records.iter().all(|record| record["kind"] != "letter"));
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:inaccessible-round-is-a-named-runtime-refusal-not-usage´
#[test]
fn inaccessible_round_is_a_named_runtime_refusal_not_usage() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = TestDir::new("inaccessible-round");
    let run_dir = directory.path().join("run");
    let round = run_dir.join("round");
    std::fs::create_dir_all(&round).expect("round");
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o000))
        .expect("deny search");
    let denied = std::fs::metadata(&round).expect_err("fixture requires an unprivileged identity");
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    let output = run([round.as_os_str(), OsStr::new("--wait=1")]);
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore cleanup");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(!stderr.contains("usage_error"), "{stderr}");
    let document: Value = serde_json::from_slice(&output.stdout).expect("failure capture");
    assert!(!document.to_string().contains("usage_error"));
}

/// ´test:integration:bare-follow-preserves-offset-bytes-and-metadata´
#[test]
fn bare_follow_preserves_offset_bytes_and_metadata() {
    use std::os::unix::fs::MetadataExt as _;
    for saved in [false, true] {
        let directory = TestDir::new("bare-follow");
        directory.write("events.jsonl", b"first\nsecond\n");
        directory.write("letters.jsonl", b"{\"kind\":\"file\",\"identity\":[\"inbox\",\"dispatch.md\",1,\"2026-01-01T00:00:00Z\"]}\n");
        if saved {
            directory.write(".letter-count", b"1\n");
            directory.write(".letter-delivered.json", b"[]\n");
            directory.write(".letter-pending.json", b"[]\n");
            directory.write(
                ".announced-replies.json",
                b"{\"schema\":1,\"replies\":[]}\n",
            );
        }
        let delivery = || {
            [
                ".letter-count",
                ".letter-delivered.json",
                ".letter-pending.json",
                ".budget-notice",
                ".announced-replies.json",
            ]
            .map(|name| {
                let path = directory.path().join(name);
                std::fs::metadata(&path).ok().map(|m| {
                    (
                        std::fs::read(path).expect("position bytes"),
                        m.ino(),
                        m.mode(),
                        m.mtime(),
                        m.mtime_nsec(),
                        m.ctime(),
                        m.ctime_nsec(),
                    )
                })
            })
        };
        let prior_delivery = delivery();
        let offset = directory.path().join(".feed-offset");
        if saved {
            directory.write(".feed-offset", b"6\n");
        }
        let before = std::fs::metadata(&offset).ok().map(|m| {
            (
                m.ino(),
                m.mode(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        });
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .args(["driver", "follow", "--bounce", "0", "--wait", "1"])
            .arg(directory.path())
            .output()
            .expect("bare follow");
        assert!(
            output.status.success(),
            "status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("capture");
        assert!(
            value["records"]
                .as_array()
                .expect("records")
                .iter()
                .any(|r| r["kind"] == "delta")
        );
        let after = std::fs::metadata(&offset).ok().map(|m| {
            (
                m.ino(),
                m.mode(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        });
        assert_eq!(before, after);
        assert_eq!(prior_delivery, delivery());
        if saved {
            assert_eq!(std::fs::read(&offset).expect("offset"), b"6\n");
        } else {
            assert!(!offset.exists());
        }
    }
}

/// ´test:integration:saving-follow-advances-only-event-cursor´
#[test]
fn saving_follow_advances_only_event_cursor() {
    let directory = TestDir::new("saving-follow");
    directory.write("events.jsonl", b"first\nsecond\n");
    let names = || {
        let mut names: Vec<_> = std::fs::read_dir(directory.path())
            .expect("directory")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort();
        names
    };
    let before = names();
    let output = run([
        directory.path().as_os_str(),
        OsStr::new("--bounce=0"),
        OsStr::new("--wait=1"),
    ]);
    assert!(
        output.status.success(),
        "status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(directory.read(".feed-offset"), b"13\n");
    let mut expected = before;
    expected.push(OsString::from(".feed-offset"));
    expected.sort();
    assert_eq!(names(), expected);
    directory.write("events.jsonl", b"first\nsecond\nthird\n");
    let second = run([
        directory.path().as_os_str(),
        OsStr::new("--bounce=0"),
        OsStr::new("--wait=1"),
    ]);
    assert_success(&second);
    let published = data_document(&second);
    assert_eq!(published["records"][0]["offset"], 13);
    assert_eq!(published["records"][1]["events"], json!([{"raw":"third"}]));
    assert_eq!(published["records"][1]["bytes"], 6);
    assert_eq!(directory.read(".feed-offset"), b"19\n");
    assert_eq!(names(), expected);
}
