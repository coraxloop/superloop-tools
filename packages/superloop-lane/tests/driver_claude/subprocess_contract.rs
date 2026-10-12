//! End-to-end contract tests use only an injected Claude executable and synthetic clocks.

mod support;

/// A suspended resumed step keeps its thread, step identity and saved duty.
/// # Panics
/// Panics only if fixture setup fails or the production resume loses its duty.
/// ´claim:claudelane:claude-recovers-a-suspended-resumed-step-with-its-saved-brief´
/// ´test:integration:claude-recovers-a-suspended-resumed-step-with-its-saved-brief´
#[test]
fn claude_recovers_a_suspended_resumed_step_with_its_saved_brief() {
    let harness = Harness::new("suspend-resume");
    let run_dir = harness.seed_resume("lane", "session-1");
    let clock = harness.home().join("clock");
    fs::write(&clock, "0:0").expect("paired clock");
    let result = harness
        .command()
        .env("CODEX_LANE_TEST_CLOCK", format!("@{}", clock.display()))
        .env("ORACLE_MODE", "suspend-resume")
        .args([
            OsStr::new("-t60"),
            OsStr::new("-r"),
            OsStr::new("session-1"),
            OsStr::new("-d"),
            run_dir.as_os_str(),
            OsStr::new("-nwork"),
            OsStr::new("saved resumed duty"),
        ])
        .output_serialized()
        .expect("production driver");
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("suspend_resumes=1"));
    assert_eq!(
        harness.read("stdin"),
        fs::read(run_dir.join("step-work.txt")).expect("saved brief")
    );
    assert!(String::from_utf8_lossy(&harness.read("argv")).contains("--resume\nsession-1\n"));
    assert_eq!(
        fs::read_to_string(run_dir.join(".step-name"))
            .expect("step")
            .trim(),
        "work"
    );
    assert!(!run_dir.join("steps/work").exists());
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("result"),
        b"recovered"
    );
}

use support::SerializedCommand as _;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use support::{Harness, argument};

const USAGE_DIAGNOSTIC: &[u8] = b"claude-lane: usage_error: invalid command-line arguments\n";

/// Missing executable settings refuse before any run directory is allocated.
/// ´claim:claudelane:configured-selectors-refuse-before-allocation´
/// ´test:integration:configured-selectors-refuse-before-allocation´
#[test]
fn configured_selectors_refuse_before_allocation() {
    for (variable, setting) in [
        ("LANE_DRIVER_ARGV", "driver_argv"),
        ("LANE_BACKEND_ARGV", "backend_argv"),
    ] {
        let harness = Harness::new(variable);
        let mut command = harness.command();
        command.env_remove(variable);
        let result = output(
            &mut command,
            &[
                OsStr::new("-t60"),
                OsStr::new("-nmissing"),
                OsStr::new("hello"),
            ],
        );
        assert_eq!(result.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(setting),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!harness.run_dir("missing").exists());
        assert_eq!(harness.read("argv"), b"");
    }
}

/// The evidence a step leaves when an earlier step's text is not published as
/// its own.
const WITHHELD_DIAGNOSTIC: &[u8] = b"claude-lane: step_message_withheld: the step's own transcript region carries no message; an earlier step's text is not this step's answer\n";

/// The pool state one lane home carries between dispatches.
const POOL_FILE: &str = "lane-pool.json";

/// The reset epoch the committed stub emits unless a case chooses its own.
const STUB_RESET_EPOCH: u64 = 1_789_820_400;

const INIT_EVENT: &str = r#"{"type":"system","subtype":"init","session_id":"session-1"}"#;
const ASSISTANT_EVENT: &str =
    r#"{"type":"assistant","message":{"content":[{"type":"text","text":"interim"}]}}"#;
const RESULT_EVENT: &str = r#"{"type":"result","subtype":"success","is_error":false,"duration_ms":12345,"result":"finished text"}"#;
const ERRORED_RESULT_EVENT: &str = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"duration_ms":12345,"result":"stopped text"}"#;
const UNTIMED_RESULT_EVENT: &str =
    r#"{"type":"result","subtype":"success","is_error":false,"result":"untimed text"}"#;

/// One event stream, every line complete.
fn transcript(lines: &[&str]) -> String {
    format!("{}\n", lines.join("\n"))
}

/// A transcript a driver was killed over: the child's terminal result landed.
fn finished_events() -> String {
    transcript(&[INIT_EVENT, ASSISTANT_EVENT, RESULT_EVENT])
}

/// The same transcript whose terminal result reports a failed turn.
fn errored_events() -> String {
    transcript(&[INIT_EVENT, ASSISTANT_EVENT, ERRORED_RESULT_EVENT])
}

/// A transcript whose last complete line is not a terminal result.
fn unfinished_events() -> String {
    transcript(&[INIT_EVENT, RESULT_EVENT, ASSISTANT_EVENT])
}

/// A finished transcript whose terminal result measures nothing.
fn untimed_events() -> String {
    transcript(&[INIT_EVENT, ASSISTANT_EVENT, UNTIMED_RESULT_EVENT])
}

/// Seconds since the epoch on the same clock the driver reads.
fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

fn read_started_at(path: &Path, earliest: u64, latest: u64) -> String {
    let stamp = fs::read_to_string(path).expect("read step start");
    let bytes = stamp.as_bytes();
    assert_eq!(bytes.len(), 21, "one UTC second and LF");
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            4 | 7 => assert_eq!(*byte, b'-'),
            10 => assert_eq!(*byte, b'T'),
            13 | 16 => assert_eq!(*byte, b':'),
            19 => assert_eq!(*byte, b'Z'),
            20 => assert_eq!(*byte, b'\n'),
            _ => assert!(byte.is_ascii_digit()),
        }
    }
    let field = |start, end| {
        std::str::from_utf8(&bytes[start..end])
            .expect("ASCII digits")
            .parse::<u64>()
            .expect("decimal UTC field")
    };
    let (year, month, day) = (field(0, 4), field(5, 7), field(8, 10));
    let (hour, minute, second) = (field(11, 13), field(14, 16), field(17, 19));
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    assert!(year >= 1970 && (1..=12).contains(&month));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_index = usize::try_from(month - 1).expect("valid month index");
    assert!((1..=months[month_index]).contains(&day));
    assert!(hour < 24 && minute < 60 && second < 60);
    let days: u64 = (1970..year).map(|year| 365 + u64::from(leap(year))).sum();
    let days = days + months.iter().take(month_index).sum::<u64>() + day - 1;
    let epoch = ((days * 24 + hour) * 60 + minute) * 60 + second;
    assert!(
        (earliest..=latest).contains(&epoch),
        "start lies within the launch"
    );
    stamp
}

/// A fresh Claude step records its UTC start.
/// ´claim:driver:claude-fresh-step-records-utc-start´
/// ´test:integration:claude-fresh-step-records-utc-start´
#[test]
fn claude_fresh_step_records_utc_start() {
    let harness = Harness::new("fresh-start");
    let before = now_epoch();
    let result = harness.run(&[OsStr::new("-t60"), OsStr::new("hello")]);
    let after = now_epoch();

    assert_eq!(result.status.code(), Some(0));
    read_started_at(&harness.run_dir("lane").join(".started-at"), before, after);
}

/// A fresh Claude run records the session id carried by its init event.
/// ´claim:driver:a-fresh-claude-run-records-its-thread-id´
/// ´test:integration:a-fresh-claude-run-records-its-thread-id´
#[test]
fn a_fresh_claude_run_records_its_thread_id() {
    let harness = Harness::new("fresh-thread-id");
    let result = harness.run(&[OsStr::new("-t60"), OsStr::new("hello")]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(harness.run_dir("lane").join("thread-id.txt")).expect("read run thread id"),
        b"22222222-2222-4222-8222-222222222222\n"
    );
}

/// ´claim:driver:claude-fresh-launch-uses-lane-runs-root-and-reports-its-directory´
/// ´test:integration:claude-fresh-launch-uses-lane-runs-root-and-reports-its-directory´
#[test]
fn claude_fresh_launch_uses_lane_runs_root_and_reports_its_directory() {
    let harness = Harness::new("runs-root");
    let root = harness.worktree().join("selected-runs");
    harness.register_runs(&root);
    let run_dir = root.join("20260912T120000Z-selected");
    let mut command = harness.command();
    command.env("LANE_RUNS_ROOT", &root);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nselected"),
            OsStr::new("hello"),
        ],
    );
    assert_eq!(result.status.code(), Some(0));
    assert!(run_dir.is_dir());
    assert!(
        String::from_utf8_lossy(&result.stdout)
            .contains(&format!(" dir={} backend_program=", run_dir.display()))
    );
}

/// ´claim:driver:copied-claude-driver-keeps-configured-root-and-selected-run-separate´
/// ´test:integration:copied-claude-driver-keeps-configured-root-and-selected-run-separate´
#[test]
fn copied_claude_driver_keeps_configured_root_and_selected_run_separate() {
    let harness = Harness::new("copied-runs-root");
    let installed = harness.worktree().join("relocated/bin");
    fs::create_dir_all(&installed).expect("relocated directory");
    let driver = installed.join("claude-lane");
    support::write_executable(
        &driver,
        &fs::read(env!("CARGO_BIN_EXE_superloop-lane")).expect("driver bytes"),
        0o755,
    )
    .expect("copied driver");
    let root = harness.worktree().join("configured-runs");
    let selected = root.join("R");
    fs::create_dir_all(&selected).expect("selected run");
    fs::remove_file(harness.home().join(".config/loops/registry.toml"))
        .expect("boxed form reads no registry");
    let mut command = harness.command_at(&driver);
    command
        .env("LANE_RUNS_ROOT", &root)
        .env("LANE_RUN_DIR", &selected);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nselected"),
            OsStr::new("hello"),
        ],
    );
    let step = selected.join("20260912T120000Z-selected");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        fs::read(step.join("run-report.txt")).expect("report"),
        result.stdout
    );
    assert!(!installed.join("runs").exists());
    assert!(
        !installed
            .parent()
            .expect("relocated parent")
            .join("runs")
            .exists()
    );
    assert!(
        !harness
            .worktree()
            .parent()
            .expect("repo")
            .join("runs")
            .exists()
    );
    let refused = selected.join("must-not-exist");
    let mut command = harness.command_at(&driver);
    command
        .env_remove("LANE_RUNS_ROOT")
        .env("LANE_RUN_DIR", &selected);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-d"),
            refused.as_os_str(),
            OsStr::new("hello"),
        ],
    );
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("runs_root_required"));
    assert!(!refused.exists());
}

/// ´claim:driver:claude-fresh-launch-refuses-missing-or-relative-runs-root-before-allocation´
/// ´test:integration:claude-fresh-launch-refuses-missing-or-relative-runs-root-before-allocation´
#[test]
fn claude_fresh_launch_refuses_missing_or_relative_runs_root_before_allocation() {
    for (index, invalid) in [None, Some(""), Some("relative")].into_iter().enumerate() {
        let harness = Harness::new(&format!("runs-root-refusal-{index}"));
        let mut command = harness.command();
        if let Some(invalid) = invalid {
            command.env("LANE_RUNS_ROOT", invalid);
        } else {
            command.env_remove("LANE_RUNS_ROOT");
        }
        let result = output(&mut command, &[OsStr::new("-t60"), OsStr::new("hello")]);
        assert_eq!(result.status.code(), Some(2));
        assert_eq!(
            result.stderr,
            b"claude-lane: runs_root_required: LANE_RUNS_ROOT must be an absolute path\n"
        );
        assert_eq!(
            result.stdout,
            b"RUN-REPORT lane=unknown exit=2 wall=0s budget=60s verdict=FAILED dir=unknown\n",
        );
        assert!(
            !harness
                .worktree()
                .parent()
                .expect("repo")
                .join("runs")
                .exists()
        );
        assert!(
            !harness
                .worktree()
                .parent()
                .expect("repo")
                .join("relative")
                .exists()
        );
        assert!(
            !harness
                .home()
                .parent()
                .expect("harness root")
                .join("argv")
                .exists()
        );
    }
}

/// Two fresh launches under the pinned UTC stamp own separate evidence.
/// ´claim:driver:two-claude-fresh-launches-in-one-second-own-separate-runs´
/// ´test:integration:two-claude-fresh-launches-in-one-second-own-separate-runs´
#[test]
fn two_claude_fresh_launches_in_one_second_own_separate_runs() {
    let harness = Harness::new("collision");
    let first_dir = harness.run_dir("lane");
    let second_dir = first_dir.with_file_name("20260912T120000Z-lane-2");
    let first = harness.run(&[OsStr::new("-t60"), OsStr::new("first")]);
    assert_eq!(first.status.code(), Some(0));
    assert!(first_dir.is_dir());
    assert!(
        String::from_utf8_lossy(&first.stdout)
            .contains(&format!(" dir={} backend_program=", first_dir.display()))
    );
    let prior = fs::read(first_dir.join("brief.txt")).expect("read first brief");
    assert_eq!(prior, b"first\n");
    let second = harness.run(&[OsStr::new("-t60"), OsStr::new("second")]);
    assert_eq!(second.status.code(), Some(0));
    assert!(second_dir.is_dir());
    assert!(
        String::from_utf8_lossy(&second.stdout)
            .contains(&format!(" dir={} backend_program=", second_dir.display()))
    );
    assert_eq!(
        fs::read(first_dir.join("brief.txt")).expect("reread first brief"),
        prior
    );
    assert_eq!(
        fs::read(second_dir.join("brief.txt")).expect("read second brief"),
        b"second\n"
    );
}

fn output(command: &mut Command, arguments: &[&OsStr]) -> Output {
    command
        .args(arguments)
        .output_serialized()
        .expect("claude-lane subprocess runs")
}

fn argv(harness: &Harness) -> String {
    String::from_utf8(harness.read("argv")).expect("UTF-8 argv")
}

/// Whether one byte string occurs in another.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn assert_report(result: &Output, lane: &str, budget: u64, verdict: &str) {
    let report_bytes = result
        .stdout
        .strip_suffix(b"\n")
        .expect("report ends in LF");
    assert!(!report_bytes.contains(&b'\n'));
    let report = String::from_utf8(result.stdout.clone()).expect("UTF-8 report");
    assert!(report.starts_with(&format!(
        "RUN-REPORT lane={lane} exit={} wall=",
        result.status.code().expect("direct status")
    )));
    assert!(report.contains(&format!("s budget={budget}s verdict={verdict} dir=")));
}

/// The usage error diagnostic uses the Claude lane prefix.
/// ´claim:claudelane:usage-diagnostics-name-the-claude-lane-binary´
/// ´test:integration:usage-error-diagnostic-uses-claude-lane-prefix´
#[test]
fn usage_error_diagnostic_uses_claude_lane_prefix() {
    let harness = Harness::new("usage-prefix");
    let result = harness.run(&[OsStr::new("-t0"), OsStr::new("prompt")]);

    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.starts_with(USAGE_DIAGNOSTIC));
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
}

/// Fresh workspace write has exact arguments and result.
/// ´claim:claudelane:a-fresh-step-streams-durable-input-and-recovers-the-terminal-result´
/// ´test:integration:fresh-workspace-write-has-exact-argv-and-result´
#[test]
fn fresh_workspace_write_has_exact_argv_and_result() {
    let harness = Harness::new("fresh");
    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-C"),
        argument(harness.worktree()),
        OsStr::new("-sworkspace-write"),
        OsStr::new("-mmodel-x"),
        OsStr::new("-ehigh"),
        OsStr::new("-nnormal"),
        OsStr::new("hello"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "normal", 60, "ok");
    assert_eq!(harness.read("stdin"), b"hello\n");
    assert_eq!(
        harness.read("cwd"),
        format!("{}\n", harness.worktree().display()).as_bytes()
    );
    assert_eq!(
        argv(&harness),
        "-p\n--output-format\nstream-json\n--verbose\n--permission-mode\nacceptEdits\n--model\nmodel-x\n--effort\nhigh\n"
    );
    assert_eq!(
        fs::read(harness.run_dir("normal").join("last-message.txt"))
            .expect("read recovered result"),
        b"final text"
    );
}

/// An empty result recovers assistant text.
/// ´claim:claudelane:an-empty-result-falls-back-to-the-last-assistant-text-block´
/// ´test:integration:empty-result-recovers-assistant-text´
#[test]
fn empty_result_recovers_assistant_text() {
    let harness = Harness::new("fallback");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "fallback");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nfallback"),
            OsStr::new("prompt"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(harness.run_dir("fallback").join("last-message.txt"))
            .expect("read recovered assistant text"),
        b"kept answer"
    );
}

/// A host suspend leaves the child alive and names its gap.
/// ´claim:claudelane:a-host-suspend-leaves-the-child-alive-and-is-recorded-beside-the-verdict´
/// ´test:integration:a-host-suspend-leaves-the-child-alive-and-names-its-gap´
#[test]
fn a_host_suspend_leaves_the_child_alive_and_names_its_gap() {
    let harness = Harness::new("suspend-continues");
    let run_dir = harness.run_dir("slept");
    let mut command = harness.command();
    // One awake second on either side of a sleep longer than both the stall
    // window and the budget, moved under a child that is still running.
    command
        .env("ORACLE_MODE", "slow")
        .env("CODEX_LANE_TEST_CLOCK", "0:0,1:901,2:902");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nslept"),
            OsStr::new("prompt"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    let evidence: serde_json::Value = serde_json::from_slice(
        &fs::read(run_dir.join("backend-settings.json")).expect("settings evidence"),
    )
    .expect("JSON evidence");
    let report = String::from_utf8_lossy(&result.stdout);
    let expected = format!(
        "RUN-REPORT lane=slept exit=0 wall=2s budget=60s verdict=ok suspend_gap=900s dir={} backend_program={} settings={} settings_sha256={}\n",
        run_dir.display(),
        evidence["program"].as_str().expect("program"),
        evidence["settings"]["path"].as_str().expect("path"),
        report
            .split(" settings_sha256=")
            .nth(1)
            .expect("settings digest")
            .trim()
    );
    assert_eq!(
        String::from_utf8(result.stdout.clone()).expect("UTF-8 report"),
        expected
    );
    assert_eq!(
        fs::read(run_dir.join("run-report.txt")).expect("read the published report"),
        expected.as_bytes()
    );
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert!(
        !run_dir.join("kill-evidence.txt").exists(),
        "a host sleep is not a kill"
    );
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read the step's own message"),
        b"final text"
    );
}

/// A silent resume step publishes no message of its own.
/// ´claim:claudelane:a-step-whose-own-region-carries-no-message-publishes-none´
/// ´test:integration:a-silent-resume-step-publishes-no-message-of-its-own´
#[test]
fn a_silent_resume_step_publishes_no_message_of_its_own() {
    let harness = Harness::new("silent-resume");
    let run_dir = harness.seed_resume("run", "session-1");
    fs::write(run_dir.join("events.jsonl"), finished_events())
        .expect("seed a prior step that ended in a result with text");

    let mut command = harness.command();
    command.env("ORACLE_MODE", "silent");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "work", 60, "ok");
    assert!(
        !run_dir.join("last-message.txt").exists(),
        "a step whose own region carries no message publishes none"
    );
    assert_eq!(result.stderr, WITHHELD_DIAGNOSTIC);
    assert_eq!(
        fs::read(run_dir.join("steps/gate/last-message.txt")).expect("read archived message"),
        b"first"
    );
}

/// A failed message write names its path and error.
/// ´claim:claudelane:a-message-the-step-produced-but-could-not-write-is-a-fault´
/// ´test:integration:a-failed-message-write-names-its-path-and-error´
#[test]
fn a_failed_message_write_names_its_path_and_error() {
    let harness = Harness::new("unwritable-message");
    let run_dir = harness.seed_resume("run", "session-1");
    let blocked = run_dir.join("last-message.txt");

    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    command.env("ORACLE_BLOCK_PATH", &blocked);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "work", 60, "ok");
    assert!(
        blocked.is_dir(),
        "the child stood a directory where the message goes"
    );
    let evidence = String::from_utf8_lossy(&result.stderr).into_owned();
    assert!(
        result.stderr.starts_with(
            format!(
                "claude-lane: step_message_unwritten: the step's message could not be written to {}: ",
                blocked.display()
            )
            .as_bytes()
        ),
        "the fault names its class and its path: {evidence}"
    );
    assert!(
        result.stderr.ends_with(b" (os error 21)\n"),
        "the fault names the error the write returned: {evidence}"
    );
    assert!(
        !contains(&result.stderr, WITHHELD_DIAGNOSTIC),
        "a message the step produced was not withheld: {evidence}"
    );
}

/// A rejected dispatch reports rate limited with its reset time.
/// ´claim:claudelane:a-pool-rejection-in-the-steps-own-region-is-its-verdict´
/// ´test:integration:a-rejected-dispatch-reports-rate-limited-with-its-reset-time´
#[test]
fn a_rejected_dispatch_reports_rate_limited_with_its_reset_time() {
    let harness = Harness::new("rate-limited");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "rate-limited");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t1800"),
            OsStr::new("-nlimited"),
            OsStr::new("prompt"),
        ],
    );

    assert_eq!(result.status.code(), Some(1));
    assert_report(&result, "limited", 1800, "RATE-LIMITED");
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: rate_limited: the pool rejected the dispatch; five_hour resets at 2026-09-19T12:20:00Z ({STUB_RESET_EPOCH})\n"
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(harness.run_dir("limited").join("rate-limit.txt")).expect("read rate-limit evidence"),
        format!(
            "status=rejected type=five_hour utilization=1 resets_at={STUB_RESET_EPOCH} resets_at_iso=2026-09-19T12:20:00Z at=20260912T120000Z\n"
        )
        .as_bytes()
    );
    let pool = fs::read_to_string(harness.config().join(POOL_FILE)).expect("read pool state");
    assert!(pool.starts_with(&format!(
        r#"{{"status":"rejected","rate_limit_type":"five_hour","utilization":1,"resets_at":{STUB_RESET_EPOCH},"observed_at":"#
    )));
    assert!(pool.ends_with(&format!(
        "\"run_dir\":\"{}\"}}\n",
        harness.run_dir("limited").display()
    )));
}

/// A recorded warning refuses the next dispatch until the window resets.
/// ´claim:claudelane:the-pool-state-of-the-last-step-refuses-the-next-dispatch´
/// ´test:integration:a-recorded-warning-refuses-the-next-dispatch-until-the-window-resets´
#[test]
fn a_recorded_warning_refuses_the_next_dispatch_until_the_window_resets() {
    let harness = Harness::new("pool");
    let resets_at = now_epoch() + 3600;
    let mut warned = harness.command();
    warned
        .env("ORACLE_MODE", "warning")
        .env("ORACLE_RESETS_AT", resets_at.to_string());
    let first = output(
        &mut warned,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nwarned"),
            OsStr::new("prompt"),
        ],
    );

    assert_eq!(first.status.code(), Some(0));
    assert_report(&first, "warned", 60, "ok");
    let pool = fs::read_to_string(harness.config().join(POOL_FILE)).expect("read pool state");
    assert!(pool.contains(r#""status":"allowed_warning""#));
    assert!(pool.contains(r#""utilization":0.97"#));
    assert!(pool.contains(&format!(r#""resets_at":{resets_at}"#)));

    let spawned = harness.read("argv");
    let refused = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-nrefused"),
        OsStr::new("prompt"),
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        refused.stdout,
        b"RUN-REPORT lane=refused exit=2 wall=0s budget=60s verdict=FAILED dir=unknown\n"
            .as_slice()
    );
    let diagnostic = String::from_utf8(refused.stderr).expect("UTF-8 refusal");
    assert!(
        diagnostic.starts_with("claude-lane: dispatch_rate_limited: the pool read 0.97 at "),
        "refusal states the reading: {diagnostic}"
    );
    assert!(diagnostic.contains("; five_hour resets at "));
    assert!(diagnostic.ends_with(&format!(
        "({resets_at}); pass --ignore-pool to dispatch anyway\n"
    )));
    assert!(!harness.run_dir("refused").exists());
    assert_eq!(harness.read("argv"), spawned);

    let raised = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("--pool-threshold"),
        OsStr::new("0.98"),
        OsStr::new("-nraised"),
        OsStr::new("prompt"),
    ]);
    assert_eq!(raised.status.code(), Some(0));
    assert_report(&raised, "raised", 60, "ok");

    let ignored = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("--ignore-pool"),
        OsStr::new("-nignored"),
        OsStr::new("prompt"),
    ]);
    assert_eq!(ignored.status.code(), Some(0));
    assert_report(&ignored, "ignored", 60, "ok");
    assert_eq!(
        fs::read_to_string(harness.config().join(POOL_FILE)).expect("read unchanged pool state"),
        pool
    );
}

/// A reset window dispatches and rewrites the pool state.
/// ´claim:claudelane:a-window-that-has-already-reset-never-refuses-a-dispatch´
/// ´test:integration:a-reset-window-dispatches-and-rewrites-the-pool-state´
#[test]
fn a_reset_window_dispatches_and_rewrites_the_pool_state() {
    let harness = Harness::new("pool-stale");
    let now = now_epoch();
    fs::write(
        harness.config().join(POOL_FILE),
        format!(
            "{{\"status\":\"rejected\",\"rate_limit_type\":\"five_hour\",\"utilization\":1,\"resets_at\":{},\"observed_at\":{},\"run_dir\":\"prior\"}}\n",
            now - 60,
            now - 120
        ),
    )
    .expect("seed a pool state whose window has reset");

    let resets_at = now + 7200;
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "warning")
        .env("ORACLE_RESETS_AT", resets_at.to_string());
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nstale"),
            OsStr::new("prompt"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "stale", 60, "ok");
    let pool = fs::read_to_string(harness.config().join(POOL_FILE)).expect("read rewritten state");
    assert!(pool.contains(&format!(r#""resets_at":{resets_at}"#)));
    assert!(pool.contains(r#""status":"allowed_warning""#));
}

/// A refused resume names its run directory.
/// ´claim:claudelane:a-refused-resume-reports-the-directory-it-would-have-continued´
/// ´test:integration:a-refused-resume-names-its-run-directory´
#[test]
fn a_refused_resume_names_its_run_directory() {
    let harness = Harness::new("pool-resume");
    let run_dir = harness.seed_resume("run", "session-1");
    let now = now_epoch();
    fs::write(
        harness.config().join(POOL_FILE),
        format!(
            "{{\"status\":\"rejected\",\"rate_limit_type\":\"five_hour\",\"utilization\":1,\"resets_at\":{},\"observed_at\":{now},\"run_dir\":\"prior\"}}\n",
            now + 3600
        ),
    )
    .expect("seed a pool state whose window still refuses");

    let refused = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        refused.stdout,
        format!(
            "RUN-REPORT lane=work exit=2 wall=0s budget=60s verdict=FAILED dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert!(
        String::from_utf8(refused.stderr)
            .expect("UTF-8 refusal")
            .starts_with("claude-lane: dispatch_rate_limited: the pool read 1 at ")
    );
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
    assert!(!run_dir.join("step-work.txt").exists());
}

/// A prior step rejection leaves a natural failure failed.
/// ´claim:claudelane:a-rejection-before-the-steps-own-start-is-not-its-verdict´
/// ´test:integration:a-prior-steps-rejection-leaves-a-natural-failure-failed´
#[test]
fn a_prior_steps_rejection_leaves_a_natural_failure_failed() {
    let harness = Harness::new("rate-limited-prior");
    let run_dir = harness.seed_resume("run", "session-1");
    let mut events = fs::read(run_dir.join("events.jsonl")).expect("read seeded events");
    events.extend_from_slice(
        br#"{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1789820400,"rateLimitType":"five_hour"},"session_id":"session-1"}
"#,
    );
    fs::write(run_dir.join("events.jsonl"), &events).expect("seed a prior step's rejection");

    let mut command = harness.command();
    command.env("ORACLE_MODE", "failing");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(1));
    assert_report(&result, "work", 60, "FAILED");
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert!(!run_dir.join("rate-limit.txt").exists());
    assert!(!harness.config().join(POOL_FILE).exists());
}

/// Resume has exact arguments and refuses a thread mismatch.
/// ´claim:claudelane:resume-validates-the-first-init-session-before-spawning´
/// ´test:integration:resume-has-exact-argv-and-refuses-thread-mismatch´
#[test]
fn resume_has_exact_argv_and_refuses_thread_mismatch() {
    let harness = Harness::new("resume");
    let run_dir = harness.seed_resume("run", "session-1");
    fs::write(run_dir.join(".started-at"), b"2026-09-24T21:35:27Z\n")
        .expect("seed prior step start");
    let prior_start = fs::read_to_string(run_dir.join(".started-at")).expect("read prior start");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    let before = now_epoch();
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );
    let after = now_epoch();

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        argv(&harness),
        "-p\n--output-format\nstream-json\n--verbose\n--permission-mode\nacceptEdits\n--resume\nsession-1\n"
    );
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read resume result"),
        b"resumed text"
    );
    assert_eq!(
        fs::read_to_string(run_dir.join("steps/gate/started-at.txt")).expect("read archived start"),
        prior_start
    );
    let new_start = read_started_at(&run_dir.join(".started-at"), before, after);
    assert!(new_start >= prior_start);

    let mismatch = Harness::new("mismatch");
    let mismatch_dir = mismatch.seed_resume("run", "session-1");
    let refused = mismatch.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rwrong-session"),
        OsStr::new("-d"),
        argument(&mismatch_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8(refused.stderr)
            .expect("UTF-8 refusal")
            .contains("resume_thread_mismatch")
    );
    assert_eq!(mismatch.read("argv"), Vec::<u8>::new());
}

/// A Claude resume records the matched event id when the run has no id file.
/// ´claim:driver:a-claude-resume-fills-a-missing-thread-id´
/// ´test:integration:a-claude-resume-fills-a-missing-thread-id´
#[test]
fn a_claude_resume_fills_a_missing_thread_id() {
    let harness = Harness::new("resume-missing-thread-id");
    let run_dir = harness.seed_resume("run", "session-1");
    assert!(!run_dir.join("thread-id.txt").exists());
    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");

    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("thread-id.txt")).expect("read run thread id"),
        b"session-1\n"
    );
    assert!(!run_dir.join("steps/gate/thread-id.txt").exists());
}

/// A Claude resume proceeds when the thread-id path cannot be written, rather than refusing as a mismatch.
/// ´claim:driver:a-claude-resume-tolerates-an-unwritable-thread-id-path´
/// ´test:integration:a-claude-resume-tolerates-an-unwritable-thread-id-path´
#[test]
fn a_claude_resume_tolerates_an_unwritable_thread_id_path() {
    let harness = Harness::new("resume-unwritable-thread-id");
    let run_dir = harness.seed_resume("run", "session-1");
    let thread_path = run_dir.join("thread-id.txt");
    fs::create_dir(&thread_path).expect("occupy thread-id path with a directory");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");

    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "work", 60, "ok");
    assert_eq!(
        fs::read(run_dir.join("run-report.txt")).expect("read settled report"),
        result.stdout
    );
    assert!(thread_path.is_dir());
}

/// A Claude resume refuses an id file that disagrees with its matched events.
/// ´claim:driver:a-claude-resume-refuses-a-conflicting-thread-id-file´
/// ´test:integration:a-claude-resume-refuses-a-conflicting-thread-id-file´
#[test]
fn a_claude_resume_refuses_a_conflicting_thread_id_file() {
    let harness = Harness::new("conflicting-thread-id");
    let run_dir = harness.seed_resume("run", "session-1");
    let thread_path = run_dir.join("thread-id.txt");
    fs::write(&thread_path, b"other-session\n").expect("seed conflicting thread id");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_thread_mismatch: first thread id does not match resume session: {}\n",
            thread_path.display()
        )
        .as_bytes()
    );
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
    assert_eq!(
        fs::read(&thread_path).expect("read unchanged thread id"),
        b"other-session\n"
    );
}

/// The missing report resume refusal uses the Claude lane prefix.
/// ´claim:claudelane:resume-refusal-diagnostics-name-the-claude-lane-binary´
/// ´test:integration:missing-report-resume-refusal-uses-claude-lane-prefix´
#[test]
fn missing_report_resume_refusal_uses_claude_lane_prefix() {
    let harness = Harness::new("missing-report-prefix");
    let run_dir = harness.seed_resume("run", "session-1");
    let report = run_dir.join("run-report.txt");
    fs::remove_file(&report).expect("remove prior report");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_missing_report: prior step report is missing: {}\n",
            report.display()
        )
        .as_bytes()
    );
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
}

/// The crash recovery diagnostic uses the Claude lane prefix.
/// ´claim:claudelane:crash-recovery-diagnostics-name-the-claude-lane-binary´
/// ´test:integration:crash-recovery-diagnostic-uses-claude-lane-prefix´
#[test]
fn crash_recovery_diagnostic_uses_claude_lane_prefix() {
    let harness = Harness::new("crash-prefix");
    let run_dir = harness.seed_resume("run", "session-1");
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    assert!(!Path::new("/proc").join(dead_pid.to_string()).exists());
    fs::remove_file(run_dir.join("run-report.txt")).expect("remove interrupted report");
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_crash_recovered: wrote a CRASHED report for dead holder pid {dead_pid} and cleared lock: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(!lock.exists());
}

/// An interrupted finish is reconstructed at the next resume.
/// ´claim:claudelane:a-finished-step-whose-driver-died-is-reconstructed-from-its-terminal-result´
/// ´test:integration:an-interrupted-finish-is-reconstructed-at-the-next-resume´
#[test]
fn an_interrupted_finish_is_reconstructed_at_the_next_resume() {
    let harness = Harness::new("reconstruct");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &finished_events());
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    assert!(!Path::new("/proc").join(dead_pid.to_string()).exists());
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_finish_reconstructed: rebuilt the finished step report from the terminal result event for dead holder pid {dead_pid} and cleared lock: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(!lock.exists());
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read reconstructed report"),
        format!(
            "RUN-REPORT lane=gate exit=0 wall=12s budget=0s verdict=ok dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/reconstructed.txt")).expect("read reconstruction record"),
        format!(
            "reason=DRIVER-EXIT derivation=duration_ms wall=12s exit=0 verdict=ok pid={dead_pid} at=20260912T120000Z\n"
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/last-message.txt")).expect("read recovered message"),
        b"finished text"
    );
    assert!(!run_dir.join(".reconstructed").exists());
}

/// An errored terminal result reconstructs as exit one.
/// ´claim:claudelane:an-errored-terminal-result-reconstructs-as-a-failed-step´
/// ´test:integration:an-errored-terminal-result-reconstructs-as-exit-one´
#[test]
fn an_errored_terminal_result_reconstructs_as_exit_one() {
    let harness = Harness::new("reconstruct-failed");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &errored_events());
    let dead_pid = u32::MAX;
    fs::write(run_dir.join(".claude-lane.lock"), format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read reconstructed report"),
        format!(
            "RUN-REPORT lane=gate exit=1 wall=12s budget=0s verdict=FAILED dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/reconstructed.txt")).expect("read reconstruction record"),
        format!(
            "reason=DRIVER-EXIT derivation=duration_ms wall=12s exit=1 verdict=FAILED pid={dead_pid} at=20260912T120000Z\n"
        )
        .as_bytes()
    );
}

/// A terminal result before the step start is not reconstructed.
/// ´claim:claudelane:a-terminal-result-before-the-steps-own-start-is-not-its-finish´
/// ´test:integration:a-terminal-result-before-the-step-start-is-not-reconstructed´
#[test]
fn a_terminal_result_before_the_step_start_is_not_reconstructed() {
    let harness = Harness::new("reconstruct-prior");
    let events = finished_events();
    let run_dir = harness.seed_interrupted_step("run", "session-1", &events);
    // Preparation archives the completed first step before the next starts.
    let prior = run_dir.join("steps/gate");
    fs::create_dir_all(&prior).expect("create prior step archive");
    fs::write(prior.join("event-start.txt"), b"0\n").expect("archive prior start");
    fs::write(prior.join("event-end.txt"), format!("{}\n", events.len()))
        .expect("archive prior end");
    fs::write(
        prior.join("run-report.txt"),
        format!(
            "RUN-REPORT lane=gate exit=0 wall=0s budget=60s verdict=ok dir={}\n",
            run_dir.display()
        ),
    )
    .expect("archive prior report");
    fs::write(run_dir.join(".step-name"), b"second\n").expect("seed the interrupted step name");
    fs::write(run_dir.join(".event-start"), format!("{}\n", events.len()))
        .expect("seed the step event start");
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_crash_recovered: wrote a CRASHED report for dead holder pid {dead_pid} and cleared lock: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/second/run-report.txt")).expect("read archived crash report"),
        format!(
            "RUN-REPORT lane=second exit=1 wall=0s budget=0s verdict=CRASHED-HOST-EXIT pid={dead_pid} dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert!(!run_dir.join("steps/second/last-message.txt").exists());
    assert!(!run_dir.join("steps/second/reconstructed.txt").exists());
    assert!(!run_dir.join(".reconstructed").exists());
}

/// A stale reconstruction record is cleared by a crash report.
/// ´claim:claudelane:a-crashed-step-carries-no-earlier-steps-reconstruction-record´
/// ´test:integration:a-stale-reconstruction-record-is-cleared-by-a-crash-report´
#[test]
fn a_stale_reconstruction_record_is_cleared_by_a_crash_report() {
    let harness = Harness::new("crash-stale-sidecar");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &unfinished_events());
    fs::write(
        run_dir.join(".reconstructed"),
        b"reason=DRIVER-EXIT derivation=duration_ms wall=12s exit=0 verdict=ok pid=4242 at=20260912T110000Z\n",
    )
    .expect("seed an earlier step's reconstruction record");
    let dead_pid = u32::MAX;
    assert!(!Path::new("/proc").join(dead_pid.to_string()).exists());
    fs::write(run_dir.join(".claude-lane.lock"), format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read archived crash report"),
        format!(
            "RUN-REPORT lane=gate exit=1 wall=0s budget=0s verdict=CRASHED-HOST-EXIT pid={dead_pid} dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert!(
        !run_dir.join("steps/gate/reconstructed.txt").exists(),
        "a crashed step files no reconstruction record"
    );
    assert!(!run_dir.join(".reconstructed").exists());
}

/// A settled report survives a dead lock.
/// ´claim:claudelane:a-report-a-step-already-published-is-kept-not-rewritten´
/// ´test:integration:a-settled-report-survives-a-dead-lock´
#[test]
fn a_settled_report_survives_a_dead_lock() {
    let harness = Harness::new("settled-report");
    let run_dir = harness.seed_resume("run", "session-1");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read settled report");
    let message = fs::read(run_dir.join("last-message.txt")).expect("read settled message");
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_settled_report_kept: kept the published report of dead holder pid {dead_pid} and cleared lock: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(!lock.exists());
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read archived report"),
        report
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/last-message.txt")).expect("read archived message"),
        message
    );
    assert!(!run_dir.join("steps/gate/reconstructed.txt").exists());
    assert!(!run_dir.join(".reconstructed").exists());
}

/// Everything a resume owes the prior step after a kill inside the window that
/// had already flipped the markers: one archive under the prior name, the
/// prior step's own region, and a new step that starts where the transcript
/// stood.
fn assert_preparation_rolled_back(
    run_dir: &Path,
    report: &[u8],
    transcript: u64,
    prior_start: Option<&[u8]>,
) {
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read the archived report"),
        report
    );
    assert!(
        !run_dir.join("steps/work").exists(),
        "a step that never started files no history"
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/last-message.txt")).expect("read the archived message"),
        b"first"
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/event-start.txt")).expect("read the archived start"),
        b"0\n",
        "the prior step keeps the region it ran in"
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/event-end.txt")).expect("read the archived end"),
        format!("{transcript}\n").as_bytes()
    );
    let archived_start = run_dir.join("steps/gate/started-at.txt");
    match prior_start {
        Some(start) => assert_eq!(
            fs::read(archived_start).expect("read restored prior start"),
            start
        ),
        None => assert!(!archived_start.exists()),
    }
    assert_eq!(
        fs::read(run_dir.join(".event-start")).expect("read the new step's start"),
        format!("{transcript}\n").as_bytes(),
        "the new step starts where the transcript stood"
    );
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read the new step's message"),
        b"resumed text"
    );
}

/// A kill inside the preparation window restores the prior step.
/// ´claim:claudelane:a-report-naming-another-step-never-settles-the-one-that-never-started´
/// ´test:integration:a-kill-inside-the-preparation-window-restores-the-prior-step´
#[test]
fn a_kill_inside_the_preparation_window_restores_the_prior_step() {
    let harness = Harness::new("preparation-window");
    let run_dir = harness.seed_preparation_window("run", "session-1", "work");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read the surviving report");
    let transcript = fs::metadata(run_dir.join("events.jsonl"))
        .expect("measure the transcript")
        .len();
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_preparation_rolled_back: step work never started, so gate was restored and the lock of dead holder pid {dead_pid} was cleared: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(!lock.exists());
    assert_report(&result, "work", 60, "ok");
    assert_preparation_rolled_back(
        &run_dir,
        &report,
        transcript,
        Some(b"2026-09-24T21:35:27Z\n"),
    );
}

/// A dead driver between the step-name and event-start writes restores the
/// earlier step before context reconciliation reads the boundary chain.
/// ´claim:driver:a-kill-between-marker-writes-restores-before-reconciliation´
/// ´test:integration:a-kill-between-marker-writes-restores-before-reconciliation´
#[test]
fn a_kill_between_marker_writes_restores_before_reconciliation() {
    let harness = Harness::new("preparation-between-markers");
    let run_dir = harness.seed_preparation_window("run", "session-1", "work");
    fs::write(run_dir.join(".event-start"), b"0\n").expect("leave prior start unflipped");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read surviving prior report");
    let transcript = fs::metadata(run_dir.join("events.jsonl"))
        .expect("measure prior transcript")
        .len();
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_preparation_rolled_back: step work never started, so gate was restored and the lock of dead holder pid {dead_pid} was cleared: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(!lock.exists());
    assert_report(&result, "work", 60, "ok");
    assert_preparation_rolled_back(
        &run_dir,
        &report,
        transcript,
        Some(b"2026-09-24T21:35:27Z\n"),
    );
    assert!(!run_dir.join(".reconstructed").exists());
}

/// An unfinished preparation without a lock restores the prior step.
/// ´claim:claudelane:a-preparation-that-released-its-lock-leaves-the-same-mismatch´
/// ´test:integration:an-unfinished-preparation-without-a-lock-restores-the-prior-step´
#[test]
fn an_unfinished_preparation_without_a_lock_restores_the_prior_step() {
    let harness = Harness::new("preparation-unlocked");
    let run_dir = harness.seed_preparation_window("run", "session-1", "work");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read the surviving report");
    let transcript = fs::metadata(run_dir.join("events.jsonl"))
        .expect("measure the transcript")
        .len();

    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_preparation_rolled_back: step work never started, so gate was restored: {}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert_report(&result, "work", 60, "ok");
    assert_preparation_rolled_back(
        &run_dir,
        &report,
        transcript,
        Some(b"2026-09-24T21:35:27Z\n"),
    );
}

/// A kill after sidecar removal keeps the prior step answer.
/// ´claim:claudelane:the-undo-restores-every-sidecar-the-preparation-had-already-removed´
/// ´test:integration:a-kill-after-the-sidecar-removal-keeps-the-prior-steps-answer´
#[test]
fn a_kill_after_the_sidecar_removal_keeps_the_prior_steps_answer() {
    let harness = Harness::new("preparation-removed");
    let run_dir = harness.seed_preparation_window_after_removal("run", "session-1", "work");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read the surviving report");
    let transcript = fs::metadata(run_dir.join("events.jsonl"))
        .expect("measure the transcript")
        .len();
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "work", 60, "ok");
    assert_preparation_rolled_back(
        &run_dir,
        &report,
        transcript,
        Some(b"2026-09-24T21:35:27Z\n"),
    );
    // The retried preparation archives what the undo put back, so the prior
    // step's own bytes are what stands in its history — not an absence, and
    // not anything this run wrote.
    for (file, bytes) in [
        ("feed-offset.txt", &b"4096\n"[..]),
        ("reconstructed.txt", b"reason=DRIVER-EXIT\n"),
        ("rate-limit.txt", b"status=rejected\n"),
    ] {
        assert_eq!(
            fs::read(run_dir.join("steps/gate").join(file)).unwrap_or_default(),
            bytes,
            "the prior step keeps {file} through the undo"
        );
    }
    assert!(
        !run_dir.join(".feed-offset").exists(),
        "the retried preparation moved the follower cursor into the history it belongs to"
    );
}

/// A Claude rollback removes a flipped start when the prior archive has none.
/// ´claim:driver:a-claude-rollback-removes-a-start-with-no-archived-marker´
/// ´test:integration:a-claude-rollback-removes-a-start-with-no-archived-marker´
#[test]
fn a_claude_rollback_removes_a_start_with_no_archived_marker() {
    let harness = Harness::new("preparation-no-prior-start");
    let run_dir = harness.seed_preparation_window("run", "session-1", "work");
    fs::remove_file(run_dir.join("steps/gate/started-at.txt"))
        .expect("remove the absent prior marker from the archive");
    fs::write(run_dir.join("thread-id.txt"), b"session-1\n").expect("seed run thread id");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read the surviving report");
    let transcript = fs::metadata(run_dir.join("events.jsonl"))
        .expect("measure the transcript")
        .len();
    let mut command = harness.command();
    command.env("ORACLE_MODE", "resume");
    let before = now_epoch();
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-rsession-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-nwork"),
            OsStr::new("PROCEED"),
        ],
    );
    let after = now_epoch();

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "work", 60, "ok");
    assert_preparation_rolled_back(&run_dir, &report, transcript, None);
    read_started_at(&run_dir.join(".started-at"), before, after);
    assert_eq!(
        fs::read(run_dir.join("thread-id.txt")).expect("read retained run thread id"),
        b"session-1\n"
    );
    assert!(!run_dir.join("steps/gate/thread-id.txt").exists());
}

/// An untimed terminal result reconstructs at wall zero.
/// ´claim:claudelane:a-terminal-result-that-measures-nothing-reconstructs-at-an-underived-wall´
/// ´test:integration:an-untimed-terminal-result-reconstructs-at-wall-zero´
#[test]
fn an_untimed_terminal_result_reconstructs_at_wall_zero() {
    let harness = Harness::new("reconstruct-untimed");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &untimed_events());
    let dead_pid = u32::MAX;
    fs::write(run_dir.join(".claude-lane.lock"), format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read reconstructed report"),
        format!(
            "RUN-REPORT lane=gate exit=0 wall=0s budget=0s verdict=ok dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/reconstructed.txt")).expect("read reconstruction record"),
        format!(
            "reason=DRIVER-EXIT derivation=unknown wall=0s exit=0 verdict=ok pid={dead_pid} at=20260912T120000Z\n"
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/last-message.txt")).expect("read recovered message"),
        b"untimed text"
    );
}

/// A live lock holder refuses resume without reconstructing.
/// ´claim:claudelane:a-live-lock-holder-keeps-its-step-running-and-unreconstructed´
/// ´test:integration:a-live-lock-holder-refuses-the-resume-without-reconstructing´
#[test]
fn a_live_lock_holder_refuses_the_resume_without_reconstructing() {
    let harness = Harness::new("reconstruct-live");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &finished_events());
    let lock = run_dir.join(".claude-lane.lock");
    let live_pid = std::process::id();
    fs::write(&lock, format!("{live_pid}\n")).expect("seed live lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_live_lock: holder pid {live_pid} is still live: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(lock.exists());
    assert!(!run_dir.join(".reconstructed").exists());
    assert!(!run_dir.join("run-report.txt").exists());
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
}

/// A trailing event without a result keeps the crashed report.
/// ´claim:claudelane:a-transcript-that-does-not-end-in-a-result-event-stays-a-crashed-step´
/// ´test:integration:a-trailing-non-result-event-keeps-the-crashed-report´
#[test]
fn a_trailing_non_result_event_keeps_the_crashed_report() {
    let harness = Harness::new("reconstruct-unfinished");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &unfinished_events());
    let lock = run_dir.join(".claude-lane.lock");
    let dead_pid = u32::MAX;
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_crash_recovered: wrote a CRASHED report for dead holder pid {dead_pid} and cleared lock: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read archived crash report"),
        format!(
            "RUN-REPORT lane=gate exit=1 wall=0s budget=0s verdict=CRASHED-HOST-EXIT pid={dead_pid} dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert!(!run_dir.join(".reconstructed").exists());
    assert!(!run_dir.join("steps/gate/reconstructed.txt").exists());
}

/// ´claim:driver:synthetic-clocks-publish-stall-and-runaway-without-killing´
/// ´test:integration:synthetic-clocks-publish-stall-and-runaway-without-killing´
#[test]
fn synthetic_clocks_publish_stall_and_runaway_without_killing() {
    for (label, budget, clock, state) in [
        ("stall", "10", "0,131", "stalled"),
        ("runaway", "1", "0,5", "runaway"),
    ] {
        let harness = Harness::new(label);
        let run_dir = harness.run_dir(label);
        let release = run_dir.parent().expect("runs root").join("release");
        let mut command = harness.command();
        command
            .env("ORACLE_MODE", "budget-wait")
            .env("ORACLE_RELEASE", &release)
            .env("CODEX_LANE_TEST_CLOCK", clock)
            .args([
                OsStr::new("-t"),
                OsStr::new(budget),
                OsStr::new("-n"),
                OsStr::new(label),
                OsStr::new("prompt"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut driver = command.spawn_serialized().expect("spawn driver");
        let sidecar = await_monitor(&run_dir, &format!(" state={state} "));
        let wall = if state == "stalled" { 131 } else { 5 };
        assert_monitor_line(
            &sidecar,
            &format!("quiet={wall}s wall={wall}s event_size=0 boot={wall}s awake={wall}s"),
            &format!(
                " budget={budget}s last_growth=0s state={state} expired_wall={wall}s expired_event_size=0 expired_last_growth=0s expired_quiet={wall}s expired_state={state}"
            ),
        );
        assert!(driver.try_wait().expect("live driver").is_none());
        assert!(!run_dir.join("kill-evidence.txt").exists());
        fs::write(&release, b"").expect("release child");
        let result = driver.wait_with_output().expect("natural completion");
        assert_eq!(result.status.code(), Some(0));
        assert_report(
            &result,
            label,
            budget.parse().expect("budget"),
            "OVER-BUDGET",
        );
    }
}

/// ´claim:driver:gateway-credit-affects-the-published-growth-state´
/// ´test:integration:gateway-credit-affects-the-published-growth-state´
#[test]
fn gateway_credit_affects_the_published_growth_state() {
    for (label, audited, open, state, quiet) in [
        ("in-flight", false, false, "runaway", 0),
        ("audited", true, false, "stalled", 131),
        ("open", false, true, "stalled", 131),
    ] {
        let harness = Harness::new(label);
        let run_dir = harness.run_dir(label);
        let release = run_dir.parent().expect("runs root").join("release");
        let gateway = harness.seed_gateway(audited);
        if open {
            fs::remove_file(gateway.join("proposal-verdicts/gw/7.json"))
                .expect("leave proposal open");
        }
        let mut command = harness.command();
        command
            .env("LANE_GATEWAY_STATE", &gateway)
            .env("ORACLE_MODE", "budget-wait")
            .env("ORACLE_RELEASE", &release)
            .env("CODEX_LANE_TEST_CLOCK", "0,131")
            .args([
                OsStr::new("-C"),
                harness.worktree().as_os_str(),
                OsStr::new("--gateway-lane"),
                OsStr::new("gw"),
                OsStr::new("-t"),
                OsStr::new("10"),
                OsStr::new("-n"),
                OsStr::new(label),
                OsStr::new("prompt"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut driver = command.spawn_serialized().expect("spawn driver");
        let sidecar = await_monitor(&run_dir, &format!(" state={state} "));
        assert!(
            sidecar.starts_with(&format!("quiet={quiet}s wall=131s ")),
            "{label}"
        );
        assert_eq!(sidecar.contains(" awaiting=gw:7"), label == "in-flight");
        assert!(driver.try_wait().expect("live driver").is_none());
        fs::write(&release, b"").expect("release child");
        let result = driver.wait_with_output().expect("natural completion");
        assert_eq!(result.status.code(), Some(0));
        assert_report(&result, label, 10, "OVER-BUDGET");
    }
}

/// ´claim:driver:a-finished-turn-can-idle-past-budget-and-exit-naturally´
/// ´test:integration:a-finished-turn-can-idle-past-budget-and-exit-naturally´
#[test]
fn a_finished_turn_can_idle_past_budget_and_exit_naturally() {
    let harness = Harness::new("result-seen");
    let run_dir = harness.run_dir("idle");
    let release = run_dir.parent().expect("runs root").join("release");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "result-then-idle")
        .env("ORACLE_RELEASE", &release)
        .env("CODEX_LANE_TEST_CLOCK", "")
        .args([
            OsStr::new("-t"),
            OsStr::new("1"),
            OsStr::new("-n"),
            OsStr::new("idle"),
            OsStr::new("prompt"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " expired_wall=");
    assert!(sidecar.contains("expired_state="));
    assert!(driver.try_wait().expect("live driver").is_none());
    fs::write(&release, b"").expect("release child");
    let result = driver.wait_with_output().expect("natural completion");

    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "idle", 1, "OVER-BUDGET");
    assert!(!run_dir.join("kill-evidence.txt").exists());
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read the finished message"),
        b"final text"
    );
}

/// ´claim:claudelane:a-finished-child-is-classified-by-its-result-not-by-its-silence´
/// ´test:integration:a-finished-child-stopped-after-budget-keeps-its-result-and-message´
#[test]
fn a_finished_child_stopped_after_budget_keeps_its_result_and_message() {
    let harness = Harness::new("result-idle-signal");
    let run_dir = harness.run_dir("idle");
    let release = run_dir.parent().expect("runs root").join("release");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "result-then-idle")
        .env("ORACLE_RELEASE", &release)
        .env("CODEX_LANE_TEST_CLOCK", "0,131")
        .args(["-t", "10", "-n", "idle", "prompt"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " expired_wall=");
    assert!(sidecar.contains("wall=131s"));
    let started = Instant::now();
    while !fs::read_to_string(run_dir.join("events.jsonl"))
        .is_ok_and(|events| events.contains("\"type\":\"result\""))
    {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "terminal result absent"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(driver.try_wait().expect("live driver").is_none());
    signal_process(driver.id(), "TERM");
    let result = driver.wait_with_output().expect("stopped driver");
    assert_eq!(result.status.code(), Some(0));
    assert_report(&result, "idle", 10, "OVER-BUDGET");
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("settled message"),
        b"final text"
    );
    assert!(!release.exists());
}

/// A driver asked to stop takes its child with it.
/// ´claim:claudelane:a-driver-asked-to-stop-stops-the-child-it-started´
/// ´test:integration:a-driver-asked-to-stop-takes-its-child-with-it´
#[test]
fn a_driver_asked_to_stop_takes_its_child_with_it() {
    let harness = Harness::new("forwarded-signal");
    let run_dir = harness.run_dir("signal");
    let child_record = run_dir.parent().expect("runs directory").join("child-pid");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "hung")
        .env("ORACLE_PID", &child_record)
        .env("CODEX_LANE_TEST_CLOCK", "0")
        .args([
            OsStr::new("-t"),
            OsStr::new("10"),
            OsStr::new("-n"),
            OsStr::new("signal"),
            OsStr::new("prompt"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let driver = command
        .spawn_serialized()
        .expect("claude-lane subprocess runs");
    let child = await_pid(&child_record);
    signal_process(driver.id(), "TERM");
    let result = driver
        .wait_with_output()
        .expect("claude-lane subprocess ends");

    assert_eq!(result.status.code(), Some(1));
    assert_report(&result, "signal", 10, "FAILED");
    assert!(
        !Path::new("/proc").join(child.to_string()).exists(),
        "child pid {child} outlived the driver it was spawned by"
    );
    assert!(!run_dir.join("kill-evidence.txt").exists());
}

/// A lock whose child is alive refuses recovery.
/// ´claim:claudelane:a-dead-driver-whose-child-still-runs-is-a-live-lock´
/// ´test:integration:a-lock-whose-child-is-alive-refuses-recovery´
#[test]
fn a_lock_whose_child_is_alive_refuses_recovery() {
    let harness = Harness::new("live-child-lock");
    let run_dir = harness.seed_interrupted_step("run", "session-1", &finished_events());
    let lock = run_dir.join(".claude-lane.lock");
    let dead_driver = u32::MAX;
    let live_child = std::process::id();
    assert!(!Path::new("/proc").join(dead_driver.to_string()).exists());
    fs::write(&lock, format!("{dead_driver}\n{live_child}\n")).expect("seed live-child lock");

    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-rsession-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-nwork"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        result.stderr,
        format!(
            "claude-lane: resume_live_lock: holder pid {live_child} is still live: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    // The transcript already carries a finish, so without the child's identity
    // this lock would have been reconstructed out from under a running step.
    assert!(lock.exists(), "a live lock is never cleared");
    assert!(!run_dir.join(".reconstructed").exists());
    assert!(!run_dir.join("run-report.txt").exists());
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
}

/// Fixture cleanup owns the driver group even when the test unwinds.
/// # Panics
/// Panics only if the fixture cannot start or leaves a live process after cleanup.
/// ´test:integration:claude-fixture-cleans-its-group-after-assertion-failure´
#[test]
fn claude_fixture_cleans_its_group_after_assertion_failure() {
    let mut identities = None;
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let harness = Harness::new("unwind-cleanup");
        let child_record = harness.home().join("child-pid");
        let driver = harness
            .command()
            .env("ORACLE_MODE", "hung")
            .env("ORACLE_PID", &child_record)
            .args(["-t", "10", "-n", "unwind", "prompt"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_serialized()
            .expect("spawn guarded driver");
        let child = await_pid(&child_record);
        identities = Some((driver.id(), child));
        assert_eq!(
            driver.id(),
            0,
            "injected assertion failure after child readiness"
        );
    }));
    assert!(
        failure.is_err(),
        "the assertion must unwind through the guard"
    );
    let (driver, child) = identities.expect("the injected failure followed readiness");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let live = fs::read_dir("/proc")
            .expect("process table")
            .filter_map(Result::ok)
            .any(|entry| {
                let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                    return false;
                };
                let Some((_, fields)) = stat.rsplit_once(") ") else {
                    return false;
                };
                let mut fields = fields.split_whitespace();
                let state = fields.next();
                let _parent = fields.next();
                let group = fields.next().and_then(|word| word.parse::<u32>().ok());
                let recorded_stub = entry.file_name() == child.to_string().as_str();
                (group == Some(driver) || recorded_stub) && !matches!(state, Some("Z" | "X"))
            });
        if !live {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixture group {driver} still has a live process (stub {child})"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !Path::new("/proc").join(driver.to_string()).exists(),
        "driver was reaped"
    );
}

/// The identity of the child the driver is supervising, as the child states it.
fn await_pid(path: &Path) -> u32 {
    let started = Instant::now();
    loop {
        if let Ok(bytes) = fs::read(path)
            && let Some(pid) = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the injected child never recorded its identity"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn await_monitor(run_dir: &Path, expected: &str) -> String {
    let started = Instant::now();
    loop {
        if let Ok(entries) = fs::read_dir(run_dir) {
            for entry in entries.filter_map(Result::ok) {
                if entry.file_name().to_string_lossy().starts_with(".monitor-")
                    && let Ok(sidecar) = fs::read_to_string(entry.path())
                    && sidecar.contains(expected)
                {
                    return sidecar;
                }
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "monitor never published {expected}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_monitor_line(line: &str, accounting: &str, suffix: &str) {
    let head = format!(
        "{accounting} context_state=unknown context_used=unknown context_window=unknown context_fraction=unknown context_source=none context_reason=no-turn context_turn=0 context_at="
    );
    let at = line
        .strip_prefix(&head)
        .and_then(|rest| rest.strip_suffix(&format!("{suffix}\n")))
        .expect("whole monitor line");
    assert_eq!(at.len(), 20);
    for (index, byte) in at.bytes().enumerate() {
        if [4, 7].contains(&index) {
            assert_eq!(byte, b'-');
        } else if index == 10 {
            assert_eq!(byte, b'T');
        } else if [13, 16].contains(&index) {
            assert_eq!(byte, b':');
        } else if index == 19 {
            assert_eq!(byte, b'Z');
        } else {
            assert!(byte.is_ascii_digit());
        }
    }
    assert_eq!(line, format!("{head}{at}{suffix}\n"));
}

/// Ask a process to stop, through the shell's own signal command.
fn signal_process(pid: u32, signal: &str) {
    let status = Command::new("/bin/sh")
        .args(["-c", &format!("kill -{signal} {pid}")])
        .status_serialized()
        .expect("signal the driver");
    assert!(status.success(), "signal delivery failed");
}

/// The stdin prompt bytes are exact.
/// ´claim:claudelane:a-stdin-prompt-is-forwarded-byte-for-byte-without-an-argv-prompt´
/// ´test:integration:stdin-prompt-bytes-are-exact´
#[test]
fn stdin_prompt_bytes_are_exact() {
    let harness = Harness::new("stdin");
    let mut command = harness.command();
    command
        .args(["-t60", "-nstdin", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn_serialized().expect("spawn stdin case");
    {
        use std::io::Write as _;
        // A child is entitled to exit without draining its stdin: a rejected argument
        // list leaves the lane before the prompt read, and a harness whose backend
        // cannot start never reaches one. A read end the child has closed therefore
        // says nothing about this case — its exit status, its streams, and the
        // recorded prompt are the verdict. Any other write failure is a fault of the
        // harness itself and must be seen.
        let write = child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(b"line one\nline two");
        if let Err(error) = write {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe,
                "write prompt: {error}"
            );
        }
    }
    let result = child.wait_with_output().expect("wait stdin case");
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(harness.read("stdin"), b"line one\nline two");
    assert!(!argv(&harness).lines().any(|line| line == "-"));
}

/// The permission mode mappings are exact.
/// ´claim:claudelane:each-lane-sandbox-has-one-declared-claude-permission-mapping´
/// ´test:integration:permission-mode-mappings-are-exact´
#[test]
fn permission_mode_mappings_are_exact() {
    for (sandbox, expected) in [
        ("read-only", vec!["--permission-mode", "plan"]),
        ("workspace-write", vec!["--permission-mode", "acceptEdits"]),
        (
            "danger-full-access",
            vec![
                "--permission-mode",
                "bypassPermissions",
                "--dangerously-skip-permissions",
            ],
        ),
    ] {
        let harness = Harness::new(sandbox);
        let result = harness.run(&[
            OsStr::new("-t60"),
            OsStr::new("-s"),
            OsStr::new(sandbox),
            OsStr::new("prompt"),
        ]);
        assert_eq!(result.status.code(), Some(0));
        let lines = argv(&harness)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(
            lines
                .windows(expected.len())
                .any(|window| window == expected)
        );
    }
}

/// The environment scrubs markers and keeps the config directory.
/// ´claim:claudelane:enclosing-harness-markers-never-reach-the-claude-child´
/// ´test:integration:environment-scrubs-markers-and-keeps-config-directory´
#[test]
fn environment_scrubs_markers_and_keeps_config_directory() {
    let harness = Harness::new("environment");
    let result = harness.run(&[OsStr::new("-t60"), OsStr::new("prompt")]);
    assert_eq!(result.status.code(), Some(0));
    let environment = String::from_utf8(harness.read("environment")).expect("UTF-8 environment");
    let temporary_root = format!(
        "TMPDIR={}",
        Path::new(&std::env::var_os("TMPDIR").expect("lane TMPDIR"))
            .canonicalize()
            .expect("resolved lane TMPDIR")
            .display()
    );
    assert!(environment.lines().any(|line| line == temporary_root));
    assert!(
        !environment
            .lines()
            .any(|line| line.starts_with("CLAUDECODE="))
    );
    assert!(
        !environment
            .lines()
            .any(|line| line.starts_with("CLAUDE_CODE_"))
    );
    assert!(
        environment
            .lines()
            .any(|line| { line == format!("CLAUDE_CONFIG_DIR={}", harness.config().display()) })
    );
}

/// # Panics
/// Panics only if the fixture or registered-home contract fails.
/// ´test:integration:claude-driver-selects-registered-home-without-explicit-configuration´
#[test]
fn claude_driver_selects_registered_home_without_explicit_configuration() {
    let harness = Harness::new("registered-home");
    let mut command = harness.command();
    command.env_remove("CLAUDE_CONFIG_DIR");
    let result = output(&mut command, &[OsStr::new("-t60"), OsStr::new("hello")]);
    assert!(result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&harness.read("environment"))
            .contains(&format!("CLAUDE_CONFIG_DIR={}", harness.config().display()))
    );
    let harness = Harness::new("default-registered-root");
    fs::write(harness.home().join(".config/loops/registry.toml"), "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n").expect("default root registry");
    let mut command = harness.command();
    command.env_remove("CLAUDE_CONFIG_DIR").env(
        "LANE_RUNS_ROOT",
        harness.home().join(".var/loops/alpha/runs"),
    );
    assert!(
        output(&mut command, &[OsStr::new("-t60"), OsStr::new("hello")])
            .status
            .success()
    );
}

/// # Panics
/// Panics only if a fixture or home-selection refusal fails.
/// ´test:integration:claude-driver-refuses-previous-mismatched-absent-and-ambiguous-homes´
#[test]
fn claude_driver_refuses_previous_mismatched_absent_and_ambiguous_homes() {
    for kind in [
        "previous-layout",
        "mismatch",
        "absent",
        "unregistered-loop",
        "ambiguous-loop",
    ] {
        let harness = Harness::new(kind);
        let mut command = harness.command();
        match kind {
            "previous-layout" => {
                command
                    .env("CLAUDE_CONFIG_DIR", harness.home().join(".claude-alpha"))
                    .env("LANE_RUN_DIR", harness.worktree().join("R"));
                fs::remove_file(harness.home().join(".config/loops/registry.toml"))
                    .expect("remove registry");
            }
            "mismatch" => {
                command.env("CLAUDE_CONFIG_DIR", harness.home().join(".claude"));
            }
            "absent" => {
                fs::remove_dir_all(harness.config()).expect("absent home");
            }
            "unregistered-loop" => {
                command.env("LANE_RUNS_ROOT", harness.home().join("legacy-runs"));
            }
            _ => {
                let path = harness.home().join(".config/loops/registry.toml");
                let source = fs::read_to_string(&path).expect("registry");
                let root = harness
                    .run_dir("probe")
                    .parent()
                    .expect("runs")
                    .to_string_lossy()
                    .into_owned();
                let row = format!(
                    ", {{ name = \"beta\", uid = 41002, launch = \"dev/beta\", runs_root = \"{root}\" }}]\n"
                );
                let (prefix, _) = source.rsplit_once("]\n").expect("rows");
                fs::write(path, format!("{prefix}{row}")).expect("duplicate effective root");
            }
        }
        let result = output(&mut command, &[OsStr::new("-t60"), OsStr::new("hello")]);
        assert_eq!(result.status.code(), Some(2), "{kind}: {result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(&format!("claude-home-{kind}")),
            "{result:?}"
        );
        assert!(!harness.run_dir("lane").exists());
    }
}

/// # Panics
/// Panics only if the fixture or standalone-resume selection fails.
/// ´test:integration:claude-standalone-resume-selects-the-parent-runs-root´
#[test]
fn claude_standalone_resume_selects_the_parent_runs_root() {
    for attached in [false, true] {
        let harness = Harness::new("standalone-home");
        let session = "22222222-2222-4222-8222-222222222222";
        let run = harness.seed_resume("old", session);
        harness.register_runs(run.parent().expect("standalone runs root"));
        let mut command = harness.command();
        command
            .env_remove("LANE_RUNS_ROOT")
            .env_remove("CLAUDE_CONFIG_DIR");
        let mut directory_option = std::ffi::OsString::from("-d");
        directory_option.push(&run);
        let mut args = vec![OsStr::new("-t60"), OsStr::new("-r"), OsStr::new(session)];
        if attached {
            args.push(directory_option.as_os_str());
        } else {
            args.extend([OsStr::new("-d"), run.as_os_str()]);
        }
        args.extend([OsStr::new("-nwork"), OsStr::new("continue")]);
        let result = output(&mut command, &args);
        assert!(result.status.success(), "{result:?}");
    }
}

/// # Panics
/// Panics only if fixture setup or the resume-root refusal contract fails.
/// ´test:integration:claude-resume-refuses-conflicting-and-unregistered-run-roots´
#[test]
fn claude_resume_refuses_conflicting_and_unregistered_run_roots() {
    for kind in [
        "cross-loop",
        "legacy-recipe",
        "legacy-standalone",
        "previous-layout",
    ] {
        let harness = Harness::new(kind);
        let session = "22222222-2222-4222-8222-222222222222";
        let original = harness.seed_resume("old", session);
        let configured_root = original.parent().expect("configured runs root");
        let selected_root = harness.home().join(if kind == "cross-loop" {
            "beta-runs"
        } else {
            "legacy-runs"
        });
        fs::create_dir(&selected_root).expect("other runs root");
        let run = selected_root.join("old");
        fs::rename(&original, &run).expect("move fixture run");
        let before = fs::read(run.join("run-report.txt")).expect("prior report");
        if kind == "cross-loop" {
            let path = harness.home().join(".config/loops/registry.toml");
            let source = fs::read_to_string(&path).expect("registry");
            let (prefix, _) = source.rsplit_once("]\n").expect("rows");
            fs::write(path, format!("{prefix}, {{ name = \"beta\", uid = 41002, launch = \"dev/beta\", runs_root = \"{}\" }}]\n", selected_root.display())).expect("register second loop");
        }
        let mut command = harness.command();
        command.env_remove("CLAUDE_CONFIG_DIR");
        if kind == "legacy-standalone" {
            command.env_remove("LANE_RUNS_ROOT");
        }
        if kind == "previous-layout" {
            command.env("CLAUDE_CONFIG_DIR", harness.home().join(".claude-alpha"));
        }
        let result = output(
            &mut command,
            &[
                OsStr::new("-t60"),
                OsStr::new("-r"),
                OsStr::new(session),
                OsStr::new("-d"),
                run.as_os_str(),
                OsStr::new("continue"),
            ],
        );
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        let error = String::from_utf8_lossy(&result.stderr);
        let refusal = match kind {
            "cross-loop" => {
                assert!(
                    error.contains(configured_root.to_str().expect("UTF-8 root")),
                    "{error}"
                );
                assert!(
                    error.contains(selected_root.to_str().expect("UTF-8 root")),
                    "{error}"
                );
                "claude-home-runs-root-mismatch"
            }
            "previous-layout" => "claude-home-previous-layout",
            _ => "claude-home-unregistered-loop",
        };
        assert!(error.contains(refusal), "{error}");
        assert_eq!(harness.read("argv"), Vec::<u8>::new());
        assert_eq!(
            fs::read(run.join("run-report.txt")).expect("unchanged report"),
            before
        );
    }
}

/// Pure mode constructs and refuses contaminated homes.
/// ´claim:claudelane:pure-mode-is-empty-read-only-and-credential-linked´
/// ´test:integration:pure-mode-constructs-and-refuses-contaminated-homes´
#[test]
fn pure_mode_constructs_and_refuses_contaminated_homes() {
    let harness = Harness::new("pure");
    let result = harness.run(&[
        OsStr::new("-Pt60"),
        OsStr::new("-npure"),
        OsStr::new("prompt"),
    ]);
    assert_eq!(result.status.code(), Some(0));
    let pure_home = harness.home().join(".claude-pure");
    let credentials = pure_home.join(".credentials.json");
    assert!(
        fs::symlink_metadata(&credentials)
            .expect("inspect credentials link")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::metadata(&credentials)
            .expect("follow credentials link")
            .ino(),
        fs::metadata(harness.config().join(".credentials.json"))
            .expect("inspect source credentials")
            .ino()
    );
    assert_eq!(
        fs::read(pure_home.join("settings.json")).expect("read settings"),
        b""
    );
    assert_eq!(
        harness.read("cwd"),
        format!("{}/cwd\n", harness.run_dir("pure").display()).as_bytes()
    );
    assert_eq!(
        argv(&harness),
        "-p\n--output-format\nstream-json\n--verbose\n--tools\n\n--setting-sources\n\n--permission-mode\nplan\n"
    );
    let environment = String::from_utf8(harness.read("environment")).expect("UTF-8 environment");
    assert!(
        environment
            .lines()
            .any(|line| { line == format!("CLAUDE_CONFIG_DIR={}", pure_home.display()) })
    );

    let contaminated = Harness::new("contaminated");
    let contaminated_home = contaminated.home().join(".claude-pure");
    fs::create_dir(&contaminated_home).expect("create contaminated pure home");
    fs::write(contaminated_home.join("CLAUDE.md"), b"contaminated\n")
        .expect("seed forbidden memory");
    let refusal = contaminated.run(&[
        OsStr::new("-Pt60"),
        OsStr::new("-npure"),
        OsStr::new("prompt"),
    ]);
    assert_eq!(refusal.status.code(), Some(2));
    assert_eq!(contaminated.read("argv"), Vec::<u8>::new());
}
