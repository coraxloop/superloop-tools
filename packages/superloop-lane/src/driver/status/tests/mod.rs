//! # `lane-watch` library test matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Argument parsing | 9 | Arity, path identity, default, decimal threshold, and refusals |
//! | Clock and threshold | 7 | Epoch flooring, future mtimes, and equality-is-stalled |
//! | Event evidence | 17 | Shell-compatible age, count, last type, stalled tail bytes, and generating evidence |
//! | Suspend-aware age | 6 | Monitor-record parsing, boot arithmetic, reboot refusal, and awake-age observation |
//! | Producer liveness | 7 | Lock discovery, driver liveness, process trees, TCP state, I/O movement, and unreadable `/proc` |
//! | Completion reports | 16 | Governed success/failure classification and invalid-marker refusal |
//! | Publication | 8 | Report order, status agreement, exact bytes, flush, and partial writes |
//! | Read-only and diagnostics | 7 | No state creation or mutation and stable path-free classes |

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::time::{Duration, UNIX_EPOCH};

use super::{
    Config, DEFAULT_STALL_SECONDS, INTERNAL_DIAGNOSTIC, LivenessEvidence, MonitorSample,
    Observation, PUBLICATION_DIAGNOSTIC, ProcReader, ProcessStat, USAGE_DIAGNOSTIC, Verdict,
    WatchError, age_seconds, awake_age, boot_seconds, classify_report, descendant_pids,
    driver_is_live, extract_last_type, last_event, observe, observe_events,
    observe_events_with_liveness, parse_args, parse_boot_seconds, parse_monitor_sample,
    parse_process_stat, parse_stall_seconds, producer_liveness_with, publish_failure,
    publish_observation, read_driver_pid, unix_seconds,
};

#[path = "../../../../tests/driver_status/support/mod.rs"]
mod support;

use support::TestDir;

fn config(directory: &TestDir, stall_seconds: u64) -> Config {
    Config {
        run_dir: directory.path().to_path_buf(),
        stall_seconds,
    }
}

/// ´test:unit:arguments-default-to-the-shell-threshold´
#[test]
fn arguments_default_to_the_shell_threshold() {
    let directory = TestDir::new("args-default");
    let parsed = parse_args([directory.path().as_os_str()]).expect("valid run directory");

    assert_eq!(parsed.run_dir, directory.path());
    assert_eq!(parsed.stall_seconds, DEFAULT_STALL_SECONDS);
}

/// ´test:unit:arguments-accept-zero-and-decimal-thresholds´
#[test]
fn arguments_accept_zero_and_decimal_thresholds() {
    let directory = TestDir::new("args-threshold");
    for (text, expected) in [
        ("0", 0),
        ("1", 1),
        ("300", 300),
        ("18446744073709551615", u64::MAX),
    ] {
        let parsed = parse_args([
            directory.path().as_os_str().to_os_string(),
            OsString::from(text),
        ])
        .expect("nonnegative decimal threshold");
        assert_eq!(parsed.stall_seconds, expected, "threshold {text}");
    }
}

/// ´test:unit:arguments-reject-missing-run-directory´
#[test]
fn arguments_reject_missing_run_directory() {
    assert!(parse_args(Vec::<OsString>::new()).is_none());
}

/// ´test:unit:arguments-reject-extra-positionals´
#[test]
fn arguments_reject_extra_positionals() {
    let directory = TestDir::new("args-extra");
    assert!(
        parse_args([
            directory.path().as_os_str().to_os_string(),
            OsString::from("10"),
            OsString::from("extra"),
        ])
        .is_none()
    );
}

/// ´test:unit:arguments-reject-missing-and-nondirectory-paths´
#[test]
fn arguments_reject_missing_and_nondirectory_paths() {
    let directory = TestDir::new("args-path");
    directory.write("ordinary-file", b"not a directory");

    assert!(parse_args([directory.path().join("missing").into_os_string()]).is_none());
    assert!(parse_args([directory.path().join("ordinary-file").into_os_string()]).is_none());
}

/// ´test:unit:arguments-reject-nondecimal-threshold-spellings´
#[test]
fn arguments_reject_nondecimal_threshold_spellings() {
    let directory = TestDir::new("args-invalid-threshold");
    for text in ["", "-1", "+1", " 1", "1 ", "1_000", "one"] {
        assert!(
            parse_args([
                directory.path().as_os_str().to_os_string(),
                OsString::from(text),
            ])
            .is_none(),
            "threshold {text:?} must be rejected"
        );
    }
}

/// ´test:unit:arguments-reject-threshold-overflow´
#[test]
fn arguments_reject_threshold_overflow() {
    assert_eq!(
        parse_stall_seconds(OsString::from("18446744073709551616").as_os_str()),
        None
    );
}

/// ´test:unit:status-arguments-accept-a-non-utf8-run-directory´
#[cfg(unix)]
#[test]
fn status_arguments_accept_a_non_utf8_run_directory() {
    use std::os::unix::ffi::OsStringExt as _;

    let parent = TestDir::new("args-non-utf8");
    let name = OsString::from_vec(vec![b'r', b'u', b'n', 0xff]);
    parent.mkdir(&name);
    let path = parent.path().join(name);
    let parsed = parse_args([path.clone().into_os_string()]).expect("non-UTF-8 run path");

    assert_eq!(parsed.run_dir, path);
}

/// ´test:unit:argument-parser-never-creates-run-directory-state´
#[test]
fn argument_parser_never_creates_run_directory_state() {
    let directory = TestDir::new("args-read-only");
    let before = directory.entry_names();

    let parsed = parse_args([directory.path()]).expect("valid run directory");

    assert_eq!(parsed.run_dir, directory.path());
    assert_eq!(directory.entry_names(), before);
}

/// ´test:unit:clock-age-matches-shell-epoch-second-subtraction´
#[test]
fn clock_age_matches_shell_epoch_second_subtraction() {
    let now = UNIX_EPOCH + Duration::new(100, 100_000_000);
    let modified = UNIX_EPOCH + Duration::new(90, 900_000_000);

    assert_eq!(age_seconds(now, modified), 10);
}

/// ´test:unit:clock-age-is-negative-for-a-future-mtime´
#[test]
fn clock_age_is_negative_for_a_future_mtime() {
    let now = UNIX_EPOCH + Duration::from_secs(100);
    let modified = UNIX_EPOCH + Duration::from_secs(140);

    assert_eq!(age_seconds(now, modified), -40);
}

/// ´test:unit:pre-epoch-seconds-floor-toward-negative-infinity´
#[test]
fn pre_epoch_seconds_floor_toward_negative_infinity() {
    let half_second_before_epoch = UNIX_EPOCH - Duration::from_millis(500);
    let exact_second_before_epoch = UNIX_EPOCH - Duration::from_secs(1);

    assert_eq!(unix_seconds(half_second_before_epoch), -1);
    assert_eq!(unix_seconds(exact_second_before_epoch), -1);
}

/// ´test:unit:age-at-one-second-across-epoch-is-exact´
#[test]
fn age_at_one_second_across_epoch_is_exact() {
    let now = UNIX_EPOCH + Duration::from_millis(100);
    let modified = UNIX_EPOCH - Duration::from_millis(100);

    assert_eq!(age_seconds(now, modified), 1);
}

/// ´test:unit:age-below-threshold-is-running´
#[test]
fn age_below_threshold_is_running() {
    let observation = observe_events(b"{\"type\":\"fresh\"}\n", 299, 300);

    assert_eq!(observation.verdict(), Verdict::Running);
    assert_eq!(
        observation.evidence(),
        b"ALIVE age=299s events=1 last=fresh\n"
    );
}

/// ´test:unit:age-equal-to-threshold-is-stalled´
#[test]
fn age_equal_to_threshold_is_stalled() {
    let observation = observe_events(b"{\"type\":\"equal\"}\n", 300, 300);

    assert_eq!(observation.verdict(), Verdict::Stalled);
    assert_eq!(
        observation.evidence(),
        b"STALLED age=300s events=1 last=equal pid=none established=0 io_delta=0\n{\"type\":\"equal\"}\n"
    );
}

/// ´test:unit:stale-events-with-liveness-emit-generating-and-remain-running´
#[test]
fn stale_events_with_liveness_emit_generating_and_remain_running() {
    let observation = observe_events_with_liveness(
        b"{\"type\":\"long-message\"}\n",
        413,
        300,
        &LivenessEvidence {
            driver_pid: Some(10),
            producer_pid: Some(20),
            established: 2,
            io_delta: 55_000,
        },
    );

    assert_eq!(observation.verdict(), Verdict::Running);
    assert_eq!(
        observation.evidence(),
        b"GENERATING age=413s events=1 last=long-message pid=20 established=2 io_delta=55000\n{\"type\":\"long-message\"}\n"
    );
}

/// ´test:unit:zero-threshold-stalls-an-existing-fresh-source´
#[test]
fn zero_threshold_stalls_an_existing_fresh_source() {
    let observation = observe_events(b"{\"type\":\"zero\"}\n", 0, 0);

    assert_eq!(observation.verdict(), Verdict::Stalled);
}

/// ´test:unit:one-line-event-matches-shell-evidence´
#[test]
fn one_line_event_matches_shell_evidence() {
    let observation = observe_events(b"{\"type\":\"agent_message\"}\n", 10, 300);

    assert_eq!(
        observation,
        Observation {
            evidence: b"ALIVE age=10s events=1 last=agent_message\n".to_vec(),
            verdict: Verdict::Running,
        }
    );
}

/// ´test:unit:multi-line-event-uses-last-line-type´
#[test]
fn multi_line_event_uses_last_line_type() {
    let events = b"{\"type\":\"first\"}\n{\"type\" : \"second\"}\n";
    let observation = observe_events(events, 20, 300);

    assert_eq!(
        observation.evidence(),
        b"ALIVE age=20s events=2 last=second\n"
    );
}

/// ´test:unit:stalled-event-repeats-last-event-verbatim´
#[test]
fn stalled_event_repeats_last_event_verbatim() {
    let events = b"{\"type\":\"first\"}\n{ \"type\" : \"last\", \"detail\": 7 }\n";
    let observation = observe_events(events, 301, 300);

    assert_eq!(
        observation.evidence(),
        b"STALLED age=301s events=2 last=last pid=none established=0 io_delta=0\n{ \"type\" : \"last\", \"detail\": 7 }\n"
    );
}

/// ´test:unit:empty-fresh-source-has-zero-events-and-unknown-type´
#[test]
fn empty_fresh_source_has_zero_events_and_unknown_type() {
    let observation = observe_events(b"", 5, 300);

    assert_eq!(
        observation.evidence(),
        b"ALIVE age=5s events=0 last=unknown\n"
    );
}

/// ´test:unit:empty-stalled-source-preserves-shell-blank-last-event´
#[test]
fn empty_stalled_source_preserves_shell_blank_last_event() {
    let observation = observe_events(b"", 300, 300);

    assert_eq!(
        observation.evidence(),
        b"STALLED age=300s events=0 last=unknown pid=none established=0 io_delta=0\n\n"
    );
}

/// ´test:unit:unterminated-event-counts-as-one-line´
#[test]
fn unterminated_event_counts_as_one_line() {
    let observation = observe_events(b"{\"type\":\"unterminated\"}", 1, 300);

    assert_eq!(
        observation.evidence(),
        b"ALIVE age=1s events=1 last=unterminated\n"
    );
}

/// ´test:unit:trailing-blank-line-is-the-last-event´
#[test]
fn trailing_blank_line_is_the_last_event() {
    let events = b"{\"type\":\"earlier\"}\n\n";
    let observation = observe_events(events, 400, 300);

    assert_eq!(
        observation.evidence(),
        b"STALLED age=400s events=2 last=unknown pid=none established=0 io_delta=0\n\n"
    );
}

#[derive(Default)]
struct FakeProc {
    stats: Option<Vec<Vec<u8>>>,
    fds: BTreeMap<u32, Vec<OsString>>,
    tcp: Vec<Vec<u8>>,
    io: BTreeMap<u32, [Option<Vec<u8>>; 2]>,
    sample: Cell<usize>,
    waits: Cell<usize>,
}

impl FakeProc {
    fn with_stats(stats: &[&[u8]]) -> Self {
        Self {
            stats: Some(stats.iter().map(|record| record.to_vec()).collect()),
            ..Self::default()
        }
    }
}

impl ProcReader for FakeProc {
    fn stat_records(&self) -> Option<Vec<Vec<u8>>> {
        self.stats.clone()
    }

    fn fd_targets(&self, pid: u32) -> Vec<OsString> {
        self.fds.get(&pid).cloned().unwrap_or_default()
    }

    fn tcp_tables(&self) -> Vec<Vec<u8>> {
        self.tcp.clone()
    }

    fn io_record(&self, pid: u32) -> Option<Vec<u8>> {
        self.io
            .get(&pid)
            .and_then(|samples| samples[self.sample.get().min(1)].clone())
    }

    fn wait(&self, _duration: Duration) {
        self.waits.set(self.waits.get() + 1);
        self.sample.set(1);
    }
}

/// ´test:unit:step-lock-discovery-accepts-either-driver-lock-name´
#[test]
fn step_lock_discovery_accepts_either_driver_lock_name() {
    for (name, pid) in [(".codex-lane.lock", 101), (".claude-lane.lock", 202)] {
        let directory = TestDir::new("driver-lock");
        directory.write(name, format!("{pid}\n").as_bytes());

        assert_eq!(read_driver_pid(directory.path()), Some(pid));
    }
}

/// ´test:unit:process-stat-parser-finds-parent-after-complex-command-name´
#[test]
fn process_stat_parser_finds_parent_after_complex_command_name() {
    assert_eq!(
        parse_process_stat(b"42 (worker ) name) S 17 0 0 0\n"),
        Some(ProcessStat {
            pid: 42,
            state: b'S',
            parent: 17,
        })
    );
    assert_eq!(parse_process_stat(b"malformed"), None);
}

/// ´test:unit:producer-tree-includes-transitive-children-only´
#[test]
fn producer_tree_includes_transitive_children_only() {
    let stats = [
        ProcessStat {
            pid: 10,
            state: b'S',
            parent: 1,
        },
        ProcessStat {
            pid: 20,
            state: b'S',
            parent: 10,
        },
        ProcessStat {
            pid: 30,
            state: b'S',
            parent: 20,
        },
        ProcessStat {
            pid: 40,
            state: b'S',
            parent: 1,
        },
    ];

    assert_eq!(descendant_pids(10, &stats), BTreeSet::from([20, 30]));
}

/// ´test:unit:synthetic-proc-matches-established-socket-in-producer-tree´
#[test]
fn synthetic_proc_matches_established_socket_in_producer_tree() {
    let mut proc = FakeProc::with_stats(&[
        b"10 (driver) S 1 0 0",
        b"20 (producer) S 10 0 0",
        b"30 (unrelated) S 1 0 0",
    ]);
    proc.fds.insert(
        20,
        vec![OsString::from("socket:[77]"), OsString::from("socket:[77]")],
    );
    proc.fds.insert(30, vec![OsString::from("socket:[88]")]);
    proc.tcp.push(
        b"sl local_address rem_address st tx_queue tr retr uid timeout inode\n0: 0100007F:0001 0100007F:0002 01 00000000:00000000 00:00000000 00000000 1000 0 77\n1: 0100007F:0003 0100007F:0004 01 00000000:00000000 00:00000000 00000000 1000 0 88\n"
            .to_vec(),
    );

    let evidence = producer_liveness_with(10, &proc);

    assert_eq!(
        evidence,
        LivenessEvidence {
            driver_pid: Some(10),
            producer_pid: Some(20),
            established: 1,
            io_delta: 0,
        }
    );
    assert_eq!(proc.waits.get(), 1);
}

/// ´test:unit:synthetic-proc-aggregates-rchar-and-wchar-movement´
#[test]
fn synthetic_proc_aggregates_rchar_and_wchar_movement() {
    let mut proc = FakeProc::with_stats(&[b"10 (driver) S 1", b"20 (producer) S 10"]);
    proc.io.insert(
        20,
        [
            Some(b"rchar: 10\nwchar: 20\n".to_vec()),
            Some(b"rchar: 15\nwchar: 27\n".to_vec()),
        ],
    );

    let evidence = producer_liveness_with(10, &proc);

    assert_eq!(evidence.producer_pid, Some(20));
    assert_eq!(evidence.established, 0);
    assert_eq!(evidence.io_delta, 12);
    assert_eq!(proc.waits.get(), 1);
}

/// ´test:unit:unreadable-proc-provides-no-liveness-evidence´
#[test]
fn unreadable_proc_provides_no_liveness_evidence() {
    let proc = FakeProc::default();

    let evidence = producer_liveness_with(10, &proc);

    assert_eq!(evidence.driver_pid, Some(10));
    assert_eq!(evidence.producer_pid, None);
    assert_eq!(evidence.established, 0);
    assert_eq!(evidence.io_delta, 0);
    assert_eq!(proc.waits.get(), 0);
}

/// ´test:unit:driver-liveness-refuses-a-zombie-and-an-unreadable-proc´
#[test]
fn driver_liveness_refuses_a_zombie_and_an_unreadable_proc() {
    assert!(driver_is_live(
        10,
        &FakeProc::with_stats(&[b"10 (driver) S 1", b"20 (producer) S 10"])
    ));
    assert!(!driver_is_live(
        10,
        &FakeProc::with_stats(&[b"10 (gone) Z 1"])
    ));
    assert!(!driver_is_live(
        10,
        &FakeProc::with_stats(&[b"11 (other) S 1"])
    ));
    assert!(!driver_is_live(10, &FakeProc::default()));
}

/// ´test:unit:type-extraction-accepts-shell-ascii-whitespace´
#[test]
fn type_extraction_accepts_shell_ascii_whitespace() {
    assert_eq!(
        extract_last_type(b"{\"type\"\t:\r \"spaced\"}"),
        Some(b"spaced".as_slice())
    );
}

/// ´test:unit:type-extraction-uses-the-last-matching-type-field´
#[test]
fn type_extraction_uses_the_last_matching_type_field() {
    let event = b"{\"type\":\"outer\",\"nested\":{\"type\":\"inner\"}}";

    assert_eq!(extract_last_type(event), Some(b"inner".as_slice()));
}

/// ´test:unit:malformed-later-type-falls-back-to-an-earlier-match´
#[test]
fn malformed_later_type_falls_back_to_an_earlier_match() {
    let event = b"{\"type\":\"valid\",\"type\":17}";

    assert_eq!(extract_last_type(event), Some(b"valid".as_slice()));
}

/// ´test:unit:absent-or-unterminated-type-is-unknown´
#[test]
fn absent_or_unterminated_type_is_unknown() {
    assert_eq!(extract_last_type(b"{\"kind\":\"other\"}"), None);
    assert_eq!(extract_last_type(b"{\"type\":\"unterminated}"), None);
}

/// ´test:unit:non-utf8-type-bytes-are-relayed-without-decoding´
#[test]
fn non_utf8_type_bytes_are_relayed_without_decoding() {
    let event = b"{\"type\":\"\xff\"}\n";
    let observation = observe_events(event, 1, 300);

    assert_eq!(observation.evidence(), b"ALIVE age=1s events=1 last=\xff\n");
}

/// ´test:unit:last-event-handles-terminated-and-unterminated-records´
#[test]
fn last_event_handles_terminated_and_unterminated_records() {
    assert_eq!(last_event(b"one\ntwo\n"), b"two");
    assert_eq!(last_event(b"one\ntwo"), b"two");
    assert_eq!(last_event(b""), b"");
}

/// ´test:unit:missing-event-source-is-unknown-age-stalled´
#[test]
fn missing_event_source_is_unknown_age_stalled() {
    let directory = TestDir::new("event-missing");

    let observation =
        observe(&config(&directory, 300), UNIX_EPOCH).expect("missing source verdict");

    assert_eq!(observation.verdict(), Verdict::Stalled);
    assert_eq!(
        observation.evidence(),
        b"STALLED age=unknown events=0 last=none\n"
    );
}

/// ´test:unit:filesystem-event-age-uses-the-supplied-clock´
#[test]
fn filesystem_event_age_uses_the_supplied_clock() {
    let directory = TestDir::new("event-clock");
    directory.write("events.jsonl", b"{\"type\":\"clocked\"}\n");
    let modified = UNIX_EPOCH + Duration::from_secs(1_000);
    directory.set_modified("events.jsonl", modified);

    let observation = observe(&config(&directory, 300), modified + Duration::from_secs(17))
        .expect("event observation");

    assert_eq!(
        observation.evidence(),
        b"ALIVE age=17s events=1 last=clocked\n"
    );
}

/// ´test:unit:future-filesystem-mtime-remains-running´
#[test]
fn future_filesystem_mtime_remains_running() {
    let directory = TestDir::new("event-future");
    directory.write("events.jsonl", b"{\"type\":\"future\"}\n");
    let modified = UNIX_EPOCH + Duration::from_secs(1_000);
    directory.set_modified("events.jsonl", modified);

    let observation = observe(&config(&directory, 300), modified - Duration::from_secs(9))
        .expect("future event observation");

    assert_eq!(
        observation.evidence(),
        b"ALIVE age=-9s events=1 last=future\n"
    );
}

struct SleepingDriver(std::process::Child);

impl SleepingDriver {
    fn spawn() -> Self {
        Self(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn a stand-in driver process"),
        )
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for SleepingDriver {
    fn drop(&mut self) {
        let _ignored = self.0.kill();
        let _ignored = self.0.wait();
    }
}

fn reaped_driver_pid() -> u32 {
    let mut child = std::process::Command::new("sleep")
        .arg("0")
        .spawn()
        .expect("spawn a driver that exits at once");
    let pid = child.id();
    child.wait().expect("reap the exited driver");
    pid
}

fn evidence_age(evidence: &[u8]) -> i128 {
    let field = evidence
        .split(|byte| *byte == b' ')
        .find_map(|field| field.strip_prefix(b"age="))
        .expect("evidence carries an age field");
    std::str::from_utf8(field.strip_suffix(b"s").expect("age is whole seconds"))
        .expect("decimal age")
        .parse()
        .expect("decimal age")
}

/// ´test:unit:a-live-monitor-record-reads-age-on-the-awake-clock´
#[test]
fn a_live_monitor_record_reads_age_on_the_awake_clock() {
    let directory = TestDir::new("monitor-awake");
    directory.write("events.jsonl", b"{\"type\":\"slept\"}\n");
    let modified = UNIX_EPOCH + Duration::from_secs(1_000_000);
    directory.set_modified("events.jsonl", modified);
    let driver = SleepingDriver::spawn();
    directory.write(".codex-lane.lock", format!("{}\n", driver.pid()).as_bytes());
    let boot = boot_seconds().expect("read this host's boot clock");
    directory.write(
        format!(".monitor-{}-0", driver.pid()),
        format!("quiet=30s wall=500s event_size=18 boot={boot}s awake=500s\n").as_bytes(),
    );

    let observation = observe(
        &config(&directory, 300),
        modified + Duration::from_secs(36_000),
    )
    .expect("observation of a step the host slept through");

    assert_eq!(observation.verdict(), Verdict::Running);
    assert_eq!(observation.verdict().status(), 0);
    // The record's quiet interval governs the verdict; the reader adds only the
    // boot seconds since that record, which a second boundary can round up.
    let age = evidence_age(observation.evidence());
    assert!(
        (30_i128..=32).contains(&age),
        "awake age derived from the record: {age}"
    );
    assert_eq!(
        observation.evidence(),
        format!("ALIVE age={age}s events=1 last=slept\n").as_bytes()
    );
}

/// ´test:unit:new-form-captures-select-the-latest-live-driver-sample´
#[test]
fn new_form_captures_select_the_latest_live_driver_sample() {
    let directory = TestDir::new("monitor-capture-selection");
    directory.write("events.jsonl", b"{\"type\":\"slept\"}\n");
    let modified = UNIX_EPOCH + Duration::from_secs(1_000_000);
    directory.set_modified("events.jsonl", modified);
    let driver = SleepingDriver::spawn();
    directory.write(".codex-lane.lock", format!("{}\n", driver.pid()).as_bytes());
    let boot = boot_seconds().expect("boot clock");
    directory.write(
        format!(".monitor-{}-0", driver.pid()),
        format!(
            "quiet=900s wall=900s event_size=18 boot={}s awake=900s\n",
            boot.saturating_sub(1)
        )
        .as_bytes(),
    );
    directory.write(
        format!(".monitor-{}-1", driver.pid()),
        format!("quiet=30s wall=500s event_size=18 boot={boot}s awake=500s\n").as_bytes(),
    );
    directory.write(
        ".monitor-4294967295-9",
        format!("quiet=900s wall=900s event_size=18 boot={boot}s awake=900s\n").as_bytes(),
    );
    let observation = observe(
        &config(&directory, 300),
        modified + Duration::from_secs(36_000),
    )
    .expect("new captures");
    assert_eq!(observation.verdict(), Verdict::Running);
    assert!((30_i128..=32).contains(&evidence_age(observation.evidence())));
}

/// ´test:unit:two-lock-readers-prefer-the-live-driver-over-a-newer-stale-lock´
#[test]
fn two_lock_readers_prefer_the_live_driver_over_a_newer_stale_lock() {
    let directory = TestDir::new("monitor-dual-lock-selection");
    directory.write("events.jsonl", b"{\"type\":\"slept\"}\n");
    let old_event = UNIX_EPOCH + Duration::from_secs(1_000_000);
    directory.set_modified("events.jsonl", old_event);
    let live = SleepingDriver::spawn();
    let stale = u32::MAX;
    directory.write(".claude-lane.lock", format!("{}\n", live.pid()).as_bytes());
    directory.write(".codex-lane.lock", format!("{stale}\n").as_bytes());
    directory.set_modified(".claude-lane.lock", UNIX_EPOCH + Duration::from_secs(2));
    directory.set_modified(".codex-lane.lock", UNIX_EPOCH + Duration::from_secs(3));
    let boot = boot_seconds().expect("boot clock");
    directory.write(
        format!(".monitor-{}-1", live.pid()),
        format!("quiet=30s wall=30s event_size=18 boot={boot}s awake=30s\n").as_bytes(),
    );
    directory.write(
        format!(".monitor-{stale}-1"),
        format!("quiet=900s wall=900s event_size=18 boot={boot}s awake=900s\n").as_bytes(),
    );
    assert_eq!(read_driver_pid(directory.path()), Some(live.pid()));
    let observation = observe(
        &config(&directory, 300),
        old_event + Duration::from_secs(36_000),
    )
    .expect("live driver selected");
    assert_eq!(observation.verdict(), Verdict::Running);
    assert!((30_i128..=32).contains(&evidence_age(observation.evidence())));
}

/// A monitor record with an awaiting field still yields quiet and boot.
/// ´test:unit:a-monitor-record-with-an-awaiting-field-still-parses´
#[test]
fn a_monitor_record_with_an_awaiting_field_still_parses() {
    let sample = parse_monitor_sample(
        b"quiet=30s wall=500s event_size=18 boot=1031s awake=500s awaiting=gw:7\n",
    )
    .expect("parse monitor record with awaiting field");
    assert_eq!(sample.quiet, 30);
    assert_eq!(sample.boot, 1_031);
}

/// ´test:unit:a-two-line-lock-still-names-its-driver-and-keeps-the-awake-age´
#[test]
fn a_two_line_lock_still_names_its_driver_and_keeps_the_awake_age() {
    let directory = TestDir::new("monitor-two-line-lock");
    directory.write("events.jsonl", b"{\"type\":\"slept\"}\n");
    let modified = UNIX_EPOCH + Duration::from_secs(1_000_000);
    directory.set_modified("events.jsonl", modified);
    let driver = SleepingDriver::spawn();
    // The lock a driver writes once its child exists: itself on the first
    // line, the child it is paying for on the second. A reader that took the
    // whole file for one identity would find no driver here at all and fall
    // back to the file timestamp, which cannot tell a suspended host from a
    // silent producer.
    directory.write(
        ".codex-lane.lock",
        format!("{}\n4294967295\n", driver.pid()).as_bytes(),
    );
    let boot = boot_seconds().expect("read this host's boot clock");
    directory.write(
        format!(".monitor-{}-0", driver.pid()),
        format!("quiet=30s wall=500s event_size=18 boot={boot}s awake=500s\n").as_bytes(),
    );

    assert_eq!(read_driver_pid(directory.path()), Some(driver.pid()));
    let observation = observe(
        &config(&directory, 300),
        modified + Duration::from_secs(36_000),
    )
    .expect("observation of a step the host slept through");

    assert_eq!(observation.verdict(), Verdict::Running);
    assert_eq!(observation.verdict().status(), 0);
    let age = evidence_age(observation.evidence());
    assert!(
        (30_i128..=32).contains(&age),
        "awake age derived from the record: {age}"
    );
}

/// ´test:unit:a-dead-driver-keeps-the-real-time-age´
#[test]
fn a_dead_driver_keeps_the_real_time_age() {
    let directory = TestDir::new("monitor-dead");
    directory.write("events.jsonl", b"{\"type\":\"slept\"}\n");
    let modified = UNIX_EPOCH + Duration::from_secs(1_000_000);
    directory.set_modified("events.jsonl", modified);
    let pid = reaped_driver_pid();
    directory.write(".codex-lane.lock", format!("{pid}\n").as_bytes());
    let boot = boot_seconds().expect("read this host's boot clock");
    directory.write(
        format!(".monitor-{pid}-0"),
        format!("quiet=30s wall=500s event_size=18 boot={boot}s awake=500s\n").as_bytes(),
    );

    let observation = observe(
        &config(&directory, 300),
        modified + Duration::from_secs(900),
    )
    .expect("observation of a dead driver's record");

    assert_eq!(observation.verdict(), Verdict::Stalled);
    assert_eq!(observation.verdict().status(), 42);
    assert_eq!(
        observation.evidence(),
        format!(
            "STALLED age=900s events=1 last=slept pid={pid} established=0 io_delta=0\n{{\"type\":\"slept\"}}\n"
        )
        .as_bytes()
    );
}

/// ´test:unit:a-monitor-record-parses-only-as-one-complete-line´
#[test]
fn a_monitor_record_parses_only_as_one_complete_line() {
    assert_eq!(
        parse_monitor_sample(b"quiet=30s wall=500s event_size=18 boot=4000s awake=500s\n"),
        Some(MonitorSample {
            quiet: 30,
            boot: 4_000,
        })
    );
    for refused in [
        b"quiet=30s wall=500s boot=4000s".as_slice(),
        b"quiet=30s boot=4000s\nquiet=0s boot=4000s\n".as_slice(),
        b"wall=500s boot=4000s\n".as_slice(),
        b"quiet=30s wall=500s\n".as_slice(),
        b"quiet=30 boot=4000s\n".as_slice(),
        b"quiet=-1s boot=4000s\n".as_slice(),
        b"quiet=s boot=4000s\n".as_slice(),
    ] {
        assert_eq!(parse_monitor_sample(refused), None);
    }
}

/// ´test:unit:the-awake-age-adds-boot-seconds-since-the-record´
#[test]
fn the_awake_age_adds_boot_seconds_since_the_record() {
    let sample = MonitorSample {
        quiet: 30,
        boot: 4_000,
    };

    assert_eq!(awake_age(sample, 4_000), Some(30));
    assert_eq!(awake_age(sample, 4_005), Some(35));
    // A boot clock behind the record's own reading belongs to a later boot, so
    // the record describes a step that did not survive into this host's life.
    assert_eq!(awake_age(sample, 3_999), None);
}

/// ´test:unit:the-boot-clock-reading-is-truncated-to-whole-seconds´
#[test]
fn the_boot_clock_reading_is_truncated_to_whole_seconds() {
    assert_eq!(parse_boot_seconds("4000.87 39500.02\n"), Some(4_000));
    assert_eq!(parse_boot_seconds("4000 39500\n"), Some(4_000));
    assert_eq!(parse_boot_seconds(""), None);
    assert_eq!(parse_boot_seconds("late 39500\n"), None);
    assert_eq!(parse_boot_seconds(".87 39500\n"), None);
}

/// ´test:unit:report-ok-classifies-completed´
#[test]
fn report_ok_classifies_completed() {
    assert_eq!(
        classify_report(b"RUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n"),
        Ok(Verdict::Completed)
    );
}

/// ´test:unit:report-over-budget-classifies-completed´
#[test]
fn report_over_budget_classifies_completed() {
    assert_eq!(
        classify_report(b"RUN-REPORT lane=x exit=0 wall=3s budget=2s verdict=OVER-BUDGET dir=x\n"),
        Ok(Verdict::Completed)
    );
}

/// ´test:unit:report-failed-statuses-classify-failed´
#[test]
fn report_failed_statuses_classify_failed() {
    for status in [1, 2] {
        let report =
            format!("RUN-REPORT lane=x exit={status} wall=1s budget=2s verdict=FAILED dir=x\n");
        assert_eq!(classify_report(report.as_bytes()), Ok(Verdict::Failed));
    }
}

/// ´test:unit:report-protocol-kills-classify-failed´
#[test]
fn report_protocol_kills_classify_failed() {
    for verdict in ["STALLED-KILLED", "RUNAWAY-KILLED"] {
        let report =
            format!("RUN-REPORT lane=x exit=1 wall=9s budget=2s verdict={verdict} dir=x\n");
        assert_eq!(classify_report(report.as_bytes()), Ok(Verdict::Failed));
    }
}

/// ´test:unit:report-rate-limited-classifies-failed´
#[test]
fn report_rate_limited_classifies_failed() {
    let report = b"RUN-REPORT lane=x exit=1 wall=5s budget=1800s verdict=RATE-LIMITED dir=x\n";

    assert_eq!(classify_report(report), Ok(Verdict::Failed));
}

/// A stored report from before the verdict was retired still reads as failed.
///
/// ´test:unit:a-stored-suspend-killed-report-classifies-failed´
#[test]
fn a_stored_suspend_killed_report_classifies_failed() {
    let report =
        b"RUN-REPORT lane=x exit=1 wall=9s budget=2s verdict=SUSPEND-KILLED suspend_gap=10s dir=x\n";

    assert_eq!(classify_report(report), Ok(Verdict::Failed));
}

/// ´test:unit:a-suspend-gap-qualifies-the-verdict-a-step-earned´
#[test]
fn a_suspend_gap_qualifies_the_verdict_a_step_earned() {
    let report = b"RUN-REPORT lane=x exit=0 wall=9s budget=60s verdict=ok suspend_gap=900s dir=x\n";

    assert_eq!(classify_report(report), Ok(Verdict::Completed));
}

/// ´test:unit:report-crashed-host-exit-classifies-failed´
#[test]
fn report_crashed_host_exit_classifies_failed() {
    let report =
        b"RUN-REPORT lane=x exit=1 wall=0s budget=0s verdict=CRASHED-HOST-EXIT pid=4242 dir=x\n";

    assert_eq!(classify_report(report), Ok(Verdict::Failed));
}

/// ´test:unit:report-classification-uses-the-final-evidence-line´
#[test]
fn report_classification_uses_the_final_evidence_line() {
    let report = b"worker evidence\nRUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n";

    assert_eq!(classify_report(report), Ok(Verdict::Completed));
}

/// ´test:unit:report-requires-a-terminal-lf´
#[test]
fn report_requires_a_terminal_lf() {
    assert_eq!(
        classify_report(b"RUN-REPORT exit=0 verdict=ok"),
        Err(WatchError::ReportContract)
    );
}

/// ´test:unit:report-requires-the-run-report-token´
#[test]
fn report_requires_the_run_report_token() {
    assert_eq!(
        classify_report(b"REPORT exit=0 verdict=ok\n"),
        Err(WatchError::ReportContract)
    );
}

/// ´test:unit:report-requires-exit-and-verdict-fields´
#[test]
fn report_requires_exit_and_verdict_fields() {
    assert_eq!(
        classify_report(b"RUN-REPORT verdict=ok\n"),
        Err(WatchError::ReportContract)
    );
    assert_eq!(
        classify_report(b"RUN-REPORT exit=0\n"),
        Err(WatchError::ReportContract)
    );
}

/// ´test:unit:report-rejects-duplicate-exit-or-verdict-fields´
#[test]
fn report_rejects_duplicate_exit_or_verdict_fields() {
    assert_eq!(
        classify_report(b"RUN-REPORT exit=0 exit=0 verdict=ok\n"),
        Err(WatchError::ReportContract)
    );
    assert_eq!(
        classify_report(b"RUN-REPORT exit=0 verdict=ok verdict=ok\n"),
        Err(WatchError::ReportContract)
    );
}

/// ´test:unit:report-rejects-status-verdict-disagreement´
#[test]
fn report_rejects_status_verdict_disagreement() {
    for report in [
        b"RUN-REPORT exit=1 verdict=ok\n".as_slice(),
        b"RUN-REPORT exit=0 verdict=FAILED\n",
        b"RUN-REPORT exit=2 verdict=STALLED-KILLED\n",
    ] {
        assert_eq!(classify_report(report), Err(WatchError::ReportContract));
    }
}

/// ´test:unit:report-rejects-empty-repeated-separators´
#[test]
fn report_rejects_empty_repeated_separators() {
    assert_eq!(
        classify_report(b"RUN-REPORT  exit=0 verdict=ok\n"),
        Err(WatchError::ReportContract)
    );
}

/// ´test:unit:report-rejects-nondecimal-or-undeclared-exit´
#[test]
fn report_rejects_nondecimal_or_undeclared_exit() {
    for report in [
        b"RUN-REPORT exit=zero verdict=ok\n".as_slice(),
        b"RUN-REPORT exit=42 verdict=stalled\n",
        b"RUN-REPORT exit=255 verdict=FAILED\n",
    ] {
        assert_eq!(classify_report(report), Err(WatchError::ReportContract));
    }
}

/// ´test:unit:report-file-bytes-are-relayed-verbatim-before-watcher-report´
#[test]
fn report_file_bytes_are_relayed_verbatim_before_watcher_report() {
    let directory = TestDir::new("report-verbatim");
    let report = b"evidence\nRUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n";
    directory.write("run-report.txt", report);

    let observation = observe(&config(&directory, 0), UNIX_EPOCH).expect("valid report");

    assert_eq!(observation.evidence(), report);
    assert_eq!(observation.verdict(), Verdict::Completed);
}

/// ´test:unit:failed-report-file-is-a-successful-failed-observation´
#[test]
fn failed_report_file_is_a_successful_failed_observation() {
    let directory = TestDir::new("report-failed");
    let report = b"RUN-REPORT lane=x exit=1 wall=1s budget=2s verdict=FAILED dir=x\n";
    directory.write("run-report.txt", report);

    let observation = observe(&config(&directory, 0), UNIX_EPOCH).expect("failed lane report");

    assert_eq!(observation.verdict(), Verdict::Failed);
    assert_eq!(observation.verdict().status(), 0);
}

/// ´test:unit:invalid-report-file-is-a-runtime-contract-failure´
#[test]
fn invalid_report_file_is_a_runtime_contract_failure() {
    let directory = TestDir::new("report-invalid");
    directory.write("run-report.txt", b"not a report\n");

    assert_eq!(
        observe(&config(&directory, 300), UNIX_EPOCH),
        Err(WatchError::ReportContract)
    );
}

/// ´test:unit:running-publication-is-byte-exact´
#[test]
fn running_publication_is_byte_exact() {
    let observation = observe_events(b"{\"type\":\"fresh\"}\n", 10, 300);
    let mut output = Vec::new();

    publish_observation(&observation, Duration::from_secs(7), &mut output)
        .expect("publish observation");

    assert_eq!(
        output,
        b"ALIVE age=10s events=1 last=fresh\nRUN-REPORT exit=0 wall=7s verdict=running\n"
    );
}

/// ´test:unit:stalled-publication-binds-report-to-status-42´
#[test]
fn stalled_publication_binds_report_to_status_42() {
    let observation = observe_events(b"{\"type\":\"quiet\"}\n", 300, 300);
    let mut output = Vec::new();

    publish_observation(&observation, Duration::ZERO, &mut output).expect("publish stalled");

    assert!(output.ends_with(b"RUN-REPORT exit=42 wall=0s verdict=stalled\n"));
    assert_eq!(observation.verdict().status(), 42);
}

/// ´test:unit:completed-and-failed-lane-reports-keep-watcher-status-zero´
#[test]
fn completed_and_failed_lane_reports_keep_watcher_status_zero() {
    for verdict in [Verdict::Completed, Verdict::Failed] {
        let observation = Observation {
            evidence: b"stored report\n".to_vec(),
            verdict,
        };
        let mut output = Vec::new();

        publish_observation(&observation, Duration::from_secs(2), &mut output)
            .expect("publish terminal observation");

        assert!(
            output.ends_with(
                format!(
                    "RUN-REPORT exit=0 wall=2s verdict={}\n",
                    verdict.report_word()
                )
                .as_bytes()
            )
        );
    }
}

/// ´test:unit:runtime-failure-publication-is-byte-exact´
#[test]
fn runtime_failure_publication_is_byte_exact() {
    let mut output = Vec::new();

    publish_failure(
        WatchError::EventSource.diagnostic(),
        Duration::from_secs(3),
        &mut output,
    )
    .expect("publish failure");

    assert_eq!(
        output,
        b"superloop-lane: event_source_failure: event source inspection failed\nRUN-REPORT exit=1 wall=3s verdict=FAILED\n"
    );
}

struct TrackingWriter {
    accepted: Vec<u8>,
    limit: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}

impl TrackingWriter {
    fn unbounded() -> Self {
        Self {
            accepted: Vec::new(),
            limit: None,
            fail_flush: false,
            flushes: 0,
        }
    }

    fn bounded(limit: usize) -> Self {
        Self {
            accepted: Vec::new(),
            limit: Some(limit),
            fail_flush: false,
            flushes: 0,
        }
    }

    fn failing_flush() -> Self {
        Self {
            accepted: Vec::new(),
            limit: None,
            fail_flush: true,
            flushes: 0,
        }
    }
}

impl Write for TrackingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(limit) = self.limit else {
            self.accepted.extend_from_slice(bytes);
            return Ok(bytes.len());
        };
        if self.accepted.len() == limit {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected publication boundary",
            ));
        }
        let accepted = bytes.len().min(limit - self.accepted.len());
        self.accepted.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected flush boundary",
            ))
        } else {
            Ok(())
        }
    }
}

/// ´test:unit:successful-publication-flushes-once-after-report´
#[test]
fn successful_publication_flushes_once_after_report() {
    let observation = observe_events(b"", 1, 300);
    let mut writer = TrackingWriter::unbounded();

    let result = publish_observation(&observation, Duration::ZERO, &mut writer);

    assert_eq!(result, Ok(()));
    assert_eq!(writer.flushes, 1);
    assert!(
        writer
            .accepted
            .ends_with(b"RUN-REPORT exit=0 wall=0s verdict=running\n")
    );
}

/// ´test:unit:partial-publication-preserves-the-accepted-prefix´
#[test]
fn partial_publication_preserves_the_accepted_prefix() {
    let observation = observe_events(b"{\"type\":\"fresh\"}\n", 1, 300);
    let mut writer = TrackingWriter::bounded(8);

    let result = publish_observation(&observation, Duration::ZERO, &mut writer);

    assert_eq!(result, Err(WatchError::Publication));
    assert_eq!(writer.accepted, b"ALIVE ag");
}

/// ´test:unit:report-partial-publication-preserves-complete-evidence´
#[test]
fn report_partial_publication_preserves_complete_evidence() {
    let observation = observe_events(b"", 1, 300);
    let evidence_length = observation.evidence().len();
    let mut writer = TrackingWriter::bounded(evidence_length + 5);

    let result = publish_observation(&observation, Duration::ZERO, &mut writer);

    assert_eq!(result, Err(WatchError::Publication));
    assert_eq!(&writer.accepted[..evidence_length], observation.evidence());
    assert_eq!(&writer.accepted[evidence_length..], b"RUN-R");
}

/// ´test:unit:flush-failure-returns-publication-after-complete-report-bytes´
#[test]
fn flush_failure_returns_publication_after_complete_report_bytes() {
    let observation = observe_events(b"", 1, 300);
    let mut writer = TrackingWriter::failing_flush();

    let result = publish_observation(&observation, Duration::ZERO, &mut writer);

    assert_eq!(result, Err(WatchError::Publication));
    assert!(
        writer
            .accepted
            .ends_with(b"RUN-REPORT exit=0 wall=0s verdict=running\n")
    );
    assert_eq!(writer.flushes, 1);
}

/// ´test:unit:missing-source-observation-creates-no-state´
#[test]
fn missing_source_observation_creates_no_state() {
    let directory = TestDir::new("readonly-missing");
    let before = directory.entry_names();

    let result = observe(&config(&directory, 300), UNIX_EPOCH).expect("missing source verdict");

    assert_eq!(result.verdict(), Verdict::Stalled);
    assert_eq!(directory.entry_names(), before);
}

/// ´test:unit:event-observation-preserves-entries-bytes-and-mtime´
#[test]
fn event_observation_preserves_entries_bytes_and_mtime() {
    let directory = TestDir::new("readonly-events");
    let bytes = b"{\"type\":\"read-only\"}\n";
    directory.write("events.jsonl", bytes);
    directory.write(".feed-offset", b"17\n");
    let before_entries = directory.entry_names();
    let before_modified = directory.modified("events.jsonl");

    let result = observe(
        &config(&directory, 300),
        before_modified + Duration::from_secs(1),
    )
    .expect("event observation");

    assert_eq!(result.verdict(), Verdict::Running);
    assert_eq!(directory.entry_names(), before_entries);
    assert_eq!(directory.read("events.jsonl"), bytes);
    assert_eq!(directory.read(".feed-offset"), b"17\n");
    assert_eq!(directory.modified("events.jsonl"), before_modified);
}

/// ´test:unit:report-observation-preserves-marker-bytes-and-entries´
#[test]
fn report_observation_preserves_marker_bytes_and_entries() {
    let directory = TestDir::new("readonly-report");
    let report = b"RUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n";
    directory.write("run-report.txt", report);
    directory.write(".feed-offset", b"9\n");
    let before = directory.entry_names();

    let result = observe(&config(&directory, 300), UNIX_EPOCH).expect("report observation");

    assert_eq!(result.verdict(), Verdict::Completed);
    assert_eq!(directory.entry_names(), before);
    assert_eq!(directory.read("run-report.txt"), report);
    assert_eq!(directory.read(".feed-offset"), b"9\n");
}

/// ´test:unit:nonfile-event-source-is-runtime-failure-without-mutation´
#[test]
fn nonfile_event_source_is_runtime_failure_without_mutation() {
    let directory = TestDir::new("readonly-event-directory");
    directory.mkdir("events.jsonl");
    let before = directory.entry_names();

    assert_eq!(
        observe(&config(&directory, 300), UNIX_EPOCH),
        Err(WatchError::EventSource)
    );
    assert_eq!(directory.entry_names(), before);
}

/// ´test:unit:nonfile-report-marker-is-runtime-failure-without-event-fallback´
#[test]
fn nonfile_report_marker_is_runtime_failure_without_event_fallback() {
    let directory = TestDir::new("readonly-report-directory");
    directory.mkdir("run-report.txt");
    directory.write("events.jsonl", b"{\"type\":\"ignored\"}\n");

    assert_eq!(
        observe(&config(&directory, 300), UNIX_EPOCH),
        Err(WatchError::ReportRead)
    );
}

/// ´test:unit:every-diagnostic-has-one-stable-class-and-no-path´
#[test]
fn every_diagnostic_has_one_stable_class_and_no_path() {
    let classes = [
        (WatchError::ReportRead, "report_read_failure"),
        (WatchError::ReportContract, "report_contract_failure"),
        (WatchError::EventSource, "event_source_failure"),
        (WatchError::EventRead, "event_read_failure"),
        (WatchError::Publication, "publication_failure"),
    ];

    for (error, class) in classes {
        let diagnostic = std::str::from_utf8(error.diagnostic()).expect("ASCII diagnostic");
        assert!(diagnostic.starts_with("superloop-lane: "));
        assert!(diagnostic.contains(class));
        assert!(diagnostic.ends_with('\n'));
        assert_eq!(diagnostic.lines().count(), 1);
        assert!(!diagnostic.contains('/'));
    }
}

/// ´test:unit:fixed-boundary-diagnostics-are-classed-and-path-free´
#[test]
fn fixed_boundary_diagnostics_are_classed_and_path_free() {
    for (diagnostic, class) in [
        (USAGE_DIAGNOSTIC, "usage_error"),
        (PUBLICATION_DIAGNOSTIC, "publication_failure"),
        (INTERNAL_DIAGNOSTIC, "internal_failure"),
    ] {
        let text = std::str::from_utf8(diagnostic).expect("ASCII diagnostic");
        assert!(text.contains(class));
        assert!(text.ends_with('\n'));
        assert!(!text.contains('/'));
    }
}
