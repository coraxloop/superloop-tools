//! # `lane-watch` subprocess contract matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Shell-agreeing oracle evidence | 10 | Normalized age plus exact remaining evidence, stderr, and status |
//! | Governed completion | 4 | Watcher report, stored lane classification, precedence, and validation |
//! | Governed usage | 5 | Status 2, empty stdout, fixed classed stderr, and argument omission |
//! | Runtime failure | 4 | Status 1, fixed classed stdout evidence, final failed report, empty stderr |
//! | Stream and state discipline | 4 | Pipe/file invariance and no run-directory mutation or offset advance |
//! | Producer liveness | 4 | Established TCP, moving I/O, dead driver locks, and absent locks |

mod support;

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use support::TestDir;

const USAGE_DIAGNOSTIC: &[u8] = b"superloop-lane: usage_error: invalid command-line arguments\n";
const REPORT_READ_DIAGNOSTIC: &[u8] =
    b"superloop-lane: report_read_failure: completion report could not be read\n";
const REPORT_CONTRACT_DIAGNOSTIC: &[u8] =
    b"superloop-lane: report_contract_failure: completion report is invalid\n";
const EVENT_SOURCE_DIAGNOSTIC: &[u8] =
    b"superloop-lane: event_source_failure: event source inspection failed\n";
const FIXTURE_ROLE: &str = "LANE_WATCH_FIXTURE_ROLE";
const FIXTURE_PRODUCER_ROLE: &str = "LANE_WATCH_FIXTURE_PRODUCER_ROLE";
const FIXTURE_RUN_DIR: &str = "LANE_WATCH_FIXTURE_RUN_DIR";
const FIXTURE_PORT: &str = "LANE_WATCH_FIXTURE_PORT";
const FIXTURE_CAPTURE: &str = "LANE_WATCH_FIXTURE_CAPTURE";
const FIXTURE_TEST: &str = "stale_events_with_established_socket_are_generating";

fn lane_watch() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
    command.args(["driver", "status"]);
    command
}

fn run<I, A>(arguments: I) -> Output
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    lane_watch()
        .args(arguments)
        .output()
        .expect("lane-watch subprocess runs")
}

fn fixture(case: &str, suffix: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/driver_status/fixtures/expected")
            .join(format!("{case}.{suffix}")),
    )
    .expect("read committed shell-oracle fixture")
}

fn fixture_status(case: &str) -> i32 {
    let bytes = fixture(case, "status");
    std::str::from_utf8(&bytes)
        .expect("ASCII fixture status")
        .trim()
        .parse()
        .expect("decimal fixture status")
}

fn split_watcher_report(stdout: &[u8]) -> (&[u8], &[u8]) {
    let marker = b"RUN-REPORT exit=";
    let start = stdout
        .windows(marker.len())
        .rposition(|window| window == marker)
        .expect("watcher report marker");
    (&stdout[..start], &stdout[start..])
}

fn normalize_numeric_field(bytes: &[u8], prefix: &[u8], suffix: u8) -> Vec<u8> {
    let Some(start) = bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .map(|index| index + prefix.len())
    else {
        return bytes.to_vec();
    };
    let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == suffix) else {
        return bytes.to_vec();
    };
    let end = start + relative_end;
    let mut normalized = Vec::with_capacity(bytes.len());
    normalized.extend_from_slice(&bytes[..start]);
    normalized.extend_from_slice(b"N");
    normalized.extend_from_slice(&bytes[end..]);
    normalized
}

fn normalize_age(bytes: &[u8]) -> Vec<u8> {
    normalize_numeric_field(bytes, b"age=", b's')
}

fn normalize_wall(bytes: &[u8]) -> Vec<u8> {
    normalize_numeric_field(bytes, b"wall=", b's')
}

fn normalize_absent_liveness(bytes: &[u8]) -> Vec<u8> {
    const ABSENT: &[u8] = b" pid=none established=0 io_delta=0";
    let Some(start) = bytes
        .windows(ABSENT.len())
        .position(|window| window == ABSENT)
    else {
        return bytes.to_vec();
    };
    let mut normalized = Vec::with_capacity(bytes.len() - ABSENT.len());
    normalized.extend_from_slice(&bytes[..start]);
    normalized.extend_from_slice(&bytes[start + ABSENT.len()..]);
    normalized
}

fn numeric_field(bytes: &[u8], prefix: &[u8], suffix: u8) -> u64 {
    let start = bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .map(|index| index + prefix.len())
        .expect("numeric field prefix");
    let relative_end = bytes[start..]
        .iter()
        .position(|byte| *byte == suffix)
        .expect("numeric field suffix");
    std::str::from_utf8(&bytes[start..start + relative_end])
        .expect("ASCII numeric field")
        .parse()
        .expect("decimal numeric field")
}

fn expected_watcher_report(status: i32, verdict: &str) -> Vec<u8> {
    format!("RUN-REPORT exit={status} wall=Ns verdict={verdict}\n").into_bytes()
}

fn assert_oracle_observation(
    directory: &TestDir,
    case: &str,
    stall_seconds: Option<&str>,
    verdict: &str,
) {
    let mut arguments = vec![directory.path().as_os_str().to_os_string()];
    if let Some(stall_seconds) = stall_seconds {
        arguments.push(OsString::from(stall_seconds));
    }
    let output = run(arguments);
    let shell_status = fixture_status(case);
    let shell_stdout = fixture(case, "stdout");
    let shell_stderr = fixture(case, "stderr");
    let (evidence, report) = split_watcher_report(&output.stdout);

    assert_eq!(output.status.code(), Some(shell_status));
    assert_eq!(
        normalize_absent_liveness(&normalize_age(evidence)),
        normalize_age(&shell_stdout)
    );
    assert_eq!(output.stderr, shell_stderr);
    assert_eq!(
        normalize_wall(report),
        expected_watcher_report(shell_status, verdict)
    );
}

fn write_events(directory: &TestDir, bytes: &[u8], age: u64) {
    directory.write("events.jsonl", bytes);
    directory.set_modified("events.jsonl", SystemTime::now() - Duration::from_secs(age));
}

fn assert_runtime_failure(output: &Output, diagnostic: &[u8]) {
    let (evidence, report) = split_watcher_report(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(evidence, diagnostic);
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=1 wall=Ns verdict=FAILED\n"
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
}

fn fixture_command() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .args([FIXTURE_TEST, "--exact", "--nocapture"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn run_fixture_process() -> bool {
    let Some(role) = std::env::var_os(FIXTURE_ROLE) else {
        return false;
    };
    match role.to_str().expect("ASCII fixture role") {
        "driver" => run_fixture_driver(),
        "socket" => run_socket_producer(),
        "io" => run_io_producer(),
        "exit" => {}
        _ => panic!("unknown fixture role"),
    }
    true
}

fn fixture_run_dir() -> PathBuf {
    PathBuf::from(std::env::var_os(FIXTURE_RUN_DIR).expect("fixture run directory"))
}

fn run_fixture_driver() {
    let run_dir = fixture_run_dir();
    std::fs::write(
        run_dir.join(".codex-lane.lock"),
        format!("{}\n", std::process::id()),
    )
    .expect("write driver lock");
    let producer_role = std::env::var_os(FIXTURE_PRODUCER_ROLE).expect("producer fixture role");
    let mut producer = fixture_command()
        .env(FIXTURE_ROLE, producer_role)
        .env(FIXTURE_RUN_DIR, &run_dir)
        .spawn()
        .expect("spawn fixture producer");
    std::fs::write(
        run_dir.join("fixture-producer-pid"),
        format!("{}\n", producer.id()),
    )
    .expect("write fixture producer pid");
    assert!(
        producer
            .wait()
            .expect("wait for fixture producer")
            .success()
    );
}

fn run_socket_producer() {
    let port = std::env::var(FIXTURE_PORT)
        .expect("fixture listener port")
        .parse::<u16>()
        .expect("decimal fixture listener port");
    let _stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect fixture producer socket");
    std::thread::sleep(Duration::from_secs(3));
}

fn run_io_producer() {
    let run_dir = fixture_run_dir();
    let mut sink = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open fixture I/O sink");
    std::fs::write(run_dir.join("fixture-ready"), b"ready\n").expect("publish fixture readiness");
    let bytes = [0_u8; 4096];
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        sink.write_all(&bytes).expect("write fixture I/O");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn spawn_fixture_driver(directory: &TestDir, producer_role: &str) -> Child {
    fixture_command()
        .env(FIXTURE_ROLE, "driver")
        .env(FIXTURE_PRODUCER_ROLE, producer_role)
        .env(FIXTURE_RUN_DIR, directory.path())
        .spawn()
        .expect("spawn fixture driver")
}

fn wait_for_fixture_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "fixture readiness timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn fixture_producer_pid(directory: &TestDir) -> u32 {
    wait_for_fixture_file(&directory.path().join("fixture-producer-pid"));
    std::fs::read_to_string(directory.path().join("fixture-producer-pid"))
        .expect("read fixture producer pid")
        .trim()
        .parse()
        .expect("decimal fixture producer pid")
}

fn stop_fixture_driver(driver: &mut Child) {
    let _already_exited = driver.kill();
    driver.wait().expect("reap fixture driver");
}

/// ´test:integration:stale-events-with-established-socket-are-generating´
#[test]
fn stale_events_with_established_socket_are_generating() {
    if run_fixture_process() {
        return;
    }
    let directory = TestDir::new("liveness-socket");
    write_events(&directory, b"{\"type\":\"socket.wait\"}\n", 600);
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture listener");
    let port = listener
        .local_addr()
        .expect("fixture listener address")
        .port();
    let mut driver = fixture_command()
        .env(FIXTURE_ROLE, "driver")
        .env(FIXTURE_PRODUCER_ROLE, "socket")
        .env(FIXTURE_RUN_DIR, directory.path())
        .env(FIXTURE_PORT, port.to_string())
        .spawn()
        .expect("spawn socket fixture driver");
    let (_fixture_stream, _peer) = listener.accept().expect("accept fixture producer socket");
    let producer_pid = fixture_producer_pid(&directory);

    let output = run([directory.path()]);
    stop_fixture_driver(&mut driver);
    let (evidence, report) = split_watcher_report(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        normalize_age(evidence),
        format!(
            "GENERATING age=Ns events=1 last=socket.wait pid={producer_pid} established=1 io_delta=0\n{{\"type\":\"socket.wait\"}}\n"
        )
        .as_bytes()
    );
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=0 wall=Ns verdict=running\n"
    );
    if let Some(path) = std::env::var_os(FIXTURE_CAPTURE) {
        std::fs::write(path, &output.stdout).expect("write requested fixture capture");
    }
}

/// ´test:integration:stale-events-with-io-movement-are-generating´
#[test]
fn stale_events_with_io_movement_are_generating() {
    let directory = TestDir::new("liveness-io");
    write_events(&directory, b"{\"type\":\"io.write\"}\n", 600);
    let mut driver = spawn_fixture_driver(&directory, "io");
    wait_for_fixture_file(&directory.path().join("fixture-ready"));
    let producer_pid = fixture_producer_pid(&directory);

    let output = run([directory.path()]);
    stop_fixture_driver(&mut driver);
    let (evidence, report) = split_watcher_report(&output.stdout);
    let io_delta = numeric_field(evidence, b"io_delta=", b'\n');

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(io_delta > 0);
    assert_eq!(
        normalize_numeric_field(&normalize_age(evidence), b"io_delta=", b'\n'),
        format!(
            "GENERATING age=Ns events=1 last=io.write pid={producer_pid} established=0 io_delta=N\n{{\"type\":\"io.write\"}}\n"
        )
        .as_bytes()
    );
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=0 wall=Ns verdict=running\n"
    );
}

/// ´test:integration:stale-events-with-dead-driver-lock-remain-stalled´
#[test]
fn stale_events_with_dead_driver_lock_remain_stalled() {
    let directory = TestDir::new("liveness-dead-lock");
    write_events(&directory, b"{\"type\":\"dead.lock\"}\n", 600);
    let mut dead = fixture_command()
        .env(FIXTURE_ROLE, "exit")
        .spawn()
        .expect("spawn dead-pid fixture");
    let dead_pid = dead.id();
    assert!(dead.wait().expect("reap dead-pid fixture").success());
    directory.write(".codex-lane.lock", format!("{dead_pid}\n").as_bytes());

    let output = run([directory.path()]);
    let (evidence, report) = split_watcher_report(&output.stdout);

    assert_eq!(output.status.code(), Some(42));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        normalize_age(evidence),
        format!(
            "STALLED age=Ns events=1 last=dead.lock pid={dead_pid} established=0 io_delta=0\n{{\"type\":\"dead.lock\"}}\n"
        )
        .as_bytes()
    );
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=42 wall=Ns verdict=stalled\n"
    );
}

/// ´test:integration:stale-events-without-driver-lock-remain-stalled´
#[test]
fn stale_events_without_driver_lock_remain_stalled() {
    let directory = TestDir::new("liveness-no-lock");
    write_events(&directory, b"{\"type\":\"no.lock\"}\n", 600);

    let output = run([directory.path()]);
    let (evidence, report) = split_watcher_report(&output.stdout);

    assert_eq!(output.status.code(), Some(42));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        normalize_age(evidence),
        b"STALLED age=Ns events=1 last=no.lock pid=none established=0 io_delta=0\n{\"type\":\"no.lock\"}\n"
    );
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=42 wall=Ns verdict=stalled\n"
    );
}

/// ´test:integration:oracle-complete-report-is-verbatim-evidence-before-watcher-report´
#[test]
fn oracle_complete_report_is_verbatim_evidence_before_watcher_report() {
    let directory = TestDir::new("oracle-complete");
    directory.write(
        "run-report.txt",
        b"RUN-REPORT lane=oracle exit=0 wall=1s budget=2s verdict=ok dir=oracle\n",
    );

    assert_oracle_observation(&directory, "complete-with-report", None, "completed");
}

/// ´test:integration:oracle-missing-events-is-byte-exact-after-watcher-report-divergence´
#[test]
fn oracle_missing_events_is_byte_exact_after_watcher_report_divergence() {
    let directory = TestDir::new("oracle-missing-events");

    assert_oracle_observation(&directory, "missing-events", None, "stalled");
}

/// ´test:integration:oracle-fresh-one-line-evidence-is-byte-exact-after-age-normalization´
#[test]
fn oracle_fresh_one_line_evidence_is_byte_exact_after_age_normalization() {
    let directory = TestDir::new("oracle-fresh-one");
    write_events(
        &directory,
        b"{\"type\":\"agent_message\",\"message\":\"one\"}\n",
        10,
    );

    assert_oracle_observation(&directory, "fresh-one-line", None, "running");
}

/// ´test:integration:oracle-fresh-multi-line-evidence-is-byte-exact-after-age-normalization´
#[test]
fn oracle_fresh_multi_line_evidence_is_byte_exact_after_age_normalization() {
    let directory = TestDir::new("oracle-fresh-multi");
    write_events(
        &directory,
        b"{\"type\":\"thread.started\"}\n{\"type\" : \"item.completed\"}\n",
        20,
    );

    assert_oracle_observation(&directory, "fresh-multi-line", None, "running");
}

/// ´test:integration:oracle-stalled-one-line-evidence-and-tail-are-byte-exact´
#[test]
fn oracle_stalled_one_line_evidence_and_tail_are_byte_exact() {
    let directory = TestDir::new("oracle-stalled-one");
    write_events(
        &directory,
        b"{\"type\":\"agent_message\",\"message\":\"quiet\"}\n",
        360,
    );

    assert_oracle_observation(&directory, "stalled-one-line", None, "stalled");
}

/// ´test:integration:oracle-stalled-multi-line-evidence-and-tail-are-byte-exact´
#[test]
fn oracle_stalled_multi_line_evidence_and_tail_are_byte_exact() {
    let directory = TestDir::new("oracle-stalled-multi");
    write_events(
        &directory,
        b"{\"type\":\"thread.started\"}\n{\"type\" : \"item.completed\",\"detail\":\"last\"}\n",
        420,
    );

    assert_oracle_observation(&directory, "stalled-multi-line", None, "stalled");
}

/// ´test:integration:oracle-empty-fresh-source-is-byte-exact´
#[test]
fn oracle_empty_fresh_source_is_byte_exact() {
    let directory = TestDir::new("oracle-empty-fresh");
    write_events(&directory, b"", 5);

    assert_oracle_observation(&directory, "empty-fresh", None, "running");
}

/// ´test:integration:oracle-empty-stalled-source-preserves-blank-last-event´
#[test]
fn oracle_empty_stalled_source_preserves_blank_last_event() {
    let directory = TestDir::new("oracle-empty-stalled");
    write_events(&directory, b"", 600);

    assert_oracle_observation(&directory, "empty-stalled", None, "stalled");
}

/// ´test:integration:oracle-explicit-window-can-keep-an-old-event-fresh´
#[test]
fn oracle_explicit_window_can_keep_an_old_event_fresh() {
    let directory = TestDir::new("oracle-window-fresh");
    write_events(&directory, b"{\"type\":\"window.fresh\"}\n", 40);

    assert_oracle_observation(&directory, "explicit-window-fresh", Some("60"), "running");
}

/// ´test:integration:oracle-explicit-window-equality-is-stalled´
#[test]
fn oracle_explicit_window_equality_is_stalled() {
    let directory = TestDir::new("oracle-window-stalled");
    write_events(&directory, b"{\"type\":\"window.stalled\"}\n", 30);

    assert_oracle_observation(&directory, "explicit-window-stalled", Some("30"), "stalled");
}

/// ´test:integration:governed-failed-lane-report-is-successful-failed-observation´
#[test]
fn governed_failed_lane_report_is_successful_failed_observation() {
    let directory = TestDir::new("governed-failed-report");
    let stored = b"RUN-REPORT lane=x exit=1 wall=1s budget=2s verdict=FAILED dir=x\n";
    directory.write("run-report.txt", stored);

    let output = run([directory.path()]);
    let (evidence, report) = split_watcher_report(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(evidence, stored);
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=0 wall=Ns verdict=failed\n"
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:governed-report-takes-precedence-over-stale-events´
#[test]
fn governed_report_takes_precedence_over_stale_events() {
    let directory = TestDir::new("governed-report-precedence");
    let stored = b"RUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n";
    directory.write("run-report.txt", stored);
    write_events(&directory, b"{\"type\":\"stale\"}\n", 10_000);

    let output = run([directory.path()]);
    let (evidence, report) = split_watcher_report(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(evidence, stored);
    assert_eq!(
        normalize_wall(report),
        b"RUN-REPORT exit=0 wall=Ns verdict=completed\n"
    );
}

/// ´test:integration:governed-malformed-report-is-runtime-failure-instead-of-shell-completion´
#[test]
fn governed_malformed_report_is_runtime_failure_instead_of_shell_completion() {
    let directory = TestDir::new("governed-malformed-report");
    directory.write("run-report.txt", b"not a governed report\n");

    let output = run([directory.path()]);

    assert_runtime_failure(&output, REPORT_CONTRACT_DIAGNOSTIC);
}

/// ´test:integration:governed-unterminated-report-is-runtime-failure´
#[test]
fn governed_unterminated_report_is_runtime_failure() {
    let directory = TestDir::new("governed-unterminated-report");
    directory.write("run-report.txt", b"RUN-REPORT exit=0 verdict=ok");

    let output = run([directory.path()]);

    assert_runtime_failure(&output, REPORT_CONTRACT_DIAGNOSTIC);
}

/// ´test:integration:shell-usage-no-arguments-is-replaced-by-classed-governed-diagnostic´
#[test]
fn shell_usage_no_arguments_is_replaced_by_classed_governed_diagnostic() {
    let output = run(Vec::<OsString>::new());
    let shell_stderr = fixture("usage-no-arguments", "stderr");

    assert_eq!(fixture_status("usage-no-arguments"), 2);
    assert_ne!(shell_stderr, USAGE_DIAGNOSTIC);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, fixture("usage-no-arguments", "stdout"));
    assert_eq!(output.stderr, USAGE_DIAGNOSTIC);
}

/// ´test:integration:shell-invalid-directory-usage-is-replaced-without-echoing-path´
#[test]
fn shell_invalid_directory_usage_is_replaced_without_echoing_path() {
    let directory = TestDir::new("usage-invalid-directory");
    let missing = directory.path().join("SHOULD_NOT_APPEAR-secret-path");

    let output = run([missing]);

    assert_eq!(fixture_status("usage-invalid-directory"), 2);
    assert_ne!(
        fixture("usage-invalid-directory", "stderr"),
        USAGE_DIAGNOSTIC
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, USAGE_DIAGNOSTIC);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SHOULD_NOT_APPEAR"));
}

/// ´test:integration:negative-threshold-is-governed-usage-failure´
#[test]
fn negative_threshold_is_governed_usage_failure() {
    let directory = TestDir::new("usage-negative-threshold");
    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("-1"),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, USAGE_DIAGNOSTIC);
}

/// ´test:integration:nonnumeric-threshold-is-usage-failure-without-echoing-value´
#[test]
fn nonnumeric_threshold_is_usage_failure_without_echoing_value() {
    let directory = TestDir::new("usage-secret-threshold");
    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("SHOULD_NOT_APPEAR-secret-threshold"),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, USAGE_DIAGNOSTIC);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SHOULD_NOT_APPEAR"));
}

/// ´test:integration:extra-argument-is-usage-failure-with-empty-stdout´
#[test]
fn extra_argument_is_usage_failure_with_empty_stdout() {
    let directory = TestDir::new("usage-extra");
    let output = run([
        directory.path().as_os_str().to_os_string(),
        OsString::from("10"),
        OsString::from("extra"),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, USAGE_DIAGNOSTIC);
}

/// ´test:integration:report-directory-is-classed-runtime-failure´
#[test]
fn report_directory_is_classed_runtime_failure() {
    let directory = TestDir::new("runtime-report-directory");
    directory.mkdir("run-report.txt");

    let output = run([directory.path()]);

    assert_runtime_failure(&output, REPORT_READ_DIAGNOSTIC);
}

/// ´test:integration:event-directory-is-classed-runtime-failure´
#[test]
fn event_directory_is_classed_runtime_failure() {
    let directory = TestDir::new("runtime-event-directory");
    directory.mkdir("events.jsonl");

    let output = run([directory.path()]);

    assert_runtime_failure(&output, EVENT_SOURCE_DIAGNOSTIC);
}

/// ´test:integration:runtime-diagnostic-precedes-one-final-failed-report´
#[test]
fn runtime_diagnostic_precedes_one_final_failed_report() {
    let directory = TestDir::new("runtime-final-report");
    directory.mkdir("events.jsonl");

    let output = run([directory.path()]);
    let occurrences = output
        .stdout
        .windows(b"RUN-REPORT".len())
        .filter(|window| *window == b"RUN-REPORT")
        .count();

    assert_eq!(occurrences, 1);
    assert!(output.stdout.starts_with(EVENT_SOURCE_DIAGNOSTIC));
    assert!(output.stdout.ends_with(b"verdict=FAILED\n"));
}

/// ´test:integration:runtime-failure-never-writes-run-directory-state´
#[test]
fn runtime_failure_never_writes_run_directory_state() {
    let directory = TestDir::new("runtime-read-only");
    directory.mkdir("events.jsonl");
    directory.write(".feed-offset", b"23\n");
    let before = directory.entry_names();

    let output = run([directory.path()]);

    assert_runtime_failure(&output, EVENT_SOURCE_DIAGNOSTIC);
    assert_eq!(directory.entry_names(), before);
    assert_eq!(directory.read(".feed-offset"), b"23\n");
}

/// ´test:integration:stdout-pipe-and-regular-file-receive-same-normalized-observation´
#[test]
fn stdout_pipe_and_regular_file_receive_same_normalized_observation() {
    let stored = b"RUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n";
    let piped_directory = TestDir::new("stream-pipe");
    piped_directory.write("run-report.txt", stored);
    let piped = run([piped_directory.path()]);

    let file_directory = TestDir::new("stream-file");
    file_directory.write("run-report.txt", stored);
    let capture_directory = TestDir::new("stream-capture");
    let capture = capture_directory.path().join("stdout.bin");
    let stdout_file = File::create(&capture).expect("create stdout capture");
    let file_output = lane_watch()
        .arg(file_directory.path())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::piped())
        .output()
        .expect("lane-watch with file stdout runs");
    let file_bytes = std::fs::read(capture).expect("read stdout capture");

    assert_eq!(piped.status.code(), Some(0));
    assert_eq!(file_output.status.code(), Some(0));
    assert_eq!(file_output.stdout, [] as [u8; 0]);
    assert_eq!(file_output.stderr, [] as [u8; 0]);
    let (file_evidence, file_report) = split_watcher_report(&file_bytes);
    let (piped_evidence, piped_report) = split_watcher_report(&piped.stdout);
    assert_eq!(file_evidence, piped_evidence);
    assert_eq!(normalize_wall(file_report), normalize_wall(piped_report));
}

/// ´test:integration:missing-events-observation-creates-no-run-directory-entry´
#[test]
fn missing_events_observation_creates_no_run_directory_entry() {
    let directory = TestDir::new("state-missing-events");
    let before = directory.entry_names();

    let output = run([directory.path()]);

    assert_eq!(output.status.code(), Some(42));
    assert_eq!(directory.entry_names(), before);
}

/// ´test:integration:event-observation-preserves-existing-offset-and-event-bytes´
#[test]
fn event_observation_preserves_existing_offset_and_event_bytes() {
    let directory = TestDir::new("state-events");
    let events = b"{\"type\":\"read-only\"}\n";
    write_events(&directory, events, 1);
    directory.write(".feed-offset", b"91\n");
    let before = directory.entry_names();
    let before_modified = directory.modified("events.jsonl");

    let output = run([directory.path()]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(directory.entry_names(), before);
    assert_eq!(directory.read("events.jsonl"), events);
    assert_eq!(directory.read(".feed-offset"), b"91\n");
    assert_eq!(directory.modified("events.jsonl"), before_modified);
}

/// ´test:integration:completion-observation-preserves-report-and-existing-offset´
#[test]
fn completion_observation_preserves_report_and_existing_offset() {
    let directory = TestDir::new("state-report");
    let stored = b"RUN-REPORT lane=x exit=0 wall=1s budget=2s verdict=ok dir=x\n";
    directory.write("run-report.txt", stored);
    directory.write(".feed-offset", b"44\n");
    let before = directory.entry_names();

    let output = run([directory.path()]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(directory.entry_names(), before);
    assert_eq!(directory.read("run-report.txt"), stored);
    assert_eq!(directory.read(".feed-offset"), b"44\n");
}
