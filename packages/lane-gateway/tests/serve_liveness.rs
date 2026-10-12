//! Process-level contract for loud serve failure and fixed liveness artifacts.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`serve_error_exits_nonzero_with_crash_report`] |  | — |
//! | [`serve_terminated_by_sigterm_records_a_stopped_heartbeat`] |  | — |
//! | [`serve_terminated_by_sighup_records_a_stopped_heartbeat`] |  | — |
//! | [`serve_terminated_by_sigint_records_a_stopped_heartbeat`] |  | — |

use std::fs;
mod support;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// How long a signalled serve subprocess is given to exit on its own.
///
/// A signalled serve stops at its next check, one configured 5 ms poll
/// interval away, and then only joins its publisher and renames one file, so
/// the real budget is milliseconds. Ten seconds is the deadline
/// [`wait_for_heartbeat`] already uses, three orders of magnitude above that
/// budget: it separates a process that is genuinely stuck from one that is
/// merely slow on a loaded host. The bound exists because the alternative is
/// an unbounded wait, which turns a stuck serve into a test run that hangs
/// until someone kills it by hand instead of a failure report.
const SERVE_EXIT_DEADLINE: Duration = Duration::from_secs(10);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lane-gateway-serve-process-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("process test directory is created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

/// A serve subprocess that is killed when its scope ends.
///
/// An assertion that fails before the test delivers its signal unwinds out of
/// the test body with the child still serving. That child would keep
/// publishing into a directory [`TestDirectory`] is about to remove and would
/// outlive the test run itself, so every exit from a test that holds one —
/// assertion failure included — goes through this kill.
struct ServeChild {
    child: Child,
}

impl ServeChild {
    fn spawn(command: &mut Command) -> Self {
        Self {
            child: command
                .spawn()
                .expect("lane-gateway serve subprocess starts"),
        }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn signal(&self, signal: Signal) {
        kill(
            Pid::from_raw(i32::try_from(self.id()).expect("child pid fits a signal target")),
            signal,
        )
        .expect("signal reaches the serve subprocess");
    }

    /// Wait for the child to exit within [`SERVE_EXIT_DEADLINE`].
    ///
    /// # Panics
    ///
    /// Panics when the child has not exited by the deadline, or when its
    /// status cannot be read; [`Drop`] then kills the child either way.
    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + SERVE_EXIT_DEADLINE;
        loop {
            match self
                .child
                .try_wait()
                .expect("serve subprocess status is readable")
            {
                Some(status) => return status,
                None => assert!(
                    Instant::now() < deadline,
                    "serve subprocess did not exit within {SERVE_EXIT_DEADLINE:?}"
                ),
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ServeChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

fn serve_command(state: &Path, shutdown: &Path) -> Command {
    let (helper, registry, loop_name) = support::settings(state);
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateway-service"));
    command
        .env("SUPERLOOP_GATEWAY_REQUESTS_HELPER", helper)
        .env("PERMISSION_TRIAGE_LOOP_REGISTRY", registry)
        .env("SUPERLOOP_GATEWAY_LOOP", loop_name)
        .arg("serve")
        .env("LANE_GATEWAY_STATE", state)
        .env("LANE_GATEWAY_RUNNER_ARGV", r#"["/bin/false"]"#)
        .env("LANE_GATEWAY_POLL_MILLIS", "5")
        .env("LANE_GATEWAY_HEARTBEAT_MILLIS", "10")
        .env("LANE_GATEWAY_SHUTDOWN_FILE", shutdown);
    command
}

/// A serve-loop filesystem error exits the real CLI nonzero, leaves stdout
/// empty, and publishes crash bytes for the same running heartbeat generation.
///
/// ´test:integration:serve-error-exits-nonzero-with-crash-report´
#[test]
fn serve_error_exits_nonzero_with_crash_report() {
    let directory = TestDirectory::new();
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("process state root is created");
    let blocked_parent = state.join("blocked-shutdown-parent");
    fs::write(&blocked_parent, b"not a directory\n").expect("shutdown parent is blocked");
    let shutdown = blocked_parent.join("shutdown");

    let output = serve_command(&state, &shutdown)
        .output()
        .expect("lane-gateway serve subprocess runs");
    assert!(!output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("gateway read_shutdown_flag failed"));

    let crash_source =
        fs::read_to_string(state.join("serve-crash.json")).expect("crash report is readable");
    let crash: serde_json::Value =
        serde_json::from_str(&crash_source).expect("crash report is strict JSON");
    assert_eq!(
        crash,
        serde_json::json!({
            "schema": 1,
            "pid": crash["pid"],
            "started_unix_ms": crash["started_unix_ms"],
            "failed_unix_ms": crash["failed_unix_ms"],
            "last_activity_unix_ms": crash["last_activity_unix_ms"],
            "failure_kind": "error",
            "message": "gateway read_shutdown_flag failed"
        })
    );

    let heartbeat_source = fs::read_to_string(state.join("serve-heartbeat.json"))
        .expect("last heartbeat of the failed generation is readable");
    let heartbeat: serde_json::Value =
        serde_json::from_str(&heartbeat_source).expect("heartbeat is strict JSON");
    assert_eq!(heartbeat["schema"], 1);
    assert_eq!(heartbeat["pid"], crash["pid"]);
    assert_eq!(heartbeat["started_unix_ms"], crash["started_unix_ms"]);
    assert_eq!(heartbeat["heartbeat_interval_millis"], 10);
    assert_eq!(heartbeat["process_state"], "stopped");
    assert_eq!(heartbeat["stop_reason"], "error");
    assert_eq!(heartbeat["activity"], "started");

    let crash_path = state.join("serve-crash.json");
    fs::remove_file(&crash_path).expect("first crash report is removed for fault injection");
    fs::create_dir(&crash_path).expect("crash report path is blocked by a directory");
    let report_failure = serve_command(&state, &shutdown)
        .output()
        .expect("lane-gateway crash-write-failure subprocess runs");
    assert!(!report_failure.status.success());
    assert_eq!(report_failure.stdout, [] as [u8; 0]);
    let diagnostics: Vec<serde_json::Value> = String::from_utf8(report_failure.stderr)
        .expect("crash-write diagnostics are UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("diagnostic line is machine JSON"))
        .collect();
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics[0]["message"],
        "gateway read_shutdown_flag failed"
    );
    assert_eq!(diagnostics[1]["message"], "serve crash report write failed");
}

/// A serve killed by its parent's SIGTERM records its own stop and names the
/// signal, so a reader never has to guess why the heartbeat went quiet.
///
/// ´test:integration:serve-terminated-by-sigterm-records-a-stopped-heartbeat´
#[test]
fn serve_terminated_by_sigterm_records_a_stopped_heartbeat() {
    assert_signal_stops_serve(Signal::SIGTERM, "signal_terminate");
}

/// A serve whose session goes away takes SIGHUP, which is the delivery a
/// detached terminal or a departing supervisor actually makes, and records it
/// by name rather than dying with the default disposition.
///
/// ´test:integration:serve-terminated-by-sighup-records-a-stopped-heartbeat´
#[test]
fn serve_terminated_by_sighup_records_a_stopped_heartbeat() {
    assert_signal_stops_serve(Signal::SIGHUP, "signal_hangup");
}

/// An interactive interrupt stops the same way and is named apart from a
/// supervisor's SIGTERM, so a reader can tell an operator from a service
/// manager without another source.
///
/// ´test:integration:serve-terminated-by-sigint-records-a-stopped-heartbeat´
#[test]
fn serve_terminated_by_sigint_records_a_stopped_heartbeat() {
    assert_signal_stops_serve(Signal::SIGINT, "signal_interrupt");
}

/// Signal a running serve subprocess and read the heartbeat it left behind.
///
/// The mechanic is POSIX: the test signals a real subprocess and reads the
/// artifact the subprocess left behind, so it is meaningful only on a platform
/// with process signals, which is every platform this gateway serves on.
fn assert_signal_stops_serve(signal: Signal, stop_reason: &str) {
    let directory = TestDirectory::new();
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("signal test state root is created");
    let shutdown = state.join("shutdown");
    let heartbeat_path = state.join("serve-heartbeat.json");
    let mut child = ServeChild::spawn(&mut serve_command(&state, &shutdown));
    let running = wait_for_heartbeat(&heartbeat_path, "running");
    assert_eq!(running["pid"], child.id());
    assert_eq!(running["heartbeat_interval_millis"], 10);
    assert_eq!(running["stop_reason"], serde_json::Value::Null);

    child.signal(signal);
    let status = child.wait_bounded();
    assert!(status.success());

    let stopped = read_heartbeat(&heartbeat_path);
    assert_eq!(stopped["pid"], running["pid"]);
    assert_eq!(stopped["process_state"], "stopped");
    assert_eq!(stopped["stop_reason"], stop_reason);
    assert_eq!(stopped["activity"], "signal_stop");
    assert!(!state.join("serve-crash.json").exists());
}

fn read_heartbeat(path: &Path) -> serde_json::Value {
    let source = fs::read_to_string(path).expect("heartbeat is readable");
    serde_json::from_str(&source).expect("heartbeat is strict JSON")
}

fn wait_for_heartbeat(path: &Path, process_state: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(source) = fs::read_to_string(path)
            && let Ok(heartbeat) = serde_json::from_str::<serde_json::Value>(&source)
            && heartbeat["process_state"] == process_state
        {
            return heartbeat;
        }
        assert!(
            Instant::now() < deadline,
            "serve heartbeat did not reach {process_state}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
