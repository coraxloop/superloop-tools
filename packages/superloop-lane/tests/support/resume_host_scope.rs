//! One real transient scope per acceptance; its parent owns the fixture root.
use crate::{fixture::bounded::CommandOutput as _, host};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::time::{Duration, Instant};

struct Scope {
    unit: String,
    fixture: Option<host::Host>,
    stopped: bool,
}
impl Scope {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unit = format!(
            "superloop-lane-run-fixture-{}-{}.service",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        Self {
            unit,
            fixture: Some(host::Host::new()),
            stopped: false,
        }
    }
    fn stop(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        let began = Instant::now();
        let _stop = Command::new("/usr/bin/systemctl")
            .args(["--user", "stop", &self.unit])
            .fixture_output("scope stop", Duration::from_secs(30))?;
        let state = Command::new("/usr/bin/systemctl")
            .args([
                "--user",
                "show",
                &self.unit,
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "ControlGroup",
            ])
            .fixture_output("scope absence", Duration::from_secs(30))?;
        let text = String::from_utf8_lossy(&state.stdout);
        if !text.lines().any(|s| s == "ActiveState=inactive")
            || !text.lines().any(|s| s == "ControlGroup=")
        {
            return Err(format!("scope absence unconfirmed: {state:?}"));
        }
        self.stopped = true;
        writeln!(
            std::io::stderr().lock(),
            "SCOPE-CLEANUP-WALL seconds={:.6}",
            began.elapsed().as_secs_f64()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            std::io::stdout().lock(),
            "SCOPE-GONE {} {}",
            self.unit,
            text.replace('\n', " ")
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
    fn execute(&self, case: &str) -> Result<std::process::Output, String> {
        let fixture = self.fixture.as_ref().expect("owned root");
        let meta = std::fs::symlink_metadata(fixture.home()).expect("held fixture identity");
        let began = Instant::now();
        let output = Command::new("/usr/bin/systemd-run")
            .args(["--user", "--quiet", "--wait", "--pipe", "--collect"])
            .arg(format!("--unit={}", self.unit))
            .args([
                "--property=Delegate=yes",
                "--property=KillMode=control-group",
                "--property=ExitType=main",
            ])
            .arg(format!("--setenv=SUPERLOOP_RUN_SCOPE_UNIT={}", self.unit))
            .arg("--setenv=SUPERLOOP_SCOPE_OBSERVING=1")
            .arg(format!(
                "--setenv=TMPDIR={}",
                std::env::temp_dir().display()
            ))
            .arg(std::env::current_exe().expect("fixture executable"))
            .args(["--fixture-scope", case])
            .arg(fixture.home())
            .arg(meta.dev().to_string())
            .arg(meta.ino().to_string())
            .fixture_output("complete public host launch", Duration::from_secs(180));
        writeln!(
            std::io::stderr().lock(),
            "SCOPE-WALL {case} seconds={:.6}",
            began.elapsed().as_secs_f64()
        )
        .expect("scope wall measurement");
        output
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            if let Some(root) = self.fixture.take() {
                std::mem::forget(root);
            }
            let _report = writeln!(std::io::stderr().lock(), "retained fixture after {error}");
        }
    }
}
pub(super) fn run(case: &str) {
    let mut scope = Scope::new();
    let result = scope.execute(case);
    let stopped = scope.stop();
    assert!(stopped.is_ok(), "{stopped:?}");
    if let Ok(metrics) = std::fs::read_to_string(
        scope
            .fixture
            .as_ref()
            .expect("owned root")
            .home()
            .join("wait-measurements.json"),
    ) {
        writeln!(std::io::stderr().lock(), "WAIT-MEASURE {case} {metrics}")
            .expect("wait measurements");
    }
    let output = result.expect("bounded scoped command");
    assert!(output.status.success(), "{output:?}");
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("scope evidence");
    std::io::stderr()
        .lock()
        .write_all(&output.stderr)
        .expect("scope diagnostics");
}

pub(super) fn child(args: &[String]) -> std::process::ExitCode {
    let [case, home, device, inode] = args else {
        panic!("scope arguments");
    };
    let fixture = host::Host::borrowed(
        home.into(),
        (
            device.parse().expect("device"),
            inode.parse().expect("inode"),
        ),
    );
    if let Some(control) = case.strip_prefix("retained-") {
        crate::retained::run(&fixture, control);
        return std::process::ExitCode::SUCCESS;
    }
    if let Some((fault, history)) = case.split_once(':') {
        crate::refusals::run(&fixture, fault, history == "failed");
        return std::process::ExitCode::SUCCESS;
    }
    if case == "stop-race" {
        let error = fixture.launch(false).expect_err("real helper stop refuses");
        assert_eq!(error.kind, "helper-stop", "{error}");
        writeln!(std::io::stdout().lock(), "STOP-RACE {error}").expect("refusal");
        let record: serde_json::Value =
            serde_json::from_slice(&fixture.reservation()).expect("race record");
        assert_eq!(record["phase"], "started");
        assert_eq!(record["rounds"][1]["phase"], "awaiting-settlement");
        assert_eq!(record["driver_end"]["successful"], true);
        assert_eq!(record["helper_end"], serde_json::Value::Null);
        return std::process::ExitCode::SUCCESS;
    }
    assert_eq!(case, "success");
    let report = fixture
        .launch(false)
        .expect("complete public host launch succeeds");
    assert_eq!(report["thread_id"], "fixture-thread", "{report}");
    let record: serde_json::Value =
        serde_json::from_slice(&fixture.reservation()).expect("settled record");
    assert_eq!(record["phase"], "settled", "{record}");
    assert_eq!(record["rounds"][1]["phase"], "settled", "{record}");
    assert_eq!(record["rounds"][1]["step"], "review");
    assert!(
        record.get("round_rollback").is_none(),
        "dispatch consumed before-image"
    );
    assert!(
        record.get("dispatch_intent").is_none(),
        "dispatch consumed intent"
    );
    writeln!(
        std::io::stdout().lock(),
        "PUBLIC-LAUNCH-PASSED scope={} helper={} driver={}",
        record["run_scope"]["unit"],
        record["helper_pid"],
        record["driver_entry_pid"]
    )
    .expect("scope result");
    std::process::ExitCode::SUCCESS
}

pub(super) fn assert_work_empty() {
    let current = std::fs::read_to_string("/proc/self/cgroup").expect("real launcher cgroup");
    let service = current
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup");
    let unit = std::env::var("SUPERLOOP_RUN_SCOPE_UNIT").expect("scope unit");
    assert_eq!(
        std::path::Path::new(service)
            .file_name()
            .and_then(|s| s.to_str()),
        Some(unit.as_str())
    );
    let events = std::fs::read_to_string(
        std::path::Path::new("/sys/fs/cgroup")
            .join(service.trim_start_matches('/'))
            .join("work/cgroup.events"),
    )
    .expect("real work cgroup events");
    assert!(
        events.lines().any(|line| line == "populated 0"),
        "restored refusal leaves no work process: {events}"
    );
}

/// Rehearse recovery only after the launcher's complete work scope is gone.
pub(super) fn recover_stop_race(reply: bool) {
    let mut scope = Scope::new();
    let fixture = scope.fixture.as_ref().expect("root");
    crate::refusals::install(fixture, "stop-race");
    if !reply {
        host::write(fixture.home().join("without-reply"), b"", 0o600);
    }
    let output = scope.execute("stop-race").expect("scoped race");
    scope.stop().expect("all original processes gone");
    assert!(output.status.success(), "{output:?}");
    let fixture = scope.fixture.as_ref().expect("retained fixture");
    let hit = std::fs::read_to_string(fixture.home().join("fault-hit")).expect("close point");
    assert!(
        hit.lines()
            .any(|s| s == "control unlinked before helper exit"),
        "{hit}"
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fixture.reservation()).expect("race record");
    let mut request = superloop_lane::launch::LaunchRequest::parse(&[
        "alpha".into(),
        "R".into(),
        "--letter".into(),
        record["letter_source"]
            .as_str()
            .expect("retained letter")
            .into(),
        "--observe".into(),
        "--dry-run".into(),
    ])
    .expect("first-dispatch recovery form");
    request.podman_bin = fixture.home().join("container-fixture");
    let before = fixture.reservation();
    let inventory = fixture.inventory();
    assert_eq!(
        record["mail_replies"].as_array().expect("replies").len(),
        usize::from(reply)
    );
    let error = superloop_lane::launch::run(fixture.home(), &request)
        .expect_err("known first-dispatch retained-letter recovery barrier");
    let direct =
        superloop_lane::home::read_letter(&request.letter, nix::unistd::Uid::effective().as_raw())
            .expect_err("same owner-letter reader cannot enter the loop-owned run");
    assert_eq!(error.kind, "unsafe-path", "{error}");
    assert_eq!(
        error.line(),
        direct.line(),
        "first-dispatch owner-letter refusal"
    );
    assert!(error.detail.contains("/runs/R: EACCES"), "{error}");
    assert_eq!(
        fixture.reservation(),
        before,
        "refused recovery preserves raw reservation"
    );
    assert_eq!(
        fixture.inventory(),
        inventory,
        "refused recovery writes no run files"
    );
    writeln!(std::io::stdout().lock(),
        "RECOVERY-BARRIER reply={reply} phase={} round={} driver={} helper={} source={} error={error}",
        record["phase"], record["rounds"][1]["phase"], record["driver_end"],
        record["helper_end"], record["letter_source"],
    ).expect("recovery finding");
}
