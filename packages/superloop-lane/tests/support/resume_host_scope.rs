//! One real transient scope per acceptance; its parent owns the fixture root.
use crate::{fixture::bounded::CommandOutput as _, host};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::time::Duration;

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
        Command::new("/usr/bin/systemd-run")
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
            .fixture_output("complete public host launch", Duration::from_secs(180))
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
    let output = result.expect("bounded scoped command");
    assert!(output.status.success(), "{output:?}");
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("scope evidence");
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
