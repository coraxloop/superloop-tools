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

fn next_round(fixture: &host::Host, choose: bool) -> std::process::ExitCode {
    let report = fixture
        .next_launch(choose, false)
        .expect("next real public launch");
    let saved: serde_json::Value =
        serde_json::from_slice(&fixture.reservation()).expect("next record");
    assert_eq!(saved["phase"], "settled", "{report}");
    assert_eq!(saved["active_round"], "after");
    assert_eq!(
        saved["rounds"]
            .as_array()
            .expect("round rows")
            .last()
            .expect("next row")["phase"],
        "settled"
    );
    assert_eq!(saved["thread_id"], "fixture-thread");
    assert_eq!(saved["driver_end"]["successful"], true);
    assert_eq!(saved["helper_end"]["successful"], true);
    writeln!(
        std::io::stdout().lock(),
        "NEXT-ROUND-SETTLED choice={choose}"
    )
    .expect("next result");
    std::process::ExitCode::SUCCESS
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
    if case == "after-reply" || case == "after-failed" {
        return next_round(&fixture, case == "after-failed");
    }
    if case == "late-reply" {
        return late_reply_child(&fixture);
    }
    if case == "stop-race" {
        let error = fixture.launch(false).expect_err("real helper stop refuses");
        assert_eq!(error.kind, "helper-stop", "{error}");
        assert!(
            error.detail.contains("within 0 seconds"),
            "fixture stop bound reached: {error}"
        );
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
fn stopped_race(reply: bool) -> Scope {
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
    scope
}

fn assert_retained_letter_barrier(fixture: &host::Host, reply: bool) {
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

pub(super) fn complete_stop_race(reply: bool) {
    let mut scope = stopped_race(reply);
    let fixture = scope.fixture.as_ref().expect("retained fixture");
    assert_retained_letter_barrier(fixture, reply);
    let before = fixture.reservation();
    let preview = fixture
        .recover(None)
        .expect("public interrupted round preview");
    assert_eq!(
        fixture.reservation(),
        before,
        "recovery preview writes nothing"
    );
    let digest = preview["interrupted_settlement"]["preview_sha256"]
        .as_str()
        .expect("digest");
    let report = fixture
        .recover(Some(digest))
        .expect("digest-bound recovery apply");
    let saved: serde_json::Value =
        serde_json::from_slice(&fixture.reservation()).expect("recovered");
    assert_eq!(
        saved["phase"],
        if reply { "settled" } else { "failed" },
        "{report}"
    );
    if !reply {
        let preview = fixture
            .settle(None)
            .expect("failed recovery settlement preview");
        let digest = preview["preview_sha256"].as_str().expect("settle digest");
        let settled = fixture
            .settle(Some(digest))
            .expect("failed recovery settlement apply");
        writeln!(std::io::stdout().lock(), "FAILED-SETTLED {settled}").expect("report");
    }
    let before = fixture.reservation();
    let preview = fixture.next_launch(false, true);
    if reply {
        let preview = preview.expect("reply resumes without a choice");
        assert_eq!(preview["helper_preflight"]["state"], "passed", "{preview}");
        assert_eq!(preview["thread_id"], "fixture-thread");
        assert_eq!(saved["rounds"][1]["phase"], "settled");
    } else {
        let error = preview.expect_err("failed round still owes a choice");
        assert_eq!(error.kind, "round-choice", "{error}");
        assert!(
            error.detail.contains("--fresh-thread or --resume-thread"),
            "{error}"
        );
        let choice = fixture
            .next_launch(true, true)
            .expect("chosen next preview");
        assert_eq!(choice["helper_preflight"]["state"], "passed", "{choice}");
        assert_eq!(choice["thread_id"], "fixture-thread");
    }
    // Binding the next letter is separate from launch and may add its binding;
    // neither preview may consume the next round or publish a preparing record.
    let after: serde_json::Value = serde_json::from_slice(&fixture.reservation()).expect("after");
    let before: serde_json::Value = serde_json::from_slice(&before).expect("before");
    assert_eq!(after["phase"], "settled");
    assert_eq!(after["rounds"], before["rounds"]);
    writeln!(std::io::stdout().lock(), "RECOVERY-COMPLETE reply={reply}").expect("report");
    std::fs::remove_file(fixture.home().join("fixture-fault")).expect("remove own injected pause");
    if !reply {
        std::fs::remove_file(fixture.home().join("without-reply")).expect("next reply enabled");
    }
    scope.stopped = false;
    let output = scope.execute(if reply { "after-reply" } else { "after-failed" });
    let stopped = scope.stop();
    assert!(stopped.is_ok(), "{stopped:?}");
    let output = output.expect("next actual scoped launch");
    assert!(
        output.status.success(),
        "next launch after recovery: {output:?}"
    );
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("next launch evidence");
    std::io::stderr()
        .lock()
        .write_all(&output.stderr)
        .expect("next launch diagnostics");
}

fn late_reply_child(fixture: &host::Host) -> std::process::ExitCode {
    let error = fixture
        .launch(false)
        .expect_err("unbound reply refuses readback");
    let driver_failed = fixture.home().join("driver-failed").exists();
    assert_eq!(
        error.kind,
        if driver_failed {
            "driver-launch"
        } else {
            "settle-evidence"
        },
        "{error}"
    );
    assert!(
        error.detail.contains("launch report:"),
        "terminal names published report: {error}"
    );
    assert!(
        error
            .detail
            .contains("This refusal removed no letter from the loop inbox"),
        "terminal explains preserved reply: {error}"
    );
    assert!(
        error
            .detail
            .contains("next command: \"superloop-lane read-launch-report alpha R --round review\""),
        "terminal names executable next command: {error}"
    );
    writeln!(std::io::stdout().lock(), "READBACK-TERMINAL {error}").expect("terminal evidence");
    let saved: serde_json::Value =
        serde_json::from_slice(&fixture.reservation()).expect("failed record");
    assert!(
        saved["rounds"][1]["settlement_error"]
            .as_str()
            .expect("readback refusal")
            .contains("readback: reply has no verified mail binding"),
        "{saved}"
    );
    std::process::ExitCode::SUCCESS
}

pub(super) fn late_reply(driver: &str) {
    let driver_failed = driver == "failed";
    let mut scope = Scope::new();
    let fixture = scope.fixture.as_ref().expect("fixture");
    host::write(fixture.home().join("late-reply"), b"", 0o600);
    if driver_failed {
        host::write(fixture.home().join("driver-failed"), b"", 0o600);
    }
    if driver == "over-budget" {
        host::write(fixture.home().join("over-budget"), b"", 0o600);
    }
    let output = scope.execute("late-reply").expect("real readback refusal");
    scope.stop().expect("scope absent");
    assert!(output.status.success(), "{output:?}");
    writeln!(
        std::io::stdout().lock(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    )
    .expect("terminal capture");
    let fixture = scope.fixture.as_ref().expect("retained fixture");
    let original = fixture.reservation();
    let failed: serde_json::Value = serde_json::from_slice(&original).expect("failed record");
    assert_eq!(failed["phase"], "failed");
    assert_eq!(failed["rounds"][1]["phase"], "failed");
    assert_eq!(
        failed["driver_end"]["successful"], !driver_failed,
        "real driver completion"
    );
    assert!(failed["rounds"][1]["reply"].is_null());
    if driver == "over-budget" {
        assert_eq!(
            failed["rounds"][1]["budget_seconds"], 7200,
            "over-budget report matches launch budget"
        );
        let before = fixture.reservation();
        let error = fixture
            .settle(None)
            .expect_err("unbound over-budget reply refuses settlement");
        assert!(
            error
                .detail
                .contains("absent reply requires a matching completed driver verdict"),
            "{error}"
        );
        assert_eq!(
            fixture.reservation(),
            before,
            "refused preview preserves the late-binding admission"
        );
    }
    readback_refusal_report(fixture, &failed);
    late_reply_refusals(fixture, &failed);
    host::write(
        fixture.home().join("runs/.reservation-R.json"),
        original,
        0o600,
    );
    settle_late_reply(fixture, &failed);
}

fn readback_refusal_report(fixture: &host::Host, failed: &serde_json::Value) {
    let path = fixture.home().join("runs/.report=R=review.json");
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path).expect("refused readback publishes launch report"),
    )
    .expect("launch report");
    assert_eq!(report["settlement"]["state"], "refused");
    assert_eq!(report["settlement"]["detail"], failed["readback_end"]);
    assert_eq!(report["settlement"]["run_phase"], "failed");
    assert_eq!(report["settlement"]["round_phase"], "failed");
    assert_eq!(
        report["settlement"]["next_command"],
        "bind-reply alpha R --step review --delivery UTC_INSTANT"
    );
    writeln!(
        std::io::stdout().lock(),
        "READBACK-REFUSAL-REPORT {}",
        report["settlement"]
    )
    .expect("report evidence");
}

fn settle_late_reply(fixture: &host::Host, failed: &serde_json::Value) {
    let binding = fixture
        .bind_reply()
        .expect("late reply binds after real readback refusal");
    let bound = fixture.reservation();
    let inventory = fixture.inventory();
    let error = fixture
        .bind_reply()
        .expect_err("already-bound failed round refuses a second binding");
    assert_eq!(error.kind, "mail-delivery");
    assert_eq!(
        error.detail,
        "failed reservation already binds a reply for step review; preview recovery with settle alpha R --round review --dry-run",
        "rebind refusal names the binding and recovery route"
    );
    assert_eq!(
        fixture.reservation(),
        bound,
        "binding refusal preserves record"
    );
    assert_eq!(
        fixture.inventory(),
        inventory,
        "binding refusal preserves files"
    );
    let preview = fixture
        .settle(None)
        .expect("bound reply settlement preview");
    assert!(
        !preview["report_archive"].is_null(),
        "refused launch report is archived"
    );
    let digest = preview["preview_sha256"]
        .as_str()
        .expect("settlement digest");
    fixture
        .settle(Some(digest))
        .expect("digest-bound late reply settlement");
    let saved: serde_json::Value = serde_json::from_slice(&fixture.reservation()).expect("settled");
    assert_eq!(saved["phase"], "settled");
    assert_eq!(saved["rounds"][1]["phase"], "settled");
    settled_bound_reply_refuses_without_recovery_remedy(fixture, &fixture.reservation());
    earlier_bound_reply_refuses_without_recovery_remedy(fixture, &fixture.reservation());
    assert_eq!(
        saved["driver_end"], failed["driver_end"],
        "settlement preserves driver failure"
    );
    assert_eq!(
        saved["rounds"][1]["reply"]["sha256"],
        binding["mail"]["evidence_digest"]
    );
    assert_eq!(
        saved["rounds"][1]["reply"]["bytes"],
        binding["mail"]["bytes"]
    );
    let next = fixture
        .next_launch(false, true)
        .expect("late reply owes no thread choice");
    assert_eq!(next["helper_preflight"]["state"], "passed");
}

fn settled_bound_reply_refuses_without_recovery_remedy(fixture: &host::Host, bound: &[u8]) {
    let mut changed: serde_json::Value = serde_json::from_slice(bound).expect("bound record");
    changed["phase"] = serde_json::json!("failed");
    assert_eq!(changed["active_round"], "review");
    assert_eq!(changed["rounds"][1]["phase"], "settled");
    let path = fixture.home().join("runs/.reservation-R.json");
    host::write(
        path.clone(),
        serde_json::to_vec(&changed).expect("record"),
        0o600,
    );
    let before = fixture.reservation();
    let inventory = fixture.inventory();
    let error = fixture
        .bind_reply_for("review")
        .expect_err("settled round is not failed recovery");
    assert_eq!(error.kind, "mail-delivery");
    assert_eq!(
        error.detail, "binding requires a started or settled reservation",
        "settled last round must not advertise failed-round settlement"
    );
    assert_eq!(
        fixture.reservation(),
        before,
        "settled-step refusal preserves record"
    );
    assert_eq!(
        fixture.inventory(),
        inventory,
        "settled-step refusal preserves files"
    );
    host::write(path, bound, 0o600);
}

fn earlier_bound_reply_refuses_without_recovery_remedy(fixture: &host::Host, bound: &[u8]) {
    let mut changed: serde_json::Value = serde_json::from_slice(bound).expect("bound record");
    changed["phase"] = serde_json::json!("failed");
    assert_eq!(changed["rounds"][1]["phase"], "settled");
    changed["active_round"] = serde_json::json!("later");
    changed["rounds"]
        .as_array_mut()
        .expect("rounds")
        .push(serde_json::json!({"step":"later", "phase":"failed", "reply":null}));
    let path = fixture.home().join("runs/.reservation-R.json");
    host::write(
        path.clone(),
        serde_json::to_vec(&changed).expect("later failure"),
        0o600,
    );
    let before = fixture.reservation();
    let inventory = fixture.inventory();
    let error = fixture
        .bind_reply_for("review")
        .expect_err("earlier binding is not active recovery");
    assert_eq!(error.kind, "mail-delivery");
    assert_eq!(
        error.detail, "binding requires a started or settled reservation",
        "earlier bound step must not advertise active-round settlement"
    );
    assert_eq!(
        fixture.reservation(),
        before,
        "earlier-step refusal preserves record"
    );
    assert_eq!(
        fixture.inventory(),
        inventory,
        "earlier-step refusal preserves files"
    );
    host::write(path, bound, 0o600);
}

fn late_reply_refusals(fixture: &host::Host, failed: &serde_json::Value) {
    for shape in ["other-refusal", "existing-reply", "wrong-step"] {
        let mut changed = failed.clone();
        match shape {
            "other-refusal" => {
                changed["rounds"][1]["settlement_error"] =
                    serde_json::json!("settle-evidence: different refusal");
            }
            "existing-reply" => changed["rounds"][1]["reply"] = serde_json::json!({"bytes":1}),
            _ => changed["active_round"] = serde_json::json!("dispatch"),
        }
        host::write(
            fixture.home().join("runs/.reservation-R.json"),
            serde_json::to_vec(&changed).expect("changed record"),
            0o600,
        );
        let before = fixture.reservation();
        let inventory = fixture.inventory();
        let error = fixture
            .bind_reply()
            .expect_err("unrelated or already-replied failed round refuses");
        assert_eq!(error.kind, "mail-delivery", "{shape}: {error}");
        assert_eq!(
            fixture.reservation(),
            before,
            "refusal preserves record: {shape}"
        );
        assert_eq!(
            fixture.inventory(),
            inventory,
            "refusal preserves files: {shape}"
        );
    }
}
