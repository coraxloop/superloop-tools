//! Retry evidence settlement for a driver that has already ended.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::unistd::Uid;
use serde_json::{Value, json};

use super::{
    helper_identity, helper_parent_identity, launch_environment, launcher_identity, lock_mailbox,
    lock_run_preparation, observer_identity, read_reservation, reservation_path, rounds,
};
use crate::container_helper::{ProcessPresence, process_presence};
use crate::error::LaneError;
use crate::{build, home, valid_run_name};

#[derive(Debug)]
pub struct SettleRequest {
    pub loop_name: String,
    pub run: String,
    pub step: String,
    pub dry_run: bool,
    pub expect_digest: Option<String>,
}

impl SettleRequest {
    /// Parse an owner settlement command.
    ///
    /// # Errors
    ///
    /// Refuses an invalid name, missing round, or changing command without a preview digest.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, flag, step, rest @ ..] = args else {
            return Err(usage());
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        if !valid_run_name(run) || flag != "--round" {
            return Err(usage());
        }
        super::letters::valid_step(step)?;
        let (dry_run, expect_digest) = match rest {
            [dry] if dry == "--dry-run" => (true, None),
            [expect, digest]
                if expect == "--expect-digest"
                    && digest.len() == 64
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                (false, Some(digest.clone()))
            }
            _ => return Err(usage()),
        };
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            step: step.clone(),
            dry_run,
            expect_digest,
        })
    }
}

fn usage() -> LaneError {
    LaneError::input(
        "settle-usage",
        "settle LOOP RUN --round STEP {--dry-run|--expect-digest HEX} (HEX is the dry run JSON field preview_sha256, the recorded preview digest)",
    )
}

fn private_words(request: &SettleRequest, owner_home: &Path) -> Result<Vec<String>, LaneError> {
    let mut words = vec![
        "_settle-evidence".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "settle-home")?,
        "--round".into(),
        request.step.clone(),
    ];
    if let Some(digest) = &request.expect_digest {
        words.extend(["--expect-digest".into(), digest.clone()]);
    } else {
        words.push("--dry-run".into());
    }
    Ok(words)
}

/// Run a pinned namespace settlement preview or matching correction.
///
/// # Errors
///
/// Refuses changed evidence, a live driver, or an unsafe owner or run root.
pub fn run(owner_home: &Path, request: &SettleRequest) -> Result<Value, LaneError> {
    run_with_failure_report(owner_home, request, &mut |_| {})
}

/// Run settlement and hand an unsaved recovered report to the caller if publication refuses.
///
/// # Errors
///
/// Refuses changed evidence, a live driver, or report publication.
pub fn run_with_failure_report(
    owner_home: &Path,
    request: &SettleRequest,
    on_failure: &mut dyn FnMut(&Value),
) -> Result<Value, LaneError> {
    let started = Instant::now();
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("settle-record", "runs root is absent"))?;
    let owner = Uid::effective().as_raw();
    let _lease = lock_run_preparation(root, &request.run, owner)?;
    let program = plan.document["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("settle-program", "container program is absent"))?;
    #[cfg(test)]
    let fixture_program = tests::PUBLIC_SETTLE_PROGRAM.with(|program| program.borrow().clone());
    #[cfg(test)]
    let program = fixture_program.as_deref().unwrap_or(program);
    crate::pinned::owner_executable(Path::new(program), owner)?;
    let record = read_reservation(&reservation_path(root, &request.run))?
        .ok_or_else(|| LaneError::input("settle-record", "reservation is absent"))?;
    if super::reaping::recovery_verdict(&record).is_ok()
        && !super::container_absent_for_run(
            Path::new(program),
            owner_home,
            &request.loop_name,
            &request.run,
        )?
    {
        return Err(LaneError::input(
            "settle-live-refusal",
            "labelled container is still present",
        ));
    }
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("settle-program", error.to_string()))?;
    crate::pinned::owner_executable(&exe, owner)?;
    #[cfg(not(test))]
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    #[cfg(test)]
    let verified_home = if fixture_program.is_some() {
        // A temporary fixture cannot supply the root-owned ancestors of a real host home.
        home::verify_host_prefix_from(owner_home, owner_home, owner, owner)?
    } else {
        home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?
    };
    let verified_runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let mut argv = vec![
        "unshare".into(),
        crate::pinned::path_word(&exe, "settle-program")?,
    ];
    argv.extend(private_words(request, owner_home)?);
    let output = build::run_checked_with_private_launch(
        Path::new(program),
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        60,
        "settle-private",
        &verified_home,
        root,
        &verified_runs,
        None,
    )?;
    let mut report: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::input("settle-private", error.to_string()))?;
    if !request.dry_run {
        let settled = read_reservation(&reservation_path(root, &request.run))?
            .ok_or_else(|| LaneError::input("settle-record", "settled reservation is absent"))?;
        publish_settled_report(
            &plan,
            root,
            &verified_runs,
            request,
            &settled,
            &report,
            started.elapsed().as_secs_f64(),
            on_failure,
        )?;
    }
    report["wall_seconds"] = json!(started.elapsed().as_secs_f64());
    Ok(report)
}

fn recovery_basis(
    record: &Value,
    step: &str,
    mut presence: impl FnMut(u32, u64) -> ProcessPresence,
) -> Result<(), LaneError> {
    if record["phase"] != "failed" || record["active_round"] != step {
        return Err(LaneError::input(
            "settle-state-refusal",
            "run is not failed in the selected round",
        ));
    }
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("settle-record", "last round is absent"))?;
    if round["step"] != step || round["phase"] != "failed" {
        return Err(LaneError::input(
            "settle-state-refusal",
            "selected round is not failed",
        ));
    }
    if !round["settlement_error"].is_string()
        && !record["readback_end"]
            .as_str()
            .is_some_and(|end| end.contains("settle-evidence:"))
    {
        return Err(LaneError::input(
            "settle-state-refusal",
            "failed round has no settlement refusal",
        ));
    }
    let recovery = super::reaping::recovery_verdict(record);
    if record["reaping_recovery"]["state"] == "collected" {
        recovery.as_ref().map_err(|error| LaneError {
            status: error.status,
            kind: error.kind,
            detail: format!("{}; consider retire, or retire --confirm-uncertain when settlement_uncertain is true", error.detail),
        })?;
    }
    let recovered = recovery.is_ok();
    if !recovered
        && (record["driver_end"]["state"] != "completed"
            || record["helper_end"]["state"] != "completed")
    {
        return Err(LaneError::input(
            "settle-live-refusal",
            "driver and helper completion are not recorded; recover a dead dispatch with the original launch LOOP RUN --letter FILE --dry-run, then apply that launch with --expect-digest HEX from interrupted_settlement.preview_sha256 instead of --dry-run before settling",
        ));
    }
    if record["observation_end"] != "completed" {
        return Err(LaneError::input(
            "settle-state-refusal",
            "host observation is not complete",
        ));
    }
    if !super::settlement_observer_ready(
        &record["observer_end"],
        record["observer_state"].as_str().unwrap_or_default(),
        record["settlement_uncertain"] != false,
    ) {
        return Err(LaneError::input(
            "settle-state-refusal",
            "observer disposition is not settled",
        ));
    }
    if !recovered {
        super::reaping::reaping_verdict(&record["reaping"])?;
    }
    if super::driver_identity(record)?.is_none() {
        return Err(LaneError::input(
            "settle-presence-refusal",
            "recorded driver identity is absent",
        ));
    }
    let identities = [
        ("launcher", launcher_identity(record)?),
        ("driver", super::driver_identity(record)?),
        ("helper", helper_identity(record)?),
        ("helper parent", helper_parent_identity(record)?),
        ("observer", observer_identity(record)?),
    ];
    for (name, identity) in identities {
        if let Some((pid, start)) = identity {
            match presence(pid, start) {
                ProcessPresence::Absent => {}
                ProcessPresence::Present => {
                    return Err(LaneError::input(
                        "settle-live-refusal",
                        format!("{name} is still alive"),
                    ));
                }
                ProcessPresence::Unknown => {
                    return Err(LaneError::input(
                        "settle-presence-refusal",
                        format!("{name} absence cannot be established"),
                    ));
                }
            }
        }
    }
    Ok(())
}

type SettlementPreview = (PathBuf, Value, String, Vec<Value>, String, Value);

fn preview(
    plan: &crate::plan::Plan,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    owner_uid: u32,
    presence: impl FnMut(u32, u64) -> ProcessPresence,
) -> Result<SettlementPreview, LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("settle-record", "runs root is absent"))?;
    let reservation = reservation_path(root, run);
    let record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("settle-record", "reservation is absent"))?;
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != json!(plan.home)
        || record["plan"]["driver_dir"] != json!(plan.driver_dir)
        || record["worker_uid"] != record["plan"]["worker_uid"]
    {
        return Err(LaneError::input(
            "settle-record",
            "reservation identity differs",
        ));
    }
    recovery_basis(&record, step, presence)?;
    super::verify_settlement_driver_dir(&plan.driver_dir, crate::plan::loop_uid(&plan.document)?)?;
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("settle-record", "round list is absent"))?;
    let round = rounds
        .last()
        .ok_or_else(|| LaneError::input("settle-record", "last round is absent"))?;
    let report_step = (rounds.len() > 1).then_some(step);
    let held_runs = home::pin_parent(root, owner_uid)?;
    let previous_report =
        replaceable_report(&held_runs, plan, &record, run, report_step, owner_uid)?;
    let report_name = super::report::name(run, report_step)?;
    let report_path = root.join(report_name).display().to_string();
    let archive = if previous_report.is_null() {
        Value::Null
    } else {
        let mut archive = super::report::archive_preview(&held_runs, run, report_step)?;
        for key in ["source", "target"] {
            archive[key] =
                json!(root.join(
                    archive[key].as_str().ok_or_else(|| LaneError::input(
                        "launch-report",
                        "archive path is absent"
                    ))?
                ));
        }
        archive
    };
    let readback = settlement_readback(plan, loop_name, run, false, owner_uid, &record)?;
    let recovered = super::reaping::recovery_verdict(&record).is_ok();
    let report_line = if recovered {
        optional_driver_report(plan, &record, round)?
    } else {
        json!(rounds::recovery_report_line(plan, &record, round)?)
    };
    let thread = if readback.is_null() && (recovered || completed_failed_round(&record)) {
        Value::Null
    } else {
        json!(rounds::recovery_thread(plan, &record, round)?)
    };
    let (_, letter_reconciliation) =
        super::letters::reconcile_run(plan, run, owner_home, owner_uid, false)?;
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("settle-record", "worker UID is absent"))?;
    let mut acknowledgments = Vec::new();
    for letter in record["letters"]
        .as_array()
        .ok_or_else(|| LaneError::input("settle-record", "letters are absent"))?
    {
        if !readback.is_null()
            && letter["step"] == step
            && letter["in_round"] == true
            && letter["state"] == "placed"
        {
            let name = letter["name"]
                .as_str()
                .ok_or_else(|| LaneError::input("settle-record", "letter name is absent"))?;
            acknowledgments.push(super::inspect_readback(
                &plan.home.join(".local/outbox").join(name),
                worker,
            )?);
        }
    }
    let basis = json!({"reservation":record,"report_path":report_path,"report_archive":archive,"previous_report":previous_report,"report_line":report_line,"thread":thread,"readback":readback,"in_round_acknowledgments":acknowledgments,"letter_reconciliation":letter_reconciliation});
    let bytes = serde_json::to_vec(&basis)
        .map_err(|error| LaneError::input("settle-record", error.to_string()))?;
    let digest = build::sha256_bytes(&bytes, &plan.driver_dir)?;
    Ok((
        reservation,
        readback,
        digest,
        letter_reconciliation,
        report_path,
        archive,
    ))
}

fn optional_driver_report(
    plan: &crate::plan::Plan,
    record: &Value,
    round: &Value,
) -> Result<Value, LaneError> {
    let directory = super::follow::recorded_directory(plan, round)?;
    match std::fs::symlink_metadata(directory.join("run-report.txt")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        _ => rounds::recovery_report_line(plan, record, round).map(Value::String),
    }
}

fn settlement_readback(
    plan: &crate::plan::Plan,
    loop_name: &str,
    run: &str,
    persist: bool,
    owner: u32,
    record: &Value,
) -> Result<Value, LaneError> {
    if super::reaping::recovery_verdict(record).is_ok() || completed_failed_round(record) {
        let step = record["active_round"]
            .as_str()
            .ok_or_else(|| LaneError::input("settle-record", "active round is absent"))?;
        super::letters::valid_step(step)?;
        let worker = record["worker_uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .ok_or_else(|| LaneError::input("settle-record", "worker UID is absent"))?;
        let parent = home::pin_parent(&plan.home.join(".local"), owner)?;
        let held = nix::fcntl::openat2(
            &parent,
            "outbox",
            nix::fcntl::OpenHow::new()
                .flags(
                    nix::fcntl::OFlag::O_RDONLY
                        | nix::fcntl::OFlag::O_DIRECTORY
                        | nix::fcntl::OFlag::O_CLOEXEC,
                )
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        )
        .map_err(|error| LaneError::input("readback", error.to_string()))?;
        let metadata = nix::sys::stat::fstat(&held)
            .map_err(|error| LaneError::input("readback", error.to_string()))?;
        if metadata.st_uid != worker || metadata.st_mode & 0o022 != 0 {
            return Err(LaneError::input(
                "readback",
                format!(
                    "outbox uid {} differs from worker {worker} or its mode permits replacement",
                    metadata.st_uid
                ),
            ));
        }
        let name = format!("{step}.md");
        match nix::fcntl::openat2(
            &held,
            name.as_str(),
            nix::fcntl::OpenHow::new()
                .flags(
                    nix::fcntl::OFlag::O_PATH
                        | nix::fcntl::OFlag::O_NOFOLLOW
                        | nix::fcntl::OFlag::O_CLOEXEC,
                )
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        ) {
            Err(nix::errno::Errno::ENOENT) => {
                let prior_reply = record["rounds"]
                    .as_array()
                    .and_then(|rows| rows.last())
                    .is_some_and(|row| !row["reply"].is_null());
                let evidence = plan
                    .driver_dir
                    .join(format!("readback-evidence-{step}.json"));
                if prior_reply
                    || !matches!(std::fs::symlink_metadata(evidence), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err(LaneError::input(
                        "readback",
                        "reply disappeared after evidence was recorded",
                    ));
                }
                if completed_failed_round(record) {
                    let round = record["rounds"]
                        .as_array()
                        .and_then(|rows| rows.last())
                        .ok_or_else(|| LaneError::input("settle-record", "last round is absent"))?;
                    let report = rounds::recovery_report_line(plan, record, round)?;
                    let verdict = if record["driver_end"]["successful"] == true {
                        "verdict=ok"
                    } else {
                        "verdict=FAILED"
                    };
                    if !report.split_whitespace().any(|word| word == verdict) {
                        return Err(LaneError::input(
                            "readback",
                            "absent reply requires a matching completed driver verdict",
                        ));
                    }
                }
                return Ok(Value::Null);
            }
            Err(error) => return Err(LaneError::input("readback", error.to_string())),
            Ok(_) => {}
        }
    }
    super::record_readback_with_owner(plan, loop_name, run, persist, owner)
}

fn replaceable_report(
    runs: &OwnedFd,
    plan: &crate::plan::Plan,
    record: &Value,
    run: &str,
    step: Option<&str>,
    owner: u32,
) -> Result<Value, LaneError> {
    if !super::report::present(runs, run, step, owner)
        .map_err(|error| LaneError::input("launch-report", error.line()))?
    {
        return Ok(Value::Null);
    }
    let prior = super::report::read_bound(runs, run, step, owner)?;
    if super::reaping::recovery_verdict(record).is_ok()
        && prior["interrupted_settlement"]["state"] == "completed-interrupted-settlement"
        && prior["interrupted_settlement"]["phase"] == "failed"
        && prior["home"] == json!(plan.home)
        && prior["driver_dir"] == json!(plan.driver_dir)
        && prior["round_dir"] == super::report::round_dir(plan, record, step)?
    {
        return Ok(prior);
    }
    Err(LaneError::input(
        "launch-report",
        "occupied report is not this failed interrupted recovery",
    ))
}

/// Recognize a failed round with recorded driver/helper ends and no recorded reply.
/// File absence and the bound driver verdict are checked by settlement before completion.
pub(super) fn completed_failed_round(record: &Value) -> bool {
    matches!(record["phase"].as_str(), Some("failed" | "settled"))
        && record["pre_driver_failure"].is_null()
        && record["driver_end"]["state"] == "completed"
        && record["driver_end"]["successful"].is_boolean()
        && record["helper_end"]["state"] == "completed"
        && record["rounds"]
            .as_array()
            .and_then(|rows| rows.last())
            .is_some_and(|round| {
                round["phase"] == "failed"
                    && round["step"].is_string()
                    && round["step"] == record["active_round"]
                    && round["reply"].is_null()
            })
}

/// Recognize the existing terminal phases, including a failed round without a reply.
pub(super) fn final_round_ready(record: &Value) -> bool {
    let Some(round) = record["rounds"].as_array().and_then(|rows| rows.last()) else {
        return false;
    };
    round["phase"] == "settled"
        || (record["phase"] == "settled"
            && round["phase"] == "failed"
            && round["reply"].is_null()
            && (super::reaping::recovery_verdict(record).is_ok() || completed_failed_round(record))
            && round["settle_attempts"]
                .as_array()
                .and_then(|rows| rows.last())
                .is_some_and(|row| row["phase"] == "complete"))
}

fn record_attempt(
    path: &Path,
    run: &str,
    digest: &str,
    phase: &str,
    detail: Option<&str>,
) -> Result<(), LaneError> {
    let root = path
        .parent()
        .ok_or_else(|| LaneError::input("settle-record", "reservation parent is absent"))?;
    let _mailbox = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut record = read_reservation(path)?
        .ok_or_else(|| LaneError::input("settle-record", "reservation is absent"))?;
    let round = record["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        .ok_or_else(|| LaneError::input("settle-record", "last round is absent"))?;
    let attempts = round
        .as_object_mut()
        .ok_or_else(|| LaneError::input("settle-record", "round is not an object"))?
        .entry("settle_attempts")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| LaneError::input("settle-record", "attempt journal is malformed"))?;
    if phase == "attempted" {
        if attempts.len() == 8 {
            attempts.remove(0);
        }
        attempts.push(json!({"preview_sha256":digest,"phase":phase,"detail":detail}));
    } else {
        let latest = attempts
            .last_mut()
            .ok_or_else(|| LaneError::input("settle-record", "attempt was not recorded"))?;
        if latest["preview_sha256"] != digest || latest["phase"] != "attempted" {
            return Err(LaneError::input(
                "settle-record",
                "attempt identity differs",
            ));
        }
        latest["phase"] = json!(phase);
        latest["detail"] = json!(detail);
    }
    super::publish_reservation(path, &record)
}

fn require_preview_digest(expected: Option<&str>, actual: &str) -> Result<(), LaneError> {
    if expected != Some(actual) {
        return Err(LaneError::input(
            "settle-preview-refusal",
            format!(
                "recorded preview {actual} differs from supplied digest {}",
                expected.unwrap_or_default()
            ),
        ));
    }
    Ok(())
}

fn recovered_report(
    plan: &crate::plan::Plan,
    request: &SettleRequest,
    settled: &Value,
    private: &Value,
    wall_seconds: f64,
) -> Result<(Option<String>, Value), LaneError> {
    let round_dir = super::report::round_dir(plan, settled, Some(&request.step))?;
    let rounds = settled["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("settle-record", "round list is absent"))?;
    let step = (rounds.len() > 1).then(|| request.step.clone());
    let attempt = rounds
        .last()
        .and_then(|round| round["settle_attempts"].as_array())
        .and_then(|attempts| attempts.last())
        .ok_or_else(|| LaneError::input("settle-record", "completed attempt is absent"))?;
    if settled["phase"] != "settled"
        || private["phase"] != "settled"
        || attempt["preview_sha256"] != private["preview_sha256"]
        || attempt["phase"] != "complete"
        || !attempt["detail"].is_null()
    {
        return Err(LaneError::input(
            "settle-record",
            "completed settlement differs from its preview or attempt",
        ));
    }
    let recovered = json!({"state":"completed-settle-round","preview_sha256":attempt["preview_sha256"],"phase":attempt["phase"],"detail":attempt["detail"]});
    let report = json!({"schema":1,"command":"launch","dry_run":false,"interrupted_settlement":recovered,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":round_dir,"wall_seconds":wall_seconds});
    Ok((step, report))
}

#[allow(clippy::too_many_arguments)]
fn publish_settled_report(
    plan: &crate::plan::Plan,
    root: &Path,
    runs: &OwnedFd,
    request: &SettleRequest,
    settled: &Value,
    private: &Value,
    wall_seconds: f64,
    on_failure: &mut dyn FnMut(&Value),
) -> Result<(), LaneError> {
    let (step, report) = recovered_report(plan, request, settled, private, wall_seconds)?;
    let expected_path = root.join(super::report::name(&request.run, step.as_deref())?);
    if private["report_path"] != expected_path.display().to_string() {
        return Err(LaneError::input(
            "settle-record",
            "private report path differs from the settled round",
        ));
    }
    let prior = &settled["reaping_recovery"]["previous_report"];
    if !prior.is_null() {
        let mut archive = super::report::archive_preview(runs, &request.run, step.as_deref())?;
        for key in ["source", "target"] {
            archive[key] =
                json!(root.join(
                    archive[key].as_str().ok_or_else(|| LaneError::input(
                        "launch-report",
                        "archive path is absent"
                    ))?
                ));
        }
        if archive != private["report_archive"] {
            on_failure(&report);
            return Err(LaneError::input(
                "launch-report",
                "failed report archive differs from settlement preview",
            ));
        }
    }
    if let Err(error) = super::report::publish_replacing(
        runs,
        &request.run,
        step.as_deref(),
        &report,
        (!prior.is_null()).then_some(prior),
    ) {
        on_failure(&report);
        return Err(LaneError {
            status: error.status,
            kind: "launch-report",
            detail: error.line(),
        });
    }
    Ok(())
}

/// Preview or repeat exactly the helper's private settlement after a failed round.
///
/// # Errors
///
/// Refuses live or settled rounds, missing evidence, and a preview changed before writing.
pub fn private_recover(owner_home: &Path, request: &SettleRequest) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let (plan, _) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    private_recover_core(&plan, owner_home, request, 0, process_presence)
}

fn journal_recovered_report(
    plan: &crate::plan::Plan,
    path: &Path,
    request: &SettleRequest,
    owner_uid: u32,
    record: &Value,
) -> Result<(), LaneError> {
    let runs = home::pin_parent(
        path.parent()
            .ok_or_else(|| LaneError::input("settle-record", "runs root is absent"))?,
        owner_uid,
    )?;
    let step = (record["rounds"]
        .as_array()
        .is_some_and(|rows| rows.len() > 1))
    .then_some(request.step.as_str());
    let prior = replaceable_report(&runs, plan, record, &request.run, step, owner_uid)?;
    let mut recovery = record["reaping_recovery"].clone();
    recovery["previous_report"] = prior;
    let root = path
        .parent()
        .ok_or_else(|| LaneError::input("settle-record", "runs root is absent"))?;
    let _mailbox = lock_mailbox(root, &request.run, owner_uid)?;
    let mut current = read_reservation(path)?
        .ok_or_else(|| LaneError::input("settle-record", "reservation is absent"))?;
    if current != *record {
        return Err(LaneError::input(
            "settle-preview-refusal",
            "reservation changed before recovery journal",
        ));
    }
    current["reaping_recovery"] = recovery;
    super::publish_reservation(path, &current)?;
    Ok(())
}

fn private_recover_core(
    plan: &crate::plan::Plan,
    owner_home: &Path,
    request: &SettleRequest,
    owner_uid: u32,
    presence: impl FnMut(u32, u64) -> ProcessPresence,
) -> Result<Value, LaneError> {
    let (path, readback, digest, expected_reconciliation, report_path, report_archive) = preview(
        plan,
        owner_home,
        &request.loop_name,
        &request.run,
        &request.step,
        owner_uid,
        presence,
    )?;
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"settle","dry_run":true,"loop":request.loop_name,"run":request.run,"round":request.step,"report_path":report_path,"report_archive":report_archive,"preview_sha256":digest,"readback":readback,"changed":1}),
        );
    }
    require_preview_digest(request.expect_digest.as_deref(), &digest)?;
    let record = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("settle-record", "reservation is absent"))?;
    let recovered = super::reaping::recovery_verdict(&record).is_ok();
    if recovered {
        journal_recovered_report(plan, &path, request, owner_uid, &record)?;
    }
    record_attempt(&path, &request.run, &digest, "attempted", None)?;
    let result = (|| {
        let (_, changes) =
            super::letters::reconcile_run(plan, &request.run, owner_home, owner_uid, false)?;
        if changes != expected_reconciliation {
            return Err(LaneError::input(
                "settle-preview-refusal",
                "letter reconciliation changed after preview",
            ));
        }
        let current = settlement_readback(
            plan,
            &request.loop_name,
            &request.run,
            false,
            owner_uid,
            &record,
        )?;
        if current != readback {
            return Err(LaneError::input(
                "settle-preview-refusal",
                "outbox changed after preview",
            ));
        }
        let (_, letter_reconciliation) =
            super::letters::reconcile_run(plan, &request.run, owner_home, owner_uid, true)?;
        let actual = settlement_readback(
            plan,
            &request.loop_name,
            &request.run,
            true,
            owner_uid,
            &record,
        )?;
        if actual != readback {
            return Err(LaneError::input(
                "settle-preview-refusal",
                "outbox changed after preview",
            ));
        }
        if recovered || (actual.is_null() && completed_failed_round(&record)) {
            finish_recovered_round(plan, &path, request, &actual, owner_uid)?;
        } else {
            rounds::record_settlement_with_recovery(plan, &request.run, &actual, true)?;
        }
        Ok(letter_reconciliation)
    })();
    match result {
        Ok(letter_reconciliation) => {
            let settled = read_reservation(&path)?.ok_or_else(|| {
                LaneError::input("settle-record", "settled reservation is absent")
            })?;
            let ended_by = if recovered || completed_failed_round(&settled) {
                settled["rounds"]
                    .as_array()
                    .and_then(|rows| rows.last())
                    .map_or(Value::Null, |row| row["ended_by"].clone())
            } else {
                json!(rounds::settled_round_end(&settled)?)
            };
            let settlement = json!({"schema":1,"command":"settle-evidence","driver_dir":plan.driver_dir,"owner_uid":crate::plan::loop_uid(&plan.document)?,"mode":"0700","paths_changed":0,"letter_reconciliation":letter_reconciliation,"readback":readback,"ended_by":ended_by});
            Ok(
                json!({"schema":1,"command":"settle","dry_run":false,"loop":request.loop_name,"run":request.run,"round":request.step,"report_path":report_path,"report_archive":report_archive,"phase":"settled","preview_sha256":digest,"settlement":settlement,"changed":1}),
            )
        }
        Err(mut error) => {
            if let Err(mark_error) =
                record_attempt(&path, &request.run, &digest, "refused", Some(&error.line()))
            {
                error.detail = format!(
                    "{}; attempt refusal could not be recorded: {}",
                    error.detail,
                    mark_error.line()
                );
            }
            Err(error)
        }
    }
}

fn finish_recovered_round(
    plan: &crate::plan::Plan,
    path: &Path,
    request: &SettleRequest,
    reply: &Value,
    owner: u32,
) -> Result<(), LaneError> {
    let root = path
        .parent()
        .ok_or_else(|| LaneError::input("settle-record", "runs root is absent"))?;
    let _mailbox = lock_mailbox(root, &request.run, owner)?;
    let mut record = read_reservation(path)?
        .ok_or_else(|| LaneError::input("settle-record", "reservation is absent"))?;
    if !completed_failed_round(&record) {
        super::reaping::recovery_verdict(&record)?;
    }
    let round = record["rounds"]
        .as_array()
        .and_then(|rows| rows.last())
        .ok_or_else(|| LaneError::input("settle-record", "last round is absent"))?
        .clone();
    let report = optional_driver_report(plan, &record, &round)?;
    if !reply.is_null() {
        record["thread_id"] = json!(rounds::recovery_thread(plan, &record, &round)?);
    }
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("settle-record", "worker UID is absent"))?;
    let stopped = record["letters"].as_array().is_some_and(|letters| {
        letters.iter().any(|letter| {
            letter["step"] == request.step && letter["stop"] == true && letter["state"] == "placed"
        })
    });
    let ended_by = report.as_str().map(|line| {
        if stopped && line.split_whitespace().any(|word| word == "exit=0") {
            "by-report-after-stop"
        } else {
            "by-report"
        }
    });
    let mut acknowledgments = Vec::new();
    for letter in record["letters"]
        .as_array()
        .ok_or_else(|| LaneError::input("settle-record", "letters are absent"))?
    {
        if !reply.is_null()
            && letter["step"] == request.step
            && letter["in_round"] == true
            && letter["state"] == "placed"
        {
            let name = letter["name"]
                .as_str()
                .ok_or_else(|| LaneError::input("settle-record", "letter name is absent"))?;
            let acknowledgment =
                super::inspect_readback(&plan.home.join(".local/outbox").join(name), worker)?;
            acknowledgments.push(json!({"letter":name,"acknowledgment":acknowledgment}));
        }
    }
    let round = record["rounds"]
        .as_array_mut()
        .and_then(|rows| rows.last_mut())
        .ok_or_else(|| LaneError::input("settle-record", "last round is absent"))?;
    round["reply"] = reply.clone();
    round["in_round_letters"] = json!(acknowledgments);
    round["phase"] = json!(if reply.is_null() { "failed" } else { "settled" });
    round["settlement_error"] = if reply.is_null() {
        json!("settle-evidence: reply absent after completed settlement")
    } else {
        Value::Null
    };
    round["ended_by"] = json!(ended_by);
    let attempt = round["settle_attempts"]
        .as_array_mut()
        .and_then(|rows| rows.last_mut())
        .ok_or_else(|| LaneError::input("settle-record", "attempt is absent"))?;
    attempt["phase"] = json!("complete");
    record["phase"] = json!("settled");
    record["readback_end"] = json!("completed");
    super::publish_reservation(path, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn collected_record(record: &mut Value) {
        record["run_scope"] = json!({"unit":"superloop-lane-run-fixture.service","cgroup":"/user.slice/superloop-lane-run-fixture.service/work","device":1,"inode":2,"proxy_unit":"proxy.service","proxy_invocation":"fixture"});
        for (pid, start) in [
            ("launcher_pid", "launcher_start"),
            ("helper_pid", "helper_start"),
            ("helper_parent_pid", "helper_parent_start"),
        ] {
            record[pid] = json!(4_000_001);
            record[start] = json!(1);
        }
        record["driver_end"] = json!({"state":"absent-on-recovery"});
        record["helper_end"] = json!({"state":"absent-on-recovery"});
        record["reaping"] = Value::Null;
        record["reaping_recovery"] = json!({"state":"collected","cgroup":record["run_scope"]["cgroup"],"scope":record["run_scope"],"container_payload":{"state":"absent","by":"loop-and-run-label"},"presence":"all-absent","identities":{"launcher":[4_000_001,1],"driver":[4_000_000,1],"helper":[4_000_001,1],"helper_parent":[4_000_001,1],"observer":null},"attempt_evidence":{"state":"absence-confirmed-with-missing-evidence","attempts":[],"container_absence_checked":true}});
    }

    fn custody_plan(fixture: &Path, old: &crate::plan::Plan) -> crate::plan::Plan {
        let owner = Uid::effective().as_raw();
        let settings = crate::settings::Settings {
            sandbox_mode: "danger-full-access".into(),
            runs_root: Some(fixture.to_path_buf()),
            backend_argv: std::collections::BTreeMap::from([(
                "codex".into(),
                vec!["/usr/libexec/superloop/codex".into()],
            )]),
            driver_argv: Vec::new(),
            entry_bin: Some("/usr/bin/true".into()),
            driver_bin: Some("/usr/bin/true".into()),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            template_dir: Some(fixture.join("template")),
            resources: Some(crate::settings::Resources {
                memory_bytes: 2_147_483_648,
                pids_max: 128,
                cpu_shares: 512,
            }),
            socket_dir: Some(fixture.join("sockets")),
            vendor_hosts: std::collections::BTreeMap::new(),
            context_threshold: None,
            retention: "keep".into(),
            source: String::new(),
        };
        let plan = crate::plan::Plan::build_for_record(
            fixture,
            "alpha",
            "R",
            &settings,
            &json!({"name":"alpha","uid":owner,"runs_root":fixture}),
            loop_home::registry::WorkerBlock {
                base: owner,
                count: 1,
            },
            (owner, owner),
        )
        .expect("custody plan");
        std::fs::create_dir_all(plan.home.parent().expect("parent")).expect("home parents");
        for path in [fixture.join(".cache"), fixture.join(".cache/tmp")] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("parent mode");
        }
        std::fs::rename(&old.home, &plan.home).expect("planned home");
        for (leaf, mode) in [("inbox", 0o750), ("sources", 0o700)] {
            let path = plan.home.join(".local").join(leaf);
            std::fs::create_dir(&path).expect("custody leaf");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .expect("leaf mode");
        }
        plan
    }

    fn git_fixture(path: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", "umask 022; exec /usr/bin/git \"$@\"", "git", "-C"])
            .arg(path)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
            .output()
            .expect("fixture Git");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Git text")
            .trim()
            .to_owned()
    }

    /// ´test:unit:collected-recovery-checkpoint-checkout-keeps-worker-commits´
    #[test]
    fn collected_recovery_checkpoint_checkout_keeps_worker_commits() {
        for has_reply in [true, false] {
            let (fixture, old, mut request) = recovery_fixture();
            let plan = custody_plan(fixture.path(), &old);
            let owner = Uid::effective().as_raw();
            let path = super::super::reservation_path(fixture.path(), "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            record["plan"] = plan.document.clone();
            record["declared_sources"] = json!([]);
            record["checkouts"] = json!([]);
            record["checkouts_omitted"] = json!(0);
            record["checkout_attempts"] = json!([]);
            record["checkout_next_index"] = json!(1);
            record["imports"] = json!([]);
            collected_record(&mut record);
            record["phase"] = json!("started");
            record["model_selection"] = json!({"model":"gpt-6-sol","effort":"high"});
            record["letter_source"] = json!(plan.letter);
            record["reaping_recovery"] = Value::Null;
            super::super::publish_reservation(&path, &record).expect("recovery record");
            let recovered = super::super::finish_interrupted_settlement_with(&path, &plan, &plan.letter, owner,
                || Ok(Value::Null), || Ok(Value::Null), |_, _| ProcessPresence::Absent, || Ok(true),
                |saved| Ok(json!({"state":"collected","cgroup":saved["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}})), crate::launch::driver_report::fixture_read).expect("launch recovery entry");
            assert_eq!(recovered["state"], "completed-interrupted-settlement");
            if !has_reply {
                std::fs::remove_file(plan.home.join(".local/outbox/work.md")).expect("no reply");
            }
            let bare = plan.home.join(".local/sources/tools.git");
            git_fixture(
                fixture.path(),
                &["init", "--bare", bare.to_str().expect("bare")],
            );
            std::fs::set_permissions(&bare, std::fs::Permissions::from_mode(0o700))
                .expect("bare mode");
            std::fs::set_permissions(bare.join("config"), std::fs::Permissions::from_mode(0o600))
                .expect("config mode");
            let work = fixture.path().join("work");
            git_fixture(fixture.path(), &["init", work.to_str().expect("work")]);
            std::fs::write(work.join("saved"), "worker commit\n").expect("work");
            git_fixture(&work, &["add", "saved"]);
            git_fixture(&work, &["commit", "-m", "worker commit"]);
            let object = git_fixture(&work, &["rev-parse", "HEAD"]);
            git_fixture(
                &work,
                &[
                    "push",
                    bare.to_str().expect("bare"),
                    "HEAD:refs/heads/lane/R",
                ],
            );
            let preview = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect("preview");
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let result = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect("settle");
            assert_eq!(result["phase"], "settled");
            let checkpoint = super::super::checkpoint::CheckpointRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                dry_run: false,
                invocation_token: Some("a".repeat(32)),
            };
            let copied = super::super::checkpoint::private_run_with_plan(
                crate::plan::Plan {
                    home: plan.home.clone(),
                    driver_dir: plan.driver_dir.clone(),
                    letter: plan.letter.clone(),
                    document: plan.document.clone(),
                },
                fixture.path(),
                &checkpoint,
                owner,
            )
            .expect("checkpoint production entry");
            assert_eq!(copied["bares"][0]["object"], object);
            let external = tempfile::tempdir_in("/tmp").expect("external checkout parent");
            std::fs::set_permissions(external.path(), std::fs::Permissions::from_mode(0o700))
                .expect("external mode");
            let checkout = super::super::checkout::CheckoutRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                repo: "tools".into(),
                into: external.path().join("checkout"),
                dry_run: false,
                invocation_token: Some("b".repeat(32)),
            };
            let checked = super::super::checkout::private_run_with_plan(
                &plan,
                fixture.path(),
                &checkout,
                owner,
            )
            .expect("checkout production entry");
            assert_eq!(checked["object"], object);
            assert_eq!(git_fixture(&checkout.into, &["rev-parse", "HEAD"]), object);
        }
    }

    /// ´test:unit:collected-recovery-settles-reply-and-finalizes-missing-reply´
    #[test]
    fn collected_recovery_settles_reply_and_finalizes_missing_reply() {
        for has_reply in [true, false] {
            let (fixture, plan, mut request) = recovery_fixture();
            let owner = Uid::effective().as_raw();
            let path = super::super::reservation_path(fixture.path(), "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            collected_record(&mut record);
            super::super::publish_reservation(&path, &record).expect("collected recovery");
            std::fs::remove_file(plan.driver_dir.join("20261007T043545Z-work/run-report.txt"))
                .expect("launcher left no report");
            if !has_reply {
                std::fs::remove_file(plan.home.join(".local/outbox/work.md")).expect("no reply");
            }
            let preview = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect("preview");
            assert_eq!(preview["readback"].is_null(), !has_reply);
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let settled = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect("settle");
            assert_eq!(settled["phase"], "settled");
            assert_eq!(settled["settlement"]["readback"].is_null(), !has_reply);
            let saved = read_reservation(&path).expect("read").expect("saved");
            assert!(final_round_ready(&saved));
            assert_eq!(
                saved["rounds"][0]["phase"],
                if has_reply { "settled" } else { "failed" }
            );
            assert_first_recovered_report(&fixture, &plan, &request, &saved, &settled, &preview);
        }
    }

    /// ´test:unit:collected-settlement-checks-owner-and-worker-identities-separately´
    #[test]
    fn collected_settlement_checks_owner_and_worker_identities_separately() {
        for worker in [3000, 3001] {
            let (fixture, plan, request) = recovery_fixture();
            let owner = Uid::effective().as_raw();
            assert_ne!(owner, worker);
            let path = super::super::reservation_path(fixture.path(), "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            collected_record(&mut record);
            record["worker_uid"] = json!(worker);
            record["plan"]["worker_uid"] = json!(worker);
            super::super::publish_reservation(&path, &record).expect("distinct worker");
            let error = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("owner outbox is not worker custody");
            assert_eq!(error.kind, "readback");
            assert!(
                error
                    .detail
                    .contains(&format!("outbox uid {owner} differs from worker {worker}")),
                "{}",
                error.line()
            );
        }
    }

    /// ´test:unit:collected-settlement-supersedes-only-its-failed-recovery-report´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn collected_settlement_supersedes_only_its_failed_recovery_report() {
        let (fixture, plan, mut request) = recovery_fixture();
        let owner = Uid::effective().as_raw();
        let path = super::super::reservation_path(fixture.path(), "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        collected_record(&mut record);
        super::super::publish_reservation(&path, &record).expect("recovery");
        let runs = home::pin_parent(fixture.path(), owner).expect("runs");
        let prior = json!({"schema":1,"command":"launch","dry_run":false,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":plan.driver_dir.join("20261007T043545Z-work"),"wall_seconds":1.0,"interrupted_settlement":{"state":"completed-interrupted-settlement","phase":"failed","ended_by":null,"attempt_evidence":{"state":"absence-confirmed-with-missing-evidence","attempts":[],"container_absence_checked":true},"observer_socket":{"state":"not-applicable"}}});
        super::super::report::publish(&runs, "R", None, &prior).expect("failed report");
        let error = super::super::interrupted_settlement_with(
            &record,
            &plan,
            Path::new("/unused"),
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            crate::launch::driver_report::fixture_read,
        )
        .expect_err("completed recovery refuses another preview");
        assert_eq!(error.kind, "launch-report");
        assert!(error.detail.contains("preview settle"));
        let mut by_report = record.clone();
        by_report["rounds"]
            .as_array_mut()
            .expect("rounds")
            .last_mut()
            .expect("round")["phase"] = json!("settled");
        let error = super::super::interrupted_settlement_with(
            &by_report,
            &plan,
            Path::new("/unused"),
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            crate::launch::driver_report::fixture_read,
        )
        .expect_err("completed by-report recovery names the new round");
        assert_eq!(error.kind, "launch-report");
        assert!(error.detail.contains("send-letter LOOP RUN --step NEW"));
        assert!(!error.detail.contains("preview settle"));
        by_report["rounds"]
            .as_array_mut()
            .expect("rounds")
            .last_mut()
            .expect("round")["ended_by"] = json!("by-report");
        by_report["readback_end"] = json!("completed");
        by_report["observation_end"] = json!("completed");
        by_report["observer_end"] =
            json!({"state":"not-started","socket":{"state":"not-applicable"}});
        let missing = json!({"state":"absence-confirmed-with-missing-evidence","attempts":[]});
        assert!(super::super::interrupted_settlement_success(
            &by_report, &missing
        ));
        for end in ["driver_end", "helper_end"] {
            by_report[end]["successful"] = json!(false);
            assert!(!super::super::interrupted_settlement_success(
                &by_report, &missing
            ));
            by_report[end]["successful"] = json!(true);
        }
        by_report["reaping_recovery"]["presence"] = json!("unknown");
        assert!(!super::super::interrupted_settlement_success(
            &by_report, &missing
        ));
        let preview = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
            ProcessPresence::Absent
        })
        .expect("matching report preview");
        assert!(
            preview["report_archive"]["target"]
                .as_str()
                .expect("archive path")
                .contains(".failed-unix-")
        );
        assert_eq!(
            preview["report_archive"]["sha256"]
                .as_str()
                .expect("archive digest")
                .len(),
            64
        );
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let mut result = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
            ProcessPresence::Absent
        })
        .expect("settle");
        let saved = read_reservation(&path).expect("read").expect("saved");
        assert_eq!(saved["reaping_recovery"]["previous_report"], prior);
        let report_path = fixture.path().join(".report=R.json");
        std::fs::write(&report_path, b"changed prior report")
            .expect("prior changed after settlement");
        let mut unsaved = None;
        let error = publish_settled_report(
            &plan,
            fixture.path(),
            &runs,
            &request,
            &saved,
            &result,
            2.0,
            &mut |report| unsaved = Some(report.clone()),
        )
        .expect_err("changed prior is a publication refusal");
        assert_eq!(error.kind, "launch-report");
        assert!(error.detail.contains("archive differs"), "{}", error.line());
        assert_eq!(
            unsaved.expect("fallback report")["interrupted_settlement"]["state"],
            "completed-settle-round"
        );
        std::fs::write(
            &report_path,
            serde_json::to_vec(&prior).expect("prior JSON"),
        )
        .expect("restore fixture report");
        result["report_archive"] =
            super::super::report::archive_preview(&runs, "R", None).expect("restored archive");
        for key in ["source", "target"] {
            result["report_archive"][key] = json!(
                fixture
                    .path()
                    .join(result["report_archive"][key].as_str().expect("path"))
            );
        }
        publish_settled_report(
            &plan,
            fixture.path(),
            &runs,
            &request,
            &saved,
            &result,
            2.0,
            &mut |_| {},
        )
        .expect("replace validated report");
        let archived = std::fs::read_dir(fixture.path())
            .expect("runs")
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                path.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .contains(".failed-unix-")
            })
            .expect("original report archive");
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(archived).expect("archive bytes"))
                .expect("archive JSON"),
            prior
        );
        let published = super::super::report::read_bound(&runs, "R", None, owner)
            .expect("production report reader");
        assert_eq!(
            published["interrupted_settlement"]["state"],
            "completed-settle-round"
        );
        assert_eq!(published["interrupted_settlement"]["phase"], "complete");
        assert!(replaceable_report(&runs, &plan, &record, "R", None, owner).is_err());
    }

    /// ´test:unit:settle-names-older-collected-proof-before-unavailable-driver-ends´
    #[test]
    fn settle_names_older_collected_proof_before_unavailable_driver_ends() {
        for worker in [3000, 3001] {
            let (fixture, plan, request) = recovery_fixture();
            let owner = Uid::effective().as_raw();
            assert_ne!(owner, worker);
            let path = super::super::reservation_path(fixture.path(), "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            collected_record(&mut record);
            record["worker_uid"] = json!(worker);
            record["plan"]["worker_uid"] = json!(worker);
            record["reaping_recovery"] = json!({"state":"collected","cgroup":record["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}});
            super::super::publish_reservation(&path, &record).expect("older proof");
            let error = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("older proof refused by name");
            assert_eq!(error.kind, "run-reaping");
            assert!(
                error
                    .detail
                    .starts_with("collected recovery proof is incomplete")
            );
            assert!(error.detail.contains("retire --confirm-uncertain"));
            assert!(error.detail.contains("consider retire, or"));
            assert_eq!(error.detail.matches("collected recovery proof").count(), 1);
        }
    }

    /// ´test:unit:collected-recovery-requires-matching-dead-identities-and-absent-payload´
    #[test]
    fn collected_recovery_requires_matching_dead_identities_and_absent_payload() {
        for worker in [3000, 3001] {
            assert_ne!(Uid::effective().as_raw(), worker);
            let mut record = failed_record(worker);
            collected_record(&mut record);
            recovery_basis(&record, "work", |_, _| ProcessPresence::Absent)
                .expect("dead identities");
            assert_eq!(
                recovery_basis(&record, "work", |_, _| ProcessPresence::Present)
                    .expect_err("live launcher")
                    .kind,
                "settle-live-refusal"
            );
            assert_eq!(
                recovery_basis(&record, "work", |_, _| ProcessPresence::Unknown)
                    .expect_err("unknown launcher")
                    .kind,
                "settle-presence-refusal"
            );
            for state in ["present", "unmeasured"] {
                let mut changed = record.clone();
                changed["reaping_recovery"]["container_payload"]["state"] = json!(state);
                assert!(recovery_basis(&changed, "work", |_, _| ProcessPresence::Absent).is_err());
            }
            record["launcher_start"] = json!(2);
            assert!(recovery_basis(&record, "work", |_, _| ProcessPresence::Absent).is_err());
        }
    }

    fn recovery_fixture() -> (tempfile::TempDir, crate::plan::Plan, SettleRequest) {
        recovery_fixture_in(Path::new("/tmp"))
    }

    fn recovery_fixture_in(parent: &Path) -> (tempfile::TempDir, crate::plan::Plan, SettleRequest) {
        let fixture = tempfile::tempdir_in(parent).expect("fixture");
        let owner = Uid::effective().as_raw();
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root mode");
        let driver_dir = fixture.path().join("R");
        let step_dir = driver_dir.join("20261007T043545Z-work");
        std::fs::create_dir_all(&step_dir).expect("step directory");
        std::fs::set_permissions(&driver_dir, std::fs::Permissions::from_mode(0o700))
            .expect("driver mode");
        std::fs::write(
            step_dir.join("events.jsonl"),
            b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n",
        )
        .expect("events");
        std::fs::write(step_dir.join(".event-start"), b"0\n").expect("event boundary");
        std::fs::write(
            step_dir.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=work exit=0 verdict=ok dir={}\n",
                step_dir.display()
            ),
        )
        .expect("report");
        let home_dir = fixture.path().join("home-R");
        std::fs::create_dir_all(home_dir.join(".local/outbox")).expect("outbox");
        for directory in [
            &home_dir,
            &home_dir.join(".local"),
            &home_dir.join(".local/outbox"),
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o750))
                .expect("private home ancestors");
        }
        let reply = home_dir.join(".local/outbox/work.md");
        std::fs::write(&reply, b"reply\n").expect("reply");
        std::fs::set_permissions(&reply, std::fs::Permissions::from_mode(0o600))
            .expect("reply mode");
        let identity_dir = fixture.path().join(".launch-R");
        std::fs::create_dir(&identity_dir).expect("identity custody");
        std::fs::set_permissions(&identity_dir, std::fs::Permissions::from_mode(0o700))
            .expect("identity mode");
        let evidence = identity_dir.join("launch-evidence.json");
        std::fs::write(
            &evidence,
            b"{\"bound_source_matrix\":{\"git_worktree\":{\"add_remove\":true}}}\n",
        )
        .expect("launch evidence");
        std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o600))
            .expect("evidence mode");
        let document = json!({"loop":"alpha","home":home_dir,"driver_dir":driver_dir,"worker_uid":owner,"paths":[{"path":home_dir,"gid":owner},{"path":driver_dir,"uid":owner,"gid":owner,"kind":"directory"}]});
        let plan = crate::plan::Plan {
            home: home_dir,
            driver_dir,
            letter: PathBuf::new(),
            document,
        };
        let mut record = failed_record(owner);
        record["loop"] = json!("alpha");
        record["run"] = json!("R");
        record["plan"] = plan.document.clone();
        record["letters"] = json!([]);
        record["thread_id"] = json!("thread-1");
        record["rounds"][0]["driver_dir"] = json!(step_dir);
        super::super::publish_reservation(
            &super::super::reservation_path(fixture.path(), "R"),
            &record,
        )
        .expect("reservation");
        let request = SettleRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            step: "work".into(),
            dry_run: true,
            expect_digest: None,
        };
        (fixture, plan, request)
    }

    fn dead_resume_fixture(
        phase: &str,
    ) -> (
        tempfile::TempDir,
        crate::plan::Plan,
        super::super::LaunchRequest,
    ) {
        dead_resume_fixture_in(phase, Path::new("/tmp"))
    }

    #[allow(clippy::too_many_lines)]
    fn dead_resume_fixture_in(
        phase: &str,
        parent: &Path,
    ) -> (
        tempfile::TempDir,
        crate::plan::Plan,
        super::super::LaunchRequest,
    ) {
        let (fixture, old, _) = recovery_fixture_in(parent);
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root = File::open(h).expect("fixture root");
        let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
        let allocated_uid = owner + 1;
        let config = h.join(".config/loops/alpha");
        for path in [
            h.join(".config"),
            h.join(".config/loops"),
            config.clone(),
            h.join(".cache"),
            h.join(".cache/tmp"),
        ] {
            std::fs::create_dir_all(&path).expect("config directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("config mode");
        }
        let runtime = h.join("runtime");
        crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\ncase \"$1\" in\nps) exit 0;;\nunshare) echo 'settle-evidence: no thread or reply' >&2; exit 2;;\n*) exit 9;;\nesac\n").expect("runtime");
        for (path, text) in [
            (
                h.join(".config/loops/registry.toml"),
                format!(
                    "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = {owner}, launch = \"src\", runs_root = \"{}\" }}]\n",
                    h.display()
                ),
            ),
            (
                h.join(".config/loops/allocations.toml"),
                format!("[alpha]\nuids = {{ base = {allocated_uid}, count = 1 }}\n"),
            ),
            (
                config.join("workers.toml"),
                format!(
                    "runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}/template\"\nsocket_dir = \"{}/sockets\"\nbackend_argv = {{ codex = [\"/usr/bin/true\"] }}\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\nvendor_hosts = {{ codex = [\"api.example.com\"] }}\n",
                    h.display(),
                    "a".repeat(64),
                    h.display(),
                    h.display()
                ),
            ),
        ] {
            std::fs::write(&path, text).expect("config file");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("config file mode");
        }
        let (mut plan, _) = crate::load_plan(h, "alpha", "R", (0, 0)).expect("resume plan");
        plan.select_worker_uid(owner).expect("fixture worker");
        plan.select_container_program(&runtime)
            .expect("runtime plan");
        let selection = json!({"model":"gpt-6-sol","effort":"high"});
        plan.select_launch_model(&selection).expect("model");
        std::fs::rename(&old.home, &plan.home).expect("planned home");
        let inbox = plan.home.join(".local/inbox");
        std::fs::create_dir(&inbox).expect("inbox");
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o750))
            .expect("inbox mode");
        let letter = inbox.join("work-1.md");
        let bytes = b"Continue.\n";
        std::fs::write(&letter, bytes).expect("letter");
        std::fs::set_permissions(&letter, std::fs::Permissions::from_mode(0o600))
            .expect("letter mode");
        std::fs::remove_file(plan.home.join(".local/outbox/work.md")).expect("absent reply");
        let directory = plan.driver_dir.join("20261007T043545Z-work-1");
        std::fs::rename(plan.driver_dir.join("20261007T043545Z-work"), &directory)
            .expect("fresh resumed directory");
        std::fs::write(directory.join("events.jsonl"), b"").expect("absent thread event");
        std::fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=work-1 exit=1 verdict=failed dir={}\n",
                directory.display()
            ),
        )
        .expect("failed driver report");
        let path = super::super::reservation_path(h, "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        collected_record(&mut record);
        record["plan"] = plan.document.clone();
        record["worker_uid"] = json!(owner);
        record["reaping_recovery"]["identities"]["driver"] = json!([4_000_002, 1]);
        record["model_selection"] = selection;
        record["phase"] = json!(phase);
        record["active_round"] = json!("work-1");
        record["thread_id"] = Value::Null;
        record["letter_source"] = json!(letter);
        record["driver_end"] =
            json!({"state":"failed","detail":"driver-launch: helper-socket refusal"});
        record["helper_end"] = json!({"state":"failed","status":"exit status: 2","parent_pid":record["launcher_pid"],"parent_start":record["launcher_start"]});
        record["readback_end"] = Value::Null;
        record["rounds"] = json!([
            {"step":"dispatch","phase":"failed","ended_by":"by-report","reply":null,"settle_attempts":[{"phase":"complete","preview_sha256":"a".repeat(64),"detail":null}]},
            {"step":"work-1","phase":"running","driver_dir":directory,"fresh_thread":true,"ended_by":null,"letter":"work-1.md","placed_at_unix_ns":1,"budget_seconds":10800,"in_round_letters":[]}
        ]);
        record["letters"] = json!([{"step":"work-1","name":"work-1.md","in_round":false,"stop":false,"bytes":bytes.len(),"sha256":build::sha256_bytes(bytes, h).expect("digest"),"placed_at_unix_ns":1,"state":"placed"}]);
        super::super::publish_reservation(&path, &record).expect("dead resume record");
        drop(super::super::lock_mailbox(h, "R", owner).expect("existing mailbox"));
        let request = super::super::LaunchRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "work-1".into(),
            "--podman-bin".into(),
            runtime.display().to_string(),
            "--dry-run".into(),
        ])
        .expect("resume request");
        (fixture, plan, request)
    }

    fn dead_socket_fixture(
        resumed: bool,
        phase: &str,
    ) -> (
        tempfile::TempDir,
        crate::plan::Plan,
        super::super::LaunchRequest,
    ) {
        let (fixture, mut plan, mut request) = dead_resume_fixture_in(phase, &std::env::temp_dir());
        // The node TMPDIR may have group-writable ancestors. Use a protected
        // system executable for the empty container census, not a scratch script.
        request.podman_bin = PathBuf::from("/usr/bin/true");
        plan.select_container_program(&request.podman_bin)
            .expect("census program");
        let path = super::super::reservation_path(fixture.path(), "R");
        let root = File::open(fixture.path()).expect("root");
        let _guard = home::activate_handed_home(fixture.path(), &root, Uid::effective().as_raw())
            .expect("private fixture");
        let mut saved = read_reservation(&path).expect("read").expect("record");
        saved["plan"] = plan.document.clone();
        super::super::publish_reservation(&path, &saved).expect("census plan");
        if !resumed {
            let path = super::super::reservation_path(fixture.path(), "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            let mut dispatch = record["rounds"][1].clone();
            let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
            std::fs::rename(
                dispatch["driver_dir"].as_str().expect("old directory"),
                &directory,
            )
            .expect("dispatch directory");
            dispatch["step"] = json!("dispatch");
            dispatch["driver_dir"] = json!(directory);
            record["rounds"] = json!([dispatch]);
            record["active_round"] = json!("dispatch");
            std::fs::write(
                directory.join("run-report.txt"),
                format!(
                    "RUN-REPORT lane=dispatch exit=1 verdict=failed dir={}\n",
                    directory.display()
                ),
            )
            .expect("dispatch report");
            request.round = None;
            request.letter = PathBuf::from(record["letter_source"].as_str().expect("letter"));
            super::super::publish_reservation(&path, &record).expect("dispatch record");
        }
        (fixture, plan, request)
    }

    fn dead_socket_paths(plan: &crate::plan::Plan) -> Vec<PathBuf> {
        vec![
            crate::container_helper::socket_path(&plan.driver_dir).expect("request socket"),
            crate::container_helper::control_socket_path(&plan.driver_dir).expect("control socket"),
        ]
    }

    fn bind_dead_sockets(plan: &crate::plan::Plan) -> Vec<PathBuf> {
        let paths = dead_socket_paths(plan);
        let owner = Uid::effective().as_raw();
        for (path, mode) in paths.iter().zip([0o660, 0o600]) {
            let slot = crate::SocketSlot::pinned(path, owner).expect("pinned socket");
            let listener = std::os::unix::net::UnixListener::bind(slot.address()).expect("bind");
            slot.set_owner_mode(owner, nix::unistd::Gid::effective().as_raw(), mode)
                .expect("mode");
            drop(listener);
        }
        paths
    }

    fn complete_socket_fixture(
        h: &Path,
        plan: &crate::plan::Plan,
        request: &super::super::LaunchRequest,
    ) -> Result<Value, LaneError> {
        let owner = Uid::effective().as_raw();
        let reap = |saved: &Value| {
            Ok(
                json!({"state":"collected","cgroup":saved["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}}),
            )
        };
        if request.round.is_some() {
            return rounds::resume_with_evidence(
                h,
                request,
                h,
                owner,
                |_| panic!("recovery needs no vendor service"),
                &mut |_| {},
                crate::container_helper::process_presence,
                reap,
            );
        }
        let record = read_reservation(&super::super::reservation_path(h, "R"))?.expect("record");
        // The dispatch fixture has no installed image/template pins; exercise the
        // leased production completion, below first-launch pin admission.
        super::super::complete_interrupted_launch(
            h,
            request,
            h,
            owner,
            plan,
            &record,
            &std::env::current_exe().expect("executable"),
            Instant::now(),
            &mut |_| {},
            crate::container_helper::process_presence,
            reap,
        )
    }

    fn print_socket_record(label: &str, path: &Path, paths: &[PathBuf]) {
        let record = read_reservation(path).expect("read").expect("record");
        writeln!(
            std::io::stdout().lock(),
            "{label}: {}",
            json!({"sockets_present":paths.iter().map(|p| p.exists()).collect::<Vec<_>>(),
            "phase":record["phase"],"rounds":record["rounds"],
            "reaping_recovery":record["reaping_recovery"],
            "interrupted_settlement":record["interrupted_settlement"],
            "current_retirement":record["current_retirement"],
            "dead_preparation_retired":record["dead_preparation_retired"],
            "retry_retirements":record["retry_retirements"]})
        )
        .expect("measurement output");
    }

    fn assert_socket_completion(resumed: bool) {
        let mut all_removed = true;
        for phase in if resumed {
            vec!["preparing", "started"]
        } else {
            vec!["started"]
        } {
            let (fixture, plan, mut request) = dead_socket_fixture(resumed, phase);
            let h = fixture.path();
            let owner = Uid::effective().as_raw();
            let root = File::open(h).expect("root");
            let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
            let paths = bind_dead_sockets(&plan);
            let path = super::super::reservation_path(h, "R");
            print_socket_record("before", &path, &paths);
            if resumed {
                let preview = complete_socket_fixture(h, &plan, &request).expect("resume preview");
                assert!(preview["checks_performed"].is_array());
                assert_eq!(preview["bound_source_matrix"]["state"], "not-applicable");
                assert!(preview.get("round").is_none());
                assert!(paths.iter().all(|path| path.exists()));
            }
            request.dry_run = false;
            let completed = complete_socket_fixture(h, &plan, &request).expect("completion");
            assert_eq!(
                completed["interrupted_settlement"]["state"],
                "completed-interrupted-settlement"
            );
            print_socket_record("completion", &path, &paths);
            let mut settle = SettleRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                step: if resumed { "work-1" } else { "dispatch" }.into(),
                dry_run: true,
                expect_digest: None,
            };
            let preview = private_recover_core(
                &plan,
                h,
                &settle,
                owner,
                crate::container_helper::process_presence,
            )
            .expect("settle preview");
            settle.dry_run = false;
            settle.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            private_recover_core(
                &plan,
                h,
                &settle,
                owner,
                crate::container_helper::process_presence,
            )
            .expect("settle");
            print_socket_record("settled", &path, &paths);
            let saved = read_reservation(&path).expect("read").expect("settled");
            assert_eq!(saved["phase"], "settled");
            assert_eq!(
                saved["rounds"]
                    .as_array()
                    .expect("rounds")
                    .last()
                    .expect("last")["phase"],
                "failed"
            );
            let removed = paths.iter().all(|p| !p.exists());
            all_removed &= removed;
            if removed {
                assert_eq!(
                    completed["interrupted_settlement"]["removed_helper_sockets"],
                    json!(paths)
                );
                assert_eq!(
                    saved["interrupted_settlement"]["removed_helper_sockets"],
                    json!(paths)
                );
                assert!(saved["current_retirement"].is_null());
                assert!(saved["dead_preparation_retired"].is_null());
            }
        }
        assert!(
            all_removed,
            "dead helper sockets survived completion and settlement"
        );
    }

    /// # Panics
    /// Panics only if dispatch recovery leaves sockets or loses its evidence.
    /// ´test:unit:dead-dispatch-entry-retires-helper-sockets´
    #[test]
    fn dead_dispatch_entry_retires_helper_sockets() {
        assert_socket_completion(false);
    }

    /// # Panics
    /// Panics only if resumed recovery leaves sockets or loses its evidence.
    /// ´test:unit:dead-resumed-round-entry-retires-helper-sockets´
    #[test]
    fn dead_resumed_round_entry_retires_helper_sockets() {
        assert_socket_completion(true);
    }

    /// # Panics
    /// Panics only if retirement uses the worker identity for owner-held sockets.
    /// ´test:unit:interrupted-completion-uses-owner-for-distinct-worker-sockets´
    #[test]
    fn interrupted_completion_uses_owner_for_distinct_worker_sockets() {
        for resumed in [false, true] {
            let (fixture, _, mut request) = dead_socket_fixture(resumed, "started");
            let h = fixture.path();
            let owner = Uid::effective().as_raw();
            let root = File::open(h).expect("root");
            let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
            let (mut plan, _) = crate::load_plan(h, "alpha", "R", (0, 0)).expect("plan");
            plan.select_worker_uid(owner + 1)
                .expect("distinct allocated worker");
            let path = super::super::reservation_path(h, "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            plan.select_container_program(&request.podman_bin)
                .expect("runtime");
            plan.select_launch_model(&record["model_selection"])
                .expect("model");
            record["worker_uid"] = json!(owner + 1);
            record["plan"] = plan.document.clone();
            super::super::publish_reservation(&path, &record).expect("distinct worker record");
            let sockets = bind_dead_sockets(&plan);
            request.dry_run = false;
            let completed = complete_socket_fixture(h, &plan, &request).expect("owner retirement");
            assert_eq!(
                completed["interrupted_settlement"]["state"],
                "completed-interrupted-settlement"
            );
            assert!(sockets.iter().all(|socket| !socket.exists()));
        }
    }

    /// # Panics
    /// Panics only if preview changes evidence or fails to name both sockets.
    /// ´test:unit:interrupted-completion-preview-preserves-helper-sockets´
    #[test]
    fn interrupted_completion_preview_preserves_helper_sockets() {
        for resumed in [false, true] {
            let (fixture, plan, request) = dead_socket_fixture(resumed, "started");
            let h = fixture.path();
            let owner = Uid::effective().as_raw();
            let root = File::open(h).expect("root");
            let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
            let paths = bind_dead_sockets(&plan);
            let path = super::super::reservation_path(h, "R");
            let before = std::fs::read(&path).expect("before");
            let preview = if resumed {
                super::super::run_with_host_root_and_proxy(h, &request, h, owner, |_| {
                    panic!("no proxy")
                })
                .expect("preview")["interrupted_settlement"]
                    .clone()
            } else {
                let record = read_reservation(&path).expect("read").expect("record");
                super::super::interrupted_settlement_with(
                    &record,
                    &plan,
                    &request.letter,
                    crate::container_helper::process_presence,
                    || Ok(true),
                    crate::launch::driver_report::fixture_read,
                )
                .expect("dispatch preview")
            };
            assert_eq!(preview["helper_sockets_to_remove"], json!(paths));
            assert_eq!(std::fs::read(&path).expect("after"), before);
            assert!(paths.iter().all(|p| p.exists()));
        }
    }

    /// # Panics
    /// Panics only if a live helper permits completion or changes custody.
    /// ´test:unit:interrupted-completion-live-helper-preserves-helper-sockets´
    #[test]
    fn interrupted_completion_live_helper_preserves_helper_sockets() {
        for resumed in [false, true] {
            let (fixture, plan, mut request) = dead_socket_fixture(resumed, "started");
            let h = fixture.path();
            let owner = Uid::effective().as_raw();
            let root = File::open(h).expect("root");
            let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
            let paths = bind_dead_sockets(&plan);
            let path = super::super::reservation_path(h, "R");
            let mut record = read_reservation(&path).expect("read").expect("record");
            record["helper_pid"] = json!(std::process::id());
            record["helper_start"] =
                json!(crate::container_helper::process_start(std::process::id()).expect("start"));
            super::super::publish_reservation(&path, &record).expect("live record");
            let before = std::fs::read(&path).expect("before");
            request.dry_run = false;
            assert_eq!(
                complete_socket_fixture(h, &plan, &request)
                    .expect_err("live helper")
                    .kind,
                "launch-busy"
            );
            assert_eq!(std::fs::read(&path).expect("after"), before);
            assert!(paths.iter().all(|p| p.exists()));
            assert!(!h.join(".report=R.json").exists());
            assert!(!h.join(".report=R=work-1.json").exists());
        }
    }

    /// # Panics
    /// Panics only if an interrupted completion loses already-published socket evidence.
    /// ´test:unit:interrupted-completion-retry-retains-removed-helper-sockets´
    #[test]
    fn interrupted_completion_retry_retains_removed_helper_sockets() {
        let (fixture, plan, mut request) = dead_socket_fixture(true, "started");
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root = File::open(h).expect("root");
        let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
        let paths = bind_dead_sockets(&plan);
        let path = super::super::reservation_path(h, "R");
        let record = read_reservation(&path).expect("read").expect("record");
        let letter = Path::new(record["letter_source"].as_str().expect("letter"));
        let interrupted = std::panic::catch_unwind(|| {
            let _lease = super::super::lock_run_preparation(h, "R", owner).expect("lease");
            super::super::finish_interrupted_settlement_with(
                &path,
                &plan,
                letter,
                owner,
                || Ok(Value::Null),
                || panic!("injected interruption after socket retirement"),
                crate::container_helper::process_presence,
                || Ok(true),
                |_| panic!("must not reach reaping"),
                crate::launch::driver_report::fixture_read,
            )
        });
        assert!(interrupted.is_err());
        assert!(paths.iter().all(|p| !p.exists()));
        let pending = read_reservation(&path).expect("read").expect("pending");
        assert_eq!(pending["phase"], "started");
        assert_eq!(pending["interrupted_settlement"]["round"], "work-1");
        assert_eq!(
            pending["interrupted_settlement"]["helper_sockets_to_remove"],
            json!(paths)
        );
        assert_eq!(
            pending["interrupted_settlement"]["socket_removal_state"],
            "confirmed-absent"
        );
        assert_eq!(
            pending["interrupted_settlement"]["removed_helper_sockets"],
            json!(paths)
        );
        request.dry_run = false;
        let completed = complete_socket_fixture(h, &plan, &request).expect("retry");
        assert_eq!(
            completed["interrupted_settlement"]["removed_helper_sockets"],
            json!(paths)
        );
        let saved = read_reservation(&path).expect("read").expect("saved");
        assert_eq!(
            saved["interrupted_settlement"],
            pending["interrupted_settlement"]
        );
    }

    /// # Panics
    /// Panics only if an interrupted completion loses already-published socket evidence.
    /// ´test:unit:interrupted-completion-retry-confirms-intent-without-claiming-removal´
    #[test]
    fn interrupted_completion_retry_confirms_intent_without_claiming_removal() {
        let (fixture, plan, mut request) = dead_socket_fixture(true, "started");
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root = File::open(h).expect("root");
        let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
        let paths = bind_dead_sockets(&plan);
        let path = super::super::reservation_path(h, "R");
        let record = read_reservation(&path).expect("read").expect("record");
        let letter = Path::new(record["letter_source"].as_str().expect("letter"));
        let interrupted = std::panic::catch_unwind(|| {
            let _lease = super::super::lock_run_preparation(h, "R", owner).expect("lease");
            super::super::finish_interrupted_settlement_with(
                &path,
                &plan,
                letter,
                owner,
                || Ok(Value::Null),
                || panic!("injected interruption after socket retirement"),
                crate::container_helper::process_presence,
                || Ok(true),
                |_| panic!("must not reach reaping"),
                crate::launch::driver_report::fixture_read,
            )
        });
        assert!(interrupted.is_err());
        assert!(paths.iter().all(|p| !p.exists()));
        let mut pending = read_reservation(&path).expect("read").expect("pending");
        pending["interrupted_settlement"]["removed_helper_sockets"] = json!([]);
        pending["interrupted_settlement"]["socket_removal_state"] = json!("pending");
        super::super::publish_reservation(&path, &pending)
            .expect("intent before interrupted confirmation");
        request.dry_run = false;
        let completed = complete_socket_fixture(h, &plan, &request).expect("retry");
        assert!(
            completed["interrupted_settlement"]
                .get("removed_helper_sockets")
                .is_none()
        );
        let saved = read_reservation(&path).expect("read").expect("saved");
        assert_eq!(
            saved["interrupted_settlement"]["helper_sockets_to_remove"],
            json!(paths)
        );
        assert_eq!(
            saved["interrupted_settlement"]["removed_helper_sockets"],
            json!([])
        );
        assert_eq!(
            saved["interrupted_settlement"]["socket_removal_state"],
            "confirmed-absent"
        );
    }

    /// # Panics
    /// Panics only if successive completions attribute old removals to the new round.
    /// ´test:unit:interrupted-completion-new-round-does-not-reuse-socket-removals´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn interrupted_completion_new_round_does_not_reuse_socket_removals() {
        let (fixture, plan, mut request) = dead_socket_fixture(true, "started");
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root: std::os::fd::OwnedFd = File::open(h).expect("root").into();
        let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
        let paths = bind_dead_sockets(&plan);
        let path = super::super::reservation_path(h, "R");
        request.dry_run = false;
        let first = complete_socket_fixture(h, &plan, &request).expect("first completion");
        assert_eq!(
            first["interrupted_settlement"]["removed_helper_sockets"],
            json!(paths)
        );
        assert!(paths.iter().all(|p| !p.exists()));
        let mut settle = SettleRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            step: "work-1".into(),
            dry_run: true,
            expect_digest: None,
        };
        let preview = private_recover_core(
            &plan,
            h,
            &settle,
            owner,
            crate::container_helper::process_presence,
        )
        .expect("settle preview");
        settle.dry_run = false;
        settle.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        private_recover_core(
            &plan,
            h,
            &settle,
            owner,
            crate::container_helper::process_presence,
        )
        .expect("settle first round");
        let first_report = super::super::report::read_bound(&root, "R", Some("work-1"), owner)
            .expect("first report");
        let mut record = read_reservation(&path).expect("read").expect("record");
        let evidence = record["interrupted_settlement"].clone();
        let helper = (record["helper_pid"].clone(), record["helper_start"].clone());
        request.round = Some("work-2".into());
        let directory = plan.driver_dir.join("20261007T053545Z-work-2");
        std::fs::create_dir(&directory).expect("second round directory");
        std::fs::write(directory.join("events.jsonl"), b"").expect("no second thread");
        std::fs::write(directory.join(".event-start"), b"0\n").expect("event boundary");
        std::fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=work-2 exit=1 verdict=failed dir={}\n",
                directory.display()
            ),
        )
        .expect("second driver report");
        let letter = plan.home.join(".local/inbox/work-2.md");
        std::fs::write(&letter, b"Continue.\n").expect("second letter");
        std::fs::set_permissions(&letter, std::fs::Permissions::from_mode(0o600))
            .expect("letter mode");
        let next = rounds::continuation_round(
            &record,
            &request,
            &directory,
            &json!({"placed_at_unix_ns":2}),
        )
        .expect("second round");
        record["rounds"].as_array_mut().expect("rounds").push(next);
        record["phase"] = json!("preparing");
        record["active_round"] = json!("work-2");
        record["letter_source"] = json!(letter);
        // The new launcher/driver/helper-parent have also died. The predecessor's
        // helper identity remains because the next helper never published its own.
        for field in [
            "driver_end",
            "helper_end",
            "readback_end",
            "reaping_recovery",
        ] {
            record[field] = Value::Null;
        }
        super::super::publish_reservation(&path, &record).expect("dead second round");
        let second = complete_socket_fixture(h, &plan, &request).expect("second completion");
        assert!(
            second["interrupted_settlement"]
                .get("removed_helper_sockets")
                .is_none()
        );
        assert_eq!(
            super::super::report::read_bound(&root, "R", Some("work-2"), owner)
                .expect("second report"),
            second
        );
        assert_eq!(
            super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                .expect("first report retained"),
            first_report
        );
        let saved = read_reservation(&path).expect("read").expect("saved");
        assert_eq!(
            (saved["helper_pid"].clone(), saved["helper_start"].clone()),
            helper
        );
        assert_eq!(saved["interrupted_settlement"], evidence);
        assert!(paths.iter().all(|p| !p.exists()));
    }

    /// # Panics
    /// Panics only if the report reader accepts malformed socket evidence or rejects valid evidence.
    /// ´test:unit:interrupted-completion-report-validates-socket-evidence´
    #[test]
    fn interrupted_completion_report_validates_socket_evidence() {
        let (fixture, plan, mut request) = dead_socket_fixture(true, "started");
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root: std::os::fd::OwnedFd = File::open(h).expect("root").into();
        let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
        let paths = bind_dead_sockets(&plan);
        request.dry_run = false;
        let report = complete_socket_fixture(h, &plan, &request).expect("completion");
        assert_eq!(
            super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                .expect("valid report"),
            report
        );
        let path = h.join(".report=R=work-1.json");
        for invalid in [
            Value::Null,
            json!([]),
            json!(true),
            json!([1]),
            json!(["relative"]),
            json!([paths[0], paths[0]]),
            json!([paths[0], paths[1], "/third"]),
        ] {
            let mut changed = report.clone();
            changed["interrupted_settlement"]["removed_helper_sockets"] = invalid;
            std::fs::write(&path, serde_json::to_vec(&changed).expect("report bytes"))
                .expect("report");
            assert_eq!(
                super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                    .expect_err("invalid evidence")
                    .kind,
                "read-launch-report"
            );
        }
        let mut misplaced = report.clone();
        misplaced["removed_helper_sockets"] = json!(paths);
        let mut settled = report.clone();
        settled["interrupted_settlement"] = json!({"state":"completed-settle-round","preview_sha256":"a".repeat(64),"phase":"complete","detail":null,"removed_helper_sockets":paths});
        for changed in [misplaced, settled] {
            std::fs::write(&path, serde_json::to_vec(&changed).expect("report bytes"))
                .expect("report");
            assert_eq!(
                super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                    .expect_err("socket evidence outside completion")
                    .kind,
                "read-launch-report"
            );
        }
        let mut older = report.clone();
        older["interrupted_settlement"]
            .as_object_mut()
            .expect("completion")
            .remove("removed_helper_sockets");
        std::fs::write(&path, serde_json::to_vec(&older).expect("report bytes")).expect("report");
        assert_eq!(
            super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                .expect("older report"),
            older
        );
        let mut single = report;
        single["interrupted_settlement"]["removed_helper_sockets"] = json!([paths[0]]);
        std::fs::write(&path, serde_json::to_vec(&single).expect("report bytes")).expect("report");
        assert_eq!(
            super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                .expect("one removed socket"),
            single
        );
    }

    /// # Panics
    ///
    /// Panics only if the resume entry fails to preview the dead round without writes.
    /// ´test:unit:dead-resumed-round-entry-preview´
    #[test]
    fn dead_resumed_round_entry_preview() {
        for phase in ["preparing", "started"] {
            let (fixture, _, request) = dead_resume_fixture(phase);
            let h = fixture.path();
            let path = super::super::reservation_path(h, "R");
            let before = std::fs::read(&path).expect("before");
            let result = super::super::run_with_host_root_and_proxy(
                h,
                &request,
                h,
                Uid::effective().as_raw(),
                |_| Ok(("active".into(), "fixture-invocation".into())),
            );
            let preview = result.expect("resume recovery preview");
            assert_eq!(
                preview["interrupted_settlement"]["state"],
                "would-complete-interrupted-settlement"
            );
            assert_eq!(
                preview["interrupted_settlement"]["attempt_evidence"]["state"],
                "absence-confirmed-with-missing-evidence"
            );
            assert_eq!(std::fs::read(&path).expect("after"), before);
            assert!(!h.join(".report=R=work-1.json").exists());
        }
    }

    /// # Panics
    ///
    /// Panics only if resume recovery or digest-bound settlement loses the failed round.
    /// ´test:unit:dead-resumed-round-entry-settles-by-report´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn dead_resumed_round_entry_settles_by_report() {
        for phase in ["preparing", "started"] {
            let (fixture, plan, mut request) = dead_resume_fixture(phase);
            let h = fixture.path();
            let owner = Uid::effective().as_raw();
            let root: std::os::fd::OwnedFd = File::open(h).expect("fixture root").into();
            let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
            let path = super::super::reservation_path(h, "R");
            let before = read_reservation(&path).expect("read").expect("before");
            let args = [
                "launch".into(),
                "alpha".into(),
                "R".into(),
                "--round".into(),
                "work-1".into(),
            ];
            assert!(
                super::super::reaping::scope_preflight_with(h, &args, |_| {
                    panic!("recovery must not require a live vendor service")
                })
                .expect("outer admission")
            );
            let preview = super::super::run_with_host_root_and_proxy(h, &request, h, owner, |_| {
                panic!("recovery preview must not require a live vendor service")
            })
            .expect("preview without proxy");
            assert_eq!(preview["changed"], false);
            request.dry_run = false;
            let recovered = rounds::resume_with_evidence(h, &request, h, owner, |_| {
                panic!("recovery must not require a live vendor service")
            }, &mut |_| {}, crate::container_helper::process_presence, |saved| {
                Ok(json!({"state":"collected","cgroup":saved["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}}))
            }).expect("resume entry completes interrupted settlement");
            assert_eq!(
                recovered["interrupted_settlement"]["state"],
                "completed-interrupted-settlement"
            );
            assert_eq!(recovered["interrupted_settlement"]["phase"], "failed");
            assert!(
                recovered["interrupted_settlement"]
                    .get("removed_helper_sockets")
                    .is_none()
            );
            let failed = read_reservation(&path).expect("read").expect("failed");
            assert!(failed.get("interrupted_settlement").is_none());
            assert_eq!(failed["phase"], "failed");
            assert_eq!(failed["rounds"][0], before["rounds"][0]);
            assert_eq!(failed["rounds"][1]["phase"], "failed");
            assert!(failed["rounds"][1]["settlement_error"].is_string());
            assert_eq!(failed["driver_end"], before["driver_end"]);
            assert_eq!(failed["helper_end"], before["helper_end"]);
            assert_eq!(failed["settlement_uncertain"], false);
            assert_eq!(failed["reaping_recovery"]["presence"], "all-absent");
            assert_ne!(
                failed["reaping_recovery"], before["reaping_recovery"],
                "resumed collection replaces dispatch proof"
            );
            assert_eq!(
                failed["reaping_recovery"]["attempt_evidence"]["state"],
                "absence-confirmed-with-missing-evidence"
            );
            super::super::reaping::recovery_verdict(&failed).expect("same measured proof");
            let published = super::super::report::read_bound(&root, "R", Some("work-1"), owner)
                .expect("recovered report");
            assert_eq!(published, recovered);
            let mut settle = SettleRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                step: "work-1".into(),
                dry_run: true,
                expect_digest: None,
            };
            let preview = private_recover_core(
                &plan,
                h,
                &settle,
                owner,
                crate::container_helper::process_presence,
            )
            .expect("settle preview");
            settle.dry_run = false;
            settle.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let settled = private_recover_core(
                &plan,
                h,
                &settle,
                owner,
                crate::container_helper::process_presence,
            )
            .expect("digest-bound settle");
            assert_eq!(settled["settlement"]["ended_by"], "by-report");
            assert!(settled["settlement"]["readback"].is_null());
            let final_record = read_reservation(&path)
                .expect("read")
                .expect("settled record");
            assert_eq!(final_record["phase"], "settled");
            assert_eq!(final_record["rounds"][0], before["rounds"][0]);
            assert_eq!(final_record["rounds"][1]["phase"], "failed");
            assert_eq!(final_record["rounds"][1]["ended_by"], "by-report");
            assert!(final_record["rounds"][1]["reply"].is_null());
            assert_eq!(
                final_record["rounds"][1]["settle_attempts"][0]["phase"],
                "complete"
            );
            assert!(rounds::threadless_continuation(&final_record));
        }
    }

    /// # Panics
    ///
    /// Panics only if unsafe resume admission mutates recovery evidence.
    /// ´test:unit:dead-resumed-round-entry-refuses-unsafe-states´
    #[test]
    fn dead_resumed_round_entry_refuses_unsafe_states() {
        for phase in ["preparing", "started"] {
            let (fixture, _, mut request) = dead_resume_fixture(phase);
            let h = fixture.path();
            let path = super::super::reservation_path(h, "R");
            let saved = read_reservation(&path).expect("read").expect("saved");
            for (pointer, value, kind) in [
                ("/launcher_pid", json!(std::process::id()), "launch-busy"),
                ("/helper_start", Value::Null, "launch-reservation"),
                ("/launcher_start", json!(2), "settlement-uncertain"),
                ("/active_round", json!("other"), "round-state"),
                ("/rounds/1/step", json!("other"), "round-state"),
                ("/rounds/1/phase", json!("failed"), "round-state"),
                ("/phase", json!("failed"), "round-state"),
                ("/run", json!("other"), "round-record"),
            ] {
                let mut record = saved.clone();
                *record.pointer_mut(pointer).expect("fixture field") = value;
                if pointer == "/launcher_pid" {
                    record["launcher_start"] = json!(
                        crate::container_helper::process_start(std::process::id())
                            .expect("live start")
                    );
                }
                for dry_run in [true, false] {
                    request.dry_run = dry_run;
                    super::super::publish_reservation(&path, &record).expect("unsafe record");
                    let before = std::fs::read(&path).expect("before");
                    let error = rounds::resume_with_evidence(
                        h,
                        &request,
                        h,
                        Uid::effective().as_raw(),
                        |_| Ok(("active".into(), "fixture".into())),
                        &mut |_| {},
                        |pid, start| {
                            if pointer == "/launcher_start" {
                                ProcessPresence::Unknown
                            } else {
                                crate::container_helper::process_presence(pid, start)
                            }
                        },
                        |_| panic!("refused state must not reap"),
                    )
                    .expect_err("unsafe state");
                    assert_eq!(error.kind, kind, "{pointer}: {error:?}");
                    if pointer == "/phase" {
                        assert!(
                            error
                                .detail
                                .contains("run settle alpha R --round STEP --dry-run")
                        );
                        assert!(
                            error
                                .detail
                                .contains("apply its preview_sha256 with --expect-digest")
                        );
                    }
                    assert_eq!(std::fs::read(&path).expect("after"), before);
                    assert!(!h.join(".report=R=work-1.json").exists());
                }
            }
        }
    }

    /// Copies the test executable under TMPDIR when protected, otherwise directly
    /// under HOME; the temporary directory removes the copy at normal test exit.
    ///
    /// # Panics
    ///
    /// Panics only if fixture setup or the recovered continuation contract fails.
    /// ´test:unit:interrupted-dispatch-without-thread-continues-in-same-run´
    #[test]
    fn interrupted_dispatch_without_thread_continues_in_same_run() {
        use std::os::unix::fs::MetadataExt as _;

        if std::env::var("SUPERLOOP_RESUME_ENTRY_FIXTURE").as_deref() == Ok("inspect") {
            let h = PathBuf::from(std::env::var_os("HOME").expect("fixture home"));
            let owner = Uid::effective().as_raw();
            let fds = home::receive_private_descriptors(&std::io::stdin(), 2)
                .expect("inspection descriptors");
            let _guard = home::activate_private_launch(&h, &fds[0], &h, &fds[1], None, owner)
                .expect("mapped custody");
            let result = rounds::inspect_current_round(&h, "alpha", "R", None)
                .expect("production private inspection");
            std::fs::write(h.join("inspection.json"), result.to_string())
                .expect("inspection result");
            return;
        }
        if std::env::var_os("SUPERLOOP_RESUME_ENTRY_FIXTURE").is_none() {
            let mut root = tempfile::TempDir::new().expect("temporary test entry");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("entry directory mode");
            let probe = root.path().join("test-entry");
            crate::fixture_exec::write_executable(&probe, b"#!/bin/sh\nexit 0\n")
                .expect("fixture-entry-probe");
            if crate::pinned::owner_executable(&probe, Uid::effective().as_raw()).is_err() {
                // A group-writable TMPDIR ancestor is refused by production. This
                // fixture then writes its executable directly under protected HOME.
                root = tempfile::TempDir::new_in(
                    std::env::var_os("HOME").expect("fixture-entry-home"),
                )
                .expect("fixture-entry-protected-directory");
                std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                    .expect("protected entry directory mode");
            }
            let entry = root.path().join("test-entry");
            crate::fixture_exec::write_executable(
                &entry,
                &std::fs::read(std::env::current_exe().expect("test executable"))
                    .expect("entry bytes"),
            )
            .expect("protected entry");
            assert_eq!(
                std::fs::metadata(&entry).expect("entry metadata").nlink(),
                1
            );
            crate::pinned::owner_executable(&entry, Uid::effective().as_raw())
                .expect("fixture-entry-protection");
            let output = crate::fixture_exec::output(std::process::Command::new(&entry)
                .args(["--exact", "launch::settle::tests::interrupted_dispatch_without_thread_continues_in_same_run"])
                .env("SUPERLOOP_RESUME_ENTRY_FIXTURE", "1"))
                .expect("isolated resume fixture");
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        resume_threadless_dispatch_through_entry();
        recovered_threadless_continuation(false, false);
        row_144_recovery_through_entry(false);
        row_144_recovery_through_entry(true);
        row_144_cleanup_uses_owner_not_worker();
    }

    fn exited_container_runtime(h: &Path, program: &Path) -> Value {
        let container = json!({"id":"a".repeat(64),"name":"superloop-lane-alpha-R-attempt-1",
            "labels":{"org.superloop.loop":"alpha","org.superloop.run":"R"},
            "state":{"Status":"exited","Running":false,"Paused":false,"Restarting":false,"Pid":0,"ExitCode":143,"FinishedAt":"2026-10-18T00:00:00Z"}});
        std::fs::write(h.join("container.json"), container.to_string()).expect("exited container");
        crate::fixture_exec::write_executable(program, br"#!/usr/bin/python3
import json, os, pathlib, subprocess, sys
root = pathlib.Path(os.environ['HOME'])
path = root / 'container.json'
args = sys.argv[1:]
if args[0] == 'ps':
    assert args == ['ps', '--all', '--no-trunc', '--format', '{{.ID}}', '--filter', 'label=org.superloop.loop=alpha', '--filter', 'label=org.superloop.run=R']
    if path.exists(): print(json.loads(path.read_text())['id'])
elif args[:2] == ['container', 'inspect']:
    data = json.loads(path.read_text())
    assert args == ['container', 'inspect', data['id']]
    print(json.dumps([{'Id': data['id'], 'Name': data['name'], 'Config': {'Labels': data['labels']}, 'State': data['state']}]))
elif args[0] == 'rm':
    data = json.loads(path.read_text())
    assert args == ['rm', '--ignore', data['id']]
    assert data['state']['Status'] == 'exited'
    with (root / 'removed').open('a') as log: log.write(data['id'] + '\n')
    if (root / 'remove-fails').exists(): sys.exit(19)
    if not (root / 'remove-survives').exists(): path.unlink()
    if (root / 'remove-disappears').exists(): sys.exit(19)
    print(data['id'])
elif args[0] == 'unshare':
    if '_inspect-round' in args:
        if '--record' in args:
            print('fixture-round-evidence-stop', file=sys.stderr)
            sys.exit(17)
        env = dict(os.environ, SUPERLOOP_RESUME_ENTRY_FIXTURE='inspect')
        result = subprocess.run([args[1], '--exact', 'launch::settle::tests::interrupted_dispatch_without_thread_continues_in_same_run'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            sys.stderr.buffer.write(result.stdout + result.stderr)
            sys.exit(result.returncode)
        print((root / 'inspection.json').read_text())
    else:
        print('settle-evidence: no thread or reply', file=sys.stderr)
        sys.exit(2)
else:
    sys.exit(9)
").expect("exited container runtime");
        container
    }

    fn row_144_cleanup_uses_owner_not_worker() {
        let exe = std::env::current_exe().expect("protected entry");
        let (fixture, _, mut request) =
            dead_resume_fixture_in("started", exe.parent().expect("protected parent"));
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root = File::open(h).expect("root");
        let _guard = home::activate_handed_home(h, &root, owner).expect("custody");
        let worker = owner + 1;
        assert_ne!(owner, worker);
        let (mut plan, _) = crate::load_plan(h, "alpha", "R", (0, 0)).expect("plan");
        plan.select_worker_uid(worker).expect("allocated worker");
        let path = super::super::reservation_path(h, "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        plan.select_container_program(&request.podman_bin)
            .expect("runtime");
        plan.select_launch_model(&record["model_selection"])
            .expect("model");
        record["plan"] = plan.document.clone();
        record["worker_uid"] = json!(worker);
        record["reaping_recovery"] = Value::Null;
        super::super::publish_reservation(&path, &record).expect("distinct worker");
        exited_container_runtime(h, &request.podman_bin);
        let preview = super::super::run_with_host_root_and_proxy(h, &request, h, owner, |_| {
            panic!("recovery needs no proxy")
        })
        .expect("owner inspects exited container");
        request.dry_run = false;
        request.expect_digest = preview["interrupted_settlement"]["preview_sha256"]
            .as_str()
            .map(str::to_owned);
        let completed =
            complete_socket_fixture(h, &plan, &request).expect("owner removes exited container");
        assert_eq!(completed["interrupted_settlement"]["phase"], "failed");
        assert!(!h.join("container.json").exists());
        let saved = read_reservation(&path).expect("read").expect("record");
        assert_eq!(saved["worker_uid"], worker);
        assert_eq!(
            saved["interrupted_container_cleanup"]["state"],
            "confirmed-absent"
        );
    }

    #[allow(clippy::too_many_lines)]
    fn row_144_recovery_through_entry(resumed: bool) {
        let parent = std::env::current_exe().expect("protected executable");
        let (fixture, plan, mut request) =
            dead_resume_fixture_in("started", parent.parent().expect("protected parent"));
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root = File::open(h).expect("fixture root");
        let _guard = home::activate_handed_home(h, &root, owner).expect("private custody");
        let path = super::super::reservation_path(h, "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        if !resumed {
            let mut dispatch = record["rounds"][1].clone();
            let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
            std::fs::rename(
                dispatch["driver_dir"].as_str().expect("directory"),
                &directory,
            )
            .expect("dispatch directory");
            std::fs::write(
                directory.join("run-report.txt"),
                format!(
                    "RUN-REPORT lane=dispatch exit=143 verdict=failed dir={}\n",
                    directory.display()
                ),
            )
            .expect("signal report");
            dispatch["step"] = json!("dispatch");
            dispatch["driver_dir"] = json!(directory);
            record["rounds"] = json!([dispatch]);
            record["active_round"] = json!("dispatch");
            request.round = None;
            request.letter = PathBuf::from(record["letter_source"].as_str().expect("letter"));
        }
        // Interrupted settlement has no completed proof for this launcher generation.
        record["reaping_recovery"] = Value::Null;
        super::super::publish_reservation(&path, &record).expect("interrupted reservation");
        let container = exited_container_runtime(h, &request.podman_bin);
        if resumed {
            let custody =
                crate::plan::protected_identity_dir(&plan.driver_dir).expect("attempt custody");
            for (name, value) in [
                (
                    "container-attempt-1.start.json",
                    json!({"schema":1,"attempt":1,"state":"started","launcher_pid":record["launcher_pid"],"launcher_start":record["launcher_start"],"container_name":container["name"]}),
                ),
                (
                    "container-attempt-1.status.json",
                    json!({"schema":1,"attempt":1,"bounded":true,"launcher_pid":record["launcher_pid"],"launcher_start":record["launcher_start"],"status":143,"capacity_evidence":false,"stream_errors":[],"stream_error":null,"wait_error":null,"stop_error":null,"thread_error":null,"post_start_error":null,"removal":{"state":"pending"}}),
                ),
            ] {
                let file = custody.join(name);
                std::fs::write(&file, value.to_string()).expect("half-written attempt");
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
                    .expect("attempt mode");
            }
        }
        let mut next = super::super::LaunchRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "work-2".into(),
            "--podman-bin".into(),
            request.podman_bin.display().to_string(),
            "--dry-run".into(),
        ])
        .expect("next launch");
        super::super::admission::set(h, "alpha", true).expect("paused admission");
        assert_eq!(
            super::super::run_with_host_root_and_proxy(h, &next, h, owner, |_| panic!(
                "paused admission precedes service checks"
            ))
            .expect_err("paused loop")
            .kind,
            "launch-paused"
        );
        super::super::admission::set(h, "alpha", false).expect("resume admission after reboot");
        // Steps 1-3: service restart alone does not settle the interrupted reservation.
        assert_eq!(
            super::super::run_with_host_root_and_proxy(h, &next, h, owner, |_| Ok((
                "inactive".into(),
                String::new()
            )))
            .expect_err("stopped service")
            .kind,
            "proxy-service-death"
        );
        assert_eq!(
            super::super::run_with_host_root_and_proxy(h, &next, h, owner, |_| Ok((
                "active".into(),
                "new-invocation".into()
            )))
            .expect_err("unsettled run")
            .kind,
            "round-state"
        );
        let mut settle = SettleRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            step: record["active_round"].as_str().expect("active step").into(),
            dry_run: true,
            expect_digest: None,
        };
        assert_eq!(
            private_recover_core(
                &plan,
                h,
                &settle,
                owner,
                crate::container_helper::process_presence
            )
            .expect_err("not yet failed")
            .kind,
            "settle-state-refusal"
        );
        let preview = |request: &super::super::LaunchRequest| {
            if resumed {
                super::super::run_with_host_root_and_proxy(h, request, h, owner, |_| {
                    panic!("recovery needs no proxy")
                })
                .map(|report| report["interrupted_settlement"].clone())
            } else {
                // The dispatch's existing installed-pin entry fixture separately exercises
                // admission; this fixture enters the same production recovery decision.
                let saved = read_reservation(&path).expect("read").expect("record");
                super::super::interrupted_recovery_preview(
                    &saved,
                    &plan,
                    &request.letter,
                    request,
                    h,
                    crate::container_helper::process_presence,
                )
            }
        };
        let before = std::fs::read(&path).expect("before preview");
        // Step 4: Exited(143) is proposed for removal, never called absent in preview.
        let proposed = preview(&request).expect("read-only cleanup preview");
        assert_eq!(proposed["containers_to_remove"], json!([container]));
        assert_eq!(
            proposed["attempt_evidence"]["state"],
            "would-confirm-absence-with-missing-evidence"
        );
        assert_eq!(std::fs::read(&path).expect("unchanged"), before);
        assert!(h.join("container.json").exists());
        assert!(!h.join("removed").exists());
        let mut live = record.clone();
        live["launcher_pid"] = json!(std::process::id());
        live["launcher_start"] = json!(
            crate::container_helper::process_start(std::process::id()).expect("current identity")
        );
        super::super::publish_reservation(&path, &live).expect("live launcher");
        assert_eq!(
            preview(&request).expect_err("live process").kind,
            "launch-busy"
        );
        assert!(!h.join("removed").exists());
        super::super::publish_reservation(&path, &record).expect("dead launcher");
        for (pointer, value) in [
            ("/id", json!("short")),
            ("/name", Value::Null),
            ("/labels/org.superloop.loop", json!("other")),
            ("/labels/org.superloop.run", json!("other")),
            ("/state/Status", json!("running")),
            ("/state/Running", json!(true)),
            ("/state/Paused", json!(true)),
            ("/state/Restarting", json!(true)),
            ("/state/Status", Value::Null),
            ("/state/Pid", json!(1)),
            ("/state/ExitCode", Value::Null),
            ("/state/FinishedAt", Value::Null),
        ] {
            let mut changed = container.clone();
            *changed.pointer_mut(pointer).expect("fixture field") = value;
            std::fs::write(h.join("container.json"), changed.to_string())
                .expect("changed container");
            assert_eq!(
                preview(&request)
                    .expect_err("unknown, live or foreign container")
                    .kind,
                "settlement-container"
            );
        }
        std::fs::write(h.join("container.json"), container.to_string()).expect("restore container");
        request.dry_run = false;
        for digest in [None, Some("0".repeat(64))] {
            request.expect_digest = digest;
            assert_eq!(
                complete_socket_fixture(h, &plan, &request)
                    .expect_err("digest required")
                    .kind,
                "settlement-digest"
            );
            assert!(!h.join("removed").exists());
            assert_eq!(std::fs::read(&path).expect("unchanged"), before);
        }
        request.expect_digest = proposed["preview_sha256"].as_str().map(str::to_owned);
        let mut changed = container.clone();
        changed["state"]["ExitCode"] = json!(137);
        std::fs::write(h.join("container.json"), changed.to_string())
            .expect("changed exit evidence");
        assert_eq!(
            complete_socket_fixture(h, &plan, &request)
                .expect_err("changed digest")
                .kind,
            "settlement-digest"
        );
        assert!(!h.join("removed").exists());
        std::fs::write(h.join("container.json"), container.to_string()).expect("restore container");
        if resumed {
            for (marker, refusal) in [
                ("remove-fails", "settlement-container"),
                ("remove-survives", "settlement-uncertain"),
                ("remove-disappears", "settlement-container"),
            ] {
                std::fs::write(h.join(marker), b"fixture").expect("removal fault");
                request.dry_run = true;
                request.expect_digest = None;
                let retry = preview(&request).expect("fresh cleanup preview");
                request.dry_run = false;
                request.expect_digest = retry["preview_sha256"].as_str().map(str::to_owned);
                assert_eq!(
                    complete_socket_fixture(h, &plan, &request)
                        .expect_err("bounded cleanup failure")
                        .kind,
                    refusal
                );
                assert_eq!(
                    h.join("container.json").exists(),
                    marker != "remove-disappears"
                );
                let pending = read_reservation(&path).expect("read").expect("pending");
                assert_eq!(pending["phase"], "started");
                assert_eq!(pending["interrupted_container_cleanup"]["state"], "pending");
                std::fs::remove_file(h.join(marker)).expect("clear fixture fault");
            }
            request.dry_run = true;
            request.expect_digest = None;
            let retry = preview(&request).expect("retry after partial cleanup");
            request.dry_run = false;
            request.expect_digest = retry["preview_sha256"].as_str().map(str::to_owned);
        }
        // Step 5: only the production act removes the labelled container and finishes recovery.
        let recovered = complete_socket_fixture(h, &plan, &request).expect("cleanup and recovery");
        assert_eq!(recovered["interrupted_settlement"]["phase"], "failed");
        assert_eq!(
            recovered["interrupted_settlement"]["attempt_evidence"]["state"],
            "absence-confirmed-with-missing-evidence"
        );
        if resumed {
            assert_eq!(
                recovered["interrupted_settlement"]["attempt_evidence"]["attempts"][0]["removal"],
                "pending"
            );
            assert_eq!(
                recovered["interrupted_settlement"]["attempt_evidence"]["attempts"][0]["status"],
                143
            );
        }
        assert_eq!(
            std::fs::read_to_string(h.join("removed")).expect("removal log"),
            format!("{}\n", "a".repeat(64)).repeat(if resumed { 3 } else { 1 })
        );
        assert!(!h.join("container.json").exists());
        let failed = read_reservation(&path).expect("read").expect("failed");
        assert_eq!(
            failed["interrupted_container_cleanup"]["state"],
            "confirmed-absent"
        );
        // Distinct worker UID must fail outbox custody; equal identities cannot hide this check.
        let mut wrong_worker = failed.clone();
        wrong_worker["worker_uid"] = json!(owner + 1);
        wrong_worker["plan"]["worker_uid"] = json!(owner + 1);
        super::super::publish_reservation(&path, &wrong_worker).expect("distinct worker fixture");
        let error = private_recover_core(
            &plan,
            h,
            &settle,
            owner,
            crate::container_helper::process_presence,
        )
        .expect_err("outbox belongs to different worker");
        assert!(error.line().contains("outbox uid"), "{}", error.line());
        super::super::publish_reservation(&path, &failed).expect("restore worker");
        // Step 6: production settlement preserves a failed outcome and null reply.
        let settlement = private_recover_core(
            &plan,
            h,
            &settle,
            owner,
            crate::container_helper::process_presence,
        )
        .expect("settle preview");
        settle.dry_run = false;
        settle.expect_digest = settlement["preview_sha256"].as_str().map(str::to_owned);
        let settled = private_recover_core(
            &plan,
            h,
            &settle,
            owner,
            crate::container_helper::process_presence,
        )
        .expect("settle apply");
        assert_eq!(settled["settlement"]["ended_by"], "by-report");
        assert!(settled["settlement"]["readback"].is_null());
        let retained = read_reservation(&path).expect("read").expect("settled");
        // Steps 7-8: use the production letter writer and resumed launch entry.
        let letter = h.join("next-letter");
        std::fs::write(&letter, "Continue after reboot.\n").expect("next letter");
        std::fs::set_permissions(&letter, std::fs::Permissions::from_mode(0o600))
            .expect("letter mode");
        super::super::letters::private_send_with_owner(
            h,
            "alpha",
            "R",
            &letter,
            "work-2",
            &build::sha256(&letter).expect("digest"),
            owner,
        )
        .expect("place next letter");
        let launch = super::super::run_with_host_root_and_proxy(h, &next, h, owner, |_| {
            Ok(("active".into(), "new-invocation".into()))
        })
        .expect("threadless continuation preview");
        assert_eq!(launch["dry_run"], true);
        // Step 9: rotation acknowledges completion even though there is no handover reply.
        let rotate = super::super::rotation::RotateRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--dry-run".into(),
        ])
        .expect("rotate request");
        let refusal = super::super::rotation::run_with_host_root(h, &rotate, h, owner)
            .expect_err("missing reply");
        assert_eq!(refusal.kind, "rotate-reply-absent");
        assert!(refusal.detail.contains("settlement completed"));
        assert!(refusal.detail.contains("launch alpha R --round NEW"));
        let placed = read_reservation(&path)
            .expect("read")
            .expect("placed letter");
        let mut continued = placed.clone();
        continued["active_round"] = json!("work-2");
        continued["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({
                "step":"work-2","phase":"settled","reply":{"bytes":6},"settle_attempts":[]
            }));
        super::super::publish_reservation(&path, &continued).expect("settled continuation");
        let refusal = super::super::rotation::run_with_host_root(h, &rotate, h, owner)
            .expect_err("earlier reply remains absent");
        assert_eq!(refusal.kind, "rotate-reply-absent");
        assert!(refusal.detail.contains("earlier reply-less failed round"));
        assert!(refusal.detail.contains("cannot hand over"));
        assert!(!refusal.detail.contains("--round NEW"));
        super::super::publish_reservation(&path, &placed).expect("restore last failed round");
        next.dry_run = false;
        let error = super::super::run_with_host_root_and_proxy(h, &next, h, owner, |_| {
            Ok(("active".into(), "new-invocation".into()))
        })
        .expect_err("stop after production round preparation");
        assert!(
            error.line().contains("fixture-round-evidence-stop"),
            "{}",
            error.line()
        );
        let prepared = read_reservation(&path).expect("read").expect("prepared");
        let rounds = prepared["rounds"].as_array().expect("rounds");
        assert_eq!(
            &rounds[..rounds.len() - 1],
            retained["rounds"].as_array().expect("retained")
        );
        assert_eq!(rounds.last().expect("new round")["fresh_thread"], true);
    }

    fn resume_threadless_dispatch_through_entry() {
        let (fixture, plan, mut request) = dead_resume_fixture("started");
        let h = fixture.path();
        let owner = Uid::effective().as_raw();
        let root = File::open(h).expect("root");
        let _guard = home::activate_handed_home(h, &root, owner).expect("private fixture");
        let path = super::super::reservation_path(h, "R");
        let mut saved = read_reservation(&path).expect("read").expect("record");
        saved["phase"] = json!("settled");
        saved["active_round"] = json!("dispatch");
        saved["rounds"].as_array_mut().expect("rounds").truncate(1);
        collected_record(&mut saved);
        saved["readback_end"] = json!("completed");
        let dispatch = saved["rounds"][0].clone();
        assert!(rounds::threadless_continuation(&saved));
        let mut negative = saved.clone();
        negative["active_round"] = json!("work-1");
        negative["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({
                "step":"work-1","phase":"settled","ended_by":"by-report",
                "reply":{"bytes":6},"settle_attempts":[]
            }));
        assert!(
            !rounds::threadless_continuation(&negative),
            "a recovered dispatch cannot authorize a later ordinary round"
        );
        super::super::publish_reservation(&path, &saved).expect("settled dispatch");
        crate::fixture_exec::write_executable(&request.podman_bin,
            b"#!/bin/sh\nfor word do\n if [ \"$word\" = --record ]; then echo fixture-round-evidence-stop >&2; exit 17; fi\ndone\nprintf '{\"thread_id\":null}\\n'\n")
            .expect("fake container entry");
        request.dry_run = false;
        let error = super::super::run_with_host_root_and_proxy(h, &request, h, owner, |_| {
            Ok(("active".into(), "fixture-invocation".into()))
        })
        .expect_err("stop after the production resume write");
        assert!(
            error.line().contains("fixture-round-evidence-stop"),
            "{}",
            error.line()
        );
        let prepared = read_reservation(&path).expect("read").expect("prepared");
        assert_eq!(prepared["phase"], "failed");
        assert_eq!(prepared["rounds"][0], dispatch);
        assert_eq!(prepared["rounds"][1]["fresh_thread"], true);
        assert_eq!(prepared["rounds"][1]["phase"], "failed");
        assert_eq!(prepared["rounds"][1]["ended_by"], "failed-at-start");
        assert_eq!(prepared["helper_spawn_state"], "not-started");
        assert_eq!(prepared["helper_end"]["state"], "not-started");
        assert_eq!(prepared["driver_end"]["state"], "not-started");
        assert!(prepared.get("readback_end").is_none());
        for key in ["reply", "settle_attempts"] {
            assert!(prepared["rounds"][1][key].is_null(), "{key}");
        }
        assert_eq!(prepared["plan"], plan.document);
    }

    /// # Panics
    ///
    /// Panics only if failed dispatch recovery loses its measured proof or retained home.
    /// ´test:unit:failed-dispatch-without-completion-settles-and-continues´
    #[test]
    fn failed_dispatch_without_completion_settles_and_continues() {
        recovered_threadless_continuation(false, true);
    }

    /// # Panics
    ///
    /// Panics only if the two production recoveries or fresh continuation fail.
    /// ´test:unit:interrupted-threadless-work-round-continues-in-same-run´
    #[test]
    fn interrupted_threadless_work_round_continues_in_same_run() {
        recovered_threadless_continuation(true, false);
    }

    #[allow(clippy::too_many_lines)]
    fn recovered_threadless_continuation(recover_again: bool, failed_dispatch: bool) {
        let (fixture, plan, mut request) = recovery_fixture_in(&std::env::temp_dir());
        let owner = Uid::effective().as_raw();
        let root = File::open(fixture.path()).expect("fixture root");
        let _guard = home::activate_handed_home(fixture.path(), &root, owner)
            .expect("private entry fixture");
        let path = super::super::reservation_path(fixture.path(), "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        collected_record(&mut record);
        record["phase"] = json!("started");
        record["active_round"] = json!("dispatch");
        record["rounds"][0]["step"] = json!("dispatch");
        record["rounds"][0]["phase"] = json!("running");
        record
            .as_object_mut()
            .expect("record fields")
            .remove("thread_id");
        record["model_selection"] = json!({"model":"gpt-6-sol","effort":"high"});
        record["letter_source"] = json!(plan.letter);
        record["reaping_recovery"] = Value::Null;
        record["readback_end"] = Value::Null;
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        std::fs::rename(plan.driver_dir.join("20261007T043545Z-work"), &directory)
            .expect("dispatch directory");
        record["rounds"][0]["driver_dir"] = json!(directory);
        std::fs::write(directory.join("events.jsonl"), b"").expect("no thread event");
        std::fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=dispatch exit=143 verdict=failed dir={}\n",
                directory.display()
            ),
        )
        .expect("interrupted report");
        std::fs::remove_file(plan.home.join(".local/outbox/work.md")).expect("no reply");
        request.step = "dispatch".into();
        if failed_dispatch {
            record["phase"] = json!("failed");
            record["rounds"][0]["phase"] = json!("failed");
            record.as_object_mut().expect("record").remove("driver_end");
        }
        super::super::publish_reservation(&path, &record).expect("interrupted fixture");
        let before = std::fs::read(&path).expect("before recovery preview");
        let preview = super::super::interrupted_settlement_with(
            &record,
            &plan,
            &plan.letter,
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            crate::launch::driver_report::fixture_read,
        )
        .expect("production recovery preview");
        assert_eq!(preview["state"], "would-complete-interrupted-settlement");
        assert_eq!(
            std::fs::read(&path).expect("after recovery preview"),
            before
        );
        let recovered = super::super::finish_interrupted_settlement_with(
            &path, &plan, &plan.letter, owner, || Ok(Value::Null),
            || Err(LaneError::input("settle-evidence", "reply absent before thread event")),
            |_, _| ProcessPresence::Absent, || Ok(true),
            |saved| Ok(json!({"state":"collected","cgroup":saved["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}})), crate::launch::driver_report::fixture_read).expect("production launch recovery");
        assert_eq!(recovered["state"], "completed-interrupted-settlement");
        assert_eq!(
            recovered["attempt_evidence"]["state"],
            "absence-confirmed-with-missing-evidence"
        );
        let failed = read_reservation(&path).expect("read").expect("failed");
        assert_eq!(failed["phase"], "failed");
        assert!(failed.get("thread_id").is_none());
        assert_eq!(failed["rounds"][0]["step"], "dispatch");
        assert_eq!(failed["rounds"][0]["phase"], "failed");
        let preview = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
            ProcessPresence::Absent
        })
        .expect("production settle preview");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let settled = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
            ProcessPresence::Absent
        })
        .expect("production settle");
        assert_eq!(settled["settlement"]["ended_by"], "by-report");
        assert!(settled["settlement"]["readback"].is_null());
        let mut saved = read_reservation(&path).expect("read").expect("settled");
        assert_eq!(saved["phase"], "settled");
        assert!(saved.get("thread_id").is_none());
        assert_eq!(saved["rounds"].as_array().expect("rounds").len(), 1);
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert_eq!(saved["rounds"][0]["ended_by"], "by-report");
        assert!(saved["rounds"][0]["reply"].is_null());
        assert_eq!(
            saved["rounds"][0]["settle_attempts"][0]["phase"],
            "complete"
        );
        rounds::check_identity(&plan, &saved).expect("recovered dispatch permits continuation");
        for (pointer, value) in [
            ("/phase", json!("failed")),
            ("/active_round", json!("other")),
            ("/thread_id", json!("")),
            ("/rounds/0/phase", json!("settled")),
            ("/rounds/0/ended_by", json!("by-report-after-stop")),
            ("/rounds/0/reply", json!({"bytes":6})),
            ("/rounds/0/settle_attempts/0/phase", json!("attempted")),
            ("/reaping_recovery/presence", json!("unknown")),
        ] {
            let mut changed = saved.clone();
            changed["thread_id"] = Value::Null;
            *changed
                .pointer_mut(pointer)
                .expect("existing fixture field") = value;
            assert!(!rounds::threadless_continuation(&changed), "{pointer}");
        }
        let mut launch = super::super::LaunchRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "work-1".into(),
            "--budget".into(),
            "900".into(),
            "--dry-run".into(),
        ])
        .expect("next round request");
        let selection = super::super::LaunchModel::select(
            b"Model: gpt-6-sol\nEffort: high\nContinue.\n",
            None,
            None,
        )
        .expect("model");
        let (mut next_dir, argv) = rounds::continuation_argv(
            &plan,
            &saved,
            Path::new("/usr/bin/true"),
            &launch,
            &selection,
        )
        .expect("fresh continuation");
        assert!(!argv.iter().any(|word| word == "-r"));
        assert!(
            argv.windows(2)
                .any(|pair| pair == ["-d", next_dir.to_str().expect("path")])
        );
        assert_ne!(next_dir, directory);
        let old_round = saved["rounds"][0].clone();
        let next_round =
            rounds::continuation_round(&saved, &launch, &next_dir, &json!({"placed_at_unix_ns":1}))
                .expect("production continuation row");
        saved["phase"] = json!("preparing");
        saved["active_round"] = json!("work-1");
        saved["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(next_round);
        rounds::check_identity(&plan, &saved).expect("prepared fresh continuation");
        rounds::publish_round_request(&plan, &saved, "work-1", 900).expect("round request");
        let requested = crate::container_helper::requested_thread(
            &plan.driver_dir,
            b"Read /home/worker/.local/inbox/work-1.md.",
        )
        .expect("read request");
        assert!(requested.is_none());
        let vector = vec!["/usr/bin/codex".into(), "exec".into(), "-".into()];
        assert_eq!(
            crate::container_helper::command_for_request(&vector, &saved, requested.as_deref())
                .expect("helper accepts fresh thread"),
            vector
        );
        assert!(
            crate::container_helper::command_for_request(&vector, &saved, Some("foreign")).is_err()
        );
        if recover_again {
            std::fs::create_dir(&next_dir).expect("interrupted fresh directory");
            std::fs::write(next_dir.join("events.jsonl"), b"").expect("no second thread event");
            std::fs::write(next_dir.join(".event-start"), b"0\n").expect("event boundary");
            std::fs::write(
                next_dir.join("run-report.txt"),
                format!(
                    "RUN-REPORT lane=work-1 exit=143 verdict=failed dir={}\n",
                    next_dir.display()
                ),
            )
            .expect("second interrupted report");
            let inbox = plan.home.join(".local/inbox");
            std::fs::create_dir(&inbox).expect("inbox");
            let letter = inbox.join("work-1.md");
            let bytes = b"Continue.\n";
            std::fs::write(&letter, bytes).expect("placed letter");
            saved["letters"] = json!([{"step":"work-1","name":"work-1.md","in_round":false,"stop":false,"bytes":bytes.len(),"sha256":build::sha256_bytes(bytes, fixture.path()).expect("letter digest"),"placed_at_unix_ns":1,"state":"placed"}]);
            saved["phase"] = json!("started");
            saved["letter_source"] = json!(letter);
            saved["readback_end"] = Value::Null;
            saved["reaping_recovery"] = Value::Null;
            super::super::publish_reservation(&path, &saved).expect("second interrupted attempt");
            let recovered = super::super::finish_interrupted_settlement_with(
                &path, &plan, &letter, owner, || Ok(Value::Null),
                || Err(LaneError::input("settle-evidence", "reply absent before thread event")),
                |_, _| ProcessPresence::Absent, || Ok(true),
                |record| Ok(json!({"state":"collected","cgroup":record["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}})), crate::launch::driver_report::fixture_read).expect("second production launch recovery");
            assert_eq!(recovered["state"], "completed-interrupted-settlement");
            request.step = "work-1".into();
            request.dry_run = true;
            request.expect_digest = None;
            let preview = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect("second settle preview");
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect("second production settle");
            saved = read_reservation(&path)
                .expect("read")
                .expect("second settled record");
            assert_eq!(saved["phase"], "settled");
            assert_eq!(saved["active_round"], "work-1");
            assert!(saved["thread_id"].is_null());
            assert_eq!(saved["readback_end"], "completed");
            assert_eq!(saved["rounds"].as_array().expect("rounds").len(), 2);
            for (round, step) in saved["rounds"]
                .as_array()
                .expect("rounds")
                .iter()
                .zip(["dispatch", "work-1"])
            {
                assert_eq!(round["step"], step);
                assert_eq!(round["phase"], "failed");
                assert_eq!(round["ended_by"], "by-report");
                assert!(round["reply"].is_null());
                let attempt = round["settle_attempts"]
                    .as_array()
                    .expect("attempts")
                    .last()
                    .expect("attempt");
                assert_eq!(attempt["phase"], "complete");
                assert!(attempt["detail"].is_null());
                assert_eq!(
                    attempt["preview_sha256"].as_str().expect("digest").len(),
                    64
                );
            }
            assert_eq!(saved["rounds"][0], old_round);
            super::super::reaping::recovery_verdict(&saved).expect("second recovery proof");
            rounds::check_identity(&plan, &saved).expect("recovered work-1 permits continuation");
            let third_letter = inbox.join("work-2.md");
            std::fs::write(&third_letter, bytes).expect("next placed letter");
            let entry = json!({"step":"work-2","name":"work-2.md","in_round":false,"stop":false,"bytes":bytes.len(),"sha256":build::sha256_bytes(bytes, fixture.path()).expect("next letter digest"),"placed_at_unix_ns":2,"state":"placed"});
            saved["letters"]
                .as_array_mut()
                .expect("letters")
                .push(entry.clone());
            launch.round = Some("work-2".into());
            let (third_dir, argv) = rounds::continuation_argv(
                &plan,
                &saved,
                Path::new("/usr/bin/true"),
                &launch,
                &selection,
            )
            .expect("third round starts fresh");
            assert_ne!(third_dir, next_dir);
            assert!(!argv.iter().any(|word| word == "-r"));
            next_dir = third_dir;
            let next_round = rounds::continuation_round(&saved, &launch, &next_dir, &entry)
                .expect("third round row");
            saved["rounds"]
                .as_array_mut()
                .expect("rounds")
                .push(next_round);
            saved["phase"] = json!("preparing");
            saved["active_round"] = json!("work-2");
            saved["letter_source"] = json!(third_letter);
            rounds::check_identity(&plan, &saved).expect("third fresh round identity");
            rounds::publish_round_request(&plan, &saved, "work-2", 900).expect("third request");
            let requested = crate::container_helper::requested_thread(
                &plan.driver_dir,
                b"Read /home/worker/.local/inbox/work-2.md.",
            )
            .expect("third client request");
            assert!(requested.is_none());
            assert_eq!(
                crate::container_helper::command_for_request(&vector, &saved, requested.as_deref())
                    .expect("helper admits third fresh round"),
                vector
            );
        }
        let step = launch.round.as_deref().expect("next step");
        let prior_rounds = saved["rounds"].as_array().expect("rounds");
        let prior_rounds = prior_rounds[..prior_rounds.len() - 1].to_vec();
        std::fs::create_dir(&next_dir).expect("fresh driver directory");
        std::fs::write(
            next_dir.join("events.jsonl"),
            b"{\"type\":\"thread.started\",\"thread_id\":\"new-thread\"}\n",
        )
        .expect("first new thread event");
        std::fs::write(next_dir.join(".event-start"), b"0\n").expect("event boundary");
        let report = format!(
            "RUN-REPORT lane={step} exit=0 verdict=ok dir={}\n",
            next_dir.display()
        );
        std::fs::write(next_dir.join("run-report.txt"), &report).expect("new report");
        super::super::publish_reservation(&path, &saved).expect("new running round");
        rounds::record_step_directory(&plan, "R", step, &report)
            .expect("fresh directory index admitted");
        rounds::record_settlement(&plan, "alpha", "R", &json!({"bytes":6,"sha256":"reply"}))
            .expect("new thread recorded through settlement");
        let completed = read_reservation(&path).expect("read").expect("completed");
        assert_eq!(completed["thread_id"], "new-thread");
        assert_eq!(completed["rounds"][0], old_round);
        let completed_rounds = completed["rounds"].as_array().expect("rounds");
        assert_eq!(completed_rounds[..prior_rounds.len()], prior_rounds);
        assert_eq!(
            completed_rounds.last().expect("new round")["phase"],
            "settled"
        );
        assert_eq!(completed["plan"]["home"], saved["plan"]["home"]);
        rounds::check_identity(&plan, &completed).expect("normal thread continuity resumes");
    }

    fn failed_record(worker_uid: u32) -> Value {
        json!({"schema":1,"phase":"failed","active_round":"work","worker_uid":worker_uid,"driver_entry_pid":4_000_000,"driver_entry_start":1,"driver_end":{"state":"completed"},"helper_end":{"state":"completed"},"observation_end":"completed","observer_state":"not-started","observer_end":{"state":"not-started","socket":{"state":"not-applicable"}},"settlement_uncertain":false,"reaping":{"state":"verified-empty","container_payload":{"state":"absent"}},"readback_end":"settle-evidence: old refusal","rounds":[{"step":"work","phase":"failed"}]})
    }

    fn fail_completed_round(plan: &crate::plan::Plan, record: &mut Value) {
        let root = plan.driver_dir.parent().expect("runs root");
        let path = super::super::reservation_path(root, "R");
        let step = record["active_round"]
            .as_str()
            .expect("active step")
            .to_owned();
        let directory = record["rounds"][0]["driver_dir"].clone();
        record["rounds"] = json!([{"step":step,"budget_seconds":900,"letter":format!("{step}.md"),"phase":"running","driver_dir":directory,"ended_by":null,"placed_at_unix_ns":1,"in_round_letters":[]}]);
        let reply = plan.home.join(format!(".local/outbox/{step}.md"));
        if reply.exists() {
            std::fs::remove_file(&reply).expect("absent reply");
        }
        super::super::publish_reservation(&path, record).expect("running round");
        let error = super::super::inspect_readback(&reply, Uid::effective().as_raw())
            .expect_err("missing reply refuses readback");
        assert_eq!(error.kind, "readback");
        rounds::record_failed_settlement(plan, "R", &error).expect("production failure writer");
        *record = read_reservation(&path)
            .expect("read")
            .expect("failed record");
        assert_eq!(record["rounds"][0]["phase"], "failed");
        assert_eq!(record["rounds"][0]["settlement_error"], error.line());
        assert!(record["rounds"][0].get("reply").is_none());
    }

    thread_local! {
        pub(super) static PUBLIC_SETTLE_PROGRAM: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }

    /// # Panics
    /// Panics only if fixture setup or the public settlement contract fails.
    /// ´test:unit:completed-failed-dispatch-public-settle-entry´
    #[test]
    fn completed_failed_dispatch_public_settle_entry() {
        public_settle_entry(false);
    }

    /// # Panics
    /// Panics only if the public settlement and next-round contract fails.
    /// ´test:unit:completed-successful-report-public-settle-entry´
    #[test]
    fn completed_successful_report_public_settle_entry() {
        public_settle_entry(true);
    }

    fn public_settle_entry(report: bool) {
        match std::env::var("SUPERLOOP_PUBLIC_SETTLE_FIXTURE").as_deref() {
            Ok("private") => public_settle_private_child(),
            Ok("helper") => public_settle_helper_child(),
            Ok("public") => completed_failed_public_settle(report),
            _ => {
                // Production pins current_exe, so run this test from an owner-protected copy.
                let root = tempfile::TempDir::new_in(std::env::var_os("HOME").expect("home"))
                    .expect("protected test entry directory");
                std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                    .expect("entry directory mode");
                let entry = root.path().join("settle-test-entry");
                crate::fixture_exec::write_executable(
                    &entry,
                    &std::fs::read(std::env::current_exe().expect("test entry"))
                        .expect("entry bytes"),
                )
                .expect("protected entry");
                let output = crate::fixture_exec::output(
                    std::process::Command::new(&entry)
                        .args([
                            "--exact",
                            if report {
                                "launch::settle::tests::completed_successful_report_public_settle_entry"
                            } else {
                                "launch::settle::tests::completed_failed_dispatch_public_settle_entry"
                            },
                            "--nocapture",
                        ])
                        .env("SUPERLOOP_PUBLIC_SETTLE_FIXTURE", "public")
                        .env("TMPDIR", root.path()),
                )
                .expect("public settlement child");
                assert!(
                    output.status.success(),
                    "stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    fn public_settle_private_child() {
        let h = PathBuf::from(std::env::var_os("HOME").expect("fixture home"));
        let owner = Uid::effective().as_raw();
        let text = std::fs::read_to_string(h.join("private-args")).expect("public entry arguments");
        let words: Vec<_> = text.lines().map(str::to_owned).collect();
        assert_eq!(words[0], "_settle-evidence");
        assert_eq!(words[3], "--owner-home");
        assert_eq!(Path::new(&words[4]), h);
        let boundary = words
            .iter()
            .position(|word| word == "--verified-home-fd")
            .expect("descriptor suffix");
        let mut public = words[1..3].to_vec();
        public.extend_from_slice(&words[5..boundary]);
        let request = SettleRequest::parse(&public).expect("public request transported intact");
        let fds = home::receive_private_descriptors(&std::io::stdin(), 2)
            .expect("public descriptor handoff");
        // Substitute only the unavailable namespace UID mapping. The public function,
        // descriptor transport, settlement core and report publication are production code.
        let _guard = home::activate_private_launch(&h, &fds[0], &h, &fds[1], None, owner)
            .expect("same-uid private custody");
        let (plan, _) =
            crate::load_plan_for_record(&h, "alpha", "R", (0, 0)).expect("private plan");
        let report = private_recover_core(
            &plan,
            &h,
            &request,
            owner,
            crate::container_helper::process_presence,
        )
        .expect("private settlement");
        std::fs::write(
            h.join("private-result.json"),
            serde_json::to_vec(&report).expect("private JSON"),
        )
        .expect("private result");
    }

    #[allow(clippy::too_many_lines)]
    fn completed_failed_public_settle(report_case: bool) {
        use std::os::unix::fs::MetadataExt as _;

        let (fixture, plan, _) = dead_resume_fixture_in("failed", &std::env::temp_dir());
        let h = fixture.path();
        let path = super::super::reservation_path(h, "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        assert_eq!(record["worker_uid"], Uid::effective().as_raw());
        assert_eq!(
            std::fs::metadata(plan.home.join(".local/outbox"))
                .expect("outbox metadata")
                .uid(),
            Uid::effective().as_raw()
        );
        let step = if report_case { "report" } else { "dispatch" };
        let directory = plan.driver_dir.join("20261023T030507Z-dispatch");
        std::fs::rename(plan.driver_dir.join("20261007T043545Z-work-1"), &directory)
            .expect("dispatch directory");
        std::fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane={step} exit={} verdict={} dir={}\n",
                i32::from(!report_case),
                if report_case { "ok" } else { "FAILED" },
                directory.display()
            ),
        )
        .expect("failed report");
        record["active_round"] = json!(step);
        record["rounds"] = json!([{"driver_dir":directory}]);
        record["letters"] = json!([]);
        record["driver_end"] = json!({"state":"completed","successful":report_case});
        record["helper_end"] = json!({"state":"completed"});
        record["pre_driver_failure"] = Value::Null;
        record["reaping_recovery"] = Value::Null;
        record["reaping"] =
            json!({"state":"verified-empty","container_payload":{"state":"absent"}});
        record["observation_end"] = json!("completed");
        record["observer_end"] = json!({"state":"not-started","socket":{"state":"not-applicable"}});
        fail_completed_round(&plan, &mut record);
        let round_index = usize::from(report_case);
        if report_case {
            record["thread_id"] = json!("thread-1");
            std::fs::write(
                directory.join("events.jsonl"),
                b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n",
            )
            .expect("retained thread event");
            record["rounds"].as_array_mut().expect("rounds").insert(0,
                json!({"step":"dispatch","driver_dir":directory,"phase":"settled","ended_by":"by-report","reply":{"bytes":6},"settle_attempts":[]}));
            super::super::publish_reservation(&path, &record).expect("prior dispatch retained");
        }
        let owner = Uid::effective().as_raw();
        let next_letter = h.join("next-letter");
        let letter = b"Write the reply of record.\n";
        std::fs::write(&next_letter, letter).expect("next letter");
        std::fs::set_permissions(&next_letter, std::fs::Permissions::from_mode(0o600))
            .expect("letter mode");
        let digest = build::sha256_bytes(letter, h).expect("letter digest");
        let send = || {
            super::super::letters::private_send_with_owner(
                h,
                "alpha",
                "R",
                &next_letter,
                "report-2",
                &digest,
                owner,
            )
        };
        if report_case {
            let root = File::open(h).expect("fixture root");
            let _guard = home::activate_handed_home(h, &root, owner).expect("same-uid custody");
            let error = send().expect_err("failed report needs settlement");
            assert_eq!(error.kind, "letter-run-state");
            assert!(
                error
                    .detail
                    .contains("preview settle LOOP RUN --round STEP --dry-run")
            );
        }
        crate::fixture_exec::write_executable(&h.join("runtime"), b"#!/bin/sh\nset -eu\ntest \"$1\" = unshare\nshift\nentry=$1\nshift\nprintf '%s\\n' \"$@\" > \"$HOME/private-args\"\nSUPERLOOP_PUBLIC_SETTLE_FIXTURE=private \"$entry\" --exact launch::settle::tests::completed_failed_dispatch_public_settle_entry --nocapture > \"$HOME/private-test.log\" 2>&1 || { cat \"$HOME/private-test.log\" >&2; exit 1; }\ncat \"$HOME/private-result.json\"\n").expect("same-uid private test transport");
        PUBLIC_SETTLE_PROGRAM.with(|program| {
            program.replace(Some(h.join("runtime").display().to_string()));
        });
        let mut request = SettleRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--round".into(),
            step.into(),
            "--dry-run".into(),
        ])
        .expect("preview request");
        let before = std::fs::read(&path).expect("before preview");
        let preview =
            super::run_with_failure_report(h, &request, &mut |_| panic!("preview cannot publish"))
                .expect("binary dispatch function previews");
        assert!(preview["readback"].is_null());
        assert_eq!(std::fs::read(&path).expect("after preview"), before);
        assert!(!h.join(".report=R.json").exists());
        assert!(!h.join(".report=R=report.json").exists());
        assert!(
            !plan
                .driver_dir
                .join(format!("readback-evidence-{step}.json"))
                .exists()
        );
        assert!(
            read_reservation(&path).expect("read").expect("record")["rounds"][round_index]
                .get("settle_attempts")
                .is_none()
        );
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let result = super::run_with_failure_report(h, &request, &mut |_| {
            panic!("publication must succeed")
        })
        .expect("binary dispatch function settles");
        assert_eq!(result["phase"], "settled");
        let saved = read_reservation(&path)
            .expect("read")
            .expect("settled record");
        assert_eq!(saved["rounds"][round_index]["phase"], "failed");
        assert!(saved["rounds"][round_index]["reply"].is_null());
        assert_eq!(
            saved["rounds"][round_index]["settle_attempts"][0]["phase"],
            "complete"
        );
        assert!(super::final_round_ready(&saved));
        assert_eq!(rounds::threadless_continuation(&saved), !report_case);
        let report: Value = serde_json::from_slice(
            &std::fs::read(h.join(if report_case {
                ".report=R=report.json"
            } else {
                ".report=R.json"
            }))
            .expect("published report"),
        )
        .expect("report JSON");
        assert_eq!(
            report["interrupted_settlement"]["state"],
            "completed-settle-round"
        );
        assert_eq!(
            report["interrupted_settlement"]["preview_sha256"],
            preview["preview_sha256"]
        );
        PUBLIC_SETTLE_PROGRAM.with(|program| program.replace(None));
        if report_case {
            let root = File::open(h).expect("fixture root");
            let _guard = home::activate_handed_home(h, &root, owner).expect("same-uid custody");
            send().expect("next letter placed by production writer");
            let placed = read_reservation(&path).expect("read").expect("placed");
            assert_eq!(placed["rounds"], saved["rounds"]);
            assert_eq!(placed["letters"][0]["step"], "report-2");
            assert_eq!(placed["letters"][0]["state"], "placed");
            assert_eq!(
                std::fs::read(plan.home.join(".local/inbox/report-2.md")).expect("inbox"),
                letter
            );
            launch_after_public_settle(h, &plan, &saved);
        }
    }

    fn public_settle_helper_child() {
        use std::io::Read as _;
        let h = PathBuf::from(std::env::var_os("HOME").expect("fixture home"));
        let fds =
            home::receive_private_descriptors(&std::io::stdin(), 2).expect("helper descriptors");
        let record = read_reservation(&h.join(".reservation-R.json"))
            .expect("read")
            .expect("record");
        let driver = Path::new(
            record["plan"]["driver_dir"]
                .as_str()
                .expect("driver directory"),
        );
        let socket = crate::container_helper::socket_path(driver).expect("socket");
        let control = crate::container_helper::control_socket_path(driver).expect("control");
        let _client = std::os::unix::net::UnixListener::bind(&socket).expect("client socket");
        let listener = std::os::unix::net::UnixListener::bind(&control).expect("control socket");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
            .expect("client mode");
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o600))
            .expect("control mode");
        let (mut stream, _) = listener.accept().expect("helper stop");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("stop bound");
        let mut request = [0];
        stream.read_exact(&mut request).expect("stop request");
        assert_eq!(&request, b"C");
        stream.write_all(b"K").expect("stop acknowledgement");
        drop(fds);
    }

    fn launch_after_public_settle(h: &Path, plan: &crate::plan::Plan, settled: &Value) {
        // Replace the container runtime, and with it the private _inspect-round and
        // _settle-evidence halves: launch still publishes the next round, starts and
        // waits for its driver, and stops its descriptor-bound helper.
        crate::fixture_exec::write_executable(&h.join("runtime"), br#"#!/bin/sh
set -eu
test "$1" = unshare
shift
entry=$1
shift
case "$1" in
_inspect-round) printf '{"thread_id":"thread-1"}\n';;
_container-helper) SUPERLOOP_PUBLIC_SETTLE_FIXTURE=helper "$entry" --exact launch::settle::tests::completed_failed_dispatch_public_settle_entry --nocapture > "$HOME/helper-test.log" 2>&1;;
_settle-evidence) printf '{}\n';;
*) exit 9;;
esac
"#).expect("next round runtime");
        let request = super::super::LaunchRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "report-2".into(),
            "--podman-bin".into(),
            h.join("runtime").display().to_string(),
        ])
        .expect("next launch request");
        let error = rounds::resume_with_evidence(
            h,
            &request,
            h,
            Uid::effective().as_raw(),
            |_| Ok(("active".into(), "fixture-invocation".into())),
            &mut |_| {},
            crate::container_helper::process_presence,
            |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
        )
        .expect_err("fixture driver emits no report after being launched");
        assert_eq!(error.kind, "round-directory", "{}", error.line());
        let launched = read_reservation(&h.join(".reservation-R.json"))
            .expect("read")
            .expect("launched");
        assert_eq!(
            &launched["rounds"].as_array().expect("launched rounds")[..2],
            settled["rounds"].as_array().expect("settled rounds")
        );
        assert_eq!(launched["active_round"], "report-2");
        assert_eq!(launched["rounds"][2]["step"], "report-2");
        assert!(launched["rounds"][2]["fresh_thread"].is_null());
        assert_eq!(
            launched["rounds"][2]["driver_dir"],
            settled["rounds"][1]["driver_dir"]
        );
        assert_eq!(launched["driver_end"]["state"], "completed");
        assert_eq!(launched["driver_end"]["successful"], true);
        assert!(launched["driver_entry_pid"].is_number());
        assert_eq!(launched["helper_end"]["state"], "completed");
        assert_eq!(launched["plan"]["home"], json!(plan.home));
    }

    /// # Panics
    /// Panics only if fixture setup or the settlement contract fails.
    /// ´test:unit:completed-failed-dispatch-settles-without-reply-and-starts-fresh´
    #[test]
    fn completed_failed_dispatch_settles_without_reply_and_starts_fresh() {
        for successful in [false, true] {
            completed_round_without_reply_starts_fresh(successful);
        }
    }

    fn completed_round_without_reply_starts_fresh(successful: bool) {
        let (fixture, plan, mut request) = recovery_fixture();
        let path = super::super::reservation_path(fixture.path(), "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        record["driver_end"]["successful"] = json!(successful);
        record["thread_id"] = Value::Null;
        let directory = plan.driver_dir.join("20261007T043545Z-work");
        std::fs::write(directory.join("events.jsonl"), b"").expect("no thread");
        std::fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=work exit={} verdict={} dir={}\n",
                i32::from(!successful),
                if successful { "ok" } else { "FAILED" },
                directory.display()
            ),
        )
        .expect("failed report");
        fail_completed_round(&plan, &mut record);
        let before = std::fs::read(&path).expect("before");
        let owner = Uid::effective().as_raw();
        let preview = private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
            ProcessPresence::Absent
        })
        .expect("preview");
        assert!(preview["readback"].is_null());
        assert_eq!(std::fs::read(&path).expect("after"), before);
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
            ProcessPresence::Absent
        })
        .expect("settle");
        let saved = read_reservation(&path).expect("read").expect("settled");
        assert_eq!(saved["phase"], "settled");
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert!(saved["rounds"][0]["reply"].is_null());
        assert_eq!(
            saved["rounds"][0]["settle_attempts"][0]["phase"],
            "complete"
        );
        assert!(super::final_round_ready(&saved));
        rounds::check_identity(&plan, &saved).expect("settled continuation");
        let launch = super::super::LaunchRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "report".into(),
            "--dry-run".into(),
        ])
        .expect("report request");
        let selection = super::super::LaunchModel::select(
            b"Model: gpt-6-sol\nEffort: high\nReport.\n",
            None,
            None,
        )
        .expect("selection");
        let (next, argv) = rounds::continuation_argv(
            &plan,
            &saved,
            Path::new("/usr/bin/true"),
            &launch,
            &selection,
        )
        .expect("fresh report round");
        assert_ne!(next, directory);
        assert!(!argv.iter().any(|word| word == "-r"));
        for (pointer, value) in [
            ("/driver_end/state", json!("not-started")),
            ("/driver_end/successful", Value::Null),
            ("/helper_end/state", json!("not-started")),
            ("/rounds/0/reply", json!({"bytes":1})),
            ("/rounds/0/settle_attempts/0/phase", json!("attempted")),
        ] {
            let mut changed = saved.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            assert!(!rounds::threadless_continuation(&changed), "{pointer}");
            assert!(!super::final_round_ready(&changed), "{pointer}");
        }
    }

    /// # Panics
    /// Panics only if fixture setup or the settlement contract fails.
    /// ´test:unit:completed-failed-round-keeps-reply-and-liveness-refusals´
    #[test]
    fn completed_failed_round_keeps_reply_and_liveness_refusals() {
        let (fixture, plan, request) = recovery_fixture();
        let path = super::super::reservation_path(fixture.path(), "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        record["driver_end"]["successful"] = json!(false);
        fail_completed_round(&plan, &mut record);
        let owner = Uid::effective().as_raw();
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Present
            })
            .expect_err("live")
            .line(),
            "settle-live-refusal: driver is still alive"
        );
        let reply = plan.home.join(".local/outbox/work.md");
        std::fs::write(&reply, b"").expect("empty reply");
        std::fs::set_permissions(&reply, std::fs::Permissions::from_mode(0o600))
            .expect("protected reply");
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("invalid existing reply")
            .line(),
            format!(
                "readback: {} has 0 bytes; expected 1 through 1048576",
                reply.display()
            )
        );
        std::fs::remove_file(&reply).expect("remove reply");
        let evidence = plan.driver_dir.join("readback-evidence-work.json");
        std::fs::write(&evidence, b"{}").expect("prior evidence");
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("lost reply")
            .line(),
            "readback: reply disappeared after evidence was recorded"
        );
        std::fs::remove_file(evidence).expect("remove evidence");
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("successful report cannot omit reply")
            .line(),
            "readback: absent reply requires a matching completed driver verdict"
        );
        record["rounds"][0]["reply"] = json!({"bytes":6});
        super::super::publish_reservation(&path, &record).expect("prior reply");
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("prior reply cannot disappear")
            .line(),
            format!(
                "readback: {}: No such file or directory (os error 2)",
                reply.display()
            )
        );
    }

    /// ´test:unit:settle-rejects-live-driver-and-already-settled-round´
    #[test]
    fn settle_rejects_live_driver_and_already_settled_round() {
        for worker in [3000_u32, 3001] {
            let record = failed_record(worker);
            assert_eq!(
                recovery_basis(&record, "work", |_, _| ProcessPresence::Present)
                    .expect_err("live driver")
                    .kind,
                "settle-live-refusal"
            );
            let mut settled = record.clone();
            settled["phase"] = json!("settled");
            settled["rounds"][0]["phase"] = json!("settled");
            assert_eq!(
                recovery_basis(&settled, "work", |_, _| ProcessPresence::Absent)
                    .expect_err("already settled")
                    .kind,
                "settle-state-refusal"
            );
            let mut incomplete = record;
            incomplete["observation_end"] = json!("refused");
            assert_eq!(
                recovery_basis(&incomplete, "work", |_, _| ProcessPresence::Absent)
                    .expect_err("other failed evidence")
                    .kind,
                "settle-state-refusal"
            );
            incomplete["observation_end"] = json!("completed");
            for (field, value) in [
                ("settlement_uncertain", json!(true)),
                ("observer_state", json!("failed")),
                (
                    "observer_end",
                    json!({"state":"not-started","socket":{"state":"uncertain"}}),
                ),
            ] {
                let mut changed = incomplete.clone();
                changed[field] = value;
                assert_eq!(
                    recovery_basis(&changed, "work", |_, _| ProcessPresence::Absent)
                        .expect_err("observer is not settled")
                        .kind,
                    "settle-state-refusal"
                );
            }
            let mut observed = incomplete;
            observed["observer_state"] = json!("ended");
            observed["observer_end"] = json!({"state":"stopped","socket":{"state":"removed"}});
            recovery_basis(&observed, "work", |_, _| ProcessPresence::Absent)
                .expect("stopped observer and removed socket");
            observed["observer_end"]["socket"]["state"] = json!("pending");
            assert_eq!(
                recovery_basis(&observed, "work", |_, _| ProcessPresence::Absent)
                    .expect_err("observer socket is pending")
                    .kind,
                "settle-state-refusal"
            );
        }
    }

    /// ´test:unit:settle-requires-named-round-and-preview-digest´
    #[test]
    fn settle_requires_named_round_and_preview_digest() {
        let words = ["alpha", "R", "--round", "work", "--dry-run"].map(str::to_owned);
        assert!(SettleRequest::parse(&words).expect("preview").dry_run);
        let changing = ["alpha", "R", "--round", "work"].map(str::to_owned);
        assert_eq!(
            SettleRequest::parse(&changing)
                .expect_err("missing digest")
                .kind,
            "settle-usage"
        );
        let wrong = ["alpha", "R", "--round", "other", "--dry-run"].map(str::to_owned);
        assert_eq!(
            recovery_basis(&failed_record(3001), &wrong[3], |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("wrong round")
            .kind,
            "settle-state-refusal"
        );
    }

    /// ´test:unit:settle-missing-outbox-refuses-without-creating-evidence´
    #[test]
    fn settle_missing_outbox_refuses_without_creating_evidence() {
        let fixture = tempfile::tempdir().expect("fixture");
        let outbox = fixture.path().join("missing.md");
        let before = std::fs::read_dir(fixture.path())
            .expect("directory")
            .count();
        let error =
            super::super::inspect_readback(&outbox, 3001).expect_err("missing outbox must refuse");
        assert_eq!(error.kind, "readback");
        assert_eq!(
            std::fs::read_dir(fixture.path())
                .expect("directory")
                .count(),
            before
        );
    }

    /// ´test:unit:settle-attempt-records-owner-custody-not-worker-custody´
    #[test]
    fn settle_attempt_records_owner_custody_not_worker_custody() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        std::fs::set_permissions(
            fixture.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private fixture root");
        let path = super::super::reservation_path(fixture.path(), "R");
        let owner = Uid::effective().as_raw();
        for worker in [3000_u32, 3001] {
            assert_ne!(owner, worker);
            let mut record = failed_record(worker);
            record["loop"] = json!("alpha");
            record["run"] = json!("R");
            super::super::publish_reservation(&path, &record).expect("reservation");
            record_attempt(&path, "R", "fixture", "attempted", None).expect("attempt");
            let saved = super::super::read_reservation(&path)
                .expect("read reservation")
                .expect("record");
            assert_eq!(saved["worker_uid"], worker);
            assert_eq!(
                saved["rounds"][0]["settle_attempts"][0]["phase"],
                "attempted"
            );
            record_attempt(&path, "R", "fixture", "refused", Some("fixture refusal"))
                .expect("refusal");
            let saved = super::super::read_reservation(&path)
                .expect("read reservation")
                .expect("record");
            assert_eq!(saved["rounds"][0]["settle_attempts"][0]["phase"], "refused");
        }
    }

    /// ´test:unit:settle-changing-core-rejects-digest-before-writing-and-completes-finding-shape´
    #[test]
    fn settle_changing_core_rejects_digest_before_writing_and_completes_finding_shape() {
        let (fixture, plan, mut request) = recovery_fixture();
        let path = super::super::reservation_path(fixture.path(), "R");
        let published = fixture.path().join(".report=R.json");
        let preview = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect("preview");
        assert_eq!(preview["changed"], 1);
        assert_eq!(preview["report_path"], json!(published));
        assert!(!published.exists(), "dry run publishes no report");
        let reservation_before = std::fs::read(&path).expect("reservation bytes");
        let driver_before = std::fs::read_dir(&plan.driver_dir)
            .expect("driver directory")
            .count();
        let step = plan.driver_dir.join("20261007T043545Z-work");
        let report_before = std::fs::read(step.join("run-report.txt")).expect("report bytes");
        let events_before = std::fs::read(step.join("events.jsonl")).expect("event bytes");
        request.dry_run = false;
        request.expect_digest = Some("0".repeat(64));
        assert_eq!(
            private_recover_core(
                &plan,
                fixture.path(),
                &request,
                Uid::effective().as_raw(),
                |_, _| ProcessPresence::Absent,
            )
            .expect_err("changed digest")
            .kind,
            "settle-preview-refusal"
        );
        assert_eq!(
            std::fs::read(&path).expect("reservation bytes"),
            reservation_before
        );
        assert_eq!(
            std::fs::read_dir(&plan.driver_dir)
                .expect("driver directory")
                .count(),
            driver_before
        );
        assert_eq!(
            std::fs::read(step.join("run-report.txt")).expect("report"),
            report_before
        );
        assert_eq!(
            std::fs::read(step.join("events.jsonl")).expect("events"),
            events_before
        );
        assert!(!plan.driver_dir.join("readback-evidence-work.json").exists());
        request.expect_digest = Some(
            preview["preview_sha256"]
                .as_str()
                .expect("preview digest")
                .to_owned(),
        );
        let settled = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect("changing recovery");
        assert_eq!(settled["phase"], "settled");
        assert_eq!(
            settled["settlement"]["owner_uid"],
            Uid::effective().as_raw()
        );
        let record = super::super::read_reservation(&path)
            .expect("read reservation")
            .expect("reservation");
        assert_eq!(
            record["rounds"][0]["settle_attempts"][0]["phase"],
            "complete"
        );
        assert_eq!(record["phase"], "settled");
        assert_first_recovered_report(&fixture, &plan, &request, &record, &settled, &preview);
    }

    fn assert_first_recovered_report(
        fixture: &tempfile::TempDir,
        plan: &crate::plan::Plan,
        request: &SettleRequest,
        record: &Value,
        settled: &Value,
        preview: &Value,
    ) {
        let runs = File::open(fixture.path()).expect("held runs root").into();
        publish_settled_report(
            plan,
            fixture.path(),
            &runs,
            request,
            record,
            settled,
            1.0,
            &mut |_| {},
        )
        .expect("session publishes recovered report");
        let report = super::super::report::read_bound(&runs, "R", None, Uid::effective().as_raw())
            .expect("recovered first-round report");
        assert_eq!(report["command"], "launch");
        assert_eq!(
            report["interrupted_settlement"]["state"],
            "completed-settle-round"
        );
        assert_eq!(report["interrupted_settlement"]["phase"], "complete");
        assert_eq!(
            report["interrupted_settlement"]["preview_sha256"],
            preview["preview_sha256"]
        );
        assert_eq!(report["round_dir"], record["rounds"][0]["driver_dir"]);
        assert_eq!(report["driver_dir"], json!(plan.driver_dir));
    }

    /// ´test:unit:settle-recovered-later-round-publishes-only-its-own-report´
    #[test]
    fn settle_recovered_later_round_publishes_only_its_own_report() {
        let (fixture, plan, mut request) = recovery_fixture();
        let path = super::super::reservation_path(fixture.path(), "R");
        let mut record = super::super::read_reservation(&path)
            .expect("read reservation")
            .expect("reservation");
        let prior = json!({"step":"dispatch","phase":"settled","driver_dir":record["rounds"][0]["driver_dir"]});
        record["rounds"]
            .as_array_mut()
            .expect("rounds")
            .insert(0, prior);
        super::super::publish_reservation(&path, &record).expect("later round reservation");
        let first = fixture.path().join(".report=R.json");
        std::fs::write(&first, b"first report remains").expect("prior report");
        let preview = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect("preview");
        assert!(!fixture.path().join(".report=R=work.json").exists());
        request.dry_run = false;
        request.expect_digest = Some(preview["preview_sha256"].as_str().expect("digest").into());
        let settled = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect("settle later round");
        let runs = File::open(fixture.path()).expect("held runs root").into();
        let record = super::super::read_reservation(&path)
            .expect("read settled reservation")
            .expect("settled reservation");
        publish_settled_report(
            &plan,
            fixture.path(),
            &runs,
            &request,
            &record,
            &settled,
            2.0,
            &mut |_| {},
        )
        .expect("session publishes later-round report");
        let report =
            super::super::report::read_bound(&runs, "R", Some("work"), Uid::effective().as_raw())
                .expect("recovered later-round report");
        assert_eq!(report["round_dir"], record["rounds"][1]["driver_dir"]);
        assert_eq!(report["interrupted_settlement"]["phase"], "complete");
        assert_eq!(
            std::fs::read(first).expect("prior report"),
            b"first report remains"
        );
    }

    /// ´test:unit:settle-recovered-report-refuses-occupied-name-without-replacement´
    #[test]
    fn settle_recovered_report_refuses_occupied_name_without_replacement() {
        let (fixture, plan, mut request) = recovery_fixture();
        let reservation = super::super::reservation_path(fixture.path(), "R");
        let original = std::fs::read(&reservation).expect("failed reservation bytes");
        let published = fixture.path().join(".report=R.json");
        let existing = b"occupied report bytes";
        std::fs::write(&published, existing).expect("occupied name");
        let error = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect_err("occupied report name refuses preview");
        assert_eq!(error.kind, "launch-report");
        assert!(error.detail.contains(".report=R.json"));
        assert_eq!(std::fs::read(&published).expect("occupied bytes"), existing);
        request.dry_run = false;
        let error = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect_err("occupied report name must refuse");
        assert_eq!(error.kind, "launch-report");
        assert!(error.detail.contains(".report=R.json"));
        assert_eq!(std::fs::read(published).expect("occupied bytes"), existing);
        assert_eq!(
            std::fs::read(&reservation).expect("failed reservation retained"),
            original
        );
        let record = super::super::read_reservation(&reservation)
            .expect("read failed reservation")
            .expect("failed reservation");
        assert_eq!(record["phase"], "failed");
        assert_eq!(record["rounds"][0]["phase"], "failed");
    }

    /// ´test:unit:settle-publication-race-delivers-unsaved-recovered-report´
    #[test]
    fn settle_publication_race_delivers_unsaved_recovered_report() {
        let (fixture, plan, mut request) = recovery_fixture();
        let preview = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect("free report name in preview");
        request.dry_run = false;
        request.expect_digest = Some(preview["preview_sha256"].as_str().expect("digest").into());
        let private = private_recover_core(
            &plan,
            fixture.path(),
            &request,
            Uid::effective().as_raw(),
            |_, _| ProcessPresence::Absent,
        )
        .expect("private settlement");
        let path = super::super::reservation_path(fixture.path(), "R");
        let settled = super::super::read_reservation(&path)
            .expect("read reservation")
            .expect("settled reservation");
        let published = fixture.path().join(".report=R.json");
        std::fs::write(&published, b"occupied after preview").expect("racing report");
        let runs = File::open(fixture.path()).expect("held runs root").into();
        let mut unsaved = None;
        let error = publish_settled_report(
            &plan,
            fixture.path(),
            &runs,
            &request,
            &settled,
            &private,
            3.0,
            &mut |report| unsaved = Some(report.clone()),
        )
        .expect_err("racing report refuses publication");
        assert_eq!(error.kind, "launch-report");
        assert!(error.detail.contains(".report=R.json"));
        let report = unsaved.expect("unsaved report delivered to stdout callback");
        assert_eq!(
            report["interrupted_settlement"]["state"],
            "completed-settle-round"
        );
        assert_eq!(report["round_dir"], settled["rounds"][0]["driver_dir"]);
        assert_eq!(
            std::fs::read(published).expect("occupied bytes"),
            b"occupied after preview"
        );
    }

    /// ´test:unit:settle-recovery-refuses-foreign-worker-outbox-and-driver-mode´
    #[test]
    fn settle_recovery_refuses_foreign_worker_outbox_and_driver_mode() {
        let (fixture, plan, request) = recovery_fixture();
        let path = super::super::reservation_path(fixture.path(), "R");
        let mut record = super::super::read_reservation(&path)
            .expect("read reservation")
            .expect("reservation");
        let owner = Uid::effective().as_raw();
        let other = owner.checked_add(1).expect("second worker uid");
        record["worker_uid"] = json!(other);
        record["plan"]["worker_uid"] = json!(other);
        super::super::publish_reservation(&path, &record).expect("foreign worker reservation");
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("foreign outbox")
            .kind,
            "readback"
        );
        record["worker_uid"] = json!(owner);
        record["plan"]["worker_uid"] = json!(owner);
        super::super::publish_reservation(&path, &record).expect("owner worker reservation");
        std::fs::set_permissions(&plan.driver_dir, std::fs::Permissions::from_mode(0o750))
            .expect("wrong driver mode");
        assert_eq!(
            private_recover_core(&plan, fixture.path(), &request, owner, |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("wrong driver mode")
            .kind,
            "driver-dir"
        );
        assert!(
            super::super::read_reservation(&path)
                .expect("read reservation")
                .expect("reservation")["rounds"][0]
                .get("settle_attempts")
                .is_none()
        );
    }
}
