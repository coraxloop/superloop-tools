//! Resume a recorded thread on its reserved home and settle each reply of record.

use std::fs::OpenOptions;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::fcntl::{RenameFlags, renameat2};
use nix::unistd::{Gid, Uid, fchown};
use serde_json::{Value, json};

use super::{
    LaunchRequest, admission, entry_argv_round, inspect_readback, launch_environment, lock_mailbox,
    lock_run_preparation, persist_settlement_field, publish_reservation, read_reservation,
    reservation_path, start_helper_with_program, stop_helper,
};
use crate::error::LaneError;
use crate::plan::Plan;
use crate::{build, home, load_plan};

fn step_event_thread(dir: &Path) -> Result<String, LaneError> {
    let path = dir.join("events.jsonl");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            LaneError::input("round-thread", format!("{}: {error}", path.display()))
        })?;
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let owner = std::fs::symlink_metadata(dir)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?
        .uid();
    if !meta.is_file() || meta.uid() != owner {
        return Err(LaneError::input(
            "round-thread",
            "events are not directory-owned regular evidence",
        ));
    }
    let size = usize::try_from(meta.len())
        .map_err(|_| LaneError::input("round-thread", "event size exceeds addressable range"))?;
    let boundaries = lane_lifecycle::validated_event_boundaries(dir, size)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let start = *boundaries
        .last()
        .ok_or_else(|| LaneError::input("round-thread", "step event boundary is absent"))?;
    file.seek(SeekFrom::Start(start as u64))
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let mut reader = BufReader::new(file.take((size - start) as u64));
    let mut line = Vec::new();
    let mut observed: Option<String> = None;
    while reader
        .read_until(b'\n', &mut line)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?
        != 0
    {
        if line.last() == Some(&b'\n')
            && let Ok(event) = serde_json::from_slice::<Value>(&line)
            && event["type"] == "thread.started"
        {
            let actual = event["thread_id"]
                .as_str()
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= 128
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
                .ok_or_else(|| {
                    LaneError::input("round-thread", "step thread event has a malformed id")
                })?;
            if observed.as_deref().is_some_and(|prior| prior != actual) {
                return Err(LaneError::input(
                    "round-thread",
                    "step contains two thread ids",
                ));
            }
            observed = Some(actual.to_owned());
        }
        line.clear();
    }
    observed.ok_or_else(|| LaneError::input("round-thread", "step has no thread.started event"))
}

fn recovered_threadless_round(round: &Value) -> bool {
    round["phase"] == "failed"
        && round["ended_by"] == "by-report"
        && round.get("reply").is_some_and(Value::is_null)
        && round["settle_attempts"]
            .as_array()
            .and_then(|rows| rows.last())
            .is_some_and(|attempt| attempt["phase"] == "complete")
}

pub(crate) fn threadless_continuation(record: &Value) -> bool {
    record["phase"] == "settled"
        && record["thread_id"].is_null()
        && record["readback_end"] == "completed"
        && record["rounds"]
            .as_array()
            .and_then(|rows| rows.last())
            .is_some_and(|round| {
                round["step"].is_string()
                    && round["step"] == record["active_round"]
                    && recovered_threadless_round(round)
            })
        && (super::reaping::recovery_verdict(record).is_ok()
            || super::settle::completed_failed_round(record))
}

pub(crate) fn fresh_thread_round(record: &Value) -> bool {
    record["thread_id"].is_null()
        && matches!(
            record["phase"].as_str(),
            Some("preparing" | "started" | "failed")
        )
        && record["rounds"]
            .as_array()
            .and_then(|rows| rows.split_last())
            .is_some_and(|(round, prior)| {
                prior.last().is_some_and(recovered_threadless_round)
                    && round["fresh_thread"] == true
                    && round["step"] == record["active_round"]
                    && round["step"] != "dispatch"
                    && matches!(
                        round["phase"].as_str(),
                        Some("running" | "awaiting-settlement" | "failed")
                    )
            })
}

fn prior_round_dir(record: &Value) -> Result<&Path, LaneError> {
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("round-record", "prior round is absent"))?;
    if round["phase"] != "settled" && !super::settle::final_round_ready(record) {
        return Err(LaneError::input(
            "round-record",
            "prior round is not settled",
        ));
    }
    round["driver_dir"].as_str().map(Path::new).ok_or_else(|| {
        LaneError::input(
            "round-record",
            "prior round has no recorded driver directory",
        )
    })
}

fn named_step_dir(plan: &Plan, record: &Value, step: &str) -> Result<PathBuf, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("round-record", "round list is absent"))?;
    let index = rounds
        .iter()
        .position(|round| round["step"] == step)
        .ok_or_else(|| LaneError::input("round-record", "round step is absent"))?;
    let directory = rounds[index]["driver_dir"].as_str().ok_or_else(|| {
        LaneError::input(
            "round-record",
            format!("{step} has no recorded driver directory"),
        )
    })?;
    let path = PathBuf::from(directory);
    let fresh = index > 0
        && rounds[index]["fresh_thread"] == true
        && recovered_threadless_round(&rounds[index - 1]);
    let expected = if index == 0 || fresh {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        path.parent() == Some(plan.driver_dir.as_path())
            && (name.ends_with(&format!("-{step}")) || name.contains(&format!("-{step}-")))
    } else {
        let prior = rounds[index - 1]["driver_dir"].as_str().ok_or_else(|| {
            LaneError::input(
                "round-record",
                "prior round has no recorded driver directory",
            )
        })?;
        path == Path::new(prior)
    };
    if !expected {
        return Err(LaneError::input(
            "round-directory",
            format!("{step} driver directory differs from the prior round"),
        ));
    }
    Ok(path)
}

fn recorded_step_dir(plan: &Plan, record: &Value, round: &Value) -> Result<PathBuf, LaneError> {
    let step = round["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-directory", "round step is absent"))?;
    let path = named_step_dir(plan, record, step)?;
    if round["driver_dir"].as_str() != path.to_str() {
        return Err(LaneError::input(
            "round-record",
            "round directory differs from row",
        ));
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|error| {
        LaneError::input("round-directory", format!("{}: {error}", path.display()))
    })?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(LaneError::input(
            "round-directory",
            format!("{step} driver directory is not a directory"),
        ));
    }
    Ok(path)
}

fn verified_report(
    plan: &Plan,
    record: &Value,
    round: &Value,
) -> Result<(PathBuf, std::fs::File), LaneError> {
    let step = round["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-directory", "round step is absent"))?;
    let directory = recorded_step_dir(plan, record, round)?;
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(&directory)
        .map_err(|error| LaneError::input("round-directory", error.to_string()))?;
    let owner = held
        .metadata()
        .map_err(|error| LaneError::input("round-directory", error.to_string()))?
        .uid();
    let file = super::driver_report::open_report(&held.into(), owner).map_err(|error| {
        LaneError::input("round-directory", format!("{step}: {}", error.detail))
    })?;
    Ok((directory, file))
}

fn verified_report_line(
    file: std::fs::File,
    directory: &Path,
    step: &str,
) -> Result<String, LaneError> {
    let mut body = String::new();
    file.take(4097)
        .read_to_string(&mut body)
        .map_err(|error| LaneError::input("round-directory", error.to_string()))?;
    let line = body.lines().last().unwrap_or_default();
    if !line.starts_with(&format!("RUN-REPORT lane={step} "))
        || !line
            .split_whitespace()
            .any(|field| field == format!("dir={}", directory.display()))
    {
        return Err(LaneError::input(
            "round-directory",
            format!("{step} completed report differs from recorded directory"),
        ));
    }
    Ok(line.to_owned())
}

fn verify_completed_step_dir(plan: &Plan, record: &Value, round: &Value) -> Result<(), LaneError> {
    let step = round["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-directory", "round step is absent"))?;
    let (directory, file) = verified_report(plan, record, round)?;
    verified_report_line(file, &directory, step).map(|_| ())
}

fn round_end_reason(plan: &Plan, record: &Value, round: &Value) -> Result<Value, LaneError> {
    let step = round["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-end", "round step is absent"))?;
    let (directory, file) = verified_report(plan, record, round)?;
    let line = verified_report_line(file, &directory, step)?;
    Ok(classify_report_end(record, round, &line))
}

pub(super) fn recovery_report_line(
    plan: &Plan,
    record: &Value,
    round: &Value,
) -> Result<String, LaneError> {
    let step = round["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("settle-record", "round step is absent"))?;
    let (directory, file) = verified_report(plan, record, round)?;
    verified_report_line(file, &directory, step)
}

pub(super) fn recovery_thread(
    plan: &Plan,
    record: &Value,
    round: &Value,
) -> Result<String, LaneError> {
    let directory = recorded_step_dir(plan, record, round)?;
    let actual = step_event_thread(&directory)?;
    if let Some(expected) = record["thread_id"].as_str() {
        if expected != actual {
            return Err(LaneError::input(
                "round-thread",
                "step thread differs from reservation",
            ));
        }
    } else if round["step"] != "dispatch" && !fresh_thread_round(record) {
        return Err(LaneError::input(
            "round-thread",
            "resume has no recorded thread",
        ));
    }
    Ok(actual)
}

fn classify_report_end(record: &Value, round: &Value, line: &str) -> Value {
    let stopped = record["letters"].as_array().is_some_and(|letters| {
        letters.iter().any(|letter| {
            letter["step"] == round["step"] && letter["stop"] == true && letter["state"] == "placed"
        })
    });
    if stopped && line.split_whitespace().any(|word| word == "exit=0") {
        json!("by-report-after-stop")
    } else {
        json!("by-report")
    }
}

pub(super) fn settled_round_end(record: &Value) -> Result<&str, LaneError> {
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("round-end", "settled round is absent"))?;
    if round["phase"] != "settled" {
        return Err(LaneError::input("round-end", "last round is not settled"));
    }
    match round["ended_by"].as_str() {
        Some(value @ ("by-report" | "by-report-after-stop" | "by-budget")) => Ok(value),
        _ => Err(LaneError::input(
            "round-end",
            "settled round has no recorded end reason",
        )),
    }
}

/// Compare the terminal report with the directory recorded before driver start.
pub(super) fn record_step_directory(
    plan: &Plan,
    run: &str,
    step: &str,
    output: &str,
) -> Result<(), LaneError> {
    let line = output
        .lines()
        .last()
        .ok_or_else(|| LaneError::input("round-directory", "driver terminal report is absent"))?;
    if !line.starts_with(&format!("RUN-REPORT lane={step} ")) {
        return Err(LaneError::input(
            "round-directory",
            "driver terminal report names a different step",
        ));
    }
    let directory = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("dir="))
        .ok_or_else(|| {
            LaneError::input("round-directory", "driver terminal report has no directory")
        })?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("round-directory", "runs root is absent"))?;
    let path = reservation_path(root, run);
    let _mailbox = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut record = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    if round["step"] != step || round["phase"] != "running" {
        return Err(LaneError::input(
            "round-record",
            "terminal report differs from running round",
        ));
    }
    let recorded = named_step_dir(plan, &record, step)?;
    if recorded.to_str() != Some(directory) {
        return Err(LaneError::input(
            "round-record",
            "terminal report directory differs from running round",
        ));
    }
    let round = record["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    round["phase"] = json!("awaiting-settlement");
    publish_reservation(&path, &record)
}

/// Recover the completed step through its recorded directory and matching report.
#[allow(clippy::too_many_lines)]
pub(super) fn recover_step_directory(plan: &Plan, run: &str) -> Result<(), LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("round-directory", "runs root is absent"))?;
    let record = read_reservation(&reservation_path(root, run))?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    if round["phase"] == "settled" || round["phase"] == "awaiting-settlement" {
        return verify_completed_step_dir(plan, &record, round);
    }
    if round["phase"] != "running" {
        return Err(LaneError::input(
            "round-record",
            "active round is not running",
        ));
    }
    let step = record["active_round"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    super::letters::valid_step(step)?;
    let (directory, file) = verified_report(plan, &record, round)?;
    let report = verified_report_line(file, &directory, step)?;
    record_step_directory(plan, run, step, &report)
}

pub(super) fn check_identity(plan: &Plan, record: &Value) -> Result<(), LaneError> {
    if record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
        || record["worker_uid"] != record["plan"]["worker_uid"]
    {
        return Err(LaneError::input(
            "round-home",
            "home, driver directory or worker UID differs from reservation",
        ));
    }
    if threadless_continuation(record) || fresh_thread_round(record) {
        return Ok(());
    }
    let saved = record["thread_id"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-thread", "thread is absent from reservation"))?;
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| {
            rounds
                .iter()
                .rev()
                .find(|round| round["phase"] == "settled")
        })
        .ok_or_else(|| LaneError::input("round-record", "settled round is absent"))?;
    let actual = step_event_thread(&recorded_step_dir(plan, record, round)?)?;
    if actual != saved {
        return Err(LaneError::input(
            "round-thread",
            format!("driver thread {actual} differs from reservation {saved}"),
        ));
    }
    Ok(())
}

/// Check the driver thread from the namespace that owns the protected directory.
///
/// # Errors
///
/// Refuses a mismatched home or thread.
pub fn private_inspect(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    evidence: Option<(&str, u64)>,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    inspect_current_round(owner_home, loop_name, run, evidence)
}

pub(super) fn inspect_current_round(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    evidence: Option<(&str, u64)>,
) -> Result<Value, LaneError> {
    let (plan, _) = load_plan(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("round-home", "runs root is absent"))?;
    let record = read_reservation(&reservation_path(root, run))?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    check_identity(&plan, &record)?;
    inspect_loaded_round(&plan, &record, evidence)
}

fn inspect_loaded_round(
    plan: &Plan,
    record: &Value,
    evidence: Option<(&str, u64)>,
) -> Result<Value, LaneError> {
    if let Some((step, budget)) = evidence {
        super::letters::valid_step(step)?;
        if record["phase"] != "preparing"
            || record["active_round"] != step
            || record["rounds"]
                .as_array()
                .and_then(|rounds| rounds.last())
                .is_none_or(|round| round["budget_seconds"] != budget)
        {
            return Err(LaneError::input(
                "round-evidence",
                "round step or budget differs from the reservation",
            ));
        }
        let loop_uid = crate::plan::loop_uid(&plan.document)?;
        let (runs_root, runtime_dir) =
            super::pin_runtime_dir(&plan.driver_dir, Uid::effective().as_raw(), loop_uid)?;
        super::prepare_client_environment(
            &plan.driver_dir,
            &runs_root,
            &runtime_dir,
            loop_uid,
            false,
        )?;
        publish_round_request(plan, record, step, budget)?;
    }
    Ok(
        json!({"schema":1,"command":"inspect-round","thread_id":record["thread_id"],"home":plan.home,"worker_uid":record["worker_uid"]}),
    )
}

pub(super) fn publish_round_request(
    plan: &Plan,
    record: &Value,
    step: &str,
    budget: u64,
) -> Result<(), LaneError> {
    let parent = std::fs::symlink_metadata(&plan.driver_dir)
        .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    if !parent.is_dir() || parent.file_type().is_symlink() {
        return Err(LaneError::input(
            "round-evidence",
            "run directory is not a directory",
        ));
    }
    let name = format!("round-launch-{step}.json");
    let temporary = format!(".round-launch-{step}-{}.tmp", std::process::id());
    let path = plan.driver_dir.join(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| {
            LaneError::operation("round-evidence", format!("{}: {error}", path.display()))
        })?;
    let body = json!({"schema":1,"step":step,"budget_seconds":budget,"letter":format!("{step}.md"),"thread_id":record["thread_id"],"home":plan.home,"worker_uid":record["worker_uid"]});
    file.write_all(body.to_string().as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    fchown(
        &file,
        Some(Uid::from_raw(parent.uid())),
        Some(Gid::from_raw(parent.gid())),
    )
    .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    file.sync_all()
        .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    let directory = std::fs::File::open(&plan.driver_dir)
        .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    renameat2(
        &directory,
        temporary.as_str(),
        &directory,
        name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    directory
        .sync_all()
        .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    Ok(())
}

/// Record the reply and each acknowledged in-round letter after the child ends.
///
/// # Errors
///
/// Refuses an absent reply, acknowledgment, thread or round record.
#[allow(clippy::too_many_lines)]
pub(super) fn record_settlement(
    plan: &Plan,
    _loop_name: &str,
    run: &str,
    reply: &Value,
) -> Result<(), LaneError> {
    record_settlement_with_recovery(plan, run, reply, false)
}

#[allow(clippy::too_many_lines)]
pub(super) fn record_settlement_with_recovery(
    plan: &Plan,
    run: &str,
    reply: &Value,
    recovery: bool,
) -> Result<(), LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("round-record", "runs root is absent"))?;
    let path = reservation_path(root, run);
    let _mailbox = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut record = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    let step = record["active_round"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?
        .to_owned();
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?
        .clone();
    if round["step"] != step {
        return Err(LaneError::input(
            "round-record",
            "active round differs from last running round",
        ));
    }
    if round["phase"] == "settled" {
        let directory = recorded_step_dir(plan, &record, &round)?;
        let actual = step_event_thread(&directory)?;
        if record["thread_id"] != actual {
            return Err(LaneError::input(
                "round-thread",
                "completed round thread differs from reservation",
            ));
        }
        if round["reply"]["bytes"] != reply["bytes"]
            || round["reply"]["sha256"] != reply["sha256"]
            || round["reply"] != *reply
        {
            return Err(LaneError::input(
                "round-reply",
                "completed round reply differs from saved size or digest",
            ));
        }
        return Ok(());
    }
    if round["phase"] != "awaiting-settlement"
        && !(recovery
            && round["phase"] == "failed"
            && (round["settlement_error"].is_string()
                || record["readback_end"]
                    .as_str()
                    .is_some_and(|end| end.contains("settle-evidence:"))))
    {
        return Err(LaneError::input(
            "round-record",
            "active round differs from last running round",
        ));
    }
    let ended_by = round_end_reason(plan, &record, &round);
    let step_dir = recorded_step_dir(plan, &record, &round);
    let outcome = (|| -> Result<Vec<Value>, LaneError> {
        ended_by
            .as_ref()
            .map_err(|error| LaneError::input(error.kind, error.detail.clone()))?;
        let actual = step_event_thread(&step_dir?)?;
        if let Some(saved) = record["thread_id"].as_str() {
            if saved != actual {
                return Err(LaneError::input(
                    "round-thread",
                    format!("step thread {actual} differs from reservation {saved}"),
                ));
            }
        } else if step == "dispatch" || fresh_thread_round(&record) {
            record["thread_id"] = json!(actual);
        } else {
            return Err(LaneError::input(
                "round-thread",
                "resume has no recorded thread",
            ));
        }
        let worker = record["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| LaneError::input("round-record", "worker UID is absent"))?;
        let mut acknowledgments = Vec::new();
        for letter in record["letters"]
            .as_array()
            .ok_or_else(|| LaneError::input("round-record", "letters are absent"))?
        {
            if letter["step"] == step && letter["in_round"] == true {
                if letter["state"] == "abandoned" {
                    acknowledgments.push(
                        json!({"letter":letter["name"],"state":"abandoned","acknowledgment":null}),
                    );
                    continue;
                }
                if letter["state"] != "placed" {
                    return Err(LaneError::input(
                        "round-letter",
                        "in-round letter publication is incomplete",
                    ));
                }
                let name = letter["name"].as_str().ok_or_else(|| {
                    LaneError::input("round-letter", "in-round letter name is absent")
                })?;
                let ack = inspect_readback(&plan.home.join(".local/outbox").join(name), worker)?;
                acknowledgments.push(json!({"letter":name,"acknowledgment":ack}));
            }
        }
        Ok(acknowledgments)
    })();
    let rounds = record["rounds"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("round-record", "rounds are absent"))?;
    let round = rounds
        .last_mut()
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    if let Ok(reason) = &ended_by {
        round["ended_by"] = reason.clone();
    }
    match &outcome {
        Ok(acknowledgments) => {
            round["reply"] = reply.clone();
            round["in_round_letters"] = json!(acknowledgments);
            round["phase"] = json!("settled");
            if recovery && let Some(fields) = round.as_object_mut() {
                let _old = fields.remove("settlement_error");
            }
            if recovery {
                let attempt = round["settle_attempts"]
                    .as_array_mut()
                    .and_then(|attempts| attempts.last_mut())
                    .ok_or_else(|| LaneError::input("settle-record", "attempt was not recorded"))?;
                if attempt["phase"] != "attempted" {
                    return Err(LaneError::input("settle-record", "attempt is not active"));
                }
                attempt["phase"] = json!("complete");
            }
        }
        Err(error) => {
            round["phase"] = json!("failed");
            round["settlement_error"] = json!(error.line());
        }
    }
    if recovery && outcome.is_ok() {
        record["phase"] = json!("settled");
        record["readback_end"] = json!("completed");
    }
    publish_reservation(&path, &record)?;
    outcome.map(|_| ())
}

pub(super) fn record_failed_settlement(
    plan: &Plan,
    run: &str,
    error: &LaneError,
) -> Result<(), LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("round-record", "runs root is absent"))?;
    let path = reservation_path(root, run);
    let _mailbox = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut record = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    let snapshot = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?
        .clone();
    let ended_by = round_end_reason(plan, &record, &snapshot).ok();
    let round = record["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    if round["phase"] == "running" || round["phase"] == "awaiting-settlement" {
        if let Some(reason) = ended_by {
            round["ended_by"] = reason;
        }
        round["phase"] = json!("failed");
        round["settlement_error"] = json!(error.line());
        publish_reservation(&path, &record)?;
    }
    Ok(())
}

fn ensure_not_rotated(record: &Value, run: &str) -> Result<(), LaneError> {
    if record["rotation"].is_object() {
        super::rotation::validate_rotation_record(&record["rotation"])?;
    }
    if record["rotation_intent"].is_object() || record["rotation"]["old_run"].as_str() == Some(run)
    {
        return Err(LaneError::input(
            "round-rotated",
            "old run has a pending or linked rotation",
        ));
    }
    Ok(())
}

fn selected_round_model(record: &Value, letter: &[u8]) -> Result<super::LaunchModel, LaneError> {
    let selection = super::LaunchModel::select(
        letter,
        record["model_selection"]["model"].as_str(),
        record["model_selection"]["effort"].as_str(),
    )?;
    if selection.model != record["model_selection"]["model"]
        || selection.effort != record["model_selection"]["effort"]
    {
        return Err(LaneError::input(
            "round-selection",
            "letter selection differs from reservation",
        ));
    }
    Ok(selection)
}

pub(super) fn continuation_argv(
    plan: &Plan,
    record: &Value,
    driver: &Path,
    request: &LaunchRequest,
    selection: &super::LaunchModel,
) -> Result<(PathBuf, Vec<String>), LaneError> {
    let step = request
        .round
        .as_deref()
        .ok_or_else(|| LaneError::input("round-step", "round is absent"))?;
    let thread = record["thread_id"].as_str();
    let fresh = threadless_continuation(record);
    let directory = if fresh {
        super::planned_step_dir(plan, step)?
    } else {
        prior_round_dir(record)?.to_path_buf()
    };
    if thread.is_none() && !fresh {
        return Err(LaneError::input("round-thread", "private thread is absent"));
    }
    let mut argv = entry_argv_round(
        driver,
        plan,
        &request.loop_name,
        &request.run,
        step,
        request.budget,
        fresh.then_some(directory.as_path()),
        thread.map(|thread| (thread, directory.as_path(), selection)),
    )?;
    if fresh {
        let prompt = argv.len() - 1;
        argv.splice(
            prompt..prompt,
            [
                "-m".into(),
                selection.model.clone(),
                "-e".into(),
                selection.effort.clone(),
            ],
        );
    }
    Ok((directory, argv))
}

pub(super) fn continuation_round(
    record: &Value,
    request: &LaunchRequest,
    directory: &Path,
    letter: &Value,
) -> Result<Value, LaneError> {
    let step = request
        .round
        .as_deref()
        .ok_or_else(|| LaneError::input("round-step", "round is absent"))?;
    let mut round = json!({"step":step,"budget_seconds":request.budget,"letter":format!("{step}.md"),"phase":"running","driver_dir":directory,"ended_by":null,"placed_at_unix_ns":letter["placed_at_unix_ns"],"in_round_letters":[]});
    if threadless_continuation(record) {
        round["fresh_thread"] = json!(true);
    }
    Ok(round)
}

/// Preview or run the next round on the same worker, starting a thread after recovery if needed.
///
/// # Errors
///
/// Refuses a missing letter, unsettled run, changed identity or failed driver.
#[allow(clippy::too_many_lines)]
pub(super) fn resume_with_host_root(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
    on_failure: &mut dyn FnMut(&Value),
    lane_bin: &Path,
) -> Result<Value, LaneError> {
    resume_with_program(
        owner_home,
        request,
        host_root,
        root_uid,
        proxy_state,
        on_failure,
        crate::container_helper::process_presence,
        |record| super::reaping::reap_interrupted_scope(record, owner_home),
        lane_bin,
    )
}

pub(super) fn interrupted_round(record: &Value, step: &str) -> bool {
    matches!(record["phase"].as_str(), Some("preparing" | "started"))
        && record["active_round"] == step
        && record["rounds"].as_array().is_some_and(|rounds| {
            rounds.len() > 1
                && rounds.last().is_some_and(|round| {
                    round["step"] == step && round["phase"] == "running" && step != "dispatch"
                })
        })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn resume_with_evidence(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
    on_failure: &mut dyn FnMut(&Value),
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    reap: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("round-program", error.to_string()))?;
    resume_with_program(
        owner_home,
        request,
        host_root,
        root_uid,
        proxy_state,
        on_failure,
        presence,
        reap,
        &exe,
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn resume_with_program(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    mut proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
    on_failure: &mut dyn FnMut(&Value),
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    reap: impl FnOnce(&Value) -> Result<Value, LaneError>,
    lane_bin: &Path,
) -> Result<Value, LaneError> {
    let began = Instant::now();
    let caller = Uid::effective().as_raw();
    let step = request
        .round
        .as_deref()
        .ok_or_else(|| LaneError::input("round-step", "round is absent"))?;
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    let _admission = crate::install::lock_loop_config(&config, true)?;
    admission::ensure_open(&config, caller)?;
    let (mut plan, settings) = load_plan(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("round-home", "runs root is absent"))?
        .to_path_buf();
    let path = reservation_path(&root, &request.run);
    let before_reconciliation = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    ensure_not_rotated(&before_reconciliation, &request.run)?;
    let recovering = interrupted_round(&before_reconciliation, step);
    let proxy_service = if recovering || before_reconciliation["plan"]["vendor_mode"].is_string() {
        json!({"verdict":"not-applicable"})
    } else {
        let (unit, invocation) =
            super::reaping::require_proxy_invocation_with(&request.loop_name, &mut proxy_state)?;
        json!({"verdict":"passed","unit":unit,"active_state":"active","invocation":invocation})
    };
    let worker = before_reconciliation["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("round-record", "worker UID is absent"))?;
    plan.select_worker_uid(worker)?;
    plan.select_container_program(&request.podman_bin)?;
    if before_reconciliation["plan"]["vendor_mode"].is_string() {
        plan.observe_vendor()?;
    }
    plan.select_launch_model(&before_reconciliation["model_selection"])?;
    plan.retain_attempt_wall(&before_reconciliation["plan"])?;
    super::compare_pinned_plan(&before_reconciliation["plan"], &plan.document)?;
    if recovering {
        let runs = home::verify_host_launch_root(host_root, owner_home, &root, caller, root_uid)?;
        super::report::require_unoccupied(
            &runs,
            &request.run,
            super::interrupted_report_step(&before_reconciliation)?,
        )?;
        if before_reconciliation["loop"] != request.loop_name
            || before_reconciliation["run"] != request.run
        {
            return Err(LaneError::input(
                "round-record",
                "reservation names another run; inspect the selected reservation before retrying launch",
            ));
        }
        let letter = before_reconciliation["letter_source"]
            .as_str()
            .map(PathBuf::from)
            .ok_or_else(|| {
                LaneError::input("launch-reservation", "recorded letter source is absent")
            })?;
        let preview = super::interrupted_recovery_preview(
            &before_reconciliation,
            &plan,
            &letter,
            request,
            owner_home,
            &mut presence,
        )?;
        if request.dry_run {
            return Ok(
                json!({"schema":1,"command":"launch","dry_run":true,"plan":plan.document,"proxy_service":proxy_service,"bound_source_matrix":{"state":"not-applicable","reason":"interrupted settlement starts no new container"},"checks_performed":["pinned plan and selected round","interrupted settlement process identities and complete attempt evidence"],"interrupted_settlement":preview,"changed":false,"wall_seconds":began.elapsed().as_secs_f64()}),
            );
        }
        return super::complete_interrupted_launch(
            owner_home,
            request,
            host_root,
            root_uid,
            &plan,
            &before_reconciliation,
            lane_bin,
            began,
            on_failure,
            presence,
            reap,
        );
    }
    if request.expect_digest.is_some() {
        return Err(LaneError::input(
            "settlement-digest",
            "--expect-digest applies only to interrupted recovery",
        ));
    }
    let (record, letter_reconciliation) =
        super::letters::reconcile_run(&plan, &request.run, owner_home, caller, !request.dry_run)?;
    ensure_not_rotated(&record, &request.run)?;
    if record["phase"] != "settled" {
        return Err(LaneError::input(
            "round-state",
            format!(
                "run has no settled round to resume; for a failed round with recorded driver and helper completion run settle {} {} --round STEP --dry-run, then apply its preview_sha256 with --expect-digest before placing and launching the next letter; for a dead dispatch with missing completion retry the original launch LOOP RUN --letter FILE --dry-run and then apply with --expect-digest HEX from interrupted_settlement.preview_sha256 instead of --dry-run; for an interrupted running round retry launch {} {} --round STEP --dry-run with its active step",
                request.loop_name, request.run, request.loop_name, request.run
            ),
        ));
    }
    super::compare_pinned_plan(&record["plan"], &plan.document)?;
    let letter_name = format!("{step}.md");
    let entry = record["letters"]
        .as_array()
        .and_then(|letters| {
            letters.iter().find(|letter| {
                letter["name"] == letter_name
                    && letter["step"] == step
                    && letter["in_round"] == false
                    && letter["state"] == "placed"
            })
        })
        .ok_or_else(|| {
            LaneError::input(
                "round-letter",
                format!("{letter_name} has no placed reservation"),
            )
        })?;
    if record["rounds"]
        .as_array()
        .is_none_or(|rounds| rounds.iter().any(|round| round["step"] == step))
    {
        return Err(LaneError::input(
            "round-step",
            "round step is already used or rounds are absent",
        ));
    }
    let letter = home::read_letter(&plan.home.join(".local/inbox").join(&letter_name), caller)?;
    if entry["bytes"] != letter.len()
        || entry["sha256"] != build::sha256_bytes(&letter, owner_home)?
    {
        return Err(LaneError::input(
            "round-letter",
            "inbox letter differs from protected placement",
        ));
    }
    let selection = selected_round_model(&record, &letter)?;
    let stop_requested = super::letters::stop_declaration(&letter)?;
    if entry["stop"] != stop_requested {
        return Err(LaneError::input(
            "letter-stop",
            "opening Stop differs from protected placement",
        ));
    }
    let podman = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("round-program", "container program is absent"))?,
    );
    let exe_word = crate::pinned::owner_executable_word(lane_bin, caller)?;
    let driver = settings
        .driver_bin
        .as_deref()
        .ok_or_else(|| LaneError::input("round-program", "driver_bin is absent"))?;
    let entry_program = settings
        .entry_bin
        .as_deref()
        .ok_or_else(|| LaneError::input("round-program", "entry_bin is absent"))?;
    let verified_home = home::verify_host_prefix_from(host_root, owner_home, caller, root_uid)?;
    let verified_runs =
        home::verify_host_launch_root(host_root, owner_home, &root, caller, root_uid)?;
    let environment = launch_environment(owner_home)?;
    let inspect = vec![
        "unshare".into(),
        exe_word.clone(),
        "_inspect-round".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ];
    let inspected = build::run_checked_with_private_launch(
        &podman,
        inspect,
        &environment,
        owner_home,
        60,
        "inspect-round",
        &verified_home,
        &root,
        &verified_runs,
        None,
    )?;
    let inspected: Value = serde_json::from_str(&inspected)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    if inspected["thread_id"] != record["thread_id"] {
        return Err(LaneError::input(
            "round-thread",
            "private thread differs from reservation",
        ));
    }
    let thread = inspected["thread_id"].as_str();
    let (prior_dir, argv) = continuation_argv(&plan, &record, driver, request, &selection)?;
    if request.dry_run {
        let saved_box = plan.document["runtime_argv"]
            .as_array()
            .ok_or_else(|| LaneError::input("round-thread", "saved box command is absent"))?
            .iter()
            .map(|word| {
                word.as_str().map(str::to_owned).ok_or_else(|| {
                    LaneError::input("round-thread", "saved box command word is not text")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let box_command = thread.map_or_else(
            || Ok(saved_box.clone()),
            |thread| crate::container_helper::resume_box_vector(&saved_box, thread),
        )?;
        return Ok(
            json!({"schema":1,"command":"launch","dry_run":true,"round":step,"budget_seconds":request.budget,"letter":letter_name,"letter_reconciliation_preview":letter_reconciliation,"proxy_service":proxy_service,"thread_id":thread,"home":plan.home,"worker_uid":worker,"invocation":{"program":entry_program,"argv":argv},"box_command":box_command,"changed":false,"wall_seconds":began.elapsed().as_secs_f64()}),
        );
    }
    let _lease = lock_run_preparation(&root, &request.run, caller)?;
    if !cfg!(test) {
        super::reaping::ensure_scoped_new_launch()?;
    }
    {
        let _mailbox = lock_mailbox(&root, &request.run, caller)?;
        let mut saved = read_reservation(&path)?
            .ok_or_else(|| LaneError::input("round-record", "reservation vanished"))?;
        ensure_not_rotated(&saved, &request.run)?;
        if saved != record {
            return Err(LaneError::input(
                "round-record",
                "reservation changed during preview",
            ));
        }
        let next_round = continuation_round(&saved, request, &prior_dir, entry)?;
        saved["phase"] = json!("preparing");
        saved["active_round"] = json!(step);
        saved["letter_source"] = json!(plan.home.join(".local/inbox").join(&letter_name));
        saved["rounds"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("round-record", "rounds are absent"))?
            .push(next_round);
        saved["launcher_pid"] = json!(std::process::id());
        saved["launcher_start"] =
            json!(crate::container_helper::process_start(std::process::id())?);
        if !cfg!(test) {
            saved["run_scope"] = super::reaping::current_scope(&request.loop_name)?;
        }
        clear_round_evidence(&mut saved)?;
        saved["helper_spawn_state"] = json!("not-started");
        publish_reservation(&path, &saved)?;
    }
    let inspect_record = vec![
        "unshare".into(),
        exe_word.clone(),
        "_inspect-round".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--record".into(),
        step.into(),
        "--budget".into(),
        request.budget.to_string(),
    ];
    let recorded = build::run_checked_with_private_launch(
        &podman,
        inspect_record,
        &environment,
        owner_home,
        60,
        "round-evidence",
        &verified_home,
        &root,
        &verified_runs,
        None,
    );
    if let Err(error) = recorded {
        let saved = super::record_failed_pre_driver(&path, &mut None, &error, caller, false);
        return Err(super::retain_startup_refusal(error, saved));
    }
    persist_settlement_field(&path, "helper_spawn_state", json!("starting"))?;
    let (mut helper, helper_start, helper_stderr) = start_helper_with_program(
        request,
        &plan,
        owner_home,
        &environment,
        &verified_home,
        &root,
        &verified_runs,
        lane_bin,
        |pid, start| {
            let mut saved = read_reservation(&path)?.ok_or_else(|| {
                LaneError::input(
                    "helper-start",
                    "reservation vanished before parent identity",
                )
            })?;
            saved["helper_parent_pid"] = json!(pid);
            saved["helper_parent_start"] = json!(start);
            saved["helper_spawn_state"] = json!("running");
            publish_reservation(&path, &saved)
        },
    )
    .map_err(|error| {
        // Preserve a failed startup even when no driver directory was created.
        let saved = super::record_failed_pre_driver(&path, &mut None, &error, caller, false);
        super::retain_startup_refusal(error, saved)
    })?;
    let mut driver_started = false;
    let mut child_end = build::ChildEnd::default();
    let result = (|| {
        let record = read_reservation(&path)?.ok_or_else(|| {
            LaneError::input("helper-session", "protected run reservation is absent")
        })?;
        build::run_checked_with_pid(
            entry_program,
            argv,
            &environment,
            owner_home,
            crate::container_helper::host_launch_bound(&record)?,
            "driver-launch",
            &mut child_end,
            |pid| {
                persist_settlement_field(&path, "driver_entry_pid", json!(pid))?;
                persist_settlement_field(
                    &path,
                    "driver_entry_start",
                    json!(crate::container_helper::process_start(pid)?),
                )?;
                driver_started = true;
                Ok(())
            },
        )
    })();
    let step_directory = result.as_ref().map_or(Ok(()), |output| {
        record_step_directory(&plan, &request.run, step, output)
    });
    persist_settlement_field(
        &path,
        "driver_end",
        super::driver_completion(&result, driver_started, &child_end),
    )?;
    let helper_stop = stop_helper(&mut helper, &plan, &verified_runs);
    if let Some(status) = helper
        .try_wait()
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?
    {
        persist_settlement_field(
            &path,
            "helper_end",
            super::helper_parent_end(
                helper.id(),
                helper_start,
                status,
                helper_stop.as_ref().err(),
            ),
        )?;
    }
    super::helper_stop_with_stderr(helper_stop, &mut helper, helper_stderr)?;
    let settle = vec![
        "unshare".into(),
        exe_word,
        "_settle-evidence".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ];
    let settlement = build::run_checked_with_private_launch(
        &podman,
        settle,
        &environment,
        owner_home,
        60,
        "settle-evidence",
        &verified_home,
        &root,
        &verified_runs,
        None,
    );
    persist_settlement_field(
        &path,
        "readback_end",
        json!(
            settlement
                .as_ref()
                .map_or_else(LaneError::line, |_| "completed".into())
        ),
    )?;
    let reaping = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("run-reaping", "reservation is absent"))
        .and_then(|saved| super::reaping::reap_scope(&saved, owner_home));
    persist_settlement_field(
        &path,
        "reaping",
        reaping.as_ref().map_or_else(
            |error| json!({"state":"failed","detail":error.line()}),
            Clone::clone,
        ),
    )?;
    let (round_dir, thread, publication) = {
        let _mailbox = lock_mailbox(&root, &request.run, caller)?;
        let mut saved = read_reservation(&path)?
            .ok_or_else(|| LaneError::input("round-record", "reservation vanished"))?;
        let success = result.is_ok()
            && step_directory.is_ok()
            && settlement.is_ok()
            && reaping
                .as_ref()
                .is_ok_and(|report| super::reaping::reaping_verdict(report).is_ok());
        if !success {
            let round = saved["rounds"]
                .as_array_mut()
                .and_then(|rounds| rounds.last_mut())
                .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
            round["phase"] = json!("failed");
            if let Some(line) = reaping.as_ref().err().map(LaneError::line).or_else(|| {
                reaping.as_ref().ok().and_then(|report| {
                    super::reaping::reaping_verdict(report)
                        .err()
                        .map(|error| error.line())
                })
            }) {
                round["settlement_error"] = json!(line);
            }
        }
        saved["phase"] = json!(if success { "settled" } else { "failed" });
        let round_dir = super::report::round_dir(&plan, &saved, Some(step))?;
        publish_reservation(&path, &saved)?;
        (round_dir, saved["thread_id"].clone(), saved)
    };
    step_directory?;
    super::reaping::reaping_verdict(&reaping?)?;
    let driver_report = result?;
    let settlement = super::settlement_document(&settlement?)?;
    let publication = super::report::credential_publication(&publication)?;
    let report = json!({"schema":1,"command":"launch","dry_run":false,"round":step,"round_dir":round_dir,"budget_seconds":request.budget,"letter":letter_name,"letter_reconciliation":letter_reconciliation,"thread_id":thread,"driver_report":super::driver_report_for_reader(&driver_report),"settlement":settlement,"credential_publication":publication,"wall_seconds":began.elapsed().as_secs_f64()});
    super::report::finish_with_fallback(
        &verified_runs,
        &request.run,
        Some(step),
        report,
        on_failure,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        check_identity, ensure_not_rotated, entry_argv_round, inspect_loaded_round,
        prior_round_dir, record_settlement, record_step_directory, recover_step_directory,
        round_end_reason, selected_round_model,
    };
    use crate::plan::Plan;
    use serde_json::json;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    fn client_environment_fixture() -> (tempfile::TempDir, Plan) {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("runs");
        let driver_dir = root.join("R");
        let runtime = driver_dir.join("launch");
        fs::create_dir_all(&runtime).expect("runtime directory");
        for directory in [&root, &driver_dir, &runtime] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let owner = nix::unistd::Uid::effective().as_raw();
        let loop_uid = if owner == 0 { 41001 } else { owner };
        if loop_uid != owner {
            for directory in [&driver_dir, &runtime] {
                nix::unistd::chown(
                    directory,
                    Some(nix::unistd::Uid::from_raw(loop_uid)),
                    Some(nix::unistd::Gid::from_raw(loop_uid)),
                )
                .expect("distinct loop custody");
            }
        }
        let home = fixture.path().join("home");
        let plan = Plan {
            document: json!({"home":home,"driver_dir":driver_dir,"paths":[{"path":home,"gid":loop_uid},{"path":driver_dir,"uid":loop_uid,"gid":loop_uid,"kind":"directory"}]}),
            home,
            driver_dir,
            letter: PathBuf::new(),
        };
        let held = fs::File::open(&root).expect("root descriptor");
        let stat = nix::sys::stat::fstat(&held).expect("root identity");
        let environment = format!(
            "HOME={}\0SUPERLOOP_CLIENT_ROOT_DEV={}\0SUPERLOOP_CLIENT_ROOT_INO={}\0SUPERLOOP_CLIENT_SOCKET_NAME=.container-R.sock\0RETAINED=unchanged\0",
            plan.driver_dir.display(),
            stat.st_dev,
            stat.st_ino,
        );
        fs::write(runtime.join("runtime.env"), environment).expect("saved client environment");
        if loop_uid != owner {
            nix::unistd::chown(
                &runtime.join("runtime.env"),
                Some(nix::unistd::Uid::from_raw(owner)),
                Some(nix::unistd::Gid::from_raw(loop_uid)),
            )
            .expect("owner-written loop-readable environment");
        }
        fs::set_permissions(
            runtime.join("runtime.env"),
            fs::Permissions::from_mode(0o440),
        )
        .expect("environment mode");
        (fixture, plan)
    }

    /// # Panics
    ///
    /// Panics only if fixture setup or per-launch client preparation fails.
    /// ´test:unit:resume-refreshes-client-root-identity-from-current-anchor´
    #[test]
    fn resume_refreshes_client_root_identity_from_current_anchor() {
        let (fixture, plan) = client_environment_fixture();
        let root = fixture.path().join("runs");
        let retired = fixture.path().join("retired-runs");
        let runtime = plan.driver_dir.join("launch");
        let owner = nix::unistd::Uid::effective().as_raw();
        let old = fs::File::open(&root).expect("old root descriptor");
        let old_stat = nix::sys::stat::fstat(&old).expect("old identity");
        let mut record = json!({"phase":"preparing","active_round":"work-1","thread_id":"thread-1","worker_uid":owner,"rounds":[{"step":"work-1","budget_seconds":900}]});
        let before = fs::read(runtime.join("runtime.env")).expect("saved environment");
        for name in ["runtime.argv", "container.argv", "container.env"] {
            fs::write(runtime.join(name), name.as_bytes()).expect("saved command file");
        }
        {
            let _anchor =
                crate::home::activate_handed_home(&root, &old, owner).expect("old anchor");
            inspect_loaded_round(&plan, &record, Some(("work-1", 900))).expect("first preparation");
        }
        fs::rename(&root, &retired).expect("retain old root");
        fs::create_dir(&root).expect("replacement root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        fs::rename(retired.join("R"), &plan.driver_dir).expect("retain run files");
        let live = fs::File::open(&root).expect("live root descriptor");
        let live_stat = nix::sys::stat::fstat(&live).expect("live identity");
        assert_ne!(
            (old_stat.st_dev, old_stat.st_ino),
            (live_stat.st_dev, live_stat.st_ino)
        );
        let _anchor = crate::home::activate_handed_home(&root, &live, owner).expect("new anchor");
        inspect_loaded_round(&plan, &record, None).expect("read-only inspection");
        assert_eq!(
            fs::read(runtime.join("runtime.env")).expect("preview environment"),
            before
        );
        record["active_round"] = json!("work-2");
        record["rounds"][0]["step"] = json!("work-2");
        inspect_loaded_round(&plan, &record, Some(("work-2", 900))).expect("second preparation");
        let after = fs::read(runtime.join("runtime.env")).expect("refreshed environment");
        let expected = String::from_utf8(before)
            .expect("environment text")
            .replace(
                &format!("SUPERLOOP_CLIENT_ROOT_DEV={}\0", old_stat.st_dev),
                &format!("SUPERLOOP_CLIENT_ROOT_DEV={}\0", live_stat.st_dev),
            )
            .replace(
                &format!("SUPERLOOP_CLIENT_ROOT_INO={}\0", old_stat.st_ino),
                &format!("SUPERLOOP_CLIENT_ROOT_INO={}\0", live_stat.st_ino),
            );
        assert_eq!(
            after,
            expected.as_bytes(),
            "live pair and every other entry retained"
        );
        let metadata = fs::metadata(runtime.join("runtime.env")).expect("environment metadata");
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (
                owner,
                crate::plan::loop_uid(&plan.document).expect("loop identity"),
                0o440
            )
        );
        for name in ["runtime.argv", "container.argv", "container.env"] {
            assert_eq!(
                fs::read(runtime.join(name)).expect("saved command"),
                name.as_bytes()
            );
        }
    }

    /// # Panics
    /// Panics only if the provisioned namespace or distinct-identity contract is absent.
    /// ´test:unit:resume-client-environment-distinguishes-owner-and-loop-identities´
    #[test]
    #[ignore = "requires provisioned namespace root with loop uid and gid 41001 mapped"]
    fn resume_client_environment_distinguishes_owner_and_loop_identities() {
        assert!(
            nix::unistd::Uid::effective().is_root(),
            "namespace-root-required"
        );
        resume_refreshes_client_root_identity_from_current_anchor();
    }

    /// # Panics
    /// Panics only if fixture setup or the loop-group mismatch refusal fails.
    /// ´test:unit:resume-client-environment-refuses-wrong-loop-group´
    #[test]
    fn resume_client_environment_refuses_wrong_loop_group() {
        let owner = nix::unistd::Uid::effective().as_raw();
        let groups = nix::unistd::getgroups().expect("fixture-supplementary-groups");
        let group = (0..u32::MAX)
            .find(|group| {
                *group != nix::unistd::Gid::effective().as_raw()
                    && !groups.iter().any(|held| held.as_raw() == *group)
            })
            .expect("fixture-unheld-loop-group");
        let (fixture, plan) = client_environment_fixture();
        let root = fs::File::open(fixture.path().join("runs")).expect("runs root");
        let runtime = fs::File::open(plan.driver_dir.join("launch")).expect("runtime");
        let root = root.into();
        let runtime = runtime.into();
        let environment = plan.driver_dir.join("launch/runtime.env");
        nix::unistd::chown(&environment, None, Some(nix::unistd::Gid::effective()))
            .expect("owner group");
        let metadata = fs::metadata(&environment).expect("environment metadata");
        assert!(metadata.is_file());
        assert_eq!((metadata.uid(), metadata.mode() & 0o7777), (owner, 0o440));
        assert_ne!(metadata.gid(), group, "fixture-loop-group-mismatch");
        let refusal = super::super::prepare_client_environment(
            &plan.driver_dir,
            &root,
            &runtime,
            group,
            false,
        )
        .expect_err("owner group cannot stand in for loop group");
        assert_eq!(refusal.kind, "runtime-client");
        assert_eq!(
            refusal.detail, "saved client environment has foreign ownership or protection",
            "loop-group-mismatch-refusal: only the saved gid differs"
        );
    }

    /// # Panics
    /// Panics only if a distinct supplementary group or its custody contract is absent.
    /// ´test:unit:resume-client-environment-distinguishes-supplementary-group´
    #[test]
    #[ignore = "requires a supplementary group distinct from the primary group"]
    fn resume_client_environment_distinguishes_supplementary_group() {
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::getgroups()
            .expect("fixture-supplementary-groups")
            .into_iter()
            .find(|group| group.as_raw() != owner && *group != nix::unistd::Gid::effective())
            .expect("fixture-supplementary-group-required");
        let (fixture, plan) = client_environment_fixture();
        let root = fs::File::open(fixture.path().join("runs")).expect("runs root");
        let runtime = fs::File::open(plan.driver_dir.join("launch")).expect("runtime");
        let root = root.into();
        let runtime = runtime.into();
        let environment = plan.driver_dir.join("launch/runtime.env");
        nix::unistd::chown(&environment, None, Some(group)).expect("supplementary loop group");
        super::super::prepare_client_environment(
            &plan.driver_dir,
            &root,
            &runtime,
            group.as_raw(),
            false,
        )
        .expect("supplementary-group refresh");
        let metadata = fs::metadata(environment).expect("refreshed environment");
        assert_eq!((metadata.uid(), metadata.gid()), (owner, group.as_raw()));
    }

    /// ´test:unit:resumed-launch-uses-recorded-selection-for-omitted-letter-lines´
    #[test]
    fn resumed_launch_uses_recorded_selection_for_omitted_letter_lines() {
        let request = crate::launch::LaunchRequest::parse(
            &["alpha", "R", "--round", "verify-1"].map(str::to_owned),
        )
        .expect("production resumed launch form");
        assert_eq!(request.round.as_deref(), Some("verify-1"));
        let record = json!({"model_selection":{"model":"gpt-6-sol","effort":"high"}});
        let omitted = selected_round_model(&record, b"Verify the result.\n")
            .expect("recorded selection supplies both missing fields");
        assert_eq!(
            (omitted.model.as_str(), omitted.effort.as_str()),
            ("gpt-6-sol", "high")
        );
        let matching = selected_round_model(&record, b"Model: gpt-6-sol\nEffort: high\n")
            .expect("matching declarations");
        assert_eq!(
            (matching.model.as_str(), matching.effort.as_str()),
            ("gpt-6-sol", "high")
        );
        assert_eq!(
            selected_round_model(&record, b"Model: gpt-5.5\nEffort: high\n")
                .expect_err("changed model refuses")
                .kind,
            "round-selection"
        );
    }

    /// ´test:unit:private-inspector-request-is-readable-by-round-client´
    #[test]
    fn private_inspector_request_is_readable_by_round_client() {
        let (fixture, plan) = client_environment_fixture();
        let directory = plan.driver_dir.clone();
        let root = fixture.path().join("runs");
        let held = fs::File::open(&root).expect("root descriptor");
        let owner = nix::unistd::Uid::effective().as_raw();
        let _anchor = crate::home::activate_handed_home(&root, &held, owner).expect("root anchor");
        let record = json!({"phase":"preparing","active_round":"review","thread_id":"thread-1","worker_uid":3000,"rounds":[{"step":"review","budget_seconds":900}]});
        assert_ne!(plan.document["paths"][1]["uid"], record["worker_uid"]);
        inspect_loaded_round(&plan, &record, Some(("review", 900)))
            .expect("private inspector publishes request");
        let path = directory.join("round-launch-review.json");
        let metadata = fs::metadata(&path).expect("request metadata");
        assert!(
            fs::read_dir(&directory)
                .expect("round directory")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".round-launch-")),
            "hidden request staging is gone after publication"
        );
        let directory_metadata = fs::metadata(&directory).expect("directory metadata");
        assert_eq!(metadata.uid(), directory_metadata.uid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let thread = crate::container_helper::requested_thread(
            &directory,
            b"Read /home/worker/.local/inbox/review.md.",
        )
        .expect("round client reads request");
        assert_eq!(thread.as_deref(), Some("thread-1"));
    }

    /// ´test:unit:round-vector-carries-budget-step-and-resume-thread´
    #[test]
    fn round_vector_carries_budget_step_and_resume_thread() {
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: PathBuf::from("/runs/R"),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let selection = super::super::LaunchModel::select(
            b"Model: gpt-6-sol\nEffort: high\nReview this round.\n",
            None,
            None,
        )
        .expect("round letter selection");
        let dispatch = json!({"rounds":[{"step":"dispatch","phase":"settled","driver_dir":"/runs/R/20261007T093830Z-dispatch"}]});
        let words = entry_argv_round(
            PathBuf::from("/bin/driver").as_path(),
            &plan,
            "alpha",
            "R",
            "review",
            900,
            None,
            Some((
                "thread-1",
                prior_round_dir(&dispatch).expect("dispatch directory"),
                &selection,
            )),
        )
        .expect("round vector");
        assert_eq!(
            words,
            vec![
                "driver-launch",
                "alpha",
                "R",
                "--driver-bin",
                "/bin/driver",
                "--run-dir",
                "/runs/R",
                "--",
                "-t",
                "900",
                "-n",
                "review",
                "-C",
                "/runs/R",
                "-s",
                "workspace-write",
                "-r",
                "thread-1",
                "-d",
                "/runs/R/20261007T093830Z-dispatch",
                "-m",
                "gpt-6-sol",
                "-e",
                "high",
                "--step-letter",
                "/home/worker/.local/inbox/review.md",
                "Read /home/worker/.local/inbox/review.md."
            ]
        );
        let second = json!({"rounds":[{"step":"dispatch","phase":"settled","driver_dir":"/runs/R/20261007T093830Z-dispatch"},{"step":"review","phase":"settled","driver_dir":"/runs/R/20261007T093830Z-dispatch"}]});
        assert_eq!(
            prior_round_dir(&second).expect("second round source"),
            PathBuf::from("/runs/R/20261007T093830Z-dispatch")
        );
    }

    /// ´test:unit:threadless-round-vector-carries-step-letter´
    #[test]
    fn threadless_round_vector_carries_step_letter() {
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: PathBuf::from("/runs/R"),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let words = entry_argv_round(
            Path::new("/bin/driver"),
            &plan,
            "alpha",
            "R",
            "review",
            900,
            Some(Path::new("/runs/R/fresh-review")),
            None,
        )
        .expect("threadless continuation vector");
        assert_eq!(
            words,
            vec![
                "driver-launch",
                "alpha",
                "R",
                "--driver-bin",
                "/bin/driver",
                "--run-dir",
                "/runs/R",
                "--",
                "-t",
                "900",
                "-n",
                "review",
                "-C",
                "/runs/R",
                "-s",
                "workspace-write",
                "-d",
                "/runs/R/fresh-review",
                "--step-letter",
                "/home/worker/.local/inbox/review.md",
                "Read /home/worker/.local/inbox/review.md."
            ]
        );
    }

    fn settlement_fixture(with_thread: bool) -> (tempfile::TempDir, Plan) {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let driver_dir = fixture.path().join("R");
        let step_dir = driver_dir.join("20261007T043545Z-dispatch");
        fs::create_dir_all(&step_dir).expect("step directory");
        if with_thread {
            fs::write(step_dir.join("thread-id.txt"), b"thread-1\n").expect("thread evidence");
        }
        let events = if with_thread {
            b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n".as_slice()
        } else {
            b"{\"type\":\"turn.started\"}\n".as_slice()
        };
        fs::write(step_dir.join("events.jsonl"), events).expect("step events");
        fs::write(step_dir.join(".event-start"), b"0\n").expect("step boundary");
        fs::write(
            step_dir.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=dispatch exit=0 verdict=ok dir={}\n",
                step_dir.display()
            ),
        )
        .expect("step report");
        let plan = Plan {
            home: fixture.path().join("home-R"),
            driver_dir,
            letter: PathBuf::new(),
            document: json!({"worker_uid":3000}),
        };
        let record = json!({"schema":1,"loop":"alpha","run":"R","phase":"started","active_round":"dispatch","worker_uid":3000,"plan":{"worker_uid":3000,"home":plan.home,"driver_dir":plan.driver_dir},"letters":[],"rounds":[{"step":"dispatch","phase":"running","driver_dir":step_dir}]});
        super::publish_reservation(&super::reservation_path(fixture.path(), "R"), &record)
            .expect("reservation");
        (fixture, plan)
    }

    /// ´test:unit:failed-round-settlement-retries-only-through-recovery´
    #[test]
    fn failed_round_settlement_retries_only_through_recovery() {
        let (fixture, plan) = settlement_fixture(true);
        let path = super::reservation_path(fixture.path(), "R");
        let mut record = super::read_reservation(&path)
            .expect("read reservation")
            .expect("record");
        record["phase"] = json!("failed");
        record["rounds"][0]["phase"] = json!("failed");
        record["readback_end"] = json!("settle-evidence: door-generation: old record");
        record["rounds"][0]["settle_attempts"] =
            json!([{"preview_sha256":"fixture","phase":"attempted","detail":null}]);
        super::publish_reservation(&path, &record).expect("failed reservation");
        let reply = json!({"bytes":4,"sha256":"fixture"});
        assert_eq!(
            record_settlement(&plan, "alpha", "R", &reply)
                .expect_err("ordinary helper cannot retry failed round")
                .kind,
            "round-record"
        );
        super::record_settlement_with_recovery(&plan, "R", &reply, true)
            .expect("recovery settles the recorded reply");
        let saved = super::read_reservation(&path)
            .expect("read reservation")
            .expect("record");
        assert_eq!(saved["rounds"][0]["phase"], "settled");
        assert_eq!(saved["phase"], "settled");
        assert_eq!(
            saved["rounds"][0]["settle_attempts"][0]["phase"],
            "complete"
        );
        assert!(saved["rounds"][0].get("settlement_error").is_none());
    }

    /// ´test:unit:stop-report-and-over-budget-use-report-round-ends´
    #[test]
    fn stop_report_and_over_budget_use_report_round_ends() {
        let (_fixture, plan) = settlement_fixture(true);
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        let round = json!({"step":"dispatch","driver_dir":directory});
        assert_eq!(
            round_end_reason(&plan, &json!({"rounds":[round]}), &round)
                .expect("ordinary terminal report"),
            "by-report"
        );
        let record =
            json!({"rounds":[round],"letters":[{"step":"dispatch","stop":true,"state":"placed"}]});
        assert_eq!(
            round_end_reason(&plan, &record, &round).expect("normal report after stop"),
            "by-report-after-stop"
        );
        fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=dispatch exit=0 verdict=OVER-BUDGET dir={}\n",
                directory.display()
            ),
        )
        .expect("over-budget report");
        assert_eq!(
            round_end_reason(&plan, &record, &round).expect("report after stop"),
            "by-report-after-stop"
        );
        for verdict in ["STALLED-KILLED", "RUNAWAY-KILLED"] {
            fs::write(
                directory.join("run-report.txt"),
                format!(
                    "RUN-REPORT lane=dispatch exit=1 verdict={verdict} dir={}\n",
                    directory.display()
                ),
            )
            .expect("historical failed report");
            assert_eq!(
                round_end_reason(&plan, &record, &round).expect("failed driver report"),
                "by-report"
            );
        }
    }

    /// ´test:unit:round-end-uses-held-report-after-path-replacement´
    #[test]
    fn round_end_uses_held_report_after_path_replacement() {
        let (_fixture, plan) = settlement_fixture(true);
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        let round = json!({"step":"dispatch","driver_dir":directory});
        let record =
            json!({"rounds":[round],"letters":[{"step":"dispatch","stop":true,"state":"placed"}]});
        let (held_directory, file) = super::verified_report(&plan, &record, &round)
            .expect("bounded owned report descriptor");
        let replacement = directory.join("replacement-report.txt");
        fs::write(
            &replacement,
            format!(
                "RUN-REPORT lane=dispatch exit=1 verdict=STALLED-KILLED dir={}\n",
                directory.display()
            ),
        )
        .expect("replacement");
        fs::rename(&replacement, directory.join("run-report.txt")).expect("replace path");
        let line = super::verified_report_line(file, &held_directory, "dispatch")
            .expect("held original report");
        assert_eq!(
            super::classify_report_end(&record, &round, &line),
            "by-report-after-stop"
        );
        assert_eq!(
            round_end_reason(&plan, &record, &round).expect("new path"),
            "by-report"
        );
    }

    /// ´test:unit:failed-private-settlement-keeps-terminal-report-end´
    #[test]
    fn failed_private_settlement_keeps_terminal_report_end() {
        let (fixture, plan) = settlement_fixture(true);
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        let report = format!(
            "RUN-REPORT lane=dispatch exit=1 wall=901s budget=900s verdict=STALLED-KILLED dir={}\n",
            directory.display()
        );
        record_step_directory(&plan, "R", "dispatch", &report).expect("directory recorded");
        fs::write(directory.join("run-report.txt"), report).expect("terminal report");
        let error = crate::error::LaneError::input("round-reply", "reply is absent");
        super::record_failed_settlement(&plan, "R", &error).expect("private failure record");
        let saved = super::read_reservation(&super::reservation_path(fixture.path(), "R"))
            .expect("read reservation")
            .expect("reservation");
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert_eq!(saved["rounds"][0]["ended_by"], "by-report");
    }

    /// ´test:unit:failed-private-settlement-keeps-verified-stop-report-end´
    #[test]
    fn failed_private_settlement_keeps_verified_stop_report_end() {
        let (fixture, plan) = settlement_fixture(true);
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        let report = format!(
            "RUN-REPORT lane=dispatch exit=0 verdict=ok dir={}\n",
            directory.display()
        );
        record_step_directory(&plan, "R", "dispatch", &report).expect("directory recorded");
        fs::write(directory.join("run-report.txt"), report).expect("terminal report");
        let path = super::reservation_path(fixture.path(), "R");
        let mut record = super::read_reservation(&path)
            .expect("read")
            .expect("reservation");
        record["letters"] = json!([{"step":"dispatch","stop":true,"state":"placed"}]);
        super::publish_reservation(&path, &record).expect("stop letter");
        let error = crate::error::LaneError::input("round-reply", "reply is absent");
        super::record_failed_settlement(&plan, "R", &error).expect("private failure record");
        let saved = super::read_reservation(&path)
            .expect("read")
            .expect("reservation");
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert_eq!(saved["rounds"][0]["ended_by"], "by-report-after-stop");
        assert!(saved["rounds"][0]["settlement_error"].is_string());
    }

    /// # Panics
    /// Panics only if fixture setup or the asserted attempt-wall contract fails.
    ///
    /// ´test:unit:attempt-wall-keeps-the-failed-report-settlement-route´
    #[test]
    fn attempt_wall_keeps_the_failed_report_settlement_route() {
        let (fixture, plan) = settlement_fixture(true);
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        let report = format!(
            "RUN-REPORT lane=dispatch exit=1 verdict=FAILED dir={} cause=attempt-wall attempt_elapsed_seconds=9 attempt_bound_seconds=8\n",
            directory.display()
        );
        let path = super::reservation_path(fixture.path(), "R");
        let mut record = super::read_reservation(&path)
            .expect("read")
            .expect("reservation");
        let end = json!({"cause":"attempt-wall","attempt_elapsed_seconds":9,"bound_seconds":8});
        record["rounds"][0]["attempt_end"] = end.clone();
        super::publish_reservation(&path, &record).expect("helper end");
        record_step_directory(&plan, "R", "dispatch", &report).expect("directory recorded");
        fs::write(directory.join("run-report.txt"), report).expect("terminal report");
        let error = crate::error::LaneError::input("round-reply", "reply is absent");
        super::record_failed_settlement(&plan, "R", &error).expect("existing failure route");
        let saved = super::read_reservation(&path)
            .expect("read")
            .expect("reservation");
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert_eq!(saved["rounds"][0]["ended_by"], "by-report");
        assert_eq!(saved["rounds"][0]["attempt_end"], end);
    }

    /// ´test:unit:old-round-admission-refuses-pending-and-linked-rotation´
    #[test]
    fn old_round_admission_refuses_pending_and_linked_rotation() {
        let pending = json!({"phase":"settled","rotation_intent":{"new_run":"R-rotation-1"}});
        assert_eq!(
            ensure_not_rotated(&pending, "R")
                .expect_err("pending handover")
                .kind,
            "round-rotated"
        );
        let linked = json!({"phase":"settled","rotation":{"old_run":"R","new_run":"R-rotation-1","context":{"state":"unknown"},"threshold":null,"force_reason":null,"digest_override_reason":null,"stop_letter":{"name":"review.md","placed_at_unix_ns":1},"replies":[],"inbox_letters":[],"next_task":{"state":"absent","sha256":null}}});
        assert_eq!(
            ensure_not_rotated(&linked, "R")
                .expect_err("linked handover")
                .kind,
            "round-rotated"
        );
        ensure_not_rotated(&linked, "R-rotation-1").expect("new run may continue");
    }

    /// ´test:unit:owner-records-step-directory-without-reading-loop-owned-tree´
    #[test]
    fn owner_records_step_directory_without_reading_loop_owned_tree() {
        let (fixture, plan) = settlement_fixture(true);
        let step = plan.driver_dir.join("20261007T043545Z-dispatch");
        fs::set_permissions(&plan.driver_dir, fs::Permissions::from_mode(0o000))
            .expect("deny owner traversal");
        let wrong = format!(
            "RUN-REPORT lane=dispatch exit=0 dir={}\n",
            fixture.path().join("elsewhere-dispatch").display()
        );
        let error = record_step_directory(&plan, "R", "dispatch", &wrong)
            .expect_err("foreign directory refuses by name");
        assert_eq!(
            error.line(),
            "round-record: terminal report directory differs from running round"
        );
        assert_eq!(error.status, 2);
        let report = format!("RUN-REPORT lane=dispatch exit=0 dir={}\n", step.display());
        record_step_directory(&plan, "R", "dispatch", &report)
            .expect("record path without reading beneath driver directory");
        fs::set_permissions(&plan.driver_dir, fs::Permissions::from_mode(0o700))
            .expect("restore driver mode");
        let saved = super::read_reservation(&super::reservation_path(fixture.path(), "R"))
            .expect("read reservation")
            .expect("record");
        assert_eq!(saved["rounds"][0]["driver_dir"], json!(step));
        assert_eq!(saved["rounds"][0]["phase"], "awaiting-settlement");
    }

    /// ´test:unit:refused-driver-directory-without-report-marks-round-failed´
    #[test]
    fn refused_driver_directory_without_report_marks_round_failed() {
        let (fixture, plan) = settlement_fixture(true);
        let step = plan.driver_dir.join("20261007T043545Z-dispatch");
        fs::remove_file(step.join("run-report.txt")).expect("remove report from occupied name");
        let error = recover_step_directory(&plan, "R")
            .expect_err("recorded directory without report cannot be recovered");
        assert_eq!(error.kind, "round-directory");
        assert_eq!(error.status, 2);
        super::record_failed_settlement(&plan, "R", &error).expect("record failed round");
        let saved = super::read_reservation(&super::reservation_path(fixture.path(), "R"))
            .expect("read")
            .expect("record");
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert_eq!(saved["rounds"][0]["driver_dir"], json!(step));
        assert_eq!(saved["rounds"][0]["settlement_error"], error.line());
    }

    /// ´test:unit:older-round-row-without-directory-refuses-by-name´
    #[test]
    fn older_round_row_without_directory_refuses_by_name() {
        let (fixture, plan) = settlement_fixture(true);
        let path = super::reservation_path(fixture.path(), "R");
        let mut record = super::read_reservation(&path)
            .expect("read")
            .expect("record");
        record["rounds"][0]
            .as_object_mut()
            .expect("round row")
            .remove("driver_dir");
        super::publish_reservation(&path, &record).expect("older row");
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        let report = format!(
            "RUN-REPORT lane=dispatch exit=0 dir={}\n",
            directory.display()
        );
        let terminal = record_step_directory(&plan, "R", "dispatch", &report)
            .expect_err("terminal report refuses older row");
        assert_eq!(
            terminal.line(),
            "round-record: dispatch has no recorded driver directory"
        );
        assert_eq!(terminal.status, 2);
        let recovery = recover_step_directory(&plan, "R").expect_err("recovery refuses older row");
        assert_eq!(recovery.line(), terminal.line());
        assert_eq!(recovery.status, 2);
    }

    /// ´test:unit:resumed-round-records-and-verifies-prior-driver-directory´
    #[test]
    fn resumed_round_records_and_verifies_prior_driver_directory() {
        let (fixture, plan) = settlement_fixture(true);
        let prior = plan.driver_dir.join("20261007T043545Z-dispatch");
        let path = super::reservation_path(fixture.path(), "R");
        let mut record = super::read_reservation(&path)
            .expect("read reservation")
            .expect("record");
        record["rounds"][0]["phase"] = json!("settled");
        record["rounds"][0]["driver_dir"] = json!(prior);
        record["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({"step":"review","phase":"running","driver_dir":prior}));
        record["active_round"] = json!("review");
        super::publish_reservation(&path, &record).expect("review reservation");
        let wrong = format!(
            "RUN-REPORT lane=review exit=0 dir={}\n",
            plan.driver_dir.join("elsewhere-review").display()
        );
        let error = record_step_directory(&plan, "R", "review", &wrong)
            .expect_err("round must use prior directory");
        assert!(error.line().contains("round-record"));
        let report = format!("RUN-REPORT lane=review exit=0 dir={}\n", prior.display());
        fs::write(prior.join("run-report.txt"), &report).expect("review report");
        recover_step_directory(&plan, "R").expect("recover resumed directory from row");
        recover_step_directory(&plan, "R").expect("private report verification");
        let mut recovered = super::read_reservation(&path)
            .expect("read recovered reservation")
            .expect("record");
        recovered["rounds"][1]["phase"] = json!("running");
        super::publish_reservation(&path, &recovered).expect("owner recording fixture");
        record_step_directory(&plan, "R", "review", &report)
            .expect("owner verifies prior directory");
        let saved = super::read_reservation(&path)
            .expect("read reservation")
            .expect("record");
        assert_eq!(saved["rounds"][1]["driver_dir"], json!(prior));
        assert_eq!(saved["rounds"][1]["phase"], "awaiting-settlement");
    }

    /// ´test:unit:private-step-verifies-awaiting-directory-and-report´
    #[test]
    fn private_step_verifies_awaiting_directory_and_report() {
        for defect in ["none", "absent", "link", "wrong-report"] {
            let (fixture, plan) = settlement_fixture(true);
            let step = plan.driver_dir.join("20261007T043545Z-dispatch");
            let report = format!("RUN-REPORT lane=dispatch exit=0 dir={}\n", step.display());
            fs::write(step.join("run-report.txt"), &report).expect("driver report");
            record_step_directory(&plan, "R", "dispatch", &report).expect("owner record");
            match defect {
                "absent" => {
                    fs::rename(&step, plan.driver_dir.join("saved-dispatch"))
                        .expect("move step directory");
                }
                "link" => {
                    let saved = plan.driver_dir.join("saved-dispatch");
                    fs::rename(&step, &saved).expect("move step directory");
                    std::os::unix::fs::symlink(&saved, &step).expect("linked step directory");
                }
                "wrong-report" => {
                    fs::write(
                        step.join("run-report.txt"),
                        format!(
                            "RUN-REPORT lane=dispatch exit=0 dir={}\n",
                            plan.driver_dir.join("other-dispatch").display()
                        ),
                    )
                    .expect("changed report");
                }
                _ => {}
            }
            if defect == "none" {
                recover_step_directory(&plan, "R").expect("matching private evidence");
            } else {
                let error = recover_step_directory(&plan, "R")
                    .expect_err("private verification refuses changed evidence");
                assert!(
                    error.line().contains("round-directory"),
                    "{defect}: {error:?}"
                );
            }
            let saved = super::read_reservation(&super::reservation_path(fixture.path(), "R"))
                .expect("read reservation")
                .expect("record");
            assert_eq!(saved["rounds"][0]["phase"], "awaiting-settlement");
        }
    }

    /// ´test:unit:round-settlement-reads-recorded-step-directory-thread´
    #[test]
    fn round_settlement_reads_recorded_step_directory_thread() {
        let (fixture, plan) = settlement_fixture(true);
        let report = format!(
            "RUN-REPORT lane=dispatch exit=0 wall=80s budget=3600s verdict=OK dir={}\n",
            plan.driver_dir.join("20261007T043545Z-dispatch").display()
        );
        record_step_directory(&plan, "R", "dispatch", &report).expect("driver directory");
        let reply = json!({"bytes":4,"sha256":"digest"});
        record_settlement(&plan, "alpha", "R", &reply).expect("settled round");
        let saved = super::read_reservation(&super::reservation_path(fixture.path(), "R"))
            .expect("read")
            .expect("record");
        assert_eq!(saved["thread_id"], "thread-1");
        assert_eq!(saved["rounds"][0]["phase"], "settled");
        assert_eq!(saved["rounds"][0]["reply"], reply);
        assert_eq!(
            saved["rounds"][0]["driver_dir"],
            json!(plan.driver_dir.join("20261007T043545Z-dispatch"))
        );
        check_identity(&plan, &saved).expect("resume reads recorded thread");
        let mut preparing = saved;
        preparing["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({"step":"review","phase":"running"}));
        check_identity(&plan, &preparing).expect("preparation uses prior settled thread");
    }

    /// ´test:unit:missing-step-thread-fails-without-a-reply-of-record´
    #[test]
    fn missing_step_thread_fails_without_a_reply_of_record() {
        let (fixture, plan) = settlement_fixture(false);
        let report = format!(
            "RUN-REPORT lane=dispatch exit=0 wall=80s budget=3600s verdict=OK dir={}\n",
            plan.driver_dir.join("20261007T043545Z-dispatch").display()
        );
        record_step_directory(&plan, "R", "dispatch", &report).expect("driver directory");
        let reply = json!({"bytes":4,"sha256":"digest"});
        let error = record_settlement(&plan, "alpha", "R", &reply).expect_err("missing thread");
        assert!(error.line().contains("round-thread"));
        let saved = super::read_reservation(&super::reservation_path(fixture.path(), "R"))
            .expect("read")
            .expect("record");
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert!(saved["rounds"][0]["reply"].is_null());
        assert!(
            saved["rounds"][0]["settlement_error"]
                .as_str()
                .expect("reason")
                .contains("round-thread")
        );
    }

    /// ´test:unit:resumed-settlement-uses-current-event-region-not-stale-sidecar´
    #[test]
    fn resumed_settlement_uses_current_event_region_not_stale_sidecar() {
        for (actual, settles) in [("thread-1", true), ("thread-2", false)] {
            let (fixture, plan) = settlement_fixture(true);
            let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
            let events = directory.join("events.jsonl");
            let first_end = fs::metadata(&events).expect("prior events").len();
            let archive = directory.join("steps/dispatch");
            fs::create_dir_all(&archive).expect("step archive");
            fs::write(archive.join("event-start.txt"), b"0\n").expect("archive start");
            fs::write(archive.join("event-end.txt"), format!("{first_end}\n"))
                .expect("archive end");
            fs::write(directory.join(".event-start"), format!("{first_end}\n"))
                .expect("review start");
            fs::OpenOptions::new()
                .append(true)
                .open(&events)
                .expect("append events")
                .write_all(
                    format!("{{\"type\":\"thread.started\",\"thread_id\":\"{actual}\"}}\n")
                        .as_bytes(),
                )
                .expect("review event");
            let path = super::reservation_path(fixture.path(), "R");
            let mut record = super::read_reservation(&path)
                .expect("read")
                .expect("record");
            record["thread_id"] = json!("thread-1");
            record["rounds"][0]["phase"] = json!("settled");
            record["rounds"][0]["driver_dir"] = json!(directory);
            record["rounds"]
                .as_array_mut()
                .expect("rounds")
                .push(json!({"step":"review","phase":"running","driver_dir":directory}));
            record["letters"] = json!([{"step":"review","stop":true,"state":"placed"}]);
            record["active_round"] = json!("review");
            super::publish_reservation(&path, &record).expect("review reservation");
            let report = format!(
                "RUN-REPORT lane=review exit=0 dir={}\n",
                directory.display()
            );
            record_step_directory(&plan, "R", "review", &report).expect("review directory");
            fs::write(directory.join("run-report.txt"), &report).expect("review report");
            let reply = json!({"bytes":4,"sha256":"digest"});
            let result = record_settlement(&plan, "alpha", "R", &reply);
            let saved = super::read_reservation(&path)
                .expect("read saved")
                .expect("saved");
            if settles {
                result.expect("matching event thread settles");
                assert_eq!(saved["rounds"][1]["phase"], "settled");
            } else {
                let error = result.expect_err("mismatched event thread refuses");
                assert!(error.line().contains("round-thread"));
                assert!(error.line().contains("thread-2"));
                assert!(error.line().contains("thread-1"));
                assert_eq!(saved["rounds"][1]["phase"], "failed");
                assert!(saved["rounds"][1]["reply"].is_null());
            }
            assert_eq!(saved["rounds"][1]["ended_by"], "by-report-after-stop");
        }
    }

    /// ´test:unit:interrupted-before-directory-record-settles-round-before-reservation´
    #[test]
    fn interrupted_before_directory_record_settles_round_before_reservation() {
        let (fixture, plan) = settlement_fixture(true);
        let step_dir = plan.driver_dir.join("20261007T043545Z-dispatch");
        fs::write(
            step_dir.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=dispatch exit=0 wall=80s budget=3600s verdict=OK dir={}\n",
                step_dir.display()
            ),
        )
        .expect("driver report");
        recover_step_directory(&plan, "R").expect("recover completed step directory");
        let reply = json!({"bytes":4,"sha256":"digest"});
        record_settlement(&plan, "alpha", "R", &reply).expect("settle reply");
        let path = super::reservation_path(fixture.path(), "R");
        let before = super::read_reservation(&path)
            .expect("read")
            .expect("record");
        let final_record = super::super::publish_interrupted_phase(
            &path,
            &before,
            true,
            &json!({"state":"complete"}),
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("terminal phase");
        assert_eq!(final_record["phase"], "settled");
        assert_eq!(final_record["rounds"][0]["phase"], "settled");
        assert_eq!(final_record["rounds"][0]["reply"], reply);
        assert_eq!(final_record["thread_id"], "thread-1");
    }

    /// ´test:unit:interrupted-after-directory-record-settles-round-before-reservation´
    #[test]
    fn interrupted_after_directory_record_settles_round_before_reservation() {
        let (fixture, plan) = settlement_fixture(true);
        let step_dir = plan.driver_dir.join("20261007T043545Z-dispatch");
        let report = format!(
            "RUN-REPORT lane=dispatch exit=0 wall=80s budget=3600s verdict=OK dir={}\n",
            step_dir.display()
        );
        record_step_directory(&plan, "R", "dispatch", &report)
            .expect("recorded before interruption");
        fs::write(step_dir.join("run-report.txt"), &report).expect("driver report");
        recover_step_directory(&plan, "R").expect("existing directory remains recorded");
        let reply = json!({"bytes":5,"sha256":"digest-2"});
        record_settlement(&plan, "alpha", "R", &reply).expect("settle reply");
        let path = super::reservation_path(fixture.path(), "R");
        let before = super::read_reservation(&path)
            .expect("read")
            .expect("record");
        let final_record = super::super::publish_interrupted_phase(
            &path,
            &before,
            true,
            &json!({"state":"complete"}),
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("terminal phase");
        assert_eq!(final_record["phase"], "settled");
        assert_eq!(final_record["rounds"][0]["phase"], "settled");
        assert_eq!(final_record["rounds"][0]["reply"], reply);
        assert_eq!(final_record["rounds"][0]["driver_dir"], json!(step_dir));
    }

    /// ´test:unit:interrupted-unreadable-reply-fails-round-before-reservation´
    #[test]
    fn interrupted_unreadable_reply_fails_round_before_reservation() {
        let (fixture, plan) = settlement_fixture(true);
        let path = super::reservation_path(fixture.path(), "R");
        let error = crate::error::LaneError::input("readback", "reply is absent");
        super::record_failed_settlement(&plan, "R", &error).expect("round failure");
        let before = super::read_reservation(&path)
            .expect("read")
            .expect("record");
        let final_record = super::super::publish_interrupted_phase(
            &path,
            &before,
            true,
            &json!({"state":"complete"}),
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("terminal phase");
        assert_eq!(final_record["phase"], "failed");
        assert_eq!(final_record["rounds"][0]["phase"], "failed");
        assert!(
            final_record["rounds"][0]["settlement_error"]
                .as_str()
                .expect("reason")
                .contains("readback")
        );
    }
}

fn clear_round_evidence(saved: &mut Value) -> Result<(), LaneError> {
    for field in [
        "driver_entry_pid",
        "driver_entry_start",
        "helper_parent_pid",
        "helper_parent_start",
        "helper_pid",
        "helper_start",
        "pre_driver_failure",
        "driver_end",
        "helper_end",
        "readback_end",
        "reaping",
        "reaping_recovery",
        "interrupted_settlement",
    ] {
        saved
            .as_object_mut()
            .ok_or_else(|| LaneError::input("round-record", "reservation is not an object"))?
            .remove(field);
    }
    Ok(())
}

#[cfg(test)]
mod generation_tests {
    /// ´test:unit:resume-clears-prior-round-reaping-and-socket-evidence´
    #[test]
    fn resume_clears_prior_round_reaping_and_socket_evidence() {
        let mut saved = serde_json::json!({"phase":"preparing","active_round":"next","reaping":{"state":"empty"},"reaping_recovery":{"state":"collected"},"interrupted_settlement":{"socket_removal_state":"confirmed-absent"}});
        super::clear_round_evidence(&mut saved).expect("clear prior generation");
        for field in ["reaping", "reaping_recovery", "interrupted_settlement"] {
            assert!(saved.get(field).is_none(), "{field}");
        }
        assert_eq!(saved["phase"], "preparing");
        assert_eq!(saved["active_round"], "next");
    }
}
