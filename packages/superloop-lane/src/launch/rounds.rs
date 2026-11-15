//! Choose continuation after failed rounds and settle each reply of record.

use std::fs::OpenOptions;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::fcntl::{RenameFlags, renameat2};
use nix::unistd::{Gid, Uid, fchown};
use serde_json::{Value, json};

use super::{
    LaunchRequest, admission, entry_argv_round, launch_environment, lock_mailbox,
    lock_run_preparation, persist_settlement_field, publish_reservation, read_reservation,
    reservation_path,
};
use crate::error::LaneError;
use crate::plan::Plan;
use crate::{build, home, load_plan};

fn round_evidence_uid(plan: &Plan) -> Result<u32, LaneError> {
    if home::private_is_active() {
        crate::plan::loop_uid(&plan.document)
    } else {
        Ok(Uid::effective().as_raw())
    }
}

fn held_round_directory(path: &Path, loop_uid: u32) -> Result<std::fs::File, LaneError> {
    let root = home::private_runs_path()
        .ok_or_else(|| LaneError::input("verified-prefix", "private runs anchor is absent"))?;
    home::pin_loop_round(&root, path, Uid::effective().as_raw(), loop_uid).map(std::fs::File::from)
}

fn thread_evidence(
    dir: &Path,
    loop_uid: u32,
) -> Result<Option<(std::fs::File, usize, usize)>, LaneError> {
    let path = dir.join("events.jsonl");
    let pinned = if home::private_is_active() {
        Some(held_round_directory(dir, loop_uid)?)
    } else {
        None
    };
    let opened = pinned.as_ref().map_or_else(
        || {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
        },
        |directory| {
            nix::fcntl::openat2(
                directory,
                "events.jsonl",
                nix::fcntl::OpenHow::new()
                    .flags(
                        nix::fcntl::OFlag::O_RDONLY
                            | nix::fcntl::OFlag::O_CLOEXEC
                            | nix::fcntl::OFlag::O_NONBLOCK,
                    )
                    .resolve(
                        nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                            | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                    ),
            )
            .map(std::fs::File::from)
            .map_err(std::io::Error::from)
        },
    );
    let parent = pinned
        .as_ref()
        .map_or_else(|| std::fs::symlink_metadata(dir), std::fs::File::metadata)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "round-thread",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    if !meta.is_file() || meta.uid() != parent.uid() {
        return Err(LaneError::input(
            "round-thread",
            "events are not directory-owned regular evidence",
        ));
    }
    let size = usize::try_from(meta.len())
        .map_err(|_| LaneError::input("round-thread", "event size exceeds addressable range"))?;
    let start = if let Some(directory) = &pinned {
        lane_lifecycle::validated_event_boundaries_at(directory, size, loop_uid)
            .map_err(|error| LaneError::input("round-thread", error.to_string()))?
            .current_start
    } else {
        *lane_lifecycle::validated_event_boundaries(dir, size)
            .map_err(|error| LaneError::input("round-thread", error.to_string()))?
            .last()
            .ok_or_else(|| LaneError::input("round-thread", "step event boundary is absent"))?
    };
    Ok(Some((file, size, start)))
}

fn step_event_thread(
    backend: crate::settings::BoxBackend,
    dir: &Path,
    loop_uid: u32,
) -> Result<String, LaneError> {
    observed_step_thread(backend, dir, loop_uid)?.ok_or_else(|| {
        LaneError::input(
            "round-thread",
            match backend {
                crate::settings::BoxBackend::Codex => "step has no thread.started event",
                crate::settings::BoxBackend::Claude => "step has no system.init event",
            },
        )
    })
}

fn observed_step_thread(
    backend: crate::settings::BoxBackend,
    dir: &Path,
    loop_uid: u32,
) -> Result<Option<String>, LaneError> {
    let Some((mut file, size, start)) = thread_evidence(dir, loop_uid)? else {
        return Ok(None);
    };
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
            && let Some(actual) = crate::container_helper::session_event(backend, &line)?
        {
            if observed.as_deref().is_some_and(|prior| prior != actual) {
                return Err(LaneError::input(
                    "round-thread",
                    "step contains two thread ids",
                ));
            }
            observed = Some(actual);
        }
        line.clear();
    }
    Ok(observed)
}

/// Preserve observed identity first, then the actual requested resume, never a prior fresh thread.
pub(super) fn failed_thread(
    plan: &Plan,
    record: &Value,
    round: &Value,
) -> Result<Value, LaneError> {
    let directory = recorded_step_dir(plan, record, round)?;
    let observed = observed_step_thread(
        crate::settings::BoxBackend::from_plan(&plan.document)?,
        &directory,
        round_evidence_uid(plan)?,
    )?;
    if let Some(id) = observed {
        return Ok(json!({"id":id,"provenance":"observed"}));
    }
    let requested = round.get("requested_thread").unwrap_or_else(|| {
        if round["step"] != "dispatch" && round["fresh_thread"] != true {
            &record["thread_id"]
        } else {
            &Value::Null
        }
    });
    if !requested.is_null()
        && !requested
            .as_str()
            .is_some_and(crate::container_helper::valid_thread)
    {
        return Err(LaneError::input(
            "round-thread",
            "requested thread is malformed",
        ));
    }
    Ok(
        json!({"id":requested,"provenance":if requested.is_string() { "requested" } else { "absent" }}),
    )
}

/// A completed settlement without a reply owes a thread decision, regardless of end reason.
pub(crate) fn failed_without_reply(round: &Value) -> bool {
    round["phase"] == "failed" && round["reply"].is_null()
}

fn finalized_failed_round(round: &Value) -> bool {
    failed_without_reply(round)
        && round["settle_attempts"]
            .as_array()
            .and_then(|rows| rows.last())
            .is_some_and(|attempt| attempt["phase"] == "complete")
}

pub(crate) fn failed_continuation(record: &Value) -> bool {
    record["phase"] == "settled"
        && record["readback_end"] == "completed"
        && record["rounds"]
            .as_array()
            .and_then(|rows| rows.last())
            .is_some_and(|round| {
                round["step"].is_string()
                    && round["step"] == record["active_round"]
                    && finalized_failed_round(round)
            })
        && (super::reaping::recovery_verdict(record).is_ok()
            || super::settle::completed_failed_round(record))
}

/// Explicit selection after a finalized round without a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadChoice {
    Fresh,
    Resume,
}

impl ThreadChoice {
    pub(crate) fn parse(flag: &str) -> Result<Self, LaneError> {
        match flag {
            "--fresh-thread" => Ok(Self::Fresh),
            "--resume-thread" => Ok(Self::Resume),
            _ => Err(LaneError::input("round-choice", "unknown thread choice")),
        }
    }
    pub(crate) const fn flag(self) -> &'static str {
        match self {
            Self::Fresh => "--fresh-thread",
            Self::Resume => "--resume-thread",
        }
    }
}

fn recorded_choice_thread(record: &Value) -> &Value {
    record["rounds"]
        .as_array()
        .and_then(|rows| rows.last())
        .and_then(|round| round.get("thread"))
        .map_or(&record["thread_id"], |thread| &thread["id"])
}

fn require_thread_choice(record: &Value, choice: Option<ThreadChoice>) -> Result<bool, LaneError> {
    if !failed_continuation(record) {
        if choice.is_some() {
            return Err(LaneError::input(
                "round-choice",
                "no failed-round choice is owed; omit --fresh-thread and --resume-thread",
            ));
        }
        return Ok(false);
    }
    let identity = recorded_choice_thread(record);
    if !identity.is_null()
        && !identity
            .as_str()
            .is_some_and(crate::container_helper::valid_thread)
    {
        return Err(LaneError::input(
            "round-thread",
            "recorded thread is malformed",
        ));
    }
    let thread = identity.as_str();
    let step = record["active_round"].as_str().unwrap_or("absent");
    match choice {
        Some(ThreadChoice::Fresh) => Ok(true),
        Some(ThreadChoice::Resume) if thread.is_some() => Ok(false),
        Some(ThreadChoice::Resume) => Err(LaneError::input(
            "round-choice",
            format!(
                "failed round {step}: --resume-thread unavailable: no recorded thread; choose --fresh-thread"
            ),
        )),
        None => Err(LaneError::input(
            "round-choice",
            format!(
                "failed round {step}: recorded thread {}; choose --fresh-thread or --resume-thread{}",
                thread.unwrap_or("absent"),
                if thread.is_none() {
                    "; only --fresh-thread is available"
                } else {
                    ""
                }
            ),
        )),
    }
}

fn choice_preview(
    record: &Value,
    choice: Option<ThreadChoice>,
    files: &Value,
    step: &str,
) -> Value {
    if !failed_continuation(record) {
        return Value::Null;
    }
    let round = record["rounds"].as_array().and_then(|rows| rows.last());
    let letter = record["mail"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["step"] == step))
        .and_then(|row| row.get("inbox_name"));
    json!({"next_round":step,"fresh_letter":letter,"failed_round":record["active_round"],"recorded_thread":recorded_choice_thread(record),
        "provenance":round.map(|round| &round["thread"]["provenance"]),
        "selection":choice.map(ThreadChoice::flag),"thread_files":files,
        "fresh_prompt":"the new round's bound letter; no old thread conversation (ordinary vendor startup instructions still apply)",
        "choice_owed":true,"consumed":false})
}

pub(crate) fn fresh_thread_round(record: &Value) -> bool {
    matches!(
        record["phase"].as_str(),
        Some("preparing" | "started" | "failed")
    ) && record["rounds"]
        .as_array()
        .and_then(|rows| rows.split_last())
        .is_some_and(|(round, prior)| {
            prior.last().is_some_and(finalized_failed_round)
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
        && finalized_failed_round(&rounds[index - 1]);
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
    let meta = if home::private_is_active() {
        held_round_directory(&path, crate::plan::loop_uid(&plan.document)?)?.metadata()
    } else {
        std::fs::symlink_metadata(&path)
    }
    .map_err(|error| LaneError::input("round-directory", format!("{}: {error}", path.display())))?;
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
    let actual = step_event_thread(
        crate::settings::BoxBackend::from_plan(&plan.document)?,
        &directory,
        round_evidence_uid(plan)?,
    )?;
    if let Some(expected) = record["thread_id"]
        .as_str()
        .filter(|_| !fresh_thread_round(record))
    {
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
    let stopped = round["step"]
        .as_str()
        .is_some_and(|step| super::steering::stop_brief(record, step).is_some());
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
    if fresh_thread_round(record) {
        return Ok(());
    }
    if failed_continuation(record) {
        let round = record["rounds"]
            .as_array()
            .and_then(|rows| rows.last())
            .ok_or_else(|| LaneError::input("round-record", "last round absent"))?;
        let observed = failed_thread(plan, record, round)?;
        if round.get("thread").is_some_and(|saved| saved != &observed)
            || (observed["id"].is_string() && record["thread_id"] != observed["id"])
        {
            return Err(LaneError::input(
                "round-thread",
                "failed thread evidence differs from settlement",
            ));
        }
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
                .find(|round| round["phase"] == "settled" || finalized_failed_round(round))
        })
        .ok_or_else(|| LaneError::input("round-record", "settled round is absent"))?;
    let actual = if finalized_failed_round(round) {
        failed_thread(plan, record, round)?["id"]
            .as_str()
            .ok_or_else(|| LaneError::input("round-thread", "failed round has no thread"))?
            .to_owned()
    } else {
        step_event_thread(
            crate::settings::BoxBackend::from_plan(&plan.document)?,
            &recorded_step_dir(plan, record, round)?,
            round_evidence_uid(plan)?,
        )?
    };
    if actual != saved {
        return Err(LaneError::input(
            "round-thread",
            format!("driver thread {actual} differs from reservation {saved}"),
        ));
    }
    Ok(())
}

type InspectionSelection<'a> = (&'a Path, Option<(&'a str, u64)>, Option<&'a str>);

/// Parse the operation body before receiving round inspection custody.
/// # Errors
/// Refuses an incomplete vector, relative home or malformed round evidence selection.
pub(super) fn parse_private_inspect(args: &[String]) -> Result<InspectionSelection<'_>, LaneError> {
    let [mode, loop_name, run, option, owner_home, rest @ ..] = args else {
        return Err(LaneError::input(
            "round-private",
            "private round inspection is incomplete",
        ));
    };
    if mode != "_inspect-round"
        || option != "--owner-home"
        || !crate::valid_run_name(run)
        || loop_home::validate_name(loop_name).is_err()
    {
        return Err(LaneError::input(
            "round-private",
            "private round inspection vector is malformed",
        ));
    }
    let home = Path::new(owner_home);
    if !home.is_absolute() {
        return Err(LaneError::input(
            "verified-prefix",
            "private launch has duplicate or non-absolute owner home",
        ));
    }
    let mut rollback_nonce = None;
    let evidence = match rest {
        [] => None,
        [option, nonce] if option == "--rollback" => {
            if nonce.len() != 64
                || !nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(LaneError::input(
                    "round-private",
                    "rollback nonce malformed",
                ));
            }
            rollback_nonce = Some(nonce.as_str());
            None
        }
        [record_option, step, budget_option, seconds]
            if record_option == "--record" && budget_option == "--budget" =>
        {
            super::letters::valid_step(step)?;
            Some((
                step.as_str(),
                seconds
                    .parse::<u64>()
                    .map_err(|_| LaneError::input("round-private", "budget is malformed"))?,
            ))
        }
        _ => {
            return Err(LaneError::input(
                "round-private",
                "private round evidence form is malformed",
            ));
        }
    };
    Ok((home, evidence, rollback_nonce))
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
    private_inspect_action(owner_home, loop_name, run, evidence, None)
}

pub(crate) fn private_inspect_action(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    evidence: Option<(&str, u64)>,
    rollback_nonce: Option<&str>,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    if let Some(nonce) = rollback_nonce {
        return rollback::private_cleanup(loop_name, run, nonce);
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
    let record = inspection_record(root, run)?;
    check_identity(&plan, &record)?;
    inspect_loaded_round(&plan, &record, evidence)
}

fn inspection_record(root: &Path, run: &str) -> Result<Value, LaneError> {
    read_reservation(&reservation_path(root, run))?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))
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
        let request = prepare_round_request(plan, record, step, budget)?;
        let bytes = super::client_environment_bytes(
            &plan.driver_dir,
            &runs_root,
            &runtime_dir,
            loop_uid,
            false,
        )?;
        let temporary = record
            .get("round_rollback")
            .map(|_| rollback::nonce(record))
            .transpose()?
            .map(|nonce| format!(".runtime.env-{nonce}"));
        super::publish_client_environment_named(&runtime_dir, loop_uid, &bytes, temporary)?;
        request.publish()?;
    }
    let thread_files = if failed_continuation(record) {
        super::thread_files::inspect(plan, recorded_choice_thread(record).as_str())?
    } else {
        Value::Null
    };
    Ok(
        json!({"schema":1,"command":"inspect-round","thread_files":thread_files,"thread_id":record["thread_id"],"home":plan.home,"worker_uid":record["worker_uid"]}),
    )
}

#[cfg(test)]
pub(super) fn publish_round_request(
    plan: &Plan,
    record: &Value,
    step: &str,
    budget: u64,
) -> Result<(), LaneError> {
    prepare_round_request(plan, record, step, budget)?.publish()
}

fn request_text(plan: &Plan, record: &Value, step: &str, budget: u64) -> Result<String, LaneError> {
    let binding = record["mail"]
        .as_array()
        .and_then(|bindings| bindings.iter().find(|binding| binding["step"] == step))
        .ok_or_else(|| {
            LaneError::input("mail-delivery", "round request lacks its delivery binding")
        })?;
    Ok(json!({
        "schema":1,"step":step,"budget_seconds":budget,"mail":binding,
        "thread_id":if fresh_thread_round(record) { Value::Null } else { record["thread_id"].clone() },"home":plan.home,"worker_uid":record["worker_uid"]
    })
    .to_string())
}

fn prepare_round_request(
    plan: &Plan,
    record: &Value,
    step: &str,
    budget: u64,
) -> Result<PreparedRoundRequest, LaneError> {
    let directory = if home::private_is_active() {
        held_round_directory(&plan.driver_dir, crate::plan::loop_uid(&plan.document)?)?
    } else {
        let parent = std::fs::symlink_metadata(&plan.driver_dir)
            .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
        if !parent.is_dir() || parent.file_type().is_symlink() {
            return Err(LaneError::input(
                "round-evidence",
                "run directory is not a directory",
            ));
        }
        std::fs::File::open(&plan.driver_dir)
            .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?
    };
    let parent = directory
        .metadata()
        .map_err(|error| LaneError::operation("round-evidence", error.to_string()))?;
    let name = format!("round-launch-{step}.json");
    let temporary = if record.get("round_rollback").is_some() {
        format!(".round-launch-{step}-{}.tmp", rollback::nonce(record)?)
    } else {
        format!(".round-launch-{step}-{}.tmp", std::process::id())
    };
    let path = plan.driver_dir.join(&temporary);
    let body = request_text(plan, record, step, budget)?;
    for leaf in [&name, &temporary] {
        match nix::sys::stat::fstatat(
            &directory,
            leaf.as_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => {}
            Ok(_) => {
                return Err(LaneError::input(
                    "round-evidence",
                    format!("{leaf} already exists"),
                ));
            }
            Err(error) => return Err(LaneError::input("round-evidence", error.to_string())),
        }
    }
    Ok(PreparedRoundRequest {
        directory,
        name,
        temporary,
        path,
        parent,
        bytes: body.into_bytes(),
    })
}

struct PreparedRoundRequest {
    directory: std::fs::File,
    name: String,
    temporary: String,
    path: PathBuf,
    parent: std::fs::Metadata,
    bytes: Vec<u8>,
}

impl PreparedRoundRequest {
    fn publish(self) -> Result<(), LaneError> {
        let Self {
            directory,
            name,
            temporary,
            path,
            parent,
            bytes,
        } = self;
        let mut file = nix::fcntl::openat(
            &directory,
            temporary.as_str(),
            nix::fcntl::OFlag::O_WRONLY
                | nix::fcntl::OFlag::O_CREAT
                | nix::fcntl::OFlag::O_EXCL
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .map(std::fs::File::from)
        .map_err(std::io::Error::from)
        .map_err(|error| {
            LaneError::operation("round-evidence", format!("{}: {error}", path.display()))
        })?;
        let result = (|| {
            file.write_all(&bytes)
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
        })();
        if result.is_err() {
            let held = file.metadata();
            let named = nix::sys::stat::fstatat(
                &directory,
                temporary.as_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            );
            if held.as_ref().is_ok_and(|held| {
                named
                    .as_ref()
                    .is_ok_and(|named| held.dev() == named.st_dev && held.ino() == named.st_ino)
            }) {
                let _removed = nix::unistd::unlinkat(
                    &directory,
                    temporary.as_str(),
                    nix::unistd::UnlinkatFlags::NoRemoveDir,
                );
            }
        }
        result
    }
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
        let actual = step_event_thread(
            crate::settings::BoxBackend::from_plan(&plan.document)?,
            &directory,
            round_evidence_uid(plan)?,
        )?;
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
        let actual = step_event_thread(
            crate::settings::BoxBackend::from_plan(&plan.document)?,
            &step_dir?,
            round_evidence_uid(plan)?,
        )?;
        if let Some(saved) = record["thread_id"]
            .as_str()
            .filter(|_| round["fresh_thread"] != true)
        {
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
        let acknowledgments = Vec::new();
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
    let fresh = require_thread_choice(record, request.thread_choice)?;
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
        thread
            .filter(|_| !fresh)
            .map(|thread| (thread, directory.as_path(), selection)),
        record["mail"]
            .as_array()
            .and_then(|bindings| bindings.iter().find(|binding| binding["step"] == step)),
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
    let mut round = json!({"step":step,"budget_seconds":request.budget,"mail":letter,"phase":"running","driver_dir":directory,"ended_by":null,"in_round_letters":[]});
    if require_thread_choice(record, request.thread_choice)? {
        round["fresh_thread"] = json!(true);
    }
    round["thread_choice"] = json!(if request.thread_choice == Some(ThreadChoice::Fresh) {
        "fresh"
    } else {
        "resume"
    });
    round["requested_thread"] = if request.thread_choice == Some(ThreadChoice::Fresh) {
        Value::Null
    } else {
        record["thread_id"].clone()
    };
    Ok(round)
}

/// Reconstruct the next round without publishing any reservation field.
pub(crate) fn preflight_record(
    run_dir: &Path,
    record: &Value,
    step: &str,
    budget: u64,
    choice: Option<ThreadChoice>,
) -> Result<Value, LaneError> {
    let mut request = LaunchRequest::parse(&[
        record["loop"]
            .as_str()
            .ok_or_else(|| LaneError::input("round-record", "loop is absent"))?
            .into(),
        record["run"]
            .as_str()
            .ok_or_else(|| LaneError::input("round-record", "run is absent"))?
            .into(),
        "--round".into(),
        step.into(),
        "--budget".into(),
        budget.to_string(),
    ])?;
    request.thread_choice = choice;
    let binding = record["mail"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["step"] == step))
        .ok_or_else(|| LaneError::input("mail-delivery", "active mail binding absent"))?;
    let directory = if require_thread_choice(record, choice)? {
        super::planned_step_dir_at(run_dir, step)?
    } else {
        prior_round_dir(record)?.to_path_buf()
    };
    let round = continuation_round(record, &request, &directory, binding)?;
    let mut next = record.clone();
    next["rounds"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("round-state", "rounds absent"))?
        .push(round);
    next["phase"] = json!("preparing");
    next["active_round"] = json!(step);
    next["letter_source"] = json!(super::steering::evidence_at(run_dir, step));
    Ok(next)
}

/// Validate publication inputs against the prospective reservation only.
pub(crate) fn validate_preflight_record(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    podman: &Path,
    record: &Value,
    step: &str,
    budget: u64,
) -> Result<(), LaneError> {
    let (plan, _) = super::pinned_plan_from_record(owner_home, loop_name, run, podman, record)?;
    let _letter = super::steering::retained_letter(&plan, record)?;
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let (runs, runtime) =
        super::pin_runtime_dir(&plan.driver_dir, Uid::effective().as_raw(), loop_uid)?;
    let _request = prepare_round_request(&plan, record, step, budget)?;
    let _environment =
        super::client_environment_bytes(&plan.driver_dir, &runs, &runtime, loop_uid, false)?;
    Ok(())
}

/// Preview or run the next round, honoring explicit failed-round thread choices.
///
/// # Errors
///
/// Refuses a missing choice or letter, unsettled run, changed identity or failed driver.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
#[doc(hidden)]
pub fn resume_with_host_root(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
    on_failure: &mut dyn FnMut(&Value),
    lane_bin: &Path,
    stop_bound: std::time::Duration,
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
        stop_bound,
    )
}

pub(super) fn interrupted_round(record: &Value, step: &str) -> bool {
    matches!(record["phase"].as_str(), Some("preparing" | "started"))
        && record["active_round"] == step
        && record["rounds"].as_array().is_some_and(|rounds| {
            rounds.len() > 1
                && rounds.last().is_some_and(|round| {
                    round["step"] == step
                        && step != "dispatch"
                        && (round["phase"] == "running"
                            || (round["phase"] == "awaiting-settlement"
                                && record["driver_end"]["state"] == "completed"
                                && record["driver_end"]["successful"] == true
                                && record["helper_end"]["successful"] != false))
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
        std::time::Duration::from_secs(90),
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
    stop_bound: std::time::Duration,
) -> Result<Value, LaneError> {
    if request.backend.is_some() {
        return Err(LaneError::input(
            "round-selection",
            "resume cannot change the recorded backend",
        ));
    }
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
    plan.retain_workspace(&before_reconciliation["plan"])?;
    plan.retain_attempt_wall(&before_reconciliation["plan"])?;
    super::compare_pinned_plan(&before_reconciliation["plan"], &plan.document)?;
    if recovering {
        if request.thread_choice.is_some() {
            return Err(LaneError::input(
                "round-choice",
                "interrupted recovery starts no next round; omit --fresh-thread and --resume-thread",
            ));
        }
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
    let record = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("round-record", "reservation vanished"))?;
    let letter_reconciliation: Vec<Value> = Vec::new();
    ensure_not_rotated(&record, &request.run)?;
    if record["phase"] != "settled" || record.get("letters").is_some() {
        return Err(LaneError::input(
            "round-state",
            format!(
                "resume requires a settled mail reservation; run settle {} {} --round STEP --dry-run and apply its preview_sha256 with --expect-digest; reconcile legacy runs at cutover",
                request.loop_name, request.run
            ),
        ));
    }
    let choice_result = require_thread_choice(&record, request.thread_choice);
    if let Err(error) = &choice_result
        && (!request.dry_run || request.thread_choice.is_some())
    {
        return Err(LaneError::input(error.kind, error.detail.clone()));
    }
    let fresh = choice_result.as_ref().copied().unwrap_or(false);
    super::compare_pinned_plan(&record["plan"], &plan.document)?;
    // The entry probe precedes the private mail binding, so a mismatched pair
    // refuses before any child touches the run (´req:superlooplane:entry-version-before-reservation´).
    let entry_program = settings
        .entry_bin
        .as_deref()
        .ok_or_else(|| LaneError::input("round-program", "entry_bin is absent"))?;
    let environment = launch_environment(owner_home)?;
    crate::pinned::owner_executable(entry_program, caller)?;
    super::entry_interface(entry_program, owner_home, &environment)?;
    let entry = record["mail"]
        .as_array()
        .and_then(|bindings| bindings.iter().find(|binding| binding["step"] == step))
        .ok_or_else(|| {
            LaneError::input(
                "mail-delivery",
                "step has no verified delivery binding; bind-mail before resume",
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
    let delivery = entry["delivery"]
        .as_str()
        .ok_or_else(|| LaneError::input("mail-delivery", "delivery instant absent"))?;
    let verified = super::steering::verify(
        owner_home,
        &plan,
        &record,
        step,
        delivery,
        true,
        (host_root, root_uid, lane_bin),
    )?;
    if &verified != entry {
        return Err(LaneError::input(
            "mail-delivery",
            "delivery differs from the pinned reservation",
        ));
    }
    let letter_name = entry["inbox_name"]
        .as_str()
        .ok_or_else(|| LaneError::input("mail-delivery", "inbox name absent"))?
        .to_owned();
    let selection = selected_round_model(&record, b"")?;
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
    let verified_home = home::verify_host_prefix_from(host_root, owner_home, caller, root_uid)?;
    let verified_runs =
        home::verify_host_launch_root(host_root, owner_home, &root, caller, root_uid)?;
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
    let thread_choice = choice_preview(
        &record,
        request.thread_choice,
        &inspected["thread_files"],
        step,
    );
    if let Err(error) = choice_result {
        return Err(LaneError::input(
            error.kind,
            format!("{}; preview={thread_choice}", error.detail),
        ));
    }
    let thread = inspected["thread_id"].as_str().filter(|_| !fresh);
    let (prior_dir, argv) = continuation_argv(&plan, &record, driver, request, &selection)?;
    let helper_preflight = super::preflight_helper_round(
        request,
        &plan,
        &environment,
        (owner_home, &verified_home),
        (&root, &verified_runs),
        lane_bin,
    )?;
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
            |thread| {
                crate::container_helper::resume_box_vector(
                    crate::settings::BoxBackend::from_plan(&plan.document)?,
                    &saved_box,
                    thread,
                )
            },
        )?;
        return Ok(
            json!({"schema":1,"command":"launch","dry_run":true,"round":step,
                "budget_seconds":request.budget,"letter":letter_name,
                "letter_reconciliation_preview":letter_reconciliation,
                "helper_preflight":helper_preflight,"proxy_service":proxy_service,"thread_choice":thread_choice,
                "thread_id":thread,"home":plan.home,"worker_uid":worker,
                "invocation":{"program":entry_program,"argv":argv},"box_command":box_command,
                "changed":false,"wall_seconds":began.elapsed().as_secs_f64()}),
        );
    }
    let _lease = lock_run_preparation(&root, &request.run, caller)?;
    if !cfg!(test) {
        super::reaping::ensure_scoped_new_launch()?;
    }
    let (nonce, published) = {
        let _mailbox = lock_mailbox(&root, &request.run, caller)?;
        let (mut saved, before) = super::read_reservation_raw(&path, true)?
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
        saved["letter_source"] = json!(super::steering::evidence(&plan, step));
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
        let request_bytes = format!("{}\n", request_text(&plan, &saved, step, request.budget)?);
        let nonce = rollback::prepare(&mut saved, &before, &request_bytes)?;
        rollback::snapshot_sockets(&mut saved, &plan)?;
        let published = publish_reservation(&path, &saved);
        let published = match rollback::publication(&path, &before, published) {
            rollback::Publication::Unchanged(error) => return Err(error),
            rollback::Publication::Attempt(result) => result,
        };
        (nonce, published)
    };
    let inspect_record = vec![
        "unshare".into(),
        exe_word.clone(),
        "_inspect-round".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        owner_home.display().to_string(),
        "--record".into(),
        step.into(),
        "--budget".into(),
        request.budget.to_string(),
    ];
    let host = rollback::Host {
        path: &path,
        nonce: &nonce,
        program: &podman,
        environment: &environment,
        owner_home,
        home: &verified_home,
        root: &root,
        runs: &verified_runs,
        argv: vec![
            "unshare".into(),
            exe_word.clone(),
            "_inspect-round".into(),
            request.loop_name.clone(),
            request.run.clone(),
            "--owner-home".into(),
            owner_home.display().to_string(),
            "--rollback".into(),
            nonce.clone(),
        ],
    };
    let mut inspector = build::LiveChild::default();
    let mut helper_receipt = build::LiveChild::default();
    if let Err(error) = published {
        return Err(host.refuse(error, (&inspector, &helper_receipt)));
    }
    let recorded = build::inspect_with_receipt(
        &podman,
        &inspect_record,
        &environment,
        owner_home,
        &verified_home,
        &root,
        &verified_runs,
        &mut inspector,
    );
    if let Err(error) = recorded {
        return Err(host.refuse(error, (&inspector, &helper_receipt)));
    }
    let started = (|| {
        persist_settlement_field(&path, "helper_spawn_state", json!("starting"))?;
        super::start_helper_observed(
            request,
            &plan,
            owner_home,
            &environment,
            &verified_home,
            &root,
            &verified_runs,
            lane_bin,
            &mut helper_receipt,
            |pid, start| record_helper_parent(&path, pid, start),
        )
    })();
    let (mut helper, helper_start, helper_stderr) = match started {
        Ok(started) => started,
        Err(error) => return Err(host.refuse(error, (&inspector, &helper_receipt))),
    };
    let intent = (|| {
        let record = read_reservation(&path)?.ok_or_else(|| {
            LaneError::input("helper-session", "protected run reservation is absent")
        })?;
        let bound = crate::container_helper::host_launch_bound(&record)?;
        rollback::intent(&path, &nonce)?;
        Ok(bound)
    })();
    let launch_bound = match intent {
        Ok(bound) => bound,
        Err(error) => {
            let _cancel =
                super::stop_helper_with_bound(&mut helper, &plan, &verified_runs, stop_bound);
            let _stop = super::stop_observer(&mut helper);
            if helper_receipt.absent() {
                let _stderr = helper_stderr.join();
            }
            return Err(host.refuse(error, (&inspector, &helper_receipt)));
        }
    };
    let mut driver_started = false;
    let mut child_end = build::ChildEnd::default();
    let result = build::run_checked_with_pid(
        entry_program,
        argv,
        &environment,
        owner_home,
        launch_bound,
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
            rollback::dispatched(&path, &nonce)?;
            Ok(())
        },
    );
    let step_directory = result.as_ref().map_or(Ok(()), |output| {
        record_step_directory(&plan, &request.run, step, output)
    });
    persist_settlement_field(
        &path,
        "driver_end",
        super::driver_completion(&result, driver_started, &child_end),
    )?;
    let helper_stop = super::stop_helper_with_bound(&mut helper, &plan, &verified_runs, stop_bound);
    if let Some(status) = helper
        .try_wait()
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?
    {
        persist_settlement_field(
            &path,
            "helper_end",
            super::helper_stopped_end(helper.id(), helper_start, status, &helper_stop),
        )?;
    }
    super::helper_stop_with_stderr(helper_stop.map(|_| ()), &mut helper, helper_stderr)?;
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
    let report = json!({"schema":1,"command":"launch","dry_run":false,"round":step,"round_dir":round_dir,"budget_seconds":request.budget,"letter":letter_name,"letter_reconciliation":letter_reconciliation,"thread_id":thread,"driver_report":driver_report,"settlement":settlement,"credential_publication":publication,"wall_seconds":began.elapsed().as_secs_f64()});
    super::report::finish_with_fallback(
        &verified_runs,
        &request.run,
        Some(step),
        report,
        on_failure,
    )
}

fn record_helper_parent(path: &Path, pid: u32, start: u64) -> Result<(), LaneError> {
    let root = path
        .parent()
        .ok_or_else(|| LaneError::input("helper-start", "root absent"))?;
    let run = path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix(".reservation-"))
        .and_then(|s| s.strip_suffix(".json"))
        .ok_or_else(|| LaneError::input("helper-start", "reservation name differs"))?;
    let _lock = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut saved = read_reservation(path)?.ok_or_else(|| {
        LaneError::input(
            "helper-start",
            "reservation vanished before parent identity",
        )
    })?;
    saved["helper_parent_pid"] = json!(pid);
    saved["helper_parent_start"] = json!(start);
    saved["helper_spawn_state"] = json!("running");
    publish_reservation(path, &saved)
}

/// Live-only rollback. Crash recovery deliberately does not consume this record yet.
pub(crate) mod rollback {
    use super::*;
    use std::fmt::Write as _;
    use std::os::fd::OwnedFd;

    #[allow(clippy::needless_pass_by_value)]
    fn refusal(detail: impl ToString) -> LaneError {
        LaneError::operation("round-rollback", detail.to_string())
    }
    pub(super) enum Publication {
        Unchanged(LaneError),
        Attempt(Result<(), LaneError>),
    }

    // Called under the mailbox lock. An fsync failure can follow rename, so an
    // error alone cannot prove that publication left the reservation untouched.
    pub(super) fn publication(
        path: &Path,
        before: &[u8],
        result: Result<(), LaneError>,
    ) -> Publication {
        match result {
            Err(mut error)
                if super::super::read_reservation_raw(path, true)
                    .ok()
                    .flatten()
                    .is_some_and(|(_, bytes)| bytes == before) =>
            {
                error
                    .detail
                    .push_str("; unchanged: preparing reservation was not published");
                Publication::Unchanged(error)
            }
            result => Publication::Attempt(result),
        }
    }

    pub fn nonce(record: &Value) -> Result<&str, LaneError> {
        let value = record["round_rollback"]["nonce"]
            .as_str()
            .ok_or_else(|| refusal("attempt nonce absent"))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refusal("attempt nonce malformed"));
        }
        Ok(value)
    }
    /// The owner-protected raw bytes are authoritative. This is a consistency handle,
    /// not authentication: sixteen leading SHA-256 hex digits, following the default
    /// handle-size calculation in docs/spec/digests.md, for at most one million attempts.
    fn before_handle(bytes: &[u8]) -> String {
        execute_command::rubric::sha256_digest(bytes)[..16].to_owned()
    }

    pub(super) fn prepare(
        saved: &mut Value,
        before: &[u8],
        request: &str,
    ) -> Result<String, LaneError> {
        let mut random = [0_u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(refusal)?;
        let mut nonce = String::with_capacity(64);
        for byte in random {
            let _written = write!(nonce, "{byte:02x}");
        }
        let text = std::str::from_utf8(before).map_err(refusal)?;
        saved["round_rollback"] = json!({"schema":1,"nonce":nonce,"before":text,
            "before_bytes":before.len(),"before_sha256_prefix":before_handle(before),
            "request":request,"sockets":[]});
        saved
            .as_object_mut()
            .ok_or_else(|| refusal("reservation is not an object"))?
            .remove("dispatch_intent");
        // The existing publisher repeats this before its first temporary/write.
        let size = serde_json::to_vec(saved).map_err(refusal)?.len();
        if u64::try_from(size).map_err(refusal)? > super::super::MAX_RESERVATION_BYTES {
            return Err(refusal(format!(
                "preparing reservation is {size} bytes; limit is {} bytes",
                super::super::MAX_RESERVATION_BYTES
            )));
        }
        Ok(nonce)
    }
    fn before(record: &Value, expected: &str) -> Result<Vec<u8>, LaneError> {
        if nonce(record)? != expected || record["round_rollback"]["schema"] != 1 {
            return Err(refusal("attempt differs"));
        }
        if record.get("dispatch_intent").is_some() {
            return Err(refusal("dispatch-intent"));
        }
        if record["phase"] != "preparing" {
            return Err(refusal("reservation-state"));
        }
        let rollback = &record["round_rollback"];
        let bytes = rollback["before"]
            .as_str()
            .ok_or_else(|| refusal("before-image absent"))?
            .as_bytes();
        if rollback["before_bytes"] != bytes.len()
            || rollback["before_sha256_prefix"] != before_handle(bytes)
            || u64::try_from(bytes.len()).map_err(refusal)? > super::super::MAX_RESERVATION_BYTES
        {
            return Err(refusal("before-image differs"));
        }
        let prior = crate::placement::reservation_bytes(bytes, refusal)?;
        if prior["phase"] != "settled"
            || prior["loop"] != record["loop"]
            || prior["run"] != record["run"]
            || prior["worker_uid"] != record["worker_uid"]
        {
            return Err(refusal("before-image identity or phase differs"));
        }
        Ok(bytes.to_vec())
    }
    pub(super) fn intent(path: &Path, expected: &str) -> Result<(), LaneError> {
        let root = path
            .parent()
            .ok_or_else(|| refusal("reservation parent absent"))?;
        let record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        let run = record["run"]
            .as_str()
            .ok_or_else(|| refusal("run absent"))?;
        let _lock = lock_mailbox(root, run, Uid::effective().as_raw())?;
        let mut record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        let _before = before(&record, expected)?;
        record["dispatch_intent"] = json!({"nonce":expected});
        publish_reservation(path, &record)
    }
    pub(super) fn dispatched(path: &Path, expected: &str) -> Result<(), LaneError> {
        let record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        let root = path
            .parent()
            .ok_or_else(|| refusal("reservation parent absent"))?;
        let run = record["run"]
            .as_str()
            .ok_or_else(|| refusal("run absent"))?;
        let _lock = lock_mailbox(root, run, Uid::effective().as_raw())?;
        let mut record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        if record["dispatch_intent"]["nonce"] != expected
            || record["driver_entry_pid"].as_u64().is_none()
        {
            return Err(refusal("dispatch receipt differs"));
        }
        let fields = record
            .as_object_mut()
            .ok_or_else(|| refusal("reservation malformed"))?;
        fields.remove("round_rollback");
        fields.remove("dispatch_intent");
        publish_reservation(path, &record)
    }
    pub fn sockets(path: &Path, identities: Value) -> Result<(), LaneError> {
        let record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        if record.get("round_rollback").is_none() {
            return Ok(());
        }
        let root = path
            .parent()
            .ok_or_else(|| refusal("reservation parent absent"))?;
        let run = record["run"]
            .as_str()
            .ok_or_else(|| refusal("run absent"))?;
        let _lock = lock_mailbox(root, run, Uid::effective().as_raw())?;
        let mut record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        if record.get("round_rollback").is_none() || record.get("dispatch_intent").is_some() {
            return Ok(());
        }
        let _before = before(&record, nonce(&record)?)?;
        if record["helper_pid"] != std::process::id() {
            return Err(refusal("helper identity differs"));
        }
        record["round_rollback"]["sockets"] = identities;
        publish_reservation(path, &record)
    }
    #[cfg(test)]
    fn finish(
        primary: LaneError,
        path: &Path,
        expected: &str,
        receipts: (&build::LiveChild, &build::LiveChild),
        cleanup: impl FnOnce() -> Result<(), LaneError>,
    ) -> LaneError {
        let root = std::fs::File::open(path.parent().expect("root"))
            .expect("held root")
            .into();
        finish_at(primary, path, expected, receipts, &root, cleanup)
    }

    fn finish_at(
        mut primary: LaneError,
        path: &Path,
        expected: &str,
        receipts: (&build::LiveChild, &build::LiveChild),
        held: &OwnedFd,
        cleanup: impl FnOnce() -> Result<(), LaneError>,
    ) -> LaneError {
        let result = restore(path, expected, receipts, &primary.line(), held, cleanup);
        match result {
            Ok(()) => {
                let _written = write!(primary.detail, "; rollback: restored");
            }
            Err(error) => {
                let _written = write!(primary.detail, "; retained: {}", error.line());
            }
        }
        primary
    }
    fn refusal_evidence(
        path: &Path,
        expected: &str,
        reason: &str,
        held: &OwnedFd,
    ) -> Result<(), LaneError> {
        let run = path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix(".reservation-"))
            .and_then(|s| s.strip_suffix(".json"))
            .ok_or_else(|| refusal("reservation name differs"))?;
        nonce(&json!({"round_rollback":{"nonce":expected}}))?;
        let evidence = path.with_file_name(format!(".round-refusal-{run}-{expected}.json"));
        let bytes = serde_json::to_vec(&json!({"schema":1,"nonce":expected,
            "state":"live-refusal","reason":reason}))
        .map_err(refusal)?;
        super::super::publish_reservation_bytes_at(&evidence, &bytes, None, Some(held))
    }

    fn restore(
        path: &Path,
        expected: &str,
        receipts: (&build::LiveChild, &build::LiveChild),
        reason: &str,
        held: &OwnedFd,
        cleanup: impl FnOnce() -> Result<(), LaneError>,
    ) -> Result<(), LaneError> {
        // Record the primary refusal even when absence or the embedded record refuses.
        refusal_evidence(path, expected, reason, held)?;
        if !receipts.0.absent() || !receipts.1.absent() {
            return Err(refusal("process-absence"));
        }
        let record = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        let bytes = before(&record, expected)?;
        let root = path
            .parent()
            .ok_or_else(|| refusal("reservation parent absent"))?;
        let run = record["run"]
            .as_str()
            .ok_or_else(|| refusal("run absent"))?;
        cleanup()?;
        let _lock = lock_mailbox(root, run, Uid::effective().as_raw())?;
        let current = read_reservation(path)?.ok_or_else(|| refusal("reservation absent"))?;
        if before(&current, expected)? != bytes {
            return Err(refusal("before-image changed"));
        }
        if !receipts.0.absent() || !receipts.1.absent() {
            return Err(refusal("process-absence"));
        }
        super::super::publish_reservation_bytes_at(path, &bytes, None, Some(held))
    }

    pub(super) struct Host<'a> {
        pub(super) path: &'a Path,
        pub(super) nonce: &'a str,
        pub(super) program: &'a Path,
        pub(super) environment: &'a std::collections::BTreeMap<String, String>,
        pub(super) owner_home: &'a Path,
        pub(super) home: &'a OwnedFd,
        pub(super) root: &'a Path,
        pub(super) runs: &'a OwnedFd,
        pub(super) argv: Vec<String>,
    }
    impl Host<'_> {
        fn quiescent(&self) -> Result<(), LaneError> {
            let record =
                read_reservation(self.path)?.ok_or_else(|| refusal("reservation absent"))?;
            let _before = before(&record, self.nonce)?;
            let loop_name = record["loop"]
                .as_str()
                .ok_or_else(|| refusal("loop absent"))?;
            let run = record["run"]
                .as_str()
                .ok_or_else(|| refusal("run absent"))?;
            if !super::super::container_absent_for_run(
                self.program,
                self.owner_home,
                loop_name,
                run,
            )? {
                return Err(refusal("container-payload-present"));
            }
            let _scope = super::super::reaping::retirement_scope(&record)?;
            Ok(())
        }
        pub(super) fn refuse(
            &self,
            error: LaneError,
            receipts: (&build::LiveChild, &build::LiveChild),
        ) -> LaneError {
            finish_at(error, self.path, self.nonce, receipts, self.runs, || {
                self.quiescent()?;
                let mut receipt = build::LiveChild::default();
                let output = build::inspect_with_receipt(
                    self.program,
                    &self.argv,
                    self.environment,
                    self.owner_home,
                    self.home,
                    self.root,
                    self.runs,
                    &mut receipt,
                )?;
                if !receipt.absent() {
                    return Err(refusal("cleanup-process-absence"));
                }
                let report: Value = serde_json::from_str(&output).map_err(refusal)?;
                if report["state"] != "cleaned" || report["nonce"] != self.nonce {
                    return Err(refusal("cleanup receipt differs"));
                }
                self.quiescent()
            })
        }
    }
    pub(super) fn snapshot_sockets(record: &mut Value, plan: &Plan) -> Result<(), LaneError> {
        let mut rows = Vec::new();
        for path in [
            crate::container_helper::socket_path(&plan.driver_dir)?,
            crate::container_helper::control_socket_path(&plan.driver_dir)?,
        ] {
            let slot = crate::SocketSlot::pinned(&path, Uid::effective().as_raw())?;
            let identity = slot
                .metadata()
                .map_err(refusal)?
                .map(|m| json!([m.st_dev, m.st_ino]));
            rows.push(
                json!({"name":path.file_name().and_then(|name| name.to_str()),"identity":identity}),
            );
        }
        record["round_rollback"]["sockets_before"] = json!(rows);
        Ok(())
    }
    fn check_unowned_sockets(record: &Value, root: &Path, driver: &Path) -> Result<(), LaneError> {
        let original = record["round_rollback"]["sockets_before"]
            .as_array()
            .ok_or_else(|| refusal("original socket receipts absent"))?;
        let owned = record["round_rollback"]["sockets"]
            .as_array()
            .ok_or_else(|| refusal("socket receipts absent"))?;
        for path in [
            crate::container_helper::socket_path(driver)?,
            crate::container_helper::control_socket_path(driver)?,
        ] {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| refusal("socket name absent"))?;
            if owned.iter().any(|row| row["name"] == name) {
                continue;
            }
            let prior = original
                .iter()
                .find(|row| row["name"] == name)
                .ok_or_else(|| refusal("original socket receipt absent"))?;
            let slot = crate::SocketSlot::pinned(&root.join(name), Uid::effective().as_raw())?;
            let identity = slot
                .metadata()
                .map_err(refusal)?
                .map(|m| json!([m.st_dev, m.st_ino]));
            if prior["identity"] != json!(identity) {
                return Err(refusal("unowned socket changed"));
            }
        }
        Ok(())
    }

    struct Leaf {
        directory: std::fs::File,
        name: String,
        identity: (u64, u64),
    }
    fn request_leaf(
        directory: &std::fs::File,
        name: String,
        expected: &[u8],
        owner: u32,
    ) -> Result<Option<Leaf>, LaneError> {
        let fd = match nix::fcntl::openat(
            directory,
            name.as_str(),
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(refusal(error)),
        };
        let mut file = std::fs::File::from(fd);
        let meta = file.metadata().map_err(refusal)?;
        if !meta.is_file()
            || meta.uid() != owner
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
            || meta.len() != u64::try_from(expected.len()).map_err(refusal)?
        {
            return Err(refusal(format!("request custody differs: {name}")));
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(super::super::MAX_RESERVATION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(refusal)?;
        if bytes != expected {
            return Err(refusal(format!("request bytes differ: {name}")));
        }
        Ok(Some(Leaf {
            directory: directory.try_clone().map_err(refusal)?,
            name,
            identity: (meta.dev(), meta.ino()),
        }))
    }
    impl Leaf {
        fn remove(self) -> Result<(), LaneError> {
            let stat = nix::sys::stat::fstatat(
                &self.directory,
                self.name.as_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(refusal)?;
            if (stat.st_dev, stat.st_ino) != self.identity {
                return Err(refusal("replacement retained"));
            }
            nix::unistd::unlinkat(
                &self.directory,
                self.name.as_str(),
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            )
            .map_err(refusal)?;
            self.directory.sync_all().map_err(refusal)
        }
    }
    pub(super) fn private_cleanup(
        loop_name: &str,
        run: &str,
        expected: &str,
    ) -> Result<Value, LaneError> {
        let root = home::private_runs_path().ok_or_else(|| refusal("runs custody absent"))?;
        let _lock = lock_mailbox(&root, run, Uid::effective().as_raw())?;
        let path = reservation_path(&root, run);
        let record = read_reservation(&path)?.ok_or_else(|| refusal("reservation absent"))?;
        let _before = before(&record, expected)?;
        let root_directory = home::pin_parent(&root, Uid::effective().as_raw())?;
        let temporary = format!(".reservation-{expected}.tmp");
        match nix::sys::stat::fstatat(
            &root_directory,
            temporary.as_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => {}
            _ => return Err(refusal("reservation temporary retained")),
        }
        if record["loop"] != loop_name || record["run"] != run {
            return Err(refusal("run identity differs"));
        }
        let driver = root.join(run);
        if record["plan"]["driver_dir"] != driver.display().to_string() {
            return Err(refusal("driver directory differs"));
        }
        let step = record["active_round"]
            .as_str()
            .ok_or_else(|| refusal("step absent"))?;
        super::super::letters::valid_step(step)?;
        let owner = crate::plan::loop_uid(&record["plan"])?;
        let directory = held_round_directory(&driver, owner)?;
        let request = record["round_rollback"]["request"]
            .as_str()
            .ok_or_else(|| refusal("request absent"))?;
        let mut leaves = Vec::new();
        for name in [
            format!("round-launch-{step}.json"),
            format!(".round-launch-{step}-{expected}.tmp"),
        ] {
            if let Some(leaf) = request_leaf(&directory, name, request.as_bytes(), owner)? {
                leaves.push(leaf);
            }
        }
        let (_, runtime) =
            super::super::pin_runtime_dir(&driver, Uid::effective().as_raw(), owner)?;
        let temporary = format!(".runtime.env-{expected}");
        match nix::sys::stat::fstatat(
            &runtime,
            temporary.as_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => {}
            _ => return Err(refusal("environment temporary retained")),
        }
        check_unowned_sockets(&record, &root, &driver)?;
        let mut sockets = Vec::new();
        for row in record["round_rollback"]["sockets"]
            .as_array()
            .ok_or_else(|| refusal("socket receipts absent"))?
        {
            let name = row["name"]
                .as_str()
                .ok_or_else(|| refusal("socket name absent"))?;
            let allowed = [
                crate::container_helper::socket_path(&driver)?,
                crate::container_helper::control_socket_path(&driver)?,
            ];
            if !allowed
                .iter()
                .any(|p| p.file_name().is_some_and(|n| n == name))
            {
                return Err(refusal("socket name differs"));
            }
            let slot = crate::SocketSlot::pinned(&root.join(name), Uid::effective().as_raw())?;
            if let Some(meta) = slot.metadata().map_err(refusal)? {
                if row["device"] != meta.st_dev
                    || row["inode"] != meta.st_ino
                    || meta.st_mode & libc::S_IFMT != libc::S_IFSOCK
                {
                    return Err(refusal("replacement socket retained"));
                }
                sockets.push((slot, (meta.st_dev, meta.st_ino)));
            }
        }
        for leaf in leaves {
            leaf.remove()?;
        }
        for (slot, identity) in sockets {
            if slot
                .metadata()
                .map_err(refusal)?
                .is_none_or(|m| (m.st_dev, m.st_ino) != identity)
            {
                return Err(refusal("replacement socket retained"));
            }
            slot.remove().map_err(refusal)?;
        }
        directory.sync_all().map_err(refusal)?;
        nix::unistd::fsync(&runtime).map_err(refusal)?;
        nix::unistd::fsync(&root_directory).map_err(refusal)?;
        Ok(json!({"schema":1,"state":"cleaned","nonce":expected}))
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::process::CommandExt as _;

        fn fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>, String) {
            let root = tempfile::tempdir().expect("caller temporary root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
            let path = reservation_path(root.path(), "R");
            let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R",
                "worker_uid":3000,"active_round":"dispatch","rounds":[]});
            let bytes = format!(
                "{}\n\n",
                serde_json::to_string_pretty(&record).expect("pretty before")
            )
            .into_bytes();
            super::super::super::publish_reservation_bytes(&path, &bytes).expect("before");
            let mut next = record;
            next["phase"] = json!("preparing");
            next["active_round"] = json!("review");
            next["rounds"] = json!([{"step":"review","phase":"running"}]);
            let nonce = prepare(&mut next, &bytes, "expected\n").expect("before-image");
            publish_reservation(&path, &next).expect("preparing");
            (root, path, bytes, nonce)
        }
        /// A live refusal preserves the published placement and exact settled bytes.
        ///
        /// # Panics
        /// Panics if preparation or restoration changes the placed plan.
        /// ´test:unit:live-round-rollback-restores-placed-reservation´
        #[test]
        fn live_round_rollback_restores_placed_reservation() {
            let (_root, path, _, _) = fixture();
            let placed = json!({"loop":"alpha","run":"R",
                "compute_workspace":crate::tests::published_workspace(),
                "compute_placement":crate::tests::published_placement()});
            let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R",
                "worker_uid":3000,"active_round":"dispatch","rounds":[],"plan":placed});
            let bytes = format!(
                "{}\n\n",
                serde_json::to_string_pretty(&record).expect("pretty placed before")
            )
            .into_bytes();
            super::super::super::publish_reservation_bytes(&path, &bytes).expect("placed before");
            let (mut next, raw) = super::super::super::read_reservation_raw(&path, true)
                .expect("placed raw read")
                .expect("placed record");
            assert_eq!(raw, bytes, "raw placed reservation preserved");
            next["phase"] = json!("preparing");
            next["active_round"] = json!("review");
            next["rounds"] = json!([{"step":"review","phase":"running"}]);
            let nonce = prepare(&mut next, &raw, "expected\n").expect("placed prepare");
            publish_reservation(&path, &next).expect("placed preparing");
            assert_eq!(
                read_reservation(&path)
                    .expect("preparing read")
                    .expect("record")["plan"],
                placed,
                "preparing retains placed plan"
            );
            let absent = build::LiveChild::default();
            let error = finish(primary(), &path, &nonce, (&absent, &absent), || Ok(()));
            assert!(error.detail.ends_with("rollback: restored"), "{error}");
            assert_eq!(
                fs::read(&path).expect("restored bytes"),
                bytes,
                "placed before-image exact"
            );
            assert_eq!(
                read_reservation(&path)
                    .expect("restored read")
                    .expect("record")["plan"],
                placed,
                "restoration retains placed plan"
            );
        }

        /// A live refusal restores the choice along with the exact settled bytes.
        ///
        /// # Panics
        /// Panics if rollback consumes the failed-round choice.
        /// ´test:unit:failed-round-choice-survives-live-rollback´
        #[test]
        fn failed_round_choice_survives_live_rollback() {
            for choice in [
                super::super::ThreadChoice::Fresh,
                super::super::ThreadChoice::Resume,
            ] {
                let (root, path, _, _) = fixture();
                let mut before = super::super::choice_tests::record();
                before["rounds"][0]["driver_dir"] = json!(root.path().join("R/prior-dispatch"));
                before["plan"] = json!({"loop":"alpha","run":"R",
                    "compute_workspace":crate::tests::published_workspace(),
                    "compute_placement":crate::tests::published_placement()});
                let bytes = format!(
                    "{}\n\n",
                    serde_json::to_string_pretty(&before).expect("before")
                )
                .into_bytes();
                let mut next = super::super::preflight_record(
                    &root.path().join("R"),
                    &before,
                    "review",
                    3600,
                    Some(choice),
                )
                .expect("chosen prospective record");
                assert_eq!(
                    next["plan"], before["plan"],
                    "chosen preflight retains placed plan"
                );
                let plan = Plan {
                    home: root.path().join("home"),
                    driver_dir: root.path().join("R"),
                    letter: PathBuf::new(),
                    document: json!({"backend":"codex"}),
                };
                let expected = format!(
                    "{}\n",
                    super::super::request_text(&plan, &next, "review", 3600).expect("request")
                );
                let nonce = prepare(&mut next, &bytes, &expected).expect("prepare");
                assert_eq!(next["round_rollback"]["request"], expected);
                assert!(
                    !super::super::failed_continuation(&next),
                    "preparing belongs to recovery"
                );
                let emitted = format!(
                    "{}\n",
                    super::super::request_text(&plan, &next, "review", 3600)
                        .expect("private request")
                );
                assert_eq!(emitted, expected, "preflight and cleanup request agree");
                publish_reservation(&path, &next).expect("preparing");
                let absent = build::LiveChild::default();
                let error = finish(primary(), &path, &nonce, (&absent, &absent), || Ok(()));
                assert!(error.detail.ends_with("rollback: restored"), "{error}");
                assert_eq!(fs::read(&path).expect("restored"), bytes);
                let saved = read_reservation(&path).expect("read").expect("saved");
                assert_eq!(
                    saved["plan"], before["plan"],
                    "chosen rollback retains placed plan"
                );
                assert_eq!(
                    super::super::require_thread_choice(&saved, None)
                        .expect_err("choice remains owed")
                        .kind,
                    "round-choice"
                );
            }
        }

        /// Raw resume reads keep legacy bytes but refuse placement-path duplicates.
        /// ´test:unit:live-round-raw-reader-preserves-placement-floor´
        #[test]
        fn live_round_raw_reader_preserves_placement_floor() {
            let (_root, path, _, _) = fixture();
            let legacy =
                br#"{"schema":1,"phase":"settled","worker_uid":3000,"legacy":1,"legacy":2}"#;
            super::super::super::publish_reservation_bytes(&path, legacy).expect("legacy");
            let (record, raw) = super::super::super::read_reservation_raw(&path, true)
                .expect("legacy read")
                .expect("present");
            assert_eq!(raw, legacy);
            assert_eq!(
                record,
                serde_json::from_slice::<Value>(legacy).expect("legacy parser")
            );
            let duplicate = concat!(
                r#"{"schema":1,"phase":"settled","worker_uid":3000,"#,
                r#""plan":{"compute_placement":null},"plan":{}}"#
            )
            .as_bytes();
            super::super::super::publish_reservation_bytes(&path, duplicate)
                .expect("duplicate bytes");
            let error = super::super::super::read_reservation_raw(&path, true)
                .expect_err("raw reader preserves placement floor");
            assert!(
                error.detail.contains("duplicate key on placement path"),
                "{error}"
            );
        }

        /// The embedded raw before-image has the same placement reader floor.
        /// ´test:unit:live-round-before-image-preserves-placement-floor´
        #[test]
        fn live_round_before_image_preserves_placement_floor() {
            let (_root, path, bytes, nonce) = fixture();
            let mut record = read_reservation(&path).expect("read").expect("record");
            assert_eq!(before(&record, &nonce).expect("legacy before-image"), bytes);
            let duplicate = concat!(
                r#"{"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"#,
                r#""plan":{"compute_placement":null,"compute_placement":null}}"#
            )
            .as_bytes();
            let nonce = prepare(&mut record, duplicate, "expected\n").expect("duplicate embedded");
            publish_reservation(&path, &record).expect("outer reservation accepts opaque before");
            let error =
                before(&record, &nonce).expect_err("embedded reader preserves placement floor");
            assert!(
                error.detail.contains("duplicate key on placement path"),
                "{error}"
            );
            let absent = build::LiveChild::default();
            let error = finish(primary(), &path, &nonce, (&absent, &absent), || {
                panic!("no cleanup")
            });
            assert!(error.detail.contains("retained:"));
            let evidence = path.with_file_name(format!(".round-refusal-R-{nonce}.json"));
            assert!(
                fs::read_to_string(evidence)
                    .expect("before-image refusal is durable")
                    .contains("original refusal")
            );
        }

        fn kernel_holder_key(locks: &str, pid: u32, inode: u64) -> Option<&str> {
            let pid = pid.to_string();
            let inode = format!(":{inode}");
            locks.lines().find_map(|line| {
                let words = line.split_whitespace().collect::<Vec<_>>();
                if words.get(1) == Some(&"FLOCK") && words.get(4) == Some(&pid.as_str()) {
                    words.get(5).copied().filter(|word| word.ends_with(&inode))
                } else {
                    None
                }
            })
        }

        /// ´test:unit:mailbox-waiter-uses-kernel-holder-device´
        #[test]
        fn mailbox_waiter_uses_kernel_holder_device() {
            let locks = "1: FLOCK ADVISORY WRITE 12 00:3d:99 0 EOF\n\
                         2: -> FLOCK ADVISORY WRITE 42 00:17:99 0 EOF\n\
                         3: FLOCK ADVISORY WRITE 42 00:24:99 0 EOF\n";
            assert_eq!(
                kernel_holder_key(locks, 42, 99),
                Some("00:24:99"),
                "kernel holder, not stat device, foreign holder or waiter"
            );
            assert_eq!(kernel_holder_key(locks, 42, 100), None);
            assert_eq!(kernel_holder_key(locks, 43, 99), None);
        }

        /// A parent callback waits for the helper publisher and preserves its identity.
        /// ´test:unit:live-round-parent-publication-takes-mailbox-lock´
        #[test]
        fn live_round_parent_publication_takes_mailbox_lock() {
            use std::sync::mpsc;
            use std::time::Duration;
            let (root, path, _, nonce) = fixture();
            let lock =
                lock_mailbox(root.path(), "R", Uid::effective().as_raw()).expect("helper lock");
            let temporary = root.path().join(format!(".reservation-{nonce}.tmp"));
            fs::write(&temporary, b"helper publication in progress").expect("occupied temporary");
            let (entered, observed) = mpsc::channel();
            let (done, completion) = mpsc::channel();
            let callback_path = path.clone();
            let callback = std::thread::spawn(move || {
                entered.send(()).expect("entered");
                let result = super::super::record_helper_parent(&callback_path, 91, 92);
                done.send(result).expect("completion");
            });
            observed
                .recv_timeout(Duration::from_secs(30))
                .expect("callback entry event");
            let metadata = lock.metadata().expect("held lock identity");
            let locks = fs::read_to_string("/proc/locks").expect("kernel holder census");
            let key = kernel_holder_key(&locks, std::process::id(), metadata.ino())
                .expect("this process's kernel holder identity");
            let deadline = std::time::Instant::now() + Duration::from_secs(180);
            let blocked = loop {
                let locks = fs::read_to_string("/proc/locks").expect("kernel lock census");
                if locks.lines().any(|line| {
                    line.contains("->") && line.split_whitespace().any(|word| word == key)
                }) {
                    break true;
                }
                if !matches!(completion.try_recv(), Err(mpsc::TryRecvError::Empty))
                    || std::time::Instant::now() >= deadline
                {
                    break false;
                }
                std::thread::yield_now();
            };
            fs::remove_file(temporary).expect("helper completed temporary");
            let mut record = read_reservation(&path).expect("read").expect("record");
            record["helper_pid"] = json!(93);
            publish_reservation(&path, &record).expect("helper identity publication");
            drop(lock);
            callback.join().expect("callback joined");
            assert!(
                blocked,
                "callback must be a kernel-recorded waiter on the held mailbox lock"
            );
            completion
                .recv_timeout(Duration::from_secs(30))
                .expect("callback complete event")
                .expect("callback publishes after helper");
            let record = read_reservation(&path).expect("read").expect("record");
            assert_eq!(record["helper_pid"], 93, "helper update kept");
            assert_eq!(record["helper_parent_pid"], 91);
            assert_eq!(record["helper_parent_start"], 92);
        }

        /// Publication errors distinguish exact unchanged bytes from uncertain writes.
        /// ´test:unit:round-preparing-publication-refuses-without-retaining-unchanged-run´
        #[test]
        fn round_preparing_publication_refuses_without_retaining_unchanged_run() {
            let (root, path, before, nonce) = fixture();
            let preparing = fs::read(&path).expect("preparing bytes");
            let record = read_reservation(&path).expect("read").expect("record");
            super::super::super::publish_reservation_bytes(&path, &before).expect("settled");
            let temporary = root.path().join(format!(".reservation-{nonce}.tmp"));
            fs::write(&temporary, b"occupied").expect("occupied own temporary");
            let result = publish_reservation(&path, &record);
            let Publication::Unchanged(error) = publication(&path, &before, result) else {
                panic!("unchanged publication is not retained");
            };
            assert_eq!(error.kind, "uid-table");
            assert!(
                error
                    .detail
                    .ends_with("unchanged: preparing reservation was not published")
            );
            assert_eq!(fs::read(&path).expect("unchanged"), before);
            assert_eq!(fs::read(&temporary).expect("other publisher"), b"occupied");
            fs::remove_file(temporary).expect("remove own obstruction");
            super::super::super::publish_reservation_bytes(&path, &preparing).expect("renamed");
            assert!(
                matches!(
                    publication(&path, &before, Err(primary())),
                    Publication::Attempt(Err(_))
                ),
                "post-rename error must still take rollback"
            );
            fs::remove_file(&path).expect("simulate unavailable readback");
            assert!(
                matches!(
                    publication(&path, &before, Err(primary())),
                    Publication::Attempt(Err(_))
                ),
                "unknown readback must retain through rollback"
            );
        }

        fn primary() -> LaneError {
            LaneError::input("injected-refusal", "original refusal")
        }

        /// ´test:unit:live-round-rollback-restores-exact-bytes-last´
        #[test]
        fn live_round_rollback_restores_exact_bytes_last() {
            let (_root, path, bytes, nonce) = fixture();
            let absent = build::LiveChild::default();
            let error = finish(primary(), &path, &nonce, (&absent, &absent), || {
                assert_eq!(
                    read_reservation(&path)?.expect("during cleanup")["phase"],
                    "preparing",
                    "reservation must remain preparing until cleanup completes"
                );
                Ok(())
            });
            assert_eq!(error.kind, "injected-refusal");
            assert_eq!(error.status, 2, "original refusal status retained");
            assert!(error.detail.starts_with("original refusal;"));
            assert!(error.detail.ends_with("rollback: restored"), "{error}");
            assert_eq!(
                fs::read(&path).expect("restored"),
                bytes,
                "exact before-image restored"
            );
            let record = read_reservation(&path).expect("read").expect("present");
            assert_eq!(record["rounds"], json!([]), "round name reusable");
            assert!(record.get("round_rollback").is_none());
        }

        /// ´test:unit:live-round-rollback-waits-for-process-absence´
        #[test]
        fn live_round_rollback_waits_for_process_absence() {
            let (_root, path, bytes, nonce) = fixture();
            let preparing = fs::read(&path).expect("preparing");
            let mut child = std::process::Command::new("/usr/bin/sleep")
                .arg("infinity")
                .process_group(0)
                .spawn()
                .expect("live attempt process");
            let mut live = build::LiveChild::default();
            live.started(child.id());
            let absent = build::LiveChild::default();
            let error = finish(primary(), &path, &nonce, (&live, &absent), || {
                Err(refusal("cleanup ran before process absence"))
            });
            child.kill().expect("stop fixture child");
            child.wait().expect("wait fixture child");
            let evidence = path.with_file_name(format!(".round-refusal-R-{nonce}.json"));
            let evidence: Value = serde_json::from_slice(
                &fs::read(evidence).expect("durable refusal before absence"),
            )
            .expect("evidence");
            assert!(
                evidence["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("original refusal")
            );
            assert!(
                error
                    .detail
                    .contains("retained: round-rollback: process-absence"),
                "{error}"
            );
            assert_eq!(
                fs::read(&path).expect("retained"),
                preparing,
                "reservation remains preparing while process exists"
            );
            let error = finish(primary(), &path, &nonce, (&live, &absent), || Ok(()));
            assert!(error.detail.ends_with("rollback: restored"), "{error}");
            assert_eq!(fs::read(path).expect("retry after wait"), bytes);
        }

        /// ´test:unit:live-round-rollback-retains-replaced-request´
        #[test]
        fn live_round_rollback_retains_replaced_request() {
            let (root, path, _, nonce) = fixture();
            let preparing = fs::read(&path).expect("preparing");
            let request = root.path().join("round-launch-review.json");
            fs::write(&request, b"replaced\n").expect("replacement");
            fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).expect("request mode");
            let absent = build::LiveChild::default();
            let error = finish(primary(), &path, &nonce, (&absent, &absent), || {
                let directory = fs::File::open(root.path()).expect("held root");
                if let Some(leaf) = request_leaf(
                    &directory,
                    "round-launch-review.json".into(),
                    b"expected\n",
                    Uid::effective().as_raw(),
                )? {
                    leaf.remove()?;
                }
                Ok(())
            });
            assert!(error.detail.contains("request bytes differ"), "{error}");
            assert_eq!(
                fs::read(&request).expect("replacement retained"),
                b"replaced\n"
            );
            assert_eq!(fs::read(path).expect("reservation retained"), preparing);
        }

        /// ´test:unit:live-round-rollback-refuses-after-dispatch-intent´
        #[test]
        fn live_round_rollback_refuses_after_dispatch_intent() {
            let (_root, path, _, nonce) = fixture();
            intent(&path, &nonce).expect("intent before spawn");
            let intended = fs::read(&path).expect("intent bytes");
            let absent = build::LiveChild::default();
            let error = finish(primary(), &path, &nonce, (&absent, &absent), || Ok(()));
            assert!(
                error
                    .detail
                    .contains("retained: round-rollback: dispatch-intent"),
                "{error}"
            );
            assert_eq!(
                fs::read(&path).expect("intent retained"),
                intended,
                "post-intent never restored"
            );
            let mut record = read_reservation(&path).expect("read").expect("record");
            record["driver_entry_pid"] = json!(42);
            publish_reservation(&path, &record).expect("driver receipt");
            dispatched(&path, &nonce).expect("receipt consumes rollback boundary");
            let record = read_reservation(&path).expect("read").expect("record");
            assert!(
                record.get("dispatch_intent").is_none(),
                "intent removed after receipt"
            );
            assert!(record.get("round_rollback").is_none());
        }

        /// ´test:unit:live-round-rollback-checks-scope-and-container-absence´
        #[test]
        fn live_round_rollback_checks_scope_and_container_absence() {
            let (root, path, _, nonce) = fixture();
            let mut record = read_reservation(&path).expect("record").expect("present");
            let scope = super::super::super::reaping::RetirementScopeFixture::new(&mut record);
            publish_reservation(&path, &record).expect("protected scope identity");
            let home = fs::File::open(root.path()).expect("home").into();
            let runs = fs::File::open(root.path()).expect("runs").into();
            let environment = std::collections::BTreeMap::new();
            // These programs model only the container inventory. Scope reads use the
            // existing explicit test cgroup root, not a claim about kernel containment.
            let mut host = Host {
                path: &path,
                nonce: &nonce,
                program: Path::new("/usr/bin/true"),
                environment: &environment,
                owner_home: root.path(),
                home: &home,
                root: root.path(),
                runs: &runs,
                argv: Vec::new(),
            };
            host.quiescent().expect("empty inventory and scope");
            fs::write(scope.path.join("cgroup.events"), "populated 1\n").expect("live scope");
            let error = host.quiescent().expect_err("populated scope retained");
            assert_eq!(error.kind, "retire-busy");
            fs::write(scope.path.join("cgroup.events"), "populated 0\n").expect("empty scope");
            host.program = Path::new("/usr/bin/printf");
            let error = host.quiescent().expect_err("container inventory retained");
            assert!(
                error.detail.contains("container-payload-present"),
                "{error}"
            );
            host.program = Path::new("/usr/bin/true");
            record["run_scope"]["inode"] = json!(1);
            publish_reservation(&path, &record).expect("changed scope identity");
            let error = host.quiescent().expect_err("replacement scope retained");
            assert_eq!(error.kind, "run-scope-record");
        }

        /// ´test:unit:live-round-reservation-failure-removes-own-temporary´
        #[test]
        fn live_round_reservation_failure_removes_own_temporary() {
            let root = tempfile::tempdir().expect("supplied temporary root");
            let path = root.path().join("occupied");
            fs::create_dir(&path).expect("refuse rename into directory");
            let error = super::super::super::publish_reservation_bytes_named(
                &path,
                b"{}",
                Some(&"a".repeat(64)),
            )
            .expect_err("rename refusal");
            assert_eq!(error.kind, "uid-table");
            let entries: Vec<_> = fs::read_dir(root.path())
                .expect("inventory")
                .map(|entry| entry.expect("entry").file_name())
                .collect();
            assert_eq!(
                entries,
                [std::ffi::OsString::from("occupied")],
                "failed reservation writer removes only its own temporary"
            );
        }

        /// ´test:unit:live-round-restoration-keeps-the-held-root´
        #[test]
        fn live_round_restoration_keeps_the_held_root() {
            let root = tempfile::tempdir().expect("caller temporary root");
            let named = root.path().join("runs");
            let moved = root.path().join("held-runs");
            fs::create_dir(&named).expect("root");
            let held = fs::File::open(&named).expect("hold root").into();
            fs::rename(&named, &moved).expect("move own root");
            fs::create_dir(&named).expect("replacement root");
            let path = named.join(".reservation-R.json");
            fs::write(&path, b"replacement sentinel").expect("replacement");
            super::super::super::publish_reservation_bytes_at(
                &path,
                b"original bytes",
                None,
                Some(&held),
            )
            .expect("held restoration");
            assert_eq!(
                fs::read(&path).expect("replacement retained"),
                b"replacement sentinel",
                "restoration never reopens the runs pathname"
            );
            assert_eq!(
                fs::read(moved.join(".reservation-R.json")).expect("held record"),
                b"original bytes"
            );
        }

        /// ´test:unit:live-round-before-image-keeps-reservation-bound´
        #[test]
        fn live_round_before_image_keeps_reservation_bound() {
            let (_root, path, bytes, _) = fixture();
            let unchanged = fs::read(&path).expect("before refusal");
            let mut record: Value = serde_json::from_slice(&bytes).expect("prior");
            record["padding"] = json!("x".repeat(3 * 1024 * 1024));
            let before = serde_json::to_vec(&record).expect("bounded prior");
            let error = prepare(&mut record, &before, "expected\n").expect_err("whole record cap");
            assert!(error.detail.contains("limit is 4194304 bytes"), "{error}");
            assert_eq!(fs::read(path).expect("no publication"), unchanged);
        }
    }
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

    /// ´test:unit:awaiting-round-recovery-requires-completed-driver´
    #[test]
    fn awaiting_round_recovery_requires_completed_driver() {
        let good = json!({"phase":"started","active_round":"review",
            "driver_end":{"state":"completed","successful":true},
            "rounds":[{"step":"dispatch","phase":"settled"},
                {"step":"review","phase":"awaiting-settlement"}]});
        assert!(super::interrupted_round(&good, "review"));
        for end in [
            serde_json::Value::Null,
            json!({"state":"running"}),
            json!({"state":"not-started"}),
        ] {
            let mut record = good.clone();
            record["driver_end"] = end;
            assert!(!super::interrupted_round(&record, "review"), "{record}");
        }
        let mut record = good.clone();
        record["driver_end"]["successful"] = json!(false);
        assert!(
            !super::interrupted_round(&record, "review"),
            "unsuccessful driver is not the stop race"
        );
        record["driver_end"]["successful"] = serde_json::Value::Null;
        assert!(
            !super::interrupted_round(&record, "review"),
            "driver success must be recorded"
        );
        record = good.clone();
        record["helper_end"] = json!({"state":"completed","successful":false});
        assert!(
            !super::interrupted_round(&record, "review"),
            "unsuccessful helper is not the stop race"
        );
        record["helper_end"]["successful"] = json!(true);
        assert!(super::interrupted_round(&record, "review"));
        assert!(!super::interrupted_round(&good, "other"));
        record["phase"] = json!("settled");
        assert!(!super::interrupted_round(&record, "review"));
        record = good;
        record["active_round"] = json!("dispatch");
        record["rounds"] = json!([{"step":"dispatch","phase":"awaiting-settlement"}]);
        assert!(
            !super::interrupted_round(&record, "dispatch"),
            "first dispatch uses its own recovery"
        );
    }

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

    /// ´test:unit:boxed-selected-session-reader-rejects-foreign-and-conflicting-evidence´
    #[test]
    fn boxed_selected_session_reader_rejects_foreign_and_conflicting_evidence() {
        use crate::settings::BoxBackend;
        let fixture = tempfile::tempdir().expect("event fixture");
        let path = fixture.path().join("events.jsonl");
        std::fs::write(fixture.path().join(".event-start"), b"0\n").expect("step boundary");
        // The driver's recorded init event supplies the session schema.
        let init = br#"{"type":"system","subtype":"init","cwd":"/x","session_id":"22222222-2222-4222-8222-222222222222","tools":[],"mcp_servers":[],"model":"claude-haiku-4-5-20251001","permissionMode":"auto"}"#;
        let mut stream = b"{\"type\":\"thread.started\",\"thread_id\":\"codex-thread\"}\n".to_vec();
        stream.extend_from_slice(init);
        stream.push(b'\n');
        std::fs::write(&path, &stream).expect("events");
        assert_eq!(
            super::step_event_thread(
                BoxBackend::Codex,
                fixture.path(),
                nix::unistd::Uid::effective().as_raw()
            )
            .expect("Codex event"),
            "codex-thread"
        );
        assert_eq!(
            super::step_event_thread(
                BoxBackend::Claude,
                fixture.path(),
                nix::unistd::Uid::effective().as_raw()
            )
            .expect("Claude event"),
            "22222222-2222-4222-8222-222222222222"
        );
        let changed = String::from_utf8(init.to_vec())
            .expect("capture text")
            .replace(
                "22222222-2222-4222-8222-222222222222",
                "44444444-4444-4444-8444-444444444444",
            );
        stream.extend_from_slice(changed.as_bytes());
        stream.push(b'\n');
        std::fs::write(&path, stream).expect("conflicting event");
        assert_eq!(
            super::step_event_thread(
                BoxBackend::Claude,
                fixture.path(),
                nix::unistd::Uid::effective().as_raw()
            )
            .expect_err("session changed")
            .kind,
            "round-thread"
        );
        std::fs::write(&path, init).expect("incomplete event");
        assert!(
            super::step_event_thread(
                BoxBackend::Claude,
                fixture.path(),
                nix::unistd::Uid::effective().as_raw()
            )
            .is_err()
        );
    }

    /// ´test:unit:round-inspection-validates-before-publication´
    #[test]
    fn round_inspection_validates_before_publication() {
        let (_fixture, plan) = client_environment_fixture();
        let runtime = plan.driver_dir.join("launch/runtime.env");
        let before = fs::read(&runtime).expect("environment");
        let metadata = fs::metadata(&runtime).expect("environment inode");
        let mut record = json!({"phase":"preparing","active_round":"review",
            "thread_id":"thread","worker_uid":0,
            "rounds":[{"step":"review","budget_seconds":900}],"mail":[]});
        let names = || {
            let mut names = fs::read_dir(&plan.driver_dir)
                .expect("run entries")
                .map(|entry| entry.expect("entry").file_name())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let original = names();
        let error = inspect_loaded_round(&plan, &record, Some(("review", 900)))
            .expect_err("missing binding before environment write");
        assert_eq!(error.kind, "mail-delivery");
        assert_eq!(fs::read(&runtime).expect("unchanged bytes"), before);
        assert_eq!(
            fs::metadata(&runtime).expect("unchanged inode").ino(),
            metadata.ino()
        );
        assert_eq!(names(), original, "no round request temporary");
        record["mail"] = json!([{"step":"review"}]);
        let request = plan.driver_dir.join("round-launch-review.json");
        fs::write(&request, b"retained request").expect("existing request");
        let original = names();
        let error = inspect_loaded_round(&plan, &record, Some(("review", 900)))
            .expect_err("occupied request before environment write");
        assert_eq!(error.kind, "round-evidence");
        assert!(
            error
                .detail
                .contains("round-launch-review.json already exists")
        );
        assert_eq!(
            fs::read(&request).expect("retained request"),
            b"retained request"
        );
        assert_eq!(fs::read(&runtime).expect("unchanged bytes"), before);
        assert_eq!(
            fs::metadata(&runtime).expect("unchanged inode").ino(),
            metadata.ino()
        );
        assert_eq!(names(), original, "no temporary on occupied destination");
        fs::remove_file(&request).expect("remove fixture destination");
        let temporary = plan
            .driver_dir
            .join(format!(".round-launch-review-{}.tmp", std::process::id()));
        fs::write(&temporary, b"retained temporary").expect("occupied exact temporary");
        let original = names();
        let error = inspect_loaded_round(&plan, &record, Some(("review", 900)))
            .expect_err("occupied temporary before environment write");
        assert_eq!(error.kind, "round-evidence");
        assert!(error.detail.contains("already exists"));
        assert_eq!(
            fs::read(&temporary).expect("retained temporary"),
            b"retained temporary"
        );
        assert_eq!(
            fs::metadata(&runtime).expect("unchanged inode").ino(),
            metadata.ino()
        );
        assert_eq!(names(), original, "only exact temporary considered");
    }

    /// ´test:unit:round-request-failure-removes-only-its-temporary´
    #[test]
    fn round_request_failure_removes_only_its_temporary() {
        let (_fixture, plan) = client_environment_fixture();
        let record = json!({"mail":[{"step":"review"}],"thread_id":"thread-1", "worker_uid":0});
        let prepared =
            super::prepare_round_request(&plan, &record, "review", 900).expect("prepared");
        let temporary = plan.driver_dir.join(&prepared.temporary);
        let destination = plan.driver_dir.join(&prepared.name);
        fs::write(&destination, b"foreign request").expect("race destination");
        let error = prepared
            .publish()
            .expect_err("rename refuses occupied name");
        assert_eq!(error.kind, "round-evidence");
        assert!(
            !temporary.exists(),
            "failed publication removes its own temporary"
        );
        assert_eq!(
            fs::read(&destination).expect("retained destination"),
            b"foreign request"
        );
        fs::remove_file(&destination).expect("fixture destination");
        let prepared =
            super::prepare_round_request(&plan, &record, "review", 900).expect("retry prepared");
        fs::write(&temporary, b"foreign temporary").expect("race temporary");
        prepared.publish().expect_err("exclusive creation refuses");
        assert_eq!(
            fs::read(&temporary).expect("foreign temporary retained"),
            b"foreign temporary"
        );
        assert!(!destination.exists(), "refusal publishes no request");
        fs::remove_file(&temporary).expect("fixture temporary");
        super::prepare_round_request(&plan, &record, "review", 900)
            .expect("same step reusable")
            .publish()
            .expect("retry publishes");
        assert!(!temporary.exists());
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(destination).expect("published"))
                .expect("request JSON");
        assert_eq!(request["step"], "review");
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
        let mut record = json!({"phase":"preparing","active_round":"work-1","thread_id":"thread-1","worker_uid":owner,"rounds":[{"step":"work-1","budget_seconds":900}],"mail":[{"step":"work-1","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter"},{"step":"work-2","inbox_name":"alpha.2026-01-01T00:00:00.001Z.letter"}]});
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

    /// # Panics
    /// Panics if inspection reopens a replaced reservation pathname after receipt.
    /// ´test:unit:inspection-reservation-retains-received-runs´
    #[test]
    fn inspection_reservation_retains_received_runs() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("runs");
        std::fs::create_dir(&root).expect("runs");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let record = serde_json::json!({"schema":1,"loop":"alpha","run":"R",
            "worker_uid":3000,"phase":"settled"});
        super::publish_reservation(&super::reservation_path(&root, "R"), &record).expect("record");
        let held = std::fs::File::open(&root).expect("held runs");
        let _guard =
            crate::home::activate_handed_home(&root, &held, nix::unistd::Uid::effective().as_raw())
                .expect("activate");
        std::fs::rename(&root, fixture.path().join("retained")).expect("rename");
        std::fs::create_dir(&root).expect("replacement");
        std::fs::write(super::reservation_path(&root, "R"), b"not a reservation")
            .expect("replacement record");
        assert_eq!(
            super::inspection_record(&root, "R").expect("held reservation"),
            record
        );
    }

    /// # Panics
    /// Panics if event reads or request publication reopen the replaced runs pathname.
    /// ´claim:superlooplane:private-round-evidence-retains-replaced-runs´
    /// ´test:unit:private-round-evidence-retains-replaced-runs´
    #[test]
    fn private_round_evidence_retains_replaced_runs() {
        let (fixture, plan) = client_environment_fixture();
        let root = fixture.path().join("runs");
        let held = fs::File::open(&root).expect("root descriptor");
        let owner = nix::unistd::Uid::effective().as_raw();
        let loop_uid = crate::plan::loop_uid(&plan.document).expect("loop identity");
        let _anchor = crate::home::activate_handed_home(&root, &held, owner).expect("root anchor");
        let retained = fixture.path().join("retained-runs");
        fs::rename(&root, &retained).expect("retain received root");
        fs::create_dir_all(root.join("R")).expect("replacement path");
        let directory = retained.join("R");
        let earlier = b"{\"type\":\"thread.started\",\"thread_id\":\"earlier-thread\"}\n";
        fs::write(
            directory.join(".event-start"),
            format!("{}\n", earlier.len()),
        )
        .expect("held boundary");
        fs::write(root.join("R/.event-start"), b"0\n").expect("replacement boundary");
        seed_prior_boundary(&directory, earlier.len(), loop_uid);
        fs::write(
            directory.join("events.jsonl"),
            [
                earlier.as_slice(),
                b"{\"type\":\"thread.started\",\"thread_id\":\"held-thread\"}\n",
            ]
            .concat(),
        )
        .expect("held events");
        for name in [".event-start", "events.jsonl"] {
            nix::unistd::chown(
                &directory.join(name),
                Some(nix::unistd::Uid::from_raw(loop_uid)),
                Some(nix::unistd::Gid::from_raw(loop_uid)),
            )
            .expect("evidence owner");
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
                .expect("evidence mode");
        }
        fs::write(root.join("R/events.jsonl"), b"not held evidence").expect("replacement");
        assert_eq!(
            super::step_event_thread(
                crate::settings::BoxBackend::Codex,
                &plan.driver_dir,
                loop_uid
            )
            .expect("held thread"),
            "held-thread"
        );
        let archives = directory.join("steps");

        nix::unistd::chown(
            &archives,
            Some(nix::unistd::Uid::from_raw(loop_uid)),
            Some(nix::unistd::Gid::from_raw(loop_uid)),
        )
        .expect("archive owner");
        fs::set_permissions(&archives, fs::Permissions::from_mode(0o770))
            .expect("widen archive directory");
        let error = super::step_event_thread(
            crate::settings::BoxBackend::Codex,
            &plan.driver_dir,
            loop_uid,
        )
        .expect_err("writable boundary archive");
        assert_eq!(error.kind, "round-thread");
        assert!(
            error.detail.contains("context-boundary: steps:"),
            "{error:?}"
        );
        fs::set_permissions(&archives, fs::Permissions::from_mode(0o700))
            .expect("restore archive directory");
        let record = json!({"phase":"preparing","active_round":"review",
            "thread_id":"held-thread","worker_uid":3000,
            "rounds":[{"step":"review","budget_seconds":900}],
            "mail":[{"step":"review","inbox_name":"fixture-letter"}]});
        inspect_loaded_round(&plan, &record, Some(("review", 900))).expect("held publication");
        let published: serde_json::Value = serde_json::from_slice(
            &fs::read(directory.join("round-launch-review.json")).expect("held request"),
        )
        .expect("request JSON");
        assert_eq!(published["thread_id"], "held-thread");
        assert!(!root.join("R/round-launch-review.json").exists());
        assert_eq!(
            fs::read(root.join("R/events.jsonl")).expect("replacement survives"),
            b"not held evidence"
        );
    }

    fn seed_prior_boundary(directory: &Path, end: usize, uid: u32) {
        let archives = directory.join("steps");
        let prior = archives.join("earlier");
        fs::create_dir_all(&prior).expect("prior archive");
        fs::write(prior.join("event-start.txt"), b"0\n").expect("prior start");
        fs::write(prior.join("event-end.txt"), format!("{end}\n")).expect("prior end");
        for path in [
            archives,
            prior.clone(),
            prior.join("event-start.txt"),
            prior.join("event-end.txt"),
        ] {
            nix::unistd::chown(
                &path,
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(uid)),
            )
            .expect("prior owner");
            let mode = if path.is_dir() { 0o700 } else { 0o600 };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("prior mode");
        }
    }

    /// # Panics
    /// Panics if the recorded-directory check observes the replacement pathname.
    /// ´test:unit:recorded-step-directory-check-retains-custody´
    #[test]
    fn recorded_step_directory_check_retains_custody() {
        let (fixture, plan) = client_environment_fixture();
        let root = fixture.path().join("runs");
        let path = plan.driver_dir.join("fixture-dispatch");
        fs::create_dir(&path).expect("step directory");
        let loop_uid = crate::plan::loop_uid(&plan.document).expect("loop identity");
        nix::unistd::chown(
            &path,
            Some(nix::unistd::Uid::from_raw(loop_uid)),
            Some(nix::unistd::Gid::from_raw(loop_uid)),
        )
        .expect("step owner");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("step mode");
        let held = fs::File::open(&root).expect("root descriptor");
        let _anchor =
            crate::home::activate_handed_home(&root, &held, nix::unistd::Uid::effective().as_raw())
                .expect("root anchor");
        fs::rename(&root, fixture.path().join("retained-runs")).expect("retain root");
        fs::create_dir_all(root.join("R")).expect("replacement root");
        fs::write(&path, b"not a directory").expect("replacement step");
        let record = json!({"rounds":[{"step":"dispatch","driver_dir":path}]});
        assert_eq!(
            super::recorded_step_dir(&plan, &record, &record["rounds"][0])
                .expect("held recorded directory"),
            path
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
        let record = json!({"phase":"preparing","active_round":"review","thread_id":"thread-1","worker_uid":3000,"rounds":[{"step":"review","budget_seconds":900}],"mail":[{"step":"review","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter"}]});
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
            b"Read /mail/inbox/alpha.2026-01-01T00:00:00.000Z.letter. Step review.",
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
            document: json!({"backend":"codex"}),
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
            Some(&json!({"step":"review","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter","evidence_digest":"a".repeat(64)})),
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
                "--backend",
                "codex",
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
                "/runs/R/mail-review.txt",
                "--step-letter-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Read /mail/inbox/alpha.2026-01-01T00:00:00.000Z.letter. Step review."
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
            document: json!({"backend":"codex"}),
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
            Some(&json!({"step":"review","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter","evidence_digest":"a".repeat(64)})),
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
                "--backend",
                "codex",
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
                "/runs/R/mail-review.txt",
                "--step-letter-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Read /mail/inbox/alpha.2026-01-01T00:00:00.000Z.letter. Step review."
            ]
        );
    }

    /// Pin the launcher's model and effort insertion for a fresh thread.
    ///
    /// # Panics
    /// Panics only if fixture setup or the continuation argument contract fails.
    /// ´test:unit:threadless-continuation-vector-carries-model-and-effort´
    #[test]
    fn threadless_continuation_vector_carries_model_and_effort() {
        let fixture = tempfile::tempdir().expect("fixture");
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: fixture.path().join("R"),
            letter: PathBuf::new(),
            document: json!({"backend":"codex"}),
        };
        let record = json!({
            "phase":"settled", "thread_id":null, "readback_end":"completed",
            "active_round":"dispatch",
            "mail":[{"step":"review","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter","evidence_digest":"a".repeat(64)}],
            "driver_end":{"state":"completed", "successful":false},
            "helper_end":{"state":"completed"},
            "rounds":[{"step":"dispatch", "phase":"failed", "ended_by":"by-report",
                "reply":null, "driver_dir":plan.driver_dir.join("prior-dispatch"),
                "settle_attempts":[{"phase":"complete"}]}]
        });
        let request = super::LaunchRequest::parse(
            &[
                "alpha",
                "R",
                "--round",
                "review",
                "--budget",
                "900",
                "--fresh-thread",
            ]
            .map(str::to_owned),
        )
        .expect("round request");
        let selection = super::super::LaunchModel::select(
            b"Model: gpt-6-sol\nEffort: high\nReview this round.\n",
            None,
            None,
        )
        .expect("round letter selection");
        let (directory, words) = super::continuation_argv(
            &plan,
            &record,
            Path::new("/bin/driver"),
            &request,
            &selection,
        )
        .expect("threadless continuation vector");
        assert_eq!(directory.parent(), Some(plan.driver_dir.as_path()));
        assert!(directory.to_str().expect("fresh path").ends_with("-review"));
        assert_ne!(directory, plan.driver_dir.join("prior-dispatch"));
        assert!(!directory.exists());
        let run_dir = plan.driver_dir.to_str().expect("run path");
        assert_eq!(
            words,
            vec![
                "driver-launch",
                "alpha",
                "R",
                "--driver-bin",
                "/bin/driver",
                "--run-dir",
                run_dir,
                "--backend",
                "codex",
                "--",
                "-t",
                "900",
                "-n",
                "review",
                "-C",
                run_dir,
                "-s",
                "workspace-write",
                "-d",
                directory.to_str().expect("fresh path"),
                "--step-letter",
                plan.driver_dir
                    .join("mail-review.txt")
                    .to_str()
                    .expect("mail evidence"),
                "--step-letter-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "-m",
                "gpt-6-sol",
                "-e",
                "high",
                "Read /mail/inbox/alpha.2026-01-01T00:00:00.000Z.letter. Step review."
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
            document: json!({"backend":"codex","worker_uid":3000}),
        };
        let record = json!({"schema":1,"loop":"alpha","run":"R","phase":"started","active_round":"dispatch","worker_uid":3000,"plan":{"backend":"codex","worker_uid":3000,"home":plan.home,"driver_dir":plan.driver_dir},"mail":[],"rounds":[{"step":"dispatch","phase":"running","driver_dir":step_dir}]});
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
            json!({"rounds":[round],"mail":[{"step":"dispatch","stop":true,"state":"placed"}]});
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
            json!({"rounds":[round],"mail":[{"step":"dispatch","stop":true,"state":"placed"}]});
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
        record["mail"] = json!([{"step":"dispatch","stop":true,"state":"placed"}]);
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
            record["mail"] = json!([{"step":"review","stop":true,"state":"placed"}]);
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

#[cfg(test)]
mod choice_tests {
    use super::*;

    pub(super) fn record() -> Value {
        json!({"schema":1,"loop":"alpha","run":"R","worker_uid":3000,
            "phase":"settled","active_round":"dispatch","readback_end":"completed",
            "thread_id":"old-thread","driver_end":{"state":"completed","successful":false},
            "helper_end":{"state":"completed"},"rounds":[{"step":"dispatch","phase":"failed",
                "driver_dir":"/fixture/R/prior-dispatch","reply":null,"ended_by":"by-budget",
                "thread":{"id":"old-thread","provenance":"observed"},
                "settle_attempts":[{"phase":"complete"}]}],
            "mail":[{"step":"review","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter","evidence_digest":"a".repeat(64)}]})
    }

    /// Every finalized failed outcome needs the loop's choice, with absence explicit.
    ///
    /// # Panics
    /// Panics if choice admission silently chooses or ignores an argument.
    /// ´test:unit:failed-round-choice-is-explicit´
    #[test]
    fn failed_round_choice_is_explicit() {
        let mut saved = record();
        for end in [json!("by-budget"), json!("by-report"), Value::Null] {
            saved["rounds"][0]["ended_by"] = end;
            let error = require_thread_choice(&saved, None).expect_err("no automatic choice");
            for word in [
                "dispatch",
                "old-thread",
                "--fresh-thread",
                "--resume-thread",
            ] {
                assert!(error.detail.contains(word), "{error}");
            }
            assert!(require_thread_choice(&saved, Some(ThreadChoice::Fresh)).expect("fresh"));
            assert!(!require_thread_choice(&saved, Some(ThreadChoice::Resume)).expect("resume"));
        }
        saved["rounds"][0]["thread"] = json!({"id":null,"provenance":"absent"});
        assert!(
            require_thread_choice(&saved, None)
                .expect_err("explicit absence")
                .detail
                .contains("only --fresh-thread")
        );
        assert!(
            require_thread_choice(&saved, Some(ThreadChoice::Resume))
                .expect_err("no recorded thread")
                .detail
                .contains("no recorded thread")
        );
        assert!(require_thread_choice(&saved, Some(ThreadChoice::Fresh)).expect("only fresh"));
        saved["rounds"][0]["phase"] = json!("settled");
        saved["rounds"][0]["reply"] = json!({"bytes":1});
        for choice in [ThreadChoice::Fresh, ThreadChoice::Resume] {
            assert_eq!(
                require_thread_choice(&saved, Some(choice))
                    .expect_err("choice not owed")
                    .kind,
                "round-choice"
            );
        }
        assert!(!require_thread_choice(&saved, None).expect("ordinary resume"));
    }

    /// Choice admission consults only finalized settled rounds, not retained attempts.
    /// ´test:unit:failed-round-choice-ignores-attempt-evidence´
    #[test]
    fn failed_round_choice_ignores_attempt_evidence() {
        let mut saved = record();
        saved["dispatch_intent"] = json!({"nonce":"old"});
        assert!(
            require_thread_choice(&saved, None).is_err(),
            "settled failure still owes choice"
        );
        saved["phase"] = json!("preparing");
        assert!(
            !failed_continuation(&saved),
            "retained attempt is not finalized"
        );
        assert!(!require_thread_choice(&saved, None).expect("no choice for interrupted recovery"));
        assert!(require_thread_choice(&saved, Some(ThreadChoice::Fresh)).is_err());
        saved["phase"] = json!("settled");
        saved["rounds"][0]["phase"] = json!("settled");
        saved["rounds"][0]["reply"] = json!({"bytes":1});
        assert!(!require_thread_choice(&saved, None).expect("intent cannot create failed choice"));
    }

    /// The enclosing settled phase is required even with a completed failed row.
    /// ´test:unit:failed-round-choice-requires-settled-reservation´
    #[test]
    fn failed_round_choice_requires_settled_reservation() {
        let mut saved = record();
        assert!(failed_continuation(&saved), "settled failed control");
        for phase in ["failed", "preparing", "started", "retired"] {
            saved["phase"] = json!(phase);
            assert!(
                !failed_continuation(&saved),
                "outer {phase} cannot owe a choice"
            );
            assert!(!require_thread_choice(&saved, None).expect("no choice gate"));
            assert_eq!(
                require_thread_choice(&saved, Some(ThreadChoice::Fresh))
                    .expect_err("choice unavailable outside settlement")
                    .kind,
                "round-choice"
            );
        }
        saved["phase"] = json!("settled");
        assert!(failed_continuation(&saved), "row was never changed");
    }

    /// A fresh request retains the old reservation identity until its own event is read.
    ///
    /// # Panics
    /// Panics if settlement uses a prior thread or changes it without a start event.
    /// ´test:unit:failed-round-fresh-thread-changes-only-with-own-start´
    #[test]
    fn failed_round_fresh_thread_changes_only_with_own_start() {
        use std::os::unix::fs::PermissionsExt as _;
        for backend in ["codex", "claude"] {
            let root = tempfile::tempdir().expect("fixture");
            let plan = Plan {
                home: root.path().join("home"),
                driver_dir: root.path().join("R"),
                letter: PathBuf::new(),
                document: json!({"backend":backend}),
            };
            let directory = plan.driver_dir.join("new-review");
            std::fs::create_dir_all(&directory).expect("directory");
            std::fs::write(directory.join(".event-start"), b"0\n").expect("boundary");
            std::fs::write(directory.join("events.jsonl"), b"").expect("before start");
            let report = directory.join("run-report.txt");
            std::fs::write(
                &report,
                format!(
                    "RUN-REPORT lane=review exit=0 verdict=ok dir={}\n",
                    directory.display()
                ),
            )
            .expect("report");
            std::fs::set_permissions(&report, std::fs::Permissions::from_mode(0o600))
                .expect("report mode");
            let mut saved = record();
            saved["rounds"][0]["driver_dir"] = json!(plan.driver_dir.join("prior-dispatch"));
            let request = LaunchRequest::parse(
                &["alpha", "R", "--round", "review", "--fresh-thread"].map(str::to_owned),
            )
            .expect("request");
            let round =
                continuation_round(&saved, &request, &directory, &saved["mail"][0]).expect("next");
            saved["rounds"].as_array_mut().expect("rounds").push(round);
            saved["rounds"][1]["phase"] = json!("awaiting-settlement");
            saved["phase"] = json!("started");
            saved["active_round"] = json!("review");
            let path = reservation_path(root.path(), "R");
            publish_reservation(&path, &saved).expect("new round");
            let reply = json!({"bytes":1});
            record_settlement_with_recovery(&plan, "R", &reply, false).expect_err("no start yet");
            assert_eq!(
                read_reservation(&path).expect("read").expect("saved")["thread_id"],
                "old-thread"
            );
            let event = if backend == "codex" {
                json!({"type":"thread.started","thread_id":"new-thread"})
            } else {
                json!({"type":"system","subtype":"init","session_id":"new-thread"})
            };
            std::fs::write(directory.join("events.jsonl"), format!("{event}\n"))
                .expect("own event");
            assert_eq!(
                recovery_thread(&plan, &saved, &saved["rounds"][1])
                    .expect("fresh recovery reads own start"),
                "new-thread"
            );
            publish_reservation(&path, &saved).expect("settlement input");
            record_settlement_with_recovery(&plan, "R", &reply, false).expect("own thread settles");
            assert_eq!(
                read_reservation(&path).expect("read").expect("saved")["thread_id"],
                "new-thread"
            );
        }
    }

    /// The selected request and prospective record agree without erasing the old thread.
    ///
    /// # Panics
    /// Panics if fresh and resume can be confused or previews consume the choice.
    /// ´test:unit:failed-round-choice-controls-request-and-preview´
    #[test]
    fn failed_round_choice_controls_request_and_preview() {
        let root = tempfile::tempdir().expect("fixture");
        let plan = Plan {
            home: root.path().join("home"),
            driver_dir: root.path().join("R"),
            letter: PathBuf::new(),
            document: json!({"backend":"codex"}),
        };
        let mut saved = record();
        saved["rounds"][0]["driver_dir"] = json!(plan.driver_dir.join("prior-dispatch"));
        let before = serde_json::to_vec(&saved).expect("before");
        for (flag, expected) in [
            ("--fresh-thread", Value::Null),
            ("--resume-thread", json!("old-thread")),
        ] {
            let request =
                LaunchRequest::parse(&["alpha", "R", "--round", "review", flag].map(str::to_owned))
                    .expect("choice");
            let next = preflight_record(
                &plan.driver_dir,
                &saved,
                "review",
                3600,
                request.thread_choice,
            )
            .expect("prospective");
            assert_eq!(
                next["thread_id"], "old-thread",
                "fresh must not erase prior thread"
            );
            let text: Value =
                serde_json::from_str(&request_text(&plan, &next, "review", 3600).expect("request"))
                    .expect("json");
            assert_eq!(text["thread_id"], expected, "chosen request thread");
            let preview = choice_preview(
                &saved,
                request.thread_choice,
                &json!({"present":true}),
                "review",
            );
            assert_eq!(preview["selection"], flag);
            assert_eq!(preview["recorded_thread"], "old-thread");
            assert_eq!(preview["consumed"], false);
            assert!(
                preview["fresh_prompt"]
                    .as_str()
                    .expect("prompt")
                    .contains("no old thread")
            );
        }
        let refusal = choice_preview(&saved, None, &json!({"present":false}), "review");
        assert!(refusal["selection"].is_null());
        assert_eq!(refusal["fresh_letter"], saved["mail"][0]["inbox_name"]);
        assert_eq!(refusal["next_round"], "review");
        assert_eq!(refusal["thread_files"]["present"], false);
        assert_eq!(serde_json::to_vec(&saved).expect("after"), before);
        for words in [
            vec!["alpha", "R", "--letter", "letter", "--fresh-thread"],
            vec![
                "alpha",
                "R",
                "--round",
                "review",
                "--fresh-thread",
                "--resume-thread",
            ],
        ] {
            assert_eq!(
                LaunchRequest::parse(&words.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .expect_err("inapplicable choice")
                    .kind,
                "round-choice"
            );
        }
    }
}
