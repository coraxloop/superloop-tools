//! Persist and read the exact report returned by each successful launch round.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::Path;

use nix::fcntl::AtFlags;
use nix::fcntl::{OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{SFlag, fstat, fstatat};
use nix::unistd::{Uid, UnlinkatFlags, unlinkat};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{error::LaneError, home, plan::Plan, valid_run_name};

use super::{checkout, follow::recorded_directory, letters::valid_step};

pub(crate) const MAX_LAUNCH_REPORT_BYTES: u64 = 4_194_304;

pub(crate) fn archive_preview(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
) -> Result<Value, LaneError> {
    archive_source(runs, run, step).map(|(_, preview, _)| preview)
}

fn archive_source(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
) -> Result<(File, Value, Vec<u8>), LaneError> {
    let source = name(run, step)?;
    let fd = openat2(
        runs,
        source.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("launch-report", error.to_string()))?;
    let meta = fstat(&fd).map_err(|error| LaneError::input("launch-report", error.to_string()))?;
    let mut bytes = Vec::new();
    let mut file = File::from(fd);
    (&mut file)
        .take(MAX_LAUNCH_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("launch-report", error.to_string()))?;
    if bytes.len() as u64 > MAX_LAUNCH_REPORT_BYTES {
        return Err(LaneError::input(
            "launch-report-size",
            "failed report exceeds reader bound",
        ));
    }
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        let _written = write!(digest, "{byte:02x}");
    }
    let target = format!(
        "{source}.failed-unix-{}-{}-{digest}",
        meta.st_mtime, meta.st_mtime_nsec
    );
    Ok((
        file,
        serde_json::json!({"source":source,"target":target,"sha256":digest}),
        bytes,
    ))
}

fn rename_archive(runs: &OwnedFd, held: &File, archive: &Value) -> Result<(), LaneError> {
    let source = archive["source"]
        .as_str()
        .ok_or_else(|| LaneError::input("launch-report", "archive source is absent"))?;
    let target = archive["target"]
        .as_str()
        .ok_or_else(|| LaneError::input("launch-report", "archive target is absent"))?;
    let opened =
        fstat(held).map_err(|error| LaneError::input("launch-report", error.to_string()))?;
    let current = fstatat(runs, source, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| LaneError::input("launch-report", error.to_string()))?;
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino) {
        return Err(LaneError::input(
            "launch-report",
            "failed recovery report identity changed",
        ));
    }
    renameat2(runs, source, runs, target, RenameFlags::RENAME_NOREPLACE)
        .map_err(|error| LaneError::operation("launch-report", format!("{target}: {error}")))
}

pub(crate) fn round_dir(
    plan: &Plan,
    record: &Value,
    step: Option<&str>,
) -> Result<String, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("launch-report", "round list is absent"))?;
    let round = rounds
        .iter()
        .rev()
        .find(|round| step.is_none_or(|selected| round["step"] == selected))
        .ok_or_else(|| LaneError::input("launch-report", "report round is absent"))?;
    Ok(recorded_directory(plan, round)?.display().to_string())
}

pub(crate) fn name(run: &str, step: Option<&str>) -> Result<String, LaneError> {
    if !valid_run_name(run) {
        return Err(LaneError::input(
            "read-launch-report",
            "run name is invalid",
        ));
    }
    if let Some(step) = step {
        valid_step(step).map_err(|error| {
            LaneError::input(
                "read-launch-report",
                format!("round {step:?}: {}", error.line()),
            )
        })?;
        Ok(format!(".report={run}={step}.json"))
    } else {
        Ok(format!(".report={run}.json"))
    }
}

/// Publish the report beneath the runs descriptor before its caller returns it.
///
/// # Errors
///
/// Refuses an invalid name, oversized report, or incomplete publication.
pub(crate) fn publish(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
    report: &Value,
) -> Result<(), LaneError> {
    publish_replacing(runs, run, step, report, None)
}

pub(crate) fn publish_replacing(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
    report: &Value,
    prior: Option<&Value>,
) -> Result<(), LaneError> {
    let final_name = name(run, step)?;
    let bytes = serde_json::to_vec(report)
        .map_err(|error| LaneError::operation("launch-report", error.to_string()))?;
    if bytes.len() as u64 > MAX_LAUNCH_REPORT_BYTES {
        return Err(LaneError::input(
            "launch-report-size",
            format!("{final_name} exceeds {MAX_LAUNCH_REPORT_BYTES} bytes"),
        ));
    }
    if let Some(prior) = prior {
        if read_bound(runs, run, step, Uid::effective().as_raw())? != *prior {
            return Err(LaneError::input(
                "launch-report",
                "failed recovery report changed",
            ));
        }
        let (held, archive, observed) = archive_source(runs, run, step)?;
        if serde_json::from_slice::<Value>(&observed).ok().as_ref() != Some(prior) {
            return Err(LaneError::input(
                "launch-report",
                "failed recovery report changed",
            ));
        }
        rename_archive(runs, &held, &archive)?;
    } else {
        require_unoccupied(runs, run, step)?;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| LaneError::operation("launch-report", error.to_string()))?
        .as_nanos();
    let temporary = format!(".report-tmp={}-{nanos}.tmp", std::process::id());
    let fd = openat2(
        runs,
        temporary.as_str(),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("launch-report", format!("{final_name}: {error}")))?;
    let mut file = File::from(fd);
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| LaneError::operation("launch-report", format!("{final_name}: {error}")))?;
    if let Err(error) = renameat2(
        runs,
        temporary.as_str(),
        runs,
        final_name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    ) {
        let _ignored = unlinkat(runs, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
        return Err(LaneError::operation(
            "launch-report",
            format!("{final_name}: {error}"),
        ));
    }
    File::from(
        nix::unistd::dup(runs)
            .map_err(|error| LaneError::operation("launch-report", error.to_string()))?,
    )
    .sync_all()
    .map_err(|error| LaneError::operation("launch-report", format!("{final_name}: {error}")))
}

/// Resolve a report name beneath a held runs root and refuse an occupied name.
///
/// # Errors
///
/// Refuses an invalid or occupied name or a failed descriptor lookup.
pub(crate) fn require_unoccupied(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
) -> Result<String, LaneError> {
    let final_name = name(run, step)?;
    match openat2(
        runs,
        final_name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(_) => {
            return Err(LaneError::input(
                "launch-report",
                format!("{final_name}: report already exists"),
            ));
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(error) => {
            return Err(LaneError::input(
                "launch-report",
                format!("{final_name}: {error}"),
            ));
        }
    }
    Ok(final_name)
}

#[cfg(test)]
pub(crate) fn finish(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
    report: Value,
) -> Result<Value, LaneError> {
    finish_with_fallback(runs, run, step, report, &mut |_| {})
}

pub(crate) fn finish_with_fallback(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
    report: Value,
    on_failure: &mut dyn FnMut(&Value),
) -> Result<Value, LaneError> {
    if let Err(error) = publish(runs, run, step, &report) {
        on_failure(&report);
        return Err(LaneError {
            status: error.status,
            kind: "launch-report",
            detail: error.line(),
        });
    }
    Ok(report)
}

fn has_exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
    })
}

fn recovered_inner_shape(value: &Value) -> bool {
    const LAUNCH: [&str; 5] = [
        "state",
        "phase",
        "ended_by",
        "attempt_evidence",
        "observer_socket",
    ];
    const EVIDENCE: [&str; 3] = ["state", "attempts", "container_absence_checked"];
    const ATTEMPT: [&str; 5] = [
        "attempt",
        "status",
        "removal",
        "error_free",
        "capacity_evidence",
    ];
    const SETTLE: [&str; 4] = ["state", "preview_sha256", "phase", "detail"];
    match value["state"].as_str() {
        Some("completed-interrupted-settlement") => {
            let evidence = &value["attempt_evidence"];
            let mut keys = LAUNCH.to_vec();
            let sockets_valid = value.get("removed_helper_sockets").is_none_or(|removed| {
                keys.push("removed_helper_sockets");
                removed.as_array().is_some_and(|paths| {
                    !paths.is_empty()
                        && paths.len() <= 2
                        && paths.iter().all(|path| {
                            path.as_str()
                                .is_some_and(|path| Path::new(path).is_absolute())
                        })
                        && paths.first() != paths.get(1)
                })
            });
            has_exact_keys(value, &keys)
                && sockets_valid
                && matches!(value["phase"].as_str(), Some("settled" | "failed"))
                && (value["ended_by"].is_string() || value["ended_by"].is_null())
                && value["observer_socket"].is_object()
                && has_exact_keys(evidence, &EVIDENCE)
                && matches!(
                    evidence["state"].as_str(),
                    Some("complete" | "absence-confirmed-with-missing-evidence")
                )
                && evidence["container_absence_checked"].is_boolean()
                && evidence["attempts"].as_array().is_some_and(|attempts| {
                    attempts.iter().all(|attempt| {
                        has_exact_keys(attempt, &ATTEMPT)
                            && attempt["attempt"].is_u64()
                            && attempt["status"].as_i64().is_some()
                            && attempt["removal"].is_string()
                            && attempt["error_free"].is_boolean()
                            && (attempt["capacity_evidence"].is_boolean()
                                || attempt["capacity_evidence"].is_null())
                    })
                })
        }
        Some("completed-settle-round") => {
            has_exact_keys(value, &SETTLE)
                && value["preview_sha256"].as_str().is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                && value["phase"] == "complete"
                && value["detail"].is_null()
        }
        _ => false,
    }
}

pub(crate) fn credential_publication(record: &Value) -> Result<Value, LaneError> {
    let evidence = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .map(|round| &round["credential_publication"])
        .filter(|value| valid_measured_publication(value))
        .ok_or_else(|| {
            LaneError::input(
                "launch-report",
                "round credential publication is absent or malformed",
            )
        })?;
    Ok(evidence.clone())
}

fn valid_measured_publication(value: &Value) -> bool {
    has_exact_keys(value, &["source_inode", "published_unix_ns"])
        && value["source_inode"]
            .as_u64()
            .is_some_and(|value| value > 0)
        && value["published_unix_ns"]
            .as_u64()
            .is_some_and(|value| value > 0)
}

const HISTORICAL_PUBLICATION_REASON: &str = "written before publication evidence existed";

fn unmeasured_publication() -> Value {
    serde_json::json!({"state":"unmeasured","reason":HISTORICAL_PUBLICATION_REASON,
        "source_inode":null,"published_unix_ns":null})
}

fn valid_publication(value: &Value) -> bool {
    valid_measured_publication(value) || *value == unmeasured_publication()
}

fn exact_shape(report: &Value, step: Option<&str>) -> bool {
    const FIRST: [&str; 15] = [
        "credential_publication",
        "schema",
        "command",
        "dry_run",
        "observe",
        "enforcing",
        "observed",
        "home",
        "driver_dir",
        "round_dir",
        "preparation",
        "driver_report",
        "settlement",
        "evidence",
        "wall_seconds",
    ];
    const RESUMED: [&str; 13] = [
        "credential_publication",
        "schema",
        "command",
        "dry_run",
        "round",
        "round_dir",
        "budget_seconds",
        "letter",
        "letter_reconciliation",
        "thread_id",
        "driver_report",
        "settlement",
        "wall_seconds",
    ];
    const RECOVERED: [&str; 8] = [
        "schema",
        "command",
        "dry_run",
        "interrupted_settlement",
        "home",
        "driver_dir",
        "round_dir",
        "wall_seconds",
    ];
    let Some(fields) = report.as_object() else {
        return false;
    };
    let recovered = fields.contains_key("interrupted_settlement");
    let expected = if recovered {
        RECOVERED.as_slice()
    } else if step.is_some() {
        RESUMED.as_slice()
    } else {
        FIRST.as_slice()
    };
    if fields.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != expected.iter().copied().collect::<BTreeSet<_>>()
        || report["schema"] != 1
        || report["command"] != "launch"
        || report["dry_run"] != false
        || !report["round_dir"].is_string()
        || !report["wall_seconds"].is_number()
        || (!recovered
            && (!report["driver_report"].is_string()
                || !report["settlement"].is_object()
                || !valid_publication(&report["credential_publication"])))
    {
        return false;
    }
    if recovered {
        return recovered_inner_shape(&report["interrupted_settlement"])
            && report["home"].is_string()
            && report["driver_dir"].is_string();
    }
    step.map_or_else(
        || {
            report["observe"].is_boolean()
                && report["enforcing"].is_boolean()
                && (report["observed"].is_object() || report["observed"].is_null())
                && report["home"].is_string()
                && report["driver_dir"].is_string()
                && report["preparation"].is_string()
                && report["evidence"] == "driver directory outside home"
        },
        |step| {
            report["round"] == step
                && report["budget_seconds"].is_u64()
                && report["letter"].is_string()
                && report["letter_reconciliation"].is_array()
                && report["thread_id"].is_string()
        },
    )
}

fn read_named(runs: &OwnedFd, name: &str, owner: u32) -> Result<(File, Vec<u8>, Value), LaneError> {
    let fd = openat2(
        runs,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("read-launch-report", format!("{name}: {error}")))?;
    let stat = fstat(&fd)
        .map_err(|error| LaneError::input("read-launch-report", format!("{name}: {error}")))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || u64::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > MAX_LAUNCH_REPORT_BYTES)
    {
        return Err(LaneError::input(
            "read-launch-report",
            format!("{name}: owner, mode, link count, size, or type differs"),
        ));
    }
    let mut bytes = Vec::new();
    let mut file = File::from(fd);
    (&mut file)
        .take(MAX_LAUNCH_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("read-launch-report", format!("{name}: {error}")))?;
    if bytes.len() as u64 > MAX_LAUNCH_REPORT_BYTES {
        return Err(LaneError::input(
            "read-launch-report",
            format!("{name}: report exceeds {MAX_LAUNCH_REPORT_BYTES} bytes"),
        ));
    }
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("read-launch-report", format!("{name}: {error}")))?;
    Ok((file, bytes, report))
}

pub(crate) fn read_bound(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
    owner: u32,
) -> Result<Value, LaneError> {
    let name = name(run, step)?;
    let (_, _, report) = read_named(runs, &name, owner)?;
    if report.get("round_dir").is_none() {
        return Err(LaneError::input(
            "read-launch-report",
            format!("{name}: round_dir is absent"),
        ));
    }
    if report.get("interrupted_settlement").is_none()
        && report.get("credential_publication").is_none()
    {
        return Err(LaneError::input(
            "read-launch-report",
            format!(
                "{name}: credential_publication is absent; preview superloop-lane rewrite-launch-reports LOOP --dry-run, then run superloop-lane rewrite-launch-reports LOOP once at an idle boundary; historical publication will be explicitly unmeasured"
            ),
        ));
    }
    if !exact_shape(&report, step) {
        return Err(LaneError::input(
            "read-launch-report",
            format!("{name}: report shape differs"),
        ));
    }
    Ok(report)
}

pub(crate) fn present(
    runs: &OwnedFd,
    run: &str,
    step: Option<&str>,
    owner: u32,
) -> Result<bool, LaneError> {
    let name = name(run, step)?;
    match openat2(
        runs,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(_) => read_bound(runs, run, step, owner).map(|_| true),
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(LaneError::input(
            "read-launch-report",
            format!("{name}: {error}"),
        )),
    }
}

/// Read one persisted launch or resumed-round report through held run custody.
///
/// # Errors
///
/// Refuses a missing reservation or report, an invalid name, or malformed report bytes.
pub fn read(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: Option<&str>,
) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    let (_, settings) = crate::load_plan_for_record(owner_home, loop_name, run, (caller, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("read-launch-report", "runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, caller, 0)?;
    let (record, _) = checkout::read_record_bound(&runs, run, caller)?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "read-launch-report",
            "reservation identity differs",
        ));
    }
    read_bound(&runs, run, step, caller)
}

fn rewrite_refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("rewrite-launch-reports", detail)
}

fn report_identity(filename: &str) -> Result<(String, Option<String>), LaneError> {
    let middle = filename
        .strip_prefix(".report=")
        .and_then(|part| part.strip_suffix(".json"))
        .ok_or_else(|| rewrite_refusal(format!("{filename}: report name differs")))?;
    let (run, step) = middle
        .split_once('=')
        .map_or((middle, None), |(run, step)| (run, Some(step)));
    if name(run, step)? != filename {
        return Err(rewrite_refusal(format!(
            "{filename}: report identity differs"
        )));
    }
    Ok((run.to_owned(), step.map(str::to_owned)))
}

type ReportInventory = BTreeMap<String, (String, Option<String>)>;

fn insert_report(
    reports: &mut ReportInventory,
    filename: &str,
    identity: (String, Option<String>),
) -> Result<(), LaneError> {
    if reports
        .get(filename)
        .is_some_and(|prior| *prior != identity)
    {
        return Err(rewrite_refusal(format!(
            "{filename}: conflicting report identities"
        )));
    }
    reports.insert(filename.to_owned(), identity);
    Ok(())
}

fn journal_reports(
    record: &Value,
    root: &Path,
    names: &BTreeSet<String>,
    reports: &mut ReportInventory,
) -> Result<(), LaneError> {
    if record
        .get("retry_retirements")
        .is_some_and(|value| !value.is_null() && !value.is_array())
    {
        return Err(rewrite_refusal(
            "retry retirement journals are not an array",
        ));
    }
    for journal in std::iter::once(&record["current_retirement"])
        .chain(std::iter::once(&record["dead_preparation_retired"]))
        .chain(record["retry_retirements"].as_array().into_iter().flatten())
    {
        if journal.is_null() {
            continue;
        }
        let paths = journal["planned_paths"]
            .as_array()
            .ok_or_else(|| rewrite_refusal("retirement planned paths are not an array"))?;
        for pair in paths {
            let source = Path::new(
                pair["source"]
                    .as_str()
                    .ok_or_else(|| rewrite_refusal("retirement source is absent"))?,
            );
            let source_name = source
                .file_name()
                .and_then(|part| part.to_str())
                .ok_or_else(|| rewrite_refusal("retirement source name is absent"))?;
            if !source_name.starts_with(".report=") {
                continue;
            }
            let identity = report_identity(source_name)?;
            let target = Path::new(pair["target"].as_str().unwrap_or_default());
            let target_name = target
                .file_name()
                .and_then(|part| part.to_str())
                .ok_or_else(|| rewrite_refusal("retired report target is absent"))?;
            if source.parent() != Some(root)
                || target.parent() != Some(root)
                || record["run"] != identity.0
                || !target_name.starts_with(&format!(".retired-{}-", identity.0))
            {
                return Err(rewrite_refusal(format!(
                    "{}: retired report custody differs",
                    target.display()
                )));
            }
            // A partially completed retirement may still have the source. A reused
            // run can also have both names; the direct inventory covers the source.
            if names.contains(target_name) {
                insert_report(reports, target_name, identity)?;
            } else if !names.contains(source_name) {
                return Err(rewrite_refusal(format!(
                    "{}: neither retained report name exists",
                    target.display()
                )));
            }
        }
    }
    Ok(())
}

fn report_inventory(
    runs: &OwnedFd,
    root: &Path,
    loop_name: &str,
    owner: u32,
) -> Result<ReportInventory, LaneError> {
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", runs.as_raw_fd()))
        .map_err(|error| rewrite_refusal(error.to_string()))?
    {
        if names.len() >= 65_536 {
            return Err(rewrite_refusal("runs inventory exceeds 65536 entries"));
        }
        let entry = entry.map_err(|error| rewrite_refusal(error.to_string()))?;
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| rewrite_refusal("runs inventory name is not UTF-8"))?;
        names.insert(filename);
    }
    let mut reports = ReportInventory::new();
    for filename in &names {
        if filename.starts_with(".report=")
            && Path::new(filename)
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            insert_report(&mut reports, filename, report_identity(filename)?)?;
        }
        let active = filename
            .strip_prefix(".reservation-")
            .and_then(|part| part.strip_suffix(".json"));
        let retired = super::census::retired_name(filename);
        if active.is_none() && !retired {
            continue;
        }
        let (_, _, record) = read_named(runs, filename, owner)?;
        if record["schema"] != 1
            || record["loop"] != loop_name
            || !record["run"].as_str().is_some_and(valid_run_name)
            || active.is_some_and(|run| record["run"] != run)
            || (retired
                && (record["phase"] != "retired"
                    || record["current_retirement"]["reservation_path"]["target"]
                        != serde_json::json!(root.join(filename))))
        {
            return Err(rewrite_refusal(format!(
                "{filename}: reservation identity differs"
            )));
        }
        journal_reports(&record, root, &names, &mut reports)
            .map_err(|error| rewrite_refusal(format!("{filename}: {}", error.detail)))?;
    }
    Ok(reports)
}

fn converted_report(report: &Value, step: Option<&str>) -> Result<Option<Value>, LaneError> {
    if report.get("credential_publication").is_some()
        || report.get("interrupted_settlement").is_some()
    {
        if !exact_shape(report, step) {
            return Err(rewrite_refusal("current report shape differs"));
        }
        return Ok(None);
    }
    let mut after = report.clone();
    let object = after
        .as_object_mut()
        .ok_or_else(|| rewrite_refusal("historical report is not an object"))?;
    object.insert("credential_publication".into(), unmeasured_publication());
    if !exact_shape(&after, step) {
        return Err(rewrite_refusal(
            "report is not the exact publication-evidence predecessor",
        ));
    }
    if after.to_string().len() as u64 > MAX_LAUNCH_REPORT_BYTES {
        return Err(rewrite_refusal("converted report exceeds reader bound"));
    }
    Ok(Some(after))
}

fn replace_report(
    runs: &OwnedFd,
    filename: &str,
    held: &File,
    after: &Value,
) -> Result<(), LaneError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| rewrite_refusal(error.to_string()))?
        .as_nanos();
    let temporary = format!(".report-rewrite-{}-{nanos}.tmp", std::process::id());
    let fd = openat2(
        runs,
        temporary.as_str(),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| rewrite_refusal(error.to_string()))?;
    let result = (|| {
        let bytes =
            serde_json::to_vec(after).map_err(|error| rewrite_refusal(error.to_string()))?;
        let mut output = File::from(fd);
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| rewrite_refusal(error.to_string()))?;
        let opened = fstat(held).map_err(|error| rewrite_refusal(error.to_string()))?;
        let current = fstatat(runs, filename, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| rewrite_refusal(error.to_string()))?;
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino) {
            return Err(rewrite_refusal("report inode changed before replacement"));
        }
        renameat2(
            runs,
            temporary.as_str(),
            runs,
            filename,
            RenameFlags::empty(),
        )
        .map_err(|error| rewrite_refusal(error.to_string()))?;
        File::from(nix::unistd::dup(runs).map_err(|error| rewrite_refusal(error.to_string()))?)
            .sync_all()
            .map_err(|error| rewrite_refusal(error.to_string()))
    })();
    if result.is_err() {
        let _ignored = unlinkat(runs, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

/// Explicitly rewrite retained historical reports under exclusive loop custody.
///
/// # Errors
/// Refuses busy configuration, unsafe custody, unknown report shapes, or changed files.
pub fn rewrite(owner_home: &Path, loop_name: &str, dry_run: bool) -> Result<Value, LaneError> {
    let begun = std::time::Instant::now();
    loop_home::validate_name(loop_name).map_err(|error| rewrite_refusal(error.message()))?;
    let config = owner_home.join(".config/loops").join(loop_name);
    // Preview must exclude launchers too: a shared preview would race publication.
    let _configuration = crate::install::lock_loop_config(&config, false)?;
    let settings =
        crate::settings::Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| rewrite_refusal("runs_root absent"))?;
    let owner = Uid::effective().as_raw();
    let _verified = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let runs = super::lock_runs_root(root, true, owner)?;
    let inventory = report_inventory(&runs, root, loop_name, owner)?;
    let mut candidates = Vec::new();
    // Validate every report before the first write; retain only hashes and names.
    for (filename, (_, step)) in &inventory {
        let (_, bytes, report) = read_named(&runs, filename, owner)?;
        if converted_report(&report, step.as_deref())
            .map_err(|error| rewrite_refusal(format!("{filename}: {}", error.detail)))?
            .is_some()
        {
            candidates.push((filename, step, Sha256::digest(&bytes)));
        }
    }
    let mut reports = Vec::new();
    for (filename, step, digest) in candidates {
        if !dry_run {
            let (held, bytes, report) = read_named(&runs, filename, owner)?;
            if Sha256::digest(&bytes) != digest {
                return Err(rewrite_refusal(format!(
                    "{filename}: report changed during rewrite"
                )));
            }
            let after = converted_report(&report, step.as_deref())?
                .ok_or_else(|| rewrite_refusal(format!("{filename}: predecessor changed")))?;
            replace_report(&runs, filename, &held, &after)
                .map_err(|error| rewrite_refusal(format!("{filename}: {}", error.detail)))?;
        }
        reports.push(serde_json::json!({"path":root.join(filename),
            "verdict":if dry_run { "would-rewrite" } else { "rewritten" },
            "credential_publication":unmeasured_publication()}));
    }
    Ok(
        serde_json::json!({"schema":1,"command":"rewrite-launch-reports","loop":loop_name,
        "dry_run":dry_run,"changed":if dry_run { 0 } else { reports.len() },
        "would_change":reports.len(),"reports":reports,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests;
