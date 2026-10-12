//! Read each round's owner record and mailbox observations before its event region.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read as _, Write};
use std::os::fd::AsRawFd as _;
use std::os::fd::FromRawFd as _;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::{build, error::LaneError, home, plan::Plan};

use super::{checkout, letters::valid_step};

// The child capture allows 2,097,152 bytes for the whole private response.
// Leave 524,288 bytes of headroom beyond this serialized response limit.
const MAX_PRIVATE_RESPONSE_BYTES: usize = 1_572_864;
// Keep at most 524,288 serialized event-array bytes from the newest events.
const MAX_EVENT_DELTA_BYTES: usize = 524_288;

/// Render the protected round record before its driver observations.
///
/// # Errors
///
/// Refuses a missing run, malformed observation, changed home or invalid event boundary.
pub fn run(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    selected: Option<&str>,
    round_only: bool,
    writer: &mut impl Write,
) -> Result<(), LaneError> {
    let caller = Uid::effective().as_raw();
    let (plan, settings) = crate::load_plan_for_record(owner_home, loop_name, run, (caller, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("follow-record", "runs root is absent"))?;
    let runs_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, caller, 0)?;
    let (record, identity) = checkout::read_record_bound(&runs_fd, run, caller)?;
    run_bound_to_writer(
        owner_home, loop_name, run, selected, round_only, &plan, root, &runs_fd, &record,
        &identity, writer,
    )
}

/// Render one bound reservation without reopening its pathname.
///
/// # Errors
///
/// Refuses a changed identity, invalid round, or failed private evidence read.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_bound(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    selected: Option<&str>,
    plan: &Plan,
    root: &Path,
    runs_fd: &OwnedFd,
    record: &Value,
    identity: &str,
) -> Result<String, LaneError> {
    let mut output = Vec::new();
    run_bound_to_writer(
        owner_home,
        loop_name,
        run,
        selected,
        false,
        plan,
        root,
        runs_fd,
        record,
        identity,
        &mut output,
    )?;
    String::from_utf8(output)
        .map_err(|error| LaneError::operation("follow-output", error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn run_bound_to_writer(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    selected: Option<&str>,
    round_only: bool,
    plan: &Plan,
    root: &Path,
    runs_fd: &OwnedFd,
    record: &Value,
    identity: &str,
    writer: &mut impl Write,
) -> Result<(), LaneError> {
    if let Some(step) = selected {
        valid_step(step)?;
    }
    let caller = Uid::effective().as_raw();
    validate_record(plan, record, loop_name, run)?;
    if round_only {
        return run_from_record(plan, record, selected, writer, true, |_, _| {
            unreachable!("round-only never invokes the private reader")
        });
    }
    let podman = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("follow-record", "container program is absent"))?,
    );
    crate::pinned::owner_executable(&podman, caller)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("follow-program", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, caller)?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, caller, 0)?;
    let environment = super::launch_environment(owner_home)?;
    run_from_record(plan, record, selected, writer, false, |step, directory| {
        let argv = private_request(
            &exe_word, owner_home, loop_name, run, step, directory, identity,
        )?;
        build::run_checked_with_private_launch(
            &podman,
            argv,
            &environment,
            owner_home,
            60,
            "follow-private",
            &verified_home,
            root,
            runs_fd,
            None,
        )
    })
}

/// Read the last round's context record through the private loop-uid walk.
///
/// # Errors
///
/// Refuses a missing or malformed context record and changed round identity.
pub fn context(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    let (plan, settings) = crate::load_plan_for_record(owner_home, loop_name, run, (caller, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-context", "runs root is absent"))?;
    let runs_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, caller, 0)?;
    let (record, identity) = checkout::read_record_bound(&runs_fd, run, caller)?;
    context_bound(
        owner_home, loop_name, run, &plan, root, &runs_fd, &record, &identity,
    )
}

/// Read context through a caller's bound reservation and runs root.
///
/// # Errors
///
/// Refuses a changed identity or failed private context read.
#[allow(clippy::too_many_arguments)]
pub(super) fn context_bound(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    plan: &Plan,
    root: &Path,
    runs_fd: &OwnedFd,
    record: &Value,
    identity: &str,
) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    validate_record(plan, record, loop_name, run)?;
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("exercise-context", "round is absent"))?;
    let step = round["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-context", "step is absent"))?;
    let directory = recorded_directory(plan, round)?;
    let podman = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("exercise-context", "container program is absent"))?,
    );
    crate::pinned::owner_executable(&podman, caller)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-context", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, caller)?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, caller, 0)?;
    let mut argv = private_request(
        &exe_word, owner_home, loop_name, run, step, &directory, identity,
    )?;
    argv[2] = "_exercise-context-private".into();
    let output = build::run_checked_with_private_launch(
        &podman,
        argv,
        &super::launch_environment(owner_home)?,
        owner_home,
        60,
        "exercise-context",
        &verified_home,
        root,
        runs_fd,
        None,
    )?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-context", error.to_string()))
}

/// Inspect one round's context state from its pinned step directory.
///
/// # Errors
///
/// Refuses a missing, changed or malformed driver record.
pub fn private_context(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    requested_directory: &Path,
    expected_identity: &str,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-context",
            "rootless namespace root is required",
        ));
    }
    let (plan, _) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("exercise-context", "runs root is absent"))?;
    let runs = home::pin_parent(root, 0)?;
    let record = bound_private_record(&runs, run, 0, expected_identity, "exercise-context-record")?;
    validate_record(&plan, &record, loop_name, run)?;
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.iter().find(|item| item["step"] == step))
        .ok_or_else(|| LaneError::input("exercise-context", "round is absent"))?;
    let directory = recorded_directory(&plan, round)?;
    if directory != requested_directory {
        return Err(LaneError::input(
            "exercise-context",
            "round directory differs from reservation",
        ));
    }
    let loop_uid = super::recorded_loop_uid(&record)?;
    let pinned = File::from(home::pin_loop_round_at(&runs, root, &directory, loop_uid)?);
    let file = open_regular_at(&pinned, "context.jsonl", "exercise-context", false)?
        .ok_or_else(|| LaneError::input("exercise-context", "context.jsonl is absent"))?;
    if file
        .metadata()
        .map_err(|error| LaneError::input("exercise-context", error.to_string()))?
        .len()
        > 16_777_216
    {
        return Err(LaneError::input(
            "exercise-context",
            "context record exceeds size bound",
        ));
    }
    let bytes = read_regular(file, "exercise-context")?;
    parse_context_state(&bytes)
}

fn parse_context_state(bytes: &[u8]) -> Result<Value, LaneError> {
    if !bytes.ends_with(b"\n") {
        return Err(LaneError::input(
            "exercise-context",
            "context record has a trailing partial line",
        ));
    }
    let line = bytes
        .split(|byte| *byte == b'\n')
        .rfind(|line| !line.is_empty())
        .ok_or_else(|| LaneError::input("exercise-context", "context record is empty"))?;
    let state: Value = serde_json::from_slice(line)
        .map_err(|error| LaneError::input("exercise-context", error.to_string()))?;
    if !matches!(state["state"].as_str(), Some("measured" | "unknown"))
        || !state["source"].is_string()
        || !state["turn"].is_number()
    {
        return Err(LaneError::input(
            "exercise-context",
            "context state is malformed",
        ));
    }
    Ok(state)
}

#[cfg(test)]
mod context_case_tests {
    use super::*;

    /// ´test:unit:context-case-distinguishes-unknown-and-missing-evidence´
    #[test]
    fn context_case_distinguishes_unknown_and_missing_evidence() {
        let unknown = br#"{"state":"unknown","used":null,"window":null,"fraction":null,"source":"turn.completed.usage","reason":"window-unreported","turn":2,"at":"2026-10-07T00:00:00Z"}
"#;
        assert_eq!(
            parse_context_state(unknown).expect("unknown state")["reason"],
            "window-unreported"
        );
        assert!(
            parse_context_state(b"")
                .expect_err("absent record")
                .line()
                .contains("exercise-context")
        );
        assert!(
            parse_context_state(b"{\"state\":\"unknown\"}")
                .expect_err("partial line")
                .line()
                .contains("exercise-context")
        );
    }
}

pub(super) fn validate_record(
    plan: &Plan,
    record: &Value,
    loop_name: &str,
    run: &str,
) -> Result<(), LaneError> {
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "follow-record",
            "run home or driver directory differs from reservation",
        ));
    }
    Ok(())
}

pub(super) fn recorded_directory(plan: &Plan, round: &Value) -> Result<PathBuf, LaneError> {
    let recorded = round["driver_dir"].as_str().ok_or_else(|| {
        LaneError::input("follow-record", "round has no recorded driver directory")
    })?;
    let directory = PathBuf::from(recorded);
    if recorded.ends_with('/')
        || !directory.is_absolute()
        || directory == plan.driver_dir
        || !directory.starts_with(&plan.driver_dir)
        || directory.parent() != Some(plan.driver_dir.as_path())
        || directory
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(LaneError::input(
            "follow-record",
            "round driver directory differs from reservation",
        ));
    }
    Ok(directory)
}

fn run_from_record(
    plan: &Plan,
    record: &Value,
    selected: Option<&str>,
    writer: &mut impl Write,
    round_only: bool,
    mut invoke: impl FnMut(&str, &Path) -> Result<String, LaneError>,
) -> Result<(), LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("follow-record", "round list is absent"))?;
    let mut found = false;
    for round in rounds {
        let step = round["step"]
            .as_str()
            .ok_or_else(|| LaneError::input("follow-record", "round step is absent"))?;
        valid_step(step)?;
        if selected.is_some_and(|wanted| wanted != step) {
            continue;
        }
        found = true;
        let directory = recorded_directory(plan, round)?;
        let phase = round["phase"]
            .as_str()
            .ok_or_else(|| LaneError::input("follow-record", "round phase is absent"))?;
        let header = json!({"kind":"round","round":step,"driver_dir":directory,"phase":phase});
        writeln!(writer, "{header}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        writer
            .flush()
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        if !round_only {
            writer
                .write_all(invoke(step, &directory)?.as_bytes())
                .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        }
    }
    if !found {
        return Err(LaneError::input("follow-round", "selected round is absent"));
    }
    Ok(())
}

fn private_request(
    exe_word: &str,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    directory: &Path,
    identity: &str,
) -> Result<Vec<String>, LaneError> {
    let mut argv = vec!["unshare".into(), exe_word.into()];
    argv.extend(private_follow_argv(
        owner_home, loop_name, run, step, directory, identity,
    )?);
    Ok(argv)
}

/// Build the private follow words used by the public command.
///
/// # Errors
///
/// Refuses a directory or owner home that cannot be passed as a path word.
pub fn private_follow_argv(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    directory: &Path,
    identity: &str,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_follow-private".into(),
        loop_name.into(),
        run.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--round".into(),
        step.into(),
        "--driver-dir".into(),
        crate::pinned::path_word(directory, "round-directory")?,
        "--record-identity".into(),
        identity.into(),
    ])
}

fn require_private_identity(
    actual: &str,
    expected: &str,
    kind: &'static str,
) -> Result<(), LaneError> {
    if actual != expected {
        return Err(LaneError::input(
            kind,
            "private reservation identity differs from the public read",
        ));
    }
    Ok(())
}

fn bound_private_record(
    runs: &OwnedFd,
    run: &str,
    owner: u32,
    expected_identity: &str,
    kind: &'static str,
) -> Result<Value, LaneError> {
    let (record, identity) = checkout::read_record_bound(runs, run, owner)?;
    require_private_identity(&identity, expected_identity, kind)?;
    Ok(record)
}

/// Read one round's driver evidence as the loop uid in the private namespace.
///
/// # Errors
///
/// Refuses a changed reservation, directory or event boundary.
pub fn private_read(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    requested_directory: &Path,
    expected_identity: &str,
) -> Result<String, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "follow-private",
            "rootless namespace root is required",
        ));
    }
    let (plan, _) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("follow-record", "runs root is absent"))?;
    let runs = home::pin_parent(root, 0)?;
    private_read_from_bound(
        &plan,
        &runs,
        0,
        loop_name,
        run,
        step,
        requested_directory,
        expected_identity,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_read_from_bound(
    plan: &Plan,
    runs: &OwnedFd,
    owner: u32,
    loop_name: &str,
    run: &str,
    step: &str,
    requested_directory: &Path,
    expected_identity: &str,
) -> Result<String, LaneError> {
    let record =
        bound_private_record(runs, run, owner, expected_identity, "follow-private-record")?;
    validate_record(plan, &record, loop_name, run)?;
    read_private_record(plan, &record, step, requested_directory)
}

fn read_private_record(
    plan: &Plan,
    record: &Value,
    step: &str,
    requested_directory: &Path,
) -> Result<String, LaneError> {
    read_private_record_with(
        plan,
        record,
        step,
        requested_directory,
        |pinned, size, uid| {
            lane_lifecycle::validated_event_boundaries_at(pinned, size, uid)
                .map_err(|error| LaneError::input("follow-boundary", error.to_string()))
        },
    )
}

fn read_private_record_with(
    plan: &Plan,
    record: &Value,
    step: &str,
    requested_directory: &Path,
    validate: impl FnOnce(
        &File,
        usize,
        u32,
    ) -> Result<lane_lifecycle::ValidatedEventBoundaries, LaneError>,
) -> Result<String, LaneError> {
    valid_step(step)?;
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("follow-record", "round list is absent"))?;
    let round = rounds
        .iter()
        .find(|round| round["step"] == step)
        .ok_or_else(|| LaneError::input("follow-round", "selected round is absent"))?;
    let directory = recorded_directory(plan, round)?;
    if directory != requested_directory {
        return Err(LaneError::input(
            "follow-record",
            "private round directory differs from reservation",
        ));
    }
    let runs_root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("follow-record", "runs root is absent"))?;
    let loop_uid = super::recorded_loop_uid(record)?;
    let pinned_run = home::pin_loop_round(
        runs_root,
        &plan.driver_dir,
        Uid::effective().as_raw(),
        loop_uid,
    )?;
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("follow-record", "round directory name is absent"))?;
    match openat2(
        &pinned_run,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(_) => (),
        Err(Errno::ENOENT) => {
            let phase = round["phase"]
                .as_str()
                .ok_or_else(|| LaneError::input("follow-record", "round phase is absent"))?;
            let detail = if phase == "running" {
                format!(
                    "{}: round driver directory is absent before its driver starts",
                    directory.display()
                )
            } else {
                format!(
                    "{}: round driver directory is absent with phase {phase}",
                    directory.display()
                )
            };
            return Err(LaneError::input("follow-round-directory", detail));
        }
        Err(error) => {
            return Err(LaneError::input(
                "unsafe-path",
                format!("{}: {error}", directory.display()),
            ));
        }
    }
    let pinned = home::pin_loop_round_at(&pinned_run, &plan.driver_dir, &directory, loop_uid)?;
    let pinned = File::from(pinned);
    let letters = open_regular_at(&pinned, "letters.jsonl", "follow-letters", true)?;
    let events = open_regular_at(&pinned, "events.jsonl", "follow-events", false)?
        .ok_or_else(|| LaneError::input("follow-events", "events.jsonl is absent"))?;
    let observations = letters.map_or_else(
        || Ok(Vec::new()),
        |file| parse_observations(&read_regular(file, "follow-letters")?),
    )?;
    let events = read_regular(events, "follow-events")?;
    let group = rounds
        .iter()
        .filter(|item| item["driver_dir"] == round["driver_dir"])
        .cloned()
        .collect::<Vec<_>>();
    let validated = validate(&pinned, events.len(), loop_uid)?;
    let boundaries = boundaries_for_rounds(&validated, &group, events.len())?;
    render(record, &observations, &events, &boundaries, Some(step))
}

fn boundaries_for_rounds(
    validated: &lane_lifecycle::ValidatedEventBoundaries,
    rounds: &[Value],
    event_size: usize,
) -> Result<BTreeMap<String, (u64, u64)>, LaneError> {
    let current_start = validated.current_start as u64;
    let mut boundaries = BTreeMap::new();
    let mut previous_end = None;
    for (index, round) in rounds.iter().enumerate() {
        let step = round["step"]
            .as_str()
            .ok_or_else(|| LaneError::input("follow-record", "round step is absent"))?;
        valid_step(step)?;
        let (start, end) = if index + 1 == rounds.len() {
            (current_start, event_size as u64)
        } else {
            validated
                .archives
                .get(step)
                .map(|(start, end)| (*start as u64, *end as u64))
                .ok_or_else(|| {
                    LaneError::input("follow-boundary", format!("round {step} has no archive"))
                })?
        };
        if start > end || end > event_size as u64 {
            return Err(LaneError::input(
                "follow-boundary",
                format!("round {step} has invalid event offsets {start}..{end}"),
            ));
        }
        if previous_end.map_or(start != 0, |previous| previous != start) {
            return Err(LaneError::input(
                "follow-boundary",
                format!("round {step} starts at {start} after {previous_end:?}"),
            ));
        }
        previous_end = Some(end);
        boundaries.insert(step.to_owned(), (start, end));
    }
    Ok(boundaries)
}

pub(super) fn open_regular_at(
    directory: &File,
    name: &str,
    kind: &'static str,
    optional: bool,
) -> Result<Option<File>, LaneError> {
    let name_c = CString::new(name).map_err(|error| LaneError::input(kind, error.to_string()))?;
    // SAFETY: directory stays pinned and the name is terminated and has one component.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        if optional && error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(LaneError::input(kind, format!("{name}: {error}")));
    }
    // SAFETY: openat returned a descriptor owned by this File.
    #[allow(unsafe_code)]
    let file = unsafe { File::from_raw_fd(raw) };
    if !file
        .metadata()
        .map_err(|error| LaneError::input(kind, error.to_string()))?
        .is_file()
    {
        return Err(LaneError::input(
            kind,
            format!("{name} is not a regular file"),
        ));
    }
    Ok(Some(file))
}

pub(super) fn read_regular(mut file: File, kind: &'static str) -> Result<Vec<u8>, LaneError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| LaneError::input(kind, error.to_string()))?;
    Ok(bytes)
}

fn parse_observations(bytes: &[u8]) -> Result<Vec<Value>, LaneError> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(LaneError::input(
            "follow-letters",
            "durable letter stream ends in a partial line",
        ));
    }
    let records: Vec<Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<Value>(line)
                .map_err(|error| LaneError::input("follow-letters", error.to_string()))
        })
        .collect::<Result<_, _>>()?;
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for record in records {
        let identity = record["identity"]
            .as_array()
            .filter(|parts| parts.len() == 4)
            .ok_or_else(|| LaneError::input("follow-letters", "letter identity is absent"))?;
        if seen.insert(json!(identity).to_string()) {
            unique.push(record);
        }
    }
    Ok(unique)
}

fn order(name: &str, step: &str) -> (u64, String) {
    if name == format!("{step}.md") {
        return (0, name.to_owned());
    }
    let number = name
        .strip_prefix(&format!("{step}-"))
        .and_then(|tail| tail.strip_suffix(".md"))
        .and_then(|tail| tail.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    (number, name.to_owned())
}

fn append_private_line(output: &mut String, value: &Value) -> Result<(), LaneError> {
    let line = serde_json::to_string(value)
        .map_err(|error| LaneError::operation("follow-output", error.to_string()))?;
    if output.len().saturating_add(line.len()).saturating_add(1) > MAX_PRIVATE_RESPONSE_BYTES {
        return Err(LaneError::input(
            "follow-output",
            format!("private response exceeds {MAX_PRIVATE_RESPONSE_BYTES} bytes"),
        ));
    }
    output.push_str(&line);
    output.push('\n');
    Ok(())
}

fn newest_events(region: &[u8], start: u64) -> Result<(u64, usize, usize, Vec<Value>), LaneError> {
    let mut kept_start = region.len();
    let mut serialized: usize = 2; // JSON array brackets count against the 524,288-byte budget.
    let mut newest = Vec::new();
    for line in region.split_inclusive(|byte| *byte == b'\n').rev() {
        let raw = line.strip_suffix(b"\n").unwrap_or(line);
        let event = serde_json::from_slice::<Value>(raw)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(raw)}));
        let added = if raw.is_empty() {
            0
        } else {
            serde_json::to_vec(&event)
                .map_err(|error| LaneError::operation("follow-output", error.to_string()))?
                .len()
                + usize::from(!newest.is_empty())
        };
        if serialized.saturating_add(added) > MAX_EVENT_DELTA_BYTES {
            break;
        }
        serialized += added;
        kept_start -= line.len();
        if !raw.is_empty() {
            newest.push(event);
        }
    }
    newest.reverse();
    let omitted_events = region[..kept_start]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    let omitted_bytes = kept_start;
    Ok((
        start + kept_start as u64,
        omitted_events,
        omitted_bytes,
        newest,
    ))
}

#[allow(clippy::too_many_lines)]
fn render(
    record: &Value,
    observations: &[Value],
    events: &[u8],
    boundaries: &BTreeMap<String, (u64, u64)>,
    selected: Option<&str>,
) -> Result<String, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("follow-record", "round list is absent"))?;
    let letters = record["letters"]
        .as_array()
        .ok_or_else(|| LaneError::input("follow-record", "letter list is absent"))?;
    let mut output = String::new();
    let mut found = false;
    for round in rounds {
        let step = round["step"]
            .as_str()
            .ok_or_else(|| LaneError::input("follow-record", "round step is absent"))?;
        if selected.is_some_and(|wanted| wanted != step) {
            continue;
        }
        found = true;
        let mut observed = observations
            .iter()
            .filter(|item| item["round"] == step)
            .cloned()
            .collect::<Vec<_>>();
        for letter in letters
            .iter()
            .filter(|letter| letter["step"] == step && letter["state"] != "withdrawn")
        {
            if let Some(name) = letter["name"].as_str()
                && !observed
                    .iter()
                    .any(|item| item["box"] == "inbox" && item["name"] == name)
            {
                observed.push(json!({"round":step,"box":"inbox","name":name,"bytes":letter["bytes"],"at":null,"line":null}));
            }
        }
        if let Some(acks) = round["in_round_letters"].as_array() {
            for ack in acks {
                if let Some(name) = ack["letter"].as_str()
                    && !ack["acknowledgment"].is_null()
                    && !observed
                        .iter()
                        .any(|item| item["box"] == "outbox" && item["name"] == name)
                {
                    observed.push(json!({"round":step,"box":"outbox","name":name,"bytes":ack["acknowledgment"]["bytes"],"at":null,"line":null}));
                }
            }
        }
        let reply_name = format!("{step}.md");
        if round["phase"] == "settled"
            && !round["reply"].is_null()
            && !observed
                .iter()
                .any(|item| item["box"] == "outbox" && item["name"] == reply_name)
        {
            observed.push(json!({"round":step,"box":"outbox","name":reply_name,"bytes":round["reply"]["bytes"],"at":null,"line":null}));
        }
        observed.sort_by_key(|item| {
            (
                u8::from(item["box"] != "inbox"),
                order(item["name"].as_str().unwrap_or_default(), step),
                item["revision"].as_u64().unwrap_or_default(),
            )
        });
        let ack_times = observed
            .iter()
            .filter(|item| item["box"] == "outbox" && item["state"] == "complete")
            .filter_map(|item| {
                Some((
                    item["name"].as_str()?.to_owned(),
                    item["at"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        for item in &observed {
            let box_name = item["box"]
                .as_str()
                .ok_or_else(|| LaneError::input("follow-letters", "box is absent"))?;
            let name = item["name"]
                .as_str()
                .ok_or_else(|| LaneError::input("follow-letters", "name is absent"))?;
            let placed = letters.iter().find(|letter| {
                letter["step"] == step && letter["name"] == name && letter["state"] != "withdrawn"
            });
            let line = json!({"kind":"letter","round":step,"box":box_name,"name":name,"bytes":item["bytes"],"state":item["state"],"revision":item["revision"],
                "placement_at_unix_ns":placed.map_or(Value::Null, |letter| letter["placed_at_unix_ns"].clone()),
                "observed_at":item["at"],"acknowledged_at":if box_name == "inbox" { ack_times.get(name).map_or(Value::Null, |at| json!(at)) } else if name != reply_name && item["state"] == "complete" { item["at"].clone() } else { Value::Null },
                "line":item["line"]});
            append_private_line(&mut output, &line)?;
        }
        if round["phase"] == "failed" {
            let status = json!({"kind":"round-status","round":step,"phase":"failed","error":round["settlement_error"]});
            append_private_line(&mut output, &status)?;
        }
        let (start, end) = boundaries.get(step).ok_or_else(|| {
            LaneError::input(
                "follow-boundary",
                format!("round {step} has no event boundary"),
            )
        })?;
        let start_index = usize::try_from(*start)
            .map_err(|_| LaneError::input("follow-boundary", "start offset overflows"))?;
        let end_index = usize::try_from(*end)
            .map_err(|_| LaneError::input("follow-boundary", "end offset overflows"))?;
        let region = events.get(start_index..end_index).ok_or_else(|| {
            LaneError::input("follow-boundary", "event region is outside the file")
        })?;
        let (kept_start, omitted_events, omitted_bytes, event_lines) =
            newest_events(region, *start)?;
        let delta = json!({"kind":"event-delta","round":step,"start":kept_start,"end":end,
            "events":event_lines,"omitted_events":omitted_events,"omitted_bytes":omitted_bytes});
        append_private_line(&mut output, &delta)?;
    }
    if !found {
        return Err(LaneError::input("follow-round", "selected round is absent"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::symlink;
    use std::rc::Rc;

    struct ProbeWriter(Rc<RefCell<(Vec<u8>, bool)>>);

    impl std::io::Write for ProbeWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.borrow_mut().1 = true;
            Ok(())
        }
    }

    /// ´test:unit:public-follow-flushes-record-before-private-refusal´
    #[test]
    fn public_follow_flushes_record_before_private_refusal() {
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: PathBuf::from("/runs/R"),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let record = json!({"rounds":[{"step":"dispatch","phase":"running","driver_dir":"/runs/R/first-dispatch"}]});
        let state = Rc::new(RefCell::new((Vec::new(), false)));
        let mut writer = ProbeWriter(Rc::clone(&state));
        let mut calls = 0;
        let error = run_from_record(
            &plan,
            &record,
            Some("dispatch"),
            &mut writer,
            false,
            |_, _| {
                calls += 1;
                let written = state.borrow();
                assert!(written.1, "round record was flushed before private read");
                let header: Value =
                    serde_json::from_slice(&written.0).expect("round record before private read");
                assert_eq!(header["kind"], "round");
                Err(LaneError::operation(
                    "follow-private",
                    "/usr/bin/podman exceeded output limit wall_seconds=0.250406",
                ))
            },
        )
        .expect_err("private output limit refusal");
        assert_eq!(calls, 1);
        assert_eq!(error.kind, "follow-private");
        assert!(state.borrow().0.ends_with(b"\n"));
    }

    /// ´test:unit:follow-renders-wrong-thread-failure-without-reply-of-record´
    #[test]
    fn follow_renders_wrong_thread_failure_without_reply_of_record() {
        let record = json!({"rounds":[{"step":"review","phase":"failed","reply":{"bytes":4,"sha256":"digest"},"settlement_error":"round-thread: step thread thread-2 differs from reservation thread-1"}],"letters":[]});
        let bounds = BTreeMap::from([("review".to_owned(), (0, 3))]);
        let output = render(&record, &[], b"{}\n", &bounds, None).expect("failed round");
        let lines = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("record"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["kind"], "round-status");
        assert_eq!(lines[0]["phase"], "failed");
        assert_eq!(lines[0]["error"], record["rounds"][0]["settlement_error"]);
        assert_eq!(lines[1]["kind"], "event-delta");
        assert!(!output.contains("\"kind\":\"letter\""));
    }

    /// ´test:unit:follow-collapses-replayed-letter-identity´
    #[test]
    fn follow_collapses_replayed_letter_identity() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let path = fixture.path().join("letters.jsonl");
        let letter = json!({"round":"dispatch","box":"inbox","name":"dispatch.md","bytes":4,
            "at":"2026-10-07T00:00:00Z","identity":["inbox","dispatch.md",4,"2026-10-07T00:00:00Z"],
            "line":"LETTER box=inbox name=dispatch.md bytes=4 at=2026-10-07T00:00:00Z id=1\n"});
        let mut replay = letter.clone();
        replay["line"] = json!(
            "LETTER box=inbox name=dispatch.md bytes=4 at=2026-10-07T00:00:00Z id=1 replay=1\n"
        );
        fs::write(&path, format!("{letter}\n{replay}\n")).expect("durable records");
        let observations = parse_observations(&fs::read(&path).expect("durable bytes"))
            .expect("deduplicated observations");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["identity"], letter["identity"]);
    }

    /// ´test:unit:follow-renders-the-pinned-letter-after-a-rename-replacement´
    #[test]
    fn follow_renders_the_pinned_letter_after_a_rename_replacement() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let directory = File::open(fixture.path()).expect("pinned step");
        let old = json!({"round":"dispatch","box":"inbox","name":"dispatch.md","bytes":3,
            "state":"complete","revision":1,"at":"2026-10-07T00:00:00Z",
            "identity":["inbox","dispatch.md",3,"2026-10-07T00:00:00Z"],"line":"old pinned letter"});
        fs::write(fixture.path().join("letters.jsonl"), format!("{old}\n"))
            .expect("first letters file");
        let held = open_regular_at(&directory, "letters.jsonl", "follow-letters", false)
            .expect("open letters")
            .expect("held letters");
        let replacement = json!({"round":"dispatch","box":"inbox","name":"other.md","bytes":3,
            "state":"complete","revision":1,"at":"2026-10-07T00:00:01Z",
            "identity":["inbox","other.md",3,"2026-10-07T00:00:01Z"],"line":"new pathname"});
        fs::write(
            fixture.path().join("replacement"),
            format!("{replacement}\n"),
        )
        .expect("replacement bytes");
        fs::rename(
            fixture.path().join("replacement"),
            fixture.path().join("letters.jsonl"),
        )
        .expect("replace after pin");
        let observations = parse_observations(
            &read_regular(held, "follow-letters").expect("read held descriptor"),
        )
        .expect("pinned observations");
        let record = json!({"rounds":[{"step":"dispatch"}],"letters":[]});
        let boundaries = BTreeMap::from([("dispatch".to_owned(), (0, 3))]);
        let rendered = render(&record, &observations, b"{}\n", &boundaries, None)
            .expect("render pinned letter");
        assert!(rendered.contains("old pinned letter"));
        assert!(!rendered.contains("new pathname"));
    }

    /// ´test:unit:follow-renders-replacement-after-withdrawal´
    #[test]
    fn follow_renders_replacement_after_withdrawal() {
        let record = json!({"rounds":[{"step":"verify-1"}],"letters":[
            {"step":"verify-1","name":"verify-1.md","state":"withdrawn","bytes":3,"placed_at_unix_ns":11},
            {"step":"verify-1","name":"verify-1.md","state":"placed","bytes":12,"placed_at_unix_ns":22}
        ]});
        let boundaries = BTreeMap::from([("verify-1".to_owned(), (0, 3))]);
        let output = render(&record, &[], b"{}\n", &boundaries, Some("verify-1"))
            .expect("replacement render");
        let letters = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("record"))
            .filter(|line| line["kind"] == "letter")
            .collect::<Vec<_>>();
        assert_eq!(letters.len(), 1);
        assert_eq!(letters[0]["bytes"], 12);
        assert_eq!(letters[0]["placement_at_unix_ns"], 22);
    }

    /// ´test:unit:follow-orders-two-rounds-and-numbered-letter-before-events´
    #[test]
    fn follow_orders_two_rounds_and_numbered_letter_before_events() {
        let record = json!({"rounds":[{"step":"dispatch"},{"step":"review"}],"letters":[
            {"step":"dispatch","name":"dispatch.md","placed_at_unix_ns":1},
            {"step":"review","name":"review.md","placed_at_unix_ns":2},
            {"step":"review","name":"review-1.md","placed_at_unix_ns":3}]});
        let observations = [
            json!({"round":"review","box":"outbox","name":"review-1.md","bytes":2,"state":"complete","at":"2026-10-07T00:00:04Z","line":"ack"}),
            json!({"round":"review","box":"inbox","name":"review-1.md","bytes":3,"at":"2026-10-07T00:00:03Z","line":"numbered"}),
            json!({"round":"dispatch","box":"inbox","name":"dispatch.md","bytes":4,"at":"2026-10-07T00:00:01Z","line":"first"}),
            json!({"round":"review","box":"inbox","name":"review.md","bytes":5,"at":"2026-10-07T00:00:02Z","line":"second"}),
        ];
        let events = b"{\"event\":1}\n{\"event\":2}\n";
        let bounds = BTreeMap::from([
            ("dispatch".to_owned(), (0, 12)),
            ("review".to_owned(), (12, 24)),
        ]);
        let lines = render(&record, &observations, events, &bounds, None).expect("follow");
        let kinds = lines
            .lines()
            .map(|line| {
                let value: Value = serde_json::from_str(line).expect("record");
                (
                    value["kind"].as_str().unwrap_or_default().to_owned(),
                    value["round"].as_str().unwrap_or_default().to_owned(),
                    value["name"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                ("letter".into(), "dispatch".into(), "dispatch.md".into()),
                ("event-delta".into(), "dispatch".into(), String::new()),
                ("letter".into(), "review".into(), "review.md".into()),
                ("letter".into(), "review".into(), "review-1.md".into()),
                ("letter".into(), "review".into(), "review-1.md".into()),
                ("event-delta".into(), "review".into(), String::new())
            ]
        );
        let numbered: Value = serde_json::from_str(lines.lines().nth(3).expect("numbered letter"))
            .expect("numbered record");
        assert_eq!(numbered["acknowledged_at"], "2026-10-07T00:00:04Z");
    }

    /// ´test:unit:follow-acknowledges-only-a-complete-outbox-record´
    #[test]
    fn follow_acknowledges_only_a_complete_outbox_record() {
        let record = json!({"rounds":[{"step":"review"}],"letters":[{"step":"review","name":"review-1.md","placed_at_unix_ns":1}]});
        let mut observations = vec![
            json!({"round":"review","box":"inbox","name":"review-1.md","bytes":4,"state":"complete","at":"2026-10-07T00:00:01Z"}),
            json!({"round":"review","box":"outbox","name":"review-1.md","bytes":2,"state":"observed","revision":1,"at":"2026-10-07T00:00:02Z"}),
        ];
        let boundaries = BTreeMap::from([("review".to_owned(), (0, 3))]);
        let partial =
            render(&record, &observations, b"{}\n", &boundaries, None).expect("observation");
        let partial_records = partial
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("line"))
            .collect::<Vec<_>>();
        assert_eq!(partial_records[0]["acknowledged_at"], Value::Null);
        assert_eq!(partial_records[1]["acknowledged_at"], Value::Null);
        observations.push(json!({"round":"review","box":"outbox","name":"review-1.md","bytes":4,"state":"complete","revision":2,"at":"2026-10-07T00:00:03Z"}));
        let complete =
            render(&record, &observations, b"{}\n", &boundaries, None).expect("completion");
        let complete_records = complete
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("line"))
            .collect::<Vec<_>>();
        assert_eq!(
            complete_records[0]["acknowledged_at"],
            "2026-10-07T00:00:03Z"
        );
        assert_eq!(complete_records[1]["acknowledged_at"], Value::Null);
        assert_eq!(
            complete_records[2]["acknowledged_at"],
            "2026-10-07T00:00:03Z"
        );
    }

    /// ´test:unit:public-follow-renders-running-round-from-recorded-directory´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn public_follow_renders_running_round_from_recorded_directory() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let reservation_root = fixture.path().join("runs");
        let run_root = reservation_root.join("R");
        let step_dir = run_root.join("20261007T043545Z-dispatch");
        fs::create_dir_all(&step_dir).expect("recorded step directory");
        for directory in [
            fixture.path(),
            reservation_root.as_path(),
            run_root.as_path(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("owner directory");
        }
        fs::set_permissions(&step_dir, fs::Permissions::from_mode(0o755)).expect("step mode");
        fs::write(
            step_dir.join("events.jsonl"),
            b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n",
        )
        .expect("step events");
        fs::write(step_dir.join(".event-start"), b"0\n").expect("step boundary");
        let observation = json!({"round":"dispatch","box":"inbox","name":"dispatch.md","bytes":5,"state":"complete","revision":1,"at":"2026-10-07T00:00:00Z","identity":["inbox","dispatch.md",1,"2026-10-07T00:00:00Z"],"line":"LETTER box=inbox name=dispatch.md bytes=5 at=2026-10-07T00:00:00Z state=complete revision=1 id=fixture\n"});
        fs::write(step_dir.join("letters.jsonl"), format!("{observation}\n"))
            .expect("step letters");
        let plan = Plan {
            home: fixture.path().join("home-R"),
            driver_dir: run_root.clone(),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let loop_uid = Uid::effective().as_raw();
        let worker_uid = if loop_uid == 3000 { 3001 } else { 3000 };
        let reservation = json!({"schema":1,"phase":"preparing","worker_uid":worker_uid,"loop":"alpha","run":"R","plan":{"home":plan.home,"driver_dir":run_root,"paths":[{"path":plan.home,"uid":loop_uid,"gid":loop_uid},{"path":run_root,"kind":"directory","uid":loop_uid,"gid":loop_uid}]},"rounds":[{"step":"dispatch","phase":"running","driver_dir":step_dir}],"letters":[{"step":"dispatch","name":"dispatch.md","placed_at_unix_ns":1}]});
        let reservation_path = super::super::reservation_path(&reservation_root, "R");
        super::super::publish_reservation(&reservation_path, &reservation).expect("reservation");
        let bound_runs: OwnedFd = File::open(&reservation_root)
            .expect("bound runs root")
            .into();
        let (saved, identity) =
            checkout::read_record_bound(&bound_runs, "R", loop_uid).expect("saved identity");
        validate_record(&plan, &saved, "alpha", "R").expect("matching reservation");
        let mut replaced = saved.clone();
        replaced["rounds"][0]["step"] = json!("review");
        super::super::publish_reservation(&reservation_path, &replaced)
            .expect("replacement reservation");
        let follow_error = private_read_from_bound(
            &plan,
            &bound_runs,
            loop_uid,
            "alpha",
            "R",
            "dispatch",
            &step_dir,
            &identity,
        )
        .expect_err("private follow refuses replaced reservation");
        assert_eq!(follow_error.kind, "follow-private-record");
        let context_error = bound_private_record(
            &bound_runs,
            "R",
            loop_uid,
            &identity,
            "exercise-context-record",
        )
        .expect_err("private context refuses replaced reservation");
        assert_eq!(context_error.kind, "exercise-context-record");
        let home_anchor = fs::File::open(fixture.path()).expect("home anchor");
        let runs_anchor = fs::File::open(&reservation_root).expect("runs anchor");
        let _private = home::activate_private_launch(
            fixture.path(),
            &home_anchor,
            &reservation_root,
            &runs_anchor,
            None,
            loop_uid,
        )
        .expect("private entry anchors");
        let mut rendered = Vec::new();
        run_from_record(
            &plan,
            &saved,
            None,
            &mut rendered,
            false,
            |step, directory| {
                let argv = private_request(
                    "/usr/bin/superloop-lane",
                    fixture.path(),
                    "alpha",
                    "R",
                    step,
                    directory,
                    &identity,
                )?;
                assert_eq!(argv[2], "_follow-private");
                assert_eq!(argv[8], "dispatch");
                assert_eq!(argv[10], directory.display().to_string());
                read_private_record(&plan, &saved, step, directory)
            },
        )
        .expect("public request through private reader");
        let rendered = String::from_utf8(rendered).expect("utf8 output");
        let lines = rendered
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("rendered line"))
            .collect::<Vec<_>>();
        assert_eq!(lines[0]["kind"], "round");
        assert_eq!(lines[0]["round"], "dispatch");
        assert_eq!(lines[0]["driver_dir"], json!(step_dir));
        assert_eq!(lines[0]["phase"], "running");
        assert_eq!(lines[1]["kind"], "letter");
        assert_eq!(lines[1]["name"], "dispatch.md");
        assert_eq!(lines[2]["kind"], "event-delta");
        assert_eq!(lines[2]["events"][0]["thread_id"], "thread-1");
        let large_events = format!(
            "{}{{\"seq\":\"newest\"}}\n",
            "{\"seq\":\"old\",\"data\":\"xxxxxxxxxxxxxxxx\"}\n".repeat(20_000)
        );
        assert!(large_events.len() > MAX_EVENT_DELTA_BYTES);
        fs::write(step_dir.join("events.jsonl"), &large_events).expect("large event region");
        let mut bounded = Vec::new();
        let mut calls = 0;
        run_from_record(
            &plan,
            &saved,
            Some("dispatch"),
            &mut bounded,
            false,
            |step, directory| {
                calls += 1;
                read_private_record(&plan, &saved, step, directory)
            },
        )
        .expect("bounded production follow");
        assert_eq!(calls, 1);
        let bounded = String::from_utf8(bounded).expect("utf8 output");
        let bounded_lines = bounded
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("bounded record"))
            .collect::<Vec<_>>();
        assert_eq!(bounded_lines.len(), 3);
        assert_eq!(bounded_lines[0]["kind"], "round");
        assert_eq!(bounded_lines[1]["kind"], "letter");
        assert_eq!(bounded_lines[2]["kind"], "event-delta");
        assert_eq!(
            bounded_lines[2]["events"]
                .as_array()
                .expect("events")
                .last()
                .expect("newest")["seq"],
            "newest"
        );
        let omitted_events = bounded_lines[2]["omitted_events"].as_u64().expect("count");
        let kept_events = bounded_lines[2]["events"].as_array().expect("events");
        assert!(omitted_events > 0);
        assert_eq!(
            usize::try_from(omitted_events).expect("count fits") + kept_events.len(),
            20_001
        );
        assert_eq!(bounded_lines[2]["omitted_bytes"], 40 * omitted_events);
        assert!(
            serde_json::to_string(kept_events)
                .expect("events array")
                .len()
                <= MAX_EVENT_DELTA_BYTES
        );
        assert_eq!(bounded_lines[2]["start"], bounded_lines[2]["omitted_bytes"]);
        assert_eq!(bounded_lines[2]["end"], large_events.len());
        assert!(bounded.len() < MAX_PRIVATE_RESPONSE_BYTES);
        let mut oversized_letter = observation.clone();
        oversized_letter["line"] = json!("x".repeat(MAX_PRIVATE_RESPONSE_BYTES));
        fs::write(
            step_dir.join("letters.jsonl"),
            format!("{oversized_letter}\n"),
        )
        .expect("oversized letter observation");
        let mut refused = Vec::new();
        let error = run_from_record(
            &plan,
            &saved,
            Some("dispatch"),
            &mut refused,
            false,
            |step, directory| read_private_record(&plan, &saved, step, directory),
        )
        .expect_err("letter line exceeds private response cap");
        assert_eq!(error.kind, "follow-output");
        assert!(error.detail.contains("1572864"));
        assert!(String::from_utf8_lossy(&refused).contains("\"kind\":\"round\""));
        fs::write(step_dir.join("letters.jsonl"), format!("{observation}\n"))
            .expect("restore letter observation");
        let before_driver = saved.clone();
        assert_link_refusals(&plan, &saved, &step_dir);
        let mut foreign = saved.clone();
        let home_row = &mut foreign["plan"]["paths"][0];
        home_row["gid"] = json!(loop_uid + 1);
        foreign["plan"]["paths"][1]["uid"] = json!(loop_uid + 1);
        foreign["plan"]["paths"][1]["gid"] = json!(loop_uid + 1);
        let error = read_private_record(&plan, &foreign, "dispatch", &step_dir)
            .expect_err("foreign-owned round component refuses");
        assert_eq!(error.kind, "unsafe-path");
        assert!(error.detail.contains("expected uid"));
        let mut conflicting = saved;
        conflicting["plan"]["paths"][1]["uid"] = json!(loop_uid + 1);
        let error = read_private_record(&plan, &conflicting, "dispatch", &step_dir)
            .expect_err("conflicting driver owner row refuses");
        assert_eq!(error.kind, "loop-identity");
        assert!(error.detail.contains("driver owner row"));
        fs::remove_dir_all(&step_dir).expect("remove round before driver fixture");
        let mut output = Vec::new();
        let absent = run_from_record(
            &plan,
            &before_driver,
            Some("dispatch"),
            &mut output,
            false,
            |step, directory| read_private_record(&plan, &before_driver, step, directory),
        )
        .expect_err("recorded directory absent");
        assert_eq!(absent.kind, "follow-round-directory");
        assert!(absent.detail.contains("absent before its driver starts"));
        assert!(String::from_utf8_lossy(&output).contains("\"kind\":\"round\""));
        let mut settled = before_driver;
        settled["rounds"][0]["phase"] = json!("settled");
        let absent = run_from_record(
            &plan,
            &settled,
            Some("dispatch"),
            &mut output,
            false,
            |step, directory| read_private_record(&plan, &settled, step, directory),
        )
        .expect_err("settled round directory absent");
        assert_eq!(absent.kind, "follow-round-directory");
        assert!(absent.detail.contains("phase settled"));
        assert!(!absent.detail.contains("before its driver starts"));
        symlink(plan.driver_dir.join("missing"), &step_dir).expect("linked round name");
        let linked = run_from_record(
            &plan,
            &settled,
            Some("dispatch"),
            &mut output,
            false,
            |step, directory| read_private_record(&plan, &settled, step, directory),
        )
        .expect_err("linked final name is not an absent directory");
        assert_eq!(linked.kind, "unsafe-path");
    }

    /// ´test:unit:public-follow-resumed-round-reuses-first-directory´
    #[test]
    fn public_follow_resumed_round_reuses_first_directory() {
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: PathBuf::from("/runs/R"),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let record = json!({"rounds":[
            {"step":"dispatch","phase":"settled","driver_dir":"/runs/R/first-dispatch"},
            {"step":"review","phase":"running","driver_dir":"/runs/R/first-dispatch"}
        ]});
        let mut output = Vec::new();
        run_from_record(
            &plan,
            &record,
            Some("review"),
            &mut output,
            false,
            |step, directory| {
                assert_eq!(step, "review");
                assert_eq!(directory, Path::new("/runs/R/first-dispatch"));
                Ok("{\"kind\":\"letter\"}\n".into())
            },
        )
        .expect("resumed follow");
        let output = String::from_utf8(output).expect("utf8 output");
        let lines = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("record"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            json!({"kind":"round","round":"review","driver_dir":"/runs/R/first-dispatch","phase":"running"})
        );
        assert_eq!(lines[1]["kind"], "letter");
    }

    /// ´test:unit:public-follow-round-only-uses-reservation-without-private-read´
    #[test]
    fn public_follow_round_only_uses_reservation_without_private_read() {
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: PathBuf::from("/runs/R"),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let record = json!({"rounds":[
            {"step":"dispatch","phase":"settled","driver_dir":"/runs/R/first-dispatch"},
            {"step":"review","phase":"running","driver_dir":"/runs/R/second-review"}
        ]});
        let mut calls = Vec::new();
        let mut all = Vec::new();
        run_from_record(&plan, &record, None, &mut all, true, |step, _| {
            calls.push(step.to_owned());
            Ok(String::new())
        })
        .expect("all round records");
        assert!(calls.is_empty(), "private closure was not called");
        let all = String::from_utf8(all).expect("utf8 output");
        let headers = all
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("round record"))
            .collect::<Vec<_>>();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0]["round"], "dispatch");
        assert_eq!(headers[1]["round"], "review");
        for header in &headers {
            let keys = header
                .as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                keys,
                BTreeSet::from(["kind", "round", "driver_dir", "phase"])
            );
        }
        let mut selected = Vec::new();
        run_from_record(
            &plan,
            &record,
            Some("review"),
            &mut selected,
            true,
            |step, _| {
                calls.push(step.to_owned());
                Ok(String::new())
            },
        )
        .expect("selected round record");
        assert!(calls.is_empty(), "private closure was not called");
        let selected = String::from_utf8(selected).expect("utf8 output");
        assert_eq!(selected.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(selected.trim()).expect("header")["round"],
            "review"
        );
    }

    /// ´test:unit:public-follow-refuses-missing-recorded-directory´
    #[test]
    fn public_follow_refuses_missing_recorded_directory() {
        let plan = Plan {
            home: PathBuf::from("/home/worker"),
            driver_dir: PathBuf::from("/runs/R"),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let record = json!({"rounds":[{"step":"dispatch","phase":"running"}]});
        let error = run_from_record(&plan, &record, None, &mut Vec::new(), false, |_, _| {
            Ok(String::new())
        })
        .expect_err("directory is absent");
        assert_eq!(error.kind, "follow-record");
        assert_eq!(error.detail, "round has no recorded driver directory");
    }

    fn assert_link_refusals(plan: &Plan, saved: &Value, step_dir: &Path) {
        // A pinned step alone does not authorize links in its boundary archive.
        symlink(step_dir, step_dir.join("steps")).expect("linked steps");
        let error = read_private_record(plan, saved, "dispatch", step_dir)
            .expect_err("linked steps refuse");
        assert_eq!(error.kind, "follow-boundary");
        assert!(error.detail.contains("steps"));
        fs::remove_file(step_dir.join("steps")).expect("remove linked steps");
        fs::create_dir(step_dir.join("steps")).expect("steps directory");
        fs::set_permissions(step_dir.join("steps"), fs::Permissions::from_mode(0o755))
            .expect("steps mode");
        symlink(step_dir, step_dir.join("steps/dispatch")).expect("linked archive");
        let error = read_private_record(plan, saved, "dispatch", step_dir)
            .expect_err("linked archive refuses");
        assert_eq!(error.kind, "follow-boundary");
        assert!(error.detail.contains("step dispatch"), "{}", error.line());
        fs::remove_file(step_dir.join("steps/dispatch")).expect("remove linked archive");
        fs::create_dir(step_dir.join("steps/dispatch")).expect("archive directory");
        fs::set_permissions(
            step_dir.join("steps/dispatch"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("archive mode");
        symlink(
            step_dir.join(".event-start"),
            step_dir.join("steps/dispatch/event-end.txt"),
        )
        .expect("linked boundary file");
        let error = read_private_record(plan, saved, "dispatch", step_dir)
            .expect_err("linked boundary file refuses");
        assert_eq!(error.kind, "follow-boundary");
        assert!(error.detail.contains("event-end.txt"));
    }

    /// ´test:unit:public-follow-refuses-foreign-owned-archive´
    #[test]
    fn public_follow_refuses_foreign_owned_archive() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let runs = fixture.path().join("runs");
        let root = runs.join("R");
        let step_dir = root.join("20261007T043545Z-dispatch");
        let archive = step_dir.join("steps/dispatch");
        fs::create_dir_all(&archive).expect("archive");
        for directory in [step_dir.join("steps"), archive.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                .expect("boundary directory mode");
        }
        for directory in [fixture.path(), runs.as_path(), root.as_path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("owner directory");
        }
        fs::set_permissions(&step_dir, fs::Permissions::from_mode(0o755)).expect("step directory");
        fs::write(step_dir.join("events.jsonl"), b"{}\n").expect("events");
        fs::write(step_dir.join(".event-start"), b"0\n").expect("current boundary");
        fs::write(archive.join("event-start.txt"), b"0\n").expect("archive start");
        fs::write(archive.join("event-end.txt"), b"0\n").expect("archive end");
        let plan = Plan {
            home: fixture.path().join("home-R"),
            driver_dir: root.clone(),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let loop_uid = Uid::effective().as_raw();
        let record = json!({"loop":"alpha","run":"R","plan":{"home":plan.home,"driver_dir":root,"paths":[{"path":plan.home,"uid":loop_uid,"gid":loop_uid},{"path":root,"kind":"directory","uid":loop_uid,"gid":loop_uid}]},"rounds":[{"step":"dispatch","phase":"running","driver_dir":step_dir}],"letters":[]});
        let home_anchor = File::open(fixture.path()).expect("home anchor");
        let runs_anchor = File::open(&runs).expect("runs anchor");
        let _private = home::activate_private_launch(
            fixture.path(),
            &home_anchor,
            &runs,
            &runs_anchor,
            None,
            loop_uid,
        )
        .expect("private entry anchors");
        let foreign_uid = if loop_uid == 3001 { 3000 } else { 3001 };
        let error = run_from_record(
            &plan,
            &record,
            None,
            &mut Vec::new(),
            false,
            |step, directory| {
                let request = private_request(
                    "/usr/bin/superloop-lane",
                    fixture.path(),
                    "alpha",
                    "R",
                    step,
                    directory,
                    "fixture-identity",
                )?;
                assert_eq!(request[2], "_follow-private");
                read_private_record_with(&plan, &record, step, directory, |pinned, size, uid| {
                    lane_lifecycle::validated_event_boundaries_at_with_metadata(
                        pinned,
                        size,
                        uid,
                        |component, name| {
                            let metadata = component.metadata()?;
                            let actual = if name == "step dispatch" {
                                foreign_uid
                            } else {
                                metadata.uid()
                            };
                            Ok((actual, metadata.mode() & 0o7777))
                        },
                    )
                    .map_err(|error| LaneError::input("follow-boundary", error.to_string()))
                })
            },
        )
        .expect_err("foreign-owned archive refuses through public request");
        assert_eq!(error.kind, "follow-boundary");
        assert!(error.detail.contains("step dispatch"), "{}", error.line());
        assert!(error.detail.contains(&format!("uid {foreign_uid}")));
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o777))
            .expect("writable archive mode");
        let error = read_private_record(&plan, &record, "dispatch", &step_dir)
            .expect_err("writable archive refuses by real metadata");
        assert_eq!(error.kind, "follow-boundary");
        assert!(error.detail.contains("mode 0777"));
    }

    /// ´test:unit:follow-renders-observation-revisions-before-completion-and-events´
    #[test]
    fn follow_renders_observation_revisions_before_completion_and_events() {
        let record = json!({"rounds":[{"step":"dispatch","reply":{"bytes":12}}],"letters":[]});
        let observations = [
            json!({"round":"dispatch","box":"outbox","name":"dispatch.md","bytes":12,"revision":3,"state":"complete","at":"2026-10-07T00:00:03Z","line":"complete"}),
            json!({"round":"dispatch","box":"outbox","name":"dispatch.md","bytes":5,"revision":1,"state":"observed","at":"2026-10-07T00:00:01Z","line":"first"}),
            json!({"round":"dispatch","box":"outbox","name":"dispatch.md","bytes":12,"revision":2,"state":"observed","at":"2026-10-07T00:00:02Z","line":"growth"}),
        ];
        let bounds = BTreeMap::from([("dispatch".to_owned(), (0, 3))]);
        let rendered = render(&record, &observations, b"{}\n", &bounds, None).expect("follow");
        let lines = rendered
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("record"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0]["revision"], 1);
        assert_eq!(lines[0]["state"], "observed");
        assert_eq!(lines[1]["revision"], 2);
        assert_eq!(lines[1]["state"], "observed");
        assert_eq!(lines[2]["revision"], 3);
        assert_eq!(lines[2]["state"], "complete");
        assert_eq!(lines[3]["kind"], "event-delta");
    }

    /// ´test:unit:follow-refuses-a-broken-archived-boundary-chain´
    #[test]
    fn follow_refuses_a_broken_archived_boundary_chain() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let archive = fixture.path().join("steps/dispatch");
        fs::create_dir_all(&archive).expect("archive");
        for directory in [fixture.path().join("steps"), archive.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                .expect("boundary directory mode");
        }
        fs::write(archive.join("event-start.txt"), b"0\n").expect("first start");
        fs::write(archive.join("event-end.txt"), b"2\n").expect("first end");
        fs::write(fixture.path().join(".event-start"), b"2\n").expect("current start");
        let rounds = [json!({"step":"dispatch"}), json!({"step":"review"})];
        let pinned = File::open(fixture.path()).expect("step directory");
        let checked = || {
            let validated = lane_lifecycle::validated_event_boundaries_at(
                &pinned,
                4,
                Uid::effective().as_raw(),
            )
            .map_err(|error| LaneError::input("follow-boundary", error.to_string()))?;
            boundaries_for_rounds(&validated, &rounds, 4)
        };
        let first = checked();
        assert!(first.is_ok(), "{first:?}");
        fs::write(archive.join("event-end.txt"), b"1\n").expect("wrong end");
        let error = checked().expect_err("broken chain");
        assert!(error.line().contains("follow-boundary"));
        assert!(
            error
                .line()
                .contains("step dispatch: end 1 != current start 2")
        );
        fs::write(archive.join("event-end.txt"), b"2\n").expect("restored end");
        fs::write(fixture.path().join(".event-start"), b"3\n").expect("wrong current start");
        assert!(
            checked()
                .expect_err("last boundary")
                .line()
                .contains("step dispatch: end 2 != current start 3")
        );
    }
}
