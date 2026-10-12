use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::{AtFlags, RenameFlags, renameat2};
use nix::sys::stat::fstatat;
use nix::unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat};
use serde_json::{Value, json};

use super::{LaunchModel, lock_mailbox, publish_reservation, read_reservation, reservation_path};
use crate::build;
use crate::error::LaneError;
use crate::home;

pub struct SendLetterRequest {
    pub loop_name: String,
    pub run: String,
    pub step: String,
    pub letter: PathBuf,
}

pub struct WithdrawLetterRequest {
    pub loop_name: String,
    pub run: String,
    pub step: String,
}

impl WithdrawLetterRequest {
    /// Parse a withdrawal by step name.
    ///
    /// # Errors
    ///
    /// Refuses missing, repeated, or malformed fields.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, flag, step] = args else {
            return Err(LaneError::input(
                "letter-usage",
                "withdraw-letter LOOP RUN --step STEP (keeps the placement record; removes its inbox file only before the round starts)",
            ));
        };
        if flag != "--step" {
            return Err(LaneError::input("letter-usage", "expected --step STEP"));
        }
        valid_step(step)?;
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            step: step.clone(),
        })
    }
}

impl SendLetterRequest {
    /// Parse a single bounded letter placement.
    ///
    /// # Errors
    ///
    /// Refuses missing, repeated or malformed fields.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "letter-usage",
                "send-letter LOOP RUN --step STEP --letter FILE (resumed letters may omit Model and Effort; missing values come from the recorded selection). The worker's reply for step STEP is written to `outbox/STEP.md`; nothing else is read.",
            ));
        };
        let mut step = None;
        let mut letter = None;
        let mut index = 0;
        while index < rest.len() {
            let value = rest
                .get(index + 1)
                .ok_or_else(|| LaneError::input("letter-usage", "option value is absent"))?;
            match rest[index].as_str() {
                "--step" if step.is_none() => step = Some(value.clone()),
                "--letter" if letter.is_none() => letter = Some(PathBuf::from(value)),
                _ => {
                    return Err(LaneError::input(
                        "letter-usage",
                        "unexpected or repeated option",
                    ));
                }
            }
            index += 2;
        }
        let step = step.ok_or_else(|| LaneError::input("letter-usage", "--step is absent"))?;
        valid_step(&step)?;
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            step,
            letter: letter.ok_or_else(|| LaneError::input("letter-usage", "--letter is absent"))?,
        })
    }
}

/// Keep a round name to one plain mailbox word.
///
/// # Errors
///
/// Refuses punctuation, whitespace and names beyond the mailbox bound.
pub fn valid_step(step: &str) -> Result<(), LaneError> {
    let bytes = step.as_bytes();
    if (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(LaneError::input(
            "round-step",
            format!("{step:?} is not a plain step word"),
        ))
    }
}

pub(crate) fn unix_ns() -> Result<u64, LaneError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| LaneError::operation("letter-clock", error.to_string()))?
        .as_nanos();
    u64::try_from(nanos).map_err(|_| LaneError::operation("letter-clock", "instant exceeds u64"))
}

/// Read the optional stop declaration from the opening letter block.
///
/// # Errors
///
/// Refuses a repeated declaration or any value other than `yes`.
pub(crate) fn stop_declaration(letter: &[u8]) -> Result<bool, LaneError> {
    let text = std::str::from_utf8(letter)
        .map_err(|_| LaneError::input("letter-stop", "letter is not UTF-8"))?;
    let mut stop = None;
    for line in text.lines().take(16) {
        let line = line.trim().trim_start_matches("- ");
        let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("stop")
            && stop.replace(value.trim().to_owned()).is_some()
        {
            return Err(LaneError::input(
                "letter-stop",
                "Stop is repeated in the opening declaration",
            ));
        }
    }
    match stop.as_deref() {
        None => Ok(false),
        Some("yes") => Ok(true),
        Some(value) => Err(LaneError::input(
            "letter-stop",
            format!("Stop has unsupported value {value:?}; expected yes"),
        )),
    }
}

/// Resolve interrupted publication from the named inbox file while the mailbox lock is held.
///
/// # Errors
///
/// Refuses a visible file whose custody, size or digest differs from its placement record.
pub(crate) fn reconcile_placing(
    record: &mut Value,
    inbox: &Path,
    owner_home: &Path,
    owner_uid: u32,
) -> Result<Vec<Value>, LaneError> {
    let mut changes = Vec::new();
    let letters = record["letters"].as_array_mut().ok_or_else(|| {
        LaneError::input("letter-record", "letters are absent from the reservation")
    })?;
    for entry in letters
        .iter_mut()
        .filter(|entry| entry["state"] == "placing")
    {
        let name = entry["name"]
            .as_str()
            .ok_or_else(|| LaneError::input("letter-reconcile", "placement name is absent"))?
            .to_owned();
        let step = entry["step"].as_str().ok_or_else(|| {
            LaneError::input("letter-reconcile", format!("{name}: step is absent"))
        })?;
        valid_step(step)?;
        if !(name == format!("{step}.md")
            || entry["in_round"] == true
                && name
                    .strip_prefix(&format!("{step}-"))
                    .and_then(|tail| tail.strip_suffix(".md"))
                    .is_some_and(|number| number.parse::<u32>().is_ok_and(|number| number > 0)))
        {
            return Err(LaneError::input(
                "letter-reconcile",
                format!("{name}: placement name is malformed"),
            ));
        }
        let path = inbox.join(&name);
        let state = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "abandoned",
            Err(error) => {
                return Err(LaneError::input(
                    "letter-reconcile",
                    format!("{name}: {error}"),
                ));
            }
            Ok(meta) => {
                if !meta.is_file()
                    || meta.uid() != owner_uid
                    || meta.permissions().mode() & 0o7777 != 0o640
                {
                    return Err(LaneError::input(
                        "letter-reconcile",
                        format!("{name}: visible file has foreign kind, owner or mode"),
                    ));
                }
                let bytes = home::read_letter(&path, owner_uid)?;
                if entry["bytes"] != bytes.len()
                    || entry["sha256"] != build::sha256_bytes(&bytes, owner_home)?
                {
                    return Err(LaneError::input(
                        "letter-reconcile",
                        format!("{name}: visible file differs from recorded size or digest"),
                    ));
                }
                "placed"
            }
        };
        let at = unix_ns()?;
        entry["state"] = json!(state);
        entry["reconciled_at_unix_ns"] = json!(at);
        entry["reconciliation"] = json!(if state == "placed" {
            "visible-file-verified"
        } else {
            "file-absent-name-retired"
        });
        changes.push(
            json!({"name":name,"state":state,"at_unix_ns":at,"reason":entry["reconciliation"]}),
        );
    }
    Ok(changes)
}

/// Reconcile one run from owner custody before a round is inspected or settled.
///
/// # Errors
///
/// Refuses a changed mailbox or placement record without replacing it.
pub(crate) fn reconcile_run(
    plan: &crate::plan::Plan,
    run: &str,
    owner_home: &Path,
    owner_uid: u32,
    publish: bool,
) -> Result<(Value, Vec<Value>), LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("letter-reconcile", "runs root is absent"))?;
    let _mailbox = lock_mailbox(root, run, owner_uid)?;
    let path = reservation_path(root, run);
    let mut record = read_reservation(&path)?
        .ok_or_else(|| LaneError::input("letter-reconcile", "reservation is absent"))?;
    if record["run"] != run
        || record["loop"] != plan.document["loop"]
        || record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "letter-reconcile",
            "reservation names another run or home",
        ));
    }
    let changes = reconcile_placing(
        &mut record,
        &plan.home.join(".local/inbox"),
        owner_home,
        owner_uid,
    )?;
    if publish && !changes.is_empty() {
        publish_reservation(&path, &record)?;
    }
    Ok((record, changes))
}

fn selected_name(record: &Value, step: &str, inbox: &Path) -> Result<(String, bool), LaneError> {
    if !["started", "settled"].contains(&record["phase"].as_str().unwrap_or_default()) {
        return Err(LaneError::input(
            "letter-run-state",
            "run is neither live nor settled; for a failed round with recorded driver and helper completion preview settle LOOP RUN --round STEP --dry-run, then apply its preview_sha256 with --expect-digest before placing the next letter",
        ));
    }
    let rounds = record["rounds"].as_array().ok_or_else(|| {
        LaneError::input("letter-record", "rounds are absent from the reservation")
    })?;
    let in_round = record["phase"] == "started" && record["active_round"] == step;
    if !in_round && rounds.iter().any(|round| round["step"] == step) {
        return Err(LaneError::input(
            "round-step",
            format!("step {step} already ran"),
        ));
    }
    if !in_round {
        if record["letters"].as_array().is_some_and(|letters| {
            letters.iter().any(|letter| {
                letter["name"] == format!("{step}.md") && letter["state"] != "withdrawn"
            })
        }) {
            return Err(LaneError::input(
                "letter-exists",
                format!("{step}.md already has a placement record"),
            ));
        }
        return Ok((format!("{step}.md"), false));
    }
    for number in 1..=10_000 {
        let name = format!("{step}-{number}.md");
        if record["letters"]
            .as_array()
            .is_some_and(|letters| letters.iter().any(|letter| letter["name"] == name))
        {
            continue;
        }
        match fs::symlink_metadata(inbox.join(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((name, true)),
            Ok(_) => {}
            Err(error) => return Err(LaneError::input("letter-inbox", error.to_string())),
        }
    }
    Err(LaneError::input(
        "letter-sequence",
        "in-round letter numbers are exhausted",
    ))
}

fn withdrawal_index(record: &Value, step: &str) -> Result<usize, LaneError> {
    if !["started", "settled"].contains(&record["phase"].as_str().unwrap_or_default()) {
        return Err(LaneError::input(
            "letter-run-state",
            "run is neither live nor settled",
        ));
    }
    if record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("letter-record", "rounds are absent"))?
        .iter()
        .any(|round| round["step"] == step)
    {
        return Err(LaneError::input(
            "round-step",
            format!("step {step} already ran; {step}.md cannot be withdrawn"),
        ));
    }
    let name = format!("{step}.md");
    record["letters"]
        .as_array()
        .ok_or_else(|| LaneError::input("letter-record", "letters are absent"))?
        .iter()
        .rposition(|letter| {
            letter["name"] == name
                && letter["step"] == step
                && letter["in_round"] == false
                && (letter["state"] == "placed" || letter["state"] == "withdrawing")
        })
        .ok_or_else(|| LaneError::input("letter-withdraw", format!("{name} has no placed letter")))
}

/// Publish a letter through the same verified descriptor transfer as make-home.
///
/// # Errors
///
/// Refuses an unsafe source, run, selection or private launch.
pub fn run(owner_home: &Path, request: &SendLetterRequest) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    let (plan, _settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("letter-run", "runs root is absent"))?;
    let reservation = reservation_path(root, &request.run);
    let record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("letter-run-state", "run is not live or settled"))?;
    if record["loop"] != request.loop_name
        || record["run"] != request.run
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "letter-run",
            "reservation names another run or home",
        ));
    }
    let source = home::read_letter(&request.letter, caller)?;
    let digest = build::sha256_bytes(&source, owner_home)?;
    let podman = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("letter-run", "container program is absent"))?,
    );
    crate::pinned::owner_executable(&podman, caller)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("letter-program", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, caller)?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, caller, 0)?;
    let verified_runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, caller, 0)?;
    let letter_dir = request
        .letter
        .parent()
        .ok_or_else(|| LaneError::input("letter-path", "letter parent is absent"))?;
    let verified_letter =
        home::verify_host_launch_root(Path::new("/"), owner_home, letter_dir, caller, 0)?;
    let argv = vec![
        "unshare".into(),
        exe_word,
        "_send-letter".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--letter".into(),
        crate::pinned::path_word(&request.letter, "letter-path")?,
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--step".into(),
        request.step.clone(),
        "--expected-sha256".into(),
        digest,
    ];
    let environment = super::launch_environment(owner_home)?;
    let output = build::run_checked_with_private_launch(
        &podman,
        argv,
        &environment,
        owner_home,
        60,
        "send-letter",
        &verified_home,
        root,
        &verified_runs,
        Some((letter_dir, &verified_letter)),
    )?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::input("letter-result", error.to_string()))
}

/// Make a completed inbox entry visible only after the owner reservation names it.
///
/// # Errors
///
/// Refuses changed source bytes, selection, run phase or mailbox metadata.
#[allow(clippy::too_many_lines)]
pub fn private_send(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    source: &Path,
    step: &str,
    expected_sha256: &str,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    private_send_with_owner(owner_home, loop_name, run, source, step, expected_sha256, 0)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn private_send_with_owner(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    source: &Path,
    step: &str,
    expected_sha256: &str,
    owner: u32,
) -> Result<Value, LaneError> {
    valid_step(step)?;
    let (plan, _settings) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("letter-run", "runs root is absent"))?;
    let reservation = reservation_path(root, run);
    let _mailbox = lock_mailbox(root, run, owner)?;
    let mut record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("letter-run-state", "run is not live or settled"))?;
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "letter-run",
            "reservation names another run or home",
        ));
    }
    let reconciled = reconcile_placing(
        &mut record,
        &plan.home.join(".local/inbox"),
        owner_home,
        owner,
    )?;
    if !reconciled.is_empty() {
        publish_reservation(&reservation, &record)?;
    }
    let bytes = home::read_letter(source, owner)?;
    let stop_requested = stop_declaration(&bytes)?;
    let digest = build::sha256_bytes(&bytes, owner_home)?;
    if digest != expected_sha256 {
        return Err(LaneError::input(
            "letter-source",
            "letter changed after owner verification",
        ));
    }
    let selection = LaunchModel::select(
        &bytes,
        record["model_selection"]["model"].as_str(),
        record["model_selection"]["effort"].as_str(),
    )?;
    if selection.model != record["model_selection"]["model"]
        || selection.effort != record["model_selection"]["effort"]
    {
        return Err(LaneError::input(
            "letter-model",
            "opening Model or Effort differs from the recorded selection; a resumed letter may omit either field",
        ));
    }
    let inbox = plan.home.join(".local/inbox");
    place_letter(
        &mut record,
        &reservation,
        &inbox,
        loop_name,
        run,
        step,
        &bytes,
        &digest,
        stop_requested,
        &reconciled,
        owner,
    )
}

#[allow(clippy::too_many_arguments)]
fn place_letter(
    record: &mut Value,
    reservation: &Path,
    inbox: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    bytes: &[u8],
    digest: &str,
    stop_requested: bool,
    reconciled: &[Value],
    owner_uid: u32,
) -> Result<Value, LaneError> {
    let directory = home::pin_parent(inbox, owner_uid)?;
    let (name, in_round) = selected_name(record, step, inbox)?;
    if in_round {
        let pid = record["driver_entry_pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or_else(|| {
                LaneError::input("letter-run-state", "live round has no driver identity")
            })?;
        let start = record["driver_entry_start"].as_u64().ok_or_else(|| {
            LaneError::input("letter-run-state", "live round has no driver start")
        })?;
        if super::super::container_helper::process_presence(pid, start)
            != super::super::container_helper::ProcessPresence::Present
        {
            return Err(LaneError::input(
                "letter-run-state",
                "round driver is no longer live",
            ));
        }
    }
    if fs::symlink_metadata(inbox.join(&name)).is_ok() {
        return Err(LaneError::input(
            "letter-exists",
            format!("{name} already exists"),
        ));
    }
    let loop_uid = super::recorded_loop_uid(record)?;
    let at = unix_ns()?;
    let temp = format!(".placing-{}-{at}", std::process::id());
    stage_letter(&directory, &temp, bytes, owner_uid, loop_uid)?;
    let entry = json!({"step":step,"name":name,"in_round":in_round,"stop":stop_requested,"bytes":bytes.len(),"sha256":digest,"placed_at_unix_ns":at,"state":"placing"});
    record["letters"]
        .as_array_mut()
        .ok_or_else(|| {
            LaneError::input("letter-record", "letters are absent from the reservation")
        })?
        .push(entry);
    publish_reservation(reservation, record)?;
    publish_letter(&directory, inbox, &temp, &name)?;
    if let Some(entry) = record["letters"]
        .as_array_mut()
        .and_then(|letters| letters.last_mut())
    {
        entry["state"] = json!("placed");
    }
    publish_reservation(reservation, record)?;
    Ok(
        json!({"schema":1,"command":"send-letter","loop":loop_name,"run":run,"step":step,"name":name,"in_round":in_round,"stop":stop_requested,"bytes":bytes.len(),"sha256":digest,"placed_at_unix_ns":at,"letter_reconciliation":reconciled,"changed":true}),
    )
}

/// Enter the protected namespace to withdraw a future round's placed letter.
///
/// # Errors
///
/// Refuses an unsafe run, missing placement, or started round.
pub fn withdraw(owner_home: &Path, request: &WithdrawLetterRequest) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    let (plan, _settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("letter-run", "runs root is absent"))?;
    let record = read_reservation(&reservation_path(root, &request.run))?
        .ok_or_else(|| LaneError::input("letter-run-state", "run is not live or settled"))?;
    if record["loop"] != request.loop_name
        || record["run"] != request.run
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "letter-run",
            "reservation names another run or home",
        ));
    }
    let podman = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("letter-run", "container program is absent"))?,
    );
    crate::pinned::owner_executable(&podman, caller)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("letter-program", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, caller)?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, caller, 0)?;
    let verified_runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, caller, 0)?;
    let argv = vec![
        "unshare".into(),
        exe_word,
        "_withdraw-letter".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--step".into(),
        request.step.clone(),
    ];
    let output = build::run_checked_with_private_launch(
        &podman,
        argv,
        &super::launch_environment(owner_home)?,
        owner_home,
        60,
        "withdraw-letter",
        &verified_home,
        root,
        &verified_runs,
        None,
    )?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::input("letter-result", error.to_string()))
}

/// Remove the named inbox placement while retaining its reservation row.
///
/// # Errors
///
/// Refuses a started round, changed inbox file, or missing placement.
pub fn private_withdraw(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    valid_step(step)?;
    let (plan, _settings) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("letter-run", "runs root is absent"))?;
    let reservation = reservation_path(root, run);
    let _mailbox = lock_mailbox(root, run, 0)?;
    let mut record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("letter-run-state", "run is not live or settled"))?;
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "letter-run",
            "reservation names another run or home",
        ));
    }
    let inbox = plan.home.join(".local/inbox");
    if !reconcile_placing(&mut record, &inbox, owner_home, 0)?.is_empty() {
        publish_reservation(&reservation, &record)?;
    }
    withdraw_placement(
        &mut record,
        &reservation,
        &inbox,
        owner_home,
        loop_name,
        run,
        step,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn withdraw_placement(
    record: &mut Value,
    reservation: &Path,
    inbox: &Path,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    owner_uid: u32,
) -> Result<Value, LaneError> {
    let name = format!("{step}.md");
    let index = withdrawal_index(record, step)?;
    let entry = &record["letters"][index];
    let was_placed = entry["state"] == "placed";
    let path = inbox.join(&name);
    let directory = home::pin_parent(inbox, owner_uid)?;
    match fstatat(&directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => {
            let bytes = home::read_letter_at(&directory, std::ffi::OsStr::new(&name), &path)?;
            if entry["bytes"] != bytes.len()
                || entry["sha256"] != build::sha256_bytes(&bytes, owner_home)?
            {
                return Err(LaneError::input(
                    "letter-withdraw",
                    format!("{name} differs from protected placement"),
                ));
            }
            if was_placed {
                record["letters"][index]["state"] = json!("withdrawing");
                publish_reservation(reservation, record)?;
            }
            unlinkat(&directory, name.as_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(|error| LaneError::operation("letter-withdraw", error.to_string()))?;
        }
        Err(nix::errno::Errno::ENOENT) if !was_placed => {}
        Err(error) => {
            return Err(LaneError::input(
                "letter-withdraw",
                format!("{name}: {error}"),
            ));
        }
    }
    fs::File::from(directory)
        .sync_all()
        .map_err(|error| LaneError::operation("letter-withdraw", error.to_string()))?;
    record["letters"][index]["state"] = json!("withdrawn");
    publish_reservation(reservation, record)?;
    Ok(
        json!({"schema":1,"command":"withdraw-letter","loop":loop_name,"run":run,"step":step,"name":name,"placement_retained":true,"inbox_removed":true,"changed":true}),
    )
}

// Shared with the injected callback fixture so its publications use the owner's code.
fn stage_letter(
    directory: &OwnedFd,
    temp: &str,
    bytes: &[u8],
    owner: u32,
    group: u32,
) -> Result<(), LaneError> {
    let temporary_path = PathBuf::from(format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), temp));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary_path)
        .map_err(|error| LaneError::operation("letter-publish", format!("{temp}: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| LaneError::operation("letter-publish", error.to_string()))?;
    fchown(
        &file,
        Some(Uid::from_raw(owner)),
        Some(Gid::from_raw(group)),
    )
    .map_err(|error| LaneError::operation("letter-publish", error.to_string()))?;
    file.set_permissions(fs::Permissions::from_mode(0o640))
        .map_err(|error| LaneError::operation("letter-publish", error.to_string()))?;
    file.sync_all()
        .map_err(|error| LaneError::operation("letter-publish", error.to_string()))?;
    Ok(())
}

fn publish_letter(
    directory: &OwnedFd,
    inbox: &Path,
    temp: &str,
    name: &str,
) -> Result<(), LaneError> {
    renameat2(
        directory,
        temp,
        directory,
        name,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| LaneError::operation("letter-publish", format!("{name}: {error}")))?;
    fs::File::open(inbox)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| LaneError::operation("letter-publish", error.to_string()))?;
    Ok(())
}

#[cfg(test)]
#[path = "letters_callback.rs"]
mod callback_tests;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use nix::unistd::{Gid, Uid};
    use serde_json::json;

    use super::{
        SendLetterRequest, WithdrawLetterRequest, place_letter, reconcile_placing, selected_name,
        stop_declaration, valid_step, withdraw_placement,
    };

    /// ´test:unit:stop-declaration-is-bounded-and-explicit´
    #[test]
    fn stop_declaration_is_bounded_and_explicit() {
        assert!(!stop_declaration(b"Model: gpt-6-sol\nEffort: high\n").expect("ordinary letter"));
        assert!(
            stop_declaration(b"Model: gpt-6-sol\nEffort: high\nStop: yes\n").expect("stop letter")
        );
        for letter in [
            b"Stop: no\n".as_slice(),
            b"Stop: yes\nStop: yes\n".as_slice(),
            b"Stop: perhaps\n".as_slice(),
        ] {
            assert_eq!(
                stop_declaration(letter).expect_err("bad stop").kind,
                "letter-stop"
            );
        }
    }

    /// ´test:unit:letter-step-refuses-nonwords´
    #[test]
    fn letter_step_refuses_nonwords() {
        for word in ["", "two words", "x/y", "x.y", "-x", "x\n"] {
            assert_eq!(valid_step(word).expect_err("not a word").kind, "round-step");
        }
        valid_step("review_2").expect("plain word");
    }

    /// ´test:unit:letter-number-follows-the-live-round´
    #[test]
    fn letter_number_follows_the_live_round() {
        let fixture = tempfile::tempdir().expect("isolated mailbox");
        let record = json!({"phase":"started","active_round":"review","rounds":[{"step":"review"}],"letters":[{"name":"review-1.md"}]});
        assert_eq!(
            selected_name(&record, "review", fixture.path()).expect("next letter"),
            ("review-2.md".into(), true)
        );
        assert_eq!(
            selected_name(&record, "next", fixture.path()).expect("future round"),
            ("next.md".into(), false)
        );
        let error = selected_name(
            &json!({"phase":"failed","rounds":[]}),
            "review",
            fixture.path(),
        )
        .expect_err("not live or settled");
        assert_eq!(error.kind, "letter-run-state");
        assert!(
            error
                .detail
                .contains("preview settle LOOP RUN --round STEP --dry-run")
        );
        assert!(
            error
                .detail
                .contains("apply its preview_sha256 with --expect-digest")
        );
    }

    /// ´test:unit:withdraw-letter-keeps-evidence-and-allows-a-new-placement´
    #[test]
    fn withdraw_letter_keeps_evidence_and_allows_a_new_placement() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected root");
        let inbox = fixture.path().join("inbox");
        fs::create_dir(&inbox).expect("inbox");
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).expect("protected inbox");
        let path = inbox.join("verify-1.md");
        let original = b"first letter\n";
        fs::write(&path, original).expect("placed letter");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("placed file mode");
        let digest = crate::build::sha256_bytes(original, fixture.path()).expect("digest");
        let group = Gid::effective().as_raw();
        let home = fixture.path().display().to_string();
        let driver = fixture.path().join("driver").display().to_string();
        let plan = json!({"home":home,"driver_dir":driver,"paths":[{"path":home,"gid":group},{"path":driver,"uid":group,"gid":group,"kind":"directory"}]});
        let mut record = json!({"phase":"settled","plan":plan,"rounds":[{"step":"dispatch"}],"letters":[{"step":"verify-1","name":"verify-1.md","in_round":false,"bytes":original.len(),"sha256":digest,"placed_at_unix_ns":11,"state":"placed"}]});
        let request =
            WithdrawLetterRequest::parse(&["alpha", "R", "--step", "verify-1"].map(str::to_owned))
                .expect("production withdrawal form");
        let reservation = fixture.path().join("reservation.json");
        let report = withdraw_placement(
            &mut record,
            &reservation,
            &inbox,
            fixture.path(),
            &request.loop_name,
            &request.run,
            &request.step,
            Uid::effective().as_raw(),
        )
        .expect("withdrawal");
        assert_eq!(report["name"], "verify-1.md");
        assert!(!path.exists());
        assert_eq!(record["letters"][0]["state"], "withdrawn");
        assert_eq!(record["letters"][0]["sha256"], digest);
        assert_eq!(record["letters"][0]["placed_at_unix_ns"], 11);
        let replacement = SendLetterRequest::parse(
            &[
                "alpha",
                "R",
                "--step",
                "verify-1",
                "--letter",
                "/tmp/replacement.md",
            ]
            .map(str::to_owned),
        )
        .expect("production sender form");
        assert_eq!(
            selected_name(&record, &replacement.step, &inbox).expect("name can be reused"),
            ("verify-1.md".into(), false)
        );
        let new_letter = b"replacement\n";
        let new_digest =
            crate::build::sha256_bytes(new_letter, fixture.path()).expect("new digest");
        let placed = place_letter(
            &mut record,
            &reservation,
            &inbox,
            &replacement.loop_name,
            &replacement.run,
            &replacement.step,
            new_letter,
            &new_digest,
            false,
            &[],
            Uid::effective().as_raw(),
        )
        .expect("sender places replacement through production publication");
        assert_eq!(placed["name"], "verify-1.md");
        assert_eq!(fs::read(&path).expect("published letter"), new_letter);
        assert_eq!(record["letters"].as_array().expect("rows").len(), 2);
        assert_eq!(
            selected_name(&record, "verify-1", &inbox)
                .expect_err("new placement now blocks duplicates")
                .kind,
            "letter-exists"
        );
    }

    /// ´test:unit:withdraw-letter-refuses-vanished-placed-file-without-changing-record´
    #[test]
    fn withdraw_letter_refuses_vanished_placed_file_without_changing_record() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected root");
        let inbox = fixture.path().join("inbox");
        fs::create_dir(&inbox).expect("inbox");
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).expect("protected inbox");
        let name = "verify-1.md";
        let letter = b"placed letter\n";
        let digest = crate::build::sha256_bytes(letter, fixture.path()).expect("digest");
        let mut record = json!({"phase":"settled","rounds":[{"step":"dispatch"}],"letters":[{"step":"verify-1","name":name,"in_round":false,"bytes":letter.len(),"sha256":digest,"placed_at_unix_ns":11,"state":"placed"}]});
        let reservation = fixture.path().join("reservation.json");
        super::super::publish_reservation(&reservation, &record).expect("placed record");
        let before = record.clone();
        let saved = fs::read(&reservation).expect("saved record");
        let request =
            WithdrawLetterRequest::parse(&["alpha", "R", "--step", "verify-1"].map(str::to_owned))
                .expect("production withdrawal form");
        let error = withdraw_placement(
            &mut record,
            &reservation,
            &inbox,
            fixture.path(),
            &request.loop_name,
            &request.run,
            &request.step,
            Uid::effective().as_raw(),
        )
        .expect_err("vanished placed file refuses withdrawal");
        assert_eq!(error.kind, "letter-withdraw");
        assert!(error.detail.contains(name));
        assert_eq!(record["letters"][0]["state"], "placed");
        assert_eq!(record, before);
        assert_eq!(fs::read(&reservation).expect("unchanged record"), saved);
        assert!(!inbox.join(name).exists());
    }

    /// ´test:unit:withdraw-letter-recovers-an-interrupted-removal´
    #[test]
    fn withdraw_letter_recovers_an_interrupted_removal() {
        for file_present in [true, false] {
            let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
            fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
                .expect("protected root");
            let inbox = fixture.path().join("inbox");
            fs::create_dir(&inbox).expect("inbox");
            fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700))
                .expect("protected inbox");
            let path = inbox.join("verify-1.md");
            let original = b"first letter\n";
            if file_present {
                fs::write(&path, original).expect("interrupted removal");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                    .expect("placed file mode");
            }
            let digest = crate::build::sha256_bytes(original, fixture.path()).expect("digest");
            let mut record = json!({"phase":"settled","rounds":[{"step":"dispatch"}],"letters":[{"step":"verify-1","name":"verify-1.md","in_round":false,"bytes":original.len(),"sha256":digest,"placed_at_unix_ns":11,"state":"withdrawing"}]});
            assert_eq!(
                selected_name(&record, "verify-1", &inbox)
                    .expect_err("pending removal blocks replacement")
                    .kind,
                "letter-exists"
            );
            let reservation = fixture.path().join("reservation.json");
            withdraw_placement(
                &mut record,
                &reservation,
                &inbox,
                fixture.path(),
                "alpha",
                "R",
                "verify-1",
                Uid::effective().as_raw(),
            )
            .expect("retry completes withdrawal");
            assert!(!path.exists());
            assert_eq!(record["letters"][0]["state"], "withdrawn");
            assert_eq!(record["letters"][0]["placed_at_unix_ns"], 11);
            assert_eq!(
                selected_name(&record, "verify-1", &inbox).expect("replacement is available"),
                ("verify-1.md".into(), false)
            );
        }
    }

    /// ´test:unit:withdraw-letter-refuses-a-started-round-by-name´
    #[test]
    fn withdraw_letter_refuses_a_started_round_by_name() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let inbox = fixture.path().join("inbox");
        fs::create_dir(&inbox).expect("inbox");
        let path = inbox.join("verify-1.md");
        fs::write(&path, b"placed\n").expect("placed letter");
        let mut record = json!({"phase":"started","active_round":"verify-1","rounds":[{"step":"dispatch"},{"step":"verify-1"}],"letters":[{"step":"verify-1","name":"verify-1.md","in_round":false,"state":"placed"}]});
        let error = withdraw_placement(
            &mut record,
            &fixture.path().join("reservation.json"),
            &inbox,
            fixture.path(),
            "alpha",
            "R",
            "verify-1",
            Uid::effective().as_raw(),
        )
        .expect_err("started placement is retained");
        assert_eq!(error.kind, "round-step");
        assert!(error.detail.contains("verify-1.md"));
        assert!(path.exists());
        assert_eq!(record["letters"][0]["state"], "placed");
    }

    /// ´test:unit:placing-visible-file-becomes-placed-with-its-original-evidence´
    #[test]
    fn placing_visible_file_becomes_placed_with_its_original_evidence() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("isolated mailbox");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected mailbox");
        let path = fixture.path().join("dispatch-1.md");
        fs::write(&path, b"four").expect("visible publication");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mailbox mode");
        let digest = crate::build::sha256_bytes(b"four", fixture.path()).expect("digest");
        let mut record = json!({"letters":[{"step":"dispatch","name":"dispatch-1.md","in_round":true,"bytes":4,"sha256":digest,"placed_at_unix_ns":11,"state":"placing"}]});
        let changes = reconcile_placing(
            &mut record,
            fixture.path(),
            fixture.path(),
            Uid::effective().as_raw(),
        )
        .expect("verified publication");
        assert_eq!(changes[0]["state"], "placed");
        assert_eq!(record["letters"][0]["state"], "placed");
        assert_eq!(record["letters"][0]["placed_at_unix_ns"], 11);
        assert_eq!(record["letters"][0]["sha256"], digest);
        assert!(record["letters"][0]["reconciled_at_unix_ns"].is_u64());
    }

    /// ´test:unit:placing-absent-file-retires-its-name´
    #[test]
    fn placing_absent_file_retires_its_name() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("isolated mailbox");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected mailbox");
        let mut record = json!({"phase":"started","active_round":"dispatch","rounds":[{"step":"dispatch"}],"letters":[{"step":"dispatch","name":"dispatch-1.md","in_round":true,"bytes":4,"sha256":"recorded","placed_at_unix_ns":11,"state":"placing"}]});
        let changes = reconcile_placing(
            &mut record,
            fixture.path(),
            fixture.path(),
            Uid::effective().as_raw(),
        )
        .expect("absent publication");
        assert_eq!(changes[0]["state"], "abandoned");
        assert_eq!(
            record["letters"][0]["reconciliation"],
            "file-absent-name-retired"
        );
        assert_eq!(record["letters"][0]["placed_at_unix_ns"], 11);
        assert_eq!(
            selected_name(&record, "dispatch", fixture.path())
                .expect("next number")
                .0,
            "dispatch-2.md"
        );
    }
}
