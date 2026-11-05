//! Measure credential publication in owner custody and the private run namespace.

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "exercise_cases.rs"]
pub(in crate::launch) mod cases;
#[path = "exercise_door_attribution.rs"]
pub mod door_attribution;
#[path = "exercise_door_extensions.rs"]
pub mod door_extensions;
#[path = "exercise_door_modes.rs"]
pub mod door_modes;
#[path = "exercise_door.rs"]
pub mod door_shape;
#[path = "exercise_layout.rs"]
pub(crate) mod layout;
#[path = "exercise_mounts.rs"]
pub mod mounts;
#[path = "exercise_network.rs"]
pub mod network;

/// Return the command status for one case report.
///
/// # Errors
///
/// Refuses a missing or unknown verdict as a malformed case report.
pub fn case_status(report: &Value) -> Result<i32, LaneError> {
    const PASS_STATUS: i32 = 0;
    const NONPASS_STATUS: i32 = 1;
    match report.get("verdict").and_then(Value::as_str) {
        Some("pass") => Ok(PASS_STATUS),
        Some("fail" | "unmeasured" | "unknown") => Ok(NONPASS_STATUS),
        _ => Err(LaneError::input(
            "exercise-case-record",
            "case verdict is absent or malformed",
        )),
    }
}

/// Measure the requested acceptance case on a recorded run.
///
/// # Errors
///
/// Refuses a missing reservation, case, driver line, acknowledgement or context record.
#[allow(clippy::too_many_lines)]
pub fn run_case(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    case: &str,
) -> Result<Value, LaneError> {
    if !valid_run_name(run) {
        return Err(LaneError::input("exercise-run", "run is not a plain word"));
    }
    if matches!(case, "door-shape" | "door-attribution" | "door-extensions")
        && !load_plan(owner_home, loop_name, run, (Uid::effective().as_raw(), 0))?
            .0
            .document["door"]
            .is_object()
    {
        return Err(LaneError::input(
            "door-generation",
            "registered door generation is absent for the box",
        ));
    }
    if case == "door-shape" {
        return door_shape::measure(owner_home, loop_name, run);
    }
    if case == "door-attribution" {
        return door_attribution::measure(owner_home, loop_name, run);
    }
    if case == "door-extensions" {
        return door_extensions::measure(owner_home, loop_name, run);
    }
    if case == "network" {
        return network::measure(owner_home, loop_name, run);
    }
    if matches!(
        case,
        "door-audit" | "door-allow" | "door-enforce" | "door-agent"
    ) {
        return door_modes::measure(owner_home, loop_name, run, case);
    }
    let caller = Uid::effective().as_raw();
    let (plan, settings) = if matches!(
        case,
        "harvest"
            | "run-identity"
            | "rotation"
            | "letters"
            | "context-use"
            | "reaping"
            | "home-layout"
    ) {
        crate::load_plan_for_record(owner_home, loop_name, run, (caller, 0))?
    } else {
        load_plan(owner_home, loop_name, run, (caller, 0))?
    };
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-record", "runs root is absent"))?;
    let root_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, caller, 0)?;
    let _mailbox = if matches!(case, "rotation" | "home-layout") {
        Some(checkpoint::checkpoint_locks_at(
            &root_fd, run, caller, true,
        )?)
    } else {
        None
    };
    let (record, record_identity) = checkout::read_record_bound(&root_fd, run, caller)?;
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "exercise-record",
            "run identity differs from reservation",
        ));
    }
    match case {
        "context-use" => {
            let context = super::follow::context_bound(
                owner_home,
                loop_name,
                run,
                &plan,
                root,
                &root_fd,
                &record,
                &record_identity,
            )?;
            let verdict = context_verdict(&context)?;
            Ok(
                json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":case,"field":context["source"],"window":context["window"],"reason":context["reason"],"context":context,"verdict":verdict,"changed":false}),
            )
        }
        "letters" => Err(LaneError::input(
            "exercise-case",
            "legacy letter exercise is retired; use the mail delivery and retained-step evidence",
        )),
        "home-layout" => {
            let measurement = layout_measure(
                owner_home,
                &plan,
                &settings,
                &record,
                loop_name,
                run,
                &record_identity,
                &root_fd,
            )?;
            cases::measure(
                owner_home,
                &plan,
                &settings,
                &record,
                loop_name,
                run,
                case,
                Some(&measurement),
                &root_fd,
            )
        }
        "harvest" => {
            let measurement = harvest_measure(
                owner_home,
                &settings,
                loop_name,
                run,
                &record_identity,
                &root_fd,
            )?;
            cases::measure(
                owner_home,
                &plan,
                &settings,
                &record,
                loop_name,
                run,
                case,
                Some(&measurement),
                &root_fd,
            )
        }
        "mounts" => mounts::measure(
            owner_home,
            &settings,
            loop_name,
            run,
            &record_identity,
            &root_fd,
        ),
        "run-identity" | "rotation" => cases::measure(
            owner_home, &plan, &settings, &record, loop_name, run, case, None, &root_fd,
        ),
        "resources" => super::exercise_resources::measure(
            owner_home, &plan, &settings, &record, loop_name, run,
        ),
        "reaping" => super::reaping::measure_case(&record, owner_home, loop_name, run),
        _ => Err(LaneError::input(
            "exercise-case",
            "case must be letters, reply-receipts, context-use, harvest, run-identity, home-layout, mounts, rotation, resources, reaping, network, door-shape, door-attribution, door-extensions, door-audit, door-allow, door-enforce or door-agent",
        )),
    }
}

fn harvest_measure(
    owner_home: &Path,
    settings: &Settings,
    loop_name: &str,
    run: &str,
    record_identity: &str,
    verified_runs: &std::os::fd::OwnedFd,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-harvest", "runs root is absent"))?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-harvest", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, owner)?;
    let podman = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman, owner)?;
    let mut argv = vec!["unshare".into(), exe_word];
    argv.extend(harvest_private_argv(
        loop_name,
        run,
        record_identity,
        owner_home,
    )?);
    let output = build::run_checked_with_private_launch(
        podman,
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        60,
        "exercise-harvest",
        &verified_home,
        root,
        verified_runs,
        None,
    )?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-harvest", error.to_string()))
}

/// Build the private harvest-audit form used by the public case.
///
/// # Errors
///
/// Refuses an owner home that cannot be passed as one absolute argument.
pub fn harvest_private_argv(
    loop_name: &str,
    run: &str,
    record_identity: &str,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-harvest".into(),
        loop_name.into(),
        run.into(),
        "--expect-record".into(),
        record_identity.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

/// Parse exactly the private form built by `harvest_private_argv`.
///
/// # Errors
///
/// Refuses missing or reordered fields before the private audit starts.
pub fn parse_harvest_private_argv(args: &[String]) -> Result<(&str, &str, &str, &Path), LaneError> {
    let [
        command,
        loop_name,
        run,
        record_flag,
        identity,
        home_flag,
        owner_home,
    ] = args
    else {
        return Err(LaneError::input(
            "exercise-harvest-form",
            "private form is incomplete",
        ));
    };
    if command != "_exercise-harvest"
        || record_flag != "--expect-record"
        || home_flag != "--owner-home"
        || identity.is_empty()
        || !Path::new(owner_home).is_absolute()
    {
        return Err(LaneError::input(
            "exercise-harvest-form",
            "private form is malformed",
        ));
    }
    Ok((loop_name, run, identity, Path::new(owner_home)))
}

/// Audit the preserved checkpoint in the bound private namespace.
///
/// # Errors
///
/// Refuses a missing private binding or changed run identity.
pub fn private_harvest_audit(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    expected_record: &str,
) -> Result<Value, LaneError> {
    if !home::private_is_active() || !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-harvest",
            "bound private namespace is absent",
        ));
    }
    private_harvest_audit_body(owner_home, loop_name, run, expected_record, 0)
}

pub(crate) fn private_harvest_audit_body(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    expected_record: &str,
    namespace_owner: u32,
) -> Result<Value, LaneError> {
    let (plan, settings) = crate::load_plan_for_record(
        owner_home,
        loop_name,
        run,
        (namespace_owner, namespace_owner),
    )?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-harvest", "runs root is absent"))?;
    let runs = home::pin_parent(root, namespace_owner)?;
    let (record, actual_record) = checkout::read_record_bound(&runs, run, namespace_owner)?;
    if actual_record != expected_record {
        return Err(LaneError::input(
            "exercise-harvest-record",
            "private reservation identity differs from the public read",
        ));
    }
    if record.get("loop").and_then(Value::as_str) != Some(loop_name)
        || record.get("run").and_then(Value::as_str) != Some(run)
        || record["plan"].get("home").and_then(Value::as_str)
            != Some(plan.home.to_str().unwrap_or_default())
        || record["plan"].get("driver_dir").and_then(Value::as_str)
            != Some(plan.driver_dir.to_str().unwrap_or_default())
    {
        return Err(LaneError::input(
            "exercise-harvest-record",
            "run identity differs from reservation",
        ));
    }
    cases::audit_preserved(&record, &plan, &settings, &runs, run)
}

#[allow(clippy::too_many_arguments)]
fn layout_measure(
    owner_home: &Path,
    plan: &Plan,
    settings: &Settings,
    record: &Value,
    loop_name: &str,
    run: &str,
    record_identity: &str,
    verified_runs: &std::os::fd::OwnedFd,
) -> Result<Value, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "rounds are absent"))?;
    if rounds.is_empty() || rounds.iter().any(|round| round["phase"] != "settled") {
        return Ok(json!({"state":"unmeasured","reason":"run is not settled"}));
    }
    if cases::home_descriptor(&plan.home)?.is_none() {
        return Ok(json!({"state":"unmeasured","reason":"home was collected"}));
    }
    let owner = Uid::effective().as_raw();
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "runs root is absent"))?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-home-layout", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, owner)?;
    let podman = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman, owner)?;
    let mut argv = vec!["unshare".into(), exe_word];
    argv.extend(home_layout_private_argv(
        loop_name,
        run,
        record_identity,
        owner_home,
    )?);
    let output = build::run_checked_with_private_launch(
        podman,
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        60,
        "exercise-home-layout",
        &verified_home,
        root,
        verified_runs,
        None,
    )?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-home-layout", error.to_string()))
}

/// Build the private home-layout form used by the public measurement.
///
/// # Errors
///
/// Refuses an owner home that cannot be passed as one absolute argument.
pub fn home_layout_private_argv(
    loop_name: &str,
    run: &str,
    record_identity: &str,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-home-layout".into(),
        loop_name.into(),
        run.into(),
        "--expect-record".into(),
        record_identity.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

/// Parse exactly the private form built by `home_layout_private_argv`.
///
/// # Errors
///
/// Refuses missing or reordered fields before the private measurement starts.
pub fn parse_home_layout_private_argv(
    args: &[String],
) -> Result<(&str, &str, &str, &Path), LaneError> {
    let [
        command,
        loop_name,
        run,
        record_flag,
        identity,
        home_flag,
        owner_home,
    ] = args
    else {
        return Err(LaneError::input(
            "exercise-home-layout-form",
            "private form is incomplete",
        ));
    };
    if command != "_exercise-home-layout"
        || record_flag != "--expect-record"
        || home_flag != "--owner-home"
        || identity.is_empty()
        || !Path::new(owner_home).is_absolute()
    {
        return Err(LaneError::input(
            "exercise-home-layout-form",
            "private form is malformed",
        ));
    }
    Ok((loop_name, run, identity, Path::new(owner_home)))
}

/// Measure the live layout as the worker in the bound private namespace.
///
/// # Errors
///
/// Refuses a missing private binding or changed run identity.
pub fn private_home_layout(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    expected_record: &str,
) -> Result<Value, LaneError> {
    layout::private_measure(owner_home, loop_name, run, expected_record)
}

/// Attempt one reserved write as the actual worker UID.
///
/// # Errors
///
/// Refuses a changed identity or malformed relative path.
pub fn worker_layout_canary(
    relative: &str,
    worker: u32,
    loop_uid: u32,
) -> Result<Value, LaneError> {
    layout::worker_canary(relative, worker, loop_uid)
}

fn context_verdict(context: &Value) -> Result<&'static str, LaneError> {
    match context["state"].as_str() {
        Some("unknown")
            if context["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()) =>
        {
            Ok("unknown")
        }
        Some("measured")
            if context["source"]
                .as_str()
                .is_some_and(|field| !field.is_empty())
                && context["window"].as_u64().is_some_and(|window| window > 0) =>
        {
            Ok("measured")
        }
        _ => Err(LaneError::input(
            "exercise-context",
            "context state lacks its source, window or unknown reason",
        )),
    }
}

#[cfg(test)]
mod letter_case_tests {
    use super::*;

    /// ´test:unit:context-case-verdict-distinguishes-unknown-from-measured´
    #[test]
    fn context_case_verdict_distinguishes_unknown_from_measured() {
        assert_eq!(
            context_verdict(&json!({"state":"unknown","reason":"window-unreported"}))
                .expect("unknown"),
            "unknown"
        );
        assert_eq!(
            context_verdict(
                &json!({"state":"measured","source":"token_count.last_token_usage","window":128_000})
            )
            .expect("measured"),
            "measured"
        );
        assert_eq!(
            context_verdict(
                &json!({"state":"measured","source":"token_count.last_token_usage","window":null})
            )
            .expect_err("window absent")
            .kind,
            "exercise-context"
        );
        assert_eq!(
            context_verdict(&json!({"state":"unknown","reason":null}))
                .expect_err("reason absent")
                .kind,
            "exercise-context"
        );
    }
}

fn wall() -> Result<u64, LaneError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| LaneError::operation("exercise-clock", error.to_string()))
}

fn measured_file(path: &Path, uid: u32) -> Result<(Value, Value), LaneError> {
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::input("exercise-path", "file parent is absent"))?;
    let held = home::pin_parent(parent, Uid::effective().as_raw())?;
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("exercise-path", "file name is absent"))?;
    let opened = nix::fcntl::openat2(
        &held,
        name,
        nix::fcntl::OpenHow::new()
            .flags(nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC)
            .resolve(
                nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                    | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
            ),
    )
    .map_err(|error| LaneError::input("exercise-path", format!("{}: {error}", path.display())))?;
    measured_open(fs::File::from(opened), path, parent, uid)
}

fn checked_worker_directory(
    fd: &impl std::os::fd::AsFd,
    name: &str,
    uid: u32,
    mode: u32,
) -> Result<std::os::fd::OwnedFd, LaneError> {
    let opened = nix::fcntl::openat2(
        fd,
        name,
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
    .map_err(|error| LaneError::input("exercise-path", format!("{name}: {error}")))?;
    let meta = fs::File::from(
        opened
            .try_clone()
            .map_err(|error| LaneError::input("exercise-path", error.to_string()))?,
    )
    .metadata()
    .map_err(|error| LaneError::input("exercise-path", error.to_string()))?;
    if !meta.is_dir() || meta.uid() != uid || meta.permissions().mode() & 0o7777 != mode {
        return Err(LaneError::input(
            "exercise-path",
            format!("{name} is not a mode-{mode:o} directory owned by uid {uid}"),
        ));
    }
    Ok(opened)
}

fn measured_worker_file(
    home_path: &Path,
    owner: u32,
    worker: u32,
) -> Result<(Value, Value), LaneError> {
    let parent = home_path
        .parent()
        .ok_or_else(|| LaneError::input("exercise-path", "worker home parent is absent"))?;
    let held = home::pin_parent(parent, owner)?;
    let name = home_path
        .file_name()
        .ok_or_else(|| LaneError::input("exercise-path", "worker home name is absent"))?;
    let home_name = name
        .to_str()
        .ok_or_else(|| LaneError::input("exercise-path", "worker home name is not UTF-8"))?;
    let home = checked_worker_directory(&held, home_name, owner, 0o750)?;
    let codex = checked_worker_directory(&home, ".codex", worker, 0o700)?;
    let opened = nix::fcntl::openat2(
        &codex,
        "auth.json",
        nix::fcntl::OpenHow::new()
            .flags(nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC)
            .resolve(
                nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                    | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
            ),
    )
    .map_err(|error| LaneError::input("exercise-path", format!("worker credential: {error}")))?;
    let path = home_path.join(".codex/auth.json");
    measured_open(
        fs::File::from(opened),
        &path,
        &home_path.join(".codex"),
        worker,
    )
}

fn measured_open(
    file: fs::File,
    path: &Path,
    parent: &Path,
    uid: u32,
) -> Result<(Value, Value), LaneError> {
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("exercise-path", error.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > 65_536
    {
        return Err(LaneError::input(
            "exercise-path",
            format!(
                "{} is not a bounded mode-0600 file owned by uid {uid}",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("exercise-path", error.to_string()))?;
    let digest = build::sha256_bytes(&bytes, parent)?;
    let document = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("exercise-path", error.to_string()))?;
    Ok((
        json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":600,"digest":digest,"modified_wall_unix_seconds":metadata.mtime()}),
        document,
    ))
}

fn compared(custody: &Value, worker: &Value, projection_digest: &str, token_only: bool) -> Value {
    json!({"same_device":custody["device"] == worker["device"],"same_inode":custody["device"] == worker["device"] && custody["inode"] == worker["inode"],"worker_matches_projection":worker["digest"] == projection_digest,"worker_token_only":token_only})
}

fn changes(previous: Option<&Value>, current: &Value) -> Value {
    let Some(previous) = previous else {
        return json!({"state":"no-prior-sample"});
    };
    let old = &previous["measurement"];
    let source_changed = old["custody"]["digest"].is_string()
        && old["custody"]["digest"] != current["custody"]["digest"];
    let runs = current["runs"].as_array().cloned().unwrap_or_default();
    let mut publications = Vec::new();
    for run in &runs {
        let name = &run["run"];
        let prior = old["runs"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["run"] == *name));
        publications.push(json!({"run":name,"changed":prior.is_some_and(|item| item["worker"]["digest"] != run["worker"]["digest"]),"path":run["worker"]["path"]}));
    }
    let peer_refresh_visible = source_changed
        && runs.len() >= 2
        && runs
            .iter()
            .all(|run| run["comparison"]["worker_matches_projection"] == true)
        && publications.iter().all(|item| item["changed"] == true);
    json!({"state":"compared","source_changed":source_changed,"shared_custody_path":current["custody"]["path"],"per_run_publications":publications,"peer_refresh_visible":peer_refresh_visible})
}

fn projection(source: &Value) -> Result<Vec<u8>, LaneError> {
    let tokens = &source["tokens"];
    for key in ["id_token", "access_token", "refresh_token", "account_id"] {
        if tokens[key].as_str().is_none_or(str::is_empty) {
            return Err(LaneError::input(
                "exercise-sign-in",
                format!("source lacks {key}"),
            ));
        }
    }
    let mut bytes = json!({"auth_mode":"chatgptAuthTokens","OPENAI_API_KEY":null,"tokens":{"id_token":tokens["id_token"],"access_token":tokens["access_token"],"refresh_token":"","account_id":tokens["account_id"]},"last_refresh":source["last_refresh"]}).to_string().into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

fn candidates(root: &Path, loop_name: &str) -> Result<Vec<Value>, LaneError> {
    let mut rows = Vec::new();
    for entry in
        fs::read_dir(root).map_err(|error| LaneError::input("exercise-root", error.to_string()))?
    {
        let entry = entry.map_err(|error| LaneError::input("exercise-root", error.to_string()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(run) = name
            .strip_prefix(".reservation-")
            .and_then(|part| part.strip_suffix(".json"))
        else {
            continue;
        };
        if !valid_run_name(run) {
            return Err(LaneError::input(
                "exercise-record",
                format!("invalid reservation name {name}"),
            ));
        }
        let record = read_reservation(&entry.path())?
            .ok_or_else(|| LaneError::input("exercise-record", format!("{name} vanished")))?;
        if record["loop"] != loop_name || record["run"] != run || record["phase"] != "started" {
            continue;
        }
        let (Some(pid), Some(start)) = (
            record["helper_pid"].as_u64(),
            record["helper_start"].as_u64(),
        ) else {
            continue;
        };
        let Ok(pid) = u32::try_from(pid) else {
            continue;
        };
        if crate::container_helper::process_presence(pid, start)
            != crate::container_helper::ProcessPresence::Present
        {
            continue;
        }
        rows.push(record);
    }
    rows.sort_by(|a, b| a["run"].as_str().cmp(&b["run"].as_str()));
    Ok(rows)
}

/// Measure only protected records for a dry run and publish a bounded evidence snapshot otherwise.
///
/// # Errors
///
/// Refuses missing live runs, unsafe records or private measurement failure.
pub fn run(owner_home: &Path, loop_name: &str, dry_run: bool) -> Result<Value, LaneError> {
    run_with(owner_home, loop_name, dry_run, || {
        measure_private(owner_home, loop_name)
    })
}

fn run_with(
    owner_home: &Path,
    loop_name: &str,
    dry_run: bool,
    measure: impl FnOnce() -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let begun = Instant::now();
    let started_wall = wall()?;
    let config = owner_home.join(".config/loops").join(loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let settings = Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-grant", "runs_root is absent"))?;
    let owner = Uid::effective().as_raw();
    let _runs = lock_runs_root(root, false, owner)?;
    let live = candidates(root, loop_name)?;
    let names = live
        .iter()
        .map(|record| record["run"].clone())
        .collect::<Vec<_>>();
    let scan_wall = wall()?;
    if dry_run {
        return Ok(
            json!({"schema":1,"command":"exercise","loop":loop_name,"dry_run":true,"live_runs":names,"refresh_trigger":"access JWT within ten minutes of expiry","forced_refresh_available":false,"checks":["owner custody and worker token file identities","protected helper publication evidence","simultaneous live helpers","token-only projection"],"walls":{"started":started_wall,"scan":scan_wall},"changed":false,"wall_seconds":begun.elapsed().as_secs_f64()}),
        );
    }
    if live.is_empty() {
        return Err(LaneError::input(
            "exercise-runs",
            "no live protected run is available for measurement",
        ));
    }
    let sample_path = config.join(".exercise-sample.lock");
    let sample_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&sample_path)
        .map_err(|error| LaneError::input("exercise-lock", error.to_string()))?;
    let sample_meta = sample_file
        .metadata()
        .map_err(|error| LaneError::input("exercise-lock", error.to_string()))?;
    if !sample_meta.is_file()
        || sample_meta.uid() != owner
        || sample_meta.permissions().mode() & 0o7777 != 0o600
    {
        return Err(LaneError::input(
            "exercise-lock",
            "sample lock is not owner mode 0600",
        ));
    }
    let _sample = Flock::lock(sample_file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| LaneError::input("exercise-busy", error.to_string()))?;
    let measurement = measure()?;
    let private_wall = wall()?;
    let path = config.join("exercise-latest.json");
    let prior = if path.exists() {
        Some(measured_file(&path, owner)?.1)
    } else {
        None
    };
    let comparison = changes(prior.as_ref(), &measurement);
    let report = json!({"schema":1,"command":"exercise","loop":loop_name,"dry_run":false,"live_runs":names,"measurement":measurement,"change_from_previous":comparison,"walls":{"started":started_wall,"scan":scan_wall,"private":private_wall,"journal":wall()?},"reload":"requires a worker rejection and in-box readback","changed":true,"wall_seconds":begun.elapsed().as_secs_f64()});
    build::publish(
        &path,
        &serde_json::to_vec(&report)
            .map_err(|error| LaneError::operation("exercise-record", error.to_string()))?,
    )?;
    fs::File::open(&config)
        .and_then(|file| file.sync_all())
        .map_err(|error| LaneError::operation("exercise-record", error.to_string()))?;
    Ok(report)
}

fn measure_private(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let config = owner_home.join(".config/loops").join(loop_name);
    let settings = Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-grant", "runs_root is absent"))?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let verified_runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-program", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, owner)?;
    let podman = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman, owner)?;
    let argv = vec![
        "unshare".into(),
        exe_word,
        "_exercise-measure".into(),
        loop_name.into(),
        "all".into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ];
    let output = build::run_checked_with_private_launch(
        podman,
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        60,
        "exercise-private",
        &verified_home,
        root,
        &verified_runs,
        None,
    )?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-private", error.to_string()))
}

/// Read token identities inside the bound private namespace without returning token bytes.
///
/// # Errors
///
/// Refuses a missing private binding or unsafe credential file.
pub fn private_measure(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    if !home::private_is_active() {
        return Err(LaneError::input(
            "exercise-private",
            "bound private home is absent",
        ));
    }
    let config = owner_home.join(".config/loops").join(loop_name);
    let settings = Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-grant", "runs_root is absent"))?;
    let source_path = config.join("lanes/codex/auth.json");
    let owner = Uid::effective().as_raw();
    let (custody, source) = measured_file(&source_path, owner)?;
    let expected = build::sha256_bytes(&projection(&source)?, owner_home)?;
    let access = source["tokens"]["access_token"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-sign-in", "access token is absent"))?;
    let refresh_due = crate::credential::refresh_due_for_access(access, wall()?)?;
    let mut runs = Vec::new();
    for record in candidates(root, loop_name)? {
        let run = record["run"].as_str().unwrap_or_default();
        let uid = record["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| LaneError::input("exercise-record", "worker uid is absent"))?;
        let home_path = Path::new(
            record["plan"]["home"]
                .as_str()
                .ok_or_else(|| LaneError::input("exercise-record", "worker home is absent"))?,
        );
        if !home_path.starts_with(owner_home) || source_path.starts_with(home_path) {
            return Err(LaneError::input(
                "exercise-path",
                "custody source enters a collectable home",
            ));
        }
        let (worker, document) = measured_worker_file(home_path, owner, uid)?;
        let token_only = document["auth_mode"] == "chatgptAuthTokens"
            && document["tokens"]["refresh_token"] == "";
        let comparison = compared(&custody, &worker, &expected, token_only);
        if comparison["same_inode"] == true
            || comparison["worker_matches_projection"] != true
            || !token_only
        {
            return Err(LaneError::input(
                "exercise-credential",
                format!("run {run} has an unexpected credential identity"),
            ));
        }
        let evidence_path = root.join(format!(".launch-{run}/credential-refresh.json"));
        let evidence = if evidence_path.exists() {
            let (identity, document) = measured_file(&evidence_path, owner)?;
            json!({"identity":identity,"state":document["state"],"host":document["host"]})
        } else {
            json!({"state":"not-published"})
        };
        runs.push(
            json!({"run":run,"worker":worker,"comparison":comparison,"helper_evidence":evidence}),
        );
    }
    Ok(
        json!({"schema":1,"custody":custody,"projection_digest":expected,"refresh_due":refresh_due,"overlap":runs.len() >= 2,"runs":runs,"checked_wall_unix_seconds":wall()?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RestoreDriver(std::path::PathBuf);

    impl Drop for RestoreDriver {
        fn drop(&mut self) {
            drop(fs::set_permissions(
                &self.0,
                fs::Permissions::from_mode(0o700),
            ));
        }
    }

    /// ´test:unit:exercise-compares-distinct-custody-and-worker-identities´
    #[test]
    fn exercise_compares_distinct_custody_and_worker_identities() {
        let custody = json!({"device":1,"inode":10,"uid":41001,"digest":"source"});
        let worker = json!({"device":1,"inode":11,"uid":3000,"digest":"projection"});
        let comparison = compared(&custody, &worker, "projection", true);
        assert_eq!(comparison["same_device"], true);
        assert_eq!(comparison["same_inode"], false);
        assert_eq!(comparison["worker_matches_projection"], true);
        assert_eq!(comparison["worker_token_only"], true);
        let previous = json!({"measurement":{"custody":{"digest":"old"},"runs":[{"run":"R","worker":{"digest":"old"}},{"run":"S","worker":{"digest":"old"}}]}});
        let current = json!({"custody":{"digest":"source","path":"~/.config/loops/alpha/lanes/codex/auth.json"},"runs":[{"run":"R","worker":{"digest":"projection","path":"~/runs/R/.codex/auth.json"},"comparison":{"worker_matches_projection":true}},{"run":"S","worker":{"digest":"projection","path":"~/runs/S/.codex/auth.json"},"comparison":{"worker_matches_projection":true}}]});
        assert_eq!(
            changes(Some(&previous), &current)["peer_refresh_visible"],
            true
        );
    }

    /// ´test:unit:exercise-preview-reads-protected-record-with-unreadable-driver´
    #[test]
    fn exercise_preview_reads_protected_record_with_unreadable_driver() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let owner_home = fixture.path();
        fs::set_permissions(owner_home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = owner_home.join(".config/loops/alpha");
        fs::create_dir_all(&config).expect("config");
        for dir in [
            owner_home.join(".config"),
            owner_home.join(".config/loops"),
            config.clone(),
        ] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).expect("config mode");
        }
        let root = owner_home.join("runs");
        fs::create_dir(&root).expect("runs root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let registry = owner_home.join(".config/loops/registry.toml");
        fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", root.display())).expect("registry");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
        let settings = config.join("workers.toml");
        fs::write(&settings, format!("runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n", root.display(), "a".repeat(64), owner_home.join("template").display(), owner_home.join("sockets").display())).expect("settings");
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
        assert_ne!(Uid::effective().as_raw(), 41001);
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o000)).expect("driver mode");
        let _restore = RestoreDriver(driver);
        let pid = std::process::id();
        let start = crate::container_helper::process_start(pid).expect("helper tick");
        publish_reservation(&reservation_path(&root, "R"), &json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"helper_pid":pid,"helper_start":start,"plan":{"home":owner_home.join("worker")}})).expect("reservation");
        let report = run(owner_home, "alpha", true).expect("preview");
        assert_eq!(report["live_runs"], json!(["R"]));
        assert_eq!(report["forced_refresh_available"], false);
        assert!(!config.join("exercise-latest.json").exists());
        let _launch =
            crate::install::lock_loop_config(&config, true).expect("live launch admission");
        let sampled = run_with(owner_home, "alpha", false, || {
            Ok(json!({"schema":1,"custody":{"digest":"fixture"},"runs":[]}))
        })
        .expect("changing sample shares launch admission");
        assert_eq!(sampled["changed"], true);
        assert!(config.join("exercise-latest.json").exists());
    }
}
