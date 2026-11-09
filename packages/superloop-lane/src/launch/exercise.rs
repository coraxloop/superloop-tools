//! Measure credential publication in owner custody and the private run namespace.

use super::*;
use crate::settings::BoxBackend;
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

fn measured_evidence(root: &Path, run: &str, owner: u32) -> Result<Value, LaneError> {
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
    let root_fd = home::pin_parent(root, owner)?;
    let resolve = ResolveFlag::RESOLVE_BENEATH
        | ResolveFlag::RESOLVE_NO_SYMLINKS
        | ResolveFlag::RESOLVE_NO_MAGICLINKS;
    let name = format!(".launch-{run}");
    let directory = match openat2(
        &root_fd,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(resolve),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(json!({"state":"not-published"})),
        Err(error) => {
            return Err(LaneError::input(
                "exercise-path",
                format!("{name}: {error}"),
            ));
        }
    };
    let stat = nix::sys::stat::fstat(&directory)
        .map_err(|error| LaneError::input("exercise-path", error.to_string()))?;
    if stat.st_uid != owner || stat.st_mode & 0o022 != 0 {
        return Err(LaneError::input(
            "exercise-path",
            "helper evidence directory is not owner-controlled",
        ));
    }
    let file = match openat2(
        &directory,
        "credential-refresh.json",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(resolve),
    ) {
        Ok(fd) => fs::File::from(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(json!({"state":"not-published"})),
        Err(error) => {
            return Err(LaneError::input(
                "exercise-path",
                format!("helper evidence: {error}"),
            ));
        }
    };
    let path = root.join(name).join("credential-refresh.json");
    let (identity, document) = measured_open(file, &path, root, owner)?;
    Ok(json!({"identity":identity,"state":document["state"],"host":document["host"]}))
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
    backend: BoxBackend,
    expected: Option<&Value>,
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
    let (state, filename) = match backend {
        BoxBackend::Codex => (".codex", "auth.json"),
        BoxBackend::Claude => (".claude", ".credentials.json"),
    };
    let vendor = checked_worker_directory(&home, state, worker, 0o700)?;
    let opened = nix::fcntl::openat2(
        &vendor,
        filename,
        nix::fcntl::OpenHow::new()
            .flags(nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC)
            .resolve(
                nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                    | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
            ),
    )
    .map_err(|error| LaneError::input("exercise-path", format!("worker credential: {error}")))?;
    let path = home_path.join(state).join(filename);
    measured_open_with(
        fs::File::from(opened),
        &path,
        &home_path.join(state),
        worker,
        backend == BoxBackend::Codex,
        expected,
    )
}

fn measured_open(
    file: fs::File,
    path: &Path,
    parent: &Path,
    uid: u32,
) -> Result<(Value, Value), LaneError> {
    measured_open_with(file, path, parent, uid, true, None)
}

fn measured_open_with(
    file: fs::File,
    path: &Path,
    parent: &Path,
    uid: u32,
    include_digest: bool,
    expected: Option<&Value>,
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
    let digest = include_digest
        .then(|| build::sha256_bytes(&bytes, parent))
        .transpose()?;
    let document = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("exercise-path", error.to_string()))?;
    let mut identity = json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":600,"modified_wall_unix_seconds":metadata.mtime()});
    if let Some(digest) = digest {
        identity["digest"] = digest.into();
    } else {
        identity["modified_nanoseconds"] = metadata.mtime_nsec().into();
        identity["projection_encoding_matches"] = expected
            .is_some_and(|projection| {
                let mut canonical = projection.to_string().into_bytes();
                canonical.push(b'\n');
                bytes == canonical
            })
            .into();
    }
    Ok((identity, document))
}

fn compared(custody: &Value, worker: &Value, projection_digest: &str, token_only: bool) -> Value {
    json!({"same_device":custody["device"] == worker["device"],"same_inode":custody["device"] == worker["device"] && custody["inode"] == worker["inode"],"worker_matches_projection":worker["digest"] == projection_digest,"worker_token_only":token_only})
}

fn changes(previous: Option<&Value>, current: &Value) -> Value {
    if current["backend"] == "claude" {
        return json!({"state":"unmeasured","reason":"metadata and projection equality do not prove token rotation or worker reload"});
    }
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

/// Parse the credential exercise selector independently of case exercises.
///
/// # Errors
/// Refuses repeated, incomplete or unknown options and vendor selectors.
pub fn parse_options(args: &[String]) -> Result<(BoxBackend, bool), LaneError> {
    let mut backend = None;
    let mut dry_run = false;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--dry-run" if !dry_run => dry_run = true,
            "--backend" if backend.is_none() => {
                let name = words.next().ok_or_else(|| {
                    LaneError::input("exercise-usage", "--backend needs codex or claude")
                })?;
                backend = Some(BoxBackend::parse(name)?);
            }
            _ => {
                return Err(LaneError::input(
                    "exercise-usage",
                    "exercise LOOP [--backend {codex|claude}] [--dry-run]",
                ));
            }
        }
    }
    Ok((backend.unwrap_or(BoxBackend::Codex), dry_run))
}

fn selected_record(record: &Value, backend: BoxBackend) -> Result<bool, LaneError> {
    Ok(BoxBackend::from_plan(&record["plan"])? == backend)
}

fn candidates(root: &Path, loop_name: &str, backend: BoxBackend) -> Result<Vec<Value>, LaneError> {
    let mut rows = Vec::new();
    for (run, record) in super::reservation_census::records(root)? {
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
        if selected_record(&record, backend)? {
            rows.push(record);
        }
    }
    rows.sort_by(|a, b| a["run"].as_str().cmp(&b["run"].as_str()));
    Ok(rows)
}

/// Measure only protected records for a dry run and publish a bounded evidence snapshot otherwise.
///
/// # Errors
///
/// Refuses missing live runs, unsafe records or private measurement failure.
pub fn run(
    owner_home: &Path,
    loop_name: &str,
    dry_run: bool,
    backend: BoxBackend,
) -> Result<Value, LaneError> {
    run_with(owner_home, loop_name, dry_run, backend, || {
        measure_private(owner_home, loop_name, backend)
    })
}

fn run_with(
    owner_home: &Path,
    loop_name: &str,
    dry_run: bool,
    backend: BoxBackend,
    measure: impl FnOnce() -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    backend.require_runtime()?;
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
    let live = candidates(root, loop_name, backend)?;
    let names = live
        .iter()
        .map(|record| record["run"].clone())
        .collect::<Vec<_>>();
    let scan_wall = wall()?;
    let refresh_trigger = match backend {
        BoxBackend::Codex => "access JWT within ten minutes of expiry",
        BoxBackend::Claude => "recorded expiresAt within ten minutes of expiry",
    };
    if dry_run {
        return Ok(
            json!({"schema":1,"command":"exercise","backend":backend.name(),"loop":loop_name,"dry_run":true,"live_runs":names,"refresh_trigger":refresh_trigger,"forced_refresh_available":false,"checks":["owner custody and worker token file identities","protected helper publication evidence","simultaneous live helpers","token-only projection"],"walls":{"started":started_wall,"scan":scan_wall},"changed":false,"wall_seconds":begun.elapsed().as_secs_f64()}),
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
    let report = json!({"schema":1,"command":"exercise","backend":backend.name(),"loop":loop_name,"dry_run":false,"live_runs":names,"measurement":measurement,"change_from_previous":comparison,"walls":{"started":started_wall,"scan":scan_wall,"private":private_wall,"journal":wall()?},"reload":"requires a worker rejection and in-box readback","changed":true,"wall_seconds":begun.elapsed().as_secs_f64()});
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

fn private_measure_words(
    owner_home: &Path,
    loop_name: &str,
    backend: BoxBackend,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-measure".into(),
        loop_name.into(),
        "all".into(),
        "--backend".into(),
        backend.name().into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

/// Receive the explicit backend of a private credential exercise.
///
/// # Errors
/// Refuses incomplete, reordered or repeated selectors and unknown vendors.
pub fn parse_private_measure(args: &[String]) -> Result<(&str, &Path, BoxBackend), LaneError> {
    let [
        command,
        loop_name,
        run,
        selector,
        backend,
        option,
        owner_home,
    ] = args
    else {
        return Err(LaneError::input(
            "exercise-private",
            "private exercise form is incomplete",
        ));
    };
    if command != "_exercise-measure"
        || run != "all"
        || selector != "--backend"
        || option != "--owner-home"
    {
        return Err(LaneError::input(
            "exercise-private",
            "private exercise needs all, --backend and --owner-home",
        ));
    }
    Ok((
        loop_name,
        Path::new(owner_home),
        BoxBackend::parse(backend)?,
    ))
}

fn measure_private(
    owner_home: &Path,
    loop_name: &str,
    backend: BoxBackend,
) -> Result<Value, LaneError> {
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
    let mut argv = vec!["unshare".into(), exe_word];
    argv.extend(private_measure_words(owner_home, loop_name, backend)?);
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
pub fn private_measure(
    owner_home: &Path,
    loop_name: &str,
    backend: BoxBackend,
) -> Result<Value, LaneError> {
    backend.require_runtime()?;
    if !home::private_is_active() {
        return Err(LaneError::input(
            "exercise-private",
            "bound private home is absent",
        ));
    }
    let config = owner_home.join(".config/loops").join(loop_name);
    let settings = crate::read_worker_settings(owner_home, loop_name)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-grant", "runs_root is absent"))?;
    if backend == BoxBackend::Claude {
        return measure_claude(owner_home, loop_name, root, wall()?);
    }
    let source_path = config.join("lanes/codex/auth.json");
    let owner = Uid::effective().as_raw();
    let configuration = crate::runtime_entry::plan_configuration(owner_home)?.ok_or_else(|| {
        LaneError::input(
            "exercise-anchor",
            "anchor-missing: operation=exercise-measure purpose=configuration",
        )
    })?;
    let source_file =
        configuration.open_private_file(&Path::new(loop_name).join("lanes/codex/auth.json"))?;
    let (custody, source) = measured_open(source_file, &source_path, owner_home, owner)?;
    let expected = build::sha256_bytes(&projection(&source)?, owner_home)?;
    let access = source["tokens"]["access_token"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-sign-in", "access token is absent"))?;
    let refresh_due = crate::credential::refresh_due_for_access(access, wall()?)?;
    let mut runs = Vec::new();
    for record in candidates(root, loop_name, backend)? {
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
        let (worker, document) =
            measured_worker_file(home_path, owner, uid, BoxBackend::Codex, None)?;
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
        let evidence = measured_evidence(root, run, owner)?;
        runs.push(
            json!({"run":run,"worker":worker,"comparison":comparison,"helper_evidence":evidence}),
        );
    }
    Ok(
        json!({"schema":1,"custody":custody,"projection_digest":expected,"refresh_due":refresh_due,"overlap":runs.len() >= 2,"runs":runs,"checked_wall_unix_seconds":wall()?}),
    )
}

fn claude_comparison(
    custody: &Value,
    worker: &Value,
    expected: &Value,
    document: &Value,
) -> Result<Value, LaneError> {
    let same_inode = custody["device"] == worker["device"] && custody["inode"] == worker["inode"];
    if same_inode || document != expected || worker["projection_encoding_matches"] != true {
        return Err(LaneError::input(
            "exercise-credential",
            "Claude worker is not a separate token-only projection",
        ));
    }
    Ok(
        json!({"same_device":custody["device"] == worker["device"],"same_inode":false,
        "worker_matches_projection":true,"worker_token_only":true}),
    )
}

fn claude_evidence(document: &Value) -> Result<Value, LaneError> {
    if document["schema"] != 2
        || document["backend"] != "claude"
        || document.get("host").is_some()
        || document["provider"]
            != json!({"kind":"owner-program","program":"/usr/bin/claude",
            "required_sha256":crate::credential::CLAUDE_SCHEMA_PROGRAM_SHA256})
    {
        return Err(LaneError::input(
            "exercise-evidence",
            "Claude helper evidence has a foreign provider",
        ));
    }
    Ok(
        json!({"schema":2,"backend":"claude","state":document["state"],"provider":document["provider"]}),
    )
}

fn measure_claude(
    owner_home: &Path,
    loop_name: &str,
    root: &Path,
    now: u64,
) -> Result<Value, LaneError> {
    let configuration = crate::runtime_entry::plan_configuration(owner_home)?.ok_or_else(|| {
        LaneError::input(
            "exercise-anchor",
            "anchor-missing: operation=exercise-measure purpose=configuration",
        )
    })?;
    let directory = configuration.open_private_directory(&Path::new(loop_name).join("claude"))?;
    let sign_in = crate::credential::claude_sign_in_dir(owner_home, loop_name);
    let owner = Uid::effective().as_raw();
    let held = home::pin_parent(root, owner)?;
    crate::credential::with_claude_exercise_snapshot(
        &directory,
        &sign_in,
        now,
        |custody, expected, refresh_due| {
            let mut runs = Vec::new();
            for record in candidates(root, loop_name, BoxBackend::Claude)? {
                let run = record["run"].as_str().unwrap_or_default();
                let uid = record["worker_uid"]
                    .as_u64()
                    .and_then(|uid| u32::try_from(uid).ok())
                    .ok_or_else(|| LaneError::input("exercise-record", "worker uid is absent"))?;
                let home_path =
                    Path::new(record["plan"]["home"].as_str().ok_or_else(|| {
                        LaneError::input("exercise-record", "worker home is absent")
                    })?);
                let source_path = Path::new(custody["path"].as_str().unwrap_or_default());
                if !home_path.starts_with(owner_home) || source_path.starts_with(home_path) {
                    return Err(LaneError::input(
                        "exercise-path",
                        "custody source enters a collectable home",
                    ));
                }
                let (worker, document) = measured_worker_file(
                    home_path,
                    owner,
                    uid,
                    BoxBackend::Claude,
                    Some(&expected),
                )?;
                let comparison = claude_comparison(&custody, &worker, &expected, &document)?;
                let evidence = match crate::credential::read_evidence(&held, run, owner)? {
                    Some(crate::credential::EvidenceObservation::Current(document)) => {
                        claude_evidence(&document)?
                    }
                    Some(crate::credential::EvidenceObservation::Historical(_)) => {
                        return Err(LaneError::input(
                            "exercise-evidence",
                            "Claude helper evidence is historical",
                        ));
                    }
                    None => json!({"state":"not-published"}),
                };
                runs.push(json!({"run":run,"worker":worker,"comparison":comparison,"helper_evidence":evidence}));
            }
            Ok(
                json!({"schema":2,"backend":"claude","custody":custody,"refresh_due":refresh_due,
            "overlap":runs.len() >= 2,"runs":runs,"checked_wall_unix_seconds":now}),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics if evidence lookup observes a replacement runs directory after binding.
    /// ´test:unit:exercise-evidence-stays-beneath-received-root´
    #[test]
    fn exercise_evidence_stays_beneath_received_root() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().expect("fixture");
        let home = temp.path().join("home");
        let root = temp.path().join("runs");
        let held = temp.path().join("held");
        for path in [&home, &root, &root.join(".launch-R")] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let file = root.join(".launch-R/credential-refresh.json");
        fs::write(&file, r#"{"state":"published","host":"fixture.invalid"}"#).expect("evidence");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("file mode");
        let owner = Uid::effective().as_raw();
        let _guard = home::activate_private_launch(
            &home,
            &fs::File::open(&home).expect("home"),
            &root,
            &fs::File::open(&root).expect("runs"),
            None,
            owner,
        )
        .expect("received roots");
        fs::rename(&root, &held).expect("retain root");
        fs::create_dir(&root).expect("replacement");
        assert_eq!(
            measured_evidence(&root, "R", owner).expect("held evidence")["state"],
            "published"
        );
        let file = held.join(".launch-R/credential-refresh.json");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).expect("widen file");
        assert_eq!(
            measured_evidence(&root, "R", owner)
                .expect_err("unsafe file")
                .kind,
            "exercise-path"
        );
        fs::remove_file(&file).expect("remove evidence");
        assert_eq!(
            measured_evidence(&root, "R", owner).expect("absent evidence")["state"],
            "not-published"
        );
        symlink("/dev/null", &file).expect("linked evidence");
        assert_eq!(
            measured_evidence(&root, "R", owner)
                .expect_err("linked file")
                .kind,
            "exercise-path"
        );
        fs::remove_file(&file).expect("remove link");
        fs::set_permissions(held.join(".launch-R"), fs::Permissions::from_mode(0o770))
            .expect("widen parent");
        assert_eq!(
            measured_evidence(&root, "R", owner)
                .expect_err("unsafe parent")
                .kind,
            "exercise-path"
        );
    }

    /// ´test:unit:claude-exercise-refuses-worker-authority-and-foreign-evidence´
    #[test]
    fn claude_exercise_refuses_worker_authority_and_foreign_evidence() {
        let custody = json!({"device":1,"inode":2});
        let worker = json!({"device":1,"inode":3,"projection_encoding_matches":true});
        let expected = json!({"claudeAiOauth":{"accessToken":"synthetic"}});
        let result =
            claude_comparison(&custody, &worker, &expected, &expected).expect("separate worker");
        assert_eq!(result["worker_token_only"], true);
        for field in ["refreshToken", "refreshTokenExpiresAt"] {
            let mut foreign = expected.clone();
            foreign["claudeAiOauth"][field] = "synthetic-owner-authority".into();
            let error =
                claude_comparison(&custody, &worker, &expected, &foreign).expect_err("owner field");
            assert_eq!(error.kind, "exercise-credential");
            assert!(!error.detail.contains("synthetic"));
        }
        let mut plugin = expected.clone();
        plugin["mcpOAuth"] = json!({});
        assert!(claude_comparison(&custody, &worker, &expected, &plugin).is_err());
        assert!(claude_comparison(&custody, &custody, &expected, &expected).is_err());
        let evidence = json!({"schema":2,"backend":"claude","state":"published","provider":{
            "kind":"owner-program","program":"/usr/bin/claude",
            "required_sha256":crate::credential::CLAUDE_SCHEMA_PROGRAM_SHA256}});
        assert_eq!(claude_evidence(&evidence).expect("provider"), evidence);
        for field in ["schema", "backend", "provider", "host"] {
            let mut foreign = evidence.clone();
            foreign[field] = "foreign".into();
            assert_eq!(
                claude_evidence(&foreign)
                    .expect_err("foreign provider")
                    .kind,
                "exercise-evidence"
            );
        }
        assert_eq!(
            changes(None, &json!({"backend":"claude"}))["state"],
            "unmeasured"
        );
        let absent = Path::new("/synthetic-absent");
        assert_eq!(
            measure_claude(absent, "alpha", absent, 0)
                .expect_err("configuration custody")
                .kind,
            "exercise-anchor"
        );
    }

    /// ´test:unit:claude-exercise-file-metadata-excludes-credential-digests´
    #[test]
    fn claude_exercise_file_metadata_excludes_credential_digests() {
        let fixture = tempfile::NamedTempFile::new().expect("fixture");
        let document = json!({"claudeAiOauth":{"accessToken":"A".repeat(108)}});
        fs::write(fixture.path(), document.to_string()).expect("synthetic worker");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600)).expect("mode");
        let (identity, read) = measured_open_with(
            fixture.reopen().expect("open"),
            fixture.path(),
            fixture.path().parent().expect("parent"),
            Uid::effective().as_raw(),
            false,
            Some(&document),
        )
        .expect("metadata");
        assert_eq!(read, document);
        assert!(identity.get("digest").is_none());
        assert!(identity["modified_nanoseconds"].is_i64());
        assert!(!identity.to_string().contains(&"A".repeat(108)));
    }

    /// ´test:unit:claude-exercise-worker-leaf-uses-selected-directory´
    #[test]
    fn claude_exercise_worker_leaf_uses_selected_directory() {
        let root = tempfile::tempdir().expect("fixture");
        let home = root.path().join("worker");
        fs::create_dir(&home).expect("worker home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o750)).expect("home mode");
        let state = home.join(".claude");
        fs::create_dir(&state).expect("Claude state");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state mode");
        let path = state.join(".credentials.json");
        let document = json!({"claudeAiOauth":{"accessToken":"A".repeat(108)}});
        fs::write(&path, format!("{document}\n")).expect("synthetic credential");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("file mode");
        let uid = Uid::effective().as_raw();
        let (identity, read) =
            measured_worker_file(&home, uid, uid, BoxBackend::Claude, Some(&document))
                .expect("selected leaf");
        assert_eq!(read, document);
        assert_eq!(identity["path"], path.to_string_lossy().as_ref());
        assert_eq!(identity["projection_encoding_matches"], true);
        assert!(identity.get("digest").is_none());
        fs::rename(&path, state.join("foreign")).expect("rename");
        std::os::unix::fs::symlink("foreign", &path).expect("symlink");
        assert_eq!(
            measured_worker_file(&home, uid, uid, BoxBackend::Claude, Some(&document))
                .expect_err("linked leaf")
                .kind,
            "exercise-path"
        );
    }

    /// ´test:unit:claude-exercise-refuses-shadowed-token-encoding´
    #[test]
    fn claude_exercise_refuses_shadowed_token_encoding() {
        let fixture = tempfile::NamedTempFile::new().expect("fixture");
        let expected = json!({"claudeAiOauth":{"accessToken":"A".repeat(108)}});
        let bytes = format!(
            "{{\"claudeAiOauth\":{{\"accessToken\":\"{}\",\"accessToken\":\"{}\"}}}}\n",
            "R".repeat(108),
            "A".repeat(108)
        );
        fs::write(fixture.path(), bytes).expect("synthetic duplicate member");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600)).expect("mode");
        let (worker, document) = measured_open_with(
            fixture.reopen().expect("open"),
            fixture.path(),
            fixture.path().parent().expect("parent"),
            Uid::effective().as_raw(),
            false,
            Some(&expected),
        )
        .expect("bounded file");
        assert_eq!(
            document, expected,
            "JSON value equality hides the first member"
        );
        assert_eq!(worker["projection_encoding_matches"], false);
        let custody =
            json!({"device":worker["device"],"inode":worker["inode"].as_u64().expect("inode")+1});
        let error = claude_comparison(&custody, &worker, &expected, &document)
            .expect_err("shadowed authority");
        assert_eq!(error.kind, "exercise-credential");
        assert!(!error.detail.contains(&"R".repeat(108)));
        assert!(worker.get("digest").is_none());
    }

    /// ´test:unit:credential-exercise-selects-only-protected-backend´
    #[test]
    fn credential_exercise_selects_only_protected_backend() {
        let words = |items: &[&str]| {
            items
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(parse_options(&[]).unwrap(), (BoxBackend::Codex, false));
        for backend in [BoxBackend::Codex, BoxBackend::Claude] {
            assert_eq!(
                parse_options(&words(&["--dry-run", "--backend", backend.name()])).unwrap(),
                (backend, true)
            );
            for saved in [BoxBackend::Codex, BoxBackend::Claude] {
                assert_eq!(
                    selected_record(&json!({"plan":{"backend":saved.name()}}), backend).unwrap(),
                    saved == backend
                );
            }
        }
        for args in [
            vec!["--backend"],
            vec!["--dry-run", "--dry-run"],
            vec!["--backend", "codex", "--backend", "claude"],
        ] {
            assert_eq!(
                parse_options(&words(&args)).unwrap_err().kind,
                "exercise-usage"
            );
        }
        assert_eq!(
            parse_options(&words(&["--backend", "foreign"]))
                .unwrap_err()
                .kind,
            "backend-selection"
        );
        for value in [Value::Null, json!("foreign")] {
            assert_eq!(
                selected_record(&json!({"plan":{"backend":value}}), BoxBackend::Codex)
                    .unwrap_err()
                    .kind,
                "backend-selection"
            );
        }
    }

    /// ´test:unit:claude-credential-exercise-refuses-before-owner-access´
    #[test]
    fn claude_credential_exercise_refuses_before_owner_access() {
        let root = tempfile::tempdir().expect("private fixture");
        let absent = root.path().join("absent-owner");
        for dry_run in [false, true] {
            let error = run_with(&absent, "alpha", dry_run, BoxBackend::Claude, || {
                panic!("measurement entered behind closed gate")
            })
            .unwrap_err();
            assert_eq!(error.kind, "backend-unavailable");
            assert!(error.detail.starts_with("claude boxed launch awaits"));
        }
        assert_eq!(
            private_measure(&absent, "alpha", BoxBackend::Claude)
                .unwrap_err()
                .kind,
            "backend-unavailable"
        );
        assert!(!absent.exists());
    }

    /// ´test:unit:credential-exercise-private-selector-is-required´
    #[test]
    fn credential_exercise_private_selector_is_required() {
        let home = Path::new("/synthetic-owner");
        for backend in [BoxBackend::Codex, BoxBackend::Claude] {
            let words = private_measure_words(home, "alpha", backend).expect("private vector");
            assert_eq!(
                parse_private_measure(&words).expect("receive"),
                ("alpha", home, backend)
            );
            for length in 0..words.len() {
                assert_eq!(
                    parse_private_measure(&words[..length]).unwrap_err().kind,
                    "exercise-private"
                );
            }
            let mut repeated = words.clone();
            repeated.extend(["--backend".into(), backend.name().into()]);
            assert_eq!(
                parse_private_measure(&repeated).unwrap_err().kind,
                "exercise-private"
            );
            for index in [0, 2, 3, 5] {
                let mut malformed = words.clone();
                malformed[index] = "foreign".into();
                assert_eq!(
                    parse_private_measure(&malformed).unwrap_err().kind,
                    "exercise-private"
                );
            }
            let mut unknown = words;
            unknown[4] = "foreign".into();
            assert_eq!(
                parse_private_measure(&unknown).unwrap_err().kind,
                "backend-selection"
            );
        }
    }

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
        let fixture = tempfile::tempdir().expect("fixture");
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
        publish_reservation(&reservation_path(&root, "R"), &json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"helper_pid":pid,"helper_start":start,"plan":{"backend":"codex","home":owner_home.join("worker")}})).expect("reservation");
        publish_reservation(&reservation_path(&root, "S"), &json!({
            "schema":1,"phase":"started","loop":"alpha","run":"S","worker_uid":3001,
            "helper_pid":pid,"helper_start":start,"plan":{"backend":"claude","home":owner_home.join("foreign-worker")}
        })).expect("foreign live reservation");
        let report = run(owner_home, "alpha", true, BoxBackend::Codex).expect("preview");
        assert_eq!(report["backend"], "codex");
        assert_eq!(report["live_runs"], json!(["R"]));
        assert_eq!(report["forced_refresh_available"], false);
        assert!(!config.join("exercise-latest.json").exists());
        let _launch =
            crate::install::lock_loop_config(&config, true).expect("live launch admission");
        let sampled = run_with(owner_home, "alpha", false, BoxBackend::Codex, || {
            Ok(json!({"schema":1,"custody":{"digest":"fixture"},"runs":[]}))
        })
        .expect("changing sample shares launch admission");
        assert_eq!(sampled["changed"], true);
        assert!(config.join("exercise-latest.json").exists());
    }
}
