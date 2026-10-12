//! Measured settlement for a reservation that lost its process identities.

use super::*;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use std::os::unix::ffi::OsStrExt as _;

pub(in crate::launch) fn needed(record: &Value) -> bool {
    if !matches!(
        record["phase"].as_str(),
        Some("preparing" | "started" | "failed" | "retiring" | "retired")
    ) {
        return false;
    }
    !record["retirement_absence_proof"].is_null()
        || (never_started_preparation(record) && record["launcher_pid"].is_null())
        || (record["phase"] == "started"
            && [
                "launcher_pid",
                "driver_entry_pid",
                "helper_pid",
                "observer_pid",
            ]
            .iter()
            .any(|key| record[*key].is_null()))
}

fn failure(detail: impl Into<String>) -> LaneError {
    LaneError::input("retire-uncertain", detail)
}

fn process_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn host_processes(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    let mut ignored = process_exclusions(Path::new("/proc"), std::process::id())?;
    ignored.scanning_argv = std::env::args_os()
        .map(|word| word.as_bytes().to_vec())
        .collect();
    let entries = fs::read_dir("/proc").map_err(|error| failure(error.to_string()))?;
    host_process_table(record, owner_home, &ignored, entries)
}

#[derive(Default)]
struct ProcessExclusions {
    pids: std::collections::BTreeMap<u32, u64>,
    uncertain: Option<String>,
    self_and_ancestors: usize,
    scanning_argv: Vec<Vec<u8>>,
}

fn launches_scanning_command(words: &[&[u8]], scanning_argv: &[Vec<u8>]) -> bool {
    if scanning_argv.is_empty() || words.len() < scanning_argv.len() {
        return false;
    }
    let tail = &words[words.len() - scanning_argv.len()..];
    let expected = Path::new(std::ffi::OsStr::from_bytes(&scanning_argv[0])).file_name();
    expected.is_some()
        && Path::new(std::ffi::OsStr::from_bytes(tail[0])).file_name() == expected
        && tail[1..]
            .iter()
            .zip(&scanning_argv[1..])
            .all(|(left, right)| *left == right.as_slice())
}

struct ProcessStat {
    comm: String,
    parent: u32,
    start: u64,
}

fn process_stat(path: &Path) -> std::io::Result<ProcessStat> {
    let bytes = fs::read(path)?;
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "process stat unreadable");
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(invalid)?;
    let name = &bytes[..end];
    let begin = name
        .iter()
        .position(|byte| *byte == b'(')
        .ok_or_else(invalid)?;
    let comm = &name[begin + 1..];
    let mut fields = bytes[end + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|word| !word.is_empty());
    let parent = fields
        .nth(1)
        .and_then(|word| std::str::from_utf8(word).ok())
        .and_then(|word| word.parse().ok())
        .ok_or_else(invalid)?;
    let start = fields
        .nth(17)
        .and_then(|word| std::str::from_utf8(word).ok())
        .and_then(|word| word.parse().ok())
        .ok_or_else(invalid)?;
    Ok(ProcessStat {
        comm: String::from_utf8_lossy(comm).into_owned(),
        parent,
        start,
    })
}

fn holder_detail(pid: u32, path: &Path) -> String {
    match process_stat(&path.join("stat")) {
        Ok(stat) => format!(
            "process {pid} ({}, parent {}) names this run",
            stat.comm, stat.parent
        ),
        Err(error) => {
            format!("process {pid} (stat unreadable: {error}, parent unknown) names this run")
        }
    }
}

fn process_exclusions(root: &Path, scanning_pid: u32) -> Result<ProcessExclusions, LaneError> {
    let mut parents = std::collections::BTreeMap::new();
    let mut children = std::collections::BTreeMap::<u32, Vec<u32>>::new();
    let mut ignored = ProcessExclusions::default();
    for entry in fs::read_dir(root).map_err(|error| failure(error.to_string()))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                ignored.uncertain = Some(error.to_string());
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|word| word.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match process_stat(&entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if process_gone(&error) => continue,
            Err(error) => {
                ignored.uncertain = Some(format!("process {pid} stat: {error}"));
                continue;
            }
        };
        children.entry(stat.parent).or_default().push(pid);
        parents.insert(pid, stat);
    }
    let mut pid = scanning_pid;
    while pid != 0 && !ignored.pids.contains_key(&pid) {
        let stat = parents
            .get(&pid)
            .ok_or_else(|| failure("process ancestry unreadable"))?;
        ignored.pids.insert(pid, stat.start);
        pid = stat.parent;
    }
    ignored.self_and_ancestors = ignored.pids.len();
    let mut pending = vec![scanning_pid];
    while let Some(parent) = pending.pop() {
        for child in children.get(&parent).into_iter().flatten() {
            if let Some(stat) = parents.get(child)
                && ignored.pids.insert(*child, stat.start).is_none()
            {
                pending.push(*child);
            }
        }
    }
    Ok(ignored)
}

fn host_process_table(
    record: &Value,
    owner_home: &Path,
    ignored: &ProcessExclusions,
    entries: impl IntoIterator<Item = std::io::Result<fs::DirEntry>>,
) -> Result<Value, LaneError> {
    host_process_table_with_environment(record, owner_home, ignored, entries, |path| fs::read(path))
}

fn environment_absent(error: &std::io::Error) -> bool {
    process_gone(error) || error.kind() == std::io::ErrorKind::PermissionDenied
}

#[allow(clippy::too_many_lines)]
fn host_process_table_with_environment(
    record: &Value,
    owner_home: &Path,
    ignored: &ProcessExclusions,
    entries: impl IntoIterator<Item = std::io::Result<fs::DirEntry>>,
    mut read_environment: impl FnMut(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Value, LaneError> {
    let run = record["run"]
        .as_str()
        .ok_or_else(|| failure("run absent"))?;
    let loop_name = record["loop"]
        .as_str()
        .ok_or_else(|| failure("loop absent"))?;
    let driver = record["plan"]["driver_dir"]
        .as_str()
        .ok_or_else(|| failure("driver path absent"))?;
    let mut uncertain = ignored.uncertain.clone();
    let mut busy = None;
    let mut launchers = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                uncertain = Some(error.to_string());
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|word| word.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(start) = ignored.pids.get(&pid) {
            match process_stat(&entry.path().join("stat")) {
                Ok(stat) if stat.start == *start => continue,
                Ok(_) => {}
                Err(error) if process_gone(&error) => continue,
                Err(error) => uncertain = Some(format!("process {pid} stat: {error}")),
            }
        }
        let bytes = match fs::read(entry.path().join("cmdline")) {
            Ok(bytes) => bytes,
            Err(error) if process_gone(&error) => continue,
            Err(error) => {
                uncertain = Some(format!("process {pid}: {error}"));
                continue;
            }
        };
        let words: Vec<_> = bytes
            .strip_suffix(&[0])
            .unwrap_or(&bytes)
            .split(|byte| *byte == 0)
            .collect();
        let named = words.contains(&run.as_bytes());
        if named && launches_scanning_command(&words, &ignored.scanning_argv) {
            launchers += 1;
            continue;
        }
        let path_match = words.iter().any(|word| {
            let word = String::from_utf8_lossy(word);
            word.contains(driver) || word.contains(&format!("lane-{loop_name}-{run}"))
        });
        if path_match {
            busy = Some(holder_detail(pid, &entry.path()));
            continue;
        }
        if !named {
            continue;
        }
        let uid = match entry.metadata() {
            Ok(metadata) => metadata.uid(),
            Err(error) if process_gone(&error) => continue,
            Err(error) => {
                uncertain = Some(error.to_string());
                continue;
            }
        };
        let same_home =
            if named && u64::from(uid) == record["worker_uid"].as_u64().unwrap_or(u64::MAX) {
                true
            } else if named && uid == Uid::effective().as_raw() {
                let env = match read_environment(&entry.path().join("environ")) {
                    Ok(env) => env,
                    Err(error) if environment_absent(&error) => continue,
                    Err(error) => {
                        uncertain = Some(format!("process {pid} environment: {error}"));
                        continue;
                    }
                };
                let home = format!("HOME={}", owner_home.display());
                let worker_home = format!(
                    "HOME={}",
                    record["plan"]["home"].as_str().unwrap_or_default()
                );
                let runs_root = format!(
                    "LANE_RUNS_ROOT={}",
                    Path::new(driver)
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .display()
                );
                env.split(|byte| *byte == 0).any(|word| {
                    word == home.as_bytes()
                        || word == worker_home.as_bytes()
                        || word == runs_root.as_bytes()
                })
            } else {
                false
            };
        if same_home {
            busy = Some(holder_detail(pid, &entry.path()));
        }
    }
    if let Some(detail) = busy {
        return Err(LaneError::input("retire-busy", detail));
    }
    if let Some(detail) = uncertain {
        return Err(failure(detail));
    }
    Ok(
        json!({"state":"absent","processes":[],"scope":"run-path-and-owner-name",
        "ignored":{"self_and_ancestors":ignored.self_and_ancestors,
            "descendants":ignored.pids.len() - ignored.self_and_ancestors,"launchers":launchers}}),
    )
}

fn host_locks(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    if matches!(record["phase"].as_str(), Some("retiring" | "retired")) {
        validate_retirement_paths(record)?;
    }
    super::super::driver_report::locks(owner_home, record)
}

#[cfg(test)]
pub(in crate::launch) fn fixture_locks(record: &Value) -> Result<Value, LaneError> {
    let directory = Path::new(
        record["plan"]["driver_dir"]
            .as_str()
            .ok_or_else(|| failure("driver path absent"))?,
    );
    let root = directory
        .parent()
        .ok_or_else(|| failure("driver parent absent"))?;
    let runs = fs::File::open(root).map_err(|error| failure(error.to_string()))?;
    let owner = Uid::effective().as_raw();
    let locks = locks_bound(&runs.into(), root, record, owner)?;
    decode_locks(&json!({"locks":locks}).to_string(), owner)
}

pub(in crate::launch) fn locks_bound(
    runs: &OwnedFd,
    root: &Path,
    record: &Value,
    owner: u32,
) -> Result<Value, LaneError> {
    let driver = record["plan"]["driver_dir"]
        .as_str()
        .ok_or_else(|| failure("driver path absent"))?;
    let mut directory = pin_lock_directory(runs, root, Path::new(driver), owner);
    if matches!(record["phase"].as_str(), Some("retiring" | "retired"))
        && let Some(pair) = record["current_retirement"]["planned_paths"]
            .as_array()
            .and_then(|pairs| pairs.iter().find(|pair| pair["source"] == driver))
        && matches!(&directory, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        let target = pair["target"]
            .as_str()
            .ok_or_else(|| failure("retired driver target absent"))?;
        directory = pin_lock_directory(runs, root, Path::new(target), owner);
    }
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
    let directory = match directory {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(
                json!({"measurement":{"state":"absent","driver_directory":"absent","driver_locks":[],"retirement_locks":"held-by-measurer"},"directory_identity":null}),
            );
        }
        Err(error) => return Err(failure(format!("driver directory: {error}"))),
    };
    let mut measured = Vec::new();
    let mut uncertain = None;
    let mut busy = None;
    for name in [".codex-lane.lock", ".claude-lane.lock"] {
        let result = measure_host_lock(&directory, name, how, &mut busy);
        match result {
            Ok(measurement) => measured.push(measurement),
            Err(error) => uncertain = Some(error),
        }
    }
    if let Some(detail) = busy {
        return Err(LaneError::input("retire-busy", detail));
    }
    if let Some(error) = uncertain {
        return Err(error);
    }
    let stat = nix::sys::stat::fstat(&directory)
        .map_err(|error| failure(format!("driver directory: {error}")))?;
    Ok(
        json!({"measurement":{"state":"absent","driver_locks":measured,"retirement_locks":"held-by-measurer"},"directory_identity":{"device":stat.st_dev,"inode":stat.st_ino,"uid":stat.st_uid}}),
    )
}

fn pin_lock_directory(
    runs: &OwnedFd,
    root: &Path,
    directory: &Path,
    owner: u32,
) -> std::io::Result<OwnedFd> {
    let invalid = || std::io::Error::other("directory path, owner or mode differs");
    let relative = directory.strip_prefix(root).map_err(|_| invalid())?;
    if relative.as_os_str().is_empty() {
        return Err(invalid());
    }
    let mut held = nix::unistd::dup(runs)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(invalid());
        };
        held = openat2(
            &held,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )?;
        let stat = nix::sys::stat::fstat(&held)?;
        if stat.st_uid != owner || stat.st_mode & 0o7022 != 0 || stat.st_mode & 0o700 != 0o700 {
            return Err(invalid());
        }
    }
    Ok(held)
}

pub(in crate::launch) fn decode_locks(output: &str, owner: u32) -> Result<Value, LaneError> {
    let invalid = || LaneError::input("driver-report-private", "private lock record shape differs");
    if output.len() > 16_384 {
        return Err(invalid());
    }
    let result: Value = serde_json::from_str(output).map_err(|_| invalid())?;
    if result.as_object().is_none_or(|object| object.len() != 1) {
        return Err(invalid());
    }
    if let Some(refusal) = result.get("refusal") {
        if refusal.as_object().is_none_or(|object| object.len() != 2) {
            return Err(invalid());
        }
        let kind = match refusal["kind"].as_str() {
            Some("retire-busy") => "retire-busy",
            Some("retire-uncertain") => "retire-uncertain",
            _ => return Err(invalid()),
        };
        let detail = refusal["detail"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(invalid)?;
        return Err(LaneError::input(kind, detail));
    }
    let locks = &result["locks"];
    if locks.as_object().is_none_or(|object| object.len() != 2)
        || locks.get("directory_identity").is_none()
    {
        return Err(invalid());
    }
    let measurement = &locks["measurement"];
    let identity = &locks["directory_identity"];
    let absent = identity.is_null();
    if measurement
        .as_object()
        .is_none_or(|object| object.len() != if absent { 4 } else { 3 })
        || measurement["state"] != "absent"
        || measurement["retirement_locks"] != "held-by-measurer"
        || (absent && measurement["driver_directory"] != "absent")
        || (!absent
            && (identity.as_object().is_none_or(|object| object.len() != 3)
                || identity["device"].as_u64().is_none()
                || identity["inode"].as_u64().is_none()
                || identity["uid"] != owner))
    {
        return Err(invalid());
    }
    let rows = measurement["driver_locks"].as_array().ok_or_else(invalid)?;
    if absent {
        if !rows.is_empty() {
            return Err(invalid());
        }
    } else {
        if rows.len() != 2 {
            return Err(invalid());
        }
        for (row, name) in rows.iter().zip([".codex-lane.lock", ".claude-lane.lock"]) {
            let size = if row.get("pids").is_some() { 3 } else { 2 };
            if row.as_object().is_none_or(|object| object.len() != size)
                || row["name"] != name
                || row["state"] != "absent"
            {
                return Err(invalid());
            }
            if let Some(pids) = row.get("pids")
                && !pids.as_array().is_some_and(|pids| {
                    (1..=2).contains(&pids.len())
                        && pids.iter().all(|pid| {
                            pid.as_u64()
                                .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok())
                        })
                })
            {
                return Err(invalid());
            }
        }
    }
    Ok(measurement.clone())
}

fn measure_host_lock(
    directory: &std::os::fd::OwnedFd,
    name: &str,
    how: OpenHow,
    busy: &mut Option<String>,
) -> Result<Value, LaneError> {
    let fd = match openat2(directory, name, how) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => {
            return Ok(json!({"name":name,"state":"absent"}));
        }
        Err(error) => return Err(failure(format!("{name}: {error}"))),
    };
    let file = fs::File::from(fd);
    if !file
        .metadata()
        .map_err(|error| failure(error.to_string()))?
        .is_file()
    {
        return Err(failure(format!("{name}: lock is not regular")));
    }
    let mut bytes = String::new();
    file.take(65)
        .read_to_string(&mut bytes)
        .map_err(|error| failure(format!("{name}: {error}")))?;
    let pids = bytes
        .lines()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| failure(format!("{name}: {error}")))?;
    if bytes.len() > 64 || !(1..=2).contains(&pids.len()) || pids.contains(&0) {
        return Err(failure(format!("{name}: invalid driver/child pid file")));
    }
    let mut uncertain = None;
    for pid in &pids {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(error) if process_gone(&error) => {}
            Err(error) => uncertain = Some(failure(format!("{name} pid {pid}: {error}"))),
            Ok(stat) => {
                let state = stat
                    .rsplit_once(')')
                    .and_then(|(_, fields)| fields.split_whitespace().next());
                match state {
                    Some("Z" | "X") => {}
                    Some(_) => {
                        *busy = Some(format!("{name} pid {pid} is present"));
                    }
                    None => uncertain = Some(failure(format!("{name} pid {pid}: unreadable stat"))),
                }
            }
        }
    }
    if let Some(error) = uncertain {
        return Err(error);
    }
    Ok(json!({"name":name,"state":"absent","pids":pids}))
}

pub(super) fn validate(proof: &Value) -> Result<(), LaneError> {
    if proof["schema"] != 1
        || proof["state"] != "absent"
        || !matches!(proof["phase"].as_str(), Some("preparing" | "started"))
    {
        return Err(failure("absence proof schema, state or phase is invalid"));
    }
    Ok(())
}

fn scan_verdict<'a>(
    scans: impl IntoIterator<Item = (&'a str, Result<Value, LaneError>)>,
) -> Result<Value, LaneError> {
    let mut evidence = serde_json::Map::new();
    let mut busy = None;
    let mut uncertain = None;
    for (name, scan) in scans {
        match scan {
            Ok(value) => {
                evidence.insert(name.into(), value);
            }
            Err(error) if error.kind == "retire-busy" => {
                if busy.is_none() {
                    busy = Some(error);
                }
            }
            Err(error) => {
                if uncertain.is_none() {
                    uncertain = Some(error);
                }
            }
        }
    }
    if let Some(error) = busy.or(uncertain) {
        return Err(error);
    }
    Ok(Value::Object(evidence))
}

fn identity_presence(name: &str, identity: Option<(u32, u64)>) -> Result<Value, LaneError> {
    let Some((pid, start)) = identity else {
        return Ok(json!({"presence":"absence-proved-without-identity"}));
    };
    match crate::container_helper::process_presence(pid, start) {
        crate::container_helper::ProcessPresence::Absent => {
            Ok(json!({"pid":pid,"start":start,"presence":"absent"}))
        }
        crate::container_helper::ProcessPresence::Present => Err(LaneError::input(
            "retire-busy",
            format!("{name} is still present"),
        )),
        crate::container_helper::ProcessPresence::Unknown => {
            Err(failure(format!("{name} presence unreadable")))
        }
    }
}

fn container_presence(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    let program = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| failure("container program absent"))?;
    let loop_name = record["loop"]
        .as_str()
        .ok_or_else(|| failure("loop absent"))?;
    let run = record["run"]
        .as_str()
        .ok_or_else(|| failure("run absent"))?;
    if !container_absent_for_run(Path::new(program), owner_home, loop_name, run)? {
        return Err(LaneError::input(
            "retire-busy",
            "labelled container is still present",
        ));
    }
    Ok(json!("absent-by-label"))
}

fn node_presence(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    let loop_name = record["loop"]
        .as_str()
        .ok_or_else(|| failure("loop absent"))?;
    let run = record["run"]
        .as_str()
        .ok_or_else(|| failure("run absent"))?;
    let plan = node_record::plan_for_record(owner_home, loop_name, run, record)?;
    if plan.value["reason"] == "node-retirement-no-registration"
        && record["plan"]["door"].is_object()
    {
        return Err(failure(
            "protected door route has no compute registration; restore the registered route before measuring node absence",
        ));
    }
    node::absence(&plan)
}

/// Measure missing observer custody without reconciling the run or its other identities.
pub(in crate::launch) fn observer_absence(
    record: &Value,
    owner_home: &Path,
) -> Result<Value, LaneError> {
    observer_absence_with_node(record, owner_home, node_presence)
}

pub(in crate::launch) fn observer_absence_with_node(
    record: &Value,
    owner_home: &Path,
    node_presence: impl FnOnce(&Value, &Path) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let mut evidence = scan_verdict([
        ("host", host_processes(record, owner_home)),
        ("locks", host_locks(record, owner_home)),
        ("node", node_presence(record, owner_home)),
    ])?;
    // Invocation-specific counts and elapsed time cannot bind a repeatable preview.
    if let Some(host) = evidence["host"].as_object_mut() {
        host.remove("ignored");
    }
    if let Some(node) = evidence["node"].as_object_mut() {
        node.remove("host_wall_seconds");
        node.remove("wall_seconds");
    }
    Ok(evidence)
}

pub(in crate::launch) fn reconcile(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    if record["settlement_uncertain"] == true {
        return Err(failure("settlement uncertainty is recorded"));
    }
    let phase = if record["retirement_absence_proof"].is_null() {
        record["phase"]
            .as_str()
            .ok_or_else(|| failure("phase absent"))?
    } else {
        validate(&record["retirement_absence_proof"])?;
        record["retirement_absence_proof"]["phase"]
            .as_str()
            .ok_or_else(|| failure("proof phase absent"))?
    };
    if !matches!(phase, "preparing" | "started") {
        return Err(failure("absence proof phase is not preparing or started"));
    }
    if matches!(record["phase"].as_str(), Some("preparing" | "started")) && record["phase"] != phase
    {
        return Err(failure("absence proof phase differs from the reservation"));
    }
    let driver_report = if phase == "started" {
        match super::super::reaping::check_unsettled_driver(record)? {
            super::super::reaping::UnsettledDriverCheck::Absent => Ok(json!("absent")),
            super::super::reaping::UnsettledDriverCheck::Unreadable(error) => Err(error),
        }
    } else {
        Ok(json!("not-applicable"))
    };
    let scope = if record.get("run_scope").is_none() {
        Ok(json!({"state":"not-recorded"}))
    } else {
        super::super::reaping::retirement_scope(record)
    };
    let mut scans = vec![("driver_report", driver_report), ("run_scope", scope)];
    for (name, identity) in [
        ("launcher", launcher_identity(record)),
        ("driver", driver_identity(record)),
        ("helper", helper_identity(record)),
        ("helper_parent", helper_parent_identity(record)),
        ("observer", observer_identity(record)),
    ] {
        scans.push((
            name,
            identity.and_then(|identity| identity_presence(name, identity)),
        ));
    }
    scans.extend([
        ("host", host_processes(record, owner_home)),
        ("locks", host_locks(record, owner_home)),
        ("container", container_presence(record, owner_home)),
        ("node", node_presence(record, owner_home)),
    ]);
    let evidence = scan_verdict(scans)?;
    let mut identities = serde_json::Map::new();
    for name in ["launcher", "driver", "helper", "helper_parent", "observer"] {
        identities.insert(name.into(), evidence[name].clone());
    }
    let mut result = record.clone();
    result["retirement_absence_proof"] = json!({"schema":1,"state":"absent","phase":phase,
        "run_scope":evidence["run_scope"],"identities":identities,"host":evidence["host"],
        "locks":evidence["locks"],"node":evidence["node"],"container":evidence["container"]});
    if matches!(record["phase"].as_str(), Some("retiring" | "retired")) {
        return Ok(result);
    }
    result["phase"] = json!("failed");
    result["reconciliation"] =
        json!({"cause":"driver-death","state":"verified","retirement":"measured-absence"});
    if let Some(round) = result["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        && matches!(
            round["phase"].as_str(),
            Some("running" | "awaiting-settlement")
        )
    {
        round["phase"] = json!("failed");
        round["settlement_error"] = json!("driver-death");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_locks(record: &Value) -> Result<Value, LaneError> {
        fixture_locks(record)
    }

    fn reconcile(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
        let _reader = crate::launch::driver_report::FixtureReader::enter();
        super::reconcile(record, owner_home)
    }

    /// # Panics
    /// Panics only if the strict private lock transport contract changes.
    /// ´test:unit:retirement-private-lock-record-shape´
    #[test]
    fn retirement_private_lock_record_shape() {
        let absent = json!({"locks":{"measurement":{"state":"absent","driver_directory":"absent","driver_locks":[],"retirement_locks":"held-by-measurer"},"directory_identity":null}});
        assert_eq!(
            decode_locks(&absent.to_string(), 41001).expect("absent")["driver_directory"],
            "absent"
        );
        let present = json!({"locks":{"measurement":{"state":"absent","driver_locks":[{"name":".codex-lane.lock","state":"absent","pids":[4_000_000,4_000_001]},{"name":".claude-lane.lock","state":"absent"}],"retirement_locks":"held-by-measurer"},"directory_identity":{"device":1,"inode":2,"uid":41001}}});
        assert_eq!(
            decode_locks(&present.to_string(), 41001).expect("locks"),
            present["locks"]["measurement"]
        );
        for (pointer, value) in [
            ("/locks/directory_identity/uid", json!(41002)),
            ("/locks/directory_identity/inode", json!(-1)),
            ("/locks/measurement/state", json!("present")),
            ("/locks/measurement/driver_locks/0/pids", json!([0])),
            ("/locks/measurement/driver_locks/0/pids", json!([1, 2, 3])),
            (
                "/locks/measurement/driver_locks/1/name",
                json!(".codex-lane.lock"),
            ),
            ("/locks/measurement/driver_locks", json!([])),
        ] {
            let mut malformed = present.clone();
            *malformed.pointer_mut(pointer).expect("field") = value;
            assert_eq!(
                decode_locks(&malformed.to_string(), 41001)
                    .expect_err("malformed")
                    .kind,
                "driver-report-private"
            );
        }
        for malformed in [
            json!({}),
            json!({"locks":{}}),
            json!({"locks":absent["locks"],"extra":0}),
            json!({"refusal":{"kind":"other","detail":"bad"}}),
        ] {
            assert_eq!(
                decode_locks(&malformed.to_string(), 41001)
                    .expect_err("envelope")
                    .kind,
                "driver-report-private"
            );
        }
        let refusal = json!({"refusal":{"kind":"retire-uncertain","detail":"driver directory: Permission denied"}});
        assert_eq!(
            decode_locks(&refusal.to_string(), 41001)
                .expect_err("unreadable")
                .kind,
            "retire-uncertain"
        );
    }

    fn fixture_stat(root: &Path, pid: u32, parent: u32, start: u64) {
        fs::write(
            root.join(pid.to_string()).join("stat"),
            format!(
                "{pid} (helper (R)) S {parent} {} {start}\n",
                "0 ".repeat(17).trim_end()
            ),
        )
        .expect("process stat");
    }

    /// # Panics
    /// Panics only if the fixture cannot be built or a byte command name prevents measurement.
    /// ´test:unit:retirement-process-scan-accepts-non-utf8-command-name´
    #[test]
    fn retirement_process_scan_accepts_non_utf8_command_name() {
        let root = tempfile::tempdir().expect("process table");
        for (pid, parent) in [(1, 0), (20, 1), (30, 1)] {
            fs::create_dir(root.path().join(pid.to_string())).expect("process");
            fixture_stat(root.path(), pid, parent, 100);
            fs::write(
                root.path().join(pid.to_string()).join("cmdline"),
                b"unrelated\0",
            )
            .expect("command");
        }
        let path = root.path().join("30/stat");
        let mut bytes = fs::read(&path).expect("stat bytes");
        let index = bytes
            .iter()
            .position(|byte| *byte == b'l')
            .expect("command byte");
        bytes[index] = 0xff;
        fs::write(path, bytes).expect("non-UTF-8 command name");
        let ignored = process_exclusions(root.path(), 20).expect("snapshot");
        assert!(ignored.uncertain.is_none());
        let record = json!({"run":"R","loop":"alpha","worker_uid":Uid::effective().as_raw(),
            "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
        let scan = || {
            host_process_table(
                &record,
                Path::new("/fixture-owner"),
                &ignored,
                fs::read_dir(root.path()).expect("table"),
            )
        };
        assert_eq!(
            scan().expect("unrelated byte name is absent")["state"],
            "absent"
        );
        fs::write(root.path().join("30/cmdline"), b"R\0").expect("holder");
        let error = scan().expect_err("byte-named holder remains busy");
        assert_eq!(error.kind, "retire-busy");
        assert_eq!(
            error.detail,
            "process 30 (he\u{fffd}per (R), parent 1) names this run"
        );
    }

    /// # Panics
    /// Panics only if invocation counts affect the digest or other evidence loses its binding.
    /// ´test:unit:retirement-preview-excludes-only-host-exclusion-counts´
    #[test]
    fn retirement_preview_excludes_only_host_exclusion_counts() {
        let mut record = json!({"retirement_absence_proof":{"schema":1,"state":"absent",
            "host":{"state":"absent","ignored":{"self_and_ancestors":2,"descendants":0}}}});
        let mut journal = json!({"settlement":record["retirement_absence_proof"]});
        let first = node_record::preview(&record, &journal, None, false);
        record["retirement_absence_proof"]["host"]["ignored"] =
            json!({"self_and_ancestors":5,"descendants":3,"launchers":1});
        journal["settlement"] = record["retirement_absence_proof"].clone();
        assert_eq!(first, node_record::preview(&record, &journal, None, false));
        assert_eq!(journal["settlement"]["host"]["ignored"]["launchers"], 1);
        assert_eq!(
            record["retirement_absence_proof"]["host"]["ignored"]["descendants"],
            3
        );
        assert_eq!(
            journal["settlement"]["host"]["ignored"]["self_and_ancestors"],
            5
        );
        record["retirement_absence_proof"]["host"]
            .as_object_mut()
            .expect("host")
            .remove("ignored");
        assert_eq!(first, node_record::preview(&record, &journal, None, false));
        record["ignored"] = json!(1);
        assert_ne!(first, node_record::preview(&record, &journal, None, false));
        record.as_object_mut().expect("record").remove("ignored");
        record["retirement_absence_proof"]["host"]["state"] = json!("present");
        assert_ne!(first, node_record::preview(&record, &journal, None, false));
    }

    /// # Panics
    /// Panics only if the fixture cannot be built or a reused pid is excluded.
    /// ´test:unit:retirement-process-scan-measures-reused-excluded-pid´
    #[test]
    fn retirement_process_scan_measures_reused_excluded_pid() {
        let root = tempfile::tempdir().expect("process table");
        for (pid, parent) in [(1, 0), (20, 1), (30, 20)] {
            fs::create_dir(root.path().join(pid.to_string())).expect("process");
            fixture_stat(root.path(), pid, parent, 100);
            fs::write(root.path().join(pid.to_string()).join("cmdline"), b"R\0").expect("command");
        }
        let ignored = process_exclusions(root.path(), 20).expect("snapshot");
        fixture_stat(root.path(), 30, 1, 200);
        let record = json!({"run":"R","loop":"alpha","worker_uid":Uid::effective().as_raw(),
            "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
        let error = host_process_table(
            &record,
            Path::new("/fixture-owner"),
            &ignored,
            fs::read_dir(root.path()).expect("table"),
        )
        .expect_err("reused pid is measured");
        assert_eq!(error.kind, "retire-busy");
        assert_eq!(
            error.detail,
            "process 30 (helper (R), parent 1) names this run"
        );
    }

    /// # Panics
    /// Panics only if the fixture cannot be built or snapshot uncertainty hides a holder.
    /// ´test:unit:retirement-snapshot-uncertainty-retains-busy-precedence´
    #[test]
    fn retirement_snapshot_uncertainty_retains_busy_precedence() {
        let root = tempfile::tempdir().expect("process table");
        for (pid, parent) in [(1, 0), (20, 1), (30, 1), (40, 1)] {
            fs::create_dir(root.path().join(pid.to_string())).expect("process");
            fixture_stat(root.path(), pid, parent, 100);
            fs::write(
                root.path().join(pid.to_string()).join("cmdline"),
                b"unrelated\0",
            )
            .expect("command");
        }
        let unreadable = root.path().join("30/stat");
        fs::remove_file(&unreadable).expect("remove stat");
        fs::create_dir(&unreadable).expect("unreadable stat");
        let ignored = process_exclusions(root.path(), 20).expect("snapshot finishes");
        assert!(ignored.uncertain.is_some());
        assert!(!ignored.pids.contains_key(&30));
        let record = json!({"run":"R","loop":"alpha","worker_uid":Uid::effective().as_raw(),
            "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
        let scan = || {
            host_process_table(
                &record,
                Path::new("/fixture-owner"),
                &ignored,
                fs::read_dir(root.path()).expect("table"),
            )
        };
        assert_eq!(
            scan().expect_err("uncertainty retained").kind,
            "retire-uncertain"
        );
        fs::write(root.path().join("40/cmdline"), b"R\0").expect("holder");
        let error = scan().expect_err("busy outranks snapshot uncertainty");
        assert_eq!(error.kind, "retire-busy");
        assert_eq!(
            error.detail,
            "process 40 (helper (R), parent 1) names this run"
        );
    }

    /// # Panics
    /// Panics only if the fixture cannot be built or the argv-tail boundary changes.
    /// ´test:unit:retirement-process-scan-counts-same-command-launchers´
    #[test]
    fn retirement_process_scan_counts_same_command_launchers() {
        let root = tempfile::tempdir().expect("process table");
        let process = root.path().join("40");
        fs::create_dir(&process).expect("process");
        fs::write(
            process.join("stat"),
            format!(
                "40 (flatpak-spawn) S 10 {} 100\n",
                "0 ".repeat(17).trim_end()
            ),
        )
        .expect("stat");
        fs::write(process.join("environ"), b"HOME=/fixture-owner\0").expect("owner home");
        let ignored = ProcessExclusions {
            scanning_argv: [
                "/usr/bin/superloop-lane",
                "retire",
                "alpha",
                "R",
                "--dry-run",
            ]
            .map(|word| word.as_bytes().to_vec())
            .to_vec(),
            ..ProcessExclusions::default()
        };
        for (run, argv, accepted) in [
            (
                "R",
                b"flatpak-spawn\0--host\0/other/bin/superloop-lane\0retire\0alpha\0R\0--dry-run\0"
                    .as_slice(),
                true,
            ),
            (
                "other",
                b"flatpak-spawn\0--host\0superloop-lane\0retire\0alpha\0other\0--dry-run\0"
                    .as_slice(),
                false,
            ),
            (
                "R",
                b"flatpak-spawn\0--host\0superloop-lane\0retire\0beta\0R\0--dry-run\0".as_slice(),
                false,
            ),
            (
                "R",
                b"flatpak-spawn\0--host\0another-program\0retire\0alpha\0R\0--dry-run\0".as_slice(),
                false,
            ),
            (
                "R",
                b"flatpak-spawn\0--host\0superloop-lane\0retire\0alpha\0R\0--dry-run\0extra\0"
                    .as_slice(),
                false,
            ),
            (
                "R",
                b"flatpak-spawn\0--host\0superloop-lane\0retire\0alpha\0R\0--dry-run\0\0"
                    .as_slice(),
                false,
            ),
        ] {
            fs::write(process.join("cmdline"), argv).expect("launcher command");
            let record = json!({"run":run,"loop":"alpha","worker_uid":u32::MAX,
                "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
            let result = host_process_table(
                &record,
                Path::new("/fixture-owner"),
                &ignored,
                fs::read_dir(root.path()).expect("table"),
            );
            if accepted {
                let proof = result.expect("same command launcher excluded");
                assert_eq!(proof["ignored"]["launchers"], 1);
                assert_eq!(proof["state"], "absent");
            } else {
                let error = result.expect_err("different command remains a holder");
                assert_eq!(error.kind, "retire-busy");
                assert!(error.detail.contains("process 40"));
                assert!(error.detail.contains("flatpak-spawn"));
                assert!(error.detail.contains("parent 10"));
            }
        }
    }

    /// # Panics
    /// Panics only if the fixture cannot be built or the scan excludes an unrelated holder.
    /// ´test:unit:retirement-process-scan-excludes-own-tree´
    #[test]
    fn retirement_process_scan_excludes_own_tree() {
        let root = tempfile::tempdir().expect("process table");
        // Create the grandchild before its parent, and include a sibling's child; the snapshot is order-independent.
        for (pid, parent) in [(1, 0), (20, 1), (3, 30), (30, 20), (40, 1), (50, 40)] {
            let process = root.path().join(pid.to_string());
            fs::create_dir(&process).expect("process");
            fs::write(
                process.join("stat"),
                format!(
                    "{pid} (helper (R)) S {parent} {} 100\n",
                    "0 ".repeat(17).trim_end()
                ),
            )
            .expect("parent field");
            fs::write(process.join("cmdline"), b"unrelated\0").expect("command");
        }
        let ignored = process_exclusions(root.path(), 20).expect("snapshot");
        assert_eq!(
            ignored.pids,
            std::collections::BTreeMap::from([(1, 100), (3, 100), (20, 100), (30, 100)])
        );
        let record = json!({"run":"R","loop":"alpha","worker_uid":Uid::effective().as_raw(),
            "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
        for pid in [1, 3, 20, 30] {
            fs::write(root.path().join(pid.to_string()).join("cmdline"), b"R\0")
                .expect("own tree names run");
        }
        let scan = || {
            host_process_table(
                &record,
                Path::new("/fixture-owner"),
                &ignored,
                fs::read_dir(root.path()).expect("table"),
            )
        };
        let preview = scan().expect("own tree is excluded");
        assert_eq!(preview["state"], "absent");
        assert_eq!(
            preview["ignored"],
            json!({"self_and_ancestors":2,"descendants":2,"launchers":0})
        );
        for pid in [40, 50] {
            let command = root.path().join(pid.to_string()).join("cmdline");
            fs::write(&command, b"R\0").expect("unrelated holder");
            let error = scan().expect_err("unrelated holder stays busy");
            assert_eq!(error.kind, "retire-busy");
            assert_eq!(
                error.detail,
                format!(
                    "process {pid} (helper (R), parent {}) names this run",
                    if pid == 40 { 1 } else { 40 }
                )
            );
            fs::write(command, b"unrelated\0").expect("release holder");
        }
    }

    /// # Panics
    /// Panics only if environment error classification changes.
    /// ´test:unit:retirement-environment-error-classification´
    #[test]
    fn retirement_environment_error_classification() {
        use std::io::ErrorKind;

        for (kind, absent) in [
            (ErrorKind::PermissionDenied, true),
            (ErrorKind::NotFound, true),
            (ErrorKind::Interrupted, false),
            (ErrorKind::InvalidData, false),
            (ErrorKind::Other, false),
        ] {
            assert_eq!(environment_absent(&std::io::Error::from(kind)), absent);
        }
        for errno in [libc::EACCES, libc::ESRCH] {
            assert!(environment_absent(&std::io::Error::from_raw_os_error(
                errno
            )));
        }
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or the scan misclassifies environment errors.
    /// ´test:unit:retirement-process-scan-permission-denied-environment-is-absent´
    #[test]
    fn retirement_process_scan_permission_denied_environment_is_absent() {
        let root = tempfile::tempdir().expect("process table");
        let process = root.path().join("1");
        fs::create_dir(&process).expect("process");
        fs::write(process.join("cmdline"), b"R\0").expect("name");
        let record = json!({"run":"R","loop":"alpha","worker_uid":u32::MAX,
            "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
        for errno in [libc::EACCES, libc::EIO] {
            let mut reads = 0;
            let result = host_process_table_with_environment(
                &record,
                Path::new("/fixture-owner"),
                &ProcessExclusions::default(),
                fs::read_dir(root.path()).expect("table"),
                |path| {
                    assert_eq!(path, process.join("environ"));
                    reads += 1;
                    Err(std::io::Error::from_raw_os_error(errno))
                },
            );
            assert_eq!(reads, 1);
            if errno == libc::EACCES {
                assert_eq!(
                    result.expect("unreadable to owner is absent")["state"],
                    "absent"
                );
            } else {
                let error = result.expect_err("other read failures remain uncertain");
                assert_eq!(error.kind, "retire-uncertain");
                assert_eq!(
                    error.detail,
                    format!(
                        "process 1 environment: {}",
                        std::io::Error::from_raw_os_error(errno)
                    )
                );
            }
        }
    }

    fn started_retirement_fixture() -> (tempfile::TempDir, Value) {
        let home = tempfile::tempdir().expect("owner home");
        fs::create_dir_all(home.path().join(".config/loops/alpha")).expect("loop configuration");
        for relative in ["", ".config", ".config/loops", ".config/loops/alpha"] {
            fs::set_permissions(
                home.path().join(relative),
                fs::Permissions::from_mode(0o700),
            )
            .expect("private configuration custody");
        }
        let driver = home.path().join("runs/R");
        fs::create_dir_all(&driver).expect("driver directory");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o700)).expect("driver custody");
        fs::write(
            driver.join(".codex-lane.lock"),
            format!("{}\n", std::process::id()),
        )
        .expect("busy lock");
        let record = json!({"phase":"started","run":"R","loop":"alpha",
            "launcher_pid":std::process::id(),
            "launcher_start":launch_process_start(std::process::id()).expect("launcher start"),
            "rounds":[{"step":"dispatch","phase":"running"}],"plan":{"driver_dir":driver}});
        (home, record)
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or unreadable reports hide measured presence.
    /// ´test:unit:retirement-reconcile-busy-outranks-unreadable-driver-report´
    #[test]
    fn retirement_reconcile_busy_outranks_unreadable_driver_report() {
        for unreadable in ["runs-root", "report"] {
            let (home, mut record) = started_retirement_fixture();
            if unreadable == "runs-root" {
                fs::remove_dir_all(home.path().join("runs")).expect("missing runs root");
            } else {
                fs::create_dir(home.path().join("runs/.report=R.json")).expect("nonregular report");
                assert_eq!(
                    host_locks(&record).expect_err("busy driver lock").kind,
                    "retire-busy"
                );
            }
            assert!(needed(&record));
            assert_eq!(
                super::super::super::reaping::require_unsettled_driver(&record)
                    .expect_err("report cannot be read")
                    .kind,
                "retire-uncertain"
            );
            assert_eq!(
                reconcile(&record, home.path()).expect_err("busy wins").kind,
                "retire-busy"
            );
            record["launcher_pid"] = Value::Null;
            record["launcher_start"] = Value::Null;
            if unreadable == "report" {
                fs::remove_file(home.path().join("runs/R/.codex-lane.lock")).expect("remove lock");
            }
            assert_eq!(
                reconcile(&record, home.path())
                    .expect_err("read failure remains")
                    .detail,
                super::super::super::reaping::require_unsettled_driver(&record)
                    .expect_err("report cannot be read")
                    .detail
            );
        }
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or reconciliation bypasses a settlement guard.
    /// ´test:unit:retirement-reconcile-preserves-settlement-guards-before-busy-scans´
    #[test]
    fn retirement_reconcile_preserves_settlement_guards_before_busy_scans() {
        let (home, record) = started_retirement_fixture();
        assert_eq!(
            host_locks(&record).expect_err("busy lock").kind,
            "retire-busy"
        );
        for pointer in [
            "/driver_end",
            "/reaping_recovery",
            "/rounds/0/report",
            "/rounds/0/driver_end",
        ] {
            let mut guarded = record.clone();
            if let Some(key) = pointer.strip_prefix("/rounds/0/") {
                guarded["rounds"][0][key] = json!({});
            } else {
                guarded[&pointer[1..]] = json!({});
            }
            assert_eq!(
                reconcile(&guarded, home.path())
                    .expect_err("preserve finished reply")
                    .kind,
                "interrupted-settlement"
            );
        }
        let mut guarded = record.clone();
        guarded["rounds"] = json!([{"step":"dispatch"},{"step":"dispatch"}]);
        assert_eq!(
            reconcile(&guarded, home.path())
                .expect_err("ambiguous round")
                .kind,
            "retire-report-ambiguous"
        );
        guarded = record;
        guarded["settlement_uncertain"] = json!(true);
        assert_eq!(
            reconcile(&guarded, home.path())
                .expect_err("settlement uncertainty")
                .detail,
            "settlement uncertainty is recorded"
        );
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or a saved reply loses settlement protection.
    /// ´test:unit:retirement-reconcile-preserves-published-driver-report-before-busy-scans´
    #[test]
    fn retirement_reconcile_preserves_published_driver_report_before_busy_scans() {
        let (home, record) = started_retirement_fixture();
        let report = json!({"schema":1,"command":"launch","dry_run":false,
            "observe":false,"enforcing":true,"observed":null,"home":"fixture-home",
            "driver_dir":"fixture-driver","round_dir":"fixture-round","preparation":"ready",
            "credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"reply retained","settlement":{},
            "evidence":"driver directory outside home","wall_seconds":0.0});
        let path = home.path().join("runs/.report=R.json");
        fs::write(&path, serde_json::to_vec(&report).expect("report JSON")).expect("saved report");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("report custody");
        assert_eq!(
            host_locks(&record).expect_err("busy lock").kind,
            "retire-busy"
        );
        assert_eq!(
            reconcile(&record, home.path())
                .expect_err("preserve published reply")
                .kind,
            "interrupted-settlement"
        );
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or reconciliation short-circuits its scans.
    /// ´test:unit:retirement-reconcile-busy-outranks-incomplete-launcher´
    #[test]
    fn retirement_reconcile_busy_outranks_incomplete_launcher() {
        let home = tempfile::tempdir().expect("owner home");
        fs::create_dir_all(home.path().join(".config/loops/alpha")).expect("loop configuration");
        for relative in ["", ".config", ".config/loops", ".config/loops/alpha"] {
            fs::set_permissions(
                home.path().join(relative),
                fs::Permissions::from_mode(0o700),
            )
            .expect("private configuration custody");
        }
        let driver = home.path().join("driver");
        fs::create_dir(&driver).expect("driver directory");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o700)).expect("driver custody");
        fs::write(
            driver.join(".codex-lane.lock"),
            format!("{}\n", std::process::id()),
        )
        .expect("busy lock");
        let record = json!({"phase":"preparing","run":"R","loop":"alpha",
            "launcher_pid":std::process::id(),"plan":{"driver_dir":driver}});
        assert_eq!(
            launcher_identity(&record)
                .expect_err("incomplete identity")
                .kind,
            "launch-reservation"
        );
        assert_eq!(
            container_presence(&record, home.path())
                .expect_err("no container program")
                .kind,
            "retire-uncertain"
        );
        assert_eq!(
            node_presence(&record, home.path()).expect("no compute registration")["state"],
            "not-applicable"
        );
        assert_eq!(
            reconcile(&record, home.path())
                .expect_err("busy lock outranks earlier refusal")
                .kind,
            "retire-busy"
        );
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or the verdict violates scan precedence.
    /// ´test:unit:retirement-verdict-busy-outranks-uncertain-scans-in-either-order´
    #[test]
    fn retirement_verdict_busy_outranks_uncertain_scans_in_either_order() {
        let root = tempfile::tempdir().expect("driver directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("driver custody");
        let record = json!({"run":"R","loop":"alpha","plan":{"driver_dir":root.path()}});
        fs::write(
            root.path().join(".codex-lane.lock"),
            format!("{}\n", std::process::id()),
        )
        .expect("busy lock");
        for order in [["host", "locks"], ["locks", "host"]] {
            let mut visited = Vec::new();
            let result = scan_verdict(order.into_iter().map(|name| {
                visited.push(name);
                let scan = if name == "host" {
                    host_process_table(
                        &record,
                        root.path(),
                        &ProcessExclusions::default(),
                        [Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "fixture process table unreadable",
                        ))],
                    )
                } else {
                    host_locks(&record)
                };
                (name, scan)
            }));
            assert_eq!(visited, order);
            assert_eq!(result.expect_err("busy wins").kind, "retire-busy");
        }
        assert_eq!(
            scan_verdict([
                ("host", Err(failure("unreadable"))),
                ("node", Ok(json!({})))
            ])
            .expect_err("uncertain wins over absent")
            .kind,
            "retire-uncertain"
        );
        assert_eq!(
            scan_verdict([("host", Ok(json!({"state":"absent"})))]).expect("all absent")["host"]["state"],
            "absent"
        );
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or the scan violates presence precedence.
    /// ´test:unit:retirement-lock-scan-busy-outranks-unreadable-in-either-order´
    #[test]
    fn retirement_lock_scan_busy_outranks_unreadable_in_either_order() {
        for names in [
            [".codex-lane.lock", ".claude-lane.lock"],
            [".claude-lane.lock", ".codex-lane.lock"],
        ] {
            let root = tempfile::tempdir().expect("driver directory");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("driver custody");
            let record = json!({"plan":{"driver_dir":root.path()}});
            let unreadable = root.path().join(names[0]);
            let busy = root.path().join(names[1]);
            fs::create_dir(&unreadable).expect("nonregular lock");
            fs::write(&busy, format!("{}\n", std::process::id())).expect("busy lock");
            assert_eq!(
                host_locks(&record).expect_err("busy wins").kind,
                "retire-busy"
            );
            fs::remove_file(busy).expect("remove busy lock");
            assert_eq!(
                host_locks(&record).expect_err("unreadable remains").kind,
                "retire-uncertain"
            );
            fs::remove_dir(unreadable).expect("remove unreadable lock");
            assert_eq!(
                host_locks(&record).expect("absent locks")["state"],
                "absent"
            );
        }
    }

    /// # Panics
    /// Panics only if fixture custody cannot be built or the scan violates presence precedence.
    /// ´test:unit:retirement-process-scan-busy-outranks-unreadable-in-either-order´
    #[test]
    fn retirement_process_scan_busy_outranks_unreadable_in_either_order() {
        for unreadable in ["cmdline", "environ"] {
            let root = tempfile::tempdir().expect("process table");
            for pid in [1, 2] {
                let process = root.path().join(pid.to_string());
                fs::create_dir(&process).expect("process");
                fs::write(process.join("cmdline"), b"R\0").expect("name");
                fs::write(process.join("environ"), b"HOME=/fixture-owner\0").expect("home");
            }
            let path = root.path().join("1").join(unreadable);
            fs::remove_file(&path).expect("remove readable field");
            fs::create_dir(&path).expect("deterministically unreadable field");
            let record = json!({"run":"R","loop":"alpha","worker_uid":u32::MAX,
                "plan":{"driver_dir":"/fixture-runs/R","home":"/fixture-worker"}});
            for reverse in [false, true] {
                let mut entries = fs::read_dir(root.path())
                    .expect("table")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("entries");
                entries.sort_by_key(std::fs::DirEntry::file_name);
                if reverse {
                    entries.reverse();
                }
                let result = host_process_table(
                    &record,
                    Path::new("/fixture-owner"),
                    &ProcessExclusions::default(),
                    entries.into_iter().map(Ok),
                );
                assert_eq!(result.expect_err("busy wins").kind, "retire-busy");
            }
            fs::remove_dir_all(root.path().join("2")).expect("remove busy process");
            let result = host_process_table(
                &record,
                Path::new("/fixture-owner"),
                &ProcessExclusions::default(),
                fs::read_dir(root.path()).expect("table"),
            );
            assert_eq!(
                result.expect_err("unreadable remains").kind,
                "retire-uncertain"
            );
            fs::remove_dir_all(root.path().join("1")).expect("remove unreadable process");
            assert!(
                host_process_table(
                    &record,
                    Path::new("/fixture-owner"),
                    &ProcessExclusions::default(),
                    fs::read_dir(root.path()).expect("table")
                )
                .is_ok()
            );
        }
    }
}
