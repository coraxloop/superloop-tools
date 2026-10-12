//! Bounded driver evidence read inside the descriptor-bound private namespace.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::fstat;
use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::{build, error::LaneError, home};

fn invalid() -> LaneError {
    LaneError::input(
        "repin-door-state",
        "matching driver run report is absent or invalid",
    )
}

fn read_error(error: &std::io::Error) -> LaneError {
    LaneError::input(
        if error.kind() == std::io::ErrorKind::NotFound {
            "repin-door-state"
        } else {
            "repin-door-uncertain"
        },
        format!("driver run report: {error}"),
    )
}

fn private_error(detail: impl Into<String>) -> LaneError {
    LaneError::input("driver-report-private", detail)
}

/// Read the report through the same pinned namespace entry as settlement.
pub(crate) fn read(owner_home: &Path, record: &Value) -> Result<Value, LaneError> {
    #[cfg(test)]
    if FIXTURE_READER.with(std::cell::Cell::get) {
        return fixture_read(record);
    }
    request(owner_home, record, false)
}

pub(super) fn locks(owner_home: &Path, record: &Value) -> Result<Value, LaneError> {
    #[cfg(test)]
    if FIXTURE_READER.with(std::cell::Cell::get) {
        return super::retire::proof::fixture_locks(record);
    }
    request(owner_home, record, true)
}

fn request(owner_home: &Path, record: &Value, locks: bool) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let run = record["run"].as_str().ok_or_else(invalid)?;
    let loop_name = record["loop"].as_str().ok_or_else(invalid)?;
    let directory = Path::new(record["plan"]["driver_dir"].as_str().ok_or_else(invalid)?);
    let root = directory.parent().ok_or_else(invalid)?;
    let verified_home = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let (current, identity) = super::checkout::read_record_bound(&runs, run, owner)?;
    if current != *record {
        return Err(private_error(
            "reservation changed before private report read",
        ));
    }
    let program = Path::new(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(invalid)?,
    );
    crate::pinned::owner_executable(program, owner)?;
    let exe = std::env::current_exe().map_err(|error| private_error(error.to_string()))?;
    let mut argv = vec![
        "unshare".into(),
        crate::pinned::owner_executable_word(&exe, owner)?,
    ];
    argv.extend(private_argv(owner_home, loop_name, run, &identity)?);
    if locks {
        argv.push("--locks".into());
    }
    let output = build::run_checked_with_private_launch(
        program,
        argv,
        &super::launch_environment(owner_home)?,
        owner_home,
        60,
        "driver-report-private",
        &verified_home,
        root,
        &runs,
        None,
    )?;
    if locks {
        super::retire::proof::decode_locks(&output, super::recorded_loop_uid(record)?)
    } else {
        decode(&output, record)
    }
}

#[cfg(test)]
thread_local! {
    static FIXTURE_READER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) struct FixtureReader(bool);

#[cfg(test)]
impl FixtureReader {
    pub(crate) fn enter() -> Self {
        Self(FIXTURE_READER.with(|enabled| enabled.replace(true)))
    }
}

#[cfg(test)]
impl Drop for FixtureReader {
    fn drop(&mut self) {
        FIXTURE_READER.with(|enabled| enabled.set(self.0));
    }
}

#[cfg(test)]
pub(crate) fn fixture_read(record: &Value) -> Result<Value, LaneError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let last = record["rounds"]
        .as_array()
        .and_then(|rows| rows.last())
        .ok_or_else(invalid)?;
    let directory = Path::new(last["driver_dir"].as_str().ok_or_else(invalid)?);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)
        .map_err(|error| read_error(&error))?;
    let owner = held.metadata().map_err(|error| read_error(&error))?.uid();
    read_directory(&held.into(), directory, last, owner)
}

pub(super) fn private_argv(
    home: &Path,
    loop_name: &str,
    run: &str,
    identity: &str,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_driver-report".into(),
        loop_name.into(),
        run.into(),
        "--owner-home".into(),
        crate::pinned::path_word(home, "driver-report-private")?,
        "--expect-record".into(),
        identity.into(),
    ])
}

/// Read only after the entry has bound the inherited home and runs descriptors.
///
/// # Errors
/// Refuses missing namespace authority, changed reservations or invalid report evidence.
pub fn private(args: &[String]) -> Result<Value, LaneError> {
    let locks = args.last().is_some_and(|word| word == "--locks");
    let args = if locks { &args[..args.len() - 1] } else { args };
    let [
        command,
        loop_name,
        run,
        home_flag,
        owner_home,
        identity_flag,
        expected,
    ] = args
    else {
        return Err(private_error("private report form is incomplete"));
    };
    if command != "_driver-report"
        || home_flag != "--owner-home"
        || identity_flag != "--expect-record"
        || !crate::valid_run_name(run)
        || loop_home::validate_name(loop_name).is_err()
        || !Uid::effective().is_root()
        || !home::private_is_active()
        || home::private_home().as_deref() != Some(Path::new(owner_home))
    {
        return Err(private_error(
            "bound namespace owner and report form are required",
        ));
    }
    let (root, runs) = home::private_runs()?;
    let (record, identity) = super::checkout::read_record_bound(&runs, run, 0)?;
    if identity != *expected
        || record["loop"] != *loop_name
        || record["run"] != *run
        || record["plan"]["driver_dir"] != json!(root.join(run))
    {
        return Err(private_error(
            "reservation differs from public report request",
        ));
    }
    // Transport report refusals as data; failure to start the private step keeps its own name.
    let owner = super::recorded_loop_uid(&record)?;
    if locks {
        return Ok(
            match super::retire::proof::locks_bound(&runs, &root, &record, owner) {
                Ok(measurement) => json!({"locks":measurement}),
                Err(error) => json!({"refusal":{"kind":error.kind,"detail":error.detail}}),
            },
        );
    }
    Ok(match read_bound(&runs, &root, &record, owner) {
        Ok(report) => json!({"report":report}),
        Err(error) => json!({"refusal":{"kind":error.kind,"detail":error.detail}}),
    })
}

pub(super) fn decode(output: &str, record: &Value) -> Result<Value, LaneError> {
    if output.len() > 16_384 {
        return Err(private_error("private report exceeds its bound"));
    }
    let result: Value =
        serde_json::from_str(output).map_err(|error| private_error(error.to_string()))?;
    if result.as_object().is_none_or(|object| object.len() != 1) {
        return Err(private_error("private report envelope differs"));
    }
    if let Some(refusal) = result.get("refusal") {
        if refusal.as_object().is_none_or(|object| object.len() != 2)
            || !refusal["detail"].is_string()
        {
            return Err(private_error("private report refusal shape differs"));
        }
        let kind = match refusal["kind"].as_str() {
            Some("repin-door-state") => "repin-door-state",
            Some("repin-door-uncertain") => "repin-door-uncertain",
            _ => return Err(private_error("private report refusal differs")),
        };
        return Err(LaneError::input(
            kind,
            refusal["detail"].as_str().ok_or_else(invalid)?,
        ));
    }
    let report = result
        .get("report")
        .ok_or_else(|| private_error("private report is absent"))?;
    let last = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(invalid)?;
    if report.as_object().is_none_or(|object| object.len() != 2)
        || !valid_identity(&report["report_identity"])
        || report["report_identity"]["uid"] != super::recorded_loop_uid(record)?
        || !valid_fields(&report["run_report"], last)
    {
        return Err(private_error(
            "private report shape or round binding differs",
        ));
    }
    Ok(report.clone())
}

pub(super) fn valid_identity(identity: &Value) -> bool {
    const KEYS: [&str; 8] = [
        "device",
        "inode",
        "uid",
        "bytes",
        "modified_seconds",
        "modified_nanoseconds",
        "changed_seconds",
        "changed_nanoseconds",
    ];
    identity.as_object().is_some_and(|object| {
        object.len() == KEYS.len()
            && KEYS
                .iter()
                .all(|key| object.get(*key).is_some_and(Value::is_number))
    }) && ["device", "inode", "uid", "bytes"]
        .iter()
        .all(|key| identity[*key].as_u64().is_some())
        && identity["uid"]
            .as_u64()
            .is_some_and(|n| u32::try_from(n).is_ok())
        && identity["bytes"].as_u64().is_some_and(|n| n <= 4096)
        && ["modified_seconds", "changed_seconds"]
            .iter()
            .all(|key| identity[*key].as_i64().is_some())
        && ["modified_nanoseconds", "changed_nanoseconds"]
            .iter()
            .all(|key| identity[*key].as_u64().is_some_and(|n| n < 1_000_000_000))
}

fn valid_fields(fields: &Value, last: &Value) -> bool {
    fields.as_object().is_some_and(|fields| {
        fields.iter().all(|(key, value)| {
            !key.is_empty() && value.as_str().is_some_and(|value| !value.is_empty())
        })
    }) && fields["lane"] == last["step"]
        && fields["dir"] == last["driver_dir"]
        && fields["exit"]
            .as_str()
            .and_then(|s| s.parse::<i32>().ok())
            .is_some()
        && fields["verdict"].as_str().is_some_and(|s| !s.is_empty())
}

pub(super) fn read_bound(
    runs: &OwnedFd,
    root: &Path,
    record: &Value,
    loop_uid: u32,
) -> Result<Value, LaneError> {
    let last = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(invalid)?;
    let directory = Path::new(last["driver_dir"].as_str().ok_or_else(invalid)?);
    let run = record["run"].as_str().ok_or_else(invalid)?;
    if !directory.starts_with(root.join(run)) || directory == root.join(run) {
        return Err(invalid());
    }
    let held = pin_directory(runs, root, directory, loop_uid)?;
    read_directory(&held, directory, last, loop_uid)
}

fn pin_directory(
    root_fd: &OwnedFd,
    root: &Path,
    directory: &Path,
    loop_uid: u32,
) -> Result<OwnedFd, LaneError> {
    let relative = directory.strip_prefix(root).map_err(|_| invalid())?;
    let mut held = nix::unistd::dup(root_fd).map_err(|error| read_error(&error.into()))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        held = openat2(
            &held,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| read_error(&error.into()))?;
        let stat = fstat(&held).map_err(|error| read_error(&error.into()))?;
        if stat.st_uid != loop_uid || stat.st_mode & 0o7022 != 0 || stat.st_mode & 0o700 != 0o700 {
            return Err(invalid());
        }
    }
    Ok(held)
}

pub(super) fn open_report(directory: &OwnedFd, owner: u32) -> Result<File, LaneError> {
    let fd = openat2(
        directory,
        "run-report.txt",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| read_error(&error.into()))?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|error| read_error(&error))?;
    if !meta.is_file() || meta.len() > 4096 || meta.uid() != owner {
        return Err(invalid());
    }
    Ok(file)
}

pub(super) fn read_directory(
    held: &OwnedFd,
    directory: &Path,
    last: &Value,
    owner: u32,
) -> Result<Value, LaneError> {
    let file = open_report(held, owner)?;
    let before = file.metadata().map_err(|error| read_error(&error))?;
    let identity = |meta: &std::fs::Metadata| {
        json!({"device":meta.dev(),"inode":meta.ino(),"uid":meta.uid(),"bytes":meta.len(),
        "modified_seconds":meta.mtime(),"modified_nanoseconds":meta.mtime_nsec(),"changed_seconds":meta.ctime(),"changed_nanoseconds":meta.ctime_nsec()})
    };
    let mut body = String::new();
    (&file)
        .take(4097)
        .read_to_string(&mut body)
        .map_err(|error| read_error(&error))?;
    if body.len() > 4096
        || identity(&before) != identity(&file.metadata().map_err(|error| read_error(&error))?)
    {
        return Err(invalid());
    }
    let mut words = body.lines().last().unwrap_or_default().split_whitespace();
    if words.next() != Some("RUN-REPORT") {
        return Err(invalid());
    }
    let mut fields = serde_json::Map::new();
    for word in words {
        let (key, value) = word.split_once('=').ok_or_else(invalid)?;
        if key.is_empty() || value.is_empty() || fields.insert(key.into(), json!(value)).is_some() {
            return Err(invalid());
        }
    }
    let fields = Value::Object(fields);
    if !valid_fields(&fields, last) || fields["dir"] != json!(directory) {
        return Err(invalid());
    }
    Ok(json!({"run_report":fields,"report_identity":identity(&before)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics only if the report reader follows a replaced directory pathname.
    /// ´test:unit:private-driver-report-keeps-held-directory-after-replacement´
    #[test]
    fn private_driver_report_keeps_held_directory_after_replacement() {
        let root = tempfile::tempdir().expect("fixture");
        let directory = root.path().join("dispatch");
        std::fs::create_dir(&directory).expect("directory");
        let last = json!({"step":"dispatch","driver_dir":directory});
        std::fs::write(
            directory.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=dispatch exit=1 verdict=FAILED dir={}\n",
                directory.display()
            ),
        )
        .expect("original report");
        let held: OwnedFd = File::open(&directory).expect("held directory").into();
        let original =
            read_directory(&held, &directory, &last, Uid::effective().as_raw()).expect("original");
        std::fs::rename(&directory, root.path().join("retained")).expect("move directory");
        std::fs::create_dir(&directory).expect("replacement directory");
        std::fs::write(directory.join("run-report.txt"), "not the original report")
            .expect("replacement");
        assert_eq!(
            read_directory(&held, &directory, &last, Uid::effective().as_raw())
                .expect("held report"),
            original
        );
    }
}
