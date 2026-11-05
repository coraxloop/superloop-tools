use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::custody::bind_custody_entry;
use crate::driver_launch::validate_driver_launch;
use crate::ensure::{ensure_roots_entry, inspect_roots_entry};
use crate::planner::{
    BridgeKind, Custody, IoMode, bridge_command, custody_tier, driver_launch_plan, entry_plan,
    provision_plan,
};
use crate::runner::publication_error;
use crate::verify::{
    EnsureReport, RootAudit, account_uid, assemble_verify, cleanup_probe_plan, inspect_roots_plan,
    inspect_runs_root, registry_drift, verify_probe_plan,
};
use crate::{CommandSpec, LoopError, LoopRecord, Runner, load_registry, registry_path};

const USAGE: &str = "usage: superloop [--json] {enter <name> [--] <cmd> [args...]|driver-launch LOOP RUN --driver-bin PATH --run-dir DIR -- ARGS...|provision <name>|run-bridge gpg|ssh <name> [--] [args...]|verify <name>|show <name>}";
static NEXT_REPORT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ReportFile {
    pub(crate) path: PathBuf,
}

impl ReportFile {
    pub(crate) fn create_in(directory: &Path) -> Result<Self, LoopError> {
        for _attempt in 0..100 {
            let sequence = NEXT_REPORT.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                "superloop-ensure-{}-{sequence}",
                std::process::id()
            ));
            if !path.is_absolute() || path.to_str().is_none() {
                return Err(LoopError::runtime(format!(
                    "could not create report {}: path must be absolute UTF-8",
                    path.display()
                )));
            }
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                        let _removed = fs::remove_file(&path);
                        return Err(LoopError::runtime(format!(
                            "could not create report {}: {error}",
                            path.display()
                        )));
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(LoopError::runtime(format!(
                        "could not create report {}: {error}",
                        path.display()
                    )));
                }
            }
        }
        Err(LoopError::runtime(format!(
            "could not create report in {}: names exhausted",
            directory.display()
        )))
    }

    fn create() -> Result<Self, LoopError> {
        let directory =
            std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        Self::create_in(&directory)
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, LoopError> {
        fs::read(&self.path).map_err(|error| {
            LoopError::runtime(format!(
                "could not read report {}: {error}",
                self.path.display()
            ))
        })
    }
}

impl Drop for ReportFile {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Enter {
        name: String,
        command: Vec<String>,
    },
    DriverLaunch {
        name: String,
        run: String,
        driver_bin: PathBuf,
        run_dir: PathBuf,
        arguments: Vec<String>,
    },
    Provision {
        name: String,
    },
    Bridge {
        kind: BridgeKind,
        name: String,
        arguments: Vec<String>,
    },
    Verify {
        name: String,
    },
    Registry {
        name: String,
    },
}

impl Action {
    fn name(&self) -> &str {
        match self {
            Self::Enter { name, .. }
            | Self::DriverLaunch { name, .. }
            | Self::Provision { name }
            | Self::Bridge { name, .. }
            | Self::Verify { name }
            | Self::Registry { name } => name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub(crate) registry: PathBuf,
    pub(crate) caller_home: PathBuf,
    pub(crate) json: bool,
    pub(crate) action: Action,
}

fn strings<I, A>(arguments: I) -> Result<Vec<String>, LoopError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    arguments
        .into_iter()
        .map(|argument| {
            argument
                .into()
                .into_string()
                .map_err(|_argument| LoopError::refusal(USAGE))
        })
        .collect()
}

fn take_global_options(arguments: &mut Vec<String>) -> bool {
    let mut json = false;
    while arguments.first().is_some_and(|value| value == "--json") {
        json = true;
        arguments.remove(0);
    }
    json
}

pub(crate) fn caller_home(home: Option<&OsStr>) -> Result<PathBuf, LoopError> {
    home.and_then(OsStr::to_str)
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| LoopError::refusal("HOME must be a nonempty UTF-8 path"))
}

fn strip_separator(arguments: &mut Vec<String>) {
    if arguments.first().is_some_and(|argument| argument == "--") {
        arguments.remove(0);
    }
}

fn take_json_options(arguments: &mut Vec<String>, json: &mut bool) {
    while arguments
        .first()
        .is_some_and(|argument| argument == "--json")
    {
        *json = true;
        arguments.remove(0);
    }
}

/// Classify a bridge symlink before handling the entrypoint's own options.
///
/// A bridge forwards every remaining word, including a sole `--version`, to
/// its fixed command. Other executable names use the ordinary entry surface.
#[must_use]
pub fn argv0_bridge(argv0: &OsStr) -> Option<(String, BridgeKind)> {
    let name = Path::new(argv0).file_name()?.to_str()?;
    if let Some(loop_name) = name.strip_suffix("-gpg") {
        return Some((loop_name.to_owned(), BridgeKind::Gpg));
    }
    name.strip_suffix("-ssh")
        .map(|loop_name| (loop_name.to_owned(), BridgeKind::Ssh))
}

pub(crate) fn parse_invocation<I, A>(
    argv0: &OsStr,
    arguments: I,
    environmental_registry: Option<&OsStr>,
    caller_home: Option<&OsStr>,
) -> Result<Invocation, LoopError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let mut arguments = strings(arguments)?;
    let mut json = take_global_options(&mut arguments);
    let caller_home = self::caller_home(caller_home)?;
    let registry = registry_path(environmental_registry, &caller_home);
    if let Some((name, kind)) = argv0_bridge(argv0) {
        strip_separator(&mut arguments);
        return Ok(Invocation {
            registry,
            caller_home,
            json,
            action: Action::Bridge {
                kind,
                name,
                arguments,
            },
        });
    }
    if arguments.is_empty() {
        return Err(LoopError::refusal(USAGE));
    }
    let mode = arguments.remove(0);
    let action = match mode.as_str() {
        "enter" => {
            take_json_options(&mut arguments, &mut json);
            if arguments.is_empty() {
                return Err(LoopError::refusal(USAGE));
            }
            let name = arguments.remove(0);
            take_json_options(&mut arguments, &mut json);
            strip_separator(&mut arguments);
            if arguments.is_empty() {
                return Err(LoopError::refusal(format!("no command for loop: {name}")));
            }
            Action::Enter {
                name,
                command: arguments,
            }
        }
        "driver-launch" => parse_driver_launch(&arguments)?,
        "provision" => parse_provision(&mut arguments, &mut json)?,
        "run-bridge" => {
            take_json_options(&mut arguments, &mut json);
            if arguments.len() < 2 {
                return Err(LoopError::refusal(USAGE));
            }
            let kind = match arguments.remove(0).as_str() {
                "gpg" => BridgeKind::Gpg,
                "ssh" => BridgeKind::Ssh,
                _ => return Err(LoopError::refusal(USAGE)),
            };
            take_json_options(&mut arguments, &mut json);
            if arguments.is_empty() {
                return Err(LoopError::refusal(USAGE));
            }
            let name = arguments.remove(0);
            take_json_options(&mut arguments, &mut json);
            strip_separator(&mut arguments);
            Action::Bridge {
                kind,
                name,
                arguments,
            }
        }
        "verify" => {
            take_json_options(&mut arguments, &mut json);
            if arguments.is_empty() {
                return Err(LoopError::refusal(USAGE));
            }
            let name = arguments.remove(0);
            take_json_options(&mut arguments, &mut json);
            if !arguments.is_empty() {
                return Err(LoopError::refusal(USAGE));
            }
            Action::Verify { name }
        }
        "show" => parse_registry_action(&mut arguments, json)?,
        _ => return Err(LoopError::refusal(USAGE)),
    };
    Ok(Invocation {
        registry,
        caller_home,
        json,
        action,
    })
}

fn parse_driver_launch(arguments: &[String]) -> Result<Action, LoopError> {
    if arguments.len() < 6 || arguments[2] != "--driver-bin" || arguments[4] != "--run-dir" {
        return Err(LoopError::refusal(
            "usage: superloop driver-launch LOOP RUN --driver-bin PATH --run-dir DIR -- ARGS...",
        ));
    }
    if arguments.get(6).is_none_or(|word| word != "--") {
        return Err(LoopError::refusal(
            "driver-launch requires -- before arguments",
        ));
    }
    if arguments.len() == 7 {
        return Err(LoopError::refusal(
            "driver-launch requires a nonempty argument vector",
        ));
    }
    Ok(Action::DriverLaunch {
        name: arguments[0].clone(),
        run: arguments[1].clone(),
        driver_bin: PathBuf::from(&arguments[3]),
        run_dir: PathBuf::from(&arguments[5]),
        arguments: arguments[7..].to_vec(),
    })
}

fn parse_provision(arguments: &mut Vec<String>, json: &mut bool) -> Result<Action, LoopError> {
    take_json_options(arguments, json);
    if arguments.is_empty() {
        return Err(LoopError::refusal(USAGE));
    }
    let name = arguments.remove(0);
    take_json_options(arguments, json);
    if !arguments.is_empty() {
        return Err(LoopError::refusal(USAGE));
    }
    Ok(Action::Provision { name })
}

fn parse_registry_action(arguments: &mut Vec<String>, json: bool) -> Result<Action, LoopError> {
    if json || arguments.len() != 1 {
        return Err(LoopError::refusal(USAGE));
    }
    Ok(Action::Registry {
        name: arguments.remove(0),
    })
}

fn executable_on_path(name: &str, path: Option<&OsStr>) -> bool {
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path).any(|directory| {
        fs::metadata(directory.join(name))
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    })
}

pub(crate) fn resolve_podman(
    override_value: Option<OsString>,
    path: Option<&OsStr>,
) -> Result<Vec<String>, LoopError> {
    if let Some(value) = override_value.filter(|value| !value.is_empty()) {
        return value
            .into_string()
            .map(|program| vec![program])
            .map_err(|_value| LoopError::refusal("ENTER_LOOP_PODMAN must be UTF-8"));
    }
    if executable_on_path("podman", path) {
        return Ok(vec![String::from("podman")]);
    }
    if executable_on_path("flatpak-spawn", path) {
        return Ok(vec![
            String::from("flatpak-spawn"),
            String::from("--host"),
            String::from("podman"),
        ]);
    }
    Err(LoopError::refusal("podman not found"))
}

pub(crate) const MAX_SYSTEM_PROGRAM_LINKS: usize = 16;
const NO_SYSTEM_CONTAINER_ROUTE: &str = "verify has no system container route; looked for podman and flatpak-spawn in /usr/bin, /bin, /usr/local/bin";

pub(crate) fn trusted_system_component(
    uid: u32,
    mode: u32,
    owner: u32,
    link: bool,
) -> Result<(), String> {
    if uid != owner {
        return Err(format!("owner uid {uid} differs from required uid {owner}"));
    }
    // A symlink's 0777 mode conveys no write access; its holding directory does.
    if !link && mode & 0o022 != 0 {
        return Err(format!(
            "mode {:04o} permits group or other writes",
            mode & 0o7777
        ));
    }
    Ok(())
}

fn system_path_parts(path: &Path, link_target: bool) -> VecDeque<(OsString, bool)> {
    path.components()
        .filter_map(|part| match part {
            std::path::Component::Normal(word) => Some((word.to_os_string(), link_target)),
            std::path::Component::ParentDir => Some((OsString::from(".."), link_target)),
            _ => None,
        })
        .collect()
}

/// Inspect every path component without following a link at the point it is checked.
pub(crate) fn inspect_system_program_from(
    candidate: &Path,
    root: &Path,
    owner: u32,
) -> Result<bool, String> {
    let relative = candidate
        .strip_prefix(root)
        .map_err(|_error| String::from("candidate escapes the trusted root"))?;
    let root_meta =
        fs::symlink_metadata(root).map_err(|error| format!("{}: {error}", root.display()))?;
    if !root_meta.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    trusted_system_component(root_meta.uid(), root_meta.mode(), owner, false)
        .map_err(|reason| format!("{}: {reason}", root.display()))?;
    let mut resolved = root.to_path_buf();
    let mut pending = system_path_parts(relative, false);
    let mut links = 0;
    while let Some((part, link_target)) = pending.pop_front() {
        if part == OsStr::new("..") {
            if resolved == root {
                return Err(String::from("link target escapes the trusted root"));
            }
            resolved.pop();
            continue;
        }
        let path = resolved.join(part);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound && link_target => {
                return Err(format!("dangling link: {} is absent", path.display()));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if meta.file_type().is_symlink() {
            trusted_system_component(meta.uid(), meta.mode(), owner, true)
                .map_err(|reason| format!("{}: {reason}", path.display()))?;
            links += 1;
            if links > MAX_SYSTEM_PROGRAM_LINKS {
                return Err(format!(
                    "link chain exceeds {MAX_SYSTEM_PROGRAM_LINKS} links"
                ));
            }
            let target =
                fs::read_link(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let target = if target.is_absolute() {
                resolved = root.to_path_buf();
                target
                    .strip_prefix(root)
                    .map_err(|_error| String::from("link target escapes the trusted root"))?
            } else {
                &target
            };
            let mut replacement = system_path_parts(target, true);
            replacement.append(&mut pending);
            pending = replacement;
        } else if pending.is_empty() {
            if !meta.is_file() {
                return Err(format!("{} is not a regular file", path.display()));
            }
            trusted_system_component(meta.uid(), meta.mode(), owner, false)
                .map_err(|reason| format!("{}: {reason}", path.display()))?;
            if meta.mode() & 0o111 == 0 {
                return Err(format!("{} is not executable", path.display()));
            }
            return Ok(true);
        } else {
            if !meta.is_dir() {
                return Err(format!("{} is not a directory", path.display()));
            }
            trusted_system_component(meta.uid(), meta.mode(), owner, false)
                .map_err(|reason| format!("{}: {reason}", path.display()))?;
            resolved = path;
        }
    }
    Err(String::from("candidate is not a regular executable file"))
}

pub(crate) fn resolve_verify_podman_in(
    directories: &[&Path],
    mut available: impl FnMut(&Path) -> Result<bool, String>,
) -> Result<Vec<String>, LoopError> {
    let mut refused = Vec::new();
    for directory in directories {
        let candidate = directory.join("podman");
        match available(&candidate) {
            Ok(true) => return Ok(vec![candidate.to_string_lossy().into_owned()]),
            Ok(false) => {}
            Err(reason) => refused.push(format!("{}: {reason}", candidate.display())),
        }
    }
    for directory in directories {
        let candidate = directory.join("flatpak-spawn");
        match available(&candidate) {
            Ok(true) => {
                return Ok(vec![
                    candidate.to_string_lossy().into_owned(),
                    String::from("--host"),
                    String::from("/usr/bin/podman"),
                ]);
            }
            Ok(false) => {}
            Err(reason) => refused.push(format!("{}: {reason}", candidate.display())),
        }
    }
    if refused.is_empty() {
        Err(LoopError::runtime(NO_SYSTEM_CONTAINER_ROUTE))
    } else {
        Err(LoopError::runtime(format!(
            "{NO_SYSTEM_CONTAINER_ROUTE}\nrefused system candidates: {}",
            refused.join("; ")
        )))
    }
}

pub(crate) fn resolve_verify_podman_with(
    available: impl FnMut(&Path) -> Result<bool, String>,
) -> Result<Vec<String>, LoopError> {
    resolve_verify_podman_in(
        &[
            Path::new("/usr/bin"),
            Path::new("/bin"),
            Path::new("/usr/local/bin"),
        ],
        available,
    )
}

pub(crate) fn resolve_verify_podman() -> Result<Vec<String>, LoopError> {
    resolve_verify_podman_with(|candidate| {
        inspect_system_program_from(candidate, Path::new("/"), 0)
    })
}

fn normalize_status(status: i32) -> u8 {
    u8::try_from(if status < 0 { 128 - status } else { status }).unwrap_or(1)
}

pub(crate) fn entry_custody(
    caller_home: &Path,
    record: &LoopRecord,
    executable: &Path,
) -> Result<Option<Custody>, LoopError> {
    let tier = custody_tier(caller_home, &record.name);
    match fs::symlink_metadata(&tier) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LoopError::refusal(format!(
            "could not inspect custody tier: {tier_display}: {error}",
            tier_display = tier.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Ok(Some(Custody {
            tier,
            executable: executable.to_path_buf(),
        })),
        Ok(_) => Err(LoopError::refusal(format!(
            "custody tier is not a directory: {}",
            tier.display()
        ))),
    }
}

fn entry_executable() -> Result<PathBuf, LoopError> {
    std::env::current_exe()
        .ok()
        .filter(|path| path.to_str().is_some())
        .ok_or_else(|| LoopError::refusal("could not resolve the entry executable"))
}

fn run_one<R: Runner>(runner: &mut R, command: &CommandSpec) -> Result<(i32, Duration), LoopError> {
    runner
        .run(command)
        .map(|output| (output.status, output.wall))
        .map_err(|failure| LoopError::runtime(format!("{}: {}", command.label, failure.detail)))
}

fn run_entry<R: Runner>(
    runner: &mut R,
    plan: &crate::EntryPlan,
) -> Result<(i32, Duration), LoopError> {
    runner
        .run_entry(plan)
        .map(|output| (output.status, output.wall))
        .map_err(|failure| {
            LoopError::runtime(format!("{}: {}", plan.command.label, failure.detail))
        })
}

fn report<W: io::Write>(
    output: &mut W,
    json: bool,
    record: &LoopRecord,
    status: i32,
    wall: Duration,
    counts: &EnsureReport,
) -> Result<(), LoopError> {
    let signal = status
        .checked_neg()
        .and_then(|number| nix::sys::signal::Signal::try_from(number).ok());
    let status = normalize_status(status);
    let ending = signal.map_or_else(String::new, |signal| {
        if json {
            format!(",\"signal\":\"{signal}\"")
        } else {
            format!(" signal={signal}")
        }
    });
    if json {
        writeln!(
            output,
            "{{\"loop\":\"{}\",\"uid\":{},\"exit\":{},\"wall_seconds\":{:.1},\"created\":{},\"corrected\":{}{ending}}}",
            record.name,
            record.uid,
            status,
            wall.as_secs_f64(),
            counts.created.len(),
            counts.corrected.len()
        )
    } else {
        writeln!(
            output,
            "ENTER-REPORT loop={} uid={} exit={} wall={:.1}s created={} corrected={}{ending}",
            record.name,
            record.uid,
            status,
            wall.as_secs_f64(),
            counts.created.len(),
            counts.corrected.len()
        )
    }
    .map_err(|error| publication_error(&error))
}

fn report_verify<W: io::Write>(
    output: &mut W,
    json: bool,
    record: &LoopRecord,
    status: u8,
    wall: Duration,
    audit: Option<&RootAudit>,
) -> Result<(), LoopError> {
    let would_create = audit.map_or_else(
        || String::from("null"),
        |audit| audit.would_create.to_string(),
    );
    let would_correct = audit.map_or_else(
        || String::from("null"),
        |audit| audit.would_correct.to_string(),
    );
    if json {
        writeln!(
            output,
            "{{\"loop\":\"{}\",\"uid\":{},\"exit\":{},\"wall_seconds\":{:.1},\"would_create\":{},\"would_correct\":{}}}",
            record.name,
            record.uid,
            status,
            wall.as_secs_f64(),
            would_create,
            would_correct
        )
    } else {
        writeln!(
            output,
            "ENTER-REPORT loop={} uid={} exit={} wall={:.1}s would_create={} would_correct={}",
            record.name,
            record.uid,
            status,
            wall.as_secs_f64(),
            would_create,
            would_correct
        )
    }
    .map_err(|error| publication_error(&error))
}

/// Plan ordinary entry, keeping private dispatch ahead of the settings wrapper.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ordinary_entry_plan(
    record: &LoopRecord,
    runs_root: Option<&Path>,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    custody: Option<&Custody>,
    podman: &[String],
    command: &[String],
    locale: (&str, &str),
) -> Result<crate::EntryPlan, LoopError> {
    let settings_path = crate::driver_launch::settings_path(caller_home, &record.name);
    let configured_command;
    let command = if settings_path.exists() {
        let settings =
            crate::workers_settings::read_execution_settings(caller_home, record, runs_root, None)?;
        let root = crate::workers_settings::read_runs_root(caller_home, record, runs_root)?;
        configured_command = std::iter::once(String::from("/usr/bin/env"))
            .chain(settings.environment())
            .chain(std::iter::once(format!(
                "LANE_RUNS_ROOT={}",
                root.display()
            )))
            .chain(command.iter().cloned())
            .collect::<Vec<_>>();
        &configured_command
    } else {
        command
    };
    Ok(entry_plan(
        record,
        executable,
        caller_home,
        report_path,
        custody,
        podman,
        command,
        locale.0,
        locale.1,
        IoMode::Inherit,
    ))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn execute<R: Runner, W: io::Write>(
    action: &Action,
    record: &LoopRecord,
    runs_root: Option<&Path>,
    executable: &Path,
    caller_home: &Path,
    report_file: &ReportFile,
    custody: Option<&Custody>,
    podman: &[String],
    locale: (&str, &str),
    registration: &(Option<u32>, Option<Vec<String>>),
    runner: &mut R,
    output: &mut W,
) -> Result<(i32, Duration, Vec<u8>, Option<String>), LoopError> {
    let (term, lang) = locale;
    match action {
        Action::Enter { command, .. } => {
            let plan = ordinary_entry_plan(
                record,
                runs_root,
                executable,
                caller_home,
                &report_file.path,
                custody,
                podman,
                command,
                locale,
            )?;
            let (status, wall) = run_entry(runner, &plan)?;
            Ok((status, wall, report_file.read()?, None))
        }
        Action::DriverLaunch {
            driver_bin,
            run_dir,
            arguments,
            ..
        } => {
            let root = runs_root.ok_or_else(|| {
                LoopError::refusal(
                    "runs_root_required: runs_root is absent from the registry grant",
                )
            })?;
            let settings = crate::workers_settings::read_execution_settings(
                caller_home,
                record,
                runs_root,
                Some("codex"),
            )?;
            if Path::new(&settings.driver_argv[0]) != driver_bin {
                return Err(LoopError::refusal(
                    "driver_argv differs from the validated driver path",
                ));
            }
            let command = [
                String::from("/usr/bin/env"),
                String::from("LANE_BOXED_RUNTIME=1"),
                format!("LANE_RUNS_ROOT={}", root.display()),
                format!("LANE_RUN_DIR={}", run_dir.display()),
            ]
            .into_iter()
            .chain(settings.environment())
            .chain(settings.driver_argv)
            .chain(arguments.iter().cloned())
            .collect::<Vec<_>>();
            let plan = driver_launch_plan(
                record,
                executable,
                caller_home,
                &report_file.path,
                custody,
                podman,
                &command,
                term,
                lang,
            );
            let (status, wall) = run_entry(runner, &plan)?;
            Ok((status, wall, report_file.read()?, None))
        }
        Action::Bridge {
            kind, arguments, ..
        } => {
            let command = bridge_command(*kind, arguments);
            let plan = entry_plan(
                record,
                executable,
                caller_home,
                &report_file.path,
                custody,
                podman,
                &command,
                term,
                lang,
                IoMode::Inherit,
            );
            let (status, wall) = run_entry(runner, &plan)?;
            Ok((status, wall, report_file.read()?, None))
        }
        Action::Provision { .. } => {
            let plan = provision_plan(record, executable, caller_home, &report_file.path, podman);
            let (status, wall) = run_one(runner, &plan.command)?;
            Ok((status, wall, report_file.read()?, None))
        }
        Action::Verify { .. } => {
            let started = Instant::now();
            let inspection = runner
                .run(&inspect_roots_plan(
                    record,
                    executable,
                    caller_home,
                    &report_file.path,
                    podman,
                ))
                .map_err(|failure| {
                    LoopError::runtime(format!("verify roots: {}", failure.detail))
                })?;
            let report_bytes = report_file.read()?;
            let audit = RootAudit::parse(&report_bytes).map_err(|failure| {
                LoopError::runtime(format!(
                    "report {}: {}",
                    report_file.path.display(),
                    failure.message()
                ))
            })?;
            let inspected_status = normalize_status(inspection.status);
            if inspected_status != audit.status {
                return Err(LoopError::runtime(
                    "verify root status differs from its report",
                ));
            }
            if audit.status != 0 {
                let reason = if audit.status == 4 {
                    "the ensure step would refuse a home entry"
                } else {
                    "the ensure step would create or correct a home entry"
                };
                writeln!(
                    output,
                    "{}",
                    audit.skipped_json(reason, registration.0, registration.1.as_deref())
                )
                .map_err(|error| publication_error(&error))?;
                return Ok((
                    i32::from(audit.status),
                    started.elapsed(),
                    report_bytes,
                    None,
                ));
            }
            let runs_root = inspect_runs_root(record, runs_root)?;
            let entry = runner
                .run_entry(&verify_probe_plan(
                    record,
                    executable,
                    caller_home,
                    &report_file.path,
                    custody,
                    podman,
                    term,
                    lang,
                ))
                .map_err(|failure| {
                    LoopError::runtime(format!("verify entry: {}", failure.detail))
                })?;
            let cleanup = runner
                .run(&cleanup_probe_plan(record, podman))
                .map_err(|failure| {
                    LoopError::runtime(format!("verify cleanup: {}", failure.detail))
                })?;
            let entry_status = normalize_status(entry.status);
            let cleanup_status = normalize_status(cleanup.status);
            if entry_status != 0 {
                return Err(LoopError::runtime(format!(
                    "verify entry exited with status {}",
                    entry.status
                )));
            }
            if cleanup_status != 0 {
                return Err(LoopError::runtime(format!(
                    "verify cleanup exited with status {}",
                    cleanup.status
                )));
            }
            let mut verification = assemble_verify(
                &entry.stdout,
                &cleanup.stdout,
                &report_bytes,
                registration.0,
                registration.1.clone(),
            )
            .map_err(|failure| {
                LoopError::runtime(format!(
                    "report {}: {}",
                    report_file.path.display(),
                    failure.message()
                ))
            })?;
            verification.runs_root = runs_root;
            if let Some(account_uid) = verification.account_uid
                && account_uid != record.uid
            {
                return Ok((
                    1,
                    started.elapsed(),
                    report_bytes,
                    Some(format!(
                        "account uid {account_uid} differs from registry uid {} for loop {}",
                        record.uid, record.name
                    )),
                ));
            }
            writeln!(output, "{}", verification.to_json())
                .map_err(|error| publication_error(&error))?;
            Ok((0, started.elapsed(), report_bytes, None))
        }
        Action::Registry { .. } => {
            writeln!(
                output,
                "{}",
                record.to_registry_json_with_runs_root(runs_root)
            )
            .map_err(|error| publication_error(&error))?;
            Ok((0, Duration::ZERO, Vec::new(), None))
        }
    }
}

fn one_line_error(message: &str) -> String {
    let mut escaped = String::new();
    for letter in message.chars() {
        if letter.is_control() {
            escaped.extend(letter.escape_default());
        } else {
            escaped.push(letter);
        }
    }
    escaped
}

fn publish_error<W: io::Write>(error: &mut W, failure: &LoopError) -> u8 {
    if writeln!(error, "{}", one_line_error(failure.message())).is_err() {
        1
    } else {
        failure.status()
    }
}

/// Extract the lane program and pass its private install request through unchanged.
///
/// The lane's private parser owns the request shape and descriptor validation.
///
/// # Errors
///
/// Returns an error when the dispatch word, required paths, or absolute paths are absent.
pub fn lane_install_private_dispatch(
    arguments: &[OsString],
) -> Result<(PathBuf, Vec<OsString>), LoopError> {
    if arguments
        .first()
        .is_none_or(|word| word != "lane-install-private")
    {
        return Err(LoopError::runtime("lane-install-private command is absent"));
    }
    let (Some(owner_home), Some(lane_word)) = (arguments.get(2), arguments.get(3)) else {
        return Err(LoopError::runtime(
            "lane-install-private needs an owner home and lane program",
        ));
    };
    let lane_bin = PathBuf::from(lane_word.as_os_str());
    if !lane_bin.is_absolute() || !Path::new(owner_home).is_absolute() {
        return Err(LoopError::runtime(
            "lane-install-private needs absolute paths",
        ));
    }
    let forwarded = arguments[1..3]
        .iter()
        .chain(arguments[4..].iter())
        .cloned()
        .collect();
    Ok((lane_bin, forwarded))
}

/// Helper words intercepted before ordinary grammar; every other word is a command.
pub(crate) const INTERCEPTED_WORDS: [&str; 12] = [
    "_supervise-command",
    "bind-custody",
    "_mail-worker-birth",
    "_mail-worker-state",
    "_mail-worker-pins",
    "_mail-provision",
    "_mail-configure",
    "_mail-journal",
    "_mail-group",
    "ensure-roots",
    "inspect-roots",
    "lane-install-private",
];

/// Run `superloop` with an injected external-command runner.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn enter_loop_entry<I, A, R, W, E>(
    argv0: &OsStr,
    arguments: I,
    runner: &mut R,
    output: &mut W,
    error: &mut E,
) -> u8
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
    R: Runner,
    W: io::Write,
    E: io::Write,
{
    let mut arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    let intercepted = arguments.first().and_then(|word| {
        INTERCEPTED_WORDS
            .iter()
            .position(|candidate| word == *candidate)
    });
    if intercepted == Some(0) {
        arguments.remove(0);
        let argv = match strings(arguments) {
            Ok(argv) => argv,
            Err(failure) => return publish_error(error, &failure),
        };
        if let Err(failure) = crate::runner::validate_watched(argv.first().map(String::as_str)) {
            return publish_error(error, &failure);
        }
        if !argv
            .get(1)
            .is_some_and(|path| Path::new(path).is_absolute())
        {
            return publish_error(
                error,
                &LoopError::refusal("relay-stop: missing or invalid stop report path"),
            );
        }
        // This relay runs as namespace root, before setpriv
        // drops credentials, so it can signal the entire private process group.
        return match runner.run(&CommandSpec::new(
            "_supervise-command",
            argv,
            IoMode::Inherit,
        )) {
            Ok(result) => normalize_status(result.status),
            Err(failure) => publish_error(error, &LoopError::runtime(failure.detail)),
        };
    }
    if intercepted == Some(1) {
        arguments.remove(0);
        return bind_custody_entry(arguments, error);
    }
    if matches!(intercepted, Some(2..=4)) {
        return crate::mail::worker_provision::entry(&arguments, error);
    }
    if matches!(intercepted, Some(5..=8)) {
        return crate::mail::provision::entry(&arguments, output, error);
    }
    if intercepted == Some(9) {
        arguments.remove(0);
        return ensure_roots_entry(arguments, error);
    }
    if intercepted == Some(10) {
        arguments.remove(0);
        return inspect_roots_entry(arguments, error);
    }
    if intercepted == Some(11) {
        let (lane_bin, forwarded) = match lane_install_private_dispatch(&arguments) {
            Ok(dispatch) => dispatch,
            Err(refusal) => return publish_error(error, &refusal),
        };
        let failure = Command::new(&lane_bin)
            .arg("_install-private")
            .args(&forwarded)
            .exec();
        return publish_error(
            error,
            &LoopError::runtime(format!(
                "lane-install-private could not run {}: {failure}",
                lane_bin.display()
            )),
        );
    }
    let caller_home = std::env::var_os("HOME");
    let registry_env = std::env::var_os("ENTER_LOOP_REGISTRY");
    let invocation = match parse_invocation(
        argv0,
        arguments,
        registry_env.as_deref(),
        caller_home.as_deref(),
    ) {
        Ok(invocation) => invocation,
        Err(failure) => return publish_error(error, &failure),
    };
    let registry = match load_registry(&invocation.registry) {
        Ok(registry) => registry,
        Err(failure) => return publish_error(error, &failure),
    };
    let record = match registry.row(invocation.action.name(), &invocation.caller_home) {
        Ok(record) => record,
        Err(failure) => return publish_error(error, &failure),
    };
    let runs_root = registry.runs_root(&record.name);
    let pinned_run = if let Action::DriverLaunch {
        run,
        driver_bin,
        run_dir,
        ..
    } = &invocation.action
    {
        match validate_driver_launch(
            &invocation.caller_home,
            &record,
            runs_root,
            run,
            driver_bin,
            run_dir,
        ) {
            Ok(pinned) => Some(pinned),
            Err(failure) => return publish_error(error, &failure),
        }
    } else {
        None
    };
    if matches!(invocation.action, Action::Registry { .. }) {
        return match writeln!(
            output,
            "{}",
            record.to_registry_json_with_runs_root(runs_root)
        ) {
            Ok(()) => 0,
            Err(failure) => publish_error(error, &publication_error(&failure)),
        };
    }
    let registration = if matches!(invocation.action, Action::Verify { .. }) {
        let account = match account_uid(&record, &invocation.caller_home) {
            Ok(account) => account,
            Err(failure) => return publish_error(error, &failure),
        };
        let drift = match registry_drift(&record, &invocation.caller_home) {
            Ok(drift) => drift,
            Err(failure) => return publish_error(error, &failure),
        };
        (account, drift)
    } else {
        (None, None)
    };
    let started = Instant::now();
    let executable = match entry_executable() {
        Ok(executable) => executable,
        Err(failure) => return publish_error(error, &failure),
    };
    let custody = if matches!(invocation.action, Action::Provision { .. }) {
        None
    } else {
        match entry_custody(&invocation.caller_home, &record, &executable) {
            Ok(custody) => custody,
            Err(failure) => return publish_error(error, &failure),
        }
    };
    let path = std::env::var_os("PATH");
    let podman = match if matches!(invocation.action, Action::Verify { .. }) {
        runner.verify_route()
    } else {
        resolve_podman(std::env::var_os("ENTER_LOOP_PODMAN"), path.as_deref())
    } {
        Ok(podman) => podman,
        Err(failure) => return publish_error(error, &failure),
    };
    let term = std::env::var("TERM").unwrap_or_else(|_error| String::from("xterm"));
    let lang = std::env::var("LANG").unwrap_or_else(|_error| String::from("C.UTF-8"));
    let report_file = match if matches!(invocation.action, Action::Verify { .. }) {
        ReportFile::create_in(Path::new("/tmp"))
    } else {
        ReportFile::create()
    } {
        Ok(report_file) => report_file,
        Err(failure) => return publish_error(error, &failure),
    };
    let _anchors = pinned_run
        .as_ref()
        .map(|pinned| (&pinned.root, &pinned.run));
    let result = execute(
        &invocation.action,
        &record,
        runs_root,
        &executable,
        &invocation.caller_home,
        &report_file,
        custody.as_ref(),
        &podman,
        (&term, &lang),
        &registration,
        runner,
        output,
    );
    drop(pinned_run);
    match result {
        Ok((status, wall, report_bytes, mismatch)) => {
            if let Some(message) = mismatch {
                return publish_error(error, &LoopError::runtime(message));
            }
            if matches!(invocation.action, Action::Verify { .. }) {
                let audit = match RootAudit::parse(&report_bytes) {
                    Ok(audit) => audit,
                    Err(failure) => return publish_error(error, &failure),
                };
                return if report_verify(
                    error,
                    invocation.json,
                    &record,
                    normalize_status(status),
                    wall,
                    Some(&audit),
                )
                .is_err()
                {
                    1
                } else {
                    normalize_status(status)
                };
            }
            let counts = match EnsureReport::parse(&report_bytes) {
                Ok(counts) => counts,
                Err(failure) => {
                    return publish_error(
                        error,
                        &LoopError::runtime(format!(
                            "report {}: {}",
                            report_file.path.display(),
                            failure.message()
                        )),
                    );
                }
            };
            if report(error, invocation.json, &record, status, wall, &counts).is_err() {
                1
            } else {
                normalize_status(status)
            }
        }
        Err(failure) => {
            let status = publish_error(error, &failure);
            if matches!(invocation.action, Action::Verify { .. }) {
                let audit = report_file
                    .read()
                    .ok()
                    .and_then(|bytes| RootAudit::parse(&bytes).ok());
                let _reported = report_verify(
                    error,
                    invocation.json,
                    &record,
                    status,
                    started.elapsed(),
                    audit.as_ref(),
                );
            } else {
                let _reported = report(
                    error,
                    invocation.json,
                    &record,
                    i32::from(status),
                    started.elapsed(),
                    &EnsureReport::default(),
                );
            }
            status
        }
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::publish_error;
    use crate::workers_settings::validate_workers_settings;
    use std::path::Path;

    /// ´claim:entry:entry-settings-refusals-escape-key-and-value-controls´
    /// ´test:unit:entry-settings-refusals-escape-key-and-value-controls´
    #[test]
    fn entry_settings_refusals_escape_key_and_value_controls() {
        for source in ["\"odd\\nkey\" = 1\n", "runs_root = \"/tmp/odd\\nvalue\"\n"] {
            let failure = validate_workers_settings(source, Path::new("/tmp/workers.toml"))
                .expect_err("invalid setting");
            let mut output = Vec::new();
            assert_eq!(publish_error(&mut output, &failure), 2);
            let text = String::from_utf8(output).expect("UTF-8 refusal");
            assert_eq!(text.lines().count(), 1);
            assert!(text.contains("\\n"));
        }
    }
}
