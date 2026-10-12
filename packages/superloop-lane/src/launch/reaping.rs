//! Account a launch to a transient user service and measure its cgroup after exit.

use super::{lock_mailbox, publish_reservation, read_reservation, reservation_path};
use crate::error::LaneError;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::Uid;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ffi::{CStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SCOPE_PREFIX: &str = "superloop-lane-run-";
const START_LINE_PREFIX: &str = "superloop-run-start:";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
static INTERRUPTED_ONLY: AtomicBool = AtomicBool::new(false);

thread_local! {
    static CHILD_CGROUP: RefCell<Option<Arc<OwnedFd>>> = const { RefCell::new(None) };
}

fn service_unit(loop_name: &str) -> Result<String, LaneError> {
    if !crate::valid_run_name(loop_name) {
        return Err(LaneError::input("run-scope", "loop is not a plain word"));
    }
    Ok(format!("superloop-lane-vendor@{loop_name}.service"))
}

/// Read a user service's active state and invocation through the launch reader.
///
/// # Errors
///
/// Refuses an unavailable or malformed service-state response.
pub fn systemctl_show(unit: &str) -> Result<(String, String), LaneError> {
    crate::pinned::owner_executable(Path::new("/usr/bin/systemctl"), Uid::effective().as_raw())?;
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "--user",
            "show",
            "--property=ActiveState",
            "--property=InvocationID",
            unit,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| LaneError::operation("run-service", error.to_string()))?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(LaneError::operation(
            "run-service",
            format!("{unit}: status {}", output.status),
        ));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|error| LaneError::input("run-service", error.to_string()))?;
    let mut state = None;
    let mut invocation = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("ActiveState=") {
            state = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("InvocationID=") {
            invocation = Some(value.to_owned());
        }
    }
    Ok((
        state.ok_or_else(|| LaneError::input("run-service", "ActiveState is absent"))?,
        invocation.ok_or_else(|| LaneError::input("run-service", "InvocationID is absent"))?,
    ))
}

pub(super) fn require_proxy_invocation_with(
    loop_name: &str,
    mut show: impl FnMut(&str) -> Result<(String, String), LaneError>,
) -> Result<(String, String), LaneError> {
    let unit = service_unit(loop_name)?;
    let (state, invocation) = show(&unit)?;
    if state != "active" || invocation.is_empty() {
        return Err(LaneError::input(
            "proxy-service-death",
            format!("{unit} has no active invocation"),
        ));
    }
    Ok((unit, invocation))
}

fn observing_scope(owner_home: &Path, args: &[String]) -> Result<bool, LaneError> {
    if args.first().is_none_or(|command| command != "launch") {
        return Ok(false);
    }
    let request = super::LaunchRequest::parse(&args[1..])?;
    if request.round.is_none() {
        return Ok(request.observe);
    }
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    let settings =
        crate::settings::Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, &request.loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("run-scope-record", "runs root is absent from settings"))?;
    let saved = read_reservation(&reservation_path(root, &request.run))?
        .ok_or_else(|| LaneError::input("round-record", "reservation is absent"))?;
    Ok(saved["plan"]["vendor_mode"].is_string())
}

/// Run the same outer launch probe as main before it starts a transient scope.
/// An absent mailbox lock is an absent recovery candidate, never a created file.
///
/// # Errors
///
/// Refuses a dead enforcing proxy before the runs root is changed.
pub fn scope_preflight_with(
    owner_home: &Path,
    args: &[String],
    mut show: impl FnMut(&str) -> Result<(String, String), LaneError>,
) -> Result<bool, LaneError> {
    let request = super::LaunchRequest::parse(&args[1..])?;
    let recovering = recovery_record(
        owner_home,
        &request.loop_name,
        &request.run,
        request.round.as_deref(),
    )?;
    if !recovering && !observing_scope(owner_home, args)? {
        require_proxy_invocation_with(&request.loop_name, &mut show)?;
    }
    Ok(recovering)
}

fn cgroup_path() -> Result<String, LaneError> {
    let proc_root = open_root(Path::new("/proc"))?;
    let pid = PathBuf::from(std::process::id().to_string());
    let process = open_cgroup(&proc_root, &pid)?
        .ok_or_else(|| LaneError::input("run-scope", "launcher proc directory is absent"))?;
    let body = read_control(&process, "cgroup")?;
    if body.len() > 4096 {
        return Err(LaneError::input("run-scope", "cgroup identity is too long"));
    }
    let mut paths = body.lines().filter_map(|line| line.strip_prefix("0::/"));
    let path = paths
        .next()
        .ok_or_else(|| LaneError::input("run-scope", "cgroup v2 identity is absent"))?;
    if paths.next().is_some() {
        return Err(LaneError::input(
            "run-scope",
            "cgroup v2 identity is repeated",
        ));
    }
    Ok(format!("/{path}"))
}

/// Read the service and cgroup that own this launcher before recording either identity.
///
/// # Errors
///
/// Refuses an unscoped process or an inactive proxy service.
#[allow(unsafe_code)]
pub fn current_scope(loop_name: &str) -> Result<Value, LaneError> {
    let unit = std::env::var("SUPERLOOP_RUN_SCOPE_UNIT")
        .map_err(|_| LaneError::input("run-scope", "transient run unit is absent"))?;
    if !unit.starts_with(SCOPE_PREFIX)
        || !unit.ends_with(".service")
        || !unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(LaneError::input(
            "run-scope",
            "transient run unit is invalid",
        ));
    }
    let cgroup = cgroup_path()?;
    if Path::new(&cgroup)
        .file_name()
        .and_then(|part| part.to_str())
        != Some(unit.as_str())
    {
        return Err(LaneError::input(
            "run-scope",
            "launcher is outside its named unit",
        ));
    }
    let proxy = if std::env::var("SUPERLOOP_SCOPE_OBSERVING").ok().as_deref() == Some("1") {
        (Value::Null, Value::Null)
    } else {
        let proxy_unit = service_unit(loop_name)?;
        let (state, invocation) = systemctl_show(&proxy_unit)?;
        if state != "active" || invocation.is_empty() {
            return Err(LaneError::input(
                "proxy-service-death",
                format!("{proxy_unit} is {state} without an active invocation"),
            ));
        }
        let expected_invocation = std::env::var("SUPERLOOP_EXPECTED_PROXY_INVOCATION")
            .map_err(|_| LaneError::input("run-scope", "expected proxy invocation is absent"))?;
        if invocation != expected_invocation {
            return Err(LaneError::input(
                "proxy-service-death",
                "proxy invocation changed before launch",
            ));
        }
        (json!(proxy_unit), json!(invocation))
    };
    let service = relative_cgroup(&cgroup)?;
    let root = open_root(Path::new(CGROUP_ROOT))?;
    require_cgroup2(&root)?;
    let work = prepare_work_cgroup(&root, service, Uid::effective().as_raw())?;
    let (device, inode) = directory_identity(&work)?;
    CHILD_CGROUP.with(|slot| *slot.borrow_mut() = Some(Arc::new(work)));
    Ok(
        json!({"unit":unit,"cgroup":format!("{cgroup}/work"),"device":device,"inode":inode,"proxy_unit":proxy.0,"proxy_invocation":proxy.1}),
    )
}

#[allow(unsafe_code)]
fn prepare_work_cgroup(
    root: &OwnedFd,
    service: &Path,
    owner_uid: u32,
) -> Result<OwnedFd, LaneError> {
    let parent = open_cgroup(root, service)?
        .ok_or_else(|| LaneError::input("run-cgroup", "service cgroup is absent"))?;
    let name = c"work";
    // SAFETY: the name is static and the descriptor pins the service cgroup.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if created != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(LaneError::operation(
            "run-cgroup",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let work = openat2(
        &parent,
        Path::new("work"),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    let stat =
        fstat(&work).map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    if !work_owner_matches(&stat, owner_uid) {
        return Err(LaneError::input(
            "run-cgroup",
            "work cgroup has another owner or type",
        ));
    }
    let control = openat2(
        &work,
        Path::new("cgroup.kill"),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("run-cgroup", format!("cgroup.kill: {error}")))?;
    check_regular(&control, "cgroup.kill")?;
    drop(control);
    Ok(work)
}

fn work_owner_matches(stat: &libc::stat, owner_uid: u32) -> bool {
    SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR
        && stat.st_uid == owner_uid
}

/// Move a child into the recorded delegated cgroup before it executes.
///
/// # Errors
///
/// Refuses an inaccessible process controller.
#[allow(unsafe_code)]
pub fn attach_command(command: &mut Command) -> Result<(), LaneError> {
    let directory = CHILD_CGROUP.with(|slot| slot.borrow().clone());
    let Some(directory) = directory else {
        return Ok(());
    };
    let procs = openat2(
        directory.as_ref(),
        Path::new("cgroup.procs"),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("run-cgroup", format!("cgroup.procs: {error}")))?;
    check_regular(&procs, "cgroup.procs")?;
    // SAFETY: pre_exec uses only the async-signal-safe write syscall and a held descriptor.
    unsafe {
        command.pre_exec(move || {
            let byte = b'0';
            let written = libc::write(procs.as_raw_fd(), (&raw const byte).cast(), 1);
            if written == 1 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(())
}

/// Execute a changing launch or rotation in a service whose cgroup is reaped on exit.
///
/// # Errors
///
/// Refuses an invalid loop name, unavailable service manager, or failed service start.
pub fn run_in_scope(args: &[String]) -> Result<i32, LaneError> {
    let loop_name = args
        .get(1)
        .ok_or_else(|| LaneError::input("run-scope", "loop is absent"))?;
    let home = crate::caller_home()?;
    let proxy = if observing_scope(&home, args)? {
        None
    } else {
        Some(require_proxy_invocation_with(loop_name, systemctl_show)?)
    };
    let unit = format!(
        "{SCOPE_PREFIX}{}.service",
        super::checkpoint::random_token()?
    );
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("run-scope", error.to_string()))?;
    crate::pinned::owner_executable(&exe, Uid::effective().as_raw())?;
    crate::pinned::owner_executable(Path::new("/usr/bin/systemd-run"), Uid::effective().as_raw())?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args(scope_arguments(
            &unit,
            proxy
                .as_ref()
                .map(|(unit, invocation)| (unit.as_str(), invocation.as_str())),
            &home,
            &exe,
            args,
            |key| std::env::var_os(key),
        ))
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|error| LaneError::operation("run-scope", error.to_string()))?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| LaneError::operation("run-scope", "transient stdout is absent"))?;
    let started = relay_scope_output(&mut output, &unit, &mut io::stdout().lock());
    let status = child
        .wait()
        .map_err(|error| LaneError::operation("run-scope", error.to_string()))?;
    scope_status(status, started?)
}

fn scope_arguments(
    unit: &str,
    proxy: Option<(&str, &str)>,
    home: &Path,
    exe: &Path,
    args: &[String],
    mut environment: impl FnMut(&str) -> Option<OsString>,
) -> Vec<OsString> {
    let mut words = [
        "--user".into(),
        "--quiet".into(),
        "--wait".into(),
        "--pipe".into(),
        "--collect".into(),
        "--same-dir".into(),
        format!("--unit={unit}").into(),
        "--property=KillMode=control-group".into(),
        "--property=ExitType=main".into(),
        "--property=Delegate=yes".into(),
        format!("--setenv=SUPERLOOP_RUN_SCOPE_UNIT={unit}").into(),
        format!("--setenv=SUPERLOOP_SCOPE_START_MARKER={unit}").into(),
    ]
    .to_vec();
    if let Some((proxy_unit, proxy_invocation)) = proxy {
        words.push(format!("--property=BindsTo={proxy_unit}").into());
        words.push(format!("--property=After={proxy_unit}").into());
        words.push(
            format!("--setenv=SUPERLOOP_EXPECTED_PROXY_INVOCATION={proxy_invocation}").into(),
        );
    } else {
        words.push("--setenv=SUPERLOOP_SCOPE_OBSERVING=1".into());
    }
    let mut home_word = OsString::from("--setenv=HOME=");
    home_word.push(home.as_os_str());
    words.push(home_word);
    for key in [
        "ENTER_LOOP_REGISTRY",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "_CONTAINERS_USERNS_CONFIGURED",
        "_CONTAINERS_ROOTLESS_UID",
    ] {
        if let Some(value) = environment(key) {
            let mut option = OsString::from(format!("--setenv={key}="));
            option.push(value);
            words.push(option);
        }
    }
    words.push("--".into());
    words.push(exe.as_os_str().to_owned());
    words.extend(args.iter().map(|word| OsString::from(word.as_str())));
    words
}

/// Publish the first byte of the inner process before its command runs.
///
/// # Errors
///
/// Refuses a broken output stream before the inner command starts.
pub fn announce_scope_start() -> Result<(), LaneError> {
    if let (Some(unit), Some(marker)) = (
        std::env::var_os("SUPERLOOP_RUN_SCOPE_UNIT"),
        std::env::var_os("SUPERLOOP_SCOPE_START_MARKER"),
    ) && unit == marker
    {
        let mut output = io::stdout().lock();
        writeln!(output, "{START_LINE_PREFIX}{}", unit.to_string_lossy())
            .and_then(|()| output.flush())
            .map_err(|error| LaneError::operation("run-scope", error.to_string()))?;
    }
    Ok(())
}

fn relay_scope_output(
    source: &mut impl io::Read,
    unit: &str,
    sink: &mut impl io::Write,
) -> Result<bool, LaneError> {
    let expected = format!("{START_LINE_PREFIX}{unit}\n");
    let mut first = Vec::with_capacity(expected.len());
    while first.len() < 256 {
        let mut byte = [0];
        if source
            .read(&mut byte)
            .map_err(|error| LaneError::operation("run-scope", error.to_string()))?
            == 0
        {
            break;
        }
        first.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let started = first == expected.as_bytes();
    if !started {
        sink.write_all(&first)
            .map_err(|error| LaneError::operation("run-scope", error.to_string()))?;
    }
    io::copy(source, sink).map_err(|error| LaneError::operation("run-scope", error.to_string()))?;
    Ok(started)
}

fn scope_status(status: std::process::ExitStatus, started: bool) -> Result<i32, LaneError> {
    if !started {
        return Err(LaneError::operation(
            "run-scope",
            format!("transient service did not start the launch: {status}"),
        ));
    }
    Ok(status.code().unwrap_or(1))
}

fn relative_cgroup(path: &str) -> Result<&Path, LaneError> {
    let relative = Path::new(path)
        .strip_prefix("/")
        .map_err(|_| LaneError::input("run-scope-record", "cgroup path is not absolute"))?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(LaneError::input(
            "run-scope-record",
            "cgroup path is not plain",
        ));
    }
    Ok(relative)
}

fn open_root(path: &Path) -> Result<OwnedFd, LaneError> {
    let held = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    let stat =
        fstat(&held).map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return Err(LaneError::input("run-cgroup", "root is not a directory"));
    }
    Ok(held)
}

#[allow(unsafe_code)]
fn require_cgroup2(root: &OwnedFd) -> Result<(), LaneError> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes one initialized statfs value for the held descriptor.
    if unsafe { libc::fstatfs(root.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(LaneError::operation(
            "run-cgroup",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: fstatfs returned success and initialized the value.
    let info = unsafe { info.assume_init() };
    if info.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(LaneError::input("run-cgroup", "root is not cgroup v2"));
    }
    Ok(())
}

fn directory_identity(directory: &OwnedFd) -> Result<(u64, u64), LaneError> {
    let stat =
        fstat(directory).map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return Err(LaneError::input("run-cgroup", "scope is not a directory"));
    }
    Ok((stat.st_dev, stat.st_ino))
}

fn open_cgroup(root: &OwnedFd, relative: &Path) -> Result<Option<OwnedFd>, LaneError> {
    let mut held = nix::unistd::dup(root)
        .map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LaneError::input(
                "run-cgroup",
                "cgroup component is invalid",
            ));
        };
        held = match openat2(
            &held,
            Path::new(name),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(next) => next,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(LaneError::operation("run-cgroup", error.to_string())),
        };
        let stat =
            fstat(&held).map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Err(LaneError::input(
                "run-cgroup",
                "cgroup component is not a directory",
            ));
        }
    }
    Ok(Some(held))
}

fn read_control(directory: &OwnedFd, name: &str) -> Result<String, LaneError> {
    let descriptor = openat2(
        directory,
        Path::new(name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("run-cgroup", format!("{name}: {error}")))?;
    check_regular(&descriptor, name)?;
    let mut text = String::new();
    File::from(descriptor)
        .take(4097)
        .read_to_string(&mut text)
        .map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    if text.len() > 4096 {
        return Err(LaneError::input(
            "run-cgroup",
            format!("{name} exceeds 4096 bytes"),
        ));
    }
    Ok(text)
}

fn check_regular(descriptor: &OwnedFd, name: &str) -> Result<(), LaneError> {
    let stat =
        fstat(descriptor).map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(LaneError::input(
            "run-cgroup",
            format!("{name} is not a file"),
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn child_names(directory: &OwnedFd) -> Result<Vec<OsString>, LaneError> {
    let fresh = openat2(
        directory,
        Path::new("."),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
    if directory_identity(&fresh)? != directory_identity(directory)? {
        return Err(LaneError::input("run-cgroup", "directory identity changed"));
    }
    let raw = fresh.into_raw_fd();
    // SAFETY: fdopendir takes ownership of this independently opened directory descriptor.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: fdopendir did not take ownership when it returned null.
        unsafe { libc::close(raw) };
        return Err(LaneError::operation("run-cgroup", error.to_string()));
    }
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: the directory stream remains open and errno is thread local.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: readdir returns an entry valid until the next call on this stream.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(LaneError::operation("run-cgroup", error.to_string()))
            };
        }
        // SAFETY: readdir's d_name is a NUL terminated entry name.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= 4096 {
            break Err(LaneError::input("run-cgroup", "too many cgroup entries"));
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    };
    // SAFETY: the stream was opened by fdopendir and is closed exactly once.
    unsafe { libc::closedir(stream) };
    result?;
    Ok(names)
}

fn collect_pids(
    directory: &OwnedFd,
    depth: usize,
    pids: &mut BTreeSet<u32>,
) -> Result<(), LaneError> {
    if depth > 32 {
        return Err(LaneError::input("run-cgroup", "cgroup nesting exceeds 32"));
    }
    for line in read_control(directory, "cgroup.procs")?.lines() {
        let pid = line
            .parse::<u32>()
            .map_err(|_| LaneError::input("run-cgroup", "cgroup PID is invalid"))?;
        if pids.len() >= 4096 {
            return Err(LaneError::input("run-cgroup", "too many cgroup PIDs"));
        }
        pids.insert(pid);
    }
    for name in child_names(directory)? {
        let child = match openat2(
            directory,
            Path::new(&name),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(child) => child,
            Err(nix::errno::Errno::ENOTDIR | nix::errno::Errno::ENOENT) => continue,
            Err(error) => return Err(LaneError::operation("run-cgroup", error.to_string())),
        };
        let stat =
            fstat(&child).map_err(|error| LaneError::operation("run-cgroup", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Err(LaneError::input(
                "run-cgroup",
                "child cgroup is not a directory",
            ));
        }
        collect_pids(&child, depth + 1, pids)?;
    }
    Ok(())
}

fn process_command(pid: u32) -> String {
    let Ok(root) = open_root(Path::new("/proc")) else {
        return "unreadable".to_owned();
    };
    let relative = PathBuf::from(pid.to_string());
    open_cgroup(&root, &relative)
        .ok()
        .flatten()
        .and_then(|directory| read_control(&directory, "comm").ok())
        .map_or_else(
            || "unreadable".to_owned(),
            |command| command.trim_end().to_owned(),
        )
}

fn measure_directory(directory: &OwnedFd) -> Result<Value, LaneError> {
    let events = read_control(directory, "cgroup.events")?;
    let populated = events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .ok_or_else(|| LaneError::input("run-cgroup", "populated control is absent"))?;
    if populated != "0" && populated != "1" {
        return Err(LaneError::input(
            "run-cgroup",
            "populated control is invalid",
        ));
    }
    let mut pids = BTreeSet::new();
    collect_pids(directory, 0, &mut pids)?;
    Ok(json!({"state":"present","populated":populated == "1","pids":pids}))
}

fn measure_at(root: &OwnedFd, scope: &ScopeFields<'_>) -> Result<Value, LaneError> {
    let relative = relative_cgroup(scope.cgroup)?;
    let Some(directory) = open_cgroup(root, relative)? else {
        return Ok(json!({"state":"collected","populated":null,"pids":[]}));
    };
    verify_scope_identity(&directory, scope)?;
    measure_directory(&directory)
}

/// Measure the recorded work subtree before retiring a never-started preparation.
///
/// # Errors
/// Refuses an absent identity, changed scope, unreadable controller or populated subtree.
pub(super) fn retirement_scope(record: &Value) -> Result<Value, LaneError> {
    let scope = scope_fields(record)?;
    #[cfg(test)]
    let fixture = RETIREMENT_ROOT.with(|slot| slot.borrow().clone());
    #[cfg(not(test))]
    let fixture: Option<PathBuf> = None;
    let root = open_root(fixture.as_deref().unwrap_or_else(|| Path::new(CGROUP_ROOT)))?;
    if fixture.is_none() {
        require_cgroup2(&root)?;
    }
    let measured = measure_at(&root, &scope)?;
    if measured["populated"] == true
        || measured["pids"]
            .as_array()
            .is_none_or(|pids| !pids.is_empty())
    {
        return Err(LaneError::input(
            "retire-busy",
            format!("recorded run scope {} retains processes", scope.cgroup),
        ));
    }
    Ok(measured)
}

#[cfg(test)]
thread_local! {
    static RETIREMENT_ROOT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(super) struct RetirementScopeFixture {
    _root: tempfile::TempDir,
    pub path: PathBuf,
}

#[cfg(test)]
impl RetirementScopeFixture {
    pub fn new(record: &mut Value) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().expect("scope fixture");
        let relative = "/superloop-lane-run-retirement.service/work";
        let path = root.path().join(&relative[1..]);
        fs::create_dir_all(&path).expect("work subtree");
        fs::write(path.join("cgroup.events"), "populated 0\n").expect("events");
        fs::write(path.join("cgroup.procs"), "").expect("processes");
        let metadata = fs::metadata(&path).expect("scope identity");
        record["run_scope"] = json!({"unit":"superloop-lane-run-retirement.service","cgroup":relative,"device":metadata.dev(),"inode":metadata.ino(),"proxy_unit":"superloop-lane-vendor@alpha.service","proxy_invocation":"fixture"});
        RETIREMENT_ROOT.with(|slot| {
            assert!(slot.borrow().is_none(), "one scope fixture per thread");
            *slot.borrow_mut() = Some(root.path().to_owned());
        });
        Self { _root: root, path }
    }
}

#[cfg(test)]
impl Drop for RetirementScopeFixture {
    fn drop(&mut self) {
        RETIREMENT_ROOT.with(|slot| *slot.borrow_mut() = None);
    }
}

fn verify_scope_identity(directory: &OwnedFd, scope: &ScopeFields<'_>) -> Result<(), LaneError> {
    if directory_identity(directory)? != (scope.device, scope.inode) {
        return Err(LaneError::input(
            "run-scope-record",
            "work cgroup identity changed",
        ));
    }
    Ok(())
}

fn kill_directory(directory: &OwnedFd) -> Result<(), LaneError> {
    let descriptor = openat2(
        directory,
        Path::new("cgroup.kill"),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("run-reaping", format!("cgroup.kill: {error}")))?;
    check_regular(&descriptor, "cgroup.kill")?;
    File::from(descriptor)
        .write_all(b"1")
        .map_err(|error| LaneError::operation("run-reaping", error.to_string()))
}

fn reap_directory_with(
    directory: &OwnedFd,
    cgroup: &str,
    mut command: impl FnMut(u32) -> String,
    mut kill: impl FnMut(&OwnedFd) -> Result<(), LaneError>,
) -> Result<Value, LaneError> {
    let before = measure_directory(directory)?;
    let survivors = before["pids"]
        .as_array()
        .ok_or_else(|| LaneError::input("run-reaping", "PID list is absent"))?
        .iter()
        .filter_map(Value::as_u64)
        .map(|pid| {
            let pid = u32::try_from(pid)
                .map_err(|_| LaneError::input("run-reaping", "survivor PID is invalid"))?;
            Ok(json!({"pid":pid,"command":command(pid)}))
        })
        .collect::<Result<Vec<_>, LaneError>>()?;
    if before["populated"] == false && survivors.is_empty() {
        return Ok(
            json!({"state":"verified-empty","cgroup":cgroup,"before":before,"after":before,"survivors":[]}),
        );
    }
    if let Err(error) = kill(directory) {
        return Ok(
            json!({"state":"cleanup-failed","cgroup":cgroup,"before":before,"survivors":survivors,"error":error.line()}),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let after = measure_directory(directory)?;
        if after["populated"] == false && after["pids"].as_array().is_some_and(Vec::is_empty) {
            return Ok(
                json!({"state":"survivors-reaped","cgroup":cgroup,"before":before,"after":after,"survivors":survivors}),
            );
        }
        if Instant::now() >= deadline {
            return Ok(
                json!({"state":"cleanup-failed","cgroup":cgroup,"before":before,"after":after,"survivors":survivors,"error":format!("run-reaping: {cgroup} retains processes")}),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn reap_named(scope: &ScopeFields<'_>, allow_collected: bool) -> Result<Value, LaneError> {
    let root = open_root(Path::new(CGROUP_ROOT))?;
    require_cgroup2(&root)?;
    reap_named_at(
        &root,
        scope,
        allow_collected,
        process_command,
        kill_directory,
    )
}

fn reap_named_at(
    root: &OwnedFd,
    scope: &ScopeFields<'_>,
    allow_collected: bool,
    command: impl FnMut(u32) -> String,
    kill: impl FnMut(&OwnedFd) -> Result<(), LaneError>,
) -> Result<Value, LaneError> {
    let Some(directory) = open_cgroup(root, relative_cgroup(scope.cgroup)?)? else {
        if allow_collected {
            return Ok(json!({"state":"collected","cgroup":scope.cgroup}));
        }
        return Err(LaneError::input(
            "run-reaping",
            "live work cgroup is absent",
        ));
    };
    verify_scope_identity(&directory, scope)?;
    reap_directory_with(&directory, scope.cgroup, command, kill)
}

/// Reap child processes before a run can publish a settled phase.
///
/// # Errors
///
/// Refuses a missing work cgroup or an unproved empty subtree.
pub fn reap_scope(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    let directory = CHILD_CGROUP
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| LaneError::input("run-reaping", "held work cgroup is absent"))?;
    reap_scope_at(
        &directory,
        record,
        || payload_measure(record, owner_home),
        process_command,
        kill_directory,
    )
}

fn reap_scope_at(
    directory: &OwnedFd,
    record: &Value,
    payload: impl FnOnce() -> Result<Value, LaneError>,
    command: impl FnMut(u32) -> String,
    kill: impl FnMut(&OwnedFd) -> Result<(), LaneError>,
) -> Result<Value, LaneError> {
    let scope = scope_fields(record)?;
    verify_scope_identity(directory, &scope)?;
    let container_payload = payload()?;
    let mut report = reap_directory_with(directory, scope.cgroup, command, kill)?;
    report["container_payload"] = container_payload;
    Ok(report)
}

/// Measure an interrupted run through its pinned recorded scope before publication.
///
/// # Errors
///
/// Refuses an invalid scope identity or unreadable survivor evidence.
pub fn reap_interrupted_scope(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    let root = open_root(Path::new(CGROUP_ROOT))?;
    require_cgroup2(&root)?;
    reap_interrupted_at(
        &root,
        record,
        || payload_measure(record, owner_home),
        process_command,
        kill_directory,
    )
}

fn reap_interrupted_at(
    root: &OwnedFd,
    record: &Value,
    payload: impl FnOnce() -> Result<Value, LaneError>,
    command: impl FnMut(u32) -> String,
    kill: impl FnMut(&OwnedFd) -> Result<(), LaneError>,
) -> Result<Value, LaneError> {
    let scope = scope_fields(record)?;
    let container_payload = payload()?;
    let mut report = reap_named_at(root, &scope, true, command, kill)?;
    report["container_payload"] = container_payload;
    Ok(report)
}

fn payload_measure(record: &Value, owner_home: &Path) -> Result<Value, LaneError> {
    let program = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("run-reaping", "container program is absent"))?;
    let loop_name = record["loop"]
        .as_str()
        .ok_or_else(|| LaneError::input("run-reaping", "loop is absent"))?;
    let run = record["run"]
        .as_str()
        .ok_or_else(|| LaneError::input("run-reaping", "run is absent"))?;
    Ok(
        match super::container_absent_for_run(Path::new(program), owner_home, loop_name, run) {
            Ok(true) => json!({"state":"absent","by":"loop-and-run-label"}),
            Ok(false) => json!({"state":"present","by":"loop-and-run-label"}),
            Err(error) => {
                json!({"state":"unmeasured","by":"loop-and-run-label","error":error.line()})
            }
        },
    )
}

/// Refuse settlement when a survivor needed cleanup or verification was incomplete.
///
/// # Errors
///
/// Returns a named run-reaping refusal for every outcome other than an empty first measurement.
pub fn reaping_verdict(report: &Value) -> Result<(), LaneError> {
    if report["state"] == "verified-empty" && report["container_payload"]["state"] == "absent" {
        Ok(())
    } else {
        Err(LaneError::operation(
            "run-reaping",
            format!(
                "{}; survivors {}; container payload {}",
                report["state"], report["survivors"], report["container_payload"]["state"]
            ),
        ))
    }
}

/// Validate the recorded quiescence proof without claiming a successful prior exit.
///
/// # Errors
///
/// Refuses missing or mismatched scope, payload, or process absence measurements.
pub(super) fn recovery_verdict(record: &Value) -> Result<(), LaneError> {
    let scope = scope_fields(record)?;
    let proof = &record["reaping_recovery"];
    if proof["state"] != "collected"
        || proof["cgroup"] != scope.cgroup
        || proof["scope"] != record["run_scope"]
        || proof["presence"] != "all-absent"
        || proof["container_payload"]["state"] != "absent"
        || proof["container_payload"]["by"] != "loop-and-run-label"
    {
        return Err(LaneError::input(
            "run-reaping",
            "collected recovery proof is incomplete",
        ));
    }
    for (name, identity) in [
        ("launcher", super::launcher_identity(record)?),
        ("driver", super::driver_identity(record)?),
        ("helper", super::helper_identity(record)?),
        ("helper_parent", super::helper_parent_identity(record)?),
        ("observer", super::observer_identity(record)?),
    ] {
        if (name != "observer" && identity.is_none())
            || proof["identities"][name] != json!(identity)
        {
            return Err(LaneError::input(
                "run-reaping",
                format!("{name} recovery identity differs"),
            ));
        }
    }
    Ok(())
}

fn stop_unit(unit: &str) -> Result<(), LaneError> {
    crate::pinned::owner_executable(Path::new("/usr/bin/systemctl"), Uid::effective().as_raw())?;
    let output = Command::new("/usr/bin/systemctl")
        .args(["--user", "stop", unit])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| LaneError::operation("run-scope-stop", error.to_string()))?;
    if !output.status.success() {
        return Err(LaneError::operation(
            "run-scope-stop",
            format!("{unit}: status {}", output.status),
        ));
    }
    Ok(())
}

struct ScopeFields<'a> {
    unit: &'a str,
    cgroup: &'a str,
    proxy_unit: Option<&'a str>,
    invocation: Option<&'a str>,
    device: u64,
    inode: u64,
}

fn scope_fields(record: &Value) -> Result<ScopeFields<'_>, LaneError> {
    let scope = &record["run_scope"];
    let unit = scope["unit"]
        .as_str()
        .ok_or_else(|| LaneError::input("run-scope-record", "unit is absent"))?;
    let cgroup = scope["cgroup"]
        .as_str()
        .ok_or_else(|| LaneError::input("run-scope-record", "cgroup is absent"))?;
    let proxy_unit = scope["proxy_unit"].as_str();
    let invocation = scope["proxy_invocation"].as_str();
    let device = scope["device"]
        .as_u64()
        .ok_or_else(|| LaneError::input("run-scope-record", "cgroup device is absent"))?;
    let inode = scope["inode"]
        .as_u64()
        .ok_or_else(|| LaneError::input("run-scope-record", "cgroup inode is absent"))?;
    if !unit.starts_with(SCOPE_PREFIX)
        || !unit.ends_with(".service")
        || Path::new(cgroup).file_name().and_then(|name| name.to_str()) != Some("work")
        || Path::new(cgroup)
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(unit)
        || proxy_unit.is_some() != invocation.is_some()
        || (proxy_unit.is_none() && !record["plan"]["vendor_mode"].is_string())
        || invocation.is_some_and(str::is_empty)
        || device == 0
        || inode == 0
    {
        return Err(LaneError::input(
            "run-scope-record",
            "scope identity is invalid",
        ));
    }
    relative_cgroup(cgroup)?;
    Ok(ScopeFields {
        unit,
        cgroup,
        proxy_unit,
        invocation,
        device,
        inode,
    })
}

fn reconciliation_cause(
    record: &Value,
    proxy: Option<(&str, &str)>,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Option<&'static str>, LaneError> {
    let scope = scope_fields(record)?;
    if let Some((proxy_state, actual_invocation)) = proxy
        && (proxy_state != "active" || Some(actual_invocation) != scope.invocation)
    {
        return Ok(Some("proxy-service-death"));
    }
    if let Some(identity) = super::launcher_identity(record)? {
        match presence(identity.0, identity.1) {
            crate::container_helper::ProcessPresence::Absent => return Ok(Some("driver-death")),
            crate::container_helper::ProcessPresence::Present => {}
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "run-presence",
                    "launcher presence is uncertain",
                ));
            }
        }
    }
    Ok(None)
}

fn record_reconciliation(record: &mut Value, cause: &str, unit: &str, reaping: &Value) {
    let never_started = super::retire::never_started_preparation(record)
        && matches!(
            reaping["state"].as_str(),
            Some("verified-empty" | "survivors-reaped" | "collected")
        );
    if record["phase"] == "preparing" && record["driver_entry_pid"].is_null() {
        record["pre_driver_failure"] = json!(cause);
        if record["driver_end"].is_null() {
            record["driver_end"] = json!({"state":"not-started"});
        }
        if record["helper_spawn_state"] == "not-started"
            && record["helper_end"].is_null()
            && [
                "helper_pid",
                "helper_start",
                "helper_parent_pid",
                "helper_parent_start",
            ]
            .iter()
            .all(|key| record[*key].is_null())
        {
            record["helper_end"] = json!({"state":"not-started"});
        }
    }
    record["phase"] = json!("failed");
    if let Some(round) = record["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        && matches!(
            round["phase"].as_str(),
            Some("running" | "awaiting-settlement")
        )
    {
        round["phase"] = json!("failed");
        round["settlement_error"] = json!(cause);
    }
    record["reconciliation"] =
        json!({"cause":cause,"scope":unit,"state":"verified","reaping":reaping});
    if never_started {
        record["reconciliation"]["retirement"] = json!("never-started-preparation");
    }
}

/// Leave launch's started and preparing reservations to its existing recovery readers.
#[must_use]
pub fn reconciles_before_command(command: &str) -> bool {
    command != "launch"
}

/// Identify a started run whose launcher is gone so its reply can be read without a new unit.
///
/// # Errors
///
/// Refuses an uncertain launcher identity or unsafe reservation input.
pub fn started_recovery_record(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<bool, LaneError> {
    recovery_record(owner_home, loop_name, run, None)
}

fn recovery_record(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: Option<&str>,
) -> Result<bool, LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    if !crate::valid_run_name(run) {
        return Err(LaneError::input(
            "run-scope-record",
            "run is not a plain word",
        ));
    }
    let loop_dir = owner_home.join(".config/loops").join(loop_name);
    let settings =
        crate::settings::Settings::read_beneath(&loop_dir.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("run-scope-record", "runs root is absent from settings"))?;
    let Some(_mailbox) = lock_existing_mailbox(root, run, Uid::effective().as_raw())? else {
        return Ok(false);
    };
    let Some(record) = read_reservation(&reservation_path(root, run))? else {
        return Ok(false);
    };
    if let Some(step) = step {
        if !super::rounds::interrupted_round(&record, step) {
            return Ok(false);
        }
        return recovery_launcher_absent(
            &record,
            loop_name,
            run,
            crate::container_helper::process_presence,
        );
    }
    started_recovery_state(
        &record,
        loop_name,
        run,
        crate::container_helper::process_presence,
    )
}

/// Probe an existing mailbox lock without creating residue for a fresh run.
fn lock_existing_mailbox(
    root: &Path,
    run: &str,
    owner_uid: u32,
) -> Result<Option<nix::fcntl::Flock<fs::File>>, LaneError> {
    let parent = crate::home::pin_parent(root, owner_uid)?;
    let name = format!(".letter-{run}.lock");
    let file = match nix::fcntl::openat2(
        &parent,
        name.as_str(),
        nix::fcntl::OpenHow::new()
            .flags(
                nix::fcntl::OFlag::O_RDWR
                    | nix::fcntl::OFlag::O_CLOEXEC
                    | nix::fcntl::OFlag::O_NOFOLLOW,
            )
            .resolve(
                nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                    | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
            ),
    ) {
        Ok(file) => fs::File::from(file),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(LaneError::input("letter-lock", format!("{name}: {error}"))),
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("letter-lock", error.to_string()))?;
    if !metadata.is_file()
        || std::os::unix::fs::MetadataExt::uid(&metadata) != owner_uid
        || std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o7777 != 0o600
    {
        return Err(LaneError::input(
            "letter-lock",
            "mailbox lock has foreign owner or mode",
        ));
    }
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map(Some)
        .map_err(|(_file, error)| LaneError::operation("letter-lock", error.to_string()))
}

fn started_recovery_state(
    record: &Value,
    loop_name: &str,
    run: &str,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<bool, LaneError> {
    if super::failed_driver_recovery(record) {
        if record["loop"] != loop_name || record["run"] != run {
            return Err(LaneError::input(
                "run-scope-record",
                "reservation names another run",
            ));
        }
        // The interrupted-settlement reader measures every identity and retains
        // its named refusals; this candidate must never start another scope.
        return Ok(true);
    }
    if record["phase"] != "started" {
        return Ok(false);
    }
    recovery_launcher_absent(record, loop_name, run, presence)
}

fn recovery_launcher_absent(
    record: &Value,
    loop_name: &str,
    run: &str,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<bool, LaneError> {
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "run-scope-record",
            "reservation names another run",
        ));
    }
    let (pid, start) = super::launcher_identity(record)?
        .ok_or_else(|| LaneError::input("run-presence", "started launcher identity is absent"))?;
    match presence(pid, start) {
        crate::container_helper::ProcessPresence::Absent => Ok(true),
        crate::container_helper::ProcessPresence::Present => Ok(false),
        crate::container_helper::ProcessPresence::Unknown => Err(LaneError::input(
            "run-presence",
            "launcher presence is uncertain",
        )),
    }
}

/// Restrict this process to the already started interrupted-settlement branch.
pub fn permit_interrupted_only() {
    INTERRUPTED_ONLY.store(true, Ordering::Release);
}

/// Refuse any new worker when this process was admitted only for recovery.
///
/// # Errors
///
/// Refuses a changed reservation before any worker starts.
pub fn ensure_scoped_new_launch() -> Result<(), LaneError> {
    if INTERRUPTED_ONLY.load(Ordering::Acquire)
        || std::env::var_os("SUPERLOOP_RUN_SCOPE_UNIT").is_none()
    {
        return Err(LaneError::input(
            "run-scope",
            "new launch is outside its named service",
        ));
    }
    Ok(())
}

trait ReconcileEffects {
    fn show(&mut self, unit: &str) -> Result<(String, String), LaneError>;
    fn presence(&mut self, pid: u32, start: u64) -> crate::container_helper::ProcessPresence;
    fn stop(&mut self, unit: &str) -> Result<(), LaneError>;
    fn reap(&mut self, record: &Value) -> Result<Value, LaneError>;
    fn payload(&mut self, record: &Value) -> Result<Value, LaneError>;
}

struct HostEffects<'a> {
    owner_home: &'a Path,
}

impl ReconcileEffects for HostEffects<'_> {
    fn show(&mut self, unit: &str) -> Result<(String, String), LaneError> {
        systemctl_show(unit)
    }

    fn presence(&mut self, pid: u32, start: u64) -> crate::container_helper::ProcessPresence {
        crate::container_helper::process_presence(pid, start)
    }

    fn stop(&mut self, unit: &str) -> Result<(), LaneError> {
        stop_unit(unit)
    }

    fn reap(&mut self, record: &Value) -> Result<Value, LaneError> {
        let scope = scope_fields(record)?;
        reap_named(&scope, true)
    }

    fn payload(&mut self, record: &Value) -> Result<Value, LaneError> {
        payload_measure(record, self.owner_home)
    }
}

fn reconcile_loaded_with(
    record: &mut Value,
    loop_name: &str,
    effects: &mut impl ReconcileEffects,
    mut publish: impl FnMut(&Value) -> Result<(), LaneError>,
) -> Result<(), LaneError> {
    if !matches!(record["phase"].as_str(), Some("preparing" | "started")) {
        return Ok(());
    }
    if record["loop"] != loop_name {
        return Err(LaneError::input(
            "run-scope-record",
            "reservation names another loop",
        ));
    }
    if record["run_scope"].is_null() && record["launcher_pid"].is_null() {
        return Ok(());
    }
    let scope = scope_fields(record)?;
    let unit = scope.unit.to_owned();
    let proxy = if let Some(proxy_unit) = scope.proxy_unit {
        if proxy_unit != service_unit(loop_name)? {
            return Err(LaneError::input(
                "run-scope-record",
                "proxy unit differs from loop",
            ));
        }
        let (state, invocation) = effects.show(proxy_unit)?;
        Some((state, invocation))
    } else {
        None
    };
    let mut launcher_presence = None;
    let cause = reconciliation_cause(
        record,
        proxy
            .as_ref()
            .map(|(state, invocation)| (state.as_str(), invocation.as_str())),
        |pid, start| {
            let observed = effects.presence(pid, start);
            launcher_presence = Some(observed);
            observed
        },
    )?;
    let Some(cause) = cause else {
        return Ok(());
    };
    if record["phase"] == "started" {
        let observed = if let Some(observed) = launcher_presence {
            observed
        } else if let Some((pid, start)) = super::launcher_identity(record)? {
            effects.presence(pid, start)
        } else {
            crate::container_helper::ProcessPresence::Unknown
        };
        match observed {
            crate::container_helper::ProcessPresence::Absent => {
                record["reconciliation"] =
                    json!({"cause":cause,"scope":unit,"state":"awaiting-interrupted-settlement"});
                publish(record)?;
                return Err(LaneError::input(
                    "interrupted-settlement",
                    "started run awaits launch recovery and reply readback",
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "run-presence",
                    "launcher presence is uncertain",
                ));
            }
            crate::container_helper::ProcessPresence::Present => {}
        }
    }
    let attempt = (|| -> Result<Value, LaneError> {
        let (scope_state, _) = effects.show(&unit)?;
        if scope_state != "inactive" && scope_state != "failed" {
            effects.stop(&unit)?;
        }
        let container_payload = effects.payload(record)?;
        let mut reaping = effects.reap(record)?;
        reaping["container_payload"] = container_payload;
        if !matches!(
            reaping["state"].as_str(),
            Some("verified-empty" | "survivors-reaped" | "collected")
        ) || reaping["container_payload"]["state"] != "absent"
        {
            return Err(LaneError::operation(
                "run-reaping",
                format!("reconciliation is unmeasured: {reaping}"),
            ));
        }
        Ok(reaping)
    })();
    match attempt {
        Ok(reaping) => {
            record_reconciliation(record, cause, &unit, &reaping);
            publish(record)
        }
        Err(error) => {
            record["reconciliation_attempt"] =
                json!({"cause":cause,"scope":unit,"state":"failed","error":error.line()});
            publish(record)?;
            Err(error)
        }
    }
}

/// Reconcile an abandoned live reservation before a changing command reads it.
///
/// # Errors
///
/// Refuses an unproved scope stop or an invalid live reservation.
pub fn reconcile_public(owner_home: &Path, loop_name: &str, run: &str) -> Result<(), LaneError> {
    reconcile_public_with(owner_home, loop_name, run, false)
}

/// Leave never-started preparations to retirement's locked validation and digest route.
///
/// # Errors
/// Refuses an unproved scope stop or an invalid live reservation.
pub fn reconcile_before_retirement(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<(), LaneError> {
    reconcile_public_with(owner_home, loop_name, run, true)
}

/// Preserve a finished driver's reply for the interrupted-settlement route.
pub(super) fn require_unsettled_driver(record: &Value) -> Result<(), LaneError> {
    match check_unsettled_driver(record)? {
        UnsettledDriverCheck::Absent => Ok(()),
        UnsettledDriverCheck::Unreadable(error) => Err(error),
    }
}

pub(super) enum UnsettledDriverCheck {
    Absent,
    Unreadable(LaneError),
}

/// Keep settlement guards immediate while allowing report read failures to rank with presence.
pub(super) fn check_unsettled_driver(record: &Value) -> Result<UnsettledDriverCheck, LaneError> {
    let refuse = || {
        LaneError::input(
            "interrupted-settlement",
            "started run awaits launch recovery and reply readback",
        )
    };
    if !record["driver_end"].is_null() || !record["reaping_recovery"].is_null() {
        return Err(refuse());
    }
    let driver = record["plan"]["driver_dir"].as_str().ok_or_else(refuse)?;
    let root = Path::new(driver).parent().ok_or_else(refuse)?;
    let run = record["run"].as_str().ok_or_else(refuse)?;
    let uncertain = |detail| LaneError::input("retire-uncertain", detail);
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| uncertain("rounds are not recorded".to_owned()))?;
    let (round, earlier) = rounds
        .split_last()
        .ok_or_else(|| uncertain("last round is not recorded".to_owned()))?;
    if !round["report"].is_null() || !round["driver_end"].is_null() {
        return Err(refuse());
    }
    let step = if earlier.is_empty() {
        None
    } else {
        let step = round["step"]
            .as_str()
            .ok_or_else(|| uncertain("last round step is not recorded".to_owned()))?;
        if earlier.iter().any(|prior| prior["step"] == step) {
            return Err(LaneError::input(
                "retire-report-ambiguous",
                "last round shares an earlier step name; recover and read back the round before retirement",
            ));
        }
        Some(step)
    };
    let present = (|| {
        let held_reports: OwnedFd = File::open(root)
            .map_err(|error| uncertain(error.to_string()))?
            .into();
        super::report::present(&held_reports, run, step, Uid::effective().as_raw())
            .map_err(|error| uncertain(error.to_string()))
    })();
    match present {
        Ok(true) => Err(refuse()),
        Ok(false) => Ok(UnsettledDriverCheck::Absent),
        Err(error) => Ok(UnsettledDriverCheck::Unreadable(error)),
    }
}

/// Compute the named transition without publishing any reservation or lock file.
pub(super) fn retirement_reconciliation(
    record: &Value,
    owner_home: &Path,
) -> Result<Value, LaneError> {
    let mut record = record.clone();
    if super::retire::proof::needed(&record) {
        return super::retire::proof::reconcile(&record, owner_home);
    }
    if record["phase"] == "started" {
        require_unsettled_driver(&record)?;
        let scope = retirement_scope(&record)?;
        let Some((pid, start)) = super::driver_identity(&record)? else {
            return Err(LaneError::input(
                "retire-uncertain",
                "driver has no recorded identity",
            ));
        };
        let identities = super::retire::checked_presence(
            owner_home,
            &record,
            false,
            crate::container_helper::process_presence,
        )?;
        let payload = payload_measure(&record, owner_home)?;
        if payload["state"] != "absent" {
            return Err(LaneError::input(
                if payload["state"] == "unmeasured" {
                    "retire-uncertain"
                } else {
                    "retire-busy"
                },
                payload.to_string(),
            ));
        }
        let state = if scope["state"] == "collected" {
            "collected"
        } else {
            "verified-empty"
        };
        record_reconciliation(
            &mut record,
            "driver-death",
            "",
            &json!({"state":state,"run_scope":scope,"identities":identities,"container_payload":payload}),
        );
        record["reconciliation"]["scope"] = record["run_scope"]["unit"].clone();
        record["reconciliation"]["retirement"] = json!("dead-driver");
        record["reconciliation"]["driver"] = json!({"pid":pid,"start":start,"presence":"absent"});
        return Ok(record);
    }
    if !super::retire::never_started_preparation(&record) {
        return Ok(record);
    }
    let Some((pid, start)) = super::launcher_identity(&record)? else {
        return Ok(record);
    };
    if crate::container_helper::process_presence(pid, start)
        != crate::container_helper::ProcessPresence::Absent
    {
        return Ok(record);
    }
    let identities = super::retire::checked_presence(
        owner_home,
        &record,
        false,
        crate::container_helper::process_presence,
    )?;
    let payload = payload_measure(&record, owner_home)?;
    if payload["state"] == "unmeasured" {
        return Err(LaneError::input("retire-uncertain", payload.to_string()));
    }
    if payload["state"] != "absent" {
        return Err(LaneError::input(
            "retire-busy",
            "labelled container is still present",
        ));
    }
    let unit = scope_fields(&record)?.unit.to_owned();
    let state = if identities["run_scope"]["state"] == "collected" {
        "collected"
    } else {
        "verified-empty"
    };
    record_reconciliation(
        &mut record,
        "driver-death",
        &unit,
        &json!({"state":state,"identities":identities,"container_payload":payload}),
    );
    Ok(record)
}

fn reconcile_public_with(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    retirement: bool,
) -> Result<(), LaneError> {
    if !crate::valid_run_name(run) {
        return Err(LaneError::input(
            "run-scope-record",
            "run is not a plain word",
        ));
    }
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let loop_dir = owner_home.join(".config/loops").join(loop_name);
    let settings =
        crate::settings::Settings::read_beneath(&loop_dir.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("run-scope-record", "runs root is absent from settings"))?;
    let reservation = reservation_path(root, run);
    let Some(record) = read_reservation(&reservation)? else {
        return Ok(());
    };
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "run-scope-record",
            "reservation names another run",
        ));
    }
    if retirement
        && (super::retire::never_started_preparation(&record)
            || record["phase"] == "started"
            || super::retire::proof::needed(&record))
    {
        return Ok(());
    }
    let _mailbox = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let Some(mut record) = read_reservation(&reservation)? else {
        return Ok(());
    };
    if retirement
        && (super::retire::never_started_preparation(&record)
            || record["phase"] == "started"
            || super::retire::proof::needed(&record))
    {
        return Ok(());
    }
    let mut effects = HostEffects { owner_home };
    reconcile_loaded_with(&mut record, loop_name, &mut effects, |saved| {
        publish_reservation(&reservation, saved)
    })
}

/// Measure whether a settled run's recorded cgroup still has processes.
///
/// # Errors
///
/// Refuses a missing scope identity or unreadable controller.
pub fn measure_case(
    record: &Value,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<Value, LaneError> {
    let root = open_root(Path::new(CGROUP_ROOT))?;
    require_cgroup2(&root)?;
    let report = measure_case_at(&root, record, loop_name, run, process_command, || {
        payload_measure(record, owner_home)
    })?;
    let program = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("reaping-record", "container program is absent"))?;
    let probes = super::probe::survivors(Path::new(program), owner_home, loop_name, run)?;
    Ok(with_probe_survivors(report, &probes))
}

fn with_probe_survivors(mut report: Value, probes: &super::probe::ProbeSurvivors) -> Value {
    if probes.total != 0 {
        report["verdict"] = json!("fail");
    }
    report["probe_survivors"] = json!(probes.rows);
    report["probe_survivor_total"] = json!(probes.total);
    report
}

fn measure_case_at(
    root: &OwnedFd,
    record: &Value,
    loop_name: &str,
    run: &str,
    mut command: impl FnMut(u32) -> String,
    mut payload: impl FnMut() -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    if record["phase"] != "settled" {
        return Err(LaneError::input("reaping-record", "run is not settled"));
    }
    let scope = scope_fields(record)?;
    if let Some(unit) = scope.proxy_unit
        && unit != service_unit(loop_name)?
    {
        return Err(LaneError::input(
            "reaping-record",
            "proxy unit differs from loop",
        ));
    }
    let measurement = measure_at(root, &scope)?;
    let survivors = measurement["pids"]
        .as_array()
        .ok_or_else(|| LaneError::input("reaping-record", "PID list is absent"))?
        .iter()
        .filter_map(Value::as_u64)
        .map(|pid| {
            let pid = u32::try_from(pid)
                .map_err(|_| LaneError::input("reaping-record", "survivor PID is invalid"))?;
            Ok(json!({"pid":pid,"command":command(pid)}))
        })
        .collect::<Result<Vec<_>, LaneError>>()?;
    let container_payload = payload()?;
    let prior = &record["reaping"];
    let collected = measurement["state"] == "collected";
    let prior_verified = (prior["state"] == "verified-empty"
        && prior["container_payload"]["state"] == "absent")
        || recovery_verdict(record).is_ok();
    let scope_clear = if collected {
        prior_verified
    } else {
        measurement["populated"] == false && survivors.is_empty()
    };
    let verdict = if container_payload["state"] == "unmeasured" || collected && !prior_verified {
        "unmeasured"
    } else if scope_clear && container_payload["state"] == "absent" {
        "pass"
    } else {
        "fail"
    };
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"reaping","scope":{"unit":scope.unit,"cgroup":scope.cgroup},"measurement":measurement,"settlement_reaping":prior,"reaping_recovery":record["reaping_recovery"],"container_payload":container_payload,"survivors":survivors,"verdict":verdict,"changed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:retirement-measures-scope-before-either-driver-death-transition´
    #[test]
    fn retirement_measures_scope_before_either_driver_death_transition() {
        for missing in [false, true] {
            let reports = tempfile::tempdir().expect("reports root");
            let mut record = json!({"phase":"started","run":"R","plan":{"driver_dir":reports.path().join("R")},"rounds":[{"step":"work-1","phase":"running"}]});
            if !missing {
                for role in [
                    "launcher",
                    "driver_entry",
                    "helper",
                    "helper_parent",
                    "observer",
                ] {
                    record[format!("{role}_pid")] = json!(u32::MAX);
                    record[format!("{role}_start")] = json!(1);
                }
            }
            let scope = RetirementScopeFixture::new(&mut record);
            fs::write(scope.path.join("cgroup.events"), "populated 1\n").expect("survivor");
            let error = retirement_reconciliation(&record, Path::new("/"))
                .expect_err("populated scope refuses both paths");
            assert_eq!(error.kind, "retire-busy");
            fs::write(scope.path.join("cgroup.events"), "unreadable\n").expect("unknown scope");
            assert!(retirement_reconciliation(&record, Path::new("/")).is_err());
        }
    }
    use std::fs;
    use std::os::unix::process::ExitStatusExt as _;
    use std::rc::Rc;

    /// ´test:unit:reaping-case-names-stale-probe-as-survivor´
    #[test]
    fn reaping_case_names_stale_probe_as_survivor() {
        let report = json!({"verdict":"pass","survivors":[]});
        let probe = json!({"label":"org.superloop.probe=mounts","identity":"alpha/R","container_name":"superloop-mount-probe-fixture","age":"2 minutes ago"});
        let measured = with_probe_survivors(
            report,
            &super::super::probe::ProbeSurvivors {
                rows: vec![probe.clone()],
                total: 65,
            },
        );
        assert_eq!(measured["verdict"], "fail");
        assert_eq!(measured["probe_survivors"], json!([probe]));
        assert_eq!(measured["probe_survivor_total"], 65);
    }

    struct FixtureEffects {
        events: Rc<RefCell<Vec<&'static str>>>,
        proxy_alive: bool,
        launcher_alive: bool,
        cleanup: Value,
    }

    impl ReconcileEffects for FixtureEffects {
        fn show(&mut self, unit: &str) -> Result<(String, String), LaneError> {
            if unit.starts_with("superloop-lane-vendor@") {
                self.events.borrow_mut().push("proxy-show");
                Ok(if self.proxy_alive {
                    ("active".into(), "fixture-invocation".into())
                } else {
                    ("inactive".into(), String::new())
                })
            } else {
                self.events.borrow_mut().push("scope-show");
                Ok(("active".into(), String::new()))
            }
        }

        fn presence(&mut self, _: u32, _: u64) -> crate::container_helper::ProcessPresence {
            self.events.borrow_mut().push("presence");
            if self.launcher_alive {
                crate::container_helper::ProcessPresence::Present
            } else {
                crate::container_helper::ProcessPresence::Absent
            }
        }

        fn stop(&mut self, _: &str) -> Result<(), LaneError> {
            self.events.borrow_mut().push("stop");
            Ok(())
        }

        fn reap(&mut self, _: &Value) -> Result<Value, LaneError> {
            self.events.borrow_mut().push("reap");
            Ok(self.cleanup.clone())
        }

        fn payload(&mut self, _: &Value) -> Result<Value, LaneError> {
            self.events.borrow_mut().push("payload");
            Ok(json!({"state":"absent"}))
        }
    }

    fn reservation() -> Value {
        json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":{"loop_uid":41001,"worker_uid":3000},"launcher_pid":4_000_000,"launcher_start":1,"driver_entry_pid":4_000_001,"driver_entry_start":1,"rounds":[{"step":"dispatch","phase":"running"}],"run_scope":{"unit":"superloop-lane-run-fixture.service","cgroup":"/superloop-lane-run-fixture.service/work","device":1,"inode":1,"proxy_unit":"superloop-lane-vendor@alpha.service","proxy_invocation":"fixture-invocation"}})
    }

    /// ´test:unit:scope-command-retains-proxy-pin-and-caller-environment´
    #[test]
    fn scope_command_retains_proxy_pin_and_caller_environment() {
        let words = scope_arguments(
            "superloop-lane-run-fixture.service",
            Some(("superloop-lane-vendor@alpha.service", "fixture-invocation")),
            Path::new("/home/owner"),
            Path::new("/usr/bin/superloop-lane"),
            &["launch".into(), "alpha".into(), "R".into()],
            |key| (key == "ENTER_LOOP_REGISTRY").then(|| OsString::from("/home/owner/registry")),
        );
        let text = words
            .iter()
            .map(|word| word.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(text.contains(&"--property=BindsTo=superloop-lane-vendor@alpha.service".into()));
        assert!(
            text.contains(
                &"--setenv=SUPERLOOP_EXPECTED_PROXY_INVOCATION=fixture-invocation".into()
            )
        );
        assert!(text.contains(&"--setenv=ENTER_LOOP_REGISTRY=/home/owner/registry".into()));
        assert!(text.contains(
            &"--setenv=SUPERLOOP_SCOPE_START_MARKER=superloop-lane-run-fixture.service".into()
        ));
        assert_eq!(
            &text[text.len() - 5..],
            &["--", "/usr/bin/superloop-lane", "launch", "alpha", "R"]
        );
        let observing = scope_arguments(
            "superloop-lane-run-observing.service",
            None,
            Path::new("/home/owner"),
            Path::new("/usr/bin/superloop-lane"),
            &[
                "launch".into(),
                "alpha".into(),
                "R".into(),
                "--observe".into(),
            ],
            |_| None,
        );
        let observing = observing
            .iter()
            .map(|word| word.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(observing.contains(&"--setenv=SUPERLOOP_SCOPE_OBSERVING=1".into()));
        assert!(!observing.iter().any(|word| word.contains("BindsTo=")
            || word.contains("After=")
            || word.contains("EXPECTED_PROXY_INVOCATION")));
        assert_eq!(
            scope_status(std::process::ExitStatus::from_raw(1 << 8), false)
                .expect_err("unit start refusal")
                .kind,
            "run-scope"
        );
        assert_eq!(
            scope_status(std::process::ExitStatus::from_raw(2 << 8), true)
                .expect("inner refusal is passed through"),
            2
        );
        let mut relayed = Vec::new();
        let started = relay_scope_output(
            &mut &b"superloop-run-start:superloop-lane-run-fixture.service\ninner output\n"[..],
            "superloop-lane-run-fixture.service",
            &mut relayed,
        )
        .expect("relay inner output");
        assert!(started);
        assert_eq!(relayed, b"inner output\n");
        let mut relayed = Vec::new();
        let started = relay_scope_output(
            &mut &b"unit start failed\n"[..],
            "superloop-lane-run-fixture.service",
            &mut relayed,
        )
        .expect("relay start failure");
        assert!(!started);
        assert_eq!(relayed, b"unit start failed\n");
    }

    /// ´test:unit:reconciliation-retains-contradictory-never-started-ends´
    #[test]
    fn reconciliation_retains_contradictory_never_started_ends() {
        for state in [
            "verified-empty",
            "survivors-reaped",
            "collected",
            "unmeasured",
        ] {
            let mut record = json!({"phase":"preparing","helper_spawn_state":"not-started"});
            record_reconciliation(
                &mut record,
                "driver-death",
                "fixture",
                &json!({"state":state}),
            );
            assert_eq!(
                record["reconciliation"]["retirement"] == "never-started-preparation",
                state != "unmeasured"
            );
        }
        for end in [Value::Null, json!({"state":"waited","status":9})] {
            let mut record = json!({"phase":"preparing","helper_spawn_state":"not-started",
                "driver_end":end,"helper_end":end});
            record_reconciliation(&mut record, "driver-death", "fixture", &json!({}));
            let expected = if end.is_null() {
                json!({"state":"not-started"})
            } else {
                end
            };
            assert_eq!(record["driver_end"], expected);
            assert_eq!(record["helper_end"], expected);
        }
    }

    /// ´test:unit:dead-service-and-driver-reconcile-fixture-reservations´
    #[test]
    fn dead_service_and_driver_reconcile_fixture_reservations() {
        let mut service = reservation();
        let cause = reconciliation_cause(&service, Some(("inactive", "")), |_, _| {
            crate::container_helper::ProcessPresence::Present
        })
        .expect("service observation")
        .expect("service death");
        record_reconciliation(
            &mut service,
            cause,
            "superloop-lane-run-fixture.service",
            &json!({"state":"collected"}),
        );
        assert_eq!(service["phase"], "failed");
        assert_eq!(service["rounds"][0]["phase"], "failed");
        assert_eq!(service["reconciliation"]["cause"], "proxy-service-death");

        let mut driver = reservation();
        let cause =
            reconciliation_cause(&driver, Some(("active", "fixture-invocation")), |pid, _| {
                if pid == 4_000_000 {
                    crate::container_helper::ProcessPresence::Absent
                } else {
                    crate::container_helper::ProcessPresence::Present
                }
            })
            .expect("driver observation")
            .expect("driver death");
        record_reconciliation(
            &mut driver,
            cause,
            "superloop-lane-run-fixture.service",
            &json!({"state":"collected"}),
        );
        assert_eq!(driver["phase"], "failed");
        assert_eq!(driver["reconciliation"]["cause"], "driver-death");
        assert_eq!(
            driver["reconciliation"]["scope"],
            "superloop-lane-run-fixture.service"
        );

        let mut settling = reservation();
        settling["driver_end"] = json!({"state":"ended"});
        let cause = reconciliation_cause(
            &settling,
            Some(("active", "fixture-invocation")),
            |pid, _| {
                if pid == 4_000_001 {
                    crate::container_helper::ProcessPresence::Absent
                } else {
                    crate::container_helper::ProcessPresence::Present
                }
            },
        )
        .expect("settling observation");
        assert_eq!(cause, None);

        let mut observing = reservation();
        observing["plan"]["vendor_mode"] = json!("observing");
        observing["run_scope"]["proxy_unit"] = Value::Null;
        observing["run_scope"]["proxy_invocation"] = Value::Null;
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut effects = FixtureEffects {
            events: Rc::clone(&events),
            proxy_alive: false,
            launcher_alive: false,
            cleanup: json!({"state":"collected"}),
        };
        assert_eq!(
            reconcile_loaded_with(&mut observing, "alpha", &mut effects, |_| Ok(()))
                .expect_err("absent observing launcher awaits settlement")
                .kind,
            "interrupted-settlement"
        );
        assert!(!events.borrow().contains(&"proxy-show"));

        let mut preparing = reservation();
        preparing["phase"] = json!("preparing");
        preparing["driver_entry_pid"] = Value::Null;
        record_reconciliation(
            &mut preparing,
            "driver-death",
            "superloop-lane-run-fixture.service",
            &json!({"state":"collected"}),
        );
        assert_eq!(preparing["pre_driver_failure"], "driver-death");
        assert_eq!(preparing["driver_end"]["state"], "not-started");
        assert!(!reconciles_before_command("launch"));
        assert!(reconciles_before_command("checkpoint"));
        assert!(
            started_recovery_state(&reservation(), "alpha", "R", |_, _| {
                crate::container_helper::ProcessPresence::Absent
            })
            .expect("started handoff")
        );
    }

    /// ´test:unit:reconciliation-lock-stops-reaps-and-publishes-in-order´
    #[test]
    fn reconciliation_lock_stops_reaps_and_publishes_in_order() {
        let root = tempfile::tempdir().expect("fixture runs root");
        let pinned = open_root(root.path()).expect("pinned fixture runs root");
        let _mailbox = super::super::lock_mailbox_at(&pinned, "R", Uid::effective().as_raw())
            .expect("fixture mailbox lock");
        let path = reservation_path(root.path(), "R");
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut effects = FixtureEffects {
            events: events.clone(),
            proxy_alive: false,
            launcher_alive: true,
            cleanup: json!({"state":"collected"}),
        };
        let mut record = reservation();
        let published = events.clone();
        reconcile_loaded_with(&mut record, "alpha", &mut effects, |saved| {
            published.borrow_mut().push("publish");
            publish_reservation(&path, saved)
        })
        .expect("reconcile dead service");
        assert_eq!(record["phase"], "failed");
        assert_eq!(record["reconciliation"]["reaping"]["state"], "collected");
        assert_eq!(
            read_reservation(&path)
                .expect("read fixture")
                .expect("saved fixture")["phase"],
            "failed"
        );
        assert_eq!(
            &*events.borrow(),
            &[
                "proxy-show",
                "presence",
                "scope-show",
                "stop",
                "payload",
                "reap",
                "publish"
            ]
        );

        let failed = Rc::new(RefCell::new(Vec::new()));
        let mut effects = FixtureEffects {
            events: failed.clone(),
            proxy_alive: false,
            launcher_alive: true,
            cleanup: json!({"state":"cleanup-failed","survivors":[{"pid":3001,"command":"fixture"}]}),
        };
        let mut record = reservation();
        let attempts = failed.clone();
        let error = reconcile_loaded_with(&mut record, "alpha", &mut effects, |saved| {
            attempts.borrow_mut().push("publish");
            publish_reservation(&path, saved)
        })
        .expect_err("cleanup failure refuses");
        assert_eq!(error.kind, "run-reaping");
        assert_eq!(record["phase"], "started");
        assert_eq!(record["reconciliation_attempt"]["state"], "failed");
        assert_eq!(
            &*failed.borrow(),
            &[
                "proxy-show",
                "presence",
                "scope-show",
                "stop",
                "payload",
                "reap",
                "publish"
            ]
        );

        let handoff = Rc::new(RefCell::new(Vec::new()));
        let mut effects = FixtureEffects {
            events: handoff.clone(),
            proxy_alive: true,
            launcher_alive: false,
            cleanup: json!({"state":"collected"}),
        };
        let mut record = reservation();
        let published = handoff.clone();
        let refusal = reconcile_loaded_with(&mut record, "alpha", &mut effects, |_| {
            published.borrow_mut().push("publish");
            Ok(())
        })
        .expect_err("started reply awaits launch recovery");
        assert_eq!(refusal.kind, "interrupted-settlement");
        assert_eq!(record["phase"], "started");
        assert_eq!(
            record["reconciliation"]["state"],
            "awaiting-interrupted-settlement"
        );
        assert_eq!(&*handoff.borrow(), &["proxy-show", "presence", "publish"]);
    }

    /// ´test:unit:reaping-case-reports-collected-recovery-proof´
    #[test]
    fn reaping_case_reports_collected_recovery_proof() {
        for worker in [3000, 3001] {
            let root = tempfile::tempdir().expect("fixture root");
            let pinned = open_root(root.path()).expect("pinned fixture root");
            let mut record = reservation();
            record["worker_uid"] = json!(worker);
            record["plan"]["worker_uid"] = json!(worker);
            record["phase"] = json!("settled");
            record["helper_pid"] = json!(4_000_002);
            record["helper_start"] = json!(1);
            record["helper_parent_pid"] = json!(4_000_003);
            record["helper_parent_start"] = json!(1);
            record["reaping_recovery"] = json!({"state":"collected","cgroup":record["run_scope"]["cgroup"],"scope":record["run_scope"],"presence":"all-absent","container_payload":{"state":"absent","by":"loop-and-run-label"},"identities":{"launcher":[4_000_000,1],"driver":[4_000_001,1],"helper":[4_000_002,1],"helper_parent":[4_000_003,1],"observer":null}});
            for (presence, verdict) in [("all-absent", "pass"), ("unknown", "unmeasured")] {
                record["reaping_recovery"]["presence"] = json!(presence);
                let report = measure_case_at(
                    &pinned,
                    &record,
                    "alpha",
                    "R",
                    |_| "fixture".into(),
                    || Ok(json!({"state":"absent"})),
                )
                .expect("exercise production measurement");
                assert_eq!(report["verdict"], verdict);
                assert_eq!(report["measurement"]["state"], "collected");
                assert!(report["settlement_reaping"].is_null());
                assert_eq!(report["reaping_recovery"], record["reaping_recovery"]);
            }
        }
    }

    /// ´test:unit:reaping-case-measures-fixture-cgroup-state´
    #[test]
    fn reaping_case_measures_fixture_cgroup_state() {
        let root = tempfile::tempdir().expect("fixture root");
        let scope = root.path().join("superloop-lane-run-fixture.service/work");
        fs::create_dir_all(&scope).expect("scope directory");
        fs::write(scope.join("cgroup.events"), "populated 0\n").expect("events");
        fs::write(scope.join("cgroup.procs"), "").expect("processes");
        let mut record = reservation();
        record["phase"] = json!("settled");
        let pinned = open_root(root.path()).expect("pinned fixture root");
        let directory = open_cgroup(
            &pinned,
            Path::new("superloop-lane-run-fixture.service/work"),
        )
        .expect("open fixture scope")
        .expect("scope exists");
        let (device, inode) = directory_identity(&directory).expect("scope identity");
        record["run_scope"]["device"] = json!(device);
        record["run_scope"]["inode"] = json!(inode);
        record["reaping"] =
            json!({"state":"verified-empty","container_payload":{"state":"absent"}});
        let empty = measure_case_at(
            &pinned,
            &record,
            "alpha",
            "R",
            |_| "fixture".into(),
            || Ok(json!({"state":"absent"})),
        )
        .expect("empty scope");
        assert_eq!(empty["verdict"], "pass");
        fs::write(scope.join("cgroup.events"), "populated 1\n").expect("events");
        let nested = scope.join("nested");
        fs::create_dir(&nested).expect("nested cgroup");
        fs::write(nested.join("cgroup.procs"), "3000\n").expect("nested processes");
        let live = measure_case_at(
            &pinned,
            &record,
            "alpha",
            "R",
            |_| "fixture".into(),
            || Ok(json!({"state":"absent"})),
        )
        .expect("live scope");
        assert_eq!(live["verdict"], "fail");
        assert_eq!(live["survivors"], json!([{"pid":3000,"command":"fixture"}]));
        fs::write(scope.join("cgroup.events"), "populated 0\n").expect("inconsistent events");
        let inconsistent = measure_case_at(
            &pinned,
            &record,
            "alpha",
            "R",
            |_| "fixture".into(),
            || Ok(json!({"state":"absent"})),
        )
        .expect("inconsistent scope");
        assert_eq!(inconsistent["verdict"], "fail");
        fs::remove_dir_all(&scope).expect("collect fixture scope");
        let collected = measure_case_at(
            &pinned,
            &record,
            "alpha",
            "R",
            |_| "fixture".into(),
            || Ok(json!({"state":"absent"})),
        )
        .expect("collected scope");
        assert_eq!(collected["measurement"]["state"], "collected");
        assert_eq!(collected["verdict"], "pass");
        record["reaping"] = Value::Null;
        let unmeasured = measure_case_at(
            &pinned,
            &record,
            "alpha",
            "R",
            |_| "fixture".into(),
            || Ok(json!({"state":"absent"})),
        )
        .expect("missing settlement measurement");
        assert_eq!(unmeasured["verdict"], "unmeasured");
    }

    /// ´test:unit:survivor-before-cleanup-remains-a-named-reaping-refusal´
    #[test]
    fn survivor_before_cleanup_remains_a_named_reaping_refusal() {
        let root = tempfile::tempdir().expect("fixture root");
        let scope = root.path().join("superloop-lane-run-fixture.service/work");
        fs::create_dir_all(&scope).expect("scope directory");
        fs::write(scope.join("cgroup.events"), "populated 1\n").expect("events");
        fs::write(scope.join("cgroup.procs"), "3000\n").expect("processes");
        let pinned = open_root(root.path()).expect("pinned fixture root");
        let directory = open_cgroup(
            &pinned,
            Path::new("superloop-lane-run-fixture.service/work"),
        )
        .expect("open fixture scope")
        .expect("scope exists");
        let mut record = reservation();
        let (device, inode) = directory_identity(&directory).expect("scope identity");
        record["run_scope"]["device"] = json!(device);
        record["run_scope"]["inode"] = json!(inode);
        let report = reap_scope_at(
            &directory,
            &record,
            || Ok(json!({"state":"absent"})),
            |_| "fixture-command".into(),
            |_| {
                fs::write(scope.join("cgroup.events"), "populated 0\n")
                    .map_err(|error| LaneError::operation("fixture", error.to_string()))?;
                fs::write(scope.join("cgroup.procs"), "")
                    .map_err(|error| LaneError::operation("fixture", error.to_string()))
            },
        )
        .expect("reap fixture");
        assert_eq!(report["container_payload"]["state"], "absent");
        assert_eq!(report["state"], "survivors-reaped");
        assert_eq!(
            report["survivors"][0],
            json!({"pid":3000,"command":"fixture-command"})
        );
        assert_eq!(
            reaping_verdict(&report).expect_err("survivor refuses").kind,
            "run-reaping"
        );
    }

    /// ´test:unit:work-cgroup-owner-and-held-identity-refuse-substitution´
    #[test]
    fn work_cgroup_owner_and_held_identity_refuse_substitution() {
        let owner_uid = 41001;
        let worker_uid = 3000;
        let other_worker_uid = 3001;

        let root = tempfile::tempdir().expect("fixture root");
        let scope = root.path().join("superloop-lane-run-fixture.service/work");
        fs::create_dir_all(&scope).expect("scope directory");
        fs::write(scope.join("cgroup.events"), "populated 0\n").expect("events");
        fs::write(scope.join("cgroup.procs"), "").expect("processes");
        fs::write(scope.join("cgroup.kill"), "").expect("kill control");
        let pinned = open_root(root.path()).expect("pinned fixture root");
        let held = prepare_work_cgroup(
            &pinned,
            Path::new("superloop-lane-run-fixture.service"),
            Uid::effective().as_raw(),
        )
        .expect("prepare fixture work cgroup");
        let mut stat = fstat(&held).expect("work metadata");
        stat.st_uid = owner_uid;
        assert!(work_owner_matches(&stat, owner_uid));
        stat.st_uid = worker_uid;
        assert!(!work_owner_matches(&stat, owner_uid));
        stat.st_uid = other_worker_uid;
        assert!(!work_owner_matches(&stat, owner_uid));
        let mut record = reservation();
        let (device, inode) = directory_identity(&held).expect("scope identity");
        record["run_scope"]["device"] = json!(device);
        record["run_scope"]["inode"] = json!(inode);
        let fields = scope_fields(&record).expect("recorded scope");
        verify_scope_identity(&held, &fields).expect("held scope identity");
        let measured = reap_scope_at(
            &held,
            &record,
            || Ok(json!({"state":"absent"})),
            |_| "fixture-command".into(),
            |_| panic!("empty scope needs no kill"),
        )
        .expect("settlement through held descriptor");
        assert_eq!(measured["state"], "verified-empty");
        reaping_verdict(&measured).expect("empty fixture settles");
        let interrupted = reap_interrupted_at(
            &pinned,
            &record,
            || Ok(json!({"state":"absent"})),
            |_| "fixture-command".into(),
            |_| panic!("empty scope needs no kill"),
        )
        .expect("interrupted scope measurement");
        assert_eq!(interrupted["state"], "verified-empty");
        fs::rename(&scope, root.path().join("former-work")).expect("move scope");
        fs::create_dir(&scope).expect("replace scope");
        let refusal = measure_at(&pinned, &fields).expect_err("replacement refuses");
        assert_eq!(refusal.kind, "run-scope-record");
        let interrupted_refusal = reap_interrupted_at(
            &pinned,
            &record,
            || Ok(json!({"state":"absent"})),
            |_| "fixture-command".into(),
            |_| panic!("substituted scope needs no kill"),
        )
        .expect_err("substituted interrupted scope refuses");
        assert_eq!(interrupted_refusal.kind, "run-scope-record");
        fs::remove_dir(&scope).expect("collect replacement");
        let collected = reap_interrupted_at(
            &pinned,
            &record,
            || Ok(json!({"state":"absent"})),
            |_| "fixture-command".into(),
            |_| panic!("collected scope needs no kill"),
        )
        .expect("collected interrupted scope");
        assert_eq!(collected["state"], "collected");
        assert_eq!(
            measure_directory(&held).expect("held original")["populated"],
            false
        );
    }
}
