use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::settings::Settings;

#[path = "build_payload.rs"]
pub mod payload;

const MAX_COMMAND_OUTPUT: usize = 2_097_152;
const CHILD_READER_GRACE: Duration = Duration::from_secs(5);
pub(crate) const MAX_CODEX_BYTES: u64 = 536_870_912;
pub(crate) const CODEX_HOST_PATH: &str = "/usr/libexec/superloop/codex-code-mode-host";
const MAX_DATA_BYTES: u64 = 65_536;
const MAX_EXEC_HELP_BYTES: usize = 16_384;
pub(crate) const CODEX_EXEC_OPTIONS: [&str; 6] = [
    "--json",
    "--sandbox",
    "--add-dir",
    "--skip-git-repo-check",
    "-C",
    "-o",
];

fn exec_help_has_option(help: &str, option: &str) -> bool {
    help.lines().any(|line| {
        line.split_whitespace()
            .take(3)
            .any(|word| word.trim_end_matches(',') == option)
    })
}

fn checked_exec_help(help: &str) -> Result<(), LaneError> {
    if help.len() > MAX_EXEC_HELP_BYTES {
        return Err(LaneError::input(
            "codex-exec-help",
            "exec help exceeds 16384 bytes",
        ));
    }
    for option in CODEX_EXEC_OPTIONS {
        if !exec_help_has_option(help, option) {
            return Err(LaneError::input(
                "codex-exec-help",
                format!("pinned Codex exec does not advertise {option}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn check_exec_probe(report: &Value, runtime_argv: &Value) -> Result<(), LaneError> {
    let probe = &report["codex_exec_probe"];
    let help = probe["stdout"].as_str().ok_or_else(|| {
        LaneError::input(
            "codex-exec-help",
            "image-build.json has no Codex exec help probe; run build",
        )
    })?;
    if probe["argv"] != json!(["exec", "--help"])
        || probe["required_options"] != json!(CODEX_EXEC_OPTIONS)
        || probe["codex_sha256"] != report["codex_sha256"]
    {
        return Err(LaneError::input(
            "codex-exec-help",
            "image-build.json Codex exec probe differs from its program or runtime options; run build",
        ));
    }
    if probe["companions"]
        != json!([{"name":"codex-code-mode-host","path":CODEX_HOST_PATH,"sha256":report["codex_host_sha256"]}])
        || report["codex_host_probe"]["sha256"] != report["codex_host_sha256"]
        || report["codex_host_probe"]["argv"] != json!(["--help"])
        || report["codex_host_probe"]["stdout"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Err(LaneError::input(
            "codex-companion",
            "image-build.json lacks the measured code-mode host companion; run build",
        ));
    }
    checked_exec_help(help)?;
    let argv = runtime_argv.as_array().ok_or_else(|| {
        LaneError::input(
            "codex-exec-help",
            "planned runtime argument vector is absent",
        )
    })?;
    let exec = argv.iter().position(|word| word == "exec").ok_or_else(|| {
        LaneError::input("codex-exec-help", "planned Codex exec argument is absent")
    })?;
    for word in &argv[exec + 1..] {
        if let Some(option) = word
            .as_str()
            .filter(|word| word.starts_with('-') && *word != "-")
            && !exec_help_has_option(help, option)
        {
            return Err(LaneError::input(
                "codex-exec-help",
                format!("planned Codex exec option {option} is absent from the pinned help"),
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct BuildRequest {
    pub loop_name: String,
    pub claude: Option<payload::ProgramInput>,
    pub base_image: String,
    pub codex_bin: PathBuf,
    pub codex_host_bin: PathBuf,
    pub codex_version: String,
    pub codex_sha256: String,
    pub codex_host_sha256: String,
    pub codex_source: String,
    pub podman_bin: PathBuf,
    pub template_dir: PathBuf,
    pub dry_run: bool,
}

pub(crate) fn default_template_dir() -> PathBuf {
    option_env!("SUPERLOOP_LANE_DATA_DIR").map_or_else(
        || PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/data")),
        PathBuf::from,
    )
}

impl BuildRequest {
    /// Parse the build's pinned inputs without running a program.
    ///
    /// # Errors
    ///
    /// Refuses an absent, repeated, or unrecognised option.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let Some(loop_name) = args.first() else {
            return Err(LaneError::input(
                "usage",
                "build LOOP --base-image REF [--codex-bin FILE --codex-host-bin FILE --codex-version VERSION --codex-sha256 HEX --codex-host-sha256 HEX --codex-source URL] [--claude-bin FILE --claude-version VERSION --claude-sha256 HEX --claude-source URL] [--podman-bin FILE] [--template-dir DIR] [--dry-run]",
            ));
        };
        let mut values = BTreeMap::new();
        let mut dry_run = false;
        let mut index = 1;
        while index < args.len() {
            let option = args[index].as_str();
            if option == "--dry-run" {
                if dry_run {
                    return Err(LaneError::input("usage", "--dry-run repeated"));
                }
                dry_run = true;
                index += 1;
                continue;
            }
            if ![
                "--claude-bin",
                "--claude-version",
                "--claude-sha256",
                "--claude-source",
                "--base-image",
                "--codex-bin",
                "--codex-host-bin",
                "--codex-version",
                "--codex-sha256",
                "--codex-host-sha256",
                "--codex-source",
                "--podman-bin",
                "--template-dir",
            ]
            .contains(&option)
            {
                return Err(LaneError::input(
                    "usage",
                    format!("unknown build option {option}"),
                ));
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| LaneError::input("usage", format!("{option} needs a value")))?;
            if values.insert(option, value.clone()).is_some() {
                return Err(LaneError::input("usage", format!("{option} repeated")));
            }
            index += 2;
        }
        let required = |key| {
            values
                .get(key)
                .cloned()
                .ok_or_else(|| LaneError::input("usage", format!("missing {key}")))
        };
        let has_codex = values.keys().any(|key| key.starts_with("--codex-"));
        let codex_value = |key| {
            if has_codex {
                required(key)
            } else {
                Ok(String::new())
            }
        };
        let claude = if values.keys().any(|key| key.starts_with("--claude-")) {
            Some(payload::ProgramInput {
                bin: PathBuf::from(required("--claude-bin")?),
                version: required("--claude-version")?,
                sha256: required("--claude-sha256")?,
                source: required("--claude-source")?,
            })
        } else {
            None
        };
        Ok(Self {
            loop_name: loop_name.clone(),
            claude,
            base_image: required("--base-image")?,
            codex_bin: PathBuf::from(codex_value("--codex-bin")?),
            codex_host_bin: PathBuf::from(codex_value("--codex-host-bin")?),
            codex_version: codex_value("--codex-version")?,
            codex_sha256: codex_value("--codex-sha256")?,
            codex_host_sha256: codex_value("--codex-host-sha256")?,
            codex_source: codex_value("--codex-source")?,
            podman_bin: values
                .get("--podman-bin")
                .map_or_else(|| PathBuf::from("/usr/bin/podman"), PathBuf::from),
            template_dir: values
                .get("--template-dir")
                .map_or_else(default_template_dir, PathBuf::from),
            dry_run,
        })
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn executable(path: &Path, name: &str) -> Result<(), LaneError> {
    if !path.is_absolute() {
        return Err(LaneError::input(
            "build-input",
            format!("{name} is not absolute: {}", path.display()),
        ));
    }
    let meta = fs::symlink_metadata(path).map_err(|error| {
        LaneError::input("build-input", format!("{name} {}: {error}", path.display()))
    })?;
    if !meta.is_file() || meta.mode() & 0o111 == 0 {
        return Err(LaneError::input(
            "build-input",
            format!(
                "{name} is not a regular executable file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn opened_source(
    path: &Path,
    name: &str,
    limit: u64,
    must_execute: bool,
) -> Result<(fs::File, Vec<u8>), LaneError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            LaneError::input("build-input", format!("{name} {}: {error}", path.display()))
        })?;
    let meta = file.metadata().map_err(|error| {
        LaneError::input("build-input", format!("{name} {}: {error}", path.display()))
    })?;
    if !meta.is_file() || meta.len() > limit || (must_execute && meta.mode() & 0o111 == 0) {
        return Err(LaneError::input(
            "build-input",
            format!(
                "{name} is not a bounded regular {}file: {}",
                if must_execute { "executable " } else { "" },
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LaneError::input("build-input", format!("{name} {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 > limit {
        return Err(LaneError::input(
            "build-input",
            format!("{name} exceeds {limit} bytes"),
        ));
    }
    Ok((file, bytes))
}

pub(crate) fn source_bytes(
    path: &Path,
    name: &str,
    limit: u64,
    must_execute: bool,
) -> Result<Vec<u8>, LaneError> {
    opened_source(path, name, limit, must_execute).map(|(_, bytes)| bytes)
}

pub(crate) fn executable_snapshot(bytes: &[u8]) -> Result<fs::File, LaneError> {
    let fd = memfd_create("superloop-codex-snapshot", MFdFlags::MFD_ALLOW_SEALING)
        .map_err(|error| LaneError::operation("build-snapshot", error.to_string()))?;
    let mut file = fs::File::from(fd);
    file.write_all(bytes)
        .map_err(|error| LaneError::operation("build-snapshot", error.to_string()))?;
    let seals = SealFlag::F_SEAL_WRITE
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_SEAL;
    fcntl(&file, FcntlArg::F_ADD_SEALS(seals))
        .map_err(|error| LaneError::operation("build-snapshot", error.to_string()))?;
    Ok(file)
}

#[derive(Clone)]
pub(crate) struct ChildSpec {
    program: PathBuf,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    cwd: PathBuf,
    timeout_seconds: u64,
    name: &'static str,
    inherited_fd: Option<i32>,
    private_directory_stdin: Option<Arc<OwnedFd>>,
    private_extra_fds: Vec<Arc<OwnedFd>>,
}

impl ChildSpec {
    pub(crate) fn preview(&self) -> Value {
        let transferred = if self.private_extra_fds.is_empty() {
            Vec::new()
        } else {
            let mut rows = vec![json!({"index":0,"role":"owner_home"})];
            rows.push(json!({"index":1,"role":if self.argv.iter().any(|word| word == "--verified-install-lock-fd") { "install_lock" } else { "runs_root" }}));
            if self.private_extra_fds.len() >= 2 {
                rows.push(json!({"index":2,"role":if self.argv.iter().any(|word| word == "--verified-stub-fd") { "door_stub_source" } else { "letter_directory" }}));
            }
            if self.private_extra_fds.len() >= 3 {
                rows.push(json!({"index":3,"role":if self.argv.iter().any(|word| word == "--verified-template-fd") { "door_template" } else { "rotation_letter_source" }}));
            }
            if self.private_extra_fds.len() >= 4 {
                rows.push(json!({"index":4,"role":"door_libexec"}));
            }
            if self.private_extra_fds.len() >= 5 {
                rows.push(json!({"index":5,"role":"door_socket_root"}));
            }
            rows
        };
        json!({"program":self.program,"argv":self.argv,"environment":self.environment,"cwd":self.cwd,"timeout_seconds":self.timeout_seconds,"inherited_fd":self.inherited_fd,"direct_private_directory_fd":if self.private_extra_fds.is_empty() { self.private_directory_stdin.as_ref().map(|_| 0) } else { None },"directory_transfer_socket_fd":if self.private_extra_fds.is_empty() { None } else { Some(0) },"transferred_directory_descriptors":transferred})
    }

    pub(crate) fn with_private_directory(mut self, directory: &OwnedFd) -> Result<Self, LaneError> {
        self.private_directory_stdin = Some(Arc::new(duplicate_private_fd(directory)?));
        self.argv.extend(["--verified-home-fd".into(), "0".into()]);
        Ok(self)
    }

    pub(crate) fn with_private_install(
        mut self,
        home: &OwnedFd,
        lock: &crate::install::InstallGuard,
    ) -> Result<Self, LaneError> {
        self = self.with_private_directory(home)?;
        let duplicate = duplicate_private_fd(lock)
            .map_err(|error| LaneError::operation("install-lock", error.detail))?;
        self.private_extra_fds.push(Arc::new(duplicate));
        self.argv
            .extend(["--verified-install-lock-fd".into(), "1".into()]);
        Ok(self)
    }

    pub(crate) fn with_private_install_source(
        self,
        home: &OwnedFd,
        lock: &crate::install::InstallGuard,
        source: &impl AsFd,
    ) -> Result<Self, LaneError> {
        let mut spec = self.with_private_install(home, lock)?;
        let duplicate = duplicate_private_fd(source)
            .map_err(|error| LaneError::operation("install-door-source", error.detail))?;
        spec.private_extra_fds.push(Arc::new(duplicate));
        spec.argv.extend(["--verified-stub-fd".into(), "2".into()]);
        Ok(spec)
    }

    pub(crate) fn with_private_door_directories(
        self,
        home: &OwnedFd,
        lock: &crate::install::InstallGuard,
        source: &impl AsFd,
        template: &impl AsFd,
        libexec: &impl AsFd,
        sockets: &impl AsFd,
    ) -> Result<Self, LaneError> {
        let mut spec = self.with_private_install_source(home, lock, source)?;
        for (fd, flag, index) in [
            (template.as_fd(), "--verified-template-fd", "3"),
            (libexec.as_fd(), "--verified-libexec-fd", "4"),
            (sockets.as_fd(), "--verified-socket-root-fd", "5"),
        ] {
            let duplicate = duplicate_private_fd(&fd)
                .map_err(|error| LaneError::operation("install-door-path", error.detail))?;
            spec.private_extra_fds.push(Arc::new(duplicate));
            spec.argv.extend([flag.into(), index.into()]);
        }
        Ok(spec)
    }

    pub(crate) fn with_private_door_listener(
        mut self,
        directory: &OwnedFd,
        listener: &impl AsFd,
    ) -> Result<Self, LaneError> {
        self.private_directory_stdin = Some(Arc::new(
            duplicate_private_fd(directory)
                .map_err(|error| LaneError::operation("door-socket", error.detail))?,
        ));
        let duplicate = duplicate_private_fd(listener)
            .map_err(|error| LaneError::operation("door-socket", error.detail))?;
        self.private_extra_fds.push(Arc::new(duplicate));
        Ok(self)
    }

    pub(crate) fn with_private_launch(
        mut self,
        home: &OwnedFd,
        runs_root: &Path,
        runs: &OwnedFd,
        letter: Option<(&Path, &OwnedFd)>,
    ) -> Result<Self, LaneError> {
        self = self.with_private_directory(home)?;
        let runs = Arc::new(duplicate_private_fd(runs)?);
        self.argv.extend([
            "--verified-runs-root".into(),
            crate::pinned::path_word(runs_root, "runs-root")?,
            "--verified-runs-root-fd".into(),
            "1".into(),
        ]);
        self.private_extra_fds.push(runs);
        if let Some((letter_dir, letter)) = letter {
            let letter = Arc::new(duplicate_private_fd(letter)?);
            self.argv.extend([
                "--verified-letter-dir".into(),
                crate::pinned::path_word(letter_dir, "letter-directory")?,
                "--verified-letter-fd".into(),
                "2".into(),
            ]);
            self.private_extra_fds.push(letter);
        }
        Ok(self)
    }

    pub(crate) fn with_private_rotation_source(
        mut self,
        source: &OwnedFd,
    ) -> Result<Self, LaneError> {
        if self.private_extra_fds.len() != 2 {
            return Err(LaneError::input(
                "rotate-source",
                "private rotation requires the bound letter directory",
            ));
        }
        self.private_extra_fds
            .push(Arc::new(duplicate_private_fd(source)?));
        self.argv
            .extend(["--verified-letter-source-fd".into(), "3".into()]);
        Ok(self)
    }
}

/// Duplicate a private directory with close-on-exec until its child is launched.
pub(crate) fn duplicate_private_fd(directory: &impl AsFd) -> Result<OwnedFd, LaneError> {
    use std::os::fd::FromRawFd as _;
    // The child clears close-on-exec only after fork, so concurrent children do not inherit it.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::fcntl(directory.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    if fd < 0 {
        return Err(LaneError::operation(
            "private-prefix",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    #[allow(unsafe_code)]
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[derive(Debug)]
pub(crate) struct ChildResult {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

fn read_capped(mut pipe: impl Read, overflow: &AtomicBool) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = pipe.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if output.len() + count > MAX_COMMAND_OUTPUT {
            overflow.store(true, Ordering::Release);
        } else {
            output.extend_from_slice(&buffer[..count]);
        }
    }
    Ok(output)
}

fn spawn_child_worker<T: Send + 'static>(
    spec: &ChildSpec,
    name: &'static str,
    task: impl FnOnce() -> T + Send + 'static,
) -> Result<std::thread::JoinHandle<T>, LaneError> {
    std::thread::Builder::new()
        .name(format!("lane-{name}"))
        .spawn(task)
        .map_err(|error| {
            LaneError::operation(
                spec.name,
                format!("{}: {name} thread: {error}", spec.program.display()),
            )
        })
}

fn finish_child_worker<T: Send + 'static>(
    spec: &ChildSpec,
    name: &'static str,
    handle: Option<std::thread::JoinHandle<std::io::Result<T>>>,
    deadline: Instant,
) -> Result<Option<T>, LaneError> {
    let Some(handle) = handle else {
        return Ok(None);
    };
    while !handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !handle.is_finished() {
        return Err(LaneError::operation(
            spec.name,
            format!(
                "{}: {name} reader did not finish after stop",
                spec.program.display()
            ),
        ));
    }
    handle
        .join()
        .map_err(|_| LaneError::operation(spec.name, format!("{name} reader panicked")))?
        .map(Some)
        .map_err(|error| LaneError::operation(spec.name, error.to_string()))
}

fn kill_group(child: &mut std::process::Child) {
    // The child starts a new process group; killing it closes pipes held by its descendants.
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ignored = child.kill();
    let deadline = Instant::now() + CHILD_READER_GRACE;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn run_child(spec: &ChildSpec, input: Option<&[u8]>) -> Result<ChildResult, LaneError> {
    run_child_with_log(spec, input, None)
}

#[allow(clippy::too_many_lines)]
fn run_child_with_log(
    spec: &ChildSpec,
    input: Option<&[u8]>,
    failure_log: Option<(&Path, &str)>,
) -> Result<ChildResult, LaneError> {
    run_child_with_start(spec, input, failure_log, |_| Ok(()))
}

#[allow(clippy::too_many_lines)]
fn run_child_with_start(
    spec: &ChildSpec,
    input: Option<&[u8]>,
    failure_log: Option<(&Path, &str)>,
    on_start: impl FnOnce(u32) -> Result<(), LaneError>,
) -> Result<ChildResult, LaneError> {
    run_child_with_end(spec, input, failure_log, on_start, &mut ChildEnd::default())
}

#[derive(Default)]
pub(crate) struct ChildEnd {
    pub(crate) wall: Option<lane_lifecycle::AttemptWall>,
}

#[allow(clippy::too_many_lines)]
fn run_child_with_end(
    spec: &ChildSpec,
    input: Option<&[u8]>,
    failure_log: Option<(&Path, &str)>,
    on_start: impl FnOnce(u32) -> Result<(), LaneError>,
    end: &mut ChildEnd,
) -> Result<ChildResult, LaneError> {
    *end = ChildEnd::default();
    // The version probe executes an inherited, measured descriptor. Every pathname
    // program is checked again at the point where the owner starts it.
    if spec.inherited_fd.is_none() {
        crate::pinned::owner_executable(&spec.program, nix::unistd::Uid::effective().as_raw())?;
    }
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.argv)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(&spec.environment)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let transfer = if spec.private_extra_fds.is_empty() {
        None
    } else {
        let (parent, child) = UnixStream::pair()
            .map_err(|error| LaneError::operation(spec.name, error.to_string()))?;
        command.stdin(Stdio::from(OwnedFd::from(child)));
        Some(parent)
    };
    if transfer.is_none()
        && let Some(directory) = &spec.private_directory_stdin
    {
        let duplicate = duplicate_private_fd(directory.as_ref())?;
        command.stdin(Stdio::from(fs::File::from(duplicate)));
    } else if transfer.is_none() && input.is_some() {
        command.stdin(Stdio::piped());
    }
    crate::launch::reaping::attach_command(&mut command)?;
    let mut child = crate::fixture_exec::spawn(&mut command).map_err(|error| {
        LaneError::operation(spec.name, format!("{}: {error}", spec.program.display()))
    })?;
    if let Some(stream) = transfer {
        let home = spec.private_directory_stdin.as_ref().ok_or_else(|| {
            LaneError::input("verified-prefix", "private home descriptor is absent")
        })?;
        let fds = std::iter::once(home.as_raw_fd())
            .chain(
                spec.private_extra_fds
                    .iter()
                    .map(std::os::fd::AsRawFd::as_raw_fd),
            )
            .collect::<Vec<_>>();
        if let Err(error) = crate::home::send_private_descriptors(&stream, &fds) {
            kill_group(&mut child);
            return Err(error);
        }
    }
    if let Err(error) = on_start(child.id()) {
        kill_group(&mut child);
        return Err(error);
    }
    let overflow = Arc::new(AtomicBool::new(false));
    let Some(stdout) = child.stdout.take() else {
        kill_group(&mut child);
        return Err(LaneError::operation(spec.name, "stdout pipe absent"));
    };
    let Some(stderr) = child.stderr.take() else {
        kill_group(&mut child);
        return Err(LaneError::operation(spec.name, "stderr pipe absent"));
    };
    let out_flag = Arc::clone(&overflow);
    let err_flag = Arc::clone(&overflow);
    let mut out_reader = None;
    let mut err_reader = None;
    let mut input_writer = None;
    let setup = (|| -> Result<(), LaneError> {
        out_reader = Some(spawn_child_worker(spec, "stdout", move || {
            read_capped(stdout, &out_flag)
        })?);
        err_reader = Some(spawn_child_worker(spec, "stderr", move || {
            read_capped(stderr, &err_flag)
        })?);
        if let Some(bytes) = input.filter(|_| spec.private_directory_stdin.is_none()) {
            let bytes = bytes.to_vec();
            let stream = child.stdin.take();
            input_writer = Some(spawn_child_worker(spec, "stdin", move || {
                stream.map_or(Ok(()), |mut pipe| pipe.write_all(&bytes))
            })?);
        }
        Ok(())
    })();
    if let Err(error) = setup {
        kill_group(&mut child);
        let deadline = Instant::now() + CHILD_READER_GRACE;
        let _input = finish_child_worker(spec, "stdin", input_writer.take(), deadline);
        let _stdout = finish_child_worker(spec, "stdout", out_reader.take(), deadline);
        let _stderr = finish_child_worker(spec, "stderr", err_reader.take(), deadline);
        return Err(error);
    }
    let began = Instant::now();
    let mut status = None;
    let mut exceeded = None;
    loop {
        if overflow.load(Ordering::Acquire)
            || began.elapsed() > Duration::from_secs(spec.timeout_seconds)
        {
            let reason = if overflow.load(Ordering::Acquire) {
                "output limit"
            } else {
                if status.is_none() {
                    end.wall = Some(lane_lifecycle::AttemptWall {
                        wall_seconds: began.elapsed().as_secs(),
                        bound_seconds: spec.timeout_seconds,
                    });
                }
                "time limit"
            };
            kill_group(&mut child);
            exceeded = Some(reason);
            break;
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exited)) => status = Some(exited),
                Ok(None) => {}
                Err(error) => {
                    kill_group(&mut child);
                    let deadline = Instant::now() + CHILD_READER_GRACE;
                    let _input = finish_child_worker(spec, "stdin", input_writer.take(), deadline);
                    let _stdout = finish_child_worker(spec, "stdout", out_reader.take(), deadline);
                    let _stderr = finish_child_worker(spec, "stderr", err_reader.take(), deadline);
                    return Err(LaneError::operation(spec.name, error.to_string()));
                }
            }
        }
        if status.is_some()
            && out_reader
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            && err_reader
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            && input_writer
                .as_ref()
                .is_none_or(std::thread::JoinHandle::is_finished)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let deadline = Instant::now() + CHILD_READER_GRACE;
    let input_result = finish_child_worker(spec, "stdin", input_writer.take(), deadline);
    let out_result = finish_child_worker(spec, "stdout", out_reader.take(), deadline);
    let err_result = finish_child_worker(spec, "stderr", err_reader.take(), deadline);
    if let Some(reason) =
        exceeded.or_else(|| overflow.load(Ordering::Acquire).then_some("output limit"))
    {
        if let Some((path, attempt)) = failure_log {
            let mut log = out_result
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .cloned()
                .unwrap_or_default();
            if let Ok(Some(stderr)) = &err_result {
                log.extend_from_slice(stderr);
            }
            publish_attempt(path, &log, attempt)?;
        }
        return Err(LaneError::operation(
            spec.name,
            format!("{} exceeded {reason}", spec.program.display()),
        ));
    }
    input_result?;
    let stdout = out_result?.ok_or_else(|| LaneError::operation(spec.name, "stdout absent"))?;
    let stderr = err_result?.ok_or_else(|| LaneError::operation(spec.name, "stderr absent"))?;
    Ok(ChildResult {
        status: status.ok_or_else(|| LaneError::operation(spec.name, "child status absent"))?,
        stdout,
        stderr,
    })
}

fn standalone_codex(bytes: &[u8], path: &Path) -> Result<(), LaneError> {
    if !bytes.starts_with(b"\x7fELF") {
        return Err(LaneError::input(
            "build-input",
            format!(
                "{} is not a standalone ELF Codex program; scripts and wrappers have unmeasured interpreters",
                path.display()
            ),
        ));
    }
    let invalid = |reason: &str| {
        LaneError::input(
            "build-input",
            format!(
                "{} is not a standalone ELF Codex program: {reason}",
                path.display()
            ),
        )
    };
    if bytes.len() < 64 || bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(invalid(
            "only complete ELF64 little-endian artifacts are measured",
        ));
    }
    let number = |start: usize, width: usize| -> Result<u64, LaneError> {
        let field = bytes
            .get(start..start + width)
            .ok_or_else(|| invalid("truncated ELF header"))?;
        let mut word = [0_u8; 8];
        word[..width].copy_from_slice(field);
        Ok(u64::from_le_bytes(word))
    };
    let header_offset =
        usize::try_from(number(32, 8)?).map_err(|_| invalid("program header offset overflows"))?;
    let entry_size =
        usize::try_from(number(54, 2)?).map_err(|_| invalid("program header size overflows"))?;
    let entries =
        usize::try_from(number(56, 2)?).map_err(|_| invalid("program header count overflows"))?;
    if entries > 0 && entry_size < 56 {
        return Err(invalid("program header is truncated"));
    }
    for index in 0..entries {
        let offset = header_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| invalid("program header overflows"))?,
            )
            .ok_or_else(|| invalid("program header overflows"))?;
        let end = offset
            .checked_add(56)
            .ok_or_else(|| invalid("program header overflows"))?;
        if bytes.get(offset..end).is_none() {
            return Err(invalid("program header is outside the artifact"));
        }
        match number(offset, 4)? {
            3 => return Err(invalid("PT_INTERP names an external loader")),
            2 => {
                let dynamic_offset = usize::try_from(number(offset + 8, 8)?)
                    .map_err(|_| invalid("dynamic table offset overflows"))?;
                let dynamic_size = usize::try_from(number(offset + 32, 8)?)
                    .map_err(|_| invalid("dynamic table size overflows"))?;
                let dynamic_end = dynamic_offset
                    .checked_add(dynamic_size)
                    .ok_or_else(|| invalid("dynamic table overflows"))?;
                if dynamic_size % 16 != 0 || bytes.get(dynamic_offset..dynamic_end).is_none() {
                    return Err(invalid("dynamic table is incomplete"));
                }
                for entry in (dynamic_offset..dynamic_end).step_by(16) {
                    match number(entry, 8)? {
                        0 => break,
                        1 => return Err(invalid("DT_NEEDED names an external library")),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn checked_output(spec: &ChildSpec, input: Option<&[u8]>) -> Result<String, LaneError> {
    let output = run_child(spec, input)?;
    if !output.status.success() {
        return Err(LaneError::operation(
            spec.name,
            format!(
                "{} exited {}: {}",
                spec.program.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim_end()
            ),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| LaneError::operation(spec.name, "output is not UTF-8"))
}

pub(crate) fn run_checked(
    program: &Path,
    argv: Vec<String>,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    timeout_seconds: u64,
    name: &'static str,
) -> Result<String, LaneError> {
    checked_output(
        &child(program, argv, environment, cwd, timeout_seconds, name),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_checked_with_private_launch(
    program: &Path,
    argv: Vec<String>,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    timeout_seconds: u64,
    name: &'static str,
    home: &OwnedFd,
    runs_root: &Path,
    runs: &OwnedFd,
    letter: Option<(&Path, &OwnedFd)>,
) -> Result<String, LaneError> {
    let spec = child(program, argv, environment, cwd, timeout_seconds, name)
        .with_private_launch(home, runs_root, runs, letter)?;
    checked_output(&spec, None)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_checked_with_private_rotation(
    program: &Path,
    argv: Vec<String>,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    timeout_seconds: u64,
    name: &'static str,
    home: &OwnedFd,
    runs_root: &Path,
    runs: &OwnedFd,
    letter: (&Path, &OwnedFd),
    source: &OwnedFd,
) -> Result<String, LaneError> {
    let spec = child(program, argv, environment, cwd, timeout_seconds, name)
        .with_private_launch(home, runs_root, runs, Some(letter))?
        .with_private_rotation_source(source)?;
    checked_output(&spec, None)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn private_launch_preview(
    program: &Path,
    argv: Vec<String>,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    timeout_seconds: u64,
    name: &'static str,
    home: &OwnedFd,
    runs_root: &Path,
    runs: &OwnedFd,
    letter: Option<(&Path, &OwnedFd)>,
) -> Result<Value, LaneError> {
    let spec = child(program, argv, environment, cwd, timeout_seconds, name)
        .with_private_launch(home, runs_root, runs, letter)?;
    Ok(spec.preview())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_checked_with_pid(
    program: &Path,
    argv: Vec<String>,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    timeout_seconds: u64,
    name: &'static str,
    end: &mut ChildEnd,
    on_start: impl FnOnce(u32) -> Result<(), LaneError>,
) -> Result<String, LaneError> {
    let spec = child(program, argv, environment, cwd, timeout_seconds, name);
    let output = run_child_with_end(&spec, None, None, on_start, end)?;
    if !output.status.success() {
        let driver_lines = bounded_diagnostic_lines(&output.stdout);
        return Err(LaneError::operation(
            name,
            format!(
                "{} exited {}: {}{}",
                program.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim_end(),
                driver_lines
            ),
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| LaneError::operation(name, "output is not UTF-8"))
}

pub(crate) fn bounded_diagnostic_lines(bytes: &[u8]) -> String {
    let tail = &bytes[bytes.len().saturating_sub(4096)..];
    let text = String::from_utf8_lossy(tail);
    let mut lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(4)
        .collect::<Vec<_>>();
    lines.reverse();
    if lines.is_empty() {
        String::new()
    } else {
        format!("; driver diagnostic: {}", lines.join(" | "))
    }
}

fn hash_spec(cwd: &Path) -> ChildSpec {
    ChildSpec {
        program: PathBuf::from("/usr/bin/sha256sum"),
        argv: Vec::new(),
        environment: BTreeMap::new(),
        cwd: cwd.to_path_buf(),
        timeout_seconds: 30,
        name: "sha256sum",
        inherited_fd: None,
        private_directory_stdin: None,
        private_extra_fds: Vec::new(),
    }
}

pub(crate) fn hash_preview(cwd: &Path) -> Value {
    hash_spec(cwd).preview()
}

fn hash_bytes(bytes: &[u8], spec: &ChildSpec) -> Result<String, LaneError> {
    crate::pinned::owner_executable(&spec.program, nix::unistd::Uid::effective().as_raw())
        .map_err(|_error| {
            LaneError::input(
                "hash-pin",
                "the hashing program must be an owner-controlled regular executable reached without symlinks; run superloop-lane on the host with that pin",
            )
        })?;
    let output = checked_output(spec, Some(bytes))?;
    let hash = output
        .strip_suffix("  -\n")
        .ok_or_else(|| LaneError::operation("sha256sum", "unexpected digest output"))?;
    if !digest(hash) {
        return Err(LaneError::operation("sha256sum", "invalid digest output"));
    }
    Ok(hash.to_owned())
}

pub(crate) fn sha256_bytes(bytes: &[u8], cwd: &Path) -> Result<String, LaneError> {
    hash_bytes(bytes, &hash_spec(cwd))
}

/// Hash a bounded regular source for a pinned install input.
///
/// # Errors
///
/// Refuses an unsafe source, an oversize file, or a failed hash command.
pub fn sha256(path: &Path) -> Result<String, LaneError> {
    let bytes = source_bytes(path, "hash input", MAX_CODEX_BYTES, false)?;
    hash_bytes(
        &bytes,
        &hash_spec(path.parent().unwrap_or_else(|| Path::new("/"))),
    )
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), LaneError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            LaneError::operation("build-write", format!("{}: {error}", path.display()))
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            LaneError::operation("build-write", format!("{}: {error}", path.display()))
        })
}

fn attempt_id() -> Result<String, LaneError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| LaneError::operation("build-clock", error.to_string()))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}

fn publish_attempt(path: &Path, bytes: &[u8], attempt: &str) -> Result<(), LaneError> {
    let temp = path.with_extension(format!("tmp-{attempt}"));
    write_private(&temp, bytes)?;
    fs::rename(&temp, path).map_err(|error| {
        LaneError::operation("build-publish", format!("{}: {error}", path.display()))
    })
}

pub(crate) fn publish(path: &Path, bytes: &[u8]) -> Result<(), LaneError> {
    publish_attempt(path, bytes, &attempt_id()?)
}

pub(crate) fn parsed_image_id(text: &str) -> Result<String, LaneError> {
    let bare = text
        .strip_suffix('\n')
        .ok_or_else(|| LaneError::operation("image-inspect", "image ID lacks newline"))?;
    if !digest(bare) {
        return Err(LaneError::operation(
            "image-inspect",
            format!("invalid bare image ID {}", bare.escape_debug()),
        ));
    }
    Ok(format!("sha256:{bare}"))
}

pub(crate) fn inspect_image(program: &Path, image: &str, home: &Path) -> Result<String, LaneError> {
    let spec = image_inspect_spec(program, image, home)?;
    parsed_image_id(&checked_output(&spec, None)?)
}

pub(crate) fn inspect_image_with_environment(
    program: &Path,
    image: &str,
    home: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<String, LaneError> {
    let mut spec = image_inspect_spec(program, image, home)?;
    spec.environment = environment.clone();
    parsed_image_id(&checked_output(&spec, None)?)
}

pub(crate) fn image_inspect_preview(
    program: &Path,
    image: &str,
    home: &Path,
) -> Result<Value, LaneError> {
    Ok(image_inspect_spec(program, image, home)?.preview())
}

fn image_inspect_spec(program: &Path, image: &str, home: &Path) -> Result<ChildSpec, LaneError> {
    Ok(child(
        program,
        vec![
            "image".into(),
            "inspect".into(),
            "--format".into(),
            "{{.Id}}".into(),
            image.into(),
        ],
        &podman_environment(home)?,
        home,
        30,
        "image-inspect",
    ))
}

fn validate_input(request: &BuildRequest) -> Result<(), LaneError> {
    let Some((repository, hash)) = request.base_image.rsplit_once("@sha256:") else {
        return Err(LaneError::input(
            "build-input",
            "base image must be a repository pinned by sha256 digest",
        ));
    };
    if repository.is_empty()
        || !digest(hash)
        || repository
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"._:/-".contains(&byte))
    {
        return Err(LaneError::input(
            "build-input",
            "base image must be one safe repository reference pinned by sha256 digest",
        ));
    }
    if request.codex_bin.as_os_str().is_empty() {
        return Ok(());
    }
    if request.codex_version.is_empty()
        || !request
            .codex_version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !digest(&request.codex_sha256)
        || !digest(&request.codex_host_sha256)
    {
        return Err(LaneError::input(
            "build-input",
            "Codex version or sha256 pin is invalid",
        ));
    }
    let source = request
        .codex_source
        .strip_prefix("https://")
        .ok_or_else(|| {
            LaneError::input(
                "build-input",
                "Codex source must be an HTTPS artifact address",
            )
        })?;
    let authority = source.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || source
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b'?' || byte == b'#')
    {
        return Err(LaneError::input(
            "build-input",
            "Codex source must be one HTTPS artifact address without credentials or query",
        ));
    }
    Ok(())
}

pub(crate) fn child(
    program: &Path,
    argv: Vec<String>,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    timeout_seconds: u64,
    name: &'static str,
) -> ChildSpec {
    ChildSpec {
        program: program.to_path_buf(),
        argv,
        environment: environment.clone(),
        cwd: cwd.to_path_buf(),
        timeout_seconds,
        name,
        inherited_fd: None,
        private_directory_stdin: None,
        private_extra_fds: Vec::new(),
    }
}

pub(crate) fn podman_environment(home: &Path) -> Result<BTreeMap<String, String>, LaneError> {
    let home_text = home
        .to_str()
        .ok_or_else(|| LaneError::input("build-input", "home is not UTF-8"))?;
    let mut environment = BTreeMap::from([
        (String::from("HOME"), home_text.to_owned()),
        (String::from("PATH"), String::from("/usr/bin:/bin")),
        (String::from("LANG"), String::from("C.UTF-8")),
    ]);
    for key in ["XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"] {
        if let Ok(value) = std::env::var(key) {
            if !Path::new(&value).is_absolute() || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(LaneError::input(
                    "build-input",
                    format!("{key} is not one absolute path"),
                ));
            }
            environment.insert(key.to_owned(), value);
        }
    }
    Ok(environment)
}

fn image_exists(spec: &ChildSpec) -> Result<bool, LaneError> {
    let result = run_child(spec, None)?;
    match result.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(LaneError::operation(
            "image-exists",
            format!(
                "{} exited {}: {}",
                spec.program.display(),
                result.status,
                String::from_utf8_lossy(&result.stderr).trim_end()
            ),
        )),
    }
}

fn stale_paths(parent: &Path, loop_name: &str) -> Result<Vec<PathBuf>, LaneError> {
    let prefix = format!("superloop-lane-build-{loop_name}");
    let mut stale = Vec::new();
    for item in fs::read_dir(parent).map_err(|error| {
        LaneError::input("build-context", format!("{}: {error}", parent.display()))
    })? {
        let item = item.map_err(|error| LaneError::input("build-context", error.to_string()))?;
        let name = item.file_name();
        let name = name.to_string_lossy();
        if name == prefix || name.starts_with(&format!("{prefix}-")) {
            stale.push(item.path());
        }
    }
    stale.sort();
    Ok(stale)
}

fn stale_publications(settings_path: &Path) -> Result<Vec<PathBuf>, LaneError> {
    let parent = settings_path
        .parent()
        .ok_or_else(|| LaneError::input("build-recover", "settings has no parent"))?;
    let mut stale = Vec::new();
    for item in fs::read_dir(parent)
        .map_err(|error| LaneError::input("build-recover", error.to_string()))?
    {
        let item = item.map_err(|error| LaneError::input("build-recover", error.to_string()))?;
        let name = item.file_name();
        let name = name.to_string_lossy();
        if ["workers.tmp", "image-build.tmp"].contains(&name.as_ref())
            || name.starts_with("workers.tmp-")
            || name.starts_with("image-build.tmp-")
        {
            stale.push(item.path());
        }
    }
    stale.sort();
    Ok(stale)
}

fn retire_stale(stale: &[PathBuf], attempt: &str) -> Result<Vec<PathBuf>, LaneError> {
    let mut retired = Vec::new();
    for (index, source) in stale.iter().enumerate() {
        let parent = source
            .parent()
            .ok_or_else(|| LaneError::input("build-context", "stale context has no parent"))?;
        let destination = parent.join(format!("superloop-lane-retired-{attempt}-{index}"));
        fs::rename(source, &destination).map_err(|error| {
            LaneError::operation("build-recover", format!("{}: {error}", source.display()))
        })?;
        retired.push(destination);
    }
    Ok(retired)
}

fn codex_image_program(template: &str) -> Result<String, LaneError> {
    let placements = template
        .lines()
        .filter_map(|line| {
            let words = line.split_whitespace().collect::<Vec<_>>();
            match words.as_slice() {
                ["COPY", "codex", destination] => Some(*destination),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let [program] = placements.as_slice() else {
        return Err(LaneError::input(
            "build-input",
            "Containerfile must place codex at one absolute program path",
        ));
    };
    validate_image_program(program)
}

pub(crate) fn validate_image_program(program: &str) -> Result<String, LaneError> {
    if !program.starts_with('/')
        || program[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || program.contains(',')
    {
        return Err(LaneError::input(
            "build-input",
            "Containerfile codex destination must be a plain absolute program path",
        ));
    }
    crate::pinned::path_word(Path::new(program), "backend-program")
}

/// Read the one recorded Codex program shape from a build report.
///
/// # Errors
///
/// Refuses a missing or invalid recorded program by name.
pub fn image_program_from_report(report: &Value) -> Result<String, LaneError> {
    let program = report["codex_image_program"]
        .as_str()
        .ok_or_else(|| LaneError::input("build-report", "codex_image_program is absent"))?;
    payload::check_claude_report(report, false)?;
    validate_image_program(program).map_err(|error| {
        LaneError::input(
            "build-report",
            format!("codex_image_program: {}", error.detail),
        )
    })
}

/// Describe or perform a pinned image build and record its result outside the worker home.
///
/// # Errors
///
/// Refuses missing inputs or a widened grant before mutation, and leaves settings unchanged on build failure.
#[allow(clippy::too_many_lines)]
pub fn run(home: &Path, request: &BuildRequest) -> Result<Value, LaneError> {
    run_inner(home, request, None)
}

/// Restore an installed image or settings pin only when local identity matches the build report.
///
/// # Errors
///
/// Refuses changed inputs or a rebuilt ID that differs from the recorded image.
pub(crate) fn run_repair(
    home: &Path,
    request: &BuildRequest,
    pinned_report: &Value,
    pinned_generation: &Value,
) -> Result<Value, LaneError> {
    run_inner(home, request, Some((pinned_report, pinned_generation)))
}

#[allow(clippy::too_many_lines)]
fn run_inner(
    home: &Path,
    request: &BuildRequest,
    pinned: Option<(&Value, &Value)>,
) -> Result<Value, LaneError> {
    let repair = pinned.is_some();
    let began = Instant::now();
    loop_home::validate_name(&request.loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let settings_path = home
        .join(".config/loops")
        .join(&request.loop_name)
        .join("workers.toml");
    let _settings_lock = crate::install::lock_loop_config(
        settings_path.parent().ok_or_else(|| {
            LaneError::input("settings-lock", "settings file has no parent directory")
        })?,
        request.dry_run,
    )?;
    let settings = Settings::read(&settings_path)?;
    settings.validate_grant(home, &request.loop_name)?;
    let report_path = settings_path.with_file_name("image-build.json");
    let prior = if let Some((report, _)) = pinned {
        Some(report.clone())
    } else {
        match fs::read(&report_path) {
            Ok(bytes) => Some(serde_json::from_slice::<Value>(&bytes).map_err(|error| {
                LaneError::input(
                    "build-report",
                    format!("{}: {error}", report_path.display()),
                )
            })?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(LaneError::input(
                    "build-report",
                    format!("{}: {error}", report_path.display()),
                ));
            }
        }
    };
    if let Some(report) = prior.as_ref() {
        if report.get("codex_sha256").is_some() {
            image_program_from_report(report)?;
        } else {
            payload::image_program(report, payload::CLAUDE)?;
        }
        payload::check_claude_report(report, false)?;
    }
    let registry_path =
        loop_home::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    registry
        .row(&request.loop_name, home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    if payload::configured(&settings).is_empty() {
        return Err(LaneError::input(
            "missing-setting",
            "no vendor is named in backend_argv or vendor_hosts",
        ));
    }
    crate::pinned::owner_executable(&request.podman_bin, nix::unistd::Uid::effective().as_raw())?;
    if !request.template_dir.is_absolute() {
        return Err(LaneError::input(
            "build-input",
            "template directory is not absolute",
        ));
    }
    validate_input(request)?;
    let template_path = request.template_dir.join("Containerfile");
    let init_path = request.template_dir.join("box-init");
    let template_bytes = source_bytes(&template_path, "image template", MAX_DATA_BYTES, false)?;
    let init_bytes = source_bytes(&init_path, "image init", MAX_DATA_BYTES, false)?;
    let template = String::from_utf8(template_bytes.clone())
        .map_err(|_| LaneError::input("build-input", "image template is not UTF-8"))?;
    if !template.contains("@BASE_IMAGE@")
        || !template.contains("@CODEX_VERSION@")
        || !template.contains("@CODEX_SHA256@")
        || !template.contains("@CODEX_HOST_SHA256@")
        || !template
            .contains("COPY codex-code-mode-host /usr/libexec/superloop/codex-code-mode-host")
    {
        return Err(LaneError::input(
            "build-input",
            format!(
                "image template lacks a required pin: {}",
                template_path.display()
            ),
        ));
    }
    let mut rendered = template
        .replace("@BASE_IMAGE@", &request.base_image)
        .replace("@CODEX_VERSION@", &request.codex_version)
        .replace("@CODEX_SHA256@", &request.codex_sha256)
        .replace("@CODEX_HOST_SHA256@", &request.codex_host_sha256);
    let mut programs = payload::Prepared::new(home, request, &settings, &rendered)?;
    let seed_keys = programs.seed_keys(&settings);
    let seed_backend = !seed_keys.is_empty();
    let hash_command = hash_spec(home);
    let template_hash = hash_bytes(&template_bytes, &hash_command)?;
    let init_hash = hash_bytes(&init_bytes, &hash_command)?;
    let environment = podman_environment(home)?;
    if !settings.configures("codex") {
        rendered = rendered
            .lines()
            .filter(|line| {
                !line.starts_with("COPY codex") && !line.starts_with("LABEL org.superloop.codex")
            })
            .map(|line| {
                line.replace(" && /usr/libexec/superloop/codex --version", "")
                    .replace(" /usr/libexec/superloop/codex-code-mode-host", "")
                    .replace(" /usr/libexec/superloop/codex", "")
            })
            .collect::<Vec<_>>()
            .join("\n");
        rendered.push('\n');
    }
    if settings.configures("claude") {
        rendered.push_str("COPY claude /usr/libexec/superloop/claude\nRUN chmod 0555 /usr/libexec/superloop/claude\n");
    }

    let attempt = attempt_id()?;
    let context_parent = home.join(".cache/tmp");
    let context = context_parent.join(format!(
        "superloop-lane-build-{}-{attempt}",
        request.loop_name
    ));
    let stale = stale_paths(&context_parent, &request.loop_name)?;
    let stale_reports = stale_publications(&settings_path)?;
    let primary = programs
        .vendors
        .first()
        .ok_or_else(|| LaneError::input("build-input", "no configured vendor payload"))?;
    let version = programs.pins[primary.version_key]
        .as_str()
        .ok_or_else(|| LaneError::input("build-input", "selected vendor version is absent"))?;
    let tag = format!(
        "localhost/superloop-lane-{}:{version}-{attempt}",
        primary.name
    );
    let build_spec = child(
        &request.podman_bin,
        vec![
            "build".into(),
            "--pull=never".into(),
            "--no-cache".into(),
            "--network=none".into(),
            "--tag".into(),
            tag.clone(),
            "--file".into(),
            context.join("Containerfile").display().to_string(),
            context.display().to_string(),
        ],
        &environment,
        home,
        900,
        "image-build",
    );
    let inspect_spec = child(
        &request.podman_bin,
        vec![
            "image".into(),
            "inspect".into(),
            "--format".into(),
            "{{.Id}}".into(),
            tag,
        ],
        &environment,
        home,
        30,
        "image-inspect",
    );
    let mut inventory_spec = child(
        &request.podman_bin,
        vec![
            "run".into(),
            "--rm".into(),
            "--network=none".into(),
            "--pull=never".into(),
            "--entrypoint".into(),
            "/usr/bin/cat".into(),
            "IMAGE_ID_FROM_INSPECT".into(),
            "/usr/share/superloop/package-inventory.txt".into(),
        ],
        &environment,
        home,
        60,
        "image-inventory",
    );
    let probe_backfill = settings.configures("codex")
        && prior.as_ref().is_some_and(|report| {
            report["codex_exec_probe"] != programs.fields["codex_exec_probe"]
        });
    let matching_report_pins = prior.as_ref().is_some_and(|report| {
        report["base_image"] == request.base_image
            && programs
                .pins
                .iter()
                .all(|(key, value)| report[key] == *value)
            && report["template_sha256"] == template_hash
            && report["init_sha256"] == init_hash
            && programs
                .vendors
                .iter()
                .all(|vendor| report[vendor.program_key] == programs.fields[vendor.program_key])
            && (report.get("claude_sha256").is_some() == settings.configures("claude"))
            && (report.get("codex_sha256").is_some() == settings.configures("codex"))
    });
    if repair && !matching_report_pins {
        return Err(LaneError::input(
            "repair-build-report",
            "measured template or init differs from the pinned build report; run build",
        ));
    }
    let matching_source_pins = matching_report_pins
        && settings
            .image_digest
            .as_ref()
            .zip(prior.as_ref())
            .is_some_and(|(current, report)| report["image_digest"] == *current);
    let matching_pins = matching_source_pins
        && prior.as_ref().is_some_and(|report| {
            report["tools_commit"] == option_env!("SUPERLOOP_TOOLS_COMMIT").unwrap_or("unrecorded")
        });
    let installed_generation = if matching_source_pins {
        if let Some((_, generation)) = pinned {
            (!generation.is_null()).then(|| generation.clone())
        } else {
            crate::install::read_generation(
                &settings_path.with_file_name("install-generation.json"),
            )?
        }
    } else {
        None
    };
    if let Some(generation) = &installed_generation {
        payload::check_claude_generation(generation)?;
    }
    let installed_match = installed_generation
        .as_ref()
        .zip(prior.as_ref())
        .is_some_and(|(generation, report)| {
            generation["phase"] == "complete"
                && generation["image_digest"] == report["image_digest"]
                && programs
                    .vendors
                    .iter()
                    .all(|vendor| generation[vendor.hash_key] == report[vendor.hash_key])
                && (!settings.configures("codex")
                    || generation["codex_host_sha256"] == report["codex_host_sha256"])
                && (!settings.configures("claude")
                    || (generation["claude_image_program"] == report["claude_image_program"]
                        && generation["claude_template_dir"]
                            == home
                                .join(".var/loops")
                                .join(&request.loop_name)
                                .join("runner-templates/claude")
                                .join(
                                    report["image_digest"]
                                        .as_str()
                                        .unwrap_or_default()
                                        .strip_prefix("sha256:")
                                        .unwrap_or_default(),
                                )
                                .display()
                                .to_string()))
                && generation["tools_commit"] == report["tools_commit"]
                && settings
                    .template_dir
                    .as_ref()
                    .is_some_and(|path| generation["template_dir"] == path.display().to_string())
                && settings
                    .socket_dir
                    .as_ref()
                    .is_some_and(|path| generation["socket_dir"] == path.display().to_string())
        });
    if installed_generation.is_some() && !installed_match {
        return Err(LaneError::input(
            "install-generation",
            "installed generation differs from the image report or settings",
        ));
    }
    if installed_match {
        for vendor in &programs.vendors {
            let program = payload::image_program(&Value::Object(programs.fields.clone()), *vendor)?;
            if prior
                .as_ref()
                .is_none_or(|report| report[vendor.program_key] != program)
                || settings
                    .backend_argv
                    .get(vendor.name)
                    .is_some_and(|argv| argv.first() != Some(&program))
            {
                return Err(LaneError::input(
                    "backend-program",
                    format!(
                        "{} recorded or configured program differs from the measured image program",
                        vendor.name
                    ),
                ));
            }
        }
    }
    let mut probes = Vec::new();
    let mut reuse = false;
    let installed_image_available = installed_match;
    if installed_match {
        let current = settings
            .image_digest
            .as_ref()
            .ok_or_else(|| LaneError::operation("image-exists", "recorded image absent"))?;
        let exists_spec = child(
            &request.podman_bin,
            vec!["image".into(), "exists".into(), current.clone()],
            &environment,
            home,
            30,
            "image-exists",
        );
        probes.push(exists_spec.preview());
        if !image_exists(&exists_spec)? {
            return Err(LaneError::input(
                if repair {
                    "repair-image"
                } else {
                    "image-exists"
                },
                "pinned image is absent from local storage",
            ));
        }
        let inspect_spec = child(
            &request.podman_bin,
            vec![
                "image".into(),
                "inspect".into(),
                "--format".into(),
                "{{.Id}}".into(),
                current.clone(),
            ],
            &environment,
            home,
            30,
            "image-inspect",
        );
        probes.push(inspect_spec.preview());
        if installed_image_available
            && parsed_image_id(&checked_output(&inspect_spec, None)?)? != *current
        {
            return Err(LaneError::input(
                if repair {
                    "repair-image"
                } else {
                    "image-identity"
                },
                "local image ID differs from the recorded digest",
            ));
        }
    }
    let repair_pin = repair && matching_report_pins && !matching_source_pins;
    if (matching_pins || repair_pin) && !installed_match {
        let current = if repair_pin {
            prior
                .as_ref()
                .and_then(|report| report["image_digest"].as_str())
                .ok_or_else(|| LaneError::input("repair-image", "pinned image ID is absent"))?
        } else {
            settings
                .image_digest
                .as_deref()
                .ok_or_else(|| LaneError::operation("image-exists", "recorded image absent"))?
        };
        let exists_spec = child(
            &request.podman_bin,
            vec!["image".into(), "exists".into(), current.to_owned()],
            &environment,
            home,
            30,
            "image-exists",
        );
        probes.push(exists_spec.preview());
        if image_exists(&exists_spec)? {
            let current_inspect = child(
                &request.podman_bin,
                vec![
                    "image".into(),
                    "inspect".into(),
                    "--format".into(),
                    "{{.Id}}".into(),
                    current.to_owned(),
                ],
                &environment,
                home,
                30,
                "image-inspect",
            );
            probes.push(current_inspect.preview());
            reuse = parsed_image_id(&checked_output(&current_inspect, None)?)? == current;
        }
    }
    if repair && !reuse && !installed_image_available {
        return Err(LaneError::input(
            "repair-image",
            "pinned image is absent from local storage or its local ID differs",
        ));
    }
    if !reuse && !installed_image_available {
        let base_exists = child(
            &request.podman_bin,
            vec!["image".into(), "exists".into(), request.base_image.clone()],
            &environment,
            home,
            30,
            "image-exists",
        );
        probes.push(base_exists.preview());
        if !image_exists(&base_exists)? {
            return Err(LaneError::input(
                "build-input",
                format!(
                    "base image absent from local storage: {}",
                    request.base_image
                ),
            ));
        }
    }
    let action = if installed_image_available {
        "seed-settings"
    } else if reuse && repair_pin {
        "repair-pin"
    } else if reuse {
        "reuse"
    } else {
        "build"
    };
    let mut children = if reuse || installed_image_available {
        Vec::new()
    } else {
        vec![
            build_spec.preview(),
            inspect_spec.preview(),
            inventory_spec.preview(),
        ]
    };
    if settings.configures("claude") {
        if reuse || installed_image_available {
            let image = prior
                .as_ref()
                .and_then(|report| report["image_digest"].as_str())
                .ok_or_else(|| LaneError::input("build-report", "image digest is absent"))?;
            let (probe, runtime) = payload::probe_claude(request, home, image)?;
            probes.push(payload::claude_probe_spec(request, home, image)?.preview());
            if prior.as_ref().is_none_or(|report| {
                report["claude_exec_probe"] != probe || report["claude_runtime"] != runtime
            }) {
                return Err(LaneError::input(
                    "claude-image-probe",
                    "pinned image evidence differs from the build report",
                ));
            }
            programs.fields.insert("claude_exec_probe".into(), probe);
            programs.fields.insert("claude_runtime".into(), runtime);
        } else {
            children.push(
                payload::claude_probe_spec(request, home, "IMAGE_ID_FROM_INSPECT")?.preview(),
            );
        }
    }
    let mut hash_checks = vec![
        json!({"input":template_path,"spec":hash_command.preview()}),
        json!({"input":init_path,"spec":hash_command.preview()}),
    ];
    for vendor in &programs.vendors {
        hash_checks.push(
            json!({"input":programs.environment[vendor.bin_key],"spec":hash_command.preview()}),
        );
        if *vendor == payload::CODEX {
            hash_checks.push(json!({"input":request.codex_host_bin,"spec":hash_command.preview()}));
        }
    }
    let mut inputs = json!({"base_image":request.base_image,"base_sha256":request.base_image.rsplit_once("@sha256:").map(|(_, hash)| hash),"template_sha256":template_hash,"init_sha256":init_hash});
    if let Some(object) = inputs.as_object_mut() {
        object.extend(programs.pins.clone());
    }
    let mut preview = json!({
        "schema":1,"command":"build","dry_run":request.dry_run,"action":action,
        "template_source":template_path,"rendered_template":rendered,"inputs":inputs,
        "hash_checks":hash_checks,"probes_executed":probes,"children":children,
        "build_argv":if reuse || installed_image_available { Value::Null } else { json!(build_spec.argv) },
        "inspect_argv":if reuse || installed_image_available { Value::Null } else { json!(inspect_spec.argv) },
        "inventory_argv":if reuse || installed_image_available { Value::Null } else { json!(inventory_spec.argv) },
        "build_environment":environment,"context":if reuse || installed_image_available { Value::Null } else { json!(context) },
        "stale_contexts":stale,"stale_publications":stale_reports,"settings":settings_path,
        "tools_commit":option_env!("SUPERLOOP_TOOLS_COMMIT").unwrap_or("unrecorded"),
        "would_seed_settings":seed_keys,
        "recorded_install_matches":installed_match,"local_image_available":if installed_match { Value::Bool(installed_image_available) } else if reuse { Value::Bool(true) } else { Value::Null },"would_backfill_exec_probe":probe_backfill,"would_repair_image_pin":repair_pin && reuse,
    });
    if let Some(object) = preview.as_object_mut() {
        object.extend(programs.fields.clone());
        object.extend(programs.checks.clone());
    }
    if request.dry_run {
        return Ok(preview);
    }
    if installed_image_available {
        if seed_backend {
            let updated = programs.settings(&settings.source, None)?;
            publish_attempt(&settings_path, updated.as_bytes(), &attempt)?;
        }
        if probe_backfill && let Some(mut updated) = prior {
            updated["codex_exec_probe"] = programs.fields["codex_exec_probe"].clone();
            publish_attempt(
                &report_path,
                serde_json::to_vec_pretty(&updated)
                    .map_err(|error| LaneError::operation("build-report", error.to_string()))?
                    .as_slice(),
                &attempt,
            )?;
        }
        let mut result = json!({"schema":1,"command":"build","changed":seed_backend || probe_backfill,"action":"seed-settings","image_digest":settings.image_digest,"settings_written":seed_keys,"build_report_probe_written":probe_backfill,"prior_report":report_path,"recorded_install_matches":true,"local_image_available":true,"check":"installed generation and image input pins agree; local image exists with the recorded ID; image unchanged","wall_seconds":began.elapsed().as_secs_f64()});
        for vendor in &programs.vendors {
            result[vendor.program_key] = programs.fields[vendor.program_key].clone();
        }
        return Ok(result);
    }
    let _pinned_parent =
        crate::home::pin_parent(&context_parent, nix::unistd::Uid::effective().as_raw())?;
    let mut retired = retire_stale(&stale, &attempt)?;
    retired.extend(retire_stale(&stale_reports, &attempt)?);
    if reuse {
        let mut settings_written = Vec::new();
        if repair_pin {
            settings_written.push("image_digest");
        }
        if seed_backend {
            settings_written.extend(seed_keys.iter().map(String::as_str));
        }
        let corrected_pin = if repair_pin {
            Some(
                prior
                    .as_ref()
                    .and_then(|report| report["image_digest"].as_str())
                    .ok_or_else(|| LaneError::input("repair-image", "pinned image ID is absent"))?
                    .to_owned(),
            )
        } else {
            None
        };
        if seed_backend || repair_pin {
            let updated = programs.settings(&settings.source, corrected_pin.as_deref())?;
            publish_attempt(&settings_path, updated.as_bytes(), &attempt)?;
        }
        if probe_backfill && let Some(mut updated) = prior {
            updated["codex_exec_probe"] = programs.fields["codex_exec_probe"].clone();
            publish_attempt(
                &report_path,
                serde_json::to_vec_pretty(&updated)
                    .map_err(|error| LaneError::operation("build-report", error.to_string()))?
                    .as_slice(),
                &attempt,
            )?;
        }
        let mut result = json!({"schema":1,"command":"build","changed":seed_backend || probe_backfill || repair_pin,"action":if repair_pin {"repair-pin"} else {"reuse"},"image_digest":if repair_pin {json!(corrected_pin)} else {json!(settings.image_digest)},"settings_written":settings_written,"build_report_probe_written":probe_backfill,"prior_report":report_path,"retired_contexts":retired,"check":"input pins and installed image ID agree","wall_seconds":began.elapsed().as_secs_f64()});
        for vendor in &programs.vendors {
            result[vendor.program_key] = programs.fields[vendor.program_key].clone();
        }
        return Ok(result);
    }
    DirBuilder::new()
        .mode(0o700)
        .create(&context)
        .map_err(|error| {
            LaneError::input("build-context", format!("{}: {error}", context.display()))
        })?;
    write_private(&context.join("Containerfile"), rendered.as_bytes())?;
    for (name, bytes) in &programs.files {
        write_private(&context.join(name), bytes)?;
        fs::set_permissions(context.join(name), fs::Permissions::from_mode(0o555))
            .map_err(|error| LaneError::operation("build-context", error.to_string()))?;
    }
    write_private(&context.join("box-init"), &init_bytes)?;
    fs::set_permissions(context.join("box-init"), fs::Permissions::from_mode(0o555))
        .map_err(|error| LaneError::operation("build-context", error.to_string()))?;
    let log_path = settings_path.with_file_name("image-build.log");
    let build = run_child_with_log(&build_spec, None, Some((&log_path, &attempt)))?;
    let mut log_bytes = build.stdout.clone();
    log_bytes.extend_from_slice(&build.stderr);
    publish_attempt(&log_path, &log_bytes, &attempt)?;
    if !build.status.success() {
        return Err(LaneError::operation(
            "image-build",
            format!(
                "container build exited {}; log {}; context {}",
                build.status,
                log_path.display(),
                context.display()
            ),
        ));
    }
    let image_digest = parsed_image_id(&checked_output(&inspect_spec, None)?)?;
    if repair {
        let pinned = prior
            .as_ref()
            .and_then(|report| report["image_digest"].as_str())
            .ok_or_else(|| LaneError::input("repair-image", "pinned build image ID is absent"))?;
        if image_digest != pinned {
            return Err(LaneError::input(
                "repair-image",
                "rebuilt image ID differs from the pinned build report",
            ));
        }
    }
    inventory_spec.argv[6].clone_from(&image_digest);
    let inventory = checked_output(&inventory_spec, None)?;
    if inventory.trim().is_empty() {
        return Err(LaneError::operation(
            "image-inventory",
            "package inventory is empty",
        ));
    }
    if settings.configures("claude") {
        let (probe, runtime) = payload::probe_claude(request, home, &image_digest)?;
        programs.fields.insert("claude_exec_probe".into(), probe);
        programs.fields.insert("claude_runtime".into(), runtime);
    }
    let old_digest = settings.image_digest;
    let updated = programs.settings(&settings.source, Some(&image_digest))?;
    let mut settings_written = vec!["image_digest"];
    if seed_backend {
        settings_written.extend(seed_keys.iter().map(String::as_str));
    }
    let mut result = json!({
        "schema":1,"command":"build","changed":true,"action":"build","old_image_digest":old_digest,
        "image_digest":image_digest,"settings_written":settings_written,"base_image":request.base_image,
        "template_sha256":template_hash,"init_sha256":init_hash,
        "package_inventory":inventory.lines().collect::<Vec<_>>(),
        "tools_commit":option_env!("SUPERLOOP_TOOLS_COMMIT").unwrap_or("unrecorded"),
        "build_environment":{"podman_environment":environment,"podman_bin":request.podman_bin,"template_dir":request.template_dir},"children":children,"retired_contexts":retired,
        "check":"build and bare image ID inspect completed; package inventory is nonempty",
        "log":log_path,"wall_seconds":began.elapsed().as_secs_f64(),
    });
    programs.add_fields(&mut result);
    if let Some(object) = result["build_environment"].as_object_mut() {
        object.extend(programs.environment.clone());
    }
    publish_attempt(
        &report_path,
        serde_json::to_string_pretty(&result)
            .map_err(|error| LaneError::operation("build-report", error.to_string()))?
            .as_bytes(),
        &attempt,
    )?;
    publish_attempt(&settings_path, updated.as_bytes(), &attempt)?;
    fs::remove_dir_all(&context).map_err(|error| {
        LaneError::operation(
            "build-context",
            format!("cleanup {}: {error}", context.display()),
        )
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{
        BuildRequest, CODEX_EXEC_OPTIONS, ChildSpec, check_exec_probe, checked_output, child,
        codex_image_program, executable_snapshot, hash_bytes, hash_spec, parsed_image_id, run,
        run_checked_with_private_launch, run_child, run_child_with_log, run_child_with_start,
        run_repair, sha256, source_bytes, standalone_codex,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn executable(path: &std::path::Path, body: &str) {
        crate::fixture_exec::write_executable(path, format!("#!/bin/sh\n{body}\n").as_bytes())
            .expect("closed and synced fixture script");
    }

    /// ´test:unit:door-listener-handoff-does-not-inherit-on-exec´
    #[test]
    fn door_listener_handoff_does_not_inherit_on_exec() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let directory: OwnedFd = fs::File::open(fixture.path()).expect("directory").into();
        let socket =
            crate::fixture_exec::fixture_socket_path(fixture.path().join("capability.sock"));
        let listener = UnixListener::bind(socket).expect("fixture listener");
        let spec = ChildSpec {
            program: PathBuf::from("/bin/sh"),
            argv: Vec::new(),
            environment: BTreeMap::new(),
            cwd: fixture.path().to_path_buf(),
            timeout_seconds: 5,
            name: "door-handoff-fixture",
            inherited_fd: None,
            private_directory_stdin: None,
            private_extra_fds: Vec::new(),
        }
        .with_private_door_listener(&directory, &listener)
        .expect("held handoff descriptors");
        let directory_fd = spec
            .private_directory_stdin
            .as_ref()
            .expect("directory handoff")
            .as_raw_fd();
        let listener_fd = spec.private_extra_fds[0].as_raw_fd();
        assert!(directory_fd >= 5 && listener_fd >= 5);
        let check = format!(
            "test ! -e /proc/self/fd/{directory_fd} && test ! -e /proc/self/fd/{listener_fd}"
        );
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(check)
            .status()
            .expect("unrelated child");
        assert!(status.success(), "door descriptors survived exec");
    }

    /// ´test:unit:private-directory-stdin-does-not-inherit-a-second-descriptor´
    #[test]
    fn private_directory_stdin_does_not_inherit_a_second_descriptor() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let directory: OwnedFd = fs::File::open(fixture.path()).expect("directory").into();
        let spec = ChildSpec {
            program: PathBuf::from("/usr/bin/dash"),
            argv: vec![
                "-c".into(),
                r#"test -d /proc/self/fd/0 || exit 1
root=$(/usr/bin/stat -Lc '%d:%i' /proc/self/fd/0)
for fd in /proc/self/fd/*; do
  test "$fd" = /proc/self/fd/0 && continue
  test -e "$fd" || continue
  test "$(/usr/bin/stat -Lc '%d:%i' "$fd")" != "$root" || exit 1
done
"#
                .into(),
            ],
            environment: BTreeMap::new(),
            cwd: fixture.path().to_path_buf(),
            timeout_seconds: 5,
            name: "private-directory-stdin-fixture",
            inherited_fd: None,
            private_directory_stdin: None,
            private_extra_fds: Vec::new(),
        }
        .with_private_directory(&directory)
        .expect("direct directory handoff");
        assert!(spec.private_extra_fds.is_empty());
        let result = run_child(&spec, None).expect("direct directory route");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    /// ´test:unit:private-install-handoff-does-not-inherit-on-exec´
    #[test]
    fn private_install_handoff_does_not_inherit_on_exec() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected configuration");
        let home: OwnedFd = fs::File::open(fixture.path())
            .expect("home directory")
            .into();
        let lock = crate::install::lock_loop_config(fixture.path(), false).expect("install lock");
        let source_path = fixture.path().join("stub");
        fs::write(&source_path, b"fixture stub").expect("stub source");
        let source = fs::File::open(&source_path).expect("stub source descriptor");
        let directories = ["template", "libexec", "sockets"].map(|name| {
            let path = fixture.path().join(name);
            fs::create_dir(&path).expect("fixture directory");
            fs::File::open(path).expect("fixture descriptor")
        });
        let spec = ChildSpec {
            program: PathBuf::from("/bin/sh"),
            argv: Vec::new(),
            environment: BTreeMap::new(),
            cwd: fixture.path().to_path_buf(),
            timeout_seconds: 5,
            name: "install-handoff-fixture",
            inherited_fd: None,
            private_directory_stdin: None,
            private_extra_fds: Vec::new(),
        }
        .with_private_door_directories(
            &home,
            &lock,
            &source,
            &directories[0],
            &directories[1],
            &directories[2],
        )
        .expect("held install descriptors");
        assert_eq!(
            spec.argv,
            [
                "--verified-home-fd",
                "0",
                "--verified-install-lock-fd",
                "1",
                "--verified-stub-fd",
                "2",
                "--verified-template-fd",
                "3",
                "--verified-libexec-fd",
                "4",
                "--verified-socket-root-fd",
                "5",
            ]
        );
        let descriptors = std::iter::once(
            spec.private_directory_stdin
                .as_ref()
                .expect("home handoff")
                .as_raw_fd(),
        )
        .chain(
            spec.private_extra_fds
                .iter()
                .map(std::os::fd::AsRawFd::as_raw_fd),
        )
        .collect::<Vec<_>>();
        assert_eq!(descriptors.len(), 6);
        assert!(descriptors.iter().all(|fd| *fd >= 5));
        let words = descriptors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let check = format!("for fd in {words}; do test ! -e /proc/self/fd/$fd || exit 1; done");
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(check)
            .status()
            .expect("unrelated child");
        assert!(status.success(), "install descriptors survived exec");
    }

    /// ´test:unit:hash-pin-refusal-hides-symlink-kernel-detail´
    #[test]
    fn hash_pin_refusal_hides_symlink_kernel_detail() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let link = fixture.path().join("sha256sum");
        std::os::unix::fs::symlink("/usr/bin/true", &link).expect("link");
        let mut spec = hash_spec(fixture.path());
        spec.program = link;
        let error = hash_bytes(b"fixture", &spec).expect_err("symlink pin refusal");
        assert_eq!(error.status, 2);
        assert_eq!(
            error.line(),
            "hash-pin: the hashing program must be an owner-controlled regular executable reached without symlinks; run superloop-lane on the host with that pin"
        );
    }

    struct HeldWriterState {
        child: Option<Child>,
        closed: bool,
    }

    struct HeldWriterGuard(Arc<Mutex<HeldWriterState>>);

    impl HeldWriterGuard {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(HeldWriterState {
                child: None,
                closed: false,
            })))
        }

        fn close(&self) {
            let child = {
                let mut state = self.0.lock().expect("writer lock");
                state.closed = true;
                state.child.take()
            };
            if let Some(mut child) = child {
                let _ignored = child.kill();
                let _ignored = child.wait();
            }
        }
    }

    impl Drop for HeldWriterGuard {
        fn drop(&mut self) {
            self.close();
        }
    }

    /// ´test:unit:codex-image-program-follows-the-measured-copy-destination´
    #[test]
    fn codex_image_program_follows_the_measured_copy_destination() {
        assert_eq!(
            codex_image_program("FROM base\nCOPY codex /usr/libexec/superloop/codex\n")
                .expect("one absolute destination"),
            "/usr/libexec/superloop/codex"
        );
        for source in [
            "COPY codex codex\n",
            "COPY codex /usr/../tmp/codex\n",
            "COPY codex /one\nCOPY codex /two\n",
        ] {
            assert_eq!(
                codex_image_program(source)
                    .expect_err("invalid destination")
                    .kind,
                "build-input"
            );
        }
    }

    /// ´test:unit:private-launch-child-inherits-external-anchors-across-exec´
    #[test]
    fn private_launch_child_inherits_external_anchors_across_exec() {
        let temp = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let home = temp.path().join("home");
        let runs = temp.path().join("runs");
        let letters = temp.path().join("letters");
        for path in [&home, &runs, &letters] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let program = temp.path().join("private-child");
        executable(
            &program,
            "python3 -c 'import array, os, socket; s=socket.socket(fileno=0); data, ancillary, flags, address=s.recvmsg(1, socket.CMSG_SPACE(12)); fds=array.array(\"i\"); fds.frombytes(ancillary[0][2]); assert data == b\"\\x01\" and len(fds) == 3; assert all(os.path.isdir(\"/proc/self/fd/%d\" % fd) for fd in fds); print(\"bound\")'",
        );
        let home_fd: OwnedFd = fs::File::open(&home).expect("home descriptor").into();
        let runs_fd: OwnedFd = fs::File::open(&runs).expect("runs descriptor").into();
        let letter_fd: OwnedFd = fs::File::open(&letters).expect("letter descriptor").into();
        let output = run_checked_with_private_launch(
            &program,
            vec!["private".into()],
            &BTreeMap::new(),
            &home,
            5,
            "private-child",
            &home_fd,
            &runs,
            &runs_fd,
            Some((&letters, &letter_fd)),
        )
        .expect("inherited external directory descriptors");
        assert_eq!(output, "bound\n");
    }

    fn fixture() -> (TempDir, BuildRequest) {
        let temp = TempDir::new_in("/tmp").expect("temporary fixture");
        let home = temp.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("private fixture");
        fs::create_dir_all(home.join(".config/loops/alpha")).expect("settings parent");
        for path in [
            home.join(".config"),
            home.join(".config/loops"),
            home.join(".config/loops/alpha"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private config");
        }
        fs::create_dir_all(home.join(".cache/tmp")).expect("context parent");
        for path in [home.join(".cache"), home.join(".cache/tmp")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private cache");
        }
        fs::write(home.join(".config/loops/registry.toml"), "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"work/alpha\" }]\n").expect("registry");
        let settings = home.join(".config/loops/alpha/workers.toml");
        fs::write(&settings, "vendor_hosts = { codex = [] }\n").expect("settings");
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
        let codex = home.join("codex");
        executable(
            &codex,
            "case \"$1 $2\" in 'exec --help') printf '%s\\n' '  --json' '  --sandbox' '  --add-dir' '  --skip-git-repo-check' '  -C, --cd' '  -o, --output-last-message';; *) printf 'codex-cli 0.1.0\\n';; esac",
        );
        let codex_host = home.join("codex-code-mode-host");
        executable(&codex_host, "printf 'Code mode host fixture\\n'");
        let podman = home.join("podman");
        executable(
            &podman,
            &format!(
                "printf '%s %s\\n' \"$1\" \"$7\" >> '{}'\ncase \"$1 $2\" in\n  'image exists') exit 0 ;;\n  'image inspect') printf '{}\\n' ;;\n  'build --pull=never') exit 0 ;;\n  'run --rm') printf 'ca-certificates 1\\ngit 2\\n' ;;\nesac",
                home.join("calls").display(),
                "b".repeat(64)
            ),
        );
        let request = BuildRequest {
            loop_name: "alpha".into(),
            claude: None,
            base_image: format!("registry.example/base@sha256:{}", "a".repeat(64)),
            codex_sha256: sha256(&codex).expect("codex hash"),
            codex_bin: codex,
            codex_host_sha256: sha256(&codex_host).expect("host hash"),
            codex_host_bin: codex_host,
            codex_version: "0.1.0".into(),
            codex_source: "https://registry.example/codex-0.1.0".into(),
            podman_bin: podman,
            template_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"),
            dry_run: true,
        };
        (temp, request)
    }

    /// ´test:unit:build-inspect-accepts-documented-bare-id´
    #[test]
    fn build_inspect_accepts_documented_bare_id() {
        assert_eq!(
            parsed_image_id(&format!("{}\n", "b".repeat(64))).expect("bare ID"),
            format!("sha256:{}", "b".repeat(64))
        );
        assert!(parsed_image_id(&format!("sha256:{}\n", "b".repeat(64))).is_err());
    }

    /// ´test:unit:build-dry-run-exposes-branch-inputs-environment-and-exact-argv´
    #[test]
    fn build_dry_run_exposes_branch_inputs_environment_and_exact_argv() {
        let (temp, request) = fixture();
        let preview = run(temp.path(), &request).expect("preview");
        assert_eq!(preview["action"], "build");
        assert_eq!(preview["build_argv"][1], "--pull=never");
        assert_eq!(preview["build_argv"][2], "--no-cache");
        assert_eq!(preview["build_argv"][3], "--network=none");
        assert_eq!(preview["inputs"]["codex_sha256"], request.codex_sha256);
        assert!(
            preview["inputs"]["init_sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64)
        );
        assert_eq!(preview["build_environment"]["PATH"], "/usr/bin:/bin");
        assert_eq!(
            preview["codex_exec_probe"]["argv"],
            json!(["exec", "--help"])
        );
        assert_eq!(
            preview["codex_exec_probe"]["required_options"],
            json!(CODEX_EXEC_OPTIONS)
        );
        assert!(
            preview["rendered_template"]
                .as_str()
                .expect("template")
                .contains(&request.base_image)
        );
        assert!(
            !temp
                .path()
                .join(".config/loops/alpha/image-build.json")
                .exists()
        );
    }

    /// ´test:unit:build-refuses-pinned-codex-without-exec-runtime-options´
    #[test]
    fn build_refuses_pinned_codex_without_exec_runtime_options() {
        let (temp, mut request) = fixture();
        executable(
            &request.codex_bin,
            "case \"$1 $2\" in 'exec --help') printf '%s\\n' '  --json' '  --sandbox';; *) printf 'codex-cli 0.1.0\\n';; esac",
        );
        request.codex_sha256 = sha256(&request.codex_bin).expect("new Codex hash");
        let error = run(temp.path(), &request).expect_err("missing exec options");
        assert_eq!(error.kind, "codex-exec-help");
        assert!(error.line().contains("--add-dir"));
    }

    /// ´test:unit:build-refuses-missing-or-changed-code-mode-host´
    #[test]
    fn build_refuses_missing_or_changed_code_mode_host() {
        let (temp, mut request) = fixture();
        fs::remove_file(&request.codex_host_bin).expect("remove host fixture");
        assert_eq!(
            run(temp.path(), &request).expect_err("missing host").kind,
            "build-input"
        );
        executable(&request.codex_host_bin, "printf 'changed host\\n'");
        assert_eq!(
            run(temp.path(), &request)
                .expect_err("changed host pin")
                .kind,
            "build-input"
        );
        request.codex_host_sha256 = sha256(&request.codex_host_bin).expect("new host hash");
        assert!(run(temp.path(), &request).is_ok());
    }

    /// ´test:unit:launch-probe-refuses-missing-companion´
    #[test]
    fn launch_probe_refuses_missing_companion() {
        let help = "  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n";
        let report = json!({"codex_sha256":"a","codex_host_sha256":"b","codex_host_probe":{"argv":["--help"],"stdout":"host help","sha256":"b"},"codex_exec_probe":{"argv":["exec","--help"],"stdout":help,"required_options":CODEX_EXEC_OPTIONS,"codex_sha256":"a","companions":[]}});
        let error = check_exec_probe(&report, &json!(["codex", "exec", "--json"]))
            .expect_err("missing image companion");
        assert_eq!(error.kind, "codex-companion");
    }

    /// ´test:unit:launch-probe-refuses-option-not-in-pinned-exec-help´
    #[test]
    fn launch_probe_refuses_option_not_in_pinned_exec_help() {
        let help = "  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n";
        let report = json!({"codex_sha256":"a","codex_host_sha256":"b","codex_host_probe":{"argv":["--help"],"stdout":"Code mode host fixture","sha256":"b"},"codex_exec_probe":{"argv":["exec","--help"],"stdout":help,"required_options":CODEX_EXEC_OPTIONS,"codex_sha256":"a","companions":[{"name":"codex-code-mode-host","path":super::CODEX_HOST_PATH,"sha256":"b"}]}});
        check_exec_probe(
            &report,
            &json!(["codex", "exec", "--json", "--sandbox", "workspace-write"]),
        )
        .expect("supported vector");
        let error = check_exec_probe(
            &report,
            &json!(["codex", "exec", "--ask-for-approval", "never"]),
        )
        .expect_err("unsupported vector");
        assert_eq!(error.kind, "codex-exec-help");
        assert!(error.line().contains("--ask-for-approval"));
    }

    /// ´test:unit:build-records-bare-id-without-worker-allocation´
    #[test]
    fn build_records_bare_id_without_worker_allocation() {
        let (temp, mut request) = fixture();
        assert!(!temp.path().join(".config/loops/allocations.toml").exists());
        request.dry_run = false;
        let result = run(temp.path(), &request).expect("build");
        assert_eq!(result["image_digest"], format!("sha256:{}", "b".repeat(64)));
        assert!(!temp.path().join(".config/loops/allocations.toml").exists());
        request.dry_run = true;
        let preview = run(temp.path(), &request).expect("repeat preview");
        assert_eq!(preview["action"], "reuse");
        assert!(preview["build_argv"].is_null());
        request.dry_run = false;
        let repeat = run(temp.path(), &request).expect("repeat");
        assert_eq!(repeat["changed"], false);
    }

    /// ´test:unit:repair-restores-a-pinned-image-id-without-rebuilding´
    #[test]
    fn repair_restores_a_pinned_image_id_without_rebuilding() {
        let (temp, mut request) = fixture();
        request.dry_run = false;
        run(temp.path(), &request).expect("initial build");
        let pinned: Value = serde_json::from_slice(
            &fs::read(temp.path().join(".config/loops/alpha/image-build.json"))
                .expect("build report"),
        )
        .expect("pinned report");
        let settings_path = temp.path().join(".config/loops/alpha/workers.toml");
        let recorded = fs::read_to_string(&settings_path).expect("recorded settings");
        let drifted = recorded.replace(
            &format!("sha256:{}", "b".repeat(64)),
            &format!("sha256:{}", "c".repeat(64)),
        );
        fs::write(&settings_path, &drifted).expect("drifted pin");
        request.dry_run = true;
        let preview =
            run_repair(temp.path(), &request, &pinned, &Value::Null).expect("repair preview");
        assert_eq!(preview["action"], "repair-pin");
        assert_eq!(preview["would_repair_image_pin"], true);
        assert_eq!(
            fs::read_to_string(&settings_path).expect("preview settings"),
            drifted
        );
        request.dry_run = false;
        let fixed =
            run_repair(temp.path(), &request, &pinned, &Value::Null).expect("repair image pin");
        assert_eq!(fixed["changed"], true);
        assert_eq!(fixed["action"], "repair-pin");
        assert_eq!(
            fs::read_to_string(&settings_path).expect("corrected settings"),
            recorded
        );
        assert_eq!(
            run_repair(temp.path(), &request, &pinned, &Value::Null).expect("repeat")["changed"],
            false
        );
    }

    /// ´test:unit:repair-refuses-missing-image-before-any-build-write´
    #[test]
    fn repair_refuses_missing_image_before_any_build_write() {
        let (temp, mut request) = fixture();
        request.dry_run = false;
        run(temp.path(), &request).expect("initial build");
        let report_path = temp.path().join(".config/loops/alpha/image-build.json");
        let pinned_bytes = fs::read(&report_path).expect("pinned report");
        let pinned: Value = serde_json::from_slice(&pinned_bytes).expect("report JSON");
        let log_path = temp.path().join(".config/loops/alpha/image-build.log");
        let log_before = fs::read(&log_path).expect("build log");
        let context_parent = temp.path().join(".cache/tmp");
        let contexts_before = fs::read_dir(&context_parent)
            .expect("context parent")
            .count();
        let marker = temp.path().join("unexpected-build");
        executable(
            &request.podman_bin,
            &format!(
                "case \"$1 $2\" in\n  'image exists') case \"$3\" in sha256:*) exit 1 ;; *) exit 0 ;; esac ;;\n  'image inspect') printf '{}\\n' ;;\n  'build --pull=never') touch '{}' ;;\n  'run --rm') printf 'git 2\\n' ;;\nesac",
                "c".repeat(64),
                marker.display()
            ),
        );
        let settings_path = temp.path().join(".config/loops/alpha/workers.toml");
        let before = fs::read(&settings_path).expect("settings before repair");
        request.dry_run = true;
        assert_eq!(
            run_repair(temp.path(), &request, &pinned, &Value::Null)
                .expect_err("preview refusal")
                .kind,
            "repair-image"
        );
        request.dry_run = false;
        let error = run_repair(temp.path(), &request, &pinned, &Value::Null)
            .expect_err("missing pinned image");
        assert_eq!(error.kind, "repair-image");
        assert!(!marker.exists(), "build child never runs");
        assert_eq!(
            fs::read_dir(&context_parent)
                .expect("context parent")
                .count(),
            contexts_before
        );
        assert_eq!(
            fs::read(&log_path).expect("build log after refusal"),
            log_before
        );
        assert_eq!(
            fs::read(&report_path).expect("report after refusal"),
            pinned_bytes
        );
        assert_eq!(
            fs::read(&settings_path).expect("settings after refusal"),
            before
        );
        executable(
            &request.podman_bin,
            &format!(
                "case \"$1 $2\" in\n  'image exists') exit 0 ;;\n  'image inspect') printf '{}\\n' ;;\n  'build --pull=never') touch '{}' ;;\nesac",
                "c".repeat(64),
                marker.display()
            ),
        );
        request.dry_run = true;
        assert_eq!(
            run_repair(temp.path(), &request, &pinned, &Value::Null)
                .expect_err("mismatched image preview")
                .kind,
            "repair-image"
        );
        request.dry_run = false;
        assert_eq!(
            run_repair(temp.path(), &request, &pinned, &Value::Null)
                .expect_err("mismatched image")
                .kind,
            "repair-image"
        );
        assert!(!marker.exists(), "mismatched image never builds");
        assert_eq!(
            fs::read_dir(&context_parent)
                .expect("context parent")
                .count(),
            contexts_before
        );
        assert_eq!(
            fs::read(&log_path).expect("build log after mismatch"),
            log_before
        );
        assert_eq!(
            fs::read(&settings_path).expect("settings after mismatch"),
            before
        );
    }

    /// ´test:unit:repair-names-measured-template-drift-before-image-probe´
    #[test]
    fn repair_names_measured_template_drift_before_image_probe() {
        let (temp, mut request) = fixture();
        let templates = temp.path().join("templates");
        fs::create_dir(&templates).expect("template directory");
        for entry in fs::read_dir(&request.template_dir).expect("source templates") {
            let entry = entry.expect("template entry");
            fs::copy(entry.path(), templates.join(entry.file_name())).expect("fixture template");
        }
        request.template_dir = templates.clone();
        request.dry_run = false;
        run(temp.path(), &request).expect("initial build");
        let report_path = temp.path().join(".config/loops/alpha/image-build.json");
        let report_bytes = fs::read(&report_path).expect("report bytes");
        let pinned: Value = serde_json::from_slice(&report_bytes).expect("pinned report");
        let settings_path = temp.path().join(".config/loops/alpha/workers.toml");
        let settings_before = fs::read(&settings_path).expect("settings bytes");
        let log_path = temp.path().join(".config/loops/alpha/image-build.log");
        let log_before = fs::read(&log_path).expect("build log");
        let calls_path = temp.path().join("calls");
        let calls_before = fs::read(&calls_path).expect("podman calls");
        let context_parent = temp.path().join(".cache/tmp");
        let contexts_before = fs::read_dir(&context_parent).expect("contexts").count();
        let containerfile = templates.join("Containerfile");
        let mut changed = fs::read(&containerfile).expect("template bytes");
        changed.extend_from_slice(b"\n# fixture drift\n");
        fs::write(&containerfile, changed).expect("changed template");
        for dry_run in [true, false] {
            request.dry_run = dry_run;
            let error = run_repair(temp.path(), &request, &pinned, &Value::Null)
                .expect_err("measured template differs");
            assert_eq!(error.kind, "repair-build-report");
            assert!(error.detail.contains("template or init"));
        }
        assert_eq!(
            fs::read(&calls_path).expect("podman calls after"),
            calls_before
        );
        assert_eq!(fs::read(&report_path).expect("report after"), report_bytes);
        assert_eq!(
            fs::read(&settings_path).expect("settings after"),
            settings_before
        );
        assert_eq!(fs::read(&log_path).expect("log after"), log_before);
        assert_eq!(
            fs::read_dir(&context_parent)
                .expect("contexts after")
                .count(),
            contexts_before
        );
    }

    /// ´test:unit:build-rebuilds-when-recorded-image-is-absent´
    #[test]
    fn build_rebuilds_when_recorded_image_is_absent() {
        let (temp, mut request) = fixture();
        request.dry_run = false;
        run(temp.path(), &request).expect("first build");
        executable(
            &request.podman_bin,
            &format!(
                "case \"$1 $2\" in\n  'image exists') case \"$3\" in sha256:*) exit 1 ;; *) exit 0 ;; esac ;;\n  'image inspect') printf '{}\\n' ;;\n  'build --pull=never') exit 0 ;;\n  'run --rm') printf 'git 2\\n' ;;\nesac",
                "b".repeat(64)
            ),
        );
        request.dry_run = true;
        let preview = run(temp.path(), &request).expect("missing image preview");
        assert_eq!(preview["action"], "build");
        request.dry_run = false;
        assert_eq!(
            run(temp.path(), &request).expect("rebuild")["changed"],
            true
        );
    }

    /// ´test:unit:build-refuses-template-injection-and-missing-inputs´
    #[test]
    fn build_refuses_template_injection_and_missing_inputs() {
        let (temp, mut request) = fixture();
        request.base_image.insert(19, '\n');
        let error = run(temp.path(), &request).expect_err("newline image reference");
        assert_eq!(error.status, 2);
        assert!(error.line().contains("base image"));
        request.base_image = format!("registry.example/base@sha256:{}", "a".repeat(64));
        request.podman_bin = temp.path().join("absent-podman");
        let missing = run(temp.path(), &request).expect_err("missing program");
        assert_eq!(missing.kind, "owner-program");
        assert!(missing.line().contains("absent-podman"));
        request.podman_bin = temp.path().join("podman");
        request.template_dir = temp.path().join("absent-template");
        assert!(
            run(temp.path(), &request)
                .expect_err("missing template")
                .line()
                .contains("image template")
        );
    }

    /// ´test:unit:build-retires-interrupted-context-and-publication´
    #[test]
    fn build_retires_interrupted_context_and_publication() {
        let (temp, mut request) = fixture();
        let context = temp.path().join(".cache/tmp/superloop-lane-build-alpha");
        fs::create_dir(&context).expect("abandoned context");
        fs::write(context.join("Containerfile"), "interrupted").expect("partial context");
        let publication = temp.path().join(".config/loops/alpha/image-build.tmp");
        fs::write(&publication, "interrupted").expect("partial report");
        let preview = run(temp.path(), &request).expect("recovery preview");
        assert_eq!(
            preview["stale_contexts"]
                .as_array()
                .expect("contexts")
                .len(),
            1
        );
        assert_eq!(
            preview["stale_publications"]
                .as_array()
                .expect("publications")
                .len(),
            1
        );
        assert!(context.exists());
        request.dry_run = false;
        let result = run(temp.path(), &request).expect("recovery build");
        assert_eq!(
            result["retired_contexts"]
                .as_array()
                .expect("retired")
                .len(),
            2
        );
        assert!(!context.exists());
        assert!(!publication.exists());
        for retired in result["retired_contexts"].as_array().expect("retired") {
            assert!(PathBuf::from(retired.as_str().expect("path")).exists());
        }
    }

    /// ´test:unit:build-children-have-stream-and-time-limits´
    #[test]
    fn build_children_have_stream_and_time_limits() {
        let temp = TempDir::new_in("/tmp").expect("temporary fixture");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let program = temp.path().join("child");
        let spec = |seconds| ChildSpec {
            program: PathBuf::from("/usr/bin/bash"),
            argv: vec![program.display().to_string()],
            environment: BTreeMap::new(),
            cwd: temp.path().to_path_buf(),
            timeout_seconds: seconds,
            name: "fixture-child",
            inherited_fd: None,
            private_directory_stdin: None,
            private_extra_fds: Vec::new(),
        };
        executable(&program, "head -c 2097153 /dev/zero");
        assert!(
            run_child(&spec(30), None)
                .expect_err("stdout limit")
                .line()
                .contains("output limit")
        );
        executable(&program, "head -c 2097153 /dev/zero >&2");
        assert!(
            run_child(&spec(30), None)
                .expect_err("stderr limit")
                .line()
                .contains("output limit")
        );
        executable(&program, "sleep 2");
        assert!(
            run_child(&spec(1), None)
                .expect_err("time limit")
                .line()
                .contains("time limit")
        );
        executable(&program, "sleep 30 & exit 0");
        let began = std::time::Instant::now();
        let mut end = super::ChildEnd::default();
        assert!(
            super::run_child_with_end(&spec(1), None, None, |_| Ok(()), &mut end)
                .expect_err("descendant pipe holder")
                .line()
                .contains("time limit")
        );
        assert!(
            end.wall.is_none(),
            "draining an exited child is not a wall end"
        );
        assert!(began.elapsed() < std::time::Duration::from_secs(5));
    }

    /// ´test:unit:build-runner-bounds-retained-pipe-after-stop´
    #[test]
    fn build_runner_bounds_retained_pipe_after_stop() {
        let temp = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let script = temp.path().join("stop-stand-in");
        executable(
            &script,
            "printf ready > \"$TEST_READY\"; while [ ! -e \"$TEST_RELEASE\" ]; do sleep 0.01; done; exit 0",
        );
        let ready = temp.path().join("ready");
        let release = temp.path().join("release");
        let environment = BTreeMap::from([
            ("TEST_READY".into(), ready.display().to_string()),
            ("TEST_RELEASE".into(), release.display().to_string()),
        ]);
        let spec = ChildSpec {
            program: PathBuf::from("/usr/bin/bash"),
            argv: vec![script.display().to_string()],
            environment,
            cwd: temp.path().to_path_buf(),
            timeout_seconds: 1,
            name: "container-stop",
            inherited_fd: None,
            private_directory_stdin: None,
            private_extra_fds: Vec::new(),
        };
        let holder = HeldWriterGuard::new();
        let held = Arc::clone(&holder.0);
        let (published, publication) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            run_child_with_start(&spec, None, None, |pid| {
                let ready_deadline = Instant::now() + Duration::from_secs(5);
                while !ready.exists() && Instant::now() < ready_deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !ready.exists() {
                    return Err(crate::error::LaneError::operation(
                        "fixture",
                        "child did not signal readiness",
                    ));
                }
                let writer = fs::OpenOptions::new()
                    .write(true)
                    .open(format!("/proc/{pid}/fd/1"))
                    .map_err(|error| {
                        crate::error::LaneError::operation("fixture", error.to_string())
                    })?;
                let child = Command::new("/bin/sleep")
                    .arg0("r002d23-fixture-holder")
                    .arg("30")
                    .process_group(0)
                    .stdout(Stdio::from(writer))
                    .spawn()
                    .map_err(|error| {
                        crate::error::LaneError::operation("fixture", error.to_string())
                    })?;
                let mut child = Some(child);
                let closed = {
                    let mut state = held.lock().expect("holder lock");
                    if state.closed {
                        true
                    } else {
                        state.child = child.take();
                        false
                    }
                };
                if closed && let Some(mut child) = child {
                    let _ignored = child.kill();
                    let _ignored = child.wait();
                }
                let _ = published.send(());
                fs::write(&release, b"").map_err(|error| {
                    crate::error::LaneError::operation("fixture", error.to_string())
                })
            })
        });
        let handoff = publication.recv_timeout(Duration::from_secs(5)).is_ok();
        let began = Instant::now();
        while !runner.is_finished() && began.elapsed() < Duration::from_secs(9) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let bounded = runner.is_finished();
        holder.close();
        let result = runner.join().expect("runner");
        assert!(handoff, "holder was published before the bound began");
        let error = result.expect_err("timeout refusal");
        assert!(bounded, "runner exceeded its reader bound");
        assert_eq!(error.kind, "container-stop");
        assert!(error.detail.contains("time limit"));
    }

    /// ´test:unit:build-limit-keeps-bounded-log´
    #[test]
    fn build_limit_keeps_bounded_log() {
        let temp = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let program = temp.path().join("child");
        executable(&program, "printf 'before deadline\\n'; sleep 2");
        let spec = ChildSpec {
            program: PathBuf::from("/usr/bin/bash"),
            argv: vec![program.display().to_string()],
            environment: BTreeMap::new(),
            cwd: temp.path().to_path_buf(),
            timeout_seconds: 1,
            name: "image-build",
            inherited_fd: None,
            private_directory_stdin: None,
            private_extra_fds: Vec::new(),
        };
        let log = temp.path().join("image-build.log");
        assert!(
            run_child_with_log(&spec, None, Some((&log, "fixture")))
                .expect_err("deadline")
                .line()
                .contains("time limit")
        );
        assert!(
            fs::read_to_string(&log)
                .expect("kept log")
                .contains("before deadline")
        );
    }

    /// ´test:unit:build-refuses-script-codex-with-unmeasured-interpreter´
    #[test]
    fn build_refuses_script_codex_with_unmeasured_interpreter() {
        let error = standalone_codex(b"#!/bin/sh\n", Path::new("/fixture/codex"))
            .expect_err("script has an unmeasured interpreter");
        assert_eq!(error.kind, "build-input");
        assert!(error.detail.contains("/fixture/codex"));
        let mut static_elf = vec![0_u8; 64];
        static_elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        assert!(standalone_codex(&static_elf, Path::new("/fixture/codex")).is_ok());
    }

    /// ´test:unit:build-refuses-elf-loader-and-external-library-tables´
    #[test]
    fn build_refuses_elf_loader_and_external_library_tables() {
        let mut bytes = vec![0_u8; 136];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
        assert!(
            standalone_codex(&bytes, Path::new("/fixture/codex"))
                .expect_err("external loader")
                .detail
                .contains("PT_INTERP")
        );
        bytes[64..68].copy_from_slice(&2_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
        bytes[120..128].copy_from_slice(&1_u64.to_le_bytes());
        assert!(
            standalone_codex(&bytes, Path::new("/fixture/codex"))
                .expect_err("external library")
                .detail
                .contains("DT_NEEDED")
        );
    }

    /// ´test:unit:build-version-executes-the-measured-snapshot´
    #[test]
    fn build_version_executes_the_measured_snapshot() {
        let temp = TempDir::new_in("/tmp").expect("fixture");
        let source = temp.path().join("codex");
        executable(&source, "printf 'codex-cli 0.1.0\\n'");
        let bytes = source_bytes(&source, "Codex program", 65536, true).expect("measured bytes");
        let snapshot = executable_snapshot(&bytes).expect("sealed snapshot");
        fs::remove_file(&source).expect("remove old path");
        executable(&source, "printf 'codex-cli 9.9.9\\n'");
        let mut spec = child(
            std::path::Path::new(&format!("/proc/self/fd/{}", snapshot.as_raw_fd())),
            vec!["--version".into()],
            &BTreeMap::new(),
            temp.path(),
            2,
            "codex-version",
        );
        spec.inherited_fd = Some(snapshot.as_raw_fd());
        assert_eq!(
            checked_output(&spec, None).expect("snapshot version"),
            "codex-cli 0.1.0\n"
        );
    }

    /// ´test:unit:build-log-publishes-over-a-link-without-following-it´
    #[test]
    fn build_log_publishes_over_a_link_without_following_it() {
        let (temp, mut request) = fixture();
        let victim = temp.path().join("victim");
        fs::write(&victim, "untouched").expect("victim");
        let log = temp.path().join(".config/loops/alpha/image-build.log");
        std::os::unix::fs::symlink(&victim, &log).expect("linked log");
        request.dry_run = false;
        run(temp.path(), &request).expect("build");
        assert_eq!(fs::read_to_string(victim).expect("victim"), "untouched");
        assert!(fs::symlink_metadata(log).expect("log").is_file());
    }

    /// ´test:unit:competing-build-attempts-use-distinct-tags-and-inventory-id´
    #[test]
    fn competing_build_attempts_use_distinct_tags_and_inventory_id() {
        let (left_home, mut left) = fixture();
        let (right_home, mut right) = fixture();
        let first = run(left_home.path(), &left).expect("first preview");
        let second = run(right_home.path(), &right).expect("second preview");
        assert_ne!(first["build_argv"][5], second["build_argv"][5]);
        assert_eq!(first["inventory_argv"][6], "IMAGE_ID_FROM_INSPECT");
        let store = TempDir::new_in("/tmp").expect("shared fake image store");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fake store");
        let backend = store.path().join("container-fixture");
        let script = format!(
            r#"#!/bin/sh
store='{store}'
case "$1 $2" in
  'image exists') exit 0 ;;
  'image inspect') key=$(printf '%s' "$5" | tr '/:' '__'); cat "$store/$key" ;;
  'build --pull=never')
    key=$(printf '%s' "$6" | tr '/:' '__')
    if grep -q 'base-b@' "$8"; then printf '{other}\n' > "$store/$key"; else printf '{initial}\n' > "$store/$key"; fi
    touch "$store/ready-$(basename "$HOME")"
    attempt=0
    while [ "$attempt" -lt 500 ]; do
      count=$(find "$store" -name 'ready-*' | wc -l)
      [ "$count" -ge 2 ] && exit 0
      sleep 0.01
      attempt=$((attempt + 1))
    done
    exit 8 ;;
  'run --rm') printf 'git 2\n' ;;
esac
"#,
            store = store.path().display(),
            initial = "b".repeat(64),
            other = "c".repeat(64)
        );
        fs::write(&backend, script).expect("shared fake backend");
        fs::set_permissions(&backend, fs::Permissions::from_mode(0o700))
            .expect("fake backend mode");
        left.podman_bin = backend.clone();
        right.podman_bin = backend;
        right.base_image = format!("registry.example/base-b@sha256:{}", "a".repeat(64));
        left.dry_run = false;
        right.dry_run = false;
        let (left_result, right_result) = std::thread::scope(|scope| {
            let one = scope.spawn(|| run(left_home.path(), &left));
            let two = scope.spawn(|| run(right_home.path(), &right));
            (
                one.join().expect("first thread"),
                two.join().expect("second thread"),
            )
        });
        assert_eq!(
            left_result.expect("first build")["image_digest"],
            format!("sha256:{}", "b".repeat(64))
        );
        assert_eq!(
            right_result.expect("second build")["image_digest"],
            format!("sha256:{}", "c".repeat(64))
        );
    }

    /// ´test:unit:build-stages-the-hashed-snapshot´
    #[test]
    fn build_stages_the_hashed_snapshot() {
        let temp = TempDir::new_in("/tmp").expect("temporary fixture");
        let source = temp.path().join("codex");
        executable(&source, "printf 'codex-cli 0.1.0\\n'");
        let bytes = source_bytes(&source, "Codex program", 65_536, true).expect("open snapshot");
        let hash = hash_bytes(&bytes, &hash_spec(temp.path())).expect("snapshot hash");
        executable(&source, "printf 'codex-cli 9.9.9\\n'");
        let staged = temp.path().join("staged");
        fs::write(&staged, &bytes).expect("stage snapshot");
        assert_eq!(sha256(&staged).expect("staged hash"), hash);
        assert_ne!(sha256(&source).expect("changed hash"), hash);
    }

    /// ´test:unit:build-template-verifies-prepared-base-offline´
    #[test]
    fn build_template_verifies_prepared_base_offline() {
        let template = include_str!("../data/Containerfile");
        assert!(template.contains("missing base program: $program"));
        assert!(template.contains("missing base certificate bundle"));
        assert!(!template.contains("dnf "));
    }

    /// ´test:unit:build-rendered-template-checks-extracted-ca-bundle´
    #[test]
    fn build_rendered_template_checks_extracted_ca_bundle() {
        let (home, request) = fixture();
        let preview = run(home.path(), &request).expect("build preview");
        let rendered = preview["rendered_template"].as_str().expect("template");
        assert!(
            rendered.contains("RUN test -s /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ||")
        );
        assert!(!rendered.contains("/etc/pki/tls/certs/ca-bundle.crt"));
    }

    /// ´test:unit:build-rechecks-container-program-after-preflight´
    #[test]
    fn build_rechecks_container_program_after_preflight() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let program = fixture.path().join("podman");
        executable(&program, "exit 0");
        crate::pinned::owner_executable(&program, nix::unistd::Uid::effective().as_raw())
            .expect("preflight");
        fs::remove_file(&program).expect("remove checked program");
        std::os::unix::fs::symlink("/usr/bin/true", &program).expect("replacement");
        let spec = child(
            &program,
            Vec::new(),
            &BTreeMap::new(),
            fixture.path(),
            1,
            "image-inspect",
        );
        assert_eq!(
            run_child(&spec, None)
                .expect_err("replacement refused at spawn")
                .kind,
            "owner-program"
        );
    }

    /// ´test:unit:build-unconfigured-vendor-refusal-prints-one-kind´
    #[test]
    fn build_unconfigured_vendor_refusal_prints_one_kind() {
        let (home, request) = fixture();
        fs::write(home.path().join(".config/loops/alpha/workers.toml"), "").expect("ungranted row");
        let error = run(home.path(), &request).expect_err("ungranted vendor");
        assert_eq!(error.status, 2);
        assert_eq!(
            error.line(),
            "missing-setting: no vendor is named in backend_argv or vendor_hosts"
        );
    }
}
