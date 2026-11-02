//! Bounded duplex transport for a peer-selected door registration.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{SFlag, fstat};
use serde_json::{Value, json};

use super::{Registration, Scope, frame_read_until, frame_write_until};
use crate::error::LaneError;

const CHUNK: usize = 8192;
const POST_FINAL_STDIN_WAIT: Duration = Duration::from_millis(500);
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
pub const MAX_UPLOAD_OUTPUT_LIMIT: usize = 1024 * 1024 * 1024;
const ROUTE_KEYS: [&str; 6] = [
    "schema",
    "loop",
    "alias",
    "mirror_root",
    "key_path",
    "node_root",
];

pub(super) fn node_root(value: &Value, config: &Path) -> Result<String, LaneError> {
    let registration = config.join("door-compute-registration.json");
    let root = value.get("node_root").ok_or_else(|| {
        LaneError::input(
            "door-compute-root-refusal",
            format!("{}: node_root is absent", registration.display()),
        )
    })?;
    root.as_str()
        .filter(|root| Path::new(root).is_absolute() && !root.contains('\0'))
        .map(str::to_owned)
        .ok_or_else(|| {
            LaneError::input(
                "door-compute-root-refusal",
                format!(
                    "{}: node_root must be an absolute path: {root}",
                    registration.display()
                ),
            )
        })
}
const REF_NOT_REACHED: u8 = 0;
const REF_ADMITTED: u8 = 1;
const REF_REFUSED: u8 = 2;
const REF_NO_REF: u8 = 3;

const fn ref_check_word(state: u8) -> &'static str {
    match state {
        REF_ADMITTED => "admitted",
        REF_REFUSED => "refused",
        REF_NO_REF => "no-ref",
        _ => "not-reached",
    }
}

pub(super) fn read_owner_leaf(
    directory: &impl AsFd,
    name: &str,
    owner: u32,
) -> Result<Vec<u8>, LaneError> {
    read_owner_leaf_optional(directory, name, owner)?.ok_or_else(|| {
        LaneError::input(
            "door-compute-registration",
            nix::errno::Errno::ENOENT.to_string(),
        )
    })
}

/// Read an optional protected leaf beneath the caller's held configuration directory.
///
/// # Errors
/// Refuses links, unsafe ownership or mode, oversized content and read failures.
pub fn read_owner_leaf_optional(
    directory: &impl AsFd,
    name: &str,
    owner: u32,
) -> Result<Option<Vec<u8>>, LaneError> {
    let fd = match openat2(
        directory,
        Path::new(name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "door-compute-registration",
                error.to_string(),
            ));
        }
    };
    let stat = fstat(&fd)
        .map_err(|error| LaneError::input("door-compute-registration", error.to_string()))?;
    let limit = 65_536_usize;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || usize::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > limit)
    {
        return Err(LaneError::input(
            "door-compute-registration",
            "owner, mode or size differs",
        ));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("door-compute-registration", error.to_string()))?;
    if bytes.len() > limit {
        return Err(LaneError::input(
            "door-compute-registration",
            "route exceeds byte limit",
        ));
    }
    Ok(Some(bytes))
}

fn check_ssh_config(bytes: &[u8]) -> Result<(), LaneError> {
    let contents = std::str::from_utf8(bytes)
        .map_err(|_| LaneError::input("door-compute-registration", "SSH config is not UTF-8"))?;
    for line in contents.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let directive = line
            .split(|symbol: char| symbol.is_ascii_whitespace() || symbol == '=')
            .next()
            .unwrap_or_default();
        let forbidden_character = if line.contains('\\') {
            Some("backslash")
        } else if line.contains('"') {
            Some("quote")
        } else {
            None
        };
        if let Some(character) = forbidden_character {
            return Err(LaneError::input(
                "door-compute-registration",
                format!("SSH config {character} in directive {directive} is forbidden"),
            ));
        }
        let keyword = directive.to_ascii_lowercase();
        let family = if keyword == "match" {
            Some("matching")
        } else if matches!(
            keyword.as_str(),
            "proxycommand"
                | "proxyjump"
                | "localcommand"
                | "permitlocalcommand"
                | "knownhostscommand"
                | "remotecommand"
        ) {
            Some("command")
        } else if keyword == "forwardagent"
            || keyword.starts_with("forwardx11")
            || matches!(
                keyword.as_str(),
                "localforward"
                    | "remoteforward"
                    | "dynamicforward"
                    | "permitremoteopen"
                    | "gatewayports"
                    | "tunnel"
                    | "tunneldevice"
            )
        {
            Some("forwarding")
        } else if matches!(
            keyword.as_str(),
            "forkafterauthentication" | "stdinnull" | "sessiontype"
        ) {
            Some("session-control")
        } else if matches!(
            keyword.as_str(),
            "identityfile"
                | "identityfile2"
                | "certificatefile"
                | "identityagent"
                | "pkcs11provider"
                | "securitykeyprovider"
                | "smartcarddevice"
                | "addkeystoagent"
        ) {
            Some("identity")
        } else if keyword == "include" {
            Some("inclusion")
        } else if keyword.starts_with("control") {
            Some("shared-connection")
        } else {
            None
        };
        if let Some(family) = family {
            return Err(LaneError::input(
                "door-compute-registration",
                format!("SSH config {family} directive {directive} is forbidden"),
            ));
        }
    }
    Ok(())
}

fn ssh_config_digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in sha2::Sha256::digest(bytes) {
        let _written = write!(digest, "{byte:02x}");
    }
    digest
}

fn checked_ssh_options(bytes: &[u8], alias: &str) -> Result<Vec<String>, LaneError> {
    check_ssh_config(bytes)?;
    let contents = std::str::from_utf8(bytes)
        .map_err(|_| LaneError::input("door-compute-registration", "SSH config is not UTF-8"))?;
    let mut selected = true;
    let mut options = std::collections::BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(|c: char| c.is_ascii_whitespace() || c == '=')
            .ok_or_else(|| {
                LaneError::input(
                    "door-compute-registration",
                    format!("SSH directive {line} lacks a value"),
                )
            })?;
        let key = key.to_ascii_lowercase();
        let value = value.trim_start_matches([' ', '\t', '=']).trim();
        if value.is_empty() || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(LaneError::input(
                "door-compute-registration",
                format!("SSH directive {key} requires one literal value"),
            ));
        }
        if key == "host" {
            if value != "*"
                && !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(LaneError::input(
                    "door-compute-registration",
                    "SSH Host requires one exact alias or *",
                ));
            }
            selected = value == alias || value == "*";
        } else {
            if !matches!(
                key.as_str(),
                "hostname"
                    | "port"
                    | "user"
                    | "hostkeyalias"
                    | "userknownhostsfile"
                    | "globalknownhostsfile"
                    | "stricthostkeychecking"
                    | "checkhostip"
                    | "updatehostkeys"
                    | "serveraliveinterval"
                    | "serveralivecountmax"
                    | "connecttimeout"
                    | "addressfamily"
                    | "loglevel"
                    | "identitiesonly"
                    | "batchmode"
            ) {
                return Err(LaneError::input(
                    "door-compute-registration",
                    format!("SSH directive {key} is unsupported"),
                ));
            }
            if matches!(key.as_str(), "identitiesonly" | "batchmode")
                && !value.eq_ignore_ascii_case("yes")
            {
                return Err(LaneError::input(
                    "door-compute-registration",
                    format!("SSH directive {key} must be yes"),
                ));
            }
            if selected {
                options.entry(key).or_insert_with(|| value.to_owned());
            }
        }
    }
    Ok(options
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    GitReceive,
    GitUpload,
    GitUploadV2,
    ProbeEcho,
    ProbeStatus,
    ProbeDeadline,
    Compute,
}

impl Operation {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::GitReceive => "git-receive",
            Self::GitUpload => "git-upload",
            Self::GitUploadV2 => "git-upload-v2",
            Self::ProbeEcho => "probe-echo",
            Self::ProbeStatus => "probe-status",
            Self::ProbeDeadline => "probe-deadline",
            Self::Compute => "compute",
        }
    }
}

pub trait Runner: Send + Sync {
    fn upload_output_limit(&self) -> Option<usize> {
        None
    }
    fn spawn_retirement(&self, _run: &str, _loop_name: &str, _seconds: f64) -> io::Result<Child> {
        Err(io::Error::other("node-retirement-runner-refusal"))
    }
    fn spawn(&self, registration: &Registration, operation: Operation) -> io::Result<Child>;
    fn spawn_compute(
        &self,
        _registration: &Registration,
        _words: &[String],
        _seconds: f64,
    ) -> io::Result<Child> {
        Err(io::Error::other("door-compute-runner-refusal"))
    }
    fn compute_words(&self) -> Option<&[String]> {
        None
    }
    fn owns_process_group(&self) -> bool {
        false
    }
}

pub(super) struct ComputeRunner<'a> {
    pub(super) inner: &'a dyn Runner,
    pub(super) words: &'a [String],
    pub(super) deadline: Instant,
}

impl Runner for ComputeRunner<'_> {
    fn spawn(&self, registration: &Registration, _operation: Operation) -> io::Result<Child> {
        self.inner.spawn_compute(
            registration,
            self.words,
            self.deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64(),
        )
    }
    fn compute_words(&self) -> Option<&[String]> {
        Some(self.words)
    }
    fn owns_process_group(&self) -> bool {
        self.inner.owns_process_group()
    }
}

type Completion<'a> = dyn Fn(&Value) -> Result<(), LaneError> + 'a;

#[derive(Clone)]
pub(super) struct HostRunner {
    alias: String,
    ssh_options: Vec<String>,
    ssh_config_sha256: String,
    mirror_root: String,
    node_root: String,
    key_path: PathBuf,
    upload_output_limit: Option<usize>,
    compute_wrapper: Option<String>,
    compute_environment: Option<Value>,
}

fn parse_compute_wrapper(value: &Value) -> Result<Option<String>, LaneError> {
    value
        .get("compute_wrapper")
        .map(|value| {
            value
                .as_str()
                .filter(|path| {
                    path.starts_with('/')
                        && path.len() <= 256
                        && path
                            .split('/')
                            .skip(1)
                            .all(|part| !part.is_empty() && part != "." && part != "..")
                        && path
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
                })
                .map(str::to_owned)
                .ok_or_else(|| {
                    LaneError::input(
                        "door-compute-registration",
                        "compute_wrapper must be an absolute command path",
                    )
                })
        })
        .transpose()
}

fn parse_compute_environment(value: &Value) -> Result<Option<Value>, LaneError> {
    let Some(environment) = value.get("compute_environment") else {
        return Ok(None);
    };
    let keys = ["RUSTUP_HOME", "PATH", "PUBLIC_PACK_TEST_LINTER"];
    let object = environment
        .as_object()
        .filter(|object| object.len() == keys.len())
        .ok_or_else(|| {
            LaneError::input(
                "door-compute-registration",
                "compute_environment requires RUSTUP_HOME, PATH and PUBLIC_PACK_TEST_LINTER",
            )
        })?;
    for key in keys {
        let text = object
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| {
                !text.is_empty()
                    && text.len() <= 4096
                    && !text.bytes().any(|byte| byte.is_ascii_control())
            })
            .ok_or_else(|| {
                LaneError::input(
                    "door-compute-registration",
                    format!("compute_environment.{key} is absent or invalid"),
                )
            })?;
        let paths: Vec<_> = if key == "PATH" {
            text.split(':').collect()
        } else {
            vec![text]
        };
        if paths.iter().any(|path| {
            !Path::new(path).is_absolute()
                || path.split('/').any(|part| part == "." || part == "..")
        }) {
            return Err(LaneError::input(
                "door-compute-registration",
                format!(
                    "compute_environment.{key} requires absolute paths without dotted components"
                ),
            ));
        }
    }
    Ok(Some(environment.clone()))
}

impl HostRunner {
    pub(super) fn compute_words(&self, args: &[Vec<u8>]) -> Result<Vec<String>, &'static str> {
        let words = super::compute::parse(
            args,
            &self.alias,
            self.compute_wrapper
                .as_deref()
                .ok_or("door-compute-wrapper-refusal")?,
        )?;
        self.compute_environment
            .as_ref()
            .ok_or("door-compute-settings-refusal")?;
        Ok(words)
    }
    /// Read the superloop's owner-private routing registration without opening its key.
    ///
    /// # Errors
    ///
    /// Refuses a missing or changed registration before any compute spawn.
    pub(super) fn load(
        directory: &impl AsFd,
        config: &Path,
        loop_name: &str,
        owner: u32,
    ) -> Result<Self, LaneError> {
        Self::load_with(directory, config, loop_name, owner, || {})
    }

    fn load_with(
        directory: &impl AsFd,
        config: &Path,
        loop_name: &str,
        owner: u32,
        after_pin: impl FnOnce(),
    ) -> Result<Self, LaneError> {
        let bytes = read_owner_leaf(directory, "door-compute-registration.json", owner)?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| LaneError::input("door-compute-registration", error.to_string()))?;
        let node_root = node_root(&value, config)?;
        if value.as_object().is_none_or(|object| {
            object.len()
                != ROUTE_KEYS.len()
                    + usize::from(object.contains_key("git_upload_output_limit_bytes"))
                    + usize::from(object.contains_key("compute_wrapper"))
                    + usize::from(object.contains_key("compute_environment"))
                || ROUTE_KEYS.iter().any(|key| !object.contains_key(*key))
        }) || value["schema"] != 1
            || value["loop"] != loop_name
        {
            return Err(LaneError::input(
                "door-compute-registration",
                "route shape or loop differs",
            ));
        }
        let compute_wrapper = parse_compute_wrapper(&value)?;
        let compute_environment = parse_compute_environment(&value)?;
        let upload_output_limit = value
            .get("git_upload_output_limit_bytes")
            .map(|limit| {
                limit
                    .as_u64()
                    .and_then(|bytes| usize::try_from(bytes).ok())
                    .filter(|bytes| (1..=MAX_UPLOAD_OUTPUT_LIMIT).contains(bytes))
                    .ok_or_else(|| {
                        LaneError::input(
                            "door-compute-registration",
                            "git_upload_output_limit_bytes must be an integer in 1..=1073741824",
                        )
                    })
            })
            .transpose()?;
        let alias = value["alias"]
            .as_str()
            .filter(|word| {
                !word.is_empty()
                    && word.len() <= 80
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            .ok_or_else(|| LaneError::input("door-compute-registration", "alias is invalid"))?;
        let mirror_root = value["mirror_root"]
            .as_str()
            .filter(|word| {
                word.starts_with("~/")
                    && word.len() <= 200
                    && word[2..]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/-_.".contains(&byte))
                    && !word.split('/').any(|part| part == ".." || part == ".")
            })
            .ok_or_else(|| {
                LaneError::input("door-compute-registration", "mirror root is invalid")
            })?;
        let pin = read_owner_leaf_optional(directory, "door-ssh_config", owner)?;
        after_pin();
        crate::door_node::verify(directory, config, loop_name, alias, pin.as_deref(), owner)?;
        let pin = pin.ok_or_else(|| {
            LaneError::input("door-node-derived-drift", "door-ssh_config is absent")
        })?;
        let ssh_options = checked_ssh_options(&pin, alias)?;
        let ssh_config_sha256 = ssh_config_digest(&pin);
        let key_path = value["key_path"]
            .as_str()
            .map(Path::new)
            .filter(|path| {
                path.is_absolute()
                    && path.parent() == Some(config)
                    && path.file_name() == Some(OsStr::new("door-key"))
            })
            .ok_or_else(|| LaneError::input("door-compute-registration", "key path is invalid"))?;
        Ok(Self {
            alias: alias.to_owned(),
            ssh_options,
            ssh_config_sha256,
            mirror_root: mirror_root.to_owned(),
            node_root,
            key_path: key_path.to_owned(),
            upload_output_limit,
            compute_wrapper,
            compute_environment,
        })
    }

    fn mirror_path(&self, registration: &Registration) -> String {
        format!("{}/{}.git", self.mirror_root, registration.run)
    }

    pub(super) fn probe_route(&self) -> Value {
        json!({"alias":self.alias,"mirror_root":self.mirror_root,
            "key_path":self.key_path,"node_root":self.node_root})
    }

    pub(super) fn retirement_route(&self) -> Value {
        let mut identity = self.probe_route();
        identity["ssh_config_sha256"] = json!(self.ssh_config_sha256);
        identity
    }

    pub(super) fn allowed(
        &self,
        args: &[Vec<u8>],
        registration: &Registration,
    ) -> Option<Operation> {
        if super::compute::candidate(args) {
            return self.compute_words(args).ok().map(|_| Operation::Compute);
        }
        if args.len() == 1 {
            return match args[0].as_slice() {
                b"door-attribution-probe" => Some(Operation::ProbeEcho),
                b"door-attribution-status" => Some(Operation::ProbeStatus),
                b"door-attribution-deadline" => Some(Operation::ProbeDeadline),
                _ => None,
            };
        }
        let words = if args.len() == 4 && args[0] == b"-o" && args[1] == b"SendEnv=GIT_PROTOCOL" {
            &args[2..]
        } else {
            args
        };
        if words.len() != 2 || words[0] != self.alias.as_bytes() {
            return None;
        }
        let mirror = self.mirror_path(registration);
        let receive = format!("git-receive-pack '{mirror}'");
        let upload = format!("git-upload-pack '{mirror}'");
        if words[1] == receive.as_bytes() && args.len() == 2 {
            Some(Operation::GitReceive)
        } else if words[1] == upload.as_bytes() {
            Some(if args.len() == 4 {
                Operation::GitUploadV2
            } else {
                Operation::GitUpload
            })
        } else {
            None
        }
    }
    fn command_for(
        &self,
        program: &Path,
        registration: &Registration,
        operation: Operation,
    ) -> Command {
        let command = match operation {
            Operation::GitReceive => format!("git-receive-pack {}", self.mirror_path(registration)),
            Operation::GitUpload | Operation::GitUploadV2 => {
                format!("git-upload-pack {}", self.mirror_path(registration))
            }
            Operation::ProbeEcho => "/usr/bin/cat".to_owned(),
            Operation::ProbeStatus | Operation::Compute => "/usr/bin/false".to_owned(),
            Operation::ProbeDeadline => "/usr/bin/sleep 2".to_owned(),
        };
        self.ssh_command(program, &command, operation == Operation::GitUploadV2, None)
    }

    fn ssh_command(
        &self,
        program: &Path,
        command: &str,
        git_v2: bool,
        connect_timeout: Option<u32>,
    ) -> Command {
        let mut child = Command::new(program);
        child
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .arg("-F")
            .arg("none")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "GSSAPIAuthentication=no",
                "-o",
                "HostbasedAuthentication=no",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
            ])
            .arg("-o")
            .arg(format!("IdentityFile={}", self.key_path.display()));
        if git_v2 {
            child
                .env("GIT_PROTOCOL", "version=2")
                .args(["-o", "SendEnv=GIT_PROTOCOL"]);
        }
        if let Some(seconds) = connect_timeout {
            child.args(["-o", &format!("ConnectTimeout={seconds}")]);
        }
        for option in &self.ssh_options {
            child.arg("-o").arg(option);
        }
        child
            .arg(&self.alias)
            .arg(command)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        child
    }
    pub(super) fn set_retirement_root(&mut self, root: &str) {
        root.clone_into(&mut self.node_root);
    }
    pub(super) fn retirement_command(&self, run: &str, loop_name: &str, seconds: f64) -> Command {
        let quote = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
        let remote = format!(
            "if test -x /usr/bin/python3 && test -x /usr/bin/timeout; then exec /usr/bin/timeout -k 5 {} /usr/bin/python3 -c {} {} {} {} {}; else echo NODE-RETIREMENT-TOOL-REFUSAL >&2; exit 127; fi",
            (seconds - 15.0).max(0.001),
            quote(super::retirement::NODE_SCRIPT),
            quote(&format!("{}/{run}.git", self.mirror_root)),
            quote(run),
            quote(loop_name),
            quote(&self.node_root),
        );
        // Built-binary fixtures retain the production command and helper while
        // substituting only SSH. Release builds have no transport override.
        #[cfg(debug_assertions)]
        if let Some(program) = std::env::var_os("SUPERLOOP_LANE_TEST_RETIRE_SSH") {
            return self.ssh_command(Path::new(&program), &remote, false, Some(10));
        }
        self.ssh_command(Path::new("/usr/bin/ssh"), &remote, false, Some(10))
    }
    pub(super) fn compute_command(
        &self,
        registration: &Registration,
        words: &[String],
        seconds: f64,
    ) -> io::Result<Command> {
        let quote = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
        let wrapper = self
            .compute_wrapper
            .as_deref()
            .ok_or_else(|| io::Error::other("door-compute-wrapper-refusal"))?;
        let environment = self
            .compute_environment
            .as_ref()
            .ok_or_else(|| io::Error::other("door-compute-settings-refusal"))?;
        let seconds = seconds.max(0.001);
        let remote = format!(
            "if test -x /usr/bin/python3 && test -x /usr/bin/timeout; then exec /usr/bin/timeout -k 10 {} /usr/bin/python3 -c {} {} {} {} {} {} {} {}; else echo DOOR-COMPUTE-TOOL-REFUSAL >&2; exit 127; fi",
            // Inner TERM is at seconds - 15; allow its ten-second kill grace,
            // then two seconds for evidence before the outer TERM (seconds - 3).
            (seconds - 15.0 + 10.0 + 2.0).max(0.001),
            quote(super::compute::NODE_SCRIPT),
            quote(&self.mirror_path(registration)),
            quote(&registration.run),
            quote(&self.node_root),
            seconds,
            quote(&serde_json::to_string(words)?),
            quote(wrapper),
            quote(&environment.to_string())
        );
        let template =
            self.command_for(Path::new("/usr/bin/ssh"), registration, Operation::Compute);
        let mut command = Command::new(template.get_program());
        let args: Vec<_> = template.get_args().collect();
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .args(&args[..args.len() - 1])
            .arg(remote)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(command)
    }
}

impl Runner for HostRunner {
    fn upload_output_limit(&self) -> Option<usize> {
        self.upload_output_limit
    }
    fn spawn_retirement(&self, run: &str, loop_name: &str, seconds: f64) -> io::Result<Child> {
        self.retirement_command(run, loop_name, seconds).spawn()
    }
    fn spawn_compute(
        &self,
        registration: &Registration,
        words: &[String],
        seconds: f64,
    ) -> io::Result<Child> {
        self.compute_command(registration, words, seconds)?.spawn()
    }
    fn spawn(&self, registration: &Registration, operation: Operation) -> io::Result<Child> {
        self.command_for(Path::new("/usr/bin/ssh"), registration, operation)
            .spawn()
    }

    fn owns_process_group(&self) -> bool {
        true
    }
}

pub(super) fn argument_bytes(request: &Value) -> Option<Vec<Vec<u8>>> {
    let args = request["argv"].as_array()?;
    if args.len() > 128 {
        return None;
    }
    args.iter()
        .map(|arg| {
            let bytes = arg.as_array()?;
            if bytes.len() > 4096 {
                return None;
            }
            bytes
                .iter()
                .map(|byte| byte.as_u64().and_then(|value| u8::try_from(value).ok()))
                .collect::<Option<Vec<_>>>()
        })
        .collect()
}

pub(super) fn refusal(
    registration: &Registration,
    peer: u32,
    reason: &str,
    started: Instant,
) -> Value {
    if peer != registration.worker_uid {
        return json!({"schema":2,"type":"final","status":125,"reason":reason,"peer_uid":peer,
            "ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
            "queue_state":"no-queue","queue_wall_seconds":null,"compute_exit_status":null,
            "mediation_wall_seconds":started.elapsed().as_secs_f64(),
            "compute_wall_seconds":0.0});
    }
    json!({"schema":2,"type":"final","status":125,"reason":reason,
        "registration":registration.document(),"peer_uid":peer,
        "ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
        "queue_state":"no-queue","queue_wall_seconds":null,"compute_exit_status":null,
        "mediation_wall_seconds":started.elapsed().as_secs_f64(),
        "compute_wall_seconds":0.0})
}

fn send_output(
    stream: &Arc<Mutex<UnixStream>>,
    kind: &str,
    bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let value = json!({"schema":2,"type":kind,"bytes":bytes});
    write_frame_locked(stream, &value, deadline)
}

fn write_frame_locked(
    stream: &Arc<Mutex<UnixStream>>,
    value: &Value,
    deadline: Instant,
) -> io::Result<()> {
    loop {
        match stream.try_lock() {
            Ok(mut locked) => return frame_write_until(&mut locked, value, deadline),
            Err(TryLockError::Poisoned(_)) => {
                return Err(io::Error::other("door writer lock poisoned"));
            }
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "door writer deadline",
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn output_pump<R: io::Read>(
    mut source: R,
    writer: &Arc<Mutex<UnixStream>>,
    kind: &'static str,
    total: &Arc<AtomicUsize>,
    stream_count: &Arc<AtomicUsize>,
    abort: &Arc<AtomicBool>,
    deadline: Instant,
    capture: Option<&Mutex<Vec<u8>>>,
    bound: usize,
) -> io::Result<()> {
    let mut buffer = [0_u8; CHUNK];
    loop {
        if Instant::now() >= deadline || abort.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "door output deadline",
            ));
        }
        let count = match source.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(());
        }
        if let Some(capture) = capture {
            let mut bytes = capture
                .lock()
                .map_err(|_| io::Error::other("compute evidence lock"))?;
            if bytes.len() + count <= OUTPUT_LIMIT {
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        if total
            .fetch_add(count, Ordering::Relaxed)
            .saturating_add(count)
            > bound
        {
            abort.store(true, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "door output exceeds limit",
            ));
        }
        if abort.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "door output stopped",
            ));
        }
        stream_count.fetch_add(count, Ordering::Relaxed);
        if let Err(error) = send_output(writer, kind, &buffer[..count], deadline) {
            abort.store(true, Ordering::Relaxed);
            return Err(error);
        }
    }
}

#[derive(Debug, PartialEq)]
struct RefPacketRefusal {
    reason: &'static str,
    packet: Option<Value>,
}

fn packet_refusal(body: &[u8]) -> RefPacketRefusal {
    let words = body
        .split(u8::is_ascii_whitespace)
        .filter(|word| !word.is_empty());
    let word_count = words.clone().count().min(65_536);
    let first = words.clone().next().unwrap_or_default();
    let first_word = if first.len() > 64 {
        "[overlong]"
    } else if first.iter().all(u8::is_ascii_graphic) {
        std::str::from_utf8(first).unwrap_or("[non-text]")
    } else {
        "[non-text]"
    };
    RefPacketRefusal {
        reason: "door-changed-ref-refusal",
        packet: Some(json!({"word_count":word_count,"first_word":first_word})),
    }
}

fn checked_ref_packet(data: &[u8], expected: &str) -> Result<Option<bool>, RefPacketRefusal> {
    let invalid = || RefPacketRefusal {
        reason: "door-git-packet-refusal",
        packet: None,
    };
    let mut at = 0;
    let mut commands = false;
    while data.len().saturating_sub(at) >= 4 {
        let size = std::str::from_utf8(&data[at..at + 4])
            .ok()
            .and_then(|word| usize::from_str_radix(word, 16).ok())
            .ok_or_else(invalid)?;
        if size == 0 {
            return Ok(Some(commands));
        }
        if !(4..=65_536).contains(&size) {
            return Err(invalid());
        }
        if data.len().saturating_sub(at) < size {
            return Ok(None);
        }
        let body = &data[at + 4..at + size];
        if body.starts_with(b"shallow ") {
            let oid = body
                .strip_prefix(b"shallow ")
                .and_then(|tail| tail.strip_suffix(b"\n"));
            if commands
                || oid.is_none_or(|oid| {
                    ![40, 64].contains(&oid.len()) || !oid.iter().all(u8::is_ascii_hexdigit)
                })
            {
                return Err(packet_refusal(body));
            }
        } else {
            let command = body.split(|byte| *byte == 0).next().unwrap_or_default();
            let words = command.split(|byte| *byte == b' ').collect::<Vec<_>>();
            if words.len() != 3
                || words[2] != expected.as_bytes()
                || ![40, 64].contains(&words[0].len())
                || words[0].len() != words[1].len()
                || !words[0]
                    .iter()
                    .chain(words[1].iter())
                    .all(u8::is_ascii_hexdigit)
            {
                return Err(packet_refusal(command));
            }
            commands = true;
        }
        at += size;
    }
    Ok(None)
}

fn write_input_until(
    destination: &mut impl Write,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "door input deadline",
            ));
        }
        match destination.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(size) => bytes = &bytes[size..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn input_pump(
    mut socket: UnixStream,
    mut destination: impl Write,
    expected_ref: Option<&str>,
    count: &Arc<AtomicUsize>,
    ref_check: &Arc<AtomicU8>,
    ref_packet: &Arc<Mutex<Option<Value>>>,
    abort: &Arc<AtomicBool>,
    stopped: &Arc<AtomicBool>,
    deadline: Instant,
) -> Result<(), &'static str> {
    let mut buffer = [0_u8; CHUNK];
    let mut guarded = Vec::new();
    let mut checked = expected_ref.is_none();
    loop {
        if Instant::now() >= deadline {
            abort.store(true, Ordering::Relaxed);
            return Err("door-deadline-refusal");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| "door-disconnect-refusal")?;
        let read = match socket.read(&mut buffer) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if stopped.load(Ordering::Relaxed) {
                    return Ok(());
                }
                abort.store(true, Ordering::Relaxed);
                return Err("door-deadline-refusal");
            }
            Err(_) if stopped.load(Ordering::Relaxed) => return Ok(()),
            Err(_) => {
                abort.store(true, Ordering::Relaxed);
                return Err("door-disconnect-refusal");
            }
        };
        if read == 0 {
            if stopped.load(Ordering::Relaxed) {
                return Ok(());
            }
            if !checked {
                abort.store(true, Ordering::Relaxed);
                return Err("door-git-packet-refusal");
            }
            return Ok(());
        }
        if count
            .fetch_add(read, Ordering::Relaxed)
            .saturating_add(read)
            > super::INPUT_LIMIT
        {
            abort.store(true, Ordering::Relaxed);
            return Err("door-input-limit-refusal");
        }
        if checked {
            write_input_until(&mut destination, &buffer[..read], deadline)
                .map_err(|_| "door-compute-io-refusal")?;
        } else {
            guarded.extend_from_slice(&buffer[..read]);
            if guarded.len() > 65_536 {
                abort.store(true, Ordering::Relaxed);
                return Err("door-git-packet-refusal");
            }
            match checked_ref_packet(&guarded, expected_ref.unwrap_or_default()) {
                Ok(Some(commands)) => {
                    ref_check.store(
                        if commands { REF_ADMITTED } else { REF_NO_REF },
                        Ordering::Relaxed,
                    );
                    checked = true;
                    write_input_until(&mut destination, &guarded, deadline)
                        .map_err(|_| "door-compute-io-refusal")?;
                    guarded.clear();
                }
                Ok(None) => {}
                Err(refusal) => {
                    if refusal.reason == "door-changed-ref-refusal" {
                        ref_check.store(REF_REFUSED, Ordering::Relaxed);
                    }
                    abort.store(true, Ordering::Relaxed);
                    *ref_packet.lock().map_err(|_| "door-git-packet-refusal")? = refusal.packet;
                    return Err(refusal.reason);
                }
            }
        }
    }
}

fn stop_group(child: &mut Child, owns_group: bool) {
    let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
    if owns_group {
        let _stopped = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    } else {
        let _stopped = child.kill();
    }
}

fn bounded_join<T>(handle: JoinHandle<T>, deadline: Instant) -> io::Result<Option<T>> {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    }
    handle
        .join()
        .map(Some)
        .map_err(|_| io::Error::other("door pump panicked"))
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(super) fn serve_compute(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    operation: Operation,
    runner: &dyn Runner,
    started: Instant,
    deadline: Instant,
    queue_state: &str,
    queue_wall: Option<f64>,
    would_do: Option<&Value>,
    complete: Option<&Completion<'_>>,
) -> io::Result<Value> {
    if registration.scope != Scope::Work {
        let reply = refusal(registration, peer, "door-review-compute-refusal", started);
        frame_write_until(stream, &reply, deadline)?;
        return Ok(reply);
    }
    let compute_started = Instant::now();
    let upload = matches!(operation, Operation::GitUpload | Operation::GitUploadV2);
    let registered = upload.then(|| runner.upload_output_limit()).flatten();
    let bound = registered.unwrap_or(OUTPUT_LIMIT);
    if bound == 0 || bound > MAX_UPLOAD_OUTPUT_LIMIT {
        return Err(io::Error::other("door upload output bound is invalid"));
    }
    let registration_state = if !upload {
        "not-applicable"
    } else if registered.is_some() {
        "present"
    } else {
        "absent"
    };
    if Instant::now() >= deadline
        || (operation == Operation::Compute
            && deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(10))
    {
        let mut reply = refusal(registration, peer, "door-request-deadline", started);
        if operation == Operation::Compute {
            reply["compute"] = super::compute::pending(runner.compute_words().unwrap_or_default());
        }
        reply["queue_state"] = json!(queue_state);
        reply["queue_wall_seconds"] = json!(queue_wall);
        reply["mediation_wall_seconds"] =
            json!((started.elapsed().as_secs_f64() - queue_wall.unwrap_or(0.0)).max(0.0));
        if let Some(complete) = complete {
            complete(&reply).map_err(io::Error::other)?;
        }
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok(reply);
    }
    if upload {
        frame_write_until(
            stream,
            &json!({"schema":2,"type":"limits","bound":bound,"registered":registration_state}),
            deadline,
        )?;
    }
    let mut child = runner.spawn(registration, operation)?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("compute stdin absent"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("compute stdout absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("compute stderr absent"))?;
    let abort = Arc::new(AtomicBool::new(false));
    let input_stopped = Arc::new(AtomicBool::new(false));
    let stdin_count = Arc::new(AtomicUsize::new(0));
    let ref_check = Arc::new(AtomicU8::new(REF_NOT_REACHED));
    let ref_packet = Arc::new(Mutex::new(None));
    let stdout_count = Arc::new(AtomicUsize::new(0));
    let stderr_count = Arc::new(AtomicUsize::new(0));
    let output_total = Arc::new(AtomicUsize::new(0));
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let input_socket = stream.try_clone()?;
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let input = {
        let count = Arc::clone(&stdin_count);
        let ref_check = Arc::clone(&ref_check);
        let ref_packet = Arc::clone(&ref_packet);
        let abort = Arc::clone(&abort);
        let stopped = Arc::clone(&input_stopped);
        let expected =
            (operation == Operation::GitReceive).then(|| registration.mirror_ref.clone());
        thread::spawn(move || {
            input_pump(
                input_socket,
                stdin,
                expected.as_deref(),
                &count,
                &ref_check,
                &ref_packet,
                &abort,
                &stopped,
                deadline,
            )
        })
    };
    let output = {
        let writer = Arc::clone(&writer);
        let total = Arc::clone(&output_total);
        let count = Arc::clone(&stdout_count);
        let abort = Arc::clone(&abort);
        thread::spawn(move || {
            output_pump(
                stdout, &writer, "stdout", &total, &count, &abort, deadline, None, bound,
            )
        })
    };
    let errors = {
        let writer = Arc::clone(&writer);
        let total = Arc::clone(&output_total);
        let count = Arc::clone(&stderr_count);
        let abort = Arc::clone(&abort);
        let evidence = Arc::clone(&evidence);
        thread::spawn(move || {
            output_pump(
                stderr,
                &writer,
                "stderr",
                &total,
                &count,
                &abort,
                deadline,
                (operation == Operation::Compute).then_some(evidence.as_ref()),
                bound,
            )
        })
    };
    let mut outcome = "door-complete";
    let status = loop {
        if abort.load(Ordering::Relaxed) {
            outcome = "door-transport-refusal";
            stop_group(&mut child, runner.owns_process_group());
            break child.wait()?;
        }
        if Instant::now() >= deadline {
            outcome = "door-deadline-refusal";
            stop_group(&mut child, runner.owns_process_group());
            let _read_end = stream.shutdown(Shutdown::Read);
            break child.wait()?;
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let compute_wall = compute_started.elapsed().as_secs_f64();
    input_stopped.store(true, Ordering::Relaxed);
    let _read_end = stream.shutdown(Shutdown::Read);
    if outcome == "door-complete" {
        // The remote command has exited; descendants cannot retain output pipes.
        stop_group(&mut child, runner.owns_process_group());
    }
    let join_deadline = Instant::now() + Duration::from_secs(2);
    let input_result = bounded_join(input, join_deadline)?;
    if let Some(Err(reason)) = input_result
        && abort.load(Ordering::Relaxed)
    {
        outcome = reason;
    }
    let output_result = bounded_join(output, join_deadline)?;
    let error_result = bounded_join(errors, join_deadline)?;
    if (output_result.as_ref().is_none_or(Result::is_err)
        || error_result.as_ref().is_none_or(Result::is_err))
        && outcome == "door-complete"
    {
        outcome = "door-output-refusal";
    }
    if output_result.is_none() || error_result.is_none() {
        abort.store(true, Ordering::Relaxed);
    }
    if output_total.load(Ordering::Relaxed) > bound {
        outcome = "door-output-limit-refusal";
    }
    let code = if outcome == "door-complete" {
        status.code().unwrap_or(125)
    } else {
        125
    };
    let total_wall = started.elapsed().as_secs_f64();
    let mut reply = json!({"schema":2,"type":"final","status":code,"reason":outcome,
        "registration":registration.document(),"peer_uid":peer,
        "compute_exit_status":status.code(),"queue_state":queue_state,
        "ref_check":if operation == Operation::GitReceive {
            ref_check_word(ref_check.load(Ordering::Relaxed))
        } else { "not-applicable" },
        "stdin_bytes":stdin_count.load(Ordering::Relaxed),
        "stdout_bytes":stdout_count.load(Ordering::Relaxed),
        "bound":bound,"output_bytes":output_total.load(Ordering::Relaxed),"registered":registration_state,
        "stderr_bytes":stderr_count.load(Ordering::Relaxed),
        "queue_wall_seconds":queue_wall,"mediation_wall_seconds":(total_wall - compute_wall - queue_wall.unwrap_or(0.0)).max(0.0),
        "compute_wall_seconds":compute_wall});
    if let Some(packet) = ref_packet
        .lock()
        .map_err(|_| io::Error::other("ref packet evidence lock"))?
        .as_ref()
    {
        reply["ref_packet"] = packet.clone();
    }
    if let Some(words) = runner.compute_words() {
        let bytes = evidence
            .lock()
            .map_err(|_| io::Error::other("compute evidence lock"))?;
        super::compute::finish(&mut reply, words, &bytes);
    }
    if let Some(would_do) = would_do {
        reply["would_do"] = would_do.clone();
    }
    if let Some(complete) = complete
        && let Err(error) = complete(&reply)
    {
        let _logged = writeln!(io::stderr().lock(), "door effect record: {}", error.line());
        reply["status"] = json!(125);
        reply["reason"] = json!("door-record-incomplete");
        reply["request_record_error"] = json!(error.line());
    }
    write_frame_locked(&writer, &reply, Instant::now() + Duration::from_secs(2))?;
    Ok(reply)
}

/// Stream exact stdin while independently draining output and final status.
///
/// # Errors
///
/// Refuses an invalid argument, byte limit, stalled transport or malformed final reply.
#[allow(clippy::too_many_lines)]
pub fn stub_call_stream<R, O, E>(
    socket: &Path,
    args: &[OsString],
    mut input: R,
    mut stdout: O,
    mut stderr: E,
) -> io::Result<Value>
where
    R: Read + Send + 'static,
    O: Write,
    E: Write,
{
    if args.len() > 128 || args.iter().any(|arg| arg.as_bytes().len() > 4096) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "door arguments exceed limit",
        ));
    }
    let mut stream = UnixStream::connect(socket)?;
    let deadline_ms = if args.len() == 1 && args[0] == "door-attribution-deadline" {
        100
    } else if args.len() == 2 && !args[1].as_encoded_bytes().starts_with(b"git-") {
        super::compute::DEADLINE_MS
    } else {
        120_000
    };
    // The service owns the command deadline; leave a bounded margin for its final frame.
    let deadline = Instant::now() + Duration::from_millis(deadline_ms + 500);
    let words = args
        .iter()
        .map(|arg| arg.as_bytes().to_vec())
        .collect::<Vec<_>>();
    frame_write_until(
        &mut stream,
        &json!({"schema":2,"argv":words,"deadline_ms":deadline_ms}),
        deadline,
    )?;
    let mut writer = stream.try_clone()?;
    let input_failure = Arc::new(Mutex::new(None));
    let sender_failure = Arc::clone(&input_failure);
    let sender = thread::spawn(move || {
        let mut buffer = [0_u8; CHUNK];
        let mut total = 0;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "door stdin deadline",
                ));
            }
            let read = if let Ok(read) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| input.read(&mut buffer)))
            {
                match read {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                }
            } else {
                *sender_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some((io::ErrorKind::Other, "door stdin sender panicked"));
                let _closed = writer.shutdown(Shutdown::Write);
                return Err(io::Error::other("door stdin sender panicked"));
            };
            if read == 0 {
                break;
            }
            total += read;
            if total > super::INPUT_LIMIT {
                *sender_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some((io::ErrorKind::InvalidInput, "door stdin exceeds limit"));
                let _closed = writer.shutdown(Shutdown::Write);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "door stdin exceeds limit",
                ));
            }
            if Instant::now() >= deadline {
                *sender_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some((io::ErrorKind::TimedOut, "door stdin deadline"));
                let _closed = writer.shutdown(Shutdown::Write);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "door stdin deadline",
                ));
            }
            super::write_all_until(&mut writer, &buffer[..read], deadline)?;
        }
        writer.shutdown(Shutdown::Write)
    });
    let mut received_out = 0_usize;
    let mut received_err = 0_usize;
    let mut bound = OUTPUT_LIMIT;
    let mut announced = false;
    let upload = args
        .last()
        .is_some_and(|arg| arg.as_bytes().starts_with(b"git-upload-pack '"));
    let mut registered = if upload { "absent" } else { "not-applicable" };
    let final_reply = loop {
        let frame = frame_read_until(&mut stream, deadline + Duration::from_secs(2))?;
        if frame["schema"] != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "door response schema differs",
            ));
        }
        match frame["type"].as_str() {
            Some("limits") if upload && !announced && received_out == 0 && received_err == 0 => {
                bound = frame["bound"]
                    .as_u64()
                    .and_then(|bytes| usize::try_from(bytes).ok())
                    .filter(|bytes| (1..=MAX_UPLOAD_OUTPUT_LIMIT).contains(bytes))
                    .ok_or_else(|| io::Error::other("door output bound differs"))?;
                if !matches!(frame["registered"].as_str(), Some("present" | "absent"))
                    || (frame["registered"] == "absent" && bound != OUTPUT_LIMIT)
                {
                    return Err(io::Error::other("door output registration differs"));
                }
                registered = if frame["registered"] == "present" {
                    "present"
                } else {
                    "absent"
                };
                announced = true;
            }
            Some("stdout" | "stderr") => {
                let bytes = frame["bytes"]
                    .as_array()
                    .and_then(|bytes| {
                        (bytes.len() <= CHUNK)
                            .then_some(bytes)?
                            .iter()
                            .map(|byte| byte.as_u64().and_then(|value| u8::try_from(value).ok()))
                            .collect::<Option<Vec<_>>>()
                    })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "door output frame differs")
                    })?;
                if received_out
                    .saturating_add(received_err)
                    .saturating_add(bytes.len())
                    > bound
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "door-output-limit-refusal bound={bound} output_bytes={} registered={registered}",
                            received_out
                                .saturating_add(received_err)
                                .saturating_add(bytes.len())
                        ),
                    ));
                }
                if frame["type"] == "stdout" {
                    received_out = received_out.saturating_add(bytes.len());
                    stdout.write_all(&bytes)?;
                    stdout.flush()?;
                } else {
                    received_err = received_err.saturating_add(bytes.len());
                    stderr.write_all(&bytes)?;
                    stderr.flush()?;
                }
            }
            Some("final") => break frame,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "door frame kind differs",
                ));
            }
        }
    };
    if final_reply["status"].as_i64().is_none()
        || final_reply["reason"].as_str().is_none()
        || final_reply["stdout_bytes"] != received_out
        || final_reply["stderr_bytes"] != received_err
        || !final_reply["mediation_wall_seconds"].is_number()
        || !final_reply["compute_wall_seconds"].is_number()
        || !matches!(
            final_reply["queue_state"].as_str(),
            Some("no-queue" | "answered" | "refused" | "deadline")
        )
        || (final_reply["queue_state"] == "no-queue"
            && !final_reply["queue_wall_seconds"].is_null())
        || (final_reply["queue_state"] != "no-queue"
            && final_reply["queue_wall_seconds"]
                .as_f64()
                .is_none_or(|wall| wall < 0.0))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "door final status differs",
        ));
    }
    // A successful final frame gives the sender at most 500 ms to finish.
    // Open local input cannot hold the completed remote command indefinitely.
    let _closed = stream.shutdown(std::net::Shutdown::Write);
    if final_reply["status"] == 0 {
        let wait_until = Instant::now() + POST_FINAL_STDIN_WAIT;
        while !sender.is_finished() && Instant::now() < wait_until {
            thread::sleep(Duration::from_millis(1));
        }
    }
    let observed_failure = input_failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some((kind, detail)) = observed_failure {
        return Err(io::Error::new(kind, detail));
    }
    if sender.is_finished() {
        match sender.join() {
            Ok(Ok(())) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::other("door stdin sender panicked")),
        }
    }
    Ok(final_reply)
}

pub(super) fn stub_call(socket: &Path, args: &[OsString], input: &[u8]) -> io::Result<Value> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    stub_call_stream(
        socket,
        args,
        io::Cursor::new(input.to_vec()),
        &mut stdout,
        &mut stderr,
    )
}

#[cfg(test)]
#[path = "."]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::{
        HostRunner, Operation, Runner, checked_ref_packet, read_owner_leaf, stub_call,
        stub_call_stream,
    };
    use crate::door::{
        Registration, Scope, frame_read_until, frame_write_until, peer_uid, serve_request,
    };
    use crate::requests::{
        Mode,
        modes::{ModeTarget, Rubric},
        store::tests::Fixture,
    };

    struct FakeRunner;

    /// ´test:unit:door-input-write-retries-interruption-without-extending-deadline´
    #[test]
    fn door_input_write_retries_interruption_without_extending_deadline() {
        struct InterruptedWriter {
            interrupted: bool,
            bytes: Vec<u8>,
        }
        impl io::Write for InterruptedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.bytes.push(bytes[0]);
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = InterruptedWriter {
            interrupted: false,
            bytes: Vec::new(),
        };
        super::write_input_until(
            &mut writer,
            b"payload",
            Instant::now() + Duration::from_secs(1),
        )
        .expect("retry and partial writes");
        assert_eq!(writer.bytes, b"payload");
        assert_eq!(
            super::write_input_until(&mut writer, b"later", Instant::now())
                .expect_err("deadline unchanged")
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(writer.bytes, b"payload");
    }

    /// ´test:unit:door-ssh-options-select-alias-with-first-value-precedence´
    #[test]
    fn door_ssh_options_select_alias_with_first_value_precedence() {
        let source = b"Host other\nHostName wrong\nHost fixture\nHostName selected\nUser account\nUserKnownHostsFile /keys\nStrictHostKeyChecking yes\nHost *\nHostName default\nPort 22\n";
        let options = super::checked_ssh_options(source, "fixture").expect("selected stanza");
        assert!(options.contains(&"hostname=selected".to_owned()));
        assert!(options.contains(&"port=22".to_owned()));
        assert!(
            !options
                .iter()
                .any(|word| word.contains("wrong") || word.contains("default"))
        );
        for source in [
            "Host fix*\nHostName host\n",
            "Host fixture other\nHostName host\n",
            "Host fixture\nHostname host\nUnknownOption value\n",
        ] {
            assert_eq!(
                super::checked_ssh_options(source.as_bytes(), "fixture")
                    .expect_err("unsupported stanza")
                    .kind,
                "door-compute-registration"
            );
        }
    }

    /// The registered alias may repeat the door's fixed identity-only setting, but cannot weaken it.
    /// ´claim:door:registered-identities-only´
    /// ´test:unit:door-ssh-identities-only-matches-transport´
    #[test]
    fn door_ssh_identities_only_matches_transport() {
        for value in ["yes", "YES"] {
            let source = format!("Host fixture\nIdentitiesOnly {value}\n");
            let options = super::checked_ssh_options(source.as_bytes(), "fixture")
                .expect("fixed identity policy");
            assert!(options.contains(&format!("identitiesonly={value}")));
        }
        for value in ["no", "ask", "yes,no"] {
            let source = format!("Host fixture\nIdentitiesOnly {value}\n");
            let error = super::checked_ssh_options(source.as_bytes(), "fixture")
                .expect_err("conflicting identity policy");
            assert_eq!(error.kind, "door-compute-registration");
            assert!(error.detail.contains("identitiesonly must be yes"));
        }
    }

    /// ´test:unit:door-ssh-value-refusals-name-directive´
    #[test]
    fn door_ssh_value_refusals_name_directive() {
        for (source, detail) in [
            ("HostName", "SSH directive HostName lacks a value"),
            ("Port=", "SSH directive port requires one literal value"),
            (
                "User first second",
                "SSH directive user requires one literal value",
            ),
        ] {
            let error = super::checked_ssh_options(source.as_bytes(), "fixture")
                .expect_err("invalid directive value");
            assert_eq!(error.kind, "door-compute-registration");
            assert_eq!(error.detail, detail);
        }
    }

    /// # Panics
    /// Panics only if a fixed batch policy is rejected or a conflicting value is admitted.
    /// ´test:unit:door-ssh-batch-mode-matches-transport´
    #[test]
    fn door_ssh_batch_mode_matches_transport() {
        for separator in [" ", "="] {
            for value in ["yes", "YES", "no", "ask", "yes,no"] {
                let source = format!("Host *\nBatchMode{separator}{value}\n");
                let result = super::checked_ssh_options(source.as_bytes(), "fixture");
                if value.eq_ignore_ascii_case("yes") {
                    assert!(
                        result
                            .expect("fixed batch policy")
                            .contains(&format!("batchmode={value}"))
                    );
                } else {
                    let error = result.expect_err("conflicting batch policy");
                    assert_eq!(error.kind, "door-compute-registration");
                    assert_eq!(error.detail, "SSH directive batchmode must be yes");
                }
            }
        }
    }

    struct InterruptedInput {
        interrupted: bool,
        bytes: io::Cursor<Vec<u8>>,
    }

    impl io::Read for InterruptedInput {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.bytes.read(buffer)
        }
    }

    /// ´test:unit:door-stub-and-output-pump-retry-interrupted-reads´
    #[test]
    fn door_stub_and_output_pump_retry_interrupted_reads() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let source = || InterruptedInput {
            interrupted: false,
            bytes: io::Cursor::new(b"payload".to_vec()),
        };
        let (_temp, socket, server) = fixture(Scope::Work);
        let mut output = Vec::new();
        let reply = stub_call_stream(
            &socket,
            &["door-attribution-probe".into()],
            source(),
            &mut output,
            io::sink(),
        )
        .expect("interrupted input survives");
        server.join().expect("server").expect("request");
        assert_eq!(reply["status"], 0);
        assert_eq!(output, b"READY\npayload");
        let (writer, mut reader) = UnixStream::pair().expect("pair");
        let total = Arc::new(AtomicUsize::new(0));
        let count = Arc::new(AtomicUsize::new(0));
        let abort = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(5);
        super::output_pump(
            source(),
            &Arc::new(Mutex::new(writer)),
            "stdout",
            &total,
            &count,
            &abort,
            deadline,
            None,
            100,
        )
        .expect("interrupted node output survives");
        let frame = frame_read_until(&mut reader, deadline).expect("output frame");
        assert_eq!(frame["bytes"], json!(b"payload".to_vec()));
        assert_eq!(count.load(Ordering::Relaxed), 7);
        assert_eq!(total.load(Ordering::Relaxed), 7);
    }

    fn ssh_fixture_output(command: &mut Command) -> io::Result<std::process::Output> {
        crate::fixture_exec::output(command)
    }

    /// ´test:unit:door-ssh-fixture-output-retries-a-held-writer´
    #[test]
    fn door_ssh_fixture_output_retries_a_held_writer() {
        use std::io::Write as _;
        let fixture = tempfile::tempdir().expect("fixture");
        let script = fixture.path().join("ssh");
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&script)
            .expect("script writer");
        writer
            .write_all(b"#!/bin/sh\nexit 0\n")
            .expect("script bytes");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("script mode");
        assert_eq!(
            Command::new(&script)
                .output()
                .expect_err("a plain fixture exec races the open writer")
                .raw_os_error(),
            Some(nix::libc::ETXTBSY)
        );
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            writer.sync_all().expect("script sync");
            drop(writer);
        });
        let output = ssh_fixture_output(&mut Command::new(&script)).expect("retrying SSH fixture");
        release.join().expect("writer release");
        assert!(output.status.success());
    }

    /// ´test:unit:door-stub-keeps-input-failures-over-successful-final-frame´
    #[test]
    fn door_stub_keeps_input_failures_over_successful_final_frame() {
        struct PanicInput(Receiver<()>);
        impl io::Read for PanicInput {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                self.0.recv().map_err(io::Error::other)?;
                panic!("fixture input panic");
            }
        }
        let fixture = tempfile::tempdir().expect("stub socket fixture");
        let socket =
            crate::fixture_exec::fixture_socket_path(fixture.path().join("capability.sock"));
        let listener = UnixListener::bind(&socket).expect("fixture listener");
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("fixture accept");
            let deadline = Instant::now() + Duration::from_secs(5);
            let _request = frame_read_until(&mut peer, deadline).expect("stub request");
            io::copy(&mut peer, &mut io::sink()).expect("drain input");
            frame_write_until(
                &mut peer,
                &json!({"schema":2,"type":"final",
                "status":0,"reason":"door-complete","ref_check":"not-applicable","stdout_bytes":0,"stderr_bytes":0,
                "queue_state":"no-queue","queue_wall_seconds":null,
                "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0}),
                deadline,
            )
            .expect("success frame");
        });
        let input = io::Cursor::new(vec![7_u8; crate::door::INPUT_LIMIT + 1]);
        let error = stub_call_stream(
            &socket,
            &[OsString::from("door-attribution-probe")],
            input,
            io::sink(),
            io::sink(),
        )
        .expect_err("oversized input must survive success frame");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("door stdin exceeds limit"));
        server.join().expect("fixture server");

        let socket = crate::fixture_exec::fixture_socket_path(fixture.path().join("panic.sock"));
        let listener = UnixListener::bind(&socket).expect("panic fixture listener");
        let (permit, ready) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("panic fixture accept");
            let deadline = Instant::now() + Duration::from_secs(5);
            let _request = frame_read_until(&mut peer, deadline).expect("panic stub request");
            permit.send(()).expect("release panic input");
            io::copy(&mut peer, &mut io::sink()).expect("drain panic input");
            frame_write_until(
                &mut peer,
                &json!({"schema":2,"type":"final",
                "status":0,"reason":"door-complete","ref_check":"not-applicable","stdout_bytes":0,"stderr_bytes":0,
                "queue_state":"no-queue","queue_wall_seconds":null,
                "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0}),
                deadline,
            )
            .expect("panic success frame");
        });
        let error = stub_call_stream(
            &socket,
            &[OsString::from("door-attribution-probe")],
            PanicInput(ready),
            io::sink(),
            io::sink(),
        )
        .expect_err("panicked sender must survive success frame");
        assert!(error.to_string().contains("door stdin sender panicked"));
        server.join().expect("panic fixture server");
    }

    /// ´test:unit:door-stub-keeps-input-deadline-over-successful-final-frame´
    #[test]
    fn door_stub_keeps_input_deadline_over_successful_final_frame() {
        struct LateInput;
        impl io::Read for LateInput {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                thread::sleep(Duration::from_millis(650));
                buffer[0] = 7;
                Ok(1)
            }
        }
        let fixture = tempfile::tempdir().expect("stub deadline fixture");
        let socket = crate::fixture_exec::fixture_socket_path(fixture.path().join("deadline.sock"));
        let listener = UnixListener::bind(&socket).expect("fixture listener");
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("fixture accept");
            let deadline = Instant::now() + Duration::from_secs(5);
            let _request = frame_read_until(&mut peer, deadline).expect("stub request");
            io::copy(&mut peer, &mut io::sink()).expect("drain input");
            frame_write_until(
                &mut peer,
                &json!({"schema":2,"type":"final",
                    "status":0,"reason":"door-complete","ref_check":"not-applicable","stdout_bytes":0,"stderr_bytes":0,
                    "queue_state":"no-queue","queue_wall_seconds":null,
                    "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0}),
                deadline,
            )
            .expect("success frame");
        });
        let error = stub_call_stream(
            &socket,
            &[OsString::from("door-attribution-deadline")],
            LateInput,
            io::sink(),
            io::sink(),
        )
        .expect_err("late input must survive success frame");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("door stdin deadline"));
        server.join().expect("fixture server");
    }

    /// ´test:unit:door-stub-success-frame-ends-open-or-broken-input´
    #[test]
    fn door_stub_success_frame_ends_open_or_broken_input() {
        struct OpenInput(mpsc::Receiver<()>);
        impl io::Read for OpenInput {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                self.0.recv().map_err(io::Error::other)?;
                Ok(0)
            }
        }
        let fixture = tempfile::tempdir().expect("stub fixture");
        for open in [true, false] {
            let socket = crate::fixture_exec::fixture_socket_path(fixture.path().join(if open {
                "open.sock"
            } else {
                "broken.sock"
            }));
            let listener = UnixListener::bind(&socket).expect("fixture listener");
            let server = thread::spawn(move || {
                let (mut peer, _) = listener.accept().expect("fixture accept");
                let deadline = Instant::now() + Duration::from_secs(5);
                let _request = frame_read_until(&mut peer, deadline).expect("request frame");
                let _closed = peer.shutdown(std::net::Shutdown::Read);
                frame_write_until(
                    &mut peer,
                    &json!({"schema":2,"type":"final",
                    "status":0,"reason":"door-complete","ref_check":"not-applicable","stdout_bytes":0,"stderr_bytes":0,
                    "queue_state":"no-queue","queue_wall_seconds":null,
                    "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0}),
                    deadline,
                )
                .expect("success frame");
            });
            let (release, receiver) = mpsc::channel();
            let started = Instant::now();
            let reply = if open {
                stub_call_stream(
                    &socket,
                    &[OsString::from("door-attribution-probe")],
                    OpenInput(receiver),
                    io::sink(),
                    io::sink(),
                )
            } else {
                stub_call_stream(
                    &socket,
                    &[OsString::from("door-attribution-probe")],
                    io::Cursor::new(vec![7_u8; 2 * 1024 * 1024]),
                    io::sink(),
                    io::sink(),
                )
            }
            .expect("successful final status");
            assert_eq!(reply["status"], 0);
            assert!(started.elapsed() < super::POST_FINAL_STDIN_WAIT + Duration::from_secs(1));
            let _released = release.send(());
            server.join().expect("fixture server");
        }
    }

    /// ´test:unit:door-route-reader-is-bound-to-held-directory´
    #[test]
    fn door_route_reader_is_bound_to_held_directory() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let fixture = tempfile::tempdir().expect("route fixture");
        let route = fixture.path().join("route.json");
        fs::write(&route, b"fixture").expect("fixture route");
        let mut permissions = fs::metadata(&route).expect("route metadata").permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&route, permissions).expect("route mode");
        let held = fs::File::open(fixture.path()).expect("held route directory");
        let owner = nix::unistd::Uid::effective().as_raw();
        assert_eq!(
            read_owner_leaf(&held, "route.json", owner).expect("bound read"),
            b"fixture"
        );
        fs::remove_file(&route).expect("replace fixture route");
        symlink(fixture.path().join("elsewhere"), &route).expect("fixture link");
        assert_eq!(
            read_owner_leaf(&held, "route.json", owner)
                .expect_err("link refusal")
                .kind,
            "door-compute-registration"
        );
    }

    /// # Panics
    /// Panics only if fixture setup fails or transport admits unregistered or stale facts.
    /// ´test:unit:door-ssh-command-uses-only-registered-key-and-fixed-environment´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_ssh_command_uses_only_registered_key_and_fixed_environment() {
        let fixture = tempfile::tempdir().expect("route fixture");
        let home = fixture.path();
        let config = home.join(".config/loops/alpha");
        for directory in [
            home.to_path_buf(),
            home.join(".config"),
            home.join(".config/loops"),
            config.clone(),
        ] {
            fs::create_dir_all(&directory).expect("fixture directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private fixture home");
        }
        let key_path = config.join("door-key");
        let route = json!({"schema":1,"loop":"alpha","alias":"fixture",
            "mirror_root":"~/mirrors","node_root":"/srv/loops/loop-a","key_path":key_path,"compute_wrapper":"/opt/fixture/bin/report","compute_environment":json!({"RUSTUP_HOME":"/opt/fixture/rustup","PATH":"/opt/fixture/tools:/opt/fixture/cargo/bin:/usr/bin:/bin","PUBLIC_PACK_TEST_LINTER":"/opt/fixture/tools/superloop-lint"})});
        let registered_config = crate::door_node::fixture(&config);
        for (name, bytes) in [
            (
                "door-compute-registration.json",
                serde_json::to_vec(&route).expect("route"),
            ),
            ("door-ssh_config", registered_config.clone()),
        ] {
            let path = config.join(name);
            fs::write(&path, bytes).expect("fixture route file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("private route mode");
        }
        let held = fs::File::open(&config).expect("held config");
        let runner = HostRunner::load(
            &held,
            &config,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("registered route");
        assert_eq!(runner.probe_route()["key_path"], route["key_path"]);
        let owner = nix::unistd::Uid::effective().as_raw();
        fs::write(
            config.join("door-ssh_config"),
            b"Host fixture\nHostName stale.invalid\n",
        )
        .expect("stale derivative");
        assert_eq!(
            HostRunner::load(&held, &config, "alpha", owner)
                .err()
                .expect("drift refusal")
                .kind,
            "door-node-derived-drift"
        );
        // Restoring the pathname after the read must not bless the stale pinned bytes.
        let refusal = HostRunner::load_with(&held, &config, "alpha", owner, || {
            fs::write(config.join("replacement"), &registered_config).expect("valid replacement");
            fs::set_permissions(
                config.join("replacement"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("replacement mode");
            fs::rename(config.join("replacement"), config.join("door-ssh_config"))
                .expect("replace after pin");
        })
        .err()
        .expect("pinned drift refusal");
        assert_eq!(refusal.kind, "door-node-derived-drift");
        // Neither the record nor known-hosts may be obtained through a new directory pathname.
        fs::write(config.join("door-known_hosts"), b"stale key\n").expect("stale known hosts");
        let relocated = config.with_file_name("held-alpha");
        let refusal = HostRunner::load_with(&held, &config, "alpha", owner, || {
            fs::rename(&config, &relocated).expect("move held configuration");
            fs::create_dir(&config).expect("replacement directory");
            fs::set_permissions(&config, fs::Permissions::from_mode(0o700))
                .expect("directory mode");
            crate::door_node::fixture(&config);
            fs::write(
                config.join("door-compute-registration.json"),
                serde_json::to_vec(&route).expect("route bytes"),
            )
            .expect("replacement route");
            fs::set_permissions(
                config.join("door-compute-registration.json"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("route mode");
        })
        .err()
        .expect("held directory drift refusal");
        assert_eq!(refusal.kind, "door-node-derived-drift");
        fs::remove_dir_all(&config).expect("remove replacement directory");
        fs::rename(&relocated, &config).expect("restore held configuration");
        crate::door_node::fixture(&config);
        let mut changed_route = route.clone();
        changed_route["alias"] = json!("other");
        HostRunner::load_with(&held, &config, "alpha", owner, || {
            fs::write(
                config.join("door-compute-registration.json"),
                serde_json::to_vec(&changed_route).expect("changed route bytes"),
            )
            .expect("replace route after parse");
        })
        .expect("verify against already parsed route alias");
        fs::write(
            config.join("door-compute-registration.json"),
            serde_json::to_vec(&route).expect("route bytes"),
        )
        .expect("restore route");
        fs::remove_file(config.join("door-node-registration.json")).expect("remove registration");
        fs::write(
            config.join("door-ssh_config"),
            b"Host fixture\nProxyCommand false\n",
        )
        .expect("legacy directive");
        let refusal = HostRunner::load(&held, &config, "alpha", owner)
            .err()
            .expect("legacy refusal before parser");
        assert_eq!(refusal.kind, "door-node-unregistered-files");
        assert!(
            refusal.detail.contains("door-ssh_config")
                && refusal.detail.contains("door-known_hosts")
        );
        crate::door_node::fixture(&config);

        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            crate::door::Scope::Work,
        )
        .expect("registration");
        let command = runner
            .compute_command(&registration, &["git".to_owned(), "diff".to_owned()], 120.0)
            .expect("compute command");
        let remote = command
            .get_args()
            .last()
            .expect("remote")
            .to_str()
            .expect("UTF-8");
        assert!(remote.ends_with(&format!("'~/mirrors/R.git' 'R' '/srv/loops/loop-a' 120 '[\"git\",\"diff\"]' '/opt/fixture/bin/report' '{}'; else echo DOOR-COMPUTE-TOOL-REFUSAL >&2; exit 127; fi", route["compute_environment"])));

        assert!(!key_path.exists(), "the lane never makes or opens the key");
        for (directive, family) in [
            ("IdentityFile=other", "identity"),
            ("IdentityFile2 other", "identity"),
            ("  certificatefile other", "identity"),
            ("IdentityAgent other", "identity"),
            ("PKCS11Provider other", "identity"),
            ("SecurityKeyProvider other", "identity"),
            ("SmartcardDevice other", "identity"),
            ("AddKeysToAgent yes", "identity"),
            ("ControlMaster yes", "shared-connection"),
            ("ControlPath other", "shared-connection"),
            ("ControlPersist yes", "shared-connection"),
            ("Include other", "inclusion"),
            ("Match exec true", "matching"),
            ("mAtCh=all", "matching"),
            ("ProxyCommand true", "command"),
            ("ProxyJump other", "command"),
            ("LocalCommand true", "command"),
            ("PermitLocalCommand yes", "command"),
            ("KnownHostsCommand true", "command"),
            ("RemoteCommand true", "command"),
            ("ForwardAgent yes", "forwarding"),
            ("ForwardX11 yes", "forwarding"),
            ("ForwardX11Trusted yes", "forwarding"),
            ("ForwardX11Timeout 10", "forwarding"),
            ("LocalForward 1000 localhost:1000", "forwarding"),
            ("RemoteForward 1000 localhost:1000", "forwarding"),
            ("DynamicForward 1000", "forwarding"),
            ("PermitRemoteOpen any", "forwarding"),
            ("GatewayPorts yes", "forwarding"),
            ("Tunnel yes", "forwarding"),
            ("TunnelDevice any:any", "forwarding"),
            ("ForkAfterAuthentication yes", "session-control"),
            ("StdinNull yes", "session-control"),
            ("SessionType none", "session-control"),
        ] {
            let refusal = super::checked_ssh_options(
                format!("Host fixture\n{directive}\n").as_bytes(),
                "fixture",
            )
            .expect_err("forbidden directive refusal");
            assert_eq!(refusal.kind, "door-compute-registration");
            assert_eq!(
                refusal.detail,
                format!(
                    "SSH config {family} directive {} is forbidden",
                    directive
                        .trim_start()
                        .split(['=', ' ', '\t'])
                        .next()
                        .expect("directive")
                )
            );
        }
        for (bytes, detail) in [
            (vec![0xff], "SSH config is not UTF-8"),
            (
                b"Host fixture\nHostName other\\name\n".to_vec(),
                "SSH config backslash in directive HostName is forbidden",
            ),
            (
                b"Host fixture\n\"ProxyCommand\" true\n".to_vec(),
                "SSH config quote in directive \"ProxyCommand\" is forbidden",
            ),
            (
                b"Host fixture\nProxy\"Command\" true\n".to_vec(),
                "SSH config quote in directive Proxy\"Command\" is forbidden",
            ),
            (
                b"Host fixture\n\"Match\" exec true\n".to_vec(),
                "SSH config quote in directive \"Match\" is forbidden",
            ),
        ] {
            let refusal =
                super::checked_ssh_options(&bytes, "fixture").expect_err("invalid config refusal");
            assert_eq!(refusal.kind, "door-compute-registration");
            assert_eq!(refusal.detail, detail);
        }
        fs::write(config.join("door-ssh_config"), &registered_config)
            .expect("restore fixture config");
        // The loaded runner must retain checked bytes even when the owner's
        // configuration pathname is replaced before spawning SSH.
        fs::write(
            config.join("replacement"),
            b"Host fixture\nProxyCommand false\n",
        )
        .expect("replacement config");
        fs::rename(config.join("replacement"), config.join("door-ssh_config"))
            .expect("replace checked pathname");
        let checked_digest = super::ssh_config_digest(&registered_config);
        let replacement_digest = super::ssh_config_digest(
            &fs::read(config.join("door-ssh_config")).expect("replacement bytes"),
        );
        assert_ne!(checked_digest, replacement_digest);
        assert_eq!(
            runner.retirement_route()["ssh_config_sha256"],
            checked_digest
        );
        let script = config.join("fixture-ssh");
        crate::fixture_exec::write_executable(&script, b"#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({'args':sys.argv[1:],'env':sorted(os.environ)}))\n")
            .expect("closed and synced fixture executable");
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        assert_eq!(
            runner.allowed(
                &[
                    b"-o".to_vec(),
                    b"SendEnv=GIT_PROTOCOL".to_vec(),
                    b"fixture".to_vec(),
                    b"git-upload-pack '~/mirrors/R.git'".to_vec(),
                ],
                &registration,
            ),
            Some(Operation::GitUploadV2)
        );
        let output = ssh_fixture_output(&mut runner.command_for(
            &script,
            &registration,
            Operation::GitUploadV2,
        ))
        .expect("fixture command output");
        assert!(output.status.success());
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("fixture command json");
        let args = document["args"].as_array().expect("args");
        let words = args
            .iter()
            .map(|word| word.as_str().expect("word"))
            .collect::<Vec<_>>();
        assert_eq!(words[0..2], ["-F", "none"]);
        for option in [
            "hostname=192.0.2.1",
            "user=fixture",
            "port=2222",
            "stricthostkeychecking=yes",
            "globalknownhostsfile=/dev/null",
            "updatehostkeys=no",
            "IdentitiesOnly=yes",
            "PreferredAuthentications=publickey",
            "GSSAPIAuthentication=no",
            "HostbasedAuthentication=no",
            "IdentityAgent=none",
            "ControlMaster=no",
            "ControlPath=none",
            "SendEnv=GIT_PROTOCOL",
        ] {
            assert!(words.contains(&option), "missing {option}");
        }
        assert!(
            words.contains(
                &format!(
                    "userknownhostsfile={}",
                    config.join("door-known_hosts").display()
                )
                .as_str()
            )
        );
        assert!(words.contains(&format!("IdentityFile={}", key_path.display()).as_str()));
        assert_eq!(
            words[words.len() - 2..],
            ["fixture", "git-upload-pack ~/mirrors/R.git"]
        );
        let environment = document["env"].as_array().expect("environment");
        assert!(environment.iter().all(|name| {
            matches!(
                name.as_str(),
                Some("PATH" | "HOME" | "GIT_PROTOCOL" | "LC_CTYPE")
            )
        }));
        assert!(!environment.iter().any(|name| name == "SSH_AUTH_SOCK"));
        assert!(environment.iter().any(|name| name == "GIT_PROTOCOL"));
        let legacy = ssh_fixture_output(&mut runner.command_for(
            &script,
            &registration,
            Operation::GitUpload,
        ))
        .expect("protocol v0 fixture command");
        let legacy_document: serde_json::Value =
            serde_json::from_slice(&legacy.stdout).expect("protocol v0 fixture json");
        assert!(
            !legacy_document["env"]
                .as_array()
                .expect("legacy env")
                .iter()
                .any(|name| name == "GIT_PROTOCOL")
        );
        assert!(
            !legacy_document["args"]
                .as_array()
                .expect("legacy args")
                .iter()
                .any(|word| word == "SendEnv=GIT_PROTOCOL")
        );
        let held_home = fs::File::open(home).expect("held fixture home");
        fs::write(config.join("door-ssh_config"), &registered_config)
            .expect("restore checked config");
        fs::set_permissions(
            config.join("door-ssh_config"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("restore config custody");
        let _private = crate::home::activate_private_home(
            home,
            &held_home,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("private namespace mapping");
        let mapped_owner = nix::unistd::Uid::effective().as_raw();
        let private_directory = crate::pinned::open_protected(home, &config, mapped_owner)
            .expect("private route directory");
        assert_eq!(
            HostRunner::load(&private_directory, &config, "alpha", mapped_owner)
                .expect("private route")
                .probe_route()["key_path"],
            route["key_path"]
        );
    }

    impl Runner for FakeRunner {
        fn spawn(&self, _registration: &Registration, operation: Operation) -> io::Result<Child> {
            let script = match operation {
                Operation::ProbeEcho => {
                    "import sys\nsys.stdout.buffer.write(b'READY\\n');sys.stdout.buffer.flush()\nwhile True:\n b=sys.stdin.buffer.read(4096)\n if not b:break\n sys.stdout.buffer.write(b);sys.stdout.buffer.flush()\n"
                }
                Operation::ProbeStatus => "import sys\nsys.stdin.buffer.read();sys.exit(7)\n",
                Operation::ProbeDeadline => "import time\ntime.sleep(2)\n",
                Operation::Compute
                | Operation::GitReceive
                | Operation::GitUpload
                | Operation::GitUploadV2 => "import sys\nsys.stdin.buffer.read()\n",
            };
            Command::new("/usr/bin/python3")
                .args(["-u", "-c", script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        }
    }

    struct LockstepRunner;

    impl Runner for LockstepRunner {
        fn spawn(&self, _registration: &Registration, _operation: Operation) -> io::Result<Child> {
            Command::new("/usr/bin/python3")
                .args([
                    "-u",
                    "-c",
                    "import sys\nsys.stdout.buffer.write(b'0000')\nsys.stdout.buffer.flush()\nif sys.stdin.buffer.readline() != b'go\\n': sys.exit(2)\nsys.stdout.buffer.write(b'done')\nsys.stdout.buffer.flush()\n",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        }
    }

    struct PipeHoldingRunner;

    impl Runner for PipeHoldingRunner {
        fn spawn(&self, _registration: &Registration, _operation: Operation) -> io::Result<Child> {
            use std::os::unix::process::CommandExt as _;
            Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import os,sys,time\nif os.fork(): sys.exit(7)\ntime.sleep(10)\n",
                ])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        }

        fn owns_process_group(&self) -> bool {
            true
        }
    }

    /// ´test:unit:door-child-exit-keeps-status-with-open-input-and-descendant-pipe´
    #[test]
    fn door_child_exit_keeps_status_with_open_input_and_descendant_pipe() {
        let (mut client, mut server) = UnixStream::pair().expect("fixture peer");
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        let started = Instant::now();
        let service = thread::spawn(move || {
            super::serve_compute(
                &mut server,
                &registration,
                3000,
                Operation::ProbeStatus,
                &PipeHoldingRunner,
                started,
                started + Duration::from_secs(4),
                "no-queue",
                None,
                None,
                None,
            )
        });
        let reply = frame_read_until(&mut client, started + Duration::from_secs(4))
            .expect("bounded final status");
        assert_eq!(reply["status"], 7);
        assert_eq!(reply["compute_exit_status"], 7);
        assert_eq!(reply["reason"], "door-complete");
        assert!(started.elapsed() < Duration::from_secs(4));
        service
            .join()
            .expect("service join")
            .expect("service result");
    }

    fn fixture_with_runner(
        scope: Scope,
        runner: &'static dyn Runner,
    ) -> (
        Fixture,
        PathBuf,
        thread::JoinHandle<io::Result<serde_json::Value>>,
    ) {
        let temp = Fixture::new();
        temp.set_floor("enforce");
        let store = temp.store();
        for target in [ModeTarget::Loop, ModeTarget::class("ssh").expect("class")] {
            store
                .set_mode(
                    &target,
                    Mode::Enforce,
                    "fixture owner",
                    "fixture first setting",
                    "1",
                    &[],
                )
                .expect("fixture setting");
        }
        let rules = [
            "probe-echo",
            "probe-status",
            "probe-deadline",
            "git-receive",
            "git-upload",
            "git-upload-v2",
        ]
        .map(|operation| {
            json!({"operation":operation,"shape_key":format!("ssh:{operation}"),
                "decision":"allow","reason":"fixture rubric"})
        });
        let rubric = Rubric::decode(
            &json!({"schema":1,"class":"ssh","undecided_reason":"fixture missing rule",
            "rules":rules}),
        )
        .expect("fixture rubric");
        let owner_home = temp.home.clone();
        let socket = crate::fixture_exec::fixture_socket_path(temp.home.join("door.sock"));
        let listener = UnixListener::bind(&socket).expect("fixture socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            let started = Instant::now();
            let _socket_peer = peer_uid(&stream)?;
            let peer = 3000;
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                "R",
                peer,
                scope,
            )
            .map_err(io::Error::other)?;
            let request = frame_read_until(&mut stream, started + Duration::from_secs(2))?;
            let route = HostRunner {
                alias: "fixture".to_owned(),
                ssh_options: Vec::new(),
                ssh_config_sha256: String::new(),
                mirror_root: "~/mirrors".to_owned(),
                node_root: "/srv/loops/loop-a".to_owned(),
                key_path: PathBuf::from("~/door-key"),
                upload_output_limit: None,
                compute_wrapper: Some("/opt/fixture/bin/report".to_owned()),
                compute_environment: Some(
                    json!({"RUSTUP_HOME":"/opt/fixture/rustup","PATH":"/opt/fixture/tools:/opt/fixture/cargo/bin:/usr/bin:/bin","PUBLIC_PACK_TEST_LINTER":"/opt/fixture/tools/superloop-lint"}),
                ),
            };
            serve_request(
                &mut stream,
                &registration,
                peer,
                &request,
                Some(&route),
                Some(runner),
                Some(&owner_home),
                Some(&rubric),
                Some(&store),
                started,
            )
            .map(|(reply, _)| reply)
        });
        (temp, socket, server)
    }

    fn fixture(
        scope: Scope,
    ) -> (
        Fixture,
        PathBuf,
        thread::JoinHandle<io::Result<serde_json::Value>>,
    ) {
        fixture_with_runner(scope, &FakeRunner)
    }

    struct GatedInput {
        gate: Receiver<()>,
        bytes: io::Cursor<Vec<u8>>,
        started: bool,
    }

    impl io::Read for GatedInput {
        fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
            if !self.started {
                self.gate
                    .recv_timeout(Duration::from_secs(3))
                    .map_err(io::Error::other)?;
                self.started = true;
            }
            self.bytes.read(target)
        }
    }

    struct GatedOutput {
        bytes: Vec<u8>,
        gate: Option<Sender<()>>,
    }

    impl io::Write for GatedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            if self.bytes.starts_with(b"READY\n")
                && let Some(gate) = self.gate.take()
            {
                let _sent = gate.send(());
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct LockstepInput {
        gate: Receiver<()>,
        bytes: io::Cursor<Vec<u8>>,
        started: bool,
    }

    impl io::Read for LockstepInput {
        fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
            if !self.started {
                if self.gate.recv_timeout(Duration::from_secs(3)).is_err() {
                    return Ok(0);
                }
                self.started = true;
            }
            self.bytes.read(target)
        }
    }

    /// ´test:unit:door-stub-flushes-output-frame-before-stdin-reply´
    #[test]
    fn door_stub_flushes_output_frame_before_stdin_reply() {
        let (_temp, socket, server) = fixture_with_runner(Scope::Work, &LockstepRunner);
        let (read_end, write_end) = nix::unistd::pipe().expect("fixture output pipe");
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut pipe = fs::File::from(read_end);
            let mut bytes = [0_u8; 4];
            pipe.read_exact(&mut bytes)
                .expect("first output frame before stdin");
            sender.send(()).expect("release fixture stdin");
            let mut tail = [0_u8; 4];
            pipe.read_exact(&mut tail).expect("remaining output frame");
            assert_eq!(&tail, b"done");
            bytes
        });
        let input = LockstepInput {
            gate: receiver,
            bytes: io::Cursor::new(b"go\n".to_vec()),
            started: false,
        };
        let mut output = io::LineWriter::new(fs::File::from(write_end));
        let mut errors = Vec::new();
        let reply = stub_call_stream(
            &socket,
            &[OsString::from("door-attribution-probe")],
            input,
            &mut output,
            &mut errors,
        )
        .expect("lockstep reply before three-second stdin deadline");
        assert_eq!(
            reply["status"], 0,
            "the output frame must release fixture stdin"
        );
        assert_eq!(reply["stdout_bytes"], 8);
        assert_eq!(reader.join().expect("output reader"), *b"0000");
        assert_eq!(errors, Vec::<u8>::new());
        server.join().expect("server join").expect("server reply");
    }

    /// ´test:unit:door-duplex-drains-output-before-stdin-and-preserves-long-bytes´
    #[test]
    fn door_duplex_drains_output_before_stdin_and_preserves_long_bytes() {
        let (_temp, socket, server) = fixture(Scope::Work);
        let (sender, receiver) = mpsc::channel();
        let bytes = (0..1_048_576_u32)
            .map(|index| u8::try_from(index % 251).expect("bounded byte"))
            .collect::<Vec<_>>();
        let input = GatedInput {
            gate: receiver,
            bytes: io::Cursor::new(bytes.clone()),
            started: false,
        };
        let mut output = GatedOutput {
            bytes: Vec::new(),
            gate: Some(sender),
        };
        let mut errors = Vec::new();
        let reply = stub_call_stream(
            &socket,
            &[OsString::from("door-attribution-probe")],
            input,
            &mut output,
            &mut errors,
        )
        .expect("duplex reply");
        assert_eq!(reply["status"], 0);
        assert_eq!(reply["reason"], "door-complete");
        assert_eq!(reply["registration"]["run"], "R");
        assert_eq!(reply["registration"]["mirror_ref"], "refs/heads/lane/R");
        assert_eq!(reply["stdin_bytes"], bytes.len());
        assert_eq!(reply["stdout_bytes"], bytes.len() + 6);
        assert!(
            reply["compute_wall_seconds"]
                .as_f64()
                .is_some_and(|wall| wall > 0.0)
        );
        assert!(reply["mediation_wall_seconds"].is_number());
        assert_eq!(&output.bytes[..6], b"READY\n");
        assert_eq!(&output.bytes[6..], bytes);
        assert_eq!(errors, Vec::<u8>::new());
        let final_on_service = server.join().expect("server join").expect("server reply");
        assert_eq!(final_on_service["status"], reply["status"]);
        assert_eq!(final_on_service["stdin_bytes"], reply["stdin_bytes"]);
        assert_eq!(final_on_service["stdout_bytes"], reply["stdout_bytes"]);
    }

    /// ´test:unit:door-ref-and-authority-refusals-precede-compute-input´
    #[test]
    fn door_ref_and_authority_refusals_precede_compute_input() {
        let old = "0".repeat(40);
        let new = "1".repeat(40);
        let wrong = format!("{old} {new} refs/heads/lane/S\0 report-status\n");
        let mut input = format!("{:04x}", wrong.len() + 4).into_bytes();
        input.extend(wrong.as_bytes());
        input.extend(b"0000");
        assert_eq!(
            checked_ref_packet(&input, "refs/heads/lane/R").map_err(|refusal| refusal.reason),
            Err("door-changed-ref-refusal")
        );
        let (first_fixture, socket, server) = fixture(Scope::Work);
        let args = [
            OsString::from("fixture"),
            OsString::from("git-receive-pack '~/mirrors/R.git'"),
        ];
        let reply = stub_call(&socket, &args, &input).expect("changed ref reply");
        assert_eq!(reply["reason"], "door-changed-ref-refusal");
        assert_eq!(reply["stdin_bytes"], input.len());
        assert_eq!(reply["stdout_bytes"], 0);
        server.join().expect("server join").expect("server reply");
        drop(first_fixture);
        let (_temp, socket, server) = fixture(Scope::Work);
        let args = [
            OsString::from("other"),
            OsString::from("git-upload-pack '~/mirrors/R.git'"),
        ];
        let reply = stub_call(&socket, &args, b"").expect("authority reply");
        assert_eq!(reply["reason"], "door-caller-authority-refusal");
        server.join().expect("server join").expect("server reply");
    }

    include!("ref_check_tests.rs");
    #[path = "route_tests.rs"]
    mod route_tests;

    /// ´test:unit:door-shape-probe-cannot-execute-compute´
    #[test]
    fn door_shape_probe_cannot_execute_compute() {
        let (_temp, socket, server) = fixture(Scope::Work);
        let reply = stub_call(
            &socket,
            &[OsString::from("door-shape-probe"), OsString::from("R")],
            b"",
        )
        .expect("effect-free shape reply");
        assert_eq!(reply["reason"], "door-transport-pending");
        assert_eq!(reply["compute_wall_seconds"], 0.0);
        assert!(reply.get("registration").is_none());
        server.join().expect("server join").expect("server reply");
    }

    /// ´test:unit:door-peer-refusal-omits-sibling-registration´
    #[test]
    fn door_peer_refusal_omits_sibling_registration() {
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        let reply = super::refusal(&registration, 3001, "door-peer-refusal", Instant::now());
        assert_eq!(reply["reason"], "door-peer-refusal");
        assert!(reply.get("registration").is_none());
        assert!(!reply.to_string().contains("refs/heads/lane/R"));
    }

    /// ´test:unit:door-status-deadline-review-and-disconnect-have-typed-outcomes´
    #[test]
    fn door_status_deadline_review_and_disconnect_have_typed_outcomes() {
        struct DeadlineRunner;
        impl Runner for DeadlineRunner {
            fn spawn(&self, _: &Registration, _: Operation) -> io::Result<Child> {
                Command::new("/bin/sleep")
                    .arg("300")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
            }
        }
        let (first_fixture, socket, server) = fixture(Scope::Work);
        let reply = stub_call(&socket, &[OsString::from("door-attribution-status")], b"")
            .expect("status reply");
        assert_eq!(reply["status"], 7);
        assert_eq!(reply["reason"], "door-complete");
        server.join().expect("server join").expect("server reply");
        drop(first_fixture);
        let (second_fixture, socket, server) = fixture_with_runner(Scope::Work, &DeadlineRunner);
        let mut client = UnixStream::connect(&socket).expect("deadline client");
        let observation = Instant::now() + Duration::from_secs(120);
        // Admission gets a loaded-node budget; the runner cannot exit naturally
        // before it, and the client's observation bound is independently longer.
        frame_write_until(
            &mut client,
            &json!({"schema":2,
            "argv":[b"door-attribution-deadline".to_vec()],"deadline_ms":3000}),
            observation,
        )
        .expect("deadline request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("deadline stdin end");
        let reply = frame_read_until(&mut client, observation).expect("deadline reply");
        assert_eq!(reply["status"], 125);
        assert_eq!(reply["reason"], "door-deadline-refusal");
        server.join().expect("server join").expect("server reply");
        drop(second_fixture);
        let (third_fixture, socket, server) = fixture(Scope::Review);
        let reply = stub_call(&socket, &[OsString::from("door-attribution-probe")], b"")
            .expect("review reply");
        assert_eq!(reply["reason"], "door-review-compute-refusal");
        server.join().expect("server join").expect("server reply");
        drop(third_fixture);
        let (_temp, socket, server) = fixture(Scope::Work);
        let mut client = UnixStream::connect(&socket).expect("disconnect client");
        frame_write_until(
            &mut client,
            &json!({"schema":2,"argv":[b"door-attribution-probe".to_vec()],
            "deadline_ms":1000}),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("request");
        drop(client);
        let ended = server.join().expect("server join");
        assert!(
            ended.is_err(),
            "disconnected peer cannot receive a final status"
        );
    }
}
