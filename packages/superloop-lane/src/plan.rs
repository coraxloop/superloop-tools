use std::collections::BTreeMap;
use std::io::{self, Read as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use serde_json::{Value, json};

use crate::error::LaneError;
use crate::settings::Settings;

#[derive(Debug)]
pub struct Plan {
    pub home: PathBuf,
    pub driver_dir: PathBuf,
    pub letter: PathBuf,
    pub document: Value,
}

impl Plan {
    /// Retain the protected plan's optional attempt wall when rebuilding runtime pins.
    ///
    /// # Errors
    ///
    /// Refuses an explicit wall that is not a positive integer of seconds.
    pub(crate) fn retain_attempt_wall(&mut self, protected: &Value) -> Result<(), LaneError> {
        if let Some(value) = protected.get("attempt_wall_seconds") {
            let seconds = value
                .as_u64()
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| {
                    LaneError::input(
                        "attempt-wall",
                        "plan attempt_wall_seconds must be a positive integer",
                    )
                })?;
            self.document["attempt_wall_seconds"] = json!(seconds);
        } else if let Some(document) = self.document.as_object_mut() {
            document.remove("attempt_wall_seconds");
        }
        Ok(())
    }
}

/// Read the loop identity shared by the home group and driver directory owner.
///
/// # Errors
///
/// Refuses a plan without matching home and driver rows.
pub(crate) fn loop_uid(document: &Value) -> Result<u32, LaneError> {
    let paths = document
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| LaneError::input("loop-identity", "plan paths are absent"))?;
    let home = document
        .get("home")
        .and_then(Value::as_str)
        .ok_or_else(|| LaneError::input("loop-identity", "plan home is absent"))?;
    let driver = document
        .get("driver_dir")
        .and_then(Value::as_str)
        .ok_or_else(|| LaneError::input("loop-identity", "driver directory is absent"))?;
    let home_row = paths
        .first()
        .ok_or_else(|| LaneError::input("loop-identity", "home row is absent"))?;
    if home_row.get("path").and_then(Value::as_str) != Some(home) {
        return Err(LaneError::input(
            "loop-identity",
            "first plan path differs from home",
        ));
    }
    let uid = home_row
        .get("gid")
        .and_then(Value::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("loop-identity", "loop UID is absent"))?;
    let mut driver_rows = paths
        .iter()
        .filter(|row| row.get("path").and_then(Value::as_str) == Some(driver));
    let row = driver_rows
        .next()
        .ok_or_else(|| LaneError::input("loop-identity", "driver owner row is absent"))?;
    if driver_rows.next().is_some()
        || row.get("uid").and_then(Value::as_u64) != Some(u64::from(uid))
        || row.get("gid").and_then(Value::as_u64) != Some(u64::from(uid))
        || row.get("kind").and_then(Value::as_str) != Some("directory")
    {
        return Err(LaneError::input(
            "loop-identity",
            "driver owner row differs from loop UID",
        ));
    }
    Ok(uid)
}

pub(crate) fn protected_identity_dir(driver_dir: &Path) -> Result<PathBuf, LaneError> {
    let parent = driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?;
    let run = driver_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("run-name", "run name is not UTF-8"))?;
    Ok(parent.join(format!(".launch-{run}")))
}

pub(crate) fn protected_identifier_path(
    driver_dir: &Path,
    attempt: u32,
) -> Result<PathBuf, LaneError> {
    let parent = driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?;
    let run = driver_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("run-name", "run name is not UTF-8"))?;
    Ok(parent.join(format!(".container-{run}-attempt-{attempt}.id")))
}

const REGISTRY_LIMIT: usize = 65_536;
const REGISTRY_DEADLINE: Duration = Duration::from_secs(5);
const REGISTRY_POLL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

fn capture<R: io::Read + Send + 'static>(mut reader: R) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((REGISTRY_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_count| bytes)
    })
}

fn finish_capture(
    task: thread::JoinHandle<io::Result<Vec<u8>>>,
    stream: Stream,
    path: &Path,
) -> Result<Vec<u8>, LaneError> {
    let name = match stream {
        Stream::Stdout => "stdout",
        Stream::Stderr => "stderr",
    };
    let bytes = task
        .join()
        .map_err(|_| {
            LaneError::input(
                "registry-command",
                format!("{}: {name} reader panicked", path.display()),
            )
        })?
        .map_err(|error| {
            LaneError::input(
                "registry-command",
                format!("{}: {name} read failed: {error}", path.display()),
            )
        })?;
    if bytes.len() > REGISTRY_LIMIT {
        let kind = match stream {
            Stream::Stdout => "registry-stdout-size",
            Stream::Stderr => "registry-stderr-size",
        };
        return Err(LaneError::input(
            kind,
            format!("{} returned over {REGISTRY_LIMIT} bytes", path.display()),
        ));
    }
    Ok(bytes)
}

fn terminate_and_reap(child: &mut Child, path: &Path) -> Result<(), LaneError> {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _killed = kill(Pid::from_raw(-pid), Signal::SIGKILL);
    }
    let _killed = child.kill();
    child.wait().map_err(|error| {
        LaneError::input(
            "registry-command",
            format!("{}: reap failed: {error}", path.display()),
        )
    })?;
    Ok(())
}

fn path(path: &Path) -> Result<String, LaneError> {
    let value = path
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| LaneError::input("path-utf8", format!("{} is not UTF-8", path.display())))?;
    if value.contains(',') {
        return Err(LaneError::input(
            "path-delimiter",
            format!("{} contains a mount delimiter comma", path.display()),
        ));
    }
    Ok(value)
}

fn required<'a>(row: &'a Value, key: &'static str) -> Result<&'a str, LaneError> {
    row.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| LaneError::input("registry-row", format!("missing {key}")))
}

/// Ask the configured entry for one validated registry row with `show NAME`.
///
/// # Errors
///
/// Refuses an unsuccessful command or malformed response.
pub fn registry(settings: &Settings, loop_name: &str) -> Result<Value, LaneError> {
    registry_with_timeout(settings, loop_name, REGISTRY_DEADLINE)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn registry_with_timeout(
    settings: &Settings,
    loop_name: &str,
    timeout: Duration,
) -> Result<Value, LaneError> {
    registry_with_ready(settings, loop_name, timeout, || Ok(()))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn registry_with_ready(
    settings: &Settings,
    loop_name: &str,
    timeout: Duration,
    ready: impl FnOnce() -> Result<(), LaneError>,
) -> Result<Value, LaneError> {
    let entry_bin = settings.entry_bin.as_ref().ok_or_else(|| {
        LaneError::input("missing-setting", "entry_bin is absent in workers.toml")
    })?;
    let mut command = Command::new(entry_bin);
    command
        .arg("show")
        .arg(loop_name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = crate::fixture_exec::spawn(&mut command).map_err(|error| {
        LaneError::input(
            "registry-command",
            format!("{}: {error}", entry_bin.display()),
        )
    })?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child, entry_bin)?;
        return Err(LaneError::input(
            "registry-command",
            "standard output pipe was unavailable",
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child, entry_bin)?;
        return Err(LaneError::input(
            "registry-command",
            "standard error pipe was unavailable",
        ));
    };
    let mut stdout_capture = Some(capture(stdout));
    let mut stderr_capture = Some(capture(stderr));
    if let Err(error) = ready() {
        terminate_and_reap(&mut child, entry_bin)?;
        return Err(error);
    }
    let deadline = Instant::now() + timeout;
    let mut stdout_bytes = None;
    let mut stderr_bytes = None;
    let mut status = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(result) => status = result,
                Err(error) => {
                    terminate_and_reap(&mut child, entry_bin)?;
                    return Err(LaneError::input(
                        "registry-command",
                        format!("{}: status failed: {error}", entry_bin.display()),
                    ));
                }
            }
        }
        for (task, stream, result) in [
            (&mut stdout_capture, Stream::Stdout, &mut stdout_bytes),
            (&mut stderr_capture, Stream::Stderr, &mut stderr_bytes),
        ] {
            if task.as_ref().is_some_and(thread::JoinHandle::is_finished)
                && let Some(finished) = task.take()
            {
                match finish_capture(finished, stream, entry_bin) {
                    Ok(bytes) => *result = Some(bytes),
                    Err(error) => {
                        terminate_and_reap(&mut child, entry_bin)?;
                        return Err(error);
                    }
                }
            }
        }
        if status.is_some() && stdout_bytes.is_some() && stderr_bytes.is_some() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            terminate_and_reap(&mut child, entry_bin)?;
            return Err(LaneError::input(
                "registry-timeout",
                format!(
                    "{} exceeded {} ms",
                    entry_bin.display(),
                    timeout.as_millis()
                ),
            ));
        }
        thread::sleep(remaining.min(REGISTRY_POLL));
    }
    let status = status.ok_or_else(|| {
        LaneError::operation(
            "registry-command",
            "child status is absent after completed capture",
        )
    })?;
    let stdout_bytes = stdout_bytes.unwrap_or_default();
    let stderr_bytes = stderr_bytes.unwrap_or_default();
    if !status.success() {
        return Err(LaneError::input(
            "registry-command",
            format!(
                "{} exited {}: {}",
                entry_bin.display(),
                status,
                String::from_utf8_lossy(&stderr_bytes).trim_end()
            ),
        ));
    }
    serde_json::from_slice(&stdout_bytes).map_err(|error| {
        LaneError::input("registry-row", format!("{}: {error}", entry_bin.display()))
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row(
    rows: &mut Vec<Value>,
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    kind: &str,
) -> Result<(), LaneError> {
    rows.push(json!({"gid": gid, "kind": kind, "mode": format!("{mode:04o}"), "path": self::path(&path)?, "uid": uid}));
    Ok(())
}

fn mount(mounts: &mut Vec<Value>, source: &str, target: &str, access: &str, kind: &str) {
    mounts.push(json!({"access": access, "kind": kind, "measurement": "provisional; launch must verify", "source": source, "target": target}));
}

#[allow(clippy::too_many_lines)]
pub(crate) fn door_pin(
    owner_home: &Path,
    loop_name: &str,
    template: &Path,
    sockets: &Path,
    owner: u32,
    loop_uid: u32,
) -> Result<Option<Value>, LaneError> {
    const KEYS: [&str; 10] = [
        "schema",
        "phase",
        "loop",
        "template_dir",
        "socket_dir",
        "stub_sha256",
        "service_sha256",
        "unit_dir",
        "registered",
        "host_door_gid",
    ];
    let path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("door-install-generation.json");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LaneError::input("door-generation", error.to_string())),
        Ok(_) => {}
    }
    let Some(bytes) =
        crate::pinned::read_private_optional(owner_home, &path, owner, 0o600, 65_536)?
    else {
        return Ok(None);
    };
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("door-generation", error.to_string()))?;
    if record["schema"] == 1 {
        return Err(LaneError::input(
            "door-generation-upgrade-required",
            "run install-door with valid door.toml to replace the pre-agent generation",
        ));
    }
    if record.as_object().is_none_or(|object| {
        object.len() != KEYS.len() + 1
            || !object.contains_key("agent")
            || KEYS.iter().any(|key| !object.contains_key(*key))
    }) || record["schema"] != 2
        || record["phase"] != "complete"
        || record["loop"] != loop_name
        || record["registered"] != json!(["ssh"])
    {
        return Err(LaneError::input(
            "door-generation",
            "door generation shape differs",
        ));
    }
    let _agent = crate::door::config::runner(&record["agent"], owner_home, loop_name)?;
    let recorded_group = record["host_door_gid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("door-generation", "recorded host door group is absent"))?;
    if record["template_dir"].as_str() != template.to_str()
        || record["socket_dir"].as_str() != sockets.to_str()
    {
        return Ok(None);
    }
    let stub_group = if crate::home::private_is_active() {
        loop_uid
    } else {
        let door_directory =
            crate::pinned::open_protected(owner_home, &sockets.join("door"), owner)?;
        let stat = nix::sys::stat::fstat(&door_directory)
            .map_err(|error| LaneError::input("door-generation", error.to_string()))?;
        if nix::sys::stat::SFlag::from_bits_truncate(stat.st_mode) & nix::sys::stat::SFlag::S_IFMT
            != nix::sys::stat::SFlag::S_IFDIR
            || stat.st_uid != owner
            || stat.st_gid != recorded_group
            || stat.st_mode & 0o7777 != 0o750
        {
            return Err(LaneError::input(
                "door-generation",
                "registered socket directory differs",
            ));
        }
        // The host sees the row group through the owner's subordinate mapping.
        recorded_group
    };
    let digest = record["stub_sha256"]
        .as_str()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| LaneError::input("door-generation", "stub digest is absent"))?;
    let stub = template.join("libexec/ssh");
    let stub_bytes = crate::pinned::read_checked(
        owner_home,
        &stub,
        owner,
        (owner, stub_group, 0o550),
        64 * 1024 * 1024,
    )?;
    if crate::build::sha256_bytes(&stub_bytes, owner_home)? != digest {
        return Err(LaneError::input(
            "door-generation",
            "stub differs from installed digest",
        ));
    }
    let service = path.with_file_name("door-service");
    let service_bytes = crate::pinned::read_checked(
        owner_home,
        &service,
        owner,
        (owner, nix::unistd::Gid::effective().as_raw(), 0o700),
        64 * 1024 * 1024,
    )?;
    if record["service_sha256"] != crate::build::sha256_bytes(&service_bytes, owner_home)? {
        return Err(LaneError::input(
            "door-generation",
            "service differs from installed digest",
        ));
    }
    Ok(Some(
        json!({"schema":1,"socket": "/home/worker/.local/door/capability.sock","stub": "/home/worker/.local/libexec/superloop/ssh","stub_sha256":digest,"registered":["ssh"]}),
    ))
}

/// Freeze the mount targets and the authority behind each explicit binding.
/// The version changes whenever the runtime's implicit mount contract changes.
#[allow(clippy::too_many_lines)]
pub(crate) fn mount_inventory(
    mounts: &[Value],
    paths: &[Value],
    source_rows: &[Value],
) -> Result<Value, LaneError> {
    let mut entries = Vec::new();
    entries.push(json!({"target":"/","kind":"rootfs","access":"ro","source_role":"pinned-image","owner":"runtime"}));
    for mount in mounts {
        let target = required(mount, "target")?;
        let kind = required(mount, "kind")?;
        let access = required(mount, "access")?;
        let source = required(mount, "source")?;
        let (source_role, owner) = if kind == "tmpfs" && target == "/run/worker" {
            ("worker-runtime", mount["owner_uid"].clone())
        } else if kind == "bind" {
            let role = match target {
                "/home/worker" => "worker-home",
                "/mail" => "worker-mail",
                "/home/worker/.codex"
                | "/home/worker/.cache/work"
                | "/home/worker/.local/outbox"
                | "/home/worker/.local/sources" => "worker-leaf",
                "/home/worker/.local/bin"
                | "/home/worker/.local/libexec/superloop"
                | "/home/worker/.codex/config.toml"
                | "/home/worker/.codex/AGENTS.md" => "runner-template",
                "/home/worker/.local/vendor" => "capability-proxy",
                "/home/worker/.local/door" => "capability-door",
                "/etc/passwd" | "/etc/group" => "run-identity",
                _ => {
                    return Err(LaneError::input(
                        "mount-inventory",
                        format!("unnamed bind {target}"),
                    ));
                }
            };
            let row = paths
                .iter()
                .chain(source_rows)
                .find(|row| row["path"] == source)
                .ok_or_else(|| {
                    LaneError::input("mount-inventory", format!("{target}: owner row is absent"))
                })?;
            let uid = row["uid"].as_u64().ok_or_else(|| {
                LaneError::input("mount-inventory", format!("{target}: source UID is absent"))
            })?;
            (role, json!(uid))
        } else {
            ("podman-implicit", json!("runtime"))
        };
        let inventory_kind = if kind == "bind" {
            "bind"
        } else {
            match target {
                "/proc/kcore"
                | "/proc/keys"
                | "/proc/latency_stats"
                | "/proc/sched_debug"
                | "/proc/timer_list"
                | "/proc/timer_stats" => "masked-proc-file",
                "/proc/acpi" | "/proc/scsi" => "masked-proc",
                "/proc"
                | "/proc/asound"
                | "/proc/bus"
                | "/proc/fs"
                | "/proc/irq"
                | "/proc/sys"
                | "/proc/sysrq-trigger" => "proc",
                "/sys" | "/sys/firmware" => "sys",
                "/sys/fs/cgroup" => "cgroup",
                "/dev" | "/dev/null" | "/dev/zero" | "/dev/full" | "/dev/random"
                | "/dev/urandom" | "/dev/tty" | "/dev/console" => "dev",
                "/dev/pts" => "devpts",
                "/dev/mqueue" => "mqueue",
                "/etc/hosts" | "/etc/hostname" | "/etc/resolv.conf" | "/run/.containerenv" => {
                    "host-file"
                }
                "/run" | "/run/podman-init" | "/run/worker" | "/tmp" | "/var/tmp" | "/dev/shm" => {
                    "runtime-tmpfs"
                }
                _ => {
                    return Err(LaneError::input(
                        "mount-inventory",
                        format!("unnamed implicit mount {target}"),
                    ));
                }
            }
        };
        let presence = if kind == "conditional" {
            "optional"
        } else {
            "required"
        };
        let mut entry = json!({"target":target,"kind":inventory_kind,"access":access,"source":source,"source_role":source_role,"owner":owner,"presence":presence});
        if kind == "tmpfs" && target == "/run/worker" {
            entry["mode"] = mount["mode"].clone();
        }
        entries.push(entry);
    }
    Ok(json!({"version":1,"entries":entries}))
}

fn arg(args: &mut Vec<String>, option: &str, value: impl AsRef<str>) {
    args.push(format!("{option}={}", value.as_ref()));
}

/// Verify that the outer box supplies the confinement used by Codex tool calls.
///
/// # Errors
///
/// Refuses a missing or expanded runtime confinement option or writable mount.
#[allow(clippy::too_many_lines)]
pub(crate) fn box_gate(document: &Value) -> Result<Value, LaneError> {
    let argv = document["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("box-gate", "runtime argument vector is absent"))?;
    let words = argv
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| LaneError::input("box-gate", "runtime argument is not a string"))?;
    let image = document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("box-gate", "image digest is absent"))?;
    let image_position = words
        .iter()
        .position(|word| *word == image)
        .ok_or_else(|| LaneError::input("box-gate", "runtime image is absent"))?;
    let container_words = &words[..image_position];
    let worker_uid = document["worker_uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("box-gate", "worker UID is absent"))?;
    let required = [
        "--userns=host",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--security-opt=label=disable",
        "--read-only",
        "--read-only-tmpfs=true",
        "--network=none",
        "--pid=private",
        "--ipc=private",
        "--uts=private",
    ];
    for option in required {
        if container_words
            .iter()
            .filter(|word| **word == option)
            .count()
            != 1
        {
            return Err(LaneError::input(
                "box-gate",
                format!("{option} is absent or repeated"),
            ));
        }
    }
    let expected_user = format!("--user={worker_uid}:{worker_uid}");
    if container_words
        .iter()
        .filter(|word| **word == expected_user)
        .count()
        != 1
    {
        return Err(LaneError::input(
            "box-gate",
            "runtime worker identity differs from the allocated UID",
        ));
    }
    if container_words.iter().any(|word| {
        word.starts_with("--cap-add")
            || (word.starts_with("--cap-drop=") && *word != "--cap-drop=ALL")
            || word.starts_with("--privileged")
            || word.starts_with("--volume")
            || *word == "-v"
            || word.starts_with("--device")
            || word.starts_with("--tmpfs")
            || (word.starts_with("--read-only=") && *word != "--read-only=true")
            || (word.starts_with("--read-only-tmpfs=") && *word != "--read-only-tmpfs=true")
            || (word.starts_with("--user=") && *word != expected_user)
            || (word.starts_with("--network=") && *word != "--network=none")
            || (word.starts_with("--userns=") && *word != "--userns=host")
            || (word.starts_with("--pid=") && *word != "--pid=private")
            || (word.starts_with("--ipc=") && *word != "--ipc=private")
            || (word.starts_with("--uts=") && *word != "--uts=private")
            || (word.starts_with("--security-opt=")
                && ![
                    "--security-opt=no-new-privileges",
                    "--security-opt=label=disable",
                ]
                .contains(word))
    }) {
        return Err(LaneError::input(
            "box-gate",
            "runtime weakens container confinement",
        ));
    }
    if !words
        .windows(2)
        .any(|pair| pair == ["--sandbox", "danger-full-access"])
        || words
            .windows(2)
            .any(|pair| pair[0] == "--sandbox" && pair[1] != "danger-full-access")
    {
        return Err(LaneError::input(
            "box-gate",
            "Codex must use danger-full-access inside the box",
        ));
    }
    let mounts = document["mounts"]
        .as_array()
        .ok_or_else(|| LaneError::input("box-gate", "mount table is absent"))?;
    let home = document["home"]
        .as_str()
        .ok_or_else(|| LaneError::input("box-gate", "worker home is absent"))?;
    let leaves = [".codex", ".cache/work", ".local/outbox", ".local/sources"];
    let mut expected_mounts = Vec::new();
    for mount in mounts.iter().filter(|mount| mount["kind"] == "bind") {
        let source = mount["source"]
            .as_str()
            .ok_or_else(|| LaneError::input("box-gate", "bind source is absent"))?;
        let target = mount["target"]
            .as_str()
            .ok_or_else(|| LaneError::input("box-gate", "bind target is absent"))?;
        let access = mount["access"]
            .as_str()
            .ok_or_else(|| LaneError::input("box-gate", "bind access is absent"))?;
        if target == "/mail" {
            let mail = &document["mail"];
            if access != "rw"
                || mail["source"] != source
                || mail["identity"]["uid"] != worker_uid
                || mail["group"] != document["mail_gid"]
                || mail["service_uid"] == worker_uid
                || mail["service_uid"] == loop_uid(document)?
                || document["environment"]["SUPERLOOP_MAIL"] != "/mail"
                || !document["mount_sources"].as_array().is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row["path"] == source
                            && row["uid"] == mail["service_uid"]
                            && row["gid"] == mail["group"]
                            && row["mode"] == "0750"
                    })
                })
            {
                return Err(LaneError::input(
                    "box-gate",
                    "mail mount differs from its worker binding",
                ));
            }
        } else if access == "rw" {
            let leaf = leaves
                .iter()
                .find(|leaf| target == format!("/home/worker/{leaf}"))
                .ok_or_else(|| {
                    LaneError::input(
                        "box-gate",
                        format!("writable mount {target} is outside worker leaves"),
                    )
                })?;
            let expected_mode = if *leaf == ".local/outbox" {
                "0750"
            } else {
                "0700"
            };
            let expected_gid = if *leaf == ".local/outbox" {
                json!(loop_uid(document)?)
            } else {
                json!(worker_uid)
            };
            if source != format!("{home}/{leaf}")
                || !document["paths"].as_array().is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row["path"] == source
                            && row["uid"] == worker_uid
                            && row["gid"] == expected_gid
                            && row["mode"] == expected_mode
                    })
                })
            {
                return Err(LaneError::input(
                    "box-gate",
                    format!("{target} differs from its worker-owned leaf mode or group"),
                ));
            }
        } else if access != "ro" {
            return Err(LaneError::input(
                "box-gate",
                format!("{target} has invalid access {access}"),
            ));
        }
        expected_mounts.push(format!("type=bind,src={source},dst={target},{access}"));
    }
    if document["mail"].is_object()
        && mounts
            .iter()
            .filter(|mount| mount["target"] == "/mail")
            .count()
            != 1
    {
        return Err(LaneError::input(
            "box-gate",
            "one confined worker mail mount is required",
        ));
    }
    if !mounts.iter().any(|mount| {
        mount["target"] == "/home/worker" && mount["source"] == home && mount["access"] == "ro"
    }) || leaves.iter().any(|leaf| {
        !mounts.iter().any(|mount| {
            mount["target"] == format!("/home/worker/{leaf}") && mount["access"] == "rw"
        })
    }) || !mounts
        .iter()
        .any(|mount| mount["target"] == "/home/worker/.local/vendor" && mount["access"] == "ro")
        || [
            "/home/worker/.local/bin",
            "/home/worker/.local/libexec/superloop",
            "/home/worker/.codex/config.toml",
            "/home/worker/.codex/AGENTS.md",
        ]
        .iter()
        .any(|target| {
            !mounts
                .iter()
                .any(|mount| mount["target"] == *target && mount["access"] == "ro")
        })
        || document["environment"]["HTTPS_PROXY"] != "http://127.0.0.1:3128"
        || document["environment"]["HTTP_PROXY"] != "http://127.0.0.1:3128"
    {
        return Err(LaneError::input(
            "box-gate",
            "read-only home or template, worker leaves or proxy route is absent",
        ));
    }
    if document["door"].is_object() {
        let run = document["run"]
            .as_str()
            .ok_or_else(|| LaneError::input("box-gate", "run is absent"))?;
        let socket_source = document["mount_sources"].as_array().and_then(|rows| {
            rows.iter().find(|row| {
                row["path"]
                    == mounts
                        .iter()
                        .find(|mount| mount["target"] == "/home/worker/.local/door")
                        .map_or(Value::Null, |mount| mount["source"].clone())
            })
        });
        if !mounts
            .iter()
            .any(|mount| mount["target"] == "/home/worker/.local/door" && mount["access"] == "ro")
            || socket_source.is_none()
            || document["door"]["socket"] != "/home/worker/.local/door/capability.sock"
            || document["door"]["stub"] != document["environment"]["GIT_SSH_COMMAND"]
            || document["door"]["peer_uid"] != worker_uid
            || document["door"]["mirror_ref"] != format!("refs/heads/lane/{run}")
        {
            return Err(LaneError::input(
                "box-gate",
                "door registration or read-only bind differs",
            ));
        }
    }
    let actual_mounts = container_words
        .windows(2)
        .filter(|pair| pair[0] == "--mount")
        .map(|pair| pair[1])
        .collect::<Vec<_>>();
    expected_mounts.push("type=tmpfs,dst=/run/worker,tmpfs-mode=0700,U=true,notmpcopyup".into());
    if actual_mounts
        != expected_mounts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(LaneError::input(
            "box-gate",
            "runtime mounts differ from the checked mount table",
        ));
    }
    let loop_name = document["loop"]
        .as_str()
        .ok_or_else(|| LaneError::input("box-gate", "loop name is absent"))?;
    let run = document["run"]
        .as_str()
        .ok_or_else(|| LaneError::input("box-gate", "run name is absent"))?;
    let driver_dir = document["driver_dir"]
        .as_str()
        .ok_or_else(|| LaneError::input("box-gate", "driver directory is absent"))?;
    let loop_uid = u64::from(loop_uid(document)?);
    let mut permitted = vec![words[0].to_owned(), "run".into(), "-i".into()];
    arg(
        &mut permitted,
        "--name",
        format!("superloop-lane-{loop_name}-{run}-attempt-1"),
    );
    arg(
        &mut permitted,
        "--hostname",
        format!("lane-{loop_name}-{run}"),
    );
    arg(
        &mut permitted,
        "--cidfile",
        path(&protected_identifier_path(Path::new(driver_dir), 1)?)?,
    );
    arg(
        &mut permitted,
        "--label",
        format!("org.superloop.run={run}"),
    );
    arg(
        &mut permitted,
        "--label",
        format!("org.superloop.loop={loop_name}"),
    );
    permitted.extend(["--pull=never".into(), "--userns=host".into()]);
    arg(
        &mut permitted,
        "--user",
        format!("{worker_uid}:{worker_uid}"),
    );
    arg(&mut permitted, "--group-add", loop_uid.to_string());
    if let Some(value) = document.get("mail_gid") {
        let group = value
            .as_u64()
            .filter(|group| {
                (1000..=65535).contains(group)
                    && *group != 65534
                    && *group != worker_uid
                    && *group != loop_uid
            })
            .ok_or_else(|| LaneError::input("box-gate", "invalid dedicated mail group"))?;
        arg(&mut permitted, "--group-add", group.to_string());
    }
    permitted.extend(
        [
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--security-opt=label=disable",
            "--read-only",
            "--read-only-tmpfs=true",
            "--image-volume=ignore",
            "--network=none",
            "--pid=private",
            "--ipc=private",
            "--uts=private",
            "--cgroupns=private",
            "--cgroups=enabled",
        ]
        .map(String::from),
    );
    for (option, key) in [
        ("--memory", "memory_bytes"),
        ("--pids-limit", "pids_max"),
        ("--cpu-shares", "cpu_shares"),
    ] {
        let value = document["resources"][key]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or_else(|| LaneError::input("box-gate", format!("resources.{key} is absent")))?;
        arg(&mut permitted, option, value.to_string());
    }
    permitted.extend(["--init", "--stop-timeout=10", "--shm-size=64m"].map(String::from));
    for binding in expected_mounts {
        permitted.extend(["--mount".into(), binding]);
    }
    for key in [
        "HOME",
        "CODEX_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_SSH_COMMAND",
        "PATH",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
    ] {
        let value = document["environment"][key]
            .as_str()
            .ok_or_else(|| LaneError::input("box-gate", format!("environment {key} is absent")))?;
        permitted.extend(["-e".into(), format!("{key}={value}")]);
    }
    if document["mail"].is_object() {
        permitted.extend(["-e".into(), "SUPERLOOP_MAIL=/mail".into()]);
    }
    permitted.extend(
        [
            "--workdir",
            "/home/worker/.cache/work",
            "--entrypoint",
            "/usr/libexec/superloop/box-init",
        ]
        .map(String::from),
    );
    if document["vendor_mode"].is_string() {
        let socket = document["vendor_socket"]
            .as_str()
            .ok_or_else(|| LaneError::input("box-gate", "observing socket is absent"))?;
        permitted.extend([
            "-e".into(),
            format!("SUPERLOOP_VENDOR_SOCKET=/home/worker/.local/vendor/{socket}"),
        ]);
    }
    if container_words != permitted.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(LaneError::input(
            "box-gate",
            "runtime option prefix differs from the permitted plan",
        ));
    }
    let paths = document["paths"]
        .as_array()
        .ok_or_else(|| LaneError::input("mount-inventory", "plan paths are absent"))?;
    let sources = document["mount_sources"]
        .as_array()
        .ok_or_else(|| LaneError::input("mount-inventory", "source rows are absent"))?;
    if document["mount_inventory"] != mount_inventory(mounts, paths, sources)? {
        return Err(LaneError::input(
            "mount-inventory",
            "versioned inventory differs from planned mounts",
        ));
    }
    let bytes = serde_json::to_vec(&document["runtime_argv"])
        .map_err(|error| LaneError::operation("box-gate", error.to_string()))?;
    let runtime_argv_sha256 = crate::build::sha256_bytes(&bytes, Path::new("/"))?;
    Ok(
        json!({"verdict":"passed","container_options":required,"root":"read-only","template":"read-only","writable_leaves":leaves,"worker_uid":worker_uid,"network":"none; vendor socket through read-only proxy mount","inner_sandbox":"danger-full-access; outer box enforces mounts","runtime_argv_sha256":runtime_argv_sha256}),
    )
}

/// Verify that the stored gate attests the current complete vector.
///
/// # Errors
///
/// Refuses a changed vector or gate result.
pub(crate) fn verify_box_attestation(document: &Value) -> Result<(), LaneError> {
    if document["box_gate"] != box_gate(document)? {
        return Err(LaneError::input(
            "box-gate",
            "runtime vector differs from its attested digest",
        ));
    }
    Ok(())
}

impl Plan {
    /// Select one registry-granted worker identity for this exact run.
    ///
    /// # Errors
    ///
    /// Refuses a malformed candidate plan.
    pub fn select_worker_uid(&mut self, selected: u32) -> Result<(), LaneError> {
        let original = self.document["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| LaneError::operation("plan-json", "worker UID is absent"))?;
        let paths = self.document["paths"]
            .as_array_mut()
            .ok_or_else(|| LaneError::operation("plan-json", "paths are absent"))?;
        for row in paths {
            for key in ["uid", "gid"] {
                if row[key] == original {
                    row[key] = json!(selected);
                }
            }
        }
        let argv = self.document["runtime_argv"]
            .as_array_mut()
            .ok_or_else(|| LaneError::operation("plan-json", "runtime argv is absent"))?;
        let user = format!("--user={original}:{original}");
        let replacement = format!("--user={selected}:{selected}");
        let position = argv
            .iter()
            .position(|value| value == &user)
            .ok_or_else(|| LaneError::operation("plan-json", "worker --user is absent"))?;
        argv[position] = json!(replacement);
        self.document["worker_uid"] = json!(selected);
        if self.document["mail"].is_object() {
            self.document["mail"]["identity"]["uid"] = json!(selected);
        }
        if self.document["door"].is_object() {
            self.document["door"]["peer_uid"] = json!(selected);
        }
        self.document["worker_uid_allocation"] = json!("reserved-against-run-table");
        if let Some(mounts) = self.document["mounts"].as_array_mut() {
            for mount in mounts {
                if mount["target"] == "/run/worker" {
                    mount["owner_uid"] = json!(selected);
                    mount["group_gid"] = json!(selected);
                }
            }
        }
        self.document["mount_inventory"] = mount_inventory(
            self.document["mounts"]
                .as_array()
                .ok_or_else(|| LaneError::operation("plan-json", "mounts are absent"))?,
            self.document["paths"]
                .as_array()
                .ok_or_else(|| LaneError::operation("plan-json", "paths are absent"))?,
            self.document["mount_sources"]
                .as_array()
                .ok_or_else(|| LaneError::operation("plan-json", "mount sources are absent"))?,
        )?;
        if let Some(group) = self.document["mail_gid"].as_u64() {
            let adjusted = i128::from(group) + i128::from(selected) - i128::from(original);
            let adjusted = u32::try_from(adjusted).map_err(|_| {
                LaneError::input(
                    "mail-group",
                    "mail group adjustment is outside the mapped range",
                )
            })?;
            self.select_mail_group(adjusted)?;
        } else {
            self.document["box_gate"] = box_gate(&self.document)?;
        }
        Ok(())
    }

    /// Add the mailbox group selected from the protected allocation ledger.
    ///
    /// # Errors
    /// Refuses invalid identities or a malformed runtime vector.
    pub(crate) fn select_mail_group(&mut self, group: u32) -> Result<(), LaneError> {
        if !(1000..=65535).contains(&group)
            || group == 65534
            || self.document["worker_uid"] == group
            || u64::from(loop_uid(&self.document)?) == u64::from(group)
        {
            return Err(LaneError::input(
                "mail-group",
                "invalid dedicated mail group",
            ));
        }
        let previous = self.document.get("mail_gid").and_then(Value::as_u64);
        let argv = self.document["runtime_argv"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("mail-group", "runtime vector is absent"))?;
        if let Some(previous) = previous {
            let word = format!("--group-add={previous}");
            let index = argv
                .iter()
                .position(|value| value == &word)
                .ok_or_else(|| LaneError::input("mail-group", "recorded mail group is absent"))?;
            argv.remove(index);
        }
        let index = argv
            .iter()
            .position(|value| value == "--cap-drop=ALL")
            .ok_or_else(|| {
                LaneError::input("mail-group", "runtime privilege boundary is absent")
            })?;
        argv.insert(index, json!(format!("--group-add={group}")));
        self.document["mail_gid"] = json!(group);
        if self.document["mail"].is_object() {
            self.document["mail"]["group"] = json!(group);
            let source = self.document["mail"]["source"].clone();
            if let Some(rows) = self.document["mount_sources"].as_array_mut() {
                for row in rows.iter_mut().filter(|row| row["path"] == source) {
                    row["gid"] = json!(group);
                }
            }
        }
        self.document["box_gate"] = box_gate(&self.document)?;
        Ok(())
    }

    /// Bind only this worker's separately provisioned mailbox at `/mail`.
    ///
    /// # Errors
    /// Refuses a mismatched identity, a relative source, or a malformed confinement plan.
    pub fn select_mailbox(
        &mut self,
        source: &Path,
        identity: &loop_home::mail::birth::Identity,
        service: u32,
    ) -> Result<(), LaneError> {
        loop_home::registry::validate_name(&identity.name)
            .map_err(|error| LaneError::input("mail-mount", error.message()))?;
        if self.document["worker_uid"] != identity.uid || !source.is_absolute() {
            return Err(LaneError::input(
                "mail-mount",
                "mailbox identity or source differs",
            ));
        }
        let source = path(source)?;
        let group = self.document["mail_gid"].clone();
        if self.document["mail"].is_object() {
            if self.document["mail"]
                != json!({"identity":identity,"source":source,"target":"/mail","service_uid":service,"group":group})
            {
                return Err(LaneError::input(
                    "mail-mount",
                    "mail binding cannot change within a worker lifetime",
                ));
            }
            self.document["box_gate"] = box_gate(&self.document)?;
            return Ok(());
        }
        self.document["mail"] = json!({"identity":identity,"source":source,"target":"/mail","service_uid":service,"group":group});
        self.document["environment"]["SUPERLOOP_MAIL"] = json!("/mail");
        self.document["mounts"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("mail-mount", "mounts absent"))?
            .push(json!({"source":source,"target":"/mail","access":"rw","kind":"bind"}));
        self.document["mount_sources"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("mail-mount", "source rows absent"))?
            .push(
                json!({"path":source,"uid":service,"gid":group,"mode":"0750","kind":"directory"}),
            );
        let argv = self.document["runtime_argv"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("mail-mount", "runtime vector absent"))?;
        // Bind mounts precede the fixed runtime tmpfs and environment options.
        let tmpfs = argv
            .iter()
            .position(|value| {
                value == "type=tmpfs,dst=/run/worker,tmpfs-mode=0700,U=true,notmpcopyup"
            })
            .ok_or_else(|| LaneError::input("mail-mount", "runtime tmpfs absent"))?;
        argv.splice(
            tmpfs - 1..tmpfs - 1,
            [
                json!("--mount"),
                json!(format!("type=bind,src={source},dst=/mail,rw")),
            ],
        );
        let workdir = argv
            .iter()
            .position(|value| value == "--workdir")
            .ok_or_else(|| LaneError::input("mail-mount", "workdir absent"))?;
        argv.splice(
            workdir..workdir,
            [json!("-e"), json!("SUPERLOOP_MAIL=/mail")],
        );
        self.document["mount_inventory"] = mount_inventory(
            self.document["mounts"]
                .as_array()
                .ok_or_else(|| LaneError::input("mail-mount", "mounts absent"))?,
            self.document["paths"]
                .as_array()
                .ok_or_else(|| LaneError::input("mail-mount", "paths absent"))?,
            self.document["mount_sources"]
                .as_array()
                .ok_or_else(|| LaneError::input("mail-mount", "sources absent"))?,
        )?;
        self.document["box_gate"] = box_gate(&self.document)?;
        Ok(())
    }

    /// Bind the runtime vector to the container program selected for this run.
    ///
    /// # Errors
    ///
    /// Refuses a missing runtime vector or nonabsolute program path.
    pub fn select_container_program(&mut self, program: &Path) -> Result<(), LaneError> {
        let program_word = crate::pinned::path_word(program, "owner-program")?;
        if !program.is_absolute()
            || program.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(LaneError::input(
                "container-program",
                "container program is not an absolute link-free path",
            ));
        }
        let argv = self.document["runtime_argv"]
            .as_array_mut()
            .ok_or_else(|| LaneError::operation("plan-json", "runtime argv is absent"))?;
        let first = argv
            .first_mut()
            .ok_or_else(|| LaneError::operation("plan-json", "runtime program is absent"))?;
        *first = json!(program_word);
        self.document["box_gate"] = box_gate(&self.document)?;
        Ok(())
    }
    /// Build the complete candidate launch document without changing disk.
    ///
    /// # Errors
    ///
    /// Refuses missing or invalid registry fields and non-UTF-8 paths.
    #[allow(clippy::too_many_lines)]
    pub fn build(
        home_root: &Path,
        loop_name: &str,
        run: &str,
        settings: &Settings,
        registry: &Value,
        worker_block: loop_home::registry::WorkerBlock,
        caller: (u32, u32),
    ) -> Result<Self, LaneError> {
        Self::build_with_door(
            home_root,
            loop_name,
            run,
            settings,
            registry,
            worker_block,
            caller,
            true,
        )
    }

    /// Build paths for a protected run-record reader without pinning a new box door.
    ///
    /// # Errors
    ///
    /// Refuses invalid settings, registry fields, or other plan inputs.
    pub(crate) fn build_for_record(
        home_root: &Path,
        loop_name: &str,
        run: &str,
        settings: &Settings,
        registry: &Value,
        worker_block: loop_home::registry::WorkerBlock,
        caller: (u32, u32),
    ) -> Result<Self, LaneError> {
        Self::build_with_door(
            home_root,
            loop_name,
            run,
            settings,
            registry,
            worker_block,
            caller,
            false,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn build_with_door(
        home_root: &Path,
        loop_name: &str,
        run: &str,
        settings: &Settings,
        registry: &Value,
        worker_block: loop_home::registry::WorkerBlock,
        caller: (u32, u32),
        include_door: bool,
    ) -> Result<Self, LaneError> {
        let entry_bin = settings.entry_bin.as_ref().ok_or_else(|| {
            LaneError::input("missing-setting", "entry_bin is absent in workers.toml")
        })?;
        let driver_bin = settings.driver_bin.as_ref().ok_or_else(|| {
            LaneError::input("missing-setting", "driver_argv is absent in workers.toml")
        })?;
        let backend_argv = settings.backend_argv.get("codex").ok_or_else(|| {
            LaneError::input(
                "missing-setting",
                "backend_argv.codex is absent in workers.toml",
            )
        })?;
        let template_dir = settings.template_dir.as_ref().ok_or_else(|| {
            LaneError::input("missing-setting", "template_dir is absent in workers.toml")
        })?;
        let socket_dir = settings.socket_dir.as_ref().ok_or_else(|| {
            LaneError::input("missing-setting", "socket_dir is absent in workers.toml")
        })?;
        let image_digest = settings.image_digest.as_ref().ok_or_else(|| {
            LaneError::input("missing-setting", "image_digest is absent in workers.toml")
        })?;
        let resources = settings.resources.as_ref().ok_or_else(|| {
            LaneError::input("missing-setting", "resources is absent in workers.toml")
        })?;
        if required(registry, "name")? != loop_name {
            return Err(LaneError::input(
                "registry-row",
                format!("name differs from {loop_name}"),
            ));
        }
        let loop_uid = registry
            .get("uid")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| LaneError::input("registry-row", "missing uid"))?;
        let door_floor = match registry.get("door_floor") {
            None => "audit",
            Some(Value::String(value))
                if matches!(value.as_str(), "audit" | "enforce" | "allow") =>
            {
                value
            }
            Some(_) => return Err(LaneError::input("registry-row", "door_floor is invalid")),
        };
        let worker_uid = worker_block.base;
        let door = if include_door {
            door_pin(
                home_root,
                loop_name,
                template_dir,
                socket_dir,
                nix::unistd::Uid::effective().as_raw(),
                loop_uid,
            )?
        } else {
            None
        };
        let runs_root = PathBuf::from(required(registry, "runs_root")?);
        if !runs_root.is_absolute()
            || runs_root
                .to_string_lossy()
                .split('/')
                .any(|part| part == "." || part == "..")
        {
            return Err(LaneError::input(
                "registry-row",
                format!("invalid runs_root: {}", runs_root.display()),
            ));
        }
        if settings
            .runs_root
            .as_deref()
            .is_some_and(|configured| configured != runs_root)
        {
            return Err(LaneError::input(
                "settings-grant",
                "runs_root differs from the registry row",
            ));
        }
        let home = home_root
            .join(".cache/tmp")
            .join(format!("lane-{loop_name}-{run}"));
        let driver_dir = runs_root.join(run);
        let identity_dir = protected_identity_dir(&driver_dir)?;
        let letter = home.join("brief.txt");
        let t = template_dir;
        let s = socket_dir;
        let mut rows = Vec::new();
        row(
            &mut rows,
            home.clone(),
            caller.0,
            loop_uid,
            0o750,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".ssh"),
            caller.0,
            loop_uid,
            0o750,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".ssh/config"),
            caller.0,
            loop_uid,
            0o640,
            "file",
        )?;
        row(
            &mut rows,
            home.join(".gitconfig"),
            caller.0,
            loop_uid,
            0o640,
            "file",
        )?;
        row(
            &mut rows,
            home.join(".codex"),
            worker_uid,
            worker_uid,
            0o700,
            "directory",
        )?;
        for name in ["config.toml", "AGENTS.md"] {
            row(
                &mut rows,
                home.join(".codex").join(name),
                worker_uid,
                worker_uid,
                0o600,
                "mountpoint",
            )?;
        }
        row(
            &mut rows,
            home.join(".codex/auth.json"),
            worker_uid,
            worker_uid,
            0o600,
            "file",
        )?;
        row(
            &mut rows,
            home.join(".cache"),
            worker_uid,
            worker_uid,
            0o700,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".cache/work"),
            worker_uid,
            worker_uid,
            0o700,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".local"),
            caller.0,
            loop_uid,
            0o750,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".local/bin"),
            caller.0,
            loop_uid,
            0o550,
            "mountpoint",
        )?;
        row(
            &mut rows,
            home.join(".local/libexec"),
            caller.0,
            loop_uid,
            0o750,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".local/libexec/superloop"),
            caller.0,
            loop_uid,
            0o550,
            "mountpoint",
        )?;
        row(
            &mut rows,
            home.join(".local/inbox"),
            caller.0,
            loop_uid,
            0o750,
            "directory",
        )?;
        row(&mut rows, letter.clone(), caller.0, loop_uid, 0o640, "file")?;
        row(
            &mut rows,
            home.join(".local/outbox"),
            worker_uid,
            loop_uid,
            0o750,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".local/sources"),
            worker_uid,
            worker_uid,
            0o700,
            "directory",
        )?;
        row(
            &mut rows,
            home.join(".local/door"),
            caller.0,
            loop_uid,
            0o750,
            "mountpoint",
        )?;
        row(
            &mut rows,
            home.join(".local/vendor"),
            caller.0,
            loop_uid,
            0o750,
            "mountpoint",
        )?;
        row(
            &mut rows,
            driver_dir.clone(),
            loop_uid,
            loop_uid,
            0o700,
            "directory",
        )?;
        row(
            &mut rows,
            driver_dir.join("launch"),
            loop_uid,
            loop_uid,
            0o700,
            "directory",
        )?;
        row(
            &mut rows,
            identity_dir.clone(),
            caller.0,
            caller.1,
            0o700,
            "directory",
        )?;
        row(
            &mut rows,
            identity_dir.join("passwd"),
            caller.0,
            loop_uid,
            0o440,
            "file",
        )?;
        row(
            &mut rows,
            identity_dir.join("group"),
            caller.0,
            loop_uid,
            0o440,
            "file",
        )?;
        row(
            &mut rows,
            driver_dir.join("plan.json"),
            loop_uid,
            loop_uid,
            0o600,
            "file",
        )?;
        row(
            &mut rows,
            driver_dir.join("settings.toml"),
            loop_uid,
            loop_uid,
            0o600,
            "file",
        )?;
        let mut mount_source_rows = Vec::new();
        for name in ["bin", "libexec"] {
            row(
                &mut mount_source_rows,
                t.join(name),
                caller.0,
                loop_uid,
                0o550,
                "directory",
            )?;
        }
        for name in ["config.toml", "AGENTS.md"] {
            row(
                &mut mount_source_rows,
                t.join(name),
                caller.0,
                loop_uid,
                0o440,
                "file",
            )?;
        }
        row(
            &mut mount_source_rows,
            s.join("vendor"),
            caller.0,
            loop_uid,
            0o750,
            "directory",
        )?;
        if door.is_some() {
            row(
                &mut mount_source_rows,
                s.join("door"),
                caller.0,
                loop_uid,
                0o750,
                "directory",
            )?;
        }
        let mut mounts = Vec::new();
        mount(&mut mounts, &path(&home)?, "/home/worker", "ro", "bind");
        for leaf in [".codex", ".cache/work", ".local/outbox", ".local/sources"] {
            mount(
                &mut mounts,
                &path(&home.join(leaf))?,
                &format!("/home/worker/{leaf}"),
                "rw",
                "bind",
            );
        }
        mount(
            &mut mounts,
            &path(&t.join("bin"))?,
            "/home/worker/.local/bin",
            "ro",
            "bind",
        );
        mount(
            &mut mounts,
            &path(&t.join("libexec"))?,
            "/home/worker/.local/libexec/superloop",
            "ro",
            "bind",
        );
        mount(
            &mut mounts,
            &path(&t.join("config.toml"))?,
            "/home/worker/.codex/config.toml",
            "ro",
            "bind",
        );
        mount(
            &mut mounts,
            &path(&t.join("AGENTS.md"))?,
            "/home/worker/.codex/AGENTS.md",
            "ro",
            "bind",
        );
        mount(
            &mut mounts,
            &path(&s.join("vendor"))?,
            "/home/worker/.local/vendor",
            "ro",
            "bind",
        );
        if door.is_some() {
            mount(
                &mut mounts,
                &path(&s.join("door"))?,
                "/home/worker/.local/door",
                "ro",
                "bind",
            );
        }
        mount(
            &mut mounts,
            &path(&identity_dir.join("passwd"))?,
            "/etc/passwd",
            "ro",
            "bind",
        );
        mount(
            &mut mounts,
            &path(&identity_dir.join("group"))?,
            "/etc/group",
            "ro",
            "bind",
        );
        for target in [
            "/dev",
            "/dev/shm",
            "/run",
            "/tmp",
            "/var/tmp",
            "/run/podman-init",
        ] {
            mount(&mut mounts, "runtime", target, "runtime", "implicit");
        }
        mounts.push(json!({"access":"rw","kind":"tmpfs","measurement":"provisional; launch must verify","source":"runtime","target":"/run/worker","owner_uid":worker_uid,"group_gid":worker_uid,"mode":"0700","empty":true}));
        for target in [
            "/proc",
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger",
            "/sys",
            "/sys/firmware",
            "/sys/fs/cgroup",
            "/dev/pts",
            "/dev/mqueue",
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/console",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/run/.containerenv",
            "/proc/kcore",
            "/proc/keys",
            "/proc/timer_list",
            "/proc/acpi",
            "/proc/asound",
            "/proc/latency_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/proc/timer_stats",
        ] {
            let access = if [
                "/proc/asound",
                "/proc/sys",
                "/proc/sysrq-trigger",
                "/sys",
                "/sys/fs/cgroup",
            ]
            .contains(&target)
            {
                "ro"
            } else {
                "runtime"
            };
            mount(&mut mounts, "runtime", target, access, "conditional");
        }
        let mut env = BTreeMap::new();
        for (key, value) in [
            ("HOME", "/home/worker"),
            ("CODEX_HOME", "/home/worker/.codex"),
            ("XDG_CACHE_HOME", "/home/worker/.cache"),
            ("XDG_RUNTIME_DIR", "/run/worker"),
            ("TMPDIR", "/tmp"),
            ("GIT_CONFIG_GLOBAL", "/home/worker/.gitconfig"),
            (
                "GIT_SSH_COMMAND",
                "/home/worker/.local/libexec/superloop/ssh",
            ),
            (
                "PATH",
                "/home/worker/.local/bin:/usr/local/bin:/usr/bin:/bin",
            ),
            ("HTTPS_PROXY", "http://127.0.0.1:3128"),
            ("HTTP_PROXY", "http://127.0.0.1:3128"),
            ("NO_PROXY", "127.0.0.1"),
        ] {
            env.insert(key, value);
        }
        let mut args = vec!["/usr/bin/podman".into(), "run".into(), "-i".into()];
        arg(
            &mut args,
            "--name",
            format!("superloop-lane-{loop_name}-{run}-attempt-1"),
        );
        arg(&mut args, "--hostname", format!("lane-{loop_name}-{run}"));
        arg(
            &mut args,
            "--cidfile",
            path(&protected_identifier_path(&driver_dir, 1)?)?,
        );
        arg(&mut args, "--label", format!("org.superloop.run={run}"));
        arg(
            &mut args,
            "--label",
            format!("org.superloop.loop={loop_name}"),
        );
        for option in ["--pull=never", "--userns=host"] {
            args.push(option.into());
        }
        arg(&mut args, "--user", format!("{worker_uid}:{worker_uid}"));
        arg(&mut args, "--group-add", loop_uid.to_string());
        for option in [
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--security-opt=label=disable",
            "--read-only",
            "--read-only-tmpfs=true",
            "--image-volume=ignore",
            "--network=none",
            "--pid=private",
            "--ipc=private",
            "--uts=private",
            "--cgroupns=private",
            "--cgroups=enabled",
        ] {
            args.push(option.into());
        }
        arg(&mut args, "--memory", resources.memory_bytes.to_string());
        arg(&mut args, "--pids-limit", resources.pids_max.to_string());
        arg(&mut args, "--cpu-shares", resources.cpu_shares.to_string());
        for option in ["--init", "--stop-timeout=10", "--shm-size=64m"] {
            args.push(option.into());
        }
        for binding in mounts.iter().filter(|binding| binding["kind"] == "bind") {
            args.push("--mount".into());
            args.push(format!(
                "type=bind,src={},dst={},{}",
                binding["source"].as_str().unwrap_or_default(),
                binding["target"].as_str().unwrap_or_default(),
                binding["access"].as_str().unwrap_or_default()
            ));
        }
        args.extend([
            "--mount".into(),
            "type=tmpfs,dst=/run/worker,tmpfs-mode=0700,U=true,notmpcopyup".into(),
        ]);
        for key in [
            "HOME",
            "CODEX_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
            "GIT_CONFIG_GLOBAL",
            "GIT_SSH_COMMAND",
            "PATH",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
        ] {
            args.push("-e".into());
            args.push(format!(
                "{key}={}",
                env.get(key).copied().unwrap_or_default()
            ));
        }
        args.extend(
            [
                "--workdir",
                "/home/worker/.cache/work",
                "--entrypoint",
                "/usr/libexec/superloop/box-init",
            ]
            .map(String::from),
        );
        args.push(image_digest.clone());
        args.push("/home/worker/.local/bin/codex".into());
        args.extend(backend_argv.iter().skip(1).cloned());
        args.extend(["exec", "--json", "--sandbox"].map(String::from));
        args.push(settings.sandbox_mode.clone());
        args.extend(
            [
                "--skip-git-repo-check",
                "-C",
                "/home/worker/.cache/work",
                "-o",
                "/home/worker/.cache/work/last-message.md",
            ]
            .map(String::from),
        );
        args.push("-".into());
        let inventory = mount_inventory(&mounts, &rows, &mount_source_rows)?;
        let vendor_hosts = settings
            .vendor_hosts
            .get("codex")
            .cloned()
            .unwrap_or_default();
        let installed_roots = image_digest.strip_prefix("sha256:").is_some_and(|digest| {
            template_dir.as_path()
                == home_root
                    .join(".var/loops")
                    .join(loop_name)
                    .join("runner-templates/codex")
                    .join(digest)
                    .as_path()
                && socket_dir.as_path()
                    == home_root
                        .join(".var/loops")
                        .join(loop_name)
                        .join("sockets")
                        .as_path()
        });
        let mut document = json!({"door_floor":door_floor,"driver_bin": path(driver_bin)?, "driver_argv": settings.driver_argv, "driver_dir": path(&driver_dir)?, "entry_bin": path(entry_bin)?, "environment": env, "home": path(&home)?, "image_digest": image_digest, "letter": path(&letter)?, "loop": loop_name, "mounts": mounts, "mount_sources":mount_source_rows, "mount_inventory": inventory, "owner_refresh_hosts": [crate::credential::REFRESH_HOST], "path_measurement": "provisional; make-home reports actual", "paths": rows, "resources":{"memory_bytes":resources.memory_bytes,"pids_max":resources.pids_max,"cpu_shares":resources.cpu_shares,"cpu_weight_requested":resources.cpu_weight_requested()}, "run": run, "runtime_argv": args, "runtime_measurement": "provisional; launch must probe", "sandbox_mode":settings.sandbox_mode,"source_measurement": "provisional; owner install and launch must verify image, driver, template and sockets", "template_measurement": "provisional; owner install must verify", "vendor_hosts":vendor_hosts,"worker_uid": worker_uid, "worker_uid_allocation": "provisional-first-slot; launch must reserve"});
        if let Some(seconds) = settings.attempt_wall_seconds()? {
            document["attempt_wall_seconds"] = json!(seconds);
        }
        if let Some(door) = door {
            document["door"] = door;
            document["door"]["peer_uid"] = json!(worker_uid);
            document["door"]["mirror_ref"] = json!(format!("refs/heads/lane/{run}"));
        }
        document["box_gate"] = box_gate(&document)?;
        if include_door && installed_roots && !document["door"].is_object() {
            let service = home_root
                .join(".config/loops")
                .join(loop_name)
                .join("door-service");
            match std::fs::symlink_metadata(&service) {
                Ok(_) => {
                    return Err(LaneError::input(
                        "door-generation",
                        "registered door generation is absent or names other roots",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(LaneError::input("door-generation", error.to_string())),
            }
        }
        Ok(Self {
            home,
            driver_dir,
            letter,
            document,
        })
    }

    /// Select the one observing vendor socket for a named first run.
    ///
    /// # Errors
    ///
    /// Refuses a plan without its loop, run, vendor mount, image, or runtime vector.
    pub fn observe_vendor(&mut self) -> Result<(), LaneError> {
        self.document["loop"]
            .as_str()
            .ok_or_else(|| LaneError::operation("plan-json", "loop is absent"))?;
        let run = self.document["run"]
            .as_str()
            .ok_or_else(|| LaneError::operation("plan-json", "run is absent"))?;
        let name = format!("observe-{run}.sock");
        let address_length = crate::socket_address_length(&name);
        if address_length > 107 {
            return Err(LaneError::input(
                "socket-path",
                format!("observer socket address length {address_length} exceeds 107"),
            ));
        }
        let mounts = self.document["mounts"]
            .as_array()
            .ok_or_else(|| LaneError::operation("plan-json", "mounts are absent"))?;
        if !mounts
            .iter()
            .any(|mount| mount["target"] == "/home/worker/.local/vendor")
        {
            return Err(LaneError::operation("plan-json", "vendor mount is absent"));
        }
        self.document["vendor_mode"] = json!("observing; host and port only; not enforcing");
        self.document["vendor_socket"] = json!(name);
        self.document["vendor_socket_address_length"] = json!(address_length);
        let image_digest = self.document["image_digest"].clone();
        let argv = self.document["runtime_argv"]
            .as_array_mut()
            .ok_or_else(|| LaneError::operation("plan-json", "runtime argv is absent"))?;
        let image = argv
            .iter()
            .position(|arg| arg == &image_digest)
            .ok_or_else(|| LaneError::operation("plan-json", "image argument is absent"))?;
        argv.splice(
            image..image,
            [
                json!("-e"),
                json!(format!(
                    "SUPERLOOP_VENDOR_SOCKET=/home/worker/.local/vendor/{name}"
                )),
            ],
        );
        self.document["box_gate"] = box_gate(&self.document)?;
        Ok(())
    }

    /// Fix the Codex selection in the reviewed runtime vector and box gate.
    ///
    /// # Errors
    ///
    /// Refuses a runtime vector without its Codex exec boundary.
    pub fn select_launch_model(&mut self, selection: &Value) -> Result<(), LaneError> {
        let model = selection["model"]
            .as_str()
            .ok_or_else(|| LaneError::input("plan-json", "model is absent"))?;
        let effort = selection["effort"]
            .as_str()
            .ok_or_else(|| LaneError::input("plan-json", "effort is absent"))?;
        let argv = self.document["runtime_argv"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("plan-json", "runtime argv is absent"))?;
        let exec = argv
            .iter()
            .position(|word| word == "exec")
            .ok_or_else(|| LaneError::input("plan-json", "Codex exec is absent"))?;
        argv.splice(
            (exec + 1)..=exec,
            [
                json!("-m"),
                json!(model),
                json!("-c"),
                json!(format!("model_reasoning_effort={effort}")),
            ],
        );
        self.document["model_selection"] = selection.clone();
        self.document["box_gate"] = box_gate(&self.document)?;
        Ok(())
    }

    /// Serialize the key-sorted document.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the document cannot be encoded.
    pub fn json(&self) -> Result<String, LaneError> {
        serde_json::to_string(&self.document)
            .map_err(|error| LaneError::operation("plan-json", error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::ffi::OsStringExt as _;
    use std::path::{Path, PathBuf};

    use serde_json::{Value, json};

    use super::Plan;

    /// ´test:unit:registry-capture-names-reader-failure´
    #[test]
    fn registry_capture_names_reader_failure() {
        struct BrokenReader;
        impl io::Read for BrokenReader {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture reader failed"))
            }
        }
        struct PanickedReader;
        impl io::Read for PanickedReader {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                panic!("fixture reader panic")
            }
        }
        let error = super::finish_capture(
            super::capture(BrokenReader),
            super::Stream::Stdout,
            Path::new("entry-fixture"),
        )
        .expect_err("reader failure");
        assert_eq!(error.kind, "registry-command");
        assert!(
            error
                .detail
                .contains("stdout read failed: fixture reader failed")
        );
        let error = super::finish_capture(
            super::capture(PanickedReader),
            super::Stream::Stderr,
            Path::new("entry-fixture"),
        )
        .expect_err("reader panic");
        assert_eq!(error.kind, "registry-command");
        assert!(error.detail.contains("stderr reader panicked"));
    }

    /// ´test:unit:plan-loop-identity-refuses-conflicting-driver-owner´
    #[test]
    fn plan_loop_identity_refuses_conflicting_driver_owner() {
        let mut document = json!({"home":"~/home-R","driver_dir":"~/runs/R","worker_uid":3000,"paths":[{"path":"~/home-R","uid":41001,"gid":41001},{"path":"~/runs/R","kind":"directory","uid":41001,"gid":41001}]});
        assert_eq!(super::loop_uid(&document).expect("shared owner"), 41001);
        document["paths"][1]["uid"] = json!(3001);
        let error = super::loop_uid(&document).expect_err("conflicting driver owner");
        assert_eq!(error.kind, "loop-identity");
        assert!(error.detail.contains("driver owner row"));
    }

    /// ´test:unit:runtime-vector-refuses-a-lossy-container-program´
    #[test]
    fn runtime_vector_refuses_a_lossy_container_program() {
        let mut plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"runtime_argv":["/usr/bin/podman"]}),
        };
        let path =
            PathBuf::from("/usr/bin").join(std::ffi::OsString::from_vec(b"podman-\xff".to_vec()));
        let error = plan
            .select_container_program(&path)
            .expect_err("invalid byte cannot name the helper's program");
        assert_eq!(error.kind, "owner-program");
        assert_eq!(plan.document["runtime_argv"][0], "/usr/bin/podman");
    }

    /// ´claim:superlooplane:mail-mount-is-one-worker-bound-read-write-folder´
    /// ´test:unit:mail-mount-is-one-worker-bound-read-write-folder´
    #[test]
    fn mail_mount_is_one_worker_bound_read_write_folder() {
        let document: Value =
            serde_json::from_str(include_str!("../tests/fixtures/plan.json")).expect("plan");
        let mut plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document,
        };
        let uid =
            u32::try_from(plan.document["worker_uid"].as_u64().expect("uid")).expect("mapped uid");
        let identity =
            loop_home::mail::birth::Identity::for_reservation(uid, "fixture:first".into());
        let source = PathBuf::from("/owner/.var/loops/alpha/workers")
            .join(&identity.name)
            .join("mail");
        plan.select_mail_group(43001).expect("mail group");
        plan.select_mailbox(&source, &identity, 42001)
            .expect("confined mail");
        super::verify_box_attestation(&plan.document).expect("complete vector");
        assert_eq!(plan.document["environment"]["SUPERLOOP_MAIL"], "/mail");
        assert_eq!(
            plan.document["mounts"]
                .as_array()
                .expect("mounts")
                .iter()
                .filter(|mount| mount["target"] == "/mail")
                .count(),
            1
        );
        let before = plan.document.clone();
        plan.select_mailbox(&source, &identity, 42001)
            .expect("same worker resume");
        assert_eq!(before, plan.document);
        let other =
            loop_home::mail::birth::Identity::for_reservation(uid, "fixture:replacement".into());
        assert!(plan.select_mailbox(&source, &other, 42001).is_err());
        for access in ["ro", "rshared"] {
            let mut changed = before.clone();
            changed["mounts"]
                .as_array_mut()
                .expect("mounts")
                .iter_mut()
                .find(|mount| mount["target"] == "/mail")
                .expect("mail")["access"] = json!(access);
            assert!(super::box_gate(&changed).is_err());
        }
        let mut peer = before.clone();
        peer["mail"]["identity"]["uid"] = json!(uid + 1);
        assert!(super::box_gate(&peer).is_err());
        let mut extra = before;
        extra["mounts"].as_array_mut().expect("mounts").push(
            json!({"source":"/owner/.var/loops","target":"/peer","access":"ro","kind":"bind"}),
        );
        assert!(super::box_gate(&extra).is_err());
    }

    /// ´test:unit:explicit-door-bind-keeps-version-one-for-repair-and-mounts´
    #[test]
    fn explicit_door_bind_keeps_version_one_for_repair_and_mounts() {
        let mut document: Value = serde_json::from_str(include_str!("../tests/fixtures/plan.json"))
            .expect("fixture plan");
        let source = "~/sockets/door";
        let target = "/home/worker/.local/door";
        let mounts = document["mounts"].as_array_mut().expect("mounts");
        let position = mounts
            .iter()
            .position(|mount| mount["target"] == "/etc/passwd")
            .expect("identity mount");
        mounts.insert(
            position,
            json!({"target":target,"source":source,"access":"ro","kind":"bind"}),
        );
        document["mount_sources"]
            .as_array_mut()
            .expect("source rows")
            .push(json!({"path":source,"uid":41001}));
        let worker = document["worker_uid"].clone();
        let run = document["run"].as_str().expect("run");
        document["door"] = json!({"schema":1,"socket":"/home/worker/.local/door/capability.sock",
            "stub":"/home/worker/.local/libexec/superloop/ssh",
            "stub_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "registered":["ssh"],"peer_uid":worker,"mirror_ref":format!("refs/heads/lane/{run}")});
        document["environment"]["GIT_SSH_COMMAND"] =
            json!("/home/worker/.local/libexec/superloop/ssh");
        let argv = document["runtime_argv"]
            .as_array_mut()
            .expect("runtime vector");
        let position = argv
            .iter()
            .position(|word| {
                word.as_str()
                    .is_some_and(|word| word.contains("dst=/etc/passwd"))
            })
            .expect("identity mount binding")
            - 1;
        argv.splice(
            position..position,
            [
                json!("--mount"),
                json!(format!("type=bind,src={source},dst={target},ro")),
            ],
        );
        document["mount_inventory"] = super::mount_inventory(
            document["mounts"].as_array().expect("mounts"),
            document["paths"].as_array().expect("paths"),
            document["mount_sources"].as_array().expect("source rows"),
        )
        .expect("door inventory");
        assert_eq!(document["mount_inventory"]["version"], 1);
        document["box_gate"] = super::box_gate(&document).expect("attested box");
        let boundary = crate::repair::boundary_from_plan(&document).expect("repair reader");
        assert_eq!(boundary["mount_inventory"]["version"], 1);
        let rows = document["mount_inventory"]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| {
                let fstype = match entry["kind"].as_str().expect("kind") {
                    "proc" => "proc",
                    "sys" => "sysfs",
                    "cgroup" => "cgroup2",
                    "devpts" => "devpts",
                    "mqueue" => "mqueue",
                    _ => "tmpfs",
                };
                json!({"target":entry["target"],"access":entry["access"],
                    "owner":entry["owner"],"mode":entry["mode"],"fstype":fstype})
            })
            .collect::<Vec<_>>();
        let differences = crate::launch::exercise::mounts::compare_inventory(
            &document["mount_inventory"],
            &json!({"mounts":rows}),
        )
        .expect("mounts reader");
        assert!(differences.is_empty(), "{differences:?}");
    }
}
