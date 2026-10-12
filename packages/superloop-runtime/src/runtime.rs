use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{self, IsTerminal as _};
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use nix::unistd::{Gid, Uid, User};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CONTAINER: &str = "superloop-runtime";
const WATCHDOG: &str = include_str!("watchdog.sh");
const PREPARE: &str = include_str!("prepare.sh");
const LABEL: &str = "superloop.runtime.identity";
const READY: &str = "/var/lib/superloop-runtime/ready";
type Result<T> = std::result::Result<T, String>;

fn required(name: &str) -> Result<OsString> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("required setting is absent: {name}"))
}

fn home() -> Result<PathBuf> {
    let path = PathBuf::from(required("HOME")?);
    if !path.is_absolute() {
        return Err("HOME must be an absolute path".into());
    }
    Ok(path)
}

fn agent() -> Result<OsString> {
    match env::var_os("CODEX_REAL_BIN") {
        Some(value) if value.is_empty() => Err("CODEX_REAL_BIN is empty".into()),
        Some(value) => Ok(value),
        None => Ok(home()?
            .join(".codex/packages/standalone/current/bin/codex")
            .into()),
    }
}

fn portal() -> OsString {
    env::var_os("SUPERLOOP_RUNTIME_PORTAL").unwrap_or_else(|| "flatpak-spawn".into())
}

fn in_container() -> bool {
    PathBuf::from(
        env::var_os("SUPERLOOP_RUNTIME_CONTAINER_MARKER")
            .unwrap_or_else(|| "/run/.containerenv".into()),
    )
    .exists()
}

fn engine() -> Result<Command> {
    if let Some(value) = env::var_os("SUPERLOOP_RUNTIME_ENGINE_ARGV") {
        let words: Vec<String> = serde_json::from_str(
            value
                .to_str()
                .ok_or("SUPERLOOP_RUNTIME_ENGINE_ARGV must be UTF-8 JSON")?,
        )
        .map_err(|error| format!("SUPERLOOP_RUNTIME_ENGINE_ARGV: {error}"))?;
        let (program, args) = words
            .split_first()
            .filter(|(program, _)| !program.is_empty())
            .ok_or("SUPERLOOP_RUNTIME_ENGINE_ARGV must name an executable")?;
        let mut command = Command::new(program);
        command.args(args);
        return Ok(command);
    }
    if in_container() {
        let mut command = Command::new(portal());
        command.args(["--host", "--watch-bus", "podman"]);
        Ok(command)
    } else {
        Ok(Command::new("podman"))
    }
}

fn captured(mut command: Command) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("runtime command: {error}"))
}

fn checked(command: Command) -> Result<Vec<u8>> {
    let output = captured(command)?;
    if !output.status.success() {
        return Err(format!(
            "runtime command exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn engine_args(args: &[&str]) -> Result<Command> {
    let mut command = engine()?;
    command.args(args);
    Ok(command)
}

fn ensure_started() -> Result<()> {
    let refused = |error| {
        format!(
            "runtime-start-refused: container {CONTAINER} is unavailable or could not be started; repair the container engine or run superloop-runtime create: {error}"
        )
    };
    let output = checked(engine_args(&[
        "inspect",
        "--format",
        "{{.State.Running}}",
        CONTAINER,
    ])?)
    .map_err(refused)?;
    if output != b"true\n" && output != b"true" {
        checked(engine_args(&["start", CONTAINER])?).map_err(refused)?;
    }
    Ok(())
}

fn replace(mut command: Command) -> Result<()> {
    Err(format!("runtime exec: {}", command.exec()))
}

pub fn execute(args: &[OsString]) -> Result<()> {
    let real = agent()?;
    let home = home()?;
    let cwd = env::current_dir().map_err(|error| format!("current directory: {error}"))?;
    ensure_started()?;
    let mut command = engine_args(&["exec", "-i"])?;
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        command.arg("-t");
    }
    command
        .args([
            "-u",
            &format!("{}:{}", Uid::current(), Gid::current()),
            "-w",
        ])
        .arg(cwd)
        .arg("-e")
        .arg(env_pair("HOME", home.as_os_str()))
        .args(["-e", &format!("CALLER_PID={}", std::process::id())]);
    for name in ["CODEX_HOME", "TMPDIR", "TERM", "COLUMNS", "LINES"] {
        if let Some(value) = env::var_os(name).filter(|value| !value.is_empty()) {
            command.arg("-e").arg(env_pair(name, &value));
        }
    }
    command
        .args([CONTAINER, "/bin/bash", "-c", WATCHDOG, "--"])
        .arg(real)
        .args(args);
    replace(command)
}

fn env_pair(name: &str, value: &OsStr) -> OsString {
    let mut pair = OsString::from(format!("{name}="));
    pair.push(value);
    pair
}

pub fn run_host(args: &[OsString]) -> Result<()> {
    let real = agent()?;
    if in_container() {
        let probe = Command::new(portal())
            .args(["--host", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if probe.is_ok_and(|status| status.success()) {
            let mut command = Command::new(portal());
            command.args(["--host", "--watch-bus"]);
            let mut directory = OsString::from("--directory=");
            directory.push(env::current_dir().map_err(|error| error.to_string())?);
            command.arg(directory);
            for name in ["CODEX_HOME", "HOME", "TMPDIR", "TERM", "COLUMNS", "LINES"] {
                if let Some(value) = env::var_os(name).filter(|value| !value.is_empty()) {
                    let mut pair = OsString::from("--env=");
                    pair.push(env_pair(name, &value));
                    command.arg(pair);
                }
            }
            command.arg(real).args(args);
            return replace(command);
        }
    }
    let mut command = Command::new(real);
    command.args(args);
    replace(command)
}

pub fn run_toolbox(args: &[OsString]) -> Result<()> {
    let toolbox = required("CLAUDE_TOOLBOX")?;
    let config = required("CLAUDE_CONFIG_DIR")?;
    let temporary = match env::var_os("TMPDIR").filter(|value| !value.is_empty()) {
        Some(path) => path,
        None => home()?.join(".cache/tmp").into(),
    };
    let mut command = Command::new(portal());
    command
        .args(["--host", "toolbox", "run", "-c"])
        .arg(toolbox)
        .arg("env")
        .arg(env_pair("CLAUDE_CONFIG_DIR", &config))
        .arg(env_pair("TMPDIR", &temporary))
        .arg("claude")
        .args(args);
    replace(command)
}

pub fn create() -> Result<()> {
    let started = std::time::Instant::now();
    let home = home()?;
    let image = env::var("SUPERLOOP_RUNTIME_IMAGE")
        .unwrap_or_else(|_| "registry.fedoraproject.org/fedora-toolbox:44".into());
    if image.is_empty() {
        return Err("SUPERLOOP_RUNTIME_IMAGE is empty".into());
    }
    let uid = Uid::current().as_raw().to_string();
    let gid = Gid::current().as_raw().to_string();
    let account = User::from_uid(Uid::current())
        .map_err(|error| error.to_string())?
        .ok_or("calling uid has no account entry")?
        .name;
    let mut identity = String::new();
    for byte in Sha256::digest(
        json!({"schema":1,"image":image,"uid":uid,"gid":gid,"home":home,"prepare":PREPARE})
            .to_string()
            .as_bytes(),
    ) {
        write!(&mut identity, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    let exists = captured(engine_args(&["container", "exists", CONTAINER])?)?;
    match exists.status.code() {
        Some(0) => {
            let bytes = checked(engine_args(&[
                "inspect",
                "--format",
                "{{json .Config.Labels}}",
                CONTAINER,
            ])?)?;
            let labels: Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("container labels: {error}"))?;
            if labels[LABEL] != identity {
                return Err(
                    "existing runtime container differs from the requested configuration".into(),
                );
            }
        }
        Some(1) => {
            create_container(&home, &image, &uid, &identity)?;
        }
        _ => {
            return Err(format!(
                "container existence query exited {}",
                exists.status
            ));
        }
    }
    ensure_started()?;
    let ready = captured(engine_args(&[
        "exec", "-u", "root", CONTAINER, "cat", READY,
    ])?)?;
    if ready.status.success() && ready.stdout == format!("{identity}\n").as_bytes() {
        report_ready(started, &identity, "existing-ready-record")?;
        return Ok(());
    }
    if !ready.status.success() && ready.status.code() != Some(1) {
        return Err(format!("runtime readiness query exited {}", ready.status));
    }
    let mut prepare = engine_args(&[
        "exec", "-u", "root", CONTAINER, "/bin/sh", "-c", PREPARE, "--", &uid, &account,
    ])?;
    prepare.arg(home).arg(&identity);
    checked(prepare)?;
    let evidence = checked(engine_args(&[
        "exec", "-u", "root", CONTAINER, "cat", READY,
    ])?)?;
    if evidence != format!("{identity}\n").as_bytes() {
        return Err("runtime readiness record differs after preparation".into());
    }
    report_ready(started, &identity, "prepared-ready-record")?;
    Ok(())
}

fn create_container(home: &std::path::Path, image: &str, uid: &str, identity: &str) -> Result<()> {
    let mut command = engine_args(&[
        "create",
        "--name",
        CONTAINER,
        "--hostname",
        CONTAINER,
        "--userns=keep-id",
        "--privileged",
        "--security-opt",
        "label=disable",
        "--security-opt",
        "unmask=all",
        "--network",
        "host",
        "--pid",
        "host",
        "--ipc",
        "host",
        "--no-hosts=false",
        "--label",
    ])?;
    command.arg(format!("{LABEL}={identity}"));
    let mut mount = home.as_os_str().to_owned();
    mount.push(":");
    mount.push(home);
    command
        .arg("-v")
        .arg(mount)
        .arg("-v")
        .arg(format!("/run/user/{uid}:/run/user/{uid}"))
        .args(["--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777,size=16g", "-e"])
        .arg(env_pair("HOME", home.as_os_str()))
        .arg("-e")
        .arg(env_pair("TMPDIR", home.join(".cache/tmp").as_os_str()))
        .args([
            "-e",
            &format!("XDG_RUNTIME_DIR=/run/user/{uid}"),
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            "exec sleep infinity",
        ]);
    checked(command)?;
    Ok(())
}

fn report_ready(started: std::time::Instant, identity: &str, evidence: &str) -> Result<()> {
    use std::io::Write as _;
    writeln!(io::stdout().lock(), "RUNTIME-READY container={CONTAINER} wall={:.3}s readiness={READY} identity={identity} evidence={evidence}", started.elapsed().as_secs_f64())
        .map_err(|error| format!("runtime readiness publication: {error}"))
}
