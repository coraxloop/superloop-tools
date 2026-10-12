use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Reply;

const VARIABLES: [&str; 10] = [
    "PERMISSION_TRIAGE_STATE_ROOT",
    "PERMISSION_TRIAGE_MODE",
    "PERMISSION_TRIAGE_ISOLATION",
    "PERMISSION_TRIAGE_OWNER_RUBRIC",
    "PERMISSION_TRIAGE_HOOK_CEILING_MS",
    "PERMISSION_TRIAGE_MODEL",
    "PERMISSION_TRIAGE_MODEL_DEADLINE_MS",
    "PERMISSION_TRIAGE_CLI",
    "PERMISSION_TRIAGE_LOOP_REGISTRY",
    "PERMISSION_TRIAGE_ESTATE_UID",
];

pub fn invoke(input: &[u8]) -> Reply {
    invoke_checked(input).unwrap_or_else(Reply::refusal)
}

fn invoke_checked(input: &[u8]) -> Result<Reply, &'static str> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or("instance file missing")?;
    let instance = option_env!("PERMISSION_TRIAGE_INSTANCE")
        .map_or_else(|| home.join(".claude/permission-triage.env"), PathBuf::from);
    let binary = option_env!("PERMISSION_TRIAGE_HOOK_BIN").map_or_else(
        || home.join(".local/libexec/superloop/hooks/permission-triage-hook"),
        PathBuf::from,
    );
    if !instance.is_absolute() || !regular(&instance) {
        return Err("instance file missing");
    }
    if !binary.is_absolute() || !regular(&binary) {
        return Err("hook binary missing");
    }
    let mut file = File::open(&binary).map_err(|_| "hook binary missing")?;
    let mut magic = [0; 4];
    if file
        .metadata()
        .map_err(|_| "hook binary missing")?
        .permissions()
        .mode()
        & 0o111
        == 0
        || file.read_exact(&mut magic).is_err()
        || magic != *b"\x7fELF"
    {
        return Err("hook binary missing");
    }
    let instance = fs::read_to_string(&instance).map_err(|_| "instance file missing")?;
    let values = parse_instance(&instance)?;
    let mut command = Command::new(binary);
    command
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in VARIABLES {
        command.env_remove(key);
    }
    command.envs(values);
    let mut child = command.spawn().map_err(|_| "wrapper internal error")?;
    let mut stdin = child.stdin.take().ok_or("wrapper internal error")?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child
        .wait_with_output()
        .map_err(|_| "wrapper internal error")?;
    let written = writer.join().map_err(|_| "wrapper internal error")?;
    if written.is_err() {
        return Err("wrapper internal error");
    }
    let status = output
        .status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .ok_or("wrapper internal error")?;
    if status != 0 && status != 2 {
        return Err("wrapper internal error");
    }
    if !output.stdout.is_empty() || status != 0 {
        let valid =
            serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok_and(|value| {
                let response = &value["hookSpecificOutput"];
                response["hookEventName"] == "PreToolUse"
                    && (response["permissionDecision"] == "deny"
                        || (status == 0 && response["permissionDecision"] == "allow"))
            });
        if !valid {
            return Err("wrapper internal error");
        }
    }
    Ok(Reply {
        status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn parse_instance(input: &str) -> Result<BTreeMap<&str, &str>, &'static str> {
    let mut values = BTreeMap::new();
    for line in input.split_terminator('\n') {
        let (key, value) = line.split_once('=').ok_or("instance file malformed")?;
        if !VARIABLES.contains(&key)
            || key == "PERMISSION_TRIAGE_ISOLATION"
            || value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_./,:@%+-".contains(&byte))
            || values.insert(key, value).is_some()
        {
            return Err("instance file malformed");
        }
        let valid = match key {
            "PERMISSION_TRIAGE_MODE" => matches!(value, "audit" | "enforce"),
            "PERMISSION_TRIAGE_CLI" | "PERMISSION_TRIAGE_LOOP_REGISTRY" => value.starts_with('/'),
            "PERMISSION_TRIAGE_ESTATE_UID" => value.bytes().all(|byte| byte.is_ascii_digit()),
            "PERMISSION_TRIAGE_HOOK_CEILING_MS" => milliseconds(value, 60_000),
            "PERMISSION_TRIAGE_MODEL_DEADLINE_MS" => milliseconds(value, 55_000),
            _ => true,
        };
        if !valid {
            return Err("instance file malformed");
        }
    }
    if [
        "PERMISSION_TRIAGE_MODE",
        "PERMISSION_TRIAGE_STATE_ROOT",
        "PERMISSION_TRIAGE_CLI",
    ]
    .iter()
    .any(|key| !values.contains_key(key))
    {
        return Err("instance file malformed");
    }
    Ok(values)
}

fn milliseconds(value: &str, ceiling: u32) -> bool {
    value.len() <= 5
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<u32>()
            .is_ok_and(|number| number > 0 && number <= ceiling)
}
