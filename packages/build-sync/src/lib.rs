#![doc = include_str!("../README.md")]

pub mod census;
mod census_calls;
mod census_data;
mod census_install;
mod census_meson;
mod census_payloads;
mod census_programs;
mod census_sources;
mod census_test_tools;
pub mod identity;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, Permissions};
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Explicit inputs to one package-scoped release build.
pub struct SyncArgs<'a> {
    pub identity: &'a identity::IdentityArgs<'a>,
    pub cargo: &'a Path,
    pub manifest: &'a Path,
    pub package: &'a str,
    pub bin: &'a str,
    pub output: &'a Path,
    pub domain: &'a str,
}

/// Inputs for recording an output produced by another program.
pub struct RecordArgs<'a> {
    pub identity: &'a identity::IdentityArgs<'a>,
    pub output: &'a Path,
    pub producer: &'a Path,
    pub domain: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Copy,
    RepairMode,
    Keep,
}

#[derive(Serialize)]
struct BuildRecord<'a> {
    bin: &'a str,
    build_wall_ms: u64,
    cargo_version: &'a str,
    domain: &'a str,
    #[serde(flatten)]
    identity: &'a identity::Identity,
    package: &'a str,
    profile: &'static str,
    rustc_version: &'a str,
    sha256: &'a str,
    written: &'a str,
}

/// Build one binary and publish changed bytes plus its build record.
///
/// # Errors
///
/// Returns the named cause of a failed Cargo invocation, missing artifact, version query, or filesystem operation.
pub fn sync(args: &SyncArgs<'_>) -> Result<(), String> {
    let identity = identity::resolve(args.identity, args.output, Some(args.package))?;
    let (artifact, build_wall_ms) = run_cargo(args)?;
    publish(args, &artifact, Some(build_wall_ms), &identity)
}

/// Publish an already built release artifact without invoking Cargo's build command.
///
/// # Errors
///
/// Returns the named cause of a missing artifact, version query, or filesystem operation.
pub fn stage(args: &SyncArgs<'_>, artifact: &Path) -> Result<(), String> {
    let identity = identity::resolve(args.identity, args.output, Some(args.package))?;
    publish(args, artifact, None, &identity)
}

fn publish(
    args: &SyncArgs<'_>,
    artifact: &Path,
    compile_wall_ms: Option<u64>,
    identity: &identity::Identity,
) -> Result<(), String> {
    let started = Instant::now();
    let built = fs::read(artifact).map_err(|error| format!("read built executable: {error}"))?;
    let existing = read_existing(args.output)?;
    let change = decide(
        existing
            .as_ref()
            .map(|(bytes, mode)| (bytes.as_slice(), *mode)),
        &built,
    );
    let record_path = record_path(args.output);
    let record_missing = match fs::symlink_metadata(&record_path) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(format!("inspect build record: {error}")),
    };

    let identity_changed = !record_identity_matches(&record_path, identity)?;
    if should_rewrite_record(change, record_missing) || identity_changed {
        // Query both versions before publishing either file, so a failed query leaves both alone.
        let cargo_version = version(
            args.cargo,
            &["--version"],
            "cargo",
            Some(args.identity.root),
        )?;
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
        let rustc_version = version(
            Path::new(&rustc),
            &["--version"],
            "rustc",
            Some(args.identity.root),
        )?;
        let written = utc_timestamp(SystemTime::now())?;

        match change {
            Change::Copy => copy_executable(args.output, &built)?,
            Change::RepairMode => repair_mode(args.output)?,
            Change::Keep => {}
        }

        let output_bytes =
            fs::read(args.output).map_err(|error| format!("read output: {error}"))?;
        let sha256 = digest(&output_bytes);
        let record = BuildRecord {
            bin: args.bin,
            build_wall_ms: compile_wall_ms.unwrap_or_else(|| {
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
            cargo_version: &cargo_version,
            domain: args.domain,
            identity,
            package: args.package,
            profile: "release",
            rustc_version: &rustc_version,
            sha256: &sha256,
            written: &written,
        };
        write_record(&record_path, &record)?;
    } else if change == Change::RepairMode {
        repair_mode(args.output)?;
    }
    Ok(())
}

/// Write a build record beside an existing generated regular file.
///
/// # Errors
///
/// Returns the named cause of an invalid output, failed version query, or filesystem operation.
pub fn record(args: &RecordArgs<'_>) -> Result<(), String> {
    let identity = identity::resolve(args.identity, args.output, None)?;
    let started = Instant::now();
    let metadata = fs::symlink_metadata(args.output)
        .map_err(|error| format!("inspect generated output: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("generated output is not a regular file".to_owned());
    }
    let bytes = fs::read(args.output).map_err(|error| format!("read generated output: {error}"))?;
    let bin = args
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("generated output has no UTF-8 file name")?;
    let producer_version = version(args.producer, &["--version"], "producer", None)?;
    let sha256 = digest(&bytes);
    let written = utc_timestamp(SystemTime::now())?;
    let build_wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let build_record = BuildRecord {
        bin,
        build_wall_ms,
        cargo_version: &producer_version,
        domain: args.domain,
        identity: &identity,
        package: &identity.package,
        profile: "generated",
        rustc_version: &producer_version,
        sha256: &sha256,
        written: &written,
    };
    let path = record_path(args.output);
    if !record_matches(&path, &build_record)? {
        write_record(&path, &build_record)?;
    }
    Ok(())
}

fn record_matches(path: &Path, expected: &BuildRecord<'_>) -> Result<bool, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("read build record: {error}")),
    };
    let Ok(mut actual) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(false);
    };
    let Some(actual) = actual.as_object_mut() else {
        return Ok(false);
    };
    if actual.len() != 14
        || !actual
            .get("build_wall_ms")
            .is_some_and(serde_json::Value::is_u64)
        || !actual
            .get("written")
            .is_some_and(serde_json::Value::is_string)
    {
        return Ok(false);
    }
    actual.remove("build_wall_ms");
    actual.remove("written");
    let mut expected = serde_json::to_value(expected)
        .map_err(|error| format!("serialize build record: {error}"))?;
    let expected = expected
        .as_object_mut()
        .ok_or("build record is not an object")?;
    expected.remove("build_wall_ms");
    expected.remove("written");
    Ok(actual == expected)
}

fn record_identity_matches(path: &Path, identity: &identity::Identity) -> Result<bool, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("read record identity: {error}")),
    };
    let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(false);
    };
    let expected = serde_json::to_value(identity).map_err(|error| error.to_string())?;
    Ok(expected
        .as_object()
        .ok_or("build identity is not an object")?
        .iter()
        .all(|(key, value)| record.get(key) == Some(value)))
}

fn run_cargo(args: &SyncArgs<'_>) -> Result<(PathBuf, u64), String> {
    let started = Instant::now();
    let mut child = Command::new(args.cargo)
        .current_dir(args.identity.root)
        .arg("build")
        .args(["--release", "--locked", "--manifest-path"])
        .arg(args.manifest)
        .args([
            "-p",
            args.package,
            "--bin",
            args.bin,
            "--message-format=json-render-diagnostics",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("start cargo build: {error}"))?;
    let stdout = child.stdout.take().ok_or("capture cargo stdout")?;
    let mut executable = None;
    let mut read_error = None;
    for line in BufReader::new(stdout).lines() {
        match line {
            Ok(line) => match select_executable(&line, args.bin) {
                Ok(Some(path)) => executable = Some(path),
                Err(error) if read_error.is_none() => read_error = Some(error.to_string()),
                Ok(None) | Err(_) => {}
            },
            Err(error) if read_error.is_none() => read_error = Some(error.to_string()),
            Err(_) => {}
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("wait for cargo build: {error}"))?;
    let build_wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if !status.success() {
        return Err(format!("cargo build exited with {status}"));
    }
    if let Some(error) = read_error {
        return Err(format!("read cargo JSON messages: {error}"));
    }
    let executable = executable
        .ok_or_else(|| format!("cargo emitted no executable artifact for {}", args.bin))?;
    Ok((executable, build_wall_ms))
}

fn select_executable(line: &str, bin: &str) -> serde_json::Result<Option<PathBuf>> {
    let message: serde_json::Value = serde_json::from_str(line)?;
    if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
        || message
            .pointer("/target/name")
            .and_then(serde_json::Value::as_str)
            != Some(bin)
    {
        return Ok(None);
    }
    Ok(message
        .get("executable")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from))
}

fn read_existing(path: &Path) -> Result<Option<(Vec<u8>, u32)>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect output: {error}")),
    };
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| format!("read output: {error}"))?;
    Ok(Some((bytes, metadata.permissions().mode() & 0o7777)))
}

fn decide(existing: Option<(&[u8], u32)>, built: &[u8]) -> Change {
    match existing {
        Some((bytes, 0o755)) if bytes == built => Change::Keep,
        Some((bytes, _)) if bytes == built => Change::RepairMode,
        _ => Change::Copy,
    }
}

fn should_rewrite_record(change: Change, record_missing: bool) -> bool {
    change == Change::Copy || record_missing
}

fn copy_executable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory).map_err(|error| format!("create output directory: {error}"))?;
    let mut staged = tempfile::Builder::new()
        .prefix(".build-sync-output-")
        .tempfile_in(directory)
        .map_err(|error| format!("stage output: {error}"))?;
    staged
        .write_all(bytes)
        .map_err(|error| format!("write output: {error}"))?;
    staged
        .as_file()
        .sync_all()
        .map_err(|error| format!("flush output: {error}"))?;
    staged
        .as_file()
        .set_permissions(Permissions::from_mode(0o755))
        .map_err(|error| format!("set output mode: {error}"))?;
    staged
        .persist(path)
        .map_err(|error| format!("publish output: {}", error.error))?;
    Ok(())
}

fn repair_mode(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, Permissions::from_mode(0o755))
        .map_err(|error| format!("repair output mode: {error}"))
}

fn record_path(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_os_string();
    name.push(".build.json");
    PathBuf::from(name)
}

fn write_record(path: &Path, record: &BuildRecord<'_>) -> Result<(), String> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let value =
        serde_json::to_value(record).map_err(|error| format!("serialize build record: {error}"))?;
    let bytes =
        serde_json::to_vec(&value).map_err(|error| format!("serialize build record: {error}"))?;
    let mut staged = tempfile::Builder::new()
        .prefix(".build-sync-record-")
        .tempfile_in(directory)
        .map_err(|error| format!("stage build record: {error}"))?;
    staged
        .write_all(&bytes)
        .map_err(|error| format!("write build record: {error}"))?;
    staged
        .as_file()
        .sync_all()
        .map_err(|error| format!("flush build record: {error}"))?;
    staged
        .as_file()
        .set_permissions(Permissions::from_mode(0o644))
        .map_err(|error| format!("set build record mode: {error}"))?;
    staged
        .persist(path)
        .map_err(|error| format!("publish build record: {}", error.error))?;
    Ok(())
}

fn version(
    program: &Path,
    args: &[&str],
    name: &str,
    directory: Option<&Path>,
) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let output = command
        .output()
        .map_err(|error| format!("query {name} version: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{name} version query exited with {}",
            output.status
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("decode {name} version: {error}"))?;
    let line = text.lines().next().unwrap_or_default().trim();
    if !line.is_empty() {
        return Ok(line.to_owned());
    }
    let first_stderr_line = output
        .stderr
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if let Ok(record) = serde_json::from_slice::<serde_json::Value>(first_stderr_line)
        && record.get("kind").and_then(serde_json::Value::as_str) == Some("version")
        && let Some(version) = record
            .pointer("/fields/version")
            .and_then(serde_json::Value::as_str)
        && !version.trim().is_empty()
    {
        return Ok(version.trim().to_owned());
    }
    Err(format!("{name} version query returned no version"))
}

fn digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut result, "{byte:02x}").expect("write to string");
    }
    result
}

fn utc_timestamp(time: SystemTime) -> Result<String, String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("read UTC time: {error}"))?
        .as_secs();
    let days =
        i64::try_from(seconds / 86_400).map_err(|error| format!("convert UTC time: {error}"))?;
    let (year, month, day) = civil_date(days);
    let second_of_day = seconds % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

// Gregorian civil date from days since the Unix epoch.
const fn civil_date(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_piece = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_piece + 2) / 5 + 1;
    let month = month_piece + if month_piece < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

/// Return whether a stamp is an empty regular file, without following symlinks.
#[must_use]
pub fn probe(stamp: &Path) -> bool {
    fs::symlink_metadata(stamp)
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.len() == 0)
}

#[cfg(test)]
mod tests;
