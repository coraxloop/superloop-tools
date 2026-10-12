#![doc = include_str!("../README.md")]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::process::Command;
use std::time::{Duration, Instant};

use superloop_execwrap::{ExecError, RoutingConfig};

const ROOTFS_TMP_ENV: &str = "RUN_REPORT_ROOTFS_TMP_MOUNT";
const WORKSPACE_ENV: &str = "RUN_REPORT_WORKSPACE_MOUNT";
const ROOTFS_TMP_DEFAULT: &str = "/tmp";
const WORKSPACE_DEFAULT: &str = "/workspace";
const EMPTY_COMMAND_EXIT: u8 = 2;
const WRAPPER_FAILURE_EXIT: u8 = 125;
const CANNOT_EXECUTE_EXIT: u8 = 126;
const COMMAND_NOT_FOUND_EXIT: u8 = 127;

/// Filesystems whose available space is included in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mounts {
    rootfs_tmp: OsString,
    workspace: OsString,
}

impl Mounts {
    /// Read mount paths from the two governed environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|name| env::var_os(name))
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<OsString>) -> Self {
        Self {
            rootfs_tmp: lookup(ROOTFS_TMP_ENV)
                .unwrap_or_else(|| OsString::from(ROOTFS_TMP_DEFAULT)),
            workspace: lookup(WORKSPACE_ENV).unwrap_or_else(|| OsString::from(WORKSPACE_DEFAULT)),
        }
    }
}

impl Default for Mounts {
    fn default() -> Self {
        Self {
            rootfs_tmp: OsString::from(ROOTFS_TMP_DEFAULT),
            workspace: OsString::from(WORKSPACE_DEFAULT),
        }
    }
}

/// Execute `command`, append its terminal report to `report`, and return the wrapper status.
///
/// Ordinary child statuses pass through unchanged. Signal deaths use `128 + signal`, missing executables use 127, other spawn failures use 126, an empty command uses 2, and an otherwise unclassifiable wrapper failure uses 125.
pub fn run_report(command: &[OsString], mounts: &Mounts, mut report: impl Write) -> u8 {
    let clock = ClockStart::now();
    let exit = match superloop_execwrap::run(command, &RoutingConfig::default(), |_| {}) {
        Ok(outcome) => normalize_exit(outcome.exit_code),
        Err(ExecError::Spawn { source }) if source.kind() == std::io::ErrorKind::NotFound => {
            COMMAND_NOT_FOUND_EXIT
        }
        Err(ExecError::Spawn { .. }) => CANNOT_EXECUTE_EXIT,
        Err(ExecError::EmptyCommand) => EMPTY_COMMAND_EXIT,
        Err(_) => WRAPPER_FAILURE_EXIT,
    };
    let wall = clock.elapsed();
    let rootfs_tmp_left = available_space(&mounts.rootfs_tmp);
    let workspace_left = available_space(&mounts.workspace);

    let _ignored = writeln!(
        report,
        "RUN-REPORT exit={exit} wall={wall}s rootfs_tmp_left={rootfs_tmp_left} workspace_left={workspace_left}"
    );
    exit
}

fn normalize_exit(exit: i32) -> u8 {
    u8::try_from(exit).unwrap_or(WRAPPER_FAILURE_EXIT)
}

struct ClockStart {
    boottime: Option<Duration>,
    monotonic: Instant,
}

impl ClockStart {
    fn now() -> Self {
        Self {
            boottime: read_boottime(),
            monotonic: Instant::now(),
        }
    }

    fn elapsed(&self) -> String {
        let elapsed = self
            .boottime
            .and_then(|start| read_boottime().and_then(|end| end.checked_sub(start)))
            .unwrap_or_else(|| self.monotonic.elapsed());
        format_wall(elapsed)
    }
}

fn read_boottime() -> Option<Duration> {
    let contents = fs::read_to_string("/proc/uptime").ok()?;
    let seconds = contents.split_ascii_whitespace().next()?.parse().ok()?;
    Duration::try_from_secs_f64(seconds).ok()
}

fn format_wall(elapsed: Duration) -> String {
    format!("{:.1}", elapsed.as_secs_f64())
}

fn available_space(path: &OsStr) -> String {
    let output = match Command::new("df")
        .args(["-h", "--output=avail", "--"])
        .arg(path)
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return String::from("n/a"),
    };

    parse_available(&output.stdout).unwrap_or_else(|| String::from("n/a"))
}

fn parse_available(stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let _header = lines.next()?;
    lines.next_back().map(String::from)
}

#[cfg(test)]
mod tests;
