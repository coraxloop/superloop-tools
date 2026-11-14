//! Fixture-only patterns, injected failures and start barrier; no supervisor.
use crate::{
    Envelope, process, receipt,
    record::{self, Result},
};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::signal::{Signal, raise};
use nix::sys::stat::{SFlag, fstat};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRecord {
    schema: u32,
    command: String,
    case: String,
    streams: [Stream; 2],
    behavior: Behavior,
    timeout_ms: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stream {
    name: String,
    length: u64,
    pattern: Pattern,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Pattern {
    Ascending,
    Descending,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Behavior {
    Normal,
    Short,
    Excess,
    Partial,
    FailAfterOutput,
    ReexecExtra,
}

fn parse(bytes: &[u8]) -> Result<FixtureRecord> {
    let case: FixtureRecord = serde_json::from_slice(bytes).map_err(|_| "fixture-record-shape")?;
    if case.schema != 1 || case.command != "fixture-emit" {
        return Err("fixture-record-schema");
    }
    if !record::name(&case.case) {
        return Err("fixture-record-case");
    }
    if case
        .streams
        .iter()
        .any(|s| !record::name(&s.name) || !(1..=1_048_576).contains(&s.length))
        || case.streams[0].name == case.streams[1].name
        || case.streams[0].pattern == case.streams[1].pattern
    {
        return Err("fixture-record-streams");
    }
    if !(1..=60_000).contains(&case.timeout_ms) {
        return Err("fixture-record-timeout");
    }
    Ok(case)
}

// Only convention slots 3 and 4 are inspected. No descriptor-table enumeration.
#[allow(unsafe_code)]
fn descriptors(case: &FixtureRecord) -> Result<[OwnedFd; 2]> {
    if std::env::var("LISTEN_PID").ok().as_deref() != Some(&std::process::id().to_string()) {
        return Err("fixture-convention-pid");
    }
    if std::env::var("LISTEN_FDS").ok().as_deref() != Some("2") {
        return Err("fixture-convention-count");
    }
    let names = std::env::var("LISTEN_FDNAMES").map_err(|_| "fixture-convention-names")?;
    if names.len() > 193 {
        return Err("fixture-convention-names");
    }
    let names: Vec<_> = names.split(':').collect();
    if names.len() != 2
        || names[0] == names[1]
        || case
            .streams
            .iter()
            .any(|s| !names.contains(&s.name.as_str()))
    {
        return Err("fixture-convention-names");
    }
    // SAFETY: both inherited slots are valid before ownership is acquired.
    // This single-threaded entry has no other owner of these convention slots;
    // fstat/fcntl validate their contracts before any generation.
    let fds = unsafe {
        if nix::libc::fcntl(3, nix::libc::F_GETFD) < 0
            || nix::libc::fcntl(4, nix::libc::F_GETFD) < 0
        {
            return Err("fixture-convention-descriptor");
        }
        [OwnedFd::from_raw_fd(3), OwnedFd::from_raw_fd(4)]
    };
    let mut identities = Vec::new();
    for fd in &fds {
        let stat = fstat(fd).map_err(|_| "fixture-convention-descriptor")?;
        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|_| "fixture-convention-descriptor")?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFIFO
            || flags & OFlag::O_ACCMODE.bits() != OFlag::O_WRONLY.bits()
            || identities.contains(&(stat.st_dev, stat.st_ino))
        {
            return Err("fixture-convention-descriptor");
        }
        identities.push((stat.st_dev, stat.st_ino));
    }
    let [a, b] = fds;
    Ok(if names[0] == case.streams[0].name {
        [a, b]
    } else {
        [b, a]
    })
}

fn reexec(case_path: &Path, fds: &[OwnedFd; 2]) -> Result<()> {
    if let Ok(marker) = std::env::var("CREDENTIAL_FIXTURE_REEXEC") {
        let (pid, raw) = marker.split_once(':').ok_or("fixture-reexec-state")?;
        if pid != std::process::id().to_string() {
            return Err("fixture-reexec-state");
        }
        let raw: i32 = raw.parse().map_err(|_| "fixture-reexec-state")?;
        if raw < 5 {
            return Err("fixture-reexec-state");
        }
        // SAFETY: only the explicitly named reexec descriptor is borrowed;
        // no ownership is acquired and failed fstat is a refusal.
        #[allow(unsafe_code)]
        let fd = unsafe {
            if nix::libc::fcntl(raw, nix::libc::F_GETFD) < 0 {
                return Err("fixture-reexec-state");
            }
            BorrowedFd::borrow_raw(raw)
        };
        let stat = fstat(fd).map_err(|_| "fixture-reexec-state")?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFCHR
            || stat.st_rdev != nix::sys::stat::makedev(1, 3)
        {
            return Err("fixture-reexec-state");
        }
        return Ok(());
    }
    let extra = std::fs::File::open("/dev/null").map_err(|_| "fixture-extra-open")?;
    fcntl(&extra, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|_| "fixture-extra-flags")?;
    for fd in fds {
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|_| "fixture-extra-flags")?;
    }
    let mut environment: Vec<(OsString, OsString)> = ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]
        .into_iter()
        .map(|name| (name.into(), std::env::var_os(name).unwrap_or_default()))
        .collect();
    environment.push((
        "CREDENTIAL_FIXTURE_REEXEC".into(),
        format!("{}:{}", std::process::id(), extra.as_raw_fd()).into(),
    ));
    let executable = std::env::current_exe().map_err(|_| "fixture-reexec-path")?;
    let mut command = std::process::Command::new(executable);
    command.arg("emit").arg("--case-record").arg(case_path);
    process::pin_program(&mut command, &environment)?;
    let _error = command.exec();
    Err("fixture-reexec")
}

pub fn emit(path: &Path) -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Err("fixture-privilege");
    }
    let start = Instant::now();
    let case = parse(&receipt::parameters(path)?)?;
    let fds = descriptors(&case)?;
    if case.behavior == Behavior::ReexecExtra {
        reexec(path, &fds)?;
    } else if std::env::var_os("CREDENTIAL_FIXTURE_REEXEC").is_some() {
        return Err("fixture-reexec-state");
    }
    // The external supervisor observes the stopped process before releasing it.
    // There is no third control pipe and the fixture does not inspect other FDs.
    raise(Signal::SIGSTOP).map_err(|_| "fixture-barrier")?;
    let deadline = Instant::now() + Duration::from_millis(case.timeout_ms);
    for (index, (stream, fd)) in case.streams.iter().zip(&fds).enumerate() {
        fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(|_| "fixture-stream-flags")?;
        let length = match (case.behavior, index) {
            (Behavior::Short, 0) => stream.length - 1,
            (Behavior::Excess, 0) => stream.length + 1,
            (Behavior::Partial, 0) => stream.length / 2,
            (Behavior::Partial, 1) => 0,
            _ => stream.length,
        };
        let mut written = 0;
        while written < length {
            if Instant::now() >= deadline {
                return Err("fixture-stream-timeout");
            }
            let mut bytes = [0; 4096];
            let count = usize::try_from((length - written).min(bytes.len() as u64))
                .map_err(|_| "fixture-length")?;
            for (offset, byte) in bytes[..count].iter_mut().enumerate() {
                let value = ((written + offset as u64) % 251) as u8;
                *byte = match stream.pattern {
                    Pattern::Ascending => value,
                    Pattern::Descending => 255 - value,
                };
            }
            match nix::unistd::write(fd, &bytes[..count]) {
                Ok(0) => return Err("fixture-stream-write"),
                Ok(n) => written += n as u64,
                Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(1)),
                Err(_) => return Err("fixture-stream-write"),
            }
        }
    }
    // Close both named streams before success or an injected failure is reported.
    drop(fds);
    if !matches!(case.behavior, Behavior::Normal | Behavior::ReexecExtra) {
        return Err("fixture-injected-failure");
    }
    superloop_cli_common::emit(&Envelope {
        schema: 1,
        command: "fixture-emit",
        case: case.case,
        outcome: "ok",
        wall_us: start.elapsed().as_micros(),
        evidence: serde_json::json!({"streams":case.streams}),
    })
    .map_err(|_| "output-write")
}
