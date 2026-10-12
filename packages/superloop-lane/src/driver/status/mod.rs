#![doc = include_str!("README.md")]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::monitor_lock;
#[cfg(test)]
mod tests;

/// Default freshness threshold, matching the shell reference.
pub const DEFAULT_STALL_SECONDS: u64 = 300;

const IO_SAMPLE_WINDOW: Duration = Duration::from_secs(1);
const MONITOR_FILE_PREFIX: &str = ".monitor-";
const BOOT_CLOCK_FILE: &str = "/proc/uptime";

/// Fixed usage diagnostic required by the command brief.
pub const USAGE_DIAGNOSTIC: &[u8] =
    b"superloop-lane: usage_error: invalid command-line arguments\n";

/// Fixed fallback diagnostic used when standard-output publication fails.
pub const PUBLICATION_DIAGNOSTIC: &[u8] =
    b"superloop-lane: publication_failure: agent-text publication failed\n";

/// Fixed diagnostic used after a suppressed panic.
pub const INTERNAL_DIAGNOSTIC: &[u8] =
    b"superloop-lane: internal_failure: unexpected internal failure\n";

/// Parsed watcher configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Worker-lane run directory to inspect without mutation.
    pub run_dir: PathBuf,
    /// Selected event-age threshold in seconds.
    pub stall_seconds: u64,
}

/// Semantic result of one successful watcher probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Event evidence is younger than the selected threshold.
    Running,
    /// A settled report encodes natural lane success.
    Completed,
    /// A settled report encodes lane failure or a protocol kill.
    Failed,
    /// Event evidence is absent or has reached the selected threshold.
    Stalled,
}

impl Verdict {
    /// Process status owned by this watcher verdict.
    #[must_use]
    pub const fn status(self) -> u8 {
        match self {
            Self::Running | Self::Completed | Self::Failed => 0,
            Self::Stalled => 42,
        }
    }

    const fn report_word(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Stalled => "stalled",
        }
    }
}

/// Evidence and semantic verdict produced by one read-only observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    evidence: Vec<u8>,
    verdict: Verdict,
}

impl Observation {
    /// Shell-compatible evidence bytes preceding the watcher report.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// Semantic watcher verdict.
    #[must_use]
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }
}

/// Stable watcher failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchError {
    /// The completion-marker identity or bytes could not be inspected.
    ReportRead,
    /// The settled completion marker did not contain a governed lane report.
    ReportContract,
    /// The event-source identity or metadata could not be inspected.
    EventSource,
    /// The event source could not be read completely.
    EventRead,
    /// Agent-text evidence or the terminal report could not be published.
    Publication,
}

impl WatchError {
    /// One fixed, classed, path-free diagnostic for this failure.
    #[must_use]
    pub const fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::ReportRead => {
                b"superloop-lane: report_read_failure: completion report could not be read\n"
            }
            Self::ReportContract => {
                b"superloop-lane: report_contract_failure: completion report is invalid\n"
            }
            Self::EventSource => {
                b"superloop-lane: event_source_failure: event source inspection failed\n"
            }
            Self::EventRead => {
                b"superloop-lane: event_read_failure: event source could not be read\n"
            }
            Self::Publication => PUBLICATION_DIAGNOSTIC,
        }
    }
}

impl fmt::Display for WatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let diagnostic = std::str::from_utf8(self.diagnostic()).unwrap_or("lane-watch failure");
        formatter.write_str(diagnostic.trim_end())
    }
}

impl std::error::Error for WatchError {}

/// Parse watcher arguments, excluding the program name.
///
/// The run directory must already be a directory, and an explicit threshold must be one nonnegative decimal integer.
#[must_use]
pub fn parse_args<I, A>(args: I) -> Option<Config>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let mut arguments = args.into_iter().map(Into::into);
    let run_dir = PathBuf::from(arguments.next()?);
    let stall_seconds = match arguments.next() {
        Some(value) => parse_stall_seconds(&value)?,
        None => DEFAULT_STALL_SECONDS,
    };
    if arguments.next().is_some() || !run_dir.is_dir() {
        return None;
    }
    Some(Config {
        run_dir,
        stall_seconds,
    })
}

/// Perform one read-only watcher observation at an explicit wall-clock instant.
///
/// Event age is real elapsed time unless the step's own monitor published a usable capture, in which case the awake age derived from it governs the threshold comparison, because a host suspend freezes a producer without stalling it.
///
/// # Errors
///
/// Returns a stable [`WatchError`] when producer evidence cannot be inspected, read, or classified; no run-directory state is written on any path.
pub fn observe(config: &Config, now: SystemTime) -> Result<Observation, WatchError> {
    if let Some(report) = read_report(&config.run_dir)? {
        let verdict = classify_report(&report)?;
        return Ok(Observation {
            evidence: report,
            verdict,
        });
    }

    let event_path = config.run_dir.join("events.jsonl");
    let metadata = match fs::metadata(&event_path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_metadata) => return Err(WatchError::EventSource),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Observation {
                evidence: b"STALLED age=unknown events=0 last=none\n".to_vec(),
                verdict: Verdict::Stalled,
            });
        }
        Err(_error) => return Err(WatchError::EventSource),
    };

    let modified = metadata
        .modified()
        .map_err(|_error| WatchError::EventSource)?;
    let events = fs::read(event_path).map_err(|_error| WatchError::EventRead)?;
    let elapsed = age_seconds(now, modified);
    let age = if elapsed >= i128::from(config.stall_seconds) {
        monitor_age(&config.run_dir, &LinuxProc).unwrap_or(elapsed)
    } else {
        elapsed
    };
    let liveness = if age >= i128::from(config.stall_seconds) {
        producer_liveness(&config.run_dir)
    } else {
        LivenessEvidence::default()
    };
    Ok(observe_events_with_liveness(
        &events,
        age,
        config.stall_seconds,
        &liveness,
    ))
}

/// Publish shell-compatible evidence followed by the watcher's terminal report.
///
/// `wall` is emitted as whole nonnegative seconds in the package's declared report order.
///
/// # Errors
///
/// Returns [`WatchError::Publication`] if any evidence or report byte, or the final flush, is rejected.
pub fn publish_observation<W: Write>(
    observation: &Observation,
    wall: Duration,
    output: &mut W,
) -> Result<(), WatchError> {
    output
        .write_all(observation.evidence())
        .map_err(|_error| WatchError::Publication)?;
    write_report(
        output,
        observation.verdict.status(),
        wall,
        observation.verdict.report_word(),
    )
}

/// Publish one runtime diagnostic followed by the required failed report.
///
/// # Errors
///
/// Returns [`WatchError::Publication`] if any diagnostic or report byte, or the final flush, is rejected.
pub fn publish_failure<W: Write>(
    diagnostic: &[u8],
    wall: Duration,
    output: &mut W,
) -> Result<(), WatchError> {
    output
        .write_all(diagnostic)
        .map_err(|_error| WatchError::Publication)?;
    write_report(output, 1, wall, "FAILED")
}

fn parse_stall_seconds(value: &OsStr) -> Option<u64> {
    let text = value.to_str()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn read_report(run_dir: &std::path::Path) -> Result<Option<Vec<u8>>, WatchError> {
    let path = run_dir.join("run-report.txt");
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => fs::read(path)
            .map(Some)
            .map_err(|_error| WatchError::ReportRead),
        Ok(_metadata) => Err(WatchError::ReportRead),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_error) => Err(WatchError::ReportRead),
    }
}

fn classify_report(report: &[u8]) -> Result<Verdict, WatchError> {
    let body = report
        .strip_suffix(b"\n")
        .ok_or(WatchError::ReportContract)?;
    let line = body
        .rsplit(|byte| *byte == b'\n')
        .next()
        .ok_or(WatchError::ReportContract)?;
    let mut fields = line.split(|byte| *byte == b' ');
    if fields.next() != Some(b"RUN-REPORT".as_slice()) {
        return Err(WatchError::ReportContract);
    }

    let mut exit = None;
    let mut verdict = None;
    for field in fields {
        if field.is_empty() {
            return Err(WatchError::ReportContract);
        }
        if let Some(value) = field.strip_prefix(b"exit=") {
            if exit.is_some() {
                return Err(WatchError::ReportContract);
            }
            exit = Some(parse_decimal(value).ok_or(WatchError::ReportContract)?);
        }
        if let Some(value) = field.strip_prefix(b"verdict=")
            && verdict.replace(value).is_some()
        {
            return Err(WatchError::ReportContract);
        }
    }

    let verdict = verdict.ok_or(WatchError::ReportContract)?;
    if exit == Some(0) && (verdict == b"ok" || verdict == b"OVER-BUDGET") {
        Ok(Verdict::Completed)
    } else if ((exit == Some(1) || exit == Some(2)) && verdict == b"FAILED")
        || (exit == Some(1) && RUNTIME_FAILURE_VERDICTS.contains(&verdict))
    {
        Ok(Verdict::Failed)
    } else {
        Err(WatchError::ReportContract)
    }
}

/// The lane verdicts that report a failed step at runtime-failure status 1.
///
/// Each names a way a step ended without completing: the monitor killed it,
/// the provider refused its dispatch, or its driver died and a later step
/// settled the record. A watcher that met one of these and answered with a
/// contract error would report a broken producer where the lane in fact
/// reported a failure precisely, which hides the very outcome an operator is
/// watching for.
///
/// `SUSPEND-KILLED` is here for the same reason although no driver writes it
/// any more: a host sleep is now measured and disclosed beside the verdict the
/// step earned rather than ending the step. Run directories written before
/// that still hold the verdict, and a reader of stored reports meets them.
const RUNTIME_FAILURE_VERDICTS: [&[u8]; 5] = [
    b"STALLED-KILLED",
    b"RUNAWAY-KILLED",
    b"RATE-LIMITED",
    b"SUSPEND-KILLED",
    b"CRASHED-HOST-EXIT",
];

fn parse_decimal(bytes: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn age_seconds(now: SystemTime, modified: SystemTime) -> i128 {
    unix_seconds(now) - unix_seconds(modified)
}

fn unix_seconds(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::from(duration.as_secs()),
        Err(error) => {
            let duration = error.duration();
            let rounded = if duration.subsec_nanos() == 0 {
                duration.as_secs()
            } else {
                duration.as_secs() + 1
            };
            -i128::from(rounded)
        }
    }
}

#[cfg(test)]
fn observe_events(events: &[u8], age: i128, stall_seconds: u64) -> Observation {
    observe_events_with_liveness(events, age, stall_seconds, &LivenessEvidence::default())
}

fn observe_events_with_liveness(
    events: &[u8],
    age: i128,
    stall_seconds: u64,
    liveness: &LivenessEvidence,
) -> Observation {
    let unterminated_line = usize::from(!events.is_empty() && !events.ends_with(b"\n"));
    let terminated_lines = events.split(|byte| *byte == b'\n').count() - 1;
    let line_count = terminated_lines + unterminated_line;
    let last_event = last_event(events);
    let last_type = extract_last_type(last_event).unwrap_or(b"unknown");
    let stalled = age >= i128::from(stall_seconds);
    let mut evidence = Vec::new();
    let generating = stalled && liveness.is_generating();
    let state = if generating {
        "GENERATING"
    } else if stalled {
        "STALLED"
    } else {
        "ALIVE"
    };
    evidence.extend_from_slice(state.as_bytes());
    evidence.extend_from_slice(b" age=");
    evidence.extend_from_slice(age.to_string().as_bytes());
    evidence.extend_from_slice(b"s events=");
    evidence.extend_from_slice(line_count.to_string().as_bytes());
    evidence.extend_from_slice(b" last=");
    evidence.extend_from_slice(last_type);
    if stalled {
        evidence.extend_from_slice(b" pid=");
        let visible_pid = if generating {
            liveness.producer_pid
        } else {
            liveness.driver_pid
        };
        if let Some(pid) = visible_pid {
            evidence.extend_from_slice(pid.to_string().as_bytes());
        } else {
            evidence.extend_from_slice(b"none");
        }
        evidence.extend_from_slice(b" established=");
        evidence.extend_from_slice(liveness.established.to_string().as_bytes());
        evidence.extend_from_slice(b" io_delta=");
        evidence.extend_from_slice(liveness.io_delta.to_string().as_bytes());
    }
    evidence.push(b'\n');
    if stalled {
        evidence.extend_from_slice(last_event);
        evidence.push(b'\n');
    }
    Observation {
        evidence,
        verdict: if !stalled || generating {
            Verdict::Running
        } else {
            Verdict::Stalled
        },
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LivenessEvidence {
    driver_pid: Option<u32>,
    producer_pid: Option<u32>,
    established: usize,
    io_delta: u64,
}

impl LivenessEvidence {
    const fn is_generating(self) -> bool {
        self.established > 0 || self.io_delta > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessStat {
    pid: u32,
    state: u8,
    parent: u32,
}

trait ProcReader {
    fn stat_records(&self) -> Option<Vec<Vec<u8>>>;
    fn fd_targets(&self, pid: u32) -> Vec<OsString>;
    fn tcp_tables(&self) -> Vec<Vec<u8>>;
    fn io_record(&self, pid: u32) -> Option<Vec<u8>>;
    fn wait(&self, duration: Duration);
}

struct LinuxProc;

impl ProcReader for LinuxProc {
    fn stat_records(&self) -> Option<Vec<Vec<u8>>> {
        Some(
            fs::read_dir("/proc")
                .ok()?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().as_bytes().iter().all(u8::is_ascii_digit))
                .filter_map(|entry| fs::read(entry.path().join("stat")).ok())
                .collect(),
        )
    }

    fn fd_targets(&self, pid: u32) -> Vec<OsString> {
        let Some(entries) = fs::read_dir(format!("/proc/{pid}/fd")).ok() else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .map(PathBuf::into_os_string)
            .collect()
    }

    fn tcp_tables(&self) -> Vec<Vec<u8>> {
        ["/proc/net/tcp", "/proc/net/tcp6"]
            .into_iter()
            .filter_map(|path| fs::read(path).ok())
            .collect()
    }

    fn io_record(&self, pid: u32) -> Option<Vec<u8>> {
        fs::read(format!("/proc/{pid}/io")).ok()
    }

    fn wait(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn producer_liveness(run_dir: &std::path::Path) -> LivenessEvidence {
    let Some(driver_pid) = read_driver_pid(run_dir) else {
        return LivenessEvidence::default();
    };
    producer_liveness_with(driver_pid, &LinuxProc)
}

fn producer_liveness_with(reader_driver_pid: u32, reader: &impl ProcReader) -> LivenessEvidence {
    let mut evidence = LivenessEvidence {
        driver_pid: Some(reader_driver_pid),
        ..LivenessEvidence::default()
    };
    let Some(records) = reader.stat_records() else {
        return evidence;
    };
    let process_stats: Vec<_> = records
        .iter()
        .filter_map(|record| parse_process_stat(record))
        .collect();
    if !live_process(reader_driver_pid, &process_stats) {
        return evidence;
    }

    let producers = descendant_pids(reader_driver_pid, &process_stats);
    if producers.is_empty() {
        return evidence;
    }

    let established_inodes = established_tcp_inodes(&reader.tcp_tables());
    let mut matched_inodes = BTreeSet::new();
    let mut socket_owner = None;
    for pid in &producers {
        for target in reader.fd_targets(*pid) {
            let Some(inode) = socket_inode(&target) else {
                continue;
            };
            if established_inodes.contains(&inode) && matched_inodes.insert(inode) {
                socket_owner.get_or_insert(*pid);
            }
        }
    }
    evidence.established = matched_inodes.len();

    let before: BTreeMap<_, _> = producers
        .iter()
        .filter_map(|pid| {
            reader
                .io_record(*pid)
                .and_then(|record| parse_io_total(&record))
                .map(|total| (*pid, total))
        })
        .collect();
    reader.wait(IO_SAMPLE_WINDOW);
    let mut io_owner = None;
    for pid in &producers {
        let Some((before_total, after_total)) = before.get(pid).copied().zip(
            reader
                .io_record(*pid)
                .and_then(|record| parse_io_total(&record)),
        ) else {
            continue;
        };
        let delta = after_total.saturating_sub(before_total);
        if delta > 0 {
            io_owner.get_or_insert(*pid);
            evidence.io_delta = evidence.io_delta.saturating_add(delta);
        }
    }
    evidence.producer_pid = socket_owner.or(io_owner);
    evidence
}

/// The driver a step lock names, from the first line it carries.
///
/// A lock names the driver on its first line and, once the step's child
/// exists, that child on its second. Reading the whole file as one identity
/// would find none in a two-line lock, and a watcher with no driver pid falls
/// back to the modification-time age and to no liveness evidence — the
/// suspend-blind reading of a monitor capture exists to avoid. The first line
/// is the driver in every lock shape a driver has ever written.
fn read_driver_pid(run_dir: &std::path::Path) -> Option<u32> {
    monitor_lock::select_driver_lock(run_dir, monitor_lock::pid_live_from_proc)
        .map(|(_, pid, _, _)| pid)
}

/// The monitor's published quiet interval and the boot reading it holds for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MonitorSample {
    quiet: u64,
    boot: u64,
}

/// The awake age of the event source, when the step's own monitor can supply one.
///
/// A record left by a dead driver says nothing about now, and one written
/// before a reboot belongs to a host that no longer exists, so both fall back
/// to real elapsed time and the watcher observes exactly as it did without any
/// record at all.
fn monitor_age(run_dir: &std::path::Path, reader: &impl ProcReader) -> Option<i128> {
    let (_, driver_pid, _, live) =
        monitor_lock::select_driver_lock(run_dir, |pid| driver_is_live(pid, reader))?;
    if !live {
        return None;
    }
    let prefix = format!("{MONITOR_FILE_PREFIX}{driver_pid}-");
    let sample = fs::read_dir(run_dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let sequence = name.to_str()?.strip_prefix(&prefix)?.parse::<u64>().ok()?;
            let sample = parse_monitor_sample(&fs::read(entry.path()).ok()?)?;
            Some(((sample.boot, sequence), sample))
        })
        .max_by_key(|(key, _)| *key)?
        .1;
    awake_age(sample, boot_seconds()?)
}

/// Awake seconds the producer has been quiet, as of the reader's boot reading.
///
/// The monitor's quiet interval is awake time already. What the reader adds is
/// the interval since that record, for which it holds one boot reading and no
/// awake one: a separate process cannot read the clock that stopped while the
/// host was away, so this sum is an upper bound, exact whenever the host stayed
/// awake and high by whatever it slept afterwards. Erring high is the safe
/// direction — a genuine stall is still reported, because the monitor's own
/// quiet interval grows through it — and the overstatement lasts only until the
/// resumed driver's next poll republishes the record.
fn awake_age(sample: MonitorSample, boot_now: u64) -> Option<i128> {
    let since_sample = boot_now.checked_sub(sample.boot)?;
    Some(i128::from(sample.quiet) + i128::from(since_sample))
}

fn parse_monitor_sample(record: &[u8]) -> Option<MonitorSample> {
    let line = record.strip_suffix(b"\n")?;
    if line.contains(&b'\n') {
        return None;
    }
    let mut quiet = None;
    let mut boot = None;
    for field in line.split(|byte| *byte == b' ') {
        if let Some(value) = field.strip_prefix(b"quiet=") {
            quiet = parse_seconds(value);
        } else if let Some(value) = field.strip_prefix(b"boot=") {
            boot = parse_seconds(value);
        }
    }
    Some(MonitorSample {
        quiet: quiet?,
        boot: boot?,
    })
}

fn parse_seconds(field: &[u8]) -> Option<u64> {
    let digits = field.strip_suffix(b"s")?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

fn boot_seconds() -> Option<u64> {
    parse_boot_seconds(&fs::read_to_string(BOOT_CLOCK_FILE).ok()?)
}

fn parse_boot_seconds(uptime: &str) -> Option<u64> {
    let field = uptime.split_ascii_whitespace().next()?;
    let whole = field
        .split_once('.')
        .map_or(field, |(whole, _fraction)| whole);
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    whole.parse().ok()
}

fn driver_is_live(driver_pid: u32, reader: &impl ProcReader) -> bool {
    let Some(records) = reader.stat_records() else {
        return false;
    };
    let process_stats: Vec<_> = records
        .iter()
        .filter_map(|record| parse_process_stat(record))
        .collect();
    live_process(driver_pid, &process_stats)
}

fn live_process(pid: u32, stats: &[ProcessStat]) -> bool {
    stats
        .iter()
        .any(|stat| stat.pid == pid && stat.state != b'Z' && stat.state != b'X')
}

fn parse_process_stat(record: &[u8]) -> Option<ProcessStat> {
    let pid_end = record.iter().position(|byte| *byte == b' ')?;
    let pid = std::str::from_utf8(record.get(..pid_end)?)
        .ok()?
        .parse()
        .ok()?;
    let command_end = record.iter().rposition(|byte| *byte == b')')?;
    let mut fields = record
        .get(command_end + 1..)?
        .split(u8::is_ascii_whitespace);
    let state = fields.find(|field| !field.is_empty())?;
    let parent = fields.find(|field| !field.is_empty())?;
    if state.len() != 1 {
        return None;
    }
    Some(ProcessStat {
        pid,
        state: state[0],
        parent: std::str::from_utf8(parent).ok()?.parse().ok()?,
    })
}

fn descendant_pids(driver_pid: u32, stats: &[ProcessStat]) -> BTreeSet<u32> {
    let mut descendants = BTreeSet::new();
    loop {
        let before = descendants.len();
        for stat in stats {
            if stat.pid != driver_pid
                && (stat.parent == driver_pid || descendants.contains(&stat.parent))
            {
                descendants.insert(stat.pid);
            }
        }
        if descendants.len() == before {
            return descendants;
        }
    }
}

fn socket_inode(target: &OsStr) -> Option<u64> {
    let bytes = target.as_bytes();
    let digits = bytes.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    std::str::from_utf8(digits).ok()?.parse().ok()
}

fn established_tcp_inodes(tables: &[Vec<u8>]) -> BTreeSet<u64> {
    tables
        .iter()
        .flat_map(|table| table.split(|byte| *byte == b'\n'))
        .filter_map(|line| {
            let mut fields = line
                .split(u8::is_ascii_whitespace)
                .filter(|field| !field.is_empty());
            let state = fields.nth(3)?;
            if state != b"01" {
                return None;
            }
            let inode = fields.nth(5)?;
            std::str::from_utf8(inode).ok()?.parse().ok()
        })
        .collect()
}

fn parse_io_total(record: &[u8]) -> Option<u64> {
    let mut rchar = None;
    let mut wchar = None;
    for line in record.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"rchar: ") {
            rchar = std::str::from_utf8(value).ok()?.parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix(b"wchar: ") {
            wchar = std::str::from_utf8(value).ok()?.parse::<u64>().ok();
        }
    }
    Some(rchar?.saturating_add(wchar?))
}

fn last_event(events: &[u8]) -> &[u8] {
    let without_terminal_lf = events.strip_suffix(b"\n").unwrap_or(events);
    without_terminal_lf
        .rsplit(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default()
}

fn extract_last_type(event: &[u8]) -> Option<&[u8]> {
    let marker = b"\"type\"";
    for start in (0..=event.len().saturating_sub(marker.len())).rev() {
        if event.get(start..start + marker.len()) != Some(marker.as_slice()) {
            continue;
        }
        let mut cursor = start + marker.len();
        skip_ascii_whitespace(event, &mut cursor);
        if event.get(cursor) != Some(&b':') {
            continue;
        }
        cursor += 1;
        skip_ascii_whitespace(event, &mut cursor);
        if event.get(cursor) != Some(&b'\"') {
            continue;
        }
        cursor += 1;
        let Some(relative_end) = event[cursor..].iter().position(|byte| *byte == b'\"') else {
            continue;
        };
        let end = relative_end + cursor;
        return Some(&event[cursor..end]);
    }
    None
}

fn skip_ascii_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
}

fn write_report<W: Write>(
    output: &mut W,
    status: u8,
    wall: Duration,
    verdict: &str,
) -> Result<(), WatchError> {
    writeln!(
        output,
        "RUN-REPORT exit={status} wall={}s verdict={verdict}",
        wall.as_secs()
    )
    .and_then(|()| output.flush())
    .map_err(|_error| WatchError::Publication)
}

mod entry;

pub(super) use entry::main as command;
