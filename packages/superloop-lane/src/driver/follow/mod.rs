#![doc = include_str!("README.md")]

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lane_lifecycle::parse_utc_instant;
use serde_json::{Value, json};
use superloop_cli_common::{CliExit, CommandExit, ControlPlaneRecord};

use super::monitor_lock;
#[cfg(test)]
mod tests;
#[cfg(test)]
use monitor_lock::parse_lock;

// Retain the capture's cost shape without scanning correspondence.
#[derive(Default)]
struct Cost {
    scans: u64,
    journal_bytes: u64,
    receipt_names: u64,
    wall: Duration,
}
impl Cost {
    fn value(&self) -> Value {
        json!({"scans":self.scans,"journal_bytes":self.journal_bytes,"receipt_names":self.receipt_names,"scan_wall_ms":u64::try_from(self.wall.as_millis()).unwrap_or(u64::MAX)})
    }
}

const COMMAND_NAME: &str = "superloop-lane";

/// Default maximum event payload, matching the Python reference.
pub const DEFAULT_CAP: u64 = 50_000;

/// Default quiet window in seconds.
pub const DEFAULT_BOUNCE: u64 = 30;

/// Poll interval used while neither an event delta nor completion is ready.
pub const SLEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Fixed usage diagnostic retained in the schema-two failure record.
pub const USAGE_DIAGNOSTIC: &str = "superloop-lane: usage_error: invalid command-line arguments\n";

/// Parsed feeder configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Worker-lane run directory to follow.
    pub run_dir: PathBuf,
    /// Maximum number of newest unread event bytes to include.
    pub cap: u64,
    /// Quiet window measured from the event log's modification time.
    pub bounce: u64,
    /// Maximum wait from invocation before publishing state alone; zero is unbounded.
    pub wait: u64,
    /// Save the accepted event offset and delivery position after publication.
    pub save_offset: bool,
}

/// Successful result of one nonblocking poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollResult {
    /// No delta has met a serve condition and no completion report exists.
    Pending,
    /// One delta record was completely written and flushed.
    Delta,
    /// One finished record was completely written and flushed.
    Finished,
    /// A delta followed by a finished record was written in one document.
    DeltaAndFinished,
    /// A budget notification was published without an event delta or finish.
    Budget,
}

/// Stable feeder failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedError {
    /// The event source could not be inspected.
    EventSource,
    /// The sampled event source regressed behind the stored follower offset.
    EvidenceContinuity,
    /// The selected event range could not be read completely.
    EventRead,
    /// The settled completion report could not be read completely.
    ReportRead,
    /// The optional last-message payload could not be read completely.
    LastMessageRead,
    /// Standard output rejected part of a document or its final flush.
    Relay,
    /// The accepted event size could not be stored after a complete delta.
    OffsetState,
    /// The durable letter stream or its follower position is invalid.
    LetterSource,
    /// The budget delivery cursor is malformed or cannot be stored safely.
    BudgetNotice,
}

impl FeedError {
    /// Stable failure-class name used by the schema-two data-plane record.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::EventSource => "event_source_failure",
            Self::EvidenceContinuity => "evidence_continuity_failure",
            Self::EventRead => "event_read_failure",
            Self::ReportRead => "report_read_failure",
            Self::LastMessageRead => "last_message_read_failure",
            Self::Relay => "relay_failure",
            Self::OffsetState => "offset_state_failure",
            Self::LetterSource => "letter_source_failure",
            Self::BudgetNotice => "budget_notice_failure",
        }
    }

    /// One fixed, classed, path-free diagnostic for this failure.
    #[must_use]
    pub const fn diagnostic(self) -> &'static str {
        match self {
            Self::EventSource => {
                "superloop-lane: event_source_failure: event source inspection failed\n"
            }
            Self::EvidenceContinuity => {
                "superloop-lane: evidence_continuity_failure: event source regressed behind follower offset\n"
            }
            Self::EventRead => {
                "superloop-lane: event_read_failure: selected event bytes could not be read\n"
            }
            Self::ReportRead => {
                "superloop-lane: report_read_failure: completion report could not be read\n"
            }
            Self::LastMessageRead => {
                "superloop-lane: last_message_read_failure: last message could not be read\n"
            }
            Self::Relay => "superloop-lane: relay_failure: feeder document publication failed\n",
            Self::OffsetState => {
                "superloop-lane: offset_state_failure: accepted event offset could not be stored\n"
            }
            Self::LetterSource => {
                "superloop-lane: letter_source_failure: durable letter stream or position is invalid\n"
            }
            Self::BudgetNotice => {
                "superloop-lane: budget_notice_failure: budget delivery cursor is invalid\n"
            }
        }
    }
}

impl fmt::Display for FeedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.diagnostic().trim_end())
    }
}

impl std::error::Error for FeedError {}

/// Parse feeder arguments, excluding the program name.
///
/// `--cap`, `--bounce`, and `--wait` accept both separated and joined spellings before or
/// after the one run-directory positional. Both values use the reference
/// helper's nonnegative Python-integer grammar.
///
/// # Errors
///
/// Returns a [`CliExit`] carrying the ADR-010 usage record and exit class when
/// the command line is invalid. Argument values and paths are never copied into
/// that record.
#[allow(clippy::result_large_err)]
pub fn parse_args<I, A>(args: I) -> Result<Config, CliExit>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let mut cap = DEFAULT_CAP;
    let mut bounce = DEFAULT_BOUNCE;
    let mut wait = 0;
    let mut save_offset = false;
    let mut run_dir = None;
    let mut arguments = args.into_iter().map(Into::into);

    while let Some(argument) = arguments.next() {
        let lossy = argument.to_string_lossy();
        if lossy == "--save-offset" {
            if save_offset {
                return Err(usage_exit());
            }
            save_offset = true;
        } else if lossy == "--cap" {
            let value = arguments.next().ok_or_else(usage_exit)?;
            cap = parse_nonnegative(&value).ok_or_else(usage_exit)?;
        } else if let Some(value) = lossy.strip_prefix("--cap=") {
            cap = parse_nonnegative(OsStr::new(value)).ok_or_else(usage_exit)?;
        } else if lossy == "--bounce" {
            let value = arguments.next().ok_or_else(usage_exit)?;
            bounce = parse_nonnegative(&value).ok_or_else(usage_exit)?;
        } else if let Some(value) = lossy.strip_prefix("--bounce=") {
            bounce = parse_nonnegative(OsStr::new(value)).ok_or_else(usage_exit)?;
        } else if lossy == "--wait" {
            let value = arguments.next().ok_or_else(usage_exit)?;
            wait = parse_nonnegative(&value).ok_or_else(usage_exit)?;
        } else if let Some(value) = lossy.strip_prefix("--wait=") {
            wait = parse_nonnegative(OsStr::new(value)).ok_or_else(usage_exit)?;
        } else if lossy.starts_with('-') || run_dir.is_some() {
            return Err(usage_exit());
        } else {
            run_dir = Some(PathBuf::from(argument));
        }
    }

    let run_dir = run_dir.ok_or_else(usage_exit)?;
    // Access failures belong to the runtime's named outbox refusal, not argv usage.
    match std::fs::metadata(&run_dir) {
        Ok(meta) if meta.is_dir() => {}
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        _ => return Err(usage_exit()),
    }
    Ok(Config {
        run_dir,
        cap,
        bounce,
        wait,
        save_offset,
    })
}

fn usage_exit() -> CliExit {
    CliExit::new(
        ControlPlaneRecord::usage_error(COMMAND_NAME, "invalid_arguments"),
        CommandExit::Usage,
    )
}

/// Poll until one complete schema-two document is emitted.
///
/// # Errors
///
/// Returns a stable [`FeedError`] for source, relay, report, or offset-state
/// failure. An incomplete delta document never advances the stored follower
/// offset.
pub fn run<W: Write>(config: &Config, output: &mut W) -> Result<(), FeedError> {
    let invoked = Instant::now();
    let cost = Cost::default();
    loop {
        let mut accepted = None;
        let result = poll_once_measured(config, output, SystemTime::now(), &cost, &mut accepted)?;
        if let Some(offset) = accepted {
            write_offset(&config.run_dir, offset)?;
        }
        match result {
            PollResult::Pending => {
                if config.wait > 0 {
                    let remaining =
                        Duration::from_secs(config.wait).saturating_sub(invoked.elapsed());
                    if remaining.is_zero() {
                        let offset = read_offset(&config.run_dir).for_source_size(u64::MAX)?;
                        return relay_success_cost(config, output, offset, &[], &cost);
                    }
                    std::thread::sleep(SLEEP_INTERVAL.min(remaining));
                } else {
                    std::thread::sleep(SLEEP_INTERVAL);
                }
            }
            PollResult::Delta
            | PollResult::Finished
            | PollResult::DeltaAndFinished
            | PollResult::Budget => {
                return Ok(());
            }
        }
    }
}

/// Publish driver event and budget evidence without inspecting correspondence.
///
/// # Errors
/// Returns the existing feeder failure; ordinary mail observation is independent.
pub fn run_with_messages(
    config: &Config,
    output: &mut impl Write,
    messages: &mut impl Write,
) -> Result<(), FeedError> {
    run_with_messages_wait(config, output, messages, std::thread::sleep)
}

fn run_with_messages_wait(
    config: &Config,
    output: &mut impl Write,
    _messages: &mut impl Write,
    mut wait: impl FnMut(Duration),
) -> Result<(), FeedError> {
    let invoked = Instant::now();
    let cost = Cost::default();
    loop {
        let mut accepted = None;
        let result = poll_once_measured(config, output, SystemTime::now(), &cost, &mut accepted)?;
        if let Some(offset) = accepted {
            write_offset(&config.run_dir, offset)?;
        }
        if result != PollResult::Pending {
            return Ok(());
        }
        let remaining = if config.wait == 0 {
            SLEEP_INTERVAL
        } else {
            Duration::from_secs(config.wait).saturating_sub(invoked.elapsed())
        };
        if remaining.is_zero() {
            let offset = read_offset(&config.run_dir).for_source_size(u64::MAX)?;
            return relay_success_cost(config, output, offset, &[], &cost);
        }
        wait(SLEEP_INTERVAL.min(remaining));
    }
}

/// Perform one nonblocking feeder poll.
///
/// # Errors
///
/// Returns a stable [`FeedError`] for source, relay, report, or offset-state
/// failure. Output can be a partial document only when the returned class is
/// [`FeedError::Relay`].
pub fn poll_once<W: Write>(config: &Config, output: &mut W) -> Result<PollResult, FeedError> {
    poll_once_at(config, output, SystemTime::now())
}

fn poll_once_at<W: Write>(
    config: &Config,
    output: &mut W,
    now: SystemTime,
) -> Result<PollResult, FeedError> {
    let mut accepted = None;
    let result = poll_once_measured(config, output, now, &Cost::default(), &mut accepted)?;
    if let Some(offset) = accepted {
        write_offset(&config.run_dir, offset)?;
    }
    Ok(result)
}

fn poll_once_measured<W: Write>(
    config: &Config,
    output: &mut W,
    now: SystemTime,
    cost: &Cost,
    accepted: &mut Option<u64>,
) -> Result<PollResult, FeedError> {
    let delivered = read_budget_cursor(&config.run_dir)?;
    let (notices, budget_cursor) = budget_records(&config.run_dir, delivered.as_ref());
    let offset = read_offset(&config.run_dir);
    let event_source = open_event_source(&config.run_dir)?;

    match event_source {
        Some((mut source, metadata)) => {
            let size = metadata.len();
            let offset = offset.for_source_size(size)?;
            if size > offset {
                let report = read_optional_file(
                    &config.run_dir.join("run-report.txt"),
                    FeedError::ReportRead,
                )?;
                let unread = size - offset;
                if !delta_is_ready(
                    unread,
                    config.cap,
                    config.bounce,
                    report.is_some(),
                    &metadata.modified(),
                    now,
                    || unread_tail_is_heartbeat(&mut source, offset, size),
                ) {
                    if notices.is_empty() {
                        return Ok(PollResult::Pending);
                    }
                    let records = notices;
                    relay_success_cost(config, output, offset, &records, cost)?;
                    save_delivery(config, budget_cursor.as_ref())?;

                    return Ok(PollResult::Budget);
                }

                let delta = read_delta(config, &mut source, offset, size)?;
                let mut records = notices;
                records.push(delta);
                let result = if let Some(report) = report {
                    records.push(finished_record(config, &report)?);
                    PollResult::DeltaAndFinished
                } else {
                    PollResult::Delta
                };

                if config.save_offset {
                    ensure_offset_target(&config.run_dir)?;
                }
                relay_success_cost(config, output, offset, &records, cost)?;
                save_delivery(config, budget_cursor.as_ref())?;

                if config.save_offset {
                    *accepted = Some(size);
                }
                return Ok(result);
            }
        }
        None => {
            if offset.is_positive() {
                return Err(FeedError::EvidenceContinuity);
            }
        }
    }

    let accepted = offset.for_source_size(u64::MAX)?;
    if !notices.is_empty() {
        let report = read_optional_file(
            &config.run_dir.join("run-report.txt"),
            FeedError::ReportRead,
        )?;
        let mut records = notices;
        let result = if let Some(report) = report {
            records.push(finished_record(config, &report)?);
            PollResult::Finished
        } else {
            PollResult::Budget
        };
        relay_success_cost(config, output, accepted, &records, cost)?;
        save_delivery(config, budget_cursor.as_ref())?;

        return Ok(result);
    }
    emit_finished_if_ready(config, output, accepted, cost)
}

fn save_delivery(config: &Config, budget: Option<&BudgetCursor>) -> Result<(), FeedError> {
    if config.save_offset {
        mark_budget_delivered(&config.run_dir, budget)?;
    }
    Ok(())
}

fn delta_is_ready(
    unread: u64,
    cap: u64,
    bounce: u64,
    report_ready: bool,
    modified: &io::Result<SystemTime>,
    now: SystemTime,
    heartbeat_tail: impl FnOnce() -> bool,
) -> bool {
    if bounce == 0 || unread >= cap || report_ready {
        return true;
    }
    let Ok(modified) = modified else {
        return true;
    };
    if now.duration_since(*modified).unwrap_or_default() >= Duration::from_secs(bounce) {
        return true;
    }
    heartbeat_tail()
}

/// Longest tail of the unread region inspected for a heartbeat line.
///
/// A heartbeat line is a few hundred bytes, so eight kibibytes hold the last
/// complete line of any ordinary event log while keeping the probe's cost
/// independent of how far the follower has fallen behind.
const HEARTBEAT_PROBE: u64 = 8 * 1024;

/// Report whether the unread region's last complete line is a heartbeat.
///
/// The probe reads at most [`HEARTBEAT_PROBE`] trailing bytes and never rewinds
/// to the start of a long region. A read that cannot be completed reports no
/// heartbeat, which leaves the surrounding bounce decision as it was.
fn unread_tail_is_heartbeat(source: &mut File, offset: u64, size: u64) -> bool {
    let unread = size - offset;
    let probe = unread.min(HEARTBEAT_PROBE);
    let Ok(length) = usize::try_from(probe) else {
        return false;
    };
    if source.seek(SeekFrom::Start(size - probe)).is_err() {
        return false;
    }
    let mut payload = vec![0_u8; length];
    if source.read_exact(&mut payload).is_err() {
        return false;
    }
    let region = if probe < unread {
        after_torn_prefix(payload.as_slice())
    } else {
        payload.as_slice()
    };
    tail_is_heartbeat(region)
}

/// Bytes after the first line terminator, where a probe window that opened
/// inside a line resumes reading complete lines.
fn after_torn_prefix(payload: &[u8]) -> &[u8] {
    match payload.iter().position(|byte| *byte == b'\n') {
        Some(index) => &payload[index + 1..],
        None => &[],
    }
}

/// Report whether the region's last newline-terminated line is a heartbeat.
///
/// A trailing line without its terminator is still being written, so it is not
/// the region's last complete line and cannot decide the release.
fn tail_is_heartbeat(region: &[u8]) -> bool {
    let Some(end) = region.iter().rposition(|byte| *byte == b'\n') else {
        return false;
    };
    let start = region[..end]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    line_is_heartbeat(&region[start..end])
}

/// Report whether one complete line is a worker liveness heartbeat: a JSON
/// object whose `type` is `tool_progress` and whose `heartbeat` is boolean true.
fn line_is_heartbeat(line: &[u8]) -> bool {
    let Ok(Value::Object(event)) = serde_json::from_slice::<Value>(line) else {
        return false;
    };
    event.get("type").and_then(Value::as_str) == Some("tool_progress")
        && event.get("heartbeat").and_then(Value::as_bool) == Some(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredOffset {
    Value(u64),
    PositiveOverflow,
}

impl StoredOffset {
    const fn is_positive(self) -> bool {
        !matches!(self, Self::Value(0))
    }

    const fn for_source_size(self, size: u64) -> Result<u64, FeedError> {
        match self {
            Self::Value(value) if value <= size => Ok(value),
            Self::Value(_) | Self::PositiveOverflow => Err(FeedError::EvidenceContinuity),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParsedInteger {
    Negative,
    Value(u64),
    PositiveOverflow,
}

fn parse_nonnegative(value: &OsStr) -> Option<u64> {
    match parse_integer(value.to_str()?)? {
        ParsedInteger::Negative => None,
        ParsedInteger::Value(value) => Some(value),
        ParsedInteger::PositiveOverflow => Some(u64::MAX),
    }
}

fn parse_integer(value: &str) -> Option<ParsedInteger> {
    let trimmed = value.trim();
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };

    if digits.is_empty() {
        return None;
    }

    let bytes = digits.as_bytes();
    let mut value = 0_u64;
    let mut overflowed = false;
    let mut saw_digit = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_digit() {
            saw_digit = true;
            if !overflowed {
                if let Some(next) = value
                    .checked_mul(10)
                    .and_then(|current| current.checked_add(u64::from(byte - b'0')))
                {
                    value = next;
                } else {
                    overflowed = true;
                }
            }
        } else if byte != b'_'
            || index == 0
            || index + 1 == bytes.len()
            || !bytes[index - 1].is_ascii_digit()
            || !bytes[index + 1].is_ascii_digit()
        {
            return None;
        }
    }

    if !saw_digit {
        return None;
    }
    if negative {
        if !overflowed && value == 0 {
            Some(ParsedInteger::Value(0))
        } else {
            Some(ParsedInteger::Negative)
        }
    } else if overflowed {
        Some(ParsedInteger::PositiveOverflow)
    } else {
        Some(ParsedInteger::Value(value))
    }
}

fn read_offset(run_dir: &Path) -> StoredOffset {
    let mut raw = String::new();
    let path = run_dir.join(".feed-offset");
    if File::open(path)
        .and_then(|mut file| file.read_to_string(&mut raw))
        .is_err()
    {
        return StoredOffset::Value(0);
    }

    match parse_integer(&raw) {
        Some(ParsedInteger::Value(value)) => StoredOffset::Value(value),
        Some(ParsedInteger::PositiveOverflow) => StoredOffset::PositiveOverflow,
        Some(ParsedInteger::Negative) | None => StoredOffset::Value(0),
    }
}

fn open_event_source(run_dir: &Path) -> Result<Option<(File, Metadata)>, FeedError> {
    match File::open(run_dir.join("events.jsonl")) {
        Ok(source) => {
            let metadata = source.metadata().map_err(|_error| FeedError::EventSource)?;
            if metadata.is_file() {
                Ok(Some((source, metadata)))
            } else {
                Err(FeedError::EventSource)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_error) => Err(FeedError::EventSource),
    }
}

fn read_delta(
    config: &Config,
    source: &mut File,
    offset: u64,
    size: u64,
) -> Result<Value, FeedError> {
    let unread = size - offset;
    let truncated = unread > config.cap;
    let start = if truncated { size - config.cap } else { offset };
    let length = if truncated { config.cap } else { unread };
    let length = usize::try_from(length).map_err(|_error| FeedError::EventRead)?;

    source
        .seek(SeekFrom::Start(start))
        .map_err(|_error| FeedError::EventRead)?;
    let mut payload = vec![0_u8; length];
    source
        .read_exact(&mut payload)
        .map_err(|_error| FeedError::EventRead)?;

    Ok(json!({
        "kind": "delta",
        "bytes": length,
        "truncated": truncated,
        "events": parse_event_lines(&payload),
    }))
}

fn parse_event_lines(payload: &[u8]) -> Vec<Value> {
    if payload.is_empty() {
        return Vec::new();
    }

    let mut lines = payload.split(|byte| *byte == b'\n').peekable();
    let mut events = Vec::new();
    while let Some(line) = lines.next() {
        if line.is_empty() && lines.peek().is_none() && payload.ends_with(b"\n") {
            break;
        }
        events.push(
            serde_json::from_slice(line).unwrap_or_else(
                |_error| json!({ "raw": String::from_utf8_lossy(line).into_owned() }),
            ),
        );
    }
    events
}

fn emit_finished_if_ready<W: Write>(
    config: &Config,
    output: &mut W,
    offset: u64,
    cost: &Cost,
) -> Result<PollResult, FeedError> {
    let Some(report) = read_optional_file(
        &config.run_dir.join("run-report.txt"),
        FeedError::ReportRead,
    )?
    else {
        return Ok(PollResult::Pending);
    };
    relay_success_cost(
        config,
        output,
        offset,
        &[finished_record(config, &report)?],
        cost,
    )?;
    Ok(PollResult::Finished)
}

fn finished_record(config: &Config, report: &[u8]) -> Result<Value, FeedError> {
    let last_message = read_optional_file(
        &config.run_dir.join("last-message.txt"),
        FeedError::LastMessageRead,
    )?;
    Ok(json!({
        "kind": "finished",
        "report": String::from_utf8_lossy(report).into_owned(),
        "last_message": last_message
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
    }))
}

fn read_optional_file(path: &Path, class: FeedError) -> Result<Option<Vec<u8>>, FeedError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_error) => return Err(class),
    };
    if !file.metadata().map_err(|_error| class)?.is_file() {
        return Err(class);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_error| class)?;
    Ok(Some(bytes))
}

/// Emit one schema-two failure envelope.
///
/// # Errors
///
/// Returns [`FeedError::Relay`] if stdout rejects any part of the document or
/// its final flush.
pub fn emit_failure_document<W: Write>(
    output: &mut W,
    kind: &str,
    message: &str,
) -> Result<(), FeedError> {
    relay_records(
        output,
        None,
        &[json!({
            "kind": kind,
            "message": message,
        })],
    )
}

fn relay_success_cost<W: Write>(
    config: &Config,
    output: &mut W,
    offset: u64,
    records: &[Value],
    cost: &Cost,
) -> Result<(), FeedError> {
    relay_success_measured(config, output, offset, records, cost, || Ok(()))
}

fn relay_success_measured<W: Write>(
    config: &Config,
    output: &mut W,
    offset: u64,
    records: &[Value],
    cost: &Cost,
    after_flush: impl FnOnce() -> Result<(), FeedError>,
) -> Result<(), FeedError> {
    let state = sample_state_cost(&config.run_dir, offset, cost);
    relay_records(output, Some(&state), records)?;
    after_flush()?;
    Ok(())
}

fn relay_records<W: Write>(
    output: &mut W,
    state: Option<&str>,
    records: &[Value],
) -> Result<(), FeedError> {
    output
        .write_all(b"{\"schema\":2,\"records\":[")
        .map_err(|_error| FeedError::Relay)?;
    if let Some(state) = state {
        output
            .write_all(state.as_bytes())
            .map_err(|_error| FeedError::Relay)?;
    }
    let mut written = state.is_some();
    for record in records {
        if written {
            output.write_all(b",").map_err(|_error| FeedError::Relay)?;
        }
        serde_json::to_writer(&mut *output, record).map_err(|_error| FeedError::Relay)?;
        written = true;
    }
    let suffix = b"]}";
    output
        .write_all(suffix)
        .map_err(|_error| FeedError::Relay)?;
    output.write_all(b"\n").map_err(|_error| FeedError::Relay)?;
    output.flush().map_err(|_error| FeedError::Relay)
}

#[cfg(test)]
fn sample_state(run_dir: &Path, offset: u64) -> String {
    sample_state_cost(run_dir, offset, &Cost::default())
}

fn sample_state_cost(run_dir: &Path, offset: u64, cost: &Cost) -> String {
    let now = SystemTime::now();
    let epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let step = read_trimmed(&run_dir.join(".step-name"));
    let started_at = read_trimmed(&run_dir.join(".started-at"));
    let wall_seconds = started_at
        .as_deref()
        .and_then(parse_utc_instant)
        .map(|start| i128::from(epoch) - i128::from(start));
    let mut state = String::new();
    write!(
        &mut state,
        "{{\"kind\":\"state\",\"at\":{},\"step\":{},\"started_at\":{},\"wall_seconds\":{},\"driver\":",
        json_string(&utc_instant(epoch)),
        json_option(step.as_deref()),
        json_option(started_at.as_deref()),
        wall_seconds.map_or_else(|| String::from("null"), |seconds| seconds.to_string()),
    )
    .expect("writing to a String cannot fail");

    let driver = read_driver(run_dir);
    let monitor = driver.and_then(|(_, pid, _, _)| read_monitor(run_dir, pid));
    if let Some((name, pid, child, driver_alive)) = driver {
        let alive = driver_alive || child.is_some_and(monitor_lock::pid_live_from_proc);
        write!(
            &mut state,
            "{{\"lock\":{},\"pid\":{pid},\"child\":{},\"alive\":{alive}}}",
            json_string(name),
            child.map_or_else(|| String::from("null"), |pid| pid.to_string()),
        )
        .expect("writing to a String cannot fail");
    } else {
        state.push_str("null");
    }

    state.push_str(",\"events\":");
    if let Ok(metadata) = fs::metadata(run_dir.join("events.jsonl")) {
        let age = event_age(
            run_dir,
            now,
            driver.is_some_and(|(_, _, _, alive)| alive),
            monitor.as_ref(),
            &metadata,
        );
        write!(
            &mut state,
            "{{\"bytes\":{},\"age_seconds\":{}}}",
            metadata.len(),
            age.map_or_else(|| String::from("null"), |seconds| seconds.to_string()),
        )
        .expect("writing to a String cannot fail");
    } else {
        state.push_str("null");
    }

    state.push_str(",\"monitor\":");
    if let Some(monitor) = monitor {
        write!(
            &mut state,
            "{{\"quiet\":{},\"wall\":{},\"event_size\":{},\"boot\":{},\"awake\":{},\"awaiting\":{},\"context\":{}",
            monitor.quiet,
            monitor.wall,
            monitor.event_size,
            monitor.boot,
            monitor.awake,
            json_option(monitor.awaiting.as_deref()),
            serde_json::to_string(&monitor.context).expect("serializing context cannot fail"),
        )
        .expect("writing to a String cannot fail");
        if let Some(budget) = &monitor.budget {
            let expiry = budget.expiry.as_ref().map(|expiry| {
                json!({"wall":expiry.wall,"event_size":expiry.event_size,"last_growth":expiry.last_growth,"quiet":expiry.quiet,"state":expiry.state})
            });
            write!(
                &mut state,
                ",\"budget\":{},\"last_growth\":{},\"expiry\":{}",
                budget.seconds,
                budget.last_growth,
                serde_json::to_string(&expiry).expect("serializing expiry cannot fail")
            )
            .expect("writing to a String cannot fail");
            if let Some(growth_state) = &budget.state {
                write!(&mut state, ",\"state\":{}", json_string(growth_state))
                    .expect("writing to a String cannot fail");
            }
        }
        state.push('}');
    } else {
        state.push_str("null");
    }
    write!(
        &mut state,
        ",\"report\":{},\"last_message\":{},\"offset\":{offset},\"cost\":{}}}",
        run_dir.join("run-report.txt").exists(),
        run_dir.join("last-message.txt").exists(),
        cost.value(),
    )
    .expect("writing to a String cannot fail");
    state
}

// Match lane-watch's awake-age upper bound: quiet is measured by lifecycle
// on the awake clock; boot elapsed since publication can overcount a sleep
// only until the producer publishes its next capture.
fn monitor_awake_age(monitor: &MonitorState) -> Option<u64> {
    let uptime = fs::read_to_string("/proc/uptime").ok()?;
    let boot = uptime
        .split_whitespace()
        .next()?
        .split('.')
        .next()?
        .parse::<u64>()
        .ok()?;
    Some(
        monitor
            .quiet
            .saturating_add(boot.checked_sub(monitor.boot)?),
    )
}

fn event_age(
    run_dir: &Path,
    now: SystemTime,
    driver_live: bool,
    monitor: Option<&MonitorState>,
    metadata: &fs::Metadata,
) -> Option<u64> {
    if driver_live
        && !run_dir.join("run-report.txt").exists()
        && let Some(age) = monitor.and_then(monitor_awake_age)
    {
        return Some(age);
    }
    metadata
        .modified()
        .ok()
        .map(|modified| now.duration_since(modified).unwrap_or_default().as_secs())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn json_option(value: Option<&str>) -> String {
    serde_json::to_string(&value).expect("serializing an optional string cannot fail")
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|raw| raw.trim().to_owned())
}

fn read_driver(run_dir: &Path) -> Option<monitor_lock::DriverLock> {
    monitor_lock::select_driver_lock(run_dir, monitor_lock::pid_live_from_proc)
}

struct MonitorState {
    quiet: u64,
    wall: u64,
    event_size: u64,
    boot: u64,
    awake: u64,
    awaiting: Option<String>,
    context: Option<Value>,
    budget: Option<BudgetState>,
}

#[derive(Clone)]
struct BudgetState {
    seconds: u64,
    last_growth: u64,
    state: Option<String>,
    expiry: Option<ExpiryState>,
}

#[derive(Clone)]
struct ExpiryState {
    wall: u64,
    event_size: u64,
    last_growth: u64,
    quiet: u64,
    state: String,
}

fn read_monitor(run_dir: &Path, driver_pid: u32) -> Option<MonitorState> {
    let prefix = format!(".monitor-{driver_pid}-");
    fs::read_dir(run_dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let sequence = name.to_str()?.strip_prefix(&prefix)?.parse::<u64>().ok()?;
            let state = parse_monitor(&fs::read(entry.path()).ok()?).ok()?;
            Some(((state.boot, sequence), state))
        })
        .max_by_key(|(key, _)| *key)
        .map(|(_, state)| state)
}

#[derive(PartialEq, Eq)]
struct BudgetCursor {
    pid: u32,
    step: String,
    budget: u64,
    wall: u64,
    state: String,
}

fn budget_records(
    run_dir: &Path,
    delivered: Option<&BudgetCursor>,
) -> (Vec<Value>, Option<BudgetCursor>) {
    let Some((_, pid, _, _)) = read_driver(run_dir) else {
        return (Vec::new(), None);
    };
    let Some(monitor) = read_monitor(run_dir, pid) else {
        return (Vec::new(), None);
    };
    let Some(budget) = monitor.budget else {
        return (Vec::new(), None);
    };
    let Some(expiry) = budget.expiry else {
        return (Vec::new(), None);
    };
    let Some(state) = budget.state.as_deref() else {
        return (Vec::new(), None);
    };
    let step = read_trimmed(&run_dir.join(".step-name")).unwrap_or_else(|| "-".to_owned());
    let current_cursor = BudgetCursor {
        pid,
        step,
        budget: budget.seconds,
        wall: expiry.wall,
        state: state.to_owned(),
    };
    if delivered == Some(&current_cursor) {
        return (Vec::new(), None);
    }
    let mut records = Vec::new();
    if !delivered.is_some_and(|value| {
        value.pid == current_cursor.pid
            && value.step == current_cursor.step
            && value.budget == current_cursor.budget
            && value.wall == current_cursor.wall
    }) {
        records.push(json!({
        "kind":"budget_expired",
        "budget":budget.seconds,
        "wall":expiry.wall,
        "event_size":expiry.event_size,
        "last_growth":expiry.last_growth,
        "quiet":expiry.quiet,
        "expiry_state":expiry.state,
        "state":state,
        "current_wall":monitor.wall,
        "current_quiet":monitor.quiet,
        "current_last_growth":budget.last_growth,
        }));
    }
    if delivered.is_some()
        && !records
            .iter()
            .any(|record| record["kind"] == "budget_expired")
    {
        records.push(json!({
            "kind":"budget_state",
            "budget":budget.seconds,
            "wall":monitor.wall,
            "state":state,
            "quiet":monitor.quiet,
            "last_growth":budget.last_growth,
            "event_size":monitor.event_size,
        }));
    }
    (records, Some(current_cursor))
}

fn mark_budget_delivered(run_dir: &Path, cursor: Option<&BudgetCursor>) -> Result<(), FeedError> {
    if let Some(cursor) = cursor {
        let path = run_dir.join(".budget-notice");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| FeedError::BudgetNotice)?
            .as_nanos();
        let temporary = run_dir.join(format!(".budget-notice-{}-{stamp}.tmp", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_error| FeedError::BudgetNotice)?;
        file.write_all(
            format!(
                "{} {} {} {} {}\n",
                cursor.pid, cursor.step, cursor.budget, cursor.wall, cursor.state
            )
            .as_bytes(),
        )
        .map_err(|_error| FeedError::BudgetNotice)?;
        file.sync_all().map_err(|_error| FeedError::BudgetNotice)?;
        fs::rename(&temporary, path).map_err(|_error| FeedError::BudgetNotice)?;
        fs::File::open(run_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|_error| FeedError::BudgetNotice)?;
    }
    Ok(())
}

fn read_budget_cursor(run_dir: &Path) -> Result<Option<BudgetCursor>, FeedError> {
    let path = run_dir.join(".budget-notice");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_error) => return Err(FeedError::BudgetNotice),
    };
    if !metadata.file_type().is_file() || metadata.len() > 256 {
        return Err(FeedError::BudgetNotice);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_error| FeedError::BudgetNotice)?;
    if !file
        .metadata()
        .map_err(|_error| FeedError::BudgetNotice)?
        .is_file()
    {
        return Err(FeedError::BudgetNotice);
    }
    let mut bytes = Vec::new();
    file.take(257)
        .read_to_end(&mut bytes)
        .map_err(|_error| FeedError::BudgetNotice)?;
    if bytes.len() > 256 {
        return Err(FeedError::BudgetNotice);
    }
    let line = bytes.strip_suffix(b"\n").ok_or(FeedError::BudgetNotice)?;
    let line = std::str::from_utf8(line).map_err(|_error| FeedError::BudgetNotice)?;
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 5
        || fields[0].parse::<u32>().ok().is_none_or(|pid| pid == 0)
        || fields[1].is_empty()
        || !fields[1]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        || fields[2]
            .parse::<u64>()
            .ok()
            .is_none_or(|budget| budget == 0)
        || fields[3]
            .parse::<u64>()
            .ok()
            .zip(fields[2].parse::<u64>().ok())
            .is_none_or(|(wall, budget)| wall <= budget)
        || !valid_growth_state(fields[4])
    {
        return Err(FeedError::BudgetNotice);
    }
    Ok(Some(BudgetCursor {
        pid: fields[0]
            .parse()
            .map_err(|_error| FeedError::BudgetNotice)?,
        step: fields[1].to_owned(),
        budget: fields[2]
            .parse()
            .map_err(|_error| FeedError::BudgetNotice)?,
        wall: fields[3]
            .parse()
            .map_err(|_error| FeedError::BudgetNotice)?,
        state: fields[4].to_owned(),
    }))
}

// One grammar validates the base line and optional context and budget sections.
#[allow(clippy::too_many_lines)]
fn parse_monitor(bytes: &[u8]) -> Result<MonitorState, &'static str> {
    let line = std::str::from_utf8(bytes.strip_suffix(b"\n").ok_or("monitor-line")?)
        .map_err(|_| "monitor-line")?;
    if line.contains('\n') {
        return Err("monitor-line");
    }
    let mut fields = line.split(' ');
    let mut required = |name: &'static str| {
        fields
            .next()
            .and_then(|field| field.strip_prefix(name))
            .ok_or("monitor-base")
    };
    let quiet = parse_seconds(required("quiet=")?).ok_or("monitor-base")?;
    let wall = parse_seconds(required("wall=")?).ok_or("monitor-base")?;
    let event_size = parse_decimal(required("event_size=")?).ok_or("monitor-base")?;
    let boot = parse_seconds(required("boot=")?).ok_or("monitor-base")?;
    let awake = parse_seconds(required("awake=")?).ok_or("monitor-base")?;
    let mut next = fields.next();
    let awaiting = if let Some(value) = next.and_then(|field| field.strip_prefix("awaiting=")) {
        let (lane_name, seq) = value.rsplit_once(':').ok_or("monitor-awaiting")?;
        if lane_name.is_empty() || parse_decimal(seq).is_none() {
            return Err("monitor-awaiting");
        }
        next = fields.next();
        Some(value.to_owned())
    } else {
        None
    };
    let context = if let Some(state) = next.and_then(|field| field.strip_prefix("context_state=")) {
        let used = fields
            .next()
            .and_then(|field| field.strip_prefix("context_used="))
            .ok_or("monitor-context")?;
        let window = fields
            .next()
            .and_then(|field| field.strip_prefix("context_window="))
            .ok_or("monitor-context")?;
        let fraction = fields
            .next()
            .and_then(|field| field.strip_prefix("context_fraction="))
            .ok_or("monitor-context")?;
        let source = fields
            .next()
            .and_then(|field| field.strip_prefix("context_source="))
            .ok_or("monitor-context")?;
        let reason = fields
            .next()
            .and_then(|field| field.strip_prefix("context_reason="))
            .ok_or("monitor-context")?;
        let turn = fields
            .next()
            .and_then(|field| field.strip_prefix("context_turn="))
            .and_then(parse_decimal)
            .ok_or("monitor-context")?;
        let at = fields
            .next()
            .and_then(|field| field.strip_prefix("context_at="))
            .filter(|value| parse_utc_instant(value).is_some())
            .ok_or("monitor-context")?;
        next = fields.next();
        if ![source, reason].iter().all(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        }) {
            return Err("monitor-context");
        }
        let (used, window, fraction) = match state {
            "unknown" if used == "unknown" && window == "unknown" && fraction == "unknown" => {
                (None, None, None)
            }
            "measured" => {
                let used = parse_decimal(used).ok_or("monitor-context")?;
                let window = parse_decimal(window)
                    .filter(|value| *value > 0)
                    .ok_or("monitor-context")?;
                let fraction = fraction
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite() && *value >= 0.0)
                    .ok_or("monitor-context")?;
                (Some(used), Some(window), Some(fraction))
            }
            _ => return Err("monitor-context"),
        };
        Some(
            json!({"state":state,"used":used,"window":window,"fraction":fraction,"source":source,"reason":reason,"turn":turn,"at":at}),
        )
    } else {
        None
    };
    let budget = if let Some(field) = next {
        let seconds = field
            .strip_prefix("budget=")
            .and_then(parse_seconds)
            .ok_or("monitor-budget")?;
        let last_growth = fields
            .next()
            .and_then(|field| field.strip_prefix("last_growth="))
            .and_then(parse_seconds)
            .filter(|value| *value <= wall)
            .ok_or("monitor-budget")?;
        let mut next = fields.next();
        let state = if let Some(value) = next.and_then(|field| field.strip_prefix("state=")) {
            if !valid_growth_state(value) {
                return Err("monitor-budget");
            }
            next = fields.next();
            Some(value.to_owned())
        } else {
            None
        };
        let expiry = if let Some(field) = next {
            if state.is_none() {
                return Err("monitor-expiry");
            }
            let expired_wall = field
                .strip_prefix("expired_wall=")
                .and_then(parse_seconds)
                .filter(|value| *value > seconds && *value <= wall)
                .ok_or("monitor-expiry")?;
            let expired_event_size = fields
                .next()
                .and_then(|field| field.strip_prefix("expired_event_size="))
                .and_then(parse_decimal)
                .ok_or("monitor-expiry")?;
            let expired_last_growth = fields
                .next()
                .and_then(|field| field.strip_prefix("expired_last_growth="))
                .and_then(parse_seconds)
                .filter(|value| *value <= expired_wall)
                .ok_or("monitor-expiry")?;
            let expired_quiet = fields
                .next()
                .and_then(|field| field.strip_prefix("expired_quiet="))
                .and_then(parse_seconds)
                .filter(|value| *value <= expired_wall)
                .ok_or("monitor-expiry")?;
            let expired_state = fields
                .next()
                .and_then(|field| field.strip_prefix("expired_state="))
                .filter(|value| valid_growth_state(value))
                .ok_or("monitor-expiry")?
                .to_owned();
            Some(ExpiryState {
                wall: expired_wall,
                event_size: expired_event_size,
                last_growth: expired_last_growth,
                quiet: expired_quiet,
                state: expired_state,
            })
        } else {
            None
        };
        Some(BudgetState {
            seconds,
            last_growth,
            state,
            expiry,
        })
    } else {
        None
    };
    if fields.next().is_some() {
        return Err("monitor-budget");
    }
    Ok(MonitorState {
        quiet,
        wall,
        event_size,
        boot,
        awake,
        awaiting,
        context,
        budget,
    })
}

fn valid_growth_state(value: &str) -> bool {
    matches!(value, "growing" | "stalled" | "runaway")
}

fn parse_seconds(value: &str) -> Option<u64> {
    parse_decimal(value.strip_suffix('s')?)
}

fn parse_decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())?
}

fn utc_instant(epoch: u64) -> String {
    let days = epoch / 86_400;
    let (year, month, day) = civil_from_days(days);
    let second = epoch % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second / 3_600,
        (second / 60) % 60,
        second % 60
    )
}

fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (year + u64::from(month <= 2), month, day)
}

fn ensure_offset_target(run_dir: &Path) -> Result<(), FeedError> {
    match std::fs::symlink_metadata(run_dir.join(".feed-offset")) {
        Ok(metadata) if !metadata.is_file() => Err(FeedError::OffsetState),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_error) => Err(FeedError::OffsetState),
    }
}

fn write_offset(run_dir: &Path, offset: u64) -> Result<(), FeedError> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(run_dir.join(".feed-offset"))
        .map_err(|_error| FeedError::OffsetState)?;
    writeln!(file, "{offset}").map_err(|_error| FeedError::OffsetState)?;
    file.flush().map_err(|_error| FeedError::OffsetState)
}

mod entry;

pub(super) use entry::main as command;
