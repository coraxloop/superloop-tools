#![deny(clippy::indexing_slicing)]

//! Read-only reconstruction and rendering of escalation journal events.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::journal::{JournalError, MAX_JOURNAL_RECORD_BYTES, read_journal_bytes, validate_record};
use crate::role::{OPEN_NO_FOLLOW, RegistryError, open_directory_no_follow};

/// Fixed warning shown before any retained command text.
pub const COMMAND_CREDENTIAL_WARNING: &str = "WARNING: command text may contain credentials.";

/// One reconstructed escalation and its optional final disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewEscalation {
    schema: u64,
    event_id: String,
    recorded_at: String,
    tool_use_id: String,
    request_digest: String,
    tool: String,
    cwd: String,
    command: String,
    classification: String,
    reason: String,
    general_rubric_digest: String,
    owner_rubric_digest: Option<String>,
    role: String,
    loop_name: Option<String>,
    stale_session: bool,
    domain_rubric_digest: Option<String>,
    model_status: String,
    scope: Option<String>,
    mode: Option<String>,
    outcome: Option<String>,
    approval_consumed: bool,
    order: usize,
}

impl ReviewEscalation {
    /// Journal event identifier.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// UTC record timestamp.
    #[must_use]
    pub fn recorded_at(&self) -> &str {
        &self.recorded_at
    }

    /// Canonical request-shape digest.
    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Requested tool name.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Request working directory.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Exact retained command or reduced action.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Closed caller role recorded for the request.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Matched loop name for an orchestrator role.
    #[must_use]
    pub fn loop_name(&self) -> Option<&str> {
        self.loop_name.as_deref()
    }

    /// Final owner outcome, or `None` while unadjudicated.
    #[must_use]
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    /// Recorded scope, or `None` for legacy unscoped history.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Recorded hook mode, or `None` for legacy history.
    #[must_use]
    pub fn mode(&self) -> Option<&str> {
        self.mode.as_deref()
    }
}

/// Identical normalized request shapes combined for owner review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewGroup {
    scope: Option<String>,
    role: String,
    loop_name: Option<String>,
    tool: String,
    cwd: String,
    command: String,
    occurrence_count: usize,
    outcomes: Vec<String>,
}

impl ReviewGroup {
    /// Scope shared by this group, absent only for legacy history.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Tool component of the normalized request shape.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Caller role shared by the group.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Matched loop name shared by the group.
    #[must_use]
    pub fn loop_name(&self) -> Option<&str> {
        self.loop_name.as_deref()
    }

    /// Working-directory component of the normalized request shape.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Command component with whitespace runs collapsed.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Number of classifications having this normalized shape.
    #[must_use]
    pub const fn occurrence_count(&self) -> usize {
        self.occurrence_count
    }

    /// Distinct observed outcomes in first-observed order.
    #[must_use]
    pub fn outcomes(&self) -> &[String] {
        &self.outcomes
    }

    /// Candidate owner-rubric Markdown row with explicit owner-filled constraints.
    #[must_use]
    pub fn candidate_row(&self) -> String {
        format!(
            "|<rule-id>|routine-superloop|{}|{}|<alias>|<account>|{}|<path>|<allowed-operands>|<deadline>|<timing>|<forbidden-expansions>|",
            markdown_cell(&self.role),
            markdown_cell(&self.tool),
            markdown_cell(&self.command)
        )
    }
}

/// Fully reconstructed read-only review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    warning_count: usize,
    blank_lines: usize,
    malformed_lines: usize,
    escalations: Vec<ReviewEscalation>,
    groups: Vec<ReviewGroup>,
}

impl Review {
    /// Number of torn trailing records skipped during reconstruction.
    #[must_use]
    pub const fn warning_count(&self) -> usize {
        self.warning_count
    }

    /// Number of blank complete separator lines skipped during reconstruction.
    #[must_use]
    pub const fn blank_lines(&self) -> usize {
        self.blank_lines
    }

    /// Number of malformed complete lines skipped during reconstruction.
    #[must_use]
    pub const fn malformed_lines(&self) -> usize {
        self.malformed_lines
    }

    /// All escalation classifications, oldest first.
    #[must_use]
    pub fn escalations(&self) -> &[ReviewEscalation] {
        &self.escalations
    }

    /// Unadjudicated escalation classifications, oldest first.
    pub fn unadjudicated(&self) -> impl Iterator<Item = &ReviewEscalation> {
        self.escalations
            .iter()
            .filter(|event| event.outcome.is_none())
    }

    /// Stable groups ordered by their oldest occurrence.
    #[must_use]
    pub fn groups(&self) -> &[ReviewGroup] {
        &self.groups
    }

    /// Render the owner-facing review without writing any state.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::new();
        if self.render_into(&mut output).is_err() {
            output.clear();
            output.push_str(COMMAND_CREDENTIAL_WARNING);
            output.push('\n');
        }
        output
    }

    fn render_into(&self, output: &mut String) -> fmt::Result {
        writeln!(output, "{COMMAND_CREDENTIAL_WARNING}")?;
        writeln!(
            output,
            "Torn trailing records skipped: {}",
            self.warning_count
        )?;
        writeln!(
            output,
            "Malformed complete lines skipped: {}",
            self.malformed_lines
        )?;
        writeln!(
            output,
            "Blank separator lines skipped: {}",
            self.blank_lines
        )?;
        output.push_str("\nUnadjudicated escalations (oldest first)\n\n");
        let mut count = 0_usize;
        for event in self.unadjudicated() {
            count += 1;
            writeln!(
                output,
                "- id={} recorded_at={} scope={} mode={} role={} loop={} tool={} cwd={} request_digest={} command={} reason={}",
                event.event_id,
                event.recorded_at,
                event.scope.as_deref().unwrap_or("legacy-unscoped"),
                event.mode.as_deref().unwrap_or("legacy"),
                event.role,
                optional_json_string(event.loop_name.as_deref())?,
                json_string(&event.tool)?,
                json_string(&event.cwd)?,
                event.request_digest,
                json_string(&event.command)?,
                json_string(&event.reason)?
            )?;
        }
        if count == 0 {
            output.push_str("None.\n");
        }

        output.push_str("\nGrouped request shapes\n\n");
        if self.groups.is_empty() {
            output.push_str("None.\n");
        } else {
            for group in &self.groups {
                writeln!(
                    output,
                    "- scope={} role={} loop={} tool={} cwd={} command={} occurrences={} outcomes={}",
                    group.scope.as_deref().unwrap_or("legacy-unscoped"),
                    group.role,
                    optional_json_string(group.loop_name.as_deref())?,
                    json_string(&group.tool)?,
                    json_string(&group.cwd)?,
                    json_string(&group.command)?,
                    group.occurrence_count,
                    group.outcomes.join(",")
                )?;
            }
        }

        output.push_str("\nCandidate owner-rubric rows\n\n");
        output.push_str("|Rule|Class|Role|Tool|Alias|Account|Command grammar|Path root|Allowed operands|Deadline|Timing|Forbidden expansions|\n");
        output.push_str("|----|-----|----|----|-----|-------|---------------|---------|----------------|--------|------|--------------------|\n");
        for group in &self.groups {
            output.push_str(&group.candidate_row());
            output.push('\n');
        }
        Ok(())
    }
}

/// One estate escalation attributed to the registered loop named by its outbox path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxEvent {
    escalation: ReviewEscalation,
    path: PathBuf,
    recorded_loop_name: Option<String>,
    loop_mismatch: bool,
}

impl OutboxEvent {
    /// Parsed escalation with its caller loop corrected from the outbox path.
    #[must_use]
    pub const fn escalation(&self) -> &ReviewEscalation {
        &self.escalation
    }

    /// Path of the immutable event file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the record's loop claim disagreed with the registered directory name.
    #[must_use]
    pub const fn loop_mismatch(&self) -> bool {
        self.loop_mismatch
    }

    /// Loop claimed in the record, before path attribution.
    #[must_use]
    pub fn recorded_loop_name(&self) -> Option<&str> {
        self.recorded_loop_name.as_deref()
    }
}

/// Read-only aggregate of all registered loop outboxes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboxReview {
    events: Vec<OutboxEvent>,
    malformed_files: Vec<PathBuf>,
    absent_directories: Vec<(String, PathBuf)>,
    groups: Vec<ReviewGroup>,
}

impl OutboxReview {
    /// Valid outbox events, oldest first by timestamp and then event identifier.
    #[must_use]
    pub fn events(&self) -> &[OutboxEvent] {
        &self.events
    }

    /// Files skipped because they were unsafe, malformed, or not one complete escalation line.
    #[must_use]
    pub fn malformed_files(&self) -> &[PathBuf] {
        &self.malformed_files
    }

    /// Registered outbox directories that have not yet been provisioned.
    #[must_use]
    pub fn absent_directories(&self) -> &[(String, PathBuf)] {
        &self.absent_directories
    }

    /// Request shapes grouped by the path's caller loop, role, tool, and working directory.
    #[must_use]
    pub fn groups(&self) -> &[ReviewGroup] {
        &self.groups
    }

    /// Render the outbox section beside an estate journal review.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::new();
        if self.render_into(&mut output).is_err() {
            output.clear();
            output.push_str("Outbox review rendering failed.\n");
        }
        output
    }

    fn render_into(&self, output: &mut String) -> fmt::Result {
        output.push_str("\nOutbox events (oldest first)\n\n");
        writeln!(output, "Absent outboxes: {}", self.absent_directories.len())?;
        for (name, path) in &self.absent_directories {
            writeln!(
                output,
                "- absent loop={} path={}",
                json_string(name)?,
                path.display()
            )?;
        }
        writeln!(
            output,
            "Malformed outbox files skipped: {}",
            self.malformed_files.len()
        )?;
        for path in &self.malformed_files {
            writeln!(output, "- malformed path={}", path.display())?;
        }
        if self.events.is_empty() {
            output.push_str("None.\n");
        }
        for item in &self.events {
            let event = &item.escalation;
            write!(
                output,
                "- id={} recorded_at={} caller_loop={} role={} tool={} cwd={} command={} path={}",
                event.event_id,
                event.recorded_at,
                optional_json_string(event.loop_name.as_deref())?,
                event.role,
                json_string(&event.tool)?,
                json_string(&event.cwd)?,
                json_string(&event.command)?,
                item.path.display()
            )?;
            if item.loop_mismatch {
                write!(
                    output,
                    " loop_name_mismatch=record:{}",
                    optional_json_string(item.recorded_loop_name.as_deref())?
                )?;
            }
            output.push('\n');
        }
        if !self.events.is_empty() {
            output.push_str("Outbox events cannot be marked in this bite.\n");
        }
        output.push_str("\nGrouped outbox request shapes\n\n");
        if self.groups.is_empty() {
            output.push_str("None.\n");
        }
        let mut caller_loops: Vec<&str> = Vec::new();
        for item in &self.events {
            if let Some(name) = item.escalation.loop_name.as_deref()
                && !caller_loops.contains(&name)
            {
                caller_loops.push(name);
            }
        }
        for name in &caller_loops {
            writeln!(output, "Caller loop: {}", json_string(name)?)?;
            for group in self
                .groups
                .iter()
                .filter(|group| group.loop_name.as_deref() == Some(*name))
            {
                writeln!(
                    output,
                    "- scope={} role={} tool={} cwd={} command={} occurrences={} outcomes={}",
                    group.scope.as_deref().unwrap_or("legacy-unscoped"),
                    group.role,
                    json_string(&group.tool)?,
                    json_string(&group.cwd)?,
                    json_string(&group.command)?,
                    group.occurrence_count,
                    group.outcomes.join(",")
                )?;
            }
        }
        output.push_str("\nCandidate owner-rubric rows for outbox events\n\n");
        if caller_loops.is_empty() {
            output.push_str("None.\n");
        }
        for name in &caller_loops {
            writeln!(output, "Caller loop: {}\n", json_string(name)?)?;
            output.push_str("|Rule|Class|Role|Tool|Alias|Account|Command grammar|Path root|Allowed operands|Deadline|Timing|Forbidden expansions|\n");
            output.push_str("|----|-----|----|----|-----|-------|---------------|---------|----------------|--------|------|--------------------|\n");
            for group in self
                .groups
                .iter()
                .filter(|group| group.loop_name.as_deref() == Some(*name))
            {
                writeln!(output, "{}", group.candidate_row())?;
            }
            output.push('\n');
        }
        Ok(())
    }
}

/// Failure while reading or correlating an event stream.
#[derive(Debug)]
pub enum ReviewError {
    /// The private journal could not be read safely.
    Journal(JournalError),
    /// A registered outbox directory could not be opened or enumerated safely.
    OutboxUnavailable {
        /// Registered outbox directory.
        path: PathBuf,
        /// Filesystem or path-shape failure.
        detail: String,
    },
    /// A complete line was not valid JSON.
    Parse(serde_json::Error),
    /// A complete line did not match the journal schema.
    RecordShape(&'static str),
    /// More than one escalation used the same event identifier.
    DuplicateEscalation,
    /// A disposition did not correlate to an escalation classification.
    OrphanDisposition,
    /// More than one disposition was recorded for an escalation.
    DuplicateDisposition,
    /// A correlated disposition contradicted its classification event.
    CorrelationMismatch,
    /// An approval consumption did not correlate to an escalation.
    OrphanConsumption,
    /// More than one request consumed the same approval.
    DuplicateConsumption,
    /// A consumption did not match an approved request.
    ConsumptionMismatch,
}

impl fmt::Display for ReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "{error}"),
            Self::OutboxUnavailable { path, detail } => {
                write!(formatter, "outbox {} unavailable: {detail}", path.display())
            }
            Self::Parse(error) => write!(formatter, "journal record JSON is malformed: {error}"),
            Self::RecordShape(detail) => write!(formatter, "journal record is invalid: {detail}"),
            Self::DuplicateEscalation => {
                write!(
                    formatter,
                    "journal event identifier has multiple escalations"
                )
            }
            Self::OrphanDisposition => write!(formatter, "journal disposition has no escalation"),
            Self::DuplicateDisposition => {
                write!(formatter, "journal escalation has multiple dispositions")
            }
            Self::CorrelationMismatch => {
                write!(
                    formatter,
                    "journal disposition does not match its escalation"
                )
            }
            Self::OrphanConsumption => {
                write!(formatter, "journal approval consumption has no escalation")
            }
            Self::DuplicateConsumption => {
                write!(formatter, "journal approval was consumed more than once")
            }
            Self::ConsumptionMismatch => {
                write!(
                    formatter,
                    "journal approval consumption does not match its escalation"
                )
            }
        }
    }
}

impl std::error::Error for ReviewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::OutboxUnavailable { .. }
            | Self::RecordShape(_)
            | Self::DuplicateEscalation
            | Self::OrphanDisposition
            | Self::DuplicateDisposition
            | Self::CorrelationMismatch
            | Self::OrphanConsumption
            | Self::DuplicateConsumption
            | Self::ConsumptionMismatch => None,
        }
    }
}

impl From<JournalError> for ReviewError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

/// Load and reconstruct the journal below one explicit state root.
///
/// # Errors
///
/// Returns an error if the state root is unsafe or valid records cannot be correlated.
pub fn load_review(state_root: &Path) -> Result<Review, ReviewError> {
    let bytes = read_journal_bytes(state_root)?;
    review_from_bytes(&bytes)
}

/// Review the stream selected from a registered loop and closed scope.
///
/// # Errors
///
/// Rejects unsafe journal files and invalid event correlations.
pub fn load_selected_review(
    journal: &crate::journal::ReviewJournal,
) -> Result<Review, ReviewError> {
    review_from_bytes(&journal.read()?)
}

/// Read every registered loop's outbox without following a directory or event-file symlink.
///
/// A missing directory is listed as absent. Unsafe or malformed event files are named and
/// skipped, while an unopenable or unenumerable directory fails the review.
///
/// # Errors
///
/// Returns an error when a registered path is not its named directory or its directory cannot
/// be opened and enumerated safely.
pub fn load_outbox_review(outboxes: &[(String, PathBuf)]) -> Result<OutboxReview, ReviewError> {
    let mut review = OutboxReview::default();
    for (registered_name, path) in outboxes {
        let caller_loop = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            ReviewError::OutboxUnavailable {
                path: path.clone(),
                detail: "outbox path has no Unicode loop-name component".to_owned(),
            }
        })?;
        if caller_loop != registered_name {
            return Err(ReviewError::OutboxUnavailable {
                path: path.clone(),
                detail: "outbox path does not end in its registered loop name".to_owned(),
            });
        }
        let directory = match open_directory_no_follow(path) {
            Ok(directory) => directory,
            Err(RegistryError::DirectoryMetadata(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                review
                    .absent_directories
                    .push((registered_name.clone(), path.clone()));
                continue;
            }
            Err(error) => {
                return Err(ReviewError::OutboxUnavailable {
                    path: path.clone(),
                    detail: error.to_string(),
                });
            }
        };
        let anchored = PathBuf::from("/proc/self/fd").join(directory.as_raw_fd().to_string());
        let entries = fs::read_dir(&anchored).map_err(|error| ReviewError::OutboxUnavailable {
            path: path.clone(),
            detail: error.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| ReviewError::OutboxUnavailable {
                path: path.clone(),
                detail: error.to_string(),
            })?;
            let file_name = entry.file_name();
            let event_path = path.join(&file_name);
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_NO_FOLLOW)
                .open(anchored.join(&file_name));
            let parsed = file
                .map_err(|_error| ())
                .and_then(|file| parse_outbox_file(file, &file_name, review.events.len()));
            let mut escalation = match parsed {
                Ok(Some(escalation)) => escalation,
                Ok(None) => continue,
                Err(()) => {
                    review.malformed_files.push(event_path);
                    continue;
                }
            };
            let recorded_loop_name = escalation.loop_name.clone();
            let loop_mismatch = recorded_loop_name.as_deref() != Some(caller_loop);
            escalation.loop_name = Some(caller_loop.to_owned());
            review.events.push(OutboxEvent {
                escalation,
                path: event_path,
                recorded_loop_name,
                loop_mismatch,
            });
        }
    }
    review.events.sort_by(|left, right| {
        left.escalation
            .recorded_at
            .cmp(&right.escalation.recorded_at)
            .then(left.escalation.event_id.cmp(&right.escalation.event_id))
            .then(left.path.cmp(&right.path))
    });
    review.malformed_files.sort();
    review.groups = group_escalations(
        &review
            .events
            .iter()
            .map(|item| item.escalation.clone())
            .collect::<Vec<_>>(),
    );
    Ok(review)
}

fn parse_outbox_file(
    file: File,
    filename: &OsStr,
    order: usize,
) -> Result<Option<ReviewEscalation>, ()> {
    let name = filename.to_str().ok_or(())?;
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(());
    }
    let metadata = file.metadata().map_err(|_error| ())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o7777 != 0o644 {
        return Err(());
    }
    let mut bytes = Vec::new();
    let mut limited = file.take(MAX_JOURNAL_RECORD_BYTES as u64 + 1);
    limited.read_to_end(&mut bytes).map_err(|_error| ())?;
    if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
        return Err(());
    }
    let line = bytes.strip_suffix(b"\n").ok_or(())?;
    if line.contains(&b'\n') {
        return Err(());
    }
    match parse_line(line, order).map_err(|_error| ())? {
        ParsedLine::Escalation(escalation)
            if escalation.scope.as_deref() == Some("estate")
                && filename == OsStr::new(escalation.event_id.as_str()) =>
        {
            Ok(Some(escalation))
        }
        ParsedLine::Ignored => {
            let value: Value = serde_json::from_slice(line).map_err(|_error| ())?;
            if value.get("scope").and_then(Value::as_str) == Some("estate")
                && value
                    .get("event_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| filename == OsStr::new(id))
            {
                Ok(None)
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

/// Reconstruct an event stream from bytes without performing filesystem access.
///
/// A nonempty final line without a newline is treated as torn, skipped, and counted once. A
/// blank or malformed complete line is also skipped and counted without affecting valid records.
///
/// # Errors
///
/// Returns an error if valid events have duplicate identifiers or cannot be correlated.
pub fn review_from_bytes(bytes: &[u8]) -> Result<Review, ReviewError> {
    let warning_count = usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n"));
    let mut blank_lines = 0_usize;
    let mut malformed_lines = 0_usize;
    let mut escalations = Vec::new();
    let mut dispositions = Vec::new();
    let mut consumptions = Vec::new();
    for (order, line) in complete_lines(bytes).enumerate() {
        if line.is_empty() {
            blank_lines += 1;
            continue;
        }
        match parse_line(line, order) {
            Ok(ParsedLine::Escalation(escalation)) => escalations.push(escalation),
            Ok(ParsedLine::Disposition(disposition)) => dispositions.push(disposition),
            Ok(ParsedLine::Consumption(consumption)) => consumptions.push(consumption),
            Ok(ParsedLine::Ignored) => {}
            Err(ReviewError::Parse(_) | ReviewError::RecordShape(_)) => malformed_lines += 1,
            Err(error) => return Err(error),
        }
    }

    escalations.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then(left.order.cmp(&right.order))
    });
    let mut event_ids = HashSet::with_capacity(escalations.len());
    for escalation in &escalations {
        if !event_ids.insert(escalation.event_id.as_str()) {
            return Err(ReviewError::DuplicateEscalation);
        }
    }
    for disposition in dispositions {
        let Some(escalation) = escalations
            .iter_mut()
            .find(|event| event.event_id == disposition.event_id)
        else {
            return Err(ReviewError::OrphanDisposition);
        };
        if escalation.outcome.is_some() {
            return Err(ReviewError::DuplicateDisposition);
        }
        if !disposition.matches(escalation) {
            return Err(ReviewError::CorrelationMismatch);
        }
        escalation.outcome = Some(disposition.outcome);
    }
    for consumption in consumptions {
        let Some(escalation) = escalations
            .iter_mut()
            .find(|event| event.event_id == consumption.event_id)
        else {
            return Err(ReviewError::OrphanConsumption);
        };
        if escalation.approval_consumed {
            return Err(ReviewError::DuplicateConsumption);
        }
        if escalation.outcome.as_deref() != Some("adjudicated-approved")
            || !consumption.matches(escalation)
        {
            return Err(ReviewError::ConsumptionMismatch);
        }
        escalation.approval_consumed = true;
    }
    let groups = group_escalations(&escalations);
    Ok(Review {
        warning_count,
        blank_lines,
        malformed_lines,
        escalations,
        groups,
    })
}

enum ParsedLine {
    Escalation(ReviewEscalation),
    Disposition(ParsedDisposition),
    Consumption(ParsedConsumption),
    Ignored,
}

fn parse_line(line: &[u8], order: usize) -> Result<ParsedLine, ReviewError> {
    let value: Value = serde_json::from_slice(line).map_err(ReviewError::Parse)?;
    if crate::requests::metadata(&value)
        .map_err(|_| ReviewError::RecordShape("invalid request collection"))?
        .is_some()
    {
        return Ok(ParsedLine::Ignored);
    }
    let object = value
        .as_object()
        .ok_or(ReviewError::RecordShape("top level is not an object"))?;
    validate_record(object).map_err(|error| match error {
        JournalError::RecordShape(detail) => ReviewError::RecordShape(detail),
        _ => ReviewError::RecordShape("journal validation failed"),
    })?;
    if !crate::evidence::valid_recorded_at(string_field(object, "recorded_at")?) {
        return Err(ReviewError::RecordShape(
            "recorded_at must be a calendar-valid UTC YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ timestamp",
        ));
    }
    match string_field(object, "event")? {
        "escalated" => parse_escalation(object, order).map(ParsedLine::Escalation),
        "disposition" => parse_disposition(object).map(ParsedLine::Disposition),
        "approval-consumed" => parse_consumption(object).map(ParsedLine::Consumption),
        "verdict" => Ok(ParsedLine::Ignored),
        _ => Err(ReviewError::RecordShape(
            "event field is outside the vocabulary",
        )),
    }
}

#[derive(Clone, Debug)]
struct ParsedDisposition {
    schema: u64,
    event_id: String,
    request_digest: String,
    tool_use_id: String,
    tool: String,
    cwd: String,
    command: String,
    classification: String,
    general_rubric_digest: String,
    owner_rubric_digest: Option<String>,
    role: String,
    loop_name: Option<String>,
    stale_session: bool,
    domain_rubric_digest: Option<String>,
    outcome: String,
    scope: Option<String>,
    mode: Option<String>,
    adjudicator_role: Option<String>,
    adjudicator_loop_name: Option<String>,
}

impl ParsedDisposition {
    fn matches(&self, event: &ReviewEscalation) -> bool {
        let digest_matches =
            self.outcome == "corrected-and-rerun" || self.request_digest == event.request_digest;
        digest_matches
            && (self.scope.as_deref() != Some("loop")
                || (self.adjudicator_role.as_deref() == Some("orchestrator")
                    && self.adjudicator_loop_name == event.loop_name))
            && self.schema == event.schema
            && self.tool_use_id == event.tool_use_id
            && self.tool == event.tool
            && self.cwd == event.cwd
            && self.command == event.command
            && self.classification == event.classification
            && self.general_rubric_digest == event.general_rubric_digest
            && self.owner_rubric_digest == event.owner_rubric_digest
            && self.role == event.role
            && self.loop_name == event.loop_name
            && self.stale_session == event.stale_session
            && self.domain_rubric_digest == event.domain_rubric_digest
            && self.scope == event.scope
            && self.mode == event.mode
    }
}

#[derive(Clone, Debug)]
struct ParsedConsumption {
    schema: u64,
    event_id: String,
    request_digest: String,
    tool: String,
    cwd: String,
    command: String,
    role: String,
    loop_name: Option<String>,
    scope: Option<String>,
    general_rubric_digest: String,
    owner_rubric_digest: Option<String>,
    domain_rubric_digest: Option<String>,
}

impl ParsedConsumption {
    fn matches(&self, event: &ReviewEscalation) -> bool {
        self.request_digest == event.request_digest
            && self.schema == event.schema
            && self.tool == event.tool
            && self.cwd == event.cwd
            && self.command == event.command
            && self.role == event.role
            && self.loop_name == event.loop_name
            && self.scope == event.scope
            && self.general_rubric_digest == event.general_rubric_digest
            && self.owner_rubric_digest == event.owner_rubric_digest
            && self.domain_rubric_digest == event.domain_rubric_digest
    }
}

fn parse_escalation(
    object: &Map<String, Value>,
    order: usize,
) -> Result<ReviewEscalation, ReviewError> {
    if object.contains_key("outcome") {
        return Err(ReviewError::RecordShape(
            "escalation classification contains outcome",
        ));
    }
    if string_field(object, "classification")? != "suspicious" {
        return Err(ReviewError::RecordShape(
            "escalation classification is not suspicious",
        ));
    }
    let schema = u64_field(object, "schema")?;
    Ok(ReviewEscalation {
        schema,
        event_id: string_field(object, "event_id")?.to_owned(),
        recorded_at: string_field(object, "recorded_at")?.to_owned(),
        tool_use_id: string_field(object, "tool_use_id")?.to_owned(),
        request_digest: string_field(object, "request_digest")?.to_owned(),
        tool: string_field(object, "tool")?.to_owned(),
        cwd: string_field(object, "cwd")?.to_owned(),
        command: string_field(object, "command")?.to_owned(),
        classification: string_field(object, "classification")?.to_owned(),
        reason: string_field(object, "reason")?.to_owned(),
        general_rubric_digest: string_field(object, "general_rubric_digest")?.to_owned(),
        owner_rubric_digest: optional_string_field(object, "owner_rubric_digest")?,
        role: string_field(object, "role")?.to_owned(),
        loop_name: optional_string_field(object, "loop_name")?,
        stale_session: bool_field(object, "stale_session")?,
        domain_rubric_digest: optional_string_field(object, "domain_rubric_digest")?,
        model_status: string_field(object, "model_status")?.to_owned(),
        scope: schema_2_optional_string(object, schema, "scope")?,
        mode: schema_2_optional_string(object, schema, "mode")?,
        outcome: None,
        approval_consumed: false,
        order,
    })
}

fn parse_disposition(object: &Map<String, Value>) -> Result<ParsedDisposition, ReviewError> {
    let outcome = string_field(object, "outcome")?;
    let schema = u64_field(object, "schema")?;
    if !matches!(
        outcome,
        "adjudicated-rule-added"
            | "adjudicated-rejected"
            | "corrected-and-rerun"
            | "adjudicated-approved"
    ) {
        return Err(ReviewError::RecordShape(
            "outcome field is outside the vocabulary",
        ));
    }
    Ok(ParsedDisposition {
        schema,
        adjudicator_role: schema_2_optional_string(object, schema, "adjudicator_role")?,
        adjudicator_loop_name: if schema == 2 {
            optional_string_field(object, "adjudicator_loop_name")?
        } else {
            None
        },
        event_id: string_field(object, "event_id")?.to_owned(),
        request_digest: string_field(object, "request_digest")?.to_owned(),
        tool_use_id: string_field(object, "tool_use_id")?.to_owned(),
        tool: string_field(object, "tool")?.to_owned(),
        cwd: string_field(object, "cwd")?.to_owned(),
        command: string_field(object, "command")?.to_owned(),
        classification: string_field(object, "classification")?.to_owned(),
        general_rubric_digest: string_field(object, "general_rubric_digest")?.to_owned(),
        owner_rubric_digest: optional_string_field(object, "owner_rubric_digest")?,
        role: string_field(object, "role")?.to_owned(),
        loop_name: optional_string_field(object, "loop_name")?,
        stale_session: bool_field(object, "stale_session")?,
        domain_rubric_digest: optional_string_field(object, "domain_rubric_digest")?,
        outcome: outcome.to_owned(),
        scope: schema_2_optional_string(object, schema, "scope")?,
        mode: schema_2_optional_string(object, schema, "mode")?,
    })
}

fn parse_consumption(object: &Map<String, Value>) -> Result<ParsedConsumption, ReviewError> {
    let schema = u64_field(object, "schema")?;
    let classification = string_field(object, "classification")?;
    if object.contains_key("outcome")
        || (schema == 1 && classification != "adjudicated-approved")
        || (schema == 2 && classification != "routine-superloop")
        || string_field(object, "model_status")? != "journal-approval"
    {
        return Err(ReviewError::RecordShape(
            "approval consumption shape is invalid",
        ));
    }
    Ok(ParsedConsumption {
        schema,
        general_rubric_digest: string_field(object, "general_rubric_digest")?.to_owned(),
        owner_rubric_digest: optional_string_field(object, "owner_rubric_digest")?,
        domain_rubric_digest: optional_string_field(object, "domain_rubric_digest")?,
        event_id: string_field(object, "event_id")?.to_owned(),
        request_digest: string_field(object, "request_digest")?.to_owned(),
        tool: string_field(object, "tool")?.to_owned(),
        cwd: string_field(object, "cwd")?.to_owned(),
        command: string_field(object, "command")?.to_owned(),
        role: string_field(object, "role")?.to_owned(),
        loop_name: optional_string_field(object, "loop_name")?,
        scope: schema_2_optional_string(object, schema, "source_scope")?,
    })
}

fn u64_field(object: &Map<String, Value>, field: &'static str) -> Result<u64, ReviewError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ReviewError::RecordShape(field))
}

fn schema_2_optional_string(
    object: &Map<String, Value>,
    schema: u64,
    field: &'static str,
) -> Result<Option<String>, ReviewError> {
    if schema == 1 {
        Ok(None)
    } else {
        string_field(object, field).map(|value| Some(value.to_owned()))
    }
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ReviewError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ReviewError::RecordShape(field))
}

fn optional_string_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, ReviewError> {
    match object.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(ReviewError::RecordShape(field)),
    }
}

fn bool_field(object: &Map<String, Value>, field: &'static str) -> Result<bool, ReviewError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(ReviewError::RecordShape(field))
}

fn complete_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_suffix(b"\n"))
}

fn group_escalations(escalations: &[ReviewEscalation]) -> Vec<ReviewGroup> {
    let mut groups: Vec<ReviewGroup> = Vec::new();
    for event in escalations {
        let command = collapse_whitespace(&event.command);
        let outcome = event
            .outcome
            .as_deref()
            .map_or("escalated", |outcome| outcome);
        if let Some(group) = groups.iter_mut().find(|group| {
            group.scope == event.scope
                && group.role == event.role
                && group.loop_name == event.loop_name
                && group.tool == event.tool
                && group.cwd == event.cwd
                && group.command == command
        }) {
            group.occurrence_count += 1;
            if !group.outcomes.iter().any(|observed| observed == outcome) {
                group.outcomes.push(outcome.to_owned());
            }
        } else {
            groups.push(ReviewGroup {
                scope: event.scope.clone(),
                role: event.role.clone(),
                loop_name: event.loop_name.clone(),
                tool: event.tool.clone(),
                cwd: event.cwd.clone(),
                command,
                occurrence_count: 1,
                outcomes: vec![outcome.to_owned()],
            });
        }
    }
    groups
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn markdown_cell(value: &str) -> String {
    collapse_whitespace(value)
        .replace('\\', "\\\\")
        .replace('|', "\\|")
}

fn json_string(value: &str) -> Result<String, fmt::Error> {
    serde_json::to_string(value).map_err(|_error| fmt::Error)
}

fn optional_json_string(value: Option<&str>) -> Result<String, fmt::Error> {
    value.map_or_else(|| Ok("null".to_owned()), json_string)
}
