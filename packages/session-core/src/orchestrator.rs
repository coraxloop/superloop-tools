use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef as _;
use serde_json::{Map, Number, Value};

use crate::orchestrator_toggle::flags;
use crate::project_root;
use crate::sha256::digest_hex;
use std::env;
use std::ffi::OsString;
pub const MAX_RULEBOOK_BYTES: usize = 9_500;

const SESSIONSTART_GRACE_SECONDS: f64 = 5.0;
const MARKER_PREFIX: &str = "ORCHESTRATION_SCOPE_MARKER v1 sha256=";
const SLOW_RUN: Duration = Duration::from_millis(250);

/// One input class in the orchestration-injection graph.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventClass {
    Malformed,
    Unsupported,
    Fresh,
    Resumed,
    Tracked,
}

impl EventClass {
    const fn mask(self) -> u8 {
        match self {
            Self::Malformed => 1,
            Self::Unsupported => 2,
            Self::Fresh => 4,
            Self::Resumed => 8,
            Self::Tracked => 16,
        }
    }

    /// All event classes used by totality tests.
    pub const ALL: [Self; 5] = [
        Self::Malformed,
        Self::Unsupported,
        Self::Fresh,
        Self::Resumed,
        Self::Tracked,
    ];

    const ALL_MASK: u8 = 31;
}

/// A specification-named graph state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum State {
    Entry,
    DisableCheck,
    Disabled,
    AudienceCheck,
    RefusedAudience,
    RulebookGuard,
    RefusedRulebook,
    EventClass,
    Fresh,
    Resumed,
    Tracked,
    Changed,
    Present,
    Deduped,
    InjectFull,
    Rotate,
    Snapshot,
    StateWrite,
    Notice,
    RefreshState,
    RefreshSnapshotState,
    Log,
    RefusedEvent,
    FailOpen,
    LogClassIfPossible,
    AllowEmpty,
    AllowContext,
}

impl State {
    /// Complete state inventory used for graph reachability evidence.
    pub const ALL: [Self; 27] = [
        Self::Entry,
        Self::DisableCheck,
        Self::Disabled,
        Self::AudienceCheck,
        Self::RefusedAudience,
        Self::RulebookGuard,
        Self::RefusedRulebook,
        Self::EventClass,
        Self::Fresh,
        Self::Resumed,
        Self::Tracked,
        Self::Changed,
        Self::Present,
        Self::Deduped,
        Self::InjectFull,
        Self::Rotate,
        Self::Snapshot,
        Self::StateWrite,
        Self::Notice,
        Self::RefreshState,
        Self::RefreshSnapshotState,
        Self::Log,
        Self::RefusedEvent,
        Self::FailOpen,
        Self::LogClassIfPossible,
        Self::AllowEmpty,
        Self::AllowContext,
    ];

    /// Whether this state is a terminal semantic verdict.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::AllowEmpty | Self::AllowContext)
    }
}

/// A graph edge predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Guard {
    InternalError,
    FailureContinuation,
    Malformed,
    Unsupported,
    Accepted,
    Disabled,
    Enabled,
    RefusedAudience,
    AcceptedAudience,
    RulebookRefused,
    RulebookAccepted,
    IsFresh,
    IsResumed,
    IsTracked,
    InvalidEventClass,
    FreshReadRefused,
    FreshDuplicate,
    FreshNew,
    NotFresh,
    ResumedReadRefused,
    ResumedDuplicate,
    ResumedNeedsFull,
    ResumedWitnessPresent,
    NotResumed,
    TrackedAbsentReadRefused,
    TrackedAbsentDuplicate,
    TrackedAbsentNew,
    TrackedMtimeEqual,
    TrackedMtimeChanged,
    NotTracked,
    ChangedReadRefused,
    ChangedDigestEqual,
    ChangedDuplicate,
    ChangedNew,
    NotChanged,
    PresentNeedsRefresh,
    PresentCurrent,
    PhaseFull,
    PhaseNotice,
    PhaseOther,
    LogAllowsContext,
    LogAllowsEmpty,
    Always,
}

/// One ordered persistence or logging effect named by a graph edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    LoadState,
    PrepareFull,
    MarkPresentRefresh,
    PrepareNotice,
    RotateSnapshot,
    WriteSnapshot,
    WriteState,
    RefreshState,
    RefreshSnapshotState,
    AppendPlannedLog,
    AppendInternalLog,
}

/// Edge data used directly by [`DiGraph`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    /// Exclusive predicate selecting this edge.
    pub guard: Guard,
    /// Ordered effects executed before reaching the destination.
    pub effects: &'static [Effect],
    event_mask: u8,
}

impl Transition {
    /// Whether this edge participates in totality for an event class.
    #[must_use]
    pub const fn covers(&self, event: EventClass) -> bool {
        self.event_mask & event.mask() != 0
    }
}

/// Build the injection machine directly as a petgraph directed graph.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn injection_graph() -> DiGraph<State, Transition> {
    let mut graph = DiGraph::new();
    let nodes = State::ALL
        .into_iter()
        .map(|state| (state, graph.add_node(state)))
        .collect::<HashMap<_, _>>();
    let all = EventClass::ALL_MASK;
    let fresh = EventClass::Fresh.mask();
    let resumed = EventClass::Resumed.mask();
    let tracked = EventClass::Tracked.mask();
    let invalid = EventClass::Malformed.mask() | EventClass::Unsupported.mask();

    let mut add = |from, to, guard, effects, event_mask| {
        graph.add_edge(
            nodes[&from],
            nodes[&to],
            Transition {
                guard,
                effects,
                event_mask,
            },
        );
    };

    add(
        State::Entry,
        State::FailOpen,
        Guard::Malformed,
        &[],
        EventClass::Malformed.mask(),
    );
    add(
        State::Entry,
        State::RefusedEvent,
        Guard::Unsupported,
        &[],
        EventClass::Unsupported.mask(),
    );
    add(
        State::Entry,
        State::DisableCheck,
        Guard::Accepted,
        &[],
        fresh | resumed | tracked,
    );
    add(
        State::DisableCheck,
        State::Disabled,
        Guard::Disabled,
        &[],
        all,
    );
    add(
        State::DisableCheck,
        State::AudienceCheck,
        Guard::Enabled,
        &[],
        all,
    );
    add(
        State::AudienceCheck,
        State::RefusedAudience,
        Guard::RefusedAudience,
        &[],
        all,
    );
    add(
        State::AudienceCheck,
        State::RulebookGuard,
        Guard::AcceptedAudience,
        &[],
        all,
    );
    add(
        State::RulebookGuard,
        State::RefusedRulebook,
        Guard::RulebookRefused,
        &[],
        all,
    );
    add(
        State::RulebookGuard,
        State::EventClass,
        Guard::RulebookAccepted,
        &[Effect::LoadState],
        all,
    );
    add(State::EventClass, State::Fresh, Guard::IsFresh, &[], fresh);
    add(
        State::EventClass,
        State::Resumed,
        Guard::IsResumed,
        &[],
        resumed,
    );
    add(
        State::EventClass,
        State::Tracked,
        Guard::IsTracked,
        &[],
        tracked,
    );
    add(
        State::EventClass,
        State::FailOpen,
        Guard::InvalidEventClass,
        &[],
        invalid,
    );

    add(
        State::Fresh,
        State::RefusedRulebook,
        Guard::FreshReadRefused,
        &[],
        fresh,
    );
    add(
        State::Fresh,
        State::Deduped,
        Guard::FreshDuplicate,
        &[],
        fresh,
    );
    add(
        State::Fresh,
        State::InjectFull,
        Guard::FreshNew,
        &[Effect::PrepareFull],
        fresh,
    );
    add(
        State::Fresh,
        State::FailOpen,
        Guard::NotFresh,
        &[],
        all ^ fresh,
    );

    add(
        State::Resumed,
        State::RefusedRulebook,
        Guard::ResumedReadRefused,
        &[],
        resumed,
    );
    add(
        State::Resumed,
        State::Deduped,
        Guard::ResumedDuplicate,
        &[],
        resumed,
    );
    add(
        State::Resumed,
        State::InjectFull,
        Guard::ResumedNeedsFull,
        &[Effect::PrepareFull],
        resumed,
    );
    add(
        State::Resumed,
        State::Present,
        Guard::ResumedWitnessPresent,
        &[Effect::MarkPresentRefresh],
        resumed,
    );
    add(
        State::Resumed,
        State::FailOpen,
        Guard::NotResumed,
        &[],
        all ^ resumed,
    );

    add(
        State::Tracked,
        State::RefusedRulebook,
        Guard::TrackedAbsentReadRefused,
        &[],
        tracked,
    );
    add(
        State::Tracked,
        State::Deduped,
        Guard::TrackedAbsentDuplicate,
        &[],
        tracked,
    );
    add(
        State::Tracked,
        State::InjectFull,
        Guard::TrackedAbsentNew,
        &[Effect::PrepareFull],
        tracked,
    );
    add(
        State::Tracked,
        State::Present,
        Guard::TrackedMtimeEqual,
        &[],
        tracked,
    );
    add(
        State::Tracked,
        State::Changed,
        Guard::TrackedMtimeChanged,
        &[],
        tracked,
    );
    add(
        State::Tracked,
        State::FailOpen,
        Guard::NotTracked,
        &[],
        all ^ tracked,
    );

    add(
        State::Changed,
        State::RefusedRulebook,
        Guard::ChangedReadRefused,
        &[],
        tracked,
    );
    add(
        State::Changed,
        State::RefreshState,
        Guard::ChangedDigestEqual,
        &[Effect::RefreshState],
        tracked,
    );
    add(
        State::Changed,
        State::Deduped,
        Guard::ChangedDuplicate,
        &[],
        tracked,
    );
    add(
        State::Changed,
        State::Rotate,
        Guard::ChangedNew,
        &[Effect::PrepareNotice],
        tracked,
    );
    add(
        State::Changed,
        State::FailOpen,
        Guard::NotChanged,
        &[],
        all ^ tracked,
    );
    add(
        State::Present,
        State::RefreshSnapshotState,
        Guard::PresentNeedsRefresh,
        &[Effect::RefreshSnapshotState],
        all,
    );
    add(
        State::Present,
        State::AllowEmpty,
        Guard::PresentCurrent,
        &[],
        all,
    );

    add(State::InjectFull, State::Snapshot, Guard::Always, &[], all);
    add(
        State::Rotate,
        State::Snapshot,
        Guard::Always,
        &[Effect::RotateSnapshot],
        all,
    );
    add(
        State::Snapshot,
        State::StateWrite,
        Guard::Always,
        &[Effect::WriteSnapshot],
        all,
    );
    add(
        State::StateWrite,
        State::Log,
        Guard::PhaseFull,
        &[Effect::WriteState],
        all,
    );
    add(
        State::StateWrite,
        State::Notice,
        Guard::PhaseNotice,
        &[Effect::WriteState],
        all,
    );
    add(
        State::StateWrite,
        State::FailOpen,
        Guard::PhaseOther,
        &[],
        all,
    );
    add(State::Notice, State::Log, Guard::Always, &[], all);
    add(
        State::RefreshState,
        State::AllowEmpty,
        Guard::Always,
        &[],
        all,
    );
    add(
        State::RefreshSnapshotState,
        State::AllowEmpty,
        Guard::Always,
        &[],
        all,
    );
    add(State::RefusedRulebook, State::Log, Guard::Always, &[], all);
    add(
        State::Log,
        State::AllowContext,
        Guard::LogAllowsContext,
        &[Effect::AppendPlannedLog],
        all,
    );
    add(
        State::Log,
        State::AllowEmpty,
        Guard::LogAllowsEmpty,
        &[Effect::AppendPlannedLog],
        all,
    );
    for state in [
        State::Disabled,
        State::RefusedAudience,
        State::Deduped,
        State::RefusedEvent,
    ] {
        add(state, State::AllowEmpty, Guard::Always, &[], all);
    }
    add(
        State::FailOpen,
        State::LogClassIfPossible,
        Guard::FailureContinuation,
        &[],
        all,
    );
    add(
        State::LogClassIfPossible,
        State::AllowEmpty,
        Guard::FailureContinuation,
        &[Effect::AppendInternalLog],
        all,
    );

    let internal_sources = State::ALL.into_iter().filter(|state| {
        !state.is_terminal()
            && !matches!(
                state,
                State::Entry | State::FailOpen | State::LogClassIfPossible
            )
    });
    for state in internal_sources {
        add(state, State::FailOpen, Guard::InternalError, &[], all);
    }
    graph
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    None,
    Full,
    Notice,
    Refusal,
}

#[derive(Clone, Copy, Debug)]
enum ErrorClass {
    Graph,
    Io,
    Serialization,
    UnknownStateField,
    Time,
}

const STATE_FIELDS: [&str; 10] = [
    "cwd",
    "dedupe_key",
    "emitted_prompt_ids",
    "hash",
    "last_prompt_id",
    "mtime",
    "session_id",
    "sessionstart_dedupe",
    "snapshot_current",
    "updated_at",
];

impl ErrorClass {
    const fn name(self) -> &'static str {
        match self {
            Self::Graph => "Graph",
            Self::Io => "Io",
            Self::Serialization => "Serialization",
            Self::UnknownStateField => "UnknownStateField",
            Self::Time => "Time",
        }
    }
}

impl From<io::Error> for ErrorClass {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

impl From<serde_json::Error> for ErrorClass {
    fn from(_: serde_json::Error) -> Self {
        Self::Serialization
    }
}

#[derive(Clone, Copy)]
enum RefusalReason {
    Missing,
    Unreadable,
    Oversized,
}

impl RefusalReason {
    const fn name(self) -> &'static str {
        match self {
            Self::Missing => "rulebook_missing",
            Self::Unreadable => "rulebook_unreadable",
            Self::Oversized => "rulebook_oversized",
        }
    }
}

struct Refusal {
    reason: RefusalReason,
    size: Option<u64>,
    error: Option<&'static str>,
}

struct Rulebook {
    bytes: Vec<u8>,
    text: String,
    digest: String,
}

struct Config {
    state_dir: PathBuf,
    rulebook: PathBuf,
}

impl Config {
    fn from_environment() -> Self {
        Self {
            state_dir: configured_path(
                "ORCHESTRATOR_STATE_DIR",
                "~/.local/state/superloop-tools/hook",
            ),
            rulebook: configured_path(
                "ORCHESTRATION_FILE",
                "~/.local/share/orchestration-instance/ORCHESTRATION.md",
            ),
        }
    }
}

/// Normalized session observations supplied by a harness or terminal caller.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub enum SessionKind {
    Start,
    Prompt,
    #[default]
    Other,
}

/// The event text is retained only as an opaque persistence and diagnostic label.
#[derive(Clone)]
pub struct SessionInput {
    pub kind: SessionKind,
    pub event_class: EventClass,
    pub event: String,
    pub session_id: String,
    pub cwd: String,
    pub source: String,
    pub prompt_id: Option<String>,
    pub transcript_path: Option<String>,
    pub refused_audience: bool,
}

impl Default for SessionInput {
    fn default() -> Self {
        Self {
            kind: SessionKind::Other,
            event_class: EventClass::Unsupported,
            event: String::new(),
            session_id: String::from("unknown"),
            cwd: String::new(),
            source: String::new(),
            prompt_id: None,
            transcript_path: None,
            refused_audience: false,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
struct Context {
    config: Config,
    kind: SessionKind,
    witness: fn(&str, &str) -> bool,
    start: Instant,
    event_class: EventClass,
    event: String,
    session_id: String,
    session_key: String,
    cwd: String,
    source: String,
    prompt_id: Option<String>,
    transcript_path: Option<String>,
    refused_audience: bool,
    mtime: Option<i64>,
    stat_refusal: Option<Refusal>,
    stat_observed: bool,
    rulebook: Option<Rulebook>,
    read_observed: bool,
    state_file: PathBuf,
    state_existed: bool,
    state: Map<String, Value>,
    state_loaded: bool,
    phase: Phase,
    refresh_present: bool,
    old_mtime: Option<i64>,
    response: Option<String>,
    dedupe_now: Option<f64>,
    full_duplicate_result: Option<bool>,
    internal_error: Option<ErrorClass>,
}

impl Context {
    fn from_input(input: &SessionInput, start: Instant, witness: fn(&str, &str) -> bool) -> Self {
        let config = Config::from_environment();
        let SessionInput {
            kind,
            event_class,
            event,
            session_id,
            cwd,
            source,
            prompt_id,
            transcript_path,
            refused_audience,
        } = input.clone();
        let session_key = safe_session_id(&session_id);
        let state_file = config
            .state_dir
            .join(format!("orchestrator-scope-{session_key}.json"));
        Self {
            config,
            kind,
            witness,
            start,
            event_class,
            event,
            session_id,
            session_key,
            cwd,
            source,
            prompt_id,
            transcript_path,
            refused_audience,
            mtime: None,
            stat_refusal: None,
            stat_observed: false,
            rulebook: None,
            read_observed: false,
            state_file,
            state_existed: false,
            state: Map::new(),
            state_loaded: false,
            phase: Phase::None,
            refresh_present: false,
            old_mtime: None,
            response: None,
            dedupe_now: None,
            full_duplicate_result: None,
            internal_error: None,
        }
    }

    fn observe_stat(&mut self) {
        if self.stat_observed {
            return;
        }
        self.stat_observed = true;
        match fs::metadata(&self.config.rulebook) {
            Ok(metadata) if metadata.len() > MAX_RULEBOOK_BYTES as u64 => {
                self.stat_refusal = Some(Refusal {
                    reason: RefusalReason::Oversized,
                    size: Some(metadata.len()),
                    error: None,
                });
            }
            Ok(metadata) => {
                let nanos = i128::from(metadata.mtime()) * 1_000_000_000
                    + i128::from(metadata.mtime_nsec());
                match i64::try_from(nanos) {
                    Ok(stamp) => self.mtime = Some(stamp),
                    Err(_) => self.internal_error = Some(ErrorClass::Time),
                }
            }
            Err(error) => {
                self.stat_refusal = Some(Refusal {
                    reason: if error.kind() == io::ErrorKind::NotFound {
                        RefusalReason::Missing
                    } else {
                        RefusalReason::Unreadable
                    },
                    size: None,
                    error: (error.kind() != io::ErrorKind::NotFound).then_some("Io"),
                });
            }
        }
    }

    fn load_state(&mut self) -> Result<(), ErrorClass> {
        if self.state_loaded {
            return Ok(());
        }
        self.state_loaded = true;
        let bytes = match fs::read(&self.state_file) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        self.state_existed = true;
        let value: Value = serde_json::from_slice(&bytes)?;
        let Value::Object(state) = value else {
            return Err(ErrorClass::Serialization);
        };
        if state
            .keys()
            .any(|field| !STATE_FIELDS.contains(&field.as_str()))
        {
            return Err(ErrorClass::UnknownStateField);
        }
        self.state = state;
        Ok(())
    }

    fn read_rulebook(&mut self) {
        if self.read_observed {
            return;
        }
        self.read_observed = true;
        let Ok(bytes) = fs::read(&self.config.rulebook) else {
            self.stat_refusal = Some(Refusal {
                reason: RefusalReason::Unreadable,
                size: None,
                error: Some("Io"),
            });
            return;
        };
        if bytes.len() > MAX_RULEBOOK_BYTES {
            self.stat_refusal = Some(Refusal {
                reason: RefusalReason::Oversized,
                size: u64::try_from(bytes.len()).ok(),
                error: None,
            });
            return;
        }
        let Ok(text) = String::from_utf8(bytes.clone()) else {
            self.stat_refusal = Some(Refusal {
                reason: RefusalReason::Unreadable,
                size: None,
                error: Some("Utf8"),
            });
            return;
        };
        self.rulebook = Some(Rulebook {
            digest: digest_hex(&bytes),
            bytes,
            text,
        });
    }

    fn disabled(&self) -> bool {
        let (global, project) = flags(&self.config.state_dir, &self.cwd);
        global.exists() || project.exists()
    }

    fn full_duplicate(&mut self) -> Result<bool, ErrorClass> {
        if let Some(result) = self.full_duplicate_result {
            return Ok(result);
        }
        self.read_rulebook();
        let Some(rulebook) = &self.rulebook else {
            return Ok(false);
        };
        if self.kind == SessionKind::Start {
            let now = wall_seconds()?;
            self.dedupe_now = Some(now);
            let key = [&self.session_id, &self.source, &rulebook.digest];
            let Some(record) = self
                .state
                .get("sessionstart_dedupe")
                .and_then(Value::as_object)
            else {
                return Ok(false);
            };
            let matches_key = record
                .get("key")
                .and_then(Value::as_array)
                .is_some_and(|stored| {
                    stored.len() == 3
                        && stored.iter().zip(key).all(|(value, expected)| {
                            value.as_str().is_some_and(|actual| actual == expected)
                        })
                });
            let recorded = record.get("time").and_then(value_as_f64);
            let result = matches_key
                && recorded.is_some_and(|time| {
                    let delta = now - time;
                    (0.0..=SESSIONSTART_GRACE_SECONDS).contains(&delta)
                });
            self.full_duplicate_result = Some(result);
            return Ok(result);
        }
        let result = self
            .prompt_id
            .as_deref()
            .is_some_and(|prompt| prompt_ids(&self.state).iter().any(|seen| seen == prompt));
        self.full_duplicate_result = Some(result);
        Ok(result)
    }

    fn resume_needs_full(&self) -> bool {
        !self.state_existed || !self.transcript_has_current_marker()
    }

    fn transcript_has_current_marker(&self) -> bool {
        match (&self.transcript_path, &self.rulebook) {
            (Some(path), Some(rulebook)) => (self.witness)(path, &rulebook.digest),
            _ => false,
        }
    }

    fn stored_mtime(&self) -> Option<i64> {
        self.state.get("mtime").and_then(value_as_i64)
    }

    fn stored_digest_matches(&self) -> bool {
        self.rulebook.as_ref().is_some_and(|rulebook| {
            self.state
                .get("hash")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest == rulebook.digest)
        })
    }

    fn prepare_full(&mut self) -> Result<(), ErrorClass> {
        let rulebook = self.rulebook.as_ref().ok_or(ErrorClass::Graph)?;
        let digest = rulebook.digest.clone();
        let text = rulebook.text.clone();
        if self.kind == SessionKind::Start {
            let now = self.dedupe_now.unwrap_or(wall_seconds()?);
            let key = Value::Array(
                [&self.session_id, &self.source, &digest]
                    .into_iter()
                    .map(|value| Value::String(value.clone()))
                    .collect(),
            );
            self.state.insert(
                String::from("sessionstart_dedupe"),
                Value::Object(Map::from_iter([
                    (String::from("key"), key.clone()),
                    (String::from("time"), number_from_f64(now)?),
                ])),
            );
            self.state.insert(
                String::from("dedupe_key"),
                Value::Object(Map::from_iter([
                    (String::from("event"), Value::String(self.event.clone())),
                    (String::from("key"), key),
                ])),
            );
        } else {
            self.record_prompt();
            let mut dedupe = Map::new();
            dedupe.insert(String::from("event"), Value::String(self.event.clone()));
            if let Some(prompt) = &self.prompt_id {
                dedupe.insert(String::from("prompt_id"), Value::String(prompt.clone()));
            }
            self.state
                .insert(String::from("dedupe_key"), Value::Object(dedupe));
        }
        self.phase = Phase::Full;
        self.update_base_state()?;
        self.response = Some(marker_text(
            &digest,
            self.mtime.ok_or(ErrorClass::Graph)?,
            &text,
        ));
        Ok(())
    }

    fn prepare_notice(&mut self) -> Result<(), ErrorClass> {
        let old_mtime = self.stored_mtime().unwrap_or(0);
        self.old_mtime = Some(old_mtime);
        self.record_prompt();
        if self.kind == SessionKind::Prompt {
            let mut dedupe = Map::new();
            dedupe.insert(String::from("event"), Value::String(self.event.clone()));
            if let Some(prompt) = &self.prompt_id {
                dedupe.insert(String::from("prompt_id"), Value::String(prompt.clone()));
            }
            self.state
                .insert(String::from("dedupe_key"), Value::Object(dedupe));
        }
        self.phase = Phase::Notice;
        self.update_base_state()?;
        let previous = self.snapshot_path("prev");
        self.response = Some(format!(
            "ORCHESTRATION.md changed (mtime {old_mtime} -> {}). Run a diff between {} and the live ORCHESTRATION.md file, then update your working rules accordingly.",
            self.mtime.ok_or(ErrorClass::Graph)?,
            previous.to_string_lossy()
        ));
        Ok(())
    }

    fn record_prompt(&mut self) {
        let Some(prompt) = &self.prompt_id else {
            return;
        };
        if prompt.is_empty() {
            return;
        }
        let mut seen = prompt_ids(&self.state)
            .into_iter()
            .filter(|item| item != prompt)
            .map(Value::String)
            .collect::<Vec<_>>();
        seen.push(Value::String(prompt.clone()));
        let keep_from = seen.len().saturating_sub(64);
        self.state.insert(
            String::from("emitted_prompt_ids"),
            Value::Array(seen.split_off(keep_from)),
        );
        self.state.insert(
            String::from("last_prompt_id"),
            Value::String(prompt.clone()),
        );
    }

    fn update_base_state(&mut self) -> Result<(), ErrorClass> {
        let rulebook = self.rulebook.as_ref().ok_or(ErrorClass::Graph)?;
        self.state.insert(
            String::from("session_id"),
            Value::String(self.session_id.clone()),
        );
        self.state
            .insert(String::from("cwd"), Value::String(self.cwd.clone()));
        self.state
            .insert(String::from("hash"), Value::String(rulebook.digest.clone()));
        self.state.insert(
            String::from("mtime"),
            Value::Number(Number::from(self.mtime.ok_or(ErrorClass::Graph)?)),
        );
        self.state.insert(
            String::from("snapshot_current"),
            Value::String(self.snapshot_path("current").to_string_lossy().into_owned()),
        );
        self.state.insert(
            String::from("updated_at"),
            number_from_f64(wall_seconds()?)?,
        );
        Ok(())
    }

    fn snapshot_path(&self, role: &str) -> PathBuf {
        self.config.state_dir.join(format!(
            "orchestration-snapshot-{}-{role}.md",
            self.session_key
        ))
    }

    fn rotate_snapshot(&self) -> Result<(), ErrorClass> {
        let current = self.snapshot_path("current");
        if current.exists() {
            fs::rename(current, self.snapshot_path("prev"))?;
        }
        Ok(())
    }

    fn write_snapshot(&self) -> Result<(), ErrorClass> {
        let bytes = &self.rulebook.as_ref().ok_or(ErrorClass::Graph)?.bytes;
        atomic_write(&self.snapshot_path("current"), bytes)
    }

    fn write_state(&self) -> Result<(), ErrorClass> {
        let mut bytes = serde_json::to_vec(&self.state)?;
        bytes.push(b'\n');
        atomic_write(&self.state_file, &bytes)
    }

    fn refresh_state(&mut self, snapshot: bool) -> Result<(), ErrorClass> {
        self.update_base_state()?;
        if snapshot {
            self.write_snapshot()?;
        }
        self.write_state()
    }

    fn planned_log(&self) -> Map<String, Value> {
        let mut record = Map::new();
        match self.phase {
            Phase::Full => {
                record.insert(
                    String::from("action"),
                    Value::String(String::from("injection")),
                );
                record.insert(String::from("event"), Value::String(self.event.clone()));
                record.insert(
                    String::from("session_id"),
                    Value::String(self.session_id.clone()),
                );
                if let Some(rulebook) = &self.rulebook {
                    record.insert(String::from("hash"), Value::String(rulebook.digest.clone()));
                }
                if let Some(mtime) = self.mtime {
                    record.insert(String::from("mtime"), Value::Number(Number::from(mtime)));
                }
            }
            Phase::Notice => {
                record.insert(
                    String::from("action"),
                    Value::String(String::from("change_notice")),
                );
                record.insert(String::from("event"), Value::String(self.event.clone()));
                record.insert(
                    String::from("session_id"),
                    Value::String(self.session_id.clone()),
                );
                record.insert(
                    String::from("old_mtime"),
                    Value::Number(Number::from(self.old_mtime.unwrap_or(0))),
                );
                if let Some(mtime) = self.mtime {
                    record.insert(
                        String::from("new_mtime"),
                        Value::Number(Number::from(mtime)),
                    );
                }
                if let Some(rulebook) = &self.rulebook {
                    record.insert(String::from("hash"), Value::String(rulebook.digest.clone()));
                }
            }
            Phase::Refusal => {
                if let Some(refusal) = &self.stat_refusal {
                    record.insert(
                        String::from("action"),
                        Value::String(String::from("guard4_refusal")),
                    );
                    record.insert(
                        String::from("reason"),
                        Value::String(String::from(refusal.reason.name())),
                    );
                    record.insert(String::from("event"), Value::String(self.event.clone()));
                    record.insert(
                        String::from("session_id"),
                        Value::String(self.session_id.clone()),
                    );
                    if let Some(size) = refusal.size {
                        record.insert(String::from("size"), Value::Number(Number::from(size)));
                        record.insert(
                            String::from("limit"),
                            Value::Number(Number::from(MAX_RULEBOOK_BYTES)),
                        );
                    }
                    if let Some(error) = refusal.error {
                        record.insert(String::from("error"), Value::String(String::from(error)));
                    }
                }
            }
            Phase::None => {}
        }
        add_elapsed(&mut record, self.start.elapsed());
        record
    }

    fn append_log(&self, mut record: Map<String, Value>) {
        if fs::create_dir_all(&self.config.state_dir).is_err() {
            return;
        }
        record.insert(
            String::from("ts"),
            Value::Number(Number::from(unix_seconds().unwrap_or(0))),
        );
        let Ok(mut line) = serde_json::to_vec(&record) else {
            return;
        };
        line.push(b'\n');
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.config.state_dir.join("orchestrator.log"))
            && file.write_all(&line).is_err()
        {}
    }

    fn rulebook_available(&mut self) -> bool {
        self.read_rulebook();
        self.stat_refusal.is_none() && self.rulebook.is_some()
    }
}

impl Guard {
    #[allow(clippy::too_many_lines)]
    fn matches(self, context: &mut Context) -> Result<bool, ErrorClass> {
        if self == Self::InternalError {
            return Ok(context.internal_error.is_some());
        }
        if self == Self::FailureContinuation {
            return Ok(true);
        }
        if context.internal_error.is_some() {
            return Ok(false);
        }
        match self {
            Self::InternalError | Self::FailureContinuation => Ok(false),
            Self::Malformed => Ok(context.event_class == EventClass::Malformed),
            Self::Unsupported => Ok(context.event_class == EventClass::Unsupported),
            Self::Accepted => Ok(matches!(
                context.event_class,
                EventClass::Fresh | EventClass::Resumed | EventClass::Tracked
            )),
            Self::Disabled => Ok(context.disabled()),
            Self::Enabled => Ok(!context.disabled()),
            Self::RefusedAudience => Ok(context.refused_audience),
            Self::AcceptedAudience => Ok(!context.refused_audience),
            Self::RulebookRefused => {
                context.observe_stat();
                if context.stat_refusal.is_some() {
                    context.phase = Phase::Refusal;
                }
                Ok(context.stat_refusal.is_some())
            }
            Self::RulebookAccepted => {
                context.observe_stat();
                Ok(context.stat_refusal.is_none())
            }
            Self::IsFresh => Ok(context.event_class == EventClass::Fresh),
            Self::IsResumed => Ok(context.event_class == EventClass::Resumed),
            Self::IsTracked => Ok(context.event_class == EventClass::Tracked),
            Self::InvalidEventClass => Ok(matches!(
                context.event_class,
                EventClass::Malformed | EventClass::Unsupported
            )),
            Self::FreshReadRefused => {
                if context.event_class != EventClass::Fresh {
                    return Ok(false);
                }
                context.read_rulebook();
                if context.stat_refusal.is_some() {
                    context.phase = Phase::Refusal;
                }
                Ok(context.stat_refusal.is_some())
            }
            Self::FreshDuplicate => Ok(context.event_class == EventClass::Fresh
                && context.rulebook_available()
                && context.full_duplicate()?),
            Self::FreshNew => Ok(context.event_class == EventClass::Fresh
                && context.rulebook_available()
                && !context.full_duplicate()?),
            Self::NotFresh => Ok(context.event_class != EventClass::Fresh),
            Self::ResumedReadRefused => {
                if context.event_class != EventClass::Resumed {
                    return Ok(false);
                }
                context.read_rulebook();
                if context.stat_refusal.is_some() {
                    context.phase = Phase::Refusal;
                }
                Ok(context.stat_refusal.is_some())
            }
            Self::ResumedDuplicate => Ok(context.event_class == EventClass::Resumed
                && context.rulebook_available()
                && context.resume_needs_full()
                && context.full_duplicate()?),
            Self::ResumedNeedsFull => Ok(context.event_class == EventClass::Resumed
                && context.rulebook_available()
                && context.resume_needs_full()
                && !context.full_duplicate()?),
            Self::ResumedWitnessPresent => Ok(context.event_class == EventClass::Resumed
                && context.rulebook_available()
                && !context.resume_needs_full()),
            Self::NotResumed => Ok(context.event_class != EventClass::Resumed),
            Self::TrackedAbsentReadRefused => {
                if context.event_class != EventClass::Tracked || context.state_existed {
                    return Ok(false);
                }
                context.read_rulebook();
                if context.stat_refusal.is_some() {
                    context.phase = Phase::Refusal;
                }
                Ok(context.stat_refusal.is_some())
            }
            Self::TrackedAbsentDuplicate => Ok(context.event_class == EventClass::Tracked
                && !context.state_existed
                && context.rulebook_available()
                && context.full_duplicate()?),
            Self::TrackedAbsentNew => Ok(context.event_class == EventClass::Tracked
                && !context.state_existed
                && context.rulebook_available()
                && !context.full_duplicate()?),
            Self::TrackedMtimeEqual => Ok(context.event_class == EventClass::Tracked
                && context.state_existed
                && context.stored_mtime() == context.mtime),
            Self::TrackedMtimeChanged => Ok(context.event_class == EventClass::Tracked
                && context.state_existed
                && context.stored_mtime() != context.mtime),
            Self::NotTracked | Self::NotChanged => Ok(context.event_class != EventClass::Tracked),
            Self::ChangedReadRefused => {
                if context.event_class != EventClass::Tracked {
                    return Ok(false);
                }
                context.read_rulebook();
                if context.stat_refusal.is_some() {
                    context.phase = Phase::Refusal;
                }
                Ok(context.stat_refusal.is_some())
            }
            Self::ChangedDigestEqual => Ok(context.event_class == EventClass::Tracked
                && context.rulebook_available()
                && context.stored_digest_matches()),
            Self::ChangedDuplicate => Ok(context.event_class == EventClass::Tracked
                && context.rulebook_available()
                && !context.stored_digest_matches()
                && context.full_duplicate()?),
            Self::ChangedNew => Ok(context.event_class == EventClass::Tracked
                && context.rulebook_available()
                && !context.stored_digest_matches()
                && !context.full_duplicate()?),
            Self::PresentNeedsRefresh => Ok(context.refresh_present),
            Self::PresentCurrent => Ok(!context.refresh_present),
            Self::PhaseFull => Ok(context.phase == Phase::Full),
            Self::PhaseNotice => Ok(context.phase == Phase::Notice),
            Self::PhaseOther => Ok(!matches!(context.phase, Phase::Full | Phase::Notice)),
            Self::LogAllowsContext => Ok(context.response.is_some()),
            Self::LogAllowsEmpty => Ok(context.response.is_none()),
            Self::Always => Ok(true),
        }
    }
}

impl Effect {
    fn apply(self, context: &mut Context) -> Result<(), ErrorClass> {
        match self {
            Self::LoadState => context.load_state()?,
            Self::PrepareFull => context.prepare_full()?,
            Self::MarkPresentRefresh => {
                context.refresh_present =
                    !context.stored_digest_matches() || context.stored_mtime() != context.mtime;
            }
            Self::PrepareNotice => context.prepare_notice()?,
            Self::RotateSnapshot => context.rotate_snapshot()?,
            Self::WriteSnapshot => context.write_snapshot()?,
            Self::WriteState => context.write_state()?,
            Self::RefreshState => context.refresh_state(false)?,
            Self::RefreshSnapshotState => context.refresh_state(true)?,
            Self::AppendPlannedLog => context.append_log(context.planned_log()),
            Self::AppendInternalLog => {
                if let Some(error) = context.internal_error {
                    let mut record = Map::from_iter([
                        (
                            String::from("action"),
                            Value::String(String::from("internal_error")),
                        ),
                        (
                            String::from("error"),
                            Value::String(String::from(error.name())),
                        ),
                    ]);
                    add_elapsed(&mut record, context.start.elapsed());
                    context.append_log(record);
                }
            }
        }
        Ok(())
    }
}

fn node_for(graph: &DiGraph<State, Transition>, state: State) -> Option<NodeIndex> {
    graph.node_indices().find(|index| {
        graph
            .node_weight(*index)
            .is_some_and(|value| *value == state)
    })
}

fn evaluate(
    input: &SessionInput,
    start: Instant,
    witness: fn(&str, &str) -> bool,
) -> Option<String> {
    let graph = injection_graph();
    let mut context = Context::from_input(input, start, witness);
    let mut current = node_for(&graph, State::Entry)?;
    let fail_open = node_for(&graph, State::FailOpen)?;
    let mut step_count = 0_usize;
    while !graph[current].is_terminal() {
        step_count += 1;
        if step_count > graph.node_count() * 4 {
            context.internal_error = Some(ErrorClass::Graph);
            current = fail_open;
            continue;
        }
        let mut selected = None;
        for edge in graph.edges(current) {
            match edge.weight().guard.matches(&mut context) {
                Ok(true) => {
                    if selected.is_some() {
                        context.internal_error = Some(ErrorClass::Graph);
                        selected = None;
                        break;
                    }
                    selected = Some((edge.target(), edge.weight().effects));
                }
                Ok(false) => {}
                Err(error) => {
                    context.internal_error = Some(error);
                    selected = None;
                    break;
                }
            }
        }
        let Some((target, effects)) = selected else {
            if context.internal_error.is_none() {
                context.internal_error = Some(ErrorClass::Graph);
            }
            if current == fail_open {
                return None;
            }
            continue;
        };
        let mut failed = false;
        for effect in effects {
            if let Err(error) = effect.apply(&mut context) {
                context.internal_error = Some(error);
                failed = true;
                break;
            }
        }
        if !failed {
            current = target;
        }
    }
    if graph[current] == State::AllowContext {
        context.response
    } else {
        None
    }
}

pub fn run(input: &SessionInput, witness: fn(&str, &str) -> bool) -> Option<String> {
    let start = Instant::now();
    let output = evaluate(input, start, witness);
    let elapsed = start.elapsed();
    if elapsed > SLOW_RUN {
        let mut record = Map::from_iter([(
            String::from("action"),
            Value::String(String::from("slow_run")),
        )]);
        add_elapsed(&mut record, elapsed);
        let context = Context::from_input(&SessionInput::default(), start, |_, _| false);
        context.append_log(record);
    }
    output
}

pub fn record_panic() {
    let start = Instant::now();
    let context = Context::from_input(&SessionInput::default(), start, |_, _| false);
    let mut record = Map::from_iter([
        (
            String::from("action"),
            Value::String(String::from("internal_error")),
        ),
        (String::from("error"), Value::String(String::from("Panic"))),
    ]);
    add_elapsed(&mut record, start.elapsed());
    context.append_log(record);
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ErrorClass> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let name = path.file_name().ok_or(ErrorClass::Io)?.to_string_lossy();
    let temporary = path.with_file_name(format!("{name}.tmp"));
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.flush()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn marker_text(digest: &str, mtime: i64, rulebook: &str) -> String {
    let separator = if rulebook.ends_with('\n') { "" } else { "\n" };
    format!(
        "{MARKER_PREFIX}{digest} mtime={mtime}\n{rulebook}{separator}ORCHESTRATION_SCOPE_MARKER_END v1 sha256={digest}"
    )
}

fn prompt_ids(state: &Map<String, Value>) -> Vec<String> {
    state
        .get("emitted_prompt_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn value_as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| number.try_into().ok()))
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn number_from_f64(value: f64) -> Result<Value, ErrorClass> {
    Number::from_f64(value)
        .map(Value::Number)
        .ok_or(ErrorClass::Time)
}

fn wall_seconds() -> Result<f64, ErrorClass> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| ErrorClass::Time)
}

fn unix_seconds() -> Result<u64, ErrorClass> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ErrorClass::Time)
}

fn add_elapsed(record: &mut Map<String, Value>, elapsed: Duration) {
    let milliseconds = (elapsed.as_secs_f64() * 1_000_000.0).round() / 1_000.0;
    if let Some(number) = Number::from_f64(milliseconds) {
        record.insert(String::from("elapsed_ms"), Value::Number(number));
    }
}

fn safe_session_id(value: &str) -> String {
    let value = if value.is_empty() { "unknown" } else { value };
    value.replace(['/', '\0'], "-")
}

#[cfg(test)]
mod tests;

pub(crate) fn configured_path(environment: &str, default: &str) -> PathBuf {
    let raw = env::var_os(environment).unwrap_or_else(|| OsString::from(default));
    expand_home(Path::new(&raw))
}

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/")
        && let Some(home) = env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    path.to_path_buf()
}

pub(crate) fn folded_cwd(cwd: &str) -> (PathBuf, String) {
    let boundary = env::var_os("HOME").map(PathBuf::from);
    let root = project_root::project_root(Path::new(cwd), boundary.as_deref());
    let folded = root.to_string_lossy().replace('/', "-");
    (root, folded)
}
