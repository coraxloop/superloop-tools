use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef as _;
use serde_json::{Value, json};

use crate::project_root::project_root;

const MIN_DELAY_SECONDS: f64 = 60.0;
const MAX_DELAY_SECONDS: f64 = 3_600.0;
const SCHEDULE_SLACK_SECONDS: f64 = 120.0;
const SEARCH_HORIZON_SECONDS: f64 = 3_720.0;
const MAX_BLOCKS_PER_TURN: i64 = 3;

pub const PROMPT_MARKER_FILE: &str = "guard-prompt";

const UNKNOWN_SESSION: &str = "unknown";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// One decision, semantic, or terminal state in the heartbeat graph.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum State {
    Entry,
    Letters,
    LettersEmpty,
    LettersUnread,
    LettersFailed,
    Toggle,
    Transcript,
    RetryOnce,
    Resolve,
    Off,
    FailOpen,
    Armed,
    Prompt,
    ExceptionUnpromptedArmed,
    ExceptionUnpromptedUnarmed,
    ExceptionLapse,
    ExceptionUnpromptedLapse,
    ComposeSilent,
    ComposePrompt,
    ComposeViolation,
    ComposeViolationAndPrompt,
    ComposeLapse,
    ComposeLapseAndViolation,
    AllowLettersFeedback,
    BlockPromptFeedback,
    BlockViolationFeedback,
    BlockViolationAndPromptFeedback,
    AllowLettersLapse,
    AllowLettersLapseAndViolation,
    BlockLetters,
    BlockLettersAndPrompt,
    BlockLettersAndViolation,
    BlockLettersAndViolationAndPrompt,
    AllowSilent,
    BlockPrompt,
    BlockViolation,
    BlockViolationAndPrompt,
    AllowLapseAlarm,
    AllowLapseAndViolationAlarm,
}

impl State {
    /// Complete state inventory used by graph verification.
    pub const ALL: [Self; 39] = [
        Self::Entry,
        Self::Letters,
        Self::LettersEmpty,
        Self::LettersUnread,
        Self::LettersFailed,
        Self::Toggle,
        Self::Transcript,
        Self::RetryOnce,
        Self::Resolve,
        Self::Off,
        Self::FailOpen,
        Self::Armed,
        Self::Prompt,
        Self::ExceptionUnpromptedArmed,
        Self::ExceptionUnpromptedUnarmed,
        Self::ExceptionLapse,
        Self::ExceptionUnpromptedLapse,
        Self::ComposeSilent,
        Self::ComposePrompt,
        Self::ComposeViolation,
        Self::ComposeViolationAndPrompt,
        Self::ComposeLapse,
        Self::ComposeLapseAndViolation,
        Self::AllowLettersFeedback,
        Self::BlockPromptFeedback,
        Self::BlockViolationFeedback,
        Self::BlockViolationAndPromptFeedback,
        Self::AllowLettersLapse,
        Self::AllowLettersLapseAndViolation,
        Self::BlockLetters,
        Self::BlockLettersAndPrompt,
        Self::BlockLettersAndViolation,
        Self::BlockLettersAndViolationAndPrompt,
        Self::AllowSilent,
        Self::BlockPrompt,
        Self::BlockViolation,
        Self::BlockViolationAndPrompt,
        Self::AllowLapseAlarm,
        Self::AllowLapseAndViolationAlarm,
    ];

    /// All heartbeat and composed process-adapter verdict paths.
    pub const VERDICTS: [Self; 16] = [
        Self::AllowSilent,
        Self::BlockPrompt,
        Self::BlockViolation,
        Self::BlockViolationAndPrompt,
        Self::AllowLapseAlarm,
        Self::AllowLapseAndViolationAlarm,
        Self::AllowLettersFeedback,
        Self::BlockPromptFeedback,
        Self::BlockViolationFeedback,
        Self::BlockViolationAndPromptFeedback,
        Self::AllowLettersLapse,
        Self::AllowLettersLapseAndViolation,
        Self::BlockLetters,
        Self::BlockLettersAndPrompt,
        Self::BlockLettersAndViolation,
        Self::BlockLettersAndViolationAndPrompt,
    ];

    /// Whether this state is a terminal verdict node.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        Self::VERDICTS.contains(&self)
    }
}

/// Predicate attached to a direct graph edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Guard {
    Malformed,
    Accepted,
    LettersEmpty,
    LettersUnread,
    LettersFailed,
    NoLettersFeedback,
    LettersMayBlock,
    LettersNotify,
    InternalError,
    FlagAbsent,
    FlagPresent,
    RetryNeeded,
    TranscriptReady,
    Armed,
    Prompt,
    Lapse,
    UnpromptedArmed,
    UnpromptedPrompt,
    UnpromptedLapse,
    WarningFresh,
    WarningRecorded,
    Always,
}

/// Ordered side effect attached to a direct graph edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    WaitAndReload,
    RecordCount,
    RecordLettersCount,
    RecordWarning,
    RecordPromptMarker,
    AppendInternalLog,
}

/// Edge weight used directly by [`DiGraph`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    /// Exclusive predicate selecting this edge.
    pub guard: Guard,
    /// Ordered effects applied before entering the destination.
    pub effects: &'static [Effect],
}

/// Neutral result of the session graph, before harness serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evaluation {
    pub state: State,
    pub path: Vec<State>,
    pub retry_count: u8,
    pub feedback: String,
}

/// Build the heartbeat machine directly as a petgraph directed graph.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn heartbeat_graph() -> DiGraph<State, Transition> {
    let mut graph = DiGraph::new();
    let nodes = State::ALL
        .into_iter()
        .map(|state| (state, graph.add_node(state)))
        .collect::<HashMap<_, _>>();
    let mut add = |from, to, guard, effects| {
        graph.add_edge(nodes[&from], nodes[&to], Transition { guard, effects });
    };

    add(State::Entry, State::FailOpen, Guard::Malformed, &[]);
    add(State::Entry, State::Letters, Guard::Accepted, &[]);
    add(
        State::Letters,
        State::LettersEmpty,
        Guard::LettersEmpty,
        &[],
    );
    add(
        State::Letters,
        State::LettersUnread,
        Guard::LettersUnread,
        &[],
    );
    add(
        State::Letters,
        State::LettersFailed,
        Guard::LettersFailed,
        &[],
    );
    for state in [
        State::LettersEmpty,
        State::LettersUnread,
        State::LettersFailed,
    ] {
        add(state, State::Toggle, Guard::Always, &[]);
    }
    add(State::Toggle, State::FailOpen, Guard::InternalError, &[]);
    add(State::Toggle, State::Off, Guard::FlagAbsent, &[]);
    add(State::Toggle, State::Transcript, Guard::FlagPresent, &[]);
    add(State::Off, State::AllowSilent, Guard::Always, &[]);
    add(
        State::Transcript,
        State::FailOpen,
        Guard::InternalError,
        &[],
    );
    add(State::Transcript, State::RetryOnce, Guard::RetryNeeded, &[]);
    add(
        State::Transcript,
        State::Resolve,
        Guard::TranscriptReady,
        &[],
    );
    add(State::RetryOnce, State::FailOpen, Guard::InternalError, &[]);
    add(
        State::RetryOnce,
        State::Transcript,
        Guard::Always,
        &[Effect::WaitAndReload],
    );
    add(State::Resolve, State::FailOpen, Guard::InternalError, &[]);
    add(State::Resolve, State::Armed, Guard::Armed, &[]);
    add(State::Resolve, State::Prompt, Guard::Prompt, &[]);
    add(State::Resolve, State::ExceptionLapse, Guard::Lapse, &[]);
    add(
        State::Resolve,
        State::ExceptionUnpromptedArmed,
        Guard::UnpromptedArmed,
        &[],
    );
    add(
        State::Resolve,
        State::ExceptionUnpromptedUnarmed,
        Guard::UnpromptedPrompt,
        &[],
    );
    add(
        State::Resolve,
        State::ExceptionUnpromptedLapse,
        Guard::UnpromptedLapse,
        &[],
    );
    add(State::Armed, State::AllowSilent, Guard::Always, &[]);
    add(State::Prompt, State::FailOpen, Guard::InternalError, &[]);
    add(
        State::Prompt,
        State::BlockPrompt,
        Guard::Always,
        &[Effect::RecordCount, Effect::RecordPromptMarker],
    );
    add(
        State::ExceptionUnpromptedArmed,
        State::FailOpen,
        Guard::InternalError,
        &[],
    );
    add(
        State::ExceptionUnpromptedArmed,
        State::BlockViolation,
        Guard::WarningFresh,
        &[Effect::RecordWarning],
    );
    add(
        State::ExceptionUnpromptedArmed,
        State::AllowSilent,
        Guard::WarningRecorded,
        &[],
    );
    add(
        State::ExceptionUnpromptedUnarmed,
        State::FailOpen,
        Guard::InternalError,
        &[],
    );
    add(
        State::ExceptionUnpromptedUnarmed,
        State::BlockViolationAndPrompt,
        Guard::WarningFresh,
        &[
            Effect::RecordWarning,
            Effect::RecordCount,
            Effect::RecordPromptMarker,
        ],
    );
    add(
        State::ExceptionUnpromptedUnarmed,
        State::BlockPrompt,
        Guard::WarningRecorded,
        &[Effect::RecordCount, Effect::RecordPromptMarker],
    );
    add(
        State::ExceptionLapse,
        State::AllowLapseAlarm,
        Guard::Always,
        &[],
    );
    add(
        State::ExceptionUnpromptedLapse,
        State::FailOpen,
        Guard::InternalError,
        &[],
    );
    add(
        State::ExceptionUnpromptedLapse,
        State::AllowLapseAndViolationAlarm,
        Guard::WarningFresh,
        &[Effect::RecordWarning],
    );
    add(
        State::ExceptionUnpromptedLapse,
        State::AllowLapseAlarm,
        Guard::WarningRecorded,
        &[],
    );
    add(
        State::FailOpen,
        State::AllowSilent,
        Guard::InternalError,
        &[Effect::AppendInternalLog],
    );
    add(State::FailOpen, State::AllowSilent, Guard::Always, &[]);
    // Preserve heartbeat guards and effects, but route each verdict through an
    // explicit composition decision before selecting the process terminal.
    let compositions = [
        (
            State::AllowSilent,
            State::ComposeSilent,
            State::AllowLettersFeedback,
            Some(State::BlockLetters),
        ),
        (
            State::BlockPrompt,
            State::ComposePrompt,
            State::BlockPromptFeedback,
            Some(State::BlockLettersAndPrompt),
        ),
        (
            State::BlockViolation,
            State::ComposeViolation,
            State::BlockViolationFeedback,
            Some(State::BlockLettersAndViolation),
        ),
        (
            State::BlockViolationAndPrompt,
            State::ComposeViolationAndPrompt,
            State::BlockViolationAndPromptFeedback,
            Some(State::BlockLettersAndViolationAndPrompt),
        ),
        (
            State::AllowLapseAlarm,
            State::ComposeLapse,
            State::AllowLettersLapse,
            None,
        ),
        (
            State::AllowLapseAndViolationAlarm,
            State::ComposeLapseAndViolation,
            State::AllowLettersLapseAndViolation,
            None,
        ),
    ];
    for (verdict, compose, feedback, block) in compositions {
        let incoming = graph
            .edges_directed(nodes[&verdict], petgraph::Direction::Incoming)
            .map(|edge| (edge.id(), edge.source(), edge.weight().clone()))
            .collect::<Vec<_>>();
        // Removing swap-indexed edges must proceed from the largest index.
        let mut incoming = incoming;
        incoming.sort_by_key(|(id, _, _)| std::cmp::Reverse(id.index()));
        for (edge, source, transition) in incoming {
            graph.remove_edge(edge);
            graph.add_edge(source, nodes[&compose], transition);
        }
        for (target, guard, effects) in [
            (verdict, Guard::NoLettersFeedback, &[][..]),
            (feedback, Guard::LettersNotify, &[][..]),
            (
                feedback,
                Guard::InternalError,
                &[Effect::AppendInternalLog][..],
            ),
        ] {
            graph.add_edge(
                nodes[&compose],
                nodes[&target],
                Transition { guard, effects },
            );
        }
        if let Some(block) = block {
            graph.add_edge(
                nodes[&compose],
                nodes[&block],
                Transition {
                    guard: Guard::LettersMayBlock,
                    effects: &[Effect::RecordLettersCount],
                },
            );
        }
    }
    graph
}

#[derive(Clone, Copy, Debug)]
pub enum FailureClass {
    Clock,
    Graph,
    Payload,
    StateRead,
    StateWrite,
    TranscriptRead,
    TranscriptStructure,
    Panic,
    LettersListingFailed,
}

impl FailureClass {
    const fn name(self) -> &'static str {
        match self {
            Self::Clock => "Clock",
            Self::Graph => "Graph",
            Self::Payload => "Payload",
            Self::StateRead => "StateRead",
            Self::StateWrite => "StateWrite",
            Self::TranscriptRead => "TranscriptRead",
            Self::TranscriptStructure => "TranscriptStructure",
            Self::Panic => "Panic",
            Self::LettersListingFailed => "LettersListingFailed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Classification {
    Malformed,
    Accepted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagState {
    Unknown,
    Absent,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Resolution {
    Unknown,
    Armed,
    Prompt,
    Lapse,
    UnpromptedArmed,
    UnpromptedPrompt,
    UnpromptedLapse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryPhase {
    Inactive,
    ActiveFresh,
    ActiveRetried,
}

pub struct Timing {
    now: f64,
    retry_now: Option<f64>,
    system: bool,
    replacement_transcript: Option<Vec<u8>>,
}

impl Timing {
    #[must_use]
    pub fn system() -> Self {
        Self {
            now: system_now().unwrap_or(f64::NAN),
            retry_now: None,
            system: true,
            replacement_transcript: None,
        }
    }

    #[must_use]
    pub fn fixed(initial: &str, retry: &str) -> Self {
        Self {
            now: parse_timestamp(initial).unwrap_or(f64::NAN),
            retry_now: parse_timestamp(retry),
            system: false,
            replacement_transcript: None,
        }
    }

    #[must_use]
    pub fn fixed_with_reload(initial: &str, retry: &str, replacement: &[u8]) -> Self {
        Self {
            now: parse_timestamp(initial).unwrap_or(f64::NAN),
            retry_now: parse_timestamp(retry),
            system: false,
            replacement_transcript: Some(replacement.to_vec()),
        }
    }

    fn wait_and_resample(&mut self, transcript_path: &Path) -> Result<(), FailureClass> {
        if self.system {
            thread::sleep(Duration::from_secs(1));
            self.now = system_now().ok_or(FailureClass::Clock)?;
        } else {
            if let Some(replacement) = self.replacement_transcript.take() {
                fs::write(transcript_path, replacement)
                    .map_err(|_| FailureClass::TranscriptRead)?;
            }
            self.now = self.retry_now.ok_or(FailureClass::Clock)?;
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
enum CountWrite {
    Pending,
    Recorded,
}

/// Validated Stop observations; field failure remains lazy when the toggle is off.
pub struct StopInput {
    pub cwd: Option<String>,
    pub fields: Result<StopFields, FailureClass>,
}

pub struct StopFields {
    pub transcript_path: PathBuf,
    pub session: Option<String>,
    pub retry: bool,
}

/// Timer observations preserve deferred structural errors until a decision needs them.
pub struct Timer {
    pub id: Result<String, FailureClass>,
    pub parameters: Result<(bool, Option<f64>), FailureClass>,
}

pub type Completion = (Result<String, FailureClass>, bool);

pub struct Entry {
    pub sidechain: bool,
    pub timestamp: Option<f64>,
    pub user: bool,
    pub assistant: bool,
    pub real_user: Result<bool, FailureClass>,
    pub feedback: Result<bool, FailureClass>,
    pub results: Result<Vec<Completion>, FailureClass>,
    pub timers: Result<Vec<Timer>, FailureClass>,
}

/// Harness boundary supplying typed transcript and letters observations.
pub trait Observations {
    /// # Errors
    /// Returns the classified failure when the transcript cannot be read.
    fn load(&self, path: &Path) -> Result<Vec<Entry>, FailureClass>;
    fn letters(&self, cwd: &str, home: &Path) -> crate::letters::Listing;
}

struct Context<'a> {
    state_dir: &'a Path,
    letters: crate::letters::Listing,
    letters_feedback_limit: usize,
    letters_may_block: bool,
    count_write: CountWrite,
    input: &'a StopInput,
    observations: &'a dyn Observations,
    classification: Classification,
    cwd: String,
    transcript_path: PathBuf,
    session: Option<String>,
    retry_phase: RetryPhase,
    entries: Vec<Entry>,
    armed: bool,
    flag: FlagState,
    resolution: Resolution,
    marker: String,
    count: i64,
    warned: bool,
    retry_count: u8,
    failure: Option<FailureClass>,
    timing: Timing,
}

impl<'a> Context<'a> {
    fn new(
        input: &'a StopInput,
        state_dir: &'a Path,
        timing: Timing,
        observations: &'a dyn Observations,
    ) -> Self {
        let classification = if input.cwd.is_some() {
            Classification::Accepted
        } else {
            Classification::Malformed
        };
        let cwd = input.cwd.clone().unwrap_or_default();
        Self {
            state_dir,
            letters: crate::letters::Listing::Empty,
            letters_feedback_limit: 20,
            letters_may_block: false,
            count_write: CountWrite::Pending,
            input,
            observations,
            classification,
            cwd,
            transcript_path: PathBuf::new(),
            session: None,
            retry_phase: RetryPhase::Inactive,
            entries: Vec::new(),
            armed: false,
            flag: FlagState::Unknown,
            resolution: Resolution::Unknown,
            marker: String::new(),
            count: 0,
            warned: false,
            retry_count: 0,
            failure: None,
            timing,
        }
    }

    fn session_key(&self) -> &str {
        self.session.as_deref().unwrap_or(UNKNOWN_SESSION)
    }

    fn prepare(&mut self, state: State) -> Result<(), FailureClass> {
        match state {
            State::Letters => {
                if self.timing.system
                    && let Some(home) = env::var_os("HOME")
                {
                    let listing = self.observations.letters(&self.cwd, Path::new(&home));
                    self.letters = listing;
                }
                Ok(())
            }
            State::ComposeSilent
            | State::ComposePrompt
            | State::ComposeViolation
            | State::ComposeViolationAndPrompt
            | State::ComposeLapse
            | State::ComposeLapseAndViolation => self.prepare_composition(state),
            State::Toggle if self.flag == FlagState::Unknown => self.prepare_toggle(),
            State::Transcript => self.prepare_transcript(),
            State::Resolve if self.resolution == Resolution::Unknown => self.prepare_resolution(),
            _ => Ok(()),
        }
    }

    fn prepare_composition(&mut self, state: State) -> Result<(), FailureClass> {
        self.prepare_letters_block(state)
    }

    fn prepare_letters_block(&mut self, state: State) -> Result<(), FailureClass> {
        let heartbeat_failed = self.failure.take().is_some();
        self.letters_may_block = false;
        if heartbeat_failed
            || !matches!(self.letters, crate::letters::Listing::Unread(_))
            || matches!(state, State::ComposeLapse | State::ComposeLapseAndViolation)
        {
            return Ok(());
        }
        // An OFF heartbeat never needed the transcript or counter. A letters
        // block does: use the same session/turn key, never a second counter.
        if self.resolution == Resolution::Unknown {
            self.prepare_payload_fields()?;
            self.entries = self.observations.load(&self.transcript_path)?;
            self.marker = user_turn_marker(&self.entries)?;
            self.count = read_count(self.state_dir, self.session_key(), &self.marker)?;
        }
        self.letters_may_block =
            self.retry_phase == RetryPhase::Inactive && self.count < MAX_BLOCKS_PER_TURN;
        Ok(())
    }

    fn prepare_toggle(&mut self) -> Result<(), FailureClass> {
        let boundary = env::var_os("HOME").map(PathBuf::from);
        let root = project_root(Path::new(&self.cwd), boundary.as_deref());
        let flag = self.state_dir.join(format!(
            "heartbeat{}",
            root.to_string_lossy().replace('/', "-")
        ));
        self.flag = match fs::metadata(flag) {
            Ok(_) => FlagState::Present,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => FlagState::Absent,
            Err(_) => return Err(FailureClass::StateRead),
        };
        Ok(())
    }

    fn prepare_transcript(&mut self) -> Result<(), FailureClass> {
        if self.transcript_path.as_os_str().is_empty() {
            self.prepare_payload_fields()?;
        }
        if !self.timing.now.is_finite() {
            return Err(FailureClass::Clock);
        }
        self.entries = self.observations.load(&self.transcript_path)?;
        self.armed = heartbeat_armed(&self.entries, self.timing.now)?;
        Ok(())
    }

    fn prepare_payload_fields(&mut self) -> Result<(), FailureClass> {
        let fields = self.input.fields.as_ref().map_err(|failure| *failure)?;
        self.transcript_path.clone_from(&fields.transcript_path);
        self.session.clone_from(&fields.session);
        self.retry_phase = if fields.retry {
            RetryPhase::ActiveFresh
        } else {
            RetryPhase::Inactive
        };
        Ok(())
    }

    fn prepare_resolution(&mut self) -> Result<(), FailureClass> {
        let index = last_user_turn_index(&self.entries)?;
        self.marker = index.map_or_else(|| String::from("None"), |value| value.to_string());
        self.count = read_count(self.state_dir, self.session_key(), &self.marker)?;
        self.warned = read_warning(self.state_dir, self.session_key(), &self.marker)?;
        let violated = unprompted_arm_in_turn(&self.entries)?;
        self.resolution = match (self.armed, violated, self.count >= MAX_BLOCKS_PER_TURN) {
            (true, false, _) => Resolution::Armed,
            (true, true, _) => Resolution::UnpromptedArmed,
            (false, false, false) => Resolution::Prompt,
            (false, false, true) => Resolution::Lapse,
            (false, true, false) => Resolution::UnpromptedPrompt,
            (false, true, true) => Resolution::UnpromptedLapse,
        };
        Ok(())
    }

    fn guard_matches(&self, guard: Guard) -> bool {
        match guard {
            Guard::Malformed => self.classification == Classification::Malformed,
            Guard::Accepted => self.classification == Classification::Accepted,
            Guard::LettersEmpty => matches!(self.letters, crate::letters::Listing::Empty),
            Guard::LettersUnread => matches!(
                self.letters,
                crate::letters::Listing::Unread(_)
                    | crate::letters::Listing::History(_)
                    | crate::letters::Listing::Notice
            ),
            Guard::LettersFailed => matches!(self.letters, crate::letters::Listing::Failed(_)),
            Guard::NoLettersFeedback => {
                self.failure.is_none() && matches!(self.letters, crate::letters::Listing::Empty)
            }
            Guard::LettersMayBlock => self.failure.is_none() && self.letters_may_block,
            Guard::LettersNotify => {
                self.failure.is_none()
                    && !matches!(self.letters, crate::letters::Listing::Empty)
                    && !self.letters_may_block
            }
            Guard::InternalError => self.failure.is_some(),
            Guard::FlagAbsent => self.failure.is_none() && self.flag == FlagState::Absent,
            Guard::FlagPresent => self.failure.is_none() && self.flag == FlagState::Present,
            Guard::RetryNeeded => {
                self.failure.is_none() && !self.armed && self.retry_phase == RetryPhase::ActiveFresh
            }
            Guard::TranscriptReady => {
                self.failure.is_none()
                    && (self.armed || self.retry_phase != RetryPhase::ActiveFresh)
            }
            Guard::Armed => self.failure.is_none() && self.resolution == Resolution::Armed,
            Guard::Prompt => self.failure.is_none() && self.resolution == Resolution::Prompt,
            Guard::Lapse => self.failure.is_none() && self.resolution == Resolution::Lapse,
            Guard::UnpromptedArmed => {
                self.failure.is_none() && self.resolution == Resolution::UnpromptedArmed
            }
            Guard::UnpromptedPrompt => {
                self.failure.is_none() && self.resolution == Resolution::UnpromptedPrompt
            }
            Guard::UnpromptedLapse => {
                self.failure.is_none() && self.resolution == Resolution::UnpromptedLapse
            }
            Guard::WarningFresh => self.failure.is_none() && !self.warned,
            Guard::WarningRecorded => self.failure.is_none() && self.warned,
            Guard::Always => self.failure.is_none(),
        }
    }

    fn apply(&mut self, effect: Effect) -> Result<(), FailureClass> {
        match effect {
            Effect::WaitAndReload => {
                self.timing.wait_and_resample(&self.transcript_path)?;
                self.retry_phase = RetryPhase::ActiveRetried;
                self.retry_count = self.retry_count.saturating_add(1);
                self.entries.clear();
                Ok(())
            }
            Effect::RecordLettersCount if self.count_write == CountWrite::Recorded => Ok(()),
            Effect::RecordCount | Effect::RecordLettersCount => {
                if effect == Effect::RecordLettersCount {
                    fs::create_dir_all(self.state_dir).map_err(|_| FailureClass::StateWrite)?;
                }
                atomic_write(
                    &self
                        .state_dir
                        .join(format!("guard-count-{}", self.session_key())),
                    format!("{} {}", self.marker, self.count + 1).as_bytes(),
                )?;
                self.count_write = CountWrite::Recorded;
                Ok(())
            }
            Effect::RecordWarning => atomic_write(
                &self
                    .state_dir
                    .join(format!("guard-warn-{}", self.session_key())),
                self.marker.as_bytes(),
            ),
            Effect::RecordPromptMarker => {
                let Some(session) = self.session.as_deref() else {
                    return Ok(());
                };
                let timestamp = format_timestamp(self.timing.now).ok_or(FailureClass::Clock)?;
                atomic_write(
                    &self.state_dir.join(prompt_marker_file(session)),
                    timestamp.as_bytes(),
                )
            }
            Effect::AppendInternalLog => {
                if let Some(failure) = self.failure {
                    append_log(self.state_dir, failure, Some(self.session_key()));
                }
                Ok(())
            }
        }
    }
}

/// Evaluate typed observations with the existing graph and persistence rules.
#[must_use]
pub fn run(
    input: &StopInput,
    state_dir: &Path,
    timing: Timing,
    observations: &dyn Observations,
    listing: crate::letters::Listing,
) -> Evaluation {
    let graph = heartbeat_graph();
    let Some(mut current) = node_index(&graph, State::Entry) else {
        return silent_result(State::AllowSilent, vec![], 0);
    };
    let mut context = Context::new(input, state_dir, timing, observations);
    context.letters = listing;
    let mut path = vec![State::Entry];
    loop {
        let state = graph[current];
        if state.is_terminal() {
            let limit = match state {
                State::BlockLettersAndViolationAndPrompt | State::AllowLettersLapseAndViolation => {
                    18
                }
                State::BlockLettersAndPrompt
                | State::BlockLettersAndViolation
                | State::AllowLettersLapse => 19,
                _ => 20,
            };
            let feedback = context
                .letters
                .feedback(limit.min(context.letters_feedback_limit));
            return Evaluation {
                state,
                path,
                retry_count: context.retry_count,
                feedback,
            };
        }
        if let Err(failure) = context.prepare(state) {
            context.failure = Some(failure);
        }
        let Some(edge) = selected_edge(&graph, current, &context) else {
            context.failure = Some(FailureClass::Graph);
            let Some(fail_open) = node_index(&graph, State::FailOpen) else {
                return silent_result(State::AllowSilent, path, context.retry_count);
            };
            current = fail_open;
            path.push(State::FailOpen);
            continue;
        };
        let transition = edge.weight().clone();
        let destination = edge.target();
        let mut effect_failed = false;
        for effect in transition.effects {
            if let Err(failure) = context.apply(*effect) {
                context.failure = Some(failure);
                effect_failed = true;
                break;
            }
        }
        if effect_failed {
            if let Some(internal) = graph
                .edges(current)
                .find(|candidate| candidate.weight().guard == Guard::InternalError)
            {
                current = internal.target();
                path.push(graph[current]);
                continue;
            }
            context.failure = Some(FailureClass::Graph);
            let Some(fail_open) = node_index(&graph, State::FailOpen) else {
                return silent_result(State::AllowSilent, path, context.retry_count);
            };
            current = fail_open;
            path.push(State::FailOpen);
            continue;
        }
        current = destination;
        path.push(graph[current]);
    }
}

fn selected_edge<'a>(
    graph: &'a DiGraph<State, Transition>,
    current: NodeIndex,
    context: &Context<'_>,
) -> Option<petgraph::graph::EdgeReference<'a, Transition>> {
    let mut matches = graph
        .edges(current)
        .filter(|edge| context.guard_matches(edge.weight().guard));
    let selected = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some(selected)
    }
}

fn node_index(graph: &DiGraph<State, Transition>, state: State) -> Option<NodeIndex> {
    graph.node_indices().find(|index| graph[*index] == state)
}

const fn silent_result(state: State, path: Vec<State>, retry_count: u8) -> Evaluation {
    Evaluation {
        state,
        path,
        retry_count,
        feedback: String::new(),
    }
}

fn heartbeat_armed(entries: &[Entry], now: f64) -> Result<bool, FailureClass> {
    let mut results = HashMap::<String, (bool, Option<f64>)>::new();
    for entry in entries.iter().rev() {
        if entry.sidechain {
            continue;
        }
        let stamp = entry.timestamp;
        if stamp.is_some_and(|value| now - value > SEARCH_HORIZON_SECONDS) {
            return Ok(false);
        }
        if entry.user {
            for (id, success) in entry.results.as_ref().map_err(|error| *error)? {
                results.insert(
                    id.as_ref().map_err(|error| *error)?.clone(),
                    (*success, stamp),
                );
            }
        } else if entry.assistant {
            for timer in entry.timers.as_ref().map_err(|error| *error)?.iter().rev() {
                let id = timer.id.as_ref().map_err(|error| *error)?;
                let Some((true, result_stamp)) = results.get(id) else {
                    continue;
                };
                let (stop, delay) = timer.parameters?;
                if stop {
                    return Ok(false);
                }
                let Some(delay) = delay.filter(|delay| delay.is_finite()) else {
                    continue;
                };
                let Some(scheduled_at) = result_stamp.or(stamp) else {
                    continue;
                };
                return Ok(now
                    < scheduled_at
                        + delay.clamp(MIN_DELAY_SECONDS, MAX_DELAY_SECONDS)
                        + SCHEDULE_SLACK_SECONDS);
            }
        }
    }
    Ok(false)
}

fn unprompted_arm_in_turn(entries: &[Entry]) -> Result<bool, FailureClass> {
    let start = last_user_turn_index(entries)?.map_or(0, |index| index + 1);
    let turn = &entries[start..];
    let mut successful = HashSet::new();
    for entry in turn {
        if entry.sidechain || !entry.user {
            continue;
        }
        for (id, success) in entry.results.as_ref().map_err(|error| *error)? {
            if *success {
                successful.insert(id.as_ref().map_err(|error| *error)?.clone());
            }
        }
    }
    let mut prompted = false;
    for entry in turn {
        if entry.sidechain {
            continue;
        }
        if entry.feedback? {
            prompted = true;
            continue;
        }
        if prompted || !entry.assistant {
            continue;
        }
        for timer in entry.timers.as_ref().map_err(|error| *error)? {
            let (stop, _) = timer.parameters?;
            let id = timer.id.as_ref().map_err(|error| *error)?;
            if !stop && successful.contains(id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn last_user_turn_index(entries: &[Entry]) -> Result<Option<usize>, FailureClass> {
    let mut index = None;
    for (candidate, entry) in entries.iter().enumerate() {
        if entry.real_user? {
            index = Some(candidate);
        }
    }
    Ok(index)
}

/// State file name of the arm prompt marker for one session.
#[must_use]
pub fn prompt_marker_file(session: &str) -> String {
    format!("{PROMPT_MARKER_FILE}-{session}")
}

fn read_count(state_dir: &Path, session: &str, marker: &str) -> Result<i64, FailureClass> {
    let source = match fs::read_to_string(state_dir.join(format!("guard-count-{session}"))) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(FailureClass::StateRead),
    };
    let mut fields = source.split_whitespace();
    let Some(stored_marker) = fields.next() else {
        return Ok(0);
    };
    let Some(stored_count) = fields.next() else {
        return Ok(0);
    };
    if stored_marker != marker || fields.next().is_some() {
        return Ok(0);
    }
    Ok(stored_count
        .parse::<i64>()
        .ok()
        .filter(|count| *count >= 0)
        .unwrap_or(0))
}

fn read_warning(state_dir: &Path, session: &str, marker: &str) -> Result<bool, FailureClass> {
    match fs::read_to_string(state_dir.join(format!("guard-warn-{session}"))) {
        Ok(source) => Ok(source.trim() == marker),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(FailureClass::StateRead),
    }
}

fn user_turn_marker(entries: &[Entry]) -> Result<String, FailureClass> {
    Ok(last_user_turn_index(entries)?
        .map_or_else(|| String::from("None"), |index| index.to_string()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), FailureClass> {
    let Some(parent) = path.parent() else {
        return Err(FailureClass::StateWrite);
    };
    if !parent.is_dir() {
        return Err(FailureClass::StateWrite);
    }
    let temp = parent.join(format!(
        ".heartbeat-guard-{}-{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&temp, bytes).map_err(|_| FailureClass::StateWrite)?;
    fs::rename(&temp, path).map_err(|_| FailureClass::StateWrite)
}

fn append_log(state_dir: &Path, failure: FailureClass, session: Option<&str>) {
    if fs::create_dir_all(state_dir).is_err() {
        return;
    }
    let mut record = json!({"action": "internal_error", "error": failure.name()});
    if let Some(session) = session {
        record["session_id"] = Value::String(session.to_owned());
    }
    let Ok(mut bytes) = serde_json::to_vec(&record) else {
        return;
    };
    bytes.push(b'\n');
    let Ok(mut log) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir.join("orchestrator.log"))
    else {
        return;
    };
    if log.write_all(&bytes).is_ok() && log.flush().is_err() {}
}

pub fn record_payload_failure(state_dir: &Path) {
    append_log(state_dir, FailureClass::Payload, None);
}

pub fn record_panic(state_dir: &Path) {
    append_log(state_dir, FailureClass::Panic, None);
}

pub fn record_letters_listing_failure(state_dir: &Path) {
    append_log(state_dir, FailureClass::LettersListingFailed, None);
}

#[must_use]
pub fn system_now() -> Option<f64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs_f64())
}

/// Read a calendar-valid `YYYY-MM-DDTHH:MM:SS[.fraction]Z` instant.
///
/// Naive and offset civil stamps are refused with a diagnostic naming their zone
/// form. Invalid or absent time evidence never acquires an assumed timezone.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn parse_timestamp(raw: &str) -> Option<f64> {
    let Some(body) = raw.strip_suffix('Z') else {
        if raw.len() >= 19 {
            let clock = raw.get(10..).unwrap_or_default();
            let found = clock.rfind(['+', '-']).map_or_else(
                || "naive".to_owned(),
                |index| format!("offset {}", &clock[index..]),
            );
            let _written = writeln!(
                std::io::stderr(),
                "heartbeat timestamp refused: {found}; expected an explicit UTC instant ending in Z"
            );
        }
        return None;
    };
    if body.len() < 19 {
        return None;
    }
    let bytes = body.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    if !bytes.iter().enumerate().all(|(index, byte)| {
        matches!(index, 4 | 7 | 10 | 13 | 16)
            || (index == 19 && *byte == b'.')
            || byte.is_ascii_digit()
    }) || (body.len() > 19 && (bytes.get(19) != Some(&b'.') || body.len() == 20))
    {
        return None;
    }
    let year = parse_i64(body.get(0..4)?)?;
    let month = parse_i64(body.get(5..7)?)?;
    let day = parse_i64(body.get(8..10)?)?;
    let hour = parse_i64(body.get(11..13)?)?;
    let minute = parse_i64(body.get(14..16)?)?;
    let second = body.get(17..)?.parse::<f64>().ok()?;
    if year == 0
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0.0..60.0).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + hour * 3_600 + minute * 60) as f64 + second)
}

#[allow(clippy::cast_possible_truncation)]
fn format_timestamp(timestamp: f64) -> Option<String> {
    if !timestamp.is_finite() || !(0.0..=253_402_300_799.0).contains(&timestamp) {
        return None;
    }
    let seconds = timestamp.floor() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    let (year, month, day) = civil_from_days(days);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

fn parse_i64(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok()
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_from_civil(mut year: i64, month: i64, day: i64) -> i64 {
    if month <= 2 {
        year -= 1;
    }
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
