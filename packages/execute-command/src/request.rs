//! Command/context identity, implications, verdicts and caller vocabulary.
//! Harness decoding and authenticated observation construction remain caller-owned.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::escalation::{Correction, Escalation};

/// Maximum encoded envelope size, checked before JSON allocation.
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;

/// A bounded nonblank text value, not an authority assertion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct Text(String);

impl TryFrom<String> for Text {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.trim().is_empty() || value.len() > 4096 {
            Err("text must contain 1 through 4096 bytes and be nonblank")
        } else {
            Ok(Self(value))
        }
    }
}

impl From<Text> for String {
    fn from(value: Text) -> Self {
        value.0
    }
}

impl Text {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded list; an empty evidence list explicitly records no evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "Vec<Text>", into = "Vec<Text>")]
pub struct TextList(Vec<Text>);

impl TryFrom<Vec<Text>> for TextList {
    type Error = &'static str;

    fn try_from(value: Vec<Text>) -> Result<Self, Self::Error> {
        if value.len() > 64 {
            Err("list exceeds 64 entries")
        } else {
            Ok(Self(value))
        }
    }
}

impl From<TextList> for Vec<Text> {
    fn from(value: TextList) -> Self {
        value.0
    }
}

impl TextList {
    #[must_use]
    pub fn as_slice(&self) -> &[Text] {
        &self.0
    }
}

/// Caller-decoded hook observations, separate from exact command identity.
///
/// Bash and command-form Monitor map their timeout/background fields to Shell.
/// Native fields are observations, never a second shell command source. The
/// caller retains harness decoding, including Monitor's deadline bound.
#[derive(Clone, Copy, Debug)]
pub enum HygieneObservation<'a> {
    Shell {
        timeout_ms: Option<u64>,
        declared_background: Option<bool>,
    },
    Native {
        tool: &'a str,
        fields: &'a serde_json::Map<String, serde_json::Value>,
    },
}

/// Exact decoded command observations required by mechanical checks.
/// Callers with an existing envelope need not fabricate the full direct-call context.
pub trait HygieneRequest: AsRef<Binding> {
    fn command(&self) -> &Command;
    fn cwd(&self) -> &str;
}

impl HygieneRequest for Request {
    fn command(&self) -> &Command {
        self.command()
    }
    fn cwd(&self) -> &str {
        self.context().cwd.as_str()
    }
}

/// Borrowed caller-decoded command facts, bound to its authenticated observations.
pub struct CommandObservation<'a> {
    pub binding: &'a Binding,
    pub command: &'a Command,
    pub cwd: &'a str,
}

impl AsRef<Binding> for CommandObservation<'_> {
    fn as_ref(&self) -> &Binding {
        self.binding
    }
}

impl HygieneRequest for CommandObservation<'_> {
    fn command(&self) -> &Command {
        self.command
    }
    fn cwd(&self) -> &str {
        self.cwd
    }
}

/// Exact learned-index key; no normalization or prefix matching is permitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchKey {
    pub class: Text,
    pub operation: Text,
    pub shape_key: Text,
}

/// Caller-validated index evidence, including retained retired labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearnedGroup {
    pub key: MatchKey,
    pub allow: u64,
    pub refuse: u64,
    pub citations: TextList,
}

/// One caller-validated registered exact rule, separate from learned counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactRule {
    pub key: MatchKey,
    pub allow: bool,
    pub reason: Text,
}

/// Caller-read judgement evidence; None is the door's undecided or absent label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelObservation {
    pub id: Text,
    pub class: Text,
    pub adjudicated: bool,
    pub would_do: Option<Judgement>,
    pub treatment: Option<Judgement>,
}

/// A learned miss retains its reason and grants no permission or referral route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatchEvaluation {
    Undecided { reason: Text },
    Decided(Box<Verdict>),
}

/// Immutable identity that every judgement and update must bind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub request_id: Text,
    pub context_digest: Text,
}

impl AsRef<Self> for Binding {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<Binding> for Request {
    fn as_ref(&self) -> &Binding {
        self.binding()
    }
}

/// Execution representation preserves bytes and argv as different requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "representation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Bytes { bytes: Vec<u8> },
    Argv { argv: Vec<String> },
}

/// Caller-validated context; possession of these fields grants no authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub cwd: Text,
    pub requester: Text,
    pub loop_id: Text,
    #[serde(deserialize_with = "required_nullable")]
    pub lane: Option<Text>,
    #[serde(deserialize_with = "required_nullable")]
    pub run: Option<Text>,
    pub purpose: Text,
    pub deadline_unix_ms: u64,
    pub snapshot: Text,
    pub registration: Text,
    pub resources: TextList,
    pub authority: Text,
    pub checks: TextList,
    pub rubric: Text,
    pub mode: Text,
    pub floor: Text,
    pub policy: Text,
}

/// Intended effects are evidence, never a proof of confinement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Implications {
    pub effects: TextList,
    pub resources: TextList,
    pub principals: TextList,
    pub reversibility: Text,
    pub scope_uncertainty: Text,
    pub evidence: TextList,
}

/// Validated bounded request. Construction goes through the strict reader.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Request {
    schema: u32,
    binding: Binding,
    command: Command,
    context: Context,
    implications: Implications,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    schema: u32,
    binding: Binding,
    command: Command,
    context: Context,
    implications: Implications,
}

/// A stable refusal name with bounded, non-authorizing diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShapeError(pub &'static str);

impl fmt::Display for ShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ShapeError {}

impl Request {
    /// Decode only the current request shape; no predecessor fallback.
    ///
    /// # Errors
    /// Returns `execute-command-request-shape` for invalid or unbounded input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ShapeError> {
        let failure = ShapeError("execute-command-request-shape");
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(failure);
        }
        let wire: RequestWire = serde_json::from_slice(bytes).map_err(|_| failure)?;
        let valid_command = match &wire.command {
            Command::Bytes { bytes } => !bytes.is_empty() && bytes.len() <= 65_536,
            Command::Argv { argv } => {
                !argv.is_empty()
                    && argv.len() <= 64
                    && !argv[0].is_empty()
                    && argv
                        .iter()
                        .all(|arg| arg.len() <= 4096 && !arg.contains('\0'))
            }
        };
        if wire.schema != 1 || !valid_command {
            return Err(failure);
        }
        Ok(Self {
            schema: wire.schema,
            binding: wire.binding,
            command: wire.command,
            context: wire.context,
            implications: wire.implications,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> &Binding {
        &self.binding
    }

    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    #[must_use]
    pub const fn context(&self) -> &Context {
        &self.context
    }
}

/// Final judgement; undecided is an internal process step, not an allowance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Judgement {
    Allow,
    Refuse,
    Refer,
}

/// Increasing-cost deciding rungs, independent of capability or classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rung {
    DeterministicChecks,
    LearnedExactMatch,
    BoundedAgent,
    LoopReview,
    Operations,
    Owner,
}

/// A valid decision is distinct from a service failure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictStatus {
    Valid,
    AgentFailure,
    InvalidOutput,
    Timeout,
    InfrastructureFailure,
}

/// Explicit nullable fields are required, including on allowed verdicts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Verdict {
    pub binding: Binding,
    pub judgement: Judgement,
    pub tier: Rung,
    pub scope: Text,
    pub reason: Text,
    pub evidence: TextList,
    pub correction: Option<Correction>,
    pub escalation: Option<Escalation>,
    pub status: VerdictStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictWire {
    binding: Binding,
    judgement: Judgement,
    tier: Rung,
    scope: Text,
    reason: Text,
    evidence: TextList,
    #[serde(deserialize_with = "required_nullable")]
    correction: Option<Correction>,
    #[serde(deserialize_with = "required_nullable")]
    escalation: Option<Escalation>,
    status: VerdictStatus,
}

impl<'de> Deserialize<'de> for Verdict {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VerdictWire::deserialize(deserializer)?;
        let verdict = Self {
            binding: wire.binding,
            judgement: wire.judgement,
            tier: wire.tier,
            scope: wire.scope,
            reason: wire.reason,
            evidence: wire.evidence,
            correction: wire.correction,
            escalation: wire.escalation,
            status: wire.status,
        };
        verdict.validate().map_err(serde::de::Error::custom)?;
        Ok(verdict)
    }
}

pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl Verdict {
    /// Read the common verdict and enforce actionable remedies.
    ///
    /// # Errors
    /// Returns `execute-command-verdict-shape` for malformed or invalid verdicts.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ShapeError> {
        let failure = ShapeError("execute-command-verdict-shape");
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(failure);
        }
        serde_json::from_slice(bytes).map_err(|_| failure)
    }

    /// Check typed verdicts before persistence or emission.
    ///
    /// # Errors
    /// Refuses absent remedies, mismatched escalation identity or failure allowance.
    pub fn validate(&self) -> Result<(), ShapeError> {
        if (self.judgement == Judgement::Refuse
            && self.correction.is_none()
            && self.escalation.is_none())
            || (self.judgement == Judgement::Refer && self.escalation.is_none())
            || self
                .escalation
                .as_ref()
                .is_some_and(|e| e.binding != self.binding)
            || (self.status != VerdictStatus::Valid && self.judgement == Judgement::Allow)
        {
            return Err(ShapeError("execute-command-verdict-shape"));
        }
        Ok(())
    }
}
