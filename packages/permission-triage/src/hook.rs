#![deny(clippy::indexing_slicing)]

//! `PreToolUse` hook processing.
//!
//! The process boundary has two environment inputs: the ceiling read by
//! `configured_hook_ceiling` and the verified proof in `PERMISSION_TRIAGE_NESTED`.
//! `adapt_hook` itself remains a pure response adapter.

use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use execute_command::record::{HookRecordFailure, hook_record_failure};
use loop_home::allocations::{Allocations, allocations_path};
use serde_json::{Map, Value};

use crate::command_checks::{
    FastLane, MAX_MONITOR_TIMEOUT_MS, READ_ONLY_TABLE, classify_scoped, scope_words,
};
use crate::journal::{request_digest, verdict_event_id};
use crate::model::{Classification, ModelError, ModelResult, run_model_at_root};
use crate::proc;
use crate::request::{DecodeResult, PermissionRequest, Scope, decode_request};
use crate::role::{
    CallerRole, ESTATE_UID_VARIABLE, LOOP_REGISTRY_VARIABLE, Registry, RegistryError,
    effective_uid, load_registry_with_estate_uid, resolve_role,
};
use crate::rubric::{
    GENERAL_RUBRIC_DIGEST, Prompt, RubricError, RubricSource, load_rubrics_for_domain,
    rubric_root_matches, rubric_root_spans,
};

/// Maximum serialized permission-decision reason size.
pub const MAX_REASON_BYTES: usize = 1_000;
/// Maximum bytes accepted from the hook harness on standard input.
pub const MAX_HOOK_INPUT_BYTES: u64 = 1024 * 1024;
/// Harness ceiling for one complete hook invocation.
pub const HOOK_CEILING_MS: u64 = 60_000;
const HOOK_CEILING_VARIABLE: &str = "PERMISSION_TRIAGE_HOOK_CEILING_MS";
/// Required environment key selecting observation or permission enforcement.
pub const MODE_VARIABLE: &str = "PERMISSION_TRIAGE_MODE";
const NESTING_GUARD_FAILURE: &str =
    "infrastructure-failure: nesting guard failed; no policy judgment was made";
const ELLIPSIS: &str = "…";
const USAGE: &[u8] = b"usage: permission-triage hook|version\n";
const LAST_RESORT_DENY: &[u8] = b"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"infrastructure-failure: response serialization failed; no policy judgment was made\",\"additionalContext\":\"infrastructure-failure: response serialization failed; no policy judgment was made\"}}";
const LOST_AUDIT_EVENT: &[u8] =
    b"permission-triage: lost audit event: journal publication failed\n";
const CLASSIFIER_STATE_ROOT_FAILURE: &str = "infrastructure-failure: model runner failed: the classifier state root could not be established; no policy judgment was made";
const ENFORCE_JOURNAL_FAILURE: &str = "infrastructure-failure: verdict journal failed: journal-degraded evidence could not be retained; the evidence journal is degraded, and the request must be sent to the superloop orchestrator agent for adjudication";

/// Closed operating mode selected by the private instance file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Record every would-be verdict without publishing a permission decision.
    Audit,
    /// Publish the recorded permission decision.
    Enforce,
}

impl Mode {
    /// Parse the exact instance-file spelling of a mode.
    #[must_use]
    pub fn parse(value: &OsStr) -> Option<Self> {
        match value.to_str() {
            Some("audit") => Some(Self::Audit),
            Some("enforce") => Some(Self::Enforce),
            _ => None,
        }
    }

    /// Read and validate the required mode at the binary boundary.
    #[must_use]
    pub fn from_environment() -> Option<Self> {
        env::var_os(MODE_VARIABLE).as_deref().and_then(Self::parse)
    }

    /// Instance-file spelling of this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Enforce => "enforce",
        }
    }
}

/// The only two decisions emitted by the hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionDecision {
    /// Run the requested tool.
    Allow,
    /// Block the requested tool.
    Deny,
}

impl PermissionDecision {
    /// Harness spelling of this decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Wall measurements supplied by the process boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookTiming {
    wall_ms: u128,
    model_wall_ms: u128,
}

impl HookTiming {
    /// Construct measurements for one hook response.
    #[must_use]
    pub const fn new(wall_ms: u128, model_wall_ms: u128) -> Self {
        Self {
            wall_ms,
            model_wall_ms,
        }
    }
}

/// Exact structured response consumed by the hook harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookResponse {
    decision: PermissionDecision,
    reason: String,
    additional_context: String,
}

/// Process response selected only after the verdict has been published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookResponseBoundary {
    /// Successful audit completion with no permission response bytes.
    SilentSuccess,
    /// An enforce-mode permission response ready for serialization.
    SerializedDecision(HookResponse),
}

impl HookResponseBoundary {
    pub(crate) fn for_mode(mode: Mode, response: HookResponse) -> Self {
        match mode {
            Mode::Audit => Self::SilentSuccess,
            Mode::Enforce => Self::SerializedDecision(response),
        }
    }
}

impl HookResponse {
    /// Permission decision.
    #[must_use]
    pub const fn decision(&self) -> PermissionDecision {
        self.decision
    }

    /// Concise permission result.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Agent-facing result and wall measurements.
    #[must_use]
    pub fn additional_context(&self) -> &str {
        &self.additional_context
    }

    /// Serialize the exact `PreToolUse` hook envelope in contract field order.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON string serialization or output assembly fails.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let decision = serde_json::to_string(self.decision.as_str())?;
        let reason = serde_json::to_string(&self.reason)?;
        let context = serde_json::to_string(&self.additional_context)?;
        let mut output = String::with_capacity(reason.len() + context.len() + 192);
        write!(
            output,
            "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":{decision},\"permissionDecisionReason\":{reason},\"additionalContext\":{context}}}}}"
        )
        .map_err(|_error| {
            serde_json::Error::io(std::io::Error::other("hook response assembly failed"))
        })?;
        Ok(output.into_bytes())
    }
}

/// One schema-2 verdict carrying validated effect scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationRecord {
    event_id: String,
    recorded_at: String,
    recorded_at_valid: bool,
    tool_use_id: Option<String>,
    request_digest: Option<String>,
    tool: Option<String>,
    cwd: Option<String>,
    command: Option<String>,
    reason: String,
    classification: Option<String>,
    scope: Scope,
    mode: Mode,
    would_be_decision: PermissionDecision,
    emitted_decision: Option<PermissionDecision>,
    general_rubric_digest: String,
    owner_rubric_digest: Option<String>,
    role: String,
    loop_name: Option<String>,
    stale_session: bool,
    domain_rubric_digest: Option<String>,
    model_status: String,
    wall_ms: u128,
    model_wall_ms: Option<u128>,
}

impl EscalationRecord {
    /// Identity shared by the published verdict and its escalation response.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// UTC timestamp used both by this record and its event identifier seed.
    #[must_use]
    pub fn recorded_at(&self) -> &str {
        &self.recorded_at
    }

    pub(crate) const fn recorded_at_valid(&self) -> bool {
        self.recorded_at_valid
    }

    /// Harness tool-use identity.
    #[must_use]
    pub fn tool_use_id(&self) -> Option<&str> {
        self.tool_use_id.as_deref()
    }

    /// Canonical request digest, or null-equivalent when the request was unavailable.
    #[must_use]
    pub fn request_digest(&self) -> Option<&str> {
        self.request_digest.as_deref()
    }

    /// Requested tool name.
    #[must_use]
    pub fn tool(&self) -> Option<&str> {
        self.tool.as_deref()
    }

    /// Request working directory.
    #[must_use]
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    /// Exact Bash command or reduced non-Bash action retained by the journal.
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    /// Concise escalation reason returned to the issuing agent.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Policy classification attached to the escalation.
    #[must_use]
    pub fn classification(&self) -> Option<&str> {
        self.classification.as_deref()
    }

    /// Computed or validated scope for this verdict.
    #[must_use]
    pub const fn scope(&self) -> &'static str {
        self.scope.as_str()
    }

    /// Explicit hook mode active for this verdict.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Decision enforcement would publish for this verdict.
    #[must_use]
    pub const fn would_be_decision(&self) -> PermissionDecision {
        self.would_be_decision
    }

    /// Decision published by the hook, which is absent in audit mode.
    #[must_use]
    pub const fn emitted_decision(&self) -> Option<PermissionDecision> {
        self.emitted_decision
    }

    /// Digest of the embedded general rubric used for classification.
    #[must_use]
    pub fn general_rubric_digest(&self) -> &str {
        &self.general_rubric_digest
    }

    /// Digest of the optional owner rubric used for classification.
    #[must_use]
    pub fn owner_rubric_digest(&self) -> Option<&str> {
        self.owner_rubric_digest.as_deref()
    }

    /// Closed caller role used for classification.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Matched loop name for an orchestrator role.
    #[must_use]
    pub fn loop_name(&self) -> Option<&str> {
        self.loop_name.as_deref()
    }

    /// Whether the loop checkout matched with stale session corroboration.
    #[must_use]
    pub const fn stale_session(&self) -> bool {
        self.stale_session
    }

    /// Digest of the optional domain rubric used for classification.
    #[must_use]
    pub fn domain_rubric_digest(&self) -> Option<&str> {
        self.domain_rubric_digest.as_deref()
    }

    /// Stable status of the successful model invocation.
    #[must_use]
    pub fn model_status(&self) -> &str {
        &self.model_status
    }

    /// Monotonic hook wall through verdict preparation.
    #[must_use]
    pub const fn wall_ms(&self) -> u128 {
        self.wall_ms
    }

    /// Model-only wall, absent when no model process ran.
    #[must_use]
    pub const fn model_wall_ms(&self) -> Option<u128> {
        self.model_wall_ms
    }
}

/// Pure adapter output and the schema-2 verdict prepared for publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookOutcome {
    response: HookResponse,
    record: EscalationRecord,
    timing: HookTiming,
    published: bool,
}

/// Borrowed request facts used for one atomic approval lookup and consumption append.
pub struct ApprovalRequest<'a> {
    tool_use_id: &'a str,
    request_digest: &'a str,
    tool: &'a str,
    cwd: &'a str,
    command: &'a str,
    role: &'a CallerRole,
    general_rubric_digest: &'a str,
    owner_rubric_digest: Option<&'a str>,
    domain_rubric_digest: Option<&'a str>,
    mode: Mode,
    verdict: &'a EscalationRecord,
}

impl ApprovalRequest<'_> {
    /// Scope already checked by the hook before this lookup.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.verdict.scope
    }

    /// Audit looks up without consuming or publishing an allow.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Prepared enforce verdict, committed under the consumption lock.
    #[must_use]
    pub const fn verdict(&self) -> &EscalationRecord {
        self.verdict
    }

    /// Tool-use identity of the request that would consume the mark.
    #[must_use]
    pub const fn tool_use_id(&self) -> &str {
        self.tool_use_id
    }

    /// Canonical digest that must equal the approved escalation digest.
    #[must_use]
    pub const fn request_digest(&self) -> &str {
        self.request_digest
    }

    /// Requested tool name.
    #[must_use]
    pub const fn tool(&self) -> &str {
        self.tool
    }

    /// Request working directory.
    #[must_use]
    pub const fn cwd(&self) -> &str {
        self.cwd
    }

    /// Exact command or reduced action.
    #[must_use]
    pub const fn command(&self) -> &str {
        self.command
    }

    /// Main-orchestrator role required for an approval match.
    #[must_use]
    pub const fn role(&self) -> &CallerRole {
        self.role
    }

    /// Embedded general-rubric digest active for the consuming request.
    #[must_use]
    pub const fn general_rubric_digest(&self) -> &str {
        self.general_rubric_digest
    }

    /// Optional owner-rubric digest active for the consuming request.
    #[must_use]
    pub const fn owner_rubric_digest(&self) -> Option<&str> {
        self.owner_rubric_digest
    }

    /// Optional domain-rubric digest active for the consuming request.
    #[must_use]
    pub const fn domain_rubric_digest(&self) -> Option<&str> {
        self.domain_rubric_digest
    }
}

impl HookOutcome {
    /// Structured hook response.
    #[must_use]
    pub const fn response(&self) -> &HookResponse {
        &self.response
    }

    /// Suspicious-denial record for the escalation sink.
    #[must_use]
    pub fn escalation(&self) -> Option<&EscalationRecord> {
        if self.record.classification.as_deref() == Some("suspicious") {
            Some(&self.record)
        } else {
            None
        }
    }

    /// Complete verdict record published for every binary hook path.
    #[must_use]
    pub const fn record(&self) -> &EscalationRecord {
        &self.record
    }

    const fn with_scope(mut self, scope: Scope) -> Self {
        self.record.scope = scope;
        self
    }

    fn with_role_and_model(
        mut self,
        role: &CallerRole,
        model_status: &str,
        model_called: bool,
    ) -> Self {
        role.as_str().clone_into(&mut self.record.role);
        self.record.loop_name = role.loop_name().map(str::to_owned);
        self.record.stale_session = role.stale_session();
        model_status.clone_into(&mut self.record.model_status);
        self.record.model_wall_ms = model_called.then_some(self.timing.model_wall_ms);
        self
    }
}

/// Sink invoked at the process boundary for suspicious-denial records.
pub trait EscalationSink {
    /// Sink-specific failure.
    type Error;

    /// Bind state selection to the same registry snapshot as caller identity.
    fn configure(&mut self, _registry: Option<&Registry>, _role: &CallerRole) -> bool {
        true
    }

    /// Diagnostic retained when configuration fails before a journal can be selected.
    fn configuration_error(&self) -> Option<&str> {
        None
    }

    /// Duplicate the caller-loop root descriptor for classifier working-directory setup.
    fn classifier_root(&self) -> Option<File> {
        None
    }

    /// Stable label of the registered journal a scoped escalation is routed to.
    ///
    /// The label is the whole answer: an escalation reason never discloses a journal's absolute
    /// path, so producing one here would only create bytes every consumer has to remember to drop.
    fn destination(&self, _scope: Scope) -> Option<&'static str> {
        None
    }

    /// Specific infrastructure detail when a scoped verdict has no destination.
    fn record_failure_detail(&self, _scope: Scope) -> Option<&'static str> {
        None
    }

    /// Consume one schema-2 verdict record.
    ///
    /// # Errors
    ///
    /// Returns a sink-specific error when the verdict cannot be retained.
    fn record(&mut self, record: &EscalationRecord) -> Result<(), Self::Error>;

    /// Atomically consume one matching approval and return its journal event identifier.
    ///
    /// # Errors
    ///
    /// Returns a sink-specific error when the approval journal cannot be read or appended safely.
    fn consume_approval(
        &mut self,
        _request: &ApprovalRequest<'_>,
    ) -> Result<Option<String>, Self::Error> {
        Ok(None)
    }

    /// Bound sink locking from the remaining hook-ceiling duration.
    fn set_lock_budget(&mut self, _remaining: Duration) {}
}

/// Failure to form the minimum safe non-Bash model input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReductionError {
    /// A safety-relevant target is missing or has the wrong type.
    MissingSafetyTarget,
}

impl fmt::Display for ReductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSafetyTarget => write!(
                formatter,
                "a required safety-relevant target is missing or has the wrong type"
            ),
        }
    }
}

impl std::error::Error for ReductionError {}

/// Optional model-stage result supplied to the pure adapter.
#[derive(Clone, Copy, Debug)]
pub enum ModelStage<'a> {
    /// No rubric or model call was needed.
    NotRun,
    /// Valid model classification.
    Result(&'a ModelResult),
    /// Rubric configuration failure before model launch, with the rubric it concerns.
    RubricError(RubricSource, &'a RubricError),
    /// Safe action reduction failed before model launch.
    ReductionError(&'a ReductionError),
    /// Model configuration, process, deadline, or output failure.
    ModelError(&'a ModelError),
}

#[derive(Clone, Copy)]
enum ModelStatus {
    NotRun,
    Success,
    RubricError,
    ReductionError,
    ModelError,
    ScopeInvalid,
}

impl ModelStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not-run",
            Self::Success => "success",
            Self::RubricError => "rubric-error",
            Self::ReductionError => "reduction-error",
            Self::ModelError => "model-error",
            Self::ScopeInvalid => "scope-invalid",
        }
    }

    const fn model_called(self) -> bool {
        matches!(self, Self::Success | Self::ModelError | Self::ScopeInvalid)
    }
}

/// Failure while the binary reads its bounded hook input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookInputError {
    /// Standard input could not be read.
    ReadFailure,
    /// Standard input exceeded [`MAX_HOOK_INPUT_BYTES`].
    TooLarge,
}

/// Fully rendered result of one binary command invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationOutput {
    status: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Result of verifying the optional classifier-child nesting proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestingGuard {
    /// No nesting proof was supplied, so normal policy evaluation applies.
    Absent,
    /// The proof names an ancestor that is this hook executable.
    Verified,
    /// A supplied proof could not be verified and must fail closed.
    Failed,
}

/// Verify the optional nesting proof from process identity available through `/proc`.
#[must_use]
pub fn verify_nesting_guard(value: Option<&OsStr>) -> NestingGuard {
    verify_nesting_guard_with(
        value,
        || fs::read("/proc/self/stat"),
        |pid| fs::read(Path::new("/proc").join(pid.to_string()).join("stat")),
        |pid| fs::read_link(Path::new("/proc").join(pid.to_string()).join("exe")),
        env::current_exe,
    )
}

#[cfg(test)]
pub(crate) fn verify_nesting_guard_for_test(
    value: Option<&OsStr>,
    read_self_stat: impl Fn() -> io::Result<Vec<u8>>,
    read_stat: impl Fn(u32) -> io::Result<Vec<u8>>,
    read_exe: impl Fn(u32) -> io::Result<PathBuf>,
    current_exe: impl Fn() -> io::Result<PathBuf>,
) -> NestingGuard {
    verify_nesting_guard_with(value, read_self_stat, read_stat, read_exe, current_exe)
}

fn verify_nesting_guard_with(
    value: Option<&OsStr>,
    read_self_stat: impl Fn() -> io::Result<Vec<u8>>,
    read_stat: impl Fn(u32) -> io::Result<Vec<u8>>,
    read_exe: impl Fn(u32) -> io::Result<PathBuf>,
    current_exe: impl Fn() -> io::Result<PathBuf>,
) -> NestingGuard {
    let Some(value) = value else {
        return NestingGuard::Absent;
    };
    let verified = parse_nesting_token(value).is_some_and(|(pid, start_time)| {
        read_stat(pid)
            .ok()
            .and_then(|stat| proc::parent_and_start_time(&stat))
            .is_some_and(|stat| stat.start_time == start_time)
            && named_pid_is_ancestor(pid, &read_self_stat, &read_stat)
            && read_exe(pid)
                .ok()
                .zip(current_exe().ok())
                .is_some_and(|(ancestor, current)| ancestor == current)
    });
    if verified {
        NestingGuard::Verified
    } else {
        NestingGuard::Failed
    }
}

fn parse_nesting_token(value: &OsStr) -> Option<(u32, u64)> {
    let value = value.to_str()?;
    let (pid, start_time) = value.split_once(':')?;
    if !canonical_decimal(pid) || !canonical_decimal(start_time) {
        return None;
    }
    Some((pid.parse().ok()?, start_time.parse().ok()?))
}

/// One nonempty decimal field written the only way the kernel writes it.
///
/// A padded field such as `0100` parses to the same number as `100`, so accepting it would let a
/// single process identity be spelled in unboundedly many ways. The minted token never pads, so
/// refusing padding costs nothing and keeps the grammar exactly as stated.
fn canonical_decimal(field: &str) -> bool {
    !field.is_empty()
        && field.bytes().all(|byte| byte.is_ascii_digit())
        && (field.len() == 1 || !field.starts_with('0'))
}

fn named_pid_is_ancestor(
    named_pid: u32,
    read_self_stat: &impl Fn() -> io::Result<Vec<u8>>,
    read_stat: &impl Fn(u32) -> io::Result<Vec<u8>>,
) -> bool {
    let Some(mut parent_pid) = read_self_stat()
        .ok()
        .and_then(|stat| proc::parent_and_start_time(&stat))
        .map(|stat| stat.parent_pid)
    else {
        return false;
    };
    let mut visited = HashSet::new();
    loop {
        if parent_pid == named_pid {
            return true;
        }
        if parent_pid <= 1 || !visited.insert(parent_pid) {
            return false;
        }
        let Some(stat) = read_stat(parent_pid)
            .ok()
            .and_then(|stat| proc::parent_and_start_time(&stat))
        else {
            return false;
        };
        parent_pid = stat.parent_pid;
    }
}

impl InvocationOutput {
    fn published_decision(response: &HookResponse) -> Self {
        match response.to_json_bytes() {
            Ok(stdout) => Self {
                status: 0,
                stdout,
                stderr: Vec::new(),
            },
            Err(_error) => Self {
                status: 2,
                stdout: Vec::new(),
                stderr: LAST_RESORT_DENY.to_vec(),
            },
        }
    }

    /// Construct a structured exit-two denial for a process-boundary validation failure.
    #[must_use]
    pub fn fail_closed(reason: &str) -> Self {
        let response = HookResponse {
            decision: PermissionDecision::Deny,
            reason: reason.to_owned(),
            additional_context: reason.to_owned(),
        };
        match response.to_json_bytes() {
            Ok(stdout) => Self {
                status: 2,
                stdout,
                stderr: format!("{reason}\n").into_bytes(),
            },
            Err(_error) => Self {
                status: 2,
                stdout: LAST_RESORT_DENY.to_vec(),
                stderr: Vec::new(),
            },
        }
    }

    /// Process exit status.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Bytes to publish on standard output.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Bytes to publish on standard error.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

/// Execute one parsed binary invocation with environment facts supplied by the process boundary.
///
/// The binary starts its clock before input reading, reports a bounded input result, and passes
/// the untrusted nesting proof for verification only after request decoding succeeds.
#[must_use]
pub fn execute_invocation<S: EscalationSink + ?Sized>(
    mode: Mode,
    arguments: &[OsString],
    hook_input: Result<&[u8], HookInputError>,
    nesting_token: Option<&OsStr>,
    started: &Instant,
    sink: &mut S,
) -> InvocationOutput {
    match arguments {
        [command] if command == "hook" => {
            let decoded = match hook_input {
                Ok(input) => decode_request(input),
                Err(error) => {
                    let registry = load_registry_with_estate_uid(
                        env::var_os(LOOP_REGISTRY_VARIABLE),
                        env::var_os(ESTATE_UID_VARIABLE),
                    )
                    .ok()
                    .flatten()
                    .filter(|registry| !registry.entries().is_empty());
                    sink.configure(registry.as_ref(), &CallerRole::Unknown);
                    return serialize_hook_outcome(
                        mode,
                        input_failure(error, started),
                        sink,
                        started,
                    );
                }
            };
            let (role, peer_roots, registry) = match resolve_caller_context(&decoded) {
                Ok(context) => context,
                Err(detail) => {
                    let outcome = routing_failure(&decoded, started, &CallerRole::Unknown, detail);
                    return unroutable_output(mode, outcome);
                }
            };
            if !sink.configure(registry.as_ref(), &role) {
                let routing_failure = routing_failure(
                    &decoded,
                    started,
                    &role,
                    sink.configuration_error()
                        .unwrap_or("registry roots or estate selection could not be validated"),
                );
                return if sink.configuration_error().is_some() {
                    unroutable_output(mode, routing_failure)
                } else {
                    serialize_hook_outcome(mode, routing_failure, sink, started)
                };
            }
            if matches!(decoded, DecodeResult::Unclassifiable { .. }) {
                return serialize_hook_outcome(
                    mode,
                    adapt_hook_for_role(
                        &decoded,
                        None,
                        ModelStage::NotRun,
                        HookTiming::new(started.elapsed().as_millis(), 0),
                        &role,
                        &peer_roots,
                    ),
                    sink,
                    started,
                );
            }
            if role.entry().is_none() {
                return serialize_hook_outcome(
                    mode,
                    identity_failure(&decoded, started, None),
                    sink,
                    started,
                );
            }
            let outcome = match verify_nesting_guard(nesting_token) {
                NestingGuard::Verified => nested_hook_response_for_role(
                    &decoded,
                    HookTiming::new(started.elapsed().as_millis(), 0),
                    &role,
                    &peer_roots,
                ),
                NestingGuard::Failed => nesting_guard_failure(
                    &decoded,
                    HookTiming::new(started.elapsed().as_millis(), 0),
                    &role,
                ),
                NestingGuard::Absent => {
                    run_pipeline(mode, &decoded, started, sink, &role, &peer_roots)
                }
            };
            serialize_hook_outcome(mode, outcome, sink, started)
        }
        _ => execute_non_hook_invocation(arguments),
    }
}

/// Execute a binary invocation that does not enter the hook policy boundary.
#[must_use]
pub fn execute_non_hook_invocation(arguments: &[OsString]) -> InvocationOutput {
    match arguments {
        [command] if command == "version" => InvocationOutput {
            status: 0,
            stdout: format!(
                "permission-triage {} general-rubric-sha256={GENERAL_RUBRIC_DIGEST}\n",
                env!("CARGO_PKG_VERSION")
            )
            .into_bytes(),
            stderr: Vec::new(),
        },
        _ => InvocationOutput {
            status: 2,
            stdout: Vec::new(),
            stderr: USAGE.to_vec(),
        },
    }
}

fn input_failure(error: HookInputError, started: &Instant) -> HookOutcome {
    let detail = match error {
        HookInputError::ReadFailure => "standard input could not be read",
        HookInputError::TooLarge => "standard input exceeded the 1048576-byte cap",
    };
    outcome(
        PermissionDecision::Deny,
        infrastructure_reason("hook input reader", detail),
        ReasonKind::Infrastructure("hook input reader"),
        None,
        HookTiming::new(started.elapsed().as_millis(), 0),
        None,
    )
    .with_role_and_model(&CallerRole::Unknown, "input-error", false)
}

/// Fixed fail-closed response used when rendered hook output cannot be published.
#[must_use]
pub const fn last_resort_deny() -> &'static [u8] {
    LAST_RESORT_DENY
}

fn run_pipeline<S: EscalationSink + ?Sized>(
    mode: Mode,
    decoded: &DecodeResult,
    started: &Instant,
    sink: &mut S,
    role: &CallerRole,
    peer_roots: &[PathBuf],
) -> HookOutcome {
    let DecodeResult::Decoded(request) = decoded else {
        return adapt_hook_for_role(
            decoded,
            None,
            ModelStage::NotRun,
            HookTiming::new(started.elapsed().as_millis(), 0),
            role,
            peer_roots,
        );
    };
    let fast_lane = classify_scoped(
        request,
        scope_floor_with_domain(request, role, None, peer_roots).as_str(),
    );
    if !matches!(fast_lane, FastLane::ToModel) {
        return adapt_hook_for_domain(
            decoded,
            Some(&fast_lane),
            ModelStage::NotRun,
            HookTiming::new(started.elapsed().as_millis(), 0),
            role,
            None,
            peer_roots,
        );
    }

    let action = match reduced_action(request) {
        Ok(action) => action,
        Err(error) => {
            return adapt_hook_for_role(
                decoded,
                Some(&fast_lane),
                ModelStage::ReductionError(&error),
                HookTiming::new(started.elapsed().as_millis(), 0),
                role,
                peer_roots,
            );
        }
    };
    let domain_path = role.domain_rubric_path();
    let rubrics = match load_rubrics_for_domain(domain_path.as_deref()) {
        Ok(rubrics) => rubrics,
        Err((source, error)) => {
            return adapt_hook_for_role(
                decoded,
                Some(&fast_lane),
                ModelStage::RubricError(source, &error),
                HookTiming::new(started.elapsed().as_millis(), 0),
                role,
                peer_roots,
            );
        }
    };
    let role_line = role.prompt_line();
    let prompt = Prompt::build_for_role(
        &rubrics,
        &role_line,
        request.tool_name(),
        request.cwd(),
        &action,
    );
    let model_started = Instant::now();
    let result = run_model_at_root(&prompt, sink.classifier_root());
    let model_wall_ms = model_started.elapsed().as_millis();
    let timing = HookTiming::new(started.elapsed().as_millis(), model_wall_ms);
    let outcome = match &result {
        Ok(result) => adapt_hook_for_domain(
            decoded,
            Some(&fast_lane),
            ModelStage::Result(result),
            timing,
            role,
            Some(&rubrics),
            peer_roots,
        ),
        Err(error) => adapt_hook_for_domain(
            decoded,
            Some(&fast_lane),
            ModelStage::ModelError(error),
            timing,
            role,
            Some(&rubrics),
            peer_roots,
        ),
    };
    let outcome = bind_rubric_digests(outcome, &rubrics);
    if outcome.record.scope == Scope::Loop
        && outcome.record.classification.as_deref() == Some("suspicious")
        && let Some(approved) =
            consume_adjudicated_approval(sink, request, role, &rubrics, mode, &outcome, started)
    {
        return approved;
    }
    outcome
}

fn resolve_caller_context(
    decoded: &DecodeResult,
) -> Result<(CallerRole, Vec<PathBuf>, Option<Registry>), &'static str> {
    let registry = match load_registry_with_estate_uid(
        env::var_os(LOOP_REGISTRY_VARIABLE),
        env::var_os(ESTATE_UID_VARIABLE),
    ) {
        Ok(registry) => registry.filter(|registry| !registry.entries().is_empty()),
        Err(RegistryError::GenerationChanged) => return Err("loop registry generation changed"),
        Err(_error) => None,
    };
    let DecodeResult::Decoded(request) = decoded else {
        return Ok((CallerRole::Unknown, Vec::new(), registry));
    };
    if let Some(registry) = registry.as_ref() {
        validate_allocation_snapshot(registry)?;
    }
    let role = effective_uid().map_or(CallerRole::Unknown, |uid| {
        resolve_role(
            registry.as_ref(),
            uid,
            request.session_id(),
            request.cwd(),
            request.transcript_path(),
            request.agent_id_truthy(),
        )
    });
    let peers = registry.as_ref().map_or_else(Vec::new, |registry| {
        registry
            .entries()
            .iter()
            .filter(|entry| Some(entry.name()) != role.loop_name())
            .flat_map(|entry| {
                [
                    Some(entry.checkout().to_path_buf()),
                    entry.state_root().map(Path::to_path_buf),
                    entry.home().map(Path::to_path_buf),
                ]
                .into_iter()
                .flatten()
            })
            .collect()
    });
    Ok((role, peers, registry))
}

fn validate_allocation_snapshot(registry: &Registry) -> Result<(), &'static str> {
    let uid = effective_uid().map_err(|_error| "allocation snapshot identity failed")?;
    if registry
        .entries()
        .iter()
        .any(|entry| entry.worker_uids().is_some_and(|block| block.contains(uid)))
    {
        return Ok(());
    }
    let home = env::var_os("HOME").ok_or("allocation snapshot has no owner home")?;
    let path = allocations_path(Path::new(&home));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if registry
                .entries()
                .iter()
                .all(|entry| entry.worker_uids().is_none() && entry.allocation_digest().is_none())
            {
                return Ok(());
            }
        }
        Err(_error) => return Err("allocation snapshot ledger unavailable"),
        Ok(_metadata) => {}
    }
    let (allocations, source) = Allocations::read_with_source(&path)
        .map_err(|_error| "allocation snapshot ledger unavailable")?;
    let digest = crate::rubric::sha256_digest(source.as_bytes());
    for entry in registry.entries() {
        let expected = allocations.get(entry.name());
        let copied = entry.worker_uids();
        if entry.allocation_digest() != Some(digest.as_str())
            || copied.map(|block| (block.base(), block.count()))
                != expected.map(|block| (block.base, block.count))
        {
            return Err("allocation snapshot stale");
        }
    }
    Ok(())
}

fn routing_failure(
    decoded: &DecodeResult,
    started: &Instant,
    role: &CallerRole,
    detail: &str,
) -> HookOutcome {
    outcome(
        PermissionDecision::Deny,
        infrastructure_reason("state routing", detail),
        ReasonKind::Infrastructure("state routing"),
        decoded_request(decoded),
        HookTiming::new(started.elapsed().as_millis(), 0),
        None,
    )
    .with_role_and_model(role, "state-error", false)
    .with_scope(if role.entry().is_some() {
        Scope::Loop
    } else {
        Scope::Estate
    })
}

fn unroutable_output(mode: Mode, outcome: HookOutcome) -> InvocationOutput {
    match mode {
        Mode::Audit => {
            let mut stderr = outcome.response.reason.into_bytes();
            stderr.push(b'\n');
            InvocationOutput {
                status: 0,
                stdout: Vec::new(),
                stderr,
            }
        }
        Mode::Enforce => InvocationOutput::published_decision(&outcome.response),
    }
}

fn identity_failure(
    decoded: &DecodeResult,
    started: &Instant,
    analyzed: Option<HookOutcome>,
) -> HookOutcome {
    let model_wall = analyzed
        .as_ref()
        .and_then(|result| result.record.model_wall_ms);
    let mut result = outcome(
        PermissionDecision::Deny,
        infrastructure_reason(
            "caller identity",
            "no unique registered caller; enforcement is blocked",
        ),
        ReasonKind::Infrastructure("caller identity"),
        decoded_request(decoded),
        HookTiming::new(started.elapsed().as_millis(), model_wall.unwrap_or(0)),
        None,
    )
    .with_role_and_model(&CallerRole::Unknown, "identity-error", model_wall.is_some())
    .with_scope(Scope::Estate);
    if let Some(analyzed) = analyzed {
        result.record.owner_rubric_digest = analyzed.record.owner_rubric_digest;
    }
    result
}

fn consume_adjudicated_approval<S: EscalationSink + ?Sized>(
    sink: &mut S,
    request: &PermissionRequest,
    role: &CallerRole,
    rubrics: &crate::rubric::Rubrics,
    mode: Mode,
    original: &HookOutcome,
    started: &Instant,
) -> Option<HookOutcome> {
    if !role.is_orchestrator() {
        return None;
    }
    sink.set_lock_budget(configured_hook_ceiling().saturating_sub(started.elapsed()));
    let action = original.record.command.as_deref()?;
    let digest = request_digest(request.tool_name(), request.cwd(), action);
    let mut approved = bind_rubric_digests(
        outcome(
            PermissionDecision::Allow,
            "adjudicated: one identical loop request consumed its prior approval".to_owned(),
            ReasonKind::Adjudicated,
            Some(request),
            HookTiming::new(started.elapsed().as_millis(), original.timing.model_wall_ms),
            None,
        )
        .with_role_and_model(role, "journal-approval", true),
        rubrics,
    );
    approved.record.scope = Scope::Loop;
    let approval = ApprovalRequest {
        tool_use_id: request.tool_use_id(),
        request_digest: &digest,
        tool: request.tool_name(),
        cwd: request.cwd(),
        command: action,
        role,
        general_rubric_digest: GENERAL_RUBRIC_DIGEST,
        owner_rubric_digest: rubrics.owner().map(crate::rubric::OwnerRubric::digest),
        domain_rubric_digest: rubrics.domain().map(crate::rubric::OwnerRubric::digest),
        mode,
        verdict: &approved.record,
    };
    match sink.consume_approval(&approval) {
        Ok(Some(event_id)) if mode == Mode::Enforce => {
            approved.response.reason = format!(
                "adjudicated: consumed adjudicated-approved mark event_id={event_id} scope=loop"
            );
            approved.response.additional_context = format!(
                "{}; wall_ms={} model_wall_ms={}",
                approved.response.reason, approved.timing.wall_ms, approved.timing.model_wall_ms
            );
            approved.published = true;
            Some(approved)
        }
        Ok(_) => None,
        Err(_error) => Some(bind_rubric_digests(
            outcome(
                PermissionDecision::Deny,
                infrastructure_reason(
                    "adjudication journal",
                    "approval lookup or consumption could not be completed safely",
                ),
                ReasonKind::Infrastructure("adjudication journal"),
                Some(request),
                HookTiming::new(started.elapsed().as_millis(), original.timing.model_wall_ms),
                None,
            )
            .with_role_and_model(role, "journal-error", true)
            .with_scope(Scope::Loop),
            rubrics,
        )),
    }
}

fn bind_rubric_digests(mut outcome: HookOutcome, rubrics: &crate::rubric::Rubrics) -> HookOutcome {
    outcome.record.owner_rubric_digest = rubrics.owner().map(|owner| owner.digest().to_owned());
    outcome.record.domain_rubric_digest = rubrics.domain().map(|domain| domain.digest().to_owned());
    outcome
}

fn serialize_hook_outcome<S: EscalationSink + ?Sized>(
    mode: Mode,
    mut hook_outcome: HookOutcome,
    sink: &mut S,
    started: &Instant,
) -> InvocationOutput {
    if hook_outcome.record.classification.as_deref() == Some("suspicious") {
        let route = if hook_outcome.record.scope == Scope::Loop {
            "caller-loop"
        } else {
            "estate"
        };
        let destination = sink
            .destination(hook_outcome.record.scope)
            .map_or_else(String::new, |label| format!(" destination={label}"));
        let reason = format!(
            "escalation: scope={} role={} loop={} event_id={} adjudicator={route}{destination}; {}",
            hook_outcome.record.scope(),
            hook_outcome.record.role,
            hook_outcome
                .record
                .loop_name
                .as_deref()
                .unwrap_or("unknown"),
            hook_outcome.record.event_id,
            hook_outcome
                .record
                .reason
                .trim_start_matches("escalation: ")
        );
        hook_outcome.response.reason = reason;
        cap_reason(&mut hook_outcome.response.reason);
        hook_outcome.response.additional_context = format!(
            "{}; wall_ms={} model_wall_ms={}",
            hook_outcome.response.reason,
            hook_outcome.timing.wall_ms,
            hook_outcome.timing.model_wall_ms
        );
    }
    hook_outcome.record.mode = mode;
    hook_outcome.record.emitted_decision = execute_command::record::hook_emission(
        mode == Mode::Audit,
        hook_outcome.record.would_be_decision == PermissionDecision::Deny,
    )
    .map(|decision| {
        if decision == execute_command::request::Judgement::Refuse {
            PermissionDecision::Deny
        } else {
            PermissionDecision::Allow
        }
    });
    hook_outcome.record.wall_ms = started.elapsed().as_millis();
    let remaining = configured_hook_ceiling().saturating_sub(started.elapsed());
    sink.set_lock_budget(remaining);
    if !hook_outcome.published && sink.record(hook_outcome.record()).is_err() {
        let failure_detail = sink.record_failure_detail(hook_outcome.record.scope);
        return match hook_record_failure(
            mode == Mode::Audit,
            hook_outcome.response.reason == CLASSIFIER_STATE_ROOT_FAILURE,
        ) {
            HookRecordFailure::LostAuditEvent => InvocationOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: LOST_AUDIT_EVENT.to_vec(),
            },
            HookRecordFailure::RetainStateRootRefusal => {
                InvocationOutput::published_decision(&hook_outcome.response)
            }
            HookRecordFailure::Refuse => {
                let reason = failure_detail.map_or_else(
                    || ENFORCE_JOURNAL_FAILURE.to_owned(),
                    |detail| infrastructure_reason("state routing", detail),
                );
                InvocationOutput::published_decision(&HookResponse {
                    decision: PermissionDecision::Deny,
                    additional_context: format!(
                        "{reason}; wall_ms={} model_wall_ms={}",
                        started.elapsed().as_millis(),
                        hook_outcome.timing.model_wall_ms
                    ),
                    reason,
                })
            }
        };
    }

    match HookResponseBoundary::for_mode(mode, hook_outcome.response) {
        HookResponseBoundary::SilentSuccess => InvocationOutput {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
        HookResponseBoundary::SerializedDecision(response) => {
            InvocationOutput::published_decision(&response)
        }
    }
}

fn configured_hook_ceiling() -> Duration {
    Duration::from_millis(hook_ceiling_ms(
        env::var_os(HOOK_CEILING_VARIABLE).as_deref(),
    ))
}

pub(crate) fn hook_ceiling_ms(value: Option<&OsStr>) -> u64 {
    value
        .and_then(OsStr::to_str)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value <= HOOK_CEILING_MS)
        .unwrap_or(HOOK_CEILING_MS)
}

/// Adapt the decoder, fast-lane, and optional model stage into a hook response.
///
/// This function consults no process or filesystem state. A suspicious model result also returns
/// an escalation record for the process boundary to pass to [`EscalationSink`].
#[must_use]
pub fn adapt_hook(
    decoded: &DecodeResult,
    fast_lane: Option<&FastLane>,
    model: ModelStage<'_>,
    timing: HookTiming,
) -> HookOutcome {
    adapt_hook_for_role(decoded, fast_lane, model, timing, &CallerRole::Unknown, &[])
}

fn adapt_hook_for_role(
    decoded: &DecodeResult,
    fast_lane: Option<&FastLane>,
    model: ModelStage<'_>,
    timing: HookTiming,
    role: &CallerRole,
    peer_roots: &[PathBuf],
) -> HookOutcome {
    adapt_hook_for_domain(decoded, fast_lane, model, timing, role, None, peer_roots)
}

fn adapt_hook_for_domain(
    decoded: &DecodeResult,
    fast_lane: Option<&FastLane>,
    model: ModelStage<'_>,
    timing: HookTiming,
    role: &CallerRole,
    rubrics: Option<&crate::rubric::Rubrics>,
    peer_roots: &[PathBuf],
) -> HookOutcome {
    use execute_command::request::VerdictStatus;
    let request = match decoded {
        DecodeResult::Decoded(request) => request.as_ref(),
        DecodeResult::Unclassifiable { reason } => {
            return outcome(
                PermissionDecision::Deny,
                infrastructure_reason("request decoder", reason),
                ReasonKind::Infrastructure("request decoder"),
                None,
                timing,
                None,
            )
            .with_role_and_model(role, "request-invalid", false);
        }
    };

    let (adapted, model_status) = match model {
        ModelStage::RubricError(source, error) => (
            adapt_service_failure(
                request,
                rubrics,
                VerdictStatus::InfrastructureFailure,
                "rubric loader",
                rubric_error_summary(source, error),
                timing,
            ),
            ModelStatus::RubricError,
        ),
        ModelStage::ReductionError(error) => (
            adapt_service_failure(
                request,
                rubrics,
                VerdictStatus::InfrastructureFailure,
                "non-Bash action reducer",
                reduction_error_summary(*error),
                timing,
            ),
            ModelStatus::ReductionError,
        ),
        ModelStage::ModelError(error) => (
            adapt_service_failure(
                request,
                rubrics,
                model_failure_status(error),
                "model runner",
                model_error_summary(error),
                timing,
            ),
            ModelStatus::ModelError,
        ),
        ModelStage::Result(result) if matches!(fast_lane, Some(FastLane::ToModel)) => {
            adapt_model_result(request, result, timing, role, rubrics, peer_roots)
        }
        ModelStage::NotRun => (
            adapt_fast_lane(request, fast_lane, timing),
            ModelStatus::NotRun,
        ),
        ModelStage::Result(_) => (
            outcome(
                PermissionDecision::Deny,
                infrastructure_reason(
                    "hook adapter",
                    "a model result arrived outside the model-routed fast lane",
                ),
                ReasonKind::Infrastructure("hook adapter"),
                Some(request),
                timing,
                None,
            ),
            ModelStatus::Success,
        ),
    };
    let scope = match model {
        ModelStage::Result(result) if adapted.record.classification.is_some() => result.scope(),
        _ => scope_floor_with_domain(request, role, None, peer_roots),
    };
    adapted
        .with_role_and_model(role, model_status.as_str(), model_status.model_called())
        .with_scope(scope)
}

/// Return the fixed allow used when the binary observes the nesting guard.
#[must_use]
pub fn nested_hook_response(timing: HookTiming) -> HookOutcome {
    nested_hook_response_for_role(
        &DecodeResult::Unclassifiable {
            reason: "nested request facts unavailable".to_owned(),
        },
        timing,
        &CallerRole::Unknown,
        &[],
    )
}

fn nested_hook_response_for_role(
    decoded: &DecodeResult,
    timing: HookTiming,
    role: &CallerRole,
    peer_roots: &[PathBuf],
) -> HookOutcome {
    outcome(
        PermissionDecision::Allow,
        "nested invocation: classifier child hook allowed without another policy evaluation"
            .to_owned(),
        ReasonKind::Nested,
        decoded_request(decoded),
        timing,
        None,
    )
    .with_role_and_model(role, "nested", false)
    .with_scope(decoded_request(decoded).map_or(Scope::Estate, |request| {
        if peer_roots.is_empty() {
            scope_floor(request, role)
        } else {
            scope_floor_with_domain(request, role, None, peer_roots)
        }
    }))
}

fn nesting_guard_failure(
    decoded: &DecodeResult,
    timing: HookTiming,
    role: &CallerRole,
) -> HookOutcome {
    outcome(
        PermissionDecision::Deny,
        NESTING_GUARD_FAILURE.to_owned(),
        ReasonKind::Infrastructure("nesting guard"),
        decoded_request(decoded),
        timing,
        None,
    )
    .with_role_and_model(role, "nesting-guard-failed", false)
}

fn decoded_request(decoded: &DecodeResult) -> Option<&PermissionRequest> {
    match decoded {
        DecodeResult::Decoded(request) => Some(request),
        DecodeResult::Unclassifiable { .. } => None,
    }
}

/// Form the exact shell command, a reviewed minimum non-Bash action, or a value-free unknown-tool
/// description.
///
/// Every reviewed reduction below names the fields of that tool's published input schema and
/// treats each field as required or optional exactly as the schema does, because a reducer that
/// demands a field the schema calls optional denies real traffic as an infrastructure failure. A
/// tool whose schema cannot be read has no reviewed reduction and takes the unknown-tool path.
///
/// Unknown input fields are ignored. Write bodies, fetched content, prompts, reasons, environment
/// values, session data, transcripts, and prior output are never copied. The `Agent` and `Task`
/// caller-authored description is carried, because it names the objective being delegated and is
/// the one safety-relevant fact those requests would otherwise reduce away.
///
/// # Errors
///
/// Returns [`ReductionError`] when a safety-relevant target cannot be represented without copying
/// arbitrary input.
pub fn reduced_action(request: &PermissionRequest) -> Result<String, ReductionError> {
    if let Some(bash) = request.bash() {
        return Ok(bash.command().to_owned());
    }
    let input = request.tool_input();
    match request.tool_name() {
        "Read" | "Write" | "Edit" => one_string_target(request.tool_name(), input, "file_path"),
        "NotebookEdit" => {
            let mut action = one_string_target("NotebookEdit", input, "notebook_path")?;
            append_optional_string(&mut action, input, "cell_id")?;
            Ok(action)
        }
        "WebSearch" => one_string_target("WebSearch", input, "query"),
        "WebFetch" => one_string_target("WebFetch", input, "url"),
        "ScheduleWakeup" => schedule_wakeup_action(input),
        "Agent" | "Task" => subagent_action(request.tool_name(), input),
        "SendMessage" => send_message_action(input),
        "ListAgents" | "ExitPlanMode" => Ok(request.tool_name().to_owned()),
        "TaskStop" => task_stop_action(input),
        "TaskOutput" => task_output_action(input),
        "AskUserQuestion" => array_count_action("AskUserQuestion", input, "questions"),
        "ToolSearch" => one_string_target("ToolSearch", input, "query"),
        "Skill" => skill_action(input),
        "EnterWorktree" => enter_worktree_action(input),
        "ExitWorktree" => exit_worktree_action(input),
        "ListPlugins" | "ListSkills" => keywords_action(request.tool_name(), input, false),
        "SearchPlugins" | "SearchSkills" => keywords_action(request.tool_name(), input, true),
        "Artifact" => artifact_action(input),
        "Monitor" => monitor_action(input),
        tool if tool.starts_with("mcp__") => mcp_action(tool, input),
        _ => unknown_action(request.tool_name(), input),
    }
}

fn adapt_fast_lane(
    request: &PermissionRequest,
    fast_lane: Option<&FastLane>,
    timing: HookTiming,
) -> HookOutcome {
    match fast_lane {
        Some(FastLane::ReadOnlyAllow { rule })
            if READ_ONLY_TABLE
                .iter()
                .any(|entry| entry.entry == *rule && entry.accepted) =>
        {
            outcome(
                PermissionDecision::Allow,
                format!("safe: harness read-only rule {rule}"),
                ReasonKind::Class("safe"),
                Some(request),
                timing,
                None,
            )
        }
        Some(FastLane::ReadOnlyAllow { .. }) => outcome(
            PermissionDecision::Deny,
            infrastructure_reason(
                "hook adapter",
                "the read-only verdict did not name an accepted rule",
            ),
            ReasonKind::Infrastructure("hook adapter"),
            Some(request),
            timing,
            None,
        ),
        Some(FastLane::AgentError {
            rule,
            defect,
            correction,
        }) => outcome(
            PermissionDecision::Deny,
            format!("correction: {defect}; {correction}; rule={rule}"),
            ReasonKind::Correction,
            Some(request),
            timing,
            None,
        ),
        Some(FastLane::ToModel) => outcome(
            PermissionDecision::Deny,
            infrastructure_reason(
                "hook adapter",
                "the model-routed request has no model result",
            ),
            ReasonKind::Infrastructure("hook adapter"),
            Some(request),
            timing,
            None,
        ),
        None => outcome(
            PermissionDecision::Deny,
            infrastructure_reason(
                "hook adapter",
                "the decoded request has no fast-lane verdict",
            ),
            ReasonKind::Infrastructure("hook adapter"),
            Some(request),
            timing,
            None,
        ),
    }
}

const fn model_failure_status(error: &ModelError) -> execute_command::request::VerdictStatus {
    use execute_command::request::VerdictStatus;
    match error {
        ModelError::Timeout(_) | ModelError::CleanupTimeout => VerdictStatus::Timeout,
        ModelError::StdoutTooLarge(_)
        | ModelError::MalformedEnvelope(_)
        | ModelError::EnvelopeShape
        | ModelError::MalformedResult(_)
        | ModelError::SchemaMismatch(_) => VerdictStatus::InvalidOutput,
        _ => VerdictStatus::AgentFailure,
    }
}

fn adapt_service_failure(
    request: &PermissionRequest,
    rubrics: Option<&crate::rubric::Rubrics>,
    status: execute_command::request::VerdictStatus,
    stage: &'static str,
    summary: &str,
    timing: HookTiming,
) -> HookOutcome {
    use execute_command::triage::{Profile, RunnerOutcome};
    let binding = crate::command_checks::binding(request, rubrics);
    let observed = RunnerOutcome::Failure {
        status,
        reason: summary
            .to_owned()
            .try_into()
            .expect("bounded static service summary"),
    };
    let verdict =
        execute_command::triage::judge(&binding, Profile::HookSixClass, &observed, Scope::Estate);
    outcome(
        PermissionDecision::Deny,
        infrastructure_reason(stage, verdict.reason.as_str()),
        ReasonKind::Infrastructure(stage),
        Some(request),
        timing,
        None,
    )
}

fn adapt_model_result(
    request: &PermissionRequest,
    result: &ModelResult,
    timing: HookTiming,
    role: &CallerRole,
    rubrics: Option<&crate::rubric::Rubrics>,
    peer_roots: &[PathBuf],
) -> (HookOutcome, ModelStatus) {
    use execute_command::request::{Judgement, VerdictStatus};
    use execute_command::triage::{Profile, RunnerOutcome};
    let domain = rubrics.and_then(|rubrics| rubrics.domain().map(crate::rubric::OwnerRubric::text));
    let binding = crate::command_checks::binding(request, rubrics);
    let observed = RunnerOutcome::Output(serde_json::json!({"classification":result.classification().as_str(),"scope":result.scope().as_str(),"reason":result.reason()}).to_string().into_bytes());
    let verdict = execute_command::triage::judge(
        &binding,
        Profile::HookSixClass,
        &observed,
        scope_floor_with_domain(request, role, domain, peer_roots),
    );
    if verdict.status != VerdictStatus::Valid {
        return (
            outcome(
                PermissionDecision::Deny,
                infrastructure_reason("scope validation", verdict.reason.as_str()),
                ReasonKind::Infrastructure("scope validation"),
                Some(request),
                timing,
                None,
            ),
            ModelStatus::ScopeInvalid,
        );
    }
    let (decision, reason, kind) = match verdict.judgement {
        Judgement::Allow => (
            PermissionDecision::Allow,
            verdict.reason.as_str().to_owned(),
            ReasonKind::Class(result.classification().as_str()),
        ),
        Judgement::Refuse => (
            PermissionDecision::Deny,
            verdict.reason.as_str().to_owned(),
            ReasonKind::Correction,
        ),
        Judgement::Refer => {
            let reason = escalation_reason(role, result.reason());
            (
                PermissionDecision::Deny,
                reason,
                ReasonKind::Escalation(role),
            )
        }
    };
    (
        outcome(decision, reason, kind, Some(request), timing, None),
        ModelStatus::Success,
    )
}

#[derive(Clone, Copy)]
enum ReasonKind<'a> {
    Class(&'static str),
    Correction,
    Escalation(&'a CallerRole),
    Infrastructure(&'static str),
    Nested,
    Adjudicated,
}

fn outcome(
    decision: PermissionDecision,
    mut reason: String,
    kind: ReasonKind<'_>,
    request: Option<&PermissionRequest>,
    timing: HookTiming,
    _legacy_escalation: Option<EscalationRecord>,
) -> HookOutcome {
    if request.is_some_and(|request| reason_repeats_action(&reason, request)) {
        reason = command_echo_fallback(kind);
    }
    cap_reason(&mut reason);
    let action = request.map(|request| {
        reduced_action(request).unwrap_or_else(|_error| request.tool_name().to_owned())
    });
    let digest = request
        .zip(action.as_deref())
        .map(|(request, action)| request_digest(request.tool_name(), request.cwd(), action));
    let classification = match kind {
        ReasonKind::Class(classification) => Some(classification.to_owned()),
        ReasonKind::Correction => Some(Classification::AgentError.as_str().to_owned()),
        ReasonKind::Escalation(_) => Some(Classification::Suspicious.as_str().to_owned()),
        ReasonKind::Adjudicated => Some(Classification::RoutineSuperloop.as_str().to_owned()),
        ReasonKind::Infrastructure(_) | ReasonKind::Nested => None,
    };
    let role = match kind {
        ReasonKind::Escalation(role) => role,
        _ => &CallerRole::Unknown,
    };
    let record_reason = reason.clone();
    let additional_context = format!(
        "{reason}; wall_ms={} model_wall_ms={}",
        timing.wall_ms, timing.model_wall_ms
    );
    let (event_id, recorded_at, recorded_at_valid) =
        match verdict_event_id(digest.as_deref().unwrap_or("unavailable")) {
            Ok((event_id, recorded_at)) => (event_id, recorded_at, true),
            Err(_error) => (String::new(), String::new(), false),
        };
    HookOutcome {
        response: HookResponse {
            decision,
            reason,
            additional_context,
        },
        record: EscalationRecord {
            event_id,
            recorded_at,
            recorded_at_valid,
            tool_use_id: request.map(|request| request.tool_use_id().to_owned()),
            request_digest: digest,
            tool: request.map(|request| request.tool_name().to_owned()),
            cwd: request.map(|request| request.cwd().to_owned()),
            command: action,
            reason: record_reason,
            classification,
            scope: Scope::Estate,
            mode: Mode::Enforce,
            would_be_decision: decision,
            emitted_decision: Some(decision),
            general_rubric_digest: GENERAL_RUBRIC_DIGEST.to_owned(),
            owner_rubric_digest: None,
            role: role.as_str().to_owned(),
            loop_name: role.loop_name().map(str::to_owned),
            stale_session: role.stale_session(),
            domain_rubric_digest: None,
            model_status: "not-run".to_owned(),
            wall_ms: timing.wall_ms,
            model_wall_ms: None,
        },
        timing,
        published: false,
    }
}

fn infrastructure_reason(component: &str, detail: &str) -> String {
    format!("infrastructure-failure: {component} failed: {detail}; no policy judgment was made")
}

fn command_echo_fallback(kind: ReasonKind<'_>) -> String {
    match kind {
        ReasonKind::Class(class) => {
            format!("{class}: reason omitted because it repeated command text")
        }
        ReasonKind::Correction => {
            "correction: reason omitted because it repeated command text".to_owned()
        }
        ReasonKind::Escalation(role) => {
            escalation_reason(role, "reason omitted because it repeated command text")
        }
        ReasonKind::Infrastructure(component) => format!(
            "infrastructure-failure: {component} failed: response detail omitted because it repeated command text; no policy judgment was made"
        ),
        ReasonKind::Nested => {
            "nested invocation: classifier child hook allowed without another policy evaluation"
                .to_owned()
        }
        ReasonKind::Adjudicated => {
            "adjudicated: approved journal mark consumed for one identical request".to_owned()
        }
    }
}

fn escalation_reason(role: &CallerRole, detail: &str) -> String {
    execute_command::escalation::loop_review_reason(role.as_str(), role.loop_name(), detail)
}

fn reason_repeats_action(reason: &str, request: &PermissionRequest) -> bool {
    let action = reduced_action(request).ok();
    action
        .iter()
        .map(String::as_str)
        .chain(quoted_targets(request))
        .any(|value| value.len() >= 4 && reason.contains(value))
}

fn quoted_targets(request: &PermissionRequest) -> Vec<&str> {
    let fields: &[&str] = match request.tool_name() {
        "Read" | "Write" | "Edit" => &["file_path"],
        "NotebookEdit" => &["notebook_path", "cell_id"],
        "WebSearch" | "ToolSearch" => &["query"],
        "WebFetch" => &["url"],
        "Agent" | "Task" => &["subagent_type", "model", "description", "isolation"],
        "SendMessage" => &["to"],
        "TaskStop" => &["task_id", "shell_id"],
        "TaskOutput" => &["task_id"],
        "Skill" => &["skill", "args"],
        "EnterWorktree" => &["name", "path"],
        "ExitWorktree" => &["action"],
        "Artifact" => &["action", "file_path", "url"],
        _ => &[],
    };
    let mut targets = fields
        .iter()
        .filter_map(|field| request.tool_input().get(*field).and_then(Value::as_str))
        .collect::<Vec<_>>();
    match request.tool_name() {
        "ListPlugins" | "SearchPlugins" | "ListSkills" | "SearchSkills" => targets.extend(
            request
                .tool_input()
                .get("keywords")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        ),
        "Monitor" => targets.extend(
            request
                .tool_input()
                .get("ws")
                .and_then(Value::as_object)
                .and_then(|source| source.get("url"))
                .and_then(Value::as_str),
        ),
        _ => {}
    }
    if let Some(allowlist) = mcp_allowlist(request.tool_name()) {
        targets.extend(
            allowlist
                .fields
                .iter()
                .filter_map(|field| request.tool_input().get(*field))
                .filter_map(Value::as_str),
        );
    }
    targets
}

const fn rubric_error_summary(source: RubricSource, error: &RubricError) -> &'static str {
    match source {
        RubricSource::Owner => owner_rubric_error_summary(error),
        RubricSource::Domain => domain_rubric_error_summary(error),
    }
}

const fn owner_rubric_error_summary(error: &RubricError) -> &'static str {
    match error {
        RubricError::OwnerPathEncoding => "the owner-rubric path encoding is invalid",
        RubricError::OwnerPathNotAbsolute(_) => "the owner-rubric path is not absolute",
        RubricError::OwnerMetadata(_) => "owner-rubric path metadata could not be read",
        RubricError::OwnerFinalSymlink => "the owner-rubric final component is a symbolic link",
        RubricError::OwnerNotRegularFile => "the owner rubric is not a regular file",
        RubricError::OwnerOpen(_) => "the owner rubric could not be opened safely",
        RubricError::OwnerFileMetadata(_) => "opened owner-rubric file metadata could not be read",
        RubricError::OwnerTooLarge(_) => "the owner rubric exceeds its size cap",
        RubricError::OwnerRead(_) => "the owner rubric could not be read",
        RubricError::OwnerInvalidUtf8 => "the owner rubric is not valid UTF-8",
    }
}

const fn domain_rubric_error_summary(error: &RubricError) -> &'static str {
    match error {
        RubricError::OwnerPathEncoding => "the domain rubric path encoding is invalid",
        RubricError::OwnerPathNotAbsolute(_) => "the domain rubric path is not absolute",
        RubricError::OwnerMetadata(_) => "domain rubric path metadata could not be read",
        RubricError::OwnerFinalSymlink => "the domain rubric final component is a symbolic link",
        RubricError::OwnerNotRegularFile => "the domain rubric is not a regular file",
        RubricError::OwnerOpen(_) => "the domain rubric could not be opened safely",
        RubricError::OwnerFileMetadata(_) => "opened domain rubric file metadata could not be read",
        RubricError::OwnerTooLarge(_) => "the domain rubric exceeds its size cap",
        RubricError::OwnerRead(_) => "the domain rubric could not be read",
        RubricError::OwnerInvalidUtf8 => "the domain rubric is not valid UTF-8",
    }
}

const fn reduction_error_summary(error: ReductionError) -> &'static str {
    match error {
        ReductionError::MissingSafetyTarget => {
            "a required safety-relevant target is missing or invalid"
        }
    }
}

const fn model_error_summary(error: &ModelError) -> &'static str {
    match error {
        ModelError::NestedInvocation => "a nested model invocation was refused",
        ModelError::NestingTokenMint => "the classifier nesting token could not be minted",
        ModelError::InvalidIsolation(_) => "the configured model isolation mode is invalid",
        ModelError::InvalidDeadline(_) => "the configured model deadline is invalid",
        ModelError::StateRoot(_) => "the classifier state root could not be established",
        ModelError::Launch(_) => "the classifier process could not be launched",
        ModelError::PromptWrite(_) => "the classifier prompt could not be written",
        ModelError::StdinWriterPanicked => "the classifier input writer failed internally",
        ModelError::Wait(_) => "the classifier process status could not be sampled",
        ModelError::Kill(_) => "the classifier process group could not be terminated",
        ModelError::Reap(_) => "the classifier process could not be reaped",
        ModelError::CleanupTimeout => "classifier process cleanup exceeded its deadline",
        ModelError::StdoutRead(_) => "classifier standard output could not be captured",
        ModelError::StdoutReaderPanicked => "the classifier output reader failed internally",
        ModelError::NonzeroExit(_) => "the classifier process exited unsuccessfully",
        ModelError::Timeout(_) => "the classifier model deadline elapsed",
        ModelError::StdoutTooLarge(_) => "classifier standard output exceeded its size cap",
        ModelError::MalformedEnvelope(_) => "the classifier JSON envelope was malformed",
        ModelError::EnvelopeShape => "the classifier JSON envelope shape was unsupported",
        ModelError::MalformedResult(_) => "the classifier result JSON was malformed",
        ModelError::SchemaMismatch(_) => "the classifier result violated its schema",
    }
}

fn cap_reason(reason: &mut String) {
    if reason.len() <= MAX_REASON_BYTES {
        return;
    }
    let mut end = MAX_REASON_BYTES - ELLIPSIS.len();
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.truncate(end);
    reason.push_str(ELLIPSIS);
}

fn one_string_target(
    operation: &str,
    input: &Map<String, Value>,
    field: &str,
) -> Result<String, ReductionError> {
    let target = required_string(input, field)?;
    Ok(format!(
        "{operation} {field}={}",
        Value::String(target.to_owned())
    ))
}

fn append_optional_string(
    action: &mut String,
    input: &Map<String, Value>,
    field: &str,
) -> Result<(), ReductionError> {
    let Some(value) = input.get(field) else {
        return Ok(());
    };
    let value = value.as_str().ok_or(ReductionError::MissingSafetyTarget)?;
    write!(action, " {field}={}", Value::String(value.to_owned()))
        .map_err(|_error| ReductionError::MissingSafetyTarget)
}

fn append_required_string(
    action: &mut String,
    input: &Map<String, Value>,
    source_field: &str,
    action_field: &str,
) -> Result<(), ReductionError> {
    let value = required_string(input, source_field)?;
    write!(
        action,
        " {action_field}={}",
        Value::String(value.to_owned())
    )
    .map_err(|_error| ReductionError::MissingSafetyTarget)
}

fn append_optional_string_as(
    action: &mut String,
    input: &Map<String, Value>,
    source_field: &str,
    action_field: &str,
) -> Result<(), ReductionError> {
    let Some(value) = input.get(source_field) else {
        return Ok(());
    };
    let value = value.as_str().ok_or(ReductionError::MissingSafetyTarget)?;
    write!(
        action,
        " {action_field}={}",
        Value::String(value.to_owned())
    )
    .map_err(|_error| ReductionError::MissingSafetyTarget)
}

fn append_optional_bool(
    action: &mut String,
    input: &Map<String, Value>,
    field: &str,
) -> Result<(), ReductionError> {
    let Some(value) = input.get(field) else {
        return Ok(());
    };
    let value = value.as_bool().ok_or(ReductionError::MissingSafetyTarget)?;
    write!(action, " {field}={value}").map_err(|_error| ReductionError::MissingSafetyTarget)
}

fn append_optional_u64(
    action: &mut String,
    input: &Map<String, Value>,
    field: &str,
) -> Result<(), ReductionError> {
    let Some(value) = input.get(field) else {
        return Ok(());
    };
    let value = value.as_u64().ok_or(ReductionError::MissingSafetyTarget)?;
    write!(action, " {field}={value}").map_err(|_error| ReductionError::MissingSafetyTarget)
}

fn required_string<'a>(
    input: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, ReductionError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ReductionError::MissingSafetyTarget)
}

/// Decide whether a JSON value is truthy, by the same rule this repository's heartbeat guard uses.
///
/// That guard reads the `stop` field of this same `ScheduleWakeup` traffic by truthiness rather
/// than by strict boolean type, so a request the guard already treats as a disarm has to reduce as
/// one here. A stricter reducer would deny as an infrastructure failure exactly the shape the
/// guard accepts, on the one tool the live registration has been exercised against.
fn json_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_none_or(|number| number != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
    }
}

/// Reduce a `ScheduleWakeup` request to the disarm flag or the delay it names.
///
/// The schema requires no field: a call either carries `stop` alone to cancel a pending wakeup or
/// carries a delay with the prompt, reason, and no-op flag that describe the work it will resume.
/// Only the disarm flag and the delay are shape facts; the prompt and reason are caller-authored
/// text the gate must not ingest, and a request naming neither form is a bare arm rather than a
/// malformed one.
///
/// The delay is any finite JSON number and is rendered exactly as it arrived, because the guard
/// reading this same field accepts a fractional delay and a reducer that demanded a whole number
/// would deny a request the rest of the estate treats as ordinary.
fn schedule_wakeup_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    if json_truthy(input.get("stop")) {
        return Ok("ScheduleWakeup stop=true".to_owned());
    }
    let mut action = "ScheduleWakeup".to_owned();
    let Some(delay) = input.get("delaySeconds") else {
        return Ok(action);
    };
    let Value::Number(delay) = delay else {
        return Err(ReductionError::MissingSafetyTarget);
    };
    if delay.as_f64().is_none_or(|delay| !delay.is_finite()) {
        return Err(ReductionError::MissingSafetyTarget);
    }
    write!(action, " delaySeconds={delay}")
        .map_err(|_error| ReductionError::MissingSafetyTarget)?;
    Ok(action)
}

/// Reduce a `TaskOutput` request to the task it reads and the filters it applies.
///
/// The schema requires `task_id` and defaults `block` and `timeout`, so their absence is an
/// omitted default rather than a malformed request. The retrieved output is never carried.
fn task_output_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = one_string_target("TaskOutput", input, "task_id")?;
    append_optional_bool(&mut action, input, "block")?;
    append_optional_u64(&mut action, input, "timeout")?;
    Ok(action)
}

/// Reduce a request whose safety-relevant shape is how many items it carries.
///
/// `AskUserQuestion` requires its `questions` array, so an absent or non-array value cannot form a
/// safe action. The question, header, and option text is presentation directed at a person rather
/// than a target, so only the count is carried.
fn array_count_action(
    operation: &str,
    input: &Map<String, Value>,
    field: &str,
) -> Result<String, ReductionError> {
    let count = input
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or(ReductionError::MissingSafetyTarget)?;
    Ok(format!("{operation} {field}={count}"))
}

/// Reduce an `Agent` or legacy `Task` request.
///
/// The schema requires only `description` and `prompt`; `subagent_type`, `model`, `isolation`, and
/// `run_in_background` are optional, so their absence is an ordinary omitted-default request and
/// not a malformed one. Only the prompt's byte length is carried, because the length is a shape
/// fact while the body is assembled from caller context the gate must not ingest.
fn subagent_action(operation: &str, input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = operation.to_owned();
    append_optional_string(&mut action, input, "subagent_type")?;
    append_optional_string(&mut action, input, "model")?;
    append_required_string(&mut action, input, "description", "description")?;
    append_optional_string(&mut action, input, "isolation")?;
    append_optional_bool(&mut action, input, "run_in_background")?;
    let prompt = required_string(input, "prompt")?;
    write!(action, " prompt_bytes={}", prompt.len())
        .map_err(|_error| ReductionError::MissingSafetyTarget)?;
    Ok(action)
}

/// Reduce a `SendMessage` request to its addressee and message size.
///
/// The schema names the addressee `to` and the body `message`, both required, with an optional
/// `summary` label and an optional `notify_when_idle` subscription flag. The summary is a
/// transcript label rather than a target, so it is omitted alongside the body.
fn send_message_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let target = required_string(input, "to")?;
    let message = required_string(input, "message")?;
    let mut action = format!(
        "SendMessage to={} message_bytes={}",
        Value::String(target.to_owned()),
        message.len()
    );
    append_optional_bool(&mut action, input, "notify_when_idle")?;
    Ok(action)
}

/// Reduce a `TaskStop` request to whichever identifier it carries.
///
/// The schema requires neither field: `task_id` is the current spelling and `shell_id` is its
/// deprecated alias, so a request naming either is well formed and a request naming neither is a
/// bare stop rather than a malformed one.
fn task_stop_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = "TaskStop".to_owned();
    let field = if input.contains_key("task_id") {
        "task_id"
    } else {
        "shell_id"
    };
    append_optional_string(&mut action, input, field)?;
    Ok(action)
}

fn skill_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = "Skill".to_owned();
    append_required_string(&mut action, input, "skill", "name")?;
    append_optional_string_as(&mut action, input, "args", "arguments")?;
    Ok(action)
}

/// Reduce an `EnterWorktree` request to the worktree it names.
///
/// The schema carries `name` for a worktree to create and `path` for an existing one to enter,
/// both optional and mutually exclusive; it has no branch field, so the branch a worktree ends up
/// on is not something the request states.
fn enter_worktree_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = "EnterWorktree".to_owned();
    append_optional_string(&mut action, input, "name")?;
    append_optional_string(&mut action, input, "path")?;
    Ok(action)
}

/// Reduce an `ExitWorktree` request to its disposition.
///
/// The schema requires `action`, which chooses between keeping and deleting the worktree and its
/// branch, and carries an optional `discard_changes` flag that decides whether that deletion may
/// proceed over uncommitted work. Both are the safety-relevant facts of the request.
fn exit_worktree_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = one_string_target("ExitWorktree", input, "action")?;
    append_optional_bool(&mut action, input, "discard_changes")?;
    Ok(action)
}

/// Reduce a plugin or skill listing or search to its keyword array.
///
/// The two search tools require `keywords` and the two listing tools treat it as an optional
/// filter, so `required` follows the schema of the tool being reduced. The array is rendered as
/// JSON so every element stays individually escaped and no element can forge the separator.
fn keywords_action(
    operation: &str,
    input: &Map<String, Value>,
    required: bool,
) -> Result<String, ReductionError> {
    let Some(value) = input.get("keywords") else {
        if required {
            return Err(ReductionError::MissingSafetyTarget);
        }
        return Ok(operation.to_owned());
    };
    let keywords = value
        .as_array()
        .ok_or(ReductionError::MissingSafetyTarget)?
        .iter()
        .map(|keyword| {
            keyword
                .as_str()
                .map(|keyword| Value::String(keyword.to_owned()))
                .ok_or(ReductionError::MissingSafetyTarget)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("{operation} keywords={}", Value::Array(keywords)))
}

/// Reduce an `Artifact` request to the operation and the targets it names.
///
/// Every field of the schema is optional, and an absent `action` means the default publish, so a
/// request without one is well formed and carries the operation implicitly. Page content, title,
/// and description text stay out of the action.
fn artifact_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    let mut action = "Artifact".to_owned();
    append_optional_string(&mut action, input, "action")?;
    append_optional_string(&mut action, input, "file_path")?;
    append_optional_string(&mut action, input, "url")?;
    Ok(action)
}

/// Reduce a `Monitor` request to the command it runs or the WebSocket it opens.
///
/// The command form's canonical action is the bare command, so it reaches the same shell analysis
/// a Bash command reaches. The WebSocket form runs no command at all; its safety-relevant target
/// is the URL being subscribed to, which is a reviewable action rather than a gate malfunction.
fn monitor_action(input: &Map<String, Value>) -> Result<String, ReductionError> {
    if input
        .get("description")
        .is_some_and(|value| !value.is_string())
        || input.get("timeout_ms").is_some_and(|value| {
            value
                .as_u64()
                .is_none_or(|timeout| timeout > MAX_MONITOR_TIMEOUT_MS)
        })
        || input
            .get("persistent")
            .is_some_and(|value| !value.is_boolean())
    {
        return Err(ReductionError::MissingSafetyTarget);
    }
    if let Some(source) = input.get("ws") {
        let source = source
            .as_object()
            .ok_or(ReductionError::MissingSafetyTarget)?;
        let url = required_string(source, "url")?;
        return Ok(format!("Monitor ws={}", Value::String(url.to_owned())));
    }
    Ok(required_string(input, "command")?.to_owned())
}

#[derive(Clone, Copy)]
struct McpAllowlist {
    server: &'static str,
    fields: &'static [&'static str],
}

const MCP_SCALAR_ALLOWLISTS: &[McpAllowlist] = &[McpAllowlist {
    server: "filesystem",
    fields: &["path"],
}];

fn mcp_allowlist(tool_name: &str) -> Option<McpAllowlist> {
    let (server, _tool) = mcp_parts(tool_name)?;
    MCP_SCALAR_ALLOWLISTS
        .iter()
        .copied()
        .find(|allowlist| allowlist.server == server)
}

fn mcp_action(tool_name: &str, input: &Map<String, Value>) -> Result<String, ReductionError> {
    let Some((server, tool)) = mcp_parts(tool_name) else {
        return unknown_action(tool_name, input);
    };
    let Some(allowlist) = mcp_allowlist(tool_name) else {
        return unknown_action(tool_name, input);
    };
    let mut action = format!("mcp {server} {tool}");
    for field in allowlist.fields {
        append_optional_string(&mut action, input, field)?;
    }
    Ok(action)
}

/// Split an MCP tool name into its server and tool segments.
///
/// The tool name is taken from the last separator so the server segment is anchored to the whole
/// prefix, and a server segment that still contains a separator is rejected rather than split
/// again. Without that anchor, `mcp__filesystem__x__tool` would read as server `filesystem`, and a
/// server whose own name embeds the separator could borrow another server's reviewed allowlist.
fn mcp_parts(tool_name: &str) -> Option<(&str, &str)> {
    let (server, tool) = tool_name.strip_prefix("mcp__")?.rsplit_once("__")?;
    (!server.is_empty() && !tool.is_empty() && !server.contains("__")).then_some((server, tool))
}

fn unknown_action(tool_name: &str, input: &Map<String, Value>) -> Result<String, ReductionError> {
    if tool_name.is_empty() {
        return Err(ReductionError::MissingSafetyTarget);
    }
    let mut fields = input.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();
    let fields = fields
        .into_iter()
        .map(|field| Value::String(field.to_owned()))
        .collect::<Vec<_>>();
    Ok(format!("{tool_name} fields={}", Value::Array(fields)))
}

/// Conservative target floor; model policy may raise loop to estate, never lower estate.
pub(crate) fn scope_floor(request: &PermissionRequest, role: &CallerRole) -> Scope {
    scope_floor_with_domain(request, role, None, &[])
}

struct ScopeContext<'a> {
    cwd: &'a Path,
    checkout: &'a Path,
    own_runs: Option<PathBuf>,
    domain: Option<&'a str>,
    protected: Vec<PathBuf>,
    peer_roots: &'a [PathBuf],
}

fn scope_floor_with_domain(
    request: &PermissionRequest,
    role: &CallerRole,
    domain: Option<&str>,
    peer_roots: &[PathBuf],
) -> Scope {
    let Some(entry) = role.entry() else {
        return Scope::Estate;
    };
    let mut protected = ["PERMISSION_TRIAGE_OWNER_RUBRIC", LOOP_REGISTRY_VARIABLE]
        .iter()
        .filter_map(env::var_os)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if let Some(domain_path) = role.domain_rubric_path() {
        protected.push(domain_path);
    }
    let context = ScopeContext {
        cwd: Path::new(request.cwd()),
        checkout: entry.checkout(),
        own_runs: entry.home().map(|home| home.join("runs")),
        domain,
        protected,
        peer_roots,
    };
    if let Some(command) = request.bash().map(crate::BashInput::command).or_else(|| {
        (request.tool_name() == "Monitor")
            .then(|| request.tool_input().get("command").and_then(Value::as_str))
            .flatten()
    }) {
        return shell_scope(command, &context);
    }
    let fields: &[&str] = match request.tool_name() {
        "Read" | "Write" | "Edit" => &["file_path"],
        "NotebookEdit" => &["notebook_path"],
        "Glob" | "Grep" => &["path"],
        "Agent" | "Task" | "SendMessage" | "ScheduleWakeup" | "TaskOutput" | "ListAgents"
        | "TaskStop" | "AskUserQuestion" | "TodoWrite" | "EnterPlanMode" | "ExitPlanMode" => &[],
        _ => return Scope::Estate,
    };
    for field in fields {
        match request.tool_input().get(*field) {
            Some(Value::String(path)) if local_scope_path(path, &context) => {}
            None if matches!(request.tool_name(), "Glob" | "Grep") => {}
            _ => return Scope::Estate,
        }
    }
    Scope::Loop
}

fn shell_scope(command: &str, context: &ScopeContext<'_>) -> Scope {
    let Some(words) = scope_words(command) else {
        return Scope::Estate;
    };
    if words.windows(2).any(|pair| {
        pair.first().is_some_and(|word| word == "git")
            && pair.get(1).is_some_and(|word| word == "config")
    }) {
        return Scope::Estate;
    }
    if estate_operation(&words) {
        return Scope::Estate;
    }
    for word in &words {
        if (!word.starts_with('-') || word.contains('=') || word.contains('/'))
            && !local_scope_path(word, context)
        {
            return Scope::Estate;
        }
    }
    Scope::Loop
}

fn estate_operation(words: &[String]) -> bool {
    words.iter().any(|word| {
        let word = operation_name(word);
        word.starts_with("PERMISSION_TRIAGE_")
            || word.starts_with("LOOP_")
            || matches!(
                word,
                "bypassPermissions"
                    | "--dangerously-skip-permissions"
                    | "--settings"
                    | "sudo"
                    | "su"
                    | "doas"
                    | "useradd"
                    | "usermod"
                    | "userdel"
                    | "groupadd"
                    | "groupmod"
                    | "groupdel"
                    | "passwd"
                    | "chpasswd"
                    | "visudo"
                    | "systemctl"
                    | "service"
                    | "iptables"
                    | "nft"
                    | "ufw"
                    | "firewall-cmd"
                    | "nmcli"
                    | "sysctl"
                    | "mount"
                    | "umount"
                    | "apt"
                    | "apt-get"
                    | "dnf"
                    | "yum"
                    | "pacman"
                    | "rustup"
                    | "podman"
                    | "docker"
                    | "toolbox"
                    | "flatpak"
                    | "crontab"
                    | "chsh"
                    | "ssh-keygen"
                    | "lane-gateway"
            )
    }) || words.windows(2).any(|pair| {
        let [first, second] = pair else {
            return false;
        };
        matches!(
            (operation_name(first), second.as_str()),
            ("cargo" | "pip" | "pip3", "install") | ("npm", "-g") | ("gh", "auth")
        )
    }) || words.windows(3).any(|triple| {
        let [first, second, third] = triple else {
            return false;
        };
        operation_name(first) == "npm"
            && matches!(second.as_str(), "install" | "i")
            && matches!(third.as_str(), "-g" | "--global")
    })
}

fn operation_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn protected_component(component: &str) -> bool {
    matches!(
        component,
        "AGENTS.md"
            | "CLAUDE.md"
            | "SKILL.md"
            | ".agents"
            | ".ssh"
            | ".gnupg"
            | "hooks"
            | "rubrics"
            | "loops.d"
            | "registry"
            | "ssh_config"
            | "authorized_keys"
            | "sudoers"
            | "settings.json"
            | "settings.local.json"
            | "config.toml"
            | "auth.json"
            | ".credentials.json"
            | "credentials.json"
            | "domain.md"
            | "owner.md"
            | "general.md"
            | ".gitconfig"
    )
}

fn protected_component_pair(first: &str, second: &str) -> bool {
    first == ".config"
        && matches!(
            second,
            "loops" | "gnupg" | "codex" | "gpg-loops" | "gh-loops" | "custody"
        )
}

// Host configuration and system installation roots remain estate-owned even when a reviewed
// domain mentions them. Check absolute components, not names within a loop's own checkout.
fn estate_path(path: &Path) -> bool {
    [
        "/etc",
        "/proc",
        "/sys",
        "/boot",
        "/dev",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/var/lib",
        "/var/run",
        "/run/systemd",
    ]
    .iter()
    .any(|root| path.starts_with(root))
}

fn local_scope_path(value: &str, context: &ScopeContext<'_>) -> bool {
    let cwd = context.cwd;
    let checkout = context.checkout;
    let value = value.split_once('=').map_or(value, |(_, target)| target);
    if matches!(
        value,
        "/dev/null" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr"
    ) {
        return true;
    }
    if value.is_empty() || value.contains(['$', '`', '*', '?', '~', '@']) || value.contains("://") {
        return false;
    }
    let path = Path::new(value);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut normalized = std::path::PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => return false,
            Component::CurDir => {}
            _ => normalized.push(component.as_os_str()),
        }
    }
    if estate_path(&normalized)
        || permission_settings_path(&normalized)
        || protected_name_outside_checkout(&normalized, checkout)
        || context
            .protected
            .iter()
            .any(|protected| normalized.starts_with(protected))
        || peer_owned_path(&normalized, context)
    {
        return false;
    }
    let domain_target = context
        .domain
        .is_some_and(|domain| domain_path_candidate(domain, &normalized));
    if !normalized.starts_with(checkout)
        && !context
            .own_runs
            .as_deref()
            .is_some_and(|runs| normalized.starts_with(runs))
        && !domain_target
    {
        return false;
    }
    // Follow existing ancestors only to check containment, including a final symlink.
    let mut ancestor = normalized.as_path();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                return fs::canonicalize(ancestor).is_ok_and(|real| {
                    let Ok(suffix) = normalized.strip_prefix(ancestor) else {
                        return false;
                    };
                    let resolved = real.join(suffix);
                    (resolved.starts_with(checkout)
                        || context
                            .own_runs
                            .as_deref()
                            .is_some_and(|runs| resolved.starts_with(runs))
                        || context
                            .domain
                            .is_some_and(|domain| domain_path_candidate(domain, &resolved)))
                        && !estate_path(&resolved)
                        && !permission_settings_path(&resolved)
                        && !protected_name_outside_checkout(&resolved, checkout)
                        && !context
                            .protected
                            .iter()
                            .any(|protected| resolved.starts_with(protected))
                        && !peer_owned_path(&resolved, context)
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = ancestor.parent() else {
                    return false;
                };
                ancestor = parent;
            }
            Err(_) => return false,
        }
    }
}

fn peer_owned_path(path: &Path, context: &ScopeContext<'_>) -> bool {
    // Deployment validation refuses a launch directory inside a registered home ("LOOP_CWD is
    // inside registered LOOP_HOME"), equal or nested launch directories ("LOOP_CWD overlaps
    // registered LOOP_CWD"), and a launch directory inside a peer's state root because that root
    // would contain the loop's registered rubrics beneath local/permissions/ ("loop state root
    // contains registered rubric of"). Journal configuration fails closed before a verdict if
    // any of these shapes reaches this path.
    context.peer_roots.iter().any(|peer| path.starts_with(peer))
}

fn permission_settings_path(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|component| matches!(component, "settings.json" | "settings.local.json"))
    })
}

fn protected_name_outside_checkout(path: &Path, checkout: &Path) -> bool {
    if path.starts_with(checkout) {
        return false;
    }
    let components = path
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components
        .iter()
        .any(|component| component.is_some_and(protected_component))
        || components.windows(2).any(|pair| {
            matches!(pair, [Some(first), Some(second)] if protected_component_pair(first, second))
        })
}

// This is only evidence that a model may classify a target inside reviewed domain data. It never
// grants an allow, and protected paths, peer roots and scope ambiguity still override the model.
fn domain_path_candidate(domain: &str, path: &Path) -> bool {
    rubric_root_spans(domain).any(|root| rubric_root_matches(root, path, false))
}
