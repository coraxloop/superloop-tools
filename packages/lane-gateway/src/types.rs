use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

const REGISTRATION_SCHEMA: u32 = 1;
const REQUEST_SCHEMA: u32 = 1;
const PROPOSAL_STATE_SCHEMA: u32 = 1;
const SERVE_HEARTBEAT_SCHEMA: u32 = 1;
const SERVE_CRASH_SCHEMA: u32 = 1;
pub const RESULT_SCHEMA: u32 = 2;
pub const AUDIT_SCHEMA: u32 = 2;
const DEFAULT_RUN_CAP: u32 = 20;
const DEFAULT_COOLDOWN_SECONDS: u64 = 5;
const DEFAULT_PROPOSAL_TIMEOUT_SECONDS: u64 = 600;
const REQUEST_FIELDS: [&str; 8] = [
    "schema",
    "seq",
    "op",
    "command",
    "argv",
    "reason",
    "proposal_lane",
    "proposal_seq",
];
const REQUIRED_COMMANDS: [&str; 6] = [
    "clippy",
    "clippy-fix-diff",
    "corpus-names",
    "fmt-check",
    "fmt-diff",
    "test",
];

/// Latest process heartbeat published by one serve generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServeHeartbeat {
    /// Heartbeat schema version.
    pub schema: u32,
    /// Operating-system process identifier of the serving generation.
    pub pid: u32,
    /// Milliseconds since the Unix epoch when this serve generation started.
    pub started_unix_ms: u64,
    /// Milliseconds since the Unix epoch when this heartbeat was written.
    pub heartbeat_unix_ms: u64,
    /// Cadence in milliseconds at which this generation republishes.
    ///
    /// A reader that never saw the serve's configuration needs the cadence to
    /// tell a busy host from a dead one, so the generation publishes its own.
    pub heartbeat_interval_millis: u64,
    /// Milliseconds since the Unix epoch of the latest useful activity.
    pub last_activity_unix_ms: u64,
    /// Whether this generation is running or stopped.
    pub process_state: ServeProcessState,
    /// Why this generation stopped, present exactly when it is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<ServeStopReason>,
    /// Latest useful activity completed or begun by this generation.
    pub activity: ServeActivity,
    /// Lane associated with the latest request activity, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    /// Sequence associated with the latest request activity, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

impl ServeHeartbeat {
    pub(crate) const fn new(
        pid: u32,
        started_unix_ms: u64,
        heartbeat_interval_millis: u64,
    ) -> Self {
        Self {
            schema: SERVE_HEARTBEAT_SCHEMA,
            pid,
            started_unix_ms,
            heartbeat_unix_ms: started_unix_ms,
            heartbeat_interval_millis,
            last_activity_unix_ms: started_unix_ms,
            process_state: ServeProcessState::Running,
            stop_reason: None,
            activity: ServeActivity::Started,
            lane: None,
            seq: None,
        }
    }
}

/// Process state carried by the fixed serve heartbeat.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServeProcessState {
    /// The serve generation is expected to keep publishing heartbeats.
    Running,
    /// The serve generation recorded its own stop and publishes no more.
    Stopped,
}

/// Why one serve generation stopped publishing.
///
/// Every exit a process can observe about itself is named here. The exits it
/// cannot observe — a kill signal, a suspended host — leave no reason at all,
/// which is why the heartbeat also carries the pid and cadence a reader needs
/// to reach its own verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServeStopReason {
    /// The configured shutdown flag ended the loop.
    ShutdownFlag,
    /// SIGTERM was delivered and the loop stopped at its next check.
    SignalTerminate,
    /// SIGINT was delivered and the loop stopped at its next check.
    SignalInterrupt,
    /// SIGHUP was delivered and the loop stopped at its next check.
    SignalHangup,
    /// The supervised loop returned a gateway error.
    Error,
    /// The supervised loop unwound with a panic payload.
    Panic,
}

/// Verdict a reader draws from one published serve heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeLiveness {
    /// The publishing process is alive and its heartbeat is current.
    Alive,
    /// The generation recorded its own stop, so no further beat is due.
    Stopped,
    /// No further heartbeat will arrive and none recorded why.
    Dead(ServeDeathReason),
}

/// What makes a heartbeat that still claims to be running a dead serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeDeathReason {
    /// The publishing process no longer exists.
    ProcessGone,
    /// The process exists but has not published within twice its cadence.
    HeartbeatStale,
}

/// Safe, typed serve-loop activity carried by the fixed heartbeat.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServeActivity {
    /// The heartbeat publisher started before registration scanning.
    Started,
    /// A lane request is about to be processed.
    RequestStarted,
    /// A request result was published to the worker protocol directory.
    ResultPublished,
    /// Open proposal projections were reconciled before request polling.
    ProposalReconciled,
    /// A stale action lock was reaped before request polling.
    ActionLockReaped,
    /// The configured shutdown flag ended the serve loop cleanly.
    CleanShutdown,
    /// A delivered watched signal ended the serve loop.
    SignalStop,
}

/// Latest reported failure of one serve generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServeCrashReport {
    /// Crash-report schema version.
    pub schema: u32,
    /// Operating-system process identifier of the failed generation.
    pub pid: u32,
    /// Milliseconds since the Unix epoch when this serve generation started.
    pub started_unix_ms: u64,
    /// Milliseconds since the Unix epoch when the failure was reported.
    pub failed_unix_ms: u64,
    /// Milliseconds since the Unix epoch of the latest useful activity.
    pub last_activity_unix_ms: u64,
    /// Whether a returned error or an unwind panic ended the serve loop.
    pub failure_kind: ServeFailureKind,
    /// Safe failure diagnostic without request-controlled context.
    pub message: String,
}

impl ServeCrashReport {
    pub(crate) const fn new(
        pid: u32,
        started_unix_ms: u64,
        failed_unix_ms: u64,
        last_activity_unix_ms: u64,
        failure_kind: ServeFailureKind,
        message: String,
    ) -> Self {
        Self {
            schema: SERVE_CRASH_SCHEMA,
            pid,
            started_unix_ms,
            failed_unix_ms,
            last_activity_unix_ms,
            failure_kind,
            message,
        }
    }
}

/// Failure class carried by the fixed serve crash report.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServeFailureKind {
    /// The supervised serve loop returned a gateway error.
    Error,
    /// The supervised serve loop unwound with a panic payload.
    Panic,
}

/// One orchestrator-approved lane registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Registration schema version. Only version one is accepted.
    pub schema: u32,
    /// Stable lane name, also used as the state-file stem.
    pub lane: String,
    /// Absolute host path of the worker-owned worktree.
    pub worktree: PathBuf,
    /// Workspace packages the lane may affect.
    pub packages: Vec<String>,
    /// Commit from which push-time scope is measured.
    pub base_commit: String,
    /// Opaque Git remote specification for the lane mirror.
    pub mirror_remote: String,
    /// Absolute checkout path interpreted by the configured runner.
    pub mirror_checkout: PathBuf,
    /// Complete fixed-argument command roster.
    pub commands: BTreeMap<String, CommandSpec>,
    /// Lane-wide run and cooldown budgets.
    #[serde(default)]
    pub budgets: BudgetPolicy,
    /// Maximum time a proposal may await a verdict.
    #[serde(default = "default_proposal_timeout_seconds")]
    pub proposal_timeout_seconds: u64,
}

impl Registration {
    /// Parse and validate one strict version-one TOML registration.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for malformed TOML or any registration rule
    /// that does not hold.
    pub fn from_toml(source: &str) -> Result<Self, RegistrationRefusal> {
        let registration: Self = toml::from_str(source)
            .map_err(|_error| RegistrationRefusal::new(RegistrationRule::MalformedToml))?;
        registration.validate()?;
        Ok(registration)
    }

    /// Validate the registration independently of storage.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic registration rule the value violates.
    pub fn validate(&self) -> Result<(), RegistrationRefusal> {
        if self.schema != REGISTRATION_SCHEMA {
            return Err(RegistrationRefusal::new(
                RegistrationRule::UnsupportedSchema,
            ));
        }
        if !is_safe_component(&self.lane) {
            return Err(RegistrationRefusal::new(RegistrationRule::InvalidLaneName));
        }
        if !self.worktree.is_absolute() {
            return Err(RegistrationRefusal::new(
                RegistrationRule::WorktreeMustBeAbsolute,
            ));
        }
        if self.packages.is_empty() {
            return Err(RegistrationRefusal::new(
                RegistrationRule::EmptyPackageAllowlist,
            ));
        }

        let mut package_names = BTreeSet::new();
        for package in &self.packages {
            if !is_package_name(package) {
                return Err(RegistrationRefusal::new(
                    RegistrationRule::InvalidPackageName,
                ));
            }
            if !package_names.insert(package.as_str()) {
                return Err(RegistrationRefusal::new(RegistrationRule::DuplicatePackage));
            }
        }

        if !is_commit_id(&self.base_commit) {
            return Err(RegistrationRefusal::new(
                RegistrationRule::InvalidBaseCommit,
            ));
        }
        if self.mirror_remote.trim().is_empty() {
            return Err(RegistrationRefusal::new(
                RegistrationRule::EmptyMirrorRemote,
            ));
        }
        if !self.mirror_checkout.is_absolute() {
            return Err(RegistrationRefusal::new(
                RegistrationRule::MirrorCheckoutMustBeAbsolute,
            ));
        }
        if self.budgets.run_cap == 0 {
            return Err(RegistrationRefusal::new(RegistrationRule::ZeroRunCap));
        }
        if self.proposal_timeout_seconds == 0 {
            return Err(RegistrationRefusal::new(
                RegistrationRule::ZeroProposalTimeout,
            ));
        }
        if self.commands.is_empty() {
            return Err(RegistrationRefusal::new(
                RegistrationRule::EmptyCommandRoster,
            ));
        }

        let roster: BTreeSet<&str> = self.commands.keys().map(String::as_str).collect();
        let required: BTreeSet<&str> = REQUIRED_COMMANDS.into_iter().collect();
        if !required.is_subset(&roster) {
            return Err(RegistrationRefusal::new(
                RegistrationRule::CommandRosterMismatch,
            ));
        }

        for (name, command) in &self.commands {
            if !is_safe_component(name) {
                return Err(RegistrationRefusal::new(
                    RegistrationRule::InvalidCommandName,
                ));
            }
            if command.argv.is_empty() || command.argv.iter().any(String::is_empty) {
                return Err(RegistrationRefusal::new(RegistrationRule::EmptyCommandArgv));
            }
            if command.wall_budget_seconds == 0 {
                return Err(RegistrationRefusal::new(
                    RegistrationRule::ZeroCommandWallBudget,
                ));
            }
        }

        let test = self
            .commands
            .get("test")
            .ok_or_else(|| RegistrationRefusal::new(RegistrationRule::CommandRosterMismatch))?;
        validate_test_pins(test, &package_names)
    }
}

/// One fixed command vector and its server wall budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    /// Exact argument vector executed for this roster name.
    pub argv: Vec<String>,
    /// Maximum server wall time for one invocation.
    pub wall_budget_seconds: u64,
}

/// Lane-wide budget settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BudgetPolicy {
    /// Maximum number of command runs. Pushes and fix application do not count.
    #[serde(default = "default_run_cap")]
    pub run_cap: u32,
    /// Minimum delay between accepted runs.
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            run_cap: default_run_cap(),
            cooldown_seconds: default_cooldown_seconds(),
        }
    }
}

const fn default_run_cap() -> u32 {
    DEFAULT_RUN_CAP
}

const fn default_cooldown_seconds() -> u64 {
    DEFAULT_COOLDOWN_SECONDS
}

const fn default_proposal_timeout_seconds() -> u64 {
    DEFAULT_PROPOSAL_TIMEOUT_SECONDS
}

fn validate_test_pins(
    test: &CommandSpec,
    packages: &BTreeSet<&str>,
) -> Result<(), RegistrationRefusal> {
    let mut pins = BTreeSet::new();
    let mut argv = test.argv.iter();

    while let Some(argument) = argv.next() {
        if matches!(
            argument.as_str(),
            "--workspace" | "--all" | "--all-packages"
        ) {
            return Err(RegistrationRefusal::new(
                RegistrationRule::TestCommandNotPackagePinned,
            ));
        }
        if matches!(argument.as_str(), "--package" | "-p") {
            let Some(package) = argv.next() else {
                return Err(RegistrationRefusal::new(
                    RegistrationRule::TestCommandNotPackagePinned,
                ));
            };
            if !pins.insert(package.as_str()) {
                return Err(RegistrationRefusal::new(
                    RegistrationRule::TestCommandNotPackagePinned,
                ));
            }
        }
    }

    if &pins != packages {
        return Err(RegistrationRefusal::new(
            RegistrationRule::TestCommandNotPackagePinned,
        ));
    }
    Ok(())
}

fn is_safe_component(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn is_package_name(value: &str) -> bool {
    is_safe_component(value)
}

fn is_commit_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Machine-readable reason a registration was not admitted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationRule {
    /// The TOML did not strictly deserialize.
    MalformedToml,
    /// The schema version is not implemented.
    UnsupportedSchema,
    /// The lane is not a safe state-file component.
    InvalidLaneName,
    /// The worktree path is relative.
    WorktreeMustBeAbsolute,
    /// The package allowlist has no entries.
    EmptyPackageAllowlist,
    /// A package is not a Cargo-style name.
    InvalidPackageName,
    /// A package occurs more than once.
    DuplicatePackage,
    /// The registered base is not a full Git object identifier.
    InvalidBaseCommit,
    /// The opaque mirror remote is empty.
    EmptyMirrorRemote,
    /// The runner checkout path is relative.
    MirrorCheckoutMustBeAbsolute,
    /// A run cap of zero cannot admit a run.
    ZeroRunCap,
    /// A zero timeout cannot queue a proposal.
    ZeroProposalTimeout,
    /// No pre-cleared commands were supplied.
    EmptyCommandRoster,
    /// The roster omits one of the ratified six command names.
    CommandRosterMismatch,
    /// A roster name cannot safely identify a command.
    InvalidCommandName,
    /// A fixed command vector is empty or contains an empty argument.
    EmptyCommandArgv,
    /// A command has no usable wall budget.
    ZeroCommandWallBudget,
    /// The test vector is not pinned exactly to the package allowlist.
    TestCommandNotPackagePinned,
    /// A registration with this lane name is already stored.
    DuplicateLane,
    /// Gateway state would be written inside the worker-owned worktree.
    StateInsideWorktree,
    /// The local mirror path does not exist or is not a Git repository.
    MirrorRemoteUnreachable,
}

impl RegistrationRule {
    /// Stable diagnostic spelling of this rule.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedToml => "malformed_toml",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidLaneName => "invalid_lane_name",
            Self::WorktreeMustBeAbsolute => "worktree_must_be_absolute",
            Self::EmptyPackageAllowlist => "empty_package_allowlist",
            Self::InvalidPackageName => "invalid_package_name",
            Self::DuplicatePackage => "duplicate_package",
            Self::InvalidBaseCommit => "invalid_base_commit",
            Self::EmptyMirrorRemote => "empty_mirror_remote",
            Self::MirrorCheckoutMustBeAbsolute => "mirror_checkout_must_be_absolute",
            Self::ZeroRunCap => "zero_run_cap",
            Self::ZeroProposalTimeout => "zero_proposal_timeout",
            Self::EmptyCommandRoster => "empty_command_roster",
            Self::CommandRosterMismatch => "command_roster_mismatch",
            Self::InvalidCommandName => "invalid_command_name",
            Self::EmptyCommandArgv => "empty_command_argv",
            Self::ZeroCommandWallBudget => "zero_command_wall_budget",
            Self::TestCommandNotPackagePinned => "test_command_not_package_pinned",
            Self::DuplicateLane => "duplicate_lane",
            Self::StateInsideWorktree => "state_inside_worktree",
            Self::MirrorRemoteUnreachable => "mirror_remote_unreachable",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::MalformedToml => "registration TOML is malformed or has unknown fields",
            Self::UnsupportedSchema => "registration schema must be version 1",
            Self::InvalidLaneName => "lane must be a safe non-empty state-file component",
            Self::WorktreeMustBeAbsolute => "worktree path must be absolute",
            Self::EmptyPackageAllowlist => "package allowlist must not be empty",
            Self::InvalidPackageName => "package allowlist contains an invalid name",
            Self::DuplicatePackage => "package allowlist contains a duplicate",
            Self::InvalidBaseCommit => "base commit must be a full Git object identifier",
            Self::EmptyMirrorRemote => "mirror remote specification must not be empty",
            Self::MirrorCheckoutMustBeAbsolute => "mirror checkout path must be absolute",
            Self::ZeroRunCap => "run cap must be greater than zero",
            Self::ZeroProposalTimeout => "proposal timeout must be greater than zero",
            Self::EmptyCommandRoster => "command roster must not be empty",
            Self::CommandRosterMismatch => "command roster must contain all six ratified names",
            Self::InvalidCommandName => "command names must be safe non-empty roster identifiers",
            Self::EmptyCommandArgv => "every roster entry must have a fixed non-empty argv",
            Self::ZeroCommandWallBudget => "every roster entry needs a positive wall budget",
            Self::TestCommandNotPackagePinned => {
                "test argv must use package flags for exactly the registered packages"
            }
            Self::DuplicateLane => "lane name is already registered",
            Self::StateInsideWorktree => "gateway state must remain outside the lane worktree",
            Self::MirrorRemoteUnreachable => {
                "registered mirror path does not exist or is not a Git repository"
            }
        }
    }
}

/// Structured registration refusal suitable for machine output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRefusal {
    /// Refusal schema version.
    pub schema: u32,
    /// Exact rule that failed.
    pub rule: RegistrationRule,
    /// Fixed safe explanation of the rule.
    pub message: String,
}

impl RegistrationRefusal {
    pub(crate) fn new(rule: RegistrationRule) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            rule,
            message: rule.message().to_owned(),
        }
    }
}

/// Operation requested through the lane protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Mirror the current worktree snapshot.
    Push,
    /// Run one registered fixed command.
    Run,
    /// Queue an exact unregistered argv for human approval.
    Propose,
    /// Withdraw an open proposal belonging to the requesting lane.
    Withdraw,
}

/// Strict version-one request envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Request schema version.
    pub schema: u32,
    /// Monotonic per-lane sequence number.
    pub seq: u64,
    /// Requested operation.
    pub op: Operation,
    /// Roster name for a run.
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub command: Option<String>,
    /// Exact argv for a proposal only.
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub argv: Option<Vec<String>>,
    /// Human approval context for a proposal only.
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<String>,
    /// Owner of the proposal targeted by withdrawal only.
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub proposal_lane: Option<String>,
    /// Original proposal sequence, distinct from the withdrawal request sequence.
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub proposal_seq: Option<u64>,
}

impl Request {
    /// Validate operation-specific fields against one lane registration.
    ///
    /// # Errors
    ///
    /// Returns a refusal naming the first operation-shape or roster rule that
    /// failed.
    pub fn validate_against(&self, registration: &Registration) -> Result<(), Box<Refusal>> {
        if self.op != Operation::Withdraw
            && (self.proposal_lane.is_some() || self.proposal_seq.is_some())
        {
            return Err(Box::new(
                Refusal::new(RefusalRule::WithdrawShapeInvalid).with_seq(self.seq),
            ));
        }
        match self.op {
            Operation::Withdraw => {
                if self.proposal_lane.as_deref().is_none_or(str::is_empty)
                    || self.proposal_seq.is_none()
                    || self.command.is_some()
                    || self.argv.is_some()
                    || self.reason.is_some()
                {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::WithdrawShapeInvalid).with_seq(self.seq),
                    ));
                }
                if self.proposal_lane.as_deref() != Some(registration.lane.as_str()) {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::WithdrawNotOwner).with_seq(self.seq),
                    ));
                }
                Ok(())
            }
            Operation::Push => {
                if self.command.is_some() || self.argv.is_some() || self.reason.is_some() {
                    Err(Box::new(
                        Refusal::new(RefusalRule::PushTakesNoExtraFields).with_seq(self.seq),
                    ))
                } else {
                    Ok(())
                }
            }
            Operation::Run => {
                let Some(command) = self.command.as_deref() else {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::RunCommandRequired).with_seq(self.seq),
                    ));
                };
                if execute_command::checks::registered_command(
                    &crate::command::binding(
                        registration,
                        self.seq,
                        registration
                            .commands
                            .get(command)
                            .map_or(&[], |entry| entry.argv.as_slice()),
                    ),
                    registration.commands.contains_key(command),
                )
                .map_err(|_| {
                    Box::new(Refusal::new(RefusalRule::UnknownRosterCommand).with_seq(self.seq))
                })?
                .is_some()
                {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::UnknownRosterCommand).with_seq(self.seq),
                    ));
                }
                if self.argv.is_some() {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::RunArgvForbidden).with_seq(self.seq),
                    ));
                }
                if self.reason.is_some() {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::RunReasonForbidden).with_seq(self.seq),
                    ));
                }
                Ok(())
            }
            Operation::Propose => {
                if self.command.is_some() {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::ProposeCommandForbidden).with_seq(self.seq),
                    ));
                }
                if self
                    .argv
                    .as_ref()
                    .is_none_or(|argv| argv.first().is_none_or(String::is_empty))
                {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::ProposeArgvRequired).with_seq(self.seq),
                    ));
                }
                if self
                    .reason
                    .as_deref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    return Err(Box::new(
                        Refusal::new(RefusalRule::ProposeReasonRequired).with_seq(self.seq),
                    ));
                }
                Ok(())
            }
        }
    }
}

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Parse a strict request without consulting lane state.
///
/// # Errors
///
/// Returns a machine-readable refusal for invalid JSON, a non-object request,
/// unknown fields, malformed field types, or an unsupported schema.
pub fn parse_request(source: &str) -> Result<Request, Box<Refusal>> {
    let value: Value = serde_json::from_str(source)
        .map_err(|_error| Box::new(Refusal::new(RefusalRule::MalformedJson)))?;
    let object = value
        .as_object()
        .ok_or_else(|| Box::new(Refusal::new(RefusalRule::RequestMustBeObject)))?;

    if let Some(field) = object
        .keys()
        .find(|field| !REQUEST_FIELDS.contains(&field.as_str()))
    {
        return Err(Box::new(
            Refusal::new(RefusalRule::UnknownRequestField).with_field(field.as_str()),
        ));
    }

    let request: Request = serde_json::from_str(source)
        .map_err(|_error| Box::new(Refusal::new(RefusalRule::MalformedRequest)))?;
    if request.schema != REQUEST_SCHEMA {
        return Err(Box::new(
            Refusal::new(RefusalRule::UnsupportedRequestSchema)
                .with_seq(request.seq)
                .with_observed_schema(request.schema),
        ));
    }
    Ok(request)
}

/// Exact validation rule violated by a refused request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefusalRule {
    /// Withdrawal fields are missing or present on an incompatible operation.
    WithdrawShapeInvalid,
    /// The request channel does not belong to the target proposal's owner.
    WithdrawNotOwner,
    /// The target proposal is absent or already terminal.
    ProposalNotOpen,
    /// The lane has no stored registration.
    UnregisteredLane,
    /// The supplied lane name cannot safely name state files.
    InvalidLaneName,
    /// The input is not valid JSON.
    MalformedJson,
    /// The JSON root is not an object.
    RequestMustBeObject,
    /// The object contains a field outside the request schema.
    UnknownRequestField,
    /// A required field is absent, null, or has the wrong type.
    MalformedRequest,
    /// The request schema is not version one.
    UnsupportedRequestSchema,
    /// The sequence equals the persisted watermark.
    SequenceReplay,
    /// The sequence is below the persisted watermark.
    SequenceRegression,
    /// Push carried an operation-specific field.
    PushTakesNoExtraFields,
    /// Run did not name a roster entry.
    RunCommandRequired,
    /// Run named no registered roster entry.
    UnknownRosterCommand,
    /// Run attempted to supply argv instead of using its fixed vector.
    RunArgvForbidden,
    /// Run carried a proposal reason.
    RunReasonForbidden,
    /// Proposal attempted to name a roster command.
    ProposeCommandForbidden,
    /// Proposal argv is absent or empty.
    ProposeArgvRequired,
    /// Proposal reason is absent or blank.
    ProposeReasonRequired,
    /// The lane has consumed its registered run cap.
    RunBudgetExhausted,
    /// The registered delay since the previous run has not elapsed.
    RunCooldownActive,
    /// No fresh successful push identifies runnable mirror state.
    NoSnapshot,
    /// The configured runner could not complete normally.
    RunnerFailed,
    /// The runner transport died before the command reported a status.
    RunnerConnectionLost,
    /// A temporary-index snapshot could not be created.
    SnapshotFailed,
    /// A registered package could not be resolved in the base tree.
    PackageAllowlistUnresolved,
    /// Git could not push the snapshot to the registered mirror.
    MirrorPushFailed,
    /// The orchestrator denied a parked proposal.
    ProposalDenied,
    /// The orchestrator explicitly expired an open proposal.
    ProposalExpired,
    /// The watched request file could not be decoded as UTF-8.
    RequestUnreadable,
    /// The request channel is not a readable regular file.
    RequestPathInvalid,
}

/// Registered budget named by a cap refusal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCap {
    /// Maximum command runs admitted for one lane.
    RunCap,
}

impl RefusalRule {
    const fn message(self) -> &'static str {
        match self {
            Self::WithdrawShapeInvalid => "withdraw requires only proposal_lane and proposal_seq",
            Self::WithdrawNotOwner => "only the proposing lane may withdraw a proposal",
            Self::ProposalNotOpen => "withdrawal requires a pending or parked proposal",
            Self::UnregisteredLane => "lane is not registered",
            Self::InvalidLaneName => "lane is not a safe state-file component",
            Self::MalformedJson => "request is not valid JSON",
            Self::RequestMustBeObject => "request JSON must be an object",
            Self::UnknownRequestField => "request contains a field outside schema 1",
            Self::MalformedRequest => "request fields do not match schema 1",
            Self::UnsupportedRequestSchema => "request schema must be version 1",
            Self::SequenceReplay => "request sequence equals the persisted watermark",
            Self::SequenceRegression => "request sequence is below the persisted watermark",
            Self::PushTakesNoExtraFields => "push takes no command, argv, or reason",
            Self::RunCommandRequired => "run requires a command roster name",
            Self::UnknownRosterCommand => "run command is not in the registered roster",
            Self::RunArgvForbidden => "run argv is fixed by registration and cannot be supplied",
            Self::RunReasonForbidden => "run does not take a proposal reason",
            Self::ProposeCommandForbidden => "propose does not name a roster command",
            Self::ProposeArgvRequired => "propose requires a non-empty argv",
            Self::ProposeReasonRequired => "propose requires a non-empty reason",
            Self::RunBudgetExhausted => {
                "registered run cap has been consumed; continue with READY FOR VERIFY"
            }
            Self::RunCooldownActive => "registered run cooldown has not elapsed",
            Self::NoSnapshot => "run requires a fresh successful mirror snapshot",
            Self::RunnerFailed => "configured runner failed to complete",
            Self::RunnerConnectionLost => {
                "runner transport died before the command reported a status"
            }
            Self::SnapshotFailed => "temporary-index snapshot creation failed",
            Self::PackageAllowlistUnresolved => {
                "registered package allowlist does not resolve uniquely at the base commit"
            }
            Self::MirrorPushFailed => "snapshot push to the registered mirror failed",
            Self::ProposalDenied => "orchestrator denied the proposed command",
            Self::ProposalExpired => "proposal was explicitly expired",
            Self::RequestUnreadable => "request file is not valid UTF-8",
            Self::RequestPathInvalid => "request file is not a readable regular file",
        }
    }
}

/// Machine-readable refusal emitted and audited for an invalid request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    /// Refusal schema version.
    #[serde(deserialize_with = "current_refusal_schema")]
    pub schema: u32,
    /// Exact validation rule that failed.
    pub rule: RefusalRule,
    /// Fixed safe explanation of the rule.
    pub message: String,
    /// Sequence when it could be read safely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Current watermark for sequence refusals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermark: Option<u64>,
    /// Unknown field name, never its value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Unsupported schema number when it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_schema: Option<u32>,
    /// Exact repo-relative paths that violated push scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Human-authored denial reason where the refusal contract permits one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Registered proposal timeout for pending and expiry results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Trusted reason class for an explicitly expired proposal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_reason: Option<ProposalExpiryReason>,
    /// Registered cap that refused this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<RefusalCap>,
    /// Registered numeric limit for the named cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_limit: Option<u32>,
    /// Number of runs already counted against the named cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_reached: Option<u32>,
}

fn current_refusal_schema<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let schema = u32::deserialize(deserializer)?;
    if schema == RESULT_SCHEMA {
        Ok(schema)
    } else {
        Err(serde::de::Error::custom(
            "refusal schema is not the current result schema",
        ))
    }
}

impl Refusal {
    pub(crate) fn new(rule: RefusalRule) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            rule,
            message: rule.message().to_owned(),
            seq: None,
            watermark: None,
            field: None,
            observed_schema: None,
            paths: Vec::new(),
            reason: None,
            timeout_seconds: None,
            expiry_reason: None,
            cap: None,
            cap_limit: None,
            count_reached: None,
        }
    }

    pub(crate) const fn with_seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    pub(crate) const fn with_watermark(mut self, watermark: u64) -> Self {
        self.watermark = Some(watermark);
        self
    }

    fn with_field(mut self, field: &str) -> Self {
        self.field = Some(field.to_owned());
        self
    }

    const fn with_observed_schema(mut self, schema: u32) -> Self {
        self.observed_schema = Some(schema);
        self
    }

    pub(crate) fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.paths = paths;
        self
    }

    pub(crate) fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_owned());
        self
    }

    pub(crate) const fn with_expiry_reason(mut self, expiry_reason: ProposalExpiryReason) -> Self {
        self.expiry_reason = Some(expiry_reason);
        self
    }

    pub(crate) const fn with_run_cap(mut self, limit: u32, count_reached: u32) -> Self {
        self.cap = Some(RefusalCap::RunCap);
        self.cap_limit = Some(limit);
        self.count_reached = Some(count_reached);
        self
    }
}

/// Result of validating one offline request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestValidationResult {
    /// Result schema version.
    pub schema: u32,
    /// Lane against which validation ran.
    pub lane: String,
    /// Accepted request or explicit refusal.
    pub outcome: ValidationOutcome,
}

impl RequestValidationResult {
    pub(crate) fn accepted(lane: &str, request: Request) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            lane: lane.to_owned(),
            outcome: ValidationOutcome::Accepted { request },
        }
    }

    pub(crate) fn refused(lane: &str, refusal: Refusal) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            lane: lane.to_owned(),
            outcome: ValidationOutcome::Refused { refusal },
        }
    }

    /// Whether the request passed every validation rule.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(&self.outcome, ValidationOutcome::Accepted { .. })
    }
}

/// Accepted or refused validation payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidationOutcome {
    /// Request is valid and its sequence became the lane watermark.
    Accepted {
        /// Fully parsed request.
        request: Request,
    },
    /// Request was rejected under one exact rule.
    Refused {
        /// Structured refusal.
        refusal: Refusal,
    },
}

/// Request representation retained in the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "encoding", rename_all = "snake_case")]
pub enum AuditedRequest {
    /// Syntactically valid JSON, including requests rejected later.
    Json {
        /// Parsed JSON value.
        value: Value,
        /// Exact request text, retaining whitespace and duplicate-key evidence.
        raw: String,
    },
    /// Invalid JSON retained verbatim as request evidence.
    InvalidJson {
        /// Exact input bytes decoded as the supplied UTF-8 string.
        raw: String,
    },
}

/// Terminal decision for one proposal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDecision {
    /// Approved for one execution.
    Approved,
    /// Explicitly denied.
    Denied,
    /// Explicitly abandoned or expired during lane closeout.
    Expired,
    /// Withdrawn by the proposing lane before a terminal decision.
    Withdrawn,
}

/// Typed proposal verdict retained in state and audit evidence.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProposalVerdict {
    /// Request sequence receiving the verdict.
    pub seq: u64,
    /// Approval decision.
    pub decision: VerdictDecision,
    /// Safe human reason where one accompanies the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Trusted expiry class when the decision is expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_reason: Option<ProposalExpiryReason>,
    /// Wall time spent reaching and recording this verdict.
    #[serde(default)]
    pub wall_millis: u64,
}

impl<'de> Deserialize<'de> for ProposalVerdict {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredVerdict {
            seq: u64,
            decision: StoredVerdictDecision,
            reason: Option<String>,
            #[serde(default)]
            expiry_reason: Option<ProposalExpiryReason>,
            wall_millis: u64,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum StoredVerdictDecision {
            Approved,
            Denied,
            Expired,
            Withdrawn,
        }

        let stored = StoredVerdict::deserialize(deserializer)?;
        let (decision, expiry_reason) = match stored.decision {
            StoredVerdictDecision::Approved => (VerdictDecision::Approved, stored.expiry_reason),
            StoredVerdictDecision::Denied => (VerdictDecision::Denied, stored.expiry_reason),
            StoredVerdictDecision::Expired => (VerdictDecision::Expired, stored.expiry_reason),
            StoredVerdictDecision::Withdrawn => (VerdictDecision::Withdrawn, stored.expiry_reason),
        };
        Ok(Self {
            seq: stored.seq,
            decision,
            reason: stored.reason,
            expiry_reason,
            wall_millis: stored.wall_millis,
        })
    }
}

/// Trusted reason class for a terminal expired proposal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalExpiryReason {
    /// The orchestrator explicitly stopped waiting for this proposal.
    Abandoned,
    /// The orchestrator expired the proposal during explicit lane closeout.
    LaneClosed,
}

/// Trusted actor responsible for an audited proposal-state change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    /// The proposing lane withdrew through its authenticated request channel.
    Lane,
    /// The trusted orchestrator supplied a proposal verdict or promotion.
    Orchestrator,
}

/// Immutable proposal body awaiting an orchestrator verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParkedProposal {
    /// Proposal-state schema version.
    pub schema: u32,
    /// Registered lane that submitted the proposal.
    pub lane: String,
    /// Request sequence identifying this proposal.
    pub seq: u64,
    /// Exact argument vector supplied by the worker.
    pub argv: Vec<String>,
    /// Exact non-blank approval context supplied by the worker.
    pub reason: String,
    /// Intake time in milliseconds since the Unix epoch.
    pub queued_unix_ms: u64,
    /// Registered attention timeout for an orchestrator verdict.
    pub timeout_seconds: u64,
}

/// Create-once marker recording an open proposal's attention-window transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProposalPark {
    /// Proposal-state schema version.
    pub schema: u32,
    /// Registered lane that submitted the proposal.
    pub lane: String,
    /// Original request sequence identifying the proposal.
    pub seq: u64,
    /// Milliseconds since the Unix epoch when the proposal was parked.
    pub parked_unix_ms: u64,
    /// Registered attention timeout that elapsed.
    pub attention_timeout_seconds: u64,
}

impl ProposalPark {
    pub(crate) fn new(
        lane: &str,
        seq: u64,
        parked_unix_ms: u64,
        attention_timeout_seconds: u64,
    ) -> Self {
        Self {
            schema: PROPOSAL_STATE_SCHEMA,
            lane: lane.to_owned(),
            seq,
            parked_unix_ms,
            attention_timeout_seconds,
        }
    }
}

/// Current lifecycle state of one proposal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
    /// Open and inside its registered attention window.
    Pending,
    /// Open after its registered attention window elapsed.
    Parked,
    /// Terminally approved for exact-once execution.
    Approved,
    /// Terminally denied as an orchestrator policy decision.
    Denied,
    /// Terminally abandoned by the orchestrator or lane closeout.
    Expired,
    /// Terminally withdrawn by the proposing lane.
    Withdrawn,
}

impl ParkedProposal {
    pub(crate) fn new(
        lane: &str,
        seq: u64,
        argv: Vec<String>,
        reason: String,
        queued_unix_ms: u64,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            schema: PROPOSAL_STATE_SCHEMA,
            lane: lane.to_owned(),
            seq,
            argv,
            reason,
            queued_unix_ms,
            timeout_seconds,
        }
    }
}

/// One unresolved proposal as surfaced to the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingProposal {
    /// Registered lane that submitted the proposal.
    pub lane: String,
    /// Request sequence identifying this proposal.
    pub seq: u64,
    /// Exact parked argument vector.
    pub argv: Vec<String>,
    /// Exact parked approval context.
    pub reason: String,
    /// Milliseconds elapsed since intake.
    pub age_millis: u64,
    /// Registered maximum wait for a verdict.
    pub timeout_seconds: u64,
    /// Current open proposal state.
    pub state: ProposalState,
    /// Attention-window transition time for a parked proposal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parked_unix_ms: Option<u64>,
}

/// Deterministically ordered pending-proposal listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProposalQueue {
    /// Result schema version.
    pub schema: u32,
    /// Pending proposals ordered by lane and sequence.
    pub proposals: Vec<PendingProposal>,
}

impl ProposalQueue {
    pub(crate) const fn new(proposals: Vec<PendingProposal>) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            proposals,
        }
    }
}

/// Audited extension of a lane's pre-cleared roster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrationChange {
    /// Proposal sequence whose argv was promoted.
    pub proposal_seq: u64,
    /// New fixed roster identifier.
    pub command: String,
    /// Exact promoted argument vector.
    pub argv: Vec<String>,
    /// Wall budget inherited by the promoted entry.
    pub wall_budget_seconds: u64,
}

/// Worker-facing and audited outcome of one gateway request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationResult {
    /// Worker-facing result schema version.
    pub schema: u32,
    /// Request sequence when it could be decoded safely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Validated operation, absent for malformed request envelopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,
    /// Roster name when a command ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Process or gateway exit code.
    pub exit_code: i32,
    /// Wall duration of the completed action.
    pub wall_millis: u64,
    /// Time from accepted request or proposal intake to runner start, for runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_wait_ms: Option<u64>,
    /// Stable success, pending, over-budget, or refusal verdict.
    pub verdict: ResultVerdict,
    /// Snapshot commit installed or executed at the mirror.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
    /// Exact Cargo target directory configured for a runner execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_target_dir: Option<PathBuf>,
    /// Typed refusal when the verdict is refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    /// Registered proposal wait timeout on pending acknowledgements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_timeout_seconds: Option<u64>,
    /// Complete standard output from this action.
    pub stdout: String,
    /// Complete standard error from this action.
    pub stderr: String,
    /// Ordered payload files used only when the published result is chunked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_chunks: Vec<OutputChunkRef>,
}

impl OperationResult {
    pub(crate) const fn success(
        seq: u64,
        operation: Operation,
        wall_millis: u64,
        commit_id: Option<String>,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(operation),
            command: None,
            exit_code: 0,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::Success,
            commit_id,
            cargo_target_dir: None,
            refusal: None,
            proposal_timeout_seconds: None,
            stdout,
            stderr,
            output_chunks: Vec::new(),
        }
    }

    pub(crate) const fn completed_run(
        seq: u64,
        wall_millis: u64,
        commit_id: String,
        exit_code: i32,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(Operation::Run),
            command: None,
            exit_code,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::Success,
            commit_id: Some(commit_id),
            cargo_target_dir: None,
            refusal: None,
            proposal_timeout_seconds: None,
            stdout,
            stderr,
            output_chunks: Vec::new(),
        }
    }

    pub(crate) const fn over_budget(
        seq: u64,
        wall_millis: u64,
        commit_id: String,
        exit_code: i32,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(Operation::Run),
            command: None,
            exit_code,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::OverBudget,
            commit_id: Some(commit_id),
            cargo_target_dir: None,
            refusal: None,
            proposal_timeout_seconds: None,
            stdout,
            stderr,
            output_chunks: Vec::new(),
        }
    }

    pub(crate) const fn refused(
        seq: Option<u64>,
        operation: Option<Operation>,
        wall_millis: u64,
        refusal: Refusal,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq,
            operation,
            command: None,
            exit_code: 1,
            wall_millis,
            queue_wait_ms: None,
            verdict: if matches!(refusal.rule, RefusalRule::RunBudgetExhausted) {
                ResultVerdict::CapRefused
            } else {
                ResultVerdict::Refused
            },
            commit_id: None,
            cargo_target_dir: None,
            refusal: Some(refusal),
            proposal_timeout_seconds: None,
            stdout,
            stderr,
            output_chunks: Vec::new(),
        }
    }

    pub(crate) const fn pending_proposal(seq: u64, wall_millis: u64, timeout_seconds: u64) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(Operation::Propose),
            command: None,
            exit_code: 0,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::Pending,
            commit_id: None,
            cargo_target_dir: None,
            refusal: None,
            proposal_timeout_seconds: Some(timeout_seconds),
            stdout: String::new(),
            stderr: String::new(),
            output_chunks: Vec::new(),
        }
    }

    pub(crate) const fn parked_proposal(seq: u64, wall_millis: u64, timeout_seconds: u64) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(Operation::Propose),
            command: None,
            exit_code: 0,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::Parked,
            commit_id: None,
            cargo_target_dir: None,
            refusal: None,
            proposal_timeout_seconds: Some(timeout_seconds),
            stdout: String::new(),
            stderr: String::new(),
            output_chunks: Vec::new(),
        }
    }

    pub(crate) fn denied_proposal(seq: u64, wall_millis: u64, reason: &str) -> Self {
        let refusal = Refusal::new(RefusalRule::ProposalDenied)
            .with_seq(seq)
            .with_reason(reason);
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(Operation::Propose),
            command: None,
            exit_code: 1,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::Denied,
            commit_id: None,
            cargo_target_dir: None,
            refusal: Some(refusal),
            proposal_timeout_seconds: None,
            stdout: String::new(),
            stderr: String::new(),
            output_chunks: Vec::new(),
        }
    }

    pub(crate) fn expired_proposal(
        seq: u64,
        wall_millis: u64,
        reason: &str,
        expiry_reason: ProposalExpiryReason,
    ) -> Self {
        let refusal = Refusal::new(RefusalRule::ProposalExpired)
            .with_seq(seq)
            .with_reason(reason)
            .with_expiry_reason(expiry_reason);
        Self {
            schema: RESULT_SCHEMA,
            seq: Some(seq),
            operation: Some(Operation::Propose),
            command: None,
            exit_code: 1,
            wall_millis,
            queue_wait_ms: None,
            verdict: ResultVerdict::Expired,
            commit_id: None,
            cargo_target_dir: None,
            refusal: Some(refusal),
            proposal_timeout_seconds: None,
            stdout: String::new(),
            stderr: String::new(),
            output_chunks: Vec::new(),
        }
    }
}

/// Standard stream carried by one ordered output chunk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    /// Command standard output.
    Stdout,
    /// Command standard error.
    Stderr,
}

/// Reference from a published result manifest to one ordered payload file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputChunkRef {
    /// Zero-based position across both standard streams.
    pub index: usize,
    /// Stream to which the payload belongs.
    pub stream: OutputStream,
    /// File name below the lane protocol directory.
    pub file: String,
}

/// One independently readable output payload file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputChunk {
    /// Result schema version.
    pub schema: u32,
    /// Request sequence when it could be decoded safely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Zero-based position across both standard streams.
    pub index: usize,
    /// Stream to which the payload belongs.
    pub stream: OutputStream,
    /// Complete payload slice for this position.
    pub data: String,
}

impl OutputChunk {
    pub(crate) const fn new(
        seq: Option<u64>,
        index: usize,
        stream: OutputStream,
        data: String,
    ) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            seq,
            index,
            stream,
            data,
        }
    }
}

/// Stable worker-facing operation verdict.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultVerdict {
    /// The requested action completed successfully.
    #[default]
    Success,
    /// An approved command exited successfully.
    Ok,
    /// An approved command or its transport failed.
    Failed,
    /// An approved command exceeded its execution or transport deadline.
    #[serde(rename = "timed-out")]
    TimedOut,
    /// A predecessor stopped before publishing an approved command's result.
    Abandoned,
    /// The proposing lane withdrew the open proposal.
    Withdrawn,
    /// A proposal is parked and awaiting an orchestrator verdict.
    Pending,
    /// A proposal remains open after its attention timeout elapsed.
    Parked,
    /// The orchestrator denied a proposal as policy.
    Denied,
    /// The orchestrator explicitly expired a proposal.
    Expired,
    /// The runner exceeded its registered wall budget and was killed.
    OverBudget,
    /// Validation or execution refused the action.
    Refused,
    /// The registered run cap is exhausted before another command starts.
    #[serde(rename = "cap-refused")]
    CapRefused,
}

/// Reason a serve or acquisition pass removed an action lock.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionLockReapReason {
    /// The recorded process identifier no longer exists.
    DeadPid,
    /// Startup found no parseable process identifier in the lock record.
    MalformedOrUnreadable,
}

/// Fixed class of a worker result projection replaced from terminal evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjectionReplacementReason {
    /// The projection bytes do not decode as a current result.
    InvalidShape,
    /// The projection decodes but carries a non-current result schema.
    WrongSchema,
    /// The projection file could not be read.
    Unreadable,
}

/// Worker-owned path involved in a refused file operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerPathClass {
    /// The registered worktree directory itself.
    Worktree,
    /// The worker's request channel.
    Request,
    /// The current result projection.
    Result,
    /// A sequence-stable proposal projection.
    ProposalResult,
    /// A published output chunk.
    OutputChunk,
    /// A directory containing worker protocol files.
    ProtocolDirectory,
}

/// Fixed defect class; worker-authored path bytes never enter the audit.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerPathDefect {
    /// The object, or a directory component on its path, has the wrong file type.
    NotARegularFile,
    /// The opened object is a named pipe.
    Fifo,
    /// The opened object is a directory.
    Directory,
    /// A symbolic link was refused by the bounded open.
    Symlink,
    /// A write failed because the directory denied it.
    UnwritableDirectory,
    /// The object could not be opened, inspected, or read.
    Unreadable,
    /// A write or publication failed for another reported I/O reason.
    WriteFailed,
    /// The opened regular file exceeded the read bound.
    TooLarge,
    /// The registered worktree was removed.
    MissingWorktree,
}

impl WorkerPathDefect {
    /// Stable defect name used in worker-facing refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotARegularFile => "not_a_regular_file",
            Self::Fifo => "fifo",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::UnwritableDirectory => "unwritable_directory",
            Self::Unreadable => "unreadable",
            Self::WriteFailed => "write_failed",
            Self::TooLarge => "too_large",
            Self::MissingWorktree => "missing_worktree",
        }
    }
}

/// Worker-owned path and defect observed by one failed file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerFileFailure {
    /// Class of the path passed to the failing operation.
    pub path_class: WorkerPathClass,
    /// Defect from that operation's file type or error code.
    pub defect: WorkerPathDefect,
}

/// Payload of one immutable audit-log record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A worker-owned file was refused without stopping the shared serve.
    WorkerFileRefused {
        /// Registered lane whose file operation failed.
        lane: String,
        /// Request or proposal sequence, when one was known.
        #[serde(skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
        /// Class of the path touched by the failing operation.
        path_class: WorkerPathClass,
        /// Defect observed by that operation.
        defect: WorkerPathDefect,
        /// Whether this failure prevented publication of a result.
        unpublishable: bool,
    },
    /// A stale lane action lock was removed mechanically.
    ActionLockReaped {
        /// Registered lane whose action slot was recovered.
        lane: String,
        /// Dead holder process identifier, absent for malformed records.
        #[serde(skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// Typed reason the lock was safe to remove.
        reason: ActionLockReapReason,
    },
    /// Every received request, before validation.
    Request {
        /// Exact parsed or raw request representation.
        request: AuditedRequest,
    },
    /// A request file was read while its writer had not finished it.
    ///
    /// One record covers a whole waiting episode: the serve loop re-polls the
    /// same file for a bounded number of cycles and appends nothing further
    /// until the file either parses or exhausts the bound.
    RequestUnfinished {
        /// Registered lane whose request file was still being written.
        lane: String,
        /// Bytes present in the unfinished read, without their content.
        bytes: usize,
    },
    /// One accepted proposal was immutably parked.
    ProposalQueued {
        /// Exact parked proposal state.
        proposal: ParkedProposal,
    },
    /// One open proposal passed its attention window without a verdict.
    ProposalParked {
        /// Exact create-once park marker.
        park: ProposalPark,
    },
    /// Every validation refusal.
    Refusal {
        /// Exact rule and safe context.
        refusal: Refusal,
    },
    /// One resolved proposal verdict.
    Verdict {
        /// Trusted actor responsible for the decision.
        actor: AuditActor,
        /// Typed verdict.
        verdict: ProposalVerdict,
    },
    /// One proposal approval extended the live command roster.
    RegistrationChange {
        /// Trusted actor responsible for the mutation.
        actor: AuditActor,
        /// Exact registered entry.
        change: RegistrationChange,
    },
    /// One pending acknowledgement or completed operation result.
    Result {
        /// Typed result, including command wall and run queue wait milliseconds.
        result: Box<OperationResult>,
    },
    /// A worker-visible current result projection was replaced from terminal evidence.
    ResultProjectionReplaced {
        /// Proposal sequence whose terminal result was restored.
        seq: u64,
        /// Fixed class of the projection defect, without worker-authored bytes.
        reason: ResultProjectionReplacementReason,
    },
}

/// One versioned JSONL audit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Audit schema version.
    pub schema: u32,
    /// Milliseconds since the Unix epoch.
    pub timestamp_unix_ms: u64,
    /// Immutable event payload.
    pub event: AuditEvent,
}

impl AuditRecord {
    pub(crate) const fn new(timestamp_unix_ms: u64, event: AuditEvent) -> Self {
        Self {
            schema: AUDIT_SCHEMA,
            timestamp_unix_ms,
            event,
        }
    }
}

/// Successful registration result used by library callers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrationResult {
    /// Result schema version.
    pub schema: u32,
    /// Stored lane name.
    pub lane: String,
}

impl RegistrationResult {
    pub(crate) fn new(lane: &str) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            lane: lane.to_owned(),
        }
    }
}

/// Successful deregistration result used by library callers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeregistrationResult {
    /// Result schema version.
    pub schema: u32,
    /// Removed lane name.
    pub lane: String,
}

impl DeregistrationResult {
    pub(crate) fn new(lane: &str) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            lane: lane.to_owned(),
        }
    }
}

/// Status report for every currently registered lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayStatus {
    /// Report schema version.
    pub schema: u32,
    /// Lanes ordered by registration name.
    pub lanes: Vec<LaneStatus>,
    /// `.toml` files sitting directly in the state directory whose stem
    /// names no registration in `lanes`. A source TOML for a currently
    /// registered lane commonly sits beside its `registrations/<lane>.toml`
    /// copy and is not flagged; only a stem with no live registration was
    /// dropped without running `register`, and is loudly surfaced here.
    #[serde(default)]
    pub unregistered_toml_files: Vec<String>,
}

impl GatewayStatus {
    pub(crate) const fn new(lanes: Vec<LaneStatus>, unregistered_toml_files: Vec<String>) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            lanes,
            unregistered_toml_files,
        }
    }
}

/// Persisted sequence and budget status for one lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaneStatus {
    /// Lane name.
    pub lane: String,
    /// Last accepted request sequence, if any.
    pub seq_watermark: Option<u64>,
    /// Run-count budget configured for the lane.
    pub run_cap: u32,
    /// Completed command runs found in the audit trail.
    pub runs_consumed: u32,
    /// Remaining command runs.
    pub runs_remaining: u32,
    /// Per-command wall budget and observed consumption.
    pub commands: BTreeMap<String, CommandBudgetStatus>,
}

/// Wall-budget status for one fixed roster command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandBudgetStatus {
    /// Registered maximum wall time for one run.
    pub wall_budget_seconds: u64,
    /// Sum of completed run wall times in the audit trail.
    pub wall_millis_consumed: u64,
}

pub fn safe_lane_name(value: &str) -> bool {
    is_safe_component(value)
}
