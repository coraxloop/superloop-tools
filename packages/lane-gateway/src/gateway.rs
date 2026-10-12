use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::types::{
    ActionLockReapReason, AuditEvent, AuditRecord, AuditedRequest, CommandBudgetStatus,
    DeregistrationResult, GatewayStatus, LaneStatus, Operation, Refusal, RefusalRule, Registration,
    RegistrationRefusal, RegistrationResult, RegistrationRule, RequestValidationResult,
    ResultVerdict, parse_request, safe_lane_name,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Filesystem-backed offline gateway trust core.
#[derive(Debug, Clone)]
pub struct Gateway {
    state_dir: PathBuf,
    pub(crate) channel: Option<crate::RequestChannel>,
}

impl Gateway {
    /// Create a gateway over an explicit state directory.
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            channel: None,
        }
    }

    /// Bind proposal storage to this gateway owner's private loop journal.
    #[must_use]
    pub fn with_request_channel(mut self, channel: crate::RequestChannel) -> Self {
        self.channel = Some(channel);
        self
    }

    pub(crate) fn request_channel(&self) -> Result<&crate::RequestChannel, GatewayError> {
        self.channel.as_ref().ok_or_else(|| {
            GatewayError::RequestChannel("gateway request channel is not configured".into())
        })
    }

    /// Create a gateway from `LANE_GATEWAY_STATE`, falling back to the
    /// standard user state directory.
    ///
    /// # Errors
    ///
    /// Returns an error when neither state-directory environment variable can
    /// provide the default's home directory.
    pub fn from_environment() -> Result<Self, GatewayError> {
        Ok(Self::from_environment_values(
            std::env::var_os("LANE_GATEWAY_STATE").map(PathBuf::from),
            std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        )?
        .with_request_channel(crate::RequestChannel::configured()?))
    }

    /// Resolve raw environment values into the configured gateway state root.
    pub(crate) fn from_environment_values(
        configured: Option<PathBuf>,
        xdg_state_home: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Result<Self, GatewayError> {
        if let Some(configured) = configured.filter(|path| !path.as_os_str().is_empty()) {
            return Ok(Self::new(configured));
        }

        if let Some(xdg_state_home) = xdg_state_home.filter(|path| !path.as_os_str().is_empty()) {
            return Ok(Self::new(xdg_state_home.join("lane-gateway")));
        }

        let home = home
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(GatewayError::HomeUnavailable)?;
        Ok(Self::new(home.join(".local/state/lane-gateway")))
    }

    /// Root containing registrations, audit logs, and watermarks.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Parse, validate, and store a registration TOML file.
    ///
    /// # Errors
    ///
    /// Returns a typed registration refusal or a state I/O failure. An
    /// existing lane is never overwritten.
    pub fn register_path(&self, path: &Path) -> Result<RegistrationResult, GatewayError> {
        let source = fs::read_to_string(path)
            .map_err(|source| GatewayError::io("read_registration", source))?;
        self.register_source(&source)
    }

    /// Parse, validate, and store registration TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed registration refusal or a state I/O failure. An
    /// existing lane is never overwritten.
    pub fn register_source(&self, source: &str) -> Result<RegistrationResult, GatewayError> {
        let registration = Registration::from_toml(source).map_err(GatewayError::Registration)?;
        self.register(&registration)
    }

    /// Store an already parsed registration without overwriting another lane.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when validation fails, the lane already exists,
    /// or the gateway state would be inside the worker-owned worktree. State
    /// I/O and serialization failures are also returned.
    pub fn register(
        &self,
        registration: &Registration,
    ) -> Result<RegistrationResult, GatewayError> {
        registration
            .validate()
            .map_err(GatewayError::Registration)?;

        let state_dir = lexical_normalize(&self.absolute_state_dir()?);
        let worktree = lexical_normalize(&registration.worktree);
        if state_dir.starts_with(worktree) {
            return Err(GatewayError::Registration(RegistrationRefusal::new(
                RegistrationRule::StateInsideWorktree,
            )));
        }
        if let Some(refusal) = mirror_remote_unreachable_refusal(&registration.mirror_remote) {
            return Err(GatewayError::Registration(refusal));
        }

        self.ensure_layout()?;
        let path = self.registration_path(&registration.lane);
        let encoded = toml::to_string_pretty(&registration)
            .map_err(|_error| GatewayError::Serialization("registration_toml"))?;

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(GatewayError::Registration(RegistrationRefusal::new(
                    RegistrationRule::DuplicateLane,
                )));
            }
            Err(source) => return Err(GatewayError::io("create_registration", source)),
        };

        if let Err(source) = file
            .write_all(encoded.as_bytes())
            .and_then(|()| file.sync_all())
        {
            drop(file);
            drop(fs::remove_file(&path));
            return Err(GatewayError::io("write_registration", source));
        }

        Ok(RegistrationResult::new(&registration.lane))
    }

    /// Remove only a lane's live registration.
    ///
    /// Audit and watermark evidence intentionally remains in place.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or unregistered lane, while any
    /// proposal remains open, or when the registration file cannot be removed.
    pub fn deregister(&self, lane: &str) -> Result<DeregistrationResult, GatewayError> {
        Self::require_safe_lane(lane)?;
        let _lock = self.lock_lane(lane)?;
        self.load_registration(lane)?;
        for proposal in self.proposal_bodies(Some(lane))? {
            if !self.resolution_exists(lane, proposal.seq)? {
                return Err(GatewayError::OpenProposals);
            }
        }
        let path = self.registration_path(lane);
        match fs::remove_file(path) {
            Ok(()) => Ok(DeregistrationResult::new(lane)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                Err(GatewayError::UnregisteredLane)
            }
            Err(source) => Err(GatewayError::io("remove_registration", source)),
        }
    }

    /// Validate one request, append its audit record, append any refusal, and
    /// persist the sequence of an accepted request.
    ///
    /// # Errors
    ///
    /// Returns only operational state failures. Invalid requests are successful
    /// calls containing a typed refusal, so none is silently dropped.
    pub fn validate_request(
        &self,
        lane: &str,
        source: &str,
    ) -> Result<RequestValidationResult, GatewayError> {
        self.validate_request_inner(lane, source, true)
    }

    /// Inspect a request against current registration, watermark and budget
    /// evidence without appending audit records or changing any watermark.
    ///
    /// # Errors
    /// Refuses unreadable or malformed trusted state.
    pub fn check_request(
        &self,
        lane: &str,
        source: &str,
    ) -> Result<RequestValidationResult, GatewayError> {
        self.validate_request_inner(lane, source, false)
    }

    fn validation_refusal(
        &self,
        record: bool,
        lane: &str,
        refusal: Refusal,
    ) -> Result<RequestValidationResult, GatewayError> {
        if record {
            self.refuse(lane, refusal)
        } else {
            Ok(RequestValidationResult::refused(lane, refusal))
        }
    }

    fn validate_request_inner(
        &self,
        lane: &str,
        source: &str,
        record: bool,
    ) -> Result<RequestValidationResult, GatewayError> {
        if !safe_lane_name(lane) {
            return Ok(RequestValidationResult::refused(
                lane,
                Refusal::new(RefusalRule::InvalidLaneName),
            ));
        }

        let audited = match serde_json::from_str::<Value>(source) {
            Ok(value) => AuditedRequest::Json {
                value,
                raw: source.to_owned(),
            },
            Err(_error) => AuditedRequest::InvalidJson {
                raw: source.to_owned(),
            },
        };
        if record {
            self.append_audit(lane, AuditEvent::Request { request: audited })?;
        }

        let registration = match self.load_registration(lane) {
            Ok(registration) => registration,
            Err(GatewayError::UnregisteredLane) => {
                return self.validation_refusal(
                    record,
                    lane,
                    Refusal::new(RefusalRule::UnregisteredLane),
                );
            }
            Err(error) => return Err(error),
        };

        let request = match parse_request(source) {
            Ok(request) => request,
            Err(refusal) => return self.validation_refusal(record, lane, *refusal),
        };

        if let Some(watermark) = self.request_watermark(lane)? {
            match request.seq.cmp(&watermark) {
                Ordering::Equal => {
                    let refusal = Refusal::new(RefusalRule::SequenceReplay)
                        .with_seq(request.seq)
                        .with_watermark(watermark);
                    return self.validation_refusal(record, lane, refusal);
                }
                Ordering::Less => {
                    let refusal = Refusal::new(RefusalRule::SequenceRegression)
                        .with_seq(request.seq)
                        .with_watermark(watermark);
                    return self.validation_refusal(record, lane, refusal);
                }
                Ordering::Greater => {}
            }
        }

        if let Err(refusal) = request.validate_against(&registration) {
            return self.validation_refusal(record, lane, *refusal);
        }

        if request.op == Operation::Withdraw {
            let target = request
                .proposal_seq
                .ok_or(GatewayError::CorruptState("validated_withdraw_target"))?;
            match self.load_open_proposal(lane, target) {
                Ok(_) => {}
                Err(GatewayError::ProposalNotPending) => {
                    return self.validation_refusal(
                        record,
                        lane,
                        Refusal::new(RefusalRule::ProposalNotOpen).with_seq(request.seq),
                    );
                }
                Err(error) => return Err(error),
            }
        }

        if request.op == Operation::Run
            && let Some(refusal) = self.command_admission(
                &registration,
                request.seq,
                registration
                    .commands
                    .get(request.command.as_deref().unwrap_or_default())
                    .map_or(&[], |command| command.argv.as_slice()),
            )?
        {
            return self.validation_refusal(record, lane, refusal);
        }

        if record {
            self.write_watermark(lane, request.seq)?;
        }
        Ok(RequestValidationResult::accepted(lane, request))
    }

    /// Append one timestamped event to a lane's JSONL audit file.
    ///
    /// This is the extension point later gateway bites use for verdicts and
    /// results. The file is opened in append mode and existing bytes are
    /// never rewritten.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lane, clock failure, serialization
    /// failure, or state I/O failure.
    pub fn append_audit(&self, lane: &str, event: AuditEvent) -> Result<AuditRecord, GatewayError> {
        Self::require_safe_lane(lane)?;
        self.ensure_layout()?;
        let timestamp = timestamp_unix_ms()?;
        let record = AuditRecord::new(timestamp, event);
        let mut encoded = serde_json::to_vec(&record)
            .map_err(|_error| GatewayError::Serialization("audit_json"))?;
        encoded.push(b'\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.audit_path(lane))
            .map_err(|source| GatewayError::io("open_audit", source))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_data())
            .map_err(|source| GatewayError::io("append_audit", source))?;
        Ok(record)
    }

    /// Report registered lanes, sequence watermarks, and audited budget use.
    ///
    /// # Errors
    ///
    /// Returns an error when stored registrations, watermarks, or audit records
    /// cannot be read exactly.
    pub fn status(&self) -> Result<GatewayStatus, GatewayError> {
        let unregistered_toml_files = self.unregistered_toml_files()?;
        let registrations = self.registrations()?;
        let mut lanes = Vec::with_capacity(registrations.len());
        for registration in registrations {
            let watermark = self.request_watermark(&registration.lane)?;
            let consumption = self.audit_consumption(&registration.lane)?;
            let commands = registration
                .commands
                .iter()
                .map(|(name, spec)| {
                    let consumed = consumption
                        .wall_millis
                        .get(name)
                        .copied()
                        .unwrap_or_default();
                    (
                        name.clone(),
                        CommandBudgetStatus {
                            wall_budget_seconds: spec.wall_budget_seconds,
                            wall_millis_consumed: consumed,
                        },
                    )
                })
                .collect();
            lanes.push(LaneStatus {
                lane: registration.lane,
                seq_watermark: watermark,
                run_cap: registration.budgets.run_cap,
                runs_consumed: consumption.runs,
                runs_remaining: registration
                    .budgets
                    .run_cap
                    .saturating_sub(consumption.runs),
                commands,
            });
        }
        Ok(GatewayStatus::new(lanes, unregistered_toml_files))
    }

    /// `.toml` files sitting directly in the state directory whose stem names
    /// no live registration.
    ///
    /// The state root legitimately holds a source TOML for every lane an
    /// orchestrator has ever registered or deregistered — `register` reads
    /// from wherever its `TOML_PATH` argument points and writes its own copy
    /// to `registrations/<lane>.toml`, so the two commonly coexist for a
    /// currently registered lane. Only a stem with no matching
    /// `registrations/<stem>.toml` was dropped without `register` ever
    /// running, leaving its lane invisible to `serve`.
    ///
    /// # Errors
    ///
    /// Returns an error when the state directory cannot be read.
    pub(crate) fn unregistered_toml_files(&self) -> Result<Vec<String>, GatewayError> {
        if !self.state_dir.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.state_dir)
            .map_err(|source| GatewayError::io("read_state_dir", source))?
        {
            let entry = entry.map_err(|source| GatewayError::io("read_state_entry", source))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                continue;
            }
            let is_file = entry
                .file_type()
                .map_err(|source| GatewayError::io("read_state_entry_type", source))?
                .is_file();
            if !is_file {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let is_registered = path
                .file_stem()
                .and_then(|value| value.to_str())
                .is_some_and(|stem| self.registration_path(stem).is_file());
            if is_registered {
                continue;
            }
            files.push(name.to_owned());
        }
        files.sort();
        Ok(files)
    }

    pub(crate) fn registrations(&self) -> Result<Vec<Registration>, GatewayError> {
        if !self.registrations_dir().exists() {
            return Ok(Vec::new());
        }
        let entries = fs::read_dir(self.registrations_dir())
            .map_err(|source| GatewayError::io("read_registrations", source))?;
        let mut registrations = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|source| GatewayError::io("read_registration", source))?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("toml") {
                continue;
            }
            let lane = entry
                .path()
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or(GatewayError::CorruptState("registration_filename"))?
                .to_owned();
            registrations.push(self.load_registration(&lane)?);
        }
        registrations.sort_by(|left, right| left.lane.cmp(&right.lane));
        Ok(registrations)
    }

    fn refuse(
        &self,
        lane: &str,
        refusal: Refusal,
    ) -> Result<RequestValidationResult, GatewayError> {
        self.append_audit(
            lane,
            AuditEvent::Refusal {
                refusal: refusal.clone(),
            },
        )?;
        Ok(RequestValidationResult::refused(lane, refusal))
    }

    pub(crate) fn load_registration(&self, lane: &str) -> Result<Registration, GatewayError> {
        Self::require_safe_lane(lane)?;
        let source = match fs::read_to_string(self.registration_path(lane)) {
            Ok(source) => source,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(GatewayError::UnregisteredLane);
            }
            Err(source) => return Err(GatewayError::io("read_registration", source)),
        };
        Registration::from_toml(&source)
            .map_err(|_refusal| GatewayError::CorruptState("registration"))
    }

    pub(crate) fn latest_snapshot(
        &self,
        lane: &str,
    ) -> Result<Option<MirrorSnapshot>, GatewayError> {
        self.audit_consumption(lane)
            .map(|consumption| consumption.mirror_snapshot)
    }

    pub(crate) fn replace_registration(
        &self,
        registration: &Registration,
    ) -> Result<(), GatewayError> {
        registration
            .validate()
            .map_err(GatewayError::Registration)?;
        let path = self.registration_path(&registration.lane);
        if !path.is_file() {
            return Err(GatewayError::UnregisteredLane);
        }
        let encoded = toml::to_string_pretty(registration)
            .map_err(|_error| GatewayError::Serialization("registration_toml"))?;
        let suffix = TEMP_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
        let temporary = self.registrations_dir().join(format!(
            ".{}.{}.{}.tmp",
            registration.lane,
            std::process::id(),
            suffix
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| GatewayError::io("create_registration_update", source))?;
        if let Err(source) = file
            .write_all(encoded.as_bytes())
            .and_then(|()| file.sync_all())
        {
            drop(file);
            drop(fs::remove_file(&temporary));
            return Err(GatewayError::io("write_registration_update", source));
        }
        drop(file);
        if let Err(source) = fs::rename(&temporary, path) {
            drop(fs::remove_file(&temporary));
            return Err(GatewayError::io("publish_registration_update", source));
        }
        Ok(())
    }

    pub(crate) fn try_lock_lane(&self, lane: &str) -> Result<Option<LaneLock>, GatewayError> {
        Self::require_safe_lane(lane)?;
        self.ensure_layout()?;
        let path = self.locks_dir().join(lane);
        if let Some(lock) = Self::create_lane_lock(&path)? {
            return Ok(Some(lock));
        }

        match read_lane_lock(&path) {
            StoredLaneLock::Pid(pid) if !process_exists(pid) => {
                self.reap_action_lock(lane, &path, Some(pid), ActionLockReapReason::DeadPid)?;
                Self::create_lane_lock(&path)
            }
            StoredLaneLock::Missing => Self::create_lane_lock(&path),
            StoredLaneLock::Pid(_) | StoredLaneLock::MalformedOrUnreadable => Ok(None),
        }
    }

    fn create_lane_lock(path: &Path) -> Result<Option<LaneLock>, GatewayError> {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                if let Err(source) =
                    writeln!(file, "{}", std::process::id()).and_then(|()| file.sync_all())
                {
                    drop(file);
                    drop(fs::remove_file(path));
                    return Err(GatewayError::io("write_lane_lock", source));
                }
                Ok(Some(LaneLock {
                    path: path.to_path_buf(),
                }))
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(source) => Err(GatewayError::io("create_lane_lock", source)),
        }
    }

    pub(crate) fn lock_lane(&self, lane: &str) -> Result<LaneLock, GatewayError> {
        self.try_lock_lane(lane)?.ok_or_else(|| {
            let path = self.locks_dir().join(lane);
            let pid = match read_lane_lock(&path) {
                StoredLaneLock::Pid(pid) => Some(pid),
                StoredLaneLock::Missing | StoredLaneLock::MalformedOrUnreadable => None,
            };
            GatewayError::LaneBusy { pid, path }
        })
    }

    /// Reap stale action locks before serve begins proposal reconciliation.
    ///
    /// Returns the last recovered lane for the typed serve heartbeat activity.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock directory, a reaped lock, or its audit
    /// record cannot be read or mutated safely.
    pub(crate) fn reconcile_action_locks(&self) -> Result<Option<String>, GatewayError> {
        self.ensure_layout()?;
        let mut lanes = fs::read_dir(self.locks_dir())
            .map_err(|source| GatewayError::io("read_lane_locks", source))?
            .map(|entry| {
                entry
                    .map_err(|source| GatewayError::io("read_lane_lock_entry", source))?
                    .file_name()
                    .into_string()
                    .map_err(|_name| GatewayError::CorruptState("lane_lock_name"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        lanes.sort();

        let mut last_reaped = None;
        for lane in lanes {
            Self::require_safe_lane(&lane)?;
            let path = self.locks_dir().join(&lane);
            let (pid, reason) = match read_lane_lock(&path) {
                StoredLaneLock::Missing => continue,
                StoredLaneLock::Pid(pid) if process_exists(pid) => continue,
                StoredLaneLock::Pid(pid) => (Some(pid), ActionLockReapReason::DeadPid),
                StoredLaneLock::MalformedOrUnreadable => {
                    (None, ActionLockReapReason::MalformedOrUnreadable)
                }
            };
            if self.reap_action_lock(&lane, &path, pid, reason)? {
                last_reaped = Some(lane);
            }
        }
        Ok(last_reaped)
    }

    fn reap_action_lock(
        &self,
        lane: &str,
        path: &Path,
        pid: Option<u32>,
        reason: ActionLockReapReason,
    ) -> Result<bool, GatewayError> {
        match fs::remove_file(path) {
            Ok(()) => {
                self.append_audit(
                    lane,
                    AuditEvent::ActionLockReaped {
                        lane: lane.to_owned(),
                        pid,
                        reason,
                    },
                )?;
                Ok(true)
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(GatewayError::io("remove_lane_lock", source)),
        }
    }

    pub(crate) fn request_watermark(&self, lane: &str) -> Result<Option<u64>, GatewayError> {
        let source = match fs::read_to_string(self.watermark_path(lane)) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(GatewayError::io("read_watermark", source)),
        };
        source
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_error| GatewayError::CorruptState("watermark"))
    }

    fn write_watermark(&self, lane: &str, seq: u64) -> Result<(), GatewayError> {
        self.ensure_layout()?;
        let suffix = TEMP_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
        let temporary =
            self.watermarks_dir()
                .join(format!(".{lane}.{}.{}.tmp", std::process::id(), suffix));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| GatewayError::io("create_watermark", source))?;
        if let Err(source) = writeln!(file, "{seq}").and_then(|()| file.sync_all()) {
            drop(file);
            drop(fs::remove_file(&temporary));
            return Err(GatewayError::io("write_watermark", source));
        }
        drop(file);

        if let Err(source) = fs::rename(&temporary, self.watermark_path(lane)) {
            drop(fs::remove_file(&temporary));
            return Err(GatewayError::io("publish_watermark", source));
        }
        Ok(())
    }

    pub(crate) fn audit_records(&self, lane: &str) -> Result<Vec<AuditRecord>, GatewayError> {
        Self::require_safe_lane(lane)?;
        let path = self.audit_path(lane);
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(source) => return Err(GatewayError::io("read_audit", source)),
        };

        let mut records = Vec::new();
        for (index, text) in source.lines().enumerate() {
            if text.trim().is_empty() {
                continue;
            }
            // Audit files are one-indexed for human diagnostics.
            let line_number = index.saturating_add(1);
            let record: AuditRecord =
                serde_json::from_str(text).map_err(|_error| GatewayError::CorruptAudit {
                    path: path.clone(),
                    line: line_number,
                    invariant: "line is not valid JSON for the audit record schema",
                })?;
            if record.schema != crate::types::AUDIT_SCHEMA {
                return Err(GatewayError::CorruptAudit {
                    path,
                    line: line_number,
                    invariant: "audit schema is not the current schema",
                });
            }
            records.push(record);
        }
        Ok(records)
    }

    pub(crate) fn audit_consumption(&self, lane: &str) -> Result<AuditConsumption, GatewayError> {
        let mut consumption = AuditConsumption::default();
        for record in self.audit_records(lane)? {
            if let AuditEvent::Result { result } = record.event {
                let result = *result;
                let has_commit = result.commit_id.is_some();
                if result.operation == Some(Operation::Push)
                    && let Some(seq) = result.seq
                    && consumption
                        .latest_push_seq
                        .is_none_or(|latest| seq >= latest)
                {
                    consumption.latest_push_seq = Some(seq);
                    consumption.mirror_snapshot = if result.verdict == ResultVerdict::Success {
                        result
                            .commit_id
                            .map(|commit_id| MirrorSnapshot { commit_id })
                    } else {
                        None
                    };
                }
                if result.operation == Some(Operation::Run) && has_commit {
                    consumption.runs = consumption.runs.saturating_add(1);
                    consumption.last_run_timestamp_ms = Some(
                        consumption
                            .last_run_timestamp_ms
                            .map_or(record.timestamp_unix_ms, |current| {
                                current.max(record.timestamp_unix_ms)
                            }),
                    );
                    if let Some(command) = result.command {
                        let total = consumption.wall_millis.entry(command).or_default();
                        *total = total.saturating_add(result.wall_millis);
                    }
                }
            }
        }
        Ok(consumption)
    }

    pub(crate) fn ensure_layout(&self) -> Result<(), GatewayError> {
        for directory in [
            self.registrations_dir(),
            self.audit_dir(),
            self.watermarks_dir(),
            self.state_dir.join("proposal-parks"),
            self.state_dir.join("proposal-verdicts"),
            self.locks_dir(),
        ] {
            fs::create_dir_all(directory)
                .map_err(|source| GatewayError::io("create_state_layout", source))?;
        }
        Ok(())
    }

    pub(crate) fn absolute_state_dir(&self) -> Result<PathBuf, GatewayError> {
        if self.state_dir.is_absolute() {
            Ok(self.state_dir.clone())
        } else {
            std::env::current_dir()
                .map(|directory| directory.join(&self.state_dir))
                .map_err(|source| GatewayError::io("resolve_state_directory", source))
        }
    }

    fn require_safe_lane(lane: &str) -> Result<(), GatewayError> {
        if safe_lane_name(lane) {
            Ok(())
        } else {
            Err(GatewayError::InvalidLaneName)
        }
    }

    fn registrations_dir(&self) -> PathBuf {
        self.state_dir.join("registrations")
    }

    fn audit_dir(&self) -> PathBuf {
        self.state_dir.join("audit")
    }

    fn watermarks_dir(&self) -> PathBuf {
        self.state_dir.join("watermarks")
    }

    fn locks_dir(&self) -> PathBuf {
        self.state_dir.join("locks")
    }

    pub(crate) fn serve_heartbeat_path(&self) -> PathBuf {
        self.state_dir.join("serve-heartbeat.json")
    }

    pub(crate) fn serve_crash_path(&self) -> PathBuf {
        self.state_dir.join("serve-crash.json")
    }

    pub(crate) fn unregistered_registrations_report_path(&self) -> PathBuf {
        self.state_dir.join("unregistered-registrations.json")
    }

    fn registration_path(&self, lane: &str) -> PathBuf {
        self.registrations_dir().join(format!("{lane}.toml"))
    }

    fn audit_path(&self, lane: &str) -> PathBuf {
        self.audit_dir().join(format!("{lane}.jsonl"))
    }

    fn watermark_path(&self, lane: &str) -> PathBuf {
        self.watermarks_dir().join(lane)
    }
}

#[derive(Debug, Default)]
pub struct AuditConsumption {
    pub(crate) runs: u32,
    wall_millis: BTreeMap<String, u64>,
    pub(crate) last_run_timestamp_ms: Option<u64>,
    latest_push_seq: Option<u64>,
    pub(crate) mirror_snapshot: Option<MirrorSnapshot>,
}

#[derive(Clone, Debug)]
pub struct MirrorSnapshot {
    pub commit_id: String,
}

/// Read the current Unix timestamp in milliseconds.
///
/// # Errors
///
/// Returns an error when the system clock predates the Unix epoch or its
/// millisecond count cannot fit in the gateway timestamp representation.
pub fn timestamp_unix_ms() -> Result<u64, GatewayError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| GatewayError::ClockBeforeEpoch)?;
    u64::try_from(elapsed.as_millis()).map_err(|_error| GatewayError::ClockOverflow)
}

/// Filesystem-backed ownership of one lane's serial execution slot.
#[derive(Debug)]
pub struct LaneLock {
    path: PathBuf,
}

#[derive(Debug)]
enum StoredLaneLock {
    Missing,
    Pid(u32),
    MalformedOrUnreadable,
}

fn read_lane_lock(path: &Path) -> StoredLaneLock {
    match fs::read_to_string(path) {
        Ok(source) => source
            .trim()
            .parse::<u32>()
            .map_or(StoredLaneLock::MalformedOrUnreadable, StoredLaneLock::Pid),
        Err(source) if source.kind() == io::ErrorKind::NotFound => StoredLaneLock::Missing,
        Err(_source) => StoredLaneLock::MalformedOrUnreadable,
    }
}

/// Test process existence only; PID reuse deliberately keeps a lock live.
fn process_exists(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

impl Drop for LaneLock {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.path));
    }
}

/// Bound on the network round trip `git ls-remote` may take while verifying
/// an opaque (non-local) mirror remote during registration. Registration is
/// an orchestrator-side action with SSH access, so a bounded wait for a
/// reachability check is acceptable; an unbounded hang is not.
const MIRROR_REACHABILITY_TIMEOUT: Duration = Duration::from_secs(15);

/// Verify a registered mirror remote before it is trusted.
///
/// An absolute local path is checked cheaply and locally (`rev-parse
/// --git-dir`, no subprocess wait needed beyond the call itself). Every other
/// shape — in practice the scp-like SSH specs
/// (`host:/workspace/.../lane.git`) every real registration actually uses —
/// is checked with a bounded `git ls-remote`, which is the shape of the mirror
/// that failed live: a server-side bare mirror the registration named but
/// nothing had provisioned.
///
/// Verification refuses rather than creates the missing mirror: a typo in a
/// registered path is far more likely than a legitimate first-time mirror, and
/// silently creating a repository at whatever path was typed would turn that
/// mistake into stray on-disk state instead of a loud refusal.
fn mirror_remote_unreachable_refusal(mirror_remote: &str) -> Option<RegistrationRefusal> {
    let path = Path::new(mirror_remote);
    let reachable = if path.is_absolute() {
        Command::new("git")
            .arg("-C")
            .arg(path)
            .arg("rev-parse")
            .arg("--git-dir")
            .env("LC_ALL", "C")
            .output()
            .is_ok_and(|output| output.status.success())
    } else {
        remote_mirror_reachable(mirror_remote)
    };
    if reachable {
        None
    } else {
        Some(RegistrationRefusal::new(
            RegistrationRule::MirrorRemoteUnreachable,
        ))
    }
}

/// Run `git ls-remote` against an opaque mirror spec within a fixed deadline,
/// killing it rather than letting registration hang on a stalled connection.
///
/// Deliberately not `--exit-code`: that flag fails on zero advertised refs,
/// which an empty (freshly provisioned) bare mirror always has, and an empty
/// mirror must pass this check.
fn remote_mirror_reachable(mirror_remote: &str) -> bool {
    let mut child = match Command::new("git")
        .arg("ls-remote")
        .arg("--")
        .arg(mirror_remote)
        .env("LC_ALL", "C")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_error) => return false,
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {}
            Err(_error) => return false,
        }
        if started.elapsed() >= MIRROR_REACHABILITY_TIMEOUT {
            drop(child.kill());
            drop(child.wait());
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _removed = normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Operational failure while reading or mutating gateway state.
#[derive(Debug)]
pub enum GatewayError {
    /// The exact-path request helper refused its private journal transaction.
    RequestChannel(String),
    /// A worker-owned file operation failed with an observed path defect.
    WorkerFile(crate::types::WorkerFileFailure),
    /// Typed registration validation failure.
    Registration(RegistrationRefusal),
    /// A lane argument cannot safely name a state file.
    InvalidLaneName,
    /// No registration exists for the requested lane.
    UnregisteredLane,
    /// Another gateway action currently owns this lane's execution slot.
    LaneBusy {
        /// Recorded holder PID, absent when the record cannot be parsed.
        pid: Option<u32>,
        /// Exact action-lock path inspected during acquisition.
        path: PathBuf,
    },
    /// No unresolved proposal matches the supplied lane and sequence.
    ProposalNotPending,
    /// One or more proposals remain pending or parked for this lane.
    OpenProposals,
    /// A denial reason is absent or blank.
    InvalidDenialReason,
    /// An abandonment reason is absent or blank.
    InvalidAbandonReason,
    /// Promotion options do not form a supported approval request.
    InvalidPromotionRequest,
    /// A supplied or derived roster identifier is invalid.
    InvalidPromotionName,
    /// The promoted roster identifier is already registered.
    PromotionNameCollision,
    /// The state directory is empty.
    EmptyStateDirectory,
    /// The default state path cannot be derived.
    HomeUnavailable,
    /// Serve configuration is empty, malformed, or would permit a busy spin.
    InvalidServeConfig,
    /// The dedicated heartbeat publisher failed to write or join.
    HeartbeatPublisherFailed,
    /// The supervised serve loop unwound with a safe panic message.
    ServePanicked(String),
    /// A serve failure remained fatal but its crash report could not be written.
    CrashReportWriteFailed {
        /// Original serve failure reported by the supervision boundary.
        failure: Box<Self>,
        /// Failure encountered while publishing the crash report.
        report_failure: Box<Self>,
    },
    /// Stored bytes violate their state schema.
    CorruptState(&'static str),
    /// One audit-log line violated a specific named decoding invariant.
    CorruptAudit {
        /// Path to the offending lane audit file.
        path: PathBuf,
        /// One-based line number of the offending record.
        line: usize,
        /// Fixed description of the violated invariant.
        invariant: &'static str,
    },
    /// A typed value could not be serialized for storage.
    Serialization(&'static str),
    /// System time precedes the Unix epoch.
    ClockBeforeEpoch,
    /// System time cannot fit the audit timestamp field.
    ClockOverflow,
    /// Filesystem operation failed.
    Io {
        /// Stable operation class without a caller-controlled path.
        operation: &'static str,
        /// Underlying I/O error.
        source: io::Error,
    },
}

impl GatewayError {
    pub(crate) const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerFile(failure) => write!(
                formatter,
                "worker file refused: {:?} {:?}",
                failure.path_class, failure.defect
            ),
            Self::Registration(refusal) => {
                write!(formatter, "registration refused: {}", refusal.rule.as_str())
            }
            Self::InvalidLaneName => formatter.write_str("invalid lane name"),
            Self::UnregisteredLane => formatter.write_str("lane is not registered"),
            Self::LaneBusy {
                pid: Some(pid),
                path,
            } => write!(
                formatter,
                "lane already has an action in flight (held by pid {pid}, {})",
                path.display()
            ),
            Self::LaneBusy { pid: None, path } => write!(
                formatter,
                "lane already has an action in flight (malformed or unreadable lock record: no pid parseable, {})",
                path.display()
            ),
            Self::RequestChannel(detail) => write!(formatter, "gateway request channel: {detail}"),
            Self::ProposalNotPending => formatter.write_str("proposal is not open"),
            Self::OpenProposals => formatter.write_str("lane has open proposals"),
            Self::InvalidDenialReason => formatter.write_str("denial reason must not be blank"),
            Self::InvalidAbandonReason => {
                formatter.write_str("abandonment reason must not be blank")
            }
            Self::InvalidPromotionRequest => formatter.write_str("promotion options are invalid"),
            Self::InvalidPromotionName => formatter.write_str("promotion name is invalid"),
            Self::PromotionNameCollision => {
                formatter.write_str("promotion name is already registered; use --as")
            }
            Self::EmptyStateDirectory => formatter.write_str("gateway state directory is empty"),
            Self::HomeUnavailable => formatter.write_str("gateway default state is unavailable"),
            Self::InvalidServeConfig => {
                formatter.write_str("gateway serve configuration is invalid")
            }
            Self::HeartbeatPublisherFailed => {
                formatter.write_str("serve heartbeat publisher failed")
            }
            Self::ServePanicked(message) => write!(formatter, "gateway serve panicked: {message}"),
            Self::CrashReportWriteFailed { failure, .. } => {
                write!(formatter, "{failure}; serve crash report write failed")
            }
            Self::CorruptState(kind) => write!(formatter, "gateway {kind} state is invalid"),
            Self::CorruptAudit {
                path,
                line,
                invariant,
            } => write!(
                formatter,
                "gateway audit state is invalid: {invariant} at {}:{line}",
                path.display()
            ),
            Self::Serialization(kind) => write!(formatter, "failed to serialize {kind}"),
            Self::ClockBeforeEpoch | Self::ClockOverflow => {
                formatter.write_str("audit clock is unavailable")
            }
            Self::Io { operation, .. } => write!(formatter, "gateway {operation} failed"),
        }
    }
}

impl Error for GatewayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::CrashReportWriteFailed { failure, .. } => Some(failure.as_ref()),
            _ => None,
        }
    }
}
