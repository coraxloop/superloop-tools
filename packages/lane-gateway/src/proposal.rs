use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::gateway::{Gateway, GatewayError, timestamp_unix_ms};
use crate::push::elapsed_millis;
use crate::serve::{ServeConfig, read_worker_regular, write_proposal_result, write_result};
use crate::types::{
    AuditActor, AuditEvent, CommandSpec, Operation, OperationResult, ParkedProposal,
    PendingProposal, ProposalExpiryReason, ProposalPark, ProposalQueue, ProposalState,
    ProposalVerdict, RESULT_SCHEMA, Registration, RegistrationChange, Request,
    ResultProjectionReplacementReason, ResultVerdict, VerdictDecision, WorkerPathClass,
    safe_lane_name,
};

const PROPOSAL_SCHEMA: u32 = 1;
static PROPOSAL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Allow six JSON escape bytes per output byte, plus result metadata and chunk
/// references, when reading a projection published under the configured limit.
fn projection_read_limit(result_size_limit_bytes: usize) -> u64 {
    result_size_limit_bytes
        .saturating_mul(6)
        .saturating_add(1024 * 1024)
        .try_into()
        .unwrap_or(u64::MAX)
}

impl Gateway {
    pub(crate) fn park_proposal(
        &self,
        registration: &Registration,
        request: &Request,
        started: Instant,
    ) -> Result<OperationResult, GatewayError> {
        let argv = request
            .argv
            .clone()
            .ok_or(GatewayError::CorruptState("validated_proposal_argv"))?;
        let reason = request
            .reason
            .clone()
            .ok_or(GatewayError::CorruptState("validated_proposal_reason"))?;
        let proposal = ParkedProposal::new(
            &registration.lane,
            request.seq,
            argv,
            reason,
            timestamp_unix_ms()?,
            registration.proposal_timeout_seconds,
        );
        self.file_common_proposal(registration, &proposal)?;
        self.append_audit(&registration.lane, AuditEvent::ProposalQueued { proposal })?;
        Ok(OperationResult::pending_proposal(
            request.seq,
            elapsed_millis(started),
            registration.proposal_timeout_seconds,
        ))
    }

    /// List every pending or parked proposal in lane and sequence order.
    ///
    /// # Errors
    ///
    /// Returns an error when proposal state or the audit clock is unreadable.
    pub fn proposals(&self) -> Result<ProposalQueue, GatewayError> {
        let now = timestamp_unix_ms()?;
        let mut pending = Vec::new();
        for proposal in self.proposal_bodies(None)? {
            if self.resolution_exists(&proposal.lane, proposal.seq)? {
                continue;
            }
            let park = self.load_proposal_park(&proposal.lane, proposal.seq)?;
            pending.push(as_pending(proposal, park, now));
        }
        pending.sort_by(|left, right| {
            left.lane
                .cmp(&right.lane)
                .then_with(|| left.seq.cmp(&right.seq))
        });
        Ok(ProposalQueue::new(pending))
    }

    /// Approve one parked proposal and execute its exact argv once.
    ///
    /// When `promote` is true, the proposal also becomes a fixed roster entry.
    /// A supplied name is accepted only with promotion; otherwise a safe name
    /// is derived from the argv head.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or resolved proposal, invalid promotion
    /// options, a zero approval margin, a busy lane, corrupt state, or failed audit/result storage.
    pub fn approve_proposal(
        &self,
        lane: &str,
        seq: u64,
        promote: bool,
        supplied_name: Option<&str>,
        config: &ServeConfig,
    ) -> Result<OperationResult, GatewayError> {
        if config.approve_deadline_margin_seconds() == 0 {
            return Err(GatewayError::InvalidServeConfig);
        }
        if !promote && supplied_name.is_some() {
            return Err(GatewayError::InvalidPromotionRequest);
        }
        let started = Instant::now();
        let _lock = self.lock_lane(lane)?;
        let mut registration = self.load_registration(lane)?;
        let proposal = self.load_open_proposal(lane, seq)?;

        let promotion_name = if promote {
            let name = resolve_promotion_name(&proposal.argv, supplied_name)?;
            if registration.commands.contains_key(&name) {
                return Err(GatewayError::PromotionNameCollision);
            }
            Some(name)
        } else {
            None
        };

        let verdict = ProposalVerdict {
            seq,
            decision: VerdictDecision::Approved,
            reason: None,
            expiry_reason: None,
            wall_millis: elapsed_millis(started),
        };
        self.record_verdict(lane, AuditActor::Orchestrator, verdict)?;

        let execution = (|| {
            if let Some(name) = promotion_name.as_deref() {
                self.promote_registration(&mut registration, &proposal, name)?;
            }
            self.execute_approved_proposal(&registration, proposal, promotion_name, config, started)
        })();
        let mut result = execution.unwrap_or_else(|error| {
            let mut result = OperationResult::completed_run(
                seq,
                elapsed_millis(started),
                String::new(),
                1,
                String::new(),
                error.to_string(),
            );
            result.commit_id = None;
            result
        });
        result.verdict = match result.verdict {
            ResultVerdict::OverBudget => ResultVerdict::TimedOut,
            ResultVerdict::CapRefused => ResultVerdict::CapRefused,
            ResultVerdict::Success if result.exit_code == 0 => ResultVerdict::Ok,
            _ => ResultVerdict::Failed,
        };
        self.append_audit(
            lane,
            AuditEvent::Result {
                result: Box::new(result.clone()),
            },
        )?;
        self.publish_terminal_proposal_result(
            &registration,
            &result,
            config.result_size_limit_bytes(),
        )?;
        Ok(result)
    }

    fn publish_terminal_proposal_result(
        &self,
        registration: &Registration,
        result: &OperationResult,
        limit: usize,
    ) -> Result<(), GatewayError> {
        let seq = result
            .seq
            .ok_or(GatewayError::CorruptState("approval_result_sequence"))?;
        self.publish_or_audit_worker_failure(
            &registration.lane,
            Some(seq),
            write_proposal_result(&registration.worktree, seq, result, limit),
        )?;
        let (current, replacement_reason) = match read_worker_regular(
            &registration.worktree,
            ".lane/result.json",
            projection_read_limit(limit),
            WorkerPathClass::Result,
        ) {
            Ok(Some(source)) => match serde_json::from_slice::<OperationResult>(&source) {
                Ok(current) if current.schema == RESULT_SCHEMA => (Some(current), None),
                Ok(_current) => (None, Some(ResultProjectionReplacementReason::WrongSchema)),
                Err(_error) => (None, Some(ResultProjectionReplacementReason::InvalidShape)),
            },
            Ok(None) => (None, None),
            Err(GatewayError::WorkerFile(failure)) => {
                self.audit_worker_file_failure(
                    &registration.lane,
                    Some(seq),
                    failure.path_class,
                    failure.defect,
                    false,
                )?;
                (None, Some(ResultProjectionReplacementReason::Unreadable))
            }
            Err(error) => return Err(error),
        };
        if current.is_none_or(|current| current.seq.is_none_or(|current| current <= seq)) {
            let published = self.publish_or_audit_worker_failure(
                &registration.lane,
                Some(seq),
                write_result(&registration.worktree, result, limit),
            )?;
            if let Some(reason) = replacement_reason.filter(|_| published) {
                self.append_audit(
                    &registration.lane,
                    AuditEvent::ResultProjectionReplaced { seq, reason },
                )?;
            }
        }
        Ok(())
    }

    fn reconcile_terminal_proposal(
        &self,
        registration: &Registration,
        proposal: &ParkedProposal,
        limit: usize,
    ) -> Result<(), GatewayError> {
        let resolution: StoredResolution = serde_json::from_str(
            &fs::read_to_string(self.resolution_path(&proposal.lane, proposal.seq))
                .map_err(|source| GatewayError::io("read_proposal_verdict", source))?,
        )
        .map_err(|_error| GatewayError::CorruptState("proposal_verdict"))?;
        if resolution.verdict.decision == VerdictDecision::Withdrawn {
            let wall_millis = timestamp_unix_ms()?
                .saturating_sub(resolution.resolved_unix_ms)
                .saturating_add(resolution.verdict.wall_millis);
            return self.reconcile_withdrawal(registration, proposal.seq, limit, wall_millis);
        }
        if resolution.verdict.decision != VerdictDecision::Approved {
            let recorded = self
                .audit_records(&proposal.lane)?
                .into_iter()
                .find_map(|record| match record.event {
                    AuditEvent::Result { result }
                        if result.seq == Some(proposal.seq)
                            && matches!(
                                result.verdict,
                                ResultVerdict::Denied | ResultVerdict::Expired
                            ) =>
                    {
                        Some(*result)
                    }
                    _ => None,
                });
            let result = if let Some(result) = recorded {
                result
            } else {
                let reason = resolution
                    .verdict
                    .reason
                    .as_deref()
                    .ok_or(GatewayError::CorruptState("proposal_verdict_reason"))?;
                let result = match resolution.verdict.decision {
                    VerdictDecision::Denied => OperationResult::denied_proposal(
                        proposal.seq,
                        resolution.verdict.wall_millis,
                        reason,
                    ),
                    VerdictDecision::Expired => OperationResult::expired_proposal(
                        proposal.seq,
                        resolution.verdict.wall_millis,
                        reason,
                        resolution
                            .verdict
                            .expiry_reason
                            .ok_or(GatewayError::CorruptState("proposal_expiry_reason"))?,
                    ),
                    _ => return Err(GatewayError::CorruptState("proposal_verdict")),
                };
                self.append_audit(
                    &proposal.lane,
                    AuditEvent::Result {
                        result: Box::new(result.clone()),
                    },
                )?;
                result
            };
            return self.publish_terminal_proposal_result(registration, &result, limit);
        }
        self.reap_runner_group(&proposal.lane, proposal.seq)?;
        let recorded = self
            .audit_records(&proposal.lane)?
            .into_iter()
            .find_map(|record| match record.event {
                AuditEvent::Result { result }
                    if result.seq == Some(proposal.seq)
                        && result.operation == Some(Operation::Run) =>
                {
                    Some(*result)
                }
                _ => None,
            });
        let result = if let Some(result) = recorded {
            result
        } else {
            let mut result = OperationResult::completed_run(
                proposal.seq,
                timestamp_unix_ms()?.saturating_sub(resolution.resolved_unix_ms),
                String::new(),
                1,
                String::new(),
                "approval inherited without a terminal result".to_owned(),
            );
            result.commit_id = self
                .latest_snapshot(&proposal.lane)?
                .map(|snapshot| snapshot.commit_id);
            result.verdict = ResultVerdict::Abandoned;
            self.append_audit(
                &proposal.lane,
                AuditEvent::Result {
                    result: Box::new(result.clone()),
                },
            )?;
            result
        };
        self.publish_terminal_proposal_result(registration, &result, limit)
    }

    pub(crate) fn fail_common_approval(
        &self,
        proposal: &ParkedProposal,
        reason: &str,
        limit: usize,
    ) -> Result<OperationResult, GatewayError> {
        let _lock = self.lock_lane(&proposal.lane)?;
        let registration = self.load_registration(&proposal.lane)?;
        self.load_open_proposal(&proposal.lane, proposal.seq)?;
        self.record_verdict(
            &proposal.lane,
            AuditActor::Orchestrator,
            ProposalVerdict {
                seq: proposal.seq,
                decision: VerdictDecision::Approved,
                reason: None,
                expiry_reason: None,
                wall_millis: 0,
            },
        )?;
        let mut result = OperationResult::completed_run(
            proposal.seq,
            0,
            String::new(),
            1,
            String::new(),
            reason.to_owned(),
        );
        result.verdict = ResultVerdict::Failed;
        self.append_audit(
            &proposal.lane,
            AuditEvent::Result {
                result: Box::new(result.clone()),
            },
        )?;
        self.publish_terminal_proposal_result(&registration, &result, limit)?;
        Ok(result)
    }

    pub(crate) fn withdraw_proposal_locked(
        &self,
        registration: &Registration,
        request: &Request,
        config: &ServeConfig,
        started: Instant,
    ) -> Result<OperationResult, GatewayError> {
        let seq = request
            .proposal_seq
            .ok_or(GatewayError::CorruptState("validated_withdraw_target"))?;
        let verdict = ProposalVerdict {
            seq,
            decision: VerdictDecision::Withdrawn,
            reason: None,
            expiry_reason: None,
            wall_millis: elapsed_millis(started),
        };
        self.request_channel()?.change(
            "withdraw",
            &[],
            Some(serde_json::json!({
                "schema":1,"id":self.common_proposal_id(&registration.lane, seq)?
            })),
        )?;
        self.record_verdict(&registration.lane, AuditActor::Lane, verdict)?;
        self.reconcile_withdrawal(
            registration,
            seq,
            config.result_size_limit_bytes(),
            elapsed_millis(started),
        )?;
        let mut acknowledgement = OperationResult::success(
            request.seq,
            Operation::Withdraw,
            elapsed_millis(started),
            None,
            String::new(),
            String::new(),
        );
        acknowledgement.verdict = ResultVerdict::Withdrawn;
        Ok(acknowledgement)
    }

    pub(crate) fn recover_common_withdrawal(
        &self,
        proposal: &ParkedProposal,
        limit: usize,
    ) -> Result<(), GatewayError> {
        let _lock = self.lock_lane(&proposal.lane)?;
        let registration = self.load_registration(&proposal.lane)?;
        if !self.resolution_exists(&proposal.lane, proposal.seq)? {
            self.record_verdict(
                &proposal.lane,
                AuditActor::Lane,
                ProposalVerdict {
                    seq: proposal.seq,
                    decision: VerdictDecision::Withdrawn,
                    reason: None,
                    expiry_reason: None,
                    wall_millis: 0,
                },
            )?;
        }
        self.reconcile_terminal_proposal(&registration, proposal, limit)
    }

    fn reconcile_withdrawal(
        &self,
        registration: &Registration,
        seq: u64,
        limit: usize,
        wall_millis: u64,
    ) -> Result<(), GatewayError> {
        let started = Instant::now();
        let recorded = self
            .audit_records(&registration.lane)?
            .into_iter()
            .find_map(|record| match record.event {
                AuditEvent::Result { result }
                    if result.seq == Some(seq)
                        && result.operation == Some(Operation::Propose)
                        && result.verdict == ResultVerdict::Withdrawn =>
                {
                    Some(*result)
                }
                _ => None,
            });
        let result = if let Some(result) = recorded {
            result
        } else {
            let mut result = OperationResult::success(
                seq,
                Operation::Propose,
                wall_millis.saturating_add(elapsed_millis(started)),
                None,
                String::new(),
                String::new(),
            );
            result.verdict = ResultVerdict::Withdrawn;
            self.append_audit(
                &registration.lane,
                AuditEvent::Result {
                    result: Box::new(result.clone()),
                },
            )?;
            result
        };
        self.publish_terminal_proposal_result(registration, &result, limit)
    }

    fn promote_registration(
        &self,
        registration: &mut Registration,
        proposal: &ParkedProposal,
        name: &str,
    ) -> Result<(), GatewayError> {
        let command = CommandSpec {
            argv: proposal.argv.clone(),
            wall_budget_seconds: proposal.timeout_seconds,
        };
        registration.commands.insert(name.to_owned(), command);
        self.replace_registration(registration)?;
        self.append_audit(
            &registration.lane,
            AuditEvent::RegistrationChange {
                actor: AuditActor::Orchestrator,
                change: RegistrationChange {
                    proposal_seq: proposal.seq,
                    command: name.to_owned(),
                    argv: proposal.argv.clone(),
                    wall_budget_seconds: proposal.timeout_seconds,
                },
            },
        )?;
        Ok(())
    }

    fn execute_approved_proposal(
        &self,
        registration: &Registration,
        proposal: ParkedProposal,
        promotion_name: Option<String>,
        config: &ServeConfig,
        started: Instant,
    ) -> Result<OperationResult, GatewayError> {
        let seq = proposal.seq;
        let wall_budget_seconds = proposal.timeout_seconds;
        let queued_unix_ms = proposal.queued_unix_ms;
        let config = config.for_approve(started, wall_budget_seconds);
        let command = CommandSpec {
            argv: proposal.argv,
            wall_budget_seconds,
        };
        let mut result =
            if let Some(refusal) = self.command_admission(registration, seq, &command.argv)? {
                self.append_audit(
                    &registration.lane,
                    AuditEvent::Refusal {
                        refusal: refusal.clone(),
                    },
                )?;
                OperationResult::refused(
                    Some(seq),
                    Some(Operation::Run),
                    elapsed_millis(started),
                    refusal,
                    String::new(),
                    String::new(),
                )
            } else {
                let mirror = self
                    .latest_snapshot(&registration.lane)?
                    .ok_or(GatewayError::CorruptState("approved_proposal_snapshot"))?;
                Self::run_registration(
                    registration,
                    &command,
                    seq,
                    mirror.commit_id,
                    &config,
                    started,
                    queued_unix_ms,
                )?
            };
        result.command = promotion_name;
        Ok(result)
    }

    /// Deny one parked proposal with an exact non-blank human reason.
    ///
    /// # Errors
    ///
    /// Returns an error for a blank reason, unknown or resolved proposal, busy
    /// lane, corrupt state, or failed audit/result storage.
    pub fn deny_proposal(
        &self,
        lane: &str,
        seq: u64,
        reason: &str,
    ) -> Result<OperationResult, GatewayError> {
        if !execute_command::escalation::proposal_reason(
            execute_command::escalation::ReviewAnswer::Deny,
            reason,
        ) {
            return Err(GatewayError::InvalidDenialReason);
        }
        let started = Instant::now();
        let _lock = self.lock_lane(lane)?;
        let registration = self.load_registration(lane)?;
        let _proposal = self.load_open_proposal(lane, seq)?;

        let verdict = ProposalVerdict {
            seq,
            decision: VerdictDecision::Denied,
            reason: Some(reason.to_owned()),
            expiry_reason: None,
            wall_millis: elapsed_millis(started),
        };
        self.record_verdict(lane, AuditActor::Orchestrator, verdict)?;
        let result = OperationResult::denied_proposal(seq, elapsed_millis(started), reason);
        let refusal = result
            .refusal
            .clone()
            .ok_or(GatewayError::CorruptState("denied_proposal_result"))?;
        self.append_audit(lane, AuditEvent::Refusal { refusal })?;
        self.append_audit(
            lane,
            AuditEvent::Result {
                result: Box::new(result.clone()),
            },
        )?;
        self.publish_proposal_worker_result(&registration, seq, &result, usize::MAX)?;
        Ok(result)
    }

    /// Explicitly abandon one pending or parked proposal.
    ///
    /// # Errors
    ///
    /// Returns an error for a blank reason, unknown or terminal proposal,
    /// busy lane, corrupt state, or failed audit/result storage.
    pub fn abandon_proposal(
        &self,
        lane: &str,
        seq: u64,
        reason: &str,
    ) -> Result<OperationResult, GatewayError> {
        if !execute_command::escalation::proposal_reason(
            execute_command::escalation::ReviewAnswer::Abandon,
            reason,
        ) {
            return Err(GatewayError::InvalidAbandonReason);
        }
        let started = Instant::now();
        let _lock = self.lock_lane(lane)?;
        let registration = self.load_registration(lane)?;
        let _proposal = self.load_open_proposal(lane, seq)?;
        let expiry_reason = if reason == "lane closed" {
            ProposalExpiryReason::LaneClosed
        } else {
            ProposalExpiryReason::Abandoned
        };
        let verdict = ProposalVerdict {
            seq,
            decision: VerdictDecision::Expired,
            reason: Some(reason.to_owned()),
            expiry_reason: Some(expiry_reason),
            wall_millis: elapsed_millis(started),
        };
        self.record_verdict(lane, AuditActor::Orchestrator, verdict)?;
        let result =
            OperationResult::expired_proposal(seq, elapsed_millis(started), reason, expiry_reason);
        let refusal = result
            .refusal
            .clone()
            .ok_or(GatewayError::CorruptState("expired_proposal_result"))?;
        self.append_audit(lane, AuditEvent::Refusal { refusal })?;
        self.append_audit(
            lane,
            AuditEvent::Result {
                result: Box::new(result.clone()),
            },
        )?;
        self.publish_proposal_worker_result(&registration, seq, &result, usize::MAX)?;
        Ok(result)
    }

    pub(crate) fn park_due_lane_proposals_locked(
        &self,
        registration: &Registration,
        result_size_limit_bytes: usize,
    ) -> Result<(), GatewayError> {
        let now = timestamp_unix_ms()?;
        for proposal in self.proposal_bodies(Some(&registration.lane))? {
            if !self.resolution_exists(&registration.lane, proposal.seq)?
                && self
                    .load_proposal_park(&registration.lane, proposal.seq)?
                    .is_none()
                && execute_command::escalation::attention_elapsed(
                    proposal.queued_unix_ms,
                    proposal.timeout_seconds,
                    now,
                )
            {
                self.park_due_proposal_locked(registration, &proposal, result_size_limit_bytes)?;
            }
        }
        Ok(())
    }

    fn park_due_proposal_locked(
        &self,
        registration: &Registration,
        proposal: &ParkedProposal,
        result_size_limit_bytes: usize,
    ) -> Result<OperationResult, GatewayError> {
        let started = Instant::now();
        let park = if let Some(park) = self.load_proposal_park(&proposal.lane, proposal.seq)? {
            if park.attention_timeout_seconds != proposal.timeout_seconds {
                return Err(GatewayError::CorruptState("proposal_park"));
            }
            park
        } else {
            let park = ProposalPark::new(
                &proposal.lane,
                proposal.seq,
                timestamp_unix_ms()?,
                proposal.timeout_seconds,
            );
            write_new_json(
                &self.proposal_park_path(&proposal.lane, proposal.seq),
                &park,
                "write_proposal_park",
            )?;
            park
        };
        if !self.proposal_park_audited(&park)? {
            self.append_audit(
                &proposal.lane,
                AuditEvent::ProposalParked { park: park.clone() },
            )?;
        }
        let result = OperationResult::parked_proposal(
            proposal.seq,
            elapsed_millis(started),
            proposal.timeout_seconds,
        );
        if !self.proposal_park_result_audited(&park)? {
            self.append_audit(
                &proposal.lane,
                AuditEvent::Result {
                    result: Box::new(result.clone()),
                },
            )?;
        }
        self.publish_proposal_worker_result(
            registration,
            proposal.seq,
            &result,
            result_size_limit_bytes,
        )?;
        Ok(result)
    }

    /// Repair open proposal markers, audit transitions, and worker projections.
    ///
    /// # Errors
    ///
    /// Returns an error when stored proposal state, registrations, audit
    /// records, or worker projections cannot be read or repaired.
    pub fn reconcile_open_proposals(
        &self,
        result_size_limit_bytes: usize,
    ) -> Result<(), GatewayError> {
        let now = timestamp_unix_ms()?;
        for registration in self.registrations()? {
            let Some(_lock) = self.try_lock_lane(&registration.lane)? else {
                continue;
            };
            for proposal in self.proposal_bodies(Some(&registration.lane))? {
                if self.resolution_exists(&proposal.lane, proposal.seq)? {
                    self.reconcile_terminal_proposal(
                        &registration,
                        &proposal,
                        result_size_limit_bytes,
                    )?;
                    continue;
                }
                let park = self.load_proposal_park(&proposal.lane, proposal.seq)?;
                if park.is_some()
                    || execute_command::escalation::attention_elapsed(
                        proposal.queued_unix_ms,
                        proposal.timeout_seconds,
                        now,
                    )
                {
                    self.park_due_proposal_locked(
                        &registration,
                        &proposal,
                        result_size_limit_bytes,
                    )?;
                } else {
                    let started = Instant::now();
                    let result = OperationResult::pending_proposal(
                        proposal.seq,
                        elapsed_millis(started),
                        proposal.timeout_seconds,
                    );
                    self.publish_proposal_worker_result(
                        &registration,
                        proposal.seq,
                        &result,
                        result_size_limit_bytes,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn proposal_park_audited(&self, park: &ProposalPark) -> Result<bool, GatewayError> {
        Ok(self.audit_records(&park.lane)?.iter().any(|record| {
            matches!(
                &record.event,
                AuditEvent::ProposalParked { park: audited }
                    if audited.lane == park.lane && audited.seq == park.seq
            )
        }))
    }

    fn proposal_park_result_audited(&self, park: &ProposalPark) -> Result<bool, GatewayError> {
        Ok(self.audit_records(&park.lane)?.iter().any(|record| {
            matches!(
                &record.event,
                AuditEvent::Result { result }
                    if result.seq == Some(park.seq)
                        && result.verdict == crate::types::ResultVerdict::Parked
            )
        }))
    }

    pub(crate) fn load_open_proposal(
        &self,
        lane: &str,
        seq: u64,
    ) -> Result<ParkedProposal, GatewayError> {
        let proposal = self
            .proposal_bodies(Some(lane))?
            .into_iter()
            .find(|proposal| proposal.seq == seq)
            .ok_or(GatewayError::ProposalNotPending)?;
        if self.resolution_exists(lane, seq)? {
            return Err(GatewayError::ProposalNotPending);
        }
        Ok(proposal)
    }

    pub(crate) fn proposal_bodies(
        &self,
        lane_filter: Option<&str>,
    ) -> Result<Vec<ParkedProposal>, GatewayError> {
        self.common_proposals()?
            .into_iter()
            .filter_map(|row| {
                if lane_filter.is_some_and(|lane| row.body["proposal"]["lane"] != lane) {
                    return None;
                }
                Some(
                    serde_json::from_value(row.body["proposal"].clone())
                        .map_err(|_| GatewayError::CorruptState("common_proposal")),
                )
            })
            .collect()
    }

    pub(crate) fn legacy_proposal_bodies(
        &self,
        lane_filter: Option<&str>,
    ) -> Result<Vec<ParkedProposal>, GatewayError> {
        let root = self.state_dir().join("proposals");
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut proposals = Vec::new();
        let lanes =
            fs::read_dir(root).map_err(|source| GatewayError::io("read_proposal_lanes", source))?;
        for lane_entry in lanes {
            let lane_entry =
                lane_entry.map_err(|source| GatewayError::io("read_proposal_lane", source))?;
            if !lane_entry
                .file_type()
                .map_err(|source| GatewayError::io("read_proposal_lane_type", source))?
                .is_dir()
            {
                continue;
            }
            let lane = lane_entry
                .file_name()
                .to_str()
                .ok_or(GatewayError::CorruptState("proposal_lane_name"))?
                .to_owned();
            if !safe_lane_name(&lane) {
                return Err(GatewayError::CorruptState("proposal_lane_name"));
            }
            if lane_filter.is_some_and(|filter| filter != lane.as_str()) {
                continue;
            }
            let entries = fs::read_dir(lane_entry.path())
                .map_err(|source| GatewayError::io("read_proposals", source))?;
            for entry in entries {
                let entry =
                    entry.map_err(|source| GatewayError::io("read_proposal_entry", source))?;
                if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let seq = entry
                    .path()
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or(GatewayError::CorruptState("proposal_filename"))?;
                let source = fs::read_to_string(entry.path())
                    .map_err(|source| GatewayError::io("read_proposal", source))?;
                let proposal: ParkedProposal = serde_json::from_str(&source)
                    .map_err(|_error| GatewayError::CorruptState("proposal"))?;
                validate_parked_identity(&proposal, &lane, seq)?;
                proposals.push(proposal);
            }
        }
        proposals.sort_by(|left, right| {
            left.lane
                .cmp(&right.lane)
                .then_with(|| left.seq.cmp(&right.seq))
        });
        Ok(proposals)
    }

    fn claim_resolution(
        &self,
        lane: &str,
        actor: AuditActor,
        verdict: &ProposalVerdict,
    ) -> Result<(), GatewayError> {
        if verdict.decision == VerdictDecision::Approved {
            let proposal = self
                .proposal_bodies(Some(lane))?
                .into_iter()
                .find(|proposal| proposal.lane == lane && proposal.seq == verdict.seq)
                .ok_or(GatewayError::ProposalNotPending)?;
            let path = self
                .state_dir()
                .join("execution-budgets")
                .join(lane)
                .join(format!("{}.json", verdict.seq));
            let budget = serde_json::json!({
                "schema": 1, "lane": lane, "seq": verdict.seq,
                "timeout_seconds": proposal.timeout_seconds
            });
            match write_new_json(&path, &budget, "write_execution_budget") {
                Ok(()) => {}
                Err(GatewayError::Io { source, .. })
                    if source.kind() == io::ErrorKind::AlreadyExists =>
                {
                    let existing = fs::read(&path)
                        .map_err(|source| GatewayError::io("read_execution_budget", source))?;
                    if serde_json::from_slice::<serde_json::Value>(&existing).ok() != Some(budget) {
                        return Err(GatewayError::CorruptState("execution_budget"));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let resolution = StoredResolution {
            schema: PROPOSAL_SCHEMA,
            actor,
            verdict: verdict.clone(),
            resolved_unix_ms: timestamp_unix_ms()?,
        };
        let path = self.resolution_path(lane, verdict.seq);
        match write_new_json(&path, &resolution, "write_proposal_verdict") {
            Ok(()) => Ok(()),
            Err(GatewayError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                Err(GatewayError::ProposalNotPending)
            }
            Err(error) => Err(error),
        }
    }

    fn record_verdict(
        &self,
        lane: &str,
        actor: AuditActor,
        verdict: ProposalVerdict,
    ) -> Result<(), GatewayError> {
        self.claim_resolution(lane, actor, &verdict)?;
        self.append_audit(lane, AuditEvent::Verdict { actor, verdict })?;
        Ok(())
    }

    pub(crate) fn resolution_exists(&self, lane: &str, seq: u64) -> Result<bool, GatewayError> {
        let path = self.resolution_path(lane, seq);
        let source = match fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(GatewayError::io("read_proposal_verdict", source)),
        };
        let resolution: StoredResolution = serde_json::from_str(&source)
            .map_err(|_error| GatewayError::CorruptState("proposal_verdict"))?;
        if resolution.schema != PROPOSAL_SCHEMA || resolution.verdict.seq != seq {
            return Err(GatewayError::CorruptState("proposal_verdict"));
        }
        Ok(true)
    }

    fn load_proposal_park(
        &self,
        lane: &str,
        seq: u64,
    ) -> Result<Option<ProposalPark>, GatewayError> {
        let source = match fs::read_to_string(self.proposal_park_path(lane, seq)) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(GatewayError::io("read_proposal_park", source)),
        };
        let park: ProposalPark = serde_json::from_str(&source)
            .map_err(|_error| GatewayError::CorruptState("proposal_park"))?;
        validate_proposal_park_identity(&park, lane, seq)?;
        Ok(Some(park))
    }

    pub(crate) fn proposal_park_path(&self, lane: &str, seq: u64) -> PathBuf {
        self.state_dir()
            .join("proposal-parks")
            .join(lane)
            .join(format!("{seq}.json"))
    }

    fn resolution_path(&self, lane: &str, seq: u64) -> PathBuf {
        self.state_dir()
            .join("proposal-verdicts")
            .join(lane)
            .join(format!("{seq}.json"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredResolution {
    schema: u32,
    actor: AuditActor,
    verdict: ProposalVerdict,
    resolved_unix_ms: u64,
}

fn write_new_json(
    path: &Path,
    value: &impl Serialize,
    operation: &'static str,
) -> Result<(), GatewayError> {
    let parent = path
        .parent()
        .ok_or(GatewayError::CorruptState("proposal_path"))?;
    fs::create_dir_all(parent)
        .map_err(|source| GatewayError::io("create_proposal_directory", source))?;
    let mut encoded =
        serde_json::to_vec(value).map_err(|_error| GatewayError::Serialization("proposal_json"))?;
    encoded.push(b'\n');
    let suffix = PROPOSAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".proposal.{}.{}.tmp", std::process::id(), suffix));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| GatewayError::io(operation, source))?;
    if let Err(source) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        drop(fs::remove_file(&temporary));
        return Err(GatewayError::io(operation, source));
    }
    drop(file);
    match fs::metadata(path) {
        Ok(_metadata) => {
            drop(fs::remove_file(&temporary));
            return Err(GatewayError::io(
                operation,
                io::Error::from(io::ErrorKind::AlreadyExists),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            drop(fs::remove_file(&temporary));
            return Err(GatewayError::io(operation, source));
        }
    }
    if let Err(source) = fs::rename(&temporary, path) {
        drop(fs::remove_file(&temporary));
        return Err(GatewayError::io(operation, source));
    }
    Ok(())
}

fn validate_parked_identity(
    proposal: &ParkedProposal,
    lane: &str,
    seq: u64,
) -> Result<(), GatewayError> {
    if proposal.schema != PROPOSAL_SCHEMA
        || proposal.lane != lane
        || proposal.seq != seq
        || proposal.argv.first().is_none_or(String::is_empty)
        || proposal.reason.trim().is_empty()
        || proposal.timeout_seconds == 0
    {
        Err(GatewayError::CorruptState("proposal"))
    } else {
        Ok(())
    }
}

fn validate_proposal_park_identity(
    park: &ProposalPark,
    lane: &str,
    seq: u64,
) -> Result<(), GatewayError> {
    if park.schema != PROPOSAL_SCHEMA
        || park.lane != lane
        || park.seq != seq
        || park.attention_timeout_seconds == 0
    {
        Err(GatewayError::CorruptState("proposal_park"))
    } else {
        Ok(())
    }
}

fn as_pending(proposal: ParkedProposal, park: Option<ProposalPark>, now: u64) -> PendingProposal {
    let state = if park.is_some() {
        ProposalState::Parked
    } else {
        ProposalState::Pending
    };
    let parked_unix_ms = park.map(|park| park.parked_unix_ms);
    PendingProposal {
        lane: proposal.lane,
        seq: proposal.seq,
        argv: proposal.argv,
        reason: proposal.reason,
        age_millis: now.saturating_sub(proposal.queued_unix_ms),
        timeout_seconds: proposal.timeout_seconds,
        state,
        parked_unix_ms,
    }
}

fn resolve_promotion_name(
    argv: &[String],
    supplied_name: Option<&str>,
) -> Result<String, GatewayError> {
    if let Some(name) = supplied_name {
        return if safe_lane_name(name) {
            Ok(name.to_owned())
        } else {
            Err(GatewayError::InvalidPromotionName)
        };
    }
    let head = argv
        .first()
        .ok_or(GatewayError::CorruptState("proposal_argv"))?;
    let name = sanitize_roster_name(head);
    if safe_lane_name(&name) {
        Ok(name)
    } else {
        Err(GatewayError::InvalidPromotionName)
    }
}

fn sanitize_roster_name(head: &str) -> String {
    let mut name = String::new();
    let mut separator_pending = false;
    for character in head.chars() {
        if character.is_ascii_alphanumeric() {
            if separator_pending && !name.is_empty() && !ends_with_separator(&name) {
                name.push('-');
            }
            name.push(character);
            separator_pending = false;
        } else if matches!(character, '-' | '_') {
            if !name.is_empty() && !ends_with_separator(&name) {
                name.push(character);
            }
            separator_pending = false;
        } else if !name.is_empty() {
            separator_pending = true;
        }
    }
    name
}

fn ends_with_separator(value: &str) -> bool {
    value
        .as_bytes()
        .last()
        .is_some_and(|byte| matches!(byte, b'-' | b'_'))
}
