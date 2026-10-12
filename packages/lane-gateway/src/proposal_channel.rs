//! Common-journal proposal custody and recovery. The service's verdict record
//! remains an execution claim, never an alternative human decision channel.

use std::fs;

use execute_command::escalation::{Answer, ReviewAnswer, validate_answer};
use execute_command::process::{
    ProposalCustody, ServiceObservation, ServiceState, consume_proposal,
};
use execute_command::request::{Text, VerdictStatus};
use execute_command::triage::{Scope, referral};
use request_core::{Request as CommonRequest, State};
use serde_json::json;

use crate::{
    AuditEvent, Gateway, GatewayError, OperationResult, ParkedProposal, Registration, ServeConfig,
};

fn failure(detail: impl Into<String>) -> GatewayError {
    GatewayError::RequestChannel(detail.into())
}

impl Gateway {
    pub(crate) fn service_guard(&self) -> Result<nix::fcntl::Flock<fs::File>, GatewayError> {
        use std::os::unix::fs::OpenOptionsExt as _;
        self.ensure_layout()?;
        let root = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(self.state_dir())
            .map_err(|error| GatewayError::io("open_service_guard", error))?;
        nix::fcntl::Flock::lock(root, nix::fcntl::FlockArg::LockExclusiveNonblock).map_err(
            |(_, error)| failure(format!("gateway service or migration is active: {error}")),
        )
    }
    fn gateway_identity(&self) -> Result<String, GatewayError> {
        let root = self.absolute_state_dir()?;
        Ok(request_core::request_id(
            root.as_os_str().as_encoded_bytes(),
        ))
    }

    pub(crate) fn common_proposal_id(&self, lane: &str, seq: u64) -> Result<String, GatewayError> {
        Ok(request_core::request_id(
            format!("gateway\0{}\0{lane}\0{seq}", self.gateway_identity()?).as_bytes(),
        ))
    }

    pub(crate) fn file_common_proposal(
        &self,
        registration: &Registration,
        proposal: &ParkedProposal,
    ) -> Result<(), GatewayError> {
        let channel = self.request_channel()?;
        let registration =
            serde_json::to_vec(registration).map_err(|error| failure(error.to_string()))?;
        let body = json!({"schema":1,"loop_name":channel.loop_name(),"gateway_id":self.gateway_identity()?,
            "registration_digest":request_core::request_id(&registration),"proposal":proposal});
        let row = CommonRequest::filed(
            self.common_proposal_id(&proposal.lane, proposal.seq)?,
            "gateway-proposal".into(),
            body,
            proposal.lane.clone(),
            proposal.seq.to_string(),
            proposal
                .queued_unix_ms
                .checked_mul(1_000_000)
                .ok_or_else(|| failure("proposal timestamp exceeds journal range"))?,
        );
        channel.change("file", &[row], None)?;
        Ok(())
    }

    pub(crate) fn common_proposals(&self) -> Result<Vec<CommonRequest>, GatewayError> {
        let identity = self.gateway_identity()?;
        let channel = self.request_channel()?;
        Ok(channel
            .read()?
            .requests
            .into_iter()
            .filter(|row| {
                row.kind == "gateway-proposal"
                    && row.body["gateway_id"] == identity
                    && row.body["loop_name"] == channel.loop_name()
            })
            .collect())
    }

    /// Move predecessor proposal bodies into the calling loop's journal while
    /// the service is held. Repeating an interrupted migration compares the
    /// immutable source before moving its predecessor into recovery.
    ///
    /// # Errors
    /// Refuses a live service, an occupied inconsistent common ID, malformed
    /// state, or failed publication. No old body is removed before admission.
    pub fn migrate_proposals(&self) -> Result<serde_json::Value, GatewayError> {
        let _guard = self.service_guard()?;
        let proposals = self.legacy_proposal_bodies(None)?;
        let mut moved = 0;
        for proposal in proposals {
            let _lock = self.lock_lane(&proposal.lane)?;
            let registration = self.load_registration(&proposal.lane)?;
            if !self.resolution_exists(&proposal.lane, proposal.seq)? {
                self.file_common_proposal(&registration, &proposal)?;
            }
            let source = self
                .state_dir()
                .join("proposals")
                .join(&proposal.lane)
                .join(format!("{}.json", proposal.seq));
            let recovery = self
                .state_dir()
                .join("migrated-proposals")
                .join(&proposal.lane);
            fs::create_dir_all(&recovery)
                .map_err(|error| GatewayError::io("create_proposal_recovery", error))?;
            let target = recovery.join(format!("{}.json", proposal.seq));
            if target.exists() {
                if fs::read(&source)
                    .map_err(|error| GatewayError::io("read_migrating_proposal", error))?
                    != fs::read(&target)
                        .map_err(|error| GatewayError::io("read_proposal_recovery", error))?
                {
                    return Err(failure("proposal recovery differs"));
                }
                fs::remove_file(&source)
                    .map_err(|error| GatewayError::io("retire_migrated_proposal", error))?;
            } else {
                fs::rename(&source, &target)
                    .map_err(|error| GatewayError::io("retire_migrated_proposal", error))?;
            }
            fs::File::open(&recovery)
                .and_then(|file| file.sync_all())
                .map_err(|error| GatewayError::io("sync_proposal_recovery", error))?;
            if let Some(parent) = source.parent() {
                fs::File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| GatewayError::io("sync_proposal_retirement", error))?;
            }
            moved += 1;
        }
        Ok(json!({"migrated":moved,"recovery":self.state_dir().join("migrated-proposals")}))
    }

    pub(crate) fn service_common_proposals(
        &self,
        config: &ServeConfig,
    ) -> Result<(), GatewayError> {
        for row in self.common_proposals()? {
            let mut custody = CommonProposalCustody {
                gateway: self,
                config,
                current: row.clone(),
                row,
                proposal: None,
                claim: None,
            };
            consume_proposal(&mut custody)?;
        }
        Ok(())
    }

    fn approve_common_proposal(
        &self,
        row: &CommonRequest,
        proposal: &ParkedProposal,
        answer: &serde_json::Value,
        config: &ServeConfig,
    ) -> Result<OperationResult, GatewayError> {
        let registration = self.load_registration(&proposal.lane)?;
        if !bound_approval(row, proposal, &registration)? {
            return self.fail_common_approval(
                proposal,
                "registration changed since proposal filing",
                config.result_size_limit_bytes(),
            );
        }
        match self.approve_proposal(
            &proposal.lane,
            proposal.seq,
            answer.get("promote").is_some(),
            answer["promote"].as_str(),
            config,
        ) {
            Err(
                error @ (GatewayError::PromotionNameCollision
                | GatewayError::InvalidPromotionName
                | GatewayError::InvalidPromotionRequest),
            ) => self.fail_common_approval(
                proposal,
                &error.to_string(),
                config.result_size_limit_bytes(),
            ),
            other => other,
        }
    }

    fn complete_common_proposal(
        &self,
        id: &str,
        claim: &str,
        result: &OperationResult,
    ) -> Result<(), GatewayError> {
        self.request_channel()?.change(
            "complete",
            &[],
            Some(json!({"schema":1,"id":id,"claim":claim,"result":result})),
        )?;
        Ok(())
    }
}

fn bound_approval(
    row: &CommonRequest,
    proposal: &ParkedProposal,
    registration: &Registration,
) -> Result<bool, GatewayError> {
    let source_digest = row.body["registration_digest"]
        .as_str()
        .ok_or_else(|| failure("proposal registration digest absent"))?;
    let source =
        crate::command::binding_fields(source_digest, &proposal.lane, proposal.seq, &proposal.argv);
    let current = crate::command::binding(registration, proposal.seq, &proposal.argv);
    let text = |value: String| Text::try_from(value).map_err(|error| failure(error.to_string()));
    let review = row
        .review
        .as_ref()
        .map(|review| text(review.review_id.clone()))
        .transpose()?;
    let decision = row
        .decision
        .as_ref()
        .ok_or_else(|| failure("proposal decision absent"))?;
    let mut escalation = referral(
        &current,
        Scope::Loop,
        VerdictStatus::Valid,
        text("gateway loop review".into())?,
    )
    .escalation
    .ok_or_else(|| failure("loop escalation absent"))?;
    escalation.requires_current_review = review.is_some();
    let answer = Answer {
        binding: source,
        review: review.clone(),
        answer: ReviewAnswer::Approve,
        adjudicator: text("authenticated common request channel".into())?,
        reason: text(format!(
            "recorded reason sha256: {}",
            request_core::request_id(decision.reason.as_bytes())
        ))?,
    };
    Ok(validate_answer(&escalation, &answer, review.as_ref()).is_ok())
}

struct CommonProposalCustody<'a> {
    gateway: &'a Gateway,
    config: &'a ServeConfig,
    row: CommonRequest,
    current: CommonRequest,
    proposal: Option<ParkedProposal>,
    claim: Option<String>,
}

const fn observation(row: &CommonRequest) -> ServiceObservation {
    ServiceObservation {
        state: match row.state {
            State::ServicePending => ServiceState::Ready,
            State::Completed => ServiceState::Completed,
            _ => ServiceState::Waiting,
        },
        waiter_gone: row.waiter_gone,
    }
}

impl CommonProposalCustody<'_> {
    fn proposal(&self) -> Result<&ParkedProposal, GatewayError> {
        self.proposal
            .as_ref()
            .ok_or_else(|| failure("proposal claim absent"))
    }
}

impl ProposalCustody for CommonProposalCustody<'_> {
    type Error = GatewayError;
    type Outcome = OperationResult;

    fn observed(&self) -> ServiceObservation {
        observation(&self.current)
    }

    fn withdraw(&mut self) -> Result<(), GatewayError> {
        let proposal = serde_json::from_value(self.row.body["proposal"].clone())
            .map_err(|error| failure(error.to_string()))?;
        self.gateway
            .recover_common_withdrawal(&proposal, self.config.result_size_limit_bytes())
    }

    fn claim(&mut self) -> Result<ServiceObservation, GatewayError> {
        let proposal: ParkedProposal = serde_json::from_value(self.row.body["proposal"].clone())
            .map_err(|error| failure(error.to_string()))?;
        let claim = self
            .gateway
            .common_proposal_id(&proposal.lane, proposal.seq)?;
        let claimed = self.gateway.request_channel()?.change(
            "claim",
            &[],
            Some(json!({"schema":1,"id":self.row.id,"claim":claim})),
        )?;
        let saved: request_core::Collection = serde_json::from_value(claimed["collection"].clone())
            .map_err(|error| failure(error.to_string()))?;
        self.current = saved
            .requests
            .into_iter()
            .find(|current| current.id == self.row.id)
            .ok_or_else(|| failure("claimed proposal absent"))?;
        self.proposal = Some(proposal);
        self.claim = Some(claim);
        Ok(observation(&self.current))
    }

    fn reviewed_answer(&self) -> Result<ReviewAnswer, GatewayError> {
        let decision = self
            .current
            .decision
            .as_ref()
            .ok_or_else(|| failure("proposal decision absent"))?;
        match decision.answer["outcome"].as_str() {
            Some("approve") => Ok(ReviewAnswer::Approve),
            Some("deny") => Ok(ReviewAnswer::Deny),
            Some("abandon") => Ok(ReviewAnswer::Abandon),
            _ => Err(failure("unknown gateway answer")),
        }
    }

    fn resolution_exists(&self) -> Result<bool, GatewayError> {
        let proposal = self.proposal()?;
        self.gateway.resolution_exists(&proposal.lane, proposal.seq)
    }

    fn recover(&mut self) -> Result<OperationResult, GatewayError> {
        let proposal = self.proposal()?;
        self.gateway
            .reconcile_open_proposals(self.config.result_size_limit_bytes())?;
        self.gateway
            .audit_records(&proposal.lane)?
            .into_iter()
            .rev()
            .find_map(|record| match record.event {
                AuditEvent::Result { result }
                    if result.seq == Some(proposal.seq)
                        && !matches!(
                            result.verdict,
                            crate::ResultVerdict::Pending | crate::ResultVerdict::Parked
                        ) =>
                {
                    Some(*result)
                }
                _ => None,
            })
            .ok_or_else(|| failure("claimed proposal has no terminal result"))
    }

    fn apply_answer(&mut self, answer: ReviewAnswer) -> Result<OperationResult, GatewayError> {
        let proposal = self.proposal()?;
        let decision = self
            .current
            .decision
            .as_ref()
            .ok_or_else(|| failure("proposal decision absent"))?;
        match answer {
            ReviewAnswer::Approve => self.gateway.approve_common_proposal(
                &self.current,
                proposal,
                &decision.answer,
                self.config,
            ),
            ReviewAnswer::Deny => {
                self.gateway
                    .deny_proposal(&proposal.lane, proposal.seq, &decision.reason)
            }
            ReviewAnswer::Abandon => {
                self.gateway
                    .abandon_proposal(&proposal.lane, proposal.seq, &decision.reason)
            }
        }
    }

    fn complete(&mut self, outcome: &OperationResult) -> Result<(), GatewayError> {
        let claim = self
            .claim
            .as_deref()
            .ok_or_else(|| failure("proposal claim absent"))?;
        self.gateway
            .complete_common_proposal(&self.row.id, claim, outcome)
    }
}
