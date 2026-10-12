#![doc = include_str!("../README.md")]

mod channel;
mod command;
mod gateway;
mod proposal;
mod proposal_channel;
mod push;
mod run;
mod serve;
mod sha256;
mod types;

pub use channel::RequestChannel;
pub use gateway::{Gateway, GatewayError};
pub use serve::{ServeConfig, heartbeat_liveness};
pub use types::{
    ActionLockReapReason, AuditActor, AuditEvent, AuditRecord, AuditedRequest, BudgetPolicy,
    CommandBudgetStatus, CommandSpec, DeregistrationResult, GatewayStatus, LaneStatus, Operation,
    OperationResult, OutputChunk, OutputChunkRef, OutputStream, ParkedProposal, PendingProposal,
    ProposalExpiryReason, ProposalPark, ProposalQueue, ProposalState, ProposalVerdict, Refusal,
    RefusalCap, RefusalRule, Registration, RegistrationChange, RegistrationRefusal,
    RegistrationResult, RegistrationRule, Request, RequestValidationResult, ResultVerdict,
    ServeActivity, ServeCrashReport, ServeDeathReason, ServeFailureKind, ServeHeartbeat,
    ServeLiveness, ServeProcessState, ServeStopReason, ValidationOutcome, VerdictDecision,
    parse_request,
};

#[cfg(test)]
mod tests;
