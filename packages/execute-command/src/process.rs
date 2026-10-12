//! Check order, mode sequencing, intent/claim/effect/outcome order and recovery.
//!
//! Callers retain execution, confinement, process reaping and transport evidence.

use crate::escalation::ReviewAnswer;

/// An observation of the custody owner's common request state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    Waiting,
    Ready,
    Completed,
}

/// Withdrawal is independent of completion: its projection may need recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceObservation {
    pub state: ServiceState,
    pub waiter_gone: bool,
}

/// Authenticated proposal custody and effects supplied by the service adapter.
///
/// Common claims and completions use request-core in the adapter. A recovered
/// common claim does not authorize replay: `resolution_exists` observes the
/// service's durable execution intent, whose recovery must never execute again.
pub trait ProposalCustody {
    type Error;
    type Outcome;

    fn observed(&self) -> ServiceObservation;
    /// # Errors
    /// Returns the adapter's withdrawal-publication refusal.
    fn withdraw(&mut self) -> Result<(), Self::Error>;
    /// # Errors
    /// Refuses failed or uncertain common-claim publication before effect.
    fn claim(&mut self) -> Result<ServiceObservation, Self::Error>;
    /// # Errors
    /// Refuses an absent, malformed or unauthenticated answer.
    fn reviewed_answer(&self) -> Result<ReviewAnswer, Self::Error>;
    /// # Errors
    /// Refuses unreadable or corrupt execution-intent custody.
    fn resolution_exists(&self) -> Result<bool, Self::Error>;
    /// # Errors
    /// Refuses failed recovery; never retries the execution itself.
    fn recover(&mut self) -> Result<Self::Outcome, Self::Error>;
    /// # Errors
    /// Refuses invalid context, failed intent publication or an interrupted effect.
    fn apply_answer(&mut self, answer: ReviewAnswer) -> Result<Self::Outcome, Self::Error>;
    /// # Errors
    /// Returns the adapter's completion-publication refusal or uncertainty.
    fn complete(&mut self, outcome: &Self::Outcome) -> Result<(), Self::Error>;
}

/// Consume one reviewed proposal without replaying a published execution intent.
///
/// A failed or uncertain claim stops before effect; callers read custody before
/// retrying. An interrupted completion recovers the existing result on retry.
///
/// # Errors
/// Propagates custody, answer, effect and publication failures without continuing.
pub fn consume_proposal<C: ProposalCustody>(custody: &mut C) -> Result<(), C::Error> {
    let observed = custody.observed();
    if observed.waiter_gone {
        return custody.withdraw();
    }
    if observed.state != ServiceState::Ready {
        return Ok(());
    }
    let claimed = custody.claim()?;
    if claimed.waiter_gone {
        return custody.withdraw();
    }
    if claimed.state != ServiceState::Ready {
        return Ok(());
    }
    let answer = custody.reviewed_answer()?;
    let outcome = if custody.resolution_exists()? {
        custody.recover()?
    } else {
        custody.apply_answer(answer)?
    };
    custody.complete(&outcome)
}
