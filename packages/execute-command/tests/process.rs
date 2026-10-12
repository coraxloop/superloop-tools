use execute_command::escalation::ReviewAnswer;
use execute_command::process::{
    ProposalCustody, ServiceObservation, ServiceState, consume_proposal,
};

struct Custody {
    observed: ServiceObservation,
    claimed: ServiceObservation,
    answer: ReviewAnswer,
    resolution: Option<u32>,
    effects: u32,
    fail: Option<&'static str>,
    calls: Vec<&'static str>,
}

impl Custody {
    const fn ready() -> Self {
        let observed = ServiceObservation {
            state: ServiceState::Ready,
            waiter_gone: false,
        };
        Self {
            observed,
            claimed: observed,
            answer: ReviewAnswer::Approve,
            resolution: None,
            effects: 0,
            fail: None,
            calls: Vec::new(),
        }
    }

    fn step(&mut self, name: &'static str) -> Result<(), &'static str> {
        self.calls.push(name);
        if self.fail == Some(name) {
            Err(name)
        } else {
            Ok(())
        }
    }
}

impl ProposalCustody for Custody {
    type Error = &'static str;
    type Outcome = u32;

    fn observed(&self) -> ServiceObservation {
        self.observed
    }
    fn withdraw(&mut self) -> Result<(), Self::Error> {
        self.step("withdraw")
    }
    fn claim(&mut self) -> Result<ServiceObservation, Self::Error> {
        self.step("claim")?;
        Ok(self.claimed)
    }
    fn reviewed_answer(&self) -> Result<ReviewAnswer, Self::Error> {
        Ok(self.answer)
    }
    fn resolution_exists(&self) -> Result<bool, Self::Error> {
        Ok(self.resolution.is_some())
    }
    fn recover(&mut self) -> Result<u32, Self::Error> {
        self.step("recover")?;
        self.resolution.ok_or("absent intent")
    }
    fn apply_answer(&mut self, answer: ReviewAnswer) -> Result<u32, Self::Error> {
        self.step("intent")?;
        // Publication precedes any effect, including a failing/uncertain effect.
        self.resolution = Some(0);
        self.step("effect")?;
        if answer == ReviewAnswer::Approve {
            self.effects += 1;
        }
        self.resolution = Some(self.effects);
        Ok(self.effects)
    }
    fn complete(&mut self, _: &u32) -> Result<(), Self::Error> {
        self.step("complete")?;
        self.observed.state = ServiceState::Completed;
        Ok(())
    }
}

/// ´test:integration:proposal-retries-recover-intent-without-replaying-effects´
#[test]
fn proposal_retries_recover_intent_without_replaying_effects() {
    for failure in ["claim", "intent", "effect", "complete"] {
        let mut custody = Custody::ready();
        custody.fail = Some(failure);
        assert_eq!(consume_proposal(&mut custody), Err(failure));
        let before = custody.effects;
        let had_intent = custody.resolution.is_some();
        custody.fail = None;
        consume_proposal(&mut custody).expect("read-before-retry");
        assert_eq!(custody.effects, if had_intent { before } else { 1 });
        let calls = custody.calls.clone();
        consume_proposal(&mut custody).expect("completed duplicate");
        assert_eq!(custody.calls, calls);
    }
}

/// ´test:integration:withdrawal-and-parked-proposals-never-apply-an-answer´
#[test]
fn withdrawal_and_parked_proposals_never_apply_an_answer() {
    for state in [
        ServiceState::Waiting,
        ServiceState::Ready,
        ServiceState::Completed,
    ] {
        let mut custody = Custody::ready();
        custody.observed = ServiceObservation {
            state,
            waiter_gone: true,
        };
        consume_proposal(&mut custody).expect("withdraw");
        assert_eq!(custody.calls, ["withdraw"]);
        assert_eq!(custody.effects, 0);
    }
    for state in [ServiceState::Waiting, ServiceState::Completed] {
        let mut custody = Custody::ready();
        custody.observed.state = state;
        consume_proposal(&mut custody).expect("no answer");
        assert_eq!(custody.calls, [] as [&str; 0]);
    }
    let mut custody = Custody::ready();
    custody.claimed.waiter_gone = true;
    consume_proposal(&mut custody).expect("withdraw after claim");
    assert_eq!(custody.calls, ["claim", "withdraw"]);
}

/// ´test:integration:denial-and-abandonment-complete-without-an-execution´
#[test]
fn denial_and_abandonment_complete_without_an_execution() {
    for answer in [ReviewAnswer::Deny, ReviewAnswer::Abandon] {
        let mut custody = Custody::ready();
        custody.answer = answer;
        consume_proposal(&mut custody).expect("terminal answer");
        assert_eq!(custody.effects, 0);
        assert_eq!(custody.observed.state, ServiceState::Completed);
        assert_eq!(custody.calls, ["claim", "intent", "effect", "complete"]);
    }
}

/// ´test:integration:attention-timeout-parks-without-supplying-an-answer´
#[test]
fn attention_timeout_parks_without_supplying_an_answer() {
    use execute_command::escalation::{attention_elapsed, proposal_reason};
    assert!(!attention_elapsed(10_000, 1, 9_000));
    assert!(!attention_elapsed(10_000, 1, 10_999));
    assert!(attention_elapsed(10_000, 1, 11_000));
    assert!(!attention_elapsed(1, u64::MAX, u64::MAX));
    for answer in [ReviewAnswer::Deny, ReviewAnswer::Abandon] {
        assert!(!proposal_reason(answer, " \n\t"));
        assert!(proposal_reason(answer, "reviewed reason"));
    }
    assert!(proposal_reason(ReviewAnswer::Approve, ""));
}
