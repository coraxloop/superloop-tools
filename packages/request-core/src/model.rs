use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Error, Review, exact, hex, review};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Filed,
    Marked,
    TriageDecided,
    Adjudicated,
    ServicePending,
    Completed,
}

impl State {
    #[must_use]
    pub const fn pending(self) -> bool {
        matches!(self, Self::Filed | Self::Marked | Self::ServicePending)
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::Marked => "marked",
            Self::TriageDecided => "triage-decided",
            Self::Adjudicated => "adjudicated",
            Self::ServicePending => "service-pending",
            Self::Completed => "completed",
        }
    }
}

/// Registered domain schema. Callers retain authority and effect execution.
pub struct Kind<'a> {
    pub name: &'a str,
    pub service: bool,
    pub body: fn(&Value) -> bool,
    pub answer: fn(&Value, &Value) -> bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub answer: Value,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub kind: String,
    pub body: Value,
    pub worker: String,
    pub run: String,
    pub filed_ns: u64,
    pub state: State,
    pub waiter_gone: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub decision: Option<Decision>,
    #[serde(deserialize_with = "required_nullable")]
    pub decision_state: Option<State>,
    #[serde(deserialize_with = "required_nullable")]
    pub review: Option<Review>,
    pub review_history: Vec<Review>,
    #[serde(deserialize_with = "required_nullable")]
    pub service_claim: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub service_result: Option<Value>,
}

// A present null is meaningful; an absent key is a malformed persisted row.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl Request {
    /// Construct a pending common record; collection admission validates its kind.
    #[must_use]
    pub const fn filed(
        id: String,
        kind: String,
        body: Value,
        worker: String,
        run: String,
        filed_ns: u64,
    ) -> Self {
        Self {
            id,
            kind,
            body,
            worker,
            run,
            filed_ns,
            state: State::Filed,
            waiter_gone: false,
            decision: None,
            decision_state: None,
            review: None,
            review_history: Vec::new(),
            service_claim: None,
            service_result: None,
        }
    }

    fn registered<'a>(&self, kinds: &'a [Kind<'_>]) -> Result<&'a Kind<'a>, Error> {
        kinds
            .iter()
            .find(|kind| kind.name == self.kind)
            .ok_or_else(|| Error::new("requests-kind", &self.kind))
    }

    fn validate(&self, kinds: &[Kind<'_>]) -> Result<(), Error> {
        let kind = self.registered(kinds)?;
        let decided = matches!(
            self.state,
            State::TriageDecided | State::Adjudicated | State::ServicePending | State::Completed
        );
        if !hex(&self.id, 64)
            || self.worker.trim().is_empty()
            || self.run.trim().is_empty()
            || !self.body.is_object()
            || !(kind.body)(&self.body)
            || decided != self.decision.is_some()
            || decided != self.decision_state.is_some()
            || self
                .decision_state
                .is_some_and(|state| !matches!(state, State::TriageDecided | State::Adjudicated))
            || self.review.as_ref() != self.review_history.last()
            || !review::valid(&self.id, &self.review_history)
            || (self.state == State::Filed && self.review.is_some())
            || (matches!(self.state, State::ServicePending | State::Completed) && !kind.service)
            || (self.service_claim.is_some()
                && !matches!(self.state, State::ServicePending | State::Completed))
            || (self.state == State::Completed) != self.service_result.is_some()
        {
            return Err(Error::new("requests-record", &self.id));
        }
        if let Some(decision) = &self.decision {
            self.validate_decision(decision, kinds)?;
        }
        let valid_decided_state = !decided
            || if kind.service {
                matches!(self.state, State::ServicePending | State::Completed)
            } else {
                self.decision_state == Some(self.state)
            };
        if !valid_decided_state
            || (self.decision_state == Some(State::Adjudicated) && self.review.is_none())
            || (self.state == State::Completed && self.service_claim.is_none())
            || self
                .service_claim
                .as_ref()
                .is_some_and(|claim| claim.trim().is_empty())
            || self
                .service_result
                .as_ref()
                .is_some_and(|result| !result.is_object())
        {
            return Err(Error::new("requests-record", &self.id));
        }
        Ok(())
    }

    fn validate_decision(&self, decision: &Decision, kinds: &[Kind<'_>]) -> Result<(), Error> {
        let kind = self.registered(kinds)?;
        if !decision.answer.is_object()
            || decision.reason.trim().is_empty()
            || !(kind.answer)(&self.body, &decision.answer)
        {
            return Err(Error::new("requests-answer", &self.id));
        }
        Ok(())
    }

    fn decide(
        &mut self,
        decision: Decision,
        state: State,
        kinds: &[Kind<'_>],
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Filed | State::Marked) {
            return Err(Error::new("requests-state", &self.id));
        }
        self.validate_decision(&decision, kinds)?;
        self.state = if self.registered(kinds)?.service {
            State::ServicePending
        } else {
            state
        };
        self.decision_state = Some(state);
        self.decision = Some(decision);
        Ok(())
    }

    /// Project an answer only after the required judgement and service result.
    #[must_use]
    pub fn answer(&self) -> Option<Value> {
        if self.waiter_gone || self.state.pending() {
            None
        } else {
            Some(json!({"decision":self.decision,"result":self.service_result}))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub schema: u32,
    pub revision: u64,
    pub requests: Vec<Request>,
}

impl Default for Collection {
    fn default() -> Self {
        Self {
            schema: 1,
            revision: 0,
            requests: Vec::new(),
        }
    }
}

impl Collection {
    /// Validate the complete persisted collection and all registered bodies.
    ///
    /// # Errors
    /// Refuses unknown schemas, duplicate IDs, invalid records or kind schemas.
    pub fn validate(&self, kinds: &[Kind<'_>]) -> Result<(), Error> {
        if self.schema != 1 {
            return Err(Error::new("requests-schema", "collection schema"));
        }
        let mut ids = BTreeSet::new();
        for request in &self.requests {
            if !ids.insert(&request.id) {
                return Err(Error::new("requests-duplicate", &request.id));
            }
            request.validate(kinds)?;
        }
        Ok(())
    }

    /// Admit one validated source record, refusing an occupied identifier.
    ///
    /// # Errors
    /// Refuses a duplicate or malformed record without changing the collection.
    pub fn file(&mut self, request: Request, kinds: &[Kind<'_>]) -> Result<(), Error> {
        request.validate(kinds)?;
        if self.requests.iter().any(|row| row.id == request.id) {
            return Err(Error::new("requests-duplicate", request.id));
        }
        self.requests.push(request);
        Ok(())
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut Request, Error> {
        self.requests
            .iter_mut()
            .find(|row| row.id == id)
            .ok_or_else(|| Error::new("requests-unknown-id", id))
    }

    /// Apply a complete triage document in memory only after every item validates.
    ///
    /// # Errors
    /// Refuses unknown, repeated, stale or malformed items without any changes.
    pub fn triage(&mut self, document: &Value, kinds: &[Kind<'_>]) -> Result<Value, Error> {
        if !exact(document, &["schema", "items"]) || document["schema"].as_u64() != Some(1) {
            return Err(Error::new("requests-document", "triage envelope"));
        }
        let items = document["items"]
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or_else(|| Error::new("requests-document", "items"))?;
        self.validate(kinds)?;
        let mut next = self.clone();
        let mut ids = BTreeSet::new();
        let mut decided = 0;
        let mut marked = 0;
        for item in items {
            let id = item["id"]
                .as_str()
                .filter(|id| hex(id, 64))
                .ok_or_else(|| Error::new("requests-document", "id"))?;
            if !ids.insert(id) {
                return Err(Error::new("requests-duplicate", id));
            }
            let request = next.get_mut(id)?;
            if exact(item, &["id", "mark_for_review"]) && item["mark_for_review"] == true {
                if request.state != State::Filed {
                    return Err(Error::new("requests-state", id));
                }
                request.state = State::Marked;
                marked += 1;
            } else if exact(item, &["id", "decision"]) {
                let decision = serde_json::from_value(item["decision"].clone())
                    .map_err(|_| Error::new("requests-document", id))?;
                request.decide(decision, State::TriageDecided, kinds)?;
                decided += 1;
            } else {
                return Err(Error::new("requests-document", id));
            }
        }
        *self = next;
        Ok(json!({"applied":items.len(),"decided":decided,"marked":marked}))
    }

    /// Refresh only a marked request's review bookkeeping.
    ///
    /// # Errors
    /// Refuses unknown or unmarked requests and exhausted clock or identifier space.
    pub fn review(&mut self, id: &str, now: u64) -> Result<Request, Error> {
        let request = self.get_mut(id)?;
        if request.state != State::Marked {
            return Err(Error::new("requests-state", id));
        }
        let review = review::next(id, now, &request.review_history)?;
        request.review_history.push(review.clone());
        request.review = Some(review);
        Ok(request.clone())
    }

    /// Apply one adjudication against the latest marked review.
    ///
    /// # Errors
    /// Refuses a stale identifier, malformed answer or already decided request.
    pub fn adjudicate(&mut self, document: &Value, kinds: &[Kind<'_>]) -> Result<Request, Error> {
        if !exact(document, &["schema", "id", "review_id", "decision"])
            || document["schema"].as_u64() != Some(1)
        {
            return Err(Error::new("requests-document", "adjudication envelope"));
        }
        let id = document["id"]
            .as_str()
            .ok_or_else(|| Error::new("requests-document", "id"))?;
        let request = self.get_mut(id)?;
        if request.state != State::Marked {
            return Err(Error::new("requests-state", id));
        }
        if request
            .review
            .as_ref()
            .is_none_or(|review| document["review_id"].as_str() != Some(&review.review_id))
        {
            return Err(Error::new("requests-review-id", id));
        }
        let decision = serde_json::from_value(document["decision"].clone())
            .map_err(|_| Error::new("requests-document", id))?;
        request.decide(decision, State::Adjudicated, kinds)?;
        Ok(request.clone())
    }

    /// Record that a worker has gone; no answer or permission follows from absence.
    ///
    /// # Errors
    /// Refuses an unknown identifier.
    pub fn waiter_gone(&mut self, id: &str) -> Result<(), Error> {
        self.get_mut(id)?.waiter_gone = true;
        Ok(())
    }

    /// Claim service execution once; false means no new execution is admitted.
    ///
    /// # Errors
    /// Refuses an undecided request, malformed claim or conflicting service claim.
    pub fn claim(&mut self, id: &str, claim: &str) -> Result<bool, Error> {
        let request = self.get_mut(id)?;
        if claim.trim().is_empty() {
            return Err(Error::new("requests-service-claim", id));
        }
        if let Some(previous) = &request.service_claim {
            return if previous == claim {
                Ok(false)
            } else {
                Err(Error::new("requests-service-claim", id))
            };
        }
        if request.state != State::ServicePending {
            return Err(Error::new("requests-state", id));
        }
        request.service_claim = Some(claim.to_owned());
        if request.waiter_gone {
            request.service_result =
                Some(json!({"outcome":"refused","reason":"waiter-gone","performed":false}));
            request.state = State::Completed;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Save the claimed service's one durable result, admitting identical retries.
    ///
    /// # Errors
    /// Refuses another claim, a conflicting result or an unclaimed request.
    pub fn complete(&mut self, id: &str, claim: &str, result: Value) -> Result<(), Error> {
        let request = self.get_mut(id)?;
        if request.service_claim.as_deref() != Some(claim) || !result.is_object() {
            return Err(Error::new("requests-service-claim", id));
        }
        if request.state == State::Completed {
            return if request.service_result.as_ref() == Some(&result) {
                Ok(())
            } else {
                Err(Error::new("requests-service-result", id))
            };
        }
        if request.state != State::ServicePending {
            return Err(Error::new("requests-state", id));
        }
        request.service_result = Some(result);
        request.state = State::Completed;
        Ok(())
    }

    #[must_use]
    pub fn list(&self, pending: bool, now: u64) -> Value {
        json!({"schema":1,"requests":self.requests.iter().filter(|row| !pending || row.state.pending()).map(|row| json!({"id":row.id,"kind":row.kind,"state":row.state,"age":now.saturating_sub(row.filed_ns)/1_000_000_000})).collect::<Vec<_>>()})
    }

    #[must_use]
    pub fn status(&self, pending: bool, now: u64) -> Value {
        let mut counts = BTreeMap::new();
        let mut oldest = None;
        for row in &self.requests {
            if pending && !row.state.pending() {
                continue;
            }
            *counts
                .entry((&row.kind, row.state.as_str()))
                .or_insert(0_u64) += 1;
            if row.state.pending() {
                oldest =
                    Some(oldest.map_or(row.filed_ns, |previous: u64| previous.min(row.filed_ns)));
            }
        }
        json!({"schema":1,"counts":counts.into_iter().map(|((kind,state),count)| json!({"kind":kind,"state":state,"count":count})).collect::<Vec<_>>(),"oldest_waiting_age":oldest.map(|at| now.saturating_sub(at)/1_000_000_000)})
    }
}
