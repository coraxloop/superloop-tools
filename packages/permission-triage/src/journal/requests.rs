use std::collections::BTreeMap;

use request_core::{Collection, Decision, Error, Request, State, transaction::Transaction};
use serde_json::{Value, json};

use super::{CallerRole, DispositionDetail, DispositionOutcome, Journal, Scope};
use crate::requests::{SNAPSHOT_SCHEMA, failure, kinds, metadata};

fn timestamp(value: &Value) -> Result<u64, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| failure("missing source time"))?;
    // Invert the canonical fixed UTC representation without a second calendar
    // implementation. The nanosecond range is bounded by the collection type.
    let (mut low, mut high) = (0_u64, u64::MAX);
    while low < high {
        let middle = low + (high - low) / 2;
        if request_core::utc_time(middle).as_str() < text {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if request_core::utc_time(low) == text {
        Ok(low)
    } else {
        Err(failure("source time outside canonical range"))
    }
}

fn legacy_decision(value: &Value) -> Result<Decision, Error> {
    let outcome = value["outcome"]
        .as_str()
        .ok_or_else(|| failure("missing disposition outcome"))?;
    let reason = value["reason"]
        .as_str()
        .ok_or_else(|| failure("missing disposition reason"))?;
    let answer = match outcome {
        "adjudicated-rejected" => json!({"outcome":outcome}),
        "adjudicated-rule-added" => {
            json!({"outcome":outcome,"rule":reason.strip_prefix("rule=").ok_or_else(|| failure("invalid rule disposition"))?})
        }
        "corrected-and-rerun" | "adjudicated-approved" => {
            json!({"outcome":outcome,"request_digest":value["request_digest"]})
        }
        _ => return Err(failure("unknown disposition outcome")),
    };
    Ok(Decision {
        answer,
        reason: reason.to_owned(),
    })
}

pub(super) fn collection(bytes: &[u8]) -> Result<Collection, Error> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(failure("torn journal tail"));
    }
    let mut saved = Collection::default();
    let mut sources = BTreeMap::new();
    let mut decisions = BTreeMap::new();
    for line in super::complete_lines(bytes) {
        let value: Value = serde_json::from_slice(line).map_err(failure)?;
        if let Some(snapshot) = metadata(&value)? {
            if snapshot.revision <= saved.revision {
                return Err(failure("journal collection revision regressed"));
            }
            saved = snapshot;
            continue;
        }
        let object = value
            .as_object()
            .ok_or_else(|| failure("non-object journal row"))?;
        super::validate_record(object).map_err(failure)?;
        if value.get("schema").and_then(Value::as_u64) != Some(2) {
            continue;
        }
        let event_id = value
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("source id absent"))?;
        match value.get("event").and_then(Value::as_str) {
            Some("escalated") => {
                if sources.insert(event_id.to_owned(), value).is_some() {
                    return Err(failure("duplicate escalation"));
                }
            }
            Some("disposition") => {
                if decisions.insert(event_id.to_owned(), value).is_some() {
                    return Err(failure("duplicate disposition"));
                }
            }
            _ => (),
        }
    }
    let kinds = kinds();
    for (event_id, source) in &sources {
        let id = request_core::request_id(event_id.as_bytes());
        if !saved.requests.iter().any(|request| request.id == id) {
            saved.file(
                Request::filed(
                    id.clone(),
                    "permission-case".to_owned(),
                    source.clone(),
                    source["role"].as_str().unwrap_or("unknown").to_owned(),
                    event_id.clone(),
                    timestamp(&source["recorded_at"])?,
                ),
                &kinds,
            )?;
        }
        let request = saved
            .requests
            .iter_mut()
            .find(|request| request.id == id)
            .ok_or_else(|| failure("source admission failed"))?;
        if request.body != *source {
            return Err(failure("collection source changed"));
        }
        match (request.decision.as_ref(), decisions.get(event_id)) {
            (Some(decision), Some(legacy)) => {
                if decision.answer != legacy_decision(legacy)?.answer {
                    return Err(failure("collection and disposition disagree"));
                }
            }
            (None, Some(legacy)) => {
                request.decision = Some(legacy_decision(legacy)?);
                request.decision_state = Some(State::TriageDecided);
                request.state = State::TriageDecided;
            }
            (Some(_), None) => return Err(failure("collection disposition missing")),
            (None, None) => (),
        }
    }
    if saved
        .requests
        .iter()
        .filter(|row| row.kind == "permission-case")
        .count()
        != sources.len()
        || decisions.keys().any(|id| !sources.contains_key(id))
    {
        return Err(failure("orphan collection or disposition"));
    }
    saved.validate(&kinds)?;
    Ok(saved)
}

pub(super) fn disposition(request: &Request, caller: &CallerRole) -> Result<Value, Error> {
    let source = request
        .body
        .as_object()
        .ok_or_else(|| failure("source absent"))?;
    let decision = request
        .decision
        .as_ref()
        .ok_or_else(|| failure("decision absent"))?;
    let answer = &decision.answer;
    let (outcome, detail) = match answer["outcome"].as_str() {
        Some("adjudicated-rejected") => (
            DispositionOutcome::AdjudicatedRejected,
            DispositionDetail::Rejection(decision.reason.clone()),
        ),
        Some("adjudicated-rule-added") => (
            DispositionOutcome::AdjudicatedRuleAdded,
            DispositionDetail::Rule(
                answer["rule"]
                    .as_str()
                    .ok_or_else(|| failure("rule absent"))?
                    .to_owned(),
            ),
        ),
        Some("corrected-and-rerun") => (
            DispositionOutcome::CorrectedAndRerun,
            DispositionDetail::CorrectedRequestDigest(
                answer["request_digest"]
                    .as_str()
                    .ok_or_else(|| failure("digest absent"))?
                    .to_owned(),
            ),
        ),
        Some("adjudicated-approved") => (
            DispositionOutcome::AdjudicatedApproved,
            DispositionDetail::ApprovedRequestDigest(
                answer["request_digest"]
                    .as_str()
                    .ok_or_else(|| failure("digest absent"))?
                    .to_owned(),
            ),
        ),
        _ => return Err(failure("unknown answer")),
    };
    if source.get("scope").and_then(Value::as_str) != Some("loop")
        || source.get("loop_name").and_then(Value::as_str) != caller.loop_name()
        || (outcome == DispositionOutcome::AdjudicatedApproved
            && source.get("role").and_then(Value::as_str) != Some("orchestrator"))
    {
        return Err(failure("adjudicator has no authority for this source"));
    }
    super::disposition_value(source, outcome, detail, caller).map_err(failure)
}

pub(super) fn publication_base(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut retained = Vec::new();
    for line in super::complete_lines(bytes) {
        let value: Value = serde_json::from_slice(line).map_err(failure)?;
        if value.get("schema").and_then(Value::as_str) != Some(SNAPSHOT_SCHEMA) {
            retained.extend_from_slice(line);
            retained.push(b'\n');
        }
    }
    Ok(retained)
}

impl super::ReviewJournal {
    /// Inspect common summaries without creating state or taking a write lock.
    ///
    /// # Errors
    /// Refuses malformed journals or a command other than status or list.
    pub fn requests(&self, action: &str, pending: bool) -> Result<Value, Error> {
        if !matches!(action, "status" | "list") {
            return Err(failure("read-only journal command"));
        }
        self.journal
            .requests(&CallerRole::Unknown, action, None, None, pending)
    }
}

impl Journal {
    /// Read or atomically change the registered permission collection. Old
    /// dispositions and collection bookkeeping share the same journal commit.
    ///
    /// # Errors
    /// Refuses unsafe custody, unknown authority, invalid records or transitions,
    /// conflicting snapshots and failed durable publication.
    pub fn requests(
        &self,
        caller: &CallerRole,
        action: &str,
        document: Option<&Value>,
        id: Option<&str>,
        pending: bool,
    ) -> Result<Value, Error> {
        let now = request_core::now_ns()?;
        if matches!(action, "status" | "list") {
            return crate::requests::apply(
                &mut collection(&self.request_bytes()?)?,
                action,
                document,
                id,
                pending,
                now,
            );
        }
        if self.scope == Scope::Estate
            || !caller.is_orchestrator()
            || self.registered_root.is_none()
            || caller
                .entry()
                .and_then(crate::role::RegistryEntry::state_root)
                != self.registered_root.as_deref()
        {
            return Err(failure("adjudicator has no registered loop authority"));
        }
        let directory = self.request_directory()?;
        let _lock = super::request_lock::acquire(&directory, self)?;
        let snapshot =
            request_core::transaction::snapshot(&directory, super::journal_filename(self.scope))?;
        let before = snapshot
            .as_ref()
            .map(request_core::transaction::Snapshot::bytes)
            .unwrap_or_default();
        let previous = collection(before)?;
        let mut next = previous.clone();
        let result = crate::requests::apply(&mut next, action, document, id, pending, now)?;
        let mut bytes = publication_base(before)?;
        for (old, new) in previous.requests.iter().zip(&next.requests) {
            if old != new
                && (new.body.get("loop_name").and_then(Value::as_str) != caller.loop_name()
                    || (new.kind == "permission-case"
                        && new.body.get("scope").and_then(Value::as_str) != Some("loop")))
            {
                return Err(failure("foreign source authority"));
            }
            if new.kind == "permission-case" && old.decision.is_none() && new.decision.is_some() {
                bytes.extend(serde_json::to_vec(&disposition(new, caller)?).map_err(failure)?);
                bytes.push(b'\n');
            }
        }
        bytes.extend(
            serde_json::to_vec(&json!({"schema":SNAPSHOT_SCHEMA,"collection":next}))
                .map_err(failure)?,
        );
        bytes.push(b'\n');
        let mut transaction = Transaction::open(
            &directory,
            super::journal_filename(self.scope),
            ".requests-transaction.lock",
        )?;
        if !transaction.matches_snapshot(&snapshot) {
            return Err(failure("journal identity changed under lock"));
        }
        transaction.replace(&bytes)?;
        Ok(result)
    }

    pub(super) fn request_bytes(&self) -> Result<Vec<u8>, Error> {
        let directory = self.request_directory()?;
        Ok(
            request_core::transaction::read(&directory, super::journal_filename(self.scope))?
                .unwrap_or_default(),
        )
    }

    pub(super) fn request_directory(&self) -> Result<std::fs::File, Error> {
        let directory = self
            .root_descriptor()
            .ok_or_else(|| failure("registered descriptor absent"))?;
        if std::os::unix::fs::MetadataExt::uid(&directory.metadata().map_err(failure)?)
            != nix::unistd::geteuid().as_raw()
        {
            return Err(failure("request root owner differs"));
        }
        Ok(directory)
    }
}
