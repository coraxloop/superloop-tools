//! The custody owner's two-phase request protocol. Preview is pure; commit
//! compares its complete preimage while holding the permission journal lock.

use request_core::{Collection, Error, Request, transaction::Transaction};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CallerRole, Journal, Scope};
use crate::requests::{SNAPSHOT_SCHEMA, failure, kinds};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerInput {
    schema: u32,
    records: Vec<Request>,
    document: Option<Value>,
    id: Option<String>,
    pending: bool,
    now_ns: u64,
    expected: Option<Collection>,
    publication: Option<Collection>,
}

fn decode(input: &[u8]) -> Result<OwnerInput, Error> {
    let value: Value = serde_json::from_slice(input).map_err(failure)?;
    let fields = [
        "schema",
        "records",
        "document",
        "id",
        "pending",
        "now_ns",
        "expected",
        "publication",
    ];
    if !value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    }) {
        return Err(failure("owner envelope fields"));
    }
    let input: OwnerInput = serde_json::from_value(value).map_err(failure)?;
    if input.schema != 1 {
        return Err(failure("owner envelope schema"));
    }
    Ok(input)
}

fn merge(collection: &mut Collection, records: Vec<Request>) -> Result<(), Error> {
    let supplied = Collection {
        schema: 1,
        revision: 0,
        requests: records,
    };
    supplied.validate(&kinds())?;
    for request in supplied.requests {
        if request.kind == "gateway-proposal" {
            let filed = Request::filed(
                request.id.clone(),
                request.kind.clone(),
                request.body.clone(),
                request.worker.clone(),
                request.run.clone(),
                request.filed_ns,
            );
            if request != filed {
                return Err(failure(
                    "gateway filing cannot supply a decision or service state",
                ));
            }
            if let Some(old) = collection.requests.iter().find(|row| row.id == request.id) {
                if old.body != request.body
                    || old.worker != request.worker
                    || old.run != request.run
                    || old.filed_ns != request.filed_ns
                {
                    return Err(Error::new("requests-conflict", &request.id));
                }
            } else {
                collection.file(request, &kinds())?;
            }
            continue;
        }
        if !matches!(
            request.kind.as_str(),
            "door-before-effect" | "door-after-effect"
        ) {
            return Err(failure("custody owner supplied a foreign kind"));
        }
        if let Some(old) = collection
            .requests
            .iter_mut()
            .find(|row| row.id == request.id)
        {
            let mut comparison = request.clone();
            comparison.body = old.body.clone();
            comparison.waiter_gone = old.waiter_gone;
            if comparison != *old || (old.waiter_gone && !request.waiter_gone) {
                return Err(Error::new("requests-conflict", &request.id));
            }
            *old = request;
        } else {
            collection.file(request, &kinds())?;
        }
    }
    Ok(())
}

fn apply(collection: &mut Collection, action: &str, input: &OwnerInput) -> Result<Value, Error> {
    if action == "file" {
        if input.pending
            || input.id.is_some()
            || input.document.is_some()
            || input.publication.is_some()
            || input
                .records
                .iter()
                .any(|row| row.kind != "gateway-proposal")
        {
            return Err(failure("gateway filing envelope fields"));
        }
        collection.revision = collection
            .revision
            .checked_add(1)
            .ok_or_else(|| failure("revision exhausted"))?;
        return Ok(json!({"filed":input.records.len()}));
    }
    if !matches!(action, "claim" | "complete" | "withdraw") {
        return crate::requests::apply(
            collection,
            action,
            input.document.as_ref(),
            input.id.as_deref(),
            input.pending,
            input.now_ns,
        );
    }
    if input.pending || input.id.is_some() {
        return Err(failure("service envelope fields"));
    }
    let document = input
        .document
        .as_ref()
        .ok_or_else(|| failure("service document absent"))?;
    let fields: &[&str] = match action {
        "claim" => &["schema", "id", "claim"],
        "complete" => &["schema", "id", "claim", "result"],
        _ => &["schema", "id"],
    };
    if document["schema"] != 1
        || !document.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
        })
    {
        return Err(failure("service document fields"));
    }
    let id = document["id"]
        .as_str()
        .ok_or_else(|| failure("service id absent"))?;
    if !collection.requests.iter().any(|row| {
        row.id == id && matches!(row.kind.as_str(), "door-before-effect" | "gateway-proposal")
    }) {
        return Err(Error::new("requests-kind", id));
    }
    let result = match action {
        "claim" => {
            json!({"claimed":collection.claim(id, document["claim"].as_str().ok_or_else(|| failure("claim absent"))?)?})
        }
        "complete" => {
            collection.complete(
                id,
                document["claim"]
                    .as_str()
                    .ok_or_else(|| failure("claim absent"))?,
                document["result"].clone(),
            )?;
            json!({"completed":true})
        }
        _ => {
            collection.waiter_gone(id)?;
            json!({"waiter_gone":true})
        }
    };
    collection.revision = collection
        .revision
        .checked_add(1)
        .ok_or_else(|| failure("revision exhausted"))?;
    collection.validate(&kinds())?;
    Ok(result)
}

fn publication(next: &Collection, candidate: &Collection) -> Result<Collection, Error> {
    let mut comparison = candidate.clone();
    for row in &mut comparison.requests {
        if matches!(
            row.kind.as_str(),
            "door-before-effect" | "door-after-effect"
        ) {
            let source = next
                .requests
                .iter()
                .find(|source| source.id == row.id)
                .ok_or_else(|| Error::new("requests-conflict", &row.id))?;
            if row.body.get("source_id") != source.body.get("source_id") {
                return Err(Error::new("requests-conflict", &row.id));
            }
            row.body = source.body.clone();
        }
    }
    if comparison != *next {
        return Err(failure(
            "owner publication changes the evaluated transition",
        ));
    }
    candidate.validate(&kinds())?;
    Ok(candidate.clone())
}

fn gateway_authority(
    journal: &Journal,
    caller: &CallerRole,
    action: &str,
    before: &Collection,
    next: &Collection,
) -> Result<(), Error> {
    for row in next
        .requests
        .iter()
        .filter(|row| row.kind == "gateway-proposal")
    {
        let old = before.requests.iter().find(|old| old.id == row.id);
        let judgement_changed = old.is_some_and(|old| {
            (matches!(action, "triage" | "review" | "adjudicate") && old != row)
                || old.decision != row.decision
                || old.review != row.review
                || old.review_history != row.review_history
        });
        if judgement_changed
            && (!caller.is_orchestrator()
                || caller
                    .entry()
                    .and_then(crate::role::RegistryEntry::state_root)
                    != journal.registered_root.as_deref()
                || row.body.get("loop_name").and_then(Value::as_str) != caller.loop_name())
        {
            return Err(Error::new("requests-authority", &row.id));
        }
    }
    Ok(())
}

impl super::ReviewJournal {
    /// Export the common record for its custody owner without modifying state.
    ///
    /// # Errors
    /// Refuses unsafe or inconsistent journal records.
    pub fn owner_read(&self) -> Result<Collection, Error> {
        super::requests::collection(&self.journal.request_bytes()?)
    }

    /// Preview one owner transaction without taking a write lock.
    ///
    /// # Errors
    /// Refuses the same invalid inputs and authority as a changing transaction.
    pub fn owner_preview(
        &self,
        caller: &CallerRole,
        action: &str,
        input: &[u8],
    ) -> Result<Value, Error> {
        self.journal.owner_transaction(caller, action, input, false)
    }
}

impl Journal {
    /// Evaluate or publish the custody owner's common transaction. The owner
    /// holds its door lock across preview, source checks and commit; this method
    /// holds the journal lock and enforces permission authority independently.
    ///
    /// # Errors
    /// Refuses mismatched preimages, unvalidated kinds, authority failures and
    /// failed publication. Preview creates neither state nor a write lock.
    pub fn owner_transaction(
        &self,
        caller: &CallerRole,
        action: &str,
        input: &[u8],
        commit: bool,
    ) -> Result<Value, Error> {
        if self.scope != Scope::Loop || self.registered_root.is_none() {
            return Err(failure("owner transaction requires registered loop"));
        }
        let input = decode(input)?;
        if commit != input.expected.is_some() || (!commit && input.publication.is_some()) {
            return Err(failure("commit requires preview preimage"));
        }
        let directory = self.request_directory()?;
        let _lock = if commit {
            Some(super::request_lock::acquire(&directory, self)?)
        } else {
            None
        };
        let snapshot =
            request_core::transaction::snapshot(&directory, super::journal_filename(self.scope))?;
        let bytes = snapshot
            .as_ref()
            .map(request_core::transaction::Snapshot::bytes)
            .unwrap_or_default();
        let saved = super::requests::collection(bytes)?;
        let mut before = saved.clone();
        merge(&mut before, input.records.clone())?;
        if input
            .expected
            .as_ref()
            .is_some_and(|expected| *expected != before)
        {
            return Err(Error::new("requests-conflict", "preview preimage changed"));
        }
        let mut next = before.clone();
        let result = apply(&mut next, action, &input)?;
        if action == "file" && before == saved {
            next.revision = saved.revision;
        }
        if let Some(candidate) = &input.publication {
            next = publication(&next, candidate)?;
        }
        gateway_authority(self, caller, action, &before, &next)?;
        // Permission records stay behind the established caller and scope checks,
        // even when a door-owning process transports the transaction.
        for row in next
            .requests
            .iter()
            .filter(|row| row.kind == "permission-case")
        {
            if before.requests.iter().find(|old| old.id == row.id) != Some(row)
                && (!caller.is_orchestrator()
                    || caller
                        .entry()
                        .and_then(crate::role::RegistryEntry::state_root)
                        != self.registered_root.as_deref()
                    || row.body.get("scope").and_then(Value::as_str) != Some("loop")
                    || row.body.get("loop_name").and_then(Value::as_str) != caller.loop_name())
            {
                return Err(Error::new("requests-authority", &row.id));
            }
        }
        if commit {
            if matches!(action, "status" | "list") {
                return Err(failure("read command cannot commit"));
            }
            if next == saved {
                return Ok(json!({"schema":1,"before":before,"collection":next,"result":result}));
            }
            let mut published = super::requests::publication_base(bytes)?;
            for row in next
                .requests
                .iter()
                .filter(|row| row.kind == "permission-case" && row.decision.is_some())
            {
                if saved
                    .requests
                    .iter()
                    .any(|old| old.id == row.id && old.decision.is_none())
                {
                    published.extend(
                        serde_json::to_vec(&super::requests::disposition(row, caller)?)
                            .map_err(failure)?,
                    );
                    published.push(b'\n');
                }
            }
            published.extend(
                serde_json::to_vec(&json!({"schema":SNAPSHOT_SCHEMA,"collection":next}))
                    .map_err(failure)?,
            );
            published.push(b'\n');
            let mut transaction = Transaction::open(
                &directory,
                super::journal_filename(self.scope),
                ".requests-transaction.lock",
            )?;
            if !transaction.matches_snapshot(&snapshot) {
                return Err(failure("journal identity changed under owner lock"));
            }
            transaction.replace(&published)?;
        }
        Ok(json!({"schema":1,"before":before,"collection":next,"result":result}))
    }
}
