//! Collection protocol. Permission authority stays with the journal; snapshot
//! evaluation alone grants no authority and performs no service effects.

use request_core::{Collection, Error, Kind};
use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) fn failure(error: impl std::fmt::Display) -> Error {
    Error::new("requests-permission", error.to_string())
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn permission_body(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        crate::journal::validate_record(object).is_ok()
            && value["schema"] == 2
            && value["event"] == "escalated"
    })
}

use execute_command::escalation::permission_answer;

fn door_body(value: &Value) -> bool {
    // The custody owner validates the source record before entering this pure
    // protocol. These fields bind the common record to that source identity.
    exact(value, &["source_id", "record"])
        && value["source_id"].as_str().is_some_and(|id| !id.is_empty())
        && value["record"].is_object()
        && value["record"]["id"] == value["source_id"]
}

fn door_answer(_: &Value, value: &Value) -> bool {
    exact(value, &["outcome"]) && matches!(value["outcome"].as_str(), Some("allow" | "refuse"))
}

/// The admitted permission, custody and gateway request kinds.
#[must_use]
pub fn kinds() -> [Kind<'static>; 4] {
    [
        request_core::gateway::kind(),
        Kind {
            name: "permission-case",
            service: false,
            body: permission_body,
            answer: permission_answer,
        },
        Kind {
            name: "door-before-effect",
            service: true,
            body: door_body,
            answer: door_answer,
        },
        Kind {
            name: "door-after-effect",
            service: false,
            body: door_body,
            answer: door_answer,
        },
    ]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    collection: Collection,
    document: Option<Value>,
    id: Option<String>,
    pending: bool,
    now_ns: u64,
}

/// Evaluate a custody owner's snapshot without accessing its files or effects.
///
/// # Errors
/// Refuses malformed envelopes, unknown commands, kinds and invalid transitions.
pub fn snapshot(action: &str, input: &[u8]) -> Result<Value, Error> {
    let value: Value = serde_json::from_slice(input).map_err(failure)?;
    if !exact(
        &value,
        &[
            "schema",
            "collection",
            "document",
            "id",
            "pending",
            "now_ns",
        ],
    ) {
        return Err(Error::new("requests-document", "snapshot envelope fields"));
    }
    let mut envelope: Snapshot = serde_json::from_value(value).map_err(failure)?;
    if envelope.schema != 1 {
        return Err(Error::new("requests-schema", "snapshot envelope"));
    }
    let result = apply(
        &mut envelope.collection,
        action,
        envelope.document.as_ref(),
        envelope.id.as_deref(),
        envelope.pending,
        envelope.now_ns,
    )?;
    Ok(json!({"schema":1,"collection":envelope.collection,"result":result}))
}

pub(crate) fn apply(
    collection: &mut Collection,
    action: &str,
    document: Option<&Value>,
    id: Option<&str>,
    pending: bool,
    now: u64,
) -> Result<Value, Error> {
    let kinds = kinds();
    collection.validate(&kinds)?;
    let result = match (action, document, id, pending) {
        ("status", None, None, _) => collection.status(pending, now),
        ("list", None, None, _) => collection.list(pending, now),
        ("triage", Some(document), None, false) => collection.triage(document, &kinds)?,
        ("review", None, Some(id), false) => {
            serde_json::to_value(collection.review(id, now)?).map_err(failure)?
        }
        ("adjudicate", Some(document), None, false) => {
            serde_json::to_value(collection.adjudicate(document, &kinds)?).map_err(failure)?
        }
        _ => {
            return Err(Error::new(
                "requests-usage",
                "status|list [--pending], triage, review ID, adjudicate",
            ));
        }
    };
    if !matches!(action, "status" | "list") {
        collection.revision = collection
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::new("requests-revision", "exhausted"))?;
    }
    collection.validate(&kinds)?;
    Ok(result)
}

pub(crate) const SNAPSHOT_SCHEMA: &str = "superloop-requests-v1";

pub(crate) fn metadata(value: &Value) -> Result<Option<Collection>, Error> {
    if value["schema"] != SNAPSHOT_SCHEMA {
        return Ok(None);
    }
    if !exact(value, &["schema", "collection"]) {
        return Err(failure("invalid journal collection"));
    }
    let collection: Collection =
        serde_json::from_value(value["collection"].clone()).map_err(failure)?;
    collection.validate(&kinds())?;
    Ok(Some(collection))
}
