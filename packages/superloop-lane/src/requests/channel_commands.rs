use std::io::{self, Read as _};
use std::path::Path;

use crate::error::LaneError;
use crate::requests::store::Store;
use serde_json::{Value, json};

fn document(input: &mut impl io::Read) -> Result<Value, LaneError> {
    let mut bytes = Vec::new();
    input
        .take(super::MAX_BATCH_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("requests-document", error.to_string()))?;
    if bytes.len() > super::MAX_BATCH_BYTES {
        return Err(LaneError::input(
            "requests-document",
            "input exceeds cap of 65,536 bytes; at least 65,537 bytes received",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("requests-document", error.to_string()))
}

pub(super) fn run(
    owner_home: &Path,
    args: &[String],
    input: &mut impl io::Read,
    output: &mut impl io::Write,
) -> Result<(), LaneError> {
    let [action, loop_name, rest @ ..] = args else {
        return Err(super::usage());
    };
    let started = std::time::Instant::now();
    let store = Store::open(owner_home, loop_name, false)?;
    let store = if action == "list" {
        store.with_reader_deadline(started + crate::requests::store::reader_lock_wait())
    } else {
        store
    };
    let result = match (action.as_str(), rest) {
        ("status" | "list", []) => read(&store, action, loop_name, false)?,
        ("status" | "list", [flag]) if flag == "--pending" => {
            read(&store, action, loop_name, true)?
        }
        ("triage" | "adjudicate", []) => {
            store.collection_command(action, Some(&document(input)?), None, false)?
        }
        ("review", [id]) => {
            let result =
                store.collection_command("review", None, Some(&store.collection_id(id)), false)?;
            if id.contains(':') {
                result["body"]["record"].clone()
            } else {
                result
            }
        }
        ("triage", [run]) => {
            let document = document(input)
                .map_err(|error| LaneError::input("requests-batch-refusal", error.detail))?;
            let decisions = document.as_array().ok_or_else(|| {
                LaneError::input("requests-batch-refusal", "expected decision array")
            })?;
            let count = store
                .collection_legacy_triage(run, decisions)
                .map_err(|error| LaneError::input("requests-batch-refusal", error.line()))?;
            json!({"schema":1,"loop":loop_name,"run":run,"changed":count,"mode_reports":[],"requests":store.list_run(run)?.iter().map(crate::requests::RequestRecord::value).collect::<Vec<_>>()})
        }
        ("adjudicate", [id, review, outcome, reason]) => {
            let document = json!({"schema":1,"id":store.collection_id(id),"review_id":review,"decision":{"answer":{"outcome":outcome},"reason":reason}});
            let result = store.collection_command("adjudicate", Some(&document), None, false)?;
            let mut record = result["body"]["record"].clone();
            record["mode_reports"] = json!([]);
            record
        }
        ("list", [flag, state])
            if flag == "--state"
                && matches!(
                    state.as_str(),
                    "waiting" | "observed" | "marked" | "adjudicated"
                ) =>
        {
            store.collection_command("list", None, None, false)?;
            let (records, _, shape_stale) = store.list_with_status()?;
            let records = records
                .into_iter()
                .filter(|row| row.value()["state"] == *state)
                .collect::<Vec<_>>();
            super::list_response(loop_name, &records, shape_stale)?
        }
        _ => return Err(super::usage()),
    };
    super::emit(output, &result)
}

fn read(store: &Store, action: &str, loop_name: &str, pending: bool) -> Result<Value, LaneError> {
    let mut result = store.collection_command(action, None, None, pending)?;
    let (records, shapes, stale) = store.list_with_status()?;
    result["loop"] = json!(loop_name);
    result["shape_record"] = json!(if stale { "stale" } else { "current" });
    result["schema"] = json!(2);
    result["decisions"] = super::list_response(loop_name, &records, stale)?["decisions"].clone();
    result["preflight_refusals"] = json!(
        records
            .iter()
            .filter(|row| row.value()["state"] == "preflight-refused")
            .map(crate::requests::RequestRecord::value)
            .collect::<Vec<_>>()
    );
    if action == "status" {
        result["door_floor"] = json!(store.floor().as_str());
        result["shape_path"] = json!(store.shape_path());
        result["shapes"] = shapes;
        result["learned_index"] = store.learned_status();
    }
    Ok(result)
}
