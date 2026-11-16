#![allow(clippy::indexing_slicing)]
use super::*;

/// ´test:unit:legacy-index-merge-matches-linear-shuffled-journals´
#[test]
fn legacy_index_merge_matches_linear_shuffled_journals() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("own fixture cleanup");
        }
    }
    let root = std::env::temp_dir().join(format!(
        "legacy-index-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let root = Root(root);
    let journal = Journal::from_state_root(&root.0.join("state"));
    for n in 0..8 {
        journal
            .append_test_escalation(&format!("printf {n}"), "fixture")
            .unwrap();
    }
    let bytes = journal.read().unwrap();
    let lines = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let saved = collection(&bytes).unwrap();
    for seed in 0..32 {
        for retained in [0, 3, 8] {
            let mut rows = saved.requests.clone();
            rows.rotate_left(seed % 8);
            if seed % 2 == 1 {
                rows.reverse();
            }
            rows.truncate(retained);
            let snapshot = Collection {
                schema: 1,
                revision: 1,
                requests: rows,
            };
            snapshot.validate(&kinds()).unwrap();
            let mut ordered = lines.clone();
            ordered.rotate_left((seed + 3) % 8);
            if seed % 3 == 0 {
                ordered.reverse();
            }
            let mut input = Vec::new();
            for line in ordered {
                input.extend(line);
                input.push(b'\n');
            }
            input.extend(
                serde_json::to_vec(&json!({"schema":SNAPSHOT_SCHEMA,"collection":snapshot}))
                    .unwrap(),
            );
            input.push(b'\n');
            let encode = |result: Result<Collection, Error>| {
                result
                    .map(|v| serde_json::to_vec(&v).unwrap())
                    .map_err(|e| e.to_string())
            };
            assert_eq!(
                encode(collection(&input)),
                encode(linear_collection(&input)),
                "{seed}/{retained}"
            );
            // A saved source with changed content must still refuse, not replace the source.
            let mut changed = snapshot;
            if let Some(row) = changed.requests.first_mut() {
                row.body["reason"] = json!("changed");
            }
            let mut bad = bytes.clone();
            bad.extend(
                serde_json::to_vec(&json!({"schema":SNAPSHOT_SCHEMA,"collection":changed}))
                    .unwrap(),
            );
            bad.push(b'\n');
            assert_eq!(encode(collection(&bad)), encode(linear_collection(&bad)));
        }
    }
}

fn linear_collection(bytes: &[u8]) -> Result<Collection, Error> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(failure("torn journal tail"));
    }
    let mut saved = Collection::default();
    let mut sources = BTreeMap::new();
    let mut decisions = BTreeMap::new();
    for line in super::super::complete_lines(bytes) {
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
        super::super::validate_record(object).map_err(failure)?;
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
