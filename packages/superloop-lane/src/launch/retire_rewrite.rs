//! Listed one-time conversion of the collection predecessor, never a live fallback.

use super::*;

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("retire-rewrite-record", detail)
}

fn convert(before: &Value, before_hash: &str) -> Result<Value, LaneError> {
    let keys = [
        "checkpoint_index",
        "state",
        "instant_unix_ns",
        "planned",
        "remaining",
        "refusal",
        "component",
        "token",
        "parent_identity",
        "home_identity",
    ];
    let object = before["collection"].as_object().ok_or_else(|| {
        refusal("missing=[] extra=[] invalid=[collection: expected predecessor object]")
    })?;
    let missing = keys
        .iter()
        .filter(|key| !object.contains_key(**key))
        .copied()
        .collect::<Vec<_>>();
    let extra = object
        .keys()
        .filter(|key| !keys.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let mut after = before.clone();
    after["collection"]["writable_collected_first"] = Value::Null;
    let mut invalid = Vec::new();
    if after["collection"]["checkpoint_index"].as_u64().is_none()
        || after["collection"]["checkpoint_index"] != after["harvest_agreement"]["checkpoint_index"]
    {
        invalid.push("checkpoint_index");
    }
    if after["collection"]["instant_unix_ns"].as_u64().is_none() {
        invalid.push("instant_unix_ns");
    }
    if after["collection"]["token"].as_str().is_none_or(|token| {
        token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        invalid.push("token");
    }
    for key in ["parent_identity", "home_identity"] {
        let identity = &after["collection"][key];
        if identity.as_object().is_none_or(|fields| fields.len() != 2)
            || identity["device"].as_u64().is_none()
            || identity["inode"].as_u64().is_none()
        {
            invalid.push(key);
        }
    }
    let mut agreement_only = after.clone();
    agreement_only["collection"] = Value::Null;
    if super::super::harvest::harvest_fields(&agreement_only).is_err()
        || after["harvest_agreement"].is_null()
    {
        invalid.push("harvest_agreement");
    }
    let collection = &after["collection"];
    if collection["planned"]
        .as_array()
        .is_none_or(|paths| !super::super::harvest::valid_planned(paths))
    {
        invalid.push("planned");
    }
    invalid_disposition(collection, &mut invalid);
    if !missing.is_empty() || !extra.is_empty() || !invalid.is_empty() {
        return Err(refusal(format!(
            "missing={missing:?} extra={extra:?} invalid={invalid:?}; only the collection shape without writable_collected_first is listed"
        )));
    }
    if before.get("retirement_rewrite").is_some() {
        return Err(refusal(
            "missing=[] extra=[retirement_rewrite] invalid=[]; use the existing journal",
        ));
    }
    after["retirement_rewrite"] = json!({"schema":1,"conversion":"collection-writable-collected-first","original_collection":before["collection"],"original_agreement":before["harvest_agreement"],"before_sha256":before_hash,"old_home_inspected":false});
    Ok(after)
}

fn invalid_disposition(collection: &Value, invalid: &mut Vec<&'static str>) {
    match collection["state"].as_str() {
        Some("removing" | "collected") => {
            let remaining_ok = if collection["state"] == "removing" {
                collection["remaining"].is_null()
            } else {
                collection["remaining"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
            };
            if !remaining_ok {
                invalid.push("remaining");
            }
            for key in ["refusal", "component"] {
                if !collection[key].is_null() {
                    invalid.push(key);
                }
            }
        }
        Some("refused") => {
            if !collection["remaining"].is_null()
                && !collection["remaining"].as_array().is_some_and(|remaining| {
                    collection["planned"].as_array().is_some_and(|planned| {
                        super::super::harvest::valid_remaining(remaining, planned)
                    })
                })
            {
                invalid.push("remaining");
            }
            for key in ["refusal", "component"] {
                if !collection[key].is_string() {
                    invalid.push(key);
                }
            }
        }
        _ => invalid.push("state"),
    }
}

/// Validate retained rewrite provenance without converting an old live record.
///
/// # Errors
/// Refuses a malformed present migration record.
pub fn validate(record: &Value) -> Result<(), LaneError> {
    let Some(value) = record.get("retirement_rewrite") else {
        return Ok(());
    };
    let keys = [
        "schema",
        "conversion",
        "original_collection",
        "original_agreement",
        "before_sha256",
        "old_home_inspected",
    ];
    if value.as_object().is_none_or(|fields| {
        fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key))
    }) || value["schema"] != 1
        || value["conversion"] != "collection-writable-collected-first"
        || value["old_home_inspected"] != false
        || value["before_sha256"].as_str().is_none_or(|hash| {
            hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(refusal("retained rewrite provenance differs"));
    }
    let mut original = record.clone();
    original
        .as_object_mut()
        .ok_or_else(|| refusal("record is not an object"))?
        .remove("retirement_rewrite");
    original["collection"] = value["original_collection"].clone();
    original["harvest_agreement"] = value["original_agreement"].clone();
    convert(
        &original,
        value["before_sha256"].as_str().unwrap_or_default(),
    )?;
    Ok(())
}

fn eligible(
    owner_home: &Path,
    root: &Path,
    request: &RetireRequest,
    record: &Value,
) -> Result<(), LaneError> {
    let run = request
        .run
        .as_deref()
        .ok_or_else(|| refusal("run absent"))?;
    let (base, count) = worker_range(owner_home, &request.loop_name)?;
    let uid = record["worker_uid"]
        .as_u64()
        .ok_or_else(|| refusal("worker identity absent"))?;
    if record["loop"] != request.loop_name
        || record["run"] != run
        || !["settled", "failed"].contains(&record["phase"].as_str().unwrap_or_default())
        || uid < u64::from(base)
        || uid >= u64::from(base) + u64::from(count)
        || record["plan"]["driver_dir"] != root.join(run).to_string_lossy().as_ref()
        || record["plan"]["home"]
            != owner_home
                .join(".cache/tmp")
                .join(format!("lane-{}-{run}", request.loop_name))
                .to_string_lossy()
                .as_ref()
    {
        return Err(refusal(
            "rewrite requires this loop's settled or failed reservation and allocated identity",
        ));
    }
    checked_presence(
        owner_home,
        record,
        false,
        crate::container_helper::process_presence,
    )?;
    let program = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| refusal("runtime absent"))?;
    if !container_absent_for_run(Path::new(program), owner_home, &request.loop_name, run)? {
        return Err(LaneError::input(
            "retire-busy",
            "labelled container is still present",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn run(
    owner_home: &Path,
    root: &Path,
    request: &RetireRequest,
    begun: Instant,
) -> Result<Value, LaneError> {
    let run = request
        .run
        .as_deref()
        .ok_or_else(|| refusal("run absent"))?;
    let owner = Uid::effective().as_raw();
    let _lease = lock_retirement_lease(root, run, owner, &request.loop_name)?;
    let _mailbox = lock_retirement_mailbox(root, run, owner, request.dry_run)?;
    let path = reservation_path(root, run);
    let journal_path = root.join(format!(".retire-rewrite-{run}.json"));
    let current = read_reservation(&path)?.ok_or_else(|| refusal("reservation absent"))?;
    eligible(owner_home, root, request, &current)?;
    let bytes = absences::read_bytes(&path)?.ok_or_else(|| refusal("reservation vanished"))?;
    let prior = absences::read_bytes(&journal_path)?
        .map(|bytes| serde_json::from_slice::<Value>(&bytes))
        .transpose()
        .map_err(|error| refusal(format!("journal: {error}")))?;
    let resuming = prior
        .as_ref()
        .is_some_and(|journal| journal["phase"] == "pending");
    let plan = if let Some(journal) = &prior {
        if journal["schema"] != 1
            || !["pending", "complete"].contains(&journal["phase"].as_str().unwrap_or_default())
            || journal["digest"] != node::digest(&journal["plan"])
        {
            return Err(refusal("rewrite journal differs"));
        }
        journal["plan"].clone()
    } else {
        let before_hash = absences::hash(&bytes);
        let after = convert(&current, &before_hash)?;
        json!({"schema":1,"command":"retire rewrite","owner_uid":owner,"loop":request.loop_name,"run":run,
            "files":[{"path":path,"before_sha256":before_hash,"before":current,"after":after}]})
    };
    if plan["schema"] != 1
        || plan["command"] != "retire rewrite"
        || plan["owner_uid"] != owner
        || plan["loop"] != request.loop_name
        || plan["run"] != run
        || plan["files"]
            .as_array()
            .is_none_or(|files| files.len() != 1)
        || plan["files"][0]["path"] != path.to_string_lossy().as_ref()
    {
        return Err(refusal("journal does not name this reservation"));
    }
    let row = &plan["files"][0];
    let converted = convert(
        &row["before"],
        row["before_sha256"]
            .as_str()
            .ok_or_else(|| refusal("original digest absent"))?,
    )?;
    if converted != row["after"] {
        return Err(refusal("journal conversion differs"));
    }
    let target = serde_json::to_vec(&row["after"]).map_err(|error| refusal(error.to_string()))?;
    let digest = node::digest(&plan);
    let mut journal = json!({"schema":1,"phase":"pending","digest":digest,"plan":plan});
    let journal_bytes = serde_json::to_vec(&journal).map_err(|error| refusal(error.to_string()))?;
    if target.len() as u64 > MAX_RESERVATION_BYTES
        || journal_bytes.len() as u64 > MAX_RESERVATION_BYTES
    {
        return Err(LaneError::input(
            "reservation-size",
            "rewrite record or journal exceeds the reservation reader bound",
        ));
    }
    if absences::hash(&bytes) != row["before_sha256"] && !(prior.is_some() && bytes == target) {
        return Err(LaneError::input(
            "retire-rewrite-digest",
            "record changed since the bound plan; restore original or exact target bytes",
        ));
    }
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"retire rewrite","dry_run":true,"plan":plan,"preview_sha256":digest,"resuming":resuming,"wall_seconds":begun.elapsed().as_secs_f64()}),
        );
    }
    if request.expect_digest.as_deref() != Some(digest.as_str()) {
        return Err(LaneError::input(
            "retire-rewrite-digest",
            "plan differs; repeat retire rewrite with --dry-run",
        ));
    }
    let rechecked = absences::read_bytes(&path)?.ok_or_else(|| refusal("reservation vanished"))?;
    if rechecked != bytes {
        return Err(LaneError::input(
            "retire-rewrite-digest",
            "record changed before publication",
        ));
    }
    publish_reservation(&journal_path, &journal)?;
    publish_reservation(&path, &row["after"])?;
    journal["phase"] = json!("complete");
    publish_reservation(&journal_path, &journal)?;
    Ok(
        json!({"schema":1,"command":"retire rewrite","dry_run":false,"plan":plan,"preview_sha256":digest,"complete":true,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:retire-rewrite-parser-requires-bound-apply´
    #[test]
    fn retire_rewrite_parser_requires_bound_apply() {
        let parse = |words: &[&str]| {
            RetireRequest::parse(
                &words
                    .iter()
                    .map(|word| (*word).to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert!(
            parse(&["rewrite", "alpha", "R", "--dry-run"])
                .expect("preview")
                .rewrite
        );
        let digest = "a".repeat(64);
        assert!(
            parse(&["rewrite", "alpha", "R", "--expect-digest", &digest])
                .expect("bound apply")
                .rewrite
        );
        for words in [
            vec!["rewrite", "alpha", "R"],
            vec!["rewrite", "alpha", "--generations", "--dry-run"],
            vec!["rewrite", "alpha", "R", "--node", "--dry-run"],
            vec![
                "rewrite",
                "alpha",
                "R",
                "--confirm-missing-lease",
                "--dry-run",
            ],
            vec!["rewrite", "rewrite", "alpha", "R", "--dry-run"],
        ] {
            assert_eq!(
                parse(&words).expect_err("invalid rewrite form").kind,
                "retire-usage"
            );
        }
    }

    fn fixture(worker: u32) -> (tempfile::TempDir, PathBuf, RetireRequest, Value) {
        let (home, root, mut request) = super::super::tests::public_fixture();
        request.rewrite = true;
        drop(lock_run_preparation(&root, "R", Uid::effective().as_raw()).expect("lease"));
        let runtime = home.path().join("runtime");
        crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n").expect("runtime");
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,"imports":[],
            "plan":{"home":home.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":[runtime]},
            "launcher_pid":u32::MAX-worker,"launcher_start":worker,"driver_entry_pid":u32::MAX-worker,"driver_entry_start":worker,
            "helper_pid":u32::MAX-worker,"helper_start":worker,"helper_parent_pid":u32::MAX-worker,"helper_parent_start":worker,
            "observer_state":"ended","observer_pid":u32::MAX-worker,"observer_start":worker,
            "harvest_agreement":{"checkpoint_index":1,"preserved_object":"a".repeat(40),"gate_object":"a".repeat(40),"instant_unix_ns":1},
            "collection":{"checkpoint_index":1,"state":"collected","instant_unix_ns":2,"planned":["."],"remaining":[],"refusal":null,"component":null,
            "token":"a".repeat(32),"parent_identity":{"device":1,"inode":2},"home_identity":{"device":1,"inode":3}}});
        publish_reservation(&reservation_path(&root, "R"), &record).expect("predecessor");
        (home, root, request, record)
    }

    /// ´test:unit:retire-rewrite-predecessor-preserves-evidence-through-retirement´
    #[test]
    fn retire_rewrite_predecessor_preserves_evidence_through_retirement() {
        for worker in [3000, 3001] {
            let (home, root, mut request, before) = fixture(worker);
            let config = home.path().join(".config/loops/alpha");
            let _live_a =
                crate::install::lock_loop_config(&config, true).expect("unrelated launcher");
            let _live_b = crate::install::lock_loop_config(&config, true).expect("other launcher");
            request.rewrite = false;
            let ordinary = super::super::run(home.path(), &request)
                .expect_err("ordinary preview names rewrite");
            assert_eq!(ordinary.kind, "harvest-record");
            assert!(ordinary.detail.contains("retire rewrite alpha R --dry-run"));
            assert!(!root.join(".letter-R.lock").exists());
            request.rewrite = true;
            let preview = super::super::run(home.path(), &request).expect("preview");
            assert!(!root.join(".letter-R.lock").exists());
            let held = lock_mailbox(&root, "R", Uid::effective().as_raw()).expect("letter writer");
            let busy =
                super::super::run(home.path(), &request).expect_err("held mailbox refuses preview");
            assert_eq!(busy.kind, "retire-busy");
            assert!(busy.detail.contains("mailbox lock"));
            drop(held);
            assert_eq!(preview["plan"]["files"][0]["before"], before);
            assert!(
                preview["plan"]["files"][0]["after"]["collection"]["writable_collected_first"]
                    .is_null()
            );
            assert_eq!(
                read_reservation(&reservation_path(&root, "R"))
                    .expect("read")
                    .expect("record"),
                before
            );
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let result = super::super::run(home.path(), &request).expect("rewrite");
            assert_eq!(result["complete"], true);
            let after = read_reservation(&reservation_path(&root, "R"))
                .expect("read")
                .expect("record");
            assert_eq!(
                after["retirement_rewrite"]["original_collection"],
                before["collection"]
            );
            assert_eq!(after["retirement_rewrite"]["old_home_inspected"], false);
            request.rewrite = false;
            request.dry_run = true;
            request.expect_digest = None;
            let retirement = super::super::run(home.path(), &request).expect("retirement preview");
            request.dry_run = false;
            request.expect_digest = retirement["preview_sha256"].as_str().map(str::to_owned);
            let retired =
                super::super::run(home.path(), &request).expect("retire rewritten record");
            assert_eq!(retired["worker_uid_released"], worker);
            let archived = read_reservation(Path::new(
                retired["retirement"]["record"].as_str().expect("archive"),
            ))
            .expect("reader")
            .expect("record");
            assert_eq!(archived["retirement_rewrite"], after["retirement_rewrite"]);
        }
    }

    /// ´test:unit:retire-rewrite-lists-missing-extra-and-invalid-fields´
    #[test]
    fn retire_rewrite_lists_missing_extra_and_invalid_fields() {
        for (field, value, expected) in [
            ("token", json!("bad"), "invalid=[\"token\"]"),
            ("unknown", json!(true), "extra=[\"unknown\"]"),
            ("home_identity", Value::Null, "missing=[\"home_identity\"]"),
        ] {
            let (home, root, mut request, mut record) = fixture(3000);
            if value.is_null() {
                record["collection"]
                    .as_object_mut()
                    .expect("collection")
                    .remove(field);
            } else {
                record["collection"][field] = value;
            }
            publish_reservation(&reservation_path(&root, "R"), &record).expect("older shape");
            let preview = super::super::run(home.path(), &request).expect_err("unknown shape");
            assert_eq!(preview.kind, "retire-rewrite-record");
            assert!(preview.detail.contains(expected), "{}", preview.line());
            request.dry_run = false;
            request.expect_digest = Some("0".repeat(64));
            let applying = super::super::run(home.path(), &request).expect_err("same refusal");
            assert_eq!(applying.kind, preview.kind);
            assert!(applying.detail.contains(expected));
        }
    }

    /// ´test:unit:retire-rewrite-keeps-removing-collection-pending´
    #[test]
    fn retire_rewrite_keeps_removing_collection_pending() {
        let (home, root, mut request, mut record) = fixture(3000);
        record["collection"]["state"] = json!("removing");
        record["collection"]["remaining"] = Value::Null;
        publish_reservation(&reservation_path(&root, "R"), &record).expect("pending collection");
        let preview = super::super::run(home.path(), &request).expect("rewrite preview");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            super::super::run(home.path(), &request).expect("rewrite")["complete"],
            true
        );
        request.rewrite = false;
        request.dry_run = true;
        request.expect_digest = None;
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("still pending")
                .kind,
            "retire-collection-pending"
        );
    }

    /// ´test:unit:retire-rewrite-stale-preview-refuses-before-journal´
    #[test]
    fn retire_rewrite_stale_preview_refuses_before_journal() {
        let (home, root, mut request, mut record) = fixture(3000);
        let preview = super::super::run(home.path(), &request).expect("preview");
        record["extra_evidence"] = json!("arrived after preview");
        publish_reservation(&reservation_path(&root, "R"), &record).expect("changed record");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("stale")
                .kind,
            "retire-rewrite-digest"
        );
        assert!(!root.join(".retire-rewrite-R.json").exists());
    }

    /// ´test:unit:retire-rewrite-resumes-original-or-exact-target-only´
    #[test]
    fn retire_rewrite_resumes_original_or_exact_target_only() {
        for published in [false, true] {
            let (home, root, mut request, _) = fixture(3001);
            let preview = super::super::run(home.path(), &request).expect("preview");
            let journal = json!({"schema":1,"phase":"pending","digest":preview["preview_sha256"],"plan":preview["plan"]});
            publish_reservation(&root.join(".retire-rewrite-R.json"), &journal)
                .expect("interrupted journal");
            if published {
                publish_reservation(
                    &reservation_path(&root, "R"),
                    &preview["plan"]["files"][0]["after"],
                )
                .expect("target published before interruption");
            }
            let resumed = super::super::run(home.path(), &request).expect("resume preview");
            assert_eq!(resumed["resuming"], true);
            assert_eq!(resumed["preview_sha256"], preview["preview_sha256"]);
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            assert_eq!(
                super::super::run(home.path(), &request).expect("resume")["complete"],
                true
            );
        }
    }

    /// ´test:unit:retire-rewrite-pending-journal-refuses-changed-record-in-preview´
    #[test]
    fn retire_rewrite_pending_journal_refuses_changed_record_in_preview() {
        let (home, root, mut request, mut record) = fixture(3000);
        let preview = super::super::run(home.path(), &request).expect("preview");
        publish_reservation(&root.join(".retire-rewrite-R.json"), &json!({"schema":1,"phase":"pending","digest":preview["preview_sha256"],"plan":preview["plan"]})).expect("journal");
        record["extra_evidence"] = json!("different");
        publish_reservation(&reservation_path(&root, "R"), &record).expect("changed record");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("preview refuses changed bytes")
                .kind,
            "retire-rewrite-digest"
        );
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("apply refuses changed bytes")
                .kind,
            "retire-rewrite-digest"
        );
    }
}
