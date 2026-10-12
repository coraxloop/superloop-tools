//! Explicit conversion of mirror-based retirement records, never a read fallback.

use super::*;

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("retire-node-rewrite-record", detail)
}

fn predecessor(plan: &Value) -> bool {
    plan["route"].as_object().is_some_and(|route| {
        route.len() == 4
            && ["alias", "mirror_root", "key_path", "ssh_config_sha256"]
                .iter()
                .all(|key| route.contains_key(*key))
    })
}

pub(super) fn has_predecessor(value: &Value) -> bool {
    predecessor(&value["plan"])
        || value["attempts"]
            .as_array()
            .is_some_and(|attempts| attempts.iter().any(|attempt| predecessor(&attempt["plan"])))
}

fn convert_plan(plan: &mut Value) -> Result<(), LaneError> {
    if predecessor(plan) {
        let mirror = plan["route"]["mirror_root"]
            .as_str()
            .ok_or_else(|| refusal("predecessor mirror root absent"))?;
        let root = Path::new(mirror)
            .parent()
            .filter(|root| root.is_absolute() || root.starts_with("~"))
            .ok_or_else(|| refusal("predecessor mirror root is not absolute or home-relative"))?;
        let root = root.to_string_lossy().into_owned();
        plan["route"]["node_root"] = json!(root);
    }
    if !node::valid_plan(plan) {
        return Err(refusal(
            "retirement plan is neither the listed predecessor nor current shape",
        ));
    }
    Ok(())
}

fn convert_value(value: &Value, loop_name: &Value, run: &Value) -> Result<Value, LaneError> {
    let mut converted = value.clone();
    convert_plan(&mut converted["plan"])?;
    for attempt in converted["attempts"]
        .as_array_mut()
        .ok_or_else(|| refusal("attempt history absent"))?
    {
        convert_plan(&mut attempt["plan"])?;
    }
    let record = json!({"loop":loop_name,"run":run,"node_retirement":converted});
    node_record::read_shape(&record)?;
    Ok(converted)
}

pub(super) fn convert(record: &Value) -> Result<Value, LaneError> {
    let Some(value) = record.get("node_retirement") else {
        return Ok(record.clone());
    };
    if !has_predecessor(value) {
        node_record::read(record)?;
        return Ok(record.clone());
    }
    if record.get("node_retirement_rewrite").is_some() {
        return Err(refusal("predecessor already carries conversion provenance"));
    }
    let converted = convert_value(value, &record["loop"], &record["run"])?;
    let mut after = record.clone();
    after["node_retirement"] = converted;
    after["node_retirement_rewrite"] = json!({"schema":1,
        "conversion":"mirror-artifact-root","original":value});
    validate(&after)?;
    Ok(after)
}

pub(super) fn validate(record: &Value) -> Result<(), LaneError> {
    let Some(provenance) = record.get("node_retirement_rewrite") else {
        return Ok(());
    };
    if provenance.as_object().is_none_or(|object| {
        object.len() != 3
            || !["schema", "conversion", "original"]
                .iter()
                .all(|key| object.contains_key(*key))
    }) || provenance["schema"] != 1
        || provenance["conversion"] != "mirror-artifact-root"
        || !has_predecessor(&provenance["original"])
    {
        return Err(refusal("conversion provenance differs"));
    }
    let original = convert_value(&provenance["original"], &record["loop"], &record["run"])?;
    if original["plan"]["route"] != record["node_retirement"]["plan"]["route"]
        || original["plan"]["paths"] != record["node_retirement"]["plan"]["paths"]
        || original["plan"]["marker"] != record["node_retirement"]["plan"]["marker"]
    {
        return Err(refusal(
            "converted destination differs from the original retirement",
        ));
    }
    Ok(())
}

fn record_name(name: &str) -> bool {
    super::super::census::retired_name(name)
        || name
            .strip_prefix(".reservation-")
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(valid_run_name)
}

fn inventory(root: &Path, loop_name: &str) -> Result<Vec<Value>, LaneError> {
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(root)
        .map_err(|error| refusal(error.to_string()))?
        .enumerate()
    {
        if index >= 4096 {
            return Err(refusal("record inventory exceeds bound"));
        }
        let entry = entry.map_err(|error| refusal(error.to_string()))?;
        if record_name(&entry.file_name().to_string_lossy()) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    let mut files = Vec::new();
    for path in paths {
        let before = super::super::read_reservation_checked(&path, false)?
            .ok_or_else(|| refusal("reservation vanished"))?;
        if before["loop"] != loop_name || !before["run"].as_str().is_some_and(valid_run_name) {
            return Err(refusal("reservation identity differs"));
        }
        let after = convert(&before)?;
        if after != before {
            let bytes =
                absences::read_bytes(&path)?.ok_or_else(|| refusal("reservation vanished"))?;
            files.push(json!({"path":path,"before":before,"before_sha256":absences::hash(&bytes),"after":after}));
        }
    }
    Ok(files)
}

fn check_plan(plan: &Value, root: &Path, loop_name: &str) -> Result<(), LaneError> {
    if plan["schema"] != 1
        || plan["command"] != "retire rewrite-node"
        || plan["loop"] != loop_name
        || plan["owner_uid"] != Uid::effective().as_raw()
    {
        return Err(refusal("journal identity differs"));
    }
    let mut paths = std::collections::BTreeSet::new();
    for row in plan["files"]
        .as_array()
        .ok_or_else(|| refusal("journal files absent"))?
    {
        let path = Path::new(
            row["path"]
                .as_str()
                .ok_or_else(|| refusal("journal path absent"))?,
        );
        if path.parent() != Some(root)
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(record_name)
            || !paths.insert(path)
            || row["before"]["loop"] != loop_name
            || convert(&row["before"])? != row["after"]
        {
            return Err(refusal("journal conversion differs"));
        }
        let bytes = row["after"].to_string().len();
        if bytes as u64 > MAX_RESERVATION_BYTES {
            return Err(refusal(format!(
                "{}: converted record exceeds the reader bound: {bytes} bytes > {MAX_RESERVATION_BYTES}",
                path.display()
            )));
        }
        let bytes = absences::read_bytes(path)?.ok_or_else(|| refusal("reservation vanished"))?;
        if absences::hash(&bytes) != row["before_sha256"]
            && bytes
                != serde_json::to_vec(&row["after"]).map_err(|error| refusal(error.to_string()))?
        {
            return Err(refusal(
                "record changed since preview; restore original or exact converted bytes",
            ));
        }
    }
    Ok(())
}

fn plan_for(loop_name: &str, files: Vec<Value>) -> Value {
    let mut plan = json!({"schema":1,"command":"retire rewrite-node","loop":loop_name,
        "owner_uid":Uid::effective().as_raw()});
    plan["files"] = Value::Array(files);
    plan
}

// Retain only paths and original byte hashes for the whole inventory. Converted
// records retain their original node value, so the full plan is reconstructible
// without retaining every before/after pair in each bounded batch journal.
fn manifest(plan: &Value) -> Vec<Value> {
    plan["files"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| json!({"path":row["path"],"before_sha256":row["before_sha256"]}))
        .collect()
}

fn batch_journal(
    plan: &Value,
    digest: &str,
    manifest: &[Value],
    index: usize,
    count: usize,
) -> Value {
    json!({"schema":2,"phase":"pending","digest":digest,"plan":plan,
        "manifest":manifest,"batch_index":index,"batch_count":count,
        "batch_digest":node::digest(plan)})
}

pub(super) fn batches(plan: &Value, digest: &str) -> Result<Vec<Value>, LaneError> {
    let manifest = manifest(plan);
    let empty = plan_for(plan["loop"].as_str().unwrap_or_default(), Vec::new());
    // Four digits cover the bounded inventory; complete is one byte longer.
    let overhead = batch_journal(&empty, digest, &manifest, 4096, 4096)
        .to_string()
        .len()
        + 1;
    let mut plans = Vec::new();
    let mut files = Vec::new();
    let mut size = overhead;
    for row in plan["files"].as_array().into_iter().flatten() {
        let bytes = row.to_string().len();
        if (overhead + bytes) as u64 > MAX_RESERVATION_BYTES {
            return Err(refusal(format!(
                "{}: one conversion file and inventory manifest exceed the bounded journal reader: {} bytes > {MAX_RESERVATION_BYTES} (record {bytes} bytes, manifest overhead {overhead})",
                row["path"].as_str().unwrap_or("invalid path"),
                overhead + bytes
            )));
        }
        if (size + bytes + usize::from(!files.is_empty())) as u64 > MAX_RESERVATION_BYTES {
            plans.push(plan_for(
                plan["loop"].as_str().unwrap_or_default(),
                std::mem::take(&mut files),
            ));
            size = overhead;
        }
        size += bytes + usize::from(!files.is_empty());
        files.push(row.clone());
    }
    if !files.is_empty() {
        plans.push(plan_for(plan["loop"].as_str().unwrap_or_default(), files));
    }
    let count = plans.len();
    Ok(plans
        .iter()
        .enumerate()
        .map(|(index, plan)| batch_journal(plan, digest, &manifest, index, count))
        .collect())
}

fn resume_plan(
    journal: &Value,
    root: &Path,
    loop_name: &str,
    inventory: &[Value],
) -> Result<Value, LaneError> {
    let rows = journal["manifest"]
        .as_array()
        .filter(|rows| rows.len() <= 4096)
        .ok_or_else(|| refusal("journal inventory absent or exceeds bound"))?;
    let mut files = Vec::new();
    let mut previous: Option<&str> = None;
    for row in rows {
        let name = row["path"]
            .as_str()
            .ok_or_else(|| refusal("journal path absent"))?;
        let path = Path::new(name);
        if path.parent() != Some(root)
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(record_name)
            || previous.is_some_and(|previous| previous >= name)
        {
            return Err(refusal("journal inventory path differs"));
        }
        previous = Some(name);
        let bytes = absences::read_bytes(path)?.ok_or_else(|| refusal("reservation vanished"))?;
        let mut before: Value =
            serde_json::from_slice(&bytes).map_err(|error| refusal(error.to_string()))?;
        if absences::hash(&bytes) != row["before_sha256"] {
            validate(&before)?;
            let original = before["node_retirement_rewrite"]["original"].clone();
            if original.is_null() {
                return Err(refusal(
                    "record changed since preview; original conversion provenance absent",
                ));
            }
            before["node_retirement"] = original;
            if let Some(object) = before.as_object_mut() {
                object.remove("node_retirement_rewrite");
            }
        }
        let after = convert(&before)?;
        files.push(
            json!({"path":path,"before":before,"before_sha256":row["before_sha256"],"after":after}),
        );
    }
    if inventory
        .iter()
        .any(|file| !rows.iter().any(|row| row["path"] == file["path"]))
    {
        return Err(refusal("record inventory changed since preview"));
    }
    let plan = plan_for(loop_name, files);
    if node::digest(&plan) != journal["digest"] {
        return Err(refusal("whole conversion plan differs from journal digest"));
    }
    check_plan(&plan, root, loop_name)?;
    Ok(plan)
}

fn read_journal(path: &Path) -> Result<Option<Value>, LaneError> {
    let prior = absences::read_bytes(path)?
        .map(|bytes| serde_json::from_slice::<Value>(&bytes))
        .transpose()
        .map_err(|error| refusal(error.to_string()))?;
    if let Some(journal) = &prior {
        let digest = node::digest(&journal["plan"]);
        if !["pending", "complete"].contains(&journal["phase"].as_str().unwrap_or_default())
            || match journal["schema"].as_u64() {
                Some(1) => journal["digest"] != digest,
                Some(2) => journal["batch_digest"] != digest,
                _ => true,
            }
        {
            return Err(refusal("rewrite journal differs"));
        }
    }
    Ok(prior)
}

/// Convert every listed retirement predecessor under the loop's exclusive locks.
///
/// # Errors
/// Refuses unknown record shapes, changed bytes, busy custody, or a mismatched digest.
#[allow(clippy::too_many_lines)]
pub fn run(home: &Path, args: &[String]) -> Result<Value, LaneError> {
    let begun = Instant::now();
    let full_plan = args.last().is_some_and(|word| word == "--full-plan");
    let args = if full_plan {
        &args[..args.len() - 1]
    } else {
        args
    };
    let (loop_name, expected) = match args {
        [name, flag] if flag == "--dry-run" => (name, None),
        [name, flag, digest]
            if flag == "--expect-digest"
                && digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            (name, Some(digest.as_str()))
        }
        _ => {
            return Err(refusal(
                "retire rewrite-node LOOP {--dry-run|--expect-digest HEX} [--full-plan]",
            ));
        }
    };
    loop_home::validate_name(loop_name).map_err(|error| refusal(error.message()))?;
    let config = home.join(".config/loops").join(loop_name);
    let _configuration = crate::install::lock_loop_config(&config, false)?;
    let settings = Settings::read_beneath(&config.join("workers.toml"), home)?;
    settings.validate_grant(home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| refusal("runs_root absent"))?;
    let _runs = lock_runs_root(root, true, Uid::effective().as_raw())?;
    // Scan and validate the entire inventory before writing even a journal.
    let files = inventory(root, loop_name)?;
    let journal_path = root.join(".retire-node-rewrite.json");
    let prior = read_journal(&journal_path)?;
    let resuming = prior
        .as_ref()
        .is_some_and(|journal| journal["phase"] == "pending");
    let pending = prior.as_ref().filter(|_| resuming);
    let plan = if let Some(journal) = pending {
        if journal["schema"] == 1 {
            journal["plan"].clone()
        } else {
            resume_plan(journal, root, loop_name, &files)?
        }
    } else {
        plan_for(loop_name, files)
    };
    check_plan(&plan, root, loop_name)?;
    let digest = node::digest(&plan);
    let changed = plan["files"].as_array().map_or(0, Vec::len);
    let mut journals = if let Some(journal) = pending.filter(|journal| journal["schema"] == 1) {
        vec![journal.clone()]
    } else {
        batches(&plan, &digest)?
    };
    let start = if let Some(journal) = pending.filter(|journal| journal["schema"] == 2) {
        let index = journal["batch_index"]
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| refusal("journal batch index absent"))?;
        if journals.get(index) != Some(journal) {
            return Err(refusal("journal batch differs from whole plan"));
        }
        for completed in journals.iter().take(index) {
            for row in completed["plan"]["files"].as_array().into_iter().flatten() {
                let path = Path::new(row["path"].as_str().unwrap_or_default());
                let target = serde_json::to_vec(&row["after"])
                    .map_err(|error| refusal(error.to_string()))?;
                if absences::read_bytes(path)?.as_deref() != Some(target.as_slice()) {
                    return Err(refusal(
                        "completed batch changed; restore exact converted bytes",
                    ));
                }
            }
        }
        index
    } else {
        0
    };
    let journal_bytes = journals
        .iter()
        .map(|journal| journal.to_string().len() + 1)
        .max()
        .unwrap_or(0);
    if journal_bytes as u64 > MAX_RESERVATION_BYTES {
        return Err(refusal("conversion journal exceeds the bounded reader"));
    }
    if let Some(expected) = expected {
        if expected != digest {
            return Err(refusal(
                "plan differs; repeat retire rewrite-node with --dry-run",
            ));
        }
        for journal in journals.iter_mut().skip(start) {
            publish_reservation(&journal_path, journal)?;
            for row in journal["plan"]["files"].as_array().into_iter().flatten() {
                let path = Path::new(row["path"].as_str().unwrap_or_default());
                let target = serde_json::to_vec(&row["after"])
                    .map_err(|error| refusal(error.to_string()))?;
                if absences::read_bytes(path)?.as_deref() != Some(target.as_slice()) {
                    publish_reservation(path, &row["after"])?;
                }
            }
            // Keep pending until the final batch: a crash between batches must
            // retain the original digest, not start a new inventory conversion.
        }
        if let Some(journal) = journals.last_mut() {
            journal["phase"] = json!("complete");
            publish_reservation(&journal_path, journal)?;
        }
    }
    let displayed_plan = if full_plan {
        plan
    } else {
        let files: Vec<_> = plan["files"].as_array().into_iter().flatten().map(|row| {
            json!({"path":row["path"],"before_sha256":row["before_sha256"],"after_sha256":node::digest(&row["after"]),"before_bytes":row["before"].to_string().len(),"after_bytes":row["after"].to_string().len()})
        }).collect();
        json!({"sha256":node::digest(&plan),"file_count":files.len(),"files":files})
    };
    Ok(
        json!({"schema":1,"command":"retire rewrite-node","loop":loop_name,
        "dry_run":expected.is_none(),"changed":changed,"resuming":resuming,
        "batch_count":journals.len(),"journal_bytes":journal_bytes,"journal_limit":MAX_RESERVATION_BYTES,
        "preview_sha256":digest,"plan":displayed_plan,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}
