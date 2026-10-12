//! Durable node debt and the owner-only completion form for archived records.

use super::{
    Duration, Instant, LaneError, Path, RetireRequest, Uid, Value, fs, json, node,
    publish_reservation, read_reservation, reservation_path,
};

const HISTORY: usize = 4;

fn refusal(detail: &str) -> LaneError {
    LaneError::input("retire-node-record", detail)
}

/// Interpret historical absence and validate present node retirement evidence.
/// An absent field permits explicit completion with the current registration;
/// no registration or a present outcome with no debt refuses as `retire-node-not-owed`.
///
/// # Errors
///
/// Refuses malformed evidence or a plan naming another run or loop.
pub fn read(record: &Value) -> Result<Value, LaneError> {
    let Some(value) = record.get("node_retirement") else {
        return Ok(json!({"state":"unmeasured","reason":"retired before node retirement existed"}));
    };
    if super::node_rewrite::has_predecessor(value) {
        return Err(LaneError::input(
            "retire-node-rewrite-required",
            format!(
                "four-key retirement route; run superloop-lane retire rewrite-node {} --dry-run before census or completion",
                record["loop"].as_str().unwrap_or("LOOP")
            ),
        ));
    }
    super::node_rewrite::validate(record)?;
    let home_relative = std::iter::once(&value["plan"])
        .chain(
            value["attempts"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|attempt| &attempt["plan"]),
        )
        .any(|plan| {
            plan["route"]["node_root"]
                .as_str()
                .is_some_and(|root| root == "~" || root.starts_with("~/"))
        });
    if home_relative && record.get("node_retirement_rewrite").is_none() {
        return Err(refusal(
            "home-relative node_root requires node_retirement_rewrite",
        ));
    }
    read_shape(record)
}

// Conversion validates the explicit predecessor's shape before attaching provenance.
pub(super) fn read_shape(record: &Value) -> Result<Value, LaneError> {
    let value = &record["node_retirement"];
    if value.as_object().is_none_or(|object| object.len() != 5)
        || value["schema"] != 1
        || value["plan"]["loop"] != record["loop"]
        || value["plan"]["run"] != record["run"]
        || !node::valid_plan(&value["plan"])
        || !node::valid_outcome(&value["outcome"], &value["plan"])
        || value["attempts_omitted"].as_u64().is_none()
        || value["attempts"].as_array().is_none_or(|attempts| {
            attempts.len() > HISTORY
                || attempts.iter().any(|attempt| {
                    attempt.as_object().is_none_or(|object| object.len() != 2)
                        || !node::valid_plan(&attempt["plan"])
                        || attempt["plan"]["loop"] != record["loop"]
                        || attempt["plan"]["run"] != record["run"]
                        || !node::valid_outcome(&attempt["outcome"], &attempt["plan"])
                })
        })
    {
        return Err(refusal("node_retirement is malformed"));
    }
    Ok(value.clone())
}

pub(super) fn pending(plan: &Value) -> Value {
    let absent = plan["reason"] == "node-retirement-no-registration";
    json!({"schema":1,"plan":plan,"outcome":{"state":"unmeasured","reason":plan["reason"],"owed":!absent,
        "host_wall_seconds":null,"helper_exit":null,"remote_completion":"unknown","evidence":null},"attempts":[],"attempts_omitted":0})
}

pub(super) fn plan_for_record(
    home: &Path,
    loop_name: &str,
    run: &str,
    record: &Value,
) -> Result<node::Plan, LaneError> {
    let mut plan = node::plan(home, loop_name, run);
    if record.get("node_retirement_rewrite").is_some() {
        read(record)?;
        let root = record["node_retirement"]["plan"]["route"]["node_root"]
            .as_str()
            .ok_or_else(|| refusal("converted artifact root absent"))?;
        plan.set_artifact_root(root);
    }
    Ok(plan)
}

pub(super) fn same_route(record: &Value, plan: &Value) -> Result<(), LaneError> {
    if let Some(prior) = record.get("node_retirement") {
        read(record)?;
        if !prior["plan"]["route"].is_null() && prior["plan"]["route"] != plan["route"] {
            return Err(LaneError::input(
                "retire-node-route",
                "registered route changed since retirement",
            ));
        }
    }
    Ok(())
}

pub(super) fn preview(
    record: &Value,
    journal: &Value,
    plan: Option<&Value>,
    node_only: bool,
) -> String {
    // Durations are excluded; stable recorded timestamps stay bound with the
    // identity, custody plan, confirmation, route and cleanup policy.
    let mut host = record.clone();
    if let Some(object) = host.as_object_mut() {
        object.remove("node_retirement");
        object.remove("current_retirement");
    }
    // The measurer's process tree is evidence, not part of the run being retired.
    if let Some(object) = host
        .pointer_mut("/retirement_absence_proof/host")
        .and_then(Value::as_object_mut)
    {
        object.remove("ignored");
    }
    let host = stable(&host);
    node::digest(
        &json!({"owner_uid":Uid::effective().as_raw(),"node_only":node_only,"host":host,
        "paths":journal["planned_paths"],"reservation_path":journal["reservation_path"],
        "identities":journal["identities"],"container_presence":journal["container_presence"],
        "uncertain":journal["uncertain"],"confirmation":journal["confirmation"],"reaping":stable(&journal["reaping"]),"reaping_recovery":stable(&journal["reaping_recovery"]),
        "node_plan":plan}),
    )
}

fn stable(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !key.contains("wall") && !key.contains("elapsed"))
                .map(|(key, value)| (key.clone(), stable(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(stable).collect()),
        _ => value.clone(),
    }
}

pub(super) fn check_digest(expected: Option<&str>, actual: &str) -> Result<(), LaneError> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(LaneError::input(
            "retire-digest",
            "preview_sha256 differs; repeat the dry run",
        ));
    }
    Ok(())
}

pub(super) fn finish(
    path: &Path,
    plan: &node::Plan,
    runner: Option<&dyn node::Runner>,
    budget: Duration,
) -> Result<Value, LaneError> {
    let mut record = read_reservation(path)?.ok_or_else(|| refusal("retired record vanished"))?;
    if record["phase"] != "retired"
        || record["current_retirement"]["reservation_path"]["target"]
            != path.to_string_lossy().as_ref()
    {
        return Err(refusal("not the recorded archived retirement"));
    }
    let mut value = if record.get("node_retirement").is_some() {
        read(&record)?
    } else {
        pending(&plan.value)
    };
    if value["outcome"]["state"] == "complete" {
        return Ok(value);
    }
    let prior = json!({"plan":value["plan"],"outcome":value["outcome"]});
    let attempts = value["attempts"]
        .as_array_mut()
        .ok_or_else(|| refusal("attempt history absent"))?;
    if prior["outcome"]["reason"] != "node-retirement-pending"
        && (prior["plan"] != plan.value || prior["outcome"] != pending(&prior["plan"])["outcome"])
    {
        attempts.push(prior);
    }
    if attempts.len() > HISTORY {
        attempts.remove(0);
        value["attempts_omitted"] = json!(
            value["attempts_omitted"]
                .as_u64()
                .unwrap_or_default()
                .saturating_add(1)
        );
    }
    // Host recovery must finish custody even if the registered route changed.
    // Keep the original destination as debt; never clean a replacement node.
    if same_route(&record, &plan.value).is_err() {
        value["outcome"] = pending(&value["plan"])["outcome"].clone();
        value["outcome"]["reason"] = json!("node-retirement-route-changed");
        record["node_retirement"] = value.clone();
        publish_reservation(path, &record)?;
        return Ok(value);
    }
    value["plan"] = plan.value.clone();
    value["outcome"] = pending(&plan.value)["outcome"].clone();
    if !plan.value["route"].is_null() {
        value["outcome"]["reason"] = json!("node-retirement-in-progress");
    }
    // Publish the attempt/debt before SSH: a crash cannot turn it into success.
    record["node_retirement"] = value.clone();
    publish_reservation(path, &record)?;
    value["outcome"] = node::attempt(plan, runner, budget);
    record["node_retirement"] = value.clone();
    read(&record)?;
    publish_reservation(path, &record)?;
    Ok(value)
}

pub(super) fn complete(
    owner_home: &Path,
    root: &Path,
    request: &RetireRequest,
    runner: Option<&dyn node::Runner>,
    budget: Duration,
    begun: Instant,
) -> Result<Value, LaneError> {
    let run = request
        .run
        .as_deref()
        .ok_or_else(|| refusal("run is absent"))?;
    if read_reservation(&reservation_path(root, run))?.is_some() {
        return Err(LaneError::input(
            "retire-node-active-run",
            "an active reservation still uses this run name",
        ));
    }
    let mut found = None;
    for (index, entry) in fs::read_dir(root)
        .map_err(|error| refusal(&error.to_string()))?
        .enumerate()
    {
        if index >= 4096 {
            return Err(refusal("retired record inventory exceeds bound"));
        }
        let entry = entry.map_err(|error| refusal(&error.to_string()))?;
        if !super::super::census::retired_name(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let path = entry.path();
        let record = read_reservation(&path)?.ok_or_else(|| refusal("retired record vanished"))?;
        if record["run"] != run {
            continue;
        }
        if record["loop"] != request.loop_name
            || record["phase"] != "retired"
            || record["current_retirement"]["reservation_path"]["target"]
                != path.to_string_lossy().as_ref()
        {
            return Err(refusal("archived run identity differs"));
        }
        if found.replace((path, record)).is_some() {
            return Err(LaneError::input(
                "retire-node-ambiguous",
                "several retired records name this run",
            ));
        }
    }
    let (path, record) = found.ok_or_else(|| refusal("no archived retirement names this run"))?;
    let prior = read(&record)?;
    if prior["outcome"]["owed"] == false {
        return Err(LaneError::input(
            "retire-node-not-owed",
            "the retired record has no node retirement owed",
        ));
    }
    let plan = plan_for_record(owner_home, &request.loop_name, run, &record)?;
    if plan.value["reason"] == "node-retirement-registration-refusal" {
        return Err(LaneError::input(
            "retire-node-registration",
            plan.value["detail"]
                .as_str()
                .unwrap_or("node-retirement-registration-refusal"),
        ));
    }
    if plan.value["reason"] == "node-retirement-no-registration" {
        return Err(LaneError::input(
            if record.get("node_retirement").is_none() {
                "retire-node-not-owed"
            } else {
                "retire-node-registration"
            },
            "node-retirement-no-registration: no compute registration is available",
        ));
    }
    same_route(&record, &plan.value)?;
    let digest = preview(
        &record,
        &record["current_retirement"],
        Some(&plan.value),
        true,
    );
    let result = if request.dry_run {
        prior
    } else {
        check_digest(request.expect_digest.as_deref(), &digest)?;
        finish(&path, &plan, runner, budget)?
    };
    Ok(
        json!({"schema":1,"command":"retire","loop":request.loop_name,"run":run,"node":true,
        "dry_run":request.dry_run,"record":path,"preview_sha256":digest,"node_plan":plan.value,
        "node_retirement":result,"worker_uid_released":null,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}
