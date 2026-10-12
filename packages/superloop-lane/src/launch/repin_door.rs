//! Explicit, digest-bound transitions of an idle run's installed door stub.

use super::{
    compare_pinned_plan, lock_runs_root, publish_reservation, read_reservation, reservation_path,
};
use crate::{error::LaneError, load_plan};
use nix::unistd::Uid;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A host-only door re-pin; it never starts a worker or reconciles a round.
pub struct Request {
    pub loop_name: String,
    pub run: String,
    pub dry_run: bool,
    pub expect_digest: Option<String>,
}

impl Request {
    /// Parse the listed preview or digest-bound changing form.
    ///
    /// # Errors
    /// Refuses every other option combination or invalid identity/digest.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let (loop_name, run, digest) = match args {
            [loop_name, run, flag, preview] if flag == "--repin-door" && preview == "--dry-run" => {
                (loop_name, run, None)
            }
            [loop_name, run, flag, expected, digest]
                if flag == "--repin-door" && expected == "--expect-digest" && is_digest(digest) =>
            {
                (loop_name, run, Some(digest.clone()))
            }
            _ => {
                return Err(LaneError::input(
                    "usage",
                    "launch LOOP RUN --repin-door {--dry-run|--expect-digest HEX}",
                ));
            }
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        if !crate::valid_run_name(run) {
            return Err(LaneError::input("run-name", "run is not a plain name"));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            dry_run: digest.is_none(),
            expect_digest: digest,
        })
    }
}

fn is_digest(word: &str) -> bool {
    word.len() == 64
        && word
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hash(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _written = write!(digest, "{byte:02x}");
    }
    digest
}

fn value_hash(value: &Value) -> Result<String, LaneError> {
    serde_json::to_vec(value)
        .map(|bytes| hash(&bytes))
        .map_err(|error| LaneError::input("repin-door-record", error.to_string()))
}

fn context(plan: &Value) -> Value {
    let mut value = plan.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("door");
    }
    value
}

pub(crate) fn door_shape(door: &Value, record: &Value) -> bool {
    const KEYS: [&str; 7] = [
        "schema",
        "socket",
        "stub",
        "stub_sha256",
        "registered",
        "peer_uid",
        "mirror_ref",
    ];
    door.as_object().is_some_and(|object| {
        object.len() == KEYS.len() && KEYS.iter().all(|key| object.contains_key(*key))
    }) && door["schema"] == 1
        && door["socket"] == "/home/worker/.local/door/capability.sock"
        && door["stub"] == "/home/worker/.local/libexec/superloop/ssh"
        && door["registered"] == json!(["ssh"])
        && door["peer_uid"] == record["worker_uid"]
        && door["mirror_ref"]
            == format!(
                "refs/heads/lane/{}",
                record["run"].as_str().unwrap_or_default()
            )
        && door["stub_sha256"].as_str().is_some_and(is_digest)
}

fn same_binding(before: &Value, after: &Value) -> bool {
    let mut before = before.clone();
    let mut after = after.clone();
    if let Some(object) = before.as_object_mut() {
        object.remove("stub_sha256");
    }
    if let Some(object) = after.as_object_mut() {
        object.remove("stub_sha256");
    }
    before == after
}

/// Validate present history without migrating reservations that have none.
pub(super) fn validate(record: &Value) -> Result<(), LaneError> {
    let Some(history) = record.get("door_pin_history") else {
        return Ok(());
    };
    let invalid = || {
        LaneError::input(
            "repin-door-record",
            "door pin history shape, binding, digest or round boundary differs",
        )
    };
    let rows = history
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 256)
        .ok_or_else(invalid)?;
    let rounds = record["rounds"].as_array().ok_or_else(invalid)?;
    let plan_context = value_hash(&context(&record["plan"]))?;
    let mut prior: Option<&Value> = None;
    let mut prior_count = 0;
    for row in rows {
        const KEYS: [&str; 12] = [
            "schema",
            "command",
            "owner_uid",
            "loop",
            "run",
            "before",
            "after",
            "prior_record_sha256",
            "plan_context_sha256",
            "after_round",
            "round_count",
            "preview_sha256",
        ];
        let count = row["round_count"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0 && *n <= rounds.len())
            .ok_or_else(invalid)?;
        let boundary = row.get("boundary").map_or(Some("settled"), Value::as_str);
        let phases: &[&str] = match boundary {
            Some("settled") => &["settled", "failed"],
            Some("interrupted-settlement") => {
                &["running", "awaiting-settlement", "settled", "failed"]
            }
            _ => return Err(invalid()),
        };
        if row.as_object().is_none_or(|object| {
            object.len()
                != KEYS.len()
                    + usize::from(object.contains_key("boundary"))
                    + usize::from(object.contains_key("evidence"))
                || KEYS.iter().any(|key| !object.contains_key(*key))
        }) || !valid_transition_evidence(row)
            || row["schema"] != 1
            || row["command"] != "launch-repin-door"
            || row["owner_uid"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .is_none()
            || row["loop"] != record["loop"]
            || row["run"] != record["run"]
            || !door_shape(&row["before"], record)
            || !door_shape(&row["after"], record)
            || !same_binding(&row["before"], &row["after"])
            || row["before"] == row["after"]
            || !row["prior_record_sha256"].as_str().is_some_and(is_digest)
            || row["plan_context_sha256"] != plan_context
            || row["after_round"] != rounds[count - 1]["step"]
            || row["after_round"]
                .as_str()
                .is_none_or(|step| super::letters::valid_step(step).is_err())
            || !phases.contains(&rounds[count - 1]["phase"].as_str().unwrap_or_default())
            || count < prior_count
            || prior.is_some_and(|old| old != &row["before"])
        {
            return Err(invalid());
        }
        let mut bound = row.clone();
        bound
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("preview_sha256");
        if row["preview_sha256"] != value_hash(&bound)? {
            return Err(invalid());
        }
        prior = Some(&row["after"]);
        prior_count = count;
    }
    if prior != Some(&record["plan"]["door"]) {
        return Err(invalid());
    }
    Ok(())
}

fn valid_transition_evidence(row: &Value) -> bool {
    let Some(evidence) = row.get("evidence") else {
        return true;
    };
    let Some(object) = evidence.as_object() else {
        return false;
    };
    if row["boundary"] != "interrupted-settlement"
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "driver" | "run_report" | "report_identity" | "containers" | "observer"
            )
        })
        || object
            .get("containers")
            .is_some_and(|containers| !valid_containers(containers))
        || object.get("observer").is_some_and(|observer| {
            observer["host"]["state"] != "absent"
                || observer["locks"]["state"] != "absent"
                || observer["node"]["state"] != "absent"
                || observer["node"]["schema"] != 1
                || observer["node"]["loop"] != row["loop"]
                || observer["node"]["run"] != row["run"]
                || observer["node"]["processes"] != json!([])
                || !matches!(observer["node"]["lock"].as_str(), Some("absent" | "unheld"))
        })
    {
        return false;
    }
    let measurements = usize::from(object.contains_key("containers"))
        + usize::from(object.contains_key("observer"));
    if object.len() == measurements && measurements > 0 {
        return true;
    }
    object.len() == 2 + usize::from(object.contains_key("report_identity")) + measurements
        && object
            .get("report_identity")
            .is_none_or(super::driver_report::valid_identity)
        && evidence["driver"] == "absent"
        && evidence["run_report"].as_object().is_some_and(|fields| {
            fields.iter().all(|(key, value)| {
                !key.is_empty() && value.as_str().is_some_and(|word| !word.is_empty())
            })
        })
        && evidence["run_report"]["lane"] == row["after_round"]
        && evidence["run_report"]["dir"].is_string()
        && evidence["run_report"]["exit"]
            .as_str()
            .and_then(|word| word.parse::<i32>().ok())
            .is_some()
        && evidence["run_report"]["verdict"].is_string()
}

fn valid_containers(value: &Value) -> bool {
    let mut ids = BTreeSet::new();
    value.as_array().is_some_and(|containers| {
        containers.len() <= 8
            && containers.iter().all(|container| {
                container
                    .as_object()
                    .is_some_and(|fields| fields.len() == 4)
                    && container["id"].as_str().is_some_and(|id| {
                        id.len() == 64
                            && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                            && ids.insert(id)
                    })
                    && container["name"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty())
                    && container["exit_code"].as_u64().is_some()
                    && container["finished_at"]
                        .as_str()
                        .is_some_and(|time| !time.is_empty())
            })
    })
}

/// Return the door pin applicable to each recorded round, retaining transitions.
pub(super) fn round_pins(record: &Value) -> Result<Value, LaneError> {
    validate(record)?;
    let rows = record["door_pin_history"].as_array();
    let rounds = record["rounds"].as_array().map_or(&[][..], Vec::as_slice);
    Ok(Value::Array(
        rounds
            .iter()
            .enumerate()
            .map(|(index, round)| {
                let door = rows
                    .and_then(|rows| {
                        rows.iter().find(|row| {
                            row["round_count"]
                                .as_u64()
                                .is_some_and(|count| (index as u64) < count)
                        })
                    })
                    .map_or(&record["plan"]["door"], |row| &row["before"]);
                json!({"step":round["step"],"door":door})
            })
            .collect(),
    ))
}

fn presence_error(error: &LaneError) -> LaneError {
    LaneError::input(
        if error.kind == "retire-busy" {
            "repin-door-live"
        } else {
            "repin-door-uncertain"
        },
        error.line(),
    )
}

pub(crate) fn settled_boundary(
    record: &Value,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<(&[Value], &Value, &'static str), LaneError> {
    boundary_with(
        record,
        crate::container_helper::process_presence,
        read_report,
    )
    .map(|(rounds, last, boundary, _)| (rounds, last, boundary))
}

type Boundary<'a> = (&'a [Value], &'a Value, &'static str, Option<Value>);

pub(crate) fn boundary_with(
    record: &Value,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Boundary<'_>, LaneError> {
    if record["rotation"]["old_run"].as_str() == record["run"].as_str()
        || record["rotation_intent"].is_object()
    {
        return Err(LaneError::input(
            "repin-door-state",
            "run must be settled or in interrupted settlement, and not rotated",
        ));
    }
    let rounds = record["rounds"]
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or_else(|| LaneError::input("repin-door-state", "settled round boundary is absent"))?;
    let last = rounds
        .last()
        .ok_or_else(|| LaneError::input("repin-door-state", "settled round boundary is absent"))?;
    let boundary = if record["phase"] == "settled"
        && ["settled", "failed"].contains(&last["phase"].as_str().unwrap_or_default())
    {
        "settled"
    } else if record["phase"] == "started"
        && (record["driver_end"]["state"] == "completed" || record["driver_end"].is_null())
        && record["reaping_recovery"].is_null()
        && last["report"].is_null()
        && last["driver_end"].is_null()
        && ["running", "awaiting-settlement"].contains(&last["phase"].as_str().unwrap_or_default())
    {
        "interrupted-settlement"
    } else {
        return Err(LaneError::input(
            "repin-door-state",
            "run must be settled or have a completed driver awaiting interrupted settlement",
        ));
    };
    if last["step"] != record["active_round"] || !last["step"].is_string() {
        return Err(LaneError::input(
            "repin-door-state",
            "active round is not the last round at the re-pin boundary",
        ));
    }
    let evidence = if boundary == "interrupted-settlement" && record["driver_end"].is_null() {
        Some(missing_driver_evidence(record, presence, read_report)?)
    } else {
        None
    };
    Ok((rounds, last, boundary, evidence))
}

/// Measure the recorded driver identity before reading its own end record.
pub(super) fn missing_driver_evidence(
    record: &Value,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let invalid = || {
        LaneError::input(
            "repin-door-state",
            "matching driver run report is absent or invalid",
        )
    };
    let last = record["rounds"]
        .as_array()
        .and_then(|rows| rows.last())
        .ok_or_else(invalid)?;
    if record["phase"] != "started"
        || !record["driver_end"].is_null()
        || !record["reaping_recovery"].is_null()
        || !last["report"].is_null()
        || !last["driver_end"].is_null()
        || last["step"] != record["active_round"]
        || !matches!(
            last["phase"].as_str(),
            Some("running" | "awaiting-settlement")
        )
    {
        return Err(invalid());
    }
    let (pid, start) = super::driver_identity(record)
        .map_err(|error| presence_error(&error))?
        .ok_or_else(|| LaneError::input("repin-door-uncertain", "driver identity is absent"))?;
    match presence(pid, start) {
        crate::container_helper::ProcessPresence::Absent => {}
        crate::container_helper::ProcessPresence::Present => {
            return Err(LaneError::input(
                "repin-door-live",
                "driver is still present",
            ));
        }
        crate::container_helper::ProcessPresence::Unknown => {
            return Err(LaneError::input(
                "repin-door-uncertain",
                "driver presence unreadable",
            ));
        }
    }
    let mut evidence = read_report(record)?;
    evidence["driver"] = json!("absent");
    Ok(evidence)
}

fn proposal(
    record: &Value,
    current: &Value,
    bytes: &[u8],
    owner: u32,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let (rounds, last, boundary, evidence) = boundary_with(
        record,
        crate::container_helper::process_presence,
        read_report,
    )?;
    let before = &record["plan"]["door"];
    let after = &current["door"];
    if !door_shape(before, record) || !door_shape(after, record) || !same_binding(before, after) {
        return Err(LaneError::input(
            "repin-door-binding",
            "only the installed stub digest may change",
        ));
    }
    let mut aligned = current.clone();
    aligned["door"] = before.clone();
    compare_pinned_plan(&record["plan"], &aligned)?;
    if before == after {
        return Err(LaneError::input(
            "repin-door-state",
            "installed stub already matches the recorded pin",
        ));
    }
    let mut transition = json!({"schema":1,"command":"launch-repin-door","owner_uid":owner,"loop":record["loop"],"run":record["run"],"before":before,"after":after,"prior_record_sha256":hash(bytes),"plan_context_sha256":value_hash(&context(current))?,"after_round":last["step"],"round_count":rounds.len()});
    transition["boundary"] = json!(boundary);
    if let Some(evidence) = evidence {
        transition["evidence"] = evidence;
    }
    transition["preview_sha256"] = json!(value_hash(&transition)?);
    Ok(transition)
}

/// Preview or publish one idle-run door transition under the owner locks.
///
/// # Errors
/// Refuses drift, malformed history, stale consent, or live/unknown run presence.
pub fn run(owner_home: &Path, request: &Request) -> Result<Value, LaneError> {
    run_with_observer(owner_home, request, super::retire::proof::observer_absence)
}

#[allow(clippy::too_many_lines)]
fn run_with_observer(
    owner_home: &Path,
    request: &Request,
    mut measure_observer: impl FnMut(&Value, &Path) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let started = std::time::Instant::now();
    let owner = Uid::effective().as_raw();
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let no_door = || LaneError::input("repin-door", "this run has no door");
    let generation = config.join("door-install-generation.json");
    if crate::pinned::read_private_optional(owner_home, &generation, owner, 0o600, 65_536)?
        .is_none()
    {
        return Err(no_door());
    }
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    registry
        .row(&request.loop_name, owner_home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let root = registry
        .runs_root(&request.loop_name)
        .ok_or_else(|| {
            LaneError::input("registry-row", "runs_root is absent from the registry row")
        })?
        .to_path_buf();
    let runs = lock_runs_root(&root, true, owner)?;
    let path = reservation_path(&root, &request.run);
    let record = read_reservation(&path)?.ok_or_else(no_door)?;
    if record["plan"].get("door").is_none_or(Value::is_null) {
        return Err(no_door());
    }
    let (mut plan, _) = load_plan(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let _lease =
        super::retire::lock_retirement_lease(&root, &request.run, owner, &request.loop_name)
            .map_err(|error| presence_error(&error))?;
    let mailbox = super::retire::lock_retirement_mailbox(&root, &request.run, owner, true)
        .map_err(|error| presence_error(&error))?;
    if mailbox.is_none() {
        return Err(LaneError::input(
            "repin-door-record",
            "settled run mailbox lock is absent",
        ));
    }
    let bytes = crate::pinned::read_private(
        &root,
        &path,
        owner,
        0o600,
        usize::try_from(super::MAX_RESERVATION_BYTES)
            .map_err(|error| LaneError::input("repin-door-record", error.to_string()))?,
    )?;
    let exact: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("repin-door-record", error.to_string()))?;
    if exact != record || record["loop"] != request.loop_name || record["run"] != request.run {
        return Err(LaneError::input(
            "repin-door-record",
            "reservation changed or names another run",
        ));
    }
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| LaneError::input("repin-door-record", "worker UID is absent"))?;
    let (base, count) = super::worker_range(owner_home, &request.loop_name)?;
    if worker < base || worker >= base + count {
        return Err(LaneError::input(
            "repin-door-binding",
            "worker is outside its allocated block",
        ));
    }
    plan.select_worker_uid(worker)?;
    let program = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("repin-door-record", "runtime program is absent"))?,
    );
    plan.select_container_program(&program)?;
    if record["plan"]["vendor_mode"].is_string() {
        plan.observe_vendor()?;
    }
    plan.select_launch_model(&record["model_selection"])?;
    plan.retain_attempt_wall(&record["plan"])?;
    let mut transition = proposal(&record, &plan.document, &bytes, owner, |record| {
        super::driver_report::read(owner_home, record)
    })?;
    if transition["boundary"] == "interrupted-settlement" {
        super::report::require_unoccupied(
            &runs,
            &request.run,
            super::interrupted_report_step(&record)?,
        )?;
    }
    let mut presence_record = record.clone();
    if transition["evidence"]["driver"] == "absent" {
        presence_record["driver_end"] = json!({"state":"completed"});
    }
    if transition["evidence"]["driver"] == "absent"
        && record["observer_end"].is_null()
        && record["observer_state"] == "not-started"
        && record["plan"]["vendor_mode"].is_null()
        && super::recorded_observer_socket(&record)?.is_none()
    {
        presence_record["observer_end"] = json!({"state":"not-started"});
    }
    let identities = super::retire::checked_presence_with_observer(
        owner_home,
        &presence_record,
        false,
        None,
        crate::container_helper::process_presence,
        || {
            if transition["boundary"] == "interrupted-settlement"
                && record["observer_state"] == "not-started"
                && record["plan"]["vendor_mode"].is_null()
                && super::recorded_observer_socket(&record)?.is_none()
            {
                measure_observer(&record, owner_home).map(Some)
            } else {
                Ok(None)
            }
        },
    )
    .map_err(|error| presence_error(&error))?;
    if let Some(evidence) = identities["observer"].get("evidence") {
        transition["evidence"]["observer"] = evidence.clone();
        transition
            .as_object_mut()
            .ok_or_else(|| LaneError::input("repin-door-record", "transition is not an object"))?
            .remove("preview_sha256");
        transition["preview_sha256"] = json!(value_hash(&transition)?);
    }
    if !super::container_absent_for_run(&program, owner_home, &request.loop_name, &request.run)
        .map_err(|error| presence_error(&error))?
    {
        if transition["boundary"] != "interrupted-settlement" {
            return Err(LaneError::input(
                "repin-door-live",
                "a labelled container is still present",
            ));
        }
        let containers =
            super::proved_exited_containers(&program, owner_home, &request.loop_name, &request.run)
                .map_err(|error| LaneError::input("repin-door-live", error.line()))?;
        transition["evidence"]["containers"] = json!(containers.iter().map(|container| {
            json!({"id":container["id"],"name":container["name"],
                "exit_code":container["state"]["ExitCode"],"finished_at":container["state"]["FinishedAt"]})
        }).collect::<Vec<_>>());
        transition
            .as_object_mut()
            .ok_or_else(|| LaneError::input("repin-door-record", "transition is not an object"))?
            .remove("preview_sha256");
        transition["preview_sha256"] = json!(value_hash(&transition)?);
    }
    let mut after = record.clone();
    after["plan"]["door"] = transition["after"].clone();
    if after.get("door_pin_history").is_none() {
        after["door_pin_history"] = json!([]);
    }
    after["door_pin_history"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("repin-door-record", "history is not an array"))?
        .push(transition.clone());
    validate(&after)?;
    if serde_json::to_vec(&after)
        .map_err(|error| LaneError::input("repin-door-record", error.to_string()))?
        .len() as u64
        > super::MAX_RESERVATION_BYTES
    {
        return Err(LaneError::input(
            "repin-door-record",
            "transition exceeds the reservation byte bound",
        ));
    }
    if !request.dry_run {
        if request.expect_digest.as_deref() != transition["preview_sha256"].as_str() {
            return Err(LaneError::input(
                "repin-door-digest",
                "preview digest differs; repeat launch --repin-door --dry-run",
            ));
        }
        let current = crate::pinned::read_private(&root, &path, owner, 0o600, bytes.len())
            .map_err(|error| LaneError::input("repin-door-digest", error.line()))?;
        if current != bytes {
            return Err(LaneError::input(
                "repin-door-digest",
                "reservation bytes changed during admission",
            ));
        }
        publish_reservation(&path, &after)?;
    }
    Ok(
        json!({"schema":1,"command":"launch","form":"repin-door","loop":request.loop_name,"run":request.run,"dry_run":request.dry_run,"boundary":transition["boundary"],"evidence":transition["evidence"],"before":transition["before"],"after":transition["after"],"preview_sha256":transition["preview_sha256"],"transition":transition,"identities":identities,"container_presence":if transition["evidence"]["containers"].as_array().is_some_and(|containers| !containers.is_empty()) {"proved-exited"} else {"absent-by-label"},"changed":!request.dry_run,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
#[path = "repin_door_tests.rs"]
pub(crate) mod tests;
