//! Measure attributable duplex door calls from a recorded live box.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;
use crate::requests::store::Store;
use crate::valid_run_name;

use super::{checkout, launch_environment, private_podman_environment};

const PROBE: &str = include_str!("exercise_door_attribution_probe.py");

fn incomplete(loop_name: &str, run: &str, reason: &str) -> Value {
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,
        "case":"door-attribution","verdict":"unmeasured","reasons":[reason],"changed":false})
}

/// Measure a live run's registered service through the pinned box stub.
///
/// # Errors
///
/// Refuses a changed reservation, missing bound namespace or malformed probe report.
pub(super) fn measure(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let settings = super::door_shape::settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let (record, identity) = checkout::read_record_bound(&runs, run, owner)?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-door-attribution",
            "reservation identity differs",
        ));
    }
    verify_box_attestation(&record["plan"])?;
    if record["phase"] != "started" {
        return Ok(incomplete(
            loop_name,
            run,
            "a live started reservation is absent",
        ));
    }
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-door-attribution", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, owner)?;
    let podman = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman, owner)?;
    let mut argv = vec!["unshare".into(), exe_word];
    argv.extend(private_argv(loop_name, run, &identity, owner_home)?);
    let output = build::run_checked_with_private_launch(
        podman,
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        90,
        "exercise-door-attribution",
        &home_fd,
        root,
        &runs,
        None,
    );
    let private = match output {
        Ok(output) => serde_json::from_str::<Value>(&output).map_err(|error| {
            LaneError::input(
                "exercise-door-attribution",
                format!("private report: {error}"),
            )
        })?,
        Err(error) => return Ok(incomplete(loop_name, run, &error.line())),
    };
    if private["loop"] != loop_name
        || private["run"] != run
        || private["case"] != "door-attribution"
    {
        return Err(LaneError::input(
            "exercise-door-attribution",
            "private report identity differs",
        ));
    }
    Ok(private)
}

fn private_argv(
    loop_name: &str,
    run: &str,
    identity: &str,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-door-attribution".into(),
        loop_name.into(),
        run.into(),
        "--expect-record".into(),
        identity.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

fn probe_environment(
    run: &str,
    reference: &str,
    worker: u64,
    scope: &str,
    alias: &str,
    mirror_root: &str,
) -> Vec<String> {
    [
        format!("SUPERLOOP_DOOR_RUN={run}"),
        format!("SUPERLOOP_DOOR_REF={reference}"),
        format!("SUPERLOOP_DOOR_UID={worker}"),
        format!("SUPERLOOP_DOOR_SCOPE={scope}"),
        format!("SUPERLOOP_DOOR_ALIAS={alias}"),
        format!("SUPERLOOP_DOOR_MIRROR_ROOT={mirror_root}"),
    ]
    .into_iter()
    .flat_map(|word| ["-e".to_owned(), word])
    .collect()
}

#[derive(Debug)]
pub(crate) struct WatchResult {
    pub(crate) answered: Vec<String>,
    pub(crate) records: HashMap<String, Vec<Value>>,
}

pub(crate) fn watch_requests(
    store: &Store,
    run: &str,
    seen: &HashSet<String>,
    finished: &AtomicBool,
) -> Result<WatchResult, LaneError> {
    watch_requests_with_observer(store, run, seen, finished, |_| {})
}

pub(crate) fn watch_requests_with_observer(
    store: &Store,
    run: &str,
    seen: &HashSet<String>,
    finished: &AtomicBool,
    observed: impl Fn(&Value),
) -> Result<WatchResult, LaneError> {
    let mut result = WatchResult {
        answered: Vec::new(),
        records: HashMap::new(),
    };
    let mut observed_ids = HashSet::new();
    // The box probe below has a 60-second execution budget. Do not restart it
    // on a contended observation or mistake that observation for a verdict.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        for row in store.list_run_until(run, deadline)? {
            let value = row.value();
            if seen.contains(row.id()) || value["run"] != run {
                continue;
            }
            if let Some(operation) = value["operation"].as_str() {
                let rows = result.records.entry(operation.to_owned()).or_default();
                if observed_ids.insert(row.id().to_owned()) {
                    rows.push(value.clone());
                } else if let Some(saved) = rows.iter_mut().find(|saved| saved["id"] == value["id"])
                {
                    *saved = value.clone();
                }
                observed(value);
            }
            if !result.answered.iter().any(|id| id == row.id())
                && value["state"] == "waiting"
                && matches!(
                    value["operation"].as_str(),
                    Some("probe-echo" | "probe-status")
                )
            {
                let at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |time| time.as_nanos())
                    .to_string();
                store.triage(
                    run,
                    &[json!({"id":row.id(),"action":"adjudicate",
                    "treatment":"allow","reason":"bounded attribution probe"})],
                    "exercise-door-attribution",
                    &at,
                )?;
                result.answered.push(row.id().to_owned());
            }
        }
        if finished.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(result)
}

/// Parse the exact descriptor-bound private case form.
///
/// # Errors
///
/// Refuses a malformed or non-absolute form.
pub fn parse_private_argv(args: &[String]) -> Result<(&str, &str, &str, &Path), LaneError> {
    let [
        command,
        loop_name,
        run,
        record_flag,
        identity,
        home_flag,
        home,
    ] = args
    else {
        return Err(LaneError::input(
            "exercise-door-attribution-form",
            "private form is incomplete",
        ));
    };
    if command != "_exercise-door-attribution"
        || record_flag != "--expect-record"
        || home_flag != "--owner-home"
        || identity.is_empty()
        || !valid_run_name(run)
        || !Path::new(home).is_absolute()
    {
        return Err(LaneError::input(
            "exercise-door-attribution-form",
            "private form is malformed",
        ));
    }
    Ok((loop_name, run, identity, Path::new(home)))
}

/// Run the box probe from the recorded vector and match its final status.
///
/// # Errors
///
/// Refuses a changed record, malformed runtime vector or unbound private namespace.
#[allow(clippy::too_many_lines)]
pub fn private_measure(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    identity: &str,
) -> Result<Value, LaneError> {
    if !home::private_is_active() || !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-door-attribution",
            "bound private namespace is absent",
        ));
    }
    let settings = super::door_shape::settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "runs root is absent"))?;
    let runs = home::pin_parent(root, 0)?;
    let (record, actual) = checkout::read_record_bound(&runs, run, 0)?;
    if actual != identity || record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-door-attribution",
            "reservation identity differs",
        ));
    }
    if record["phase"] != "started" {
        return Ok(incomplete(
            loop_name,
            run,
            "a live started reservation is absent",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let Some(reference) = document["door"]["mirror_ref"].as_str() else {
        return Ok(incomplete(loop_name, run, "recorded mirror ref is absent"));
    };
    let worker = record["worker_uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "worker uid is absent"))?;
    let scope = record["door_scope"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "door scope is absent"))?;
    let config = owner_home.join(".config/loops").join(loop_name);
    let config_directory = crate::pinned::open_protected(owner_home, &config, 0)?;
    let route = match crate::door::registered_route(&config_directory, &config, loop_name, 0) {
        Ok(route) => route,
        Err(error) => return Ok(incomplete(loop_name, run, &error.line())),
    };
    let alias = route["alias"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "route alias is absent"))?;
    let mirror_root = route["mirror_root"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "route mirror is absent"))?;
    let mut argv =
        super::mounts::probe_vector_for(document, loop_name, run, "door-attribution", PROBE)?;
    let image = document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "image digest is absent"))?;
    let position = argv
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("exercise-door-attribution", "image boundary is absent"))?;
    argv.splice(
        position..position,
        probe_environment(run, reference, worker, scope, alias, mirror_root),
    );
    let program = Path::new(argv.first().ok_or_else(|| {
        LaneError::input("exercise-door-attribution", "container program is absent")
    })?);
    if let Err(error) = crate::pinned::owner_executable(program, 0) {
        return Ok(incomplete(loop_name, run, &error.line()));
    }
    let environment = match private_podman_environment(owner_home) {
        Ok(value) => value,
        Err(error) => return Ok(incomplete(loop_name, run, &error.line())),
    };
    if let Err(error) =
        super::image_check_with_environment(program, image, owner_home, &environment)
    {
        return Ok(incomplete(loop_name, run, &error.line()));
    }
    let name =
        crate::launch::probe::name(&argv, &super::mounts::probe_name_prefix("door-attribution"))?;
    let store =
        Store::open(owner_home, loop_name, false)?.with_reader_budget(Duration::from_secs(60));
    let seen = store
        .list_run(run)?
        .into_iter()
        .map(|row| row.id().to_owned())
        .collect::<std::collections::HashSet<_>>();
    let finished = Arc::new(AtomicBool::new(false));
    let watcher_finished = Arc::clone(&finished);
    let watcher_run = run.to_owned();
    let watcher =
        thread::spawn(move || watch_requests(&store, &watcher_run, &seen, &watcher_finished));
    let output = build::run_checked(
        program,
        argv[1..].to_vec(),
        &environment,
        owner_home,
        60,
        "exercise-door-attribution-box",
    );
    finished.store(true, Ordering::Release);
    let answered_result = watcher
        .join()
        .map_err(|_| LaneError::operation("exercise-door-attribution", "request watcher panicked"));
    if let Err(error) = crate::launch::probe::remove(
        program,
        owner_home,
        &environment,
        name,
        "door-attribution",
        loop_name,
        run,
    ) {
        return Ok(incomplete(loop_name, run, &error.line()));
    }
    let observation = answered_result??;
    let output = match output {
        Ok(output) => output,
        Err(error) => return Ok(incomplete(loop_name, run, &error.line())),
    };
    let probe: Value = serde_json::from_str(&output).map_err(|error| {
        LaneError::input("exercise-door-attribution", format!("box probe: {error}"))
    })?;
    let (reasons, verdict, claims) =
        evaluate(&probe, run, reference, worker, scope, &observation.records);
    let changed = !observation.answered.is_empty();
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,
        "case":"door-attribution","probe":probe,"registered_route":route,
        "credential_observation":"unmeasured","answered_requests":observation.answered,
        "reasons":reasons,"verdict":verdict,"claims":claims,"changed":changed,
        "compute_requests":compute_observation(&observation.records)}),
    )
}

pub(crate) fn compute_observation(records: &HashMap<String, Vec<Value>>) -> Value {
    let rows = records.get("compute").cloned().unwrap_or_default();
    json!({"status":if rows.is_empty() {"unmeasured"} else {"recorded"},
        "reason":if rows.is_empty() {"no compute request observed during this exercise"} else {"protected request evidence; this exercise does not approve or replay compute"},
        "requests":rows})
}

fn walls(reply: &Value) -> Option<bool> {
    let state = reply.get("queue_state");
    let queue = reply.get("queue_wall_seconds");
    let queue_valid = match (state.and_then(Value::as_str), queue) {
        (Some("answered"), Some(value)) => value.as_f64().is_some_and(|wall| wall >= 0.0),
        (Some("no-queue"), Some(value)) => value.is_null(),
        (None, None) => return None,
        _ => false,
    };
    if !queue_valid {
        return Some(false);
    }
    reply["mediation_wall_seconds"]
        .as_f64()
        .zip(reply["compute_wall_seconds"].as_f64())
        .map(|(mediation, compute)| mediation >= 0.0 && compute > 0.0)
}

fn record_mode<'a>(
    records: &'a HashMap<String, Vec<Value>>,
    operation: &str,
    index: usize,
) -> Option<&'a str> {
    let rows = records.get(operation)?;
    if operation == "git-receive" && rows.len() != 1 {
        return None;
    }
    rows.get(index)?.get("mode")?.as_str()
}

fn labelled_receive_refusal_reason(record: &Value) -> String {
    let adjudicator = record["label"]["adjudicator"]
        .as_str()
        .unwrap_or("unrecorded");
    format!(
        "changed ref is unmeasured: ref_check is not-reached; the refuse label from recorded adjudicator {adjudicator} stopped the probe's changed-ref receive before the door ref check"
    )
}

fn changed_ref_claim(
    probe: &Value,
    reference: &str,
    records: &HashMap<String, Vec<Value>>,
) -> (Option<bool>, String) {
    if probe["changed_ref_waiting"] == true {
        return (
            None,
            "changed ref is unmeasured: git-receive is waiting in the unlabelled queue".into(),
        );
    }
    let (Some(probe_ref), Some(packet_bytes)) = (
        probe["changed_ref"].as_str(),
        probe["changed_ref_bytes"].as_u64(),
    ) else {
        return (
            None,
            "changed ref is unmeasured: the probe's changed-ref receive did not complete".into(),
        );
    };
    if probe_ref == reference {
        return (
            None,
            format!("changed ref is unmeasured: probe ref {probe_ref} equals registered ref"),
        );
    }
    let stderr = probe["changed_ref_reason"].as_str();
    let receive = records
        .get("git-receive")
        .filter(|rows| rows.len() == 1)
        .and_then(|rows| rows.first());
    let Some(record) = receive else {
        return (
            None,
            "changed ref is unmeasured: an attributable git-receive request record is absent"
                .into(),
        );
    };
    let effect = &record["effect"];
    let check = effect["ref_check"].as_str().unwrap_or("pending");
    let recorded_reason = effect["reason"].as_str();
    let adjudicated_refusal = recorded_reason == Some("door-adjudicated-refusal")
        && record["label"]["treatment"] == "refuse";
    let stderr_refused = stderr == Some("door-changed-ref-refusal");
    let recorded_refused = recorded_reason == Some("door-changed-ref-refusal");
    let precheck_stderr = stderr.is_some_and(|reason| {
        matches!(
            reason,
            "door-adjudicated-refusal"
                | "door-git-packet-refusal"
                | "door-request-deadline"
                | "door-rubric-refusal"
                | "door-peer-refusal"
                | "door-capacity-refusal"
                | "door-request-refusal"
                | "door-caller-authority-refusal"
                | "door-review-compute-refusal"
                | "door-compute-unregistered"
                | "door-requests-unregistered"
                | "door-request-record-refusal"
                | "door-request-read-refusal"
        ) || reason.starts_with(crate::door::FULL_STORE_REASON_PREFIX)
    });
    if (check == "admitted" && (stderr_refused || recorded_refused || precheck_stderr))
        || (check == "refused" && (!recorded_refused || (stderr.is_some() && !stderr_refused)))
        || (stderr_refused && check != "refused")
        || (precheck_stderr && matches!(check, "refused" | "no-ref"))
    {
        return (
            None,
            format!("changed ref is unmeasured: stderr and ref_check contradict ({check})"),
        );
    }
    if matches!(check, "admitted" | "refused")
        && effect["stdin_bytes"].as_u64() != Some(packet_bytes)
    {
        return (
            None,
            "changed ref is unmeasured: recorded input differs from the probe's packet".into(),
        );
    }
    match check {
        "admitted" => (Some(false), "changed ref was admitted".into()),
        "refused" => (Some(true), "measured".into()),
        "no-ref" => (
            None,
            "changed ref is unmeasured: no-ref contradicts the changed-ref probe".into(),
        ),
        "not-reached" if adjudicated_refusal => (None, labelled_receive_refusal_reason(record)),
        "not-reached" | "unrecorded" | "not-applicable" | "pending" => (
            None,
            format!("changed ref is unmeasured: ref_check is {check}"),
        ),
        _ => (
            None,
            format!("changed ref is unmeasured: unknown ref_check {check}"),
        ),
    }
}

fn frame_agrees_with_mode(reply: &Value, record: &Value) -> Option<bool> {
    let state = reply["queue_state"].as_str()?;
    let mode = record["mode"].as_str()?;
    Some(match mode {
        "audit" => state == "answered",
        "allow" => state == "no-queue",
        "enforce" => {
            let decided = record["would_do"]["decision"]
                .as_str()
                .is_some_and(|decision| decision != "undecided");
            state == if decided { "no-queue" } else { "answered" }
        }
        _ => false,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn evaluate(
    probe: &Value,
    run: &str,
    reference: &str,
    worker: u64,
    scope: &str,
    records: &HashMap<String, Vec<Value>>,
) -> (Vec<String>, &'static str, Value) {
    let mut reasons = Vec::new();
    if let Some(error) = probe["error"].as_str() {
        reasons.push(format!("box probe: {error}"));
    }
    if scope == "review" {
        if probe["review_reason"].is_string()
            && probe["review_reason"] != "door-review-compute-refusal"
            && probe["review_reason"] != "door-request-concurrent"
        {
            reasons.push("review compute refusal is absent".into());
            return (
                reasons,
                "fail",
                json!({"review_compute_refusal":{
                "verdict":"fail","reason":"review compute refusal is absent","mode":null}}),
            );
        }
        if probe["review_reason"] == "door-review-compute-refusal" {
            reasons.push("review scope: compute attribution needs a work-scope run".into());
        } else if probe["review_reason"] == "door-request-concurrent" {
            reasons.push("door-request-concurrent: review compute refusal is unmeasured".into());
        } else {
            reasons.push("review compute refusal is unmeasured".into());
        }
        return (
            reasons.clone(),
            "unmeasured",
            json!({"review_compute_refusal":{
            "verdict":"unmeasured","reason":reasons[0],"mode":null}}),
        );
    }
    let reply = &probe["reply"];
    let echo_frame = records
        .get("probe-echo")
        .and_then(|rows| rows.first())
        .and_then(|record| frame_agrees_with_mode(reply, record));
    let (changed_ref_observation, changed_ref_reason) =
        changed_ref_claim(probe, reference, records);
    let checks: [(Option<bool>, &str, &str, &str); 9] = [
        (
            reply["status"]
                .as_i64()
                .zip(reply["reason"].as_str())
                .map(|(status, reason)| status == 0 && reason == "door-complete"),
            "complete_status",
            "complete status is absent",
            "probe-echo",
        ),
        (
            reply["registration"]["run"]
                .as_str()
                .zip(reply["registration"]["mirror_ref"].as_str())
                .zip(reply["peer_uid"].as_u64())
                .map(|((actual_run, actual_ref), actual_uid)| {
                    actual_run == run && actual_ref == reference && actual_uid == worker
                }),
            "peer_registration",
            "peer registration or exact ref differs",
            "probe-echo",
        ),
        (
            probe["bytes_match"]
                .as_bool()
                .zip(reply["stdin_bytes"].as_u64())
                .zip(probe["input_bytes"].as_u64())
                .zip(reply["stdout_bytes"].as_u64())
                .zip(probe["output_bytes"].as_u64())
                .map(|((((match_bytes, received), sent), written), observed)| {
                    match_bytes && received == sent && written == observed && sent >= 1_000_000
                }),
            "long_duplex",
            "long duplex bytes differ",
            "probe-echo",
        ),
        (
            walls(reply),
            "separate_walls",
            "separate walls are absent",
            "probe-echo",
        ),
        (
            changed_ref_observation,
            "changed_ref",
            &changed_ref_reason,
            "git-receive",
        ),
        (
            probe["authority_reason"]
                .as_str()
                .map(|reason| reason == "door-caller-authority-refusal"),
            "caller_authority",
            "caller authority was admitted",
            "unregistered",
        ),
        (
            probe["status_exit"]
                .as_i64()
                .zip(probe["status_reply"]["status"].as_i64())
                .zip(probe["status_reply"]["reason"].as_str())
                .map(|((exit, status), reason)| {
                    exit == 1 && status == 1 && reason == "door-complete"
                }),
            "remote_exit_status",
            "remote exit status is incomplete",
            "probe-status",
        ),
        (
            probe["deadline_reason"]
                .as_str()
                .map(|reason| reason == "door-request-deadline"),
            "whole_command_deadline",
            "whole-command deadline is absent",
            "probe-deadline",
        ),
        (
            probe["disconnect_followup"].as_bool(),
            "disconnect_followup",
            "disconnect left the door unavailable",
            "probe-status",
        ),
    ];
    let mut failed = false;
    let mut missing = probe["error"].is_string();
    let mut claims = serde_json::Map::new();
    for (observation, slug, reason, operation) in checks {
        let admission_reason = match slug {
            "changed_ref" => &probe["changed_ref_reason"],
            "caller_authority" => &probe["authority_reason"],
            "remote_exit_status" => &probe["status_reply"]["reason"],
            "whole_command_deadline" => &probe["deadline_reason"],
            "disconnect_followup" => &probe["disconnect_reason"],
            _ => &reply["reason"],
        };
        let concurrent = admission_reason.as_str().is_some_and(|reason| {
            reason == "door-request-concurrent" || reason.starts_with("door-request-concurrent:")
        });
        let disconnect_effect = records
            .get("probe-echo")
            .and_then(|rows| rows.get(1))
            .and_then(|record| record["effect"]["reason"].as_str());
        let disconnect_unmeasured =
            slug == "disconnect_followup" && disconnect_effect != Some("door-disconnect-refusal");
        let index = usize::from(slug == "disconnect_followup");
        let mode_operation = if slug == "disconnect_followup" {
            "probe-echo"
        } else {
            operation
        };
        let mode = record_mode(records, mode_operation, index);
        let echo_disagrees = operation == "probe-echo" && echo_frame == Some(false);
        let own_observation = observation;
        let observation = if concurrent || disconnect_unmeasured {
            None
        } else if echo_disagrees {
            Some(false)
        } else {
            observation
        };
        let measured_reason = if disconnect_unmeasured && !concurrent {
            format!(
                "disconnect is unmeasured: second probe-echo record with door-disconnect-refusal is absent; recorded effect={}",
                disconnect_effect.unwrap_or("absent")
            )
        } else if concurrent {
            "door-request-concurrent: admission did not become available within the bounded probe retry; claim unmeasured".to_owned()
        } else if echo_disagrees {
            let override_reason = "echo frame queue state disagrees with the recorded mode";
            if own_observation == Some(false) {
                format!("{reason}; contradiction: {override_reason}")
            } else {
                override_reason.to_owned()
            }
        } else if observation == Some(true) {
            "measured".to_owned()
        } else {
            reason.to_owned()
        };
        let claim_reason = if slug == "disconnect_followup" {
            format!(
                "{measured_reason}; disconnect measurement mode={}",
                mode.unwrap_or("unrecorded")
            )
        } else if mode.is_none() && operation == "unregistered" {
            format!("{measured_reason}; mode does not apply to a refusal before filing")
        } else if mode.is_none()
            && slug == "changed_ref"
            && records.get(operation).is_some_and(|rows| rows.len() > 1)
        {
            format!(
                "{measured_reason}; mode cannot be attributed among concurrent git-receive requests"
            )
        } else if mode.is_none() {
            format!(
                "{measured_reason}; mode cannot be attributed because the request record is absent"
            )
        } else {
            measured_reason
        };
        claims.insert(
            slug.to_owned(),
            json!({"verdict":match observation {
            Some(true) => "pass", Some(false) => "fail", None => "unmeasured"},
            "reason":claim_reason,"mode":mode}),
        );
        if observation != Some(true) {
            reasons.push(claim_reason);
            if observation == Some(false) {
                failed = true;
            } else {
                missing = true;
            }
        }
    }
    let verdict = if failed {
        "fail"
    } else if missing {
        "unmeasured"
    } else {
        "pass"
    };
    (reasons, verdict, Value::Object(claims))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        PROBE, changed_ref_claim, evaluate, frame_agrees_with_mode, probe_environment, walls,
        watch_requests, watch_requests_with_observer,
    };
    use crate::requests::{
        Mode, ModeSetting, RequestRecord,
        modes::ModeTarget,
        store::tests::{Fixture, with_shape_write_failure},
        tests::waiting,
    };
    use serde_json::json;

    /// ´test:unit:door-attribution-watcher-names-read-and-triage-refusals´
    #[test]
    fn door_attribution_watcher_names_read_and_triage_refusals() {
        let finished = AtomicBool::new(false);
        {
            let fixture = Fixture::new();
            let store = fixture.store();
            store
                .file(waiting("R", "1a", 3000, Mode::Audit))
                .expect("waiting fixture");
            let lock = fixture.home.join(".config/loops/alpha/door-requests.lock");
            fs::remove_file(&lock).expect("remove fixture lock");
            let read = watch_requests(&store, "R", &HashSet::new(), &finished)
                .expect_err("custody without lock");
            assert_eq!(read.kind, "requests-record-refusal");
        }
        {
            let fixture = Fixture::new();
            let store = fixture.store();
            store
                .file(waiting("R", "2b", 3001, Mode::Audit))
                .expect("waiting fixture");
            store
                .fixture_edit_run("R", |run| {
                    run["requests"][0]["operation"] = json!("probe-echo");
                })
                .expect("probe request");
            let triage = with_shape_write_failure(|| {
                watch_requests(&store, "R", &HashSet::new(), &finished)
            })
            .expect_err("triage write refusal");
            assert_eq!(triage.kind, "requests-record-refusal");
            assert!(
                triage.detail.contains("fixture shape write failure"),
                "{triage:?}"
            );
        }
    }

    /// ´test:unit:door-attribution-watcher-refreshes-receive-effect´
    #[test]
    fn door_attribution_watcher_refreshes_receive_effect() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let mut request = waiting("R", "5e", 3000, Mode::Audit).into_value();
        request["class"] = json!("ssh");
        request["shape_key"] = json!("ssh:git-receive");
        request["operation"] = json!("git-receive");
        store
            .file(RequestRecord::decode(request).expect("receive request"))
            .expect("file receive");
        let finished = AtomicBool::new(false);
        let initial_seen = AtomicBool::new(false);
        let refreshed_seen = AtomicBool::new(false);
        let (observed_tx, observed_rx) = mpsc::channel();
        let observed = thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                watch_requests_with_observer(&store, "R", &HashSet::new(), &finished, |value| {
                    if value["effect"]["reason"] == "door-complete" {
                        if !refreshed_seen.swap(true, Ordering::AcqRel) {
                            observed_tx.send("refreshed").expect("notify refreshed");
                        }
                    } else if !initial_seen.swap(true, Ordering::AcqRel) {
                        observed_tx.send("initial").expect("notify initial");
                    }
                })
            });
            let initial = observed_rx.recv_timeout(Duration::from_secs(5));
            if initial.is_err() {
                finished.store(true, Ordering::Release);
            }
            assert_eq!(initial.expect("initial observation"), "initial");
            store
                .record_effect(
                    "R:5e",
                    json!({
                        "state":"completed","reason":"door-complete","exit_status":0,
                        "ref_check":"admitted",
                        "stdin_bytes":101,"stdout_bytes":0,"stderr_bytes":0,
                        "queue_wall_seconds":null,"mediation_wall_seconds":0.01,
                        "compute_wall_seconds":0.01
                    }),
                )
                .expect("record receive effect");
            let refreshed = observed_rx.recv_timeout(Duration::from_secs(5));
            if refreshed.is_err() {
                finished.store(true, Ordering::Release);
            }
            assert_eq!(refreshed.expect("refreshed observation"), "refreshed");
            finished.store(true, Ordering::Release);
            watcher
                .join()
                .expect("watcher")
                .expect("receive observation")
        });
        assert_eq!(
            observed.records["git-receive"][0]["effect"]["reason"],
            "door-complete"
        );
    }

    fn receive_probe_is_not_labelled(floor: &str, mode: Mode) {
        let fixture = Fixture::new();
        fixture.set_floor(floor);
        let store = fixture.store();
        if floor == "allow" {
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Allow,
                    "owner",
                    "fixture allow",
                    "1",
                    &[],
                )
                .expect("allow loop mode");
            store
                .set_mode(
                    &ModeTarget::class("ssh").expect("ssh class"),
                    Mode::Allow,
                    "owner",
                    "fixture allow",
                    "2",
                    &[],
                )
                .expect("allow ssh mode");
        } else {
            store.ensure_first_mode("ssh").expect("audit mode");
        }
        let setting = store.effective_mode("ssh").expect("fixture mode");
        assert_eq!(setting["mode"], floor);
        let mut request = waiting("R", "3c", 3000, mode).into_value();
        request["class"] = json!("ssh");
        request["shape_key"] = json!("ssh:git-receive");
        request["operation"] = json!("git-receive");
        request["mode"] = setting["mode"].clone();
        request["class_setting"] = setting["class"].clone();
        request["loop_setting"] = setting["loop"].clone();
        store
            .file(RequestRecord::decode(request).expect("mode-bound request"))
            .expect("receive request");
        let mut worker_request = waiting("R", "4d", 3000, mode).into_value();
        worker_request["class"] = json!("ssh");
        worker_request["shape_key"] = json!("ssh:git-receive");
        worker_request["operation"] = json!("git-receive");
        worker_request["mode"] = setting["mode"].clone();
        worker_request["class_setting"] = setting["class"].clone();
        worker_request["loop_setting"] = setting["loop"].clone();
        store
            .file(RequestRecord::decode(worker_request).expect("worker request"))
            .expect("worker receive");
        let finished = AtomicBool::new(false);
        let answered = thread::scope(|scope| {
            let watcher = scope.spawn(|| watch_requests(&store, "R", &HashSet::new(), &finished));
            thread::sleep(Duration::from_millis(100));
            finished.store(true, std::sync::atomic::Ordering::Release);
            watcher.join().expect("watcher").expect("labelled request")
        });
        assert!(answered.answered.is_empty(), "{floor}");
        assert_eq!(answered.records["git-receive"].len(), 2);
        assert_eq!(answered.records["git-receive"][0]["mode"], floor);
        assert_eq!(
            store.request("R:3c").expect("unlabelled receive").value()["label"],
            json!(null)
        );
        assert_eq!(
            store
                .request("R:4d")
                .expect("unlabelled worker receive")
                .value()["label"],
            json!(null)
        );
    }

    /// ´test:unit:door-attribution-audit-receive-probe-is-not-labelled´
    #[test]
    fn door_attribution_audit_receive_probe_is_not_labelled() {
        receive_probe_is_not_labelled("audit", Mode::Audit);
    }

    /// ´test:unit:door-attribution-allow-receive-probe-is-not-labelled´
    #[test]
    fn door_attribution_allow_receive_probe_is_not_labelled() {
        receive_probe_is_not_labelled("allow", Mode::Allow);
    }

    fn records(mode: &str) -> HashMap<String, Vec<serde_json::Value>> {
        [
            "probe-echo",
            "git-receive",
            "probe-status",
            "probe-deadline",
        ]
        .into_iter()
        .map(|operation| {
            let mut record = json!({"mode":mode,"state":"waiting"});
            if operation == "git-receive" {
                record["effect"] = json!({"reason":"door-changed-ref-refusal",
                    "ref_check":"refused","stdin_bytes":101});
            }
            let mut rows = vec![record.clone()];
            if operation == "probe-status" {
                rows.push(record.clone());
            }
            if operation == "probe-echo" {
                record["effect"] = json!({"reason":"door-disconnect-refusal"});
                rows.push(record);
            }
            (operation.to_owned(), rows)
        })
        .collect()
    }

    /// ´test:unit:door-attribution-walls-accept-audit-allow-and-enforce-frames´
    #[test]
    fn door_attribution_walls_accept_audit_allow_and_enforce_frames() {
        for (mode, state, queue) in [
            ("audit", "answered", json!(0.022)),
            ("allow", "no-queue", json!(null)),
            ("enforce", "answered", json!(0.022)),
        ] {
            let report = json!({"reply":{"status":0,"reason":"door-complete","ref_check":"not-applicable","registration":{"run":"R","mirror_ref":"refs/heads/lane/R"},"peer_uid":3000,"stdin_bytes":1_054_200,"stdout_bytes":1_054_200,"queue_state":state,"queue_wall_seconds":queue,"mediation_wall_seconds":0.605,"compute_wall_seconds":14.08},"bytes_match":true,"input_bytes":1_054_200,"output_bytes":1_054_200,"changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101,"changed_ref_reason":"door-changed-ref-refusal","authority_reason":"door-caller-authority-refusal","status_exit":1,"status_reply":{"status":1,"reason":"door-complete","ref_check":"not-applicable"},"deadline_reason":"door-request-deadline","disconnect_followup":true});
            let (reasons, verdict, claims) = evaluate(
                &report,
                "R",
                "refs/heads/lane/R",
                3000,
                "work",
                &records(mode),
            );
            assert_eq!(verdict, "pass", "{mode}: {reasons:?}");
            assert_eq!(claims["disconnect_followup"]["mode"], mode);
            assert_eq!(claims["disconnect_followup"]["verdict"], "pass");
            assert_eq!(claims["separate_walls"]["mode"], mode);
            assert_eq!(claims["separate_walls"]["verdict"], "pass");
            assert_eq!(claims["caller_authority"]["verdict"], "pass");
            assert!(claims["caller_authority"]["mode"].is_null());
        }
    }

    /// # Panics
    /// Panics only if refused admission is reported as a measured claim.
    /// ´test:unit:door-attribution-concurrent-admission-is-unmeasured´
    #[test]
    fn door_attribution_concurrent_admission_is_unmeasured() {
        let report = json!({"reply":{"status":125,"reason":"door-request-concurrent"},
            "bytes_match":false,"input_bytes":100,"output_bytes":0,
            "changed_ref_reason":"door-request-concurrent: admission held",
            "authority_reason":"door-request-concurrent: admission held",
            "status_exit":125,"status_reply":{"status":125,"reason":"door-request-concurrent"},
            "deadline_reason":"door-request-concurrent","disconnect_reason":"door-request-concurrent",
            "disconnect_followup":false});
        let (_, verdict, claims) = evaluate(
            &report,
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert_eq!(verdict, "unmeasured");
        for claim in claims.as_object().expect("claims").values() {
            assert_eq!(claim["verdict"], "unmeasured");
            assert!(
                claim["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("door-request-concurrent")
            );
        }
        let (_, verdict, _) = evaluate(
            &json!({"review_reason":"door-request-concurrent"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "review",
            &HashMap::new(),
        );
        assert_eq!(verdict, "unmeasured");
    }

    /// # Panics
    /// Panics only if follow-up success stands in for an unobserved disconnect.
    /// ´test:unit:door-attribution-disconnect-needs-recorded-effect´
    #[test]
    fn door_attribution_disconnect_needs_recorded_effect() {
        let probe = json!({"disconnect_followup":true});
        for mode in ["audit", "enforce", "allow"] {
            let mut rows = records("allow");
            for (reason, expected_reason) in [
                (
                    None,
                    "disconnect is unmeasured: second probe-echo record with door-disconnect-refusal is absent; recorded effect=absent",
                ),
                (
                    Some("door-complete"),
                    "disconnect is unmeasured: second probe-echo record with door-disconnect-refusal is absent; recorded effect=door-complete",
                ),
                (
                    Some("door-request-concurrent"),
                    "disconnect is unmeasured: second probe-echo record with door-disconnect-refusal is absent; recorded effect=door-request-concurrent",
                ),
                (Some("door-disconnect-refusal"), "measured"),
            ] {
                let echo = rows.get_mut("probe-echo").expect("echo records");
                echo.truncate(1);
                if let Some(reason) = reason {
                    echo.push(json!({"mode":mode,"effect":{"reason":reason}}));
                }
                let (_, _, claims) =
                    evaluate(&probe, "R", "refs/heads/lane/R", 3000, "work", &rows);
                let claim = &claims["disconnect_followup"];
                assert_eq!(
                    claim["verdict"],
                    if reason == Some("door-disconnect-refusal") {
                        "pass"
                    } else {
                        "unmeasured"
                    },
                    "{mode} {reason:?}: {claims}"
                );
                let measured_mode = reason.map(|_| mode);
                assert_eq!(claim["mode"], json!(measured_mode));
                assert_eq!(
                    claim["reason"],
                    format!(
                        "{expected_reason}; disconnect measurement mode={}",
                        measured_mode.unwrap_or("unrecorded")
                    )
                );
            }
        }
    }

    /// ´test:unit:door-attribution-walls-refuse-invalid-queue-shapes´
    #[test]
    fn door_attribution_walls_refuse_invalid_queue_shapes() {
        for (state, queue) in [
            ("deadline", json!(null)),
            ("refused", json!(null)),
            ("answered", json!(null)),
            ("no-queue", json!(0.022)),
            ("answered", json!(-0.022)),
        ] {
            let report = json!({"reply":{"ref_check":"not-applicable","queue_state":state,"queue_wall_seconds":queue,
                "mediation_wall_seconds":0.605,"compute_wall_seconds":14.08}});
            assert_eq!(walls(&report["reply"]), Some(false), "{state}: {queue}");
            let (_, _, claims) = evaluate(
                &report,
                "R",
                "refs/heads/lane/R",
                3000,
                "work",
                &records("audit"),
            );
            assert_eq!(
                claims["separate_walls"]["verdict"], "fail",
                "{state}: {queue}"
            );
        }
    }

    /// ´test:unit:door-attribution-echo-mismatch-names-override-and-keeps-own-failure´
    #[test]
    fn door_attribution_echo_mismatch_names_override_and_keeps_own_failure() {
        let mut report = json!({"reply":{"status":0,"reason":"door-complete","ref_check":"not-applicable","registration":{"run":"R","mirror_ref":"refs/heads/lane/R"},"peer_uid":3000,"stdin_bytes":1_054_200,"stdout_bytes":1_054_200,"queue_state":"no-queue","queue_wall_seconds":null,"mediation_wall_seconds":0.605,"compute_wall_seconds":14.08},"bytes_match":false,"input_bytes":1_054_200,"output_bytes":1_054_200,"changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101,"changed_ref_reason":"door-changed-ref-refusal","authority_reason":"door-caller-authority-refusal","status_exit":1,"status_reply":{"status":1,"reason":"door-complete","ref_check":"not-applicable"},"deadline_reason":"door-request-deadline","disconnect_followup":true});
        let (_, verdict, claims) = evaluate(
            &report,
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert_eq!(verdict, "fail");
        for slug in ["complete_status", "peer_registration", "separate_walls"] {
            assert_eq!(claims[slug]["verdict"], "fail", "{slug}");
            assert_eq!(
                claims[slug]["reason"], "echo frame queue state disagrees with the recorded mode",
                "{slug}"
            );
        }
        assert_eq!(claims["long_duplex"]["verdict"], "fail");
        assert_eq!(
            claims["long_duplex"]["reason"],
            "long duplex bytes differ; contradiction: echo frame queue state disagrees with the recorded mode"
        );
        report["reply"]["queue_state"] = json!("answered");
        report["reply"]["queue_wall_seconds"] = json!(0.022);
        let (_, verdict, claims) = evaluate(
            &report,
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert_eq!(verdict, "fail");
        assert_eq!(claims["long_duplex"]["reason"], "long duplex bytes differ");
        assert_eq!(claims["long_duplex"]["verdict"], "fail");
        for slug in ["complete_status", "peer_registration", "separate_walls"] {
            assert_eq!(claims[slug]["verdict"], "pass", "{slug}");
        }
    }

    /// ´test:unit:door-attribution-enforce-frame-follows-recorded-decision´
    #[test]
    fn door_attribution_enforce_frame_follows_recorded_decision() {
        let queued = json!({"mode":"enforce","would_do":{"decision":"undecided"}});
        let decided = json!({"mode":"enforce","would_do":{"decision":"allow"}});
        assert_eq!(
            frame_agrees_with_mode(&json!({"queue_state":"answered"}), &queued),
            Some(true)
        );
        assert_eq!(
            frame_agrees_with_mode(&json!({"queue_state":"no-queue"}), &decided),
            Some(true)
        );
        assert_eq!(
            frame_agrees_with_mode(&json!({"queue_state":"no-queue"}), &queued),
            Some(false)
        );
    }

    /// ´test:unit:door-attribution-concurrent-receive-unmeasured-without-mode´
    #[test]
    fn door_attribution_concurrent_receive_unmeasured_without_mode() {
        let mut filed = records("audit");
        filed.get_mut("git-receive").expect("receives").push(json!({
            "mode":"audit","state":"waiting"
        }));
        let (_, verdict, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101,
                "changed_ref_reason":"door-changed-ref-refusal",
                "authority_reason":"admitted"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(verdict, "fail");
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(claims["changed_ref"]["mode"].is_null());
        assert_eq!(claims["caller_authority"]["verdict"], "fail");
        assert!(claims["caller_authority"]["mode"].is_null());
        let (_, verdict, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101,
                "changed_ref_reason":"admitted",
                "authority_reason":"door-caller-authority-refusal"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(verdict, "unmeasured");
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(claims["changed_ref"]["mode"].is_null());
        assert_eq!(claims["caller_authority"]["verdict"], "pass");
    }

    /// ´test:unit:door-attribution-changed-ref-admission-uses-ref-check-record´
    #[test]
    fn door_attribution_changed_ref_admission_uses_ref_check_record() {
        let mut filed = records("allow");
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-compute-io-refusal","ref_check":"admitted","stdin_bytes":101
        });
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_reason":"door-compute-io-refusal","changed_ref_bytes":101}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "fail");
        assert_eq!(claims["changed_ref"]["reason"], "changed ref was admitted");
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_reason":"door-compute-io-refusal", "changed_ref_bytes":101,
                "changed_ref_waiting":true}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .expect("reason")
                .contains("waiting in the unlabelled queue")
        );
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_reason":"door-compute-io-refusal", "changed_ref_bytes":101}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &HashMap::new(),
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .expect("reason")
                .contains("attributable git-receive request record")
        );
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-complete","ref_check":"admitted","stdin_bytes":101
        });
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "fail");
        assert_eq!(claims["changed_ref"]["reason"], "changed ref was admitted");
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-compute-io-refusal","ref_check":"admitted","stdin_bytes":101
        });
        filed
            .get_mut("git-receive")
            .expect("receive")
            .push(json!({"mode":"allow","state":"waiting"}));
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .expect("reason")
                .contains("among concurrent git-receive requests")
        );
    }

    /// ´test:unit:door-attribution-waiting-receive-does-not-borrow-another-record´
    #[test]
    fn door_attribution_waiting_receive_does_not_borrow_another_record() {
        let mut filed = records("allow");
        filed.get_mut("git-receive").expect("other receive")[0]["effect"] = json!({
            "reason":"door-compute-io-refusal","ref_check":"admitted","stdin_bytes":129
        });
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_reason":"door-compute-io-refusal", "changed_ref_bytes":129,
                "changed_ref_waiting":true}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .expect("reason")
                .contains("waiting in the unlabelled queue")
        );
    }

    /// ´test:unit:door-attribution-precheck-reasons-are-unmeasured´
    #[test]
    fn door_attribution_precheck_reasons_are_unmeasured() {
        for reason in ["door-adjudicated-refusal", "door-git-packet-refusal"] {
            let mut filed = records("audit");
            filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
                "reason":reason,"ref_check":"not-reached"
            });
            let (_, _, claims) = evaluate(
                &json!({"changed_ref":"refs/heads/lane/R-changed",
                    "changed_ref_bytes":101,"changed_ref_reason":reason}),
                "R",
                "refs/heads/lane/R",
                3000,
                "work",
                &filed,
            );
            assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
            assert!(
                claims["changed_ref"]["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("not-reached")
            );
        }
        let mut filed = records("allow");
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-compute-io-refusal","ref_check":"admitted","stdin_bytes":101
        });
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_reason":"door-adjudicated-refusal","changed_ref_bytes":101}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .expect("reason")
                .contains("stderr and ref_check contradict")
        );
    }

    fn records_with_labelled_receive(
        reason: &str,
        effect_before_label: bool,
    ) -> HashMap<String, Vec<serde_json::Value>> {
        let mut filed = records("audit");
        let floor = if effect_before_label {
            Mode::Allow
        } else {
            Mode::Audit
        };
        let mut receive = waiting("R", "3c", 3000, floor).into_value();
        receive["class"] = json!("ssh");
        receive["shape_key"] = json!("ssh:git-receive");
        receive["operation"] = json!("git-receive");
        if effect_before_label {
            let setting =
                ModeSetting::first(Mode::Enforce, Mode::Allow, "owner", "fixture enforce", "2")
                    .expect("enforce setting");
            receive["mode"] = json!("enforce");
            receive["class_setting"] = setting.value().clone();
            receive["loop_setting"] = setting.value().clone();
            receive["would_do"] = json!({"decision":"refuse","reason":"fixture rubric"});
            receive["state"] = json!(null);
        }
        let mut receive = RequestRecord::decode(receive).expect("receive request");
        let mut reply = json!({
            "schema":2,"type":"final","status":125,"reason":reason,
            "registration":{"schema":1,"loop":"alpha","run":"R","worker_uid":3000,
                "loop_uid":2000,"scope":"work","mirror_ref":"refs/heads/lane/R"},
            "peer_uid":3000,"ref_check":"not-reached",
            "stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
            "queue_state":"no-queue","queue_wall_seconds":null,"compute_exit_status":null,
            "mediation_wall_seconds":0.01,"compute_wall_seconds":0.0
        });
        if !effect_before_label {
            reply["queue_state"] = json!("refused");
            reply["queue_wall_seconds"] = json!(0.01);
            reply["request_id"] = receive.value()["id"].clone();
        }
        let effect = crate::door::effect_from_final(&reply);
        if effect_before_label {
            receive.record_effect(effect).expect("early effect");
            receive.publish_observed().expect("observed effect");
            receive.mark_observed().expect("mark observed effect");
            receive.review("review", "3").expect("review effect");
            receive
                .adjudicate(
                    "review",
                    "refuse",
                    "fixture refusal",
                    "owner-adjudicate",
                    "4",
                )
                .expect("later refuse label");
        } else {
            receive
                .triage("refuse", "fixture refusal", "owner-triage", "2")
                .expect("refuse label");
            receive.record_effect(effect).expect("labelled effect");
        }
        assert_eq!(receive.value()["state"], "adjudicated");
        assert_eq!(
            receive.value()["label"]
                .as_object()
                .map(serde_json::Map::len),
            Some(8)
        );
        filed.get_mut("git-receive").expect("receive")[0] =
            RequestRecord::decode(receive.into_value())
                .expect("adjudicated receive")
                .into_value();
        filed
    }

    /// ´test:unit:door-attribution-refuse-label-names-recorded-adjudicator´
    #[test]
    fn door_attribution_refuse_label_names_recorded_adjudicator() {
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_bytes":101,"changed_ref_reason":"door-adjudicated-refusal"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records_with_labelled_receive("door-adjudicated-refusal", false),
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert_eq!(
            claims["changed_ref"]["reason"],
            "changed ref is unmeasured: ref_check is not-reached; the refuse label from recorded adjudicator owner-triage stopped the probe's changed-ref receive before the door ref check"
        );
    }

    /// ´test:unit:door-attribution-later-refuse-label-keeps-door-refusal´
    #[test]
    fn door_attribution_later_refuse_label_keeps_door_refusal() {
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_bytes":101,"changed_ref_reason":"door-rubric-refusal"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records_with_labelled_receive("door-rubric-refusal", true),
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert_eq!(
            claims["changed_ref"]["reason"],
            "changed ref is unmeasured: ref_check is not-reached"
        );
    }

    /// ´test:unit:door-attribution-ref-check-verdicts-replace-stdin-proxy´
    #[test]
    fn door_attribution_ref_check_verdicts_replace_stdin_proxy() {
        for (check, reason, stderr, verdict, detail) in [
            (
                "admitted",
                "door-complete",
                "door-complete",
                Some(false),
                "changed ref was admitted",
            ),
            (
                "refused",
                "door-changed-ref-refusal",
                "door-changed-ref-refusal",
                Some(true),
                "measured",
            ),
            (
                "not-reached",
                "door-git-packet-refusal",
                "door-git-packet-refusal",
                None,
                "not-reached",
            ),
            (
                "unrecorded",
                "door-complete",
                "door-complete",
                None,
                "unrecorded",
            ),
            (
                "no-ref",
                "door-complete",
                "door-complete",
                None,
                "no-ref contradicts",
            ),
            (
                "admitted",
                "door-complete",
                "door-adjudicated-refusal",
                None,
                "contradict",
            ),
            (
                "not-reached",
                "door-git-packet-refusal",
                "door-changed-ref-refusal",
                None,
                "contradict",
            ),
            (
                "admitted",
                "door-deadline-refusal",
                "door-deadline-refusal",
                Some(false),
                "changed ref was admitted",
            ),
            (
                "admitted",
                "door-input-limit-refusal",
                "door-input-limit-refusal",
                Some(false),
                "changed ref was admitted",
            ),
            (
                "admitted",
                "door-requests-full-refusal: loop request capacity is full; retire LOOP RUN for a finished run to free room",
                "door-requests-full-refusal: loop request capacity is full; retire LOOP RUN for a finished run to free room",
                None,
                "contradict",
            ),
        ] {
            let mut filed = records("allow");
            filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
                "reason":reason,"ref_check":check,"stdin_bytes":101
            });
            let probe = json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_reason":stderr,"changed_ref_bytes":101});
            let (observed, explanation) = changed_ref_claim(&probe, "refs/heads/lane/R", &filed);
            assert_eq!(observed, verdict, "{check}: {stderr}");
            assert!(explanation.contains(detail), "{check}: {explanation}");
        }
    }

    /// ´test:unit:door-attribution-registered-changed-ref-cannot-be-a-failure´
    #[test]
    fn door_attribution_registered_changed_ref_cannot_be_a_failure() {
        let mut filed = records("allow");
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-complete","ref_check":"admitted","stdin_bytes":101
        });
        let probe = json!({"changed_ref":"refs/heads/lane/changed","changed_ref_bytes":101});
        let (_, _, claims) = evaluate(
            &probe,
            "changed",
            "refs/heads/lane/changed",
            3000,
            "work",
            &filed,
        );
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .expect("reason")
                .contains("equals registered ref")
        );
        let (observed, reason) = changed_ref_claim(
            &json!({"changed_ref":"refs/heads/lane/changed-changed",
                "changed_ref_bytes":101}),
            "refs/heads/lane/changed",
            &filed,
        );
        assert_eq!(observed, Some(false));
        assert_eq!(reason, "changed ref was admitted");
    }

    /// ´test:unit:door-attribution-probe-error-without-receive-cannot-borrow-admission´
    #[test]
    fn door_attribution_probe_error_without_receive_cannot_borrow_admission() {
        let mut filed = records("allow");
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-complete","ref_check":"admitted","stdin_bytes":101
        });
        for probe in [
            json!({"error":"probe failed before receive"}),
            json!({"error":"probe failed before receive","changed_ref_bytes":101}),
            json!({"error":"probe failed before receive",
                "changed_ref":"refs/heads/lane/R-changed"}),
        ] {
            let (_, _, claims) = evaluate(&probe, "R", "refs/heads/lane/R", 3000, "work", &filed);
            assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
            assert!(
                claims["changed_ref"]["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("changed-ref receive did not complete")
            );
        }
    }

    /// ´test:unit:door-attribution-other-receive-bytes-cannot-borrow-admission´
    #[test]
    fn door_attribution_other_receive_bytes_cannot_borrow_admission() {
        let mut filed = records("allow");
        filed.get_mut("git-receive").expect("receive")[0]["effect"] = json!({
            "reason":"door-complete","ref_check":"admitted","stdin_bytes":202
        });
        for stderr in [None, Some("door-socket: unavailable")] {
            let probe = json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_bytes":101,"changed_ref_reason":stderr});
            let (_, _, claims) = evaluate(&probe, "R", "refs/heads/lane/R", 3000, "work", &filed);
            assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
            assert!(
                claims["changed_ref"]["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("input differs from the probe's packet")
            );
        }
    }

    /// ´test:unit:door-attribution-unlabelled-receive-names-queue´
    #[test]
    fn door_attribution_unlabelled_receive_names_queue() {
        let report = json!({"changed_ref":"refs/heads/lane/R-changed",
            "changed_ref_bytes":101,"changed_ref_waiting":true});
        let (_, verdict, claims) = evaluate(
            &report,
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert_eq!(verdict, "unmeasured");
        assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
        assert!(
            claims["changed_ref"]["reason"]
                .as_str()
                .unwrap()
                .contains("waiting in the unlabelled queue")
        );
        let (_, _, claims) = evaluate(
            &json!({"changed_ref":"refs/heads/lane/R-changed",
                "changed_ref_bytes":101,"changed_ref_waiting":false}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert!(
            !claims["changed_ref"]["reason"]
                .as_str()
                .expect("claim reason")
                .contains("waiting in the unlabelled queue")
        );
    }

    /// ´test:unit:door-attribution-box-environment-has-one-flag-per-value´
    #[test]
    fn door_attribution_box_environment_has_one_flag_per_value() {
        let words = probe_environment(
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            "fixture",
            "~/mirrors",
        );
        assert_eq!(words.len(), 12);
        assert!(words.as_chunks::<2>().0.iter().all(|pair| pair[0] == "-e"));
        assert_eq!(words[9], "SUPERLOOP_DOOR_ALIAS=fixture");
        assert_eq!(words[11], "SUPERLOOP_DOOR_MIRROR_ROOT=~/mirrors");
    }

    /// ´test:unit:door-attribution-missing-and-git-text-are-unmeasured´
    #[test]
    fn door_attribution_missing_and_git_text_are_unmeasured() {
        let (reasons, verdict, _) = evaluate(
            &json!({"error":"stub absent"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert_eq!(verdict, "unmeasured");
        assert!(reasons.iter().any(|reason| reason.contains("stub absent")));
        let (reasons, verdict, _) = evaluate(
            &json!({"reply":{"status":0,"reason":"door-complete","ref_check":"not-applicable"},
                "changed_ref":"refs/heads/lane/R-changed","changed_ref_bytes":101,
                "changed_ref_reason":"other"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "work",
            &records("audit"),
        );
        assert_eq!(verdict, "unmeasured");
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("stderr and ref_check contradict"))
        );
    }

    /// ´test:unit:door-attribution-review-scope-names-why-work-attribution-is-unmeasured´
    #[test]
    fn door_attribution_review_scope_names_why_work_attribution_is_unmeasured() {
        let (reasons, verdict, _) = evaluate(
            &json!({"review_reason":"door-review-compute-refusal"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "review",
            &records("audit"),
        );
        assert_eq!(verdict, "unmeasured");
        assert_eq!(
            reasons,
            ["review scope: compute attribution needs a work-scope run"]
        );
        let (reasons, verdict, _) = evaluate(
            &json!({"review_reason":"door-request-refusal"}),
            "R",
            "refs/heads/lane/R",
            3000,
            "review",
            &records("audit"),
        );
        assert_eq!(verdict, "fail");
        assert_eq!(reasons, ["review compute refusal is absent"]);
        for malformed in [
            json!({"review_reason":true}),
            json!({"review_reason":["door-review-compute-refusal"]}),
        ] {
            let (reasons, verdict, _) = evaluate(
                &malformed,
                "R",
                "refs/heads/lane/R",
                3000,
                "review",
                &records("audit"),
            );
            assert_eq!(verdict, "unmeasured");
            assert_eq!(reasons, ["review compute refusal is unmeasured"]);
        }
    }

    /// The probe shares its budget across calls and reports timeouts without inventing a door reply.
    ///
    /// # Panics
    /// Panics only if the controlled clock fixture or the unmeasured classification differs.
    /// ´test:unit:door-attribution-probe-shares-one-deadline´
    #[test]
    fn door_attribution_probe_shares_one_deadline() {
        let output = Command::new("/usr/bin/python3")
            .args(["-c", r"
import contextlib, io, json, os, subprocess, sys, types
probe = {'__name__': 'probe'}
exec(sys.argv[1], probe)
clock = [0.0]
probe['time'] = types.SimpleNamespace(monotonic=lambda: clock[0], sleep=lambda delay: clock.__setitem__(0, clock[0] + delay))
budgets = []
def timeout_run(argv, **options):
    budgets.append(options['timeout'])
    clock[0] += options['timeout']
    raise subprocess.TimeoutExpired(argv, options['timeout'])
probe['subprocess'] = types.SimpleNamespace(run=timeout_run, PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired)
for expected in [35, 20]:
    try:
        probe['invoke']('fixture', deadline=55)
    except subprocess.TimeoutExpired:
        assert budgets[-1] == expected, budgets
    else:
        raise AssertionError('timeout escaped')
assert clock[0] == 55
try:
    probe['invoke']('fixture', deadline=55)
except TimeoutError:
    pass
else:
    raise AssertionError('exhausted budget admitted another call')
assert budgets == [35, 20]
clock[0] = 50
try:
    probe['invoke']('fixture', deadline=55, timeout=15)
except subprocess.TimeoutExpired:
    assert budgets[-1] == 5
else:
    raise AssertionError('receive cap ignored the shared budget')
class Peer:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, value): assert 0 < value <= 5
    def connect(self, path): clock[0] += 5
    def sendall(self, data): raise AssertionError('socket budget restarted after connect')
probe['socket'] = types.SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=lambda *args: Peer())
clock[0] = 0
try:
    probe['raw_request']({}, deadline=55, disconnect=True)
except TimeoutError:
    pass
else:
    raise AssertionError('raw request exceeded its call budget')
os.environ.update(SUPERLOOP_DOOR_RUN='R', SUPERLOOP_DOOR_REF='refs/heads/lane/R', SUPERLOOP_DOOR_ALIAS='fixture', SUPERLOOP_DOOR_MIRROR_ROOT='/fixture')
reports = []
for scope in ['review', 'work']:
    clock[0] = 0
    os.environ['SUPERLOOP_DOOR_SCOPE'] = scope
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured): probe['main']()
    report = json.loads(captured.getvalue())
    assert report['error'] == probe['TIMEOUT_REASON']
    assert 'reply' not in report and 'review_reason' not in report
    reports.append(report)
print(json.dumps(reports))
", PROBE])
            .output()
            .expect("controlled probe execution");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reports: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).expect("probe reports");
        for report in reports {
            let (reasons, verdict, _) = evaluate(
                &report,
                "R",
                "refs/heads/lane/R",
                3000,
                report["scope"].as_str().expect("scope"),
                &HashMap::new(),
            );
            assert_eq!(verdict, "unmeasured");
            assert!(reasons.iter().any(|reason| {
                reason.contains("door-request-concurrent: attribution probe timed out")
            }));
        }
    }

    /// ´test:unit:door-attribution-python-probe-derives-distinct-ref-and-requires-canaries´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_attribution_python_probe_derives_distinct_ref_and_requires_canaries() {
        let fixture = tempfile::tempdir().expect("probe fixture");
        let stub = fixture.path().join("stub");
        let socket =
            crate::fixture_exec::fixture_socket_path(fixture.path().join("capability.sock"));
        let listener = UnixListener::bind(&socket).expect("fixture socket");
        listener
            .set_nonblocking(true)
            .expect("bounded fixture accept");
        crate::fixture_exec::write_executable(&stub, r#"#!/usr/bin/python3
import json,sys,os
op=sys.argv[1]
counter=os.environ['SUPERLOOP_FIXTURE_COUNTER']+'/'+os.environ['SUPERLOOP_FIXTURE_MODE']+'-'+os.environ['SUPERLOOP_DOOR_RUN']+'-'+op
if not os.path.exists(counter):
 open(counter,'w').close()
 if op=='unregistered' or op=='fixture':
  print('door-request-concurrent: admission held',file=sys.stderr)
 else:
  print(json.dumps({'type':'final','status':125,'reason':'door-request-concurrent'}),file=sys.stderr)
 sys.exit(125)
if op=='door-attribution-probe':
 data=sys.stdin.buffer.read()
 sys.stdout.buffer.write(data)
 mode=os.environ['SUPERLOOP_FIXTURE_MODE']
 print(json.dumps({'type':'final','status':0,'reason':'door-complete','ref_check':'not-applicable','registration':{'run':os.environ['SUPERLOOP_DOOR_RUN'],'mirror_ref':os.environ['SUPERLOOP_DOOR_REF']},'peer_uid':3000,'stdin_bytes':len(data),'stdout_bytes':len(data),'queue_state':'no-queue' if mode=='allow' else 'answered','queue_wall_seconds':None if mode=='allow' else 0.022,'mediation_wall_seconds':0.605,'compute_wall_seconds':14.08}),file=sys.stderr)
elif op=='fixture' and sys.argv[2]=="git-receive-pack '~/mirrors/"+os.environ['SUPERLOOP_DOOR_RUN']+".git'":
 data=sys.stdin.buffer.read()
 expected=(os.environ['SUPERLOOP_DOOR_REF']+'-changed').encode()
 reason='door-changed-ref-refusal' if expected in data and data.endswith(b'0000') else 'door-git-packet-refusal'
 print(reason,file=sys.stderr)
 sys.exit(125)
elif op=='door-attribution-status':
 print(json.dumps({'type':'final','status':1,'reason':'door-complete'}),file=sys.stderr)
 sys.exit(1)
elif op=='door-attribution-deadline':
 print(json.dumps({'type':'final','status':125,'reason':'door-request-deadline'}),file=sys.stderr)
 sys.exit(125)
else:
 print('door-caller-authority-refusal',file=sys.stderr)
 sys.exit(125)
"#.as_bytes()).expect("closed and synced fixture stub");
        // A concurrent fork can retain a fixture writer until its next exec.
        // Keep one open to prove that the fixture is interpreted as input.
        let _held_writer = fs::OpenOptions::new()
            .write(true)
            .open(&stub)
            .expect("held fixture writer");
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            for _ in 0..4 {
                let (mut peer, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("fixture peer: {error}"),
                    }
                };
                let mut size = [0_u8; 4];
                peer.read_exact(&mut size).expect("frame header");
                let mut request = vec![0; u32::from_be_bytes(size) as usize];
                peer.read_exact(&mut request).expect("request frame");
            }
        });
        assert_eq!(PROBE.matches("[STUB, *words]").count(), 1);
        let patched = PROBE
            .replace("[STUB, *words]", "[\"/usr/bin/python3\", STUB, *words]")
            .replace(
                "STUB = \"/home/worker/.local/libexec/superloop/ssh\"",
                &format!("STUB = {:?}", stub.display().to_string()),
            )
            .replace(
                "SOCKET = \"/home/worker/.local/door/capability.sock\"",
                &format!("SOCKET = {:?}", socket.display().to_string()),
            );
        for (mode, run) in [
            ("audit", "R"),
            ("allow", "R"),
            ("enforce", "R"),
            ("allow", "changed"),
        ] {
            let reference = format!("refs/heads/lane/{run}");
            let output = Command::new("/usr/bin/python3")
                .args(["-c", &patched])
                .env("SUPERLOOP_DOOR_SCOPE", "work")
                .env("SUPERLOOP_DOOR_RUN", run)
                .env("SUPERLOOP_DOOR_REF", &reference)
                .env("SUPERLOOP_DOOR_UID", "3000")
                .env("SUPERLOOP_DOOR_ALIAS", "fixture")
                .env("SUPERLOOP_DOOR_MIRROR_ROOT", "~/mirrors")
                .env("SUPERLOOP_FIXTURE_MODE", mode)
                .env("SUPERLOOP_FIXTURE_COUNTER", fixture.path())
                .output()
                .expect("probe execution");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("box report");
            assert_eq!(
                report["changed_ref"],
                format!("{reference}-changed"),
                "probe report: {report}"
            );
            assert_ne!(report["changed_ref"], reference);
            assert_eq!(report["changed_ref_reason"], "door-changed-ref-refusal");
            if run == "changed" {
                continue;
            }
            let mut filed = records(mode);
            filed.get_mut("git-receive").expect("receive")[0]["effect"]["stdin_bytes"] =
                report["changed_ref_bytes"].clone();
            let (reasons, verdict, claims) =
                evaluate(&report, run, &reference, 3000, "work", &filed);
            assert_eq!(verdict, "pass", "{mode}: {reasons:?}");
            assert_eq!(claims["disconnect_followup"]["verdict"], "pass");
            assert_eq!(claims["separate_walls"]["verdict"], "pass");
            assert_eq!(claims["separate_walls"]["mode"], mode);
        }
        server.join().expect("fixture server");
    }
}
