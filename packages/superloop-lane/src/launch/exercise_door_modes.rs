//! Read durable door-mode evidence from the run that the launcher recorded.

use std::path::Path;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;
use crate::requests::store::Store;

use super::{checkout, door_shape};

fn report(
    loop_name: &str,
    run: &str,
    case: &str,
    verdict: &str,
    reasons: &[String],
    evidence: &Value,
    changed: bool,
) -> Value {
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":case,
        "verdict":verdict,"reasons":reasons,"evidence":evidence,"changed":changed})
}

fn case_verdict(reasons: &[String], observed: bool, unmeasured: &[String]) -> &'static str {
    if reasons.is_empty() && unmeasured.is_empty() {
        "pass"
    } else if reasons.is_empty()
        || (!observed && reasons.len() == 1 && reasons[0].starts_with("no recorded"))
    {
        "unmeasured"
    } else {
        "fail"
    }
}

fn sequence_reasons(case: &str, records: &[Value], outcomes: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    let Some(outcomes) = outcomes.as_array() else {
        return vec!["fixture service outcomes are absent".into()];
    };
    for record in records {
        if (case == "door-audit" && record["mode"] != "audit")
            || (case == "door-allow" && record["mode"] != "allow")
            || (case == "door-enforce" && record["mode"] != "enforce")
        {
            continue;
        }
        let Some(outcome) = outcomes
            .iter()
            .find(|row| row["request_id"] == record["id"])
        else {
            reasons.push("fixture service outcome is absent".into());
            continue;
        };
        let observed = outcome["spawn_observations"].as_array();
        let decision = record["would_do"]["decision"].as_str().unwrap_or_default();
        let completed = record["effect"]["state"] == "completed";
        let refused = record["effect"]["state"] == "refused";
        let should_wait =
            case == "door-audit" || (case == "door-enforce" && decision == "undecided");
        if should_wait
            && completed
            && !observed.is_some_and(|rows| {
                rows.len() == 1
                    && rows[0]["state"] == "adjudicated"
                    && rows[0]["label"]["treatment"] == "allow"
            })
        {
            reasons.push("effect preceded its adjudicated answer".into());
        }
        if (case == "door-allow" || (case == "door-enforce" && decision != "undecided"))
            && completed
            && !observed.is_some_and(|rows| {
                rows.len() == 1
                    && rows[0]["label"].is_null()
                    && rows[0]["effect_state"] == "pending"
            })
        {
            reasons.push("immediate effect waited for an answer or lacked an intent".into());
        }
        if refused && observed.is_some_and(|rows| !rows.is_empty()) {
            reasons.push("refused request reached compute".into());
        }
        let queue = outcome["final"]["queue_state"].as_str().unwrap_or_default();
        if (case == "door-allow" || (case == "door-enforce" && decision != "undecided"))
            && queue != "no-queue"
        {
            reasons.push("immediate rubric route made a needless request wait".into());
        }
        if should_wait && completed && queue != "answered" {
            reasons.push("answer wait is absent from the final frame".into());
        }
    }
    reasons
}

/// Measure only requests filed by the registered service for one recorded run.
///
/// # Errors
///
/// Refuses a changed reservation, malformed recorded plan, or unsafe request custody.
#[allow(clippy::too_many_lines)]
pub(super) fn measure(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    case: &str,
) -> Result<Value, LaneError> {
    let mut stage = "preflight-settings";
    match measure_inner(owner_home, loop_name, run, case, &mut stage) {
        Err(error) if case == "door-agent" => Ok(json!({
            "schema":1,"command":"exercise","case":case,"loop":loop_name,"run":run,
            "verdict":if crate::door::exercise_admission_unmeasured(error.kind) { "unmeasured" } else { "fail" },"failed_stage":stage,"reasons":[error.line()],
            "observations":[],"runner_fixtures":[],"class":null,
            "real_runner":{"status":"unmeasured","reason":"not reached","agent_model":null,"agent_effort":null},
            "loop_mode_restored":{"status":"unknown"}
        })),
        result => result,
    }
}

#[allow(clippy::too_many_lines)]
fn measure_inner(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    case: &str,
    phase: &mut &'static str,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let settings = door_shape::settings(owner_home, loop_name)?;
    *phase = "preflight-reservation";
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door-mode", "runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let (reservation, _) = checkout::read_record_bound(&runs, run, owner)?;
    if reservation["loop"] != loop_name || reservation["run"] != run {
        return Err(LaneError::input(
            "exercise-door-mode",
            "reservation identity differs",
        ));
    }
    *phase = "preflight-plan";
    verify_box_attestation(&reservation["plan"])?;
    let reference = reservation["plan"]["door"]["mirror_ref"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-door-mode", "recorded mirror ref is absent"))?;
    let worker = reservation["worker_uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("exercise-door-mode", "recorded worker uid is absent"))?;
    let boundary_reasons = door_shape::recorded_boundary_reasons(
        &reservation["plan"],
        u32::try_from(worker).map_err(|_| {
            LaneError::input("exercise-door-mode", "recorded worker uid is invalid")
        })?,
        run,
    );
    if !boundary_reasons.is_empty() {
        if case == "door-agent" {
            return Err(LaneError::input(
                "exercise-door-mode",
                boundary_reasons.join("; "),
            ));
        }
        return Ok(report(
            loop_name,
            run,
            case,
            "fail",
            &boundary_reasons,
            &json!({"recorded_plan":reservation["plan"]["door"]}),
            false,
        ));
    }
    *phase = "preflight-registration";
    let row = crate::plan::registry(&settings, loop_name)?;
    let registration = super::door_registration_from_record(
        &row,
        loop_name,
        run,
        u32::try_from(worker).map_err(|_| {
            LaneError::input("exercise-door-mode", "recorded worker uid is invalid")
        })?,
        &reservation,
    )?;
    #[cfg(test)]
    let registration = if tests::fault_is("attribution") {
        let mut altered = registration;
        altered.mirror_ref.push_str("-other");
        altered
    } else {
        registration
    };
    *phase = "preflight-store";
    // Bound this measurement's store reads by the ordinary door request budget.
    let store = Store::open(owner_home, loop_name, false)?
        .with_reader_budget(std::time::Duration::from_secs(120));
    if case == "door-agent" {
        return Ok(crate::door::exercise_agent(owner_home, &registration));
    }
    let floor = store.floor().as_str();
    if (case == "door-allow" && floor != "allow") || (case == "door-enforce" && floor == "audit") {
        return Ok(report(
            loop_name,
            run,
            case,
            "unmeasured",
            &[format!("recorded door_floor={floor} does not admit {case}")],
            &json!({"recorded_plan":reservation["plan"]["door"],"door_floor":floor,
                "claims":{"mode_precondition":{"status":"unmeasured","floor":floor}}}),
            false,
        ));
    }
    let fixture = crate::door::exercise_mode_fixture(owner_home, &registration, case);
    let fixture = match fixture {
        Ok(fixture) => fixture,
        Err(error) => {
            return Ok(report(
                loop_name,
                run,
                case,
                if crate::door::exercise_admission_unmeasured(error.kind) {
                    "unmeasured"
                } else {
                    "fail"
                },
                &[error.line()],
                &json!({"recorded_plan":reservation["plan"]["door"],"fixture":"refused"}),
                true,
            ));
        }
    };
    if let Some(kind) = fixture["fixture_error_kind"].as_str() {
        let mut reasons = vec![fixture["fixture_error"].as_str().unwrap_or(kind).to_owned()];
        if fixture["claims"]["loop_restored"]["status"] != "pass" {
            reasons.push("loop-wide setting was not restored".into());
        }
        return Ok(report(
            loop_name,
            run,
            case,
            fixture_error_verdict(&fixture, kind),
            &reasons,
            &json!({"recorded_plan":reservation["plan"]["door"],"fixture":fixture}),
            true,
        ));
    }
    #[cfg(test)]
    let mut fixture = fixture;
    #[cfg(test)]
    tests::apply_case_fault(&store, owner_home, &mut fixture)?;
    let (records, shapes, stale) = store.list_with_status()?;
    let modes = store.modes()?;
    let class = fixture["class"].as_str().unwrap_or_default();
    let request_ids = fixture["request_ids"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-door-mode", "fixture request ids are absent"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::HashSet<_>>();
    let run_records = records
        .into_iter()
        .map(crate::requests::RequestRecord::into_value)
        .filter(|record| {
            record["run"] == run
                && record["id"]
                    .as_str()
                    .is_some_and(|id| request_ids.contains(id))
        })
        .collect::<Vec<_>>();
    let mut reasons = Vec::new();
    if request_ids.len() != run_records.len() {
        reasons.push("fixture request is absent from recorded custody".into());
    }
    if run_records.iter().any(|record| record["class"] != class) {
        reasons.push("fixture request class differs from the recorded service class".into());
    }
    if registration.mirror_ref != reference {
        reasons.push("row-derived ref differs from the recorded plan".into());
    }
    let (mode_reasons, observed) = match case {
        "door-audit" => audit(&run_records),
        "door-allow" => allow(&run_records),
        "door-enforce" => enforce(&run_records, &modes, class, &fixture["claims"]),
        _ => {
            return Err(LaneError::input(
                "exercise-door-mode",
                "door case is invalid",
            ));
        }
    };
    reasons.extend(mode_reasons);
    reasons.extend(sequence_reasons(case, &run_records, &fixture["outcomes"]));
    if fixture["claims"]["loop_restored"]["status"] != "pass" {
        reasons.push("loop-wide setting was not restored".into());
    }
    if stale {
        reasons.push("derived shape record is stale".into());
    }
    let unmeasured = fixture["claims"]
        .as_object()
        .into_iter()
        .flat_map(|claims| claims.iter())
        .filter(|(_, claim)| claim["status"] == "unmeasured")
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let verdict = case_verdict(&reasons, observed, &unmeasured);
    Ok(report(
        loop_name,
        run,
        case,
        verdict,
        &reasons,
        &json!({"recorded_plan":reservation["plan"]["door"],"worker_uid":worker,
            "mirror_ref":reference,"requests":run_records,"modes":modes,"shapes":shapes,
            "fixture":fixture,"claims":fixture["claims"],"unmeasured_claims":unmeasured,
            "socket_caller":"owner on private fixture socket",
            "authority":"recorded registration; caller attribution is measured by door-attribution",
            "shape_record":if stale {"stale"} else {"current"}}),
        true,
    ))
}

fn fixture_error_verdict(fixture: &Value, kind: &str) -> &'static str {
    let claims = &fixture["claims"];
    let failed = claims
        .as_object()
        .is_some_and(|rows| rows.values().any(|claim| claim["status"] == "fail"));
    if crate::door::exercise_admission_unmeasured(kind)
        && !failed
        && claims["loop_restored"]["status"] == "pass"
    {
        "unmeasured"
    } else {
        "fail"
    }
}

fn has_reason(record: &Value) -> bool {
    record["would_do"]["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty())
}

fn label_after_file(record: &Value) -> bool {
    record["filed_at"]
        .as_str()
        .zip(record["label"]["at"].as_str())
        .is_some_and(|(filed, label)| {
            filed
                .parse::<u128>()
                .ok()
                .zip(label.parse::<u128>().ok())
                .is_some_and(|(filed, label)| label > filed)
        })
}

pub(crate) fn audit(records: &[Value]) -> (Vec<String>, bool) {
    let rows = records
        .iter()
        .filter(|record| record["mode"] == "audit")
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return (vec!["no recorded audit door calls".into()], false);
    }
    let mut reasons = Vec::new();
    if rows.iter().any(|record| {
        record["effect"]["state"] == "completed" && record["label"]["treatment"] != "allow"
    }) {
        reasons.push("audit effect occurred before an adjudicated allowance".into());
    }
    if rows.iter().any(|record| record["state"] != "adjudicated") {
        reasons.push("audit request has no adjudicated answer".into());
    }
    let allowed = rows.iter().any(|record| {
        record["label"]["treatment"] == "allow"
            && record["effect"]["state"] == "completed"
            && has_reason(record)
            && label_after_file(record)
            && record["effect"]["queue_wall_seconds"]
                .as_f64()
                .is_some_and(|wall| wall > 0.0)
    });
    if !allowed {
        reasons.push("audit allowed request, would-do, label or effect is absent".into());
    }
    let corrected = rows.iter().any(|record| {
        record["would_do"]["decision"] == "allow"
            && record["label"]["treatment"] == "refuse"
            && has_reason(record)
            && record["effect"]["state"] == "refused"
            && record["effect"]["reason"] == "door-adjudicated-refusal"
            && label_after_file(record)
    });
    if !corrected {
        reasons.push("audit corrected refusal without an effect is absent".into());
    }
    (reasons, true)
}

pub(crate) fn allow(records: &[Value]) -> (Vec<String>, bool) {
    let rows = records
        .iter()
        .filter(|record| record["mode"] == "allow")
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return (vec!["no recorded allow door calls".into()], false);
    }
    let mut reasons = Vec::new();
    if rows
        .iter()
        .any(|record| record["floor"] != "allow" || record["class_setting"]["mode"] != "allow")
    {
        reasons.push("allow setting is below its recorded row floor".into());
    }
    if rows
        .iter()
        .any(|record| record["effect"]["queue_wall_seconds"] != Value::Null)
    {
        reasons.push("allow added a confirmation wait".into());
    }
    if rows
        .iter()
        .any(|record| record["effect"]["state"] == "pending")
    {
        reasons.push("allow effect is unrecorded".into());
    }
    let complete = rows.iter().any(|record| {
        record["effect"]["state"] == "completed"
            && record["state"] == "adjudicated"
            && has_reason(record)
            && label_after_file(record)
            && record["effect"]["queue_wall_seconds"] == Value::Null
            && record["class_setting"]["setter"].is_string()
            && record["class_setting"]["evidence"].is_string()
    });
    if !complete {
        reasons
            .push("allow immediate effect, later label or attributable setting is absent".into());
    }
    (reasons, true)
}

pub(crate) fn enforce(
    records: &[Value],
    modes: &Value,
    class_name: &str,
    claims: &Value,
) -> (Vec<String>, bool) {
    let rows = records
        .iter()
        .filter(|record| record["mode"] == "enforce")
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return (
            vec!["no recorded fixture-class enforce calls".into()],
            false,
        );
    }
    let mut reasons = Vec::new();
    if class_name != "fixture" && !class_name.starts_with("fixture-")
        || rows.iter().any(|record| record["class"] != class_name)
    {
        reasons.push("enforce case includes a production class".into());
    }
    if rows.iter().any(|record| {
        matches!(
            record["would_do"]["decision"].as_str(),
            Some("allow" | "refuse")
        ) && ((record["would_do"]["decision"] == "allow"
            && record["effect"]["state"] != "completed")
            || (record["would_do"]["decision"] == "refuse"
                && record["effect"]["state"] != "refused"))
    }) {
        reasons.push("enforce rubric produced the wrong effect".into());
    }
    if rows.iter().any(|record| {
        matches!(
            record["would_do"]["decision"].as_str(),
            Some("allow" | "refuse")
        ) && !record["effect"]["queue_wall_seconds"].is_null()
    }) {
        reasons.push("enforce rubric made a needless request wait".into());
    }
    for (decision, state, effect) in [
        ("allow", "observed", "completed"),
        ("refuse", "observed", "refused"),
        ("undecided", "adjudicated", "completed"),
    ] {
        if !rows.iter().any(|record| {
            record["would_do"]["decision"] == decision
                && record["state"] == state
                && record["effect"]["state"] == effect
                && has_reason(record)
        }) {
            reasons.push(format!("enforce {decision} rubric route is absent"));
        }
    }
    let class = modes["classes"]
        .as_array()
        .and_then(|classes| classes.iter().find(|row| row["class"] == class_name));
    let history = class.map(|row| &row["settings"]);
    if history.and_then(Value::as_array).is_none_or(|settings| {
        !settings.iter().any(|setting| setting["mode"] == "enforce")
            || !settings.last().is_some_and(|setting| {
                setting["mode"] == "audit" && setting["evidence"].is_string()
            })
    }) {
        reasons.push("enforce correction and reported return to audit are absent".into());
    }
    if claims["correction_report"]["status"] != "pass" {
        reasons.push("enforce correction and reported return to audit are absent".into());
    }
    if history.and_then(Value::as_array).is_none_or(|settings| {
        !settings
            .first()
            .is_some_and(|setting| setting["mode"] == "enforce" && setting["floor"] != "audit")
            && !settings.windows(2).any(|pair| {
                pair[0]["mode"] == "audit"
                    && pair[1]["mode"] == "enforce"
                    && pair[1]["citations"]
                        .as_array()
                        .is_some_and(|ids| !ids.is_empty())
            })
    }) {
        reasons.push("floor-compliant first enforce or cited audit move is absent".into());
    }
    if claims["allow_to_enforce"]["status"] == "pass"
        && history.and_then(Value::as_array).is_none_or(|settings| {
            !settings
                .windows(2)
                .any(|pair| pair[0]["mode"] == "allow" && pair[1]["mode"] == "enforce")
        })
    {
        reasons.push("stricter allow-to-enforce move is absent".into());
    }
    if claims["below_floor"]["status"] == "fail" {
        reasons.push("below-floor move was not refused".into());
    }
    (reasons, true)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use serde_json::{Value, json};

    use crate::error::LaneError;
    use crate::requests::store::{Store, tests::Fixture};

    std::thread_local! {
        static CASE_FAULT: RefCell<Option<&'static str>> = const { RefCell::new(None) };
    }

    fn with_case_fault<T>(fault: &'static str, f: impl FnOnce() -> T) -> T {
        CASE_FAULT.with(|selected| *selected.borrow_mut() = Some(fault));
        let result = f();
        CASE_FAULT.with(|selected| *selected.borrow_mut() = None);
        result
    }

    pub(super) fn fault_is(fault: &str) -> bool {
        CASE_FAULT.with(|selected| *selected.borrow() == Some(fault))
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn apply_case_fault(
        store: &Store,
        owner_home: &Path,
        fixture: &mut Value,
    ) -> Result<(), LaneError> {
        let Some(fault) = CASE_FAULT.with(|selected| selected.borrow_mut().take()) else {
            return Ok(());
        };
        if fault == "attribution" {
            return Ok(());
        }
        if fault == "seq-missing-outcomes-array" {
            fixture["outcomes"] = Value::Null;
            return Ok(());
        }
        if fault == "seq-missing-outcome" {
            fixture["outcomes"]
                .as_array_mut()
                .expect("outcomes")
                .remove(0);
            return Ok(());
        }
        if fault == "missing-request-ids" {
            fixture["request_ids"] = Value::Null;
            return Ok(());
        }
        if fault == "absent-custody-id" {
            fixture["request_ids"]
                .as_array_mut()
                .expect("request ids")
                .push(json!("R:fixture-absent"));
            return Ok(());
        }
        if fault == "changed-service-class" {
            fixture["class"] = json!("fixture-changed-class");
            return Ok(());
        }
        if fault == "no-observation" {
            fixture["request_ids"] = json!([]);
            fixture["outcomes"] = json!([]);
            return Ok(());
        }
        if fault == "enforce-correction-report" {
            fixture["claims"]["correction_report"]["status"] = json!("fail");
            return Ok(());
        }
        if matches!(
            fault,
            "enforce-first-setting" | "enforce-strict-move" | "enforce-correction-history"
        ) {
            let class = fixture["class"].as_str().unwrap_or_default().to_owned();
            return store.fixture_edit_modes(|modes| {
                let history = modes["classes"]
                    .as_array_mut()
                    .expect("class histories")
                    .iter_mut()
                    .find(|row| row["class"] == class)
                    .expect("fixture class");
                let settings = history["settings"].as_array_mut().expect("settings");
                match fault {
                    "enforce-first-setting" => settings[0]["mode"] = json!("audit"),
                    "enforce-strict-move" => {
                        let setting = settings
                            .iter_mut()
                            .find(|row| row["mode"] == "allow")
                            .expect("relaxed setting");
                        setting["mode"] = json!("enforce");
                    }
                    "enforce-correction-history" => {
                        settings.last_mut().expect("last setting")["mode"] = json!("enforce");
                    }
                    _ => unreachable!("matched fixture fault"),
                }
            });
        }
        if fault == "stale-shape" {
            let path = owner_home.join(".config/loops/alpha/door-shapes.json");
            fs::write(path, b"{}").map_err(|error| {
                LaneError::operation("exercise-door-fixture", error.to_string())
            })?;
            return Ok(());
        }
        if fault.starts_with("seq-") {
            let outcomes = fixture["outcomes"].as_array_mut().expect("outcomes");
            let row = match fault {
                "seq-audit-early" | "seq-missing-answer-frame" => outcomes
                    .iter_mut()
                    .find(|row| row["final"]["queue_state"] == "answered")
                    .expect("answered outcome"),
                "seq-immediate-late" | "seq-needless-wait" => outcomes
                    .iter_mut()
                    .find(|row| {
                        row["final"]["queue_state"] == "no-queue"
                            && row["spawn_observations"]
                                .as_array()
                                .is_some_and(|seen| !seen.is_empty())
                    })
                    .expect("immediate outcome"),
                "seq-refused-compute" => outcomes
                    .iter_mut()
                    .find(|row| row["final"]["queue_state"] == "refused")
                    .expect("refused outcome"),
                _ => panic!("unknown sequence fault: {fault}"),
            };
            match fault {
                "seq-audit-early" => row["spawn_observations"][0]["state"] = json!("waiting"),
                "seq-immediate-late" => {
                    row["spawn_observations"][0]["label"] = json!({"treatment":"allow"});
                }
                "seq-refused-compute" => row["spawn_observations"] = json!([{"state":"waiting"}]),
                "seq-needless-wait" => row["final"]["queue_state"] = json!("answered"),
                "seq-missing-answer-frame" => row["final"]["queue_state"] = json!("no-queue"),
                _ => unreachable!("matched sequence fault"),
            }
            return Ok(());
        }
        let ids = fixture["request_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        store.fixture_edit_run("R", |run| {
            let rows = run["requests"].as_array_mut().expect("fixture rows");
            if let Some(decision) = fault.strip_prefix("enforce-route-") {
                rows.retain(|row| {
                    !ids.iter().any(|id| row["id"] == *id)
                        || row["would_do"]["decision"] != decision
                });
                return;
            }
            let mut selected = rows
                .iter_mut()
                .filter(|row| {
                    row["id"]
                        .as_str()
                        .is_some_and(|id| ids.iter().any(|wanted| wanted == id))
                })
                .collect::<Vec<_>>();
            match fault {
                "audit-early" => {
                    selected[0]["state"] = json!("waiting");
                    selected[0]["label"] = Value::Null;
                    selected[0]["decision_tier"] = selected[0]["would_do_source"].clone();
                }
                "audit-answer" => {
                    selected[0]["state"] = json!("waiting");
                    selected[0]["label"] = Value::Null;
                    selected[0]["decision_tier"] = selected[0]["would_do_source"].clone();
                    selected[0]["effect"]["state"] = json!("pending");
                    selected[0]["effect"]["reason"] = Value::Null;
                    selected[0]["effect"]["ref_check"] = Value::Null;
                }
                "allow-wait" => {
                    let row = selected
                        .into_iter()
                        .find(|row| row["mode"] == "allow")
                        .expect("allow row");
                    row["effect"]["queue_wall_seconds"] = json!(0.5);
                }
                "allow-unrecorded" => {
                    let row = selected
                        .into_iter()
                        .find(|row| row["mode"] == "allow")
                        .expect("allow row");
                    row["effect"]["state"] = json!("pending");
                    row["effect"]["reason"] = Value::Null;
                    row["effect"]["ref_check"] = Value::Null;
                }
                "allow-label" => {
                    let row = selected
                        .into_iter()
                        .find(|row| row["mode"] == "allow")
                        .expect("allow row");
                    row["state"] = json!("waiting");
                    row["label"] = Value::Null;
                    row["decision_tier"] = row["would_do_source"].clone();
                }
                "enforce-wrong-effect" => {
                    let row = selected
                        .into_iter()
                        .find(|row| {
                            row["mode"] == "enforce" && row["would_do"]["decision"] == "allow"
                        })
                        .expect("decided allow");
                    row["effect"]["state"] = json!("refused");
                    row["effect"]["reason"] = json!("fixture-wrong-effect");
                }
                "enforce-needless-wait" => {
                    let row = selected
                        .into_iter()
                        .find(|row| {
                            row["mode"] == "enforce" && row["would_do"]["decision"] == "allow"
                        })
                        .expect("decided allow");
                    row["effect"]["queue_wall_seconds"] = json!(0.5);
                }
                "enforce-production-class" => {
                    let row = selected
                        .into_iter()
                        .find(|row| row["mode"] == "enforce")
                        .expect("enforce row");
                    row["class"] = json!("ssh");
                }
                _ => panic!("unknown fixture fault: {fault}"),
            }
        })
    }

    fn recorded_fixture(fixture: &Fixture, floor: &str) {
        recorded_fixture_with_boundary(fixture, floor, false);
    }

    fn recorded_fixture_with_boundary(fixture: &Fixture, floor: &str, changed: bool) {
        fixture.set_floor(floor);
        let config = fixture.home.join(".config/loops/alpha");
        let root = fixture.home.join("runs");
        let entry = config.join("entry-fixture");
        fs::write(
            &entry,
            crate::registry_fixture::script("printf '%s\\n' '{\"name\":\"alpha\",\"uid\":2001}'"),
        )
        .expect("entry fixture");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("entry mode");
        let settings = format!(
            "runs_root = \"{}\"\nentry_bin = \"{}\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
            root.display(),
            entry.display(),
            "a".repeat(64),
            fixture.home.join("template").display(),
            fixture.home.join("sockets").display(),
        );
        let settings_path = config.join("workers.toml");
        fs::write(&settings_path, settings).expect("fixture settings");
        fs::set_permissions(&settings_path, fs::Permissions::from_mode(0o600))
            .expect("settings mode");
        let route = json!({"schema":1,"loop":"alpha","alias":"fixture",
            "mirror_root":"~/mirrors","node_root":"/srv/loops/loop-a","key_path":config.join("door-key")});
        for (name, bytes) in [
            (
                "door-compute-registration.json",
                serde_json::to_vec(&route).expect("route bytes"),
            ),
            ("door-ssh_config", b"Host fixture\n".to_vec()),
        ] {
            let path = config.join(name);
            fs::write(&path, bytes).expect("route fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("route mode");
        }
        crate::door_node::fixture(&config);
        let mut plan: Value = serde_json::from_str(include_str!("../../tests/fixtures/plan.json"))
            .expect("fixture plan");
        let source = "~/sockets/door";
        let target = "/home/worker/.local/door";
        let mounts = plan["mounts"].as_array_mut().expect("mounts");
        let position = mounts
            .iter()
            .position(|mount| mount["target"] == "/etc/passwd")
            .expect("identity mount");
        mounts.insert(
            position,
            json!({"target":target,"source":source,
            "access":"ro","kind":"bind"}),
        );
        plan["mount_sources"]
            .as_array_mut()
            .expect("sources")
            .push(json!({"path":source,"uid":2001}));
        plan["door"] = json!({"schema":1,"socket":"/home/worker/.local/door/capability.sock",
            "stub":"/home/worker/.local/libexec/superloop/ssh",
            "stub_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "registered":["ssh"],"peer_uid":3000,"mirror_ref":"refs/heads/lane/R"});
        if changed {
            plan["door"]["registered"] = json!(["other"]);
        }
        let argv = plan["runtime_argv"].as_array_mut().expect("argv");
        let position = argv
            .iter()
            .position(|word| {
                word.as_str()
                    .is_some_and(|word| word.contains("dst=/etc/passwd"))
            })
            .expect("identity bind")
            - 1;
        argv.splice(
            position..position,
            [
                json!("--mount"),
                json!(format!("type=bind,src={source},dst={target},ro")),
            ],
        );
        plan["mount_inventory"] = crate::plan::mount_inventory(
            plan["mounts"].as_array().expect("mounts"),
            plan["paths"].as_array().expect("paths"),
            plan["mount_sources"].as_array().expect("sources"),
        )
        .expect("inventory");
        plan["door_floor"] = json!(floor);
        plan["box_gate"] = crate::plan::box_gate(&plan).expect("attested fixture");
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R",
            "worker_uid":3000,"door_scope":"work","plan":plan});
        crate::launch::publish_reservation(&crate::launch::reservation_path(&root, "R"), &record)
            .expect("recorded fixture run");
    }

    /// ´test:unit:door-mode-cases-read-recorded-run-through-service´
    #[test]
    fn door_mode_cases_read_recorded_run_through_service() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "allow");
        crate::door::with_fixture_cat_runner(|| {
            let audit =
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-audit")
                    .expect("audit case");
            assert_eq!(audit["verdict"], "pass", "{audit}");
            assert!(
                audit["evidence"]["requests"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 2)
            );
            let allow =
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-allow")
                    .expect("allow case");
            assert_eq!(allow["verdict"], "pass", "{allow}");
            assert_eq!(
                allow["evidence"]["fixture"]["claims"]["loop_restored"]["status"],
                "pass"
            );
            let enforce =
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-enforce")
                    .expect("enforce case");
            assert_eq!(enforce["verdict"], "unmeasured", "{enforce}");
            assert_eq!(
                enforce["evidence"]["claims"]["below_floor"]["status"],
                "unmeasured"
            );
            assert!(
                enforce["reasons"].as_array().is_some_and(Vec::is_empty),
                "{enforce}"
            );
        });
    }

    /// ´test:unit:door-agent-case-uses-production-handler-and-names-unmeasured-vendor´
    #[test]
    fn door_agent_case_uses_production_handler_and_names_unmeasured_vendor() {
        if std::env::var_os("SUPERLOOP_DOOR_AGENT_ENV_CASE").is_none() {
            let root = tempfile::TempDir::new_in("/tmp").expect("isolated caller");
            // Python -c otherwise imports this caller-controlled module before
            // the helper creates its private working directory.
            std::fs::write(
                root.path().join("tempfile.py"),
                "def mkdtemp(*args, **kwargs):\n    raise RuntimeError('inherited caller cwd')\n",
            )
            .expect("shadow module");
            let temporary = root.path().join("temporary");
            std::fs::create_dir(&temporary).expect("caller temporary directory");
            for exported in [false, true] {
                let mut command =
                    std::process::Command::new(std::env::current_exe().expect("test executable"));
                command
                    .args([
                        "--exact",
                        "launch::exercise::door_modes::tests::door_agent_case_uses_production_handler_and_names_unmeasured_vendor",
                    ])
                    .current_dir(root.path())
                    .env("HOME", root.path().join("absent-host-home"))
                    .env("SUPERLOOP_DOOR_AGENT_ENV_CASE", "1")
                    .env_remove("TMPDIR");
                if exported {
                    command.env("TMPDIR", &temporary);
                }
                let output = crate::fixture_exec::output(&mut command).expect("isolated case");
                assert!(
                    output.status.success(),
                    "TMPDIR exported={exported}: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            return;
        }
        let (fixture, _executables) = protected_agent_fixture();
        let report = crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-agent")
            .expect("agent case");
        assert_eq!(report["verdict"], "unmeasured", "{report}");
        assert_eq!(report["real_runner"]["status"], "unmeasured");
        assert!(
            report["real_runner"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("door.toml")),
            "{report}"
        );
        let rows = report["observations"].as_array().expect("observations");
        assert_eq!(rows.len(), 24);
        assert!(rows.iter().all(|row| row["status"] == "pass"), "{report}");
        let probes = report["runner_fixtures"]
            .as_array()
            .expect("runner observations");
        assert_eq!(probes.len(), 8);
        assert!(probes.iter().all(|row| row["status"] == "pass"), "{report}");
        let configuration = fixture.home.join(".config/loops/alpha/door.toml");
        std::fs::write(&configuration, "invalid = [").expect("invalid configuration");
        std::fs::set_permissions(
            &configuration,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("private configuration");
        let invalid = crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-agent")
            .expect("invalid configuration report");
        assert_eq!(invalid["real_runner"]["status"], "fail", "{invalid}");
        assert_eq!(invalid["verdict"], "fail");
    }

    fn agent_case(fixture: &Fixture, run: &str) -> Value {
        crate::launch::exercise::run_case(&fixture.home, "alpha", run, "door-agent")
            .expect("structured agent report")
    }

    fn second_agent_run(fixture: &Fixture) {
        let root = fixture.home.join("runs");
        let mut record: Value = serde_json::from_slice(
            &fs::read(crate::launch::reservation_path(&root, "R")).expect("first reservation"),
        )
        .expect("reservation JSON");
        let text = serde_json::to_string(&record)
            .expect("fixture JSON")
            .replace("3000", "3001")
            .replace("-R", "-S")
            .replace("/R", "/S")
            .replace("run=R", "run=S")
            .replace("\"R\"", "\"S\"");
        record = serde_json::from_str(&text).expect("second fixture JSON");
        record["plan"]["box_gate"] =
            crate::plan::box_gate(&record["plan"]).expect("second attestation");
        crate::launch::publish_reservation(&crate::launch::reservation_path(&root, "S"), &record)
            .expect("second reservation");
    }

    fn remove_agent_route(fixture: &Fixture) {
        fs::remove_file(
            fixture
                .home
                .join(".config/loops/alpha/door-compute-registration.json"),
        )
        .expect("unavailable fixture route");
    }

    /// ´test:unit:door-agent-early-failure-preserves-absent-and-allow-loop-history´
    #[test]
    fn door_agent_early_failure_preserves_absent_and_allow_loop_history() {
        use crate::requests::{Mode, modes::ModeTarget};
        for persisted in [false, true] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "allow");
            let store = fixture.store();
            if persisted {
                store
                    .set_mode(
                        &ModeTarget::Loop,
                        Mode::Allow,
                        "owner",
                        "prior allow",
                        "1",
                        &[],
                    )
                    .expect("prior loop");
            }
            remove_agent_route(&fixture);
            let report = agent_case(&fixture, "R");
            assert_eq!(report["verdict"], "fail", "{report}");
            assert_eq!(report["failed_stage"], "fixture-baseline");
            assert!(
                report["reasons"][0]
                    .as_str()
                    .expect("reason")
                    .starts_with("door-compute-registration:")
            );
            assert_eq!(
                report["loop_mode_restored"],
                json!({"status":"unchanged","mode":"allow"})
            );
            assert_eq!(report["observations"], json!([]));
            assert!(store.list_run("R").expect("no requests").is_empty());
            let modes = store.modes().expect("mode history");
            assert_eq!(modes["revision"], 3);
            let loop_history = modes["loop_settings"].as_array().expect("loop history");
            assert_eq!(loop_history.len(), 1);
            let first = &loop_history[0];
            assert_eq!(
                first,
                &json!({"mode":"allow","floor":"allow",
                "setter":if persisted {"owner"} else {"door-service"},
                "evidence":if persisted {"prior allow"} else {"row door_floor=allow initializes absent setting"},
                "set_at":first["set_at"],"revision":1,"citations":[]})
            );
            assert!(
                first["set_at"]
                    .as_str()
                    .expect("stamp")
                    .parse::<u128>()
                    .is_ok()
            );
            let class = &modes["classes"][0];
            assert_eq!(class["class"], report["class"]);
            assert_eq!(class["settings"][0]["mode"], "allow");
            assert_eq!(class["settings"][1]["mode"], "audit");
            assert_eq!(class["settings"][1]["revision"], 2);
        }
    }

    /// ´test:unit:door-agent-recovers-only-exercise-written-loop-revision´
    #[test]
    fn door_agent_recovers_only_exercise_written_loop_revision() {
        use crate::requests::{Mode, modes::ModeTarget};
        for setter in ["exercise-agent", "owner"] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "allow");
            let store = fixture.store();
            store
                .ensure_first_mode("fixture-saved")
                .expect("floor initialization");
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Audit,
                    setter,
                    "agent fixture ordering and restoration",
                    "2",
                    &[],
                )
                .expect("old audit");
            let before = store.modes().expect("before");
            remove_agent_route(&fixture);
            let report = agent_case(&fixture, "R");
            assert_eq!(report["failed_stage"], "fixture-baseline", "{report}");
            let after = store.modes().expect("after");
            let rows = after["loop_settings"].as_array().expect("history");
            assert_eq!(rows[0], before["loop_settings"][0]);
            assert_eq!(rows[1], before["loop_settings"][1]);
            if setter == "exercise-agent" {
                assert_eq!(rows.len(), 3);
                assert_eq!(
                    rows[2],
                    json!({"mode":"allow","floor":"allow",
                    "setter":"exercise-agent-restoration",
                    "evidence":"restore loop setting revision 1 after exercise-agent",
                    "set_at":rows[2]["set_at"],"revision":3,"citations":[]})
                );
                assert_eq!(report["loop_mode_restored"]["status"], "restored");
                assert_eq!(report["loop_mode_restored"]["restored_revision"], 1);
                let second = agent_case(&fixture, "R");
                assert_eq!(second["loop_mode_recovery"]["status"], "unchanged");
                assert_eq!(
                    store.modes().expect("again")["loop_settings"],
                    after["loop_settings"]
                );
            } else {
                assert_eq!(rows.len(), 2);
                assert_eq!(report["loop_mode_restored"]["mode"], "audit");
                assert_eq!(report["loop_mode_restored"]["status"], "unchanged");
            }
        }
    }

    fn assert_trailing_agent_history(prior: crate::requests::Mode, tail: &[(&str, bool)]) {
        use crate::requests::modes::ModeTarget;
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "allow");
        let store = fixture.store();
        store
            .set_mode(
                &ModeTarget::Loop,
                prior,
                "owner",
                "owner-held mode",
                "1",
                &[],
            )
            .expect("owner setting");
        // Seed historical rows, including the base exercise's cited transitions.
        store.fixture_edit_modes(|ledger| {
            let rows = ledger["loop_settings"].as_array_mut().expect("loop history");
            for (mode, cited) in tail {
                let revision = rows.len() + 1;
                rows.push(json!({"mode":mode,"floor":"allow","setter":"exercise-agent",
                    "evidence":"agent fixture ordering and restoration","set_at":revision.to_string(),
                    "revision":revision,"citations":if *cited {json!(["R:historical-allow"])} else {json!([])}}));
            }
            ledger["revision"] = json!(rows.len());
        }).expect("historical exercise rows");
        let before = store.modes().expect("before recovery");
        remove_agent_route(&fixture);
        let report = agent_case(&fixture, "R");
        assert_eq!(report["failed_stage"], "fixture-baseline", "{report}");
        let after = store.modes().expect("after recovery");
        let old = before["loop_settings"].as_array().expect("old rows");
        let rows = after["loop_settings"].as_array().expect("new rows");
        assert_eq!(&rows[..old.len()], old);
        let changed = old.last().expect("current")["mode"] != prior.as_str();
        assert_eq!(rows.len(), old.len() + usize::from(changed));
        assert_eq!(
            after["revision"],
            before["revision"].as_u64().expect("revision") + 2 + u64::from(changed)
        );
        let recovery = &report["loop_mode_recovery"];
        assert_eq!(
            recovery["status"],
            if changed { "restored" } else { "unchanged" }
        );
        assert_eq!(recovery["mode"], prior.as_str());
        assert_eq!(recovery["restored_revision"], 1);
        if changed {
            let restored = rows.last().expect("restoration row");
            assert_eq!(
                restored,
                &json!({"mode":prior.as_str(),"floor":"allow",
                "setter":"exercise-agent-restoration","evidence":"restore loop setting revision 1 after exercise-agent",
                "set_at":restored["set_at"],"revision":old.len()+1,"citations":[]})
            );
        }
        let again = agent_case(&fixture, "R");
        assert_eq!(again["loop_mode_recovery"]["status"], "unchanged");
        assert_eq!(again["loop_mode_recovery"]["restored_revision"], 1);
        assert_eq!(
            store.modes().expect("repeated recovery")["loop_settings"],
            after["loop_settings"]
        );
    }

    /// ´test:unit:door-agent-recovery-preserves-owner-audit-after-base-mode-resets´
    #[test]
    fn door_agent_recovery_preserves_owner_audit_after_base_mode_resets() {
        assert_trailing_agent_history(
            crate::requests::Mode::Audit,
            &[
                ("enforce", true),
                ("audit", false),
                ("allow", true),
                ("audit", false),
            ],
        );
    }

    /// ´test:unit:door-agent-recovery-preserves-completed-base-allow-restoration´
    #[test]
    fn door_agent_recovery_preserves_completed_base_allow_restoration() {
        assert_trailing_agent_history(
            crate::requests::Mode::Allow,
            &[
                ("audit", false),
                ("enforce", true),
                ("audit", false),
                ("allow", true),
                ("audit", false),
                ("allow", true),
            ],
        );
    }

    /// ´test:unit:door-agent-recovery-walks-both-relaxations-to-owner-audit´
    #[test]
    fn door_agent_recovery_walks_both_relaxations_to_owner_audit() {
        assert_trailing_agent_history(
            crate::requests::Mode::Audit,
            &[("enforce", true), ("allow", true)],
        );
    }

    /// ´test:unit:door-agent-recovery-refuses-floor-and-missing-predecessor´
    #[test]
    fn door_agent_recovery_refuses_floor_and_missing_predecessor() {
        use crate::requests::{Mode, modes::ModeTarget};
        for missing in [false, true] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "allow");
            let store = fixture.store();
            if !missing {
                store
                    .set_mode(&ModeTarget::Loop, Mode::Allow, "owner", "prior", "1", &[])
                    .expect("prior");
            }
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Audit,
                    "exercise-agent",
                    "old exercise",
                    "2",
                    &[],
                )
                .expect("audit");
            let before = store.modes().expect("before");
            if !missing {
                fixture.set_floor("enforce");
            }
            let report = agent_case(&fixture, "R");
            assert_eq!(report["failed_stage"], "recover-loop-mode", "{report}");
            assert_eq!(report["loop_mode_restored"]["status"], "failed");
            let reason = if missing {
                "door-mode-setting-refusal: exercise revision has no preceding loop setting"
            } else {
                "door-mode-floor-refusal: setting is less strict than the registry floor"
            };
            assert_eq!(report["reasons"], json!([reason]));
            assert_eq!(report["loop_mode_restored"]["reason"], reason);
            assert_eq!(store.modes().expect("after"), before);
        }
    }

    /// ´test:unit:door-agent-keeps-measurement-and-restoration-failures-with-attribution´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_agent_keeps_measurement_and_restoration_failures_with_attribution() {
        use crate::requests::{Mode, modes::ModeTarget};
        for fault in ["agent-after-relaxation", "agent-restoration"] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "allow");
            second_agent_run(&fixture);
            let store = fixture.store();
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Audit,
                    "owner",
                    "prior audit",
                    "1",
                    &[],
                )
                .expect("prior");
            for (run, worker) in [("R", 3000), ("S", 3001)] {
                let previous_rows = store.modes().expect("before run")["loop_settings"].clone();
                let report =
                    crate::door::with_fixture_helper_fault(fault, || agent_case(&fixture, run));
                assert_eq!(report["verdict"], "fail", "{report}");
                assert_eq!(report["failed_stage"], "class-mode");
                assert_eq!(
                    report["reasons"],
                    json!(["exercise-door-agent: fixture failure after relaxation"])
                );
                let restored = &report["loop_mode_restored"];
                assert_eq!(
                    restored["status"],
                    if fault == "agent-restoration" {
                        "failed"
                    } else {
                        "restored"
                    }
                );
                if fault == "agent-restoration" {
                    assert_eq!(
                        restored["reason"],
                        "door-mode-record-refusal: fixture mode write failure"
                    );
                } else {
                    assert_eq!(restored["setting"]["mode"], "audit");
                    assert_eq!(restored["setting"]["citations"], json!([]));
                    assert!(
                        restored["setting"]["evidence"]
                            .as_str()
                            .expect("restoration evidence")
                            .starts_with("restore loop setting revision ")
                    );
                }
                let observations = report["observations"]
                    .as_array()
                    .expect("completed observations");
                assert_eq!(observations.len(), 8);
                for row in observations {
                    assert_eq!(row["status"], "pass", "{row}");
                    assert_eq!(row["record"]["worker_uid"], worker);
                    assert_eq!(row["record"]["run"], run);
                    assert_eq!(row["transport"]["registered_worker_uid"], worker);
                    assert_eq!(
                        row["transport"]["socket_peer_uid"],
                        nix::unistd::Uid::effective().as_raw()
                    );
                }
                let history = store.modes().expect("history after run");
                let rows = history["loop_settings"].as_array().expect("loop rows");
                let previous_rows = previous_rows.as_array().expect("previous loop rows");
                assert_eq!(&rows[..previous_rows.len()], previous_rows);
                let failed_restore = fault == "agent-restoration";
                let expected_len = if run == "R" { 3 } else { 5 } - usize::from(failed_restore);
                assert_eq!(rows.len(), expected_len);
                for (index, row) in rows.iter().enumerate() {
                    assert_eq!(row["revision"], index + 1);
                    assert_eq!(
                        row["mode"],
                        if index % 2 == 0 { "audit" } else { "enforce" }
                    );
                    if index == 0 {
                        assert_eq!(row["setter"], "owner");
                        assert_eq!(row["evidence"], "prior audit");
                        assert_eq!(row["citations"], json!([]));
                    } else if index % 2 == 1 {
                        assert_eq!(row["setter"], "exercise-agent");
                        assert_eq!(row["evidence"], "agent fixture ordering and restoration");
                        let citations = row["citations"].as_array().expect("relaxation citations");
                        assert_eq!(citations.len(), 1);
                        let cited_run = if index == 1 { "R" } else { "S" };
                        let request = store
                            .request(citations[0].as_str().expect("citation"))
                            .expect("cited baseline");
                        assert_eq!(request.value()["run"], cited_run);
                        assert_eq!(request.value()["label"]["treatment"], "allow");
                    } else {
                        assert_eq!(row["setter"], "exercise-agent-restoration");
                        assert_eq!(row["citations"], json!([]));
                        let evidence = if failed_restore {
                            "restore loop setting revision 1 after exercise-agent".to_owned()
                        } else {
                            format!(
                                "restore loop setting revision {} after agent measurement",
                                index - 1
                            )
                        };
                        assert_eq!(row["evidence"], evidence);
                    }
                }
                if run == "S" {
                    assert_eq!(
                        report["loop_mode_recovery"]["status"],
                        if failed_restore {
                            "restored"
                        } else {
                            "unchanged"
                        }
                    );
                    assert_eq!(report["loop_mode_recovery"]["mode"], "audit");
                    assert_eq!(report["loop_mode_recovery"]["restored_revision"], 1);
                    if failed_restore {
                        assert_eq!(report["loop_mode_recovery"]["setting"], rows[2]);
                    }
                }
            }
        }
    }

    fn protected_agent_fixture() -> (Fixture, tempfile::TempDir) {
        // The child owns this root independently of its caller's cwd and TMPDIR.
        // Request writers sync while holding their per-home lock. Keep this small
        // store off shared disk I/O so polling readers do not time out on fsync.
        let temp = tempfile::tempdir_in("/dev/shm").expect("memory-backed door fixture");
        assert_eq!(
            nix::sys::statfs::statfs(temp.path())
                .expect("fixture filesystem")
                .filesystem_type()
                .0,
            nix::libc::TMPFS_MAGIC,
            "request fixture must use tmpfs"
        );
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture ancestor");
        let fixture = Fixture::with_temp(temp);
        // Publication walks .var even though no independent loop identity is
        // provisioned by this request/agent fixture.
        drop(fixture.snapshot_store());
        recorded_fixture(&fixture, "allow");
        // /dev/shm can be noexec. Keep only the stand-in entry on executable
        // storage, with real protected ancestors for the host-side runner.
        let executables = tempfile::tempdir_in("/tmp").expect("protected fixture programs");
        fs::set_permissions(executables.path(), fs::Permissions::from_mode(0o700))
            .expect("protected program ancestor");
        let config = fixture.home.join(".config/loops/alpha");
        let original = config.join("entry-fixture");
        let entry = executables.path().join("entry-fixture");
        crate::fixture_exec::write_executable(&entry, &fs::read(&original).expect("entry bytes"))
            .expect("executable entry");
        let settings = config.join("workers.toml");
        let text = fs::read_to_string(&settings).expect("settings").replace(
            &original.display().to_string(),
            &entry.display().to_string(),
        );
        fs::write(settings, text).expect("executable entry settings");
        fs::remove_file(original).expect("remove unused noexec entry");
        (fixture, executables)
    }

    fn configured_agent_fixture(canonical: bool) -> (Fixture, tempfile::TempDir) {
        let (fixture, executables) = protected_agent_fixture();
        let entry = executables.path().join("configured-entry");
        crate::fixture_exec::write_executable(&entry,
            b"#!/bin/sh\nif [ \"$1\" = show ]; then printf '%s\\n' '{\"name\":\"alpha\",\"uid\":2001}'; exit 0; fi\nexit 7\n")
            .expect("failing agent entry");
        let config = fixture.home.join(".config/loops/alpha");
        let settings = config.join("workers.toml");
        let text = fs::read_to_string(&settings).expect("settings").replace(
            &executables
                .path()
                .join("entry-fixture")
                .display()
                .to_string(),
            &entry.display().to_string(),
        );
        fs::write(settings, text).expect("configured entry");
        let door = config.join("door.toml");
        fs::write(&door, "rubric_root = '/fixture'\nexecutable = '/fixture/codex'\nmodel = 'fixture-model'\neffort = 'high'\n").expect("configuration");
        fs::set_permissions(door, fs::Permissions::from_mode(0o600))
            .expect("private configuration");
        if canonical {
            let lanes = config.join("lanes");
            let root = lanes.join("codex");
            fs::create_dir_all(&root).expect("canonical lock root");
            for path in [&lanes, &root] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .expect("canonical directory mode");
            }
            drop(crate::credential::try_lock(&fixture.home, "alpha").expect("canonical lock"));
        }
        (fixture, executables)
    }

    /// ´test:unit:door-agent-configured-call-refuses-absent-canonical-root´
    #[test]
    fn door_agent_configured_call_refuses_absent_canonical_root() {
        let (fixture, _executables) = configured_agent_fixture(false);
        let root = fixture.home.join(".config/loops/alpha/lanes/codex");
        assert!(!root.exists());
        let report = agent_case(&fixture, "R");
        assert_eq!(report["verdict"], "fail", "{report}");
        assert_eq!(report["failed_stage"], "real-runner-call", "{report}");
        assert_eq!(report["real_runner"]["reason"], "door-agent-refresh-lock");
        assert!(
            !root.exists(),
            "refusal must not prepare the canonical root"
        );
    }

    /// ´test:unit:door-agent-configured-call-failure-keeps-allow-and-effort´
    #[test]
    fn door_agent_configured_call_failure_keeps_allow_and_effort() {
        use crate::requests::{Mode, modes::ModeTarget};
        let (fixture, _executables) = configured_agent_fixture(true);
        let store = fixture.store();
        store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "owner",
                "prior allow",
                "1",
                &[],
            )
            .expect("prior");
        let before = store.modes().expect("before")["loop_settings"].clone();
        let report = agent_case(&fixture, "R");
        assert_eq!(report["verdict"], "fail", "{report}");
        assert_eq!(report["failed_stage"], "real-runner-call");
        assert_eq!(report["real_runner"]["reason"], "door-agent-call-failed");
        assert_eq!(report["real_runner"]["agent_effort"], "high");
        assert!(report["real_runner"]["agent_model"].is_null());
        assert_eq!(
            report["observations"]
                .as_array()
                .expect("observations")
                .len(),
            24
        );
        assert_eq!(
            report["loop_mode_restored"],
            json!({"status":"unchanged","mode":"allow"})
        );
        assert_eq!(store.modes().expect("after")["loop_settings"], before);
    }

    /// ´test:unit:door-agent-audit-loop-measures-all-modes-without-prior-labels´
    #[test]
    fn door_agent_audit_loop_measures_all_modes_without_prior_labels() {
        use crate::requests::{Mode, modes::ModeTarget};
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "allow");
        let store = fixture.store();
        store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Audit,
                "owner",
                "prior audit",
                "1",
                &[],
            )
            .expect("prior");
        assert!(store.list_run("R").expect("empty requests").is_empty());
        let report = agent_case(&fixture, "R");
        assert_eq!(report["verdict"], "unmeasured", "{report}");
        assert_eq!(
            report["observations"]
                .as_array()
                .expect("observations")
                .len(),
            24
        );
        assert_eq!(report["loop_mode_restored"]["status"], "restored");
        let modes = store.modes().expect("history");
        let rows = modes["loop_settings"].as_array().expect("loop settings");
        assert_eq!(rows.len(), 4);
        for (row, mode) in rows.iter().zip(["audit", "enforce", "allow", "audit"]) {
            assert_eq!(row["mode"], mode);
        }
        for row in &rows[1..3] {
            assert_eq!(row["setter"], "exercise-agent");
            assert_eq!(row["evidence"], "agent fixture ordering and restoration");
            let citations = row["citations"].as_array().expect("relaxation citations");
            assert_eq!(citations.len(), 1);
            let baseline = store
                .request(citations[0].as_str().expect("citation"))
                .expect("baseline request");
            assert_eq!(baseline.value()["run"], "R");
            assert_eq!(baseline.value()["class"], report["class"]);
            assert_eq!(baseline.value()["label"]["treatment"], "allow");
            assert_eq!(baseline.value()["would_do"]["decision"], "allow");
        }
        assert_eq!(
            rows[3],
            json!({"mode":"audit","floor":"allow","setter":"exercise-agent-restoration",
            "evidence":"restore loop setting revision 1 after agent measurement",
            "set_at":rows[3]["set_at"],"revision":4,"citations":[]})
        );
    }

    /// ´test:unit:door-agent-preflight-failure-is-a-case-report´
    #[test]
    fn door_agent_preflight_failure_is_a_case_report() {
        let fixture = Fixture::new();
        recorded_fixture_with_boundary(&fixture, "allow", true);
        let report = agent_case(&fixture, "R");
        assert_eq!(report["verdict"], "fail");
        assert_eq!(report["failed_stage"], "preflight-plan");
        assert_eq!(report["loop_mode_restored"]["status"], "unknown");
        assert_eq!(report["observations"], json!([]));
        assert_eq!(
            crate::launch::exercise::case_status(&report).expect("status"),
            1
        );
    }

    /// ´test:unit:door-mode-cases-name-measured-failures-on-recorded-run´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_mode_cases_name_measured_failures_on_recorded_run() {
        for (case, floor, fault, named) in [
            (
                "door-audit",
                "audit",
                "audit-early",
                "audit effect occurred before",
            ),
            (
                "door-audit",
                "audit",
                "audit-answer",
                "audit request has no adjudicated answer",
            ),
            (
                "door-allow",
                "allow",
                "allow-wait",
                "allow added a confirmation wait",
            ),
            (
                "door-allow",
                "allow",
                "allow-unrecorded",
                "allow effect is unrecorded",
            ),
            ("door-allow", "allow", "allow-label", "later label"),
            (
                "door-enforce",
                "allow",
                "enforce-wrong-effect",
                "wrong effect",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-needless-wait",
                "needless request",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-production-class",
                "production class",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-route-allow",
                "enforce allow rubric route is absent",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-route-refuse",
                "enforce refuse rubric route is absent",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-route-undecided",
                "enforce undecided rubric route is absent",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-first-setting",
                "floor-compliant first enforce",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-strict-move",
                "stricter allow-to-enforce move is absent",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-correction-history",
                "reported return to audit are absent",
            ),
            (
                "door-enforce",
                "allow",
                "enforce-correction-report",
                "reported return to audit are absent",
            ),
            (
                "door-enforce",
                "enforce",
                "below-floor-proof",
                "below-floor move was not refused",
            ),
            (
                "door-audit",
                "audit",
                "stale-shape",
                "derived shape record is stale",
            ),
        ] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, floor);
            let report = crate::door::with_fixture_cat_runner(|| {
                if fault == "below-floor-proof" {
                    crate::door::with_wrong_floor_probe(|| {
                        crate::launch::exercise::run_case(&fixture.home, "alpha", "R", case)
                    })
                } else {
                    with_case_fault(fault, || {
                        crate::launch::exercise::run_case(&fixture.home, "alpha", "R", case)
                    })
                }
            })
            .expect("recorded case");
            assert_eq!(report["verdict"], "fail", "{case} {fault}: {report}");
            assert!(
                report["reasons"].as_array().is_some_and(|reasons| reasons
                    .iter()
                    .any(|reason| reason.as_str().is_some_and(|reason| reason.contains(named)))),
                "{case} {fault}: {report}"
            );
        }
    }

    /// ´test:unit:door-mode-sequence-checks-refuse-each-broken-order´
    #[test]
    fn door_mode_sequence_checks_refuse_each_broken_order() {
        for (case, floor, fault, reason) in [
            (
                "door-audit",
                "audit",
                "seq-audit-early",
                "effect preceded its adjudicated answer",
            ),
            (
                "door-allow",
                "allow",
                "seq-immediate-late",
                "immediate effect waited for an answer or lacked an intent",
            ),
            (
                "door-audit",
                "audit",
                "seq-refused-compute",
                "refused request reached compute",
            ),
            (
                "door-allow",
                "allow",
                "seq-needless-wait",
                "immediate rubric route made a needless request wait",
            ),
            (
                "door-audit",
                "audit",
                "seq-missing-answer-frame",
                "answer wait is absent from the final frame",
            ),
            (
                "door-audit",
                "audit",
                "seq-missing-outcome",
                "fixture service outcome is absent",
            ),
            (
                "door-audit",
                "audit",
                "seq-missing-outcomes-array",
                "fixture service outcomes are absent",
            ),
        ] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, floor);
            let result = crate::door::with_fixture_cat_runner(|| {
                with_case_fault(fault, || {
                    crate::launch::exercise::run_case(&fixture.home, "alpha", "R", case)
                })
            })
            .expect("recorded case");
            assert_eq!(result["verdict"], "fail", "{fault}: {result}");
            assert!(
                result["reasons"]
                    .as_array()
                    .is_some_and(|reasons| reasons.iter().any(|row| row == reason)),
                "{fault}: {result}"
            );
        }
    }

    /// ´test:unit:door-mode-measure-refuses-missing-request-identity´
    #[test]
    fn door_mode_measure_refuses_missing_request_identity() {
        for (fault, expected, status) in [
            ("missing-request-ids", "fixture request ids are absent", 2),
            (
                "absent-custody-id",
                "fixture request is absent from recorded custody",
                0,
            ),
            (
                "changed-service-class",
                "fixture request class differs from the recorded service class",
                0,
            ),
        ] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "audit");
            let result = crate::door::with_fixture_cat_runner(|| {
                with_case_fault(fault, || {
                    crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-audit")
                })
            });
            if status == 2 {
                let error = result.expect_err("missing ids refusal");
                assert_eq!(error.status, status);
                assert!(error.detail.contains(expected));
            } else {
                let report = result.expect("measured failure");
                assert_eq!(report["verdict"], "fail", "{report}");
                assert!(
                    report["reasons"]
                        .as_array()
                        .is_some_and(|reasons| reasons.iter().any(|row| row == expected)),
                    "{fault}: {report}"
                );
            }
        }
    }

    /// ´test:unit:door-mode-admission-preserves-measured-failure´
    #[test]
    fn door_mode_admission_preserves_measured_failure() {
        let mut fixture = json!({"claims":{"loop_restored":{"status":"pass"}}});
        for kind in [
            "exercise-door-admission-unmeasured",
            "door-mode-floor-refusal",
        ] {
            assert_eq!(super::fixture_error_verdict(&fixture, kind), "unmeasured");
            fixture["claims"]["earlier"] = json!({"status":"fail"});
            assert_eq!(super::fixture_error_verdict(&fixture, kind), "fail");
            fixture["claims"]["earlier"]["status"] = json!("pass");
            for status in ["fail", "unmeasured"] {
                fixture["claims"]["loop_restored"]["status"] = json!(status);
                assert_eq!(super::fixture_error_verdict(&fixture, kind), "fail");
            }
            fixture["claims"]["loop_restored"]["status"] = json!("pass");
        }
    }

    /// # Panics
    /// Panics only if the isolated exercise loses a claim before a busy admission refusal.
    /// ´test:unit:door-enforce-retains-floor-claim-before-busy-admission´
    #[test]
    fn door_enforce_retains_floor_claim_before_busy_admission() {
        use std::os::unix::fs::OpenOptionsExt as _;
        for wrong_probe in [false, true] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "enforce");
            let file = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(
                    fixture
                        .home
                        .join(".config/loops/alpha/door-admission-3000.lock"),
                )
                .expect("admission file");
            let _held = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .expect("active box");
            let run =
                || crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-enforce");
            let report = crate::door::with_fixture_cat_runner(|| {
                if wrong_probe {
                    crate::door::with_wrong_floor_probe(run)
                } else {
                    run()
                }
            })
            .expect("busy enforce report");
            let evidence = &report["evidence"]["fixture"];
            assert_eq!(
                evidence["fixture_error_kind"],
                "exercise-door-admission-unmeasured"
            );
            assert_eq!(
                evidence["claims"]["below_floor"]["status"],
                if wrong_probe { "fail" } else { "pass" }
            );
            assert_eq!(evidence["claims"]["loop_restored"]["status"], "pass");
            assert_eq!(
                report["verdict"],
                if wrong_probe { "fail" } else { "unmeasured" },
                "{report}"
            );
            assert!(
                fixture
                    .store()
                    .list_run("R")
                    .expect("no request filed")
                    .is_empty()
            );
        }
    }

    /// ´test:unit:door-mode-restores-loop-after-fixture-refusal´
    #[test]
    fn door_mode_restores_loop_after_fixture_refusal() {
        let fixture = Fixture::new();
        fixture
            .store()
            .ensure_first_mode("fixture-audit-baseline")
            .expect("audit before floor change");
        recorded_fixture(&fixture, "allow");
        let report = crate::door::with_fixture_cat_runner(|| {
            crate::door::with_abort_after_relax(|| {
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-allow")
            })
        })
        .expect("failure report");
        assert_eq!(report["verdict"], "fail", "{report}");
        assert_eq!(
            report["evidence"]["fixture"]["claims"]["loop_restored"]["status"],
            "pass"
        );
        assert!(
            report["evidence"]["fixture"]["mode_moves"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["mode"] == "audit"))
        );
        let store = fixture.store();
        assert_eq!(
            store.modes().expect("restored modes")["loop_settings"]
                .as_array()
                .and_then(|rows| rows.last())
                .expect("last mode")["mode"],
            "audit"
        );
    }

    /// ´test:unit:door-mode-restore-write-failure-gates-verdict´
    #[test]
    fn door_mode_restore_write_failure_gates_verdict() {
        let fixture = Fixture::new();
        fixture
            .store()
            .ensure_first_mode("fixture-audit-baseline")
            .expect("audit before floor change");
        recorded_fixture(&fixture, "allow");
        let report = crate::door::with_fixture_cat_runner(|| {
            crate::door::with_abort_after_relax(|| {
                crate::door::with_restore_write_failure(|| {
                    crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-allow")
                })
            })
        })
        .expect("failed restore report");
        assert_eq!(report["verdict"], "fail", "{report}");
        let restoration = &report["evidence"]["fixture"]["claims"]["loop_restored"];
        assert_eq!(restoration["status"], "fail", "{report}");
        assert!(
            restoration["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("fixture mode write failure"))
        );
        assert!(report["reasons"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row == "loop-wide setting was not restored")
        }));
        let store = fixture.store();
        assert_eq!(
            store.modes().expect("relaxed modes")["loop_settings"]
                .as_array()
                .and_then(|rows| rows.last())
                .expect("last mode")["mode"],
            "allow"
        );
    }

    /// ´test:unit:door-mode-successful-fixture-restore-write-failure-gates-verdict´
    #[test]
    fn door_mode_successful_fixture_restore_write_failure_gates_verdict() {
        let fixture = Fixture::new();
        fixture
            .store()
            .ensure_first_mode("fixture-audit-baseline")
            .expect("audit before floor change");
        recorded_fixture(&fixture, "allow");
        let report = crate::door::with_fixture_cat_runner(|| {
            crate::door::with_restore_write_failure(|| {
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-allow")
            })
        })
        .expect("failed restore report");
        assert_eq!(report["verdict"], "fail", "{report}");
        let restoration = &report["evidence"]["fixture"]["claims"]["loop_restored"];
        assert_eq!(restoration["status"], "fail", "{report}");
        assert!(
            restoration["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("fixture mode write failure"))
        );
        assert!(report["reasons"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row == "loop-wide setting was not restored")
        }));
        assert_eq!(
            fixture.store().modes().expect("relaxed modes")["loop_settings"]
                .as_array()
                .and_then(|rows| rows.last())
                .expect("last mode")["mode"],
            "allow"
        );
    }

    /// ´test:unit:door-mode-recorded-boundary-and-floor-refusal-are-nonpass´
    #[test]
    fn door_mode_recorded_boundary_and_floor_refusal_are_nonpass() {
        {
            let changed = Fixture::new();
            recorded_fixture_with_boundary(&changed, "audit", true);
            let boundary =
                crate::launch::exercise::run_case(&changed.home, "alpha", "R", "door-audit")
                    .expect("recorded boundary report");
            assert_eq!(boundary["verdict"], "fail", "{boundary}");
            assert_eq!(boundary["changed"], false);
            assert!(boundary["reasons"].as_array().is_some_and(|rows| {
                rows.iter()
                    .any(|row| row.as_str().is_some_and(|text| text.contains("recorded")))
            }));
        }
        {
            let floor = Fixture::new();
            recorded_fixture(&floor, "audit");
            let refusal = crate::door::with_fixture_floor_refusal(|| {
                crate::launch::exercise::run_case(&floor.home, "alpha", "R", "door-audit")
            })
            .expect("floor report");
            assert_eq!(refusal["verdict"], "unmeasured", "{refusal}");
            assert!(
                refusal["reasons"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().any(|row| row
                        .as_str()
                        .is_some_and(|text| text.contains("door-mode-floor-refusal"))))
            );
        }
    }

    /// # Panics
    /// Panics only if busy box admission is reported as a measured exercise failure.
    /// ´test:unit:door-exercises-busy-admission-is-unmeasured´
    #[test]
    fn door_exercises_busy_admission_is_unmeasured() {
        use std::os::unix::fs::OpenOptionsExt as _;
        for case in ["door-agent", "door-audit", "door-allow", "door-enforce"] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture, "allow");
            let file = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(
                    fixture
                        .home
                        .join(".config/loops/alpha/door-admission-3000.lock"),
                )
                .expect("admission file");
            let _held = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .expect("active box");
            let started = std::time::Instant::now();
            let report = crate::door::with_fixture_cat_runner(|| {
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", case)
            })
            .expect("busy exercise report");
            assert!(
                started.elapsed() >= std::time::Duration::from_secs(2),
                "retry bound was not exercised"
            );
            assert_eq!(report["verdict"], "unmeasured", "{case}: {report}");
            assert!(
                report["reasons"]
                    .to_string()
                    .contains("exercise-door-admission-unmeasured"),
                "{report}"
            );
            assert!(
                fixture
                    .store()
                    .list_run("R")
                    .expect("no request filed")
                    .is_empty()
            );
        }
    }

    /// ´test:unit:door-mode-floor-precondition-is-unmeasured´
    #[test]
    fn door_mode_floor_precondition_is_unmeasured() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "audit");
        for case in ["door-allow", "door-enforce"] {
            let report = crate::door::with_fixture_cat_runner(|| {
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", case)
            })
            .expect("floor precondition");
            assert_eq!(report["verdict"], "unmeasured");
            assert_eq!(report["changed"], false);
            assert_eq!(report["evidence"]["door_floor"], "audit");
        }
    }

    /// ´test:unit:door-audit-unobserved-request-cannot-pass´
    #[test]
    fn door_audit_unobserved_request_cannot_pass() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "audit");
        let report = crate::door::with_fixture_cat_runner(|| {
            with_case_fault("no-observation", || {
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-audit")
            })
        })
        .expect("incomplete case");
        assert_eq!(report["verdict"], "unmeasured", "{report}");
        assert!(
            report["reasons"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row == "no recorded audit door calls"))
        );
    }

    /// ´test:unit:door-mode-case-refuses-missing-fixture-and-changed-attribution´
    #[test]
    fn door_mode_case_refuses_missing_fixture_and_changed_attribution() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "audit");
        let registration = crate::door::with_fixture_cat_runner(|| {
            with_case_fault("attribution", || {
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-audit")
            })
        })
        .expect("recorded attribution case");
        assert_eq!(registration["verdict"], "fail", "{registration}");
        assert!(registration["reasons"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row == "row-derived ref differs from the recorded plan")
        }));
        fs::remove_file(
            fixture
                .home
                .join(".config/loops/alpha/door-compute-registration.json"),
        )
        .expect("remove fixture route");
        let refused = crate::door::with_fixture_cat_runner(|| {
            crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-audit")
        })
        .expect("typed fixture refusal");
        assert_eq!(refused["verdict"], "fail", "{refused}");
        assert!(
            refused["reasons"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row
                    .as_str()
                    .is_some_and(|text| text.contains("door-compute-registration"))))
        );
    }

    /// ´test:unit:door-enforce-records-floor-refusal-at-enforce-floor´
    #[test]
    fn door_enforce_records_floor_refusal_at_enforce_floor() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "enforce");
        let report = crate::door::with_fixture_cat_runner(|| {
            crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-enforce")
        })
        .expect("enforce floor case");
        assert_eq!(report["verdict"], "unmeasured", "{report}");
        assert_eq!(
            report["evidence"]["claims"]["below_floor"]["status"],
            "pass"
        );
        assert_eq!(
            report["evidence"]["claims"]["below_floor"]["refusal"],
            "door-mode-floor-refusal"
        );
        assert_eq!(
            report["evidence"]["claims"]["below_floor"]["history_unchanged"],
            true
        );
        assert_eq!(
            report["evidence"]["claims"]["allow_to_enforce"]["status"],
            "unmeasured"
        );
        assert!(
            report["evidence"]["fixture"]["correction_reports"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["mode"] == "audit"))
        );
    }

    /// ´test:unit:door-enforce-two-floors-cover-each-recorded-claim´
    #[test]
    fn door_enforce_two_floors_cover_each_recorded_claim() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture, "enforce");
        crate::door::with_fixture_cat_runner(|| {
            let strict =
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-enforce")
                    .expect("strict-floor case");
            assert_eq!(
                strict["evidence"]["claims"]["below_floor"]["status"],
                "pass"
            );
            assert_eq!(
                strict["evidence"]["claims"]["allow_to_enforce"]["status"],
                "unmeasured"
            );
            fixture.set_floor("allow");
            let loose =
                crate::launch::exercise::run_case(&fixture.home, "alpha", "R", "door-enforce")
                    .expect("allow-floor case");
            assert_eq!(
                loose["evidence"]["claims"]["allow_to_enforce"]["status"],
                "pass"
            );
            assert_eq!(
                loose["evidence"]["claims"]["below_floor"]["status"],
                "unmeasured"
            );
            assert!(
                strict["reasons"].as_array().is_some_and(Vec::is_empty),
                "{strict}"
            );
            assert!(
                loose["reasons"].as_array().is_some_and(Vec::is_empty),
                "{loose}"
            );
            assert!(
                strict["evidence"]["requests"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
            );
            assert!(
                loose["evidence"]["requests"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
            );
        });
    }
}
