//! Compare the recorded vendor grant with box routes and proxy refusals.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;
use crate::valid_run_name;

use super::{checkout, launch_environment, private_podman_environment};

const PROBE: &str = include_str!("exercise_network_probe.py");

fn incomplete(loop_name: &str, run: &str, reason: &str) -> Value {
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,
        "case":"network","verdict":"unmeasured","reasons":[reason],"changed":false})
}

fn private_report(
    loop_name: &str,
    run: &str,
    output: Result<String, LaneError>,
) -> Result<Value, LaneError> {
    match output {
        Ok(output) => serde_json::from_str::<Value>(&output).map_err(|error| {
            LaneError::input("exercise-network", format!("private report: {error}"))
        }),
        Err(error) => Ok(incomplete(loop_name, run, &error.line())),
    }
}

fn preflight_or_incomplete<T>(
    loop_name: &str,
    run: &str,
    result: Result<T, LaneError>,
) -> Result<T, Value> {
    result.map_err(|error| incomplete(loop_name, run, &error.line()))
}

fn box_report(
    loop_name: &str,
    run: &str,
    document: &Value,
    scope: &str,
    candidate: &str,
    output: Result<String, LaneError>,
    cleanup: Result<(), LaneError>,
) -> Result<Value, LaneError> {
    if let Err(error) = cleanup {
        return Ok(incomplete(loop_name, run, &error.line()));
    }
    let output = match output {
        Ok(output) => output,
        Err(error) => return Ok(incomplete(loop_name, run, &error.line())),
    };
    let probe: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-network", format!("box probe: {error}")))?;
    Ok(evaluate(loop_name, run, document, scope, candidate, &probe))
}

fn exact_hosts(value: &Value) -> Result<Vec<String>, LaneError> {
    let hosts = value.as_array().ok_or_else(|| {
        LaneError::input(
            "exercise-network-hosts",
            "recorded vendor host list is absent",
        )
    })?;
    let mut seen = BTreeSet::new();
    if hosts.is_empty() || hosts.len() > 128 {
        return Err(LaneError::input(
            "exercise-network-hosts",
            "recorded vendor host list is empty or over limit",
        ));
    }
    for host in hosts {
        let Some(host) = host.as_str() else {
            return Err(LaneError::input(
                "exercise-network-hosts",
                "recorded vendor host is not a name",
            ));
        };
        if !crate::vendor_net::exact_dns_host(host) || !seen.insert(host) {
            return Err(LaneError::input(
                "exercise-network-hosts",
                format!("recorded vendor host {host} is invalid or repeated"),
            ));
        }
    }
    Ok(seen.into_iter().map(str::to_owned).collect())
}

fn new_host(hosts: &[String]) -> Result<String, LaneError> {
    for index in 0..=128 {
        let candidate = format!("new-{index}.invalid");
        if !hosts.iter().any(|host| host == &candidate) {
            return Ok(candidate);
        }
    }
    Err(LaneError::input(
        "exercise-network-hosts",
        "no bounded unlisted canary host is available",
    ))
}

fn private_argv(
    loop_name: &str,
    run: &str,
    identity: &str,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-network".into(),
        loop_name.into(),
        run.into(),
        "--expect-record".into(),
        identity.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

/// Parse the one descriptor-bound private network form.
///
/// # Errors
///
/// Refuses malformed words or a path outside an absolute owner home.
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
            "exercise-network-form",
            "private network form is incomplete",
        ));
    };
    if command != "_exercise-network"
        || record_flag != "--expect-record"
        || home_flag != "--owner-home"
        || identity.is_empty()
        || !valid_run_name(run)
        || !Path::new(home).is_absolute()
    {
        return Err(LaneError::input(
            "exercise-network-form",
            "private network form is malformed",
        ));
    }
    Ok((loop_name, run, identity, Path::new(home)))
}

fn private_probe(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    root: &Path,
    runs: &std::os::fd::OwnedFd,
    identity: &str,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-network", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, owner)?;
    let podman = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman, owner)?;
    let mut argv = vec!["unshare".into(), exe_word];
    argv.extend(private_argv(loop_name, run, identity, owner_home)?);
    let output = build::run_checked_with_private_launch(
        podman,
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        90,
        "exercise-network",
        &home_fd,
        root,
        runs,
        None,
    );
    private_report(loop_name, run, output)
}

#[allow(clippy::too_many_lines)]
fn measure_with(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    probe: impl FnOnce(
        &Path,
        &str,
        &str,
        &Path,
        &std::os::fd::OwnedFd,
        &str,
    ) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let settings = super::door_shape::settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-network", "runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let (record, identity) = checkout::read_record_bound(&runs, run, owner)?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-network",
            "reservation identity differs",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let hosts = match exact_hosts(&document["vendor_hosts"]) {
        Ok(hosts) => hosts,
        Err(error) => return Ok(incomplete(loop_name, run, &error.line())),
    };
    let current = settings
        .vendor_hosts
        .get("codex")
        .cloned()
        .unwrap_or_default();
    let mut current_sorted = current.clone();
    current_sorted.sort();
    let pinned_match = hosts == current_sorted;
    let evidence = super::network_evidence::read(&runs, run, owner, loop_name, &hosts)?;
    let private = probe(owner_home, loop_name, run, root, &runs, &identity)?;
    if private["loop"] != loop_name || private["run"] != run || private["case"] != "network" {
        return Err(LaneError::input(
            "exercise-network",
            "private report identity differs",
        ));
    }
    let mut claims = private["claims"].clone();
    let start = evidence
        .as_ref()
        .and_then(|value| value["events"].as_array())
        .and_then(|events| events.first());
    let (transition_status, transition_detail, dns_status, dns_detail) = observed_claims(start);
    claims["list_change"] = claim(transition_status, &transition_detail);
    claims["dns_answers"] = claim(dns_status, &dns_detail);
    let mut reasons = private["reasons"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .filter(|reason| {
            !(transition_status == "pass" && reason.starts_with("new-host admission after"))
        })
        .filter(|reason| {
            !(dns_status == "pass" && reason.starts_with("private and reserved DNS answers need"))
        })
        .collect::<Vec<_>>();
    if !pinned_match {
        reasons.push("active vendor host list differs from the run's pinned list".into());
    }
    let lifecycle = evidence
        .as_ref()
        .and_then(|value| value["events"].as_array())
        .is_some_and(|events| events.len() == 3);
    if !lifecycle {
        reasons.push("host start, refresh and resume evidence is incomplete".into());
    }
    if transition_status == "fail" {
        reasons.push(transition_detail);
    }
    if dns_status == "fail" {
        reasons.push(dns_detail);
    }
    let claim_statuses = claims
        .as_object()
        .into_iter()
        .flat_map(|rows| rows.values())
        .filter_map(|row| row["status"].as_str())
        .collect::<Vec<_>>();
    let verdict =
        if !pinned_match || private["verdict"] == "fail" || claim_statuses.contains(&"fail") {
            "fail"
        } else if lifecycle
            && claim_statuses.len() == 6
            && claim_statuses.iter().all(|status| *status == "pass")
        {
            "pass"
        } else {
            "unmeasured"
        };
    let sources = evidence
        .as_ref()
        .and_then(|value| value["events"].as_array())
        .map(|events| {
            events
                .iter()
                .map(|event| event["source"].clone())
                .collect::<Vec<_>>()
        });
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,
        "case":"network","pinned_hosts":hosts,"active_hosts":current,
        "claims":claims,"box_probe":private["probe"],
        "host_lifecycle":if lifecycle {json!({"status":"attested","source":"owner host observation","event_sources":sources,"events":evidence.as_ref().map(|value| &value["events"])})} else {json!({"status":"unmeasured","events":evidence.as_ref().map(|value| &value["events"])})},
        "reasons":reasons,"verdict":verdict,"changed":false}),
    )
}

/// Measure the recorded network boundary through the real private box.
///
/// # Errors
///
/// Refuses a changed reservation or malformed private probe report.
pub(super) fn measure(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    measure_with(owner_home, loop_name, run, private_probe)
}

/// Probe the pinned network boundary inside the recorded box.
///
/// # Errors
///
/// Refuses a changed reservation, missing namespace or malformed box report.
pub fn private_measure(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    identity: &str,
) -> Result<Value, LaneError> {
    if !home::private_is_active() || !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-network",
            "bound private namespace is absent",
        ));
    }
    let settings = super::door_shape::settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-network", "runs root is absent"))?;
    let runs = home::pin_parent(root, 0)?;
    let (record, actual) = checkout::read_record_bound(&runs, run, 0)?;
    if actual != identity || record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-network",
            "reservation identity differs",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let hosts = exact_hosts(&document["vendor_hosts"])?;
    let candidate = new_host(&hosts)?;
    let mut argv = super::mounts::probe_vector_for(document, loop_name, run, "network", PROBE)?;
    let image = document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-network", "image digest is absent"))?;
    let position = argv
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("exercise-network", "image boundary is absent"))?;
    let scope = record["door_scope"].as_str().unwrap_or_default();
    argv.splice(
        position..position,
        [
            "-e".into(),
            format!("SUPERLOOP_NETWORK_NEW_HOST={candidate}"),
            "-e".into(),
            format!("SUPERLOOP_DOOR_SCOPE={scope}"),
        ],
    );
    let program = Path::new(
        argv.first()
            .ok_or_else(|| LaneError::input("exercise-network", "container program is absent"))?,
    );
    if let Err(report) =
        preflight_or_incomplete(loop_name, run, crate::pinned::owner_executable(program, 0))
    {
        return Ok(report);
    }
    let environment =
        match preflight_or_incomplete(loop_name, run, private_podman_environment(owner_home)) {
            Ok(value) => value,
            Err(report) => return Ok(report),
        };
    if let Err(report) = preflight_or_incomplete(
        loop_name,
        run,
        super::image_check_with_environment(program, image, owner_home, &environment),
    ) {
        return Ok(report);
    }
    let name = crate::launch::probe::name(&argv, &super::mounts::probe_name_prefix("network"))?;
    let output = build::run_checked(
        program,
        argv[1..].to_vec(),
        &environment,
        owner_home,
        60,
        "exercise-network-box",
    );
    let cleanup = crate::launch::probe::remove(
        program,
        owner_home,
        &environment,
        name,
        "network",
        loop_name,
        run,
    );
    box_report(loop_name, run, document, scope, &candidate, output, cleanup)
}

fn dns_answers() -> Vec<Value> {
    [
        "127.0.0.1",
        "10.0.0.1",
        "198.51.100.1",
        "::1",
        "fc00::1",
        "2001:db8::1",
    ]
    .into_iter()
    .map(|word| {
        let address = word.parse::<IpAddr>().expect("fixed DNS canary address");
        json!({"address":word,"refused":!crate::vendor_net::public_address(address)})
    })
    .collect()
}

fn claim(status: &str, detail: &str) -> Value {
    json!({"status":status,"detail":detail})
}

fn observed_claims(start: Option<&Value>) -> (&'static str, String, &'static str, String) {
    let Some(start) = start else {
        return (
            "unmeasured",
            "host-list transition is absent from protected observations".into(),
            "unmeasured",
            "DNS answer refusals are absent from protected observations".into(),
        );
    };
    let transition = &start["host_list_transition"];
    let (transition_status, transition_detail) = if transition.is_null() {
        (
            "unmeasured",
            "host-list transition is absent from protected observations".into(),
        )
    } else if transition["before_reply"] == "HTTP/1.1 403 Forbidden"
        && transition["after_reply"] == "HTTP/1.1 200 Connection Established"
    {
        (
            "pass",
            format!(
                "protected proxy observations from {} refused {} under the prior pin and admitted it after the reviewed list change",
                transition["source"].as_str().unwrap_or_default(),
                transition["host"].as_str().unwrap_or_default()
            ),
        )
    } else {
        ("fail", "proxy observations do not show refusal before and admission after the host-list change".into())
    };
    let checks = start["dns_answer_checks"].as_array();
    let expected = dns_answers()
        .into_iter()
        .filter_map(|row| row["address"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let seen = checks
        .into_iter()
        .flatten()
        .filter_map(|row| row["address"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let (dns_status, dns_detail) = if checks.is_none_or(Vec::is_empty) {
        (
            "unmeasured",
            "DNS answer refusals are absent from protected observations".into(),
        )
    } else if checks.is_some_and(|rows| {
        rows.iter()
            .any(|row| row["proxy_reply"] == "HTTP/1.1 200 Connection Established")
    }) {
        (
            "fail",
            "proxy admitted a private or reserved DNS answer".into(),
        )
    } else if seen == expected && checks.is_some_and(|rows| rows.len() == expected.len()) {
        (
            "pass",
            "protected proxy observations refused each private and reserved DNS answer".into(),
        )
    } else {
        (
            "unmeasured",
            "protected observations do not cover every private and reserved DNS answer".into(),
        )
    };
    (transition_status, transition_detail, dns_status, dns_detail)
}

#[allow(clippy::too_many_lines)]
fn evaluate(
    loop_name: &str,
    run: &str,
    document: &Value,
    scope: &str,
    candidate: &str,
    probe: &Value,
) -> Value {
    let mut reasons: Vec<String> = Vec::new();
    let pinned = exact_hosts(&document["vendor_hosts"]);
    let list_status = if pinned.is_ok() && !document["vendor_mode"].is_string() {
        "pass"
    } else if document["vendor_mode"].is_string() {
        reasons.push("run still uses an unenforced observing proxy".into());
        "fail"
    } else {
        reasons.push("recorded vendor host list is absent or invalid".into());
        "fail"
    };
    let change_status = "unmeasured";
    reasons.push("new-host admission after a reviewed list update needs a later host run".into());
    let proxy = &probe["proxy"];
    let proxy_replies = ["other_name", "new_host", "ip_literal"].map(|name| proxy[name].as_str());
    let proxy_status = if proxy_replies
        .iter()
        .all(|reply| *reply == Some("HTTP/1.1 403 Forbidden"))
    {
        "pass"
    } else if proxy_replies.contains(&Some("HTTP/1.1 200 Connection Established")) {
        reasons.push("vendor proxy admitted another name, new host or IP literal".into());
        "fail"
    } else if proxy_replies
        .iter()
        .any(|reply| reply.is_none_or(|line| line.is_empty() || line.starts_with("error:")))
    {
        reasons.push("vendor proxy did not answer a refusal probe".into());
        "unmeasured"
    } else {
        reasons.push("vendor proxy returned an unexpected refusal reply".into());
        "unmeasured"
    };
    let direct = [&probe["direct_ip"], &probe["direct_dns"]];
    let direct_status = if direct
        .iter()
        .all(|row| row["connected"] == false && row["error"].is_string())
    {
        "pass"
    } else if direct.iter().any(|row| row["connected"] == true) {
        reasons.push("direct IP or DNS egress bypass is present".into());
        "fail"
    } else {
        reasons.push("direct IP or DNS refusal is unmeasured".into());
        "unmeasured"
    };
    let answer_rows = dns_answers();
    let dns_status = "unmeasured";
    reasons.push("private and reserved DNS answers need the proxy unit fixture; the box cannot choose an answer".into());
    let review_status = if scope != "review" {
        reasons.push("review-lane compute refusal needs a recorded review scope".into());
        "unmeasured"
    } else if probe["review"]["status"] == 125
        && probe["review"]["reason"] == "door-review-compute-refusal"
    {
        "pass"
    } else if probe["review"]["status"] == 125
        && probe["review"]["reason"].as_str().is_some_and(|reason| {
            reason == "door-request-concurrent" || reason.starts_with("door-request-concurrent:")
        })
    {
        reasons.push(
            "door-request-concurrent: bounded admission retry exhausted; review refusal unmeasured"
                .into(),
        );
        "unmeasured"
    } else if probe["review"]["status"] == 0
        || (probe["review"]["status"].is_number() && probe["review"]["reason"].is_string())
    {
        reasons.push("door granted compute to review or returned a different refusal".into());
        "fail"
    } else {
        reasons.push("review-lane compute refusal is unmeasured".into());
        "unmeasured"
    };
    let statuses = [
        list_status,
        change_status,
        proxy_status,
        direct_status,
        dns_status,
        review_status,
    ];
    let verdict = if statuses.contains(&"fail") {
        "fail"
    } else if statuses.contains(&"unmeasured") {
        "unmeasured"
    } else {
        "pass"
    };
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"network",
        "pinned_hosts":document["vendor_hosts"],"new_host":candidate,
        "dns_policy_self_check":{"source":"vendor_net policy, not observed","rows":answer_rows},"probe":probe,
        "claims":{"pinned_list":claim(list_status,"recorded enforced host list"),
            "list_change":claim(change_status,"new-host admission after a reviewed host-list change needs a later host run"),
            "proxy_refusals":claim(proxy_status,"other name, new host and IP literal"),
            "direct_routes":claim(direct_status,"direct IP and DNS attempts from the box"),
            "dns_answers":claim(dns_status,"private and reserved DNS answers require the proxy unit fixture"),
            "review_compute":claim(review_status,"registered review peer's typed refusal")},
        "reasons":reasons,"verdict":verdict,"changed":false})
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use serde_json::json;

    use crate::launch::network_evidence::tests::{event, observed_start, recorded_fixture, submit};
    use crate::requests::store::tests::Fixture;

    use super::{
        PROBE, box_report, evaluate, exact_hosts, measure_with, new_host, parse_private_argv,
        preflight_or_incomplete, private_report,
    };

    /// ´test:unit:network-private-and-box-report-errors-remain-incomplete´
    #[test]
    fn network_private_and_box_report_errors_remain_incomplete() {
        let refusal = || crate::error::LaneError::input("fixture-network", "fixture route failed");
        let private = private_report("alpha", "R", Err(refusal())).expect("private incomplete");
        assert_eq!(private["verdict"], "unmeasured");
        assert!(
            private["reasons"]
                .to_string()
                .contains("fixture route failed")
        );
        assert!(
            private_report("alpha", "R", Ok("not JSON".into()))
                .expect_err("private JSON")
                .detail
                .contains("private report")
        );
        let output = serde_json::to_string(&probe()).expect("probe");
        for (result, cleanup) in [(Err(refusal()), Ok(())), (Ok(output), Err(refusal()))] {
            let report = box_report(
                "alpha",
                "R",
                &plan(),
                "review",
                "new-0-r.invalid",
                result,
                cleanup,
            )
            .expect("box incomplete");
            assert_eq!(report["verdict"], "unmeasured");
            assert!(
                report["reasons"]
                    .to_string()
                    .contains("fixture route failed")
            );
        }
        assert!(
            box_report(
                "alpha",
                "R",
                &plan(),
                "review",
                "new-0-r.invalid",
                Ok("not JSON".into()),
                Ok(())
            )
            .expect_err("box JSON")
            .detail
            .contains("box probe")
        );
        for stage in ["program", "environment", "image"] {
            let report = preflight_or_incomplete::<()>(
                "alpha",
                "R",
                Err(crate::error::LaneError::input("fixture-network", stage)),
            )
            .expect_err(stage);
            assert_eq!(report["verdict"], "unmeasured");
            assert!(report["reasons"].to_string().contains(stage));
        }
    }

    fn plan() -> serde_json::Value {
        json!({"vendor_hosts":["api.example.com"],"runtime_argv":["--network=none"]})
    }

    fn probe() -> serde_json::Value {
        json!({"direct_ip":{"connected":false,"error":"ENETUNREACH"},
            "direct_dns":{"connected":false,"error":"EAI_AGAIN"},
            "proxy":{"other_name":"HTTP/1.1 403 Forbidden",
                "new_host":"HTTP/1.1 403 Forbidden",
                "ip_literal":"HTTP/1.1 403 Forbidden"},
            "review":{"status":125,"reason":"door-review-compute-refusal"}})
    }

    /// ´test:unit:network-concurrent-admission-is-unmeasured´
    #[test]
    fn network_concurrent_admission_is_unmeasured() {
        let mut probe = probe();
        for reason in [
            "door-request-concurrent",
            "door-request-concurrent: publication window",
        ] {
            probe["review"]["reason"] = json!(reason);
            let report = evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &probe);
            assert_eq!(report["verdict"], "unmeasured");
            assert_eq!(report["claims"]["review_compute"]["status"], "unmeasured");
            assert!(
                report["reasons"]
                    .to_string()
                    .contains("door-request-concurrent")
            );
            assert!(
                !report["reasons"]
                    .to_string()
                    .contains("door granted compute")
            );
        }
        probe["review"]["status"] = json!(0);
        assert_eq!(
            evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &probe)["verdict"],
            "fail"
        );
        probe["review"]["status"] = json!(125);
        probe["direct_ip"]["connected"] = json!(true);
        assert_eq!(
            evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &probe)["verdict"],
            "fail"
        );
    }

    /// ´test:unit:network-comparison-names-every-egress-and-review-refusal´
    #[test]
    fn network_comparison_names_every_egress_and_review_refusal() {
        let clean = evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &probe());
        assert_eq!(clean["verdict"], "unmeasured", "{clean}");
        assert_eq!(clean["claims"]["list_change"]["status"], "unmeasured");
        assert_eq!(clean["claims"]["dns_answers"]["status"], "unmeasured");
        assert_eq!(
            clean["dns_policy_self_check"]["rows"]
                .as_array()
                .map(Vec::len),
            Some(6)
        );
        assert_eq!(
            clean["dns_policy_self_check"]["source"],
            "vendor_net policy, not observed"
        );
        let invalid = evaluate(
            "alpha",
            "R",
            &plan(),
            "review",
            "new_host.invalid",
            &probe(),
        );
        assert_eq!(invalid["claims"]["list_change"]["status"], "unmeasured");
        for (field, reason) in [
            ("other_name", "vendor proxy admitted"),
            ("new_host", "vendor proxy admitted"),
            ("ip_literal", "vendor proxy admitted"),
        ] {
            let mut changed = probe();
            changed["proxy"][field] = json!("HTTP/1.1 200 Connection Established");
            let report = evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed);
            assert_eq!(report["verdict"], "fail");
            assert!(report["reasons"].to_string().contains(reason));
        }
        let mut changed = probe();
        changed["direct_ip"]["connected"] = json!(true);
        assert_eq!(
            evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed)["verdict"],
            "fail"
        );
        let mut changed = probe();
        changed["direct_dns"]["connected"] = json!(true);
        assert_eq!(
            evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed)["verdict"],
            "fail"
        );
        let mut changed = probe();
        changed["review"]["reason"] = json!("door-complete");
        assert_eq!(
            evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed)["verdict"],
            "fail"
        );
        let mut changed = probe();
        changed["review"]["status"] = json!(0);
        changed["review"]["reason"] = serde_json::Value::Null;
        let granted = evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed);
        assert_eq!(granted["verdict"], "fail");
        assert!(granted["reasons"].to_string().contains("granted compute"));
        let mut changed = probe();
        changed["proxy"]["new_host"] = serde_json::Value::Null;
        assert_eq!(
            evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed)["verdict"],
            "unmeasured"
        );
        for reply in ["error:Connection refused", "", "HTTP/1.1 503 Unavailable"] {
            let mut changed = probe();
            changed["proxy"]["new_host"] = json!(reply);
            let report = evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &changed);
            assert_eq!(report["claims"]["proxy_refusals"]["status"], "unmeasured");
            assert!(!report["reasons"].to_string().contains("admitted"));
        }
        assert_eq!(
            evaluate("alpha", "R", &plan(), "work", "new-0-r.invalid", &probe())["verdict"],
            "unmeasured"
        );
        let mut observing = plan();
        observing["vendor_mode"] = json!("observing");
        let report = evaluate(
            "alpha",
            "R",
            &observing,
            "review",
            "new-0-r.invalid",
            &probe(),
        );
        assert_eq!(report["verdict"], "fail");
        assert!(
            report["reasons"]
                .to_string()
                .contains("unenforced observing proxy")
        );
    }

    /// ´test:unit:network-host-list-and-private-form-refuse-changed-inputs´
    #[test]
    fn network_host_list_and_private_form_refuse_changed_inputs() {
        for list in [
            json!([]),
            json!(["1.1.1.1"]),
            json!(["*.example.com"]),
            json!(["a.example", "a.example"]),
        ] {
            assert_eq!(
                exact_hosts(&list).expect_err("invalid host list").kind,
                "exercise-network-hosts"
            );
        }
        let list = exact_hosts(&json!(["api.example.com", "new-0.invalid"])).expect("hosts");
        assert_eq!(new_host(&list).expect("alternate"), "new-1.invalid");
        let full = (0..128)
            .map(|index| format!("new-{index}.invalid"))
            .collect::<Vec<_>>();
        assert_eq!(new_host(&full).expect("bounded spare"), "new-128.invalid");
        assert_eq!(
            parse_private_argv(&["_exercise-network".into()])
                .expect_err("short form")
                .kind,
            "exercise-network-form"
        );
        let valid = vec![
            "_exercise-network".into(),
            "alpha".into(),
            "R".into(),
            "--expect-record".into(),
            "identity".into(),
            "--owner-home".into(),
            "/home/owner".into(),
        ];
        for (index, value) in [
            (0, "wrong"),
            (2, "bad/run"),
            (3, "wrong"),
            (4, ""),
            (5, "wrong"),
            (6, "relative"),
        ] {
            let mut changed = valid.clone();
            changed[index] = value.into();
            assert_eq!(
                parse_private_argv(&changed)
                    .expect_err("malformed private form")
                    .kind,
                "exercise-network-form"
            );
        }
    }

    /// ´test:unit:network-case-binds-box-probe-to-recorded-host-phases´
    #[test]
    fn network_case_binds_box_probe_to_recorded_host_phases() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        let private = evaluate("alpha", "R", &plan(), "review", "new-0-r.invalid", &probe());
        let early = measure_with(&fixture.home, "alpha", "R", |_, _, _, _, _, _| {
            Ok(private.clone())
        })
        .expect("early report");
        assert_eq!(early["verdict"], "unmeasured", "{early}");
        assert_eq!(early["host_lifecycle"]["status"], "unmeasured");
        for (index, phase) in ["start", "refresh", "resume"].into_iter().enumerate() {
            submit(&fixture.home, &event(phase, index)).expect("phase");
        }
        let report = measure_with(&fixture.home, "alpha", "R", |_, _, _, _, _, _| {
            Ok(private.clone())
        })
        .expect("complete report");
        assert_eq!(report["verdict"], "unmeasured", "{report}");
        assert_eq!(report["pinned_hosts"], json!(["api.example.com"]));
        assert_eq!(report["host_lifecycle"]["status"], "attested");
        assert_eq!(
            report["host_lifecycle"]["event_sources"],
            json!(["journal-0", "journal-1", "journal-2"])
        );
        assert_eq!(report["claims"]["review_compute"]["status"], "pass");
        let mut failed = private;
        failed["verdict"] = json!("fail");
        failed["reasons"] = json!(["direct IP or DNS egress bypass is present"]);
        let report = measure_with(&fixture.home, "alpha", "R", |_, _, _, _, _, _| Ok(failed))
            .expect("failed report");
        assert_eq!(report["verdict"], "fail");
        assert!(report["reasons"].to_string().contains("bypass"));
        let wrong = measure_with(&fixture.home, "alpha", "R", |_, _, _, _, _, _| {
            Ok(json!({"case":"network","loop":"other","run":"R","verdict":"unmeasured"}))
        })
        .expect_err("private identity");
        assert!(wrong.detail.contains("private report identity differs"));
        let settings = fixture.home.join(".config/loops/alpha/workers.toml");
        let before = std::fs::read_to_string(&settings).expect("settings");
        std::fs::write(
            &settings,
            before.replace("api.example.com", "other.example.com"),
        )
        .expect("changed hosts");
        let report = measure_with(&fixture.home, "alpha", "R", |_, _, _, _, _, _| {
            Ok(evaluate(
                "alpha",
                "R",
                &plan(),
                "review",
                "new-0-r.invalid",
                &probe(),
            ))
        })
        .expect("active hosts");
        assert_eq!(report["verdict"], "fail");
        assert!(
            report["reasons"]
                .to_string()
                .contains("active vendor host list differs")
        );
    }

    /// ´test:unit:network-case-measures-recorded-proxy-transition-and-dns-answers´
    #[test]
    fn network_case_measures_recorded_proxy_transition_and_dns_answers() {
        for changed_kind in ["none", "transition", "dns", "partial-dns"] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture);
            let mut start = observed_start();
            if changed_kind == "transition" {
                start["host_list_transition"]["before_reply"] =
                    json!("HTTP/1.1 200 Connection Established");
            } else if changed_kind == "dns" {
                start["dns_answer_checks"][0]["proxy_reply"] =
                    json!("HTTP/1.1 200 Connection Established");
            } else if changed_kind == "partial-dns" {
                start["dns_answer_checks"]
                    .as_array_mut()
                    .expect("fixture DNS checks")
                    .truncate(3);
            }
            submit(&fixture.home, &start).expect("start");
            submit(&fixture.home, &event("refresh", 1)).expect("refresh");
            submit(&fixture.home, &event("resume", 2)).expect("resume");
            let report = measure_with(&fixture.home, "alpha", "R", |_, _, _, _, _, _| {
                Ok(evaluate(
                    "alpha",
                    "R",
                    &plan(),
                    "review",
                    "new-0-r.invalid",
                    &probe(),
                ))
            })
            .expect("case");
            let expected = match changed_kind {
                "none" => "pass",
                "partial-dns" => "unmeasured",
                _ => "fail",
            };
            assert_eq!(report["verdict"], expected, "{changed_kind}: {report}");
            assert_eq!(
                report["claims"]["list_change"]["status"],
                if changed_kind == "transition" {
                    "fail"
                } else {
                    "pass"
                }
            );
            assert_eq!(
                report["claims"]["dns_answers"]["status"],
                if changed_kind == "dns" {
                    "fail"
                } else if changed_kind == "partial-dns" {
                    "unmeasured"
                } else {
                    "pass"
                }
            );
            if changed_kind == "partial-dns" {
                assert_eq!(
                    report["claims"]["dns_answers"]["detail"],
                    "protected observations do not cover every private and reserved DNS answer"
                );
            }
        }
    }

    /// ´test:unit:network-python-probe-reads-fixture-socket-and-refused-direct-route´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn network_python_probe_reads_fixture_socket_and_refused_direct_route() {
        let fixture = tempfile::tempdir_in("/tmp").expect("probe fixture");
        let harness = r"
import ast, errno, os, socket, sys, threading
tree = ast.parse(sys.argv[1])
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {'direct', 'proxy_request'}]
scope = {'socket': socket, 'errno': errno}
exec(compile(ast.Module(body=functions, type_ignores=[]), '<probe>', 'exec'), scope)
path = os.path.join(sys.argv[2], 'proxy.sock')
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
def answer():
    peer, _ = server.accept()
    with peer:
        data = b''
        while not data.endswith(b'\r\n\r\n'):
            data += peer.recv(512)
        assert data == b'CONNECT new.example.invalid:443 HTTP/1.1\r\n\r\n'
        peer.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
thread = threading.Thread(target=answer)
thread.start()
assert scope['proxy_request']('new.example.invalid', path) == 'HTTP/1.1 403 Forbidden'
thread.join(timeout=3)
assert not thread.is_alive()
server.close()
os.unlink(path)
empty = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
empty.bind(path)
empty.listen(1)
def close_without_reply():
    peer, _ = empty.accept()
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        data += peer.recv(512)
    peer.close()
thread = threading.Thread(target=close_without_reply)
thread.start()
assert scope['proxy_request']('new.example.invalid', path) == ''
thread.join(timeout=3)
assert not thread.is_alive()
empty.close()
os.unlink(path)
try:
    scope['proxy_request']('new.example.invalid', path)
    assert False, 'missing socket must refuse'
except OSError:
    pass
old = socket.create_connection
def no_route(*_args, **_kwargs):
    raise OSError(errno.ENETUNREACH, 'no route')
socket.create_connection = no_route
try:
    assert scope['direct']('1.1.1.1') == {'connected': False, 'error': 'ENETUNREACH'}
finally:
    socket.create_connection = old

import types, json
clock = [0.0]
calls = []
replies = []
def sleep(seconds):
    clock[0] += seconds
def invoke(argv, **kwargs):
    calls.append((argv, kwargs))
    assert 0 < kwargs['timeout'] <= 10
    return types.SimpleNamespace(returncode=125, stdout=b'', stderr=replies[min(len(calls)-1, len(replies)-1)])
namespace = {'subprocess': types.SimpleNamespace(run=invoke, PIPE=-1),
             'time': types.SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep), 'json': json}
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'review_refusal']
exec(compile(ast.Module(body=functions, type_ignores=[]), '<probe>', 'exec'), namespace)
for busy in [b'door-request-concurrent', b'door-request-concurrent: publication window', json.dumps({'type':'final','reason':'door-request-concurrent'}).encode()]:
    for persistent in [False, True]:
        calls.clear()
        clock[0] = 0
        replies[:] = [busy] if persistent else [busy, json.dumps({'type':'final','reason':'door-review-compute-refusal'}).encode()]
        reply = namespace['review_refusal']()
        if persistent:
            assert 2 <= clock[0] < 2.1
            assert 40 <= len(calls) <= 42
            assert reply['reason'] == 'door-request-concurrent'
        else:
            assert len(calls) == 2
            assert reply['reason'] == 'door-review-compute-refusal'
    calls.clear()
    clock[0] = 0
    replies[:] = [json.dumps({'type':'final','reason':'door-other-refusal'}).encode()]
    namespace['review_refusal']()
    assert len(calls) == 1 and clock[0] == 0
";
        let output = Command::new("/usr/bin/python3")
            .args([
                "-c",
                harness,
                PROBE,
                fixture.path().to_str().expect("fixture path"),
            ])
            .output()
            .expect("Python fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
