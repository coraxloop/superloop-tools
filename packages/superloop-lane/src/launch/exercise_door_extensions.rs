//! Measure every registered outward stub against the one recorded door socket.

use std::collections::BTreeSet;
use std::path::Path;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;

use super::checkout;

fn scope_reasons(document: &Value) -> (Vec<String>, Vec<Value>) {
    let door = &document["door"];
    let socket = door["socket"].as_str();
    let registered = door["registered"].as_array();
    let mut reasons = Vec::new();
    let mut scopes = Vec::new();
    let mut seen = BTreeSet::new();
    if socket != Some("/home/worker/.local/door/capability.sock") {
        reasons.push("registered door socket differs".into());
    }
    let entries = &document["mount_inventory"]["entries"];
    let door_mounts = entries.as_array().map(|rows| {
        rows.iter()
            .filter(|row| row["target"] == "/home/worker/.local/door")
            .collect::<Vec<_>>()
    });
    if door_mounts.as_ref().is_none_or(|rows| {
        rows.len() != 1 || rows[0]["source_role"] != "capability-door" || rows[0]["access"] != "ro"
    }) {
        reasons.push("one protected door mount is absent".into());
    }
    if !document["runtime_argv"]
        .as_array()
        .is_some_and(|argv| argv.iter().any(|word| word == "--network=none"))
    {
        reasons.push("box has an independent network route".into());
    }
    let Some(registered) = registered else {
        reasons.push("registered capability list is absent".into());
        return (reasons, scopes);
    };
    if registered.is_empty() || registered.len() > 16 {
        reasons.push("registered capability list is empty or over limit".into());
    }
    for name in registered {
        let Some(name) = name.as_str().filter(|name| {
            !name.is_empty()
                && name.len() <= 32
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        }) else {
            reasons.push("registered capability name is invalid".into());
            continue;
        };
        if !seen.insert(name) {
            reasons.push(format!("registered capability {name} repeats"));
            continue;
        }
        let (scope_socket, stub, scope) = if name == "ssh" {
            (
                socket,
                door["stub"].as_str(),
                Some("peer-bound work or review"),
            )
        } else {
            let registration = &door["extensions"][name];
            (
                registration["socket"].as_str(),
                registration["stub"].as_str(),
                registration["scope"].as_str(),
            )
        };
        if scope_socket != socket
            || stub.is_none_or(|path| {
                !path.starts_with("/home/worker/.local/libexec/superloop/") || path.contains("..")
            })
            || scope.is_none_or(str::is_empty)
        {
            reasons.push(format!("{name} has an independent or unrecorded route"));
        } else {
            scopes.push(json!({"capability":name,"socket":scope_socket,"stub":stub,"scope":scope}));
        }
    }
    if !seen.contains("ssh") {
        reasons.push("registered SSH stub is absent".into());
    }
    if door["extensions"]
        .as_object()
        .is_some_and(|rows| rows.keys().any(|name| !seen.contains(name.as_str())))
    {
        reasons.push("unregistered outward route is present".into());
    }
    (reasons, scopes)
}

fn report(loop_name: &str, run: &str, document: &Value, shape: &Value) -> Value {
    let (mut reasons, scopes) = scope_reasons(document);
    let shape_verdict = shape["verdict"].as_str();
    if shape_verdict == Some("fail") {
        reasons.push("registered SSH route or socket failed its box probe".into());
    } else if shape_verdict != Some("pass") {
        reasons.push("registered SSH route or socket is unmeasured".into());
    }
    let verdict = if reasons.iter().any(|reason| !reason.contains("unmeasured")) {
        "fail"
    } else if reasons.is_empty() {
        "pass"
    } else {
        "unmeasured"
    };
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,
        "case":"door-extensions","registered":document["door"]["registered"],
        "socket":document["door"]["socket"],"scopes":scopes,
        "door_shape":shape,"reasons":reasons,"verdict":verdict,"changed":false})
}

fn measure_with(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    shape_probe: impl FnOnce(&Path, &str, &str) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let settings = super::door_shape::settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door-extensions", "runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let (record, _identity) = checkout::read_record_bound(&runs, run, owner)?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-door-extensions",
            "reservation identity differs",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let shape = shape_probe(owner_home, loop_name, run)?;
    Ok(report(loop_name, run, document, &shape))
}

/// Measure the registered scopes and the shared socket of a recorded run.
///
/// # Errors
///
/// Refuses a missing or changed reservation before probing its box route.
pub(super) fn measure(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    measure_with(owner_home, loop_name, run, super::door_shape::measure)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use crate::launch::network_evidence::tests::recorded_fixture;
    use crate::requests::store::tests::Fixture;

    use super::{measure_with, report, scope_reasons};

    fn plan() -> serde_json::Value {
        json!({"door":{"socket":"/home/worker/.local/door/capability.sock",
            "stub":"/home/worker/.local/libexec/superloop/ssh","registered":["ssh"]},
            "runtime_argv":["/usr/bin/podman","--network=none"],
            "mount_inventory":{"entries":[{"target":"/home/worker/.local/door",
                "source_role":"capability-door","access":"ro"}]}})
    }

    /// ´test:unit:door-extensions-every-independent-route-refuses-by-name´
    #[test]
    fn door_extensions_every_independent_route_refuses_by_name() {
        let mut cases = Vec::new();
        let mut document = plan();
        document["door"]["socket"] = json!("/tmp/elsewhere.sock");
        cases.push((document, "registered door socket differs"));
        let mut document = plan();
        document["mount_inventory"]["entries"] = json!([]);
        cases.push((document, "one protected door mount is absent"));
        let mut document = plan();
        document["mount_inventory"]["entries"][0]["access"] = json!("rw");
        cases.push((document, "one protected door mount is absent"));
        let mut document = plan();
        document["runtime_argv"] = json!(["/usr/bin/podman"]);
        cases.push((document, "box has an independent network route"));
        let mut document = plan();
        document["door"]
            .as_object_mut()
            .expect("door")
            .remove("registered");
        cases.push((document, "registered capability list is absent"));
        let mut document = plan();
        document["door"]["registered"] = json!([]);
        cases.push((
            document,
            "registered capability list is empty or over limit",
        ));
        let mut document = plan();
        document["door"]["registered"] = json!([
            "ssh", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"
        ]);
        cases.push((
            document,
            "registered capability list is empty or over limit",
        ));
        let mut document = plan();
        document["door"]["registered"] = json!(["ssh", "BAD"]);
        cases.push((document, "registered capability name is invalid"));
        let mut document = plan();
        document["door"]["registered"] = json!(["ssh", "ssh"]);
        cases.push((document, "registered capability ssh repeats"));
        let mut document = plan();
        document["door"]["stub"] = json!("/tmp/ssh");
        cases.push((document, "ssh has an independent or unrecorded route"));
        let mut document = plan();
        document["door"]["registered"] = json!(["fetch"]);
        document["door"]["extensions"] = json!({"fetch":{"socket":"/home/worker/.local/door/capability.sock","stub":"/home/worker/.local/libexec/superloop/fetch","scope":"read"}});
        cases.push((document, "registered SSH stub is absent"));
        let mut document = plan();
        document["door"]["extensions"] = json!({"fetch":{"socket":"/tmp/elsewhere.sock"}});
        cases.push((document, "unregistered outward route is present"));
        for (document, expected) in cases {
            let (reasons, _) = scope_reasons(&document);
            assert!(
                reasons.iter().any(|reason| reason == expected),
                "{expected}: {reasons:?}"
            );
            let result = report("alpha", "R", &document, &json!({"verdict":"pass"}));
            assert_eq!(result["verdict"], "fail", "{expected}: {result}");
        }
        let mut document = plan();
        document["door"]["registered"] = json!(["ssh", "fetch"]);
        document["door"]["extensions"] = json!({"fetch":{"socket":"/home/worker/.local/door/capability.sock","stub":"/home/worker/.local/libexec/superloop/fetch","scope":""}});
        assert!(
            scope_reasons(&document)
                .0
                .iter()
                .any(|reason| reason == "fetch has an independent or unrecorded route")
        );
        let failed_shape = report("alpha", "R", &plan(), &json!({"verdict":"fail"}));
        assert_eq!(failed_shape["verdict"], "fail");
        assert!(
            failed_shape["reasons"]
                .to_string()
                .contains("failed its box probe")
        );
    }

    /// ´test:unit:door-extensions-initial-and-future-scopes-use-one-socket´
    #[test]
    fn door_extensions_initial_and_future_scopes_use_one_socket() {
        let mut document = plan();
        let passed = report("alpha", "R", &document, &json!({"verdict":"pass"}));
        assert_eq!(passed["verdict"], "pass");
        assert_eq!(passed["registered"], json!(["ssh"]));
        document["door"]["registered"] = json!(["ssh", "fetch"]);
        document["door"]["extensions"] = json!({"fetch":{
            "socket":"/home/worker/.local/door/capability.sock",
            "stub":"/home/worker/.local/libexec/superloop/fetch",
            "scope":"registered read"}});
        assert_eq!(scope_reasons(&document).0, Vec::<String>::new());
        assert_eq!(
            report("alpha", "R", &document, &json!({"verdict":"pass"}))["verdict"],
            "pass"
        );
        document["door"]["extensions"]["fetch"]["socket"] = json!("/tmp/other.sock");
        let failed = report("alpha", "R", &document, &json!({"verdict":"pass"}));
        assert_eq!(failed["verdict"], "fail");
        assert!(failed["reasons"].to_string().contains("independent"));
        assert_eq!(
            report("alpha", "R", &plan(), &json!({"verdict":"unmeasured"}))["verdict"],
            "unmeasured"
        );
    }

    /// ´test:unit:door-extensions-case-reads-recorded-run-and-box-reply´
    #[test]
    fn door_extensions_case_reads_recorded_run_and_box_reply() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        let reservation = crate::launch::reservation_path(&fixture.home.join("runs"), "R");
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&reservation).expect("reservation bytes"))
                .expect("reservation JSON");
        let plan = &mut record["plan"];
        plan["door"] = json!({"schema":1,
            "socket":"/home/worker/.local/door/capability.sock",
            "stub":"/home/worker/.local/libexec/superloop/ssh",
            "registered":["ssh"],"peer_uid":3000,"mirror_ref":"refs/heads/lane/R"});
        let source = "~/sockets/door";
        let target = "/home/worker/.local/door";
        let mounts = plan["mounts"].as_array_mut().expect("mounts");
        let position = mounts
            .iter()
            .position(|row| row["target"] == "/etc/passwd")
            .expect("identity mount");
        mounts.insert(
            position,
            json!({"target":target,"source":source,"access":"ro","kind":"bind"}),
        );
        plan["mount_sources"]
            .as_array_mut()
            .expect("sources")
            .push(json!({"path":source,"uid":2001}));
        let argv = plan["runtime_argv"].as_array_mut().expect("runtime");
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
        plan["box_gate"] = crate::plan::box_gate(plan).expect("attestation");
        crate::launch::publish_reservation(&reservation, &record).expect("door record");
        let passed = measure_with(&fixture.home, "alpha", "R", |_, _, _| {
            Ok(json!({"verdict":"pass","probe":{"stub_reason":"door-transport-pending"}}))
        })
        .expect("case");
        assert_eq!(passed["verdict"], "pass", "{passed}");
        assert_eq!(passed["registered"], json!(["ssh"]));
        record["plan"]["door"]["registered"] = json!(["ssh", "fetch"]);
        record["plan"]["door"]["extensions"] = json!({"fetch":{
            "socket":"/tmp/other.sock","stub":"/home/worker/.local/libexec/superloop/fetch",
            "scope":"registered read"}});
        crate::launch::publish_reservation(&reservation, &record).expect("changed route");
        let failed = measure_with(&fixture.home, "alpha", "R", |_, _, _| {
            Ok(json!({"verdict":"pass"}))
        })
        .expect("failed case");
        assert_eq!(failed["verdict"], "fail");
        assert!(failed["reasons"].to_string().contains("independent"));
    }
}
