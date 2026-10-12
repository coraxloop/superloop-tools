//! Host retirement bridge using the door's owner-private route and runner.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, Uid};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::transport::HostRunner;
pub use super::transport::Runner;
use crate::error::LaneError;

pub const NODE_SCRIPT: &str = include_str!("retire_node.py");
pub const DEADLINE: Duration = Duration::from_secs(120);
const OUTPUT_LIMIT: usize = 16_384;

pub struct Plan {
    pub value: Value,
    runner: Option<HostRunner>,
}

impl Plan {
    pub(crate) fn set_artifact_root(&mut self, root: &str) {
        if let Some(runner) = &mut self.runner {
            runner.set_retirement_root(root);
            self.value["route"]["node_root"] = json!(root);
            let run = self.value["run"].as_str().unwrap_or_default().to_owned();
            self.value["paths"][1] =
                json!(Path::new(root).join("lanes").join(format!("{run}-build")));
            self.value["paths"][2] =
                json!(Path::new(root).join("lanes").join(format!("{run}-tmp")));
        }
    }
}

pub fn digest(value: &Value) -> String {
    hash(value.to_string().as_bytes())
}

fn hash(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

pub fn plan(owner_home: &Path, loop_name: &str, run: &str) -> Plan {
    let config = owner_home.join(".config/loops").join(loop_name);
    let loaded = (|| {
        let owner = Uid::effective().as_raw();
        let directory = crate::pinned::open_protected(owner_home, &config, owner)?;
        match nix::sys::stat::fstatat(
            &directory,
            "door-compute-registration.json",
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => {
                return Err(LaneError::input(
                    "door-compute-registration",
                    error.to_string(),
                ));
            }
            Ok(_) => {}
        }
        let route = HostRunner::load(&directory, &config, loop_name, owner)?;
        let identity = route.retirement_route();
        Ok(Some((route, identity)))
    })();
    let mut value = json!({"schema":1,"loop":loop_name,"run":run,"deadline_seconds":120,
        "helper_sha256":hash(NODE_SCRIPT.as_bytes()),
        "policy":"host-completes-node-owed","route":null,"paths":null,"marker":null});
    let runner = match loaded {
        Ok(Some((route, identity))) => {
            let mirror = identity["mirror_root"].as_str().unwrap_or_default();
            let parent = Path::new(mirror).parent().unwrap_or_else(|| Path::new("~"));
            let lanes = parent.join("lanes");
            let artifacts =
                Path::new(identity["node_root"].as_str().unwrap_or_default()).join("lanes");
            value["route"] = identity;
            value["paths"] = json!([
                lanes.join(run),
                artifacts.join(format!("{run}-build")),
                artifacts.join(format!("{run}-tmp")),
                lanes.join(format!("{run}.lock"))
            ]);
            value["marker"] = json!(lanes.join(format!("{run}.retired")));
            value["reason"] = json!("node-retirement-pending");
            Some(route)
        }
        Ok(None) => {
            value["reason"] = json!("node-retirement-no-registration");
            None
        }
        Err(error) => {
            value["reason"] = json!("node-retirement-registration-refusal");
            value["detail"] = json!(error.line());
            None
        }
    };
    Plan { value, runner }
}

fn stop(child: &mut Child, group: bool) {
    if group && let Ok(pid) = i32::try_from(child.id()) {
        let _killed = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _killed = child.kill();
    let _waited = child.wait();
}

fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> io::Result<bool> {
    let mut chunk = [0; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + count > OUTPUT_LIMIT {
                    return Err(io::Error::other("node retirement output exceeds bound"));
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn capture(child: &mut Child, deadline: Instant) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    drop(child.stdin.take());
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout absent"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr absent"))?;
    for fd in [
        &stdout as &dyn std::os::fd::AsFd,
        &stderr as &dyn std::os::fd::AsFd,
    ] {
        let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
        fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "node retirement deadline",
            ));
        }
        let out_done = drain(&mut stdout, &mut out)?;
        let err_done = drain(&mut stderr, &mut err)?;
        if let Some(status) = child.try_wait()?
            && out_done
            && err_done
        {
            return Ok((status, out, err));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn valid_listing(value: &Value, paths: &Value) -> bool {
    let (Some(rows), Some(paths)) = (value.as_array(), paths.as_array()) else {
        return false;
    };
    let prefix = rows
        .first()
        .and_then(|row| row["path"].as_str())
        .zip(paths.first().and_then(Value::as_str))
        .and_then(|(actual, expected)| actual.strip_suffix(expected.trim_start_matches('~')));
    rows.len() == 4
        && paths.len() == 4
        && prefix.is_some()
        && rows.iter().zip(paths).all(|(row, path)| {
            row.as_object().is_some_and(|object| object.len() == 4)
                && row["path"]
                    .as_str()
                    .zip(path.as_str())
                    .is_some_and(|(actual, expected)| {
                        actual.starts_with('/')
                            && !actual.split('/').any(|p| p == ".." || p == ".")
                            && if expected.starts_with('/') {
                                actual == expected
                            } else {
                                actual.strip_suffix(expected.trim_start_matches('~')) == prefix
                            }
                    })
                && row["exists"].as_bool().is_some()
                && row["entries"].as_u64().is_some()
                && row["bytes"].as_u64().is_some()
                && if row["exists"] == true {
                    row["entries"].as_u64().is_some_and(|entries| entries > 0)
                } else {
                    row["entries"] == 0 && row["bytes"] == 0
                }
        })
}

fn evidence(bytes: &[u8], status: ExitStatus, plan: &Value) -> Option<Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    let value: Value =
        serde_json::from_str(lines.next()?.strip_prefix("NODE-RETIREMENT ")?).ok()?;
    (lines.next().is_none() && valid_evidence(&value, status.code().map(i64::from), plan))
        .then_some(value)
}

fn valid_evidence(value: &Value, exit: Option<i64>, plan: &Value) -> bool {
    checked_evidence(value, exit, plan).is_some()
}

fn checked_evidence(value: &Value, exit: Option<i64>, plan: &Value) -> Option<()> {
    let keys = [
        "schema",
        "run",
        "loop",
        "before",
        "after",
        "bytes_freed",
        "wall_seconds",
        "helper_exit",
        "reason",
        "marker",
    ];
    if value.as_object().is_none_or(|object| {
        keys.iter().any(|key| !object.contains_key(*key))
            || object
                .keys()
                .any(|key| !keys.contains(&key.as_str()) && key != "error")
    }) || value
        .get("error")
        .is_some_and(|error| error.as_str().is_none_or(|error| error.len() > 4096))
        || value["schema"] != 1
        || value["run"] != plan["run"]
        || value["loop"] != plan["loop"]
        || value["helper_exit"].as_i64() != exit
        || !value["marker"].is_boolean()
        || !value["wall_seconds"]
            .as_f64()
            .is_some_and(|wall| wall.is_finite() && wall >= 0.0)
        || ![
            "node-retirement-complete",
            "node-retirement-removal-failed",
            "node-retirement-deadline",
        ]
        .contains(&value["reason"].as_str()?)
    {
        return None;
    }
    for key in ["before", "after"] {
        if !value[key].is_null() && !valid_listing(&value[key], &plan["paths"]) {
            return None;
        }
    }
    let expected = match value["reason"].as_str()? {
        "node-retirement-complete" => 0,
        "node-retirement-deadline" => 124,
        _ => 125,
    };
    if exit != Some(expected) {
        return None;
    }
    if value["reason"] == "node-retirement-complete"
        && (value["marker"] != true
            || !valid_listing(&value["before"], &plan["paths"])
            || !valid_listing(&value["after"], &plan["paths"])
            || value["after"]
                .as_array()?
                .iter()
                .any(|row| row["exists"] != false))
    {
        return None;
    }
    if let (Some(before), Some(after)) = (value["before"].as_array(), value["after"].as_array()) {
        if before
            .iter()
            .zip(after)
            .any(|(before, after)| before["path"] != after["path"])
        {
            return None;
        }
        let sum = |rows: &[Value]| {
            rows.iter().try_fold(0_u64, |total, row| {
                total.checked_add(row["bytes"].as_u64()?)
            })
        };
        if value["bytes_freed"].as_u64()? != sum(before)?.saturating_sub(sum(after)?) {
            return None;
        }
    } else if !value["bytes_freed"].is_null() {
        return None;
    }
    Some(())
}

pub fn valid_plan(value: &Value) -> bool {
    let keys = [
        "schema",
        "loop",
        "run",
        "deadline_seconds",
        "helper_sha256",
        "policy",
        "route",
        "paths",
        "marker",
        "reason",
    ];
    if value.as_object().is_none_or(|object| {
        keys.iter().any(|key| !object.contains_key(*key))
            || object
                .keys()
                .any(|key| !keys.contains(&key.as_str()) && key != "detail")
    }) || value["schema"] != 1
        || value["deadline_seconds"] != 120
        || value["policy"] != "host-completes-node-owed"
        || !value["run"].as_str().is_some_and(crate::valid_run_name)
        || value["loop"]
            .as_str()
            .is_none_or(|name| loop_home::validate_name(name).is_err())
        || !hex_digest(&value["helper_sha256"])
        || value
            .get("detail")
            .is_some_and(|detail| !detail.is_string())
    {
        return false;
    }
    if value["route"].is_null() {
        return value["paths"].is_null()
            && value["marker"].is_null()
            && matches!(
                value["reason"].as_str(),
                Some("node-retirement-no-registration" | "node-retirement-registration-refusal")
            );
    }
    let route = &value["route"];
    if route.as_object().is_none_or(|object| object.len() != 5)
        || !["alias", "mirror_root", "key_path", "node_root"]
            .iter()
            .all(|key| route[*key].as_str().is_some_and(|word| !word.is_empty()))
        || !route["node_root"].as_str().is_some_and(|root| {
            Path::new(root).is_absolute()
                || (root == "~" || root.starts_with("~/"))
                    && Path::new(route["mirror_root"].as_str().unwrap_or_default()).parent()
                        == Some(Path::new(root))
        })
        || !hex_digest(&route["ssh_config_sha256"])
        || value["reason"] != "node-retirement-pending"
    {
        return false;
    }
    let mirror = Path::new(route["mirror_root"].as_str().unwrap_or_default());
    let lanes = mirror
        .parent()
        .unwrap_or_else(|| Path::new("~"))
        .join("lanes");
    let artifacts = Path::new(route["node_root"].as_str().unwrap_or_default()).join("lanes");
    let run = value["run"].as_str().unwrap_or_default();
    value["paths"]
        == json!([
            lanes.join(run),
            artifacts.join(format!("{run}-build")),
            artifacts.join(format!("{run}-tmp")),
            lanes.join(format!("{run}.lock"))
        ])
        && value["marker"] == json!(lanes.join(format!("{run}.retired")))
}

fn hex_digest(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|word| word.len() == 64 && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn valid_outcome(value: &Value, plan: &Value) -> bool {
    let untimed = value["remote_completion"] == "unknown"
        && matches!(
            value["reason"].as_str(),
            Some(
                "node-retirement-pending"
                    | "node-retirement-in-progress"
                    | "node-retirement-no-registration"
                    | "node-retirement-registration-refusal"
                    | "node-retirement-route-changed"
            )
        );
    let keys = [
        "state",
        "reason",
        "owed",
        "host_wall_seconds",
        "helper_exit",
        "remote_completion",
        "evidence",
    ];
    if value.as_object().is_none_or(|object| {
        keys.iter().any(|key| !object.contains_key(*key))
            || object.keys().any(|key| {
                !keys.contains(&key.as_str()) && key != "detail" && key != "transport_exit"
            })
    }) || !(value["host_wall_seconds"].is_null() && untimed
        || value["host_wall_seconds"]
            .as_f64()
            .is_some_and(|wall| wall.is_finite() && wall >= 0.0))
        || value
            .get("detail")
            .is_some_and(|detail| !detail.is_string())
        || value
            .get("transport_exit")
            .is_some_and(|exit| !exit.is_null() && exit.as_i64().is_none())
    {
        return false;
    }
    if value["remote_completion"] == "measured" {
        let complete = value["reason"] == "node-retirement-complete";
        return value["state"] == if complete { "complete" } else { "incomplete" }
            && !plan["route"].is_null()
            && value["owed"] == !complete
            && value["reason"] == value["evidence"]["reason"]
            && valid_evidence(&value["evidence"], value["helper_exit"].as_i64(), plan);
    }
    value["remote_completion"] == "unknown"
        && if matches!(
            value["reason"].as_str(),
            Some("node-retirement-no-registration" | "node-retirement-registration-refusal")
        ) {
            value["reason"] == plan["reason"] && plan["route"].is_null()
        } else {
            !plan["route"].is_null()
        }
        && value["state"] == "unmeasured"
        && value["helper_exit"].is_null()
        && value["evidence"].is_null()
        && value["owed"] == (value["reason"] != "node-retirement-no-registration")
        && matches!(
            value["reason"].as_str(),
            Some(
                "node-retirement-pending"
                    | "node-retirement-in-progress"
                    | "node-retirement-route-changed"
                    | "node-retirement-no-registration"
                    | "node-retirement-registration-refusal"
                    | "node-retirement-unreachable"
                    | "node-retirement-tools-absent"
                    | "node-retirement-deadline"
                    | "node-retirement-evidence-refusal"
                    | "node-retirement-transport-refusal"
            )
        )
}

pub fn attempt(plan: &Plan, override_runner: Option<&dyn Runner>, budget: Duration) -> Value {
    let started = Instant::now();
    let mut outcome = json!({"state":"unmeasured","reason":plan.value["reason"],"owed":plan.value["reason"] != "node-retirement-no-registration",
        "host_wall_seconds":null,"helper_exit":null,"remote_completion":"unknown","evidence":null});
    let Some(runner) = override_runner
        .or_else(|| plan.runner.as_ref().map(|r| r as &dyn Runner))
        .filter(|_| !plan.value["route"].is_null())
    else {
        return outcome;
    };
    let spawned = runner.spawn_retirement(
        plan.value["run"].as_str().unwrap_or_default(),
        plan.value["loop"].as_str().unwrap_or_default(),
        budget.as_secs_f64(),
    );
    match spawned {
        Err(error) => {
            outcome["reason"] = json!("node-retirement-unreachable");
            outcome["detail"] = json!(error.to_string());
        }
        Ok(mut child) => {
            let result = capture(&mut child, started + budget);
            stop(&mut child, runner.owns_process_group());
            match result {
                Ok((status, out, err)) => {
                    if let Some(evidence) = evidence(&out, status, &plan.value) {
                        let complete = evidence["reason"] == "node-retirement-complete";
                        outcome["state"] = json!(if complete { "complete" } else { "incomplete" });
                        outcome["reason"] = evidence["reason"].clone();
                        outcome["owed"] = json!(!complete);
                        outcome["helper_exit"] = evidence["helper_exit"].clone();
                        outcome["remote_completion"] = json!("measured");
                        outcome["evidence"] = evidence;
                    } else {
                        outcome["reason"] = json!(if String::from_utf8_lossy(&err)
                            .lines()
                            .any(|line| line == "NODE-RETIREMENT-TOOL-REFUSAL")
                        {
                            "node-retirement-tools-absent"
                        } else if status.code() == Some(255) {
                            "node-retirement-unreachable"
                        } else if matches!(status.code(), Some(124 | 137)) {
                            "node-retirement-deadline"
                        } else {
                            "node-retirement-evidence-refusal"
                        });
                        outcome["transport_exit"] = json!(status.code());
                    }
                }
                Err(error) => {
                    outcome["reason"] = json!(if error.kind() == io::ErrorKind::TimedOut {
                        "node-retirement-deadline"
                    } else {
                        "node-retirement-transport-refusal"
                    });
                    outcome["detail"] = json!(error.to_string());
                }
            }
        }
    }
    outcome["host_wall_seconds"] = json!(started.elapsed().as_secs_f64());
    outcome
}

/// Measure an unrecorded run's node absence without invoking node cleanup.
///
/// # Errors
/// Refuses an unavailable route, transport, lock or process measurement.
pub fn absence(plan: &Plan) -> Result<Value, LaneError> {
    let started = Instant::now();
    if plan.value["reason"] == "node-retirement-registration-refusal" {
        return Err(LaneError::input(
            "retire-node-registration",
            plan.value["detail"]
                .as_str()
                .unwrap_or("node-retirement-registration-refusal"),
        ));
    }
    if plan.value["reason"] == "node-retirement-no-registration" {
        return Ok(
            json!({"state":"not-applicable","reason":"no-compute-registration","wall_seconds":0.0}),
        );
    }
    let fail = |detail: String| LaneError::input("retire-uncertain", detail);
    let runner = plan
        .runner
        .as_ref()
        .ok_or_else(|| fail(plan.value.to_string()))?;
    let run = plan.value["run"].as_str().unwrap_or_default();
    let loop_name = plan.value["loop"].as_str().unwrap_or_default();
    let mut child = runner
        .spawn_retirement(&format!("--absence={run}"), loop_name, 30.0)
        .map_err(|error| fail(error.to_string()))?;
    let captured = capture(&mut child, started + Duration::from_secs(30));
    stop(&mut child, runner.owns_process_group());
    let (status, out, err) = captured.map_err(|error| fail(error.to_string()))?;
    let mut proof: Value = std::str::from_utf8(&out)
        .ok()
        .and_then(|text| text.trim().strip_prefix("NODE-ABSENCE "))
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or_else(|| {
            fail(format!(
                "node absence evidence unreadable: {}",
                String::from_utf8_lossy(&err)
            ))
        })?;
    if proof["schema"] == 1
        && proof["run"] == run
        && proof["loop"] == loop_name
        && proof["state"] == "present"
    {
        return Err(LaneError::input(
            "retire-busy",
            format!("node presence measured: {proof}"),
        ));
    }
    if !status.success()
        || proof["schema"] != 1
        || proof["run"] != run
        || proof["loop"] != loop_name
        || proof["state"] != "absent"
        || proof["processes"] != json!([])
        || !matches!(proof["lock"].as_str(), Some("absent" | "unheld"))
    {
        return Err(fail(format!("node absence not established: {proof}")));
    }
    proof["host_wall_seconds"] = json!(started.elapsed().as_secs_f64());
    proof["route"] = plan.value["route"].clone();
    Ok(proof)
}

#[cfg(test)]
mod tests {

    /// ´test:unit:node-retirement-uses-registered-ssh-and-independent-remote-deadline´
    #[test]
    fn node_retirement_uses_registered_ssh_and_independent_remote_deadline() {
        let fixture = crate::requests::store::tests::Fixture::new();
        let route = super::super::tests::route_for(&fixture.home);
        let command = route.retirement_command("R", "alpha", 120.0);
        let args: Vec<_> = command
            .get_args()
            .map(|word| word.to_string_lossy().into_owned())
            .collect();
        assert_eq!(command.get_program(), "/usr/bin/ssh");
        for option in [
            "BatchMode=yes",
            "ConnectTimeout=10",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "ControlMaster=no",
            "ControlPath=none",
        ] {
            assert!(args.iter().any(|arg| arg == option), "{option}");
        }
        assert!(args.iter().any(|arg| arg
            == &format!(
                "IdentityFile={}",
                fixture.home.join(".config/loops/alpha/door-key").display()
            )));
        assert_eq!(args[args.len() - 2], "fixture");
        let remote = args.last().expect("remote");
        assert!(remote.starts_with("if test -x /usr/bin/python3 && test -x /usr/bin/timeout;"));
        assert!(remote.contains("exec /usr/bin/timeout -k 5 105 /usr/bin/python3 -c"));
        assert!(remote.ends_with("'~/mirrors/R.git' 'R' 'alpha' '/srv/loops/loop-a'; else echo NODE-RETIREMENT-TOOL-REFUSAL >&2; exit 127; fi"));
        assert!(!fixture.home.join(".config/loops/alpha/door-key").exists());
    }
}
