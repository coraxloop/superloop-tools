//! Measure the recorded door boundary through the pinned box and peer socket.

use std::path::Path;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;
use crate::settings::Settings;
use crate::valid_run_name;

use super::{checkout, launch_environment, private_podman_environment};

const PROBE: &str = include_str!("exercise_door_probe.py");

fn refusal(loop_name: &str, run: &str, reason: &str) -> Value {
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"door-shape",
        "verdict":"unmeasured","reasons":[reason],"changed":false})
}

pub(in crate::launch) fn settings(
    owner_home: &Path,
    loop_name: &str,
) -> Result<Settings, LaneError> {
    let path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("workers.toml");
    Settings::read(&path)
}

#[allow(clippy::too_many_lines)]
pub(super) fn measure(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let settings = settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door", "runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let (record, identity) = checkout::read_record_bound(&runs, run, owner)?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-door",
            "reservation identity differs",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let door = &document["door"];
    let inventory = &document["mount_inventory"];
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("exercise-door", "worker uid is absent"))?;
    let mut reasons = recorded_boundary_reasons(document, worker, run);
    let boundary_failed = !reasons.is_empty();
    let mut measured_failure = boundary_failed;
    let row = crate::plan::registry(&settings, loop_name)?;
    let registration = super::door_registration_from_record(&row, loop_name, run, worker, &record);
    let registration = match registration {
        Ok(registration) => Some(registration),
        Err(error) => {
            reasons.push(error.line());
            measured_failure = true;
            None
        }
    };
    let socket = settings
        .socket_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door", "socket root is absent"))?
        .join("door/capability.sock");
    let (socket_state, socket_observed) = match crate::SocketSlot::pinned(&socket, owner) {
        Ok(slot) => match slot.metadata() {
            Ok(state) => (state, true),
            Err(error) => {
                reasons.push(format!("socket metadata is unmeasured: {error}"));
                (None, false)
            }
        },
        Err(error) => {
            reasons.push(format!("socket path is unmeasured: {}", error.line()));
            (None, false)
        }
    };
    let loop_uid = row["uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("exercise-door", "row uid is absent"))?;
    let socket_ok = socket_state.is_some_and(|stat| {
        stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && stat.st_uid == owner
            && stat.st_gid == loop_uid
            && stat.st_mode & 0o7777 == 0o660
    });
    if !socket_ok {
        reasons.push("registered socket is absent or changed".to_owned());
        measured_failure |= socket_observed;
    }
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-door", error.to_string()))?;
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
        "exercise-door",
        &home_fd,
        root,
        &runs,
        None,
    );
    let box_report = match output {
        Ok(output) => serde_json::from_str::<Value>(&output).map_err(|error| {
            LaneError::input("exercise-door", format!("private report: {error}"))
        })?,
        Err(error) => refusal(loop_name, run, &error.line()),
    };
    if box_report["loop"] != loop_name
        || box_report["run"] != run
        || box_report["case"] != "door-shape"
    {
        reasons.push("private box report identity differs".to_owned());
        measured_failure = true;
    }
    measured_failure |= box_report["verdict"] == "fail";
    if box_report["verdict"] != "pass" {
        if let Some(box_reasons) = box_report["reasons"].as_array() {
            reasons.extend(
                box_reasons
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned),
            );
        } else {
            reasons.push("box probe has no verdict reasons".to_owned());
        }
    }
    let verdict = compose_verdict(&reasons, measured_failure);
    let observed = &box_report["probe"];
    let worker_key = worker_key_observation(observed);
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"door-shape",
        "recorded_inventory":inventory,"stub_sha256":door["stub_sha256"],"socket":socket,
        "door_pin_history":record["door_pin_history"],"round_door_pins":super::super::repin_door::round_pins(&record)?,
        "socket_present":socket_ok,"peer_registration":registration.map(|row| row.document()),
        "registered":door["registered"],"worker_key":worker_key,
        "box_probe":box_report,"reasons":reasons,"verdict":verdict,"changed":false}),
    )
}

fn worker_key_observation(observed: &Value) -> Value {
    if observed["key_paths"]
        .as_array()
        .is_some_and(|paths| !paths.is_empty())
        || observed["key_environment"]
            .as_array()
            .is_some_and(|names| !names.is_empty())
    {
        json!(true)
    } else if observed["scan_complete"] != true {
        json!("unmeasured")
    } else {
        json!(false)
    }
}

pub(super) fn recorded_boundary_reasons(document: &Value, worker: u32, run: &str) -> Vec<String> {
    let door = &document["door"];
    let inventory = &document["mount_inventory"];
    let mut reasons = Vec::new();
    if inventory["version"] != 1
        || !inventory["entries"].as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["target"] == "/home/worker/.local/door" && entry["access"] == "ro"
            })
        })
    {
        reasons.push("recorded door mount is absent".to_owned());
    }
    if door["registered"] != json!(["ssh"])
        || door["peer_uid"] != worker
        || door["mirror_ref"] != format!("refs/heads/lane/{run}")
        || door["stub_sha256"].as_str().is_none()
    {
        reasons.push("recorded door pin or peer differs".to_owned());
    }
    reasons
}

const fn compose_verdict(reasons: &[String], measured_failure: bool) -> &'static str {
    if measured_failure {
        "fail"
    } else if reasons.is_empty() {
        "pass"
    } else {
        "unmeasured"
    }
}

fn private_argv(
    loop_name: &str,
    run: &str,
    identity: &str,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-door-shape".into(),
        loop_name.into(),
        run.into(),
        "--expect-record".into(),
        identity.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

/// Parse the exact descriptor-bound private probe form.
///
/// # Errors
///
/// Refuses malformed words before entering the private namespace.
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
            "exercise-door-form",
            "private form is incomplete",
        ));
    };
    if command != "_exercise-door-shape"
        || record_flag != "--expect-record"
        || home_flag != "--owner-home"
        || identity.is_empty()
        || !valid_run_name(run)
        || !Path::new(home).is_absolute()
    {
        return Err(LaneError::input(
            "exercise-door-form",
            "private form is malformed",
        ));
    }
    Ok((loop_name, run, identity, Path::new(home)))
}

/// Probe the recorded runtime vector without rebuilding the run's plan.
///
/// # Errors
///
/// Refuses an unbound namespace or changed reservation.
pub fn private_measure(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    identity: &str,
) -> Result<Value, LaneError> {
    if !home::private_is_active() || !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-door",
            "bound private namespace is absent",
        ));
    }
    let settings = settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-door", "runs root is absent"))?;
    let runs = home::pin_parent(root, 0)?;
    let (record, actual) = checkout::read_record_bound(&runs, run, 0)?;
    if actual != identity || record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-door",
            "reservation identity differs",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let Some(digest) = document["door"]["stub_sha256"].as_str() else {
        return Ok(refusal(loop_name, run, "recorded stub digest is absent"));
    };
    let scope = match record["door_scope"].as_str() {
        Some("work" | "review") => record["door_scope"].as_str().unwrap_or_default(),
        _ => return Ok(refusal(loop_name, run, "recorded door scope is absent")),
    };
    let mut argv = super::mounts::probe_vector_for(document, loop_name, run, "door-shape", PROBE)?;
    let image = document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-door", "image digest is absent"))?;
    let image_position = argv
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("exercise-door", "image boundary is absent"))?;
    argv.splice(
        image_position..image_position,
        [
            "-e".into(),
            format!("SUPERLOOP_DOOR_RUN={run}"),
            "-e".into(),
            format!("SUPERLOOP_DOOR_DIGEST={digest}"),
            "-e".into(),
            format!("SUPERLOOP_DOOR_SCOPE={scope}"),
        ],
    );
    let program = Path::new(
        argv.first()
            .ok_or_else(|| LaneError::input("exercise-door", "container program is absent"))?,
    );
    if let Err(error) = crate::pinned::owner_executable(program, 0) {
        return Ok(refusal(loop_name, run, &error.line()));
    }
    let environment = match private_podman_environment(owner_home) {
        Ok(value) => value,
        Err(error) => return Ok(refusal(loop_name, run, &error.line())),
    };
    if let Err(error) =
        super::image_check_with_environment(program, image, owner_home, &environment)
    {
        return Ok(refusal(loop_name, run, &error.line()));
    }
    let probe_name =
        crate::launch::probe::name(&argv, &super::mounts::probe_name_prefix("door-shape"))?;
    let output = build::run_checked(
        program,
        argv[1..].to_vec(),
        &environment,
        owner_home,
        60,
        "exercise-door-box",
    );
    if let Err(error) = crate::launch::probe::remove(
        program,
        owner_home,
        &environment,
        probe_name,
        "door-shape",
        loop_name,
        run,
    ) {
        return Ok(refusal(loop_name, run, &error.line()));
    }
    let output = match output {
        Ok(value) => value,
        Err(error) => return Ok(refusal(loop_name, run, &error.line())),
    };
    let probe: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-door", format!("box probe: {error}")))?;
    let (reasons, verdict) = evaluate_probe(&probe, digest, scope);
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"door-shape",
        "probe":probe,"reasons":reasons,"verdict":verdict,"changed":false}),
    )
}

fn evaluate_probe(probe: &Value, digest: &str, scope: &str) -> (Vec<String>, &'static str) {
    let mut reasons = Vec::new();
    let mut measured_failure = false;
    if probe["scan_complete"] != true {
        reasons.push("key-path scan was incomplete".to_owned());
    }
    if probe["stub_sha256"] != digest {
        reasons.push("box stub differs from recorded digest".to_owned());
        measured_failure |= probe["stub_sha256"].is_string();
    }
    if probe["stub_status"] != 125 {
        reasons.push("box stub did not return complete status 125".to_owned());
        measured_failure |= probe["stub_status"].is_number();
    }
    if probe["stub_stdout_bytes"] != 0 {
        reasons.push("box stub wrote unexpected stdout bytes".to_owned());
        measured_failure |= probe["stub_stdout_bytes"].is_number();
    }
    let expected = if scope == "review" {
        "door-review-compute-refusal"
    } else {
        "door-transport-pending"
    };
    if probe["stub_reason"].as_str().is_some_and(|reason| {
        reason == "door-request-concurrent" || reason.starts_with("door-request-concurrent:")
    }) {
        reasons.push(
            "door-request-concurrent: bounded admission retry exhausted; socket reply unmeasured"
                .to_owned(),
        );
    } else if probe["stub_reason"] != expected {
        reasons.push(format!("box stub reply differs from {expected}"));
        measured_failure |= probe["stub_reason"].is_string();
    }
    if probe["key_paths"]
        .as_array()
        .is_none_or(|paths| !paths.is_empty())
        || probe["key_environment"]
            .as_array()
            .is_none_or(|names| !names.is_empty())
    {
        reasons.push("key path or key environment is present".to_owned());
        measured_failure |= probe["key_paths"]
            .as_array()
            .is_some_and(|paths| !paths.is_empty())
            || probe["key_environment"]
                .as_array()
                .is_some_and(|names| !names.is_empty());
    }
    if let Some(error) = probe["error"].as_str() {
        reasons.push(format!("box probe: {error}"));
    }
    let verdict = compose_verdict(&reasons, measured_failure);
    (reasons, verdict)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use serde_json::json;

    use super::{
        PROBE, compose_verdict, evaluate_probe, recorded_boundary_reasons, worker_key_observation,
    };

    /// ´test:unit:box-probe-names-missing-stub-reply-and-key-observation´
    #[test]
    fn box_probe_names_missing_stub_reply_and_key_observation() {
        let measured = json!({"scan_complete":true,"stub_sha256":"digest",
            "stub_status":125,"stub_stdout_bytes":0,
            "stub_reason":"door-transport-pending","key_paths":[],"key_environment":[]});
        assert_eq!(evaluate_probe(&measured, "digest", "work").1, "pass");
        let mut refused = measured;
        refused["stub_reason"] = json!("door-socket: unavailable");
        refused["key_environment"] = json!(["SSH_AUTH_SOCK"]);
        let (reasons, verdict) = evaluate_probe(&refused, "digest", "work");
        assert_eq!(verdict, "fail");
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("socket") || reason.contains("pending"))
        );
        assert!(reasons.iter().any(|reason| reason.contains("key path")));
        refused["scan_complete"] = json!(false);
        assert_eq!(evaluate_probe(&refused, "digest", "work").1, "fail");
        refused["stub_reason"] = json!("door-transport-pending");
        refused["key_environment"] = json!([]);
        assert_eq!(evaluate_probe(&refused, "digest", "work").1, "unmeasured");
        let review = json!({"scan_complete":true,"stub_sha256":"digest",
            "stub_status":125,"stub_stdout_bytes":0,
            "stub_reason":"door-review-compute-refusal","key_paths":[],"key_environment":[]});
        assert_eq!(evaluate_probe(&review, "digest", "review").1, "pass");
    }

    /// ´test:unit:door-shape-concurrent-admission-is-unmeasured´
    #[test]
    fn door_shape_concurrent_admission_is_unmeasured() {
        let mut probe = json!({"scan_complete":true,"stub_sha256":"digest",
            "stub_status":125,"stub_stdout_bytes":0,"key_paths":[],"key_environment":[]});
        for reason in [
            "door-request-concurrent",
            "door-request-concurrent: publication window",
        ] {
            probe["stub_reason"] = json!(reason);
            for scope in ["work", "review"] {
                let (reasons, verdict) = evaluate_probe(&probe, "digest", scope);
                assert_eq!(verdict, "unmeasured");
                assert!(
                    reasons
                        .iter()
                        .any(|reason| reason.contains("door-request-concurrent"))
                );
            }
        }
        probe["key_environment"] = json!(["SSH_AUTH_SOCK"]);
        assert_eq!(evaluate_probe(&probe, "digest", "work").1, "fail");
    }

    /// ´test:unit:doorless-recorded-plan-fails-with-unmeasured-box´
    #[test]
    fn doorless_recorded_plan_fails_with_unmeasured_box() {
        let document = json!({"mount_inventory":{"version":1,"entries":[]},"door":null});
        let mut reasons = recorded_boundary_reasons(&document, 3001, "R");
        assert!(
            reasons
                .iter()
                .any(|reason| reason == "recorded door mount is absent")
        );
        let measured_failure = !reasons.is_empty();
        reasons.push("recorded stub digest is absent".to_owned());
        assert_eq!(compose_verdict(&reasons, measured_failure), "fail");
        assert_eq!(
            compose_verdict(&["box probe unavailable".to_owned()], false),
            "unmeasured"
        );
        assert_eq!(
            worker_key_observation(
                &json!({"scan_complete":false,"key_paths":["/home/worker/.ssh"],"key_environment":[]})
            ),
            true
        );
    }

    /// ´test:unit:door-python-probe-scans-fixture-with-held-descriptors´
    #[test]
    fn door_python_probe_scans_fixture_with_held_descriptors() {
        let fixture = tempfile::tempdir_in("/tmp").expect("probe fixture");
        let harness = r"
import ast, os, pathlib, stat, sys
tree = ast.parse(sys.argv[1])
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {'held_directory', 'scan'}]
root = pathlib.Path(sys.argv[2])
worker = root / 'home' / 'worker'
worker.mkdir(parents=True)
(worker / '.ssh').mkdir()
namespace = {'os': os, 'stat': stat, 'seen': set(), 'count': 0,
             'result': {'scan_complete': True, 'key_paths': [], 'key_environment': []}}
exec(compile(ast.Module(body=functions, type_ignores=[]), '<probe>', 'exec'), namespace)
fd = namespace['held_directory'](tuple(worker.parts[1:]))
try:
    namespace['scan'](fd, '/home/worker', 0)
finally:
    os.close(fd)
assert namespace['result']['scan_complete'] is True
assert namespace['result']['key_paths'] == ['/home/worker/.ssh']
(worker / 'link').symlink_to(worker, target_is_directory=True)
try:
    namespace['held_directory'](tuple((worker / 'link').parts[1:]))
except OSError:
    pass
else:
    raise AssertionError('symlink ancestor accepted')

import types, json
clock = [0.0]
calls = []
replies = []
def sleep(seconds):
    clock[0] += seconds
def invoke(argv, **kwargs):
    calls.append((argv, kwargs))
    assert 0 < kwargs['timeout'] <= 8
    return types.SimpleNamespace(returncode=125, stdout=b'', stderr=replies[min(len(calls)-1, len(replies)-1)])
namespace = {'subprocess': types.SimpleNamespace(run=invoke, PIPE=-1),
             'time': types.SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep), 'json': json}
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'invoke_stub']
exec(compile(ast.Module(body=functions, type_ignores=[]), '<probe>', 'exec'), namespace)
for busy in [b'door-request-concurrent', b'door-request-concurrent: publication window']:
    for persistent in [False, True]:
        calls.clear()
        clock[0] = 0
        replies[:] = [busy] if persistent else [busy, b'door-transport-pending']
        reply = namespace['invoke_stub']('/fixture/stub', 'R')
        if persistent:
            assert 2 <= clock[0] < 2.1
            assert 40 <= len(calls) <= 42
            assert reply.stderr.startswith(b'door-request-concurrent')
        else:
            assert len(calls) == 2
            assert reply.stderr == b'door-transport-pending'
    calls.clear()
    clock[0] = 0
    replies[:] = [b'door-other-refusal']
    namespace['invoke_stub']('/fixture/stub', 'R')
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
            .expect("Python probe fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
