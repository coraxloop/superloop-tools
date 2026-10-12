//! Compare a probe in the planned box with its versioned mount boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;
use crate::settings::Settings;
use crate::{load_plan, valid_run_name};

use super::{checkout, launch_environment, private_podman_environment};

const PROBE: &str = include_str!("exercise_mounts_probe.py");

pub(super) fn private_argv(
    loop_name: &str,
    run: &str,
    identity: &str,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_exercise-mounts".into(),
        loop_name.into(),
        run.into(),
        "--expect-record".into(),
        identity.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ])
}

/// Parse the bound private form before it enters the owner's namespace.
///
/// # Errors
///
/// Refuses a malformed form or a path outside an absolute owner home.
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
            "exercise-mounts-form",
            "private form is incomplete",
        ));
    };
    if command != "_exercise-mounts"
        || record_flag != "--expect-record"
        || home_flag != "--owner-home"
        || identity.is_empty()
        || !valid_run_name(run)
        || !Path::new(home).is_absolute()
    {
        return Err(LaneError::input(
            "exercise-mounts-form",
            "private form is malformed",
        ));
    }
    Ok((loop_name, run, identity, Path::new(home)))
}

pub(super) fn measure(
    owner_home: &Path,
    settings: &Settings,
    loop_name: &str,
    run: &str,
    identity: &str,
    runs: &std::os::fd::OwnedFd,
) -> Result<Value, LaneError> {
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-mounts", "runs root is absent"))?;
    let owner = Uid::effective().as_raw();
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("exercise-mounts", error.to_string()))?;
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
        "exercise-mounts",
        &home_fd,
        root,
        runs,
        None,
    )?;
    let report: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::input("exercise-mounts", format!("private report: {error}")))?;
    if report["loop"] != loop_name || report["run"] != run || report["case"] != "mounts" {
        return Err(LaneError::input(
            "exercise-mounts",
            "private report identity differs",
        ));
    }
    Ok(report)
}

/// Run the inventory probe through the same pinned box options as a worker.
///
/// # Errors
///
/// Refuses an unbound namespace, changed reservation, or malformed plan.
#[allow(clippy::too_many_lines)]
pub fn private_measure(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    identity: &str,
) -> Result<Value, LaneError> {
    if !home::private_is_active() || !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-mounts",
            "bound private namespace is absent",
        ));
    }
    let (_plan, settings) = load_plan(owner_home, loop_name, run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-mounts", "runs root is absent"))?;
    let runs = home::pin_parent(root, 0)?;
    let (record, actual_identity) = checkout::read_record_bound(&runs, run, 0)?;
    if actual_identity != identity || record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "exercise-mounts",
            "reservation identity differs",
        ));
    }
    let document = &record["plan"];
    verify_box_attestation(document)?;
    let inventory = &document["mount_inventory"];
    if inventory["version"] != 1 || !inventory["entries"].is_array() {
        return Err(LaneError::input(
            "mount-inventory",
            "version one entries are absent",
        ));
    }
    let argv = probe_vector(document, loop_name, run)?;
    let program = Path::new(
        argv.first()
            .ok_or_else(|| LaneError::input("exercise-mounts", "container program is absent"))?,
    );
    if let Err(error) = crate::pinned::owner_executable(program, 0) {
        return Ok(probe_refusal(loop_name, run, &error.line()));
    }
    let (plan, settings) =
        super::pinned_plan_from_record(owner_home, loop_name, run, program, &record)?;
    let preflight = super::check_mount_roots(&plan, &settings, owner_home).and_then(|()| {
        super::check_pins(
            &plan,
            &settings,
            owner_home,
            record["plan"]["vendor_mode"].is_string(),
            true,
        )
    });
    if let Err(error) = preflight {
        return Ok(probe_refusal(loop_name, run, &error.line()));
    }
    let environment = match private_podman_environment(owner_home) {
        Ok(environment) => environment,
        Err(error) => return Ok(probe_refusal(loop_name, run, &error.line())),
    };
    if let Err(error) = super::image_check_with_environment(
        program,
        image_from(document)?,
        owner_home,
        &environment,
    ) {
        return Ok(probe_refusal(loop_name, run, &error.line()));
    }
    let probe_name = crate::launch::probe::name(&argv, &probe_name_prefix("mounts"))?;
    let output = build::run_checked(
        program,
        argv[1..].to_vec(),
        &environment,
        owner_home,
        60,
        "exercise-mounts-box",
    );
    if let Err(error) = crate::launch::probe::remove(
        program,
        owner_home,
        &environment,
        probe_name,
        "mounts",
        loop_name,
        run,
    ) {
        return Ok(probe_refusal(loop_name, run, &error.line()));
    }
    let probe = match output {
        Ok(output) => serde_json::from_str::<Value>(&output).map_err(|error| {
            LaneError::input("exercise-mounts", format!("box probe report: {error}"))
        })?,
        Err(error) => {
            return Ok(probe_refusal(loop_name, run, &error.line()));
        }
    };
    let differences = compare_inventory(inventory, &probe)?;
    let canaries = compare_canaries(&probe)?;
    let verdict = if !differences.is_empty() || canaries["verdict"] == "fail" {
        "fail"
    } else if canaries["verdict"] == "unmeasured" {
        "unmeasured"
    } else {
        "pass"
    };
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"mounts","mount_inventory_version":1,"inventory":inventory,"observed_mounts":probe["mounts"],"differing_entries":differences,"canaries":canaries,"verdict":verdict,"changed":false}),
    )
}

fn probe_refusal(loop_name: &str, run: &str, reason: &str) -> Value {
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"mounts","mount_inventory_version":1,"verdict":"unmeasured","reason":format!("box probe refused: {reason}"),"changed":false})
}

fn image_from(document: &Value) -> Result<&str, LaneError> {
    document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-mounts", "image digest is absent"))
}

fn probe_vector(document: &Value, loop_name: &str, run: &str) -> Result<Vec<String>, LaneError> {
    probe_vector_for(document, loop_name, run, "mounts", PROBE)
}

pub(super) fn probe_vector_for(
    document: &Value,
    loop_name: &str,
    run: &str,
    case: &str,
    script: &str,
) -> Result<Vec<String>, LaneError> {
    let image = image_from(document)?;
    let saved = document["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-mounts", "runtime vector is absent"))?;
    let words = saved
        .iter()
        .map(|word| word.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            LaneError::input("exercise-mounts", "runtime vector has a non-string word")
        })?;
    let position = words
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("exercise-mounts", "image boundary is absent"))?;
    let owner = document["paths"][0]["uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("exercise-mounts", "owner UID is absent"))?;
    let mut argv = Vec::with_capacity(position + 9);
    for word in &words[..position] {
        if word.starts_with("--cidfile=") {
            continue;
        }
        if word.starts_with("--label=org.superloop.run=")
            || word.starts_with("--label=org.superloop.loop=")
        {
            continue;
        }
        if word.starts_with("--name=") {
            argv.push(format!(
                "--name={}{}",
                probe_name_prefix(case),
                crate::launch::checkpoint::random_token()?
            ));
        } else {
            argv.push(word.clone());
        }
    }
    argv.insert(2, "--rm".into());
    argv.push(format!("--label=org.superloop.probe={case}"));
    argv.push(crate::launch::probe::identity_option(loop_name, run));
    argv.push("-e".into());
    argv.push(format!("SUPERLOOP_MOUNT_OWNER_UID={owner}"));
    argv.push(image.into());
    argv.extend(["/usr/bin/python3".into(), "-c".into(), script.into()]);
    Ok(argv)
}

pub(super) fn probe_name_prefix(case: &str) -> String {
    format!("superloop-{case}-probe-")
}

pub(crate) fn compare_inventory(inventory: &Value, probe: &Value) -> Result<Vec<Value>, LaneError> {
    let entries = inventory["entries"]
        .as_array()
        .ok_or_else(|| LaneError::input("mount-inventory", "entries are absent"))?;
    let observed = probe["mounts"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-mounts", "mountinfo observations are absent"))?;
    let mut expected = BTreeMap::new();
    for entry in entries {
        let target = entry["target"]
            .as_str()
            .ok_or_else(|| LaneError::input("mount-inventory", "target is absent"))?;
        if expected.insert(target, entry).is_some() {
            return Err(LaneError::input(
                "mount-inventory",
                format!("duplicate target {target}"),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    let mut differences = Vec::new();
    for row in observed {
        let target = row["target"]
            .as_str()
            .ok_or_else(|| LaneError::input("exercise-mounts", "observed target is absent"))?;
        if !seen.insert(target) {
            differences.push(json!({"target":target,"reason":"duplicate live mount"}));
        }
        let Some(entry) = expected.get(target) else {
            differences.push(json!({"target":target,"reason":"unnamed live mount"}));
            continue;
        };
        let access = entry["access"].as_str().ok_or_else(|| {
            LaneError::input("mount-inventory", format!("{target}: access is absent"))
        })?;
        if access != "runtime" && row["access"] != access {
            differences.push(json!({"target":target,"reason":"access differs","expected":access,"observed":row["access"]}));
        }
        if entry["kind"] == "bind" && row["owner"] != entry["owner"] {
            differences.push(json!({"target":target,"reason":"bind owner differs","expected":entry["owner"],"observed":row["owner"]}));
        }
        if entry["source_role"] == "worker-runtime" {
            if row["owner"] != entry["owner"] {
                differences.push(json!({"target":target,"reason":"runtime owner differs","expected":entry["owner"],"observed":row["owner"]}));
            }
            if row["mode"] != entry["mode"] {
                differences.push(json!({"target":target,"reason":"runtime mode differs","expected":entry["mode"],"observed":row["mode"]}));
            }
        }
        let fstype = row["fstype"].as_str().ok_or_else(|| {
            LaneError::input(
                "exercise-mounts",
                format!("{target}: filesystem type is absent"),
            )
        })?;
        let kind = entry["kind"].as_str().ok_or_else(|| {
            LaneError::input("mount-inventory", format!("{target}: kind is absent"))
        })?;
        let compatible = match kind {
            "proc" => fstype == "proc",
            "sys" if target == "/sys/firmware" => fstype == "sysfs" || fstype == "tmpfs",
            "sys" => fstype == "sysfs",
            "cgroup" => fstype == "cgroup2",
            "devpts" => fstype == "devpts",
            "mqueue" => fstype == "mqueue",
            "runtime-tmpfs" if target == "/run/worker" || target == "/dev/shm" => fstype == "tmpfs",
            "masked-proc" => fstype == "tmpfs",
            "masked-proc-file" => fstype == "tmpfs" || fstype == "devtmpfs",
            "rootfs" => row["access"] == "ro",
            "bind" | "host-file" | "dev" | "runtime-tmpfs" => true,
            _ => false,
        };
        if !compatible {
            differences.push(json!({"target":target,"reason":"mount kind differs","expected":kind,"observed_fstype":fstype}));
        }
    }
    for (target, entry) in &expected {
        if !seen.contains(target) && entry["presence"] != "optional" {
            differences.push(json!({"target":target,"reason":"planned mount absent"}));
        }
    }
    Ok(differences)
}

fn compare_canaries(probe: &Value) -> Result<Value, LaneError> {
    let doors = probe["host_doors"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-mounts", "host-door observations are absent"))?;
    let ancestors = probe["ancestors"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-mounts", "ancestor observations are absent"))?;
    let routes = probe["direct_routes"]["trials"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-mounts", "route observations are absent"))?;
    let mut failures = Vec::new();
    if doors.len() != 8 {
        failures.push(json!({"canary":"host-door","reason":"named path count differs","observed":doors.len()}));
    }
    if ancestors.len() != 5 {
        failures.push(json!({"canary":"protected-ancestor","reason":"ancestor count differs","observed":ancestors.len()}));
    }
    if routes.len() != 4 {
        failures.push(json!({"canary":"direct-route","reason":"route trial count differs","observed":routes.len()}));
    }
    for path in [
        "/",
        "/home",
        "/home/worker",
        "/home/worker/.local",
        "/home/worker/.local/inbox",
    ] {
        if !ancestors.iter().any(|row| row["path"] == path) {
            failures.push(
                json!({"canary":"protected-ancestor","path":path,"reason":"observation absent"}),
            );
        }
    }
    for row in doors {
        if row["present"] != false {
            failures
                .push(json!({"canary":"host-door","path":row["path"],"observed":row["present"]}));
        }
    }
    for row in ancestors {
        if row["worker_writable"] != false
            || row["create_succeeded"] != false
            || row["rename_succeeded"] != false
        {
            failures.push(json!({"canary":"protected-ancestor","path":row["path"],"observed":row}));
        }
    }
    if probe["direct_routes"]["default_route"] != false {
        failures.push(json!({"canary":"direct-route","reason":"default route exists"}));
    }
    let nonloopback = probe["direct_routes"]["nonloopback_routes"]
        .as_array()
        .ok_or_else(|| {
            LaneError::input(
                "exercise-mounts",
                "nonloopback route observations are absent",
            )
        })?;
    if !nonloopback.is_empty() {
        failures.push(json!({"canary":"direct-route","reason":"nonloopback route exists","observed":nonloopback}));
    }
    let ipv6_default = &probe["direct_routes"]["ipv6_default_route"];
    let ipv6_nonloopback = &probe["direct_routes"]["ipv6_nonloopback_routes"];
    let mut unmeasured = Vec::new();
    if ipv6_default.is_null() || !ipv6_nonloopback.is_array() {
        unmeasured.push(json!({"canary":"direct-route","unmeasured":"ipv6 route table"}));
    }
    if ipv6_default == true {
        failures.push(json!({"canary":"direct-route","reason":"ipv6 default route exists"}));
    }
    if let Some(rows) = ipv6_nonloopback.as_array()
        && !rows.is_empty()
    {
        failures.push(json!({"canary":"direct-route","reason":"ipv6 nonloopback route exists","observed":rows}));
    }
    for row in routes {
        if row["name"] == "ipv6-documentation"
            && (row["result"] == "EAFNOSUPPORT" || row["result"] == "EPROTONOSUPPORT")
        {
            unmeasured.push(json!({"canary":"direct-route","unmeasured":"ipv6 connection trial","result":row["result"]}));
        } else if row["refused"] != true {
            failures.push(json!({"canary":"direct-route","name":row["name"],"address":row["address"],"observed":row["result"]}));
        }
    }
    Ok(
        json!({"verdict":if !failures.is_empty() {"fail"} else if !unmeasured.is_empty() {"unmeasured"} else {"pass"},"host_doors":doors,"protected_ancestors":ancestors,"direct_routes":probe["direct_routes"],"failures":failures,"unmeasured":unmeasured}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// ´test:unit:mount-inventory-names-extra-and-missing-targets´
    #[test]
    fn mount_inventory_names_extra_and_missing_targets() {
        let inventory = json!({"version":1,"entries":[{"target":"/","kind":"rootfs","access":"ro","owner":"runtime"},{"target":"/home/worker/.local/bin","kind":"bind","access":"ro","owner":41001}]});
        let probe = json!({"mounts":[{"target":"/","fstype":"overlay","access":"ro","owner":0},{"target":"/run/host","fstype":"tmpfs","access":"rw","owner":0}]});
        let differences = compare_inventory(&inventory, &probe).expect("inventory comparison");
        assert!(
            differences
                .iter()
                .any(|row| row["target"] == "/run/host" && row["reason"] == "unnamed live mount")
        );
        assert!(
            differences
                .iter()
                .any(|row| row["target"] == "/home/worker/.local/bin"
                    && row["reason"] == "planned mount absent")
        );
    }

    /// ´test:unit:mount-inventory-checks-optional-access-owner-kind-and-duplicates´
    #[test]
    fn mount_inventory_checks_optional_access_owner_kind_and_duplicates() {
        let inventory = json!({"version":1,"entries":[
            {"target":"/","kind":"rootfs","access":"ro","owner":"runtime"},
            {"target":"/home/worker/.local/bin","kind":"bind","access":"ro","owner":41001},
            {"target":"/proc/sys","kind":"proc","access":"ro","owner":"runtime","presence":"optional"},
            {"target":"/dev/console","kind":"dev","access":"runtime","owner":"runtime","presence":"optional"},
            {"target":"/run/worker","kind":"runtime-tmpfs","access":"rw","owner":3000,"mode":"0700","source_role":"worker-runtime"},
            {"target":"/proc/kcore","kind":"masked-proc-file","access":"runtime","owner":"runtime","presence":"optional"}
        ]});
        let probe = json!({"mounts":[
            {"target":"/","fstype":"overlay","access":"ro","owner":0},
            {"target":"/home/worker/.local/bin","fstype":"tmpfs","access":"rw","owner":3001},
            {"target":"/proc/sys","fstype":"tmpfs","access":"rw","owner":0},
            {"target":"/proc/sys","fstype":"tmpfs","access":"rw","owner":0},
            {"target":"/run/worker","fstype":"tmpfs","access":"rw","owner":3001,"mode":"0755"},
            {"target":"/proc/kcore","fstype":"devtmpfs","access":"ro","owner":0}
        ]});
        let differences = compare_inventory(&inventory, &probe).expect("inventory comparison");
        let named = differences
            .iter()
            .map(|row| {
                (
                    row["target"].as_str().expect("target"),
                    row["reason"].as_str().expect("reason"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            named
                .iter()
                .filter(|(_, reason)| *reason == "access differs")
                .count(),
            3
        );
        assert!(named.contains(&("/home/worker/.local/bin", "bind owner differs")));
        assert!(named.contains(&("/proc/sys", "mount kind differs")));
        assert!(named.contains(&("/proc/sys", "duplicate live mount")));
        assert!(named.contains(&("/run/worker", "runtime owner differs")));
        assert!(named.contains(&("/run/worker", "runtime mode differs")));
        assert!(!named.iter().any(|(target, reason)| *target == "/proc/kcore" && *reason == "mount kind differs"));
        assert!(
            !named
                .iter()
                .any(|(target, reason)| *target == "/dev/console"
                    && *reason == "planned mount absent")
        );
    }

    /// ´test:unit:mount-probe-refusal-is-unmeasured´
    #[test]
    fn mount_probe_refusal_is_unmeasured() {
        let report = probe_refusal("alpha", "R", "image absent");
        assert_eq!(report["verdict"], "unmeasured");
        assert_eq!(report["reason"], "box probe refused: image absent");
    }

    /// ´test:unit:mount-probe-does-not-borrow-run-labels´
    #[test]
    fn mount_probe_does_not_borrow_run_labels() {
        let plan = json!({"image_digest":"sha256:fixture","paths":[{"uid":41001}],"runtime_argv":[
            "/usr/bin/podman","run","--cidfile=/tmp/run.cid","--name=superloop-R",
            "--label=org.superloop.run=R","--label=org.superloop.loop=alpha","sha256:fixture"
        ]});
        let argv = probe_vector(&plan, "alpha", "R").expect("probe vector");
        assert!(
            argv.iter()
                .any(|word| word == "--label=org.superloop.probe=mounts")
        );
        assert!(
            argv.iter()
                .any(|word| word == "--label=org.superloop.probe.identity=alpha/R")
        );
        assert!(
            !argv
                .iter()
                .any(|word| word.starts_with("--label=org.superloop.run=")
                    || word.starts_with("--label=org.superloop.loop="))
        );
    }

    /// ´test:unit:mount-and-door-probe-names-match-their-vectors´
    #[test]
    fn mount_and_door_probe_names_match_their_vectors() {
        let plan = json!({"image_digest":"sha256:fixture","paths":[{"uid":41001}],"runtime_argv":[
            "/usr/bin/podman","run","--name=superloop-R","sha256:fixture"
        ]});
        for case in ["mounts", "door-shape"] {
            let argv =
                probe_vector_for(&plan, "alpha", "R", case, "print('{}')").expect("probe vector");
            let prefix = probe_name_prefix(case);
            let name = crate::launch::probe::name(&argv, &prefix).expect("probe name");
            assert!(name.starts_with(&prefix));
        }
    }

    /// ´test:unit:mount-python-probe-reads-ipv6-fixture-routes´
    #[test]
    fn mount_python_probe_reads_ipv6_fixture_routes() {
        let harness = r"
import ast, errno, json, socket, sys
tree = ast.parse(sys.argv[1])
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'direct_routes')
class Connection:
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def settimeout(self, value): pass
    def connect_ex(self, address): return errno.ENETUNREACH
class Sockets:
    AF_INET = socket.AF_INET
    AF_INET6 = socket.AF_INET6
    SOCK_STREAM = socket.SOCK_STREAM
    def socket(self, family, kind): return Connection()
null_route = ('0' * 32) + ' 00 ' + ('0' * 32) + ' 00 ' + ('0' * 32) + ' ffffffff 00000000 00000000 00200200 lo\n'
ipv6_lines = [null_route, null_route]
def read_proc(parts):
    if parts[-1] == 'route': return 'Iface Destination\n'
    if parts[-1] == 'ipv6_route': return ''.join(ipv6_lines)
    raise AssertionError(parts)
namespace = {'errno': errno, 'socket': Sockets(), 'read_proc': read_proc}
exec(compile(ast.Module(body=[function], type_ignores=[]), '<probe>', 'exec'), namespace)
result = namespace['direct_routes']()
assert result['default_route'] is False
assert result['ipv6_default_route'] is False
assert result['ipv6_nonloopback_routes'] == []
assert len(result['trials']) == 4
assert result['trials'][3]['name'] == 'ipv6-documentation'
assert result['trials'][3]['refused'] is True
ipv6_lines.append(('0' * 32) + ' 00 ' + ('0' * 32) + ' 00 ' + ('0' * 32) + ' 00000000 00000000 00000000 00000003 eth0\n')
result = namespace['direct_routes']()
assert result['ipv6_default_route'] is True
assert result['ipv6_nonloopback_routes'][0]['interface'] == 'eth0'
";
        let output = Command::new("/usr/bin/python3")
            .args(["-c", harness, PROBE])
            .output()
            .expect("Python probe fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// ´test:unit:mount-canaries-name-host-doors-routes-and-protected-ancestors´
    #[test]
    fn mount_canaries_name_host_doors_routes_and_protected_ancestors() {
        let probe = json!({"host_doors":[{"path":"/run/host","present":true}],"ancestors":[{"path":"/home/worker/.local","worker_writable":true,"create_succeeded":true,"rename_succeeded":false}],"direct_routes":{"default_route":true,"nonloopback_routes":[{"interface":"eth0","destination":"00000000"}],"trials":[{"name":"pod-gateway","address":"10.88.0.1","result":"ECONNREFUSED","refused":false}]}});
        let report = compare_canaries(&probe).expect("canaries");
        assert_eq!(report["verdict"], "fail");
        let failures = report["failures"].as_array().expect("failures");
        assert!(
            failures
                .iter()
                .any(|row| row["canary"] == "host-door" && row["path"] == "/run/host")
        );
        assert!(failures.iter().any(
            |row| row["canary"] == "protected-ancestor" && row["path"] == "/home/worker/.local"
        ));
        assert!(
            failures
                .iter()
                .any(|row| row["canary"] == "direct-route"
                    && row["reason"] == "default route exists")
        );
        assert!(
            failures
                .iter()
                .any(|row| row["canary"] == "direct-route" && row["name"] == "pod-gateway")
        );
    }

    /// ´test:unit:mount-canaries-accept-a-complete-refusing-box´
    #[test]
    fn mount_canaries_accept_a_complete_refusing_box() {
        let doors = [
            "/run/user/41001/bus",
            "/run/host",
            "/run/dbus/system_bus_socket",
            "/run/systemd/private",
            "/run/systemd/journal/socket",
            "/run/podman/podman.sock",
            "/run/user/41001/podman/podman.sock",
            "/var/run/docker.sock",
        ];
        let ancestors = [
            "/",
            "/home",
            "/home/worker",
            "/home/worker/.local",
            "/home/worker/.local/inbox",
        ];
        let probe = json!({
            "host_doors":doors.map(|path| json!({"path":path,"present":false})),
            "ancestors":ancestors.map(|path| json!({"path":path,"worker_writable":false,"create_succeeded":false,"rename_succeeded":false})),
            "direct_routes":{"default_route":false,"nonloopback_routes":[],"ipv6_default_route":false,"ipv6_nonloopback_routes":[],"trials":[
                {"name":"external-test-net","address":"198.51.100.1","result":"ENETUNREACH","refused":true},
                {"name":"pod-gateway","address":"10.88.0.1","result":"ENETUNREACH","refused":true},
                {"name":"rootless-gateway","address":"10.0.2.2","result":"ENETUNREACH","refused":true},
                {"name":"ipv6-documentation","address":"2001:db8::1","result":"ENETUNREACH","refused":true}
            ]}
        });
        assert_eq!(
            compare_canaries(&probe).expect("complete canaries")["verdict"],
            "pass"
        );
        let mut ipv6_open = probe.clone();
        ipv6_open["direct_routes"]["ipv6_default_route"] = json!(true);
        assert!(
            compare_canaries(&ipv6_open).expect("ipv6 route")["failures"]
                .as_array()
                .expect("failures")
                .iter()
                .any(|row| row["reason"] == "ipv6 default route exists")
        );
        let mut ipv6_connection = probe.clone();
        ipv6_connection["direct_routes"]["trials"][3]["refused"] = json!(false);
        ipv6_connection["direct_routes"]["trials"][3]["result"] = json!("CONNECTED");
        assert!(
            compare_canaries(&ipv6_connection).expect("ipv6 connection")["failures"]
                .as_array()
                .expect("failures")
                .iter()
                .any(|row| row["name"] == "ipv6-documentation")
        );
        let mut ipv6_absent = probe;
        ipv6_absent["direct_routes"]["ipv6_default_route"] = Value::Null;
        assert_eq!(
            compare_canaries(&ipv6_absent).expect("ipv6 absent")["verdict"],
            "unmeasured"
        );
        assert_eq!(
            compare_canaries(&ipv6_absent).expect("ipv6 reason")["unmeasured"][0]["unmeasured"],
            "ipv6 route table"
        );
    }
}
