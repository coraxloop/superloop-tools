//! Measure the resource controllers in a probe box with the run's recorded options.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{SFlag, fstat};
use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::plan::Plan;
use crate::settings::Settings;

const PROBE: &str = r"
import errno, json, os, stat
def directory(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        raise OSError(errno.ENOTDIR, name)
    return fd
def read(parent, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return {'state': 'wrong-type'}
            data = os.read(fd, 65)
            if len(data) > 64:
                return {'state': 'too-large'}
            return {'state': 'present', 'value': data.decode('ascii').strip()}
        finally:
            os.close(fd)
    except OSError as error:
        return {'state': 'missing' if error.errno == errno.ENOENT else 'unreadable', 'errno': errno.errorcode.get(error.errno, 'UNKNOWN')}
result = {'frame': 'box-cgroup-v2', 'worker_uid': os.geteuid(), 'files': {}}
try:
    root = directory(None, '/')
    try:
        system = directory(root, 'sys')
        try:
            cgroup = directory(system, 'fs')
            try:
                anchor = directory(cgroup, 'cgroup')
                try:
                    for name in ('memory.max', 'pids.max', 'cpu.weight'):
                        result['files'][name] = read(anchor, name)
                finally:
                    os.close(anchor)
            finally:
                os.close(cgroup)
        finally:
            os.close(system)
    finally:
        os.close(root)
except OSError as error:
    result['mount_error'] = errno.errorcode.get(error.errno, 'UNKNOWN')
print(json.dumps(result, sort_keys=True))
";

/// Read one bounded kernel identity map through held proc descriptors.
///
/// # Errors
///
/// Refuses a missing, changed or oversized map.
pub fn map_bytes(name: &str) -> Result<String, LaneError> {
    let root = open(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|error| LaneError::input("uid-map", error.to_string()))?;
    let mut parent = root;
    for component in ["proc".to_owned(), std::process::id().to_string()] {
        parent = openat2(
            &parent,
            component.as_str(),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| LaneError::input("uid-map", format!("{component}: {error}")))?;
        let stat =
            fstat(&parent).map_err(|error| LaneError::input("uid-map", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Err(LaneError::input(
                "uid-map",
                format!("{component} is not a directory"),
            ));
        }
    }
    let fd: OwnedFd = openat2(
        &parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("uid-map", format!("{name}: {error}")))?;
    let stat = fstat(&fd).map_err(|error| LaneError::input("uid-map", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(LaneError::input(
            "uid-map",
            format!("{name} is not a regular file"),
        ));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("uid-map", format!("{name}: {error}")))?;
    if bytes.len() > 4096 {
        return Err(LaneError::input(
            "uid-map",
            format!("{name} exceeds 4096 bytes"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| LaneError::input("uid-map", format!("{name}: {error}")))
}

fn block_mapped(source: &str, base: u32, count: u32) -> bool {
    let end = u64::from(base) + u64::from(count);
    let mut ranges = Vec::new();
    for line in source.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let [inside, outside, length] = fields.as_slice() else {
            return false;
        };
        let Ok((inside, outside, length)) = inside
            .parse::<u64>()
            .and_then(|inside| outside.parse::<u64>().map(|outside| (inside, outside)))
            .and_then(|(inside, outside)| {
                length
                    .parse::<u64>()
                    .map(|length| (inside, outside, length))
            })
        else {
            return false;
        };
        if length == 0
            || inside.checked_add(length).is_none()
            || outside.checked_add(length).is_none()
        {
            return false;
        }
        ranges.push((inside, inside + length));
    }
    ranges.sort_unstable();
    let mut covered = u64::from(base);
    for (start, stop) in ranges {
        if start > covered {
            break;
        }
        covered = covered.max(stop);
        if covered >= end {
            return true;
        }
    }
    false
}

fn verify_map_sources(uid: &str, gid: &str, base: u32, count: u32) -> Result<(), LaneError> {
    for (name, source) in [("uid_map", uid), ("gid_map", gid)] {
        if !block_mapped(source, base, count) {
            return Err(LaneError::input(
                "uid-map",
                format!("{name} does not map worker block {base}..{}", base + count),
            ));
        }
    }
    Ok(())
}

/// Verify that the rootless namespace maps every allocated worker user and group.
///
/// # Errors
///
/// Refuses a missing or incomplete identity map before the worker home is created.
pub(super) fn verify_worker_block(base: u32, count: u32) -> Result<(), LaneError> {
    verify_map_sources(&map_bytes("uid_map")?, &map_bytes("gid_map")?, base, count)
}

fn expected(record: &Value, settings: &Settings) -> Result<Value, LaneError> {
    let resources = settings.resources.as_ref().ok_or_else(|| {
        LaneError::input(
            "exercise-resources-record",
            "resources is absent in workers.toml",
        )
    })?;
    let expected = json!({"memory_bytes":resources.memory_bytes,"pids_max":resources.pids_max,"cpu_shares":resources.cpu_shares,"cpu_weight_requested":resources.cpu_weight_requested()});
    if record["plan"]["resources"]
        .as_object()
        .is_none_or(|resources| !resources.contains_key("cpu_weight_requested"))
    {
        return Err(LaneError::input(
            "exercise-resources-record",
            "recorded plan predates resources.cpu_weight_requested",
        ));
    }
    if record["plan"]["resources"] != expected {
        return Err(LaneError::input(
            "exercise-resources-record",
            "recorded resources differ from workers.toml",
        ));
    }
    Ok(expected)
}

fn claim(observed: &Value, name: &str, target: u64) -> Value {
    let file = &observed["files"][name];
    let value = file["value"]
        .as_str()
        .and_then(|word| word.parse::<u64>().ok());
    let verdict = if file["state"] == "present" && value == Some(target) {
        "pass"
    } else {
        "fail"
    };
    json!({"verdict":verdict,"file":name,"expected":target,"measured":file["value"],"state":file["state"],"reason":if verdict == "pass" {format!("{name} matches the recorded limit")} else if file["state"] != "present" {format!("{name} controller file is absent or unreadable")} else if file["value"] == "max" {format!("{name} is unlimited")} else if value.is_none() {format!("{name} is not a numeric limit")} else {format!("{name} differs from the recorded limit")}})
}

fn compare(loop_name: &str, run: &str, expected: &Value, observed: &Value, worker: u64) -> Value {
    let claims = json!({
        "memory.max":claim(observed, "memory.max", expected["memory_bytes"].as_u64().unwrap_or(0)),
        "pids.max":claim(observed, "pids.max", expected["pids_max"].as_u64().unwrap_or(0)),
        "cpu.weight":claim(observed, "cpu.weight", expected["cpu_weight_requested"].as_u64().unwrap_or(0)),
        "worker_uid":{"verdict":if observed["worker_uid"] == worker {"pass"} else {"fail"},"expected":worker,"measured":observed["worker_uid"]}
    });
    let verdict = if claims
        .as_object()
        .is_some_and(|claims| claims.values().all(|claim| claim["verdict"] == "pass"))
    {
        "pass"
    } else {
        "fail"
    };
    json!({"schema":1,"command":"exercise","case":"resources","loop":loop_name,"run":run,"expected":expected,"measured":observed,"claims":claims,"verdict":verdict,"changed":false})
}

fn vector(plan: &Value, loop_name: &str, run: &str) -> Result<Vec<String>, LaneError> {
    crate::plan::verify_box_attestation(plan)?;
    let image = plan["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("exercise-resources-record", "image digest is absent"))?;
    let mut words = plan["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-resources-record", "runtime vector is absent"))?
        .iter()
        .map(|word| {
            word.as_str().map(str::to_owned).ok_or_else(|| {
                LaneError::input("exercise-resources-record", "runtime word is not text")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let image_index = words
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("exercise-resources-record", "runtime image is absent"))?;
    words.truncate(image_index + 1);
    words.retain(|word| {
        !word.starts_with("--cidfile=")
            && !word.starts_with("--label=org.superloop.run=")
            && !word.starts_with("--label=org.superloop.loop=")
    });
    let name = words
        .iter_mut()
        .find(|word| word.starts_with("--name="))
        .ok_or_else(|| LaneError::input("exercise-resources-record", "container name is absent"))?;
    *name = format!(
        "--name=superloop-resource-probe-{}",
        super::checkpoint::random_token()?
    );
    let image_index = words
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("exercise-resources-record", "runtime image moved"))?;
    words.insert(image_index, "--rm".into());
    words.insert(
        image_index + 1,
        "--label=org.superloop.probe=resources".into(),
    );
    words.insert(
        image_index + 2,
        super::probe::identity_option(loop_name, run),
    );
    words.extend(["/usr/bin/python3".into(), "-c".into(), PROBE.into()]);
    Ok(words)
}

/// Probe the recorded box options and compare its live controller files.
///
/// # Errors
///
/// Refuses malformed recorded resources or an unavailable container program.
pub(in crate::launch) fn measure(
    owner_home: &Path,
    plan: &Plan,
    settings: &Settings,
    record: &Value,
    loop_name: &str,
    run: &str,
) -> Result<Value, LaneError> {
    let expected = expected(record, settings)?;
    let worker = record["plan"]["worker_uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("exercise-resources-record", "worker UID is absent"))?;
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-resources-record", "rounds are absent"))?;
    if rounds.is_empty() || rounds.iter().any(|round| round["phase"] != "settled") {
        return Ok(
            json!({"schema":1,"command":"exercise","case":"resources","loop":loop_name,"run":run,"expected":expected,"measured":null,"claims":{},"verdict":"unmeasured","reason":"run is not settled","changed":false}),
        );
    }
    if record["plan"]["home"] != plan.home.display().to_string() {
        return Err(LaneError::input(
            "exercise-resources-record",
            "worker home differs from the plan",
        ));
    }
    let words = vector(&record["plan"], loop_name, run)?;
    if words.first().is_none_or(|word| word != "/usr/bin/podman") {
        return Err(LaneError::input(
            "exercise-resources-record",
            "container program differs from the launch route",
        ));
    }
    crate::pinned::owner_executable(
        Path::new("/usr/bin/podman"),
        nix::unistd::Uid::effective().as_raw(),
    )?;
    let probe_name = super::probe::name(&words, "superloop-resource-probe-")?;
    let environment = super::launch_environment(owner_home)?;
    let output = build::run_checked(
        Path::new("/usr/bin/podman"),
        words[1..].to_vec(),
        &environment,
        owner_home,
        60,
        "exercise-resources",
    );
    if let Err(error) = super::probe::remove(
        Path::new("/usr/bin/podman"),
        owner_home,
        &environment,
        probe_name,
        "resources",
        loop_name,
        run,
    ) {
        return Ok(
            json!({"schema":1,"command":"exercise","case":"resources","loop":loop_name,"run":run,"expected":expected,"measured":null,"claims":{},"verdict":"unmeasured","reason":error.line(),"changed":false}),
        );
    }
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            return Ok(
                json!({"schema":1,"command":"exercise","case":"resources","loop":loop_name,"run":run,"expected":expected,"measured":null,"claims":{},"verdict":"unmeasured","reason":error.line(),"changed":false}),
            );
        }
    };
    let observed: Value = serde_json::from_str(output.trim()).map_err(|error| {
        LaneError::input(
            "exercise-resources",
            format!("probe output is malformed: {error}"),
        )
    })?;
    Ok(compare(loop_name, run, &expected, &observed, worker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture_settings() -> Settings {
        Settings {
            runs_root: None,
            backend_argv: BTreeMap::default(),
            driver_argv: Vec::new(),
            entry_bin: None,
            driver_bin: None,
            image_digest: None,
            template_dir: None,
            resources: Some(crate::settings::Resources {
                memory_bytes: 2_147_483_648,
                pids_max: 128,
                cpu_shares: 512,
            }),
            socket_dir: None,
            vendor_hosts: BTreeMap::default(),
            sandbox_mode: String::new(),
            context_threshold: None,
            retention: String::new(),
            source: String::new(),
        }
    }

    /// ´test:unit:fixture-cgroup-files-compare-by-controller´
    #[test]
    fn fixture_cgroup_files_compare_by_controller() {
        let expected = json!({"memory_bytes":2_147_483_648_u64,"pids_max":128,"cpu_shares":512,"cpu_weight_requested":59});
        let mut observed = json!({"frame":"box-cgroup-v2","worker_uid":3000,"files":{"memory.max":{"state":"present","value":"2147483648"},"pids.max":{"state":"present","value":"128"},"cpu.weight":{"state":"present","value":"59"}}});
        let pass = compare("alpha", "R", &expected, &observed, 3000);
        assert_eq!(pass["verdict"], "pass");
        assert_eq!(pass["case"], "resources");
        assert_eq!(pass["schema"], 1);
        assert_eq!(pass["command"], "exercise");
        assert_eq!(pass["changed"], false);
        assert!(pass["claims"].get("frame").is_none());
        observed["files"]["memory.max"]["value"] = json!("max");
        observed["files"]["pids.max"] = json!({"state":"missing","errno":"ENOENT"});
        observed["files"]["cpu.weight"]["value"] = json!("100");
        let fail = compare("alpha", "R", &expected, &observed, 3000);
        assert_eq!(fail["verdict"], "fail");
        assert_eq!(
            fail["claims"]["memory.max"]["reason"],
            "memory.max is unlimited"
        );
        assert_eq!(fail["claims"]["pids.max"]["verdict"], "fail");
        assert_eq!(fail["claims"]["cpu.weight"]["measured"], "100");
        assert_eq!(fail["claims"]["cpu.weight"]["verdict"], "fail");
        assert_eq!(
            fail["claims"]["cpu.weight"]["reason"],
            "cpu.weight differs from the recorded limit"
        );
        observed["files"]["memory.max"]["value"] = json!("2147483648");
        observed["files"]["pids.max"] = json!({"state":"present","value":"128"});
        observed["files"]["cpu.weight"]["value"] = json!("59");
        observed["worker_uid"] = json!(3001);
        assert_eq!(
            compare("alpha", "R", &expected, &observed, 3000)["claims"]["worker_uid"]["verdict"],
            "fail"
        );
        assert_eq!(
            compare("alpha", "R", &expected, &observed, 3001)["verdict"],
            "pass"
        );
    }

    /// ´test:unit:fixture-cgroup-file-refusals-are-named´
    #[test]
    fn fixture_cgroup_file_refusals_are_named() {
        let expected = json!({"memory_bytes":2_147_483_648_u64,"pids_max":128,"cpu_shares":512,"cpu_weight_requested":59});
        let mut observed = json!({"frame":"box-cgroup-v2","worker_uid":3000,"files":{"memory.max":{"state":"missing","errno":"ENOENT"},"pids.max":{"state":"unreadable","errno":"EACCES"},"cpu.weight":{"state":"wrong-type"}}});
        let failed = compare("alpha", "R", &expected, &observed, 3000);
        assert_eq!(failed["verdict"], "fail");
        for name in ["memory.max", "pids.max", "cpu.weight"] {
            assert_eq!(failed["claims"][name]["verdict"], "fail");
            assert_eq!(
                failed["claims"][name]["reason"],
                format!("{name} controller file is absent or unreadable")
            );
        }
        observed["mount_error"] = json!("ENOENT");
        observed["files"] = json!({});
        let failed_mount = compare("alpha", "R", &expected, &observed, 3000);
        assert_eq!(failed_mount["measured"]["mount_error"], "ENOENT");
        assert_eq!(failed_mount["verdict"], "fail");
        assert_eq!(failed_mount["claims"]["cpu.weight"]["verdict"], "fail");
    }

    /// ´test:unit:pinned-plan-probe-keeps-attested-box-options´
    #[test]
    fn pinned_plan_probe_keeps_attested_box_options() {
        let plan: Value = serde_json::from_str(include_str!("../../tests/fixtures/plan.json"))
            .expect("pinned plan fixture");
        let words = vector(&plan, "alpha", "R").expect("attested runtime vector");
        assert_eq!(words.first().map(String::as_str), Some("/usr/bin/podman"));
        assert!(words.iter().any(|word| word == "--memory=2147483648"));
        assert!(words.iter().any(|word| word == "--pids-limit=128"));
        assert!(words.iter().any(|word| word == "--cpu-shares=512"));
        assert!(words.iter().any(|word| word == "--rm"));
        assert!(words.iter().all(|word| !word.starts_with("--cidfile=")));
        assert!(
            words
                .iter()
                .all(|word| !word.starts_with("--label=org.superloop.run="))
        );
        assert!(
            words
                .iter()
                .all(|word| !word.starts_with("--label=org.superloop.loop="))
        );
        assert!(
            words
                .iter()
                .any(|word| word == "--label=org.superloop.probe=resources")
        );
        assert!(
            words
                .iter()
                .any(|word| word == "--label=org.superloop.probe.identity=alpha/R")
        );
        assert_eq!(words[words.len() - 3], "/usr/bin/python3");
        assert_eq!(words[words.len() - 2], "-c");
        assert_eq!(words[words.len() - 1], PROBE);
    }

    /// ´test:unit:older-resource-record-refuses-by-shape´
    #[test]
    fn older_resource_record_refuses_by_shape() {
        let record = json!({"plan":{"resources":{"memory_bytes":2_147_483_648_u64,"pids_max":128,"cpu_shares":512}}});
        let error = expected(&record, &fixture_settings()).expect_err("older plan");
        assert_eq!(error.kind, "exercise-resources-record");
        assert!(
            error
                .line()
                .contains("predates resources.cpu_weight_requested")
        );
    }

    /// ´test:unit:allocated-block-must-be-fully-mapped´
    #[test]
    fn allocated_block_must_be_fully_mapped() {
        assert!(block_mapped("0 41001 1\n3000 100000 2\n", 3000, 2));
        assert!(!block_mapped("0 41001 1\n3000 100000 1\n", 3000, 2));
        assert!(!block_mapped(
            "0 41001 1\n3000 100000 1\n3002 100002 1\n",
            3000,
            3
        ));
        let mapped = "0 41001 1\n3000 100000 2\n";
        let short = "0 41001 1\n3000 100000 1\n";
        let uid = verify_map_sources(short, mapped, 3000, 2).expect_err("unmapped user");
        assert_eq!(uid.kind, "uid-map");
        assert!(uid.line().contains("uid_map"));
        let gid = verify_map_sources(mapped, short, 3000, 2).expect_err("unmapped group");
        assert_eq!(gid.kind, "uid-map");
        assert!(gid.line().contains("gid_map"));
    }
}
