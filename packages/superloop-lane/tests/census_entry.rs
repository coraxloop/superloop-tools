//! Credential evidence observations through the production census command.

#[path = "support/entry.rs"]
mod entry;

use entry::retry_busy_entry;

#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::Digest as _;

struct Fixture {
    home: tempfile::TempDir,
    runs: PathBuf,
}

/// ´test:integration:lane-retired-setting-names-the-driver-vector´
#[test]
fn lane_retired_setting_names_the_driver_vector() {
    let fixture = Fixture::new();
    let settings = fixture.home.path().join(".config/loops/alpha/workers.toml");
    let installed = installed_entry();
    let programs = tempfile::TempDir::new_in("/var/tmp").expect("protected alias directory");
    let alias = programs.path().join("lane-link");
    std::os::unix::fs::symlink(installed, &alias).expect("lane alias");
    let driver = fs::canonicalize(&alias).expect("resolved lane executable");
    loop_home::workers_settings::owner_executable(&driver, nix::unistd::Uid::effective().as_raw())
        .expect("verified driver");
    let run = || {
        retry_busy_entry(|| {
            Command::new(&alias)
                .args(["census", "alpha"])
                .env("HOME", fixture.home.path())
                .env_remove("ENTER_LOOP_REGISTRY")
                .output()
        })
        .expect("lane settings refusal")
    };
    write(&settings, "driver_bin = '/retired/codex-lane'\n");
    let output = run();
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stderr);
    let expected = format!(
        "retired-setting: driver_bin; set driver_argv = [{}, \"driver\", \"start\", \"--backend\", \"codex\"]",
        toml::Value::String(driver.to_string_lossy().into_owned())
    );
    assert!(text.contains(&expected), "{text}");
    write(&settings, "never_valid = true\n");
    let output = run();
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains(&format!(
            "unknown-setting: {}: never_valid",
            settings.display()
        )),
        "{text}"
    );
}

// Publish one protected copy per process before any fixture executes it. Other
// threads may still fork during initialization, so executions also retry ETXTBSY.
static ENTRY: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();

fn remove_entry_directory(path: &Path) {
    drop(fs::remove_dir_all(path));
}

extern "C" fn remove_installed_entry() {
    if let Some((directory, _)) = ENTRY.get() {
        remove_entry_directory(directory.path());
    }
}

fn installed_entry() -> &'static Path {
    &ENTRY
        .get_or_init(|| {
            let directory =
                tempfile::TempDir::new_in("/var/tmp").expect("protected entry directory");
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("private entry directory");
            let binary = directory.path().join("superloop-lane");
            fs::copy(env!("CARGO_BIN_EXE_superloop-lane"), &binary).expect("production entry");
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).expect("entry mode");
            // The static owner is never dropped; exit is when all tests are done.
            // SAFETY: the callback has the required C ABI, outlives the process,
            // and neither unwinds nor accesses a dropped static owner.
            #[allow(unsafe_code)]
            let registered = unsafe { libc::atexit(remove_installed_entry) };
            assert_eq!(registered, 0);
            (directory, binary)
        })
        .1
}

/// # Panics
/// Panics only if fixture creation or directory removal fails.
/// ´test:integration:installed-entry-removal-tolerates-absence´
#[test]
fn installed_entry_removal_tolerates_absence() {
    let directory = tempfile::TempDir::new().expect("entry directory");
    fs::write(directory.path().join("superloop-lane"), b"fixture").expect("entry file");
    remove_entry_directory(directory.path());
    assert!(!directory.path().exists());
    remove_entry_directory(directory.path());
    assert!(!directory.path().exists());
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).expect("fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("fixture file mode");
}

fn directory(path: &Path) {
    fs::create_dir_all(path).expect("fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("fixture directory mode");
}

impl Fixture {
    fn new() -> Self {
        // The production custody walk rejects the node's group-writable lane ancestor.
        // Only these tiny synthetic records use /tmp; build artifacts stay in the lane root.
        let home = tempfile::TempDir::new_in("/tmp").expect("fixture home");
        let config = home.path().join(".config/loops/alpha");
        for path in [
            home.path().to_path_buf(),
            home.path().join(".config"),
            home.path().join(".config/loops"),
            config.clone(),
        ] {
            directory(&path);
        }
        let runs = home.path().join("runs");
        directory(&runs);
        write(
            &home.path().join(".config/loops/registry.toml"),
            format!(
                "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n",
                runs.display()
            ),
        );
        write(
            &home.path().join(".config/loops/allocations.toml"),
            "[alpha]\nuids = { base = 3000, count = 2 }\n",
        );
        write(
            &config.join("workers.toml"),
            format!(
                "runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
                runs.display(),
                "a".repeat(64),
                home.path().join("template").display(),
                home.path().join("sockets").display()
            ),
        );
        for (run, worker) in [("R", 3000), ("S", 3001)] {
            write(&runs.join(format!(".reservation-{run}.json")), json!({"schema":1,"phase":"started","loop":"alpha","run":run,"worker_uid":worker,"observer_state":"not-started","plan":{}}).to_string());
            directory(&runs.join(format!(".launch-{run}")));
            write(
                &runs.join(format!(".launch-{run}/credential-refresh.json")),
                evidence().to_string(),
            );
        }
        let retired = runs.join(".retired-R-20-1-2");
        write(&retired, json!({"schema":1,"phase":"retired","loop":"alpha","run":"R","worker_uid":3001,"observer_state":"not-started","current_retirement":{"reservation_path":{"target":retired},"planned_paths":[]},"plan":{}}).to_string());
        Self { home, runs }
    }

    fn path(&self) -> PathBuf {
        self.runs.join(".launch-R/credential-refresh.json")
    }

    fn command(&self) -> Output {
        self.invoke(&["census", "alpha"])
    }

    fn invoke(&self, args: &[&str]) -> Output {
        retry_busy_entry(|| self.invocation(args).output()).expect("census entry")
    }

    fn invocation(&self, args: &[&str]) -> Command {
        let library = self.home.path().join("report-custody.so");
        let binary = if library.exists() {
            installed_entry().to_path_buf()
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_superloop-lane"))
        };
        let mut command = Command::new(binary);
        command
            .args(args)
            .env("HOME", self.home.path())
            .env_remove("ENTER_LOOP_REGISTRY");
        if library.exists() {
            command.env("LD_PRELOAD", library).env(
                "REPORT_FIXTURE_RUN",
                self.runs.join(args.get(2).copied().unwrap_or("R")),
            );
        }
        command
    }

    fn row(&self) -> Value {
        let output = self.command();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("census JSON");
        assert_eq!(report["reservations"].as_array().expect("rows").len(), 2);
        assert_eq!(report["reservations"][0]["worker_uid"], 3000);
        assert_eq!(report["reservations"][1]["worker_uid"], 3001);
        assert_eq!(
            report["reservations"][1]["credential_refresh"]["state"],
            "measured"
        );
        let retired = &report["retired_records"][0]["credential_refresh"];
        assert_eq!(retired["reason"], "retired");
        assert!(
            retired
                .get("expires_unix")
                .expect("retired expiry key")
                .is_null()
        );
        assert!(
            retired
                .get("refresh_due_unix")
                .expect("retired due key")
                .is_null()
        );
        report["reservations"][0]["credential_refresh"].clone()
    }
}

/// # Panics
/// Panics only if fixture creation fails or census confuses run-name digits with retirement fields.
/// ´test:integration:census-retired-run-ending-in-twenty-keeps-entry-kinds´
#[test]
fn census_retired_run_ending_in_twenty_keeps_entry_kinds() {
    for suffix in ["", ".1"] {
        let fixture = Fixture::new();
        let archive = fixture.runs.join(format!(".retired-X-20-20-1-3{suffix}"));
        let mut record: Value = serde_json::from_slice(
            &fs::read(fixture.runs.join(".retired-R-20-1-2")).expect("retired fixture"),
        )
        .expect("record");
        record["run"] = json!("X-20");
        record["current_retirement"]["reservation_path"]["target"] = json!(archive);
        write(&archive, record.to_string());
        directory(&fixture.runs.join(".retired-X-20-0-1-4"));
        write(
            &fixture.runs.join(".retired-X-20-21-1-5"),
            b"not a reservation",
        );
        let report = success(&fixture.command());
        assert!(
            report["retired_records"]
                .as_array()
                .expect("retired rows")
                .iter()
                .any(|row| row["run"] == "X-20")
        );
        for name in [".retired-X-20-0-1-4", ".retired-X-20-21-1-5"] {
            assert!(
                report["skipped_names"]
                    .as_array()
                    .expect("skipped names")
                    .contains(&json!(name))
            );
        }
    }
}

fn historical(refused: bool) -> Value {
    if refused {
        json!({"schema":1,"host":"auth.openai.com","state":"refused","kind":"credential-refresh","detail":"fixture authority refusal"})
    } else {
        json!({"schema":1,"host":"auth.openai.com","state":"published","run_refusals":[]})
    }
}

fn rewrite_fixture(worker: u32, refused: bool) -> Fixture {
    let fixture = Fixture::new();
    let runtime = fixture.home.path().join("runtime");
    write(&runtime, "#!/bin/sh\nexit 0\n");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("runtime mode");
    write(&fixture.runs.join(".prepare-R.lock"), "");
    let dead = u32::MAX - worker;
    let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,
        "plan":{"driver_dir":fixture.runs.join("R"),"home":fixture.home.path().join(".cache/tmp/lane-alpha-R"),"runtime_argv":[runtime]},
        "launcher_pid":dead,"launcher_start":worker,"driver_entry_pid":dead,"driver_entry_start":worker,
        "helper_pid":dead,"helper_start":worker,"helper_parent_pid":dead,"helper_parent_start":worker,
        "observer_state":"ended","observer_pid":dead,"observer_start":worker});
    write(
        &fixture.runs.join(".reservation-R.json"),
        record.to_string(),
    );
    let peer_path = fixture.runs.join(".reservation-S.json");
    let mut peer: Value =
        serde_json::from_slice(&fs::read(&peer_path).expect("peer record")).expect("peer JSON");
    peer["worker_uid"] = json!(if worker == 3000 { 3001 } else { 3000 });
    write(&peer_path, peer.to_string());
    write(&fixture.path(), format!("{}\n", historical(refused)));
    fixture
}

fn success(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command JSON")
}

fn preparing_retirement_fixture() -> Fixture {
    let fixture = Fixture::new();
    let home = fixture.home.path();
    let runtime = home.join("runtime");
    directory(&home.join("sockets"));
    private_retirement_runtime(&fixture, &runtime);
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("runtime mode");
    let unit = format!(
        "superloop-lane-run-entry-{}.service",
        home.file_name().expect("name").to_string_lossy()
    );
    let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,
        "imports":[],"harvest_agreement":null,"collection":null,
        "plan":{"home":home.join(".cache/tmp/lane-alpha-R"),"driver_dir":fixture.runs.join("R"),"runtime_argv":[runtime],"paths":[{"path":home.join(".cache/tmp/lane-alpha-R"),"gid":41001},{"path":fixture.runs.join("R"),"kind":"directory","uid":41001,"gid":41001}],"vendor_mode":"observe","vendor_socket":"proxy-R.sock","mounts":[{"target":"/home/worker/.local/vendor","source":home.join("sockets")}]},
        "launcher_pid":u32::MAX,"launcher_start":1,"observer_state":"not-started","helper_spawn_state":"not-started","probe_starts":[],
        "run_scope":{"unit":unit,"cgroup":format!("/{unit}/work"),"device":1,"inode":2}});
    write(
        &fixture.runs.join(".reservation-R.json"),
        record.to_string(),
    );
    write(&fixture.runs.join(".prepare-R.lock"), b"");
    fixture
}

// Reuse the custody model, including protected /tmp ancestry, for the new private
// lock entry. This exercises production code without claiming kernel uid separation.
fn private_retirement_runtime(fixture: &Fixture, runtime: &Path) {
    let home = fixture.home.path();
    let library = home.join("report-custody.so");
    let output = Command::new("/usr/bin/cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/report_custody.c"))
        .arg("-ldl")
        .output()
        .expect("compile custody model");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    write(runtime, br"#!/usr/bin/python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args == ['ps'] or args[0] == 'ps':
    sys.exit(0)
assert args[0] == 'unshare'
home = pathlib.Path(os.environ['HOME'])
run = args[4]
record = json.loads((home / 'runs' / ('.reservation-' + run + '.json')).read_text())
driver = pathlib.Path(record['plan']['driver_dir'])
if not driver.exists():
    for pair in record.get('current_retirement', {}).get('planned_paths', []):
        if pair['source'] == str(driver):
            driver = pathlib.Path(pair['target'])
            break
env = dict(os.environ, LD_PRELOAD=str(home / 'report-custody.so'), REPORT_FIXTURE_PRIVATE='1', REPORT_FIXTURE_RUN=str(driver))
os.execve(args[1], args[1:], env)
");
}

/// # Panics
/// Panics only if fixture custody cannot be built or the binary violates the absence contract.
/// ´test:integration:retirement-node-absence-through-built-entry´
#[test]
#[cfg(debug_assertions)]
#[allow(clippy::too_many_lines)]
fn retirement_node_absence_through_built_entry() {
    for shape in ["absent", "present", "held", "timeout"] {
        let fixture = preparing_retirement_fixture();
        let home = fixture.home.path();
        let run = format!("absence-{}-{shape}", std::process::id());
        let old = fixture.runs.join(".reservation-R.json");
        let path = fixture.runs.join(format!(".reservation-{run}.json"));
        let mut record: Value =
            serde_json::from_slice(&fs::read(&old).expect("record")).expect("JSON");
        record["run"] = json!(run);
        record["launcher_pid"] = Value::Null;
        record["launcher_start"] = Value::Null;
        record["plan"]["home"] = json!(home.join(format!(".cache/tmp/lane-alpha-{run}")));
        record["plan"]["driver_dir"] = json!(fixture.runs.join(&run));
        record["plan"]["paths"][0]["path"] = record["plan"]["home"].clone();
        record["plan"]["paths"][1]["path"] = record["plan"]["driver_dir"].clone();
        write(&path, record.to_string());
        fs::remove_file(old).expect("replace run");
        fs::rename(
            fixture.runs.join(".prepare-R.lock"),
            fixture.runs.join(format!(".prepare-{run}.lock")),
        )
        .expect("rename lease");
        let config = home.join(".config/loops/alpha");
        let node = home.join("node");
        directory(&node);
        write(
            &config.join("door-compute-registration.json"),
            json!({"schema":1,"loop":"alpha",
            "alias":"fixture","mirror_root":"~/mirrors","node_root":node,
            "key_path":config.join("door-key")})
            .to_string(),
        );
        write(
            &config.join("door-ssh_config"),
            format!(
                "# Registered host key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nHost fixture\n  HostName fixture.invalid\n  Port 22\n  User fixture\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  BatchMode yes\n",
                config.join("door-known_hosts").display()
            ),
        );
        write(&config.join("door-node-registration.json"), json!({"schema":1,"loop":"alpha","alias":"fixture","address":"fixture.invalid","port":22,"user":"fixture","host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).to_string());
        write(
            &config.join("door-known_hosts"),
            "fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
        write(&home.join("shape"), shape);
        write(&home.join("run"), &run);
        let ssh = home.join("fixture-ssh");
        write(
            &ssh,
            r"#!/usr/bin/python3
import fcntl, json, os, subprocess, sys, time
from pathlib import Path
home = Path(__file__).parent
run = (home / 'run').read_text()
shape = (home / 'shape').read_text()
args = sys.argv[1:]
assert args[:2] == ['-F', 'none']
assert 'BatchMode=yes' in args and 'ConnectTimeout=10' in args
assert args[-2] == 'fixture'
probe = '--absence=' + run in args[-1]
if probe:
    assert 'timeout -k 5 15' in args[-1]
with (home / 'ssh-calls').open('a') as log:
    log.write(json.dumps({'probe': probe, 'args': args}) + '\n')
os.environ['HOME'] = str(home / 'node')
child = None
lock = None
try:
    if probe and shape == 'timeout':
        time.sleep(60)
    if probe and shape == 'present':
        child = subprocess.Popen(['/bin/sh', '-c', 'read word', run], stdin=subprocess.PIPE)
    if probe and shape == 'held':
        lanes = home / 'node/lanes'
        lanes.mkdir(mode=0o700)
        lock = (lanes / (run + '.lock')).open('w')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    sys.exit(subprocess.run(['/bin/sh', '-c', args[-1]], check=False).returncode)
finally:
    if child is not None:
        child.kill()
        child.wait()
    if lock is not None:
        lock.close()
",
        );
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).expect("SSH mode");
        let invoke = |args: &[&str]| {
            retry_busy_entry(|| {
                fixture
                    .invocation(args)
                    .env("SUPERLOOP_LANE_TEST_RETIRE_SSH", &ssh)
                    .output()
            })
            .expect("binary entry")
        };
        let before = fs::read(&path).expect("before");
        let started = Instant::now();
        let output = invoke(&["retire", "alpha", &run, "--dry-run"]);
        assert_eq!(fs::read(&path).expect("unchanged preview"), before);
        if shape == "absent" {
            let preview = success(&output);
            let proof = &preview["retirement"]["journal"]["settlement"]["node"];
            assert_eq!(proof["state"], "absent");
            assert_eq!(proof["lock"], "absent");
            assert!(proof["host_wall_seconds"].as_f64().expect("wall") > 0.0);
            assert!(!node.join("lanes").exists());
            success(&invoke(&[
                "retire",
                "alpha",
                &run,
                "--expect-digest",
                preview["preview_sha256"].as_str().expect("digest"),
            ]));
            let calls = fs::read_to_string(home.join("ssh-calls")).expect("calls");
            assert_eq!(
                calls
                    .lines()
                    .filter(
                        |line| serde_json::from_str::<Value>(line).expect("call")["probe"] == true
                    )
                    .count(),
                2
            );
        } else {
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            if shape == "timeout" {
                assert!(
                    stderr.contains("retire-uncertain") && stderr.contains("deadline"),
                    "{stderr}"
                );
                assert!(started.elapsed() >= Duration::from_secs(30));
            } else {
                assert!(stderr.contains("retire-busy"), "{stderr}");
                if shape == "held" {
                    assert!(stderr.contains("held"), "{stderr}");
                }
            }
        }
    }
}

fn first_round_report(fixture: &Fixture) -> Value {
    json!({"schema":1,"command":"launch","dry_run":false,"observe":false,
        "enforcing":true,"observed":null,"home":fixture.home.path(),
        "driver_dir":fixture.runs.join("R"),"round_dir":fixture.runs.join("R/work-1"),
        "preparation":"complete","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"complete","settlement":{},
        "evidence":"driver directory outside home","wall_seconds":1.0})
}

/// # Panics
/// Panics only if synthetic retained reports violate the explicit rewrite contract.
/// ´test:integration:launch-report-rewrite-entry-preserves-measurements-and-retired-custody´
#[test]
#[allow(clippy::too_many_lines)]
fn launch_report_rewrite_entry_preserves_measurements_and_retired_custody() {
    let fixture = Fixture::new();
    let settings = fixture.home.path().join(".config/loops/alpha/workers.toml");
    let mut configured = fs::read_to_string(&settings).expect("fixture settings");
    configured.push_str("backend_argv = { codex = ['/usr/bin/true'] }\n");
    write(&settings, configured);
    let mut old = first_round_report(&fixture);
    old.as_object_mut()
        .expect("report object")
        .remove("credential_publication");
    let original = old.to_string();
    let active = fixture.runs.join(".report=R.json");
    write(&active, &original);
    let measured = fixture.runs.join(".report=S.json");
    let measured_bytes =
        serde_json::to_string_pretty(&first_round_report(&fixture)).expect("measured JSON");
    write(&measured, &measured_bytes);
    let measured_inode = fs::metadata(&measured).expect("measured metadata").ino();
    let retired = fixture.runs.join(".retired-R-21-1-3");
    write(&retired, &original);
    let journal = fixture.runs.join(".retired-R-20-1-2");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&journal).expect("journal bytes")).expect("journal JSON");
    record["current_retirement"]["planned_paths"] = json!([{"source":active,"target":retired}]);
    write(&journal, record.to_string());
    let refused = fixture.invoke(&["read-launch-report", "alpha", "R"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("read-launch-report"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let preview = success(&fixture.invoke(&["rewrite-launch-reports", "alpha", "--dry-run"]));
    assert_eq!(preview["changed"], 0);
    assert_eq!(preview["would_change"], 2);
    let rows = preview["reports"].as_array().expect("preview reports");
    for path in [&active, &retired] {
        assert!(
            rows.iter()
                .any(|row| row["path"] == json!(path) && row["verdict"] == "would-rewrite")
        );
        assert_eq!(
            fs::read(path).expect("preview preserves bytes"),
            original.as_bytes()
        );
    }
    let applied = success(&fixture.invoke(&["rewrite-launch-reports", "alpha"]));
    assert_eq!(applied["changed"], 2);
    let unmeasured = json!({"state":"unmeasured","reason":"written before publication evidence existed","source_inode":null,"published_unix_ns":null});
    for row in applied["reports"].as_array().expect("applied reports") {
        assert_eq!(row["verdict"], "rewritten");
        assert_eq!(row["credential_publication"], unmeasured);
    }
    for path in [&active, &retired] {
        let mut after: Value = serde_json::from_slice(&fs::read(path).expect("rewritten bytes"))
            .expect("rewritten JSON");
        assert_eq!(after["credential_publication"], unmeasured);
        after
            .as_object_mut()
            .expect("report object")
            .remove("credential_publication");
        assert_eq!(after, old);
        assert_eq!(
            fs::metadata(path).expect("report mode").mode() & 0o7777,
            0o600
        );
    }
    let read = success(&fixture.invoke(&["read-launch-report", "alpha", "R"]));
    assert_eq!(read["credential_publication"], unmeasured);
    let active_after = fs::read(&active).expect("converted bytes");
    let active_inode = fs::metadata(&active).expect("converted inode").ino();
    let repeated = success(&fixture.invoke(&["rewrite-launch-reports", "alpha"]));
    assert_eq!(repeated["changed"], 0);
    assert_eq!(repeated["reports"], json!([]));
    assert_eq!(
        fs::read(&active).expect("repeat preserves bytes"),
        active_after
    );
    assert_eq!(
        fs::metadata(&active).expect("repeat inode").ino(),
        active_inode
    );
    assert_eq!(
        fs::read(&measured).expect("measured bytes retained"),
        measured_bytes.as_bytes()
    );
    assert_eq!(
        fs::metadata(&measured)
            .expect("measured inode retained")
            .ino(),
        measured_inode
    );
    let measured_read = success(&fixture.invoke(&["read-launch-report", "alpha", "S"]));
    assert_eq!(measured_read["credential_publication"]["source_inode"], 42);
}

/// # Panics
/// Panics only if a rewritten report blocks retirement or loses retained custody.
/// ´test:integration:retirement-after-report-rewrite-keeps-both-inode-generations´
#[test]
#[allow(clippy::too_many_lines)]
fn retirement_after_report_rewrite_keeps_both_inode_generations() {
    let fixture = preparing_retirement_fixture();
    let settings = fixture.home.path().join(".config/loops/alpha/workers.toml");
    let mut configured = fs::read_to_string(&settings).expect("settings");
    configured.push_str("backend_argv = { codex = ['/usr/bin/true'] }\n");
    write(&settings, configured);
    let reservation = fixture.runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&reservation).expect("record")).expect("record JSON");
    record["phase"] = json!("started");
    for role in ["driver_entry", "helper", "helper_parent", "observer"] {
        record[format!("{role}_pid")] = json!(u32::MAX);
        record[format!("{role}_start")] = json!(1);
    }
    record["rounds"] = json!([
        {"step":"work-1","phase":"settled","report":".report=R.json"},
        {"step":"work-2","phase":"running"}
    ]);
    write(&reservation, record.to_string());
    let active = fixture.runs.join(".report=R.json");
    let measured = first_round_report(&fixture);
    write(&active, measured.to_string());
    let first = success(&fixture.invoke(&["retire", "alpha", "R"]));
    let archive = PathBuf::from(first["retirement"]["record"].as_str().expect("archive"));
    let mut archived: Value =
        serde_json::from_slice(&fs::read(&archive).expect("archive bytes")).expect("archive JSON");
    let retired = PathBuf::from(
        archived["current_retirement"]["planned_paths"]
            .as_array()
            .expect("paths")
            .iter()
            .find(|pair| pair["source"] == json!(active))
            .expect("report pair")["target"]
            .as_str()
            .expect("target"),
    );
    let original_inode = fs::metadata(&retired).expect("retired metadata").ino();
    let mut historical = measured.clone();
    historical
        .as_object_mut()
        .expect("report object")
        .remove("credential_publication");
    write(&retired, historical.to_string());
    let rewritten = success(&fixture.invoke(&["rewrite-launch-reports", "alpha"]));
    assert_eq!(rewritten["changed"], 1);
    assert_ne!(
        fs::metadata(&retired).expect("rewritten metadata").ino(),
        original_inode
    );
    let retained_bytes = fs::read(&retired).expect("retained report");
    write(&reservation, record.to_string());
    write(&active, measured.to_string());
    // Model allocator reuse deterministically: the rewritten report's name encodes
    // the new active inode, while its journal still identifies the retained file.
    // Both reports keep the production reader's required single-link custody.
    let metadata = fs::metadata(&active).expect("active metadata");
    let collision = fixture.runs.join(format!(
        ".retired-R-21-{}-{}",
        metadata.dev(),
        metadata.ino()
    ));
    fs::rename(&retired, &collision).expect("model reused inode name");
    for pair in archived["current_retirement"]["planned_paths"]
        .as_array_mut()
        .expect("paths")
    {
        if pair["source"] == json!(active) {
            pair["target"] = json!(collision);
        }
    }
    write(&archive, archived.to_string());
    let retired = collision;
    let preview_output = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
    assert!(!String::from_utf8_lossy(&preview_output.stderr).contains("is occupied"));
    let preview = success(&preview_output);
    let second = success(&fixture.invoke(&[
        "retire",
        "alpha",
        "R",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    let second_archive = second["retirement"]["record"]
        .as_str()
        .expect("second archive");
    let mut second_record: Value =
        serde_json::from_slice(&fs::read(second_archive).expect("second bytes"))
            .expect("second JSON");
    let suffixed = PathBuf::from(format!("{}.1", retired.display()));
    assert!(
        second_record["current_retirement"]["planned_paths"]
            .as_array()
            .expect("paths")
            .iter()
            .any(|pair| pair["source"] == json!(active) && pair["target"] == json!(suffixed))
    );
    assert_eq!(fs::read(&retired).expect("first retained"), retained_bytes);
    assert_eq!(
        fs::read(&suffixed).expect("second retained"),
        measured.to_string().as_bytes()
    );
    // Exercise inventory readers with a suffixed reservation as well as a report.
    // Inode reuse may already have selected a suffixed reservation name.
    let suffixed_archive = if Path::new(second_archive).extension().is_some() {
        PathBuf::from(second_archive)
    } else {
        PathBuf::from(format!("{second_archive}.1"))
    };
    second_record["current_retirement"]["reservation_path"]["target"] = json!(suffixed_archive);
    fs::rename(second_archive, &suffixed_archive).expect("suffixed reservation");
    write(&suffixed_archive, second_record.to_string());
    write(&suffixed, historical.to_string());
    let rewritten = success(&fixture.invoke(&["rewrite-launch-reports", "alpha"]));
    assert_eq!(rewritten["changed"], 1);
    let census = success(&fixture.command());
    assert!(
        census["retired_records"]
            .as_array()
            .expect("retired records")
            .iter()
            .any(
                |row| row["journaled_names"]
                    .as_array()
                    .is_some_and(|names| names
                        .iter()
                        .any(|name| name
                            == suffixed.file_name().expect("name").to_str().expect("UTF-8")))
            )
    );
}

/// # Panics
/// Panics only if the production rewrite ignores a launcher lock or rewrites unknown evidence.
/// ´test:integration:launch-report-rewrite-entry-refuses-launchers-and-unknown-shapes´
#[test]
fn launch_report_rewrite_entry_refuses_launchers_and_unknown_shapes() {
    use nix::fcntl::{Flock, FlockArg};
    let fixture = Fixture::new();
    let config =
        fs::File::open(fixture.home.path().join(".config/loops/alpha")).expect("configuration");
    let launcher = Flock::lock(config, FlockArg::LockSharedNonblock).expect("launcher shared lock");
    for args in [
        vec!["rewrite-launch-reports", "alpha", "--dry-run"],
        vec!["rewrite-launch-reports", "alpha"],
    ] {
        let output = fixture.invoke(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("install-busy"));
    }
    drop(launcher);
    let mut old = first_round_report(&fixture);
    old.as_object_mut()
        .expect("object")
        .remove("credential_publication");
    let active = fixture.runs.join(".report=R.json");
    write(&active, old.to_string());
    let unknown = fixture.runs.join(".report=S.json");
    let mut invalid = old.clone();
    invalid["unexpected"] = json!(true);
    write(&unknown, invalid.to_string());
    let output = fixture.invoke(&["rewrite-launch-reports", "alpha"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exact publication-evidence predecessor")
    );
    assert_eq!(
        fs::read(&active).expect("no partial conversion"),
        old.to_string().as_bytes()
    );
    fs::remove_file(&unknown).expect("remove malformed fixture");
    std::os::unix::fs::symlink(&active, &unknown).expect("linked report fixture");
    let output = fixture.invoke(&["rewrite-launch-reports", "alpha", "--dry-run"]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(&active).expect("link refusal preserves source"),
        old.to_string().as_bytes()
    );
    fs::remove_file(&unknown).expect("remove linked fixture");
    let journal = fixture.runs.join(".retired-R-20-1-2");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&journal).expect("journal bytes")).expect("journal JSON");
    record["current_retirement"]["planned_paths"] = json!("malformed");
    write(&journal, record.to_string());
    let output = fixture.invoke(&["rewrite-launch-reports", "alpha"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("planned paths are not an array"));
    record["current_retirement"]["planned_paths"] =
        json!([{"source":active,"target":fixture.home.path().join(".retired-R-21-1-3")}]);
    write(&journal, record.to_string());
    let output = fixture.invoke(&["rewrite-launch-reports", "alpha"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("retired report custody differs"));
    assert_eq!(
        fs::read(&active).expect("journal refusal preserves source"),
        old.to_string().as_bytes()
    );
}

fn resumed_dead_driver_retirement(missing: bool) {
    let fixture = preparing_retirement_fixture();
    let path = fixture.runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
    record["phase"] = json!("started");
    if missing {
        record["launcher_pid"] = Value::Null;
        record["launcher_start"] = Value::Null;
    } else {
        for role in ["driver_entry", "helper", "helper_parent", "observer"] {
            record[format!("{role}_pid")] = json!(u32::MAX);
            record[format!("{role}_start")] = json!(1);
        }
    }
    record["rounds"] = json!([
        {"step":"work-1","phase":"settled","report":".report=R.json"},
        {"step":"work-2","phase":"running"}
    ]);
    write(
        &fixture.runs.join(".report=R.json"),
        first_round_report(&fixture).to_string(),
    );
    write(&path, record.to_string());
    let current_report = fixture.runs.join(".report=R=work-2.json");
    let report = json!({"schema":1,"command":"launch","dry_run":false,
        "round":"work-2","round_dir":fixture.runs.join("R/work-2"),"budget_seconds":10,
        "letter":"continue","letter_reconciliation":[],"thread_id":"thread",
        "credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"complete","settlement":{},"wall_seconds":1.0});
    for (bytes, name) in [
        (report.to_string(), "interrupted-settlement"),
        ("{}".to_owned(), "retire-uncertain"),
    ] {
        write(&current_report, bytes);
        for args in [
            vec!["retire", "alpha", "R", "--dry-run"],
            vec!["retire", "alpha", "R"],
        ] {
            let output = fixture.invoke(&args);
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(name),
                "{output:?}"
            );
            assert_eq!(
                fs::read(&path).expect("unchanged"),
                record.to_string().as_bytes()
            );
        }
    }
    fs::remove_file(current_report).expect("remove current report");
    let mut ambiguous = record.clone();
    ambiguous["rounds"][0]["step"] = json!("work-2");
    write(&path, ambiguous.to_string());
    for args in [
        vec!["retire", "alpha", "R", "--dry-run"],
        vec!["retire", "alpha", "R"],
    ] {
        let output = fixture.invoke(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("retire-report-ambiguous"));
        assert_eq!(
            fs::read(&path).expect("unchanged"),
            ambiguous.to_string().as_bytes()
        );
    }
    write(&path, record.to_string());
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    assert_eq!(
        fs::read(&path).expect("unchanged"),
        record.to_string().as_bytes()
    );
    let done = success(&fixture.invoke(&[
        "retire",
        "alpha",
        "R",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    let archived: Value = serde_json::from_slice(
        &fs::read(done["retirement"]["record"].as_str().expect("archive")).expect("bytes"),
    )
    .expect("JSON");
    assert_eq!(
        archived["reconciliation"]["retirement"],
        if missing {
            "measured-absence"
        } else {
            "dead-driver"
        }
    );
    assert_eq!(archived["rounds"][0], record["rounds"][0]);
    assert_eq!(archived["rounds"][1]["step"], "work-2");
    assert_eq!(archived["rounds"][1]["phase"], "failed");
    assert_eq!(archived["rounds"][1]["settlement_error"], "driver-death");
}

/// ´test:integration:retirement-entry-measures-resumed-missing-identities´
#[test]
fn retirement_entry_measures_resumed_missing_identities() {
    resumed_dead_driver_retirement(true);
}

/// ´test:integration:retirement-confirmation-refuses-missing-identity-by-name´
#[test]
fn retirement_confirmation_refuses_missing_identity_by_name() {
    for lease in [false, true] {
        let fixture = preparing_retirement_fixture();
        let path = fixture.runs.join(".reservation-R.json");
        let mut record: Value =
            serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
        record["launcher_pid"] = Value::Null;
        record["launcher_start"] = Value::Null;
        let flag = if lease {
            fs::remove_file(fixture.runs.join(".prepare-R.lock")).expect("remove lease");
            "--confirm-missing-lease"
        } else {
            record
                .as_object_mut()
                .expect("object")
                .remove("harvest_agreement");
            "--confirm-missing-harvest-fields"
        };
        write(&path, record.to_string());
        for args in [
            vec!["retire", "alpha", "R", flag, "--dry-run"],
            vec!["retire", "alpha", "R", flag],
        ] {
            let output = fixture.invoke(&args);
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("retire-confirmation-missing-identity"),
                "{output:?}"
            );
            assert_eq!(
                fs::read(&path).expect("unchanged"),
                record.to_string().as_bytes()
            );
        }
    }
}

/// ´test:integration:retirement-entry-preserves-interrupted-settlement´
#[test]
fn retirement_entry_preserves_interrupted_settlement() {
    for missing in [false, true] {
        for evidence in ["driver_end", "reaping_recovery", "report"] {
            let fixture = preparing_retirement_fixture();
            let path = fixture.runs.join(".reservation-R.json");
            let mut record: Value =
                serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
            record["phase"] = json!("started");
            record["rounds"] = json!([{"step":"work-2","phase":"running"}]);
            if missing {
                record["launcher_pid"] = Value::Null;
                record["launcher_start"] = Value::Null;
            } else {
                for role in ["driver_entry", "helper", "helper_parent", "observer"] {
                    record[format!("{role}_pid")] = json!(u32::MAX);
                    record[format!("{role}_start")] = json!(1);
                }
            }
            if evidence == "report" {
                write(
                    &fixture.runs.join(".report=R.json"),
                    first_round_report(&fixture).to_string(),
                );
            } else {
                record[evidence] = json!({"state":"completed"});
            }
            write(&path, record.to_string());
            for args in [
                vec!["retire", "alpha", "R", "--dry-run"],
                vec!["retire", "alpha", "R"],
            ] {
                let output = fixture.invoke(&args);
                assert!(!output.status.success());
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("interrupted-settlement"),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let unchanged: Value =
                    serde_json::from_slice(&fs::read(&path).expect("unchanged")).expect("JSON");
                assert_eq!(unchanged, record);
            }
        }
    }
}

/// # Panics
/// Panics only if fixture custody cannot be built or registration refusal changes shape.
/// ´test:integration:retirement-entry-names-refused-registration´
#[test]
fn retirement_entry_names_refused_registration() {
    for phase in ["preparing", "started"] {
        let fixture = preparing_retirement_fixture();
        let path = fixture.runs.join(".reservation-R.json");
        let mut record: Value =
            serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
        record["phase"] = json!(phase);
        record["launcher_pid"] = Value::Null;
        record["launcher_start"] = Value::Null;
        record["rounds"] = json!([{"step":"work-2","phase":"running"}]);
        write(&path, record.to_string());
        let original = fs::read(&path).expect("original");
        write(
            &fixture
                .home
                .path()
                .join(".config/loops/alpha/door-compute-registration.json"),
            json!({"node_root":"/fixture-node"}).to_string(),
        );
        for args in [
            vec!["retire", "alpha", "R", "--dry-run"],
            vec!["retire", "alpha", "R"],
        ] {
            let refused = fixture.invoke(&args);
            assert_eq!(refused.status.code(), Some(2));
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(stderr.contains("retire-node-registration"), "{stderr}");
            assert!(
                stderr.contains("door-compute-registration: route shape or loop differs"),
                "{stderr}"
            );
            assert!(!stderr.contains("retire-uncertain"), "{stderr}");
            assert!(!stderr.contains("helper_sha256"), "{stderr}");
            assert_eq!(fs::read(&path).expect("unchanged refusal"), original);
        }
    }
}

/// ´test:integration:retirement-entry-measures-missing-identities´
#[test]
fn retirement_entry_measures_missing_identities() {
    for phase in ["preparing", "started"] {
        let fixture = preparing_retirement_fixture();
        let path = fixture.runs.join(".reservation-R.json");
        let mut record: Value =
            serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
        record["phase"] = json!(phase);
        record["launcher_pid"] = Value::Null;
        record["launcher_start"] = Value::Null;
        record["rounds"] = json!([{"step":"work-2","phase":"running"}]);
        write(&path, record.to_string());
        let original = fs::read(&path).expect("original");
        let driver = fixture.runs.join("R");
        directory(&driver);
        let lock_path = driver.join(".codex-lane.lock");
        write(&lock_path, format!("{}\n", std::process::id()));
        let busy = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
        assert!(!busy.status.success());
        assert!(String::from_utf8_lossy(&busy.stderr).contains("retire-busy"));
        assert_eq!(fs::read(&path).expect("unchanged busy"), original);
        write(
            &lock_path,
            format!("{}\n{}\n", u32::MAX, std::process::id()),
        );
        let child_busy = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
        assert!(String::from_utf8_lossy(&child_busy.stderr).contains("retire-busy"));
        write(&lock_path, "unreadable\n");
        let uncertain = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
        assert!(String::from_utf8_lossy(&uncertain.stderr).contains("retire-uncertain"));
        write(&lock_path, format!("{}\n{}\n", u32::MAX, u32::MAX - 1));
        let mut named = Command::new("/bin/sh")
            .args(["-c", "read word", "R"])
            .env("HOME", fixture.home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("named process");
        let busy = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
        named.kill().expect("stop named process");
        named.wait().expect("reap named process");
        assert!(!busy.status.success());
        assert!(
            String::from_utf8_lossy(&busy.stderr).contains("names this run"),
            "{busy:?}"
        );
        let mut missing_route = record.clone();
        missing_route["plan"]["door"] = json!({"schema":1});
        write(&path, missing_route.to_string());
        let missing = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("retire-uncertain"));
        assert!(
            String::from_utf8_lossy(&missing.stderr)
                .contains("protected door route has no compute registration")
        );
        write(&path, &original);
        let refused = fixture.invoke(&["retire", "alpha", "R", "--confirm-uncertain", "--dry-run"]);
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains(
            "confirmation requires a failed run with recorded boolean settlement uncertainty"
        ));
        let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
        assert_eq!(fs::read(&path).expect("unchanged"), original);
        let proof = &preview["retirement"]["journal"]["settlement"];
        assert_eq!(proof["state"], "absent");
        assert_eq!(proof["phase"], phase);
        assert_eq!(proof["host"]["processes"], json!([]));
        assert_eq!(proof["node"]["state"], "not-applicable");
        assert_eq!(proof["run_scope"]["state"], "collected");
        let refused = fixture.invoke(&["retire", "alpha", "R", "--expect-digest", &"0".repeat(64)]);
        assert!(String::from_utf8_lossy(&refused.stderr).contains("retire-digest"));
        assert_eq!(
            fs::read(&path).expect("digest refusal leaves reservation"),
            original
        );
        let done = success(&fixture.invoke(&[
            "retire",
            "alpha",
            "R",
            "--expect-digest",
            preview["preview_sha256"].as_str().expect("digest"),
        ]));
        let archived: Value = serde_json::from_slice(
            &fs::read(done["retirement"]["record"].as_str().expect("archive"))
                .expect("archive bytes"),
        )
        .expect("archive JSON");
        assert_eq!(archived["plan"], record["plan"]);
        assert_eq!(archived["retirement_absence_proof"]["phase"], phase);
        assert_eq!(archived["rounds"][0]["step"], "work-2");
        assert_eq!(archived["rounds"][0]["settlement_error"], "driver-death");
    }
}

/// ´test:integration:retirement-entry-reconciles-recorded-dead-driver´
#[test]
fn retirement_entry_reconciles_recorded_dead_driver() {
    resumed_dead_driver_retirement(false);
    let fixture = preparing_retirement_fixture();
    let path = fixture.runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
    record["phase"] = json!("started");
    for prefix in ["driver_entry", "helper", "helper_parent", "observer"] {
        record[format!("{prefix}_pid")] = json!(u32::MAX);
        record[format!("{prefix}_start")] = json!(1);
    }
    record["rounds"] = json!([{"step":"work-2","phase":"running"}]);
    write(&path, record.to_string());
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&path).expect("record")).expect("JSON"),
        record
    );
    let done = success(&fixture.invoke(&[
        "retire",
        "alpha",
        "R",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    let archived: Value = serde_json::from_slice(
        &fs::read(done["retirement"]["record"].as_str().expect("archive")).expect("bytes"),
    )
    .expect("JSON");
    assert_eq!(archived["reconciliation"]["retirement"], "dead-driver");
    assert_eq!(archived["reconciliation"]["driver"]["presence"], "absent");
    assert_eq!(
        archived["reconciliation"]["reaping"]["run_scope"]["state"],
        "collected"
    );
    assert_eq!(archived["rounds"][0]["phase"], "failed");
    assert_eq!(archived["rounds"][0]["step"], "work-2");
    assert_eq!(archived["rounds"][0]["settlement_error"], "driver-death");
    assert_eq!(archived["plan"], record["plan"]);
}

/// ´test:integration:retirement-entry-retains-other-command-preparation-names´
#[test]
#[allow(clippy::too_many_lines)]
fn retirement_entry_retains_other_command_preparation_names() {
    let build =
        tempfile::tempdir_in(temporary_root::temporary_root()).expect("boundary build directory");
    let source = build.path().join("reconcile-host.c");
    fs::write(&source, include_bytes!("fixtures/reconcile-host.c")).expect("boundary source");
    let library = build.path().join("reconcile-host.so");
    let compiled = Command::new("/usr/bin/cc")
        .args(["-shared", "-fPIC", "-O0", "-Wall", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .arg("-ldl")
        .output()
        .expect("node C compiler for isolated syscall boundary");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    for survivors in [false, true] {
        let fixture = preparing_retirement_fixture();
        let path = fixture.runs.join(".reservation-R.json");
        let mut record: Value =
            serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
        let root = fixture.home.path().join("cgroup");
        let unit = record["run_scope"]["unit"]
            .as_str()
            .expect("unit")
            .to_owned();
        let work = root.join(&unit).join("work");
        directory(&work);
        write(
            &work.join("cgroup.events"),
            if survivors {
                "populated 1\n"
            } else {
                "populated 0\n"
            },
        );
        write(
            &work.join("cgroup.procs"),
            if survivors {
                format!("{}\n", std::process::id())
            } else {
                String::new()
            },
        );
        write(&work.join("cgroup.kill"), b"");
        let metadata = fs::metadata(&work).expect("scope identity");
        record["run_scope"]["device"] = json!(metadata.dev());
        record["run_scope"]["inode"] = json!(metadata.ino());
        if !survivors {
            record["run_scope"]["proxy_unit"] = json!("superloop-lane-vendor@alpha.service");
            record["run_scope"]["proxy_invocation"] = json!("previous-invocation");
        }
        write(&path, record.to_string());
        let systemctl = fixture.home.path().join("systemctl");
        write(&systemctl, b"#!/bin/sh\n[ \"$2\" = show ] || exit 9\nprintf 'ActiveState=inactive\\nInvocationID=\\n'\n");
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o700))
            .expect("systemctl fixture");
        let invoke = |args: &[&str]| {
            retry_busy_entry(|| {
                fixture
                    .invocation(args)
                    .env("LD_PRELOAD", &library)
                    .env("LANE_FIXTURE_CGROUP", &root)
                    .env("LANE_FIXTURE_SYSTEMCTL", &systemctl)
                    .output()
            })
            .expect("production binary dispatch")
        };
        let kernel = survivors.then(|| {
            let work = work.clone();
            std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(10);
                while Instant::now() < until {
                    if fs::read(work.join("cgroup.kill")).expect("kill request") == b"1" {
                        write(&work.join("cgroup.procs"), b"");
                        write(&work.join("events-next"), b"populated 0\n");
                        fs::rename(work.join("events-next"), work.join("cgroup.events"))
                            .expect("kernel empties scope");
                        return true;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                false
            })
        });
        let checkpoint = invoke(&["checkpoint", "alpha", "R"]);
        if let Some(kernel) = kernel {
            assert!(
                kernel.join().expect("kernel fixture"),
                "{}",
                String::from_utf8_lossy(&checkpoint.stderr)
            );
        }
        // Checkpoint itself cannot accept an unsettled preparation, but its
        // production pre-dispatch reconciliation must already have named it.
        assert!(!checkpoint.status.success());
        let reconciled: Value =
            serde_json::from_slice(&fs::read(&path).expect("reconciled")).expect("JSON");
        assert_eq!(
            reconciled["phase"],
            "failed",
            "{}",
            String::from_utf8_lossy(&checkpoint.stderr)
        );
        assert_eq!(
            reconciled["reconciliation"]["retirement"],
            "never-started-preparation"
        );
        assert_eq!(
            reconciled["pre_driver_failure"],
            if survivors {
                "driver-death"
            } else {
                "proxy-service-death"
            }
        );
        assert_eq!(
            reconciled["reconciliation"]["reaping"]["state"],
            if survivors {
                "survivors-reaped"
            } else {
                "verified-empty"
            }
        );
        let preview = success(&invoke(&["retire", "alpha", "R", "--dry-run"]));
        let done = success(&invoke(&[
            "retire",
            "alpha",
            "R",
            "--expect-digest",
            preview["preview_sha256"].as_str().expect("digest"),
        ]));
        let archived: Value = serde_json::from_slice(
            &fs::read(done["retirement"]["record"].as_str().expect("archive")).expect("bytes"),
        )
        .expect("JSON");
        assert_eq!(archived["reconciliation"], reconciled["reconciliation"]);
        assert_eq!(archived["plan"], record["plan"]);
    }
}

/// ´test:integration:retirement-entry-remeasures-proof-after-partial-custody-move´
#[test]
fn retirement_entry_remeasures_proof_after_partial_custody_move() {
    let fixture = preparing_retirement_fixture();
    let path = fixture.runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
    record["launcher_pid"] = Value::Null;
    record["launcher_start"] = Value::Null;
    write(&path, record.to_string());
    let driver = fixture.runs.join("R");
    directory(&driver);
    write(&driver.join(".codex-lane.lock"), format!("{}\n", u32::MAX));
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    let journal = &preview["retirement"]["journal"];
    let target = journal["planned_paths"]
        .as_array()
        .expect("paths")
        .iter()
        .find(|pair| pair["source"] == driver.display().to_string())
        .expect("driver pair")["target"]
        .as_str()
        .expect("target");
    record["phase"] = json!("retiring");
    record["current_retirement"] = journal.clone();
    record["retirement_absence_proof"] = journal["settlement"].clone();
    record["node_retirement"] = preview["retirement"]["node_retirement"].clone();
    write(&path, record.to_string());
    let mut tampered = record.clone();
    tampered["current_retirement"]["reservation_path"]["target"] =
        json!(fixture.home.path().join(".retired-outside"));
    write(&path, tampered.to_string());
    let refused = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("retire-record: reservation target is outside runs root"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    write(&path, record.to_string());
    fs::rename(&driver, target).expect("first custody move");
    let lock = Path::new(target).join(".codex-lane.lock");
    write(&lock, format!("{}\n", std::process::id()));
    let busy = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
    assert!(
        String::from_utf8_lossy(&busy.stderr).contains("retire-busy"),
        "{}",
        String::from_utf8_lossy(&busy.stderr)
    );
    write(&lock, format!("{}\n", u32::MAX));
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    let done = success(&fixture.invoke(&[
        "retire",
        "alpha",
        "R",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    assert_eq!(done["retirement"]["state"], "retired");
}

/// ´test:integration:retirement-entry-reconciles-never-started-preview-before-digest´
#[test]
fn retirement_entry_reconciles_never_started_preview_before_digest() {
    for historical in [false, true] {
        let fixture = preparing_retirement_fixture();
        let path = fixture.runs.join(".reservation-R.json");
        let mut preview_args = vec!["retire", "alpha", "R"];
        if historical {
            fs::remove_file(fixture.runs.join(".prepare-R.lock")).expect("missing lease");
            let mut record: Value =
                serde_json::from_slice(&fs::read(&path).expect("read")).expect("record");
            record
                .as_object_mut()
                .expect("object")
                .remove("harvest_agreement");
            record.as_object_mut().expect("object").remove("collection");
            write(&path, record.to_string());
            let before = fs::read(&path).expect("historical bytes");
            for (args, kind) in [
                (vec!["retire", "alpha", "R", "--dry-run"], "retire-lease"),
                (
                    vec![
                        "retire",
                        "alpha",
                        "R",
                        "--confirm-missing-lease",
                        "--dry-run",
                    ],
                    "harvest-record",
                ),
            ] {
                let refused = fixture.invoke(&args);
                assert_eq!(refused.status.code(), Some(2));
                assert!(
                    String::from_utf8_lossy(&refused.stderr).contains(kind),
                    "{}",
                    String::from_utf8_lossy(&refused.stderr)
                );
                assert_eq!(fs::read(&path).expect("unchanged historical bytes"), before);
            }
            preview_args.extend([
                "--confirm-missing-lease",
                "--confirm-missing-harvest-fields",
            ]);
        }
        let mut apply_args = preview_args.clone();
        preview_args.push("--dry-run");
        let mailbox = fixture.runs.join(".letter-R.lock");
        assert!(!mailbox.exists());
        let before = fs::read(&path).expect("preparing bytes");
        let preview = success(&fixture.invoke(&preview_args));
        assert_eq!(fs::read(&path).expect("unchanged preview"), before);
        assert!(!mailbox.exists());
        let repeated = success(&fixture.invoke(&preview_args));
        assert_eq!(preview["preview_sha256"], repeated["preview_sha256"]);
        apply_args.extend([
            "--expect-digest",
            preview["preview_sha256"].as_str().expect("digest"),
        ]);
        let done = success(&fixture.invoke(&apply_args));
        assert!(mailbox.is_file());
        assert_eq!(done["retirement"]["state"], "retired");
        assert!(!path.exists());
        let archived = done["retirement"]["record"].as_str().expect("archive");
        let reconciled: Value = serde_json::from_slice(&fs::read(archived).expect("read archive"))
            .expect("retired record");
        assert_eq!(reconciled["phase"], "retired");
        assert_eq!(reconciled["pre_driver_failure"], "driver-death");
        assert_eq!(reconciled["helper_end"]["state"], "not-started");
        assert_eq!(
            reconciled["reconciliation"]["retirement"],
            "never-started-preparation"
        );
        assert_eq!(
            reconciled["reconciliation"]["reaping"]["state"],
            "collected"
        );
        assert_eq!(reconciled["current_retirement"]["prior_phase"], "failed");
    }
}

/// ´test:integration:retirement-entry-keeps-changed-input-and-contradictory-end-refusals´
#[test]
fn retirement_entry_keeps_changed_input_and_contradictory_end_refusals() {
    let fixture = preparing_retirement_fixture();
    let path = fixture.runs.join(".reservation-R.json");
    let before = fs::read(&path).expect("preparing bytes");
    let lease = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.runs.join(".prepare-R.lock"))
        .expect("lease");
    let held = nix::fcntl::Flock::lock(lease, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .expect("active preparer");
    let refused = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("retire-busy"));
    assert_eq!(fs::read(&path).expect("unchanged preparation"), before);
    drop(held);
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("read")).expect("record");
    record["fixture_changed_input"] = json!(true);
    write(&path, record.to_string());
    let refused = fixture.invoke(&[
        "retire",
        "alpha",
        "R",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("retire-digest"));
    assert!(path.exists());
    record["phase"] = json!("preparing");
    record["helper_end"] = json!({"state":"waited","status":9});
    write(&path, record.to_string());
    let refused = fixture.invoke(&["retire", "alpha", "R", "--dry-run"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("retire-uncertain"));
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path).expect("read")).expect("record"),
        record
    );
}

/// ´test:integration:retirement-entry-recovers-after-stale-preparation-digest´
#[test]
fn retirement_entry_recovers_after_stale_preparation_digest() {
    let fixture = preparing_retirement_fixture();
    let path = fixture.runs.join(".reservation-R.json");
    let preparing: Value =
        serde_json::from_slice(&fs::read(&path).expect("preparing")).expect("JSON");
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    let journal = &preview["retirement"]["journal"];
    // The old preview bound the preparing record rather than its named outcome.
    let stale_inputs = json!({
        "owner_uid":nix::unistd::Uid::effective().as_raw(),"node_only":false,"host":preparing,
        "paths":journal["planned_paths"],"reservation_path":journal["reservation_path"],
        "identities":journal["identities"],"container_presence":journal["container_presence"],
        "uncertain":journal["uncertain"],"confirmation":journal["confirmation"],
        "reaping":journal["reaping"],"reaping_recovery":journal["reaping_recovery"],
        "node_plan":preview["retirement"]["node_retirement"]["plan"]
    });
    let mut stale = String::new();
    for byte in sha2::Sha256::digest(stale_inputs.to_string().as_bytes()) {
        write!(stale, "{byte:02x}").expect("digest text");
    }
    assert_ne!(preview["preview_sha256"], stale);
    let refused = fixture.invoke(&["retire", "alpha", "R", "--expect-digest", &stale]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("retire-digest"));
    let before = fs::read(&path).expect("named failed bytes");
    let failed: Value = serde_json::from_slice(&before).expect("failed");
    assert_eq!(failed["phase"], "failed");
    assert_eq!(
        failed["reconciliation"]["retirement"],
        "never-started-preparation"
    );
    let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
    assert_eq!(fs::read(&path).expect("unchanged failed bytes"), before);
    let done = success(&fixture.invoke(&[
        "retire",
        "alpha",
        "R",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    let retired: Value = serde_json::from_slice(
        &fs::read(done["retirement"]["record"].as_str().expect("archive")).expect("read archive"),
    )
    .expect("retired");
    assert_eq!(retired["phase"], "retired");
}

fn shared_lock_is_blocked(path: &Path) -> bool {
    let file = fs::File::open(path).expect("existing lock");
    match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockSharedNonblock) {
        Ok(guard) => {
            drop(guard);
            false
        }
        Err((_, error)) => {
            assert_eq!(error, nix::errno::Errno::EWOULDBLOCK);
            true
        }
    }
}

fn await_retirement_stage(child: &mut std::process::Child, reached: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !reached() {
        assert!(
            child.try_wait().expect("act status").is_none(),
            "act exited before stage"
        );
        if Instant::now() >= deadline {
            child.kill().expect("stop blocked act");
            child.wait().expect("reap blocked act");
            panic!("retirement did not reach synchronized stage");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// ´test:integration:retirement-entry-act-creates-and-holds-exclusive-writer-locks´
#[test]
fn retirement_entry_act_creates_and_holds_exclusive_writer_locks() {
    for held_writer in [false, true] {
        let fixture = preparing_retirement_fixture();
        let home = fixture.home.path();
        let mailbox = fixture.runs.join(".letter-R.lock");
        let requests = home.join(".config/loops/alpha/door-requests.lock");
        let reservation = fixture.runs.join(".reservation-R.json");
        let before = fs::read(&reservation).expect("original preparation");
        let preview = success(&fixture.invoke(&["retire", "alpha", "R", "--dry-run"]));
        assert!(!mailbox.exists());
        assert!(!requests.exists());
        let writer = if held_writer {
            write(&mailbox, b"");
            Some(
                nix::fcntl::Flock::lock(
                    fs::File::open(&mailbox).expect("writer lock"),
                    nix::fcntl::FlockArg::LockExclusive,
                )
                .expect("letter writer"),
            )
        } else {
            None
        };
        let release = home.join("release");
        nix::unistd::mkfifo(
            &release,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("release FIFO");
        let mut release = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&release)
            .expect("release handle");
        // The first container measurement cannot complete until the parent has
        // probed the locks; later measurements proceed without another handshake.
        write(&home.join("runtime"), b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nif mkdir \"$HOME/probe-entered\" 2>/dev/null; then read -r release < \"$HOME/release\"; fi\nexit 0\n");
        fs::set_permissions(home.join("runtime"), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        let mut act = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .args([
                "retire",
                "alpha",
                "R",
                "--expect-digest",
                preview["preview_sha256"].as_str().expect("digest"),
            ])
            .env("HOME", home)
            .env_remove("ENTER_LOOP_REGISTRY")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("retire act");
        if held_writer {
            let lease = fixture.runs.join(".prepare-R.lock");
            await_retirement_stage(&mut act, || shared_lock_is_blocked(&lease));
            assert!(!home.join("probe-entered").exists());
            assert_eq!(
                fs::read(&reservation).expect("writer holds custody"),
                before
            );
        }
        drop(writer);
        await_retirement_stage(&mut act, || home.join("probe-entered").is_dir());
        assert!(shared_lock_is_blocked(&mailbox));
        assert!(shared_lock_is_blocked(&requests));
        assert_eq!(
            fs::metadata(&mailbox)
                .expect("mailbox mode")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::read(&reservation).expect("measurement precedes publish"),
            before
        );
        release
            .write_all(b"continue\n")
            .expect("release measurement");
        let done = success(&act.wait_with_output().expect("retirement completion"));
        assert_eq!(done["retirement"]["state"], "retired");
        assert!(!shared_lock_is_blocked(&mailbox));
        assert!(!shared_lock_is_blocked(&requests));
    }
}

fn preview(fixture: &Fixture) -> Value {
    success(&fixture.invoke(&["census", "rewrite", "alpha", "R", "--dry-run"]))
}

fn apply(fixture: &Fixture, digest: &str) -> Output {
    fixture.invoke(&["census", "rewrite", "alpha", "R", "--expect-digest", digest])
}

/// ´test:integration:retirement-root-rewrite-entry-precedes-reconciliation´
#[test]
fn retirement_root_rewrite_entry_precedes_reconciliation() {
    let fixture = Fixture::new();
    let path = fixture.runs.join(".retired-R-20-1-2");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("record")).expect("JSON");
    record["node_retirement"] = json!({"schema":1,"plan":{
        "schema":1,"loop":"alpha","run":"R","deadline_seconds":120,
        "policy":"host-completes-node-owed","reason":"node-retirement-pending",
        "helper_sha256":"a".repeat(64),"route":{"alias":"fixture","mirror_root":"~/mirrors","key_path":"/fixture/key","ssh_config_sha256":"b".repeat(64)},
        "paths":["~/lanes/R","~/lanes/R-build","~/lanes/R-tmp","~/lanes/R.lock"],"marker":"~/lanes/R.retired"},
        "outcome":{"state":"unmeasured","reason":"node-retirement-unreachable","owed":true,
        "host_wall_seconds":0.1,"helper_exit":null,"remote_completion":"unknown","evidence":null},
        "attempts":[],"attempts_omitted":0});
    write(&path, record.to_string());
    let before = fs::read(&path).expect("predecessor bytes");
    let refused = fixture.command();
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("retire-node-rewrite-required"));
    let preview = success(&fixture.invoke(&["retire", "rewrite-node", "alpha", "--dry-run"]));
    assert!(preview["plan"]["files"][0].get("before").is_none());
    assert_eq!(preview["plan"]["file_count"], 1);
    let full = success(&fixture.invoke(&[
        "retire",
        "rewrite-node",
        "alpha",
        "--dry-run",
        "--full-plan",
    ]));
    assert!(full["plan"]["files"][0]["before"].is_object());
    assert_eq!(full["preview_sha256"], preview["preview_sha256"]);
    assert_eq!(preview["changed"], 1);
    assert_eq!(fs::read(&path).expect("preview leaves bytes"), before);
    let applied = success(&fixture.invoke(&[
        "retire",
        "rewrite-node",
        "alpha",
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    assert_eq!(applied["changed"], preview["changed"]);
    assert_eq!(applied["plan"], preview["plan"]);
    let converted: Value =
        serde_json::from_slice(&fs::read(&path).expect("converted bytes")).expect("JSON");
    assert_eq!(
        converted["node_retirement"]["plan"]["route"]["node_root"],
        "~"
    );
    assert_eq!(
        converted["node_retirement_rewrite"]["original"],
        record["node_retirement"]
    );
    let census = success(&fixture.command());
    assert_eq!(
        census["retired_records"][0]["node_retirement"],
        converted["node_retirement"]
    );
}

/// ´test:integration:census-entry-observes-historical-shapes-without-rewriting´
#[test]
fn census_entry_observes_historical_shapes_without_rewriting() {
    for worker in [3000, 3001] {
        for refused in [false, true] {
            for phase in ["started", "settled"] {
                let fixture = rewrite_fixture(worker, refused);
                let reservation = fixture.runs.join(".reservation-R.json");
                let mut record: Value =
                    serde_json::from_slice(&fs::read(&reservation).expect("reservation bytes"))
                        .expect("reservation JSON");
                record["phase"] = json!(phase);
                write(&reservation, record.to_string());
                let before_record = fs::read(&reservation).expect("original reservation");
                let before_evidence = fs::read(fixture.path()).expect("original evidence");
                let report = success(&fixture.command());
                let row = &report["reservations"][0];
                assert_eq!(row["worker_uid"], worker);
                assert_eq!(row["phase"], phase);
                assert_ne!(row["worker_uid"], report["reservations"][1]["worker_uid"]);
                let expected = if refused {
                    json!({"state":"unmeasured","reason":"historical-envelope:five-key-refusal",
                        "expires_unix":null,"refresh_due_unix":null,"evidence_state":"refused","refused":"credential-refresh"})
                } else {
                    json!({"state":"unmeasured","reason":"historical-envelope:four-key-run-refusals",
                        "expires_unix":null,"refresh_due_unix":null,"evidence_state":"published","refused":null})
                };
                assert_eq!(row["credential_refresh"], expected);
                assert_eq!(
                    report["reservations"][1]["credential_refresh"]["state"],
                    "measured"
                );
                assert_eq!(
                    report["retired_records"][0]["credential_refresh"],
                    json!({
                        "state":"unmeasured","reason":"retired","expires_unix":null,
                        "refresh_due_unix":null,"evidence_state":null,"refused":null
                    })
                );
                assert_eq!(
                    fs::read(&reservation).expect("unchanged reservation"),
                    before_record
                );
                assert_eq!(
                    fs::read(fixture.path()).expect("unchanged evidence"),
                    before_evidence
                );
                assert!(!fixture.runs.join(".census-rewrite-R.json").exists());
                if phase == "started" {
                    let output = fixture.invoke(&["census", "rewrite", "alpha", "R", "--dry-run"]);
                    assert_eq!(output.status.code(), Some(2));
                    assert_eq!(output.stdout, [] as [u8; 0]);
                    assert!(
                        String::from_utf8_lossy(&output.stderr)
                            .contains("settled or failed reservation")
                    );
                } else {
                    assert_eq!(preview(&fixture)["plan"]["before"], historical(refused));
                }
            }
        }
    }
}

/// ´test:integration:census-rewrite-entry-preserves-both-historical-shapes-and-identities´
#[test]
fn census_rewrite_entry_preserves_both_historical_shapes_and_identities() {
    for worker in [3000, 3001] {
        for refused in [false, true] {
            let fixture = rewrite_fixture(worker, refused);
            let before = fs::read(fixture.path()).expect("original bytes");
            let report = success(&fixture.command());
            assert_eq!(
                report["reservations"][0]["credential_refresh"]["state"],
                "unmeasured"
            );
            let plan = preview(&fixture);
            assert_eq!(
                fs::read(fixture.path()).expect("unchanged evidence"),
                before
            );
            assert!(!fixture.runs.join(".census-rewrite-R.json").exists());
            assert!(!fixture.runs.join(".letter-R.lock").exists());
            assert_eq!(plan["plan"]["before"], historical(refused));
            assert_eq!(
                plan["plan"]["after"]["credential_rewrite"]["token_observed"],
                false
            );
            let digest = plan["preview_sha256"].as_str().expect("digest");
            assert_eq!(apply(&fixture, &"0".repeat(64)).status.code(), Some(2));
            assert_eq!(
                fs::read(fixture.path()).expect("stale digest retains bytes"),
                before
            );
            assert_eq!(success(&apply(&fixture, digest))["complete"], true);
            let target = fs::read(fixture.path()).expect("rewritten evidence");
            let converted: Value = serde_json::from_slice(&target).expect("converted JSON");
            assert_eq!(
                converted["credential_rewrite"]["original_bytes"]
                    .as_str()
                    .expect("original")
                    .as_bytes(),
                before
            );
            assert_eq!(
                converted["credential_rewrite"]["before_sha256"],
                plan["plan"]["before_sha256"]
            );
            let census = success(&fixture.command());
            let row = &census["reservations"][0];
            assert_eq!(row["worker_uid"], worker);
            assert_ne!(row["worker_uid"], census["reservations"][1]["worker_uid"]);
            assert_eq!(row["credential_refresh"]["state"], "unmeasured");
            assert_eq!(
                row["credential_refresh"]["reason"],
                "historical-helper-did-not-measure"
            );
            assert_eq!(
                row["credential_refresh"]["evidence_state"],
                historical(refused)["state"]
            );
            assert_eq!(
                row["credential_refresh"]["refused"],
                historical(refused)["kind"]
            );
            assert!(row["credential_refresh"]["expires_unix"].is_null());
            assert_eq!(
                census["reservations"][1]["credential_refresh"]["state"],
                "measured"
            );
            assert_eq!(preview(&fixture)["preview_sha256"], digest);
            assert_eq!(success(&apply(&fixture, digest))["complete"], true);
            assert_eq!(
                fs::read(fixture.path()).expect("repeat retains target"),
                target
            );
        }
    }
}

/// ´test:integration:census-rewrite-entry-recovers-only-original-or-exact-target´
#[test]
fn census_rewrite_entry_recovers_only_original_or_exact_target() {
    for target_published in [false, true] {
        let fixture = rewrite_fixture(3000, false);
        let plan = preview(&fixture);
        let digest = plan["preview_sha256"].as_str().expect("digest");
        let journal = fixture.runs.join(".census-rewrite-R.json");
        write(
            &journal,
            json!({"schema":1,"phase":"pending","plan":plan["plan"],"preview_sha256":digest})
                .to_string(),
        );
        if target_published {
            write(&fixture.path(), plan["plan"]["after"].to_string());
        }
        let resumed = preview(&fixture);
        assert_eq!(resumed["resuming"], true);
        assert_eq!(resumed["preview_sha256"], digest);
        assert_eq!(success(&apply(&fixture, digest))["complete"], true);
        assert_eq!(
            fs::read(fixture.path()).expect("published evidence bytes"),
            serde_json::to_vec(&plan["plan"]["after"]).expect("serialized planned evidence")
        );
        let completed: Value =
            serde_json::from_slice(&fs::read(&journal).expect("completed journal bytes"))
                .expect("completed journal JSON");
        assert_eq!(completed["phase"], "complete");
    }
    let fixture = rewrite_fixture(3001, true);
    let plan = preview(&fixture);
    let digest = plan["preview_sha256"].as_str().expect("digest");
    write(
        &fixture.runs.join(".census-rewrite-R.json"),
        json!({"schema":1,"phase":"pending","plan":plan["plan"],"preview_sha256":digest})
            .to_string(),
    );
    let changed = format!("{}  ", historical(true));
    write(&fixture.path(), &changed);
    let output = apply(&fixture, digest);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("record changed"));
    assert_eq!(
        fs::read(fixture.path()).expect("changed bytes retained"),
        changed.as_bytes()
    );
}

/// ´test:integration:census-rewrite-entry-refuses-unknown-shapes-and-changed-bindings´
#[test]
fn census_rewrite_entry_refuses_unknown_shapes_and_changed_bindings() {
    let fixture = rewrite_fixture(3000, false);
    for field in ["extra", "expires_unix", "kind"] {
        let mut document = historical(false);
        document[field] = Value::Null;
        write(&fixture.path(), document.to_string());
        let output = fixture.invoke(&["census", "rewrite", "alpha", "R", "--dry-run"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("only the listed historical"));
    }
    for bytes in ["{", "[]"] {
        write(&fixture.path(), bytes);
        let output = fixture.command();
        assert_eq!(output.status.code(), Some(2));
        let error = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert!(!error.contains("census rewrite"), "{error}");
    }
    write(&fixture.path(), historical(false).to_string());
    let plan = preview(&fixture);
    let reservation = fixture.runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&reservation).expect("reservation")).expect("JSON");
    record["worker_uid"] = json!(3001);
    write(&reservation, record.to_string());
    assert_eq!(
        apply(&fixture, plan["preview_sha256"].as_str().expect("digest"))
            .status
            .code(),
        Some(2)
    );
    record["worker_uid"] = json!(3000);
    write(&reservation, record.to_string());
    let plan = preview(&fixture);
    let digest = plan["preview_sha256"].as_str().expect("digest");
    success(&apply(&fixture, digest));
    let mut target: Value =
        serde_json::from_slice(&fs::read(fixture.path()).expect("target")).expect("JSON");
    for replacement in [None, Some(json!("invalid")), Some(json!(1_900_000_000_u64))] {
        let mut damaged = target.clone();
        let expected = if let Some(value) = replacement {
            damaged["expires_unix"] = value;
            "invalid"
        } else {
            damaged
                .as_object_mut()
                .expect("object")
                .remove("expires_unix");
            "absent"
        };
        write(&fixture.path(), damaged.to_string());
        let report = success(&fixture.command());
        assert_eq!(
            report["reservations"][0]["credential_refresh"]["state"],
            expected
        );
        assert!(report["reservations"][0]["credential_refresh"]["expires_unix"].is_null());
        assert_eq!(
            report["reservations"][1]["credential_refresh"]["state"],
            "measured"
        );
    }
    target["credential_rewrite"]["token_observed"] = json!(true);
    write(&fixture.path(), target.to_string());
    assert_census_refusal(&fixture, "rewrite provenance");
    assert_eq!(apply(&fixture, digest).status.code(), Some(2));
}

/// ´test:integration:census-rewrite-entry-excludes-live-unknown-and-locked-writers´
#[test]
fn census_rewrite_entry_excludes_live_unknown_and_locked_writers() {
    use nix::fcntl::{Flock, FlockArg};
    for worker in [3000, 3001] {
        let fixture = rewrite_fixture(worker, false);
        let path = fixture.runs.join(".reservation-R.json");
        let original = fs::read(&path).expect("reservation");
        let mut record: Value = serde_json::from_slice(&original).expect("JSON");
        let process_record = fs::read_to_string("/proc/self/stat").expect("process stat");
        let start: u64 = process_record
            .rsplit_once(") ")
            .expect("process name")
            .1
            .split_whitespace()
            .nth(19)
            .expect("start field")
            .parse()
            .expect("start number");
        record["helper_pid"] = json!(std::process::id());
        record["helper_start"] = json!(start);
        write(&path, record.to_string());
        let output = fixture.invoke(&["census", "rewrite", "alpha", "R", "--dry-run"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("helper is still present"));
        record.as_object_mut().expect("object").remove("helper_pid");
        record
            .as_object_mut()
            .expect("object")
            .remove("helper_start");
        write(&path, record.to_string());
        let output = fixture.invoke(&["census", "rewrite", "alpha", "R", "--dry-run"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("helper has no recorded identity or absence proof")
        );
        write(&path, &original);
        for name in [".prepare-R.lock", ".letter-R.lock"] {
            let lock = fixture.runs.join(name);
            write(&lock, "");
            let file = fs::File::open(lock).expect("lock file");
            let _held = Flock::lock(file, FlockArg::LockExclusiveNonblock).expect("writer lock");
            assert_eq!(
                fixture
                    .invoke(&["census", "rewrite", "alpha", "R", "--dry-run"])
                    .status
                    .code(),
                Some(2)
            );
        }
        let shared =
            fs::File::open(fixture.home.path().join(".config/loops/alpha")).expect("configuration");
        let _door =
            Flock::lock(shared, FlockArg::LockSharedNonblock).expect("unrelated door guard");
        assert_eq!(preview(&fixture)["dry_run"], true);
        assert!(!fixture.runs.join(".census-rewrite-R.json").exists());
    }
}

fn evidence() -> Value {
    json!({"schema":1,"host":"auth.openai.com","state":"current","expires_unix":1_900_000_000_u64,"refresh_due_unix":1_899_999_400_u64,"run_refusals":[],"run_refusals_omitted":0,"kind":null,"detail":null})
}

/// ´test:integration:census-entry-reports-temporal-evidence-with-other-rows-intact´
#[test]
fn census_entry_reports_temporal_evidence_with_other_rows_intact() {
    let fixture = Fixture::new();
    let row = fixture.row();
    assert_eq!(row["state"], "measured");
    assert_eq!(row["evidence_state"], "current");
    assert_eq!(row["expires_unix"], 1_900_000_000_u64);
    for field in ["expires_unix", "refresh_due_unix"] {
        let mut document = evidence();
        document.as_object_mut().expect("object").remove(field);
        write(&fixture.path(), document.to_string());
        let row = fixture.row();
        assert_eq!(row["state"], "absent");
        assert_eq!(row["reason"], format!("missing-field:{field}"));
        assert!(row.get(field).expect("instant key").is_null());
        for invalid in [
            Value::Null,
            json!("1900000000"),
            json!(-1),
            json!(1.5),
            json!(true),
        ] {
            let mut document = evidence();
            document[field] = invalid;
            write(&fixture.path(), document.to_string());
            let row = fixture.row();
            assert_eq!(row["state"], "invalid");
            assert!(row.get(field).expect("instant key").is_null());
        }
    }
    let mut document = evidence();
    document["refresh_due_unix"] = json!(1);
    write(&fixture.path(), document.to_string());
    let row = fixture.row();
    assert_eq!(row["state"], "invalid");
    assert_eq!(row["reason"], "refresh-due-disagrees");
    assert!(row["refresh_due_unix"].is_null());
    document["expires_unix"] = Value::Null;
    document["refresh_due_unix"] = Value::Null;
    document["state"] = json!("refused");
    document["kind"] = json!("credential-sign-in");
    document["detail"] = json!("fixture source unavailable");
    write(&fixture.path(), document.to_string());
    let row = fixture.row();
    assert_eq!(row["state"], "unmeasured");
    assert_eq!(row["evidence_state"], "refused");
    assert_eq!(row["refused"], "credential-sign-in");
    assert!(row.get("expires_unix").expect("expiry key").is_null());
    assert!(row.get("refresh_due_unix").expect("due key").is_null());
    fs::remove_file(fixture.path()).expect("remove evidence");
    let row = fixture.row();
    assert_eq!(row["state"], "absent");
    assert_eq!(row["reason"], "missing-file");
}

/// ´test:integration:census-entry-refuses-undecodable-and-unsafe-evidence´
#[test]
fn census_entry_refuses_undecodable_and_unsafe_evidence() {
    let fixture = Fixture::new();
    for bytes in [
        "{",
        "[]",
        "{\"schema\":1,\"host\":\"auth.openai.com\",\"state\":\"partial\",\"run_refusals\":[]}",
        "{\"schema\":1,\"host\":\"auth.openai.com\",\"state\":\"refused\",\"kind\":\"\",\"detail\":\"bad\"}",
    ] {
        write(&fixture.path(), bytes);
        assert_census_refusal(&fixture, "credential-evidence");
    }
    write(&fixture.path(), evidence().to_string());
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    assert_census_refusal(&fixture, "owner, mode, type or size");
    write(&fixture.path(), " ".repeat(65_537));
    assert_census_refusal(&fixture, "owner, mode, type or size");
    write(&fixture.path(), evidence().to_string());
    let protected = fixture.runs.join(".launch-R");
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o755)).expect("unsafe directory");
    assert_census_refusal(&fixture, "protected directory owner or mode");
    directory(&protected);
    fs::remove_file(fixture.path()).expect("remove evidence");
    std::os::unix::fs::symlink("missing-evidence", fixture.path()).expect("unreadable evidence");
    assert_census_refusal(&fixture, "credential-refresh.json");
    fs::remove_file(fixture.path()).expect("remove link");
    write(&fixture.path(), evidence().to_string());
    fs::rename(
        fixture.runs.join(".reservation-R.json"),
        fixture.runs.join(".reservation-bad name.json"),
    )
    .expect("invalid reservation name");
    assert_census_refusal(&fixture, "invalid run name");
}

fn assert_census_refusal(fixture: &Fixture, detail: &str) {
    let output = fixture.command();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(detail), "{error}");
    assert!(!error.contains("census rewrite"), "{error}");
    assert!(!error.contains("recovery:"), "{error}");
}

/// ´claim:superlooplane:mail-migration-census-exposes-retained-home-custody-through-entry´
/// ´test:integration:mail-migration-census-exposes-retained-home-custody-through-entry´
#[test]
fn mail_migration_census_exposes_retained_home_custody_through_entry() {
    let fixture = Fixture::new();
    let parent = fixture.home.path().join(".cache/tmp");
    directory(&parent);
    for run in ["R", "S"] {
        let record_path = fixture.runs.join(format!(".reservation-{run}.json"));
        let mut record: Value =
            serde_json::from_slice(&fs::read(&record_path).expect("record")).expect("JSON");
        let home = parent.join(format!("lane-alpha-{run}"));
        directory(&home);
        record["plan"] = json!({"home":home,"driver_dir":fixture.runs.join(run)});
        write(&record_path, record.to_string());
    }
    let archived = parent.join("archived");
    directory(&archived);
    directory(&archived.join(".local/inbox"));
    write(&archived.join(".local/inbox/opaque"), [0, 255, 10]);
    let info = fs::metadata(&archived).expect("retained identity");
    let target = parent.join(format!(".retired-R-1-{}-{}", info.dev(), info.ino()));
    fs::rename(archived, &target).expect("recorded move");
    let record_path = fixture.runs.join(".retired-R-20-1-2");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&record_path).expect("record")).expect("JSON");
    record["plan"] =
        json!({"home":parent.join("lane-alpha-R"),"driver_dir":fixture.runs.join("R")});
    record["current_retirement"]["planned_paths"] =
        json!([{"source":parent.join("lane-alpha-R"),"target":target}]);
    write(&record_path, record.to_string());
    let report = success(&fixture.invoke(&["census", "alpha", "--mail-migration"]));
    let rows = report["mail_migration"]["records"]
        .as_array()
        .expect("inventory rows");
    assert_eq!(rows.len(), 3);
    assert_eq!(report["mail_migration"]["activation_verified"], false);
    let archived = rows
        .iter()
        .find(|row| row["record"] == record_path.to_string_lossy().as_ref())
        .expect("retired row");
    assert_eq!(
        archived["homes"][0]["path"],
        target.to_string_lossy().as_ref()
    );
    assert_eq!(archived["homes"][0]["required"], true);
    assert_eq!(
        archived["homes"][0]["stores"],
        json!([target.join(".local/inbox"), target.join(".local/outbox")])
    );
    assert_eq!(
        fs::read(target.join(".local/inbox/opaque")).expect("unread opaque bytes"),
        [0, 255, 10]
    );
    fs::rename(&target, parent.join("retained-but-missing-from-name")).expect("replace witness");
    directory(&target);
    let refused = fixture.invoke(&["census", "alpha", "--mail-migration"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("protected rename witness"));
}
