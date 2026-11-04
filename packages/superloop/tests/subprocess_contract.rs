//! # `superloop` subprocess contract matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Reports | 6 | Text and JSON count reports, report mode and removal, wall errors, TMPDIR placement, provision on an existing home, one recorded outer invocation, and byte-stable command arguments |
//! | Registry | 6 | Compact validated rows with and without declared roots and backend programs, owner reporting, an unknown name, an absent account, and account UID disagreement |
//! | Home resolution | 1 | The executed outer script passes either the base or private home to the nested call |
//! | GnuPG bridge | 3 | The entered command selects custody or pre-custody keyrings, or no keyring, and executes system GnuPG |
//! | Forge entry | 1 | The bound forge directory refuses as absent, nondirectory or inaccessible after the identity switch and names provisioning; a provisioned directory reaches the client |
//! | Custody environment | 1 | Separate compositions export selectors only with a custody tier |
//! | Status propagation | 2 | Child status seven becomes process status seven; verify probe and cleanup failures become status one |
//! | Termination | 2 | External SIGTERM reaps the private group and closes its pipe within five seconds with a named trailer; private groups retain terminal input |
//! | Refusal | 7 | Invalid names, nondirectory tiers, non-UTF-8 HOME, planted links, malformed ensure arguments, the owner-only row, and an ensure failure refuse without mounting |
//! | Driver launch | 5 | Exact positional argv and child status, ordinary command dispatch, and byte-stable prelaunch refusals leave the stub untouched |

mod support;
#[path = "subprocess_contract/termination.rs"]
mod termination;

use support::SerializedCommand as _;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Instant;

use loop_home::{
    CommandOutput, CommandSpec, IoMode, ProcessRunner, RunError, Runner, enter_loop_entry,
};

use support::TestDir;

fn enter_loop() -> Command {
    Command::new(env!("CARGO_BIN_EXE_superloop"))
}

/// The production entry checks the bound forge directory before executing its client.
///
/// # Panics
/// Panics only if fixture setup, entry planning or refusal assertions fail.
///
/// ´claim:loophome:forge-refuses-unprovisioned-configuration-before-transport´
/// ´test:integration:forge-entry-distinguishes-absent-nondirectory-and-inaccessible´
#[test]
fn forge_entry_distinguishes_absent_nondirectory_and_inaccessible() {
    let directory = TestDir::new("forge-entry");
    let (root, podman_stub) = directory.prepare();
    let home = directory.path().join(".var/loops/alpha");
    fs::create_dir_all(home.join(".config/custody")).expect("bound fixture tier");
    fs::create_dir_all(home.join(".local/bin")).expect("client directory");
    fs::create_dir_all(directory.path().join(".config/loops/alpha/private/ssh"))
        .expect("tier selector");
    support::write_executable(
        &home.join(".local/bin/gh"),
        b"#!/bin/sh\nprintf 'forge client reached\\n'\n",
        0o700,
    )
    .expect("fixture client");
    let log = directory.path().join("podman.log");
    let planned = run(
        &root,
        &podman_stub,
        &log,
        0,
        &["enter", "alpha", "--", "gh"],
    );
    assert!(planned.status.success(), "{planned:?}");
    let script = recorded_outer(&log);
    let forge = home.join(".config/custody/gh");
    for reason in [
        "forge-config-absent",
        "forge-config-not-directory",
        "forge-config-inaccessible",
    ] {
        if reason == "forge-config-not-directory" {
            fs::write(&forge, "fixture file").expect("nondirectory");
        } else if reason == "forge-config-inaccessible" {
            fs::remove_file(&forge).expect("remove file");
            fs::create_dir(&forge).expect("directory");
            fs::set_permissions(&forge, fs::Permissions::from_mode(0o000))
                .expect("inaccessible mode");
        }
        let output = execute_outer_command(&directory, &script, true);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!(
                "superloop: {reason}: GH_CONFIG_DIR; run superloop provision LOOP\n"
            )),
            "{output:?}"
        );
        let switches =
            fs::read_to_string(directory.path().join("setpriv.log")).expect("identity switch");
        assert!(switches.starts_with("--reuid=41001\n--regid=41001\n--clear-groups\n"));
    }
    fs::set_permissions(&forge, fs::Permissions::from_mode(0o700)).expect("restore mode");
    let output = execute_outer_command(&directory, &script, true);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"forge client reached\n");
}

fn run(root: &Path, stub: &Path, log: &Path, status: i32, arguments: &[&str]) -> Output {
    run_from_home(root, root, stub, log, status, arguments)
}

fn run_from_home(
    root: &Path,
    caller_home: &Path,
    stub: &Path,
    log: &Path,
    status: i32,
    arguments: &[&str],
) -> Output {
    if arguments.contains(&"verify") {
        return run_verify_fixture(root, caller_home, stub, log, status, arguments, &[]);
    }
    enter_loop()
        .args(arguments)
        .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
        .env("ENTER_LOOP_PODMAN", stub)
        .env("ENTER_LOOP_STUB_LOG", log)
        .env("ENTER_LOOP_STUB_STATUS", status.to_string())
        .env("HOME", caller_home)
        .env("TMPDIR", root)
        .env("TERM", "vt100")
        .env("LANG", "C.UTF-8")
        .output_serialized()
        .expect("superloop subprocess runs")
}

fn run_verify_fixture(
    root: &Path,
    caller_home: &Path,
    stub: &Path,
    log: &Path,
    status: i32,
    arguments: &[&str],
    extra_env: &[(&str, String)],
) -> Output {
    let result = root.join("fixture-verify-result");
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", "fixture_verify_process", "--nocapture"])
        .env("LOOP_HOME_FIXTURE_ARGS", arguments.join("\x1f"))
        .env("LOOP_HOME_FIXTURE_RESULT", &result)
        .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
        .env("ENTER_LOOP_PODMAN", stub)
        .env("ENTER_LOOP_STUB_LOG", log)
        .env("ENTER_LOOP_STUB_STATUS", status.to_string())
        .env("HOME", caller_home)
        .env("TMPDIR", root)
        .env("TERM", "vt100")
        .env("LANG", "C.UTF-8");
    for (name, value) in extra_env {
        command.env(name, value);
    }
    let child = command
        .output_serialized()
        .expect("fixture verification process");
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let code = fs::read_to_string(result.with_extension("status"))
        .expect("fixture status")
        .parse::<i32>()
        .expect("numeric fixture status");
    Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: fs::read(result.with_extension("stdout")).expect("fixture stdout"),
        stderr: fs::read(result.with_extension("stderr")).expect("fixture stderr"),
    }
}

struct FixturePodmanRunner;

impl Runner for FixturePodmanRunner {
    fn run_entry(&mut self, plan: &loop_home::EntryPlan) -> Result<CommandOutput, RunError> {
        if std::env::var_os("LOOP_HOME_REAL_VERIFY_RELAY").is_some() {
            let mut plan = plan.clone();
            plan.command.argv[0] = std::env::var("ENTER_LOOP_PODMAN").expect("fixture podman");
            return ProcessRunner.run_entry(&plan);
        }
        self.run(&plan.command)
    }

    fn verify_route(&self) -> Result<Vec<String>, loop_home::LoopError> {
        Ok(vec![String::from("/usr/bin/podman")])
    }

    fn run(&mut self, request: &CommandSpec) -> Result<CommandOutput, RunError> {
        assert!(
            request.label.starts_with("verify-"),
            "verification command must use a trusted PATH"
        );
        assert!(
            request.argv[0].starts_with("/usr/") || request.argv[0].starts_with("/bin/"),
            "fixed system route"
        );
        let log = std::env::var_os("ENTER_LOOP_STUB_LOG").expect("fixture log");
        fs::write(
            format!("{}.{}", Path::new(&log).display(), request.label),
            request.argv.join("\n"),
        )
        .expect("fixture command plan");
        let stub = std::env::var_os("ENTER_LOOP_PODMAN").expect("fixture podman");
        if std::env::var_os("LOOP_HOME_REAL_VERIFY_RELAY").is_some() {
            let mut request = request.clone();
            request.argv[0] = stub.to_string_lossy().into_owned();
            return loop_home::ProcessRunner.run(&request);
        }
        let started = Instant::now();
        let output = Command::new(stub)
            .args(&request.argv[1..])
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .output()
            .map_err(|error| RunError {
                detail: error.to_string(),
                wall: started.elapsed(),
            })?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
            wall: started.elapsed(),
        })
    }
}

/// Run a verification through the injected fixture runner in a separate process.
///
/// ´claim:entry:fixture-verify-process´
/// ´test:integration:fixture-verify-process´
#[test]
fn fixture_verify_process() {
    let Ok(arguments) = std::env::var("LOOP_HOME_FIXTURE_ARGS") else {
        return;
    };
    let result = std::path::PathBuf::from(
        std::env::var_os("LOOP_HOME_FIXTURE_RESULT").expect("fixture output path"),
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = enter_loop_entry(
        OsStr::new("superloop"),
        arguments.split('\x1f'),
        &mut FixturePodmanRunner,
        &mut stdout,
        &mut stderr,
    );
    fs::write(result.with_extension("stdout"), stdout).expect("fixture stdout");
    fs::write(result.with_extension("stderr"), stderr).expect("fixture stderr");
    fs::write(result.with_extension("status"), status.to_string()).expect("fixture status");
}

/// Record the actual process runner's environment in an isolated test process.
///
/// ´claim:entry:fixture-verify-child-environment´
/// ´test:integration:fixture-verify-child-environment´
#[test]
fn fixture_verify_child_environment() {
    let Some(result) = std::env::var_os("LOOP_HOME_ENV_RESULT") else {
        return;
    };
    let mut recorded = String::new();
    for label in ["verify-roots", "verify-entry", "verify-cleanup"] {
        let request = CommandSpec {
            label: label.to_owned(),
            argv: vec![String::from("/usr/bin/env")],
            io: IoMode::Capture,
        };
        let output = ProcessRunner.run(&request).expect("fixed env child");
        assert_eq!(output.status, 0);
        assert!(output.stderr.is_empty(), "loader warning in {label}");
        recorded.push_str(label);
        recorded.push('\n');
        recorded.push_str(&String::from_utf8(output.stdout).expect("UTF-8 child environment"));
        recorded.push('\n');
    }
    fs::write(result, recorded).expect("environment fixture result");
}

/// Loader, shell-startup and tool override variables do not reach any verify child.
///
/// ´claim:entry:verify-children-receive-only-explicit-environment´
/// ´test:integration:verify-children-receive-only-explicit-environment´
#[test]
fn verify_children_receive_only_explicit_environment() {
    let directory = TestDir::new("verify-child-environment");
    let result = directory.path().join("child-env.txt");
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "fixture_verify_child_environment", "--nocapture"])
        .env("LOOP_HOME_ENV_RESULT", &result)
        .env("HOME", directory.path())
        .env("LD_PRELOAD", "/absent/loop-preload.so")
        .env("LD_AUDIT", "/absent/loop-audit.so")
        .env("LD_LIBRARY_PATH", directory.path())
        .env("BASH_ENV", directory.path().join("startup"))
        .env("ENV", directory.path().join("startup"))
        .env("GCONV_PATH", directory.path())
        .env("PYTHONPATH", directory.path())
        .output_serialized()
        .expect("environment fixture process");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recorded = fs::read_to_string(result).expect("child environment");
    let runtime = format!("/run/user/{}", nix::unistd::Uid::effective().as_raw());
    let mut expected = vec![
        String::from("PATH=/usr/local/bin:/usr/bin:/bin"),
        format!("HOME={}", directory.path().display()),
        format!("XDG_RUNTIME_DIR={runtime}"),
        format!("DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"),
    ];
    expected.sort();
    let sections: Vec<_> = recorded
        .split("\n\n")
        .filter(|part| !part.is_empty())
        .collect();
    assert_eq!(sections.len(), 3);
    for (section, label) in sections
        .iter()
        .zip(["verify-roots", "verify-entry", "verify-cleanup"])
    {
        let mut lines = section.lines();
        assert_eq!(lines.next(), Some(label));
        let mut environment: Vec<_> = lines.map(str::to_owned).collect();
        environment.sort();
        assert_eq!(environment, expected, "{label}");
    }
    for name in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "PYTHONPATH",
    ] {
        assert!(
            !recorded.contains(&format!("{name}=")),
            "{name} reached a child"
        );
    }
}

fn recorded_outer(log: &Path) -> String {
    let recorded = fs::read_to_string(log).expect("recorded podman argv");
    recorded
        .strip_prefix("unshare\nsh\n-c\n")
        .and_then(|script| script.strip_suffix('\n'))
        .expect("recorded outer script")
        .to_owned()
}

fn execute_outer(directory: &TestDir, script: &str) -> Output {
    execute_outer_command(directory, script, false)
}

fn execute_outer_command(directory: &TestDir, script: &str, run_command: bool) -> Output {
    let bin = directory.path().join("custody-bin");
    fs::create_dir_all(&bin).expect("create stub directory");
    support::write_executable(
        &bin.join("unshare"),
        b"#!/bin/sh\nset -eu\nshift\nexec \"$@\"\n",
        0o755,
    )
    .expect("write unshare stub");
    support::write_executable(
        &bin.join("mount"),
        b"#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$ENTER_LOOP_MOUNT_LOG\"\n",
        0o755,
    )
    .expect("write mount stub");
    support::write_executable(
        &bin.join("setpriv"),
        b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$ENTER_LOOP_SETPRIV_LOG\"\nif [ \"$ENTER_LOOP_RUN_COMMAND\" = yes ]; then shift 3; exec \"$@\"; fi\n",
        0o755,
    )
    .expect("write setpriv stub");
    let custody_stub = bin.join("entry-custody");
    support::write_executable(
        &custody_stub,
        b"#!/bin/sh\nset -eu\nif [ \"$1\" = _supervise-command ]; then\n    exec \"$ENTER_LOOP_REAL_ENTRY\" \"$@\"\nelif [ \"$1\" = ensure-roots ]; then\n    if [ -f \"$ENTER_LOOP_ENSURE_FAIL_MARKER\" ]; then exit 2; fi\n    printf 'wall 10\\n' >> \"$5\"\nelif [ \"$1\" = _mail-group ]; then\n    exit 0\nelif [ \"$1\" = letters-group ]; then\n    printf '65535\\n'\nelse\n    printf '%s\\n' \"$@\" > \"$ENTER_LOOP_CUSTODY_LOG\"\nfi\n",
        0o755,
    )
    .expect("write custody stub");
    let executable =
        fs::canonicalize(env!("CARGO_BIN_EXE_superloop")).expect("canonical entry path");
    let script = script.replace(
        executable.to_str().expect("UTF-8 entry path"),
        "entry-custody",
    );
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").expect("system utility path")
    );
    Command::new("sh")
        .args(["-c", &script])
        // The replayed script carries the planner's literal watched set.
        .env("PATH", path)
        .env("ENTER_LOOP_REAL_ENTRY", &executable)
        .env(
            "ENTER_LOOP_RUN_COMMAND",
            if run_command { "yes" } else { "no" },
        )
        .env("ENTER_LOOP_MOUNT_LOG", directory.path().join("mount.log"))
        .env(
            "ENTER_LOOP_CUSTODY_LOG",
            directory.path().join("custody.log"),
        )
        .env(
            "ENTER_LOOP_SETPRIV_LOG",
            directory.path().join("setpriv.log"),
        )
        .env(
            "ENTER_LOOP_ENSURE_FAIL_MARKER",
            directory.path().join("ensure-fail"),
        )
        .output_serialized()
        .expect("outer script runs")
}

fn assert_report(stderr: &[u8], status: i32) {
    let text = std::str::from_utf8(stderr).expect("UTF-8 report");
    let prefix = format!("ENTER-REPORT loop=alpha uid=41001 exit={status} wall=");
    let wall = text
        .strip_prefix(&prefix)
        .and_then(|tail| tail.strip_suffix("s created=1 corrected=1\n"))
        .expect("stable report framing");
    let _seconds = wall.parse::<f64>().expect("numeric wall");
    assert_ne!(wall, "");
}

fn driver_fixture(
    directory: &TestDir,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let root = directory.path();
    let runs = root.join("configured-durable/runs");
    fs::write(root.join("registry.toml"), format!(
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", session = \"SESSION-ID\", runs_root = \"{}\" }}]\n", runs.display()
    )).expect("root grant");
    let driver = root.join("driver");
    support::write_executable(&driver, b"#!/bin/sh\nexit 0\n", 0o755).expect("driver executable");
    let settings = root.join(".config/loops/alpha/workers.toml");
    fs::create_dir_all(settings.parent().expect("settings parent")).expect("settings directory");
    for directory in [
        root.join(".config"),
        root.join(".config/loops"),
        root.join(".config/loops/alpha"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("settings directory mode");
    }
    fs::write(&settings, driver_settings(&driver, &runs)).expect("workers settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings file mode");
    let run_dir = runs.join("R");
    fs::create_dir_all(&run_dir).expect("run directory");
    fs::set_permissions(
        root.join("configured-durable"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("private run ancestor");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o711)).expect("runs root mode");
    (root.to_path_buf(), driver, settings, run_dir)
}

fn driver_settings(driver: &Path, runs: &Path) -> String {
    format!(
        "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n",
        driver.display(),
        runs.display()
    )
}

/// ´claim:loophome:entry-retired-setting-names-the-driver-vector´
/// ´test:integration:entry-retired-setting-names-the-driver-vector´
#[test]
fn entry_retired_setting_names_the_driver_vector() {
    let directory = TestDir::new_safe("retired-setting");
    let (root, stub) = directory.prepare();
    let log = root.join("podman.log");
    let (_, _, settings, _) = driver_fixture(&directory);
    let built = fs::canonicalize(env!("CARGO_BIN_EXE_superloop")).expect("resolved build binary");
    let programs = tempfile::TempDir::new_in("/var/tmp").expect("protected program directory");
    fs::set_permissions(programs.path(), fs::Permissions::from_mode(0o700))
        .expect("private program directory");
    let entry = programs.path().join("superloop");
    fs::copy(built, &entry).expect("protected entry fixture");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o755)).expect("installed entry mode");
    let alias = programs.path().join("entry-link");
    symlink(&entry, &alias).expect("entry alias");
    let driver = fs::canonicalize(&alias)
        .expect("resolved entry")
        .with_file_name("superloop-lane");
    support::write_executable(&driver, b"#!/bin/sh\nexit 0\n", 0o755).expect("verified sibling");
    let owner = nix::unistd::Uid::effective().as_raw();
    loop_home::workers_settings::owner_executable(&entry, owner).expect("verified entry");
    loop_home::workers_settings::owner_executable(&driver, owner).expect("verified driver");
    let run_entry = || {
        Command::new(&alias)
            .args(["enter", "alpha", "--", "true"])
            .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
            .env("ENTER_LOOP_PODMAN", &stub)
            .env("ENTER_LOOP_STUB_LOG", &log)
            .env("HOME", &root)
            .env("TMPDIR", &root)
            .output_serialized()
            .expect("entry refusal")
    };
    fs::write(&settings, "driver_bin = '/retired/codex-lane'\n").expect("retired setting");
    let output = run_entry();
    let expected = format!(
        "retired-setting: driver_bin; set driver_argv = [{}, \"driver\", \"start\", \"--backend\", \"codex\"]\n",
        toml::Value::String(driver.to_string_lossy().into_owned())
    );
    assert_entry_settings_refusal(&output, &log, &expected);
    let literal = "retired-setting: driver_bin; set driver_argv = [PATH, \"driver\", \"start\", \"--backend\", \"codex\"]";
    for mode in [0o644, 0o777] {
        fs::set_permissions(&driver, fs::Permissions::from_mode(mode))
            .expect("unsafe sibling mode");
        assert_entry_settings_refusal(&run_entry(), &log, literal);
    }
    fs::remove_file(&driver).expect("absent sibling");
    assert_entry_settings_refusal(&run_entry(), &log, literal);
    symlink(&entry, &driver).expect("linked sibling");
    assert_entry_settings_refusal(&run_entry(), &log, literal);
    fs::write(&settings, "never_valid = true\n").expect("unknown setting");
    let output = run_entry();
    assert_entry_settings_refusal(
        &output,
        &log,
        &format!("unknown-setting: {}: never_valid\n", settings.display()),
    );
}

/// ´claim:loophome:ordinary-entry-needs-no-backend-vectors´
/// ´test:integration:ordinary-entry-needs-no-backend-vectors´
#[test]
fn ordinary_entry_needs_no_backend_vectors() {
    let directory = TestDir::new_safe("enter-without-backends");
    let (root, stub) = directory.prepare();
    let (_, driver, settings, run_dir) = driver_fixture(&directory);
    let mut configured: toml::Table =
        toml::from_str(&fs::read_to_string(&settings).expect("settings")).expect("TOML");
    configured.remove("backend_argv");
    fs::write(
        &settings,
        toml::to_string(&configured).expect("settings TOML"),
    )
    .expect("settings without backends");
    let log = root.join("enter-podman.log");
    let output = run(
        &root,
        &stub,
        &log,
        7,
        &["enter", "alpha", "--", "printf", "ok"],
    );
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recorded = fs::read_to_string(&log).expect("entered command");
    assert!(recorded.contains("LANE_BACKEND_ARGV={}"), "{recorded}");
    assert!(recorded.contains("printf ok"), "{recorded}");
    let log = root.join("launch-podman.log");
    let output = launch(
        &root,
        &stub,
        &log,
        0,
        "R",
        &driver,
        &run_dir,
        &["--runtime-contract"],
    );
    assert_driver_refusal(
        &output,
        &log,
        "missing-setting: backend_argv.codex must be a nonempty argument array\n",
    );
    configured.insert("backend_argv".into(), toml::Value::String("invalid".into()));
    fs::write(
        &settings,
        toml::to_string(&configured).expect("malformed settings TOML"),
    )
    .expect("malformed backend table");
    let output = run(&root, &stub, &log, 0, &["enter", "alpha", "--", "true"]);
    assert_entry_settings_refusal(
        &output,
        &log,
        "bad-setting: backend_argv must be an inline table",
    );
}

fn assert_entry_settings_refusal(output: &Output, log: &Path, expected: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let text = std::str::from_utf8(&output.stderr).expect("entry refusal");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(expected.trim_end()));
    assert!(
        lines
            .next()
            .is_some_and(|line| line.starts_with("ENTER-REPORT loop=alpha uid=41001 exit=2 wall=")),
        "{text}"
    );
    assert_eq!(lines.next(), None);
    assert!(!log.exists(), "settings refusal must not launch podman");
}

#[allow(clippy::too_many_arguments)]
fn launch(
    root: &Path,
    stub: &Path,
    log: &Path,
    status: i32,
    run_name: &str,
    driver: &Path,
    run_dir: &Path,
    args: &[&str],
) -> Output {
    let mut words = vec![
        "driver-launch",
        "alpha",
        run_name,
        "--driver-bin",
        driver.to_str().expect("driver path"),
        "--run-dir",
        run_dir.to_str().expect("run path"),
        "--",
    ];
    words.extend_from_slice(args);
    run(root, stub, log, status, &words)
}

fn assert_driver_refusal(output: &Output, log: &Path, prefix: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let message = std::str::from_utf8(&output.stderr).expect("UTF-8 refusal");
    assert!(message.starts_with(prefix), "{message}");
    assert_eq!(message.lines().count(), 1, "{message}");
    assert!(!log.exists(), "refusal must not launch podman");
}

/// ´claim:loophome:driver-launch-forwards-argv-and-child-status´
/// ´test:integration:driver-launch-forwards-argv-and-child-status´
#[test]
fn driver_launch_forwards_argv_and_child_status() {
    let directory = TestDir::new_safe("driver-success");
    let (root, stub) = directory.prepare();
    let (_home, driver, settings_path, run_dir) = driver_fixture(&directory);
    let mut configured: toml::Value =
        toml::from_str(&fs::read_to_string(&settings_path).expect("settings"))
            .expect("TOML settings");
    configured["driver_argv"]
        .as_array_mut()
        .expect("driver vector")
        .extend([
            toml::Value::String("--fixed".into()),
            toml::Value::String("fixed argument".into()),
        ]);
    fs::write(
        &settings_path,
        toml::to_string(&configured).expect("TOML settings"),
    )
    .expect("fixed driver arguments");
    let log = root.join("driver-podman.log");
    let emitting_stub = root.join("emitting-podman-stub");
    support::write_executable(
        &emitting_stub,
        format!(
            "#!/bin/sh\n\"{}\" \"$@\"\nrc=$?\nprintf 'driver stdout\\n'\nprintf 'driver stderr\\n' >&2\nexit \"$rc\"\n",
            stub.display()
        )
        .as_bytes(),
        0o755,
    )
    .expect("emitting podman stub");
    let output = launch(
        &root,
        &emitting_stub,
        &log,
        7,
        "R",
        &driver,
        &run_dir,
        &["a b", "$(touch nope)", "driver-launch"],
    );
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"driver stdout\n");
    assert!(output.stderr.starts_with(b"driver stderr\n"));
    assert_report(&output.stderr[b"driver stderr\n".len()..], 7);
    let recorded = fs::read_to_string(&log).expect("recorded argv");
    assert!(recorded.contains("sh \"$t\" \"$h\" \"$@\""));
    let settings = loop_home::workers_settings::ExecutionSettings {
        driver_argv: vec![
            driver.to_string_lossy().into_owned(),
            "--fixed".into(),
            "fixed argument".into(),
        ],
        backend_argv: std::collections::BTreeMap::from([(
            "codex".to_owned(),
            vec!["/usr/bin/codex".to_owned()],
        )]),
        path: root.join(".config/loops/alpha/workers.toml"),
    };
    assert!(recorded.ends_with(&format!(
        "\nsh\n/usr/bin/env\nLANE_BOXED_RUNTIME=1\nLANE_RUNS_ROOT={}\nLANE_RUN_DIR={}\n{}\n{}\n--fixed\nfixed argument\na b\n$(touch nope)\ndriver-launch\n",
        run_dir.parent().expect("configured root").display(),
        run_dir.display(),
        settings.environment().join("\n"),
        driver.display()
    )));
    assert!(!root.join("nope").exists());
    assert_eq!(
        fs::read_dir(&run_dir).expect("read run directory").count(),
        0
    );
}

/// ´claim:loophome:entry-refuses-absent-settings-root-before-launch´
/// ´test:integration:driver-launch-missing-root-setting-refuses-by-name´
#[test]
fn driver_launch_missing_root_setting_refuses_by_name() {
    let directory = TestDir::new_safe("driver-missing-derived-run");
    let (root, stub) = directory.prepare();
    let (_home, driver, settings, run_dir) = driver_fixture(&directory);
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\n",
            driver.display()
        ),
    )
    .expect("missing setting");
    let log = root.join("driver-podman.log");
    let output = launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]);
    let expected = "runs_root_required: runs_root is absent from workers settings\n";
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, expected.as_bytes());
    assert!(!log.exists());
}

/// ´claim:loophome:configured-root-preserves-driver-input-refusals´
/// ´test:integration:driver-launch-with-configured-root-keeps-refusal-matrix´
#[test]
#[allow(clippy::too_many_lines)]
fn driver_launch_with_configured_root_keeps_refusal_matrix() {
    let cases = [
        "usage",
        "separator",
        "empty arguments",
        "empty home",
        "unknown loop",
        "bad loop name",
        "bad run name",
        "relative driver path",
        "missing settings",
        "linked settings",
        "settings directory",
        "unreadable settings text",
        "malformed settings",
        "missing driver bin",
        "relative driver bin",
        "different driver bin",
        "missing driver",
        "nonexecutable driver",
        "outside run directory",
        "missing run directory",
        "missing runs root",
        "linked run directory",
        "linked runs root",
        "file run directory",
        "file runs root",
        "dotted home",
    ];
    for case in cases {
        let directory = TestDir::new_safe("driver-base-refusals");
        let (root, stub) = directory.prepare();
        let (_home, driver, settings, run_dir) = driver_fixture(&directory);
        let runs_root = run_dir.parent().expect("runs root");
        let log = root.join("driver-podman.log");
        let mut home = root.clone();
        let mut args = vec![
            String::from("driver-launch"),
            String::from("alpha"),
            String::from("R"),
            String::from("--driver-bin"),
            driver.to_string_lossy().into_owned(),
            String::from("--run-dir"),
            run_dir.to_string_lossy().into_owned(),
            String::from("--"),
            String::from("arg"),
        ];
        let noent = std::io::Error::from_raw_os_error(libc::ENOENT);
        let expected = match case {
            "usage" => {
                args.truncate(2);
                String::from(
                    "usage: superloop driver-launch LOOP RUN --driver-bin PATH --run-dir DIR -- ARGS...",
                )
            }
            "separator" => {
                args[7] = String::from("arg");
                String::from("driver-launch requires -- before arguments")
            }
            "empty arguments" => {
                args.pop();
                String::from("driver-launch requires a nonempty argument vector")
            }
            "empty home" => {
                home = std::path::PathBuf::new();
                String::from("HOME must be a nonempty UTF-8 path")
            }
            "unknown loop" => {
                args[1] = String::from("other");
                String::from("unknown loop: other")
            }
            "bad loop name" => {
                args[1] = String::from("bad/name");
                String::from("bad loop name: bad/name")
            }
            "bad run name" => {
                args[2] = String::from("bad/run");
                String::from("bad run name: bad/run")
            }
            "relative driver path" => {
                args[4] = String::from("relative");
                String::from("driver path is not absolute: relative")
            }
            "missing settings" => {
                fs::remove_file(&settings).expect("remove settings");
                format!(
                    "could not read workers settings {}: {noent}",
                    settings.display()
                )
            }
            "linked settings" => {
                fs::remove_file(&settings).expect("remove settings");
                symlink(root.join("target"), &settings).expect("link settings");
                format!(
                    "could not read workers settings {}: {}",
                    settings.display(),
                    std::io::Error::from_raw_os_error(libc::ELOOP)
                )
            }
            "settings directory" => {
                fs::remove_file(&settings).expect("remove settings");
                fs::create_dir(&settings).expect("settings directory");
                format!(
                    "workers settings is not a regular file: {}",
                    settings.display()
                )
            }
            "unreadable settings text" => {
                fs::write(&settings, b"\xff").expect("invalid settings text");
                format!(
                    "could not read workers settings {}: stream did not contain valid UTF-8",
                    settings.display()
                )
            }
            "malformed settings" => {
                fs::write(&settings, "driver_argv = [\n").expect("malformed settings");
                format!("settings-toml: {}: malformed TOML", settings.display())
            }
            "missing driver bin" => {
                fs::write(&settings, "").expect("settings without driver");
                String::from("missing-setting: driver_argv must be a nonempty argument array")
            }
            "relative driver bin" => {
                fs::write(&settings, "driver_argv = [\"relative\"]\n").expect("relative setting");
                String::from(
                    "bad-setting: driver_argv must start with an absolute path without dotted components or commas",
                )
            }
            "different driver bin" => {
                fs::write(
                    &settings,
                    driver_settings(Path::new("/different"), runs_root),
                )
                .expect("different setting");
                format!(
                    "driver path differs from workers settings: {}",
                    settings.display()
                )
            }
            "missing driver" => {
                fs::remove_file(&driver).expect("remove driver");
                format!("could not inspect driver {}: {noent}", driver.display())
            }
            "nonexecutable driver" => {
                fs::set_permissions(&driver, fs::Permissions::from_mode(0o644))
                    .expect("nonexecutable driver");
                format!(
                    "driver is not a regular executable file: {}",
                    driver.display()
                )
            }
            "outside run directory" => {
                let outside = root.join("other/R");
                args[6] = outside.to_string_lossy().into_owned();
                format!(
                    "run directory is outside the loop runs root or has the wrong name: {}",
                    outside.display()
                )
            }
            "missing run directory" => {
                fs::remove_dir(&run_dir).expect("remove run directory");
                format!(
                    "run directory cannot inspect: {noent}: {}",
                    run_dir.display()
                )
            }
            "missing runs root" => {
                fs::remove_dir(&run_dir).expect("remove run directory");
                fs::remove_dir(runs_root).expect("remove runs root");
                format!(
                    "runs_root for loop alpha cannot inspect: {noent}: {}",
                    runs_root.display()
                )
            }
            "linked run directory" => {
                fs::remove_dir(&run_dir).expect("remove run directory");
                symlink(root.join("target"), &run_dir).expect("link run directory");
                format!(
                    "run directory reached through a link: {}",
                    run_dir.display()
                )
            }
            "linked runs root" => {
                let moved = root.join("moved-runs");
                fs::rename(runs_root, &moved).expect("move runs root");
                symlink(&moved, runs_root).expect("link runs root");
                format!(
                    "runs_root for loop alpha is reached through a link: {}",
                    runs_root.display()
                )
            }
            "file run directory" => {
                fs::remove_dir(&run_dir).expect("remove run directory");
                fs::write(&run_dir, b"file").expect("file run directory");
                format!(
                    "run directory component is not a directory: {}",
                    run_dir.display()
                )
            }
            "file runs root" => {
                fs::remove_dir(&run_dir).expect("remove run directory");
                fs::remove_dir(runs_root).expect("remove runs root");
                fs::write(runs_root, b"file").expect("file runs root");
                format!(
                    "runs_root for loop alpha has a nondirectory component: {}",
                    runs_root.display()
                )
            }
            "dotted home" => {
                fs::create_dir(root.join("dot")).expect("dotted home component");
                home = root.join("dot/..");
                let spelled_run = home.join("configured-durable/runs/R");
                args[6] = spelled_run.to_string_lossy().into_owned();
                format!(
                    "allocations path has a dotted component: {}",
                    home.join(".config/loops/allocations.toml").display()
                )
            }
            _ => unreachable!("listed case"),
        };
        let words = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = run_from_home(&root, &home, &stub, &log, 0, &words);
        assert_eq!(output.status.code(), Some(2), "{case}");
        assert_eq!(output.stdout, [] as [u8; 0], "{case}");
        assert_eq!(output.stderr, format!("{expected}\n").as_bytes(), "{case}");
        assert!(!log.exists(), "{case}: refusal must not launch podman");
    }
}

/// ´claim:loophome:driver-launch-refusals-run-no-command´
/// ´test:integration:driver-launch-refuses-unregistered-and-malformed-invocations´
#[test]
fn driver_launch_refuses_unregistered_and_malformed_invocations() {
    let directory = TestDir::new("driver-arguments");
    let (root, stub) = directory.prepare();
    let (_home, driver, _settings, run_dir) = driver_fixture(&directory);
    let log = root.join("driver-podman.log");
    let unknown = run(
        &root,
        &stub,
        &log,
        0,
        &[
            "driver-launch",
            "other",
            "R",
            "--driver-bin",
            driver.to_str().expect("driver path"),
            "--run-dir",
            run_dir.to_str().expect("run path"),
            "--",
            "arg",
        ],
    );
    assert_driver_refusal(&unknown, &log, "unknown loop: other\n");
    let bad_run = launch(
        &root,
        &stub,
        &log,
        0,
        "bad/run",
        &driver,
        &run_dir,
        &["arg"],
    );
    assert_driver_refusal(&bad_run, &log, "bad run name: bad/run\n");
    let newline_run = launch(
        &root,
        &stub,
        &log,
        0,
        "bad\nrun",
        &driver,
        &run_dir,
        &["arg"],
    );
    assert_driver_refusal(&newline_run, &log, "bad run name: bad\\nrun\n");
    let relative = launch(
        &root,
        &stub,
        &log,
        0,
        "R",
        Path::new("driver"),
        &run_dir,
        &["arg"],
    );
    assert_driver_refusal(&relative, &log, "driver path is not absolute: driver\n");
    let no_separator = run(
        &root,
        &stub,
        &log,
        0,
        &[
            "driver-launch",
            "alpha",
            "R",
            "--driver-bin",
            driver.to_str().expect("driver path"),
            "--run-dir",
            run_dir.to_str().expect("run path"),
            "arg",
        ],
    );
    assert_driver_refusal(
        &no_separator,
        &log,
        "driver-launch requires -- before arguments\n",
    );
    let empty = launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &[]);
    assert_driver_refusal(
        &empty,
        &log,
        "driver-launch requires a nonempty argument vector\n",
    );
}

/// ´claim:loophome:ordinary-entry-keeps-driver-launch-as-a-command-word´
/// ´test:integration:ordinary-entry-can-start-a-command-named-driver-launch´
#[test]
fn ordinary_entry_can_start_a_command_named_driver_launch() {
    let directory = TestDir::new("ordinary-driver-word");
    let (root, stub) = directory.prepare();
    let log = root.join("ordinary-podman.log");
    let output = run(
        &root,
        &stub,
        &log,
        0,
        &["enter", "alpha", "--", "driver-launch", "arg"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_report(&output.stderr, 0);
    let script = recorded_outer(&log);
    assert!(script.contains("driver-launch arg"));
    assert!(!script.contains("sh \"$t\" \"$h\" \"$@\""));
}

/// ´claim:loophome:driver-launch-checks-settings-executable-and-run-root´
/// ´test:integration:driver-launch-refuses-unsafe-settings-and-paths-before-launch´
#[test]
#[allow(clippy::too_many_lines)]
fn driver_launch_refuses_unsafe_settings_and_paths_before_launch() {
    let directory = TestDir::new_safe("driver-paths");
    let (root, stub) = directory.prepare();
    let (_home, driver, settings, run_dir) = driver_fixture(&directory);
    let runs_root = run_dir.parent().expect("runs root");
    let log = root.join("driver-podman.log");
    fs::remove_file(&settings).expect("remove settings");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "could not read workers settings ",
    );
    let target = root.join("real-workers.toml");
    fs::write(
        &target,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\n",
            driver.display()
        ),
    )
    .expect("settings target");
    symlink(&target, &settings).expect("settings link");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "could not read workers settings ",
    );
    fs::remove_file(&settings).expect("remove settings link");
    fs::create_dir(&settings).expect("nondocument settings");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "workers settings is not a regular file: ",
    );
    fs::remove_dir(&settings).expect("remove settings directory");
    fs::write(&settings, driver_settings(&driver, runs_root)).expect("readable settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o000)).expect("unreadable settings");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "could not read workers settings ",
    );
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600))
        .expect("restore settings mode");
    fs::write(&settings, "driver_argv = [\n").expect("malformed settings");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "settings-toml: ",
    );
    fs::write(&settings, "driver_argv = [\"relative\"]\n").expect("relative setting");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "bad-setting: driver_argv must start with an absolute path",
    );
    fs::write(
        &settings,
        driver_settings(Path::new("/different"), runs_root),
    )
    .expect("different setting");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "driver path differs from workers settings: ",
    );
    fs::write(&settings, driver_settings(&driver, runs_root)).expect("valid setting");
    let outside = root.join("other/R");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &outside, &["arg"]),
        &log,
        "run directory is outside the loop runs root or has the wrong name: ",
    );
    fs::remove_dir(&run_dir).expect("remove run dir");
    symlink(&outside, &run_dir).expect("run link");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "run directory reached through a link: ",
    );
    fs::remove_file(&run_dir).expect("remove run link");
    fs::create_dir(&run_dir).expect("restore run dir");
    let runs = run_dir.parent().expect("runs root");
    let moved = root.join("moved-runs");
    fs::rename(runs, &moved).expect("move runs root");
    symlink(&moved, runs).expect("link runs root");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "runs_root for loop alpha is reached through a link: ",
    );
    fs::remove_file(runs).expect("remove runs link");
    fs::rename(&moved, runs).expect("restore runs root");
    fs::remove_dir(&run_dir).expect("remove run directory");
    fs::write(&run_dir, "not a directory").expect("run file");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "run directory component is not a directory: ",
    );
    fs::remove_file(&run_dir).expect("remove run file");
    fs::create_dir(&run_dir).expect("restore run directory");
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o644)).expect("nonexecutable driver");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "driver is not a regular executable file: ",
    );
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("restore driver mode");
    fs::remove_file(&driver).expect("remove driver");
    assert_driver_refusal(
        &launch(&root, &stub, &log, 0, "R", &driver, &run_dir, &["arg"]),
        &log,
        "could not inspect driver ",
    );
}

/// A successful command records one outer `unshare sh -c` and emits the stable report line.
///
/// ´claim:loophome:successful-entry-emits-one-report-after-one-podman-command´
/// ´test:integration:successful-entry-has-one-recorded-command-and-report´
#[test]
fn successful_entry_has_one_recorded_command_and_report() {
    let directory = TestDir::new("success");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &stub,
        &log,
        0,
        &["enter", "alpha", "--", "printf", "ok"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_report(&output.stderr, 0);
    let recorded = fs::read_to_string(&log).expect("recorded podman argv");
    assert!(recorded.starts_with("unshare\nsh\n-c\nset -e\n"));
    assert!(recorded.contains("unshare -m sh -c"));
    let report_path = fs::read_to_string(format!("{}.report", log.display())).expect("report path");
    assert_eq!(
        fs::read_to_string(format!("{}.mode", log.display())).expect("report mode"),
        "600\n"
    );
    assert!(!Path::new(report_path.trim()).exists());
}

/// JSON reporting includes both ensure row counts after the temporary report is removed.
///
/// ´claim:loophome:json-entry-report-counts-created-and-corrected-rows´
/// ´test:integration:json-entry-report-carries-ensure-counts´
#[test]
fn json_entry_report_carries_ensure_counts() {
    let directory = TestDir::new("json-report");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["--json", "enter", "alpha", "true"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = std::str::from_utf8(&output.stderr).expect("JSON report");
    assert!(stderr.starts_with("{\"loop\":\"alpha\",\"uid\":41001,\"exit\":0,\"wall_seconds\":"));
    assert!(stderr.ends_with(",\"created\":1,\"corrected\":1}\n"));
    let report_path = fs::read_to_string(format!("{}.report", log.display())).expect("report path");
    assert!(!Path::new(report_path.trim()).exists());
}

/// A missing inspection summary is reported with the temporary report's exact path.
///
/// ´claim:loophome:entry-names-the-report-path-when-inspection-omits-summary´
/// ´test:integration:verify-missing-inspection-error-names-the-report-path´
#[test]
fn verify_missing_inspection_error_names_the_report_path() {
    let directory = TestDir::new("missing-wall");
    let (root, _stub) = directory.prepare();
    let stub = directory.path().join("no-wall-stub");
    support::write_executable(
        &stub,
        b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$7\" > \"$ENTER_LOOP_STUB_LOG\"\n",
        0o755,
    )
    .expect("write no-wall stub");
    let log = directory.path().join("report-path.log");
    let output = run(&root, &stub, &log, 0, &["verify", "alpha"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let report_path = fs::read_to_string(&log).expect("recorded report path");
    assert!(!Path::new(report_path.trim()).exists());
    let expected = format!(
        "report {}: root inspection report omitted summary\n",
        report_path.trim()
    );
    assert!(String::from_utf8_lossy(&output.stderr).starts_with(&expected));
    assert!(
        String::from_utf8_lossy(&output.stderr).ends_with("would_create=null would_correct=null\n")
    );
}

/// The stubbed entry step sees the report as its fifth argument under TMPDIR.
///
/// ´claim:loophome:entry-creates-its-report-under-caller-tmpdir´
/// ´test:integration:report-file-is-created-under-tmpdir´
#[test]
fn report_file_is_created_under_tmpdir() {
    let directory = TestDir::new("report-tmpdir");
    let (root, _stub) = directory.prepare();
    let temporary = directory.path().join("temporary");
    fs::create_dir(&temporary).expect("temporary directory");
    let entry_stub = directory.path().join("entry-stub");
    support::write_executable(
        &entry_stub,
        b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$5\" > \"$ENTER_LOOP_STUB_LOG\"\nprintf 'wall 42\\n' >> \"$5\"\n",
        0o755,
    )
    .expect("write entry stub");
    let podman_stub = directory.path().join("podman-entry-stub");
    support::write_executable(
        &podman_stub,
        b"#!/bin/sh\nset -eu\nscript=$4\nline=$(printf '%s\\n' \"$script\" | sed -n '3p')\nif [ -z \"$line\" ]; then line=$script; fi\neval \"set -- $line\"\nshift\nexec \"$ENTER_LOOP_ENTRY_STUB\" \"$@\"\n",
        0o755,
    )
    .expect("write podman stub");
    let log = directory.path().join("report-path.log");
    let output = enter_loop()
        .args(["provision", "alpha"])
        .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
        .env("ENTER_LOOP_PODMAN", &podman_stub)
        .env("ENTER_LOOP_ENTRY_STUB", &entry_stub)
        .env("ENTER_LOOP_STUB_LOG", &log)
        .env("HOME", &root)
        .env("TMPDIR", &temporary)
        .output_serialized()
        .expect("provision subprocess");
    assert_eq!(output.status.code(), Some(0));
    let report_path = fs::read_to_string(&log).expect("recorded fifth argument");
    let report_path = Path::new(report_path.trim());
    assert_eq!(report_path.parent(), Some(temporary.as_path()));
    assert!(!report_path.exists());
}

/// Provision accepts an existing home and reports zero created rows after the step succeeds.
///
/// ´claim:loophome:provision-accepts-an-existing-complete-home´
/// ´test:integration:provision-accepts-an-existing-home-with-zero-created-rows´
#[test]
fn provision_accepts_an_existing_home_with_zero_created_rows() {
    let directory = TestDir::new("provision-existing");
    let (root, stub) = directory.prepare();
    fs::create_dir_all(root.join(".var/loops/alpha/private")).expect("existing home");
    let log = directory.path().join("podman.log");
    let output = enter_loop()
        .args(["provision", "alpha"])
        .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
        .env("ENTER_LOOP_PODMAN", &stub)
        .env("ENTER_LOOP_STUB_LOG", &log)
        .env("ENTER_LOOP_STUB_STATUS", "0")
        .env("ENTER_LOOP_STUB_ROWS", "none")
        .env("HOME", &root)
        .env("TMPDIR", &root)
        .output_serialized()
        .expect("provision subprocess");
    assert_eq!(output.status.code(), Some(0));
    let stderr = std::str::from_utf8(&output.stderr).expect("report");
    assert!(stderr.ends_with(" created=0 corrected=0\n"));
    assert_eq!(recorded_outer(&log).lines().count(), 4);
    assert!(recorded_outer(&log).contains("_mail-provision"));
}

/// The first private step's failure stops the outer script before its mount namespace.
///
/// ´claim:loophome:ensure-failure-stops-entry-before-any-mount´
/// ´test:integration:ensure-failure-ends-the-outer-script-before-a-mount´
#[test]
fn ensure_failure_ends_the_outer_script_before_a_mount() {
    let directory = TestDir::new("ensure-fail");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["enter", "alpha", "true"]);
    assert_eq!(output.status.code(), Some(0));
    fs::write(directory.path().join("ensure-fail"), b"fail").expect("failure marker");
    let output = execute_outer(&directory, &recorded_outer(&log));
    assert_eq!(output.status.code(), Some(2));
    assert!(!directory.path().join("mount.log").exists());
    assert!(!directory.path().join("setpriv.log").exists());
}

/// The registry command publishes one validated row without touching the runner.
///
/// ´claim:loophome:registry-command-publishes-a-compact-validated-row´
/// ´test:integration:registry-prints-the-validated-row-as-compact-json´
#[test]
fn registry_prints_the_validated_row_as_compact_json() {
    let directory = TestDir::new("registry-json");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["show", "alpha"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!(
            "{{\"launch\":\"{}/dev/alpha\",\"name\":\"alpha\",\"session\":\"SESSION-ID\",\"uid\":41001}}\n",
            directory.path().display()
        )
        .as_bytes()
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!log.exists());
}

/// A declared root appears in the registry row and verify reports its actual owner.
///
/// ´claim:loophome:declared-runs-root-is-published-and-verified´
/// ´test:integration:registry-and-verify-publish-declared-runs-root´
#[test]
fn registry_and_verify_publish_declared_runs_root() {
    let directory = TestDir::new("registry-runs-root");
    let safe_directory = TestDir::new_safe("durable-runs-root");
    let (root, stub) = directory.prepare();
    let runs_root = safe_directory.path().join("durable/runs");
    fs::create_dir_all(&runs_root).expect("durable runs root");
    fs::set_permissions(
        safe_directory.path().join("durable"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("private durable ancestor");
    fs::set_permissions(&runs_root, fs::Permissions::from_mode(0o711)).expect("runs root mode");
    fs::write(
        root.join("registry.toml"),
        format!(
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", runs_root = \"{}\" }}]\n",
            runs_root.display()
        ),
    )
    .expect("registry with runs root");
    let log = root.join("podman.log");
    let registry = run(&root, &stub, &log, 0, &["show", "alpha"]);
    assert_eq!(registry.status.code(), Some(0));
    assert_eq!(
        registry.stdout,
        format!(
            "{{\"launch\":\"{}/dev/alpha\",\"name\":\"alpha\",\"session\":null,\"runs_root\":\"{}\",\"uid\":41001}}\n",
            root.display(),
            runs_root.display()
        )
        .as_bytes()
    );
    let verify = run(&root, &stub, &log, 0, &["verify", "alpha"]);
    assert_eq!(verify.status.code(), Some(0));
    let owner = fs::metadata(&runs_root).expect("runs root owner");
    assert!(String::from_utf8_lossy(&verify.stdout).contains(&format!(
        "\"runs_root\":{{\"gid\":{},\"mode\":\"0711\",\"path\":\"{}\",\"uid\":{}}}",
        owner.gid(),
        runs_root.display(),
        owner.uid()
    )));
}

/// Registry output carries loop identity and refuses former worker keys.
/// ´claim:entry:registry-refuses-former-worker-keys´
/// ´test:integration:registry-refuses-former-worker-keys´
#[test]
fn registry_refuses_former_worker_keys() {
    let directory = TestDir::new("registry-worker-keys");
    let (root, stub) = directory.prepare();
    let path = root.join("registry.toml");
    let log = root.join("podman.log");
    for field in ["workers", "claude_argv", "codex_argv", "default_driver"] {
        fs::write(&path, format!(
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", {field} = 1 }}]\n"
        )).expect("registry fixture");
        let output = run(&root, &stub, &log, 0, &["show", "alpha"]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            output.stderr,
            format!("unknown loop row key: {field}\n").as_bytes()
        );
    }
    fs::write(&path, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n").expect("valid registry");
    let output = run(&root, &stub, &log, 0, &["show", "alpha"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!(
            "{{\"launch\":\"{}/dev/alpha\",\"name\":\"alpha\",\"session\":null,\"uid\":41001}}\n",
            root.display()
        )
        .as_bytes()
    );
}

/// An unknown row is a status-two refusal with no report or runner call.
///
/// ´claim:loophome:registry-command-refuses-an-unregistered-name´
/// ´test:integration:registry-refuses-an-unknown-loop-with-status-2´
#[test]
fn registry_refuses_an_unknown_loop_with_status_2() {
    let directory = TestDir::new("registry-unknown");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["show", "ghost"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, b"unknown loop: ghost\n");
    assert!(!log.exists());
}

/// An absent account file is shown as null while verification succeeds.
///
/// ´claim:loophome:verify-permits-a-row-before-its-account-exists´
/// ´test:integration:verify-without-an-account-file-succeeds-with-null´
#[test]
fn verify_without_an_account_file_succeeds_with_null() {
    let directory = TestDir::new("verify-no-account");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["verify", "alpha"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"account_uid\":null"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"registry_drift\":null"));
}

/// Account disagreement is a status-one diagnostic naming both UID values.
///
/// ´claim:loophome:verify-refuses-account-uid-disagreement-by-name´
/// ´test:integration:verify-with-a-different-account-uid-exits-one´
#[test]
fn verify_with_a_different_account_uid_exits_one() {
    let directory = TestDir::new("verify-account-different");
    let (root, stub) = directory.prepare();
    let account = root.join(".claude/superloop/accounts/alpha/uid");
    fs::create_dir_all(account.parent().expect("account parent")).expect("account parent");
    fs::write(account, b"41002\n").expect("account uid");
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["verify", "alpha"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        output.stderr,
        b"account uid 41002 differs from registry uid 41001 for loop alpha\n"
    );
}

/// A home that needs preparation or refuses a row never starts the inner probe.
///
/// ´claim:entry:verify-home-statuses-skip-the-inner-probe´
/// ´test:integration:verify-home-statuses-skip-the-inner-probe´
#[test]
fn verify_home_statuses_skip_the_inner_probe() {
    for (inspection_status, expected_reason) in [
        (3, "the ensure step would create or correct a home entry"),
        (4, "the ensure step would refuse a home entry"),
    ] {
        let directory = TestDir::new("verify-home-status");
        let (root, stub) = directory.prepare();
        let log = root.join("podman.log");
        let output = run_verify_fixture(
            &root,
            &root,
            &stub,
            &log,
            0,
            &["verify", "alpha"],
            &[
                (
                    "ENTER_LOOP_STUB_INSPECTION_STATUS",
                    inspection_status.to_string(),
                ),
                ("ENTER_LOOP_STUB_WOULD_CREATE", String::from("2")),
                ("ENTER_LOOP_STUB_WOULD_CORRECT", String::from("1")),
            ],
        );
        assert_eq!(output.status.code(), Some(inspection_status));
        let stdout = String::from_utf8(output.stdout).expect("verify JSON");
        assert!(stdout.contains(&format!("\"reason\":\"{expected_reason}\"")));
        assert!(stdout.contains("\"probe\":{\"made\":false"));
        assert!(stdout.contains("\"would_correct\":1,\"would_create\":2"));
        let stderr = String::from_utf8(output.stderr).expect("verify report");
        assert!(stderr.ends_with("s would_create=2 would_correct=1\n"));
        let invocation = fs::read_to_string(&log).expect("inspection invocation");
        assert!(invocation.contains("inspect-roots\n"));
        assert!(!invocation.contains("sh\n-c\n"));
    }
}

/// The full verification plan ignores every caller and loop executable shadow.
///
/// ´claim:entry:verify-invocation-uses-only-fixed-system-programs´
/// ´test:integration:verify-invocation-uses-only-fixed-system-programs´
#[test]
fn verify_invocation_uses_only_fixed_system_programs() {
    let directory = TestDir::new("verify-all-program-shadows");
    let (root, stub) = directory.prepare();
    let caller_bin = root.join("caller-bin");
    let loop_bin = root.join(".var/loops/alpha/private/.local/bin");
    fs::create_dir_all(&caller_bin).expect("caller fixture bin");
    fs::create_dir_all(&loop_bin).expect("loop fixture bin");
    let marker = root.join("shadow-ran");
    for directory in [&caller_bin, &loop_bin] {
        for name in [
            "podman", "sh", "mktemp", "cat", "mkdir", "unshare", "mount", "setpriv", "env", "rm",
            "id", "sort", "sed", "stat", "od", "findmnt", "wc", "find",
        ] {
            support::write_executable(
                &directory.join(name),
                format!("#!/bin/sh\nprintf ran > {}\nexit 77\n", marker.display()).as_bytes(),
                0o755,
            )
            .expect("shadow fixture");
        }
    }
    let log = root.join("podman.log");
    let output = run_verify_fixture(
        &root,
        &root,
        &stub,
        &log,
        0,
        &["verify", "alpha"],
        &[("PATH", format!("{}:/usr/bin:/bin", caller_bin.display()))],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"probe\":{\"made\":true"));
    assert!(!marker.exists());
    let entry = fs::read_to_string(format!("{}.verify-entry", log.display())).expect("entry plan");
    let first = entry.lines().next().expect("resolved container route");
    assert!(
        [
            "/usr/bin/podman",
            "/bin/podman",
            "/usr/local/bin/podman",
            "/usr/bin/flatpak-spawn",
            "/bin/flatpak-spawn",
            "/usr/local/bin/flatpak-spawn",
        ]
        .contains(&first),
        "{first}"
    );
    if first.ends_with("flatpak-spawn") {
        assert!(entry.starts_with(&format!(
            "{first}\n--host\n/usr/bin/podman\nunshare\n/bin/sh\n-c\n"
        )));
    } else {
        assert!(entry.starts_with(&format!("{first}\nunshare\n/bin/sh\n-c\n")));
    }
    for program in [
        "/usr/bin/mktemp",
        "/usr/bin/cat",
        "/usr/bin/mkdir",
        "/usr/bin/rm",
        "/usr/bin/unshare",
        "/usr/bin/mount",
        "/usr/bin/setpriv",
        "/usr/bin/env",
    ] {
        assert!(entry.contains(program), "{program}");
    }
    for unqualified in [
        "$(mktemp ",
        "\ncat ",
        "\nmkdir ",
        "\nrm -rf",
        "\nunshare -m sh",
        "\nmount --bind",
        "\nexec setpriv",
    ] {
        assert!(!entry.contains(unqualified), "{unqualified}");
    }
    assert!(entry.contains("PATH=\"/usr/bin:/bin\""));
    assert!(entry.contains("_mail-group"));
    assert!(entry.contains("group_option=--groups=$mail_group"));
    assert!(entry.contains("--clear-groups"));
}

/// Probe and cleanup statuses never masquerade as home inspection findings.
///
/// ´claim:entry:verify-probe-and-cleanup-failures-exit-one-with-command-status´
/// ´test:integration:verify-probe-and-cleanup-failures-exit-one-with-command-status´
#[test]
fn verify_probe_and_cleanup_failures_exit_one_with_command_status() {
    for status in [2, 3, 4] {
        let directory = TestDir::new("verify-entry-failure");
        let (root, stub) = directory.prepare();
        let log = root.join("podman.log");
        let output = run(&root, &stub, &log, status, &["verify", "alpha"]);
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).expect("verify diagnostic");
        assert!(stderr.contains(&format!("verify entry exited with status {status}")));
        assert!(stderr.contains("exit=1"));
    }
    let directory = TestDir::new("verify-cleanup-failure");
    let (root, stub) = directory.prepare();
    let log = root.join("podman.log");
    let output = run_verify_fixture(
        &root,
        &root,
        &stub,
        &log,
        0,
        &["verify", "alpha"],
        &[("ENTER_LOOP_STUB_CLEANUP_STATUS", String::from("4"))],
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("verify diagnostic");
    assert!(stderr.contains("verify cleanup exited with status 4"));
    assert!(stderr.contains("exit=1"));
}

/// A caller-selected temporary directory inside the named home is ignored by verify.
///
/// ´claim:entry:verify-report-stays-outside-home-with-home-tmpdir´
/// ´test:integration:verify-report-stays-outside-home-with-home-tmpdir´
#[test]
fn verify_report_stays_outside_home_with_home_tmpdir() {
    let directory = TestDir::new("verify-home-tmpdir");
    let (root, _stub) = directory.prepare();
    let home = root.join(".var/loops/alpha");
    fs::create_dir_all(&home).expect("fixture loop home");
    let before = fs::symlink_metadata(&home).expect("home before");
    let stub = root.join("verify-tmp-stub");
    support::write_executable(
        &stub,
        b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$7\" > \"$ENTER_LOOP_STUB_LOG\"\nprintf 'inspection 3 1 0\\n[{\"action\":\"create\"}]\\n' >> \"$7\"\nexit 3\n",
        0o755,
    )
    .expect("inspection stub");
    let log = root.join("inspection-report-path");
    let output = run_verify_fixture(
        &root,
        &root,
        &stub,
        &log,
        0,
        &["verify", "alpha"],
        &[("TMPDIR", home.to_string_lossy().into_owned())],
    );
    assert_eq!(output.status.code(), Some(3));
    let after = fs::symlink_metadata(&home).expect("home after");
    assert_eq!(before.uid(), after.uid());
    assert_eq!(before.gid(), after.gid());
    assert_eq!(before.mode(), after.mode());
    assert_eq!(before.mtime(), after.mtime());
    assert_eq!(before.mtime_nsec(), after.mtime_nsec());
    assert_eq!(fs::read_dir(&home).expect("home entries").count(), 0);
    let report_path = fs::read_to_string(&log).expect("report path");
    let report_path = Path::new(report_path.trim());
    assert!(!report_path.starts_with(&home));
    assert!(!report_path.exists());
}

/// An executed outer script passes the directory present at entry time to the nested call.
///
/// ´claim:loophome:the-entry-home-is-private-when-the-loop-home-carries-it´
/// ´test:integration:entry-home-follows-private-when-present´
#[test]
fn entry_home_follows_private_when_present() {
    let directory = TestDir::new("entry-home");
    let (root, podman_stub) = directory.prepare();
    let home = directory.path().join(".var/loops/alpha");
    fs::create_dir_all(&home).expect("create loop home");
    let podman_log = directory.path().join("podman.log");
    let output = run(
        &root,
        &podman_stub,
        &podman_log,
        0,
        &["enter", "alpha", "--", "true"],
    );
    assert_eq!(output.status.code(), Some(0));
    let recorded = fs::read_to_string(podman_log).expect("recorded podman argv");
    let outer_script = recorded
        .strip_prefix("unshare\nsh\n-c\n")
        .and_then(|script| script.strip_suffix('\n'))
        .expect("recorded outer script");

    let bin = directory.path().join("bin");
    fs::create_dir(&bin).expect("create stub directory");
    let unshare_stub = bin.join("unshare");
    support::write_executable(
        &unshare_stub,
        b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$ENTER_LOOP_UNSHARE_LOG\"\n",
        0o755,
    )
    .expect("write unshare stub");
    let unshare_log = directory.path().join("unshare.log");
    let entry_stub = bin.join("entry-step");
    support::write_executable(
        &entry_stub,
        b"#!/bin/sh\nif [ \"$1\" = _supervise-command ]; then exec \"$ENTER_LOOP_REAL_ENTRY\" \"$@\"; fi\nprintf 'wall 10\\n' >> \"$5\"\n",
        0o755,
    )
    .expect("write entry stub");
    let executable = fs::canonicalize(env!("CARGO_BIN_EXE_superloop")).expect("entry path");
    let outer_script = outer_script.replace(executable.to_str().expect("UTF-8 path"), "entry-step");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").expect("system utility path")
    );
    let run_outer = || {
        let output = Command::new("sh")
            .args(["-c", &outer_script])
            .env("PATH", &path)
            .env("ENTER_LOOP_UNSHARE_LOG", &unshare_log)
            .env("ENTER_LOOP_REAL_ENTRY", &executable)
            .output_serialized()
            .expect("outer script runs");
        assert!(
            output.status.success(),
            "outer script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::read_to_string(&unshare_log)
            .expect("recorded unshare argv")
            .lines()
            .last()
            .expect("nested home argument")
            .to_owned()
    };

    assert_eq!(run_outer(), home.to_string_lossy());
    let private = home.join("private");
    fs::create_dir(&private).expect("create private home");
    assert_eq!(run_outer(), private.to_string_lossy());
}

/// The bridge runs the fixed `GnuPG` executable with the entered home's custody selector.
///
/// ´claim:loophome:the-gpg-bridge-uses-the-custody-keyring-through-the-entry´
/// ´test:integration:gpg-bridge-execs-gpg-with-the-custody-keyring´
#[test]
fn gpg_bridge_execs_gpg_with_the_custody_keyring() {
    let directory = TestDir::new("gpg-bridge-custody");
    let (root, podman_stub) = directory.prepare();
    let home = directory.path().join(".var/loops/alpha");
    fs::create_dir_all(home.join(".config/custody")).expect("create custody bind target");
    fs::create_dir_all(home.join(".ssh")).expect("create SSH bind target");
    fs::create_dir_all(directory.path().join(".config/loops/alpha/private/ssh"))
        .expect("create custody tier");
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &podman_stub,
        &log,
        0,
        &["run-bridge", "gpg", "alpha", "--", "--version", "two words"],
    );
    assert_eq!(output.status.code(), Some(0));
    let output = execute_outer(&directory, &recorded_outer(&log));
    assert!(
        output.status.success(),
        "GnuPG bridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let custody =
        fs::read_to_string(directory.path().join("custody.log")).expect("custody arguments");
    assert!(custody.starts_with("bind-custody\n41001\n"));
    let setpriv =
        fs::read_to_string(directory.path().join("setpriv.log")).expect("setpriv arguments");
    assert!(setpriv.contains(&format!("GNUPGHOME={}/.config/custody/gpg", home.display())));
    assert!(setpriv.contains(&format!(
        "GH_CONFIG_DIR={}/.config/custody/gh",
        home.display()
    )));
    assert!(setpriv.contains("/usr/bin/gpg\n--version\ntwo words\n"));
    let mounts = fs::read_to_string(directory.path().join("mount.log")).expect("mount arguments");
    assert_eq!(mounts.matches("--bind\n").count(), 3);
}

/// Without a tier, the bridge selects the keyring beneath the home chosen by the outer script.
///
/// ´claim:loophome:the-gpg-bridge-selects-an-entered-home-pre-custody-keyring-without-a-tier´
/// ´test:integration:gpg-bridge-selects-the-pre-custody-keyring-without-a-tier´
#[test]
fn gpg_bridge_selects_the_pre_custody_keyring_without_a_tier() {
    let directory = TestDir::new("gpg-bridge-pre-custody");
    let (root, podman_stub) = directory.prepare();
    let home = directory.path().join(".var/loops/alpha");
    let entered = home.join("private");
    fs::create_dir_all(entered.join(".config/gpg-loops/alpha"))
        .expect("create entered-home keyring directory");
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &podman_stub,
        &log,
        0,
        &["run-bridge", "gpg", "alpha", "--", "--version"],
    );
    assert_eq!(output.status.code(), Some(0));
    let output = execute_outer(&directory, &recorded_outer(&log));
    assert!(
        output.status.success(),
        "GnuPG bridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let setpriv =
        fs::read_to_string(directory.path().join("setpriv.log")).expect("setpriv arguments");
    assert!(
        setpriv
            .lines()
            .any(|word| word == format!("GNUPGHOME={}/.config/gpg-loops/alpha", entered.display()))
    );
    assert!(setpriv.contains("/usr/bin/gpg\n--version\n"));
    assert!(!directory.path().join("custody.log").exists());
}

/// Without either keyring location, the bridge passes no `GnuPG` home to the loop.
///
/// ´claim:loophome:the-gpg-bridge-leaves-the-keyring-unselected-without-a-tier-or-old-directory´
/// ´test:integration:no-keyring-is-selected-without-a-tier-or-a-pre-custody-directory´
#[test]
fn no_keyring_is_selected_without_a_tier_or_a_pre_custody_directory() {
    let directory = TestDir::new("gpg-bridge-no-keyring");
    let (root, podman_stub) = directory.prepare();
    let home = directory.path().join(".var/loops/alpha");
    fs::create_dir_all(&home).expect("create loop home");
    fs::create_dir_all(directory.path().join(".config/gpg-loops/alpha"))
        .expect("create caller-home decoy keyring directory");
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &podman_stub,
        &log,
        0,
        &["run-bridge", "gpg", "alpha", "--", "--version"],
    );
    assert_eq!(output.status.code(), Some(0));
    let output = execute_outer(&directory, &recorded_outer(&log));
    assert!(
        output.status.success(),
        "GnuPG bridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let setpriv =
        fs::read_to_string(directory.path().join("setpriv.log")).expect("setpriv arguments");
    assert!(!setpriv.lines().any(|word| word.starts_with("GNUPGHOME=")));
    assert!(setpriv.contains("/usr/bin/gpg\n--version\n"));
    assert!(!directory.path().join("custody.log").exists());
}

/// Separate compositions select the two custody exports only with a tier.
///
/// ´claim:loophome:the-entry-binds-custody-and-selects-its-keyring-and-forge-config´
/// ´test:integration:entry-environment-carries-custody-variables-only-when-present´
#[test]
fn entry_environment_carries_custody_variables_only_when_present() {
    let directory = TestDir::new("custody-environment");
    let (root, podman_stub) = directory.prepare();
    let home = directory.path().join(".var/loops/alpha");
    fs::create_dir_all(home.join(".config/custody")).expect("create custody bind target");
    fs::create_dir_all(home.join(".ssh")).expect("create SSH bind target");
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &podman_stub,
        &log,
        0,
        &["enter", "alpha", "--", "/usr/bin/env"],
    );
    assert_eq!(output.status.code(), Some(0));
    let script = recorded_outer(&log);
    let output = execute_outer(&directory, &script);
    assert!(output.status.success());
    let setpriv =
        fs::read_to_string(directory.path().join("setpriv.log")).expect("setpriv arguments");
    assert!(!setpriv.contains("GNUPGHOME="));
    assert!(!setpriv.contains("GH_CONFIG_DIR="));
    assert!(!directory.path().join("custody.log").exists());
    let mounts = fs::read_to_string(directory.path().join("mount.log")).expect("mount arguments");
    assert_eq!(mounts.matches("--bind\n").count(), 3);

    fs::create_dir_all(directory.path().join(".config/loops/alpha/private/ssh"))
        .expect("create custody tier");
    fs::remove_file(directory.path().join("mount.log")).expect("reset mount log");
    let output = run(
        &root,
        &podman_stub,
        &log,
        0,
        &["enter", "alpha", "--", "/usr/bin/env"],
    );
    assert_eq!(output.status.code(), Some(0));
    let output = execute_outer(&directory, &recorded_outer(&log));
    assert!(
        output.status.success(),
        "custody entry failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let setpriv =
        fs::read_to_string(directory.path().join("setpriv.log")).expect("setpriv arguments");
    assert!(setpriv.contains(&format!(
        "GNUPGHOME={}/.config/custody/gpg\n",
        home.display()
    )));
    assert!(setpriv.contains(&format!(
        "GH_CONFIG_DIR={}/.config/custody/gh\n",
        home.display()
    )));
    let custody =
        fs::read_to_string(directory.path().join("custody.log")).expect("custody arguments");
    assert_eq!(
        custody,
        format!(
            "bind-custody\n41001\n{}\n{}\n{}\n",
            home.display(),
            home.display(),
            directory
                .path()
                .join(".config/loops/alpha/private")
                .display()
        )
    );
    let mounts = fs::read_to_string(directory.path().join("mount.log")).expect("mount arguments");
    assert_eq!(mounts.matches("--bind\n").count(), 3);
}

/// A command argument containing a newline reaches the recorded outer script as one literal word.
///
/// ´claim:loophome:command-arguments-survive-entry-composition-byte-for-byte´
/// ´test:integration:command-argument-newline-survives-composition´
#[test]
fn command_argument_newline_survives_composition() {
    let directory = TestDir::new("newline-argument");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &stub,
        &log,
        0,
        &["enter", "alpha", "--", "printf", "%s", "line-a\nline-b"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_report(&output.stderr, 0);
    let recorded = fs::read(log).expect("recorded podman argv");
    assert!(
        recorded
            .windows(b"'line-a\nline-b'".len())
            .any(|window| window == b"'line-a\nline-b'")
    );
    assert!(!recorded.windows(2).any(|window| window == b"\\\n"));
}

/// A nonzero inner status is returned unchanged and remains visible in the report.
///
/// ´claim:loophome:entry-exit-status-is-the-entered-command-status´
/// ´test:integration:status-seven-is-propagated-and-reported´
#[test]
fn status_seven_is_propagated_and_reported() {
    let directory = TestDir::new("status-seven");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 7, &["enter", "alpha", "true"]);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_report(&output.stderr, 7);
}

///
/// # Panics
/// Panics only if fixture setup fails or entry changes the forwarded command or status.
/// ´claim:entry:ordinary-entry-forwards-former-mail-word-and-status´
/// ´test:integration:ordinary-entry-forwards-former-mail-word-and-status´
#[test]
fn ordinary_entry_forwards_former_mail_word_and_status() {
    let directory = TestDir::new("letters-wall-entry");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(
        &root,
        &stub,
        &log,
        124,
        &[
            "enter", "alpha", "--", "letters", "follow", "--next", "--wall", "1",
        ],
    );
    assert_eq!(output.status.code(), Some(124));
    let recorded = fs::read_to_string(log).expect("forwarded private command");
    assert!(!recorded.contains("letters-private alpha"));
    assert!(recorded.contains("letters follow --next --wall 1"));
    assert!(recorded.contains("follow --next --wall 1"));
    assert_report(&output.stderr, 124);
}

/// Invalid names are rejected with one line and without reaching the configured podman stub.
///
/// ´claim:loophome:refusals-precede-every-podman-invocation´
/// ´test:integration:bad-name-refusal-exits-two-without-podman´
#[test]
fn bad_name_refusal_exits_two_without_podman() {
    let directory = TestDir::new("bad-name");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["enter", "Bad", "true"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, b"bad loop name: Bad\n");
    assert!(!log.exists());
}

/// A symbolic link at the owner-tested tier is refused before resolving podman.
///
/// ´claim:loophome:a-nondirectory-tier-stops-the-subprocess-before-podman´
/// ´test:integration:a-custody-tier-that-is-not-a-directory-is-refused-without-podman´
#[test]
fn a_custody_tier_that_is_not_a_directory_is_refused_without_podman() {
    let directory = TestDir::new("tier-link");
    let (root, stub) = directory.prepare();
    let tier = directory.path().join(".config/loops/alpha/private");
    fs::create_dir_all(tier.parent().expect("tier parent")).expect("create parent");
    let destination = directory.path().join("destination");
    fs::create_dir(&destination).expect("create destination");
    symlink(&destination, &tier).expect("link tier");
    let log = directory.path().join("podman.log");
    let output = run(&root, &stub, &log, 0, &["enter", "alpha", "true"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        output.stderr,
        format!("custody tier is not a directory: {}\n", tier.display()).as_bytes()
    );
    assert!(!log.exists());
}

/// An unrepresentable caller HOME is refused even with a registry override.
///
/// ´claim:loophome:a-non-utf8-home-stops-the-subprocess-before-podman´
/// ´test:integration:a-non-utf8-home-is-refused-without-podman´
#[test]
fn a_non_utf8_home_is_refused_without_podman() {
    let directory = TestDir::new("bad-home");
    let (root, stub) = directory.prepare();
    let log = directory.path().join("podman.log");
    let output = enter_loop()
        .args(["enter", "alpha", "true"])
        .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
        .env("HOME", std::ffi::OsString::from_vec(b"/bad\xff".to_vec()))
        .env("ENTER_LOOP_PODMAN", &stub)
        .env("ENTER_LOOP_STUB_LOG", &log)
        .output_serialized()
        .expect("entry runs");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stderr, b"HOME must be a nonempty UTF-8 path\n");
    assert!(!log.exists());
}

/// The real private step refuses a planted SSH link at open, before any mount or UID check.
///
/// ´claim:loophome:the-private-subprocess-refuses-a-planted-ssh-link-at-open´
/// ´test:integration:bind-custody-refuses-a-symbolic-link-before-any-mount´
#[test]
fn bind_custody_refuses_a_symbolic_link_before_any_mount() {
    let directory = TestDir::new("bind-link");
    let home = directory.path().join(".var/loops/alpha");
    let tier = directory.path().join("tier");
    fs::create_dir_all(home.join(".config/custody")).expect("custody target");
    fs::create_dir_all(tier.join("ssh")).expect("custody ssh");
    let elsewhere = directory.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("link destination");
    symlink(&elsewhere, home.join(".ssh")).expect("plant ssh link");
    let output = enter_loop()
        .args(["bind-custody", "41001"])
        .arg(&home)
        .arg(&home)
        .arg(&tier)
        .output_serialized()
        .expect("private step runs");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        output.stderr,
        format!(
            "custody bind refused: {}: ELOOP\n",
            home.join(".ssh").display()
        )
        .as_bytes()
    );
}

/// The private ensure step accepts only its four validated arguments.
///
/// ´claim:loophome:ensure-roots-accepts-only-its-four-validated-arguments´
/// ´test:integration:ensure-roots-refuses-every-other-argument-form´
#[test]
fn ensure_roots_refuses_every_other_argument_form() {
    let directory = TestDir::new("ensure-usage");
    let home = directory.path().join("home");
    let report = directory.path().join("report");
    let mut forms = vec![
        vec!["41001", "alpha", "/home"],
        vec!["999", "alpha", "/home", "/report"],
        vec!["65536", "alpha", "/home", "/report"],
        vec!["word", "alpha", "/home", "/report"],
        vec!["41001", "Bad", "/home", "/report"],
        vec!["41001", "-alpha", "/home", "/report"],
        vec!["41001", "invalid_name", "/home", "/report"],
        vec!["41001", "alpha", "home", "/report"],
        vec!["41001", "alpha", "/home", "report"],
        vec!["41001", "alpha", "/home", "/report", "extra"],
    ];
    forms.push(vec!["+41001", "alpha", "/home", "/report"]);
    for arguments in forms {
        let output = enter_loop()
            .arg("ensure-roots")
            .args(arguments)
            .output_serialized()
            .expect("usage subprocess");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert_eq!(
            output.stderr,
            b"usage: superloop ensure-roots UID NAME HOME REPORT\n"
        );
    }
    for slot in [0, 1, 2, 3] {
        let mut arguments = ["41001", "alpha", "/home", "/report"].map(std::ffi::OsString::from);
        arguments[slot] = std::ffi::OsString::from_vec(b"/bad\xff".to_vec());
        let output = enter_loop()
            .arg("ensure-roots")
            .args(arguments)
            .output_serialized()
            .expect("non-UTF-8 argument subprocess");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert_eq!(
            output.stderr,
            b"usage: superloop ensure-roots UID NAME HOME REPORT\n"
        );
    }
    let output = enter_loop()
        .arg("ensure-roots")
        .arg("41001")
        .arg("provision")
        .arg(&home)
        .arg(&report)
        .output_serialized()
        .expect("absent report subprocess");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        output.stderr,
        format!(
            "ensure refused: {}: No such file or directory (os error 2)\n",
            report.display()
        )
        .as_bytes()
    );
    assert!(!report.exists());
}

/// The real step requires namespace-root ownership before touching any row.
///
/// ´claim:loophome:ensure-roots-subprocess-refuses-a-nonowner-class-root-before-changes´
/// ´test:integration:ensure-roots-refuses-the-first-owner-row-under-an-unprivileged-uid´
#[test]
fn ensure_roots_refuses_the_first_owner_row_under_an_unprivileged_uid() {
    let directory = TestDir::new("ensure-owner");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("fixture home");
    let class = home.join(".var");
    fs::create_dir(&class).expect("fixture class root");
    fs::set_permissions(&class, fs::Permissions::from_mode(0o711)).expect("class mode");
    let cache = home.join(".cache");
    fs::create_dir(&cache).expect("fixture cache root");
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o711)).expect("cache mode");
    fs::create_dir(home.join(".config")).expect("fixture config root");
    let report = directory.path().join("report");
    fs::write(&report, b"").expect("preexisting report");
    let uid = fs::metadata(&class).expect("class owner").uid();
    let output = enter_loop()
        .arg("ensure-roots")
        .arg("41001")
        .arg("alpha")
        .arg(&home)
        .arg(&report)
        .output_serialized()
        .expect("ensure subprocess");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 refusal"),
        format!(
            "ensure refused: {}: owned by uid {uid}, expected uid 0\n",
            class.display()
        )
    );
    assert_eq!(fs::read(&report).expect("report"), b"");
    assert!(!home.join(".var/loops").exists());
}
