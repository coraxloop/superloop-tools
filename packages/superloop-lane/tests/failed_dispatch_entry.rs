//! Failed dispatch recovery through the production command entry.

#[path = "support/entry.rs"]
mod entry;

use entry::retry_busy_entry;

#[path = "support/registry_entry.rs"]
mod registry_fixture;

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use superloop_lane::build::sha256;
use tempfile::TempDir;

fn executable(path: &Path, source: &str) {
    fs::write(path, source).expect("fixture program");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("program mode");
}

struct Fixture {
    _root: TempDir,
    home: PathBuf,
    binary: PathBuf,
    letter: PathBuf,
    podman: PathBuf,
    reservation: PathBuf,
}

#[allow(clippy::too_many_lines)]
fn fixture() -> Fixture {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
        .expect("host ancestor mode");
    let home_dir = fixture.path().join("home");
    fs::create_dir(&home_dir).expect("owner home");
    let home = home_dir.as_path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o711)).expect("host home mode");
    let custody = home.join(".config/loops/alpha");
    fs::create_dir_all(&custody).expect("custody");
    for path in [
        home.join(".config"),
        home.join(".config/loops"),
        custody.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("custody mode");
    }
    let runs = home.join(".var/loops/alpha/runs");
    let template = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64));
    let sockets = home.join(".var/loops/alpha/sockets");
    let entry = home.join("entry-fixture");
    let podman = home.join("container-fixture");
    let driver = home.join("driver-fixture");
    let lane_bin = home.join("lane-fixture");
    let scratchpad = home.join("scratchpad");
    fs::create_dir(&scratchpad).expect("letter scratchpad");
    fs::set_permissions(&scratchpad, fs::Permissions::from_mode(0o700)).expect("scratchpad mode");
    let letter = scratchpad.join("first-letter");
    let observation = json!({"schema":1,"command":"observed-hosts","loop":"alpha","run":"R","mode":"observing","enforcing":false,"source":runs.join(".observed-R.txt"),"attempted_connect_hosts":{"api.example.com":true,"failed.example.com":false},"connected_hosts":["api.example.com"]});
    executable(&entry, "#!/bin/sh\nexit 0\n");
    executable(
        &podman,
        &format!(
            "#!/bin/sh\nprintf 'called\\n' >> '{}'\nif [ \"$1 $2\" = 'image inspect' ]; then printf '{}\\n'; exit 0; fi\nif [ \"$1\" = unshare ]; then printf '%s\\n' '{}'; exit 0; fi\nif [ \"$1\" = ps ]; then exit 0; fi\nexit 9\n",
            home.join("container-calls").display(),
            "a".repeat(64),
            observation
        ),
    );
    executable(
        &driver,
        "#!/bin/sh\nif [ \"$5\" = --runtime-contract ]; then printf 'boxed-runtime 1\\n'; fi\nexit 0\n",
    );
    fs::copy(env!("CARGO_BIN_EXE_superloop-lane"), &lane_bin).expect("production binary");
    fs::set_permissions(&lane_bin, fs::Permissions::from_mode(0o700)).expect("binary mode");
    executable(&home.join("proxy-fixture"), "#!/bin/sh\nexit 0\n");
    fs::create_dir_all(&runs).expect("runs root");
    for path in [
        home.join(".var"),
        home.join(".var/loops"),
        home.join(".var/loops/alpha"),
        runs.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private runs ancestor");
    }
    fs::create_dir_all(template.join("bin")).expect("template bin");
    fs::create_dir_all(template.join("libexec")).expect("template helper directory");
    fs::create_dir_all(sockets.join("vendor")).expect("vendor sockets");
    fs::create_dir_all(sockets.join("door")).expect("door sockets");
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700))
        .expect("socket directory mode");
    fs::set_permissions(sockets.join("vendor"), fs::Permissions::from_mode(0o700))
        .expect("vendor socket directory mode");
    let vendor_socket = sockets.join("vendor/proxy.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&vendor_socket).expect("vendor socket");
    fs::set_permissions(&vendor_socket, fs::Permissions::from_mode(0o660)).expect("socket mode");
    fs::set_permissions(sockets.join("door"), fs::Permissions::from_mode(0o750))
        .expect("door socket directory mode");
    fs::create_dir_all(custody.join("lanes/codex")).expect("sign-in place");
    fs::create_dir_all(home.join(".cache/tmp")).expect("home parent");
    fs::write(template.join("bin/codex"), "pinned codex\n").expect("codex pin");
    fs::write(template.join("bin/codex-code-mode-host"), "pinned host\n").expect("host pin");
    fs::write(
        template.join("config.toml"),
        "sandbox_mode = \"danger-full-access\"\n",
    )
    .expect("policy pin");
    fs::write(template.join("AGENTS.md"), "A worker charter.\n").expect("charter pin");
    let data = home.join("image-data");
    fs::create_dir(&data).expect("image data");
    fs::write(data.join("box-init"), "fixed init\n").expect("init pin");
    fs::write(template.join("libexec/box-init"), "fixed init\n").expect("installed init pin");
    fs::write(template.join("libexec/ssh"), "keyless stub\n").expect("door stub pin");
    fs::write(custody.join("door-service"), "registered service\n").expect("door service pin");
    let image = format!("sha256:{}", "a".repeat(64));
    let codex_hash = sha256(&template.join("bin/codex")).expect("codex hash");
    let host_hash = sha256(&template.join("bin/codex-code-mode-host")).expect("host hash");
    fs::write(template.join("manifest"), serde_json::to_vec(&json!({"image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"config_sha256":sha256(&template.join("config.toml")).expect("config hash"),"charter_sha256":sha256(&template.join("AGENTS.md")).expect("charter hash")})).expect("manifest")).expect("manifest file");
    for (path, mode) in [
        (home.join(".var/loops/alpha/runner-templates"), 0o711),
        (home.join(".var/loops/alpha/runner-templates/codex"), 0o711),
        (template.join("bin/codex"), 0o550),
        (template.join("bin/codex-code-mode-host"), 0o550),
        (template.join("config.toml"), 0o440),
        (template.join("AGENTS.md"), 0o440),
        (template.join("manifest"), 0o440),
        (template.join("bin"), 0o550),
        (template.join("libexec"), 0o550),
        (template.join("libexec/box-init"), 0o440),
        (template.join("libexec/ssh"), 0o550),
        (template.clone(), 0o550),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("installed pin mode");
    }
    fs::set_permissions(
        custody.join("door-service"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("door service mode");
    let image_program = "/usr/libexec/superloop/fixture-image-codex";
    assert!(!std::path::Path::new(image_program).exists());
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&json!({"package_inventory":[],"image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"codex_host_probe":{"argv":["--help"],"stdout":"host help","sha256":host_hash},"init_sha256":sha256(&data.join("box-init")).expect("init hash"),"codex_image_program":image_program,"build_environment":{"template_dir":data},"codex_exec_probe":{"argv":["exec","--help"],"stdout":"  -m, --model\n  -c, --config\n  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n","required_options":["--json", "--sandbox", "--add-dir", "--skip-git-repo-check", "-C", "-o"],"codex_sha256":codex_hash,"companions":[{"name":"codex-code-mode-host","path":"/usr/libexec/superloop/codex-code-mode-host","sha256":host_hash}]}})).expect("report")).expect("report file");
    fs::write(custody.join("install-generation.json"), serde_json::to_vec(&json!({"schema":1,"phase":"complete","image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"codex_image_program":image_program,"proxy_bin":home.join("proxy-fixture"),"proxy_sha256":sha256(&home.join("proxy-fixture")).expect("proxy hash"),"init_sha256":sha256(&data.join("box-init")).expect("init hash")})).expect("generation")).expect("generation file");
    fs::write(&letter, "Read this letter.\n").expect("letter");
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display())).expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let allocations = home.join(".config/loops/allocations.toml");
    fs::write(&allocations, "[alpha]\nuids = { base = 3000, count = 2 }\n").expect("allocation");
    fs::set_permissions(&allocations, fs::Permissions::from_mode(0o600)).expect("allocation mode");
    let settings = custody.join("workers.toml");
    let source = format!(
        "runs_root = \"{}\"\nentry_bin = \"{}\"\ndriver_argv = [\"{}\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nbackend_argv = {{ codex = [\"{}\"] }}\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
        runs.display(),
        entry.display(),
        driver.display(),
        "a".repeat(64),
        template.display(),
        sockets.display(),
        image_program
    );
    fs::write(&settings, &source).expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    let door_generation = custody.join("door-install-generation.json");
    let stub_digest = sha256(&template.join("libexec/ssh")).expect("stub digest");
    fs::write(
        &door_generation,
        serde_json::to_vec(&json!({"schema":2,"agent":{"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"entry":"/fixture/entry","loop_home":"/fixture/home"},"phase":"complete","loop":"alpha","template_dir":template,"socket_dir":sockets,"stub_sha256":stub_digest,"service_sha256":sha256(&custody.join("door-service")).expect("service digest"),"unit_dir":custody.join("units"),"registered":["ssh"],"host_door_gid":nix::unistd::Gid::effective().as_raw()})).expect("door generation"),
    )
    .expect("door generation file");
    fs::set_permissions(&door_generation, fs::Permissions::from_mode(0o600))
        .expect("door generation mode");
    fs::write(
        &settings,
        format!("{source}vendor_hosts = {{ codex = [\"api.example.com\"] }}\n"),
    )
    .expect("enforcing hosts");
    let (mut plan, _) = superloop_lane::load_plan(home, "alpha", "R", (0, 0)).expect("plan");
    plan.select_container_program(&podman)
        .expect("container program");
    plan.select_worker_uid(3000).expect("worker");
    let selection = json!({"model":"gpt-6-sol","effort":"high","model_source":"launch-flag","effort_source":"launch-flag"});
    plan.select_launch_model(&selection).expect("selection");
    for path in [
        plan.driver_dir.clone(),
        runs.join(".launch-R"),
        plan.home.clone(),
    ] {
        fs::create_dir_all(&path).expect("retained directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("retained mode");
    }
    let reservation = runs.join(".reservation-R.json");
    let record = json!({"schema":1,"phase":"failed","loop":"alpha","run":"R","worker_uid":3000,"plan":plan.document,"model_selection":selection,"letter_source":letter,"active_round":"dispatch","launcher_pid":4_000_000,"launcher_start":1,"driver_entry_pid":4_000_001,"driver_entry_start":1,"helper_pid":4_000_002,"helper_start":1,"helper_parent_pid":4_000_003,"helper_parent_start":1,"observer_state":"not-started","settlement_uncertain":false,"rounds":[{"step":"dispatch","phase":"failed","settlement_error":"settle-evidence: reply absent"}],"letters":[],"run_scope":{"unit":"superloop-lane-run-fixture.service","cgroup":"/user.slice/superloop-lane-run-fixture.service/work","device":1,"inode":2,"proxy_unit":"superloop-lane-vendor@alpha.service","proxy_invocation":"fixture"}});
    fs::write(&reservation, serde_json::to_vec(&record).expect("JSON")).expect("reservation");
    fs::set_permissions(&reservation, fs::Permissions::from_mode(0o600)).expect("record mode");
    let mailbox = runs.join(".letter-R.lock");
    fs::write(&mailbox, b"").expect("retained mailbox lock");
    fs::set_permissions(&mailbox, fs::Permissions::from_mode(0o600)).expect("mailbox mode");
    Fixture {
        _root: fixture,
        home: home_dir,
        binary: lane_bin,
        letter,
        podman,
        reservation,
    }
}

impl Fixture {
    fn invoke(&self, args: &[&str]) -> Output {
        retry_busy_entry(|| {
            Command::new(&self.binary)
                .env("HOME", &self.home)
                .env_remove("ENTER_LOOP_REGISTRY")
                .env_remove("SUPERLOOP_RUN_SCOPE_UNIT")
                .args(args)
                .output()
        })
        .expect("production command")
    }

    fn launch(&self, dry_run: bool) -> Output {
        let mut command = Command::new(&self.binary);
        command
            .env("HOME", &self.home)
            .env_remove("ENTER_LOOP_REGISTRY")
            .env_remove("SUPERLOOP_RUN_SCOPE_UNIT")
            .args(["launch", "alpha", "R", "--letter"])
            .arg(&self.letter)
            .args(["--podman-bin"])
            .arg(&self.podman)
            .args(["--model", "gpt-6-sol", "--effort", "high"]);
        if dry_run {
            command.arg("--dry-run");
        }
        retry_busy_entry(|| command.output()).expect("production launch")
    }
}

struct ReportFixture {
    fixture: Fixture,
    library: PathBuf,
    run: PathBuf,
    report: PathBuf,
}

impl ReportFixture {
    fn new() -> Self {
        let fixture = fixture();
        let lease = fixture
            .reservation
            .parent()
            .expect("runs")
            .join(".prepare-R.lock");
        fs::write(&lease, b"").expect("retained preparation lease");
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).expect("lease mode");
        let library = fixture.home.join("report-custody.so");
        let compiled = Command::new("/usr/bin/cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/report_custody.c"))
            .arg("-ldl")
            .output()
            .expect("compile custody boundary");
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let mut record: Value =
            serde_json::from_slice(&fs::read(&fixture.reservation).expect("record")).expect("JSON");
        let run = PathBuf::from(record["plan"]["driver_dir"].as_str().expect("run"));
        let directory = run.join("20261029T000000Z-dispatch");
        fs::create_dir(&directory).expect("round directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("private round");
        let report = directory.join("run-report.txt");
        fs::write(
            &report,
            format!(
                "RUN-REPORT lane=dispatch exit=1 wall=4416s budget=10800s verdict=FAILED dir={}\n",
                directory.display()
            ),
        )
        .expect("driver report");
        record["phase"] = json!("started");
        record["driver_end"] = Value::Null;
        record["helper_spawn_state"] = json!("started");
        record["rounds"][0] = json!({"step":"dispatch","phase":"running","driver_dir":directory});
        record["plan"]["door"]["stub_sha256"] = json!("b".repeat(64));
        fs::write(
            &fixture.reservation,
            serde_json::to_vec(&record).expect("JSON"),
        )
        .expect("interrupted record");
        let value = Self {
            fixture,
            library,
            run,
            report,
        };
        value.runtime("");
        value
    }

    fn runtime(&self, extra: &str) {
        executable(
            &self.fixture.podman,
            &format!(
                "#!/bin/sh\nif [ \"$1 $2\" = 'image inspect' ]; then printf '%s\\n' '{}'; exit 0; fi\nif [ \"$1\" = ps ]; then exit 0; fi\nif [ \"$1\" = unshare ]; then shift; exec env LD_PRELOAD='{}' REPORT_FIXTURE_PRIVATE=1 REPORT_FIXTURE_RUN='{}' {extra} \"$@\"; fi\nexit 9\n",
                "a".repeat(64),
                self.library.display(),
                self.run.display()
            ),
        );
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.fixture.binary);
        command
            .env("HOME", &self.fixture.home)
            .env_remove("ENTER_LOOP_REGISTRY")
            .env_remove("SUPERLOOP_RUN_SCOPE_UNIT")
            .env("LD_PRELOAD", &self.library)
            .env("REPORT_FIXTURE_RUN", &self.run);
        command
    }

    fn custody_probe(&self, readable: bool) -> Output {
        let mut command = Command::new("/bin/cat");
        command
            .arg(&self.report)
            .env("LD_PRELOAD", &self.library)
            .env("REPORT_FIXTURE_RUN", &self.run);
        if readable {
            command.env("REPORT_FIXTURE_READABLE", "1");
        }
        command.output().expect("launcher custody probe")
    }

    fn repin(&self, digest: Option<&str>, readable: bool) -> Output {
        for directory in [&self.run, self.report.parent().expect("report directory")] {
            fs::set_permissions(
                directory,
                fs::Permissions::from_mode(if readable { 0o755 } else { 0o700 }),
            )
            .expect("loop directory access mode");
        }
        let mut command = self.command();
        command.args(["launch", "alpha", "R", "--repin-door"]);
        if readable {
            command.env("REPORT_FIXTURE_READABLE", "1");
        }
        match digest {
            Some(digest) => {
                command.args(["--expect-digest", digest]);
            }
            None => {
                command.arg("--dry-run");
            }
        }
        retry_busy_entry(|| command.output()).expect("production repin")
    }

    fn recovery(&self, digest: Option<&str>) -> Output {
        let mut command = self.command();
        command
            .args(["launch", "alpha", "R", "--letter"])
            .arg(&self.fixture.letter)
            .arg("--podman-bin")
            .arg(&self.fixture.podman)
            .args(["--model", "gpt-6-sol", "--effort", "high"]);
        match digest {
            Some(digest) => {
                command.args(["--expect-digest", digest]);
            }
            None => {
                command.arg("--dry-run");
            }
        }
        retry_busy_entry(|| command.output()).expect("production recovery")
    }
}

fn successful_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("production JSON")
}

/// # Panics
/// Panics only if the production retirement cannot measure modelled private custody.
/// The interposer models launcher denial and protected `/tmp` ancestry, not kernel uid separation.
/// ´test:integration:retirement-measures-loop-locks-through-private-entry´
#[test]
fn retirement_measures_loop_locks_through_private_entry() {
    let fixture = ReportFixture::new();
    fs::set_permissions(&fixture.run, fs::Permissions::from_mode(0o700)).expect("private run");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.fixture.reservation).expect("record"))
            .expect("JSON");
    record["launcher_pid"] = Value::Null;
    record["launcher_start"] = Value::Null;
    record["plan"]["door"] = Value::Null;
    record["harvest_agreement"] = Value::Null;
    record["collection"] = Value::Null;
    record["imports"] = json!([]);
    fs::write(
        &fixture.fixture.reservation,
        serde_json::to_vec(&record).expect("JSON"),
    )
    .expect("record");
    let denied = fixture.custody_probe(false);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Permission denied"));
    let output = retry_busy_entry(|| {
        fixture
            .command()
            .args(["retire", "alpha", "R", "--dry-run"])
            .output()
    })
    .expect("retirement");
    let preview = successful_json(&output);
    assert_eq!(preview["retirement"]["state"], "would-retire");
    fixture.runtime("REPORT_FIXTURE_UNREADABLE=1");
    let output = retry_busy_entry(|| {
        fixture
            .command()
            .args(["retire", "alpha", "R", "--dry-run"])
            .output()
    })
    .expect("unreadable retirement");
    assert!(!output.status.success());
    let refusal = String::from_utf8_lossy(&output.stderr);
    assert!(
        refusal.contains("retire-uncertain: driver directory:"),
        "{refusal}"
    );
    assert!(refusal.contains("Permission denied"), "{refusal}");
}

/// # Panics
/// Panics only if the production private evidence or digest contract fails.
/// The interposer models launcher denial on loop-owned mode-0700 custody and
/// rewrites `/tmp` ancestry as protected; it does not establish kernel uid separation.
/// ´test:integration:repin-and-recovery-read-loop-custody-through-private-entry´
#[test]
fn repin_and_recovery_read_loop_custody_through_private_entry() {
    let fixture = ReportFixture::new();
    assert_ne!(nix::unistd::Uid::effective().as_raw(), 41001);
    let denied = fixture.custody_probe(false);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Permission denied"));
    let preview = successful_json(&fixture.repin(None, false));
    let readable = successful_json(&fixture.repin(None, true));
    let readable_bytes = fixture.custody_probe(true);
    assert!(readable_bytes.status.success());
    assert_eq!(
        readable_bytes.stdout,
        fs::read(&fixture.report).expect("fixture bytes")
    );
    assert_eq!(preview["evidence"], readable["evidence"]);
    assert_eq!(preview["preview_sha256"], readable["preview_sha256"]);
    assert_eq!(preview["evidence"]["report_identity"]["uid"], 41001);
    assert_eq!(preview["evidence"]["run_report"]["exit"], "1");
    let digest = preview["preview_sha256"].as_str().expect("digest");
    let applied = successful_json(&fixture.repin(Some(digest), false));
    assert_eq!(applied["evidence"], preview["evidence"]);
    assert_eq!(applied["changed"], true);
    let recovery = successful_json(&fixture.recovery(None));
    let end = &recovery["interrupted_settlement"]["recovered_driver_end"];
    assert_eq!(end["state"], "completed");
    assert_eq!(end["successful"], false);
    assert_eq!(end["evidence"], preview["evidence"]);
    let applied = fixture.recovery(Some(
        recovery["interrupted_settlement"]["preview_sha256"]
            .as_str()
            .expect("cleanup digest"),
    ));
    let completion = successful_json(&applied);
    assert_eq!(
        completion["interrupted_settlement"]["state"],
        "completed-interrupted-settlement"
    );
    let saved: Value =
        serde_json::from_slice(&fs::read(&fixture.fixture.reservation).expect("recovered record"))
            .expect("JSON");
    assert_eq!(
        saved["driver_end"],
        *end,
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
}

/// # Panics
/// Panics only if a report refusal is hidden or a stale digest is admitted.
/// ´test:integration:private-driver-report-refusals-and-replacement-bind-apply´
#[test]
fn private_driver_report_refusals_and_replacement_bind_apply() {
    for defect in [
        "absent",
        "unreadable",
        "owner",
        "directory",
        "utf8",
        "start",
        "link",
        "oversized",
    ] {
        let fixture = ReportFixture::new();
        let expected = match defect {
            "absent" => {
                fs::remove_file(&fixture.report).expect("remove report");
                "repin-door-state"
            }
            "unreadable" => {
                fixture.runtime("REPORT_FIXTURE_UNREADABLE=1");
                "repin-door-uncertain"
            }
            "owner" => {
                fixture.runtime("REPORT_FIXTURE_WRONG_OWNER=1");
                "repin-door-state"
            }
            "directory" => {
                fs::write(
                    &fixture.report,
                    "RUN-REPORT lane=dispatch exit=1 verdict=FAILED dir=/other/run\n",
                )
                .expect("wrong dir");
                "repin-door-state"
            }
            "utf8" => {
                fs::write(&fixture.report, [0xff]).expect("non UTF-8");
                "repin-door-uncertain"
            }
            "start" => {
                executable(&fixture.fixture.podman, "#!/bin/sh\nexit 9\n");
                "driver-report-private"
            }
            "link" => {
                fs::remove_file(&fixture.report).expect("remove");
                std::os::unix::fs::symlink("elsewhere", &fixture.report).expect("link");
                "repin-door-uncertain"
            }
            _ => {
                fs::write(&fixture.report, vec![b'x'; 4097]).expect("oversized");
                "repin-door-state"
            }
        };
        let output = fixture.repin(None, false);
        assert_eq!(
            output.status.code(),
            Some(if defect == "start" { 1 } else { 2 }),
            "{defect}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{defect}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let fixture = ReportFixture::new();
    let preview = successful_json(&fixture.repin(None, false));
    let replacement = fixture.report.with_extension("replacement");
    let modified = fs::metadata(&fixture.report)
        .expect("original metadata")
        .modified()
        .expect("mtime");
    fs::copy(&fixture.report, &replacement).expect("same report bytes");
    fs::File::options()
        .write(true)
        .open(&replacement)
        .expect("replacement file")
        .set_times(fs::FileTimes::new().set_modified(modified))
        .expect("preserve mtime");
    fs::rename(replacement, &fixture.report).expect("replace inode");
    let replaced = successful_json(&fixture.repin(None, false));
    assert_ne!(
        preview["evidence"]["report_identity"]["inode"],
        replaced["evidence"]["report_identity"]["inode"]
    );
    assert_eq!(
        preview["evidence"]["report_identity"]["modified_seconds"],
        replaced["evidence"]["report_identity"]["modified_seconds"]
    );
    assert_eq!(
        preview["evidence"]["report_identity"]["modified_nanoseconds"],
        replaced["evidence"]["report_identity"]["modified_nanoseconds"]
    );
    let output = fixture.repin(preview["preview_sha256"].as_str(), false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("repin-door-digest"));
}

/// The exercise command queries the entry before validating its returned row.
/// # Panics
/// Panics only if fixture setup fails or the command does not reach row validation.
/// ´test:integration:exercise-door-queries-show-through-built-command´
#[test]
fn exercise_door_queries_show_through_built_command() {
    let fixture = fixture();
    let entry = fixture.home.join("entry-fixture");
    executable(
        &entry,
        &registry_fixture::script(
            "printf '%s\\n' \"$@\" > \"$0.argv\"\nprintf '%s\\n' '{\"name\":\"alpha\",\"uid\":\"invalid-fixture-uid\"}'",
        ),
    );
    let output = fixture.invoke(&["exercise", "alpha", "--run", "R", "--case", "door-shape"]);
    assert_eq!(
        fs::read_to_string(entry.with_extension("argv")).expect("registry invocation"),
        "show\nalpha\n"
    );
    assert_eq!(output.status.code(), Some(2));
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("exercise-door: row uid is absent"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains("registry-command"), "{diagnostic}");
}

fn completed_failed_fixture(report: bool) -> Fixture {
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "provisioned namespace root required"
    );
    let fixture = fixture();
    let registry = fixture.home.join(".config/loops/registry.toml");
    let source = fs::read_to_string(&registry).expect("registry");
    fs::write(&registry, source.replace("uid = 41001", "uid = 0")).expect("namespace loop owner");
    let (mut plan, _) =
        superloop_lane::load_plan(&fixture.home, "alpha", "R", (0, 0)).expect("plan");
    plan.select_container_program(&fixture.podman)
        .expect("runtime");
    plan.select_worker_uid(3000).expect("worker");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.reservation).expect("reservation"))
            .expect("record");
    plan.select_launch_model(&record["model_selection"])
        .expect("selection");
    plan.observe_vendor()
        .expect("observing fixture needs no live service");
    record["plan"] = plan.document.clone();
    record["driver_end"] = json!({"state":"completed","successful":report});
    record["helper_end"] = json!({"state":"completed","successful":true});
    record["pre_driver_failure"] = Value::Null;
    record["observation_end"] = json!("completed");
    record["observer_end"] = json!({"state":"not-started","socket":{"state":"not-applicable"}});
    record["reaping"] = json!({"state":"verified-empty","container_payload":{"state":"absent"}});
    let step = if report { "report" } else { "dispatch" };
    record["active_round"] = json!(step);
    record["rounds"][0]["step"] = json!(step);
    record["rounds"][0]["settlement_error"] = json!(format!(
        "readback: {}/.local/outbox/{step}.md: No such file or directory (os error 2)",
        plan.home.display()
    ));
    let directory = plan.driver_dir.join("20261023T030507Z-dispatch");
    fs::create_dir(&directory).expect("driver round");
    fs::write(
        directory.join("run-report.txt"),
        format!(
            "RUN-REPORT lane={step} exit={} verdict={} dir={}\n",
            i32::from(!report),
            if report { "ok" } else { "FAILED" },
            directory.display()
        ),
    )
    .expect("failed driver verdict");
    fs::write(directory.join("events.jsonl"), b"").expect("no thread");
    fs::write(directory.join(".event-start"), b"0\n").expect("event boundary");
    record["rounds"][0]["driver_dir"] = json!(directory);
    assert!(record["rounds"][0].get("reply").is_none());
    for (name, mode) in [
        (".local", 0o750),
        (".local/outbox", 0o700),
        (".local/inbox", 0o750),
    ] {
        let path = plan.home.join(name);
        fs::create_dir_all(&path).expect("mailbox");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("mailbox mode");
    }
    nix::unistd::chown(
        &plan.home.join(".local/outbox"),
        Some(nix::unistd::Uid::from_raw(3000)),
        None,
    )
    .expect("worker outbox");
    executable(
        &fixture.podman,
        "#!/bin/sh\nif [ \"$1\" = unshare ]; then shift; exec \"$@\"; fi\nif [ \"$1\" = ps ]; then exit 0; fi\nexit 9\n",
    );
    if report {
        record["thread_id"] = json!("thread-1");
        fs::write(
            directory.join("events.jsonl"),
            b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n",
        )
        .expect("retained thread event");
        record["rounds"].as_array_mut().expect("rounds").insert(0,
            json!({"step":"dispatch","driver_dir":directory,"phase":"settled","ended_by":"by-report","reply":{"bytes":6},"settle_attempts":[]}));
    }
    fs::write(
        &fixture.reservation,
        serde_json::to_vec(&record).expect("record JSON"),
    )
    .expect("record");
    fixture
}

/// # Panics
/// Panics only if fixture setup or the production settlement and continuation contract fails.
/// ´test:integration:completed-failed-dispatch-settles-and-admits-report-letter´
#[test]
#[ignore = "main.rs::bind_private_launch_args binds descriptors as uid 0; launch/settle.rs::private_recover and launch/letters.rs::private_send require namespace root; fixture also maps worker uid 3000"]
fn completed_failed_dispatch_settles_and_admits_report_letter() {
    completed_failed_round_settles_and_admits_letter(false);
}

/// # Panics
/// Panics only if the production report-readback recovery contract fails.
/// ´test:integration:completed-successful-report-settles-and-admits-next-letter´
#[test]
#[ignore = "main.rs::bind_private_launch_args binds descriptors as uid 0; launch/settle.rs::private_recover and launch/letters.rs::private_send require namespace root; fixture also maps worker uid 3000"]
fn completed_successful_report_settles_and_admits_next_letter() {
    completed_failed_round_settles_and_admits_letter(true);
}

#[allow(clippy::too_many_lines)]
fn completed_failed_round_settles_and_admits_letter(report: bool) {
    let fixture = completed_failed_fixture(report);
    let step = if report { "report" } else { "dispatch" };
    let next = if report { "report-2" } else { "report" };
    let round_index = usize::from(report);
    let before = fs::read(&fixture.reservation).expect("before");
    let preview = fixture.invoke(&["settle", "alpha", "R", "--round", step, "--dry-run"]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: Value = serde_json::from_slice(&preview.stdout).expect("preview JSON");
    assert!(preview["readback"].is_null());
    assert_eq!(
        fs::read(&fixture.reservation).expect("after preview"),
        before
    );
    let runs = fixture.reservation.parent().expect("runs root");
    assert!(!runs.join(".report=R.json").exists());
    assert!(!runs.join(".report=R=report.json").exists());
    let original: Value = serde_json::from_slice(&before).expect("original record");
    assert!(
        !Path::new(
            original["plan"]["driver_dir"]
                .as_str()
                .expect("driver directory")
        )
        .join(format!("readback-evidence-{step}.json"))
        .exists()
    );
    let output = fixture.invoke(&[
        "settle",
        "alpha",
        "R",
        "--round",
        step,
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let saved: Value =
        serde_json::from_slice(&fs::read(&fixture.reservation).expect("settled record"))
            .expect("JSON");
    assert_eq!(saved["phase"], "settled");
    assert_eq!(saved["rounds"][round_index]["phase"], "failed");
    assert!(saved["rounds"][round_index]["reply"].is_null());
    assert_eq!(
        saved["rounds"][round_index]["settle_attempts"][0]["phase"],
        "complete"
    );
    let report_letter = fixture.home.join("scratchpad/report-letter");
    fs::write(&report_letter, b"Write the reply of record.\n").expect("report letter");
    fs::set_permissions(&report_letter, fs::Permissions::from_mode(0o600)).expect("letter mode");
    let output = fixture.invoke(&[
        "send-letter",
        "alpha",
        "R",
        "--step",
        next,
        "--letter",
        report_letter.to_str().expect("path"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after: Value =
        serde_json::from_slice(&fs::read(&fixture.reservation).expect("after letter"))
            .expect("JSON");
    assert_eq!(after["rounds"], saved["rounds"]);
    assert_eq!(after["letters"][0]["step"], next);
    assert_eq!(after["letters"][0]["state"], "placed");
    assert_eq!(after["plan"]["home"], saved["plan"]["home"]);
    let output = fixture.invoke(&[
        "launch",
        "alpha",
        "R",
        "--round",
        next,
        "--dry-run",
        "--podman-bin",
        fixture.podman.to_str().expect("runtime path"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let launch: Value = serde_json::from_slice(&output.stdout).expect("launch JSON");
    assert_eq!(
        launch["thread_id"],
        if report {
            json!("thread-1")
        } else {
            Value::Null
        }
    );
    assert_eq!(launch["home"], saved["plan"]["home"]);
    assert_eq!(
        launch["invocation"]["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .any(|word| word == "-r"),
        report
    );
}

/// # Panics
/// Panics only if a repeated recovery previews or changes an occupied report.
/// ´test:integration:failed-dispatch-second-recovery-refuses-occupied-report´
#[test]
fn failed_dispatch_second_recovery_refuses_occupied_report() {
    let fixture = fixture();
    let before = fs::read(&fixture.reservation).expect("record before");
    let report = fixture
        .reservation
        .parent()
        .expect("runs")
        .join(".report=R.json");
    let bytes = b"{\"interrupted_settlement\":{\"state\":\"completed-interrupted-settlement\"}}\n";
    fs::write(&report, bytes).expect("published recovery report");
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
    for dry_run in [true, false] {
        let output = fixture.launch(dry_run);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("launch-report: .report=R.json: report already exists"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&report).expect("unchanged report"), bytes);
        assert_eq!(
            fs::read(&fixture.reservation).expect("unchanged record"),
            before
        );
    }
    let mut settled: Value = serde_json::from_slice(&before).expect("record");
    settled["rounds"][0]["phase"] = json!("settled");
    settled["rounds"][0]["ended_by"] = json!("by-report");
    let settled = serde_json::to_vec(&settled).expect("settled record");
    fs::write(&fixture.reservation, &settled).expect("by-report recovery");
    for dry_run in [true, false] {
        let output = fixture.launch(dry_run);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr.contains("launch-report:"), "{stderr}");
        assert!(
            stderr.contains("send-letter LOOP RUN --step NEW"),
            "{stderr}"
        );
        assert!(!stderr.contains("preview settle"), "{stderr}");
        assert_eq!(
            fs::read(&fixture.reservation).expect("unchanged record"),
            settled
        );
        assert_eq!(fs::read(&report).expect("unchanged report"), bytes);
    }
}

/// # Panics
///
/// Panics only if the production preview changes the failed reservation or refuses recovery.
/// ´test:integration:failed-driver-dispatch-previews-without-recording-recovery´
#[test]
fn failed_driver_dispatch_previews_without_recording_recovery() {
    let fixture = fixture();
    let before = fs::read(&fixture.reservation).expect("record before");
    let output = fixture.launch(true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("preview");
    assert_eq!(
        report["interrupted_settlement"]["state"],
        "would-complete-interrupted-settlement"
    );
    assert_eq!(report["interrupted_settlement"]["presence"], "all-absent");
    assert_eq!(report["changed"], false);
    assert_eq!(
        fs::read(&fixture.reservation).expect("record after"),
        before
    );
    assert!(
        !fixture
            .reservation
            .parent()
            .expect("runs")
            .join(".report=R.json")
            .exists()
    );
}

/// # Panics
///
/// Panics only if a fixture operation fails or a live identity or container is admitted.
/// ´test:integration:failed-driver-dispatch-refuses-present-process-and-container´
#[test]
fn failed_driver_dispatch_refuses_present_process_and_container() {
    let fixture = fixture();
    let before = fs::read(&fixture.reservation).expect("original record");
    let mut record: Value = serde_json::from_slice(&before).expect("record");
    record["driver_entry_pid"] = json!(std::process::id());
    let stat = fs::read_to_string("/proc/self/stat").expect("live process stat");
    record["driver_entry_start"] = json!(
        stat.rsplit_once(')')
            .expect("process command")
            .1
            .split_whitespace()
            .nth(19)
            .expect("start field")
            .parse::<u64>()
            .expect("process start")
    );
    let live = serde_json::to_vec(&record).expect("live JSON");
    fs::write(&fixture.reservation, &live).expect("live record");
    for dry_run in [true, false] {
        let output = fixture.launch(dry_run);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("launch-busy: driver is still alive"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        fs::read(&fixture.reservation).expect("unchanged live record"),
        live
    );
    fs::write(&fixture.reservation, &before).expect("restore absent identities");
    let program = fs::read_to_string(&fixture.podman).expect("container fixture");
    let id = "a".repeat(64);
    let removal_log = fixture.home.join("container-removals");
    let inspection = json!([{
        "Id":id,"Name":"live-attempt",
        "Config":{"Labels":{"org.superloop.loop":"alpha","org.superloop.run":"R"}},
        "State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,
            "Pid":123,"ExitCode":0,"FinishedAt":"0001-01-01T00:00:00Z"}
    }]);
    executable(
        &fixture.podman,
        &program.replace(
            "if [ \"$1\" = ps ]; then exit 0; fi",
            &format!(
                "if [ \"$1\" = ps ]; then printf '%s\\n' '{id}'; exit 0; fi\nif [ \"$1 $2\" = 'container inspect' ]; then test \"$#\" = 3 && test \"$3\" = '{id}' || exit 9; printf '%s\\n' '{inspection}'; exit 0; fi\nif [ \"$1\" = rm ]; then printf '%s\\n' \"$@\" >> '{}'; exit 9; fi",
                removal_log.display()
            ),
        ),
    );
    for dry_run in [true, false] {
        let output = fixture.launch(dry_run);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!(
                "settlement-container: container {id} is live or its exited state is unproved"
            )),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(&fixture.reservation).expect("unchanged container record"),
            before
        );
        assert!(!removal_log.exists(), "live container must never reach rm");
    }
    assert_eq!(
        fs::read(&fixture.reservation).expect("unchanged container record"),
        before
    );
}
