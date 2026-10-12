#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use nix::fcntl::{Flock, FlockArg};
use serde_json::json;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A fork can inherit another test thread's writable stub descriptor, making its exec fail with ETXTBSY; at commit 1303417c4, library/std/src/sys/process/unix/unix.rs waits for close-on-exec EOF or the error written after `do_exec` before returning from fork-path spawn (lines 104, 138-160).
/// That file delegates the other path to `posix_spawnp` (lines 456-475, 783); Linux glibc's `CLONE_VFORK` suspension until exec or failure is the platform premise, so the lock across stub writes and direct test-side spawns closes the inherited-descriptor window and can end before waiting for the child.
/// For output callers with unconfigured streams, library/std/src/process.rs documents inherited stdio for spawn and noninherited stdin for output (lines 1063, 1095-1096, 1103, 1138-1139), library/std/src/sys/process/mod.rs selects `MakePipe` (lines 54-57), and library/std/src/sys/process/unix/common.rs selects null stdin (lines 358-365).
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn write_executable(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn spawn_serialized(command: &mut Command) -> std::io::Result<Child> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

#[allow(dead_code)]
trait SerializedCommand {
    fn spawn_serialized(&mut self) -> std::io::Result<Child>;
    fn output_serialized(&mut self) -> std::io::Result<Output>;
    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output>;
    fn status_serialized(&mut self) -> std::io::Result<ExitStatus>;
}

impl SerializedCommand for Command {
    fn spawn_serialized(&mut self) -> std::io::Result<Child> {
        spawn_serialized(self)
    }

    fn output_serialized(&mut self) -> std::io::Result<Output> {
        self.output_serialized_with_stdin(Stdio::null())
    }

    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output> {
        self.stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        spawn_serialized(self)?.wait_with_output()
    }

    fn status_serialized(&mut self) -> std::io::Result<ExitStatus> {
        spawn_serialized(self)?.wait()
    }
}

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new(name: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = temporary_root::temporary_root().join(format!(
            "permission-triage-assemble-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique assemble fixture directory is created");
        fs::create_dir(path.join("home")).expect("fixture HOME is created");
        fs::create_dir_all(path.join("home/.config/loops"))
            .expect("fixture configuration root is created");
        for private in [path.join("home/.config"), path.join("home/.config/loops")] {
            fs::set_permissions(private, fs::Permissions::from_mode(0o700))
                .expect("fixture configuration directory is private");
        }
        fs::create_dir_all(path.join("repo/local/permissions"))
            .expect("fixture private repository tree is created");
        fs::write(path.join("repo/local/permissions/owner.md"), [])
            .expect("empty fixture owner rubric is written");
        fs::write(
            path.join("repo/local/permissions/domain.md"),
            "fixture domain rubric\n",
        )
        .expect("fixture domain rubric is written");
        let registry = path.join("registry-parent/loops.d");
        fs::create_dir_all(&registry).expect("fixture registry is created");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o700))
            .expect("fixture registry is private");
        let state = path.join("repo/local/permissions/state");
        fs::create_dir(&state).expect("fixture registered root");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("private registered root");
        let registry_entry = registry.join("orchestration.env");
        fs::write(
            &registry_entry,
            format!(
                "LOOP_NAME=orchestration\nLOOP_SID=session-main\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                path.join("repo").display(),
                state.display()
            ),
        )
        .expect("fixture registry entry is written");
        fs::set_permissions(registry_entry, fs::Permissions::from_mode(0o600))
            .expect("fixture registry entry is private");
        let classifier = path.join("classifier-cli");
        fs::write(&classifier, "fixture classifier bytes\n")
            .expect("fixture classifier is written");
        fs::set_permissions(&classifier, fs::Permissions::from_mode(0o755))
            .expect("fixture classifier is executable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn allocation_home(&self) -> PathBuf {
        Path::new("/tmp").join(format!(
            "{}-allocation-home",
            self.0.file_name().expect("fixture name").to_string_lossy()
        ))
    }

    fn assembly_home(&self) -> PathBuf {
        let path = self.allocation_home();
        if path.exists() { path } else { self.home() }
    }

    fn repo(&self) -> PathBuf {
        self.0.join("repo")
    }

    fn verdict(&self) -> PathBuf {
        self.0.join("verdict.json")
    }

    fn instance(&self) -> PathBuf {
        self.repo().join("local/permissions/permission-triage.env")
    }

    fn out(&self) -> PathBuf {
        self.0.join("out")
    }

    fn classifier(&self) -> PathBuf {
        self.0.join("classifier-cli")
    }

    fn registry(&self) -> PathBuf {
        self.0.join("registry-parent/loops.d")
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
        let _cleanup = fs::remove_dir_all(self.allocation_home());
    }
}

fn verdict_document(topology: &str, blocked: bool) -> Vec<u8> {
    let roster = permission_triage::topology::planned_topology_roster();
    let mut value = json!({"schema": 2, "roster_selection": "full", "supported_harness_version": "2.1.258", "harness_version": "2.1.258", "selected_topology": if blocked { "blocked" } else { topology }, "deployment_blocked": blocked, "roster": roster, "planned_trials": roster.len() * 3, "audit": [], "bypass": [], "settings_deny_wins": [], "infrastructure": [], "table_confirmation": [], "trials": [], "friction": {}});
    value["harness_binary"] = json!("/fixture/claude");
    value["harness_provenance"] = json!({"kind": "real", "path": "/fixture/claude", "version": "2.1.258", "sha256": "0".repeat(64), "fake_name_match": false, "fake_bytes_match": false});
    let mut trials = Vec::new();
    for mut row in permission_triage::topology::acceptance_requirements() {
        let phase = row["phase"].as_str().expect("phase").to_owned();
        let ids = (1..=3)
            .map(|repetition| {
                json!(format!(
                    "{phase}-{}-{repetition}",
                    row["row"].as_str().expect("row")
                ))
            })
            .collect::<Vec<_>>();
        trials.extend(
            ids.iter()
                .map(|id| json!({"id": id, "hook_stdout": [], "invocation_wall_ms": 1})),
        );
        row["repetitions"] = json!(ids);
        row["classification"] = json!("pass");
        value[&phase].as_array_mut().expect("rows").push(row);
    }
    for row in roster
        .iter()
        .filter(|row| row["phase"] == "table-confirmation" && row["polarity"] == "positive")
    {
        let mut summary = json!({"member": row["row"], "classification": "candidate"});
        for polarity in ["positive", "negative"] {
            let ids = (1..=3)
                .map(|repetition| {
                    json!(format!(
                        "table-{}-{polarity}-{repetition}",
                        row["row"].as_str().expect("row")
                    ))
                })
                .collect::<Vec<_>>();
            trials.extend(
                ids.iter()
                    .map(|id| json!({"id": id, "hook_stdout": [], "invocation_wall_ms": 1})),
            );
            summary[format!("{polarity}_repetitions")] = json!(ids);
        }
        value["table_confirmation"]
            .as_array_mut()
            .expect("tables")
            .push(summary);
    }
    for field in ["invocation_wall_ms", "hook_wall_ms", "verdict_wall_ms"] {
        value["friction"][field] = json!({"sample_count": trials.len(), "censored_count": 0, "p50": 1, "p95": 1, "p99": 1, "max": 1});
    }
    value["trials"] = json!(trials);
    let mut bytes = serde_json::to_vec_pretty(&value).expect("fixture verdict");
    bytes.push(b'\n');
    bytes
}

fn instance_document(fixture: &FixtureDirectory, state_root: &Path) -> Vec<u8> {
    instance_document_with_classifier(fixture, state_root, &fixture.classifier())
}

fn instance_document_with_classifier(
    fixture: &FixtureDirectory,
    state_root: &Path,
    classifier: &Path,
) -> Vec<u8> {
    instance_document_with_limits(fixture, state_root, classifier, 60_000, 55_000)
}

fn instance_document_with_limits(
    fixture: &FixtureDirectory,
    state_root: &Path,
    classifier: &Path,
    hook_ceiling_ms: u64,
    model_deadline_ms: u64,
) -> Vec<u8> {
    format!(
        "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT={}\nPERMISSION_TRIAGE_OWNER_RUBRIC={}\nPERMISSION_TRIAGE_HOOK_CEILING_MS={hook_ceiling_ms}\nPERMISSION_TRIAGE_MODEL=fixture-model\nPERMISSION_TRIAGE_MODEL_DEADLINE_MS={model_deadline_ms}\nPERMISSION_TRIAGE_CLI={}\nPERMISSION_TRIAGE_LOOP_REGISTRY={}\n",
        state_root.display(),
        fixture.repo().join("local/permissions/owner.md").display(),
        classifier.display(),
        fixture.registry().display()
    )
    .into_bytes()
}

fn instance_document_without_registry(fixture: &FixtureDirectory, state_root: &Path) -> Vec<u8> {
    format!(
        "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT={}\nPERMISSION_TRIAGE_OWNER_RUBRIC={}\nPERMISSION_TRIAGE_HOOK_CEILING_MS=30000\nPERMISSION_TRIAGE_MODEL=fixture-model\nPERMISSION_TRIAGE_MODEL_DEADLINE_MS=25000\nPERMISSION_TRIAGE_CLI={}\n",
        state_root.display(),
        fixture.repo().join("local/permissions/owner.md").display(),
        fixture.classifier().display()
    )
    .into_bytes()
}

/// ´test:integration:assembler-validates-estate-uid-instance-grammar´
#[test]
fn assembler_validates_estate_uid_instance_grammar() {
    let fixture = FixtureDirectory::new("estate-uid-grammar");
    fs::write(fixture.verdict(), verdict_document("bypass", false)).expect("ready verdict");
    let valid = String::from_utf8(instance_document(
        &fixture,
        &fixture.repo().join("local/permissions/state"),
    ))
    .expect("valid instance");
    for suffix in [
        "PERMISSION_TRIAGE_ESTATE_UID=0x7d4\n",
        "PERMISSION_TRIAGE_ESTATE_UID=41004\nPERMISSION_TRIAGE_ESTATE_UID=41004\n",
    ] {
        fs::write(fixture.instance(), format!("{valid}{suffix}")).expect("instance");
        let output = command(&fixture)
            .arg("--check")
            .output_serialized()
            .expect("assembler exits");
        assert_status(&output, 1);
    }
}

/// ´test:integration:assembler-check-accepts-declared-estate-registry´
#[test]
fn assembler_check_accepts_declared_estate_registry() {
    let fixture = FixtureDirectory::new("estate-registry");
    fs::write(fixture.verdict(), verdict_document("bypass", false)).expect("ready verdict");
    let owner = fs::metadata(fixture.registry())
        .expect("registry owner")
        .uid();
    let home = PathBuf::from(std::env::var_os("HOME").expect("home for estate registry"));
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let estate = home.join(format!(
        "permission-triage-assemble-estate-{}-{sequence}",
        std::process::id()
    ));
    for ancestor in estate.ancestors().skip(1) {
        let mode = fs::metadata(ancestor)
            .expect("estate ancestor")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o022,
            0,
            "fixture ancestor {} is group- or other-writable",
            ancestor.display()
        );
    }
    fs::create_dir(&estate).expect("estate directory");
    fs::set_permissions(&estate, fs::Permissions::from_mode(0o755)).expect("estate directory mode");
    let registry = estate.join("registry");
    fs::create_dir(&registry).expect("estate registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o755))
        .expect("estate registry mode");
    let entry = registry.join("orchestration.env");
    let mut text =
        fs::read_to_string(fixture.registry().join("orchestration.env")).expect("entry text");
    writeln!(text, "LOOP_UID={owner}").expect("uid line");
    fs::write(&entry, text).expect("estate entry");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o644)).expect("estate entry mode");
    let valid = String::from_utf8(instance_document(
        &fixture,
        &fixture.repo().join("local/permissions/state"),
    ))
    .expect("valid instance");
    let instance = valid.replace(
        &fixture.registry().display().to_string(),
        &registry.display().to_string(),
    );
    fs::write(
        fixture.instance(),
        format!("{instance}PERMISSION_TRIAGE_ESTATE_UID={owner}\n"),
    )
    .expect("estate instance");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembler exits");
    fs::remove_dir_all(&estate).expect("remove estate directory");
    assert_status(&output, 0);
}

fn instance_document_with_owner(
    fixture: &FixtureDirectory,
    state_root: &Path,
    owner: &Path,
) -> Vec<u8> {
    format!(
        "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT={}\nPERMISSION_TRIAGE_OWNER_RUBRIC={}\nPERMISSION_TRIAGE_HOOK_CEILING_MS=30000\nPERMISSION_TRIAGE_MODEL=fixture-model\nPERMISSION_TRIAGE_MODEL_DEADLINE_MS=25000\nPERMISSION_TRIAGE_CLI={}\nPERMISSION_TRIAGE_LOOP_REGISTRY={}\n",
        state_root.display(),
        owner.display(),
        fixture.classifier().display(),
        fixture.registry().display()
    )
    .into_bytes()
}

/// ´test:integration:assembler-enforces-raised-ceiling-and-deadline-caps´
#[test]
fn assembler_enforces_raised_ceiling_and_deadline_caps() {
    let fixture = FixtureDirectory::new("raised-caps");
    fs::write(fixture.verdict(), verdict_document("bypass", false))
        .expect("ready verdict is written");
    let state_root = fixture.repo().join("local/permissions/state");

    for (ceiling, deadline) in [(60_000, 55_000), (45_000, 40_000)] {
        fs::write(
            fixture.instance(),
            instance_document_with_limits(
                &fixture,
                &state_root,
                &fixture.classifier(),
                ceiling,
                deadline,
            ),
        )
        .expect("in-range instance is written");
        let output = command(&fixture)
            .arg("--check")
            .output_serialized()
            .expect("assembler check exits");
        assert_status(&output, 0);
        assert_eq!(output.stderr, [] as [u8; 0]);
    }

    for (ceiling, deadline, message) in [
        (
            60_001,
            55_000,
            "PERMISSION_TRIAGE_HOOK_CEILING_MS exceeds 60000\n",
        ),
        (
            60_000,
            55_001,
            "PERMISSION_TRIAGE_MODEL_DEADLINE_MS exceeds 55000\n",
        ),
    ] {
        fs::write(
            fixture.instance(),
            instance_document_with_limits(
                &fixture,
                &state_root,
                &fixture.classifier(),
                ceiling,
                deadline,
            ),
        )
        .expect("out-of-range instance is written");
        let output = command(&fixture)
            .arg("--check")
            .output_serialized()
            .expect("assembler check exits");
        assert_status(&output, 1);
        assert_eq!(
            String::from_utf8(output.stderr).expect("semantic failure is UTF-8"),
            format!("infrastructure: {message}")
        );
    }
}

/// ´test:integration:assembler-validates-required-mode-independently-and-renders-first-install-audit´
#[test]
fn assembler_validates_required_mode_independently_and_renders_first_install_audit() {
    for (name, replacement) in [
        ("missing", None),
        ("empty", Some("")),
        ("misspelled", Some("audti")),
        ("wrong-case", Some("Audit")),
    ] {
        let fixture = FixtureDirectory::new(name);
        fs::write(fixture.verdict(), verdict_document("bypass", false))
            .expect("topology verdict is written");
        let instance = String::from_utf8(instance_document(
            &fixture,
            &fixture.repo().join("local/permissions/state"),
        ))
        .expect("instance is UTF-8");
        let mode_line = replacement.map_or_else(String::new, |mode| {
            format!("PERMISSION_TRIAGE_MODE={mode}\n")
        });
        let instance = instance.replacen("PERMISSION_TRIAGE_MODE=audit\n", &mode_line, 1);
        fs::write(fixture.instance(), instance).expect("invalid mode fixture is written");
        let mut command = command(&fixture);
        if replacement.is_none() {
            command.env("PERMISSION_TRIAGE_MODE", "audit");
        }
        let output = command.output_serialized().expect("assembler exits");
        assert_status(&output, 1);
        assert!(!fixture.out().exists());
    }

    let duplicate = FixtureDirectory::new("duplicate-mode");
    fs::write(duplicate.verdict(), verdict_document("bypass", false))
        .expect("topology verdict is written");
    let mut instance = instance_document(
        &duplicate,
        &duplicate.repo().join("local/permissions/state"),
    );
    instance.extend_from_slice(b"PERMISSION_TRIAGE_MODE=audit\n");
    fs::write(duplicate.instance(), instance).expect("duplicate mode fixture is written");
    let output = command(&duplicate)
        .output_serialized()
        .expect("assembler exits");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("repeats PERMISSION_TRIAGE_MODE"));

    let enforce = FixtureDirectory::new("first-install-enforce");
    fs::write(enforce.verdict(), verdict_document("bypass", false))
        .expect("topology verdict is written");
    let instance = String::from_utf8(instance_document(
        &enforce,
        &enforce.repo().join("local/permissions/state"),
    ))
    .expect("instance is UTF-8")
    .replacen(
        "PERMISSION_TRIAGE_MODE=audit",
        "PERMISSION_TRIAGE_MODE=enforce",
        1,
    );
    fs::write(enforce.instance(), instance).expect("enforce mode fixture is written");
    let output = command(&enforce)
        .output_serialized()
        .expect("assembler exits");
    assert_status(&output, 0);
    assert_eq!(read_assembly(&enforce)["hookMode"], "audit");
}

fn write_ready_inputs(fixture: &FixtureDirectory, topology: &str) -> (Vec<u8>, Vec<u8>) {
    let verdict = verdict_document(topology, false);
    let instance = instance_document(fixture, &fixture.repo().join("local/permissions/state"));
    fs::write(fixture.verdict(), &verdict).expect("fixture verdict is written");
    fs::write(fixture.instance(), &instance).expect("fixture instance is written");
    (verdict, instance)
}

fn probe_emitted_harness_provenance(fixture: &FixtureDirectory) -> serde_json::Value {
    let harness = fixture.path().join("probe-harness");
    write_executable(
        &harness,
        b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '9.9.9'; exit 0; fi\nexit 99\n",
        0o700,
    )
    .expect("probe harness fixture");
    let probe_root = fixture.path().join("probe-provenance");
    let output = Command::new(env!("CARGO_BIN_EXE_permission-triage-topology"))
        .args([
            "--fixture-root",
            probe_root.to_str().expect("probe root path is UTF-8"),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fixture.home())
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
        .output_serialized()
        .expect("topology preflight exits");
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("preflight verdict");
    verdict["harness_provenance"].clone()
}

fn real_shaped_probe_provenance(fixture: &FixtureDirectory) -> serde_json::Value {
    let mut provenance = probe_emitted_harness_provenance(fixture);
    // Index assignment inserts a missing key, so overwriting first would silently re-add a key the
    // probe had renamed away. The emitted key set is pinned before anything is written to it, and
    // the two keys this helper then overwrites are read at their emitted values first, because no
    // other assertion in the package observes them.
    let emitted = provenance
        .as_object()
        .expect("probe provenance is an object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        emitted,
        BTreeSet::from([
            "fake_bytes_match",
            "fake_name_match",
            "kind",
            "path",
            "sha256",
            "version",
        ]),
    );
    assert_eq!(provenance["kind"], json!("unsupported"));
    assert_eq!(provenance["version"], json!("9.9.9"));
    provenance["kind"] = json!("real");
    provenance["version"] = json!(permission_triage::topology::SUPPORTED_HARNESS_VERSION);
    provenance
}

fn command(fixture: &FixtureDirectory) -> Command {
    command_with_out(fixture, &fixture.out())
}

fn command_with_out(fixture: &FixtureDirectory, out: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permission-triage-assemble"));
    command
        .args([
            "--verdict",
            fixture.verdict().to_str().expect("verdict path is UTF-8"),
            "--repo",
            fixture.repo().to_str().expect("repo path is UTF-8"),
            "--instance",
            fixture.instance().to_str().expect("instance path is UTF-8"),
            "--out",
            out.to_str().expect("output path is UTF-8"),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fixture.assembly_home())
        .env(
            "PERMISSION_TRIAGE_ADAPTER_BIN",
            "/private/superloop-claude-hook",
        )
        .env(
            "PERMISSION_TRIAGE_HOOK_BIN",
            env!("CARGO_BIN_EXE_permission-triage-hook"),
        );
    command
}

/// ´test:integration:assembler-renders-only-the-configured-adapter-and-protects-its-path´
#[test]
fn assembler_renders_only_the_configured_adapter_and_protects_its_path() {
    let fixture = FixtureDirectory::new("configured-adapter");
    write_ready_inputs(&fixture, "bypass");
    let adapter = fixture.path().join("private adapter's binary");
    let output = command(&fixture)
        .env("PERMISSION_TRIAGE_ADAPTER_BIN", &adapter)
        .output_serialized()
        .expect("assemble adapter setting");
    assert_status(&output, 0);
    let fragment: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.out().join("settings-fragment.json")).expect("fragment"),
    )
    .expect("JSON fragment");
    assert_eq!(
        fragment["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        format!(
            "'{}' pre-tool-use",
            adapter.display().to_string().replace('\'', "'\\''")
        )
    );
    assert!(!adapter.exists());
    let refused = command_with_out(&fixture, &adapter)
        .env("PERMISSION_TRIAGE_ADAPTER_BIN", &adapter)
        .output_serialized()
        .expect("overlap refusal");
    assert_status(&refused, 3);
    assert!(!adapter.exists());
    let relative = command(&fixture)
        .env("PERMISSION_TRIAGE_ADAPTER_BIN", "relative")
        .output_serialized()
        .expect("relative adapter refusal");
    assert!(!relative.status.success());
    assert!(String::from_utf8_lossy(&relative.stderr).contains("PERMISSION_TRIAGE_ADAPTER_BIN"));
}

/// ´test:integration:assembler-invokes-only-the-configured-helper-path´
#[test]
fn assembler_invokes_only_the_configured_helper_path() {
    let fixture = FixtureDirectory::new("configured-helper");
    write_ready_inputs(&fixture, "bypass");
    let helper = fixture.path().join("independent-helper-release");
    fs::copy(env!("CARGO_BIN_EXE_permission-triage-hook"), &helper).expect("copy helper");
    let output = command(&fixture)
        .env("PERMISSION_TRIAGE_HOOK_BIN", &helper)
        .arg("--check")
        .output_serialized()
        .expect("configured helper");
    assert_status(&output, 0);
    let retained = fs::read(&helper).expect("helper bytes");
    let output = command_with_out(&fixture, &helper)
        .env("PERMISSION_TRIAGE_HOOK_BIN", &helper)
        .arg("--check")
        .output_serialized()
        .expect("helper output alias refused");
    assert_status(&output, 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("output overlaps a protected input"));
    assert_eq!(fs::read(&helper).expect("retained helper"), retained);
    for path in [
        PathBuf::from("permission-triage-hook"),
        fixture.path().join("missing-helper"),
    ] {
        let output = command(&fixture)
            .env("PERMISSION_TRIAGE_HOOK_BIN", path)
            .arg("--check")
            .output_serialized()
            .expect("refused helper");
        assert_status(&output, 1);
    }
}

fn assert_status(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if code != 0 {
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}

fn worker_rubric_fixture(
    fixture: &FixtureDirectory,
    orchestrator_text: &str,
    worker_text: Option<&str>,
) -> PathBuf {
    let orchestrator = fixture.repo().join("local/permissions/orchestrator.md");
    fs::write(&orchestrator, orchestrator_text).expect("orchestrator rubric");
    let home = fixture.path().join("worker-home");
    fs::create_dir_all(home.join("shared/permissions")).expect("worker rubric directory");
    fs::create_dir_all(home.join("runs")).expect("public run directory");
    if let Some(text) = worker_text {
        fs::write(home.join("shared/permissions/domain.md"), text).expect("worker rubric");
    }
    let entry = fixture.registry().join("orchestration.env");
    let mut text = fs::read_to_string(&entry).expect("registry entry");
    let ledger_source = "[orchestration]\nuids = { base = 40000, count = 1 }\n";
    let ledger_digest = permission_triage::rubric::sha256_digest(ledger_source.as_bytes());
    writeln!(text, "LOOP_HOME={}", home.display()).expect("home field");
    writeln!(text, "LOOP_WORKER_UIDS=40000:1").expect("worker block");
    writeln!(text, "LOOP_ALLOCATIONS_SHA256={ledger_digest}").expect("allocation digest");
    writeln!(
        text,
        "LOOP_ALLOCATIONS_COPIED_AT=2026-09-30T00:00:00.000000000Z"
    )
    .expect("allocation copy time");
    writeln!(text, "LOOP_ORCHESTRATOR_RUBRIC={}", orchestrator.display())
        .expect("orchestrator rubric field");
    fs::write(&entry, text).expect("registry entry");
    write_allocation_fixture(fixture, ledger_source);
    home
}

fn write_allocation_fixture(fixture: &FixtureDirectory, source: &str) {
    let home = fixture.allocation_home();
    fs::create_dir_all(&home).expect("allocation fixture home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("private allocation home");
    let directory = home.join(".config/loops");
    fs::create_dir_all(&directory).expect("allocation directory");
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700))
        .expect("private config");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("private loops");
    let registry = directory.join("registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"orchestration\", uid = 41001, launch = \"projects/fixture\" }]\n").expect("registry fixture");
    fs::set_permissions(registry, fs::Permissions::from_mode(0o600)).expect("private registry");
    let ledger = directory.join("allocations.toml");
    fs::write(&ledger, source).expect("ledger fixture");
    fs::set_permissions(ledger, fs::Permissions::from_mode(0o600)).expect("private ledger");
}

/// ´test:integration:assembler-publishes-ledger-block-and-refuses-mismatch´
#[test]
fn assembler_publishes_ledger_block_and_refuses_mismatch() {
    let fixture = FixtureDirectory::new("allocation-publisher");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    let row_path = fixture.registry().join("orchestration.env");
    let row = fs::read_to_string(&row_path).expect("row");
    fs::write(&row_path, row.replace("LOOP_WORKER_UIDS=40000:1\n", "")).expect("unpublished row");
    let first = command(&fixture)
        .output_serialized()
        .expect("assembly exits");
    assert_status(&first, 0);
    let row =
        fs::read_to_string(fixture.registry().join("orchestration.env")).expect("published row");
    assert!(row.contains("LOOP_WORKER_UIDS=40000:1\n"));
    assert!(row.contains("LOOP_ALLOCATIONS_SHA256="));
    assert!(row.contains("LOOP_ALLOCATIONS_COPIED_AT="));
    let changed = row.replace("LOOP_WORKER_UIDS=40000:1", "LOOP_WORKER_UIDS=41000:1");
    fs::write(fixture.registry().join("orchestration.env"), changed).expect("mismatched row");
    let second = command(&fixture)
        .output_serialized()
        .expect("assembly exits");
    assert_status(&second, 1);
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("allocation row disagrees with ledger")
    );
}

/// ´test:integration:assembler-output-failure-keeps-live-registry´
#[test]
fn assembler_output_failure_keeps_live_registry() {
    let fixture = FixtureDirectory::new("allocation-output-failure");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    let row_path = fixture.registry().join("orchestration.env");
    let row = fs::read_to_string(&row_path).expect("row");
    let row = row.replace("LOOP_WORKER_UIDS=40000:1\n", "");
    fs::write(&row_path, &row).expect("unpublished row");
    fs::create_dir(fixture.out()).expect("output directory");
    let stale = fixture
        .out()
        .join(".settings-fragment.json.permission-triage-assemble.tmp");
    fs::write(&stale, "stale").expect("stale output temporary");
    fs::create_dir(fixture.out().join("settings-fragment.json"))
        .expect("output destination cannot be replaced by a file");
    let output = command(&fixture)
        .output_serialized()
        .expect("assembly exits");
    assert_status(&output, 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a dedicated directory"));
    assert_eq!(fs::read_to_string(&row_path).expect("live row"), row);
    assert_eq!(
        fs::read_to_string(&stale).expect("stale temporary"),
        "stale"
    );
}

/// ´test:integration:assembler-refuses-overlapping-and-populated-output´
#[test]
fn assembler_refuses_overlapping_and_populated_output() {
    let fixture = FixtureDirectory::new("output-separation");
    write_ready_inputs(&fixture, "bypass");
    let registry = fixture.registry();
    let row = registry.join("orchestration.env");
    let original = fs::read(&row).expect("original registry row");
    let aliases = [
        registry.clone(),
        registry.parent().expect("registry parent").to_path_buf(),
        registry.join("nested"),
        fixture.path().to_path_buf(),
        fixture.repo(),
        fixture.repo().join("nested"),
        fixture.verdict(),
        fixture.instance(),
        fixture.classifier(),
        fixture.home().join(".config/loops/allocations.toml"),
        fixture.home().join(".config/loops"),
    ];
    for alias in aliases {
        for check in [true, false] {
            let mut run = command_with_out(&fixture, &alias);
            if check {
                run.arg("--check");
            }
            let output = run.output_serialized().expect("assembly refuses alias");
            assert_status(&output, 3);
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("output overlaps a protected input"),
                "{}",
                alias.display()
            );
            assert_eq!(fs::read(&row).expect("registry row remains"), original);
        }
    }
    fs::create_dir(fixture.out()).expect("dedicated output directory");
    let unrelated = fixture.out().join("unrelated.txt");
    fs::write(&unrelated, "preserve").expect("unrelated output file");
    for check in [true, false] {
        let mut run = command(&fixture);
        if check {
            run.arg("--check");
        }
        let output = run
            .output_serialized()
            .expect("assembly refuses populated output");
        assert_status(&output, 3);
        assert!(String::from_utf8_lossy(&output.stderr).contains("not a dedicated directory"));
        assert_eq!(
            fs::read(&unrelated).expect("unrelated file remains"),
            b"preserve"
        );
        assert_eq!(fs::read(&row).expect("registry row remains"), original);
    }
    fs::remove_file(&unrelated).expect("unrelated output removed");
    fs::write(fixture.out().join("assembly-marker.json"), "old marker")
        .expect("partial previous output");
    for check in [true, false] {
        let mut run = command(&fixture);
        if check {
            run.arg("--check");
        }
        let output = run
            .output_serialized()
            .expect("assembly refuses partial output");
        assert_status(&output, 3);
        assert!(String::from_utf8_lossy(&output.stderr).contains("not a dedicated directory"));
        assert_eq!(fs::read(&row).expect("registry row remains"), original);
    }
}

/// ´test:integration:assembler-refuses-incomplete-worker-snapshot-and-duplicate-loop-uid´
#[test]
fn assembler_refuses_incomplete_worker_snapshot_and_duplicate_loop_uid() {
    for name in ["unannotated", "out-of-range", "duplicate-uid"] {
        let fixture = FixtureDirectory::new(name);
        write_ready_inputs(&fixture, "bypass");
        let row = fixture.registry().join("orchestration.env");
        let mut text = fs::read_to_string(&row).expect("registry row");
        match name {
            "unannotated" => text.push_str("LOOP_WORKER_UIDS=3000:1\n"),
            "out-of-range" => {
                text.push_str("LOOP_WORKER_UIDS=65535:2\n");
                write!(
                    text,
                    "LOOP_ALLOCATIONS_SHA256={}\nLOOP_ALLOCATIONS_COPIED_AT=2026-09-30T00:00:00.000000000Z\n",
                    "a".repeat(64)
                )
                .expect("allocation snapshot fields");
            }
            _ => {
                text.push_str("LOOP_UID=41001\n");
                let peer = format!(
                    "LOOP_NAME=peer\nLOOP_SID=peer-sid\nLOOP_CWD={}\nLOOP_UID=41001\n",
                    fixture.path().join("peer-checkout").display()
                );
                let peer_path = fixture.registry().join("peer.env");
                fs::write(&peer_path, peer).expect("peer row");
                fs::set_permissions(peer_path, fs::Permissions::from_mode(0o600))
                    .expect("private peer row");
            }
        }
        fs::write(&row, text).expect("changed registry row");
        for check in [true, false] {
            let mut run = command(&fixture);
            if check {
                run.arg("--check");
            }
            let output = run.output_serialized().expect("assembler refuses row");
            assert_status(&output, 1);
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("loop registry generation changed"),
                "{name}"
            );
        }
    }
}

/// ´test:integration:assembler-check-validates-planned-worker-block´
#[test]
fn assembler_check_validates_planned_worker_block() {
    let fixture = FixtureDirectory::new("allocation-check");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    let row_path = fixture.registry().join("orchestration.env");
    let row = fs::read_to_string(&row_path).expect("row");
    let row = row.replace("LOOP_WORKER_UIDS=40000:1\n", "");
    fs::write(&row_path, &row).expect("unpublished row");
    assert!(!worker_verdict_path(&home).exists());
    for check in [true, false] {
        let mut run = command(&fixture);
        if check {
            run.arg("--check");
        }
        let output = run.output_serialized().expect("assembly exits");
        assert_status(&output, 1);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("worker rubric verdict for orchestration is unreadable")
        );
        assert_eq!(fs::read_to_string(&row_path).expect("live row"), row);
    }
}

/// A later row refusal leaves the entire deployed generation unchanged.
/// ´test:integration:assembler-refuses-later-row-without-publishing-earlier-row´
#[test]
fn assembler_refuses_later_row_without_publishing_earlier_row() {
    let fixture = FixtureDirectory::new("allocation-generation");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    let first_path = fixture.registry().join("orchestration.env");
    let first = fs::read_to_string(&first_path).expect("first row");
    let first = first.replace("LOOP_WORKER_UIDS=40000:1\n", "");
    fs::write(&first_path, &first).expect("unpublished first row");
    let peer = fixture.registry().join("peer.env");
    let ledger_digest = permission_triage::rubric::sha256_digest(
        b"[orchestration]\nuids = { base = 40000, count = 1 }\n",
    );
    fs::write(&peer, format!("LOOP_NAME=peer\nLOOP_SID=session-peer\nLOOP_CWD={}\nLOOP_UID=41002\nLOOP_HOME={}\nLOOP_STATE_ROOT={}\nLOOP_WORKER_UIDS=41000:1\nLOOP_ALLOCATIONS_SHA256={ledger_digest}\nLOOP_ALLOCATIONS_COPIED_AT=2026-09-30T00:00:00.000000000Z\n", fixture.path().join("peer").display(), fixture.path().join("peer-home").display(), fixture.path().join("peer-state").display())).expect("later row");
    fs::set_permissions(&peer, fs::Permissions::from_mode(0o600)).expect("peer mode");
    let output = command(&fixture)
        .output_serialized()
        .expect("assembly exits");
    assert_status(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("allocation row disagrees with ledger for peer")
    );
    assert_eq!(
        fs::read_to_string(&first_path).expect("first row after refusal"),
        first
    );
}

/// ´test:integration:assembler-retains-only-the-previous-registry-generation´
#[test]
fn assembler_retains_only_the_previous_registry_generation() {
    let fixture = FixtureDirectory::new("retired-generation");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    let row = fixture.registry().join("orchestration.env");
    let original = fs::read_to_string(&row).expect("initial row");
    fs::write(&row, original.replace("LOOP_WORKER_UIDS=40000:1\n", "")).expect("unpublished row");
    assert_status(
        &command(&fixture)
            .output_serialized()
            .expect("first assembly"),
        0,
    );
    let previous = fs::read_to_string(&row).expect("first published row");
    assert_status(
        &command(&fixture)
            .output_serialized()
            .expect("second assembly"),
        0,
    );
    let retired = fs::read_dir(fixture.registry().parent().expect("registry parent"))
        .expect("registry parent listing")
        .map(|entry| entry.expect("registry parent entry").path())
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with(".loops.d.permission-triage-retired-")
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(retired.len(), 1);
    assert_eq!(
        fs::read_to_string(
            retired
                .first()
                .expect("previous generation")
                .join("orchestration.env")
        )
        .expect("retained previous row"),
        previous
    );
}

/// A newer private ledger replaces an older deployed worker block.
/// ´test:integration:assembler-refreshes-block-after-ledger-change´
#[test]
fn assembler_refreshes_block_after_ledger_change() {
    let fixture = FixtureDirectory::new("allocation-refresh");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    assert_status(
        &command(&fixture)
            .output_serialized()
            .expect("first assembly"),
        0,
    );
    let ledger = fixture
        .allocation_home()
        .join(".config/loops/allocations.toml");
    fs::write(
        &ledger,
        "[orchestration]\nuids = { base = 40001, count = 1 }\n",
    )
    .expect("changed allocation");
    let second = command(&fixture)
        .output_serialized()
        .expect("second assembly");
    assert_status(&second, 0);
    let row =
        fs::read_to_string(fixture.registry().join("orchestration.env")).expect("refreshed row");
    assert!(row.contains("LOOP_WORKER_UIDS=40001:1\n"));
}

/// ´test:integration:assembler-refuses-contender-across-ledger-change´
#[test]
fn assembler_refuses_contender_across_ledger_change() {
    let fixture = FixtureDirectory::new("assembly-lock");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    let row_path = fixture.registry().join("orchestration.env");
    let row = fs::read_to_string(&row_path).expect("row");
    fs::write(&row_path, row.replace("LOOP_WORKER_UIDS=40000:1\n", "")).expect("unpublished row");
    let parent = fs::File::open(fixture.registry().parent().expect("registry parent"))
        .expect("assembly lock parent");
    let lock = Flock::lock(parent, FlockArg::LockExclusiveNonblock)
        .expect("first assembler holds parent lock");
    let busy = command(&fixture)
        .output_serialized()
        .expect("contending assembly exits");
    assert_status(&busy, 1);
    assert!(String::from_utf8_lossy(&busy.stderr).contains("assembly-busy"));
    fs::write(
        fixture
            .allocation_home()
            .join(".config/loops/allocations.toml"),
        "[orchestration]\nuids = { base = 40001, count = 1 }\n",
    )
    .expect("ledger changes during first assembly");
    drop(lock);
    let fresh = command(&fixture)
        .output_serialized()
        .expect("fresh assembly exits");
    assert_status(&fresh, 0);
    let row = fs::read_to_string(&row_path).expect("published row");
    assert!(row.contains("LOOP_WORKER_UIDS=40001:1\n"));
}

/// ´test:integration:assembler-refuses-unreadable-ledger-parent´
#[test]
fn assembler_refuses_unreadable_ledger_parent() {
    let fixture = FixtureDirectory::new("unreadable-ledger-parent");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    let row_path = fixture.registry().join("orchestration.env");
    let row = fs::read_to_string(&row_path).expect("row");
    let row = row.replace("LOOP_WORKER_UIDS=40000:1\n", "");
    fs::write(&row_path, &row).expect("unannotated row");
    let parent = fixture.allocation_home().join(".config/loops");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o000))
        .expect("allocation parent inaccessible");
    let output = command(&fixture)
        .output_serialized()
        .expect("assembly exits");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
        .expect("allocation parent restored");
    assert_status(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("output path inspection failed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&row_path).expect("live row"), row);
}

fn worker_check_command(fixture: &FixtureDirectory) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permission-triage-assemble"));
    command
        .args([
            "--worker-rubric-check",
            "--instance",
            fixture.instance().to_str().expect("instance path"),
            "--loop",
            "orchestration",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fixture.home());
    command
}

fn worker_verdict_path(home: &Path) -> PathBuf {
    home.join("runs/worker-rubric-verdict.json")
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
        let mut children = fs::read_dir(path)
            .expect("snapshot directory is readable")
            .map(|entry| entry.expect("snapshot entry is readable").path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            let metadata = fs::symlink_metadata(&child).expect("snapshot metadata is readable");
            let relative = child
                .strip_prefix(root)
                .expect("snapshot child is beneath root")
                .to_owned();
            if metadata.is_dir() {
                entries.insert(relative, (metadata.permissions().mode(), Vec::new()));
                visit(root, &child, entries);
            } else {
                entries.insert(
                    relative,
                    (
                        metadata.permissions().mode(),
                        fs::read(&child).expect("snapshot file is readable"),
                    ),
                );
            }
        }
    }

    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

/// ´test:integration:assembler-blocks-an-explicitly-blocked-verdict´
#[test]
fn assembler_blocks_an_explicitly_blocked_verdict() {
    let fixture = FixtureDirectory::new("blocked");
    fs::write(fixture.verdict(), verdict_document("blocked", true))
        .expect("blocked verdict is written");
    fs::write(
        fixture.instance(),
        instance_document(&fixture, &fixture.repo().join("local/permissions/state")),
    )
    .expect("fixture instance is written");

    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");

    assert_status(&output, 3);
    assert_eq!(
        String::from_utf8(output.stderr).expect("blocked reason is UTF-8"),
        "blocked: deployment blocked: topology verdict forbids deployment\n"
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-blocks-a-missing-verdict´
#[test]
fn assembler_blocks_a_missing_verdict() {
    let fixture = FixtureDirectory::new("missing");
    fs::write(
        fixture.instance(),
        instance_document(&fixture, &fixture.repo().join("local/permissions/state")),
    )
    .expect("fixture instance is written");

    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");

    assert_status(&output, 3);
    assert_eq!(
        String::from_utf8(output.stderr).expect("blocked reason is UTF-8"),
        "blocked: deployment blocked: topology verdict is missing\n"
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-renders-audit-after-the-complete-probe-contract´
#[test]
fn assembler_renders_audit_after_the_complete_probe_contract() {
    let fixture = FixtureDirectory::new("bypass");
    write_ready_inputs(&fixture, "bypass");
    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");
    assert_status(&output, 0);
    assert_eq!(read_assembly(&fixture)["hookMode"], "audit");
}

/// ´test:integration:assembler-validates-an-unset-loop-registry-before-probe-block´
#[test]
fn assembler_validates_an_unset_loop_registry_before_probe_block() {
    let fixture = FixtureDirectory::new("unset-registry");
    fs::write(fixture.verdict(), verdict_document("bypass", false))
        .expect("ready verdict is written");
    fs::write(
        fixture.instance(),
        instance_document_without_registry(
            &fixture,
            &fixture.repo().join("local/permissions/state"),
        ),
    )
    .expect("fixture instance without a registry is written");

    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");

    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("loop registry is required"));
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-rejects-a-configured-missing-owner-rubric´
#[test]
fn assembler_rejects_a_configured_missing_owner_rubric() {
    let fixture = FixtureDirectory::new("missing-owner");
    fs::write(fixture.verdict(), verdict_document("bypass", false))
        .expect("ready verdict is written");
    fs::write(
        fixture.instance(),
        instance_document_with_owner(
            &fixture,
            &fixture.repo().join("local/permissions/state"),
            &fixture.repo().join("local/permissions/missing-owner.md"),
        ),
    )
    .expect("fixture instance with a missing owner rubric is written");

    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");

    assert_status(&output, 1);
    assert!(
        String::from_utf8(output.stderr)
            .expect("failure reason is UTF-8")
            .contains("configured owner rubric is missing")
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-rejects-an-insecure-loop-registry-directory´
#[test]
fn assembler_rejects_an_insecure_loop_registry_directory() {
    let fixture = FixtureDirectory::new("public-registry-directory");
    write_ready_inputs(&fixture, "bypass");
    fs::set_permissions(fixture.registry(), fs::Permissions::from_mode(0o755))
        .expect("fixture registry directory is made public");

    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");

    assert_status(&output, 1);
    assert!(
        String::from_utf8(output.stderr)
            .expect("failure reason is UTF-8")
            .contains("loop registry is not a private directory")
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-rejects-an-insecure-loop-registry-entry´
#[test]
fn assembler_rejects_an_insecure_loop_registry_entry() {
    let fixture = FixtureDirectory::new("public-registry-entry");
    write_ready_inputs(&fixture, "bypass");
    fs::set_permissions(
        fixture.registry().join("orchestration.env"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("fixture registry entry is made public");

    let output = command(&fixture)
        .output_serialized()
        .expect("assembler exits");

    assert_status(&output, 1);
    assert!(
        String::from_utf8(output.stderr)
            .expect("failure reason is UTF-8")
            .contains("loop registry is not a private directory")
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-rejects-invalid-private-state-roots-and-classifier-binaries´
#[test]
fn assembler_rejects_invalid_private_state_roots_and_classifier_binaries() {
    let fixture = FixtureDirectory::new("invalid-state-root");
    fs::write(fixture.verdict(), verdict_document("bypass", false))
        .expect("ready verdict is written");
    let cases = [PathBuf::from("local/permissions/state")];
    for state_root in cases {
        fs::write(fixture.instance(), instance_document(&fixture, &state_root))
            .expect("invalid fixture instance is written");

        let output = command(&fixture)
            .output_serialized()
            .expect("assembler exits");

        assert_status(&output, 1);
        assert_ne!(output.stderr, [] as [u8; 0]);
        assert!(!fixture.out().exists());
    }
    let state_root = fixture.repo().join("local/permissions/state");
    for classifier in [
        PathBuf::from("relative/claude"),
        fixture.path().join("missing-classifier"),
    ] {
        fs::write(
            fixture.instance(),
            instance_document_with_classifier(&fixture, &state_root, &classifier),
        )
        .expect("invalid classifier instance is written");

        let output = command(&fixture)
            .output_serialized()
            .expect("assembler exits");

        assert_status(&output, 1);
        assert_ne!(output.stderr, [] as [u8; 0]);
        assert!(!fixture.out().exists());
    }
}

/// ´test:integration:assembler-accepts-registered-root-outside-checkout´
#[test]
fn assembler_accepts_registered_root_outside_checkout() {
    let fixture = FixtureDirectory::new("outside-state-root");
    write_ready_inputs(&fixture, "bypass");
    let root = fixture.path().join("outside/state");
    fs::create_dir_all(&root).expect("outside root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    fs::write(
        fixture.registry().join("orchestration.env"),
        format!(
            "LOOP_NAME=orchestration\nLOOP_SID=session-main\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            fixture.repo().display(),
            root.display()
        ),
    )
    .expect("registered outside root");
    fs::write(fixture.instance(), instance_document(&fixture, &root)).expect("instance root");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&output, 0);
}

/// ´test:integration:assembler-rejects-registry-beneath-state-root´
#[test]
fn assembler_rejects_registry_beneath_state_root() {
    let fixture = FixtureDirectory::new("registry-beneath-state");
    write_ready_inputs(&fixture, "bypass");
    let root = fixture.path().join("outside/state");
    fs::create_dir_all(&root).expect("outside root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let nested_registry = root.join("loops.d");
    fs::rename(fixture.registry(), &nested_registry).expect("registry beneath root");
    fs::write(
        nested_registry.join("orchestration.env"),
        format!(
            "LOOP_NAME=orchestration\nLOOP_SID=session-main\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            fixture.repo().display(),
            root.display()
        ),
    )
    .expect("registered root");
    let instance = String::from_utf8(instance_document(&fixture, &root))
        .expect("instance UTF-8")
        .replace(
            &fixture.registry().display().to_string(),
            &nested_registry.display().to_string(),
        );
    fs::write(fixture.instance(), instance).expect("instance registry");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("authorization source"));
}

/// ´test:integration:assembler-check-is-write-free-and-usage-exits-two´
#[test]
fn assembler_check_is_write_free_and_usage_exits_two() {
    let fixture = FixtureDirectory::new("check");
    write_ready_inputs(&fixture, "bypass");
    let before = snapshot(fixture.path());

    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembler check exits");

    assert_status(&output, 0);
    assert!(
        output.stdout.is_empty(),
        "check must not expose a deployment record before bite 5"
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(snapshot(fixture.path()), before);
    assert!(!fixture.out().exists());

    let output = Command::new(env!("CARGO_BIN_EXE_permission-triage-assemble"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fixture.home())
        .output_serialized()
        .expect("assembler usage exits");

    assert_status(&output, 2);
    assert_eq!(
        String::from_utf8(output.stderr).expect("usage is UTF-8"),
        "usage: permission-triage-assemble --verdict FILE --repo DIR --instance FILE --out DIR [--audit-evidence FILE] [--check]\n"
    );
    assert_eq!(snapshot(fixture.path()), before);
}

/// ´test:integration:bite-two-assembler-rejects-legacy-manual-auto-in-check´
#[test]
fn bite_two_assembler_rejects_legacy_manual_auto_in_check() {
    for topology in ["manual", "auto"] {
        let fixture = FixtureDirectory::new("legacy-check");
        write_ready_inputs(&fixture, topology);
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
        legacy["schema"] = json!(1);
        legacy["selected_topology"] = json!(topology);
        fs::write(
            fixture.verdict(),
            serde_json::to_vec(&legacy).expect("JSON"),
        )
        .expect("legacy verdict");
        let output = command(&fixture)
            .arg("--check")
            .output_serialized()
            .expect("assembler");
        assert_status(&output, 1);
        assert!(String::from_utf8_lossy(&output.stderr).contains("schema is not 2"));
        assert!(!fixture.out().exists());
    }
}

/// ´test:integration:bite-two-assembler-requires-every-evidence-component´
#[test]
fn bite_two_assembler_requires_every_evidence_component() {
    for field in [
        "audit",
        "bypass",
        "settings_deny_wins",
        "infrastructure",
        "table_confirmation",
        "friction",
    ] {
        let fixture = FixtureDirectory::new("missing-row");
        write_ready_inputs(&fixture, "bypass");
        let mut verdict: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
        verdict["schema"] = json!(2);
        for present in [
            "audit",
            "bypass",
            "settings_deny_wins",
            "infrastructure",
            "table_confirmation",
            "friction",
        ] {
            verdict[present] = json!([{"classification": "pass"}]);
        }
        verdict.as_object_mut().expect("object").remove(field);
        fs::write(
            fixture.verdict(),
            serde_json::to_vec(&verdict).expect("JSON"),
        )
        .expect("verdict");
        let output = command(&fixture)
            .arg("--check")
            .output_serialized()
            .expect("assembler");
        assert_status(&output, 1);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(field),
            "{field}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!fixture.out().exists());
    }
}

fn check_mutated_verdict(mutator: impl FnOnce(&mut serde_json::Value), reason: &str) {
    let fixture = FixtureDirectory::new("adversarial-verdict");
    write_ready_inputs(&fixture, "bypass");
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    mutator(&mut verdict);
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("mutated verdict");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembler check");
    assert!(!output.status.success(), "mutated evidence accepted");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{reason}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:fix-assembler-rejects-stale-roster-and-planned-count´
#[test]
fn fix_assembler_rejects_stale_roster_and_planned_count() {
    check_mutated_verdict(
        |v| {
            v["roster"].as_array_mut().expect("roster").pop();
        },
        "roster is missing or stale",
    );
    check_mutated_verdict(
        |v| v["planned_trials"] = json!(1),
        "roster is missing or stale",
    );
}

/// ´test:integration:fix-assembler-rejects-nonpass-and-missing-rows´
#[test]
fn fix_assembler_rejects_nonpass_and_missing_rows() {
    for state in ["fail", "deferred", "not-run"] {
        check_mutated_verdict(
            |v| v["bypass"][0]["classification"] = json!(state),
            "row did not pass",
        );
    }
    check_mutated_verdict(
        |v| {
            v["audit"].as_array_mut().expect("audit").remove(0);
        },
        "row is missing or duplicated",
    );
}

/// ´test:integration:fix-assembler-rejects-short-and-duplicate-repetitions´
#[test]
fn fix_assembler_rejects_short_and_duplicate_repetitions() {
    check_mutated_verdict(
        |v| {
            v["bypass"][0]["repetitions"]
                .as_array_mut()
                .expect("ids")
                .pop();
        },
        "requires three repetitions",
    );
    check_mutated_verdict(
        |v| v["bypass"][0]["repetitions"][1] = v["bypass"][0]["repetitions"][0].clone(),
        "repetitions are duplicated",
    );
}

/// ´test:integration:fix-assembler-rejects-missing-captures´
#[test]
fn fix_assembler_rejects_missing_captures() {
    for field in ["hook_stdout", "invocation_wall_ms"] {
        check_mutated_verdict(
            |v| {
                for trial in v["trials"].as_array_mut().expect("trials") {
                    trial.as_object_mut().expect("trial").remove(field);
                }
            },
            "captures are missing",
        );
    }
}

/// ´test:integration:fix-assembler-rejects-censored-friction-and-stale-version´
#[test]
fn fix_assembler_rejects_censored_friction_and_stale_version() {
    check_mutated_verdict(
        |v| v["friction"]["invocation_wall_ms"]["censored_count"] = json!(1),
        "censored observations",
    );
    check_mutated_verdict(
        |v| v["harness_version"] = json!("2.1.257"),
        "harness version is stale",
    );
}

/// ´test:integration:fix-assembler-rejects-schema-two-manual-auto-and-test-rosters´
#[test]
fn fix_assembler_rejects_schema_two_manual_auto_and_test_rosters() {
    for topology in ["manual", "auto"] {
        check_mutated_verdict(
            |v| v["selected_topology"] = json!(topology),
            "selected no deployable topology",
        );
    }
    check_mutated_verdict(
        |v| v["roster_selection"] = json!("test-implemented"),
        "test roster",
    );
}

/// ´test:integration:fix-empty-latency-is-no-samples´
#[test]
fn fix_empty_latency_is_no_samples() {
    check_mutated_verdict(
        |v| v["friction"]["hook_wall_ms"] = json!({"sample_count": 0, "censored_count": 0, "p50": null, "p95": null, "p99": null, "max": null}),
        "no samples",
    );
}

// Both assembler claims consume the same completed probe document. Neither reads its
// fixture paths: fake provenance is refused before path validation, and the tampering
// test supplies a fresh real-shaped provenance. The producing fixture is removed here.
fn emitted_probe_verdict() -> serde_json::Value {
    static VERDICT: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    VERDICT
        .get_or_init(|| {
            let fixture = FixtureDirectory::new("probe-emitted");
            write_ready_inputs(&fixture, "bypass");
            let harness = fixture.path().join("fake-harness.sh");
            write_executable(&harness, include_bytes!("topology/fake-harness.sh"), 0o700)
                .expect("harness");
            let probe = Command::new(env!("CARGO_BIN_EXE_permission-triage-topology"))
                .args([
                    "--fixture-root",
                    fixture.path().join("probe").to_str().expect("path"),
                ])
                .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
                .env(
                    "PERMISSION_TRIAGE_HOOK_BIN",
                    env!("CARGO_BIN_EXE_permission-triage-hook"),
                )
                .env("FAKE_HARNESS_MODE", "topology-auto-executed")
                .output_serialized()
                .expect("probe");
            let verdict: serde_json::Value =
                serde_json::from_slice(&probe.stdout).unwrap_or_else(|error| {
                    panic!(
                        "probe verdict: {error}; status={}; stderr={}",
                        probe.status,
                        String::from_utf8_lossy(&probe.stderr)
                    )
                });
            assert_eq!(probe.status.code(), Some(3), "{}", verdict["reasons"]);
            assert!(
                verdict["reasons"]
                    .as_array()
                    .expect("reasons")
                    .contains(&json!("harness: fake"))
            );
            assert_eq!(
                verdict["deferred_rows"].as_array().expect("deferred").len(),
                0
            );
            verdict
        })
        .clone()
}

/// ´test:integration:fix-assembler-validates-probe-emitted-verdict´
#[test]
fn fix_assembler_validates_probe_emitted_verdict() {
    let fixture = FixtureDirectory::new("probe-emitted-blocked");
    write_ready_inputs(&fixture, "bypass");
    let verdict = emitted_probe_verdict();
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("emitted verdict"),
    )
    .expect("actual verdict");
    let blocked = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembler");
    assert_status(&blocked, 3);
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("harness: fake"));
}

/// ´test:integration:assembler-refuses-tampered-probe-infrastructure-row´
#[test]
fn assembler_refuses_tampered_probe_infrastructure_row() {
    let fixture = FixtureDirectory::new("probe-emitted-tampered");
    write_ready_inputs(&fixture, "bypass");
    let emitted = emitted_probe_verdict();
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("ready verdict"))
            .expect("ready verdict JSON");
    // Only the measured infrastructure row is under test. Unrelated audit trials
    // can time out under load and must not choose this fixture's topology.
    let row = &emitted["infrastructure"][0];
    assert_eq!(row["classification"], "pass", "{row}");
    verdict["infrastructure"][0] = row.clone();
    for id in row["repetitions"].as_array().expect("measured repetitions") {
        let trial = emitted["trials"]
            .as_array()
            .expect("measured trials")
            .iter()
            .find(|trial| trial["id"] == *id)
            .expect("measured repetition");
        let target = verdict["trials"]
            .as_array_mut()
            .expect("ready trials")
            .iter_mut()
            .find(|trial| trial["id"] == *id)
            .expect("ready repetition");
        *target = trial.clone();
    }
    let provenance = real_shaped_probe_provenance(&fixture);
    verdict["harness_binary"] = provenance["path"].clone();
    verdict["harness_provenance"] = provenance;
    verdict["deployment_blocked"] = json!(false);
    assert_eq!(verdict["selected_topology"], "bypass");
    verdict["reasons"] = json!([]);
    verdict["status"] = json!("ready");
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("untampered measured row");
    let accepted = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("baseline assembler");
    assert_status(&accepted, 0);
    verdict["infrastructure"][0]["classification"] = json!("fail");
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("tampered flag");
    let tampered = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembler");
    // Row validation is reached only once the provenance reads real, and it refuses as an
    // infrastructure failure rather than a blocked verdict, so the arm is discriminated by both.
    assert_status(&tampered, 1);
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("row did not pass"));
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-accepts-probe-emitted-real-provenance-shape´
#[test]
fn assembler_accepts_probe_emitted_real_provenance_shape() {
    let fixture = FixtureDirectory::new("probe-provenance-shape");
    write_ready_inputs(&fixture, "bypass");
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    let provenance = real_shaped_probe_provenance(&fixture);
    verdict["harness_binary"] = provenance["path"].clone();
    verdict["harness_provenance"] = provenance;
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("verdict");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 0);
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-requires-the-estate-domain-rubric´
#[test]
fn assembler_requires_the_estate_domain_rubric() {
    let fixture = FixtureDirectory::new("missing-estate-domain");
    write_ready_inputs(&fixture, "bypass");
    fs::remove_file(fixture.repo().join("local/permissions/domain.md")).expect("remove domain");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("domain rubric"));
}

/// ´test:integration:assembler-inventory-uses-registered-estate-rubric´
#[test]
fn assembler_inventory_uses_registered_estate_rubric() {
    let fixture = FixtureDirectory::new("estate-rubric-inventory");
    write_ready_inputs(&fixture, "bypass");
    let estate = fixture.repo().join("local/permissions/orchestrator.md");
    fs::write(&estate, "estate domain\n").expect("estate rubric");
    let entry = fixture.registry().join("orchestration.env");
    let mut text = fs::read_to_string(&entry).expect("registry entry");
    writeln!(text, "LOOP_ORCHESTRATOR_RUBRIC={}", estate.display()).expect("registry field");
    fs::write(&entry, text).expect("registry entry");
    let output = command(&fixture).output_serialized().expect("assemble");
    assert_status(&output, 0);
    let record = read_assembly(&fixture);
    assert_eq!(
        record["domainRubricDigests"]["orchestration"],
        permission_triage::rubric::sha256_digest(b"estate domain\n")
    );
}

/// ´test:integration:assembler-refuses-orchestrator-rubric-outside-owner-directory´
#[test]
fn assembler_refuses_orchestrator_rubric_outside_owner_directory() {
    let fixture = FixtureDirectory::new("outside-estate-rubric");
    write_ready_inputs(&fixture, "bypass");
    let entry = fixture.registry().join("orchestration.env");
    let mut text = fs::read_to_string(&entry).expect("registry entry");
    writeln!(
        text,
        "LOOP_ORCHESTRATOR_RUBRIC={}",
        fixture.path().join("outside.md").display()
    )
    .expect("registry field");
    fs::write(&entry, text).expect("registry entry");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("LOOP_ORCHESTRATOR_RUBRIC"));
}

/// ´test:integration:deployment-requires-domain-rubric-for-every-loop´
#[test]
fn deployment_requires_domain_rubric_for_every_loop() {
    let fixture = FixtureDirectory::new("peer-missing-domain");
    write_ready_inputs(&fixture, "bypass");
    let peer = fixture.path().join("peer");
    let state = peer.join("local/state");
    fs::create_dir_all(&state).expect("peer state root");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("private peer root");
    let entry = fixture.registry().join("peer.env");
    fs::write(
        &entry,
        format!(
            "LOOP_NAME=peer\nLOOP_SID=peer-session\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            peer.display(),
            state.display()
        ),
    )
    .expect("peer registry entry");
    fs::set_permissions(entry, fs::Permissions::from_mode(0o600)).expect("private peer entry");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembly check");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("domain rubric is missing for peer"));
}

/// ´test:integration:worker-rubric-check-refuses-invalid-deployment-layout´
#[test]
fn worker_rubric_check_refuses_invalid_deployment_layout() {
    let fixture = FixtureDirectory::new("worker-invalid-layout");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    let entry = fixture.registry().join("orchestration.env");
    let text = fs::read_to_string(&entry).expect("registry entry");
    let original = format!("LOOP_CWD={}", fixture.repo().display());
    fs::write(
        &entry,
        text.replace(&original, &format!("LOOP_CWD={}", home.display())),
    )
    .expect("invalid launch directory");
    let output = worker_check_command(&fixture)
        .output_serialized()
        .expect("worker check");
    assert_status(&output, 2);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("LOOP_CWD"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!worker_verdict_path(&home).exists());
}

/// ´test:integration:worker-rubric-check-removes-stale-temporary-verdict-symlink´
#[test]
fn worker_rubric_check_removes_stale_temporary_verdict_symlink() {
    let fixture = FixtureDirectory::new("worker-stale-temporary");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    let sentinel = fixture.path().join("stale-sentinel");
    fs::write(&sentinel, "keep me").expect("sentinel");
    let output = Command::new("/bin/sh")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "-c",
            "set -e; ln -s \"$1\" \"$2/.worker-rubric-verdict.$$.tmp\"; exec \"$3\" --worker-rubric-check --instance \"$4\" --loop orchestration",
            "worker-check",
        ])
        .arg(&sentinel)
        .arg(home.join("runs"))
        .arg(env!("CARGO_BIN_EXE_permission-triage-assemble"))
        .arg(fixture.instance())
        .output_serialized()
        .expect("worker check");
    assert_status(&output, 0);
    assert!(worker_verdict_path(&home).exists());
    assert_eq!(fs::read(&sentinel).expect("sentinel remains"), b"keep me");
    assert!(
        fs::read_dir(home.join("runs"))
            .expect("run directory")
            .all(|entry| !entry
                .expect("run entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".worker-rubric-verdict."))
    );
}

/// ´test:integration:worker-rubric-check-publishes-contained-verdict-and-digests´
#[test]
fn worker_rubric_check_publishes_contained_verdict_and_digests() {
    let fixture = FixtureDirectory::new("worker-contained");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    let output = worker_check_command(&fixture)
        .output_serialized()
        .expect("worker check");
    assert_status(&output, 0);
    let path = worker_verdict_path(&home);
    let bytes = fs::read(&path).expect("published verdict");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("verdict JSON");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["loop"], "orchestration");
    assert_eq!(
        value["orchestrator_rubric_digest"],
        permission_triage::rubric::sha256_digest(b"`/domain/`\n")
    );
    assert_eq!(
        value["worker_rubric_digest"],
        permission_triage::rubric::sha256_digest(b"`/domain/sub/`\n")
    );
    assert_eq!(value["verdict"], "contained");
    assert_eq!(value["refused_roots"], json!([]));
    assert!(
        value["checked_at"]
            .as_str()
            .is_some_and(|stamp| stamp.ends_with('Z'))
    );
    assert_eq!(
        fs::metadata(&path)
            .expect("verdict metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    let text = String::from_utf8(bytes).expect("verdict text");
    let fields = [
        "\"schema\"",
        "\"loop\"",
        "\"orchestrator_rubric_digest\"",
        "\"worker_rubric_digest\"",
        "\"verdict\"",
        "\"refused_roots\"",
        "\"checked_at\"",
    ];
    let positions = fields.map(|field| text.find(field).expect("ordered verdict field"));
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

/// ´test:integration:worker-rubric-check-publishes-refused-roots´
#[test]
fn worker_rubric_check_publishes_refused_roots() {
    let fixture = FixtureDirectory::new("worker-refused");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/outside/`\n"));
    let output = worker_check_command(&fixture)
        .output_serialized()
        .expect("worker check");
    assert_status(&output, 1);
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(worker_verdict_path(&home)).expect("published refusal"))
            .expect("verdict JSON");
    assert_eq!(value["verdict"], "refused");
    assert_eq!(value["refused_roots"], json!(["/outside/"]));
}

/// ´test:integration:worker-rubric-check-missing-rubric-publishes-nothing´
#[test]
fn worker_rubric_check_missing_rubric_publishes_nothing() {
    let fixture = FixtureDirectory::new("worker-missing");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", None);
    let output = worker_check_command(&fixture)
        .output_serialized()
        .expect("worker check");
    assert_status(&output, 2);
    assert!(!worker_verdict_path(&home).exists());
}

/// ´test:integration:deployment-requires-published-worker-rubric-verdict´
#[test]
fn deployment_requires_published_worker_rubric_verdict() {
    let fixture = FixtureDirectory::new("deployment-missing-worker-verdict");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembly check");
    assert_status(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("worker rubric verdict for orchestration")
    );
}

/// ´test:integration:deployment-refuses-published-worker-rubric-refusal´
#[test]
fn deployment_refuses_published_worker_rubric_refusal() {
    let fixture = FixtureDirectory::new("deployment-refused-worker-verdict");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/outside/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        1,
    );
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembly check");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not contained"));
}

/// ´test:integration:deployment-refuses-stale-orchestrator-rubric-digest´
#[test]
fn deployment_refuses_stale_orchestrator_rubric_digest() {
    let fixture = FixtureDirectory::new("deployment-stale-worker-verdict");
    write_ready_inputs(&fixture, "bypass");
    let _home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    fs::write(
        fixture.repo().join("local/permissions/orchestrator.md"),
        "`/changed/`\n",
    )
    .expect("changed orchestrator rubric");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("assembly check");
    assert_status(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("different orchestrator rubric digest")
    );
}

/// ´test:integration:deployment-records-contained-worker-rubric-verdict´
#[test]
fn deployment_records_contained_worker_rubric_verdict() {
    let fixture = FixtureDirectory::new("deployment-contained-worker-verdict");
    write_ready_inputs(&fixture, "bypass");
    let home = worker_rubric_fixture(&fixture, "`/domain/`\n", Some("`/domain/sub/`\n"));
    assert_status(
        &worker_check_command(&fixture)
            .output_serialized()
            .expect("worker check"),
        0,
    );
    let output = command(&fixture).output_serialized().expect("assembly");
    assert_status(&output, 0);
    let record = read_assembly(&fixture);
    let published: serde_json::Value =
        serde_json::from_slice(&fs::read(worker_verdict_path(&home)).expect("worker verdict"))
            .expect("verdict JSON");
    let saved = &record["workerRubricVerdicts"]["orchestration"];
    assert_eq!(saved["loop"], "orchestration");
    assert_eq!(
        saved["orchestratorRubricDigest"],
        published["orchestrator_rubric_digest"]
    );
    assert_eq!(
        saved["workerRubricDigest"],
        published["worker_rubric_digest"]
    );
    assert_eq!(saved["checkedAt"], published["checked_at"]);
}

/// ´test:integration:assembler-requires-every-registered-peer-domain-rubric´
#[test]
fn assembler_requires_every_registered_peer_domain_rubric() {
    let fixture = FixtureDirectory::new("missing-peer-domain");
    write_ready_inputs(&fixture, "bypass");
    let checkout = fixture.path().join("peer");
    let root = checkout.join("local/state");
    fs::create_dir_all(&root).expect("peer root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private peer root");
    let entry = fixture.registry().join("peer.env");
    fs::write(
        &entry,
        format!(
            "LOOP_NAME=peer\nLOOP_SID=peer-session\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            checkout.display(),
            root.display()
        ),
    )
    .expect("peer entry");
    fs::set_permissions(entry, fs::Permissions::from_mode(0o600)).expect("private peer entry");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("domain rubric"));
}

/// ´test:integration:assembler-requires-estate-registration-and-matching-state-root´
#[test]
fn assembler_requires_estate_registration_and_matching_state_root() {
    for missing in [true, false] {
        let fixture = FixtureDirectory::new("missing-estate-registration");
        write_ready_inputs(&fixture, "bypass");
        let entry = fixture.registry().join("orchestration.env");
        if missing {
            fs::remove_file(entry).expect("remove estate entry");
        } else {
            let alternate = fixture.repo().join("local/alternate");
            fs::create_dir(&alternate).expect("alternate root");
            fs::set_permissions(&alternate, fs::Permissions::from_mode(0o700))
                .expect("private alternate");
            let text = fs::read_to_string(&entry).expect("estate entry");
            fs::write(
                entry,
                text.replace(
                    &fixture
                        .repo()
                        .join("local/permissions/state")
                        .to_string_lossy()
                        .into_owned(),
                    &alternate.to_string_lossy(),
                ),
            )
            .expect("mismatching estate root");
        }
        let output = command(&fixture)
            .arg("--check")
            .output_serialized()
            .expect("check exits");
        assert_status(&output, 1);
    }
}

/// ´test:integration:assembler-refuses-entry-without-session-identifier´
#[test]
fn assembler_refuses_entry_without_session_identifier() {
    let fixture = FixtureDirectory::new("missing-session-identifier");
    write_ready_inputs(&fixture, "bypass");
    let entry = fixture.registry().join("orchestration.env");
    let text = fs::read_to_string(&entry).expect("estate entry");
    fs::write(&entry, text.replace("LOOP_SID=session-main\n", ""))
        .expect("entry without session identifier");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&output, 1);
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("orchestration"), "{diagnostic}");
    assert!(diagnostic.contains("LOOP_SID"), "{diagnostic}");
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-check-validates-complete-registry-without-publishing´
#[test]
fn assembler_check_validates_complete_registry_without_publishing() {
    let fixture = FixtureDirectory::new("complete-inventory");
    write_ready_inputs(&fixture, "bypass");
    let checkout = fixture.path().join("peer");
    let root = checkout.join("local/state");
    fs::create_dir_all(&root).expect("peer state");
    fs::create_dir_all(checkout.join("local/permissions")).expect("peer permissions");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    fs::write(
        checkout.join("local/permissions/domain.md"),
        "peer domain\n",
    )
    .expect("peer domain");
    let entry = fixture.registry().join("peer.env");
    fs::write(
        &entry,
        format!(
            "LOOP_NAME=peer\nLOOP_SID=peer-session\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            checkout.display(),
            root.display()
        ),
    )
    .expect("peer entry");
    fs::set_permissions(entry, fs::Permissions::from_mode(0o600)).expect("private entry");
    let output = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&output, 0);
    assert_eq!(output.stdout, [] as [u8; 0]);
    fs::remove_file(checkout.join("local/permissions/domain.md")).expect("remove peer domain");
    let missing_domain = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&missing_domain, 1);
    assert!(
        String::from_utf8_lossy(&missing_domain.stderr)
            .contains("domain rubric is missing for peer")
    );
    assert!(!fixture.out().exists());
}

/// ´test:integration:assembler-publishes-with-registry-under-configuration-root´
#[test]
fn assembler_publishes_with_registry_under_configuration_root() {
    let fixture = FixtureDirectory::new("shared-assembly-lock");
    write_ready_inputs(&fixture, "bypass");
    let old_registry = fixture.registry();
    let configuration_root = fixture.home().join(".config/loops");
    let registry = configuration_root.join("loops.d");
    fs::rename(&old_registry, &registry).expect("registry beneath configuration root");
    let instance = fs::read_to_string(fixture.instance()).expect("instance");
    let old_path = old_registry.to_str().expect("old registry path");
    let new_path = registry.to_str().expect("new registry path");
    assert!(instance.contains(old_path));
    fs::write(fixture.instance(), instance.replace(old_path, new_path))
        .expect("instance names relocated registry");

    let check = command(&fixture)
        .arg("--check")
        .output_serialized()
        .expect("check exits");
    assert_status(&check, 0);
    assert!(!fixture.out().exists());

    let publish = command(&fixture)
        .output_serialized()
        .expect("publishing assembly exits");
    assert_status(&publish, 0);
    assert!(registry.join("orchestration.env").is_file());
    assert!(fixture.out().join("assembly-marker.json").is_file());
}

/// ´test:integration:assembler-rejects-real-claim-with-fake-harness-provenance´
#[test]
fn assembler_rejects_real_claim_with_fake_harness_provenance() {
    for evidence in ["name", "bytes", "digest"] {
        let fixture = FixtureDirectory::new(evidence);
        write_ready_inputs(&fixture, "bypass");
        let mut verdict: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
        verdict["harness_binary"] = json!("/fixture/claude");
        verdict["harness_provenance"] = json!({
            "kind": "real", "path": "/fixture/claude", "version": "2.1.258",
            "fake_name_match": evidence == "name", "fake_bytes_match": evidence == "bytes",
            "sha256": if evidence == "digest" { permission_triage::rubric::sha256_digest(include_bytes!("topology/fake-harness.sh")) } else { "0".repeat(64) }
        });
        fs::write(
            fixture.verdict(),
            serde_json::to_vec(&verdict).expect("JSON"),
        )
        .expect("verdict");
        for check in [false, true] {
            let mut command = command(&fixture);
            if check {
                command.arg("--check");
            }
            let output = command.output_serialized().expect("assembler");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("harness: fake"),
                "{evidence}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_status(&output, 3);
            assert_eq!(output.stdout, [] as [u8; 0]);
            assert!(!fixture.out().exists());
        }
    }
}

fn audit_evidence(fixture: &FixtureDirectory) -> serde_json::Value {
    use permission_triage::rubric::sha256_digest;
    let registry = permission_triage::load_registry(Some(fixture.registry().into_os_string()))
        .expect("registry loads")
        .expect("registry exists");
    let domains: BTreeMap<_, _> = registry
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.name().to_owned(),
                sha256_digest(
                    &fs::read(entry.checkout().join("local/permissions/domain.md"))
                        .expect("domain"),
                ),
            )
        })
        .collect();
    json!({
        "schema": 1,
        "window_start": "2026-09-01T00:00:00.000000000Z",
        "window_end": "2026-09-01T01:00:00.000000000Z",
        "harness_version": permission_triage::topology::SUPPORTED_HARNESS_VERSION,
        "binary_digest": "0".repeat(64),
        "topology_digest": sha256_digest(&fs::read(fixture.verdict()).expect("verdict")),
        "registry_digest": sha256_digest(&serde_json::to_vec(&registry.sorted_state_entries()).expect("inventory")),
        "domain_digests": domains,
        "sessions": [{"session": "session-main", "loop": "orchestration", "role": "orchestrator", "count": 100}],
        "unknown_count": 0, "lost_record_count": 0, "sample_count": 100,
        "model_call_share": 0.2,
        "verdict_wall_ms": {"p50": 1, "p95": 2, "p99": 3, "max": 4},
        "invocation_wall_ms": {"p50": 5, "p95": 6, "p99": 7, "max": 8},
        "would_be_denials": [{"class": "agent-error", "loop": "orchestration", "scope": "loop", "count": 1, "share": 0.01}],
        "peer_domain_denial_count": 0,
        "limits": {
            "verdict_wall_ms": {"p50": 10, "p95": 20, "p99": 30, "max": 40},
            "invocation_wall_ms": {"p50": 50, "p95": 60, "p99": 70, "max": 80},
            "model_call_share_max": 0.25, "denial_share_max": 0.05
        }
    })
}

fn evidence_command(fixture: &FixtureDirectory, evidence: &serde_json::Value) -> Command {
    let path = fixture.path().join("audit-evidence.json");
    fs::write(&path, serde_json::to_vec(evidence).expect("evidence JSON")).expect("evidence");
    let mut cmd = command(fixture);
    cmd.arg("--audit-evidence").arg(path);
    cmd
}

fn reject_evidence(mutator: impl FnOnce(&mut serde_json::Value), reason: &str) {
    let fixture = FixtureDirectory::new("audit-evidence");
    write_ready_inputs(&fixture, "bypass");
    let mut evidence = audit_evidence(&fixture);
    mutator(&mut evidence);
    let mut cmd = evidence_command(&fixture, &evidence);
    let before = snapshot(fixture.path());
    let output = cmd.arg("--check").output_serialized().expect("check exits");
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "expected {reason}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(snapshot(fixture.path()), before);
}

/// ´test:integration:evidence-complete-check-is-silent-write-free-and-mode-independent´
#[test]
fn evidence_complete_check_is_silent_write_free_and_mode_independent() {
    let fixture = FixtureDirectory::new("evidence-accept");
    write_ready_inputs(&fixture, "bypass");
    let evidence = audit_evidence(&fixture);
    for mode in ["audit", "enforce"] {
        let instance = String::from_utf8(instance_document(
            &fixture,
            &fixture.repo().join("local/permissions/state"),
        ))
        .expect("UTF-8")
        .replace(
            "PERMISSION_TRIAGE_MODE=audit",
            &format!("PERMISSION_TRIAGE_MODE={mode}"),
        );
        fs::write(fixture.instance(), instance).expect("instance");
        let mut cmd = evidence_command(&fixture, &evidence);
        let before = snapshot(fixture.path());
        let output = cmd.arg("--check").output_serialized().expect("check");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert_eq!(snapshot(fixture.path()), before);
    }
}

/// ´test:integration:evidence-rejects-wrong-schema´
#[test]
fn evidence_rejects_wrong_schema() {
    reject_evidence(
        |value| {
            value["schema"] = json!(2);
        },
        "schema",
    );
}

/// ´test:integration:evidence-rejects-unknown-field´
#[test]
fn evidence_rejects_unknown_field() {
    reject_evidence(
        |value| {
            value["extra"] = json!(0);
        },
        "unknown field",
    );
}

/// ´test:integration:evidence-rejects-missing-threshold´
#[test]
fn evidence_rejects_missing_threshold() {
    reject_evidence(
        |value| {
            value["limits"]
                .as_object_mut()
                .expect("limits")
                .remove("model_call_share_max");
        },
        "missing field",
    );
}

/// ´test:integration:evidence-rejects-harness-version-mismatch´
#[test]
fn evidence_rejects_harness_version_mismatch() {
    reject_evidence(
        |value| {
            value["harness_version"] = json!("9.9.9");
        },
        "harness_version mismatch",
    );
}

/// ´test:integration:evidence-rejects-binary-digest-mismatch´
#[test]
fn evidence_rejects_binary_digest_mismatch() {
    reject_evidence(
        |value| {
            value["binary_digest"] = json!("1".repeat(64));
        },
        "binary_digest mismatch",
    );
}

/// ´test:integration:evidence-rejects-topology-digest-mismatch´
#[test]
fn evidence_rejects_topology_digest_mismatch() {
    reject_evidence(
        |value| {
            value["topology_digest"] = json!("1".repeat(64));
        },
        "topology_digest mismatch",
    );
}

/// ´test:integration:evidence-rejects-registry-digest-mismatch´
#[test]
fn evidence_rejects_registry_digest_mismatch() {
    reject_evidence(
        |value| {
            value["registry_digest"] = json!("1".repeat(64));
        },
        "registry_digest mismatch",
    );
}

/// ´test:integration:evidence-rejects-missing-domain´
#[test]
fn evidence_rejects_missing_domain() {
    reject_evidence(
        |value| {
            value["domain_digests"] = json!({});
        },
        "domain inventory mismatch",
    );
}

/// ´test:integration:evidence-rejects-extra-domain´
#[test]
fn evidence_rejects_extra_domain() {
    reject_evidence(
        |value| {
            value["domain_digests"]["ghost"] = json!("0".repeat(64));
        },
        "domain inventory mismatch",
    );
}

/// ´test:integration:evidence-rejects-domain-digest-mismatch´
#[test]
fn evidence_rejects_domain_digest_mismatch() {
    reject_evidence(
        |value| {
            value["domain_digests"]["orchestration"] = json!("1".repeat(64));
        },
        "domain inventory mismatch",
    );
}

/// ´test:integration:evidence-rejects-uppercase-digest´
#[test]
fn evidence_rejects_uppercase_digest() {
    reject_evidence(
        |value| {
            value["binary_digest"] = json!("A".repeat(64));
        },
        "digest",
    );
}

/// ´test:integration:evidence-rejects-unknown-session-role´
#[test]
fn evidence_rejects_unknown_session_role() {
    reject_evidence(
        |value| {
            value["sessions"][0]["role"] = json!("unknown");
        },
        "unknown session",
    );
}

/// ´test:integration:evidence-rejects-unknown-session-loop´
#[test]
fn evidence_rejects_unknown_session_loop() {
    reject_evidence(
        |value| {
            value["sessions"][0]["loop"] = json!("ghost");
        },
        "unknown session",
    );
}

/// ´test:integration:evidence-rejects-unknown-session-id´
#[test]
fn evidence_rejects_unknown_session_id() {
    reject_evidence(
        |value| {
            value["sessions"][0]["session"] = json!("unregistered");
        },
        "unknown session",
    );
}

/// ´test:integration:evidence-rejects-unobserved-session´
#[test]
fn evidence_rejects_unobserved_session() {
    reject_evidence(
        |value| {
            value["sessions"][0]["count"] = json!(0);
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-missing-live-loop´
#[test]
fn evidence_rejects_missing_live_loop() {
    reject_evidence(
        |value| {
            value["sessions"] = json!([]);
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-unknown-count´
#[test]
fn evidence_rejects_unknown_count() {
    reject_evidence(
        |value| {
            value["unknown_count"] = json!(1);
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-lost-record´
#[test]
fn evidence_rejects_lost_record() {
    reject_evidence(
        |value| {
            value["lost_record_count"] = json!(1);
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-sample-count-mismatch´
#[test]
fn evidence_rejects_sample_count_mismatch() {
    reject_evidence(
        |value| {
            value["sample_count"] = json!(99);
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-empty-window´
#[test]
fn evidence_rejects_empty_window() {
    reject_evidence(
        |value| {
            value["window_end"] = value["window_start"].clone();
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-reversed-window´
#[test]
fn evidence_rejects_reversed_window() {
    reject_evidence(
        |value| {
            value["window_end"] = json!("2026-08-31T00:00:00.000000000Z");
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-future-window´
#[test]
fn evidence_rejects_future_window() {
    reject_evidence(
        |value| {
            value["window_end"] = json!("9999-01-01T00:00:00.000000000Z");
        },
        "incomplete window",
    );
}

/// ´test:integration:evidence-rejects-invalid-calendar-date´
#[test]
fn evidence_rejects_invalid_calendar_date() {
    reject_evidence(
        |value| {
            value["window_start"] = json!("2026-02-30T00:00:00.000000000Z");
        },
        "timestamp",
    );
}

/// ´test:integration:evidence-rejects-noncanonical-timestamp´
#[test]
fn evidence_rejects_noncanonical_timestamp() {
    reject_evidence(
        |value| {
            value["window_start"] = json!("2026-09-01T00:00:00+00:00");
        },
        "timestamp",
    );
}

/// ´test:integration:evidence-rejects-negative-count´
#[test]
fn evidence_rejects_negative_count() {
    reject_evidence(
        |value| {
            value["sample_count"] = json!(-1);
        },
        "nonnegative integer",
    );
}

/// ´test:integration:evidence-rejects-fractional-count´
#[test]
fn evidence_rejects_fractional_count() {
    reject_evidence(
        |value| {
            value["sample_count"] = json!(1.5);
        },
        "nonnegative integer",
    );
}

/// ´test:integration:evidence-rejects-negative-share´
#[test]
fn evidence_rejects_negative_share() {
    reject_evidence(
        |value| {
            value["model_call_share"] = json!(-0.1);
        },
        "share",
    );
}

/// ´test:integration:evidence-rejects-share-above-one´
#[test]
fn evidence_rejects_share_above_one() {
    reject_evidence(
        |value| {
            value["model_call_share"] = json!(1.1);
        },
        "share",
    );
}

/// ´test:integration:evidence-rejects-model-share-over-limit´
#[test]
fn evidence_rejects_model_share_over_limit() {
    reject_evidence(
        |value| {
            value["model_call_share"] = json!(0.3);
        },
        "model_call_share exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-denial-share-over-limit´
#[test]
fn evidence_rejects_denial_share_over_limit() {
    reject_evidence(
        |value| {
            value["would_be_denials"][0]["count"] = json!(6);
            value["would_be_denials"][0]["share"] = json!(0.06);
        },
        "denial share exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-peer-domain-denial´
#[test]
fn evidence_rejects_peer_domain_denial() {
    reject_evidence(
        |value| {
            value["peer_domain_denial_count"] = json!(1);
        },
        "peer domain denial",
    );
}

/// ´test:integration:evidence-rejects-unknown-denial-class´
#[test]
fn evidence_rejects_unknown_denial_class() {
    reject_evidence(
        |value| {
            value["would_be_denials"][0]["class"] = json!("invented");
        },
        "denial class",
    );
}

/// ´test:integration:evidence-rejects-unknown-denial-scope´
#[test]
fn evidence_rejects_unknown_denial_scope() {
    reject_evidence(
        |value| {
            value["would_be_denials"][0]["scope"] = json!("global");
        },
        "denial scope",
    );
}

/// ´test:integration:evidence-rejects-unknown-denial-loop´
#[test]
fn evidence_rejects_unknown_denial_loop() {
    reject_evidence(
        |value| {
            value["would_be_denials"][0]["loop"] = json!("ghost");
        },
        "denial loop",
    );
}

/// ´test:integration:evidence-rejects-verdict-wall-ms-p50-over-limit´
#[test]
fn evidence_rejects_verdict_wall_ms_p50_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["verdict_wall_ms"]["p50"] = json!(0);
        },
        "verdict_wall_ms.p50 exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-verdict-wall-ms-p95-over-limit´
#[test]
fn evidence_rejects_verdict_wall_ms_p95_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["verdict_wall_ms"]["p95"] = json!(0);
        },
        "verdict_wall_ms.p95 exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-verdict-wall-ms-p99-over-limit´
#[test]
fn evidence_rejects_verdict_wall_ms_p99_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["verdict_wall_ms"]["p99"] = json!(0);
        },
        "verdict_wall_ms.p99 exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-verdict-wall-ms-max-over-limit´
#[test]
fn evidence_rejects_verdict_wall_ms_max_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["verdict_wall_ms"]["max"] = json!(0);
        },
        "verdict_wall_ms.max exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-invocation-wall-ms-p50-over-limit´
#[test]
fn evidence_rejects_invocation_wall_ms_p50_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["invocation_wall_ms"]["p50"] = json!(0);
        },
        "invocation_wall_ms.p50 exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-invocation-wall-ms-p95-over-limit´
#[test]
fn evidence_rejects_invocation_wall_ms_p95_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["invocation_wall_ms"]["p95"] = json!(0);
        },
        "invocation_wall_ms.p95 exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-invocation-wall-ms-p99-over-limit´
#[test]
fn evidence_rejects_invocation_wall_ms_p99_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["invocation_wall_ms"]["p99"] = json!(0);
        },
        "invocation_wall_ms.p99 exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-invocation-wall-ms-max-over-limit´
#[test]
fn evidence_rejects_invocation_wall_ms_max_over_limit() {
    reject_evidence(
        |value| {
            value["limits"]["invocation_wall_ms"]["max"] = json!(0);
        },
        "invocation_wall_ms.max exceeds limit",
    );
}

/// ´test:integration:evidence-rejects-missing-audit-rows´
#[test]
fn evidence_rejects_missing_audit_rows() {
    let fixture = FixtureDirectory::new("missing-audit");
    write_ready_inputs(&fixture, "bypass");
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    verdict["audit"] = json!([]);
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("verdict");
    let output = evidence_command(&fixture, &audit_evidence(&fixture))
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(
        "blocked: enforce-readiness blocked: topology verdict audit row is missing or duplicated"
    ));
    assert!(!fixture.out().exists());
}

/// ´test:integration:evidence-rejects-missing-bypass-rows´
#[test]
fn evidence_rejects_missing_bypass_rows() {
    let fixture = FixtureDirectory::new("missing-bypass");
    write_ready_inputs(&fixture, "bypass");
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    verdict["bypass"] = json!([]);
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("verdict");
    let output = evidence_command(&fixture, &audit_evidence(&fixture))
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(
        "blocked: enforce-readiness blocked: topology verdict bypass row is missing or duplicated"
    ));
    assert!(!fixture.out().exists());
}

/// ´test:integration:evidence-rejects-missing-settings-deny-wins-rows´
#[test]
fn evidence_rejects_missing_settings_deny_wins_rows() {
    let fixture = FixtureDirectory::new("missing-settings_deny_wins");
    write_ready_inputs(&fixture, "bypass");
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    verdict["settings_deny_wins"] = json!([]);
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("verdict");
    let output = evidence_command(&fixture, &audit_evidence(&fixture))
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(
        "blocked: enforce-readiness blocked: topology verdict settings_deny_wins row is missing or duplicated"
    ));
    assert!(!fixture.out().exists());
}

/// ´test:integration:evidence-rejects-missing-infrastructure-rows´
#[test]
fn evidence_rejects_missing_infrastructure_rows() {
    let fixture = FixtureDirectory::new("missing-infrastructure");
    write_ready_inputs(&fixture, "bypass");
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    verdict["infrastructure"] = json!([]);
    fs::write(
        fixture.verdict(),
        serde_json::to_vec(&verdict).expect("JSON"),
    )
    .expect("verdict");
    let output = evidence_command(&fixture, &audit_evidence(&fixture))
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(
        "blocked: enforce-readiness blocked: topology verdict infrastructure row is missing or duplicated"
    ));
    assert!(!fixture.out().exists());
}

/// ´test:integration:evidence-rejects-missing-live-root´
#[test]
fn evidence_rejects_missing_live_root() {
    let fixture = FixtureDirectory::new("missing-live-root");
    write_ready_inputs(&fixture, "bypass");
    let evidence = audit_evidence(&fixture);
    fs::remove_dir(fixture.repo().join("local/permissions/state")).expect("remove root");
    let output = evidence_command(&fixture, &evidence)
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with(
            "blocked: enforce-readiness blocked: loop registry root deployment failed:"
        )
    );
}

/// ´test:integration:evidence-rejects-missing-fields-and-unknown-nested-keys´
#[test]
fn evidence_rejects_missing_fields_and_unknown_nested_keys() {
    let fixture = FixtureDirectory::new("strict-schema");
    write_ready_inputs(&fixture, "bypass");
    let evidence = audit_evidence(&fixture);
    for pointer in [
        "",
        "/verdict_wall_ms",
        "/invocation_wall_ms",
        "/sessions/0",
        "/would_be_denials/0",
        "/limits",
        "/limits/verdict_wall_ms",
        "/limits/invocation_wall_ms",
    ] {
        let fields = evidence
            .pointer(pointer)
            .expect("object")
            .as_object()
            .expect("object");
        for key in fields.keys() {
            reject_evidence(
                |value| {
                    value
                        .pointer_mut(pointer)
                        .expect("object")
                        .as_object_mut()
                        .expect("object")
                        .remove(key);
                },
                "missing field",
            );
        }
        reject_evidence(
            |value| {
                value
                    .pointer_mut(pointer)
                    .expect("object")
                    .as_object_mut()
                    .expect("object")
                    .insert("extra".to_owned(), json!(0));
            },
            "unknown field",
        );
    }
}

/// ´test:integration:evidence-rejects-mutated-renamed-fixture-build´
#[test]
fn evidence_rejects_mutated_renamed_fixture_build() {
    let fixture = FixtureDirectory::new("renamed-build");
    write_ready_inputs(&fixture, "bypass");
    let mut evidence = audit_evidence(&fixture);
    let mut verdict: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.verdict()).expect("verdict")).expect("JSON");
    let provenance = real_shaped_probe_provenance(&fixture);
    verdict["harness_binary"] = provenance["path"].clone();
    verdict["harness_provenance"] = provenance;
    let bytes = serde_json::to_vec(&verdict).expect("JSON");
    evidence["topology_digest"] = json!(permission_triage::rubric::sha256_digest(&bytes));
    fs::write(fixture.verdict(), bytes).expect("verdict");
    let output = evidence_command(&fixture, &evidence)
        .arg("--check")
        .output_serialized()
        .expect("check");
    assert_status(&output, 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("binary_digest mismatch"));
}

fn read_assembly(fixture: &FixtureDirectory) -> serde_json::Value {
    serde_json::from_slice(&fs::read(fixture.out().join("deployment-record.json")).expect("record"))
        .expect("record JSON")
}

/// ´test:integration:assembly-record-binds-mode-bypass-inventory-and-friction´
#[test]
fn assembly_record_binds_mode_bypass_inventory_and_friction() {
    let fixture = FixtureDirectory::new("assembly-record");
    let (verdict_bytes, _) = write_ready_inputs(&fixture, "bypass");
    let evidence = audit_evidence(&fixture);
    let output = evidence_command(&fixture, &evidence)
        .output_serialized()
        .expect("assemble");
    assert_status(&output, 0);
    let record = read_assembly(&fixture);
    let verdict: serde_json::Value = serde_json::from_slice(&verdict_bytes).expect("verdict");
    assert_eq!(record["hookMode"], "audit");
    assert_eq!(
        record["bypassEvidenceDigest"],
        permission_triage::rubric::sha256_digest(
            &serde_json::to_vec(&verdict["bypass"]).expect("bypass")
        )
    );
    assert_eq!(record["auditEvidence"], evidence);
    assert_eq!(
        record["auditEvidenceDigest"],
        permission_triage::rubric::sha256_digest(
            &fs::read(fixture.path().join("audit-evidence.json")).expect("evidence")
        )
    );
    assert_eq!(
        record["loopRegistry"]["sha256"],
        evidence["registry_digest"]
    );
    assert_eq!(record["domainRubricDigests"], evidence["domain_digests"]);
    assert_eq!(record["registryInventory"][0][0], "orchestration");
    assert_eq!(
        record["registryInventory"][0][3],
        fixture
            .repo()
            .join("local/permissions/state")
            .to_str()
            .expect("path")
    );
}

/// ´test:integration:assembly-reinstall-renders-audit-after-enforce´
#[test]
fn assembly_reinstall_renders_audit_after_enforce() {
    let fixture = FixtureDirectory::new("reinstall");
    write_ready_inputs(&fixture, "bypass");
    let instance = fs::read_to_string(fixture.instance())
        .expect("instance")
        .replace(
            "PERMISSION_TRIAGE_MODE=audit",
            "PERMISSION_TRIAGE_MODE=enforce",
        );
    fs::write(fixture.instance(), &instance).expect("enforce instance");
    fs::create_dir(fixture.out()).expect("previous installation");
    fs::write(
        fixture.out().join("deployment-record.json"),
        b"{\"hookMode\":\"enforce\"}\n",
    )
    .expect("previous record");
    for name in [
        "settings-fragment.json",
        "permission-triage.env",
        "assembly-marker.json",
    ] {
        fs::write(fixture.out().join(name), b"previous generation\n")
            .expect("previous output file");
    }
    let output = command(&fixture).output_serialized().expect("assemble");
    assert_status(&output, 0);
    assert_eq!(read_assembly(&fixture)["hookMode"], "audit");
    assert!(
        fs::read_to_string(fixture.out().join("permission-triage.env"))
            .expect("rendered instance")
            .starts_with("PERMISSION_TRIAGE_MODE=audit\n")
    );
    assert_eq!(
        fs::read_to_string(fixture.instance()).expect("live instance"),
        instance
    );
}

/// ´test:integration:assembly-never-writes-live-instance-or-enables-bypass´
#[test]
fn assembly_never_writes_live_instance_or_enables_bypass() {
    let fixture = FixtureDirectory::new("render-only");
    let (_, instance) = write_ready_inputs(&fixture, "bypass");
    let live = fixture.home().join(".claude");
    fs::create_dir(&live).expect("live home");
    fs::write(
        live.join("permission-triage.env"),
        b"PERMISSION_TRIAGE_MODE=enforce\n",
    )
    .expect("live instance");
    fs::write(
        live.join("settings.json"),
        b"{\"permissions\":{\"defaultMode\":\"default\"}}\n",
    )
    .expect("live settings");
    let before = snapshot(&fixture.home());
    let output = command(&fixture).output_serialized().expect("assemble");
    assert_status(&output, 0);
    assert_eq!(snapshot(&fixture.home()), before);
    assert_eq!(
        fs::read(fixture.instance()).expect("source instance"),
        instance
    );
    let fragment: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.out().join("settings-fragment.json")).expect("fragment"),
    )
    .expect("JSON");
    assert_eq!(
        fragment
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["hooks"]
    );
    assert!(!fragment.to_string().contains("bypass"));
    assert!(read_assembly(&fixture)["auditEvidence"].is_null());
}

/// ´test:integration:assembly-refuses-output-aliasing-an-instance´
#[test]
fn assembly_refuses_output_aliasing_an_instance() {
    let fixture = FixtureDirectory::new("output-alias");
    write_ready_inputs(&fixture, "bypass");
    let before = snapshot(fixture.path());
    let output = Command::new(env!("CARGO_BIN_EXE_permission-triage-assemble"))
        .arg("--verdict")
        .arg(fixture.verdict())
        .arg("--repo")
        .arg(fixture.repo())
        .arg("--instance")
        .arg(fixture.instance())
        .arg("--out")
        .arg(fixture.instance().parent().expect("parent"))
        .env_clear()
        .env(
            "PERMISSION_TRIAGE_ADAPTER_BIN",
            "/private/superloop-claude-hook",
        )
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fixture.home())
        .output_serialized()
        .expect("assemble");
    assert_status(&output, 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("output overlaps a protected input"));
    assert_eq!(snapshot(fixture.path()), before);
}
