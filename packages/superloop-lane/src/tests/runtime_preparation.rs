//! Production namespace preparation executes held programs and completes native worker creation.
use super::helper_service;
use loop_home::CommandSpec;
use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// # Panics
/// Panics if the real namespace entry does not execute the received runtime program.
/// ´claim:superlooplane:runtime-preparation-executes-received-podman´
/// ´test:crate:runtime-preparation-executes-received-podman´
#[test]
fn runtime_preparation_executes_received_podman() {
    proof("SUPERLOOP_RUNTIME_PROOF", "RUNTIME-PODMAN-MEASURED");
}

/// # Panics
/// Panics if the production namespace fixture fails or omits its measured marker.
pub(super) fn proof(flag: &str, marker: &str) -> String {
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "tests::launch::proxy_refresh_preserves_live_helper_pins",
            "--nocapture",
        ])
        .env(flag, "1")
        .env("SUPERLOOP_REFRESH_PROOF", "1")
        .env("_CONTAINERS_USERNS_CONFIGURED", "1")
        .env(
            "_CONTAINERS_ROOTLESS_UID",
            nix::unistd::Uid::effective().as_raw().to_string(),
        )
        .output()
        .expect("runtime fixture");
    std::io::Write::write_all(&mut std::io::stdout().lock(), &output.stderr)
        .expect("entry observations");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains(marker), "{stdout}");
    stdout.into_owned()
}

/// Read the grant measured from production native creation, not a fixture member.
///
/// # Panics
/// Panics if the writer or its read-back does not produce the exact declaration.
pub fn published_plan() -> Value {
    static SNAPSHOT: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    SNAPSHOT
        .get_or_init(|| {
            let output = proof(
                "SUPERLOOP_WORKSPACE_CREATION_PROOF",
                "WORKSPACE-DECLARATION ",
            );
            let row = output
                .lines()
                .find_map(|line| line.strip_prefix("WORKSPACE-DECLARATION "))
                .expect("production grant marker");
            serde_json::from_str(row).expect("production grant")
        })
        .clone()
}

/// Measured grant from the production creation fixture.
#[must_use]
pub fn published_workspace() -> Value {
    published_plan()["compute_workspace"].clone()
}
/// Measured placement from the same production publication.
#[must_use]
pub fn published_placement() -> Value {
    published_plan()["compute_placement"].clone()
}

pub(super) struct MappedStorage(pub(super) PathBuf, pub(super) String);
impl Drop for MappedStorage {
    fn drop(&mut self) {
        drop(helper_service::namespace_python(
            &self.0,
            "import shutil,sys\nfrom pathlib import Path\np=Path(sys.argv[1]);shutil.rmtree(p/'.var/loops/alpha/private',ignore_errors=True);shutil.rmtree(p/'.var/loops/alpha/workers',ignore_errors=True);shutil.rmtree(p/'.var/loops/alpha/runs/R',ignore_errors=True);shutil.rmtree(sys.argv[2],ignore_errors=True)\n",
            &self.1,
        ));
    }
}

/// # Panics
/// Panics if the package binary built beside Cargo's unit test executable is absent.
pub(super) fn binary() -> PathBuf {
    let image = std::env::current_exe().expect("test executable");
    // The nearest ancestor holding the binary is its profile directory, the gate's custom one too.
    let binary = image
        .ancestors()
        .map(|path| path.join("superloop-lane"))
        .find(|path| path.is_file())
        .unwrap_or_default();
    assert!(
        binary.is_file(),
        "unmeasured runtime entry: build the package binary before the focused library test"
    );
    binary
}

/// # Panics
/// Panics if the complete production vector cannot enter a real namespace with its descriptors.
pub(super) fn run(request: &CommandSpec) -> std::process::Output {
    run_with_registry(request, None)
}

/// # Panics
/// Panics if the real namespace entry cannot receive its vector and descriptors.
pub(super) fn run_with_registry(
    request: &CommandSpec,
    registry: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    if let Some(registry) = registry {
        command.env("ENTER_LOOP_REGISTRY", registry);
    }
    request
        .descriptors
        .configure(&mut command)
        .expect("entry descriptor transfer");
    command.output().expect("real namespace entry")
}

const STORAGE: &str = r"
import os,sys,tomllib,shutil
from pathlib import Path
home=Path(sys.argv[1]);root=home/'.var/loops/alpha'
assert os.geteuid()==0
assert os.stat('/').st_uid==int(Path('/proc/sys/kernel/overflowuid').read_text())
gid=tomllib.loads((home/'.config/loops/registry.toml').read_text())['loops'][0]['uid']
shutil.rmtree(root/'workers')
private=root/'private'
for p in [private,private/'.config',private/'.config/mail']:
 p.mkdir(exist_ok=True);os.chmod(p,0o700);os.chown(p,gid,gid)
p=private/'.config/mail/loop.toml'
p.write_text('workers=[]\n[mail]\nversion=1\nallow=[]\n');os.chmod(p,0o600);os.chown(p,gid,gid)
for p in [root/'runs/R',root/'runs/R/launch']:
 p.mkdir(exist_ok=True);os.chmod(p,0o700);os.chown(p,gid,gid)
";

/// # Panics
/// Panics if mapped storage cannot supply a real protected lifetime before runtime verification.
fn birth(home: &Path, runs: &Path, image: &Path, record: &mut Value) {
    let output =
        helper_service::namespace_python(home, STORAGE, "").expect("mapped runtime storage");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let identity: loop_home::mail::birth::Identity =
        serde_json::from_value(record["plan"]["mail"]["identity"].clone()).expect("planned birth");
    for phase in ["reserve", "finish"] {
        let request = loop_home::mail::worker_provision::anchored_command(
            home,
            "alpha",
            &identity,
            "_mail-worker-birth",
            phase,
            image,
            &["/usr/bin/podman".into(), "unshare".into()],
        )
        .expect("production worker composer");
        let output = run(&request);
        assert!(
            output.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    record["mail_birth"] = serde_json::to_value(identity).expect("birth record");
    crate::launch::publish_reservation(&runs.join(".reservation-R.json"), record)
        .expect("birth bound to reservation");
}

/// # Panics
/// Panics if the composer fails to pin the runtime or the real entry misses image inspection.
pub(super) fn exercise(home: &Path, runs: &Path, program: &Path) {
    let mut record = helper_service::prepare(home, runs, program);
    let _storage = MappedStorage(
        home.to_path_buf(),
        record["plan"]["home"]
            .as_str()
            .expect("worker home")
            .to_owned(),
    );
    let image = binary();
    birth(home, runs, &image, &mut record);
    let held_home = fs::File::open(home).expect("home descriptor").into();
    let held_runs = fs::File::open(runs).expect("runs descriptor").into();
    let argv = vec![
        "unshare".into(),
        image.display().to_string(),
        "_prepare-runtime".into(),
        "alpha".into(),
        "R".into(),
        "--owner-home".into(),
        home.display().to_string(),
        "--podman-bin".into(),
        program.display().to_string(),
    ];
    for status in [23, 29] {
        fs::copy("/bin/sh", program).expect("native runtime capability");
        fs::set_permissions(program, fs::Permissions::from_mode(0o700)).expect("executable mode");
        fs::write(
            home.join("image"),
            format!("printf 'received-image-{status}\\n' > runtime-inspection\nexit {status}\n"),
        )
        .expect("image inspection fixture");
        let mut request =
            crate::runtime_entry::command(program, &argv, home, &held_home, runs, &held_runs)
                .expect("production runtime composer");
        let replacement = home.join("runtime-replacement");
        fs::copy("/usr/bin/false", &replacement).expect("replacement native file");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
            .expect("replacement mode");
        fs::rename(replacement, program).expect("replace pinned name");
        // Podman bootstraps the real entry; the payload's program key and held inode stay bound.
        request.argv[0] = "/usr/bin/podman".into();
        let output = run(&request);
        let report = String::from_utf8_lossy(&output.stderr);
        writeln!(std::io::stderr().lock(), "RUNTIME-INSPECTION {report}")
            .expect("inspection observation");
        assert!(!output.status.success(), "image inspection fixture refuses");
        assert!(report.contains("image-identity"), "{report}");
        assert!(
            report.contains(&format!(" exited exit status: {status}: ")),
            "{report}"
        );
        assert_eq!(
            fs::read_to_string(home.join("runtime-inspection")).expect("held program ran"),
            format!("received-image-{status}\n")
        );
        fs::remove_file(home.join("runtime-inspection")).expect("reset execution evidence");
    }
    std::io::Write::write_all(&mut std::io::stdout().lock(), b"RUNTIME-PODMAN-MEASURED\n")
        .expect("measurement marker");
}

/// # Panics
/// Panics if production native creation fails to complete its protected lifetime.
/// ´claim:superlooplane:native-creation-completes-reserve-and-finish´
/// ´test:crate:native-creation-completes-reserve-and-finish´
#[test]
fn native_creation_completes_reserve_and_finish() {
    proof("SUPERLOOP_CREATION_PROOF", "NATIVE-CREATION-MEASURED");
}

/// # Panics
/// Panics if the real private writer loses the reviewed workspace binding.
/// ´test:crate:workspace-native-creation-publishes-the-reviewed-grant´
#[test]
fn workspace_native_creation_publishes_the_reviewed_grant() {
    proof(
        "SUPERLOOP_WORKSPACE_CREATION_PROOF",
        "NATIVE-CREATION-MEASURED",
    );
}

/// # Panics
/// Panics if a production creation receipt, binding or placed home disagrees with its reservation.
pub(super) fn exercise_creation(home: &Path, runs: &Path, program: &Path) {
    let record = helper_service::prepare(home, runs, program);
    let worker = record["plan"]["home"].as_str().expect("worker home");
    let _storage = MappedStorage(home.to_path_buf(), worker.to_owned());
    let output = helper_service::namespace_python(home, STORAGE, worker).expect("mapped storage");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = helper_service::namespace_python(
        home,
        r"
import sys,shutil
from pathlib import Path
home=Path(sys.argv[1]);root=home/'.var/loops/alpha/runs'
for run in ['R','S']:
 (root/f'.reservation-{run}.json').unlink()
 shutil.rmtree(root/run,ignore_errors=True)
 shutil.rmtree(root/f'.launch-{run}',ignore_errors=True)
shutil.rmtree(sys.argv[2])
",
        worker,
    )
    .expect("fresh creation destinations");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (mut request, expected_workspace) = workspace_creation_request(home, runs, program, worker);
    request.argv[0] = "/usr/bin/podman".into();
    let output = run(&request);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("production creation report");
    assert_eq!(
        report["reservation"],
        runs.join(".reservation-R.json").display().to_string()
    );
    let output = helper_service::namespace_python(
        home,
        r"
import sys,tomllib,json
from pathlib import Path
home=Path(sys.argv[1]);root=home/'.var/loops/alpha'
record=json.loads((root/'runs/.reservation-R.json').read_text());identity=record['mail_birth']
assert record['worker_uid']==identity['uid']==3000
assert identity['reservation']=='superloop-lane:R'
config=tomllib.loads((root/'private/.config/mail/loop.toml').read_text())
binding=config['worker_births'][identity['name']]
assert binding['identity']==identity and binding['phase']=='active',binding
receipts=[tomllib.loads(p.read_text()) for p in (root/'.mail-births').glob('*.toml')]
assert len(receipts)==1 and receipts[0]['identity']==identity and not receipts[0]['retired'],receipts
worker=Path(sys.argv[2]);assert (worker/'brief.txt').read_bytes()==(home/'scratchpad/first-letter').read_bytes()
auth=json.loads((worker/'.codex/auth.json').read_text());assert auth['tokens']['refresh_token']==''
assert (root/'workers'/identity['name']/'mail').is_dir()
print('NATIVE-CREATION-MEASURED')
assert json.loads((Path(record['plan']['driver_dir'])/'plan.json').read_text()) == record['plan']
print(json.dumps({k:record['plan'].get(k) for k in ['compute_workspace','compute_placement']}))
",
        worker,
    )
    .expect("read completed native lifetime");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let measured: Value = serde_json::from_str(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .expect("measured plan"),
    )
    .expect("grant observation");
    assert_eq!(
        measured["compute_workspace"], expected_workspace["compute_workspace"],
        "native writer retains exactly the reviewed grant"
    );
    assert_eq!(
        measured["compute_placement"],
        expected_workspace["compute_placement"]
    );
    writeln!(std::io::stdout().lock(), "WORKSPACE-DECLARATION {measured}")
        .expect("production grant marker");
    std::io::Write::write_all(&mut std::io::stdout().lock(), &output.stdout)
        .expect("measurement marker");
}

/// # Panics
/// Panics if the stale private apply publishes an identity or the fixture cannot prepare policy.
fn workspace_creation_request(
    home: &Path,
    runs: &Path,
    program: &Path,
    worker: &str,
) -> (CommandSpec, Value) {
    let expected_workspace = if std::env::var_os("SUPERLOOP_WORKSPACE_CREATION_PROOF").is_some() {
        creation_declaration(home)
    } else {
        Value::Null
    };
    let declaration =
        (!expected_workspace.is_null()).then(|| expected_workspace["declaration"].to_string());
    if let Some(declaration) = declaration.as_deref() {
        let mut stale = creation_request(home, runs, program, Some((declaration, &"0".repeat(64))));
        stale.argv[0] = "/usr/bin/podman".into();
        let refused = run(&stale);
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("workspace-digest"),
            "{}",
            String::from_utf8_lossy(&refused.stderr)
        );
        let unchanged = helper_service::namespace_python(home,"import sys\nfrom pathlib import Path\nh=Path(sys.argv[1]);assert not (h/'.var/loops/alpha/runs/.reservation-R.json').exists();assert not Path(sys.argv[2]).exists();assert not list((h/'.var/loops/alpha/.mail-births').glob('*.toml'))",worker).expect("stale act leaves no identity");
        assert!(
            unchanged.status.success(),
            "{}",
            String::from_utf8_lossy(&unchanged.stderr)
        );
    }
    let request = creation_request(
        home,
        runs,
        program,
        declaration
            .as_deref()
            .map(|text| (text, expected_workspace["digest"].as_str().unwrap())),
    );
    (request, expected_workspace)
}

/// # Panics
/// Panics if the owner's real placement writer cannot prepare the fixture declaration.
fn creation_declaration(home: &Path) -> Value {
    let settings = home.join(".config/loops/alpha/workers.toml");
    let mut source = fs::read_to_string(&settings).expect("existing settings");
    write!(
        source,
        "\nworkspace_policy = {{ quick_policy_digest = {:?}, blacklist_digest = {:?} }}\n",
        "a".repeat(64),
        "b".repeat(64)
    )
    .expect("policy text");
    fs::write(settings, source).expect("owner policy identities");
    let parent = home.join("placement-parent");
    fs::create_dir(&parent).expect("placement parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("private parent");
    let mut grant = crate::plan::fixture_workspace_snapshot()["grant"].clone();
    grant["workspace"] = serde_json::json!(parent.join("R"));
    for (key, child) in [
        ("CARGO_TARGET_DIR", "target"),
        ("CARGO_HOME", "cargo"),
        ("TMPDIR", "tmp"),
    ] {
        grant["baseline_env"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!([key, parent.join("R").join(child)]));
    }
    let input =
        serde_json::json!({"grant":grant,"baseline_environment_is_public":true}).to_string();
    let preview = crate::placement::commands::prepare(&parent, &input, None, true)
        .expect("placement preview");
    let result = crate::placement::commands::prepare(
        &parent,
        &input,
        preview["preview_sha256"].as_str(),
        false,
    )
    .expect("owner placement writer");
    let declaration = result["declaration"].clone();
    let snapshot =
        crate::launch::workspace::declaration(&declaration.to_string()).expect("declared grant");
    serde_json::json!({"compute_workspace":snapshot,"compute_placement":declaration["compute_placement"],"declaration":declaration,"digest":result["workspace_declaration_digest"]})
}

/// # Panics
/// Panics if the production creation bundle cannot pin the fixture inputs.
fn creation_request(
    home: &Path,
    runs: &Path,
    program: &Path,
    workspace: Option<(&str, &str)>,
) -> CommandSpec {
    let image = binary();
    let letter = home.join("scratchpad/first-letter");
    let held_home = fs::File::open(home).expect("home descriptor").into();
    let held_runs = fs::File::open(runs).expect("runs descriptor").into();
    let letter_dir = letter.parent().expect("letter directory");
    let held_letter = fs::File::open(letter_dir)
        .expect("letter descriptor")
        .into();
    let mut argv = vec![
        "unshare".into(),
        image.display().to_string(),
        "_make-home".into(),
        "alpha".into(),
        "R".into(),
        "--letter".into(),
        letter.display().to_string(),
        "--owner-home".into(),
        home.display().to_string(),
        "--worker-uid".into(),
        "3000".into(),
        "--podman-bin".into(),
        program.display().to_string(),
        "--model".into(),
        "gpt-6-sol".into(),
        "--effort".into(),
        "high".into(),
        "--model-source".into(),
        "launch-flag".into(),
        "--effort-source".into(),
        "launch-flag".into(),
        "--door-scope".into(),
        "work".into(),
        "--backend".into(),
        "codex".into(),
        "--observe".into(),
    ];
    if let Some((declaration, digest)) = workspace {
        argv.splice(
            argv.len() - 1..argv.len() - 1,
            [
                "--compute-workspace".into(),
                declaration.into(),
                "--workspace-digest".into(),
                digest.into(),
            ],
        );
    }
    crate::creation_entry::command(
        program,
        &argv,
        (home, &held_home),
        (runs, &held_runs),
        (letter_dir, &held_letter),
        None,
    )
    .expect("production creation composer")
}
