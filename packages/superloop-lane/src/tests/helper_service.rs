//! Production helper service acceptance under the rootless namespace.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// # Panics
/// Panics if the production helper loses the reserved runtime or its authority thread.
/// ´claim:superlooplane:helper-service-executes-received-runtime´
/// ´claim:superlooplane:helper-service-refreshes-live-credentials´
/// ´test:crate:helper-service-executes-received-runtime´
#[test]
fn helper_service_executes_received_runtime() {
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "tests::launch::proxy_refresh_preserves_live_helper_pins",
            "--nocapture",
        ])
        .env("SUPERLOOP_SERVICE_PROOF", "1")
        .env("SUPERLOOP_REFRESH_PROOF", "1")
        .env("_CONTAINERS_USERNS_CONFIGURED", "1")
        .env(
            "_CONTAINERS_ROOTLESS_UID",
            nix::unistd::Uid::effective().as_raw().to_string(),
        )
        .output()
        .expect("complete service fixture");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("HELPER-SERVICE-MEASURED"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

/// # Panics
/// Panics if the real receiver or service refuses the complete namespace fixture.
/// ´test:crate:namespace-service-entry´
#[test]
fn namespace_service_entry() {
    let Ok(source) = std::env::var("HELPER_SERVICE_VECTOR") else {
        return;
    };
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
    let overflow: u32 = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .expect("overflow uid")
        .trim()
        .parse()
        .expect("overflow number");
    assert_eq!(fs::metadata("/").expect("namespace root").uid(), overflow);
    let refusal = loop_home::ancestor::Owners::current(0)
        .expect("live namespace map")
        .check(overflow)
        .expect_err("overflow-owned root grants no authority");
    assert!(
        refusal.contains("unmapped or ambiguous ancestor uid"),
        "{refusal}"
    );
    let endpoint = std::env::var("HELPER_SERVICE_ENDPOINT").expect("fixture refresh endpoint");
    assert!(
        endpoint.starts_with("http://127.0.0.1:"),
        "fixture endpoint stays on loopback"
    );
    let _endpoint = crate::credential::fixture_service_endpoint(endpoint);
    let args: Vec<String> = serde_json::from_str(&source).expect("private entry vector");
    assert_eq!(
        crate::container_entry::serve(&args).expect("production helper entry and service"),
        0
    );
    writeln!(std::io::stdout().lock(), "HELPER-SERVICE-ENTRY-END").expect("entry marker");
}

struct FixtureChild(Option<Child>);
impl Drop for FixtureChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            drop(child.kill());
            drop(child.wait());
        }
    }
}
impl FixtureChild {
    /// # Panics
    /// Panics if a fixture child cannot finish within its bounded measurement.
    fn finish(mut self) -> Output {
        let began = Instant::now();
        let child = self.0.as_mut().expect("live child");
        while child.try_wait().expect("child status").is_none() {
            assert!(
                began.elapsed() < Duration::from_secs(60),
                "fixture child exceeded bound"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        self.0
            .take()
            .expect("completed child")
            .wait_with_output()
            .expect("child output")
    }
}

/// Run mapped fixture setup or cleanup.
///
/// # Errors
/// Returns a namespace command spawn or collection error.
pub(super) fn namespace_python(home: &Path, script: &str, worker: &str) -> std::io::Result<Output> {
    Command::new("/usr/bin/podman")
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", script])
        .arg(home)
        .arg(worker)
        .output()
}

struct MappedWorker {
    home: PathBuf,
    worker: String,
}
impl Drop for MappedWorker {
    fn drop(&mut self) {
        drop(namespace_python(
            &self.home,
            "import shutil,sys\nshutil.rmtree(sys.argv[2], ignore_errors=True)\n",
            &self.worker,
        ));
    }
}

// Synthetic credentials expire relative to the fixture clock; no token or signature is real.
const SETUP: &str = r"
import os,sys,tomllib,base64,json,time,datetime
from pathlib import Path
home=Path(sys.argv[1])
gid=tomllib.loads((home/'.config/loops/registry.toml').read_text())['loops'][0]['uid']
os.chown(home/'.var/loops/alpha/runner-templates/codex'/('a'*64)/'libexec/ssh',0,gid)
for name in ['passwd','group']:
 os.chown(home/'.var/loops/alpha/runs/.launch-R'/name,0,gid)
p=Path(sys.argv[2])
p.mkdir(exist_ok=True)
(p/'.codex').mkdir(exist_ok=True)
for path,uid in [(p,0),(p/'.codex',3000)]:
 os.chown(path,uid,uid)
 os.chmod(path,0o700)
expiry=int(time.time())+86400
payload=base64.urlsafe_b64encode(json.dumps({'exp':expiry}).encode()).decode().rstrip('=')
token='header.'+payload+'.signature'
tokens={'id_token':token,'access_token':token,
        'refresh_token':'fixture-service-refresh','account_id':'fixture-account'}
refreshed=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
source={'auth_mode':'chatgpt','OPENAI_API_KEY':None,'tokens':tokens,'last_refresh':refreshed}
auth=home/'.config/loops/alpha/lanes/codex/auth.json'
auth.write_text(json.dumps(source))
os.chmod(auth,0o600)
";

/// # Panics
/// Panics if the helper fixture cannot publish its source and mapped worker directory.
pub(super) fn prepare(home: &Path, runs: &Path, podman: &Path) -> Value {
    let path = runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("reservation")).expect("record");
    record["phase"] = json!("preparing");
    record["active_round"] = json!("dispatch");
    record["rounds"] = json!([{"step":"dispatch","budget_seconds":3600}]);
    crate::launch::publish_reservation(&path, &record).expect("preparing reservation");
    for path in [
        home.parent().expect("fixture root").to_path_buf(),
        home.to_path_buf(),
        home.join(".var"),
        home.join(".var/loops"),
        home.join(".var/loops/alpha"),
        runs.to_path_buf(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o711)).expect("loop traversal");
    }
    fs::create_dir_all(runs.join("R")).expect("driver directory");
    for path in [
        home.join(".config/loops/alpha/lanes"),
        home.join(".config/loops/alpha/lanes/codex"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("source ancestry");
    }
    let worker = record["plan"]["home"].as_str().expect("worker home");
    let output = namespace_python(home, SETUP, worker).expect("mapped fixture operation");
    assert!(
        output.status.success(),
        "unmeasured mapped fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::copy("/bin/sh", podman).expect("native shell runtime fixture");
    fs::set_permissions(podman, fs::Permissions::from_mode(0o700)).expect("native runtime mode");
    // Same image-inspect fixture answer as the shared launch fixture; only the executable form changes.
    fs::write(
        home.join("image"),
        format!("printf '%s\\n' '{}'\n", "a".repeat(64)),
    )
    .expect("image script");
    fs::write(home.join("run"), "printf 'received-runtime\\n'\nexit 23\n").expect("attempt script");
    for name in ["ps", "container", "stop", "wait", "rm"] {
        fs::write(home.join(name), "exit 0\n").expect("empty container inventory");
    }
    record
}

/// # Panics
/// Panics if the production composer or namespace process cannot start.
fn start(home: &Path, runs: &Path, podman: &Path, endpoint: &str) -> FixtureChild {
    let image = std::env::current_exe().expect("entry image");
    let held_home = fs::File::open(home).expect("home descriptor").into();
    let held_runs = fs::File::open(runs).expect("runs descriptor").into();
    let bundle = crate::container_entry::pin(
        "alpha",
        (home, &held_home),
        (runs, &held_runs),
        &image,
        podman,
        crate::settings::BoxBackend::Codex,
    )
    .expect("production composer");
    let replacement = home.join("replaced-runtime");
    fs::copy("/usr/bin/false", &replacement).expect("replacement native program");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    fs::rename(replacement, podman).expect("replace selected runtime pathname");
    let args = vec![
        "_container-helper".to_owned(),
        "--run-dir".into(),
        runs.join("R").display().to_string(),
        "--owner-home".into(),
        home.display().to_string(),
        "--verified-home-fd".into(),
        "0".into(),
        "--verified-runs-root".into(),
        runs.display().to_string(),
        "--verified-runs-root-fd".into(),
        "1".into(),
        "--anchor-manifest".into(),
        bundle.manifest,
    ];
    let (sender, input) = UnixStream::pair().expect("rights channel");
    let input: std::os::fd::OwnedFd = input.into();
    let child = Command::new("/usr/bin/podman")
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .arg("unshare")
        .arg(image)
        .args([
            "--exact",
            "tests::helper_service::namespace_service_entry",
            "--nocapture",
        ])
        .env("HOME", home)
        .env("HELPER_SERVICE_ENDPOINT", endpoint)
        .env(
            "HELPER_SERVICE_VECTOR",
            serde_json::to_string(&args).expect("vector"),
        )
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("real rootless namespace entry");
    let child = FixtureChild(Some(child));
    loop_home::anchor::transport::send(&sender, &bundle.descriptors)
        .expect("complete capability frame");
    child
}

/// # Panics
/// Panics if the loop peer cannot exchange a prompt and status with the real service.
fn exchange(home: &Path, runs: &Path, loop_uid: u32) -> Output {
    let script = r"
import os,socket,struct,sys,time
from pathlib import Path
p=Path(sys.argv[1]); deadline=time.monotonic()+30
while not (p/'client-ready').exists():
 assert time.monotonic()<deadline
 time.sleep(.01)
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[2]);s.sendall(struct.pack('<I',0))
def read(n):
 b=b''
 while len(b)<n:
  q=s.recv(n-len(b));assert q;b+=q
 return b
while True:
 h=read(5);b=read(struct.unpack('<I',h[1:])[0])
 if h[:1]==b'X':
  print('STATUS',struct.unpack('<i',b)[0]);break
 print('FRAME',h[:1].decode(),b.decode(),flush=True)
";
    let uid = loop_uid.to_string();
    let client = Command::new("/usr/bin/podman")
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .args([
            "unshare",
            "/usr/bin/setpriv",
            "--reuid",
            &uid,
            "--regid",
            &uid,
            "--clear-groups",
            "/usr/bin/python3",
            "-I",
            "-c",
            script,
        ])
        .arg(home)
        .arg(crate::container_helper::socket_path(&runs.join("R")).expect("socket"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("mapped loop peer");
    let pid = client.id();
    let client = FixtureChild(Some(client));
    let path = runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("helper record")).expect("record JSON");
    record["driver_entry_pid"] = json!(pid);
    record["driver_entry_start"] =
        json!(crate::container_helper::process_start(pid).expect("driver start"));
    crate::launch::publish_reservation(&path, &record).expect("authorized driver identity");
    fs::write(home.join("client-ready"), b"ready").expect("release peer");
    client.finish()
}

/// # Panics
/// Panics if the synthetic source cannot supply one loopback refresh response.
fn namespace_refresh_endpoint(home: &Path) -> (String, std::thread::JoinHandle<Value>, String) {
    let original: Value = serde_json::from_slice(
        &fs::read(home.join(".config/loops/alpha/lanes/codex/auth.json")).expect("source"),
    )
    .expect("source JSON");
    let token = original["tokens"]["access_token"]
        .as_str()
        .expect("synthetic token");
    let rotated = format!("{}.refreshed", token.rsplit_once('.').expect("JWT shape").0);
    let (endpoint, refresh) = crate::credential::fixture_refresh_endpoint(json!({
        "id_token":rotated,"access_token":rotated,"refresh_token":"namespace-service-rotated",
    }));
    (endpoint, refresh, rotated)
}

/// # Panics
/// Panics if the service's real periodic authority does not refresh and publish its live worker.
fn refresh_namespace_authority(
    home: &Path,
    runs: &Path,
    worker: &str,
    evidence: &Path,
    rotated: &str,
) {
    let generation = fs::metadata(evidence)
        .expect("first evidence generation")
        .ino();
    let path = runs.join(".reservation-R.json");
    let mut record: Value =
        serde_json::from_slice(&fs::read(&path).expect("record")).expect("record JSON");
    record["phase"] = json!("started");
    crate::launch::publish_reservation(&path, &record).expect("live reservation for refresh");
    let output = namespace_python(
        home,
        r"
import sys,json,time,base64
from pathlib import Path
p=Path(sys.argv[1])/'.config/loops/alpha/lanes/codex/auth.json'
s=json.loads(p.read_text())
claims=json.dumps({'exp':int(time.time())+300}).encode()
payload=base64.urlsafe_b64encode(claims).decode().rstrip('=')
for field in ['id_token','access_token']: s['tokens'][field]='header.'+payload+'.due'
p.write_text(json.dumps(s))
",
        worker,
    )
    .expect("make synthetic authority due");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let began = Instant::now();
    while fs::metadata(evidence).expect("authority generation").ino() == generation {
        assert!(
            began.elapsed() < Duration::from_secs(90),
            "namespace refresh remains unmeasured"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let observed: Value = serde_json::from_slice(&fs::read(evidence).expect("refresh evidence"))
        .expect("evidence JSON");
    assert_eq!(observed["state"], "published", "{observed}");
    assert_eq!(observed["run_refusals"], json!([]), "{observed}");
    let source: Value = serde_json::from_slice(
        &fs::read(home.join(".config/loops/alpha/lanes/codex/auth.json")).expect("rotated source"),
    )
    .expect("source JSON");
    assert_eq!(
        source["tokens"]["refresh_token"],
        "namespace-service-rotated"
    );
    assert_eq!(source["tokens"]["access_token"], rotated);
    assert!(
        source["last_refresh"]
            .as_str()
            .expect("held clock output")
            .ends_with('Z')
    );
    let output = namespace_python(
        home,
        "import sys
from pathlib import Path
print((Path(sys.argv[2])/'.codex/auth.json').read_text())
",
        worker,
    )
    .expect("read mapped worker publication");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let published: Value = serde_json::from_slice(&output.stdout).expect("worker auth JSON");
    assert_eq!(published["tokens"]["access_token"], rotated);
    assert_eq!(published["tokens"]["refresh_token"], "");
}

/// # Panics
/// Panics if the complete service does not execute its held runtime and publish authority evidence.
pub(super) fn exercise(home: &Path, runs: &Path, podman: &Path) {
    let record = prepare(home, runs, podman);
    let worker = record["plan"]["home"].as_str().expect("worker home");
    let _cleanup = MappedWorker {
        home: home.to_path_buf(),
        worker: worker.to_owned(),
    };
    let loop_uid = crate::plan::loop_uid(&record["plan"]).expect("loop uid");
    let (endpoint, refresh, rotated) = namespace_refresh_endpoint(home);
    let mut child = start(home, runs, podman, &endpoint);
    let evidence = crate::plan::protected_identity_dir(&runs.join("R"))
        .expect("protected root")
        .join("credential-refresh.json");
    let began = Instant::now();
    while !evidence.exists() {
        if child
            .0
            .as_mut()
            .expect("helper")
            .try_wait()
            .expect("helper status")
            .is_some()
        {
            let output = child.finish();
            panic!(
                "helper before readiness: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            began.elapsed() < Duration::from_secs(45),
            "service readiness exceeded bound"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let observed: Value = serde_json::from_slice(&fs::read(&evidence).expect("authority evidence"))
        .expect("evidence JSON");
    assert_eq!(observed["state"], "current");
    refresh_namespace_authority(home, runs, worker, &evidence, &rotated);
    let request = refresh.join().expect("namespace refresh request");
    assert_eq!(request["grant_type"], "refresh_token");
    assert_eq!(request["refresh_token"], "fixture-service-refresh");
    let client = exchange(home, runs, loop_uid);
    if !client.status.success() {
        let control =
            crate::container_helper::control_socket_path(&runs.join("R")).expect("control");
        if let Ok(mut stream) = UnixStream::connect(control) {
            drop(stream.write_all(b"C"));
        }
    }
    let helper = child.finish();
    assert!(
        client.status.success(),
        "client: {} helper: {}{}",
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&helper.stdout),
        String::from_utf8_lossy(&helper.stderr)
    );
    let output = String::from_utf8_lossy(&client.stdout);
    assert!(output.contains("received-runtime"), "{output}");
    assert!(output.contains("STATUS 23"), "{output}");
    assert!(
        helper.status.success(),
        "{}{}",
        String::from_utf8_lossy(&helper.stdout),
        String::from_utf8_lossy(&helper.stderr)
    );
    assert!(String::from_utf8_lossy(&helper.stdout).contains("HELPER-SERVICE-ENTRY-END"));
    let protected = crate::plan::protected_identity_dir(&runs.join("R")).expect("protected root");
    for path in [
        protected.join("container-attempt-1.status.json"),
        runs.join("R/container-attempt-1.status.json"),
    ] {
        let bytes = fs::read(path).expect("attempt evidence");
        let status: Value = serde_json::from_slice(&bytes).expect("status JSON");
        assert_eq!(status["status"], 23);
    }
    let cleanup = namespace_python(
        home,
        "import shutil,sys\nshutil.rmtree(sys.argv[2])\n",
        worker,
    )
    .expect("mapped cleanup");
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    writeln!(std::io::stdout().lock(), "HELPER-SERVICE-MEASURED").expect("service marker");
}

/// ´test:crate:built-helper-resume-retains-mail-custody´
#[test]
fn built_helper_resume_retains_mail_custody() {
    built_round_fixture(false);
}

/// ´test:crate:built-round-rollback-cleanup-retains-custody´
#[test]
fn built_round_rollback_cleanup_retains_custody() {
    built_round_fixture(true);
}

fn built_round_fixture(rollback: bool) {
    let workspace = super::published_workspace();
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "tests::launch::proxy_refresh_preserves_live_helper_pins",
            "--nocapture",
        ])
        .env("SUPERLOOP_ROUND_PROOF", "1")
        .env("SUPERLOOP_ROLLBACK_PROOF", if rollback { "1" } else { "0" })
        .env("SUPERLOOP_ROUND_WORKSPACE", workspace.to_string())
        .env(
            "SUPERLOOP_ROUND_PLACEMENT",
            super::published_placement().to_string(),
        )
        .env("SUPERLOOP_REFRESH_PROOF", "1")
        .env("_CONTAINERS_USERNS_CONFIGURED", "1")
        .env(
            "_CONTAINERS_ROOTLESS_UID",
            nix::unistd::Uid::effective().as_raw().to_string(),
        )
        .output()
        .expect("round fixture");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8_lossy(&output.stdout);
    if rollback {
        assert!(output.contains("ROLLBACK-PRIVATE-CLEANUP"), "{output}");
    }
    for marker in [
        "FIRST-HELPER-READY",
        "RESUMED-HELPER-READY",
        "PREVIOUS-SOURCES-NOT-READ",
        "ROUND-PREFLIGHT-READONLY",
        "PUBLICATION-PREFLIGHT-READONLY",
        "INSPECTION-REFUSALS-READONLY",
    ] {
        assert!(output.contains(marker), "{output}");
    }
}

fn built_helper(home: &Path, runs: &Path, podman: &Path, preflight: bool) -> FixtureChild {
    let binary = std::env::current_exe()
        .expect("test image")
        .ancestors()
        .map(|path| path.join("superloop-lane"))
        .find(|path| path.is_file())
        .expect("build package binary before acceptance");
    let own = fs::File::open(home).expect("home").into();
    let storage = fs::File::open(runs).expect("runs").into();
    let bundle = crate::container_entry::pin(
        "alpha",
        (home, &own),
        (runs, &storage),
        &binary,
        podman,
        crate::settings::BoxBackend::Codex,
    )
    .expect("held bundle");
    let mut args = vec![
        "_container-helper".to_owned(),
        "--run-dir".into(),
        runs.join("R").display().to_string(),
        "--owner-home".into(),
        home.display().to_string(),
        "--verified-home-fd".into(),
        "0".into(),
        "--verified-runs-root".into(),
        runs.display().to_string(),
        "--verified-runs-root-fd".into(),
        "1".into(),
        "--anchor-manifest".into(),
        bundle.manifest,
    ];
    if preflight {
        args.extend([
            "--preflight-round".into(),
            "review".into(),
            "--budget".into(),
            "3600".into(),
        ]);
    }
    let (sender, input) = UnixStream::pair().expect("rights");
    let child = Command::new("/usr/bin/podman")
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .arg("unshare")
        .arg(binary)
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(input)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("built helper");
    let child = FixtureChild(Some(child));
    loop_home::anchor::transport::send(&sender, &bundle.descriptors).expect("send held bundle");
    child
}

fn ready_and_stop(mut child: FixtureChild, runs: &Path, marker: &str) {
    let control = crate::container_helper::control_socket_path(&runs.join("R")).expect("control");
    let socket = crate::container_helper::socket_path(&runs.join("R")).expect("client");
    let start = Instant::now();
    while !control.exists() || !socket.exists() {
        if child
            .0
            .as_mut()
            .expect("child")
            .try_wait()
            .expect("status")
            .is_some()
        {
            let output = child.finish();
            panic!(
                "{marker}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            start.elapsed() < Duration::from_secs(45),
            "{marker}: readiness deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = UnixStream::connect(&control).expect("control connect");
    stream.write_all(b"C").expect("cancel helper");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("ack bound");
    let mut ack = [0];
    stream.read_exact(&mut ack).expect("cancel acknowledgement");
    assert_eq!(&ack, b"K");
    drop(stream);
    let output = child.finish();
    assert!(
        output.status.success(),
        "{marker}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !control.exists() && !socket.exists(),
        "helper removed its sockets"
    );
    writeln!(std::io::stdout().lock(), "{marker}").expect("readiness marker");
}

struct RoundOwner<'a> {
    home: &'a Path,
    run: PathBuf,
    identity: (u64, u64),
    template_directories: [fs::File; 3],
}
impl Drop for RoundOwner<'_> {
    fn drop(&mut self) {
        // TempDir cannot unlink children of the fixture's read-only templates.
        // These descriptors were opened while creating this fixture, not from output.
        for directory in &self.template_directories {
            directory
                .set_permissions(fs::Permissions::from_mode(0o700))
                .expect("restore fixture directory write permission");
        }
        let input =
            json!({"run":self.run,"device":self.identity.0,"inode":self.identity.1}).to_string();
        let output = namespace_python(
            self.home,
            r"
import os,json,sys
v=json.loads(sys.argv[2]);fd=os.open(v['run'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
s=os.fstat(fd)
assert (s.st_dev,s.st_ino)==(v['device'],v['inode'])
for name in ['mail-review.txt','launch']:
 try: os.chown(name,0,0,dir_fd=fd,follow_symlinks=False)
 except FileNotFoundError: pass
try:
 child=os.open('fixture-dispatch',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
except FileNotFoundError: pass
else:
 for name in ['events.jsonl','.event-start']:
  try: os.chown(name,0,0,dir_fd=child,follow_symlinks=False)
  except FileNotFoundError: pass
 os.fchown(child,0,0);os.close(child)
os.fchown(fd,0,0)
",
            &input,
        )
        .expect("restore mapped fixture owner");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn template_directories(home: &Path) -> [fs::File; 3] {
    let template = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64));
    ["", "bin", "libexec"].map(|name| {
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(template.join(name))
            .expect("created template directory");
        let metadata = directory.metadata().expect("held template metadata");
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
        directory
    })
}

/// Publish the fixture reservation with the supplied grant and placement.
///
/// # Panics
/// Panics if either declaration is absent or malformed, or publication fails.
fn publish_declared(runs: &Path, record: &mut Value) {
    record["plan"]["compute_workspace"] = serde_json::from_str(
        &std::env::var("SUPERLOOP_ROUND_WORKSPACE").expect("production declaration supplied"),
    )
    .expect("grant");
    record["plan"]["compute_placement"] = serde_json::from_str(
        &std::env::var("SUPERLOOP_ROUND_PLACEMENT").expect("placement supplied"),
    )
    .unwrap();
    crate::launch::publish_reservation(&runs.join(".reservation-R.json"), record)
        .expect("declaration retained for helper");
}

/// # Panics
/// Panics if the built helper refuses the correctly provisioned synthetic rounds.
pub(super) fn rounds_acceptance(home: &Path, runs: &Path, podman: &Path) {
    let mut record = prepare(home, runs, podman);
    publish_declared(runs, &mut record);
    let _worker = MappedWorker {
        home: home.to_path_buf(),
        worker: record["plan"]["home"].as_str().expect("worker").into(),
    };
    let run = runs.join("R");
    let metadata = fs::metadata(&run).expect("run");
    let _owner = RoundOwner {
        home,
        run: run.clone(),
        identity: (metadata.dev(), metadata.ino()),
        template_directories: template_directories(home),
    };
    let uid = crate::plan::loop_uid(&record["plan"]).expect("loop uid");
    let input = json!({"run":run,"uid":uid}).to_string();
    let output = namespace_python(
        home,
        r"
import os,json,sys
v=json.loads(sys.argv[2]);os.chown(v['run'],v['uid'],v['uid']);os.chmod(v['run'],0o700)
s=os.stat(v['run']);p=os.stat(os.path.dirname(v['run']))
assert s.st_uid==v['uid'] and p.st_uid==0 and s.st_uid!=p.st_uid
assert s.st_mode&0o7777==0o700 and p.st_mode&0o7777==0o711
d=os.path.join(v['run'],'launch');os.makedirs(d,exist_ok=True)
os.chmod(d,0o700);os.chown(d,v['uid'],v['uid'])
f=os.path.join(d,'runtime.env')
with open(f,'wb') as out: out.write(b'SUPERLOOP_CLIENT_ROOT_DEV=1\0SUPERLOOP_CLIENT_ROOT_INO=2\0')
os.chown(f,0,v['uid']);os.chmod(f,0o440)
",
        &input,
    )
    .expect("two uid layout");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    ready_and_stop(
        built_helper(home, runs, podman, false),
        runs,
        "FIRST-HELPER-READY",
    );
    record["phase"] = json!("settled");
    record["thread_id"] = json!("fixture-thread");
    record["rounds"][0]["phase"] = json!("settled");
    record["rounds"][0]["driver_dir"] = json!(run.join("fixture-dispatch"));
    let bytes = b"Continue the synthetic round.\n";
    let path = run.join("mail-review.txt");
    let input = json!({"run":run,"uid":uid,"text":String::from_utf8_lossy(bytes)}).to_string();
    let output = namespace_python(
        home,
        r"
import os,json,sys
from pathlib import Path
v=json.loads(sys.argv[2]);p=Path(v['run'])/'mail-review.txt'
p.write_text(v['text']);p.chmod(0o600);os.chown(p,v['uid'],v['uid'])
",
        &input,
    )
    .expect("retained mail");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    record["mail"] = json!([{"step":"review","worker_uid":record["worker_uid"],"bytes":bytes.len(),
        "evidence_digest":crate::build::sha256_bytes(bytes,home).expect("digest")}]);
    let reservation = runs.join(".reservation-R.json");
    crate::launch::publish_reservation(&reservation, &record).expect("settled binding");
    let settled = record.clone();
    check_previous_sources(home, runs, podman, &settled);
    record["phase"] = json!("preparing");
    record["active_round"] = json!("review");
    record["letter_source"] = json!(path);
    record["rounds"]
        .as_array_mut()
        .expect("rounds")
        .push(json!({"step":"review","phase":"preparing"}));
    crate::launch::publish_reservation(&reservation, &record).expect("resume input");
    ready_and_stop(
        built_helper(home, runs, podman, false),
        runs,
        "RESUMED-HELPER-READY",
    );
    check_round_previews(home, runs, podman, &settled, uid);
    check_publication_previews(home, runs, podman, &settled, uid);
    check_built_inspection(home, runs, &settled, uid);
    if std::env::var("SUPERLOOP_ROLLBACK_PROOF").as_deref() == Ok("1") {
        check_rollback_cleanup(home, runs, podman, &settled, uid);
    }
}

fn check_previous_sources(home: &Path, runs: &Path, podman: &Path, settled: &Value) {
    let dispatch = PathBuf::from(settled["letter_source"].as_str().expect("dispatch source"));
    let original = fs::read(&dispatch).expect("fixture dispatch letter");
    let reservation = runs.join(".reservation-R.json");
    for case in ["dispatch-altered", "dispatch-removed", "rotation", "later"] {
        let mut prior = settled.clone();
        if case == "dispatch-altered" {
            fs::write(&dispatch, b"Model: deliberately-invalid\nEffort: invalid\n")
                .expect("alter fixture dispatch");
        } else if case == "dispatch-removed" {
            fs::remove_file(&dispatch).expect("remove fixture dispatch");
        } else if case == "rotation" {
            prior["rotation_source_sha256"] = json!("f".repeat(64));
            let brief =
                Path::new(prior["plan"]["home"].as_str().expect("worker home")).join("brief.txt");
            assert!(!brief.exists(), "preceding rotation brief is absent");
            prior["letter_source"] = json!(brief);
        } else {
            prior["active_round"] = json!("previous");
            let mut previous = prior["rounds"][0].clone();
            previous["step"] = json!("previous");
            prior["rounds"]
                .as_array_mut()
                .expect("prior rounds")
                .push(previous);
            let mut previous_binding = prior["mail"][0].clone();
            previous_binding["step"] = json!("previous");
            prior["mail"]
                .as_array_mut()
                .expect("mail history")
                .push(previous_binding);
            prior["letter_source"] = json!(runs.join("R/mail-previous.txt"));
        }
        crate::launch::publish_reservation(&reservation, &prior).expect("prior reservation");
        let before = publication_inventory(home, runs);
        let output = built_helper(home, runs, podman, true).finish();
        assert!(
            output.status.success(),
            "{case} preview: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("real preflight report");
        assert_eq!(report["state"], "passed", "{case}: {report}");
        assert_eq!(
            publication_inventory(home, runs),
            before,
            "{case}: read only"
        );
        let mut next =
            crate::launch::rounds::preflight_record(&runs.join("R"), &prior, "review", 3600)
                .expect("prospective record");
        assert_eq!(
            next["plan"]["compute_placement"],
            settled["plan"]["compute_placement"]
        );
        next["launcher_pid"] = settled["launcher_pid"].clone();
        next["launcher_start"] = settled["launcher_start"].clone();
        assert_eq!(
            next["plan"]["compute_workspace"],
            settled["plan"]["compute_workspace"]
        );
        crate::launch::publish_reservation(&reservation, &next).expect("published next round");
        ready_and_stop(built_helper(home, runs, podman, false), runs, case);
    }
    fs::write(&dispatch, original).expect("restore fixture dispatch");
    crate::launch::publish_reservation(&reservation, settled).expect("restore settled fixture");
    writeln!(std::io::stdout().lock(), "PREVIOUS-SOURCES-NOT-READ").expect("source marker");
}

fn check_preflight_report(bytes: &[u8], record: &Value) {
    let preview: Value = serde_json::from_slice(bytes).expect("preview JSON");
    assert_eq!(preview["state"], "passed");
    assert!(
        preview["checked"]
            .as_array()
            .expect("checked inputs")
            .contains(&json!(
                "saved runtime environment and unoccupied final round-request name"
            )),
        "preflight limits occupancy claim to final name: {preview}"
    );
    assert!(
        preview["not_checked"]
            .as_array()
            .expect("unchecked window")
            .contains(&json!(
                "every step after the preparing reservation is published"
            )),
        "preflight names whole publication window: {preview}"
    );
    assert!(
        preview["not_checked"]
            .as_array()
            .expect("unchecked inputs")
            .contains(&json!(
                "busy lease, scope admission and preparing-record size before publication"
            )),
        "preflight leaves final preparing-record size to apply: {preview}"
    );
    assert!(
        record["plan"]["compute_workspace"].is_object(),
        "real declaration reaches helper preflight"
    );
}

fn check_round_previews(home: &Path, runs: &Path, podman: &Path, record: &Value, uid: u32) {
    let run = runs.join("R");
    let reservation = runs.join(".reservation-R.json");
    let bytes = b"Continue the synthetic round.\n";
    crate::launch::publish_reservation(&reservation, record).expect("settled before preview");
    let before = fs::read(&reservation).expect("before preview");
    let credential = runs.join(".launch-R/credential-refresh.json");
    let evidence = (
        fs::metadata(&credential).expect("evidence inode").ino(),
        fs::read(&credential).expect("evidence bytes"),
    );
    let output = built_helper(home, runs, podman, true).finish();
    assert!(
        output.status.success(),
        "preview: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    check_preflight_report(&output.stdout, record);
    assert_eq!(fs::read(&reservation).expect("after preview"), before);
    assert!(!run.join("round-launch-review.json").exists());
    writeln!(std::io::stdout().lock(), "ROUND-PREFLIGHT-READONLY").expect("preview marker");
    assert_eq!(
        (
            fs::metadata(&credential).expect("same inode").ino(),
            fs::read(&credential).expect("same evidence")
        ),
        evidence
    );
    for (change, text) in [
        (
            "bytes",
            "retained evidence differs from active mail binding",
        ),
        ("owner", "evidence custody differs"),
        ("directory-owner", "loop directory uid"),
    ] {
        let input = json!({"run":run,"uid":uid,"change":change}).to_string();
        let output = namespace_python(
            home,
            r"
import os,json,sys
from pathlib import Path
v=json.loads(sys.argv[2]);p=Path(v['run'])/'mail-review.txt'
if v['change']=='bytes': p.write_text('changed synthetic letter')
elif v['change']=='directory-owner': os.chown(p.parent,3001,3001)
else: os.chown(p,3001,3001)
",
            &input,
        )
        .expect("change retained source");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let inventory = publication_inventory(home, runs);
        let output = built_helper(home, runs, podman, true).finish();
        assert_eq!(
            publication_inventory(home, runs),
            inventory,
            "bad {change}: no writes"
        );
        assert_eq!(output.status.code(), Some(2), "bad {change} preview passed");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(text),
            "{change}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(&reservation).expect("refused preview unchanged"),
            before
        );
        let input = json!({"run":run,"uid":uid,"text":String::from_utf8_lossy(bytes)}).to_string();
        let output = namespace_python(
            home,
            r"
import os,json,sys
from pathlib import Path
v=json.loads(sys.argv[2]);p=Path(v['run'])/'mail-review.txt'
p.write_text(v['text']);os.chown(p,v['uid'],v['uid']);os.chown(p.parent,v['uid'],v['uid'])
",
            &input,
        )
        .expect("restore retained source");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn check_publication_previews(home: &Path, runs: &Path, podman: &Path, record: &Value, uid: u32) {
    let reservation = runs.join(".reservation-R.json");
    for (case, expected) in [
        ("binding", "active mail binding absent"),
        ("runtime", "saved client environment is invalid"),
        (
            "runtime-owner",
            "saved client environment has foreign ownership",
        ),
        ("occupied", "round-launch-review.json already exists"),
        ("state", "preflight requires an unused settled round"),
    ] {
        let mut input = record.clone();
        if case == "binding" {
            input["mail"] = json!([]);
        }
        if case == "state" {
            input["phase"] = json!("failed");
        }
        crate::launch::publish_reservation(&reservation, &input).expect("case reservation");
        let setup = json!({"run":runs.join("R"),"uid":uid,"case":case}).to_string();
        let prepared = namespace_python(
            home,
            r"
import os,json,sys
from pathlib import Path
v=json.loads(sys.argv[2]);d=Path(v['run']);p=d/'launch/runtime.env'
p.write_bytes(b'SUPERLOOP_CLIENT_ROOT_DEV=1\0SUPERLOOP_CLIENT_ROOT_INO=2\0')
os.chown(p,0,v['uid']);p.chmod(0o440)
if v['case']=='runtime': p.write_bytes(b'invalid')
if v['case']=='runtime-owner': os.chown(p,v['uid'],v['uid'])
if v['case']=='occupied': (d/'round-launch-review.json').write_bytes(b'existing request')
",
            &setup,
        )
        .expect("prepare publication refusal");
        assert!(prepared.status.success(), "{prepared:?}");
        let before = publication_inventory(home, runs);
        let output = built_helper(home, runs, podman, true).finish();
        assert_eq!(output.status.code(), Some(2), "{case}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{case}: {output:?}"
        );
        assert_eq!(
            publication_inventory(home, runs),
            before,
            "{case}: no publication on refusal"
        );
        if case == "occupied" {
            let removed = namespace_python(
                home,
                r"
import os,sys
os.unlink(os.path.join(sys.argv[2],'R/round-launch-review.json'))
",
                runs.to_str().expect("runs"),
            )
            .expect("remove fixture request");
            assert!(removed.status.success(), "{removed:?}");
        }
    }
    crate::launch::publish_reservation(&reservation, record).expect("restore settled record");
    writeln!(std::io::stdout().lock(), "PUBLICATION-PREFLIGHT-READONLY").expect("marker");
}

fn publication_inventory(home: &Path, runs: &Path) -> Vec<u8> {
    let output = namespace_python(
        home,
        r"
import os,sys,json,hashlib,stat
from pathlib import Path
root=Path(sys.argv[2]);rows=[]
for directory,dirs,files in os.walk(root,followlinks=False):
 for name in sorted(dirs+files):
  p=Path(directory)/name;s=p.lstat();payload=None
  if stat.S_ISREG(s.st_mode): payload=hashlib.sha256(p.read_bytes()).hexdigest()
  elif stat.S_ISLNK(s.st_mode): payload=os.readlink(p)
  rows.append((str(p.relative_to(root)),s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,payload))
print(json.dumps(sorted(rows)))
",
        runs.to_str().expect("runs"),
    )
    .expect("whole run inventory");
    assert!(output.status.success(), "{output:?}");
    output.stdout
}

fn check_built_inspection(home: &Path, runs: &Path, seed: &Value, uid: u32) {
    let setup = json!({"run":runs.join("R"),"uid":uid}).to_string();
    let output = namespace_python(
        home,
        r"
import os,json,sys
from pathlib import Path
v=json.loads(sys.argv[2]);r=Path(v['run']);d=r/'fixture-dispatch';d.mkdir()
d.chmod(0o700);os.chown(d,v['uid'],v['uid'])
p=d/'events.jsonl'
p.write_text(json.dumps({'type':'thread.started','thread_id':'fixture-thread'})+'\n')
p.chmod(0o600);os.chown(p,v['uid'],v['uid'])
p=d/'.event-start';p.write_bytes(b'0\n');p.chmod(0o600);os.chown(p,v['uid'],v['uid'])
p=r/'launch/runtime.env'
p.write_bytes(b'SUPERLOOP_CLIENT_ROOT_DEV=1\0SUPERLOOP_CLIENT_ROOT_INO=2\0')
os.chown(p,0,v['uid']);p.chmod(0o440)
",
        &setup,
    )
    .expect("inspection history");
    assert!(output.status.success(), "{output:?}");
    let reservation = runs.join(".reservation-R.json");
    for (case, expected) in [
        ("binding", "round request lacks its delivery binding"),
        ("occupied", "round-launch-review.json already exists"),
    ] {
        let mut record = seed.clone();
        record["phase"] = json!("preparing");
        record["active_round"] = json!("review");
        record["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({"step":"review","budget_seconds":3600}));
        if case == "binding" {
            record["mail"] = json!([]);
        }
        crate::launch::publish_reservation(&reservation, &record).expect("inspect record");
        if case == "occupied" {
            let output = namespace_python(
                home,
                r"
import pathlib,sys
(pathlib.Path(sys.argv[2])/'R/round-launch-review.json').write_bytes(b'retained request')
",
                runs.to_str().expect("runs"),
            )
            .expect("occupied request");
            assert!(output.status.success(), "{output:?}");
        }
        let before = publication_inventory(home, runs);
        let error = built_inspection(home, runs).expect_err("inspection refuses input");
        assert!(error.detail.contains(expected), "{case}: {error:?}");
        assert_eq!(
            publication_inventory(home, runs),
            before,
            "{case}: built inspection must not publish before validation"
        );
    }
    writeln!(std::io::stdout().lock(), "INSPECTION-REFUSALS-READONLY").expect("marker");
}

fn built_inspection(home: &Path, runs: &Path) -> Result<String, crate::error::LaneError> {
    built_inspection_action(home, runs, &["--record", "review", "--budget", "3600"])
}

fn built_inspection_action(
    home: &Path,
    runs: &Path,
    action: &[&str],
) -> Result<String, crate::error::LaneError> {
    let binary = std::env::current_exe()
        .expect("test image")
        .ancestors()
        .map(|path| path.join("superloop-lane"))
        .find(|path| path.is_file())
        .expect("built lane");
    let own = fs::File::open(home).expect("home").into();
    let storage = fs::File::open(runs).expect("runs").into();
    let mut args = vec![
        "unshare".into(),
        binary.display().to_string(),
        "_inspect-round".into(),
        "alpha".into(),
        "R".into(),
        "--owner-home".into(),
        home.display().to_string(),
    ];
    args.extend(action.iter().map(|word| (*word).to_owned()));
    let mut receipt = crate::build::LiveChild::default();
    let result = crate::build::inspect_with_receipt(
        Path::new("/usr/bin/podman"),
        &args,
        &crate::launch::launch_environment(home)?,
        home,
        &own,
        runs,
        &storage,
        &mut receipt,
    );
    assert!(
        receipt.absent(),
        "private inspector waited for its process group"
    );
    result
}

fn rollback_request(home: &Path, runs: &Path, uid: u32, text: &str) {
    let input = json!({"run":runs.join("R"),"uid":uid,"text":text}).to_string();
    let output = namespace_python(
        home,
        r"
import os,json,sys
from pathlib import Path
v=json.loads(sys.argv[2]);p=Path(v['run'])/'round-launch-review.json'
p.write_text(v['text']);p.chmod(0o600);os.chown(p,v['uid'],v['uid'])
",
        &input,
    )
    .expect("own mapped request");
    assert!(output.status.success(), "{output:?}");
}

fn rollback_record(seed: &Value, runs: &Path, nonce: &str, request: &str) -> Value {
    let before = serde_json::to_string_pretty(seed).expect("raw settled bytes");
    let mut record = seed.clone();
    record["phase"] = json!("preparing");
    record["active_round"] = json!("review");
    record["letter_source"] = json!(runs.join("R/mail-review.txt"));
    record["rounds"]
        .as_array_mut()
        .expect("rounds")
        .push(json!({"step":"review","phase":"preparing","budget_seconds":3600}));
    let original: Vec<Value> = [
        crate::container_helper::socket_path(&runs.join("R")).expect("socket"),
        crate::container_helper::control_socket_path(&runs.join("R")).expect("control"),
    ]
    .iter()
    .map(|path| json!({"name":path.file_name().and_then(|name| name.to_str()),"identity":null}))
    .collect();
    let handle = execute_command::rubric::sha256_digest(before.as_bytes());
    record["round_rollback"] = json!({"schema":1,"nonce":nonce,"before":before,
        "before_bytes":before.len(),"before_sha256_prefix":&handle[..16],
        "request":request,"sockets":[],"sockets_before":original});
    record
}

fn check_rollback_cleanup(home: &Path, runs: &Path, podman: &Path, seed: &Value, uid: u32) {
    let nonce = "a".repeat(64);
    let reservation = runs.join(".reservation-R.json");
    let request = format!(
        "{}\n",
        json!({"schema":1,"step":"review","budget_seconds":3600,
        "mail":seed["mail"][0],"thread_id":seed["thread_id"],"home":seed["plan"]["home"],
        "worker_uid":seed["worker_uid"]})
    );
    let inventory = rollback_inventory(home, runs);
    let mut record = rollback_record(seed, runs, &nonce, &request);
    crate::launch::publish_reservation(&reservation, &record).expect("attempt");
    rollback_request(home, runs, uid, &"x".repeat(request.len()));
    let before = publication_inventory(home, runs);
    let error = built_inspection_action(home, runs, &["--rollback", &nonce])
        .expect_err("replacement is retained");
    assert!(error.detail.contains("request bytes differ"), "{error:?}");
    assert_eq!(
        publication_inventory(home, runs),
        before,
        "refusal changes nothing"
    );
    rollback_request(home, runs, uid, &request);
    record["dispatch_intent"] = json!({"nonce":nonce});
    crate::launch::publish_reservation(&reservation, &record).expect("intent");
    let before = publication_inventory(home, runs);
    let error = built_inspection_action(home, runs, &["--rollback", &nonce])
        .expect_err("intent cannot roll back");
    assert!(error.detail.contains("dispatch-intent"), "{error:?}");
    assert_eq!(
        publication_inventory(home, runs),
        before,
        "intent preserved"
    );
    record
        .as_object_mut()
        .expect("record")
        .remove("dispatch_intent");
    check_rollback_socket(home, runs, &mut record, &nonce);
    crate::launch::publish_reservation(&reservation, &record).expect("retry attempt");
    let output = built_inspection_action(home, runs, &["--rollback", &nonce])
        .expect("real received-custody cleanup");
    let report: Value = serde_json::from_str(&output).expect("real cleanup report");
    assert_eq!(report["state"], "cleaned");
    assert_eq!(report["nonce"], nonce);
    let cleaned = publication_inventory(home, runs);
    assert!(!String::from_utf8_lossy(&cleaned).contains("round-launch-review.json"));
    assert_eq!(
        fs::read(&reservation).expect("preparing remains"),
        serde_json::to_vec(&record).expect("unchanged preparing")
    );
    check_rollback_helper(home, runs, podman, &nonce);
    assert_eq!(
        rollback_inventory(home, runs),
        inventory,
        "no stray attempt files"
    );
    writeln!(std::io::stdout().lock(), "ROLLBACK-PRIVATE-CLEANUP").expect("marker");
}

fn check_rollback_socket(home: &Path, runs: &Path, record: &mut Value, nonce: &str) {
    let socket = crate::container_helper::socket_path(&runs.join("R")).expect("socket");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("fixture socket");
    let identity = fs::symlink_metadata(&socket).expect("socket identity");
    record["round_rollback"]["sockets"] = json!([{
        "name":socket.file_name().and_then(|name| name.to_str()),
        "device":identity.dev(),"inode":identity.ino()+1}]);
    let reservation = runs.join(".reservation-R.json");
    crate::launch::publish_reservation(&reservation, record).expect("socket attempt");
    let before = publication_inventory(home, runs);
    let error = built_inspection_action(home, runs, &["--rollback", nonce])
        .expect_err("replacement socket retained");
    assert!(
        error.detail.contains("replacement socket retained"),
        "{error:?}"
    );
    assert_eq!(
        publication_inventory(home, runs),
        before,
        "replacement untouched"
    );
    record["round_rollback"]["sockets"][0]["inode"] = json!(identity.ino());
    drop(listener);
}

fn check_rollback_helper(home: &Path, runs: &Path, podman: &Path, nonce: &str) {
    built_inspection(home, runs).expect("same private inspection can publish after cleanup");
    ready_and_stop(
        built_helper(home, runs, podman, false),
        runs,
        "ROLLBACK-HELPER-RETRY",
    );
    let reservation = runs.join(".reservation-R.json");
    let record: Value =
        serde_json::from_slice(&fs::read(&reservation).expect("registered sockets"))
            .expect("record");
    assert_eq!(record["round_rollback"]["nonce"], nonce);
    assert_eq!(
        record["round_rollback"]["sockets"]
            .as_array()
            .expect("receipts")
            .len(),
        2,
        "real helper registered both held socket identities"
    );
    let output = built_inspection_action(home, runs, &["--rollback", nonce])
        .expect("cleanup real published request after helper stop");
    let report: Value = serde_json::from_str(&output).expect("cleanup receipt");
    assert_eq!(report["state"], "cleaned");
    let inventory = publication_inventory(home, runs);
    assert!(!String::from_utf8_lossy(&inventory).contains("round-launch-review.json"));
}

fn rollback_inventory(home: &Path, runs: &Path) -> Value {
    let bytes = publication_inventory(home, runs);
    let mut inventory: Value = serde_json::from_slice(&bytes).expect("inventory rows");
    inventory.as_array_mut().expect("rows").retain(|row| {
        ![
            ".reservation-R.json",
            "R/round-launch-review.json",
            "R/launch/runtime.env",
            ".launch-R/credential-refresh.json",
        ]
        .iter()
        .any(|name| row[0] == *name)
    });
    inventory
}
