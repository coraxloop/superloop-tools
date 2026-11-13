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
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "tests::launch::proxy_refresh_preserves_live_helper_pins",
            "--nocapture",
        ])
        .env("SUPERLOOP_ROUND_PROOF", "1")
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
    for marker in [
        "FIRST-HELPER-READY",
        "RESUMED-HELPER-READY",
        "ROUND-PREFLIGHT-READONLY",
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
for name in ['mail-review.txt']:
 try: os.chown(name,0,0,dir_fd=fd,follow_symlinks=False)
 except FileNotFoundError: pass
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

/// # Panics
/// Panics if the built helper refuses the correctly provisioned synthetic rounds.
pub(super) fn rounds_acceptance(home: &Path, runs: &Path, podman: &Path) {
    let mut record = prepare(home, runs, podman);
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
    let preview: Value = serde_json::from_slice(&output.stdout).expect("preview JSON");
    assert_eq!(preview["state"], "passed");
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
        let output = built_helper(home, runs, podman, true).finish();
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
