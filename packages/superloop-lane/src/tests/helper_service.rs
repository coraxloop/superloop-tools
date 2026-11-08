//! Production helper service acceptance under the rootless namespace.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// # Panics
/// Panics if the production helper loses the reserved runtime or its authority thread.
/// ´claim:superlooplane:helper-service-executes-received-runtime´
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
fn namespace_python(home: &Path, script: &str, worker: &str) -> std::io::Result<Output> {
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
source={'auth_mode':'chatgpt','OPENAI_API_KEY':None,'tokens':{'id_token':token,'access_token':token,'refresh_token':'fixture-service-refresh','account_id':'fixture-account'},'last_refresh':datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
auth=home/'.config/loops/alpha/lanes/codex/auth.json'
auth.write_text(json.dumps(source))
os.chmod(auth,0o600)
";

/// # Panics
/// Panics if the helper fixture cannot publish its source and mapped worker directory.
fn prepare(home: &Path, runs: &Path, podman: &Path) -> Value {
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
fn start(home: &Path, runs: &Path, podman: &Path) -> FixtureChild {
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
    let script = "import os,socket,struct,sys,time\nfrom pathlib import Path\np=Path(sys.argv[1]); deadline=time.monotonic()+30\nwhile not (p/'client-ready').exists():\n assert time.monotonic()<deadline\n time.sleep(.01)\ns=socket.socket(socket.AF_UNIX);s.connect(sys.argv[2]);s.sendall(struct.pack('<I',0))\ndef read(n):\n b=b''\n while len(b)<n:\n  q=s.recv(n-len(b));assert q;b+=q\n return b\nwhile True:\n h=read(5);b=read(struct.unpack('<I',h[1:])[0])\n if h[:1]==b'X':\n  print('STATUS',struct.unpack('<i',b)[0]);break\n print('FRAME',h[:1].decode(),b.decode(),flush=True)\n";
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
/// Panics if the complete service does not execute its held runtime and publish authority evidence.
pub(super) fn exercise(home: &Path, runs: &Path, podman: &Path) {
    let record = prepare(home, runs, podman);
    let worker = record["plan"]["home"].as_str().expect("worker home");
    let _cleanup = MappedWorker {
        home: home.to_path_buf(),
        worker: worker.to_owned(),
    };
    let loop_uid = crate::plan::loop_uid(&record["plan"]).expect("loop uid");
    let mut child = start(home, runs, podman);
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
    let observed: Value = serde_json::from_slice(&fs::read(evidence).expect("authority evidence"))
        .expect("evidence JSON");
    assert_eq!(observed["state"], "current");
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
