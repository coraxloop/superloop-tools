//! Actual package acceptance shares only fixture setup with the library session target.
#[path = "../../loop-home/tests/reply_custody.rs"]
pub mod fixture;
use fixture::bounded::CommandOutput as _;
use loop_home::anchor::{self, Manifest, Transport};
use std::fs::{self, File};
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn binary() -> PathBuf {
    std::env::current_exe()
        .expect("image")
        .ancestors()
        .map(|p| p.join("superloop-lane"))
        .find(|p| p.is_file())
        .expect("build the package binary in this profile before this acceptance")
}
fn seed(home: &Path) {
    fixture::configuration(home);
    let result = fixture::child_command(home, "seed")
        .fixture_output("reply package seed", Duration::from_secs(60))
        .expect("seed");
    assert!(result.status.success(), "{result:?}");
    let own = File::open(home).expect("home");
    let runs = File::open(home.join("runs")).expect("runs");
    let entry = std::env::current_exe().expect("seed entry");
    let pins = loop_home::mail::reply_entry::pins(
        (home, &own.into()),
        (&home.join("runs"), &runs.into()),
        &entry,
        "alpha",
    )
    .expect("seed pins");
    let declaration = Manifest {
        version: 1,
        operation: "mail-binding".into(),
        loop_name: "alpha".into(),
        transport: Transport::Rights,
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("seed rights");
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .expect("seed transfer");
    let result = fixture::child_command(home, "package-seed")
        .env(
            "LOOP_HOME_REPLY_MANIFEST",
            serde_json::to_string(&declaration).expect("declaration"),
        )
        .stdin(OwnedFd::from(input))
        .fixture_spawn("reply seed delivery", Duration::from_secs(60))
        .expect("seed process")
        .wait()
        .expect("seed delivery output");
    assert!(result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("PACKAGE-DELIVERY"),
        "{result:?}"
    );
}
fn plan(home: &Path, entry: &Path) {
    let config = home.join(".config/loops/alpha");
    fs::create_dir(&config).expect("config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("mode");
    let registry = home.join(".config/loops/registry.toml");
    let source = fs::read_to_string(&registry).expect("registry").replace(
        "launch='dev/alpha'",
        &format!(
            "launch='dev/alpha',runs_root='{}'",
            home.join("runs").display()
        ),
    );
    fs::write(&registry, source).expect("registry runs grant");
    let settings = format!(
        concat!(
            "runs_root='{}'\nentry_bin='{}'\ndriver_argv=['/usr/bin/false']\n",
            "backend_argv={{codex=['/usr/bin/false']}}\nimage_digest='sha256:{}'\n",
            "template_dir='{}'\nsocket_dir='{}'\n",
            "resources={{memory_bytes=2147483648,pids_max=128,cpu_shares=512}}\n",
        ),
        home.join("runs").display(),
        entry.display(),
        "a".repeat(64),
        home.join(".var/loops/alpha/template").display(),
        home.join(".var/loops/alpha/sockets").display()
    );
    let path = config.join("workers.toml");
    fs::write(&path, settings).expect("settings");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    let driver = home.join("runs/R");
    let worker_home = home.join(".cache/tmp/lane-alpha-R");
    let record = serde_json::json!({"schema":1,"phase":"started","worker_uid":64010,
        "loop":"alpha","run":"R",
        "mail_birth":{"uid":64010,"name":"worker","reservation":"reply-fixture"},
        "mail":[],"mail_replies":[],"plan":{"home":worker_home,"driver_dir":driver,
        "runtime_argv":["/usr/bin/podman"],"paths":[{"path":worker_home,"gid":64000},
        {"path":driver,"kind":"directory","uid":64000,"gid":64000}]}});
    let path = home.join("runs/.reservation-R.json");
    fs::write(&path, serde_json::to_vec(&record).expect("record")).expect("reservation");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("reservation mode");
}
fn request(home: &Path, entry: &Path) -> loop_home::CommandSpec {
    let argv = vec![
        "unshare".into(),
        entry.display().to_string(),
        "_bind-reply".into(),
        "alpha".into(),
        "R".into(),
        "--owner-home".into(),
        home.display().to_string(),
        "--step".into(),
        "review".into(),
        "--delivery".into(),
        "2026-01-01T00:00:00.001Z".into(),
    ];
    superloop_lane::launch::reply_entry::command(
        Path::new("/usr/bin/podman"),
        &argv,
        (home, &File::open(home).expect("home").into()),
        (
            &home.join("runs"),
            &File::open(home.join("runs")).expect("runs").into(),
        ),
    )
    .expect("production composer")
}
fn run(spec: &loop_home::CommandSpec) -> std::process::Output {
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    spec.descriptors
        .configure(&mut command)
        .expect("descriptor handoff");
    command
        .fixture_spawn("actual reply entry", Duration::from_secs(60))
        .expect("entry")
        .wait()
        .expect("entry output")
}
struct Replacement {
    original: PathBuf,
    retained: PathBuf,
}
impl Replacement {
    fn new(path: &Path) -> Self {
        let retained = path.with_file_name(format!(
            "{}.retained",
            path.file_name().expect("name").to_string_lossy()
        ));
        fs::rename(path, &retained).expect("retain received directory");
        fs::create_dir(path).expect("replacement");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        Self {
            original: path.to_owned(),
            retained,
        }
    }
}
impl Drop for Replacement {
    fn drop(&mut self) {
        fs::remove_dir(&self.original).expect("replacement remains empty");
        fs::rename(&self.retained, &self.original).expect("restore parent-owned fixture");
    }
}
/// # Panics
/// Panics if the production binding loses custody or admits a named substitution.
/// (´claim:superlooplane:reply-entry-retains-custody´)
// Executed by the custom main, outside the libtest census.
fn reply_entry_retains_custody(kind: &str) {
    let fixture = fixture::Fixture::new();
    let home = &fixture.0;
    seed(home);
    let entry = if kind == "new-to-old" {
        PathBuf::from(std::env::var_os("LANE_REPLY_OLD_BINARY").expect("comparison binary"))
    } else {
        binary()
    };
    plan(home, &entry);
    if kind == "public-route" {
        public_route(home, &entry);
        return;
    }
    let mut spec = request(home, &entry);
    alter_frame(&mut spec, home, &entry, kind);
    let path = match kind {
        "configuration" => Some(home.join(".config/loops")),
        "storage" => Some(home.join(".var/loops/alpha")),
        "journal" => Some(home.join(".var/loops/.mail-service")),
        "home" => Some(home.clone()),
        "runs" => Some(home.join("runs")),
        _ => None,
    };
    let replacement = path.as_deref().map(Replacement::new);
    evidence_change(home, kind);
    if kind == "runs-mode" {
        fs::set_permissions(home.join("runs"), fs::Permissions::from_mode(0o500))
            .expect("runs root without owner write");
    }
    let result = if kind == "lock-order" {
        lock_order(home, &spec)
    } else if kind.starts_with("public-override") {
        public_reply(home, &entry, kind)
    } else {
        run(&spec)
    };
    drop(replacement);
    if kind == "runs-mode" {
        fs::set_permissions(home.join("runs"), fs::Permissions::from_mode(0o700))
            .expect("restored runs root mode");
    }
    if let Some(expected) = refusal(kind) {
        assert!(!result.status.success(), "{kind}: {result:?}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(expected), "{kind}: {result:?}");
        if kind == "identity" {
            assert!(!stderr.contains("anchor-"), "{result:?}");
        }
        return;
    }
    assert!(result.status.success(), "{kind}: {result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).expect("binding");
    assert_eq!(report["sender"], "alpha+worker");
    assert_eq!(report["recipient"], "alpha");
    assert_eq!(report["worker_uid"], 64010);
    let result = namespace(
        home,
        concat!(
            "import pathlib,sys;root=pathlib.Path(sys.argv[1]);",
            "assert (root/'runs/R/reply-review.txt').read_bytes()==b'reply bytes\\x00\\xff\\n'"
        ),
    );
    assert!(result.status.success(), "{kind}: {result:?}");
}
fn public_route(home: &Path, entry: &Path) {
    let request = superloop_lane::launch::steering::Request::parse(&[
        "alpha".into(),
        "R".into(),
        "--step".into(),
        "review".into(),
        "--delivery".into(),
        "2026-01-01T00:00:00.001Z".into(),
    ])
    .expect("public selection");
    let host = (home, nix::unistd::Uid::effective().as_raw(), Some(entry));
    let first = superloop_lane::launch::steering::run_from(home, &request, true, host)
        .expect("complete public reply route");
    assert_eq!(first["command"], "bind-reply");
    assert_eq!(first["resume_authorized"], false);
    assert_eq!(first["mail"]["sender"], "alpha+worker");
    assert_eq!(first["mail"]["recipient"], "alpha");
    let path = home.join("runs/.reservation-R.json");
    let bytes = fs::read(&path).expect("published reservation");
    let record: serde_json::Value = serde_json::from_slice(&bytes).expect("record");
    assert_eq!(record["mail_replies"], serde_json::json!([first["mail"]]));
    let second = superloop_lane::launch::steering::run_from(home, &request, true, host)
        .expect("public rebind");
    assert_eq!(second, first);
    assert_eq!(fs::read(path).expect("unchanged reservation"), bytes);
    let output = namespace(
        home,
        concat!(
            "import pathlib,sys;root=pathlib.Path(sys.argv[1]);",
            "assert (root/'runs/R/reply-review.txt').read_bytes()==b'reply bytes\\x00\\xff\\n'"
        ),
    );
    assert!(output.status.success(), "{output:?}");
}
fn public_reply(home: &Path, entry: &Path, kind: &str) -> std::process::Output {
    Command::new(entry)
        .args([
            "bind-reply",
            "alpha",
            "R",
            "--step",
            "review",
            "--delivery",
            "2026-01-01T00:00:00.001Z",
        ])
        .env("HOME", home)
        .env(
            "ENTER_LOOP_REGISTRY",
            if kind.ends_with("empty") {
                PathBuf::new()
            } else {
                home.join(".config/loops/registry.toml")
            },
        )
        .fixture_output("public reply command", Duration::from_secs(60))
        .expect("public binding")
}
fn namespace(home: &Path, source: &str) -> std::process::Output {
    Command::new("/usr/bin/podman")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", source])
        .arg(home)
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .fixture_output("reply namespace control", Duration::from_secs(30))
        .expect("control")
}
fn evidence_change(home: &Path, kind: &str) {
    let action = match kind {
        "evidence-link" => "p.symlink_to('/dev/null')",
        "evidence-mode" => "p.write_bytes(b'changed');p.chmod(0o644)",
        "evidence-links" => {
            "p.write_bytes(b'changed');p.chmod(0o600);os.link(p,p.with_name('other'))"
        }
        "evidence-owner" => "p.write_bytes(b'changed');p.chmod(0o600);os.chown(p,64011,64011)",
        _ => return,
    };
    let source = format!(
        "import pathlib,sys,os;p=pathlib.Path(sys.argv[1])/'runs/R/reply-review.txt';{action}"
    );
    let result = namespace(home, &source);
    assert!(result.status.success(), "{result:?}");
}

// A separate process owns the admission lock and starts an independent receipt waiter.
// The pipe protocol, not a delay, orders the observations against the real entry.
fn lock_order(home: &Path, spec: &loop_home::CommandSpec) -> std::process::Output {
    use std::io::{Read as _, Write as _};
    let (mut control, child) = std::os::unix::net::UnixStream::pair().expect("lock control");
    control
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("control bound");
    let mut command = Command::new("/usr/bin/podman");
    command
        .args(["unshare", "/usr/bin/python3", "-I", "-c", LOCK_ORDER])
        .arg(home)
        .stdin(OwnedFd::from(child))
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    let holder = command
        .fixture_spawn("receipt lease observer", Duration::from_secs(40))
        .expect("lock holder");
    let mut signal = [0];
    control.read_exact(&mut signal).expect("admission held");
    assert_eq!(signal, *b"L");
    let mut entry = Command::new(&spec.argv[0]);
    entry
        .args(&spec.argv[1..])
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    spec.descriptors.configure(&mut entry).expect("frame");
    let entry = entry
        .fixture_spawn("reply waiting on admission", Duration::from_secs(35))
        .expect("entry");
    control
        .read_exact(&mut signal)
        .expect("both waits measured");
    assert_eq!(signal, *b"B");
    control.write_all(b"R").expect("release admission");
    let result = entry.wait().expect("entry bounded completion");
    control
        .read_exact(&mut signal)
        .expect("receipt acquired after entry");
    assert_eq!(signal, *b"A");
    let observed = holder.wait().expect("observer completion");
    assert!(observed.status.success(), "{observed:?}");
    assert!(String::from_utf8_lossy(&observed.stdout).contains("receipt-after-entry"));
    result
}
const LOCK_ORDER: &str = r"import os,sys,fcntl,time,select
root=sys.argv[1]
j=os.open(root+'/.var/loops/.mail-service',os.O_RDONLY|os.O_DIRECTORY)
r=os.open(root+'/.var/loops/alpha/.mail-births',os.O_RDONLY|os.O_DIRECTORY)
fcntl.flock(j,fcntl.LOCK_EX)
os.write(0,b'L')
def blocked(fd):
 s=os.fstat(fd); key=f'{os.major(s.st_dev):02x}:{os.minor(s.st_dev):02x}:{s.st_ino}'
 end=time.monotonic()+10
 while True:
  with open('/proc/locks') as f: lines=f.read().splitlines()
  if any('->' in line and key in line.split() for line in lines): return
  assert time.monotonic()<end, ('missing waiter',key,lines)
  os.sched_yield()
blocked(j)
read,write=os.pipe()
pid=os.fork()
if pid==0:
 os.close(read);os.close(j)
 fcntl.flock(r,fcntl.LOCK_EX)
 os.write(write,b'A');os._exit(0)
os.close(write)
blocked(r)
os.write(0,b'B')
assert os.read(0,1)==b'R'
fcntl.flock(j,fcntl.LOCK_UN)
assert select.select([read],[],[],15)[0], 'receipt waiter deadline'
assert os.read(read,1)==b'A'
assert os.waitpid(pid,0)[1]==0
os.write(0,b'A')
print('receipt-after-entry',flush=True)
";

fn refusal(kind: &str) -> Option<&'static str> {
    match kind {
        "home" => Some("purpose=owner-home"),
        "runs" => Some("socket-dir-handoff"),
        "runs-mode" => Some("purpose=runs-root check=directory-mode"),
        "identity" => Some("identity provisioning step refused"),
        "entry-image" => Some("anchor-identity: operation=mail-binding purpose=entry-executable"),
        "evidence-link" => Some("ELOOP"),
        "evidence-mode" | "evidence-links" | "evidence-owner" => Some("evidence custody differs"),
        "public-override-empty" | "public-override-canonical" => Some("purpose=registry-override"),
        "count" => Some("purpose=count"),
        "old-launcher" => Some("anchor-missing"),
        "not-socket" => Some("anchor-missing: operation=mail-binding purpose=rights"),
        "new-to-old" => Some("verified-prefix"),
        "short-frame" => Some("expected=8 received=7"),
        "excess-frame" => Some("expected=8 received=8 malformed=true"),
        _ => None,
    }
}
fn alter_frame(spec: &mut loop_home::CommandSpec, home: &Path, entry: &Path, kind: &str) {
    if kind == "not-socket" {
        spec.descriptors = loop_home::CommandDescriptors::default()
            .with_input(File::open("/dev/null").expect("non-socket input").into());
        return;
    }
    if kind == "old-launcher" {
        spec.argv.truncate(spec.argv.len() - 4);
        spec.argv.extend([
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-runs-root".into(),
            home.join("runs").display().to_string(),
            "--verified-runs-root-fd".into(),
            "1".into(),
        ]);
        spec.descriptors = loop_home::CommandDescriptors::default();
        return;
    }
    if !matches!(
        kind,
        "identity" | "entry-image" | "count" | "short-frame" | "excess-frame"
    ) {
        return;
    }
    let mut pins = loop_home::mail::reply_entry::pins(
        (home, &File::open(home).expect("home").into()),
        (
            &home.join("runs"),
            &File::open(home.join("runs")).expect("runs").into(),
        ),
        entry,
        "alpha",
    )
    .expect("production pins");
    if kind == "identity" {
        pins[6] = anchor::HostVerifier::current()
            .expect("host")
            .for_operation("mail-binding")
            .pin(
                Path::new("/usr/bin/false"),
                "identity-executable",
                6,
                anchor::Policy {
                    kind: anchor::Kind::File,
                    owner: anchor::Owner::RootFile,
                    mode: anchor::ModePolicy::Executable,
                },
            )
            .expect("honest received false");
    }
    if kind == "entry-image" {
        pins[2] = anchor::HostVerifier::current()
            .expect("host")
            .for_operation("mail-binding")
            .pin(
                Path::new("/usr/bin/true"),
                "entry-executable",
                2,
                anchor::Policy {
                    kind: anchor::Kind::File,
                    owner: anchor::Owner::RootFile,
                    mode: anchor::ModePolicy::Executable,
                },
            )
            .expect("honest received image");
    }
    let mut manifest: Manifest =
        serde_json::from_str(spec.argv.last().expect("manifest")).expect("frame");
    manifest.records = pins.iter().map(anchor::HostPin::record).collect();
    if kind == "count" {
        manifest.records.pop();
    }
    *spec.argv.last_mut().expect("manifest") =
        serde_json::to_string(&manifest).expect("declaration");
    let mut fds = pins
        .into_iter()
        .map(anchor::HostPin::into_fd)
        .collect::<Vec<_>>();
    if kind == "short-frame" {
        fds.pop();
    }
    if kind == "excess-frame" {
        fds.push(File::open(home).expect("surplus").into());
    }
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("replacement frame");
    anchor::transport::send(&sender, &fds).expect("frame");
    spec.descriptors = loop_home::CommandDescriptors::default().with_input(input.into());
}
const NAME: &str = "reply_entry_retains_custody";

fn main() -> std::process::ExitCode {
    if std::env::var_os("LOOP_HOME_REPLY_PHASE").is_some()
        || std::env::args()
            .nth(1)
            .is_some_and(|a| a.starts_with("_mail-worker-"))
    {
        return fixture::main();
    }
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let selection = match fixture::TestArguments::parse(&args) {
        Ok(selection) => selection,
        Err(error) => {
            writeln!(std::io::stderr().lock(), "reply-entry: {error}").expect("argument refusal");
            return std::process::ExitCode::from(2);
        }
    };
    if selection.list {
        if selection.selected_for(NAME) {
            writeln!(std::io::stdout().lock(), "{NAME}: test").expect("test listing");
        }
        return std::process::ExitCode::SUCCESS;
    }
    if !selection.selected_for(NAME) {
        writeln!(
            std::io::stdout().lock(),
            "test result: ok. 0 passed; 0 failed; 1 filtered out"
        )
        .expect("filtered result");
        return std::process::ExitCode::SUCCESS;
    }
    let cases = [
        "basic",
        "public-route",
        "configuration",
        "storage",
        "journal",
        "home",
        "runs",
        "runs-mode",
        "identity",
        "entry-image",
        "count",
        "old-launcher",
        "not-socket",
        "short-frame",
        "excess-frame",
        "evidence-link",
        "evidence-mode",
        "evidence-links",
        "evidence-owner",
        "lock-order",
        "public-override-empty",
        "public-override-canonical",
    ];
    let selected = std::env::var("LANE_REPLY_CASE").ok();
    if let Some(kind) = selected.as_deref() {
        assert!(
            cases.contains(&kind) || kind == "new-to-old",
            "unknown case {kind}"
        );
    }
    for kind in selected
        .as_deref()
        .map_or_else(|| cases.to_vec(), |kind| vec![kind])
    {
        reply_entry_retains_custody(kind);
        writeln!(std::io::stdout().lock(), "reply entry {kind} passed").expect("case result");
    }
    writeln!(std::io::stdout().lock(), "reply entry passed").expect("test result");
    std::process::ExitCode::SUCCESS
}
