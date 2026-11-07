//! Real worker lifetime entry through the production composer and rootless Podman.
use loop_home::mail::birth::Identity;
use loop_home::{IoMode, ProcessRunner, Runner};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_worker-run")
}
struct Fixture {
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let home =
            std::env::temp_dir().join(format!("worker-anchor-{}-{stamp}", std::process::id()));
        for path in [
            home.clone(),
            home.join(".config"),
            home.join(".config/loops"),
        ] {
            fs::create_dir_all(&path).expect("configuration directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        for (name, source) in [
            (
                "registry.toml",
                "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=64000,launch='dev/alpha'}]\n",
            ),
            (
                "allocations.toml",
                "mail_uid=64001\n[alpha]\nuids={base=64010,count=2}\nmail_gids={base=64020,count=3}\n",
            ),
            (
                "mail-service.toml",
                "version=1\nuid=64001\ncrash_consistent_rename=true\ndurable_sync=true\n",
            ),
        ] {
            let path = home.join(".config/loops").join(name);
            fs::write(&path, source).expect("configuration");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("configuration mode");
        }
        let fixture = Self { home };
        fixture.python(r"
import os,sys
from pathlib import Path
home=Path(sys.argv[1])
with open('/proc/self/uid_map') as source: mapping=source.read().splitlines()
assert len(mapping)>1 and os.geteuid()==0
with open('/proc/sys/kernel/overflowuid') as source: overflow=int(source.read())
assert os.stat('/').st_uid==overflow
for path,uid,mode in [(home/'.var',0,0o711),(home/'.var/loops',0,0o711),(home/'.var/loops/alpha',0,0o711),(home/'.var/loops/alpha/private',64000,0o700),(home/'.var/loops/.mail-service',64001,0o700),(home/'.var/loops/alpha/worker-homes',64000,0o710),(home/'.var/loops/alpha/worker-homes/lane-a',64000,0o750)]:
 path.mkdir(exist_ok=True)
 os.chmod(path,mode)
 os.chown(path,uid,uid)
private=home/'.var/loops/alpha/private'
for path in [private/'.config',private/'.config/mail']:
 path.mkdir()
 os.chmod(path,0o700)
 os.chown(path,64000,64000)
config=private/'.config/mail/loop.toml'
config.write_text('workers=[]\n[mail]\nversion=1\nallow=[]\n')
os.chmod(config,0o600)
os.chown(config,64000,64000)
(home/'.var/loops/alpha/worker-homes/lane-a/evidence').write_bytes(bytes([0,255]))
");
        fixture
    }
    fn python(&self, script: &str) {
        let output = Command::new("/usr/bin/podman")
            .args(["unshare", "/usr/bin/python3", "-I", "-c", script])
            .arg(&self.home)
            .output()
            .expect("namespace fixture");
        assert!(
            output.status.success(),
            "unmeasured or fixture refused: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn identity() -> Identity {
        Identity::for_reservation(64010, "worker-run:lane-a:64010:1".into())
    }
    fn command(&self, phase: &str) -> loop_home::CommandSpec {
        let mut request = loop_home::mail::worker_provision::anchored_command(
            &self.home,
            "alpha",
            &Self::identity(),
            "_mail-worker-birth",
            phase,
            Path::new(binary()),
            &["/usr/bin/podman".into(), "unshare".into()],
        )
        .expect("production composer");
        request.io = IoMode::Capture;
        request
    }
    fn run(&self, phase: &str) {
        let output = ProcessRunner
            .run(&self.command(phase))
            .expect("worker entry");
        assert_eq!(
            output.status,
            0,
            "{phase}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = Command::new("/usr/bin/podman")
            .args([
                "unshare",
                "/usr/bin/python3",
                "-I",
                "-c",
                "import shutil,sys; shutil.rmtree(sys.argv[1])",
            ])
            .arg(&self.home)
            .output();
    }
}

/// # Panics
/// Panics if the real rootless map or any worker lifetime transition is unmeasured or refused.
/// ´claim:runworker:worker-lifetime-retains-namespace-capabilities´
/// ´test:integration:worker-lifetime-retains-namespace-capabilities´
#[test]
fn worker_lifetime_retains_namespace_capabilities() {
    let fixture = Fixture::new();
    fixture.run("reserve");
    fixture.run("finish");
    fixture.run("verify-only");
    let mut retire = fixture.command("retire");
    // Move every directory that the retired operation already holds. No absolute
    // configuration, private-tier or journal reopen can reach these objects now.
    fixture.python(
        r"
import os,sys
from pathlib import Path
home=Path(sys.argv[1])
os.rename(home/'.config/loops',home/'.config/held-loops')
os.rename(home/'.var/loops/alpha',home/'.var/loops/held-alpha')
os.rename(home/'.var/loops/.mail-service',home/'.var/loops/held-service')
",
    );
    retire.io = IoMode::Capture;
    let output = ProcessRunner.run(&retire).expect("retirement entry");
    assert_eq!(
        output.status,
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.python(
        r"
import os,sys,tomllib
from pathlib import Path
home=Path(sys.argv[1])
root=home/'.var/loops/held-alpha'
receipts=list((root/'.mail-births').glob('name-*.toml'))
assert len(receipts)==1 and tomllib.loads(receipts[0].read_text())['retired']
assert not (home/'.config/loops').exists() and not (home/'.var/loops/alpha').exists()
os.rename(home/'.config/held-loops',home/'.config/loops')
os.rename(root,home/'.var/loops/alpha')
os.rename(home/'.var/loops/held-service',home/'.var/loops/.mail-service')
",
    );
    fixture.run("retire");
    let mut home = loop_home::mail::worker_provision::anchored_command(
        &fixture.home,
        "alpha",
        &Fixture::identity(),
        "_mail-worker-home",
        "lane-a",
        Path::new(binary()),
        &["/usr/bin/podman".into(), "unshare".into()],
    )
    .expect("home composer");
    home.io = IoMode::Capture;
    let output = ProcessRunner.run(&home).expect("home retirement");
    assert_eq!(
        output.status,
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.python(
        r"
import sys,tomllib
from pathlib import Path
root=Path(sys.argv[1])/'.var/loops/alpha'
receipt=tomllib.loads(next((root/'.mail-births').glob('name-*.toml')).read_text())
retained=root/'.worker-history'/receipt['identity']['name']
assert retained.stat().st_uid==0 and retained.stat().st_mode&0o7777==0o700
assert (retained/'evidence').read_bytes()==bytes([0,255])
assert not (root/'worker-homes/lane-a').exists()
",
    );
}

/// # Panics
/// Panics if missing or altered declarations reach a worker mutation.
/// ´claim:runworker:worker-entry-refuses-capability-substitution´
/// ´test:integration:worker-entry-refuses-capability-substitution´
#[test]
fn worker_entry_refuses_capability_substitution() {
    let fixture = Fixture::new();
    for (field, value, refusal) in [
        (
            "operation",
            serde_json::json!("mail-worker-birth-finish"),
            "anchor-declaration",
        ),
        ("inode", serde_json::json!(0), "anchor-identity"),
    ] {
        let mut request = fixture.command("reserve");
        let declaration = request.argv.last_mut().expect("manifest");
        let mut parsed: serde_json::Value = serde_json::from_str(declaration).expect("JSON");
        if field == "inode" {
            parsed["records"][0][field] = value;
        } else {
            parsed[field] = value;
        }
        *declaration = serde_json::to_string(&parsed).expect("JSON");
        let output = ProcessRunner.run(&request).expect("refusal");
        assert_eq!(output.status, 2);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(refusal),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!fixture.home.join(".var/loops/alpha/.mail-births").exists());
    }
    let output = Command::new(binary())
        .args([
            "_mail-worker-birth",
            "/missing",
            "alpha",
            "reserve",
            "worker",
            "64010",
            "reservation",
        ])
        .output()
        .expect("missing manifest");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("anchor-missing"));
}

/// # Panics
/// Panics if a changed live mode or absent prepared configuration bypasses its refusal.
/// ´claim:runworker:worker-entry-rechecks-modes-and-prepared-configuration´
/// ´test:integration:worker-entry-rechecks-modes-and-prepared-configuration´
#[test]
fn worker_entry_rechecks_modes_and_prepared_configuration() {
    let fixture = Fixture::new();
    let entry = fixture.home.join("unsafe-entry");
    fs::copy("/usr/bin/true", &entry).expect("executable fixture");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o752)).expect("unsafe mode");
    let error = loop_home::mail::worker_provision::anchored_command(
        &fixture.home,
        "alpha",
        &Fixture::identity(),
        "_mail-worker-birth",
        "reserve",
        &entry,
        &["/usr/bin/podman".into(), "unshare".into()],
    )
    .expect_err("unsafe executable mode");
    assert!(error.to_string().contains("anchor-mode"), "{error}");
    let request = fixture.command("reserve");
    fs::set_permissions(
        fixture.home.join(".var/loops/alpha"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("changed mode");
    let output = ProcessRunner.run(&request).expect("live mode refusal");
    assert_eq!(output.status, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("anchor-mode"));
    fs::set_permissions(
        fixture.home.join(".var/loops/alpha"),
        fs::Permissions::from_mode(0o711),
    )
    .expect("restore mode");
    fixture.python("import sys; from pathlib import Path; (Path(sys.argv[1])/'.var/loops/alpha/private/.config/mail/loop.toml').unlink()");
    let output = ProcessRunner
        .run(&fixture.command("reserve"))
        .expect("prepared configuration refusal");
    assert_eq!(output.status, 2);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("missing prepared configuration beneath anchor"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// # Panics
/// Panics if the namespace cannot measure the bind, or the production receiver accepts its overflow-owned child.
/// ´claim:runworker:worker-entry-refuses-overflow-child´
/// ´test:integration:worker-entry-refuses-overflow-child´
#[test]
fn worker_entry_refuses_overflow_child() {
    let fixture = Fixture::new();
    let script = r"
import array,ctypes,os,socket,sys
from pathlib import Path
home=Path(sys.argv[1])
source=b'/usr/bin/true'
target=os.fsencode(home/'.config/loops/allocations.toml')
libc=ctypes.CDLL(None,use_errno=True)
assert libc.mount(source,target,None,4096,None)==0, ('unmeasured overflow-child bind',ctypes.get_errno())
with open('/proc/sys/kernel/overflowuid') as f: overflow=int(f.read())
assert os.stat(target).st_uid==overflow
original=socket.socket(fileno=0)
frame,control,flags,address=original.recvmsg(1,socket.CMSG_SPACE(64*array.array('i').itemsize))
assert frame==bytes([1]) and flags==0 and original.recv(1)==b''
fds=array.array('i')
for level,kind,payload in control:
 assert level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS
 fds.frombytes(payload)
# Reopening this same verified directory in the isolated mount view preserves
# dev/ino but makes the injected child visible. The receiver must still check
# the child owner; the directory declaration cannot authorize an overflow UID.
old=os.fstat(fds[0])
os.close(fds[0])
fds[0]=os.open(home/'.config/loops',os.O_PATH|os.O_DIRECTORY)
new=os.fstat(fds[0])
assert (old.st_dev,old.st_ino)==(new.st_dev,new.st_ino)
sender,receiver=socket.socketpair()
sender.sendmsg([bytes([1])],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,fds)])
sender.shutdown(socket.SHUT_WR)
sender.close()
original.close()
os.dup2(receiver.fileno(),0,inheritable=True)
receiver.close()
for fd in fds: os.close(fd)
print('OVERFLOW_CHILD_UID='+str(overflow),file=sys.stderr,flush=True)
os.execv(sys.argv[2],sys.argv[2:])
";
    let namespace = vec![
        "/usr/bin/podman".into(),
        "unshare".into(),
        "/usr/bin/unshare".into(),
        "--mount".into(),
        "/usr/bin/python3".into(),
        "-I".into(),
        "-c".into(),
        script.into(),
        fixture.home.to_string_lossy().into_owned(),
    ];
    let mut request = loop_home::mail::worker_provision::anchored_command(
        &fixture.home,
        "alpha",
        &Fixture::identity(),
        "_mail-worker-birth",
        "reserve",
        Path::new(binary()),
        &namespace,
    )
    .expect("host composer");
    request.io = IoMode::Capture;
    let output = ProcessRunner.run(&request).expect("overflow child entry");
    let error = String::from_utf8(output.stderr).expect("diagnostic");
    assert_eq!(output.status, 2, "{error}");
    let uid = error
        .lines()
        .find_map(|line| line.strip_prefix("OVERFLOW_CHILD_UID="))
        .expect("measured overflow UID");
    assert!(
        error.contains("anchor-owner") && error.contains(&format!("observed {uid}")),
        "{error}"
    );
    assert!(!fixture.home.join(".var/loops/alpha/.mail-births").exists());
}
