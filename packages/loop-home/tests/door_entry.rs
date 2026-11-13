//! Dedicated receiver through the actual package image, with parent-owned namespace cleanup.
use loop_home::anchor::{self, HostPin, HostVerifier, Manifest, Owner, Transport};
use loop_home::door_entry::Invocation;
use loop_home::door_frame::{self, Operation};
use nix::sys::memfd::{MFdFlags, memfd_create};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const HANG: Duration = Duration::from_secs(120);
const UID: u32 = 41001;
const MEASURE: &str = r"
import json,os,pwd,sys
mask=os.umask(0o077);os.umask(mask)
fds=[]
for n in os.listdir('/proc/self/fd'):
 try: os.fstat(int(n));fds.append(int(n))
 except OSError: pass
import ctypes
libc=ctypes.CDLL(None);death=ctypes.c_int();sub=ctypes.c_int()
assert libc.prctl(2,ctypes.byref(death),0,0,0)==0
assert libc.prctl(37,ctypes.byref(sub),0,0,0)==0
status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
current=os.stat('.')
account=list(pwd.getpwuid(os.geteuid()))
print(json.dumps(dict(uid=os.getuid(),euid=os.geteuid(),gid=os.getgid(),groups=os.getgroups(),
 death=death.value,subreaper=sub.value,env=dict(os.environ),
 cwd=[current.st_dev,current.st_ino],umask=mask,nnp=int(status['NoNewPrivs']),
 account=account,fds=sorted(fds),expected=sys.argv[-1],loop=sys.argv[-2])))
";
const MOUNT: &str = r"
import ctypes,os,pathlib,sys
root,entry=sys.argv[1:3]
libc=ctypes.CDLL(None,use_errno=True)
assert libc.unshare(0x20000)==0,ctypes.get_errno()
image=os.open(entry,os.O_PATH)
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
assert libc.mount(None,b'/',None,0x44000,None)==0,ctypes.get_errno()
parents=reversed(pathlib.Path(root).parents)
blocked=next((str(p) for p in parents if os.stat(p).st_mode & 0o023 != 1),None)
if blocked is not None:
 assert blocked!='/'
 assert libc.mount(b'tmpfs',blocked.encode(),b'tmpfs',6,b'mode=0755,size=1m')==0,ctypes.get_errno()
 os.makedirs(root)
 cursor=pathlib.Path(root)
 while True:
  os.chown(cursor,0,0);os.chmod(cursor,0o755)
  if str(cursor)==blocked: break
  cursor=cursor.parent
 source=('/proc/self/fd/'+str(fd)).encode()
 assert libc.mount(source,root.encode(),None,4096,None)==0,ctypes.get_errno()
os.close(fd)
if os.environ.get('DOOR_FIXTURE_UNLINK'): os.unlink(entry)
if os.environ.get('DOOR_FIXTURE_WRONG_UID'):
 import socket,array
 connection=socket.socket(fileno=0)
 data,control,flags,address=connection.recvmsg(1,socket.CMSG_SPACE(32*4))
 rights=array.array('i');rights.frombytes(control[0][2]);assert len(rights)==7
 os.set_inheritable(image,True);os.set_inheritable(rights[6],True)
 os.execv('/usr/bin/setpriv',['setpriv','--reuid=41000','--regid=41000','--clear-groups',
  '/proc/self/fd/'+str(image),'_door-consumer','door-agent','alpha','41001',
  str(rights[6]),str(os.getppid())])
os.setgroups([42000]);os.umask(0o022)
os.execv('/proc/self/fd/'+str(image),[entry,*sys.argv[3:]])
";

struct Child(std::process::Child, bool);
impl Drop for Child {
    fn drop(&mut self) {
        if !self.1 {
            let _signal = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(self.0.id().cast_signed()),
                nix::sys::signal::Signal::SIGKILL,
            );
            let until = Instant::now() + Duration::from_secs(5);
            while self.0.try_wait().ok().flatten().is_none() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
fn output(command: &mut Command, mut event: impl FnMut(u32)) -> Output {
    let mut stdout = File::from(memfd_create("door-fixture-out", MFdFlags::MFD_CLOEXEC).unwrap());
    let mut stderr = File::from(memfd_create("door-fixture-err", MFdFlags::MFD_CLOEXEC).unwrap());
    let mut child = Child(
        command
            .process_group(0)
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .expect("fixture spawn"),
        false,
    );
    let until = Instant::now() + HANG;
    let status = loop {
        event(child.0.id());
        assert!(
            stdout.metadata().unwrap().len() <= 1_048_576
                && stderr.metadata().unwrap().len() <= 1_048_576,
            "fixture output cap"
        );
        if let Some(status) = child.0.try_wait().expect("fixture wait") {
            child.1 = true;
            break status;
        }
        assert!(Instant::now() < until, "fixture hang bound: {command:?}");
        std::thread::sleep(Duration::from_millis(10));
    };
    stdout.rewind().unwrap();
    stderr.rewind().unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(1_048_577).read_to_end(&mut out).unwrap();
    stderr.take(1_048_577).read_to_end(&mut err).unwrap();
    Output {
        status,
        stdout: out,
        stderr: err,
    }
}
fn namespace(script: &str, root: &Path) -> Command {
    let mut command = Command::new("/usr/bin/podman");
    command
        .args(["unshare", "/usr/bin/python3", "-I", "-c", script])
        .arg(root)
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    command
}
fn file(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "door-receiver-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("parent-created root");
        let fixture = Self(root);
        let root = &fixture.0;
        fs::set_permissions(root, fs::Permissions::from_mode(0o711)).unwrap();
        fs::create_dir_all(root.join(".config/loops")).unwrap();
        fs::set_permissions(
            root.join(".config/loops"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        file(
            &root.join(".config/loops/registry.toml"),
            concat!(
                "namespace='org.superloop-tools.loophome.registry'\n",
                "version=[1,0,0]\nloops=[{name='alpha',uid=41001,launch='dev/alpha'}]\n",
            )
            .as_bytes(),
            0o600,
        );
        file(
            &root.join(".config/loops/allocations.toml"),
            b"[alpha]\nuids={base=42000,count=64}\n",
            0o600,
        );
        let script = r"
import os,sys
root=sys.argv[1]
for name,uid,mode in [('.var',0,0o711),('.var/loops',0,0o711),('.var/loops/alpha',0,0o711),
 ('.var/loops/alpha/private',41001,0o700),('.var/loops/alpha/private/.run',41001,0o700),
 ('.var/loops/alpha/private/.codex',41001,0o700),('events',41001,0o755)]:
 p=root+'/'+name;os.mkdir(p);os.chown(p,uid,uid);os.chmod(p,mode)
p=root+'/.var/loops/alpha/private/.codex/auth.json'
open(p,'w').write('{}');os.chown(p,41001,41001);os.chmod(p,0o600)
";
        let result = output(namespace(script, root).stdin(Stdio::null()), |_| {});
        assert!(result.status.success(), "seed: {result:?}");
        file(&root.join("rubric"), b"Reviewed fixture rubric.\n", 0o644);
        fixture
    }
    fn private(&self) -> PathBuf {
        self.0.join(".var/loops/alpha/private")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let result = output(
            namespace("import shutil,sys; shutil.rmtree(sys.argv[1])", &self.0)
                .stdin(Stdio::null()),
            |_| {},
        );
        if !result.status.success() {
            let _reported = writeln!(
                std::io::stderr().lock(),
                "fixture cleanup failed; retained {}: {result:?}",
                self.0.display()
            );
            assert!(std::thread::panicking(), "fixture cleanup failed");
        }
    }
}
fn pins(
    fixture: &Fixture,
    entry: &Path,
    operation: Operation,
    invocation: &Invocation,
) -> Vec<HostPin> {
    let host = HostVerifier::current()
        .expect("host verifier")
        .for_operation(operation.name());
    let paths = [
        fixture.0.join(".config/loops"),
        entry.into(),
        fixture.0.join(".var/loops/alpha"),
        fixture.private(),
        PathBuf::from("/usr/bin/setpriv"),
        PathBuf::from("/usr/bin/podman"),
    ];
    let required = operation
        .requirements(UID, Owner::Host, Owner::RootFile)
        .unwrap();
    let mut pins: Vec<_> = paths
        .iter()
        .zip(required)
        .enumerate()
        .map(|(slot, (path, required))| {
            host.pin(
                path,
                &required.purpose,
                slot.try_into().unwrap(),
                required.policy,
            )
            .expect("host pin")
        })
        .collect();
    pins.push(
        door_frame::pin_invocation(&host, operation, &serde_json::to_vec(invocation).unwrap())
            .unwrap(),
    );
    pins
}
fn invocation(case: &str, fixture: &Fixture) -> Invocation {
    let mut result = Invocation {
        source: MEASURE.into(),
        arguments: vec![],
        input: String::new(),
    };
    if case == "consumer-uid" {
        result.source = "print('unexpected-consumer')".into();
    }
    if matches!(case, "rubric-read" | "rubric-owner") {
        if case == "rubric-owner" {
            let changed = output(
                namespace(
                    "import os,sys; os.chown(sys.argv[1]+'/rubric',41000,41000)",
                    &fixture.0,
                )
                .stdin(Stdio::null()),
                |_| {},
            );
            assert!(changed.status.success(), "rubric change: {changed:?}");
        }
        result.source = format!(
            concat!(
                "{}\n",
                "import sys,json\n",
                "try:\n",
                " text,digest=read_rubric(sys.argv[1],int(sys.argv[-1])); ",
                "print(json.dumps(dict(text=text,digest=digest)))\n",
                "except RubricFailure as e:\n",
                " print(e.evidence);sys.exit(2)\n",
            ),
            include_str!("../src/runner/sign_in_policy.py")
        );
        result
            .arguments
            .push(fixture.0.join("rubric").to_string_lossy().into());
    }
    if matches!(case, "vendor" | "cancellation") {
        let events = fixture.0.join("events");
        let vendor = if case == "vendor" {
            concat!(
                "#!/usr/bin/python3\n",
                "import json,sys\n",
                "sys.stdin.read()\n",
                "print(json.dumps({'type':'item.completed','item':{'type':'agent_message','t",
                "ext':'fixture verdict'}}))\n",
            )
            .into()
        } else {
            format!(
                concat!(
                    "#!/usr/bin/python3\n",
                    "import json,os,signal,time\n",
                    "read_end,write_end=os.pipe();child=os.fork()\n",
                    "if child==0:\n",
                    " os.close(read_end);os.setsid();signal.alarm(180)\n",
                    " os.write(write_end,b'R');os.close(write_end)\n",
                    " while True: signal.pause()\n",
                    "os.close(write_end);assert os.read(read_end,1)==b'R';os.close(read_end)\n",
                    "value=dict(parent=os.getpid(),child=child)\n",
                    "with open({path},'w') as f: json.dump(value,f)\n",
                    "os.chmod({path},0o644)\n",
                    "os.rename({path},{ready})\n",
                    "signal.alarm(180)\n",
                    "while True: signal.pause()\n",
                ),
                path = json!(events.join("pending")),
                ready = json!(events.join("ready"))
            )
        };
        file(&fixture.0.join("vendor"), vendor.as_bytes(), 0o755);
        result.source = format!(
            concat!(
                "{}\n",
                "{}\n",
                "{}\n",
                "with open({},'w') as done: json.dump(RESULT,done)\n",
                "os.chmod({},0o644)\n",
                "os.rename({},{})\n",
            ),
            include_str!("../src/runner/sign_in_policy.py"),
            include_str!("../src/runner/program_policy.py"),
            include_str!("../src/runner/agent_runner.py"),
            json!(events.join("done-pending")),
            json!(events.join("done-pending")),
            json!(events.join("done-pending")),
            json!(events.join("done"))
        );
        result.arguments = vec![
            fixture.0.join("vendor").to_string_lossy().into(),
            "fixture".into(),
            "low".into(),
            "120000".into(),
            fixture.0.join("rubric").to_string_lossy().into(),
            "4102444800".into(),
        ];
        result.input = "{}".into();
    }
    result
}

fn completed_cancellation(fixture: &Fixture, signalled: bool) {
    assert!(signalled, "vendor readiness must precede cancellation");
    let until = Instant::now() + HANG;
    let done = fixture.0.join("events/done");
    while !done.try_exists().unwrap() {
        assert!(
            Instant::now() < until,
            "consumer did not finish cancellation"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let result: Value = serde_json::from_slice(&fs::read(done).unwrap()).unwrap();
    assert_eq!(result["reason"], "door-agent-cancelled", "{result}");
    assert_eq!(
        result["runner_evidence"]["children_reaped"], true,
        "{result}"
    );
    assert_eq!(
        result["runner_evidence"]["private_directory_removed"], true,
        "{result}"
    );
    let ready: Value =
        serde_json::from_slice(&fs::read(fixture.0.join("events/ready")).unwrap()).unwrap();
    for name in ["parent", "child"] {
        assert!(
            !Path::new(&format!("/proc/{}", ready[name])).exists(),
            "{name} survived: {ready}"
        );
    }
    let script = concat!(
        "import os,sys; assert os.listdir(sys.argv[1]+",
        "'/.var/loops/alpha/private/.run/door-agent')==[]"
    );
    let checked = output(namespace(script, &fixture.0).stdin(Stdio::null()), |_| {});
    assert!(checked.status.success(), "private cleanup: {checked:?}");
    writeln!(
        std::io::stdout().lock(),
        "door cancellation evidence: {result}"
    )
    .expect("fixture result");
}

fn unsealed(invocation: &Invocation) -> HostPin {
    let mut writable = File::from(
        memfd_create(
            "unsealed",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )
        .unwrap(),
    );
    writable
        .write_all(&serde_json::to_vec(invocation).unwrap())
        .unwrap();
    nix::sys::stat::fchmod(
        &writable,
        nix::sys::stat::Mode::from_bits_truncate(anchor::READONLY_PRIVATE_MODE),
    )
    .unwrap();
    let readonly = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd()))
        .unwrap()
        .into();
    HostVerifier::current()
        .unwrap()
        .retain_readonly_file(&readonly, "invocation", 6)
        .unwrap()
}

fn frame(
    case: &str,
    operation: Operation,
    fixture: &Fixture,
    entry: &Path,
    invocation: &Invocation,
) -> (Vec<HostPin>, Manifest) {
    let mut pins = pins(fixture, entry, operation, invocation);
    if case == "invocation-unsealed" {
        pins[6] = unsealed(invocation);
    }
    let mut manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.name().into(),
        loop_name: "alpha".into(),
        records: pins.iter().map(HostPin::record).collect(),
    };
    if case == "entry-image" || case == "identity" {
        let slot = if case == "entry-image" { 1 } else { 4 };
        let host = HostVerifier::current().unwrap();
        pins[slot] = host
            .pin(
                Path::new("/usr/bin/false"),
                door_frame::PURPOSES[slot],
                slot.try_into().unwrap(),
                anchor::Policy {
                    kind: anchor::Kind::File,
                    owner: Owner::RootFile,
                    mode: anchor::ModePolicy::Executable,
                },
            )
            .unwrap();
        manifest.records[slot] = pins[slot].record();
    }
    match case {
        "count" => {
            manifest.records.pop();
        }
        "frame-before-config" => {
            manifest.records[3].purpose = "other".into();
            fs::remove_file(fixture.0.join(".config/loops/registry.toml")).unwrap();
        }
        "override-first" => {
            fs::remove_file(fixture.0.join(".config/loops/registry.toml")).unwrap();
        }
        "purpose" => manifest.records[3].purpose = "other".into(),
        "operation" => manifest.operation = "door-metadata".into(),
        "loop" => manifest.loop_name = "other".into(),
        "registry-uid" => {
            let path = fixture.0.join(".config/loops/registry.toml");
            let text = fs::read_to_string(&path).unwrap().replace("41001", "41002");
            fs::write(path, text).unwrap();
        }
        "private-owner" => {
            let changed = output(
                namespace(
                    "import os,sys; os.chown(sys.argv[1]+'/.var/loops/alpha/private',41000,41000)",
                    &fixture.0,
                )
                .stdin(Stdio::null()),
                |_| {},
            );
            assert!(changed.status.success(), "owner change: {changed:?}");
        }
        "mode" => fs::set_permissions(
            fixture.0.join(".var/loops/alpha"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap(),
        _ => {}
    }
    (pins, manifest)
}

fn run(case: &str, operation: Operation) {
    let fixture = Fixture::new();
    let package = PathBuf::from(
        std::env::var_os("SUPERLOOP_TEST_BINARY")
            .expect("build package and set SUPERLOOP_TEST_BINARY"),
    );
    // The actual package image lives beneath the fixture's visible bind mount.
    // A pathname reopen must work in the control and fail only after replacement.
    let entry = fixture.0.join("entry");
    fs::copy(&package, &entry).unwrap();
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o755)).unwrap();
    let invocation = invocation(case, &fixture);
    let (pins, manifest) = frame(case, operation, &fixture, &entry, &invocation);
    let (sender, input) = UnixStream::pair().unwrap();
    let mut fds: Vec<_> = pins.into_iter().map(HostPin::into_fd).collect();
    if case == "short" {
        fds.pop();
    }
    if case == "excess" {
        fds.push(fds[0].as_fd().try_clone_to_owned().unwrap());
    }
    anchor::transport::send(&sender, &fds).unwrap();
    drop(sender);
    let word = match operation {
        Operation::Rubric => "_door-rubric",
        Operation::Agent => "_door-agent",
        Operation::Metadata => "_door-metadata",
    };
    let mut command = namespace(MOUNT, &fixture.0);
    command
        .arg(&entry)
        .arg(word)
        .arg(&fixture.0)
        .args(["alpha", "--anchor-manifest"])
        .arg(serde_json::to_string(&manifest).unwrap())
        .stdin(std::os::fd::OwnedFd::from(input))
        .env("SHOULD_NOT_SURVIVE", "ambient");
    if case == "consumer-uid" {
        command.env("DOOR_FIXTURE_WRONG_UID", "1");
    }
    if case == "entry-unlinked" {
        command.env("DOOR_FIXTURE_UNLINK", "1");
    }
    if matches!(case, "override" | "override-first") {
        command.env("ENTER_LOOP_REGISTRY", "");
    }
    if matches!(case, "not-socket" | "override-first") {
        command.stdin(Stdio::null());
    }
    let mut signalled = false;
    let result = output(&mut command, |pid| {
        if case == "cancellation"
            && !signalled
            && fixture.0.join("events/ready").try_exists().unwrap()
        {
            nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid.cast_signed()),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap();
            signalled = true;
        }
    });
    if case == "cancellation" {
        completed_cancellation(&fixture, signalled);
        writeln!(std::io::stdout().lock(), "door receiver case {case} passed")
            .expect("fixture result");
        return;
    }
    check_result(case, &fixture, &result);
}

fn check_result(case: &str, fixture: &Fixture, result: &Output) {
    let stderr = String::from_utf8_lossy(&result.stderr);
    let expected = match case {
        "count" | "purpose" | "operation" | "loop" | "frame-before-config" => {
            Some("anchor-declaration")
        }
        "mode" => Some("anchor-mode"),
        "registry-uid" | "private-owner" => Some("anchor-owner"),
        "invocation-unsealed" => Some("sealed-readonly-0400"),
        "entry-image" => Some("anchor-identity"),
        "short" | "excess" => Some("anchor-transport"),
        "override" | "override-first" => Some("registry-override"),
        "not-socket" => Some("purpose=rights-socket"),
        "consumer-uid" => Some("purpose=identity check=loop-uid"),
        _ => None,
    };
    if let Some(expected) = expected {
        assert_eq!(result.status.code(), Some(2), "{case}: {result:?}");
        assert!(stderr.contains(expected), "{case}: {result:?}");
    } else if case == "rubric-owner" {
        assert_eq!(result.status.code(), Some(2), "{case}: {result:?}");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("file-owner"),
            "{result:?}"
        );
    } else if case == "rubric-read" {
        assert!(result.status.success(), "{case}: {result:?}");
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["text"], "Reviewed fixture rubric.\n");
    } else if case == "vendor" {
        assert!(result.status.success(), "{case}: {result:?}");
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["text"], "fixture verdict", "{value}");
        assert_eq!(value["runner_evidence"]["loop_uid"], UID);
    } else if case == "identity" {
        assert!(
            !result.status.success() && !stderr.contains("anchor-"),
            "{case}: {result:?}"
        );
    } else {
        assert!(result.status.success(), "{case}: {result:?}");
        let value: Value = serde_json::from_slice(&result.stdout).expect("contract JSON");
        assert_eq!(value["uid"], UID, "{case}: {value}");
        assert_eq!(value["euid"], UID);
        assert_eq!(value["gid"], UID);
        assert_eq!(value["groups"], json!([]));
        assert_eq!(value["nnp"], 1);
        assert_eq!(value["death"], 15);
        assert_eq!(value["subreaper"], 1);
        assert_eq!(value["umask"], 0o077);
        assert_eq!(value["fds"], json!([0, 1, 2]), "{result:?}");
        assert_eq!(value["expected"], UID.to_string());
        assert_eq!(value["loop"], "alpha");
        let private = fs::metadata(fixture.private()).unwrap();
        assert_eq!(value["cwd"], json!([private.dev(), private.ino()]));
        assert_eq!(value["account"][0], "alpha");
        assert_eq!(value["account"][5], fixture.private().to_str().unwrap());
        assert_eq!(
            value["env"],
            json!({
                "HOME":fixture.private(),"TMPDIR":fixture.private().join(".run"),
                "PATH":"/usr/bin:/bin","LANG":"C.UTF-8"
            })
        );
        writeln!(std::io::stdout().lock(), "door environment {case}: {value}")
            .expect("fixture result");
    }
    writeln!(std::io::stdout().lock(), "door receiver case {case} passed").expect("fixture result");
}

/// ´claim:loophome:door-receiver-retains-entry-and-isolates-consumer´
/// ´test:integration:door-receiver-retains-entry-and-measures-consumer´
#[test]
fn door_receiver_retains_entry_and_measures_consumer() {
    for case in [
        "agent",
        "frame-before-config",
        "rubric",
        "metadata",
        "entry-unlinked",
        "entry-image",
        "identity",
        "count",
        "purpose",
        "operation",
        "loop",
        "mode",
        "short",
        "excess",
        "override",
        "not-socket",
        "rubric-read",
        "rubric-owner",
        "vendor",
        "cancellation",
        "registry-uid",
        "private-owner",
        "invocation-unsealed",
        "consumer-uid",
        "override-first",
    ] {
        let operation = match case {
            "rubric" => Operation::Rubric,
            "metadata" => Operation::Metadata,
            _ => Operation::Agent,
        };
        run(case, operation);
    }
    writeln!(std::io::stdout().lock(), "door receiver passed").expect("fixture result");
}
