//! Canonical mail plus a complete synthetic installed runtime, never an invented preflight.
use crate::fixture;
use fixture::bounded::CommandOutput as _;
use loop_home::anchor::{self, Manifest, Transport};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub(super) struct Host {
    root: fixture::Fixture,
    lane: PathBuf,
    runtime: PathBuf,
}
impl Host {
    pub(super) fn new() -> Self {
        let root = fixture::Fixture::new();
        let home = &root.0;
        let lane = std::env::current_exe()
            .expect("test image")
            .ancestors()
            .map(|p| p.join("superloop-lane"))
            .find(|p| p.is_file())
            .expect("built lane binary");
        seed(home);
        let runtime = super::install::configure(home);
        let host = Self {
            root,
            lane,
            runtime,
        };
        host.record();
        host.bind();
        host
    }
    pub(super) fn helper_preflights(&self) -> usize {
        fs::read_to_string(self.root.0.join("entry-calls"))
            .expect("real private entry trace")
            .lines()
            .filter(|line| *line == "_container-helper")
            .count()
    }
    pub(super) fn reservation(&self) -> Vec<u8> {
        fs::read(self.root.0.join("runs/.reservation-R.json")).expect("raw reservation")
    }
    pub(super) fn inventory(&self) -> Vec<u8> {
        let output = mapped(
            &self.root.0,
            r"
import os,sys,json,stat
root=sys.argv[1];rows=[]
for base,dirs,files in os.walk(root+'/runs'):
 for name in sorted(dirs+files):
  p=os.path.join(base,name);s=os.lstat(p)
  data=open(p,'rb').read().hex() if stat.S_ISREG(s.st_mode) else None
  rows.append([os.path.relpath(p,root),s.st_uid,s.st_gid,s.st_mode,data])
print(json.dumps(sorted(rows)))
",
        );
        output.stdout
    }
    pub(super) fn launch(&self, dry: bool) -> Result<Value, superloop_lane::error::LaneError> {
        let mut words = vec![
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "review".into(),
        ];
        if dry {
            words.push("--dry-run".into());
        }
        let mut request = superloop_lane::launch::LaunchRequest::parse(&words)?;
        request.podman_bin.clone_from(&self.runtime);
        superloop_lane::launch::rounds::resume_with_host_root(
            &self.root.0,
            &request,
            &self.root.0,
            nix::unistd::Uid::effective().as_raw(),
            |_| panic!("observing fixture needs no proxy reply"),
            &mut |_| panic!("preview starts no driver"),
            &self.lane,
        )
    }
    fn bind(&self) {
        let request = superloop_lane::launch::steering::Request::parse(&[
            "alpha".into(),
            "R".into(),
            "--step".into(),
            "review".into(),
            "--delivery".into(),
            "2026-01-01T00:00:00.001Z".into(),
        ])
        .expect("mail selection");
        let report = superloop_lane::launch::steering::run_from(
            &self.root.0,
            &request,
            false,
            (
                &self.root.0,
                nix::unistd::Uid::effective().as_raw(),
                Some(&self.lane),
            ),
        )
        .expect("production public mail binding");
        let identity =
            loop_home::mail::birth::Identity::for_reservation(64010, "superloop-lane:R".into());
        assert_eq!(
            report["mail"]["recipient"],
            format!("alpha+{}", identity.name)
        );
    }
    fn record(&self) {
        let home = &self.root.0;
        let (mut plan, _) =
            superloop_lane::load_plan(home, "alpha", "R", (0, 0)).expect("host plan");
        plan.select_worker_uid(64010).expect("worker");
        plan.select_container_program(&self.runtime)
            .expect("runtime");
        plan.observe_vendor().expect("observing fixture");
        let model = json!({"model":"gpt-6-sol","effort":"high"});
        plan.select_launch_model(&model).expect("model");
        let identity =
            loop_home::mail::birth::Identity::for_reservation(64010, "superloop-lane:R".into());
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R",
            "worker_uid":64010,"mail_birth":identity,"mail":[],"mail_replies":[],
            "plan":plan.document,"model_selection":model,"thread_id":"fixture-thread",
            "active_round":"dispatch","letter_source":home.join("first-letter"),
            "rounds":[{"step":"dispatch","phase":"settled","driver_dir":home.join("runs/R/fixture-dispatch")}]});
        write(
            home.join("runs/.reservation-R.json"),
            serde_json::to_vec(&record).expect("record"),
            0o600,
        );
        mapped(
            home,
            &format!(
                "{}\nworker={}\n{}",
                MAP_SETUP,
                serde_json::to_string(&plan.home).expect("worker"),
                MAP_WORKER
            ),
        );
    }
}
pub(super) fn write(path: PathBuf, bytes: impl AsRef<[u8]>, mode: u32) {
    fs::write(&path, bytes).expect("fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture file mode");
}
pub(super) fn directory(path: PathBuf, mode: u32) {
    fs::create_dir_all(&path).expect("fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture directory mode");
}
pub(super) fn mapped(home: &Path, source: &str) -> std::process::Output {
    let output = Command::new("/usr/bin/podman")
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", source])
        .arg(home)
        .fixture_output("mapped host fixture", Duration::from_secs(60))
        .expect("namespace");
    assert!(output.status.success(), "{output:?}");
    output
}
fn seed(home: &Path) {
    fixture::configuration(home);
    let result = fixture::child_command(home, "seed")
        .fixture_output("host seed", Duration::from_secs(60))
        .expect("seed");
    assert!(result.status.success(), "{result:?}");
    let owner = File::open(home).expect("owner").into();
    let runs = File::open(home.join("runs")).expect("runs").into();
    let image = std::env::current_exe().expect("seed image");
    let pins = loop_home::mail::reply_entry::pins(
        (home, &owner),
        (&home.join("runs"), &runs),
        &image,
        "alpha",
    )
    .expect("production seed pins");
    let manifest = Manifest {
        version: 1,
        operation: "mail-binding".into(),
        loop_name: "alpha".into(),
        transport: Transport::Rights,
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("rights");
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .expect("seed handoff");
    let result = fixture::child_command(home, "package-canonical-inbound-seed")
        .env(
            "LOOP_HOME_REPLY_MANIFEST",
            serde_json::to_string(&manifest).expect("manifest"),
        )
        .stdin(OwnedFd::from(input))
        .fixture_spawn("canonical delivery", Duration::from_secs(60))
        .expect("seed child")
        .wait()
        .expect("seed output");
    assert!(result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("PACKAGE-DELIVERY"),
        "{result:?}"
    );
}

const MAP_SETUP: &str = r#"
import os,sys,json,base64,time,datetime
from pathlib import Path
home=Path(sys.argv[1])
for p in [home,home/'runs',home/'.var',home/'.var/loops',home/'.var/loops/alpha']:
 os.chmod(p,0o711)
p=home/'runs/.launch-R';p.mkdir(mode=0o700,exist_ok=True)
for name,data in [('passwd','worker:x:64010:64010::/home/worker:/bin/sh\n'),('group','worker:x:64010:\nloop:x:64000:worker\n')]:
 f=p/name;f.write_text(data);os.chmod(f,0o440);os.chown(f,0,64000)
os.chown(home/'.var/loops/alpha/runner-templates/codex'/('a'*64)/'libexec/ssh',0,64000)
for name in ['R','R/launch','R/fixture-dispatch']:
 p=home/'runs'/name;p.mkdir(mode=0o700,exist_ok=True);os.chmod(p,0o700);os.chown(p,64000,64000)
p=home/'runs/R/launch/runtime.env';p.write_bytes(b'SUPERLOOP_CLIENT_ROOT_DEV=1\0SUPERLOOP_CLIENT_ROOT_INO=2\0');os.chmod(p,0o440);os.chown(p,0,64000)
for name,data in [('events.jsonl','{\"type\":\"thread.started\",\"thread_id\":\"fixture-thread\"}\n'),('.event-start','0\n')]:
 p=home/'runs/R/fixture-dispatch'/name;p.write_text(data);os.chmod(p,0o600);os.chown(p,64000,64000)
"#;
const MAP_WORKER: &str = r"
p=Path(worker);p.mkdir(mode=0o700,parents=True,exist_ok=True)
os.chown(p,0,0);os.chmod(p,0o700)
p=p/'.codex';p.mkdir(mode=0o700,exist_ok=True);os.chown(p,64010,64010);os.chmod(p,0o700)
payload=base64.urlsafe_b64encode(json.dumps({'exp':int(time.time())+86400}).encode()).decode().rstrip('=')
token='header.'+payload+'.signature'
source={'auth_mode':'chatgpt','OPENAI_API_KEY':None,'tokens':{'id_token':token,'access_token':token,'refresh_token':'fixture-refresh','account_id':'fixture-account'},'last_refresh':datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
p=home/'.config/loops/alpha/lanes/codex/auth.json';p.write_text(json.dumps(source));os.chmod(p,0o600)
";
