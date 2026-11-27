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
    _root: Option<fixture::Fixture>,
    home: PathBuf,
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
            home: root.0.clone(),
            _root: Some(root),
            lane,
            runtime,
        };
        host.record();
        host.dispatch_observer();
        host.bind();
        host
    }
    pub(super) fn home(&self) -> &Path {
        &self.home
    }
    pub(super) fn borrowed(home: PathBuf, expected: (u64, u64)) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        let meta = fs::symlink_metadata(&home).expect("fixture root");
        assert!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "plain fixture root"
        );
        assert_eq!(
            (meta.dev(), meta.ino()),
            expected,
            "retained parent fixture identity"
        );
        assert_eq!(
            fs::read(home.join(".reply-fixture")).expect("marker"),
            b"owned by reply fixture parent\n"
        );
        let lane = std::env::current_exe()
            .expect("image")
            .ancestors()
            .map(|p| p.join("superloop-lane"))
            .find(|p| p.is_file())
            .expect("built lane");
        Self {
            _root: None,
            runtime: home.join("container-fixture"),
            home,
            lane,
        }
    }
    fn dispatch_observer(&self) {
        let program = PathBuf::from(env!("CARGO_BIN_EXE_superloop-lane-vendor-proxy"));
        mapped(
            &self.home,
            &format!(
                "proxy={}\n{}",
                serde_json::to_string(&program).expect("proxy path"),
                OBSERVER
            ),
        );
    }
    pub(super) fn deliver_reply(&self) {
        let _delivery = delivery(&self.home, "package-canonical-reply");
    }
    pub(super) fn deliver_reply_now(&self) -> String {
        delivery(&self.home, "package-canonical-reply-now")
    }
    pub(super) fn reply(&self) {
        self.bind_reply().expect("production reply binding");
    }
    pub(super) fn bind_reply(&self) -> Result<Value, superloop_lane::error::LaneError> {
        let record: Value = serde_json::from_slice(&self.reservation()).expect("active record");
        let step = record["active_round"].as_str().expect("active step");
        self.bind_reply_for(step)
    }
    pub(super) fn bind_reply_for(
        &self,
        step: &str,
    ) -> Result<Value, superloop_lane::error::LaneError> {
        let record: Value = serde_json::from_slice(&self.reservation()).expect("active record");
        if !self.home.join("late-reply").exists()
            && record["mail_replies"].as_array().is_none_or(Vec::is_empty)
        {
            let _delivery = delivery(&self.home, "package-canonical-reply");
        }
        let request = superloop_lane::launch::steering::Request::parse(&[
            "alpha".into(),
            "R".into(),
            "--step".into(),
            step.into(),
            "--delivery".into(),
            "2026-01-01T00:00:00.002Z".into(),
        ])
        .expect("reply selection");
        superloop_lane::launch::steering::run_from(
            &self.home,
            &request,
            true,
            (
                &self.home,
                nix::unistd::Uid::effective().as_raw(),
                Some(&self.lane),
            ),
        )
    }
    pub(super) fn place(&self) {
        let parent = self.home.join("placement-parent");
        directory(parent.clone(), 0o700);
        let root = parent.join("R");
        let input = json!({"grant":{"schema":1,"loop":"alpha","run":"R",
            "node":"fixture-node","workspace":root,
            "baseline_env":[["PATH","/usr/bin"],["CARGO_TARGET_DIR",root.join("target")],
                ["CARGO_HOME",root.join("cargo")],["TMPDIR",root.join("tmp")]],
            "resources":{},"shells":["/bin/sh"],"quick_policy_digest":"a".repeat(64),
            "blacklist_digest":"b".repeat(64),"executor_protocol":1},
            "baseline_environment_is_public":true})
        .to_string();
        let preview = superloop_lane::placement::commands::prepare(&parent, &input, None, true)
            .expect("owner placement preview");
        let placed = superloop_lane::placement::commands::prepare(
            &parent,
            &input,
            preview["preview_sha256"].as_str(),
            false,
        )
        .expect("owner placement publication");
        let mut record: Value = serde_json::from_slice(&self.reservation()).expect("record");
        record["plan"]["compute_workspace"] = preview["compute_workspace"].clone();
        record["plan"]["compute_placement"] = placed["declaration"]["compute_placement"].clone();
        assert_eq!(record["plan"]["compute_placement"]["root"], json!(root));
        assert_eq!(record["plan"]["compute_placement"]["run"], "R");
        write(
            self.home.join("runs/.reservation-R.json"),
            serde_json::to_vec(&record).expect("placed record"),
            0o600,
        );
    }
    pub(super) fn helper_preflights(&self) -> usize {
        fs::read_to_string(self.home.join("entry-calls"))
            .expect("real private entry trace")
            .lines()
            .filter(|line| *line == "_container-helper")
            .count()
    }
    pub(super) fn reservation(&self) -> Vec<u8> {
        fs::read(self.home.join("runs/.reservation-R.json")).expect("raw reservation")
    }
    pub(super) fn inventory(&self) -> Vec<u8> {
        let output = mapped(
            &self.home,
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
        self.launch_choice(dry, false)
    }
    pub(super) fn launch_choice(
        &self,
        dry: bool,
        resume: bool,
    ) -> Result<Value, superloop_lane::error::LaneError> {
        let mut words = vec![
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "review".into(),
        ];
        if self.home.join("over-budget").exists() {
            words.extend(["--budget".into(), "7200".into()]);
        }
        if resume {
            words.push("--resume-thread".into());
        }
        if dry {
            words.push("--dry-run".into());
        }
        let mut request = superloop_lane::launch::LaunchRequest::parse(&words)?;
        request.podman_bin.clone_from(&self.runtime);
        self.round_request(&request)
    }
    pub(super) fn recover(
        &self,
        digest: Option<&str>,
    ) -> Result<Value, superloop_lane::error::LaneError> {
        let mut words = vec![
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "review".into(),
        ];
        if let Some(digest) = digest {
            words.extend(["--expect-digest".into(), digest.into()]);
        } else {
            words.push("--dry-run".into());
        }
        let mut request = superloop_lane::launch::LaunchRequest::parse(&words)?;
        request.podman_bin.clone_from(&self.runtime);
        self.round_request(&request)
    }
    pub(super) fn settle(
        &self,
        digest: Option<&str>,
    ) -> Result<Value, superloop_lane::error::LaneError> {
        let mut words = vec![
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "review".into(),
        ];
        if let Some(digest) = digest {
            words.extend(["--expect-digest".into(), digest.into()]);
        } else {
            words.push("--dry-run".into());
        }
        let request = superloop_lane::launch::settle::SettleRequest::parse(&words)?;
        superloop_lane::launch::settle::run_with_host_root(
            &self.home,
            &request,
            &self.home,
            nix::unistd::Uid::effective().as_raw(),
            &self.lane,
            &mut |_| {},
        )
    }
    pub(super) fn next_launch(
        &self,
        choose: bool,
        dry: bool,
    ) -> Result<Value, superloop_lane::error::LaneError> {
        let binding = superloop_lane::launch::steering::Request::parse(&[
            "alpha".into(),
            "R".into(),
            "--step".into(),
            "after".into(),
            "--delivery".into(),
            "2026-01-01T00:00:00.001Z".into(),
        ])
        .expect("next delivery binding");
        superloop_lane::launch::steering::run_from(
            &self.home,
            &binding,
            false,
            (
                &self.home,
                nix::unistd::Uid::effective().as_raw(),
                Some(&self.lane),
            ),
        )?;
        let mut words = vec!["alpha".into(), "R".into(), "--round".into(), "after".into()];
        if dry {
            words.push("--dry-run".into());
        }
        if choose {
            words.push("--resume-thread".into());
        }
        let mut request = superloop_lane::launch::LaunchRequest::parse(&words)?;
        request.podman_bin.clone_from(&self.runtime);
        self.round_request(&request)
    }
    fn round_request(
        &self,
        request: &superloop_lane::launch::LaunchRequest,
    ) -> Result<Value, superloop_lane::error::LaneError> {
        superloop_lane::launch::rounds::resume_with_host_root(
            &self.home,
            request,
            &self.home,
            nix::unistd::Uid::effective().as_raw(),
            |_| panic!("observing fixture needs no proxy reply"),
            &mut |_| assert!(!request.dry_run, "preview starts no driver"),
            &self.lane,
            if fs::read_to_string(self.home.join("fixture-fault"))
                .is_ok_and(|fault| fault == "stop-race")
            {
                // The real helper is paused at its unlink event, not merely slow.
                Duration::ZERO
            } else {
                Duration::from_secs(90)
            },
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
            &self.home,
            &request,
            false,
            (
                &self.home,
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
        let home = &self.home;
        let (mut plan, _) =
            superloop_lane::load_plan(home, "alpha", "R", (0, 0)).expect("host plan");
        assert_ne!(
            plan.document["worker_uid"], 64010,
            "public fixture worker must differ from allocation base"
        );
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
            "rounds":[{"step":"dispatch","phase":"settled","driver_dir":home.join("runs/R/fixture-dispatch"),"reply_designation":{"state":"unmeasured"}}]});
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
        .env("TMPDIR", home.parent().expect("owned temporary root"))
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", source])
        .arg(home)
        .fixture_output("mapped host fixture", Duration::from_secs(180))
        .expect("namespace");
    assert!(output.status.success(), "{output:?}");
    output
}
fn seed(home: &Path) {
    fixture::configuration(home);
    let allocation = home.join(".config/loops/allocations.toml");
    let text = fs::read_to_string(&allocation).expect("fixture allocation");
    write(
        allocation,
        text.replace("uids={base=64010,count=2}", "uids={base=64009,count=3}")
            .replace(
                "mail_gids={base=64020,count=3}",
                "mail_gids={base=64020,count=4}",
            ),
        0o600,
    );
    let result = fixture::child_command(home, "seed")
        .fixture_output("host seed", Duration::from_secs(180))
        .expect("seed");
    assert!(result.status.success(), "{result:?}");
    let _delivery = delivery(home, "package-canonical-inbound-seed");
}
fn delivery(home: &Path, phase: &str) -> String {
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
    let result = fixture::child_command(home, phase)
        .env("TMPDIR", home.parent().expect("owned temporary root"))
        .env(
            "LOOP_HOME_REPLY_MANIFEST",
            serde_json::to_string(&manifest).expect("manifest"),
        )
        .stdin(OwnedFd::from(input))
        .fixture_spawn("canonical delivery", Duration::from_secs(180))
        .expect("seed child")
        .wait()
        .expect("seed output");
    assert!(result.status.success(), "{result:?}");
    let output = String::from_utf8(result.stdout).expect("delivery output");
    output
        .split_whitespace()
        .skip_while(|word| *word != "PACKAGE-DELIVERY")
        .nth(1)
        .expect("delivery instant")
        .to_owned()
}

const MAP_SETUP: &str = r#"
import os,sys,json,base64,time,datetime
from pathlib import Path
home=Path(sys.argv[1])
for p in [home,home/'runs',home/'.var',home/'.var/loops',home/'.var/loops/alpha']:
 os.chmod(p,0o711)
p=home/'runs/.launch-R';p.mkdir(mode=0o700,exist_ok=True)
# Completed dispatch evidence is seeded history; this fixture does not run first dispatch.
f=p/'launch-evidence.json';f.write_text(json.dumps({'bound_source_matrix':{'git_worktree':{'add_remove':True}}}));os.chmod(f,0o600)
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

const OBSERVER: &str = r"
import os,sys,json,subprocess
from pathlib import Path
home=Path(sys.argv[1]);file=home/'runs/.reservation-R.json';record=json.loads(file.read_text())
socket_dir=next(Path(m['source']) for m in record['plan']['mounts'] if m['target']=='/home/worker/.local/vendor')
socket_path=socket_dir/record['plan']['vendor_socket']
runs=os.open(home/'runs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
sockets=os.open(socket_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
with open(os.devnull,'r+b') as null:
 child=subprocess.Popen([proxy,'--socket',str(socket_path),'--group','64000','--observe','R',
  '--observed-file',str(home/'runs/.observed-R.txt'),'--verified-runs-root-fd',str(runs),
  '--verified-socket-dir-fd',str(sockets),'--owner-home',str(home)],
  stdin=null,stdout=null,stderr=subprocess.PIPE,pass_fds=(runs,sockets),start_new_session=True)
 try:
  line=child.stderr.readline();assert b'proxy-ready' in line,line
  start=int(Path('/proc',str(child.pid),'stat').read_text().rsplit(')',1)[1].split()[19])
  identity=socket_path.lstat();assert child.poll() is None,'dispatch observer exited early'
  os.killpg(child.pid,15);status=child.wait(timeout=180)
  try: os.killpg(child.pid,0)
  except ProcessLookupError: pass
  else: raise RuntimeError('dispatch observer group remains')
  try: named=socket_path.lstat()
  except FileNotFoundError: socket_state='absent'
  else:
   assert (named.st_dev,named.st_ino)==(identity.st_dev,identity.st_ino)
   socket_path.unlink();socket_state='removed'
  record['observer_pid']=child.pid;record['observer_start']=start
  record['observer_state']='ended';record['observation_end']='completed';record['settlement_uncertain']=False
  record['observer_end']={'state':'stopped','pid':child.pid,'start':start,'already_exited':False,
   'stop_signals':['SIGTERM'],'group_presence':'absent','status':str(status),'socket':{'state':socket_state}}
  file.write_text(json.dumps(record));os.chmod(file,0o600)
  print('DISPATCH-OBSERVER-STOPPED '+str(child.pid))
 finally:
  if child.poll() is None:
   try: os.killpg(child.pid,9)
   except ProcessLookupError: pass
   child.wait()
os.close(runs);os.close(sockets)
";
