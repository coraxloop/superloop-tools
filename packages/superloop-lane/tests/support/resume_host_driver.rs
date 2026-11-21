//! Declared driver stand-in: real mapped loop identity, event/report files and mail publication.
use crate::{fixture::bounded::CommandOutput as _, host};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub(super) fn child(args: &[String]) -> std::process::ExitCode {
    let home = PathBuf::from(args.first().expect("fixture home"));
    assert_eq!(args.get(1).map(String::as_str), Some("driver-launch"));
    let meta = std::fs::symlink_metadata(&home).expect("fixture root");
    let fixture = host::Host::borrowed(home.clone(), (meta.dev(), meta.ino()));
    let publication_started = Instant::now();
    let published = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-c", PUBLICATION])
        .arg(&home)
        .arg(std::process::id().to_string())
        .fixture_output(
            "driver reservation publication event",
            Duration::from_secs(180),
        )
        .expect("publication event wait");
    assert!(
        published.status.success(),
        "publication event: {published:?}"
    );
    let publication_seconds = publication_started.elapsed().as_secs_f64();
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").expect("driver cgroup");
    assert!(
        cgroup.trim_end().ends_with("/work"),
        "driver in real work scope: {cgroup}"
    );
    let helper_started = Instant::now();
    let _attempt = host::mapped(&home, CLIENT);
    host::write(
        home.join("wait-measurements.json"),
        serde_json::json!({"driver_publication":publication_seconds,
            "mapped_helper":helper_started.elapsed().as_secs_f64()})
        .to_string(),
        0o600,
    );
    if home.join("reply-candidates-two").exists() || home.join("reply-candidates-one").exists() {
        let mut instants = vec![fixture.deliver_reply_now()];
        if home.join("reply-candidates-two").exists() {
            std::thread::sleep(Duration::from_millis(2));
            instants.push(fixture.deliver_reply_now());
        }
        host::write(
            home.join("candidate-instants.json"),
            serde_json::to_vec(&instants).expect("candidate instants"),
            0o600,
        );
    } else if home.join("late-reply").exists() {
        fixture.deliver_reply();
    } else if !home.join("without-reply").exists() && !home.join("reply-candidates-none").exists() {
        fixture.reply();
    }
    let output = host::mapped(&home, DRIVER);
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("driver terminal report");
    if home.join("driver-failed").exists() {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
const DRIVER: &str = r"
import os,sys,json
from pathlib import Path
home=Path(sys.argv[1]);record=json.loads((home/'runs/.reservation-R.json').read_text())
runs=home/'runs';run=runs/'R'
assert (runs.stat().st_uid,runs.stat().st_mode&0o777)==(0,0o711)
assert (run.stat().st_uid,run.stat().st_mode&0o777)==(64000,0o700)
assert record['phase']=='started'
failed=(home/'driver-failed').exists();over_budget=(home/'over-budget').exists()
step=record['active_round'];assert step in ('review','after')
p=Path(record['rounds'][-1]['driver_dir']);os.chdir(p)
os.setgroups([]);os.setgid(64000);os.setuid(64000)
assert os.geteuid()==64000 and int(os.readlink('/proc/self'))==os.getpid()
assert Path('/proc/self/cgroup').read_text().strip().endswith('/work')
result='exit=1 wall=0s budget=3600s verdict=FAILED' if failed else 'exit=0 wall=0s budget=3600s verdict=OK'
if over_budget:result='exit=0 wall=7616s budget=7200s verdict=OVER-BUDGET'
line='RUN-REPORT lane='+step+' '+result+' dir='+str(p)
Path('run-report.txt').write_text(line+'\n');os.chmod('run-report.txt',0o600)
print(line)
";

// The stand-in drives the documented wire protocol from a real loop-uid child.
// Its held cwd avoids granting traversal through the account's private test root.
const CLIENT: &str = r"
import os,sys,json,socket,struct,select
from pathlib import Path
home=Path(sys.argv[1]);record=json.loads((home/'runs/.reservation-R.json').read_text())
helper=Path('/proc/'+str(record['helper_pid']))
helper_exit=os.pidfd_open(record['helper_pid'])
assert int(helper.joinpath('stat').read_text().rsplit(')',1)[1].split()[19])==record['helper_start']
assert helper.joinpath('cgroup').read_text().strip().endswith('/work')
assert record['phase']=='preparing'
round_name=record['active_round'];assert round_name in ('review','after')
run=home/'runs/R';request=json.loads((run/('round-launch-'+round_name+'.json')).read_text())
assert request['thread_id']=='fixture-thread'
prompt=('Read /mail/inbox/'+request['mail']['inbox_name']+'. Step '+round_name+'.').encode()
payload=b'\0'+request['thread_id'].encode()+b'\0'+prompt
step=Path(record['rounds'][-1]['driver_dir']);held=os.open(step,os.O_RDONLY|os.O_DIRECTORY)
stop_race=(home/'fixture-fault').exists() and (home/'fixture-fault').read_text()=='stop-race'
os.chdir(home/'runs')
if stop_race:
 import ctypes
 libc=ctypes.CDLL(None,use_errno=True)
 watch=libc.inotify_init1(os.O_CLOEXEC);assert watch>=0
 assert libc.inotify_add_watch(watch,b'.',0x200)>=0
os.setgroups([]);os.setgid(64000);os.setuid(64000)
assert int(os.readlink('/proc/self'))==os.getpid()
assert Path('/proc/self/cgroup').read_text().strip().endswith('/work')
peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.settimeout(30);peer.connect('.container-R.sock')
pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert pid==record['helper_pid'] and uid==0
peer.sendall(struct.pack('<I',len(payload))+payload)
def exact(n):
 data=b''
 while len(data)<n:
  chunk=peer.recv(n-len(data));assert chunk,'real helper final status absent';data+=chunk
 return data
out=b'';err=b''
while True:
 head=exact(5);length=struct.unpack('<I',head[1:])[0];assert length<=8192
 data=exact(length)
 if head[:1]==b'X':
  assert struct.unpack('<i',data)[0]==0,(out,err,data);break
 if head[:1]==b'O':out+=data
 elif head[:1]==b'E':err+=data
 else:raise AssertionError(head)
 assert len(out)+len(err)<=65536
peer.close()
ended=select.poll();ended.register(helper_exit,select.POLLIN)
if stop_race:
 # The real cleanup unlinks before our injected pause. Observe that event rather
 # than a scheduling delay; the host will encounter the actual missing socket.
 while Path('.control-R.sock').exists():
  assert select.select([watch],[],[],180)[0],'control unlink event'
  os.read(watch,65536)
 os.close(watch)
else:
 assert ended.poll(30000),'actual helper completion event'
os.close(helper_exit);os.fchdir(held);os.close(held)
events=Path('events.jsonl');offset=events.stat().st_size
previous_start=int(Path('.event-start').read_text())
archive=Path('steps')/record['rounds'][-2]['step'];archive.mkdir(mode=0o700,parents=True)
os.chmod(archive.parent,0o700)
for name,value in [('event-start.txt',previous_start),('event-end.txt',offset)]:
 leaf=archive/name;leaf.write_text(str(value)+'\n');os.chmod(leaf,0o600)
Path('.event-start').write_text(str(offset)+'\n');os.chmod('.event-start',0o600)
assert any(json.loads(line).get('thread_id')=='fixture-thread' for line in out.splitlines()),out
with events.open('ab') as target:target.write(out)
identity={'pid':os.getpid(),'proc_self':int(os.readlink('/proc/self')),'uid':os.geteuid(),'gid':os.getegid(),'helper_pid':pid,'helper_uid':uid,'cgroup':Path('/proc/self/cgroup').read_text()}
Path('fixture-driver-identity.json').write_text(json.dumps(identity));os.chmod('fixture-driver-identity.json',0o600)
print('REAL-HELPER-ATTEMPT '+json.dumps(identity))
";

// Install the watch before reading: replacement before or during the read cannot
// be lost. Unrelated directory events cause a recheck, never a successful verdict.
const PUBLICATION: &str = r"
import ctypes,json,os,select,sys
from pathlib import Path
runs=Path(sys.argv[1])/'runs';expected=int(sys.argv[2])
libc=ctypes.CDLL(None,use_errno=True)
fd=libc.inotify_init1(os.O_CLOEXEC);assert fd>=0,ctypes.get_errno()
try:
 assert libc.inotify_add_watch(fd,os.fsencode(runs),0x80|0x100|0x8)>=0,ctypes.get_errno()
 while True:
  record=json.loads((runs/'.reservation-R.json').read_bytes())
  if record.get('driver_entry_pid')==expected and 'round_rollback' not in record:break
  assert select.select([fd],[],[],180)[0],'driver publication event hang bound'
  assert os.read(fd,65536),'directory watch ended'
finally:os.close(fd)
";
