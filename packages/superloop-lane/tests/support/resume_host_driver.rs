//! Declared driver stand-in: real mapped loop identity, event/report files and mail publication.
use crate::host;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub(super) fn child(args: &[String]) -> std::process::ExitCode {
    let home = PathBuf::from(args.first().expect("fixture home"));
    assert_eq!(args.get(1).map(String::as_str), Some("driver-launch"));
    let meta = std::fs::symlink_metadata(&home).expect("fixture root");
    let fixture = host::Host::borrowed(home.clone(), (meta.dev(), meta.ino()));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let record: serde_json::Value =
            serde_json::from_slice(&fixture.reservation()).expect("record");
        if record["driver_entry_pid"] == std::process::id()
            && record.get("round_rollback").is_none()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "driver PID and intent-consumption publication"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").expect("driver cgroup");
    assert!(
        cgroup.trim_end().ends_with("/work"),
        "driver in real work scope: {cgroup}"
    );
    let _attempt = host::mapped(&home, CLIENT);
    fixture.reply();
    let output = host::mapped(&home, DRIVER);
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("driver terminal report");
    std::process::ExitCode::SUCCESS
}
const DRIVER: &str = r"
import os,sys,json
from pathlib import Path
home=Path(sys.argv[1]);record=json.loads((home/'runs/.reservation-R.json').read_text())
runs=home/'runs';run=runs/'R'
assert (runs.stat().st_uid,runs.stat().st_mode&0o777)==(0,0o711)
assert (run.stat().st_uid,run.stat().st_mode&0o777)==(64000,0o700)
assert record['phase']=='started' and record['active_round']=='review'
p=Path(record['rounds'][-1]['driver_dir']);os.chdir(p)
os.setgroups([]);os.setgid(64000);os.setuid(64000)
assert os.geteuid()==64000 and int(os.readlink('/proc/self'))==os.getpid()
assert Path('/proc/self/cgroup').read_text().strip().endswith('/work')
line='RUN-REPORT lane=review exit=0 wall=0s budget=3600s verdict=OK dir='+str(p)
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
assert record['phase']=='preparing' and record['active_round']=='review'
run=home/'runs/R';request=json.loads((run/'round-launch-review.json').read_text())
assert request['thread_id']=='fixture-thread'
prompt=('Read /mail/inbox/'+request['mail']['inbox_name']+'. Step review.').encode()
payload=b'\0'+request['thread_id'].encode()+b'\0'+prompt
step=Path(record['rounds'][-1]['driver_dir']);held=os.open(step,os.O_RDONLY|os.O_DIRECTORY)
os.chdir(home/'runs');os.setgroups([]);os.setgid(64000);os.setuid(64000)
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
assert ended.poll(30000),'actual helper completion event'
os.close(helper_exit);os.fchdir(held);os.close(held)
events=Path('events.jsonl');offset=events.stat().st_size
archive=Path('steps/dispatch');archive.mkdir(mode=0o700,parents=True)
os.chmod(archive.parent,0o700)
for name,value in [('event-start.txt',0),('event-end.txt',offset)]:
 leaf=archive/name;leaf.write_text(str(value)+'\n');os.chmod(leaf,0o600)
Path('.event-start').write_text(str(offset)+'\n');os.chmod('.event-start',0o600)
assert any(json.loads(line).get('thread_id')=='fixture-thread' for line in out.splitlines()),out
with events.open('ab') as target:target.write(out)
identity={'pid':os.getpid(),'proc_self':int(os.readlink('/proc/self')),'uid':os.geteuid(),'gid':os.getegid(),'helper_pid':pid,'helper_uid':uid,'cgroup':Path('/proc/self/cgroup').read_text()}
Path('fixture-driver-identity.json').write_text(json.dumps(identity));os.chmod('fixture-driver-identity.json',0o600)
print('REAL-HELPER-ATTEMPT '+json.dumps(identity))
";
