"""Synthetic mail population; every service launch uses the installed production entry."""
import os, sys, pathlib, struct, subprocess, json, time
P=pathlib.Path
SERVICE=65535

def acl(path, uid, access, owner=7):
    rows=[(1,owner,0xffffffff),(2,access,uid),(4,0,0xffffffff),(16,access,0xffffffff),(32,0,0xffffffff)]
    os.setxattr(path,'system.posix_acl_access',struct.pack('<I',2)+b''.join(struct.pack('<HHI',*r) for r in rows))
def directory(path,uid=0,gid=0,mode=0o711):
    path.mkdir();os.chown(path,uid,gid);os.chmod(path,mode)
def file(path,text,uid=0,mode=0o600,grant=None):
    path.write_text(text);os.chown(path,uid,uid);os.chmod(path,mode)
    if grant is not None:acl(path,SERVICE,grant,6)
def mailbox(parent,uid,gid):
    directory(parent/'mail',SERVICE,gid,0o750)
    for name in ['inbox','sent']:directory(parent/'mail'/name,SERVICE,gid,0o770)
    for name in ['draft','outbox','read']:directory(parent/'mail'/name,uid,uid,0o700)
    acl(parent/'mail/outbox',SERVICE,7)
    directory(parent/'.mail-staging',SERVICE,SERVICE,0o700)
def seed(home,count,binary):
    assert count>=14 and count<=32242
    directory(home,mode=0o711)
    directory(home/'.config');directory(home/'.config/loops',mode=0o700);acl(home/'.config/loops',SERVICE,1)
    directory(home/'.var');directory(home/'.var/loops',mode=0o755)
    directory(home/'.var/loops/.mail-service',SERVICE,SERVICE,0o700)
    rows=[];alloc=f'mail_uid={SERVICE}\n'
    counts=[(count-14)*2//3,(count-14)-(count-14)*2//3]+[0]*12
    next_uid=1024;next_group=33280
    for i,n in enumerate(counts):
        name=f'loop{i:02}';uid=1000+i;base=next_uid;group=next_group;capacity=max(1,n)
        next_uid+=capacity;next_group+=capacity+1
        rows.append(f'{{name="{name}",uid={uid},launch="dev/{name}"}}')
        alloc+=f'[{name}]\nuids={{base={base},count={capacity}}}\nmail_gids={{base={group},count={capacity+1}}}\n'
        root=home/'.var/loops'/name;directory(root);mailbox(root,uid,group)
        directory(root/'workers',mode=0o755)
        workers=[]
        for j in range(n):
            w=f'worker{j:05}';workers.append(f'{{name="{w}",state="active"}}')
            directory(root/'workers'/w);mailbox(root/'workers'/w,base+j,group+j+1)
        for path in [root/'private',root/'private/.config',root/'private/.config/mail']:
            directory(path,uid,uid,0o700);acl(path,SERVICE,1)
        file(root/'private/.config/mail/loop.toml','workers=['+','.join(workers)+']\n[mail]\nversion=1\nallow=[]\n',uid,grant=4)
    file(home/'.config/loops/registry.toml','namespace="org.superloop-tools.loophome.registry"\nversion=[1,0,0]\nloops=['+','.join(rows)+']\n',grant=4)
    file(home/'.config/loops/allocations.toml',alloc,grant=4)
    file(home/'.config/loops/mail-service.toml',f'version=1\nuid={SERVICE}\ncrash_consistent_rename=true\ndurable_sync=true\n',grant=4)
    descriptor=os.open(binary,os.O_RDONLY)
    os.setgroups([]);os.setgid(SERVICE);os.setuid(SERVICE)
    subprocess.run([f"/proc/self/fd/{descriptor}",'initialize',str(home)],pass_fds=(descriptor,),check=True)
    os.close(descriptor)


import datetime, hashlib, textwrap

def history(home,n):
    root=home/'.var/loops/.mail-service'
    os.setgroups([]);os.setgid(SERVICE);os.setuid(SERVICE)
    base=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=1)
    for i in range(n):
        stamp=(base+datetime.timedelta(milliseconds=i)).isoformat(timespec='milliseconds').replace('+00:00','Z')
        text=f'''version = 1
    delivery = "{stamp}"
    acceptance = "{stamp}"
    sender = "loop00"
    recipient = "loop01"
    outgoing = "loop01.history-{i}.letter"
    bytes = 0
    digest = "{hashlib.sha256(b'').hexdigest()}"
    registry_digest = "{'0'*64}"
    configuration_digests = []
    source_path = "{home}/.var/loops/loop00/.mail-staging/loop01.history-{i}.letter"
    sent_name = "loop01.{stamp}.letter"
    inbox_name = "loop00.{stamp}.letter"
    phase = "complete"
    completed = "{stamp}"
    [source_identity]
    device = 1
    inode = {i+1}
    [recipient_temporary]
    path = "{home}/.var/loops/loop01/.mail-staging/history-{i}"
    [recipient_temporary.identity]
    device = 1
    inode = {i+1}
    '''
        p=root/'deliveries'/f'{stamp}.toml';p.write_text(text);p.chmod(0o600)
    if n:
        (root/'state.toml').write_text(f'version=1\ngreatest_reserved="{stamp}"\nacceptance_available=false\n')

def scan_starts(text):
    return text.count('mail scan started')

def assert_operations(reading):
    assert reading['phases']['wake']=={'open':0,'stat':0,'list':0,'history_reads':0}, 'ordinary wake resolved unrelated mailboxes or read history'
    # Fifty percent headroom over the measured 28/34/6; the unrelated wake and outbox exclusions stay exact.
    for operation,bound in {'open':42,'stat':51,'list':9}.items():
        assert 0<=reading['unrelated_loop_operations'][operation]<=bound, f'unrelated {operation} operations exceeded the selected-delivery bound'
    assert reading['unrelated_directory_reads']['outbox']==0, 'unrelated outbox was listed'
    assert reading['unrelated_directory_reads']['staging']<=3, 'extra unrelated staging walks'
    assert 1<=reading['history_passes']<=3, 'full recovery returned to the selected scan'

def observation_check():
    assert scan_starts('mail scan complete\nmail selected scan complete\n')==0
    assert scan_starts('mail scan started\nmail scan complete\nmail scan started\nmail selected scan complete\n')==2
    sample={'phases':{'wake':{'open':0,'stat':0,'list':0,'history_reads':0}},'unrelated_loop_operations':{'open':35,'stat':40,'list':8},'unrelated_directory_reads':{'outbox':0,'staging':2},'history_passes':2}
    assert_operations(sample) # Harmless extra metadata operations have explicit headroom.
    sample['unrelated_directory_reads']['outbox']=1
    try:assert_operations(sample)
    except AssertionError:pass
    else:raise AssertionError('an unrelated outbox read must fail the operation guard')


def measure(count,binary,tag,post_claim=False,enforce=True,operations=False):
    observation_check()
    root=P(os.environ['TMPDIR'])
    for path in [root,*root.parents]:
        if not path.stat().st_mode & 1:
            raise RuntimeError("fixture needs a searchable disk-backed TMPDIR; no ancestor permission is changed")
    home=root/f'{tag}-{count}'
    evidence=root/f'{tag}-{count}-evidence'
    evidence.mkdir()
    subprocess.run(['/usr/bin/podman','unshare',sys.executable,str(P(__file__).resolve()),'seed',str(home),str(count),binary],check=True)
    history=int(os.environ.get('MAIL_FIXTURE_HISTORY','0'))
    if history:subprocess.run(['/usr/bin/podman','unshare',sys.executable,str(P(__file__).resolve()),'history',str(home),str(history)],check=True)
    log=evidence/f'{tag}-{count}.log'
    with log.open('w') as output:
        process=subprocess.Popen([binary,'serve',str(home)],stdout=output,stderr=output,env={**os.environ,'RUST_LOG':'loop_home::mail::service=debug'})
        (evidence/f'{tag}-{count}.pid').write_text(str(process.pid))
        service_pid=None
        try:
            deadline=time.monotonic()+300
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError(log.read_text())
                if log.read_text().count('phase=complete')>=3 or 'mail scan complete' in log.read_text():break
                time.sleep(.1)
            else:raise RuntimeError('service did not finish initial reconciliation within fixture bound')
            for path in P('/proc').glob('[0-9]*/cmdline'):
                try:command=path.read_bytes().split(b'\0')
                except (OSError,PermissionError):continue
                if len(command)>2 and os.fsdecode(command[0])==binary and command[1]==b'_serve' and os.fsdecode(command[2])==str(home):
                    service_pid=int(path.parent.name);break
            assert service_pid is not None, 'service child must be measured, not its namespace launcher'
            (evidence/f'{tag}-{count}.service-pid').write_text(str(service_pid))
            def cpu():
                fields=P(f'/proc/{service_pid}/stat').read_text().rsplit(')',1)[1].split()
                return (int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')
            inspected=subprocess.run(['/usr/bin/podman','unshare',sys.executable,str(P(__file__).resolve()),'inspect',str(service_pid),str(home)],capture_output=True,text=True,check=True)
            descriptor_count=int(inspected.stdout)
            scan_count=scan_starts(log.read_text());c=cpu();t=time.monotonic();time.sleep(10);elapsed=time.monotonic()-t;used=cpu()-c;idle_scans=scan_starts(log.read_text())-scan_count
            if operations:
                operation_probe(home,service_pid,log,enforce)
                return
            if post_claim:
                post_claim_refusal(home,service_pid,log,enforce)
                return
            probe=r'''
    import os,sys,time,pathlib,json
    home=pathlib.Path(sys.argv[1]);reader,writer=os.pipe();pid=os.fork()
    if pid==0:
     os.setgroups([33280]);os.setgid(1000);os.setuid(1000)
     p=home/'.var/loops/loop00/mail/draft/probe';p.write_bytes(b'synthetic latency probe\n')
     start=time.monotonic();os.write(writer,str(start).encode());os.rename(p,home/'.var/loops/loop00/mail/outbox/loop01.probe.letter');os._exit(0)
    os.close(writer);start=float(os.read(reader,100));os.close(reader);os.waitpid(pid,0)
    while time.monotonic()-start<300:
     sent=list((home/'.var/loops/loop00/mail/sent').iterdir());inbox=list((home/'.var/loops/loop01/mail/inbox').iterdir())
     if sent and inbox and not (home/'.var/loops/loop00/mail/outbox/loop01.probe.letter').exists():
      assert sent[0].read_bytes()==inbox[0].read_bytes()==b'synthetic latency probe\n'
      print(json.dumps({'delivery_seconds':time.monotonic()-start}));break
     time.sleep(.001)
    else:raise RuntimeError('delivery fixture timeout')
    '''
            delivery_cpu_start=cpu()
            delivery=subprocess.run(['/usr/bin/podman','unshare',sys.executable,'-c',textwrap.dedent(probe),str(home)],capture_output=True,text=True,timeout=310)
            assert idle_scans==0, "idle service performed an unsolicited scan"
            assert descriptor_count<=16, "idle mailbox descriptors remain pinned"
            assert delivery.returncode==0, delivery.stderr
            print(json.dumps({'tag':tag,'mailboxes':count,'idle_wall':elapsed,'idle_cpu':used,'idle_scans':idle_scans,'idle_percent':100*used/elapsed,'delivery_cpu':cpu()-delivery_cpu_start,'delivery_status':delivery.returncode,'delivery':delivery.stdout,'delivery_stderr':delivery.stderr,'scans':scan_starts(log.read_text()),'idle_descriptors':descriptor_count}),flush=True)
        finally:
            if service_pid is None:
                for path in P('/proc').glob('[0-9]*/cmdline'):
                    try:command=path.read_bytes().split(b'\0')
                    except OSError:continue
                    if len(command)>2 and command[1]==b'_serve' and os.fsdecode(command[2])==str(home):
                        service_pid=int(path.parent.name);break
            if service_pid is not None:
                subprocess.run(['/usr/bin/podman','unshare',sys.executable,str(P(__file__).resolve()),'stop',str(service_pid),str(home)],check=True)
            if process.poll() is None:process.terminate()
            process.wait(timeout=30)

def operation_probe(home,service_pid,log,enforce=True):
    probe=r'''
import os,pathlib,signal,subprocess,sys,time,json,re,platform
home=pathlib.Path(sys.argv[1]);pid=int(sys.argv[2]);trace=pathlib.Path(sys.argv[3])
command=pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
assert len(command)>2 and command[1]==b'_serve' and os.fsdecode(command[2])==str(home)
records=sorted(p.name for p in (home/'.var/loops/.mail-service/deliveries').glob('*.toml'))
assert records, 'operation fixture requires retained history'
errors=trace.with_suffix('.stderr').open('w')
tracer=subprocess.Popen(['/usr/bin/strace','-f','-qq','-yy','-s','4096','-e','trace=open,openat,openat2,stat,lstat,fstat,newfstatat,statx,getdents,getdents64,poll,ppoll,read,pread64,readv,preadv,preadv2,close,write,writev','-o',str(trace),'-p',str(pid)],stdout=subprocess.DEVNULL,stderr=errors)
try:
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  if tracer.poll() is not None:raise RuntimeError('strace refused fixture attachment')
  status=pathlib.Path(f'/proc/{pid}/status').read_text()
  if int(re.search(r'^TracerPid:\s+(\d+)',status,re.M).group(1))==tracer.pid:break
  time.sleep(.01)
 else:raise RuntimeError('strace attachment not observed')
 actor=os.fork()
 if actor==0:
  os.setgroups([33280]);os.setgid(1000);os.setuid(1000)
  draft=home/'.var/loops/loop00/mail/draft/operations';draft.write_bytes(b'operation-count fixture\n')
  os.rename(draft,home/'.var/loops/loop00/mail/outbox/loop01.operations.letter');os._exit(0)
 os.waitpid(actor,0);deadline=time.monotonic()+120
 while time.monotonic()<deadline:
  sent=list((home/'.var/loops/loop00/mail/sent').iterdir());inbox=list((home/'.var/loops/loop01/mail/inbox').iterdir())
  if sent and inbox and not (home/'.var/loops/loop00/mail/outbox/loop01.operations.letter').exists():
   assert sent[0].read_bytes()==inbox[0].read_bytes()==b'operation-count fixture\n'
   break
  time.sleep(.01)
 else:raise RuntimeError('operation fixture delivery did not finish')
 # Completion is a kernel wait after the queued self-events, not a latency assertion.
 deadline=time.monotonic()+30;quiet=0
 poll_calls={'x86_64':{'7','271'},'aarch64':{'73'}}.get(platform.machine())
 assert poll_calls, 'fixture needs the architecture syscall numbers for poll'
 while time.monotonic()<deadline:
  syscall=pathlib.Path(f'/proc/{pid}/syscall').read_text().split()[0]
  quiet=quiet+1 if syscall in poll_calls else 0
  if quiet>=3:break
  time.sleep(.1)
 else:raise RuntimeError('fixture service never returned to poll')
finally:
 if tracer.poll() is None:tracer.send_signal(signal.SIGINT)
 try:tracer.wait(timeout=10)
 except subprocess.TimeoutExpired:
  tracer.kill();tracer.wait();raise
 errors.close()
assert tracer.returncode in [0,-signal.SIGINT], trace.with_suffix('.stderr').read_text()
phases={name:{'open':0,'stat':0,'list':0,'history_reads':0} for name in ['wake','delivery']};phase='wake'
all_phases={name:dict(counts) for name,counts in phases.items()};totals={'open':0,'stat':0,'list':0}
counts={'open':0,'stat':0,'list':0};folders={'outbox':0,'staging':0}
history={name:0 for name in records};record_opens=0;descriptors={}
root=str(home/'.var/loops/loop02')
cwd=os.readlink(f'/proc/{pid}/cwd')
def targets(line,op):
 paths=re.findall(r'<([^>]+)>',line)
 at=re.search(r'\((AT_FDCWD|\d+(?:<([^>]+)>)?),\s*("(?:[^"\\]|\\.)*")',line) if op in ['openat','openat2','newfstatat','statx'] else None
 if at:
  name=json.loads(at.group(3));base=at.group(2) or cwd
  paths.append(os.path.normpath(os.path.join(base,name)))
 elif op in ['open','stat','lstat']:
  arg=re.search(r'\(("(?:[^"\\]|\\.)*")',line)
  if arg:paths.append(os.path.normpath(os.path.join(cwd,json.loads(arg.group(1)))))
 return paths
# Calibrate relative descriptor paths: the syscall need not print an absolute target.
assert root in targets(f'newfstatat(7<{home}/.var/loops>, "loop02", {{...}}, 0) = 0','newfstatat')
assert root+'/mail/outbox' in targets(f'openat(8<{root}/mail>, "outbox", 0) = -1 EACCES','openat')
for line in trace.read_text().splitlines():
 if 'mail candidate attempt' in line:phase='delivery'
 match=re.search(r'\b(open|openat|openat2|stat|lstat|fstat|newfstatat|statx|getdents|getdents64|read|pread64|readv|preadv|preadv2|close)\(',line)
 if not match:continue
 op=match.group(1)
 if op.startswith('open'):
  returned=re.search(r'= (\d+)<',line)
  if returned:
   descriptor=int(returned.group(1));descriptors.pop(descriptor,None)
   stamp=re.search(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\.toml',line)
   if stamp and stamp.group() in history and '/.mail-service/deliveries' in line:
    record_opens+=1;descriptors[descriptor]=(stamp.group(),False)
 if op in ['read','pread64','readv','preadv','preadv2','close']:
  descriptor=int(re.search(r'\((\d+)',line[match.start():]).group(1))
  if op=='close':descriptors.pop(descriptor,None)
  elif descriptor in descriptors:
   name,seen=descriptors[descriptor]
   if not seen:history[name]+=1;phases[phase]['history_reads']+=1;all_phases[phase]['history_reads']+=1;descriptors[descriptor]=(name,True)
  continue
 kind='open' if op.startswith('open') else 'list' if op.startswith('getdents') else 'stat'
 totals[kind]+=1;all_phases[phase][kind]+=1
 paths=targets(line,op)
 if any(path==root or path.startswith(root+'/') for path in paths):
  counts[kind]+=1;phases[phase][kind]+=1
  if kind=='list':
   folders['outbox']+=int(root+'/mail/outbox' in paths)
   folders['staging']+=int(root+'/.mail-staging' in paths)
assert len(set(history.values()))==1, 'retained records did not receive equal whole-history reads'
print(json.dumps({'all_operations':totals,'all_phases':all_phases,'phases':phases,'unrelated_loop_operations':counts,'unrelated_directory_reads':folders,'history_passes':next(iter(history.values())),'history_record_reads':sum(history.values()),'history_record_opens':record_opens,'retained_records':len(history),'trace':str(trace)}))
'''
    result=subprocess.run(['/usr/bin/podman','unshare',sys.executable,'-c',probe,str(home),str(service_pid),str(log.parent/'operations.trace')],capture_output=True,text=True,check=True,timeout=180)
    reading=json.loads(result.stdout)
    print(json.dumps(reading),flush=True)
    if enforce:assert_operations(reading)

def post_claim_refusal(home,service_pid,log,enforce=True):
    # The observer counts actual claims while only this fixture's journal is unwritable.
    probe=r'''
import ctypes,os,pathlib,select,struct,sys,time,json
home=pathlib.Path(sys.argv[1]);pid=int(sys.argv[2]);log=pathlib.Path(sys.argv[3])
libc=ctypes.CDLL(None,use_errno=True);fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
assert fd>=0
outbox=home/'.var/loops/loop00/mail/outbox';name='loop01.postclaim.letter'
assert libc.inotify_add_watch(fd,os.fsencode(outbox),0x40|0x80)>=0
handle=os.pidfd_open(pid)
command=pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
assert len(command)>2 and command[1]==b'_serve' and os.fsdecode(command[2])==str(home)
assert not select.select([handle],[],[],0)[0], 'fixture service exited before fault'
(home/'.var/loops/.mail-service/deliveries').chmod(0o500)
def claims(timeout):
 count=0
 if select.select([fd],[],[],timeout)[0]:
  events=os.read(fd,65536);offset=0
  while offset<len(events):
   wd,mask,cookie,length=struct.unpack_from('iIII',events,offset)
   assert not mask&0x4000, 'observer notification overflow'
   entry=events[offset+16:offset+16+length].split(b'\0',1)[0];offset+=16+length
   if entry==name.encode() and mask&0x40:count+=1
 return count
actor=os.fork()
if actor==0:
 os.setgroups([33280]);os.setgid(1000);os.setuid(1000)
 draft=home/'.var/loops/loop00/mail/draft/postclaim';draft.write_bytes(b'x'*8192)
 os.rename(draft,outbox/name);os._exit(0)
os.waitpid(actor,0);claimed=False;deadline=time.monotonic()+60
while time.monotonic()<deadline:
 claimed=bool(claims(.05)) or claimed
 if claimed:
  try:
   restored=(outbox/name).read_bytes()==b'x'*8192
   reasons=[p.read_text() for p in outbox.iterdir() if p.name!=name]
   if restored and any('Permission denied' in reason for reason in reasons):break
  except (FileNotFoundError,PermissionError):pass
else:raise RuntimeError('fixture did not witness post-claim refusal and restoration')
def cpu():
 fields=pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
 return (int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')
claims(0)
before=log.read_text().count('mail scan started');start=time.monotonic();used=cpu();attempts=0
while time.monotonic()-start<30:
 attempts+=claims(min(.1,max(0,30-(time.monotonic()-start))))
elapsed=time.monotonic()-start;used=cpu()-used
assert not select.select([handle],[],[],0)[0], 'fixture service exited during retries'
os.close(handle);os.close(fd)
print(json.dumps({'case':'post-claim-refusal','attempts':attempts,'scan_count':log.read_text().count('mail scan started')-before,'interval_seconds':elapsed,'cpu_seconds':used,'cpu_percent':100*used/elapsed}))
'''
    result=subprocess.run(['/usr/bin/podman','unshare',sys.executable,'-c',probe,str(home),str(service_pid),str(log)],capture_output=True,text=True,check=True,timeout=100)
    reading=json.loads(result.stdout)
    elapsed=reading['interval_seconds'];instant=0;bound=0
    for delay in [1,2,4,8,16]+[30]*int(elapsed//30+2):
        instant+=delay
        if instant<=elapsed+1:bound+=1
    reading['attempt_bound']=bound
    reading['scan_bound']=bound+2
    print(json.dumps(reading),flush=True)
    if enforce:
        assert reading['attempts']<=bound, 'restored source bypassed its retry schedule'
        assert reading['scan_count']<=bound+2, 'restored source kept driving scans'

def own_process(pid,home,stop=False):
    import signal
    try:descriptor=os.pidfd_open(pid)
    except ProcessLookupError:return
    try:
        command=P(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        assert len(command)>2 and command[1]==b'_serve' and os.fsdecode(command[2])==str(home), 'not this fixture service'
        if stop:signal.pidfd_send_signal(descriptor,signal.SIGTERM)
        else:print(len(list(P(f'/proc/{pid}/fd').iterdir())))
    except ProcessLookupError:pass
    finally:os.close(descriptor)

if __name__=='__main__':
    phase=sys.argv[1]
    if phase=='observation-check':observation_check()
    elif phase=='seed':seed(P(sys.argv[2]),int(sys.argv[3]),sys.argv[4])
    elif phase=='history':history(P(sys.argv[2]),int(sys.argv[3]))
    elif phase=='measure':measure(int(sys.argv[2]),sys.argv[3],sys.argv[4])
    elif phase=='operations-profile':measure(int(sys.argv[2]),sys.argv[3],sys.argv[4],enforce=False,operations=True)
    elif phase=='operations':measure(int(sys.argv[2]),sys.argv[3],sys.argv[4],operations=True)
    elif phase=='post-claim-profile':measure(int(sys.argv[2]),sys.argv[3],sys.argv[4],True,False)
    elif phase=='post-claim':measure(int(sys.argv[2]),sys.argv[3],sys.argv[4],True)
    elif phase in ['inspect','stop']:own_process(int(sys.argv[2]),P(sys.argv[3]),phase=='stop')
    else:raise ValueError('expected seed, history, measure, post-claim, inspect or stop')
