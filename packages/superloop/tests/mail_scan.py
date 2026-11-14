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

def measure(count,binary,tag):
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
            scan_count=log.read_text().count('mail scan complete');c=cpu();t=time.monotonic();time.sleep(10);elapsed=time.monotonic()-t;used=cpu()-c;idle_scans=log.read_text().count('mail scan complete')-scan_count
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
            delivery=subprocess.run(['/usr/bin/podman','unshare',sys.executable,'-c',textwrap.dedent(probe),str(home)],capture_output=True,text=True,timeout=310)
            assert idle_scans==0, "idle service performed an unsolicited scan"
            assert descriptor_count<=16, "idle mailbox descriptors remain pinned"
            assert delivery.returncode==0, delivery.stderr
            print(json.dumps({'tag':tag,'mailboxes':count,'idle_wall':elapsed,'idle_cpu':used,'idle_scans':idle_scans,'idle_percent':100*used/elapsed,'delivery_status':delivery.returncode,'delivery':delivery.stdout,'delivery_stderr':delivery.stderr,'scans':log.read_text().count('mail scan complete'),'idle_descriptors':descriptor_count}),flush=True)
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
    if phase=='seed':seed(P(sys.argv[2]),int(sys.argv[3]),sys.argv[4])
    elif phase=='history':history(P(sys.argv[2]),int(sys.argv[3]))
    elif phase=='measure':measure(int(sys.argv[2]),sys.argv[3],sys.argv[4])
    elif phase in ['inspect','stop']:own_process(int(sys.argv[2]),P(sys.argv[3]),phase=='stop')
    else:raise ValueError('expected seed, history, measure, inspect or stop')
