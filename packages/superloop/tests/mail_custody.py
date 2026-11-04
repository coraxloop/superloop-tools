"""Exercise the production scanner under existing independent fixture identities."""
import argparse, grp, hashlib, json, os, pathlib, pwd, struct, subprocess, sys, time, shutil, select, tomllib

def acl(path, uid, access, owner=7):
    rows=[(1,owner,0xffffffff),(2,access,uid),(4,0,0xffffffff),(16,access,0xffffffff),(32,0,0xffffffff)]
    os.setxattr(path,'system.posix_acl_access',struct.pack('<I',2)+b''.join(struct.pack('<HHI',*row) for row in rows))

def directory(path, mode=0o711, gid=None):
    path.mkdir(exist_ok=True)
    if gid is not None:os.chown(path,-1,gid)
    os.chmod(path,mode)

def main():
    os.umask(0o022)
    p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,required=True);p.add_argument('--binary',type=pathlib.Path,required=True);p.add_argument('--service-account',required=True);p.add_argument('--loop-account',required=True);p.add_argument('--mail-group',required=True);p.add_argument('--loop-binary',type=pathlib.Path);p.add_argument('--actor');p.add_argument('--report',type=pathlib.Path)
    a=p.parse_args();root=a.root;home=root/'home';loop=home/'.var/loops/alpha';mail=loop/'mail';service=pwd.getpwnam(a.service_account).pw_uid;actor=pwd.getpwnam(a.loop_account).pw_uid;group=grp.getgrnam(a.mail_group).gr_gid
    if a.actor:
        task=json.loads(sys.stdin.readline()) if a.actor=="entered" else json.load(sys.stdin)
        if task['op']=='entered-config':
            os.chdir(loop/'private')
            descriptor=os.open(task['program'],os.O_RDONLY)
            print('READY',flush=True)
            assert sys.stdin.readline().strip()=='GO'
            try:subprocess.run([task['program'],'_mail-configure','.',str(service)],check=False)
            except PermissionError:pass
            else:raise AssertionError('private host prefix remains traversable')
            executable=f'/proc/self/fd/{descriptor}'
            denied=subprocess.run(['/usr/bin/setpriv','--no-new-privs',executable,'_mail-configure',str(loop/'private'),str(service)],pass_fds=(descriptor,),capture_output=True)
            assert denied.returncode==2,denied
            completed=subprocess.run(['/usr/bin/setpriv','--no-new-privs',executable,'_mail-configure','.',str(service)],pass_fds=(descriptor,),capture_output=True)
            if completed.returncode:raise AssertionError((completed.returncode,completed.stderr))
            os.close(descriptor)
        elif task['op']=='service-setup':
            for path in [loop/'.mail-staging',home/'.var/loops/.mail-service']:directory(path,0o700)
            directory(mail,0o770,group)
            for part in ['inbox','sent']:directory(mail/part,0o770,group)
        elif task['op']=='loop-setup':
            for part in ['draft','outbox','read']:directory(mail/part,0o700)
            acl(mail/'outbox',service,7)
            for path in ([loop/'private'] if task.get('production_config') else [loop/'private',loop/'private/.config',loop/'private/.config/mail']):
                directory(path,0o700);acl(path,service,1)
            if task.get('production_config'):return
            config=loop/'private/.config/mail/loop.toml';config.write_text('workers=[]\n[mail]\nversion=1\nallow=[]\n');acl(config,service,4,6)
        elif task['op']=='service-finish':os.chmod(mail,0o750)
        elif task['op']=='submit':
            path=mail/'draft'/task['name'];path.write_bytes(bytes.fromhex(task['hex']));os.rename(path,mail/'outbox'/task['name'])
        elif task['op']=='bad':
            name=task['name'];path=mail/'outbox'/name
            if task['kind']=='symlink':path.symlink_to('absent')
            elif task['kind']=='hardlink':
                source=mail/'draft/linked';source.write_bytes(b'body');os.link(source,path)
            else:path.write_bytes(b'body')
        elif task['op']=='capacity':
            path=loop/'.mail-staging/capacity-fixture'
            if task['full']:
                with path.open('wb') as file:file.truncate(67108864-2097152)
                os.chmod(path,0o600)
            else:path.unlink()
        elif task['op']=='config':
            path=loop/'private/.config/mail/loop.toml'
            replacement=path.with_suffix('.replacement');replacement.write_text(task['source'])
            if task['grant']:acl(replacement,service,4,6)
            else:os.chmod(replacement,0o600)
            os.replace(replacement,path)
        elif task['op']=='config-read':print((loop/'private/.config/mail/loop.toml').read_text(),end='')
        elif task['op']=='config-loss':
            for name in ['loop.toml','loop.toml.backup']:(loop/'private/.config/mail'/name).unlink(missing_ok=True)
        elif task['op']=='config-exists':print((loop/'private/.config/mail/loop.toml').exists())
        elif task['op']=='config-mask':
            for path in [loop/'private',loop/'private/.config',loop/'private/.config/mail']:os.chmod(path,0o700)
            os.chmod(loop/'private/.config/mail/loop.toml',0o600)
        elif task['op']=='unsafe-outbox':
            if task['unsafe']:os.chmod(mail/'outbox',0o777)
            else:acl(mail/'outbox',service,7)
        elif task['op']=='read':
            print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (mail/task['part']).iterdir() if p.is_file()}))
        elif task['op']=='move':
            name=task['name'];os.rename(mail/'inbox'/name,mail/'read'/name)
        elif task['op']=='write-denied':
            try:(mail/task['part']/task['name']).write_bytes(b'corrupt')
            except PermissionError:print('denied')
            else:raise AssertionError('actor altered service bytes')
        elif task['op']=='reason':print((mail/'outbox'/task['name']).read_text())
        elif task['op']=='withdraw':os.rename(mail/'outbox'/task['name'],mail/'draft'/task['name'])
        return
    start=time.monotonic();events=[]
    def run(argv,body=None,expected=0):
        stamp=time.monotonic();r=subprocess.run(argv,input=None if body is None else json.dumps(body),text=True,capture_output=True,timeout=90)
        events.append({'argv':argv,'wall_seconds':round(time.monotonic()-stamp,3),'status':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        if r.returncode!=expected:raise AssertionError(events[-1])
        return r.stdout
    def who(account,task):return run(['sudo','-n','-P','-u',account,sys.executable,str(pathlib.Path(__file__).resolve()),'--root',str(root),'--binary',str(a.binary),'--service-account',a.service_account,'--loop-account',a.loop_account,'--mail-group',a.mail_group,'--actor','yes'],task)
    def scan(mode='scan',expected=0):
        output=run(['sudo','-n','-P','-u',a.service_account,str(a.binary),mode,str(home)],expected=expected)
        return output+events[-1]['stderr']
    try:
        directory(root,0o755)
        for path in [home,home/'.config',home/'.config/loops',home/'.var',home/'.var/loops']:directory(path,0o755)
        directory(loop,0o770,group)
        registry=home/'.config/loops/registry.toml';registry.write_text(f'namespace="org.superloop-tools.loophome.registry"\nversion=[1,0,0]\nloops=[{{name="alpha",uid={actor},launch="dev/alpha"}},{{name="beta",uid=4000,launch="dev/beta"}}]\n')
        (home/'.config/loops/allocations.toml').write_text(f'mail_uid={service}\n[alpha]\nuids={{base=3000,count=64}}\nmail_gids={{base={group},count=65}}\n')
        (home/'.config/loops/mail-service.toml').write_text(f'version=1\nuid={service}\ncrash_consistent_rename=true\ndurable_sync=true\n')
        (home/'.config/loops/loop.toml').write_text('workers=[{name="decoy",state="active"}]\n[mail]\nversion=1\nallow=[]\n')
        os.chown(home/'.var/loops',-1,group);os.chmod(home/'.var/loops',0o770)
        who(a.service_account,{'op':'service-setup'});who(a.loop_account,{'op':'loop-setup','production_config':a.loop_binary is not None});
        if a.loop_binary:
            run(['sudo','-n','-P','-u',a.loop_account,str(a.loop_binary),'_mail-configure',str(loop/'private'),str(service)])
        who(a.service_account,{'op':'service-finish'})
        os.chmod(home/'.var/loops',0o755);os.chmod(loop,0o711)
        scan('initialize')
        held=loop/'.mail-migration-hold';held.mkdir(mode=0o700)
        assert 'retained migration history requires reconciliation' in scan(expected=2)
        held.rmdir()
        cases=[('alpha.01.letter',b''),('alpha.02.letter',bytes([0,255,128,10])),('alpha.03.letter',b'x'*1048576)]
        for name,body in cases:who(a.loop_account,{'op':'submit','name':name,'hex':body.hex()})
        assert 'beta:' in scan()
        inbox=json.loads(who(a.loop_account,{'op':'read','part':'inbox'}));sent=json.loads(who(a.loop_account,{'op':'read','part':'sent'}))
        expected=[hashlib.sha256(body).hexdigest() for _,body in cases]
        assert [inbox[name] for name in sorted(inbox)]==expected,(inbox,expected);assert inbox==sent
        name=sorted(inbox)[0];assert who(a.loop_account,{'op':'write-denied','part':'inbox','name':name}).strip()=='denied'
        who(a.loop_account,{'op':'move','name':name});scan();assert len(json.loads(who(a.loop_account,{'op':'read','part':'inbox'})))==2
        for name,kind,code in [('alpha.04.letter','symlink','invalid-file'),('alpha.05.letter','hardlink','invalid-file'),('nobody.06.letter','regular','unknown-recipient'),('wrong.reason.toml','regular','invalid-name'),('alpha+decoy.09.letter','regular','unknown-recipient')]:
            who(a.loop_account,{'op':'bad','name':name,'kind':kind});assert code in scan();reason=who(a.loop_account,{'op':'reason','name':name+'.reason.toml'});assert 'code = "'+code+'"' in reason,reason
            assert who(a.loop_account,{'op':'write-denied','part':'outbox','name':name+'.reason.toml'}).strip()=='denied'
            who(a.loop_account,{'op':'withdraw','name':name});scan()
        who(a.loop_account,{'op':'submit','name':'alpha.07.letter','hex':(b'x'*1048577).hex()});assert 'oversize' in scan()
        who(a.loop_account,{'op':'withdraw','name':'alpha.07.letter'});scan()
        who(a.service_account,{'op':'capacity','full':True})
        who(a.loop_account,{'op':'submit','name':'alpha.08.letter','hex':b'capacity'.hex()});assert 'service-capacity' in scan()
        reason=who(a.loop_account,{'op':'reason','name':'alpha.08.letter.reason.toml'});assert 'service-capacity' in reason
        who(a.service_account,{'op':'capacity','full':False});assert 'beta:' in scan()
        who(a.loop_account,{'op':'submit','name':'alpha+decoy.10.letter','hex':b'configuration'.hex()})
        for source,grant in [('workers=[]\n[mail]\nversion=1\nallow=[]\n',False),('workers=[]\n[mail]\nversion=1\nallow=[]\nunknown=true\n',True)]:
            who(a.loop_account,{'op':'config','source':source,'grant':grant});assert 'invalid-directory' in scan()
        who(a.loop_account,{'op':'config','source':'workers=[]\n[mail]\nversion=1\nallow=[]\n','grant':True});assert 'unknown-recipient' in scan()
        who(a.loop_account,{'op':'withdraw','name':'alpha+decoy.10.letter'});scan()
        who(a.loop_account,{'op':'unsafe-outbox','unsafe':True});assert 'unsafe-storage' in scan()
        who(a.loop_account,{'op':'unsafe-outbox','unsafe':False});assert 'beta:' in scan()
        if a.loop_binary:
            preserved=json.loads(who(a.loop_account,{'op':'read','part':'read'}))
            retained='workers=[{name="retained",state="retired"}]\nprivate_preference="preserved"\n[mail]\nversion=1\nallow=[]\n'
            who(a.loop_account,{'op':'config','source':retained,'grant':True})
            who(a.loop_account,{'op':'config-mask'})
            for _ in range(2):
                run(['sudo','-n','-P','-u',a.loop_account,str(a.loop_binary),'_mail-configure',str(loop/'private'),str(service)])
            assert who(a.loop_account,{'op':'config-read'})==retained
            assert preserved==json.loads(who(a.loop_account,{'op':'read','part':'read'}))
            assert 'beta:' in scan()
            def worker_state(phase,name,uid,reference,expected=0):
                run(['sudo','-n','-P','-u',a.loop_account,str(a.loop_binary),'_mail-worker-state',str(loop/'private'),str(service),phase,name,str(uid),reference],expected=expected)
                return events[-1]['stderr']
            for offset,name in enumerate(['0','provision','a'*512]):
                uid=3010+offset;reference=f'fixture:{uid}'
                worker_state('reserve',name,uid,reference)
                pending=tomllib.loads(who(a.loop_account,{'op':'config-read'}))
                assert next(w for w in pending['workers'] if w['name']==name)['state']=='retired'
                assert 'invalid-directory' in worker_state('verify',name,uid,reference,2)
                worker_state('reserve',name,uid,reference)
                worker_state('activate',name,uid,reference)
                worker_state('verify',name,uid,reference)
                worker_state('reserve',name,uid,reference)
                worker_state('retire',name,uid,reference)
                worker_state('verify-retired',name,uid,reference)
                assert worker_state('reserve',name,uid,reference,2)
                assert worker_state('reserve',name,uid+20,reference+'-replacement',2)
            for name in ['-alpha','a_b']:
                assert 'invalid-name' in worker_state('reserve',name,3040,'invalid',2)
            worker_state('reserve','replacement',3010,'replacement')
            worker_state('activate','replacement',3010,'replacement')
            worker_state('retire','replacement',3010,'replacement')
            worker_state('verify-retired','replacement',3010,'replacement')
            assert tomllib.loads(who(a.loop_account,{'op':'config-read'}))['private_preference']=='preserved'
            private_program=home/'private-helper';shutil.copyfile(a.loop_binary,private_program);os.chmod(private_program,0o755)
            argv=['sudo','-n','-P','-u',a.loop_account,sys.executable,str(pathlib.Path(__file__).resolve()),'--root',str(root),'--binary',str(a.binary),'--service-account',a.service_account,'--loop-account',a.loop_account,'--mail-group',a.mail_group,'--actor','entered']
            stamp=time.monotonic();process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                process.stdin.write(json.dumps({'op':'entered-config','program':str(private_program)})+'\n');process.stdin.flush()
                assert select.select([process.stdout],[],[],90)[0],'entered fixture readiness timeout'
                assert process.stdout.readline()=='READY\n'
                acl(home,service,1)
                stdout,stderr=process.communicate('GO\n',timeout=90)
                events.append({'argv':argv,'wall_seconds':round(time.monotonic()-stamp,3),'status':process.returncode,'stdout':stdout,'stderr':stderr})
                assert process.returncode==0,events[-1]
            finally:
                if process.poll() is None:process.kill();process.wait()
                os.removexattr(home,'system.posix_acl_access');os.chmod(home,0o755)
            directory(loop/'.mail-births',0o700)
            who(a.loop_account,{'op':'config-loss'})
            assert 'requires backup reconciliation' in worker_state('reserve','after-loss',3042,'loss',2)
            assert who(a.loop_account,{'op':'config-exists'}).strip()=='False'
        result='PASS'
    except BaseException:
        result='FAIL';raise
    finally:
        report={'result':result,'wall_seconds':round(time.monotonic()-start,3),'events':events}
        if a.report:a.report.write_text(json.dumps(report,indent=2))
        print(json.dumps({'result':result,'wall_seconds':report['wall_seconds']}))
if __name__=='__main__':main()
