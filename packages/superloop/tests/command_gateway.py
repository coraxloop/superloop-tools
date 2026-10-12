import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--bin-dir',type=Path,required=True)
parser.add_argument('--runner',type=Path,required=True)
parser.add_argument('--report',type=Path,required=True)
args=parser.parse_args()
root,bins=args.root,args.bin_dir
if root.exists(): shutil.rmtree(root)
root.mkdir(mode=0o700)
events=[]
def run(argv,value=None,expected=0,env=None):
    start=time.time_ns()
    print(f'START utc_ns={start} argv={list(map(str,argv))}',flush=True)
    result=subprocess.run(list(map(str,argv)),input=None if value is None else json.dumps(value).encode(),capture_output=True,env=env,timeout=60)
    end=time.time_ns()
    events.append(dict(argv=list(map(str,argv)),start_ns=start,end_ns=end,wall_ns=end-start,exit=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode()))
    print(f'END utc_ns={end} wall_ns={end-start} exit={result.returncode}',flush=True)
    args.report.write_text(json.dumps(dict(events=events),indent=2)+'\n')
    if expected is not None: assert result.returncode==expected,events[-1]
    return result
def write(path,value,mode=0o600):
    path.write_text(value);path.chmod(mode)
def record(path,value): write(path,json.dumps(value)+'\n')
for name in ['worktree','mirrors','checkouts','checkouts/fixture','registry','journal','fake-bin','targets']:
    (root/name).mkdir(mode=0o700)
worktree=root/'worktree'
run(['git','init','-q',worktree])
write(worktree/'README.md','gateway binary fixture\n')
(worktree/'packages/lane-gateway').mkdir(parents=True)
write(worktree/'packages/lane-gateway/Cargo.toml','[package]\nname = "lane-gateway"\nversion = "0.1.0"\n')
run(['git','-C',worktree,'add','README.md','packages/lane-gateway/Cargo.toml'])
run(['git','-C',worktree,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','fixture'])
base=run(['git','-C',worktree,'rev-parse','HEAD']).stdout.decode().strip()
run(['git','init','-q','--bare',root/'mirrors/fixture.git'])
run(['git','init','-q',root/'checkouts/fixture'])
write(root/'registry/fixture.env',f'LOOP_NAME=fixture\nLOOP_SID=fixture\nLOOP_CWD={root}\nLOOP_STATE_ROOT={root/"journal"}\n')
record(root/'context.json',dict(hook_event_name='PreToolUse',permission_mode='default',session_id='fixture',cwd=str(root),transcript_path=str(root/'transcript.jsonl'),tool_name='Bash',tool_use_id='review',tool_input=dict(command='review')))
write(root/'rust-env',':\n')
# A local fixture transport executes only the runner's stdin script. No network
# alias or external SSH connection is used by this built-runner measurement.
write(root/'fake-bin/ssh','#!/bin/sh\nif test -f "'+str(root/'transport-fail')+'"; then exit 255; fi\nexec /bin/bash -s\n',0o700)
runner=args.runner
env=dict(os.environ,LANE_GATEWAY_STATE=str(root/'state'),SUPERLOOP_GATEWAY_REQUESTS_HELPER=str(bins/'requests-helper'),PERMISSION_TRIAGE_LOOP_REGISTRY=str(root/'registry'),PERMISSION_TRIAGE_REQUEST_CONTEXT=str(root/'context.json'),SUPERLOOP_GATEWAY_LOOP='fixture',LANE_GATEWAY_RUNNER_ARGV=json.dumps([str(runner)]),LANE_GATEWAY_POLL_MILLIS='25',LANE_GATEWAY_SHUTDOWN_FILE=str(root/'shutdown'),LANE_GATEWAY_HEARTBEAT_MILLIS='100',LANE_GATEWAY_TARGET_ROOT=str(root/'targets'),GATEWAY_RUNNER_SSH='fixture-local',GATEWAY_RUNNER_REMOTE_WRAPPER='/usr/bin/env',GATEWAY_RUNNER_RUST_ENV=str(root/'rust-env'),GATEWAY_RUNNER_LANES=str(root/'mirrors'),GATEWAY_RUNNER_REMOTE_PATH=os.environ['PATH'],PATH=str(root/'fake-bin')+':'+os.environ['PATH'])
registration=f'''schema = 1
lane = "fixture"
worktree = "{worktree}"
packages = ["lane-gateway"]
base_commit = "{base}"
mirror_remote = "{root/'mirrors/fixture.git'}"
mirror_checkout = "{root/'checkouts/fixture'}"
proposal_timeout_seconds = 5
[budgets]
run_cap = 100
cooldown_seconds = 0
[commands.check]
argv = ["/usr/bin/true"]
wall_budget_seconds = 30
'''
for name in ['clippy','clippy-fix-diff','corpus-names','fmt-check','fmt-diff','test']:
    argv=['cargo','test','--package','lane-gateway'] if name=='test' else ['/usr/bin/true']
    registration+=f'[commands.{name}]\nargv = {json.dumps(argv)}\nwall_budget_seconds = 30\n'
write(root/'registration.toml',registration)
run([bins/'gateway-service','register',root/'registration.toml'],env=env)
service=None
def start():
    global service
    (root/'shutdown').unlink(missing_ok=True)
    stamp=time.time_ns()
    service=subprocess.Popen([str(bins/'gateway-service'),'serve'],env=env,stdout=(root/'serve.stdout').open('ab'),stderr=(root/'serve.stderr').open('ab'))
    events.append(dict(service_start_ns=stamp,pid=service.pid))
    print(f'SERVICE_START utc_ns={stamp} pid={service.pid}',flush=True)
def stop():
    global service
    if service is not None:
        write(root/'shutdown','stop\n')
        code=service.wait(timeout=45)
        events.append(dict(service_end_ns=time.time_ns(),pid=service.pid,exit=code))
        service=None
        assert code==0,(root/'serve.stderr').read_text()
def crash():
    global service
    service.kill()
    code=service.wait(timeout=10)
    events.append(dict(service_crash_ns=time.time_ns(),pid=service.pid,exit=code))
    assert code==-9
    service=None
def failed_publication():
    until=time.monotonic()+10
    while time.monotonic()<until:
        audit=[json.loads(line) for line in (root/'state/audit/fixture.jsonl').read_text().splitlines()]
        failures=[r for r in audit if r['event']['kind']=='worker_file_refused' and r['event'].get('seq')==11]
        if failures:
            assert failures[-1]['event']['unpublishable'] is True
            events.append(dict(output_failure=failures[-1],observed_ns=time.time_ns()))
            stop()
            return
        time.sleep(.025)
    raise AssertionError('output failure was not audited')
def wait_effects(count):
    until=time.monotonic()+30
    while time.monotonic()<until:
        if counter.exists() and counter.read_text().count('effect')==count: return
        time.sleep(.025)
    raise AssertionError('effect counter did not reach '+str(count))
def wait_result(seq,terminal=True):
    path=worktree/('.lane/proposals/'+str(seq)+'.json' if seq>=3 else '.lane/result.json')
    until=time.monotonic()+45
    while time.monotonic()<until:
        if service is not None and service.poll() is not None: raise AssertionError((root/'serve.stderr').read_text())
        try: result=json.loads(path.read_text())
        except (FileNotFoundError,json.JSONDecodeError): time.sleep(.025);continue
        if result.get('seq')==seq and (not terminal or result['verdict'] not in ['pending','parked']): return result
        time.sleep(.025)
    raise AssertionError(dict(seq=seq,stderr=(root/'serve.stderr').read_text(),result=result if 'result' in locals() else None))
def request(seq,op,**fields):
    path=worktree/'.lane/request.json'
    path.parent.mkdir(exist_ok=True)
    temporary=path.with_suffix('.tmp');record(temporary,dict(schema=1,seq=seq,op=op,**fields));temporary.replace(path)
    return wait_result(seq,op!='propose')
def owner(action,document):
    value=dict(schema=1,records=[],document=document,id=None,pending=False,now_ns=time.time_ns(),expected=None,publication=None)
    preview=json.loads(run([bins/'requests-helper','--owner-preview',action,'--loop','fixture'],value,env=env).stdout)
    value['expected']=preview['before']
    return json.loads(run([bins/'requests-helper','--owner-commit',action,'--loop','fixture'],value,env=env).stdout)
def rows(): return json.loads(run([bins/'requests-helper','--owner-read','--loop','fixture'],env=env).stdout)['requests']
def row(seq): return next(r for r in rows() if r['body']['proposal']['seq']==seq)
def answer(seq,outcome,**extra):
    document=dict(schema=1,items=[dict(id=row(seq)['id'],decision=dict(answer=dict(outcome=outcome,**extra),reason='fixture reviewed answer'))])
    return run([bins/'requests-helper','triage','--loop','fixture'],document,env=env)
counter=root/'effects'
argv=['/bin/sh','-c','printf effect\\n >> "$1"','fixture',str(counter)]
results={}
try:
    start()
    results['push']=request(1,'push');assert results['push']['verdict']=='success',results
    results['precleared']=request(2,'run',command='check');assert results['precleared']['verdict']=='success',results
    for seq,outcome,expected,extra in [(3,'approve','ok',{}),(4,'deny','denied',{}),(5,'abandon','expired',{}),(6,'approve','ok',dict(promote='measured-command')),(7,'approve','failed',dict(promote='fmt-check'))]:
        request(seq,'propose',argv=argv,reason='binary acceptance')
        stop()
        answer(seq,outcome,**extra)
        if seq==3:
            claimed=row(seq)
            owner('claim',dict(schema=1,id=claimed['id'],claim=claimed['id']))
        start()
        results[str(seq)]=wait_result(seq)
        assert results[str(seq)]['verdict']==expected,results[str(seq)]
        stop();start()
        assert wait_result(seq)==results[str(seq)]
    request(8,'propose',argv=argv,reason='park then withdraw')
    stop()
    parked=row(8)
    run([bins/'requests-helper','triage','--loop','fixture'],dict(schema=1,items=[dict(id=parked['id'],mark_for_review=True)]),env=env)
    start()
    time.sleep(5.3)
    results['park']=wait_result(8,False)
    assert results['park']['verdict']=='parked',results['park']
    stop();owner('withdraw',dict(schema=1,id=parked['id']));start()
    results['withdraw']=wait_result(8);assert results['withdraw']['verdict']=='withdrawn',results['withdraw']
    request(9,'propose',argv=argv,reason='transport failure')
    stop();answer(9,'approve');write(root/'transport-fail','fail\n');start()
    results['transport']=wait_result(9)
    assert results['transport']['verdict']=='failed',results['transport']
    stop();(root/'transport-fail').unlink();start()
    assert wait_result(9)==results['transport']
    request(10,'propose',argv=argv,reason='registration drift')
    stop();answer(10,'approve')
    registration_path=root/'state/registrations/fixture.toml'
    original=registration_path.read_bytes()
    registration_path.write_text(original.decode().replace('run_cap = 100','run_cap = 101'))
    assert registration_path.read_bytes()!=original
    start();results['drift']=wait_result(10)
    assert results['drift']['verdict']=='failed' and 'registration changed' in json.dumps(results['drift']),results['drift']
    stop()
    duplicate=run([bins/'requests-helper','triage','--loop','fixture'],dict(schema=1,items=[dict(id=row(10)['id'],decision=dict(answer=dict(outcome='approve'),reason='duplicate'))]),expected=None,env=env)
    assert duplicate.returncode!=0
    start()
    assert wait_result(10)==results['drift']
    projection=worktree/'.lane/proposals/11.json'
    request(11,'propose',argv=['/bin/sh','-c','rm -f "$2"; mkdir "$2"; printf effect\\n >> "$1"','fixture',str(counter),str(projection)],reason='result publication interrupted')
    stop();answer(11,'approve');start();wait_effects(3);failed_publication()
    assert projection.is_dir()
    projection.rmdir();start()
    results['output-recovery']=wait_result(11)
    assert results['output-recovery']['verdict']=='ok',results['output-recovery']
    assert counter.read_text().count('effect')==3
    request(12,'propose',argv=['/bin/sh','-c','printf effect\\n >> "$1"; exec sleep 30','fixture',str(counter)],reason='uncertain running attempt')
    stop();answer(12,'approve');start();wait_effects(4);crash();start()
    results['uncertain-recovery']=wait_result(12)
    assert results['uncertain-recovery']['verdict']=='abandoned',results['uncertain-recovery']
    stop();start()
    assert wait_result(12)==results['uncertain-recovery']
    assert counter.read_text().count('effect')==4,counter.read_text()
    request(13,'propose',argv=argv,reason='current review binding')
    stop();reviewed=row(13)
    run([bins/'requests-helper','triage','--loop','fixture'],dict(schema=1,items=[dict(id=reviewed['id'],mark_for_review=True)]),env=env)
    review=json.loads(run([bins/'requests-helper','review','--loop','fixture',reviewed['id']],env=env).stdout)
    document=dict(schema=1,id=reviewed['id'],review_id='0'*64,decision=dict(answer=dict(outcome='approve'),reason='review binding'))
    stale=run([bins/'requests-helper','adjudicate','--loop','fixture'],document,expected=None,env=env)
    assert stale.returncode!=0
    document['review_id']=review['review']['review_id']
    run([bins/'requests-helper','adjudicate','--loop','fixture'],document,env=env)
    start();results['reviewed']=wait_result(13)
    assert results['reviewed']['verdict']=='ok',results['reviewed']
    stop();start()
    assert wait_result(13)==results['reviewed']
    assert counter.read_text().count('effect')==5,counter.read_text()
    home=root/'home';config=home/'.config/loops/fixture'
    config.mkdir(parents=True,mode=0o700)
    for directory in [home,home/'.config',home/'.config/loops',config]: directory.chmod(0o700)
    runs=root/'runs';runs.mkdir(mode=0o700)
    write(config.parent/'registry.toml',f'namespace = "org.superloop-tools.loophome.registry"\nversion = [1, 0, 0]\nloops = [{{ name = "fixture", uid = 41001, launch = "dev/fixture", runs_root = "{runs}", door_floor = "allow" }}]\n')
    write(config/'workers.toml',f'socket_dir = "{root/"sockets"}"\n')
    lane_env=dict(env,HOME=str(home),SUPERLOOP_LANE_REQUESTS_HELPER=str(bins/'requests-helper'))
    results['lane-status']=json.loads(run([bins/'superloop-lane','requests','status','fixture'],env=lane_env).stdout)
finally:
    stop()
report=dict(events=events,results=results,effects=counter.read_text().count('effect'),transport='fixture-local stdin transport; no network',digests={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in [('gateway-service',bins/'gateway-service'),('gateway-runner',runner),('requests-helper',bins/'requests-helper'),('superloop-lane',bins/'superloop-lane')]})
args.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='events'}),flush=True)
