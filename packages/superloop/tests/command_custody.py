"""Two-identity acceptance against the built direct entry; no account provisioning."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import pwd
import subprocess
import sys
import time

ROOT = OWNER = LOOP = HOME = LOOP_ROOT = STAGING = PAYLOAD = None
OWNER_UID = OWNER_GID = LOOP_UID = LOOP_GID = FIXTURE_GID = None
EVENTS = []

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def sha(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def source(value):
    return dict(revision=sha(value), sha256=sha(value), value=value)

def directory(path, gid, mode):
    path.mkdir(exist_ok=True)
    os.chown(path, -1, gid)
    os.chmod(path, mode)

def actor(task):
    action = task['action']
    if action == 'owner-setup':
        for path in [HOME, HOME/'.var', HOME/'.var/loops', LOOP_ROOT]:
            directory(path, OWNER_GID, 0o711)
        directory(LOOP_ROOT/'policy', LOOP_GID, 0o2750)
        os.chown(LOOP_ROOT, -1, LOOP_GID)
        os.chmod(LOOP_ROOT, 0o730)
    elif action == 'loop-setup':
        for name in ['private', 'shared', 'direct']:
            directory(LOOP_ROOT/name, LOOP_GID, 0o700)
    elif action == 'owner-finish':
        os.chown(LOOP_ROOT, -1, OWNER_GID)
        os.chmod(LOOP_ROOT, 0o711)
    elif action == 'snapshot':
        path = LOOP_ROOT/'policy/snapshot.json'
        tmp = path.with_suffix('.tmp')
        tmp.write_bytes(encoded(task['value']))
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    elif action == 'chmod':
        os.chmod(LOOP_ROOT/task['path'], task['mode'])
    elif action == 'chgrp':
        os.chown(LOOP_ROOT/task['path'], -1, task['gid'])
    elif action == 'remove-snapshot':
        (LOOP_ROOT/'policy/snapshot.json').unlink(missing_ok=True)
    elif action == 'journal':
        print((LOOP_ROOT/'direct/command-requests.jsonl').read_text())
    elif action == 'counter':
        path=LOOP_ROOT/'direct/agent-calls'
        print(len(path.read_text().splitlines()) if path.exists() else 0)
    elif action == 'effect-counter':
        path=LOOP_ROOT/'direct/effects'
        print(len(path.read_text().splitlines()) if path.exists() else 0)
    elif action == 'effect':
        with (LOOP_ROOT/'direct/effects').open('a') as file:
            file.write('one effect\n')
    elif action == 'remove-sign-in':
        (LOOP_ROOT/'private/.codex/auth.json').unlink(missing_ok=True)
    elif action == 'cross-write':
        try:
            (LOOP_ROOT/task['path']).write_text('must not publish')
        except PermissionError:
            print(json.dumps({'rule': 'permission-denied'}))
        else:
            raise AssertionError('cross-custody write succeeded')
    elif action == 'sign-in':
        directory(LOOP_ROOT/'private/.codex', LOOP_GID, 0o700)
        path = LOOP_ROOT/'private/.codex/auth.json'
        path.write_text('synthetic fixture; no credential')
        os.chmod(path, 0o600)
    elif action == 'owner-test-reset':
        for path in [HOME/'.config', HOME/'runs']:
            if path.exists():
                shutil.rmtree(path)
        (LOOP_ROOT/'policy/snapshot.json').unlink(missing_ok=True)
        directory(HOME/'owner-tmp', OWNER_GID, 0o700)
    elif action == 'clear-calls':
        (LOOP_ROOT/'direct/agent-calls').unlink(missing_ok=True)
    elif action == 'loop-owned-twin':
        directory(STAGING/('custody-twin-'+task['name']), LOOP_GID, 0o2770)
    elif action == 'swap-twin':
        target = LOOP_ROOT if task['name']=='root' else LOOP_ROOT/'policy'
        if task.get('restore'):
            os.rename(target, STAGING/('custody-twin-'+task['name']))
            os.rename(str(target)+'.saved', target)
        else:
            os.rename(target, str(target)+'.saved')
            os.rename(STAGING/('custody-twin-'+task['name']), target)
    elif action == 'symlink-twin':
        target={'anchor':HOME/'.var','loops':HOME/'.var/loops','root':LOOP_ROOT,'policy':LOOP_ROOT/'policy','file':LOOP_ROOT/'policy/snapshot.json'}[task['name']]
        saved=Path(str(target)+'.linked-source')
        if task.get('restore'):
            target.unlink(); os.rename(saved,target)
        else:
            os.rename(target,saved); target.symlink_to(saved.name)
    else:
        raise AssertionError(action)

def run(argv, *, data=None, check=True, env=None):
    started = time.time_ns()
    print(f'START utc_ns={started} argv={argv!r}', file=sys.stderr, flush=True)
    result = subprocess.run(argv, input=None if data is None else encoded(data), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, env=env)
    ended = time.time_ns()
    wall = (ended-started)/1e9
    EVENTS.append(dict(argv=argv,start_ns=started,end_ns=ended,wall=wall,exit=result.returncode))
    print(f'END utc_ns={ended} wall={wall} exit={result.returncode}', file=sys.stderr, flush=True)
    if check and result.returncode:
        raise AssertionError((argv, result.returncode, result.stdout.decode(), result.stderr.decode()))
    return result, wall

def account(who, task):
    return run(['sudo', '-n', '-u', who, '/usr/bin/python3', str(PAYLOAD/'probe.py'), '--root', str(ROOT), '--owner', OWNER, '--loop-account', LOOP, '--actor'], data=task)

def main():
    global ROOT, OWNER, LOOP, HOME, LOOP_ROOT, STAGING, PAYLOAD
    global OWNER_UID, OWNER_GID, LOOP_UID, LOOP_GID, FIXTURE_GID
    parser=argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--loop-account', required=True)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--actor', action='store_true')
    parser.add_argument('--binary')
    parser.add_argument('--lane-tests')
    parser.add_argument('--hook', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--native-root', type=Path)
    parser.add_argument('--door-report', type=Path)
    parser.add_argument('--gateway-report', type=Path)
    args=parser.parse_args()
    ROOT, OWNER, LOOP = args.root, args.owner, args.loop_account
    owner, loop = pwd.getpwnam(OWNER), pwd.getpwnam(LOOP)
    OWNER_UID, OWNER_GID = owner.pw_uid, owner.pw_gid
    LOOP_UID, LOOP_GID = loop.pw_uid, loop.pw_gid
    FIXTURE_GID = ROOT.stat().st_gid
    HOME = ROOT / 'custody-owner'
    LOOP_ROOT = HOME / '.var/loops/alpha'
    STAGING, PAYLOAD = ROOT, ROOT / 'custody-programs'
    if args.actor:
        actor(json.load(sys.stdin)); return
    for who in [OWNER, LOOP]:
        run(['sudo','-n','-u',who,'id'])
    PAYLOAD.mkdir(exist_ok=True)
    os.chmod(PAYLOAD, 0o755)
    shutil.copyfile(__file__, PAYLOAD/'probe.py')
    shutil.copyfile(args.binary, PAYLOAD/'superloop')
    os.chmod(PAYLOAD/'superloop', 0o755)
    if args.lane_tests:
        shutil.copyfile(args.lane_tests, PAYLOAD/'lane-tests')
        os.chmod(PAYLOAD/'lane-tests', 0o755)
        shutil.copyfile(Path(args.binary).parent/'requests-helper', PAYLOAD/'requests-helper')
        os.chmod(PAYLOAD/'requests-helper', 0o755)
    account(OWNER, {'action':'owner-setup'})
    account(LOOP, {'action':'loop-setup'})
    account(OWNER, {'action':'owner-finish'})
    account(OWNER, {'action':'remove-snapshot'})
    account(LOOP, {'action':'clear-calls'})
    report=[]
    comparisons=[]
    def call(action, body, expected=None):
        result, wall=run(['sudo','-n','-u',LOOP,'env','HOME='+str(LOOP_ROOT/'private'),str(PAYLOAD/'superloop'),'command',action,'alpha'],data=body,check=expected is None)
        if expected:
            assert result.returncode, result.stdout
            reply=json.loads(result.stderr)
            assert reply['rule']==expected, reply
        else:
            reply=json.loads(result.stdout)
        return reply,wall
    def case(name, expected=None):
        reply,wall=call('status', {'schema':1,'binding':None,'resolve':None}, expected)
        report.append(dict(case=name,wall=wall,rule=expected,result='PASS'))
        return reply
    snapshot=dict(schema=1,loop='alpha',loop_uid=LOOP_UID,written_at='fixture-1',door=True,
        registry=source({'floor':'enforce','root':str(LOOP_ROOT)}),
        modes=source({'ledger':{'classes':[],'loop_settings':[]},'effective':{}}),
        learned=source({'groups':{}}),rubric=source({'agent':None}))
    case('snapshot-absent','execute-command-snapshot-absent')
    account(OWNER, {'action':'snapshot','value':snapshot})
    context=case('owner-snapshot-loop-reader')['context']
    output,wall=run(['sudo','-n','-u',OWNER,'env','HOME='+str(LOOP_ROOT/'private'),str(PAYLOAD/'superloop'),'command','status','alpha'],
        data={'schema':1,'binding':None,'resolve':None},check=False)
    assert output.returncode and json.loads(output.stderr)['rule']=='execute-command-snapshot-custody'
    report.append(dict(case='anchor-is-reader-uid',result='PASS',wall=wall))
    for name in ['anchor','loops','root','policy','file']:
        account(OWNER,{'action':'symlink-twin','name':name})
        case('symlink-'+name,'execute-command-snapshot-custody')
        account(OWNER,{'action':'symlink-twin','name':name,'restore':True})
    for gid in [FIXTURE_GID,OWNER_GID]:
        account(OWNER, {'action':'chgrp','path':'policy','gid':gid})
        case('policy-wrong-group-'+str(gid),'execute-command-snapshot-custody')
    account(OWNER, {'action':'chgrp','path':'policy','gid':LOOP_GID})
    for mode in [0o644,0o660]:
        account(OWNER, {'action':'chmod','path':'policy/snapshot.json','mode':mode})
        case('snapshot-mode-'+oct(mode),'execute-command-snapshot-custody')
    account(OWNER, {'action':'chmod','path':'policy/snapshot.json','mode':0o640})
    for tier in ['shared','private']:
        account(LOOP, {'action':'chmod','path':tier,'mode':0o770})
        case(tier+'-group-write','execute-command-snapshot-custody')
        account(LOOP, {'action':'chmod','path':tier,'mode':0o700})
    for name in ['policy','root']:
        account(LOOP, {'action':'loop-owned-twin','name':name})
        account(OWNER, {'action':'swap-twin','name':name})
        account(LOOP, {'action':'chmod','path':'.' if name=='root' else 'policy','mode':0o711 if name=='root' else 0o2750})
        case('loop-owned-'+name,'execute-command-snapshot-custody')
        account(LOOP, {'action':'chmod','path':'.' if name=='root' else 'policy','mode':0o2770})
        account(OWNER, {'action':'swap-twin','name':name,'restore':True})
    snapshot['loop_uid']=OWNER_UID
    account(OWNER, {'action':'snapshot','value':snapshot})
    case('snapshot-wrong-loop-uid','execute-command-snapshot-identity')
    snapshot['loop_uid']=LOOP_UID
    account(OWNER, {'action':'snapshot','value':snapshot})
    for who,path in [(OWNER,'direct/foreign'),(LOOP,'policy/foreign')]:
        reply,wall=account(who, {'action':'cross-write','path':path})
        assert json.loads(reply.stdout)['rule']=='permission-denied'
        report.append(dict(case=who+'-cross-write',result='PASS',rule='permission-denied',wall=wall))
    def request(command):
        request=dict(schema=1,command={'representation':'bytes','bytes':list(command.encode())},context={
            'cwd':context['cwd'],'requester':context['principal'],'loop_id':'alpha','lane':None,'run':None,
            'purpose':'authenticated fixture '+str(time.time_ns()),'deadline_unix_ms':4102444800000,
            'snapshot':'caller evidence','registration':context['registration'],'resources':[],
            'authority':'caller-loop','checks':[],'rubric':'caller cannot select this','mode':'allow','floor':'allow','policy':'caller cannot select this'},
            implications={'effects':[],'resources':[],'principals':[],'reversibility':'unknown','scope_uncertainty':'fixture','evidence':[]})
        request['binding']={'request_id':sha(request),'context_digest':sha(request['context'])}
        return request
    def judge(name, req, expected):
        reply,wall=call('judge', {'schema':1,'request':req})
        assert reply['verdict']['judgement']==expected, reply
        report.append(dict(case=name,result='PASS',wall=wall,verdict=reply['verdict']))
        return reply
    judge('hygiene', request('rm -rf "$TARGET"'), 'refuse')
    req=request('printf learned-fixture')
    key=json.dumps(['command','execute',sha(req['command'])],separators=(',',':'))
    snapshot['learned']=source({'groups':{key:{'allow':1,'refuse':0,'citations':['fixture-review']}}})
    account(OWNER, {'action':'snapshot','value':snapshot})
    judge('learned-hit-enforce', req, 'allow')
    snapshot['registry']=source({'floor':'audit','root':str(LOOP_ROOT)})
    account(OWNER, {'action':'snapshot','value':snapshot})
    judge('learned-hit-audit', request('printf learned-fixture'), 'refer')
    judge('agent-miss-unconfigured', request('printf unseen-fixture'), 'refer')
    program=PAYLOAD/'agent'
    program.write_text('''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
document=json.load(sys.stdin)
auth=Path(os.environ['CODEX_HOME'])/'auth.json'
expected=Path('''+repr(str(LOOP_ROOT/'private/.codex/auth.json'))+''')
assert auth.is_symlink() and auth.resolve()==expected
assert os.geteuid()=='''+str(LOOP_UID)+'''
assert document['reviewed_rubric']=='Reviewed fixture rubric. Return a loop allowance.'
with Path('''+repr(str(LOOP_ROOT/'direct/agent-calls'))+''').open('a') as file:
    file.write('one call\\n')
print(json.dumps({'type':'response.completed','response':{'model':'observed-fixture'}}))
print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':json.dumps({'verdict':'allow','scope':'loop','reason':'reviewed fixture'})}}))
''')
    program.chmod(0o755)
    rubric='Reviewed fixture rubric. Return a loop allowance.'
    snapshot['rubric']=source({'agent':{'executable':str(program),'model':'configured-fixture','effort':'medium','cap_ms':10000},
        'path':None,'text':rubric,'sha256':hashlib.sha256(rubric.encode()).hexdigest()})
    snapshot['registry']=source({'floor':'enforce','root':str(LOOP_ROOT)})
    account(OWNER, {'action':'snapshot','value':snapshot})
    account(LOOP, {'action':'sign-in'})
    def counter():
        return int(account(LOOP, {'action':'counter'})[0].stdout)
    before=counter()
    judge('learned-hit-zero-calls',request('printf learned-fixture'),'allow')
    assert counter()==before
    judged=judge('agent-miss-one-call',request('printf model-fixture'),'allow')
    assert counter()==before+1
    assert 'observed-model:observed-fixture' in judged['verdict']['evidence'], judged
    account(LOOP, {'action':'remove-sign-in'})
    refused=judge('sign-in-bound-to-loop',request('printf missing-sign-in'),'refer')
    assert refused['verdict']['reason']=='door-agent-sign-in-unavailable', refused
    assert counter()==before+1
    account(LOOP, {'action':'sign-in'})
    binding=judged['verdict']['binding']
    claimed,_=call('claim',{'schema':1,'binding':binding})
    assert claimed['fresh_claim'] is True
    account(LOOP,{'action':'effect'})
    call('claim',{'schema':1,'binding':binding},'execute-command-claim-used')
    outcome=dict(binding=binding,outcome='completed',rationale='one fixture effect',queue_wall_ms=None,judgement_wall_ms=None,execution_wall_ms=1)
    completed,wall=call('complete',{'schema':1,'binding':binding,'outcome':outcome})
    retained=account(LOOP,{'action':'journal'})[0].stdout
    repeated,_=call('complete',{'schema':1,'binding':binding,'outcome':outcome})
    assert repeated==completed and account(LOOP,{'action':'journal'})[0].stdout==retained
    rows=json.loads(retained)['rows']
    matching=[row for row in rows if row['request']['binding']==binding]
    assert len(matching)==1 and matching[0]['outcome']==outcome, matching
    assert matching[0]['snapshot_digest']==hashlib.sha256(encoded(snapshot)).hexdigest(), matching
    report.append(dict(case='claim-complete-retry-one-outcome',result='PASS',wall=wall))
    stale=judge('policy-binding-before-publication',request('printf learned-fixture'),'allow')
    snapshot['written_at']='fixture-policy-republished'
    account(OWNER,{'action':'snapshot','value':snapshot})
    call('claim',{'schema':1,'binding':stale['verdict']['binding']},'execute-command-persistence-authority')
    report.append(dict(case='changed-policy-refuses-stale-claim',result='PASS'))
    if args.hook:
        commands=[
            ('remote','ssh worker true','timeout 10 ssh -n -o BatchMode=yes worker true'),
            ('background','sleep 10 &','sleep 0'),
            ('timing','cargo test --locked','time cargo test --locked'),
            ('objective','touch a; touch b','touch a'),
            ('pipeline','time cargo test | tail -1','set -o pipefail; time cargo test | tail -1'),
            ('destructive','rm -rf "$TARGET"','rm -f ./fixture-file'),
            ('privilege','timeout 10 ssh root@10.0.0.1 sudo true','timeout 10 ssh -n -o BatchMode=yes worker sudo -n true'),
            ('syntax',"printf '",'printf fixture')]
        hook_root=args.native_root/'command-hook-parity'
        if hook_root.exists():
            shutil.rmtree(hook_root)
        hook_root.mkdir(mode=0o700)
        for rule,bad,good in commands:
            for matched,command in [(True,bad),(False,good)]:
                label=rule+('-hit' if matched else '-miss')
                case_root=hook_root/label
                case_root.mkdir(mode=0o700)
                state,registry=case_root/'state',case_root/'registry'
                state.mkdir(mode=0o700); registry.mkdir(mode=0o700)
                entry=registry/'alpha.env'
                entry.write_text(f'LOOP_NAME=alpha\nLOOP_SID=fixture\nLOOP_CWD={case_root}\nLOOP_STATE_ROOT={state}\n')
                entry.chmod(0o600)
                event=dict(session_id='fixture',cwd=str(case_root),transcript_path=str(case_root/'transcript.jsonl'),
                    permission_mode='manual',hook_event_name='PreToolUse',tool_name='Bash',tool_input={'command':command},tool_use_id=label)
                context_file=case_root/'context.json'
                context_file.write_bytes(encoded(event)); context_file.chmod(0o600)
                cli=case_root/'classifier'
                shutil.copyfile(args.source/'packages/permission-triage/tests/fixtures/fake-cli.sh',cli)
                cli.chmod(0o700)
                capture=case_root/'capture'
                env={k:v for k,v in os.environ.items() if not k.startswith('PERMISSION_TRIAGE_') and k!='LD_PRELOAD'}
                env.update(PERMISSION_TRIAGE_REQUEST_CONTEXT=str(context_file),PERMISSION_TRIAGE_LOOP_REGISTRY=str(registry),
                    PERMISSION_TRIAGE_MODE='enforce',PERMISSION_TRIAGE_CLI=str(cli),PERMISSION_TRIAGE_FAKE_CAPTURE=str(capture),
                    PERMISSION_TRIAGE_FAKE_RESPONSE='safe',PERMISSION_TRIAGE_FAKE_SCOPE='estate',
                    PERMISSION_TRIAGE_MODEL_DEADLINE_MS='2000',PERMISSION_TRIAGE_STATE_ROOT=str(state))
                calls=counter()
                direct=judge('direct-hook-'+label,request(command),'refuse' if matched else 'allow')
                assert counter()-calls==int(not matched)
                output,wall=run([str(args.hook),'hook'],data=event,env=env)
                hook=json.loads(output.stdout)['hookSpecificOutput']
                assert hook['permissionDecision']==('deny' if matched else 'allow'), hook
                assert capture.with_suffix('.argv').exists()==(not matched)
                if matched:
                    correction=direct['verdict']['correction']
                    assert correction['changes'] in hook['permissionDecisionReason'], (correction,hook)
                    assert 'rule='+correction['rule'] in hook['permissionDecisionReason'], (correction,hook)
                    assert direct['outcome']['outcome']=='refused-before-effect'
                records=[json.loads(line) for path in state.rglob('*escalations.jsonl') for line in path.read_text().splitlines()]
                events=[row for row in records if 'model_status' in row]
                assert len(events)==1, records
                comparisons.append(dict(callers=['direct','hook'],rule=rule,matched=matched,shared_decision='refuse' if matched else 'allow',
                    correction=direct['verdict']['correction'],hook_reason=hook['permissionDecisionReason'],hook_outcome='unknown-until-harness-observation',
                    records_per_request=1,wall=wall))
    if args.door_report:
        door=json.loads(json.loads(args.door_report.read_text())['stdout'])
        observations=door['observations']
        assert len(observations)==24 and all(row['status']=='pass' for row in observations)
        assert all(row['calls']==int(row['hit'] is None) for row in observations)
        identities=[row['record']['id'] for row in observations]
        assert len(set(identities))==len(identities)
        for row in observations:
            assert len(row['transport']['spawn_observations'])==int(row['record']['effect']['state']=='completed'), row
        for mode in ['audit','enforce']:
            row=next(row for row in observations if row['mode']==mode and row['hit']=='allow')
            snapshot['registry']=source({'floor':mode,'root':str(LOOP_ROOT)})
            account(OWNER,{'action':'snapshot','value':snapshot})
            direct=judge('door-direct-learned-'+mode,request('printf learned-fixture'),'refer' if mode=='audit' else 'allow')
            assert row['record']['would_do']['decision']=='allow'
            assert row['record']['would_do_source']=='fast-lane'
            assert row['calls']==0
            assert direct['verdict']['correction'] is None
            assert (direct['verdict']['escalation'] is not None)==(mode=='audit')
            comparisons.append(dict(callers=['direct','door'],rule='exact-match-and-mode',mode=mode,would_do='allow',agent_calls=0,
                remedy=direct['verdict']['escalation'],door_request_id=row['record']['id'],door_effect=row['record']['effect']['state']))
    if args.gateway_report:
        gateway=json.loads(args.gateway_report.read_text())
        assert gateway['effects']==5
        assert gateway['results']['3']['verdict']=='ok' and gateway['results']['4']['verdict']=='denied'
        snapshot['registry']=source({'floor':'audit','root':str(LOOP_ROOT)})
        account(OWNER,{'action':'snapshot','value':snapshot})
        for answer,expected,sequence in [('approve','allow','3'),('deny','refuse','4')]:
            req=request('printf learned-fixture')
            judged=judge('gateway-review-'+answer,req,'refer')
            direct,_=call('answer',{'schema':1,'answer':{'binding':req['binding'],'review':judged['review'],
                'answer':answer,'adjudicator':context['principal'],'reason':'fixture reviewed answer'}})
            assert direct['verdict']['judgement']==expected
            call('answer',{'schema':1,'answer':{'binding':req['binding'],'review':judged['review'],
                'answer':answer,'adjudicator':context['principal'],'reason':'fixture reviewed answer'}},'execute-command-record-transition')
            if answer=='approve':
                before=int(account(LOOP,{'action':'effect-counter'})[0].stdout)
                claimed,_=call('claim',{'schema':1,'binding':req['binding']})
                assert claimed['fresh_claim'] is True
                account(LOOP,{'action':'effect'})
                outcome=dict(binding=req['binding'],outcome='completed',rationale='one reviewed fixture effect',queue_wall_ms=None,judgement_wall_ms=None,execution_wall_ms=1)
                completed,_=call('complete',{'schema':1,'binding':req['binding'],'outcome':outcome})
                repeated,_=call('complete',{'schema':1,'binding':req['binding'],'outcome':outcome})
                assert completed==repeated and int(account(LOOP,{'action':'effect-counter'})[0].stdout)==before+1
                rows=json.loads(account(LOOP,{'action':'journal'})[0].stdout)['rows']
                assert len([row for row in rows if row['request']['binding']==req['binding'] and row['outcome']==outcome])==1
            else:
                assert direct['outcome']['outcome']=='refused-before-effect'
            comparisons.append(dict(callers=['direct','gateway'],rule='authenticated-loop-review',answer=answer,shared_decision=expected,
                remedy=direct['verdict']['escalation'],native_result=gateway['results'][sequence]['verdict'],duplicate_answer='refused',outcomes_per_effect=1))
    if args.lane_tests:
        tests=['requests::store::snapshot::tests::'+test for test in [
            'direct_policy_publication_preserves_floor_derived_absence_and_mode_revisions',
            'direct_policy_publication_failure_withdraws_stale_policy',
            'direct_policy_publication_refreshes_a_long_lived_stores_registry_floor',
            'direct_policy_writer_compares_policy_group_with_observed_loop_tiers']]
        tests.append('requests::store::tests::failed_mode_publication_keeps_corrected_class_in_audit')
        tests.append('requests::store::tests::snapshot_failure_preserves_durable_door_filings')
        for test in tests:
            account(OWNER, {'action':'owner-test-reset'})
            result,wall=run(['sudo','-n','-u',OWNER,'env','SUPERLOOP_TEST_DIRECT_HOME='+str(HOME),
                'TMPDIR='+str(HOME/'owner-tmp'),'SUPERLOOP_TEST_REQUESTS_HELPER='+str(PAYLOAD/'requests-helper'),str(PAYLOAD/'lane-tests'),
                '--exact',test,'--nocapture'])
            assert b'1 passed' in result.stdout, result.stdout
            if test.endswith('snapshot_failure_preserves_durable_door_filings'):
                assert b'door-rubric-unavailable' in result.stderr, result.stderr
                assert b'direct-policy-publication' in result.stderr, result.stderr
            report.append(dict(case=test,result='PASS',wall=wall))
        account(OWNER, {'action':'owner-test-reset'})
        account(OWNER, {'action':'snapshot','value':snapshot})
        account(LOOP, {'action':'chmod','path':'shared','mode':0o770})
        result,wall=run(['sudo','-n','-u',OWNER,'env','SUPERLOOP_TEST_DIRECT_HOME='+str(HOME),
            'SUPERLOOP_TEST_POLICY_DRIFT=1','TMPDIR='+str(HOME/'owner-tmp'),
            'SUPERLOOP_TEST_REQUESTS_HELPER='+str(PAYLOAD/'requests-helper'),str(PAYLOAD/'lane-tests'),
            '--exact','requests::store::tests::failed_mode_publication_keeps_corrected_class_in_audit','--nocapture'])
        assert b'1 passed' in result.stdout, result.stdout
        assert b'execute-command-snapshot-custody' in result.stderr, result.stderr
        account(LOOP, {'action':'chmod','path':'shared','mode':0o700})
        report.append(dict(case='loop-shared-drift-cannot-block-owner-mode-or-correction',result='PASS',wall=wall))
    evidence={'cases':report,'context':context,'commands':EVENTS,'comparisons':comparisons,
        'comparison_scope':'per shared rule with caller-specific mode, audit and envelope rendering',
        'four_callers':bool(args.hook and args.door_report and args.gateway_report),
        'binaries':{'superloop':hashlib.sha256((PAYLOAD/'superloop').read_bytes()).hexdigest()}}
    if args.hook:
        evidence['binaries']['permission-triage-hook']=hashlib.sha256(args.hook.read_bytes()).hexdigest()
    if args.door_report:
        evidence['door_measurement_sha256']=hashlib.sha256(args.door_report.read_bytes()).hexdigest()
    if args.gateway_report:
        evidence['gateway_measurement_sha256']=hashlib.sha256(args.gateway_report.read_bytes()).hexdigest()
    if args.report:
        args.report.write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'cases':len(report),'result':'PASS','report':str(args.report)},sort_keys=True))

if __name__=='__main__':
    main()
