#!/usr/bin/env python3
"""Fixture-only public migration entry; namespace-root rehearsal is explicit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def controller_pin(path):
    return {'path':str(path.absolute()), 'sha256':digest(path)}


def run(argv):
    start = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    return result, round(time.monotonic() - start, 3)


CONTROLLER = r'''#!/usr/bin/python3
import json,os,shutil,sys
from pathlib import Path
operation,home,state=sys.argv[1:]
state=Path(state)
if operation=='restore-state':
    manifest=json.loads((state/'cutover.json').read_text())
    for snapshot in manifest['snapshots']:
        target=Path(snapshot['path'])
        if not snapshot['present']:
            if target.exists():raise RuntimeError('unexpected legacy destination')
            continue
        source=state/snapshot['backup']/'tree'
        if not target.exists():
            shutil.copytree(source,target,symlinks=True)
        for original in sorted([source,*source.rglob('*')],key=lambda p:len(p.parts),reverse=True):
            restored=target/original.relative_to(source)
            info=original.lstat()
            os.chown(restored,info.st_uid,info.st_gid,follow_symlinks=False)
            shutil.copystat(original,restored,follow_symlinks=False)
    for artifact in manifest['plan']['deployment']['artifacts']:
        source=Path(artifact['previous']['path']);target=Path(artifact['path'])
        shutil.copyfile(source,target);shutil.copystat(source,target)
if operation=='install-current':
    manifest=json.loads((state/'cutover.json').read_text())
    for artifact in manifest['plan']['deployment']['artifacts']:
        source=Path(artifact['current']['path']);target=Path(artifact['path'])
        shutil.copyfile(source,target);shutil.copystat(source,target)
# This fixture starts no sessions, containers, workers, unit or watcher.
if operation not in ['hold','verify-held','restore-state','restore-processes','verify-restored','install-current']:
    raise RuntimeError('unknown fixture operation')
print(json.dumps({'operation':operation,'home':home,'state':str(state),'complete':True}))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--lane', type=Path)
    parser.add_argument('--controller', type=Path, help='digest-pin this estate adapter instead of the fixture controller')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--namespace-root', action='store_true')
    args = parser.parse_args()
    selected_controller = controller_pin(args.controller) if args.controller else None
    if not args.namespace_root:
        if os.geteuid() == 0:
            raise SystemExit('explicit --namespace-root and a fresh fixture root are required')
        result, wall = run([str(args.binary), 'migrate', 'prepare', '/absent/migration-state', '/absent/migration-plan'])
        assert result.returncode == 2, result.stderr
        assert 'namespace-root migration required' in result.stderr, result.stderr
        if args.controller:
            assert controller_pin(args.controller) == selected_controller, 'controller changed during public refusal'
        print(json.dumps({'result':'PASS','wall_seconds':wall,'measured':'public unprivileged refusal','namespace_root':'unmeasured; explicit host rehearsal required','controller':selected_controller}))
        return
    if os.geteuid() != 0 or args.root is None or args.lane is None:
        raise SystemExit('namespace root, --root and --lane are required')
    root = args.root.absolute()
    root.mkdir(mode=0o711)  # Refuse any pre-existing fixture root.
    os.chmod(root,0o711)
    home = root/'home'; state = root/'state'
    home.mkdir(mode=0o711); state.mkdir(mode=0o700)
    for name in ['.config','.config/loops','.var','.var/loops','.var/loops/alpha','.var/loops/alpha/private']:
        path=home/name;path.mkdir();os.chmod(path,0o711 if name.startswith('.var') else 0o700)
    loop=home/'.var/loops/alpha'
    os.chown(loop/'private',3000,3000);os.chmod(loop/'private',0o700)
    private_config=loop/'private/.config';private_config.mkdir();os.chown(private_config,3000,3000);os.chmod(private_config,0o700)
    mail_config=private_config/'mail';mail_config.mkdir();os.chown(mail_config,3000,3000);os.chmod(mail_config,0o700)
    (mail_config/'preserved').write_bytes(b'configuration remains opaque\x00\xff')
    os.chown(mail_config/'preserved',3000,3000)
    # Synthetic stand-in only: this fixture refuses any pre-existing root.
    key=b'fixture credential never enters migration state\x00\xff'
    credential=private_config/'gpg-loops/alpha/private-keys-v1.d/key'
    credential.parent.mkdir(parents=True)
    for directory in [private_config/'gpg-loops',private_config/'gpg-loops/alpha',credential.parent]:
        os.chown(directory,3000,3000);os.chmod(directory,0o700)
    credential.write_bytes(key);os.chown(credential,3000,3000);os.chmod(credential,0o600)
    credential_identity=(credential.stat().st_dev,credential.stat().st_ino)
    private_config_identity=(private_config.stat().st_dev,private_config.stat().st_ino)
    def credentials_stay_private():
        assert (credential.stat().st_dev,credential.stat().st_ino)==credential_identity
        assert credential.stat().st_uid==3000 and credential.read_bytes()==key
        assert (private_config.stat().st_dev,private_config.stat().st_ino)==private_config_identity
        assert not any(p.is_file() and p.read_bytes()==key for p in state.rglob('*'))
        assert any(p.is_file() and p.read_bytes()==b'configuration remains opaque\x00\xff' for p in state.rglob('*')), 'STATE scan must reach the preserved backup'

    (home/'.config/loops/registry.toml').write_text("namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=3000,launch='dev/alpha'}]\n")
    (home/'.config/loops/allocations.toml').write_text('[alpha]\nuids={base=4000,count=64}\n')
    (home/'.config/loops/mail-service.toml').write_text('version=1\nuid=65535\ncrash_consistent_rename=true\ndurable_sync=true\n')
    for name in ['registry.toml','allocations.toml']: os.chmod(home/'.config/loops'/name, 0o600)
    for leaf in ['inbox','inbox/new','inbox/cur','workers','workers/lane','runs']:
        path=loop/leaf;path.mkdir();os.chmod(path,0o755 if leaf=='runs' else 0o710)
        if leaf!='runs':os.chown(path,3000,3000)
    (loop/'workers/lane/retained').write_bytes(b'execution tree\x00\xff')
    (loop/'runs/table.tsv').write_text('uid\tlane\tdriver\tcommit\tstarted\n4000\tlane\tfixture\tfixture\t0\n')
    letters=[('inbox/new/duplicate',b'old envelope\x00\xff'),('inbox/cur/duplicate',b'other bytes'),('inbox/new/.tmp-legacy',b'partial opaque history')]
    for name,body in letters:(loop/name).write_bytes(body)
    images=root/'images';images.mkdir();installed=root/'installed';installed.mkdir()
    artifacts=[]
    names=['superloop','superloop-install','superloop-lane','superloop-mail','door-service','door-ssh','permission-triage-assemble','permission-triage-hook','superloop-claude-hook','vendor-proxy','worker-run']
    for name in names:
        current=images/(name+'.current');previous=images/(name+'.previous');target=installed/name
        source=args.binary if name=='superloop-mail' else args.lane if name=='superloop-lane' else None
        if source:shutil.copyfile(source,current)
        else:current.write_text('#!/bin/sh\nexit 0\n')
        previous.write_text('#!/bin/sh\nexit 0 # previous fixture deployment\n')
        os.chmod(current,0o755);os.chmod(previous,0o755);shutil.copyfile(current,target);os.chmod(target,0o755)
        artifacts.append({'path':str(target),'current':{'path':str(current),'sha256':digest(current)},'previous':{'path':str(previous),'sha256':digest(previous)}})
    if selected_controller is None:
        controller=images/'controller';controller.write_text(CONTROLLER);os.chmod(controller,0o700)
        selected_controller=controller_pin(controller)
    review=images/'retirement-review';review.write_text('Fixture reviewed entry and round retirement artifact projection.\n')
    projection=hashlib.sha256(json.dumps(artifacts,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    plan={'version':1,'home':str(home),'deployment':{'controller':selected_controller,'native_lane':next(item['current'] for item in artifacts if Path(item['path']).name=='superloop-lane'),'artifacts':artifacts,'retirements':[{'requirement':requirement,'revision':'1'*40,'review':{'path':str(review),'sha256':digest(review)},'installed_digest':projection} for requirement in ['req:mail:legacy-entry-retirement','req:mail:round-transport']]}}
    plan_path=root/'plan.json';plan_path.write_text(json.dumps(plan));os.chmod(plan_path,0o600)
    events=[]
    binary=images/'superloop-mail.current'
    for operation in ['prepare','apply','apply','verify']:
        result,wall=run([str(binary),'migrate',operation,str(state),str(plan_path)])
        events.append({'operation':operation,'wall_seconds':wall,'status':result.returncode,'output':result.stderr})
        assert result.returncode==0,result.stderr
        credentials_stay_private()
    manifest=json.loads((state/'cutover.json').read_text())
    assert manifest['phase']=='verified' and manifest['legacy_outbox_policy'].startswith('inert:')
    assert (loop/'worker-homes/lane/retained').read_bytes()==b'execution tree\x00\xff'
    observed=sorted(path.read_bytes() for path in (loop/'mail/read').rglob('*') if path.is_file())
    assert observed==sorted(body for _,body in letters)
    for name,_ in letters:assert not (loop/name).exists()
    for operation in ['rollback','rollback']:
        result,wall=run([str(binary),'migrate',operation,str(state),str(plan_path)])
        events.append({'operation':operation,'wall_seconds':wall,'status':result.returncode,'output':result.stderr})
        assert result.returncode==0,result.stderr
        credentials_stay_private()
    for name,body in letters:assert (loop/name).read_bytes()==body
    assert (loop/'workers/lane/retained').read_bytes()==b'execution tree\x00\xff'
    assert (loop/'.mail-migration-hold').is_dir()
    assert (state/'lifetime-history/history.json').is_file()
    assert not (loop/'mail').exists()
    assert (mail_config/'preserved').read_bytes()==b'configuration remains opaque\x00\xff'
    first_names=[worker['identity']['name'] for worker in manifest['inventory']['workers']]
    for operation in ['reconcile','apply','verify','rollback']:
        result,wall=run([str(binary),'migrate',operation,str(state),str(plan_path)])
        events.append({'operation':operation,'wall_seconds':wall,'status':result.returncode,'output':result.stderr})
        assert result.returncode==0,result.stderr
        credentials_stay_private()
    next_manifest=json.loads((state/'cutover.json').read_text())
    assert next_manifest['generation']==1
    assert set(first_names).isdisjoint(worker['identity']['name'] for worker in next_manifest['inventory']['workers'])
    assert next_manifest['mapping_history']
    (root/'evidence.json').write_text(json.dumps({'result':'PASS','namespace_root':True,'events':events},indent=2)+'\n')
    print(json.dumps({'result':'PASS','fixture':str(root),'events':events}))


if __name__=='__main__':
    main()
