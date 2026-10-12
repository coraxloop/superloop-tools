import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()
root, tree, binary = args.root, args.source, args.binary
if root.exists():
    shutil.rmtree(root)
root.mkdir(mode=0o700)
home = root / 'home'
config = home / '.config/loops/alpha'
runs = home / 'runs'
for path in [home, home / '.config', config.parent, config, runs, runs / '.launch-R']:
    path.mkdir(mode=0o700)
def write(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)
def record(path, value):
    write(path, json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n')
write(config.parent / 'registry.toml', f'namespace = "org.superloop-tools.loophome.registry"\nversion = [1, 0, 0]\nloops = [{{ name = "alpha", uid = 41001, launch = "dev/alpha", runs_root = "{runs}", door_floor = "allow" }}]\n')
entry = config / 'entry-fixture'
write(entry, '#!/bin/sh\n[ "$1" = show ] || exit 2\nprintf \'%s\\n\' \'{"name":"alpha","uid":41001}\'\n', 0o700)
write(config / 'workers.toml', f'runs_root = "{runs}"\nentry_bin = "{entry}"\ndriver_argv = ["/usr/bin/true"]\nimage_digest = "sha256:{"a"*64}"\ntemplate_dir = "{home / "template"}"\nsocket_dir = "{home / "sockets"}"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n')
record(config / 'door-compute-registration.json', dict(schema=1, loop='alpha', alias='fixture', mirror_root='~/mirrors', node_root='/srv/loops/loop-a', key_path=str(config / 'door-key')))
key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
record(config / 'door-node-registration.json', dict(schema=1, loop='alpha', alias='fixture', address='192.0.2.1', port=2222, user='fixture', host_key=key))
write(config / 'door-known_hosts', f'[192.0.2.1]:2222 {key}\n')
write(config / 'door-ssh_config', f'# Registered host key: {key}\nHost fixture\n  HostName 192.0.2.1\n  Port 2222\n  User fixture\n  UserKnownHostsFile {config / "door-known_hosts"}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  BatchMode yes\n')
plan = json.loads((tree / 'packages/superloop-lane/tests/fixtures/plan.json').read_text())
source = '~/sockets/door'
target = '/home/worker/.local/door'
index = next(i for i,row in enumerate(plan['mounts']) if row['target'] == '/etc/passwd')
plan['mounts'].insert(index, dict(target=target, source=source, access='ro', kind='bind'))
plan['mount_sources'].append(dict(path=source, uid=41001))
inventory = plan['mount_inventory']['entries']
index = next(i for i,row in enumerate(inventory) if row['target'] == '/etc/passwd')
inventory.insert(index, dict(target=target, source=source, access='ro', kind='bind', source_role='capability-door', owner=41001, presence='required'))
argv = plan['runtime_argv']
index = next(i for i,word in enumerate(argv) if 'dst=/etc/passwd' in word)-1
argv[index:index] = ['--mount', f'type=bind,src={source},dst={target},ro']
plan['box_gate']['runtime_argv_sha256'] = hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest()
plan['door_floor'] = 'allow'
plan['door'] = dict(schema=1, socket='/home/worker/.local/door/capability.sock', stub='/home/worker/.local/libexec/superloop/ssh', stub_sha256='0'*64, registered=['ssh'], peer_uid=3000, mirror_ref='refs/heads/lane/R')
record(runs / '.reservation-R.json', dict(schema=1, phase='settled', loop='alpha', run='R', worker_uid=3000, door_scope='work', plan=plan))
write(config / 'door-requests.lock', '')
setting = dict(mode='audit', floor='allow', setter='fixture', evidence='registered floor', set_at='1', revision=1, citations=[])
record(config / 'door-modes.json', dict(schema=1, loop='alpha', revision=1, loop_settings=[setting], classes=[]))
env = dict(os.environ, HOME=str(home))
env.pop('LD_PRELOAD', None)
start = time.time_ns()
print(f'START utc_ns={start} case=door-agent-public-exercise', flush=True)
output = subprocess.run([str(binary), 'exercise', 'alpha', '--run', 'R', '--case', 'door-agent'], capture_output=True, env=env, timeout=120)
end = time.time_ns()
print(f'END utc_ns={end} wall_ns={end-start} exit={output.returncode}', flush=True)
print(output.stdout.decode(), flush=True)
print(output.stderr.decode(), flush=True)
args.report.write_text(json.dumps(dict(start_ns=start, end_ns=end, wall_ns=end-start, exit=output.returncode, stdout=output.stdout.decode(), stderr=output.stderr.decode(), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()), indent=2)+'\n')
report = json.loads(output.stdout)
assert len(report['observations']) == 24, report
assert all(row['status'] == 'pass' for row in report['observations']), report
assert all(row['status'] == 'pass' for row in report['runner_fixtures']), report
assert report['real_runner']['status'] == 'unmeasured', report
print('TRIAGE_DOOR 24 mode observations; process fixtures pass; vendor call unmeasured', flush=True)

for row in report['observations']:
    assert row['calls'] == (0 if row['hit'] is not None else 1), row
    if row['mode'] in ['audit', 'enforce'] and row['hit'] is None and row['verdict'] == 'refer':
        before = row['transport']['before_answer']
        assert before['state'] == 'waiting' and before['effect']['state'] == 'pending' and before['label'] is None, before
        assert before['would_do']['decision'] == 'refer', before
        assert 'execute-command-route-unprovisioned' not in before['agent_reason'], before
print('DOOR_REFERRALS audit/enforce waiting with pending effects before loop answer', flush=True)
