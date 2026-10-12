# Permission-triage settings fragment

Assembly renders `settings-fragment.json` from the configured absolute `PERMISSION_TRIAGE_ADAPTER_BIN`; the source file is a template, not an installable registration. The rendered file is a merge fragment containing only the single all-tools `PreToolUse` registration. `matcher: "*"` selects every tool; the command timeout is 60 seconds, matching the 60000-millisecond hook ceiling. Neither the fragment nor assembly selects a harness permission mode. Mode, bypass evidence, inventory, and readiness remain in the separate deployment record and must never be merged into settings.

Before registration or reinstall, the owner stops bypass sessions or restores their ordinary harness gate and reads back that no bypass session remains. Follow `assemble.md` in order: inventory and digests; declared workload/window/limits; audit assembly; reviewed placement; this merge; fresh-session read-back; observation and readiness review; then the separately authorized enforce transition. Assembly always renders an audit instance, even when the source or previous deployment record says enforce.

Under the separate owner authorization, back up the settings and merge exactly one registration. The command below refuses an existing permission-triage command, appends the assembled object to the existing `PreToolUse` array, verifies every previous array element and other setting remains unchanged, and atomically replaces the file. It inserts only the new JSON bytes; every existing byte, including other hook registrations and their whitespace, is preserved. It neither adds nor changes a permissions setting. Use the private `TRIAGE_STAGE` established in `assemble.md`.

```sh
set -eu
/usr/bin/cp -p "$HOME/.claude/settings.json" "$TRIAGE_STAGE/settings.before.json"
/usr/bin/python3 - "$HOME/.claude/settings.json" "$TRIAGE_STAGE/assembly/settings-fragment.json" <<'PY'
import copy, json, os, pathlib, shlex, sys
p = pathlib.Path(sys.argv[1]); before_bytes = p.read_bytes(); before = json.loads(before_bytes)
fragment = json.load(open(sys.argv[2]))
assert set(fragment) == {'hooks'} and set(fragment['hooks']) == {'PreToolUse'}
entry, = fragment['hooks']['PreToolUse']
assert entry['matcher'] == '*'
adapter = os.environ['PERMISSION_TRIAGE_ADAPTER_BIN']
assert pathlib.Path(adapter).is_absolute()
hook, = entry['hooks']
assert shlex.split(hook['command']) == [adapter, 'pre-tool-use']
assert hook['timeout'] == 60 and hook['type'] == 'command'
for registrations in before.get('hooks', {}).values():
    for registration in registrations:
        for hook in registration.get('hooks', []):
            assert shlex.split(hook.get('command', '')) != [adapter, 'pre-tool-use'], 'registration already exists'
after = copy.deepcopy(before)
after.setdefault('hooks', {}).setdefault('PreToolUse', []).append(entry)
previous = copy.deepcopy(after)
previous['hooks']['PreToolUse'].pop()
if 'PreToolUse' not in before.get('hooks', {}):
    del previous['hooks']['PreToolUse']
if 'hooks' not in before:
    del previous['hooks']
assert previous == before
original = before_bytes.decode('utf-8')
decoder = json.JSONDecoder()
def skip_space(position):
    while position < len(original) and original[position].isspace():
        position += 1
    return position
def member(start, name):
    position = skip_space(start)
    assert original[position] == '{'
    position = skip_space(position + 1)
    found = None
    while original[position] != '}':
        key, position = decoder.raw_decode(original, position)
        position = skip_space(position)
        assert original[position] == ':'
        start_value = skip_space(position + 1)
        value, end_value = decoder.raw_decode(original, start_value)
        if key == name:
            assert found is None, 'duplicate target key'
            found = (start_value, end_value, value)
        position = skip_space(end_value)
        if original[position] == '}':
            break
        assert original[position] == ','
        position = skip_space(position + 1)
    return found
hooks = member(0, 'hooks')
pre = member(hooks[0], 'PreToolUse') if hooks else None
if pre:
    assert isinstance(pre[2], list)
    offset = pre[1] - 1
    insertion = (',' if pre[2] else '') + json.dumps(entry)
elif hooks:
    assert isinstance(hooks[2], dict)
    offset = hooks[1] - 1
    insertion = (',' if hooks[2] else '') + '"PreToolUse":' + json.dumps([entry])
else:
    offset = len(original.rstrip()) - 1
    insertion = (',' if before else '') + '"hooks":' + json.dumps({'PreToolUse': [entry]})
updated = original[:offset] + insertion + original[offset:]
assert json.loads(updated) == after
raw = updated.encode()
tmp = p.with_name(p.name + '.owner-merge.tmp')
with tmp.open('xb') as f:
    os.chmod(tmp, p.stat().st_mode & 0o777); f.write(raw); f.flush(); os.fsync(f.fileno())
os.replace(tmp, p)
assert json.loads(p.read_bytes()) == after
print(json.dumps(after['hooks']['PreToolUse'][-1], indent=2))
PY
```

Fresh-session read-back is a human act: start fresh ordinary-gate sessions and verify the one registration, explicit audit instance, active harness mode, reviewed hook/harness build identities, registry/domain digests, adjudicator routes, and zero healthy audit decision bytes. Every live session must appear in the private inventory; the absence of complaints does not prove silence or coverage. The real-harness sentinel rehearsal on the host is required separately; fake-harness results are procedure tests only.

The owner flips only after the complete readiness record passes `assemble --check` with `--audit-evidence`, and the same command without `--check` publishes its justification. In a controlled session transition with no intervening tool work, set the explicit hook mode to enforce, read it back and validate, then start the measured bypass session. Read back both modes and repeat allow, deny, settings-deny, and failure sentinels before resuming work. Never enable bypass while audit remains active.

Rollback reverses that order: stop bypass sessions or restore their ordinary harness gate and verify it, then set audit or remove the registration and restore the saved settings. Under the owner authorization, settings restoration is self-verified below. Preserve the deployment/readiness record and journal evidence; a subsequent reinstall renders audit again.

```sh
/usr/bin/cp -p "$TRIAGE_STAGE/settings.before.json" "$HOME/.claude/settings.json"
/usr/bin/cmp "$TRIAGE_STAGE/settings.before.json" "$HOME/.claude/settings.json"
```
