"""Host-authored sealed invocation, after the dedicated receiver's identity transition."""
import io
import json
import os
import sys

invocation = json.load(sys.stdin)
loop_name, loop_uid = sys.argv[1:]
if os.getuid() != int(loop_uid) or os.geteuid() != int(loop_uid):
    raise ValueError('anchor-identity: operation=door-consumer purpose=loop-uid')
sys.argv = ['door-consumer', *invocation['arguments'], loop_name, loop_uid]
sys.stdin = io.TextIOWrapper(io.BytesIO(invocation['input'].encode('utf-8')))
exec(compile(invocation['source'], '<door-invocation>', 'exec'), {'__name__': '__main__'})
