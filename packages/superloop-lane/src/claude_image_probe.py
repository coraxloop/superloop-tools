"""Measure only the pinned image's CLI and runtime, with no sign-in or network."""
import hashlib
import json
import os
import selectors
import struct
import subprocess
import time

program = '/usr/libexec/superloop/claude'
with open(program, 'rb') as source:
    artifact = source.read()
if artifact[:7] != b'\x7fELF\x02\x01\x01':
    raise RuntimeError('Claude is not ELF64 little-endian')
offset = struct.unpack_from('<Q', artifact, 32)[0]
size, count = struct.unpack_from('<HH', artifact, 54)
interpreters = []
for index in range(count):
    header = offset + index * size
    if struct.unpack_from('<I', artifact, header)[0] == 3:
        start = struct.unpack_from('<Q', artifact, header + 8)[0]
        length = struct.unpack_from('<Q', artifact, header + 32)[0]
        interpreters.append(artifact[start:start + length].rstrip(b'\0').decode())
if len(interpreters) != 1 or not interpreters[0].startswith('/'):
    raise RuntimeError('Claude must name one image interpreter')
interpreter = interpreters[0]
environment = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp/claude-home',
               'CLAUDE_CONFIG_DIR': '/tmp/claude-home/.claude',
               'DISABLE_AUTOUPDATER': '1',
               'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1'}
os.makedirs(environment['CLAUDE_CONFIG_DIR'], mode=0o700)


def run(argv):
    with subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            deadline = time.monotonic() + 20
            output = {child.stdout: bytearray(), child.stderr: bytearray()}
            with selectors.DefaultSelector() as selector:
                for pipe in output:
                    selector.register(pipe, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError('image probe deadline')
                    for key, _ in selector.select(remaining):
                        data = os.read(key.fd, 4096)
                        if not data:
                            selector.unregister(key.fileobj)
                        else:
                            output[key.fileobj].extend(data)
                            if len(output[key.fileobj]) > 65536:
                                raise RuntimeError('probe output exceeds 65536 bytes')
            if child.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise RuntimeError('image program probe refused')
            return output[child.stdout].decode()
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


def measured(path):
    if not path.startswith('/') or not os.path.isfile(path):
        raise RuntimeError('runtime dependency is not an image file')
    with open(path, 'rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'path': path, 'sha256': digest}


libraries = set()
for line in run([interpreter, '--list', program]).splitlines():
    words = line.split()
    if not words:
        continue
    if 'not found' in line:
        raise RuntimeError('missing image runtime dependency')
    path = words[2] if len(words) > 2 and words[1] == '=>' else words[0]
    if path.startswith('/') and path != interpreter:
        libraries.add(path)
if not libraries:
    raise RuntimeError('no image runtime libraries measured')
print(json.dumps({'sha256': hashlib.sha256(artifact).hexdigest(),
                  'version': run([program, '--version']),
                  'help': run([program, '--help']),
                  'interpreter': measured(interpreter),
                  'libraries': [measured(path) for path in sorted(libraries)]}))
