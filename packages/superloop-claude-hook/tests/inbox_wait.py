#!/usr/bin/env python3
"""Exercise the shipped ordinary-tool waiting recipe under isolated mail folders."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--recipe', required=True, type=pathlib.Path)
    args = parser.parse_args()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='inbox-wait-') as directory:
        root = pathlib.Path(directory)
        script = root / 'recipe.sh'
        script.write_text(args.recipe.read_text().split('```bash\n', 1)[1].split('```', 1)[0])
        inbox = root / 'inbox'
        history = root / 'read'
        inbox.mkdir()
        history.mkdir()
        (history / 'old').write_bytes(b'old envelope\0\xff')
        process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.2)
            assert process.poll() is None, 'read history must not notify'
            (inbox / '.binary').write_bytes(b'\0\xffprivate body')
            output, error = process.communicate(timeout=5)
            assert process.returncode == 0 and output == b"You've got mail.\n" and not error
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)
        (inbox / '.binary').unlink()
        process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.2)
            inbox.rename(root / 'replaced')
            inbox.mkdir()
            time.sleep(0.2)
            (inbox / 'replacement').write_bytes(b'new directory')
            output, error = process.communicate(timeout=5)
            assert output == b"You've got mail.\n" and not error
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)
        (inbox / 'replacement').unlink()
        # A fixture watch acknowledges arming after publishing an arrival, before listing.
        tools = root / 'bin'
        tools.mkdir()
        stub = tools / 'inotifywait'
        stub.write_text('#!/bin/sh\nprintf armed > "$WATCH_MARKER"\nprintf "\\000\\377" > "$WATCH_INBOX/raced"\nprintf "Watches established.\\n" >&2\nexec /bin/sleep 20\n')
        stub.chmod(0o700)
        environment = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'], WATCH_MARKER=str(root / 'armed'), WATCH_INBOX=str(inbox))
        result = subprocess.run(['/bin/bash', str(script), str(inbox), '1'], env=environment, capture_output=True, timeout=5, check=True)
        assert (root / 'armed').read_text() == 'armed'
        assert result.stdout == b"You've got mail.\n" and not result.stderr
        (inbox / 'raced').unlink()
        # Overflow is reconciled by listing rather than interpreted as a delivery.
        stub.write_text('#!/bin/sh\nprintf "Watches established.\\n" >&2\n/bin/sleep 0.2\nprintf opaque > "$WATCH_INBOX/overflow"\nprintf "Q_OVERFLOW\\n"\nexec /bin/sleep 20\n')
        result = subprocess.run(['/bin/bash', str(script), str(inbox), '1'], env=environment, capture_output=True, timeout=5, check=True)
        assert result.stdout == b"You've got mail.\n" and not result.stderr
        (inbox / 'overflow').unlink()
        # Watch failure uses bounded ordinary listings, without inspecting bodies.
        stub.write_text('#!/bin/sh\nexit 1\n')
        process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.2)
            (inbox / 'fallback').write_bytes(b'no metadata')
            output, error = process.communicate(timeout=5)
            assert output == b"You've got mail.\n" and not error
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)
    print(json.dumps({'result': 'PASS', 'wall_seconds': round(time.monotonic() - started, 3)}))


if __name__ == '__main__':
    main()
