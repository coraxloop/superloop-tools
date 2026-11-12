#!/usr/bin/env python3
"""Exercise the shipped ordinary-tool waiting recipe under isolated mail folders."""
import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time


def assert_notice(status, output, error):
    assert status == 0 and output == b"You've got mail.\n" and not error, (status, output, error)


def ready_ordering(root, recipe, rearm):
    """Hold the async child before its redirection until the real grep has read."""
    case = root / ('rearm' if rearm else 'first-arm')
    case.mkdir()
    inbox = case / 'inbox'
    inbox.mkdir()
    tools = case / 'bin'
    tools.mkdir()
    helper = case / 'control.py'
    helper.write_text(r'''import os, pathlib, subprocess, sys, time
root = pathlib.Path(os.environ['READY_CASE'])
mode = sys.argv[1]
def wait(path):
    deadline = time.monotonic() + 10
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('fixture gate timed out: ' + str(path))
        time.sleep(0.005)
phase = (root / 'phase').read_text().strip()
if mode == 'gate':
    (root / ('blocked-' + phase)).touch()
    wait(root / ('release-' + phase))
elif mode == 'grep':
    done = root / ('observed-' + phase)
    if not done.exists():
        wait(root / ('blocked-' + phase))
        ready = pathlib.Path(sys.argv[-1])
        state = 'missing' if not ready.exists() else ('stale' if ready.read_bytes() else 'empty')
        result = subprocess.run(['/usr/bin/grep', *sys.argv[2:]])
        done.write_text(state)
        (root / ('release-' + phase)).touch()
        # Never let the recipe kill a child that has not reached its watch stub.
        wait(root / ('executed-' + phase))
        sys.exit(result.returncode)
    os.execv('/usr/bin/grep', ['/usr/bin/grep', *sys.argv[2:]])
elif mode == 'watch':
    inbox = root / 'inbox'
    if os.environ['READY_REARM'] == '1' and phase == '1':
        inbox.rename(root / 'retired-inbox')
        inbox.mkdir()
    else:
        (inbox / 'letter').write_text('fixture')
    print('Watches established.', file=sys.stderr, flush=True)
    (root / ('executed-' + phase)).touch()
    os.execv('/bin/sleep', ['/bin/sleep', '20'])
''')
    for name, mode in [('grep', 'grep'), ('inotifywait', 'watch')]:
        tool = tools / name
        tool.write_text('#!/bin/sh\nexec "$READY_PYTHON" "$READY_HELPER" ' + mode + ' "$@"\n')
        tool.chmod(0o700)
    # Instrument only scheduling before the original async command's redirects.
    # Its redirect, grep, readiness loop and cleanup remain the shipped code.
    # Exec keeps the delayed wrapper and watch at the PID the recipe will reap.
    lines = recipe.splitlines(keepends=True)
    launch = next(line for line in lines if line.lstrip().startswith('LC_ALL=C inotifywait '))
    assert launch.rstrip().endswith(' &')
    child = launch.rstrip()[:-2].replace('LC_ALL=C inotifywait', 'LC_ALL=C exec inotifywait', 1)
    replacement = ('        phase=$(( ${phase:-0} + 1 )); '
                   'printf "%s" "$phase" > "$READY_CASE/phase"\n'
                   '        { "$READY_PYTHON" "$READY_HELPER" gate;\n' +
                   child + '\n        } &\n')
    script = case / 'recipe.sh'
    script.write_text(recipe.replace(launch, replacement, 1))
    environment = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'],
                       READY_CASE=str(case), READY_HELPER=str(helper),
                       READY_PYTHON=sys.executable, READY_REARM=str(int(rearm)))
    process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        output, error = process.communicate(timeout=30)
    finally:
        # Own the group: even a broken recipe cannot leave a fixture watcher behind.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)
    evidence = (process.returncode, output, error)
    assert_notice(*evidence)
    phases = ['1', '2'] if rearm else ['1']
    observed = [(case / ('observed-' + phase)).read_text() for phase in phases]
    assert observed == ['empty'] * len(phases), (observed, evidence)
    print(json.dumps({'ready_ordering': 'rearm' if rearm else 'first-arm', 'observed': observed}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--recipe', required=True, type=pathlib.Path)
    parser.add_argument('--ordering-only', choices=['first', 'rearm'])
    args = parser.parse_args()
    # Meson stops a timed-out test with SIGTERM to the fixture's group only; unwinding runs
    # each scheduling case's finally, which kills the recipe's own session.
    signal.signal(signal.SIGTERM, lambda number, frame: sys.exit(128 + number))
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='inbox-wait-') as directory:
        root = pathlib.Path(directory)
        script = root / 'recipe.sh'
        script.write_text(args.recipe.read_text().split('```bash\n', 1)[1].split('```', 1)[0])
        if args.ordering_only:
            ready_ordering(root, script.read_text(), args.ordering_only == 'rearm')
            return
        ready_ordering(root, script.read_text(), False)
        ready_ordering(root, script.read_text(), True)
        inbox = root / 'inbox'
        history = root / 'read'
        missing = subprocess.run(['/bin/bash', str(script), str(inbox), '1'], capture_output=True, timeout=5)
        assert missing.returncode == 3 and not missing.stdout
        assert b'inbox is missing or unreadable' in missing.stderr
        inbox.mkdir()
        history.mkdir()
        (history / 'old').write_bytes(b'old envelope\0\xff')
        process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.2)
            assert process.poll() is None, 'read history must not notify'
            (inbox / '.binary').write_bytes(b'\0\xffprivate body')
            output, error = process.communicate(timeout=5)
            assert_notice(process.returncode, output, error)
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
            assert_notice(process.returncode, output, error)
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
        result = subprocess.run(['/bin/bash', str(script), str(inbox), '1'], env=environment,
                                capture_output=True, timeout=5)
        assert (root / 'armed').read_text() == 'armed'
        assert_notice(result.returncode, result.stdout, result.stderr)
        (inbox / 'raced').unlink()
        # Overflow is reconciled by listing rather than interpreted as a delivery.
        stub.write_text('#!/bin/sh\nprintf "Watches established.\\n" >&2\n/bin/sleep 0.2\nprintf opaque > "$WATCH_INBOX/overflow"\nprintf "Q_OVERFLOW\\n"\nexec /bin/sleep 20\n')
        result = subprocess.run(['/bin/bash', str(script), str(inbox), '1'], env=environment,
                                capture_output=True, timeout=5)
        assert_notice(result.returncode, result.stdout, result.stderr)
        (inbox / 'overflow').unlink()
        # Watch failure uses bounded ordinary listings, without inspecting bodies.
        stub.write_text('#!/bin/sh\nexit 1\n')
        process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.2)
            (inbox / 'fallback').write_bytes(b'no metadata')
            output, error = process.communicate(timeout=5)
            assert_notice(process.returncode, output, error)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)
        (inbox / 'fallback').unlink()
        if os.geteuid() != 0:
            # The marker proves startup accepted the readable inbox before access
            # is removed, so exit 3 must come from notice(), not the startup guard.
            marker = root / 'unreadable-armed'
            environment['WATCH_MARKER'] = str(marker)
            stub.write_text('#!/bin/sh\nprintf armed > "$WATCH_MARKER"\nexit 1\n')
            process = subprocess.Popen(['/bin/bash', str(script), str(inbox), '1'], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    assert process.poll() is None, 'watcher exits before arming'
                    time.sleep(0.01)
                assert marker.exists(), 'watcher entered after startup guard'
                inbox.chmod(0o000)
                output, error = process.communicate(timeout=5)
                assert process.returncode == 3 and not output
                assert error == b'inbox-watch: inbox is unreadable\n'
            finally:
                inbox.chmod(0o700)
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=3)
    print(json.dumps({'result': 'PASS', 'wall_seconds': round(time.monotonic() - started, 3)}))


if __name__ == '__main__':
    main()
