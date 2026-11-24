"""Exercise the production node program with real Git and a fake wrapper."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
import shutil
import time
import itertools
import types
import struct
from unittest.mock import patch

source, temporary = sys.argv[1:]
namespace = {"__name__": "fixture"}
exec(source, namespace)
# Production still reads its clock at each phase; scheduling cannot spend the
# synthetic preparation budget while real Git executes in this fixture.
ticks = itertools.count()
namespace["time"] = types.SimpleNamespace(monotonic=lambda: next(ticks) / 1000)
namespace["route_ended"] = lambda: False
root = Path(temporary)
mirror = root / "mirrors" / "R.git"
mirror.parent.mkdir()
seed = root / "seed"
seed.mkdir()
real_run = subprocess.run
events = []
wrappers = []
compute_environment = {"RUSTUP_HOME": "/opt/fixture/rustup", "PATH": "/opt/fixture/tools:/opt/fixture/cargo/bin:/usr/bin:/bin", "PUBLIC_PACK_TEST_LINTER": "/opt/fixture/tools/superloop-lint"}


def git(*words, cwd=seed):
    return real_run(["/usr/bin/git", *words], cwd=cwd, check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


git("init", "--bare", str(mirror))
git("init")
git("config", "user.name", "Fixture")
git("config", "user.email", "fixture@example.invalid")
git("config", "commit.gpgsign", "false")
(seed / "file").write_text("original\n")
git("add", "file")
git("commit", "-m", "fixture")


def run(command, **kwargs):
    events.append(command)
    if command[0] == "/usr/bin/timeout":
        assert command[1:3] == ["-k", "10"]
        assert command[4:7] == ["/usr/bin/timeout", "-k", "10"]
        assert command[3] == command[7]
        assert command[8] == "/opt/fixture/bin/report"
        env = kwargs["env"]
        assert env["RUSTDOCFLAGS"] == "-D warnings"
        assert env["CARGO_NET_OFFLINE"] == "true"
        assert env["CARGO_HOME"] == str(root / "cargo")
        assert env["CARGO_TARGET_DIR"] == str(root / "lanes/R-build")
        assert Path(env["TMPDIR"]).is_dir()
        assert env["PATH"] == compute_environment["PATH"]
        assert env["RUSTUP_HOME"] == compute_environment["RUSTUP_HOME"]
        assert "RUSTUP_TOOLCHAIN" not in env
        checkout = kwargs["cwd"]
        assert env["PUBLIC_PACK_TEST_LINTER"] == compute_environment["PUBLIC_PACK_TEST_LINTER"]
        with (root / "lanes/R.lock").open("a") as held:
            try:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                raise AssertionError("run lock was released before wrapper completion")
            except BlockingIOError:
                pass
        wrappers.append((git("rev-parse", "HEAD", cwd=checkout), command[9:]))
        if command[9:11] == ["cargo", "fmt"]:
            (checkout / "file").write_text("formatted\n")
        elif command[9:] == ["git", "diff"]:
            assert "+formatted" in git("diff", cwd=checkout)
        print("RUN-REPORT exit=3 wall=0.1s rootfs_tmp_left=1G workspace_left=1T", file=sys.stderr)
        return subprocess.CompletedProcess(command, 3)
    return real_run(command, **kwargs)


def invoke(words, seconds="30", runner=run, available=True, node_root=None, environment=compute_environment, lookup=None):
    root_word = str(root if node_root is None else node_root)
    sys.argv = ["node", str(mirror), "R", root_word, seconds, json.dumps(words), "/opt/fixture/bin/report", json.dumps(environment)]
    errors = io.StringIO()
    def which(program, path):
        return lookup(program, path) if lookup else ("/fixture/tool" if available else None)
    with contextlib.redirect_stderr(errors), patch("subprocess.run", runner), \
            patch.dict(namespace, run_wrapper=runner,
                       run_preparation=lambda command, deadline, lock, **kwargs: runner(
                           command, check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, **kwargs)), \
            patch("os.access", return_value=available), \
            patch("shutil.which", side_effect=which):
        result = namespace["main"]()
    metadata = json.loads(errors.getvalue().split("DOOR-COMPUTE ")[-1])
    if metadata["reason"] == "door-compute-root-refusal":
        assert root_word in errors.getvalue()
    return result, metadata


def unexpected_command(*args, **kwargs):
    raise AssertionError("root refusal must precede checkout preparation and wrapper execution")


not_directory = root / "not-directory"
not_directory.write_text("file")
for invalid_root in [root / "absent", not_directory, "relative", ""]:
    status, metadata = invoke(["git", "diff"], runner=unexpected_command,
                              node_root=invalid_root)
    assert status == 125
    assert metadata["reason"] == "door-compute-root-refusal"
    assert metadata["detail"]["checkout_path"] is None
    assert not (root / "lanes").exists()


status, metadata = invoke(["git", "diff"], runner=unexpected_command)
assert status == 125 and metadata["reason"] == "door-compute-root-refusal"
assert not (root / "lanes").exists()
(root / "lanes").mkdir(mode=0o700)
for invalid_environment in [None, {}, {"PATH": "/bin"},
                            {**compute_environment, "RUSTUP_HOME": "relative"},
                            {**compute_environment, "PATH": "/bin:"},
                            {**compute_environment, "PUBLIC_PACK_TEST_LINTER": "/bin/../superloop-lint"}]:
    status, metadata = invoke(["git", "diff"], runner=unexpected_command,
                              environment=invalid_environment)
    assert status == 125 and metadata["reason"] == "door-compute-settings-refusal"
    assert metadata["detail"]["checkout_path"] is None
    assert not (root / "lanes/R").exists()
print("node settings cases=6: absent, empty, incomplete, relative, empty PATH component, dotted path")
missing = invoke(["git", "diff"])[1]
assert missing["reason"] == "door-compute-lane-ref-absent"
assert missing["detail"]["checkout_path"] is None
assert missing["detail"]["checkout_ref"] is None
assert invoke(["git", "diff"], available=False)[1]["reason"] == "door-compute-tool-refusal"
assert not wrappers
git("push", str(mirror), "HEAD:refs/heads/lane/R")
first = git("rev-parse", "HEAD")
status, metadata = invoke(["cargo", "fmt", "--all"])
assert status == 3
assert metadata["detail"]["tree_clean"] is True
assert metadata["detail"]["tree_change_count"] == 0
assert wrappers[-1][0] == first
status, metadata = invoke(["git", "diff"])
assert status == 3
assert metadata["detail"]["tree_clean"] is False
assert metadata["detail"]["tree_change_count"] == 1
assert metadata["detail"]["discarded"] == dict(tracked=0, untracked=0)
assert sum(command[1] == "fetch" for command in events if len(command) > 1) == 2
assert sum(command[1] == "checkout" for command in events if len(command) > 1) == 2
(seed / "file").write_text("new push\n")
git("commit", "-am", "second")
git("push", str(mirror), "HEAD:refs/heads/lane/R")
checkout = root / "lanes/R"
(checkout / "untracked").write_text("discard with tracked edits")
status, metadata = invoke(["git", "status", "--short"])
assert status == 3
assert metadata["detail"]["discarded"] == dict(tracked=1, untracked=1)
assert metadata["detail"]["tree_clean"] is True
assert metadata["detail"]["tree_change_count"] == 0
assert not (checkout / "untracked").exists()
assert wrappers[-1][0] == git("rev-parse", "HEAD")
assert wrappers[-1][0] != first
# An untracked-only tree also survives the same commit, and is cleared on push.
(checkout / "extra").write_text("untracked only")
metadata = invoke(["git", "status", "--short"])[1]
assert metadata["detail"]["tree_clean"] is False
assert metadata["detail"]["tree_change_count"] == 1
assert (checkout / "extra").exists()
(seed / "extra").write_text("new tracked path")
git("add", "extra")
git("commit", "-m", "third")
git("push", str(mirror), "HEAD:refs/heads/lane/R")
metadata = invoke(["git", "status", "--short"])[1]
assert metadata["detail"]["discarded"] == dict(tracked=0, untracked=1)
assert metadata["detail"]["tree_clean"] is True
assert (checkout / "extra").read_text() == "new tracked path"
assert invoke(["git", "diff"], seconds="0")[1]["reason"] == "door-request-deadline"
assert len(wrappers) == 5

# A real child with no RUN-REPORT still produces clock and CPU evidence.
real_wrapper = namespace["run_wrapper"]
def silent_wrapper(command, **kwargs):
    if command[0] == "/usr/bin/timeout":
        return real_wrapper([sys.executable, "-c", "sum(range(1000000))"], **kwargs)
    return real_run(command, **kwargs)
status, metadata = invoke(["git", "diff"], runner=silent_wrapper)
assert status == 0 and metadata["reason"] == "door-complete"
assert metadata["detail"]["wrapper_wall_seconds"] > 0
assert metadata["detail"]["wrapper_user_cpu_seconds"] >= 0
assert metadata["detail"]["wrapper_system_cpu_seconds"] >= 0
assert (metadata["detail"]["wrapper_user_cpu_seconds"]
        + metadata["detail"]["wrapper_system_cpu_seconds"]) > 0

# Ignored output is measured, retained at the same commit, then discarded.
(checkout / ".git/info/exclude").write_text("ignored-output\n")
(checkout / "ignored-output").write_text("cached output")
metadata = invoke(["git", "status", "--short"])[1]
assert metadata["detail"]["tree_clean"] is False
assert metadata["detail"]["tree_change_count"] == 1
assert (checkout / "ignored-output").exists()
git("commit", "--allow-empty", "-m", "fourth")
git("push", str(mirror), "HEAD:refs/heads/lane/R")
metadata = invoke(["git", "status", "--short"])[1]
assert metadata["detail"]["tree_clean"] is True
assert metadata["detail"]["discarded"] == dict(tracked=0, untracked=1)
assert not (checkout / "ignored-output").exists()

# Recover both forms of a clone interrupted before its first detach.
for default_branch in [False, True]:
    shutil.rmtree(checkout)
    if default_branch:
        git("push", str(mirror), "HEAD:refs/heads/default")
        git("--git-dir=" + str(mirror), "symbolic-ref", "HEAD", "refs/heads/default")
    git("clone", "--no-checkout", str(mirror), str(checkout))
    (checkout / "interrupted").write_text("never prepared")
    event_start = len(events)
    metadata = invoke(["git", "status", "--short"])[1]
    assert metadata["reason"] == "door-complete"
    assert metadata["detail"]["checkout_commit"] == git("rev-parse", "HEAD")
    assert metadata["detail"]["discarded"] == dict(tracked=0, untracked=0)
    assert metadata["detail"]["tree_clean"] is True
    assert not (checkout / "interrupted").exists()
    assert not any(command[1] == "diff" for command in events[event_start:])


def fail_fetch(command, **kwargs):
    if command[0:2] == ["/usr/bin/git", "fetch"]:
        raise subprocess.CalledProcessError(1, command)
    return run(command, **kwargs)


assert invoke(["git", "diff"], runner=fail_fetch)[1]["reason"] == "door-compute-refresh-refusal"
assert len(wrappers) == 9


# Check the second tool lookup independently of the pre-interpreter guard.
def unavailable_command(tool, **kwargs):
    return None if tool == "git" else "/fixture/tool"

sys.argv = ["node", str(mirror), "R", str(root), "30", json.dumps(["git", "diff"]), "/opt/fixture/bin/report", json.dumps(compute_environment)]
errors = io.StringIO()
with contextlib.redirect_stderr(errors), patch("subprocess.run", run), \
        patch("os.access", return_value=True), patch("shutil.which", unavailable_command):
    assert namespace["main"]() == 125
assert json.loads(errors.getvalue().split("DOOR-COMPUTE ")[-1])["reason"] == "door-compute-tool-refusal"


def terminate_preparation(command, **kwargs):
    os.kill(os.getpid(), signal.SIGTERM)
    raise AssertionError("SIGTERM must interrupt preparation")


status, metadata = invoke(["git", "diff"], runner=terminate_preparation)
assert status == 124
assert metadata["reason"] == "door-request-deadline"
assert metadata["detail"]["checkout_commit"] is None

# Exercise wrapper status classification and real process-group cleanup by events.
probe = root / "deadline.py"
probe.write_text("""
import subprocess, sys, os, signal, select, types, contextlib
from pathlib import Path
from unittest.mock import patch
source, mirror, mode, environment_json = sys.argv[1:]
namespace = {"__name__": "fixture"}
exec(source, namespace)
namespace["route_ended"] = lambda: False
namespace["KILL_GRACE"] = 1
namespace["DEADLINE_MARGIN"] = 5
clock = {"now": 0.0}
namespace["time"] = types.SimpleNamespace(monotonic=lambda: clock["now"])
real_popen, real_killpg = subprocess.Popen, os.killpg
kills = []
def killpg(pid, sig):
    kills.append((pid, sig))
    return real_killpg(pid, sig)
class ControlledChild:
    def __init__(self, child, ready):
        self.child, self.ready, self.first = child, ready, True
        self.pid = child.pid
        self.stdin = child.stdin
    def __enter__(self):
        return self
    def __exit__(self, *args):
        if self.child.poll() is None:
            real_killpg(self.pid, signal.SIGKILL)
        return self.child.__exit__(*args)
    def wait(self, timeout=None):
        if not self.first:
            assert (self.pid, signal.SIGTERM) in kills, "outer TERM must reach supervisor"
            return self.child.wait(timeout=120)
        self.first = False
        assert select.select([self.ready], [], [], 120)[0], "wrapper readiness"
        assert os.read(self.ready, 1) == b"R", "wrapper announced ready"
        os.close(self.ready)
        if mode == "outer":
            Path(mirror + ".pid").write_text(str(self.pid))
            clock["now"] = 1000.0
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("TERM must interrupt the wrapper wait")
        if mode == "yes":
            real_killpg(self.pid, signal.SIGKILL)
        elif mode == "no":
            real_killpg(self.pid, signal.SIGTERM)
        result = self.child.wait(timeout=120)
        clock["now"] = 0.0 if mode in ("124", "137") else 1000.0
        return result
    def poll(self):
        return self.child.poll()
    def terminate(self):
        kills.append((self.pid, signal.SIGTERM))
        self.child.terminate()
def popen(command, **kwargs):
    if command[0] != "/usr/bin/timeout":
        return real_popen(command, **kwargs)
    assert command[:3] == ["/usr/bin/timeout", "-k", "1"], command
    assert float(command[3]) == 114.0, command
    ready, announce = os.pipe()
    program = "import os,signal,sys; "
    program += "signal.signal(signal.SIGTERM, lambda *_: sys.exit(124)); "
    program += "os.write(" + str(announce) + ", b'R'); os.close(" + str(announce) + "); "
    if mode in ("124", "137"):
        program += "print('RUN-REPORT exit=" + mode + " wall=0.01s',file=sys.stderr,flush=True); sys.exit(" + mode + ")"
    else:
        program += "signal.pause()"
    child = real_popen([sys.executable, "-c", program], pass_fds=(announce,), **kwargs)
    os.close(announce)
    return ControlledChild(child, ready)
@contextlib.contextmanager
def guarded(command, lock=None, **kwargs):
    with popen(command, start_new_session=True, **kwargs) as child:
        yield child
namespace["supervised_process"] = guarded
namespace["run_preparation"] = lambda command, deadline, lock, **kwargs: subprocess.run(
    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
sys.argv = ["node", mirror, "R", str(Path(mirror).parent.parent), "120", '["git","diff"]', "/opt/fixture/bin/report", environment_json]
with patch("subprocess.Popen", popen), patch("os.killpg", killpg), patch("os.access", return_value=True), \\
        patch("shutil.which", return_value="/fixture/tool"):
    sys.exit(namespace["main"]())
""")
# Controlled clock selects deadline classification; pipe readiness orders signals.
# Real child groups still prove outer TERM cleanup. The timeout is only a hang guard.
for mode, expected in [("yes", 137), ("no", 124), ("outer", 124),
                       ("124", 124), ("137", 137)]:
    result = real_run(["/usr/bin/timeout", "-k", "5", "120", sys.executable,
                       str(probe), source, str(mirror), mode, json.dumps(compute_environment)], capture_output=True)
    assert b"DOOR-COMPUTE " in result.stderr, result.stderr
    metadata = json.loads(result.stderr.decode().split("DOOR-COMPUTE ")[-1])
    early = mode in ("124", "137")
    assert metadata["reason"] == ("door-complete" if early else "door-request-deadline"), result.stderr
    assert result.returncode == expected, result.stderr
    assert metadata["detail"]["tree_clean"] is True
    assert metadata["detail"]["wrapper_exit_status"] == (expected if early else None)
    if early:
        assert f"RUN-REPORT exit={expected}" in result.stderr.decode()
    if mode == "no":
        assert b"node preparation deadline" not in result.stderr, result.stderr
    if mode == "outer":
        assert b"node preparation deadline" in result.stderr, result.stderr
        wrapper_pid = int(Path(str(mirror) + ".pid").read_text())
        process = Path(f"/proc/{wrapper_pid}/stat")
        assert not process.exists() or process.read_text().split(") ", 1)[1][0] == "Z"
        with (root / "lanes/R.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("node cases=20: original 13, ignored output, interrupted unborn HEAD, interrupted default HEAD, early 124, early 137, outer TERM kills wrapper group, no-report measured child")

# Root selection is explicit for equal and differing loop/account names.
for loop_name, account in [("alpha", "alpha"), ("project-a", "loop-b")]:
    workspace = root / account
    workspace.mkdir()
    (workspace / "lanes").mkdir(mode=0o700)
    def observe_environment(command, **kwargs):
        if command[0] != "/usr/bin/timeout":
            return real_run(command, **kwargs)
        env = kwargs["env"]
        assert env["WORKSPACE"] == str(workspace), loop_name
        assert env["CARGO_HOME"] == str(workspace / "cargo")
        assert env["CARGO_TARGET_DIR"] == str(workspace / "lanes/R-build")
        assert env["TMPDIR"] == str(workspace / "lanes/R-tmp")
        assert Path(env["TMPDIR"]).is_dir()
        assert kwargs["cwd"] == root / "lanes/R"
        return subprocess.CompletedProcess(command, 0)
    status, metadata = invoke(["git", "diff"], runner=observe_environment,
                              node_root=workspace)
    assert status == 0 and metadata["reason"] == "door-complete"
print("node root cases=7: missing lanes, equal name, differing name, absent directory, non-directory, relative, empty")

# The tool check resolves a checkout-relative program before the wrapper runs.
script = checkout / "scripts/prepare.sh"
script.parent.mkdir(exist_ok=True)
script.write_text("#!/bin/sh\nexit 0\n")
script.chmod(0o700)
resolved = []
def checkout_lookup(program, path):
    resolved.append(program)
    if program in ("/usr/bin/timeout", "/opt/fixture/bin/report"):
        return program
    return program if Path(program).is_file() and os.access(program, os.X_OK) else None
status, metadata = invoke(["scripts/prepare.sh", "check"], lookup=checkout_lookup)
assert status == 3 and metadata["reason"] == "door-complete"
assert resolved[-1] == str(script), resolved
assert wrappers[-1][1] == ["scripts/prepare.sh", "check"]
status, metadata = invoke(["scripts/missing.sh"], lookup=checkout_lookup)
assert status == 125 and metadata["reason"] == "door-compute-tool-refusal"
assert resolved[-1] == str(checkout / "scripts/missing.sh"), resolved
print("node checkout-relative program cases=2: executable and missing")

# Exercise the payload as the SSH route does: its input stays open after the
# worker's ordinary input EOF, and closes only when the route itself ends.
route_root = root / "route"
route_root.mkdir()
(route_root / "lanes").mkdir()
route_mirror = route_root / "mirrors" / "R.git"
route_mirror.parent.mkdir()
git("clone", "--bare", str(mirror), str(route_mirror))
wrapper = route_root / "wrapper"
wrapper.write_text("#!/bin/sh\nmarker=$1\nprintf '%s\\n' \"$$\" > \"$marker\"\n"
                   "if [ -e \"${marker}.pause\" ]; then\n"
                   "  until [ -e \"${marker}.held\" ]; do sleep 0.01; done\nfi\n"
                   "shift\nexec \"$@\"\n")
wrapper.chmod(0o700)
lock_path = route_root / "lanes/R.lock"


def route_call(marker, seconds, command, payload=source, outer=False, hold_marker=False):
    if hold_marker:
        marker.with_name(marker.name + ".pause").touch()
    route = [sys.executable, "-c", payload, str(route_mirror), "R", str(route_root),
             str(seconds), json.dumps([str(wrapper), str(marker), *command]),
             "/usr/bin/env", json.dumps(compute_environment)]
    if outer:
        # The serving route's compute_timeout sends TERM three seconds before
        # the node's request deadline; this is the actual timeout layer.
        route = ["/usr/bin/timeout", "-k", "10", str(max(0.001, seconds - 3)), *route]
    return subprocess.Popen(
        route,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)


def wait_for(observation):
    until = time.monotonic() + 20
    while not observation():
        if time.monotonic() >= until:
            raise AssertionError("fixture event was not reached")
        time.sleep(0.02)


def hold_process(marker):
    # The child waits for this acknowledgement after writing its PID, so it
    # cannot exit and let the number be reused before pidfd_open succeeds.
    wait_for(marker.exists)
    descriptor = os.pidfd_open(int(marker.read_text()))
    marker.with_name(marker.name + ".held").touch()
    return descriptor


def stop_held(descriptor):
    if descriptor is not None:
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.close(descriptor)


def finish_route(child):
    try:
        child.wait(timeout=25)
        return child.returncode, child.stderr.read()
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)


def has_lock_open(child):
    descriptors = Path(f"/proc/{child.pid}/fd")
    if not descriptors.is_dir():
        return False
    for entry in descriptors.iterdir():
        try:
            if entry.resolve() == lock_path:
                return True
        except (FileNotFoundError, PermissionError):
            pass
    return False


# The wrapper is silent after announcing readiness. Route EOF kills its group
# and frees the run lock, even though no child output can reveal the close.
marker = route_root / "silent.pid"
child = route_call(marker, 40, ["/usr/bin/sleep", "30"], hold_marker=True)
wrapper_handle = None
try:
    wrapper_handle = hold_process(marker)
    wrapper_pid = int(marker.read_text())
    child.stdin.close()
    code, errors = finish_route(child)
    assert code == 125, errors
    assert json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])["reason"] == "door-disconnect-refusal"
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    process = Path(f"/proc/{wrapper_pid}/stat")
    assert not process.exists() or process.read_text().split(") ", 1)[1][0] == "Z"
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
    stop_held(wrapper_handle)

# A waiting request abandons the queue when its own route closes or its
# preparation deadline passes. Neither may spawn the wrapper after the lock.
with lock_path.open("a") as held:
    fcntl.flock(held, fcntl.LOCK_EX)
    for ending, seconds in [("door-disconnect-refusal", 40),
                            ("door-request-deadline", 1)]:
        marker = route_root / (ending + ".pid")
        child = route_call(marker, seconds, ["/usr/bin/true"])
        try:
            wait_for(lambda: has_lock_open(child))
            if ending == "door-disconnect-refusal":
                child.stdin.close()
            code, errors = finish_route(child)
            assert code == (125 if ending == "door-disconnect-refusal" else 124), errors
            assert json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])["reason"] == ending
            assert not marker.exists(), ending
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)

marker = route_root / "complete.pid"
child = route_call(marker, 40, ["/usr/bin/true"])
try:
    code, errors = finish_route(child)
    assert code == 0, errors
    assert marker.exists()
    assert json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])["reason"] == "door-complete"
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
print("node route cases=4: silent disconnect, queued disconnect, queued deadline, natural completion")

# A worker killed by a signal is reported as the command's completion. GNU
# timeout propagates the signal to itself, so the node observes its signal.
marker = route_root / "signal-worker.pid"
child = route_call(marker, 40, ["/usr/bin/sleep", "30"], hold_marker=True)
worker_handle = None
try:
    worker_handle = hold_process(marker)
    signal.pidfd_send_signal(worker_handle, signal.SIGKILL)
    code, errors = finish_route(child)
    result = json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])
    assert code == 137, errors
    assert result["reason"] == "door-complete", errors
    assert result["detail"]["wrapper_exit_status"] == 137, errors
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
    stop_held(worker_handle)
print("node route signal case=1: worker death is command completion")

# The worker's input EOF is a zero frame, not the SSH route's EOF. A command
# reading to EOF must finish while the route remains open.
marker = route_root / "input.pid"
child = route_call(marker, 40, ["/usr/bin/sh", "-c", "cat >/dev/null"])
try:
    child.stdin.write(struct.pack(">I", 5) + b"hello" + struct.pack(">I", 0))
    child.stdin.flush()
    code, errors = finish_route(child)
    assert code == 0, errors
    assert json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])["reason"] == "door-complete"
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)

# A Git fetch that blocks in preparation is ended when the route closes. The
# wrapper is not reached, and the run lock is available for the next request.
stall = route_root / "git-stall"
fetch_pid = route_root / "fetch.pid"
stall.write_text("#!/bin/sh\nif [ \"$1\" = fetch ]; then\n"
                 + f"printf '%s\\n' \"$$\" > '{fetch_pid}'\n"
                 + f"until [ -e '{fetch_pid}.held' ]; do sleep 0.01; done\n"
                 + "exec /usr/bin/sleep 30\nfi\nexec /usr/bin/git \"$@\"\n")
stall.chmod(0o700)
stall_payload = source.replace('["/usr/bin/git", *args]', '["' + str(stall) + '", *args]')
marker = route_root / "stalled.pid"
child = route_call(marker, 40, ["/usr/bin/true"], stall_payload)
fetch_handle = None
try:
    fetch_handle = hold_process(fetch_pid)
    child.stdin.close()
    code, errors = finish_route(child)
    assert code == 125, errors
    assert json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])["reason"] == "door-disconnect-refusal"
    assert not marker.exists()
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    process = Path(f"/proc/{int(fetch_pid.read_text())}/stat")
    assert not process.exists() or process.read_text().split(") ", 1)[1][0] == "Z"
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
    stop_held(fetch_handle)
print("node route repair cases=2: command input EOF, interrupted fetch")

# Outer KILL must not free the run lock while a TERM-ignoring fetch can still
# write. The fetch inherits the lock; its timeout parent gets a death signal.
ignore = route_root / "git-ignore-term"
ignored_pid = route_root / "ignored-fetch.pid"
ignore.write_text("#!/bin/sh\nif [ \"$1\" = fetch ]; then\n"
                  + "trap '' TERM\n"
                  + f"printf '%s\\n' \"$$\" > '{ignored_pid}'\n"
                  + f"until [ -e '{ignored_pid}.held' ]; do sleep 0.01; done\n"
                  + "exec /usr/bin/sleep 30\nfi\n"
                  + "exec /usr/bin/git \"$@\"\n")
ignore.chmod(0o700)
ignore_payload = source.replace('["/usr/bin/git", *args]',
                                '["' + str(ignore) + '", *args]')
child = route_call(route_root / "never-wrapper.pid", 40, ["/usr/bin/true"],
                   ignore_payload)
ignored_handle = None
try:
    ignored_handle = hold_process(ignored_pid)
    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=5)
    process = Path(f"/proc/{int(ignored_pid.read_text())}/stat")
    def stopped_and_unlocked():
        if process.exists() and process.read_text().split(") ", 1)[1][0] != "Z":
            return False
        with lock_path.open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                return False
    wait_for(stopped_and_unlocked)
    assert lock_path.read_bytes() == b"pending\n"
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
    stop_held(ignored_handle)

# A post-detach interrupted fetch may leave Git's lock file behind. The next
# request clears the marked checkout and reaches the newly pushed commit.
(route_root / "lanes/R/.git/index.lock").write_text("stale lock\n")
git("commit", "--allow-empty", "-m", "post-interruption")
git("push", str(route_mirror), "HEAD:refs/heads/lane/R")
marker = route_root / "recovered.pid"
child = route_call(marker, 40, ["/usr/bin/true"])
try:
    code, errors = finish_route(child)
    assert code == 0, errors
    detail = json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])
    assert detail["reason"] == "door-complete"
    assert detail["detail"]["checkout_commit"] == git("rev-parse", "HEAD")
    assert not (route_root / "lanes/R/.git/index.lock").exists()
    assert lock_path.read_bytes() == b""
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
print("node route recovery cases=2: outer KILL, next request after interrupted fetch")

# A third party can kill the timeout parent first. Its writer then retains the
# inherited lock until it exits; a subsequent request names that condition.
survivor = route_root / "git-survivor"
survivor_pid = route_root / "survivor.pid"
supervisor_pid = route_root / "supervisor.pid"
survivor.write_text("#!/bin/sh\nif [ \"$1\" = fetch ]; then\n"
                    + "trap '' TERM\n"
                    + f"printf '%s\\n' \"$$\" > '{survivor_pid}'\n"
                    + f"printf '%s\\n' \"$PPID\" > '{supervisor_pid}'\n"
                    + f"until [ -e '{survivor_pid}.held' ] && [ -e '{supervisor_pid}.held' ]; do sleep 0.01; done\n"
                    + "exec /usr/bin/sleep 30\nfi\n"
                    + "exec /usr/bin/git \"$@\"\n")
survivor.chmod(0o700)
survivor_payload = source.replace('["/usr/bin/git", *args]',
                                  '["' + str(survivor) + '", *args]')
child = route_call(route_root / "survivor-wrapper.pid", 40,
                   ["/usr/bin/true"], survivor_payload)
writer_handle = None
supervisor_handle = None
try:
    writer_handle = hold_process(survivor_pid)
    supervisor_handle = hold_process(supervisor_pid)
    stop_held(supervisor_handle)
    supervisor_handle = None
    code, errors = finish_route(child)
    assert code == 125, errors
    with lock_path.open("a") as held:
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            raise AssertionError("surviving preparation writer lost the run lock")
        except BlockingIOError:
            pass
    refused = route_call(route_root / "refused-wrapper.pid", 10,
                         ["/usr/bin/true"], outer=True)
    try:
        code, errors = finish_route(refused)
        assert code == 124, errors
        assert b"earlier request's preparation still holds the run lock" in errors
        assert b"do not remove the lock file" in errors
        assert json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])["reason"] == "door-compute-preparation-held"
    finally:
        if refused.poll() is None:
            os.killpg(refused.pid, signal.SIGKILL)
            refused.wait(timeout=5)
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
    stop_held(supervisor_handle)
    stop_held(writer_handle)
    wait_for(stopped_and_unlocked)
print("node route survivor case=1: writer keeps lock and next request names it")

# An interrupted removal leaves the pending marker. Repeating it twice still
# lets a normal request discard the partial directory and clone the wanted ref.
removal_ready = route_root / "removal.ready"
remover_code = ("import os,pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                "(p/'.git/HEAD').unlink(missing_ok=True); "
                + f"pathlib.Path({str(removal_ready)!r}).write_text(str(os.getpid())); "
                + f"ack=pathlib.Path({str(removal_ready) + '.held'!r}); "
                + "\nwhile not ack.exists(): time.sleep(0.01)\n"
                + "time.sleep(30)")
remove_payload = source.replace(
    'remover = "import shutil,sys; shutil.rmtree(sys.argv[1])"',
    'remover = ' + repr(remover_code))
for attempt in range(2):
    removal_ready.unlink(missing_ok=True)
    removal_ready.with_name(removal_ready.name + ".held").unlink(missing_ok=True)
    child = route_call(route_root / f"removal-{attempt}.pid", 40,
                       ["/usr/bin/true"], remove_payload)
    remover_handle = None
    try:
        remover_handle = hold_process(removal_ready)
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
        wait_for(stopped_and_unlocked)
        assert lock_path.read_bytes() == b"pending\n"
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        stop_held(remover_handle)
child = route_call(route_root / "removal-recovered.pid", 40,
                   ["/usr/bin/true"])
try:
    code, errors = finish_route(child)
    assert code == 0, errors
    detail = json.loads(errors.decode().split("DOOR-COMPUTE ")[-1])
    assert detail["reason"] == "door-complete"
    assert detail["detail"]["checkout_commit"] == git("rev-parse", "HEAD")
    assert lock_path.read_bytes() == b""
finally:
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
print("node route removal cases=3: two interruptions and a clean recovery")
