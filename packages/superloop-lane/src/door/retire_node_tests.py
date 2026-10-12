"""Hermetic production-helper evidence and lock-unlink concurrency fixtures."""
import contextlib
import fcntl
import io
import json
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import patch

source, compute_source, temporary = sys.argv[1:]
node = {"__name__": "fixture"}
compute = {"__name__": "fixture"}
exec(source, node)
exec(compute_source, compute)
root = Path(temporary)
environment_json = json.dumps({"RUSTUP_HOME": "/opt/fixture/rustup", "PATH": "/opt/fixture/tools:/usr/bin:/bin", "PUBLIC_PACK_TEST_LINTER": "/opt/fixture/tools/superloop-lint"})
lanes = root / "lanes"
lanes.mkdir()
mirror = root / "mirrors/R.git"
cases = 0
begun = time.monotonic()


def probe(run):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = node["absence_probe"](str(mirror), run, "alpha")
    evidence = json.loads(output.getvalue().removeprefix("NODE-ABSENCE "))
    return status, evidence


probe_name = "absence-fixture-" + str(os.getpid())
before_probe = sorted(lanes.iterdir())
with patch.object(Path, "read_bytes", side_effect=ProcessLookupError(3, "No such process")):
    status, proof = probe(probe_name)
    assert status == 0 and proof["state"] == "absent", proof
status, proof = probe(probe_name)
assert status == 0 and proof["state"] == "absent", proof
assert proof["lock"] == "absent" and proof["wall_seconds"] >= 0
assert sorted(lanes.iterdir()) == before_probe
lock_path = lanes / (probe_name + ".lock")
with lock_path.open("w") as held:
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    status, proof = probe(probe_name)
    assert status == 2 and proof["state"] == "present" and proof["lock"] == "held", proof
lock_path.unlink()
named = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", probe_name])
try:
    status, proof = probe(probe_name)
    assert status == 2 and proof["state"] == "present", proof
    assert named.pid in proof["processes"]
    lock_path.mkdir()
    try:
        status, proof = probe(probe_name)
        assert status == 2 and proof["state"] == "present", proof
        assert named.pid in proof["processes"], proof
        assert proof["lock"] == "unmeasured", proof
        assert proof["error"] == "run lock is not regular", proof
    finally:
        lock_path.rmdir()
finally:
    named.terminate()
    named.wait()
cases += 5


# Complete the process scan regardless of whether unreadable or busy comes first.
for entries in [[Path("/proc/100000001"), Path("/proc/100000002")],
                [Path("/proc/100000002"), Path("/proc/100000001")]]:
    visited = []

    def cmdline(path):
        visited.append(path.parent)
        if path.parent.name == "100000001":
            raise PermissionError("fixture process unreadable")
        return probe_name.encode() + b"\0"

    with patch.object(Path, "iterdir", return_value=iter(entries)), \
            patch.object(Path, "read_bytes", cmdline):
        status, proof = probe(probe_name)
    assert visited == entries, visited
    assert status == 2 and proof["state"] == "present", proof
    assert proof["processes"] == [100000002], proof
    with patch.object(Path, "iterdir", return_value=iter([Path("/proc/100000001")])), \
            patch.object(Path, "read_bytes", cmdline):
        status, proof = probe(probe_name)
    assert status == 2 and proof["state"] == "unmeasured", proof
    assert proof["error"] == "fixture process unreadable", proof
    with patch.object(Path, "iterdir", return_value=iter([])):
        status, proof = probe(probe_name)
    assert status == 0 and proof["state"] == "absent", proof
    cases += 1


def invoke(run="R", node_root=root):
    sys.argv = ["node", str(mirror), run, "alpha", str(node_root)]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = node["main"]()
    lines = output.getvalue().splitlines()
    assert len(lines) == 1 and lines[0].startswith("NODE-RETIREMENT ")
    evidence = json.loads(lines[0].split(" ", 1)[1])
    assert evidence["helper_exit"] == status
    return evidence


for name in ["R", "R-build", "R-tmp"]:
    (lanes / name).mkdir()
(lanes / "R/file").write_bytes(b"x" * 8192)
os.link(lanes / "R/file", lanes / "R-build/hardlink")
(lanes / "R-tmp/outside").symlink_to(root)
paths = [lanes / name for name in ["R", "R-build", "R-tmp", "R.lock"]]
measured = node["listing"](paths)
assert measured[0]["entries"] == 2
assert measured[1]["bytes"] == (lanes / "R-build").stat().st_blocks * 512
assert measured[2]["entries"] == 2
cases += 1
removals = []
real_remove = node["remove"]


def remove(path):
    marker = json.loads((lanes / "R.retired").read_text())
    assert marker == dict(schema=1, run="R", loop="alpha")
    assert (lanes / "R.lock").exists()
    removals.append(path.name)
    real_remove(path)


with patch.dict(node, remove=remove):
    evidence = invoke()
assert evidence["reason"] == "node-retirement-complete", evidence
assert evidence["marker"] is True
assert removals == ["R", "R-build", "R-tmp"]
assert all(not row["exists"] for row in evidence["after"])
assert evidence["bytes_freed"] == sum(row["bytes"] for row in evidence["before"])
assert root.exists() and (lanes / "R.retired").exists()
cases += 1
evidence = invoke()
assert evidence["helper_exit"] == 0 and evidence["bytes_freed"] == 0
cases += 1
evidence = invoke("absent")
assert evidence["helper_exit"] == 0 and evidence["bytes_freed"] == 0
assert (lanes / "absent.retired").exists()
cases += 1

# A partial removal retains the marker and lock, and reports the remaining paths.
for name in ["F", "F-build", "F-tmp"]:
    (lanes / name).mkdir()
    (lanes / name / "file").write_bytes(b"x" * 4096)


def fail_midway(path):
    if path.name == "F-build":
        raise PermissionError("fixture removal denied")
    real_remove(path)


with patch.dict(node, remove=fail_midway):
    evidence = invoke("F")
assert evidence["reason"] == "node-retirement-removal-failed"
assert evidence["helper_exit"] == 125 and evidence["marker"] is True
assert [row["exists"] for row in evidence["after"]] == [False, True, True, True]
assert evidence["bytes_freed"] > 0
assert invoke("F")["helper_exit"] == 0
cases += 1

# Compute refuses before tool checks, without recreating even the lock pathname.
sys.argv = ["node", str(mirror), "R", str(root), "30", '["git","diff"]', "/opt/fixture/bin/report", environment_json]
errors = io.StringIO()
with contextlib.redirect_stderr(errors):
    assert compute["main"]() == 125
assert json.loads(errors.getvalue().split("DOOR-COMPUTE ")[1])["reason"] == "door-compute-retired-run"
assert not (lanes / "R.lock").exists() and not (lanes / "R").exists()
cases += 1

# Force a compute caller to open the old inode before it waits for retirement.
ctx = multiprocessing.get_context("fork")


def queued_compute(ready, result):
    real_open = os.open
    def opened(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if str(path).endswith("Q.lock"):
            ready.send("opened")
        return fd
    sys.argv = ["node", str(mirror), "Q", str(root), "30", '["git","diff"]', "/opt/fixture/bin/report", environment_json]
    errors = io.StringIO()
    with patch("os.open", opened), contextlib.redirect_stderr(errors):
        status = compute["main"]()
    result.send((status, errors.getvalue()))


with node["retirement_lock"](lanes, "Q") as directory:
    ready, sender = ctx.Pipe(duplex=False)
    result, writer = ctx.Pipe(duplex=False)
    child = ctx.Process(target=queued_compute, args=(sender, writer))
    child.start()
    assert ready.poll(5) and ready.recv() == "opened"
    fcntl.flock(directory, fcntl.LOCK_EX)
    node["mark"](lanes, "Q", "alpha", directory)
    (lanes / "Q.lock").unlink()
    fcntl.flock(directory, fcntl.LOCK_UN)
    # The forked child inherited this process's open file descriptions,
    # including the one holding the run lock, so the parent's close at
    # context exit would not release that lock while the child lives.
    # retirement_lock yields only the directory, so find the unlinked lock
    # among this process's descriptors and unlock it explicitly.
    for fd in Path("/proc/self/fd").iterdir():
        try:
            if os.readlink(fd) == str(lanes / "Q.lock") + " (deleted)":
                fcntl.flock(int(fd.name), fcntl.LOCK_UN)
        except FileNotFoundError:
            pass
assert result.poll(5)
status, output = result.recv()
child.join(5)
assert child.exitcode == 0 and status == 125
assert json.loads(output.split("DOOR-COMPUTE ")[1])["reason"] == "door-compute-retired-run"
assert not (lanes / "Q.lock").exists()
cases += 1

# Overlapping retirements must re-open after the first unlinks the old inode.
ready, sender = ctx.Pipe(duplex=False)
result, writer = ctx.Pipe(duplex=False)


def queued_retire():
    real_open = os.open
    def opened(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if str(path).endswith("T.lock"):
            sender.send("opened")
        return fd
    with patch("os.open", opened):
        writer.send(invoke("T"))


with node["retirement_lock"](lanes, "T") as directory:
    child = ctx.Process(target=queued_retire)
    child.start()
    assert ready.poll(5) and ready.recv() == "opened"
    fcntl.flock(directory, fcntl.LOCK_EX)
    node["mark"](lanes, "T", "alpha", directory)
    (lanes / "T.lock").unlink()
    fcntl.flock(directory, fcntl.LOCK_UN)
    for fd in Path("/proc/self/fd").iterdir():
        try:
            if os.readlink(fd) == str(lanes / "T.lock") + " (deleted)":
                fcntl.flock(int(fd.name), fcntl.LOCK_UN)
        except FileNotFoundError:
            pass
assert result.poll(5)
evidence = result.recv()
child.join(5)
assert child.exitcode == 0 and evidence["helper_exit"] == 0, evidence
assert ready.poll(5) and ready.recv() == "opened", "retry did not revalidate inode"
assert all(not row["exists"] for row in evidence["after"])
cases += 1

# Compute keeps its lock through the wrapper; retirement waits, then measures.
account_root = root / "loop-a"
(account_root / "lanes").mkdir(parents=True, mode=0o700)
seed = root / "seed"
seed.mkdir()
mirror.parent.mkdir()


def git(*words):
    subprocess.run(["/usr/bin/git", *words], cwd=seed, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


git("init")
git("config", "user.name", "Fixture")
git("config", "user.email", "fixture@example.invalid")
git("config", "commit.gpgsign", "false")
(seed / "file").write_text("compute input")
git("add", "file")
git("commit", "-m", "fixture")
git("clone", "--bare", str(seed), str(mirror))
git("push", str(mirror), "HEAD:refs/heads/lane/C")
ready, sender = ctx.Pipe(duplex=False)
release, releaser = ctx.Pipe(duplex=False)
result, writer = ctx.Pipe(duplex=False)


def holding_compute():
    def wrapper(command, **kwargs):
        target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
        target.mkdir()
        (target / "built").write_bytes(b"x" * 8192)
        sender.send("wrapper")
        assert release.poll(5) and release.recv() == "retirement waiting"
        # The notification precedes the blocking flock. Keep compute's lock
        # until the kernel confirms retirement actually queued on this inode.
        lock = (lanes / "C.lock").stat()
        retirement_pid = os.getppid()
        deadline = time.monotonic() + 5
        holder = None
        waiter = None
        rows = []
        while time.monotonic() < deadline:
            rows = Path("/proc/locks").read_text().splitlines()
            # Use one snapshot: lock numbers can change between reads, and the
            # kernel's device can differ from st_dev on btrfs subvolumes.
            holders = []
            for row in rows:
                fields = row.split()
                if (len(fields) == 8 and fields[1:4] == ["FLOCK", "ADVISORY", "WRITE"]
                        and fields[4] == str(os.getpid()) and fields[6:] == ["0", "EOF"]
                        and fields[5].rsplit(":", 1)[-1] == str(lock.st_ino)):
                    holders.append(fields)
            assert len(holders) <= 1, f"ambiguous compute lock holder: {holders}"
            holder = holders[0] if holders else None
            for row in rows:
                fields = row.split()
                # Waiters add an arrow after the lock number, unlike holders:
                # N: -> FLOCK ADVISORY WRITE PID MAJOR:MINOR:INODE 0 EOF
                if (len(fields) != 9 or fields[1:5] != ["->", "FLOCK", "ADVISORY", "WRITE"]
                        or fields[5] != str(retirement_pid) or fields[7:] != ["0", "EOF"]):
                    continue
                if holder is not None and (fields[0], fields[6]) == (holder[0], holder[5]):
                    waiter = row
                    break
            if waiter is not None:
                break
            time.sleep(0.01)
        assert holder is not None, (
            f"missing compute PID {os.getpid()} holder for inode {lock.st_ino}: {rows}"
        )
        assert waiter is not None, (
            f"retirement PID {retirement_pid} never queued on {holder[5]}; "
            f"missing or unrecognized /proc/locks waiter: {rows}"
        )
        assert not (lanes / "C.retired").exists(), "retirement progressed while compute held its lock"
        assert (target / "built").read_bytes() == b"x" * 8192
        print("compute-first holder: " + " ".join(holder), flush=True)
        print("compute-first waiter: " + waiter, flush=True)
        (target / "completed").write_text("wrapper completed")
        return subprocess.CompletedProcess(command, 0)
    sys.argv = ["node", str(mirror), "C", str(account_root), "30", '["git","diff"]', "/opt/fixture/bin/report", environment_json]
    errors = io.StringIO()
    with patch.dict(compute, run_wrapper=wrapper), \
            patch("os.access", return_value=True), \
            patch("shutil.which", return_value="/fixture/tool"), \
            contextlib.redirect_stderr(errors):
        status = compute["main"]()
    writer.send((status, errors.getvalue()))


child = ctx.Process(target=holding_compute)
child.start()
assert ready.poll(5) and ready.recv() == "wrapper"
real_flock = fcntl.flock


def wait_for_compute(fd, operation):
    if os.readlink(f"/proc/self/fd/{fd}") == str(lanes / "C.lock"):
        try:
            real_flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            raise AssertionError("compute released lock before wrapper completed")
        except BlockingIOError:
            releaser.send("retirement waiting")
    return real_flock(fd, operation)


with patch("fcntl.flock", wait_for_compute):
    evidence = invoke("C", account_root)
assert result.poll(5)
status, output = result.recv()
child.join(5)
assert child.exitcode == 0 and status == 0
assert json.loads(output.split("DOOR-COMPUTE ")[1])["reason"] == "door-complete"
assert evidence["helper_exit"] == 0
assert evidence["before"][1]["path"] == str(account_root / "lanes/C-build")
assert evidence["before"][2]["path"] == str(account_root / "lanes/C-tmp")
assert not (account_root / "lanes/C-build").exists()
assert not (account_root / "lanes/C-tmp").exists()
assert evidence["before"][1]["entries"] == 3
assert evidence["before"][1]["bytes"] >= 8192
assert all(not row["exists"] for row in evidence["after"])
cases += 1

def expire(_paths):
    os.kill(os.getpid(), signal.SIGTERM)


with patch.dict(node, listing=expire):
    evidence = invoke("deadline")
assert evidence["reason"] == "node-retirement-deadline" and evidence["helper_exit"] == 124
cases += 1
print(f"retirement node cases={cases} wall={time.monotonic() - begun:.3f}s")
