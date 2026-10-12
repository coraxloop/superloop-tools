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
from unittest.mock import patch

source, temporary = sys.argv[1:]
namespace = {"__name__": "fixture"}
exec(source, namespace)
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
        assert command[4] == "/opt/fixture/bin/report"
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
        wrappers.append((git("rev-parse", "HEAD", cwd=checkout), command[5:]))
        if command[5:7] == ["cargo", "fmt"]:
            (checkout / "file").write_text("formatted\n")
        elif command[5:] == ["git", "diff"]:
            assert "+formatted" in git("diff", cwd=checkout)
        print("RUN-REPORT exit=3 wall=0.1s rootfs_tmp_left=1G workspace_left=1T", file=sys.stderr)
        return subprocess.CompletedProcess(command, 3)
    return real_run(command, **kwargs)


def invoke(words, seconds="30", runner=run, available=True, node_root=None, environment=compute_environment):
    root_word = str(root if node_root is None else node_root)
    sys.argv = ["node", str(mirror), "R", root_word, seconds, json.dumps(words), "/opt/fixture/bin/report", json.dumps(environment)]
    errors = io.StringIO()
    with contextlib.redirect_stderr(errors), patch("subprocess.run", runner), \
            patch.dict(namespace, run_wrapper=runner), \
            patch("os.access", return_value=available), \
            patch("shutil.which", return_value="/fixture/tool" if available else None):
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

# Exercise real nested timeout process groups, with whole-second margins.
# The outer budget is inner budget + kill grace + evidence margin, as in Rust.
probe = root / "deadline.py"
probe.write_text("""
import subprocess, sys, os
from pathlib import Path
from unittest.mock import patch
source, mirror, ignore_term, environment_json = sys.argv[1:]
namespace = {"__name__": "fixture"}
exec(source, namespace)
namespace["KILL_GRACE"] = 1
namespace["DEADLINE_MARGIN"] = 5
real_popen = subprocess.Popen
def popen(command, **kwargs):
    if command[0] == "/usr/bin/timeout":
        # Ignore TERM so timeout must use its kill grace and return 137.
        program = "import signal,time; "
        if ignore_term in ("yes", "outer"):
            program += "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        if ignore_term == "outer":
            program += ("import os,pathlib; pathlib.Path(" + repr(mirror + ".pid")
                        + ").write_text(str(os.getpid())); os.kill("
                        + str(os.getpid()) + ", signal.SIGTERM); ")
        program += "time.sleep(30)"
        if ignore_term in ("124", "137"):
            program = ("import sys; print('RUN-REPORT exit=" + ignore_term
                       + " wall=0.01s', file=sys.stderr, flush=True); sys.exit("
                       + ignore_term + ")")
        command = command[:4] + [sys.executable, "-c", program]
    return real_popen(command, **kwargs)
sys.argv = ["node", mirror, "R", str(Path(mirror).parent.parent), "8", '["git","diff"]', "/opt/fixture/bin/report", environment_json]
with patch("subprocess.Popen", popen), patch("os.access", return_value=True), \\
        patch("shutil.which", return_value="/fixture/tool"):
    sys.exit(namespace["main"]())
""")
for ignore_term, expected in [("yes", 137), ("no", 124), ("outer", 124),
                              ("124", 124), ("137", 137)]:
    started = time.monotonic()
    result = real_run(["/usr/bin/timeout", "-k", "1", "6", sys.executable,
                       str(probe), source, str(mirror), ignore_term, json.dumps(compute_environment)], capture_output=True)
    assert time.monotonic() - started < 12
    metadata = json.loads(result.stderr.decode().split("DOOR-COMPUTE ")[-1])
    early = ignore_term in ("124", "137")
    assert metadata["reason"] == ("door-complete" if early else "door-request-deadline"), result.stderr
    assert result.returncode == expected, result.stderr
    assert metadata["detail"]["tree_clean"] is True
    assert metadata["detail"]["wrapper_exit_status"] == (expected if early else None)
    if early:
        assert f"RUN-REPORT exit={expected}" in result.stderr.decode()
    if ignore_term == "outer":
        wrapper_pid = int(Path(str(mirror) + ".pid").read_text())
        process = Path(f"/proc/{wrapper_pid}/stat")
        assert not process.exists() or process.read_text().split(") ", 1)[1][0] == "Z"
        with (root / "lanes/R.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("node cases=19: original 13, ignored output, interrupted unborn HEAD, interrupted default HEAD, early 124, early 137, outer TERM kills wrapper group")

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
