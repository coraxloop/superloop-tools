"""Service-owned node preparation; caller words never enter a shell program."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import shutil
import signal
import sys
import time
import contextlib
import stat

KILL_GRACE = 10
DEADLINE_MARGIN = 5


class RetiredRun(Exception):
    pass


@contextlib.contextmanager
def compute_lock(root, run):
    # The directory hold only serializes open/unlink, never the run-lock wait.
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        try:
            if os.path.lexists(root / (run + ".retired")):
                raise RetiredRun(run)
            lock = os.open(root / (run + ".lock"),
                           os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ValueError("run lock is not a regular file")
        finally:
            fcntl.flock(directory, fcntl.LOCK_UN)
        fcntl.flock(lock, fcntl.LOCK_EX)
        # A retirement may have held the old inode while this caller waited.
        if os.path.lexists(root / (run + ".retired")):
            raise RetiredRun(run)
        yield
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


class Deadline(Exception):
    pass


def run_wrapper(command, **kwargs):
    # Keep the group leader's pid so an outer TERM cannot orphan its wrapper.
    with subprocess.Popen(command, start_new_session=True, **kwargs) as child:
        try:
            return subprocess.CompletedProcess(command, child.wait())
        except Deadline:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise


def main():
    mirror_word, run, node_root, seconds, encoded, wrapper, environment_json = sys.argv[1:]
    words = json.loads(encoded)
    started = time.monotonic()
    mirror = Path(os.path.expanduser(mirror_word))
    root = mirror.parent.parent / "lanes"
    checkout = root / run
    ref = "refs/heads/lane/" + run
    detail = dict(words=words, checkout_path=None, checkout_ref=None,
                  checkout_commit=None, wrapper_exit_status=None,
                  wrapper_wall_seconds=None, preparation_wall_seconds=None,
                  tree_clean=None, tree_change_count=None, discarded=None)
    reason = "door-compute-refresh-refusal"
    status = 125
    def terminated(_signal, _frame):
        raise Deadline("node preparation deadline")
    previous_handler = signal.signal(signal.SIGTERM, terminated)
    try:
        workspace = Path(node_root)
        if not workspace.is_absolute() or not workspace.is_dir():
            reason = "door-compute-root-refusal"
            raise ValueError("node_root is not an existing absolute directory: " + node_root)
        if not (workspace / "lanes").is_dir():
            reason = "door-compute-root-refusal"
            raise ValueError("node_root lanes is not an existing directory: " + str(workspace / "lanes"))
        environment = json.loads(environment_json)
        required = {"RUSTUP_HOME", "PATH", "PUBLIC_PACK_TEST_LINTER"}
        if not isinstance(environment, dict) or set(environment) != required:
            reason = "door-compute-settings-refusal"
            raise ValueError("compute_environment requires RUSTUP_HOME, PATH and PUBLIC_PACK_TEST_LINTER")
        for key, value in environment.items():
            paths = value.split(":") if isinstance(value, str) and key == "PATH" else [value]
            if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value) or any(not Path(path).is_absolute() or "." in path.split("/") or ".." in path.split("/") for path in paths):
                reason = "door-compute-settings-refusal"
                raise ValueError("compute_environment." + key + " requires absolute paths")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with compute_lock(root, run):
            for tool in ["/usr/bin/git", "/usr/bin/timeout", wrapper]:
                if not os.access(tool, os.X_OK):
                    reason = "door-compute-tool-refusal"
                    raise ValueError("required node tool absent: " + tool)
            def git(*args, cwd=None):
                return subprocess.run(["/usr/bin/git", *args], cwd=cwd,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      check=True).stdout.decode().strip()
            try:
                commit = git("--git-dir=" + str(mirror), "rev-parse", "--verify", ref + "^{commit}")
            except subprocess.CalledProcessError:
                reason = "door-compute-lane-ref-absent"
                raise
            if checkout.exists():
                try:
                    git("symbolic-ref", "--quiet", "HEAD", cwd=checkout)
                except subprocess.CalledProcessError as error:
                    if error.returncode != 1:
                        raise
                else:
                    # Clone --no-checkout can leave an unborn or default-branch
                    # HEAD if preparation stops before the first detach.
                    shutil.rmtree(checkout)
            created = not checkout.exists()
            if created:
                git("clone", "--no-checkout", "--", str(mirror), str(checkout))
            detail["checkout_path"] = str(checkout)
            detail["checkout_ref"] = ref
            git("fetch", "--no-tags", str(mirror), ref, cwd=checkout)
            commit = git("rev-parse", "FETCH_HEAD^{commit}", cwd=checkout)
            try:
                old = git("rev-parse", "HEAD", cwd=checkout)
            except subprocess.CalledProcessError:
                old = None
            detail["discarded"] = dict(tracked=0, untracked=0)
            if not created and old != commit:
                tracked = git("diff", "--name-only", "-z", "HEAD", cwd=checkout)
                untracked = git("ls-files", "--others", "-z", cwd=checkout)
                git("reset", "--hard", commit, cwd=checkout)
                detail["discarded"]["tracked"] = tracked.count("\0")
                git("clean", "-ffdx", cwd=checkout)
                detail["discarded"]["untracked"] = untracked.count("\0")
            git("checkout", "--detach", commit, cwd=checkout)
            detail["checkout_commit"] = git("rev-parse", "HEAD", cwd=checkout)
            changes = git("status", "--porcelain", "--untracked-files=all", "--ignored", cwd=checkout)
            detail["tree_clean"] = not changes
            detail["tree_change_count"] = len(changes.splitlines())
            env = os.environ.copy()
            env.update(environment)
            env.pop("RUSTUP_TOOLCHAIN", None)
            env.update(WORKSPACE=str(workspace),
                       CARGO_HOME=str(workspace / "cargo"),
                       CARGO_TARGET_DIR=str(workspace / "lanes" / (run + "-build")),
                       TMPDIR=str(workspace / "lanes" / (run + "-tmp")),
                       RUSTDOCFLAGS="-D warnings", CARGO_NET_OFFLINE="true")
            Path(env["TMPDIR"]).mkdir(mode=0o700, exist_ok=True)
            for tool in ["/usr/bin/timeout", wrapper, words[0]]:
                if shutil.which(tool, path=env["PATH"]) is None:
                    reason = "door-compute-tool-refusal"
                    raise ValueError("required node tool absent: " + tool)
            detail["preparation_wall_seconds"] = time.monotonic() - started
            remaining = float(seconds) - detail["preparation_wall_seconds"] - KILL_GRACE - DEADLINE_MARGIN
            if remaining <= 0:
                reason = "door-request-deadline"
                raise ValueError("no time remains for wrapper and termination grace")
            wrapper_started = time.monotonic()
            result = run_wrapper(["/usr/bin/timeout", "-k", str(KILL_GRACE), str(remaining),
                                  wrapper, *words], cwd=checkout, env=env)
            wrapper_elapsed = time.monotonic() - wrapper_started
            # GNU timeout's KILL also kills its own process group: Python then
            # observes -SIGKILL rather than the shell's conventional 137.
            status = 137 if result.returncode == -signal.SIGKILL else result.returncode
            if status < 0:
                status = 125
            if wrapper_elapsed >= remaining:
                reason = "door-request-deadline"
            else:
                detail["wrapper_exit_status"] = status
                reason = "door-complete"
    except RetiredRun as error:
        reason = "door-compute-retired-run"
        print("retired run: " + str(error), file=sys.stderr, flush=True)
    except Deadline as error:
        reason = "door-request-deadline"
        status = 124
        print(str(error), file=sys.stderr, flush=True)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr, flush=True)
    if detail["preparation_wall_seconds"] is None:
        detail["preparation_wall_seconds"] = time.monotonic() - started
    print("DOOR-COMPUTE " + json.dumps(dict(reason=reason, detail=detail)), file=sys.stderr, flush=True)
    signal.signal(signal.SIGTERM, previous_handler)
    return status


if __name__ == "__main__":
    sys.exit(main())
