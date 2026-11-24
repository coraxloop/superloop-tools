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
import resource
import contextlib
import stat
import select
import threading
import struct
import ctypes

KILL_GRACE = 10
DEADLINE_MARGIN = 5


class RetiredRun(Exception):
    pass


class RouteClosed(Exception):
    pass


def route_ended():
    # The route carries framed worker input; only this process reads it.
    watcher = select.poll()
    watcher.register(sys.stdin.fileno(), select.POLLHUP | select.POLLERR)
    return any(events & (select.POLLHUP | select.POLLERR)
               for _, events in watcher.poll(0))


def lock_until(descriptor, deadline, preparation=False):
    while True:
        if time.monotonic() >= deadline:
            if preparation and os.pread(descriptor, 64, 0) == b"pending\n":
                since = os.fstat(descriptor).st_mtime_ns
                raise PreparationHeld(
                    "earlier request's preparation still holds the run lock "
                    + f"since unix_ns={since}; wait for it to end, or inspect "
                    + "and end that process on the registered node before retrying; "
                    + "do not remove the lock file")
            raise Deadline("node preparation deadline")
        if route_ended():
            raise RouteClosed("node compute route closed")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            # The door's outer timeout sends TERM three seconds before this
            # deadline. Name an inherited preparation hold while the route is
            # still alive and able to carry its footer to the worker.
            if (preparation and time.monotonic() >= deadline - 6
                    and os.pread(descriptor, 64, 0) == b"pending\n"):
                since = os.fstat(descriptor).st_mtime_ns
                raise PreparationHeld(
                    "earlier request's preparation still holds the run lock "
                    + f"since unix_ns={since}; wait for it to end, or inspect "
                    + "and end that process on the registered node before retrying; "
                    + "do not remove the lock file")
            threading.Event().wait(0.05)


@contextlib.contextmanager
def compute_lock(root, run, deadline):
    # The directory hold only serializes open/unlink, never the run-lock wait.
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        lock_until(directory, deadline)
        try:
            if os.path.lexists(root / (run + ".retired")):
                raise RetiredRun(run)
            lock = os.open(root / (run + ".lock"),
                           os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ValueError("run lock is not a regular file")
        finally:
            fcntl.flock(directory, fcntl.LOCK_UN)
        lock_until(lock, deadline, preparation=True)
        # A retirement may have held the old inode while this caller waited.
        if os.path.lexists(root / (run + ".retired")):
            raise RetiredRun(run)
        yield lock
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


class Deadline(Exception):
    pass


class PreparationHeld(Deadline):
    pass


LIBC = ctypes.CDLL(None, use_errno=True)
PREPARATION_GRACE = 2


def parent_death_signal(parent):
    # This is called in the forked child before exec. The main Python thread
    # starts both supervisors; Linux tracks that thread for PR_SET_PDEATHSIG.
    if LIBC.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(125)


@contextlib.contextmanager
def supervised_process(command, lock=None, **kwargs):
    parent = os.getpid()
    passed = () if lock is None else (lock,)
    child = subprocess.Popen(command, start_new_session=True, pass_fds=passed,
                             preexec_fn=lambda: parent_death_signal(parent), **kwargs)
    try:
        yield child
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait()


def stop_supervisor(child):
    if child.poll() is None:
        child.terminate()
    child.wait()


def run_preparation(command, deadline, lock, **kwargs):
    remaining = deadline - time.monotonic() - PREPARATION_GRACE
    if remaining <= 0:
        raise Deadline("node preparation deadline")
    supervised = ["/usr/bin/timeout", "-k", str(PREPARATION_GRACE),
                  str(remaining), *command]
    with supervised_process(supervised, lock=lock, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                            **kwargs) as child:
        try:
            while True:
                if route_ended():
                    raise RouteClosed("node compute route closed")
                if time.monotonic() >= deadline:
                    raise Deadline("node preparation deadline")
                try:
                    stdout, stderr = child.communicate(timeout=0.05)
                    if child.returncode in (124, 137, -signal.SIGKILL):
                        raise Deadline("node preparation deadline")
                    result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
                    result.check_returncode()
                    return result
                except subprocess.TimeoutExpired:
                    if child.poll() is not None:
                        # A surviving writer may retain the supervisor's output
                        # pipes. Its lock remains held, but this script must end.
                        child.stdout.close()
                        child.stderr.close()
                        raise OSError("preparation supervisor ended while its writer remains; retry after that writer exits")
        except (RouteClosed, Deadline):
            stop_supervisor(child)
            raise


def remove_checkout(checkout, deadline, lock):
    remover = "import shutil,sys; shutil.rmtree(sys.argv[1])"
    run_preparation([sys.executable, "-c", remover, str(checkout)], deadline, lock)


def read_exact(route, size):
    collected = bytearray()
    while len(collected) < size:
        chunk = os.read(route, size - len(collected))
        if not chunk:
            return None
        collected.extend(chunk)
    return collected


def child_input(route, destination):
    try:
        while True:
            header = read_exact(route, 4)
            if header is None:
                return
            size = struct.unpack(">I", header)[0]
            if size == 0:
                return
            remaining = size
            while remaining:
                chunk = os.read(route, min(remaining, 65536))
                if not chunk:
                    return
                destination.write(chunk)
                destination.flush()
                remaining -= len(chunk)
    except (BrokenPipeError, OSError):
        pass
    finally:
        destination.close()


def run_wrapper(command, **kwargs):
    # Timeout supervises its own command; the worker command inherits no lock.
    with supervised_process(command, stdin=subprocess.PIPE, **kwargs) as child:
        reader = threading.Thread(target=child_input,
                                  args=(sys.stdin.fileno(), child.stdin), daemon=True)
        reader.start()
        try:
            while True:
                if route_ended():
                    raise RouteClosed("node compute route closed")
                try:
                    return subprocess.CompletedProcess(command, child.wait(timeout=0.05))
                except subprocess.TimeoutExpired:
                    pass
        except RouteClosed:
            stop_supervisor(child)
            raise
        except Deadline:
            stop_supervisor(child)
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
                  wrapper_wall_seconds=None, wrapper_user_cpu_seconds=None,
                  wrapper_system_cpu_seconds=None, preparation_wall_seconds=None,
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
        with compute_lock(root, run, started + float(seconds)) as preparation_lock:
            for tool in ["/usr/bin/git", "/usr/bin/timeout", wrapper]:
                if not os.access(tool, os.X_OK):
                    reason = "door-compute-tool-refusal"
                    raise ValueError("required node tool absent: " + tool)
            def git(*args, cwd=None):
                return run_preparation(["/usr/bin/git", *args], started + float(seconds),
                                       preparation_lock, cwd=cwd).stdout.decode().strip()
            try:
                commit = git("--git-dir=" + str(mirror), "rev-parse", "--verify", ref + "^{commit}")
            except subprocess.CalledProcessError:
                reason = "door-compute-lane-ref-absent"
                raise
            os.lseek(preparation_lock, 0, os.SEEK_SET)
            marker = os.read(preparation_lock, 64)
            if marker not in (b"", b"pending\n"):
                raise ValueError("run lock preparation marker malformed")
            recovering = bool(marker)
            if not recovering:
                os.lseek(preparation_lock, 0, os.SEEK_SET)
                os.write(preparation_lock, b"pending\n")
                os.fsync(preparation_lock)
            if checkout.exists():
                # An interrupted first clone or later fetch may leave a stale
                # lock or partial tree. The marker survives every stopped step.
                if recovering or not (checkout / ".git").is_dir():
                    remove_checkout(checkout, started + float(seconds), preparation_lock)
                else:
                    try:
                        git("symbolic-ref", "--quiet", "HEAD", cwd=checkout)
                    except subprocess.CalledProcessError as error:
                        if error.returncode != 1:
                            raise
                    else:
                        remove_checkout(checkout, started + float(seconds), preparation_lock)
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
            os.ftruncate(preparation_lock, 0)
            os.fsync(preparation_lock)
            env = os.environ.copy()
            env.update(environment)
            env.pop("RUSTUP_TOOLCHAIN", None)
            env.update(WORKSPACE=str(workspace),
                       CARGO_HOME=str(workspace / "cargo"),
                       CARGO_TARGET_DIR=str(workspace / "lanes" / (run + "-build")),
                       TMPDIR=str(workspace / "lanes" / (run + "-tmp")),
                       RUSTDOCFLAGS="-D warnings", CARGO_NET_OFFLINE="true")
            Path(env["TMPDIR"]).mkdir(mode=0o700, exist_ok=True)
            program = words[0]
            if "/" in program and not Path(program).is_absolute():
                program = str(checkout / program)
            for tool in ["/usr/bin/timeout", wrapper, program]:
                if shutil.which(tool, path=env["PATH"]) is None:
                    reason = "door-compute-tool-refusal"
                    raise ValueError("required node tool absent: " + tool)
            detail["preparation_wall_seconds"] = time.monotonic() - started
            remaining = float(seconds) - detail["preparation_wall_seconds"] - KILL_GRACE - DEADLINE_MARGIN
            if remaining <= 0:
                reason = "door-request-deadline"
                raise ValueError("no time remains for wrapper and termination grace")
            if route_ended():
                raise RouteClosed("node compute route closed")
            wrapper_started = time.monotonic()
            usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
            try:
                # The inner deadline survives if the outer supervisor is killed
                # without its child. Neither timeout nor the worker inherits the lock.
                timed_command = ["/usr/bin/timeout", "-k", str(KILL_GRACE),
                                 str(remaining), wrapper, *words]
                result = run_wrapper(["/usr/bin/timeout", "-k", str(KILL_GRACE),
                                      str(remaining), *timed_command],
                                     cwd=checkout, env=env)
            finally:
                wrapper_elapsed = time.monotonic() - wrapper_started
                usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
                detail["wrapper_wall_seconds"] = wrapper_elapsed
                detail["wrapper_user_cpu_seconds"] = usage_after.ru_utime - usage_before.ru_utime
                detail["wrapper_system_cpu_seconds"] = usage_after.ru_stime - usage_before.ru_stime
            # GNU timeout's KILL also kills its own process group: Python
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
    except PreparationHeld as error:
        reason = "door-compute-preparation-held"
        status = 124
        print(str(error), file=sys.stderr, flush=True)
    except Deadline as error:
        reason = "door-request-deadline"
        status = 124
        print(str(error), file=sys.stderr, flush=True)
    except RouteClosed as error:
        reason = "door-disconnect-refusal"
        status = 125
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
