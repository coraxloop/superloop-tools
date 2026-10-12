"""Retire one compute workspace; retain a durable terminal marker and mirror."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import time


class Deadline(Exception):
    pass


@contextlib.contextmanager
def retirement_lock(root, run):
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        while True:
            fcntl.flock(directory, fcntl.LOCK_EX)
            try:
                lock = os.open(root / (run + ".lock"),
                               os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                if not stat.S_ISREG(os.fstat(lock).st_mode):
                    raise ValueError("run lock is not a regular file")
            finally:
                fcntl.flock(directory, fcntl.LOCK_UN)
            fcntl.flock(lock, fcntl.LOCK_EX)
            fcntl.flock(directory, fcntl.LOCK_EX)
            try:
                try:
                    current = (root / (run + ".lock")).lstat()
                except FileNotFoundError:
                    current = None
                held = os.fstat(lock)
                if current is not None and (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino):
                    break
            finally:
                fcntl.flock(directory, fcntl.LOCK_UN)
            # Another retirement unlinked the inode while this caller waited.
            os.close(lock)
            lock = None
        yield directory
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def listing(paths):
    seen = set()
    rows = []
    for path in paths:
        row = dict(path=str(path), exists=False, entries=0, bytes=0)
        pending = [path]
        while pending:
            entry = pending.pop()
            try:
                metadata = entry.lstat()
            except FileNotFoundError:
                if entry == path:
                    break
                raise
            row["exists"] = True
            row["entries"] += 1
            identity = (metadata.st_dev, metadata.st_ino)
            if identity not in seen:
                row["bytes"] += metadata.st_blocks * 512
                seen.add(identity)
            if stat.S_ISDIR(metadata.st_mode):
                pending.extend(sorted(entry.iterdir(), reverse=True))
        rows.append(row)
    return rows


def mark(root, run, loop, directory):
    marker = root / (run + ".retired")
    expected = dict(schema=1, run=run, loop=loop)
    if os.path.lexists(marker):
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            if json.loads(stream.read(4097)) != expected:
                raise ValueError("retirement marker identity differs")
        return
    temporary = root / (run + ".retired." + str(os.getpid()) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(expected, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker)
        os.fsync(directory)
    finally:
        temporary.unlink(missing_ok=True)


def remove(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(metadata.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def main():
    mirror_word, run, loop, node_root = sys.argv[1:]
    if run.startswith("--absence="):
        return absence_probe(mirror_word, run.removeprefix("--absence="), loop)
    started = time.monotonic()
    evidence = dict(schema=1, run=run, loop=loop, before=None, after=None,
                    bytes_freed=None, wall_seconds=None, helper_exit=125,
                    reason="node-retirement-removal-failed", marker=False)
    def terminated(_signal, _frame):
        raise Deadline("node retirement deadline")
    previous = signal.signal(signal.SIGTERM, terminated)
    try:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", run):
            raise ValueError("invalid run name")
        mirror = Path(os.path.expanduser(mirror_word))
        root = mirror.parent.parent / "lanes"
        workspace = Path(os.path.expanduser(node_root))
        if not workspace.is_absolute():
            raise ValueError("node_root must be absolute: " + node_root)
        artifacts = workspace / "lanes"
        paths = [root / run, artifacts / (run + "-build"), artifacts / (run + "-tmp"), root / (run + ".lock")]
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with retirement_lock(root, run) as directory:
            # Serialize publication with compute's marker check and lock open.
            fcntl.flock(directory, fcntl.LOCK_EX)
            try:
                mark(root, run, loop, directory)
                evidence["marker"] = True
            finally:
                fcntl.flock(directory, fcntl.LOCK_UN)
            try:
                evidence["before"] = listing(paths)
                for path in paths[:-1]:
                    remove(path)
                fcntl.flock(directory, fcntl.LOCK_EX)
                try:
                    paths[-1].unlink()
                    os.fsync(directory)
                finally:
                    fcntl.flock(directory, fcntl.LOCK_UN)
                evidence["reason"] = "node-retirement-complete"
                evidence["helper_exit"] = 0
            finally:
                evidence["after"] = listing(paths)
                if evidence["before"] is not None:
                    evidence["bytes_freed"] = max(0, sum(row["bytes"] for row in evidence["before"])
                                                 - sum(row["bytes"] for row in evidence["after"]))
    except Deadline as error:
        evidence["reason"] = "node-retirement-deadline"
        evidence["helper_exit"] = 124
        evidence["error"] = str(error)
    except (OSError, ValueError) as error:
        evidence["reason"] = "node-retirement-removal-failed"
        evidence["helper_exit"] = 125
        evidence["error"] = str(error)[:1024]
    evidence["wall_seconds"] = time.monotonic() - started
    print("NODE-RETIREMENT " + json.dumps(evidence), flush=True)
    signal.signal(signal.SIGTERM, previous)
    return evidence["helper_exit"]


def absence_probe(mirror_word, run, loop):
    """Read process and existing lock evidence without creating any node path."""
    started = time.monotonic()
    evidence = dict(schema=1, run=run, loop=loop, state="unmeasured")
    try:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", run):
            raise ValueError("invalid run name")
        root = Path(os.path.expanduser(mirror_word)).parent.parent / "lanes"
        ignored = set()
        pid = os.getpid()
        while pid > 0 and pid not in ignored:
            ignored.add(pid)
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            pid = int(fields[1])
        processes = []
        uncertain = None
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal() or int(entry.name) in ignored:
                continue
            try:
                words = (entry / "cmdline").read_bytes().split(b"\0")
                tokens = [word.decode(errors="surrogateescape") for word in words]
                if any(word == run or str(root / run) in word
                       or f"lane-{loop}-{run}" in word for word in tokens):
                    processes.append(int(entry.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError as error:
                uncertain = str(error)[:1024]
        lock_path = root / (run + ".lock")
        lock = None
        try:
            lock = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ValueError("run lock is not regular")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_state = "unheld"
        except FileNotFoundError:
            lock_state = "absent"
        except BlockingIOError:
            lock_state = "held"
        except (OSError, ValueError) as error:
            lock_state = "unmeasured"
            uncertain = str(error)[:1024]
        finally:
            if lock is not None:
                os.close(lock)
        evidence.update(state="absent" if not processes and lock_state != "held" else "present",
                        processes=processes, lock=lock_state)
        if uncertain is not None:
            evidence["error"] = uncertain
            if evidence["state"] != "present":
                evidence["state"] = "unmeasured"
    except (OSError, ValueError) as error:
        evidence["error"] = str(error)[:1024]
    evidence["wall_seconds"] = time.monotonic() - started
    print("NODE-ABSENCE " + json.dumps(evidence), flush=True)
    return 0 if evidence["state"] == "absent" else 2


if __name__ == "__main__":
    sys.exit(main())
