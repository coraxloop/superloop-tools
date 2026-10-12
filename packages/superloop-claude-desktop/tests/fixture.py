"""Synthetic application state; every action runs the built client binary."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

BINARY, CASE = sys.argv[1:]
PREFIX = b"_https://claude.ai\0\1"
STORE = PREFIX + b"dframe-store"
MIRROR = PREFIX + b"LSS-persisted.dframe-group-scopes"
BLOCK = 32768


def crc(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    value ^= 0xffffffff
    return (((value >> 15) | (value << 17)) + 0xa282ead8) & 0xffffffff


def var(n):
    data = bytearray()
    while n >= 128:
        data.append((n & 127) | 128)
        n >>= 7
    return bytes(data) + bytes([n])


def unvar(data, pos):
    n = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        n |= (byte & 127) << shift
        if byte < 128:
            return n, pos
        shift += 7


def storage(value, latin=False):
    text = json.dumps(value, separators=(",", ":"))
    return b"\1" + text.encode("latin1") if latin else b"\0" + text.encode("utf-16-le")


def wal(entries, seq=1):
    payload = struct.pack("<QI", seq, len(entries))
    for key, value in entries:
        payload += bytes([value is not None]) + var(len(key)) + key
        if value is not None:
            payload += var(len(value)) + value
    data = bytearray()
    first = True
    while payload:
        left = BLOCK - len(data) % BLOCK
        if left < 7:
            data.extend(b"\0" * left)
            left = BLOCK
        piece, payload = payload[:left - 7], payload[left - 7:]
        kind = (1 if not payload else 2) if first else (4 if not payload else 3)
        data.extend(struct.pack("<IHB", crc(bytes([kind]) + piece), len(piece), kind) + piece)
        first = False
    return data


def read_wal(path):
    data = path.read_bytes()
    pos = 0
    fragment = b""
    entries = {}
    maximum = 0
    while pos < len(data):
        left = BLOCK - pos % BLOCK
        if left < 7:
            pos += left
            continue
        checksum, size, kind = struct.unpack_from("<IHB", data, pos)
        piece = data[pos + 7:pos + 7 + size]
        assert crc(bytes([kind]) + piece) == checksum
        pos += size + 7
        fragment += piece
        if kind not in (1, 4):
            continue
        seq, count = struct.unpack_from("<QI", fragment)
        at = 12
        for index in range(count):
            tag = fragment[at]
            size, at = unvar(fragment, at + 1)
            key = fragment[at:at + size]
            at += size
            value = None
            if tag:
                size, at = unvar(fragment, at)
                value = fragment[at:at + size]
                at += size
            entries[key] = (seq + index, value)
        assert at == len(fragment)
        maximum = max(maximum, seq + count - 1)
        fragment = b""
    assert not fragment
    return entries, maximum


def table(entries):
    # A genuine table footer and block trailers, with a Snappy literal data block.
    def block(rows, compressed):
        raw = b"".join(var(0) + var(len(k)) + var(len(v)) + k + v for k, v in rows)
        raw += struct.pack("<II", 0, 1)
        if compressed:
            length = len(raw) - 1
            width = max(1, (length.bit_length() + 7) // 8)
            raw = var(len(raw)) + bytes([(59 + width) << 2]) + length.to_bytes(width, "little") + raw
        kind = bytes([int(compressed)])
        return raw + kind + struct.pack("<I", crc(raw + kind)), len(raw)
    data, size = block([(key + struct.pack("<Q", (seq << 8) | 1), value) for key, seq, value in entries], True)
    index, index_size = block([(b"z", var(0) + var(size))], False)
    handles = var(0) + var(0) + var(len(data)) + var(index_size)
    return data + index + handles.ljust(40, b"\0") + bytes.fromhex("57fb808b247547db")


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, (bytes, bytearray)) else json.dumps(data).encode())


def snapshot(root):
    # Snapshot without introducing the atime changes that the assertion detects.
    result = {}
    def visit(path):
        stat = path.lstat()
        content = None
        if path.is_dir():
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
            try:
                names = sorted(os.listdir(fd))
            finally:
                os.close(fd)
            for name in names:
                visit(path / name)
        elif path.is_file():
            fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
            try:
                chunks = []
                while chunk := os.read(fd, 65536):
                    chunks.append(chunk)
                content = b"".join(chunks)
            finally:
                os.close(fd)
        result[str(path.relative_to(root))] = (stat.st_ino, stat.st_mode, stat.st_uid, stat.st_gid, stat.st_size, stat.st_atime_ns, stat.st_mtime_ns, stat.st_ctime_ns, content)
    visit(root)
    return result


def layout(base):
    root = base / "fixture"
    db = root / "application/Local Storage/leveldb"
    a = root / "application/claude-code-sessions/a/org"
    b = root / "application/claude-code-sessions/b/org"
    for path in (db, a, b, root / "registry", root / "projects", root / "proc"):
        path.mkdir(parents=True)
    write(db / "LOCK", b"")
    write(a / "local_one.json", {"cliSessionId": "first", "lastActivityAt": 10, "title": "private-title"})
    write(b / "local_two.json", {"cliSessionId": "second", "lastActivityAt": 20})
    for name in ("first", "second"):
        write(root / f"projects/project/{name}.jsonl", b"private-transcript\n")
    poison = base / "poison"
    poison.mkdir()
    write(poison / "000001.log", b"invalid")
    return root, db, a, b


def run(root, *args, code=0, readonly=False, explicit=False):
    before = snapshot(root) if readonly else None
    env = os.environ.copy()
    poison = str(root.parent / "poison")
    env.update(HOME=poison, CCD_LEVELDB_DIR=poison, CCD_SESSIONS_ROOT=poison, CCD_SESSIONS_REGISTRY=poison)
    roots = ["--fixture-root", str(root)]
    if explicit:
        roots = []
        for flag, suffix in (("leveldb-dir", "application/Local Storage/leveldb"), ("sessions-root", "application/claude-code-sessions"), ("sessions-registry", "registry"), ("projects-root", "projects"), ("proc-root", "proc")):
            roots += ["--" + flag, str(root / suffix)]
    result = subprocess.run([BINARY, *roots, *args], env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    assert "CCD-DURATION-MS " in result.stdout
    assert "private-title" not in result.stdout and "private-transcript" not in result.stdout
    if readonly:
        assert snapshot(root) == before, "read-only command changed bytes or metadata"
    return result.stdout


def group_state():
    scope = {"groups": [{"id": "g", "name": "private-group"}], "assignments": {"chat:local_one": "g", "chat:local_missing": "g"}, "order": {"g": ["chat:local_one", "chat:local_missing"]}}
    return {"state": {"customGroupsByScope": {"a/org": scope}}, "padding": "x" * 35000}


def groups(base):
    root, db, _, _ = layout(base)
    # Compacted store at sequence 50, current WAL mirror at sequence 2.
    write(db / "000001.ldb", table([(STORE, 50, storage(group_state(), True))]))
    write(db / "000002.log", wal([(MIRROR, storage({"value": {}, "timestamp": 0}))], 2))
    text = run(root, "sync-groups", "--dry-run", readonly=True)
    assert "groups=1 assignments=1 dropped=1 changed=2" in text
    run(root, "sync-groups", "--dry-run", "--migrate", readonly=True, explicit=True)
    run(root, "sync-groups", "--migrate")
    entries, maximum = read_wal(db / "000002.log")
    assert maximum == 52 and entries[STORE][0] == 51 and entries[MIRROR][0] == 52
    state = json.loads(entries[STORE][1][1:].decode("utf-16-le"))["state"]
    assert set(state["customGroupsByScope"]) == {"a/org", "b/org"}
    assert state["customGroupsByScope"]["a/org"] == state["customGroupsByScope"]["b/org"]
    assert state["pendingLegacyGroupMigration"]["assignments"] == {"chat:local_one": "g"}
    assert len(list((root / "application").glob("local-storage-backup-*.tar.gz"))) == 1
    run(root, "sync-groups", "--migrate", readonly=True)
    # Read the now-fragmented UTF16 WAL without consulting a table.
    (db / "000001.ldb").unlink()
    run(root, "sync-groups", "--dry-run", readonly=True)


def group_order(base):
    for weighted in (False, True):
        root, db, _, _ = layout(base / str(weighted))
        first = {"groups": [{"id": "z", "name": "first-z"}, {"id": "a", "name": "first-a"}], "assignments": {"chat:local_one": "z"}, "order": {"z": ["chat:local_one"]}}
        second = {"groups": [{"id": "a", "name": "second-a"}, {"id": "z", "name": "second-z"}], "assignments": {"chat:local_one": "a"}, "order": {"a": ["chat:local_one"]}}
        if weighted:
            second["assignments"]["chat:local_two"] = "a"
        # Reverse lexical scope and group order. Equal-weight ties must keep
        # input scope order; greater assignment count must still win priority.
        source = {"state": {"customGroupsByScope": {"b/org": first, "a/org": second}}}
        write(db / "000001.log", wal([(STORE, storage(source))]))
        run(root, "sync-groups", "--dry-run", readonly=True)
        run(root, "sync-groups")
        entries, _ = read_wal(db / "000001.log")
        state = json.loads(entries[STORE][1][1:].decode("utf-16-le"))["state"]
        expected = second if weighted else first
        for scope in state["customGroupsByScope"].values():
            assert scope["groups"] == expected["groups"]
            assert scope["assignments"]["chat:local_one"] == expected["assignments"]["chat:local_one"]
        run(root, "sync-groups", readonly=True)


def sessions(base):
    root, db, a, b = layout(base)
    text = run(root, "merge-sessions", "--dry-run", readonly=True)
    assert "changed=2 held=0 forks=0 orphans=0" in text
    run(root, "merge-sessions", "--check", code=1, readonly=True, explicit=True)
    # The proc root is synthetic; neither the host process table nor HOME is read.
    write(root / "registry/active.json", {"entrypoint": "claude-desktop", "pid": 424242, "sessionId": "first", "procStart": 77})
    write(root / "proc/424242/stat", ("424242 (fixture process) " + " ".join(["S"] + ["0"] * 18 + ["77"]) + "\n").encode())
    assert "held=1" in run(root, "merge-sessions", "--dry-run", readonly=True)
    run(root, "merge-sessions", code=3)
    assert not (b / "local_one.json").exists()
    write(root / "registry/active.json", {"entrypoint": "claude-desktop", "pid": 424242, "sessionId": "first", "procStart": 78})
    run(root, "merge-sessions")
    assert (b / "local_one.json").read_bytes() == (a / "local_one.json").read_bytes()
    run(root, "merge-sessions", "--check", readonly=True)
    run(root, "merge-sessions", readonly=True)
    # Archive metadata changes mtime without advancing lastActivityAt. Choose
    # the later store first, then the earlier store, to catch enumeration ties.
    first, second = a / "local_one.json", b / "local_one.json"
    activity = json.loads(first.read_bytes())["lastActivityAt"]
    os.utime(first, ns=(1_000_000_000, 1_000_000_000))
    data = json.loads(second.read_bytes())
    data["isArchived"] = True
    write(second, data)
    os.utime(second, ns=(2_000_000_000, 2_000_000_000))
    text = run(root, "merge-sessions", "--dry-run", readonly=True)
    assert "changed=1" in text and "archived" in text, text
    assert "archived" in run(root, "merge-sessions")
    assert json.loads(first.read_bytes())["isArchived"] is True
    assert json.loads(first.read_bytes())["lastActivityAt"] == activity
    assert first.stat().st_mtime_ns == second.stat().st_mtime_ns
    data["isArchived"] = False
    write(first, data)
    os.utime(first, ns=(3_000_000_000, 3_000_000_000))
    assert "unarchived" in run(root, "merge-sessions")
    assert json.loads(second.read_bytes())["isArchived"] is False
    data["isPinned"] = True
    write(second, data)
    os.utime(second, ns=(4_000_000_000, 4_000_000_000))
    assert "metadata rewritten 4000000000 ns since 1970-01-01T00:00:00Z" in run(root, "merge-sessions")
    assert json.loads(first.read_bytes())["isPinned"] is True
    # Mtime alone cannot cause a write or backup for byte-identical content.
    os.utime(first, ns=(5_000_000_000, 5_000_000_000))
    run(root, "merge-sessions", "--check", readonly=True)
    run(root, "merge-sessions", readonly=True)
    assert second.stat().st_mtime_ns == 4_000_000_000
    # Activity remains the primary key even when the older copy has a new mtime.
    data["lastActivityAt"] = activity + 1
    write(second, data)
    os.utime(second, ns=(2_000_000_000, 2_000_000_000))
    assert f"was {activity}" in run(root, "merge-sessions")
    assert json.loads(first.read_bytes())["lastActivityAt"] == activity + 1
    write(a / "local_one.json", {"cliSessionId": "old", "lastActivityAt": 100})
    write(b / "local_one.json", {"cliSessionId": "new", "priorCliSessionIds": ["old"], "lastActivityAt": 50})
    run(root, "merge-sessions", "--dry-run", code=4, readonly=True)
    run(root, "merge-sessions", "--prefer-successor", "--dry-run", readonly=True)
    assert "transcript old -> new" in run(root, "merge-sessions", "--prefer-successor")
    assert json.loads((a / "local_one.json").read_bytes())["cliSessionId"] == "new"


def refusals(base):
    root, db, first, _ = layout(base)
    write(db / "000001.log", wal([(STORE, storage(group_state())), (MIRROR, storage({}))]))
    # POSIX locks belong to a process: a snapshot opening/closing LOCK in the
    # locking process would release it. Hold it in a separate foreground child.
    locker = subprocess.Popen([sys.executable, "-c", "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.lockf(f,fcntl.LOCK_EX); print('locked',flush=True); sys.stdin.read()", str(db / "LOCK")], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert locker.stdout.readline() == b"locked\n"
    try:
        run(root, "sync-groups", "--dry-run", code=2, readonly=True)
        run(root, "merge-sessions", code=2, readonly=True)
        run(root, "merge-sessions", "--dry-run", readonly=True)
        run(root, "merge-sessions", "--allow-live")
    finally:
        locker.communicate(timeout=5)
        assert locker.returncode == 0
    data = bytearray((db / "000001.log").read_bytes())
    data[0] ^= 1
    write(db / "000001.log", data)
    saved_session = (first / "local_one.json").read_bytes()
    write(first / "local_one.json", b"not JSON")
    result = subprocess.run([BINARY, "--fixture-root", str(root), "merge-sessions", "--check"], capture_output=True)
    assert result.returncode == 2
    assert b"CCD-FAILED" in result.stderr
    assert b"CCD_SESSIONS_DIVERGED" not in result.stdout
    assert b"CCD-DURATION-MS" in result.stdout
    write(first / "local_one.json", saved_session)
    run(root, "sync-groups", "--dry-run", code=1, readonly=True)
    write(db / "000001.log", wal([(STORE, storage(group_state())), (MIRROR, storage([]))]))
    run(root, "sync-groups", "--dry-run", code=1, readonly=True)
    write(db / "000001.log", wal([(STORE, None)]))
    run(root, "sync-groups", "--dry-run", code=1, readonly=True)
    for args in (["merge-sessions", "--unknown"], ["sync-groups", "--unknown"], ["--unknown"], ["--proc-root"]):
        result = subprocess.run([BINARY, "--fixture-root", str(root), *args], capture_output=True)
        assert result.returncode == 2
        assert result.stderr
        assert b"DURATION" not in result.stdout + result.stderr
    for flag in ("--help", "--version"):
        result = subprocess.run([BINARY, "--fixture-root", str(root), flag], capture_output=True)
        assert result.returncode == 0


with tempfile.TemporaryDirectory(prefix="desktop-fixture-") as directory:
    {"groups": groups, "group-order": group_order, "sessions": sessions, "refusals": refusals}[CASE](Path(directory))
print("fixture=" + CASE + " passed")
