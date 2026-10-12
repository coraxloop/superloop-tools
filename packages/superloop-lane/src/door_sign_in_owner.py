"""Owner-side content-bound descriptor handoff; reports never contain credentials."""
import hashlib
import json
import os
import stat
import subprocess
import sys


def source_parent(path):
    if not path.startswith('/') or any(p in ('', '.', '..') for p in path.split('/')[1:]):
        raise ValueError('door-sign-in-source-path')
    parts = path.split('/')[1:]
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            sticky = info.st_uid in (0, 65534) and stat.S_IMODE(info.st_mode) == 0o1777
            if info.st_uid not in (0, 65534, os.geteuid()) or (info.st_mode & 0o022 and not sticky):
                raise ValueError('door-sign-in-source-parent')
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('door-sign-in-canonical-directory-owner-mode')
        return parent, parts[-1]
    except BaseException:
        os.close(parent)
        raise


def main():
    entry, loop, uid, home, source, dry, expected, helper = sys.argv[1:]
    if source == home + '/.codex/auth.json':
        raise ValueError('door-sign-in-source-is-destination; use the canonical source')
    parent, name = source_parent(source)
    fd = None
    try:
        fd = os.open(name, (os.O_RDONLY | os.O_NONBLOCK)
                     | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= 1048576):
            raise ValueError('door-sign-in-source-owner-mode-type-size')
        data = os.pread(fd, 1048577, 0)
        after = os.fstat(fd)
        if (len(data) != info.st_size or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns or after.st_size != info.st_size):
            raise ValueError('door-sign-in-source-changed-or-size')
        digest = hashlib.sha256(data).hexdigest()
        del data
        preview = hashlib.sha256(json.dumps(dict(loop=loop, source=source,
            destination=home + '/.codex/auth.json', sha256=digest, byte_count=info.st_size),
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if expected and expected != preview:
            raise ValueError('door-sign-in-digest-mismatch; preview again')
        binding = dict(device=info.st_dev, inode=info.st_ino, size=info.st_size,
                       mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns, sha256=digest)
        argv = [entry, 'enter', loop, '--', '/usr/bin/python3', '-I', '-c', helper,
                uid, home, dry, json.dumps(binding)]
        result = subprocess.run(argv, stdin=subprocess.DEVNULL if dry == 'true' else fd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False)
        if result.returncode != 0:
            # The receiver emits metadata/path diagnostics only, never input bytes.
            raise ValueError('door-sign-in-entry: ' + result.stderr.decode('utf-8', 'replace')[:2048])
        destination = json.loads(result.stdout)
        if destination.get('path') != home + '/.codex/auth.json' or destination.get('loop_uid') != int(uid):
            raise ValueError('door-sign-in-receiver-report')
        removed = False
        if dry != 'true':
            if (destination.get('published') is not True or destination.get('sha256') != digest
                    or destination.get('byte_count') != info.st_size):
                raise ValueError('door-sign-in-publication-unconfirmed; source retained')
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev != info.st_dev or current.st_ino != info.st_ino
                    or current.st_size != info.st_size or current.st_mtime_ns != info.st_mtime_ns
                    or current.st_ctime_ns != info.st_ctime_ns
                    or hashlib.sha256(os.pread(fd, 1048577, 0)).hexdigest() != digest):
                raise ValueError('door-sign-in-source-changed-after-publication; source retained')
            # The canonical source remains in owner custody after every placement.
        print(json.dumps(dict(source=dict(path=source, exists=True, owner_uid=info.st_uid,
                                          mode=format(stat.S_IMODE(info.st_mode), '04o'),
                                          sha256=digest, byte_count=info.st_size),
                              destination=destination, source_removed=removed, preview_sha256=preview)))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


try:
    main()
except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
    print('door-sign-in: ' + str(error), file=sys.stderr)
    sys.exit(2)
