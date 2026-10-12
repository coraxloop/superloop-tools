"""Receive a bound canonical derivative as the entered loop UID, never emit it."""
import fcntl
import hashlib
import json
import os
import signal
import stat
import sys
import uuid


def metadata(fd, path):
    info = os.fstat(fd)
    return dict(path=path, exists=True, owner_uid=info.st_uid,
                mode=format(stat.S_IMODE(info.st_mode), '04o'),
                loop_uid=os.geteuid())


def directory(path):
    if not path.startswith('/') or any(p in ('.', '..', '') for p in path.split('/')[1:]):
        raise ValueError('door-sign-in-private-home-path')
    parts = path.split('/')[1:]
    parent = os.open('/', os.O_PATH | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(parent)
        parent = child
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('door-sign-in-private-home-owner-mode')
        return parent
    except BaseException:
        os.close(parent)
        raise


def main():
    def expired(_signum, _frame):
        raise TimeoutError('door-sign-in-receiver-deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(10)
    uid, home, dry, binding_text = sys.argv[1:]
    if os.geteuid() != int(uid) or os.environ.get('HOME') != home or not home.endswith('/private'):
        raise ValueError('door-sign-in-entry-identity')
    binding = json.loads(binding_text)
    root = directory(home)
    path = home + '/.codex/auth.json'
    config = None
    temporary = None
    try:
        try:
            config = os.open('.codex', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        except FileNotFoundError:
            if dry == 'true':
                print(json.dumps(dict(path=path, exists=False, owner_uid=None, mode=None,
                                      loop_uid=os.geteuid(), published=False)))
                return
            os.mkdir('.codex', 0o700, dir_fd=root)
            os.fsync(root)
            config = os.open('.codex', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        info = os.fstat(config)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('door-sign-in-config-owner-mode')
        fcntl.flock(config, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            existing = os.open('auth.json', os.O_PATH | os.O_NOFOLLOW, dir_fd=config)
        except FileNotFoundError:
            report = dict(path=path, exists=False, owner_uid=None, mode=None, loop_uid=os.geteuid())
        else:
            try:
                info = os.fstat(existing)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise ValueError('door-sign-in-destination-owner-mode-type')
                report = metadata(existing, path)
            finally:
                os.close(existing)
        if dry == 'true':
            report['published'] = False
            print(json.dumps(report))
            return
        before = os.fstat(0)
        if (before.st_dev != binding['device'] or before.st_ino != binding['inode']
                or before.st_size != binding['size'] or before.st_mtime_ns != binding['mtime_ns']
                or not stat.S_ISREG(before.st_mode)):
            raise ValueError('door-sign-in-source-binding')
        data = sys.stdin.buffer.read(1048577)
        after = os.fstat(0)
        if (not data or len(data) > 1048576 or len(data) != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns or after.st_size != before.st_size
                or after.st_ctime_ns != before.st_ctime_ns
                or hashlib.sha256(data).hexdigest() != binding['sha256']):
            raise ValueError('door-sign-in-source-changed-or-size')
        temporary = '.door-auth-' + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=config)
        with os.fdopen(fd, 'wb') as target:
            target.write(data)
            target.flush()
            os.fchmod(target.fileno(), 0o600)
            os.fsync(target.fileno())
            report = metadata(target.fileno(), path)
        os.replace(temporary, 'auth.json', src_dir_fd=config, dst_dir_fd=config)
        temporary = None
        os.fsync(config)
        report['published'] = True
        report['sha256'] = hashlib.sha256(data).hexdigest()
        report['byte_count'] = len(data)
        print(json.dumps(report))
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=config)
        if config is not None:
            os.close(config)
        os.close(root)


try:
    main()
except (OSError, ValueError, KeyError) as error:
    print('door-sign-in-private: ' + str(error), file=sys.stderr)
    sys.exit(2)
