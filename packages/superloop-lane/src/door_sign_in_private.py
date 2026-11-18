"""Receive a bound canonical derivative as the entered loop UID, never emit it."""
import errno
import fcntl
import json
import os
import signal
import stat
import struct
import sys
import uuid


def metadata(fd, path):
    info = os.fstat(fd)
    return dict(path=path, exists=True, owner_uid=info.st_uid,
                mode=format(stat.S_IMODE(info.st_mode), '04o'),
                loop_uid=os.geteuid())


def private_home_mode(fd, mode):
    # Match the owner-authorized mail traversal shape, not arbitrary group access.
    try:
        os.getxattr(fd, 'system.posix_acl_default')
    except OSError as error:
        if error.errno != errno.ENODATA:
            return False
    else:
        return False
    try:
        access = os.getxattr(fd, 'system.posix_acl_access')
    except OSError as error:
        return error.errno == errno.ENODATA and mode == 0o700
    if len(access) != 44:
        return False
    service = struct.unpack_from('<I', access, 16)[0]
    undefined = 2**32 - 1
    expected = struct.pack('<I', 2) + b''.join(
        struct.pack('<HHI', tag, permissions, identity)
        for tag, permissions, identity in [
            (1, 7, undefined), (2, 1, service), (4, 0, undefined),
            (16, 1, undefined), (32, 0, undefined)])
    return mode == 0o710 and access == expected


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
        if info.st_uid != os.geteuid() or not private_home_mode(parent, stat.S_IMODE(info.st_mode)):
            raise ValueError('door-sign-in-private-home-owner-mode')
        return parent
    except BaseException:
        os.close(parent)
        raise


def projection(data):
    if not data or len(data) > 65536:
        raise ValueError('door-projection-size')
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('door-projection-shape') from None
    if (not isinstance(value, dict)
            or set(value) != {'auth_mode', 'OPENAI_API_KEY', 'tokens', 'last_refresh'}
            or value['auth_mode'] != 'chatgptAuthTokens'
            or value['OPENAI_API_KEY'] is not None
            or not isinstance(value['last_refresh'], str)):
        raise ValueError('door-projection-shape')
    tokens = value['tokens']
    if (not isinstance(tokens, dict)
            or set(tokens) != {'id_token', 'access_token', 'refresh_token', 'account_id'}
            or tokens['refresh_token'] != ''
            or any(not isinstance(tokens[field], str) or not tokens[field]
                   for field in ('id_token', 'access_token', 'account_id'))):
        raise ValueError('door-projection-renewable-or-incomplete')
    return data


def remove_stale_temporaries(config):
    removed = False
    for name in os.listdir(config):
        if not name.startswith('.door-auth-'):
            continue
        suffix = name[len('.door-auth-'):]
        if len(suffix) != 32 or any(letter not in '0123456789abcdef' for letter in suffix):
            continue
        fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=config)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError('door-projection-stale-temporary-custody')
        finally:
            os.close(fd)
        os.unlink(name, dir_fd=config)
        removed = True
    if removed:
        os.fsync(config)


def main():
    def expired(_signum, _frame):
        raise TimeoutError('door-projection-receiver-deadline')
    signal.signal(signal.SIGALRM, expired)
    uid, home, remaining_ms = sys.argv[1:]
    signal.setitimer(signal.ITIMER_REAL, min(int(remaining_ms) / 1000, 10))
    if os.geteuid() != int(uid) or os.environ.get('HOME') != home or not home.endswith('/private'):
        raise ValueError('door-projection-entry-identity')
    root = directory(home)
    path = home + '/.codex/auth.json'
    config = None
    temporary = None
    try:
        data = projection(sys.stdin.buffer.read(65537))
        try:
            config = os.open('.codex', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        except FileNotFoundError:
            os.mkdir('.codex', 0o700, dir_fd=root)
            os.fsync(root)
            config = os.open('.codex', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        info = os.fstat(config)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('door-projection-config-owner-mode')
        fcntl.flock(config, fcntl.LOCK_EX | fcntl.LOCK_NB)
        remove_stale_temporaries(config)
        try:
            existing = os.open('auth.json', os.O_PATH | os.O_NOFOLLOW, dir_fd=config)
        except FileNotFoundError:
            pass
        else:
            try:
                info = os.fstat(existing)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise ValueError('door-projection-destination-owner-mode-type')
            finally:
                os.close(existing)
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
        report['byte_count'] = len(data)
        print(json.dumps(report))
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=config)
            except FileNotFoundError:
                pass
        if config is not None:
            os.close(config)
        os.close(root)


try:
    main()
except (OSError, ValueError, KeyError, TimeoutError) as error:
    reason = str(error) if isinstance(error, (ValueError, TimeoutError)) else 'door-projection-io'
    print('door-projection-private: ' + reason, file=sys.stderr)
    sys.exit(2)
