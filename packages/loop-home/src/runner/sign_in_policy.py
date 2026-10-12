"""Shared custody predicate for metadata inspection and attempted agent use."""
import hashlib
import os
import stat


def sign_in_usable(file, directory, uid):
    return (stat.S_ISDIR(directory.st_mode)
            and directory.st_uid == uid
            and not directory.st_mode & 0o022
            and stat.S_ISREG(file.st_mode)
            and file.st_uid == uid
            and not file.st_mode & 0o077)


class RubricFailure(Exception):
    def __init__(self, check, path, info=None, error=None):
        self.evidence = dict(check=check, path=path[:4096],
                             owner_uid=None if info is None else info.st_uid,
                             mode=None if info is None else format(stat.S_IMODE(info.st_mode), '04o'),
                             errno=None if error is None else error.errno)
        super().__init__(check)


def rubric_ancestor(info, path, loop_uid):
    if info.st_uid not in (0, 65534, loop_uid):
        raise RubricFailure('ancestor-owner', path, info)
    sticky_root = info.st_uid in (0, 65534) and info.st_mode & 0o1777 == 0o1777
    if info.st_mode & 0o022 and not sticky_root:
        raise RubricFailure('ancestor-writable', path, info)


def read_rubric(path, loop_uid=None):
    """Read bounded rubric bytes under entered identity, pinning every ancestor."""
    if loop_uid is None:
        loop_uid = os.getuid()
    parts = path.split('/')[1:]
    if (not path.startswith('/') or len(path) > 4096 or not parts
            or any(part in ('', '.', '..') for part in parts)):
        raise RubricFailure('path', path)
    parent = None
    descriptor = None
    component = '/'
    check = 'ancestor-open'
    info = None
    try:
        parent = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts[:-1]:
            component = os.path.join(component, part)
            info = None
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            # Traverse under the real entered identity; bind the expected loop
            # identity at the leaf before reading any rubric bytes.
            rubric_ancestor(info, component, os.getuid())
        component = path
        check = 'file-open'
        info = None
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RubricFailure('file-type', path, info)
        if info.st_uid not in (0, loop_uid):
            raise RubricFailure('file-owner', path, info)
        if os.geteuid() != loop_uid:
            raise RubricFailure('entry-uid', path, info)
        if info.st_mode & 0o022:
            raise RubricFailure('file-writable', path, info)
        check = 'file-read'
        with os.fdopen(descriptor, 'rb') as file:
            descriptor = None
            rubric = file.read(65537)
        if len(rubric) > 65536 or not rubric.strip():
            raise RubricFailure('file-size', path, info)
        try:
            text = rubric.decode('utf-8')
        except UnicodeError as error:
            raise RubricFailure('file-utf8', path, info) from error
        return text, hashlib.sha256(rubric).hexdigest()
    except OSError as error:
        raise RubricFailure(check, component, info, error) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)
