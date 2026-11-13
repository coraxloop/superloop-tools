"""Per-call vendor admission under the independently selected loop identity."""
import os
import stat


def program_component(info, path, loop_uid, leaf):
    if info.st_uid not in (0, 65534, loop_uid):
        raise RubricFailure('program-owner', path, info)
    if info.st_mode & 0o022:
        raise RubricFailure('program-writable', path, info)
    if leaf:
        if not stat.S_ISREG(info.st_mode):
            raise RubricFailure('program-type', path, info)
        if info.st_mode & 0o6000:
            raise RubricFailure('program-set-id', path, info)
    elif not stat.S_ISDIR(info.st_mode):
        raise RubricFailure('program-directory', path, info)


def admit_program(path, loop_uid):
    parts = path.split('/')[1:]
    if (not path.startswith('/') or len(path) > 4096 or not parts
            or any(part in ('', '.', '..') for part in parts)):
        raise RubricFailure('program-path', path)
    parent = None
    child = None
    component = '/'
    try:
        parent = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        program_component(os.fstat(parent), '/', loop_uid, False)
        for index, part in enumerate(parts):
            component = os.path.join(component, part)
            child = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(child)
            if stat.S_ISLNK(info.st_mode):
                raise RubricFailure('program-link', component, info)
            leaf = index == len(parts) - 1
            program_component(info, component, loop_uid, leaf)
            if leaf and not os.access(part, os.X_OK, dir_fd=parent, effective_ids=True):
                raise RubricFailure('program-executable', component, info)
            os.close(parent)
            parent, child = child, None
    except OSError as error:
        raise RubricFailure('program-open', component, error=error) from error
    finally:
        if child is not None:
            os.close(child)
        if parent is not None:
            os.close(parent)
