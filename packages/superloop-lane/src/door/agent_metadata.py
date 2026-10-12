"""Metadata only, executed after the registered entry selects the loop UID."""
import json
import os
import stat
import sys


def executable_usable(info, uid, gid, groups):
    if not stat.S_ISREG(info.st_mode):
        return False
    if uid == 0:
        return bool(info.st_mode & 0o111)
    bit = 0o100 if info.st_uid == uid else (0o010 if info.st_gid in {gid, *groups} else 0o001)
    return bool(info.st_mode & bit)


def inspect(path, executable=False):
    result = dict(path=path, exists=None, owner_uid=None, mode=None,
                  loop_uid=os.geteuid(), usable=None, inspection_error=None)
    parent = None
    child = None
    try:
        parts = path.split('/')[1:]
        if not path.startswith('/') or not parts or any(p in ('', '.', '..') for p in parts):
            raise ValueError('non-normalized-path')
        parent = os.open('/', os.O_PATH | os.O_DIRECTORY)
        for index, part in enumerate(parts):
            child = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(child)
            last = index == len(parts) - 1
            if last:
                result.update(exists=True, owner_uid=info.st_uid,
                              mode=format(stat.S_IMODE(info.st_mode), '04o'))
            if stat.S_ISLNK(info.st_mode) or (not last and not stat.S_ISDIR(info.st_mode)):
                result['usable'] = False
                raise ValueError('symbolic-link-or-nondirectory')
            if last:
                directory = os.fstat(parent)
                result['usable'] = (executable_usable(info, os.geteuid(), os.getegid(), os.getgroups())
                                    if executable else sign_in_usable(info, directory, os.geteuid()))
            else:
                os.close(parent)
                parent, child = child, None
    except FileNotFoundError:
        result['exists'] = False
    except (OSError, ValueError) as error:
        result['inspection_error'] = error.__class__.__name__ + ':' + str(error)
    finally:
        if child is not None:
            os.close(child)
        if parent is not None:
            os.close(parent)
    return result


def main():
    program, loop, expected_uid = sys.argv[1:]
    if os.geteuid() != int(expected_uid):
        raise ValueError('entry-loop-uid-mismatch')
    sign_in = inspect(os.path.join(os.environ['HOME'], '.codex', 'auth.json'))
    sign_in['remedy'] = ('superloop-lane door-sign-in ' + loop
                         if sign_in['exists'] is False else None)
    print(json.dumps(dict(sign_in=sign_in, executable_status=inspect(program, True))))


if __name__ == '__main__':
    main()
