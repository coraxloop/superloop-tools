"""Regression fixtures for the production metadata program; synthetic inputs only."""
import os
import stat
import sys
from types import SimpleNamespace

scope = {'__name__': 'fixture'}
exec(sys.argv[1], scope)
execute = scope['executable_usable']
for uid, gid, groups, mode, owner, group, expected in [
        (1001, 1001, [], 0o100, 1001, 1002, True),
        (1001, 1001, [], 0o010, 1001, 1001, False),
        (1001, 1001, [], 0o010, 1002, 1001, True),
        (1001, 1001, [1002], 0o010, 1003, 1002, True),
        (1001, 1001, [], 0o001, 1002, 1003, True),
        (1001, 1001, [], 0o010, 1002, 1003, False),
        (0, 0, [], 0o600, 1001, 1001, False),
        (0, 0, [], 0o001, 1001, 1001, True)]:
    info = SimpleNamespace(st_uid=owner, st_gid=group, st_mode=stat.S_IFREG | mode)
    assert execute(info, uid, gid, groups) is expected

root = sys.argv[2]
for file_uid, directory_uid, expected in [
        (1001, 1001, True), (1002, 1001, False),
        (1001, 1002, False), (1002, 1002, False),
        (0, 1001, False), (1001, 0, False)]:
    file = SimpleNamespace(st_uid=file_uid, st_mode=stat.S_IFREG | 0o600)
    parent = SimpleNamespace(st_uid=directory_uid, st_mode=stat.S_IFDIR | 0o700)
    assert scope['sign_in_usable'](file, parent, 1001) is expected
directory = root + '/.codex'
auth = directory + '/auth.json'
os.mkdir(directory, 0o700)
with open(auth, 'w') as file:
    file.write('synthetic credential')
os.chmod(auth, 0o400)
os.chmod(directory, 0o755)
assert scope['inspect'](auth)['usable'] is True
os.chmod(auth, 0o640)
assert scope['inspect'](auth)['usable'] is False
os.chmod(auth, 0o400)
real_open = os.open


def rename_after_open(path, *args, **kwargs):
    fd = real_open(path, *args, **kwargs)
    if path == 'auth.json':
        os.rename(directory, directory + '-held')
        os.mkdir(directory, 0o777)
        os.chmod(directory, 0o777)
    return fd


os.open = rename_after_open
try:
    assert scope['inspect'](auth)['usable'] is True
finally:
    os.open = real_open


def denied(*args, **kwargs):
    raise PermissionError('fixture denial')


os.open = denied
try:
    result = scope['inspect'](auth)
    assert result['exists'] is None and result['usable'] is None
    assert result['inspection_error']
finally:
    os.open = real_open
