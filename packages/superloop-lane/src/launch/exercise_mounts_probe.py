import errno
import json
import os
import socket
import stat

FLAGS = os.O_CLOEXEC | os.O_NOFOLLOW
DIR = FLAGS | os.O_DIRECTORY | os.O_RDONLY
ROOT = os.open("/", DIR)
if not stat.S_ISDIR(os.fstat(ROOT).st_mode):
    raise ValueError("root is not a directory")


def open_at(components, final_flags=DIR):
    held = os.dup(ROOT)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, DIR, dir_fd=held)
            if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                os.close(next_fd)
                raise ValueError("path component is not a directory")
            os.close(held)
            held = next_fd
        if not components:
            return held
        result = os.open(components[-1], final_flags, dir_fd=held)
        os.fstat(result)
        os.close(held)
        return result
    except BaseException:
        os.close(held)
        raise


def read_proc(components):
    fd = open_at(["proc", str(os.getpid())] + components, FLAGS | os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("proc entry is not a regular file")
        data = os.read(fd, 1048577)
        if len(data) > 1048576:
            raise ValueError("proc entry exceeds the probe limit")
        return data.decode("utf-8")
    finally:
        os.close(fd)


def unescape(value):
    for escaped, plain in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(escaped, plain)
    return value


def mounts():
    rows = []
    for line in read_proc(["mountinfo"]).splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        after = right.split()
        target = unescape(fields[4])
        components = [part for part in target.split("/") if part]
        try:
            fd = open_at(components, FLAGS | os.O_PATH)
            info = os.fstat(fd)
            owner = info.st_uid
            mode = format(stat.S_IMODE(info.st_mode), "04o")
            os.close(fd)
        except OSError:
            owner = None
            mode = None
        rows.append({"target": target, "fstype": after[0], "access": "ro" if "ro" in fields[5].split(",") else "rw", "owner": owner, "mode": mode})
        if len(rows) > 512:
            raise ValueError("mount table exceeds 512 entries")
    return rows


def present(path):
    components = [part for part in path.split("/") if part]
    try:
        fd = open_at(components, FLAGS | os.O_PATH)
        os.close(fd)
        return True
    except OSError as error:
        if error.errno == errno.ENOENT:
            return False
        return "refused:" + errno.errorcode.get(error.errno, str(error.errno))


def ancestors():
    names = ["home", "worker", ".local", "inbox"]
    result = []
    for count in range(len(names) + 1):
        components = names[:count]
        path = "/" + "/".join(components)
        fd = open_at(components)
        info = os.fstat(fd)
        mount_readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
        worker = os.geteuid()
        groups = set(os.getgroups()) | {os.getegid()}
        writable = (info.st_uid == worker and bool(info.st_mode & stat.S_IWUSR)) or (info.st_gid in groups and bool(info.st_mode & stat.S_IWGRP)) or bool(info.st_mode & stat.S_IWOTH)
        created = False
        canary = ".superloop-mount-canary-" + str(os.getpid())
        try:
            canary_fd = os.open(canary, FLAGS | os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
            if not stat.S_ISREG(os.fstat(canary_fd).st_mode):
                raise ValueError("canary is not a regular file")
            os.close(canary_fd)
            created = True
            os.unlink(canary, dir_fd=fd)
        except OSError as error:
            create_error = errno.errorcode.get(error.errno, str(error.errno))
        else:
            create_error = "created-removed"
        os.close(fd)
        renamed = False
        rename_error = "root-has-no-parent"
        if count:
            parent = open_at(names[:count - 1])
            replacement = ".superloop-mount-canary-" + str(os.getpid())
            try:
                os.rename(names[count - 1], replacement, src_dir_fd=parent, dst_dir_fd=parent)
                renamed = True
                os.rename(replacement, names[count - 1], src_dir_fd=parent, dst_dir_fd=parent)
                rename_error = "renamed-restored"
            except OSError as error:
                rename_error = errno.errorcode.get(error.errno, str(error.errno))
            os.close(parent)
        result.append({"path": path, "uid": info.st_uid, "mode": format(stat.S_IMODE(info.st_mode), "04o"), "mount_readonly": mount_readonly, "worker_writable": writable and not mount_readonly, "create_succeeded": created, "create_result": create_error, "rename_succeeded": renamed, "rename_result": rename_error})
    return result


def direct_routes():
    table = read_proc(["net", "route"])
    rows = [row.split() for row in table.splitlines()[1:]]
    default = any(len(row) > 1 and row[1] == "00000000" for row in rows)
    nonloopback = [{"interface": row[0], "destination": row[1]} for row in rows if len(row) > 1 and row[0] != "lo"]
    try:
        ipv6_rows = [row.split() for row in read_proc(["net", "ipv6_route"]).splitlines()]
    except FileNotFoundError:
        ipv6_rows = None
    if ipv6_rows is not None and any(len(row) < 10 for row in ipv6_rows):
        ipv6_rows = None
    ipv6_default = None if ipv6_rows is None else any(row[0] == "0" * 32 and row[1] == "00" and row[-1] != "lo" and not (int(row[8], 16) & 0x0200) for row in ipv6_rows)
    ipv6_nonloopback = None if ipv6_rows is None else [{"interface": row[-1], "destination": row[0], "prefix": row[1]} for row in ipv6_rows if len(row) >= 10 and row[-1] != "lo"]
    trials = []
    for name, address, family in (("external-test-net", "198.51.100.1", socket.AF_INET), ("pod-gateway", "10.88.0.1", socket.AF_INET), ("rootless-gateway", "10.0.2.2", socket.AF_INET), ("ipv6-documentation", "2001:db8::1", socket.AF_INET6)):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.25)
                code = connection.connect_ex((address, 443))
        except OSError as error:
            code = error.errno
        trials.append({"name": name, "address": address, "family": "ipv6" if family == socket.AF_INET6 else "ipv4", "result": errno.errorcode.get(code, str(code)), "refused": code in (errno.ENETUNREACH, errno.EHOSTUNREACH)})
    return {"default_route": default, "nonloopback_routes": nonloopback, "ipv6_default_route": ipv6_default, "ipv6_nonloopback_routes": ipv6_nonloopback, "trials": trials}


owner = os.environ.get("SUPERLOOP_MOUNT_OWNER_UID", "")
if not owner.isdecimal():
    raise ValueError("owner UID is absent")
doors = ["/run/user/" + owner + "/bus", "/run/host", "/run/dbus/system_bus_socket", "/run/systemd/private", "/run/systemd/journal/socket", "/run/podman/podman.sock", "/run/user/" + owner + "/podman/podman.sock", "/var/run/docker.sock"]
print(json.dumps({"mounts": mounts(), "ancestors": ancestors(), "host_doors": [{"path": path, "present": present(path)} for path in doors], "direct_routes": direct_routes()}, separators=(",", ":")))
