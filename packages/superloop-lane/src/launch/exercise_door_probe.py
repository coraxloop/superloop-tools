"""Measure the pinned stub, registered socket reply and key-bearing paths in the box."""

import hashlib
import json
import os
import stat
import subprocess
import time


def invoke_stub(stub, run):
    started = time.monotonic()
    while True:
        # Follow door ADMISSION_WAIT: 30 s + 2 s reply margin + 3 s slack.
        reply = subprocess.run(
            [stub, "door-shape-probe", run], input=b"", capture_output=True,
            timeout=max(0.001, 35 - (time.monotonic() - started)), check=False,
        )
        reason = reply.stderr.decode("utf-8", "replace").strip()
        if not (reason == "door-request-concurrent" or reason.startswith("door-request-concurrent:")):
            return reply
        if time.monotonic() - started >= 2:
            return reply
        time.sleep(0.05)

stub = "/home/worker/.local/libexec/superloop/ssh"
run = os.environ.get("SUPERLOOP_DOOR_RUN", "")
result = {
    "scan_complete": True,
    "key_scan": "names-and-metadata",
    "key_paths": [],
    "key_environment": [],
    "stub_sha256": None,
    "stub_status": None,
    "stub_reason": None,
    "stub_stdout_bytes": None,
}

for name in os.environ:
    if name in {"SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS"} or name.endswith(
        ("_PRIVATE_KEY", "_SSH_KEY")
    ):
        if len(result["key_environment"]) < 32:
            result["key_environment"].append(name)
        else:
            result["scan_complete"] = False
            result["error"] = "key environment exceeds entry limit"

seen = set()
count = 0


def held_directory(parts):
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in parts:
            next_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                raise ValueError("directory component changed type")
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def scan(directory_fd, logical, depth):
    global count
    metadata = os.fstat(directory_fd)
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in seen:
        return
    seen.add(identity)
    if depth > 24:
        result["scan_complete"] = False
        result["error"] = "key-path walk exceeds depth limit"
        return
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            count += 1
            if count > 50000:
                result["scan_complete"] = False
                result["error"] = "key-path walk exceeds entry limit"
                return
            name = entry.name.lower()
            observed = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            path = logical + "/" + entry.name
            if (
                name == ".ssh"
                or name.startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
                or name.endswith((".pem", ".key"))
                or name in {"authorized_keys", "ssh-agent.sock"}
            ):
                if len(result["key_paths"]) < 32:
                    result["key_paths"].append(path)
            if stat.S_ISDIR(observed.st_mode):
                child = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (
                        observed.st_dev,
                        observed.st_ino,
                    ):
                        raise ValueError("key-path component changed identity")
                    scan(child, path, depth + 1)
                finally:
                    os.close(child)
            if not result["scan_complete"]:
                return


try:
    home_fd = held_directory(("home", "worker"))
    try:
        scan(home_fd, "/home/worker", 0)
    finally:
        os.close(home_fd)
except (OSError, ValueError) as error:
    result["scan_complete"] = False
    result["error"] = f"key-path walk: {error}"

try:
    template_fd = held_directory(
        ("home", "worker", ".local", "libexec", "superloop")
    )
    try:
        fd = os.open("ssh", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=template_fd)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024 * 1024:
                raise ValueError("stub type or size differs")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            result["stub_sha256"] = digest.hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(template_fd)
    reply = invoke_stub(stub, run)
    result["stub_status"] = reply.returncode
    result["stub_reason"] = reply.stderr.decode("utf-8", "replace").strip()
    result["stub_stdout_bytes"] = len(reply.stdout)
except (OSError, ValueError, subprocess.TimeoutExpired) as error:
    result["error"] = f"stub or socket: {error}"

print(json.dumps(result, sort_keys=True))
