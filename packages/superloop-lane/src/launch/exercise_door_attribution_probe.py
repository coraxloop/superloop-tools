"""Measure a registered door through the pinned stub inside the recorded box."""

import json
import os
import socket
import struct
import subprocess
import time

STUB = "/home/worker/.local/libexec/superloop/ssh"
SOCKET = "/home/worker/.local/door/capability.sock"


def invoke(*words, data=b"", timeout=40):
    started = time.monotonic()
    while True:
        reply = subprocess.run(
            [STUB, *words], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=max(0.001, timeout - (time.monotonic() - started)), check=False,
        )
        # Refused admission writes no record and executes no effect, so only
        # this named refusal is safe to retry. Keep the box observation bounded.
        reason = (final_from_stderr(reply.stderr) or {}).get("reason")
        concurrent = reason == "door-request-concurrent" or reply.stderr.startswith(b"door-request-concurrent")
        if not concurrent or time.monotonic() - started >= min(2, timeout):
            return reply
        time.sleep(0.05)


def final_from_stderr(stderr):
    for line in reversed(stderr.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("type") == "final":
            return value
    return None


def changed_ref(reference):
    return reference + "-changed"


def raw_request(request, disconnect=False):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(5)
        peer.connect(SOCKET)
        data = json.dumps(request, separators=(",", ":")).encode()
        peer.sendall(struct.pack(">I", len(data)) + data)
        if disconnect:
            return None
        peer.shutdown(socket.SHUT_WR)
        header = bytearray()
        while len(header) < 4:
            part = peer.recv(4 - len(header))
            if not part:
                raise RuntimeError("door frame header closed")
            header.extend(part)
        size = struct.unpack(">I", header)[0]
        output = bytearray()
        while len(output) < size:
            part = peer.recv(size - len(output))
            if not part:
                raise RuntimeError("final door frame closed")
            output.extend(part)
        return json.loads(output)


def main():
    scope = os.environ["SUPERLOOP_DOOR_SCOPE"]
    run = os.environ["SUPERLOOP_DOOR_RUN"]
    reference = os.environ["SUPERLOOP_DOOR_REF"]
    alias = os.environ["SUPERLOOP_DOOR_ALIAS"]
    mirror = os.environ["SUPERLOOP_DOOR_MIRROR_ROOT"] + "/" + run + ".git"
    result = {"schema": 1, "scope": scope}
    try:
        if scope == "review":
            refusal = invoke("door-attribution-probe")
            result["review_reason"] = (final_from_stderr(refusal.stderr) or {}).get("reason")
            print(json.dumps(result, sort_keys=True))
            return
        data = bytes(range(251)) * 4200
        echo = invoke("door-attribution-probe", data=data)
        reply = final_from_stderr(echo.stderr)
        result.update({
            "reply": reply, "bytes_match": echo.stdout == data,
            "input_bytes": len(data), "output_bytes": len(echo.stdout),
            "stub_exit": echo.returncode,
        })
        result["changed_ref"] = changed_ref(reference)
        command = (
            b"0" * 40 + b" " + b"1" * 40
            + b" " + result["changed_ref"].encode() + b"\0 report-status\n"
        )
        packet = f"{len(command) + 4:04x}".encode() + command + b"0000"
        try:
            # The service request has a 120 s deadline. End this observation at
            # 15 s, leaving room inside the 60 s box cap after the measured
            # 14.08 s echo for the authority, status, deadline and followup.
            changed = invoke(alias, f"git-receive-pack '{mirror}'", data=packet, timeout=15)
            result["changed_ref_reason"] = (
                changed.stderr.decode(errors="replace").strip().splitlines() or [None]
            )[-1]
        except subprocess.TimeoutExpired:
            result["changed_ref_reason"] = None
            result["changed_ref_waiting"] = True
        result["changed_ref_bytes"] = len(packet)
        authority = invoke("unregistered", "git-upload-pack 'other'")
        result["authority_reason"] = authority.stderr.decode(errors="replace").strip()
        status = invoke("door-attribution-status")
        result["status_exit"] = status.returncode
        result["status_reply"] = final_from_stderr(status.stderr)
        deadline = invoke("door-attribution-deadline")
        result["deadline_reason"] = (final_from_stderr(deadline.stderr) or {}).get("reason")
        raw_request({
            "schema": 2, "argv": [list(b"door-attribution-probe")],
            "deadline_ms": 1000,
        }, disconnect=True)
        followup = invoke("door-attribution-status")
        result["disconnect_reason"] = (final_from_stderr(followup.stderr) or {}).get("reason")
        result["disconnect_followup"] = followup.returncode == 1
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
