"""Measure a registered door through the pinned stub inside the recorded box."""

import json
import os
import socket
import struct
import subprocess
import time

STUB = "/home/worker/.local/libexec/superloop/ssh"
SOCKET = "/home/worker/.local/door/capability.sock"
PROBE_SECONDS = 55  # Leave five seconds for reporting inside the 60-second box run.
TIMEOUT_REASON = "door-request-concurrent: attribution probe timed out; claim unmeasured"


def remaining(deadline, cap):
    budget = min(cap, deadline - time.monotonic())
    if budget <= 0:
        raise TimeoutError("attribution probe budget exhausted")
    return budget


def invoke(*words, deadline, data=b"", timeout=35):
    started = time.monotonic()
    call_deadline = min(deadline, started + timeout)
    while True:
        reply = subprocess.run(
            [STUB, *words], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=remaining(call_deadline, 35), check=False,
        )
        # Refused admission writes no record and executes no effect, so only
        # this named refusal is safe to retry. Keep the box observation bounded.
        reason = (final_from_stderr(reply.stderr) or {}).get("reason")
        concurrent = reason == "door-request-concurrent" or reply.stderr.startswith(b"door-request-concurrent")
        if not concurrent or time.monotonic() - started >= min(2, timeout):
            return reply
        time.sleep(remaining(call_deadline, 0.05))


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


def raw_request(request, deadline, disconnect=False):
    call_deadline = min(deadline, time.monotonic() + 5)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(remaining(call_deadline, 5))
        peer.connect(SOCKET)
        data = json.dumps(request, separators=(",", ":")).encode()
        peer.settimeout(remaining(call_deadline, 5))
        peer.sendall(struct.pack(">I", len(data)) + data)
        if disconnect:
            return None
        peer.shutdown(socket.SHUT_WR)
        header = bytearray()
        while len(header) < 4:
            peer.settimeout(remaining(call_deadline, 5))
            part = peer.recv(4 - len(header))
            if not part:
                raise RuntimeError("door frame header closed")
            header.extend(part)
        size = struct.unpack(">I", header)[0]
        output = bytearray()
        while len(output) < size:
            peer.settimeout(remaining(call_deadline, 5))
            part = peer.recv(size - len(output))
            if not part:
                raise RuntimeError("final door frame closed")
            output.extend(part)
        return json.loads(output)


def main():
    deadline = time.monotonic() + PROBE_SECONDS
    scope = os.environ["SUPERLOOP_DOOR_SCOPE"]
    run = os.environ["SUPERLOOP_DOOR_RUN"]
    reference = os.environ["SUPERLOOP_DOOR_REF"]
    alias = os.environ["SUPERLOOP_DOOR_ALIAS"]
    mirror = os.environ["SUPERLOOP_DOOR_MIRROR_ROOT"] + "/" + run + ".git"
    result = {"schema": 1, "scope": scope}
    try:
        if scope == "review":
            refusal = invoke("door-attribution-probe", deadline=deadline)
            result["review_reason"] = (final_from_stderr(refusal.stderr) or {}).get("reason")
            print(json.dumps(result, sort_keys=True))
            return
        data = bytes(range(251)) * 4200
        echo = invoke("door-attribution-probe", deadline=deadline, data=data)
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
            # The receive may await adjudication beyond this observation. Its
            # smaller cap still consumes the same whole-probe budget.
            changed = invoke(alias, f"git-receive-pack '{mirror}'", deadline=deadline, data=packet, timeout=15)
            result["changed_ref_reason"] = (
                changed.stderr.decode(errors="replace").strip().splitlines() or [None]
            )[-1]
        except subprocess.TimeoutExpired:
            result["changed_ref_reason"] = None
            result["changed_ref_waiting"] = True
        result["changed_ref_bytes"] = len(packet)
        authority = invoke("unregistered", "git-upload-pack 'other'", deadline=deadline)
        result["authority_reason"] = authority.stderr.decode(errors="replace").strip()
        status = invoke("door-attribution-status", deadline=deadline)
        result["status_exit"] = status.returncode
        result["status_reply"] = final_from_stderr(status.stderr)
        expired = invoke("door-attribution-deadline", deadline=deadline)
        result["deadline_reason"] = (final_from_stderr(expired.stderr) or {}).get("reason")
        raw_request({
            "schema": 2, "argv": [list(b"door-attribution-probe")],
            "deadline_ms": 1000,
        }, deadline=deadline, disconnect=True)
        followup = invoke("door-attribution-status", deadline=deadline)
        result["disconnect_reason"] = (final_from_stderr(followup.stderr) or {}).get("reason")
        result["disconnect_followup"] = followup.returncode == 1
    except (subprocess.TimeoutExpired, TimeoutError):
        result["error"] = TIMEOUT_REASON
    except (OSError, ValueError, RuntimeError) as error:
        result["error"] = str(error)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
