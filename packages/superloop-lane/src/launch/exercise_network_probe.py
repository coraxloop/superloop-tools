"""Measure the recorded box's direct routes and vendor and door sockets."""

import errno
import json
import os
import socket
import subprocess
import time


def direct(address):
    try:
        with socket.create_connection((address, 443), timeout=0.5):
            return {"connected": True, "error": None}
    except OSError as error:
        return {"connected": False, "error": errno.errorcode.get(error.errno, error.__class__.__name__)}


def proxy_request(host, socket_path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(socket_path)
        peer.sendall(("CONNECT " + host + ":443 HTTP/1.1\r\n\r\n").encode("ascii"))
        return peer.recv(128).decode("ascii", errors="replace").split("\r\n", 1)[0]


def review_refusal():
    started = time.monotonic()
    while True:
        result = subprocess.run(
            ["/home/worker/.local/libexec/superloop/ssh", "door-attribution-probe"],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=max(0.001, 10 - (time.monotonic() - started)), check=False,
        )
        reason = None
        for line in reversed(result.stderr.splitlines()):
            try:
                frame = json.loads(line)
            except ValueError:
                continue
            if isinstance(frame, dict) and frame.get("type") == "final":
                reason = frame.get("reason")
                break
        if result.stderr.startswith(b"door-request-concurrent"):
            reason = "door-request-concurrent"
        if reason != "door-request-concurrent" or time.monotonic() - started >= 2:
            return {"status": result.returncode, "reason": reason}
        time.sleep(0.05)


def main():
    vendor_socket = os.environ.get(
        "SUPERLOOP_VENDOR_SOCKET", "/home/worker/.local/vendor/proxy.sock"
    )
    new_host = os.environ["SUPERLOOP_NETWORK_NEW_HOST"]
    result = {"schema": 1, "direct_ip": direct("1.1.1.1"),
              "direct_dns": direct("example.com"), "proxy": {},
              "review": None}
    for name, host in (("other_name", "blocked.example.invalid"),
                       ("new_host", new_host), ("ip_literal", "1.1.1.1")):
        try:
            result["proxy"][name] = proxy_request(host, vendor_socket)
        except OSError as error:
            result["proxy"][name] = "error:" + str(error)
    if os.environ.get("SUPERLOOP_DOOR_SCOPE") == "review":
        try:
            result["review"] = review_refusal()
        except (OSError, subprocess.TimeoutExpired) as error:
            result["review"] = {"error": str(error)}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
