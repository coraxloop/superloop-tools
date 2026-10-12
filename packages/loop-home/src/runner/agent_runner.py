"""Tool-free Codex call, entered as the registered loop, never as its worker."""

import ctypes
import errno
import json
import hashlib
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import stat

RESULT = None
EVIDENCE = {}
STDERR_TAIL_BYTES = 4096
STDERR_FIRST_LINE_BYTES = 1024


class StderrTail:
    def __init__(self):
        self.data = bytearray()
        self.total = 0
        self.first = bytearray()
        self.first_done = False

    def append(self, chunk):
        if not self.first_done:
            line = chunk.split(b'\n', 1)[0]
            self.first.extend(line[:STDERR_FIRST_LINE_BYTES - len(self.first)])
            self.first_done = b'\n' in chunk or len(self.first) == STDERR_FIRST_LINE_BYTES
        self.total += len(chunk)
        self.data.extend(chunk)
        del self.data[:-STDERR_TAIL_BYTES]

    def first_line(self):
        text = self.first.decode('utf-8', 'replace').split('\r', 1)[0]
        return text.encode('utf-8')[:STDERR_FIRST_LINE_BYTES].decode('utf-8', 'ignore')

    def text(self):
        offset = 0
        while True:
            dropped = self.total - len(self.data) + offset
            if dropped and offset < len(self.data) and self.data[offset] & 0xc0 == 0x80:
                offset += 1
                continue
            text = self.data[offset:].decode('utf-8', 'replace')
            marker = f'[stderr cut: {dropped} bytes dropped]\n' if dropped else ''
            if len((marker + text).encode('utf-8')) <= STDERR_TAIL_BYTES:
                return marker + text
            offset += 1


class Cancelled(Exception):
    pass


def cancel(_signum, _frame):
    raise Cancelled()


def emit(value):
    global RESULT
    RESULT = value


def main():
    signal.signal(signal.SIGTERM, cancel)
    parent = os.getppid()
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        emit({"service_status": "failure", "reason": "door-agent-parent-watch"})
        return
    if os.getppid() != parent:
        raise Cancelled()
    started = time.monotonic()
    program, model, effort, budget, rubric_path, deadline, loop_name = sys.argv[1:]
    remaining = min(int(budget) / 1000, float(deadline) - time.time())
    end = started + remaining - 2.0
    if remaining <= 2.0:
        emit({"service_status": "timeout", "reason": "door-agent-no-budget"})
        return
    prompt = sys.stdin.buffer.read(262145)
    if len(prompt) > 262144:
        emit({"service_status": "failure", "reason": "door-agent-input-limit"})
        return
    document = json.loads(prompt)
    try:
        if rubric_path == "snapshot-input":
            # The direct adapter has pinned the owner snapshot and checked this
            # source digest. This argv-selected transport never reads request text.
            text = document["reviewed_rubric"]
            if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 65536:
                raise RubricFailure("snapshot-input", rubric_path)
            rubric_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        else:
            text, rubric_digest = read_rubric(rubric_path)
    except RubricFailure as error:
        EVIDENCE["rubric_failure"] = error.evidence
        emit({"service_status": "failure", "reason": "door-rubric-unavailable"})
        return
    EVIDENCE["rubric_path"] = rubric_path
    EVIDENCE["rubric_digest"] = rubric_digest
    document["reviewed_rubric"] = text
    prompt = json.dumps(document).encode("utf-8")
    # superloop enter supplies HOME after selecting the registered private home and
    # changing UID. Never consult the host's or a worker's authentication path.
    home = os.environ["HOME"]
    auth = os.path.join(home, ".codex", "auth.json")
    EVIDENCE["sign_in_source"] = auth
    EVIDENCE["loop_uid"] = os.getuid()
    EVIDENCE["sign_in_absent"] = False
    try:
        auth_directory = os.lstat(os.path.join(home, ".codex"))
        if (not stat.S_ISDIR(auth_directory.st_mode)
                or auth_directory.st_uid != os.getuid()
                or auth_directory.st_mode & 0o022):
            raise ValueError("unsafe sign-in directory")
        auth_file = os.lstat(auth)
        own_sign_in = sign_in_usable(auth_file, auth_directory, os.geteuid())
    except FileNotFoundError:
        EVIDENCE["sign_in_absent"] = True
        own_sign_in = False
    except (OSError, ValueError):
        own_sign_in = False
    if not own_sign_in:
        emit({"service_status": "failure", "reason": "door-agent-sign-in-unavailable", "remedy": "superloop-lane door-sign-in " + loop_name, "rubric_digest": rubric_digest})
        return
    root = os.path.join(os.environ["TMPDIR"], "door-agent")
    call = None
    auth_link = None
    process = None
    stage = "setup"
    stderr_tail = StderrTail()
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        metadata = os.lstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o777 != 0o700:
            emit({"service_status": "failure", "reason": "door-agent-temporary-root"})
            return
        call = tempfile.mkdtemp(prefix="call-", dir=root)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        cwd = os.path.join(call, "cwd")
        config = os.path.join(call, "config")
        os.mkdir(cwd, 0o700)
        os.mkdir(config, 0o700)
        EVIDENCE["working_directory_empty"] = os.listdir(cwd) == []
        EVIDENCE["working_directory_mode"] = os.stat(cwd).st_mode & 0o777
        # Authentication stays in loop custody. No credential byte is copied,
        # interpreted, emitted, or included in the request/response record.
        os.symlink(auth, os.path.join(config, "auth.json"))
        auth_link = os.lstat(os.path.join(config, "auth.json"))
        with open(os.path.join(config, "config.toml"), "x", encoding="utf-8") as file:
            file.write('approval_policy = "never"\nsandbox_mode = "read-only"\n'
                       'web_search = "disabled"\nmodel_provider = "vendor-proxy"\n'
                       'cli_auth_credentials_store = "file"\n'
                       '[model_providers.vendor-proxy]\nname = "vendor-proxy"\n'
                       'requires_openai_auth = true\nwire_api = "responses"\n'
                       'request_max_retries = 0\nstream_max_retries = 0\n')
        argv = [program, "exec", "--json", "--skip-git-repo-check", "-C", cwd,
                "-s", "read-only", "-m", model, "-c", "sandbox_permissions=[]",
                "-c", "project_doc_max_bytes=0", "-c", "model_reasoning_effort=" + effort]
        for feature in ["shell_tool", "unified_exec", "code_mode_host", "multi_agent",
                        "apps", "plugins", "browser_use", "browser_use_external",
                        "computer_use", "image_generation", "view_image", "skill_search",
                        "skill_mcp_dependency_install", "tool_suggest"]:
            argv.extend(["--disable", feature])
        argv.extend(["-c", "mcp_servers={}", "-"])
        EVIDENCE["sandbox"] = "read-only"
        EVIDENCE["execution_tools"] = False
        EVIDENCE["agent_calls"] = 1
        EVIDENCE["available_wall_ms"] = int(remaining * 1000)
        EVIDENCE["cleanup_reserve_ms"] = 2000
        environment = {"HOME": call, "CODEX_HOME": config, "TMPDIR": call,
                       "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        # Adopt orphaned descendants so cleanup observes their termination.
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise OSError("subreaper unavailable")
        stage = "spawn"
        process = subprocess.Popen(argv, cwd=cwd, env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        stage = "running"
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        output = bytearray()
        offset = 0
        status = None
        while selector.get_map():
            if time.monotonic() >= end:
                status = "timeout"
                break
            for key, _ in selector.select(min(0.02, max(0, end - time.monotonic()))):
                if key.fileobj is process.stdin:
                    try:
                        offset += os.write(key.fd, prompt[offset:])
                    except BrokenPipeError:
                        offset = len(prompt)
                    if offset == len(prompt):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    chunk = os.read(key.fd, 8192)
                    if key.fileobj is process.stderr:
                        stderr_tail.append(chunk)
                    else:
                        output.extend(chunk)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    if len(output) > 65536:
                        status = "invalid-output"
                        break
            if status:
                break
        selector.close()
        wait_remaining = max(0, end - time.monotonic())
        if status is None:
            try:
                if process.wait(timeout=wait_remaining) != 0:
                    status = "failure"
            except subprocess.TimeoutExpired:
                status = "timeout"
        if status:
            emit({"service_status": status, "reason": "door-agent-" + status, "rubric_digest": rubric_digest})
        else:
            messages = []
            observed_model = None
            for line in output.splitlines():
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event object required")
                # A CLI selection/header is not a measurement. Most CLI
                # versions expose no response model at all: retain null then.
                if event.get("type") == "response.completed":
                    response = event.get("response")
                    if not isinstance(response, dict):
                        raise ValueError("response metadata object required")
                    reported = response.get("model")
                    if reported is not None:
                        if not isinstance(reported, str) or not reported.strip() or len(reported.encode("utf-8")) > 256:
                            raise ValueError("invalid response model identifier")
                        if observed_model is not None and observed_model != reported:
                            raise ValueError("conflicting response model identifiers")
                        observed_model = reported
                item = event.get("item", {})
                if not isinstance(item, dict):
                    raise ValueError("item object required")
                if event.get("type") == "item.completed" and item.get("type") == "agent_message":
                    messages.append(item.get("text"))
                if item and item.get("type") not in ("agent_message", "reasoning"):
                    raise ValueError("unexpected tool event")
            if len(messages) != 1 or not isinstance(messages[0], str):
                raise ValueError("one final message required")
            emit({"text": messages[0], "model": observed_model, "rubric_digest": rubric_digest})
    except Cancelled:
        emit({"service_status": "timeout", "reason": "door-agent-cancelled", "rubric_digest": rubric_digest})
    except (ValueError, KeyError):
        emit({"service_status": "invalid-output", "reason": "door-agent-invalid-output", "rubric_digest": rubric_digest})
    except OSError as error:
        EVIDENCE["runner_stage"] = stage
        EVIDENCE["runner_errno"] = ("MISSING_ERRNO" if error.errno is None
                                    else errno.errorcode.get(error.errno, "UNRECOGNIZED_ERRNO"))
        emit({"service_status": "failure", "reason": "door-agent-runner-failure", "rubric_digest": rubric_digest})
        if process is None:
            RESULT["agent_runner_stderr_tail"] = "runner " + stage + ": " + EVIDENCE["runner_errno"]
            RESULT["agent_runner_first_line"] = RESULT["agent_runner_stderr_tail"]
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            cleanup_end = started + remaining - 0.25
            while time.monotonic() < cleanup_end:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if pid == 0:
                        with open(f"/proc/self/task/{os.getpid()}/children", encoding="ascii") as children:
                            for word in children.read().split():
                                try:
                                    os.kill(int(word), signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                        time.sleep(0.005)
                except ChildProcessError:
                    EVIDENCE["children_reaped"] = True
                    break
            else:
                emit({"service_status": "failure", "reason": "door-agent-unreaped", "rubric_digest": rubric_digest})
        if call is not None:
            if auth_link is not None:
                try:
                    after = os.lstat(os.path.join(call, "config", "auth.json"))
                    intact = (stat.S_ISLNK(after.st_mode)
                              and (after.st_dev, after.st_ino) == (auth_link.st_dev, auth_link.st_ino)
                              and os.readlink(os.path.join(call, "config", "auth.json")) == auth)
                except OSError:
                    intact = False
                EVIDENCE["sign_in_link_preserved"] = intact
                if not intact:
                    emit({"service_status": "failure", "reason": "door-agent-sign-in-link-replaced", "rubric_digest": rubric_digest})
            shutil.rmtree(call)
            EVIDENCE["private_directory_removed"] = not os.path.exists(call)
        if process is not None:
            # Never wait for an escaped descendant retaining the pipe.
            while time.monotonic() < cleanup_end:
                try:
                    chunk = os.read(process.stderr.fileno(), 8192)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                stderr_tail.append(chunk)
            else:
                stderr_tail.append(b'\n[stderr end cut: cleanup deadline]\n')
            code = process.returncode
            RESULT["agent_runner_exit"] = (
                None if code is None else {"code": code} if code >= 0 else {"signal": -code})
            if RESULT.get("service_status") is not None:
                RESULT["agent_runner_stderr_tail"] = stderr_tail.text()
                RESULT["agent_runner_first_line"] = stderr_tail.first_line()


if __name__ == "__main__":
    try:
        main()
    except Cancelled:
        emit({"service_status": "timeout", "reason": "door-agent-cancelled-before-start"})
    RESULT["runner_evidence"] = EVIDENCE
    RESULT.setdefault("agent_runner_exit", None)
    RESULT.setdefault("agent_runner_first_line", "")
    print(json.dumps(RESULT), flush=True)
