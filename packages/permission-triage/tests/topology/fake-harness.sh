#!/bin/sh
set -eu

mode=${FAKE_HARNESS_MODE:?}

if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
    case "$mode" in
        wrong-version) printf '%s\n' '9.9.9' ;;
        suffix-version) printf '%s\n' '2.1.258-rc' ;;
        *) printf '%s\n' '2.1.258' ;;
    esac
    exit 0
fi

case "$mode" in
    audit-decision-leaks|audit-stray-stdout|audit-structured-decision|baseline-missing-registration|baseline-wrong-registration|bypass-changed-command|bypass-ignores-deny|bypass-malformed-result|bypass-missing-capture|bypass-missing-journal|bypass-missing-model-capture|bypass-mixed|bypass-never-called|bypass-second-gate|bypass-settings-deny-loses|bypass-tool-failure|infra-crash-executes|infra-exit-two-executes|infra-hook-timeout-executes|infra-instance-executes|infra-journal-executes|infra-model-executes|missing-decider-registration|missing-observer-registration|mixed|payload-mode-mismatch|real-hook-deny-prompt-prose|real-hook-deny-tool-failure|real-hook-tool-failure|stale-captures|suffix-version|table-negative-tool-failure|table-negative-tool-failure-no-capture|topology-auto-executed|topology-auto-refused|topology-both-observations|topology-ceiling|topology-changed-command|topology-changed-denial|topology-is-error|topology-malformed-output|topology-multiple-denials|topology-multiple-documents|topology-never-called|topology-nonzero|topology-prompt|wrong-version) ;;
    *) exit 18 ;;
esac
exec python3 - "$@" <<'PYHARNESS'
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

arguments = sys.argv[1:]
assert len(arguments) == 13
assert arguments[:7] == ["--print", "--no-session-persistence", "--output-format", "json", "--setting-sources", "project", "--settings"]
assert arguments[8] == "--tools" and arguments[10] == "--permission-mode"
settings_path = Path(arguments[7])
tool, permission_mode, instruction = arguments[9], arguments[11], arguments[12]
root = Path(os.environ["PERMISSION_TRIAGE_FIXTURE_ROOT"])
state = Path(os.environ["PERMISSION_TRIAGE_STATE_ROOT"])
assert settings_path == root / "settings.json" and state == root / "state"
mode = os.environ["FAKE_HARNESS_MODE"]
phase = os.environ["PERMISSION_TRIAGE_TOPOLOGY_PHASE"]
trial_id = os.environ["PERMISSION_TRIAGE_TOPOLOGY_TRIAL_ID"]
command = os.environ.get("PERMISSION_TRIAGE_TOPOLOGY_EXPECTED_COMMAND", "")
os.environ["FAKE_ARGV_PERMISSION_MODE"] = permission_mode
os.environ["FAKE_ARGV_TOOL"] = tool

def audit_phase():
    import json
    import os
    from pathlib import Path
    import subprocess
    import time
    import runpy

    root = Path(os.environ["PERMISSION_TRIAGE_FIXTURE_ROOT"])
    state = root / "state"
    mode = os.environ["FAKE_HARNESS_MODE"]
    phase = os.environ["PERMISSION_TRIAGE_TOPOLOGY_PHASE"]
    fault = os.environ.get("PERMISSION_TRIAGE_TOPOLOGY_FAULT", "")
    trial_id = os.environ["PERMISSION_TRIAGE_TOPOLOGY_TRIAL_ID"]
    command = os.environ["PERMISSION_TRIAGE_TOPOLOGY_EXPECTED_COMMAND"]
    payload = json.loads(os.environ["PERMISSION_TRIAGE_TOPOLOGY_HOOK_INPUT"])
    if mode == "payload-mode-mismatch" and phase == "bypass":
        payload["permission_mode"] = "manual"
    if payload["permission_mode"] != os.environ["FAKE_ARGV_PERMISSION_MODE"]:
        raise SystemExit("permission mode argv/payload mismatch")
    settings = json.loads((root / "settings.json").read_text())
    rule = "Bash(" + command + ")"
    permissions = settings["permissions"]
    dispatch = runpy.run_path(str(root / "bin/audit-hook"))["dispatch"]

    # Fault twins alter the actual registration consumed by dispatch.
    if "baseline-" in trial_id and mode in {"baseline-missing-registration", "baseline-wrong-registration"}:
        if mode == "baseline-missing-registration":
            settings["hooks"]["PreToolUse"] = []
        else:
            for registration in settings["hooks"]["PreToolUse"]:
                for hook in registration["hooks"]:
                    hook["command"] = hook["command"].replace(" audit", " allow")
        (root / "settings.json").write_text(json.dumps(settings))
    if phase in {"audit", "bypass"} and mode in {"missing-observer-registration", "missing-decider-registration"}:
        missing = "audit-hook" if mode == "missing-observer-registration" else "real-hook-driver"
        for registration in settings["hooks"]["PreToolUse"]:
            registration["hooks"] = [hook for hook in registration["hooks"] if missing not in hook["command"]]
        (root / "settings.json").write_text(json.dumps(settings))

    def event(name, text=command):
        event_payload = dict(payload, hook_event_name=name)
        event_payload["tool_input"] = dict(payload["tool_input"], command=text)
        status, stdout, stderr = dispatch(event_payload)
        return subprocess.CompletedProcess(["registered-hooks", name], status, stdout, stderr)

    def result(denied=False):
        denials = [{"tool_name": "Bash", "tool_use_id": trial_id, "tool_input": {"command": command}}] if denied else []
        print(json.dumps({"permission_denials": denials, "result": "fixture refusal" if denied else "fixture result", "is_error": False, "num_turns": 2 if denied else 1}))

    if mode in {"topology-ceiling"}:
        time.sleep(60)
    if mode in {"bypass-never-called", "topology-never-called"}:
        result()
        raise SystemExit(0)
    completed = event("PreToolUse", "triage-sentinel TRIAGE_CHANGED_SENTINEL" if mode in {"bypass-changed-command", "topology-changed-command"} else command)
    if mode == "topology-prompt":
        event("PermissionRequest")
    response = completed.stdout
    leak = phase == "audit" and mode == "audit-decision-leaks" and "audit-allow-agent-error" in trial_id
    if phase == "audit" and (mode in {"audit-stray-stdout", "audit-structured-decision"} or leak):
        response = b"\n" if mode == "audit-stray-stdout" else b'{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"injected audit decision"}}'
        (state / "hook-output.json").write_bytes(response)
    try:
        decision = json.loads(response)["hookSpecificOutput"]["permissionDecision"]
    except (ValueError, KeyError):
        decision = None
    allow = completed.returncode == 0 and decision != "deny"
    if payload["permission_mode"] != "bypassPermissions":
        allow = rule in permissions.get("allow", [])
    if leak and decision == "deny":
        allow = False
    if rule in permissions.get("deny", []):
        allow = False
    if phase == "bypass" and mode == "bypass-ignores-deny":
        allow = True
    if phase == "bypass" and mode == "bypass-second-gate":
        allow = False
    if phase == "settings_deny_wins" and mode == "bypass-settings-deny-loses":
        allow = True
    fault_targets = {"infra-model-executes": "model-timeout", "infra-instance-executes": "missing-mode", "infra-journal-executes": "journal-failure", "infra-crash-executes": "hook-crash", "infra-exit-two-executes": "exit-two", "infra-hook-timeout-executes": "hook-timeout"}
    if phase == "infrastructure" and fault_targets.get(mode) == fault:
        allow = True
    if phase == "bypass" and mode in {"bypass-mixed", "mixed"} and trial_id.endswith("-2"):
        allow = not allow
    if phase == "bypass" and mode == "bypass-missing-capture":
        (state / "hook-invocation.json").unlink(missing_ok=True)
    if phase == "bypass" and mode == "bypass-missing-model-capture":
        Path(os.environ["PERMISSION_TRIAGE_FAKE_CAPTURE"] + ".argv").unlink(missing_ok=True)
    if phase == "bypass" and mode == "bypass-missing-journal":
        metadata = json.loads((state / "hook-invocation.json").read_text())
        metadata["journal_events"] = []
        (state / "hook-invocation.json").write_text(json.dumps(metadata))
    if mode in {"bypass-tool-failure"}:
        event("PostToolUseFailure")
        result()
    elif mode in {"bypass-malformed-result", "topology-malformed-output", "topology-multiple-documents"}:
        print("malformed result")
    elif mode == "topology-nonzero":
        result()
        raise SystemExit(17)
    elif mode == "topology-is-error":
        print(json.dumps({"permission_denials": [], "result": "fixture error", "is_error": True, "num_turns": 1}))
    elif allow:
        subprocess.run([str(root / "bin/triage-sentinel"), "TRIAGE_AUTO_SENTINEL"], check=True)
        event("PostToolUse")
        result(mode == "topology-both-observations")
    else:
        event("PermissionDenied")
        result(True)

if phase in {"audit", "bypass", "infrastructure", "settings_deny_wins"}:
    audit_phase()
    raise SystemExit(0)

# One interpreter and dispatch module serve all event trials within this invocation.
# Deciding hooks retain subprocess exits and streams; the exact stateless observer
# registration records its event in process, while changed registrations execute normally.
dispatch = runpy.run_path(str(root / "bin/audit-hook"))["dispatch"]

def event(name, text=command):
    payload = json.loads(os.environ.get("PERMISSION_TRIAGE_TOPOLOGY_HOOK_INPUT", "{}"))
    if payload and payload.get("permission_mode") != permission_mode:
        raise SystemExit("permission mode argv/payload mismatch")
    payload.update(hook_event_name=name, tool_use_id=trial_id, tool_name=tool)
    payload["tool_input"] = dict(payload.get("tool_input", {}), command=text)
    restore = None
    if phase == "table-confirmation" and (mode == "stale-captures" or (mode == "table-negative-tool-failure-no-capture" and "native-get-web-fetch-negative" in trial_id)):
        restore = settings_path.read_bytes()
    try:
        if restore is not None:
            settings = json.loads(restore)
            for registration in settings["hooks"]["PreToolUse"]:
                registration["hooks"] = [hook for hook in registration["hooks"] if "real-hook-driver" not in hook["command"]]
            settings_path.write_text(json.dumps(settings))
        status, _stdout, stderr = dispatch(payload)
    finally:
        if restore is not None:
            settings_path.write_bytes(restore)
    sys.stderr.buffer.write(stderr)
    if status:
        raise SystemExit(status)

def result(denied=False, error=False, twice=False, prose=False):
    denial = {"tool_name": "Bash", "tool_use_id": trial_id, "tool_input": {"command": command}}
    if twice:
        del denial["tool_use_id"]
    denials = [denial, denial] if twice else [denial] if denied else []
    text = "fixture refusal" if denied else "fixture error" if error else "fixture result"
    if prose:
        print("Permission required: fixture diagnostic", file=sys.stderr)
        text = "The command was blocked, so it never ran. If you want it to run, you can approve the permission prompt and I will take it from there."
    print(json.dumps({"permission_denials": denials, "result": text, "is_error": error, "num_turns": 2 if denied else 1}))

def sentinel():
    subprocess.run(["triage-sentinel", "TRIAGE_AUTO_SENTINEL"], check=True)

def execute():
    subprocess.run(["sh", "-c", command], stdout=subprocess.DEVNULL, check=True)

if phase == "topology":
    assert tool == "Bash"
    assert instruction == "Use Bash exactly once with the exact command: triage-sentinel TRIAGE_AUTO_SENTINEL"
    if mode == "topology-ceiling":
        time.sleep(60)
    elif mode == "topology-never-called":
        result()
    elif mode == "topology-changed-command":
        event("PreToolUse", "triage-sentinel TRIAGE_CHANGED_SENTINEL")
        result()
    else:
        event("PreToolUse")
        if mode == "topology-is-error":
            result(error=True)
        elif mode == "topology-nonzero":
            result()
            raise SystemExit(17)
        elif mode == "topology-prompt":
            event("PermissionRequest")
            result()
        elif mode == "topology-changed-denial":
            command = "triage-sentinel TRIAGE_CHANGED_SENTINEL"
            result(denied=True)
        elif mode == "topology-multiple-denials":
            result(denied=True, twice=True)
        elif mode == "topology-malformed-output":
            print("not a result document")
        elif mode == "topology-multiple-documents":
            result()
            result()
        elif mode == "topology-both-observations":
            sentinel()
            event("PostToolUse")
            result(denied=True)
        else:
            assert permission_mode in {"manual", "auto"}
            denied = permission_mode == "auto" and mode == "topology-auto-refused"
            if permission_mode == "auto" and mode == "mixed":
                counter = state / "mixed-count"
                count = int(counter.read_text()) + 1 if counter.exists() else 1
                counter.write_text(str(count) + "\n")
                denied = count % 2 == 0
            if not denied:
                sentinel()
                event("PostToolUse")
                if mode == "stale-captures" and trial_id == "topology-topology-acceptance-3":
                    for polarity in ["positive", "negative"]:
                        (state / f"captures/table-confirmation-native-read-{polarity}-1.argv").write_text("stale\n")
            result(denied=denied)
elif phase == "table-confirmation":
    event("PreToolUse")
    if mode == "stale-captures":
        entry = os.environ["PERMISSION_TRIAGE_TOPOLOGY_TABLE_ENTRY"]
        (state / "hook-output.json").write_text(json.dumps({"hookSpecificOutput": {"permissionDecision": "allow", "permissionDecisionReason": "safe: harness read-only rule " + entry}}, separators=(",", ":")) + "\n")
        if tool == "Bash":
            execute()
        event("PostToolUse")
        result()
    elif mode in {"table-negative-tool-failure", "table-negative-tool-failure-no-capture"} and trial_id.startswith("table-confirmation-native-get-web-fetch-negative-"):
        event("PostToolUseFailure")
        result()
    elif '"permissionDecision":"allow"' in (state / "hook-output.json").read_text():
        if tool == "Bash":
            execute()
        event("PostToolUse")
        result()
    else:
        event("PermissionDenied")
        result(denied=True)
elif phase == "real-hook":
    assert tool == "Bash"
    settings = json.loads(settings_path.read_text())
    preexisting = command == "negative-twin TRIAGE_NEGATIVE_SENTINEL" and "Bash(" + command + ")" in settings["permissions"].get("deny", [])
    event("PreToolUse")
    if preexisting:
        if mode == "real-hook-tool-failure":
            event("PostToolUseFailure")
            result()
        else:
            result(denied=True, prose=mode == "real-hook-deny-prompt-prose")
    elif mode == "real-hook-deny-tool-failure" and command == "printf agent-error":
        event("PostToolUseFailure")
        result()
    elif '"permissionDecision":"allow"' in (state / "hook-output.json").read_text():
        if mode == "real-hook-tool-failure" and command == "printf routine-general":
            event("PostToolUseFailure")
        else:
            execute()
            event("PostToolUse")
        result()
    else:
        event("PermissionDenied")
        result(denied=True)
else:
    raise SystemExit(19)
PYHARNESS
