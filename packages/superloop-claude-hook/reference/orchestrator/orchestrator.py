#!/usr/bin/env python3
"""Inject top-level orchestration rules into main Claude Code sessions."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

ALLOWED_EVENTS = {"SessionStart", "UserPromptSubmit"}
FRESH_SESSION_SOURCES = {"startup", "clear", "compact"}
RESUME_SESSION_SOURCES = {"resume", "fork"}
MAX_RULEBOOK_BYTES = 9500
TRANSCRIPT_TAIL_BYTES = 1024 * 1024
SLOW_RUN_NS = 250_000_000
SESSIONSTART_GRACE_SECONDS = 5.0

DEFAULT_ORCHESTRATION_FILE = "~/.local/share/orchestration/ORCHESTRATION.md"
DEFAULT_STATE_DIR = "~/.local/state/superloop-tools/hook"
MARKER_PREFIX = "ORCHESTRATION_SCOPE_MARKER v1 sha256="


def configured_path(env_name: str, default: str) -> Path:
    return Path(os.path.expanduser(os.environ.get(env_name, default)))


def state_dir() -> Path:
    return configured_path("ORCHESTRATOR_STATE_DIR", DEFAULT_STATE_DIR)


def rulebook_path() -> Path:
    return configured_path("ORCHESTRATION_FILE", DEFAULT_ORCHESTRATION_FILE)


def folded_cwd(cwd: str) -> str:
    return cwd.replace("/", "-")


def safe_session_id(value: Any) -> str:
    raw = value if isinstance(value, str) and value else "unknown"
    return raw.replace("/", "-").replace("\0", "-")


def elapsed_ms(start_ns: int) -> float:
    return (time.monotonic_ns() - start_ns) / 1_000_000


def log_record(directory: Path, record: dict[str, Any]) -> None:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        line = {"ts": int(time.time()), **record}
        with (directory / "orchestrator.log").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n")
    except OSError:
        pass


def output_json(event: str, text: str) -> str:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": text,
        }
    }
    return json.dumps(payload, separators=(",", ":"))


def disabled(directory: Path, cwd: str) -> bool:
    if (directory / "orchestrator-disabled-GLOBAL").exists():
        return True
    return (directory / ("orchestrator-disabled" + folded_cwd(cwd))).exists()


def subagent_payload(payload: dict[str, Any]) -> bool:
    # Truthy check: a real subagent always carries a non-empty id, and a
    # main-session payload with agent_id null must not lose injection.
    transcript = payload.get("transcript_path")
    return bool(payload.get("agent_id")) or (
        isinstance(transcript, str) and "/subagents/" in transcript
    )


def rulebook_stat(path: Path, directory: Path, start_ns: int, event: str, session: str) -> os.stat_result | None:
    try:
        stat_result = path.stat()
    except FileNotFoundError:
        log_record(
            directory,
            {
                "action": "guard4_refusal",
                "reason": "rulebook_missing",
                "event": event,
                "session_id": session,
                "path": str(path),
                "elapsed_ms": round(elapsed_ms(start_ns), 3),
            },
        )
        return None
    except OSError as exc:
        log_record(
            directory,
            {
                "action": "guard4_refusal",
                "reason": "rulebook_unreadable",
                "error": type(exc).__name__,
                "event": event,
                "session_id": session,
                "path": str(path),
                "elapsed_ms": round(elapsed_ms(start_ns), 3),
            },
        )
        return None
    if stat_result.st_size > MAX_RULEBOOK_BYTES:
        log_record(
            directory,
            {
                "action": "guard4_refusal",
                "reason": "rulebook_oversized",
                "event": event,
                "session_id": session,
                "path": str(path),
                "size": stat_result.st_size,
                "limit": MAX_RULEBOOK_BYTES,
                "elapsed_ms": round(elapsed_ms(start_ns), 3),
            },
        )
        return None
    return stat_result


def read_rulebook(path: Path, directory: Path, start_ns: int, event: str, session: str) -> tuple[bytes, str, str] | None:
    try:
        data = path.read_bytes()
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        log_record(
            directory,
            {
                "action": "guard4_refusal",
                "reason": "rulebook_unreadable",
                "error": type(exc).__name__,
                "event": event,
                "session_id": session,
                "path": str(path),
                "elapsed_ms": round(elapsed_ms(start_ns), 3),
            },
        )
        return None
    if len(data) > MAX_RULEBOOK_BYTES:
        log_record(
            directory,
            {
                "action": "guard4_refusal",
                "reason": "rulebook_oversized",
                "event": event,
                "session_id": session,
                "path": str(path),
                "size": len(data),
                "limit": MAX_RULEBOOK_BYTES,
                "elapsed_ms": round(elapsed_ms(start_ns), 3),
            },
        )
        return None
    return data, text, hashlib.sha256(data).hexdigest()


def state_path(directory: Path, session_key: str) -> Path:
    return directory / ("orchestrator-scope-" + session_key + ".json")


def snapshot_path(directory: Path, session_key: str, name: str) -> Path:
    return directory / ("orchestration-snapshot-" + session_key + "-" + name + ".md")


def load_state(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def write_state(path: Path, state: dict[str, Any]) -> None:
    # Atomic: a crash mid-write must not leave a corrupt state file.
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, sort_keys=True, separators=(",", ":"))
        fh.write("\n")
    os.replace(tmp, path)


def write_snapshot(path: Path, data: bytes) -> None:
    # Atomic: a torn snapshot would poison a future change-notice diff.
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def rotate_snapshot(directory: Path, session_key: str) -> None:
    current = snapshot_path(directory, session_key, "current")
    previous = snapshot_path(directory, session_key, "prev")
    if current.exists():
        os.replace(current, previous)


def stamped_mtime(stat_result: os.stat_result) -> int:
    return int(stat_result.st_mtime_ns)


def marker_text(digest: str, mtime: int, rulebook: str) -> str:
    start = f"{MARKER_PREFIX}{digest} mtime={mtime}"
    end = f"ORCHESTRATION_SCOPE_MARKER_END v1 sha256={digest}"
    separator = "" if rulebook.endswith("\n") else "\n"
    return f"{start}\n{rulebook}{separator}{end}"


def transcript_has_current_marker(transcript_path: Any, digest: str) -> bool:
    if not isinstance(transcript_path, str) or not transcript_path:
        return False
    marker = (MARKER_PREFIX + digest).encode("utf-8")
    try:
        with Path(os.path.expanduser(transcript_path)).open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - TRANSCRIPT_TAIL_BYTES))
            return marker in fh.read(TRANSCRIPT_TAIL_BYTES)
    except OSError:
        return False


def prompt_ids(state: dict[str, Any]) -> list[str]:
    raw = state.get("emitted_prompt_ids")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, str)]


def prompt_already_emitted(state: dict[str, Any], prompt_id: Any) -> bool:
    return isinstance(prompt_id, str) and prompt_id in prompt_ids(state)


def record_prompt_id(state: dict[str, Any], prompt_id: Any) -> None:
    if not isinstance(prompt_id, str) or not prompt_id:
        return
    seen = [item for item in prompt_ids(state) if item != prompt_id]
    seen.append(prompt_id)
    state["emitted_prompt_ids"] = seen[-64:]
    state["last_prompt_id"] = prompt_id


def sessionstart_key(session_id: str, source: str, digest: str) -> list[str]:
    return [session_id, source, digest]


def sessionstart_dedupe_hit(state: dict[str, Any], key: list[str], now: float) -> bool:
    raw = state.get("sessionstart_dedupe")
    if not isinstance(raw, dict) or raw.get("key") != key:
        return False
    try:
        recorded = float(raw.get("time", 0.0))
    except (TypeError, ValueError):
        return False
    return 0.0 <= now - recorded <= SESSIONSTART_GRACE_SECONDS


def update_base_state(
    state: dict[str, Any],
    session_id: str,
    cwd: str,
    digest: str,
    mtime: int,
    current_snapshot: Path,
) -> None:
    state["session_id"] = session_id
    state["cwd"] = cwd
    state["hash"] = digest
    state["mtime"] = mtime
    state["snapshot_current"] = str(current_snapshot)
    state["updated_at"] = time.time()


def emit_full_injection(
    payload: dict[str, Any],
    state: dict[str, Any],
    state_file: Path,
    directory: Path,
    session_id: str,
    session_key: str,
    digest: str,
    mtime: int,
    rulebook_bytes: bytes,
    rulebook: str,
    start_ns: int,
) -> str | None:
    event = str(payload.get("hook_event_name"))
    source = str(payload.get("source") or "")
    if event == "SessionStart":
        now = time.time()
        key = sessionstart_key(session_id, source, digest)
        if sessionstart_dedupe_hit(state, key, now):
            return None
        state["sessionstart_dedupe"] = {"key": key, "time": now}
        state["dedupe_key"] = {"event": event, "key": key}
    elif prompt_already_emitted(state, payload.get("prompt_id")):
        return None
    else:
        record_prompt_id(state, payload.get("prompt_id"))
        state["dedupe_key"] = {
            "event": event,
            "prompt_id": payload.get("prompt_id"),
        }

    current = snapshot_path(directory, session_key, "current")
    write_snapshot(current, rulebook_bytes)
    update_base_state(state, session_id, str(payload.get("cwd") or ""), digest, mtime, current)
    write_state(state_file, state)
    log_record(
        directory,
        {
            "action": "injection",
            "event": event,
            "session_id": session_id,
            "hash": digest,
            "mtime": mtime,
            "elapsed_ms": round(elapsed_ms(start_ns), 3),
        },
    )
    return output_json(event, marker_text(digest, mtime, rulebook))


def emit_change_notice(
    payload: dict[str, Any],
    state: dict[str, Any],
    state_file: Path,
    directory: Path,
    session_id: str,
    session_key: str,
    old_mtime: int,
    digest: str,
    mtime: int,
    rulebook_bytes: bytes,
    start_ns: int,
) -> str | None:
    event = str(payload.get("hook_event_name"))
    if event == "UserPromptSubmit" and prompt_already_emitted(state, payload.get("prompt_id")):
        return None
    if event == "UserPromptSubmit":
        record_prompt_id(state, payload.get("prompt_id"))
        state["dedupe_key"] = {
            "event": event,
            "prompt_id": payload.get("prompt_id"),
        }

    rotate_snapshot(directory, session_key)
    current = snapshot_path(directory, session_key, "current")
    write_snapshot(current, rulebook_bytes)
    update_base_state(state, session_id, str(payload.get("cwd") or ""), digest, mtime, current)
    previous = snapshot_path(directory, session_key, "prev")
    write_state(state_file, state)
    notice = (
        f"ORCHESTRATION.md changed (mtime {old_mtime} -> {mtime}). "
        f"Run a diff between {previous} and the live ORCHESTRATION.md file, "
        "then update your working rules accordingly."
    )
    log_record(
        directory,
        {
            "action": "change_notice",
            "event": event,
            "session_id": session_id,
            "old_mtime": old_mtime,
            "new_mtime": mtime,
            "hash": digest,
            "elapsed_ms": round(elapsed_ms(start_ns), 3),
        },
    )
    return output_json(event, notice)


def current_state_mtime(state: dict[str, Any]) -> int | None:
    try:
        return int(state.get("mtime"))
    except (TypeError, ValueError):
        return None


def refresh_present_state(
    state: dict[str, Any],
    state_file: Path,
    directory: Path,
    session_id: str,
    session_key: str,
    cwd: str,
    digest: str,
    mtime: int,
    rulebook_bytes: bytes,
) -> None:
    current = snapshot_path(directory, session_key, "current")
    write_snapshot(current, rulebook_bytes)
    update_base_state(state, session_id, cwd, digest, mtime, current)
    write_state(state_file, state)


def handle(start_ns: int) -> str | None:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None

    event = payload.get("hook_event_name")
    if event not in ALLOWED_EVENTS:
        return None

    directory = state_dir()
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else os.getcwd()
    if disabled(directory, cwd):
        return None
    if subagent_payload(payload):
        return None

    session_id = payload.get("session_id") if isinstance(payload.get("session_id"), str) else "unknown"
    session_key = safe_session_id(session_id)
    path = rulebook_path()
    stat_result = rulebook_stat(path, directory, start_ns, str(event), session_id)
    if stat_result is None:
        return None

    mtime = stamped_mtime(stat_result)
    scope_state_file = state_path(directory, session_key)
    had_state = scope_state_file.exists()
    state = load_state(scope_state_file)
    source = payload.get("source") if isinstance(payload.get("source"), str) else ""

    if event == "SessionStart" and source in FRESH_SESSION_SOURCES:
        loaded = read_rulebook(path, directory, start_ns, str(event), session_id)
        if loaded is None:
            return None
        data, text, digest = loaded
        return emit_full_injection(
            payload, state, scope_state_file, directory, session_id, session_key,
            digest, mtime, data, text, start_ns
        )

    if event == "SessionStart" and source in RESUME_SESSION_SOURCES:
        loaded = read_rulebook(path, directory, start_ns, str(event), session_id)
        if loaded is None:
            return None
        data, text, digest = loaded
        if not had_state:
            return emit_full_injection(
                payload, state, scope_state_file, directory, session_id, session_key,
                digest, mtime, data, text, start_ns
            )
        if not transcript_has_current_marker(payload.get("transcript_path"), digest):
            return emit_full_injection(
                payload, state, scope_state_file, directory, session_id, session_key,
                digest, mtime, data, text, start_ns
            )
        if state.get("hash") != digest or current_state_mtime(state) != mtime:
            refresh_present_state(
                state, scope_state_file, directory, session_id, session_key,
                cwd, digest, mtime, data
            )
        return None

    if not had_state:
        loaded = read_rulebook(path, directory, start_ns, str(event), session_id)
        if loaded is None:
            return None
        data, text, digest = loaded
        return emit_full_injection(
            payload, state, scope_state_file, directory, session_id, session_key,
            digest, mtime, data, text, start_ns
        )

    old_mtime = current_state_mtime(state)
    if old_mtime == mtime:
        return None

    loaded = read_rulebook(path, directory, start_ns, str(event), session_id)
    if loaded is None:
        return None
    data, _text, digest = loaded
    if state.get("hash") == digest:
        current = snapshot_path(directory, session_key, "current")
        update_base_state(state, session_id, cwd, digest, mtime, current)
        write_state(scope_state_file, state)
        return None

    return emit_change_notice(
        payload, state, scope_state_file, directory, session_id, session_key,
        old_mtime if old_mtime is not None else 0, digest, mtime, data, start_ns
    )


def main() -> None:
    start_ns = time.monotonic_ns()
    output = None
    try:
        output = handle(start_ns)
    except Exception as exc:  # fail open
        log_record(
            state_dir(),
            {
                "action": "internal_error",
                "error": type(exc).__name__,
                "elapsed_ms": round(elapsed_ms(start_ns), 3),
            },
        )
    finally:
        duration = time.monotonic_ns() - start_ns
        if duration > SLOW_RUN_NS:
            log_record(
                state_dir(),
                {
                    "action": "slow_run",
                    "elapsed_ms": round(duration / 1_000_000, 3),
                },
            )
        if output:
            sys.stdout.write(output)


if __name__ == "__main__":
    main()
