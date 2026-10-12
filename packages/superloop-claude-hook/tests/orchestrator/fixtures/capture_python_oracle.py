#!/usr/bin/env python3
"""Capture deterministic orchestrator.py characterization fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ORACLE = Path(__file__).resolve().parents[3] / "reference/orchestrator/orchestrator.py"
EXPECTED = Path(__file__).resolve().parent / "expected"
PROJECT = "/fixture/project"
SESSION = "fixture/session"
OLD_MTIME = 1_700_000_000_123_456_789
NEW_MTIME = 1_700_000_010_987_654_321
OLD_RULEBOOK = "# Fixture rules\n\nKeep evidence exact.\n"
NEW_RULEBOOK = "# Fixture rules\n\nKeep evidence exact and bounded.\n"


def payload(event: str, **fields: object) -> dict[str, object]:
    value: dict[str, object] = {
        "hook_event_name": event,
        "session_id": SESSION,
        "cwd": PROJECT,
    }
    value.update(fields)
    return value


def write_rulebook(path: Path, text: str, stamp: int) -> None:
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(stamp, stamp))


def invoke(state_dir: Path, rulebook: Path, event: dict[str, object]) -> str:
    environment = os.environ.copy()
    environment["ORCHESTRATOR_STATE_DIR"] = os.fspath(state_dir)
    environment["ORCHESTRATION_FILE"] = os.fspath(rulebook)
    completed = subprocess.run(
        [sys.executable, os.fspath(ORACLE)],
        input=json.dumps(event).encode(),
        capture_output=True,
        check=False,
        env=environment,
        timeout=5,
    )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError(
            f"oracle failed: exit={completed.returncode} stderr={completed.stderr!r}"
        )
    return completed.stdout.decode().replace(os.fspath(state_dir), "<STATE_DIR>")


def fresh_precondition() -> dict[str, object]:
    return {
        "rulebook": {"text": OLD_RULEBOOK, "mtime_ns": OLD_MTIME},
        "state": "absent",
        "snapshots": "absent",
    }


def record(
    name: str,
    event: dict[str, object],
    precondition: dict[str, object],
    expected_stdout: str,
    *,
    authority: str = "python",
    spec_label: str | None = None,
    divergence: str | None = None,
    expected_effect: dict[str, object] | None = None,
    python_effect: dict[str, object] | None = None,
) -> None:
    value: dict[str, object] = {
        "name": name,
        "authority": authority,
        "payload": event,
        "state_precondition": precondition,
        "expected_stdout": expected_stdout,
    }
    if spec_label is not None:
        value["spec_label"] = spec_label
    if divergence is not None:
        value["divergence"] = divergence
    if expected_effect is not None:
        value["expected_effect"] = expected_effect
    if python_effect is not None:
        value["python_effect"] = python_effect
    target = EXPECTED / f"{name}.json"
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalized_state(state_dir: Path) -> dict[str, object]:
    state_file = state_dir / "orchestrator-scope-fixture-session.json"
    value = json.loads(state_file.read_text(encoding="utf-8"))
    value.pop("updated_at", None)
    dedupe = value.get("sessionstart_dedupe")
    if isinstance(dedupe, dict):
        dedupe.pop("time", None)
    if isinstance(value.get("snapshot_current"), str):
        value["snapshot_current"] = str(value["snapshot_current"]).replace(
            os.fspath(state_dir), "<STATE_DIR>"
        )
    return value


def capture_aligned() -> None:
    with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
        root = Path(temporary)
        state_dir = root / "state"
        rulebook = root / "ORCHESTRATION.md"
        write_rulebook(rulebook, OLD_RULEBOOK, OLD_MTIME)
        startup = payload("SessionStart", source="startup")
        first = invoke(state_dir, rulebook, startup)
        record("fresh-startup", startup, fresh_precondition(), first)

        duplicate = invoke(state_dir, rulebook, startup)
        record(
            "duplicate-startup",
            startup,
            {"prior": "fresh-startup within five seconds"},
            duplicate,
        )

        prompt_event = payload("UserPromptSubmit", prompt_id="prompt-1")
        unchanged = invoke(state_dir, rulebook, prompt_event)
        record(
            "unchanged-prompt",
            prompt_event,
            {"prior": "fresh-startup", "live_rulebook": "unchanged"},
            unchanged,
        )

        write_rulebook(rulebook, NEW_RULEBOOK, NEW_MTIME)
        change_event = payload("UserPromptSubmit", prompt_id="prompt-2")
        notice = invoke(state_dir, rulebook, change_event)
        record(
            "change-notice",
            change_event,
            {
                "prior": "fresh-startup",
                "rulebook": {"text": NEW_RULEBOOK, "mtime_ns": NEW_MTIME},
            },
            notice,
        )

    for witness in (False, True):
        with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            rulebook = root / "ORCHESTRATION.md"
            transcript = root / "transcript.jsonl"
            write_rulebook(rulebook, OLD_RULEBOOK, OLD_MTIME)
            invoke(state_dir, rulebook, payload("SessionStart", source="startup"))
            digest = hashlib.sha256(OLD_RULEBOOK.encode()).hexdigest()
            marker = f"ORCHESTRATION_SCOPE_MARKER v1 sha256={digest}"
            transcript.write_text(marker if witness else "no marker", encoding="utf-8")
            resume = payload(
                "SessionStart", source="resume", transcript_path=os.fspath(transcript)
            )
            output = invoke(state_dir, rulebook, resume)
            suffix = "present" if witness else "absent"
            record(
                f"resume-marker-{suffix}",
                {**resume, "transcript_path": "<TRANSCRIPT>"},
                {"prior": "fresh-startup", "marker_witness": witness},
                output,
            )


def capture_divergences() -> None:
    with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
        root = Path(temporary)
        state_dir = root / "state"
        rulebook = root / "ORCHESTRATION.md"
        write_rulebook(rulebook, OLD_RULEBOOK, OLD_MTIME)
        state_dir.mkdir()
        project_root = "/fixture"
        (state_dir / ("orchestrator-disabled" + project_root.replace("/", "-"))).write_bytes(
            b""
        )
        event = payload("SessionStart", source="startup")
        output = invoke(state_dir, rulebook, event)
        python_state = normalized_state(state_dir)
        record(
            "spec-project-root-disable",
            event,
            {
                "rulebook": {"text": OLD_RULEBOOK, "mtime_ns": OLD_MTIME},
                "project_root": project_root,
                "project_disable_flag": "present",
                "state": "absent",
            },
            "",
            authority="spec",
            spec_label="rule:hooks:disable-precedence",
            divergence="The project disable flag is keyed by the resolved project root; Python keys it by the raw subdirectory working directory and injects.",
            expected_effect={"injection": "disabled", "session_state": "absent"},
            python_effect={
                "injection": "emitted",
                "cwd": python_state["cwd"],
                "stdout": output,
            },
        )

    with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
        root = Path(temporary)
        state_dir = root / "state"
        rulebook = root / "ORCHESTRATION.md"
        write_rulebook(rulebook, OLD_RULEBOOK, OLD_MTIME)
        event = payload("SessionStart", source=7)
        output = invoke(state_dir, rulebook, event)
        python_state = normalized_state(state_dir)
        record(
            "spec-nonstring-source",
            event,
            fresh_precondition(),
            output,
            authority="spec",
            spec_label="sig:hooks:injection-input",
            divergence="A nonstring source is classified and deduplicated as empty; Python stringifies it in the persisted dedupe key.",
            expected_effect={"sessionstart_dedupe.key": [SESSION, "", python_state["hash"]]},
            python_effect={"sessionstart_dedupe.key": python_state["sessionstart_dedupe"]["key"]},
        )

    with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
        root = Path(temporary)
        state_dir = root / "state"
        rulebook = root / "ORCHESTRATION.md"
        write_rulebook(rulebook, OLD_RULEBOOK, OLD_MTIME)
        event = payload("SessionStart", source="startup", cwd=17)
        output = invoke(state_dir, rulebook, event)
        python_state = normalized_state(state_dir)
        record(
            "spec-nonstring-cwd",
            event,
            fresh_precondition(),
            output,
            authority="spec",
            spec_label="sig:hooks:injection-input",
            divergence="A nonstring working directory is replaced by the process working directory; Python persists an empty string after injection.",
            expected_effect={"cwd": "<PROCESS_CWD>"},
            python_effect={"cwd": python_state["cwd"]},
        )

    with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
        root = Path(temporary)
        state_dir = root / "state"
        rulebook = root / "ORCHESTRATION.md"
        write_rulebook(rulebook, OLD_RULEBOOK, OLD_MTIME)
        event = payload("UserPromptSubmit", prompt_id={"invalid": True})
        output = invoke(state_dir, rulebook, event)
        python_state = normalized_state(state_dir)
        record(
            "spec-nonstring-prompt",
            event,
            fresh_precondition(),
            output,
            authority="spec",
            spec_label="proto:hooks:prompt-deduplication",
            divergence="A nonstring prompt identity does not enter deduplication state; Python copies it into its auxiliary dedupe_key field.",
            expected_effect={"dedupe_key": {"event": "UserPromptSubmit"}},
            python_effect={"dedupe_key": python_state["dedupe_key"]},
        )

    with tempfile.TemporaryDirectory(prefix="orchestrator-oracle-") as temporary:
        root = Path(temporary)
        state_dir = root / "state"
        rulebook = root / "CALLER-SUPPLIED-secret-name.md"
        event = payload("SessionStart", source="startup")
        output = invoke(state_dir, rulebook, event)
        log_value = json.loads((state_dir / "orchestrator.log").read_text(encoding="utf-8"))
        record(
            "spec-redacted-refusal",
            event,
            {"rulebook": "missing at caller-supplied configured path", "state": "absent"},
            output,
            authority="spec",
            spec_label="req:hooks:redacted-diagnostics",
            divergence="A refusal log omits caller-supplied paths; Python records the configured path.",
            expected_effect={
                "log": {
                    "action": "guard4_refusal",
                    "reason": "rulebook_missing",
                    "event": "SessionStart",
                    "session_id": SESSION,
                }
            },
            python_effect={"log.path_present": "path" in log_value},
        )


def main() -> int:
    if not ORACLE.is_file():
        raise RuntimeError(f"Python oracle unavailable at {ORACLE}")
    EXPECTED.mkdir(parents=True, exist_ok=True)
    capture_aligned()
    capture_divergences()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
