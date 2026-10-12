#!/usr/bin/env python3
"""Capture codex-lane shell behavior with synthetic process and time inputs."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


SCRIPT_DIR = Path(__file__).resolve().parent
PACKAGE_DIR = SCRIPT_DIR.parents[1]
REFERENCE = PACKAGE_DIR / "reference" / "codex-lane.sh"
EXPECTED = SCRIPT_DIR / "expected"
REFERENCE_SHA256 = "ad14ab4a05c2dcdf82035cbb2467faafe8082b4429268ddedc2a76a8b9cf1075"
CODEX_STUB = (SCRIPT_DIR / "stubs" / "codex").read_text(encoding="utf-8")

DATE_STUB = r'''#!/bin/sh
set -eu
if [ "$1" = "-u" ]; then
    printf '%s\n' '20260828T120000Z'
else
    /bin/cat "$ORACLE_CLOCK"
fi
'''

SLEEP_STUB = r'''#!/bin/sh
set -eu
now=$(/bin/cat "$ORACLE_CLOCK")
printf '%s\n' "$((now + ORACLE_TICK))" >"$ORACLE_CLOCK"
if [ "$ORACLE_RELEASE_MODE" = "yes" ]; then
    : >"$ORACLE_RELEASE"
    while [ ! -e "$ORACLE_ACK" ]; do :; done
fi
'''


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def normalize(raw: bytes, run_dir: Path, repo: Path) -> bytes:
    raw = raw.replace(os.fsencode(run_dir), b"$RUN_DIR")
    raw = raw.replace(os.fsencode(repo), b"$REPO")
    raw = re.sub(rb"line 158: +[0-9]+ Killed", b"line 158: PID Killed", raw)
    return re.sub(rb" wall=[0-9]+s budget=", b" wall=Ns budget=", raw)


def selected_layout(run_dir: Path) -> bytes:
    names = sorted(
        str(path.relative_to(run_dir)) + ("/" if path.is_dir() else "")
        for path in run_dir.rglob("*")
    )
    return "".join(f"{name}\n" for name in names).encode()


def selected_input(run_dir: Path) -> bytes:
    step_files = sorted(run_dir.glob("step-*.txt"))
    path = step_files[-1] if step_files else run_dir / "brief.txt"
    return path.read_bytes()


def read_if_present(path: Path) -> bytes:
    return path.read_bytes() if path.exists() else b""


def capture(
    root: Path,
    name: str,
    arguments: list[str],
    *,
    stdin: bytes = b"",
    mode: str = "normal",
    tick: int = 5,
    stall_window: int = 120,
    runaway_mult: int = 4,
    resume_dir: Path | None = None,
) -> None:
    case = root / name
    case.mkdir(exist_ok=True)
    repo = case / "repo"
    tools = case / "bin"
    home = case / "home"
    (repo / "bin").mkdir(parents=True)
    tools.mkdir()
    (home / ".codex").mkdir(parents=True)
    shutil.copy2(REFERENCE, repo / "bin" / "codex-lane")
    write_executable(tools / "codex", CODEX_STUB)
    write_executable(tools / "date", DATE_STUB)
    write_executable(tools / "sleep", SLEEP_STUB)

    clock = case / "clock"
    clock.write_text("0\n", encoding="ascii")
    release = case / "release"
    ack = case / "ack"
    argv = case / "argv"
    child_stdin = case / "stdin"
    cwd = case / "cwd"
    codex_home = case / "codex-home"
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "PATH": f"{tools}:/usr/bin:/bin",
            "CODEX_HOME": "",
            "ORACLE_PROGRAM": str(tools / "codex"),
            "ORACLE_ARGV": str(argv),
            "ORACLE_STDIN": str(child_stdin),
            "ORACLE_CWD": str(cwd),
            "ORACLE_CODEX_HOME": str(codex_home),
            "ORACLE_CLOCK": str(clock),
            "ORACLE_MODE": mode,
            "ORACLE_EXIT": "1",
            "ORACLE_TICK": str(tick),
            "ORACLE_RELEASE": str(release),
            "ORACLE_ACK": str(ack),
            "ORACLE_RELEASE_MODE": "yes" if mode == "growing" else "no",
            "LANE_STALL_WINDOW": str(stall_window),
            "LANE_RUNAWAY_MULT": str(runaway_mult),
        }
    )

    completed = subprocess.run(
        ["bash", str(repo / "bin" / "codex-lane"), *arguments],
        cwd=repo,
        env=environment,
        input=stdin,
        capture_output=True,
        check=False,
        timeout=10,
    )
    run_dir = resume_dir
    if run_dir is None:
        candidates = list((repo / "runs").iterdir())
        if len(candidates) != 1:
            raise RuntimeError(f"{name}: expected one run dir, got {candidates}")
        run_dir = candidates[0]

    EXPECTED.mkdir(exist_ok=True)
    records = {
        "stdout": normalize(completed.stdout, run_dir, repo),
        "stderr": normalize(completed.stderr, run_dir, repo),
        "status": f"{completed.returncode}\n".encode(),
        "argv": normalize(argv.read_bytes(), run_dir, repo),
        "stdin": child_stdin.read_bytes(),
        "cwd": normalize(cwd.read_bytes(), run_dir, repo),
        "codex-home": normalize(codex_home.read_bytes(), run_dir, repo),
        "layout": selected_layout(run_dir),
        "input": selected_input(run_dir),
        "events": (run_dir / "events.jsonl").read_bytes(),
        "last-message": read_if_present(run_dir / "last-message.txt"),
        "report": normalize((run_dir / "run-report.txt").read_bytes(), run_dir, repo),
    }
    for suffix, data in records.items():
        (EXPECTED / f"{name}.{suffix}").write_bytes(data)


def main() -> None:
    digest = hashlib.sha256(REFERENCE.read_bytes()).hexdigest()
    if digest != REFERENCE_SHA256:
        raise SystemExit(f"reference SHA-256 mismatch: {digest}")
    tmpdir = os.environ.get("TMPDIR")
    if not tmpdir:
        raise SystemExit("TMPDIR must name disk-backed temporary storage")
    root = Path(tempfile.mkdtemp(prefix="codex-lane-oracle.", dir=tmpdir))
    try:
        capture(root, "normal-completion", ["-t", "60", "hello"])
        capture(root, "stdin-prompt", ["-t", "60", "-"], stdin=b"stdin prompt")

        resume_case = root / "resume-step"
        resume_case.mkdir()
        resume_dir = resume_case / "run"
        resume_dir.mkdir()
        (resume_dir / "events.jsonl").write_bytes(
            b'{"type":"thread.started","thread_id":"session-1"}\n'
        )
        (resume_dir / "last-message.txt").write_bytes(b"first")
        (resume_dir / "run-report.txt").write_bytes(b"old report\n")
        (resume_dir / ".feed-offset").write_bytes(b"51\n")
        capture(
            root,
            "resume-step",
            [
                "-t",
                "60",
                "-r",
                "session-1",
                "-d",
                str(resume_dir),
                "-n",
                "work",
                "PROCEED",
            ],
            resume_dir=resume_dir,
        )

        capture(
            root,
            "empty-output-fallback",
            ["-t", "60", "fallback"],
            mode="fallback",
        )
        capture(
            root,
            "over-budget-growing",
            ["-t", "2", "late"],
            mode="growing",
            tick=3,
        )
        capture(
            root,
            "stalled-kill",
            ["-t", "10", "stall"],
            mode="hang",
            stall_window=1,
        )
        capture(
            root,
            "runaway-kill",
            ["-t", "1", "runaway"],
            mode="hang",
        )
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
