#!/usr/bin/env python3
"""Capture and normalize the deployed Python scenario-suite transcript."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
SUITE = HERE.parents[3] / "hooks" / "heartbeat-guard-test.py"
EXPECTED = HERE / "expected"


def main() -> int:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="heartbeat-guard-oracle-") as home:
        environment["HOME"] = home
        completed = subprocess.run(
            [sys.executable, os.fspath(SUITE)],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=30,
        )
    normalized = re.sub(r"wall=\d+\.\d+s", "wall=<elapsed>", completed.stdout)
    normalized = re.sub(r"in \d+\.\d+s", "in <elapsed>", normalized)
    normalized = re.sub(
        r"allow \d+\.\d+s, first-eval block \d+\.\d+s .*post-block retry \d+\.\d+s",
        "allow <elapsed>, first-eval block <elapsed> (both <1s), post-block retry <elapsed>",
        normalized,
    )
    EXPECTED.mkdir(parents=True, exist_ok=True)
    (EXPECTED / "python-reference-suite.stdout").write_text(normalized, encoding="utf-8")
    (EXPECTED / "python-reference-suite.status").write_text(
        "{}\n".format(completed.returncode), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
