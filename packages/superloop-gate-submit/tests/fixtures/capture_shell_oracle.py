#!/usr/bin/env python3
"""Capture the shell superloop-gate-submit contract with fake Git and SSH tools."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


SCRIPT_DIR = Path(__file__).resolve().parent
PACKAGE_DIR = SCRIPT_DIR.parents[1]
REFERENCE = PACKAGE_DIR / "reference" / "superloop-gate-submit.sh"
EXPECTED = SCRIPT_DIR / "expected"
REFERENCE_SHA256 = "f116380e4de9457a1048131983ee9f9a390ca497b6e3bdbd61d8395918c668e7"
FICTIONAL_REFERENCE = Path(
    "/var/home/example-user/work/orchestration/packages/superloop-gate-submit/reference/superloop-gate-submit.sh"
)
EXAMPLE_PROFILE = {
    "LANE_VERIFY_SSH": "sagofink-orchestration",
    "LANE_VERIFY_CLONE": "/srv/orchestration-pack/worktree",
    "LANE_VERIFY_REMOTE_RUNNER": "/srv/orchestration-pack/bin/run-report bash -s",
    "LANE_VERIFY_RUST_ENV": "/srv/orchestration-pack/env/rust.sh",
}

GIT_STUB = (SCRIPT_DIR / "stubs" / "git").read_text(encoding="utf-8")
SSH_STUB = (SCRIPT_DIR / "stubs" / "ssh").read_text(encoding="utf-8")


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def normalized_stdout(raw: bytes) -> bytes:
    return re.sub(rb" wall=[0-9]+s verdict=", b" wall=Ns verdict=", raw)


def capture(
    root: Path,
    name: str,
    arguments: list[str],
    *,
    ssh_output: bytes = b"",
    ssh_rc: int = 0,
    overrides: dict[str, str] | None = None,
    git_failure: str | None = None,
    include_profile: bool = True,
) -> None:
    case = root / name
    case.mkdir()
    worktree = case / "worktree"
    git_dir = worktree / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "index").write_bytes(b"oracle-index-bytes\n")
    tools = case / "bin"
    tools.mkdir()
    write_executable(tools / "git", GIT_STUB)
    write_executable(tools / "ssh", SSH_STUB)

    git_log = case / "git.log"
    ssh_argv = case / "ssh.argv"
    ssh_stdin = case / "ssh.stdin"
    ssh_output_path = case / "ssh.output"
    index_path = case / "index.path"
    ssh_output_path.write_bytes(ssh_output)

    environment = os.environ.copy()
    for variable in EXAMPLE_PROFILE:
        environment.pop(variable, None)
    environment.update(
        {
            "PATH": f"{tools}{os.pathsep}{environment['PATH']}",
            "TMPDIR": str(case),
            "ORACLE_WORKTREE": str(worktree),
            "ORACLE_GIT_LOG": str(git_log),
            "ORACLE_INDEX_PATH": str(index_path),
            "ORACLE_SSH_ARGV": str(ssh_argv),
            "ORACLE_SSH_STDIN": str(ssh_stdin),
            "ORACLE_SSH_OUTPUT": str(ssh_output_path),
            "ORACLE_SSH_RC": str(ssh_rc),
        }
    )
    if include_profile:
        environment.update(EXAMPLE_PROFILE)
    if overrides:
        environment.update(overrides)
    if git_failure:
        environment["ORACLE_GIT_FAIL"] = git_failure

    command = [
        "bash",
        "-c",
        'source "$1" "${@:2}"',
        str(FICTIONAL_REFERENCE),
        str(REFERENCE),
        *arguments,
    ]
    completed = subprocess.run(command, env=environment, capture_output=True, check=False)
    EXPECTED.mkdir(exist_ok=True)
    (EXPECTED / f"{name}.stdout").write_bytes(normalized_stdout(completed.stdout))
    (EXPECTED / f"{name}.stderr").write_bytes(completed.stderr)
    (EXPECTED / f"{name}.status").write_text(f"{completed.returncode}\n", encoding="ascii")
    for source, suffix in [
        (git_log, "git"),
        (ssh_argv, "ssh-argv"),
        (ssh_stdin, "ssh-stdin"),
    ]:
        (EXPECTED / f"{name}.{suffix}").write_bytes(
            source.read_bytes() if source.exists() else b""
        )

    if index_path.exists():
        temporary_index = Path(index_path.read_text(encoding="utf-8"))
        cleanup = "leaked" if temporary_index.exists() else "clean"
    else:
        cleanup = "unused"
    (EXPECTED / f"{name}.temp-index").write_text(f"{cleanup}\n", encoding="ascii")


def main() -> None:
    digest = hashlib.sha256(REFERENCE.read_bytes()).hexdigest()
    if digest != REFERENCE_SHA256:
        raise SystemExit(f"reference SHA-256 mismatch: {digest}")

    tmpdir = os.environ.get("TMPDIR")
    if not tmpdir:
        raise SystemExit("TMPDIR must name disk-backed temporary storage")
    root = Path(tempfile.mkdtemp(prefix="superloop-gate-submit-oracle.", dir=tmpdir))
    try:
        default_worktree = root / "default-success" / "worktree"
        capture(
            root,
            "default-success",
            ["-p", "alpha,beta", str(default_worktree)],
            ssh_output=b"server evidence\nRUN-REPORT exit=0 wall=1s rootfs_tmp_left=1T workspace_left=2T\n",
        )

        override_worktree = root / "overrides-failure" / "worktree"
        capture(
            root,
            "overrides-failure",
            ["-p", "alpha", "-n", "named", "-A", "-D", str(override_worktree)],
            ssh_output=b"remote failed\nRUN-REPORT exit=1 wall=2s rootfs_tmp_left=1T workspace_left=2T\n",
            ssh_rc=1,
            overrides={
                "LANE_VERIFY_SSH": "mondreiher-analysis",
                "LANE_VERIFY_REMOTE": "hub-override",
                "LANE_VERIFY_CLONE": "/srv/example/worktree",
                "LANE_VERIFY_REMOTE_RUNNER": "/srv/example/bin/run-report bash -s",
                "LANE_VERIFY_RUST_ENV": "/srv/example/env/rust.sh",
            },
        )

        tail_worktree = root / "tail-cap" / "worktree"
        lines = b"".join(f"remote-line-{number:02}\n".encode() for number in range(1, 71))
        capture(
            root,
            "tail-cap",
            ["-p", "alpha", "-n", "tail", str(tail_worktree)],
            ssh_output=lines,
        )

        for name, arguments in [
            ("usage-no-packages", []),
            ("usage-extra-argument", ["-p", "alpha", "one", "two"]),
            ("usage-unknown-option", ["-p", "alpha", "-Z", "one"]),
        ]:
            capture(root, name, arguments)

        missing_profile_worktree = root / "usage-missing-profile" / "worktree"
        capture(
            root,
            "usage-missing-profile",
            ["-p", "alpha", str(missing_profile_worktree)],
            include_profile=False,
        )

        add_worktree = root / "snapshot-add-failure" / "worktree"
        capture(
            root,
            "snapshot-add-failure",
            ["-p", "alpha", str(add_worktree)],
            git_failure="add",
        )

        push_worktree = root / "push-failure" / "worktree"
        capture(
            root,
            "push-failure",
            ["-p", "alpha", str(push_worktree)],
            git_failure="push",
        )

        unsafe_worktree = root / "unsafe-name" / "worktree"
        capture(
            root,
            "unsafe-name",
            ["-p", "alpha", "-n", "bad name", str(unsafe_worktree)],
            ssh_output=b"verified\n",
        )

        undeclared_worktree = root / "remote-undeclared" / "worktree"
        capture(
            root,
            "remote-undeclared",
            ["-p", "alpha", str(undeclared_worktree)],
            ssh_output=b"remote evidence\n",
            ssh_rc=7,
        )

        unterminated_worktree = root / "unterminated-evidence" / "worktree"
        capture(
            root,
            "unterminated-evidence",
            ["-p", "alpha", str(unterminated_worktree)],
            ssh_output=b"partial evidence",
        )
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
