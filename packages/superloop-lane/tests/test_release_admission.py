"""Verify the fixture admission is absent from the complete release artifact set.
"""
import argparse
import json
from pathlib import Path
import subprocess

SENTINELS = (b"SUPERLOOP_CLAUDE_FIXTURE_ADMISSION_V1_ONLY_UNIT_TESTS",
             b"SUPERLOOP_MAIL_STANDIN_V1_ONLY_UNIT_TESTS")


def contains(path):
    """Keep overlap so a sentinel crossing a read boundary is still found."""
    with path.open("rb") as stream:
        assert stream.read(4) == b"\x7fELF", f"not an ELF binary: {path}"
        stream.seek(0)
        tail = b""
        found = set()
        while block := stream.read(1024 * 1024):
            data = tail + block
            found.update(sentinel for sentinel in SENTINELS if sentinel in data)
            if len(found) == len(SENTINELS):
                break
            tail = data[-(max(map(len, SENTINELS)) - 1):]
    return found


def test_release_admission(positive, artifacts):
    """Release binaries exclude the fixture admission; the unit binary includes it.

    ´test:integration:test-release-admission´
    """
    assert artifacts, "release artifact set is empty"
    assert len(set(artifacts)) == len(artifacts), "duplicate release artifact"
    positive_found = contains(positive)
    assert positive_found == set(SENTINELS), (
        f"unit positive control lacks sentinels: {positive_found}")
    for artifact in artifacts:
        found = contains(artifact)
        assert not found, f"fixture admission in {artifact}: {found}"
    print(json.dumps({"positive_control": str(positive),
                      "release_artifacts": list(map(str, artifacts)),
                      "fixture_admission": "absent"}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("artifacts", nargs="*")
    args = parser.parse_args()
    assert args.artifacts, "release artifact set is empty"
    command = [args.cargo, "test", "--locked", "--profile", "gate", "-p",
               "superloop-lane", "--lib", "--no-run", "--message-format=json"]
    result = subprocess.run(command, cwd=args.root, capture_output=True, text=True,
                            timeout=600, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    candidates = []
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact"
                and message["target"]["name"] == "superloop_lane"
                and message["target"]["kind"] == ["lib"]
                and message["profile"]["test"] and message.get("executable")):
            candidates.append(Path(message["executable"]))
    assert len(candidates) == 1, f"expected one current lane unit-test binary: {candidates}"
    test_release_admission(candidates[0], [args.build / name for name in args.artifacts])


if __name__ == "__main__":
    main()
