"""Verify the fixture admission is absent from the complete release artifact set.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

SENTINELS = (b"SUPERLOOP_CLAUDE_FIXTURE_ADMISSION_V1_ONLY_UNIT_TESTS",
             b"SUPERLOOP_MAIL_STANDIN_V1_ONLY_UNIT_TESTS")
BLOCK = 1024 * 1024


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def carries_test_configuration(value):
    if isinstance(value, dict):
        return any(carries_test_configuration(item) for item in value.values())
    if isinstance(value, list):
        tokens = value
    elif isinstance(value, str):
        tokens = value.split("\x1f") if "\x1f" in value else shlex.split(value)
    else:
        return False
    return any(token == "--test" or token == "--cfg=test"
               or (token == "--cfg" and index + 1 < len(tokens)
                   and tokens[index + 1] == "test")
               for index, token in enumerate(tokens))


def build_record(build, artifacts):
    """Bind compiler-input evidence to exactly the artifact bytes being scanned."""
    record = json.loads((build / "workspace-build.json").read_text())
    require(record.get("schema") == 1 and record.get("profile") == "release",
            "missing release build record schema/profile")
    require(isinstance(record.get("source_commit"), str)
            and len(record["source_commit"]) == 40, "missing build source commit")
    inputs = record.get("compiler_inputs", {})
    environment = inputs.get("environment", {})
    required = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET",
                "CARGO_TARGET_*_RUSTFLAGS"}
    require(set(environment) == required, "incomplete compiler environment record")
    configurations = inputs.get("configurations")
    require(isinstance(configurations, list) and configurations,
            "missing Cargo configuration inventory")
    require(not carries_test_configuration(environment), "test configuration in build environment")
    for config in configurations:
        require(set(config) == {"path", "present", "selected", "settings"},
                "incomplete Cargo configuration record")
        require(not carries_test_configuration(config["settings"]),
                "test configuration in Cargo config: " + config["path"])
    saved = record.get("artifacts", {})
    require(set(saved) == {path.name for path in artifacts}, "stale build artifact inventory")
    for path in artifacts:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        require(saved[path.name] == {"bytes": path.stat().st_size, "sha256": digest},
                "stale build artifact record: " + path.name)


def refused(action, expected):
    try:
        action()
    except (SystemExit, FileNotFoundError) as error:
        require(expected in str(error), f"wrong record refusal: {error}")
    else:
        raise SystemExit("record control unexpectedly passed: " + expected)


def test_release_build_record(source):
    """Build-time inputs and byte binding refuse test flags and stale evidence.

    ´test:integration:test-release-build-record´
    """
    spec = importlib.util.spec_from_file_location(
        "workspace_record", source / "packages/build-sync/workspace.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    with tempfile.TemporaryDirectory(prefix="release-record-") as directory:
        root = Path(directory)
        cargo = root / ".cargo"
        cargo.mkdir()
        (cargo / "config.toml").write_text(
            'include = ["flags.toml"]\n[registry]\ntoken = "synthetic-not-recorded"\n')
        (cargo / "flags.toml").write_text('[build]\nrustflags = ["--cfg", "test"]\n')
        inputs, _ = builder.compiler_inputs(
            root, {"HOME": str(root / "account"), "CARGO_HOME": str(cargo)})
        require("synthetic-not-recorded" not in json.dumps(inputs),
                "unrelated configuration value recorded")
        require(any(config["path"].endswith("flags.toml")
                    and carries_test_configuration(config["settings"])
                    for config in inputs["configurations"]), "included flags not recorded")
        (cargo / "config").write_text('[build]\nrustflags = []\n')
        inputs, _ = builder.compiler_inputs(
            root, {"HOME": str(root / "account"), "CARGO_HOME": str(cargo)})
        require(not any(config["selected"] and config["path"].endswith("flags.toml")
                        for config in inputs["configurations"]), "legacy config precedence")
        artifact = root / "cargo-fixture"
        artifact.write_bytes(b"\x7fELFfixture")
        record = {"schema": 1, "profile": "release", "source_commit": "a" * 40,
                  "compiler_inputs": inputs,
                  "artifacts": {artifact.name: {"bytes": artifact.stat().st_size,
                                "sha256": builder.file_digest(artifact)}}}
        path = root / "workspace-build.json"
        refused(lambda: build_record(root, [artifact]), "workspace-build.json")
        path.write_text(json.dumps(record))
        build_record(root, [artifact])
        artifact.write_bytes(b"\x7fELFdifferent")
        refused(lambda: build_record(root, [artifact]), "stale build artifact record")
        artifact.write_bytes(b"\x7fELFfixture")
        original = json.dumps(record)
        for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"]:
            for flags in ["--cfg test", "--cfg=test", "--test", "--cfg\x1ftest"]:
                record = json.loads(original)
                record["compiler_inputs"]["environment"][name] = flags
                path.write_text(json.dumps(record))
                refused(lambda: build_record(root, [artifact]), "test configuration")
        record = json.loads(original)
        record["compiler_inputs"]["environment"]["CARGO_TARGET_*_RUSTFLAGS"] = {
            "CARGO_TARGET_FIXTURE_RUSTFLAGS": "--cfg=test"}
        path.write_text(json.dumps(record))
        refused(lambda: build_record(root, [artifact]), "test configuration")
        record = json.loads(original)
        record["compiler_inputs"]["configurations"][0]["settings"] = {
            "target": {"cfg(unix)": {"rustflags": ["--test"]}}}
        path.write_text(json.dumps(record))
        refused(lambda: build_record(root, [artifact]), "test configuration")
        # Each sentinel leaves only its last byte past a block boundary, so the
        # overlap must cover the longer one and both must be found in one pass.
        first, second = SENTINELS
        boundary = root / "boundary"
        boundary.write_bytes(b"\x7fELF" + b"x" * (BLOCK - 4 - (len(first) - 1)) + first
                             + b"x" * (BLOCK - len(second)) + second)
        require(contains(boundary) == set(SENTINELS), "sentinel boundary control")


def contains(path):
    """Keep overlap so a sentinel crossing a read boundary is still found."""
    with path.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", f"not an ELF binary: {path}")
        stream.seek(0)
        tail = b""
        found = set()
        while block := stream.read(BLOCK):
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
    require(artifacts, "release artifact set is empty")
    require(len(set(artifacts)) == len(artifacts), "duplicate release artifact")
    positive_found = contains(positive)
    require(positive_found == set(SENTINELS),
            f"unit positive control lacks sentinels: {positive_found}")
    for artifact in artifacts:
        found = contains(artifact)
        require(not found, f"fixture admission in {artifact}: {found}")
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
    require(args.artifacts, "release artifact set is empty")
    test_release_build_record(args.root)
    build_record(args.build, [args.build / name for name in args.artifacts])
    command = [args.cargo, "test", "--locked", "--profile", "gate", "-p",
               "superloop-lane", "--lib", "--no-run", "--message-format=json"]
    result = subprocess.run(command, cwd=args.root, capture_output=True, text=True,
                            check=False)
    require(result.returncode == 0, result.stdout + result.stderr)
    candidates = []
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact"
                and message["target"]["name"] == "superloop_lane"
                and message["target"]["kind"] == ["lib"]
                and message["profile"]["test"] and message.get("executable")):
            candidates.append(Path(message["executable"]))
    require(len(candidates) == 1,
            f"expected one current lane unit-test binary: {candidates}")
    test_release_admission(candidates[0], [args.build / name for name in args.artifacts])


if __name__ == "__main__":
    main()
