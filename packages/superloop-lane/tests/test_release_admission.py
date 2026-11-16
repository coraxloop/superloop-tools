"""Verify the fixture admission is absent from the complete release artifact set.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from unittest.mock import patch

sys.dont_write_bytecode = True

SENTINELS = (b"SUPERLOOP_CLAUDE_FIXTURE_ADMISSION_V1_ONLY_UNIT_TESTS",
             b"SUPERLOOP_MAIL_STANDIN_V1_ONLY_UNIT_TESTS")
BLOCK = 1024 * 1024


def require(condition, message):
    if not condition:
        raise SystemExit(message)


# Rust's White_Space property excludes Python's extra U+001C..U+001F separators.
RUST_WHITESPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004" \
                  "\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
OVERRIDES = ("RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
             "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
             "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")


def configuration_flag_tokens(value, source):
    # Cargo's advanced-env mode accepts TOML arrays for configured env lists.
    # Check them conservatively even if that mode was not enabled by this build.
    if source != "config" and value.lstrip(RUST_WHITESPACE).startswith("["):
        try:
            array = tomllib.loads("flags = " + value)["flags"]
            if isinstance(array, list) and all(isinstance(item, str) for item in array):
                return array
        except tomllib.TOMLDecodeError:
            pass
    return re.split("[" + RUST_WHITESPACE + "]+", value)


def carries_test_configuration(value, source="config"):
    if isinstance(value, list):
        tokens = value
    elif isinstance(value, str):
        if source == "CARGO_ENCODED_RUSTFLAGS":
            tokens = value.split("\x1f")
        elif source == "RUSTFLAGS":
            tokens = [token.strip(RUST_WHITESPACE) for token in value.split(" ")]
            tokens = [token for token in tokens if token]
        else:
            tokens = configuration_flag_tokens(value, source)
    else:
        return False
    return any(token == "--test" or token == "--cfg=test"
               or (token == "--cfg" and index + 1 < len(tokens)
                   and tokens[index + 1] == "test")
               for index, token in enumerate(tokens))


def environment_has_test(values, config_path=None):
    for name, value in values.items():
        if isinstance(value, dict) and "value" in value:
            value = value["value"]
        if name in OVERRIDES:
            if config_path is None:
                message = f"compiler override in build environment: {name}; unset {name}"
            else:
                message = (f"compiler override in Cargo config [env]: {config_path}: {name}; "
                           "remove the [env] entry")
            require(value is None, message +
                    "; then remove the build directory's workspace-build.json and rebuild")
        elif name == "CARGO_TARGET_*_RUSTFLAGS":
            if any(carries_test_configuration(flags, target)
                   for target, flags in value.items()):
                return True
        elif name in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"} \
                or (name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS")):
            if carries_test_configuration(value, name):
                return True
    return False


def configuration_has_test(settings, path="<configuration>"):
    build = settings.get("build", {})
    for name in ["rustc", "rustc-wrapper", "rustc-workspace-wrapper"]:
        require(build.get(name) is None,
                f"compiler override in Cargo config: {path}: build.{name}; remove the key; "
                "then remove the build directory's workspace-build.json and rebuild")
    return (carries_test_configuration(build.get("rustflags"))
            or any(carries_test_configuration(target.get("rustflags"))
                   for target in settings.get("target", {}).values())
            or environment_has_test(settings.get("env", {}), path))


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
    require(not environment_has_test(environment), "test configuration in build environment")
    for config in configurations:
        require(set(config) == {"path", "present", "selected", "settings"},
                "incomplete Cargo configuration record")
        require(not configuration_has_test(config["settings"], config["path"]),
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


def test_release_override_remedies():
    """Name each override's origin and how to regenerate its retained record.

    ´test:integration:test-release-override-remedies´
    """
    remedy = "; then remove the build directory's workspace-build.json and rebuild"
    cases = [
        (lambda: environment_has_test({"RUSTC_WRAPPER": ""}),
         "compiler override in build environment: RUSTC_WRAPPER; unset RUSTC_WRAPPER"),
        (lambda: configuration_has_test({"build": {"rustc": "fixture"}},
                                       "/fixture/config.toml"),
         "compiler override in Cargo config: /fixture/config.toml: build.rustc; remove the key"),
        (lambda: configuration_has_test({"env": {"RUSTC": {"value": "fixture"}}},
                                       "/fixture/config.toml"),
         "compiler override in Cargo config [env]: /fixture/config.toml: RUSTC; "
         "remove the [env] entry"),
    ]
    for action, expected in cases:
        try:
            action()
        except SystemExit as error:
            require(str(error) == expected + remedy, f"override remedy differs: {error}")
        else:
            raise SystemExit("override unexpectedly accepted")


def test_release_flag_sources():
    """Use Cargo's source-specific boundaries and refuse executable overrides.

    ´test:integration:test-release-flag-sources´
    """
    require(carries_test_configuration("--cfg test -Cmetadata=a\x1fb", "RUSTFLAGS"),
            "plain flags retain test before an embedded unit separator")
    require(carries_test_configuration("--cfg\x1ftest", "CARGO_ENCODED_RUSTFLAGS"),
            "encoded flag separator")
    require(not carries_test_configuration("--cfg test", "CARGO_ENCODED_RUSTFLAGS"),
            "encoded flags preserve embedded spaces")
    require(not carries_test_configuration("--cfg\ttest", "RUSTFLAGS"),
            "plain RUSTFLAGS splits spaces, not internal tabs")
    require(carries_test_configuration("--cfg\ttest", "CARGO_BUILD_RUSTFLAGS"),
            "config environment splits Rust whitespace")
    require(not carries_test_configuration("--cfg\x1f test", "RUSTFLAGS"),
            "Rust trim retains unit separator")
    require(not carries_test_configuration(["--cfg test"]), "array token is indivisible")
    require(carries_test_configuration(["--cfg", "test"]), "array token boundaries")
    for source in ["CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_FIXTURE_RUSTFLAGS"]:
        require(carries_test_configuration('["--cfg", "test"]', source),
                "configured environment array boundaries")
    require(not carries_test_configuration('["--cfg", "test"]', "RUSTFLAGS"),
            "plain flags do not decode configured environment arrays")
    require(not carries_test_configuration('["--cfg", "test"]'),
            "configuration strings remain whitespace lists")
    require(not carries_test_configuration("-Cmetadata=unmatched'", "RUSTFLAGS"),
            "flags are not shell parsed")
    for name in OVERRIDES:
        for value in ["", "/fixture/unmatched'", {"value": "/fixture/compiler"}]:
            refused(lambda: environment_has_test({name: value}), "compiler override")
    for name in ["rustc", "rustc-wrapper", "rustc-workspace-wrapper"]:
        refused(lambda: configuration_has_test({"build": {name: "/fixture/unmatched'"}}),
                "compiler override")
    for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"]:
        flags = "--cfg\x1ftest" if name == "CARGO_ENCODED_RUSTFLAGS" else "--cfg test"
        require(configuration_has_test({"env": {name: {"value": flags, "force": True}}}),
                "config env flag source")
    require(not environment_has_test({name: None for name in OVERRIDES}),
            "absent overrides remain accepted")


def test_release_configuration_includes(builder, root, cargo):
    """Record string and list includes, leaving missing-file policy to Cargo.

    ´test:integration:test-release-configuration-includes´
    """
    path = cargo / "config.toml"
    original = path.read_bytes()
    environment = {"HOME": str(root / "account"), "CARGO_HOME": str(cargo)}
    try:
        for directive in ['"flags.toml"', '["flags.toml"]',
                          '[{path="flags.toml", optional=true}]']:
            path.write_text("include = " + directive + "\n")
            inputs, _ = builder.compiler_inputs(root, environment)
            matched = [row for row in inputs["configurations"]
                       if row["path"] == str(cargo / "flags.toml")]
            require(len(matched) == 1 and matched[0]["present"]
                    and configuration_has_test(matched[0]["settings"]),
                    "include is one complete path")
        for directive in ['"missing.toml"', '["missing.toml"]',
                          '[{path="missing.toml", optional=true}]']:
            path.write_text("include = " + directive + "\n")
            inputs, observed = builder.compiler_inputs(root, environment)
            missing = cargo / "missing.toml"
            matched = [row for row in inputs["configurations"] if row["path"] == str(missing)]
            require(len(matched) == 1 and not matched[0]["present"]
                    and matched[0]["selected"] and observed[missing] is None,
                    "missing include is inventoried without a recorder refusal")
    finally:
        path.write_bytes(original)


def producer_fixture(root):
    workspace, output, cargo_home = root / "source", root / "build", root / "cargo-home"
    (workspace / "fixture/src").mkdir(parents=True)
    output.mkdir()
    cargo_home.mkdir()
    (workspace / "Cargo.toml").write_text('[workspace]\nmembers = ["fixture"]\n')
    (workspace / "fixture/Cargo.toml").write_text('[package]\nname = "fixture"\n')
    (workspace / "fixture/src/main.rs").write_text("fn main() {}\n")
    cargo = workspace / "fixture-cargo"
    cargo.write_text("#!" + sys.executable + "\n" + r"""
import json, os
from pathlib import Path
root = Path.cwd()
changing = (root / "change-config").exists()
if changing:
    (Path(os.environ["CARGO_HOME"]) / "config.toml").write_text(
        '[build]\nrustflags = ["--cfg", "changed_during_build"]\n')
artifact = root / "fixture-artifact"
artifact.write_bytes(b"\x7fELFchanged" if changing else b"\x7fELForiginal")
print(json.dumps({"reason": "compiler-artifact", "package_id": "fixture",
                  "target": {"name": "fixture", "kind": ["bin"]},
                  "features": [], "executable": str(artifact)}))
""")
    cargo.chmod(0o700)
    return workspace, output, cargo_home, cargo


def test_release_producer_dependencies(builder, source):
    """Exercise configuration races and newly created inputs through the producer.

    ´test:integration:test-release-producer-dependencies´
    """
    with tempfile.TemporaryDirectory(prefix="release-producer-") as directory:
        root = Path(directory)
        workspace, output, cargo_home, cargo = producer_fixture(root)
        record = output / "workspace-build.json"
        environment = {name: value for name, value in os.environ.items()
                       if not builder.flag_name(name)}
        environment.update(HOME=str(root / "account"), CARGO_HOME=str(cargo_home))
        command = shlex.join([sys.executable, str(source / "packages/build-sync/workspace.py"),
                              "build", str(workspace), str(record), str(cargo), "a" * 40])
        # Quote the shell command, then escape Ninja's own dollar expansion.
        target = str(record).replace("$", "$$").replace(" ", "$ ").replace(":", "$:")
        (output / "build.ninja").write_text(
            "rule record\n  restat = 1\n  command = " + command.replace("$", "$$")
            + "\n  depfile = workspace-build.d\nbuild " + target + ": record\n")
        ninja = shutil.which("ninja")
        require(ninja is not None, "producer dependency control requires Ninja")
        ninja_command = [ninja, "-C", str(output)]
        for added in [False, True]:
            if added:
                (cargo_home / "config.toml").write_text(
                    '[build]\nrustflags = ["--cfg", "new_config"]\n')
                modified = max(cargo_home.stat().st_mtime_ns, record.stat().st_mtime_ns + 1)
                os.utime(cargo_home, ns=(modified, modified))
            result = subprocess.run(ninja_command, env=environment,
                                    capture_output=True, text=True, check=False)
            require(result.returncode == 0, result.stdout + result.stderr)
            saved = json.loads(record.read_text())
            selected = [item for item in saved["compiler_inputs"]["configurations"]
                        if item["path"] == str(cargo_home / "config.toml")]
            require(len(selected) == 1 and selected[0]["present"] == added,
                    "new Cargo config must invalidate the producer dependency file")
        original = record.read_bytes()
        artifact = output / "cargo-fixture"
        original_artifact = artifact.read_bytes()
        (workspace / "change-config").touch()
        with patch.dict(os.environ, environment, clear=True):
            refused(lambda: builder.build(workspace, record, str(cargo), "a" * 40),
                    "Cargo configuration changed during release build")
        require(record.read_bytes() == original and artifact.read_bytes() == original_artifact,
                "during-build config refusal must retain published bytes and record")


def test_release_build_record(source):
    """Build-time inputs and byte binding refuse test flags and stale evidence.

    ´test:integration:test-release-build-record´
    """
    spec = importlib.util.spec_from_file_location(
        "workspace_record", source / "packages/build-sync/workspace.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    test_release_producer_dependencies(builder, source)
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
                    and configuration_has_test(config["settings"], config["path"])
                    for config in inputs["configurations"]), "included flags not recorded")
        test_release_configuration_includes(builder, root, cargo)
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
            forms = ["--cfg=test", "--test"]
            forms.append("--cfg\x1ftest" if name == "CARGO_ENCODED_RUSTFLAGS"
                         else "--cfg test -Cmetadata=a\x1fb")
            for flags in forms:
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
    test_release_flag_sources()
    test_release_override_remedies()
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
