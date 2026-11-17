#!/usr/bin/env python3
"""Measure the version control-plane contract of one Meson-synced binary."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import tomllib


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


def check_provenance(args, version, group, package=None):
    record = json.loads(args.record.read_text(), object_pairs_hook=unique_object)
    expected = {"installed_name": args.installed_name, "version": version,
                "release_group": group, "repository": args.repository,
                "source_commit": args.record_commit,
                "sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest()}
    if package is not None:
        expected["package"] = package
    return ["provenance differs: " + key for key, value in expected.items()
            if record.get(key) != value]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--installed-name", required=True)
    authority = parser.add_mutually_exclusive_group(required=True)
    authority.add_argument("--manifest", type=Path)
    authority.add_argument("--expected-version")
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--record-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-group")
    parser.add_argument("--record-version")
    parser.add_argument("--commit")
    args = parser.parse_args()

    package = None
    version = args.expected_version
    group = args.release_group
    if args.manifest:
        with args.manifest.open("rb") as source:
            manifest = tomllib.load(source)
        package = manifest["package"]["name"]
        version = manifest["package"]["version"]
        if version == {"workspace": True}:
            with (args.manifest.resolve().parents[2] / "Cargo.toml").open("rb") as source:
                version = tomllib.load(source)["workspace"]["package"]["version"]
        group = manifest["package"]["metadata"]["superloop"]["release-group"]
    if not isinstance(version, str):
        raise ValueError("resolved manifest version must be a string")
    if not isinstance(group, str):
        raise ValueError("provenance release group must be explicit")

    binary = args.binary.name
    command = args.installed_name
    version_text = command + " " + version
    expected = {
        "schema": 1,
        "command": command,
        "kind": "version",
        "message": "version requested",
        "fields": {"type": "version", "version": version_text},
    }
    if args.commit is not None:
        expected["fields"]["source_commit"] = args.commit

    started = time.monotonic()
    result = subprocess.run(
        [str(args.binary), "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    wall = time.monotonic() - started
    failures = check_provenance(args, version, group, package)
    if result.returncode != 0:
        failures.append("exit status is not zero")
    if result.stdout:
        failures.append("stdout is not empty")
    record = None
    try:
        if not result.stderr.endswith(b"\n") or len(result.stderr.splitlines()) != 1:
            raise ValueError("stderr must contain exactly one LF-terminated JSON record")
        record = json.loads(result.stderr, object_pairs_hook=unique_object)
        if not isinstance(record, dict) or type(record.get("schema")) is not int:
            raise ValueError("record schema must be an integer")
    except (ValueError, UnicodeDecodeError) as error:
        failures.append(str(error))
    if command == "superloop-lint" and isinstance(record, dict):
        identity = record.get("identity", {})
        if not isinstance(identity, dict):
            identity = {}
        measured = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        artifact = identity.get("artifact_sha256")
        absence = identity.get("digest_absence")
        measurement_valid = ((artifact == measured and absence is None)
                             or (artifact is None and absence in
                                 ("unreadable", "no-running-image-handle")))
        required = {"schema", "repository", "version", "source_commit", "source_tree", "source_state",
                    "release_tag", "artifact_sha256", "digest_absence"}
        if (set(identity) != required or identity.get("schema") != 1
                or identity.get("repository") != "superloop-tools"
                or identity.get("version") != version
                or not measurement_valid):
            failures.append("linter identity differs from the measured executable")
        state = identity.get("source_state")
        tag = identity.get("release_tag")
        source_commit = identity.get("source_commit")
        if (state not in ("release", "candidate", "dirty", "unknown")
                or (state == "release") != (isinstance(tag, str) and bool(tag))
                or (source_commit is None and state not in ("unknown", "dirty"))
                or (source_commit is not None and args.record_commit
                    and source_commit != args.record_commit)):
            failures.append("linter source identity differs from its producer handoff")
        expected["identity"] = identity
        if identity.get("source_commit") is not None:
            expected["fields"]["source_commit"] = identity["source_commit"]
        source = identity.get("source_commit") or "unknown"
        artifact = ("sha256:" + identity["artifact_sha256"]
                    if identity.get("artifact_sha256") else
                    "artifact digest unavailable (" + str(identity.get("digest_absence")) + ")")
        expected["message"] = (f"{version_text} superloop-tools tree:{identity.get('source_tree') or 'unknown'} commit:{source} "
                               f"{identity.get('source_state')} {artifact}")
    if record != expected:
        failures.append("version record does not match manifest identity and compiled commit")
    summary = {
        "binary": binary,
        "exit": result.returncode,
        "stdout_bytes": len(result.stdout),
        "record_command": record.get("command") if isinstance(record, dict) else None,
        "package": package,
        "version": version,
        "commit": args.commit,
        "wall_seconds": round(wall, 6),
        "failures": failures,
    }
    if command == "superloop-lint" and isinstance(record, dict):
        # Keep absence visible to artifact-admission readers. This version
        # conformance check does not add their requirement for a measured image.
        summary["identity"] = record.get("identity")
    print(json.dumps(summary, separators=(",", ":")), flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
