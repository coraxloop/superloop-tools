"""Build the release workspace once and publish Meson's declared artifacts."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib


def binaries(root):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    names = set()
    for member in workspace["workspace"]["members"]:
        directory = root / member
        package = tomllib.loads((directory / "Cargo.toml").read_text())
        explicit = package.get("bin", [])
        names.update(binary["name"] for binary in explicit)
        paths = {binary.get("path") for binary in explicit}
        if (directory / "src/main.rs").exists() and "src/main.rs" not in paths:
            names.add(package["package"]["name"])
        if package["package"].get("autobins", True):
            names.update(path.stem for path in (directory / "src/bin").glob("*.rs")
                         if str(path.relative_to(directory)) not in paths)
    return sorted(names)


def publish(source, destination):
    if not destination.exists() or source.read_bytes() != destination.read_bytes():
        temporary = destination.with_suffix(".tmp")
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        temporary.replace(destination)


FLAG_NAMES = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
              "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
              "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
              "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET")
BUILD_KEYS = ("rustflags", "rustc", "rustc-wrapper", "rustc-workspace-wrapper", "target")


def flag_name(name):
    return name in FLAG_NAMES or (name.startswith("CARGO_TARGET_")
                                 and name.endswith("_RUSTFLAGS"))


# The build record binds these bytes against later artifact replacement/staleness.
# It is not an authenticity claim against a writer able to replace both objects.
def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compiler_inputs(root, environment):
    """Record only compiler controls, never registry credentials or unrelated env."""
    values = {name: environment.get(name) for name in FLAG_NAMES}
    values["CARGO_TARGET_*_RUSTFLAGS"] = {
        name: value for name, value in sorted(environment.items())
        if name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS")}
    home = Path(environment["CARGO_HOME"]) if "CARGO_HOME" in environment else (
        Path(environment.get("HOME", str(Path.home()))) / ".cargo")
    if not home.is_absolute():
        home = root / home
    directories = [path / ".cargo" for path in [root, *root.parents]] + [home]
    records, observed, active = {}, {}, set()

    def visit(path, selected):
        path = path.absolute()
        if path in active:
            raise SystemExit("Cargo configuration include cycle")
        if str(path) in records and (not selected or records[str(path)]["selected"]):
            return
        present = path.is_file()
        record = {"path": str(path), "present": present, "selected": selected,
                  "settings": {}}
        records[str(path)] = record
        observed[path] = file_digest(path) if present else None
        if not present or not selected:
            return
        active.add(path)
        config = tomllib.loads(path.read_text())
        record["settings"] = {
            "build": {key: value for key, value in config.get("build", {}).items()
                      if key in BUILD_KEYS},
            "target": {key: {"rustflags": value["rustflags"]}
                       for key, value in config.get("target", {}).items()
                       if "rustflags" in value},
            "env": {key: value for key, value in config.get("env", {}).items()
                    if flag_name(key)}}
        includes = config.get("include", [])
        if isinstance(includes, str):
            includes = [includes]
        for item in includes:
            name = item if isinstance(item, str) else item["path"]
            included = path.parent / name
            # Record absence; Cargo decides whether its enabled include semantics
            # require this file. The recorder must not add an independent refusal.
            visit(included, True)
        active.remove(path)

    for directory in directories:
        legacy, modern = directory / "config", directory / "config.toml"
        visit(legacy, legacy.is_file())
        visit(modern, not legacy.is_file())
    return {"environment": values, "configurations": list(records.values())}, observed


def build(root, output, cargo, commit, release_tag):
    started = time.monotonic()
    environment = dict(os.environ)
    # Explicit public source is checked by the linter build owner against the
    # closed private overlay; never infer it from either merge parent.
    environment["SUPERLOOP_TOOLS_PUBLIC_COMMIT"] = commit
    environment["SUPERLOOP_TOOLS_RELEASE_TAG"] = release_tag
    if not commit:
        commit = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
    environment["SUPERLOOP_TOOLS_COMMIT"] = commit
    compiler, configurations = compiler_inputs(root.resolve(), environment)
    locked = ["--locked"] if (root / "Cargo.lock").exists() else []
    process = subprocess.Popen(
        [cargo, "build", "--release", *locked, "--workspace", "--manifest-path",
         str(root / "Cargo.toml"), "--message-format=json-render-diagnostics"],
        cwd=root, env=environment, stdout=subprocess.PIPE, text=True,
    )
    artifacts = {}
    features = {}
    for line in process.stdout:
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact":
            key = message["package_id"] + " " + message["target"]["name"] + " " + ",".join(message["target"]["kind"])
            features.setdefault(key, []).append(message["features"])
            if message.get("executable"):
                artifacts[message["target"]["name"]] = message["executable"]
    if process.wait():
        raise SystemExit("workspace release build failed")
    if compiler_inputs(root.resolve(), environment)[1] != configurations:
        raise SystemExit("Cargo configuration changed during release build")
    published = {}
    for name in binaries(root):
        destination = output.parent / ("cargo-" + name)
        publish(Path(artifacts[name]), destination)
        published[destination.name] = {"bytes": destination.stat().st_size,
                                       "sha256": file_digest(destination)}
    record = {"schema": 1, "profile": "release", "compiler_inputs": compiler,
              "artifacts": published, "source_commit": commit, "features": features,
              "build_wall_ms": int((time.monotonic() - started) * 1000)}
    temporary_record = output.with_suffix(".tmp")
    temporary_record.write_text(json.dumps(record, sort_keys=True) + "\n")
    temporary_record.replace(output)
    # Directory dependencies notice newly added or removed inputs, including untracked sources.
    # The build directory and Cargo target are excluded even for in-source configurations.
    target = Path(environment.get("CARGO_TARGET_DIR", root / "target")).resolve()
    dependencies = [path for path, value in configurations.items() if value is not None]
    for path in configurations:
        parent = path.parent
        while not parent.is_dir():
            parent = parent.parent
        dependencies.append(parent)
    for directory, children, files in os.walk(root):
        path = Path(directory)
        children[:] = [child for child in children if child != ".git"
                       and not child.startswith(".lane")
                       and (path / child).resolve() not in {target, output.parent.resolve()}]
        dependencies.append(path)
        dependencies.extend(path / name for name in files)
    git = root / ".git"
    if git.is_dir():
        dependencies.extend(path for path in git.rglob("*") if path.is_file()
                            and (path.name in {"HEAD", "packed-refs"} or "refs" in path.parts))
    def escape(path):
        return str(path).replace("$", "$$").replace(" ", "\\ ").replace("#", "\\#")
    output.with_suffix(".d").write_text(
        escape(output) + ": " + " ".join(map(escape, dependencies)) + "\n"
    )


if __name__ == "__main__":
    mode, source, *arguments = sys.argv[1:]
    root = Path(source)
    if mode == "outputs":
        print("\n".join("cargo-" + name for name in binaries(root)))
    elif mode == "build":
        output, cargo, commit, release_tag = arguments
        build(root, Path(output), cargo, commit, release_tag)
    else:
        raise SystemExit("unknown workspace build operation")
