"""Build the release workspace once and publish Meson's declared artifacts."""

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


def build(root, output, cargo, commit):
    started = time.monotonic()
    environment = dict(os.environ)
    if not commit:
        commit = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
    environment["SUPERLOOP_TOOLS_COMMIT"] = commit
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
    for name in binaries(root):
        publish(Path(artifacts[name]), output.parent / ("cargo-" + name))
    record = {"source_commit": commit, "features": features,
              "build_wall_ms": int((time.monotonic() - started) * 1000)}
    output.write_text(json.dumps(record, sort_keys=True) + "\n")
    # Directory dependencies notice newly added or removed inputs, including untracked sources.
    # The build directory and Cargo target are excluded even for in-source configurations.
    target = Path(environment.get("CARGO_TARGET_DIR", root / "target")).resolve()
    dependencies = []
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
        output, cargo, commit = arguments
        build(root, Path(output), cargo, commit)
    else:
        raise SystemExit("unknown workspace build operation")
