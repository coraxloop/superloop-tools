"""Build, stage-verify and consume the two published libraries through public commands."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True, type=Path)
parser.add_argument('--pack', required=True)
parser.add_argument('--linter', required=True)
parser.add_argument('--cargo', required=True)
args = parser.parse_args()
args.pack = str(Path(args.pack).resolve())
args.linter = str(Path(args.linter).resolve())


def run(argv, cwd, env=None):
    started = time.monotonic()
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    print(json.dumps({'argv': argv, 'status': result.returncode,
                      'wall': time.monotonic() - started}), flush=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


with tempfile.TemporaryDirectory(prefix='pack-consumer-') as temporary:
    proof = Path(temporary)
    source = proof / 'source'
    source.mkdir()
    for name in ['superloop-cli-common', 'superloop-execwrap']:
        shutil.copytree(args.root / 'packages' / name, source / 'packages' / name)
    manifest = (args.root / 'Cargo.toml').read_text()
    start = manifest.index('members = [')
    end = manifest.index(']', start) + 1
    manifest = manifest[:start] + 'members = ["packages/superloop-cli-common", "packages/superloop-execwrap"]' + manifest[end:]
    (source / 'Cargo.toml').write_text(manifest)
    shutil.copyfile(args.root / 'Cargo.lock', source / 'Cargo.lock')
    (source / 'public-set.toml').write_text('''namespace = "org.superloop-tools.public-set"
version = [1, 0, 0]
[include]
rows = [{ pattern = "Cargo.*" }, { pattern = "packages/" }, { pattern = "public-set.toml" }]
[exclude]
rows = [{ pattern = ".linter/", reason = "Fixture policy declarations." }]
[reserved]
rows = [{ pattern = "docs/public-pack-provenance.toml", reason = "Generated archive provenance." }]
[public]
readme = "README.md"
licence_code = "LICENSE-CODE"
licence_docs = "LICENSE-DOCS"
''')
    declaration = source / '.linter'
    declaration.mkdir()
    bodies = {
        'owners': 'root_owner = "PROJECTA"\nowners = ["PROJECTA"]\npartitions = [{ name = "fixture", owner = "PROJECTA", pattern = "*VCHAR" }]\nmay_cite = []\n',
        'environments': 'environments = []\n',
        'policies': 'policies = [{ owner = "PROJECTA", policy = "public-pack.values-absent" }, { owner = "PROJECTA", policy = "labels.mints-well-formed" }]\n',
        'lists': '[PROJECTA."public-pack.values-absent"]\npath_counts = []\n[PROJECTA."labels.mints-well-formed"]\nallowances = []\n',
        'shape': 'universe = "git-tracked"\nignore = []\n',
        'policy-public-pack-values': '[owners.PROJECTA]\nsurface = "*VCHAR"\nvalues = "local/burn-register.toml"\nexclude = \'%s"local" [ "/" *VCHAR ]\'\n',
    }
    for name, body in bodies.items():
        namespace = ('class.linter.policy.public-pack.values-absent' if name.startswith('policy-')
                     else ('class.linter.' if name == 'lists' else 'org.example.linter.') + name)
        (declaration / (name + '.toml')).write_text('namespace = ' + json.dumps(namespace) + '\nversion = [1, 0, 0]\n' + body)
    burn = proof / 'burn.toml'
    burn.write_text('values = [{ value = "fixture-private-absent-value", match = "substring" }]\n')
    run(['git', 'init', '-q'], source)
    run(['git', 'add', '-A'], source)
    run(['git', '-c', 'commit.gpgsign=false', '-c', 'user.name=Fixture', '-c',
         'user.email=fixture@example.invalid', 'commit', '-qm', 'consumer source'], source)
    run(['git', '-c', 'tag.gpgsign=false', 'tag', 'fixture-release'], source)
    run([args.linter, "check", "--root", str(source), "--public-pack", "--burn-input", str(burn)], source)
    archive = proof / 'source.zip'
    run([args.pack, 'build', '--tag', 'fixture-release', '--out', str(archive),
         '--burn-register', str(burn), '--linter-version', 'fixture'], source)
    stage = proof / 'stage'
    stage.mkdir()
    run([args.pack, 'stage-verify', '--pack', str(archive), '--burn-register', str(burn),
         '--linter', args.linter, '--staging', str(stage)], source)
    assert (stage / 'public-set.toml').is_file()
    assert (stage / 'docs/public-pack-provenance.toml').is_file()
    product = proof / 'product'
    (product / 'src').mkdir(parents=True)
    dependencies = ''
    for name in ['superloop-cli-common', 'superloop-execwrap']:
        library = next(stage.rglob(name + '/Cargo.toml')).parent
        dependencies += name + ' = { path = ' + json.dumps(str(library)) + ' }\n'
    (product / 'Cargo.toml').write_text('[package]\nname="consumer"\nversion="0.1.0"\nedition="2024"\n[dependencies]\n' + dependencies)
    (product / 'src/main.rs').write_text('fn main() { let _ = superloop_cli_common::CommandExit::Success; let _ = superloop_execwrap::Stream::Stdout; }\n')
    environment = os.environ.copy()
    environment['CARGO_HOME'] = environment.get('CARGO_HOME', str(Path.home() / '.cargo'))
    environment.pop('HOME', None)
    run([args.cargo, 'generate-lockfile', '--offline'], product, environment)
    run([args.cargo, 'build', '--offline', '--locked'], product, environment)
