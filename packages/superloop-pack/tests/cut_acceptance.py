"""Prove a committed public cut and its history-free archive configure and lint."""
import argparse
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True, type=Path)
parser.add_argument('--pack', required=True, type=Path)
parser.add_argument('--linter', required=True, type=Path)
args = parser.parse_args()
args.pack = args.pack.resolve()
args.linter = args.linter.resolve()
started = time.monotonic()
deadline = started + 1800


def run(argv, cwd):
    remaining = deadline - time.monotonic()
    assert remaining > 0, 'cut acceptance exhausted its shared wall budget'
    before = time.monotonic()
    result = subprocess.run(['timeout', '--kill-after=2s', str(remaining) + 's'] +
                            [str(value) for value in argv], cwd=cwd,
                            capture_output=True, text=True)
    print(json.dumps({'argv': [str(value) for value in argv],
                      'exit': result.returncode, 'wall': time.monotonic() - before}), flush=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


with tempfile.TemporaryDirectory(prefix='cut-acceptance-') as directory:
    fixture = Path(directory)
    source, public, archive = (fixture / name for name in ('source', 'public', 'archive'))
    burn = fixture / 'burn.toml'
    burn.write_text('[[values]]\nvalue = "fictional-private-estate-sentinel"\nmatch = "substring"\n')
    run(['git', 'clone', '--no-hardlinks', '--quiet', args.root, source], fixture)
    run(['git', '-c', 'tag.gpgsign=false', 'tag', 'cut-acceptance'], source)
    run([args.pack, 'cut', '--tag', 'cut-acceptance', '--manifest', 'public-set.toml',
         '--out', public, '--author', 'Fixture Author <fixture@example.com>',
         '--date', '2026-10-12T16:11:22Z', '--public-tag', 'v0.1.0',
         '--burn-register', burn, '--linter', args.linter], source)
    recut = fixture / 'recut'
    run([args.pack, 'cut', '--tag', 'cut-acceptance', '--manifest', 'public-set.toml',
         '--out', recut, '--author', 'Fixture Author <fixture@example.com>',
         '--date', '2026-10-12T16:11:22Z', '--public-tag', 'v0.1.0',
         '--burn-register', burn, '--linter', args.linter], source)
    for ref in ('HEAD', 'HEAD^{tree}', 'refs/tags/v0.1.0'):
        original = run(['git', 'rev-parse', ref], public)
        assert original == run(['git', 'rev-parse', ref], recut)
        print(json.dumps({'recut_equal': ref, 'object': original}), flush=True)
    assert [int(value) for value in run(
        ['git', 'log', '-1', '--format=%at %ct'], public).split()] == [1791821482] * 2
    assert run(['git', 'tag', '-l', '--format=%(objecttype) %(taggername) %(contents:subject)', 'v0.1.0'], public) == (
        'tag Fixture Author superloop-tools v0.1.0')
    assert int(run(['git', 'tag', '-l', '--format=%(taggerdate:unix)',
                    'v0.1.0'], public)) == 1791821482
    assert not (public / 'Cargo.lock').exists(), 'public cut must omit Cargo.lock'
    run(['meson', 'setup', 'build'], public)
    assert not (public / 'docs/public/README.md').exists()
    assert (public / 'README.md').read_bytes() == (source / 'README.md').read_bytes()
    readme = (public / 'README.md').read_text()
    for label in ('guide:publictools:superloop-tools', 'sec:publictools:build',
                  'sec:publictools:public-releases', 'sec:publictools:acknowledgements',
                  'sec:publictools:licensing'):
        assert readme.count(label) == 1, 'one README mint per label: ' + label
    run([args.linter, 'check', '--root', '.'], public)
    run(['cargo', 'build', '--workspace', '--bins', '--tests', '--target-dir', public / 'target'], public)
    run(['git', '-c', 'tag.gpgsign=false', 'tag', 'cut-acceptance'], public)
    commit = run(['git', 'rev-parse', 'HEAD'], public)
    tar = fixture / 'public.tar'
    run(['git', 'archive', 'cut-acceptance', '--format=tar', '--output', tar], public)
    archive.mkdir()
    with tarfile.open(tar) as contents:
        contents.extractall(archive, filter='data')
    assert not (archive / 'Cargo.lock').exists(), 'public archive must omit Cargo.lock'
    run(['meson', 'setup', 'build', '-Dtools_source_commit=' + commit], archive)
    print(json.dumps({'acceptance': 'cut-tree', 'wall': time.monotonic() - started}), flush=True)
