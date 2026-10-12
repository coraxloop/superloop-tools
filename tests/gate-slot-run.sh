#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:?}/gate-slot-test.XXXXXX")
trap 'chmod -R u+rwX "$fixture"; rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin"
cat > "$fixture/bin/rustc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cat rust-toolchain.toml
SH
cat > "$fixture/check" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'rustc fixture-%s\nhost: fixture-host\n' "$1" > rust-toolchain.toml
mkdir -p "$CARGO_TARGET_DIR"
if [ "$1" = first ]; then
  touch "$CARGO_TARGET_DIR/warm"
else
  test -f "$CARGO_TARGET_DIR/warm"
fi
printf '%s\n' "$TMPDIR" > scratch-path
mkdir "$TMPDIR/protected"
touch "$TMPDIR/protected/file"
chmod 000 "$TMPDIR/protected"
exit "$2"
SH
chmod +x "$fixture/bin/rustc" "$fixture/check"
export PATH="$fixture/bin:$PATH"
runner=$ROOT/infra/gate/run-slot.sh
"$runner" "$fixture/gates" 1 "$fixture/check" first 0
grep -q 'fixture-first' "$fixture/gates/slot-1/result.json"
status=0
"$runner" "$fixture/gates" 1 "$fixture/check" second 7 || status=$?
test "$status" -eq 7
test ! -e "$(cat "$fixture/gates/slot-1/scratch-path")"
python3 - "$fixture/gates/slot-1/result.json" "$fixture/gates/target-slot-1" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    record = json.load(source)
assert record == {"schema": 1, "compiler": "rustc fixture-second\nhost: fixture-host\n",
                  "target": sys.argv[2], "exit_code": 7}, record
PY
status=0
"$runner" "$fixture/gates" 1 rm rust-toolchain.toml 2> "$fixture/refusal" || status=$?
test "$status" -eq 2
grep -q '^gate-slot-compiler:' "$fixture/refusal"
test ! -e "$fixture/gates/slot-1/result.json"
status=0
"$runner" "$fixture/gates" invalid true 2> "$fixture/refusal" || status=$?
test "$status" -eq 2
grep -q '^gate-slot-arguments:' "$fixture/refusal"
python3 - "$runner" "$fixture" <<'PY'
import os
import pathlib
import subprocess
import sys

runner, fixture = sys.argv[1:]
root = pathlib.Path(fixture)
ready_r, ready_w = os.pipe()
release_r, release_w = os.pipe()
# Close stdout only after the command has made its protected scratch tree.
# The child blocks on the release pipe, so sampler setup cannot race the close.
command = ['python3', '-c', r'''
import os, pathlib, sys
scratch = pathlib.Path(os.environ['TMPDIR'])
pathlib.Path('rust-toolchain.toml').write_text('rustc fixture-closed\nhost: fixture-host\n')
(scratch / 'protected').mkdir()
(scratch / 'protected/file').touch()
(scratch / 'protected').chmod(0)
pathlib.Path('scratch-path').write_text(str(scratch))
os.write(int(sys.argv[1]), b'R')
os.read(int(sys.argv[2]), 1)
''', str(ready_w), str(release_r)]
child = subprocess.Popen([runner, str(root / 'closed'), '1', *command],
                         stdout=subprocess.PIPE, pass_fds=(ready_w, release_r))
os.close(ready_w)
os.close(release_r)
assert os.read(ready_r, 1) == b'R'
child.stdout.close()
os.write(release_w, b'G')
os.close(release_w)
os.close(ready_r)
assert child.wait() == -13  # Bash dies on the final sampler's SIGPIPE.
scratch = pathlib.Path((root / 'closed/slot-1/scratch-path').read_text())
assert not scratch.exists(), scratch
PY
mkdir -p "$fixture/fail-bin"
cat > "$fixture/fail-bin/rm" <<'SH'
#!/usr/bin/env bash
# The fresh slot has no result.json; fail only the later scratch removal.
if [ "$1" = -rf ]; then exit 1; fi
exit 0
SH
chmod +x "$fixture/fail-bin/rm"
status=0
PATH="$fixture/fail-bin:$PATH" "$runner" "$fixture/failure" 1 "$fixture/check" first 0 > "$fixture/samples" 2> "$fixture/refusal" || status=$?
test "$status" -eq 2
grep -q '^gate-slot-cleanup: scratch removal failed$' "$fixture/refusal"
test -d "$(cat "$fixture/failure/slot-1/scratch-path")"
for battery in command gate; do
  grep -Eq "^SAMPLE $battery end .*own_user_s=[0-9.]+ own_system_s=[0-9.]+" "$fixture/samples"
  grep -Eq "^DELTA $battery wall=[0-9.]+s .*own_user_s=[0-9.]+ own_system_s=[0-9.]+" "$fixture/samples"
done
printf 'PASS gate slot reuse, compiler record, failure status, cleanup and refusal\n'
