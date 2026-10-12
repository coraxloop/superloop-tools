#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CLEANER=${TARGET_CLEAN_TEST_BINARY:?Meson must bind the configured cleaner}
TEST_TMP_ROOT=${TMPDIR:-/tmp}
FIXTURE=$(mktemp -d "$TEST_TMP_ROOT/cargo-clean-test.XXXXXX")
trap 'rm -rf "$FIXTURE"' EXIT
HARNESS_T0=$(date +%s%3N)
passed=0
total=15

case $(realpath -m -s -- "$FIXTURE") in
  "$TEST_TMP_ROOT"/*) ;;
  *) printf 'cargo-clean tests: unsafe fixture path\n' >&2; exit 2 ;;
esac

CONTROL=$FIXTURE/control
BIN=$CONTROL/bin
NOJQ_BIN=$CONTROL/bin-no-jq
HOME_ROOT=$FIXTURE/home
FALLBACK_HOME=$FIXTURE/fallback-home
EMPTY_HOME=$FIXTURE/empty-home
LOCK_HOME=$FIXTURE/lock-home
MAP=$CONTROL/cargo-map
CARGO_LOG=$CONTROL/cargo.log
JQ_LOG=$CONTROL/jq.log
MAIN_LOG=$CONTROL/main-logger.log
MAIN_OUT=$CONTROL/main.out
mkdir -p "$BIN" "$NOJQ_BIN" "$HOME_ROOT" "$FALLBACK_HOME" "$EMPTY_HOME" "$LOCK_HOME"
: > "$MAP"
: > "$CARGO_LOG"
: > "$JQ_LOG"
: > "$MAIN_LOG"

REAL_STAT=$(command -v stat)
export CARGO_TEST_FIXTURE=$FIXTURE
export CARGO_TEST_MAP=$MAP
export CARGO_TEST_CARGO_LOG=$CARGO_LOG
export CARGO_TEST_JQ_LOG=$JQ_LOG
export CARGO_TEST_REAL_STAT=$REAL_STAT
export CARGO_TEST_UNOWNED=$HOME_ROOT/loops/unowned-target
export CARGO_TEST_FOREIGN_UID=$(( $(id -u) + 1 ))

cat > "$BIN/cargo" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$CARGO_TEST_CARGO_LOG"
printf '\n' >> "$CARGO_TEST_CARGO_LOG"
command_name=${1-}
shift || true
manifest=
while [ "$#" -gt 0 ]; do
  case $1 in
    --manifest-path) manifest=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$manifest" ] || exit 20
case $manifest in
  */bad-metadata/Cargo.toml) exit 21 ;;
esac
target=
while IFS='|' read -r mapped_manifest mapped_target; do
  if [ "$mapped_manifest" = "$manifest" ]; then
    target=$mapped_target
    break
  fi
done < "$CARGO_TEST_MAP"
[ -n "$target" ] || exit 22
case $command_name in
  metadata)
    printf '{"target_directory":"%s"}\n' "$target"
    ;;
  clean)
    case $target in
      "$CARGO_TEST_FIXTURE"/*) ;;
      *) exit 23 ;;
    esac
    [ ! -L "$target" ] || exit 24
    if [ -d "$target" ]; then
      find -P "$target" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    fi
    ;;
  *) exit 25 ;;
esac
SHIM

cat > "$BIN/logger" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CARGO_TEST_LOGGER_LOG"
SHIM

cat > "$BIN/stat" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1-}" = -c ] && [ "${2-}" = %u ] && [ "${3%/}" = "$CARGO_TEST_UNOWNED" ]; then
  printf '%s\n' "$CARGO_TEST_FOREIGN_UID"
  exit 0
fi
exec "$CARGO_TEST_REAL_STAT" "$@"
SHIM

cat > "$BIN/jq" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$CARGO_TEST_JQ_LOG"
printf '\n' >> "$CARGO_TEST_JQ_LOG"
IFS= read -r input
printf '%s\n' "$input" | sed -n 's/.*"target_directory"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
SHIM
chmod +x "$BIN/cargo" "$BIN/logger" "$BIN/stat" "$BIN/jq"

for tool in bash date du find flock id mkdir realpath rm sed sort timeout; do
  ln -s "$(command -v "$tool")" "$NOJQ_BIN/$tool"
done
ln -s "$BIN/cargo" "$NOJQ_BIN/cargo"
ln -s "$BIN/logger" "$NOJQ_BIN/logger"
ln -s "$BIN/stat" "$NOJQ_BIN/stat"

assert_fixture_root() {
  local selected=$1
  local resolved
  resolved=$(realpath -m -s -- "$selected")
  case $resolved in
    "$FIXTURE"/*) ;;
    *) printf 'cargo-clean tests: refused unsafe cleanup root %s\n' "$resolved" >&2; exit 2 ;;
  esac
}

run_clean() {
  local selected=$1
  local selected_path=$2
  local idle_hours=$3
  local logger_log=$4
  assert_fixture_root "$selected"
  HOME=$selected \
    PATH=$selected_path \
    CARGO_CLEAN_HOME=$selected \
    CARGO_CLEAN_CARGO=$BIN/cargo \
    CARGO_CLEAN_LOGGER=$BIN/logger \
    CARGO_CLEAN_MIN_IDLE_HOURS=$idle_hours \
    CARGO_TEST_LOGGER_LOG=$logger_log \
    "$CLEANER"
}

fail() {
  printf 'not ok - %s\n' "$1" >&2
  printf '%s\n' 'cargo argv:' >&2
  sed 's/^/  /' "$CARGO_LOG" >&2
  printf '%s\n' 'cleaner stdout:' >&2
  sed 's/^/  /' "$MAIN_OUT" >&2
  exit 1
}

pass_pin() {
  local name=$1
  local started=$2
  local ended
  ended=$(date +%s%3N)
  passed=$((passed + 1))
  printf 'ok %d - %s duration_ms=%d\n' "$passed" "$name" "$((ended - started))"
}

make_marked_target() {
  local target=$1
  mkdir -p "$target"
  printf 'Signature: 8a477f597d28d172789f06886806bc55\n# cargo cache\n' > "$target/CACHEDIR.TAG"
  printf '{}\n' > "$target/.rustc_info.json"
  printf 'build output\n' > "$target/artifact"
}

WORK_REPO=$HOME_ROOT/workspace
WORK_TARGET=$WORK_REPO/target
DETACHED=$HOME_ROOT/.cache/detached-old
FOREIGN=$HOME_ROOT/.cache/foreign-cache
BUSY=$HOME_ROOT/loops/busy-target
UNOWNED=$CARGO_TEST_UNOWNED
SYMLINK_PROJECT=$HOME_ROOT/symlink-project
SYMLINK_TARGET=$HOME_ROOT/linked-target
SYMLINK_BACKING=$FIXTURE/symlink-backing
OUTSIDE_PROJECT=$HOME_ROOT/outside-project
OUTSIDE_TARGET=$FIXTURE/outside-target
BAD_PROJECT=$HOME_ROOT/bad-metadata

mkdir -p "$WORK_REPO/member" "$WORK_TARGET/generated" "$SYMLINK_PROJECT" "$OUTSIDE_PROJECT" "$BAD_PROJECT"
printf '[workspace]\nmembers = ["member"]\n' > "$WORK_REPO/Cargo.toml"
printf '[package]\nname = "member"\nversion = "0.1.0"\n' > "$WORK_REPO/member/Cargo.toml"
printf '[package]\nname = "generated"\nversion = "0.1.0"\n' > "$WORK_TARGET/generated/Cargo.toml"
printf '[package]\nname = "symlink-project"\nversion = "0.1.0"\n' > "$SYMLINK_PROJECT/Cargo.toml"
printf '[package]\nname = "outside-project"\nversion = "0.1.0"\n' > "$OUTSIDE_PROJECT/Cargo.toml"
printf '[package]\nname = "bad-metadata"\nversion = "0.1.0"\n' > "$BAD_PROJECT/Cargo.toml"
make_marked_target "$WORK_TARGET"
make_marked_target "$DETACHED"
mkdir -p "$FOREIGN"
printf 'Signature: foreign-cache-signature\n' > "$FOREIGN/CACHEDIR.TAG"
printf '{}\n' > "$FOREIGN/.rustc_info.json"
printf 'must survive\n' > "$FOREIGN/artifact"
make_marked_target "$BUSY"
make_marked_target "$UNOWNED"
make_marked_target "$SYMLINK_BACKING"
ln -s "$SYMLINK_BACKING" "$SYMLINK_TARGET"
mkdir -p "$OUTSIDE_TARGET"
printf 'must remain outside\n' > "$OUTSIDE_TARGET/artifact"

find -P "$WORK_TARGET" "$DETACHED" "$UNOWNED" "$SYMLINK_BACKING" -type f -exec touch -d "@$(( $(date -u +%s) - 7200 ))" {} +
touch "$BUSY/artifact"
touch -d "@$(( $(date -u +%s) - 7200 ))" "$BUSY/CACHEDIR.TAG" "$BUSY/.rustc_info.json"

printf '%s|%s\n' "$WORK_REPO/Cargo.toml" "$WORK_TARGET" >> "$MAP"
printf '%s|%s\n' "$WORK_REPO/member/Cargo.toml" "$WORK_TARGET" >> "$MAP"
printf '%s|%s\n' "$SYMLINK_PROJECT/Cargo.toml" "$SYMLINK_TARGET" >> "$MAP"
printf '%s|%s\n' "$OUTSIDE_PROJECT/Cargo.toml" "$OUTSIDE_TARGET" >> "$MAP"

mkdir -p "$HOME_ROOT/.cache/cargo-clean"
: > "$HOME_ROOT/.cache/cargo-clean/lock"

tree_checksum() {
  local path relative digest
  while IFS= read -r -d '' path; do
    relative=${path#"$HOME_ROOT"/}
    if [ -L "$path" ]; then
      printf 'link %s %s\n' "$relative" "$(readlink "$path")"
    else
      digest=$(sha256sum "$path")
      printf 'file %s %s\n' "$relative" "${digest%% *}"
    fi
  done < <(
    find -P "$HOME_ROOT" \
      \( -path "$WORK_TARGET" -o -path "$DETACHED" -o -path "$BUSY" -o -path "$UNOWNED" \) -prune -o \
      \( -type f -o -type l \) -print0 |
      sort -z
  ) | sha256sum | sed 's/[[:space:]].*//'
}

BEFORE_TREE=$(tree_checksum)
if ! run_clean "$HOME_ROOT" "$BIN:$PATH" 1 "$MAIN_LOG" > "$MAIN_OUT"; then
  fail 'main fixture run failed'
fi
AFTER_TREE=$(tree_checksum)

pin_t0=$(date +%s%3N)
[ "$(grep -c '^metadata .*--manifest-path .*workspace/Cargo.toml ' "$CARGO_LOG")" -eq 1 ] || fail 'workspace root metadata count'
[ "$(grep -c '^metadata .*--manifest-path .*workspace/member/Cargo.toml ' "$CARGO_LOG")" -eq 1 ] || fail 'workspace member metadata count'
[ "$(grep -c '^clean --manifest-path .*workspace/Cargo.toml ' "$CARGO_LOG")" -eq 1 ] || fail 'workspace target clean count'
if grep -q 'workspace/target/generated/Cargo.toml' "$CARGO_LOG"; then fail 'resolved target was not pruned'; fi
pass_pin 'workspace root and member resolve to one target cleaned once' "$pin_t0"

pin_t0=$(date +%s%3N)
[ ! -e "$DETACHED" ] || fail 'detached Cargo target survived'
grep -Fq "target=$DETACHED mode=remove" "$MAIN_OUT" || fail 'detached target removal was not reported'
pass_pin 'detached directory with the Cargo marker pair is removed' "$pin_t0"

pin_t0=$(date +%s%3N)
[ -f "$FOREIGN/artifact" ] || fail 'foreign cache signature was removed'
if grep -Fq "target=$FOREIGN " "$MAIN_OUT"; then fail 'foreign cache signature was reported as Cargo'; fi
pass_pin 'foreign CACHEDIR.TAG signature survives' "$pin_t0"

pin_t0=$(date +%s%3N)
[ -L "$SYMLINK_TARGET" ] || fail 'target symlink was changed'
[ -f "$SYMLINK_BACKING/artifact" ] || fail 'symlink backing target was changed'
grep -Fq "target=$SYMLINK_TARGET mode=skip-symlink" "$MAIN_OUT" || fail 'symlink target skip was not reported'
pass_pin 'symlink target is skipped and its referent is untouched' "$pin_t0"

pin_t0=$(date +%s%3N)
[ -f "$UNOWNED/artifact" ] || fail 'unowned target was changed'
grep -Fq "target=$UNOWNED mode=skip-unowned" "$MAIN_OUT" || fail 'unowned target skip was not reported'
pass_pin 'foreign-uid target is skipped through the stat shim' "$pin_t0"

pin_t0=$(date +%s%3N)
[ -f "$BUSY/artifact" ] || fail 'busy target was changed'
grep -Fq "target=$BUSY mode=skip-busy" "$MAIN_OUT" || fail 'busy target skip was not reported'
[ -d "$WORK_TARGET" ] || fail 'cargo clean removed the target directory itself'
[ -z "$(find -P "$WORK_TARGET" -mindepth 1 -print -quit)" ] || fail 'old target contents were not cleaned'
pass_pin 'one-hour idle threshold skips fresh files and cleans old files' "$pin_t0"

pin_t0=$(date +%s%3N)
TARGET_RE='^cargo-clean: target=[^[:space:]]+ mode=(clean|remove|skip-busy|skip-unowned|skip-symlink|skip-metadata|skip-outside|fail) before_bytes=[0-9]+ freed_bytes=[0-9]+ duration_ms=[0-9]+$'
SUMMARY_RE='^cargo-clean: run root=[^[:space:]]+ targets=7 cleaned=1 removed=1 skipped=5 failed=0 freed_bytes=[0-9]+ duration_ms=[0-9]+$'
if grep '^cargo-clean: target=' "$MAIN_OUT" | grep -Ev "$TARGET_RE" >/dev/null; then fail 'target journal line shape'; fi
grep -Eq "$SUMMARY_RE" "$MAIN_OUT" || fail 'summary journal line shape or counters'
sed 's/^cargo-clean: /-t cargo-clean /' "$MAIN_OUT" > "$CONTROL/expected-logger.log"
cmp -s "$CONTROL/expected-logger.log" "$MAIN_LOG" || fail 'stdout and logger lines differ'
awk '$0 ~ / mode=remove / { for (i = 1; i <= NF; i++) if ($i ~ /^freed_bytes=/) { split($i, a, "="); if (a[2] > 0) found=1 } } END { exit found ? 0 : 1 }' "$MAIN_OUT" || fail 'real removal did not report positive freed bytes'
pass_pin 'target and summary lines match exactly and removal frees bytes' "$pin_t0"

pin_t0=$(date +%s%3N)
LOCK_LOG=$CONTROL/lock-logger.log
LOCK_OUT=$CONTROL/lock.out
: > "$LOCK_LOG"
mkdir -p "$LOCK_HOME/.cache/cargo-clean"
exec 8>"$LOCK_HOME/.cache/cargo-clean/lock"
flock -n 8 || fail 'could not hold fixture lock'
set +e
run_clean "$LOCK_HOME" "$BIN:$PATH" 0 "$LOCK_LOG" > "$LOCK_OUT"
lock_rc=$?
set -e
flock -u 8
exec 8>&-
[ "$lock_rc" -eq 3 ] || fail 'lock contender exit code'
[ "$(wc -l < "$LOCK_OUT")" -eq 1 ] || fail 'lock contender stdout line count'
[ "$(wc -l < "$LOCK_LOG")" -eq 1 ] || fail 'lock contender logger line count'
grep -Eq '^cargo-clean: run root=[^[:space:]]+ mode=locked$' "$LOCK_OUT" || fail 'lock contender diagnostic'
pass_pin 'held flock makes a second run exit 3 without waiting' "$pin_t0"

pin_t0=$(date +%s%3N)
FAKE_HOME=$FIXTURE/missing-home
INVALID_LOG=$CONTROL/invalid-logger.log
INVALID_OUT=$CONTROL/invalid.out
: > "$INVALID_LOG"
assert_fixture_root "$FAKE_HOME"
set +e
env -u CARGO_CLEAN_HOME HOME="$FAKE_HOME" PATH="$BIN:$PATH" CARGO_CLEAN_CARGO="$BIN/cargo" CARGO_CLEAN_LOGGER="$BIN/logger" CARGO_TEST_LOGGER_LOG="$INVALID_LOG" "$CLEANER" > "$INVALID_OUT"
invalid_rc=$?
set -e
[ "$invalid_rc" -eq 2 ] || fail 'invalid HOME exit code'
[ "$(wc -l < "$INVALID_OUT")" -eq 1 ] || fail 'invalid HOME stdout line count'
[ "$(wc -l < "$INVALID_LOG")" -eq 1 ] || fail 'invalid HOME logger line count'
grep -Eq '^cargo-clean: run root=[^[:space:]]+ mode=refuse reason=root-not-directory$' "$INVALID_OUT" || fail 'invalid HOME diagnostic'
pass_pin 'unset override and nonexistent fixture HOME exit 2' "$pin_t0"

pin_t0=$(date +%s%3N)
[ "$BEFORE_TREE" = "$AFTER_TREE" ] || fail 'fixture content outside declared targets changed'
pass_pin 'find checksum proves non-target fixture content unchanged' "$pin_t0"

pin_t0=$(date +%s%3N)
[ -f "$OUTSIDE_TARGET/artifact" ] || fail 'outside target was changed'
grep -Fq "target=$OUTSIDE_TARGET mode=skip-outside before_bytes=0 freed_bytes=0" "$MAIN_OUT" || fail 'outside target skip was not reported'
if grep -q '^clean --manifest-path .*outside-project/Cargo.toml ' "$CARGO_LOG"; then fail 'outside target was cleaned'; fi
pass_pin 'metadata target outside the selected root is skipped' "$pin_t0"

pin_t0=$(date +%s%3N)
grep -Fq "target=$BAD_PROJECT/Cargo.toml mode=skip-metadata before_bytes=0 freed_bytes=0" "$MAIN_OUT" || fail 'metadata failure line'
pass_pin 'metadata failure reports the manifest with zero byte fields' "$pin_t0"

pin_t0=$(date +%s%3N)
[ "$(wc -l < "$JQ_LOG")" -ge 1 ] || fail 'jq parser path was not exercised'
pass_pin 'jq metadata parser path is exercised' "$pin_t0"

pin_t0=$(date +%s%3N)
FALLBACK_REPO=$FALLBACK_HOME/repo
FALLBACK_TARGET=$FALLBACK_REPO/target
FALLBACK_LOG=$CONTROL/fallback-logger.log
FALLBACK_OUT=$CONTROL/fallback.out
mkdir -p "$FALLBACK_REPO" "$FALLBACK_TARGET"
printf '[package]\nname = "fallback"\nversion = "0.1.0"\n' > "$FALLBACK_REPO/Cargo.toml"
printf 'fallback output\n' > "$FALLBACK_TARGET/artifact"
printf '%s|%s\n' "$FALLBACK_REPO/Cargo.toml" "$FALLBACK_TARGET" >> "$MAP"
: > "$FALLBACK_LOG"
jq_calls_before=$(wc -l < "$JQ_LOG")
run_clean "$FALLBACK_HOME" "$NOJQ_BIN" 0 "$FALLBACK_LOG" > "$FALLBACK_OUT" || fail 'sed fallback run failed'
[ "$(wc -l < "$JQ_LOG")" -eq "$jq_calls_before" ] || fail 'jq unexpectedly ran in fallback fixture'
grep -Fq "target=$FALLBACK_TARGET mode=clean" "$FALLBACK_OUT" || fail 'sed fallback did not resolve target'
[ -z "$(find -P "$FALLBACK_TARGET" -mindepth 1 -print -quit)" ] || fail 'sed fallback target was not cleaned'
pass_pin 'sed metadata parser works when jq is absent from PATH' "$pin_t0"

pin_t0=$(date +%s%3N)
EMPTY_LOG=$CONTROL/empty-logger.log
EMPTY_OUT=$CONTROL/empty.out
: > "$EMPTY_LOG"
run_clean "$EMPTY_HOME" "$BIN:$PATH" 0 "$EMPTY_LOG" > "$EMPTY_OUT" || fail 'empty scan failed'
grep -Eq '^cargo-clean: run root=[^[:space:]]+ targets=0 cleaned=0 removed=0 skipped=0 failed=0 freed_bytes=0 duration_ms=[0-9]+$' "$EMPTY_OUT" || fail 'empty summary line'
[ "$(wc -l < "$EMPTY_OUT")" -eq 1 ] || fail 'empty run emitted more than its summary'
pass_pin 'empty discovery still journals one measured summary' "$pin_t0"

HARNESS_T1=$(date +%s%3N)
printf 'cargo-clean tests: %d/%d passed duration_ms=%d\n' "$passed" "$total" "$((HARNESS_T1 - HARNESS_T0))"
