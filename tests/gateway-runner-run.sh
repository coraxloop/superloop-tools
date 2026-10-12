#!/usr/bin/env bash
set -u

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER=${GATEWAY_RUNNER_TEST_BINARY:?GATEWAY_RUNNER_TEST_BINARY must name the configured runner}
TEST_ROOT=$(mktemp -d "${TMPDIR:-$HOME/.cache/tmp}/gateway-runner-tests.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/bin"
PASS_COUNT=0
export GATEWAY_RUNNER_REMOTE_WRAPPER=/opt/fixture/bin/report
export GATEWAY_RUNNER_RUST_ENV=/opt/fixture/rust-env.sh
export GATEWAY_RUNNER_REMOTE_PATH=/opt/fixture/bin:/usr/bin

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS $1"
}

fail() {
  echo "FAIL $1" >&2
  if [ -n "${CASE_OUT:-}" ] && [ -r "$CASE_OUT" ]; then
    sed 's/^/  stdout: /' "$CASE_OUT" >&2
  fi
  if [ -n "${CASE_ERR:-}" ] && [ -r "$CASE_ERR" ]; then
    sed 's/^/  stderr: /' "$CASE_ERR" >&2
  fi
  if [ -n "${CASE_LOG:-}" ] && [ -r "$CASE_LOG" ]; then
    sed 's/^/  ssh-log: /' "$CASE_LOG" >&2
  fi
  exit 1
}

cat > "$TEST_ROOT/bin/ssh" <<'FAKESSH'
#!/usr/bin/env bash
set -u

LOG=${FAKE_SSH_LOG:?FAKE_SSH_LOG is required}
STDIN_FILE=${FAKE_SSH_STDIN:?FAKE_SSH_STDIN is required}
MODE=${FAKE_SSH_MODE:?FAKE_SSH_MODE is required}
EXPECTED_ALIAS=${FAKE_SSH_EXPECT_ALIAS:?FAKE_SSH_EXPECT_ALIAS is required}
PID_FILE=${FAKE_SSH_PID_FILE:-}

{
  printf 'CALL'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >> "$LOG"

host=
while [ "$#" -gt 0 ]; do
  case $1 in
    -o)
      shift
      [ "$#" -gt 0 ] || exit 97
      shift
      ;;
    *)
      host=$1
      break
      ;;
  esac
done

cat > "$STDIN_FILE"

[ "$host" = "$EXPECTED_ALIAS" ] || exit 96
printf 'gateway stdout %s\nsecond line\n' "$MODE"

case $MODE in
  0)
    exit 0
    ;;
  124)
    exit 124
    ;;
  255)
    exit 255
    ;;
  sleep)
    [ -n "$PID_FILE" ] || exit 95
    printf '%s\n' "$$" > "$PID_FILE"
    exec sleep "${FAKE_SSH_SLEEP_SECONDS:-30}"
    ;;
  *)
    echo "unknown fake ssh mode: $MODE" >&2
    exit 98
    ;;
esac
FAKESSH
chmod +x "$TEST_ROOT/bin/ssh"

new_case() {
  CASE_DIR=$TEST_ROOT/$1
  CASE_OUT=$CASE_DIR/stdout
  CASE_ERR=$CASE_DIR/stderr
  CASE_LOG=$CASE_DIR/ssh.log
  CASE_STDIN=$CASE_DIR/stdin
  CASE_SSH_PID=$CASE_DIR/ssh.pid
  mkdir -p "$CASE_DIR"
}

run_runner() {
  local mode=$1
  local checkout=$2
  local target_mode=$3
  shift 3
  if invoke_runner "$mode" "$checkout" "$target_mode" "$@"; then
    STATUS=0
  else
    STATUS=$?
  fi
}

start_runner() {
  local mode=$1
  local checkout=$2
  local target_mode=$3
  shift 3
  if [ "$target_mode" = set ]; then
    PATH=$TEST_ROOT/bin:/usr/bin:/bin \
      FAKE_SSH_LOG=$CASE_LOG \
      FAKE_SSH_STDIN=$CASE_STDIN \
      FAKE_SSH_PID_FILE=$CASE_SSH_PID \
      FAKE_SSH_MODE=$mode \
      FAKE_SSH_EXPECT_ALIAS=server-alpha \
      GATEWAY_RUNNER_SSH=server-alpha \
      GATEWAY_RUNNER_LANES=/remote/lanes \
      LANE_GATEWAY_WALL_BUDGET_SECONDS=37 \
      LANE_GATEWAY_MIRROR_COMMIT=deadbeef1234 \
      CARGO_TARGET_DIR="$TEST_ROOT/target dir" \
      "$RUNNER" "$checkout" "$@" > "$CASE_OUT" 2> "$CASE_ERR" &
    RUNNER_PID=$!
  else
    env -u CARGO_TARGET_DIR \
      PATH=$TEST_ROOT/bin:/usr/bin:/bin \
      FAKE_SSH_LOG=$CASE_LOG \
      FAKE_SSH_STDIN=$CASE_STDIN \
      FAKE_SSH_PID_FILE=$CASE_SSH_PID \
      FAKE_SSH_MODE=$mode \
      FAKE_SSH_EXPECT_ALIAS=server-alpha \
      GATEWAY_RUNNER_SSH=server-alpha \
      GATEWAY_RUNNER_LANES=/remote/lanes \
      LANE_GATEWAY_WALL_BUDGET_SECONDS=37 \
      LANE_GATEWAY_MIRROR_COMMIT=deadbeef1234 \
      "$RUNNER" "$checkout" "$@" > "$CASE_OUT" 2> "$CASE_ERR" &
    RUNNER_PID=$!
  fi
}

invoke_runner() {
  local mode=$1
  local checkout=$2
  local target_mode=$3
  local -a ssh_setting=(GATEWAY_RUNNER_SSH=server-alpha)
  shift 3
  if [ "${RUNNER_SSH_UNSET:-0}" -eq 1 ]; then
    ssh_setting=(-u GATEWAY_RUNNER_SSH)
  fi
  if [ "$target_mode" = set ]; then
    env "${ssh_setting[@]}" \
      PATH=$TEST_ROOT/bin:/usr/bin:/bin \
      FAKE_SSH_LOG=$CASE_LOG \
      FAKE_SSH_STDIN=$CASE_STDIN \
      FAKE_SSH_PID_FILE=$CASE_SSH_PID \
      FAKE_SSH_MODE=$mode \
      FAKE_SSH_EXPECT_ALIAS=server-alpha \
      GATEWAY_RUNNER_LANES=/remote/lanes \
      LANE_GATEWAY_WALL_BUDGET_SECONDS=37 \
      LANE_GATEWAY_MIRROR_COMMIT=deadbeef1234 \
      CARGO_TARGET_DIR="$TEST_ROOT/target dir" \
      "$RUNNER" "$checkout" "$@" > "$CASE_OUT" 2> "$CASE_ERR"
  else
    env -u CARGO_TARGET_DIR "${ssh_setting[@]}" \
      PATH=$TEST_ROOT/bin:/usr/bin:/bin \
      FAKE_SSH_LOG=$CASE_LOG \
      FAKE_SSH_STDIN=$CASE_STDIN \
      FAKE_SSH_PID_FILE=$CASE_SSH_PID \
      FAKE_SSH_MODE=$mode \
      FAKE_SSH_EXPECT_ALIAS=server-alpha \
      GATEWAY_RUNNER_LANES=/remote/lanes \
      LANE_GATEWAY_WALL_BUDGET_SECONDS=37 \
      LANE_GATEWAY_MIRROR_COMMIT=deadbeef1234 \
      "$RUNNER" "$checkout" "$@" > "$CASE_OUT" 2> "$CASE_ERR"
  fi
}

expected_stdin() {
  local checkout=$1
  local target_mode=$2
  local q_checkout q_mirror q_commit q_budget q_target
  local target_line=:
  printf -v q_checkout '%q' "$checkout"
  printf -v q_mirror '%q' /remote/lanes/lane-one.git
  printf -v q_commit '%q' deadbeef1234
  printf -v q_budget '%q' 37
  printf -v q_target '%q' "$TEST_ROOT/target dir"
  if [ "$target_mode" = set ]; then
    target_line="export CARGO_TARGET_DIR=$q_target"
  fi
  cat <<EXPECTED
set -euo pipefail
. /opt/fixture/rust-env.sh
export PATH=/opt/fixture/bin:/usr/bin
$target_line
cd $q_checkout
git fetch -q $q_mirror "+refs/lanes/gateway/lane-one:refs/gateway/incoming"
git checkout -qf $q_commit
git clean -qfd
timeout $q_budget cargo test --package lane-gateway -- case\\ name
EXPECTED
}

assert_argv() {
  local name=$1
  awk -F '\t' 'BEGIN { ok=0 } $1 == "CALL" { ok = (NF == 9 && $2 == "-o" && $3 == "ServerAliveInterval=30" && $4 == "-o" && $5 == "ServerAliveCountMax=4" && $6 == "-o" && $7 == "ConnectTimeout=30" && $8 == "server-alpha" && $9 == "/opt/fixture/bin/report bash -s") } END { exit ok ? 0 : 1 }' "$CASE_LOG" || fail "$name argv"
}

assert_stdin() {
  local name=$1
  local checkout=$2
  local target_mode=$3
  expected_stdin "$checkout" "$target_mode" > "$CASE_DIR/expected-stdin"
  cmp -s "$CASE_DIR/expected-stdin" "$CASE_STDIN" || fail "$name stdin"
}

expected_stdout() {
  printf 'gateway stdout %s\nsecond line\n' "$1"
}

assert_stdout() {
  local name=$1
  local mode=$2
  expected_stdout "$mode" > "$CASE_DIR/expected-stdout"
  cmp -s "$CASE_DIR/expected-stdout" "$CASE_OUT" || fail "$name stdout"
}

assert_empty_stderr() {
  local name=$1
  printf '' | cmp -s - "$CASE_ERR" || fail "$name stderr"
}

wait_for_file() {
  local path=$1
  local unused
  for unused in {1..40}; do
    [ -s "$path" ] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_gone() {
  local pid=$1
  local unused
  for unused in {1..40}; do
    [ ! -e "/proc/$pid" ] && return 0
    sleep 0.05
  done
  return 1
}

checkout=$TEST_ROOT/checkouts/lane-one
mkdir -p "$checkout"

new_case missing-ssh
RUNNER_SSH_UNSET=1 run_runner 0 "$checkout" set true
[ ! -e "$CASE_LOG" ] || fail "missing SSH alias launched ssh"
[ "$STATUS" -eq 2 ] || fail "missing SSH alias status was $STATUS"
printf '%s\n' 'gateway-runner: missing GATEWAY_RUNNER_SSH' | cmp -s - "$CASE_ERR" || fail "missing SSH alias stderr"
pass "missing SSH alias refuses before transport"

for setting in GATEWAY_RUNNER_REMOTE_WRAPPER GATEWAY_RUNNER_RUST_ENV; do
  new_case "missing-$setting"
  saved=${!setting}
  export "$setting="
  run_runner 0 "$checkout" set true
  [ ! -e "$CASE_LOG" ] || fail "missing $setting launched ssh"
  [ "$STATUS" -eq 2 ] || fail "missing $setting status was $STATUS"
  printf '%s\n' "gateway-runner: missing $setting" | cmp -s - "$CASE_ERR" || fail "missing $setting stderr"
  export "$setting=$saved"
  pass "missing $setting refuses before transport"
done

new_case exit-0
run_runner 0 "$checkout" set cargo test --package lane-gateway -- "case name"
[ "$STATUS" -eq 0 ] || fail "exit-0 status was $STATUS"
assert_argv exit-0
assert_stdin exit-0 "$checkout" set
assert_stdout exit-0 0
assert_empty_stderr exit-0
pass "exit 0 preserves argv stdin stdout and quiet stderr"

new_case exit-255
run_runner 255 "$checkout" set cargo test --package lane-gateway -- "case name"
[ "$STATUS" -eq 255 ] || fail "exit-255 status was $STATUS"
assert_argv exit-255
assert_stdin exit-255 "$checkout" set
assert_stdout exit-255 255
printf '%s\n' "gateway-runner: ssh transport failed (exit 255) to server-alpha" | cmp -s - "$CASE_ERR" || fail "exit-255 stderr"
pass "exit 255 is named and preserved"

new_case exit-124
run_runner 124 "$checkout" set cargo test --package lane-gateway -- "case name"
[ "$STATUS" -eq 124 ] || fail "exit-124 status was $STATUS"
assert_argv exit-124
assert_stdin exit-124 "$checkout" set
assert_stdout exit-124 124
assert_empty_stderr exit-124
pass "exit 124 is preserved without transport stderr"

new_case no-target
run_runner 0 "$checkout" unset cargo test --package lane-gateway -- "case name"
[ "$STATUS" -eq 0 ] || fail "no-target status was $STATUS"
assert_argv no-target
assert_stdin no-target "$checkout" unset
assert_stdout no-target 0
assert_empty_stderr no-target
pass "unset CARGO_TARGET_DIR keeps colon target export"

new_case signal-term
start_runner sleep "$checkout" set cargo test --package lane-gateway -- "case name"
wait_for_file "$CASE_SSH_PID" || fail "signal-term pid file"
ssh_pid=$(cat "$CASE_SSH_PID")
kill -TERM "$RUNNER_PID"
if wait "$RUNNER_PID"; then
  STATUS=0
else
  STATUS=$?
fi
[ "$STATUS" -eq 143 ] || fail "signal-term status was $STATUS"
wait_for_gone "$ssh_pid" || fail "signal-term fake ssh still alive"
assert_argv signal-term
assert_stdin signal-term "$checkout" set
assert_stdout signal-term sleep
assert_empty_stderr signal-term
pass "SIGTERM forwards to fake ssh and preserves signal exit"

echo "PASS all $PASS_COUNT gateway-runner cases"
