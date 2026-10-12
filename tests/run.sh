#!/usr/bin/env bash
set -u

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT=${CORRESPONDENCE_TEST_BINARY:?CORRESPONDENCE_TEST_BINARY must name the built client}
TEST_ROOT=$(mktemp -d "${TMPDIR:-$HOME/.cache/tmp}/correspondence-tests.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/bin"
ln -s "$ROOT/tests/fake-ssh" "$TEST_ROOT/bin/ssh"
PASS_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS $1"
}

fail() {
  echo "FAIL $1" >&2
  if [ -n "${CASE_OUT:-}" ] && [ -r "$CASE_OUT" ]; then
    sed 's/^/  captured: /' "$CASE_OUT" >&2
  fi
  if [ -r "${CASE_LOG:-}" ]; then
    sed 's/^/  transport: /' "$CASE_LOG" >&2
  fi
  exit 1
}

new_case() {
  CASE_DIR=$TEST_ROOT/$1
  CASE_HOME=$CASE_DIR/home
  CASE_OUT=$CASE_DIR/output
  CASE_LOG=$CASE_DIR/ssh.log
  mkdir -p "$CASE_HOME/.ssh"
  printf "%s\n" "fixture host key" > "$CASE_HOME/.ssh/known_hosts.clients"
  printf '%s\n' 'Host alpha beta' '  HostName 192.0.2.1' 'Host *' '  BatchMode yes' > "$CASE_HOME/.ssh/config"
}

run_feed() {
  local mode=$1 deadline=$2 poll=$3
  shift 3
  prepare_transport "$mode"
  if HOME=$CASE_HOME PATH=$TEST_ROOT/bin:/usr/bin:/bin FAKE_SSH_LOG=$CASE_LOG FAKE_SSH_MODE=$mode FAKE_SSH_SNAPSHOT=$SNAPSHOT CORRESPONDENCE_FEED_DEADLINE_MS=$deadline CORRESPONDENCE_FEED_POLL_MS=$poll "$CLIENT" poll --advance-cursor --known-hosts "$CASE_HOME/.ssh/known_hosts.clients" "$@" > "$CASE_OUT" 2>&1; then
    STATUS=0
  else
    STATUS=$?
  fi
}

run_watch() {
  local mode=$1 watch_deadline=$2 feed_deadline=$3 poll=$4
  shift 4
  prepare_transport "$mode"
  if HOME=$CASE_HOME PATH=$TEST_ROOT/bin:/usr/bin:/bin FAKE_SSH_LOG=$CASE_LOG FAKE_SSH_MODE=$mode FAKE_SSH_SNAPSHOT=$SNAPSHOT CORRESPONDENCE_WATCH_DEADLINE_MS=$watch_deadline CORRESPONDENCE_FEED_DEADLINE_MS=$feed_deadline CORRESPONDENCE_FEED_POLL_MS=$poll "$CLIENT" watch --advance-cursor --known-hosts "$CASE_HOME/.ssh/known_hosts.clients" "$@" > "$CASE_OUT" 2>&1; then
    STATUS=0
  else
    STATUS=$?
  fi
}

prepare_transport() {
  local mode=$1 host status observed
  SNAPSHOT=
  [ "$mode" != slow ] || return 0
  SNAPSHOT=$CASE_DIR/transport-ready
  mkdir -p "$SNAPSHOT"
  for host in alpha beta; do
    status=0
    FAKE_SSH_LOG=$SNAPSHOT/setup.log FAKE_SSH_MODE=$mode FAKE_SSH_SNAPSHOT= \
      "$TEST_ROOT/bin/ssh" "$host" fixture > "$SNAPSHOT/$host.reply" || status=$?
    printf '%s\n' "$status" > "$SNAPSHOT/$host.status"
    observed=0
    FAKE_SSH_LOG=$SNAPSHOT/setup.log FAKE_SSH_SNAPSHOT=$SNAPSHOT \
      "$TEST_ROOT/bin/ssh" "$host" fixture > "$SNAPSHOT/observed" || observed=$?
    [ "$observed" -eq "$status" ] || fail "transport readiness status"
    cmp "$SNAPSHOT/$host.reply" "$SNAPSHOT/observed" || fail "transport readiness bytes"
  done
}

read_feed_counts() {
  local duration
  duration=$(grep '^FEED-DURATION-MS ' "$CASE_OUT")
  if [[ $duration =~ ssh_fails=([0-9]+)[[:space:]]polls=([0-9]+)$ ]]; then
    REPORTED_FAILS=${BASH_REMATCH[1]}
    REPORTED_POLLS=${BASH_REMATCH[2]}
  else
    fail "missing feed duration counts"
  fi
  if [ -f "$CASE_LOG" ]; then
    RECORDED_CALLS=$(grep -c '^CALL' "$CASE_LOG" || true)
  else
    RECORDED_CALLS=0
  fi
  [ "$RECORDED_CALLS" -le "$REPORTED_POLLS" ] || fail "ssh call log exceeded reported polls"
}

new_case all-fail
run_feed all-fail 250 50 alpha
[ "$STATUS" -eq 1 ] || fail "all-fail census exit was $STATUS"
read_feed_counts
[ "$REPORTED_POLLS" -gt 0 ] && [ "$REPORTED_FAILS" -eq "$REPORTED_POLLS" ] || fail "all-fail reported counts"
[ "$(tail -n 1 "$CASE_OUT")" = "FEED-FAILED all ssh polls failed: ssh_fails=$REPORTED_FAILS polls=$REPORTED_POLLS" ] || fail "all-fail final verdict"
pass "all-fail census is non-zero with a final FEED-FAILED verdict"

new_case partial
run_feed partial 350 50 alpha beta
[ "$STATUS" -eq 0 ] || fail "partial census exit was $STATUS"
read_feed_counts
[ "$REPORTED_FAILS" -gt 0 ] && [ "$REPORTED_FAILS" -lt "$REPORTED_POLLS" ] || fail "partial census reported counts"
grep -q "^FEED-WARNING partial ssh failure: ssh_fails=$REPORTED_FAILS polls=$REPORTED_POLLS$" "$CASE_OUT" || fail "partial census warning"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-EMPTY ] || fail "partial census empty verdict"
pass "partial-fail census is zero with a named warning"

new_case quiet
run_feed empty 200 50 alpha
[ "$STATUS" -eq 0 ] || fail "quiet success exit was $STATUS"
read_feed_counts
[ "$REPORTED_POLLS" -gt 0 ] && [ "$REPORTED_FAILS" -eq 0 ] || fail "quiet success reported counts"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-EMPTY ] || fail "quiet success verdict"
if grep -Eq '^FEED-(WARNING|FAILED)' "$CASE_OUT"; then
  fail "quiet success carried a warning or failure"
fi
pass "quiet successful polling ends FEED-EMPTY"

new_case poll-floor
run_feed empty 40 50 alpha
[ "$STATUS" -eq 0 ] || fail "poll floor exit was $STATUS"
read_feed_counts
[ "$REPORTED_FAILS" -eq 0 ] && [ "$REPORTED_POLLS" -eq 0 ] || fail "poll floor reported counts"
[ ! -s "$CASE_LOG" ] || fail "poll floor reached ssh"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-EMPTY ] || fail "poll floor verdict"
pass "a deadline below the poll floor ends quietly without ssh"

new_case deadline
DEADLINE_MS=300
DEADLINE_JITTER_MS=5000
run_feed slow "$DEADLINE_MS" 50 alpha
[ "$STATUS" -eq 1 ] || fail "slow deadline exit was $STATUS"
REPORTED_MS=$(awk '/^FEED-DURATION-MS / { print $2 }' "$CASE_OUT")
[ "$REPORTED_MS" -ge 250 ] && [ "$REPORTED_MS" -lt "$((DEADLINE_MS + DEADLINE_JITTER_MS))" ] || fail "reported deadline duration: ${REPORTED_MS}ms"
pass "slow ssh is cut off by the feeder deadline (${REPORTED_MS}ms recorded)"

awk -F '\t' 'BEGIN { calls=0 } $1 == "CALL" { calls++; connect=alive=count=0; for (i=2; i<NF; i++) if ($i == "-o") { if ($(i+1) == "ConnectTimeout=5") connect=1; if ($(i+1) == "ServerAliveInterval=5") alive=1; if ($(i+1) == "ServerAliveCountMax=1") count=1 } if (!(connect && alive && count)) bad=1 } END { exit calls == 0 || bad }' "$CASE_LOG" || fail "ssh liveness options"
pass "every recorded ssh argv has ConnectTimeout=5 and ServerAlive keepalives"

new_case no-hosts
run_feed empty 200 50
[ "$STATUS" -eq 1 ] || fail "no hosts exit was $STATUS"
grep -q "required arguments were not provided" "$CASE_OUT" || fail "missing-host diagnostic"
[ ! -e "$CASE_LOG" ] || fail "no hosts reached ssh"
pass "no hosts refuse before ssh"

new_case blank-host-single
run_feed empty 200 50 ' '
[ "$STATUS" -eq 1 ] || fail "single blank host exit was $STATUS"
grep -Eq "^FEED-FAILED unknown ssh alias: .* wall_ms=[0-9]+$" "$CASE_OUT" || fail "invalid-host diagnostic"
[ ! -e "$CASE_LOG" ] || fail "single blank host reached ssh"
pass "single blank host refuses before ssh"

new_case blank-host-pair
run_feed empty 200 50 ' ' '  '
[ "$STATUS" -eq 1 ] || fail "blank host pair exit was $STATUS"
grep -Eq "^FEED-FAILED unknown ssh alias: .* wall_ms=[0-9]+$" "$CASE_OUT" || fail "invalid-host diagnostic"
[ ! -e "$CASE_LOG" ] || fail "blank host pair reached ssh"
pass "blank host pair refuses before ssh"

new_case blank-host-mixed
run_feed empty 200 50 alpha ''
[ "$STATUS" -eq 1 ] || fail "mixed blank host exit was $STATUS"
grep -Eq "^FEED-FAILED unknown ssh alias: .* wall_ms=[0-9]+$" "$CASE_OUT" || fail "invalid-host diagnostic"
[ ! -e "$CASE_LOG" ] || fail "mixed blank host reached ssh"
pass "blank host among aliases refuses before ssh"

new_case unknown-alias
run_feed empty 200 50 missing-alias
[ "$STATUS" -eq 1 ] || fail "unknown alias exit was $STATUS"
grep -Eq '^FEED-FAILED unknown ssh alias: missing-alias wall_ms=[0-9]+$' "$CASE_OUT" || fail "unknown alias verdict"
[ ! -e "$CASE_LOG" ] || fail "unknown alias reached ssh"
pass "unknown alias is named and fatal before polling"

new_case watch-no-hosts
run_watch empty 200 100 50
[ "$STATUS" -eq 1 ] || fail "watch no hosts exit was $STATUS"
grep -q "required arguments were not provided" "$CASE_OUT" || fail "missing-host diagnostic"
[ ! -e "$CASE_LOG" ] || fail "watch no hosts reached ssh"
pass "supervisor without hosts propagates refusal before ssh"

new_case failed-cursor
mkdir -p "$CASE_HOME/dev/superloop-tools/correspondence-watch"
printf '%s' cursor-old > "$CASE_HOME/dev/superloop-tools/correspondence-watch/cursor-alpha"
run_feed all-fail 200 50 alpha
[ "$STATUS" -eq 1 ] || fail "failed cursor poll exit was $STATUS"
[ "$(cat "$CASE_HOME/dev/superloop-tools/correspondence-watch/cursor-alpha")" = cursor-old ] || fail "failed poll changed cursor"
pass "failed polls leave cursor files untouched"

new_case admin-only
run_feed admin-only 120 20 alpha
[ "$STATUS" -eq 0 ] || fail "admin-only exit was $STATUS"
grep -q '^host=alpha from=admin sender=test file=/messages/alpha-admin$' "$CASE_OUT" || fail "admin-only delta output"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-EMPTY ] || fail "admin-only verdict"
pass "admin-only delta prints and ends FEED-EMPTY"
[ "$(cat "$CASE_HOME/dev/superloop-tools/correspondence-watch/cursor-alpha")" = cursor-alpha-admin-new ] || fail "admin-only delta did not advance cursor"
pass "admin-only deltas advance cursor files"

new_case mixed
run_feed mixed 200 10 alpha
[ "$STATUS" -eq 0 ] || fail "mixed exit was $STATUS"
grep -q '^host=alpha from=admin sender=test file=/messages/alpha-admin$' "$CASE_OUT" || fail "mixed admin output"
grep -q '^host=alpha from=user sender=test file=/messages/alpha-user$' "$CASE_OUT" || fail "mixed user output"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-CONTENT ] || fail "mixed verdict"
pass "mixed admin and user delta prints both and ends FEED-CONTENT"

new_case user-only
run_feed user-only 200 10 alpha
[ "$STATUS" -eq 0 ] || fail "user-only exit was $STATUS"
grep -q '^host=alpha from=user sender=test file=/messages/alpha$' "$CASE_OUT" || fail "user-only delta output"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-CONTENT ] || fail "user-only verdict"
pass "user-only delta remains FEED-CONTENT"

new_case successful-cursor
mkdir -p "$CASE_HOME/dev/superloop-tools/correspondence-watch"
printf '%s' cursor-old > "$CASE_HOME/dev/superloop-tools/correspondence-watch/cursor-alpha"
run_feed content 200 10 alpha
[ "$STATUS" -eq 0 ] || fail "successful cursor poll exit was $STATUS"
[ "$(cat "$CASE_HOME/dev/superloop-tools/correspondence-watch/cursor-alpha")" = cursor-alpha-new ] || fail "successful poll did not advance cursor"
pass "successful polls advance cursor files"

new_case watch-content
run_watch content 500 100 10 alpha
[ "$STATUS" -eq 0 ] || fail "watch content exit was $STATUS"
grep -q '^host=alpha from=user sender=test file=/messages/alpha$' "$CASE_OUT" || fail "watch content output"
[ "$(tail -n 1 "$CASE_OUT")" = FEED-CONTENT ] || fail "watch content verdict"
pass "supervisor content path exits 0 and prints feeder output"

new_case watch-admin-only
run_watch admin-only 250 500 100 alpha
[ "$STATUS" -eq 2 ] || fail "watch admin-only exit was $STATUS"
[ -s "$CASE_LOG" ] || fail "watch admin-only never polled"
grep -q '^host=alpha from=admin sender=test file=/messages/alpha-admin$' "$CASE_OUT" || fail "watch omitted admin records"
grep -Eq '^FEED-DURATION-MS [0-9]+$' "$CASE_OUT" || fail "watch deadline omitted wall"
pass "supervisor publishes admin-only deltas before deadline exit 2"

new_case watch-failure
run_watch all-fail 500 200 50 alpha
[ "$STATUS" -eq 1 ] || fail "watch failure exit was $STATUS"
grep -q '^FEED-FAILED all ssh polls failed:' "$CASE_OUT" || fail "watch failure output"
pass "supervisor loud-failure path propagates exit 1 and verdict"

new_case watch-deadline
run_watch empty 500 150 50 alpha
[ "$STATUS" -eq 2 ] || fail "watch deadline exit was $STATUS"
grep -Eq '^FEED-DURATION-MS [0-9]+$' "$CASE_OUT" || fail "watch deadline omitted wall"
[ "$(wc -l < "$CASE_OUT")" -eq 1 ] || fail "empty watch emitted records"
[ "$(grep -c '^CALL' "$CASE_LOG")" -gt 1 ] || fail "watcher did not re-invoke feeder"
pass "supervisor deadline path exits 2 with its wall after repeated polls"

echo "PASS all $PASS_COUNT correspondence harness pins"
