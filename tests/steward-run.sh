#!/usr/bin/env bash
set -u
export LC_ALL=C

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
EXPORTER=${STEWARD_TEST_EXPORTER:?Meson or Cargo must bind the configured transcript exporter}
CLIENT=${STEWARD_TEST_BINARY:?Meson or Cargo must bind the built steward client}
TEST_ROOT=$(mktemp -d "${TMPDIR:-$HOME/.cache/tmp}/steward-tests.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
TEST_BIN=$TEST_ROOT/bin
mkdir -p "$TEST_BIN"
ln -s "$ROOT/tests/steward-fake-ssh" "$TEST_BIN/ssh"
ln -s "$ROOT/tests/steward-fake-exporter" "$TEST_BIN/transcript-export"
ln -s "$ROOT/tests/steward-fake-claude" "$TEST_BIN/claude"
PASS_COUNT=0
REPLAY_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS $1"
}

fail() {
  echo "FAIL $1" >&2
  if [ -n "${CASE_OUT:-}" ] && [ -r "$CASE_OUT" ]; then
    sed 's/^/  captured: /' "$CASE_OUT" >&2
  fi
  exit 1
}

new_case() {
  CASE_DIR=$TEST_ROOT/$1
  CASE_HOME=$CASE_DIR/home
  CASE_OUT=$CASE_DIR/output
  CASE_SSH_LOG=$CASE_DIR/ssh.log
  CASE_CLAUDE_LOG=$CASE_DIR/claude.log
  CASE_TREES=$CASE_DIR/trees
  mkdir -p "$CASE_HOME/.ssh" "$CASE_TREES/alpha" "$CASE_TREES/beta"
  : > "$CASE_HOME/keys"
  printf '%s\n' \
    'Host alpha-steward beta-steward' \
    '  HostName 192.0.2.1' \
    'Host *' \
    '  BatchMode yes' > "$CASE_HOME/.ssh/config"
}

write_record() {
  local server=$1 relative=$2 record=$3 target
  target=$CASE_TREES/$server/$relative
  mkdir -p "$(dirname -- "$target")"
  printf '%s\n' "$record" > "$target"
}

append_record() {
  local server=$1 relative=$2 record=$3 target
  target=$CASE_TREES/$server/$relative
  printf '%s\n' "$record" >> "$target"
}

prepare_transport() {
  local server=$1
  [ -d "$CASE_TREES/$server" ] || return 0
  local snapshot=$CASE_DIR/transport-ready relative size identity stamp
  mkdir -p "$snapshot"
  # Prepare both poll and watch replies before the production deadlines start.
  # Preserve source identities and stamps for replacement/truncation checks.
  FAKE_STEWARD_TREE_BASE=$CASE_TREES FAKE_STEWARD_ACTIVE_SERVER=$server \
    "$TEST_BIN/transcript-export" list > "$snapshot/list" || fail "exporter readiness"
  while IFS=$'\t' read -r relative size identity stamp; do
    [ -n "$relative" ] || continue
    mkdir -p "$snapshot/$(dirname -- "$relative")"
    cp -- "$CASE_TREES/$server/$relative" "$snapshot/$relative"
  done < "$snapshot/list"
  # Observe the actual stub's list/read transport before the client arms either
  # deadline; preparing exporter bytes alone does not establish this contract.
  FAKE_STEWARD_SSH_LOG=$snapshot/setup.log FAKE_STEWARD_SSH_SNAPSHOT=$snapshot \
    "$TEST_BIN/ssh" "$server-steward" "'$TEST_BIN/transcript-export' list" > "$snapshot/observed" \
    || fail "list transport readiness"
  cmp "$snapshot/list" "$snapshot/observed" || fail "list transport bytes"
  while IFS=$'\t' read -r relative size identity stamp; do
    [ -n "$relative" ] || continue
    FAKE_STEWARD_SSH_LOG=$snapshot/setup.log FAKE_STEWARD_SSH_SNAPSHOT=$snapshot \
      "$TEST_BIN/ssh" "$server-steward" "'$TEST_BIN/transcript-export' read '$relative' 0 $size" > "$snapshot/observed" \
      || fail "read transport readiness"
    cmp "$snapshot/$relative" "$snapshot/observed" || fail "read transport bytes"
  done < "$snapshot/list"
}

verify_transport() {
  local server=$1 line remote snapshot=$CASE_DIR/transport-ready
  [ -f "$CASE_SSH_LOG" ] || return 0
  while IFS= read -r line; do
    [[ $line == CALL$'\t'* ]] || fail "transport log record"
    remote=${line##*$'\t'}
    [[ $remote == "'$TEST_BIN/transcript-export' "* ]] || fail "remote exporter path and quoting"
    # Exercise the client's exact command against the original exporter, after
    # the timed client has exited. Failure modes have no reply; compare their
    # commands against the normal snapshot too, without injecting the failure.
    FAKE_STEWARD_TREE_BASE=$CASE_TREES FAKE_STEWARD_ACTIVE_SERVER=$server \
      bash -c "$remote" > "$snapshot/exporter-observed" || fail "logged exporter command"
    FAKE_STEWARD_SSH_LOG=$snapshot/replay.log FAKE_STEWARD_SSH_SNAPSHOT=$snapshot \
      "$TEST_BIN/ssh" "$server-steward" "$remote" > "$snapshot/replay-observed" \
      || fail "logged snapshot command"
    cmp "$snapshot/exporter-observed" "$snapshot/replay-observed" || fail "logged exporter bytes"
    REPLAY_COUNT=$((REPLAY_COUNT + 1))
  done < "$CASE_SSH_LOG"
}

run_feed() {
  local server=$1 deadline=${2:-800} mode=${3:-run} read_timeout=${4:-300}
  prepare_transport "$server"
  rm -f "$CASE_SSH_LOG"
  FEED_STARTED=$(date +%s%3N)
  if HOME=$CASE_HOME PATH=$TEST_BIN:/usr/bin:/bin \
    TMPDIR='' \
    FAKE_STEWARD_SSH_LOG=$CASE_SSH_LOG \
    FAKE_STEWARD_SSH_MODE=$mode \
    FAKE_STEWARD_SSH_SNAPSHOT=$CASE_DIR/transport-ready \
    FAKE_STEWARD_TREE_BASE=$CASE_TREES \
    FAKE_STEWARD_CLAUDE_LOG=$CASE_CLAUDE_LOG \
    STEWARD_TRANSCRIPT_FEED_DEADLINE_MS=$deadline \
    STEWARD_TRANSCRIPT_READ_TIMEOUT_MS=$read_timeout \
    STEWARD_TRANSCRIPT_READ_MAX_BYTES=64 \
    STEWARD_TRANSCRIPT_TAIL_BYTES=32 \
    "$CLIENT" transcript poll --exporter "$TEST_BIN/transcript-export" --advance-cursor --known-hosts "$CASE_HOME/keys" "$server" > "$CASE_OUT" 2>&1; then
    STATUS=0
  else
    STATUS=$?
  fi
  FEED_FINISHED=$(date +%s%3N)
  verify_transport "$server"
}

run_watch() {
  local server=$1 watch_deadline=$2 feed_deadline=$3 poll=$4 mode=${5:-run}
  prepare_transport "$server"
  rm -f "$CASE_SSH_LOG"
  if HOME=$CASE_HOME PATH=$TEST_BIN:/usr/bin:/bin \
    TMPDIR='' \
    FAKE_STEWARD_SSH_LOG=$CASE_SSH_LOG \
    FAKE_STEWARD_SSH_MODE=$mode \
    FAKE_STEWARD_SSH_SNAPSHOT=$CASE_DIR/transport-ready \
    FAKE_STEWARD_TREE_BASE=$CASE_TREES \
    FAKE_STEWARD_CLAUDE_LOG=$CASE_CLAUDE_LOG \
    STEWARD_TRANSCRIPT_WATCH_DEADLINE_MS=$watch_deadline \
    STEWARD_TRANSCRIPT_FEED_DEADLINE_MS=$feed_deadline \
    STEWARD_TRANSCRIPT_WATCH_POLL_MS=$poll \
    STEWARD_TRANSCRIPT_READ_TIMEOUT_MS=100 \
    "$CLIENT" transcript watch --exporter "$TEST_BIN/transcript-export" --advance-cursor --known-hosts "$CASE_HOME/keys" "$server" > "$CASE_OUT" 2>&1; then
    STATUS=0
  else
    STATUS=$?
  fi
  verify_transport "$server"
}

run_send() {
  local server=$1
  shift
  if HOME=$CASE_HOME PATH=$TEST_BIN:/usr/bin:/bin \
    FAKE_STEWARD_SSH_LOG=$CASE_SSH_LOG \
    FAKE_STEWARD_TREE_BASE=$CASE_TREES \
    FAKE_STEWARD_CLAUDE_LOG=$CASE_CLAUDE_LOG \
    "$CLIENT" send --exporter "$TEST_BIN/transcript-export" --known-hosts "$CASE_HOME/keys" "$server" "$@" > "$CASE_OUT" 2> "$CASE_OUT.error"; then
    STATUS=0
  else
    STATUS=$?
    cat "$CASE_OUT.error" >> "$CASE_OUT"
  fi
}

new_case exporter-contract
EXPORT_TREE=$CASE_DIR/export-root
mkdir -p "$EXPORT_TREE/project/nested"
printf '%s\n' '{"type":"user","message":"export me"}' > "$EXPORT_TREE/project/nested/session.jsonl"
EXPORT_COPY=$CASE_DIR/transcript-export
cp "$EXPORTER" "$EXPORT_COPY"
chmod 0755 "$EXPORT_COPY"
if STEWARD_PROJECTS_ROOT= "$EXPORT_COPY" list > "$CASE_OUT" 2>&1; then STATUS=0; else STATUS=$?; fi
[ "$STATUS" -ne 0 ] || fail "exporter accepted empty projects root override"
grep -q 'STEWARD_PROJECTS_ROOT is required' "$CASE_OUT" || fail "empty root diagnostic"
export STEWARD_PROJECTS_ROOT=$EXPORT_TREE
if LIST=$($EXPORT_COPY list 2> "$CASE_OUT"); then STATUS=0; else STATUS=$?; fi
[ "$STATUS" -eq 0 ] || fail "exporter list status was $STATUS"
printf '%s\n' "$LIST" | grep -Eq '^project/nested/session\.jsonl[[:space:]][0-9]+[[:space:]][0-9]+:[0-9]+[[:space:]][0-9]+:[0-9]+$' ||
  fail "exporter list wire contract"
if READ=$($EXPORT_COPY read project/nested/session.jsonl 0 8 2> "$CASE_OUT"); then STATUS=0; else STATUS=$?; fi
[ "$STATUS" -eq 0 ] && [ "$READ" = '{"type":' ] || fail "exporter raw read contract"
if $EXPORT_COPY read ../escape.jsonl 0 1 > "$CASE_OUT" 2>&1; then STATUS=0; else STATUS=$?; fi
[ "$STATUS" -ne 0 ] || fail "exporter accepted lexical escape"
OUTSIDE=$CASE_DIR/outside.jsonl
printf '%s\n' outside > "$OUTSIDE"
ln -s "$OUTSIDE" "$EXPORT_TREE/project/outside.jsonl"
if $EXPORT_COPY list > "$CASE_OUT" 2>&1; then STATUS=0; else STATUS=$?; fi
[ "$STATUS" -ne 0 ] || fail "exporter accepted outbound symlink"
pass "exporter pins fixed list/read format, nested files, lexical containment, and outbound-symlink refusal"

new_case append-delivery
FIRST='{"type":"user","message":"first prompt"}'
SECOND='{"type":"assistant","decision":"inspect state"}'
THIRD='{"type":"assistant","message":"append delivered"}'
write_record alpha project/session-a.jsonl "$FIRST"
append_record alpha project/session-a.jsonl "$SECOND"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "initial append feed status was $STATUS"
[ "$(grep -c '^server=alpha path=project/session-a.jsonl off=' "$CASE_OUT")" -eq 2 ] ||
  fail "initial records were not delivered once"
[ "$(tail -n 1 "$CASE_OUT")" = STEWARD-TRANSCRIPT-CONTENT ] || fail "initial content verdict"
INITIAL_SIZE=$(wc -c < "$CASE_TREES/alpha/project/session-a.jsonl")
append_record alpha project/session-a.jsonl "$THIRD"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "append feed status was $STATUS"
grep -q "^server=alpha path=project/session-a.jsonl off=$INITIAL_SIZE-.*append delivered" "$CASE_OUT" ||
  fail "appended record offset or content"
[ "$(grep -c '^server=alpha path=project/session-a.jsonl off=' "$CASE_OUT")" -eq 1 ] ||
  fail "append replayed old records"
pass "append delivery emits only newly acknowledged JSONL records with byte offsets"

CURSOR=$CASE_HOME/dev/superloop-tools/steward-transcript-watch/cursor-alpha
cp "$CURSOR" "$CASE_DIR/cursor-before-empty"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "empty repeat status was $STATUS"
[ "$(tail -n 1 "$CASE_OUT")" = STEWARD-TRANSCRIPT-EMPTY ] || fail "empty repeat verdict"
if grep -q '^server=alpha path=' "$CASE_OUT"; then fail "empty repeat replayed content"; fi
cmp -s "$CURSOR" "$CASE_DIR/cursor-before-empty" || fail "empty repeat changed cursor"
pass "empty repeat does not replay records or move its cursor"

new_case rotation
write_record alpha project/session-a.jsonl '{"type":"user","message":"before rotation"}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "rotation setup status was $STATUS"
REPLACEMENT=$CASE_DIR/replacement.jsonl
printf '%s\n' '{"type":"assistant","message":"after rotation"}' > "$REPLACEMENT"
mv "$REPLACEMENT" "$CASE_TREES/alpha/project/session-a.jsonl"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "rotation status was $STATUS"
grep -q '^STEWARD-TRANSCRIPT-FINDING server=alpha kind=replacement path=project/session-a.jsonl ' "$CASE_OUT" ||
  fail "rotation replacement finding"
grep -q 'after rotation' "$CASE_OUT" || fail "rotated content delivery"
grep -q '^STEWARD-TRANSCRIPT-WARNING ' "$CASE_OUT" || fail "rotation warning verdict"
pass "file-identity rotation is reported and the replacement is read from offset zero"

new_case truncation
write_record alpha project/session-a.jsonl '{"type":"user","message":"long first record"}'
append_record alpha project/session-a.jsonl '{"type":"assistant","message":"long second record"}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "truncation setup status was $STATUS"
CURSOR=$CASE_HOME/dev/superloop-tools/steward-transcript-watch/cursor-alpha
cp "$CURSOR" "$CASE_DIR/cursor-before-truncation"
printf '%s\n' '{}' > "$CASE_TREES/alpha/project/session-a.jsonl"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "truncation finding status was $STATUS"
grep -q '^STEWARD-TRANSCRIPT-FINDING server=alpha kind=truncation ' "$CASE_OUT" ||
  fail "truncation was not a finding"
grep -q '^STEWARD-TRANSCRIPT-WARNING ' "$CASE_OUT" || fail "truncation warning verdict"
cmp -s "$CURSOR" "$CASE_DIR/cursor-before-truncation" || fail "truncation advanced cursor"
pass "truncation is a warning finding and leaves acknowledgment untouched"

new_case cursor-regression
write_record alpha project/session-a.jsonl '{"type":"user","message":"cursor high water"}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "cursor regression setup status was $STATUS"
CURSOR=$CASE_HOME/dev/superloop-tools/steward-transcript-watch/cursor-alpha
awk -F '\t' 'BEGIN { OFS="\t" } $1 == "F" { $4=0; $8=0; $9="-" } { print }' \
  "$CURSOR" > "$CASE_DIR/regressed"
mv "$CASE_DIR/regressed" "$CURSOR"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "cursor regression status was $STATUS"
grep -q '^STEWARD-TRANSCRIPT-FINDING server=alpha kind=cursor-regression ' "$CASE_OUT" ||
  fail "cursor regression finding"
grep -q '^STEWARD-TRANSCRIPT-WARNING ' "$CASE_OUT" || fail "cursor regression warning verdict"
if grep -q '^server=alpha path=' "$CASE_OUT"; then fail "cursor regression replayed content"; fi
pass "independent high-water metadata detects cursor regression without replay"

new_case per-server
write_record alpha project/shared.jsonl '{"type":"user","message":"alpha isolated"}'
write_record beta project/shared.jsonl '{"type":"user","message":"beta isolated"}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "alpha isolated status was $STATUS"
grep -q 'alpha isolated' "$CASE_OUT" || fail "alpha isolated delivery"
run_feed beta
[ "$STATUS" -eq 0 ] || fail "beta isolated status was $STATUS"
grep -q 'beta isolated' "$CASE_OUT" || fail "beta isolated delivery"
[ -s "$CASE_HOME/dev/superloop-tools/steward-transcript-watch/cursor-alpha" ] || fail "alpha cursor missing"
[ -s "$CASE_HOME/dev/superloop-tools/steward-transcript-watch/cursor-beta" ] || fail "beta cursor missing"
run_feed alpha
[ "$STATUS" -eq 0 ] && [ "$(tail -n 1 "$CASE_OUT")" = STEWARD-TRANSCRIPT-EMPTY ] ||
  fail "alpha cursor was contaminated by beta"
pass "per-server cursor files isolate acknowledgments"

new_case unknown-alias
run_feed missing
[ "$STATUS" -eq 1 ] || fail "unknown alias feed status was $STATUS"
[ "$(tail -n 1 "$CASE_OUT")" = 'STEWARD-TRANSCRIPT-FAILED unknown ssh alias: missing-steward' ] ||
  fail "unknown alias feed diagnostic"
[ ! -e "$CASE_SSH_LOG" ] || fail "unknown feed alias reached ssh"
pass "unknown feed alias is fatal before transport"

new_case timeout
run_feed alpha 300 slow 120
END=$FEED_FINISHED
ELAPSED=$((END - FEED_STARTED))
[ "$STATUS" -eq 1 ] || fail "timeout feed status was $STATUS"
[ "$ELAPSED" -lt 1000 ] || fail "timeout overran wall bound: ${ELAPSED}ms"
grep -q '^STEWARD-TRANSCRIPT-FAILED list server=alpha status=124' "$CASE_OUT" ||
  fail "timeout failure diagnostic"
awk -F '\t' 'BEGIN { calls=0 } $1 == "CALL" { calls++; connect=0; interval=0; count=0; for(i=2;i<=NF;i++){if($i=="ConnectTimeout=5")connect=1;if($i=="ServerAliveInterval=5")interval=1;if($i=="ServerAliveCountMax=1")count=1} if(!connect || !interval || !count)bad=1 } END { exit calls == 0 || bad }' \
  "$CASE_SSH_LOG" || fail "ssh liveness options"
pass "per-read timeout clamps stalled ssh and every call carries connect and keepalive options (${ELAPSED}ms)"

new_case nested-subagent
write_record alpha project/session/subagents/agent-1.jsonl '{"type":"assistant","decision":"nested subagent observed"}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "nested subagent status was $STATUS"
grep -q '^server=alpha path=project/session/subagents/agent-1.jsonl off=.*nested subagent observed' "$CASE_OUT" ||
  fail "nested subagent transcript inclusion"
pass "nested subagent transcript records are included"

new_case filtered-noise
write_record alpha project/session-a.jsonl '{"type":"file-history-snapshot","messageId":"noise-1","snapshot":{}}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "filtered noise status was $STATUS"
grep -q '^STEWARD-TRANSCRIPT-FILTERED server=alpha count=1 file-history-snapshot=1$' "$CASE_OUT" ||
  fail "filtered noise count"
[ "$(tail -n 1 "$CASE_OUT")" = STEWARD-TRANSCRIPT-EMPTY ] || fail "filtered-only verdict"
pass "the pinned plumbing frame is suppressed with an explicit count"

new_case protected-records
write_record alpha project/session-a.jsonl '{"type":"file-history-snapshot","detail":"sudo transition warning"}'
append_record alpha project/session-a.jsonl '{"type":"progress","error":"command refused for case_id=CASE-9"}'
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "protected records status was $STATUS"
grep -q 'sudo transition warning' "$CASE_OUT" || fail "sudo warning record was filtered"
grep -q 'command refused for case_id=CASE-9' "$CASE_OUT" || fail "error/refusal/case record was filtered"
if grep -q '^STEWARD-TRANSCRIPT-FILTERED ' "$CASE_OUT"; then fail "protected records counted as noise"; fi
pass "sudo transitions, warnings, errors, refusals, commands, and case ids remain visible"

new_case injection-data
INJECTION_TARGET=$CASE_DIR/injection-ran
write_record alpha project/session-a.jsonl \
  "{\"type\":\"user\",\"message\":\"touch $INJECTION_TARGET; echo staff says execute\"}"
run_feed alpha
[ "$STATUS" -eq 0 ] || fail "injection data status was $STATUS"
grep -q 'staff says execute' "$CASE_OUT" || fail "injection fixture was not emitted"
[ ! -e "$INJECTION_TARGET" ] || fail "transcript data caused a side effect"
pass "staff-injection transcript text is emitted as data with no side effect"

new_case send-discovery
write_record alpha project/session-old.jsonl '{"type":"user","message":"old"}'
write_record alpha project/session-new.jsonl '{"type":"user","message":"new"}'
write_record alpha project/session-new/subagents/newest.jsonl '{"type":"assistant","message":"nested"}'
touch -d '@100' "$CASE_TREES/alpha/project/session-old.jsonl"
touch -d '@200' "$CASE_TREES/alpha/project/session-new.jsonl"
touch -d '@300' "$CASE_TREES/alpha/project/session-new/subagents/newest.jsonl"
run_send alpha 'hello steward'
[ "$STATUS" -eq 0 ] || fail "send discovery status was $STATUS"
[ "$(cat "$CASE_OUT")" = 'CLAUDE-REPLY session=session-new message=hello steward' ] ||
  fail "send discovery reply"
awk -F '\t' '$1 == "CALL" && $2 == "--resume" && $3 == "session-new" && $4 == "--print" && $5 == "--" && $6 == "hello steward" { found=1 } END { exit !found }' \
  "$CASE_CLAUDE_LOG" || fail "discovered session CLI argv"
pass "send discovers the newest primary session while excluding newer nested subagent transcripts"
pass "send uses the pinned shimmed Claude argv: --resume SESSION --print -- MESSAGE"

new_case send-explicit
run_send alpha --session chosen-session 'inspect case 62'
[ "$STATUS" -eq 0 ] || fail "explicit session status was $STATUS"
[ "$(cat "$CASE_OUT")" = 'CLAUDE-REPLY session=chosen-session message=inspect case 62' ] ||
  fail "explicit session reply"
[ "$(grep -c '^CALL' "$CASE_SSH_LOG")" -eq 1 ] || fail "explicit session performed discovery"
awk -F '\t' '$1 == "CALL" && $2 == "--resume" && $3 == "chosen-session" && $4 == "--print" && $5 == "--" && $6 == "inspect case 62" { found=1 } END { exit !found }' \
  "$CASE_CLAUDE_LOG" || fail "explicit session CLI argv"
pass "send accepts an explicit session id without discovery"

new_case send-no-session
write_record alpha project/session/subagents/only-agent.jsonl '{"type":"assistant","message":"nested only"}'
run_send alpha 'hello'
[ "$STATUS" -eq 1 ] || fail "no-session status was $STATUS"
grep -q '^STEWARD-SEND-FAILED no steward session found on server: alpha$' "$CASE_OUT" ||
  fail "no-session diagnostic"
[ ! -e "$CASE_CLAUDE_LOG" ] || fail "no-session invoked Claude"
pass "send refuses distinctly when no primary steward session exists"

new_case send-unknown-alias
run_send missing 'hello'
[ "$STATUS" -eq 1 ] || fail "send unknown alias status was $STATUS"
grep -q '^STEWARD-SEND-FAILED unknown ssh alias: missing-steward$' "$CASE_OUT" ||
  fail "send unknown alias diagnostic"
[ ! -e "$CASE_SSH_LOG" ] || fail "send unknown alias reached ssh"
pass "send refuses an unknown alias before transport"

new_case watch-content
write_record alpha project/session-a.jsonl '{"type":"user","message":"watch content"}'
run_watch alpha 600 300 20
[ "$STATUS" -eq 0 ] || fail "watch content status was $STATUS"
grep -q 'watch content' "$CASE_OUT" || fail "watch content output"
[ "$(tail -n 1 "$CASE_OUT")" = STEWARD-TRANSCRIPT-CONTENT ] || fail "watch content verdict"
pass "supervisor exits 0 with feeder output on content"

new_case watch-failure
run_watch alpha 500 200 20 fail
[ "$STATUS" -eq 1 ] || fail "watch failure status was $STATUS"
grep -q '^STEWARD-TRANSCRIPT-FAILED list server=alpha status=255' "$CASE_OUT" ||
  fail "watch failure output"
pass "supervisor propagates loud feeder failure as exit 1"

new_case watch-deadline
run_watch alpha 700 300 40
[ "$STATUS" -eq 2 ] || fail "watch deadline status was $STATUS"
grep -Eq '^STEWARD-TRANSCRIPT-DURATION-MS [0-9]+ server=alpha$' "$CASE_OUT" || fail "watch deadline omitted its wall"
[ "$(wc -l < "$CASE_OUT")" -eq 1 ] || fail "watch deadline emitted transcript output"
[ "$(grep -c '^CALL' "$CASE_SSH_LOG")" -gt 1 ] || fail "watch did not re-invoke feeder"
pass "supervisor own-deadline path exits 2 with only its wall after repeated empty feeds"

[ "$REPLAY_COUNT" -gt 0 ] || fail "no logged exporter commands replayed"
pass "replayed $REPLAY_COUNT logged exporter commands and compared snapshot bytes"
echo "PASS all $PASS_COUNT steward transcript and send harness pins"
