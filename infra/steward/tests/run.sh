#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
KIT=$HERE/..
APPEND=${STEWARD_TEST_APPEND:?Meson must bind the configured spool appender}
RUNNER=${STEWARD_TEST_RUNNER:?Meson must bind the configured runner}
TEST_TMP_ROOT=${TMPDIR:-$HOME/.cache/tmp}
FIXTURE=$(mktemp -d "$TEST_TMP_ROOT/steward-test.XXXXXX")
trap 'rm -rf "$FIXTURE"' EXIT

BIN=$FIXTURE/bin
mkdir -p "$BIN"
CURRENT_UID=$(id -u)
CURRENT_USER=$(id -un)
STEWARD_TEST_REAL_STAT=$(command -v stat)
STEWARD_TEST_FOREIGN_UID=$((CURRENT_UID + 1))
export STEWARD_TEST_REAL_STAT STEWARD_TEST_FOREIGN_UID
PASS=0

fail() {
  printf 'not ok - %s\n' "$1" >&2
  exit 1
}

pass() {
  PASS=$((PASS + 1))
  printf 'ok %s - %s\n' "$PASS" "$1"
}

pass_pin() {
  local name=$1
  local started=$2
  local ended
  ended=$(date +%s%3N)
  PASS=$((PASS + 1))
  printf 'ok %s - %s duration_ms=%s\n' "$PASS" "$name" "$((ended - started))"
}

cat > "$BIN/logger" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$STEWARD_TEST_JOURNAL"
SHIM

cat > "$BIN/stat" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 4 ] && [ "$1" = -c ] && [ "$2" = %u ] &&
  [ "$3" = -- ] && [ "$4" = "$STEWARD_TEST_FOREIGN_PATH" ]; then
  printf '%s\n' "$STEWARD_TEST_FOREIGN_UID"
  exit 0
fi
exec "$STEWARD_TEST_REAL_STAT" "$@"
SHIM

cat > "$BIN/claude" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
INPUT=$(mktemp "${TMPDIR:-$HOME/.cache/tmp}/steward-claude-input.XXXXXX")
trap 'rm -f "$INPUT"' EXIT
cat > "$INPUT"
printf '%s\n' "$STEWARD_TEST_MODE" >> "$STEWARD_TEST_INVOCATIONS"
printf '%s:%s\n' "$(id -u)" "$(id -un)" >> "$STEWARD_TEST_PROCESS_OWNERS"
case $STEWARD_TEST_MODE in
  crash) exit 23 ;;
  fail) exit 7 ;;
  deadline) sleep 5; exit 0 ;;
  block)
    : > "$STEWARD_TEST_ENTERED"
    while [ ! -e "$STEWARD_TEST_RELEASE" ]; do
      sleep 0.02
    done
    ;;
  success) ;;
  *) exit 64 ;;
esac

case_id=
while IFS= read -r line; do
  case $line in
    'CASE-ID: '*) case_id=${line#CASE-ID: } ;;
    'DISPOSITION-PATH: '*)
      disposition=${line#DISPOSITION-PATH: }
      [ -n "$case_id" ] || exit 65
      printf 'case: %s\nresult: completed\n' "$case_id" > "$disposition"
      disposition_sha=$(sha256sum "$disposition" | cut -d ' ' -f 1)
      printf 'STEWARD-DISPOSITION\t%s\t%s\t%s\n' "$case_id" "$disposition" "$disposition_sha"
      ;;
  esac
done < "$INPUT"
SHIM
chmod +x "$BIN/logger" "$BIN/stat" "$BIN/claude"

setup_fixture() {
  local base=$1
  mkdir -p "$base/source" "$base/state/invocations" "$base/owner"
  : > "$base/spool.tsv"
  : > "$base/state/dispositions.tsv"
  : > "$base/journal.log"
  : > "$base/invocations.log"
  : > "$base/process-owners.log"
  printf '%s\n' 'fixture charter' > "$base/charter.md"
}

append_event() {
  local base=$1
  local source=$2
  local relative=$3
  local timestamp=${4:-2026-09-01T00:00:00Z}
  local event_sha
  event_sha=$(sha256sum "$source/$relative" | cut -c1-12)
  STEWARD_SPOOL_EXPECT_UID=$CURRENT_UID \
    STEWARD_SPOOL_FILE=$base/spool.tsv \
    STEWARD_SPOOL_LOCK_FILE=$base/spool.lock \
    "$APPEND" \
      --source "$source" \
      --file "$relative" \
      --sha "$event_sha" \
      --classification 'user=owner from=user' \
      --timestamp "$timestamp"
}

runner_fixture_environment() {
  local base=$1
  local mode=${2:-success}
  local deadline=${3:-5}
  export STEWARD_STATE_DIR=$base/state
  export STEWARD_SPOOL_FILE=$base/spool.tsv
  export STEWARD_LEDGER_FILE=$base/state/dispositions.tsv
  export STEWARD_LOCK_FILE=$base/state/runner.lock
  export STEWARD_OUTPUT_DIR=$base/state/invocations
  export STEWARD_CHARTER_FILE=$base/charter.md
  export STEWARD_CLAUDE_COMMAND=$BIN/claude
  export STEWARD_LOGGER=$BIN/logger
  export STEWARD_DEADLINE_SECONDS=$deadline
  export STEWARD_KILL_AFTER_SECONDS=1
  export STEWARD_EXPECT_USER=$CURRENT_USER
  export STEWARD_EXPECT_DISPOSITION_UID=$CURRENT_UID
  export STEWARD_TEST_MODE=$mode
  export STEWARD_TEST_INVOCATIONS=$base/invocations.log
  export STEWARD_TEST_PROCESS_OWNERS=$base/process-owners.log
  export STEWARD_TEST_JOURNAL=$base/journal.log
  export STEWARD_TEST_ENTERED=${STEWARD_TEST_ENTERED:-$base/entered}
  export STEWARD_TEST_RELEASE=${STEWARD_TEST_RELEASE:-$base/release}
}

run_runner() (
  local base=$1
  local mode=${2:-success}
  local deadline=${3:-5}
  local owner_correspondence=${4-$base/owner}
  runner_fixture_environment "$base" "$mode" "$deadline"
  export STEWARD_OWNER_CORRESPONDENCE=$owner_correspondence
  "$RUNNER"
)

run_runner_missing_owner() (
  local base=$1
  runner_fixture_environment "$base"
  unset STEWARD_OWNER_CORRESPONDENCE
  "$RUNNER"
)

assert_owner_configuration_refusal() {
  local base=$1
  local output=$2
  local status=$3
  [ "$status" -eq 1 ] || fail 'owner correspondence configuration refusal used the wrong status'
  [ "$output" = 'STEWARD-RUN-FAILED configuration variable=STEWARD_OWNER_CORRESPONDENCE' ] ||
    fail 'owner correspondence configuration refusal used the wrong verdict'
  grep -Fqx -- '-t steward-runner result=failed reason=configuration variable=STEWARD_OWNER_CORRESPONDENCE' \
    "$base/journal.log" || fail 'owner correspondence configuration refusal used the wrong journal diagnostic'
  [ "$(wc -l < "$base/journal.log")" -eq 1 ] ||
    fail 'owner correspondence configuration refusal did not emit exactly one journal line'
  [ ! -s "$base/invocations.log" ] || fail 'owner correspondence configuration refusal invoked Claude'
}

for script in "$APPEND" "$RUNNER" "$HERE/run.sh"; do
  bash -n "$script"
done
pass 'bash -n accepts every steward script'

grep -Fqx 'User=superloop-steward' "${STEWARD_TEST_SERVICE:?Meson must bind the configured service}" || fail 'service does not pin User=superloop-steward'
[ "$(grep -c '^User=' "${STEWARD_TEST_SERVICE:?Meson must bind the configured service}")" -eq 1 ] || fail 'service carries an identity fallback'
grep -Fqx "ExecStart=${SERVER_KIT_PRIVATE_DIR:?Meson must bind the private directory}/steward-runner" "${STEWARD_TEST_SERVICE:?Meson must bind the configured service}" || fail 'service does not invoke the runner'
grep -Fqx 'Persistent=true' "${STEWARD_TEST_TIMER:?Meson must bind the configured timer}" || fail 'timer is not persistent'
grep -Fq 'STEWARD_PILOT_CADENCE=5min' "${STEWARD_TEST_TIMER:?Meson must bind the configured timer}" || fail 'timer cadence is not a named pilot constant'
pass 'units pin uid superloop-steward, the runner, persistence, and pilot cadence'

MISSING_OWNER_BASE=$FIXTURE/missing-owner-correspondence
setup_fixture "$MISSING_OWNER_BASE"
pin_t0=$(date +%s%3N)
set +e
MISSING_OWNER_OUTPUT=$(run_runner_missing_owner "$MISSING_OWNER_BASE")
MISSING_OWNER_STATUS=$?
set -e
assert_owner_configuration_refusal "$MISSING_OWNER_BASE" "$MISSING_OWNER_OUTPUT" "$MISSING_OWNER_STATUS"
pass_pin 'missing STEWARD_OWNER_CORRESPONDENCE is a configuration refusal before work' "$pin_t0"

EMPTY_OWNER_BASE=$FIXTURE/empty-owner-correspondence
setup_fixture "$EMPTY_OWNER_BASE"
pin_t0=$(date +%s%3N)
set +e
EMPTY_OWNER_OUTPUT=$(run_runner "$EMPTY_OWNER_BASE" success 5 '')
EMPTY_OWNER_STATUS=$?
set -e
assert_owner_configuration_refusal "$EMPTY_OWNER_BASE" "$EMPTY_OWNER_OUTPUT" "$EMPTY_OWNER_STATUS"
pass_pin 'empty STEWARD_OWNER_CORRESPONDENCE is a configuration refusal before work' "$pin_t0"

RELATIVE_OWNER_BASE=$FIXTURE/relative-owner-correspondence
setup_fixture "$RELATIVE_OWNER_BASE"
pin_t0=$(date +%s%3N)
set +e
RELATIVE_OWNER_OUTPUT=$(run_runner "$RELATIVE_OWNER_BASE" success 5 relative-owner)
RELATIVE_OWNER_STATUS=$?
set -e
assert_owner_configuration_refusal "$RELATIVE_OWNER_BASE" "$RELATIVE_OWNER_OUTPUT" "$RELATIVE_OWNER_STATUS"
pass_pin 'relative STEWARD_OWNER_CORRESPONDENCE is a configuration refusal before work' "$pin_t0"

NON_DIRECTORY_OWNER_BASE=$FIXTURE/non-directory-owner-correspondence
setup_fixture "$NON_DIRECTORY_OWNER_BASE"
printf '%s\n' 'not a directory' > "$NON_DIRECTORY_OWNER_BASE/owner-file"
pin_t0=$(date +%s%3N)
set +e
NON_DIRECTORY_OWNER_OUTPUT=$(run_runner "$NON_DIRECTORY_OWNER_BASE" success 5 "$NON_DIRECTORY_OWNER_BASE/owner-file")
NON_DIRECTORY_OWNER_STATUS=$?
set -e
assert_owner_configuration_refusal \
  "$NON_DIRECTORY_OWNER_BASE" "$NON_DIRECTORY_OWNER_OUTPUT" "$NON_DIRECTORY_OWNER_STATUS"
pass_pin 'non-directory STEWARD_OWNER_CORRESPONDENCE is a configuration refusal at first use' "$pin_t0"

ID_BASE=$FIXTURE/idempotence
setup_fixture "$ID_BASE"
printf '%s\n' 'unchanged work order' > "$ID_BASE/source/work.md"
FIRST_APPEND=$(append_event "$ID_BASE" "$ID_BASE/source" work.md 2026-09-01T00:00:00Z)
SECOND_APPEND=$(append_event "$ID_BASE" "$ID_BASE/source" work.md 2026-09-01T00:01:00Z)
case $FIRST_APPEND in STEWARD-SPOOL-APPENDED' case='*) ;; *) fail 'first append was not named appended' ;; esac
case $SECOND_APPEND in STEWARD-SPOOL-UNCHANGED' case='*) ;; *) fail 'unchanged append was not named unchanged' ;; esac
[ "${FIRST_APPEND#*case=}" = "${SECOND_APPEND#*case=}" ] || fail 'unchanged event changed its stable case id'
[ "$(wc -l < "$ID_BASE/spool.tsv")" -eq 1 ] || fail 'unchanged event duplicated the spool line'
pass 'spool append is durable and idempotent for an unchanged event'

for BAD_TIMESTAMP in 2026-09-01T00:00:00 2026-09-01T02:00:00+02:00 2026-02-29T00:00:00Z 2026-09-01T24:00:00Z 2026-09-01T00:00:00.1Z; do
  if BAD_OUTPUT=$(append_event "$ID_BASE" "$ID_BASE/source" work.md "$BAD_TIMESTAMP" 2>&1); then
    fail "accepted invalid timestamp $BAD_TIMESTAMP"
  else
    [ "$?" -eq 2 ] || fail 'invalid timestamp returned the wrong status'
  fi
  [[ $BAD_OUTPUT == *"invalid UTC timestamp"*"$BAD_TIMESTAMP"* ]] || fail 'timestamp refusal lost its source value'
  [ "$(wc -l < "$ID_BASE/spool.tsv")" -eq 1 ] || fail 'invalid timestamp changed the spool'
done
append_event "$ID_BASE" "$ID_BASE/source" work.md 2024-02-29T00:00:00Z >/dev/null
pass 'spool timestamp validation refuses naive offsets and invalid calendars before publication'


SPOOL_OWNER_BASE=$FIXTURE/spool-foreign-owner
setup_fixture "$SPOOL_OWNER_BASE"
printf '%s\n' 'foreign spool owner' > "$SPOOL_OWNER_BASE/source/work.md"
set +e
SPOOL_OWNER_OUTPUT=$(
  PATH="$BIN:$PATH" STEWARD_TEST_FOREIGN_PATH=$SPOOL_OWNER_BASE/spool.tsv \
    append_event "$SPOOL_OWNER_BASE" "$SPOOL_OWNER_BASE/source" work.md 2>&1
)
SPOOL_OWNER_STATUS=$?
set -e
[ "$SPOOL_OWNER_STATUS" -eq 1 ] || fail 'spool owner comparison used the wrong status'
[ "$SPOOL_OWNER_OUTPUT" = "steward-spool-append: spool must be owned by uid $CURRENT_UID, found $STEWARD_TEST_FOREIGN_UID" ] ||
  fail 'spool owner comparison used the wrong message'
[ ! -s "$SPOOL_OWNER_BASE/spool.tsv" ] || fail 'spool owner comparison appended a case'
pass 'spool file owner comparison refuses a foreign uid before append'

CURRENT_UID_BASE=$FIXTURE/spool-wrong-current-uid
setup_fixture "$CURRENT_UID_BASE"
printf '%s\n' 'unexpected current uid' > "$CURRENT_UID_BASE/source/work.md"
set +e
CURRENT_UID_OUTPUT=$(
  STEWARD_SPOOL_EXPECT_UID=$STEWARD_TEST_FOREIGN_UID \
    STEWARD_SPOOL_FILE=$CURRENT_UID_BASE/spool.tsv \
    STEWARD_SPOOL_LOCK_FILE=$CURRENT_UID_BASE/spool.lock \
    "$APPEND" \
      --source "$CURRENT_UID_BASE/source" \
      --file work.md \
      --sha 0123456789ab \
      --classification 'user=owner from=user' \
      --timestamp 2026-09-01T00:00:00Z 2>&1
)
CURRENT_UID_STATUS=$?
set -e
[ "$CURRENT_UID_STATUS" -eq 1 ] || fail 'current uid comparison used the wrong status'
[ "$CURRENT_UID_OUTPUT" = "steward-spool-append: expected uid $STEWARD_TEST_FOREIGN_UID, found $CURRENT_UID" ] ||
  fail 'current uid comparison used the wrong message'
[ ! -s "$CURRENT_UID_BASE/spool.tsv" ] || fail 'current uid comparison appended a case'
pass 'current uid comparison refuses an unexpected uid before append'

QUIET_BASE=$FIXTURE/quiet
setup_fixture "$QUIET_BASE"
QUIET_OUTPUT=$(run_runner "$QUIET_BASE")
[ "$QUIET_OUTPUT" = STEWARD-RUN-QUIET ] || fail 'empty pending set was not quiet'
[ ! -s "$QUIET_BASE/invocations.log" ] || fail 'quiet run invoked Claude'
pass 'empty pending set ends STEWARD-RUN-QUIET without a model invocation'

SUCCESS_BASE=$FIXTURE/success
setup_fixture "$SUCCESS_BASE"
printf '%s\n' 'perform the no-op' > "$SUCCESS_BASE/source/work.md"
SUCCESS_APPEND=$(append_event "$SUCCESS_BASE" "$SUCCESS_BASE/source" work.md)
SUCCESS_CASE=${SUCCESS_APPEND#*case=}
pin_t0=$(date +%s%3N)
SUCCESS_OUTPUT=$(run_runner "$SUCCESS_BASE" success 5 "$SUCCESS_BASE/owner")
case $SUCCESS_OUTPUT in STEWARD-RUN-OK' '*) ;; *) fail 'pending case did not end STEWARD-RUN-OK' ;; esac
SUCCESS_DISPOSITION=$SUCCESS_BASE/owner/steward-$SUCCESS_CASE-admin-reply.md
[ -f "$SUCCESS_DISPOSITION" ] || fail 'successful invocation did not install disposition output'
grep -Fq "$SUCCESS_CASE" "$SUCCESS_BASE/state/dispositions.tsv" || fail 'successful invocation did not advance the ledger'
grep -Fq "state=completed disposition=$SUCCESS_DISPOSITION" "$SUCCESS_BASE/journal.log" || fail 'successful case lacks its journal record'
[ "$(wc -l < "$SUCCESS_BASE/state/dispositions.tsv")" -eq 1 ] || fail 'successful case advanced the ledger more than once'
[ "$(wc -l < "$SUCCESS_BASE/process-owners.log")" -eq 1 ] || fail 'model process ownership was not recorded once'
if grep -Fvx "$CURRENT_UID:$CURRENT_USER" "$SUCCESS_BASE/process-owners.log"; then fail 'model child did not inherit the runner uid'; fi
pass_pin 'absolute fixture STEWARD_OWNER_CORRESPONDENCE keeps the model under the runner uid and makes disposition durable before one ledger advance' "$pin_t0"

SECOND_SUCCESS=$(run_runner "$SUCCESS_BASE")
[ "$SECOND_SUCCESS" = STEWARD-RUN-QUIET ] || fail 'disposed case was not quiet on repeat'
[ "$(wc -l < "$SUCCESS_BASE/invocations.log")" -eq 1 ] || fail 'disposed case invoked Claude twice'
[ "$(find "$SUCCESS_BASE/owner" -type f | wc -l)" -eq 1 ] || fail 'disposed case duplicated its letter'
pass 'completed case is subtracted and does not duplicate invocation or disposition'

DISPOSITION_OWNER_BASE=$FIXTURE/disposition-foreign-owner
setup_fixture "$DISPOSITION_OWNER_BASE"
printf '%s\n' 'valid disposition, foreign owner' > "$DISPOSITION_OWNER_BASE/source/work.md"
DISPOSITION_OWNER_APPEND=$(append_event "$DISPOSITION_OWNER_BASE" "$DISPOSITION_OWNER_BASE/source" work.md)
DISPOSITION_OWNER_CASE=${DISPOSITION_OWNER_APPEND#*case=}
DISPOSITION_OWNER_PATH=$DISPOSITION_OWNER_BASE/owner/steward-$DISPOSITION_OWNER_CASE-admin-reply.md
set +e
DISPOSITION_OWNER_OUTPUT=$(
  PATH="$BIN:$PATH" STEWARD_TEST_FOREIGN_PATH=$DISPOSITION_OWNER_PATH \
    run_runner "$DISPOSITION_OWNER_BASE"
)
DISPOSITION_OWNER_STATUS=$?
set -e
[ "$DISPOSITION_OWNER_STATUS" -eq 1 ] || fail 'disposition owner comparison used the wrong status'
[ "$DISPOSITION_OWNER_OUTPUT" = "STEWARD-RUN-FAILED disposition-owner case=$DISPOSITION_OWNER_CASE uid=$STEWARD_TEST_FOREIGN_UID" ] ||
  fail 'disposition owner comparison used the wrong verdict'
[ -f "$DISPOSITION_OWNER_PATH" ] || fail 'disposition owner comparison did not reach a durable disposition'
grep -Fqx "case: $DISPOSITION_OWNER_CASE" "$DISPOSITION_OWNER_PATH" ||
  fail 'disposition owner comparison lacked a valid case'
grep -Fqx 'result: completed' "$DISPOSITION_OWNER_PATH" ||
  fail 'disposition owner comparison lacked a valid result'
[ ! -s "$DISPOSITION_OWNER_BASE/state/dispositions.tsv" ] || fail 'disposition owner comparison advanced the ledger'
if grep -Fq 'state=completed' "$DISPOSITION_OWNER_BASE/journal.log"; then
  fail 'disposition owner comparison journaled completion'
fi
pass 'disposition file owner comparison refuses a foreign uid before disposition'

CRASH_BASE=$FIXTURE/crash
setup_fixture "$CRASH_BASE"
printf '%s\n' 'survive a crash' > "$CRASH_BASE/source/work.md"
CRASH_APPEND=$(append_event "$CRASH_BASE" "$CRASH_BASE/source" work.md)
CRASH_CASE=${CRASH_APPEND#*case=}
set +e
CRASH_OUTPUT=$(run_runner "$CRASH_BASE" crash)
CRASH_STATUS=$?
set -e
[ "$CRASH_STATUS" -ne 0 ] || fail 'crashed invocation returned success'
case $CRASH_OUTPUT in STEWARD-RUN-FAILED' cli-exit=23 '*) ;; *) fail 'crashed invocation did not name its failure' ;; esac
[ ! -s "$CRASH_BASE/state/dispositions.tsv" ] || fail 'crash-before-disposition advanced the ledger'
[ ! -e "$CRASH_BASE/owner/steward-$CRASH_CASE-admin-reply.md" ] || fail 'crash-before-disposition created a letter'
REPLAY_OUTPUT=$(run_runner "$CRASH_BASE")
case $REPLAY_OUTPUT in STEWARD-RUN-OK' '*) ;; *) fail 'crashed case did not replay successfully' ;; esac
[ "$(wc -l < "$CRASH_BASE/invocations.log")" -eq 2 ] || fail 'crashed case did not invoke exactly twice'
[ "$(wc -l < "$CRASH_BASE/state/dispositions.tsv")" -eq 1 ] || fail 'replayed case duplicated its ledger entry'
[ "$(find "$CRASH_BASE/owner" -type f | wc -l)" -eq 1 ] || fail 'replayed case duplicated its disposition'
[ "$(run_runner "$CRASH_BASE")" = STEWARD-RUN-QUIET ] || fail 'replayed case did not become quiet'
pass 'crash before disposition leaves the stable case pending for one nonduplicating replay'

OVERLAP_BASE=$FIXTURE/overlap
setup_fixture "$OVERLAP_BASE"
printf '%s\n' 'hold the runner lock' > "$OVERLAP_BASE/source/work.md"
append_event "$OVERLAP_BASE" "$OVERLAP_BASE/source" work.md >/dev/null
run_runner "$OVERLAP_BASE" block > "$OVERLAP_BASE/first.out" &
FIRST_PID=$!
for attempt in $(seq 1 250); do
  [ -e "$OVERLAP_BASE/entered" ] && break
  sleep 0.02
done
[ -e "$OVERLAP_BASE/entered" ] || fail 'blocking shim did not enter'
set +e
OVERLAP_OUTPUT=$(run_runner "$OVERLAP_BASE")
OVERLAP_STATUS=$?
set -e
[ "$OVERLAP_STATUS" -ne 0 ] || fail 'overlapping runner returned success'
case $OVERLAP_OUTPUT in STEWARD-RUN-FAILED' overlap '*) ;; *) fail 'overlap refusal was not named' ;; esac
: > "$OVERLAP_BASE/release"
wait "$FIRST_PID"
case $(< "$OVERLAP_BASE/first.out") in STEWARD-RUN-OK' '*) ;; *) fail 'lock holder did not complete after release' ;; esac
pass 'non-overlap lock refuses a concurrent runner with a nonzero named verdict'

DEADLINE_BASE=$FIXTURE/deadline
setup_fixture "$DEADLINE_BASE"
printf '%s\n' 'do not park' > "$DEADLINE_BASE/source/work.md"
append_event "$DEADLINE_BASE" "$DEADLINE_BASE/source" work.md >/dev/null
set +e
DEADLINE_OUTPUT=$(run_runner "$DEADLINE_BASE" deadline 1)
DEADLINE_STATUS=$?
set -e
[ "$DEADLINE_STATUS" -ne 0 ] || fail 'deadline expiry returned success'
case $DEADLINE_OUTPUT in STEWARD-RUN-FAILED' deadline '*) ;; *) fail 'deadline expiry was not named' ;; esac
[ ! -s "$DEADLINE_BASE/state/dispositions.tsv" ] || fail 'deadline expiry advanced the ledger'
pass 'elapsed-wall deadline kills the invocation and leaves the case pending'

TOTAL_BASE=$FIXTURE/total-source
setup_fixture "$TOTAL_BASE"
printf '%s\n' 'vanishing source' > "$TOTAL_BASE/source/work.md"
append_event "$TOTAL_BASE" "$TOTAL_BASE/source" work.md >/dev/null
rm "$TOTAL_BASE/source/work.md"
set +e
TOTAL_OUTPUT=$(run_runner "$TOTAL_BASE")
TOTAL_STATUS=$?
set -e
[ "$TOTAL_STATUS" -ne 0 ] || fail 'total source blindness returned success'
case $TOTAL_OUTPUT in STEWARD-RUN-FAILED' total-source-visibility '*) ;; *) fail 'total source blindness was not named' ;; esac
[ ! -s "$TOTAL_BASE/invocations.log" ] || fail 'total source blindness invoked Claude'
pass 'total source failure is distinct, loud, and nonzero'

PARTIAL_BASE=$FIXTURE/partial-source
setup_fixture "$PARTIAL_BASE"
mkdir -p "$PARTIAL_BASE/second-source"
printf '%s\n' 'visible source' > "$PARTIAL_BASE/source/visible.md"
printf '%s\n' 'missing source' > "$PARTIAL_BASE/second-source/missing.md"
VISIBLE_APPEND=$(append_event "$PARTIAL_BASE" "$PARTIAL_BASE/source" visible.md)
VISIBLE_CASE=${VISIBLE_APPEND#*case=}
MISSING_APPEND=$(append_event "$PARTIAL_BASE" "$PARTIAL_BASE/second-source" missing.md)
MISSING_CASE=${MISSING_APPEND#*case=}
rm "$PARTIAL_BASE/second-source/missing.md"
PARTIAL_OUTPUT=$(run_runner "$PARTIAL_BASE")
case $PARTIAL_OUTPUT in STEWARD-RUN-WARNING' partial-visibility '*) ;; *) fail 'partial visibility did not return warning' ;; esac
grep -Fq "$VISIBLE_CASE" "$PARTIAL_BASE/state/dispositions.tsv" || fail 'visible case was not advanced during warning'
if grep -Fq "$MISSING_CASE" "$PARTIAL_BASE/state/dispositions.tsv"; then fail 'missing case advanced during warning'; fi
[ "$(wc -l < "$PARTIAL_BASE/state/dispositions.tsv")" -eq 1 ] || fail 'partial run advanced an unexpected ledger row'
pass 'partial visibility completes visible work with a distinct zero-status warning'

IDENTITY_BASE=$FIXTURE/identity
setup_fixture "$IDENTITY_BASE"
set +e
IDENTITY_OUTPUT=$(
  STEWARD_STATE_DIR=$IDENTITY_BASE/state \
    STEWARD_SPOOL_FILE=$IDENTITY_BASE/spool.tsv \
    STEWARD_CHARTER_FILE=$IDENTITY_BASE/charter.md \
    STEWARD_OWNER_CORRESPONDENCE=$IDENTITY_BASE/owner \
    "$RUNNER"
)
IDENTITY_STATUS=$?
set -e
[ "$IDENTITY_STATUS" -ne 0 ] || fail 'runner accepted a non-steward default identity'
case $IDENTITY_OUTPUT in STEWARD-RUN-FAILED' wrong-user expected=superloop-steward '*) ;; *) fail 'identity refusal was not named' ;; esac
pass 'runner identity guard has no owner or root fallback'

printf '1..%s\n' "$PASS"
