#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SCAN=${CORRESPONDENCE_TEST_SCAN:?Meson must bind the configured scanner}
TEST_TMP_ROOT=${TMPDIR:-/tmp}
FIXTURE=$(mktemp -d "$TEST_TMP_ROOT/correspondence-watch-test.XXXXXX")
trap 'rm -rf "$FIXTURE"' EXIT

HOMES=$FIXTURE/homes
STATE=$FIXTURE/state
BIN=$FIXTURE/bin
LOG=$FIXTURE/logger.log
SPOOL_LOG=$FIXTURE/spool.log
mkdir -p "$HOMES/owner/correspondence" "$HOMES/alice/correspondence" "$BIN"

USER_FILE=$HOMES/alice/correspondence/question.md
ROOT_REPLY=$HOMES/alice/correspondence/status.md
NAMED_REPLY=$HOMES/alice/correspondence/status-admin-reply.md
OWNER_FILE=$HOMES/owner/correspondence/work-order.md
OWNER_ROOT_REPLY=$HOMES/owner/correspondence/disposition.md
OWNER_NAMED_REPLY=$HOMES/owner/correspondence/disposition-admin-reply.md
printf 'question\n' > "$USER_FILE"
printf 'root reply\n' > "$ROOT_REPLY"
printf 'named reply\n' > "$NAMED_REPLY"
printf 'owner work order\n' > "$OWNER_FILE"
printf 'owner root reply\n' > "$OWNER_ROOT_REPLY"
printf 'owner named reply\n' > "$OWNER_NAMED_REPLY"
: > "$LOG"
: > "$SPOOL_LOG"

REAL_STAT=$(command -v stat)
export CORRESPONDENCE_TEST_HOMES=$HOMES
export CORRESPONDENCE_TEST_REAL_STAT=$REAL_STAT
export CORRESPONDENCE_TEST_LOG=$LOG
export CORRESPONDENCE_TEST_SPOOL_LOG=$SPOOL_LOG

cat > "$BIN/stat" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
target=${3%/}
if [ "${1-}" = -c ] && [ "${2-}" = %u ]; then
  case $target in
    "$CORRESPONDENCE_TEST_HOMES/alice"|"$CORRESPONDENCE_TEST_HOMES/alice/correspondence/question.md"|"$CORRESPONDENCE_TEST_HOMES/alice/correspondence/status-admin-reply.md")
      printf '1000\n'
      exit 0
      ;;
    "$CORRESPONDENCE_TEST_HOMES/owner"|"$CORRESPONDENCE_TEST_HOMES/owner/correspondence/work-order.md"|"$CORRESPONDENCE_TEST_HOMES/owner/correspondence/disposition-admin-reply.md")
      printf '1001\n'
      exit 0
      ;;
    "$CORRESPONDENCE_TEST_HOMES/alice/correspondence/status.md"|"$CORRESPONDENCE_TEST_HOMES/owner/correspondence/disposition.md")
      printf '0\n'
      exit 0
      ;;
  esac
fi
exec "$CORRESPONDENCE_TEST_REAL_STAT" "$@"
SHIM

cat > "$BIN/logger" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CORRESPONDENCE_TEST_LOG"
SHIM

cat > "$BIN/steward-spool-append" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
source_folder=
relative=
event_sha=
classification=
timestamp=
while [ "$#" -gt 0 ]; do
  case $1 in
    --source) source_folder=$2; shift 2 ;;
    --file) relative=$2; shift 2 ;;
    --sha) event_sha=$2; shift 2 ;;
    --classification) classification=$2; shift 2 ;;
    --timestamp) timestamp=$2; shift 2 ;;
    *) exit 2 ;;
  esac
done
printf '%s\t%s\t%s\t%s\t%s\n' "$source_folder" "$relative" "$event_sha" "$classification" "$timestamp" >> "$CORRESPONDENCE_TEST_SPOOL_LOG"
SHIM
chmod +x "$BIN/stat" "$BIN/logger" "$BIN/steward-spool-append"

run_scan() {
  local spool_enabled=${1:-0}
  PATH="$BIN:$PATH" \
    CORRESPONDENCE_WATCH_HOME_ROOT=$HOMES \
    CORRESPONDENCE_WATCH_STATE_DIR=$STATE \
    CORRESPONDENCE_WATCH_LOGGER=$BIN/logger \
    CORRESPONDENCE_WATCH_STEWARD_SPOOL_ENABLED=$spool_enabled \
    CORRESPONDENCE_WATCH_STEWARD_SPOOL_APPEND=$BIN/steward-spool-append \
    "$SCAN"
}

fail() {
  printf 'not ok - %s\n' "$1" >&2
  printf '%s\n' 'captured logger output:' >&2
  sed 's/^/  /' "$LOG" >&2
  exit 1
}

pass() {
  printf 'ok %s - %s\n' "$1" "$2"
}

event_line() {
  local user=$1
  local from=$2
  local file=$3
  local path=$4
  local size sha
  size=$($REAL_STAT -c %s "$path")
  sha=$(sha256sum "$path" | cut -c1-12)
  printf '%s\n' "-t correspondence-watch user=$user from=$from file=$file size=$size sha=$sha"
}

run_scan
USER_EVENT=$(event_line alice user question.md "$USER_FILE")
ROOT_EVENT=$(event_line alice admin status.md "$ROOT_REPLY")
NAMED_EVENT=$(event_line alice admin status-admin-reply.md "$NAMED_REPLY")
OWNER_EVENT=$(event_line owner user work-order.md "$OWNER_FILE")
OWNER_ROOT_EVENT=$(event_line owner admin disposition.md "$OWNER_ROOT_REPLY")
OWNER_NAMED_EVENT=$(event_line owner admin disposition-admin-reply.md "$OWNER_NAMED_REPLY")
grep -Fqx -- "$USER_EVENT" "$LOG" || fail 'user-owned file was not classified from=user'
pass 1 'user file -> from=user'
grep -Fqx -- "$ROOT_EVENT" "$LOG" || fail 'different-owner file was not classified from=admin'
pass 2 'root-style reply -> from=admin'
grep -Fqx -- "$NAMED_EVENT" "$LOG" || fail 'user-owned admin-reply filename was not classified from=admin'
pass 3 'user-owned *-admin-reply.md -> from=admin'
grep -Fqx -- "$OWNER_EVENT" "$LOG" || fail 'owner-owned file was not classified from=user'
pass 4 'owner work order -> from=user'
grep -Fqx -- "$OWNER_ROOT_EVENT" "$LOG" || fail 'root-style owner reply was not classified from=admin'
pass 5 'root-style owner reply -> from=admin'
grep -Fqx -- "$OWNER_NAMED_EVENT" "$LOG" || fail 'owner-owned admin-reply filename was not classified from=admin'
pass 6 'owner-owned *-admin-reply.md -> from=admin'
[ "$(wc -l < "$LOG")" -eq 7 ] || fail 'initial scan did not emit exactly six events and one summary'
grep -Eq '^-t correspondence-watch scan events=6 duration_ms=[0-9]+$' "$LOG" || fail 'initial scan summary is missing or malformed'
pass 7 'events/duration summary -> events=6 with numeric duration_ms'
[ ! -s "$SPOOL_LOG" ] || fail 'default-off steward hook appended cases'
pass 8 'default-off steward hook leaves correspondence-only output unchanged'

: > "$LOG"
run_scan
[ -f "$STATE/stamp" ] || fail 'scan cursor stamp was not installed'
[ ! -s "$LOG" ] || fail 'unchanged repeat scan emitted events'
sleep 0.02
printf 'owner work order updated\n' > "$OWNER_FILE"
run_scan 1
UPDATED_EVENT=$(event_line owner user work-order.md "$OWNER_FILE")
grep -Fqx -- "$UPDATED_EVENT" "$LOG" || fail 'changed owner file was not emitted after the cursor advanced'
[ "$(wc -l < "$LOG")" -eq 2 ] || fail 'changed-file scan did not emit exactly one event and one summary'
[ "$(wc -l < "$SPOOL_LOG")" -eq 1 ] || fail 'enabled steward hook did not append exactly one user event'
IFS=$'\t' read -r spool_source spool_relative spool_sha spool_classification spool_timestamp < "$SPOOL_LOG"
[ "$spool_source" = "$HOMES/owner/correspondence" ] || fail 'steward hook recorded the wrong source folder'
[ "$spool_relative" = work-order.md ] || fail 'steward hook recorded the wrong relative file'
[ "$spool_sha" = "$(sha256sum "$OWNER_FILE" | cut -c1-12)" ] || fail 'steward hook recorded the wrong sha'
[ "$spool_classification" = 'user=owner from=user' ] || fail 'steward hook recorded the wrong classification'
printf '%s\n' "$spool_timestamp" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || fail 'steward hook timestamp is malformed'
: > "$LOG"
run_scan 1
[ ! -s "$LOG" ] || fail 'second unchanged repeat scan emitted events'
[ "$(wc -l < "$SPOOL_LOG")" -eq 1 ] || fail 'unchanged scan reinvoked the steward hook'
pass 9 'stamp cursor -> changed owner input emits and spools once; unchanged scans are quiet'

sleep 0.02
printf 'owner root reply updated\n' > "$OWNER_ROOT_REPLY"
run_scan 1
[ "$(wc -l < "$SPOOL_LOG")" -eq 1 ] || fail 'admin output opened a steward case'
grep -Fqx -- "$(event_line owner admin disposition.md "$OWNER_ROOT_REPLY")" "$LOG" || fail 'changed admin output was not journaled as context'
pass 10 'enabled steward hook ignores from=admin output context'

printf '1..10\n'
