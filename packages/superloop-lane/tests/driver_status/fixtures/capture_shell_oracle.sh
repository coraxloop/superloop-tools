#!/usr/bin/env bash
# Capture the shell lane-watch process contract for synthetic run directories.
set -euo pipefail

readonly ORIGINAL=${LANE_WATCH_REFERENCE:-}
[[ -n "$ORIGINAL" ]] || {
  printf '%s\n' 'lane-watch oracle: LANE_WATCH_REFERENCE is required' >&2
  exit 2
}
readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly EXPECTED=$SCRIPT_DIR/expected
readonly CAPTURE_ROOT=$(mktemp -d "${TMPDIR:?TMPDIR must name disk-backed temporary storage}/lane-watch-oracle.XXXXXX")

cleanup() {
  rm -rf -- "$CAPTURE_ROOT"
}
trap cleanup EXIT

[[ -f "$ORIGINAL" && -r "$ORIGINAL" ]] || {
  printf '%s\n' 'lane-watch shell oracle source is unavailable' >&2
  exit 1
}

mkdir -p "$EXPECTED"

capture() {
  local name=$1
  shift
  set +e
  bash "$ORIGINAL" "$@" >"$EXPECTED/$name.stdout" 2>"$EXPECTED/$name.stderr"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$EXPECTED/$name.status"
}

new_run_dir() {
  local name=$1
  local run_dir=$CAPTURE_ROOT/$name
  mkdir "$run_dir"
  printf '%s\n' "$run_dir"
}

pin_age() {
  local path=$1
  local age=$2
  local now
  now=$(date +%s)
  touch -d "@$((now - age))" "$path"
}

run_dir=$(new_run_dir complete-with-report)
printf '%s\n' 'RUN-REPORT lane=oracle exit=0 wall=1s budget=2s verdict=ok dir=oracle' >"$run_dir/run-report.txt"
capture complete-with-report "$run_dir"

run_dir=$(new_run_dir missing-events)
capture missing-events "$run_dir"

run_dir=$(new_run_dir fresh-one-line)
printf '%s\n' '{"type":"agent_message","message":"one"}' >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 10
capture fresh-one-line "$run_dir"

run_dir=$(new_run_dir fresh-multi-line)
printf '%s\n' '{"type":"thread.started"}' '{"type" : "item.completed"}' >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 20
capture fresh-multi-line "$run_dir"

run_dir=$(new_run_dir stalled-one-line)
printf '%s\n' '{"type":"agent_message","message":"quiet"}' >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 360
capture stalled-one-line "$run_dir"

run_dir=$(new_run_dir stalled-multi-line)
printf '%s\n' '{"type":"thread.started"}' '{"type" : "item.completed","detail":"last"}' >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 420
capture stalled-multi-line "$run_dir"

run_dir=$(new_run_dir empty-fresh)
: >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 5
capture empty-fresh "$run_dir"

run_dir=$(new_run_dir empty-stalled)
: >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 600
capture empty-stalled "$run_dir"

run_dir=$(new_run_dir explicit-window-fresh)
printf '%s\n' '{"type":"window.fresh"}' >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 40
capture explicit-window-fresh "$run_dir" 60

run_dir=$(new_run_dir explicit-window-stalled)
printf '%s\n' '{"type":"window.stalled"}' >"$run_dir/events.jsonl"
pin_age "$run_dir/events.jsonl" 30
capture explicit-window-stalled "$run_dir" 30

capture usage-no-arguments
capture usage-invalid-directory "$CAPTURE_ROOT/absent"
