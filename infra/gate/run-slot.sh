#!/usr/bin/env bash
# Sourced by the sampler fixture and embedded in the submitter's remote script.
# Missing kernel counters remain unknown; shared cgroup CPU is not own CPU.
samp_init() {
  local hierarchy controllers path
  CGN=unknown
  while IFS=: read -r hierarchy controllers path; do
    if [ "$hierarchy" = 0 ] && [ -z "$controllers" ]; then CGN=$path; break; fi
  done < "/proc/$$/cgroup"
  CG=${1:-/sys/fs/cgroup$CGN}
  [ "$#" -eq 0 ] || CGN=$1
  CLK=$(getconf CLK_TCK)
  declare -gA SAMP_START=()
  CUR=
}

own() {
  local stat
  IFS= read -r stat < "/proc/$$/stat"
  # Strip through the last closing parenthesis: comm can contain spaces or ')'.
  stat=${stat##*) }
  awk -v c="$CLK" -v s="$stat" 'BEGIN {split(s, a, " "); printf "own_user_s=%.6f own_system_s=%.6f", (a[12]+a[14])/c, (a[13]+a[15])/c}'
}

samp() {
  local battery=$1 edge=$2 now key value rest resource class item values
  local -A counters=()
  now=$(date +%s.%N)
  if [ -r "$CG/cpu.stat" ]; then
    while read -r key value rest; do counters["cpu_$key"]=$value; done < "$CG/cpu.stat"
  fi
  for key in memory.current memory.peak; do
    if [ -r "$CG/$key" ]; then read -r value < "$CG/$key"; counters["${key/./_}"]=$value; fi
  done
  for resource in cpu memory io; do
    if [ -r "$CG/$resource.pressure" ]; then
      while read -r class rest; do
        for item in $rest; do counters["${resource}_${class}_${item%%=*}"]=${item#*=}; done
      done < "$CG/$resource.pressure"
    fi
  done
  values="t=$now $(own)"
  for key in cpu_usage_usec cpu_user_usec cpu_system_usec cpu_nr_throttled memory_current memory_peak; do
    values+=" $key=${counters[$key]:-?}"
  done
  for resource in cpu memory io; do
    for class in some full; do
      for item in avg10 avg60 avg300 total; do
        key=${resource}_${class}_$item
        values+=" $key=${counters[$key]:-?}"
      done
    done
  done
  printf 'SAMPLE %s %s cgroup=%s scope=shared-or-unisolated %s\n' "$battery" "$edge" "$CGN" "$values"
  if [ "$edge" = start ]; then
    SAMP_START[$battery]=$values
  elif [ -n "${SAMP_START[$battery]:-}" ]; then
    awk -v b="$battery" -v cg="$CGN" -v before="${SAMP_START[$battery]}" -v after="$values" '
      BEGIN {
        n=split(before, old, " "); for (i=1;i<=n;i++) {split(old[i], pair, "="); start[pair[1]]=pair[2]}
        n=split(after, new, " "); split(new[1], pair, "=")
        printf "DELTA %s wall=%.6fs cgroup=%s scope=shared-or-unisolated", b, pair[2]-start["t"], cg
        for (i=2;i<=n;i++) {
          split(new[i], pair, "="); key=pair[1]
          if (pair[2]=="?" || start[key]=="?") printf " %s=?", key
          else printf " %s=%.6f", key, pair[2]-start[key]
        }
        printf "\n"
      }'
    unset 'SAMP_START[$battery]'
  fi
}

sec() {
  [ -z "$CUR" ] || samp "$CUR" end
  CUR=$1
  samp "$CUR" start
  printf '== %s ==\n' "$CUR"
}

samp_finish() {
  [ -z "$CUR" ] || samp "$CUR" end
  CUR=
  samp gate end
}

# END GATE SAMPLER
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return; fi
# Meson substitutes the release group's manifest or ledger version.
if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
  printf '%s\n' '{"schema":1,"command":"run-slot.sh","kind":"version","message":"version requested","fields":{"type":"version","version":"run-slot.sh @VERSION@"}}' >&2
  exit 0
fi
# Run one gate in a persistent, exclusively held workspace and target slot.
set -euo pipefail
if [ "$#" -lt 3 ] || [[ $1 != /* || ! $2 =~ ^[0-9]+$ ]]; then
  echo 'gate-slot-arguments: expected absolute root, numeric slot, and command' >&2
  exit 2
fi
root=$1
slot=$2
shift 2
samp_init
samp gate start
trap 'samp_finish' EXIT
mkdir -p "$root"
exec 9>"$root/slot-$slot.lock"
if ! flock -w 120 9; then
  echo 'gate-slot-lock: workspace remained occupied for 120 seconds' >&2
  exit 2
fi
checkout=$root/slot-$slot
mkdir -p "$checkout" "$root/tmp-slot-$slot"
export CARGO_TARGET_DIR=$root/target-slot-$slot
export TMPDIR
TMPDIR=$(mktemp -d "$root/tmp-slot-$slot/round.XXXXXX")
cleanup() {
  local status=$?
  trap - EXIT
  if ! chmod -R u+rwX "$TMPDIR" || ! rm -rf -- "$TMPDIR"; then
    echo 'gate-slot-cleanup: scratch removal failed' >&2
    samp_finish
    exit 2
  fi
  samp_finish
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cd "$checkout"
rm -f result.json
status=0
sec command
"$@" || status=$?
if ! rustc --version --verbose > "$TMPDIR/compiler"; then
  echo 'gate-slot-compiler: compiler version unavailable' >&2
  exit 2
fi
python3 - "$checkout/result.json" "$TMPDIR/compiler" "$CARGO_TARGET_DIR" "$status" <<'PY'
import json
import os
import sys

path, compiler, target, status = sys.argv[1:]
with open(compiler, encoding="utf-8") as source:
    version = source.read()
with open(path + ".tmp", "w", encoding="utf-8") as output:
    json.dump({"schema": 1, "compiler": version, "target": target,
               "exit_code": int(status)}, output)
os.replace(path + ".tmp", path)
PY
exit "$status"
