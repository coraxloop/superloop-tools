#!/usr/bin/env bash
# codex-lane — run one headless Codex lane with a mandatory wall-time
# budget, a JSONL event log the heartbeat watchdog can stat for growth,
# and a RUN-REPORT line (wall-time ruling: every action reports its
# duration).
#
# Usage:
#   codex-lane -t <budget_seconds> [-C <dir>] [-s <sandbox>] [-m <model>]
#              [-e <effort>] [-n <name>] <prompt | ->
#   codex-lane -t <budget_seconds> -r <session_id> -d <run_dir>
#              [-C <dir>] [-s <sandbox>] [-n <label>] <message | ->
#
#   -t  wall-time budget in seconds (mandatory; the lane is SIGKILLed
#       10s after budget as a backstop — exceeding budget is a finding)
#   -C  working root for the agent (default: current directory)
#   -s  sandbox: read-only | workspace-write | danger-full-access
#       (default: workspace-write)
#   -m  model override (default: ~/.codex/config.toml)
#   -e  model_reasoning_effort override (e.g. low, medium, high, xhigh)
#   -n  lane name for the run directory (default: lane); in resume
#       mode, the step label for the RUN-REPORT line
#   -P  PURE mode: a tool-less, context-clean consultation. The lane
#       runs with CODEX_HOME=~/.codex-pure (auth symlinked; NO
#       AGENTS.md, so no charter/instructions reach the model), cwd
#       forced to a fresh empty dir under the run dir, sandbox forced
#       read-only with sandbox_permissions=[], and every tool feature
#       disabled. Verified 2026-08-23 (codex 0.149.0): exec fails
#       closed ("code-mode host is disabled"), no AGENTS.md content in
#       context — the model sees ONLY the messages. Resumable: pass
#       -P again with -r/-d so the disables re-apply on every step
#       (sessions persist under ~/.codex-pure/sessions). KNOWN
#       RESIDUAL: collaboration.spawn_agent stays callable, but a
#       spawned agent inherits the same tool-dead pure config (no
#       exec, no filesystem, no network) — inert token spend only.
#       Per-turn input cap (backend, measured 2026-08-23): 1,048,576
#       chars — chunk bigger payloads across resume steps.
#   -r  resume mode: continue the session with this id (from the run's
#       thread.started event) — the gated PROCEED and VERIFY steps
#   -d  resume mode: the EXISTING run dir to continue (mandatory with
#       -r); events append to its events.jsonl, and the step owns
#       run-report.txt (deleted at step start, rewritten at step end,
#       so a log-eater keyed on its existence tracks the LIVE step)
#   prompt (or resume message) as one argument, or '-' for stdin.
#
# Artifacts in runs/<utc-stamp>-<name>/ under the repo root:
#   brief.txt, events.jsonl (watch THIS for stall detection),
#   last-message.txt (completion marker + result), run-report.txt
set -euo pipefail

: "${ORACLE_PROGRAM:?fixture program must be selected}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

budget="" workdir="$PWD" sandbox="workspace-write" model="" effort="" name="lane"
session="" resume_dir="" pure=""
while getopts "t:C:s:m:e:n:r:d:P" opt; do
  case "$opt" in
    t) budget="$OPTARG" ;;
    C) workdir="$OPTARG" ;;
    s) sandbox="$OPTARG" ;;
    m) model="$OPTARG" ;;
    e) effort="$OPTARG" ;;
    n) name="$OPTARG" ;;
    r) session="$OPTARG" ;;
    d) resume_dir="$OPTARG" ;;
    P) pure=1 ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))


[ -n "$budget" ] || { echo "codex-lane: -t <budget_seconds> is mandatory (wall-time ruling)" >&2; exit 2; }
[ $# -eq 1 ] || { echo "codex-lane: exactly one prompt argument (or '-') required" >&2; exit 2; }

if [ -n "$session" ]; then
  [ -n "$resume_dir" ] || { echo "codex-lane: -d <run_dir> is mandatory with -r (resume mode)" >&2; exit 2; }
  [ -d "$resume_dir" ] || { echo "codex-lane: no such run dir: $resume_dir" >&2; exit 2; }
  run_dir="$resume_dir"
  step_input="$run_dir/step-$name.txt"
  if [ "$1" = "-" ]; then cat > "$step_input"; else printf '%s\n' "$1" > "$step_input"; fi
  # The live step owns the finish marker: absent while running, so an
  # eater keyed on its existence follows THIS step, not a stale one.
  rm -f "$run_dir/run-report.txt"
else
  run_dir="$REPO_ROOT/runs/$(date -u +%Y%m%dT%H%M%SZ)-$name"
  mkdir -p "$run_dir"
  step_input="$run_dir/brief.txt"
  if [ "$1" = "-" ]; then cat > "$step_input"; else printf '%s\n' "$1" > "$step_input"; fi
fi

if [ -n "$pure" ]; then
  # Pure home: auth only, no AGENTS.md, minimal config. Created on
  # first use; auth.json is a SYMLINK so token refresh writes through.
  PURE_HOME="$HOME/.codex-pure"
  mkdir -p "$PURE_HOME"
  [ -e "$PURE_HOME/auth.json" ] || ln -s "$HOME/.codex/auth.json" "$PURE_HOME/auth.json"
  [ -e "$PURE_HOME/config.toml" ] || : > "$PURE_HOME/config.toml"
  if [ -e "$PURE_HOME/AGENTS.md" ]; then
    echo "codex-lane: $PURE_HOME/AGENTS.md exists — pure home is contaminated, refusing" >&2
    exit 2
  fi
  export CODEX_HOME="$PURE_HOME"
  workdir="$run_dir/cwd"
  mkdir -p "$workdir"
  sandbox="read-only"
fi

args=(exec --json --skip-git-repo-check -C "$workdir" -s "$sandbox"
      -o "$run_dir/last-message.txt")
if [ -n "$pure" ]; then
  args+=(-c 'sandbox_permissions=[]'
        --disable shell_tool --disable unified_exec --disable code_mode_host
        --disable multi_agent --disable apps --disable plugins
        --disable browser_use --disable browser_use_external
        --disable computer_use --disable image_generation
        --disable view_image --disable skill_search
        --disable skill_mcp_dependency_install --disable tool_suggest)
fi
[ -n "$model" ] && args+=(-m "$model")
[ -n "$effort" ] && args+=(-c "model_reasoning_effort=$effort")
[ -n "$session" ] && args+=(resume "$session")

# Budget is a REPORTING threshold, not a kill switch (user ruling
# 2026-08-22, after a healthy worker was SIGKILLed at budget expiry
# mid-wrap-up): past budget the lane is STUDIED, not shot. A worker
# whose events.jsonl keeps growing runs on (verdict OVER-BUDGET, a
# wall-time finding); only a worker with no event growth for
# LANE_STALL_WINDOW seconds past budget is killed (STALLED-KILLED),
# and LANE_RUNAWAY_MULT*budget is the absolute runaway backstop.
STALL_WINDOW="${LANE_STALL_WINDOW:-120}"
RUNAWAY_MULT="${LANE_RUNAWAY_MULT:-4}"

start=$(date +%s)
"$ORACLE_PROGRAM" "${args[@]}" - \
  < "$step_input" >> "$run_dir/events.jsonl" 2>> "$run_dir/stderr.txt" &
lane_pid=$!

kill_reason=""
last_size=0
last_growth=$start
while kill -0 "$lane_pid" 2>/dev/null; do
  sleep 5
  now=$(date +%s)
  size=$(stat -c%s "$run_dir/events.jsonl" 2>/dev/null || echo 0)
  if [ "$size" -gt "$last_size" ]; then last_size=$size; last_growth=$now; fi
  wall=$(( now - start ))
  if [ "$wall" -gt "$budget" ] && [ $(( now - last_growth )) -gt "$STALL_WINDOW" ]; then
    kill_reason=STALLED
  elif [ "$wall" -gt $(( budget * RUNAWAY_MULT )) ]; then
    kill_reason=RUNAWAY
  fi
  if [ -n "$kill_reason" ]; then
    kill -9 "$lane_pid" 2>/dev/null || true
    break
  fi
done
set +e
wait "$lane_pid"
exit_code=$?
set -e
wall=$(( $(date +%s) - start ))

verdict=ok
[ "$wall" -gt "$budget" ] && verdict=OVER-BUDGET
[ "$kill_reason" = STALLED ] && verdict=STALLED-KILLED
[ "$kill_reason" = RUNAWAY ] && verdict=RUNAWAY-KILLED
[ "$exit_code" -ne 0 ] && { [ "$verdict" = ok ] || [ "$verdict" = OVER-BUDGET ]; } && [ -z "$kill_reason" ] && verdict=FAILED

report="RUN-REPORT lane=$name exit=$exit_code wall=${wall}s budget=${budget}s verdict=$verdict dir=$run_dir"
printf '%s\n' "$report" | tee "$run_dir/run-report.txt"
exit "$exit_code"
