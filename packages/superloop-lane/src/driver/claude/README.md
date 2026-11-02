# `superloop-lane driver start --backend claude` · `guide:claudelane:claude-lane`

`superloop-lane driver start --backend claude` drives one fresh or resumed Claude CLI print-mode step through the shared `lane-lifecycle` durable run-directory contract.

Shared lifecycle diagnostics emitted by this driver are prefixed with `claude-lane: `.

## Command line · `sec:claudelane:command-line`

```text
superloop-lane driver start --backend claude -t BUDGET [-C DIR] [-s SANDBOX] [-m MODEL] [-e EFFORT] [-n NAME] [-P] [--pool-threshold F] [--ignore-pool] [--gateway-lane LANE] [--step-letter FILE] PROMPT|-
superloop-lane driver start --backend claude -t BUDGET -r SESSION -d RUN_DIR [-C DIR] [-s SANDBOX] [-m MODEL] [-e EFFORT] [-n STEP] [-P] [--pool-threshold F] [--ignore-pool] [--gateway-lane LANE] [--step-letter FILE] MESSAGE|-
Fresh launch environment: LANE_RUNS_ROOT=/absolute/runs
Boxed entry also supplies: LANE_RUN_DIR=/absolute/runs/R
```

The wrapper invokes the transported `backend_argv.claude` vector, appending `-p --output-format stream-json --verbose` and supplies the durable prompt bytes on standard input. It sets the process current directory instead of passing a working-directory flag and removes `CLAUDECODE` and every `CLAUDE_CODE_*` harness marker. A host launch runs directly as the owner, because the registered home is owner-held at mode 0700, and resolves the unique loop registry row whose effective runs root equals `LANE_RUNS_ROOT`, or the parent of `-d RUN_DIR` whenever that option is present. A row's explicit `runs_root` overrides `HOME/.var/loops/<name>/runs`. The driver sets its child's `CLAUDE_CONFIG_DIR` to `HOME/.config/loops/<name>/claude`; an explicit `CLAUDE_CONFIG_DIR` is accepted only when it equals that registered home, and a different value refuses `claude-home-mismatch`. No match refuses `claude-home-unregistered-loop`, multiple matches refuse `claude-home-ambiguous-loop`, and an absent registered home refuses `claude-home-absent`, all before spawn. A resume under an unregistered `legacy-runs` refuses as unregistered whether or not `LANE_RUNS_ROOT` is set. For a registered run root, a differing `LANE_RUNS_ROOT` refuses `claude-home-runs-root-mismatch`, naming both paths. With `LANE_RUN_DIR` present the boxed protocol instead takes its explicit configuration without reading the owner registry. Every form checks `claude-home-previous-layout` first; no previous-layout fallback exists.

Fresh mode allocates `{UTC-stamp}-{name}` beneath an absolute `LANE_RUNS_ROOT`; an unset, empty, or relative value is refused with a `LANE_RUNS_ROOT` diagnostic before any run directory is allocated or written. When the plain name exists, exclusive creation tries the next free suffix from `-2` through `-32`, never adopting an existing directory; another create error or exhaustion is a runtime failure. Resume uses the supplied run directory.

The shared lifecycle saves a fresh prompt as `brief.txt` before the child starts, records the active name in `.step-name`, and appends the Claude stream to `events.jsonl` with child errors in `stderr.txt`. A resumed step saves its input as `step-<name>.txt` and updates `.step-name`; a work-first round without a resume or `--step-letter` has no step file. With `--step-letter FILE`, fresh and resumed rounds save the letter body as the step text while retaining the positional pointer as child input, on host and boxed routes alike (`[LANELIFECYCLE-sec:lanelifecycle:resume-boundary]`). The active directory also holds `.event-start` and `.started-at`; completed steps publish `run-report.txt` and, when available, `last-message.txt`. Resume moves the prior report, last message, event bounds, and any `.feed-offset` (as `feed-offset.txt`) into `steps/{prior-step}/` and clears the active `.feed-offset` for the new step.

The mandatory `-t` budget sizes the planned work and marks a reporting threshold. At expiry, the driver latches budget, wall, event size, last-growth offset, quiet interval, and growth state in its atomic monitor sidecar, keeps Claude running, and updates the current `growing`, `stalled`, or `runaway` state on later polls. The monitor reports these states for the loop to decide whether to wait, write to the worker, or stop it explicitly. Natural success past budget retains `OVER-BUDGET`. New drivers never publish `STALLED-KILLED` or `RUNAWAY-KILLED` and never write `kill-evidence.txt`; old reports remain readable. The lane's Sonnet watcher relays these observations and owns continued waiting and its deadline; the session decides and messages that same live watcher with later duties.

|Lane sandbox|Claude permission arguments|
|------------|---------------------------|
|`read-only`|`--permission-mode plan`|
|`workspace-write`|`--permission-mode acceptEdits`|
|`danger-full-access`|`--permission-mode bypassPermissions --dangerously-skip-permissions`|

The first `system`/`init` event supplies `session_id`. The last nonempty terminal `result` string supplies `last-message.txt`; an empty terminal result falls back to the last nonempty text block in an `assistant` event. Events remain byte-for-byte Claude stream JSON for the schema-agnostic `lane-feed` consumer.

A terminal `result` line on the transcript's last complete line also states the finish a killed driver never recorded: its `is_error` gives the exit and verdict, and its `duration_ms` gives the wall of the step the shared resume boundary reconstructs.

## Pure mode · `sec:claudelane:pure-mode`

`-P` selects `HOME/.claude-pure`, links `.credentials.json` from the resolved Claude configuration directory only when the link is absent, creates an empty `settings.json`, refuses a `CLAUDE.md`, forces an empty run-local `cwd` and read-only operation, and passes `--tools "" --setting-sources "" --permission-mode plan`. Deployment records the pure link's `readlink` before and after the per-loop moves; the move command refuses the pure home.

## Rate limits · `sec:claudelane:rate-limits`

Several lane homes signed into one account share one window, so a dispatch can be refused before any work happens. A refused dispatch exits nonzero within seconds and its transcript's first line is a `rate_limit_event`; without reading it the step is indistinguishable from one that ran and failed, and the reset time the event carries is lost.

The driver reads that event from the step's own event region alone. A top-level `rate_limit_event` line whose nested `rate_limit_info.status` is `rejected` makes the verdict `RATE-LIMITED` at exit 1, states the window and its reset on standard error, and leaves `rate-limit.txt` in the run directory with the status, window, utilization, and reset time as both epoch and ISO-8601 UTC. These are the two shapes the reader decodes:

```json
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1789820400,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"org_level_disabled","isUsingOverage":false,"unifiedWindows":{"five_hour":{"utilization":1,"resetsAt":1789820400},"seven_day":{"utilization":0.28,"resetsAt":1790301600}}},"uuid":"...","session_id":"..."}
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","surpassedThreshold":0.9,"resetsAt":1789820400,"rateLimitType":"five_hour","unifiedWindows":{"five_hour":{"utilization":0.97,"resetsAt":1789820400}}},"uuid":"...","session_id":"..."}
```

`rate_limit_info` is a nested object, so every field is decoded through that object's own span; utilization is the `five_hour` window's reading when the event carries the window table.

After every step the last such event in the step's region is recorded as `lane-pool.json` in the resolved registered home, or the explicit boxed configuration, carrying `status`, `rate_limit_type`, `utilization`, `resets_at`, `observed_at`, and `run_dir`. There is no desktop-home fallback. A step whose region carries no such event leaves the file exactly as it was.

Before it spawns a child the driver reads that file and refuses the dispatch with exit 2, one `dispatch_rate_limited` diagnostic on standard error, the fallback `FAILED` report as its one terminal standard-output line with `dir=unknown`, and no run directory at all, when the record was observed before its own window reset, that window has still not reset, and either the status is `rejected` or the utilization is at or above `--pool-threshold` (default 0.95). `--ignore-pool` dispatches regardless. A missing, unreadable, or already-reset record is ignored: the read is one step old and advisory, and the rejection verdict is what guarantees a refused dispatch is legible.

## Test matrix · `sec:claudelane:test-matrix`

|Layer|Cases|Evidence|
|-----|-----|--------|
|Backend parser|Captured init, result, and assistant lines; nested and reordered keys; rejection and warning rate-limit events|Session identity, last-message selection, and pool state use structurally correct top-level and nested extraction.|
|Subprocess contract|Normal, fallback, resume and mismatch, stall, runaway, stdin, three permissions, environment, pure mode, rejected dispatch, pool refusal and its overrides|Only the committed Claude stub runs; argv, input, cwd, environment, artifacts, status, and reports are asserted.|

The entry transports executable arrays and their trusted source evidence in `LANE_DRIVER_ARGV`, `LANE_BACKEND_ARGV` and `LANE_SETTINGS_EVIDENCE`. Missing selectors refuse before allocating a run directory. Each executed step saves `backend-settings.json`; its run report names the configured absolute backend program, settings path and SHA-256 of the selected settings evidence. Report words percent-encode nonportable bytes. Host execution appends the backend grammar to the configured vector; boxed execution retains its fixed run-directory protocol.
