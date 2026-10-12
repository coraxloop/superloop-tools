# `superloop-lane driver start --backend codex` · `guide:codexlane:codex-lane`

`superloop-lane driver start --backend codex` owns one fresh or resumed headless Codex lifecycle step. It is the Rust port of `reference/codex-lane.sh`; the ratified lane lifecycle and output specifications govern wherever the deployed reference differs.

The backend-independent durable process lifecycle lives in `lane-lifecycle`; this package supplies only the Codex command, event interpretation and compatibility API.

## Command line · `sec:codexlane:command-line`

```text
superloop-lane driver start --backend codex -t BUDGET [-C DIR] [-s SANDBOX] [-m MODEL] [-e EFFORT]
           [-n NAME] [--pool-threshold F] [--ignore-pool]
           [--gateway-lane LANE] PROMPT|-
superloop-lane driver start --backend codex -t BUDGET -r SESSION -d RUN_DIR [-C DIR] [-s SANDBOX]
           [-m MODEL] [-e EFFORT] [-n STEP] [--pool-threshold F]
           [--ignore-pool] [--gateway-lane LANE] MESSAGE|-
Fresh launch environment: LANE_RUNS_ROOT=/absolute/runs
Boxed entry also supplies: LANE_RUN_DIR=/absolute/runs/R
```

`CODEX_HOME` must be nonempty for host start and resume. An absent or empty value is refused by name before the vendor child starts. Boxed starts and resumes take the child environment, including its home, from `runtime.env`; the boxed driver does not require or inherit a host `CODEX_HOME`.

`-t` is a mandatory positive decimal reporting threshold in seconds. `-C` defaults to the caller's current directory. `-s` defaults to `workspace-write` and accepts `read-only`, `workspace-write`, and `danger-full-access`. `-m` and `-e` add model and reasoning-effort controls. `-n` defaults to `lane`; in fresh mode it names the run and in resume mode it uniquely names the step. A literal `-` reads its bytes from standard input; an argument prompt receives the reference's terminating LF.

Short options retain the reference's `getopts` forms: values may be separate or attached and retired `-P` requests, including clustered forms, refuse before vendor launch. Harness-level options are assembled before `resume SESSION`. `-d` without `-r` remains an ignored compatibility input.

## Fresh, resume, and artifacts · `sec:codexlane:fresh-resume-and-artifacts`

Fresh mode exclusively allocates `{UTC-stamp}-{name}` beneath an absolute `LANE_RUNS_ROOT`; an unset, empty, or relative value is refused with a `LANE_RUNS_ROOT` diagnostic before any run directory is allocated or written. When the plain name exists, exclusive creation tries the next free suffix from `-2` through `-32`, never adopting an existing directory; another create error or exhaustion is a runtime failure. Resume mode requires the named directory, its settled report, no live step lock, an event-stream thread identity matching `SESSION`, and a step name not already used in that lane. A refusal names the missing report, conflicting step path, live lock, or missing, unreadable, or mismatched event stream on standard error. A dead holder's lock is recovered through the shared boundary, which reconstructs a killed driver's finish from the terminal result event the step's own region ends on: a completed Codex turn closes with `turn.completed` immediately after its last `item.completed`, and a turn the provider ended closes with `turn.failed`. A region ending in neither belongs to a step that never finished and is recovered as a CRASHED step. A dead holder whose recorded child is still alive is not recovered at all — the lock is live and names that child, because the step is still producing.

For a boxed launch, the entry starts the driver as the loop UID and carries `driver_argv`, `backend_argv` and their source evidence as JSON in `LANE_DRIVER_ARGV`, `LANE_BACKEND_ARGV` and `LANE_SETTINGS_EVIDENCE`. `LANE_BOXED_RUNTIME=1` selects the fixed NUL-framed client vector at `LANE_RUN_DIR/launch/runtime.argv`; the driver reads that bounded protocol file and its paired `runtime.env` and starts only the client. The client forwards a bounded prompt, streams and status through the loop-group socket to the namespace-owner helper, which checks the saved container vector and environment against the protected plan before using the local image store. A Codex event reporting that the selected model is at capacity triggers the shared lifecycle's bounded retry; the helper gives each container attempt a distinct name and identifier file and the driver reports each attempt outside the worker home. In a box, the helper retains the thread from its own attempt capture, falling back to the validated round request when no thread was captured, and resumes it in the same writable `.codex` home. Attempt status evidence names `thread_id`, `resume_thread` and `thread_id_source`; the source is `captured`, `requested`, or null when neither supplied an identity, and an attempt record without `thread_id_source` predates the field and does not say where its `thread_id` came from. The helper cannot guarantee the vendor flushed that thread's rollout before failure, and a missing rollout never triggers a fresh-thread fallback. A capacity retry uses the same prompt, including a dispatch retry, while preserving the original round-request checks. Capacity evidence comes from complete lines in a bounded tail, so a transcript larger than 1 MiB does not disable retry.

```text
brief.txt
step-{step-name}.txt
events.jsonl
stderr.txt
last-message.txt
run-report.txt
.feed-offset
.started-at
steps/{prior-step}/started-at.txt
```

Input is durable before the child starts. Child standard output appends to `events.jsonl`; standard error appends to `stderr.txt`; and `-o` names `last-message.txt`. On an empty output file, the driver recovers the last nonempty `agent_message` text from retained JSONL events. Existing event bytes are never rewritten.

The active step also owns `.step-name`, `.event-start`, and `.started-at`. At a resume boundary the preceding report, last message, event bounds, `started-at.txt` when present, historical `kill-evidence.txt` when present, and capture-consumer offset when present move into immutable `steps/{prior-step}/` history. Only after that history and the new input are durable does the shared marker disappear. The active `.feed-offset` is removed so the next capture invocation begins at byte zero and the lane's existing Sonnet watcher can replay the retained backlog after its new-duty message; the archived offset preserves the prior capture consumer's accepted boundary.

`run-report.txt` is absent while the wrapper owns a live step. After the child has been waited and all result evidence has settled, the complete report is written to a same-directory temporary file, synced, and renamed into place. No observer can open an empty or partial marker.

## Budget and process disposition · `sec:codexlane:budget-and-process-disposition`

The effective budget is mandatory for sizing and is a reporting threshold. Natural success above it returns 0 with `OVER-BUDGET`; natural nonzero completion returns shared failure 1 even after an overrun.

The protocol constants are fixed at a strictly-more-than 120-second no-growth window and a strictly-more-than four-times-budget runaway threshold. At the first poll beyond budget the driver latches the expiry tuple in its atomic monitor sidecar: budget, wall, event size, last-growth offset, quiet interval, and state. Later sidecars keep that tuple while updating the current `growing`, `stalled`, or `runaway` state. When both thresholds cross on one probe, the more specific stall classification wins. Compatibility environment values cannot silently select different protocol constants.

Budget expiry and its stall or runaway states do not signal the child. The driver keeps observing it, and `worker-monitor` publishes the expiry and state changes for the Sonnet watcher to relay and the loop to decide whether to assign continued watching, write to the worker, or stop it explicitly. New drivers never publish `STALLED-KILLED` or `RUNAWAY-KILLED` and never write `kill-evidence.txt`; historical reports with those verdicts remain readable.

A finished child is classified by its result: a successful turn above budget reports `OVER-BUDGET` at status 0, and a failed turn reports `FAILED` at status 1. A `SIGTERM` or `SIGINT` sent explicitly to the driver stops its child; a durable terminal result still determines the verdict and last message, while an unfinished child publishes `FAILED` at status 1. A boxed round stopped cooperatively by a placed `Stop: yes` letter ends `by-report-after-stop` after a successful worker report.

Every terminal line has this byte-stable agent-text shape:

```text
RUN-REPORT lane=NAME exit=STATUS wall=SECONDSs budget=BUDGETs verdict=VERDICT dir=RUN_DIR
```

The line is the final authored standard-output line and its decimal status equals the direct caller's status. Malformed usage, runtime, and suppressed-panic paths place one `codex-lane: ` classed diagnostic before a failed report. Resume-boundary refusals instead place a path-bearing, classed diagnostic on standard error and leave the failed report as the sole standard-output line. Before a valid identity or directory exists, the fallback fields are `lane=unknown` and `dir=unknown`.

## Context observation · `sec:codexlane:context-observation`

The pinned Codex 0.157.0 `exec --json` stream ends a completed turn with `turn.completed.usage`, whose five counters are cumulative token usage for the thread; neither that event nor another `exec --json` event reports the current context or its model window. The driver publishes one `context.jsonl` record per completed or failed turn, identified by the event's ending byte offset, with `used`, `window`, and `fraction` null, `state=unknown`, the source and named reason, the turn ordinal, and a UTC instant; its live monitor record carries the same unknown state. Publication atomically replaces a complete record set, and recovery reconciles complete event lines with the records, repairing a trailing partial line or a missed turn without duplicating an event boundary. The cumulative counters never substitute for context consumption, so this record cannot trigger rotation until a measured field and window are established from a host run.

The record's `at` is the driver's UTC observation time: the scan that saw the complete event line, or the recovery scan when a missing record is reconstructed.

## Rate limits · `sec:codexlane:rate-limits`

The shared driver publishes `RATE-LIMITED` at exit 1 when a step's own event region carries the provider refusing its dispatch, and records the last such event as `lane-pool.json` in the lane home the step dispatched from — the required `CODEX_HOME` for host dispatches, or the boxed driver's `HOME/.codex` for boxed dispatches. The boxed location retains the existing driver pool metadata route; it does not select the vendor child's home, which comes from `runtime.env`. Before spawning a child it refuses to dispatch with exit 2 and a `dispatch_rate_limited` diagnostic when that record was observed before its own window reset, the window has still not reset, and either the recorded status is `rejected` or the recorded utilization is at or above `--pool-threshold` (default 0.95); `--ignore-pool` dispatches regardless, and a missing, unreadable, or already-reset record is ignored.

These are the event shapes the shared reader decodes, as the Claude backend records them:

```json
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1789820400,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"org_level_disabled","isUsingOverage":false,"unifiedWindows":{"five_hour":{"utilization":1,"resetsAt":1789820400},"seven_day":{"utilization":0.28,"resetsAt":1790301600}}},"uuid":"...","session_id":"..."}
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","surpassedThreshold":0.9,"resetsAt":1789820400,"rateLimitType":"five_hour","unifiedWindows":{"five_hour":{"utilization":0.97,"resetsAt":1789820400}}},"uuid":"...","session_id":"..."}
```

No recorded Codex transcript in this package's fixtures carries an event for the vendor's usage limit, so the Codex shape is not yet known to carry a rejection at all. This backend therefore reports no rejection and no pool state for every transcript: a refused Codex dispatch stays a `FAILED` step, and it will keep doing so until a captured transcript states the shape. Classifying on a guessed shape would be worse than the true poorer report, because a wrong guess misclassifies ordinary failures.

## PURE mode · `sec:codexlane:pure-mode`

Codex `-P` is retired. Fresh and resumed pure requests return a usage failure before starting a vendor child and never read or create `~/.codex-pure`. Ordinary owner-side lanes use `CODEX_HOME=~/.config/loops/<loop>/codex/` with the direct tools-publication charter link; there is no replacement pure home. Claude pure mode remains unchanged.

## Process-wrapper choice · `sec:codexlane:process-wrapper-choice`

This package uses `std::process` and carries no dependency edge. `superloop-execwrap` was evaluated first. Its library owns the child through a blocking wait and returns only after completion, so it cannot expose the live handle required for event-growth probes, signal/wait agreement, or studied-overrun monitoring. It also has no per-run standard-input source or command environment/current-directory API, and its file routes are truncating capture destinations rather than append-only lane evidence. Consuming it would leave the lifecycle boundary implemented a second time beside the wrapper.

## Reference divergences · `sec:codexlane:reference-divergences`

|Governing specification|Named fixture|Governed behavior|
|-----------------------|-------------|-----------------|
|(`[ORCHESTRATION-req:lanes:read-back-evidence]`), (`[ORCHESTRATION-rule:lanes:step-owned-marker]`), (`[ORCHESTRATION-verif:lanes:lifecycle-replay]`)|`resume_matches_shell_invocation_and_preserves_step_history`|The shell clobbers the shared report and retains only one live offset. Rust archives report, message, event bounds, and offset under the preceding step identity.|
|(`[ORCHESTRATION-inv:lanes:marker-after-evidence]`)|`marker_publication_is_atomic`|The shell's `tee` exposes an empty or partial marker. Rust syncs a complete temporary file and renames it into place.|
|(`[ORCHESTRATION-proto:lanes:watcher-probe]`), (`[ORCHESTRATION-spec:lanes:watcher-verdicts]`)|`every_allocated_run_is_live_until_a_finished_marker_exists`|A shell failure after allocation can leave a terminated producer without a settled marker. Rust publishes a failed marker on every writable post-allocation terminal path.|
|(`[TOOLS-spec:output:codex-lane-report]`), (`[TOOLS-req:output:agent-text-status-agreement]`), (`[ORCHESTRATION-rule:lanes:runaway-termination]`), (`[ORCHESTRATION-scenario:lanes:stalled-step]`)|`budget_expiry_leaves_codex_running_until_natural_completion`, `runaway_is_a_live_state_without_a_signal`|The shell kills at the stall and runaway bounds and returns signal-derived status 137. Rust signals nothing at either bound: it records the expiry and the `stalled` or `runaway` state in the monitor sidecar and publishes the child's natural result.|
|(`[ORCHESTRATION-def:lanes:feeder-offset]`), (`[ORCHESTRATION-proto:lanes:feeder-completion]`), (`[ORCHESTRATION-rule:lanes:log-eater-replacement]`)|`fresh_follower_replays_from_zero_at_resume_boundary`|The shell leaves the preceding capture consumer's offset active, so a new step can skip retained context. Rust archives it and starts the new capture invocation from zero.|
|(`[ORCHESTRATION-req:lanes:read-back-evidence]`)|`empty_output_uses_last_nonempty_agent_message`|The reference leaves an empty last-message file; Rust recovers the last nonempty agent message from events.|
|(`[ORCHESTRATION-term:lanes:fresh-launch]`), (`[ORCHESTRATION-rule:lanes:run-isolation]`)|`fresh_allocation_refuses_a_timestamp_name_collision`|The shell merges a colliding fresh path. Rust's leaf allocation is exclusive.|
|(`[ORCHESTRATION-term:lanes:gated-resume]`), (`[ORCHESTRATION-rule:lanes:run-isolation]`)|`resume_refusal_names_missing_prior_report`, `resume_refusal_names_existing_step_input`, `resume_refusal_names_existing_step_history`, `resume_refusal_names_live_lock`, `resume_refusal_names_missing_event_stream`, `resume_refusal_names_unreadable_event_stream`, `resume_refusal_names_thread_mismatch`|The shell accepts invalid resume boundaries and can overwrite duplicate step input. Rust refuses every boundary violation before changing the marker and names its offending path.|
|(`[ORCHESTRATION-proto:lanes:fresh-launch]`), (`[TOOLS-proto:output:run-report-line]`)|`usage_error_matrix_returns_two_and_a_final_report`|The shell accepts nonpositive budgets and unchecked sandbox/name values, then emits usage prose without a report. Rust validates them and every usage path ends in one status-2 failed report.|
|(`[ORCHESTRATION-term:lanes:wall-time-classification]`)|`event_growth_resets_only_the_stall_basis`, `stall_takes_priority_when_both_kill_bounds_cross`|The shell permits environment-selected monitor constants. Rust fixes the ratified values; synthetic clocks vary observations, not policy.|
|(`[TOOLS-rule:output:panics]`), (`[TOOLS-spec:output:codex-lane-report]`)|`panic_before_argument_handling_is_suppressed_and_reported`, `panic_after_argument_handling_is_suppressed_and_reported`|Rust suppresses default panic presentation and emits fixed internal-failure evidence plus one matching report.|

## Test isolation · `sec:codexlane:test-isolation`

Subprocess tests inject only a committed fake Codex executable, isolated homes and repositories, fixed UTC stamps, and monotonic clock samples. Budget cases hold a busy stub past expiry and release it to complete naturally; tests contain no wall-clock sleeps. The historical shell-oracle generator shadows `date` and `sleep`, allowing reference timing captures without elapsed waiting. Its seven-case, eighty-four-file capture records terminal streams, status, child argv/input, event/message/report bytes, and deployed artifact layout.

The entry transports executable arrays and their trusted source evidence in `LANE_DRIVER_ARGV`, `LANE_BACKEND_ARGV` and `LANE_SETTINGS_EVIDENCE`. Missing selectors refuse before allocating a run directory. Each executed step saves `backend-settings.json`; its run report names the configured absolute backend program, settings path and SHA-256 of the selected settings evidence. Report words percent-encode nonportable bytes. Host execution appends the backend grammar to the configured vector; boxed execution retains its fixed run-directory protocol.
