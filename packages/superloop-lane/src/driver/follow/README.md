# `superloop-lane driver follow` · `guide:workermonitor:worker-monitor`

`superloop-lane driver follow` follows one worker-lane run directory and publishes one schema-two JSON envelope per completed invocation. Every successful document begins with a sampled worker state; event deltas and completion follow when ready. It batches event deltas with a caller-selected quiet window while completion, cap pressure, and worker heartbeats remain immediate. This executable is the capture tool used by a lane's Sonnet watcher, not another agent; the watcher owns step and gate waiting, relay and deadlines, and the session decides from its hand-back.

Backlog entry 47 replaces the Python feeder's byte frames. The Rust package is therefore governed by this contract rather than byte compatibility with the Python reference.

## Command line · `sec:workermonitor:command-line`

```text
superloop-lane driver follow RUN-DIR [--save-offset] [--cap BYTES] [--bounce SECONDS] [--wait SECONDS]
```

All three options also accept joined spellings (`--cap=BYTES`, `--bounce=SECONDS`, and `--wait=SECONDS`) and may precede the run directory. The default cap is 50,000 bytes. The default bounce is 30 seconds; `--bounce 0` restores immediate delta service. The default wait is 0, which waits until a delta or completion is served; a positive wait bounds the invocation and publishes state alone when it expires without either record.

Cap, bounce, and wait values share the reference helper's nonnegative Python-integer grammar: surrounding whitespace, one leading plus, negative zero, and digit-separated underscores are accepted; other negative or malformed values are usage errors. Positive values beyond `u64` saturate at `u64::MAX`.

On a box run, the lane's Sonnet watcher invokes the capture tool through `timeout 110 superloop enter LOOP -- ~/.local/bin/superloop-lane driver follow --save-offset ROUND-DIR --bounce 30 --wait 70` as the loop identity that owns the run, where ROUND-DIR is the round's recorded driver directory holding `events.jsonl`; the caller's shell expands `~` before the entry runs, so the entry's fixed `PATH` does not need the owner's deployment directory. The runbook pins the equivalent full path instead. The session owner cannot search that private run; the Sonnet watcher's outside-box `timeout` bounds each inner call at 110 s inside a foreground script loop bounded at 420 s, run with a 600000 ms tool timeout. On every call, the monitor reads the newline-terminated journal rows for each published outbox name and lists `.reply-receipts/` in the round holding its latest observation, selecting the newest observation instant and revision across the run root and its direct round directories; the pinned run's `plan.json` establishes mailbox coverage, and the owner-private reservation is never read; `.tmp-` names are ignored, and an unplanned shim has no mailbox coverage. It emits `NEW MESSAGE name=NAME at=UTC_INSTANT revision=N` on stderr for an unreceipted name or revision not yet announced in this capture directory, independently of `unread_letters`, `.letter-count` and the delivery markers; stdout remains one schema-two JSON capture. The name uses canonical bytewise percent escaping. The shared `lane_lifecycle::reply_observations` resolver selects the observation that first recorded the current file version: a completion-only row retains it, while an inode or nanosecond ctime change measured by the driver mailbox observer's descriptor-relative `fstatat` starts a new observation, even at the same size; recorded device numbers remain data and do not participate in version comparison. A receipt name is the lowercase SHA-256 of that selected observation's compact serialized journal `identity` array `[box, name, revision, at]`, followed by `.json`; only receipt names and metadata are inspected, never 0600 receipt bodies or worker replies. The monitor holds directory descriptors, checks the calling identity's search bit on every ancestor through the selected round, and names an inaccessible ancestor as `outbox-search` with the required directory owner; unsafe paths and malformed records also refuse by name. An outbox refusal emits one escaped `OUTBOX REFUSAL kind=KIND detail=DETAIL` stderr line per call and stops further outbox scans for that call, while capture, waiting and the capture's exit status continue unchanged. Within a call, the monitor holds metadata watches and repeats the outbox scan only when a journal's size or nanosecond mtime, the run or receipt directory's mtime, or a watched binding, mode or plan changes; the capture's letter journal and delivery markers are also cached until their size or mtime changes. Samples are taken before parsing so a concurrent change remains eligible on the next poll. Every call rebuilds the unread listing from observations and receipts; a new name or revision releases the wait even after a hand-back or during a read. Observations do not prove completion; only a `finished` record does. The Sonnet watcher hands back unknown observations once, including on every resumed turn, never also by message; the session reads replies with `superloop-lane read-reply LOOP RUN NAME` and messages the same live watcher with its next duty. At a mid-round spawn, the first hand-back carries the initial `NEW MESSAGE` and `OUTBOX REFUSAL` lines once, excluding the watched round's exact `STEP.md` name and acknowledgements of session-placed letters matching `STEP-N.md` for that round's STEP (including `dispatch-N.md`) at any revision, including revisions 1 and 2, which are Known by pattern; other worker-authored requests, questions, clarifications and status files are handed back even when their names begin with the watched step name. Only after that hand-back are the initial observations Known, without a hand-built list. Read receipts already remove delivered replies from the capture, so suppressing its initial observations would lose unread replies that arrived while the watcher was dead. Saving calls remember announced reply names and revisions in `.announced-replies.json`; a previously announced unreceipted revision holds until independent evidence or bounded expiry, when it is listed as `announced-before`. A receipt prunes the set after publication. The watcher keeps Known observations in its session context after hand-back and recovers them from the session after replacement. Bare follow reads every delivery cursor without changing it; `--save-offset` saves the declared capture position.

## Debounce · `sec:workermonitor:debounce`

The bounce window is anchored to `events.jsonl`'s own modification timestamp, never to the time the monitor was invoked. A log already quiet for the whole window is served immediately; the caller does not pay a new fixed delay.

When unread bytes exist, the delta is served as soon as any one condition is true:

1. the log mtime is at least the bounce window old;
2. unread bytes are at least the cap;
3. `run-report.txt` exists and can be read as the settled completion report; or
4. the unread region's last complete line is a heartbeat — a JSON object whose top-level `type` is `tool_progress` and whose `heartbeat` is boolean true.

The second condition is a pressure valve for a sustained stream. The third preempts the hold and publishes the pending delta before the finished record in the same envelope. While none holds, the monitor remains pending and keeps the existing one-second poll interval, bounded by a positive `--wait`.

The fourth condition exists because a hold anchored to the log's own timestamp can never close while a heartbeat keeps arriving. A worker inside one long tool call appends a liveness heartbeat on a cadence at or under the default window, so the mtime is younger than the window on effectively every poll: `superloop-lane driver follow` waits out its own timeout and publishes nothing while the worker is alive and the transcript is growing. The debounce exists to batch a burst of real events, and a tail that is a heartbeat is not a burst — it is the worker reporting that it is alive, which is the very thing the Sonnet watcher is waiting to read.

The probe reads at most the last eight kibibytes of the unread region rather than the whole file, and only a newline-terminated line counts: a half-written heartbeat is still being appended, so it is not the region's last complete line and releases nothing. A release publishes the whole unread region, the real events ahead of the heartbeat included, and the record shape is unchanged — the heartbeat travels as an ordinary event inside the delta record's `events`, so a reader sampling event types sees new content rather than an empty run.

An unreadable mtime fails open and serves the delta. An mtime in the future has age zero and holds unless cap, completion, or a heartbeat tail preempts it.

## State record · `sec:workermonitor:state-record`

The first record of every successful document has these fields in this order. It is sampled once immediately before publication, so a reader can decide whether the driver is present, how fresh the event source is, how far the step has progressed, and whether the report has settled without inferring state from an empty round.

|Field|Meaning and reason|
|-----|------------------|
|`kind`|Always `state`, identifying the first record.|
|`at`|The sample instant in RFC 3339 UTC seconds with a `Z` suffix, anchoring all ages.|
|`step`|Trimmed `.step-name` text, or null when missing or unreadable, naming the lifecycle step.|
|`started_at`|Trimmed `.started-at` text, or null when missing or unreadable, preserving the driver's start marker.|
|`wall_seconds`|Seconds from a parseable RFC 3339 UTC `started_at` to `at`, or null when the marker is missing or invalid, showing step wall progress.|
|`driver`|The selected lock's file name, driver `pid`, optional `child`, and `alive`; null when no valid lock exists. A live driver PID wins over a stale driver PID, then modification time and lock name break ties. `alive` is true while either named process is live, including when the driver has died but its child continues.|
|`events`|The event source's byte size and `age_seconds`, or null when the source is missing. For an unsettled step with a live driver and a valid monitor capture no later than the reader's boot clock, age is the producer's awake `quiet` plus boot seconds since publication, matching lane-watch's upper bound until the producer republishes after sleep. Otherwise age uses mtime; an unreadable mtime gives null and a future mtime gives zero. This shows source freshness independently of new delta bytes.|
|`monitor`|Parsed fields `quiet`, `wall`, `event_size`, `boot`, `awake`, optional `awaiting` as `lane:sequence`, and `context` from the valid `.monitor-PID-SEQUENCE` capture matching the selected driver PID with the greatest boot timestamp, breaking ties by sequence; null when no capture qualifies. The context object has `state`, `used`, `window`, `fraction`, `source`, `reason`, `turn`, and `at`, or is null when the line has no context fields. New sidecars also carry `budget` and `last_growth`; from expiry onward they carry current `state` (`growing`, `stalled`, or `runaway`) and an immutable `expiry` object with `wall`, `event_size`, `last_growth`, `quiet`, and `state` from the first over-budget poll.|
|`report`|Whether `run-report.txt` exists, identifying a settled step marker.|
|`last_message`|Whether `last-message.txt` exists, showing optional result data without treating it as completion.|
|`offset`|The stored `.feed-offset` value read for this probe, showing the consumer's accepted byte boundary.|
|`cost`|Fixed-size per-call outbox scan counters: `scans`, `journal_bytes` (newline-terminated journal bytes submitted to the outbox parser, including repeated scans), `receipt_names` (directory entries enumerated except dot and dot-dot, including ignored staging names), and `scan_wall_ms` (accumulated scan wall, excluding waits and unchanged metadata probes). Counters saturate at the unsigned 64-bit limit; milliseconds truncate fractions. The capture-only library APIs `run` and `poll_once` have zero outbox cost. No reply or receipt bodies are read.|

The sidecar has one grammar: `awaiting`, context, letter count, budget, and expiry are optional ordered suffixes on the same line, so older sidecars still parse. A partial or malformed budget or expiry suffix is rejected; `superloop-lane driver follow` discards an invalid capture and publishes `monitor: null` when no valid capture qualifies.

## Standard-output data plane · `sec:workermonitor:standard-output-data-plane`

Every completed invocation writes exactly one compact JSON document followed by LF. The envelope has schema version 2. The following examples show state alone, state with a delta, state with completion, and all three records in order:

A letter record has `kind: letter`, its durable `identity`, and `replay: 1` when a previous saving capture was interrupted. Every document carrying a letter adds `"letters":{"delivery":"at-least-once","collapse_by":"identity"}` at the top level. Stdout and this capture deliver at least once with identity and a replay mark; `follow` and the launch result show exactly one record per identity from the authoritative `letters.jsonl` stream, while a capture consumer collapses by identity as the document declares. A saving capture writes and flushes the document before marking delivery, collapses duplicate identities within one document, and places each letter ahead of the event delta that follows it; a bare capture reads the delivery position without marking it, so it repeats each letter that no saving capture has delivered.

At the first visible expiry, the capture emits a `budget_expired` record with the latched `budget`, `wall`, `event_size`, `last_growth`, `quiet`, and `expiry_state`, plus current `state` and current readings, then ends its call. Later changes of current state emit `budget_state` with `budget`, current `wall`, `state`, `quiet`, `last_growth`, and `event_size`, and end the call. These are monitor record kinds, independent of event deltas and completion. The `.budget-notice` file is only a delivery cursor for the last published step identity, budget and state: a saving capture advances it after publication, and a bare capture reads it without writing, so a bare capture repeats a record that no saving capture has delivered; the atomic sidecar remains the source of the expiry facts. A rearmed monitor with `Known BUDGET-EXPIRED lane=<step> budget=<s>` ignores that known hand-back and follows until a finished record, escalation, or a new state change; after a state hand-back it also carries `Known BUDGET-STATE lane=<step> budget=<s> state=<growing|stalled|runaway>` so the known change does not end a later turn. A new state hands back `BUDGET-STATE lane=<step> state=<growing|stalled|runaway> quiet=<s> last_growth=<s>`. The initial hand-back is `BUDGET-EXPIRED lane=<step> budget=<s> wall=<current_wall> state=<state> last_growth=<current_last_growth>`. The runbook prompt has no budget-derived call cap.

```json
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":null,"monitor":null,"report":false,"last_message":false,"offset":0}]}
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":{"bytes":16,"age_seconds":0},"monitor":null,"report":false,"last_message":false,"offset":0},{"kind":"delta","bytes":16,"truncated":false,"events":[{"event":"one"}]}]}
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":null,"monitor":null,"report":true,"last_message":false,"offset":0},{"kind":"finished","report":"RUN-REPORT exit=0\n","last_message":null}]}
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":{"bytes":16,"age_seconds":0},"monitor":null,"report":true,"last_message":false,"offset":0},{"kind":"delta","bytes":16,"truncated":false,"events":[{"event":"one"}]},{"kind":"finished","report":"RUN-REPORT exit=0\n","last_message":null}]}
```

A delta record is:

```json
{"kind":"delta","bytes":16,"truncated":false,"events":[{"event":"one"}]}
```

`bytes` counts the selected source bytes. If unread growth exceeds the cap, the newest cap-sized suffix is selected and `truncated` is true. Each selected line is parsed independently as JSON and stays in file order. A corrupt line or a partial line created by cap truncation appears in place as `{"raw":"<line text>"}`. A terminal LF does not invent an extra empty event; an actual empty line inside the payload is represented as `{"raw":""}`. Text that is not valid UTF-8 uses Unicode replacement characters so the outer document remains valid JSON.

A finished record is:

```json
{"kind":"finished","report":"RUN-REPORT exit=0\n","last_message":null}
```

When `last-message.txt` exists, `last_message` is its text instead of null. A call observing both unread bytes and the report publishes one document with a delta record first and a finished record second.

Failures keep their established class names and exit meanings. Their stdout record is:

```json
{"schema":2,"records":[{"kind":"event_source_failure","message":"superloop-lane: event_source_failure: event source inspection failed\n"}]}
```

Usage follows the same form with `kind` equal to `usage_error`. The retired `DELTA`, `FINISHED`, and `LAST-MESSAGE` framing tokens never appear on stdout.

## superloop-cli-common control plane · `sec:workermonitor:cli-common-control-plane`

The binary uses superloop-cli-common's ADR-010 surfaces: `CommandExit` supplies status classes, invalid argv travels through `CliExit`, `ControlPlaneRecord` JSON is written to stderr, `redact_text` protects runtime diagnostics, and the shared JSON panic hook suppresses Rust's default panic output. Usage records omit raw arguments, offending values, and caller paths.

Successful calls without unread outbox replies write nothing to stderr. Usage and runtime failures add one LF-terminated control-plane record on stderr while retaining the entry-47 failure envelope on stdout. The numeric exit mapping did not change during this migration: success remains 0, runtime/relay/internal failure remains 1, and usage remains 2.

## Offset state · `sec:workermonitor:offset-state`

`.feed-offset` contains one nonnegative ASCII decimal byte position followed by LF. A missing, unreadable, malformed, or negative offset recovers to zero; a positive offset beyond a regressed or missing event source is an `evidence_continuity_failure`. Bare inspection leaves every cursor absent or byte- and metadata-identical. `--save-offset` saves the shared capture position: `.feed-offset`, `.letter-count`, `.letter-delivered.json`, `.letter-pending.json`, `.budget-notice` and `.announced-replies.json`. Existing records are read with their original meanings, and malformed records refuse by name. Letters, budget transitions and reply revisions publish once; an interrupted letter publication retains pending evidence for replay.

With `--save-offset`, the offset advances to the sampled event size only after the entire envelope is written and flushed. An incomplete publication retains the previous accepted offset. Capture invocations must not share one offset file concurrently.
