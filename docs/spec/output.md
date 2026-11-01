# Command and output contracts · `spec:outputspec:command-and-output-contracts`

This part fixes the command boundary assigned to it by the accepted specification programme (`[ORCHESTRATION-dec:decisions:spec-concept-accepted]`) and its declared part scope (`[ORCHESTRATION-part:spec:output]`). It elevates the ratified output contract into normative prose; implementations are evidence about conformance, not a source of authority when they contradict that contract. Every label minted here has area `output`.

## Scope · `sec:output:scope`

This division governs bytes and process statuses observable at a first-party command boundary. It does not govern the internal representation of a result, the lane lifecycle that produced it, or the policy decision a consumer makes from it. Stream assignments, framing, exit meanings, and terminal report lines are external compatibility surfaces and therefore remain stable under the architecture rule that owns such stability (`[ORCHESTRATION-rule:architecture:external-contract-stability]`). A deployed program that differs is nonconforming; its behavior does not silently amend this part.

Runtime values are evidence, not standing specification data. In particular, this part fixes that a budget occupies a report field and fixes that field's bytes and position, but it fixes no current budget value, following the accepted mutable-facts ruling (`[ORCHESTRATION-rule:architecture:dynamic-facts-stay-in-registries]`).

**Definition (Output mode)** · `def:output:output-mode`

An output mode is one sanctioned ownership contract assigning every tool-authored result byte, diagnostic byte, terminal publication, and process status at one executable boundary. The sanctioned modes are exactly `hook-json`, `agent-text`, `machine-json`, and `feeder-stream`. A mode includes its stream grammar and failure behavior; it is not a presentation preference or a serialization option.

Bytes merely relayed from another producer retain that producer's provenance. The relaying command nevertheless owns whether, where, and with what framing those bytes cross its own boundary. Stream ownership is evaluated separately at every process boundary, so a caller that explicitly merges a child's standard error into its own standard output does not retroactively change the child's declared report stream.

**Terminology (Report stream)** · `term:output:report-stream`

The report stream is the standard stream on which a mode or command publishes its terminal result. In `agent-text` it carries the final `RUN-REPORT` line; in `machine-json` it is standard output carrying the result object; in `feeder-stream` it is standard output carrying one frame and its payload. The hook harness owns the corresponding terminal protocol in `hook-json`, so that mode has no workspace report line. A command must name its report stream even when the successful terminal publication may be empty.

**Signature (Process result)** · `sig:output:process-result`

For one invocation, the observable process result is `(status, stdout-bytes, stderr-bytes, elapsed, publication-state)`. `status` is the numeric process status returned to the direct caller; the two byte members are ordered byte strings, not lines inferred by a reader; `elapsed` is wall time measured across the invocation; and `publication-state` is one of `not-started`, `started`, or `complete`. `started` means at least one result or payload byte was accepted by its stream, while `complete` means the mode's entire terminal form was accepted. Process termination does not turn a started publication into a complete one.

**Requirement (Reported places are checked at publication)** · `req:output:report-path-validity`

A report that names a place checks that place when it publishes the report. A path proved earlier may now name another object, so an earlier path check cannot warrant the place asserted by a terminal report.

**Requirement (State results after their exit line)** · `req:output:result-after-exit`

A result is stated only after its exit line has been read. Earlier output or apparent silence cannot prove that a command has finished or establish its result (`sig:output:process-result`).

**Requirement (Plan forms agree)** · `req:output:plan-forms-agree`

A plan published as both a structured document and an argument vector states one action: the forms agree for every input admitted by their grammar. Any input byte that would delimit the argument form is encoded without ambiguity or refused by the grammar before either form is published, because an executable consumer must receive the action the reader reviewed.

**Table (Sanctioned modes)** · `tab:output:sanctioned-modes`

The table assigns each mode to one native consumer and fixes the role of both standard streams. A consumer may relay a stream later, but the producing boundary remains governed by this row.

|Mode|Native consumer|Standard output|Standard error|Terminal result and status basis|
|----|---------------|---------------|--------------|--------------------------------|
|`hook-json`|Hook harness|Empty or harness-protocol JSON on allow; empty on block.|Harness block reason or harness-permitted operational diagnostic.|Harness verdict; allow is 0 and block is 2.|
|`agent-text`|Agents and orchestrator|Command-declared human evidence and, when selected, the terminal report.|Command-declared human evidence and, when selected, the terminal report.|Exactly one final `RUN-REPORT`; shared statuses plus declared exceptions.|
|`machine-json`|Structured automation and agents|At most one JSON result object followed by LF.|Newline-delimited JSON control and diagnostic records.|The JSON object is the report; shared statuses plus declared exceptions.|
|`feeder-stream`|Sonnet watcher and byte-stream consumers|Exactly one frame and its verbatim payload on success.|Classed diagnostic on usage or failure; never payload.|Frame completion; shared statuses.|

## Shared contract · `sec:output:shared-contract`

This division binds every mode before a mode-specific rule specializes it. It adopts the ratified declaration, exit, safety, and panic decisions (`rule:output:single-mode-declaration`), (`rule:output:default-exit-classes`), (`rule:output:diagnostic-redaction`), and (`rule:output:panic-suppression`).

**Rule (Single-mode declaration)** · `rule:output:single-mode-declaration`

Every first-party executable that is shipped or invoked as a workspace helper must declare exactly one sanctioned output mode in its owning command contract. Every subcommand and every terminal path of that executable remains inside that mode. An executable absent from the binary-mode map is not thereby unregulated: it is ineligible for shipment until its owner assigns one of the four modes and demonstrates conformance.

**Rule (No runtime mode switch)** · `rule:output:no-runtime-mode-switch`

No argument, environment variable, caller identity, pipe state, terminal detection result, or subcommand may select a different output mode. A mode may contain command-declared result variants, but none may transfer stream ownership or select a second grammar. Adding a format flag that changes human-readable output into JSON, or JSON into text, is forbidden.

**Rule (Terminal invariance)** · `rule:output:terminal-invariance`

Result and diagnostic formats are byte-identical whether a standard stream is a terminal, pipe, socket, or regular file. The `machine-json` terminal refusal is a status-bearing refusal before result publication, not a switch to a pretty or human-readable format. No other mode acquires terminal-only color, decoration, prompts, or alternate framing.

**Rule (Default exit classes)** · `rule:output:default-exit-classes`

The shared exit classes are fixed as follows:

|Class|Status|Meaning|
|-----|-----:|-------|
|success|0|The command completed successfully under its declared contract.|
|failure|1|Startup, execution, validation, relay, publication, or internal runtime failure.|
|usage|2|The caller supplied invalid arguments or invoked a contractually refused usage.|

No mode may reinterpret status 1. `hook-json` alone gives status 2 the harness-owned meaning of block on an intentional block path; machine terminal refusal and all ordinary argument errors retain the usage meaning.

**Requirement (Finding statuses carry their own finding)** · `req:output:finding-status-ownership`

A status reserved for a finding is returned only when that finding occurred and its report carries the finding. A child process's status is never passed through as that reserved status: the calling command maps a child failure to its own failure status and emits a diagnostic that names the child and the child's status, so one status cannot mean both a finding and a failed child.

**Rule (Declared specific exits)** · `rule:output:declared-specific-exits`

A status outside 0, 1, and 2 is valid only when the owning command fixes the number, stable name, meaning, result-publication state, and applicable terminal paths. A child status, library error, signal number, or provider status may not escape merely because it is available. This part declares only status 42 for `superloop-lane driver status` and status 3 for `superloop-lint` and `superloop-lane bound-roots`; every other number remains nonconforming until separately declared.

**Rule (Diagnostic redaction)** · `rule:output:diagnostic-redaction`

Before diagnostic text or a diagnostic field is published, the producer must classify its data. Secret values and fields whose safe representation cannot be established are omitted; permitted free-form text is centrally redacted; and the resulting diagnostic retains a stable failure class. Redaction applies equally in normal, debug, usage, failure, and panic paths. A debug flag may add safe diagnostic detail but may never relax classification.

Verbatim capture tool payload and explicitly relayed child evidence are producer data rather than the relaying helper's diagnostic text. Their contracts forbid the relay from inspecting or redacting them; the upstream producer remains responsible for what it produced.

**Rule (Argument and path omission)** · `rule:output:argument-and-path-omission`

An error or usage diagnostic must not reproduce raw process arguments, an offending value, a command line, or a caller-supplied path. It may name a stable argument role, parser error class, stream role, or failure class. Successful structured result fields may carry a path or reference only when their command contract declares that field. The mandatory `dir` and `ref` fields in the two legacy lane reports are declared report metadata, not free form error text, and remain present on every terminal report path.

**Rule (Panic suppression)** · `rule:output:panic-suppression`

Every entrypoint must replace its language runtime's default panic or uncaught exception presentation before fallible argument handling. No mode may emit a panic payload, traceback, raw source path, raw argument, or default panic text, including under debug. A panic maps to runtime failure 1 unless the declared orchestrator-hook fail-open path applies.

Where output is still possible, `hook-json` records a classed and redacted internal failure without corrupting the hook response; `agent-text` emits classed evidence followed by its failed terminal report; `machine-json` leaves standard output empty and emits one classed JSON diagnostic on standard error; and `feeder-stream` follows the pre-relay or mid-relay failure rule according to publication state. Failure to publish the diagnostic does not authorize a second panic presentation.

**Scenario (Publication after failure)** · `scenario:output:publication-after-failure`

If a failure occurs while publication-state is `not-started`, the command must leave the result stream empty and use only the mode's failure channel. If bytes have been accepted, they cannot be withdrawn, overwritten, or retrospectively reclassified as a complete result. The command preserves those bytes, emits no fabricated suffix or replacement object, diagnoses only on the permitted failure channel, and returns failure 1.

An `agent-text` command whose evidence is already accepted still attempts its one truthful failed terminal report because that report is part of the mode; it must not claim completion if the report itself cannot be published. A `machine-json` command never appends a second object to repair a partial first object. A capture tool never inserts diagnostic bytes into a frame or relayed payload.

## Hook JSON mode · `sec:output:hook-json-mode`

This division specializes the harness-owned mode ratified for hook callbacks (`spec:output:hook-json-streams`). The hook protocol, not workspace report syntax, determines the JSON response schema.

**Specification (Hook JSON streams)** · `spec:output:hook-json-streams`

The hook harness owns both standard streams. On an allow path, standard output is empty or contains only one response permitted by the event's hook JSON protocol, and standard error is empty. On an intentional block path, standard output is empty and standard error contains only the redacted reason in the harness-prescribed form. `RUN-REPORT` tokens, machine-mode control records, capture tool headers, workspace diagnostics, and human evidence are forbidden on both streams.

Whether the harness JSON response ends in LF is part of the harness protocol, not a workspace newline convention. A hook must write the response as one complete publication and must not mix a partial response with a diagnostic.

**Rule (Hook JSON statuses)** · `rule:output:hook-json-statuses`

Status 0 means allow and status 2 means intentional block. For this mode only, status 2 is a harness verdict and not the shared usage class. An operational failure that is not declared fail-open uses status 1 and is not an intentional block. No other status is defined. The status and the harness response must describe the same verdict: block bytes require 2, and an allow response cannot accompany 2.

**Scenario (Orchestrator-hook fail-open)** · `scenario:output:orchestrator-hook-fail-open`

If the orchestrator injection hook cannot complete an internal injection, it may deliberately fail open. It appends one structured, redacted `internal_error` record to its declared out-of-band hook log, emits no bytes on either standard stream, and returns allow status 0. A partial JSON injection response is discarded before publication; once response publication has started, the ordinary publication-after-failure rule applies instead.

This exception is limited to internal injection failure. It cannot convert an intentional guard block into allow, emit the log record on a harness-owned standard stream, or expose exception text, traceback, arguments, or paths.

## Agent text mode · `sec:output:agent-text-mode`

This division fixes the human-evidence mode and preserves the ratified legacy report contract (`spec:output:agent-text-streams`) and (`proto:output:run-report-line`).

**Specification (Agent text streams)** · `spec:output:agent-text-streams`

An `agent-text` command may emit human-readable evidence only on the streams its command row declares. Evidence may contain multiple lines and may include verbatim child evidence when the command declares that relay. After all evidence and diagnostics have been written and flushed, the command publishes exactly one terminal `RUN-REPORT` line on its report stream. Every terminal path, including usage, runtime failure, declared specific status, and panic, must end in that report unless the report stream itself cannot accept it.

**Invariant (Final report is final)** · `inv:output:final-report-is-final`

No tool-authored byte may follow the LF terminating the terminal report on either standard stream. Before writing the report, a wrapper must drain every child stream and finish every own diagnostic. The process then returns the same status recorded in the report. A caller's later relaying or annotation is a new process boundary and does not weaken this finality at the producer.

**Protocol (Run-report line)** · `proto:output:run-report-line`

A report is exactly one physical line. It begins with the seven ASCII bytes `RUN-REPORT`, then one ASCII space, then the command's ordered `key=value` fields separated by one ASCII space, and ends with one LF byte. It has no leading whitespace, repeated separator, trailing space, CR, quoting, escaping, or continuation line. Each placeholder in a declared form occupies one field and therefore contains no ASCII whitespace or line terminator. A command must refuse an input that cannot be represented without changing this grammar.

The ordered field list is part of the command contract. The decimal `exit` value is the process status returned to the direct caller. `wall` is elapsed wall time in the unit shown by its value. A `verdict` is drawn from the command's declared vocabulary and must agree with `exit`; automation branches on the status and fields, never on preceding evidence.

**Specification (Lane-driver report)** · `spec:output:codex-lane-report`

The terminal report for `superloop-lane driver start` with either `--backend codex` or `--backend claude` is written to standard output after all lane evidence, with exactly one terminating LF, in whichever of these four base field orders the step selects:

```text
RUN-REPORT lane=<lane> exit=<code> wall=<seconds>s budget=<seconds>s verdict=<verdict> dir=<run-dir>
RUN-REPORT lane=<lane> exit=<code> wall=<seconds>s budget=<seconds>s verdict=<verdict> suspend_gap=<seconds>s dir=<run-dir>
RUN-REPORT lane=<lane> exit=1 wall=<seconds>s budget=<seconds>s verdict=CRASHED-HOST-EXIT pid=<pid> dir=<run-dir>
RUN-REPORT lane=<lane> exit=1 wall=<seconds>s budget=<seconds>s verdict=FAILED dir=<run-dir> cause=attempt-wall attempt_elapsed_seconds=<seconds> attempt_bound_seconds=<seconds>
```

A step that resumed its vendor child after a measured suspend gap appends `suspend_resumes=N` immediately after `dir`, before any attempt-wall fields, where N is the number of resumes, from one through three. Its run directory retains each attempt in `suspend-resumes-STEP.txt`. Recovery requires a child that exited with its own status rather than by a signal, a measured gap and no terminal result event for the step, a recorded thread identity, no explicit stop or helper attempt-wall end, and remaining awake budget; each attempt uses the saved brief and ordinary backend resume form without creating a new step. The count is omitted when zero.

`lane` is the declared lane or resume-step identity; `exit` is the lane process status; `wall` is the time the host was awake during the step and `budget` its effective reporting threshold, both nonnegative decimal seconds followed by literal `s`; `verdict` is `ok`, `OVER-BUDGET`, `FAILED`, `STALLED-KILLED`, `RUNAWAY-KILLED`, `RATE-LIMITED`, or `CRASHED-HOST-EXIT`; and `dir` is the declared run-directory token. `ok` and `OVER-BUDGET` require exit 0, and `FAILED` requires shared failure or usage status 1 or 2. Every remaining verdict requires runtime-failure status 1: the two kill verdicts, `RATE-LIMITED`, which reports that the provider refused the dispatch so no work was attempted, and `CRASHED-HOST-EXIT`, which reports a step whose driver died before publishing anything. A copy of the same line may be stored as lane state, but that internal storage does not alter the standard-output contract.

`CRASHED-HOST-EXIT` occurs only in that stored copy. No invocation returns it as its own verdict, because the step it describes had no driver left to publish one; the next step's driver writes it into the crashed step's stored report so the run directory records a settled outcome rather than an absent one. A reader of stored reports must therefore accept it, and accept it as a failed step, exactly as it accepts every other verdict in the vocabulary. The same obligation covers `SUSPEND-KILLED`, a retired verdict no conforming lane produces: stored reports written before a host sleep became a measurement still carry it, and a reader that refused them would report a broken producer over a settled record.

The second and third forms each carry one additional field after `verdict` and before `dir`, and the two conditions are disjoint, so a report never carries both. `suspend_gap` is the seconds the host spent suspended during the step, present exactly when that measurement is nonzero and on whichever verdict the step earned, because a host sleep is a fact about the host rather than an outcome of the step: it neither stops a child nor consumes its budget, and `wall` plus `suspend_gap` is the elapsed time an observer outside the host saw pass. `pid` is the decimal identifier of the dead driver whose lock the reporting step cleared; writing that report removes the lock file the identifier was read from, so the field is the only surviving record of which holder died. The fourth form is the only one with fields after `dir`: a `FAILED` boxed step whose helper stopped its attempt at the attempt wall ends the first or second form with `cause=attempt-wall`, then `attempt_elapsed_seconds`, the whole seconds the attempt had run when the helper stopped it, and `attempt_bound_seconds`, the bound it crossed (four times the active round's budget, or the protected plan's explicit wall), so a reader that branches on `exit` and `verdict` sees the same failure and a reader that locates `dir` splits on fields rather than taking the rest of the line.

**Specification (Lane-verify report)** · `spec:output:lane-verify-report`

The `superloop-gate-submit` terminal report is written to standard output after the relayed server evidence, in exactly this field order and with exactly one terminating LF:

```text
RUN-REPORT lane=verify-<name> exit=<code> wall=<seconds>s verdict=<verdict> ref=refs/lanes/verify-<name>
```

The same `name` token occurs in `lane` and `ref`; `exit` is the verifier process status; `wall` is nonnegative decimal seconds followed by literal `s`; and `verdict` is `ok` exactly when `exit` is 0 and `FAILED` when `exit` is 1 or 2. No other exit is declared. The server wrapper's stderr report may appear earlier as relayed evidence after the verifier explicitly merges child streams. At the server wrapper boundary that report remains a standard-error report.

**Specification (Server-wrapper report)** · `spec:output:server-wrapper-report`

The server run wrapper drains the child's output and writes its terminal report to standard error, in exactly this field order and with exactly one terminating LF:

```text
RUN-REPORT exit=<code> wall=<duration> rootfs_tmp_left=<size> workspace_left=<size>
```

`exit` is the status the wrapper returns for the run, `wall` is one whitespace-free duration token, and the two space fields are the measured whitespace-free availability tokens for root temporary storage and workspace storage. `exit` is one of the shared statuses unless a separate owner-ratified contract declares another. All four fields are mandatory. The `exit` field itself carries the verdict; a `verdict` field must not be inserted. The report is the wrapper's last authored line even when child evidence was relayed on either stream.

**Rule (Lane-watch stalled status)** · `rule:output:lane-watch-stalled-status`

`superloop-lane driver status` reserves status 42 with the sole meaning `stalled`: the watched lane has no completion report and its event evidence is absent or older than the declared stall threshold. The age compared with that threshold is awake time wherever the step's own monitor publishes it — the run directory's `.monitor` record, whose published quiet counts an awaited gateway run as progress, read only while the driver named by the lock is alive and the reader's own boot clock is readable and not behind the record's — and the modification-time-derived age in every other case, because a host suspend freezes a producer without stalling it while a file timestamp cannot tell the two apart. A `superloop-lane driver status` diagnostic may compare the modification-time-derived age first and consult the record only once that age reaches the threshold, since the awake age never exceeds it. Producer-tree liveness evidence from an established TCP connection or I/O movement contradicts an age-only stall and keeps the observation at status 0 with verdict `running`. Status 0 otherwise means the observation completed without that stalled verdict, including an alive or completed observation; statuses 1 and 2 retain runtime-failure and usage meanings. Status 42 does not redefine failure 1 and may not be used by another helper without its own declaration.

As an `agent-text` command, `superloop-lane driver status` declares standard output as its evidence and report stream. Before shipment, its owning command contract must declare one terminal report order containing at least `exit`, `wall`, and `verdict`, and must bind its stalled verdict to exit 42. A completed lane's stored report may be quoted as evidence, but cannot replace the diagnostic's own terminal report or its process status.

**Requirement (Agent-text status agreement)** · `req:output:agent-text-status-agreement`

On every terminal path, the report's decimal `exit` value must equal the status observed by the direct caller. `ok` may accompany only status 0; `FAILED` may accompany only 1 or 2; kill verdicts require 1; the `superloop-lane driver status` stalled verdict requires 42; and `OVER-BUDGET` is a successful process outcome carrying an independent timing finding and therefore requires 0. The server wrapper has no separate verdict field, so its `exit` field is the complete status assertion.

A wrapper must not report a child's status as its own unless its command contract declares that exact propagation. In particular, relaying another command's report as evidence never satisfies the wrapper's obligation to report its own status.

## Structured modes · `sec:output:structured-modes`

This division fixes the `superloop-lane driver follow` capture tool's schema-two envelope and the single-object machine protocol ratified for structured consumers (`spec:output:machine-json-streams`). The owner-ratified entry-47 migration retires `feeder-stream`: its `DELTA`, `FINISHED`, and `LAST-MESSAGE` frames have no remaining mapped producer.

**Specification (Capture documents)** · `spec:output:feeder-streams`

Every completed `superloop-lane driver follow` invocation writes exactly one compact JSON document followed by one LF to standard output. The document is an object with integer `schema` equal to 2 and a nonempty ordered `records` array. Every successful document starts with a state record sampled immediately before publication; a bounded wait makes a live round yield that record even without a delta or completion. It writes no `RUN-REPORT` and no human diagnostic to standard output. Success exits 0. Usage exits 2 and runtime or relay failure exits 1; these codes are unchanged by the superloop-cli-common migration. A caller timeout is not a monitor status.

Unlike the generic machine-result failure rule below, the entry-47 specialization requires driver-follow usage and runtime failures to publish their one-record failure envelope on standard output. superloop-cli-common `ControlPlaneRecord` JSON is additionally written as one LF-terminated record on standard error; argv failures use `CliExit`, statuses use `CommandExit`, runtime diagnostic text is subject to the ADR-010 redaction policy, and the shared JSON panic hook suppresses default runtime text.

**Protocol (Lane-feed envelope)** · `proto:output:delta-frame`

The envelope and successful record forms are:

```json
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":null,"monitor":null,"report":false,"last_message":false,"offset":0}]}
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":{"bytes":16,"age_seconds":0},"monitor":null,"report":false,"last_message":false,"offset":0},{"kind":"delta","bytes":16,"truncated":false,"events":[{"event":"one"}]}]}
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":null,"monitor":null,"report":true,"last_message":false,"offset":0},{"kind":"finished","report":"RUN-REPORT exit=0\n","last_message":null}]}
{"schema":2,"records":[{"kind":"state","at":"2026-09-26T00:00:00Z","step":null,"started_at":null,"wall_seconds":null,"driver":null,"events":{"bytes":16,"age_seconds":0},"monitor":null,"report":true,"last_message":true,"offset":0},{"kind":"delta","bytes":16,"truncated":false,"events":[{"event":"one"}]},{"kind":"finished","report":"RUN-REPORT exit=0\n","last_message":"final answer"}]}
```

The state record has keys in the displayed order: `kind`, `at`, `step`, `started_at`, `wall_seconds`, `driver`, `events`, `monitor`, `report`, `last_message`, and `offset`. `at` is the UTC sample instant to the second with `Z`; `step` and `started_at` are trimmed marker text or null when absent; `wall_seconds` is null unless `started_at` parses as an RFC 3339 UTC instant. `driver` is null for a missing or malformed lock, otherwise it holds the selected `.codex-lane.lock` or `.claude-lane.lock` name, driver pid, optional child pid, and `alive` according to either process's `/proc` presence; when both locks exist the newer mtime wins. `events` is null for a missing source, otherwise it holds its byte size and mtime age in seconds, with null for an unreadable mtime and zero for a future mtime. `monitor` is null for a missing or malformed `.monitor`, otherwise it holds numeric `quiet`, `wall`, `event_size`, `boot`, `awake`, and optional `awaiting`. `report` and `last_message` say whether their respective files exist, and `offset` is the stored offset read for this probe.

For event size `S`, stored nonnegative offset `O`, and configured nonnegative cap `C`, a delta exists only when `S` is greater than `O`. If `S - O` is at most `C`, the selected bytes range from `O` to `S` and `truncated` is false. If it is greater than `C`, the selected bytes are the last `C` bytes ending at `S` and `truncated` is true. `bytes` is the selected byte count, not a Unicode character count. A missing, malformed, or negative stored offset is treated as zero.

Each selected payload line is parsed independently as JSON and placed in `events` in file order. A line that cannot be parsed, including a partial line selected by cap truncation, appears in place as `{"raw":"<line text>"}`. A terminal LF does not add an empty event; an empty line within the selected range becomes `{"raw":""}`. Non-UTF-8 text uses Unicode replacement characters so the containing document remains valid JSON.

The finished record's `report` is the `run-report.txt` text. `last_message` is the `last-message.txt` text when that file exists and null otherwise. When unread event bytes and a settled report both exist, the one envelope contains both records with delta first; terminal readiness therefore cannot hide unread evidence.

**Requirement (Mtime-anchored debounce)** · `req:output:verbatim-relay`

`--bounce SECONDS` defaults to 30 and uses the same nonnegative integer grammar and joined or separated spellings as `--cap`; zero restores immediate delta service. `--wait SECONDS` shares that grammar, defaults to zero for an unbounded wait, and when positive publishes state alone if no delta or completion is ready by the invocation's deadline without changing the offset. The bounce window is measured from `events.jsonl`'s modification timestamp, never from invocation time, so a log already quiet for the window serves immediately. Pending unread bytes are served when the mtime age reaches the window, unread bytes reach the cap, `run-report.txt` has settled, or the unread region's last complete line is a heartbeat — a JSON object whose top-level `type` is `tool_progress` and whose `heartbeat` is boolean true. Until one of those four conditions holds the existing one-second poll remains pending. An unreadable mtime fails open and serves; a future mtime has age zero and holds subject to cap, report, and heartbeat-tail preemption.

The fourth condition is required because a hold anchored to the transcript's age can never close while a worker's tool call refreshes that timestamp once per window: the capture consumer would wait out its own timeout with a live worker and a growing transcript on the other side, and a consumer counting empty reads would escalate over an ordinary wait. The window exists to batch a burst of real events, and a tail that is a heartbeat is not a burst but the worker's liveness, which is the one thing the capture consumer is waiting to read. The heartbeat probe reads at most the last eight kibibytes of the unread region rather than the whole file and counts only a newline-terminated line, so a partially written heartbeat continues to hold; a heartbeat release publishes the whole unread region with the real events ahead of the heartbeat included and leaves the record forms above unchanged.

The stored offset advances to sampled size `S` only after the complete envelope is accepted and flushed. A publication failure retains the previous offset. If standard output rejects bytes after publication begins, accepted bytes cannot be withdrawn; the capture tool writes the classed, redacted control record on standard error and returns failure 1.

**Scenario (Lane-feed failure document)** · `scenario:output:mid-relay-failure`

Usage and runtime failures use the same envelope, with the established class name and diagnostic text:

```json
{"schema":2,"records":[{"kind":"usage_error","message":"superloop-lane: usage_error: invalid command-line arguments\n"}]}
{"schema":2,"records":[{"kind":"event_source_failure","message":"superloop-lane: event_source_failure: event source inspection failed\n"}]}
```

**Specification (Machine JSON streams)** · `spec:output:machine-json-streams`

A machine-result command publishes at most one complete JSON object encoded as UTF-8 followed by exactly one LF on standard output. A completed successful result uses status 0; a declared finding-bearing result may use its specific status. Runtime failure 1, usage failure 2, help, version, and precondition refusal publish no result object. Standard error contains only complete JSON control-plane or diagnostic objects, one per line and each followed by one LF.

The result object is the report; `RUN-REPORT` lines, human diagnostics, capture tool frames, and JSON arrays used as an outer stream envelope are forbidden. A control record on standard error neither counts as nor substitutes for the result object.

**Specification (Codex sign-in home check)** · `spec:output:codex-signin-home-check`

`superloop-lane check-signin-home --backend codex LOOP` publishes one JSON object followed by LF with `loop`, `home`, `ok`, `missing`, `varied` and `varied_lines`, plus `location` when a home location differs. The `varied` field is a list of label strings for permitted configuration differences; `varied_lines` contains one object per varied label, in the same order, with `label`, the verbatim `expected` configuration line, and the whole `actual` home configuration line carrying the same key, or null when that key is absent. A line carries the key when, after leading whitespace, it begins with `writable_roots` or `trust_level` followed by optional whitespace and `=`, or with the `[projects."` header prefix, and the first such line of the file is reported. Both lists are always present and empty without permitted configuration differences. Variations do not fail verification: a completed check exits 0 when `missing` is empty and `ok` is true, or 1 when `missing` is nonempty and `ok` is false; invalid arguments exit 2.

**Specification (Bound roots clearance)** · `spec:output:bound-roots-clearance`

`superloop-lane bound-roots --runs-root DIR PATH [PATH...]` is a read-only, lock-free scan of the immediate run directories under DIR. PATH values must be existing absolute UTF-8 paths whose spelling equals their filesystem canonicalization; missing paths, symlink aliases and noncanonical components refuse as `bound-roots-path` with status 2. Each record must be an object with exactly `schema` equal to 1 and `roots` an array of absolute path strings. A recorded root matches a requested path when it equals that path or is beneath it by path components. Locks use the shared monitor parser and process probe, with selection ordered by driver-or-child liveness, modification time and lock name; `/proc/PID/stat` states Z and X are not live. A run is live while either its driver or its recorded child is live. Missing locks are not live; a present lock that cannot be inspected, read or parsed refuses as `bound-roots-lock` rather than permitting clearance. This is a measurement at invocation, not a reservation against subsequent launches.

Completed scans publish exactly one JSON object plus LF on stdout with `schema:1`, `paths`, `unrecorded_live_runs`, `verdict`, and `refusal`. Each `paths` entry has the requested `path` and a `runs` array; each run has `run`, `lock`, `driver_pid`, `child_pid`, and `live`, with null lock and pids for an absent selected lock and null `child_pid` for a one-line lock. Run lists are sorted by run name and paths retain argument order. `unrecorded_live_runs` contains the same run objects for live drivers or children without a record. Status 0 means `verdict:"clear"` with `refusal:null`: no matching live run and no unrecorded live driver or child. Status 3, named `clearance-refused`, means the scan completed and published its complete finding-bearing object with `verdict:"refused"`; `refusal` has `kind` and a `runs` array of run names. `bound-roots-unrecorded` takes precedence when any live driver or child is unrecorded; otherwise `bound-roots-live` names the matching live runs. Matching evidence remains present regardless of refusal.

Status 1 means runtime, validation or publication failure and publishes no stdout result. Invalid JSON or record shape refuses as `bound-roots-shape`, naming each affected run in the stderr diagnostic's `failures` array. Record and lock failures retain the valid matches and unrecorded live runs in an `evidence` object of the same report shape with `verdict:"refused"`; malformed evidence never permits clearance. The top-level `kind` is the first failure in run-name order (lock failures precede record failures within a run); each `failures` entry retains its own kind and run. Other read failures use `bound-roots-read`, unrepresentable run names use `bound-roots-name`, and publication failures use `bound-roots-publication`. Diagnostics are JSON objects plus LF with `schema:1`, `command:"superloop-lane bound-roots"`, `class:"runtime"` or `class:"usage"`, and a stable `kind`. Status 2 means invalid arguments (`bound-roots-usage` or `bound-roots-path`) or terminal stdout (`bound-roots-terminal`), with empty stdout and a stderr diagnostic. Diagnostics do not echo raw arguments or caller-supplied paths; run names and structured evidence paths are declared report metadata.

**Rule (Terminal stdout refusal)** · `rule:output:terminal-stdout-refusal`

Before semantic work or result publication, a machine-result command must detect standard output attached to a terminal, emit one classed JSON refusal record on standard error, leave standard output empty, and return usage status 2. The refusal applies to every `superloop-lint` subcommand. It does not authorize a text fallback and does not depend on whether standard error is a terminal.

**Rule (Linter findings status)** · `rule:output:linter-findings-status`

`superloop-lint` status 3 means exactly that a judging command completed, published its complete result object on standard output, and the object contains at least one finding of failing severity. It is the binary's only specific status. `check`, `assemble`, `burn`, `project`, and `fix` may return 3; a refused precondition or failed command returns 1 with empty standard output instead. The configuration and completed-verdict distinction is defined by (`rule:lintcontracts:verdicts`).

**Rule (Informational success)** · `rule:output:informational-success`

The `linter report`, `linter coverage`, and `linter shape` commands return 0 whenever they complete and publish their result, regardless of the length or content of advisory listings. They never return 3. Runtime and usage failures remain 1 and 2, so informational does not mean infallible. This keeps advisory reporting separate from judging commands (`rule:lintcontracts:verdicts`).

## Output evidence · `sec:output:output-evidence`

This division binds planned helpers to their modes and turns the byte contracts above into release evidence. The map specializes the ratified planned map (`tab:output:binary-mode-map`); the verification set strengthens its ratified gate (`gate:output:output-conformance`).

**Table (Binary mode map)** · `tab:output:binary-mode-map`

This is the complete planned helper map. A row fixes one mode, native consumer, report stream, and every status exception; absence from the table grants no implicit mode.

|Binary|Native consumer|Mode|Report stream|Status exception or terminal note|
|------|---------------|----|-------------|---------------------------------|
|Orchestrator hook|Hook harness|`hook-json`|Harness protocol; no workspace report|0 allow; 2 block; declared internal injection failure may fail open as 0.|
|Heartbeat guard|Hook harness|`hook-json`|Harness protocol; no workspace report|0 allow; 2 block.|
|`superloop-lane driver start` with either backend|Agents and orchestrator|`agent-text`|Standard output|Shared statuses; legacy six-field report.|
|`superloop-lane driver follow`|Sonnet watcher and capture consumers|`machine-json`|Standard output|Shared statuses; exactly one schema-two envelope on every completed invocation, its first record the worker's state, with superloop-cli-common control records on standard error.|
|`superloop-gate-submit`|Agents and orchestrator|`agent-text`|Standard output|Shared statuses; legacy five-field report.|
|`superloop-lane driver status`|Agents and orchestrator|`agent-text`|Standard output|Status 42 is `stalled`; the owning command must declare its nonlegacy report order.|
|Server run wrapper|Agents and orchestrator|`agent-text`|Standard error|Shared statuses; legacy four-field report after relayed child evidence.|
|`superloop-lint`|Automation and agents|`machine-json`|Standard output|Status 3 is completed with failing findings.|
|`superloop-lane bound-roots --runs-root DIR PATH [PATH...]`|Close-out automation and agents|`machine-json`|Standard output|0 clear; 3 `clearance-refused` with a complete finding-bearing result; 1 runtime failure and 2 usage or terminal stdout refusal with no stdout result.|
|`superloop-lane render-routes`|Owner staging and agents|`machine-json`|Standard output|Shared statuses; success declares `fields.output` as the staging path, and refusals carry `class` on standard error.|

**Requirement (Failure-class naming)** · `req:output:failure-class-naming`

Every emitted error must carry one stable failure class without requiring a consumer to parse prose. JSON modes place it in a protocol-defined structural field; human diagnostics spell a fixed class token before redacted detail; and capture tool stderr does the same. Intentional hook block and linter finding codes are verdict data, not runtime error classes. The same cause retains its class across terminal and nonterminal streams, debug settings, and internal refactors.

**Verification (Stream ownership)** · `verif:output:stream-ownership`

For every mapped binary, subprocess tests capture standard output and standard error separately across success, usage, runtime failure, declared specific status, and terminal/nonterminal cases. Each test asserts the full byte string, proves every permitted class appears only on its owned stream, and seeds a forbidden `RUN-REPORT`, JSON record, capture tool header, human diagnostic, or raw payload to prove that cross-mode leakage fails. Relays are tested at both the producer and wrapper boundaries so an intentional merge cannot disguise the original ownership.

**Verification (Legacy report bytes)** · `verif:output:legacy-report-bytes`

Subprocess fixtures exercise success, usage, runtime failure, and applicable specific verdicts for both backends of `superloop-lane driver start`, `superloop-gate-submit`, and the server wrapper. For each of the three displayed legacy forms, the test compares the complete line including token, key spelling, field order, separators, units, and final LF; asserts its declared stream; asserts exactly one occurrence; proves no tool-authored byte follows it; and compares its `exit` and verdict semantics with the observed process status. Dynamic values are normalized only by fixture control, never by deleting or reordering fields.

**Verification (Capture documents)** · `verif:output:feeder-bytes`

Fixtures vary stored offset, event size, cap, bounce, wait, controlled mtimes, invalid and non-UTF-8 lines, empty payload, report text, and last-message presence. Every completed subprocess stdout parses as one schema-two object with a nonempty records array; exact-document cases pin the first state record and its ordered keys, state-only bounded waits, delta, finished, failure, raw-line, and combined ordering. State fixtures cover absent lock, monitor, event source, and start marker as null; dead process IDs; and sampled `at`, `wall_seconds`, and `age_seconds` types and plausible ranges. Timestamp tests pin quiet-log immediate service, fresh hold and later service, cap and report preemption, unreadable-mtime fail-open, future-mtime age zero, a heartbeat-tailed region released inside the window, an ordinary fresh tail still held for the window, and a torn heartbeat line that releases nothing. Separate publication fault injection proves preserved partial stdout, superloop-cli-common control records on stderr, failure status 1, and no offset advance after an incomplete document.

**Verification (Machine JSON shape)** · `verif:output:machine-json-shape`

Every `superloop-lint` subcommand is exercised with captured nonterminal streams and with terminal standard output. Success and status 3 each produce exactly one parseable object and one LF on standard output; failure 1 and usage 2 produce none; stderr is parsed as zero or more complete NDJSON records. Tests cover status 3 for all five judging commands, status 0 for all three informational commands regardless of advisory content, precondition refusal, help, version, unknown arguments, and terminal refusal without semantic side effects.

**Verification (Panic and redaction)** · `verif:output:panic-and-redaction`

Each mode is forced through a panic or uncaught-exception path before and after argument parsing, before publication, and after publication begins where the mode permits streaming. Captured bytes must contain the stable failure class but no seeded secret, raw argument, offending value, caller path, panic payload, traceback marker, source location, or default runtime text, with debug both off and on. The same matrix tests free-form credential redaction and proves that deliberately verbatim capture tool payload is unchanged while capture tool diagnostics remain redacted.

**Gate (Output conformance)** · `gate:output:output-conformance`

Release or deployment is blocked until every shipped executable appears once in the binary-mode inventory, declares one sanctioned mode, and passes the stream, legacy-report, capture tool, machine-shape, status, terminal-invariance, failure-class, redaction, and panic checks above. A missing row, undeclared status, changed field order, wrong stream, partial object presented as a result, post-report byte, traceback, or implementation/contract discrepancy is a failing finding. Passing internal unit tests or preserving an implementation accident cannot waive the gate; changing one of these external contracts requires a separate owner-ratified compatibility decision.
