# `lane-gateway` · `guide:lanegateway:lane-gateway`

The private `gateway-service` and `gateway-runner` programs in `lane-gateway` implement the host-side trust boundary for mediated lane access. It stores orchestrator-authored registrations, validates worker-authored requests, persists accepted sequence watermarks, snapshots and pushes package-scoped worktree state, executes pre-cleared and individually approved commands through a configured runner, polls lane protocol directories, writes explicit worker results, and retains append-only audit evidence.

Roster membership and run admission are shared execute-command checks. The gateway supplies registration and audit observations, binds them to the registration digest, lane, sequence and argv, and renders the existing refusal names without changing its records or result envelopes.

The shared command process orders proposal withdrawal, common claim, existing execution-intent recovery, answer application and completion. The gateway adapter applies request-core’s transitions through the authenticated request channel and retains runner custody, immutable execution intents, result projections and audit publication. An inherited common claim can resume before execution intent exists; once intent exists, recovery reads its outcome and never executes the command again. Approval binding compares the stored registration digest, lane, sequence and argv with the current registration before acting; denial and abandonment retain their existing no-effect paths.

## Trust boundary · `sec:gateway:trust-boundary`

The worker supplies only JSON request data. A run selects one registered name; its argument vector comes exclusively from the registration and request-supplied argv is refused. A proposal carries exact argv as data for a later approval tier. The mirror remote is one opaque string passed as one Git argument: production may use an SSH alias and path while tests use a local bare repository. The typed runner prefix is gateway configuration rather than request data. The Rust service composes typed arguments; its separately declared private shell runner owns SSH transport.

Lane names become state-file stems and ref suffixes and therefore use one conservative path-component grammar: an ASCII letter or digit followed by letters, digits, hyphens, or underscores. Host worktree and runner-interpreted mirror checkout paths are absolute, base commits are full hexadecimal object identifiers, and mirror remote strings are non-blank. Registration also refuses a gateway state root lexically nested below the worker-owned worktree.

## Registration file · `sec:gateway:registration`

Registration TOML is strict and versioned with `schema = 1`. The command table initially contains the ratified six names and may later contain audited proposal promotions. Every entry has a conservative roster identifier, supplies a fixed non-empty argv and a positive wall budget, and the required `test` argv uses separate `--package` or `-p` pairs for exactly the package allowlist. Unknown fields and duplicate TOML keys are parse refusals.

```toml
schema = 1
lane = "lane-031"
worktree = "/worktrees/lane-031"
packages = ["lane-gateway"]
base_commit = "0123456789012345678901234567890123456789"
mirror_remote = "lane-compute:/srv/lanes/lane-031.git"
mirror_checkout = "/srv/lanes/checkouts/lane-031"

[budgets]
run_cap = 20
cooldown_seconds = 5

[commands.fmt-check]
argv = ["cargo", "fmt", "--all", "--", "--check"]
wall_budget_seconds = 120

[commands.fmt-diff]
argv = ["run-report.sh", "fmt-diff"]
wall_budget_seconds = 120

[commands.clippy]
argv = ["cargo", "clippy", "--workspace"]
wall_budget_seconds = 600

[commands.test]
argv = ["cargo", "test", "--package", "lane-gateway"]
wall_budget_seconds = 900

[commands.corpus-names]
argv = ["run-report.sh", "corpus-names"]
wall_budget_seconds = 120

[commands.clippy-fix-diff]
argv = ["run-report.sh", "clippy-fix-diff"]
wall_budget_seconds = 600
```

Omitting `budgets` selects a run cap of 20 and cooldown of 5 seconds. Omitting `proposal_timeout_seconds` selects 600 seconds. The proposal timeout is an attention deadline: crossing it parks the proposal without ending its lifetime. The same value bounds an approved proposal's runner invocation, and a promoted entry inherits it as the command wall budget. Push and worker-side fix application do not consume the run cap.

## Request and refusal contract · `sec:gateway:requests`

Request JSON is strict and versioned with `schema: 1`. Sequences increase independently for every registered lane. An accepted sequence is published atomically to its watermark file; an equal sequence is a replay and a lower sequence is a regression.

```json
{"schema":1,"seq":1,"op":"push"}
{"schema":1,"seq":2,"op":"run","command":"clippy"}
{"schema":1,"seq":3,"op":"propose","argv":["cargo","metadata"],"reason":"inspect package metadata"}
{"schema":1,"seq":4,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":3}
```

A worker publishes a request by writing a sibling temporary file below `.lane/` and renaming it over `request.json`, so a reader never sees a half-written document. The gateway no longer depends on that discipline: a read that finds an empty file, a truncated trailing UTF-8 sequence, or JSON that ends before its document does is treated as not yet written and re-polled, because a plain shell redirect exposes the file at creation and the gateway would otherwise refuse the writer's own race. The contract remains the writer's because renaming is atomic and costs nothing, while re-polling costs the worker a wait.

Push takes none of the optional fields. Run requires a registered command and refuses both argv and reason. Propose requires non-empty argv and a non-blank reason and refuses a roster command name. Every invalid request returns a `refused` result carrying a stable rule enum, and the same refusal is appended to the lane audit after the request record.

Every result carries required `schema: 2`, the sequence when readable, the validated operation when available, one of `success`, `pending`, `parked`, `denied`, `expired`, `over_budget`, `refused`, `cap-refused`, `ok`, `failed`, `timed-out`, `abandoned`, or `withdrawn`, an exit code, wall milliseconds, an optional pushed or executed commit, a typed refusal where required, and complete standard output and error. A run result carries `queue_wait_ms` beside `wall_millis`, measured from accepted request or proposal intake to runner start; other results omit it. A result without a `schema` field does not decode, and projection writers reject any in-memory result that is not schema two before touching worker files. Pending and parked proposal acknowledgements state the registered attention timeout. A denial uses top-level `denied` plus `proposal_denied` and the orchestrator's exact reason; explicit abandonment uses top-level `expired` plus `proposal_expired`, the exact reason, and `abandoned` or `lane_closed`. Every accepted operation result is appended to the audit. Status derives accepted-run count and per-command wall consumption from immutable records for executions that reached a mirror commit, including nonzero tool exits, runner failures, and timeouts.

Result readers require `verdict`, `stdout`, and `stderr`; a nested refusal requires schema two and the current rule vocabulary, with no `tier` field. Stored verdicts require `wall_millis`, and verdict audit actors are `orchestrator` or `lane`.

## Push tier · `sec:gateway:push-tier`

An accepted push copies the lane's real index to a gateway-owned temporary file, points `GIT_INDEX_FILE` at that copy, stages the complete worktree, writes a tree, and creates an unreferenced snapshot commit. The lane's index, HEAD, and refs are not mutated. All direct subprocesses are `git`; arguments and environment entries are supplied through `std::process::Command` without a shell.

Before staging, the snapshot excludes candidate paths whose metadata is a character device, FIFO, or socket, plus zero-byte regular files that are untracked and whose first path component is hidden; Git cannot stage the special files, and the latter shape matches an untracked dotfile placeholder left by a sandbox mask. The push result notes the number omitted, and a worktree with no matching paths uses the same staging arguments and tree content as before.

Before transport, the gateway resolves each registered Cargo package directory from the base commit and diffs that base against the snapshot with rename detection disabled. Every changed repo-relative path must have a registered package directory or `.lane/` as a component-aware prefix. A refusal contains the exact offending list. A successful snapshot is force-pushed to `refs/lanes/gateway/<lane>` on the opaque registered mirror remote.

## Run tier · `sec:gateway:run-tier`

An accepted run looks up its named `CommandSpec` again and composes one typed subprocess vector: the configured runner prefix, the registered absolute mirror checkout, then the registered command argv. The request sequence, raw JSON, and any request-supplied argv never enter that vector. The runner process also receives `LANE_GATEWAY_WALL_BUDGET_SECONDS`, `LANE_GATEWAY_MIRROR_COMMIT`, `LANE_GATEWAY_MIRROR_REMOTE`, and the derived `CARGO_TARGET_DIR`; a production transport is responsible for conveying those values to its server wrapper. Every runner result retained in the audit has a `cargo_target_dir` field containing exactly the path configured on that spawned command, so an SSH transport that fails to forward the value is visible by comparing the audit with remote runner evidence. Tests configure `/bin/sh` plus a local stub script, which records the received values, fetches the lane mirror ref into an isolated checkout, resets to the recorded commit, changes directory there, and executes the fixed suffix.

`LANE_GATEWAY_MIRROR_REMOTE` carries the registration's `mirror_remote` verbatim, beside the commit variable that says which snapshot to check out: the commit is what to run, the remote is where that lane's bare mirror lives. It makes placement a per-lane fact. A runner that derives its host and lanes root from its own launch environment puts every lane of one serve on a single compute node, so a serve cannot move one lane to a quieter node however the estate's load moves; a runner that reads this variable resolves both host and mirror path from the registration the gateway already validated and pushed to. The value is passed unaltered because only Git and the runner interpret a remote specification, so a specification carrying spaces or a colon arrives byte for byte. A remote that is blank by the registration's own emptiness test configures no variable at all, leaving a runner's own defaults in force, and a runner that does not read the variable is unaffected by its presence — the registration gains no field and the request and result schemas do not change.

Every runner spawn unconditionally overrides `CARGO_TARGET_DIR`, including roster commands and approved or promoted proposal commands. When `LANE_GATEWAY_TARGET_ROOT` is set, the target directory is `ROOT/lane-gateway-DIGEST`, where `DIGEST` is the first sixteen lowercase hexadecimal digits of the SHA-256 hash of the canonical mirror-checkout path; if canonicalization fails, the uncanonicalized path is hashed instead and the run continues. When the root variable is unset, the target directory is `MIRROR_CHECKOUT/target`. Per-checkout directories prevent Cargo from serving binaries built from another checkout, preserve warm caches for repeated runs in one checkout, and let checkout removal reap the default cache automatically instead of leaving a shared target directory to grow without bound.

The runner's exit code carries a fixed convention: 255 is the transport, 124 is the remote `timeout`, and every other code is the command's own status. ssh exits 255 only for its own failures — a connection it could not establish, a reset, a host gone unreachable, a keepalive that expired — and never for the status of the remote command, which it passes through unchanged; the runner preserves ssh's code in turn. A run that ends in 255 is therefore refused as `runner_connection_lost` rather than reported as a command that ran and failed, and the refusal still carries the output, the exit code, and the mirror commit the run reached. 124 is the remote `timeout` utility reporting that it killed the command, which is the command's own status like any other and is not a gateway refusal.

A run requires the latest accepted push result to be successful. No accepted push, or a later failed push, produces `no_snapshot`, preventing execution against an older mirror state. The result records the successful push commit used by the runner.

Every accepted run consumes one of the lane's registered run slots, regardless of tool exit status. An immediate follow-up inside the registered cooldown is refused. The gateway polls the runner until the command's registered wall budget expires, kills it on expiry, and returns an `over_budget` result with output captured before termination. Cap exhaustion returns `cap-refused` with refusal rule `run_budget_exhausted`, `cap: "run_cap"`, `cap_limit`, and `count_reached`, directing the worker to `READY FOR VERIFY`; an approved command that exits nonzero reports `failed`. The serve loop is synchronous, so it cannot have two requests in flight for one lane.

Each runner starts as leader of its own process group. Execution timeout, transport loss, and stalled approval output signal the group with SIGTERM, giving the runner's existing forwarding path a chance to terminate the remote command group. Surviving processes receive SIGKILL after `RUNNER_TERMINATION_GRACE`, default ten seconds; the remaining approval deadline caps this grace when a smaller margin is configured. A `ServeConfig` builder can shorten the grace in unit tests only. The direct child is reaped with a bounded wait, and partial output is retained. The gateway records the group PID, Linux process start ticks, and the identity of the running boot under `runner-groups/<lane>/<seq>.json` before waiting. Startup reconciliation holds the lane lock, checks the recorded identity to avoid signaling a reused PID, terminates an inherited group, and then repairs or publishes the approval's terminal result. A record whose recorded leader is gone is discarded without a signal, so descendants that outlived their leader survive rather than have a signal reach whatever now carries that PID. A record naming another boot, and an older record naming no boot at all, is discarded on the same terms, because a PID and a start tick identify a process only within the boot that issued them. Failed cleanup retains the record for recovery. Group liveness uses the kernel's signal-zero probe. When the direct runner becomes a zombie, one process-table check permits early reaping only if no live descendants remain; otherwise the leader identity is retained for safe escalation. The grace loop uses kernel probes instead of repeated process-table scans. Inherited zombie-only groups can consume the bounded grace but hold no command locks.

Runner stdout and stderr remain complete in the audit result. A served result whose combined output exceeds `result_size_limit_bytes` is published as a metadata manifest with ordered `output_chunks`. Each reference names an independently readable JSON payload below `.lane/`; stdout chunks precede stderr chunks and each stream retains byte order. The manifest is published only after all chunk files have been synced.

## Proposal tier · `sec:gateway:proposal-tier`

An accepted proposal becomes a `gateway-proposal` row in the calling loop's common journal through the exact configured private `requests-helper`. Its immutable body contains exact argv, reason, lane, sequence, filing time, attention timeout, gateway identity and registration evidence. The common ID binds gateway, lane and sequence. Intake publishes schema-two pending results at `.lane/result.json` and `.lane/proposals/SEQ.json`; later requests do not replace the latter projection. The service never opens another loop's journal.

Human decisions use `superloop-lane requests list LOOP --pending`, `triage LOOP`, `review LOOP ID` and `adjudicate LOOP`. Triage accepts an atomic batch; adjudication names the current review ID. Answers contain `outcome: approve|deny|abandon` and the common decision's non-blank reason. Only approval accepts `promote: true` or a roster name. The helper independently checks registered-loop orchestrator authority. Filing cannot supply a decision, change an admitted body, or select another loop.

Attention expiry creates park evidence and republishes `parked`; it never makes a human decision. The service claims the common ID before execution, uses the exclusive lane execution record, then saves the terminal result in the common row. An inherited common claim without an execution record can proceed; an inherited execution record without a result is abandoned rather than executed again. Registration drift or a promotion collision produces a terminal failed result without execution. Promotion never changes the proposal body.

Pending and parked predecessor bodies migrate during a service hold with `superloop-lane gateway migrate-proposals`. Each unresolved body reaches the journal before its old file moves into `migrated-proposals/LANE/SEQ.json`. Interrupted retries compare immutable identity and bytes. Existing terminal worker projections remain readable; a second migration reports zero moves. Serve refuses predecessor bodies awaiting migration. Service and migration exclude each other through the state-directory lock.

Withdrawal retains the worker request grammar and original proposal sequence. It records common waiter departure before publishing the terminal worker projection; recovery repairs an interruption between those writes. Execution and withdrawal retain the same lane lock. Closeout adjudicates abandonment with reason `lane closed`, waits for the service result, then deregisters. The helper never executes an effect.

Every claimed approval has a serve-side deadline equal to its command's `wall_budget_seconds` plus `ServeConfig::approve_deadline_margin_seconds`, default 60 seconds. `with_approve_deadline_margin_seconds` overrides the margin, and the CLI reads the positive `LANE_GATEWAY_APPROVE_MARGIN_SECONDS` environment override. Both configuration routes require a positive margin; zero is refused before serving, accepting a request, or claiming an approval. Output collection shares that deadline and reserves termination time from the transport margin, so an inherited pipe cannot keep approval waiting after the runner exits. The result is `ok` for exit zero, `failed` for nonzero exits or admission/transport failures, and `timed-out` when the execution or transport budget expires. Exit codes, partial output, and typed transport refusal evidence remain attached. Restart reconciliation under the lane lock turns an approved marker without a result into `abandoned` exactly once; a completed audit result repairs its missing projection without executing again. Pending and attention-parked proposals remain open across restart. Terminal results use the existing schema-two `OperationResult`, audit, `.lane/result.json`, and `.lane/proposals/<seq>.json` paths; repair never overwrites a newer shared result.

## Serve loop · `sec:gateway:serve-loop`

`Gateway::serve` takes a `ServeConfig`, whose default polling interval is 500 ms, default heartbeat interval is 5,000 ms, default result payload limit is 512 KiB, and default shutdown flag is `shutdown` below the gateway state root. The CLI requires `LANE_GATEWAY_RUNNER_ARGV` as a non-empty JSON string array and applies optional positive `LANE_GATEWAY_POLL_MILLIS`, `LANE_GATEWAY_HEARTBEAT_MILLIS`, and `LANE_GATEWAY_RESULT_SIZE_LIMIT_BYTES` overrides plus a nonempty `LANE_GATEWAY_SHUTDOWN_FILE`. Three missed default heartbeat intervals, or 15 seconds, is the stale threshold used by supervision.

A dedicated publisher thread writes `serve-heartbeat.json` before the first registration scan and at every configured cadence, including while the main loop waits synchronously for a runner. Each publication uses a create-new sibling named `.serve-heartbeat.<pid>.<sequence>.tmp`, syncs it, and atomically renames it over the fixed file. A publisher write, channel, lock, or join failure is a fatal serve error. Heartbeat JSON is strict schema one and contains no argv, reasons, paths, output, remote, or credential-bearing values:

```json
{"schema":1,"pid":4242,"started_unix_ms":1000,"heartbeat_unix_ms":1200,"heartbeat_interval_millis":5000,"last_activity_unix_ms":1100,"process_state":"running","activity":"result_published","lane":"lane-031","seq":7}
```

`last_activity_unix_ms` starts at process start, changes immediately before request processing and after result, stale-lock, or reconciled proposal projection publication, and remains unchanged during idle scans and runner waits. `heartbeat_unix_ms` changes on every cadence. Activity is one of `started`, `request_started`, `result_published`, `action_lock_reaped`, `proposal_reconciled`, `clean_shutdown`, or `signal_stop`; process state is `running` or `stopped`. Clean shutdown clears lane and sequence context, publishes one final stopped `clean_shutdown` heartbeat, joins the publisher, and succeeds. A signal stop takes the same path and records `signal_stop`, so the activity alone tells an operator's flag from a delivered signal without reading `stop_reason`.

Every exit the process can observe about itself marks the heartbeat stopped and records why in `stop_reason`: `shutdown_flag` for the operator flag, `signal_terminate`, `signal_interrupt`, or `signal_hangup` for a delivered SIGTERM, SIGINT, or SIGHUP, `error` for a returned gateway error, and `panic` for a caught unwind. The reason field is present exactly when the state is `stopped`. SIGHUP is watched with the two deliberate stops because a serve whose session goes away is sent one, and its default disposition ends the process just as silently. The three signals are blocked on the thread entering `serve`, before the publisher thread starts, and accepted by a dedicated watch thread, so no thread can take one with its default disposition and end the process while the heartbeat still says `running`; the loop stops at its next check and exits zero through the ordinary stopped path. A signal mask is per-thread, so every generation blocks again rather than trusting an earlier one, and the accepted-signal record is cleared when a generation starts so a stop belonging to an earlier generation cannot end the next one on its first check. A runner subprocess is unaffected because `std::process::Command` restores an empty signal mask in each child before exec.

### Heartbeat reader contract · `sec:gateway:heartbeat-reader-contract`

A serve killed outright — SIGKILL, a suspended host, a severed container — records nothing, so the heartbeat carries what a reader needs to reach its own verdict: the publishing `pid` and the `heartbeat_interval_millis` that generation is publishing at. **A heartbeat older than twice its interval, or whose pid is not alive, is a dead serve.** One missed publication can be a busy host; two cannot, and a pid that `/proc` does not know cannot publish a third. `heartbeat_liveness(&heartbeat, now_unix_ms)` is that verdict as a library function, returning alive, stopped, or dead with `process_gone` or `heartbeat_stale`; readers supply their own clock, which also lets a runbook replay a captured file. A stopped generation is reported stopped rather than dead however old it is, because it said so itself.

**A stop request reaches a busy serve at the end of its cycle, not within one polling interval.** The loop checks the shutdown flag and the accepted signal between cycles, and a cycle that is executing a runner does not return until that command does, so a flag written or a signal delivered during a run waits up to the command's registered wall budget — ten minutes for `clippy` at the ratified roster. A second signal does not shorten that wait: the watched signals are blocked on every serving thread, so there is no escalation to a default disposition to fall back on. SIGKILL is the only immediate stop for a busy serve, and a reader that needs one reads the `pid` the heartbeat publishes; the generation then records nothing, which is exactly the case the pid and cadence exist to settle.

A live serve may hold a lane's action lock at any time after startup, so absence of the lock file is never a contract; only the holder's identity distinguishes current work from a stale lock.

The public `Gateway::serve` is the supervision boundary around private `serve_inner`. It catches unwind panics as well as returned errors, stops and joins the publisher, atomically replaces `serve-crash.json`, and returns an error for the CLI's nonzero exit path. Error messages use the safe `GatewayError` display; panic messages use a string payload or the fixed `non-string panic payload`. Crash JSON is strict schema one:

```json
{"schema":1,"pid":4242,"started_unix_ms":1000,"failed_unix_ms":1300,"last_activity_unix_ms":1100,"failure_kind":"error","message":"gateway read_shutdown_flag failed"}
```

A crash marks the heartbeat stopped with reason `error` or `panic` before publishing the crash report, so a reader never has to distinguish a failed generation from a busy one. Crash-report write failure never turns the serve command green: the CLI emits the original serve diagnostic and then `serve crash report write failed`, both as machine JSON, before exiting nonzero. Starting a replacement does not delete an older crash report; heartbeat and crash `pid` plus `started_unix_ms` distinguish process generations.

Before polling, startup reconciliation repairs every open proposal and seeds accepted request bytes from the durable watermark. Every cycle lists live registrations, parks newly due proposals under each available lane lock, and inspects each registered worktree's `.lane/request.json`. A request written while serve is absent is consumed when its sequence is above the watermark; an already accepted request at or below the watermark is seeded into the seen set instead of replay-refused. Distinct request bytes are validated through the same audited `Gateway` path; push and run execute, while proposals enter pending state and immediately release the request channel. Gateway-authored worktree files remain below `.lane/`: `result.json`, `proposals/<seq>.json`, and any ordered result chunk files. The loop checks the shutdown flag before and after each cycle and sleeps for the configured non-zero polling interval.

An unfinished read starts a waiting episode instead of a refusal. The first cycle that sees one appends a single `request_unfinished` audit record carrying the lane and the byte count without the bytes; cycles two, three, and four re-poll the same file in silence, and cycle five refuses the bytes it can see as `malformed_json` exactly once. Completion within any of those cycles is served as an ordinary request, so a worker keying on refusals sees none; the refused bytes enter the seen set so a permanently truncated file neither reopens the episode nor repeats its record. Startup seeding cannot read a sequence out of a prefix, so a lane whose seeding read was unfinished is seeded from the loop's first complete read instead of replay-refusing a request the lane already accepted.

No file or mode a worker controls stops the shared serve. Every serve touch of a worker-owned path opens it beneath the registered worktree without following a symbolic link and without blocking, and reads or replaces it only when the opened object is a regular file. A touch that fails appends one `worker_file_refused` audit event carrying the lane, the sequence where there is one, the path class, the defect class, and whether a result went unpublished, without worker-authored path bytes, and the serve moves on to the next lane. A request file that is not a readable regular file of at most 1 MiB is refused as `request_path_invalid` once, and again only after its defect changes; a result that the worker's `.lane/` refuses is recorded as unpublishable and not retried.

## State layout · `sec:gateway:state`

The explicit state-root override is a non-empty `LANE_GATEWAY_STATE`, used verbatim. Otherwise, a non-empty `XDG_STATE_HOME` selects `XDG_STATE_HOME/lane-gateway`; without one, a non-empty `HOME` selects `HOME/.local/state/lane-gateway`. A missing or empty `HOME` when neither earlier value is available produces `gateway default state is unavailable`. An estate that kept its state under a source checkout preserves that location by setting `LANE_GATEWAY_STATE` to it. Tests supply isolated temporary roots. Deregistration removes only the live TOML registration, preserving audit and watermark evidence.

```text
registrations/lane-031.toml
audit/lane-031.jsonl
watermarks/lane-031
migrated-proposals/lane-031/3.json
proposal-verdicts/lane-031/3.json
proposal-parks/lane-031/3.json
runner-groups/lane-031/3.json
locks/lane-031
tmp/index-PID-SEQUENCE
serve-heartbeat.json
serve-crash.json
shutdown
```

Each request, queued or parked proposal, refusal, verdict, registration change, stale-lock reap, served result, result-projection replacement, and refused worker file is one JSON object with `timestamp_unix_ms` (integer milliseconds since `1970-01-01T00:00:00Z`) appended as a new line. Audit records use schema two, and readers refuse any other audit schema. Existing audit bytes are never rewritten. Proposal bodies, park markers, and verdict JSON files are immutable history. The lane lock contains the holder PID and normally exists only for the duration of an active gateway action. PID existence is checked only through `/proc/PID`: a missing process makes the lock stale, while a live unrelated process that recycled the PID conservatively keeps the lock busy. Startup removes dead-PID and malformed or unreadable locks; acquisition removes and audits a dead-PID lock before retrying once, but keeps a malformed or unreadable lock busy. Every reap writes an `action_lock_reaped` audit event with the lane, the `dead_pid` or `malformed_or_unreadable` reason, and the dead PID when one was parseable. A live-PID refusal names the PID and lock path; a malformed acquisition refusal names the malformed record and path. Temporary indexes are removed after each push. Published chunk files use names such as `.lane/result-2-0000.json` and are referenced in order by current and canonical proposal results. The shutdown flag is operator-authored and read-only from the gateway's perspective.

## Command-line contract · `sec:gateway:cli`

`superloop-lane gateway register FILE`, `deregister LANE`, `status`, `check-request LANE FILE`, `migrate-proposals` and `serve` dispatch to the configured absolute private `gateway-service`. The private program owns the same grammar. `register`, `deregister` and `serve` keep stdout empty; inspection and migration return one JSON result. Inspection creates no state, advances no watermark and appends no audit. Help, installed-name version, usage and diagnostics use control-plane JSON on stderr. Old proposal-list and approve/deny/abandon commands refuse; judgement exists only in common requests.

`SUPERLOOP_GATEWAY_SERVICE_BIN` and `SUPERLOOP_GATEWAY_REQUESTS_HELPER` select absolute private executable paths, with configured install-path defaults. `SUPERLOOP_GATEWAY_LOOP` names the calling loop and `PERMISSION_TRIAGE_LOOP_REGISTRY` its private registry. `LANE_GATEWAY_RUNNER_ARGV` names the private runner by exact absolute path. The runner requires `GATEWAY_RUNNER_SSH`, `GATEWAY_RUNNER_LANES`, `GATEWAY_RUNNER_REMOTE_WRAPPER`, `GATEWAY_RUNNER_RUST_ENV` and `GATEWAY_RUNNER_REMOTE_PATH`. Node roots and the node search path come from those settings. Derived Cargo target, mirror commit and budget are forwarded after sourcing the configured node environment.

The service publishes `execution-budgets/LANE/SEQ.json` before claiming approved execution. Its schema, lane, sequence and timeout in seconds let the lifecycle reader bound progress credit without reading the private request journal or the retired proposal-body directory. Existing active executions are drained before migration.
