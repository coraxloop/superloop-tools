# `superloop-lane driver status` · `guide:lanewatch:lane-watch`

`superloop-lane driver status` performs one read-only observation of a worker-lane run directory and reports whether its current step is running, completed, failed, or stalled. This is a one-shot diagnostic, not the Sonnet watcher agent; its verdict describes the observed lane step.

The package is the Rust port of the shell `superloop-lane driver status`; the ratified output and lane specifications govern wherever the reference implementation differs.

## Command line · `sec:lanewatch:command-line`

```text
superloop-lane driver status RUN-DIR [STALL-SECONDS]
```

The stall threshold defaults to 300 seconds, and an explicitly supplied threshold is a nonnegative decimal integer.

Usage failures return status 2 with empty standard output and one fixed `usage_error` diagnostic on standard error, as explicitly required by the port brief.

This package uses only the Rust standard library because its agent-text boundary needs fixed evidence and report bytes rather than `superloop-cli-common`'s machine-JSON conventions.

## Output contract · `sec:lanewatch:output-contract`

A settled `run-report.txt` takes precedence over event freshness; its bytes are relayed verbatim as evidence, its governed lane verdict is classified, and the diagnostic returns status 0.

Without a settled report, a missing `events.jsonl` emits `STALLED age=unknown events=0 last=none` and returns the declared stalled status 42 without attempting producer discovery.

An existing event source below the selected threshold emits the unchanged shell-compatible `ALIVE` evidence line with integer age, line count, and last event type.

At or above the threshold, the diagnostic selects a live driver's valid lock before a stale one, breaking ties by the lock's modification time and then its name. It selects the valid `.monitor-PID-SEQUENCE` capture for that live driver PID with the greatest boot timestamp, breaking ties by sequence. Each monitor rewrites its own capture beside the lock on every poll as one line: `quiet=<s>s wall=<s>s event_size=<n> boot=<s>s awake=<s>s` with optional trailing `awaiting=<lane>:<seq>`. When that record parses and its boot reading is not ahead of the diagnostic's own `/proc/uptime` reading, the age becomes the record's quiet seconds plus the boot seconds elapsed since the record, and that awake age is what the threshold comparison reads. A host suspend freezes a producer without stalling it, so a step that slept through a long host suspend and kept its place answers `ALIVE` instead of reporting a stall that never happened.

The awake age is an upper bound: exact up to the two whole-second boot reads it is built from whenever the host stayed awake since the record, and high by whatever the host slept afterwards, for at most one poll, since the resumed driver republishes the record on its next one. The exact figure is not available to a reader by construction — separating awake seconds from suspended ones needs a reading of the clock that stops with the host, which no unprivileged `/proc` file exposes and which no one-shot process can take for an interval that ended before it started — and erring high is the safe direction, because a genuine stall keeps growing the monitor's own quiet interval and is still reported.

`age=` reports the age the verdict was read from in every shape below: the awake age where a usable record governs, and real elapsed time — the supplied instant minus the event file's modification time — in every other case, which is an age still below the threshold, where no record is consulted at all, a missing, unparsable, or earlier-boot record, a lock naming no live driver process, and an unreadable boot clock. A settled `run-report.txt` still takes precedence over both, so a finished step never consults a record at all.

At or above the governing age, the diagnostic reads `.codex-lane.lock` or `.claude-lane.lock` for the driver PID, which is the lock's first line — a driver that has spawned its child names that child on a second line, and a reader that took the whole file for one identity would find no driver in such a lock at all — walks `/proc` once to identify the driver's descendant process tree, counts the tree's socket inodes present in state `01` in `/proc/net/tcp` and `/proc/net/tcp6`, and measures movement in the sum of `rchar` and `wchar` across one second. Missing or unreadable lock or process evidence contributes no liveness signal; the diagnostic never signals or controls a process.

Either one established TCP socket or a positive I/O delta proves that the producer is generating, emits this evidence line in place of `STALLED`, and keeps the diagnostic verdict `running` at status 0:

```text
GENERATING age=<s> events=<n> last=<type> pid=<producer> established=<count> io_delta=<bytes>
```

Without either liveness signal, an existing stale event source repeats its last event bytes after this evidence line and returns the declared stalled status 42:

```text
STALLED age=<s> events=<n> last=<type> pid=<driver-or-none> established=0 io_delta=0
```

Every successful running, terminal, or stalled observation ends on standard output with the diagnostic's own report in this declared field order:

```text
RUN-REPORT exit=STATUS wall=SECONDSs verdict=VERDICT
```

The diagnostic verdict vocabulary is `running`, `completed`, `failed`, and `stalled`; `running`, `completed`, and `failed` describe a successful observation and return 0, while `stalled` returns 42.

Runtime, validation, and panic failures return status 1 with fixed classed evidence followed by `RUN-REPORT exit=1 wall=SECONDSs verdict=FAILED` on standard output; standard error is reserved for usage or a publication failure that prevents the owned report stream from completing.

## Reference divergences · `sec:lanewatch:reference-divergences`

- The shell emits no diagnostic-owned terminal report; the governed Rust observation appends the declared report after shell-compatible evidence.
- The shell's usage prose is unclassed; the Rust command emits one fixed path-free `usage_error` diagnostic and accepts only a nonnegative decimal threshold.
- The shell treats any regular report file as completion without validating its report; the Rust command classifies the settled report's governed exit and verdict or returns `report_contract_failure`.
- The shell treats non-file event and report paths like absent files; the Rust command returns a classed identity failure because diagnostic probes must inspect the expected evidence identity.
- The shell exposes utility diagnostics and default runtime behavior on read or metadata failures; the Rust command emits fixed path-free classes, suppresses panic payloads, and still attempts its terminal report.
- The shell uses event age alone for existing stale sources; the Rust command appends producer PID, established-socket count, and one-second I/O delta fields and keeps live generation at status 0.
- The shell measures freshness in real time alone; the Rust command prefers the awake age published by a live step's own monitor, so the hours a host spends suspended are not counted against a producer that was frozen with it.

## Read-only discipline · `sec:lanewatch:read-only-discipline`

The diagnostic opens run-directory and `/proc` producer evidence only for metadata inspection and reading; it does not create, truncate, replace, or remove any run-directory entry.

In particular, it never creates or advances `.feed-offset`, never changes a lifecycle marker, and never writes derived diagnostic state into the run directory. The monitor record is the driver's to write and the diagnostic's to read: an observation neither creates, refreshes, nor removes it, and a run directory without one observes exactly as it did before the record existed.

## What this package deliberately does not do · `sec:lanewatch:what-this-package-deliberately-does-not-do`

- It does not retain a preceding event-size sample or claim to prove growth from directory-only freshness.
- It does not measure host suspension itself; it reads the awake accounting the step's own monitor published and falls back to real elapsed time whenever that accounting cannot be trusted.
- It does not signal, reap, suspend, kill, or otherwise control the producer process.
- It does not create capture offset state, marker files, summaries, locks, or caches.
- It does not infer whole-lane acceptance from a current-step report.
- It does not add a runtime output-mode switch or terminal-only presentation.
