# Orchestrator decisions · `guide:orchestratorhook:orchestrator-hook`

The adapter translates the session events into the neutral rulebook decision graph. Public `superloop orchestrator` commands own the terminal toggles and neutral decisions; both preserve the session state and snapshot identities.

## Commands · `sec:orchestratorhook:commands`

```text
superloop-claude-hook session-start|user-prompt-submit
superloop orchestrator on|off|status [--global]
```

With no arguments the binary preserves the shell toggle's default `status` operation. Project toggles are keyed by the project root resolved from `PWD`: for an absolute working directory, `HOME` bounds the walk whenever it is a lexical prefix, including equality, with candidates from the working directory through ancestors strictly below that exclusive boundary, or the same unbounded walk through the filesystem root when `HOME` is not a prefix. The first existing `.git` entry ends the walk and selects its directory only when it is a directory containing a `HEAD` file or a file beginning with `gitdir:`; an implausible entry or no entry leaves the supplied working directory as the key, a relative or empty directory is returned unchanged without a filesystem probe, and toggle output names the resolved root. The resolved root is slash-folded for the project flag; global toggles use `orchestrator-disabled-GLOBAL`. Status preserves the shell output field order and reports the shared 9,500-byte rulebook budget.

`hook` reads one harness event object from standard input. An allow with context writes one compact hook response object to standard output; an output-free allow writes nothing. The injection specification defines no intentional block transition, so the callback has no exit-2 path. Malformed input, refusal, persistence failure, and panic all fail open with exit 0 and no partial response. Operational errors go only to the redacted append-only injection log.

The deployed defaults are `~/.local/state/superloop-tools/hook` for state and `~/.local/share/orchestration-instance/ORCHESTRATION.md` for the rulebook, both expanded from `HOME` at run time; `ORCHESTRATOR_STATE_DIR` and `ORCHESTRATION_FILE` keep selecting their respective paths. The `status` and `hook` defaults tests remove both overrides and set `HOME` to a temporary directory; other tests set both paths to isolated temporary locations.

## Deployment · `sec:orchestratorhook:deployment`

The adapter and public root share the declared state directory. Retire the former hook executables only after the registration read-back and old-session drain; no old state path or executable alias is read.

## Direct state graph · `sec:orchestratorhook:direct-state-graph`

The injection machine is a `petgraph::graph::DiGraph` whose node weights are the specification-named decision and terminal states. Transition guards and ordered effects are edge weights, and evaluation advances through the graph with `NodeIndex`. No graph wrapper or parallel decision tree selects a semantic result. Every fallible nonterminal state has an explicit internal-error edge to `FAIL_OPEN`; graph tests prove reachability of every named node and event-class totality at every nonterminal node.

The neutral graph, decisions and persistence live in the internal tier 1 `session-core`. This compatibility package retains Claude input translation and harness-owned response rendering. Its `superloop-cli-common` dependency supplies the command version response; the machine-JSON adapter does not own the hook stream. The private `superloop-claude-hook` consumes the same core beside this retained entry point. Both toggles read `status` without creating the state directory; `on` and `off` continue to establish it.

## State shape · `sec:orchestratorhook:persistence-compatibility`

A state record is the JSON object the Rust writer stores in `orchestrator-scope-{session}.json`, holding only the fields the writer emits: `cwd`, `dedupe_key`, `hash`, `mtime`, `session_id`, `sessionstart_dedupe`, `snapshot_current`, `updated_at`, and, after a prompt with an identity, `emitted_prompt_ids` and `last_prompt_id`. An unknown field refuses the record as `UnknownStateField`, and invalid JSON or a non-object record refuses as `Serialization`, each through the existing internal-error diagnostic before any write; the hook then fails open without injection and leaves the record and its snapshots as they were, so the session receives no injection while the record stands.

Snapshot and state writes use sibling temporary files followed by atomic replacement. Full injection replaces only current; content-change notice rotates current to previous before publishing the new current snapshot. A prompt dedupe hit performs none of those effects.

## Specification-over-Python divergences · `sec:orchestratorhook:specification-over-python-divergences`

The ratified hook specification governs these five reference differences:

- (`[ORCHESTRATION-sig:hooks:injection-input]`): a nonstring `source` is the empty source for classification and session-start deduplication. Python classifies it as ordinary but stringifies the value in the persisted dedupe key. Fixture: `spec-nonstring-source.json`.
- (`[ORCHESTRATION-sig:hooks:injection-input]`): a nonstring payload working directory is replaced by the process working directory for persistence as well as toggle selection. Python selects with that fallback but persists an empty string after full injection. Fixture: `spec-nonstring-cwd.json`.
- (`[ORCHESTRATION-proto:hooks:prompt-deduplication]`): a nonstring prompt identity does not enter deduplication state. Python cannot deduplicate it but copies the raw value into its auxiliary `dedupe_key`; Rust records only the event class. Fixture: `spec-nonstring-prompt.json`.
- (`[ORCHESTRATION-rule:hooks:disable-precedence]`): the project injection-disable flag is keyed by the resolved project root. Python folds the raw payload working directory, so a root flag does not suppress injection from a subdirectory. Fixture: `spec-project-root-disable.json`.
- (`[ORCHESTRATION-req:hooks:redacted-diagnostics]`): a rulebook-refusal diagnostic omits caller-supplied configured paths. Python includes the environment-selected path. Fixture: `spec-redacted-refusal.json`.

Every other committed oracle fixture uses Python authority. The capture script fixes rulebook stamps, drives the deployed Python callback with synthetic payloads and isolated paths, and normalizes temporary state-root text before recording expected standard output.

## Test boundaries · `sec:orchestratorhook:test-boundaries`

The integration suite carries the eleven canonical scenarios, exact oracle response fixtures, production-writer state-shape fixtures, unknown-field refusal, toggle behavior, and ADR-001 subprocess stream and status assertions. Unit tests cover SHA-256 vectors, marker construction, input classification, dedupe retention, graph inventory, graph reachability, effect order, and per-state event-class totality. A debug-only panic trigger exists solely so subprocess tests can prove that the default panic hook was replaced before argument handling; release builds do not contain that trigger.
