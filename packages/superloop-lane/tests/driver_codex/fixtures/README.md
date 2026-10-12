# Shell-oracle fixtures · `guide:codexlanefixtures:shell-oracle-fixtures`

The capture script drives the committed shell reference with PATH-injected Codex and synthetic clock tools. It captures terminal bytes, status, child arguments and input, and run-directory layout without contacting Codex or waiting on wall time.

The committed reference has SHA-256 `ad14ab4a05c2dcdf82035cbb2467faafe8082b4429268ddedc2a76a8b9cf1075`. Regeneration refuses any other bytes. Dynamic run paths and measured wall seconds are replaced with `$RUN_DIR` and `N` only.

## Inventory · `sec:codexlanefixtures:inventory`

- `normal-completion` records fresh default execution and artifact layout.
- `stdin-prompt` records byte-preserving prompt input from standard input.
- `resume-step` records exec-level flag order, appended events, and deployed marker/offset behavior at a step boundary.
- `empty-output-fallback` records the reference leaving an empty output file after a final empty message; the governed port recovers the last nonempty agent message.
- `over-budget-growing` records natural success after the reporting threshold while events grow.
- `stalled-kill` records the reference's stall kill and its nonconforming signal-derived status.
- `runaway-kill` records the corresponding absolute-backstop behavior.

## Regeneration · `sec:codexlanefixtures:regeneration`

Run `python3 packages/superloop-lane/tests/driver_codex/fixtures/capture_shell_oracle.py` from the workspace root. The script requires disk-backed `TMPDIR` and deletes its isolated capture tree.
