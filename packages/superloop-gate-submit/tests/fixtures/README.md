# Shell-oracle fixtures · `guide:laneverifyfixtures:shell-oracle-fixtures`

`capture_shell_oracle.py` drives `reference/superloop-gate-submit.sh` against synthetic worktrees and PATH-injected `git` and `ssh` executables. It captures standard output, standard error, status, normalized Git argv and temporary-index use, SSH argv, and the exact remote script delivered on SSH standard input.

The committed reference has SHA-256 `f116380e4de9457a1048131983ee9f9a390ca497b6e3bdbd61d8395918c668e7`. The capture script refuses any other bytes.

Only the decimal `wall` value in the shell-owned terminal report is normalized to `N`; all other output and command bytes are retained. Dynamic worktree and temporary-index paths in Git traces are replaced by `$WORKTREE` and `$TMP_INDEX` tokens.

## Inventory · `sec:laneverifyfixtures:inventory`

- `default-success` captures the injected fictional example profile, basename-derived identity, two package arguments, successful server evidence, report bytes, and snapshot object flow.
- `overrides-failure` captures `-n`, `-A`, `-D`, explicit hub and server-profile overrides, a failed declared remote verdict, and the optional documentation command.
- `tail-cap` captures seventy server lines and proves that only the last sixty precede the verifier report.
- `usage-no-packages`, `usage-extra-argument`, and `usage-unknown-option` capture shell usage behavior for governed diagnostic/report divergence tests.
- `usage-missing-profile` captures the named pre-transport refusal when a required server-profile field is absent.
- `snapshot-add-failure` and `push-failure` capture shell runtime failures that predate the governed agent-text terminal report requirement.
- `unsafe-name` captures a shell report whose caller-controlled name breaks the governed whitespace-free field grammar.
- `remote-undeclared` captures the shell propagating status 7 even though the specification declares only statuses 0, 1, and 2.
- `unterminated-evidence` captures the shell joining its report directly to a final server line without LF; the governed implementation inserts the report-line separator.
- `committed-head-success` is a Rust-mode aligned capture of the direct HEAD push, exact SSH argv and script bytes, checked-out server object line, and verifier-owned object field; it has no shell-oracle equivalent because the shell implements only snapshot mode.

Each successful or failed snapshot fixture also records whether the shell removed its temporary index. A value of `clean` is required.

## Regeneration · `sec:laneverifyfixtures:regeneration`

Run `python3 packages/superloop-gate-submit/tests/fixtures/capture_shell_oracle.py` from the workspace root. Temporary files are created under `TMPDIR`, which must name disk-backed storage.

The Rust comparison removes the embedded gate sampler and maps its battery boundaries to the historical shell headings before comparing these retained captures; executable fixtures separately require one start sample, end sample and delta per battery and gate, including failure and committed-head exit paths.
