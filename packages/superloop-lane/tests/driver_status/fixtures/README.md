# Characterization fixtures · `guide:lanewatchfixtures:characterization-fixtures`

`capture_shell_oracle.sh` creates isolated synthetic run directories, invokes the shell reference supplied through the required `LANE_WATCH_REFERENCE` input with sandbox `bash`, and captures standard output, standard error, and status separately in `expected/`; `/var/home/example-user/work/orchestration/bin/lane-watch` is a fictional workstation illustration.

The captured reference had SHA-256 `9338bfd9ffb7e0111e80780f268194f77387aa3ede15f9cdd51d41ed69b28c1b` on 2026-08-28; set `LANE_WATCH_REFERENCE` to a checkout of those exact bytes.

`LANE_WATCH_REFERENCE` has no default. If it is absent or empty, the script prints `lane-watch oracle: LANE_WATCH_REFERENCE is required` to standard error and exits 2 before creating a temporary directory; if the supplied value is unreadable, the script prints `lane-watch shell oracle source is unavailable` to standard error and exits 1.

The committed captures are provenance evidence, not authority: Rust tests assert the evidence bytes where the shell and ratified specification agree and assert governed report or diagnostic bytes for every documented divergence.

The Linux subprocess contract also creates live fixtures directly: a fixture driver writes the step lock and owns a child with either a loopback established TCP connection or moving `/dev/null` I/O, while separate cases use a dead driver PID and no lock. Their dynamic PIDs, ages, wall times, and I/O deltas are asserted without entering the historical shell captures.

## Inventory · `sec:lanewatchfixtures:inventory`

- `complete-with-report` captures verbatim completion-report bytes and shell status 0.
- `missing-events` captures the unknown-age stalled line and shell status 42.
- `fresh-one-line` and `fresh-multi-line` capture fresh age, line count, and last-event type behavior.
- `stalled-one-line` and `stalled-multi-line` capture stalled evidence, including the verbatim last event on its own line.
- `empty-fresh` and `empty-stalled` capture zero-line and unknown-type behavior for an existing empty event source.
- `explicit-window-fresh` and `explicit-window-stalled` prove that the second argument selects the comparison threshold and that equality belongs to stalled.
- `usage-no-arguments` and `usage-invalid-directory` capture the shell's unclassed usage diagnostic and status 2 for the governed diagnostic-divergence tests.

## Time normalization · `sec:lanewatchfixtures:time-normalization`

The capture script pins each event mtime to a declared age relative to an immediately sampled epoch second, but scheduler delay can still increase the displayed shell age.

Subprocess tests therefore normalize only the decimal `age` field in both oracle and Rust evidence before byte comparison; fixed-clock library tests separately prove exact age subtraction, threshold equality, future mtimes, and report-wall formatting.

## Regeneration · `sec:lanewatchfixtures:regeneration`

Set `LANE_WATCH_REFERENCE` and run `packages/superloop-lane/tests/driver_status/fixtures/capture_shell_oracle.sh` from any directory; the script resolves its output directory from its own location and creates temporary run directories under `TMPDIR`.
