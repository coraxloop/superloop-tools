# `superloop-gate-submit` · `guide:laneverify:superloop-gate-submit`

`superloop-gate-submit` snapshots an uncommitted worker-lane worktree without touching its real index, force-pushes that snapshot to the hub, and asks the worker server to run the governed Rust verification sequence. It also verifies a clean committed lane head from an external checkout. It is the Rust port of `reference/superloop-gate-submit.sh`; the ratified lane and output specifications govern wherever the reference differs.

## Command line · `sec:laneverify:command-line`

```text
superloop-gate-submit -p PACKAGE[,PACKAGE...] [-n NAME] [-A] [-D] [--release-build] [--push-remote NAME]... [--committed-head refs/heads/lane/RUN [--seed-object HEX]] WORKTREE
```

`-p` is mandatory and may name multiple Cargo packages separated by commas. `-n` selects the lane/ref identity and defaults to the canonical worktree basename. `-A` adds `--all-features` to the package tests. `-D` adds the warning-denying package documentation check. `--release-build` appends a locked release-profile workspace build without running release-profile tests. Short options accept the same separate, attached, and clustered forms as the shell reference.

Each repeatable `--push-remote NAME` schedules one branch push after verification. Names retain their command-line order. When at least one is present, argument handling resolves the worktree's current branch and refuses detached HEAD with usage status 2 before snapshot or verification work begins. After the complete server sequence returns status 0, each scheduled step runs `git push NAME HEAD:BRANCH` from the verified worktree. A failed push does not stop later remotes, so every configured hub gets its independent attempt. Server gate status 1 or 2, remote transport failure, and snapshot transport failure all return before this post-gate phase; no scheduled push is attempted.

`--committed-head refs/heads/lane/RUN` selects a committed checkout. Before transport it refuses staged changes, tracked changes, and nonignored untracked files as `dirty_checkout` with status 2, and it refuses a detached or different HEAD as `head_mismatch` with status 2. It pushes that HEAD object directly to `refs/lanes/verify-NAME` without a temporary index or snapshot commit. The server checks out the pushed verification ref and its wrapper prints `CHECKED-OUT object=HEX ref=refs/heads/lane/RUN token=TOKEN` on gate success or failure. The verifier requires one line carrying its unpredictable invocation token in the sixty-line evidence tail, rejects a gate-authored unbound line, and compares the reported object to the pushed HEAD.

`--seed-object HEX` accepts a full forty-character object ID only with `--committed-head`; the verifier runs `git merge-base --is-ancestor` in the external checkout before push, and the server repeats it after checking out the pushed head before the Cargo gates. On a seeded invocation the server's exit probe also prints `SEED-ANCESTRY object=HEX seed=HEX token=TOKEN result=RESULT`, and the verifier requires exactly one such line carrying its invocation token, the object of the bound `CHECKED-OUT` line and the requested seed. A seed absent from the external checkout, or one the committed head does not descend from there or in the bound line, prints `superloop-gate-submit: seed_ancestry` and ends with `FAILED` status 1. An absent, unbound, mismatched, malformed or duplicated seed line, or a bound line reporting `result=error` or `result=missing`, ends with `FAILED` status 1 under its own `superloop-gate-submit: seed_ancestry_REASON` line followed by `superloop-gate-submit: seed_result_failure`, and makes no ancestry claim; any other failure of the external check relays a line naming the failed step and the reason in the tool's own words, followed by `superloop-gate-submit: seed_check_failure`, with `FAILED` status 1. The superloop supplies the seed recorded beside the selected preserved bare's lane object; an unseeded bare omits the option.

Package and name tokens use the conservative lane grammar: an ASCII alphanumeric first byte followed by ASCII alphanumerics, hyphens, or underscores. This prevents a package token from becoming remote shell syntax and guarantees that the name can occupy the whitespace-free `lane` and `ref` report fields. With a complete, valid server profile, other invalid argument forms return usage status 2 before any subprocess starts.

## Environment contract · `sec:laneverify:environment-contract`

The server profile has four required fields. No operational default exists for any of them; parsing refuses before snapshot or transport work when a field is absent, empty, non-Unicode, or outside its grammar.

|Variable|Requirement or default|Validation|Fictional example|
|--------|----------------------|----------|-----------------|
|`LANE_VERIFY_SSH`|required; no default|ASCII alphanumeric first byte, then only ASCII alphanumerics, hyphens, or underscores|`sagofink-orchestration`|
|`LANE_VERIFY_CLONE`|required; no default|non-empty Unicode value containing only ASCII alphanumerics, slash, dot, hyphen, or underscore|`/srv/orchestration-pack/worktree`|
|`LANE_VERIFY_REMOTE_RUNNER`|required; no default|non-empty Unicode value with no leading or trailing space and containing only ASCII alphanumerics, slash, dot, hyphen, underscore, or space|`/srv/orchestration-pack/bin/run-report bash -s`|
|`LANE_VERIFY_RUST_ENV`|required; no default|non-empty Unicode value containing only ASCII alphanumerics, slash, dot, hyphen, or underscore|`/srv/orchestration-pack/env/rust.sh`|
|`LANE_VERIFY_REMOTE`|`shared` when absent or empty|passed to Git as supplied|`shared`|
|`LANE_VERIFY_TARGET_DIR`|derived from the canonical server checkout path when absent or empty|an explicit value must be Unicode and use the same grammar as `LANE_VERIFY_CLONE`|derived|

The complete fictional example profile is:

```sh
export LANE_VERIFY_SSH=sagofink-orchestration
export LANE_VERIFY_CLONE=/srv/orchestration-pack/worktree
export LANE_VERIFY_REMOTE_RUNNER='/srv/orchestration-pack/bin/run-report bash -s'
export LANE_VERIFY_RUST_ENV=/srv/orchestration-pack/env/rust.sh
superloop-gate-submit -p PACKAGE WORKTREE
```

For the first required field in table order that is absent or empty, the verifier returns usage status 2 and emits the corresponding fixed diagnostic below. Each displayed diagnostic is followed by exactly one LF byte.

```text
superloop-gate-submit: usage_error: LANE_VERIFY_SSH is required
superloop-gate-submit: usage_error: LANE_VERIFY_CLONE is required
superloop-gate-submit: usage_error: LANE_VERIFY_REMOTE_RUNNER is required
superloop-gate-submit: usage_error: LANE_VERIFY_RUST_ENV is required
```

A present but invalid server-profile field returns usage status 2 with the same fixed diagnostic as any other invalid command-line input, also followed by exactly one LF byte:

```text
superloop-gate-submit: usage_error: invalid command-line arguments
```

By default, the remote script resolves the checkout with `pwd -P`, hashes that canonical path with SHA-256, and uses the first sixteen hexadecimal digits in a `superloop-gate-submit-DIGEST` directory beneath the account's normal Cargo target root. One checkout therefore retains a warm cache without sharing compiled test binaries with another checkout path. `LANE_VERIFY_TARGET_DIR` is the explicit operator escape hatch and names the exact target directory instead of deriving one.

## Snapshot and remote execution · `sec:laneverify:snapshot-and-remote-execution`

The verifier resolves `HEAD` and the absolute Git directory, creates a new temporary index under the system temporary directory with exclusive `create_new` semantics, copies the real index bytes, and runs `git add -A`, `write-tree`, and `commit-tree` against only that temporary index. An owning guard removes the temporary file on success, ordinary failure, and unwind. The worktree's index, tree, HEAD, and refs are never changed by snapshot construction.

The snapshot commit is parented on the resolved `HEAD` and force-pushed to `refs/lanes/verify-NAME`. SSH receives two typed arguments: `LANE_VERIFY_SSH` as the alias and the complete `LANE_VERIFY_REMOTE_RUNNER` value as one remote-command argument. The generated script travels on standard input, sources `LANE_VERIFY_RUST_ENV`, changes to `LANE_VERIFY_CLONE`, and retains the reference sequence and byte-compatible `time nice -n19` command prefixes: forced fetch/checkout/clean, workspace format check, locked workspace Clippy with warnings denied, locked named-package tests, the optional locked documentation check, and the opt-in locked release-profile workspace build. Each verification step has its own shell `time` report in the returned output tail.

Committed-head mode uses the same server gate sequence and reports the server's checked-out object as `object=HEX` on the verifier-owned `RUN-REPORT` line. Snapshot mode's script and report bytes remain unchanged.

SSH standard output and standard error share one Unix pipe, matching the reference's explicit merge before tail selection. The last sixty lines are relayed byte-for-byte. If the last evidence line lacks LF, one separator is inserted so the owned report remains a physical line.

Post-gate pushes add one line apiece after that server tail, preserving argument order:

```text
PUSH-REPORT remote=NAME wall=SECONDS.MILLISECONDSs verdict=VERDICT
```

The per-remote verdict is `ok` or `FAILED`, and each wall value measures only that remote's push. Child diagnostics remain suppressed so repository paths and transport details do not enter the agent-text stream.

## Process-wrapper choice · `sec:laneverify:process-wrapper-choice`

This package uses `std::process` and no external dependency. `superloop-execwrap` was evaluated first, as required: it can spawn and route a child, but its public API cannot supply the remote script on child standard input, set the snapshot command's temporary-index environment/current directory, or return captured merged bytes for the governed sixty-line tail. Using it would still require a second process implementation and could not express the SSH boundary. The standard-library path supplies each argv directly, while a shared `UnixStream` gives SSH the required merged output without a command shell.

## Agent-text output · `sec:laneverify:agent-text-output`

Server evidence is followed on standard output by exactly one verifier-owned report:

```text
RUN-REPORT lane=verify-NAME exit=STATUS wall=SECONDSs verdict=VERDICT ref=refs/lanes/verify-NAME
```

Status 0 maps to `ok`. Declared server gate statuses 1 and 2 are relayed with `FAILED`; an undeclared server status or a local snapshot, transport, publication, or internal failure becomes status 1 with `FAILED`; and local argument or server-profile refusal uses status 2 with `FAILED`. Status 3 is reserved for `PUSH-FAILED`: every server gate returned green, but at least one scheduled branch push failed. This distinct terminal pair prevents a partial hub outage from rewriting the verification verdict as a gate failure. Usage, runtime failure, and suppressed panic paths emit a fixed classed diagnostic followed by the same report. Before a valid identity exists, the required report uses the fixed `unknown` identity. Standard error is used only for the fixed publication-failure fallback when standard output cannot accept the owned report.

## Reference divergences · `sec:laneverify:reference-divergences`

|Governing specification|Named fixture|Governed behavior|
|-----------------------|-------------|-----------------|
|(`[TOOLS-spec:output:agent-text-streams]`), (`[TOOLS-spec:output:lane-verify-report]`)|`usage-no-packages`, `usage-extra-argument`, `usage-unknown-option`|The shell writes unclassed usage prose to standard error and no report. Rust writes a fixed classed diagnostic and failed status-2 report to standard output.|
|(`[TOOLS-spec:output:agent-text-streams]`), (`[TOOLS-inv:output:final-report-is-final]`)|`snapshot-add-failure`, `push-failure`|The shell exposes child diagnostics and exits without a report. Rust relays a line naming the failed step and the reason in the tool's own words, which may carry a path: the child's last sixty standard-error lines, its exit status when standard error is empty, `empty output` when a value-producing step prints nothing, or the I/O error text when the step cannot run. The fixed path-free failure class follows, and a failed status-1 report ends the output.|
|(`[TOOLS-proto:output:run-report-line]`), (`[TOOLS-spec:output:lane-verify-report]`)|`unsafe-name`|The shell accepts whitespace-bearing identity and emits a malformed multi-field report. Rust rejects tokens that cannot occupy the declared grammar.|
|(`[TOOLS-spec:output:lane-verify-report]`), (`[TOOLS-req:output:agent-text-status-agreement]`)|`remote-undeclared`|The shell propagates arbitrary remote status 7. Rust maps every undeclared status to runtime failure 1 and records `FAILED`.|
|(`[TOOLS-proto:output:run-report-line]`)|`unterminated-evidence`|The shell concatenates its report to unterminated remote evidence. Rust inserts one LF separator before the report.|
|(`[TOOLS-rule:output:panic-suppression]`)|`panic_hook_is_installed_before_argument_handling_and_hides_payload`, `panic_after_parsing_still_ends_in_one_failed_report`|The shell inherits default runtime presentation. Rust installs an empty panic hook before argument handling and converts an unwind to fixed evidence plus a failed report.|

The `default_target_dir_hashes_the_canonical_checkout_path` and `explicit_target_dir_override_wins_without_derivation` fixtures demonstrate a plain implementation fact: cached test binaries embed checkout-specific fixture paths, so the Rust verifier derives a target directory per checkout rather than sharing one across checkout paths unless the operator supplies an explicit override.

The `release_build_flag_appends_a_separately_timed_workspace_build` fixture demonstrates another plain implementation fact: release-profile verification is opt-in, and the Rust verifier appends a separately timed locked workspace build only when `--release-build` is present.

The aligned `default-success`, `overrides-failure`, and `tail-cap` fixtures prove identical terminal report bytes after normalization of only measured wall seconds, identical Git object flow and parentage, exact SSH argv/script bytes, environment override behavior, remote verdict mapping, and the sixty-line relay.

The aligned `committed-head-success` fixture pins the direct committed-object push, exact SSH argv and script bytes, server checked-out line, and verifier report object; committed-head refusal fixtures cover dirty or mismatched local HEAD and missing or differing server object evidence.

## Test isolation · `sec:laneverify:test-isolation`

Subprocess tests prepend only committed fake `git` and `ssh` executables to `PATH`, and the remote-execution cases add a generated fake `cargo` that exits 0. The stubs record argv, temporary-index selection, source-index byte equality, SSH standard input, and canned output/status; in the remote-execution cases the `ssh` stub instead runs the received script under local `bash` in the synthetic worktree, with only its profile line replaced and `/usr/bin:/bin` appended after the fake tools, so the generated seed check and exit probe run against the stubs. They cannot invoke a real SSH client or contact a remote. The committed captures are provenance evidence, not authority; their source SHA-256 and regeneration procedure are recorded in `tests/fixtures/README.md`.

The command surface is `--version`, snapshot submission with `-p PACKAGE[,PACKAGE...]`, `-n NAME`, `-A`, `-D`, `--release-build` and repeated `--push-remote NAME`, and committed-head submission with `--committed-head REF` and optional `--seed-object HEX`. Every submission takes one worktree. The `LANE_VERIFY_*` settings select the transport and remote wrapper independently of the installed command name. Snapshot and committed-head forms retain their ref and object-identity contracts.
