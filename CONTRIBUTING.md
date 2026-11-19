# Contributing to superloop-tools · `guide:contributing:superloop-tools`

This is the first reading for contributors, workers and reviewers in the tools repository: it states how work is done, defines its label and citation form and routes its statements of kind ``inv``. The public introduction (`guide:publictools:superloop-tools`) describes its purpose; the backlog (`plan:toolsbacklog:superloop-tools-backlog`) and priorities register (`reg:toolsbacklog:priorities`) order the open work. Read those records with the worker charter and the working letter, which supply the lane's scope, compute route, budget and exact gate. Generic dispatch rules are published by the orchestration repository; its import snapshot determines which of its labels this tree can cite.

## Select and work a slice · `sec:contributing:slice-work`

Clone the supplied workspace bare into your own checkout, branch from the brief's base, and push only the lane branch to the workspace bare and the compute mirror explicitly named by the working letter. Read the backlog's status paragraphs and priorities register together: dependencies, readings, verification bars and partial holdings matter as much as order. Select unheld work; do not take another lane's implementation to satisfy a dependency.

The selection report proposes twenty to thirty rows, or the whole backlog when it holds fewer. For each row name its label and repository, order and reason, intended commit or coherent pair, files, tests, wall estimate and contradictions with the code or documents. Stop at that report; the loop's working letter supplies the next scope and bar. This is the slice form named by ``proto:dispatch:slice-dispatch`` in the generic specification.

Make each commit of an authorized step a named Conventional Commit with a body explaining why and pass the working letter's bar before shipping. Once pushed, a slice branch is never rebased, squashed, amended or force-pushed: merge a moved base into it and append review corrections as fixup commits. The charter's single-bite squash-and-fold convention does not apply to a slice worker; the generic rule is ``rule:dispatch:lane-branch-merge-in``. The loop owns the review branch and remakes reviewed work on the base under ``proto:dispatch:review-branch-landing``; never edit that branch, sign a worker commit or touch a signing key.

## Text, code and declarations · `sec:contributing:text-and-declarations`

State contracts timelessly and keep dated measurements in records and release history. Keep each prose paragraph on one physical line. Public fixtures and examples carry fictional values, never credentials or an estate's private identifiers. Compatibility readers, aliases and shims are defects under the repository's pre-1.0 policy (`sec:publictools:versioning`).

Each heading or named environment mints one label of its declared kind, and an existing label keeps its identity. Cite a same-owner label in parenthesized backticks, as in (`reg:toolsbacklog:priorities`). An imported citation puts its declared owner and label inside brackets; the displayed form is ``[ORCHESTRATION-kind:area:slug]`` and requires a target in the import snapshot plus a permitted owner edge. Do not mint a foreign label locally or refresh an import merely to make an unrelated citation resolve. Use double-backtick mentions for file paths in prose, such as ``docs/backlog.md``, and for displayed labels that are not citations. Never write the token made by joining a less-than sign, the letters c h a r and a greater-than sign in a tracked file, even in an example or test.

Declare each new tracked file in the appropriate inventory reached from ``meson.build``, fit it to a partition in ``.linter/owners.toml``, and classify it in ``public-set.toml``. A root guide belongs in the root prose inventory; package code, tests and data belong in their package declarations. Keep declared callers, test-tool bindings, installed programs and dependency-ledger facts consistent when changing them. A Meson inventory edit changes that file's measured scope digest: review the executable forms, refresh their ledger scope digests from the dependency census and reconfigure before the final census. Give a new document a reader-facing route and regenerate any affected projection instead of hand-editing generated regions.

Use Rust or Meson for implementation work under the repository's build decisions. Follow rustfmt and clippy; use ``fmt::Write`` when writing formatted fragments into a string, iterator idioms where appropriate, and document a new panic condition in the function's Panics section. Tests should exercise the production boundary and refusal behavior, including distinct identities when custody is the subject; a fixture that proves only a helper's own assumptions is not the acceptance evidence.

The label form here is ``kind:area:slug``: kind names the statement's form, area its subject and slug its identity; the mint and citation notation is (`[ORCHESTRATION-ntn:environment:labels]`). An Invariant-kind statement uses kind ``inv``. A citation uses parentheses around a single-backtick label, or around the bracketed imported owner and label; a double-backtick mention names text without asserting a citation.

## Invariants and their sources · `sec:contributing:invariants-and-their-sources`

The adopted contract sources below carry the repository's Invariant-kind statements (`[ORCHESTRATION-rule:dispatch:briefs-cite-the-rules-they-state]`). Read the named statement and its argument before asserting it; a label mention alone supplies neither. New or moved ``inv`` mints remain reachable from this section in the same change. These routes preserve each source's scope and status, and generated copies are not additional mints. For these routes, invariant means a statement of kind ``inv``; a property cited under another kind, such as a rule, axiom or requirement, is written authority without an entry here, and its absence is neither a missing route nor an unwritten invariant. The reviewer judges the cited statement and its argument, not whether its kind is ``inv``. Any route to a proposal or plan is kept separately and does not adopt its claims.

|Document|Place of the invariant mints|
|--------|----------------------------|
|``docs/spec/deployment.md``|(`sec:deployment:installation`)|
|``docs/spec/linter-conformance.md``|(`sec:conformance:linter-frontier`)|
|``docs/spec/output.md``|(`sec:output:agent-text-mode`)|
|``packages/superloop-lane/README.md``|``inv:superlooplane:run-authority-separation``, ``sec:readme:commands``, ``sec:readme:settings``|

The lane package is a separate label owner. Its row gives the document and its local mint and section labels as literal locators; search within that document. It does not invent a TOOLS-to-SUPERLOOPLANE citation edge. The package's Commands and Settings sections contain the remaining invariant heads.

## Verify on the named compute node · `sec:contributing:verification`

Use only the node and route scoped by the working letter. Source its toolchain environment, use its disk-backed temporary root and lane-owned target directory, and retain one compile configuration across comparable runs. Do not build or run checks in a worker sandbox reserved for editing. If the letter supplies private build inputs, merge them only in the node verification checkout before Cargo or Meson; never publish that merge or its contents with the public lane branch.

The tools gate includes the following operations, with ``BUILDDIR`` and ``LINTER`` supplied by the working letter. The touched packages also run their focused tests. Use the gate's declared test-tool bindings and profile for the workspace battery so a missing fixture program is not mistaken for a product failure.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps
cargo test --locked --workspace --no-fail-fast
meson setup -Ddomain=server "$BUILDDIR" .
ninja -C "$BUILDDIR"
meson test -C "$BUILDDIR" --suite lint --suite release --print-errorlogs
"$LINTER" check --root .
"$LINTER" project --root .
"$LINTER" fmt --check .
git diff --check
```

Meson's census, lint and release suites run for document-only changes too: a prose file must be declared, and the publication still has to build. Bind the linter to the candidate when the deployed linter predates its declarations; report the version mismatch rather than weakening the manifest. A public-pack check uses the externally held burn input named by the letter; pass its path without printing or copying its contents. Report the workspace battery before READY FOR VERIFY even when focused tests pass.

An acceptance-debt classification requires the same failing test on the base and tip, with passed and failed counts for both. Do not fix an unrelated base failure as part of a documentation row. Read a red at a wall guard under load as a defect of the test, to be repaired in the test whether or not it passes alone; isolated reruns do not classify it (`prob:gates:elapsed-time-assertions-are-censused-and-rewritten`), and a timing failure in an untouched package supplies no causal claim about the candidate without further evidence (`[ORCHESTRATION-rule:conformance:ordering-and-timing-evidence]`). Retain command output, exit status and wall seconds, and distinguish skipped checks from passed ones.

## Close and report · `sec:contributing:close-and-report`

Remove a met item from the backlog and its priorities row in the commit that meets it, adjusting the count while preserving the remaining order. Fold its claim into the lasting documentation and add an Unreleased line in ``CHANGELOG.md`` using the repository's backtick label form; the release stamp belongs to the loop. If the behavior already exists, name the check that proves it instead of adding a second implementation. The backlog manager owns allocations and holdings outside the completed item's removal.

The working-step report has one section per named commit: full hash, repository, subject, files and line counts; a check table with commands, wall seconds and results; the start and wait form of every server round; the items closed and their backlog or changelog locations; deviations or NONE; and the ready or blocked word required by the letter. Report each friction the work met as one of the two kinds the well-made principle distinguishes (`prin:publictools:well-made-and-good-to-use`): a manufacturing defect, ground down where it is, or the symptom of a design question, which the report names. Time substantive commands, including Git and transport. Keep a detached node round's PID, log and end marker, wait for it in the foreground, and reconnect to that same round after an interruption; never treat a lost connection as completion or relaunch a round merely because its waiter was lost.
