# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The region-reader catalogue classifies a terminal `.j2` template by its inner file kind and treats a `LICENSE-AGPL_3_0` licence notice as opaque (``prob:linter:region-reader-catalogue-gains-j2-and-the-agpl-text``).

- Nested corpus roots require tracked ownership metadata before loading their snapshot, and a failed tracked-file census names its own refusal (``prob:linter:nested-root-with-no-tracked-paths-is-accepted-vacuously``).

- Publication tests compare author, committer and tagger instants as epoch seconds, also checking stored offsets and the reported date across Git date renderings (``prob:pack:cut-acceptance-compares-epoch-seconds``).



- The door's direct policy publication reads the loop registry through the ACL mask that mail provisioning leaves on it, so the door publishes its policy after the cutover (``sec:loophome:mail-migration``).

- The door's tier custody check compares the private and direct tier modes through the ACL mask that mail provisioning leaves on the private tier, so the policy publication passes its custody check after the cutover (``sec:loophome:mail-migration``).

## [0.4.0] - 2026-11-05

### Changed

- Installed worker instructions use the mounted mailbox, name its submission grammar and verified steering rule, and distinguish the initial brief and inert legacy slots (``prob:mail:confined-box-mount``; ``prob:mail:legacy-entry-retirement``).

- Round previews refuse missing or drifted birth metadata, configuration state and mailbox grants without creating or repairing them (``prob:mail:round-transport-over-mail``).

- Worker preparation publishes its claim watermark atomically under the run-table lock so interrupted writes preserve rebirth capacity (``prob:mail:worker-birth-in-the-lane-launcher``).

- Migration documentation assigns worker mailbox instructions to the instance's held cutover documents, outside the migration command (``prob:mail:migration-command``).

- Mail migration snapshots and parks only mail configuration, restoring private configuration ancestors by metadata while credential siblings remain in loop custody (``prob:mail:migration-command``).

- Entry dispatch exposes its intercepted-word inventory, live capture documentation is retained, and follow drops obsolete zero-valued correspondence cost fields (``prob:mail:legacy-entry-retirement``).

- Round previews verify retained mail pins without publication, admission waits for bounded pin writers, and the estate pin projection has its own 1 MiB implementation bound (``prob:mail:round-transport-over-mail``).

- Inbox presence checks report unavailable folders through the existing fail-open path, and ordinary waiting refuses an unavailable inbox (``prob:mail:notice-and-ordinary-waiting``).

- Mail directory overflow identifies the registry or allocations metadata instead of blaming the submitted letter (``prob:mail:delivery-core-and-user-unit``).

- Worker preparation retains a unique claim stamp across retirement, and mail compaction releases deregistered-loop pins while projecting inventory pins from its single record read (``prob:mail:worker-birth-in-the-lane-launcher``).

- Mail migration inventories legacy stores and retained run evidence, relocates worker execution homes, preserves opaque history with restartable manifests, and holds activation behind verified deployment and rollback boundaries (``prob:mail:migration-command``).

- Retired mail custody remains service-recoverable after UID release, while unavailable active endpoints retain their inbox evidence (``prob:mail:worker-birth-in-the-lane-launcher``; ``prob:mail:delivery-core-and-user-unit``).

- Ordinary loop entry no longer dispatches legacy letters commands; worker follow retains event evidence without reading correspondence sidecars, and initial briefing is an immutable input outside mail (``prob:mail:legacy-entry-retirement``).

- Resumed rounds bind service-verified mail before authorization, retain exact delivery bytes for step evidence, and release journal pins on retirement; reply settlement consumes verified worker-to-loop mail and the legacy round-letter commands are retired (``prob:mail:round-transport-over-mail``).

- Mail hooks expose only the arrival notice from inbox presence, and ordinary filesystem waiting arms before listing and reconciles every wakeup without reading letters (``prob:mail:notice-and-ordinary-waiting``).

- Box launches bind only their worker mail folder read-write at /mail, identify it through SUPERLOOP_MAIL, and include its service ownership and worker binding in confinement checks (``prob:mail:confined-box-mount``).

- Delivery reports an oversized loop configuration as invalid-directory, preserving oversize for letter admission (``prob:mail:delivery-core-and-user-unit``).

- Worker launch refusals name mail provisioning and legacy-home relocation, and protected receipt reads have a 4 KiB implementation bound (``prob:mail:worker-birth-in-the-lane-launcher``).

- Worker retirement transfers retained mailbox custody to the service before releasing the UID, and worker-run close serializes retirement against launch while retaining names (``prob:mail:worker-birth-in-the-lane-launcher``).

- Worker creators reserve immutable mail identities before home creation, publish only complete endpoints and retain retired names and UID receipts across retries and replacement (``prob:mail:worker-birth-in-the-lane-launcher``).

- Lane preparation accepts the preserved service search ACL, and delivery retries contended loop configuration without blocking other loops (``prob:mail:loop-mail-at-birth``).

- Mail scans isolate unavailable actors, bound loop configuration reads and install a refusal-aware user unit in the user data search path (``prob:mail:delivery-core-and-user-unit``; ``prob:mail:loop-mail-at-birth``).

- Mail provisioning pins its helper image and enters the private working directory before dropping credentials, preserving access beneath a private host-home prefix (``prob:mail:loop-mail-at-birth``).

- Explicit loop provisioning stages isolated mail folders and creates loop-owned routing configuration while preserving existing bytes, retained names and service ACLs on retry (``prob:mail:loop-mail-at-birth``; ``prob:mail:mail-configuration-never-shares-the-registry-file``).

- The host-session mail core serializes opaque delivery, fresh loop-owned routing decisions, durable refusal projection and capacity-aware recovery; its user unit enters the existing subordinate namespace without enabling itself (``prob:mail:delivery-core-and-user-unit``).

- Mail completion clears resolved transport errors and measures retention age from the latest known instant so clock rollback postpones pruning without permanent pins (``prob:mail:journal-records-recovery-and-retention``).

- Mail publication syncs protected snapshots before acceptance, publishes inbox bytes by one no-replace rename, and recovers through journal witnesses and restartable source restoration without redelivery (``prob:mail:journaled-inbox-publication``; ``req:mail:inbox-publication``).

- Mail persistence protects delivery records and UTC reservations, derives recovery from publication witnesses, and bounds retained history with pinned evidence and restartable compaction (``prob:mail:journal-records-recovery-and-retention``; ``req:mail:records-recovery-retention``).

- Registry, worker allocation and mail parsing share the identity production, with leading hyphens refused, command words admitted as names and storage failures separated from syntax (``prob:mail:name-grammar-alignment``; ``reg:mail:identity-names``).

- Door admission waits up to 30 seconds within the request deadline before refusing concurrency, reports the actual wait and a 30-second retry recommendation in JSON and stderr, and admits requests when the held guard clears (Door request admission, ``rule:superlooplane:door-request-admission``; capability mediation (`rule:workercontracts:capability-mediation`)).

### Fixed

- The migration census binds a retired worker home to its inode alone, because the anonymous device numbers of btrfs subvolumes change across mounts while inodes stay (``sec:loophome:mail-migration``).

- The ancestor-trust checks of the allocation ledger, the workers settings and the runs root accept the overflow uid that an unmapped root shows inside a user namespace, so the migration can read the ledger it freezes as namespace root (``sec:loophome:mail-migration``).

- The private protected-file reader compares the mode through the ACL mask that mail provisioning leaves on the registry and the ledger, so the door install runs after the cutover (``sec:loophome:mail-migration``).

- The namespace-root migration fixture writes its ledger, registry, service settings and home with the real estate's modes (``sec:loophome:mail-migration``).

- Driver launch opens step letters without following symlinks or blocking on special files, and names `--step-letter` and its path in refusals (`rule:workercontracts:launch-and-evidence`).

- Document that compute store writers, including the admission record, retry against the compute request's own 1,800-second deadline (`rule:workercontracts:capability-mediation`).

## [0.3.2] - 2026-11-02

### Fixed

- Round launches retain the selected letter text beside the pointer brief for both driver backends, including resumed and threadless continuations; retries preserve the pointer input (`rule:workercontracts:letters-and-retention`).

- Replay attributes unparseable public root metadata to its input context before refusing (`req:output:failure-class-naming`).

- Replay author examples use the same double-quoted identity as cut (`spec:outputspec:command-and-output-contracts`).

- Release refuses conflicting public and Cargo workspace versions, naming both declarations (`rule:commandcontracts:public-release-version-agreement`).

- The 0.2.0 release notes have one dated section listing each entry once, every entry citing its contract label, so release-note selection is unambiguous (`rule:commandcontracts:public-release-version-agreement`).

- Door writers retry contended record locks until the request deadline, retain completed effects across a sibling's longer record hold, and report lock wait time and known holder identity in the service journal and worker refusal (`rule:workercontracts:capability-mediation`).

- Door records retain the base writer wait after their request deadline, connection refusals disclose only typed lock contention, and request-scoped wait diagnostics distinguish retry expiries from final timeouts (`rule:workercontracts:capability-mediation`).

- Release honors Git’s merge and tag signing switches, reports preview signing intent and final object identities, and refuses signer failures before moving refs (`rule:commandcontracts:public-release-signing`).

- Release signing declares its disposable GPG test dependencies, cleans fixture agents and socket directories on every exit path, names signer failures, and checks unsigned object shapes before promotion (`rule:commandcontracts:public-release-signing`).

- The release unsigned-shape test name agrees with its inventory label, keeping the candidate linter gate enforceable (`rule:commandcontracts:public-release-signing`).

- Disposable signing-home cleanup diagnostics use the explicit stderr writer required by the workspace gate (`rule:commandcontracts:public-release-signing`).

## [0.3.1] - 2026-11-02

### Added

- The public-set manifest accepts an optional `[public] version = "X.Y.Z"`, the repository's release version, distinct from the manifest-format `version`; every manifest reader refuses a malformed declaration.

### Changed

- `superloop-pack release` takes the release version from the Cargo workspace manifest's `[workspace.package] version` when development carries one, and otherwise from the manifest's `[public] version`; it refuses `version-missing` when neither is declared and reports the selected `version_source`.

## [0.3.0] - 2026-11-02

### Added

- The digest specification (`spec:digests:handles-and-bindings`) distinguishes digest handles, 16-hex-digit prefixes of the full digest sized against a declared collision budget, from cryptographic bindings, which keep the full digest and state the forgery they prevent, the trusted reference and the actor-controlled side; it installs with the other specifications.

- The digest specification inventories each digest use by package, file and line as a binding or a handle, and names the unstated protections and the handle migrations that need coordinated reader changes.

- `superloop-pack replay` reports burn matches as pre-existing when the matched value already occurs in the public root at the same path or corresponding metadata field, allowing already-public history to replay while refusing introduced values.

- `superloop-pack replay --author "Name <addr>"` sets every replayed commit's author and committer identity while preserving source dates; the private report records the mapping and source metadata remains subject to burn checks.

## [0.2.0] - 2026-11-02

### Added

- `build-sync census` reads explicit ledgered installation maps and document roots; `--installations-only` checks document repositories without Cargo metadata (`rule:buildcontracts:installation`).

- `superloop-pack replay` projects linear source history onto an existing public development branch, preserving commit metadata and skipping unchanged public trees. Each source commit uses its own manifest, bounded by the tag's final public policy; missing historical manifests, README sources and licences refuse. The entire range is preflighted against the external burn register before destination writes; refusals name their check, source ordinal and commit, and path or field, and retain a private refusal record and diagnostic scratch (`rule:buildcontracts:repository-boundaries`).

- `superloop-pack release` validates a pinned public development tree and creates an unsigned merge and annotated version tag in one expected-old transaction advancing main and development, with check and dry-run reports and an explicit three-ref push allowlist (`rule:commandcontracts:public-release-version-agreement`).

- `superloop-lint` reports `inactive_prose_owner`: a declared owner whose partitions attribute Markdown sources but which activates no `labels.mints-well-formed` row, because such an owner's prose silently left the corpus and read like a clean result (`rule:lintcontracts:ownership`).

- `superloop-lint` accepts `nested = [{ owner, root, reason }]` in the owner declarations for a nested corpus checked as its own repository; the loader refuses an unregistered owner, a root outside the owner's partitions, a root without a loadable linter snapshot, or an empty reason (`rule:lintcontracts:ownership`).

- `superloop-lint` defers an activated pair whose row names a repository-local programme (`programme = { package, binary }`) instead of refusing an uncatalogued policy; the report gains `deferred` and `deferred_policies`, the pair's list table is accepted by shape, and `clean` stays the catalogued policies' verdict (`rule:lintcontracts:verdicts`).

- `superloop-pack cut` takes the default annotated tag title from the manifest's required `[public] name` (`NAME TAG`, then the CHANGELOG section body; `--tag-message` overrides verbatim), and the shared reader refuses a blank or multi-line name (`rule:buildcontracts:build-provenance`).

- `superloop-pack cut` and the linter's `public_set` check refuse an include row that selects the root README while `[public] readme` names a different source, naming the selector to turn into an exclusion with a reason (`rule:buildcontracts:repository-boundaries`).

### Changed

- `superloop-pack cut` retains the historical snapshot and the linter's output when `citation-sites` refuses, and names the retained directory in the refusal (`req:output:report-path-validity`).

- Private architecture, runbooks and linter design history leave the tools tree together with their ownership and prose inventory; public projections and the empty label register remain checked, and consumer-generated lockfiles remain local build inputs (`spec:lintcontracts:linter-contracts`).

- Public tools now carry their README and reusable worker, command, linter and build contracts directly; operational history and instructions are served by the instance publication (`spec:workercontracts:worker-boundaries`).

- Tools installations retain public specifications and executable identities while instance-owned maps, wrappers and the runtime unit leave the tools build (`spec:buildcontracts:build-and-installation`).

- Sign-in home commands accept `--charter PATH`, default to the instance worker-charter publication, refuse unavailable inputs before changing a home, report the resolved path, and reconcile existing Codex charter links (`rule:workercontracts:launch-and-evidence`).

- The unresolved-import finding names the owner and prefix it searched, and says when the owner activates no `labels.mints-well-formed` row (`rule:lintcontracts:references`).

### Fixed

- Nested-root containment is judged against the tracked universe, so an untracked or ignored file under a nested root no longer refuses the declaration (`rule:lintcontracts:ownership`).

- A burn or lower rewrite of the list declarations keeps the bytes and position of list tables deferred to a repository programme (`rule:lintcontracts:maintenance`).

- A `programme` row checked outside a Git checkout refuses with a message naming the programme check and its reason (`rule:lintcontracts:verdicts`).

- The pack's real-linter fixtures activate their prose, so the fixtures pass the `inactive_prose_owner` finding (`rule:lintcontracts:ownership`).

## [0.1.0] - 2026-10-12

### Added

- `superloop-lane` and `superloop-gate-submit` for running worker lanes and checking changes before integration.
- `door-ssh` and `door-service` for mediating command execution.
- `build-sync` and `superloop-install` for staging build outputs and installing declared releases.
- `superloop-lint` for checking repository documentation and declarations.
- `superloop-pack` for publishing selected source trees with independent Git history.
- `superloop-steward` for polling transcripts and reporting work progress.
- `superloop-claude-hook` and `permission-triage-hook` for handling harness events and command permissions.
- GPL-3.0-or-later code and CC0-1.0 documents, with no backwards compatibility before 1.0.

[Unreleased]: https://github.com/coraxloop/superloop-tools/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/coraxloop/superloop-tools/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/coraxloop/superloop-tools/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/coraxloop/superloop-tools/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/coraxloop/superloop-tools/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/coraxloop/superloop-tools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/coraxloop/superloop-tools/releases/tag/v0.1.0
