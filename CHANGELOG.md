# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Reply sessions can retain a worker lifetime lease across the service identity drop and bind or verify delivery pins through received configuration, storage, endpoint and journal custody, as a library prerequisite for the reply entry (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Reply-binding inventory can retain received configuration and storage custody through loop snapshots, mailbox metadata and endpoint freshness, sharing one loop-storage capability between endpoints (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:loophome:binding-inventory-retains-received-custody``).

- Active lifetime verification exposes a non-admitting stage whose lease acquisition rechecks custody, receipts and loop-owned bindings, with rootless interleaving and read-only journal metadata regressions (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Mail endpoints can open and recheck freshness beneath received loop-storage custody, retaining canonical journal paths and existing endpoint identity, mode, group and filesystem checks (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:loophome:endpoint-opening-and-freshness-retain-loop-storage``).

- Mail reservation binding and verification can use received journal custody without reopening the journal path, retaining delivery checks and compaction admission while the service writer remains active (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:loophome:journal-reservation-binding-retains-custody``).

- Draft owner-operated Claude credential acceptance distinguishes external token-only startup, refresh attempts, same-process reload and the margin, binding-cost and contention measurements; it leaves vendor outcomes and activation unmeasured (``prob:box:claude-sign-in-and-endpoints-in-the-box``; ``prob:box:claude-print-probe-refresh-margin-measured-against-refresh-ahead``; ``sec:superlooplane:claude-credential-acceptance-draft``).

- Gated Claude credential exercise payload observes the locked token-only projection and schema-2 provider evidence without reporting credential-derived digests; namespace and vendor acceptance remain unmeasured (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-credential-exercise-payload``).

- Credential exercise selects one protected backend through the public and private forms, excludes foreign live runs and keeps Claude measurement gated before owner access (``prob:box:claude-boxed-workers``; ``proto:superlooplane:credential-exercise-backend``).

- Add `superloop-capture-admit` for verified capture admission, manifest-bound identities, quota refusal and current/keep/lease-aware pruning (`prob:servers:capture-admit-admits-and-prunes-sealed-generations`).

- Gated Claude harvest inventories and removes its selected worker state without preserving credentials or sessions, and refuses missing or foreign backend ownership (``prob:box:claude-resources-and-harvest-measured``; ``proto:superlooplane:harvest-selected-worker-state``).

- Gated Claude program comparisons read the installation reference through held configuration custody retained across the authority thread, refusing unsafe or absent custody; the related entry refusal assertions use short constants (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-install-reference-custody``).

- Gated Claude periodic publication selects live worker homes by protected backend and records owner-program evidence without a fabricated OAuth host (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-periodic-credential-publication``).

- Gated Claude credential paths bind the held owner program to the completed installation's reviewed digest and the loop's credential-structure program pin before credential access and again before refresh execution (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-owner-program-binding``).

- Gated Claude preflight and per-round credential publication share the locked provider and post-refresh expiry check, preserving token-only files and the existing publication receipt shape; a failed refresh or an expired result leaves the prior worker file untouched (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-round-credential-publication``).

- The gated Claude owner provider reads only the ``claudeAiOauth`` object of the owner's credential file and refuses any departure from the loop's structural record, and its token-only worker encoding carries the access token with its expiry, scopes and account descriptors and neither refresh field nor the host's plugin state; the owner's own program refreshes, expiry is checked again on the clock read after that program returns, the Codex adapter is unchanged and Claude execution remains gated (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-owner-credential-encoding``; ``rec:superlooplane:claude-credential-structure-input``).

- Boxed launch checks the entry deployment and interface before reservation and names both versions on refusal; the entry query resolves no loop state (``prob:box:launch-probes-the-entry-version-before-the-reservation``; ``req:superlooplane:entry-version-before-reservation``; ``proto:loophome:driver-entry-interface-query``).

- Claude candidate launch vectors carry selected print and model arguments through structural container checks while execution remains gated on credential and trial acceptance (``prob:box:claude-boxed-workers``; ``proto:superlooplane:boxed-launch``; ``conv:superlooplane:backend-selection-compatibility``).

- Boxed image checks bind the protected backend to its own measured program, template and manifest hashes, including the Claude sibling template in mixed installations; Claude execution remains gated (``prob:box:claude-boxed-workers``; ``pre:superlooplane:launch-input-checks``; ``proto:superlooplane:boxed-launch``).

- Exact compute forms in the loop's installed configuration select longer whole-request deadlines while other forms retain 1,800 seconds; the service announces the remaining window to the stub and deadline refusals name the registered bound (``prob:door:door-compute-deadline-per-form``; ``setup:superlooplane:compute-deadline-registration``).

- Owners can explicitly declare unchanged upstream trees non-participating with a reason, retaining partition and census coverage while refusing label activations and preserving the inactive-prose guard for all other owners (``prob:linter:non-participating-owner-for-unchanged-upstream-trees``).

- Door capacity refusals identify the fixed sixteen-peer service bound and a 120-second retry cadence; the worker contract treats them as transient while node compute scheduling remains with the owner-controlled wrapper (``open:door:door-compute-capacity-under-many-lanes``; ``rule:superlooplane:door-peer-capacity``).

- Registered `cargo test` commands admit `--no-run` for compile-only checks under the existing judgement tiers, retaining the exact argv and refusing the flag on other verbs or in runner arguments (``prob:door:door-compute-admits-test-no-run``).

- The mail service emits structured stderr spans and events for inventory skips, each naming the skipped loop or worker and the reason the scan's failure report collects, and for delivery, refusal codes, restoration, recovery, pruning and clock waits, with `RUST_LOG` filtering and a quiet `info` default; refusal sidecars are unchanged (``prob:mail:inventory-skips-are-events-and-the-refusal-names-its-class``).

- Claude plan and home construction select their own worker state leaf and immutable configuration mounts, refuse cross-vendor layouts before writes and leave runtime and credential acceptance explicitly unavailable (``prob:box:claude-boxed-workers``).

- Registered test commands accept one restricted filter after a named test target, including the explicit exact-match suffix, while retaining the argv and refusing additional or unbound filters (``prob:door:door-compute-admits-test-name-filter``).

- Boxed launch accepts an explicit `--backend {codex|claude}` selector, validates that vendor's configured program without cross-vendor fallback and names the selection in its preview; Claude execution remains refused as `backend-unavailable` pending its plan, home, entry, credential and runtime adapters, and resumed rounds refuse a backend selection; existing settings files select Codex as before (``prob:box:claude-boxed-workers``; ``conv:superlooplane:backend-selection-compatibility``).

- Namespace entry has a shared capability foundation for verified maps, bounded descriptor handoff, operation-bound custody checks and ledger/registry reads beneath one configuration anchor; production caller migration remains deferred (``req:workercontracts:namespace-anchor-authority``).

- Publication manifests declare the unpublished-label register destination through `public.unpublished`; cuts generate it there and bind the owner snapshot to it, refusing excluded-definition citations without a declaration and unsafe or conflicting destinations (``prob:pack:manifest-declares-the-unpublished-register``).

- The contributing guide gives slice workers the branch workflow, source declarations, node verification bar and working-step report contract (``guide:contributing:superloop-tools``).

### Changed

- Claude namespace mutation cleanup retains the host fixture identity instead of trusting a namespace-writable path record, with redirection and directory-replacement regressions (``prob:gates:lane-fixture-homes-leave-no-temporary-root-behind``; ``test:unit:claude-cleanup-retains-host-fixture-identity``).

- Pin Claude helper-service gate refusals and their existing validation order before introducing fixture admission (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-service-claude-gate-baseline``).

- Pin the wrong-program digest refusal through a due Claude round publication, including retained worker bytes and inode (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-namespace-held-program-standin``).

- Pin Claude namespace fixture cleanup across timeout and host panic, including subordinate-owned worker storage (``prob:gates:lane-fixture-homes-leave-no-temporary-root-behind``; ``test:unit:claude-namespace-fixture-cleanup-survives-timeout-and-panic``).

- Contain Claude namespace fixture descendants across process-group changes with a per-case PID namespace and a watchdog regression (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-namespace-watchdog-contains-detached-descendant``).

- Record a synthetic probe of the namespace watchdog's kill sequence, in which a descendant in a process group of its own survives, keeping descendant cleanup and its regression through the namespace wrapper open (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Bound the Claude trial draft's worker-file observations, same-process rejection evidence and expired print-call regime without selecting a repair policy (``prob:box:claude-sign-in-and-endpoints-in-the-box``; ``prob:box:claude-print-probe-refresh-margin-measured-against-refresh-ahead``).

- Pin held Claude owner-program execution in the mapped namespace with a recorded-digest native stand-in, transferred custody and expired-result preservation (`prob:box:claude-program-binding-formats-pins-and-measures-its-hash`).

- The capture state record specifies the completed-step driver and monitor fallback, and the finished-state observation item closes there on its retained historical observations, invalid-monitor and rollback regressions, corrected lock-name wording and the supplied watcher glossary (`prob:lanes:claude-lane-finished-state-null-driver`).

- The remaining door merge-failure, deadline, wait-error, decided-enforce and learned-hit regressions consume validated lock-wait credits before their final reply within one bounded window (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:door-final-reply-follows-lock-wait-credits``).

- Pin restoration of the completed observation through resume-preparation rollback, retaining the production snapshot bytes in the retried archive (``prob:lanes:claude-lane-finished-state-null-driver``; ``test:integration:claude-rollback-restores-completed-snapshot``).

- Pin completed driver identity retention when embedded monitor text is invalid, with the real driver publication and follower as the control (``prob:lanes:claude-lane-finished-state-null-driver``; ``test:integration:claude-finished-state-keeps-identity-with-invalid-monitor``).

- Door enforcement, adjudication and incomplete-record regressions consume request-lock credit frames before their final-reply assertions, with deterministic multi-credit coverage (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:door-final-reply-follows-lock-wait-credits``).

- Five credential-exercise JSON macro bodies are split into reviewable lines without changing their fields or values (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-credential-exercise-payload``).

- A mapped-identity fixture exercises Claude provider preparation, round publication and observation with synthetic authority, retaining the worker file on expired refresh and keeping the public runtime gate closed (``prob:box:claude-boxed-workers``; ``test:unit:claude-namespace-publication-keeps-worker-authority-separate``).

- Credential binding regression checks isolate activation-start clearing and mid-activation anchor replacement, and census provider refusals pin their detail (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-program-binding-cadence``).

- Capture admission uses the sanctioned agent-text terminal report with matched statuses, classed diagnostics and suppressed panic payloads; its interrupted-generation and write-order follow-ups are met (``prob:servers:capture-admit-orders-its-writes-and-declares-its-output-mode``).

- Keep capture admission and pruning available after an interrupted generation rename, publish keep before current, and cover special-entry refusals (``prob:servers:capture-admit-orders-its-writes-and-declares-its-output-mode``).

- The audit-before-effect regression waits through request-lock credit frames before asserting the final reply, retaining its no-effect-before-label checks (``test:unit:door-audit-label-precedes-effect``; ``proto:superlooplane:request-lock-wait-credit``).

- Periodic Claude refresh regression coverage exposes repeated owner-program calls for unrotated authority inside the refresh-ahead window and retains worker bytes at expiry (``prob:box:claude-print-probe-refresh-margin-measured-against-refresh-ahead``; ``proto:superlooplane:claude-periodic-credential-publication``).

- Credential evidence regression cases refuse cross-schema provider fields and foreign backends at both publication and census, retaining prior evidence on a refused publication (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-periodic-credential-publication``).

- Gated Claude program bindings reuse successful verification only for unchanged held custody within one thread and activation; metadata, policy and required-pin checks remain on every boundary (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-program-binding-cadence``).

- Native creation is accepted through its production namespace composer, receiver and home creation, with reserve and finish bound to the protected receipt, active mail configuration, placed brief and redacted worker credential (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:native-creation-completes-reserve-and-finish``).

- Runtime preparation executes its received container program through the production namespace receiver after pathname replacement, with real anchored birth setup and distinct image-inspection results (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:runtime-preparation-executes-received-podman``).

- The complete rootless helper service refreshes a due synthetic owner source through its real periodic authority, publishes the rotated bearer without the refresh token to a live mapped worker, and records successful custody evidence before its socket attempt (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:helper-service-refreshes-live-credentials``).

- Service credential-authority fixtures keep every refresh endpoint on loopback, order the first check after parent guard release, clean retained homes during unwinding and bound cancellation before joining (``prob:box:service-credential-spawner-fails-closed-and-pins-its-guards``; ``claim:superlooplane:service-authority-cancellation-prevents-first-check``; ``claim:superlooplane:service-authority-retention-cleans-up-on-panic``).

- Credential regressions exercise the helper publication transaction with foreign client custody and retain the failed-refresh preservation case as its own bounded test (``prob:box:claude-credential-tests-the-mismatch-site-and-splits-the-long-test``; ``test:unit:helper-credential-mismatch-precedes-reservation-publication``; ``test:unit:claude-failed-round-refresh-preserves-worker-file``).

- Native creation carries the selected backend into its private form and credential capability, reconstructs that plan through held configuration and keeps Claude preflight behind the runtime gate (``prob:box:claude-boxed-workers``; ``proto:superlooplane:native-creation-selected-credential-custody``).

- The helper service's credential-authority spawn retains its own directory and executable custody after the parent releases its guards; a replaced-home fixture measures the real authority loop's first healthy and refused evidence, its received client execution and its cancellation (``test:unit:service-credential-authority-retains-custody``).

- The helper transfers only the protected backend's credential client and clock into its authority thread; Claude has a distinct executable role and foreign-only capability maps refuse without ambient fallback (``prob:box:claude-boxed-workers``; ``proto:superlooplane:selected-credential-executable-custody``).

- Owner credential refresh runs behind a provider boundary that keeps the Codex adapter's existing transport and custody, with test stand-ins for staged publication, an owner program's own publication, owner replacement and refusal, and Claude execution remains gated (``prob:box:claude-boxed-workers``; ``proto:superlooplane:owner-credential-provider``).

- The private boxed entry argument form and its refusal boundaries are pinned beside the interface-version constant through the production parser, so an argument-contract change requires a deliberate update of the versioned test (``prob:box:entry-probe-fixtures-follow-the-workspace-version``; ``req:loophome:driver-entry-versioned-form``).

- Boxed resumed paths bind session evidence and resume arguments to the protected backend; Claude quota rejection does not authorize capacity retries, and execution remains gated (``prob:box:claude-boxed-workers``; ``proto:superlooplane:selected-backend-round-evidence``).

- Document the existing executable-byte pins and the verified door step owed by lane-crate rebuilds, including changes outside the helpers' own sources; this chooses the record's documentation option and adds no rebuild-invariance guarantee (``prob:door:runner-template-keyed-on-embedded-bytes``; ``rule:superlooplane:door-rebuild-rollout``).

- Cut-tree acceptance retains its Cargo target and Meson build directories across rounds, resets fixture sources and checks fresh cut identities on every run; configuration compiles publication selectors once (``sec:publicpack:publication-follow-ups``).

- Private boxed entry carries the protected backend explicitly, validates only its configured program and binds the driver selector without changing settings evidence; matching lane and entry versions are required, and Claude launch remains unavailable pending the image, runtime and credential adapters (``prob:box:claude-boxed-workers``; ``sec:loophome:driver-launch``; ``conv:superlooplane:backend-selection-compatibility``).

- Every workspace package depends on the shared `tracing` crate so instrumentation requires no per-package dependency change (``rule:buildcontracts:tiers``).

- Boxed plans bind the selected backend through home and runtime checks, resumed-plan reconstruction and credential publication; Codex refresh skips Claude records. Old runs without a binding must drain and retire before deployment; no backend is inferred for them (``prob:box:claude-boxed-workers``).

- Replay regressions pin malformed historical manifests, unpublished owner and path-class audit context, and drift-path burn refusals before destination writes; existing tests already cover committer and email preservation and audit mapping (``prob:pack:replay-optional-tests``).

- A built-binary cut regression pins existing tag-blob register planning and owner rewriting independently of clean-worktree admission, preserving the complete public tree when source files change after preflight (``prob:pack:register-planning-from-tag-blobs``).

- ACL widening fixtures reach the settings and handed-lock readers with a non-writable mask and pin their named refusals; settings diagnostics describe nominal modes with validated ACLs (``prob:homes:exact-mode-readers-reason-about-the-acl-mask``).

- The compute grammar explicitly retains dash-led run-binary names in the existing `-p` value domain; regressions pin that choice and the stricter check, clippy and test selector matrix (``open:door:compute-run-bin-value-rule``).

- Built-binary cut regressions pin the refusals of an absent and a failed linter, malformed citation JSON and an unknown protocol namespace or version, with measured protocol fixtures, retained failure diagnostics and no publication on refusal (``prob:pack:cut-executable-route-refusals-tested``).

- Read-only request listings expose admitted door judgements, runner observations, call-count provenance, rubric digests and effect walls without requiring review (``prob:door:requests-show-exposes-judgement-fields``).

- Strict schema-five door records retain bounded agent observations, including rubric failures and cleanup probes; the explicit digest-bound rewrite preserves schema-four judgements with null historical observations (``prob:door:request-record-keeps-agent-observations``).

- Request rewrite previews mark each custody file with a digest-bound `changed` flag and name the fixed conversion schema pair explicitly (``prob:door:requests-rewrite-preview-omits-unchanged-files``).

- The README names the built and installed public commands, private helpers and build-only report tool while retaining the source-consumer lockfile policy (``sec:publictools:build``).

- Replay coverage pins refusal before destination writes when a historical manifest lacks its required register declaration, even when TAG declares one; the replay contract states that this optional field has no fallback (``prob:pack:manifest-declares-the-unpublished-register``).

- Door agent isolation documents that credential-free records and logs depend on the configured agent not emitting credentials; captured failed-agent stderr has no credential filter (``prob:door:agent-stderr-tail-credential-filter``).

- Request-list shared-deadline regressions run the plain, pending and state-filtered forms on scoped threads, retaining their independent contention assertions while overlapping the production wait allowances (``rule:superlooplane:requests-list-contention``).

- Real-Git regression coverage verifies repeated no-op pushes through the door stub and handler, including completion, unchanged mirror refs and recorded no-ref outcomes around a push carrying new objects, while the historical mixed-version refusal is not reproduced by this fixture (``proto:superlooplane:registered-ssh-transport``).

- Two-identity request fixtures exercise valid documents and marked requests and assert named registry and state-root owner mismatches for both mapped callers; their ignore reasons name the required UID/GID map and fixture capability (``test:integration:requests-entry-requires-one-account-for-door-and-permission-custody``).

### Fixed

- Anchored lifetime admission revalidates loop-storage after waiting for its receipt lock, refusing custody changes during the wait before returning a lease (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Interrupted-settlement report tests compare measured walls within JSON floating-point precision while keeping every other report field exact, including resumed rounds and older socket evidence (``prob:lanes:settle-report-wall-survives-json-round-trip``).

- Retirement process scans bind driver paths at argument and component boundaries and leave container-name ownership to the labelled container scan, so sibling fixtures and unrelated hub commands do not hold a run by a shared name substring (``prob:lanes:retire-busy-census-binds-to-the-runs-own-processes``).

- Active worker lifetime leases can retain receiver-validated configuration, storage and identity-execution custody while verifying and locking the receipt, without reopening the owner-home paths; reply binding keeps its existing route until its journal and endpoint custody move (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Mail entry requires its exact two-record declaration before descriptor receipt and configuration reads, replaces the consumed stdin socket with the null binding, and preserves descriptor duplication and rights-socket inspection failure causes in mail and worker entry refusals (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Private checkout retains configuration, hashing, Git and its external destination parent across namespace entry, refusing mismatched capabilities before state reads; settled checkpoint, checkout, import and harvest-preview cases distinguish execution through the received tools (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:checkout-entry-retains-custody``).

- Completed driver captures retain advisory driver and monitor state after lock removal, bound to the current step and start marker and never treated as live PID authority (``prob:lanes:claude-lane-finished-state-null-driver``; ``proto:lanelifecycle:completed-step-observation``; ``proto:workermonitor:completed-driver-observation``).

- Harvest recovery carries only its five used capabilities and requires no Git executable; checkpoint restores its relative-home refusal before descriptor receipt and has a focused coverage witness, and the namespace recovery fixture receives its hashing capability from the host (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:harvest-entry-retains-configuration``; ``claim:superlooplane:checkpoint-entry-retains-configuration``).

- Private import marking retains configuration, hashing and Git custody across namespace entry before validating the preserved checkpoint and import journal (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:import-entry-retains-configuration``).

- Private harvest and recovery retain configuration, hashing and Git custody through namespace entry before inspecting collection state; measurement refuses surplus capability declarations and private-report custody has its production test witness (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:harvest-entry-retains-configuration``; ``claim:superlooplane:private-reports-retain-received-custody``).

- Public harvest preserves protected backend refusals before child execution; namespace recovery independently pins its closed Claude gate and unchanged state (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:harvest-selected-worker-state``).

- Private checkpoint entry retains configuration, hashing and Git custody through namespace entry, refusing malformed bundles before checkpoint state reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:checkpoint-entry-retains-configuration``).

- Private credential exercise refuses relative owner homes before reader custody; its digest inventory retires the removed reply comparison instead of pointing at an unrelated line (``proto:superlooplane:credential-exercise-backend``; ``rule:digests:inventory-evidence``).

- Credential measurement no longer requires or transfers an unused Git executable; its exact five-capability frame retains configuration and hashing custody (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``).

- Gated Claude exercise refuses worker files whose bytes differ from the token-only encoding, including duplicate members hidden by JSON value equality (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-credential-exercise-payload``).

- Follow and context readers retain configuration and runs custody across namespace entry; replaced configuration paths supply no input, while raw follow events and bounded context evidence keep their public formats (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Driver reports and retirement lock reads retain operation-bound home, runs, entry and hashing custody across namespace entry; reader tool ownership and exact descriptor frames refuse before state reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-reports-retain-received-custody``).

- Private observed-host reads retain operation-bound configuration custody through namespace entry, preserving the protected reservation and observation checks when the configuration pathname is replaced (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``).

- Private credential measurement retains configuration, reservation and helper-evidence custody across namespace entry and pathname replacement, preserving worker token checks and refusing a disappearing census entry (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``; ``claim:superlooplane:reservation-census-stays-beneath-received-root``).

- Harvest and removal recovery require the protected backend's runtime gate before collection processing, refusing Claude records while activation remains closed (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:harvest-selected-worker-state``).

- Service authority fixtures require a spawning-thread endpoint and refuse before spawning when it is absent; nested guards restore the prior endpoint and a new thread inherits no hook, while production keeps its fixed endpoint (``prob:box:service-credential-test-hook-closes-by-default``; ``claim:superlooplane:service-fixture-endpoint-required``).

- Private harvest and home-layout readers retain configuration and checkpoint-tool capabilities through namespace entry, refusing changed identities and unsafe modes before plan reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``; ``claim:superlooplane:checkpoint-tools-use-received-capabilities``).

- Private worker-identity selection scans reservations, driver directories and protected residue beneath the received runs-root descriptor, retaining record validation and refusing a substituted root or linked record by name (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:reservation-census-stays-beneath-received-root``).

- Helper custody regression checks execute the received runtime through the production namespace receiver and socket service after pathname replacement, authorize a mapped loop peer, retain authority-thread evidence, and complete a loopback refresh through the production spawner beneath the retained home (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:helper-service-executes-received-runtime``; ``claim:superlooplane:service-reservation-key-binds-held-runtime``; ``claim:superlooplane:service-credential-authority-retains-custody``).

- Door-agent exercise probes give verdict and output checks execution headroom beyond cleanup while retaining the separate short timeout and child-reaping bound; delayed real-runner fixtures pin the distinction (``prob:gates:door-modes-runner-probes-red-intermittently-after-the-custody-move``; ``test:unit:agent-probes-separate-semantic-and-timeout-budgets``).

- Native creation previews derive their ordered capability roles from the receiver definitions; the public preview fixture pins the complete required and optional lists, and partial-map exercise fixtures pin their runs-root alias refusal envelope (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The network exercise acceptance executes its reservation-selected native capability through the production namespace entry after pathname replacement, distinguishing the held image-inspection exit from the replacement without claiming a measured box boundary (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper receipt names aliased home and runs roots as the runs-root refusal, and the credential handoff exercises the received client file through the refresh path while refusing a pathname fallback (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Runtime version-query regression derives its expected program version from the workspace package version, retaining its no-state-access assertion across release bumps (``prob:box:runtime-subprocess-contract-follows-the-workspace-version``; ``test:integration:version-and-usage-do-not-open-runtime-state``).

- Credited compute refusal regressions drive the production stub with the 1,000 ms caller budget on early and queued refusals, retaining raw announcement checks, the shared credit cap and exact final diagnostic assertions (``proto:superlooplane:request-lock-wait-credit``).

- Container helpers and the four container-backed exercises receive configuration custody alongside executable custody; registry, ledger and worker settings reads use the held directory despite pathname replacement, and ambient registry overrides refuse before helper pins or private reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``proto:workercontracts:namespace-anchor-handoff``).

- Runtime and native creation read worker settings beneath the received configuration directory, retain the bounded parser and validated ACL checks, and refuse missing or unsafe held files despite substituted settings; isolated host-composer cases require registry-override refusal before pinning (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Compute deadline regressions retain the stronger unextended spawn-budget bound and force store contention on early execution-window refusals, queued deadline expiry and queued adjudicated refusals, keeping requested and registered figures exact while asserting their separate effective bound (``proto:superlooplane:request-lock-wait-credit``).

- Entry-version fixtures derive the current package version and their mismatches at compilation, keeping fresh and resumed probe contracts valid across workspace version bumps (``prob:box:entry-probe-fixtures-follow-the-workspace-version``; ``req:superlooplane:entry-fixture-package-version``).

- The credential refresh fixture joins the production helper bundle and its shared authority-thread handoff, verifying a real refresh exchange with only the client and clock capabilities transferred (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Native creation previews describe the capability bundle instead of retired descriptor flags, and creation receipt keeps owner home and runs root distinct while permitting the letter directory to reuse either (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Native creation selects worker UIDs from its verified configuration and held loop-storage history, preserving receipt and reconciliation checks after configuration or storage path replacement (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Admission-release regression readers consume store-wait progress before their final completion, with both release timings forced through a contended store and the execution and custody assertions retained (``proto:superlooplane:request-lock-wait-credit``).

- A service-to-stub regression pins a contradictory RUN-REPORT beside the unchanged node measurements and its persisted refusal; the spawn-budget assertion retains the original requested bound while the registration and request assertions remain exact (``proto:superlooplane:compute-deadline-and-evidence``; ``proto:superlooplane:request-lock-wait-credit``).

- The completed-command regression consumes sibling-record-wait progress through the production stub before checking the final completion, with a forced progress frame and unchanged execution-count and custody assertions (``proto:superlooplane:request-lock-wait-credit``).

- Estate-referral regressions use the production stub to consume contention progress before asserting the final adjudicated refusal and unchanged custody evidence (``proto:superlooplane:request-lock-wait-credit``).

- Compute replies preserve the exact registered and requested deadline bounds under store contention and name the credited bound separately as `effective_deadline_ms` (``proto:superlooplane:request-lock-wait-credit``).

- Namespace executable checks share their pin and image validation, retain the active operation’s refusal envelope and reject surplus exercise arguments before parsing the private form; the attempt runner and real runtime entry exercise held execution across pathname replacement (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Runtime and native creation plans use the registry and allocation snapshot validated beneath their configuration capability, including settings grants and worker identity selection, without reopening ambient registry paths (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Anchored native creation and runtime verification refuse every ambient registry override, including the canonical registry path, before reading grants or changing custody (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Warm public-cut acceptance leaves its configured Meson tree intact; only the replaced archive is reconfigured, and both setup walls remain reported (``prob:build:cut-acceptance-reconfigures-only-the-changed-tree``; ``proto:publicpack:configure-changed-cut-tree``).

- The container helper pins its credential client and clock before namespace entry and transfers only those held executable capabilities to the refresh thread, which executes them by descriptor (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Native creation reserves and finishes worker mail lifetimes beneath configuration and storage descriptors verified before namespace entry; its bundle retains the letter directory, any already-open rotation source, and credential refresh executables (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Authenticated compute-shaped requests receive their deadline announcement before admission, including route and root-registration refusals, so the stub retains the named refusal through admission and record waits (``prob:door:compute-stub-first-wait-covers-admission``; ``proto:superlooplane:compute-deadline-and-evidence``).

- A valid RUN-REPORT that disagrees with node measurements refuses as `door-compute-report-contradiction`, and a present report with an absent or invalid wall or exit as `door-compute-report-refusal`; replies retain the report's parsed wall and exit in `run_report` beside the node measurements, and missing node evidence keeps `door-compute-evidence-refusal` (``prob:door:run-report-contradiction-is-named-apart-from-missing-evidence``; ``proto:superlooplane:compute-deadline-and-evidence``).

- Door store contention receives bounded, measured deadline credit in the service and matching stub, with cumulative wait frames and reply figures; a two-requester regression pins pending custody and the existing unlocked agent-judgement boundary, without attributing the historical long custody hold to the agent (``prob:door:request-record-lock-released-before-triage``; ``proto:superlooplane:request-lock-wait-credit``).

- Mount, network, door-shape and door-attribution exercises retain their protected reservation’s selected executable and hashing custody through namespace entry, refusing changed records, programs and descriptor declarations (``proto:workercontracts:namespace-anchor-handoff``).

- Runtime preparation carries its configuration, worker storage and executable capabilities across namespace entry, verifies the native lifetime beneath held storage, and previews the bundle without requiring provisioned private paths (``proto:workercontracts:namespace-anchor-handoff``).

- Compute completion retains the node-measured wrapper wall and child user/system CPU even without a RUN-REPORT line; a present contradictory report refuses by name. Schema-six request custody uses the explicit rewrite for older records, preserving their walls with unmeasured CPU. The historical deployed null-wall observation has not been remeasured (``prob:door:door-compute-wrapper-wall-measured``; ``proto:superlooplane:compute-deadline-and-evidence``).

- Release refuses a non-string declared public version in Cargo repositories before check, dry-run or apply can proceed, retaining destination refs, objects and worktree (``prob:pack:release-refuses-a-non-string-public-version``).

- Container helpers retain host-verified entry, Podman and hashing file custody across namespace entry and execute protected-plan hashes, attempts and cleanup through held descriptors; the bundle refuses missing, substituted and excess descriptors and changed declarations (``proto:workercontracts:namespace-anchor-handoff``).

- Route documentation distinguishes the door registration route, the registry-only check-mode finding and every empty artifact rendered for retired routes (``proto:superlooplane:door-node-registration``; ``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- Worker custody entry keeps consumed stdin bound to the null device and refuses non-UTF-8 launcher paths without lossy conversion; capability duplication failures name their system cause as `anchor-io` (``proto:workercontracts:namespace-anchor-handoff``).

- The two-account mail fixture leaves coordinator verification to the rootless worker acceptance, which checks unchanged verification and missing-lock refusal through the production descriptor handoff instead of an obsolete private invocation (``proto:workercontracts:namespace-anchor-handoff``).

- Worker-run birth and retirement and native lane retirement carry configuration, storage and executable custody through namespace entry and identity children; the runner retains only declared descriptors, and native retirement preserves its bounded command handling (``proto:workercontracts:namespace-anchor-handoff``).

- Cut and replay projection batch blob reads, object hashing and index updates per tree instead of spawning Git per file, preserving binary contents, path spelling, symlinks and modes; real Git traces pin the bounded process counts (``prob:pack:replay-projection-spawns-git-per-file``).

- Interrupted request rewrites can renew their helper snapshot after a concurrent helper arrival, requiring a new preview digest while retaining the original custody plan and preserving unrelated helper requests (``alg:superlooplane:request-schema-rewrite``).

- Anchor refusals retain the caller operation, failed custody or transport check and configuration parser cause; writable ancestors refuse as mode failures and system failures retain their errno (``req:workercontracts:namespace-anchor-refusals``).

- Mail startup carries verified configuration and executable descriptors through namespace entry, reads settings, ledger and registry beneath the held configuration, and preserves named capability and identity-drop refusals; scan-time configuration reads retain that anchor (``req:workercontracts:namespace-anchor-acceptance``).

- Host rubric and sign-in source walks validate the initial UID map and reject unrelated nobody ownership, including sticky ancestors, while retaining explicit owner and loop grants (``req:workercontracts:namespace-anchor-authority``).

- Citation planning bounds each linter invocation and both output streams to 120 seconds, killing its process group and reaping its leader on timeout while retaining diagnostics and refusing before publication; real-process and built-binary regressions pin cleanup and unchanged destinations (``prob:pack:cut-linter-invocation-time-bound``).

- Door agent calls give Codex sibling private configuration and temporary directories, keeping its home outside the child temporary root and removing both after reaping (``prob:door:door-agent-codex-home-outside-temp``).

- Cuts refuse a selected owner snapshot carrying an `unpublished` field when the publication manifest has no register declaration, preventing unaudited register publication and dangling snapshot references (``prob:pack:manifest-declares-the-unpublished-register``).

- Registered state-root ownership refusals name the state root instead of the loop registry; mapped request fixtures assert the custody root and both uids (``prob:door:two-uid-fixtures-assert-owner-mismatch``).

- Runtime rubric admission compares the effective uid with the real entered uid, restoring refusal of entries that change only the effective uid (``proto:superlooplane:bounded-rubric-judgement``).

- Custody readers compare the complete mode with the named read/search ACL mask for private files, the registry, loop tiers, settings and transferred configuration locks, refusing ordinary group grants and widened masks; fixtures also preserve the ledger readers’ ACL contract (``prob:homes:exact-mode-readers-reason-about-the-acl-mask``).

- The route-rendering contract names the owner-side Codex home as the destination for door-only loops and distinguishes it from the canonical credential source (``prob:homes:render-routes-codex-home-from-custody``).

- Standalone route rendering refuses an absent loop before publication while retaining empty node sections for retired routes; fixtures pin missing-key refusal without active routes and preserve home contents across registry refusals and route reactivation (``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- Codex reconciliation collapses identical complete generated SSH headers to one, preserves owner comments and refuses conflicting or incomplete duplicate headers (``prob:homes:reconciled-ssh-config-header-written-once``).

- Codex home preparation and reconciliation select the loop’s active registry routes when no nodes are named, while an explicit node list remains the selection override (``prob:homes:codex-reconcile-resolves-nodes-from-routes-row``).

- Sign-in home checks resolve the loop’s active registry rows when no nodes are named, preserving explicit subsets and reporting registry failures without changing the home (``prob:homes:check-signin-home-resolves-active-registry-rows``).

- Sign-in homes prepare and reconcile an empty node section when the loop has no active routes, report the observation, and retain credentials, worker-key bindings and unrelated SSH stanzas (``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- The empty-route home fixture declares its executable dependency in the build ledger, including the shifted call-site identities (``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- Registry path admission and worker-identity refusal text share component-fault classification, preserving dot-component precedence and accepted path forms (``prob:homes:routes-worker-form-shares-path-component-predicate``).

- The shared route-path classification test carries the inventory label derived from its function name (``prob:homes:routes-worker-form-shares-path-component-predicate``).

- A registered Git receive can complete beside its box’s running compute request while same-class requests and other operations retain bounded admission exclusion (``rule:superlooplane:door-request-admission``).

- Deferred list rewrites remove complete dotted stale-family and singleton assignments; rendered TOML is parsed before replacement, so active dotted-singleton duplication refuses without changing the source (``prob:linter:deferred-writer-parses-its-output-before-replacing``; ``prob:linter:deferred-mode-rewrite-keeps-a-stale-catalogued-table``).

- Folder-matrix checks and writes ignore cell padding and valid table delimiter layout while preserving exact cell content, row identity, order and count; equivalent layouts remain unchanged, while a tab anywhere in a delimiter row and an empty delimiter cell remain stale, matching the formatter’s space-only delimiter grammar (``prob:linter:matrix-comparison-normalises-cell-layout``).

- Claim projections stop the introductory gloss at the first trimmed level-one rustdoc heading, leaving section headings and bodies out of test-index and folder-matrix cells (``prob:linter:claim-extractor-stops-at-rustdoc-sections``).

- Request-list contention refusals add listing-level elapsed time; regressions pin the shared deadline at a contended second acquisition and include helper state in read-only snapshots (``rule:superlooplane:requests-list-contention``).

- The door rubric check admits the caller’s service uid alongside root and the loop uid at install and runtime; a mapped non-root service fixture verifies distinct loop custody and foreign-owner refusal (``prob:door:door-rubric-custody-admits-service-uid``; ``proto:superlooplane:bounded-rubric-judgement``).

- The shared request reader rejects upload bounds and output counts on preflight refusal records (``conv:superlooplane:door-transport-compatibility``).

- Tools packs classify their generated provenance as an optional exact publication member; a fresh pack audit against the supplied 41-entry estate register measures zero occurrences and zero owed debt (``prob:pack:tools-tree-burn-register-matches``).

## [0.4.1] - 2026-11-06

### Changed

- Regression coverage verifies that 24 repeated learned door decisions retain their adjudicated allow and execute once per request without calling an agent; attribution of the historical excess wall remains open (``prob:door:learned-hit-judgement-wall-after-bite-6``).

### Fixed

- The region-reader catalogue classifies a terminal `.j2` template by its inner file kind and treats a `LICENSE-AGPL_3_0` licence notice as opaque (``prob:linter:region-reader-catalogue-gains-j2-and-the-agpl-text``).

- To-do derivation excludes the header's ownership citation from the summary and name, preserves it through label insertion and repair, and leaves summary citations unchanged (``prob:linter:todo-derivation-keeps-the-ownership-slot``).

- Reach reconciliation supplies self and the crate-bearing root without declared rows, refuses redundant structural-root rows, and preserves explicit reach to a crateless root (``prob:linter:reach-reconciliation-supplies-the-structural-root-like-self``).

- Catalogued burn policies accept exact ABNF exclusions on their owner surfaces, retain derived share exclusions, and report the paths excluded from both prose and code censuses (``prob:linter:catalogued-burn-families-accept-an-exclude-relation``).

- Pack verification declares and probes its unzip prerequisite, refusing ``unzip_unavailable`` before extraction when it cannot run; deployment names the prerequisite as a requirement independent of build placement (``prob:pack:stage-verify-declares-its-extraction-dependency``).

- List rewrites retain active family containers, remove stale singleton and family entries beside deferred bytes, and canonicalize inline owners without duplicate keys in either mode; malformed rewrite sources refuse without writes (``prob:linter:deferred-mode-rewrite-keeps-a-stale-catalogued-table``).

- Nested corpus roots require tracked ownership metadata before loading their snapshot, and a failed tracked-file census names its own refusal (``prob:linter:nested-root-with-no-tracked-paths-is-accepted-vacuously``).

- Publication tests compare author, committer and tagger instants as epoch seconds, also checking stored offsets and the reported date across Git date renderings (``prob:pack:cut-acceptance-compares-epoch-seconds``).

- Sign-in home tests pin the check-mode registry user refusal without writes and bind reversed host selections to each worker stanza (``prob:homes:registry-node-user-refusal-check-mode-test``; ``prob:homes:codex-home-hosts-test-pins-stanza``).

- Request listings share one bounded lock-acquisition deadline across reads and name the elapsed wait and retry remedy on contention expiry, without changing request records (``rule:superlooplane:requests-list-contention``).

- The door attribution probe shares a 55-second budget from its main function across calls and retries, caps stub calls at 35 seconds and receive at 15 seconds within the remaining budget, and names top-level timeouts while leaving missing observations unmeasured (``proto:superlooplane:registered-ssh-transport``).

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

[Unreleased]: https://github.com/coraxloop/superloop-tools/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/coraxloop/superloop-tools/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/coraxloop/superloop-tools/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/coraxloop/superloop-tools/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/coraxloop/superloop-tools/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/coraxloop/superloop-tools/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/coraxloop/superloop-tools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/coraxloop/superloop-tools/releases/tag/v0.1.0
