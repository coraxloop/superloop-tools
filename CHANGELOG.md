# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `superloop-credential-custody` for strict parameter records, sealed-length observations and calibration identity comparisons. Meson installs it with the other public commands and its build record, and nothing calls it yet; a rehearsal needs the operator's separate root-owned installation with its reviewed parser and parameters. Each observation requires an immutable caller-owned parameter file and private sealed directories with protected ancestry before any probe or parser runs, so rehearsal operators prepare those modes explicitly. Format discovery is its own `format-discover` command with a small tagged record and an `observed` receipt, so no completion is asserted for a campaign that has not run (``guide:credentialcustody:observations``).

- Prepare an unselected node-executor library for exact commands in a reservation-declared workspace, with a retained cwd, explicit environment, one sequence deadline and node-measured outcomes. It provisions nothing and writes no request record; no installed command or door route selects it, so deployment needs no rewrite or restart. Later callers still require the workspace readers before publishing effects (``proto:superlooplane:workspace-node-executor``; ``prob:door:w2b-node-executor-runs-in-the-declared-workspace``).

- Add dedicated private door receivers that retain the entry and identity program and enter the registered loop with a minimal environment. No door caller or installed generation selects them yet: ordinary entry, running doors and direct triage keep their existing behavior. This preparation needs no hold, per-loop refresh or restart. A manually invoked private word requires its seven-role rights frame and refuses a missing socket or mismatched image before entering the loop (``claim:loophome:door-receiver-retains-entry-and-isolates-consumer``).

- The lane tools now read the workspace stage's records before any program writes them: an optional workspace grant in a protected run plan, retained through the pinned read, round resume, door re-pinning and interrupted recovery; schema-seven compute-workspace request records, including a sequence whose overall deadline expired between steps; and schema-six preflight refusals named `door-workspace-unregistered`, `door-workspace-context-differs` or `door-workspace-protocol-refusal`, or the shared `door-caller-authority-refusal` and `door-review-compute-refusal`, which carry at most the first 65,536 raw bytes of the refused frame, marked truncated when the frame was longer. A build carrying an earlier form of these readers refuses such a truncated prefix and this one refuses that form's longer evidence; nothing writes either yet, so no record needs a rewrite, and a later writer of these refusals needs this release deployed first. Legacy `door-request-refusal` and `door-changed-ref-refusal` records still admit their original bounded raw arguments even when those arguments resemble the new tagged form; existing run listings remain readable. Only an explicit launch declaration, below, writes the grant; nothing writes the request forms yet and the door selects no workspace operation, so existing runs, reservations, request records, door modes and node payloads behave as before. The request reader's refusal of an unsupported schema now reads `schema must equal 6 or 7`, and the learned-index status and rebuild messages name schema seven beside six; `requests rewrite` and `requests rebuild-index` leave schema-seven records unconverted. Deploy with no rewrite and no service step; once a later release writes a workspace declaration or record, the loop cannot roll back below this release (``proto:superlooplane:workspace-readers``; ``proto:executecommand:compute-workspace``; ``prob:door:w1-workspace-contracts-and-readers-land-first``).

- Launch accepts `--compute-workspace JSON` for a new run: the dry run shows the declared grant and its digest, and the apply, repeating the declaration with `--expect-digest`, records the grant once in the run's protected reservation and plan before the home is built. The grant is immutable: preparation retries, later rounds, door re-pinning and recovery keep it, and a different grant needs a new run. Its baseline environment is shown to workers, previews, records and the judge, so the declaration must acknowledge it as public, and duplicate names and recognizable credential names or values refuse without echoing them; that recognition is limited and is no secret detector. Duplicate resource names in the grant refuse rather than keeping the last value. The run's mail birth is reserved before its preparing reservation is published, as for an undeclared launch, so an interrupted preparation never names an unreserved birth. A declaration also requires the loop's `workers.toml` to publish `workspace_policy = { quick_policy_digest = "HEX", blacklist_digest = "HEX" }` matching the grant. Without the argument and the table nothing changes: undeclared launches write the same reservation and plan bytes, and no workspace execution route opens; the one change they see is which refusal comes first, since a fresh launch reads an existing reservation before probing the entry program, box and proxy, so a malformed one reports its `uid-table` read refusal first. The workspace readers above are the floor for any declared run. Before any loop's `workers.toml` carries `workspace_policy`, install this release's `superloop`, `worker-run` and `superloop-lane`, refresh each loop's door copy with `install-door` and restart its door service, and let every run whose boxed helper started under an earlier release end: each of these validates the settings, and an earlier one refuses the table as `unknown-setting`. To roll back below this release, first remove `workspace_policy` from every loop's `workers.toml`; keep the reservations of declared runs, which the readers still resume (``proto:superlooplane:workspace-launch-declaration``).

- Inbound mail binding and verification can retain received custody through a selected library session, with distinct operations, unchanged pin records and read-only verification. The selected library session retains the existing pin record format (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

### Changed

- Door request writers now wait in arrival order within one process, including unnamed mode writes and concurrent phases of the same request. A retry keeps its place; expiration, refusal and unwinding remove it. Newer writers in that process cannot repeatedly overtake an older waiter. Readers and other processes still contend through the operating system lock; transaction work, acquisition deadlines, wait credit and admission remain unchanged. Commands use the new ordering from installation; a door needs its own refresh and restart after in-flight requests finish. Unnamed exclusive waits, such as a request's first mode check, now also appear in the existing `door-request-lock` wait lines with a null request identifier. No configuration or record migration is needed (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Door request projection computes each record’s lookup key once instead of hashing it again for every candidate. The first matching row and the complete projected record stay unchanged; no lock, helper call or publication moves. This reduces record-transaction work and shortens holds as collections grow. Existing doors gain the improvement after their own refresh and restart; finish in-flight requests first. No record migration or operator configuration change is needed (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Door request writers now report one bounded `door-request-lock` release line with the operation, request identifier when known, acquisition wait, hold time and named transaction phases. This diagnoses queue stalls; lock scope, ordering and deadlines are unchanged. Commands that take the exclusive lock in their own process, such as the owner's changing `requests` commands and retirement, print the line on their own stderr as soon as the new binary is installed; existing door copies show the lines only after their per-loop refresh and restart; let in-flight requests finish first. Request contents and filesystem paths are not included (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Prepare the library contract for three door entry operations, with fixed capability roles and a sealed, bounded invocation. No production caller or installed command changes; no new operator preparation is required (``claim:loophome:door-frame-fixes-local-entry-custody``).

- Mail binding’s release sentinel now follows the test-only admission hook itself, and acceptance pins override refusal before plan reads and refusal of a changed prior binding. Production command behavior and record formats are unchanged (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- `bind-mail` and both `launch … --round` modes now retain received configuration, storage, identity-program, journal and run custody through binding or read-only verification. Install with neither command in flight, then rerun an identical binding and a settled run’s dry resume. The reply entry’s owner, mode, ACL and link requirements now apply to these commands too; provisioner-written homes and recorded bindings need no migration. Unset `ENTER_LOOP_REGISTRY`, even an empty or canonical value: `bind-mail` newly refuses it before plan reads, while resume refuses after its existing plan and reservation reads. A process crossing the install refuses `anchor-missing` with its selected operation or `verified-prefix` before publication or preparation; rerun it afterwards. Running containers are unchanged until their next resume (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:inbound-binding-retains-custody``).

### Fixed

- Clarify launch interruption on each side of reservation publication: only a published reservation lets retirement name its reserved mail birth. Pin the production ordering-helper call and distinguish legacy refusal evidence from workspace-tagged evidence; no launch or reader behavior changes (``proto:superlooplane:workspace-launch-declaration``; ``test:unit:workspace-private-make-uses-birth-publication-boundary``).

- The `launch LOOP RUN --round STEP` usage now says its budget is per round, defaults to 3,600 seconds and is not inherited from dispatch. Pass `--budget SECONDS` on each resumed launch that needs a longer allowance; command behavior and existing runs are unchanged (``proto:superlooplane:resumed-letter-placement``).

- The correspondence publication/deadline fixture's partial-failure poll now starts with fresh alpha content, so its round ends once both hosts have been polled, under a 120-second hang bound instead of the fixture's 400 ms round. Its slow transport gets a five-second feed deadline, below the stub's ten-second sleep, so it reaches and logs its call before the timeout. Both cases check the call log after the client exits. The partial-failure warning and cursor-isolation assertions remain; installed correspondence behavior is unchanged (``test:integration:failure-isolation-admin-publication-and-deadlines``).

- A refused resumed-round request publication now removes the temporary it created and preserves an occupied destination; the preview’s `helper_preflight.checked` now reads `saved runtime environment and unoccupied final round-request name`, claiming nothing about the later inspector’s temporary. This does not yet roll back a published preparing reservation (``test:unit:round-request-failure-removes-only-its-temporary``).

- The preserved-checkout fixture disables automatic Git maintenance in both repositories before snapshotting the pushed objects, so a transient maintenance lock cannot change its verified file list (``test:unit:checkout-clones-only-verified-preserved-objects``).

- The boxed first dispatch tells the worker to carry out the brief and report as it asks. Install `superloop-lane` with no launch in flight: the launcher, its container helper and the box's prompt client are that one program, so only a launch that crosses the install can pair builds that disagree on that exact prompt, and the prompt client then refuses with `round prompt does not name a mail delivery and step` before it reaches the helper (``proto:superlooplane:container-attempt-completion``).

- A resumed launch, preview or apply, no longer reads the round before it: a dispatch `--letter` file moved, deleted or edited after the dispatch, a rotated run’s absent home `brief.txt`, or a previous step’s absent retained mail no longer refuses the next round, which needs only its own bound retained `mail-STEP.txt`. The preview’s `helper_preflight.not_checked` now reads `busy lease and scope admission before publication`, `every step after the preparing reservation is published` and `launch-time descriptor transfer and intervening changes` (``test:crate:built-helper-resume-retains-mail-custody``).

- After vendor execution, unparseable answers from the entered door-agent runner now report stdout and stderr byte counts and format classes, the parsing stage and, when stdout was parsed, content-free completed-turn, failed-turn and error-event counts, without recording answer text. An invalid-output refusal keeps the bounded stderr tail and first line only for a complete, uncut plain-text stream with no JSON object line; usage-limit text remains visible, while truncated or mixed answer streams are blanked. The vendor arguments and verdict policy are unchanged. Refresh and restart each installed door copy to receive these diagnostics; direct triage receives them with the global tools install. This does not establish the cause of an existing invalid-output refusal (``prob:door:entered-agent-runner-reads-the-answer-the-vendor-gave``).

- A resumed launch now checks its saved client environment (`launch/runtime.env`) and its round request (the step’s delivery binding, and `round-launch-STEP.json` not already present) in the preview and again before it changes the run, so `saved client environment is invalid`, `saved client environment has foreign ownership or protection`, `round request lacks its delivery binding` and `round-launch-STEP.json already exists` now refuse with the reservation still settled; the preview lists the new check under `helper_preflight.checked`. The changing launch now verifies retained mail exactly as its preview does and no longer rewrites it: where the retained `mail-STEP.txt` no longer matches its delivery, the apply refuses with `retained evidence differs from verified delivery` instead of quietly restoring it, and rerunning the identical `bind-mail` for that step restores changed bytes from the journal before the next preview. Compatibility: no command, reservation or request format changes; a refusal after the round is published can still strand it until the separate rollback work lands (``test:unit:round-inspection-validates-before-publication``; ``test:integration:resumed-launch-validates-before-reconciliation``; ``test:crate:built-helper-resume-retains-mail-custody``).

- A resumed boxed round now reads its retained mail through the loop-owned run directory instead of requiring that directory to belong to the host. Both `launch … --round STEP --dry-run` and the changing launch now check that mail binding and the helper’s plan and arguments before a round is published, so a refusal there leaves the reservation settled and the round name unused; the preview lists what it checked under `helper_preflight.checked` and the launch-time steps it cannot guarantee under `helper_preflight.not_checked`. Compatibility: initial letters and initial rotation sources keep their existing custody rules; settled runs need no migration and running helpers keep their loaded code. Install with no resume launch in flight, then rerun the resumed dry run, read its `checked` and `not_checked` fields, and launch. Installing this does not repair a round already stranded by the earlier refusal: keep that run’s reservation, retained mail and evidence in place for the separate recovery step (``test:unit:retained-round-mail-requires-exact-source-and-binding``; ``test:crate:built-helper-resume-retains-mail-custody``).

- The suspended-driver recovery fixture names its mode and clock settings in failed assertions, including an unexpected resume record. Its thirteen cases and production behavior are unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- The door attribution fixture tolerates scheduling stalls while waiting for its four probe connections and gives real fixture operations a generous hang bound. A controlled delay pins the accept bound without sleeping; the separate deadline test still checks production budgets, and installed programs are unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- The door-agent budget fixture drives deadline selection with a controlled clock and checks real descendant cleanup after an observed readiness event. CPU stalls no longer consume its deliberately short logical timeout. Live exercise and door-call deadlines are unchanged, and installed programs behave as before (``prob:gates:load-sensitive-tests-made-deterministic``; ``test:unit:agent-probes-separate-semantic-and-timeout-budgets``).

- The door effect-order fixture now forces a store-lock progress frame before reading the final reply, with a generous hang bound. Its effect, queue and label assertions no longer depend on the first frame being final; production behavior is unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- A boxed helper whose setup fails after it binds its first socket, whose credential thread cannot start, or that panics while serving now cancels and joins the threads it started and removes the sockets it bound, so such a failure no longer leaves the run’s request or control socket behind or its control thread running. A socket whose name was replaced during the run is left in place, and the helper then exits with `replacement socket retained` even if the request succeeded; a socket whose identity cannot be read back after bind is left in place with an error saying `retain its slot`. Compatibility: successful runs keep their protocol and result. When a request refuses and the credential thread also fails, the request’s error is now the reported one, where 0.4.2 reported the thread’s, and thread and cleanup failures follow it after `; cleanup`; with no request error a credential-thread failure still comes first. A panicking helper now waits, as a refused request already did, for an in-flight credential pass, and any of these exits can wait up to the control reader’s existing five-second timeout while a control peer stays silent. A helper running at the install keeps its old code until its run ends (``test:unit:helper-service-setup-failures-clean-owned-sockets``; ``test:unit:helper-service-cleanup-joins-an-accepted-control-read``; ``test:unit:helper-service-cleanup-retains-replacement-sockets``).

- Worker allocation blocks can no longer contain namespace uid 65534. **Before installing**, inspect every worker range in the allocation ledger. A containing block refuses with `worker uids include reserved uid 65534 for loop: NAME`: ordinary entry fails for every loop, permission triage denies affected routed calls, and driver launch, mail provisioning and worker retirement, replacement allocation and mail migration cutover refuse when they read the whole ledger. An affected estate must migrate or retire the allocated identities and their owned data, then correct its ledger **using its current tools, before installing this version**. Keep the original records for that migration; nothing is renumbered or rewritten in place. Automatic allocation now skips 65534. Homes whose blocks exclude it need no action (``prob:homes:worker-blocks-exclude-the-overflow-uid``).

- Door installation now exposes `agent_program_admission` at the top level of preview and apply output, separating `admitted`, `refused` and `unmeasured` from the legacy execute-bit observation. No metadata field authorizes runtime execution, and no installed generation changes shape. Validation-only runner configuration cannot execute without a registry loop uid; the ordinary configured door route is unchanged (``reg:superlooplane:door-agent-metadata``).

- Door executable metadata keeps its existing `usable` permission observation separate from the new `admitted` custody verdict. The door-agent exercise creates its protected probe programs beneath the effective account's home, independently of caller-controlled `HOME` and `TMPDIR` (``reg:superlooplane:door-agent-metadata``; ``test:unit:door-agent-case-uses-production-handler-and-names-unmeasured-vendor``).

- Door rubric checks no longer admit the host's numeric uid as a subordinate owner, and runtime checks the registry's loop uid. Door and direct-triage agent calls now refuse a linked, foreign-owned, writable or set-id vendor program (including unsafe ancestors) as `door-agent-program-custody`; configure the resolved protected target. `install-door LOOP --dry-run` reports `executable_status.admitted` and its refusal without running the vendor. The shared program changes direct triage at the global install; refresh each door's installed generation and restart its service to take the fix there. Existing generation and request record formats need no migration (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- `superloop-lane door-sign-in` again accepts a private home carrying the mail system's search-only entry (mode 0710), which it refused with `door-sign-in-private-home-owner-mode` on every mail-provisioned loop; any other access ACL still refuses, and the dry run and placement are otherwise unchanged (``test:integration:door-sign-in-receiver-admits-only-private-home-traversal-acl``).

- The release suite now exercises the workspace producer’s refusal of a Cargo configuration changed during compilation, which keeps the earlier published binaries and record, and its rebuild when a Cargo-home configuration is created (``test:integration:test-release-producer-dependencies``). The producer also depends on the checkout's ancestor directories and the Cargo home, so adding or removing an entry directly in one of them can rerun Cargo at a later build even when no source changed.

- The release build’s compiler-input recorder now treats a string include as one path and records missing included configurations without adding a refusal of its own; Cargo still decides whether the build requires them (``test:integration:test-release-configuration-includes``).

- The release suite (`meson test --suite release`) now refuses a build whose record names a compiler or wrapper override, even an empty one: `RUSTC`, `RUSTC_WRAPPER` or `RUSTC_WORKSPACE_WRAPPER`, their `CARGO_BUILD_` forms, or `rustc`, `rustc-wrapper` or `rustc-workspace-wrapper` under `[build]` in a Cargo configuration the build read, a compiler cache wrapper included. Unset the variable or remove the key, then remove the build directory's `workspace-build.json` before building. Compiler flags are now read with each Cargo source's own token boundaries, so a unit separator inside plain `RUSTFLAGS` no longer hides `--cfg test`, and no path is parsed as shell syntax (``test:integration:test-release-flag-sources``).

- Request-schema conversion (`superloop-lane requests rewrite`) now refuses a custody file whose converted form exceeds the 8 MiB run-file limit in both the dry run and the apply, before writing custody or a pending journal; the apply previously wrote the pending journal and the custody files before it and then stopped at that file, leaving a conversion that every resume refused. The refusal (`requests-rewrite-refusal`) names the custody file, its converted bytes and the limit, and exactly 8 MiB is accepted. A conversion an earlier build left stopped at such a file now refuses before any further write and cannot complete with this release; keep its journal and custody files as they are (``test:unit:rewrite-checks-converted-custody-byte-bound-before-publication``).

- The release suite (`meson test --suite release`) now refuses unless the build directory's `workspace-build.json`, written by the workspace build itself, lists exactly the scanned binaries with their sizes and SHA-256 digests and records no `--test`, `--cfg test` or `--cfg=test` in the compiler-flag variables or the Cargo configuration that build read; Python optimization settings no longer remove its checks, and Meson's timeout now also stops the compiler processes the test starts. A retained build directory writes the record at its first build after this change; after changing compiler flags, wrappers or the toolchain for a retained build directory, remove its `workspace-build.json` before building so that the workspace build runs again and records them. The record stays in the build directory and is not installed (``test:integration:test-release-build-record``; ``test:integration:test-release-admission``).

- Request-schema conversion (`superloop-lane requests rewrite`) now refuses a helper collection whose commit input exceeds the helper's 64 MiB input cap in both the dry run and the apply, before writing custody or a pending journal, even when applying an older preview; the refusal names the collection, the measured bytes and the cap (``test:unit:rewrite-refuses-helper-input-before-publication``).

- Request-schema conversion (`superloop-lane requests rewrite`) now admits plans up to 128 MiB, up from 32 MiB, so loops with larger retired request stores can preview and apply their conversion; a loop whose preview was refused with `plan exceeds bound` reruns the dry run, and oversized-plan refusals now report the measured bytes and bound. Record shapes and the door and helper readers are unchanged (``test:unit:rewrite-converts-plan-above-old-bound``; ``test:unit:rewrite-plan-bound-reports-measured-bytes``).

- The generic repository's public pack verifies: its root documentation partition owns the generated ``docs/public-pack-provenance.toml``, and its publication manifest classifies that member with a reserved exact row and declares the unpublished-label register through `public.unpublished`, which the public-set readers released in 0.4.2 accept. With those declarations, the pack and linter built for this closure passed all eight verification checks against the supplied 41-entry external register with zero occurrences (``prob:pack:pack-verify-burn-evidence-rule``).

## [0.4.2] - 2026-11-12

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

- Publication manifests declare the unpublished-label register destination through `public.unpublished`; cuts generate it there and bind the owner snapshot to it, refusing excluded-definition citations without a declaration and unsafe or conflicting destinations; readers built before this release (the linter, the build-sync census and the pack) refuse the field as unknown, so a tree that declares it is read by this release's linter, build-sync and pack, installed together (``prob:pack:manifest-declares-the-unpublished-register``).

- The contributing guide gives slice workers the branch workflow, source declarations, node verification bar and working-step report contract (``guide:contributing:superloop-tools``).

### Changed

- Close the helper-authority cancellation record after its activation, scope and panic regressions, retaining the release compatibility statement beside the protocol (``prob:box:helper-service-cancels-when-its-authority-thread-exits``).

- Pin fixture-admission absence in every workspace release artifact with a current unit-test positive control and an empty-set refusal (``test:integration:test-release-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Reply binding now has an actual-package acceptance through the public binding body, including vector construction, rights handoff, result comparison, reservation publication and an identical retry. A fixture host-root seam leaves the normal launcher’s root walk and executable selection unchanged; no deployment action or command syntax change is required (``claim:superlooplane:reply-entry-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Retain the fixture enclosure when a watchdog collects output after an unconfirmed namespace stop, so consuming the child handle cannot authorize removal during unwind (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-unconfirmed-stop-retains-enclosure``).

- Pin the Claude fixture transaction's bound-evidence read-back, dead-helper exclusion and authority panic cancellation, and retain uncertain source custody and child output on fixture failures; production behavior is unchanged (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``prob:box:helper-service-cancels-when-its-authority-thread-exits``; ``test:unit:claude-fixture-periodic-dead-helper``; ``test:unit:helper-authority-panic-cancels-service``; ``test:unit:claude-fixture-move-rechecks-custody-before-drop``; ``test:unit:claude-fixture-watchdog-retains-child-output``).

- The inbox watcher readiness problem is closed with its record in the hook package's README: a loop takes the fix by restarting its inbox watcher from the updated recipe with the same command, and a watcher that is not restarted keeps working on its previous recipe (``prob:hooks:inbox-recipe-resets-its-readiness-before-each-watcher-launch``).

- Exercise the test-only Claude periodic authority over a live fixture reservation, including event-controlled evidence and configuration scope loss, mapped worker publication and exact enclosing-storage inventory; production remains gated (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-periodic-publication``).

- The anchored mail service's refusal sidecar names an entry refusal by its anchor class in `code` (`anchor-declaration`, `anchor-missing`, `anchor-transport`, `anchor-owner`, `anchor-mode`, `anchor-kind`, `anchor-identity`, `anchor-escape`, `anchor-exec`, `anchor-io` or `anchor-uid-map`) and any other entry refusal as `entry-refusal`, where it wrote `io-failure`. Such a sidecar is written only when the service's own configuration custody fails before a letter's delivery is accepted and holds again when the refusal is projected, because a lasting fault stops the service at its next scan instead; filesystem failures keep `io-failure`, the `reason` text is unchanged, the letter stays refused until its sender withdraws or changes it, 0.4.1 wrote no entry refusal, and nothing in this tree reads the field. The reply-session library, which has no production caller, now receives its five mail capabilities into an owned bundle validated before lifetime repair, rechecks the live outbox at binding and inside the journal verifier, and revalidates journal custody after the admission wait; its direct lifetime guard refuses a registry override in the entry form, exit 2. The reply command, its pathname journal admission and the held caller switches are unchanged (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``test:unit:mail-service-records-anchor-refusal-code``; ``test:unit:mail-entry-refusal-code-uses-a-closed-allowlist``).

- Keep a replacement enclosure intact when mapped fixture cleanup fails during host drop, disarming automatic pathname-recursive removal before fallible cleanup (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-cleanup-failure-keeps-replacement``).

- Check the mapped fixture cleanup's current-directory identity against its held enclosure before removal, retaining stderr on refusal and measuring renamed-directory custody (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-cleanup-checks-mapped-enclosing-identity``).

- Make the private credential-authority wait injectable for event-driven pass boundaries, retaining the production thirty-second cancellable interval (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-authority-waits-for-pass-release``).

- Inventory fixture cleanup reports metadata-query errors when checking that the parent-owned root and marker remain, retaining the directory and regular-file checks (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The closed dead-pid fixture record now preserves the dated measurement of recurring collision windows at the node’s pid churn (``prob:gates:fixtures-name-a-dead-process-by-a-number-no-process-can-hold``).

- Exercise one test-only Claude helper round through held namespace custody, with mapped worker publication and enclosing-storage cleanup controls; production remains gated (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-admitted-round``).

- The anchored reply session refuses ambient registry overrides as entry declarations rather than backing-store I/O, converging on mail exit 2 before the command migration (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Fixture admissions validate actual helper-thread inputs and exact evidence destinations before exposing a binding, retain cleanup with the host, and reject noncanonical digests and password-database account roots (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Helper unit tests carry opaque fixture scope through consumer refusals and one-shot periodic custody, with root creation and held-anchor identity checks; production retains its closed Claude gate (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- The inventory fixture removes its home root only from the parent that created it, and only after namespace cleanup has removed the mapped children; that cleanup retains the root and marker, its phases admit only a real directory directly beneath the temporary directory, and metadata failures are reported instead of treated as absence (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Bounded fixture output always gives the child the null device as standard input, as the replaced `Command::output` call did by default, instead of the test's own input, and retains both output streams in timeout diagnostics, with a non-null input control (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The reply-session acceptance honours matching and nonmatching libtest filters, exact and skipped selections, listing, quiet and colour flags and libtest's `--option=value` spellings without accidentally running a filtered fixture (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper authority carries the same borrowed program binding through evidence construction and publication, retaining production evidence bytes and the compiled census boundary while custody tests pass an explicit runtime admission (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:helper-runtime-admission``).

- Dead-process fixtures use distinct positive process IDs above Linux’s PID ceiling, with a live-lock control, so PID counter wrap cannot turn a recovery fixture into a live-owner refusal (``prob:gates:fixtures-name-a-dead-process-by-a-number-no-process-can-hold``; ``test:unit:dead-lock-fixture-pid-exceeds-kernel-limit-and-live-lock-refuses``).

- The helper runtime-admission protocol uses the lane manual's bold protocol-statement form, retaining its label and contract (``proto:superlooplane:helper-runtime-admission``).

- Helper-service custody alone constructs and consumes the admission thread token; program binding is borrowed from the admission without producing another owned proof (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Helper-service refusal tests call the admitted production cores with the gate explicitly; the six test-only forwarding wrappers are removed and the core documentation names the actual endpoint selection (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Claude fixture cleanup rechecks retained identity after mapped cleanup and refuses a linked runs directory, with precise replacement regressions (``prob:gates:lane-fixture-homes-leave-no-temporary-root-behind``; ``test:unit:claude-cleanup-rechecks-host-identity-after-mapped-removal``; ``test:unit:claude-cleanup-refuses-a-linked-runs-directory``).

- The custom reply-session acceptance lists its test without entering the namespace and refuses unsupported filter arguments (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Mail inventory and reply-session acceptances bound subprocess waits, inherited output pipes and cleanup, reporting retained fixture paths on cleanup failure (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper credential pins and Claude evidence consume an explicit reviewed program binding while retaining the compiled reference and closed runtime gate (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-owner-program-binding``).

- Claude helper-service refusal regressions distinguish publication custody, launcher identity and periodic refused evidence through cancellation (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-service-periodic-claude-gate-publishes-refusal``).

- Held mail inventory acceptance pins empty and canonical registry-override refusals and checks the service’s credentials against every registered loop before narrowing to the selected loop (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper-service runtime gates use explicit admission cores and a custody-bound thread token, retaining the existing refusals and introducing no fixture admission (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:helper-runtime-admission``).

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

- `bind-reply LOOP RUN --step STEP --delivery INSTANT` hands its private `_bind-reply` entry one operation-bound bundle of the owner home, runs root, entry executable, configuration, loop storage, private storage, identity executable and journal; the entry reads the reservation and evidence directory beneath the received runs root, keeps the worker lifetime lease through the service identity drop and evidence publication, and rechecks the worker's outbox and the journal's custody after the admission wait. Compatibility: the public syntax, delivery selection and reservation records are unchanged, but the public command and its private entry must come from one build: an older public process reaching the new entry refuses as `anchor-missing: operation=mail-binding purpose=manifest` and a newer one reaching an older entry as `verified-prefix: private launch requires bound home, runs root and letter descriptors`, both before any binding, so install with no `bind-reply` running and run the same command again afterwards. `bind-reply` refuses an ambient `ENTER_LOOP_REGISTRY`, empty or canonical values included, and now needs a root-owned `/usr/bin/setpriv` reached without links; a host-owned `~/.config/loops` at 0700 whose registry, allocations and mail-service files are host-owned at 0600, the provisioned service search and read grants showing as 0710 and 0640 and passing; `~/.var/loops/LOOP` host-owned at 0711, its `private` directory loop-owned at 0700 and `~/.var/loops/.mail-service` service-owned at 0700; and an owner home and runs root that are distinct and give their owner full access with no setuid, setgid or sticky bit and no group or other write. Trees written by the mail provisioner and the home preparation pass; a hand-widened mode, a symlink, a foreign owner, unsafe reply evidence or custody changed during an admission wait refuses by its named anchor boundary (``claim:superlooplane:reply-entry-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The helper service stops when its credential-authority thread exits for any reason, including a custody activation or scope refusal and a panic, and the thread's own error remains the helper's reported error (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-authority-activation-failure-cancels-service``). Compatibility: in a release build the authority's activation and scope checks cannot refuse and an evidence-publication failure already stopped the service, so the one reachable change is a panicking authority thread, which now cancels the in-flight round at once and ends the helper with `credential-thread: authority thread panicked`, where the helper used to keep serving without refresh until the run ended and then report that error; successful refresh, evidence and the thirty-second cadence are unchanged, no file, argument, setting or gate changes, an upgrade needs no step, and a helper already running keeps its old behaviour until its run ends.

- Inbox watchers start each watch with an empty readiness file, avoiding a stray missing-file error on the failure channel and premature arming after directory replacement. A running watcher keeps the old form until it is restarted from the updated recipe (``guide:superloopclaudehook:ordinary-inbox-waiting``).

- Private rotation handover, the half of `rotate LOOP RUN`, `--dry-run` included, that reads the old run's settled replies, saved briefs and last context observation, receives the five-role reader bundle: its plan's settings, registry and allocations come from the validated configuration snapshot, its runs-root argument and the public read's reservation identity are bound to the received runs root, and the reservation, reply and brief digests execute the received hashing file. Compatibility: the public syntax and journal admission are unchanged, but the launcher and the private entry must come from one build, an older launcher's handover refusing as `rotate-private: anchor-missing: operation=rotation-handover purpose=manifest` and a newer launcher's handover to an older entry as `verified-prefix: private launch requires bound home, runs root and letter descriptors`; either refusal comes before any private read and before the rotation records an intent, so `rotate` is run again once both sides are installed, and a rotation whose intent is already recorded resumes without a handover. `rotate` now needs a root-owned `/usr/bin/sha256sum` reached without links, a host-owned `~/.config/loops` of mode 0700, and an owner home and runs root with full owner access and no setuid, setgid or sticky bit, and refuses an ambient `ENTER_LOOP_REGISTRY` at the handover (``claim:superlooplane:rotation-handover-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Steward protocol fixtures separate ordinary list/read budgets from timeout measurements, with a delayed-list regression and controlled-clock repeated feeds (``prob:gates:steward-transcript-list-step-deterministic-under-stall``).

- Private round inspection, the half of `launch LOOP RUN --round STEP` that reads the settled thread and records the next round's request, receives the five-role reader bundle: its plan's settings, registry and allocations come from the validated configuration snapshot, and its reservation, step events, event boundary and optional request publication stay beneath the received runs root. Private settlement's step-directory check and thread read take the same held walk. Compatibility: the public syntax is unchanged, but the launcher and the private entry must come from one build, an older launcher's descriptor suffix refusing as `round-private: anchor-missing` and an ambient `ENTER_LOOP_REGISTRY` refusing before private state reads; the launcher requires a root-owned `/usr/bin/sha256sum` and a host-owned `~/.config/loops` of mode 0700; and every directory beneath the runs root down to the step directory, the `steps` archive and each step archive must belong to the loop identity without group or other write, links refuse, and every step archive needs both its boundary files, where the pathname walk accepted the reported step's archive without its end (``claim:superlooplane:round-inspection-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Process-absence fixtures share the kernel-impossible PID constant, including public retirement's real presence check (``prob:gates:fixtures-name-a-dead-process-by-a-number-no-process-can-hold``; ``test:unit:dead-lock-fixture-pid-exceeds-kernel-limit-and-live-lock-refuses``).

- The node absence probe matches the paths retirement removes, the checkout beside the mirrors and the build and temporary directories beneath the registered node root, and worker-home components in whole arguments or option values, so a sibling run’s prefix collision or script text no longer holds retirement (``prob:lanes:node-absence-probe-binds-the-run-at-component-boundaries``).

- Composed reply entry explicitly refuses registry overrides in its existing lifetime error envelope before lifetime admission or changing identity (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Held mail inventories preserve every snapshot refusal, including invalid service ACLs, rather than losing the cause and retirement state; pathname inventories retain their existing skip behavior (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Held mail inventories preserve namespace-entry and anchor refusals instead of reducing them to per-actor skips, and revalidate private-storage custody after acquiring the configuration's read lock (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

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

[Unreleased]: https://github.com/coraxloop/superloop-tools/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/coraxloop/superloop-tools/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/coraxloop/superloop-tools/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/coraxloop/superloop-tools/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/coraxloop/superloop-tools/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/coraxloop/superloop-tools/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/coraxloop/superloop-tools/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/coraxloop/superloop-tools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/coraxloop/superloop-tools/releases/tag/v0.1.0
