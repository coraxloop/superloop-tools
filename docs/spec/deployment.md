# Tool build and install contracts · `spec:deployment:tool-build-and-install-contracts`

This specification extracts the tool build, installation, managed-copy and deployment-evidence contracts from the generic build and deployment topology part (`[ORCHESTRATION-spec:deployment:build-and-deployment-topology]`). The agent execution environment and the orchestrator’s execution-domain, container, priority and routine-toolchain rules remain with that part. Tool builds and installation follow those rules, including (`[ORCHESTRATION-rule:deployment:build-where-executed]`), (`[ORCHESTRATION-rule:deployment:minimum-build-priority]`) and (`[ORCHESTRATION-conv:deployment:routine-toolchain]`).

**Definition (Development build)** · `def:deployment:development-build`

A development build is a build from source state that has not been admitted as the reviewed milestone tag for a live installation. It is used for routine implementation, local feedback within the compute domain, and scoped or self-contained verification. Its evidence identifies the source commit and any working-tree difference, selected package, features, profile, toolchain, cache namespace, and execution domain.

A development build may prove that a change is ready for review. Its artifact is never a deployment source, even when the tree is clean, the tests are green, or its bytes happen to equal a later release artifact. Installation requires a new build through the tagged path.

**Definition (Milestone tag)** · `def:deployment:milestone-tag`

A milestone tag is the owner-reviewed source-control name selected for one release milestone. It resolves to exactly one reviewed commit and therefore to one source tree. The particular tag name, commit identity, reviewer, and selection time are release-record values; the durable rule is that the tag is fixed before any admitted host build and remains identical throughout the install. This specializes the milestone cadence decision (`[ORCHESTRATION-dec:decisions:release-cadence]`).

A missing tag, a tag whose resolution changed, a checkout with modifications, or a mismatch between the reviewed commit and the resolved commit invalidates the candidate. Creating a tag after compiling does not convert the earlier artifact into a tagged artifact.

**Definition (Execution domain)** · `def:deployment:execution-domain`

An execution domain is the trust and machine context in which a built helper will run. It includes the trusted-host or compute-server trust class, target platform, selected toolchain, scheduling boundary, and the storage surfaces used for source, temporary data, caches, and build outputs. A binary belongs to the domain that built it for execution there; matching filenames or target triples do not establish domain identity.

Current machine identities, capabilities, toolchain versions, scheduling mechanisms, and storage locations remain registry facts under (`[ORCHESTRATION-rule:architecture:dynamic-facts-stay-in-registries]`). The stable constraints in this part govern their selection, and stale or unowned values fail closed as required by (`[ORCHESTRATION-rule:architecture:stable-constraints-govern-registries]`).

**Definition (Deployment target)** · `def:deployment:deployment-target`

A deployment target is one managed regular-file copy declared by the tagged install map. Its declaration names a tagged source file or a tagged build output relative to the build root, a harness-owned configuration root, a relative destination below that root, an executable or data-file mode, and the execution domain of any installed binary. A render target names its base relative to the shape root supplied to the install, allowing an instance overlay to render over a published generic shape without copying that shape into its repository. The resolved destination must remain below the declared root after normalization and must not traverse a symlink.

The declaration is structural: machine-specific absolute roots are registry data resolved at install time. The `.pre-deploy` backup and `.provenance` file are reserved siblings beside a target, not second deployment targets; every build target and every copy requesting provenance receives the latter. Every live target has exactly one declaration; an undeclared file, ambiguous source, escaping path, sibling collision, or target of the wrong file type blocks installation.

## Implementation · `sec:deployment:implementation`

This division fixes the maintained implementation and build layers. Package boundaries may evolve, but a release has one explicit owner for every helper, shared library, build target, and installed copy.

**Rule (Rust or Meson only)** · `rule:deployment:rust-or-meson-only`

Maintained executable and library behavior shall be implemented in Rust. Meson shall be the only maintained build and install orchestration layer. The tools repository holds the one Cargo workspace and the root Meson graph that enumerates its packages; a package-level declaration owns each Rust target, scoped test set, and installable output. The generic and instance repositories hold documents-only Meson layers that run the deployed tools and build nothing. Shared behavior belongs in an explicit Rust library rather than being duplicated in wrappers (`rule:buildcontracts:repository-boundaries`).

Meson selects and orders Rust outputs and obtains every binary through the Rust sync primitive. It invokes a Rust install primitive with each repository's declared target map: the tools repository's install runs the primitive built from the same tagged tree, and the generic and instance layers, which build nothing, run the deployed one. Meson shall not reimplement helper semantics or the content, backup, permission, and modification-time contract. This is the durable shape anticipated by the planned Meson skeleton and the no-shell decision (`[ORCHESTRATION-dec:decisions:no-shell]`). A package split, merge, or port must leave the external contract unchanged unless a separate owner-ratified change applies (`[ORCHESTRATION-rule:architecture:external-contract-stability]`).

**Rule (No shell helpers)** · `rule:deployment:no-shell-helpers`

No released build, verification, installation, hook, lane, or wrapper path may delegate maintained behavior to a shell program. Every remaining shell helper shall be ported to Rust or replaced by Meson orchestration, and the replacement must own all success, failure, evidence, state, and recovery behavior formerly carried by the script. A shell trampoline around a Rust or Meson command is still a shell helper and does not satisfy this rule.

The two historical installers are behavior sources retired as implementation. Their replacement install maps cover both target families: the rulebook renders with content-diffed copies, outgoing-byte backups, declared modes and unchanged mtime behavior, and the worker charter as a copy in its separate harness-owned configuration root. Both families remain subject to the no-shell and Meson-install decisions (`[ORCHESTRATION-dec:decisions:no-shell]`) and (`[ORCHESTRATION-dec:decisions:meson-installs]`); a partial replacement cannot pass the trusted deployment gate.

## Tool build contracts · `sec:deployment:tool-build-contracts`

**Rule (Server development builds)** · `rule:deployment:server-development-builds`

Routine development builds and self-contained verification builds shall run in the compute-server domain. This includes repeated compilation caused by tests, format or documentation gates, and linters unless the narrow host checker exception below applies. Binaries intended to execute on the server are built there. These placement consequences refine server-first computation (`[ORCHESTRATION-rule:server:server-first-computation]`).

A short expected duration is not permission to move routine work to the host. Server artifacts and a green server report are review evidence; neither is an installable host artifact nor the verdict of record.

**Rule (Host builds from tags)** · `rule:deployment:host-builds-from-tags`

The trusted host may compile an installable host artifact only from a fixed, reviewed milestone tag. The build uses a clean checkout of the tag, tagged Meson declarations, a registered host toolchain, and no executable output returned from the compute server. The resulting artifact is admitted only for the target and domain named by the same tagged install map.

This is a narrow release-build exception to routine server placement and to the default host compile ceiling. It does not authorize exploratory host builds, untagged verification, or reuse of a host artifact on the server. The exception and its boundary are the accepted build topology (`[ORCHESTRATION-dec:decisions:build-deployment-topology]`).

**Rule (Tag before install)** · `rule:deployment:tag-before-install`

The milestone tag shall exist and resolve to the reviewed commit before Meson configuration, compilation, test execution for installation, or target mutation begins. The installer records the resolved tag and commit before the first of those actions and re-resolves them before live mutation. Both resolutions must agree.

No later tag, branch name, working-tree cleanliness claim, or byte comparison may retroactively admit an earlier build. If the tag is missing, moves, or no longer matches the reviewed source, all derived build output is rejected and the release starts again from the corrected tag. This enforces tag-first milestone cadence (`[ORCHESTRATION-dec:decisions:release-cadence]`).

**Rule (Cache intelligence)** · `rule:deployment:cache-intelligence`

Routine runs shall reuse stable toolchains, package caches, and purpose-specific target directories instead of manufacturing an unscoped clean build. Each domain has one Meson build directory and one Cargo target directory per purpose. Cache namespaces separate execution domain, toolchain identity, source identity, package set, feature set, build profile, and purpose such as development, release, or vendored checking. A mismatch in any key selects a different namespace or invalidates the affected entries.

Cache hits do not establish source provenance and cannot substitute for a required build or test record. Host and server outputs never share an executable cache. The host exception for a repository's own vendored linter or checker is valid only for a package-scoped, cache-intelligent build; a bare workspace build or an unrelated package is routine work and belongs on the server. Exact cache paths, installed toolchain versions, and capacity limits are registry data rather than constants in this part.

**Rule (Disk-backed temporaries)** · `rule:deployment:disk-backed-temporaries`

Source work trees, Meson build directories, Rust target directories, package caches, compiler temporaries, link outputs, and generated test data shall use the domain's assigned disk-backed workspace surface. A memory-backed system temporary surface may hold only small bounded control data and shall never be the fallback for build or bulk-install staging.

Before launch, the build controller resolves the registered workspace and temporary roots, verifies their declared storage class and ownership, and checks the current run-specific free-space margin. Missing placement, insufficient margin, or fallback prevents the build. The path and capacity are registry facts; disk-backed placement and preflight are durable constraints. Server builds additionally satisfy (`[ORCHESTRATION-rule:server:disk-backed-workspace]`).

**Scenario (Host compile overrun)** · `scenario:deployment:host-compile-overrun`

Detection begins by classifying a proposed host compile as a tagged installation build, the repository's own vendored checker built package-scoped and cache-intelligently, or prohibited routine work. Routine work is misplaced even when it would finish quickly. For an accidentally started routine build, the current declared host ceiling is 60.0 seconds of monotonic wall time; an elapsed value greater than that ceiling is an error. A warm run beyond the ceiling proves the placement failure without a cold confirmation run. The ceiling, warm-implies-cold corollary, and two named exceptions are governing contract constants, not adjustable run-budget registry entries.

Recovery stops the expensive child and its build descendants when safe, marks every partial output nondeployable, and reports the source state, tag classification, package scope, cache namespace, priority class, elapsed wall time, termination status, and retained evidence. It then moves the routine command to the server, rebuilds server-executed artifacts in that domain, and repeats the intended check there under (`[ORCHESTRATION-rule:server:server-first-computation]`). No partial host artifact is reused.

A tagged installation build or qualifying vendored-checker build that crosses the numeric bound records its duration and exception evidence but is not reclassified as routine solely because of elapsed time. If the evidence does not prove every exception precondition, recovery treats the work as routine and follows the server path above. Changing the ceiling or exception set requires an owner-ratified change to the governing machine rule and this specification; registry drift cannot widen either.

## Installation · `sec:deployment:installation`

This division turns one admitted milestone tag into declared managed copies. It preserves the load-bearing content and mtime behavior of the historical copy loops while replacing their shell implementation with Meson and Rust.

**Protocol (Meson install)** · `proto:deployment:meson-install`

Installation from a milestone tag proceeds in repository order: tools, then generic, then instance. Each install runs only tools and shapes no older than the tree it installs, and each repository publishes to its own share folder (`rule:buildcontracts:repository-boundaries`). Within each install, the steps divide between Meson and the primitive as (`rule:buildcontracts:installation`) records:

1. Meson resolves the reviewed tag to its fixed commit and verifies a clean tagged source tree as the first action of configuration; the primitive resolves both again before planning and binds the tagged target map to that identity.
2. The host recipe resolves the trusted-host execution domain, toolchain, scheduling mechanism, disk-backed build, cache, temporary, staging, and harness configuration roots from their owned registries and passes all placement preflights; Meson and the records capture the selected values.
3. Meson configures out of tree from the tagged root using only tagged declarations and rejects any shell helper or undeclared build input.
4. At minimum priority, Meson builds the required Rust artifacts from the tools repository and runs its declared checks; the generic and instance layers build no artifacts and run their document and template checks with the deployed tools.
5. The primitive materializes an install plan naming every source digest, normalized relative destination, target class, declared mode, execution domain, and current target state. Before mutation, it rejects a missing source, escaping path, symlink, duplicate destination, unresolved mode, or target-map difference not present in the reviewed plan.
6. For each planned target, the primitive compares exact source and target bytes. It leaves an equal target completely untouched. Before replacing a differing existing regular target, it preserves and verifies its outgoing bytes in the declared sibling backup. It installs a new independent copy, applies its declared mode, and, for the watched rulebook, verifies a modification-stamp transition.
7. The primitive re-reads every installed target and verifies its file type, bytes, mode, mapping, and build provenance. It records unchanged, new, changed, and backed-up outcomes separately, together with before and after modification stamps.
8. The primitive re-resolves the tag and commit and publishes its report only if they still match; Meson prints each map's report, and the host recipe retains the reports and provenance as evidence for the trusted deployment decision.

Any failed step stops later mutation and reports the last completed step and all targets already touched. The resulting target set is not trusted. Recovery either restores verified outgoing bytes and modes from the recorded backups or reapplies the same fixed tag after correcting the failure; it never advances to different source state without a new review and plan. This protocol is the normative replacement for the copy loop selected by (`[ORCHESTRATION-dec:decisions:meson-installs]`).

**Requirement (Copy, not symlink)** · `req:deployment:copy-not-symlink`

Every deployment target shall be an independent regular file whose bytes can be read without following an instruction-discovery link. The installer shall create copies, shall not create or preserve a symlink as a managed target, and shall reject a target or traversed destination component that resolves outside the declared harness-owned root. Source and target may not share an inode.

The historical one-time removal of a pre-ruling charter symlink is migration evidence, not standing authority to remove arbitrary links. Any future legacy link conversion must be separately reviewed, preserve recoverable prior state, and complete before the target enters the ordinary install plan.

**Requirement (Content-diffed install)** · `req:deployment:content-diffed-install`

The install decision for each target shall be based on exact source and target bytes. A missing target is new; an existing regular target whose bytes differ is changed; equal bytes are unchanged. A digest may accelerate planning, but the mutation decision must be confirmed against the bytes and a digest alone may not authorize replacement.

An unchanged outcome performs no copy, rename, permission operation, touch, backup, or target-parent rewrite. A changed outcome follows the backup and permission requirements below. The installer revalidates the observed target immediately before mutation; a concurrent byte, type, or identity change invalidates the plan and stops that target rather than overwriting new state.

**Invariant (Unchanged mtime)** · `inv:deployment:unchanged-mtime`

When source and target bytes are equal, installation preserves the target's exact observed modification stamp. It does so by performing no target operation, then re-statting the target and proving that its file identity, bytes, mode, and nanosecond modification stamp equal the preflight values. A source timestamp is irrelevant and must not be copied onto an unchanged target.

For a changed watched rulebook, the installed stamp must differ from the outgoing stamp; equal stamps after a byte change fail installation. Modification time is only the hook's fast-path trigger, never proof of content identity. The digest decision and notice behavior remain owned by (`[ORCHESTRATION-proto:hooks:rulebook-change-notice]`).

**Requirement (Outgoing-byte backup)** · `req:deployment:outgoing-byte-backup`

Before overwriting any changed existing regular target, the installer shall copy its exact outgoing bytes to the sibling target formed with the `.pre-deploy` suffix and verify that backup byte-for-byte. Only successful backup verification permits target mutation. Failure to create, replace, read, or verify the backup leaves the target untouched and fails the install.

The install report records the outgoing and backup digests, target identity, and whether the backup replaced an older backup. A backup is recovery evidence and is never executed or treated as current configuration. Automatic recovery may restore it only when its recorded digest and target mapping still agree; otherwise recovery stops for review rather than clobbering later bytes.

**Requirement (Installed permissions)** · `req:deployment:installed-permissions`

The tagged target map shall declare one exact mode for every target and classify it as executable or data. Every new or content-changed copy receives that mode after its bytes are installed, and verification must prove both the mode and bytes before success. A data target may not acquire execution bits, and an executable target may not acquire permission broader than its declared mode.

An equal-byte target is not silently chmodded: its existing mode must already match the declaration or installation fails as non-idempotent state. Exact per-target modes live in the source-controlled tagged map; they are release declarations, not mutable machine-registry defaults or ambient umask results.

**Rule (One change event per deploy)** · `rule:deployment:one-change-event-per-deploy`

A deployment that changes the watched rulebook shall perform one content replacement of that target, establish one outgoing-to-installed modification stamp transition, and perform no later touch or metadata rewrite of the rulebook in the same run. The next accepted tracked hook event can therefore observe the changed stamp, compare the digest, and emit exactly one content-change notice under (`[ORCHESTRATION-proto:hooks:rulebook-change-notice]`). Backups and changes to other targets shall not mutate the watched target.

An installation whose tagged rulebook bytes are already present leaves its stamp unchanged and produces no notice. Reapplying the same deployment also produces no notice. Serialization of rulebook installation and the post-install digest-and-stamp record are required evidence; concurrent writers or a changed rulebook with an unchanged stamp fail this rule.

**Requirement (Manifest removal is recoverable)** · `req:deployment:reversible-manifest-removal`

Any program of this family that removes a file because a manifest names it shall rename the entry without replacement into a recovery place and record that place with the source identity. It shall not unlink the entry: preservation of its bytes and one move back for restoration are part of the removal's result, regardless of which program of this family reads the manifest.

**Protocol (Close admission before draining users)** · `proto:deployment:drain-before-removal`

When removal depends on nobody using the old thing, the change that stops new users acquiring it happens first and is read back. Only then does the remover count users who acquired it before that closure, prove that each has left, and remove it. If closure, census or departure cannot be shown, the old thing stays; counting before closing the door would miss a new user.

**Requirement (Removal identity comes from reviewed text)** · `req:deployment:reviewed-removal-digest`

For a program of this family, the authority to remove an entry comes from its full digest in the reviewed manifest, checked against the opened target before the move. A sidecar beside the target cannot supply this authority, because an actor able to replace the target can replace the sidecar too (`req:deployment:reversible-manifest-removal`).

**Requirement (Recovery place is exclusive)** · `req:deployment:exclusive-recovery-place`

For a program of this family, the recovery place is writable by its owner alone, and a moved entry counts as recovered only if no other path or writer can reach its bytes or that place. A target with another hard link is not recovered by a move alone, because another path can still reach its bytes (`req:deployment:reversible-manifest-removal`).

**Protocol (Execution-domain rebuild)** · `proto:deployment:execution-domain-rebuild`

Rebuilding an installed helper for its execution domain proceeds in this order:

1. Identify the target's tagged mapping, intended execution domain, current installed provenance, and external contract.
2. Resolve the fixed milestone tag and the target domain's current registered toolchain, scheduling boundary, disk-backed temporary root, package cache, and purpose-specific target directory.
3. In that domain, configure the tagged Meson graph and build the owning Rust package at minimum priority. Do not import or execute an artifact built in a different domain.
4. Run the target's scoped tests and compare all externally visible bytes, statuses, state effects, and target mappings with the admitted contract (`[ORCHESTRATION-rule:architecture:external-contract-stability]`).
5. Pass the resulting artifact and its complete build record to the Meson install protocol, then verify the installed digest, declared mode, tag, domain, and mapping.
6. Retain the old installed provenance and any outgoing-byte backup with the new record until the deployment gate and recovery window close.

If the intended domain is unavailable, its toolchain or storage facts are stale, or contract verification fails, the old target remains current and the rebuild is reported blocked. Availability in another domain never authorizes a substitute binary.

**Requirement (Probe staged programs where they run)** · `req:deployment:staged-runtime-probe`

A built program is probed in its execution domain from its staged copy before it replaces the live one, exercising each command the change touched. Source review and a gate in another domain cannot establish the runtime resolver's result there: a system program may be reached through a symbolic link even when a test fixture used a regular file, so the staged probe must precede the live switch.

## Deployment evidence · `sec:deployment:deployment-evidence`

This division defines the evidence required before a tagged candidate may change a live harness configuration root. Evidence refers to exact source, domain, target, byte, mode, and modification-stamp identities rather than to a claim that an install command succeeded.

**Verification (Install idempotence)** · `verif:deployment:install-idempotence`

Install idempotence is verified against isolated harness-equivalent staging roots with the same target-map and filesystem semantics as the live roots. The verification checks these conditions:

1. Seed each target class as absent, equal, and content-different; include a watched rulebook and an existing outgoing-byte backup.
2. Install the fixed tagged candidate once. For every target, capture file type, exact bytes, mode, file identity, nanosecond modification stamp, backup bytes, and the install outcome.
3. Prove absent targets became independent copies with declared modes; changed targets preserved outgoing bytes before replacement; equal targets retained their complete captured state; and one changed rulebook created exactly one detectable stamp transition.
4. Install the same tag and mapping a second time without modifying any input. Require zero new or changed outcomes, zero backup writes, zero notices, and equality between its observed target inventory and the first post-install inventory, except for run identity and elapsed observations.
5. Compare the two post-install snapshots. Every target and backup must have zero byte, file-type, permission, and modification-time drift; a differing identity for an unchanged target also fails.
6. Exercise an equal-byte target with a wrong mode and a concurrent target change. Each case must fail without target replacement, backup overwrite, or a false unchanged result.

Any unplanned write, unreported difference, extra change notice, missing backup, or timestamp ambiguity fails verification. A clean second command status without the before-and-after inventory is insufficient.

**Verification (Tag provenance)** · `verif:deployment:tag-provenance`

Tag provenance is verified by reconstructing one unbroken chain:

1. The reviewed milestone tag resolves twice to the same reviewed commit, and the complete source diff admitted by the reviewer ends at that commit.
2. The clean checkout tree, tagged Meson graph, selected packages, features, profile, and target map are recorded against that identity.
3. The registered toolchain and execution-domain observations, cache keys, priority evidence, build commands, test statuses, and output digests bind every binary to its in-domain build.
4. Each copied rule or data target equals its tagged source bytes; each binary target equals the recorded tagged build output; and every installed path and mode equals the tagged target map.
5. No server-built artifact enters a trusted-host install. Any server-returned source or evidence follows the quarantined review sequence (`[ORCHESTRATION-proto:architecture:returned-evidence-review]`) before the tag is selected.
6. The final installed inventory names the same tag, commit, domain, mapping, and digests as the build and install records, with no intervening source or registry selection change.

A moved or unresolved tag, dirty checkout, unrecorded executable input, cross-domain artifact, target digest mismatch, missing test record, or broken identity edge fails provenance. Similar version text or equal filenames cannot repair the chain.

**Gate (Trusted deployment)** · `gate:deployment:trusted-deployment`

Live installation is blocked until the reviewing orchestrator proves all of the following over one exact candidate and target plan:

1. The source is a fixed milestone tag whose complete change diff, Meson graph, package ownership, and target-map diff were reviewed, and whose clean commit identity is unchanged.
2. All required package, integration, external-contract, and release checks passed over the recorded source and build outputs. Server-green evidence is retained but remains advisory as required by (`[ORCHESTRATION-rule:server:server-green-is-advisory]`).
3. Every build was correctly classified as server development, tagged host installation, or the narrow vendored-checker exception; every executable was built in its execution domain; and no unreviewed returned artifact is an input.
4. Minimum priority, disk-backed temporary and cache placement, current toolchain selection, free-space preflight, cache namespace, elapsed time, and any host-ceiling exception are present and satisfy the tool build contracts and the generic execution rules (`[ORCHESTRATION-rule:deployment:minimum-build-priority]`), (`[ORCHESTRATION-conv:deployment:routine-toolchain]`).
5. A staging `meson install --destdir` used the exact live target maps and demonstrated independent copies, normalized destinations, exact content decisions, outgoing-byte backups, declared modes, unchanged mtimes, and one detectable rulebook change event with no shell helper or symlink target.
6. Install-idempotence and tag-provenance verification passed, and the planned live add, change, unchanged, backup, and refusal sets match the reviewed staging report.
7. The final trusted-host verdict covers the exact tagged state under (`[ORCHESTRATION-inv:architecture:trusted-final-gate]`), and no source, tag, toolchain, registry, build output, test result, or target observation changed after that verdict.

Only then may the recorded live plan run in tools, generic, instance order. The three installs' reports and provenance files establish the live deployment's evidence. Any missing condition, unexplained skip, stale registry value, diff mismatch, target-map ambiguity, failed preflight, server-to-host disagreement, or intervening change keeps the gate closed. This gate grants authority for the declared copies only; runtime server operation and helper behavior remain with their owning parts, and the broader release still satisfies the trusted release gate (`[ORCHESTRATION-gate:conformance:trusted-release]`).
