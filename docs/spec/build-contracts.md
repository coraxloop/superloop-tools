# Build and installation contracts · `spec:buildcontracts:build-and-installation`

These contracts keep reusable source, executable identity and installation inputs independently checkable. The census compares declarations with measured build outputs and refuses disagreement.

**Rule (Repository boundaries)** · `rule:buildcontracts:repository-boundaries`

The tools repository holds reusable implementations and their public contracts. The generic repository holds reusable policy and shapes. Each instance owns its values, deployment maps, operational instructions and history. Dependencies point from an instance to public tools and policy; public contracts never depend on private instance labels. Independent checkouts and pinned source identities make each layer reviewable without another repository's administrative files. A lane preserves and tests the same source object before import. Publication and deployment retain their respective source identities rather than inferring equality from similar content.

**Rule (Artifact synchronization)** · `rule:buildcontracts:artifact-sync`

Meson orders and stages Cargo outputs through build-sync. The helper selects executable artifacts from Cargo metadata or an explicitly supplied built artifact, validates the requested binary identity, and records package, version, release group, source repository and commit, toolchain, domain, digest and wall. Changed bytes are flushed to a sibling temporary file, set executable and atomically renamed. Equal bytes with a wrong executable mode are repaired without replacing bytes or modification time; equal valid outputs remain unchanged. A missing or changed identity record is published without pretending the binary was rebuilt. Stamp probes accept only empty regular files. Shared workspace compilation and artifact staging remain separate so staging cannot trigger an unaccounted build.

**Rule (Installation inputs)** · `rule:buildcontracts:installation`

The repository declaring an installation owns its map, source root, destination and ledger evidence. A map path does not redefine the source root. Instance maps may consume explicitly supplied public build outputs and generic shape roots. Inputs cannot escape their declared roots. Tools install public documents natively; included documents remain covered by the installation census. Exactly one owned installation-inputs row declares maps and document roots. Every selected document needs a matching declared copy or an admitted native public installation, and every measured destination needs a ledger identity. A document-only census retains these checks without claiming a Cargo graph verdict.

Staging runs the same installation declarations below an explicit destination prefix. Preflight materializes sources, digests, destinations, modes and provenance before mutation. Verification re-reads installed bytes, modes and identities. Two clean stages must agree, and an unchanged repeated install must preserve the promised metadata. Retirement requires a reviewed old/new destination inventory and the consumer acknowledgements required by the deploying instance.

**Rule (Build provenance)** · `rule:buildcontracts:build-provenance`

An executable's build record binds it to its reviewed source, toolchain and execution domain. Build and temporary directories, toolchain paths and source inputs are explicit. A compute artifact is not evidence that a host artifact was built in the authorized host environment. Deployment checks the actual artifact digest and domain and retains command status and wall with the source identity.

The full artifact digest binds the executable bytes to the independently retained build record against an artifact supplier who can replace delivered binaries but cannot rewrite the trusted record. Reviewed payload and Meson expression digests likewise bind measured source to the reviewed ledger against a contributor changing executable inputs without updating their reviewed declaration. Both uses require the protection statements of (`rule:digests:full-digest-justification`); a record returned under the same supplier's control needs independent review before it can be that reference.

**Rule (Server kit authority)** · `rule:buildcontracts:server-kits`

Protocol-coupled clients and server helpers share a release authority. A server kit installation names its prefix, program and unit destinations and staged evidence without implicitly activating services. State and timer intent survive replacement. Pending work is accounted for before a protocol switch, and a second installation proves idempotence. Live account, service and registration changes belong to the instance's authorized deployment procedure.

**Rule (Dependency tiers)** · `rule:buildcontracts:tiers`

Internal source dependencies point strictly downward: tier 0 is common command vocabulary, tier 1 is domain libraries, tier 2 is public tools, and tier 3 is private helpers. Tier 3 may depend only on tiers 0 and 1. The rule covers ordinary, development, build and target-specific dependencies. Process invocation is a separately declared protocol and does not authorize a source edge. Owners, consumers, external admissions, resolved closure, test tools, executable-bearing calls and installation destinations are checked against the ledger; no unnamed exception disables a census.

**Table (Package destinations)** · `tab:buildcontracts:package-destinations`

|Present source|Destination and tier|
|--------------|--------------------|
|`build-sync`|Tier 3; release group `build-sync`.|
|`execute-command`|Tier 1; release group `execute-command`.|
|`lane-gateway`|Tier 3; release group `lane-gateway`.|
|`lane-lifecycle`|Tier 1; release group `lane-lifecycle`.|
|`loop-home`|Tier 1; release group `loop-home`.|
|`permission-triage`|Tier 3; release group `requests`.|
|`pulldown-cmark-to-cmark`|Tier 1; release group `pulldown-cmark-to-cmark`.|
|`request-core`|Tier 1; release group `request-core`.|
|`run-worker`|Tier 3; release group `run-worker`.|
|`session-core`|Tier 1; release group `session-core`.|
|`staff-provision`|Tier 3; release group `staff-provision`.|
|`superloop`|Tier 2; release group `superloop`.|
|`superloop-chat-export`|Tier 2; release group `superloop-chat-export`.|
|`superloop-claude-desktop`|Tier 2; release group `claude-desktop`.|
|`superloop-claude-hook`|Tier 3; release group `claude-hook`.|
|`superloop-cli-common`|Tier 0; release group `superloop-cli-common`.|
|`superloop-correspondence`|Tier 2; release group `correspondence`.|
|`superloop-execwrap`|Tier 1; release group `superloop-execwrap`.|
|`superloop-gate-submit`|Tier 2; release group `superloop-gate-submit`.|
|`superloop-install`|Tier 2; release group `superloop-install`.|
|`superloop-lane`|Tier 2; release group `lane`.|
|`superloop-lint`|Tier 2; release group `superloop-lint`.|
|`superloop-node-status`|Tier 2; release group `node-status`.|
|`superloop-pack`|Tier 2; release group `superloop-pack`.|
|`superloop-run-report`|Tier 2; release group `superloop-run-report`.|
|`superloop-runtime`|Tier 2; release group `runtime`.|
|`superloop-steward`|Tier 2; release group `steward`.|

**Table (Session and request domains)** · `tab:buildcontracts:session-request-domains`

|Package|Tier and domain|Accountable owner|Consumers|
|-------|---------------|-----------------|---------|
|`session-core`|Internal tier 1: typed session observations, heartbeat and rulebook decisions, toggles and persistence.|ORCHESTRATORHOOK|The Claude adapter and loop session entry points.|
|`request-core`|Internal tier 1: common request transitions, single-use claims, identical-retry completion, review identities and atomic transactions.|PERMISSIONTRIAGE|The permission/request release group and lane door integration.|
|`execute-command`|Internal tier 1: command judgement, escalation and learning through bounded semantic persistence operations.|PERMISSIONTRIAGE|Door, permission hook, gateway and direct session adapters.|
