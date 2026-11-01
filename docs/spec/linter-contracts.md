# Linter contracts · `spec:lintcontracts:linter-contracts`

The linter evaluates declared repository data through one validated snapshot and one policy plan. Its implementation knows schema and policy semantics; repository identities, partitions, paths and debt counts come from declarations.

**Rule (Isolation and one plan)** · `rule:lintcontracts:isolation`

Production decisions must not depend on a compiled repository owner, sibling package, path roster, current count or Markdown fallback. Fixtures use invented identities and topology with the current schema dialect. A fixture may name a schema implemented by the checker because that identifies the decoder under test. All commands that judge a corpus consume the same loaded snapshot and policy plan; an independent command-specific ladder must not reinterpret the declarations. Policy data is explicit input, not an implementation constant.

**Rule (Snapshot loading)** · `rule:lintcontracts:snapshot`

Before corpus work, load every required core declaration and every active parameter declaration, parse each envelope before its content, and cross-validate the entire set. Missing or malformed declarations, unknown vocabulary and an absent required list refuse the command. No partial load or per-file default supplies missing authority. Physical configuration membership comes from declared snapshot inputs rather than an unrelated tracked-file assumption. Formatting explicit paths is outside policy preflight because it forms no repository verdict.

The kind registry's runtime authority is the declared environment relation. Built-in syntax knowledge does not duplicate repository extensions. The synchronization seam compares declarations with their consumers and reports disagreement; it never repairs policy by silently copying compiled values into data.

**Rule (Declaration grammar)** · `rule:lintcontracts:declarations`

A dotted namespace and version form the interchange envelope; the namespace identifies the declaration instance. Named data lives in singular `set.TYPE` tables, with strings for simple entries and inline tables for parameterized entries. Owner selection has three forms: named pattern rows under `owners.OWNER.TYPE`, a singular `use` selecting one entry where exactly one applies, and owner-bound data directly under `owners.OWNER`. Activation declares owner/program pairs. Omitting a pair declares non-application.

Patterns use augmented Backus–Naur form, not a second regular-expression dialect. Semantic designs decompose matches rather than relying on capture groups. Allowance and ratchet keys are owner, policy namespace relative to the list envelope's corpus prefix, and policy-set entry when present. Namespace and entry names distinguish independent payloads without a separate policy/family envelope. A declaration is never inferred from a current source count.

**Rule (Universe and ownership)** · `rule:lintcontracts:ownership`

Resolve the declared physical universe, subtract the global ignore relation, and then partition the survivors. Every surviving source has exactly one owner; unmatched or overlapping inclusion is a finding. Owner patterns are repository coordinates, not coordinates relative to the declaration file. Ownership and policy applicability are separate relations.

An owner reaches itself. A package reaches another package through a direct workspace-path dependency in ordinary, development or build dependencies; reach is not transitively closed. Packages may cite repository policy upward; repository policy must not cite package-owned heads downward. An unlawful dependency is repaired by promoting the shared rule to repository policy or adopting an existing shared authority, never by adding a decorative edge. The declared reach relation is reconciled independently with manifests in both directions. Source defects belong to the source owner; partition or relation reconciliation defects belong to the declaration owner that can repair them. Manifest disagreement remains visible evidence.

**Rule (References and carriers)** · `rule:lintcontracts:references`

Reference readers use owner declarations and the complete declared reach relation. Minting, citation, display and nonparticipating carrier regions remain distinct. Source decoding precedes recognition, so displayed Markdown and non-documentation strings do not become production citations merely because their bytes resemble labels. A declaration owns the policy inputs; an encountered path or label does not create a new owner or citation edge.

**Rule (Burn families and tracking)** · `rule:lintcontracts:burn-families`

A burn family has one catalogued recognizer with its complete parameter set, one declared prose/code surface and one per-source ratchet. Families never borrow recognizers or rows. Carrier-aware scanning precedes recognition. Fixture roots are outside production unless independently declared; an omitted source is not silently clean. Changing a recognizer requires a fresh policy census.

Verification treats each declared ceiling as an upper bound. Lowering or retiring a row requires a resolving semantic replacement and the complete live census; direct edits cannot raise debt. The authorized append protocol is the explicit growth boundary. An inventory-remainder family's zero means every live asset is paired, not that the underlying inventory is empty. Superseded reference forms remain visible debt until their replacements exist. Tracking tables declare exact columns for head, document and entry; displayed cells are data and are compared with the tracked sources in both directions.

**Rule (Maintenance requests and receipts)** · `rule:lintcontracts:maintenance`

Burn audit, append and write are mutually exclusive modes; bare verification is the default. Audit is read-only and classifies requested identities as equal, grown, shrunk or stale, retaining structurally parseable defects for inspection. Append requires an authority-bearing batch, rereads under a lock and admits only growth currently observed at exactly that ceiling. The batch is atomic. Write lowers lists to earned observations and needs no growth request.

Audit and append read exactly one whole request from standard input after configuration preflight and require an output receipt. Lexical normalization must place that output directly under the repository root, outside the configuration directory and its members. Nested and outside destinations refuse. The durable response file and stdout are identical bytes: one JSON object plus LF, with `input` equal to `stdin`. The list commits before the receipt; a crash in between leaves the entire batch committed, and before/after digests plus a subsequent audit expose the missing receipt. Terminal stdout refusal still applies.

**Rule (Verdicts and dependencies)** · `rule:lintcontracts:verdicts`

Malformed or incomplete configuration is a command refusal, while coherent parseable declarations that disagree with the repository produce findings. A judging command returns status 3 only after completion and publication of a result containing a failing finding. Runtime refusal is status 1 with no result; usage is status 2. Informational reporting returns 0 after publishing regardless of advisory counts. A status belonging to another executable has no implied meaning here.

Policy prerequisites are explicit dependencies of the activated owner/program pair. The checker validates them before execution and reports missing dependencies without silently activating them. Runtime derived governance belongs to the assembled plan, while source declarations retain their authored shape and authority. Commands never rewrite declarations to manufacture agreement; named maintenance modes own only their declared list edits.

**Rule (Generated projection freshness)** · `rule:lintcontracts:projections`

A generated projection is a deterministic view of declared source authority. Verification regenerates the expected bytes and compares them exactly with the published artifact; a digest or a remembered earlier success cannot substitute for that comparison. Index, matrix and constant-pin projections preserve source identity and resolve their generated citations under the same rules as authored citations. Explicit absence markers distinguish missing authored data from a generated value. Regeneration changes only the declared generated surface and never invents a claim, adoption decision or policy input.
