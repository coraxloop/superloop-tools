# Linter conformance · `spec:conformance:linter-conformance`

This specification extracts the linter construction and verification contracts from the generic conformance and evidence part (`[ORCHESTRATION-spec:conformance:conformance-and-evidence]`). Evidence authority and corpus-standing principles remain with that part; the contracts here govern the tool that checks them. The recorded three-package census and eight-test frontier describe the specification adoption campaign, not a measurement of the current workspace. Current verification derives repository membership and assembly membership from their declarations.

## Linter ownership · `sec:conformance:linter-ownership`

**Terminology (Frontier test)** · `term:conformance:frontier-test`

A frontier test is one of the eight repository-facing integration tests whose present failure deliberately witnesses corpus state that the accepted campaign has not yet supplied. Its mapped green condition is a prerequisite for changing that test from frontier evidence into a gate check. Removing it, ignoring it, filtering it out, weakening an assertion, or substituting a fixture does not discharge the frontier.

**Requirement (Current owner prefixes)** · `req:conformance:current-owner-prefixes`

The owner partition and prefix signature must be derived from the present workspace member manifests on every check. For each crate name, the derivation strips a leading project namespace when present, removes hyphens, and uppercases the remainder; an invalid result registers no prefix and fails the owning reconciliation. Repository prose in this virtual-root workspace belongs to its crateless repository owner. This part keeps no independently editable prefix roster.

**Requirement (Carrier completeness)** · `req:conformance:carrier-completeness`

The prose carrier must include the root readme, every Markdown document below the repository `adr/` and `docs/` trees, package `adr/` and `docs/` trees, and a package readme at any depth. Missing optional trees are empty; unreadable present trees are findings. Version-control, build, dependency, archive, and vendored directories are excluded. Every authored specification part must be carried, while the generated assembled publication must be excluded exactly once.

**Requirement (Source-owner retargeting)** · `req:conformance:source-owner-retargeting`

Before a repository-facing frontier test can turn green, every adopted path, package name, owner prefix, assembly pair, benchmark entry, migration prefix, and fixture witness inherited from the source corpus must be replaced by the corresponding current-workspace fact or removed. The audit fails on an absent source package, an old parts directory or publication, a benchmark outside the current carrier, or a scale threshold copied from the source workspace. A fixture may retain a fictional owner only when it is explicitly fixture-local and no repository assertion depends on it.

## Profiles and census · `sec:conformance:profiles-and-census`

This division fixes the live test population and its committed anti-vacuity basis. The counts below are deliberate evidence data, not a mutable operational roster.

**Requirement (Test-profile adoption)** · `req:conformance:test-profile-adoption`

The test profile must range over every current workspace member and every Rust file under each member's `src/` and top-level `tests/` roots. The census parses abstract syntax, counts a function once when any bare or call-form attribute path ends in `test`, includes configured-out and ignored tests, descends into inline modules, and never follows module declarations. Tests in a top-level `tests/` tree are `integration`, tests in `src/tests/` are `crate`, and other tests below `src/` are `unit`. The derived label is the `test` kind, that area, and the function identifier with underscores changed to hyphens; its standard place is the final documentation line.

**Requirement (One mint per covered test)** · `req:conformance:one-mint-per-covered-test`

Every covered test function must derive exactly one well-formed, collision-free label and seed exactly one code-side mint before any citation is resolved. The number of derived test mints must equal both the live covered count and the committed total in the census table. A prose author may cite that mint but may not create it, and the authored prose registry must remain smaller than the derived test registry when the corresponding frontier assertion is enabled.

**Requirement (Test derivation injectivity)** · `req:conformance:test-derivation-injectivity`

Within each owner, no two covered tests may share a bare function identifier, even when their files classify into different areas, and no two covered tests may derive the same full label. The collision report must name every member of each identifier and full-label collision group. Equal identifiers in different owners remain distinct because owner qualification separates their registries.

**Requirement (Census totality)** · `req:conformance:census-totality`

Every test function discovered from a readable member source must be assigned to exactly one of `unit`, `crate`, or `integration`, derive a label, and appear in exactly one package/area cell. A source parse failure is a finding and cannot be treated as a source with no tests. The trusted gate requires no unexplained parse exception; any temporary exception must identify its file, owner, reason, and closing change without reducing the committed basis silently.

**Rule (Census-derived floor)** · `rule:conformance:census-derived-floor`

Anti-vacuity bounds are derived from the committed current-workspace census in the following table, never from the scale of the vendored source repository. The live census must reconcile exactly with every package/area cell before the table can serve as its floor. The table changes only in the same reviewed change whose source addition, removal, or package/area move changes one of its values; that change updates every affected cell and total and explains any decrease. A rename that does not move a cell changes derived-label evidence, not a census count. Updating a bound without the source change that moves it, or moving the source without the table, is a failing divergence.

**Table (Test census)** · `tab:conformance:test-census`

This is the committed basis derived on 2026-08-22 from the three member manifests and their live `src/` and `tests/` Rust sources. All live test attributes use the plain `#[test]` form. The recount excludes lookalike text in string literals, counts each attributed function once, and classifies by the package-relative file rules above.

|Package|Unit|Crate|Integration|Total|
|-------|---:|----:|----------:|----:|
|`superloop-cli-common`|0|69|5|74|
|`superloop-execwrap`|0|25|18|43|
|`superloop-lint`|408|0|35|443|
|**Workspace**|**408**|**94**|**58**|**560**|

**Verification (Live and dead test citations)** · `verif:conformance:live-and-dead-test-citations`

Recompute the live census and select a covered asset owned by a current member, not by a remembered source package. Four independent analyses must then prove: a same-owner citation resolves once; a well-formed label absent from the census raises one unresolved-citation finding; a citation from a different owner whose manifest reaches the witness owner resolves through the witness's derived prefix; and a bare authored occurrence of the reserved test label raises one unwarranted-reserved-kind finding and adds no mint. The fixture fails if the witness, prefix, or reach edge is not current.

## Linter reports · `sec:conformance:linter-reports`

**Requirement (Shape distributions)** · `req:conformance:shape-distributions`

For each participating measured document, recompute document words, citations, heads, named heads, and each environment's words and citations. A word is one maximal non-whitespace source run. Across the whole measured corpus, report count, minimum, arithmetic mean, nearest-rank `p10`, `p50`, `p75`, `p90`, and maximum for named-environment words and citations, division words, and heads per document. Percentile rank is the ceiling of percentage times population size, clamped to a present observation. These distributions are measurements, not bands that classify individual environments as acceptable or outlying.

**Verification (Shape report)** · `verif:conformance:shape-report`

Run the shape command over the exact subscribed carrier used by the check and independently recompute participating-document selection, generated-document exclusion, named and division counts, environment extents, every distribution field, and percentile ordering. The measured document list and per-document summaries must reconcile with that carrier, both divisions and named heads must be represented when the corpus supplies them, and no configured benchmark, comparison verdict, or edition datum may enter the result. Advisory measurements never change the command's success status.

**Requirement (Graph resolution space)** · `req:conformance:graph-resolution-space`

Build one owner-partitioned graph after seeding the current code surface with covered test, to-do, claim, and constant mints and harvesting participating prose mints. Resolve prose and Rust-commentary citations against those completed registries in one pass, independent of traversal order. Each mint is a node; each resolved citation whose source lies in a containing environment is an edge from that environment to the mint. Generated-region citations resolve in the same space but remain attributed to their generator.

**Requirement (Graph has no dangling edges)** · `req:conformance:graph-no-dangling`

Every graph edge must have a current minted node at both ends, and every participating citation must resolve once or raise its specific resolution finding. A resolved citation standing after a mint in the same source creates one edge from the nearest preceding mint; one before the source's first mint is counted as resolved but creates no edge. The trusted check requires the dangling finding set to be empty and the edge count to be nonzero. A report may display dangling findings for diagnosis, but may not turn them into edges, discard them, or issue a second verdict.

**Requirement (Graph hubs)** · `req:conformance:graph-hubs`

The review summary ranges over authored document mints: it retains every legitimate zero-in-degree mint as an orphan and ranks cited mints by in-degree descending, with owner and label as deterministic ties, truncated to the requested hub count. Derived and other code-side mints remain in the resolution graph and reverse lookup but do not swamp document listings. For each owner and area, `mints` must equal `cited + orphans`; the frontier requires enough cited document mints to fill its requested hub list.

**Verification (Graph report)** · `verif:conformance:graph-report`

Rebuild the report from the same seeded analysis used by the repository check. Reconcile authored mint and edge totals with the graph, every dangling entry with an existing resolution finding, every orphan and hub with node in-degree, every owner and area cell with the global partition, and any reverse lookup with all matching mint sites and its incoming citation sites in source order. The frontier requires more than one hundred authored mints, no dangling citation, at least one but not all mints orphaned, and a full correctly ranked requested hub list.

**Requirement (Burn-register freshness)** · `req:conformance:burn-register-freshness`

The six adopted registers—section-sign references, retired record numbers, superseded tag forms, retired scenario numbers, retired division names, and unlabelled to-do notices—must each be read with its production recognizer over its declared prose or Rust-comment surface and exclusions. Every live census row and committed row must agree exactly. A family at zero retains its empty register so revival is growth. Regeneration may remove stale rows in the same change as the corpus reduction, but it must never certify new growth.

**Requirement (Projection freshness)** · `req:conformance:projection-freshness`

Every recognized generated in-file test index and folder test matrix must equal the deterministic projection of current test labels, areas, and authored claim cells byte for byte. Generated claim citations must resolve in the common graph, and a dangling generated citation is projection staleness rather than an author-edit suggestion. A missing projection in a staged, not-yet-adopted source is counted as absent and is not called fresh; once a generated region is present or its adoption closes, a hand edit, duplicate matrix head, wrong level, or stale row is a failing finding until regeneration settles it.

**Rule (Informational reports do not judge)** · `rule:conformance:informational-reports-do-not-judge`

Graph, coverage, and shape commands describe the completed analysis and return success whenever they publish their result, regardless of orphan, unwitnessed, dangling, long, or short listings. They never use the linter's finding-bearing status. Runtime and usage failures retain their own statuses. This applies the output rule (`rule:output:informational-success`) and the command-specific rule (`rule:lintcontracts:verdicts`); judging checks, not reports, own corpus standing.

**Verification (Repository prose)** · `verif:conformance:repository-prose`

Read the current workspace and complete prose carrier, seed exactly the code surfaces used by the check—tests, notices, claims, constants, and Rust commentary citations—and analyze all participating authored documents. Require workspace and carrier traversal to have no finding and the analysis to have no failing finding across participation, legacy lint, heads, mints, citations, generated regions, and outline tracking. Re-running with a smaller seed is not equivalent evidence.

**Verification (Repository census)** · `verif:conformance:repository-census`

Rediscover members, enumerate and parse their test roots, and recompute every test's package, area, transformed name, full label, standard-place standing, identifier collision, and label collision. Reconcile every package/area cell and total with the committed table, require the live covered and derived populations both to equal its grand total, require all three areas populated, require no underivable asset, allow at most one source-parse failure, and require any such failure to be explicitly owned. Any legitimate census change first updates the committed basis under the census-derived-floor rule and is then verified against that new basis.

**Verification (Repository assembly)** · `verif:conformance:repository-assembly`

Read the one adopted root assembly without writing. Recompute manifest parsing, draft state, bidirectional membership, part count and order, duplicate mints, generated publication bytes, and the committed-byte comparison. Evidence is green only when one assembly is declared, none is dormant, the manifest is not draft, all declared parts are present exactly once, one assembly is verified, and there is no assembly finding. Draft membership success alone is not freshness.

**Verification (Repository check)** · `verif:conformance:repository-check`

Run the complete adopted check over one source state. It must combine workspace and carrier traversal; test, to-do, claim, and constant profiles; code citation harvest; prose calculus and outline tracking; claim coverage; index and matrix projection checks; assembly; all burn registers; and owner reach. The result is clean only with no failing finding, every covered test carrying its exact derived label, no missing, wrong, misplaced, underivable, or colliding test asset, current projections and registers, and a live fresh assembly. Its anti-vacuity assertion uses the committed census table's grand total, not the source repository's historical scale; no retired edition register participates.

## Linter frontier · `sec:conformance:linter-frontier`

**Table (Frontier ownership)** · `tab:conformance:frontier-ownership`

These eight rows record the frontier conditions of the specification adoption campaign; their presence is not a current test verdict. “Green only when” is the complete corpus condition that permits the later retargeting change; the table does not waive any existing assertion.

|Frontier test|Owning parts|Green only when|
|-------------|------------|---------------|
|`the_repository_prose_is_in_good_standing`|(`[ORCHESTRATION-part:spec:architecture]`), (`[ORCHESTRATION-part:spec:output]`), and (`[ORCHESTRATION-part:spec:conformance]`)|Every authored accepted part is carried and head-valid; root prose and all seeded code surfaces have no unresolved, duplicate, reserved-kind, outline, legacy, generated-region, or owner-partition finding; and all source-owner adoption data are retargeted to this workspace.|
|`the_repository_seeds_one_mint_for_every_covered_test`|(`[ORCHESTRATION-part:spec:conformance]`)|The current profile covers the committed census, derives and seeds exactly one unique mint for every tabled test, uses the table's grand total instead of the inherited thousand-test threshold, and the authored prose mint count remains below the derived count.|
|`a_document_citing_a_live_test_resolves_and_a_dead_one_does_not`|(`[ORCHESTRATION-part:spec:architecture]`) and (`[ORCHESTRATION-part:spec:conformance]`)|The fixture selects a live test from a current member, uses its current owner and a manifest-reached prefix, and obtains exactly the live-resolution, dead-refusal, imported-resolution, and unwarranted-authorship outcomes specified by the four-outcome verification.|
|`the_repository_graph_report_is_sane`|(`[ORCHESTRATION-part:spec:architecture]`), (`[ORCHESTRATION-part:spec:dispatch]`), (`[ORCHESTRATION-part:spec:hooks]`), (`[ORCHESTRATION-part:spec:lanes]`), (`[ORCHESTRATION-part:spec:server]`), (`[ORCHESTRATION-part:spec:output]`), (`[ORCHESTRATION-part:spec:deployment]`), and (`[ORCHESTRATION-part:spec:conformance]`)|Completed participating prose and current code form one graph with more than one hundred authored mints, no dangling citation, legitimate but non-total orphans, a fully populated ranked requested hub list, exact owner arithmetic, and current prefixes and reach data.|
|`the_assembly_of_the_specification_is_live_and_fresh`|(`[ORCHESTRATION-part:spec:architecture]`), (`[ORCHESTRATION-part:spec:dispatch]`), (`[ORCHESTRATION-part:spec:hooks]`), (`[ORCHESTRATION-part:spec:lanes]`), (`[ORCHESTRATION-part:spec:server]`), (`[ORCHESTRATION-part:spec:output]`), (`[ORCHESTRATION-part:spec:deployment]`), and (`[ORCHESTRATION-part:spec:conformance]`)|The adopted pair is retargeted to `docs/spec/` and `docs/spec.md`; all eight manifest rows and only those rows resolve once in approved order; the draft marker is absent; and the committed publication is the exact generated concatenation reported as one declared, zero dormant, one verified.|
|`the_repository_shape_report_is_sane`|(`[ORCHESTRATION-part:spec:architecture]`), (`[ORCHESTRATION-part:spec:output]`), and (`[ORCHESTRATION-part:spec:conformance]`)|The report measures the complete subscribed participating corpus, excludes generated documents, reconciles its document and environment totals, and reproduces every nearest-rank distribution without a configured benchmark, comparison verdict, edition field, or outlier list.|
|`the_repository_census_covers_every_test_function`|(`[ORCHESTRATION-part:spec:conformance]`)|The live AST census equals every cell and total of the committed package/area table, every test is covered, classified, and derivable, every area is populated, at most one source-parse failure exists and any such exception is owned, and the inherited four-thousand-test assertion is replaced by the committed current-workspace floor.|
|`the_repository_check_is_clean`|(`[ORCHESTRATION-part:spec:architecture]`), (`[ORCHESTRATION-part:spec:dispatch]`), (`[ORCHESTRATION-part:spec:hooks]`), (`[ORCHESTRATION-part:spec:lanes]`), (`[ORCHESTRATION-part:spec:server]`), (`[ORCHESTRATION-part:spec:output]`), (`[ORCHESTRATION-part:spec:deployment]`), and (`[ORCHESTRATION-part:spec:conformance]`)|The complete adopted check has no failing finding; every test represented by the committed table is correctly labelled with no profile defect; prose, owner declarations, six burn registers, projections, and the live assembly are current; and the labelled-count assertion uses the committed current-corpus basis.|

**Verification (Eight frontier tests)** · `verif:conformance:eight-frontier-tests`

Enumerate the frontier by exact test name and compare it with the eight rows of the ownership table, then run those eight tests unignored and unfiltered over the same reviewed source state. A row turns green only after every condition in its cell has independent evidence and the executable assertion has been retargeted without weakening its semantic checks. A removed, renamed, skipped, unexpectedly absent, or still-red test fails verification; so does an old scale, path, owner, benchmark, or assembly assertion surviving the retargeting.

**Invariant (Existing greens remain green)** · `inv:conformance:existing-greens-remain-green`

Every corpus integration test outside the eight-row frontier and every unit or subprocess contract test that was green at the accepted baseline must remain green in every campaign change. Frontier discharge may retarget repository facts but may not weaken fixture contracts, change informational-report semantics, relax calculus findings, or hide a regression by changing the test selection. The verification record separates expected frontier failures from any new failure so the former can never mask the latter.
