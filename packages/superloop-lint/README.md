# Estate Label Linter · `guide:indexlinter:overview`

The estate's label-calculus linter for repository prose and source code.

Copyright (c) 2026 Torrust project contributors. Licensed under GPL-3.0-or-later; see [LICENSE-CODE](../../LICENSE-CODE).

Declare the repository carrier explicitly at top level in `.linter/owners.toml` with `root_owner = "OWNER"`, replacing `OWNER` with a name registered in `owners`. A root-files partition alone does not declare the carrier; paths outside every partition use this explicit root owner for label attribution while partition coverage still reports them. Assembly publication checks use `assembly.publications-current`.

## Overview · `sec:indexlinter:readme-overview`

This package is the checker the label calculus names as its gate. It reads the corpus's authored prose and its Rust sources, harvests every mint into its owner's registry, resolves every citation against those registries, validates every environment head against the kind registry read from the record's own tables, and reports what does not hold. Beside the gate it runs the inventory profiles for tests, to-do notices and declared constants, the claim census of the test documentation policy, the burn registers that ratchet a migration down to zero, and three generated surfaces — ADR-T-017's two projections, the in-file test index and per-folder test matrix, plus ADR-T-018's constant pins — which it verifies by exact byte comparison and rewrites on request.

The commands divide by whether they judge. The check, the assembly, the burn census, the Meson graph census, the projection verification, `fmt --check` and the fix sweep exit 3 when their reports carry failures or, for formatter check, files that would change; formatter write mode likewise exits 3 when it records a rejection, while successfully applying guarded changes exits zero. The report, the coverage and the shape commands describe and exit zero however long their listings run, because a mint nobody cites, a promise nobody has kept and a long environment are all ordinary and none of them is a defect.

Every judging command result carries its wall time as top-level `elapsed_micros`, and its completion log line carries the same wall.

Package attribution follows the declared partition's attribution of the package manifest, uses the declared root owner for the root package and carrier, and falls back to package-derived ownership only for uncovered packages; test, claim and todo profiles census only packages whose attributed owners activate their respective policies, and test and todo fixes use those same selections.

```sh
linter check --root . | jq .
linter coverage --root . | jq .
linter project --root . --write | jq .
```

## Judging command output · `sec:indexlinter:judging-command-output`

`check --root ROOT`, `project --root ROOT`, `assemble --root ROOT`, `fmt --check PATH...` and `census --root ROOT --declared FILE --excluded FILE --pattern REGEX [--required FILE]` have direct mode when neither output flag is present: their JSON report goes to standard output, which is refused when it is a terminal. With `--write-report FILE --write-stamp FILE`, they use build mode: the JSON report is published atomically and compare-if-changed, then an empty success stamp is touched; standard output stays empty. A completed verdict with findings exits 3, publishes its report and leaves the stamp untouched. A lone output flag is a usage error, and an existing nonempty stamp is refused without changing its bytes. Build reports omit measured wall time so equal results keep equal bytes.

`project --write`, `assemble --write` and `fmt` without `--check` write sources and refuse the output pair. The informational `report`, `coverage` and `shape` commands take no output pair.

A refused configuration leaves stdout empty and exits 1. Each JSON diagnostic puts the named refusal verbatim in `message` and `refusal`, retaining `the declared configuration is not a snapshot` as `kind`; the first message therefore names the first refusal. `check --text` prints each configuration refusal as a plain line on stderr instead, including when tracing is disabled. Completed checks still publish their usual JSON report.

## Meson graph census · `sec:indexlinter:meson-graph-census`

`linter census --root ROOT --declared FILE --excluded FILE --pattern REGEX [--required FILE]` audits the two newline-delimited repository-relative path lists and a Rust regex against the tracked-exclusive corpus; the optional TOML contract has a version array and rows carrying exactly `path`, `purpose`, `required` and `template`, and it lists required files, directory paths ending in `/` that must contain a tracked regular file, and last-component `*` patterns, while rows with `required = false` are ignored. It refuses an unlisted tracked path (`missing_path`), an untracked checkout path outside the shape's ignore rows (`untracked_path`), a missing tracked checkout path (`missing_tracked_path`), a stale declared or excluded path (`stale_declared_path`, `stale_excluded_path`), a declared path also matched by the pattern (`declared_pattern_overlap`), a repeated declared path (`duplicate_declared_path`), an index mode other than 100644 or 100755 (`invalid_tracked_mode`), a traversal failure (`traversal_failure`), a missing required file or directory (`missing_required_path`), an unmatched required pattern (`unmatched_required_pattern`), an invalid required list (`invalid_required_list`), and a required pattern with more than one `*` or a `*` outside its last component (`invalid_required_pattern`). The report names each refusal, and any refusal exits 3. Meson writes the two list files from its explicit graph lists at configuration; the census reads them on every build, including when no declared input changed.

## Public-pack burn contract · `sec:indexlinter:public-pack-burn-contract`

The optional `public-pack.values-absent` policy declares one raw whole-file burn surface on its activating owner's table. Its keys follow the other policy documents: `surface` is an ABNF path pattern, `values` is a canonical repository-relative path, and optional `exclude` is an ABNF relation whose literal openings are path prefixes removed from this family alone. A minimal fictional declaration is:

```toml
namespace = "class.linter.policy.public-pack.values-absent"
version = [1, 0, 0]

[owners.PROJECTA]
surface = "*VCHAR"
values = "local/linter/example-burn.toml"
exclude = '%s"local" [ "/" *VCHAR ]'
```

The selected document is TOML with one non-empty `values` array. Every entry has exactly `value`, a non-empty string, and `match`, either `substring` or `identifier`:

```toml
values = [
  { value = "sagofink", match = "identifier" },
  { value = "example-loop", match = "substring" },
]
```

Normal mode requires that repository document and refuses the command when it is absent, unreadable, malformed, or empty. For an extracted tree, the global `--public-pack` flag selects superloop-pack snapshot mode; if the repository document is absent, `--burn-input PATH` supplies its read-only replacement and must resolve outside the repository. `--burn-input` is invalid without `--public-pack`, while superloop-pack mode needs it only when an activated family has lost its repository document:

```sh
linter --public-pack --burn-input /read-only/example-burn.toml check --root extracted
```

An owner may explicitly add `activation = "public-pack"` to this policy's table. Normal mode then validates the declaration without reading the private values document or emitting a measured external family. Public-pack mode retains the non-empty document requirement and outside-tree input validation. Omitting `activation` retains the normal-mode requirement above. The only accepted selector is `public-pack`; unknown owner fields, selections, selector values and selector types refuse even in normal mode. The closed owner vocabulary is `surface`, `values`, `exclude` and `activation`.

Substring mode matches at any byte position. Identifier mode matches only when neither immediately adjacent byte is an ASCII letter; starts, ends, digits, hyphens, underscores, at-signs, and every other non-letter are boundaries.

Both check and burn reports carry top-level `public_pack`. Their per-family burn objects retain the existing prose, code, exclusion, census, ratchet, and row fields; the external-value family additionally carries `declared`, the `substring`/`identifier` `mode` counts, `source` as the path actually read, and `source_kind` as `repository` or `external`. In a check report these objects are under `burn.families`; in a burn report they remain in the top-level `families` array.

## Writing a label in prose · `sec:indexlinter:writing-a-label-in-prose`

A single-backtick span holding a bare label and nothing else mints the label where it stands, so writing that bare span twice in participating prose creates a duplicate mint that the check refuses. Parentheses hugging the same span cite the label the owner minted elsewhere; when the span's interior brackets another owner's registered prefix before the label, those parentheses cite that owner's mint. An import-shaped span without those parentheses is reported rather than read as text. A doubled-delimiter span or a fenced block exhibits the label as text and makes neither a mint nor a citation. Any other span matching no occurrence form is ordinary text, so commands, paths and file names can use the same delimiters.

```md
The witness is minted at `sec:demo:witnesses`, cited at (`sec:demo:witnesses`), and exhibited at ``sec:demo:witnesses``.
```

In the worked line, the first span mints the witness where it stands, the parenthesised second span cites that mint without minting again, and the doubled-delimiter third span exhibits its spelling without making an occurrence. Standing in running prose, that first span would also be reported as a mint that heads nothing, because a mint pairs only with a heading or with a paragraph that opens on a bold environment name; a label is minted at its head and cited everywhere else. A second bare span of the same label anywhere in the owner's participating prose is reported as a duplicate mint; refer to it again with the parenthesised form.

Source comments use corresponding acute-delimited forms with the same reading at warranted mint positions and in citations; in a comment, a parenthesis carrying prose beside the label is a malformed citation and is reported rather than read as text, while in Markdown prose such a parenthesis does not hug the span, which therefore reads as a bare mint.

The cross-owner form is the bracketed prefix ``[OWNER-kind:area:slug]`` inside the citation's parentheses and single delimiters. A prefix comes from the owner's declaration, and the cited label must stand in that owner's registry; a retired label in an imported registry therefore fails as an unresolved citation.

## Head policy and document titles · `sec:indexlinter:head-policy`

`labels.mints-well-formed` reads label syntax; `labels.heads-conform` separately validates the heads in the activating owner's share. The head policy requires the same owner's `labels.mints-kind-conform`, which requires `labels.mints-well-formed`. An owner activating only mint well-formedness receives no head check.

A first-level Markdown heading is read as the environment `Document`, irrespective of its title words. The adopted base relation does not catalogue that environment. An owner checking document heads therefore needs a local extension row for each title genre it uses, such as `{ environment = "Document", kind = "guide" }` in the `extensions` array of ``.linter/environments.toml``. This repository declares `guide`, `plan`, `proposal`, `rec`, `reg`, `rep` and `spec` as document-title extensions. These rows extend the effective registry without changing the adopted base relation or imported registry compatibility.

## Allowance declarations · `sec:indexlinter:allowance-declarations`

Every declared owner with attributed Markdown sources, including the root and crateless owners, must activate ``labels.mints-well-formed`` with its paired list; otherwise configuration fails rather than silently omitting that owner's prose.

Each activated owner-policy pair needs exactly one list in ``.linter/lists.toml``, using the policy's codec. A fingerprint policy's empty list is `allowances = []`; a nonempty list contains tables, not strings:

```toml
namespace = "class.linter.lists"
version = [1, 0, 0]

[VENDOR."labels.mints-well-formed"]
allowances = [
  { fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", maximum = 1 },
]
```

The fingerprint above illustrates syntax only. Use the fingerprint emitted for the actual finding: `sha256:` followed by exactly 64 lowercase hexadecimal digits. `maximum` is the admitted multiplicity. A string entry instead of the table refuses with `data did not match any variant of untagged enum ListEntry`; a list without its activation refuses with `a list stands at a pair nothing activates`; malformed fingerprint syntax refuses with `not a canonical fingerprint`. An activation's prerequisites must also be activated for the required owner and have their own lists: for example, VENDOR's `labels.citations-local-resolve` requires VENDOR's `labels.mints-unique`, or the loader names `policy dependency: VENDOR : labels.citations-local-resolve: missing same-owner pair VENDOR : labels.mints-unique`. That uniqueness policy in turn requires mint well-formedness. Lists do not activate policies, and allowances do not bypass declaration refusal.

## The corpus universe · `sec:indexlinter:the-corpus-universe`

`git-tracked` takes the version-control index as its base but does not inspect the checkout, so it cannot see an untracked file or a tracked file deleted locally; `as-written` takes checkout paths but does not inspect version control, so a file excluded by Git but not by the declared ignore relation can change the count between machines; `tracked-exclusive` takes the tracked base and holds the checkout to it after declared ignores, with `untracked_path` naming an uncovered checkout path and `missing_tracked_path` naming a tracked path absent from the checkout. A corpus that needs one declaration to give one number on every machine declares `tracked-exclusive`, because neither side can change unseen. A tracked path the checkout does not carry is reported once as `missing_tracked_path` and draws no reader failure, because the corpus has already named the repair and a failed open would name it again under a code that does not explain the absence.

## The area register · `sec:indexlinter:area-register`

Every claim this package mints names an area, and this register says what each area is for. The requirement it answers is ADR-T-017, The test documentation policy: an owner minting claims carries one register in its own prose, an entry per area, whose head prose states the stake — what is lost if claims of this area fail.

The stake is the one thing about an area that no census can compute and no individual claim states, because a claim says what the system does rather than why anyone should care that it does it. This owner is a peculiar case and the entries say so where it matters: because the package is the gate, the shallow answer for every area is that the gate stops meaning what it says, and the entries below are written to say instead what specifically stops being checkable and what a corpus would then quietly accumulate.

The areas are named after the modules that mint in them, with three exceptions worth knowing when a reader goes looking for the source: the owner area lives in the workspace-discovery module, the check area in the engine, and the report area is split across the finding taxonomy and the report envelope. That split makes the report area a genuine mixture, and the projection area — the largest here, covering two artefacts that share a staleness discipline and little else — is the clearest candidate for a split of its own. An unregistered area is a report line rather than a finding, so a claim minted in a new one is admitted and counted, and this register is what catches up.

**Section (adoption)** · `sec:indexlinter:area-adoption`

If this fails: the corpus loses its account of who owns what. Every resolution judgment runs through the signature, so a prefix mapping to no owner, or to two, decides whether an imported citation reaches a registry or reaches nothing — and a partition that leaves a source unowned quietly excuses that source from the calculus rather than failing it. Participation rides here too, and it now carries one datum rather than two: a document assembled from parts is read past, because its mints stand in the parts it was assembled from.

**Section (assembly)** · `sec:indexlinter:area-assembly`

If this fails: a document published from parts stops being those parts. Membership is checked both ways because the likely accident is writing a new part and forgetting to list it, which looks exactly like having finished; freshness is checked by exact byte comparison because a publication nobody republished is a document describing an older corpus. Lose either and a part is silently dropped from a publication, or an edited part sits unpublished indefinitely while the committed document reads plausibly and says something its own sources no longer say. The draft marker is the one deliberate suspension, and it suspends freshness alone.

**Section (burn)** · `sec:indexlinter:area-burn`

If this fails: the migration loses its ratchet. A register kept per file is what stops one document paying for another's regression, and it is checked in both directions, so a register allowed to overstate becomes a document about a corpus that no longer exists and the floor it was meant to be turns into a ceiling nobody has measured. The recognisers are the lint's own for the same reason: a census counting references its own way would drift from the gate's notion of what a reference is, and the tallies would keep falling while the debt stayed exactly where it was. Where a family censuses owner shares rather than the whole corpus, a register row is owned through the partition's attribution: when registering a crate as an owner re-cuts the partition, a row now attributed elsewhere makes the loader refuse the whole declaration, an audit names it as the `owner_path_mismatch` anomaly, and every append is refused while it stands, so the row leaves its former owner's table and the new owner records the debt by its own append, because silently following the re-cut would certify for the new owner debt it never counted.

A path-count ratchet row may carry `kept = "reason"` when its occurrences are settled and retained, such as text a machine reads or prints. Its reason must contain non-whitespace text. The census still counts the file, and the ratchet still refuses growth above its ceiling and a stale ceiling above the census; lowering moves that ceiling to the census. Only debt accounting changes: the report retains `registered` and divides it into `kept` and `owed`, so zero `owed` obtained by marking rows remains visible as marking because `kept` is reported beside it.

**Section (carrier)** · `sec:indexlinter:area-carrier`

If this fails: the checker judges a corpus that is not the one on disk. Everything downstream — minting, resolution, head validation — is drawn from whatever the carrier gathered, so a directory quietly skipped is a tree exempted from the calculus, and a document silently admitted is prose held to rules nobody meant it to meet. The distinction carrying the most weight is absence against unreadability: a tree that simply is not there costs nothing, while a tree that cannot be read must become a finding, because an unreadable corpus reported as an empty one passes every check there is.

**Section (census)** · `sec:indexlinter:area-census`

If this fails: the inventory stops being the tests that actually run. The census is read from the abstract syntax rather than from the bytes, so a test attribute inside a string literal, a macro body or a comment is never mistaken for the real thing, and files are enumerated rather than module declarations followed — the alternative visits one shared support module once per target and invents collisions that exist nowhere in the source. It also records the positions and indentation a later pass writes against, so an error here surfaces as a sweep laying lines in the wrong place rather than as a miscount.

**Section (check)** · `sec:indexlinter:area-check`

If this fails: a citation stops meaning that somebody said the thing. The two passes are kept strictly apart so that the order the corpus is traversed in decides nothing; resolution is total so that a label-shaped span reaching no mint fails rather than lapsing into text; and derived labels are seeded before the harvest so that prose citing a test breaks when the test is renamed instead of leaving a quiet lie behind. Weaken any of the three and the corpus goes on checking clean while accumulating references to statements nobody made, which is the exact condition the calculus exists to prevent. A declaration that activates nothing reports `nothing_governed` once beside any label-calculus findings, because the check still reads every workspace package's Rust sources for the labels they derive and the citations they carry whatever is activated, while prose joins that harvest only for an owner activating `labels.mints-well-formed`; a declaration the loader refused receives no such report, because the command has already refused it rather than measured a corpus.

**Section (claim)** · `sec:indexlinter:area-claim`

If this fails: what a test establishes stops being written down where the test is. The claim is authored rather than derived, so nothing computes it and nothing recovers it once the placement rules stop holding: a claim below the derived label, sharing its line with other words, or stacked two to a comment is a statement the projections will render wrongly or not at all. Shared coverage rests on the mint-and-citation distinction, so losing that turns a scenario covered many times over back into something a reader must count by hand across many files.

**Section (cli)** · `sec:indexlinter:area-cli`

If this fails: the gate becomes unusable from anything but a human's eyes. The check, assembly, burn census and projection verification decide and exit accordingly; report, coverage and shape describe without judging and exit zero however long their listings run, which is what keeps advisory information out of the pass-or-fail decision. The sweep's refusal over a dirty tree is the other guarantee: a mechanical edit across thousands of files is reviewable only against a clean baseline.

**Section (comment)** · `sec:indexlinter:area-comment`

If this fails: the linter reads its own fixtures as the corpus's debt. A string literal may carry anything, and these sources carry plenty holding exactly the shapes the registers count — a reject table, a test's expected output, a URL whose authority is introduced by two solidi — so a scanner reading a string as commentary produces a census that can never reach zero without renaming the code. The quiet failures are the awkward cases: a leading quote opening a lifetime rather than a literal swallows everything up to the next quote in the file, and a raw string closing early takes the rest of its line with it.

**Section (constant)** · `sec:indexlinter:area-constant`

If this fails: a value stops being answerable to the argument that fixed it. The pin is what makes a change loud — every citation of a value dangles in the commit that moves it — so a derivation that is not injective, or a program that accepts a shape it cannot encode, turns that alarm into a silence, and a corpus goes on citing a number the code no longer holds. The census is the other half: a declaration the census misses is a value nobody can adopt, and a local or a test fixture the census wrongly reads is a warrant demanded where no record could ever exist.

**Section (coverage)** · `sec:indexlinter:area-coverage`

If this fails: the corpus loses the instrument the scenario matrix retired behind. An intent is a statement written down in prose that no test yet carries, and the join between the two registries is the whole of the evidence that nothing was dropped when a document full of promises stopped existing. Nothing here moves an exit status, deliberately, so an error is invisible in the verdict and shows only as a reviewer being told a promise is kept when no test establishes it — or being steered by figures computed from some corpus other than the one the gate judged.

**Section (fix)** · `sec:indexlinter:area-fix`

If this fails: labels go back to being maintained by hand at a scale where nobody can maintain them. The sweep's whole licence is that it writes labels and never rewrites prose: every edit is a whole line inserted, a line replaced when that line was nothing but an attestation, or a notice's own marker line rebuilt from the parts its reader already parsed — no byte before the marker moved and no continuation line read at all — and a place it cannot reach any of those ways is handed back to its author rather than guessed at. Lose that boundary and a mechanical pass edits somebody's sentences across thousands of files at once. Idempotence is what makes the sweep safe to run at all, since one whose second pass differed from its first could never be trusted with the first.

**Section (graph)** · `sec:indexlinter:area-graph`

If this fails: outline review loses its instrument without losing its exit status, which is the worst way to lose one. None of these questions is a rule and none can be — a mint nothing cites is often exactly right, since whole genres of environment are minted to be flipped in place or pinned later — so the listings are advisory and a long one is something a reviewer reads rather than something a run fails on. The derived inventory stays out of every listing for arithmetic reasons: admit it and the orphan listing runs to thousands with the handful anybody wanted buried somewhere inside.

**Section (head)** · `sec:indexlinter:area-head`

If this fails: an environment stops having an identity. Minting and heading are two halves of one act, so a head carrying no label names nothing a citation could reach, and a label standing away from every head names nothing at all — and both failures read, in the source, as perfectly ordinary prose. The recognition has to be narrow in both directions at once: a paragraph merely opening in bold is how running text stresses its first words, and reading every one of those as an environment head would find heads throughout prose that heads nothing, while missing the real shape leaves whole documents unlabelled and unremarked.

**Section (label)** · `sec:indexlinter:area-label`

If this fails: nothing downstream can trust the shape of what it holds. A value of the label type exists only for text matching the grammar exactly, which is what lets every later stage read a kind, an area or a name off the value instead of splitting the text again and disagreeing about the result. Rendering back to the source text is what keeps a label written into a report or a projection the same string its author wrote. The ordering matters as quietly: a sorted registry and a sorted list of rendered labels must agree, or two views of one corpus disagree about what comes first.

**Section (layers)** · `sec:indexlinter:area-layers`

If this fails: a corpus cites what it never took on, and repo-wide policy stops being common. The empty may-cite relation is dormant and reconciles nothing, while one row wakes the reconciliation of every crate-bearing member against its manifest, because declaring reach commits to the whole graph and a declaration left partial would hide the rest of it. The root corpus's prose refuses every package-prefix import, even one its manifest reaches, before a declared row can admit it, because repo-wide policy resting on a package's private premise would cease to be common; it may cite an imported owner's published policy along a declared may-cite row, because that row takes the other repository's premise on as common policy. Every member reaches the crate-bearing root without a manifest edge, sideways imports between crate-bearing members follow manifest edges (a crateless endpoint needs an explicit row), and reach is reflexive but never transitive, because common policy must be citable by every member while an unstated second hop cannot license an import.

An imported owner is a crateless endpoint of the may-cite relation: a citing owner, including the root corpus's prose, needs an explicit ``may_cite`` row to reach it, and without one a resolved citation raises the ordinary ``unreached_import`` finding. It has no partition or manifest in the importing tree, so the reach reconciliation counts its declared edge as reach but does not compare that edge with a manifest dependency; the crate-bearing subrelation remains the one reconciled in both directions. The layer counters count an import from the root to any other owner as ``downward_imports``, including an admitted imported-owner citation, and an import between two non-root owners as ``sideways_imports``; imported mints resolve citations without entering this tree's mint count. The owner-reconciliation pin counts the declared owners as the manifest-derived owners, the repository owner and the imported owners, sorts rows aimed at imported owners with the crateless rows outside manifest comparison, and asserts that no imported owner receives a manifest edge. The declared-surface pin keeps its exact table of declaration documents, treats ``.linter/imports/`` as the registry loader's directory rather than a document, and adds imported owners to its owner count without adding partitions or declaration documents.

A local crateless owner's Markdown mints enter its declared owner's registry when ``labels.mints-well-formed`` is activated, and a prefixed citation resolves there before an explicit ``may_cite`` row admits it; a sibling ``.md.j2`` template contributes no second mint.

**Section (legacy)** · `sec:indexlinter:area-legacy`

If this fails: retiring a notation buys nothing, because the retired forms can still be written. The recognizer reads a source for the shapes the campaign leaves behind, and what holds a corpus to them is the burn ratchet: each family is enumerated per file in a register that may only shrink, over the surface its own list names. A per-document register in the checker was the earlier arrangement and it retires, because the ratchet already says which sources are counted and says it where the corpus can read it. Where a form may stand is as much of the rule as what it looks like: a form in code font is a token exhibited rather than a reference made, which is what lets the campaign's own documents name what they ban.

**Section (occurrence)** · `sec:indexlinter:area-occurrence`

If this fails: the difference between establishing a statement and referring to one stops being carried by the notation. Parentheses alone separate a mint from a citation, and brackets alone name another owner, so a reader confusing the forms either invents mints throughout ordinary prose or lets a cross-owner citation pass unresolved for the loss of two characters. Totality is what keeps the calculus safe to adopt: a span matching no form is ordinary text, so prose may quote commands, paths and file names in the same delimiters without any of them becoming an occurrence a run can fail on.

**Section (outline)** · `sec:indexlinter:area-outline`

If this fails: an outline becomes a document nobody can trust, which is worse than having no outline at all. The whole point of a document saying entry by entry what another must contain is that it can be believed, and it is only believable while something checks both directions — an entry claiming a head the document does not carry, and a head no entry claims, are equally drift, and a check running one way lets a document grow silently past its own contract. The relation is declared rather than inferred for the same reason: a checker guessing which of a row's citations was the target is the guess an outline exists to remove.

**Section (owner)** · `sec:indexlinter:area-owner`

If this fails: the signature stops matching the tree it describes. Prefixes are computed from crate names by one rule rather than transcribed, so a package joins the corpus by joining the workspace and nobody writes a prefix by hand at a mint; the record's own table of owners is checked against the computed set rather than believed, which is the only thing keeping the document and the workspace from drifting apart unremarked. A manifest that cannot be read has to be reported rather than passed over, because owners going missing quietly means a run over a damaged tree reports a smaller corpus and calls it clean.

The owner file lists both local and imported prefixes in ``owners``. Local owners take named ``partitions`` of this tree; imported owners instead use ``imports = [{ owner = "EXAMPLE", registry = ".linter/imports/example.toml" }]`` and cannot take a partition. A registry path is repository-relative and may stand anywhere under the root; ``.linter/imports/`` is the snapshot convention. The loader reads each registry before a command runs, refuses unreadable or malformed files, unknown namespace or major version, and a kind relation differing from the importing corpus's own. Imported mints resolve citations but do not enter this tree's mint counts.

**Section (profile)** · `sec:indexlinter:area-profile`

If this fails: a test's label stops being a fact about the test. The area comes from where the file sits and the name from the identifier with its separators rewritten, and nothing else feeds either, so a classification reading module nesting instead of the file would make a label change whenever somebody reorganised a source. Attestation is the sharper edge: the label at the standard place attests the derivation rather than naming the test, so a renamed function whose label was not updated must fail — otherwise a citation reaches a label that describes nothing any more, and the prose that cited it goes on reading as though it did.

**Section (projection)** · `sec:indexlinter:area-projection`

If this fails: the generated tables stop being owned by the labels and start being owned by whoever last typed in them. Both projections are compared byte for byte, so a hand-edit is indistinguishable from staleness and is treated as staleness: reported by the check, overwritten by the sweep. Recognition is by exact header row or by label rather than by position, which is what lets an author add a paragraph above a table without the generator losing track of its own region, and what leaves the corpus's many hand-written test tables as a migration backlog rather than as failures on the day the machinery lands.

**Section (prose)** · `sec:indexlinter:area-prose`

If this fails: the checker reads documentation as bytes rather than as prose, and the participation rule collapses with it. Delimiter pairing and block structure must be settled before any span's interior is read, or an occurrence inside a quotation or split across a wrapped list item reads differently from the same occurrence in a plain paragraph. The display boundary is what makes the calculus writable at all: a fenced block or a doubled-delimiter span exhibits a token without meaning it, so a document may show mints and citations while making neither, and an unpaired delimiter costs its own block rather than the whole file.

**Section (registry)** · `sec:indexlinter:area-registry`

If this fails: the vocabulary of environments stops being the recorded one. The classification relation is read from the decision record's own tables rather than transcribed, and the embedded edition is held against the committed document, so the two cannot drift apart unnoticed — a transcription would go stale in silence, and head validation would then reject names the record plainly catalogues. Presentation reduction is where the subtlety sits: prose must be free to qualify, number and nest a name without stepping outside the vocabulary, while a name catalogued in its own right has to beat the reduction that would strip it back to something it is not.

``linter export --root . --owner EXAMPLE --out labels.toml`` writes one local owner's labels in label order as deterministic TOML. Its ``namespace`` is ``class.linter.labels`` and its version identifies the format edition; an import under another namespace is refused with both the offending and expected namespaces. The ``source`` carries the owner and the exporting tree's full Git commit or ``unknown`` outside a checkout, ``kinds`` carries the declared environment, extension and reserved-kind relations, and each inline ``labels`` row names the label, its head, kind and repository-relative file. The importing corpus's entire ``kinds`` relation must equal the document's; a changed relation refuses the import before citation resolution.

The generic repository's bare checkout requires the public-pack snapshot configuration for export: run `orchestration-linter --public-pack --burn-input "$BURN" export --root . --owner ORCHESTRATION --out "$LABELS"` from that checkout. `$BURN` is a nonempty burn-values file outside the exporting tree, prepared from the generic repository's `docs/examples/linter/public-pack-burn.toml`; the public-pack burn contract governs its validation (`sec:indexlinter:public-pack-burn-contract`). Export without the snapshot configuration can refuse before writing labels, and a consumer's previously committed import does not establish that it matches the current generic label set.

**Section (report)** · `sec:indexlinter:area-report`

If this fails: a reader cannot act on what the run found. Locations count lines and columns from one and count columns in characters, so a reported position can be typed straight into an editor rather than landing past the text an accented letter displaced, and an offset beyond the end clamps rather than costing the whole run. The finding variants are kept apart on purpose because the repairs differ — one the sweep writes, one it rewrites, one only renaming fixes, one nothing may paper over — and the stable codes beside them are what let a consumer select the findings it cares about without parsing sentences. The configuration object's `activations` list carries one entry per activated pair — its owner, its policy, the `paths` the declared partition attributes to that owner, the `surface_paths` the policy's own declared surface reaches over the participating corpus where its census domain declares one, and the `findings` this binary ties back to the pair — beside `unattributed_findings`, the findings no pair produced, so that an activation governing nothing reads differently from one that measured a share and found nothing in it.

A finding's class is its `code` member.

|Code|Meaning|
|----|-------|
|``inactive_prose_owner``|Failure naming an owner, its Markdown source count, and the missing ``labels.mints-well-formed`` activation.|

The ``unresolved_citation`` finding names the searched owner and registered prefix for an imported label missing from that owner's registry; an unknown prefix remains ``unregistered_prefix``.

The report's `burn.declared` counts the burn lists declared by activated migration policies, not the policies themselves, with one list per family and every family named in `burn.families`.

A policy document copied from another corpus keeps that corpus's `prose`, `code`, and `exclude` surface paths until they are rewritten; when a burn policy censuses those paths, the report exposes them as `burn.families[].prose`, `burn.families[].code`, and `burn.families[].excluded`.

**Section (retired)** · `sec:indexlinter:area-retired`

If this fails: hundreds of references outlive the document that gave them meaning. Nothing outside the retired matrix defines what its ninetieth scenario is, or which promises one of its named divisions covers, so once that document goes a reference to either names nothing at all — and these references sit in test comments and planning prose where they read perfectly naturally. The bounds are what make the family countable: an unbounded rule would sweep up every mark and number in the corpus, giving the register a floor it could never reach, because reaching zero would mean rewriting prose that was never about the matrix.

**Section (shape)** · `sec:indexlinter:area-shape`

If this fails: the standard for a well-shaped record goes back to having no numbers attached to it. Nothing here is a rule and nothing may become one — a long environment may be exactly right, and a short one may be the sharpest paragraph in the corpus — so the report raises no finding and the reader decides. What gives the numbers their meaning is that the band comes from the documents the corpus already considers well shaped rather than from a constant somebody typed, and that divisions are measured apart, since a section heading whose next block is a subsection heads little but its own line.

**Section (snapshot)** · `sec:indexlinter:area-snapshot`

If this fails: a command stops having one coherent declaration snapshot to judge. The loader must distinguish absence from unreadability, keep the required surface closed, bind policy instance documents to their declared schemas, and join every owner-indexed list to a live activation; otherwise a command can silently run a partial policy or apply one corpus's declarations as another's.

The five required declaration documents — `owners.toml`, `environments.toml`, `policies.toml`, `lists.toml` and `shape.toml` — are found by filename. The namespaces of owners, environments, policies and shape are parsed and discarded, so these four kinds may keep corpus-owned identities such as ``org.example.linter.owners``. The lists envelope must be ``class.linter.lists``. Every ``policy-*.toml`` instance must carry a namespace beginning with ``class.linter.policy.`` followed by its declared domain; a catalogued policy's compiled identity fixes that domain unchanged across corpora. The loader refuses foreign lists and policy-instance namespaces before checking, naming the offending namespace and the expected identity or prefix. Renaming a document's file does not change its namespace identity.

Deployment keys shorten an instance namespace by removing the validated lists namespace's ``class.linter`` prefix; the remaining ``policy.<domain>`` component and the set entry identify the deployment. Policy activation is declared separately in ``policies.toml``. An instance under a corpus-owned prefix does not supply the catalogued policy's parameters or census surface and is refused rather than skipped; a genuinely absent census surface still receives the missing-surface finding. Corpora adopting this format rename lists, policy-instance and import-registry envelopes to the format namespaces while retaining their four corpus-owned core envelopes.

The `lists.toml` document is indexed by owner and every list pairs with a live activation, so it must be rewritten when the owner set changes.

Activations are per owner, with one pair for each owner and policy.

**Section (todo)** · `sec:indexlinter:area-todo`

If this fails: the deficiency backlog stops being measurable. A notice has no identifier the language gives it, so its author's own opening words are the identifier — the alternative, a slug written beside the label, is authorship wearing a derivation's clothes and lets the two disagree. Only the marker's own line feeds the name, which is what lets a reader confirm a label against the line it stands on and what stops re-wrapping a long notice re-deriving its label. The check and the register read through one recogniser for the reason the ratchet needs: two counters would eventually disagree about what a notice is.

## License · `sec:indexlinter:readme-license`

Copyright (c) 2024 The Torrust Developers.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 or any later version.

See [LICENSE-CODE](../../LICENSE-CODE) for details.

The binary dispatcher exposes `export`, `citation-sites`, `check`, `census`, `report`, `coverage`, `shape`, `assemble`, `burn`, `project`, `fix` and `fmt`. `check`, `census`, `report`, `coverage` and `shape` inspect their subjects. `export` publishes the selected labels; `citation-sites` emits the check recognizer's resolved citation sites as versioned JSON (`class.linter.citation-sites` 1.0.0) for the public cut, carrying addresses and paths but no document text; `assemble --write` and `project --write` regenerate their declared outputs; `burn --audit` and `burn --append` publish burn evidence; `fix --write` and ordinary `fmt` change their named subjects, while `fmt --check` inspects them. Build report and stamp publication requires the explicit pair `--write-report FILE --write-stamp FILE`; direct checking creates neither output. No old report or stamp option is accepted.
