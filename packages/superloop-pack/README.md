# `superloop-pack` · `guide:publicpack:public-pack`

`superloop-pack` builds provenance-bound ZIP archives from fixed Git tags and verifies them in an empty disk-backed staging directory. It executes typed child-process arguments and never invokes a shell.

## Command line · `sec:publicpack:command-line`

```text
superloop-pack build --tag TAG --out FILE.zip --burn-register PATH [--linter-version TEXT]
superloop-pack stage-verify --pack FILE.zip --burn-register PATH --linter PATH --staging DIR
superloop-pack cut --tag TAG --manifest public-set.toml --out DIR --author "Name <addr>" [--date RFC3339] [--public-tag NAME] [--message TEXT] [--tag-message TEXT] [--previous DIR] [--burn-register PATH] [--linter PATH]
superloop-pack replay --since SRC --tag TAG --manifest public-set.toml --out DIR --previous DIR --burn-register PATH --linter PATH --public-root OID [--accept-generated-drift]
```

`--linter-version` defaults to `unspecified`; supplying it binds an archive release's registered linter version into the manifest. All five commands (`build`, `stage-verify`, `cut`, `replay`, and `release`) declare `agent-text` output mode. Successful evidence and refusal lines go to standard output, followed by exactly one terminal report; `build` and `stage-verify` retain their path-free refusals:

```text
RUN-REPORT exit=STATUS wall=SECONDS.MILLISs verdict=VERDICT
```

A sole `--version` emits one JSON version record on standard error, leaves standard output empty and exits zero, or one if emission fails. Help and other accepted version argument forms retain their text and terminal report. Failure to publish the owned standard-output report also uses standard error.

## Public cut · `sec:publicpack:public-cut`

The cut command reads the tracked publication manifest from a clean checkout of the tag and writes only its selected Git blobs, preserving executable and symbolic-link modes. The public README source is consumed and published only at the root as `README.md`; the public manifest describes the emitted inventory. If a different README source is declared, a selected root `README.md` refuses and names the include selector to change to an exclusion with a reason. The manifest uses a namespace and version triple, include and exclude row tables, reserved exclusions, and a public table naming the required repository `name` (the default tag title is `NAME TAG`), README source, `licence_code` (`LICENSE-CODE`) and `licence_docs` (`LICENSE-DOCS`). Selectors ending in a slash are literal prefixes; other selectors support component-local `*` and `?` globs. Every tracked path must match exactly one row. Ordinary rows must match something; reserved rows may be absent. Excluded rows require reasons. Both licence files must be selected regular files; a missing code or documents licence refuses publication and names the missing path.

When the selected tree carries a linter snapshot, the cut writes a register of public citations whose definitions are excluded, recording only each label, its owner, and its manifest path class. The public snapshot declares that register; the linter reports those citations as resolved-unpublished and rejects uncited entries. Recutting a public tree retains its live unpublished addresses. The cut invokes the required `--linter` executable through its versioned `citation-sites` JSON protocol; pack does not link the linter library. This requires an outside-tree `--burn-register` in the existing values schema. Missing, empty, malformed, or source-contained inputs refuse. The guard checks each entry's label, owner and path class with the burn register's declared match kind after lowercasing both field and value (`identifier` bounded by ends or non-ASCII-letter bytes, `substring` anywhere); a refusal names the field and kind and never the value, and names the entry by its one-based ordinal (`entry N of M`) when any case-folded burn value occurs in its label. The audit input is never published.

An initial output must be absent or an empty directory and receives one root commit with no source history. For later releases, `--previous` and `--out` must resolve to the same clean public repository; one commit is added over its head, even when the tree is unchanged. The required author supplies both author and committer, commits are unsigned, and `--date RFC3339` sets both dates for initial and later commits (an explicit offset or Z is required, fractional seconds are truncated to Git’s whole-second precision); without it the source commit time supplies both dates. The default commit subject is `feat(release): publish NAME` with `--public-tag NAME`, or `feat(release): publish the source set` without it, with no body. `--message TEXT` overrides the whole message verbatim, requires non-empty text, and normalizes trailing newlines to one; the report records `message_override=yes` when supplied. The source commit remains in the cut report only. `--public-tag NAME` creates an annotated, unsigned tag on the public commit, validates its Git ref name, uses the publishing author as tagger and the commit date as tag date, and binds the release notes; identical inputs reproduce the same tag object, and the report includes `public_tag=NAME`. The tag message is `REPOSITORY NAME`, with REPOSITORY taken from required `public.name`, followed by a blank line and the body of the published `CHANGELOG.md` section `## [VERSION] - DATE` (NAME without its leading `v`), ending at the next `## ` heading with link reference definitions omitted and trailing blank lines trimmed; a missing file or section or an empty section body refuses with the required heading, while `--tag-message TEXT` overrides the whole tag message verbatim, refuses empty, whitespace-only or NUL text, and records `tag_message_override=yes`. The report gives copied files, bytes, public commit, stored date and tree hashes, tag, source commit and elapsed wall time. The public tree is assembled separately before publication, without Git content filters; unsupported entries, dirty inputs, overlapping source/output roots and moved tags refuse.

## Replay · `sec:publicpack:replay`

`replay` performs the one-time transition from private source history to public development history. Run it in a clean source checkout with HEAD at TAG. SRC and TAG accept commit IDs or refs and are reported as full IDs. Both `--out` and `--previous` must name the same clean public clone, checked out on `development` at exactly `--public-root`; a mismatch reports both IDs. An empty range refuses with `nothing to replay`.

The command preflights the entire first-parent range SRC..TAG, oldest first, and refuses merges, disconnected ancestry, invalid identities, unsupported entries, missing licences and invalid manifests. TAG's committed manifest is read once and supplies the sole projection policy for every tree: selection rows, public name, README source and licence paths. Historical manifests are never decoded as policy, so older schemas cannot block replay; even a path excluded historically is public history when the final rows select it. The burn scan remains the guard against private values. The selected manifest is rendered as a public snapshot using the final policy, consuming exclusion and reserved rows. Owners and unpublished citations come from each historical tree using the final rows. Both final licence paths must exist as selected regular files in every tree; a refusal names the commit. README replacement uses the same projection functions as `cut` when the final README source exists. Otherwise the historical root README is retained unchanged; each mapping records `readme_fallback` and `readme_fallback_commits` counts these source commits (including skips, excluding SRC). None of these inputs comes from today's working tree.

Citation planning materializes one historical input tree at a time in a disposable directory under TMPDIR, invokes the linter's `citation-sites` protocol, and removes that directory before continuing. These scratch reads bypass Git filters and hooks and never live under the output repository. Set TMPDIR to a private disk-backed directory outside both checkouts; the report records it as `scratch_root`. No output object, ref, staging directory or report file is written before the whole-range preflight passes.

The external, nonempty burn register scans every projected path and blob, every source message, and both identities, including commits that will be skipped. Matching uses the register's case-folded identifier or substring rules. Refusals identify the source ordinal, field and match kind without printing the matched value. Private messages and identities require a separately reviewed source decision; replay never silently sanitizes them. Unsupported metadata that cannot survive the unsigned `commit-tree` writer refuses.

The projected SRC tree must match the public root. Differences refuse as `generated drift` with the affected paths unless `--accept-generated-drift` explicitly accepts them. Accepted drift is recorded and enters the first changed public tree. After preflight, a private staging repository holds only public ancestry and projected objects. Every projected tree passes the linter's public-pack check with evidence that it consumed the external register. A tree equal to its mapped parent's tree is listed as `skipped` and maps to that parent. Otherwise one unsigned, single-parent commit preserves the original author, committer, timestamps, timezone offsets and message bytes. Source signatures are omitted and reported. Only after all checks pass does an expected-old update advance `development`.

Keep the JSON report private: it records the full range, public root and final tip/tree, ordered mapping and parent mapping, original and resulting identities and dates, message digests, selected and omitted path counts, drift, projection/linter versions and digests, policy/register digests, and check exits and wall seconds. A human summary and the terminal report follow the JSON on stdout; no report is placed in the public clone. Identical inputs reproduce identical public objects and mappings; timing and scratch locations are observational fields. `cut` remains available for historical publication reproduction and selection tests, outside normal import, deployment and release.

## Release · `sec:publicpack:release`

```text
superloop-pack release --repository DIR --version X.Y.Z --manifest public-set.toml --author "Name <addr>" [--date RFC3339] [--tag-message TEXT] [--changelog CHANGELOG.md] [--expected-main M] [--expected-development D] [--check | --dry-run]
```

Release runs against a clone of the public repository with `main` and `development`. Run `--check` before deployment and retain its M and D; after successful deployment, pass those full object IDs as `--expected-main` and `--expected-development`. Apply requires both pins and refuses with `unpinned` if either is absent; `--check` and `--dry-run` may omit them. The working tree must be clean, main must be an ancestor of development, and development must differ from main. An existing version tag refuses. The root workspace version at D must equal the requested version, the manifest at D must name the public repository, and the selected changelog at D must contain a non-empty `## [X.Y.Z]` section (optionally followed by ` - YYYY-MM-DD`). Paths are repository-relative. Validation reads committed D blobs even when another branch is checked out.

The command creates an unsigned merge R with parents M then D and exactly D's tree, with subject `chore(release): merge development into main for vX.Y.Z`. The supplied author is both author and committer; both dates use `--date` or D's committer date and offset. The annotated tag's title is `NAME vX.Y.Z` from the manifest name; its body is the matching changelog section, with reference definitions omitted and trailing blank lines trimmed. `--tag-message` replaces the tag text verbatim, while the changelog section remains required. Empty, whitespace-only and NUL-containing overrides refuse.

Apply stages objects privately, then locks and verifies both branches and tag absence in one Git expected-old transaction before promoting objects and committing all three refs. A stale development tip refuses without advancing either branch or publishing the tag; the deployment coordinator must wait for a successful deployment of the newer development. A conflicting tag requires reconciliation, never replacement or a different version chosen to bypass the conflict. The release contains D, so advancing development to R needs no force push. A release is never rewound: a bad deployment gets a corrective deployment and the next patch.

`--check` validates and reports state `checked`; `--dry-run` reports state `prepared`. Both compute the prospective objects without writing repository objects or refs. Apply reports `locally-committed`. Each report gives M, D, R, the tree, annotated tag object, JSON-quoted title, body byte count and exactly these three refspecs:

```text
refs/heads/main refs/heads/development refs/tags/vX.Y.Z
```

The superloop's transport script holds its coordination lock through remote acknowledgement and pushes those three refs together with `git push --atomic REMOTE refs/heads/main refs/heads/development refs/tags/vX.Y.Z`. It must refuse a remote without atomic push support. Pack never pushes or signs. After transport failure, retain the prepared local objects and revalidate local and remote tips under the coordination lock before retrying exactly those objects; never overwrite intervening imports. Remote acknowledgement is recorded by the script. A clone checked out on old main may need its index and working tree synchronized afterward; the command changes refs and objects only.

## Archive build · `sec:publicpack:archive-build`

The build command resolves `TAG` as a tag ref, its commit, tree, and commit time. It requires `HEAD` to equal that commit and `git status
--porcelain=v1 --untracked-files=all` to be empty. Git creates the unmanifested archive directly from the tag's object database with the pathspec `.` and `:!local`; ignored, untracked, and modified working-tree bytes therefore cannot enter even if the work tree changes after preflight.

The command hashes that archive, parses and hashes the non-empty burn register, renders the provenance member, and creates the final ZIP with Git's typed `--add-file` mechanism. A fixed `--mtime` equal to the commit time applies to both archives. The tag is resolved again before a mode-0644 staged file is renamed over the destination. A missing or moved tag, dirty or wrong checkout, malformed register, failed Git archive, or failed publication refuses the build. Success prints the final ZIP SHA-256 followed by the complete manifest.

## Provenance manifest · `sec:publicpack:provenance-manifest`

The member `docs/public-pack-provenance.toml` has this strict schema; unknown fields refuse verification:

```toml
pack_format = 1
tag = "v1.0.0"
commit = "0123456789abcdef0123456789abcdef01234567"
tree = "89abcdef0123456789abcdef0123456789abcdef"
archive_sha256 = "64 lowercase hexadecimal digits"
burn_register_sha256 = "64 lowercase hexadecimal digits"
burn_register_count = 2
linter_version = "registered version text"
```

`archive_sha256` identifies the deterministic ZIP before the manifest is added. The digest printed by the command identifies the complete published ZIP. The register count uses the linter's strict TOML shape: one non-empty `values` array whose entries contain exactly a non-empty `value` and a `match` value of `substring` or `identifier`.

## Verification · `sec:publicpack:verification`

Verification performs these checks in order and prints every outcome and wall duration. When one refuses, every later check is printed as skipped.

1. `staging` (status 4) requires an absolute, existing, empty directory whose complete component chain contains no symlink. Its filesystem device ID must equal the device ID of the process temporary root. The report prints both IDs and `same_mount=yes`; the registered temporary root is the disk-backed storage-class reference.
2. `archive_members` (status 5) parses the ZIP end record, central directory, and every corresponding local header before extraction. It rejects ZIP64, split, encrypted, non-UTF-8, duplicate, escaping, absolute, backslash, symlink, special-file, `local/`, and `.git/` members, plus local/central name disagreement and file/descendant collisions.
3. `extraction` (status 5) invokes `unzip` directly with typed arguments, then proves the extracted regular-file/directory tree exactly equals the audited member tree and contains no symlink or special file.
4. `manifest` (status 6) reads the strict provenance member and validates its format, object IDs, digests, non-zero register count, and non-empty fields.
5. `burn_register` (status 7) requires the supplied register to resolve outside staging, parses the same strict non-empty shape, and matches its raw-byte SHA-256 and entry count against the manifest.
6. `inert_index` (status 8) runs typed `git init -q` and `git add -A` in staging. It creates no commit and imports no history.
7. `linter_execution` (status 9) directly runs the supplied executable as `check --root DIR --public-pack --burn-input PATH` and parses its single JSON result. Only the linter's declared success or findings statuses reach the verdict check.
8. `linter_verdict` (status 10) requires process success, `clean: true`, zero failures, `public_pack: true`, and zero `owed` in the burn block and its family rows. At least one family must bind the supplied register through `source_kind: external`, its exact `source` path, and a positive `declared` value count. Every bound family must have zero occurrences, including kept occurrences: a public pack never carries a registered private value. Growth (`occurrences > registered`) is `burn_evidence` even when the linter exits with findings. Only a burn refusal carries family details, naming only the rows responsible for debt, growth, private occurrences, or a failed register binding. The summary's `burn_declared` retains its value-count meaning: it sums declared values in the bound external families, not the number of burn families.

The verifier proves standalone root conformance, absence of owed burn debt, and a non-vacuous zero census of the supplied register's values. A clean linter report without a bound external family refuses because it does not prove the register was read. It intentionally does not build the extracted workspace. The release orchestrator performs the third proof: a package-scoped build of those exact extracted bytes on its registered build machine, bound to the manifest source identity.

Activating `public-pack.values-absent` requires a policy document naming the values file and a burn-list section as well as the activation row. The policy's owner section accepts `surface`, `values`, `exclude`, and the optional `activation = "public-pack"`; unknown fields and other activation values refuse. Without that selector, plain checks retain the requirement for a repository-local, non-empty values document. With it, plain `check --root .` validates the declaration but does not read or report that private-value census. Public-pack mode still requires the approved register and reports its measured burn family.

For a pack-only policy owned by TOOLS, the owner section can read:

```toml
[owners.TOOLS]
activation = "public-pack"
surface = "*VCHAR"
values = "local/linter/public-pack-burn.toml"
exclude = '%s"local" [ "/" *VCHAR ]'
```

Keep that approved document untracked under the excluded `local/` tree. Add `/local/` to Git's ignore rules because the build refuses visible untracked paths, and declare a corpus-shape ignore row such as `{ name = "private-register", pattern = '%s"local" [ "/" *VCHAR ]' }` when the universe is `tracked-exclusive`. Ordinary worker and review clones then need no private inventory. The build excludes `local/`, and verification reads its supplied register from outside staging. Public-pack mode uses that external input only when the declared local document is absent; a shipped values document outside `local/` selects `source_kind: repository` and cannot satisfy the verifier's external binding. An empty or invented register is not a substitute for the approved inventory.

The ownership declaration must also account for the generated `docs/public-pack-provenance.toml` member. A narrow documentation partition can explicitly include that path alongside its existing public guide without admitting every document. The real-linter fixture checks both the owned member and its omission: the same source passes a plain check without private values, but only the pack with declared provenance ownership verifies.

This follows the gate's root/probe distinction: the root check has no burn input; the probe checks archived bytes without `local/`, with an external register. Verification consumes the `burn` evidence from that superloop-pack `check` result. It retains the stronger requirement that the supplied register was actually read and has zero private occurrences; it does not replace that evidence with a separate burn invocation or accept a clean but unmeasured census. Deploy a linter that understands the selector before activating it in a repository's shared policy documents.

## Exit statuses · `sec:publicpack:exit-statuses`

|Status|Meaning|
|-----:|-------|
|0|Success, help, or version.|
|1|Internal or report-publication failure.|
|2|Invalid command arguments.|
|3|Archive build, cut, replay or release refusal.|
|4|Staging refusal.|
|5|Archive-member or extraction refusal.|
|6|Manifest refusal.|
|7|Burn-register refusal.|
|8|Inert-index refusal.|
|9|Linter launch or JSON-report refusal.|
|10|Linter acceptance-verdict refusal.|

Panics are caught behind a silent panic hook. Neither payloads nor Rust's default panic text are published.

## Library surface · `sec:publicpack:library-surface`

`build` and `verify` accept explicit request values and return successful evidence or typed, path-free refusals. `write_build_report` and `write_verify_report` publish those results under the binary's output contract.

## Test register · `sec:publicpack:test-register`

The package tests create fictional Git repositories in disk-backed temporary directories. They cover object-database exclusions and provenance round trips, dirty checkout and moved-tag refusals, a green stub-linter verification, forbidden archive members, register mismatch, non-empty staging, owed burn debt, false superloop-pack reports, and agent-text help and usage paths. End-to-end fixtures build packs in-process and verify them with the executable named by `PUBLIC_PACK_TEST_LINTER`, which a route running these tests must set to the absolute path of its registered linter. They cover a clean bound external family, refusal of an unread register, family-named growth refusals, registered debt, refusal of kept private values, and pack-only activation with an ignored untracked register and narrow provenance ownership. An absent variable fails by name; the tests never search `PATH` or silently skip the real-linter fixtures.

The binary dispatcher exposes `build`, `stage-verify`, `cut`, `replay`, and `release`. `stage-verify` explicitly extracts into the supplied staging directory and initializes its verification checkout before invoking the declared linter. There is no `verify` command or old executable alias. The source archive contains the supported `superloop-cli-common` and `superloop-execwrap` libraries under those package names.

## Publication follow-ups · `sec:publicpack:publication-follow-ups`

**Entry (Plan from tagged blobs)** · `entry:publicpack:blob-sourced-planning`

**PARTIAL.** Citation planning and the owner snapshot rewrite now read the selected commit's blobs. Preserving the owner file's leading comment remains open; the existing snapshot serialization is unchanged.

**Entry (Declare the unpublished register in the manifest)** · `entry:publicpack:manifest-register-declaration`

**OPEN.** Move the register destination and generation decision into the public manifest, and refuse excluded-definition citations without that declaration. Generation currently follows the selected owner snapshot. Retain the conservative whole-register substring guard; a generic value such as “index” may intentionally refuse a future address and calls for a better-scoped audit input, not a weaker guard.

The repository cut acceptance runs as Meson's `slow` test `cut-tree-acceptance`, using the built pack and candidate linter. Its shared 180-second budget covers the cut, linter check, single README mints and a Git archive configured with an explicit source commit. Cargo tests retain the small publication fixtures and refusal checks.
