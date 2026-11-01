# `superloop-pack` · `guide:publicpack:public-pack`

`superloop-pack` builds provenance-bound ZIP archives from fixed Git tags and verifies them in an empty disk-backed staging directory. It executes typed child-process arguments and never invokes a shell.

## Command line · `sec:publicpack:command-line`

```text
superloop-pack build --tag TAG --out FILE.zip --burn-register PATH [--linter-version TEXT]
superloop-pack stage-verify --pack FILE.zip --burn-register PATH --linter PATH --staging DIR
superloop-pack cut --tag TAG --manifest public-set.toml --out DIR --author "Name <addr>" [--date RFC3339] [--public-tag NAME] [--message TEXT] [--tag-message TEXT] [--previous DIR] [--burn-register PATH] [--linter PATH]
```

`--linter-version` defaults to `unspecified`; supplying it binds an archive release's registered linter version into the manifest. All three commands declare `agent-text` output mode. Successful evidence and refusal lines go to standard output, followed by exactly one terminal report; `build` and `stage-verify` retain their path-free refusals:

```text
RUN-REPORT exit=STATUS wall=SECONDS.MILLISs verdict=VERDICT
```

A sole `--version` emits one JSON version record on standard error, leaves standard output empty and exits zero, or one if emission fails. Help and other accepted version argument forms retain their text and terminal report. Failure to publish the owned standard-output report also uses standard error.

## Public cut · `sec:publicpack:public-cut`

The cut command reads the tracked publication manifest from a clean checkout of the tag and writes only its selected Git blobs, preserving executable and symbolic-link modes. The public README source is consumed and published only at the root as `README.md`; the public manifest describes the emitted inventory. If a different README source is declared, a selected root `README.md` refuses and names the include selector to change to an exclusion with a reason. The manifest uses a namespace and version triple, include and exclude row tables, reserved exclusions, and a public table naming the required repository `name` (the default tag title is `NAME TAG`), README source, `licence_code` (`LICENSE-CODE`) and `licence_docs` (`LICENSE-DOCS`). Selectors ending in a slash are literal prefixes; other selectors support component-local `*` and `?` globs. Every tracked path must match exactly one row. Ordinary rows must match something; reserved rows may be absent. Excluded rows require reasons. Both licence files must be selected regular files; a missing code or documents licence refuses publication and names the missing path.

When the selected tree carries a linter snapshot, the cut writes a register of public citations whose definitions are excluded, recording only each label, its owner, and its manifest path class. The public snapshot declares that register; the linter reports those citations as resolved-unpublished and rejects uncited entries. Recutting a public tree retains its live unpublished addresses. The cut invokes the required `--linter` executable through its versioned `citation-sites` JSON protocol; pack does not link the linter library. This requires an outside-tree `--burn-register` in the existing values schema. Missing, empty, malformed, or source-contained inputs refuse. The guard checks each entry's label, owner and path class with the burn register's declared match kind after lowercasing both field and value (`identifier` bounded by ends or non-ASCII-letter bytes, `substring` anywhere); a refusal names the field and kind and never the value, and names the entry by its one-based ordinal (`entry N of M`) when any case-folded burn value occurs in its label. The audit input is never published.

An initial output must be absent or an empty directory and receives one root commit with no source history. For later releases, `--previous` and `--out` must resolve to the same clean public repository; one commit is added over its head, even when the tree is unchanged. The required author supplies both author and committer, commits are unsigned, and `--date RFC3339` sets both dates for initial and later commits (an explicit offset or Z is required, fractional seconds are truncated to Git’s whole-second precision); without it the source commit time supplies both dates. The default commit subject is `feat(release): publish NAME` with `--public-tag NAME`, or `feat(release): publish the source set` without it, with no body. `--message TEXT` overrides the whole message verbatim, requires non-empty text, and normalizes trailing newlines to one; the report records `message_override=yes` when supplied. The source commit remains in the cut report only. `--public-tag NAME` creates an annotated, unsigned tag on the public commit, validates its Git ref name, uses the publishing author as tagger and the commit date as tag date, and binds the release notes; identical inputs reproduce the same tag object, and the report includes `public_tag=NAME`. The tag message is `REPOSITORY NAME`, with REPOSITORY taken from required `public.name`, followed by a blank line and the body of the published `CHANGELOG.md` section `## [VERSION] - DATE` (NAME without its leading `v`), ending at the next `## ` heading with link reference definitions omitted and trailing blank lines trimmed; a missing file or section or an empty section body refuses with the required heading, while `--tag-message TEXT` overrides the whole tag message verbatim, refuses empty, whitespace-only or NUL text, and records `tag_message_override=yes`. The report gives copied files, bytes, public commit, stored date and tree hashes, tag, source commit and elapsed wall time. The public tree is assembled separately before publication, without Git content filters; unsupported entries, dirty inputs, overlapping source/output roots and moved tags refuse.

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
|3|Archive build refusal.|
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

The binary dispatcher exposes `build`, `stage-verify`, and `cut`. `stage-verify` explicitly extracts into the supplied staging directory and initializes its verification checkout before invoking the declared linter. There is no `verify` command or old executable alias. The source archive contains the supported `superloop-cli-common` and `superloop-execwrap` libraries under those package names.

## Publication follow-ups · `sec:publicpack:publication-follow-ups`

**Entry (Plan from tagged blobs)** · `entry:publicpack:blob-sourced-planning`

**OPEN.** Build citation planning and the owner snapshot rewrite from the tagged blobs, preserving the owner file's leading comment. Today the cut validates a clean checkout of the tag before reading these working-tree inputs; blob-backed planning would remove that second source of truth.

**Entry (Declare the unpublished register in the manifest)** · `entry:publicpack:manifest-register-declaration`

**OPEN.** Move the register destination and generation decision into the public manifest, and refuse excluded-definition citations without that declaration. Generation currently follows the selected owner snapshot. Retain the conservative whole-register substring guard; a generic value such as “index” may intentionally refuse a future address and calls for a better-scoped audit input, not a weaker guard.

The repository cut acceptance runs as Meson's `slow` test `cut-tree-acceptance`, using the built pack and candidate linter. Its shared 180-second budget covers the cut, linter check, single README mints and a Git archive configured with an explicit source commit. Cargo tests retain the small publication fixtures and refusal checks.
