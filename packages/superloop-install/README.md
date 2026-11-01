# `superloop-install` · `guide:rulebookinstall:rulebook-install`

`superloop-install` deterministically renders generic Markdown bases with instance overlays and installs source files and verified build outputs through a content-diffed transaction. It creates independent copies, never managed symlinks, and executes no shell or script.

## Command line · `sec:rulebookinstall:command-line`

```text
superloop-install --map PATH [--root PATH] [--build-root PATH] [--shape-root PATH] [--registry PATH] [--destdir PATH] [--release-tag TAG --release-commit COMMIT] [--dry-run]
superloop-install inventory --stage PATH --prefix PATH --repository NAME --source-commit COMMIT --report PATH
superloop-install retire --old-inventory PATH --new-inventory PATH --prefix PATH [--destdir PATH] --recovery PATH --report PATH [--destination RELATIVE_PATH]...
```

`--map` is required for the map-install form. Repository input paths resolve below `MESON_SOURCE_ROOT` when Meson supplies it, or the process working directory otherwise. `--root` substitutes an absolute destination boundary, chiefly for staging and tests; for a registry map it is a parent beneath which each loop name gets a root. `--build-root` is the absolute boundary for build outputs and their records. `--registry` substitutes a registry file; `RULEBOOK_INSTALL_REGISTRY` is its environment fallback for Meson install scripts. `--destdir` or Meson's `DESTDIR` stages the resolved roots beneath an absolute directory, creating their missing prefix after preflight. An install given `--root`, `--destdir` or `DESTDIR` is a staging install and any other is live, because existing staging callers such as the permission-triage deploy dry run pass `--root` without a release identity; the Meson install scripts pass none of the three, so a live `meson install` keeps both the release and the domain checks. `--release-tag` and `--release-commit` must occur together; a live install requires them, while a staging install without them reports `untagged`. `--dry-run` performs the complete parse, render, path, type, mode, and state preflight and reports predicted outcomes without creating directories, backups, temporary files, or targets.

`--shape-root` resolves a render base below its normalized absolute directory instead of the repository root and includes that directory in the reported map identity, while overlays and copy sources remain repository-relative.

The binary declares `agent-text` output mode. Standard output carries one line per skipped or refused registry loop, then one declaration-order line per target, one count summary, then exactly one terminal report in this field order:

```text
RUN-REPORT exit=STATUS wall=SECONDS.MILLISs verdict=VERDICT
```

Successful target lines use `unchanged`, `new`, or `changed`. A staged build whose record domain differs from the map reports `domain-mismatch` with its byte state, and the summary counts it. A changed line names whether its `.pre-deploy` backup was planned or written, whether an older backup was replaced, and the matching outgoing and verified-backup SHA-256 digests. Identity, mode, and nanosecond mtime evidence contains only numeric filesystem metadata; target paths are deliberately identified by their one-based plan index. A refusal line names a stable class and reason without echoing a caller-supplied path, except that a registry refusal names the loop and root path. A plan-wide error also prints its primary class and reason even when no target index was assigned; target lines marked `plan_refused` do not replace that diagnostic. The summary counts each byte outcome and skipped loop, records dry-run state, map SHA-256, release identity and total wall time, and names the last completed step. Standard error is reserved for a failure that prevents publication of the owned standard-output report.

## Reviewed retirement · `sec:rulebookinstall:reviewed-retirement`

The bootstrap deploy has no reviewed predecessor inventory: retain the first native install's staging report and staging inventory beside its build records as the inventory of record. Predecessors with no remaining caller retire once by the hand route, with their paths listed and their bytes archived with digests under the deploy's evidence. The inventory route applies from the next deploy onward; rehearse `retire` under `--destdir` over a fixture holding the previous staging, using that retained inventory and the successor's inventory.

The `inventory` form reads a separately staged release beneath `STAGE/PREFIX`. Its JSON records the repository, full source commit, prefix, relative destinations, full SHA-256 digests and modes. Capture the old inventory from reviewed release sources or build outputs, never by blessing the live targets. Preserve it independently of Meson's latest install log. An inventory covers native and migration-map files in the same prefix; a provenance sibling is a separate destination.

The `retire` form compares old and new inventories with equal repository and prefix identities. It selects only old destinations absent from the new release; repeated `--destination` options narrow that set. With `--destdir`, every managed path is staged beneath that directory. The recovery directory and JSON report must be outside the managed prefix, and the report must be outside recovery. Use absolute paths, a caller-owned staging tree with no group or other write permissions, and a separate recovery parent on the same filesystem. An absent recovery directory is created with mode `0700`.

All selected files pass ownership, regular-file, single-link, mode and full-digest checks before the first move. Descriptor-relative traversal refuses symlinks. Each move uses an exclusive destination and verifies the moved inode and bytes. The durable JSON report names both source commits, every planned recovery destination, completed moves and a later conflict. If a concurrent change interrupts the operation, inspect that report and recovery bytes before retrying. A second invocation recognizes verified recovery files and reports `destinations=0`; a missing source without matching recovery refuses. No new-release destination is eligible for retirement.

## Install-map schema · `sec:rulebookinstall:install-map-schema`

The TOML document has exactly one of `root` or `[registry]`, plus `targets`. Unknown fields refuse. `root` is an absolute deployment directory or a `~/` path resolved against the invoking `HOME`; a live root already exists and is not a symlink. `[registry]` has `path`, a `~/` path to the loop registry, and `root`, a `~/` pattern with exactly one `{name}` placeholder, plus optional `missing_root = "refuse" | "skip"`. The default `refuse` policy refuses the entire plan before mutation and reports each unavailable registry root with `reason=root-unavailable loop=NAME root=PATH cause=CODE`. The cause distinguishes `root_unavailable` for a missing component, `root_symlink`, `root_not_directory`, `root_inaccessible`, `root_metadata` for other metadata errors, and `invalid_root` for an invalid absolute root. An invalid root shape retains `class=map reason=invalid_root` with the same loop, root and cause context. The production entry normalizes absolute roots before checking their components. Owner-owned mode-0700 directories remain admissible with a POSIX ACL entry; the check rejects unsafe path components, not the presence of an ACL. The `skip` policy omits absent roots, reports each omitted loop with `outcome=skipped`, its name and root path, and counts omitted loops as `skipped` in the summary; existing unsafe roots still refuse. The live hand form requires both release identity arguments even for `--dry-run`: without them it reports `target=map outcome=refused class=map reason=release_identity` once and lists resolved registry loops and roots with `outcome=not_reached class=plan reason=plan_refused`, without a measured root `cause`. A registry-read or root-pattern failure is reported separately with `outcome=unresolved` and `stage=root_resolution`; it does not replace the release-identity refusal. Both `--root` and `--destdir` select staging forms that do not require release identity. The installer reads the registry through `loop-home` and installs for the remaining loops in file order. `--destdir` still permits missing staging roots to be created. Each `[[targets]]` entry has `kind`, `destination`, and `mode`; destinations are normalized relative paths below each root. `mode` is a quoted, exactly four-digit octal value such as `"0644"` or `"0755"`.

A deployment with two destination roots uses two maps, one per root: each map names one root, and no destination may escape it.

A copy entry has `kind = "copy"` and exactly one repository-relative `source`, with optional `provenance = true`; it has no `output`, `domain`, `base`, `overlay`, or `max_bytes`. A render entry has `kind = "render"`, a relative `base`, a repository-relative `overlay`, and optional nonnegative `max_bytes`; it has no `source`, `output`, `domain`, or `provenance`. A build entry has `kind = "build"`, `output` normalized relative to `--build-root`, `destination`, `mode`, and `domain`; it has none of the copy or render fields. A target carrying fields belonging to another kind is a map refusal.

When `--shape-root` is given, a render target's `base` is relative to that directory and must remain within it as a regular, symlink-free input; without the flag the existing repository-relative base rule applies.

```toml
[[targets]]
kind = "build"
output = "packages/example/example-bin"
destination = "example-bin"
mode = "0755"
domain = "trusted-host"
```

```toml
[registry]
path = "~/.config/loops/registry.toml"
root = "~/.config/loops/{name}/claude"

[[targets]]
kind = "copy"
source = "docs/worker-instructions.md"
destination = "CLAUDE.md"
mode = "0644"
```

The example at `docs/examples/rulebooks/install-map.toml` uses fictional paths. A minimal shape is:

```toml
root = "/srv/example/example-user/harness"

[[targets]]
kind = "copy"
source = "examples/sagofink/shared.md"
destination = "shared.md"
mode = "0644"

[[targets]]
kind = "render"
base = "examples/sagofink/base.md"
overlay = "examples/sagofink/overlay.md"
destination = "rules.md"
mode = "0644"
max_bytes = 9500
```

Duplicate normalized destinations refuse. A target destination may not occupy another target's reserved `.pre-deploy` or `.provenance` sibling, including the provenance sibling's backup. Absolute or root-escaping source, output and destination paths refuse. Input components and destination components are inspected without following symlinks; inputs must be regular files, and a live destination root must be a real directory. Build outputs require `--build-root` and a sibling `<output>.build.json` record whose SHA-256 equals the output; an output outside the build root or a missing output or record refuses. A record domain differing from the target's refuses live installation but is installed and counted as `domain-mismatch` in staging so server outputs can prove the live maps.

## Rendering · `sec:rulebookinstall:rendering`

A base slot is one complete line with exact bytes `{{overlay:LABEL}}`. A label uses the repository register's colon-separated ASCII spelling. The overlay starts immediately with a labeled Markdown heading and consists of complete sections. One section runs from its labeled heading through the byte before the next heading of the same or higher level, or through end of file; lower-level headings remain section content.

The renderer indexes unique overlay sections, validates the complete slot/section bijection, rejects a slot label already carried by a base heading, then substitutes section bytes in base slot order. It preserves every non-slot base byte and every selected section byte. Duplicate slots, duplicate overlay sections, missing or unused sections, malformed overlay section boundaries, and any surviving `{{overlay:` bytes refuse. `max_bytes` measures the final byte vector, inclusive at the declared limit. No timestamp, environment value, or Markdown reformatting enters the output.

The installer loads a `--shape-root` base through the same regular-file and component checks as other inputs, refuses a missing or escaping base in the source class, and continues to load the overlay from the repository.

## Transaction · `sec:rulebookinstall:transaction`

Preflight reads and materializes every input, normalizes every path, rejects destination, backup and provenance collisions, inspects every existing destination, and validates every mode before the first target mutation. An equal regular destination is admissible only at the exact declared mode and must not share its inode with an input. The execution phase re-stats and re-reads the target before acting, so a changed identity, bytes, mode, or nanosecond mtime refuses as concurrent change. With `DESTDIR`, the stage prefix is created after preflight and each target is installed below the stage joined to the resolved map root.

An unchanged target receives no write, rename, chmod, backup, parent creation, or timestamp operation. Its identity, exact bytes, mode, and nanosecond mtime are re-proven against preflight. A missing target is written to an owner-private sibling temporary, flushed, synchronized, assigned the declared mode, and renamed once into place. A changed target first stages the exact outgoing bytes to the `.pre-deploy` sibling, verifies those bytes, revalidates the live target, then performs the same one-rename installation. Mode changes happen before rename, and a staged changed file is forced to a modification stamp distinct from the outgoing file if the filesystem initially gives both the same stamp.

After each replacement the installer re-reads type, bytes, exact mode, input independence, identity transition, and, for a changed target, nanosecond mtime transition. Every build target and every copy with `provenance = true` then installs a reserved `<destination>.provenance` sibling at 0644 under those same byte, backup and mtime rules. Its six lines are `source-repo`, `source-commit`, `dirty`, `built`, `build`, and `sha256-prefix`; the installer derives them from the verified build record or copy source, the SHA-256 it checked, and `git rev-parse HEAD` and a clean-tree check run directly in the repository. Equal bytes leave both files untouched; a new commit over equal target bytes changes only provenance. A failure stops later targets. The refusal report records all completed target outcomes, every target whose destination or backup was touched, and the last completed step. The transaction is deliberately target-ordered rather than claiming an impossible multi-file atomic rename.

When a release pair is supplied, the installer resolves the tag and `HEAD` with Git before planning, requires both to equal the supplied commit and the tree to be clean, and binds the map digest to that identity in its report. It resolves them again after the last target and publishes success only while they still agree; a refusal names the last completed step. Staging without the pair publishes `untagged`.

## Repository maps · `sec:rulebookinstall:repository-maps`

Programs install natively with build records under the data directory. Private account, worker, gateway and harness helpers install outside the search path. The Claude adapter and permission hook install into the private hook directory; permission tools install under `libexec/superloop`, with records under `share/superloop/build-records`.

The deploying instance owns document and charter maps under its `deploy/tools/maps/` directory. It supplies that map path, its own source root and any required tools build root explicitly. The instance publication supplies `~/.local/share/orchestration-instance/docs/tools/integration.md` and `~/.local/share/orchestration-instance/docs/tools/worker-charter.md`; loop sign-in homes use the configured published charter input. Tools install their public specifications natively.

## Exit statuses · `sec:rulebookinstall:exit-statuses`

|Status|Class|Meaning|
|-----:|-----|-------|
|0|success|Every target completed, or a fully validated dry-run completed.|
|1|failure|Internal failure or report-stream publication failure.|
|2|usage|Invalid command arguments.|
|3|map|Map read, UTF-8, TOML, shape, mode, normalization, or destination-collision refusal.|
|4|source|Missing, symlinked, non-regular, or unreadable repository input.|
|5|render|Overlay shape, slot/section matching, uniqueness, conflict, leftover marker, or final-size refusal.|
|6|destination|Unsafe root/component/type, equal-byte mode mismatch, input alias, or unsafe backup identity.|
|7|concurrent change|A source, target, root, component, or backup changed after its observed preflight state.|
|8|backup|The outgoing-byte backup could not be staged, replaced, read, or verified.|
|9|install|Parent creation, target staging, exact-mode application, distinct-mtime preparation, or rename failed.|
|10|verification|A renamed target failed the required type, byte, mode, identity, or mtime proof.|

A sole `--version` emits one JSON version record on standard error, leaves standard output empty and exits zero, or one if emission fails. Help and other accepted version argument forms return zero after their static text and terminal report. Panics are caught behind a silent panic hook; payloads and default Rust panic text are never published.

## Library surface · `sec:rulebookinstall:library-surface`

`install` accepts an explicit `InstallRequest` containing the map path, repository root, optional destination, build and registry overrides, staging directory, optional release pair, and dry-run flag. It returns `InstallReport` or a typed `InstallError` carrying the refusal class, reason, target index, completed reports, touched indices, and last completed step. `render` exposes the environment-free byte renderer independently. `write_report` publishes either result under the binary's declared agent-text contract.

## Test register · `sec:rulebookinstall:test-register`

The package test matrix covers schema exclusivity; path normalization, duplicate, backup and provenance collisions, and symlink refusals; missing inputs; copy independence and exact modes; build records, digest and domain checks; release identity and registry roots; unchanged identity/byte/mode/nanosecond-mtime retention; changed backup and single-replacement evidence; idempotent second installation and commit-sensitive provenance; every rendering refusal; final size enforcement; dry-run non-mutation; stable exit mappings; report framing; and subprocess usage, success, refusal and staging contracts.

The binary dispatcher exposes map installation (`--map` with optional `--dry-run`), `inventory` and `retire`. Inventory writes its explicit report; retirement moves only reviewed old destinations into recovery and publishes its explicit report. Meson installs this executable natively and keeps its build record under the data directory.

Foreign-owned destination refusal is unmeasured by the unprivileged single-uid fixture: a gate with a second uid must create a foreign-owned regular destination and directory, and require refusal before any move or report of a change. The existing ownership checks remain mandatory.
