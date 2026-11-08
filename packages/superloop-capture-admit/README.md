# Capture admission · `guide:captureadmit:sealed-generations`

`superloop-capture-admit` admits and prunes capture generations under a store account. Admission verifies the bytes it writes, not the source's stability; account confinement protects the resulting bytes from readers. The program refuses effective uid zero, a root with another owner, or a root whose mode is not 0750. Provisioning owns the account, reader group, root-owned executable, provenance and single sudoers command; admission does not provision them.

## Commands · `sec:captureadmit:commands`

```text
superloop-capture-admit admit --store ROOT --source DIR --manifest FILE --name NAME [--keep-previous] [--quota-bytes N]
superloop-capture-admit prune --store ROOT
superloop-capture-admit --version
```

NAME is one to 200 ASCII letters, digits, dots, underscores or hyphens, excluding `.` and `..`. An existing NAME with the same manifest digest is `already-sealed`, without copying or changing the current selector; a different digest refuses. Admission serializes store operations through an exclusive nonblocking lock on the pinned root directory; contention refuses as `store-busy` without a lock file. The default quota is 5,000,000,000 bytes across all sealed generations plus the candidate, before any copy; a quota refusal lists prune candidates, their reclaimable bytes and whether pruning suffices. It does not automatically prune.

## Manifest and copy · `sec:captureadmit:manifest`

A manifest consists of optional leading `key=value` header lines, then `sha256 size relative-path` lines. Keys use ASCII letters, digits, underscore, dot or hyphen; values are opaque bytes. Hashes are 64 lowercase hexadecimal characters, sizes are decimal byte counts, and the path is the remainder of the line. Paths have no NUL, absolute prefix, empty component, `.` or `..`; duplicates refuse. Blank lines, comments and malformed lines refuse. The manifest digest covers its exact bytes, including headers. A final line need not end in LF; the receipt terminates each copied header line before its own fields.

Each source component is opened without following symlinks. Only regular files are copied, hashed as they are written and compared for size and digest. A final source walk refuses unlisted entries, including empty directories. Missing files, special files, symlinks, wrong sizes and wrong digests refuse; private work is removed. The admitted files have mode 0644 and directories 0755, and are fsynced before publication.

## Store and leases · `sec:captureadmit:store`

Under an existing root, admission maintains ``generations/`` and ``receipts/`` at 0755, ``leases/`` at 0770 and ``.incoming/`` at 0700. The store account owns those directories, with the store root’s group. Private copies start at ``.incoming/NAME.PID`` mode 0700. A receipt carries the manifest headers, then `name=`, `digest=`, `files=` and `bytes=`. Publication renames the sealed directory, publishes the receipt and replaces ``current`` with a relative ``generations/NAME`` symlink. `--keep-previous` appends the old current NAME to ``keep`` at 0644; only admission writes it.

A lease in ``leases/NAME.lease`` has exactly three ordered lines: `identity=NAME`, `holder=TEXT`, `expiry=UTC`. The holder is nonempty text. UTC uses the existing observation parser's RFC 3339 form: years 1970 through 9999, `T`, `Z` or `+00:00`, with an optional decimal fraction. Prune validates all leases before deleting anything; malformed leases refuse. It removes expired leases and generations that are neither current, kept nor live-leased, together with their receipts. It never changes ``current``. Readers maintain leases through their group access; the store account alone changes sealed generations.

## Reports and evidence · `sec:captureadmit:reports`

Admission prints its receipt fields; a same-identity no-op prefixes `already-sealed`. Prune prints each removed NAME and its bytes, followed by removed-count and byte totals. Operation output ends in `wall=SECONDSs`; refusals have a diagnostic on standard error, with status two for an argument refusal and status one otherwise. `--version` uses the shared JSON identity contract. Subprocess tests use fictional data under the caller's TMPDIR and remove their fixtures; another-owner and effective-root execution require separate account authority and are not asserted by ordinary-uid fixtures.
