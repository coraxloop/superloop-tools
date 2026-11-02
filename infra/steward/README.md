# resident steward kit · `guide:steward:resident-steward-kit`

This directory contains workstation-prepared, owner-installed artifacts for the resident server steward. The correspondence scanner remains the producer. With `CORRESPONDENCE_WATCH_STEWARD_SPOOL_ENABLED` absent or `0`, the spool hook does nothing; the owner activates it only at the one-consumer handoff.

## Durable case and verdict contract · `sec:steward:durable-case-and-verdict-contract`

`steward-spool-append` accepts only `from=user` events and writes one tab-delimited line to the root-owned spool: stable case identifier, absolute source folder, relative file, event SHA, classification, and first-seen UTC timestamp. The identifier is the full SHA-256 of the source folder, relative file, event SHA, and classification; replaying an unchanged event is therefore a locked no-op. The spool is appended and synchronized before success is returned.

`steward-runner` runs only as the dedicated non-root, non-owner `superloop-steward` identity. It locks against overlap, subtracts the steward-owned disposition ledger, checks pending source visibility, and gives the visible batch plus the installed charter to `claude --print`. Tests replace only the executable through `STEWARD_CLAUDE_COMMAND`. For every case the CLI installs the exact case-named administrative disposition requested in the batch and emits a tab-delimited `STEWARD-DISPOSITION` marker carrying the case id, absolute path, and full digest.

`STEWARD_OWNER_CORRESPONDENCE` is required and has no default. It must be an absolute path naming a directory. When it is unset, empty, relative, or not a directory, the runner returns status 1 with final line `STEWARD-RUN-FAILED configuration variable=STEWARD_OWNER_CORRESPONDENCE` and writes journal payload `result=failed reason=configuration variable=STEWARD_OWNER_CORRESPONDENCE` under the `steward-runner` tag.

The runner first durably installs the invocation output, then verifies and synchronizes every root-owned disposition letter, and only then appends and synchronizes ledger entries. A failed or killed invocation therefore leaves the case pending. Stable case ids and case-named disposition paths make replay idempotent.

|Final line|Status|Meaning|
|----------|------|-------|
|`STEWARD-RUN-QUIET`|zero|The spool and ledger were readable and no case remains pending.|
|`STEWARD-RUN-OK ...`|zero|Every visible pending case received durable disposition and ledger records.|
|`STEWARD-RUN-WARNING ...`|zero|Visible cases completed, but at least one pending spool source was malformed or unreadable.|
|`STEWARD-RUN-FAILED ...`|nonzero|Identity, source, lock, deadline, CLI, disposition, ledger, or journal integrity failed.|

Each invocation writes one final verdict line. Detailed start, case, completion, warning, and failure telemetry uses the `steward-runner` journal tag.

## Unprivileged verification · `sec:steward:unprivileged-verification`

Run the Meson release suite in the reviewed build directory. Meson binds the configured runner, spool appender, exporter and units into the unprivileged harness. The harness uses a fake Claude executable and fixture spool, ledger, state, source and owner folder; it proves replay, failed disposition and recovery without changing a server.

## Owner install and dormant probes · `sec:steward:owner-install-and-dormant-probes`

The orchestrator installs each handed-over server after recording its read-only freshness inventory and first-time announcement (`rule:buildcontracts:server-kits`). An uncertain or nonestate finding stops the operation for the person's answer. The build selects one install prefix; private programs and configured units use that same prefix. A workstation build leaves `server_kits` false and installs none of these server outputs.

```bash
meson setup SERVER_BUILD . --prefix /usr/local --libexecdir libexec --sysconfdir /etc -Ddomain=server -Dserver_kits=true -Dsteward_projects_root=/srv/INSTALLATION/transcript-projects -Dsystem_unitdir=/etc/systemd/system
ninja -C SERVER_BUILD
meson test -C SERVER_BUILD --no-rebuild --suite release --print-errorlogs
meson install -C SERVER_BUILD --no-rebuild --destdir STAGE --tags server-steward
meson install -C SERVER_BUILD --no-rebuild --destdir STAGE --tags server-steward
```

The staged destinations are `libexec/superloop/transcript-export`, `steward-runner` and `steward-spool-append` under the configured prefix, their build records under `share/superloop/build-records`, the charter under the configured system configuration directory and ``superloop-steward.service`` and `.timer` under the system unit directory. Compare the second staged install's bytes and modes with the first. Installation never invokes systemd or changes timer state. The orchestrator reviews the staged result before installing the same tag live.

A fresh installation provisions `superloop-steward` as a dedicated non-root account with an installation-selected home. Configure `-Dsteward_projects_root=PATH` with that installation's absolute transcript projects directory (for example, `/srv/INSTALLATION/transcript-projects`). This option has no default path and is required when `server_kits=true`; Meson embeds it in the versioned exporter, so SSH callers need no environment setting. `STEWARD_PROJECTS_ROOT`, when set, overrides the installation value; an empty override refuses. Keep the root-owned spool directory and file at `/var/lib/steward/spool` and `cases.tsv`, group `superloop-steward`, modes 0750 and 0640. Keep `/var/lib/steward/state`, `state/invocations` and `state/dispositions.tsv` owned by that account and group at modes 0700, 0700 and 0600. Create missing empty state only; never truncate existing files. Install the root-owned owner-correspondence drop-in below `superloop-steward.service.d`, setting `STEWARD_OWNER_CORRESPONDENCE` to the declared absolute owner folder. That folder remains owner-owned mode 0755. Fresh timers remain disabled and inactive until the separately reported activation operation.

## Account and layout migration · `sec:steward:account-and-layout-migration`

Run this per server in the order of (`rule:buildcontracts:server-kits`). The account rename preserves numeric uid and gid, the home, spool, state, ledger and correspondence paths and their bytes.

1. Record both steward and scanner timers' enabled and active states, spool-hook drop-in, spool and ledger digests, pending case identifiers, ownership and modes. Preserve old programs, provenance siblings, units, drop-ins and sudo rules in a root-only rollback directory with their original metadata.
2. When the steward timer was active, retain one pending case; if needed append one through the old appender from a test file in the owner folder. An inactive steward gets no new case.
3. Stop and disable only the timers that were enabled or active. Arrange the bounded service drain with an absolute UTC deadline; wait for the running case to finish before changing its account or programs.
4. Rename the account and group in place to `superloop-steward`, retaining numeric identifiers and the installation's existing home. Verify the spool, state, invocation and ledger ownership and modes above. Do not recursively rewrite ownership or relocate data.
5. Before building, set `-Dsteward_projects_root=PATH` to the `.claude/projects` directory beneath the installation's existing home, retaining that directory and its contents. Inspect the configured exporter and prove `list` without an environment override before switching callers. Install the reviewed native tags `server-steward` and `server-correspondence`. Move the unchanged owner-correspondence and spool-hook drop-ins beneath the new unit names. Update sudo and command rules naming the account or program paths. Switch each server's steward client `--exporter` to `/usr/local/libexec/superloop/transcript-export` (or that server's configured prefix), including continuing watchers and send callers. After preserving recovery copies, retire the old `/usr/local/bin/steward-transcript-export`, `steward-runner`, `steward-spool-append` and `correspondence-scan`, their provenance siblings, and the old `steward` and `correspondence-watch` units and drop-in directories. Restore file labels and reload systemd. The scanner invokes the configured private spool appender; it does not search an old path.
6. Restore each timer's recorded enabled and active state under `superloop-steward` and `superloop-correspondence-scan`. A disabled timer stays disabled and an inactive timer stays inactive. Trigger one steward run only where its timer was active.
7. For an active steward, prove the retained case's disposition letter, ledger entry and `STEWARD-RUN-OK`; earlier ledger bytes retain their digest and the spool changes only by appends. For a dormant steward, process no case: verify configured units, account and group, state ownership and modes, unchanged spool and ledger digests, and both timers' recorded states. Where the scanner was active, prove one scan. Run a transcript poll with `--advance-cursor` through the new exporter path. Repeat installation and compare destination bytes, modes and timer state: zero changes.

The retirement report names each removed destination and its recovery place. Repeat retirement leaves absent destinations alone. No helper reads an old installed name after the switch.

## Rollback · `sec:steward:rollback`

Stop new timers, drain the service, restore the account and group names with their original numeric identifiers, restore the saved programs, units, drop-ins and sudo rules, reload systemd and restore each old timer's recorded state. Restore each client's recorded exporter path in the same hold. Preserve spool, ledger, invocation outputs, letters and journal evidence; rollback does not move or rewrite state. Reconcile the last completed case before resuming a consumer.
