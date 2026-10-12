# correspondence-watch · `guide:correspondencewatch:correspondence-watch`

Server-side half of the correspondence pipeline, deployed on each configured root-full server; the fictional registry illustrates the server set with `sagofink-root` and `mondreiher-root`. Every account, including `owner`, carries a `~/correspondence/` folder; files a teammate drops there are how humans and staff accounts reach the orchestration loop, and admin replies are installed into the same folder. A one-minute systemd timer scans the folders and journals each new or changed file to the system log under the tag `correspondence-watch`.

## Classification: admin-reply naming, then ownership · `sec:correspondencewatch:classification-admin-reply-naming-then-ownership`

A basename matching `*-admin-reply.md` is always journaled `from=admin`, regardless of ownership. Every other file carries `from=user` when it is owned by the home's own account and `from=admin` otherwise, preserving root-owned replies as admin correspondence. The filename convention survives delivery methods that write as the receiving account. It also fails safe: a user who gives their own message the admin-reply suffix only suppresses their own message from escalation.

The same classifier governs the owner folder: an owner-owned letter is an authenticated work order reported as `user=owner from=user`, while a root-owned steward disposition or an `*-admin-reply.md` file is output context reported as `user=owner from=admin`. The owner folder must remain `owner:owner` mode `0755`; group or world write permission invalidates the channel boundary and blocks steward activation.

## Configuration and tests · `sec:correspondencewatch:configuration-and-tests`

The deployed defaults remain `/var/home` for the scanned home root, `/var/lib/correspondence-watch` for scanner state, and `logger` for the journal sink. Tests may override them with `CORRESPONDENCE_WATCH_HOME_ROOT`, `CORRESPONDENCE_WATCH_STATE_DIR`, and `CORRESPONDENCE_WATCH_LOGGER` respectively. `CORRESPONDENCE_WATCH_STEWARD_SPOOL_ENABLED` defaults to `0`, preserving correspondence-only operation; setting it to `1` invokes `CORRESPONDENCE_WATCH_STEWARD_SPOOL_APPEND` (default the configured private `steward-spool-append` path) for `from=user` events only. The owner activates this hook at the steward handoff, never before the durable spool and ledger are installed.

Run the configured Meson release suite for the unprivileged fixture harness. The harness prepends temporary `stat`, `logger`, and spool-producer shims to `PATH`; the ownership shim returns controlled UIDs only for fixture paths and delegates every other query to the real `stat`, so the production ownership lookup remains unchanged. The fixture pins the hook off by default, one enabled owner event, and exclusion of admin output.

## Journal line shapes · `sec:correspondencewatch:journal-line-shapes`

```
correspondence-watch: user=<acct> from=<user|admin> file=<relpath> size=<bytes> sha=<12-hex>
correspondence-watch: scan events=<n> duration_ms=<ms>
```

Quiet scans journal nothing (journald hygiene); the duration line accompanies any scan that found events, which keeps the wall-time reporting duty on every scan that did observable work.

## Deploy (confined server, via owner sudo) · `sec:correspondencewatch:deploy-confined-server-via-owner-sudo`

Use the native `server-correspondence` install tag from the server build described in (`sec:steward:owner-install-and-dormant-probes`). It stages the configured `correspondence-scan`, its build record and `superloop-correspondence-scan.service` and `.timer`. A second staged install must preserve all bytes and modes. Installation does not activate a timer.

Migrate in the seven-step steward procedure (`sec:steward:account-and-layout-migration`), including preservation of the scanner's state at `/var/lib/correspondence-watch`, cursor data, spool-hook drop-in and recorded timer intent. Retire `/usr/local/bin/correspondence-scan` and its provenance sibling and the old `correspondence-watch` units only after backup and caller switch. Keep every account's correspondence folder and the owner's 0755 channel unchanged. An inactive scanner stays inactive; where it was active, prove one scan under the new unit name and an unchanged second install.

## Workstation half · `sec:correspondencewatch:workstation-half`

The installed `superloop-correspondence poll` receives explicit SSH aliases and a provisioned read-only host-key file through `--known-hosts`; `--ssh-config` selects its SSH configuration and `--state-dir` can select the existing cursor root. Each bounded poll reads the scanner journal and prints records prefixed `host=ALIAS`, duration and a final content, empty or failure verdict. Bare polls and watches preserve shared cursor bytes and metadata. A continuing `superloop-correspondence watch --advance-cursor` publishes every consumed record, including admin records, before saving that host's cursor; it returns on user content or a visibility warning and exits 2 at its deadline after printing any admin records it consumed. The watcher calls the polling module directly. The defaults remain a 500-second poll deadline and a 20-second pause. No local backlog scan is implemented. These server services remain separate from loop letters and their inbox watcher.
