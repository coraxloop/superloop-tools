# cargo-clean · `guide:cargoclean:cargo-clean`

This artifact reclaims Cargo build output from each confined staff account with that account's own permissions. One timer instance per approved staff account runs every two hours and covers every Cargo repository under that account's home. It never runs as root, crosses into another account, or gains privilege.

## Project and detached-target discovery · `sec:cargoclean:project-and-detached-target-discovery`

Discovery A walks the account home with `find -P`, pruning `.git`, `node_modules`, `.rustup`, `.cargo/registry`, `.cargo/git`, and target directories learned during the scan. For every remaining `Cargo.toml`, `cargo metadata --format-version 1 --no-deps --offline --manifest-path` supplies the effective `target_directory`; `jq` reads the JSON when available and a narrow `sed` expression is the dependency-free fallback. Workspace members that resolve to the same directory therefore produce one `cargo clean --manifest-path` action. A failed or unparseable metadata call is reported against its manifest as `mode=skip-metadata`, with both byte values zero, and is never guessed. A resolved target outside the selected home is reported `mode=skip-outside` without reading or changing it.

Discovery B covers detached output such as purpose-specific directories under `.cache` and `loops`. Cargo provides the evidence: a target directory has a `CACHEDIR.TAG` whose first line is exactly `Signature: 8a477f597d28d172789f06886806bc55`, together with a sibling `.rustc_info.json`. Both regular-file markers are required. A foreign cache-tag signature is not Cargo evidence and is ignored. A marked directory already covered by discovery A is counted only once under A; every other distinct marked directory is removed directly because Cargo recreates it on the next build.

## Safeguards · `sec:cargoclean:safeguards`

The selected root must be a real directory owned by the invoking uid, and root invocation is refused. The walk never follows symlinks. Metadata-resolved symlink targets are reported `mode=skip-symlink`, foreign-owned targets are `mode=skip-unowned`, and out-of-root targets are `mode=skip-outside`. Direct removal is confined to an owned directory below the selected root whose marker pair is revalidated immediately before removal. A nonblocking `flock` at `$HOME/.cache/cargo-clean/lock` serializes each account; contention exits 3 rather than waiting. Configuration refusals exit 2, target failures exit 1, and a failure-free run exits 0.

## Runtime knobs · `sec:cargoclean:runtime-knobs`

`CARGO_CLEAN_HOME` overrides the default root of `$HOME` for tests. `CARGO_CLEAN_MIN_IDLE_HOURS` defaults to `0`, so the ruled deployment skips nothing; a positive whole-hour value reports a target containing a newer file as `mode=skip-busy`. `CARGO_CLEAN_CMD_TIMEOUT` defaults to 600 seconds for each metadata and clean command. `CARGO_CLEAN_CARGO` defaults to executable `$HOME/.cargo/bin/cargo`, then `cargo` on `PATH`. Discovery B still runs without Cargo, but manifests make the overall run a loud configuration refusal. `CARGO_CLEAN_LOGGER` defaults to `logger`.

Every build following a clean is cold. The idle-hours knob is the deliberate softening lever: an operator can set it without redeploying the script by adding `Environment=CARGO_CLEAN_MIN_IDLE_HOURS=1` in a `superloop-target-clean@ACCOUNT.service` drop-in, then running `systemctl daemon-reload`.

## Journal lines · `sec:cargoclean:journal-lines`

Every target and every run are printed to stdout and sent to the journal sink with tag `cargo-clean`. Paths are absolute account-local paths.

```
cargo-clean: target=<path> mode=<clean|remove|skip-busy|skip-unowned|skip-symlink|skip-metadata|skip-outside|fail> before_bytes=<n> freed_bytes=<n> duration_ms=<ms>
cargo-clean: run root=<path> targets=<n> cleaned=<n> removed=<n> skipped=<n> failed=<n> freed_bytes=<n> duration_ms=<ms>
```

The summary is emitted even when the scan finds no targets. Skip lines report zero freed bytes; metadata and outside-root skips avoid untrusted reads and report zero before bytes as well. Early configuration refusal and lock-contention runs emit one `cargo-clean: run` diagnostic carrying `mode=refuse` or `mode=locked` respectively.

## Deploy on a confined server via owner sudo · `sec:cargoclean:deploy-on-a-confined-server-via-owner-sudo`

Use the native `server-target-clean` install tag from the server build described in (`sec:steward:owner-install-and-dormant-probes`). It stages private `target-clean`, its build record and `superloop-target-clean@.service` and `.timer`. Each instance names one approved confined account; root and owner remain excluded. Installation does not invoke systemd.

Before the hold, record every existing `cargo-clean@ACCOUNT.timer` enabled and active state and preserve its units, drop-ins, `/usr/local/bin/cargo-clean-home` and provenance sibling with metadata in the server's rollback directory. Drain an active cleanup before replacing its executable. Install the new tag, transfer unchanged per-account drop-ins to the new unit name, update sudo and command rules, and retire the saved old destinations. Reload systemd and restore exactly each instance's prior enabled and active state under `superloop-target-clean@ACCOUNT.timer`; do not activate dormant instances. The account-local lock and cache state retain their paths.

Verify the configured units and one approved account's cleaning invocation under the new name, then read that invocation's `cargo-clean: run` journal summary. Repeat staged and live installation and compare destination bytes, modes and timer states: zero changes. The retirement report lists recovery places. Rollback restores the saved files and old timer states without changing account data.

## Fixture harness · `sec:cargoclean:fixture-harness`

Run the configured Meson release suite as an ordinary user. It builds a temporary home and prepends controlled `cargo`, `logger`, and `stat` shims. Its containment guard refuses any cleanup invocation whose selected root would leave that temporary fixture.
