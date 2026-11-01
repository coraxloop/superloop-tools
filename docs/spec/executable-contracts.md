# Executable identities · `spec:buildcontracts:executable-identities`

**Table (Executable identity correspondence)** · `tab:buildcontracts:executable-identities`

Each correspondence binds its named interface to the ledger's installed, build-only, delegated or absent identity. The census checks every row in both directions so a compatibility name cannot hide an unregistered output. A name in the first column does not authorize installing an alias.

|Present name|Successor|Installs to|
|------------|---------|-----------|
|`enter-loop`|`superloop`|search path|
|`superloop-lane`|stays `superloop-lane`|search path|
|`vendor-proxy`, `door-ssh`, `door-service`|stay in the lane release group|private directory|
|`requests-helper`|stays in the permission/request release group|private directory|
|`permission-triage-hook` binary|stays `hooks/permission-triage-hook`|private directory|
|`superloop-claude-hook`|stays `hooks/superloop-claude-hook`|private directory|
|`superloop-lane-vendor@`, `superloop-lane-door@` unit templates|stay with the loop as instance|user unit directory|
|`claude-lane`, `codex-lane`|`superloop-lane driver start\|resume --backend claude\|codex`|search path|
|`lane-watch`, `worker-monitor`|`superloop-lane driver status`, `superloop-lane driver follow [--save-offset]`|search path|
|`lane-verify`|`superloop-gate-submit`|search path|
|`run-worker`|private `worker-run`; `superloop-lane launch`|private directory; search path|
|`lane-gateway`, `gateway-runner`|private `gateway-service`, `gateway-runner`; `superloop-lane gateway`|private directory; search path|
|`LOOP-gpg`, `LOOP-ssh`|generated `LOOP-gpg`, `LOOP-ssh`|user private directory|
|`loop-gh`|`superloop run-bridge gh`|search path|
|`loop-codex-home`|`superloop-lane prepare-signin-home\|check-signin-home --backend codex`|search path|
|`loop-keygen`, `staff-provision`|private `account`; `superloop account keygen\|check\|create\|admit-key`|private directory; search path|
|`heartbeat-guard`, `superloop`, `heartbeat`|private `hooks/superloop-claude-hook stop\|pre-tool-use`; `superloop heartbeat on\|off\|status`|private directory; search path|
|`orchestrator-hook`, `orchestrator`|private `hooks/superloop-claude-hook session-start\|user-prompt-submit`; `superloop orchestrator on\|off\|status`|private directory; search path|
|`permission-triage` wrapper and old hook destination|private `hooks/superloop-claude-hook pre-tool-use`; private `hooks/permission-triage-hook`|private directory|
|`permission-triage-review`, `-topology`, `-assemble`|private `requests-helper`; `superloop-lane requests status\|list\|triage\|review\|adjudicate`; private fixture and registration steps|private directory; search path|
|``correspondence-feed.sh``, ``correspondence-watch.sh``|`superloop-correspondence poll\|watch [--advance-cursor]`|search path|
|``steward-send.sh``, ``steward-transcript-feed.sh``, ``steward-transcript-watch.sh``|`superloop-steward send\|transcript poll\|transcript watch [--advance-cursor]`|search path|
|`steward-runner`, `steward-spool-append`, `steward-transcript-export`|`steward-runner`, `steward-spool-append`, `transcript-export`|server private directory|
|`correspondence-scan`, `cargo-clean-home`|`correspondence-scan`, `target-clean`|server private directory|
|``steward.service``, `.timer`|``superloop-steward.service``, `.timer`|server system unit directory|
|``correspondence-watch.service``, `.timer`|``superloop-correspondence-scan.service``, `.timer`|server system unit directory|
|``cargo-clean@.service``, `.timer`|``superloop-target-clean@.service``, `.timer` with the account as instance|server system unit directory|
|`codex-rt`, `codex`, `codex-rt-create`, `codex-host`, `claude-in-loops`|`superloop-runtime exec\|create\|run-host\|run-toolbox`; `codex` retires|search path|
|`rulebook-install`, `public-pack`|`superloop-install`, `superloop-pack`|search path|
|`linter`, deployed `orchestration-linter`|`superloop-lint`|search path|
|`build-sync`|`build-sync`|private directory|
|`run-report`|`superloop-run-report`|build tree only; not installed|
|`chat-export`, `node-load`|`superloop-chat-export`, `superloop-node-status`|search path|
|`ccd-groups-sync`, `ccd-session-merge`|`superloop-claude-desktop sync-groups\|merge-sessions`|search path|
|the `execwrap` binary|not shipped|none|

The executable ledger supplies the concrete installed and build-output identities for these rows. Missing, duplicate or extra correspondences fail the census before a release can claim complete coverage.
