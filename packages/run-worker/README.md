# `run-worker` · `guide:runworker:run-worker`

`run-worker` gives one dispatched lane a UID of its own. It allocates a slot from its loop's declared block, builds the lane's tree at the loop UID, owns the parts the lane must write to that slot, drops the lane's driver into it, and waits on the public run directory the lane writes. Pure planners turn a validated registry record and arguments into exact argv and exact file bytes, and an injected `Runner` owns every external command, so no unit test invokes podman or `setpriv`.

This is the first bite of [the worker launcher](../../docs/proposals/run-worker.md): `prepare`, `launch`, `watch`, and `close` for the Claude driver. `fetch` refuses until its loop-side export path is available. `close LOOP LANE` is the explicit lane close-out operation.

## Command line · `sec:runworker:command-line`

Newly generated worker settings register only `PreToolUse`, invoking the configured absolute Claude adapter followed by `pre-tool-use`. `RUN_WORKER_CLAUDE_HOOK_BIN` overrides the path supplied by Meson, whose native default is `libexec/superloop/hooks/superloop-claude-hook` under the install prefix. A development build defaults to that private path beneath the caller's `.local`. Launch refuses a relative, non-UTF-8 or absent adapter before privileged calls. Shell quoting and JSON encoding preserve the configured path as one command word. Generation changes no host registration and does not repair older worker homes. The worker's existing permission instance and the adapter's separately installed permission helper are still required; missing or invalid inputs fail closed. The old wrapper remains installed until the superloop proves registration and session drain.

```text
run-worker prepare LOOP LANE COMMIT --hub PATH --brief PATH
run-worker launch LOOP LANE --driver claude --estate DIR [--budget SECONDS] [--model MODEL] [--effort EFFORT]
run-worker watch LOOP LANE [--stall SECONDS] [--budget SECONDS]
```

`LOOP` and `LANE` are positional on every subcommand, and `LANE` obeys the same portable grammar as a loop name — one or more lowercase ASCII letters, digits, and hyphens — because it is a path component under `worker-homes/`, a field in the tab-separated run table, and the account name the temporary passwd and group lines carry; a name outside that grammar is a usage refusal decided before anything else runs. The registry is the file `ENTER_LOOP_REGISTRY` names, defaulting to `HOME/.config/loops/registry.toml`, the same file the entry reads. `--budget` defaults to 3600 seconds, `--stall` to 300, `--model` to `claude-opus-5`, `--effort` to `xhigh`. The owner-controlled `workers.toml` supplies `driver_argv` and `backend_argv.claude`; missing selectors refuse before launch state changes. Fixed arguments are preserved without shell interpretation.

|Status|Meaning|
|------|-------|
|0|The subcommand succeeded, or `watch` read a run report.|
|2|A command-line form this binary does not accept, including `fetch`.|
|3|`watch` found a line in the worker's escalation journal.|
|4|A refusal decided before any privileged call: a full block, an unmapped block, a missing estate file, a lane already live.|
|5|The budget passed with no run report.|
|42|The events file stopped growing while the child was alive, which is the estate's stalled status.|
|1|Anything else.|

Every refusal writes one line beginning `REFUSED` to standard error; every success writes one evidence line beginning with the subcommand's name in capitals to standard output. Every invocation ends on standard output with `RUN-REPORT exit=STATUS wall=S.SSSs verdict=VERDICT`.

## Allocation · `sec:runworker:allocation`

The tools record a loop's inclusive worker block as `[LOOP]` with `uids = { base = BASE, count = COUNT }` in `~/.config/loops/allocations.toml`, beside the identity registry. `loop-home` validates every table, refuses malformed or overlapping blocks and a run leaving 1000 through 65535, and refuses a loop without an allocation by name before launch.

`prepare` takes the lowest free slot of that block. Free means absent from both `runs/table.tsv` and the protected non-retired mail receipts; removing a run-table row does not release a retained mail UID. Before any slot is taken the block is checked against the mapping the deployment account actually has: `/etc/subuid` and `/etc/subgid` are read for the account name of this process's own real UID, and every UID in the block, and the GIDs beside it, must be no greater than the smaller of the two counts, because a rootless namespace maps each subordinate range onto namespace identifiers 1 through its count. A block checked only against a compiled range validates at deployment and fails at `chown` or at `setpriv` instead, after a tree exists and before anything runs. The block is also required to be disjoint from every other registered loop's block, from every registered loop `uid`, and from the deployment UID.

The run-table row reserves preparation within this harness, and one table lock spans taking that slot. The mail coordinator then reserves the same identity under the shared root admission lock before any home is created, so a concurrent harness cannot publish a second binding. `prepare` reads the table, chooses the lowest free UID from what it holds, and writes the row back inside a single hold of `runs/table.lock`, because two callers that each read the table before either wrote it would choose the same UID and both append it — two lanes at one UID, which is exactly the kernel boundary this package exists to create. A second guard sits under the same lock: a row whose UID is already live is refused, so no path into the table can add a duplicate.

The claimed row carries `uid` and `lane` with `driver`, `commit`, and `started` empty. `commit` is filled only after the clone exists, from `git -C CLONE rev-parse HEAD` read through the injected runner, so the table records the commit the clone actually resolved rather than the branch or tag the caller named; a clone that fails retains the claimed row so explicit close can retire its pending mail identity. `launch` fills `driver` and `started` under the same lock and refuses a row that already carries a start.

The lock is an exclusive create of `runs/table.lock` rather than an advisory lock, so it needs no library beyond the standard one and a crashed holder is visible as a file naming its PID.

## Credentials and entry composition · `sec:runworker:credentials-and-entry-composition`

The composition is the entry command's, which is why its four measured requirements are inherited rather than restated: the clean environment, the temporary passwd entry, the empty bind-mounted `ssh_config.d`, and the nested mount namespace (`packages/loop-home/src/planner.rs:109-152`, and the reasons in `packages/loop-home/README.md:71`).

One field differs, and it is the field this package exists for. A loop's entry drops with `--regid=UID --clear-groups` (`planner.rs:110-112`), which for a worker UID would leave the lane in no loop group at all and close every group-mediated path the tier layout depends on. A worker's drop is therefore `setpriv --reuid=WORKER_UID --regid=WORKER_GID --groups=LOOP_GID --no-new-privs`, where `WORKER_GID` equals the worker's own UID so the lane's own files stay closed to its siblings, and `LOOP_GID` is named numerically so membership does not depend on a member list being right. `--no-new-privs` makes the drop final across every later exec, which matters because the estate tree's hook directory is world-executable by design.

The temporary group file gains two lines instead of one: the worker's own group `LOOP-LANE:x:WORKER_GID:` and the loop's group `LOOP:x:LOOP_GID:LOOP-LANE` naming the worker as a member, so a tool resolving either GID by name finds one. The temporary passwd line names the same account at the worker's home.

The dropped child runs `superloop-lane driver start --backend claude -C CLONE -d RUN_DIR -s workspace-write -m MODEL -e EFFORT -t BUDGET -n work -` with the brief on standard input, under `HOME` and `CLAUDE_CONFIG_DIR` inside the lane's own tree. The redirect is why the child is composed as one `sh -c` word: a redirect is shell syntax and `env -i` has none.

## The monitor · `sec:runworker:the-monitor`

The parent of the drop stays at namespace root, because only namespace root can signal a process at another UID and only it can write a lock into a directory the worker does not own. Its surface is small on purpose: it writes its own PID into `worker-homes/LANE/monitor.lock`, starts the drop, appends the child's PID as the lock's second line, and then waits. The lock is created empty by the layout before the drop, so a reader finding a dead holder over a live child knows the step is still running; the child's PID can only be appended once the child exists, which is the one ordering this design cannot choose differently. This namespace-root parent monitor is a program role, distinct from the lane's Sonnet watcher, which owns orchestration waiting, relay and deadlines and hands results back for the session's decision.

At the budget the monitor writes an `over-budget` notification naming the lane, UID, child, budget and observation time to `RUN_DIR/budget-notice.txt`, outside the driver’s archived kill-evidence set, without signalling the worker; the compatibility grace setting does not trigger a later stop.

## Directory layout · `sec:runworker:directory-layout`

Both subcommands are invoked by the deployment account, which is the one account whose user namespace maps every subordinate identifier, and which owns none of the loop's own parents: `worker-homes/LANE/` is 0750 loop-owned, so an ordinary write by that account is refused by the kernel. Root inside the user namespace can write into subordinate-owned parents, so every row below is created by one `podman unshare sh -c` command through the injected runner rather than by an in-process write. The bytes of a file row are written first into a staging directory the deployment account does own, under its own temporary root at `TMPDIR/run-worker-LANE-UID/` at mode 0700, and the namespace command copies them into place, links what is a link, and then modes and owns everything. Nothing this process writes with its own hands lands under a row the loop owns, so `TMPDIR` must be the launcher account's own disk-backed temporary root — a brief and an identity file staged under a shared one would be readable by every account that shares it.

The run tree is the exception, and it is the launcher's rather than the loop's. `runs/table.tsv` and its lock are the launcher's own record, and the single-lock claim needs them written in process, so `runs/` is owned by the account this launcher runs as, grouped to the loop, at 0755 — the loop needs only the read and traverse that mode already gives it, and the world-readable run directories beneath it are unaffected. `prepare` creates it when it is absent by one namespace command that makes the directory, owns it to root inside the namespace, which is the launcher's account outside it, and modes it 0755; it refuses with status 4 when the directory exists under another owner, naming the path and that owner, rather than failing later on a lock it cannot take. The row is excluded from the mode and ownership commands exactly as the links are, so no launch takes the tree away from the account that has to write it.

The launcher builds the rows below, in this order, and the loop's own four rows (`LOOP_HOME`, `private/`, `shared/`, and the worker rubric) are preconditions it checks rather than paths it creates — they belong to the loop home's own provisioning.

|Path|Owner|Group|Mode|Stage|
|----|-----|-----|----|-----|
|`worker-homes/`|loop|loop|0710|prepare|
|`worker-homes/LANE/`|loop|lane|0750|prepare|
|`worker-homes/LANE/clone`|worker|lane|0700|prepare|
|`worker-homes/LANE/home/`|loop|lane|0750|prepare|
|`worker-homes/LANE/home/.claude/`|loop|lane|0750|prepare|
|the eleven harness children under `home/`|worker|lane|0700|prepare|
|`worker-homes/LANE/brief.md`|loop|lane|0640|prepare|
|`runs/`|the launcher's account|loop|0755|prepare|
|`home/.claude/settings.json`|loop|lane|0640|launch|
|`home/.claude/CLAUDE.md`|link to the estate charter|—|—|launch|
|`home/.claude/logins`|link to the loop's `shared/logins/`|—|—|launch|
|`worker-homes/LANE/identity.env`|loop|lane|0640|launch|
|`worker-homes/LANE/monitor.lock`|loop|lane|0640|launch|
|`runs/UID/`|worker|lane|0755|launch|
|`runs/UID/launch.env`|loop|lane|0644|launch|

`worker-homes/LANE/`, `home/`, and `home/.claude/` are loop-owned because ownership of a directory is the permission to unlink what is inside it: a lane owning its own tree could remove the `identity.env` that names it, the brief it is measured against, or the settings that register the classifier hook. Their group is the lane's own GID rather than the loop's, because every lane shares the loop's supplementary group and a loop-grouped lane tree would be readable by every sibling lane. The harness's writable children are pre-created at the worker's UID, so a harness version wanting one the launcher did not create fails with a permission error, which is loud and repairable.

The charter and the sign-in directory are links rather than copies, for the reason the proposal's links section gives: a redeploy of the rules reaches every live worker, no worker holds a private copy of the text it is judged by, and the loop's single sign-in stays single, which is what lets the harness rewrite it when a token refreshes. Both links are excluded from the mode and ownership commands, so no `chown` follows a link out of the lane's tree; which credential filename the harness opens behind `logins` is the acceptance launch's business, not this bite's.

Modes are applied before ownership, and ownership is the last thing the plan does, so a crash leaves a tree owned by a UID with nothing running as it rather than a tree the worker holds and the loop cannot mode.

`identity.env` carries `LANE`, `LOOP`, `WORKER_UID`, `WORKER_GID`, `LOOP_GID`, `ROLE=worker`, `RUN_DIR`, `RUBRIC`, and `ESTATE`, one assignment per line in that order, loop-owned at 0640 in the lane's group: it is data about the worker rather than a claim by it. `launch.env` carries `DRIVER`, `MODEL`, `EFFORT`, `BUDGET`, and `STARTED`, which is where a later `watch` reads the budget it was not told.

## Waiting · `sec:runworker:waiting`

`watch LOOP LANE` resolves the UID from the lane's row, reads the child's PID from the monitor's lock, and polls the run directory once a second. It returns 0 with the run report's first line, 3 with the first line of `escalation.jsonl`, 42 when the step is stalled, and 5 when the budget passes with no report. Nothing in this bite writes `escalation.jsonl` — the hook's wiring to that file is the classifier's identity bite, and `watch` only reads it.

Two things make the budget mean what it says. The elapsed clock is seeded from `STARTED` in the launch record rather than from the moment the waiter attached, so a waiter armed late does not grant the lane a second budget. And a stall is decided not only when `events.jsonl` stops growing while the child is alive, but also when the lock names a child that is gone and no report was written: a lane whose monitor and child are both dead has nothing left to wait for, and waiting to the budget would only delay the same answer.

A missing or unreadable `launch.env` is refused with status 4 rather than defaulting to a compiled budget. The record sits inside the worker-owned run directory, so a lane can unlink it; a launcher that silently fell back to 3600 seconds would then measure a budget nobody set, which is the kind of quiet substitution a waiter must not make.

## Test matrix · `sec:runworker:test-matrix`

|Layer|Cases|Evidence|
|-----|-----|--------|
|Credentials|Exact drop words, both group lines, the passwd line|`--groups` is numeric, `--no-new-privs` is present, and `--clear-groups` is absent.|
|Allocation|Lowest free slot, full block, peer-block overlap, registered-UID overlap, block beyond a fixture subordinate UID count, the same for GIDs, reuse after a row is removed|The lowest free slot is taken and an unmapped or overlapping block is refused before any command runs.|
|Entry planner|Exact inner and outer scripts, the monitored outer script, a home and a command carrying a space and a single quote|Byte-stable composition against the entry command's measured requirements.|
|Layout builder|Every row with owner, group, mode, and stage; harness children; `identity.env` and `launch.env` bytes; modes before ownership; the lock before the drop|Each path carries its stated owner, group, and mode, in the stated order, with the ownership change last.|
|Subcommand contract|Each subcommand's evidence and report lines against a scripted runner, the run tree's own command and a foreign owner, sequential preparations, the recorded head, a failed clone and a failed cleanup, a start before the epoch, each `watch` outcome and status from files a test writes, `a_malformed_peer_registry_row_is_refused`, refusals before any privileged call|Status and report bytes are asserted, slots ascend and a live UID is refused, the row carries the runner's `rev-parse`, a failure frees the row and removes the tree while keeping its cause, no in-process write lands under a loop-owned row, and a refusal leaves the runner log empty.|

The acceptance is one real launch — a read-back lane prepared and launched at a real worker UID, its run directory read at the deployment UID, the loop's private tree and a sibling lane's tree proved unreadable from the worker's UID — and it is a separate step that this bite's gate does not perform. Unit fixtures cannot authorize it: a test process has one UID, so the fake namespace shim proves the layout, the ordering, and the refusals, and cannot prove that a different UID is refused.

Worker mail uses the separate protected `workers/WORKER/mail` tree. Preparation derives a stable `worker-` name from the harness-qualified reservation and reserves it and its harness-qualified lifetime binding before creating the loop-owned execution home; a failed preparation can release its run-table row while the retained mail receipt keeps that UID unavailable. Existing legacy execution homes require explicit reconciliation before launch. The worker drop carries its private primary GID, the loop execution group and only its own allocated mailbox group.

A watched process ending does not retire its worker lifetime. `close LOOP LANE` takes the lifetime lock, refuses while launch is running or any process retains the UID, transfers retained mailbox custody to the service and marks the protected receipt retired before removing the run-table row. The name remains reserved forever; another lane may reuse the released UID. Lane close-out calls this operation. A crash before table removal is retryable. The loop alone owns directed whitelist changes.
