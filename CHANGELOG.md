# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- A changing `rotate` now holds the loop's shared configuration lock from before it reconciles the old run and reads the plan and old reservation, through handover, pending-intent recovery, the new run's dispatch and failure recording. An installation holding the lock exclusively makes rotation refuse `install-busy`, including with `--force`; an installation arriving during rotation likewise finds the loop busy, and its refusal names a changing rotation among the possible holders. Preview remains read-only without this rotation-wide hold. Compatibility: only the host `superloop-lane` program's behaviour changes; other programs of the release can relink, and `install-door LOOP --dry-run` shows whether a door step is owed (``rule:superlooplane:door-rebuild-rollout``). A rotation started by an earlier lane program does not hold this lock, so an installer's idle check does not see it; let such a rotation finish before an installation that relies on that check. Stored reservation and generation forms do not change.

- Name a `preparing` run whose preparation lease is unheld or absent as `preparing-without-launch` in the census, with its retirement preview command, adding `--confirm-missing-lease` when the lease is absent, and the retired-row conversion after it; a lease that cannot be measured is named `preparing-lease-unmeasured` without a command, and a held lease is not named. Compatibility: the census adds these two blocker kinds, so a reader that pins the census's blocker kinds meets two new ones; it changes no reservation or command that writes one.

- After a completed legacy or workspace compute command, print one `door-complete stdout_bytes=N stderr_bytes=M` line on the boxed worker's standard error, using the door's verified delivered-byte counts; when a completed workspace request's terminal record fails, that line also carries the record error. A completed Git request remains silent. A `door-request-concurrent` refusal names a known request of the same box holding admission by ID, class and elapsed hold, or says `waiting_slots=2/2` for a third workspace waiter. Compatibility: the boxed `door-ssh` stub prints the new completion line, so each loop's `install-door` step must repin the runs it names before those workers see it; callers comparing completed command standard error byte for byte will see a closing line and, after a partial final line, a separating LF. The restarted door service supplies holder evidence where it knows it, as optional `holder_request_id`, `holder_class`, `holder_held_seconds` and `waiting_slots_full` keys of the final frame, which an earlier stub ignores, so a worker reads the holder words once both the service and its stub are new. Stored record forms do not change.

- Read an owner's request status or listing under one shared store hold and one local custody inventory, where each took two, and return only pending rows from a pending listing, which still validates every run's custody to report shape staleness and the helper's door rows. A rebuild of a lost learned index, and the custody inventory that every request write takes, now index the owner collection once instead of searching it for each record, shortening the store hold on a large store. Compatibility: update the host `superloop-lane` program; refresh each installed door service at an idle door step and repin the runs the installation lists (``rule:superlooplane:door-rebuild-rollout``), because the service's own writes and its index rebuild use the same projection. The node entry, worker stub and request record forms do not change, so either order is safe.

### Fixed

- Rebuild a door's absent, damaged or interrupted learned index before the door service binds its socket, and under the store lock on a later request write or owner `triage` or `adjudicate` that finds it so, so that a publication that once stopped between its tombstone and its index no longer sends every later request to the agent. A rebuild that cannot complete records `index rebuild refused` with its cause and keeps the named miss, without another scan on each write, until the next service start or a stopped-service `requests rebuild-index`; a capacity limit remains a named miss. A learned miss on the legacy route now journals `door learned lookup` with its class, operation, shape and reason. Compatibility: install the lane program on the host and run each door's step at an idle boundary, repinning the runs `install-door` names (``rule:superlooplane:door-rebuild-rollout``); the service's first start rebuilds an unavailable index before it accepts connections, so on a large store a request is refused by its stub without dispatch for the rebuild's length, which the service journals as `door learned index startup` with its wall. Request records and the index's form do not change, so either install order is safe and no rollback floor arises.

- Align the lane guide's producing default with `gpt-6-sol` at medium effort while keeping the door's own model setting explicit (``setup:superlooplane:door-model-and-effort``).

## [0.13.3] - 2026-11-26

### Fixed

- Let a legacy compute request's node preparation read an exited step's remaining output for up to two seconds, within the request deadline, before it concludes that a surviving writer holds the step's pipes. A Git step or checkout removal that ended just after the 50-millisecond pipe poll no longer refuses a healthy request as `door-compute-refresh-refusal` with `preparation supervisor ended while its writer remains`; a writer that really keeps the pipes open still receives that refusal and advice, up to two seconds later, or `door-request-deadline` when the request's deadline comes first. Compatibility: the preparation program is embedded in the door service and sent with each legacy compute request, so a loop receives this repair with its door step; the node entry, the wire and stored records do not change. Install in this order: on the host, replace `superloop-lane` with its entry `superloop` and the other programs of this release, since launch and resume refuse as `entry-version` unless the entry reports the lane's exact version, and let a lane process started before the rename end before its owner commands, which it can refuse with `owner-program: … (deleted): ENOENT`; refresh each pilot installation's vendor proxy with `install --pilot LOOP --refresh-proxy --dry-run` and `install --pilot LOOP --refresh-proxy`, since a boxed launch refuses as `proxy-program` until then; and for each loop that runs a door, at an idle boundary, run `superloop-lane install-door LOOP --dry-run`, stop its door service, run `install-door LOOP` and `systemctl --user daemon-reload`, repin each run listed in `repin_required_runs` with `launch LOOP RUN --repin-door --dry-run` and then `--expect-digest`, and start its door service (``rule:superlooplane:door-rebuild-rollout``, ``alg:superlooplane:door-rollout-sequence``). Until its door step a loop's legacy compute keeps the earlier preparation. Reinstalling the node entry only aligns its version, in either order. Stored records do not change, so this release sets no rollback floor: a rollback to 0.13.2 replaces the same programs, refreshes the proxy and repeats the door step.

## [0.13.2] - 2026-11-26

### Fixed

- Let simultaneous door judgements of one loop wait for the owner refresh guard within each call's existing budget, so the second request can receive its own agent verdict instead of an immediate `door-agent-refresh-busy` referral. The wait ends when the request stops or the call's cleanup allowance begins; a guard still held then refers `door-agent-refresh-busy` without starting the vendor, and the vendor never runs under the guard. Compatibility: the change is in the door service's agent runner, so a loop receives it with the one door step the next entry orders for this release (``rule:superlooplane:door-rebuild-rollout``), and until then keeps the immediate referral; the boxed stub, the node entry, the wire and stored records do not change.

- Send a declared workspace call's schema-three `compute-deadline` frame before box admission when the call comes from the box's registered worker, so a command sent while another command of its box holds the box's guards waits through the bounded guard wait and then either runs or receives `door-request-concurrent` with its admission figures, instead of `door-workspace-unavailable` after the stub's ten-second first-frame window. A stop during admission and a full peer-capacity refusal also keep their own names; capacity remains an immediate schema-two final that the workspace stub reads by name, and on every route the stub now also reads that final by name when its request write finds the door already closed, where it reported the failed write. A peer that leaves during a contended first-mode store wait now ends that wait at once, so the handler no longer holds the box's guards until the lock frees or the request deadline passes. Compatibility: the door service and boxed stub both change. A refreshed door gives the early announcement and named admission replies to every stub that sends schema three; a refreshed stub names the immediate schema-two capacity final. Schema-two calls, Git and legacy compute keep their frames. An older stub against a refreshed door can still misname a capacity refusal as `door-workspace-unavailable` or report it as a failed write; a refreshed stub against an older door names capacity but can still misname a delayed first frame or another early schema-two final. Install in this order: on the host, replace `superloop-lane` with its entry `superloop` and the other programs of this release, since launch and resume refuse as `entry-version` unless the entry reports the lane's exact version, and let a lane process started before the rename end before its owner commands, which it can refuse with `owner-program: … (deleted): ENOENT`; refresh each pilot installation's vendor proxy with `install --pilot LOOP --refresh-proxy --dry-run` and `install --pilot LOOP --refresh-proxy`, since a boxed launch refuses as `proxy-program` until then; and for each loop that runs a door, at an idle boundary, run the door step once for both door entries: `superloop-lane install-door LOOP --dry-run`, stop its door service, run `install-door LOOP` and `systemctl --user daemon-reload`, repin each run listed in `repin_required_runs` with `launch LOOP RUN --repin-door --dry-run` and then `--expect-digest`, and start its door service (``rule:superlooplane:door-rebuild-rollout``, ``alg:superlooplane:door-rollout-sequence``). Until its door step a loop's door serves as its pinned copy did, and its Git and legacy compute routes do not change. The node entry's behaviour does not change, so reinstalling it only aligns its version, in either order. Stored records do not change, so this release sets no rollback floor: a rollback to 0.13.1 replaces the same programs, refreshes the proxy and repeats the door step.

- Give fresh-launch `prepare-home`, `prepare-runtime` and all three `bound-source` publication stages a 600-second hang bound instead of the 60-second wall limit, which refused rootless Podman preparation slowed by host load in launches that succeeded when repeated. The private runner retains the same timeout refusal and cleanup. Compatibility: no operator acts and no stored form changes; a fresh-launch dry run prints `timeout_seconds: 600` for the shared setup program and `prepare-home`, and no preview digest binds that field. A step that is truly stuck is now refused after ten minutes instead of one, and for that long the run's other changing commands refuse as `launch-busy` and the loop's installations as `install-busy`, as they already did while preparation ran.

## [0.13.1] - 2026-11-25

### Fixed

- Initialize the compute class and loop mode settings from the registry floor before a declared run's first workspace request, so a quick-ruled command no longer receives `door-mode-setting-refusal: class or loop first setting is absent` merely because legacy compute has never run. Read the node entry's standard input without a userspace buffer, so a coalesced `start` or heartbeat frame no longer leaves the command at `door-workspace-not-started` with `node-heartbeat-silence` (``rule:superlooplane:door-mode-initialization``, ``proto:superlooplane:workspace-executor-call``). Compatibility: rebuild the whole `superloop-lane` crate, including its boxed stub and door service, and rebuild and reinstall `superloop-lane-node-exec` on each compute node. For each loop, refresh its door at an idle boundary and repin every run named by `install-door`'s `repin_required_runs` before restarting the service (``rule:superlooplane:door-rebuild-rollout``). The wire and stored forms do not change, so either install order is safe; until the door is refreshed an affected request can receive the old mode refusal, and until the node entry is refreshed a coalesced start can end `door-workspace-not-started` without running. A loop's first workspace request writes absent settings from its floor while retaining settings recorded by hand. Where that floor is `allow`, so is the first setting, and a miss then runs alongside judgement; a loop that wants misses to wait records `enforce` for its loop or compute class before declaring a workspace. After the tools are installed by rename, a lane process started before the rename can refuse owner commands with `owner-program: … (deleted): ENOENT`; restart each door service and let other long-running lane processes end before issuing their owner commands.

## [0.13.0] - 2026-11-25

### Added

- Print the strict canonical digests of the loop's protected `workspace-quick-policy.json` and `workspace-blacklist.json` with `superloop-lane workspace-digests LOOP`, ready for its `workers.toml` policy table. Let the loop set `workspace_deadline_ms` in `door.toml` from 60,000 through 86,400,000 milliseconds, defaulting to the ordinary 1,800,000-millisecond compute bound; `compute_deadlines` still serves legacy exact forms only. Compatibility: the command needs only this release's lane program, since it prints the same digests a 0.12.0 door already checks. Set the new key only on a door refreshed to this release, as the waiting entry below orders; a 0.12.0 door refuses it, so remove it from `door.toml` before the door step of a rollback to 0.12.0.

- Serve an allow-mode workspace miss under its filed intent while the agent judges alongside, and let enforce and audit misses publish one waiting notice, release box admission during bounded judgement, then re-read, claim and run only on an allowance. At most two workspace requests of one box wait at once; a third receives a named refusal before filing. Agent refusals and referrals record an ending without starting a command. A waited command may run for less than its requested bound so the door can stop it and report its own deadline within the window announced to the stub (``rule:superlooplane:door-request-admission``, ``inv:superlooplane:workspace-execution-follows-its-own-claim``). Compatibility: install in one window, in this order: on the host, replace `superloop-lane` with its entry `superloop`, since launch and resume refuse as `entry-version` unless the entry reports the lane's exact version, together with the other programs of this release; refresh each pilot installation's vendor proxy with `install --pilot LOOP --refresh-proxy --dry-run` and `install --pilot LOOP --refresh-proxy`, since a boxed launch refuses as `proxy-program` until then; and for each loop that runs a door, at an idle boundary, run `superloop-lane install-door LOOP --dry-run`, stop its door service, run `install-door LOOP` and `systemctl --user daemon-reload`, repin each run listed in `repin_required_runs` with `launch LOOP RUN --repin-door --dry-run` and then `--expect-digest`, and start its door service (``rule:superlooplane:door-rebuild-rollout``, ``alg:superlooplane:door-rollout-sequence``). Until its door is refreshed, a loop keeps its legacy compute route, its Git route and its owner commands unchanged; only a declared workspace needs the refreshed door, since the 0.12.0 door still refuses a request requiring judgement. The 0.12.0 node entry already serves this call, so reinstalling the node entry only aligns its version. Record forms do not change: do not roll a door or the host's lane back below the release that first wrote a workspace record in that run, and roll back only when no workspace request of the loop is waiting, because a 0.12.0 owner command would import a judged request that this release's door has not yet claimed.

## [0.12.0] - 2026-11-25

### Added

- Publish a replaceable, read-only boxed workspace context for declared runs, including the grant's first shell, and teach the stub to send schema-three argv for shell-equivalent plain words or the worker's unchanged shell text for everything else, with a one-line waiting notice. A simple leading assignment becomes an environment addition; a grant with no shell uses `/bin/sh` and reaches judgement as an undeclared-shell miss. Compatibility: the door that serves schema three is the serving caller below, in this same release; install as that entry orders. An undeclared run publishes no context and its stub sends the same schema-two bytes; Git transport does not read a workspace context. A box launched by an earlier program has the door directory bind but no context file, and keeps schema two until a later declared launch round publishes one. A schema-three stub against an older door reports `door-workspace-unavailable` at once. Stored request forms do not change for an undeclared run (``proto:superlooplane:workspace-launch-declaration``, ``proto:executecommand:compute-workspace``).

- Serve a declared run's schema-three workspace command when its protected table has an exact quick allowance or its request has a learned allowance in allow or enforce mode. The door claims the request, streams the node entry's separate output to the boxed stub, records the effect, and returns the command's status; a published blacklist entry records a refusal, while a command requiring judgement receives a named no-run refusal. A workspace command runs for at most the ordinary 1,800-second compute bound, with the requested and registered bounds announced separately and the judgement window read from the door configuration; a command the door stops at its own deadline is reported as `door-request-deadline` with both bounds, and the selected cause is kept beside the node's evidence even when no terminal frame was observed. The two owner-written JSON tables beside `door.toml` must parse strictly and match both digests in `workers.toml` and the grant (``inv:superlooplane:workspace-execution-follows-its-own-claim``, ``proto:superlooplane:workspace-executor-call``). Compatibility: the whole release installs in one window, in the order the other entries here refer to: replace `superloop-lane` with its entry `superloop`, the private `requests-helper` and the lane gateway's `gateway-service`, all from this release, restarting a running gateway service on the new program; rebuild and reinstall `superloop-lane-node-exec` on each compute node, in either order with the doors, since the 0.11.0 entry speaks the same protocol; then for each loop at an idle boundary run `superloop-lane install-door LOOP --dry-run`, stop its door service, run `install-door LOOP` and `systemctl --user daemon-reload`, repin each run listed in `repin_required_runs` with `launch LOOP RUN --repin-door --dry-run` and then `--expect-digest`, and start its door service; and refresh each pilot installation's vendor proxy with `install --pilot LOOP --refresh-proxy --dry-run` and `install --pilot LOOP --refresh-proxy` (``rule:superlooplane:door-rebuild-rollout``, ``alg:superlooplane:door-rollout-sequence``). Declare no workspace before that order is complete for the loop. The typed quick-rule citation's reader arrives with its writer, so after a quick-rule workspace command starts, do not roll any door or host reader back below this release: an older reader refuses that record, and a bound collection can then refuse the loop's records. A 0.11.0 door also refuses a `door.toml` that sets the optional `workspace_judgement_wait_ms`, whose default is 30 seconds, so leave it unset while a rollback below this release remains possible. Undeclared runs and schema-two Git and compute requests keep their existing path. This release does not serve judgement waits or allow-mode misses; do not invite loops to declare workspaces until a release that serves them is installed.

### Fixed

- Size the request-owner transport cap for two collection images and its envelope, so a request collection can still be triaged or adjudicated after it grows beyond half its storage bound. Oversize input refusals now name the measured bytes and cap. Compatibility: the new 193 MiB bound is shared by `requests-helper` and its two clients, `superloop-lane` and the lane gateway's `gateway-service`, which are installed together as the serving entry under Added orders; the stored collection and wire shapes do not change. Owner commands run by the host's lane reach the new bound as soon as those programs are installed, while a door still running its 0.11.0 copy keeps the 64 MiB bound for its own publications until its door is refreshed.

- Cancel a workspace command when the node entry's output reader fails, and close a failed pipe setup without waiting for the control route's silence bound (``proto:superlooplane:workspace-executor-call``). Compatibility: no wire or record shape changes; a reader error now ends the command and reports incomplete output, and the repaired node entry is reinstalled on each compute node with this release, as the serving entry under Added orders.

## [0.11.0] - 2026-11-24

### Added

- Read the workspace caller terminal states and node observation before a serving caller writes them, count the three new endings separately from pending in request shapes, and bind the observation's reason, ending and outcome to the adapter's results (``proto:superlooplane:workspace-readers``). The existing reply reader accepts the documented final reason names. Compatibility: this release writes no new workspace record or reply, and the readers need no box repin of their own. The whole release installs in one window, in the order the other entries here refer to: at an idle boundary for each loop, with no request in flight, stop its door service; replace `superloop-lane`, whose release carries the door service, door stub and vendor proxy, together with its entry `superloop` and the private `requests-helper`, all from this release; then for each loop run `superloop-lane install-door LOOP --dry-run`, `install-door LOOP` and `systemctl --user daemon-reload`, repin each run listed in `repin_required_runs` with `launch LOOP RUN --repin-door --dry-run` and then `--expect-digest`, and start its door service; refresh each pilot installation's vendor proxy with `install --pilot LOOP --refresh-proxy --dry-run` and `install --pilot LOOP --refresh-proxy` (``rule:superlooplane:door-rebuild-rollout``, ``alg:superlooplane:door-rollout-sequence``); and rebuild and reinstall `superloop-lane-node-exec` on each compute node in the same window, rehearsing it over the registered route before a later workspace caller is enabled. The derived shape index is repaired from records; once a later caller has written these forms, a rollback must retain this reader.

- Build the unselected door half of the workspace executor call: the protected route's node name binds the grant before SSH, the door composes and checks protocol-one frames over the constant node entry, maps node endings by reason into typed door results, closes an acknowledged stopped route within a bound, and retains the entry release and incomplete output as evidence (``proto:superlooplane:workspace-executor-call``). Compatibility: no serving caller uses this adapter, so no request record or reply changes on a serving path; the updated node entry installed with this release and the existing node-named route registration are what a later caller uses, and operations rehearses the installed entry over the registered route before any declared workspace run is activated.

- Show the latest durable `incomplete` attempt in `requests status LOOP` as `incomplete_attempt`, beside the request counts, even if the owner helper committed a completed row before the lane found a differing publication reply; the historical marker remains after later completion (``test:unit:status-names-incomplete-attempt-after-successful-owner-commit``). Compatibility: the existing attempt journal and request records keep their formats; the lane status output gains an object or null, so a consumer that validates its exact top-level keys must accept that field. It needs the updated lane program, installed as the workspace-reader entry above orders, and no box, run or record rewrite of its own; a loop's pinned door service keeps writing the marker it already writes.

### Changed

- Carry the node entry's observed child start in its terminal and the door's evidence, and name a command that fails before spawn as `node-start-failed`, with `not-found`, `not-executable` or `other` and the attempted step index. A quiet command that started and was stopped remains interrupted, and `not-started` requires positive evidence that no child of any step started. The node frames one diagnostic on standard error; the door maps it to command status 127 or 126. If an earlier child leaves output held when a later start fails, `node-output-incomplete` and `incomplete` take precedence; if it reaches the output limit, `node-output-limit` and `refused` take precedence instead. Both retain `start_failure` only after an earlier child started, and the record reader checks the adapter's actual mapping (``test:unit:workspace-node-held-output-precedes-a-later-failed-start``, ``test:unit:workspace-node-output-limit-precedes-a-later-failed-start``, ``test:unit:workspace-failed-start-status-is-record-readable``; ``proto:superlooplane:workspace-executor-call``, ``proto:superlooplane:workspace-readers``). Compatibility: the node entry and the lane carry it, installed as the workspace-reader entry under Added orders. The terminal adds the optional `child_started` and `start_failure` members within protocol one; an older door that selected this route would refuse them, but no released serving path selects it. A new door reads a 0.10.0 entry's missing start observation as unknown and never calls it `not-started`. No existing record is rewritten.

- Make the workspace disposition follow the door mode: a published blacklist entry blocks in every mode; under allow a quick or learned allowance runs at once, a miss runs while it is judged and a learned refusal runs with what the door would have done recorded; under enforce a quick or learned allowance runs at once, a miss waits for judgement and a learned refusal blocks; under audit every request waits (``proto:executecommand:compute-workspace``). Compatibility: nothing calls the workspace disposition yet, so no deployed door, request or record changes.

- Let an absolute shell absent from the workspace grant's declared shell list reach judgement, marked as an undeclared shell in the agent input; the node executor no longer refuses it at admission (``proto:executecommand:compute-workspace``). Compatibility: the node entry and the lane carry it, installed as the workspace-reader entry under Added orders; no deployed door selects this route yet, so existing requests and records do not change.

- Bound the node entry's wait for start to ten seconds or its command deadline, without renewal by heartbeats; running heartbeat silence retains its separate 120-second bound (``proto:superlooplane:workspace-executor-call``). Compatibility: the node entry carries it, installed as the workspace-reader entry under Added orders; old and new door halves send the same call and start frames. No deployed serving caller selects the workspace route yet.

### Fixed

- Close the node entry's internal output-pipe descriptors on exec, so a command or unrelated process cannot keep those pipes open after the command's standard streams close; a failed start retains its `node-start-failed` reason and a daemon with closed standard streams no longer causes `node-output-incomplete` (``test:unit:workspace-node-closed-standard-streams-do-not-hold-output``). Keep a close-on-exec read end until the command ends, so cancellation stops a blocked command before a broken pipe lets its shell continue (``test:unit:workspace-node-entry-stalled-output-bounds-memory-and-command``). Compatibility: no wire or record shape changes; the repaired node entry is reinstalled with this release in the workspace-reader install window under Added.

- Preserve duration-derived float bits when the lane and owner helper decode a compute request's nested effect record. A realistic record changed `preparation_wall_seconds` by one ULP at the owner boundary and made the helper refuse the candidate as a changed evaluated transition; the shared JSON parser now uses round-trip float decoding. This reproduces a precommit refusal, not the reported postcommit reply mismatch (``test:unit:compute-record-survives-owner-service-publication``, ``test:unit:compute-record-measurements-survive-owner-service-sweep``). Compatibility: request record schemas and serialized fields are unchanged, and existing records need no rewrite. The lane, a loop's pinned door copy and the host's one `requests-helper` decode a publication on either side, so the repair holds only between programs of this release: install as the workspace-reader entry under Added orders, with each loop's door stopped and no owner `requests` command running from the helper's replacement until that loop's door is refreshed; a mixed old and new pair can still disagree on a float, as the 0.10.0 programs did. Historical incomplete markers remain visible in `requests status`.

- Keep a completed door command's streamed output and exit status when effect recording or publication fails, while printing `door-record-incomplete` and the record error beside them (``test:unit:door-stub-keeps-command-status-after-effect-record-failure``, ``test:unit:door-compute-stub-keeps-command-failure-beside-record-failure``). Compatibility: the change is in the door service, installed as the workspace-reader entry under Added orders; the stub already installed reads `status` and prints `request_record_error`, so it needs no box rebuild or record rewrite of its own, and the runs `install-door` lists are repinned there as for any rebuilt stub. A record failure before execution still refuses with status 125, and no command is replayed.

- End a present-route compute command's process group when the door closes its node route, including a silent command or preparation step, preserve the worker's standard-input EOF independently of route life, and bound node lock waits, Git preparation and partial-checkout removal by that request's deadline and route life, with each preparation writer retaining the run lock if the node script dies and a marked checkout rebuilt on the next request (``proto:superlooplane:door-request-lifetime``, ``proto:superlooplane:compute-checkout-preparation``). Compatibility: the change is in the lane and its pinned door service, installed as the workspace-reader entry under Added orders; the embedded node script travels with each request, so it needs no separate node install or record rewrite. A stopped request retains its existing deadline or disconnect reason. A surviving preparation writer keeps the run lock; a later request can name that holder for inspection if its node footer reaches the door within the request's remaining lifetime, otherwise the door reports its deadline. The worker command inherits no run lock, and a nested timeout may continue to bound a command after its outer supervisor dies. A supervisor signal death before the deadline is reported as the command result, including the rare case where an outside actor killed only that supervisor.

- Let `retire LOOP RUN --dry-run` answer for a boxed run whose worker home the caller cannot enter: `worker_projection` reports `{"present":null,"visibility":"not-visible-to-caller"}` on permission denial, while present and absent entries the caller can reach keep their current report (``test:unit:public-retire-preview-reports-a-hidden-worker-projection``). Compatibility: a retirement preview that refused as `retire-projection` solely because the caller could not traverse the worker home now prints `would-retire` with unknown projection presence, and a retirement confirmed with `--confirm-missing-lease` or `--confirm-missing-harvest-fields`, which builds its plan from that preview, no longer refuses there either; an unrelated I/O error still refuses, the preview digest keeps the same inputs, and a plain retirement never made this read. A loop whose run refused previews it again and retires it with that preview's digest; a projection the preview could not see stays inside the retired home.

- Refuse a first `launch --door-scope work` without the door's complete registered route, with the same `door-scope-route` remedy as `set-door-scope` (`dec:door:the-door-is-measured-against-the-unmediated-host-worker`). Compatibility: existing records and successful routes are unchanged; a work-scoped first launch that previously reached later preflight or reservation without a valid route now refuses before reservation. Review-scoped launches are unchanged.

- Make `set-door-scope` say what to do next: a preparing run's refusal reads the run's preparation lease, waiting while a launch holds it, naming the retirement preview when it is unheld and its missing-lease confirmation when it is absent, and inferring nothing when it cannot be measured; a pending whole-record rewrite refuses with its resume; and a `work` target is read through the door's own route loader and given the registered node alias, mirror path, run ref and clone remote address (`dec:door:the-door-is-measured-against-the-unmediated-host-worker`). Compatibility: reservations and history keep their form, and no door restart or record rewrite is needed; a pending rewrite, or a missing or malformed registered route for a change to `work`, now refuses before the change, naming its resume or the registration it needs, where the command previously could proceed.

## [0.10.0] - 2026-11-22

### Added

- Let a loop preview and digest-bind a `superloop-lane set-door-scope` change on an existing unretired run, with a bounded history; census now shows each run's `door_scope` (`prin:publictools:well-made-and-good-to-use`). Compatibility: install the lane command without restarting the door; old records read with empty history and gain it only on change, and a release without this command reads a changed record by its new scope and ignores the history, so a rollback needs no step. Started runs use the new scope at their next request read, settled runs at their next round; requests already read keep their admitted scope. Preparing, retiring and rotated runs refuse; outstanding digest-bound previews must be repeated after a change. Switching to `work` does not seed the node mirror or a remote in the worker clone.

- Install the protocol-one `superloop-lane-node-exec` entry for an admitted workspace call. It checks the bounded frame, grant, placement and installed node identity before opening the workspace, frames typed pre-acknowledgement refusals, names its build in the acknowledgement, starts only after a separate control frame, bounds queued output and blocked writes, reports node-specific ending causes including endings before start, and marks held output pipes incomplete after an idle or total drain bound (``proto:superlooplane:workspace-executor-call``). Compatibility: installing this unselected node entry changes no running door or stored record; operations build and install the entry and its root-owned identity file on each node, and confirm the registered alias-to-name mapping, before a later door caller is activated.

- Add a read-only reply designation query to the held loop-home reply session: it lists retained delivery instants and phases for one worker, loop recipient and exact outgoing name (``spec:loophome:reply-designation-query``). Compatibility: no public command, round record or settlement behavior changes and no operator acts; nothing calls the query yet.

- Read the door's stored workspace judgement input: an agent-judged `compute-workspace` record requires `workspace_agent_input` and every other record refuses it. Its execution, working directory, environment and grant must equal the record's workspace effect, its readable display keeps only the execution's shape, and its flag rows must be true of the exact bytes and, with the omitted count, account for every non-ASCII code point and ASCII control; the reader renders no display and applies no flag selection beyond that floor (``inv:superlooplane:stored-workspace-agent-input-reads-from-its-record``). Compatibility: no door writes this field yet and no store holds a workspace record, so door requests, records and answers are unchanged and no operator acts now; every door loop installs this release before any later release that writes workspace judgement records, and a rollback from that later release returns to this release, not to 0.9.0, whose reader refuses the field.

- Show counts of round rows without a reply designation and pending whole-row images in `superloop-lane census`, naming each affected run and its available recovery command (``alg:superlooplane:run-census-and-admission``). Compatibility: census adds a read-only result member and now refuses a malformed or unknown-phase rewrite journal as `census-record`, naming the journal's path, instead of listing it among skipped names; it changes no reservation or journal and performs no conversion, and an operator acts only where that refusal names a journal.

- Record `reply_designation: {"state":"unmeasured"}` on newly created first and continuation round rows (``spec:superlooplane:round-reply-designation-member``). Compatibility: existing rows keep their form, and ordinary readers accept rows with or without the member; no reply is designated or selected.

- Add `superloop-lane census rewrite-replies LOOP` with a read-only preview, digest-bound apply and resumable per-digest journal for live and retired round rows (``alg:superlooplane:round-reply-row-rewrite``); census now also counts invalid members, reports retained record count and bytes, aggregates rows without the member by run with this command, and lists rollback images as evidence rather than blockers. Compatibility: no installation hold or ordinary-reader change is required; each loop converts during its own paused minute, and an older process can create another old-form row that census counts for a later conversion. The loop operator must attest that its mail cutover is not pending because lane commands cannot see that state.

### Changed

- Bind each protected door SSH registration to its node's registry name: `door-node-registration.json` gains a required `node` member in the node identity file's grammar, written by `register-door-node LOOP --node NODE` and read strictly (``proto:superlooplane:door-node-registration``). Compatibility: every reader refuses a registration without `node`. `install-door` and `retire LOOP RUN --node` refuse as `door-node-registration` and name `register-door-node --node`; a door service of this release answers every routed request, Git transport included, with `door-compute-unregistered` and logs the `door-node-registration` refusal until its route is re-registered. In the release window, stop each door, run `register-door-node --dry-run` with the route's current facts and `--node` set to the node's registry name, check that both transport actions read `unchanged` and that the registration gains only `node`, repeat with `--expect-digest`, preview and apply `install-door`, then restart. A rollback below this release re-registers with that release's command, without `--node`, because its reader refuses the new member. No serving path reads `node` yet, and runs and stored request records do not change.

- Admit every well-framed, work-scope command through the registered compute route without a Cargo or Git family list: the route keeps its one-command frame and its refusal while admitting literal `~`, `^`, `@`, `%` and `#` bytes in its words, the shape keys and the readers of the two retired refusal reasons, resolves a first word containing a slash against the run's prepared checkout, and the direct `superloop command judge` keys every argument vector under its general command key (``prob:door:the-old-compute-routes-command-list-is-deleted``; ``prob:door:compute-grammar-admits-command-families-by-measured-shape``; ``test:unit:compute-frame-admits-unlisted-command-families``; ``test:unit:direct-judge-argv-uses-general-command-key``). Compatibility: deploy `superloop-lane`, `superloop-lane-door-service` and `superloop` together and restart each door; the node needs nothing, since the service sends its node program with each request. A previously unlisted command now reaches judgement, under allow running while it is judged and under audit or enforce waiting for it; existing learned labels and rubric rows keep their shape keys and now cover every command sharing a shape; installed deadline forms still read; and a direct Cargo argv no longer shares the door's compute labels. An older reader refuses a store holding a compute record with words its list did not admit, so roll back only before the first such record, or after the runs holding those records are retired and then with no learned-index rebuild on the older release, since a rebuild also reads retired custody. The former ``rule:superlooplane:door-cargo-admission`` is withdrawn.

- Answer a work-scope lane's push to its own registered mirror with the door's transport rule instead of the door agent, recording `transport-rule` as the decision source with the registered `mirror_ref`; the transport still checks every ref of the push's command list against the registered ref before forwarding any byte, and refuses a push naming another ref with nothing forwarded (``test:unit:door-registered-receive-rule-skips-agent-and-keeps-packet-refusal``). Compatibility: every door loop runs 0.9.0 or later, whose reader accepts `transport-rule` records, before installing this release, then restarts its door; allow and enforce pushes of the registered ref skip the agent call, audit still waits for the loop's judgement, refusals keep their reasons, and a rollback from this release returns to 0.9.0, not to 0.8.2, whose readers refuse the new source.

### Fixed

- Read only a saved plan without a backend field as the legacy Codex form, and refuse an explicit null backend as `backend-selection`, as the strict plan reader already does (``test:unit:saved-backend-reader-keeps-legacy-codex-default``). Compatibility: no released writer stores a null backend, so valid saved plans, reservations and records read as before.

- Start each exercise probe box from a process whose soft and hard core limit is zero, set by the exercise command before it starts the container program, and refuse as `exercise-core-limit` if it cannot set it (``test:unit:exercise-probe-box-inherits-zero-core-limit``). Compatibility: the exercise command keeps the zero limit for the rest of its run; pinned box vectors, plans, reservations and records do not change, and no operator acts.

- Withdraw a boxed worker's published sign-in projection when the helper cannot write the preparing reservation after publishing it, and keep the service's or the reservation's own refusal when the withdrawal cannot start or meets a changed entry (``test:unit:claude-fixture-service-round-reservation-write-withdraws-publication``; ``test:unit:helper-withdrawal-setup-refusal-keeps-service-error``). Compatibility: a failed preparing-reservation write now withdraws the projection it had just published before its refusal is returned; the refusal an operator reads keeps its kind and text, with any withdrawal failure appended as cleanup evidence; no pinned plan, reservation or record form changes.

- Withdraw a boxed worker's published sign-in projection, `.codex/auth.json` or `.claude/.credentials.json`, once the helper's registered service has stopped the box and joined its authority thread, by metadata beneath the worker's credential directory without opening the entry; keep the next round's publication before readiness, report projection presence by metadata in `retire --dry-run`, and set the helper's core limit to zero, soft and hard, before it serves (``test:unit:codex-worker-projection-withdraws-and-republishes``; ``test:unit:codex-service-end-withdraws-the-worker-projection``; ``test:unit:claude-fixture-service-round-publishes-read-mode``). Compatibility: existing runs resume unchanged and republish their projection at their next round; the projection is now absent between rounds and in newly retired homes, while homes retired earlier keep the file earlier releases left and a killed helper leaves its projection until a later removal; `retire --dry-run` output gains `worker_projection`; the Claude half stays behind the closed production gate; a helper crash leaves no core file and is diagnosed from its error and a fixture.

## [0.9.0] - 2026-11-21

### Added

- Accept the door's registered receive transport rule as a request record's decision source, `transport-rule`, kept on the deterministic rung of retained decisions and bound to the record's mirror ref (``test:unit:registered-receive-rule-round-trips-and-binds-the-mirror-ref``). Compatibility: no door writes this form yet and existing records keep theirs; every door loop installs this release and restarts its door on it before any later release that writes transport-rule records is installed, and a rollback from that later release returns to this release, not to 0.8.2, whose readers refuse the new source.

- Read a door's workspace request against the grant its loop declared at launch, taken from the run's protected reservation through the registered runs descriptor and checked against the registered loop, run, worker and scope and the caller's node, with the request's original wire decoded once by the strict envelope decoder (``test:unit:door-workspace-request-binds-protected-grant-and-raw-wire``). Compatibility: no production caller selects this reader yet, so door requests, records and answers are unchanged and no operator acts.

- Pair the workspace classifier's exact agent input with an escaped, display-only rendering of each execution word and shell text, and flag the U+2028 and U+2029 line separators with their field and byte offset (``test:unit:workspace-agent-input-pairs-readable-execution-with-exact-bytes``). Compatibility: no door request, record or route changes and no operator acts; the rendering appears only when a later release activates the workspace route.

### Changed

- Default the boxed Claude helper's owner credential path to access-only reads and publication; due or expired authority refuses without invoking the vendor program. An owner-held cutover request remains refused until carrier exclusion can be proved (``inv:superlooplane:one-claude-source-refresher``). Compatibility: the production Claude gate remains closed, Codex boxes are unchanged, and Claude owner checks can now refuse as `credential-read-due`, `credential-read-expired`, `credential-mode` or `credential-cutover-gate`.

- Refuse named vendor credential variables in a box plan, owner sign-in binds at launch, and recognized credential files in image and install inputs as `credential-environment`, `credential-mount` and `credential-image-input`; pin the Claude periodic cutover refusal at its production entry (``inv:superlooplane:box-inputs-exclude-recognized-credentials``). Compatibility: the production Claude gate remains closed; Codex plans, launches, builds and installs now refuse the same recognized credential inputs, while ordinary Codex boxes and harvest keep their existing forms; a loop whose inputs are refused removes the named variable, bind or file and reruns the command.

### Fixed

- Admit the exact `tmp/arg0-linux` dispatch scratch tree alongside `tmp/arg0` during sign-in convergence, and raise the private installation report's bound from 65536 to 1048576 bytes, beneath the child runner's 2097152-byte output bound, so the report keeps its per-entry metadata for a vendor-maintained tree of several hundred changed entries (``test:crate:pilot-install-preserves-arg0-linux-dispatch-links``, ``test:crate:pilot-install-reports-large-fictional-sign-in-walk-in-preview-and-act``). Compatibility: previews and acts of `install`, with or without `--pilot` and `--refresh-proxy`, and of `repair` that refused on a link inside `tmp/arg0-linux` or on a private report between 65536 and 1048576 bytes now complete, and an acting installation without `--refresh-proxy`, or an acting repair, then converges the vendor-maintained `plugins`, `skills` and `cache` entries to owner-only modes and lists each repair; the report keeps its shape, every entry outside the two named scratch trees keeps its link and type refusals, a link refusal now names the full sign-in path and a remedy where it named only the entry, and an oversized refusal names the sign-in path and the inspection step.

- Name the searched round window and each in-window worker delivery with its complete `bind-reply` command in a missing-binding launch refusal whose saved state admits a late binding; when none is present, name the box report that needs a hand reading, and null-readback settlement only when the saved state admits its preview. Compatibility: the refusal keeps its exit status and reservation state; its report and error detail now carry candidate instants and recovery commands, and no delivery is bound by launch.

- Select the protected run's backend for `record-hosts`, observed-plan conflicts, network evidence and the network exercise, so a Claude run cannot read or write Codex's reviewed host list and `record-hosts` writes the reviewed names under the run's own backend (``test:unit:network-evidence-selects-saved-backend-hosts``). Compatibility: Codex-only loops keep the same host list, settings bytes and refusal details; a saved run whose backend program is no longer configured still refuses `missing-setting` from the saved-run loader before `record-hosts` writes anything, and the enforcing vendor proxy still serves only `vendor_hosts.codex`.

- Run a Claude launch dry run through the launch's installed-input and read-only preview checks before the closed `backend-unavailable` gate; check source custody from metadata without reading its document, and the refresh-mode marker and any existing refresh lock as the act does without creating the lock, defer the unanswered Claude driver contract to launch time, and name the selected backend in setting refusals (``test:crate:claude-dry-run-reaches-every-launch-check-before-the-gate``). Compatibility: a Claude-only operator now sees the first launch check that refuses before the final runtime gate, whose refusal says the read-only checks passed and carries source custody metadata, while changing Claude launches remain gated first and Codex launch behavior is unchanged.

- Select a Claude-only loop's configured backend in the public `plan` and `make-home --letter` forms and the free-worker-UID chooser; keep Codex as the default when both programs are configured (``test:integration:plan-previews-the-configured-boxed-backend``). Compatibility: a Claude-only candidate now reaches plan construction instead of refusing for absent `backend_argv.codex`, and `make-home --letter` now creates a Claude-shaped home for such a loop, with no credential file; existing Codex candidates keep their selection, and production Claude launch remains closed.

- Rebuild saved-run plans for the backend named by their reservation across settlement, harvest, follow, checkpoint, import, checkout, exercise, rotation and resumed rounds; an absent backend in a legacy record keeps the Codex default. Service fixtures wait for joined threads to disappear from procfs under their hang guard (``test:unit:claude-only-settle-reads-recorded-backend``; ``test:unit:claude-only-resume-reads-recorded-backend``; ``test:unit:codex-only-record-readers-keep-the-default``). Compatibility: the production Claude gate remains closed and valid Codex runs retain their plan. A malformed or unsafe reservation can now be refused while the backend is selected, before a later saved-run check, and a loop whose settings are broken in more than one way may now see its registry or settings-grant refusal before the backend-setting refusal.

- Carry the verified runs root into helper service and private runtime preparation instead of selecting a Codex plan to find the reservation; align the Claude fixture's installed paths with the loop root and default its held runtime to a stand-in (``test:unit:helper-service-plan-readers-keep-wrapped-gate``; ``test:unit:helper-service-refuses-a-run-outside-registry-runs-root``; ``test:crate:claude-service-fixture-defaults-to-held-standin-runtime``). Compatibility: the production Claude gate stays closed, and no refusal kind changes for a Codex loop: the helper service already reported a broken `backend_argv.codex` inside `helper-pin`, and private preparation still reports it as `missing-setting`, now after reading the run's reservation, so a preparation without a reservation reports `launch-reservation` first. No reservation or install record changes.

## [0.8.2] - 2026-11-20

### Fixed

- Keep learned shape history in the door's fast lane and operator records, but send no earlier request text, identifiers, verdict reasons or adjudication reasons to the bounded agent on a miss (``inv:superlooplane:door-agent-input-has-no-learned-history``). Compatibility: the agent for both `superloop-lane` and `superloop command judge` now sees only the current request, capability class, fixed instruction and reviewed rubric, so its verdict on a miss can differ where an earlier verdict leaned on earlier reasons; a lesson a door loop means to outlast a run belongs in its reviewed rubric or in the agreeing labels the fast lane decides by. Stored records and the learned index need no rewrite or rebuild. Install `superloop-lane` and `superloop` together and restart each door.

- Make the door wait-error fixture assert the durable disconnect, skipped final write and incomplete attempt after closing its client at the read boundary, independent of which stop check observes the close. Product behavior and record formats are unchanged (``test:unit:door-wait-errors-send-final-and-record-incomplete``).

## [0.8.1] - 2026-11-19

### Changed

- Link sign-in operations and permission-triage referrals to the generic owner-desk list (`[ORCHESTRATION-reg:oper:owner-desk-list]`), distinguishing an unmet command condition from a new owner decision without changing command or classifier behavior. CONTRIBUTING defines the citation form and routes to the existing invariant statements.

### Fixed

- Admit up to eight content-free client `error` notices completed before the door agent's turn, counted as `startup_notice_count` without their text, while retaining strict in-turn item refusals; a failed turn no longer supplies a verdict, even after a message. Drop the ignored `sandbox_permissions` override and keep read-only sandboxing and the disabled code-mode host. Compatibility: the runner travels in both `superloop-lane` and `superloop`; stop each door, install both programs, then restart the door before its next agent judgement; records gain the count and need no conversion (``prin:publictools:well-made-and-good-to-use``; ``test:unit:agent-startup-notices-are-content-free``; ``test:unit:agent-startup-notice-limit-names-overflow``; ``test:unit:agent-failed-turn-with-message-refuses``).

## [0.8.0] - 2026-11-19

### Added

- Before each door agent start, the owner publishes the current access-only Codex projection under the loop refresh lock, then releases that lock before the client runs. The entered receiver rejects renewable input and clears checked stale temporaries; the manual full-source `door-sign-in` command and its credential digests retire. Content-free expiry evidence and typed pre-start referrals distinguish owner authority from local publication failures. Compatibility: verify each door's accepted template client; drain and stop each door, remove its former renewable copy and leftover placement temporaries as the loop with `superloop enter LOOP -- /usr/bin/sh -c 'rm -f -- "$HOME/.codex/auth.json" "$HOME"/.codex/.door-auth-*'`, then run `install-door` and start the door; no per-renewal placement is due. `superloop command judge` misses use the door's last projection and refer once it has expired (``prob:door:door-credential-follows-the-canonical-sign-in``; ``proto:superlooplane:door-access-projection``).

- A clean build configured with the workspace release tag installs a separate regular `superloop-lint-<tag>` and its build record beside `superloop-lint`. The command hook recognizes release-shaped tagged names, and the version smoke checker accepts the tagged installed name when invoked against it. Other valid build tags retain their existing install without a tagged copy. Compatibility: the plain command remains the linter installed by that build; build-sync's census reads the workspace version only when a build tag is configured, and refuses a tagged build whose workspace declares none (``prin:publictools:well-made-and-good-to-use``).

### Fixed

- Make the helper close test shut down its stop peer's receive half before checking a failed acknowledgement. Dropping one descriptor alone can leave another holder able to receive the byte. Compatibility: no program or record format changes (``test:unit:helper-close-answers-every-queued-control``).

- Publish the scope-floor design reasoning, recorded vendor facts and open reliance choices without changing execution or activation (`rec:scopefloor:directory-and-expansion`).

- Clarify that non-erasing command-text inspection does not establish runtime working-directory or filename-expansion containment (``rule:permissiontriage:command-string-scope-extraction``).

- Formatter refusals now say that an integrity failure would change the document's meaning and describe a writer failure using the error shown in the same message. The writer refusal also confirms valid Markdown. Native build guidance tells deployers to record private merge and lock inputs separately (``rule:output:linter-findings-status``; ``reg:superlooplane:native-build-provenance``).

- Door agent invalid-output records now name the first refused item by a checked kind, item-event phase and one-based stream line, without retaining the item's text. Unknown, warning-shaped and tool items still refuse until an observed kind can justify a narrower rule. Compatibility: a door loop sees `agent_observations.answer.unexpected_item` on this refusal; verdict and tool-free admission rules do not change (``prin:publictools:well-made-and-good-to-use``; ``test:unit:agent-unexpected-items-name-kind-and-position-without-text``).

## [0.7.0] - 2026-11-17

### Fixed

- Clarify the door record wave’s retained owner executable and step-4 path report, live triage admission holds, and failed-round repinning. The repin binds only the stub digest; the service verifies the compute SSH configuration per request. Compatibility: operators retain `changed` from the wave's first `pause`, resume only a pause introduced by the wave, and run the ordinary resume dry run after admission resumes. No program or record format changes (``alg:superlooplane:door-request-life-deploy``).

- Door lookup and queue fixtures wait for durable filing or entry into the store read before selecting expiry or closing their peer. Compute and input deadline fixtures inject expiry at the check they claim; the open-input case proves completion before releasing its reader rather than requiring a short wall. Tests only; installed request limits and the deployment wave are unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- An observed full peer close now ends admission, owner wait and running compute alike: no final is attempted, the durable final-write observation is `not-attempted`, and the service returns successfully. A close selected during a request-store read retains its typed disconnect cause instead of becoming a read failure and logs the coincident store error under a stop-specific journal prefix. Compatibility: the unreleased ending shape gains `not-attempted` while `unknown` remains for lost observations; the service result changes and a spurious broken-pipe diagnostic disappears. The request-life wave still supplies the one refresh and restart, with no additional rewrite or operator step (``prob:door:a-door-requests-life-is-watched-stopped-bounded-and-recovered``).

- The door gives final replies the remaining request lifetime instead of a separate two-second write window. A slow live peer can drain queued output and receive its final; a partial final closes the write half and cannot be followed by credit. The stopped-caller notice rounds the remote bound upward to whole seconds, explains its unobserved start and admits a repeat without asking the worker to await a loop response. Compatibility: the door and SSH stub receive these changes through the same coordinated rewrite, repin and restart wave; no second stop or new record shape is required (``prob:door:a-door-requests-life-is-watched-stopped-bounded-and-recovered``).

### Added

- Door stop replies now carry the remote state and supplied relative bound, and the SSH notice tells the caller whether to ask again or report an unconfirmed effect to its loop. Top-level effect and reply walls identify their awake monotonic clock, distinct from the suspend-counting deadline; historical clocks remain unobserved. Compatibility: these required ending fields join the held record rewrite and the same coordinated door reinstall/restart wave. The wave names digest-bound repinning and the startup recovery retry commands.

- Door finals count only complete output frames delivered before them and seal the writer against later output. A child's exit no longer starts a two-second delivery race: output drains under the request lifetime, with a typed stop on expiry or full close. A partial failed frame closes the stream and leaves its terminal evidence in the record. Compatibility: this repair rides the request-life rewrite and reinstall wave, with one restart per door (``proto:superlooplane:door-request-lifetime``).

- Door requests count their deadline from acceptance on the boot-time clock through admission, judgement and compute; suspend no longer extends that budget. A full peer close stops those phases, while half close and Git receive/upload retain EOF semantics. Replies and durable endings retain one typed first cause, and compute SSH uses the derived 30-by-4 keepalive. Compatibility: deploy both request-life slices in the coordinated stopped-door rewrite and reinstall wave; keep every affected loop and shared installation held until its own conversion and startup checks complete. Missing interrupted measurements are null rather than invented zero. The wave distinguishes running publications from effects awaiting startup recovery and states the shared-installation and first-apply rollback boundaries (``proto:superlooplane:door-request-lifetime``; ``alg:superlooplane:door-request-life-deploy``).

- Door request effects retain their ending cause, local final-write observation, child disposition and the remote timeout's unobserved start. Startup marks stranded pending requests abandoned; installer previews report whether admission locks are idle. Compatibility: hold the global tools install until every affected loop has quiesced boxes, exercises and retirement, finished active publications, retained idle recovery entries and stopped its door. Each loop then previews and applies its own digest-bound rewrite, refreshes and starts with the new tools. Finish all old record commands before global replacement. The first rewrite write prohibits old-reader rollback; a failed apply leaves the door stopped until its resumable transaction completes. Apply refuses a live service; interrupted rewrites resume and are not atomic across all files. Coordinate this record change with the accompanying behavior slice in one restart wave (``sec:superlooplane:door-request-endings``).

## [0.6.0] - 2026-11-17

### Changed

- The readable version sentence names the full public source tree before its commit. Install matching linter and pack releases together; the deploy's explicit `tools_source_commit` handover also names the public commit in build records (``spec:output:linter-build-identity``).

- Formatter refusals pin table-row and table-header ranges across overlay slots, give an ambiguous header a line, a range and an action, and name the first differing writer event. A writer refusal asks for the smallest non-private excerpt that still refuses, shared with whoever supplied the build together with its build record's identity, and states that the package declares no public issue route; a run retained by a reference-dependent list can start before the failing block (`rule:output:linter-findings-status`).

- Linter identity includes the public commit's tree, allowing equal public source to be recognized across commit histories. Version answers put their readable message first and name an unavailable artifact digest plainly. Malformed diagnostics remain visible as identified JSON error records. In-tree Meson builds use ignored `build/`; generated outputs no longer invalidate the source observer. Compatibility: the citation-sites reader requires identity, so deploy the matching `superloop-pack` and `superloop-lint` together; a null artifact digest remains accepted (``spec:output:linter-build-identity``).

### Fixed

- Inspect literal command text independently of shell and launcher body selection: every argument and redirect, including option values, positional arguments and printf/echo data, is inspected at any bounded depth of literal command text, so a visible refused path cannot hide when a recognizer picks the wrong body. Option-bearing sh/bash and dash/ksh/zsh `-c`, literal `env -S`, `stdbuf` and `flock` launch forms are interpreted with the existing parser; nonexecuting help and version queries carry no body, and unsupported command-string or launcher grammar is unresolved, with a refusal naming a supported literal-body spelling. Brace expansion is unresolved, and paths after equals, colon or attached option letters are checked. Unparseable data uses a quote-dropping lexical view, preserving ordinary prose and patterns while exposing their path fragments. Compatibility: inline protected-path data and brace-bearing text can acquire estate scope; ordinary timed builds and benign stdin controls keep their verdicts. Encoded producer output, unread script inputs, fixed refusal-family remedies and replay remain deferred (``rule:permissiontriage:command-string-scope-extraction``).

- The topology probe gives its own canned classifier a 20-second hang bound, below the harness hook timeout, so host load no longer fails an otherwise complete acceptance trial at two seconds; the deliberate 20 ms timeout trials are unchanged. Each trial's progress now names its classification reason and, when journalled, its model status and wall. Compatibility: the verdict schema and installed hook settings are unchanged; progress-line readers must accept the added fields (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``; ``prin:publictools:well-made-and-good-to-use``).

- Mail retry-clock tests hold logical time through an interrupted scan, then advance it to prove the retry; a loaded test node can no longer complete the retry before the pending-state assertion. Mail reminder and inventory log captures run in their own test processes, so another test cannot suppress their events through a shared tracing callsite; failures print the captured diagnostics. Tests only; installed mail behavior is unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- A launch refused at reply readback names its published launch report on the terminal, with guidance and the exact `read-launch-report` command as a JSON string before the final `wall_seconds`; the original refusal and non-zero exit remain. In the report, `next_command` keeps the released `bind-reply LOOP RUN --step STEP --delivery UTC_INSTANT` action when the saved reservation admits late binding, or the released `settle LOOP RUN --round STEP --dry-run` action when settle's saved-record checks admit it; neither action is prescribed when its checks fail. The new `recorded_cause` names the saved cause, including a later reaping fault, and `guidance` claims no letter delivery, identifies the report's own command field, and withholds the settle preview after an unsettled observer disposition (``test:unit:launch-readback-refusal-report-retains-cause-and-remedy``; ``test:unit:launch-refusal-advice-follows-recorded-admission``; ``test:unit:launch-binding-advice-withholds-unadmitted-settlement``; ``test:unit:launch-nonbinding-refusal-prescribes-settle-preview``).

- Sign-in entry fixtures now keep executable writes and child starts in one test interval, so a child forked by another test cannot retain a writer and make the inspector report an unmeasured entry. Every sign-in report assertion prints the full report on failure, including its inspection error. Tests only; installed door behavior is unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- Formatter refusals put the unchanged-file assurance and location first; serialization refusals name the writer detail before recovery advice, and both serialization and integrity-guard refusals give self-builders a concrete test location and other readers the build-record identity to report; only a deferred reference-dependent list adds the location caveat. Table and integrity-guard refusals use the same reader-facing order, keeping their structured categories and ranges (``rule:output:linter-findings-status``).

- The built-helper fixture now waits for its control socket to accept a connection, and reports a helper that exits before readiness. Its child, evidence and peer waits use distant 120-second hang guards. A socket pathname appearing during bind can no longer make a loaded test node refuse a healthy helper. Tests only; installed helper behavior is unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- Suspended lane steps count accepted resume attempts and append each observed outcome to its record. A stop recorded before acceptance leaves no attempt; a stop recorded at the check before spawn leaves `not-started:stopped:SIGNAL`. If a signal is delivered but the watcher has not recorded it at that check, a child can start; the driver records `started-stopped:SIGNAL` if it stops that child, or the child's status if it exits first. Compatibility: the `suspend_resumes` field keeps its name and bound, but can count an attempt that did not start; a line without an outcome leaves the attempt's ending unknown (``spec:output:codex-lane-report``).

- Format emphasized footnote references with their definitions instead of rejecting them. Each block is validated with the document's actual footnote definitions as context and still chooses its own spelling, so a later fallback no longer re-spells unrelated blocks; public constructs are pinned to exact bytes. Documents without footnotes format as before, and the event comparison is unchanged (``claim:fmt:construct-fixtures-have-stable-bytes``).

- The door fixture socket test now retries its exact stub call until the listener accepts it, with a distant hang guard, and reports a server failure before listen; a loaded test node no longer turns the brief bind-to-listen interval into a connection refusal. The compute-node fixture distinguishes its own `no` mode from the outer TERM by the deadline diagnostic; the 120-second probe timeout is its hang guard. Tests only; installed doors and operator procedures are unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- A permission-triage journal-lock denial now names the one unavailable caller-loop or estate journal lock, each exhausted approval-lookup or verdict-recording wait, and whether its budget came from the journal's 10 ms minimum, half the hook's remaining time, or the journal's 4000 ms maximum. It then tells the reader to retry later if needed and routes a continued refusal by reader and journal: a worker or in-session subagent reports to its loop's orchestrator; a loop orchestrator may inspect ``escalations.jsonl`` in its registered state root and reports an unreadable loop journal to the superloop. At a held estate journal it states the refusal in its own session and reports to the superloop only after the lock clears. The superloop reports a continued refusal to the owner of this hook; a host with no estate route names the current session and the owner instead of a nonexistent superloop. Lookup-only denials follow the same route. The `journal-degraded` reason is replaced on these lock paths; readers matching the whole reason must accept the new wording. Other failure reasons and decisions are unchanged. Compatibility: install the new binary; no state migration or service restart is needed (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``; ``prin:publictools:well-made-and-good-to-use``).

- The oversized model cleanup test now keeps its descendant alive for 300 seconds, far beyond its explicit 20-second cleanup deadline, so a missing cleanup cannot pass after that descendant exits by itself. Installed model deadlines are unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- Judge recognized SSH payloads' absolute paths against declared domain roots by text, independent of the caller's filesystem; keep local redirects, pipe neighbors and SSH option values local. Only the bare `ssh` client is attributed: a qualified client or launcher, an assignment before the client or an enclosing shell, an `env` option, a login or interactive shell startup, an unmodeled SSH option or a command joined before the client keeps the local judgment, while ordinary timing wrappers, plain `env` and noninteractive `bash -c` keep attribution. A missing-root scope refusal names its class without echoing the path, sends a worker to its loop and an orchestrator or in-session subagent to the owner, and replaces only the exact scope-contradiction reason within the existing infrastructure-failure grammar. Compatibility: remote absolute paths under the caller's checkout or run root but outside every declared domain root are now estate-scoped, because caller-local registration describes no remote filesystem; a loop whose remote host shares those paths declares them in its domain rubric. Relative protected names, including bare remote words such as `make hooks` and `cargo test -p registry`, also become estate-scoped. Other relative words retain the documented approximation (``rule:permissiontriage:remote-scope-paths``).

- A domain-rubric root needs a component with literal text: `/`, `//`, `///`, `/*/` and other slash-only or wildcard-only roots no longer name a domain candidate for local or remote paths, where the broad ones previously matched every path. Compatibility: a rubric relying on such a root gains no domain scope from it, and an orchestrator rubric that bounded its worker rubrics with one makes the worker-rubric check refuse the worker roots it alone covered; declare a restricting root instead (``sec:permissiontriage:reason-grammar``).

### Added

- Custody campaigns retain an immutable start binding and a separate bounded recovery sequence. Failure summaries and diagnostics name the child, stage, first cause and last recovery receipt; cleanup facts remain readable after uncertainty and distinguish observed actions from resource absence. Sealer process and thread creation is denied so helpers cannot outlive a killed keeper. Direct sealers die with a killed keeper and cannot unset their parent-death signal or change the credentials that could clear it; the documented manager activation and stop limits bound orphaned generator processes. A signal descriptor records cooperative stop requests and bounds invocation-based recovery without stopping by name alone. Direct sealer status additionally compares every gid and supplementary group with the measured keeper identity before release. Accept and duplication failures retain kernel resource context, while case tests enforce their shared resource guard and keep diagnostics inside test capture. Interrupted holder-stop recovery either completes the bound stop or records an explicit unit-unloaded observation in lifecycle schema 3; operator reconciliation skips stop and reset for an already-unloaded unit and retains a live UID witness when available. Never-submitted holders are recorded as not attempted, and between-case stops do not claim a reservation. Schema-3 calibration evidence records the measured campaign owner, rejects old envelopes, and separates observation receipts from campaign roots; calibration-run prints its published matrix digest. The hard-kill procedure locates the last case without a terminal receipt and preserves runtime manifests. Operators preserve completed evidence and reconcile retained runtime objects explicitly (``sec:credentialcustody:campaign-failure-evidence``).

- Compile checked public-source identity into the linter; retain dirty state, share the installer's clean-HEAD release rule and refuse unverified producer claims outside the two-path private overlay (``spec:output:linter-build-identity``).

- Record the Python reader's implementation and version beside linter build identity when Python was read, including syntax refusals. Mixed interpreter observations refuse before verdict publication; non-Python commands need no interpreter. Build reports retain this runtime evidence (``spec:output:linter-build-identity``).

- Identify the running linter on both version spellings and every result or refusal, including build reports and audit responses. Measure the running image independently of installation sidecars; retain version and formatting access when its digest is unavailable. Compatibility: JSON envelopes gain `identity`, and version messages describe it while `fields.version` stays unchanged (``spec:output:linter-build-identity``).

## [0.5.0] - 2026-11-16

### Added

- Install the collection journal design with the tools documentation, including the staged cuts, their acceptance and deployment boundaries, and the warning that no supported command prunes the current journal (`prob:docs:collection-journal-design-joins-the-tree`).

- Add owner-invoked own-path placement preparation and a read-only orphan census. The explicit private parent is the inventory, so an interrupted placement remains discoverable without a second catalog. Launch binds the placement and grant to one preview and publishes them together; the unselected executor checks the opened root's UUID and file handle before cwd or spawn. The census takes the runs root from the registry; no workers override is required. Compatibility: deploy P1 at every reservation consumer first, refresh and restart each loop's door copy and verify its build identity before the first placement. Install the matching lane binary on the node, verify its hash against its build record, and use its placement dry run against the real parent to probe the identity interface before apply. Placement acceptance tests require that interface on their temporary filesystem and no longer skip its absence. Published placements prohibit rollback below P1. Existing runs need no migration; no door route, seed publisher, holder or cleanup is enabled (``proto:superlooplane:workspace-placement-reader``).

- Door operators get request-keyed agent usage start and finish journal lines and persisted token counts in the existing request observations. The optional `agent_expected_tokens` setting defaults to 16,384, a policy starting figure to calibrate to about twice a day's observed median, not a measured limit; a call's excess and an hour's first excess are error-severity journal lines, the hour's return under its threshold an info line, and none alters a verdict. The installed door generation's closed shape changes, and the launcher, each run's boxed helper and the door service all read it: after the tools are installed, the launcher refuses a loop's launch, resume and repin until that loop's door is refreshed, and once it is refreshed a round whose boxed helper started under the earlier release refuses its next helper request. So install the tools, then refresh and restart each door when none of its loop's rounds is in flight and before its next launch. Refresh writes the effective expectation into the generation and replaces the embedded runner. Write the key only after the install, since an earlier `install-door` refuses it, and refresh again for it to take effect. No request rewrite is needed. The alarm remains journal-only until the self-letter route and typed publisher exist (``proto:superlooplane:door-agent-token-accounting``; ``prob:door:door-agent-token-use-is-recorded-and-an-outsized-one-is-an-error``).

- Add `superloop-credential-custody` for strict parameter records, sealed-length observations and calibration identity comparisons. Meson installs it with the other public commands and its build record, and nothing calls it yet; a rehearsal needs the operator's separate root-owned installation with its reviewed parser and parameters. Each observation requires an immutable caller-owned parameter file and private sealed directories with protected ancestry before any probe or parser runs, so rehearsal operators prepare those modes explicitly. Format discovery is its own `format-discover` command with a small tagged record and an `observed` receipt, so no completion is asserted for a campaign that has not run. Children never inherit descriptors from 3 upward, process groups are cancelled before their leader is reaped, aliased identity members refuse, and text byte counts must match the frozen encoding form. Executed programs are checked under protected ancestry and run by retained descriptor; evidence and calibration ancestry are protected, with repository and dynamic-loader custody explicitly assigned to operator witnesses. Probe identities retain only SHA-256 digests, keeping arbitrary probe output out of receipts. Observation records now use schema 3 and calibration/result envelopes schema 2, binding completed campaign outputs and measured code/configuration; old success/configuration assertions and old calibration forms refuse without compatibility readers. Operators retain original campaign evidence and prepare separately protected sealed-only analysis copies. Parser-source reads deny every Git transport even when repository configuration enables one, and interpreter execution must match the retained file used for its identity digest. Root-only calibration-run, descriptors, barrier-release and completion commands reuse the bounded launcher cores, measured artifacts and public cases, retaining exclusive immutable case state and one pair at a time. The commands refuse ordinary users and require independently installed role confinement; nothing invokes a campaign automatically. Calibration-run selects its campaign with `--campaign` and refuses the old `--case` spelling; operators follow the documented one-shot per-case sequence rather than blindly retry an effect after a lost reply. The private resident driver waits for captured-barrier inventory and release requests, polls invocation-bound completion within the same case deadline, and retains the keeper until a read-only client has observed completion. A private authenticated request core retains its connection-bound peer while the keeper processes administrative metadata; the existing status endpoint refuses these actions. Launch-policy schema 2 separates the fixed direct-sealer construction from the five unit roles and refuses the obsolete sealer-unit form. Output binding loss latches uncertainty and records its refusal class independently of output verification, so restoring a swapped output cannot reopen success. A private two-sealer core now passes pipe capabilities directly to a measured native image, observes EOF without reading plaintext, bounds diagnostics and sealed output, and cancels failed cases through the creation manifest; capture contradictions also latch uncertainty and terminal receipts retain the original cause across custody or publication failure; direct sealer children now require Landlock ABI 6 with signal and abstract-socket scoping, read only the single host-key file, and are refused new filesystem write opens, socket creation, cross-process resource limits, kernel keyrings, IPC and process-group/session changes; cancellation also targets the retained leader pidfd; manager startup is quiet and artifacts are bounded at 64 MiB; private runtime FIFOs retain keeper writers until matching fixture descriptors are captured and leave a protected creation manifest; a private pinned manager CLI adapter builds closed unit vectors and compares bounded invocation-bound property replies; a retained keeper core binds stopped process identity and a bounded administrative status socket, quarantining ambiguous failures; a private external observer checks the stopped fixture’s exact descriptor inventory and each direct sealer’s own confinement status; a private release core binds its immutable inventory receipt and persists single-use intent before pidfd continuation; one null-device standard-stream template binds manager submission and inventory; the private observer protocol transfers only an observation-only retained pidfd after checking the peer lacks signalling capability in every set; the peer is pinned by the connection’s kernel pidfd without a numeric fallback; a native namespace peer witnesses successful handoff without signalling authority; a private completion core retains invocation-bound generator results before holder cleanup and requires both sealer EOF/exit results and synced immutable outputs before its exclusive completion receipt; a private read-only completion transaction binds retained generator and sealer results to a fresh nonce and a live kernel-pinned keeper connection; its private path-opening adapter requires an immutable measured control manifest and protected socket, rechecks retained objects and measures peer birth without observation capability; valid terminal evidence survives expiry before holder cleanup, and manager construction is confined to the keeper; completion requests generate their own kernel-random nonce and compare the connection-pinned keeper’s measured process start time; a private sequential campaign core publishes a bounded matrix only from revalidated completed case evidence and stops on the first failure; the schema-2 matrix additionally retains measured sealed-output digests and configuration bindings, with a protected private handoff reader; observation-record integration remains separate. Open and spawn refusals retain numeric errno and descriptor/resource context without leaking paths or foreign diagnostics (``guide:credentialcustody:observations``; ``sec:credentialcustody:launcher-cores``; ``sec:credentialcustody:sealer-core``).

- Add the rehearsal-only `credential-fixture` build artifact with two named synthetic streams, a cooperative start barrier and explicit negative cases. Ordinary installation omits it; a rehearsal operator stages its reviewed binary and build record separately. Its strict public-only case may be root-owned 0444 for a manager-allocated non-root identity; private observation inputs retain their existing custody (``sec:credentialcustody:fixture``).

- Read and retain optional own-path placement facts in protected plans, binding the owner-held grant to a filesystem UUID and directory file handle. Reservation byte readers reject duplicate placement-path keys before accepting decoded values; unrelated duplicate keys and records without placement keep their existing behavior. No writer, execution route, cleanup operation or node payload is selected. Compatibility: deploy these readers at every reservation consumer before a later writer adds placement; that writer raises the rollback floor. Existing runs need no migration or service step (``proto:superlooplane:workspace-placement-reader``).

- Prepare an unselected node-executor library for exact commands in a reservation-declared workspace, with a retained cwd, explicit environment, one sequence deadline and node-measured outcomes. It provisions nothing and writes no request record; no installed command or door route selects it, so deployment needs no rewrite or restart. Later callers still require the workspace readers before publishing effects (``proto:superlooplane:workspace-node-executor``; ``prob:door:w2b-node-executor-runs-in-the-declared-workspace``).

- Add dedicated private door receivers that retain the entry and identity program and enter the registered loop with a minimal environment. No door caller or installed generation selects them yet: ordinary entry, running doors and direct triage keep their existing behavior. This preparation needs no hold, per-loop refresh or restart. A manually invoked private word requires its seven-role rights frame and refuses a missing socket or mismatched image before entering the loop (``claim:loophome:door-receiver-retains-entry-and-isolates-consumer``).

- The lane tools now read the workspace stage's records before any program writes them: an optional workspace grant in a protected run plan, retained through the pinned read, round resume, door re-pinning and interrupted recovery; schema-seven compute-workspace request records, including a sequence whose overall deadline expired between steps; and schema-six preflight refusals named `door-workspace-unregistered`, `door-workspace-context-differs` or `door-workspace-protocol-refusal`, or the shared `door-caller-authority-refusal` and `door-review-compute-refusal`, which carry at most the first 65,536 raw bytes of the refused frame, marked truncated when the frame was longer. A build carrying an earlier form of these readers refuses such a truncated prefix and this one refuses that form's longer evidence; nothing writes either yet, so no record needs a rewrite, and a later writer of these refusals needs this release deployed first. Legacy `door-request-refusal` and `door-changed-ref-refusal` records still admit their original bounded raw arguments even when those arguments resemble the new tagged form; existing run listings remain readable. Only an explicit launch declaration, below, writes the grant; nothing writes the request forms yet and the door selects no workspace operation, so existing runs, reservations, request records, door modes and node payloads behave as before. The request reader's refusal of an unsupported schema now reads `schema must equal 6 or 7`, and the learned-index status and rebuild messages name schema seven beside six; `requests rewrite` and `requests rebuild-index` leave schema-seven records unconverted. Deploy with no rewrite and no service step; once a later release writes a workspace declaration or record, the loop cannot roll back below this release (``proto:superlooplane:workspace-readers``; ``proto:executecommand:compute-workspace``; ``prob:door:w1-workspace-contracts-and-readers-land-first``).

- Launch accepts `--compute-workspace JSON` for a new run: the dry run shows the declared grant and its digest, and the apply, repeating the declaration with `--expect-digest`, records the grant once in the run's protected reservation and plan before the home is built. The grant is immutable: preparation retries, later rounds, door re-pinning and recovery keep it, and a different grant needs a new run. Its baseline environment is shown to workers, previews, records and the judge, so the declaration must acknowledge it as public, and duplicate names and recognizable credential names or values refuse without echoing them; that recognition is limited and is no secret detector. Duplicate resource names in the grant refuse rather than keeping the last value. The run's mail birth is reserved before its preparing reservation is published, as for an undeclared launch, so an interrupted preparation never names an unreserved birth. A declaration also requires the loop's `workers.toml` to publish `workspace_policy = { quick_policy_digest = "HEX", blacklist_digest = "HEX" }` matching the grant. Without the argument and the table nothing changes: undeclared launches write the same reservation and plan bytes, and no workspace execution route opens; the one change they see is which refusal comes first, since a fresh launch reads an existing reservation before probing the entry program, box and proxy, so a malformed one reports its `uid-table` read refusal first. The workspace readers above are the floor for any declared run. Before any loop's `workers.toml` carries `workspace_policy`, install this release's `superloop`, `worker-run` and `superloop-lane`, refresh each loop's door copy with `install-door` and restart its door service, and let every run whose boxed helper started under an earlier release end: each of these validates the settings, and an earlier one refuses the table as `unknown-setting`. To roll back below this release, first remove `workspace_policy` from every loop's `workers.toml`; keep the reservations of declared runs, which the readers still resume (``proto:superlooplane:workspace-launch-declaration``).

- Inbound mail binding and verification can retain received custody through a selected library session, with distinct operations, unchanged pin records and read-only verification. The selected library session retains the existing pin record format (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

### Changed

- Pin formatter refusal locations across one or more overlay slots, including LF and CRLF padding and multibyte prefixes, through check and write mode. The line and byte position refer to the unchanged complete input (``test:integration:refusal-locations-cross-overlay-slots``).

- Formatter writer refusals now use `serialization_failure` instead of `source_parse_failure`, identify the block's starting line and byte position, and suggest simplifying it or reporting it with the formatter version. Ambiguous table rows name a line and give their original byte range. Callers must recognize the new kind; exit statuses and refusal to overwrite rejected files are unchanged (``rule:output:linter-findings-status``).

- The exec wrapper uses textwrap 0.16.4 with the ICU line breaker. Non-ASCII text may wrap at different positions in calligraphic output; plain output is unchanged (`sec:publictools:build`).

- The Markdown formatter uses the adopted upstream writer 23.0.1, retaining reference labels, authored code spans and blank-line padding. The writer now receives the parser flags and uses Unicode reference-label comparisons. Compatibility: after the rebuilt linter is deployed, `superloop-lint fmt --check` flags tables whose separators previously omitted code spans from header widths; run the rebuilt `fmt` over repositories held to this linter to size separators to the whole header cell. Escaped entities formerly refused by the integrity guard now format successfully; the unchanged guard still refuses changed document events (`sec:publictools:build`).

- Chat export uses MiniJinja 3 with explicit Serde contexts, retaining HTML escaping and its single safe Markdown value. The embedded-template feature set stays limited to macros, cross-template operations and Serde (`sec:publictools:build`).

- Build Unix process and namespace operations against nix 0.32. The workspace uses none of the changed socket-accept or splice interfaces; no command form or operator action changes (`sec:publictools:build`).

- The helper-parent lock regression observes the exact mailbox lock's waiter in `/proc/locks` before releasing its holder, deriving its device and inode token from the kernel holder line rather than `stat`, including on btrfs. No installed behavior changes (``test:unit:live-round-parent-publication-takes-mailbox-lock``; ``test:unit:mailbox-waiter-uses-kernel-holder-device``).

- The public helper-stop recovery rehearsal checks the retained-letter refusal and the complete resumed recovery on one raced record per reply variant, preserving every assertion while removing duplicate setups. Its hidden library stop bound is injected after the real helper is paused at the unlink event; installed launches keep 90 seconds (``test:integration:public-helper-stop-recovers-resumed-reply``; ``test:integration:public-helper-stop-recovers-resumed-no-reply``).

- Keep ordinary mail preparation off the retained delivery history with a writer-owned lookup rebuilt at restart and updated after durable transitions. Delivery checks and record formats stay unchanged; the service still reads history for retention and exceptional recovery, and still counts staging across mailboxes. Install the binary and restart the mail service; loops need no mailbox rewrite or resubmission (``proto:loophome:mail-preparation-index``).

- An allow-mode door releases its admission slot after the durable effect and sent final reply, before joining its advisory agent. Later calls from that worker can overlap agent work and see judgement history before the earlier verdict is recorded; learning and correction authority do not change. The waiting publication gets a fresh, uncredited lock-admission allowance of at least 300 seconds or the original request deadline plus maximum credit if later, with failures visible in the journal and status and retained for recovery. Hold new requests and require `unpublished_effects` to be empty before refreshing and restarting each door; no record migration is needed (``rule:superlooplane:door-request-admission``).

- The public resumed-launch fixture waits for reservation publication events instead of polling against a ten-second deadline; its 180-second hang bound does not select a launch outcome (`public_resumed_launch_uses_real_work_scope`).

- Pin the public rollback retention boundaries with a live work process, an in-place changed request and a durable dispatch intent. These test-only controls distinguish unsafe restoration and deletion from the supported live retry; they add no recovery command (`public_resumed_rollback_retains_dispatch_intent`).

- Exercise five real public resumed-launch refusals with exact rollback and an identical retry: inspector, helper pin, stale socket, credential thread start and readiness. The fixture checks both reply and failed histories, preserves the explicit thread choice, and confirms scope teardown; vendor execution remains synthetic. Tests only (`public_resumed_inspector_refusal_restores_and_retries`).

- Exercise a complete resumed host launch in a real work scope with a declared driver/vendor stand-in, actual helper peer checks and settlement, and confirmed scope teardown on both success and refusal. Tests only; the five rollback refusals are not claimed by this foundation (`public_resumed_launch_uses_real_work_scope`).

- Exercise a positive resumed-launch preview with canonical mail provisioning and the real built helper preflight, preserving the reservation and run files. This changes tests only; the five live rollback refusals remain a separate acceptance (`public_resumed_preview_uses_canonical_custody`).

- Pin live rollback and failed-round choice preservation over a production-published workspace grant and placement, including the exact settled reservation bytes; the public inspector-refusal case also restores and retries a placed `alpha/R` (``test:unit:live-round-rollback-restores-placed-reservation``; ``test:unit:failed-round-choice-survives-live-rollback``).

- After a failed boxed round, `launch LOOP RUN --round STEP` now refuses until the launching loop chooses `--fresh-thread` or `--resume-thread`. Settlement keeps the observed or requested thread, or explicitly records its absence; with no recorded thread only an explicit fresh choice is available. The dry run shows the choice and whether session files exist, without promising vendor acceptance. Reply-settled rounds and host-lane choices are unchanged (``test:unit:failed-round-choice-is-explicit``; ``test:unit:failed-round-settlement-keeps-thread-provenance``).

  Compatibility: before making a new settlement, replace every launch and settlement program copy used for these runs, and let no settlement begun by an old program complete across the handover. Older launchers do not enforce the choice; additive record members do not establish a reader floor. This conclusion comes from reading the old release's source, not from running its binary.

- Door request operations reuse their first collection read for door projections until that request-lock hold ends, replacing the view after their own confirmed collection commits. Helper preview and commit still read live state and retain their conflict checks, so independent permission writes and appended journal lines are preserved. This removes repeated whole-journal reads from a hold without changing record formats, the helper protocol or lock rules. Installed commands gain it immediately; refresh and restart each door after its in-flight requests finish to update its own copy (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Policy publication now evaluates all classes from one inventory, and the lane and permission helper use identifier lookups for collection reconciliation instead of repeated scans. Modes, refusals, disposition order, record schemas and the helper protocol are unchanged. Audit-only publications still need no inventory. Install the lane and permission helper together, then refresh and restart each door after its in-flight requests finish; existing door copies retain the old cost until refreshed (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Door request transactions skip their final policy publication only after the learned-index write and its first publication, including the directory sync, have succeeded. A failed write or publication still gets the existing final recovery attempt. Successful transactions have one fewer policy attempt in the request-lock release line and shorter holds, especially with large collections; record formats and lock rules are unchanged. Installed commands gain this immediately; an existing door gains it after refreshing its own copy and restarting its service (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Door request writers now wait in arrival order within one process, including unnamed mode writes and concurrent phases of the same request. A retry keeps its place; expiration, refusal and unwinding remove it. Newer writers in that process cannot repeatedly overtake an older waiter. Readers and other processes still contend through the operating system lock; transaction work, acquisition deadlines, wait credit and admission remain unchanged. Commands use the new ordering from installation; a door needs its own refresh and restart after in-flight requests finish. Unnamed exclusive waits, such as a request's first mode check, now also appear in the existing `door-request-lock` wait lines with a null request identifier. No configuration or record migration is needed (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Door request projection computes each record’s lookup key once instead of hashing it again for every candidate. The first matching row and the complete projected record stay unchanged; no lock, helper call or publication moves. This reduces record-transaction work and shortens holds as collections grow. Existing doors gain the improvement after their own refresh and restart; finish in-flight requests first. No record migration or operator configuration change is needed (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Door request writers now report one bounded `door-request-lock` release line with the operation, request identifier when known, acquisition wait, hold time and named transaction phases. This diagnoses queue stalls; lock scope, ordering and deadlines are unchanged. Commands that take the exclusive lock in their own process, such as the owner's changing `requests` commands and retirement, print the line on their own stderr as soon as the new binary is installed; existing door copies show the lines only after their per-loop refresh and restart; let in-flight requests finish first. Request contents and filesystem paths are not included (``prob:door:door-parts-contend-for-the-request-lock-within-one-request``).

- Prepare the library contract for three door entry operations, with fixed capability roles and a sealed, bounded invocation. No production caller or installed command changes; no new operator preparation is required (``claim:loophome:door-frame-fixes-local-entry-custody``).

- Mail binding’s release sentinel now follows the test-only admission hook itself, and acceptance pins override refusal before plan reads and refusal of a changed prior binding. Production command behavior and record formats are unchanged (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- `bind-mail` and both `launch … --round` modes now retain received configuration, storage, identity-program, journal and run custody through binding or read-only verification. Install with neither command in flight, then rerun an identical binding and a settled run’s dry resume. The reply entry’s owner, mode, ACL and link requirements now apply to these commands too; provisioner-written homes and recorded bindings need no migration. Unset `ENTER_LOOP_REGISTRY`, even an empty or canonical value: `bind-mail` newly refuses it before plan reads, while resume refuses after its existing plan and reservation reads. A process crossing the install refuses `anchor-missing` with its selected operation or `verified-prefix` before publication or preparation; rerun it afterwards. Running containers are unchanged until their next resume (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:inbound-binding-retains-custody``).

### Fixed

- Make door compute deadline and disconnect tests decide by readiness and controlled phase clocks; require typed fixture endpoints and reconcile answer output counts. Compatibility: test fixtures only; installed door behavior is unchanged (``sec:superlooplane:door-test-fixtures``).

- Claude-home lock coverage now exercises the deployed five-second limit directly, so changing it cannot pass by supplying a separate test budget. Installed lock behavior is unchanged (``test:unit:claude-directory-lock-refuses-with-path-within-bound``).

- Permission-triage model and journal tests now start short timeout claims after fixture readiness, use held events for ordering, and give ordinary fixture runs distant hang guards. Their interrupted fixtures outlive the model run's hang guard, so a missing kill or group kill fails the test instead of passing after the fixture exits. A loaded test machine no longer changes their verdicts. Installed time limits and behavior are unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- Selected fake topology rosters now have a 120-second per-trial hang bound, over sixty times the largest trial wall measured under node load; their outcome assertions and full-roster deadlines are unchanged. Release builds still refuse test rosters (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- A launch that refuses at reply readback now leaves a readable launch report with its cause and next command while still exiting non-zero. A later digest-bound settlement archives that refused report before publishing the recovered report; no reply binds automatically (``test:unit:launch-readback-refusal-report-retains-cause-and-remedy``).

- A repeated late `bind-reply` no longer suggests failed-round settlement when the last round is already settled, even if the run remains failed; the ordinary phase refusal applies (``claim:superlooplane:late-reply-recovery-keeps-delivered-replies``).

- Correspondence transport failures now print `failure=exit status=N`, `failure=timeout call_limit_ms=N`, or `failure=signal signal=SIGNAME` beside `SSH-FAILED`. An optional `stderr_truncated=true` marks a cut; the last field is `stderr_last_line`, either `(none)` or a quoted, bounded diagnostic with the current cursor redacted and equals signs escaped. Compatibility: the deployed client printed only `host=NAME SSH-FAILED`; install the new client and let exact-line readers accept these appended fields and parse the last field as quoted data. Cursor files, exit codes and feed verdict lines are unchanged (``prob:watchers:correspondence-client-names-a-failed-transports-status-and-error``; ``prin:publictools:well-made-and-good-to-use``).

- Door test fixtures expose an owned client whose answer read consumes validated progress frames; raw wire reads require an explicit opt-in. The sized-run test waits for each resumed reader to finish after proving the writer can acquire without waiting. Tests only; installed doors and operator procedures are unchanged (``sec:superlooplane:door-test-fixtures``).

- Door test replies use a shared final-status reader across service, compute, concurrency and startup fixtures; intermediate protocol events are requested explicitly. Lock-wait progress cannot be mistaken for an answer. Tests only; no installed behavior or deployment procedure changes (`prob:gates:elapsed-time-assertions-are-censused-and-rewritten`).

- Correspondence subprocess checks now give executable readiness a distant hang guard and use publication itself to prove cursor-lock ownership. Unexpected child results name their exit status and stderr with a bounded stdout tail, and the slow SSH fixture stays beyond its five-second cutoff (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``; ``rule:conformance:ordering-and-timing-evidence``).

- The build-child limit regression observes the direct child’s unreaped successful exit before starting its drain budget and requires completion with an indefinitely held pipe. Scheduler delay no longer decides whether its evidence is a child wall end (``test:unit:build-children-have-stream-and-time-limits``).

- Request-wait regressions use the store’s existing logical clock: an immediate result credits no pause and timeout credits exactly the requested second. Installed wait deadlines and pauses are unchanged (``test:unit:requests-wait-immediate-run-and-usage``; ``test:unit:requests-wait-timeout-has-no-rows-and-a-refusal``).

- Claude-home lock coverage checks the five-second budget in exact logical 25 ms steps; public command cases keep the full-budget lower bound and a distant hang guard, without a scheduler upper-bound verdict. Installed lock limits are unchanged (``test:unit:claude-directory-lock-refuses-with-path-within-bound``; ``test:integration:claude-preparation-preview-and-apply-refuse-locked-loop``; ``test:integration:claude-move-preview-refuses-locked-loop``).

- The Markdown writer validates retained code-span spelling inside table cells consistently with its renderer, so a literal or escaped pipe beside emphasis or bold does not trigger a false serialization refusal. Exact source/event matching and validation of the surrounding block remain required. Serialization refusals name the starting line of the buffered block, including after overlay slots (`prin:publictools:well-made-and-good-to-use`).

- Door transport tests decide disconnect, receive expiry, child exit and input release from their events, with distant hang guards instead of short fixture windows. Installed programs and door deployment are unchanged (`prob:gates:elapsed-time-assertions-are-censused-and-rewritten`).

- The unreaped-feeder regression checks the process-state branch directly, so a corpse and a deadline cannot pass as the same negative reading and scheduler delay cannot decide the verdict (``test:integration:an-unreaped-corpse-is-not-a-feeder-still-reaching-its-exec``).

- Registry capture coverage now gates pipe output and child exit separately, retaining the late stderr and unsuccessful-exit checks without scheduling sleeps or lower elapsed-time verdicts (``test:crate:registry-capture-waits-for-child-and-both-streams-under-load``).

- The retained credential-authority regression now observes its completed publication pass and joins through a completion event, preserving replacement-home and evidence checks without short elapsed-time verdicts. The deployed authority cadence is unchanged (``test:unit:service-credential-authority-retains-custody``).

- A repeated late `bind-reply` names the settlement recovery only for the active failed round. Repeating an earlier round’s binding after a later failure keeps the ordinary phase refusal, instead of suggesting a recovery that cannot admit that step (``claim:superlooplane:late-reply-recovery-keeps-delivered-replies``).

- Door transport tests distinguish pre-spawn refusal from running-child expiry by a test-only spawn hook, without a node-speed verdict; deployed deadlines are unchanged (`[ORCHESTRATION-rule:conformance:ordering-and-timing-evidence]`).

- Door transport deadline fixtures consume lock-wait progress before checking the final reply, using the shared bounded frame reader; deployed behavior is unchanged (`[ORCHESTRATION-rule:conformance:ordering-and-timing-evidence]`).

- Build-child regressions now check named timeout evidence without an elapsed-time verdict; retained-pipe coverage waits for completion while its holder remains alive. Production limits are unchanged (``test:unit:build-children-have-stream-and-time-limits``; ``test:unit:build-runner-bounds-retained-pipe-after-stop``).

- Request-reader regressions now order writer publication through contention events and check deadline credit with the existing fixture clock, so scheduler delay cannot decide their verdicts. Installed lock limits are unchanged (``test:unit:request-reader-outlasts-slow-writer-sync``; ``test:unit:request-reader-refuses-after-lock-bound``).

- The helper dead-driver regression now observes its unknown-identity measurement before releasing the driver-end case, and requires reaping and removal evidence without a ten-second elapsed verdict or finite child lifetime. Production behavior is unchanged (``test:unit:helper-reaps-dead-driver-through-built-process``).

- Silent-helper cancellation tests now distinguish the control request from client disappearance and require completion plus stop/wait evidence from a child with no natural end, instead of a five-second elapsed-time verdict. Installed behavior is unchanged (``proto:superlooplane:container-attempt-completion``).

- Helper wall-stop coverage now waits for completion and checks the named wall cause against a child with no natural end; node scheduling no longer decides an elapsed-time verdict. Production deadlines are unchanged (``test:unit:helper-wall-stop-retains-cause-in-outcome-and-round``).

- Door sized-run waiters remain parked after their reads while the writer publishes, replacing a fifteen-second performance verdict with lock ordering. Refusal-frame comparisons use the peer’s encode/decode form; retained-reader fixtures assert the injected zero drain and observe early runner completion. Installed behavior is unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- Helper retained-reader tests now inject drain expiry and wait for holder, runtime-stop and cleanup events, with distant hang guards instead of short scheduling windows. Deployed helper deadlines and cleanup behavior are unchanged (``proto:superlooplane:container-attempt-completion``).

- An over-budget round with a letter-delivered reply can recover through `bind-reply` after the missing-binding readback refusal, then digest-bound `settle`; the public regression reproduces the unbound preview refusal and the successful reply settlement (``claim:superlooplane:late-reply-recovery-keeps-delivered-replies``).

- Repeating `bind-reply` after a late binding now names the existing binding and gives the `settle --dry-run` recovery route instead of claiming that only a started or settled run may bind (``claim:superlooplane:late-reply-recovery-keeps-delivered-replies``).

- A reply left unbound when launch refuses at readback can now be recovered: run `bind-reply`, then preview and apply `settle` with its digest. Only the selected last failed round with the exact missing-binding refusal and no reply or reply binding is admitted; other failed runs still refuse. Deploy is a notice: running launchers keep their code, and the new binding command can recover an existing matching refusal without a record migration (``claim:superlooplane:late-reply-recovery-keeps-delivered-replies``).

- Resuming a failed boxed round now checks session files against that run’s allocated worker, rather than the allocation block’s base. A run refused for this mismatch can repeat its preview after installing the new lane command; foreign-owned session files still refuse (``claim:superlooplane:round-inspection-uses-the-allocated-worker``).

- Door class, full-store and mode-exercise fixtures consume lock-wait progress before reading their final reply. This removes first-frame assumptions from these tests without changing installed doors (``prob:gates:load-sensitive-tests-made-deterministic``).

- Meson lint, release, Cargo and slow-suite limits now leave headroom for loaded runs and end hangs rather than refusing healthy checks. Installed commands are unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``; ``prob:build:release-linter-check-timeout-from-measured-wall``).

- The steward overlap harness now waits for its fixture's entered event under a distant guard; delayed scheduling no longer reports a missing lock holder. Installed steward behavior is unchanged (``prob:gates:elapsed-time-assertions-are-censused-and-rewritten``).

- Three permission-triage topology assertions now share the same implemented-roster fixture result, avoiding two duplicate 345-trial probes while retaining each status, stderr and verdict check. Installed topology behavior is unchanged (``test:integration:disabled-table-rows-are-candidates-and-do-not-block``; ``test:integration:fix-implemented-roster-reaches-ready``).

- The topology ceiling fixture now gives its version preflight a distant test-only hang guard while keeping the 20 ms trial ceiling, so a delayed process start cannot turn censored-trial evidence into an infrastructure exit. Deployed topology ceilings and verdicts are unchanged (``test:integration:bite-two-generated-counts-and-censored-latency-survive-failure``).

- The correspondence harness now checks admin-only feed delivery and an empty watch's deadline separately, so a 250 ms watch window cannot turn node scheduling delay into a failed combined case. The deployed poll and watch behavior is unchanged (``test:integration:release-harness-keeps-all-correspondence-pins``).

- The correspondence watch harness now checks immediate expiry and an empty-then-content repoll as separate events; content delivery has a distant hang bound. These checks no longer require two transport calls within 500 ms, and deployed watch behavior is unchanged (``test:integration:release-harness-keeps-all-correspondence-pins``).

- Correspondence feed tests now decide empty, admin, partial-failure and watch-expiry verdicts on a stepped clock; the binary harness retains content, cursor, refusal and SSH timeout checks without short polling verdicts. The installed client still uses the system clock and the same SSH transport, and its poll and watch output, exit codes and deadlines are unchanged; the clock and reader its feed core now takes are internal and add no setting, environment variable or argument. Compatibility: operators need no configuration or state change when installing this build (``test:unit:stepped-watch-expires-after-empty-rounds-and-cuts-final-round``; ``test:unit:stepped-poll-distinguishes-empty-admin-content-and-floor``; ``test:unit:stepped-poll-keeps-partial-total-and-over-budget-failures``; ``test:unit:stepped-failed-transport-does-not-advance-cursor``).

- A run whose driver failed after its bound reply was read back can now be settled. Both launch paths leave it `failed` with its round `failed`, the reply retained and no settlement refusal, a state every command but `retire` refused; `settle LOOP RUN --round STEP --dry-run` and then its `--expect-digest` apply now re-read the reply against its delivery, end the round `settled` with that reply and the run `settled`, keep `driver_end` unsuccessful as the record of the failure, and publish the recovered launch report, after which the next round resumes the recorded thread with no choice owed. A failed round that `settle` still refuses now names each recorded term of that state: its driver and helper end states and successes, its readback end and reply, any pre-driver failure and any recovery record's state. Compatibility: no record shape changes and runs already in this state need no migration; install the lane program before settling them (``test:unit:driver-failed-after-readback-settles-with-its-reply``; ``proto:superlooplane:failed-round-settlement``).

- The permission-triage two-stealer test now gives each of its five channel events a distant 120-second hang guard, so a delayed test thread cannot look like a failed lock ordering. The deployed lock wait is unchanged (``test:crate:journal-two-stealers-restore-during-release``).

- The permission-triage no-stdin fixture now uses a 120-second hang guard for its five usage and version invocations, so load cannot make a healthy hook outlive a two-second sentinel. The tests still fail if the hook waits for input; deployed hook behavior is unchanged.

- The permission-triage failed-kill fixture now starts its short model deadline after its descendant records readiness, and checks that descendant is still alive when the failed kill returns. A loaded shell start no longer makes a missing PID look like a failed cleanup; the deployed model deadline is unchanged (``test:crate:failed-group-kill-bounds-helper-joins``).

- The permission-triage zombie-lock fixture now waits for its shell's exit without reaping it, so node load cannot turn a 10-second fixture poll into a failed lock-recovery test. Deployed lock recovery is unchanged (``test:integration:a-zombie-lock-holder-is-dead-for-stale-recovery``).

- The permission-triage lock-recovery test checks that its unreaped holder is actually a zombie before testing recovery, so a different process state cannot satisfy the fixture (``test:integration:a-zombie-lock-holder-is-dead-for-stale-recovery``).

- Permission-triage's no-input fixture now ends its deadline process and its sleeping descendant as a group, leaving no orphan after the test succeeds (``test:integration:real-binary-exit-status-usage-and-argument-contract``; ``test:integration:version-does-not-read-stdin-and-prints-version-and-digest``).

- The same no-input fixture now sleeps briefly between PID and reap event checks, avoiding a busy core while retaining the 120-second hang guards (``test:integration:real-binary-exit-status-usage-and-argument-contract``).

- The failed-kill test now holds its descendant on a pipe until the runner returns, so the helper-join claim follows an event instead of a 30-second fixture lifetime (``test:crate:failed-group-kill-bounds-helper-joins``).

- Ordinary permission-triage tests now pin the unchanged 120-second topology default directly and prove timeout, group kill, and reap with a shorter override; the full 120-second run remains available on demand (``test:unit:unconfigured-ceiling-is-the-pinned-production-maximum``; ``test:integration:short-ceiling-times-out-and-reaps-version-process``; ``test:integration:actual-production-ceiling-times-out-and-reaps-version-process``).

- The topology ceiling matrix now checks recorded walls on its existing 20 ms trials, with one separate real half-second process wait; ordinary gates no longer repeat that wait across 171 trials (``test:integration:topology-ceiling-trials-account-for-short-real-wait``; ``test:unit:one-half-second-process-wait-reaches-its-ceiling``).

- The pack cut replay now judges the hung linter's 120-second refusal and retained diagnostics without an upper wall verdict; the deployed route timeout is named and pinned, and the real route test still spends that timeout (``test:unit:route-citation-timeout-is-pinned``; ``test:integration:cut-route-refuses-a-hung-linter``).

- Ordinary pack tests now prove a hung citation linter's refusal, both kept streams and group reap with a short in-process bound; the unchanged 120-second binary replay is available on demand (``test:unit:resolved-sites-timeout-retains-diagnostics-and-reaps-group``; ``test:integration:cut-route-refuses-a-hung-linter``).

- A first-dispatch helper-stop refusal now preserves the observer’s actual stop result. Recovery no longer accepts an observer merely because it is absent; a premature observer exit still refuses settlement. Compatibility: running launchers keep their old accounting (``test:unit:dispatch-observer-end-precedes-helper-stop-refusal``).

- The boxed helper now removes its control pathname before draining queued stop connections and closing the listener, answering requests that already reached it. Errors from peers drained after cancellation are logged without failing an otherwise clean stop; the honoured controller request and listener errors still propagate. The launcher still requires the helper's successful exit. Compatibility: deploy the host wait fix with this close fix; installation does not replace an in-flight helper (``test:unit:helper-close-answers-every-queued-control``).

- A launcher now waits for its exact helper child after a failed stop handshake and proceeds to settlement only after a successful exit. Non-zero exits and the existing 90-second timeout retain both the handshake and exit errors; a successful exit keeps the handshake error in its recorded helper-end detail. Compatibility: new launchers tolerate the close race in an older helper; a launcher already running retains its old stop behavior (``test:unit:helper-stop-waits-for-exit-after-handshake-failure``).

- A resumed round left awaiting settlement after a helper-stop error can now be recovered with its original `launch --round STEP --dry-run`, then the preview's digest. Admission requires a completed successful driver end, no helper end recorded unsuccessful, and the existing process-absence and evidence checks. A recovered reply settles normally; without a reply, complete `settle` and explicitly choose the next thread. Compatibility: install the matching launcher and private settlement entry before recovery; a running launcher keeps its old code (``test:integration:public-helper-stop-recovers-resumed-reply``; ``test:integration:public-helper-stop-recovers-resumed-no-reply``).

- A default door test now checks that two pending agent judgements release the request writer lock, using entry and release events instead of the on-demand six-second credit fixture. Deployed lock and agent behavior is unchanged (``test:unit:door-pending-judgements-release-request-writer-lock``).

- The driver-follow bounded-wait test now runs through its child-owning 120-second hang guard, so a hung command is stopped and reaped rather than leaving an unreachable elapsed-time check after `.output()`. Its one-second minimum and document assertions remain (``test:integration:bounded-wait-emits-state-only-and-keeps-offset``).

- The request reader's renewed-budget test releases its competing writer on the observed contention hook and checks that the hook fired; a 300 ms fixture delay no longer spends the reader's one-second real budget. Deployed reader budgets are unchanged (``test:unit:request-reader-renews-budget-per-read``).

- The store lock-retry credit and deadline tests now use a test-only clock, including progress frames at each 50 ms threshold. The six-second service integration proof remains available by its documented on-demand command and no longer runs in ordinary or Meson slow gates; deployed lock and agent budgets are unchanged (``test:unit:request-lock-clock-credits-exact-contention-and-expires``; ``test:unit:door-wait-credit-announces-fifty-ms-steps-and-caps-deadline``).

- The receive deadline tests now check the input pump's deadline with a held-open partial packet and start the recording fixture's deadline after its request is filed, so durable mediation work cannot decide the test. The deployed receive deadline and packet handling are unchanged (``test:unit:door-input-pump-deadline-before-packet-keeps-ref-not-reached``; ``test:unit:door-receive-deadline-before-packet-records-not-reached``).

- The driver-follow bounded-wait test keeps its one-second minimum and uses a distant hang guard instead of treating three seconds of loaded-node wall time as a failure. The command's wait setting is unchanged (``test:integration:bounded-wait-emits-state-only-and-keeps-offset``).

- The compute refusal fixture now waits for its filed request event before adjudicating it; compute announcement and admission tests use distant frame and effect hang guards. The two-box admission fixture checks release and distinct records without a short wall limit. Deployed admission and request deadlines are unchanged (``test:unit:door-compute-deadline-refusal-names-the-owner-bound``; ``test:unit:door-two-boxes-share-the-bounded-store-wait``).

- The request-store contention tests now decide by the named lock refusal and holder evidence instead of 500 ms and one-second upper wall bounds. The request deadlines and lock handling in deployed commands are unchanged (``test:unit:request-writer-deadline-names-lock-wait-and-holder``; ``test:unit:request-reader-renews-budget-per-read``).

- The helper's absent-launcher test now waits for the observed zombie state, with a distant hang guard, before checking that the unreaped launcher is treated as absent. Deployed process classification is unchanged (``test:unit:helper-detects-the-launchers-absent-process``).

- The trickling-peer deadline test now keeps its writer socket open until the frame read returns, so a loaded reader observes the deadline rather than an early end-of-file. The door's frame deadline is unchanged (``test:unit:door-frame-deadline-bounds-a-trickling-peer``).

- Busy-admission exercise tests now carry a controlled admission clock into the fixture service thread and prove one refused attempt from events. They no longer spend thirty real seconds per case; deployed admission and exercise retry budgets are unchanged (``test:unit:door-exercise-retries-concurrent-admission``; ``test:unit:door-exercises-busy-admission-is-unmeasured``; ``test:unit:door-enforce-retains-floor-claim-before-busy-admission``).

- Test-build fixture executables now retry transient text-file-busy spawn errors under a distant hang bound; the held-writer test drives expiry with an already exhausted budget and proves release by the retry event. Deployed spawning is unchanged (``test:unit:fixture-spawn-retries-only-text-file-busy``; ``test:unit:fixture-exec-fork-during-write-is-bounded``).

- Door agent exercise tests now run their semantic and timeout probes through the existing controlled judge, so a loaded node cannot make a real-clock 2,600 ms probe appear to fail. The deployed exercise still measures real time and keeps its production budgets (``test:unit:door-agent-case-uses-production-handler-and-names-unmeasured-vendor``; ``test:unit:door-agent-audit-loop-measures-all-modes-without-prior-labels``).

- The door exercise admission fixture now waits for its first observed refusal before releasing the held admission, and only that test widens its retry to a distant hang bound. A loaded node can no longer exhaust a two-second test retry before that release; the deployed exercise and the tests that hold admission throughout keep the two-second retry (``test:unit:door-exercise-retries-concurrent-admission``).

- Agent fixture tests now use one distant hang bound for runner cap and semantic judge budgets, including recorded-runner and temporary-home checks, so node load cannot turn their verdicts into fixture timeouts. The immediately refused 10 ms request is decided before execution; the shortened reaping claim uses a controlled clock. Running doors keep their production budget (``test:unit:runner-isolates-loop-sign-in-and-rubric``; ``test:unit:agent-input-limit-and-refresh-link-replacement``; ``test:unit:real-agent-absent-sign-in-is-unmeasured-from-runner``).

- Read the door file-refusal test through lock-wait progress to its final reply, preventing a progress frame from failing the refusal assertion. This changes tests only and requires no operator action (``prob:gates:door-file-refusals-test-reads-the-final-frame``).

- A successful door request no longer takes an exclusive recovery hold for another request whose advisory handler is still live. Idle and malformed unpublished effects still trigger recovery; the shared-read preflight remains. Refresh and restart each door under the documented hold to enable this. Peer-reply tests compare both values after the same JSON round trip, without changing the protocol or dependency features (``claim:superlooplane:unpublished-effects-recover-without-reexecuting``).

- Door recovery preserves decided enforce outcomes as observed instead of reopening them for triage. A successful request with nothing unpublished adds no exclusive recovery hold. Real retirement retries its run’s abandoned effects without a door restart; dry-run stays read-only. Status names malformed activity leases per record and keeps other records visible and recoverable. Refresh and restart each door under the documented hold to enable the door changes; retirement and status change with the installed lane program (``claim:superlooplane:unpublished-effects-recover-without-reexecuting``).

- Doors retain abandoned recorded effects for startup or later-request recovery, and give post-reply publication at least five minutes of lock admission or the remaining request-wide allowance if greater. Request status distinguishes running publication work from work awaiting recovery. Hold new work and drain unpublished effects before a normal refresh and restart; for old abandoned effects, stop the old door before starting the refreshed door, verify recovery, then resume. Pending effects are not reconstructed.

- The separate-process door admission fixtures use the controlled admission clock for both ordinary and root-refusal peers, so scheduling stalls cannot change their logical wait verdicts. Door timing is unchanged (``rule:superlooplane:door-request-admission``).

- Doors send no request-lock progress or second refusal after a successful final reply. Late agent and publication failures name the request and phase in the service journal; `requests status` and retirement expose recorded effects awaiting publication, including work still running. Refresh and restart a door to update its own copy; installed status and retirement commands gain the listing immediately (``rule:superlooplane:door-request-admission``).

- The slow 206 MiB route transfer check now uses the gate build profile and reports transfer time as a measurement, without treating node load as a failed upload. Its integrity and 512 MiB output-bound checks remain; the door's 120-second production command deadline is unchanged.

- Keep running journal byte accounting under writer and reservation exclusion, and prune at the hourly deadline or capacity pressure instead of before every mail delivery (``proto:loophome:mail-journal-byte-accounting``).

- Reconsider unchanged mail refusals through bounded per-letter hourly retries, and publish quiet-at-rest service activity counters with rate-limited diagnostics when a refusal cannot be written (``proto:loophome:mail-change-wakeup``; ``proto:loophome:mail-activity-counters``).

- A resumed launch whose preparing publication fails now reports `unchanged: preparing reservation was not published` when a locked read-back proves the exact settled bytes remain. A changed or unreadable reservation still takes rollback and may report `retained:`. Compatibility: no record shape changes; a running launcher keeps its old wording (``test:unit:round-preparing-publication-refuses-without-retaining-unchanged-run``).

- Mail event scheduling resolves only selected senders, and transport resolves its sender and recipient through the existing custody verifier; global staging, retention and identity admission remain explicit accounting costs. Repeated fallback scans no longer postpone hourly refusal reconsideration (``proto:loophome:mail-change-wakeup``).

- Notice in-place repairs of refused mail, reconsider missed changes hourly, and leave not-yet-due refused senders out of unrelated wakes (``proto:loophome:mail-change-wakeup``).

- Make the door admission final-interval test use a controlled clock, so a stalled test cannot skip its release event. Production keeps the same real-clock budget and polling order (`prob:gates:load-sensitive-tests-made-deterministic`).

- A refused resumed launch before driver dispatch restores its original settled reservation and permits the same round name to be retried only when process absence is proven and the attempt's own files are removed. The refusal ends with `rollback: restored` or `retained:` and a reason; for `retained:`, leave the run and its files alone: nothing yet recovers a retained attempt, a crash during a resumed launch or a run stranded before this change. Derived environment and credential refreshes are kept. The preparing record includes the settled bytes, so a settled record above about half the 4 MiB bound refuses to resume with `round-rollback: preparing reservation is N bytes; limit is 4194304 bytes`. The helper-parent update takes the mailbox lock, and refusal evidence is written before absence checks, as `.round-refusal-RUN-NONCE.json` in the runs root, which retirement does not yet inventory; rollback's raw records use the placement-aware reader. Compatibility: the added reservation members are accepted by existing readers; a running launcher keeps its old code (``test:unit:live-round-rollback-restores-exact-bytes-last``; ``test:unit:live-round-rollback-waits-for-process-absence``; ``test:unit:live-round-parent-publication-takes-mailbox-lock``; ``test:unit:live-round-before-image-preserves-placement-floor``; ``test:unit:live-round-raw-reader-preserves-placement-floor``).

- Schedule mail from event-named outboxes and known unfinished senders, retaining delivery checks while avoiding unrelated outbox scans and repeated recovery-history reads (``proto:loophome:mail-change-wakeup``).

- Gate unchanged refused mail by source identity, configuration changes and retry deadlines; report persistent notification fallback and release obsolete uncovered paths (``proto:loophome:mail-change-wakeup``).

- Keep permanent mail refusals off the retry clock; transient failures retain their bounded retries (``proto:loophome:mail-change-wakeup``).

- The agent usage regression check now allows a long hang bound for its completed vendor event, so ordinary node load cannot turn its usage evidence into an unrelated fixture timeout. Running doors and their deadlines are unchanged (``test:unit:agent-usage-complete-survives-cleanup-refusal``).

- The agent stderr-drain regression checks now use a fixed clock for the open-pipe and expired-deadline cases, with a long outer hang bound for their completed vendor event. Running doors and their drain deadline are unchanged (``test:unit:agent-stderr-drain-deadline-blanks-open-pipe``; ``test:unit:agent-stderr-drain-empty-open-pipe-is-not-eof``).

- A complete, successful external checkout pack transfer could be refused as a broken pipe when the machine was busy; it now reads the packing stream to its end before closing the indexing stream. Interrupted reads and writes retry. Real failures still name both Git exits and bounded error tails in the `checkout-git` refusal; successful checkouts keep their output and leave no transfer files. Focused library proofs that launch the lane binary now refuse one older than any source Cargo recorded for it, naming the build command that the documented focused battery runs first, so they cannot exercise a stale executable. No run or record migration is needed (``test:crate:focused-library-binary-refuses-stale-sources``; ``test:unit:checkout-transfer-complete-before-index-close``; ``test:unit:checkout-transfer-eof-with-live-packer``; ``test:unit:checkout-stream-retries-interrupted-io``; ``test:unit:checkout-pack-failure-names-own-stderr``; ``test:unit:checkout-index-failure-names-own-stderr``; ``test:unit:checkout-pack-stderr-flood-stays-bounded``; ``test:unit:checkout-pack-transfer-needs-no-temporary-directory``; ``test:unit:checkout-recorded-transfer-names-both-exits``; ``test:unit:checkout-transfer-spawn-failures-name-command-status``; ``test:unit:checkout-transfer-copy-failure-keeps-status-and-stderr``; ``test:unit:checkout-transfer-missing-streams-name-the-absent-end``).

- Bound mail scan wakes after restored refusals, keep delivery available through notification-limit fallback, and retry known unfinished letters on a capped backoff without waiting for unrelated changes (``proto:loophome:mail-change-wakeup``).

- Make the mail service wait for kernel notifications between scans, eliminating continuous idle polling and repeated history reads per mailbox; preserve delivery checks and reduce ordinary arrival latency, while large-population active scans remain a documented limitation (``proto:loophome:mail-change-wakeup``).

- Door agent invalid-output refusals retain stderr only after end of stream: an open empty pipe, a cleanup deadline, and JSON strings or arrays cannot expose an answer. Complete plain vendor errors remain readable. Refresh and restart each installed door to receive it; direct triage receives it with the global tools install.

- The top-level `superloop-lane` launch usage now lists `--compute-workspace JSON` with its existing arguments, matching the launch refusal's usage; parsing and existing runs are unchanged (``prob:lanes:top-level-usage-lists-the-compute-workspace-argument``).

- Clarify launch interruption on each side of reservation publication: only a published reservation lets retirement name its reserved mail birth. Pin the production ordering-helper call and distinguish legacy refusal evidence from workspace-tagged evidence; no launch or reader behavior changes (``proto:superlooplane:workspace-launch-declaration``; ``test:unit:workspace-private-make-uses-birth-publication-boundary``).

- The `launch LOOP RUN --round STEP` usage now says its budget is per round, defaults to 3,600 seconds and is not inherited from dispatch. Pass `--budget SECONDS` on each resumed launch that needs a longer allowance; command behavior and existing runs are unchanged (``proto:superlooplane:resumed-letter-placement``).

- The correspondence publication/deadline fixture's partial-failure poll now starts with fresh alpha content, so its round ends once both hosts have been polled, under a 120-second hang bound instead of the fixture's 400 ms round. Its slow transport gets a five-second feed deadline, below the stub's ten-second sleep, so it reaches and logs its call before the timeout. Both cases check the call log after the client exits. The partial-failure warning and cursor-isolation assertions remain; installed correspondence behavior is unchanged (``test:integration:failure-isolation-admin-publication-and-deadlines``).

- A refused resumed-round request publication now removes the temporary it created and preserves an occupied destination; the preview’s `helper_preflight.checked` now reads `saved runtime environment and unoccupied final round-request name`, claiming nothing about the later inspector’s temporary. This does not yet roll back a published preparing reservation (``test:unit:round-request-failure-removes-only-its-temporary``).

- The preserved-checkout fixture disables automatic Git maintenance in both repositories before snapshotting the pushed objects, so a transient maintenance lock cannot change its verified file list (``test:unit:checkout-clones-only-verified-preserved-objects``).

- The boxed first dispatch tells the worker to carry out the brief and report as it asks. Install `superloop-lane` with no launch in flight: the launcher, its container helper and the box's prompt client are that one program, so only a launch that crosses the install can pair builds that disagree on that exact prompt, and the prompt client then refuses with `round prompt does not name a mail delivery and step` before it reaches the helper (``proto:superlooplane:container-attempt-completion``).

- A resumed launch, preview or apply, no longer reads the round before it: a dispatch `--letter` file moved, deleted or edited after the dispatch, a rotated run’s absent home `brief.txt`, or a previous step’s absent retained mail no longer refuses the next round, which needs only its own bound retained `mail-STEP.txt`. The preview’s `helper_preflight.not_checked` now reads `busy lease and scope admission before publication`, `every step after the preparing reservation is published` and `launch-time descriptor transfer and intervening changes` (``test:crate:built-helper-resume-retains-mail-custody``).

- After vendor execution, unparseable answers from the entered door-agent runner now report stdout and stderr byte counts and format classes, the parsing stage and, when stdout was parsed, content-free completed-turn, failed-turn and error-event counts, without recording answer text. An invalid-output refusal keeps the bounded stderr tail and first line only for a complete, uncut plain-text stream with no JSON object line; usage-limit text remains visible, while truncated or mixed answer streams are blanked. The vendor arguments and verdict policy are unchanged. Refresh and restart each installed door copy to receive these diagnostics; direct triage receives them with the global tools install. This does not establish the cause of an existing invalid-output refusal (``prob:door:entered-agent-runner-reads-the-answer-the-vendor-gave``).

- A resumed launch now checks its saved client environment (`launch/runtime.env`) and its round request (the step’s delivery binding, and `round-launch-STEP.json` not already present) in the preview and again before it changes the run, so `saved client environment is invalid`, `saved client environment has foreign ownership or protection`, `round request lacks its delivery binding` and `round-launch-STEP.json already exists` now refuse with the reservation still settled; the preview lists the new check under `helper_preflight.checked`. The changing launch now verifies retained mail exactly as its preview does and no longer rewrites it: where the retained `mail-STEP.txt` no longer matches its delivery, the apply refuses with `retained evidence differs from verified delivery` instead of quietly restoring it, and rerunning the identical `bind-mail` for that step restores changed bytes from the journal before the next preview. Compatibility: no command, reservation or request format changes; a refusal after the round is published can still strand it until the separate rollback work lands (``test:unit:round-inspection-validates-before-publication``; ``test:integration:resumed-launch-validates-before-reconciliation``; ``test:crate:built-helper-resume-retains-mail-custody``).

- A resumed boxed round now reads its retained mail through the loop-owned run directory instead of requiring that directory to belong to the host. Both `launch … --round STEP --dry-run` and the changing launch now check that mail binding and the helper’s plan and arguments before a round is published, so a refusal there leaves the reservation settled and the round name unused; the preview lists what it checked under `helper_preflight.checked` and the launch-time steps it cannot guarantee under `helper_preflight.not_checked`. Compatibility: initial letters and initial rotation sources keep their existing custody rules; settled runs need no migration and running helpers keep their loaded code. Install with no resume launch in flight, then rerun the resumed dry run, read its `checked` and `not_checked` fields, and launch. Installing this does not repair a round already stranded by the earlier refusal: keep that run’s reservation, retained mail and evidence in place for the separate recovery step (``test:unit:retained-round-mail-requires-exact-source-and-binding``; ``test:crate:built-helper-resume-retains-mail-custody``).

- The suspended-driver recovery fixture names its mode and clock settings in failed assertions, including an unexpected resume record. Its thirteen cases and production behavior are unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- The door attribution fixture tolerates scheduling stalls while waiting for its four probe connections and gives real fixture operations a generous hang bound. A controlled delay pins the accept bound without sleeping; the separate deadline test still checks production budgets, and installed programs are unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- The door-agent budget fixture drives deadline selection with a controlled clock and checks real descendant cleanup after an observed readiness event. CPU stalls no longer consume its deliberately short logical timeout. Live exercise and door-call deadlines are unchanged, and installed programs behave as before (``prob:gates:load-sensitive-tests-made-deterministic``; ``test:unit:agent-probes-separate-semantic-and-timeout-budgets``).

- The door effect-order fixture now forces a store-lock progress frame before reading the final reply, with a generous hang bound. Its effect, queue and label assertions no longer depend on the first frame being final; production behavior is unchanged (``prob:gates:load-sensitive-tests-made-deterministic``).

- A boxed helper whose setup fails after it binds its first socket, whose credential thread cannot start, or that panics while serving now cancels and joins the threads it started and removes the sockets it bound, so such a failure no longer leaves the run’s request or control socket behind or its control thread running. A socket whose name was replaced during the run is left in place, and the helper then exits with `replacement socket retained` even if the request succeeded; a socket whose identity cannot be read back after bind is left in place with an error saying `retain its slot`. Compatibility: successful runs keep their protocol and result. When a request refuses and the credential thread also fails, the request’s error is now the reported one, where 0.4.2 reported the thread’s, and thread and cleanup failures follow it after `; cleanup`; with no request error a credential-thread failure still comes first. A panicking helper now waits, as a refused request already did, for an in-flight credential pass, and any of these exits can wait up to the control reader’s existing five-second timeout while a control peer stays silent. A helper running at the install keeps its old code until its run ends (``test:unit:helper-service-setup-failures-clean-owned-sockets``; ``test:unit:helper-service-cleanup-joins-an-accepted-control-read``; ``test:unit:helper-service-cleanup-retains-replacement-sockets``).

- Worker allocation blocks can no longer contain namespace uid 65534. **Before installing**, inspect every worker range in the allocation ledger. A containing block refuses with `worker uids include reserved uid 65534 for loop: NAME`: ordinary entry fails for every loop, permission triage denies affected routed calls, and driver launch, mail provisioning and worker retirement, replacement allocation and mail migration cutover refuse when they read the whole ledger. An affected estate must migrate or retire the allocated identities and their owned data, then correct its ledger **using its current tools, before installing this version**. Keep the original records for that migration; nothing is renumbered or rewritten in place. Automatic allocation now skips 65534. Homes whose blocks exclude it need no action (``prob:homes:worker-blocks-exclude-the-overflow-uid``).

- Door installation now exposes `agent_program_admission` at the top level of preview and apply output, separating `admitted`, `refused` and `unmeasured` from the legacy execute-bit observation. No metadata field authorizes runtime execution, and no installed generation changes shape. Validation-only runner configuration cannot execute without a registry loop uid; the ordinary configured door route is unchanged (``reg:superlooplane:door-agent-metadata``).

- Door executable metadata keeps its existing `usable` permission observation separate from the new `admitted` custody verdict. The door-agent exercise creates its protected probe programs beneath the effective account's home, independently of caller-controlled `HOME` and `TMPDIR` (``reg:superlooplane:door-agent-metadata``; ``test:unit:door-agent-case-uses-production-handler-and-names-unmeasured-vendor``).

- Door rubric checks no longer admit the host's numeric uid as a subordinate owner, and runtime checks the registry's loop uid. Door and direct-triage agent calls now refuse a linked, foreign-owned, writable or set-id vendor program (including unsafe ancestors) as `door-agent-program-custody`; configure the resolved protected target. `install-door LOOP --dry-run` reports `executable_status.admitted` and its refusal without running the vendor. The shared program changes direct triage at the global install; refresh each door's installed generation and restart its service to take the fix there. Existing generation and request record formats need no migration (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- `superloop-lane door-sign-in` again accepts a private home carrying the mail system's search-only entry (mode 0710), which it refused with `door-sign-in-private-home-owner-mode` on every mail-provisioned loop; any other access ACL still refuses, and the dry run and placement are otherwise unchanged (``test:integration:door-sign-in-receiver-admits-only-private-home-traversal-acl``).

- The release suite now exercises the workspace producer’s refusal of a Cargo configuration changed during compilation, which keeps the earlier published binaries and record, and its rebuild when a Cargo-home configuration is created (``test:integration:test-release-producer-dependencies``). The producer also depends on the checkout's ancestor directories and the Cargo home, so adding or removing an entry directly in one of them can rerun Cargo at a later build even when no source changed.

- The release build’s compiler-input recorder now treats a string include as one path and records missing included configurations without adding a refusal of its own; Cargo still decides whether the build requires them (``test:integration:test-release-configuration-includes``).

- The release suite (`meson test --suite release`) now refuses a build whose record names a compiler or wrapper override, even an empty one: `RUSTC`, `RUSTC_WRAPPER` or `RUSTC_WORKSPACE_WRAPPER`, their `CARGO_BUILD_` forms, or `rustc`, `rustc-wrapper` or `rustc-workspace-wrapper` under `[build]` in a Cargo configuration the build read, a compiler cache wrapper included. Unset the variable or remove the key, then remove the build directory's `workspace-build.json` before building. Compiler flags are now read with each Cargo source's own token boundaries, so a unit separator inside plain `RUSTFLAGS` no longer hides `--cfg test`, and no path is parsed as shell syntax (``test:integration:test-release-flag-sources``).

- Request-schema conversion (`superloop-lane requests rewrite`) now refuses a custody file whose converted form exceeds the 8 MiB run-file limit in both the dry run and the apply, before writing custody or a pending journal; the apply previously wrote the pending journal and the custody files before it and then stopped at that file, leaving a conversion that every resume refused. The refusal (`requests-rewrite-refusal`) names the custody file, its converted bytes and the limit, and exactly 8 MiB is accepted. A conversion an earlier build left stopped at such a file now refuses before any further write and cannot complete with this release; keep its journal and custody files as they are (``test:unit:rewrite-checks-converted-custody-byte-bound-before-publication``).

- The release suite (`meson test --suite release`) now refuses unless the build directory's `workspace-build.json`, written by the workspace build itself, lists exactly the scanned binaries with their sizes and SHA-256 digests and records no `--test`, `--cfg test` or `--cfg=test` in the compiler-flag variables or the Cargo configuration that build read; Python optimization settings no longer remove its checks, and Meson's timeout now also stops the compiler processes the test starts. A retained build directory writes the record at its first build after this change; after changing compiler flags, wrappers or the toolchain for a retained build directory, remove its `workspace-build.json` before building so that the workspace build runs again and records them. The record stays in the build directory and is not installed (``test:integration:test-release-build-record``; ``test:integration:test-release-admission``).

- Request-schema conversion (`superloop-lane requests rewrite`) now refuses a helper collection whose commit input exceeds the helper's 64 MiB input cap in both the dry run and the apply, before writing custody or a pending journal, even when applying an older preview; the refusal names the collection, the measured bytes and the cap (``test:unit:rewrite-refuses-helper-input-before-publication``).

- Request-schema conversion (`superloop-lane requests rewrite`) now admits plans up to 128 MiB, up from 32 MiB, so loops with larger retired request stores can preview and apply their conversion; a loop whose preview was refused with `plan exceeds bound` reruns the dry run, and oversized-plan refusals now report the measured bytes and bound. Record shapes and the door and helper readers are unchanged (``test:unit:rewrite-converts-plan-above-old-bound``; ``test:unit:rewrite-plan-bound-reports-measured-bytes``).

- The generic repository's public pack verifies: its root documentation partition owns the generated ``docs/public-pack-provenance.toml``, and its publication manifest classifies that member with a reserved exact row and declares the unpublished-label register through `public.unpublished`, which the public-set readers released in 0.4.2 accept. With those declarations, the pack and linter built for this closure passed all eight verification checks against the supplied 41-entry external register with zero occurrences (``prob:pack:pack-verify-burn-evidence-rule``).

## [0.4.2] - 2026-11-12

### Added

- Reply sessions can retain a worker lifetime lease across the service identity drop and bind or verify delivery pins through received configuration, storage, endpoint and journal custody, as a library prerequisite for the reply entry (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Reply-binding inventory can retain received configuration and storage custody through loop snapshots, mailbox metadata and endpoint freshness, sharing one loop-storage capability between endpoints (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:loophome:binding-inventory-retains-received-custody``).

- Active lifetime verification exposes a non-admitting stage whose lease acquisition rechecks custody, receipts and loop-owned bindings, with rootless interleaving and read-only journal metadata regressions (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Mail endpoints can open and recheck freshness beneath received loop-storage custody, retaining canonical journal paths and existing endpoint identity, mode, group and filesystem checks (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:loophome:endpoint-opening-and-freshness-retain-loop-storage``).

- Mail reservation binding and verification can use received journal custody without reopening the journal path, retaining delivery checks and compaction admission while the service writer remains active (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:loophome:journal-reservation-binding-retains-custody``).

- Draft owner-operated Claude credential acceptance distinguishes external token-only startup, refresh attempts, same-process reload and the margin, binding-cost and contention measurements; it leaves vendor outcomes and activation unmeasured (``prob:box:claude-sign-in-and-endpoints-in-the-box``; ``prob:box:claude-print-probe-refresh-margin-measured-against-refresh-ahead``; ``sec:superlooplane:claude-credential-acceptance-draft``).

- Gated Claude credential exercise payload observes the locked token-only projection and schema-2 provider evidence without reporting credential-derived digests; namespace and vendor acceptance remain unmeasured (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-credential-exercise-payload``).

- Credential exercise selects one protected backend through the public and private forms, excludes foreign live runs and keeps Claude measurement gated before owner access (``prob:box:claude-boxed-workers``; ``proto:superlooplane:credential-exercise-backend``).

- Add `superloop-capture-admit` for verified capture admission, manifest-bound identities, quota refusal and current/keep/lease-aware pruning (`prob:servers:capture-admit-admits-and-prunes-sealed-generations`).

- Gated Claude harvest inventories and removes its selected worker state without preserving credentials or sessions, and refuses missing or foreign backend ownership (``prob:box:claude-resources-and-harvest-measured``; ``proto:superlooplane:harvest-selected-worker-state``).

- Gated Claude program comparisons read the installation reference through held configuration custody retained across the authority thread, refusing unsafe or absent custody; the related entry refusal assertions use short constants (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-install-reference-custody``).

- Gated Claude periodic publication selects live worker homes by protected backend and records owner-program evidence without a fabricated OAuth host (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-periodic-credential-publication``).

- Gated Claude credential paths bind the held owner program to the completed installation's reviewed digest and the loop's credential-structure program pin before credential access and again before refresh execution (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-owner-program-binding``).

- Gated Claude preflight and per-round credential publication share the locked provider and post-refresh expiry check, preserving token-only files and the existing publication receipt shape; a failed refresh or an expired result leaves the prior worker file untouched (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-round-credential-publication``).

- The gated Claude owner provider reads only the ``claudeAiOauth`` object of the owner's credential file and refuses any departure from the loop's structural record, and its token-only worker encoding carries the access token with its expiry, scopes and account descriptors and neither refresh field nor the host's plugin state; the owner's own program refreshes, expiry is checked again on the clock read after that program returns, the Codex adapter is unchanged and Claude execution remains gated (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-owner-credential-encoding``; ``rec:superlooplane:claude-credential-structure-input``).

- Boxed launch checks the entry deployment and interface before reservation and names both versions on refusal; the entry query resolves no loop state (``prob:box:launch-probes-the-entry-version-before-the-reservation``; ``req:superlooplane:entry-version-before-reservation``; ``proto:loophome:driver-entry-interface-query``).

- Claude candidate launch vectors carry selected print and model arguments through structural container checks while execution remains gated on credential and trial acceptance (``prob:box:claude-boxed-workers``; ``proto:superlooplane:boxed-launch``; ``conv:superlooplane:backend-selection-compatibility``).

- Boxed image checks bind the protected backend to its own measured program, template and manifest hashes, including the Claude sibling template in mixed installations; Claude execution remains gated (``prob:box:claude-boxed-workers``; ``pre:superlooplane:launch-input-checks``; ``proto:superlooplane:boxed-launch``).

- Exact compute forms in the loop's installed configuration select longer whole-request deadlines while other forms retain 1,800 seconds; the service announces the remaining window to the stub and deadline refusals name the registered bound (``prob:door:door-compute-deadline-per-form``; ``setup:superlooplane:compute-deadline-registration``).

- Owners can explicitly declare unchanged upstream trees non-participating with a reason, retaining partition and census coverage while refusing label activations and preserving the inactive-prose guard for all other owners (``prob:linter:non-participating-owner-for-unchanged-upstream-trees``).

- Door capacity refusals identify the fixed sixteen-peer service bound and a 120-second retry cadence; the worker contract treats them as transient while node compute scheduling remains with the owner-controlled wrapper (``open:door:door-compute-capacity-under-many-lanes``; ``rule:superlooplane:door-peer-capacity``).

- Registered `cargo test` commands admit `--no-run` for compile-only checks under the existing judgement tiers, retaining the exact argv and refusing the flag on other verbs or in runner arguments (``prob:door:door-compute-admits-test-no-run``).

- The mail service emits structured stderr spans and events for inventory skips, each naming the skipped loop or worker and the reason the scan's failure report collects, and for delivery, refusal codes, restoration, recovery, pruning and clock waits, with `RUST_LOG` filtering and a quiet `info` default; refusal sidecars are unchanged (``prob:mail:inventory-skips-are-events-and-the-refusal-names-its-class``).

- Claude plan and home construction select their own worker state leaf and immutable configuration mounts, refuse cross-vendor layouts before writes and leave runtime and credential acceptance explicitly unavailable (``prob:box:claude-boxed-workers``).

- Registered test commands accept one restricted filter after a named test target, including the explicit exact-match suffix, while retaining the argv and refusing additional or unbound filters (``prob:door:door-compute-admits-test-name-filter``).

- Boxed launch accepts an explicit `--backend {codex|claude}` selector, validates that vendor's configured program without cross-vendor fallback and names the selection in its preview; Claude execution remains refused as `backend-unavailable` pending its plan, home, entry, credential and runtime adapters, and resumed rounds refuse a backend selection; existing settings files select Codex as before (``prob:box:claude-boxed-workers``; ``conv:superlooplane:backend-selection-compatibility``).

- Namespace entry has a shared capability foundation for verified maps, bounded descriptor handoff, operation-bound custody checks and ledger/registry reads beneath one configuration anchor; production caller migration remains deferred (``req:workercontracts:namespace-anchor-authority``).

- Publication manifests declare the unpublished-label register destination through `public.unpublished`; cuts generate it there and bind the owner snapshot to it, refusing excluded-definition citations without a declaration and unsafe or conflicting destinations; readers built before this release (the linter, the build-sync census and the pack) refuse the field as unknown, so a tree that declares it is read by this release's linter, build-sync and pack, installed together (``prob:pack:manifest-declares-the-unpublished-register``).

- The contributing guide gives slice workers the branch workflow, source declarations, node verification bar and working-step report contract (``guide:contributing:superloop-tools``).

### Changed

- Close the helper-authority cancellation record after its activation, scope and panic regressions, retaining the release compatibility statement beside the protocol (``prob:box:helper-service-cancels-when-its-authority-thread-exits``).

- Pin fixture-admission absence in every workspace release artifact with a current unit-test positive control and an empty-set refusal (``test:integration:test-release-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Reply binding now has an actual-package acceptance through the public binding body, including vector construction, rights handoff, result comparison, reservation publication and an identical retry. A fixture host-root seam leaves the normal launcher’s root walk and executable selection unchanged; no deployment action or command syntax change is required (``claim:superlooplane:reply-entry-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Retain the fixture enclosure when a watchdog collects output after an unconfirmed namespace stop, so consuming the child handle cannot authorize removal during unwind (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-unconfirmed-stop-retains-enclosure``).

- Pin the Claude fixture transaction's bound-evidence read-back, dead-helper exclusion and authority panic cancellation, and retain uncertain source custody and child output on fixture failures; production behavior is unchanged (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``prob:box:helper-service-cancels-when-its-authority-thread-exits``; ``test:unit:claude-fixture-periodic-dead-helper``; ``test:unit:helper-authority-panic-cancels-service``; ``test:unit:claude-fixture-move-rechecks-custody-before-drop``; ``test:unit:claude-fixture-watchdog-retains-child-output``).

- The inbox watcher readiness problem is closed with its record in the hook package's README: a loop takes the fix by restarting its inbox watcher from the updated recipe with the same command, and a watcher that is not restarted keeps working on its previous recipe (``prob:hooks:inbox-recipe-resets-its-readiness-before-each-watcher-launch``).

- Exercise the test-only Claude periodic authority over a live fixture reservation, including event-controlled evidence and configuration scope loss, mapped worker publication and exact enclosing-storage inventory; production remains gated (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-periodic-publication``).

- The anchored mail service's refusal sidecar names an entry refusal by its anchor class in `code` (`anchor-declaration`, `anchor-missing`, `anchor-transport`, `anchor-owner`, `anchor-mode`, `anchor-kind`, `anchor-identity`, `anchor-escape`, `anchor-exec`, `anchor-io` or `anchor-uid-map`) and any other entry refusal as `entry-refusal`, where it wrote `io-failure`. Such a sidecar is written only when the service's own configuration custody fails before a letter's delivery is accepted and holds again when the refusal is projected, because a lasting fault stops the service at its next scan instead; filesystem failures keep `io-failure`, the `reason` text is unchanged, the letter stays refused until its sender withdraws or changes it, 0.4.1 wrote no entry refusal, and nothing in this tree reads the field. The reply-session library, which has no production caller, now receives its five mail capabilities into an owned bundle validated before lifetime repair, rechecks the live outbox at binding and inside the journal verifier, and revalidates journal custody after the admission wait; its direct lifetime guard refuses a registry override in the entry form, exit 2. The reply command, its pathname journal admission and the held caller switches are unchanged (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``test:unit:mail-service-records-anchor-refusal-code``; ``test:unit:mail-entry-refusal-code-uses-a-closed-allowlist``).

- Keep a replacement enclosure intact when mapped fixture cleanup fails during host drop, disarming automatic pathname-recursive removal before fallible cleanup (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-cleanup-failure-keeps-replacement``).

- Check the mapped fixture cleanup's current-directory identity against its held enclosure before removal, retaining stderr on refusal and measuring renamed-directory custody (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-cleanup-checks-mapped-enclosing-identity``).

- Make the private credential-authority wait injectable for event-driven pass boundaries, retaining the production thirty-second cancellable interval (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-authority-waits-for-pass-release``).

- Inventory fixture cleanup reports metadata-query errors when checking that the parent-owned root and marker remain, retaining the directory and regular-file checks (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The closed dead-pid fixture record now preserves the dated measurement of recurring collision windows at the node’s pid churn (``prob:gates:fixtures-name-a-dead-process-by-a-number-no-process-can-hold``).

- Exercise one test-only Claude helper round through held namespace custody, with mapped worker publication and enclosing-storage cleanup controls; production remains gated (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-fixture-admitted-round``).

- The anchored reply session refuses ambient registry overrides as entry declarations rather than backing-store I/O, converging on mail exit 2 before the command migration (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Fixture admissions validate actual helper-thread inputs and exact evidence destinations before exposing a binding, retain cleanup with the host, and reject noncanonical digests and password-database account roots (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Helper unit tests carry opaque fixture scope through consumer refusals and one-shot periodic custody, with root creation and held-anchor identity checks; production retains its closed Claude gate (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- The inventory fixture removes its home root only from the parent that created it, and only after namespace cleanup has removed the mapped children; that cleanup retains the root and marker, its phases admit only a real directory directly beneath the temporary directory, and metadata failures are reported instead of treated as absence (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Bounded fixture output always gives the child the null device as standard input, as the replaced `Command::output` call did by default, instead of the test's own input, and retains both output streams in timeout diagnostics, with a non-null input control (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The reply-session acceptance honours matching and nonmatching libtest filters, exact and skipped selections, listing, quiet and colour flags and libtest's `--option=value` spellings without accidentally running a filtered fixture (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper authority carries the same borrowed program binding through evidence construction and publication, retaining production evidence bytes and the compiled census boundary while custody tests pass an explicit runtime admission (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:helper-runtime-admission``).

- Dead-process fixtures use distinct positive process IDs above Linux’s PID ceiling, with a live-lock control, so PID counter wrap cannot turn a recovery fixture into a live-owner refusal (``prob:gates:fixtures-name-a-dead-process-by-a-number-no-process-can-hold``; ``test:unit:dead-lock-fixture-pid-exceeds-kernel-limit-and-live-lock-refuses``).

- The helper runtime-admission protocol uses the lane manual's bold protocol-statement form, retaining its label and contract (``proto:superlooplane:helper-runtime-admission``).

- Helper-service custody alone constructs and consumes the admission thread token; program binding is borrowed from the admission without producing another owned proof (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Helper-service refusal tests call the admitted production cores with the gate explicitly; the six test-only forwarding wrappers are removed and the core documentation names the actual endpoint selection (``proto:superlooplane:helper-runtime-admission``; ``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Claude fixture cleanup rechecks retained identity after mapped cleanup and refuses a linked runs directory, with precise replacement regressions (``prob:gates:lane-fixture-homes-leave-no-temporary-root-behind``; ``test:unit:claude-cleanup-rechecks-host-identity-after-mapped-removal``; ``test:unit:claude-cleanup-refuses-a-linked-runs-directory``).

- The custom reply-session acceptance lists its test without entering the namespace and refuses unsupported filter arguments (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Mail inventory and reply-session acceptances bound subprocess waits, inherited output pipes and cleanup, reporting retained fixture paths on cleanup failure (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper credential pins and Claude evidence consume an explicit reviewed program binding while retaining the compiled reference and closed runtime gate (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-owner-program-binding``).

- Claude helper-service refusal regressions distinguish publication custody, launcher identity and periodic refused evidence through cancellation (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-service-periodic-claude-gate-publishes-refusal``).

- Held mail inventory acceptance pins empty and canonical registry-override refusals and checks the service’s credentials against every registered loop before narrowing to the selected loop (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper-service runtime gates use explicit admission cores and a custody-bound thread token, retaining the existing refusals and introducing no fixture admission (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:helper-runtime-admission``).

- Claude namespace mutation cleanup retains the host fixture identity instead of trusting a namespace-writable path record, with redirection and directory-replacement regressions (``prob:gates:lane-fixture-homes-leave-no-temporary-root-behind``; ``test:unit:claude-cleanup-retains-host-fixture-identity``).

- Pin Claude helper-service gate refusals and their existing validation order before introducing fixture admission (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-service-claude-gate-baseline``).

- Pin the wrong-program digest refusal through a due Claude round publication, including retained worker bytes and inode (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-namespace-held-program-standin``).

- Pin Claude namespace fixture cleanup across timeout and host panic, including subordinate-owned worker storage (``prob:gates:lane-fixture-homes-leave-no-temporary-root-behind``; ``test:unit:claude-namespace-fixture-cleanup-survives-timeout-and-panic``).

- Contain Claude namespace fixture descendants across process-group changes with a per-case PID namespace and a watchdog regression (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:claude-namespace-watchdog-contains-detached-descendant``).

- Record a synthetic probe of the namespace watchdog's kill sequence, in which a descendant in a process group of its own survives, keeping descendant cleanup and its regression through the namespace wrapper open (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``).

- Bound the Claude trial draft's worker-file observations, same-process rejection evidence and expired print-call regime without selecting a repair policy (``prob:box:claude-sign-in-and-endpoints-in-the-box``; ``prob:box:claude-print-probe-refresh-margin-measured-against-refresh-ahead``).

- Pin held Claude owner-program execution in the mapped namespace with a recorded-digest native stand-in, transferred custody and expired-result preservation (`prob:box:claude-program-binding-formats-pins-and-measures-its-hash`).

- The capture state record specifies the completed-step driver and monitor fallback, and the finished-state observation item closes there on its retained historical observations, invalid-monitor and rollback regressions, corrected lock-name wording and the supplied watcher glossary (`prob:lanes:claude-lane-finished-state-null-driver`).

- The remaining door merge-failure, deadline, wait-error, decided-enforce and learned-hit regressions consume validated lock-wait credits before their final reply within one bounded window (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:door-final-reply-follows-lock-wait-credits``).

- Pin restoration of the completed observation through resume-preparation rollback, retaining the production snapshot bytes in the retried archive (``prob:lanes:claude-lane-finished-state-null-driver``; ``test:integration:claude-rollback-restores-completed-snapshot``).

- Pin completed driver identity retention when embedded monitor text is invalid, with the real driver publication and follower as the control (``prob:lanes:claude-lane-finished-state-null-driver``; ``test:integration:claude-finished-state-keeps-identity-with-invalid-monitor``).

- Door enforcement, adjudication and incomplete-record regressions consume request-lock credit frames before their final-reply assertions, with deterministic multi-credit coverage (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:door-final-reply-follows-lock-wait-credits``).

- Five credential-exercise JSON macro bodies are split into reviewable lines without changing their fields or values (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-credential-exercise-payload``).

- A mapped-identity fixture exercises Claude provider preparation, round publication and observation with synthetic authority, retaining the worker file on expired refresh and keeping the public runtime gate closed (``prob:box:claude-boxed-workers``; ``test:unit:claude-namespace-publication-keeps-worker-authority-separate``).

- Credential binding regression checks isolate activation-start clearing and mid-activation anchor replacement, and census provider refusals pin their detail (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-program-binding-cadence``).

- Capture admission uses the sanctioned agent-text terminal report with matched statuses, classed diagnostics and suppressed panic payloads; its interrupted-generation and write-order follow-ups are met (``prob:servers:capture-admit-orders-its-writes-and-declares-its-output-mode``).

- Keep capture admission and pruning available after an interrupted generation rename, publish keep before current, and cover special-entry refusals (``prob:servers:capture-admit-orders-its-writes-and-declares-its-output-mode``).

- The audit-before-effect regression waits through request-lock credit frames before asserting the final reply, retaining its no-effect-before-label checks (``test:unit:door-audit-label-precedes-effect``; ``proto:superlooplane:request-lock-wait-credit``).

- Periodic Claude refresh regression coverage exposes repeated owner-program calls for unrotated authority inside the refresh-ahead window and retains worker bytes at expiry (``prob:box:claude-print-probe-refresh-margin-measured-against-refresh-ahead``; ``proto:superlooplane:claude-periodic-credential-publication``).

- Credential evidence regression cases refuse cross-schema provider fields and foreign backends at both publication and census, retaining prior evidence on a refused publication (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-periodic-credential-publication``).

- Gated Claude program bindings reuse successful verification only for unchanged held custody within one thread and activation; metadata, policy and required-pin checks remain on every boundary (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:claude-program-binding-cadence``).

- Native creation is accepted through its production namespace composer, receiver and home creation, with reserve and finish bound to the protected receipt, active mail configuration, placed brief and redacted worker credential (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:native-creation-completes-reserve-and-finish``).

- Runtime preparation executes its received container program through the production namespace receiver after pathname replacement, with real anchored birth setup and distinct image-inspection results (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:runtime-preparation-executes-received-podman``).

- The complete rootless helper service refreshes a due synthetic owner source through its real periodic authority, publishes the rotated bearer without the refresh token to a live mapped worker, and records successful custody evidence before its socket attempt (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:helper-service-refreshes-live-credentials``).

- Service credential-authority fixtures keep every refresh endpoint on loopback, order the first check after parent guard release, clean retained homes during unwinding and bound cancellation before joining (``prob:box:service-credential-spawner-fails-closed-and-pins-its-guards``; ``claim:superlooplane:service-authority-cancellation-prevents-first-check``; ``claim:superlooplane:service-authority-retention-cleans-up-on-panic``).

- Credential regressions exercise the helper publication transaction with foreign client custody and retain the failed-refresh preservation case as its own bounded test (``prob:box:claude-credential-tests-the-mismatch-site-and-splits-the-long-test``; ``test:unit:helper-credential-mismatch-precedes-reservation-publication``; ``test:unit:claude-failed-round-refresh-preserves-worker-file``).

- Native creation carries the selected backend into its private form and credential capability, reconstructs that plan through held configuration and keeps Claude preflight behind the runtime gate (``prob:box:claude-boxed-workers``; ``proto:superlooplane:native-creation-selected-credential-custody``).

- The helper service's credential-authority spawn retains its own directory and executable custody after the parent releases its guards; a replaced-home fixture measures the real authority loop's first healthy and refused evidence, its received client execution and its cancellation (``test:unit:service-credential-authority-retains-custody``).

- The helper transfers only the protected backend's credential client and clock into its authority thread; Claude has a distinct executable role and foreign-only capability maps refuse without ambient fallback (``prob:box:claude-boxed-workers``; ``proto:superlooplane:selected-credential-executable-custody``).

- Owner credential refresh runs behind a provider boundary that keeps the Codex adapter's existing transport and custody, with test stand-ins for staged publication, an owner program's own publication, owner replacement and refusal, and Claude execution remains gated (``prob:box:claude-boxed-workers``; ``proto:superlooplane:owner-credential-provider``).

- The private boxed entry argument form and its refusal boundaries are pinned beside the interface-version constant through the production parser, so an argument-contract change requires a deliberate update of the versioned test (``prob:box:entry-probe-fixtures-follow-the-workspace-version``; ``req:loophome:driver-entry-versioned-form``).

- Boxed resumed paths bind session evidence and resume arguments to the protected backend; Claude quota rejection does not authorize capacity retries, and execution remains gated (``prob:box:claude-boxed-workers``; ``proto:superlooplane:selected-backend-round-evidence``).

- Document the existing executable-byte pins and the verified door step owed by lane-crate rebuilds, including changes outside the helpers' own sources; this chooses the record's documentation option and adds no rebuild-invariance guarantee (``prob:door:runner-template-keyed-on-embedded-bytes``; ``rule:superlooplane:door-rebuild-rollout``).

- Cut-tree acceptance retains its Cargo target and Meson build directories across rounds, resets fixture sources and checks fresh cut identities on every run; configuration compiles publication selectors once (``sec:publicpack:publication-follow-ups``).

- Private boxed entry carries the protected backend explicitly, validates only its configured program and binds the driver selector without changing settings evidence; matching lane and entry versions are required, and Claude launch remains unavailable pending the image, runtime and credential adapters (``prob:box:claude-boxed-workers``; ``sec:loophome:driver-launch``; ``conv:superlooplane:backend-selection-compatibility``).

- Every workspace package depends on the shared `tracing` crate so instrumentation requires no per-package dependency change (``rule:buildcontracts:tiers``).

- Boxed plans bind the selected backend through home and runtime checks, resumed-plan reconstruction and credential publication; Codex refresh skips Claude records. Old runs without a binding must drain and retire before deployment; no backend is inferred for them (``prob:box:claude-boxed-workers``).

- Replay regressions pin malformed historical manifests, unpublished owner and path-class audit context, and drift-path burn refusals before destination writes; existing tests already cover committer and email preservation and audit mapping (``prob:pack:replay-optional-tests``).

- A built-binary cut regression pins existing tag-blob register planning and owner rewriting independently of clean-worktree admission, preserving the complete public tree when source files change after preflight (``prob:pack:register-planning-from-tag-blobs``).

- ACL widening fixtures reach the settings and handed-lock readers with a non-writable mask and pin their named refusals; settings diagnostics describe nominal modes with validated ACLs (``prob:homes:exact-mode-readers-reason-about-the-acl-mask``).

- The compute grammar explicitly retains dash-led run-binary names in the existing `-p` value domain; regressions pin that choice and the stricter check, clippy and test selector matrix (``open:door:compute-run-bin-value-rule``).

- Built-binary cut regressions pin the refusals of an absent and a failed linter, malformed citation JSON and an unknown protocol namespace or version, with measured protocol fixtures, retained failure diagnostics and no publication on refusal (``prob:pack:cut-executable-route-refusals-tested``).

- Read-only request listings expose admitted door judgements, runner observations, call-count provenance, rubric digests and effect walls without requiring review (``prob:door:requests-show-exposes-judgement-fields``).

- Strict schema-five door records retain bounded agent observations, including rubric failures and cleanup probes; the explicit digest-bound rewrite preserves schema-four judgements with null historical observations (``prob:door:request-record-keeps-agent-observations``).

- Request rewrite previews mark each custody file with a digest-bound `changed` flag and name the fixed conversion schema pair explicitly (``prob:door:requests-rewrite-preview-omits-unchanged-files``).

- The README names the built and installed public commands, private helpers and build-only report tool while retaining the source-consumer lockfile policy (``sec:publictools:build``).

- Replay coverage pins refusal before destination writes when a historical manifest lacks its required register declaration, even when TAG declares one; the replay contract states that this optional field has no fallback (``prob:pack:manifest-declares-the-unpublished-register``).

- Door agent isolation documents that credential-free records and logs depend on the configured agent not emitting credentials; captured failed-agent stderr has no credential filter (``prob:door:agent-stderr-tail-credential-filter``).

- Request-list shared-deadline regressions run the plain, pending and state-filtered forms on scoped threads, retaining their independent contention assertions while overlapping the production wait allowances (``rule:superlooplane:requests-list-contention``).

- Real-Git regression coverage verifies repeated no-op pushes through the door stub and handler, including completion, unchanged mirror refs and recorded no-ref outcomes around a push carrying new objects, while the historical mixed-version refusal is not reproduced by this fixture (``proto:superlooplane:registered-ssh-transport``).

- Two-identity request fixtures exercise valid documents and marked requests and assert named registry and state-root owner mismatches for both mapped callers; their ignore reasons name the required UID/GID map and fixture capability (``test:integration:requests-entry-requires-one-account-for-door-and-permission-custody``).

### Fixed

- `bind-reply LOOP RUN --step STEP --delivery INSTANT` hands its private `_bind-reply` entry one operation-bound bundle of the owner home, runs root, entry executable, configuration, loop storage, private storage, identity executable and journal; the entry reads the reservation and evidence directory beneath the received runs root, keeps the worker lifetime lease through the service identity drop and evidence publication, and rechecks the worker's outbox and the journal's custody after the admission wait. Compatibility: the public syntax, delivery selection and reservation records are unchanged, but the public command and its private entry must come from one build: an older public process reaching the new entry refuses as `anchor-missing: operation=mail-binding purpose=manifest` and a newer one reaching an older entry as `verified-prefix: private launch requires bound home, runs root and letter descriptors`, both before any binding, so install with no `bind-reply` running and run the same command again afterwards. `bind-reply` refuses an ambient `ENTER_LOOP_REGISTRY`, empty or canonical values included, and now needs a root-owned `/usr/bin/setpriv` reached without links; a host-owned `~/.config/loops` at 0700 whose registry, allocations and mail-service files are host-owned at 0600, the provisioned service search and read grants showing as 0710 and 0640 and passing; `~/.var/loops/LOOP` host-owned at 0711, its `private` directory loop-owned at 0700 and `~/.var/loops/.mail-service` service-owned at 0700; and an owner home and runs root that are distinct and give their owner full access with no setuid, setgid or sticky bit and no group or other write. Trees written by the mail provisioner and the home preparation pass; a hand-widened mode, a symlink, a foreign owner, unsafe reply evidence or custody changed during an admission wait refuses by its named anchor boundary (``claim:superlooplane:reply-entry-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The helper service stops when its credential-authority thread exits for any reason, including a custody activation or scope refusal and a panic, and the thread's own error remains the helper's reported error (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``test:unit:helper-authority-activation-failure-cancels-service``). Compatibility: in a release build the authority's activation and scope checks cannot refuse and an evidence-publication failure already stopped the service, so the one reachable change is a panicking authority thread, which now cancels the in-flight round at once and ends the helper with `credential-thread: authority thread panicked`, where the helper used to keep serving without refresh until the run ended and then report that error; successful refresh, evidence and the thirty-second cadence are unchanged, no file, argument, setting or gate changes, an upgrade needs no step, and a helper already running keeps its old behaviour until its run ends.

- Inbox watchers start each watch with an empty readiness file, avoiding a stray missing-file error on the failure channel and premature arming after directory replacement. A running watcher keeps the old form until it is restarted from the updated recipe (``guide:superloopclaudehook:ordinary-inbox-waiting``).

- Private rotation handover, the half of `rotate LOOP RUN`, `--dry-run` included, that reads the old run's settled replies, saved briefs and last context observation, receives the five-role reader bundle: its plan's settings, registry and allocations come from the validated configuration snapshot, its runs-root argument and the public read's reservation identity are bound to the received runs root, and the reservation, reply and brief digests execute the received hashing file. Compatibility: the public syntax and journal admission are unchanged, but the launcher and the private entry must come from one build, an older launcher's handover refusing as `rotate-private: anchor-missing: operation=rotation-handover purpose=manifest` and a newer launcher's handover to an older entry as `verified-prefix: private launch requires bound home, runs root and letter descriptors`; either refusal comes before any private read and before the rotation records an intent, so `rotate` is run again once both sides are installed, and a rotation whose intent is already recorded resumes without a handover. `rotate` now needs a root-owned `/usr/bin/sha256sum` reached without links, a host-owned `~/.config/loops` of mode 0700, and an owner home and runs root with full owner access and no setuid, setgid or sticky bit, and refuses an ambient `ENTER_LOOP_REGISTRY` at the handover (``claim:superlooplane:rotation-handover-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Steward protocol fixtures separate ordinary list/read budgets from timeout measurements, with a delayed-list regression and controlled-clock repeated feeds (``prob:gates:steward-transcript-list-step-deterministic-under-stall``).

- Private round inspection, the half of `launch LOOP RUN --round STEP` that reads the settled thread and records the next round's request, receives the five-role reader bundle: its plan's settings, registry and allocations come from the validated configuration snapshot, and its reservation, step events, event boundary and optional request publication stay beneath the received runs root. Private settlement's step-directory check and thread read take the same held walk. Compatibility: the public syntax is unchanged, but the launcher and the private entry must come from one build, an older launcher's descriptor suffix refusing as `round-private: anchor-missing` and an ambient `ENTER_LOOP_REGISTRY` refusing before private state reads; the launcher requires a root-owned `/usr/bin/sha256sum` and a host-owned `~/.config/loops` of mode 0700; and every directory beneath the runs root down to the step directory, the `steps` archive and each step archive must belong to the loop identity without group or other write, links refuse, and every step archive needs both its boundary files, where the pathname walk accepted the reported step's archive without its end (``claim:superlooplane:round-inspection-retains-custody``; ``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Process-absence fixtures share the kernel-impossible PID constant, including public retirement's real presence check (``prob:gates:fixtures-name-a-dead-process-by-a-number-no-process-can-hold``; ``test:unit:dead-lock-fixture-pid-exceeds-kernel-limit-and-live-lock-refuses``).

- The node absence probe matches the paths retirement removes, the checkout beside the mirrors and the build and temporary directories beneath the registered node root, and worker-home components in whole arguments or option values, so a sibling run’s prefix collision or script text no longer holds retirement (``prob:lanes:node-absence-probe-binds-the-run-at-component-boundaries``).

- Composed reply entry explicitly refuses registry overrides in its existing lifetime error envelope before lifetime admission or changing identity (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Held mail inventories preserve every snapshot refusal, including invalid service ACLs, rather than losing the cause and retirement state; pathname inventories retain their existing skip behavior (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Held mail inventories preserve namespace-entry and anchor refusals instead of reducing them to per-actor skips, and revalidate private-storage custody after acquiring the configuration's read lock (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Anchored lifetime admission revalidates loop-storage after waiting for its receipt lock, refusing custody changes during the wait before returning a lease (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Interrupted-settlement report tests compare measured walls within JSON floating-point precision while keeping every other report field exact, including resumed rounds and older socket evidence (``prob:lanes:settle-report-wall-survives-json-round-trip``).

- Retirement process scans bind driver paths at argument and component boundaries and leave container-name ownership to the labelled container scan, so sibling fixtures and unrelated hub commands do not hold a run by a shared name substring (``prob:lanes:retire-busy-census-binds-to-the-runs-own-processes``).

- Active worker lifetime leases can retain receiver-validated configuration, storage and identity-execution custody while verifying and locking the receipt, without reopening the owner-home paths; reply binding keeps its existing route until its journal and endpoint custody move (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Mail entry requires its exact two-record declaration before descriptor receipt and configuration reads, replaces the consumed stdin socket with the null binding, and preserves descriptor duplication and rights-socket inspection failure causes in mail and worker entry refusals (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Private checkout retains configuration, hashing, Git and its external destination parent across namespace entry, refusing mismatched capabilities before state reads; settled checkpoint, checkout, import and harvest-preview cases distinguish execution through the received tools (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:checkout-entry-retains-custody``).

- Completed driver captures retain advisory driver and monitor state after lock removal, bound to the current step and start marker and never treated as live PID authority (``prob:lanes:claude-lane-finished-state-null-driver``; ``proto:lanelifecycle:completed-step-observation``; ``proto:workermonitor:completed-driver-observation``).

- Harvest recovery carries only its five used capabilities and requires no Git executable; checkpoint restores its relative-home refusal before descriptor receipt and has a focused coverage witness, and the namespace recovery fixture receives its hashing capability from the host (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:harvest-entry-retains-configuration``; ``claim:superlooplane:checkpoint-entry-retains-configuration``).

- Private import marking retains configuration, hashing and Git custody across namespace entry before validating the preserved checkpoint and import journal (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:import-entry-retains-configuration``).

- Private harvest and recovery retain configuration, hashing and Git custody through namespace entry before inspecting collection state; measurement refuses surplus capability declarations and private-report custody has its production test witness (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:harvest-entry-retains-configuration``; ``claim:superlooplane:private-reports-retain-received-custody``).

- Public harvest preserves protected backend refusals before child execution; namespace recovery independently pins its closed Claude gate and unchanged state (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:harvest-selected-worker-state``).

- Private checkpoint entry retains configuration, hashing and Git custody through namespace entry, refusing malformed bundles before checkpoint state reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:checkpoint-entry-retains-configuration``).

- Private credential exercise refuses relative owner homes before reader custody; its digest inventory retires the removed reply comparison instead of pointing at an unrelated line (``proto:superlooplane:credential-exercise-backend``; ``rule:digests:inventory-evidence``).

- Credential measurement no longer requires or transfers an unused Git executable; its exact five-capability frame retains configuration and hashing custody (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``).

- Gated Claude exercise refuses worker files whose bytes differ from the token-only encoding, including duplicate members hidden by JSON value equality (``prob:box:claude-boxed-workers``; ``proto:superlooplane:claude-credential-exercise-payload``).

- Follow and context readers retain configuration and runs custody across namespace entry; replaced configuration paths supply no input, while raw follow events and bounded context evidence keep their public formats (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Driver reports and retirement lock reads retain operation-bound home, runs, entry and hashing custody across namespace entry; reader tool ownership and exact descriptor frames refuse before state reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-reports-retain-received-custody``).

- Private observed-host reads retain operation-bound configuration custody through namespace entry, preserving the protected reservation and observation checks when the configuration pathname is replaced (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``).

- Private credential measurement retains configuration, reservation and helper-evidence custody across namespace entry and pathname replacement, preserving worker token checks and refusing a disappearing census entry (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``; ``claim:superlooplane:reservation-census-stays-beneath-received-root``).

- Harvest and removal recovery require the protected backend's runtime gate before collection processing, refusing Claude records while activation remains closed (``prob:box:claude-program-binding-formats-pins-and-measures-its-hash``; ``proto:superlooplane:harvest-selected-worker-state``).

- Service authority fixtures require a spawning-thread endpoint and refuse before spawning when it is absent; nested guards restore the prior endpoint and a new thread inherits no hook, while production keeps its fixed endpoint (``prob:box:service-credential-test-hook-closes-by-default``; ``claim:superlooplane:service-fixture-endpoint-required``).

- Private harvest and home-layout readers retain configuration and checkpoint-tool capabilities through namespace entry, refusing changed identities and unsafe modes before plan reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:private-exercise-readers-retain-configuration``; ``claim:superlooplane:checkpoint-tools-use-received-capabilities``).

- Private worker-identity selection scans reservations, driver directories and protected residue beneath the received runs-root descriptor, retaining record validation and refusing a substituted root or linked record by name (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:reservation-census-stays-beneath-received-root``).

- Helper custody regression checks execute the received runtime through the production namespace receiver and socket service after pathname replacement, authorize a mapped loop peer, retain authority-thread evidence, and complete a loopback refresh through the production spawner beneath the retained home (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``claim:superlooplane:helper-service-executes-received-runtime``; ``claim:superlooplane:service-reservation-key-binds-held-runtime``; ``claim:superlooplane:service-credential-authority-retains-custody``).

- Door-agent exercise probes give verdict and output checks execution headroom beyond cleanup while retaining the separate short timeout and child-reaping bound; delayed real-runner fixtures pin the distinction (``prob:gates:door-modes-runner-probes-red-intermittently-after-the-custody-move``; ``test:unit:agent-probes-separate-semantic-and-timeout-budgets``).

- Native creation previews derive their ordered capability roles from the receiver definitions; the public preview fixture pins the complete required and optional lists, and partial-map exercise fixtures pin their runs-root alias refusal envelope (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- The network exercise acceptance executes its reservation-selected native capability through the production namespace entry after pathname replacement, distinguishing the held image-inspection exit from the replacement without claiming a measured box boundary (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Helper receipt names aliased home and runs roots as the runs-root refusal, and the credential handoff exercises the received client file through the refresh path while refusing a pathname fallback (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Runtime version-query regression derives its expected program version from the workspace package version, retaining its no-state-access assertion across release bumps (``prob:box:runtime-subprocess-contract-follows-the-workspace-version``; ``test:integration:version-and-usage-do-not-open-runtime-state``).

- Credited compute refusal regressions drive the production stub with the 1,000 ms caller budget on early and queued refusals, retaining raw announcement checks, the shared credit cap and exact final diagnostic assertions (``proto:superlooplane:request-lock-wait-credit``).

- Container helpers and the four container-backed exercises receive configuration custody alongside executable custody; registry, ledger and worker settings reads use the held directory despite pathname replacement, and ambient registry overrides refuse before helper pins or private reads (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``; ``proto:workercontracts:namespace-anchor-handoff``).

- Runtime and native creation read worker settings beneath the received configuration directory, retain the bounded parser and validated ACL checks, and refuse missing or unsafe held files despite substituted settings; isolated host-composer cases require registry-override refusal before pinning (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Compute deadline regressions retain the stronger unextended spawn-budget bound and force store contention on early execution-window refusals, queued deadline expiry and queued adjudicated refusals, keeping requested and registered figures exact while asserting their separate effective bound (``proto:superlooplane:request-lock-wait-credit``).

- Entry-version fixtures derive the current package version and their mismatches at compilation, keeping fresh and resumed probe contracts valid across workspace version bumps (``prob:box:entry-probe-fixtures-follow-the-workspace-version``; ``req:superlooplane:entry-fixture-package-version``).

- The credential refresh fixture joins the production helper bundle and its shared authority-thread handoff, verifying a real refresh exchange with only the client and clock capabilities transferred (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Native creation previews describe the capability bundle instead of retired descriptor flags, and creation receipt keeps owner home and runs root distinct while permitting the letter directory to reuse either (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Native creation selects worker UIDs from its verified configuration and held loop-storage history, preserving receipt and reconciliation checks after configuration or storage path replacement (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Admission-release regression readers consume store-wait progress before their final completion, with both release timings forced through a contended store and the execution and custody assertions retained (``proto:superlooplane:request-lock-wait-credit``).

- A service-to-stub regression pins a contradictory RUN-REPORT beside the unchanged node measurements and its persisted refusal; the spawn-budget assertion retains the original requested bound while the registration and request assertions remain exact (``proto:superlooplane:compute-deadline-and-evidence``; ``proto:superlooplane:request-lock-wait-credit``).

- The completed-command regression consumes sibling-record-wait progress through the production stub before checking the final completion, with a forced progress frame and unchanged execution-count and custody assertions (``proto:superlooplane:request-lock-wait-credit``).

- Estate-referral regressions use the production stub to consume contention progress before asserting the final adjudicated refusal and unchanged custody evidence (``proto:superlooplane:request-lock-wait-credit``).

- Compute replies preserve the exact registered and requested deadline bounds under store contention and name the credited bound separately as `effective_deadline_ms` (``proto:superlooplane:request-lock-wait-credit``).

- Namespace executable checks share their pin and image validation, retain the active operation’s refusal envelope and reject surplus exercise arguments before parsing the private form; the attempt runner and real runtime entry exercise held execution across pathname replacement (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Runtime and native creation plans use the registry and allocation snapshot validated beneath their configuration capability, including settings grants and worker identity selection, without reopening ambient registry paths (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Anchored native creation and runtime verification refuse every ambient registry override, including the canonical registry path, before reading grants or changing custody (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Warm public-cut acceptance leaves its configured Meson tree intact; only the replaced archive is reconfigured, and both setup walls remain reported (``prob:build:cut-acceptance-reconfigures-only-the-changed-tree``; ``proto:publicpack:configure-changed-cut-tree``).

- The container helper pins its credential client and clock before namespace entry and transfers only those held executable capabilities to the refresh thread, which executes them by descriptor (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Native creation reserves and finishes worker mail lifetimes beneath configuration and storage descriptors verified before namespace entry; its bundle retains the letter directory, any already-open rotation source, and credential refresh executables (``prob:homes:ancestor-trust-resolves-the-namespace-uid-map``).

- Authenticated compute-shaped requests receive their deadline announcement before admission, including route and root-registration refusals, so the stub retains the named refusal through admission and record waits (``prob:door:compute-stub-first-wait-covers-admission``; ``proto:superlooplane:compute-deadline-and-evidence``).

- A valid RUN-REPORT that disagrees with node measurements refuses as `door-compute-report-contradiction`, and a present report with an absent or invalid wall or exit as `door-compute-report-refusal`; replies retain the report's parsed wall and exit in `run_report` beside the node measurements, and missing node evidence keeps `door-compute-evidence-refusal` (``prob:door:run-report-contradiction-is-named-apart-from-missing-evidence``; ``proto:superlooplane:compute-deadline-and-evidence``).

- Door store contention receives bounded, measured deadline credit in the service and matching stub, with cumulative wait frames and reply figures; a two-requester regression pins pending custody and the existing unlocked agent-judgement boundary, without attributing the historical long custody hold to the agent (``prob:door:request-record-lock-released-before-triage``; ``proto:superlooplane:request-lock-wait-credit``).

- Mount, network, door-shape and door-attribution exercises retain their protected reservation’s selected executable and hashing custody through namespace entry, refusing changed records, programs and descriptor declarations (``proto:workercontracts:namespace-anchor-handoff``).

- Runtime preparation carries its configuration, worker storage and executable capabilities across namespace entry, verifies the native lifetime beneath held storage, and previews the bundle without requiring provisioned private paths (``proto:workercontracts:namespace-anchor-handoff``).

- Compute completion retains the node-measured wrapper wall and child user/system CPU even without a RUN-REPORT line; a present contradictory report refuses by name. Schema-six request custody uses the explicit rewrite for older records, preserving their walls with unmeasured CPU. The historical deployed null-wall observation has not been remeasured (``prob:door:door-compute-wrapper-wall-measured``; ``proto:superlooplane:compute-deadline-and-evidence``).

- Release refuses a non-string declared public version in Cargo repositories before check, dry-run or apply can proceed, retaining destination refs, objects and worktree (``prob:pack:release-refuses-a-non-string-public-version``).

- Container helpers retain host-verified entry, Podman and hashing file custody across namespace entry and execute protected-plan hashes, attempts and cleanup through held descriptors; the bundle refuses missing, substituted and excess descriptors and changed declarations (``proto:workercontracts:namespace-anchor-handoff``).

- Route documentation distinguishes the door registration route, the registry-only check-mode finding and every empty artifact rendered for retired routes (``proto:superlooplane:door-node-registration``; ``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- Worker custody entry keeps consumed stdin bound to the null device and refuses non-UTF-8 launcher paths without lossy conversion; capability duplication failures name their system cause as `anchor-io` (``proto:workercontracts:namespace-anchor-handoff``).

- The two-account mail fixture leaves coordinator verification to the rootless worker acceptance, which checks unchanged verification and missing-lock refusal through the production descriptor handoff instead of an obsolete private invocation (``proto:workercontracts:namespace-anchor-handoff``).

- Worker-run birth and retirement and native lane retirement carry configuration, storage and executable custody through namespace entry and identity children; the runner retains only declared descriptors, and native retirement preserves its bounded command handling (``proto:workercontracts:namespace-anchor-handoff``).

- Cut and replay projection batch blob reads, object hashing and index updates per tree instead of spawning Git per file, preserving binary contents, path spelling, symlinks and modes; real Git traces pin the bounded process counts (``prob:pack:replay-projection-spawns-git-per-file``).

- Interrupted request rewrites can renew their helper snapshot after a concurrent helper arrival, requiring a new preview digest while retaining the original custody plan and preserving unrelated helper requests (``alg:superlooplane:request-schema-rewrite``).

- Anchor refusals retain the caller operation, failed custody or transport check and configuration parser cause; writable ancestors refuse as mode failures and system failures retain their errno (``req:workercontracts:namespace-anchor-refusals``).

- Mail startup carries verified configuration and executable descriptors through namespace entry, reads settings, ledger and registry beneath the held configuration, and preserves named capability and identity-drop refusals; scan-time configuration reads retain that anchor (``req:workercontracts:namespace-anchor-acceptance``).

- Host rubric and sign-in source walks validate the initial UID map and reject unrelated nobody ownership, including sticky ancestors, while retaining explicit owner and loop grants (``req:workercontracts:namespace-anchor-authority``).

- Citation planning bounds each linter invocation and both output streams to 120 seconds, killing its process group and reaping its leader on timeout while retaining diagnostics and refusing before publication; real-process and built-binary regressions pin cleanup and unchanged destinations (``prob:pack:cut-linter-invocation-time-bound``).

- Door agent calls give Codex sibling private configuration and temporary directories, keeping its home outside the child temporary root and removing both after reaping (``prob:door:door-agent-codex-home-outside-temp``).

- Cuts refuse a selected owner snapshot carrying an `unpublished` field when the publication manifest has no register declaration, preventing unaudited register publication and dangling snapshot references (``prob:pack:manifest-declares-the-unpublished-register``).

- Registered state-root ownership refusals name the state root instead of the loop registry; mapped request fixtures assert the custody root and both uids (``prob:door:two-uid-fixtures-assert-owner-mismatch``).

- Runtime rubric admission compares the effective uid with the real entered uid, restoring refusal of entries that change only the effective uid (``proto:superlooplane:bounded-rubric-judgement``).

- Custody readers compare the complete mode with the named read/search ACL mask for private files, the registry, loop tiers, settings and transferred configuration locks, refusing ordinary group grants and widened masks; fixtures also preserve the ledger readers’ ACL contract (``prob:homes:exact-mode-readers-reason-about-the-acl-mask``).

- The route-rendering contract names the owner-side Codex home as the destination for door-only loops and distinguishes it from the canonical credential source (``prob:homes:render-routes-codex-home-from-custody``).

- Standalone route rendering refuses an absent loop before publication while retaining empty node sections for retired routes; fixtures pin missing-key refusal without active routes and preserve home contents across registry refusals and route reactivation (``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- Codex reconciliation collapses identical complete generated SSH headers to one, preserves owner comments and refuses conflicting or incomplete duplicate headers (``prob:homes:reconciled-ssh-config-header-written-once``).

- Codex home preparation and reconciliation select the loop’s active registry routes when no nodes are named, while an explicit node list remains the selection override (``prob:homes:codex-reconcile-resolves-nodes-from-routes-row``).

- Sign-in home checks resolve the loop’s active registry rows when no nodes are named, preserving explicit subsets and reporting registry failures without changing the home (``prob:homes:check-signin-home-resolves-active-registry-rows``).

- Sign-in homes prepare and reconcile an empty node section when the loop has no active routes, report the observation, and retain credentials, worker-key bindings and unrelated SSH stanzas (``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- The empty-route home fixture declares its executable dependency in the build ledger, including the shifted call-site identities (``prob:homes:home-preparation-admits-a-loop-with-no-active-route``).

- Registry path admission and worker-identity refusal text share component-fault classification, preserving dot-component precedence and accepted path forms (``prob:homes:routes-worker-form-shares-path-component-predicate``).

- The shared route-path classification test carries the inventory label derived from its function name (``prob:homes:routes-worker-form-shares-path-component-predicate``).

- A registered Git receive can complete beside its box’s running compute request while same-class requests and other operations retain bounded admission exclusion (``rule:superlooplane:door-request-admission``).

- Deferred list rewrites remove complete dotted stale-family and singleton assignments; rendered TOML is parsed before replacement, so active dotted-singleton duplication refuses without changing the source (``prob:linter:deferred-writer-parses-its-output-before-replacing``; ``prob:linter:deferred-mode-rewrite-keeps-a-stale-catalogued-table``).

- Folder-matrix checks and writes ignore cell padding and valid table delimiter layout while preserving exact cell content, row identity, order and count; equivalent layouts remain unchanged, while a tab anywhere in a delimiter row and an empty delimiter cell remain stale, matching the formatter’s space-only delimiter grammar (``prob:linter:matrix-comparison-normalises-cell-layout``).

- Claim projections stop the introductory gloss at the first trimmed level-one rustdoc heading, leaving section headings and bodies out of test-index and folder-matrix cells (``prob:linter:claim-extractor-stops-at-rustdoc-sections``).

- Request-list contention refusals add listing-level elapsed time; regressions pin the shared deadline at a contended second acquisition and include helper state in read-only snapshots (``rule:superlooplane:requests-list-contention``).

- The door rubric check admits the caller’s service uid alongside root and the loop uid at install and runtime; a mapped non-root service fixture verifies distinct loop custody and foreign-owner refusal (``prob:door:door-rubric-custody-admits-service-uid``; ``proto:superlooplane:bounded-rubric-judgement``).

- The shared request reader rejects upload bounds and output counts on preflight refusal records (``conv:superlooplane:door-transport-compatibility``).

- Tools packs classify their generated provenance as an optional exact publication member; a fresh pack audit against the supplied 41-entry estate register measures zero occurrences and zero owed debt (``prob:pack:tools-tree-burn-register-matches``).

## [0.4.1] - 2026-11-06

### Changed

- Regression coverage verifies that 24 repeated learned door decisions retain their adjudicated allow and execute once per request without calling an agent; attribution of the historical excess wall remains open (``prob:door:learned-hit-judgement-wall-after-bite-6``).

### Fixed

- The region-reader catalogue classifies a terminal `.j2` template by its inner file kind and treats a `LICENSE-AGPL_3_0` licence notice as opaque (``prob:linter:region-reader-catalogue-gains-j2-and-the-agpl-text``).

- To-do derivation excludes the header's ownership citation from the summary and name, preserves it through label insertion and repair, and leaves summary citations unchanged (``prob:linter:todo-derivation-keeps-the-ownership-slot``).

- Reach reconciliation supplies self and the crate-bearing root without declared rows, refuses redundant structural-root rows, and preserves explicit reach to a crateless root (``prob:linter:reach-reconciliation-supplies-the-structural-root-like-self``).

- Catalogued burn policies accept exact ABNF exclusions on their owner surfaces, retain derived share exclusions, and report the paths excluded from both prose and code censuses (``prob:linter:catalogued-burn-families-accept-an-exclude-relation``).

- Pack verification declares and probes its unzip prerequisite, refusing ``unzip_unavailable`` before extraction when it cannot run; deployment names the prerequisite as a requirement independent of build placement (``prob:pack:stage-verify-declares-its-extraction-dependency``).

- List rewrites retain active family containers, remove stale singleton and family entries beside deferred bytes, and canonicalize inline owners without duplicate keys in either mode; malformed rewrite sources refuse without writes (``prob:linter:deferred-mode-rewrite-keeps-a-stale-catalogued-table``).

- Nested corpus roots require tracked ownership metadata before loading their snapshot, and a failed tracked-file census names its own refusal (``prob:linter:nested-root-with-no-tracked-paths-is-accepted-vacuously``).

- Publication tests compare author, committer and tagger instants as epoch seconds, also checking stored offsets and the reported date across Git date renderings (``prob:pack:cut-acceptance-compares-epoch-seconds``).

- Sign-in home tests pin the check-mode registry user refusal without writes and bind reversed host selections to each worker stanza (``prob:homes:registry-node-user-refusal-check-mode-test``; ``prob:homes:codex-home-hosts-test-pins-stanza``).

- Request listings share one bounded lock-acquisition deadline across reads and name the elapsed wait and retry remedy on contention expiry, without changing request records (``rule:superlooplane:requests-list-contention``).

- The door attribution probe shares a 55-second budget from its main function across calls and retries, caps stub calls at 35 seconds and receive at 15 seconds within the remaining budget, and names top-level timeouts while leaving missing observations unmeasured (``proto:superlooplane:registered-ssh-transport``).

- The door's direct policy publication reads the loop registry through the ACL mask that mail provisioning leaves on it, so the door publishes its policy after the cutover (``sec:loophome:mail-migration``).

- The door's tier custody check compares the private and direct tier modes through the ACL mask that mail provisioning leaves on the private tier, so the policy publication passes its custody check after the cutover (``sec:loophome:mail-migration``).

## [0.4.0] - 2026-11-05

### Changed

- Installed worker instructions use the mounted mailbox, name its submission grammar and verified steering rule, and distinguish the initial brief and inert legacy slots (``prob:mail:confined-box-mount``; ``prob:mail:legacy-entry-retirement``).

- Round previews refuse missing or drifted birth metadata, configuration state and mailbox grants without creating or repairing them (``prob:mail:round-transport-over-mail``).

- Worker preparation publishes its claim watermark atomically under the run-table lock so interrupted writes preserve rebirth capacity (``prob:mail:worker-birth-in-the-lane-launcher``).

- Migration documentation assigns worker mailbox instructions to the instance's held cutover documents, outside the migration command (``prob:mail:migration-command``).

- Mail migration snapshots and parks only mail configuration, restoring private configuration ancestors by metadata while credential siblings remain in loop custody (``prob:mail:migration-command``).

- Entry dispatch exposes its intercepted-word inventory, live capture documentation is retained, and follow drops obsolete zero-valued correspondence cost fields (``prob:mail:legacy-entry-retirement``).

- Round previews verify retained mail pins without publication, admission waits for bounded pin writers, and the estate pin projection has its own 1 MiB implementation bound (``prob:mail:round-transport-over-mail``).

- Inbox presence checks report unavailable folders through the existing fail-open path, and ordinary waiting refuses an unavailable inbox (``prob:mail:notice-and-ordinary-waiting``).

- Mail directory overflow identifies the registry or allocations metadata instead of blaming the submitted letter (``prob:mail:delivery-core-and-user-unit``).

- Worker preparation retains a unique claim stamp across retirement, and mail compaction releases deregistered-loop pins while projecting inventory pins from its single record read (``prob:mail:worker-birth-in-the-lane-launcher``).

- Mail migration inventories legacy stores and retained run evidence, relocates worker execution homes, preserves opaque history with restartable manifests, and holds activation behind verified deployment and rollback boundaries (``prob:mail:migration-command``).

- Retired mail custody remains service-recoverable after UID release, while unavailable active endpoints retain their inbox evidence (``prob:mail:worker-birth-in-the-lane-launcher``; ``prob:mail:delivery-core-and-user-unit``).

- Ordinary loop entry no longer dispatches legacy letters commands; worker follow retains event evidence without reading correspondence sidecars, and initial briefing is an immutable input outside mail (``prob:mail:legacy-entry-retirement``).

- Resumed rounds bind service-verified mail before authorization, retain exact delivery bytes for step evidence, and release journal pins on retirement; reply settlement consumes verified worker-to-loop mail and the legacy round-letter commands are retired (``prob:mail:round-transport-over-mail``).

- Mail hooks expose only the arrival notice from inbox presence, and ordinary filesystem waiting arms before listing and reconciles every wakeup without reading letters (``prob:mail:notice-and-ordinary-waiting``).

- Box launches bind only their worker mail folder read-write at /mail, identify it through SUPERLOOP_MAIL, and include its service ownership and worker binding in confinement checks (``prob:mail:confined-box-mount``).

- Delivery reports an oversized loop configuration as invalid-directory, preserving oversize for letter admission (``prob:mail:delivery-core-and-user-unit``).

- Worker launch refusals name mail provisioning and legacy-home relocation, and protected receipt reads have a 4 KiB implementation bound (``prob:mail:worker-birth-in-the-lane-launcher``).

- Worker retirement transfers retained mailbox custody to the service before releasing the UID, and worker-run close serializes retirement against launch while retaining names (``prob:mail:worker-birth-in-the-lane-launcher``).

- Worker creators reserve immutable mail identities before home creation, publish only complete endpoints and retain retired names and UID receipts across retries and replacement (``prob:mail:worker-birth-in-the-lane-launcher``).

- Lane preparation accepts the preserved service search ACL, and delivery retries contended loop configuration without blocking other loops (``prob:mail:loop-mail-at-birth``).

- Mail scans isolate unavailable actors, bound loop configuration reads and install a refusal-aware user unit in the user data search path (``prob:mail:delivery-core-and-user-unit``; ``prob:mail:loop-mail-at-birth``).

- Mail provisioning pins its helper image and enters the private working directory before dropping credentials, preserving access beneath a private host-home prefix (``prob:mail:loop-mail-at-birth``).

- Explicit loop provisioning stages isolated mail folders and creates loop-owned routing configuration while preserving existing bytes, retained names and service ACLs on retry (``prob:mail:loop-mail-at-birth``; ``prob:mail:mail-configuration-never-shares-the-registry-file``).

- The host-session mail core serializes opaque delivery, fresh loop-owned routing decisions, durable refusal projection and capacity-aware recovery; its user unit enters the existing subordinate namespace without enabling itself (``prob:mail:delivery-core-and-user-unit``).

- Mail completion clears resolved transport errors and measures retention age from the latest known instant so clock rollback postpones pruning without permanent pins (``prob:mail:journal-records-recovery-and-retention``).

- Mail publication syncs protected snapshots before acceptance, publishes inbox bytes by one no-replace rename, and recovers through journal witnesses and restartable source restoration without redelivery (``prob:mail:journaled-inbox-publication``; ``req:mail:inbox-publication``).

- Mail persistence protects delivery records and UTC reservations, derives recovery from publication witnesses, and bounds retained history with pinned evidence and restartable compaction (``prob:mail:journal-records-recovery-and-retention``; ``req:mail:records-recovery-retention``).

- Registry, worker allocation and mail parsing share the identity production, with leading hyphens refused, command words admitted as names and storage failures separated from syntax (``prob:mail:name-grammar-alignment``; ``reg:mail:identity-names``).

- Door admission waits up to 30 seconds within the request deadline before refusing concurrency, reports the actual wait and a 30-second retry recommendation in JSON and stderr, and admits requests when the held guard clears (Door request admission, ``rule:superlooplane:door-request-admission``; capability mediation (`rule:workercontracts:capability-mediation`)).

### Fixed

- The migration census binds a retired worker home to its inode alone, because the anonymous device numbers of btrfs subvolumes change across mounts while inodes stay (``sec:loophome:mail-migration``).

- The ancestor-trust checks of the allocation ledger, the workers settings and the runs root accept the overflow uid that an unmapped root shows inside a user namespace, so the migration can read the ledger it freezes as namespace root (``sec:loophome:mail-migration``).

- The private protected-file reader compares the mode through the ACL mask that mail provisioning leaves on the registry and the ledger, so the door install runs after the cutover (``sec:loophome:mail-migration``).

- The namespace-root migration fixture writes its ledger, registry, service settings and home with the real estate's modes (``sec:loophome:mail-migration``).

- Driver launch opens step letters without following symlinks or blocking on special files, and names `--step-letter` and its path in refusals (`rule:workercontracts:launch-and-evidence`).

- Document that compute store writers, including the admission record, retry against the compute request's own 1,800-second deadline (`rule:workercontracts:capability-mediation`).

## [0.3.2] - 2026-11-02

### Fixed

- Round launches retain the selected letter text beside the pointer brief for both driver backends, including resumed and threadless continuations; retries preserve the pointer input (`rule:workercontracts:letters-and-retention`).

- Replay attributes unparseable public root metadata to its input context before refusing (`req:output:failure-class-naming`).

- Replay author examples use the same double-quoted identity as cut (`spec:outputspec:command-and-output-contracts`).

- Release refuses conflicting public and Cargo workspace versions, naming both declarations (`rule:commandcontracts:public-release-version-agreement`).

- The 0.2.0 release notes have one dated section listing each entry once, every entry citing its contract label, so release-note selection is unambiguous (`rule:commandcontracts:public-release-version-agreement`).

- Door writers retry contended record locks until the request deadline, retain completed effects across a sibling's longer record hold, and report lock wait time and known holder identity in the service journal and worker refusal (`rule:workercontracts:capability-mediation`).

- Door records retain the base writer wait after their request deadline, connection refusals disclose only typed lock contention, and request-scoped wait diagnostics distinguish retry expiries from final timeouts (`rule:workercontracts:capability-mediation`).

- Release honors Git’s merge and tag signing switches, reports preview signing intent and final object identities, and refuses signer failures before moving refs (`rule:commandcontracts:public-release-signing`).

- Release signing declares its disposable GPG test dependencies, cleans fixture agents and socket directories on every exit path, names signer failures, and checks unsigned object shapes before promotion (`rule:commandcontracts:public-release-signing`).

- The release unsigned-shape test name agrees with its inventory label, keeping the candidate linter gate enforceable (`rule:commandcontracts:public-release-signing`).

- Disposable signing-home cleanup diagnostics use the explicit stderr writer required by the workspace gate (`rule:commandcontracts:public-release-signing`).

## [0.3.1] - 2026-11-02

### Added

- The public-set manifest accepts an optional `[public] version = "X.Y.Z"`, the repository's release version, distinct from the manifest-format `version`; every manifest reader refuses a malformed declaration.

### Changed

- `superloop-pack release` takes the release version from the Cargo workspace manifest's `[workspace.package] version` when development carries one, and otherwise from the manifest's `[public] version`; it refuses `version-missing` when neither is declared and reports the selected `version_source`.

## [0.3.0] - 2026-11-02

### Added

- The digest specification (`spec:digests:handles-and-bindings`) distinguishes digest handles, 16-hex-digit prefixes of the full digest sized against a declared collision budget, from cryptographic bindings, which keep the full digest and state the forgery they prevent, the trusted reference and the actor-controlled side; it installs with the other specifications.

- The digest specification inventories each digest use by package, file and line as a binding or a handle, and names the unstated protections and the handle migrations that need coordinated reader changes.

- `superloop-pack replay` reports burn matches as pre-existing when the matched value already occurs in the public root at the same path or corresponding metadata field, allowing already-public history to replay while refusing introduced values.

- `superloop-pack replay --author "Name <addr>"` sets every replayed commit's author and committer identity while preserving source dates; the private report records the mapping and source metadata remains subject to burn checks.

## [0.2.0] - 2026-11-02

### Added

- `build-sync census` reads explicit ledgered installation maps and document roots; `--installations-only` checks document repositories without Cargo metadata (`rule:buildcontracts:installation`).

- `superloop-pack replay` projects linear source history onto an existing public development branch, preserving commit metadata and skipping unchanged public trees. Each source commit uses its own manifest, bounded by the tag's final public policy; missing historical manifests, README sources and licences refuse. The entire range is preflighted against the external burn register before destination writes; refusals name their check, source ordinal and commit, and path or field, and retain a private refusal record and diagnostic scratch (`rule:buildcontracts:repository-boundaries`).

- `superloop-pack release` validates a pinned public development tree and creates an unsigned merge and annotated version tag in one expected-old transaction advancing main and development, with check and dry-run reports and an explicit three-ref push allowlist (`rule:commandcontracts:public-release-version-agreement`).

- `superloop-lint` reports `inactive_prose_owner`: a declared owner whose partitions attribute Markdown sources but which activates no `labels.mints-well-formed` row, because such an owner's prose silently left the corpus and read like a clean result (`rule:lintcontracts:ownership`).

- `superloop-lint` accepts `nested = [{ owner, root, reason }]` in the owner declarations for a nested corpus checked as its own repository; the loader refuses an unregistered owner, a root outside the owner's partitions, a root without a loadable linter snapshot, or an empty reason (`rule:lintcontracts:ownership`).

- `superloop-lint` defers an activated pair whose row names a repository-local programme (`programme = { package, binary }`) instead of refusing an uncatalogued policy; the report gains `deferred` and `deferred_policies`, the pair's list table is accepted by shape, and `clean` stays the catalogued policies' verdict (`rule:lintcontracts:verdicts`).

- `superloop-pack cut` takes the default annotated tag title from the manifest's required `[public] name` (`NAME TAG`, then the CHANGELOG section body; `--tag-message` overrides verbatim), and the shared reader refuses a blank or multi-line name (`rule:buildcontracts:build-provenance`).

- `superloop-pack cut` and the linter's `public_set` check refuse an include row that selects the root README while `[public] readme` names a different source, naming the selector to turn into an exclusion with a reason (`rule:buildcontracts:repository-boundaries`).

### Changed

- `superloop-pack cut` retains the historical snapshot and the linter's output when `citation-sites` refuses, and names the retained directory in the refusal (`req:output:report-path-validity`).

- Private architecture, runbooks and linter design history leave the tools tree together with their ownership and prose inventory; public projections and the empty label register remain checked, and consumer-generated lockfiles remain local build inputs (`spec:lintcontracts:linter-contracts`).

- Public tools now carry their README and reusable worker, command, linter and build contracts directly; operational history and instructions are served by the instance publication (`spec:workercontracts:worker-boundaries`).

- Tools installations retain public specifications and executable identities while instance-owned maps, wrappers and the runtime unit leave the tools build (`spec:buildcontracts:build-and-installation`).

- Sign-in home commands accept `--charter PATH`, default to the instance worker-charter publication, refuse unavailable inputs before changing a home, report the resolved path, and reconcile existing Codex charter links (`rule:workercontracts:launch-and-evidence`).

- The unresolved-import finding names the owner and prefix it searched, and says when the owner activates no `labels.mints-well-formed` row (`rule:lintcontracts:references`).

### Fixed

- Nested-root containment is judged against the tracked universe, so an untracked or ignored file under a nested root no longer refuses the declaration (`rule:lintcontracts:ownership`).

- A burn or lower rewrite of the list declarations keeps the bytes and position of list tables deferred to a repository programme (`rule:lintcontracts:maintenance`).

- A `programme` row checked outside a Git checkout refuses with a message naming the programme check and its reason (`rule:lintcontracts:verdicts`).

- The pack's real-linter fixtures activate their prose, so the fixtures pass the `inactive_prose_owner` finding (`rule:lintcontracts:ownership`).

## [0.1.0] - 2026-10-12

### Added

- `superloop-lane` and `superloop-gate-submit` for running worker lanes and checking changes before integration.
- `door-ssh` and `door-service` for mediating command execution.
- `build-sync` and `superloop-install` for staging build outputs and installing declared releases.
- `superloop-lint` for checking repository documentation and declarations.
- `superloop-pack` for publishing selected source trees with independent Git history.
- `superloop-steward` for polling transcripts and reporting work progress.
- `superloop-claude-hook` and `permission-triage-hook` for handling harness events and command permissions.
- GPL-3.0-or-later code and CC0-1.0 documents, with no backwards compatibility before 1.0.

[Unreleased]: https://github.com/coraxloop/superloop-tools/compare/v0.13.3...HEAD
[0.13.3]: https://github.com/coraxloop/superloop-tools/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/coraxloop/superloop-tools/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/coraxloop/superloop-tools/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/coraxloop/superloop-tools/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/coraxloop/superloop-tools/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/coraxloop/superloop-tools/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/coraxloop/superloop-tools/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/coraxloop/superloop-tools/compare/v0.8.2...v0.9.0
[0.8.2]: https://github.com/coraxloop/superloop-tools/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/coraxloop/superloop-tools/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/coraxloop/superloop-tools/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/coraxloop/superloop-tools/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/coraxloop/superloop-tools/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/coraxloop/superloop-tools/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/coraxloop/superloop-tools/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/coraxloop/superloop-tools/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/coraxloop/superloop-tools/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/coraxloop/superloop-tools/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/coraxloop/superloop-tools/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/coraxloop/superloop-tools/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/coraxloop/superloop-tools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/coraxloop/superloop-tools/releases/tag/v0.1.0
