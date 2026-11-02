# Worker boundaries · `spec:workercontracts:worker-boundaries`

These contracts keep a worker's mutable task state separate from the authority that launches, observes and admits its effects. Instance registries supply identities, roots and deployment choices.

**Rule (Launch and evidence)** · `rule:workercontracts:launch-and-evidence`

A worker consists of the selected agent executable and its descendants in one disposable home and confinement boundary. Its runtime, executable, policy, charter and identity are fixed at launch. The driver and its durable evidence directory remain outside that boundary. The worker cannot write or replace captured events, lifecycle markers, wall measurements, exit observations or termination evidence. A worker report is evidence to review, not authority to declare the driver's result. A resume retains the same home, driver directory, template, identity, image and mounts and substitutes the pinned program's resume form and recorded thread identifier. Launch probes must measure real start, refresh and resume with that pinned program.

The declared mount set contains only the home, runtime and explicit executable, policy, credential and capability mounts. Protected inputs resist replacement through every worker-reachable ancestor. Host management sockets, the session bus, host filesystem portals and the container-engine socket are absent. A launch requiring full access refuses before reservation unless its gate proves dropped capabilities, no new privileges, the declared user namespace, read-only root and templates, writable worker-owned leaves only, and the declared network route. A failed command does not authorize widening the boundary.

**Rule (Provisioning and settings)** · `rule:workercontracts:provisioning-and-settings`

The instance registry grants the loop identity and door floor; the allocation ledger grants its worker identity range. Engineering settings describe how to carry those grants out and cannot widen either. Missing or invalid registration, allocation or required settings refuses the dependent operation by name. Provisioning derives only what the grant authorizes; vendor sign-in renewal and a new host harness registration remain separate authority inputs.

Worker settings are owner-owned mode 0600 beneath an owner-owned mode-0700 configuration directory. Readers walk components without following links, open once with no-follow, and verify regular-file type, ownership and exact mode from the descriptor before parsing its bytes. Readers refuse replaceable ancestors, malformed settings, relative or nonexecutable program paths, stale image digests and identities or modes outside the registry grant before launch. Image and template manifests bind the runtime, executable, helper, charter, policy and source digests. A run pins immutable template children; updating a selector affects future runs and retains inputs still used by live runs.

`make-home` creates protected inputs and worker-writable leaves from the pinned template and bound sources; `plan` only reports. Shared sign-in homes are prepared and checked separately from disposable run homes. Worker harness hooks belong to the prepared home. A home contains routing but no private SSH key, disables signing, and preserves only declared outputs at collection.

**Rule (Credentials and egress)** · `rule:workercontracts:credentials-and-egress`

Credentials follow the identity they authenticate. Loop-private credentials are loop-owned mode 0700; credentials read by owner-run drivers remain in an owner-owned mode-0700 tier. Workers bind their own loop's vendor sign-in directory, never the supervising session's sign-in or a copied credential in the disposable home. Binding the directory preserves visibility of an atomic credential replacement. Concurrent safety requires measurements of overlapping writes and refresh visibility; synthetic custody and locking tests cannot prove vendor token rotation semantics. Rotation probes cover both sequential orders, interleaving, atomic-save preservation and expiry reload, recording identities, times and outcomes without secret bytes.

The vendor proxy admits only exact configured hostnames justified by observed pinned start, refresh and resume. It rejects wildcards, IP literals, other targets and private or reserved resolved addresses, resolves upstream itself, and records destination, byte counts and wall. A newly required host remains refused until the declared set changes. Non-vendor outward work uses the registered capability door. Remote effects remain bounded by the remote account's permissions and server policy: a local socket does not confine the remote account.

**Rule (Letters and retention)** · `rule:workercontracts:letters-and-retention`

Each round's inbox letter defines its task and its outbox reply is the reply of record. Later letters are ordered, acknowledged before the next command, and answered in that reply; a stop letter ends the round through its normal report. The driver lists escaped names, sizes and times without reading letter contents during a round, publishes those listings before the terminal report, and preserves the worker event stream unchanged. Readers consume letters in round order before event deltas.

Durable records are retained by default and cannot be pruned while an import needs them. Rotation occurs at a declared threshold below the context limit, with a stop letter and a new thread carrying the prior replies. Before collecting a home, settle execution, preserve both mailboxes and source bares, and prove the preserved lane ref equals the exact successfully tested ref. A local bare within a disposable home is not durable preservation. Early collection requires explicit abandonment.

**Rule (Capability mediation)** · `rule:workercontracts:capability-mediation`

The capability door comprises an SSH stub, a bound Unix socket and a service outside the worker boundary. Launcher registration selects the loop, run, roots and evidence destinations; the request cannot select keys or private roots. The service validates registration, caller identity, registered scope and transport before judgement. Unknown in-scope command shapes reach judgement and do not become preflight refusals merely because no known shape matches. Structural parsing preserves words, verbs, options and operands, including bounded compound recipes, so a required correction can name the actual effect.

The service records the request, deciding tier, mode, proposed treatment, adjudicated evidence, effective outcome and wall. It preserves long bidirectional streams, disconnects, exit status and the whole-request deadline. Mediation time and remote execution time are distinct evidence. Git mirroring is limited to the registered lane ref; agreement with the local ship precedes import. Neither an admission nor an adjudicated label proves remote completion.

**Rule (Bounded judgement)** · `rule:workercontracts:bounded-judgement`

An undecided request may receive one bounded model call from an empty private directory with the loop's sign-in and no execution tools. Its inputs are the request, capability class, structural observations and reviewed rubric; it never reads the worker home. The result is exactly one object with `verdict`, `scope` and nonblank `reason`; verdict is `allow`, `refuse` or `refer`, and scope is `loop` or `estate`. Failed calls, invalid output and timeouts yield a distinct service referral, never allowance. The cap fits within remaining request time with cleanup reserved, and the caller terminates and reaps the process within that bound. Expiry grants no effect.

The rubric is reviewed instance data with a recorded digest. Requests, worker text and remote output are evidence, not instructions that can replace it. Adjudicated labels answer their bound request and are data for subsequent learning. Mode changes record authority, floor and evidence: stricter treatment is available immediately, relaxation stays within the authoritative floor, and crossing that floor requires a changed grant. A wrong enforcing rubric returns to audit. Settings and model judgements cannot supply that grant.

**Rule (Measured boundary acceptance)** · `rule:workercontracts:boundary-acceptance`

An exercise records pre-state, effects, observations, wall and result. Success requires the named observation; an absent measurement is not success. Negative probes attempt evidence replacement, protected-ancestor replacement, undeclared mounts, direct egress, unregistered compute and resource-limit escape, and verify that stopped descendants are reaped. Credential probes use real pinned start, refresh and resume without revealing credentials. Harvest probes compare preserved and tested object identities and leave the home intact on disagreement. Read-only planning and effectful exercises retain distinct interfaces.

**Rule (Run observation and gate completion)** · `rule:workercontracts:run-observation`

A gate binds its result to the exact source object and retained log. A launcher keeps the driver directory and reports the actual command, status and wall after observing completion. Long remote rounds retain their PID, log and terminal marker; a detached round is awaited through a foreground PID-bound log reader, and an interrupted connection resumes that same wait. Silence, transport loss and an admission verdict do not establish completion. Instance publications provide the operational gate and lane recipes.

**Rule (Registered node routes)** · `rule:workercontracts:node-routes`

A node route is selected from the deploying instance's authenticated registration. Callers use the declared alias and confined account, retain the selected route in evidence, and refuse missing registration. The route grants neither ambient host access nor authority beyond the registered remote scope.

**Table (Loop roots)** · `tab:workercontracts:loop-roots`

Roots derive from the caller's home and the registered loop name and identity. The owner is the provisioning principal; the loop UID and GID are interpreted in the entry's namespace. Checked-only class roots must already have the required ownership and traversal. Custody is selected only when its private tier exists, so ensuring a home never fabricates credentials. Protected owner directories keep the loop from replacing another principal's policy or evidence.

|Path|Owner|Mode|Ensure step|
|----|-----|----|-----------|
|`~/.var/`|owner|0711|Checked, never created or changed.|
|`~/.cache/`|owner|0711|Checked, never created or changed.|
|`~/.var/loops/`|owner|0711|Created and checked.|
|`~/.var/loops/<loop>/`|owner|0711|Created and checked.|
|`~/.var/loops/<loop>/private/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.run/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.config/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.config/custody/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.ssh/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.local/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.local/bin/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.local/share/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/private/.local/state/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/shared/`|loop uid|0750|Created and checked.|
|`~/.var/loops/<loop>/src/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/direct/`|loop uid|0700|Created and checked.|
|`~/.var/loops/<loop>/policy/`|owner uid, loop gid|02750|Created and checked.|
|`~/.var/loops/<loop>/runs/`|owner|0711|Created and checked.|
|`~/.config/loops/`|owner|0700|Created and checked.|
|`~/.config/loops/<loop>/`|owner|0700|Created and checked.|
|`~/.config/loops/<loop>/lanes/`|owner|0700|Created and checked.|
|`~/.config/loops/<loop>/lanes/keys/`|owner|0700|Created and checked.|
|`~/.config/loops/<loop>/private/`|loop uid|0700|Checked when present, never created.|
|`~/.config/loops/<loop>/private/ssh/`|loop uid|0700|Checked when the tier is present.|
|`~/.config/loops/<loop>/private/gpg/`|loop uid|0700|Checked when the tier is present.|
|`~/.config/loops/<loop>/private/gh/`|loop uid|0700|Created empty and checked when the tier is present; existing contents are preserved.|
|`~/.cache/loops/`|owner|0711|Created and checked.|
|`~/.cache/loops/<loop>/`|loop uid|0700|Created and checked.|
|`~/.cache/loops/<loop>/tmp/`|loop uid|0700|Created and checked.|
