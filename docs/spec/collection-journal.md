# Collection journal: bounded request work · `proposal:collectionjournal:bounded-request-work`

This staged design makes a request-lock hold cost the rows it touches rather than the collection's history. It separates local optimizations that preserve the format and helper protocol from later protocol, storage, retention and notification changes. Stage descriptions are design requirements, not a claim that every stage or command is implemented; the linked backlog items carry their implementation status.

## Measurement basis · `sec:collectionjournal:measurement-basis`

The source census is anchored at tools commit 803d6bdf. Source locators below refer to that baseline unless a later implementation is explicitly named. Measurements dated 2026-11-14 use a synthetic approximately 21 MB one-line snapshot and a live journal of 21,114,757 bytes. The live population contains 6,977 after-effect rows and seven before-effect rows, with no permission or gateway rows; all three non-audit classes are in use. A synthetic acceptance also includes permission rows and legacy lines, because those exercise authority, preservation and legacy-merge paths absent from that population.

A policy publication reads the collection to evaluate effective modes; it does not rewrite the collection journal. Owner commits rewrite the journal. With three non-audit classes, the baseline filing performs eleven owner reads: the run read, mode check, capacity inventory, before and after inventories, and two publications with three class inventories each. Effects perform ten reads, waiting publication nine and explicit policy publication three. A one-class fixture understates this multiplier.

The baseline contains linear searches inside loops in lane triage, helper owner merge, publication validation, gateway authority, permission authority, disposition append and legacy merge. Validated collections refuse duplicate identifiers, so per-call indexes can replace these searches while retaining row order, results and exact errors. A matched-byte comparison with different row counts is load-confounded and cannot establish a scaling coefficient.

The 2026-11-14 field readings put helper parsing near 1.9 s per whole read and lane inventory work near 2.2 s per call. Filing holds were 42–49 s, effects 38–43 s, waiting publication 34–36 s and explicit policy publication 10.7 s. These are workload observations, not latency guarantees; filesystem, cache state, row mix and load differ between fixture and field. The estimates below use those baseline observations. Exact read counts are the deterministic acceptance.

## Slice A: publish once, inventory once per publication, index by identity · `sec:collectionjournal:slice-a`

Implementation status and remaining work: (`prob:door:door-parts-contend-for-the-request-lock-within-one-request`).

Scope, in two packages, with no format, protocol or reader-floor change:

1. **One inventory per publication.** Split ``effective_locked`` (``store.rs:827-855``) into a pure part that takes the already-read rows and a reading wrapper. ``publish_snapshot_locked`` (``snapshot.rs:196-215``) reads ``all_runs(None)`` once, and only if any class with a loop setting is not audit. It then evaluates every class against those rows. Single-class callers keep their one inventory: ``effective_mode`` ``:821-825``, ``ensure_first_mode`` ``:902``, and ``file`` ``:1948``. One read per publication is also more coherent than three separate baseline reads: the classes are evaluated against one state, not three successive ones.
2. **The second publication only after a failed first.** ``write_learned`` (``store.rs:2090-2112``) returns whether its publication succeeded. Success means ``Ok`` with ``published:true``, after the directory sync (``snapshot.rs:278-280``). ``commit_run`` (``:1917-1918``) publishes again only if the learned write failed, the publication failed, or nothing was published. Withdrawal on failure (``snapshot.rs:135-144``) is unchanged. The not-provisioned case returns before any inventory and stays as it is.
3. **Searches by identity.** Replace the linear searches listed in the measurement basis with maps from identifier to row, built once per call from a collection that has already passed ``validate``, which refuses duplicate identifiers (``request-core/src/model.rs:238-246``). Results and errors must be unchanged:
   - a missing lane preview source keeps ``requests-channel-refusal: preview source disappeared``; a missing helper publication source keeps ``requests-conflict``;
   - a source-identifier mismatch is still ``requests-conflict``;
   - authority failures are still ``requests-authority``;
   - dispositions are still appended in row order.

In ``publication``, build the map from ``next`` (validated), not from ``candidate``, which is validated after (``owner.rs:229``).

Tests that must discriminate:

- **Effective modes.** Use a store with four classes: audit; enforce with a pending correction; allow; enforce without one. The published snapshot's ``modes.effective`` must be byte-equal to a verbatim copy of the old per-class loop. A filing's release line must show 6 helper reads and 3 ``inventory_other`` calls with three non-audit classes, instead of 11 and 8.
- **Publication outcomes:**
  - first succeeds → exactly one policy call;
  - first fails, second succeeds → snapshot present, two calls;
  - both fail → snapshot absent, request recorded;
  - directory sync fails after the rename → counted as failure and retried.
- **Searches.** A property case over shuffled collections with unique identifiers compares each function's observable result between the old linear search and the map. The observable results are:
  - the lane triage's ``changed`` list and ``next`` bytes;
  - the helper's publication result and errors;
  - authority errors;
  - appended dispositions.
- **Mutations:**
  - restoring per-class inventories must fail the count assertion;
  - always publishing twice must fail it too;
  - never retrying must fail the recovery case;
  - a wrong map key must fail equivalence.

**Expected saving.** Against the field lines, slice A removes five whole reads from a filing (11 → 6), from ``record_effect`` (10 → 5) and from ``publish_waiting`` (9 → 4), and two from ``publish_snapshot`` (3 → 1). ``ensure_first_mode`` is unchanged at 1.

At the field's per-read cost (about 1.9 s in the helper plus about 2.2 s of lane decode and projection, from the lines' per-call means), that is roughly:

|Path|Measurement baseline|After slice A|
|----|--------------------|-------------|
|Filing|42–49 s|about 22–29 s|
|``record_effect``|38–43 s|about 18–23 s|
|``publish_waiting``|34–36 s|about 14–16 s|
|``publish_snapshot``|10.7 s|about 3.6 s|

A one-class fixture predicts only the second-publication saving and must not be used for the three-class estimate. Triage also gains the identifier indexes; its saving must be measured independently. Provisioned comparisons use three non-audit classes and state node load beside their medians.

**Estimate:** three to four hours with the bar. The deploy is the tools install and each door's refresh and restart, after in-flight requests finish.

## Slice B: one owner read per hold · `sec:collectionjournal:slice-b`

Implementation status and remaining work: (`prob:door:door-parts-contend-for-the-request-lock-within-one-request`).

**The boundary.** An exclusive or shared hold answers every lane-side question about the collection against the collection as read at the hold's first owner read. The questions are:

- projection in ``read_run`` and ``all_runs`` (``store.rs:1500-1526``);
- the door rows in ``channel_doors`` (``channel.rs:433-460``);
- the door row looked up by ``claim_request`` (``channel.rs:726``);
- the door row looked up by ``channel_record_effect`` (``channel.rs:750``).

The hold's own owner commits replace that view with the collection the commit returns. The helper's preview and commit keep their own live reads and preimage checks (``owner.rs:317-332``, ``:391-399``), so no collection is ever published from the view without a live preimage check.

**Why this is enough, and needs neither a revision nor a cache across holds:**

- The view's only use is answering questions about door rows. Door rows change only through owner commits.
- The orchestrator's direct path refuses any door-row change. Door bodies are exactly ``source_id`` and ``record`` (``permission-triage/src/requests.rs:28-35``), and that path requires the caller's ``loop_name`` on every changed row (``journal/requests.rs:276-283``).
- The door's own owner commits run under its exclusive lock. Readers hold the shared lock, which excludes those writers.
- Legacy escalation lines appended by the hook (``journal.rs:390-396``) and merged at reading (``journal/requests.rs:82-98``) make permission rows, never door rows.
- What a hold sees is therefore the state at its start. It is the same state baseline code sees at its first read, which ``change_one_locked`` already persists into local custody (``:2686``).
- The one owner that could in principle touch a door row outside the door's lock is the gateway (``lane-gateway/src/channel.rs:61-77``). Its actions are gateway-scoped; the helper-side check that makes that rule explicit belongs in stage 2, where the protocol changes.

**Mechanism.**

- A per-hold slot, set at lock acquisition for that lock key and cleared when the guard drops, holds an ``Arc`` of the typed collection.
- ``channel_read`` and the three direct reads (``channel.rs:488``, ``:726``, ``:750``) consult it.
- The rewrite paths (``channel.rs:244``, ``:287``, ``:336``) keep their live reads, because they compare plans with live state.
- A guard released on another thread does not carry the view.

**Tests that must discriminate:**

- One helper read per hold for filing, ``record_agent``, ``publish_waiting`` and the channel route of ``record_effect``.
- Projection equivalence with fresh reads when an independent permission writer files a row and appends a legacy line mid-hold.
- A hold's own triage commit followed by a claim in the same hold sees the committed rows.
- No reuse across holds: a door row changed by an owner triage in another process between two holds is seen by the second.
- Shared holds keep their own view.
- **Mutations:** a view kept past the guard; a view not replaced after the hold's own commit.

**Expected saving:** a filing goes to one whole read (about 4 s in the field) plus local work, so about 6–8 s from baseline 45 s or from slice A's 25 s; ``record_effect`` and ``publish_waiting`` likewise. Triage keeps its helper preview and commit reads.

**Deploy:** the tools install and door refreshes; no floor change. **Estimate:** a working day with the bar.

## Target and later stages · `sec:collectionjournal:target`

Implementation status and remaining work: (`prob:door:door-parts-contend-for-the-request-lock-within-one-request`).

The target: a hold costs what its own request costs, whatever the history. Today every question the hold asks is answered by reading the population. The table names each population-proportional cost and the stage that removes it.

|Population-proportional cost (803d6bdf)|Removed by|
|---------------------------------------|----------|
|Whole-journal read, parse, transport, decode and validate per owner read (``channel.rs:410-413``, ``journal/requests.rs:54-98``, ``transaction.rs:87-116``)|B (to one per hold), 2 (answers, not collections), 3 (rows by identity)|
|One inventory per non-audit class per publication (``snapshot.rs:208-215``)|A|
|Whole-journal rewrite per owner commit (``owner.rs:368-399``)|3|
|Review history unbounded per row, revalidated on every read (``model.rs:69``, ``:137-138``, ``:326-327``)|3, 4|
|Linear searches in loops (§1 list)|A|
|Hook approval check and disposition read the whole journal (``journal.rs:354-362``, ``:405-411``)|3|
|Door inventories decode every live run on every check (``store.rs:1530`` onward)|5|
|Run file, shapes file, learned index and policy snapshot rewritten whole per commit (``store.rs:1838-1918``, ``snapshot.rs:257-280``)|5, 6|
|``wait_answer`` polls on a clock (``door.rs:932-999``, sleeps at ``:950``, ``:997``)|6|

The questions the hold actually asks, and what answers them in the target:

|Question|Answered by|
|--------|-----------|
|A live record's door row (projection)|the row addressed by its common identifier|
|The pending set (owner status and listing)|a pending membership|
|A class's correction-pending state|a lane-side counter maintained on label transitions|
|Capacity|lane-side run and request counters|
|Deduplication|identity existence, plus tombstones for archived identities|
|A claim|in its row, with an in-flight claims membership|
|An approval match for the hook|a membership keyed by the approval's match key|
|A run's rows (retirement)|a per-run membership|

## Stage 2: the helper answers questions · `sec:collectionjournal:stage-2`

Implementation status and remaining work: (`prob:door:collection-helper-answers-questions-within-a-declared-scope`).

The stored format is unchanged; the protocol is replaced. The helper protocol carries answers, not the collection:

- rows by identity, with each row's revision;
- the pending rows;
- an apply operation on named rows, whose preimage is the named rows' revisions rather than the whole collection, returning only the changed rows and the new collection revision.

Owner commits declare their scope (door or gateway). The helper refuses a commit that changes rows outside its scope's kinds, which makes slice B's boundary an enforced rule.

- **Reader floor:** helper, door and gateway at the same release. There is no compatibility path before a first release.
- **Deploy:** install, then refresh every door and restart the gateways in one window, with in-flight requests finished first.
- **Operator-visible result:** the same command outputs; release lines whose helper phases no longer carry the collection's transport.
- **Saving alone (after B):** the lane's decode becomes proportional to the answer, which takes about 2 s off each field hold. Triage loses its two whole-collection transports. The helper still parses the whole file once per call.

## Stage 3: per-identity storage · `sec:collectionjournal:stage-3`

Implementation status and remaining work: (`prob:door:collection-journal-becomes-one-file-per-row`). Under the loop's registered permission root, ``requests.d/`` holds:

- one current row per identity, at ``rows/AB/CD/ID.json`` (two hex shard levels, opened by identity, never listed);
- memberships: ``runs/RUN/ID``, ``pending/ID``, ``claims/ID``, ``approvals/KEY/ID``;
- a ``revision`` file carrying the format version and the global revision;
- a write-ahead directory ``wal/`` holding at most the one transaction in flight;
- dispositions appended to day files, ``dispositions/YYYY-MM-DD.jsonl``.

Operations:

- A filing creates its row with ``O_EXCL`` (deduplication by existence) and its memberships.
- An owner transaction writes one intent to ``wal/``, replaces the named rows and memberships, bumps the revision and removes the intent.
- The hook's escalation is a row create; its disposition is a row update plus a day-file append; its approval check is a membership lookup.

Per-row review history is bounded: the current review plus a fixed recent window. Older reviews go to the row's archive.

The alternatives have different costs:

- **Per-run files:** they make a run's rows one file rewritten whole per change.
- **Appended deltas with a replay:** they need checkpoints of the whole state, which are rewrites in proportion to the population. Per-identity rows give a bounded replay by construction: recovery replays at most the one intent in ``wal/``.

Costs:

- **Start-up:** reading ``revision`` and the intents in ``wal/``.
- **Memory and registrations** may follow the population: inodes, shard directories and tombstones. Work does not.

**Proposed crossing: one time, per loop, run by the deploy.**

1. Stop the door after its in-flight requests.
2. Run ``superloop-lane requests migrate-collection LOOP``. It takes the door's lock and the journal's lock, which excludes the hook and the gateway. It reads the one-line journal once (its cost is proportional to the rows and is stated in its report), writes the rows, memberships and dispositions, and writes ``revision`` last as the commit point. It renames ``escalations.jsonl`` to ``escalations.jsonl.migrated-REV``, kept read-only for audit.
3. Refresh and start the door.

Readers at this release refuse a store without ``revision``, and they refuse a live ``escalations.jsonl`` beside ``requests.d/``.

- **Operator-visible result:** a migration report with rows by kind, memberships, dispositions and wall time; then helper phases in milliseconds.
- **Deployment requirements:** a per-loop window of a minute or two with lanes idle.
- **Saving alone (after B and 2):** the collection's share of a hold becomes proportional to the rows the hold touches. A filing's remaining cost is the door's local inventories and its syncs, about a second in the field. Triage becomes proportional to its decisions.

## Stage 4: retention · `sec:collectionjournal:stage-4`

Implementation status and remaining work: (`prob:door:collection-retires-terminal-rows-to-archive-segments`).

Kept hot:

- identities;
- rows that are pending or claimed;
- rows of live runs.

Moved to archive (``archive/YYYY-MM/`` segments, appended, read only by explicit history queries), each leaving a tombstone of about 150 bytes (identity, kind, terminal state, decision outcome, run, archived-at) for deduplication:

- terminal door rows (after-effect, completed or withdrawn before-effect) of retired runs;
- decided permission rows past a retention window, keeping their decision under their identity for re-escalation;
- terminal gateway proposals.

Never archived: a door row with an active service claim. Retirement completes or withdraws it first, as departed waiters already do (``channel.rs:742-801``). Dispositions stay in their day files, which are the permission learning record. Review references resolve through the retired run's retirement record, which already keeps the run's records.

Run retirement archives that run's rows through ``runs/RUN/`` (the work follows the retired run). The migration archives the existing history once, which also covers the field's 374 retired runs.

- **Format:** additive to stage 3 (archive and tombstones).
- **Operator-visible result:** archive counts in retirement reports.
- **Saving:** no hot-path time after stage 3. It is what keeps storage, shard sizes and deduplication bounded.

## Stage 5: the door's own store · `sec:collectionjournal:stage-5`

Implementation status and remaining work: (`prob:door:door-keeps-a-store-of-its-own-records`).

- Each local run becomes one record per request plus run metadata, instead of ``door-requests.json`` rewritten whole per commit (``store.rs:1874``, cap ``MAX_RUN_BYTES`` at ``:49``).
- Shapes and the learned index are maintained by applying the changed record, not derived from every run on every commit (``:1838-1846``, ``repair_shapes`` at ``:1783``).
- Capacity and per-class correction-pending become counters updated in the same commit.
- The crossing is a one-time rewrite of the live runs during a door refresh. Live runs are capped, so its cost is stated and small. Retired records are untouched.
- **Operator-visible result:** constant ``run_write``, ``shape_write`` and inventory phases.
- **Saving:** the last inventories in proportion to the live population go, and a hold becomes proportional to its request plus its syncs.

## Stage 6: wake-ups and the policy snapshot · `sec:collectionjournal:stage-6`

Implementation status and remaining work: (`prob:door:door-parts-contend-for-the-request-lock-within-one-request`).

- ``wait_answer`` and any waiter on an answer watch that request's row file with inotify instead of polling on a clock. Acceptance measures wake-up latency with one watch per directory and verifies that idle polling is absent.
- The policy snapshot stops embedding the learned index whole. At the measurement baseline it rewrites the learned index twice per commit, which is small in the baseline but grows with groups. It is published by parts or referenced by digest. That is a consumer-floor change for execute-command.

**Cut order and what each stage alone saves:**

|Stage|Saves on its own (field)|
|-----|------------------------|
|A|about half of every local hold|
|B|the rest of the repeated reads (holds of about 6–8 s)|
|2|about 2 s a hold, and triage's transports|
|3|the collection's whole cost (a hold of about 1 s)|
|4|bounded storage|
|5|the local inventories (a hold proportional to its request)|
|6|clock work and the snapshot's growth|

A and B change no format. Stage 2 is the protocol; stage 3 is the storage behind it; 2 and 3 can be designed together and landed in that order.

## Safe operation before migration · `sec:collectionjournal:safe-operation`

No supported command compacts or prunes the one-line collection journal, with the door either stopped or running. Owner commits refuse a publication that differs from the evaluated transition; no action removes rows. The direct orchestrator path cannot change door rows, and ``rewrite-door`` is a schema migration, not retention. The migration command in stage 3 is proposed, not an existing repair command.

Hand edits can lose service claims, permit an effect twice or strand a waiter, break deduplication and re-escalation identity, lose review and label history, or discard dispositions used for permission learning. Concurrent edits can also leave a torn tail that readers refuse. Stopping the door alone does not make hand pruning safe: the hook and gateway also use the collection, and the semantic losses remain after a clean rewrite.

Before the staged changes, fewer live lanes reduce queueing but not a transaction's own work. Batched triage amortizes one hold across several decisions. Unused non-audit classes can be moved to audit as a tightening; changing a class still in use makes its requests require owner adjudication and is not a performance-only change. Those operational choices trade throughput or owner latency for contention; they are not substitutes for bounded storage.

Measurements collect counts and sizes without journal content: mode counts; journal bytes and line count; row counts by kind; live run-record, shapes and learned-index bytes; and release-line phases with load. A result distinguishes owner reads from the helper's internal preview and commit reads, and policy snapshot publication from collection-journal replacement.

## Placement record · `sec:collectionjournal:placement-record`

**Problem (The collection journal's design joins the tree as a tracked design document)** · `prob:docs:collection-journal-design-joins-the-tree`

**CLOSED (2026-11-14).** This tracked, classified and installed design gives the staged work a durable citation. The docs owner partition and prose inventory include it; the native installation ledger records it, and the dependency census verifies the root build scope. The request-lock and stage items cite its title and it cites their remaining work. Placement changes no running program or journal format.
