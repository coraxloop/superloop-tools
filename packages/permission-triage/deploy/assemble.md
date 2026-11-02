# Permission-triage owner deployment runbook

Assembly produces reviewable files; deployment and the enforce flip are separate owner acts. The assembler never registers a hook, changes a live instance, changes harness settings, or enables bypass. Installation and reinstall render audit, including when the supplied instance or previous deployment record says enforce. A real authenticated rehearsal on the deployment host is an owner step; the disposable fake-harness rehearsal tests the procedure and cannot authorize enforcement.

Use a private staging directory outside the live harness home, repository, registry directory and its parent; each output directory is dedicated to the four assembly files. Replace every `/absolute/` placeholder before running these commands. Keep the reviewed repository, release binaries, verdict, declaration, inventory, audit evidence, and resulting deployment record together for review. The instance grammar accepts only its documented assignments; never source an unreviewed instance as shell code.

```sh
set -eu
export TRIAGE_REPO=/absolute/path/to/orchestration
export TRIAGE_TOOLS=/absolute/path/to/superloop-tools
export TRIAGE_PREFIX=/absolute/install/prefix
export TRIAGE_BUILD=/absolute/build/directory
export TRIAGE_STAGE=/absolute/private/triage-review
export TRIAGE_REGISTRY=/absolute/private/loops.d
export TRIAGE_LOOP=registered-loop-name
export TRIAGE_ESTATE_ROOT=/absolute/path/to/orchestration/local/permissions/state
export TRIAGE_HARNESS=/absolute/path/to/claude
export TRIAGE_INSTALLER=/absolute/path/to/superloop-install
export TRIAGE_RELEASE="$TRIAGE_PREFIX/libexec/superloop"
export PERMISSION_TRIAGE_HOOK_BIN="$TRIAGE_RELEASE/hooks/permission-triage-hook"
export PERMISSION_TRIAGE_ADAPTER_BIN="$TRIAGE_RELEASE/hooks/superloop-claude-hook"
export TRIAGE_INSTANCE="$TRIAGE_REPO/local/permissions/permission-triage.env"
export TRIAGE_VERDICT="$TRIAGE_STAGE/verdict.json"
export TRIAGE_EVIDENCE="$TRIAGE_STAGE/audit-evidence.json"
/usr/bin/test -d "$TRIAGE_REPO/local/permissions"
/usr/bin/test -x "$TRIAGE_HARNESS"
/usr/bin/install -d -m 0700 "$TRIAGE_STAGE"
```

1. Inventory before registration. The owner enumerates every live loop and session, including peer loops, provisioned worker uid blocks and registered homes, and in-session subagents; records the session-to-loop/role correspondence; provisions each registry entry, its orchestrator and worker rubrics, distinct registered loop root, and adjudicator route; and authorizes the exact settings change. Loop roots must exist at their registered absolute paths with no overlap or authorization source inside them; worker run roots derive from the registered `LOOP_HOME` and caller uid and may be world-readable. The estate instance root must equal its own registry entry's root. The calling loop owns its private registry: a mode-0700 directory with mode-0600 entries. A helper does not traverse another loop's private registry or journal. Estate-wide inspection runs through the superloop's own loop instance. For each worker-enabled loop, run `--worker-rubric-check --instance FILE --loop NAME` as the loop uid through its entry, then read back the published verdict and matching rubric digests. Read back all entries and domain facts. Confirm that a loop approval cannot authorize an estate effect. Record raw-file digests below and a sorted JSON array of `(name, optional session identifier, checkout, state root)` tuples as `registry-tuples.json`; serialize it as compact UTF-8 JSON with no trailing newline for the canonical registry digest. The assembler independently computes that same tuple digest and domain-byte digests; compare them with this declared inventory at step 3.

```sh
/usr/bin/sha256sum "$TRIAGE_REGISTRY"/*.env
/usr/bin/sha256sum "$TRIAGE_REPO/local/permissions/domain.md"
/usr/bin/sha256sum "$TRIAGE_STAGE/registry-tuples.json"
"$TRIAGE_HARNESS" --version
/usr/bin/sha256sum "$TRIAGE_HARNESS"
```

2. Declare workload, window, and limits before observation. Save the representative workload, explicit live-session inventory, planned UTC start/end, and numeric limits in a private declaration. Require separate p50/p95/p99/max maxima for verdict and full invocation walls, `model_call_share_max`, and `denial_share_max`; a hook safety timeout supplies no workload budget. Retain this dated declaration before collecting samples. Build the exact reviewed source using `provenance.md`, then run the complete topology probe with the real pinned harness in a disposable authenticated account. Retain its complete output and wall, including every audit, bypass, settings-deny, infrastructure-failure, and table-confirmation row. The probe deliberately measures enforce/bypass only inside its disposable fixture. Never run it against a live state root. A fake, blocked, missing, stale, or partial verdict stops production assembly.

```sh
cd "$TRIAGE_RELEASE"
/usr/bin/date -u +%s.%N
PERMISSION_TRIAGE_HARNESS_BIN="$TRIAGE_HARNESS" "$TRIAGE_RELEASE/permission-triage-topology" --fixture-root "$TRIAGE_STAGE/probe" --verdict "$TRIAGE_VERDICT" >"$TRIAGE_STAGE/probe.log" 2>&1
/usr/bin/date -u +%s.%N
/usr/bin/python3 - "$TRIAGE_VERDICT" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
assert v['schema'] == 2 and v['deployment_blocked'] is False
assert v['selected_topology'] == 'bypass' and v['roster_selection'] == 'full'
assert v['harness_provenance']['kind'] == 'real'
for field in ('audit', 'bypass', 'settings_deny_wins', 'infrastructure', 'table_confirmation', 'friction'):
    assert v[field], field
print(v['harness_provenance'], v['planned_trials'])
PY
```

3. Assemble and install audit with the ordinary harness gate active. Complete the private instance with absolute reviewed classifier and registry paths. An explicit owner rubric must exist; an empty file is a valid zero-rule rubric. First run the silent check below without audit evidence: it validates instance grammar and paths, the executable classifier, configured private hook version/general rubric, full schema-2 topology rows and provenance, and every registered root/domain. It also constructs the prospective output and checks output separation. A passing check validates a temporarily staged registry, prints nothing, leaves published files unchanged, and exits zero; an interrupted check can leave its hidden stage for the next successful publishing assembly to retire, if cleanup succeeds. Run the same command without `--check`. Under the exclusive nonblocking registry-parent lock it stages the rows and review files. It then checks the configuration root and takes its shared lock when distinct, or keeps the existing exclusive guard when both names select one inode; next it takes the ledger lock shared when present, rechecks the ledger, exchanges the live registry when a ledger exists, publishes one review directory containing `settings-fragment.json`, `permission-triage.env`, `deployment-record.json`, and `assembly-marker.json`, and only then retires older hidden generations. Only after the assembly command exits zero, compare the marker's ledger digest and copy time with the deployed rows, compare its inventory digest with the record, and inspect the record and owner and worker routing. An interruption can leave a hidden stage or retained prior registry generation; a failed output publication can leave the exchanged registry beside the previous review directory, whose marker cannot override the failure exit and whose files must not be installed. Initial `auditEvidence` and `auditEvidenceDigest` are null, so this record is not enforce readiness. `hookMode` and the staged instance are always audit; `sourceInstanceDigest` binds the input, while `instanceDigest` binds the rendered instance. `registryInventory`, `loopRegistry.sha256`, and `domainRubricDigests` must match the predeclared inventory. `bypassEvidenceDigest` hashes the verdict's bypass rows serialized as compact sorted-key JSON with no trailing newline; `verdictDigest` hashes the exact complete verdict file.

```sh
"$TRIAGE_RELEASE/permission-triage-assemble" --verdict "$TRIAGE_VERDICT" --repo "$TRIAGE_REPO" --instance "$TRIAGE_INSTANCE" --out "$TRIAGE_STAGE/assembly" --check
"$TRIAGE_RELEASE/permission-triage-assemble" --verdict "$TRIAGE_VERDICT" --repo "$TRIAGE_REPO" --instance "$TRIAGE_INSTANCE" --out "$TRIAGE_STAGE/assembly"
/usr/bin/python3 - "$TRIAGE_STAGE/assembly" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1]); r = json.loads((p/'deployment-record.json').read_bytes())
instance = (p/'permission-triage.env').read_bytes()
assert r['hookMode'] == 'audit'
assert b'PERMISSION_TRIAGE_MODE=audit\n' in instance
assert hashlib.sha256(instance).hexdigest() == r['instanceDigest']
print(json.dumps(r, indent=2))
PY
```

Read-back checklist before live registration: stop existing bypass sessions or restore their ordinary harness gate; confirm no session is still in bypass; review the installer dry run and the source/binary provenance; place the reviewed hook-side artifacts and staged audit instance under the separate owner authorization described in `provenance.md`; merge the single registration using `settings-fragment.md`. Start fresh sessions and read back registration, adapter path, explicit audit mode, active ordinary harness mode, hook/harness versions and binary digests, registry digest, domain digests, and adjudicator destinations. Observe actual zero hook-output bytes for healthy audit invocations. An old session or an unchanged on-disk file alone is not read-back evidence.

4. Observe and review the declared window. Review every loop journal and the separate estate journal, all health diagnostics, and full invocation timings; correlate each sample with the explicit private session inventory because journal records deliberately omit session identifiers. Confirm every recorded `stale_session` value is false; a rotated identifier resolves unknown and invalidates acceptance. Record every inventoried session with an observed count of at least one; unknown roles, missing loops/domains/roots, unobserved sessions, gaps, lost records, timeouts, and unexpected estate routing invalidate acceptance. Correct the scoped cause and restart the affected window. Review would-be denials by class, loop, and scope and prove zero peer-domain denials. Preserve event IDs and the session correlation worksheet alongside the evidence, rather than adding extra fields to its closed schema. Read-only request inspection selects the calling loop. Estate-journal and outbox inspection is a separate superloop operation; its evidence remains required for the declared inventory and is not supplied by another loop's helper.

```sh
PERMISSION_TRIAGE_LOOP_REGISTRY="$TRIAGE_REGISTRY" "$TRIAGE_RELEASE/requests-helper" list --loop "$TRIAGE_LOOP"
```

5. Record and validate the justification. Create private `audit-evidence.json` from the reviewed journals, invocation measurements, and explicit inventory. Its exact schema is described below. `binary_digest` and `harness_version` must equal the verdict's `harness_provenance.sha256` and `.version`; a real-looking path or renamed fixture cannot substitute for the reviewed digest. Validate using `--audit-evidence` and `--check`; the silent check additionally verifies every field, binding, session/loop coverage, complete window, and numeric limit. Validation is identical for audit and enforce input instances. It renders no record in check mode. Repeat without `--check` to publish the justification, including the complete validated evidence and its exact-file digest. Review that record and record the owner's decision and source evidence IDs separately. The assembler checks the supplied summary against deployment inputs; the owner remains responsible for its journal/session correlation and the truth of the live inventory.

```sh
"$TRIAGE_RELEASE/permission-triage-assemble" --verdict "$TRIAGE_VERDICT" --repo "$TRIAGE_REPO" --instance "$TRIAGE_INSTANCE" --out "$TRIAGE_STAGE/readiness" --audit-evidence "$TRIAGE_EVIDENCE" --check
"$TRIAGE_RELEASE/permission-triage-assemble" --verdict "$TRIAGE_VERDICT" --repo "$TRIAGE_REPO" --instance "$TRIAGE_INSTANCE" --out "$TRIAGE_STAGE/readiness" --audit-evidence "$TRIAGE_EVIDENCE"
/usr/bin/python3 - "$TRIAGE_STAGE/readiness/deployment-record.json" "$TRIAGE_EVIDENCE" <<'PY'
import hashlib, json, pathlib, sys
r = json.load(open(sys.argv[1])); raw = pathlib.Path(sys.argv[2]).read_bytes()
assert r['auditEvidence'] == json.loads(raw)
assert r['auditEvidenceDigest'] == hashlib.sha256(raw).hexdigest()
assert r['hookMode'] == 'audit'
print(json.dumps(r, indent=2))
PY
```

6. Perform the controlled transition only under the separate owner decision. Stop tool work and retain the ordinary harness gate. In one controlled transition, change only the live instance's explicit mode to enforce, validate it, then start the measured bypass session. Never start bypass while the hook is audit. The following owner commands preserve the other instance lines and atomically replace the mode file; the subsequent assembler check must succeed before the harness launch. If anything fails, keep the ordinary gate and investigate. This command sequence is a host owner step, not a lane deployment command.

```sh
set -eu
/usr/bin/python3 - "$HOME/.claude/permission-triage.env" <<'PY'
import os, pathlib, sys
p = pathlib.Path(sys.argv[1]); raw = p.read_bytes()
assert raw.splitlines().count(b'PERMISSION_TRIAGE_MODE=audit') == 1
updated = raw.replace(b'PERMISSION_TRIAGE_MODE=audit', b'PERMISSION_TRIAGE_MODE=enforce')
tmp = p.with_name(p.name + '.owner-flip.tmp')
with tmp.open('xb') as f:
    os.chmod(tmp, 0o600); f.write(updated); f.flush(); os.fsync(f.fileno())
os.replace(tmp, p)
assert p.read_bytes() == updated
PY
"$TRIAGE_RELEASE/permission-triage-assemble" --verdict "$TRIAGE_VERDICT" --repo "$TRIAGE_REPO" --instance "$HOME/.claude/permission-triage.env" --out "$TRIAGE_STAGE/flip-check" --audit-evidence "$TRIAGE_EVIDENCE" --check && "$TRIAGE_HARNESS" --permission-mode bypassPermissions
```

Fresh-session read-back checklist: the live instance says enforce exactly once; the active harness session reports the measured bypass mode; the registration and all reviewed digests match; harmless allow, deny, settings-deny, and failure sentinels reproduce the accepted topology's hook-output, execution/refusal, journal, and timing evidence. Retain each sentinel's exact command, result document, marker, and hook events. A mismatch blocks activation and ordinary work remains stopped. Running the corresponding fake-harness tests does not replace this host rehearsal.

7. Assign observation and its deadline to the deployment lane's Sonnet watcher; the session decides rollback from the hand-back and follows the reverse safe order. Stop bypass sessions or restore their ordinary harness gate first, and read back that no bypass session remains. Only then set audit or remove the hook registration and restore the backed-up settings. Retain the journals, owner decision, sentinel transcript, and rollback record. Reinstallation follows the same gate-restoration prerequisite because its rendered instance is always audit.

```sh
# Owner read-back prerequisite: every bypass session has stopped or restored its ordinary gate.
/usr/bin/python3 - "$HOME/.claude/permission-triage.env" <<'PY'
import os, pathlib, sys
p = pathlib.Path(sys.argv[1]); raw = p.read_bytes()
assert raw.splitlines().count(b'PERMISSION_TRIAGE_MODE=enforce') == 1
updated = raw.replace(b'PERMISSION_TRIAGE_MODE=enforce', b'PERMISSION_TRIAGE_MODE=audit')
tmp = p.with_name(p.name + '.owner-rollback.tmp')
with tmp.open('xb') as f:
    os.chmod(tmp, 0o600); f.write(updated); f.flush(); os.fsync(f.fileno())
os.replace(tmp, p)
assert p.read_bytes() == updated
PY
```

## Closed readiness schema

The top-level object has exactly `schema` (integer 1), `window_start`, `window_end`, `harness_version`, `binary_digest`, `topology_digest`, `registry_digest`, `domain_digests`, `sessions`, `unknown_count`, `lost_record_count`, `sample_count`, `model_call_share`, `verdict_wall_ms`, `invocation_wall_ms`, `would_be_denials`, `peer_domain_denial_count`, and `limits`. There are no defaults; missing or unknown keys refuse at every fixed-shape object level. Domain keys are precisely the live registered loop names.

Timestamps use the journal writer's canonical UTC `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` representation, with valid calendar dates and seconds 00–59. The scoped evidence parser validates that format; the existing journal reader itself still accepts string timestamps. Require `window_start < window_end <= assembledAt`. Digests are 64 lowercase hexadecimal digits: harness bytes, exact topology-file bytes, canonical sorted registry-tuple bytes including roots, and each domain rubric's exact bytes. Harness version and digest must match the topology provenance; topology, registry, and domain bindings must match the assembler's independently inspected inputs.

These full evidence digests bind submitted evidence to the assembler's independently inspected harness, topology, registry and rubric. An evidence supplier controls its evidence record and could claim a different inspected configuration; the independently loaded inputs are the trusted reference (`[TOOLS-rule:digests:full-digest-justification]`).

`sessions` is an array of exact `{session, loop, role, count}` objects. Roles are `orchestrator` or `orchestrator-subagent`, never unknown; loop names must be registered, identifiers must be nonempty and cannot identify another loop, and an orchestrator identifier must match its registered identifier when supplied. Duplicate session/loop/role rows refuse. Every registered loop and main-session identifier must be observed. Every count is a nonnegative integer and each session count must be positive. `sample_count` must equal their checked sum; `unknown_count` and `lost_record_count` must both be zero. Violations of these completeness conditions are named `incomplete window`.

Both wall objects have exactly `p50`, `p95`, `p99`, `max`; observations and maxima are finite nonnegative numbers in milliseconds. `limits` has exactly `verdict_wall_ms`, `invocation_wall_ms`, `model_call_share_max`, `denial_share_max`. Each limit wall has those same four numeric fields. Shares, including both share limits, are finite numbers in [0,1]. Every wall observation and `model_call_share` must be at or below its corresponding limit; equality passes.

`would_be_denials` is an array of exact `{class, loop, scope, count, share}` objects. Classes are `agent-error`, `suspicious`, or `infrastructure-failure`; scope is `loop` or `estate`; the loop must be inventoried. Duplicate class/loop/scope rows refuse, row counts cannot exceed `sample_count`, and each share must be within [0,1] and at or below `denial_share_max`. `peer_domain_denial_count` must be zero. The owner verifies denial counts/shares against the retained journal review.

Any supplied readiness evidence that is malformed, missing required topology evidence, mismatched to the reviewed harness/inventory, incomplete, over a numeric limit, or contains a peer-domain denial is refused by name with exit 3. Usage errors exit 2 and other infrastructure failures exit 1. A passing check is silent and leaves published files unchanged while temporarily staging a proposed registry when a ledger exists; an interruption can leave that hidden stage until a successful publishing assembly retires it, if cleanup succeeds. The corresponding assembly command holds the exclusive nonblocking registry-parent lock, then the configuration-root lock shared and the ledger lock shared when present, through publication; it exchanges live registry rows when a ledger exists before atomically publishing the marked review directory and retiring older hidden generations, and leaves installed mode and harness settings unchanged. A failed publication blocks installation regardless of any matching marker; after a zero exit, check the marker against the live rows before installing any review file.
