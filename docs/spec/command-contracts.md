# Command decisions · `spec:commandcontracts:command-decisions`

Command judgement, authority and execution are separate boundaries. Keeping those boundaries explicit lets doors, hooks, gateways and direct callers share decisions without sharing credentials or acquiring one another's authority.

**Rule (Domain and adapters)** · `rule:commandcontracts:domain-and-adapters`

`execute-command` is accountable to the permission/request domain owner PERMISSIONTRIAGE and is an internal tier-1 domain library for command identity, checks, policy, rubric validation, bounded triage, escalation, records, learning and process sequencing. Callers retain harness decoding, peer authentication, registry observations, authoritative configuration, persistence custody, model isolation, transport and actual execution. The domain accepts typed observations and bounded semantic persistence operations; it exposes neither arbitrary mutation closures nor another library's persistence types.

`request-core` alone owns common request transitions, review identities, single-use claims, identical-retry completion and atomic transaction preconditions. Callers adapt domain operations to that engine while retaining authority validation. `session-core` owns neutral session decisions and explicit state paths; harness adapters decode events and render replies. These tier-1 libraries depend internally only on tier 0. Neither a common record nor a successful transaction grants permission.

**Rule (Policy and request binding)** · `rule:commandcontracts:policy-and-binding`

Absent loop and class mode settings initialize from the registered floor. Context digests bind decisions within the caller's protocol: a door binds source identity, mode and proposed treatment; a hook binds request and rubric digests; a gateway binds registration, lane, sequence and arguments; a direct caller binds its complete context. A review answer binds the request, its context digest and the current review identity when answering a marked review. Stale or unrelated answers cannot resume the process.

**Rule (Escalation and actionable verdicts)** · `rule:commandcontracts:escalation`

Decision cost increases through deterministic validation and pre-cleared rules, agreeing learned exact matches, one bounded agent call, loop review, operations and owner authority. Conflicts and misses remain undecided. The caller's mode selects when it executes or waits; an approval to one request does not implicitly promote a reusable command. Door allow/refuse/refer values, hook classifications and gateway lifecycle results retain their own wire meanings while adapters attach the common judgement and outcome.

Every verdict contains `correction` and `escalation`, explicitly null when inapplicable. A refusal populates at least one; a referral populates escalation. Infrastructure failure names a repair or responsible authority. Invalid output, a failed judgement call or timeout produces a service referral with a distinct status and no new effect. Request text cannot replace the reviewed rubric, and the time budget reserves cleanup.

Operations and owner routes require configured identities, delegation, authenticated delivery and answer intake, request/context/review binding, and retained answer provenance. Acceptance covers unanswered and parked retention, wrong identity or recipient, stale reviews, duplicate delivery and revoked delegation. Only a current authorized answer resumes work; a floor change reaches its authoritative grant. An unprovisioned route returns a named provisioning remedy and cannot claim deliverability.

**Rule (Direct policy custody)** · `rule:commandcontracts:direct-policy`

A provisioned direct caller uses a loop-owned mode-0700 `direct` tier for its journal and transaction files and an owner-owned mode-02750 `policy` tier with the loop's group for a mode-0640 snapshot. These are distinct from the entered home. Readers hold descriptors beneath the trusted class root, refuse symlinks or writable ancestors, and require the observed owner on policy ancestors and the reader's group on the policy tier and snapshot. The direct tier carries the reader's effective identity. Host writers derive ownership from the held shared tier, require shared, private and direct to agree, and do not compare numeric identities across namespace views.

Policy comes only from the owner-published snapshot: registry floor, mode revisions, learned index, rubric path and digest, with source revisions and digests. Each journal record binds the snapshot digest. A source writer withdraws the snapshot under its existing lock before mutation, republishes afterward, and leaves it absent on publication failure while reporting that failure. Missing policy refuses as `execute-command-snapshot-absent` with a publication remedy; unsafe custody and mismatched loop identity refuse under their named custody and identity classes. Request text supplies no policy fallback.
