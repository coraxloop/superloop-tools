# Digest handles and cryptographic bindings · `spec:digests:handles-and-bindings`

A digest serves either to distinguish values in a namespace or to bind untrusted bytes to a trusted reference. Its representation follows that purpose. Long identifiers make records harder to read and compare without improving a namespace's useful discrimination once its collision budget is met. A cryptographic binding instead retains the complete digest and states the substitution it prevents.

**Definition (Handle)** · `def:digests:handle`

A handle names, looks up, deduplicates or keys a value, or states which of several values is meant. Its equality supplies probabilistic content identity within a declared namespace. A handle is a lowercase hexadecimal prefix of the complete digest, never a suffix, folded value or hash of the digest. Retaining the algorithm and canonical input definition permits recomputing the complete value when a binding is needed; a prefix alone cannot reconstruct its missing bits.

**Definition (Cryptographic binding)** · `def:digests:binding`

A binding compares the complete digest of candidate bytes with a trusted reference outside the candidate supplier's control. Its protection statement names the actor who could forge, what that actor controls, the trusted reference and exactly which bytes or canonical fields are bound to it. The algorithm, framing, ordering and encoding are part of that definition. A digest supplied beside bytes by the same untrusted actor establishes no authenticity by itself. Custody, authenticated delivery or reviewed text must supply the independent reference.

**Rule (Full digest justification)** · `rule:digests:full-digest-justification`

Every use requiring a full-length digest shall carry the protection statement of (`def:digests:binding`) in the specification rule requiring it and in a doc comment at the defining field or constant. An untyped record member or command binding shall place that comment at its producer and cite its specification. A generic digest implementation documents its algorithm; each consumer separately documents its purpose. Algorithm round constants and known-answer test vectors are algorithm data, not truncated identifiers.

A full-length digest without both statements is a finding. Where no protection can be stated, the use is a handle under (`def:digests:handle`), including caches, equality shortcuts and diagnostic identities. A plausible binding with a missing comment remains a documentation finding; naming a threat does not prove the implementation preserves the required custody. Imported protocols and immutable formats that prevent shortening remain explicit migration findings, not implicit exceptions.

**Bound (Accidental collisions)** · `bound:digests:accidental-collisions`

For at most n distinct inputs with uniformly distributed k-digit hexadecimal prefixes in one namespace, the probability of any accidental collision is at most n(n−1)/(2 × 16ᵏ), by summing the collision probabilities of all pairs. The namespace owner declares its lifetime population bound n and acceptable collision probability ε, including retained history and values compared across processes. Choose k so that n(n−1)/(2 × 16ᵏ) ≤ ε. This argument assumes non-adversarial inputs and a digest with the requisite distribution; it is not an authentication argument.

**Calculation (Default handle size)** · `calc:digests:default-handle-size`

Sixteen hexadecimal digits retain 64 bits. At n = 1,000,000 the bound is approximately 2.71 × 10⁻⁸, below ε = 10⁻⁷. This supports a useful default without carrying 64 hexadecimal digits through every record. At n = 1,000,000,000, 24 digits retain 96 bits and give approximately 6.31 × 10⁻¹². Larger populations or smaller collision budgets use the same formula, rather than treating any fixed length as universally sufficient.

**Rule (Handle length and ambiguity)** · `rule:digests:handle-length`

The default handle is the first 16 lowercase hexadecimal digits of the full digest, with the default namespace contract n ≤ 1,000,000 and ε = 10⁻⁷. A namespace that cannot satisfy that contract declares its own n, ε and longer prefix length using (`bound:digests:accidental-collisions`). A detected collision must never silently select a different value: refuse the ambiguity or extend the prefix consistently with the namespace's readers and stored representation. Adversarial substitution is never answered by a handle length but by a full binding.

**Rule (Reports and prose)** · `rule:digests:report-handles`

Reports, diagnostics and prose use the handle form unless the line itself carries a binding consumed against a trusted reference. A display abbreviation is labelled as a prefix and never substituted into a binding field. Command output used by a reader, a persisted record, a pin or a protocol retains its existing representation until its producers and readers change together. Such incompatible handle representations are inventory findings, not authority for silently truncating records.

**Example (Reviewed removal)** · `ex:digests:reviewed-removal`

The full digest required by (`req:deployment:reviewed-removal-digest`) binds the opened removal target to the independently reviewed manifest. An actor controlling the target and its adjacent sidecar could replace both; that actor cannot choose the trusted reviewed digest. The manifest's provenance and custody remain necessary. A digest newly computed from the live target cannot create removal authority.

**Example (Command context)** · `ex:digests:command-context`

The full context binding of (`rule:commandcontracts:policy-and-binding`) prevents a requester controlling proposed arguments, lane data or request text from applying an authorized answer to different execution context. The trusted reference is the context retained by the authenticated decision owner for that request and review. Door source identity, mode and treatment; hook request and rubric; gateway registration, lane, sequence and arguments; and a direct caller's complete context are separately framed inputs. A request lookup identifier does not acquire this protection merely by sharing the same hash algorithm.

**Rule (Inventory evidence)** · `rule:digests:inventory-evidence`

An inventory entry names its package, file and line, defining member or output, purpose, current representation and policy representation. A binding entry states both the trusted reference and the actor-controlled side; a handle entry records the current and required lengths. An unstated protection is explicitly a handle finding until justified. Search occurrences, algorithm plumbing, fixtures and inventory entries are distinct counts. A reader or record migration is named as follow-up work; inventory alone changes no stored representation.
