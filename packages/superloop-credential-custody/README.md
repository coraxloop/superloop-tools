# Credential observations · `guide:credentialcustody:observations`

`superloop-credential-custody` observes completed sealed-file metadata and compares calibration identities. It is a tier-2 Rust package in release group `credential-custody`. Neither command requires privilege, a host key or a supervisor. Root-owned installation and read access are deployment choices; execution never rejects an otherwise valid invocation because of its uid. Meson installs the binary and its build record with the other public commands, and nothing invokes it; a rehearsal's root-owned copy is a separate operator installation.

## Commands · `sec:credentialcustody:commands`

```text
superloop-credential-custody length-observe --parameters FILE --case NAME --receipt NAME
superloop-credential-custody length-observe --parameters FILE --case NAME --receipt NAME --discover RELATIVE
```

The parameter record is reviewed metadata, not an untrusted command service. Probe argument vectors are explicit operator authority to execute their named programs; no shell expansion occurs. The caller must exclude deployment and file replacement throughout observation. Sealed inputs must be completed, regular, single-link, caller-owned and nonwritable, beneath the declared sealed root. Completion assertions bind each file digest to its case and invocation. This slice consumes those assertions; it does not observe a supervisor or establish generator success independently. Future completion observers must supply that evidence before these observations can witness a real campaign.

## Records · `sec:credentialcustody:records`

Schema 1 is strict JSON limited to 262144 bytes. Every object rejects unknown and duplicate keys, missing members and wrong types. Later commands need a separately reviewed schema version; ignored extension fields are not permitted. The top-level fields are `schema`, `case`, `config_digest`, `code_digest`, `sealed_root`, `evidence_root`, `payload`, `limits`, `identity`, `probes`, `names`, `lengths`, `contents`, `comparisons` and `samples`. Names contain at most 96 ASCII letters, digits, dots, underscores or hyphens, excluding dot and dot-dot. Paths are explicit and reject traversal. No field carries plaintext, a credential, or a secret-bearing argument.

`payload` names an installed `path`, full `sha256`, source `repository`, forty-character `source_commit` and repository-relative `document`. The observer extracts single-quoted heredoc bodies from that exact committed document and requires exactly one body matching both the reviewed digest and installed payload bytes. It runs those bytes with fixed `/usr/bin/python3 -I -`, followed only by sealed-root, wrap-width and final-LF metadata. The stdin here carries reviewed program source, never plaintext or a counting stream. The record cannot substitute a Python executable, module, command string or shell. The estate supplies and installs its reviewed payload; this repository ships only a synthetic test stand-in.

`limits` gives `file_bytes` (1–16777216), `output_bytes` (1–4194304 per child stream) and `timeout_ms` (1–60000 per child). Children receive an empty environment, closed unrelated descriptors, null metadata input for probes, bounded captured stdout/stderr and finite cancellation. Nonzero child status, any stderr, output overflow or timeout refuses without relaying foreign diagnostics. The interpreter digest is included in the identity. The source document and installed payload are both bounded.

`identity` contains `measure` (`decoded-length`), `computation` (`3*(N/4)-P`), `form` (`wrap`, `final_lf`), `files`, `probes` and `source_commit`. `files` requires `sealer`, `library`, `interpreter` and `parser`, each with `path` and full `sha256`. Interpreter path is fixed to `/usr/bin/python3`; its resolved regular-file bytes are hashed. Each identity probe has `role` and exact `bytes` as a JSON byte array. The parameter `probes` give `role` and exact `argv`; both rosters require exactly boot, deployment, live-applied, sealer-version, sealer-package, library-mapping and interpreter-package. Probe results compare byte for byte, including final newlines. The deployment owns the package and library mapping commands and their meaning; this tool embeds no distribution or package manager.

`names` contains 1–16 distinct names, `lengths` 2–16 distinct bounded input lengths, and `contents` exactly two distinct public pattern identifiers. `samples` must cover their full product exactly once. Each sample has `name`, `input_length`, `content` and `completion`; completion contains matching `case`, nonempty `invocation`, true `success` and `distinct_content`, and `sealed_sha256`. Files are named ``NAME/LENGTH-CONTENT.sealed`` beneath the sealed root. `comparisons` contains bounded distinct `id`, `left` and `right` pairs drawn from the name roster. Equality across different names is recorded, not required.

## Length and identity · `sec:credentialcustody:length-identity`

The reviewed parser emits space-delimited metadata rows: `NAME LENGTH CONTENT file-bytes N wrap W final-lf F base64-chars N padding P decoded N offset N`, one `NAME constant N` per name, and one `ID same-constant-both-names True|False` per comparison. Complete rows, exact roster, numeric consistency, observed text sizes and the fixed form are mandatory. One decoded-minus-input constant must hold across all lengths and both contents of each name. The payload rejects whitespace normalization, wrong wrapping/newline form, alphabet or padding. Sealed digests are checked before and after execution; identity is checked on both sides. No decoded bytes are materialized by the observer.

Discovery reports only `line_count`, `wrap_width` (null for irregular wrapping), `final_newline` and `alphabet_conformity`, with `discovery:true`. It cannot create a calibration or accept a length. Alphabet conformity is a representation observation, not a padding or length verdict. The operator must freeze a separately reviewed form before calibration.

## Publication and output · `sec:credentialcustody:publication`

The executable declares `machine-json`. Success emits exactly one schema-1 object plus LF with `command`, `case`, `outcome`, `wall_us` and `evidence`. Runtime failure returns 1 with empty stdout and one classed, redacted JSON diagnostic; invalid command-line usage and terminal stdout return 2. Help and version use shared JSON control records on stderr. Panic payloads and foreign errors are suppressed. Output-write failure is failure even if a receipt has already been published.

Receipts are exclusively created as ``.NAME.partial`` at 0600 beneath an existing caller-owned 0700 evidence directory. The writer flushes and synchronizes bytes, sets 0400, synchronizes again, then publishes with Linux no-replace rename and synchronizes the directory. Existing destinations and partial candidates refuse; partial files are never acceptance. A failed publication can leave a complete disk receipt, so retry inspects retained state rather than assuming nothing happened. Tests exercise caller-owned synthetic files only and make no encryption, supervisor, root-installation or power-loss claim.
