# `staff-provision` · `guide:staffprovision:staff-provision`

The `staff-provision` package supplies the private `account` helper behind `superloop account`. It keeps key custody separate from privileged server changes: a superloop mints its own private keys locally with `superloop account keygen`, while the orchestrator alone runs `superloop account` through an owner SSH alias. The helper never transmits private key material.

The package uses only the standard library. Pure planners turn probed state into ordered exact-argv command plans, and an injected `Runner` owns every external command. Unit tests use a scripted runner; they never contact a server or invoke a real `ssh-keygen`.

## Key generation · `sec:staffprovision:loop-keygen`

```text
Usage: superloop account keygen --loop NAME [--dir KEYDIR]

Mint a loop master key and an independently revocable Codex worker key.

Options:
  --loop NAME    Loop and requested account name (required)
  --dir KEYDIR   Key directory (default: $HOME/.ssh)
  -h, --help     Show this help
```

The loop name follows the bootstrap account-name grammar and cannot be a reserved administrative identity. Before key generation, the tool probes all four destinations and refuses on the first existing file or symbolic link. There is no force mode.

The exact generated paths and comments are:

```text
KEYDIR/NAME_ed25519        NAME@workstation
KEYDIR/NAME_ed25519.pub
KEYDIR/NAME-codex_ed25519  NAME-codex@workstation
KEYDIR/NAME-codex_ed25519.pub
```

Generation uses `ssh-keygen -t ed25519 -N ""` through the runner. Before probing or generating any key, `superloop account keygen` requires all four variables below; none has a default.

|Variable|Value|
|--------|-----|
|`LOOP_KEYGEN_COORDINATOR`|A non-empty, single-line request-recipient label. The example value is `Example Coordinator`.|
|`LOOP_KEYGEN_CLIENT_CONFIG`|The non-empty, single-line path to the operator's client SSH configuration. The example value is `/home/example/.ssh/config`.|
|`LOOP_KEYGEN_SSH_RECORDS`|Zero or more newline-separated records. Every non-empty record has exactly `alias`, `user`, and `identity_file` fields separated by literal tabs; the variable itself is still required when its value is empty.|
|`LOOP_KEYGEN_ROUTES`|Zero or more newline-separated routes copied from the registered node endpoints. Each line contains tab-separated `alias`, `address`, `port`, and an optional public host key (`algorithm base64 [comment]`); an omitted or empty fourth field means unpinned. The variable is required even when empty.|

For example, a two-record `LOOP_KEYGEN_SSH_RECORDS` value is:

```text
sagofink-orchestration	example-loop	/keys/example-loop-codex_ed25519
mondreiher-analysis	example-loop	/keys/example-loop-codex_ed25519
```

The configured coordinator labels the request banner and its `To:` field; the provisioning request text is unchanged. Each SSH record must have exactly one route in `LOOP_KEYGEN_ROUTES`, and each route must name a record's alias; duplicate records and missing, duplicate or unmatched routes refuse with the alias named before any key is generated. Route addresses must be valid IP addresses or DNS hostnames, ports must be canonical decimal values from 1 to 65535, and supplied public host keys must have two or three fields with a known SSH algorithm and decodable base64. New loops cannot resolve arbitrary aliases through the loop-specific instance registry before registration, so the caller supplies these explicit routes from the registered node's endpoint and public host key.

The rendered SSH configuration begins with `Include CLIENT_CONFIG`, then each stanza renders `Host` from the record's alias, `HostName` and `Port` from its route, `User` and `IdentityFile` from the record, and `IdentitiesOnly yes`. A pinned route adds `UserKnownHostsFile` naming `known_hosts.routes` beside `CLIENT_CONFIG` and `StrictHostKeyChecking yes`; the runner creates that mode-0600 file with `address algorithm key` lines for port 22 and `[address]:port algorithm key` lines for other ports, refusing an existing destination before generating keys. If key generation fails after that write, the companion remains and must be inspected and removed before retrying. The client configuration's parent directory must already exist, and the client configuration must not itself be named `known_hosts.routes`. A route without a key uses `StrictHostKeyChecking accept-new` and prints a comment naming the alias as unpinned. The generated stanza is printed for the caller to install; the tool writes only the pinned companion and key files, and never edits the included client configuration.

A missing variable reports `NAME is required`, a non-UTF-8 variable reports `NAME must be UTF-8`, and either case is a `usage_error` with status 2. A malformed record, including one with a missing, empty, or extra field, reports `LOOP_KEYGEN_SSH_RECORDS line N must contain exactly alias, user, and identity_file separated by tabs` as a `usage_error` with status 2. An `alias` or `user` that is an IP address, a socket address, contains a colon, starts with a hyphen, or contains bytes outside ASCII letters, digits, hyphen, underscore, and dot is refused as `alias_only_addressing` with status 3 before any key command runs.

After generation, output contains both public keys verbatim, the ready-to-send request for the configured coordinator, and the configured SSH records with explicit routes using the Codex worker identity. The private keys remain in `KEYDIR`.

## Account changes · `sec:staffprovision:staff-provision`

```text
Usage:
  superloop account check --server BIRD [--ssh-alias ALIAS] ACCOUNT
  superloop account create --server BIRD [--ssh-alias ALIAS] ACCOUNT --class loop|human --uid UID --key PUBKEY_FILE [--key PUBKEY_FILE]... [--showcase ACCOUNT] [--dry-run]
  superloop account admit-key --server BIRD [--ssh-alias ALIAS] ACCOUNT [--mirror-showcase ACCOUNT] [--key PUBKEY_FILE]... [--dry-run]

Options:
  --server BIRD              Server name; default alias is BIRD-owner
  --ssh-alias ALIAS          Override the owner SSH alias
  --class loop|human         Registry class for create
  --uid UID                  New decimal UID, greater than 1000
  --key PUBKEY_FILE          Public-key input; repeat for multiple files
  --showcase ACCOUNT         Required mirror target for class loop
  --mirror-showcase ACCOUNT  Mirror admitted loop keys to this account
  --dry-run                  Probe and print exact argv without mutations
  -h, --help                 Show this help

admit-key reads public-key lines from standard input when --key is absent.
```

Every remote command uses `ssh` with the pinned host-key file named by `SUPERLOOP_ACCOUNT_KNOWN_HOSTS`, strict host-key checking and the selected alias. Privileged commands continue with `sudo -n`; a nonzero noninteractive-sudo result is a refusal and is never retried. Every command report includes its exact local argv and measured monotonic wall duration. A dry run performs current-state read probes, prints mutation and conditional post-create probe argv plus stdin payloads, and executes no mutation.

### Owner guard · `sec:staffprovision:owner-guard`

Before an existing account can be changed, read-only probes in the same invocation must establish all three conditions:

- its explicit `SELinux` login mapping is exactly `staff_u`;
- its group list does not contain `wheel`; and
- its UID is greater than 1000.

Managed accounts must also use `/var/home/ACCOUNT`, and managed SSH paths cannot be symbolic links or unexpected file kinds. A showcase account receives its own complete guard before any mirror write.

Creation uses the inverse pre-state guard: the account must not exist and the requested UID must be free. The first ordered mutations are `useradd`, the explicit `staff_u` mapping, and password lock. The new account is then re-probed and must pass the ordinary guard before `.ssh`, keys, correspondence, or loop hubs are installed. A failed post-create guard is a critical divergence.

### Subcommands · `sec:staffprovision:subcommands`

`check` is read-only and exits successfully with an existence verdict. For an existing account it reports UID, groups with `wheel` visibly marked as administrative, explicit `SELinux` mapping, home path, `.ssh/`, `authorized_keys`, `git/`, `loops/`, `correspondence/`, and a local `ssh-keygen -lf /dev/stdin` result for every installed noncomment key line.

`create` mirrors the bootstrap account sequence. It creates a private-group Bash account at the requested UID and `/var/home/ACCOUNT`, maps it to `staff_u`, locks its password, installs `.ssh/` at 0700 and `authorized_keys` at 0600, creates `correspondence/` at 0755, and restores `SELinux` file contexts. A loop class additionally creates `git/` and `loops/` at 0755 and requires an explicit guarded showcase account whose installed keys receive the loop keys with exact-line deduplication.

`admit-key` accepts repeated files or standard input. Every input line must contain an OpenSSH type token followed by decodable base64; leading whitespace, trailing whitespace, blank lines, comments, and malformed payloads are refused with the source and one-based line number. Exact installed-line duplicates are skipped. The report identifies every added and skipped source line separately for the target and optional showcase. SSH ownership and modes are converged even when every key is already present. Supplying `--mirror-showcase` declares loop semantics for the emitted registry class; without it, the emitted class is `human`.

After a successful non-dry-run create or admission, the tool re-probes and reports the target, then prints a bootstrap registry block containing:

```text
accounts/ACCOUNT/uid:
UID
accounts/ACCOUNT/class:
CLASS
accounts/ACCOUNT/authorized_keys:
PUBLIC_KEY_LINES
```

The block is intended for the external key-custody registry. Showcase registry key content remains empty; mirrored aggregate keys are installed state, not showcase-owned registry input.

## Exit codes and diagnostics · `sec:staffprovision:exit-codes-and-diagnostics`

Exit status 0 means help or successful completion. Status 1 is a runtime, critical-divergence, or publication failure. Status 2 is invalid usage. Status 3 is a classed input or safety refusal.

Every nonzero path writes ``PROGRAM: CLASS: DETAIL`` to standard error. The complete class list is:

|Class|Condition|
|-----|---------|
|`usage_error`|The command line, name, UID, or environment is invalid.|
|`alias_only_addressing`|A key-generation SSH record alias or user is endpoint-shaped or is not a valid alias token.|
|`path_exists`|A key-generation destination already exists.|
|`public_key_missing`|No public-key lines were supplied.|
|`public_key_malformed`|An input line is not a type token plus decodable base64.|
|`input_failure`|A named key file or standard input cannot be read.|
|`command_failure`|A local command or SSH process cannot be executed.|
|`ssh_failure`|An unprivileged SSH command exits unsuccessfully.|
|`sudo_refused`|A remote `sudo -n` command exits unsuccessfully.|
|`remote_probe_failure`|A read-only remote probe returns invalid state.|
|`account_missing`|An `admit-key` target does not exist.|
|`account_exists`|A `create` target already exists.|
|`uid_taken`|A `create` UID is already assigned.|
|`showcase_required`|A loop-class create omitted its explicit showcase account.|
|`guard_mapping`|A mutation target is not explicitly mapped to `staff_u`.|
|`guard_wheel`|A mutation target belongs to `wheel`.|
|`guard_uid`|A mutation target UID is not greater than 1000.|
|`unsafe_path`|A managed home or SSH path is nonstandard or has an unsafe file kind.|
|`critical_divergence`|A changed account fails post-change verification.|
|`publication_failure`|The tool cannot publish its report or diagnostic.|

## Public account dispatch · `sec:staffprovision:public-account-dispatch`

The package installs one private `account` binary. Public callers use `superloop account keygen|check|create|admit-key`; the root delegates through its configured absolute helper path and preserves exact arguments, streams and status. For account operations, put the verb before `--server BIRD [--ssh-alias ALIAS] ACCOUNT`.

Every remote account operation requires `SUPERLOOP_ACCOUNT_KNOWN_HOSTS` to name an existing absolute regular host-key file. SSH uses strict checking against that file, disables global host-key lookup and updates, and disables connection sharing and local-command hooks. A first-contact check cannot establish trust by writing a new host key; unknown keys refuse. Deploy the reviewed pinned host-key file before switching account callers.
