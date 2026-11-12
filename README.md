# superloop-tools · `guide:publictools:superloop-tools`

superloop-tools is tooling for running and auditing loops of collaborative engineering work. It provides worker lanes, doors that mediate command execution, sign-in homes, a repository linter, and a gate for checking changes before integration.

Slice workers start with the contributing guide (`guide:contributing:superloop-tools`) and read the backlog with its priorities register.

## Build · `sec:publictools:build`

Build the Rust workspace with its pinned toolchain:

```sh
cargo build
```

The workspace builds executable programs and shared libraries. Meson builds and installs the public commands `superloop`, `superloop-mail`, `superloop-lane`, `superloop-runtime`, `superloop-lint`, `superloop-pack`, `superloop-install`, `superloop-gate-submit`, `superloop-capture-admit`, `superloop-chat-export`, `superloop-claude-desktop`, `superloop-correspondence`, `superloop-node-status` and `superloop-steward` into the configured binary directory. ``meson.build`` declares their version identities and installation destinations; the build contract records those identities (`tab:buildcontracts:executable-identities`).

Private helpers, including `build-sync`, `gateway-service`, `gateway-runner`, `worker-run`, `account`, `vendor-proxy`, the permission helpers, the lane door helpers and the `superloop-claude-hook` adapter, install below the configured libexec directory in `superloop`. `superloop-run-report` is built for the workspace and is not installed. Server-kit scripts and units have an explicit opt-in installation (`rule:buildcontracts:server-kits`); a build alone does not deploy or activate them. Package documentation describes each program's commands and configuration.

External users vendor the sources and merge changes as they prefer, maintaining their own lockfile. The public repository therefore carries no ``Cargo.lock`` and pins dependencies at the compatibility major only, certifying no dependency chain.

The contracts live in ``docs/spec/``; the contributing guide describes the build and verification workflow (`sec:contributing:verification`).

## Versioning · `sec:publictools:versioning`

This is version 0.4.2; before 1.0 backwards compatibility is explicitly excluded, every release may change any interface, file format or command, and compatibility code (a reader that accepts an older form, a shim, a deprecated alias) is a defect to be reported, not a courtesy.

## Public releases · `sec:publictools:public-releases`

A public release is a selected source tree with independent Git history. The first release has one root commit; each later release adds one commit over the previous public release. The publication manifest declares the included sources and explains exclusions. A cut requires an explicit publishing identity and both committed licence files.

## Acknowledgements · `sec:publictools:acknowledgements`

We thank the Torrust developers for the tooling that these tools grew beside.

## Licensing · `sec:publictools:licensing`

The code in every first-party crate, including the linter, is licensed under the GNU General Public License version 3 or any later version (`GPL-3.0-or-later`); see `LICENSE-CODE`. The documents are licensed under CC0 1.0 Universal (`CC0-1.0`); see `LICENSE-DOCS`. Third-party notices in the tree keep their own terms.
