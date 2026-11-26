# superloop-tools · `guide:publictools:superloop-tools`

superloop-tools is tooling for running and auditing loops of collaborative engineering work. It provides worker lanes, doors that mediate command execution, sign-in homes, a repository linter, and a gate for checking changes before integration.

**Principle (Well made and good to use)** · `prin:publictools:well-made-and-good-to-use`

These tools are well made and ergonomic in the practical sense: they are designed for the comfort and efficiency of whoever calls and operates them, when an operation goes wrong as much as when it goes right. A friction met in their use is therefore read as one of two things: a manufacturing defect, ground down where it is; or, more often, the symptom of an engineering or design question that was settled without its user's comfort and efficiency in mind, and then the repair goes to that question and to wherever else it was left unasked, not only to the place where the friction surfaced. A loop and its workers act through these tools all day, so an awkward tool is paid for at every use, and a user who cannot see, stop or recover an operation works around it.

Slice workers start with the contributing guide (`guide:contributing:superloop-tools`) and read the backlog with its priorities register.

## Build · `sec:publictools:build`

Build the Rust workspace with its pinned toolchain:

```sh
cargo build
```

The workspace builds executable programs and shared libraries. The rehearsal-only `credential-fixture` and its build record are available in the build tree and are not installed by Meson. Meson builds and installs the public commands `superloop`, `superloop-mail`, `superloop-lane`, `superloop-runtime`, `superloop-lint`, `superloop-pack`, `superloop-install`, `superloop-gate-submit`, `superloop-capture-admit`, `superloop-credential-custody`, `superloop-chat-export`, `superloop-claude-desktop`, `superloop-correspondence`, `superloop-node-status` and `superloop-steward` into the configured binary directory. ``meson.build`` declares their version identities and installation destinations; the build contract records those identities (`tab:buildcontracts:executable-identities`).

Private helpers, including `build-sync`, `gateway-service`, `gateway-runner`, `worker-run`, `account`, `vendor-proxy`, the permission helpers, the lane door helpers and the `superloop-claude-hook` adapter, install below the configured libexec directory in `superloop`. `superloop-run-report` is built for the workspace and is not installed. Server-kit scripts and units have an explicit opt-in installation (`rule:buildcontracts:server-kits`); a build alone does not deploy or activate them. Package documentation describes each program's commands and configuration.

External users vendor the sources and merge changes as they prefer, maintaining their own lockfile. The public repository therefore carries no ``Cargo.lock`` and pins dependencies at the compatibility major only, certifying no dependency chain.

Design records in ``docs/design/`` preserve reasoning and open choices without defining contracts or promising implementation; the scope-floor record explains directory and expansion limits (`rec:scopefloor:directory-and-expansion`).

The contracts live in ``docs/spec/``; the contributing guide describes the build and verification workflow (`sec:contributing:verification`).

The concurrent request-store concept (`proposal:requeststore:concurrent-custody`) derives proposed custody properties and separates per-request publication from the cross-request decisions needed to replace collection-wide locking.

## Versioning · `sec:publictools:versioning`

This is version 0.13.3; before 1.0 backwards compatibility is explicitly excluded, every release may change any interface, file format or command, and compatibility code (a reader that accepts an older form, a shim, a deprecated alias) is a defect to be reported, not a courtesy.

## Public releases · `sec:publictools:public-releases`

A public release is a selected source tree with independent Git history. The first release has one root commit; each later release adds one commit over the previous public release. The publication manifest declares the included sources and explains exclusions. A cut requires an explicit publishing identity and both committed licence files.

## Acknowledgements · `sec:publictools:acknowledgements`

We thank the Torrust developers for the tooling that these tools grew beside.

## Licensing · `sec:publictools:licensing`

The code in every first-party crate, including the linter, is licensed under the GNU General Public License version 3 or any later version (`GPL-3.0-or-later`); see `LICENSE-CODE`. The documents are licensed under CC0 1.0 Universal (`CC0-1.0`); see `LICENSE-DOCS`. Third-party notices in the tree keep their own terms.
