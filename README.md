# superloop-tools · `guide:publictools:superloop-tools`

superloop-tools is tooling for running and auditing loops of collaborative engineering work. It provides worker lanes, doors that mediate command execution, sign-in homes, a repository linter, and a gate for checking changes before integration.

## Build · `sec:publictools:build`

Build the Rust workspace with its pinned toolchain:

```sh
cargo build
```

The project produces no binaries; whoever uses the repository externally vendors it and merges its changes as they prefer, maintaining their own lockfile; the public repository therefore carries no ``Cargo.lock`` and pins its dependencies at the compatibility major only, certifying no dependency chain.

The workspace contains the individual tools and shared libraries. The contracts live in `docs/spec/`; package documentation describes each tool's commands and configuration.

## Versioning · `sec:publictools:versioning`

This is version 0.4.1; before 1.0 backwards compatibility is explicitly excluded, every release may change any interface, file format or command, and compatibility code (a reader that accepts an older form, a shim, a deprecated alias) is a defect to be reported, not a courtesy.

## Public releases · `sec:publictools:public-releases`

A public release is a selected source tree with independent Git history. The first release has one root commit; each later release adds one commit over the previous public release. The publication manifest declares the included sources and explains exclusions. A cut requires an explicit publishing identity and both committed licence files.

## Acknowledgements · `sec:publictools:acknowledgements`

We thank the Torrust developers for the tooling that these tools grew beside.

## Licensing · `sec:publictools:licensing`

The code in every first-party crate, including the linter, is licensed under the GNU General Public License version 3 or any later version (`GPL-3.0-or-later`); see `LICENSE-CODE`. The documents are licensed under CC0 1.0 Universal (`CC0-1.0`); see `LICENSE-DOCS`. Third-party notices in the tree keep their own terms.
