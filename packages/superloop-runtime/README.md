# Runtime environments · `guide:runtime:runtime-environments`

`superloop-runtime` is the tier 2 runtime release group. Its root `--version` emits the installed-name JSON version record. An agent version query follows a command, such as `superloop-runtime exec -- --version`; agent arguments, streams and exit status pass through without becoming runtime output.

## Commands and settings · `sec:runtime:commands-and-settings`

|Command|Effect|Settings|
|-------|------|--------|
|`create`|Create and prepare the named runtime container; repeat a completed matching configuration without changing it.|`HOME`, optional `SUPERLOOP_RUNTIME_IMAGE`, `SUPERLOOP_RUNTIME_ENGINE_ARGV`.|
|`exec`|Start a stopped runtime container and execute the selected agent with the caller's cwd, uid, gid and streams.|`CODEX_REAL_BIN`, `HOME`, `CODEX_HOME`, `TMPDIR`, terminal dimensions and engine selector.|
|`run-host`|Escape a toolbox through the host portal when reachable, otherwise execute the selected agent in place.|Agent selector, home, cwd, agent environment and portal selector.|
|`run-toolbox`|Launch Claude through the selected toolbox, forwarding its home and temporary root explicitly.|Required `CLAUDE_TOOLBOX` and `CLAUDE_CONFIG_DIR`, optional `TMPDIR` and portal selector.|

`CODEX_REAL_BIN` defaults beneath the current home to the installed standalone Codex program. `SUPERLOOP_RUNTIME_ENGINE_ARGV` is a JSON executable argument array; an empty or malformed array refuses. Without it, the engine is `podman` on the host and the host portal's `podman` inside a container. `SUPERLOOP_RUNTIME_PORTAL` selects the portal executable, default `flatpak-spawn`. `SUPERLOOP_RUNTIME_CONTAINER_MARKER` selects the container marker path, default `/run/.containerenv`. These selectors let the fixture exercise both execution environments without using a real engine. The default image is `registry.fedoraproject.org/fedora-toolbox:44`; a configured image is part of the container identity.

The container is named `superloop-runtime`. Creation binds its image, calling uid and gid, home and preparation payload into an identity label. A different existing configuration refuses before mutation. A matching ready container repeats with reads only; an interrupted matching preparation can finish before the readiness record is published. The private temporary mount, shared host PID namespace and caller watchdog preserve the agent's sandbox and ensure a killed runtime client does not leave its agent running. Embedded shell payloads execute inside the container and version with this package.

## Staged deployment and migration · `sec:runtime:staged-deployment-and-migration`

Build and test the workspace, then review two native staging installs. The binary installs into `bindir` with its build record in the data directory, and the user unit installs into `share/systemd/user`. No staging step starts a container or a unit.

|Retired installed form|Successor|
|----------------------|---------|
|`codex-rt ARG…`, its `codex ARG…` copy|`superloop-runtime exec -- ARG…`|
|`codex-host ARG…`|`superloop-runtime run-host -- ARG…`|
|`claude-in-loops ARG…`|`superloop-runtime run-toolbox -- ARG…`|
|`codex-rt-create` with no arguments|`superloop-runtime create`|
|`codex-rt-create --version`|`superloop-runtime --version`|
|``codex-rt.service`` and container `codex-rt`|``superloop-runtime.service`` and container `superloop-runtime`|

The three argument adapters had no dispatcher: their `--version` queried the agent. Those queries retain that meaning after the execution verb. The retired destination inventory includes `bin/codex-rt`, `bin/codex`, `bin/codex-host`, `bin/claude-in-loops`, `bin/codex-rt-create`, their `.provenance` siblings, and the old unit in the user unit directory. The retirement command consumes the old and new staged inventories, explicitly selects these destinations, and records verified recovery copies; a second invocation changes nothing.

The orchestrator drains every loop's lanes before the live switch. Record the old container and user unit states, the configured backend arrays, program hashes and recovery places. Install the new runtime, create its named container and switch the user unit to `superloop-runtime.service`. Set each loop's `backend_argv.codex` to the installed binary and `exec` or `run-host` as reviewed, and `backend_argv.claude` to the installed binary and `run-toolbox`. Retire the five old wrapper destinations and their provenance siblings, the old user unit and container after the configured callers move; no alias or old name is read by the runtime.

Prove each command, an agent version query through all three execution commands, one lane step for each configured backend, and unchanged second creation and install. Restore only the recorded enabled and active unit states. Report old and new container and unit states, the absence of in-flight lanes, configured argv changes, digests and retirement recovery places. The runtime's repository tests use a fake engine and portal; actual container and per-loop deployment proofs belong to the orchestrator.
