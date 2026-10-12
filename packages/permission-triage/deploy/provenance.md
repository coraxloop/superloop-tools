# Permission tool provenance

Build the reviewed source on the deployment host through the native Meson workspace producer. The source root selects the pinned Rust toolchain. Set the installation prefix and private paths before building; the adapter and its permission helper must agree on the configured helper path. Assembly queries `PERMISSION_TRIAGE_HOOK_BIN` for the general-rubric digest and renders `PERMISSION_TRIAGE_ADAPTER_BIN` into the registration. Both settings are absolute paths.

```sh
meson setup --reconfigure -Ddomain=server --prefix "$TRIAGE_PREFIX" "$TRIAGE_BUILD" "$TRIAGE_TOOLS"
ninja -C "$TRIAGE_BUILD"
meson install -C "$TRIAGE_BUILD" --no-rebuild --tags harness-private --destdir "$TRIAGE_STAGE/root"
```

Review the staged adapter and permission hook under `libexec/superloop/hooks`, and `requests-helper`, `permission-triage-topology` and `permission-triage-assemble` under `libexec/superloop`. Their individually named JSON build records install under `share/superloop/build-records`; compare source commit, release group, version, compiler and artifact digest. Every executable answers `--version` with its installed-name control-plane record. The topology harness version and SHA-256 remain separate: readiness `binary_digest` names that harness, not the hook or classifier. Preserve the source and staged records with the owner review.

First install the private successors, retain the previous release and rollback settings, and follow the registration read-back and session-drain protocol in the integration runbook. Installation does not change host settings, a live instance or an existing worker home. Assembly always renders audit. A fake-harness rehearsal cannot authorize enforcement.

After the orchestrator has proved the drain, stage retirement against separately reviewed old and new home-prefix inventories. Select only `.claude/hooks/permission-triage`, `.claude/hooks/permission-triage-hook`, `.claude/hooks/permission-triage-review` and `.claude/hooks/permission-triage-topology`, each with its `.provenance` sibling. Preserve each recovery place and require a second retirement to report zero changes. The remaining heartbeat and orchestrator hooks retire with the subject-root bite.

The orchestrator performs live placement and registration under the hold after reviewing staging, source identities, registry and domain digests, the declared session inventory and the real-harness rehearsal. Estate journals and outboxes are inspected through the superloop's own loop instance; another loop's helper does not read them. Preserve their required observation evidence separately. Follow the assembly and settings runbooks for the audit observation window and the separately authorized enforce transition. On rollback, stop bypass sessions or restore their ordinary gate before restoring settings; retain the deployment record and journal evidence.
