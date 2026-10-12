# Orchestrator oracle fixtures · `guide:orchestratorfixtures:orchestrator-oracle-fixtures`

`capture_python_oracle.py` drives the retired Python implementation at `packages/orchestrator-hook/reference/orchestrator.py` (fixture-class evidence; the Rust binary is the deployed hook) with synthetic payloads and isolated `ORCHESTRATOR_STATE_DIR` and `ORCHESTRATION_FILE` values. It fixes rulebook modification stamps and normalizes temporary state paths before committing each JSON fixture.

The ten original captures predate the Rust port and were produced against the retired hook script, while `spec-project-root-disable.json` was captured from the committed reference oracle by the retargeted script, which is also the capture path for every future fixture.

Each fixture records its payload, state precondition, expected standard output, and authority. Python-authority fixtures characterize behavior where the reference and ratified hook specification agree. Spec-authority fixtures name a documented divergence and record both the specified effect and Python's differing effect. For a spec-authority output divergence, `expected_stdout` holds the specified hook bytes and `python_effect.stdout` holds the retired oracle bytes.

Run `python3 packages/orchestrator-hook/tests/fixtures/capture_python_oracle.py` from any directory to regenerate the corpus.
