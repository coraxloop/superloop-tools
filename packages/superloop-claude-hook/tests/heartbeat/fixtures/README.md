# Heartbeat-guard oracle fixtures · `guide:heartbeatfixtures:heartbeat-guard-oracle-fixtures`

`capture_python_oracle.py` runs the retired Python implementation at `packages/superloop-claude-hook/reference/heartbeat/heartbeat-guard.py` (fixture-class evidence; the Rust binary is the deployed hook) with an isolated `HOME`, so neither capture nor Rust tests touch the operator's Claude state. It normalizes only measured wall times. The captured status is intentionally one: the deployed audit still expects the retired user-directed warning behavior in six cases, while the deployed guard source and the ratified specification deliver an agent-directed correction block.

The retired Python implementation keys the heartbeat flag on the raw working directory, while the deployed guard keys it on the resolved project root, so they agree only for a repository-root or marker-less working directory, and the capture remains fixture-class evidence of the retired behavior.

The specification fixtures name source-level differences where the ratified contract governs over deployed Python:

- `spec-block-stderr.json` records the hook-JSON process adapter's stderr/status-2 block instead of Python's stdout/status-0 decision object.
- `spec-invalid-field-fail-open.json` records output-free fail-open instead of Python's uncaught type failure.
- `spec-unreadable-state-fail-open.json` records the fail-open safety edge instead of fabricating a prompt from an unreadable counter.
- `spec-state-write-fail-open.json` records the anti-wedge edge when a counter or warning cannot be persisted.
- `spec-nonnumeric-delay.json` records the numeric-delay requirement instead of Python's string-to-float coercion.
- `spec-list-feedback-turn-marker.json` records that list-form guard feedback does not create a real-user-turn marker.
