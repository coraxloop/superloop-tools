## Serve process boundary · `sec:lanegateway:bin-serve-process-boundary`

The `serve` action loads the required typed runner prefix plus polling, shutdown, result-size, and positive heartbeat-cadence overrides before entering `Gateway::serve`. A clean supervised return exits zero with empty stdout. Every returned serve error, caught panic, publisher failure, or crash-report failure exits one with empty stdout and ADR-001 machine JSON on stderr.

When crash-report publication fails, `GatewayError::CrashReportWriteFailed` retains the original serve failure. The binary emits that original diagnostic first and the fixed `serve crash report write failed` diagnostic second, preserving both facts while remaining nonzero. It never prints caller argv, reasons, paths, runner output, panic debug representations, or credentials.

## Unit test matrix · `tab:lanegateway:bin-unit-test-matrix`

**Table (Unit test matrix)**

No unit tests in this folder.
