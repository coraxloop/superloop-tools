version_smoke_checker = files('version-smoke.py')

harness_runs = files(
  '../infra/cargo-clean/tests/run.sh',
  '../infra/correspondence-watch/tests/run.sh',
  '../infra/steward/tests/run.sh',
  'gateway-runner-run.sh',
  'gate-slot-run.sh',
  'gate-sample-run.sh',
  'loop-codex-home-run.sh',
  'run.sh',
  'steward-run.sh',
)

harnesses = harness_runs + files(
  'conductor-fake-notify',
  'fake-ssh',
  'steward-fake-claude',
  'steward-fake-exporter',
  'steward-fake-ssh',
)
