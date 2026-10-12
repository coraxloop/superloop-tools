pkg_execute_command_rust = files(
  'src/lib.rs',
  'src/request.rs',
  'src/checks.rs',
  'src/checks/hygiene.rs',
  'src/checks/compute.rs',
  'src/policy.rs',
  'src/rubric.rs',
  'src/snapshot.rs',
  'src/triage.rs',
  'src/escalation.rs',
  'src/record.rs',
  'src/learning.rs',
  'src/process.rs',
  'tests/shapes.rs',
  'tests/persistence.rs',
  'tests/support/mod.rs',
  'src/checks/hygiene_parity.rs',
  'tests/checks_parity.rs',
  'tests/policy_parity.rs',
  'tests/triage.rs',
  'tests/learning.rs',
  'tests/process.rs',
)
pkg_execute_command_prose = files('README.md')
pkg_execute_command_toml = []
pkg_execute_command_install = []
pkg_execute_command_excluded_rust = []
pkg_execute_command_excluded_prose = []
pkg_execute_command_excluded_toml = []
pkg_execute_command_sync_outputs = []

dependency_ledger += ['''
{"kind":"package","name":"execute-command","manifest":"packages/execute-command/Cargo.toml","tier":1,"release_group":"execute-command","version_authority":"packages/execute-command/Cargo.toml"}
''']
