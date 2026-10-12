pkg_session_core_rust = files(
  'src/heartbeat.rs',
  'src/heartbeat_toggle.rs',
  'src/letters.rs',
  'src/lib.rs',
  'src/orchestrator.rs',
  'src/orchestrator/tests.rs',
  'src/orchestrator_toggle.rs',
  'src/pre_tool.rs',
  'src/project_root.rs',
  'src/sha256.rs',
)

pkg_session_core_prose = files('README.md')
pkg_session_core_toml = []
pkg_session_core_install = []
pkg_session_core_excluded_rust = []
pkg_session_core_excluded_prose = []
pkg_session_core_excluded_toml = []
pkg_session_core_sync_outputs = []

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"session-core","manifest":"packages/session-core/Cargo.toml","tier":1,"release_group":"session-core","version_authority":"packages/session-core/Cargo.toml"}
''']
