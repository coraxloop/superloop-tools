pkg_request_core_rust = files(
  'src/lib.rs',
  'src/gateway.rs',
  'src/model.rs',
  'src/review.rs',
  'src/transaction.rs',
  'tests/transaction.rs',
  'tests/gateway.rs',
  'tests/transitions.rs',
)

pkg_request_core_prose = files('README.md')
pkg_request_core_toml = []
pkg_request_core_install = []
pkg_request_core_excluded_rust = []
pkg_request_core_excluded_prose = []
pkg_request_core_excluded_toml = []
pkg_request_core_sync_outputs = []

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"request-core","manifest":"packages/request-core/Cargo.toml","tier":1,"release_group":"request-core","version_authority":"packages/request-core/Cargo.toml"}
''']
