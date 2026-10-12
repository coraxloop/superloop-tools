pkg_superloop_execwrap_rust = files(
  'src/lib.rs',
  'src/tests/mod.rs',
  'src/writer.rs',
  'tests/subprocess_contract.rs',
)

pkg_superloop_execwrap_prose = files(
  'README.md',
)

pkg_superloop_execwrap_toml = []

pkg_superloop_execwrap_install = []

pkg_superloop_execwrap_excluded_rust = []

pkg_superloop_execwrap_excluded_prose = []

pkg_superloop_execwrap_excluded_toml = []

pkg_superloop_execwrap_sync_outputs = []

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-execwrap","manifest":"packages/superloop-execwrap/Cargo.toml","tier":1,"release_group":"superloop-execwrap","version_authority":"packages/superloop-execwrap/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-execwrap/src/lib.rs:program#1","caller":"superloop-execwrap","owner":"SUPERLOOPEXECWRAP","selector":"program","callee":"external:wrapped-command","lookup":"configured-external","setting":"ExecConfig argv","contract":"Execute the supplied program and arguments; relay bounded process streams and preserve the wrapper status contract"}
{"kind":"call","site":"packages/superloop-execwrap/tests/subprocess_contract.rs:std :: env :: current_exe () . expect (\"test executable\")#1","caller":"superloop-execwrap","owner":"SUPERLOOPEXECWRAP","selector":"std :: env :: current_exe () . expect (\"test executable\")","callee":"fixture:superloop-execwrap:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
''']
