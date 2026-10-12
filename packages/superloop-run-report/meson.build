pkg_superloop_run_report_rust = files(
  'src/bin/superloop-run-report.rs',
  'src/lib.rs',
  'src/tests/mod.rs',
  'tests/subprocess_contract.rs',
)

pkg_superloop_run_report_prose = files(
  'README.md',
)

pkg_superloop_run_report_toml = []

pkg_superloop_run_report_install = []

pkg_superloop_run_report_excluded_rust = []

pkg_superloop_run_report_excluded_prose = []

pkg_superloop_run_report_excluded_toml = []

pkg_superloop_run_report_sync_outputs = []

pkg_superloop_run_report_sync_run_report = custom_target(
  'sync-superloop-run-report',
  output: ['superloop-run-report', 'superloop-run-report.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-run-report', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-run-report', 'superloop-run-report', '@OUTPUT0@'],
  build_by_default: true,
)
pkg_superloop_run_report_sync_outputs += pkg_superloop_run_report_sync_run_report

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-run-report","manifest":"packages/superloop-run-report/Cargo.toml","tier":2,"release_group":"superloop-run-report","version_authority":"packages/superloop-run-report/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"build/superloop-run-report","output":"packages/superloop-run-report/superloop-run-report","package":"superloop-run-report","version_authority":"packages/superloop-run-report/Cargo.toml","form":"rust","installation_class":"build","cargo_binary":"superloop-run-report","callers":["release-suite","superloop-run-report"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-run-report/src/lib.rs:\"df\"#1","caller":"superloop-run-report","owner":"SUPERLOOPRUNREPORT","selector":"\"df\"","callee":"external:df","lookup":"public-command","contract":"Report available filesystem capacity in the requested numeric form"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-run-report/tests/subprocess_contract.rs:BINARY#1","caller":"superloop-run-report","owner":"SUPERLOOPRUNREPORT","selector":"BINARY","callee":"build/superloop-run-report","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-run-report","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-run-report/meson.build:custom_target#1","sha256":"4dd344d0a75912f55944cbf8c736360a9b2b01f0f282b9ba39ec4f4d2f645e5b","caller":"meson:superloop-run-report","owner":"superloop-run-report","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"15cd8f1ce4fa7b64f89d0d5cf9a866c1877d66b08d4d7a9eb0e4477c496c5bcb"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-run-report/meson.build:find_program#1","caller":"meson:superloop-run-report","owner":"superloop-run-report","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"15cd8f1ce4fa7b64f89d0d5cf9a866c1877d66b08d4d7a9eb0e4477c496c5bcb"}
''']
