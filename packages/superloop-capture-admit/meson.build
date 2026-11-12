# Tier 2; package.version is the version authority; release group superloop-capture-admit.
pkg_superloop_capture_admit_rust = files(
  'src/main.rs',
  'src/cli.rs',
  'src/manifest.rs',
  'src/copy.rs',
  'src/store.rs',
  'tests/subprocess_contract.rs',
)
pkg_superloop_capture_admit_prose = files('README.md')
pkg_superloop_capture_admit_toml = []
pkg_superloop_capture_admit_install = []
pkg_superloop_capture_admit_excluded_rust = []
pkg_superloop_capture_admit_excluded_prose = []
pkg_superloop_capture_admit_excluded_toml = []
pkg_superloop_capture_admit_sync_outputs = []
pkg_superloop_capture_admit_sync = custom_target(
  'sync-superloop-capture-admit',
  output: ['superloop-capture-admit', 'superloop-capture-admit.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-capture-admit', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-capture-admit', 'superloop-capture-admit', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_capture_admit_sync_outputs += pkg_superloop_capture_admit_sync

# Machine-readable Meson ledger rows.
dependency_ledger += ['''
{"kind":"package","name":"superloop-capture-admit","manifest":"packages/superloop-capture-admit/Cargo.toml","tier":2,"release_group":"superloop-capture-admit","version_authority":"packages/superloop-capture-admit/Cargo.toml"}
{"kind":"program","identity":"bin/superloop-capture-admit","output":"packages/superloop-capture-admit/superloop-capture-admit","package":"superloop-capture-admit","version_authority":"packages/superloop-capture-admit/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-capture-admit","callers":["release-suite","superloop-capture-admit"]}
{"kind":"call","site":"packages/superloop-capture-admit/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-capture-admit\")#1","caller":"superloop-capture-admit","owner":"SUPERLOOPCAPTUREADMIT","selector":"env ! (\"CARGO_BIN_EXE_superloop-capture-admit\")","callee":"bin/superloop-capture-admit","lookup":"test-executable","contract":"Cargo supplies the capture admission binary to its subprocess contract tests","binding":"CARGO_BIN_EXE_superloop-capture-admit"}
{"kind":"meson-call","site":"packages/superloop-capture-admit/meson.build:custom_target#1","sha256":"e8e1b6034959ec892ee3a82ae51fc015509857b900bcbc17f1ac4541e69b10a1","caller":"meson:superloop-capture-admit","owner":"superloop-capture-admit","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"da9c283a0062e65119a4afbef4780819af7a55eac216da2cea6b6446b1012463"}
{"kind":"meson-call","site":"packages/superloop-capture-admit/meson.build:find_program#1","caller":"meson:superloop-capture-admit","owner":"superloop-capture-admit","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"da9c283a0062e65119a4afbef4780819af7a55eac216da2cea6b6446b1012463"}
''']
