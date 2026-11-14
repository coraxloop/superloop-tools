# Tier 2; package.version is the version authority; release group credential-custody.
pkg_superloop_credential_custody_rust = files(
  'src/main.rs',
  'src/record.rs',
  'src/receipt.rs',
  'src/process.rs',
  'src/observe.rs',
  'src/identity.rs',
  'tests/subprocess_contract.rs',
)
pkg_superloop_credential_custody_prose = files('README.md')
pkg_superloop_credential_custody_toml = []
pkg_superloop_credential_custody_install = []
pkg_superloop_credential_custody_excluded_rust = []
pkg_superloop_credential_custody_excluded_prose = []
pkg_superloop_credential_custody_excluded_toml = []
pkg_superloop_credential_custody_sync_outputs = []
pkg_superloop_credential_custody_sync = custom_target(
  'sync-superloop-credential-custody',
  output: ['superloop-credential-custody', 'superloop-credential-custody.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-credential-custody', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-credential-custody', 'superloop-credential-custody', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_credential_custody_sync_outputs += pkg_superloop_credential_custody_sync

# Machine-readable Meson ledger rows.
dependency_ledger += ['''
{"kind":"package","name":"superloop-credential-custody","manifest":"packages/superloop-credential-custody/Cargo.toml","tier":2,"release_group":"credential-custody","version_authority":"packages/superloop-credential-custody/Cargo.toml"}
{"kind":"program","identity":"bin/superloop-credential-custody","output":"packages/superloop-credential-custody/superloop-credential-custody","package":"superloop-credential-custody","version_authority":"packages/superloop-credential-custody/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-credential-custody","callers":["release-suite","superloop-credential-custody"]}
{"kind":"call","site":"packages/superloop-credential-custody/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-credential-custody\")#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"env ! (\"CARGO_BIN_EXE_superloop-credential-custody\")","callee":"bin/superloop-credential-custody","lookup":"test-executable","contract":"Cargo supplies the credential custody binary to its subprocess contract tests","binding":"CARGO_BIN_EXE_superloop-credential-custody"}
{"kind":"meson-call","site":"packages/superloop-credential-custody/meson.build:custom_target#1","sha256":"c03d84c9dc5dce5a02aced3354bfdf6ff45cf8d57d56438f7926d66670e08923","caller":"meson:superloop-credential-custody","owner":"superloop-credential-custody","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"9ca52a0fb954a0666adc2b1183df226aa5d8319318570c7f7d6abb2a6ad47070"}
{"kind":"meson-call","site":"packages/superloop-credential-custody/meson.build:find_program#1","caller":"meson:superloop-credential-custody","owner":"superloop-credential-custody","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"9ca52a0fb954a0666adc2b1183df226aa5d8319318570c7f7d6abb2a6ad47070"}
{"kind":"call","site":"packages/superloop-credential-custody/src/identity.rs:& probe . argv [0]#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"& probe . argv [0]","callee":"external:credential-identity-probe","lookup":"configured-external","contract":"Bounded metadata-only execution with empty environment; source extraction and isolated parser are fixed argv; probes use reviewed exact vectors","setting":"parameters.probes[].argv"}
{"kind":"call","site":"packages/superloop-credential-custody/src/observe.rs:\"/usr/bin/git\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"private-exact-path","contract":"Bounded metadata-only execution with empty environment; source extraction and isolated parser are fixed argv; probes use reviewed exact vectors"}
{"kind":"call","site":"packages/superloop-credential-custody/src/observe.rs:\"/usr/bin/python3\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/python3\"","callee":"external:/usr/bin/python3","lookup":"private-exact-path","contract":"Bounded metadata-only execution with empty environment; source extraction and isolated parser are fixed argv; probes use reviewed exact vectors"}
{"kind":"call","site":"packages/superloop-credential-custody/tests/subprocess_contract.rs:\"/usr/bin/git\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"private-exact-path","contract":"Bounded metadata-only execution with empty environment; source extraction and isolated parser are fixed argv; probes use reviewed exact vectors"}
{"kind":"external-program","identity":"external:credential-identity-probe","selector":"parameters.probes[].argv[0]","contract":"Operator-reviewed exact metadata probe vector; no shell interpretation or raw diagnostic relay","callers":["superloop-credential-custody"]}
{"kind":"data","identity":"credential-parameters","writer":"external:operator","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Strict versioned bounded JSON metadata; digest-only probe identities and independently protected reviewed references","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/record.rs","anchor":"pub struct Parameters"},{"path":"packages/superloop-credential-custody/src/record.rs","anchor":"pub struct Discovery"}]}
{"kind":"data","identity":"credential-calibration","writer":"superloop-credential-custody","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Strict versioned bounded JSON metadata; digest-only probe identities and independently protected reviewed references","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/observe.rs","anchor":"pub fn validate"}]}
''']
