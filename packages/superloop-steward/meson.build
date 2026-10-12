# Tier 2; package.version is the version authority; release group steward.
pkg_superloop_steward_rust = files(
  'src/cursor.rs',
  'src/main.rs',
  'src/protocol.rs',
  'src/polling_tests.rs',
  'src/ssh.rs',
  'src/transcript.rs',
  'tests/subprocess_contract.rs',
)
pkg_superloop_steward_prose = files('README.md')
pkg_superloop_steward_toml = []
pkg_superloop_steward_install = []
pkg_superloop_steward_excluded_rust = []
pkg_superloop_steward_excluded_prose = []
pkg_superloop_steward_excluded_toml = []
pkg_superloop_steward_sync_outputs = []
pkg_superloop_steward_sync = custom_target(
  'sync-superloop-steward',
  output: ['superloop-steward', 'superloop-steward.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-steward', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-steward', 'superloop-steward', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_steward_sync_outputs += pkg_superloop_steward_sync

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-steward","manifest":"packages/superloop-steward/Cargo.toml","tier":2,"release_group":"steward","version_authority":"packages/superloop-steward/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-steward","output":"packages/superloop-steward/superloop-steward","package":"superloop-steward","version_authority":"packages/superloop-steward/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-steward","callers":["release-suite","superloop-steward"]}
{"kind":"program","identity":"infra/steward/transcript-export","source":"infra/steward/transcript-export","output":"versioned-infra-steward-transcript-export","package":"superloop-steward","version_authority":"packages/superloop-steward/Cargo.toml","release_group":"steward","form":"shell","installation_class":"infra","callers":["release-suite","superloop-steward"]}
{"kind":"program","identity":"infra/steward/steward-runner","source":"infra/steward/steward-runner","output":"versioned-infra-steward-steward-runner","package":"superloop-steward","version_authority":"packages/superloop-steward/Cargo.toml","release_group":"steward","form":"shell","installation_class":"infra","callers":["release-suite","superloop-steward"]}
{"kind":"program","identity":"infra/steward/steward-spool-append","source":"infra/steward/steward-spool-append","output":"versioned-infra-steward-steward-spool-append","package":"superloop-steward","version_authority":"packages/superloop-steward/Cargo.toml","release_group":"steward","form":"shell","installation_class":"infra","callers":["release-suite","superloop-correspondence","superloop-steward"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-steward/tests/subprocess_contract.rs:self . root . path () . join (\"ssh\")#1","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"self . root . path () . join (\"ssh\")","callee":"external:ssh","lookup":"test-executable","setting":"fixture-root ssh stub","contract":"Retry transient ETXTBSY and observe prepared list and raw read reply bytes before starting the production client deadline"}
{"kind":"call","site":"packages/superloop-steward/src/ssh.rs:\"ssh\"#1","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"\"ssh\"","callee":"external:ssh","lookup":"public-command","contract":"SSH noninteractive remote command transport using the declared alias and configuration"}
{"kind":"call","site":"packages/superloop-steward/src/ssh.rs:\"timeout\"#1","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"\"timeout\"","callee":"external:timeout","lookup":"public-command","contract":"Bound child wall time and propagate the specified timeout status"}
{"kind":"call","site":"packages/superloop-steward/tests/subprocess_contract.rs:\"bash\"#1","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"\"bash\"","callee":"external:bash","lookup":"public-command","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-steward/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-steward\")#1","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"env ! (\"CARGO_BIN_EXE_superloop-steward\")","callee":"bin/superloop-steward","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-steward"}
{"kind":"call","site":"packages/superloop-steward/tests/subprocess_contract.rs:\"python3\"#1","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"\"python3\"","callee":"external:python3","lookup":"public-command","contract":"Python 3 payload execution; the caller supplies the program and its bounded input/output contract"}
{"kind":"call","site":"packages/superloop-steward/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-steward\")#2","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"env ! (\"CARGO_BIN_EXE_superloop-steward\")","callee":"bin/superloop-steward","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-steward"}
{"kind":"call","site":"packages/superloop-steward/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-steward\")#3","caller":"superloop-steward","owner":"SUPERLOOPSTEWARD","selector":"env ! (\"CARGO_BIN_EXE_superloop-steward\")","callee":"bin/superloop-steward","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-steward"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-steward/meson.build:custom_target#1","sha256":"66e294e0b8a4f1c5a35501e4dd171bc8fa8ce6c58819fc209911c47e9e948e60","caller":"meson:superloop-steward","owner":"superloop-steward","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"9f3c8ccbbcdef5fa1d8b61aacbf9e73c26892f497b04b39da321feb3e26b2458"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-steward/meson.build:find_program#1","caller":"meson:superloop-steward","owner":"superloop-steward","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"9f3c8ccbbcdef5fa1d8b61aacbf9e73c26892f497b04b39da321feb3e26b2458"}
''']
