# Tier 2; package.version is the version authority; release group correspondence.
pkg_superloop_correspondence_rust = files(
  'src/cursor.rs',
  'src/main.rs',
  'src/ssh.rs',
  'tests/subprocess_contract.rs',
)
pkg_superloop_correspondence_prose = files('README.md')
pkg_superloop_correspondence_toml = []
pkg_superloop_correspondence_install = []
pkg_superloop_correspondence_excluded_rust = []
pkg_superloop_correspondence_excluded_prose = []
pkg_superloop_correspondence_excluded_toml = []
pkg_superloop_correspondence_sync_outputs = []
pkg_superloop_correspondence_sync = custom_target(
  'sync-superloop-correspondence',
  output: ['superloop-correspondence', 'superloop-correspondence.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-correspondence', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-correspondence', 'superloop-correspondence', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_correspondence_sync_outputs += pkg_superloop_correspondence_sync

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-correspondence","manifest":"packages/superloop-correspondence/Cargo.toml","tier":2,"release_group":"correspondence","version_authority":"packages/superloop-correspondence/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-correspondence","output":"packages/superloop-correspondence/superloop-correspondence","package":"superloop-correspondence","version_authority":"packages/superloop-correspondence/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-correspondence","callers":["release-suite","superloop-correspondence"]}
{"kind":"program","identity":"infra/correspondence-watch/correspondence-scan","source":"infra/correspondence-watch/correspondence-scan","output":"versioned-infra-correspondence-watch-correspondence-scan","package":"superloop-correspondence","version_authority":"packages/superloop-correspondence/Cargo.toml","release_group":"correspondence","form":"shell","installation_class":"infra","callers":["release-suite","superloop-correspondence"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:& stub#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"& stub","callee":"external:ssh","lookup":"test-executable","setting":"fixture-root ssh stub with a deliberately held writer","contract":"Force ETXTBSY, release the executable writer on the first busy result, and prove readiness succeeds without a sleep"}
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:self . root . path () . join (\"ssh\")#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"self . root . path () . join (\"ssh\")","callee":"external:ssh","lookup":"test-executable","setting":"fixture-root ssh stub","contract":"Run the fixture-placed SSH stub with --fixture-ready and observe its prepared reply before arming the production command deadline"}
{"kind":"call","site":"packages/superloop-correspondence/src/ssh.rs:\"ssh\"#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"\"ssh\"","callee":"external:ssh","lookup":"public-command","contract":"SSH noninteractive remote command transport using the declared alias and configuration"}
{"kind":"call","site":"packages/superloop-correspondence/src/ssh.rs:\"timeout\"#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"\"timeout\"","callee":"external:timeout","lookup":"public-command","contract":"Bound child wall time and propagate the specified timeout status"}
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-correspondence\")#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"env ! (\"CARGO_BIN_EXE_superloop-correspondence\")","callee":"bin/superloop-correspondence","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-correspondence"}
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:\"bash\"#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"\"bash\"","callee":"external:bash","lookup":"public-command","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:\"python3\"#1","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"\"python3\"","callee":"external:python3","lookup":"public-command","contract":"Python 3 payload execution; the caller supplies the program and its bounded input/output contract"}
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-correspondence\")#2","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"env ! (\"CARGO_BIN_EXE_superloop-correspondence\")","callee":"bin/superloop-correspondence","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-correspondence"}
{"kind":"call","site":"packages/superloop-correspondence/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-correspondence\")#3","caller":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE","selector":"env ! (\"CARGO_BIN_EXE_superloop-correspondence\")","callee":"bin/superloop-correspondence","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-correspondence"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-correspondence/meson.build:custom_target#1","sha256":"56942f61610286f4a12afd1c157495497d47a15cdec95c51c23ff654f47b84df","caller":"meson:superloop-correspondence","owner":"superloop-correspondence","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"20a6f60704640ec44e99ef107a1a81445b13be7e7db257a6776f8607b88aa919"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-correspondence/meson.build:find_program#1","caller":"meson:superloop-correspondence","owner":"superloop-correspondence","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"20a6f60704640ec44e99ef107a1a81445b13be7e7db257a6776f8607b88aa919"}
''']
