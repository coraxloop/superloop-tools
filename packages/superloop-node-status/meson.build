# Tier 2; package.version is the version authority; release group node-status.
pkg_superloop_node_status_rust = files(
  'src/main.rs',
  'src/ssh.rs',
  'tests/subprocess_contract.rs',
)
pkg_superloop_node_status_prose = files('README.md')
pkg_superloop_node_status_toml = []
pkg_superloop_node_status_install = []
pkg_superloop_node_status_excluded_rust = []
pkg_superloop_node_status_excluded_prose = []
pkg_superloop_node_status_excluded_toml = []
pkg_superloop_node_status_sync_outputs = []
pkg_superloop_node_status_sync = custom_target(
  'sync-superloop-node-status',
  output: ['superloop-node-status', 'superloop-node-status.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-node-status', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-node-status', 'superloop-node-status', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_node_status_sync_outputs += pkg_superloop_node_status_sync

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-node-status","manifest":"packages/superloop-node-status/Cargo.toml","tier":2,"release_group":"node-status","version_authority":"packages/superloop-node-status/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-node-status","output":"packages/superloop-node-status/superloop-node-status","package":"superloop-node-status","version_authority":"packages/superloop-node-status/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-node-status","callers":["release-suite","superloop-node-status"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-node-status/src/ssh.rs:\"ssh\"#1","caller":"superloop-node-status","owner":"SUPERLOOPNODESTATUS","selector":"\"ssh\"","callee":"external:ssh","lookup":"public-command","contract":"SSH noninteractive remote command transport using the declared alias and configuration"}
{"kind":"call","site":"packages/superloop-node-status/src/ssh.rs:\"timeout\"#1","caller":"superloop-node-status","owner":"SUPERLOOPNODESTATUS","selector":"\"timeout\"","callee":"external:timeout","lookup":"public-command","contract":"Bound child wall time and propagate the specified timeout status"}
{"kind":"call","site":"packages/superloop-node-status/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-node-status\")#1","caller":"superloop-node-status","owner":"SUPERLOOPNODESTATUS","selector":"env ! (\"CARGO_BIN_EXE_superloop-node-status\")","callee":"bin/superloop-node-status","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-node-status"}
{"kind":"call","site":"packages/superloop-node-status/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-node-status\")#2","caller":"superloop-node-status","owner":"SUPERLOOPNODESTATUS","selector":"env ! (\"CARGO_BIN_EXE_superloop-node-status\")","callee":"bin/superloop-node-status","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-node-status"}
{"kind":"call","site":"packages/superloop-node-status/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-node-status\")#3","caller":"superloop-node-status","owner":"SUPERLOOPNODESTATUS","selector":"env ! (\"CARGO_BIN_EXE_superloop-node-status\")","callee":"bin/superloop-node-status","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-node-status"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-node-status/meson.build:custom_target#1","sha256":"5e5ca27c95cdd46d33fffc547c4c2a2a1c7835344281bf19c660db3f2f8dd2bb","caller":"meson:superloop-node-status","owner":"superloop-node-status","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"989a146e50c5806ca758b901e213986726a61735ea17212af423209f0a29e64c"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-node-status/meson.build:find_program#1","caller":"meson:superloop-node-status","owner":"superloop-node-status","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"989a146e50c5806ca758b901e213986726a61735ea17212af423209f0a29e64c"}
''']
