pkg_superloop_install_rust = files(
  'src/bin/superloop-install.rs',
  'src/lib.rs',
  'src/retirement.rs',
  'src/retirement/filesystem.rs',
  'src/tests.rs',
  'tests/subprocess_contract.rs',
  'tests/retirement_contract.rs',
)

pkg_superloop_install_prose = files(
  'README.md',
  'tests/fixtures/repository/base.md',
  'tests/fixtures/repository/copy.md',
  'tests/fixtures/repository/overlay.md',
)

pkg_superloop_install_toml = []

pkg_superloop_install_install = []

pkg_superloop_install_excluded_rust = []

pkg_superloop_install_excluded_prose = []

pkg_superloop_install_excluded_toml = files(
  'tests/fixtures/maps/charter.toml',
  'tests/fixtures/maps/copy.toml',
  'tests/fixtures/maps/render.toml',
  'tests/fixtures/registry.toml',
)

pkg_superloop_install_sync_outputs = []

pkg_superloop_install_sync_rulebook_install = custom_target(
  'sync-rulebook-install',
  output: ['superloop-install', 'superloop-install.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-install', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-install', 'superloop-install', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_install_sync_outputs += pkg_superloop_install_sync_rulebook_install

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-install","manifest":"packages/superloop-install/Cargo.toml","tier":2,"release_group":"superloop-install","version_authority":"packages/superloop-install/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-install","output":"packages/superloop-install/superloop-install","package":"superloop-install","version_authority":"packages/superloop-install/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-install","callers":["meson:build-sync","release-suite","superloop-install"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-install/src/lib.rs:\"git\"#1","caller":"superloop-install","owner":"SUPERLOOPINSTALL","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-install/src/tests.rs:\"git\"#1","caller":"superloop-install","owner":"SUPERLOOPINSTALL","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-install/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-install\")#1","caller":"superloop-install","owner":"SUPERLOOPINSTALL","selector":"env ! (\"CARGO_BIN_EXE_superloop-install\")","callee":"bin/superloop-install","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-install"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-install/meson.build:custom_target#1","sha256":"77e0f94b2e40869e9de1d52826cd57c91aa29eedce1ae0751d9a7a407d981feb","caller":"meson:superloop-install","owner":"superloop-install","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"86783a8cdfb5895832785b3050ab67fb092c0f5b00e3b2b5b786a13bce1763a3"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-install/tests/retirement_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-install\")#1","caller":"superloop-install","owner":"SUPERLOOPINSTALL","selector":"env ! (\"CARGO_BIN_EXE_superloop-install\")","callee":"bin/superloop-install","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-install","contract":"Exercise reviewed staged inventories and retirement through the built argument dispatcher; preserve bytes on refusal and prove the second invocation changes nothing"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-install/meson.build:find_program#1","caller":"meson:superloop-install","owner":"superloop-install","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"86783a8cdfb5895832785b3050ab67fb092c0f5b00e3b2b5b786a13bce1763a3"}
''']
