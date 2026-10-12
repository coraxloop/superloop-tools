pkg_build_sync_rust = files(
  'src/census.rs',
  'src/census_calls.rs',
  'src/census_data.rs',
  'src/census_install.rs',
  'src/census_meson.rs',
  'src/census_payloads.rs',
  'src/census_programs.rs',
  'src/census_sources.rs',
  'src/census_test_tools.rs',
  'src/lib.rs',
  'src/identity.rs',
  'src/main.rs',
  'src/tests/mod.rs',
  'tests/subprocess_contract.rs',
  'tests/census_contract.rs',
  'tests/support/temporary_root.rs',
)

pkg_build_sync_prose = files(
  'README.md',
)

pkg_build_sync_toml = []

pkg_build_sync_install = files('dependency-ledger.jsonl.in')

pkg_build_sync_excluded_rust = []

pkg_build_sync_excluded_prose = []

pkg_build_sync_excluded_toml = []

pkg_build_sync_sync_outputs = []

pkg_build_sync_sync_build_sync = custom_target(
  'sync-build-sync',
  output: ['build-sync', 'build-sync.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-build-sync', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'build-sync', 'build-sync', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_build_sync_sync_outputs += pkg_build_sync_sync_build_sync

# Machine-readable Meson ledger rows; build-sync checks their measured identities.






dependency_ledger += ['''
{"kind":"package","name":"build-sync","manifest":"packages/build-sync/Cargo.toml","tier":3,"release_group":"build-sync","version_authority":"packages/build-sync/Cargo.toml"}
{"kind":"program","identity":"libexec/build-sync","output":"packages/build-sync/build-sync","package":"build-sync","version_authority":"packages/build-sync/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"build-sync","callers":["build-sync","meson:build-sync","meson:lane-gateway","meson:permission-triage","meson:run-worker","meson:staff-provision","meson:superloop","meson:superloop-chat-export","meson:superloop-claude-desktop","meson:superloop-claude-hook","meson:superloop-correspondence","meson:superloop-gate-submit","meson:superloop-install","meson:superloop-lane","meson:superloop-lint","meson:superloop-node-status","meson:superloop-pack","meson:superloop-run-report","meson:superloop-runtime","meson:superloop-steward","release-suite"]}
{"kind":"call","site":"packages/build-sync/tests/census_contract.rs:env ! (\"CARGO_BIN_EXE_build-sync\")#1","caller":"build-sync","owner":"BUILDSYNC","selector":"env ! (\"CARGO_BIN_EXE_build-sync\")","callee":"libexec/build-sync","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_build-sync"}
{"kind":"call","site":"packages/build-sync/tests/census_contract.rs:env ! (\"CARGO_BIN_EXE_build-sync\")#2","caller":"build-sync","owner":"BUILDSYNC","selector":"env ! (\"CARGO_BIN_EXE_build-sync\")","callee":"libexec/build-sync","lookup":"test-executable","contract":"Prove a metadata launch refusal retains the production diagnostic at the requested census report path","binding":"CARGO_BIN_EXE_build-sync"}
{"kind":"call","site":"packages/build-sync/tests/subprocess_contract.rs:& fixture . cargo#1","caller":"build-sync","owner":"BUILDSYNC","selector":"& fixture . cargo","callee":"external:build-version-provider","lookup":"configured-external","setting":"fixture.cargo","contract":"Fixture compiler selects its version from the working directory; prove the build directory selects a different compiler from the source root"}
{"kind":"call","site":"packages/build-sync/src/census.rs:cargo#1","caller":"build-sync","owner":"BUILDSYNC","selector":"cargo","callee":"external:configured-cargo","lookup":"configured-external","setting":"--cargo","contract":"Cargo metadata --locked --format-version 1; nonzero status refuses the census"}
{"kind":"call","site":"packages/build-sync/src/lib.rs:args . cargo#1","caller":"build-sync","owner":"BUILDSYNC","selector":"args . cargo","callee":"external:configured-cargo","lookup":"configured-external","setting":"SyncArgs.cargo","contract":"Cargo release locked build with JSON artifact messages for the selected package and binary"}
{"kind":"call","site":"packages/build-sync/src/lib.rs:program#1","caller":"build-sync","owner":"BUILDSYNC","selector":"program","callee":"external:build-version-provider","lookup":"configured-external","setting":"producer/cargo/rustc","contract":"Cargo, rustc or configured producer version query; read plain version text or the installed-name control-plane record"}
{"kind":"call","site":"packages/build-sync/tests/subprocess_contract.rs:BINARY#1","caller":"build-sync","owner":"BUILDSYNC","selector":"BINARY","callee":"libexec/build-sync","lookup":"test-executable","binding":"CARGO_BIN_EXE_build-sync","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"call","site":"packages/build-sync/tests/subprocess_contract.rs:BINARY#2","caller":"build-sync","owner":"BUILDSYNC","selector":"BINARY","callee":"libexec/build-sync","lookup":"test-executable","binding":"CARGO_BIN_EXE_build-sync","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"call","site":"packages/build-sync/tests/subprocess_contract.rs:BINARY#3","caller":"build-sync","owner":"BUILDSYNC","selector":"BINARY","callee":"libexec/build-sync","lookup":"test-executable","binding":"CARGO_BIN_EXE_build-sync","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"call","site":"packages/build-sync/tests/subprocess_contract.rs:BINARY#4","caller":"build-sync","owner":"BUILDSYNC","selector":"BINARY","callee":"libexec/build-sync","lookup":"test-executable","binding":"CARGO_BIN_EXE_build-sync","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"meson-call","site":"packages/build-sync/meson.build:custom_target#1","sha256":"b5fecf27a54cfd539d27d9824f5bbca852075a5c9241239b24aab8b9f240bfa6","caller":"meson:build-sync","owner":"build-sync","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"f976744b6bb4b40fe39b18c377020330345ce9af0ffb1a798f936a5c3f1d6cec"}
{"kind":"meson-call","site":"packages/build-sync/meson.build:find_program#1","caller":"meson:build-sync","owner":"build-sync","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"f976744b6bb4b40fe39b18c377020330345ce9af0ffb1a798f936a5c3f1d6cec"}
{"kind":"call","site":"packages/build-sync/tests/subprocess_contract.rs:BINARY#5","caller":"build-sync","owner":"BUILDSYNC","selector":"BINARY","callee":"libexec/build-sync","lookup":"test-executable","contract":"Exercise artifact staging through the built binary with declared identity inputs and a build stub that must not execute","binding":"CARGO_BIN_EXE_build-sync"}
''']
