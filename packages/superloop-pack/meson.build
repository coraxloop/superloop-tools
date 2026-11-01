pkg_superloop_pack_rust = files(
  'src/bin/superloop-pack.rs',
  'src/lib.rs',
  'src/cut.rs',
  'src/replay.rs',
  'tests/cut.rs',
  'tests/replay.rs',
  'src/tests.rs',
  'tests/subprocess_contract.rs',
)

pkg_superloop_pack_prose = files(
  'README.md',
)

pkg_superloop_pack_toml = []

pkg_superloop_pack_install = files('tests/consumer.py', 'tests/cut_acceptance.py')

pkg_superloop_pack_excluded_rust = []

pkg_superloop_pack_excluded_prose = []

pkg_superloop_pack_excluded_toml = []

pkg_superloop_pack_sync_outputs = []

pkg_superloop_pack_sync_public_pack = custom_target(
  'sync-public-pack',
  output: ['superloop-pack', 'superloop-pack.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-pack', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-pack', 'superloop-pack', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_pack_sync_outputs += pkg_superloop_pack_sync_public_pack

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-pack","manifest":"packages/superloop-pack/Cargo.toml","tier":2,"release_group":"superloop-pack","version_authority":"packages/superloop-pack/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-pack","output":"packages/superloop-pack/superloop-pack","package":"superloop-pack","version_authority":"packages/superloop-pack/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-pack","callers":["release-suite","superloop-pack"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-pack/src/lib.rs:\"git\"#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-pack/src/lib.rs:\"unzip\"#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"unzip\"","callee":"external:unzip","lookup":"public-command","contract":"Read the explicitly named ZIP archive"}
{"kind":"call","site":"packages/superloop-pack/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-pack\")#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"env ! (\"CARGO_BIN_EXE_superloop-pack\")","callee":"bin/superloop-pack","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-pack"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-pack/src/lib.rs:linter#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"superloop-lint","callee":"bin/superloop-lint","lookup":"configured-external","setting":"--linter","contract":"Verify extracted public pack with --public-pack and the external burn input; capture its report and exit status"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-pack/src/tests.rs:& linter#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"& linter","callee":"bin/superloop-lint","lookup":"test-executable","setting":"PUBLIC_PACK_TEST_LINTER","contract":"Run real-linter plain and superloop-pack policy fixtures; absence is a named refusal"}
{"kind":"call","site":"packages/superloop-pack/src/tests.rs:& linter#2","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"& linter","callee":"bin/superloop-lint","lookup":"test-executable","setting":"PUBLIC_PACK_TEST_LINTER","contract":"Run real-linter plain and superloop-pack policy fixtures; absence is a named refusal"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-pack/meson.build:custom_target#1","sha256":"7cfb5f70fa9dd377557004027799e4b1f2784f07130decca2ae777c146eec190","caller":"meson:superloop-pack","owner":"superloop-pack","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"0086ce9536e2549ecde7e5a5e9d882203c6d77b5696deaa71d66d2eef109c6d9"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-pack/meson.build:find_program#1","caller":"meson:superloop-pack","owner":"superloop-pack","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"0086ce9536e2549ecde7e5a5e9d882203c6d77b5696deaa71d66d2eef109c6d9"}
''']

# Publication command dependencies.
dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-pack/src/replay.rs:& linter#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"superloop-lint","callee":"bin/superloop-lint","lookup":"configured-external","setting":"--linter","contract":"Record the candidate linter version before replay preflight"}
{"kind":"call","site":"packages/superloop-pack/tests/replay.rs:\"git\"#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"git\"","callee":"external:git","lookup":"test-executable","contract":"Create and inspect isolated replay histories and prove no-write refusals"}
{"kind":"call","site":"packages/superloop-pack/tests/replay.rs:env ! (\"CARGO_BIN_EXE_superloop-pack\")#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"env ! (\"CARGO_BIN_EXE_superloop-pack\")","callee":"bin/superloop-pack","lookup":"test-executable","contract":"Exercise replay metadata preservation, deterministic mapping and preflight refusals through the built binary","binding":"CARGO_BIN_EXE_superloop-pack"}
{"kind":"call","site":"packages/superloop-pack/src/cut.rs:linter#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"superloop-lint","callee":"bin/superloop-lint","lookup":"configured-external","setting":"--linter","contract":"Read the versioned citation-sites JSON from the built linter recognizer; refuse unsuccessful status or malformed protocol"}
{"kind":"call","site":"packages/superloop-pack/tests/cut.rs:\"git\"#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Create and inspect isolated source and public history fixtures"}
{"kind":"call","site":"packages/superloop-pack/tests/cut.rs:\"git\"#2","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Read the written public commit object to verify its exact message bytes"}
{"kind":"call","site":"packages/superloop-pack/tests/cut.rs:\"git\"#3","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Read the release tag contents to verify changelog link definitions and trailing blank lines are omitted"}
{"kind":"call","site":"packages/superloop-pack/tests/cut.rs:\"git\"#4","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Read the audit tag object to verify the explicit tag-message override is preserved verbatim"}
{"kind":"call","site":"packages/superloop-pack/tests/cut.rs:env ! (\"CARGO_BIN_EXE_superloop-pack\")#1","caller":"superloop-pack","owner":"SUPERLOOPPACK","selector":"env ! (\"CARGO_BIN_EXE_superloop-pack\")","callee":"bin/superloop-pack","lookup":"test-executable","contract":"Prove public root ancestry, reproducible trees, explicit identity, append semantics and licence refusals","binding":"CARGO_BIN_EXE_superloop-pack"}
''']

dependency_ledger += ['''
''']
