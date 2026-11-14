# Tier 2; package.version is the version authority; release group credential-custody.
pkg_superloop_credential_custody_rust = files(
  'src/main.rs',
  'src/lib.rs',
  'src/launch.rs',
  'src/launch/policy.rs',
  'src/launch/measure.rs',
  'src/launch/state.rs',
  'src/launch/store.rs',
  'src/launch/tests.rs',
  'src/launch/channel.rs',
  'src/launch/confinement.rs',
  'src/launch/sealer.rs',
  'src/launch/sealer_tests.rs',
  'tests/support/sealer_native.rs',
  'tests/support/confinement_probe.rs',
  'src/observation_cli.rs',
  'src/fixture_cli.rs',
  'src/fixture.rs',
  'src/fixture_main.rs',
  'tests/fixture_contract.rs',
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

# Rehearsal-only artifact: built and versioned, deliberately never installed.
pkg_superloop_credential_fixture_sync = custom_target(
  'sync-credential-fixture',
  output: ['credential-fixture', 'credential-fixture.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-credential-fixture', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-credential-custody', 'credential-fixture', '@OUTPUT0@'],
  build_by_default: true,
)
pkg_superloop_credential_custody_sync_outputs += pkg_superloop_credential_fixture_sync

# Machine-readable Meson ledger rows.
dependency_ledger += ['''
{"kind":"package","name":"superloop-credential-custody","manifest":"packages/superloop-credential-custody/Cargo.toml","tier":2,"release_group":"credential-custody","version_authority":"packages/superloop-credential-custody/Cargo.toml"}
{"kind":"program","identity":"bin/superloop-credential-custody","output":"packages/superloop-credential-custody/superloop-credential-custody","package":"superloop-credential-custody","version_authority":"packages/superloop-credential-custody/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-credential-custody","callers":["release-suite","superloop-credential-custody"]}
{"kind":"call","site":"packages/superloop-credential-custody/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-credential-custody\")#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"env ! (\"CARGO_BIN_EXE_superloop-credential-custody\")","callee":"bin/superloop-credential-custody","lookup":"test-executable","contract":"Cargo supplies the credential custody binary to its subprocess contract tests","binding":"CARGO_BIN_EXE_superloop-credential-custody"}
{"kind":"meson-call","site":"packages/superloop-credential-custody/meson.build:custom_target#1","sha256":"c03d84c9dc5dce5a02aced3354bfdf6ff45cf8d57d56438f7926d66670e08923","caller":"meson:superloop-credential-custody","owner":"superloop-credential-custody","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"1e664803d4d131cd943a4eda728e2a8aba95d86b74419c4bd2ad99fe5785eede"}
{"kind":"meson-call","site":"packages/superloop-credential-custody/meson.build:find_program#1","caller":"meson:superloop-credential-custody","owner":"superloop-credential-custody","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"1e664803d4d131cd943a4eda728e2a8aba95d86b74419c4bd2ad99fe5785eede"}
{"kind":"call","site":"packages/superloop-credential-custody/src/identity.rs:& probe . argv [0]#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"& probe . argv [0]","callee":"external:credential-identity-probe","lookup":"configured-external","contract":"Bounded metadata-only probe execution with empty environment and reviewed exact vectors","setting":"parameters.probes[].argv"}
{"kind":"call","site":"packages/superloop-credential-custody/src/observe.rs:\"/usr/bin/git\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"private-exact-path","contract":"Fixed source-extraction vector with transport denial and an overriding empty transport allowlist; reviewed Git executes through its held descriptor"}
{"kind":"call","site":"packages/superloop-credential-custody/src/observe.rs:\"/usr/bin/python3\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/python3\"","callee":"external:/usr/bin/python3","lookup":"private-exact-path","contract":"Fixed isolated parser vector with empty environment; the measured interpreter inode must equal the held execution anchor"}
{"kind":"call","site":"packages/superloop-credential-custody/tests/subprocess_contract.rs:\"/usr/bin/git\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"private-exact-path","contract":"Test helper constructs and configures only synthetic source repositories for subprocess controls"}
{"kind":"call","site":"packages/superloop-credential-custody/src/process.rs:& path#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"& path","callee":"external:/usr/bin/printf","lookup":"private-exact-path","contract":"Test-only byte-identical native program copies exercise measured-inode execution and refuse replacement without changing the host interpreter"}
{"kind":"call","site":"packages/superloop-credential-custody/tests/subprocess_contract.rs:\"/usr/bin/git\"#2","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"private-exact-path","contract":"Synthetic missing-object positive control verifies that repository configuration would execute its transport without the overriding allowlist"}
{"kind":"external-program","identity":"external:/usr/bin/printf","selector":"/usr/bin/printf","contract":"Native byte-identical test images only; no configurable interpreter path is admitted by the observation command","callers":["superloop-credential-custody"]}
{"kind":"external-program","identity":"external:credential-identity-probe","selector":"parameters.probes[].argv[0]","contract":"Operator-reviewed exact metadata probe vector; no shell interpretation or raw diagnostic relay","callers":["superloop-credential-custody"]}
{"kind":"data","identity":"credential-parameters","writer":"external:operator","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Strict versioned bounded JSON metadata; digest-only probe identities and independently protected reviewed references","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/record.rs","anchor":"pub struct Parameters"},{"path":"packages/superloop-credential-custody/src/record.rs","anchor":"pub struct Discovery"}]}
{"kind":"data","identity":"credential-calibration","writer":"superloop-credential-custody","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Strict versioned bounded JSON metadata; digest-only probe identities and independently protected reviewed references","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/observe.rs","anchor":"pub fn validate"}]}
''']

dependency_ledger += ['''
{"kind":"program","identity":"build/credential-fixture","output":"packages/superloop-credential-custody/credential-fixture","package":"superloop-credential-custody","version_authority":"packages/superloop-credential-custody/Cargo.toml","form":"rust","installation_class":"build","cargo_binary":"credential-fixture","callers":["release-suite","superloop-credential-custody"]}
{"kind":"call","site":"packages/superloop-credential-custody/tests/fixture_contract.rs:BINARY#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"BINARY","callee":"build/credential-fixture","lookup":"test-executable","binding":"CARGO_BIN_EXE_credential-fixture","contract":"Synthetic supervisor supplies two named pipes and observes the fixture start barrier; fixture-side evidence only"}
{"kind":"call","site":"packages/superloop-credential-custody/src/fixture.rs:executable#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"executable","callee":"build/credential-fixture","lookup":"private-exact-path","contract":"Reexecute the pinned current fixture image with one deliberate inherited harmless descriptor before its barrier"}
{"kind":"meson-call","site":"packages/superloop-credential-custody/meson.build:custom_target#2","caller":"meson:superloop-credential-custody","owner":"superloop-credential-custody","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the rehearsal-only fixture and provenance record without installing either","sha256":"4d7546a25101c32f7761587371abbece7ba952f69731e5fb31be54e070544076","scope_sha256":"1e664803d4d131cd943a4eda728e2a8aba95d86b74419c4bd2ad99fe5785eede"}
{"kind":"meson-call","site":"packages/superloop-credential-custody/meson.build:find_program#2","caller":"meson:superloop-credential-custody","owner":"superloop-credential-custody","callees":["external:env"],"lookup":"build-artifact","contract":"Stage the rehearsal-only fixture and provenance record without installing either","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"1e664803d4d131cd943a4eda728e2a8aba95d86b74419c4bd2ad99fe5785eede"}
{"kind":"data","identity":"credential-fixture-case","writer":"external:operator","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Separate strict tagged schema-1 public metadata: internal patterns, lengths, names and bounded injected behavior; caller-owned 0400 or root-owned 0444 with root-owned ancestors","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/fixture.rs","anchor":"struct FixtureRecord"}]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-credential-custody/tests/fixture_contract.rs:BINARY#2","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"BINARY","callee":"build/credential-fixture","lookup":"test-executable","binding":"CARGO_BIN_EXE_credential-fixture","contract":"Check the rehearsal artifact control-plane statuses without running emission"}
{"kind":"call","site":"packages/superloop-credential-custody/tests/fixture_contract.rs:BINARY#3","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"BINARY","callee":"build/credential-fixture","lookup":"test-executable","binding":"CARGO_BIN_EXE_credential-fixture","contract":"Check the rehearsal artifact control-plane statuses without running emission"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-credential-custody/tests/fixture_contract.rs:executable . as_ptr () , pointers . as_ptr () , env . as_ptr ()#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"executable . as_ptr () , pointers . as_ptr () , env . as_ptr ()","callee":"build/credential-fixture","lookup":"test-executable","binding":"CARGO_BIN_EXE_credential-fixture","contract":"Execute a byte-for-byte staged Cargo fixture with PID-bound convention metadata constructed without allocation after fork"}
''']

dependency_ledger += ['''
{"kind":"data","identity":"credential-launch-policy","writer":"external:operator","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Separate strict schema-1 launch policy with typed roles, finite bounds and protected references; private cores only, no manager adapter or entrypoint","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/launch/policy.rs","anchor":"pub(super) struct Policy"}]}
{"kind":"data","identity":"credential-launch-state","writer":"superloop-credential-custody","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Immutable private case creation and state receipts bind measured policy, artifact, public-case and typed configuration bytes to held object identities; binding loss latches uncertainty with a static refusal class even when outputs no longer verify; no live completion claim without later adapters","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/launch/store.rs","anchor":"struct Snapshot<'a>"}]}
''']

# The native Cargo example is test-only: no versioned program or staging target.
dependency_ledger += ['''
{"kind":"external-program","identity":"external:credential-sealer","selector":"launch-policy.artifacts[role=sealer].path","contract":"Reviewed native sealer receives only admitted stdin and exclusive sealed stdout; fixed host-key encryption vector, held measured image, empty environment and private bounded diagnostics","callers":["superloop-credential-custody"]}
{"kind":"call","site":"packages/superloop-credential-custody/src/launch/sealer.rs:path#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"path","callee":"external:credential-sealer","lookup":"configured-external","setting":"launch-policy.artifacts[role=sealer].path","contract":"Private C2 core executes the measured native sealer through the shared held executor; tests supply only a synthetic Cargo example image through test-only admission"}
{"kind":"data","identity":"credential-sealer-completion","writer":"superloop-credential-custody","readers":["superloop-credential-custody"],"format_authority":"packages/superloop-credential-custody/README.md","format_contract":"Private metadata-only pipe EOF and native exit observations; no length acceptance, generator success or encryption claim","owner":"SUPERLOOPCREDENTIALCUSTODY","sites":[{"path":"packages/superloop-credential-custody/src/launch/sealer.rs","anchor":"pub(super) struct Completion"}]}
''']

# The watchdog control uses the fixed held interpreter and event-driven pidfd observations.
dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-credential-custody/src/process.rs:\"/usr/bin/python3\"#1","caller":"superloop-credential-custody","owner":"SUPERLOOPCREDENTIALCUSTODY","selector":"\"/usr/bin/python3\"","callee":"external:/usr/bin/python3","lookup":"private-exact-path","contract":"Test-only event-driven descendant watchdog exercises shared cancellation without a startup timing window"}
''']
