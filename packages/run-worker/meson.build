pkg_run_worker_rust = files(
  'src/alloc.rs',
  'src/app.rs',
  'src/bin/worker-run.rs',
  'src/cli.rs',
  'src/clock.rs',
  'src/entry.rs',
  'src/error.rs',
  'src/layout.rs',
  'src/lib.rs',
  'src/table.rs',
  'src/tests/mod.rs',
  'src/watch.rs',
  'tests/settings_contract.rs',
)

pkg_run_worker_prose = files(
  'README.md',
)

pkg_run_worker_toml = []

pkg_run_worker_install = []

pkg_run_worker_excluded_rust = []

pkg_run_worker_excluded_prose = []

pkg_run_worker_excluded_toml = []

pkg_run_worker_sync_outputs = []

pkg_run_worker_sync_run_worker = custom_target(
  'sync-worker-run',
  output: ['worker-run', 'worker-run.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-worker-run', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'run-worker', 'worker-run', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_run_worker_sync_outputs += pkg_run_worker_sync_run_worker

# Machine-readable Meson ledger rows; build-sync checks their measured identities.





dependency_ledger += ['''
{"kind":"package","name":"run-worker","manifest":"packages/run-worker/Cargo.toml","tier":3,"release_group":"run-worker","version_authority":"packages/run-worker/Cargo.toml"}
{"kind":"program","identity":"libexec/worker-run","output":"packages/run-worker/worker-run","package":"run-worker","version_authority":"packages/run-worker/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"worker-run","callers":["release-suite","run-worker","superloop-lane"]}
{"kind":"call","site":"packages/run-worker/src/tests/mod.rs:\"/bin/sh\"#1","caller":"run-worker","owner":"RUNWORKER","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"meson-call","site":"packages/run-worker/meson.build:custom_target#1","sha256":"aae81b7f83a3be4002c71886f36a1ac71c8a6557bec7083f02b90f8abd0df1bf","caller":"meson:run-worker","owner":"run-worker","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"03053f0783fb7838e1f253e41b41e471ca7c1f7811b963835d2e5da9ae6fb974"}
{"kind":"meson-call","site":"packages/run-worker/meson.build:find_program#1","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","caller":"meson:run-worker","owner":"run-worker","callees":["external:env"],"lookup":"public-command","contract":"Resolve the required env executable during configuration and refuse if unavailable","scope_sha256":"03053f0783fb7838e1f253e41b41e471ca7c1f7811b963835d2e5da9ae6fb974"}
{"kind":"installation","route":"native","source":"build:packages/run-worker/worker-run","destination":"@libexecdir@/superloop/worker-run","owner":"run-worker"}
{"kind":"installation","route":"native","source":"build:packages/run-worker/worker-run.build.json","destination":"@datadir@/superloop/build-records/worker-run.build.json","owner":"run-worker"}
{"kind":"call","site":"packages/run-worker/tests/settings_contract.rs:& binary#1","caller":"run-worker","owner":"RUNWORKER","selector":"& binary","callee":"libexec/worker-run","lookup":"test-executable","binding":"CARGO_BIN_EXE_worker-run","contract":"Run the resolved built binary from a protected fixture path and assert the retired-setting replacement from production output"}
{"kind":"test-tool","consumer":"run-worker","binding":"CARGO_BIN_EXE_worker-run","provider":"cargo-target","callee":"libexec/worker-run","suite":"cargo-test","contract":"Cargo supplies worker-run for the private reader refusal fixture"}
''']
