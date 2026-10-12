pkg_staff_provision_rust = files(
  'tests/account_contract.rs',
  'src/app.rs',
  'src/bin/account.rs',
  'src/config.rs',
  'src/error.rs',
  'src/keys.rs',
  'src/lib.rs',
  'src/loop_keygen.rs',
  'src/planner.rs',
  'src/probe.rs',
  'src/report.rs',
  'src/runner.rs',
  'src/staff.rs',
  'src/state.rs',
  'src/tests/entries.rs',
  'src/tests/mod.rs',
  'src/tests/planners.rs',
)

pkg_staff_provision_prose = files(
  'README.md',
)

pkg_staff_provision_toml = []

pkg_staff_provision_install = []

pkg_staff_provision_excluded_rust = []

pkg_staff_provision_excluded_prose = []

pkg_staff_provision_excluded_toml = []

pkg_staff_provision_sync_outputs = []

pkg_staff_provision_sync_account = custom_target(
  'sync-account',
  output: ['account', 'account.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-account', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'staff-provision', 'account', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_staff_provision_sync_outputs += pkg_staff_provision_sync_account

# Machine-readable Meson ledger rows; build-sync checks their measured identities.






dependency_ledger += ['''
{"kind":"package","name":"staff-provision","manifest":"packages/staff-provision/Cargo.toml","tier":3,"release_group":"staff-provision","version_authority":"packages/staff-provision/Cargo.toml"}
{"kind":"program","identity":"libexec/account","output":"packages/staff-provision/account","package":"staff-provision","version_authority":"packages/staff-provision/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"account","callers":["release-suite","staff-provision","superloop"]}
{"kind":"call","site":"packages/staff-provision/src/runner.rs:program#1","caller":"staff-provision","owner":"STAFFPROVISION","selector":"program","callee":"external:account-command-plan","lookup":"configured-external","setting":"RunRequest.argv","contract":"Execute a validated account operation plan with LC_ALL=C, explicit stdin and captured status"}
{"kind":"meson-call","site":"packages/staff-provision/meson.build:custom_target#1","sha256":"b4242ee5b315fa3fb94b7ced77f34dd66957267b26bb2afd7325b08821feaf13","caller":"meson:staff-provision","owner":"staff-provision","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"476b0f610e9ed2f3a412ad59a4e903e79dda6094a6ec7138e076240490c3984f"}
{"kind":"meson-call","site":"packages/staff-provision/meson.build:find_program#1","caller":"meson:staff-provision","owner":"staff-provision","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"476b0f610e9ed2f3a412ad59a4e903e79dda6094a6ec7138e076240490c3984f"}
{"kind":"installation","route":"native","source":"build:packages/staff-provision/account","destination":"@libexecdir@/superloop/account","owner":"staff-provision"}
{"kind":"installation","route":"native","source":"build:packages/staff-provision/account.build.json","destination":"@datadir@/superloop/build-records/account.build.json","owner":"staff-provision"}
{"kind":"call","site":"packages/staff-provision/tests/account_contract.rs:env ! (\"CARGO_BIN_EXE_account\")#1","caller":"staff-provision","owner":"STAFFPROVISION","selector":"env ! (\"CARGO_BIN_EXE_account\")","callee":"libexec/account","lookup":"test-executable","contract":"Exercise the declared built binary with isolated fixture state and assert its exact streams, status and effects","binding":"CARGO_BIN_EXE_account"}
''']
