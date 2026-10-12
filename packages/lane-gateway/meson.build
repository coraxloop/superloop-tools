pkg_lane_gateway_rust = files(
  'src/bin/gateway-service.rs',
  'src/gateway.rs',
  'src/command.rs',
  'src/lib.rs',
  'src/channel.rs',
  'src/proposal.rs',
  'src/proposal_channel.rs',
  'src/push.rs',
  'src/run.rs',
  'src/serve.rs',
  'src/sha256.rs',
  'src/tests.rs',
  'src/types.rs',
  'tests/serve_generations.rs',
  'tests/serve_liveness.rs',
  'tests/support/mod.rs',
  'tests/command_surface.rs',
)

pkg_lane_gateway_prose = files(
  'README.md',
  'src/README.md',
  'src/bin/README.md',
  'tests/README.md',
  'tests/support/README.md',
)

pkg_lane_gateway_toml = []

pkg_lane_gateway_install = files('gateway-runner')

pkg_lane_gateway_excluded_rust = []

pkg_lane_gateway_excluded_prose = []

pkg_lane_gateway_excluded_toml = []

pkg_lane_gateway_sync_outputs = []

pkg_lane_gateway_sync_lane_gateway = custom_target(
  'sync-gateway-service',
  output: ['gateway-service', 'gateway-service.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-gateway-service', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'lane-gateway', 'gateway-service', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_lane_gateway_sync_outputs += pkg_lane_gateway_sync_lane_gateway

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"lane-gateway","manifest":"packages/lane-gateway/Cargo.toml","tier":3,"release_group":"lane-gateway","version_authority":"packages/lane-gateway/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"libexec/gateway-service","output":"packages/lane-gateway/gateway-service","package":"lane-gateway","version_authority":"packages/lane-gateway/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"gateway-service","callers":["lane-gateway","release-suite","superloop","superloop-lane"]}
{"kind":"program","identity":"libexec/gateway-runner","source":"packages/lane-gateway/gateway-runner","output":"versioned-libexec-gateway-runner","package":"lane-gateway","version_authority":"packages/lane-gateway/Cargo.toml","release_group":"lane-gateway","form":"shell","installation_class":"libexec","callers":["lane-gateway","release-suite","superloop"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/lane-gateway/src/gateway.rs:\"git\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/lane-gateway/src/gateway.rs:\"git\"#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/lane-gateway/src/push.rs:\"git\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/lane-gateway/src/run.rs:\"/bin/true\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"/bin/true\"","callee":"external:/bin/true","lookup":"configured-external","contract":"Successful no-effect process fixture"}
{"kind":"call","site":"packages/lane-gateway/src/run.rs:\"/bin/sh\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/lane-gateway/src/run.rs:\"/bin/sh\"#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/lane-gateway/src/run.rs:\"/bin/true\"#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"/bin/true\"","callee":"external:/bin/true","lookup":"configured-external","contract":"Successful no-effect process fixture"}
{"kind":"call","site":"packages/lane-gateway/src/run.rs:\"/bin/true\"#3","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"/bin/true\"","callee":"external:/bin/true","lookup":"configured-external","contract":"Successful no-effect process fixture"}
{"kind":"call","site":"packages/lane-gateway/src/run.rs:\"/bin/sh\"#3","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:\"git\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:\"mknod\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"mknod\"","callee":"external:mknod","lookup":"public-command","contract":"Create the specified device fixture or refuse without privilege"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:\"mkfifo\"#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"mkfifo\"","callee":"external:mkfifo","lookup":"public-command","contract":"Create the specified FIFO for a process fixture"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:\"mkfifo\"#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"mkfifo\"","callee":"external:mkfifo","lookup":"public-command","contract":"Create the specified FIFO for a process fixture"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:\"mkfifo\"#3","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"\"mkfifo\"","callee":"external:mkfifo","lookup":"public-command","contract":"Create the specified FIFO for a process fixture"}
{"kind":"call","site":"packages/lane-gateway/tests/serve_liveness.rs:env ! (\"CARGO_BIN_EXE_gateway-service\")#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"env ! (\"CARGO_BIN_EXE_gateway-service\")","callee":"libexec/gateway-service","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_gateway-service"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/lane-gateway/src/run.rs:program#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"program","callee":"libexec/gateway-runner","lookup":"private-exact-path","setting":"LANE_GATEWAY_RUNNER_ARGV","contract":"Runner prefix followed by mirror checkout and approved exact argv, with declared target directory and process-group cleanup"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: current_exe () . expect (\"test executable is available\")#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: current_exe () . expect (\"test executable is available\")","callee":"fixture:lane-gateway:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: current_exe () . expect (\"test executable exists\")#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: current_exe () . expect (\"test executable exists\")","callee":"fixture:lane-gateway:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: current_exe () . expect (\"test executable exists\")#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: current_exe () . expect (\"test executable exists\")","callee":"fixture:lane-gateway:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: current_exe () . expect (\"test executable exists\")#3","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: current_exe () . expect (\"test executable exists\")","callee":"fixture:lane-gateway:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: current_exe () . expect (\"test executable exists\")#4","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: current_exe () . expect (\"test executable exists\")","callee":"fixture:lane-gateway:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: current_exe () . expect (\"test executable exists\")#5","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: current_exe () . expect (\"test executable exists\")","callee":"fixture:lane-gateway:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:& config . runner_prefix () [0]#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"& config . runner_prefix () [0]","callee":"fixture:lane-gateway:runner","lookup":"test-executable","setting":"fixture runner_prefix","contract":"Exercise runner process-group identity, recovery and cleanup with controlled completion markers"}
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:& config . runner_prefix () [0]#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"& config . runner_prefix () [0]","callee":"fixture:lane-gateway:runner","lookup":"test-executable","setting":"fixture runner_prefix","contract":"Exercise runner process-group identity, recovery and cleanup with controlled completion markers"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/lane-gateway/meson.build:custom_target#1","sha256":"da8dceb08a365729309b43765ce0faa9affd89cc4096bbd60db3f96e246432d8","caller":"meson:lane-gateway","owner":"lane-gateway","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"56a394d407df6d2d3e6cb28f875640562ea4fc929d1aaef9124ba0471306110b"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/lane-gateway/meson.build:find_program#1","caller":"meson:lane-gateway","owner":"lane-gateway","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"56a394d407df6d2d3e6cb28f875640562ea4fc929d1aaef9124ba0471306110b"}
''']

dependency_ledger += ['''
{"kind":"installation","route":"native","source":"build:packages/lane-gateway/gateway-service","destination":"@libexecdir@/superloop/gateway-service","owner":"lane-gateway"}
{"kind":"installation","route":"native","source":"build:packages/lane-gateway/gateway-service.build.json","destination":"@datadir@/superloop/build-records/gateway-service.build.json","owner":"lane-gateway"}
{"kind":"installation","route":"native","source":"build:versioned-libexec-gateway-runner","destination":"@libexecdir@/superloop/gateway-runner","owner":"lane-gateway"}
{"kind":"installation","route":"native","source":"build:versioned-libexec-gateway-runner.build.json","destination":"@datadir@/superloop/build-records/versioned-libexec-gateway-runner.build.json","owner":"lane-gateway"}
{"kind":"call","site":"packages/lane-gateway/src/channel.rs:& self . helper#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"& self . helper","callee":"libexec/requests-helper","lookup":"private-exact-path","setting":"SUPERLOOP_GATEWAY_REQUESTS_HELPER","contract":"Read, file and claim common requests in the configured calling loop journal through the exact private helper"}
{"kind":"test-tool","consumer":"lane-gateway","binding":"SUPERLOOP_TEST_REQUESTS_HELPER","provider":"meson-environment","callee":"libexec/requests-helper","suite":"cargo-test","contract":"Real common journal fixture uses the declared built helper"}
''']
