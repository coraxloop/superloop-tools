pkg_superloop_rust = files(
  'src/bin/superloop-mail.rs',
  'src/command.rs',
  'src/command/policy.rs',
  'src/command/judgement.rs',
  'src/command/agent.rs', 'src/command/store.rs', 'src/command/protocol_tests.rs', 'tests/command_contract.rs',
  'tests/session_contract.rs','src/main.rs', 'src/session.rs', 'src/dispatch.rs', 'src/bridges.rs', 'tests/subprocess_contract.rs', 'tests/subprocess_contract/termination.rs', 'tests/support/mod.rs')
pkg_superloop_prose = files('README.md')
pkg_superloop_toml = []
pkg_superloop_install = files('data/superloop-mail.service.in', 'tests/mail_custody.py', 'tests/mail_migration.py', 'tests/command_custody.py', 'tests/command_door.py', 'tests/command_gateway.py')
pkg_superloop_excluded_rust = []
pkg_superloop_excluded_prose = []
pkg_superloop_excluded_toml = []
pkg_superloop_sync_outputs = []

pkg_superloop_sync_superloop = custom_target(
  'sync-superloop',
  output: ['superloop', 'superloop.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop', 'superloop', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_sync_outputs += pkg_superloop_sync_superloop

pkg_superloop_sync_mail = custom_target(
  'sync-superloop-mail',
  output: ['superloop-mail', 'superloop-mail.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-mail', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop', 'superloop-mail', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_sync_outputs += pkg_superloop_sync_mail
mail_unit_configuration = configuration_data()
mail_unit_configuration.set('MAIL_PROGRAM', get_option('prefix') / get_option('bindir') / 'superloop-mail')
configure_file(input: 'data/superloop-mail.service.in', output: 'superloop-mail.service', configuration: mail_unit_configuration, install_dir: get_option('datadir') / 'systemd/user')

if get_option('loop_registry') != ''
  meson.add_install_script('env', pkg_superloop_sync_superloop[0].full_path(), '_install-bridges', get_option('loop_registry'), get_option('prefix') / get_option('libexecdir') / 'superloop')
endif



dependency_ledger += ['''
{"kind":"package","name":"superloop","manifest":"packages/superloop/Cargo.toml","tier":2,"release_group":"superloop","version_authority":"packages/superloop/Cargo.toml"}
{"kind":"program","identity":"bin/superloop","output":"packages/superloop/superloop","package":"superloop","version_authority":"packages/superloop/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop","callers":["meson:superloop","release-suite","superloop","superloop-claude-hook","superloop-lane"]}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop\")#1","caller":"superloop","owner":"SUPERLOOP","selector":"env ! (\"CARGO_BIN_EXE_superloop\")","callee":"bin/superloop","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:\"sh\"#1","caller":"superloop","owner":"SUPERLOOP","selector":"\"sh\"","callee":"external:sh","lookup":"public-command","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:\"sh\"#2","caller":"superloop","owner":"SUPERLOOP","selector":"\"sh\"","callee":"external:sh","lookup":"public-command","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:std :: env :: current_exe () . expect (\"test executable\")#1","caller":"superloop","owner":"SUPERLOOP","selector":"std :: env :: current_exe () . expect (\"test executable\")","callee":"fixture:loop-home:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:std :: env :: current_exe () . expect (\"test executable\")#2","caller":"superloop","owner":"SUPERLOOP","selector":"std :: env :: current_exe () . expect (\"test executable\")","callee":"fixture:loop-home:self","lookup":"test-executable","binding":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:stub#1","caller":"superloop","owner":"SUPERLOOP","selector":"stub","callee":"fixture:loop-home:podman","lookup":"test-executable","setting":"ENTER_LOOP_PODMAN","contract":"Fixture Podman receives the operation plan and captures argv under the isolated home"}
{"kind":"installation","route":"native","source":"build:packages/superloop/superloop","destination":"@bindir@/superloop","owner":"superloop"}
{"kind":"installation","route":"native","source":"build:packages/superloop/superloop.build.json","destination":"@datadir@/superloop/build-records/superloop.build.json","owner":"superloop"}
{"kind":"call","site":"packages/superloop/src/dispatch.rs:& program#1","caller":"superloop","owner":"SUPERLOOP","selector":"& program","callee":"libexec/account","lookup":"private-exact-path","contract":"Exec the configured absolute private helper, preserving argument words, streams and exit status","setting":"SUPERLOOP_ACCOUNT_BIN"}
{"kind":"call","site":"packages/superloop/src/dispatch.rs:\"flatpak-spawn\"#1","caller":"superloop","owner":"SUPERLOOP","selector":"\"flatpak-spawn\"","callee":"external:flatpak-spawn","lookup":"public-command","contract":"Execute the forge bridge on the host through the selected toolbox with explicit loop configuration"}
{"kind":"call","site":"packages/superloop/tests/session_contract.rs:env ! (\"CARGO_BIN_EXE_superloop\")#1","caller":"superloop","owner":"SUPERLOOP","selector":"env ! (\"CARGO_BIN_EXE_superloop\")","callee":"bin/superloop","lookup":"test-executable","contract":"Exercise the declared built binary with isolated fixture state and assert its exact streams, status and effects","binding":"CARGO_BIN_EXE_superloop"}
{"kind":"call","site":"packages/superloop/tests/session_contract.rs:& adapter#1","caller":"superloop","owner":"SUPERLOOP","selector":"& adapter","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Compare neutral session decisions with the private adapter receiving the equivalent validated harness event","binding":"SUPERLOOP_TEST_CLAUDE_HOOK"}
{"kind":"call","site":"packages/superloop/tests/session_contract.rs:std :: env :: var_os (\"SUPERLOOP_TEST_CLAUDE_HOOK\") . expect (\"SUPERLOOP_TEST_CLAUDE_HOOK\") ,#1","caller":"superloop","owner":"SUPERLOOP","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_CLAUDE_HOOK\") . expect (\"SUPERLOOP_TEST_CLAUDE_HOOK\") ,","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Compare neutral session decisions with the private adapter receiving the equivalent validated harness event","binding":"SUPERLOOP_TEST_CLAUDE_HOOK"}
{"kind":"call","site":"packages/superloop/tests/session_contract.rs:destination . join (\"alpha-gpg\")#1","caller":"superloop","owner":"SUPERLOOP","selector":"destination . join (\"alpha-gpg\")","callee":"bin/superloop","lookup":"test-executable","contract":"Execute the byte-identical generated private bridge and prove argv0 dispatch precedes version handling"}
{"kind":"meson-call","site":"packages/superloop/meson.build:custom_target#1","sha256":"94318813c262c352305e8ce5644b6d64a1b9fa35e9d2c78226c3202b7db352a8","scope_sha256":"91c9e10d5442de51e39f41067fc14408980155ee7cf6b6b74d251fd48b353723","caller":"meson:superloop","owner":"superloop","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the public root and its compiler and source provenance from the shared workspace artifact"}
{"kind":"meson-call","site":"packages/superloop/meson.build:find_program#1","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"91c9e10d5442de51e39f41067fc14408980155ee7cf6b6b74d251fd48b353723","caller":"meson:superloop","owner":"superloop","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env for the declared workspace staging helper"}
{"kind":"meson-call","site":"packages/superloop/meson.build:add_install_script#1","sha256":"07f3aa3c4f1c0fd8093309ca901e03298e1ec59156640cd3423ba37600fdac1d","scope_sha256":"91c9e10d5442de51e39f41067fc14408980155ee7cf6b6b74d251fd48b353723","caller":"meson:superloop","owner":"superloop","callees":["external:env","bin/superloop"],"lookup":"build-artifact","contract":"Generate byte-identical private signing and SSH bridges from the configured registry under DESTDIR"}
{"kind":"delegated-call","identity":"superloop-forge-toolbox","caller":"superloop","callee":"external:toolbox","selector":"toolbox","lookup":"public-command","execution_host":"configured host toolbox","path":"packages/superloop/src/dispatch.rs","anchor":"\"toolbox\"","contract":"Select the configured host toolbox"}
{"kind":"delegated-call","identity":"superloop-forge-env","caller":"superloop","callee":"external:env","selector":"env","lookup":"public-command","execution_host":"configured host toolbox","path":"packages/superloop/src/dispatch.rs","anchor":".arg(\"env\")","contract":"Forward the explicit loop forge configuration"}
{"kind":"delegated-call","identity":"superloop-forge-gh","caller":"superloop","callee":"external:gh","selector":"gh","lookup":"public-command","execution_host":"configured host toolbox","path":"packages/superloop/src/dispatch.rs","anchor":".arg(\"gh\")","contract":"Execute the forge client with unchanged argument words and streams"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract/termination.rs:\"python3\"#1","caller":"superloop","owner":"SUPERLOOP","selector":"\"python3\"","callee":"external:python3","lookup":"public-command","contract":"Run the fixture controller that assigns terminal ownership and drives private stop and resume through the public entry"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract/termination.rs:env ! (\"CARGO_BIN_EXE_superloop\")#1","caller":"superloop","owner":"SUPERLOOP","selector":"env ! (\"CARGO_BIN_EXE_superloop\")","callee":"bin/superloop","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop","contract":"Exercise the real private relay refusal for absent, malformed and unsupported watched signal sets"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract/termination.rs:& executable#1","caller":"superloop","owner":"SUPERLOOP","selector":"& executable","lookup":"test-executable","callee":"bin/superloop","binding":"CARGO_BIN_EXE_superloop","contract":"Run the built entry with the real signal relay and command group under stubbed namespace operations"}
{"kind":"call","site":"packages/superloop/tests/subprocess_contract.rs:& alias#1","caller":"superloop","owner":"SUPERLOOP","selector":"& alias","callee":"bin/superloop","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop","contract":"Run the resolved built binary from a protected fixture path and assert the retired-setting replacement from production output"}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop/tests/command_custody.py","form":"python","sha256":"375474690e7e1be7b0c46bc64d48d4ea48c11615f47e2f2109c93d7868aa4a0b","owner":"superloop","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop/Cargo.toml","contract":"Two provisioned fixture identities exercise the built direct entry and owner publication with independent UID and group custody; no account provisioning","calls":[{"callee":"external:sudo","selector":"sudo -n -u fixture-account","anchor":"subprocess.run(argv","contract":"Run only the two explicitly provisioned test identities and their built fixtures","lookup":"test-executable"},{"callee":"libexec/permission-triage-hook","selector":"--hook","anchor":"run([str(args.hook)","contract":"Compare the built hook with authenticated direct decisions for equivalent hygiene observations","lookup":"test-executable"}]}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop/tests/command_door.py","form":"python","sha256":"430bd467841b1a608f910b89f3c532673ad908cfa11865bcd963d2757ce1a6c0","owner":"superloop","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop/Cargo.toml","contract":"Native caller observations for the direct command acceptance comparison; no production service or network transport","calls":[{"callee":"bin/superloop-lane","selector":"binary","anchor":"[str(binary)","contract":"Exercise the public door fixture with authenticated reservation evidence","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/superloop/tests/command_gateway.py","form":"python","sha256":"926d73f9e39beb2a858e576e48d0210e1d5dafc1b885feb65d9c226a293aaa65","owner":"superloop","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop/Cargo.toml","contract":"Native caller observations for the direct command acceptance comparison; no production service or network transport","calls":[{"callee":"libexec/gateway-service","selector":"gateway-service","anchor":"bins/'gateway-service'","contract":"Exercise the built gateway serve and proposal commands","lookup":"test-executable"},{"callee":"libexec/gateway-runner","selector":"--runner","anchor":"runner=args.runner","contract":"Use the staged runner under a local stdin-only fixture transport","lookup":"test-executable"},{"callee":"bin/superloop-lane","selector":"superloop-lane","anchor":"bins/'superloop-lane'","contract":"Answer common loop reviews through the public request entry","lookup":"test-executable"},{"callee":"libexec/requests-helper","selector":"requests-helper","anchor":"bins/'requests-helper'","contract":"Bind the built request helper for authenticated loop answers","lookup":"test-executable"},{"callee":"external:git","selector":"git","anchor":"run(['git'","contract":"Create isolated fixture repositories and measure the gateway snapshot","lookup":"test-executable"}]}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-mail","output":"packages/superloop/superloop-mail","package":"superloop","version_authority":"packages/superloop/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-mail","callers":["superloop"]}
{"kind":"installation","route":"native","source":"build:packages/superloop/superloop-mail","destination":"@bindir@/superloop-mail","owner":"superloop"}
{"kind":"installation","route":"native","source":"build:packages/superloop/superloop-mail.build.json","destination":"@datadir@/superloop/build-records/superloop-mail.build.json","owner":"superloop"}
{"kind":"installation","route":"native","source":"build:packages/superloop/superloop-mail.service","destination":"@datadir@/systemd/user/superloop-mail.service","owner":"superloop"}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop/tests/mail_custody.py","form":"python","sha256":"c315ca6749fc1cc6ca5a724d987da9b0db1665eea098db65b00257b046063106","owner":"superloop","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop/Cargo.toml","contract":"Provision only fixture paths with supplied existing accounts and exercise production mail scanning under separate service and loop identities","calls":[{"callee":"external:/usr/bin/setpriv","selector":"/usr/bin/setpriv","anchor":"subprocess.run(['/usr/bin/setpriv'","contract":"Preserve the pinned helper descriptor across the real no-new-privileges entry utility under the loop fixture identity","lookup":"test-executable"},{"callee":"external:sudo","selector":"entered fixture actor","anchor":"subprocess.Popen(argv","contract":"Enter an existing loop fixture identity before the host prefix becomes private","lookup":"test-executable"},{"callee":"bin/superloop","selector":"pinned --loop-binary","anchor":"executable=f'/proc/self/fd/{descriptor}'","contract":"Exercise the opened-image configuration entry from the entered private cwd after absolute path traversal is denied","lookup":"test-executable"},{"callee":"bin/superloop","selector":"private fixture executable path","anchor":"subprocess.run([task['program']","contract":"Prove that the private host prefix denies a new path-based exec by the loop identity","lookup":"test-executable"},{"callee":"bin/superloop","selector":"--loop-binary","anchor":"str(a.loop_binary),'_mail-configure'","contract":"Exercise the private configuration entry as the owning loop identity under fixtures","lookup":"test-executable"},{"callee":"external:sudo","selector":"sudo -n -P -u fixture-account","anchor":"subprocess.run(argv","contract":"Run the explicitly supplied fixture identities without provisioning accounts","lookup":"test-executable"},{"callee":"bin/superloop-mail","selector":"--binary","anchor":"str(a.binary),mode,str(home)","contract":"Exercise built scanner and journal initialization with exact fixture credentials","lookup":"test-executable"},{"callee":"bin/superloop","selector":"--loop-binary worker state","anchor":"str(a.loop_binary),'_mail-worker-state'","contract":"Exercise loop-owned birth reservation, interrupted retry, activation and retained retirement through the production private entry under two fixture identities","lookup":"test-executable"},{"callee":"bin/superloop","selector":"--loop-binary namespace coordinator","anchor":"str(a.loop_binary),'_mail-worker-birth'","contract":"Exercise verify-only through the real namespace-root private entry under host fixtures, including missing-lock refusal; the node measures root refusal and the separate loop-identity child","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/superloop/data/superloop-mail.service.in","form":"unit-template","sha256":"4d80b6a86271fd09309844da0d96fef2b0f2d7bbc5ac279e3b48efe0e5ac2aab","owner":"superloop","interpreter":"systemd user manager","execution_host":"install host","version_authority":"packages/superloop/Cargo.toml","contract":"Render the host-session delivery unit without enabling or starting it","calls":[{"callee":"bin/superloop-mail","selector":"@MAIL_PROGRAM@","anchor":"ExecStart=@MAIL_PROGRAM@ serve %h","contract":"Enter the existing user namespace and run serialized mail delivery","lookup":"unit-install-path"}]}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop/meson.build:custom_target#2","sha256":"9543d0df2e30cd0830a180dc1a49f475e0a2a8d35d92e9516b8dd2ac6e4a9d92","scope_sha256":"91c9e10d5442de51e39f41067fc14408980155ee7cf6b6b74d251fd48b353723","caller":"meson:superloop","owner":"superloop","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the mail delivery program and its compiler and source provenance from the shared workspace artifact"}
{"kind":"meson-call","site":"packages/superloop/meson.build:find_program#2","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"91c9e10d5442de51e39f41067fc14408980155ee7cf6b6b74d251fd48b353723","caller":"meson:superloop","owner":"superloop","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env for the mail program staging helper"}
''']


dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop/tests/mail_migration.py","form":"python","sha256":"1c8499db8c6c26640be896921b19603b8b687c02660e849f5af9680d728d8d14","owner":"superloop","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop/Cargo.toml","contract":"Fixture-only production migration entry: node measures unprivileged refusal; explicit namespace-root host rehearsal moves and restores only a newly created fixture estate without activating units or live processes","calls":[{"callee":"bin/superloop-mail","selector":"--binary or independently copied fixture image","anchor":"subprocess.run(argv","contract":"Execute prepare, interrupted-safe apply, verify and rollback through the public migration command against only the supplied fresh fixture root","lookup":"test-executable"}]}
''']

test('mail-migration-controller-option', python,
  args: [files('tests/mail_migration.py'), '--binary', pkg_superloop_sync_mail[0],
    '--controller', pkg_superloop_sync_mail[0]],
  suite: 'release', timeout: 30)

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop/meson.build:test#1","sha256":"b0625556a68fe54863236de845da212edc5af26cdc3dc0fcb4a4f2bbab699358","scope_sha256":"91c9e10d5442de51e39f41067fc14408980155ee7cf6b6b74d251fd48b353723","caller":"meson:superloop","owner":"superloop","callees":["external:python3"],"lookup":"test-executable","contract":"Exercise the custom controller option and unchanged digest pin through the public unprivileged migration refusal; never execute the supplied fixture image as a controller"}
''']
