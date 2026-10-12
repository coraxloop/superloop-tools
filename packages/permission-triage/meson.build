pkg_permission_triage_rust = files(
  'src/bin/requests-helper.rs',
  'src/requests.rs',
  'src/journal/requests.rs',
  'src/journal/request_lock.rs',
  'src/journal/owner.rs',
  'tests/requests_helper.rs',
  'src/bin/permission-triage-assemble.rs',
  'src/bin/permission-triage-topology.rs',
  'src/bin/permission-triage-hook.rs',
  'src/hook_entry.rs',
  'tests/private_hook.rs',
  'src/evidence.rs',
  'src/command_checks.rs',
  'src/hook.rs',
  'src/journal.rs',
  'src/lib.rs',
  'src/model.rs',
  'src/proc.rs',
  'src/request.rs',
  'src/review.rs',
  'src/role.rs',
  'src/rubric.rs',
  'src/tests/hook.rs',
  'src/tests/journal.rs',
  'src/tests/mod.rs',
  'src/tests/review.rs',
  'src/tests/rubric_model.rs',
  'src/tests/topology.rs',
  'src/topology.rs',
  'tests/assemble.rs',
  'tests/hook.rs',
  'tests/journal.rs',
  'tests/support/mod.rs',
  'tests/support/temporary_root.rs',
  'tests/topology.rs',
)

pkg_permission_triage_prose = files(
  'README.md',
  'deploy/assemble.md',
  'deploy/provenance.md',
  'deploy/settings-fragment.md',
  'rubrics/general.md',
)

pkg_permission_triage_toml = []

pkg_permission_triage_install = files(
  'deploy/settings-fragment.json',
  'schema/classification.json',
)

pkg_permission_triage_excluded_rust = []

pkg_permission_triage_excluded_prose = []

pkg_permission_triage_excluded_toml = []

pkg_permission_triage_sync_outputs = []



pkg_permission_triage_sync_permission_triage_assemble = custom_target(
  'sync-permission-triage-assemble',
  output: ['permission-triage-assemble', 'permission-triage-assemble.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-permission-triage-assemble', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'permission-triage', 'permission-triage-assemble', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
  install_tag: 'harness-private',
)
pkg_permission_triage_sync_outputs += pkg_permission_triage_sync_permission_triage_assemble


pkg_permission_triage_sync_permission_triage_topology = custom_target(
  'sync-permission-triage-topology',
  output: ['permission-triage-topology', 'permission-triage-topology.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-permission-triage-topology', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'permission-triage', 'permission-triage-topology', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
  install_tag: 'harness-private',
)
pkg_permission_triage_sync_outputs += pkg_permission_triage_sync_permission_triage_topology

pkg_permission_triage_sync_hook = custom_target(
  'sync-permission-triage-hook',
  output: ['permission-triage-hook', 'permission-triage-hook.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-permission-triage-hook', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'permission-triage', 'permission-triage-hook', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop' / 'hooks', get_option('datadir') / 'superloop' / 'build-records'],
  install_tag: 'harness-private',
)
pkg_permission_triage_sync_outputs += pkg_permission_triage_sync_hook

pkg_permission_triage_sync_requests = custom_target(
  'sync-requests-helper',
  output: ['requests-helper', 'requests-helper.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-requests-helper', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'permission-triage', 'requests-helper', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('libexecdir') / 'superloop', get_option('datadir') / 'superloop' / 'build-records'],
  install_tag: 'harness-private',
)
pkg_permission_triage_sync_outputs += pkg_permission_triage_sync_requests

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"permission-triage","manifest":"packages/permission-triage/Cargo.toml","tier":3,"release_group":"requests","version_authority":"packages/permission-triage/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"libexec/permission-triage-assemble","output":"packages/permission-triage/permission-triage-assemble","package":"permission-triage","version_authority":"packages/permission-triage/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"permission-triage-assemble","callers":["permission-triage","release-suite"]}
{"kind":"program","identity":"libexec/permission-triage-topology","output":"packages/permission-triage/permission-triage-topology","package":"permission-triage","version_authority":"packages/permission-triage/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"permission-triage-topology","callers":["permission-triage","release-suite"]}
{"kind":"program","identity":"libexec/permission-triage-hook","output":"packages/permission-triage/permission-triage-hook","package":"permission-triage","version_authority":"packages/permission-triage/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"permission-triage-hook","callers":["permission-triage","release-suite","superloop","superloop-claude-hook"]}
{"kind":"program","identity":"libexec/requests-helper","output":"packages/permission-triage/requests-helper","package":"permission-triage","version_authority":"packages/permission-triage/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"requests-helper","callers":["lane-gateway","permission-triage","release-suite","superloop","superloop-lane"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/permission-triage/src/tests/rubric_model.rs:\"/bin/kill\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"/bin/kill\"","callee":"external:/bin/kill","lookup":"configured-external","contract":"Send the named signal to the selected process or process group"}
{"kind":"call","site":"packages/permission-triage/src/topology.rs:\"kill\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"kill\"","callee":"external:kill","lookup":"public-command","contract":"Send the named signal to the selected process or process group"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:env ! (\"CARGO_BIN_EXE_permission-triage-topology\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-topology\")","callee":"libexec/permission-triage-topology","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-topology"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")","callee":"libexec/permission-triage-assemble","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-assemble"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")#2","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")","callee":"libexec/permission-triage-assemble","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-assemble"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")#3","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")","callee":"libexec/permission-triage-assemble","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-assemble"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:env ! (\"CARGO_BIN_EXE_permission-triage-topology\")#2","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-topology\")","callee":"libexec/permission-triage-topology","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-topology"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:\"/bin/sh\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/permission-triage/tests/assemble.rs:env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")#4","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-assemble\")","callee":"libexec/permission-triage-assemble","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-assemble"}
{"kind":"call","site":"packages/permission-triage/tests/hook.rs:env ! (\"CARGO_BIN_EXE_permission-triage-hook\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-hook\")","callee":"libexec/permission-triage-hook","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-hook"}
{"kind":"call","site":"packages/permission-triage/tests/hook.rs:\"/bin/sleep\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"/bin/sleep\"","callee":"external:/bin/sleep","lookup":"configured-external","contract":"Block for the specified duration until completion or signal"}
{"kind":"call","site":"packages/permission-triage/tests/journal.rs:env ! (\"CARGO_BIN_EXE_permission-triage-hook\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-hook\")","callee":"libexec/permission-triage-hook","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-hook"}
{"kind":"call","site":"packages/permission-triage/tests/journal.rs:\"sh\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"sh\"","callee":"external:sh","lookup":"public-command","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/permission-triage/tests/requests_helper.rs:env ! (\"CARGO_BIN_EXE_requests-helper\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_requests-helper\")","callee":"libexec/requests-helper","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_requests-helper"}
{"kind":"call","site":"packages/permission-triage/tests/requests_helper.rs:env ! (\"CARGO_BIN_EXE_requests-helper\")#2","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_requests-helper\")","callee":"libexec/requests-helper","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_requests-helper"}
{"kind":"call","site":"packages/permission-triage/tests/requests_helper.rs:env ! (\"CARGO_BIN_EXE_requests-helper\")#3","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_requests-helper\")","callee":"libexec/requests-helper","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_requests-helper"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:\"git\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:\"git\"#2","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:\"git\"#3","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:\"git\"#4","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:\"git\"#5","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:env ! (\"CARGO_BIN_EXE_permission-triage-topology\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_permission-triage-topology\")","callee":"libexec/permission-triage-topology","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_permission-triage-topology"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/permission-triage/src/bin/permission-triage-assemble.rs:& binary#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"& binary","callee":"libexec/permission-triage-hook","lookup":"private-exact-path","setting":"PERMISSION_TRIAGE_HOOK_BIN","contract":"Private version subcommand returns the embedded rubric identity used by registration assembly"}
{"kind":"call","site":"packages/permission-triage/src/model.rs:& self . cli#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"& self . cli","callee":"external:permission-classifier","lookup":"configured-external","setting":"classifier executable configuration","contract":"Isolated classifier arguments, nesting guard, bounded request framing, deadline and process-group cleanup"}
{"kind":"call","site":"packages/permission-triage/src/model.rs:program#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"program","callee":"external:process-group-signal","lookup":"configured-external","setting":"signal_process_group_with program","contract":"Signal a selected process group with optional KILL; capture no output and preserve process failure"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/permission-triage/src/topology.rs:executable#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"executable","callee":"external:topology-probe","lookup":"configured-external","setting":"topology executable selector","contract":"Probe the configured harness executable with controlled cwd/environment and bounded capture/deadline"}
{"kind":"call","site":"packages/permission-triage/tests/hook.rs:fake_cli ()#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"fake_cli ()","callee":"fixture:permission-triage:model","lookup":"test-executable","setting":"fake_cli()","contract":"Model fixture supplies deterministic classifier replies and deadlines without an ambient model"}
{"kind":"call","site":"packages/permission-triage/tests/private_hook.rs:binary#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"binary","callee":"fixture:permission-triage:hook-entries","lookup":"test-executable","setting":"Cargo hook binary selection","contract":"Compare retained and private permission-hook arguments, payloads and exact reply bytes"}
{"kind":"call","site":"packages/permission-triage/tests/requests_helper.rs:format ! (\"/proc/self/fd/{}\" , binary . as_raw_fd ())#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"format ! (\"/proc/self/fd/{}\" , binary . as_raw_fd ())","callee":"libexec/requests-helper","lookup":"test-executable","setting":"opened CARGO_BIN_EXE_requests-helper descriptor","contract":"Exercise the built helper under selected UIDs through an inherited descriptor"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:binary#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"binary","callee":"fixture:permission-triage:topology","lookup":"test-executable","setting":"topology fixture binary or generated real-hook-driver","contract":"Exercise topology assembly and audit faults against the real hook with isolated fake classifier"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:root . join (\"bin/real-hook-driver\")#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"root . join (\"bin/real-hook-driver\")","callee":"fixture:permission-triage:topology","lookup":"test-executable","setting":"topology fixture binary or generated real-hook-driver","contract":"Exercise topology assembly and audit faults against the real hook with isolated fake classifier"}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/permission-triage/tests/fixtures/fake-cli.sh","form":"shell","sha256":"2fd6f167d9b71f76f1e7df28d0f9d2a4ef4399ec509821bab574c446fe29bd02","owner":"permission-triage","interpreter":"/bin/sh","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:sleep","selector":"sleep","anchor":"sleep","contract":"Synthetic classifier drains or stalls input, creates descendants and emits bounded or deliberately oversized replies","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Synthetic classifier drains or stalls input, creates descendants and emits bounded or deliberately oversized replies","lookup":"test-executable"},{"callee":"external:sh","selector":"sh","anchor":"sh","contract":"Synthetic classifier drains or stalls input, creates descendants and emits bounded or deliberately oversized replies","lookup":"test-executable"},{"callee":"external:head","selector":"head","anchor":"head","contract":"Synthetic classifier drains or stalls input, creates descendants and emits bounded or deliberately oversized replies","lookup":"test-executable"},{"callee":"external:tr","selector":"tr","anchor":"tr","contract":"Synthetic classifier drains or stalls input, creates descendants and emits bounded or deliberately oversized replies","lookup":"test-executable"},{"callee":"external:setsid","selector":"setsid_program","anchor":"\"$setsid_program\" -f sh","contract":"Construct the double-fork fixture using the available setsid executable","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/permission-triage/tests/topology/bin/audit-hook","form":"script","sha256":"5273ca7bc0f67b2eabf3f0ed0486860bfe924323a123220b41fbb2214f85eb47","owner":"permission-triage","interpreter":"/usr/bin/env python3","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:sh","selector":"registered hook command","anchor":"executable=\"/bin/sh\"","contract":"Execute deciding hooks and altered registrations using the actual shell command; reuse only the exact stateless observer in process","lookup":"public-command"}]}
{"kind":"payload","path":"packages/permission-triage/tests/topology/bin/negative-twin","form":"script","sha256":"8792ca32c47c53a723242367e5dc92a65367075c6e6a0d736e98af109e167321","owner":"permission-triage","interpreter":"/bin/sh","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[]}
{"kind":"payload","path":"packages/permission-triage/tests/topology/bin/read-only-stub","form":"script","sha256":"ff50cc91ef7efb527cbccc3fa0ffa09d7a1f4846573aa4d2d7ff4292a6be397f","owner":"permission-triage","interpreter":"/bin/sh","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[]}
{"kind":"payload","path":"packages/permission-triage/tests/topology/bin/real-hook-driver","form":"script","sha256":"cb1c0289c39f0f4273068a03cae93b1e5186d470eee8f77706f52117c31be306","owner":"permission-triage","interpreter":"/usr/bin/env python3","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:cat","selector":"cat","anchor":"cat >","contract":"The generated malformed-scope classifier drains fixture stdin before returning its synthetic reply","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/permission-triage/tests/topology/bin/triage-sentinel","form":"script","sha256":"299bfdf4c7c872955e7c74d7d86e946892635a20472360fae004ff6b82872754","owner":"permission-triage","interpreter":"/bin/sh","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:rm","selector":"rm","anchor":"rm -f","contract":"Remove an unpublished synthetic sentinel","lookup":"test-executable"},{"callee":"external:mv","selector":"mv","anchor":"mv \"$temporary\"","contract":"Publish the synthetic approval execution sentinel","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/permission-triage/tests/topology/fake-harness.sh","form":"shell","sha256":"5ffd3b613d7e58edb18b1b3d6399c20958a1e114d671a0d3854da7af98fd05f1","owner":"permission-triage","interpreter":"/bin/sh","execution_host":"test build host","version_authority":"packages/permission-triage/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:python3","selector":"python3","anchor":"exec python3","contract":"Run the observer harness in Python while retaining real deciding-hook subprocesses","lookup":"public-command"},{"callee":"external:sh","selector":"sh","anchor":"subprocess.run([\"sh\", \"-c\", command]","contract":"Execute the fixture command with real process status and streams","lookup":"public-command"},{"callee":"external:triage-sentinel-fixture","selector":"triage-sentinel","anchor":"TRIAGE_AUTO_SENTINEL","contract":"Execute the declared sentinel fixture to prove the selected topology","lookup":"test-executable"}]}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/permission-triage/meson.build:custom_target#1","sha256":"9e9517ee79e9c116b6fb7ae0e52d100e70c966ce01a4f8cd84c0de3d2bed2a7f","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"meson-call","site":"packages/permission-triage/meson.build:custom_target#2","sha256":"b0de683d0573efab47ef6fe958472bfed7579c6c9fb181ddf7b354f99e9418ff","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"meson-call","site":"packages/permission-triage/meson.build:find_program#1","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env"],"lookup":"public-command","contract":"Resolve the required env executable during configuration and refuse if unavailable","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"meson-call","site":"packages/permission-triage/meson.build:custom_target#3","sha256":"fc1fc5d89b90206bc43886c635d96091a032da210ddd19cc53406b03ce4b841e","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"meson-call","site":"packages/permission-triage/meson.build:custom_target#4","sha256":"c4b2c9852aa1496422b13b73686d0c31bcd5c1d4bd5b8b0365c5d3835e378cdd","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/permission-triage/meson.build:find_program#2","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"meson-call","site":"packages/permission-triage/meson.build:find_program#3","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"meson-call","site":"packages/permission-triage/meson.build:find_program#4","caller":"meson:permission-triage","owner":"permission-triage","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"3873a2e4a07b5fd18b9d7048cdf8e85657adb4a70237d1eabd964c002557c8c0"}
{"kind":"call","site":"packages/permission-triage/tests/topology.rs:\"python3\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"python3\"","callee":"external:python3","lookup":"test-executable","contract":"Inspect the declared Python harness fixture to verify that all supported modes have driving tests"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/permission-triage/tests/requests_helper.rs:env ! (\"CARGO_BIN_EXE_requests-helper\")#4","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_requests-helper\")","callee":"libexec/requests-helper","lookup":"test-executable","binding":"CARGO_BIN_EXE_requests-helper","contract":"Exercise the registered loop collection through the built helper; estate files remain outside the selected journal and unsupported scope selectors refuse"}
{"kind":"call","site":"packages/permission-triage/tests/requests_helper.rs:env ! (\"CARGO_BIN_EXE_requests-helper\")#5","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"env ! (\"CARGO_BIN_EXE_requests-helper\")","callee":"libexec/requests-helper","lookup":"test-executable","binding":"CARGO_BIN_EXE_requests-helper","contract":"Exercise the registered loop collection through the built helper; estate files remain outside the selected journal and unsupported scope selectors refuse"}
{"kind":"call","site":"packages/permission-triage/src/tests/rubric_model.rs:\"/bin/sleep\"#1","caller":"permission-triage","owner":"PERMISSIONTRIAGE","selector":"\"/bin/sleep\"","lookup":"test-executable","callee":"external:/bin/sleep","contract":"Keep the child alive until the cleanup-deadline fixture signals and reaps it"}
{"kind":"data","identity":"private-registry-validation","writer":"superloop-lane","readers":["permission-triage"],"format_authority":"packages/permission-triage/README.md","format_contract":"Bounded map of entry names to bytes over stdin; private helper parses and validates deployment at the calling uid without opening paths, returning schema-one names, state roots and homes","sites":[{"path":"packages/superloop-lane/src/requests/provision.rs","anchor":"--registry-validate"},{"path":"packages/permission-triage/src/bin/requests-helper.rs","anchor":"fn registry_snapshot"}],"owner":"PERMISSIONTRIAGE"}
''']
