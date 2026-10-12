pkg_superloop_gate_submit_rust = files(
  'src/bin/superloop-gate-submit.rs',
  'src/lib.rs',
  'tests/subprocess_contract.rs',
  'tests/support/mod.rs',
)

pkg_superloop_gate_submit_prose = files(
  'README.md',
  'tests/fixtures/README.md',
)

pkg_superloop_gate_submit_toml = []

pkg_superloop_gate_submit_install = files(
  'reference/superloop-gate-submit.sh',
)

pkg_superloop_gate_submit_excluded_rust = []

pkg_superloop_gate_submit_excluded_prose = []

pkg_superloop_gate_submit_excluded_toml = []

pkg_superloop_gate_submit_sync_outputs = []

pkg_superloop_gate_submit_sync_superloop_gate_submit = custom_target(
  'sync-superloop-gate-submit',
  output: ['superloop-gate-submit', 'superloop-gate-submit.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-gate-submit', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-gate-submit', 'superloop-gate-submit', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_gate_submit_sync_outputs += pkg_superloop_gate_submit_sync_superloop_gate_submit

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-gate-submit","manifest":"packages/superloop-gate-submit/Cargo.toml","tier":2,"release_group":"superloop-gate-submit","version_authority":"packages/superloop-gate-submit/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-gate-submit","output":"packages/superloop-gate-submit/superloop-gate-submit","package":"superloop-gate-submit","version_authority":"packages/superloop-gate-submit/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-gate-submit","callers":["release-suite","superloop-gate-submit"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#2","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#3","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#4","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#5","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#6","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#7","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#8","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#9","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#10","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#11","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#12","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"git\"#13","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"ssh\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"ssh\"","callee":"external:ssh","lookup":"public-command","contract":"SSH noninteractive remote command transport using the declared alias and configuration"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"/usr/bin/git\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"/bin/bash\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"/bin/bash\"","callee":"external:/bin/bash","lookup":"configured-external","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-gate-submit/src/lib.rs:\"/bin/bash\"#2","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"/bin/bash\"","callee":"external:/bin/bash","lookup":"configured-external","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-gate-submit/tests/subprocess_contract.rs:\"git\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/tests/subprocess_contract.rs:\"bash\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"bash\"","callee":"external:bash","lookup":"public-command","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-gate-submit/tests/subprocess_contract.rs:\"/usr/bin/git\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-gate-submit/tests/subprocess_contract.rs:\"/bin/bash\"#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"/bin/bash\"","callee":"external:/bin/bash","lookup":"configured-external","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-gate-submit/tests/subprocess_contract.rs:\"/bin/bash\"#2","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"\"/bin/bash\"","callee":"external:/bin/bash","lookup":"configured-external","contract":"Bash script or command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/superloop-gate-submit/tests/support/mod.rs:env ! (\"CARGO_BIN_EXE_superloop-gate-submit\")#1","caller":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT","selector":"env ! (\"CARGO_BIN_EXE_superloop-gate-submit\")","callee":"bin/superloop-gate-submit","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-gate-submit"}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop-gate-submit/reference/superloop-gate-submit.sh","form":"shell","sha256":"81673208af011a7d36f14a55829ce6f28ac6377db3ec0152240664cf728a9369","owner":"superloop-gate-submit","interpreter":"/usr/bin/env bash","execution_host":"install host","version_authority":"packages/superloop-gate-submit/Cargo.toml","contract":"Retained reference implementation used to capture the owning package parity fixtures; not installed","calls":[{"callee":"external:basename","selector":"basename","anchor":"basename","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:date","selector":"date","anchor":"date","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:git","selector":"git","anchor":"git","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:cp","selector":"cp","anchor":"cp","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:ssh","selector":"ssh","anchor":"ssh","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:tail","selector":"tail","anchor":"tail","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:nice","selector":"nice","anchor":"nice","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:cargo","selector":"cargo","anchor":"cargo","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:env","selector":"env","anchor":"env","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","lookup":"test-executable"},{"callee":"external:gate-report-wrapper","selector":"LANE_VERIFY_REMOTE_RUNNER","anchor":"\"$REMOTE_RUNNER\"","contract":"Selected remote wrapper runs the reference verification script during manual capture","lookup":"configured-external"}]}
{"kind":"payload","path":"packages/superloop-gate-submit/tests/fixtures/capture_shell_oracle.py","form":"python","sha256":"05c0f417bf4f084bda267ee81ae3552351409764a077c085f0145d049b0de0ae","owner":"superloop-gate-submit","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop-gate-submit/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:bash","selector":"bash","anchor":"'source \"$1\" \"${@:2}\"'","contract":"Source the retained shell submitter using synthetic Git and SSH commands and a disposable profile","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/superloop-gate-submit/tests/fixtures/stubs/git","form":"script","sha256":"e4df59c575f8f9f72e5494a057d89fdd657ceca62e4a60bb2ca5252676a75901","owner":"superloop-gate-submit","interpreter":"/usr/bin/python3","execution_host":"test build host","version_authority":"packages/superloop-gate-submit/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[]}
{"kind":"payload","path":"packages/superloop-gate-submit/tests/fixtures/stubs/ssh","form":"script","sha256":"8b654d427b35fda68cc94befec6643ff8390a35b92415f5fd8f2ab4f071596a6","owner":"superloop-gate-submit","interpreter":"/usr/bin/python3","execution_host":"test build host","version_authority":"packages/superloop-gate-submit/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:/bin/bash","selector":"/bin/bash","anchor":"[\"/bin/bash\", \"-s\"]","contract":"Execute the captured gate script against synthetic Git and worktree state when the test requests execution","lookup":"test-executable"}]}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-gate-submit/meson.build:custom_target#1","sha256":"af0e53df6cc66e091d58a08e602b4b79a8dfb4c60021b9c52a5401176d8c3791","caller":"meson:superloop-gate-submit","owner":"superloop-gate-submit","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"108d5a6714b2e09b889d6232581814357aa0593188707984d3470b42a2b42723"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-gate-submit/meson.build:find_program#1","caller":"meson:superloop-gate-submit","owner":"superloop-gate-submit","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"108d5a6714b2e09b889d6232581814357aa0593188707984d3470b42a2b42723"}
''']
