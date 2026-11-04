pkg_superloop_claude_hook_rust = files(
  'tests/heartbeat/graph_contract.rs',
  'tests/heartbeat/letters_contract.rs',
  'tests/heartbeat/oracle_fixtures.rs',
  'tests/heartbeat/reference_scenarios.rs',
  'tests/heartbeat/state_and_faults.rs',
  'tests/heartbeat/structural_matrix.rs',
  'tests/heartbeat/subprocess_contract.rs',
  'tests/heartbeat/support/mod.rs',
  'tests/orchestrator/canonical_scenarios.rs',
  'tests/orchestrator/oracle_fixtures.rs',
  'tests/orchestrator/project_root_contract.rs',
  'tests/orchestrator/project_root_identity.rs',
  'tests/orchestrator/subprocess_contract.rs',
  'tests/orchestrator/support/mod.rs',
  'src/heartbeat/entry_listing.rs',
  'src/heartbeat/letters.rs',
  'src/heartbeat/letters_context.rs',
  'src/heartbeat/machine.rs',
  'src/heartbeat/mod.rs',
  'src/heartbeat/pre_tool.rs',
  'src/heartbeat/project_root.rs',
  'src/lib.rs',
  'src/main.rs',
  'src/orchestrator.rs',
  'src/permission.rs',
  'tests/adapter_contract.rs',
  'tests/oracle_fixtures.rs',
  'tests/oracle_support/mod.rs',
)

pkg_superloop_claude_hook_prose = files(
  'docs/heartbeat.md',
  'docs/mail-watcher.md',
  'docs/orchestrator.md',
  'tests/heartbeat/fixtures/README.md',
  'tests/orchestrator/fixtures/README.md','README.md')
pkg_superloop_claude_hook_toml = []
pkg_superloop_claude_hook_install = files(
  'tests/inbox_wait.py',
  'reference/heartbeat/heartbeat-guard.py',
  'reference/orchestrator/orchestrator.py',
  'tests/heartbeat/fixtures/capture_python_oracle.py',
  'tests/heartbeat/fixtures/expected/python-reference-suite.status',
  'tests/heartbeat/fixtures/expected/python-reference-suite.stdout',
  'tests/heartbeat/fixtures/expected/spec-block-stderr.json',
  'tests/heartbeat/fixtures/expected/spec-invalid-field-fail-open.json',
  'tests/heartbeat/fixtures/expected/spec-list-feedback-turn-marker.json',
  'tests/heartbeat/fixtures/expected/spec-nonnumeric-delay.json',
  'tests/heartbeat/fixtures/expected/spec-state-write-fail-open.json',
  'tests/heartbeat/fixtures/expected/spec-unreadable-state-fail-open.json',
  'tests/orchestrator/fixtures/capture_python_oracle.py',
  'tests/orchestrator/fixtures/expected/change-notice.json',
  'tests/orchestrator/fixtures/expected/duplicate-startup.json',
  'tests/orchestrator/fixtures/expected/fresh-startup.json',
  'tests/orchestrator/fixtures/expected/resume-marker-absent.json',
  'tests/orchestrator/fixtures/expected/resume-marker-present.json',
  'tests/orchestrator/fixtures/expected/spec-nonstring-cwd.json',
  'tests/orchestrator/fixtures/expected/spec-nonstring-prompt.json',
  'tests/orchestrator/fixtures/expected/spec-nonstring-source.json',
  'tests/orchestrator/fixtures/expected/spec-project-root-disable.json',
  'tests/orchestrator/fixtures/expected/spec-redacted-refusal.json',
  'tests/orchestrator/fixtures/expected/unchanged-prompt.json',
)
pkg_superloop_claude_hook_excluded_rust = []
pkg_superloop_claude_hook_excluded_prose = []
pkg_superloop_claude_hook_excluded_toml = []
pkg_superloop_claude_hook_sync_outputs = []

pkg_superloop_claude_hook_sync_adapter = custom_target(
  'sync-superloop-claude-hook',
  output: ['superloop-claude-hook', 'superloop-claude-hook.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-claude-hook', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-claude-hook', 'superloop-claude-hook', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_tag: 'harness-private',
  install_dir: [get_option('libexecdir') / 'superloop' / 'hooks', get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_claude_hook_sync_outputs += pkg_superloop_claude_hook_sync_adapter

# Machine-readable Meson ledger rows; build-sync checks their measured identities.







dependency_ledger += ['''
{"kind":"package","name":"superloop-claude-hook","manifest":"packages/superloop-claude-hook/Cargo.toml","tier":3,"release_group":"claude-hook","version_authority":"packages/superloop-claude-hook/Cargo.toml"}
{"kind":"program","identity":"libexec/superloop-claude-hook","output":"packages/superloop-claude-hook/superloop-claude-hook","package":"superloop-claude-hook","version_authority":"packages/superloop-claude-hook/Cargo.toml","form":"rust","installation_class":"libexec","cargo_binary":"superloop-claude-hook","callers":["release-suite","superloop","superloop-claude-hook"]}
{"kind":"call","site":"packages/superloop-claude-hook/src/heartbeat/entry_listing.rs:\"/bin/true\"#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"\"/bin/true\"","callee":"external:/bin/true","lookup":"configured-external","contract":"Successful no-effect process fixture"}
{"kind":"call","site":"packages/superloop-claude-hook/src/heartbeat/entry_listing.rs:\"/bin/true\"#2","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"\"/bin/true\"","callee":"external:/bin/true","lookup":"configured-external","contract":"Successful no-effect process fixture"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/adapter_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-claude-hook"}
{"kind":"call","site":"packages/superloop-claude-hook/src/heartbeat/entry_listing.rs:& path#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"& path","callee":"bin/superloop","lookup":"configured-external","setting":"entry(home)","contract":"Loop-selected ordinary shell inbox presence test with bounded capture, deadline and child-group cleanup"}
{"kind":"call","site":"packages/superloop-claude-hook/src/permission.rs:binary#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"binary","callee":"libexec/permission-triage-hook","lookup":"private-exact-path","setting":"configured permission hook path","contract":"Original bounded hook request bytes; denial at status zero and infrastructure refusal retain precedence"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/oracle_support/mod.rs:binary#1","caller":"superloop-claude-hook","owner":"ORCHESTRATORHOOK","selector":"binary","callee":"libexec/superloop-claude-hook","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-claude-hook","contract":"Adapter-owned oracle runner dispatches each event through the built adapter and compares reply bytes and state"}
{"kind":"data","identity":"retained-session-oracles","writer":"external:repository","readers":["superloop-claude-hook"],"format_authority":"packages/superloop-claude-hook/tests/oracle_fixtures.rs","format_contract":"Committed JSON oracle payload, state precondition and expected output; each package owns its executable fixture runner","owner":"ORCHESTRATORHOOK","sites":[{"path":"packages/superloop-claude-hook/tests/oracle_fixtures.rs","anchor":"tests/orchestrator/fixtures/expected"}]}
{"kind":"meson-call","site":"packages/superloop-claude-hook/meson.build:custom_target#1","sha256":"c7831b52ad2891f4fe815c5549fd5be17d44c3e198e44b1cb2da8c9ef555a18f","caller":"meson:superloop-claude-hook","owner":"superloop-claude-hook","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"2fd71f79c24c8a671a87a2125e6a1b8ec3feab7a12d4d164abd3b81f97d4f7d7"}
{"kind":"meson-call","site":"packages/superloop-claude-hook/meson.build:find_program#1","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","caller":"meson:superloop-claude-hook","owner":"superloop-claude-hook","callees":["external:env"],"lookup":"public-command","contract":"Resolve the required env executable during configuration and refuse if unavailable","scope_sha256":"2fd71f79c24c8a671a87a2125e6a1b8ec3feab7a12d4d164abd3b81f97d4f7d7"}
{"kind":"payload","path":"packages/superloop-claude-hook/reference/heartbeat/heartbeat-guard.py","form":"python","sha256":"33d79b97ba44e218f4deb1b6a75df72a7bf0281880de300c8c269f6a64423ee0","owner":"superloop-claude-hook","interpreter":"Python 3 standard library","execution_host":"install host","version_authority":"packages/superloop-claude-hook/Cargo.toml","contract":"Retained reference implementation used to capture the owning package parity fixtures; not installed","calls":[]}
{"kind":"payload","path":"packages/superloop-claude-hook/tests/heartbeat/fixtures/capture_python_oracle.py","form":"python","sha256":"e6841d694a09dc8682f65832190be04e97b0e94a06c59588aa38a9d40d0bb93d","owner":"superloop-claude-hook","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop-claude-hook/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:python3","selector":"sys.executable","anchor":"[sys.executable, os.fspath(SUITE)]","contract":"Capture the separately supplied heartbeat scenario-suite source; this manual capture helper is not a release-suite command","lookup":"test-executable"}]}
{"kind":"payload","path":"packages/superloop-claude-hook/reference/orchestrator/orchestrator.py","form":"python","sha256":"c9c2934c116cfbcdf1fefd7ad760b8c8a7142dfb2b82e6534174581c00a40e65","owner":"superloop-claude-hook","interpreter":"Python 3 standard library","execution_host":"install host","version_authority":"packages/superloop-claude-hook/Cargo.toml","contract":"Retained reference implementation used to capture the owning package parity fixtures; not installed","calls":[]}
{"kind":"payload","path":"packages/superloop-claude-hook/tests/orchestrator/fixtures/capture_python_oracle.py","form":"python","sha256":"d2dd2b86ae7e5e0a142868536ff30bced0be0d8445a974f3177becb76e10b6b9","owner":"superloop-claude-hook","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop-claude-hook/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"external:python3","selector":"sys.executable","anchor":"[sys.executable, os.fspath(ORACLE)]","contract":"Capture the retained in-tree orchestrator reference with disposable state and normalize only its state-root path","lookup":"test-executable"}]}
{"kind":"call","site":"packages/superloop-claude-hook/tests/heartbeat/letters_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Exercise the declared built binary with isolated fixture state and assert its exact streams, status and effects","binding":"CARGO_BIN_EXE_superloop-claude-hook"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/heartbeat/subprocess_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Exercise the declared built binary with isolated fixture state and assert its exact streams, status and effects","binding":"CARGO_BIN_EXE_superloop-claude-hook"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/heartbeat/support/mod.rs:\"python3\"#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"\"python3\"","callee":"external:python3","lookup":"public-command","contract":"Prepare controlled filesystem faults in the retained heartbeat fixture"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/heartbeat/support/mod.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\")#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\")","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/subprocess_contract.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/subprocess_contract.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,#2","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/subprocess_contract.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,#3","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/subprocess_contract.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,#4","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/subprocess_contract.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,#5","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\") ,","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/support/mod.rs:env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"env ! (\"CARGO_BIN_EXE_superloop-claude-hook\")","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Exercise the declared built binary with isolated fixture state and assert its exact streams, status and effects","binding":"CARGO_BIN_EXE_superloop-claude-hook"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/support/mod.rs:binary#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"binary","callee":"libexec/superloop-claude-hook","lookup":"test-executable","contract":"Exercise the private adapter event dispatcher with isolated session fixtures","binding":"CARGO_BIN_EXE_superloop-claude-hook"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/support/mod.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\")#1","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\")","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
{"kind":"call","site":"packages/superloop-claude-hook/tests/orchestrator/support/mod.rs:std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\")#2","caller":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_BINARY\") . expect (\"SUPERLOOP_TEST_BINARY\")","callee":"bin/superloop","lookup":"test-executable","contract":"Use the built public session toggle against the same isolated state observed by the adapter","binding":"SUPERLOOP_TEST_BINARY"}
''']

test('mail-inbox-wait', python,
  args: [files('tests/inbox_wait.py'), '--recipe', files('docs/mail-watcher.md')],
  suite: 'release', timeout: 30)

dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop-claude-hook/tests/inbox_wait.py","form":"python","sha256":"e387de87ede05f0947e9260fc7df1847db63360805eedab7b9ea25958106e7d7","owner":"superloop-claude-hook","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop-claude-hook/Cargo.toml","contract":"Execute the documented ordinary filesystem waiting recipe under fixtures, proving arming, overflow, replacement and listing fallback without body reads","calls":[{"callee":"external:/bin/bash","selector":"/bin/bash","anchor":"['/bin/bash'","contract":"Run the exact fenced shell recipe extracted from the installed runbook","lookup":"test-executable"}]}
{"kind":"meson-call","site":"packages/superloop-claude-hook/meson.build:test#1","sha256":"6699340739b98dbbab6a2615aaa402ec94213e7395f8835f47206d0c88882fd5","scope_sha256":"2fd71f79c24c8a671a87a2125e6a1b8ec3feab7a12d4d164abd3b81f97d4f7d7","caller":"meson:superloop-claude-hook","owner":"superloop-claude-hook","callees":["external:python3"],"lookup":"test-executable","contract":"Exercise the ordinary waiting recipe in the release suite"}
{"kind":"delegated-call","identity":"hook-mail-presence-shell","caller":"superloop-claude-hook","callee":"external:/bin/sh","selector":"/bin/sh","lookup":"public-command","execution_host":"entered loop identity","path":"packages/superloop-claude-hook/src/heartbeat/entry_listing.rs","anchor":"\"/bin/sh\"","contract":"Observe only inbox entry presence through the ordinary loop entry with its five-second deadline"}
''']
