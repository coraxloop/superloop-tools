pkg_superloop_chat_export_rust = files(
  'src/agents.rs',
  'src/folder.rs',
  'src/head.rs',
  'src/input.rs',
  'src/lib.rs',
  'src/load.rs',
  'src/main.rs',
  'src/markdown.rs',
  'src/names.rs',
  'src/output.rs',
  'src/owner.rs',
  'src/plan.rs',
  'src/pool.rs',
  'src/registry.rs',
  'src/render.rs',
  'src/templates.rs',
  'src/tests/aids.rs',
  'src/tests/bounds.rs',
  'src/tests/conserve.rs',
  'src/tests/forms.rs',
  'src/tests/input.rs',
  'src/tests/markdown.rs',
  'src/tests/mod.rs',
  'src/tests/ownership.rs',
  'src/tests/paging.rs',
  'src/tests/render.rs',
  'src/tests/tree.rs',
  'src/tree.rs',
  'src/view.rs',
  'tests/subprocess_contract.rs',
)

pkg_superloop_chat_export_prose = files(
  'README.md',
)

pkg_superloop_chat_export_toml = []

pkg_superloop_chat_export_install = files(
  'assets/chat-export.css',
  'assets/chat-export.js',
  'templates/agent.html',
  'templates/base.html',
  'templates/branch.html',
  'templates/index.html',
  'templates/latest.html',
  'templates/loops.html',
  'templates/macros.html',
  'templates/page.html',
  'templates/pages.html',
  'templates/prompts.html',
  'templates/rows.html',
  'templates/turns.html',
)

pkg_superloop_chat_export_excluded_rust = []

pkg_superloop_chat_export_excluded_prose = []

pkg_superloop_chat_export_excluded_toml = []

pkg_superloop_chat_export_sync_outputs = []

pkg_superloop_chat_export_sync_chat_export = custom_target(
  'sync-superloop-chat-export',
  output: ['superloop-chat-export', 'superloop-chat-export.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-chat-export', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-chat-export', 'superloop-chat-export', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_chat_export_sync_outputs += pkg_superloop_chat_export_sync_chat_export

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-chat-export","manifest":"packages/superloop-chat-export/Cargo.toml","tier":2,"release_group":"superloop-chat-export","version_authority":"packages/superloop-chat-export/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-chat-export","output":"packages/superloop-chat-export/superloop-chat-export","package":"superloop-chat-export","version_authority":"packages/superloop-chat-export/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-chat-export","callers":["release-suite","superloop-chat-export"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-chat-export/tests/subprocess_contract.rs:\"sh\"#1","caller":"superloop-chat-export","owner":"SUPERLOOPCHATEXPORT","selector":"\"sh\"","callee":"external:sh","lookup":"public-command","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-chat-export/tests/subprocess_contract.rs:BINARY#1","caller":"superloop-chat-export","owner":"SUPERLOOPCHATEXPORT","selector":"BINARY","callee":"bin/superloop-chat-export","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-chat-export","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"call","site":"packages/superloop-chat-export/tests/subprocess_contract.rs:BINARY#2","caller":"superloop-chat-export","owner":"SUPERLOOPCHATEXPORT","selector":"BINARY","callee":"bin/superloop-chat-export","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-chat-export","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"call","site":"packages/superloop-chat-export/tests/subprocess_contract.rs:BINARY#3","caller":"superloop-chat-export","owner":"SUPERLOOPCHATEXPORT","selector":"BINARY","callee":"bin/superloop-chat-export","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-chat-export","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
{"kind":"call","site":"packages/superloop-chat-export/tests/subprocess_contract.rs:BINARY#4","caller":"superloop-chat-export","owner":"SUPERLOOPCHATEXPORT","selector":"BINARY","callee":"bin/superloop-chat-export","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-chat-export","contract":"Cargo supplies the fixture binary; arguments and asserted streams/status belong to the named test"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-chat-export/meson.build:custom_target#1","sha256":"1d41e8cc80d0fa91aa0f4aa03b65926df9f655453c9ad222736d387fadd4c05c","caller":"meson:superloop-chat-export","owner":"superloop-chat-export","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"cb05aafc747fadd5e84b2b20e8c828c10afbc7dea49b07b725d01c12150818c0"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-chat-export/meson.build:find_program#1","caller":"meson:superloop-chat-export","owner":"superloop-chat-export","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"cb05aafc747fadd5e84b2b20e8c828c10afbc7dea49b07b725d01c12150818c0"}
''']
