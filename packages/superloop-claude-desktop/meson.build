# Tier 2; package.version is the version authority; release group claude-desktop.
pkg_superloop_claude_desktop_rust = files(
  'src/codec.rs',
  'src/files.rs',
  'src/groups.rs',
  'src/main.rs',
  'src/sessions.rs',
  'tests/subprocess_contract.rs',
)
pkg_superloop_claude_desktop_prose = files('README.md')
pkg_superloop_claude_desktop_toml = []
pkg_superloop_claude_desktop_install = files('tests/fixture.py')
pkg_superloop_claude_desktop_excluded_rust = []
pkg_superloop_claude_desktop_excluded_prose = []
pkg_superloop_claude_desktop_excluded_toml = []
pkg_superloop_claude_desktop_sync_outputs = []
pkg_superloop_claude_desktop_sync = custom_target(
  'sync-superloop-claude-desktop',
  output: ['superloop-claude-desktop', 'superloop-claude-desktop.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-claude-desktop', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-claude-desktop', 'superloop-claude-desktop', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_claude_desktop_sync_outputs += pkg_superloop_claude_desktop_sync

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-claude-desktop","manifest":"packages/superloop-claude-desktop/Cargo.toml","tier":2,"release_group":"claude-desktop","version_authority":"packages/superloop-claude-desktop/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-claude-desktop","output":"packages/superloop-claude-desktop/superloop-claude-desktop","package":"superloop-claude-desktop","version_authority":"packages/superloop-claude-desktop/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-claude-desktop","callers":["release-suite","superloop-claude-desktop"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-claude-desktop/src/files.rs:\"tar\"#1","caller":"superloop-claude-desktop","owner":"SUPERLOOPCLAUDEDESKTOP","selector":"\"tar\"","callee":"external:tar","lookup":"public-command","contract":"Create or read the explicitly named archive"}
{"kind":"call","site":"packages/superloop-claude-desktop/tests/subprocess_contract.rs:\"python3\"#1","caller":"superloop-claude-desktop","owner":"SUPERLOOPCLAUDEDESKTOP","selector":"\"python3\"","callee":"external:python3","lookup":"public-command","contract":"Python 3 payload execution; the caller supplies the program and its bounded input/output contract"}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/superloop-claude-desktop/tests/fixture.py","form":"python","sha256":"b23c813e99439cc6b38fe3169cd339ffa256cd8cb49ea130ad6dad1a2b3b45ba","owner":"superloop-claude-desktop","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"packages/superloop-claude-desktop/Cargo.toml","contract":"Synthetic fixture or oracle exercised by the owning package tests; not an installed command","calls":[{"callee":"bin/superloop-claude-desktop","selector":"BINARY positional argument","anchor":"[BINARY,","contract":"Run every fixture action through the supplied built client with synthetic roots and byte/metadata snapshots","lookup":"test-executable"},{"callee":"external:python3","selector":"sys.executable","anchor":"[sys.executable, \"-c\"","contract":"Hold a genuine POSIX database lock in a separate foreground child for live-database refusal tests","lookup":"test-executable"}]}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-claude-desktop/meson.build:custom_target#1","sha256":"ff4d22faab4f165337d1c0add727ed9de013b4f43ac4d7bc53b8e664b2682412","caller":"meson:superloop-claude-desktop","owner":"superloop-claude-desktop","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"a798f718a02004c4a92223c4828347483a556511df04403062cb2601ccd270c7"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-claude-desktop/meson.build:find_program#1","caller":"meson:superloop-claude-desktop","owner":"superloop-claude-desktop","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"a798f718a02004c4a92223c4828347483a556511df04403062cb2601ccd270c7"}
''']
