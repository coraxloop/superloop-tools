pkg_superloop_cli_common_rust = files(
  'src/burn_match.rs',
  'src/lib.rs',
  'src/public_set.rs',
  'src/publication.rs',
  'src/tests/mod.rs',
  'tests/public_api.rs',
)

pkg_superloop_cli_common_prose = files(
  'README.md',
)

pkg_superloop_cli_common_toml = []

pkg_superloop_cli_common_install = []

pkg_superloop_cli_common_excluded_rust = []

pkg_superloop_cli_common_excluded_prose = []

pkg_superloop_cli_common_excluded_toml = []

pkg_superloop_cli_common_sync_outputs = []

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-cli-common","manifest":"packages/superloop-cli-common/Cargo.toml","tier":0,"release_group":"superloop-cli-common","version_authority":"packages/superloop-cli-common/Cargo.toml"}
''']

# Publication command dependencies.
dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-cli-common/src/public_set.rs:\"git\"#1","caller":"superloop-cli-common","owner":"SUPERLOOPCLICOMMON","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Enumerate the complete tracked publication set without ignore-policy filtering"}
''']
