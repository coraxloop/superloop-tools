pkg_pulldown_cmark_to_cmark_rust = files(
  'src/lib.rs',
  'src/source_range.rs',
  'src/text_modifications.rs',
)

pkg_pulldown_cmark_to_cmark_prose = files(
  'README.md',
)

pkg_pulldown_cmark_to_cmark_toml = []

pkg_pulldown_cmark_to_cmark_install = files(
  'LICENSE-APACHE',
)

pkg_pulldown_cmark_to_cmark_excluded_rust = []

pkg_pulldown_cmark_to_cmark_excluded_prose = []

pkg_pulldown_cmark_to_cmark_excluded_toml = []

pkg_pulldown_cmark_to_cmark_sync_outputs = []

dependency_ledger += ['''
{"kind":"vendored","name":"pulldown-cmark-to-cmark","manifest":"packages/pulldown-cmark-to-cmark/Cargo.toml","upstream":"https://github.com/Byron/pulldown-cmark-to-cmark","tag":"v22.0.1","commit":"66f7c5d4a99bd312eacc876b81dad1c91f623e4f","license":"Apache-2.0","owner":"SUPERLOOPLINT","reason":"Retain the converter implementation used by the formatter","divergences":["workspace edition and rust-version","workspace lints and required source changes","upstream tests omitted; repository formatter corpus supplies behavioral evidence"]}
''']

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"pulldown-cmark-to-cmark","manifest":"packages/pulldown-cmark-to-cmark/Cargo.toml","tier":1,"release_group":"pulldown-cmark-to-cmark","version_authority":"packages/pulldown-cmark-to-cmark/Cargo.toml"}
''']
