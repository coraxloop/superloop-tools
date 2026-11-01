pkg_superloop_lint_rust = files(
  'src/abnf.rs',
  'src/adoption.rs',
  'src/application.rs',
  'src/areas.rs',
  'src/assembly.rs',
  'src/bin/superloop-lint.rs',
  'src/burn.rs',
  'src/carrier.rs',
  'src/catalogue.rs',
  'src/census.rs',
  'src/claim.rs',
  'src/code.rs',
  'src/comment.rs',
  'src/commentary.rs',
  'src/constant.rs',
  'src/control.rs',
  'src/coverage.rs',
  'src/declaration.rs',
  'src/depend.rs',
  'src/engine.rs',
  'src/export.rs',
  'src/finding.rs',
  'src/fix.rs',
  'src/fmt.rs',
  'src/graph.rs',
  'src/head.rs',
  'src/index.rs',
  'src/interchange.rs',
  'src/label.rs',
  'src/layers.rs',
  'src/leader.rs',
  'src/legacy.rs',
  'src/legacy_profile.rs',
  'src/lib.rs',
  'src/public_set.rs',
  'tests/public_set.rs',
  'src/matrix.rs',
  'src/macro_carrier.rs',
  'src/meson_census.rs',
  'src/names.rs',
  'src/occurrence.rs',
  'src/outline.rs',
  'src/partition.rs',
  'src/pattern.rs',
  'src/plan.rs',
  'src/profile.rs',
  'src/python.rs',
  'src/program.rs',
  'src/prose.rs',
  'src/reference.rs',
  'src/registry.rs',
  'src/report.rs',
  'src/residual.rs',
  'src/retired.rs',
  'src/roster.rs',
  'src/selection.rs',
  'src/shape.rs',
  'src/snapshot.rs',
  'src/spdx.rs',
  'src/subscribe.rs',
  'src/surface.rs',
  'src/test_support.rs',
  'src/tests/burn_and_ratchets.rs',
  'src/tests/commands_and_projections.rs',
  'src/tests/control_and_lists.rs',
  'src/tests/coverage_reporting.rs',
  'src/tests/future_plan.rs',
  'src/tests/graph_reporting.rs',
  'src/tests/label_calculus.rs',
  'src/tests/mod.rs',
  'src/tests/owner_reach.rs',
  'src/tests/partition_and_universe.rs',
  'src/tests/profile_writers.rs',
  'src/tests/program_catalogue.rs',
  'src/tests/surface_loading_and_refusal.rs',
  'src/todo.rs',
  'src/token.rs',
  'src/universe.rs',
  'src/workspace.rs',
  'tests/corpus.rs',
  'tests/declared_surface.rs',
  'tests/fmt.rs',
  'tests/meson_census.rs',
  'tests/owner_reconciliation.rs',
  'tests/support/git.rs',
)

pkg_superloop_lint_prose = files(
  'README.md',
  'docs/adrs.md',
  'src/README.md',
  'src/bin/README.md',
  'src/tests/README.md',
  'tests/README.md',
  'tests/fixtures/fmt/blockquotes.md',
  'tests/fixtures/fmt/references-and-lists.md',
  'tests/support/README.md',
)

foreach path : source_paths
  if path.startswith('packages/superloop-lint/adr/') or path.startswith('packages/superloop-lint/docs/plans/') or path == 'packages/superloop-lint/docs/isolation-audit.md'
    pkg_superloop_lint_prose += files(path.substring(24))
  endif
endforeach

pkg_superloop_lint_toml = files(
  'meson-paths.in',
)

pkg_superloop_lint_install = files(
)

pkg_superloop_lint_excluded_rust = []

pkg_superloop_lint_excluded_prose = []

pkg_superloop_lint_excluded_toml = files(
  'tests/fixtures/burn/policy-legacy-implementation.toml',
  'tests/fixtures/burn/policy-legacy-record-references-repository.toml',
  'tests/fixtures/burn/policy-legacy-record-references.toml',
  'tests/fixtures/burn/policy-legacy-section-references-repository.toml',
  'tests/fixtures/burn/policy-legacy-section-references.toml',
  'tests/fixtures/burn/policy-legacy-tag-references.toml',
  'tests/fixtures/burn/policy-legacy-todos.toml',
  'tests/fixtures/burn/policy-legacy-unprefixed-record-references.toml',
  'tests/fixtures/burn/policy-references-divisions.toml',
  'tests/fixtures/burn/policy-references-prefix-numbers.toml',
  'tests/fixtures/burn/policy-references-scenarios.toml',
  'tests/fixtures/census-required-directory-missing.toml',
  'tests/fixtures/census-required-invalid-pattern.toml',
  'tests/fixtures/census-required-malformed-path.toml',
  'tests/fixtures/census-required-malformed-row.toml',
  'tests/fixtures/census-required-malformed-toml.toml',
  'tests/fixtures/census-required-missing.toml',
  'tests/fixtures/census-required-ok.toml',
  'tests/fixtures/census-required-unmatched.toml',
  'tests/fixtures/claims-policies.toml',
  'tests/fixtures/root-owner.toml',
)

pkg_superloop_lint_sync_outputs = []

pkg_superloop_lint_sync_linter = custom_target(
  'sync-linter',
  output: ['superloop-lint', 'superloop-lint.build.json'],
  input: workspace_build,
  command: [find_program('env'), workspace_sync, '--artifact', meson.project_build_root() / 'cargo-superloop-lint', build_identity_args, '--domain', domain, cargo.full_path(), root_manifest, 'superloop-lint', 'superloop-lint', '@OUTPUT0@'],
  build_by_default: true,
  install: true,
  install_dir: [get_option('bindir'), get_option('datadir') / 'superloop' / 'build-records'],
)
pkg_superloop_lint_sync_outputs += pkg_superloop_lint_sync_linter

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"superloop-lint","manifest":"packages/superloop-lint/Cargo.toml","tier":2,"release_group":"superloop-lint","version_authority":"packages/superloop-lint/Cargo.toml"}
{"kind":"call","site":"packages/superloop-lint/src/python.rs:\"python3\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"python3\"","callee":"external:python3","lookup":"public-command","contract":"Execute the embedded isolated standard-library AST reader on stdin without importing corpus code; refuse an unavailable interpreter or malformed source"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#25","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#26","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#27","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#28","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#12","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#13","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
''']

dependency_ledger += ['''
{"kind":"program","identity":"bin/superloop-lint","output":"packages/superloop-lint/superloop-lint","package":"superloop-lint","version_authority":"packages/superloop-lint/Cargo.toml","form":"rust","installation_class":"bin","cargo_binary":"superloop-lint","callers":["meson:build-sync","release-suite","superloop-lint","superloop-pack"]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-lint/src/export.rs:\"git\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-lint/src/export.rs:\"git\"#2","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-lint/src/fix.rs:\"git\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-lint/src/meson_census.rs:\"git\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-lint/src/plan.rs:\"git\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#2","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#3","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#4","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#5","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#6","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#7","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#8","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#9","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#10","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#11","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#12","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#13","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#14","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#15","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#16","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#17","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#18","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#19","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#20","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#21","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#22","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#23","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#24","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#2","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#3","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#4","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#5","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#6","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#7","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#8","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#9","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#10","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/fmt.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#11","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/meson_census.rs:\"git\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/superloop-lint/tests/meson_census.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/meson_census.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#2","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
{"kind":"call","site":"packages/superloop-lint/tests/meson_census.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#3","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Cargo supplies this workspace binary to its integration fixture; arguments and asserted streams/status belong to the named test","binding":"CARGO_BIN_EXE_superloop-lint"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-lint/meson.build:custom_target#1","sha256":"5d58c2a0c06db241bdc59317f8835ada6178fe82df36e415a7caf5c97866d81a","caller":"meson:superloop-lint","owner":"superloop-lint","callees":["external:env","libexec/build-sync"],"lookup":"build-artifact","contract":"Stage the declared binary from the shared workspace artifact without compilation; validate its installed identity and publish changed bytes with the owning version, release group, repository and full source commit","scope_sha256":"5a98894903de5956047b48f4a25c36fa23942a7a00a7bcb9b17f0bfa1af05646"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"packages/superloop-lint/meson.build:find_program#1","caller":"meson:superloop-lint","owner":"superloop-lint","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the shared artifact staging helper","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","scope_sha256":"5a98894903de5956047b48f4a25c36fa23942a7a00a7bcb9b17f0bfa1af05646"}
''']

# Publication command dependencies.
dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-lint/tests/public_set.rs:\"git\"#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"\"git\"","callee":"external:git","lookup":"public-command","contract":"Track the invented publication fixture"}
{"kind":"call","site":"packages/superloop-lint/tests/public_set.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#1","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Exercise optional classification, dead and reserved rows, unclassified paths and overlap through the built binary","binding":"CARGO_BIN_EXE_superloop-lint"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#30","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Verify explicit repository-programme deferral, loader refusals, independent verdicts and preservation of opaque lists through the built checker and burn writer","binding":"CARGO_BIN_EXE_superloop-lint"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/superloop-lint/tests/corpus.rs:env ! (\"CARGO_BIN_EXE_superloop-lint\")#29","caller":"superloop-lint","owner":"SUPERLOOPLINT","selector":"env ! (\"CARGO_BIN_EXE_superloop-lint\")","callee":"bin/superloop-lint","lookup":"test-executable","contract":"Assert the citation-sites executable protocol preserves resolved addresses without prose","binding":"CARGO_BIN_EXE_superloop-lint"}
''']
