pkg_loop_home_rust = files(
  'src/allocations.rs',
  'src/ancestor.rs',
  'src/anchor.rs',
  'src/anchor/transport.rs',
  'src/anchor/tests.rs',
  'src/ancestor_owners.py',
  'src/app.rs',
  'src/custody.rs',
  'src/driver_launch.rs',
  'src/ensure.rs',
  'src/error.rs',
  'src/lib.rs',
  'src/mail/mod.rs',
  'src/mail/migration.rs',
  'src/mail/migration_hold.rs',
  'src/mail/migration_history.rs',
  'src/mail/migration_inventory.rs',
  'src/mail/migration_control.rs',
  'src/mail/migration_cutover.rs',
  'src/mail/migration_relocation.rs',
  'src/mail/migration_tree.rs',
  'src/mail/migration_metadata.rs',
  'src/mail/steering.rs',
  'src/mail/provision.rs',
  'src/mail/birth.rs',
  'src/mail/worker_provision.rs',
  'src/mail/worker_anchors.rs',
  'src/mail/birth_tests.rs',
  'src/mail/configuration_store.rs',
  'src/mail/configuration_store_tests.rs',
  'src/mail/acl.rs',
  'src/mail/io.rs',
  'src/mail/configuration.rs',
  'src/mail/configuration_tests.rs',
  'src/mail/directory.rs',
  'src/mail/refusal.rs',
  'src/mail/service.rs',
  'src/mail/service_tests.rs',
  'src/mail/command.rs',
  'src/mail/entry_anchors.rs',

  'src/mail/instant.rs',
  'src/mail/journal.rs',
  'src/mail/journal_tests.rs',
  'src/mail/store.rs',
  'src/mail/publication.rs',
  'src/mail/publication_tests.rs',
  'src/mail/names.rs',
  'src/planner.rs',
  'src/registry.rs',
  'src/runner.rs',
  'src/runner/agent_runner.py',
  'src/runner/sign_in_policy.py',
  'src/runner/signals.rs',
  'src/tests/mod.rs',
  'src/verify.rs',
  'src/workers_settings.rs',
  'tests/reply_custody.rs',
  'tests/support/bounded.rs',
)

pkg_loop_home_prose = files(
  'README.md',
)

pkg_loop_home_toml = []

pkg_loop_home_install = []

pkg_loop_home_excluded_rust = []

pkg_loop_home_excluded_prose = []

pkg_loop_home_excluded_toml = []

pkg_loop_home_sync_outputs = []

# Machine-readable Meson ledger rows; build-sync checks their measured identities.







dependency_ledger += ['''
{"kind":"package","name":"loop-home","manifest":"packages/loop-home/Cargo.toml","tier":1,"release_group":"loop-home","version_authority":"packages/loop-home/Cargo.toml"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/bin/sh\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/bin/sh\"#2","caller":"loop-home","owner":"LOOPHOME","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/bin/sh\"#3","caller":"loop-home","owner":"LOOPHOME","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/git\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/git\"#2","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/git\"#3","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/git\"#4","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/git\"#5","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/git\"#6","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/git\"","callee":"external:/usr/bin/git","lookup":"configured-external","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/usr/bin/timeout\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/timeout\"","callee":"external:/usr/bin/timeout","lookup":"configured-external","contract":"Bound child wall time and propagate the specified timeout status"}
{"kind":"call","site":"packages/loop-home/src/tests/mod.rs:\"/bin/sh\"#4","caller":"loop-home","owner":"LOOPHOME","selector":"\"/bin/sh\"","callee":"external:/bin/sh","lookup":"configured-external","contract":"POSIX shell command execution with the supplied arguments, streams and exit status"}
{"kind":"call","site":"packages/loop-home/src/app.rs:& lane_bin#1","caller":"loop-home","owner":"LOOPHOME","selector":"& lane_bin","callee":"bin/superloop-lane","lookup":"configured-external","setting":"lane_install_private_dispatch","contract":"Pinned lane executable receives _install-private and the validated forwarded arguments"}
{"kind":"call","site":"packages/loop-home/src/runner.rs:program#1","caller":"loop-home","owner":"LOOPHOME","selector":"program","callee":"external:loop-home-command-plan","lookup":"configured-external","setting":"RunRequest.argv","contract":"Execute a validated home operation plan; explicit argv, environment, stdin and measured wall/status"}
''']

dependency_ledger += ['''
{"kind":"payload","path":"packages/loop-home/src/ancestor_owners.py","form":"python","sha256":"86432698c5cf7e3322fc262c97b3d77a545ab3e3f94c7c622260e786a66fdb20","owner":"loop-home","interpreter":"Python 3 standard library","execution_host":"host or namespace receiver","version_authority":"packages/loop-home/Cargo.toml","contract":"UID-map foundation with verified procfs reads; legacy caller migration is separate","calls":[]}
{"kind":"payload","path":"packages/loop-home/src/runner/agent_runner.py","form":"python","sha256":"61c7f2413afe77949f3d331ecb22c59056070ea0abd596793c90f6e279cc12ea","owner":"loop-home","interpreter":"Python 3 standard library","execution_host":"entered loop","version_authority":"packages/loop-home/Cargo.toml","contract":"Run the configured Codex executable with tool-free exec arguments and record bounded result evidence","calls":[{"callee":"external:configured-codex-agent","selector":"program argument","anchor":"subprocess.Popen(argv","contract":"Pinned agent path receives tool-free Codex exec JSON arguments with bounded streams and process-group cleanup","lookup":"configured-external","execution_host":"entered loop"}]}
{"kind":"payload","path":"packages/loop-home/src/runner/sign_in_policy.py","form":"python","sha256":"0cddefbb2a477d5934c27a1cf35bf30a37378323fbd49f5899b023314d4fc4bb","owner":"loop-home","interpreter":"Python 3 standard library","execution_host":"entered loop","version_authority":"packages/loop-home/Cargo.toml","contract":"Shared credential custody predicate embedded in metadata and agent programs","calls":[]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/provision.rs:\"/usr/bin/setpriv\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/setpriv\"","callee":"external:/usr/bin/setpriv","lookup":"configured-external","contract":"Namespace-root provisioning pins its executing image, enters the loop private cwd before dropping credentials, and invokes the same-image configuration or journal entry through an inherited descriptor with only the allocated mailbox group"}
''']


dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/migration_tree.rs:\"/usr/bin/cp\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/cp\"","callee":"external:/usr/bin/cp","lookup":"configured-external","contract":"Copy a pinned legacy execution tree into a protected backup with archive metadata; independently compare every name, byte, link, mode, owner and extended attribute before accepting it"}
''']


dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/migration_control.rs:& program#1","caller":"loop-home","owner":"LOOPHOME","selector":"& program","callee":"external:reviewed-mail-migration-controller","lookup":"configured-external","setting":"mail migration deployment artifact","contract":"Execute a digest-pinned namespace-root deployment controller or native lane census through its held executable inode with fixed migration arguments; retain output and refuse changed artifacts or failure"}
''']


dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/ancestor.rs:\"python3\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"python3\"","callee":"external:python3","lookup":"test-executable","contract":"Execute the embedded rubric policy against namespace ownership fixtures and the live kernel map"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/entry_anchors.rs:& program#1","caller":"loop-home","owner":"LOOPHOME","selector":"& program","callee":"external:namespace-entry-command","lookup":"configured-external","contract":"Host-verified namespace command receives the pinned mail entry word and one operation-bound descriptor bundle; tests inject unshare through the same composer"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/worker_anchors.rs:\"/usr/bin/setpriv\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/setpriv\"","callee":"external:/usr/bin/setpriv","lookup":"configured-external","contract":"Drop only to the validated worker-mail role with the held image and operation-bound private or journal capability"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/anchor/tests.rs:& path#1","caller":"loop-home","owner":"LOOPHOME","selector":"& path","callee":"external:anchor-fixture-executable","lookup":"configured-external","setting":"anchor_fixture_image","contract":"Execute the held native fixture after removing its pathname, with no fallback lookup"}
{"kind":"call","site":"packages/loop-home/src/anchor/tests.rs:& path#2","caller":"loop-home","owner":"LOOPHOME","selector":"& path","callee":"external:anchor-fixture-executable","lookup":"configured-external","setting":"anchor_fixture_image","contract":"Refuse an unsupported script without invoking an unpinned interpreter by pathname"}
{"kind":"call","site":"packages/loop-home/src/anchor/tests.rs:& image#1","caller":"loop-home","owner":"LOOPHOME","selector":"& image","callee":"external:anchor-fixture-executable","lookup":"configured-external","setting":"anchor_fixture_image","contract":"Prepare held execution under descriptor exhaustion without spawning a child"}
{"kind":"call","site":"packages/loop-home/src/anchor/tests.rs:std :: env :: current_exe () . expect (\"test executable\")#1","caller":"loop-home","owner":"LOOPHOME","selector":"std :: env :: current_exe () . expect (\"test executable\")","callee":"fixture:loop-home:self","lookup":"test-executable","binding":"current_exe","contract":"Isolate descriptor exhaustion and stdin replacement in the same test binary"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/configuration_tests.rs:\"/usr/bin/podman\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/podman\"","callee":"external:/usr/bin/podman","lookup":"configured-external","contract":"Rootless inventory fixture enters the real test binary with the received configuration and storage descriptors, then drops to the reserved service identity"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/tests/support/bounded.rs:\"/usr/bin/python3\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/python3\"","callee":"external:python3","lookup":"configured-external","contract":"Probe bounded fixture child and inherited-pipe deadlines with an owned process group"}
{"kind":"call","site":"packages/loop-home/tests/support/bounded.rs:std :: env :: current_exe () . expect (\"bounded fixture executable\")#1","caller":"loop-home","owner":"LOOPHOME","selector":"std :: env :: current_exe () . expect (\"bounded fixture executable\")","callee":"fixture:loop-home:self","lookup":"test-executable","contract":"Measure a named cleanup refusal in an isolated copy of the fixture test binary","binding":"current_exe"}
{"kind":"call","site":"packages/loop-home/tests/reply_custody.rs:std :: env :: current_exe () . expect (\"reply fixture executable\")#1","caller":"loop-home","owner":"LOOPHOME","selector":"std :: env :: current_exe () . expect (\"reply fixture executable\")","callee":"fixture:loop-home:self","lookup":"test-executable","binding":"current_exe","contract":"Bounded self-executable probes admit listing and refuse unsupported arguments before fixture dispatch"}
{"kind":"call","site":"packages/loop-home/tests/reply_custody.rs:\"/usr/bin/podman\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/podman\"","callee":"external:/usr/bin/podman","lookup":"configured-external","contract":"Remove only the fixture root created by the parent through rootless namespace cleanup; no environment-supplied cleanup path"}
{"kind":"call","site":"packages/loop-home/tests/reply_custody.rs:\"/usr/bin/podman\"#2","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/podman\"","callee":"external:/usr/bin/podman","lookup":"configured-external","contract":"Run the received reply-session library fixture under the real rootless namespace and reserved service identity"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/tests/reply_custody.rs:\"/usr/bin/python3\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/python3\"","callee":"external:python3","lookup":"configured-external","contract":"Install the principal mailbox fixture's exact named service ACL inside the test namespace"}
''']
