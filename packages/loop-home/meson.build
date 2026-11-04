pkg_loop_home_rust = files(
  'src/allocations.rs',
  'src/app.rs',
  'src/custody.rs',
  'src/driver_launch.rs',
  'src/ensure.rs',
  'src/error.rs',
  'src/lib.rs',
  'src/mail/mod.rs',
  'src/mail/steering.rs',
  'src/mail/provision.rs',
  'src/mail/birth.rs',
  'src/mail/worker_provision.rs',
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
{"kind":"payload","path":"packages/loop-home/src/runner/agent_runner.py","form":"python","sha256":"8ecdc8e7889ee0a0c84c7d4a1b5ca9d5e1fb37efc2fc6c8852891ff1d98e8226","owner":"loop-home","interpreter":"Python 3 standard library","execution_host":"entered loop","version_authority":"packages/loop-home/Cargo.toml","contract":"Run the configured Codex executable with tool-free exec arguments and record bounded result evidence","calls":[{"callee":"external:configured-codex-agent","selector":"program argument","anchor":"subprocess.Popen(argv","contract":"Pinned agent path receives tool-free Codex exec JSON arguments with bounded streams and process-group cleanup","lookup":"configured-external","execution_host":"entered loop"}]}
{"kind":"payload","path":"packages/loop-home/src/runner/sign_in_policy.py","form":"python","sha256":"b328b67875d90f119a655f20a2bda2e1e2466ff8cd3fa301fe64a3fc52d5a08c","owner":"loop-home","interpreter":"Python 3 standard library","execution_host":"entered loop","version_authority":"packages/loop-home/Cargo.toml","contract":"Shared credential custody predicate embedded in metadata and agent programs","calls":[]}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/command.rs:& podman [0]#1","caller":"loop-home","owner":"LOOPHOME","selector":"& podman [0]","callee":"external:podman","lookup":"configured-external","setting":"ENTER_LOOP_PODMAN","contract":"Enter the existing host-session user namespace through the loop-home Podman resolver, preserving its optional host prefix and exact private mail arguments"}
''']


dependency_ledger += ['''
{"kind":"call","site":"packages/loop-home/src/mail/provision.rs:\"/usr/bin/setpriv\"#1","caller":"loop-home","owner":"LOOPHOME","selector":"\"/usr/bin/setpriv\"","callee":"external:/usr/bin/setpriv","lookup":"configured-external","contract":"Namespace-root provisioning pins its executing image, enters the loop private cwd before dropping credentials, and invokes the same-image configuration or journal entry through an inherited descriptor with only the allocated mailbox group"}
''']
