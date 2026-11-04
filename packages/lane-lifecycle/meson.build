pkg_lane_lifecycle_rust = files(
  'src/execution_settings.rs',
  'src/lib.rs',
  'src/observation.rs',
  'src/monitor_lock.rs',
)

pkg_lane_lifecycle_prose = files(
  'README.md',
)

pkg_lane_lifecycle_toml = []

pkg_lane_lifecycle_install = []

pkg_lane_lifecycle_excluded_rust = []

pkg_lane_lifecycle_excluded_prose = []

pkg_lane_lifecycle_excluded_toml = []

pkg_lane_lifecycle_sync_outputs = []

# Machine-readable Meson ledger rows; build-sync checks their measured identities.
dependency_ledger += ['''
{"kind":"package","name":"lane-lifecycle","manifest":"packages/lane-lifecycle/Cargo.toml","tier":1,"release_group":"lane-lifecycle","version_authority":"packages/lane-lifecycle/Cargo.toml"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/lane-lifecycle/src/lib.rs:\"date\"#1","caller":"lane-lifecycle","owner":"LANELIFECYCLE","selector":"\"date\"","callee":"external:date","lookup":"public-command","contract":"Format wall-clock time in the requested machine-readable form"}
{"kind":"call","site":"packages/lane-lifecycle/src/lib.rs:\"/usr/bin/sleep\"#1","caller":"lane-lifecycle","owner":"LANELIFECYCLE","selector":"\"/usr/bin/sleep\"","callee":"external:/usr/bin/sleep","lookup":"configured-external","contract":"Block for the specified duration until completion or signal"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/lane-lifecycle/src/execution_settings.rs:& words [0]#1","caller":"lane-lifecycle","owner":"LANELIFECYCLE","selector":"& words [0]","callee":"external:lane-backend","lookup":"configured-external","setting":"LANE_BACKEND_ARGV","contract":"Validated backend_argv selected by claude or codex; retain settings evidence and resolved executable before allocating run state"}
{"kind":"data","identity":"driver-capacity-attempts","writer":"lane-lifecycle","readers":["external:orchestrator"],"format_authority":"packages/lane-lifecycle/README.md","format_contract":"capacity-attempts.txt records attempt number, provider capacity result, selected backoff and measured wait, with terminal report annotation; retries retain the captured thread and the original step budget","sites":[{"path":"packages/lane-lifecycle/src/lib.rs","anchor":"capacity-attempts.txt"}],"owner":"LANELIFECYCLE"}
''']
