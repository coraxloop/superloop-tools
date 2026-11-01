project('superloop-tools', version: '0.2.0', meson_version: '>=1.12.0')

git = find_program('git')
release_tag = get_option('release_tag')
release_commit = ''
if release_tag != ''
  tagged = run_command(git, '-C', meson.project_source_root(), 'rev-parse', '--verify', 'refs/tags/' + release_tag + '^{commit}', check: true).stdout().strip()
  release_commit = run_command(git, '-C', meson.project_source_root(), 'rev-parse', 'HEAD', check: true).stdout().strip()
  dirty = run_command(git, '-C', meson.project_source_root(), 'status', '--porcelain', '--untracked-files=all', check: true).stdout().strip()
  assert(tagged == release_commit and dirty == '', 'release_tag must name the clean checkout HEAD')
endif

cargo = find_program('cargo')
cargo_fmt = find_program('cargo-fmt')
bash = find_program('bash')
python = find_program('python3')
meson_program = find_program('meson')
fs = import('fs')
domain = get_option('domain')

# Classify the index once. Every downstream file list uses this same inventory;
# missing tracked inputs still fail files(), including source-only inputs.
publication = run_command(python, '-c', '''
import functools, os, pathlib, re, subprocess, sys, tomllib
root = pathlib.Path(sys.argv[1])
manifest = tomllib.loads((root / 'public-set.toml').read_text())
@functools.cache
def component_pattern(pattern):
    expression = b''.join(b'.*' if c == 42 else b'.' if c == 63 else re.escape(bytes([c])) for c in pattern.encode())
    return re.compile(expression, flags=re.DOTALL)
def matches(pattern, path):
    if pattern.endswith('/'):
        return path.startswith(pattern)
    left, right = pattern.split('/'), path.split('/')
    return len(left) == len(right) and all(component_pattern(a).fullmatch(b.encode()) is not None for a, b in zip(left, right))
if (root / '.git').exists():
    paths = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
else:
    paths = []
    for directory, children, files in os.walk(root):
        base = pathlib.Path(directory)
        children[:] = [name for name in children if name != '.git' and base / name != root / 'target' and not (base / name / 'meson-private').is_dir()]
        paths.extend(str((base / name).relative_to(root)) for name in children if (base / name).is_symlink())
        children[:] = [name for name in children if not (base / name).is_symlink()]
        paths.extend(str((base / name).relative_to(root)) for name in files)
for path in sorted(set(paths) - {''}):
    classes = [kind for kind in ('include', 'exclude', 'reserved') for row in manifest.get(kind, {}).get('rows', []) if matches(row['pattern'], path)]
    if len(classes) != 1:
        sys.exit('public-set classification must resolve once: ' + path)
    print(classes[0] + ':' + path)
''', meson.project_source_root(), check: true).stdout().strip().split('\n')
source_paths = []
public_paths = []
foreach entry : publication
  parts = entry.split(':')
  source_paths += parts[1]
  if parts[0] == 'include'
    public_paths += parts[1]
  endif
endforeach

root_manifest = meson.project_source_root() / 'Cargo.toml'
sync_outputs = []
dependency_ledger = []

tools_source_commit = get_option('tools_source_commit')
if tools_source_commit == ''
  if not fs.exists(meson.project_source_root() / '.git')
    error('set -Dtools_source_commit to the reviewed source commit when building without Git history')
  endif
  tools_source_commit = run_command(git, '-C', meson.project_source_root(), 'rev-parse', 'HEAD', check: true).stdout().strip()
endif
build_identity_args = ['--ledger', meson.project_build_root() / 'dependency-ledger.jsonl', '--source-root', meson.project_source_root(), '--source-repository', meson.project_name(), '--source-commit', tools_source_commit]

# One compile environment for every deployed binary; staging never invokes Cargo.
workspace_builder = files('packages/build-sync/workspace.py')
# A new checkout commit changes the embedded version even when Rust sources are identical.
if fs.exists(meson.project_source_root() / '.git')
  source_head = run_command(git, '-C', meson.project_source_root(), 'rev-parse', '--path-format=absolute', '--git-path', 'HEAD', check: true).stdout().strip()
  configure_file(input: source_head, output: 'workspace-source-head', copy: true)
  source_ref = run_command(git, '-C', meson.project_source_root(), 'symbolic-ref', '-q', 'HEAD', check: false)
  if source_ref.returncode() == 0
    source_ref_path = run_command(git, '-C', meson.project_source_root(), 'rev-parse', '--path-format=absolute', '--git-path', source_ref.stdout().strip(), check: true).stdout().strip()
    if fs.exists(source_ref_path)
      configure_file(input: source_ref_path, output: 'workspace-source-ref', copy: true)
    endif
  endif
endif
workspace_artifacts = run_command(python, workspace_builder, 'outputs', meson.project_source_root(), check: true).stdout().strip().split('\n')
workspace_environment = environment()
workspace_environment.set('SUPERLOOP_ACCOUNT_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'account')
workspace_environment.set('SUPERLOOP_GATEWAY_SERVICE_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'gateway-service')
workspace_environment.set('SUPERLOOP_GATEWAY_REQUESTS_HELPER', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'requests-helper')
workspace_environment.set('SUPERLOOP_WORKER_RUN_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'worker-run')
workspace_environment.set('PERMISSION_TRIAGE_HOOK_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'hooks' / 'permission-triage-hook')
workspace_environment.set('PERMISSION_TRIAGE_ADAPTER_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'hooks' / 'superloop-claude-hook')
workspace_environment.set('RUN_WORKER_CLAUDE_HOOK_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'hooks' / 'superloop-claude-hook')
workspace_environment.set('SUPERLOOP_LANE_REQUESTS_HELPER', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'requests-helper')
workspace_environment.set('SUPERLOOP_LANE_DATA_DIR', get_option('prefix') / get_option('datadir') / 'superloop' / 'lane')
workspace_environment.set('SUPERLOOP_LANE_PROXY_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'vendor-proxy')
workspace_environment.set('SUPERLOOP_LANE_DOOR_STUB_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'door-ssh')
workspace_environment.set('SUPERLOOP_LANE_DOOR_SERVICE_BIN', get_option('prefix') / get_option('libexecdir') / 'superloop' / 'door-service')
workspace_lock = []
if fs.exists('Cargo.lock')
  workspace_lock = files('Cargo.lock')
endif
workspace_build = custom_target(
  'workspace-release',
  input: workspace_builder + files('Cargo.toml') + workspace_lock,
  output: ['workspace-build.json'] + workspace_artifacts,
  depfile: 'workspace-build.d',
  command: [python, workspace_builder, 'build', meson.project_source_root(), '@OUTPUT0@', cargo, get_option('tools_source_commit')],
  env: workspace_environment,
  build_by_default: true,
  console: true,
)
workspace_sync = meson.project_build_root() / 'cargo-build-sync'

# Typed fixtures are declared by their members; this takes only build definitions and untyped fixture outputs and data.
excluded_pattern = '(^|/)meson[.](build|options)$|^packages/[^/]+/(src/)?tests/(driver_(claude|codex|follow|status)/)?(fixtures|topology)/(.*/)?([^./]+|[^/]*[.]([^mrt./][^./]*|m|m[^d./][^./]*|md[^./]+|r|r[^s./][^./]*|rs[^./]+|t|t[^o./][^./]*|to|to[^m./][^./]*|tom|tom[^l./][^./]*|toml[^./]+))$'

prose_files = files(
  'README.md',
  'CHANGELOG.md',
  'packages/README.md',
)

foreach path : source_paths
  if path.startswith('adr/') and path.endswith('.md')
    prose_files += files(path)
  endif
endforeach

rust_files = []
declaration_files = files(
  'public-set.toml',
  'LICENSE-CODE',
  'LICENSE-DOCS',
  '.gitignore',
  'Cargo.toml',
  'packages/superloop-runtime/Cargo.toml',
  'packages/superloop-claude-desktop/Cargo.toml',
  'packages/superloop-node-status/Cargo.toml',
  'packages/superloop-steward/Cargo.toml',
  'packages/superloop-correspondence/Cargo.toml',
  'rust-toolchain.toml',
  'packages/build-sync/Cargo.toml',
  'packages/superloop-chat-export/Cargo.toml',
  'packages/superloop-cli-common/Cargo.toml',
  'packages/superloop-execwrap/Cargo.toml',
  'packages/lane-gateway/Cargo.toml',
  'packages/lane-lifecycle/Cargo.toml',
  'packages/superloop-gate-submit/Cargo.toml',
  'packages/superloop-lint/Cargo.toml',
  'packages/loop-home/Cargo.toml',
  'packages/superloop/Cargo.toml',
  'packages/permission-triage/Cargo.toml',
  'packages/superloop-pack/Cargo.toml',
  'packages/pulldown-cmark-to-cmark/Cargo.toml',
  'packages/superloop-install/Cargo.toml',
  'packages/superloop-run-report/Cargo.toml',
  'packages/run-worker/Cargo.toml',
  'packages/staff-provision/Cargo.toml',
  'packages/session-core/Cargo.toml',
  'packages/request-core/Cargo.toml',
  'packages/execute-command/Cargo.toml',
  'packages/superloop-claude-hook/Cargo.toml',
  'packages/superloop-lane/Cargo.toml',
)

if fs.exists('Cargo.lock')
  declaration_files += files('Cargo.lock')
endif

foreach path : source_paths
  if path.startswith('.linter/') or path == 'docs/public/unpublished-labels.toml'
    declaration_files += files(path)
  endif
endforeach

install_inputs = files(
)

excluded_subjects = []

subdir('docs')
prose_files += docs_prose
foreach document : docs_prose
  relative = fs.relative_to(document, meson.project_source_root())
  if public_paths.contains(relative)
    install_data(document, install_dir: get_option('datadir') / 'superloop-tools' / fs.parent(relative))
  endif
endforeach

subdir('tests')
install_inputs += harnesses
install_inputs += version_smoke_checker

subdir('infra')
prose_files += infra_documents
install_inputs += infra_kits

subdir('packages/superloop-correspondence')
sync_outputs += pkg_superloop_correspondence_sync_outputs
rust_files += pkg_superloop_correspondence_rust
prose_files += pkg_superloop_correspondence_prose
declaration_files += pkg_superloop_correspondence_toml
install_inputs += pkg_superloop_correspondence_install
excluded_subjects += pkg_superloop_correspondence_excluded_rust
excluded_subjects += pkg_superloop_correspondence_excluded_prose
excluded_subjects += pkg_superloop_correspondence_excluded_toml

subdir('packages/superloop-steward')
sync_outputs += pkg_superloop_steward_sync_outputs
rust_files += pkg_superloop_steward_rust
prose_files += pkg_superloop_steward_prose
declaration_files += pkg_superloop_steward_toml
install_inputs += pkg_superloop_steward_install
excluded_subjects += pkg_superloop_steward_excluded_rust
excluded_subjects += pkg_superloop_steward_excluded_prose
excluded_subjects += pkg_superloop_steward_excluded_toml

subdir('packages/superloop-node-status')
sync_outputs += pkg_superloop_node_status_sync_outputs
rust_files += pkg_superloop_node_status_rust
prose_files += pkg_superloop_node_status_prose
declaration_files += pkg_superloop_node_status_toml
install_inputs += pkg_superloop_node_status_install
excluded_subjects += pkg_superloop_node_status_excluded_rust
excluded_subjects += pkg_superloop_node_status_excluded_prose
excluded_subjects += pkg_superloop_node_status_excluded_toml

subdir('packages/superloop-claude-desktop')
sync_outputs += pkg_superloop_claude_desktop_sync_outputs
rust_files += pkg_superloop_claude_desktop_rust
prose_files += pkg_superloop_claude_desktop_prose
declaration_files += pkg_superloop_claude_desktop_toml
install_inputs += pkg_superloop_claude_desktop_install
excluded_subjects += pkg_superloop_claude_desktop_excluded_rust
excluded_subjects += pkg_superloop_claude_desktop_excluded_prose
excluded_subjects += pkg_superloop_claude_desktop_excluded_toml

subdir('packages/build-sync')
sync_outputs += pkg_build_sync_sync_outputs
rust_files += pkg_build_sync_rust
prose_files += pkg_build_sync_prose
declaration_files += pkg_build_sync_toml
install_inputs += pkg_build_sync_install
excluded_subjects += pkg_build_sync_excluded_rust
excluded_subjects += pkg_build_sync_excluded_prose
excluded_subjects += pkg_build_sync_excluded_toml

subdir('packages/superloop-chat-export')
sync_outputs += pkg_superloop_chat_export_sync_outputs
rust_files += pkg_superloop_chat_export_rust
prose_files += pkg_superloop_chat_export_prose
declaration_files += pkg_superloop_chat_export_toml
install_inputs += pkg_superloop_chat_export_install
excluded_subjects += pkg_superloop_chat_export_excluded_rust
excluded_subjects += pkg_superloop_chat_export_excluded_prose
excluded_subjects += pkg_superloop_chat_export_excluded_toml


subdir('packages/superloop-cli-common')
sync_outputs += pkg_superloop_cli_common_sync_outputs
rust_files += pkg_superloop_cli_common_rust
prose_files += pkg_superloop_cli_common_prose
declaration_files += pkg_superloop_cli_common_toml
install_inputs += pkg_superloop_cli_common_install
excluded_subjects += pkg_superloop_cli_common_excluded_rust
excluded_subjects += pkg_superloop_cli_common_excluded_prose
excluded_subjects += pkg_superloop_cli_common_excluded_toml


subdir('packages/superloop-execwrap')
sync_outputs += pkg_superloop_execwrap_sync_outputs
rust_files += pkg_superloop_execwrap_rust
prose_files += pkg_superloop_execwrap_prose
declaration_files += pkg_superloop_execwrap_toml
install_inputs += pkg_superloop_execwrap_install
excluded_subjects += pkg_superloop_execwrap_excluded_rust
excluded_subjects += pkg_superloop_execwrap_excluded_prose
excluded_subjects += pkg_superloop_execwrap_excluded_toml

subdir('packages/lane-gateway')
sync_outputs += pkg_lane_gateway_sync_outputs
rust_files += pkg_lane_gateway_rust
prose_files += pkg_lane_gateway_prose
declaration_files += pkg_lane_gateway_toml
install_inputs += pkg_lane_gateway_install
excluded_subjects += pkg_lane_gateway_excluded_rust
excluded_subjects += pkg_lane_gateway_excluded_prose
excluded_subjects += pkg_lane_gateway_excluded_toml

subdir('packages/superloop-claude-hook')
sync_outputs += pkg_superloop_claude_hook_sync_outputs
rust_files += pkg_superloop_claude_hook_rust
prose_files += pkg_superloop_claude_hook_prose
declaration_files += pkg_superloop_claude_hook_toml
install_inputs += pkg_superloop_claude_hook_install
excluded_subjects += pkg_superloop_claude_hook_excluded_rust
excluded_subjects += pkg_superloop_claude_hook_excluded_prose
excluded_subjects += pkg_superloop_claude_hook_excluded_toml

subdir('packages/execute-command')
sync_outputs += pkg_execute_command_sync_outputs
rust_files += pkg_execute_command_rust
prose_files += pkg_execute_command_prose
declaration_files += pkg_execute_command_toml
install_inputs += pkg_execute_command_install
excluded_subjects += pkg_execute_command_excluded_rust
excluded_subjects += pkg_execute_command_excluded_prose
excluded_subjects += pkg_execute_command_excluded_toml

subdir('packages/request-core')
sync_outputs += pkg_request_core_sync_outputs
rust_files += pkg_request_core_rust
prose_files += pkg_request_core_prose
declaration_files += pkg_request_core_toml
install_inputs += pkg_request_core_install
excluded_subjects += pkg_request_core_excluded_rust
excluded_subjects += pkg_request_core_excluded_prose
excluded_subjects += pkg_request_core_excluded_toml

subdir('packages/session-core')
sync_outputs += pkg_session_core_sync_outputs
rust_files += pkg_session_core_rust
prose_files += pkg_session_core_prose
declaration_files += pkg_session_core_toml
install_inputs += pkg_session_core_install
excluded_subjects += pkg_session_core_excluded_rust
excluded_subjects += pkg_session_core_excluded_prose
excluded_subjects += pkg_session_core_excluded_toml

subdir('packages/lane-lifecycle')
sync_outputs += pkg_lane_lifecycle_sync_outputs
rust_files += pkg_lane_lifecycle_rust
prose_files += pkg_lane_lifecycle_prose
declaration_files += pkg_lane_lifecycle_toml
install_inputs += pkg_lane_lifecycle_install
excluded_subjects += pkg_lane_lifecycle_excluded_rust
excluded_subjects += pkg_lane_lifecycle_excluded_prose
excluded_subjects += pkg_lane_lifecycle_excluded_toml

subdir('packages/superloop-gate-submit')
sync_outputs += pkg_superloop_gate_submit_sync_outputs
rust_files += pkg_superloop_gate_submit_rust
prose_files += pkg_superloop_gate_submit_prose
declaration_files += pkg_superloop_gate_submit_toml
install_inputs += pkg_superloop_gate_submit_install
excluded_subjects += pkg_superloop_gate_submit_excluded_rust
excluded_subjects += pkg_superloop_gate_submit_excluded_prose
excluded_subjects += pkg_superloop_gate_submit_excluded_toml


subdir('packages/superloop-lint')
install_inputs += files('ci/test_docstring_carrier.py')
sync_outputs += pkg_superloop_lint_sync_outputs
rust_files += pkg_superloop_lint_rust
prose_files += pkg_superloop_lint_prose
declaration_files += pkg_superloop_lint_toml
install_inputs += pkg_superloop_lint_install
excluded_subjects += pkg_superloop_lint_excluded_rust
excluded_subjects += pkg_superloop_lint_excluded_prose
excluded_subjects += pkg_superloop_lint_excluded_toml

subdir('packages/loop-home')
sync_outputs += pkg_loop_home_sync_outputs
rust_files += pkg_loop_home_rust
prose_files += pkg_loop_home_prose
declaration_files += pkg_loop_home_toml
install_inputs += pkg_loop_home_install
excluded_subjects += pkg_loop_home_excluded_rust
excluded_subjects += pkg_loop_home_excluded_prose
excluded_subjects += pkg_loop_home_excluded_toml

subdir('packages/superloop')
sync_outputs += pkg_superloop_sync_outputs
rust_files += pkg_superloop_rust
prose_files += pkg_superloop_prose
declaration_files += pkg_superloop_toml
install_inputs += pkg_superloop_install
excluded_subjects += pkg_superloop_excluded_rust
excluded_subjects += pkg_superloop_excluded_prose
excluded_subjects += pkg_superloop_excluded_toml

subdir('packages/permission-triage')
sync_outputs += pkg_permission_triage_sync_outputs
rust_files += pkg_permission_triage_rust
prose_files += pkg_permission_triage_prose
declaration_files += pkg_permission_triage_toml
install_inputs += pkg_permission_triage_install
excluded_subjects += pkg_permission_triage_excluded_rust
excluded_subjects += pkg_permission_triage_excluded_prose
excluded_subjects += pkg_permission_triage_excluded_toml

subdir('packages/superloop-pack')
sync_outputs += pkg_superloop_pack_sync_outputs
rust_files += pkg_superloop_pack_rust
prose_files += pkg_superloop_pack_prose
declaration_files += pkg_superloop_pack_toml
install_inputs += pkg_superloop_pack_install
excluded_subjects += pkg_superloop_pack_excluded_rust
excluded_subjects += pkg_superloop_pack_excluded_prose
excluded_subjects += pkg_superloop_pack_excluded_toml

subdir('packages/pulldown-cmark-to-cmark')
sync_outputs += pkg_pulldown_cmark_to_cmark_sync_outputs
rust_files += pkg_pulldown_cmark_to_cmark_rust
prose_files += pkg_pulldown_cmark_to_cmark_prose
declaration_files += pkg_pulldown_cmark_to_cmark_toml
install_inputs += pkg_pulldown_cmark_to_cmark_install
excluded_subjects += pkg_pulldown_cmark_to_cmark_excluded_rust
excluded_subjects += pkg_pulldown_cmark_to_cmark_excluded_prose
excluded_subjects += pkg_pulldown_cmark_to_cmark_excluded_toml

subdir('packages/superloop-install')
sync_outputs += pkg_superloop_install_sync_outputs
rust_files += pkg_superloop_install_rust
prose_files += pkg_superloop_install_prose
declaration_files += pkg_superloop_install_toml
install_inputs += pkg_superloop_install_install
excluded_subjects += pkg_superloop_install_excluded_rust
excluded_subjects += pkg_superloop_install_excluded_prose
excluded_subjects += pkg_superloop_install_excluded_toml

subdir('packages/superloop-run-report')
sync_outputs += pkg_superloop_run_report_sync_outputs
rust_files += pkg_superloop_run_report_rust
prose_files += pkg_superloop_run_report_prose
declaration_files += pkg_superloop_run_report_toml
install_inputs += pkg_superloop_run_report_install
excluded_subjects += pkg_superloop_run_report_excluded_rust
excluded_subjects += pkg_superloop_run_report_excluded_prose
excluded_subjects += pkg_superloop_run_report_excluded_toml

subdir('packages/superloop-runtime')
sync_outputs += pkg_superloop_runtime_sync_outputs
rust_files += pkg_superloop_runtime_rust
prose_files += pkg_superloop_runtime_prose
declaration_files += pkg_superloop_runtime_toml
install_inputs += pkg_superloop_runtime_install
excluded_subjects += pkg_superloop_runtime_excluded_rust
excluded_subjects += pkg_superloop_runtime_excluded_prose
excluded_subjects += pkg_superloop_runtime_excluded_toml

subdir('packages/run-worker')
sync_outputs += pkg_run_worker_sync_outputs
rust_files += pkg_run_worker_rust
prose_files += pkg_run_worker_prose
declaration_files += pkg_run_worker_toml
install_inputs += pkg_run_worker_install
excluded_subjects += pkg_run_worker_excluded_rust
excluded_subjects += pkg_run_worker_excluded_prose
excluded_subjects += pkg_run_worker_excluded_toml

subdir('packages/staff-provision')
sync_outputs += pkg_staff_provision_sync_outputs
rust_files += pkg_staff_provision_rust
prose_files += pkg_staff_provision_prose
declaration_files += pkg_staff_provision_toml
install_inputs += pkg_staff_provision_install
excluded_subjects += pkg_staff_provision_excluded_rust
excluded_subjects += pkg_staff_provision_excluded_prose
excluded_subjects += pkg_staff_provision_excluded_toml

subdir('packages/superloop-lane')
sync_outputs += pkg_superloop_lane_sync_outputs
rust_files += pkg_superloop_lane_rust
prose_files += pkg_superloop_lane_prose
declaration_files += pkg_superloop_lane_toml
install_inputs += pkg_superloop_lane_install
install_inputs += pkg_superloop_lane_probe
excluded_subjects += pkg_superloop_lane_excluded_rust
excluded_subjects += pkg_superloop_lane_excluded_prose
excluded_subjects += pkg_superloop_lane_excluded_toml


declared_files = prose_files + rust_files + declaration_files + install_inputs + workspace_builder

package_documents = []
foreach document : prose_files
  relative = fs.relative_to(document, meson.project_source_root())
  if relative.startswith('packages/') and relative != 'packages/README.md'
    package_documents += document
  endif
endforeach

declared_paths = []
foreach subject : declared_files
  declared_paths += fs.relative_to(subject, meson.project_source_root())
endforeach
excluded_paths = []
foreach subject : excluded_subjects
  excluded_paths += fs.relative_to(subject, meson.project_source_root())
endforeach
declared_configuration = configuration_data()
declared_configuration.set('PATHS', '\n'.join(declared_paths))
excluded_configuration = configuration_data()
excluded_configuration.set('PATHS', '\n'.join(excluded_paths))
declared_list = configure_file(input: 'packages/superloop-lint/meson-paths.in', output: 'declared-paths.txt', configuration: declared_configuration)
excluded_list = configure_file(input: 'packages/superloop-lint/meson-paths.in', output: 'excluded-paths.txt', configuration: excluded_configuration)

linter_check = custom_target(
  'linter-check',
  input: prose_files + rust_files + declaration_files + install_inputs + [pkg_superloop_lint_sync_linter[0]],
  output: ['linter-check.stamp', 'linter-check.json'],
  command: [pkg_superloop_lint_sync_linter[0], 'check', '--root', meson.project_source_root(), '--write-report', '@OUTPUT1@', '--write-stamp', '@OUTPUT0@'],
  build_by_default: true,
)
linter_project = custom_target(
  'linter-project',
  input: rust_files + package_documents + declaration_files + [pkg_superloop_lint_sync_linter[0]],
  output: ['linter-project.stamp', 'linter-project.json'],
  command: [pkg_superloop_lint_sync_linter[0], 'project', '--root', meson.project_source_root(), '--write-report', '@OUTPUT1@', '--write-stamp', '@OUTPUT0@'],
  build_by_default: true,
)
linter_fmt = custom_target(
  'linter-fmt',
  input: prose_files + [pkg_superloop_lint_sync_linter[0]],
  output: ['linter-fmt.stamp', 'linter-fmt.json'],
  command: [pkg_superloop_lint_sync_linter[0], 'fmt', '--check'] + prose_files + ['--write-report', '@OUTPUT1@', '--write-stamp', '@OUTPUT0@'],
  build_by_default: true,
)
meson_census = custom_target(
  'census',
  input: [declared_list, excluded_list, pkg_superloop_lint_sync_linter[0]],
  output: ['census.stamp', 'census.json'],
  command: [pkg_superloop_lint_sync_linter[0], 'census', '--root', meson.project_source_root(), '--declared', declared_list, '--excluded', excluded_list, '--pattern', excluded_pattern, '--write-report', '@OUTPUT1@', '--write-stamp', '@OUTPUT0@'],
  build_always_stale: true,
  build_by_default: true,
)

run_target('linter-project-write', command: [pkg_superloop_lint_sync_linter[0], 'project', '--root', meson.project_source_root(), '--write'], depends: pkg_superloop_lint_sync_linter)
run_target('linter-fmt-write', command: [pkg_superloop_lint_sync_linter[0], 'fmt'] + prose_files, depends: pkg_superloop_lint_sync_linter)

foreach name, stamp : {'linter-check': linter_check, 'linter-project': linter_project, 'linter-fmt': linter_fmt, 'census': meson_census}
  # A loaded-node check took 40.6 seconds before parallel contention; retain
  # headroom for four concurrent probes without an external timeout multiplier.
  test(name, find_program('env'), args: [workspace_sync, '--probe', stamp[0]], depends: [stamp, workspace_build], suite: 'lint', workdir: meson.project_source_root(), timeout: 180)
endforeach

syntax_scripts = harnesses + infra_shell_scripts
test('slow-route-transfer', cargo,
  args: ['test', '--locked', '-p', 'superloop-lane', '--lib', 'door::transport::tests::route_tests::door_upload_large_mirror_through_route', '--', '--ignored', '--exact'],
  suite: 'slow', workdir: meson.project_source_root(), timeout: 300)

foreach script : syntax_scripts
  relative = fs.relative_to(script, meson.project_source_root())
  test('syntax-' + relative.replace('/', '-').replace('.', '-'), bash, args: ['-n', script], suite: 'lint', timeout: 10)
endforeach

server_kit_test_env = [
  'SIGNIN_TEST_BINARY=' + pkg_superloop_lane_sync_superloop_lane[0].full_path(),
  'SUPERLOOP_TEST_BINARY=' + pkg_superloop_sync_superloop[0].full_path(),
  'RUNTIME_TEST_BINARY=' + pkg_superloop_runtime_sync_superloop_runtime[0].full_path(),
  'STEWARD_TEST_EXPORTER=' + meson.project_build_root() / 'versioned-infra-steward-transcript-export',
  'STEWARD_TEST_RUNNER=' + meson.project_build_root() / 'versioned-infra-steward-steward-runner',
  'GATEWAY_RUNNER_TEST_BINARY=' + meson.project_build_root() / 'versioned-libexec-gateway-runner',
  'STEWARD_TEST_APPEND=' + meson.project_build_root() / 'versioned-infra-steward-steward-spool-append',
  'STEWARD_TEST_SERVICE=' + meson.project_build_root() / 'superloop-steward.service',
  'STEWARD_TEST_TIMER=' + meson.project_build_root() / 'superloop-steward.timer',
  'CORRESPONDENCE_TEST_SCAN=' + meson.project_build_root() / 'versioned-infra-correspondence-watch-correspondence-scan',
  'TARGET_CLEAN_TEST_BINARY=' + meson.project_build_root() / 'versioned-infra-cargo-clean-target-clean',
  'SERVER_KIT_PRIVATE_DIR=' + get_option('prefix') / get_option('libexecdir') / 'superloop',
]

foreach script : harness_runs
  relative = fs.relative_to(script, meson.project_source_root())
  test('release-harness-' + relative.replace('/', '-').replace('.', '-'), bash,
    args: [script], env: server_kit_test_env + ['CORRESPONDENCE_TEST_BINARY=' + pkg_superloop_correspondence_sync[0].full_path(), 'STEWARD_TEST_BINARY=' + pkg_superloop_steward_sync[0].full_path()], depends: [pkg_superloop_correspondence_sync, pkg_superloop_steward_sync, pkg_superloop_runtime_sync_superloop_runtime, pkg_superloop_sync_superloop, pkg_superloop_lane_sync_superloop_lane], suite: 'release', workdir: meson.project_source_root(), timeout: 60)
endforeach

test('release-linter-check', pkg_superloop_lint_sync_linter[0], args: ['check', '--root', meson.project_source_root()], depends: pkg_superloop_lint_sync_linter, suite: 'release', timeout: 30)
test('release-python-docstring-carrier', python,
  args: ['-I', '-B', '-m', 'unittest', 'discover', '-s', meson.project_source_root() / 'ci', '-p', 'test_docstring_carrier.py'],
  depends: pkg_superloop_lint_sync_linter, suite: 'release', timeout: 30)
test('release-census', pkg_superloop_lint_sync_linter[0], args: ['census', '--root', meson.project_source_root(), '--declared', declared_list, '--excluded', excluded_list, '--pattern', excluded_pattern], depends: pkg_superloop_lint_sync_linter, suite: 'release', timeout: 30)
# Installed identity is the key; distinct private and hook destinations may share a basename.
rust_version_roster = {
  'bin/superloop-runtime': 'packages/superloop-runtime/superloop-runtime',
  'libexec/build-sync': 'packages/build-sync/build-sync',
  'bin/superloop-chat-export': 'packages/superloop-chat-export/superloop-chat-export',
  'libexec/gateway-service': 'packages/lane-gateway/gateway-service',
  'bin/superloop-gate-submit': 'packages/superloop-gate-submit/superloop-gate-submit',
  'bin/superloop-lint': 'packages/superloop-lint/superloop-lint',
  'bin/superloop': 'packages/superloop/superloop',
  'libexec/permission-triage-assemble': 'packages/permission-triage/permission-triage-assemble',
  'libexec/permission-triage-topology': 'packages/permission-triage/permission-triage-topology',
  'libexec/permission-triage-hook': 'packages/permission-triage/permission-triage-hook',
  'libexec/requests-helper': 'packages/permission-triage/requests-helper',
  'bin/superloop-pack': 'packages/superloop-pack/superloop-pack',
  'bin/superloop-install': 'packages/superloop-install/superloop-install',
  'build/superloop-run-report': 'packages/superloop-run-report/superloop-run-report',
  'libexec/worker-run': 'packages/run-worker/worker-run',
  'libexec/account': 'packages/staff-provision/account',
  'bin/superloop-claude-desktop': 'packages/superloop-claude-desktop/superloop-claude-desktop',
  'libexec/superloop-claude-hook': 'packages/superloop-claude-hook/superloop-claude-hook',
  'bin/superloop-correspondence': 'packages/superloop-correspondence/superloop-correspondence',
  'bin/superloop-lane': 'packages/superloop-lane/superloop-lane',
  'libexec/vendor-proxy': 'packages/superloop-lane/vendor-proxy',
  'libexec/door-ssh': 'packages/superloop-lane/door-ssh',
  'libexec/door-service': 'packages/superloop-lane/door-service',
  'bin/superloop-node-status': 'packages/superloop-node-status/superloop-node-status',
  'bin/superloop-steward': 'packages/superloop-steward/superloop-steward',
}
assert(rust_version_roster.keys().length() == sync_outputs.length(), 'version roster must cover every synced Rust program')
version_seen = []
foreach identity, path : rust_version_roster
  matched = false
  foreach synced : sync_outputs
    binary = synced[0]
    if fs.relative_to(binary.full_path(), meson.project_build_root()) == path
      assert(not matched and not version_seen.contains(path), 'duplicate version roster output: ' + path)
      matched = true
      version_seen += path
      package_manifest = meson.project_source_root() / fs.parent(path) / 'Cargo.toml'
      version_args = [version_smoke_checker[0], '--manifest', package_manifest, '--installed-name', fs.name(identity), '--binary', binary, '--record', synced[1], '--record-commit', tools_source_commit, '--repository', meson.project_name()]
      if identity == 'bin/superloop-lane'
        version_args += ['--commit', lane_source_commit]
      endif
      test('version-' + identity.replace('/', '-'), python, args: version_args, depends: synced, suite: 'release', timeout: 30)
    endif
  endforeach
  assert(matched, 'version roster names an absent output: ' + path)
endforeach

server_kit_programs = {
  'infra/steward/transcript-export': 'server-steward',
  'infra/steward/steward-runner': 'server-steward',
  'infra/steward/steward-spool-append': 'server-steward',
  'infra/correspondence-watch/correspondence-scan': 'server-correspondence',
  'infra/cargo-clean/target-clean': 'server-target-clean',
}

steward_projects_root = get_option('steward_projects_root')
assert(not get_option('server_kits') or steward_projects_root != '', 'server_kits requires -Dsteward_projects_root=PATH')
if steward_projects_root != ''
  assert(steward_projects_root.startswith('/') and steward_projects_root != '/', 'steward_projects_root must be an absolute projects directory, not /')
  assert(not steward_projects_root.contains('\n') and not steward_projects_root.contains('\r'), 'steward_projects_root must be a single line')
endif
# Escape the configured path for the exporter's double-quoted shell literal.
steward_projects_root_shell = steward_projects_root.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')

# Shell-only groups own the explicit version here; Rust groups read their manifest.
script_version_roster = {
  'libexec/gateway-runner': ['packages/lane-gateway/Cargo.toml', '', 'lane-gateway'],
  'infra/steward/transcript-export': ['packages/superloop-steward/Cargo.toml', '', 'steward'],
  'infra/cargo-clean/target-clean': ['', '0.1.0', 'cargo-clean'],
  'infra/correspondence-watch/correspondence-scan': ['packages/superloop-correspondence/Cargo.toml', '', 'correspondence'],
  'infra/steward/steward-runner': ['packages/superloop-steward/Cargo.toml', '', 'steward'],
  'infra/steward/steward-spool-append': ['packages/superloop-steward/Cargo.toml', '', 'steward'],
  'infra/gate/run-slot.sh': ['', '0.1.0', 'gate-slot'],
}
script_sources = {'libexec/gateway-runner': 'packages/lane-gateway/gateway-runner'}
foreach identity, authority : script_version_roster
  source = script_sources.get(identity, identity)
  script_version = authority[1]
  if authority[0] != ''
    script_version = run_command(python, '-c', 'import sys,tomllib; v=tomllib.load(open(sys.argv[1], "rb"))["package"]["version"]; print(tomllib.load(open(sys.argv[2], "rb"))["workspace"]["package"]["version"] if v == {"workspace": True} else v)', files(authority[0]), root_manifest, check: true).stdout().strip()
  endif
  config = configuration_data()
  config.set('VERSION', script_version)
  config.set('STEWARD_PROJECTS_ROOT', steward_projects_root_shell)
  config.set('CHARTER_FILE', get_option('prefix') / get_option('sysconfdir') / 'steward' / 'charter.md')
  config.set('PRIVATE_DIR', get_option('prefix') / get_option('libexecdir') / 'superloop')
  output_name = 'versioned-' + identity.replace('/', '-')
  program = configure_file(input: source, output: output_name, configuration: config)
  record = custom_target('record-' + output_name,
    input: program, output: output_name + '.build.json',
    command: [pkg_build_sync_sync_build_sync[0], build_identity_args, '--domain', domain, '--record', '@INPUT@', '--producer', meson_program.full_path()],
    depends: pkg_build_sync_sync_build_sync, build_by_default: true,
    install: source == 'packages/lane-gateway/gateway-runner' or (get_option('server_kits') and source in server_kit_programs),
    install_dir: get_option('datadir') / 'superloop' / 'build-records',
    install_tag: server_kit_programs.get(source, 'runtime'))
  if source == 'packages/lane-gateway/gateway-runner' or (get_option('server_kits') and source in server_kit_programs)
    install_data(program, install_dir: get_option('libexecdir') / 'superloop',
      rename: fs.name(source), install_mode: 'rwxr-xr-x', install_tag: server_kit_programs.get(source, 'runtime'))
  endif
  test('version-' + source.replace('/', '-'), python,
    args: [version_smoke_checker[0], '--binary', program, '--installed-name', fs.name(source), '--expected-version', script_version, '--release-group', authority[2], '--record', record, '--record-commit', tools_source_commit, '--repository', meson.project_name()],
    depends: record, suite: 'release', timeout: 30)
endforeach

server_kit_units = {
  'infra/steward/superloop-steward.service': 'server-steward',
  'infra/steward/superloop-steward.timer': 'server-steward',
  'infra/correspondence-watch/superloop-correspondence-scan.service': 'server-correspondence',
  'infra/correspondence-watch/superloop-correspondence-scan.timer': 'server-correspondence',
  'infra/cargo-clean/superloop-target-clean@.service': 'server-target-clean',
  'infra/cargo-clean/superloop-target-clean@.timer': 'server-target-clean',
}
kit_configuration = configuration_data()
kit_configuration.set('PRIVATE_DIR', get_option('prefix') / get_option('libexecdir') / 'superloop')
foreach source, tag : server_kit_units
  configure_file(input: source, output: fs.name(source), configuration: kit_configuration,
    install: get_option('server_kits'), install_dir: get_option('system_unitdir'), install_tag: tag)
endforeach

if get_option('server_kits')
  install_data('infra/steward/charter.md', install_dir: get_option('sysconfdir') / 'steward', install_tag: 'server-steward')
endif

# Staging targets share one workspace build and retain the declared installed names.
alias_target('binary-syncs', sync_outputs)

test('cargo-fmt', cargo_fmt, args: ['--all', '--check'], suite: 'cargo', workdir: meson.project_source_root(), timeout: 60, is_parallel: false)
test('cargo-clippy', cargo, args: ['clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'], suite: 'cargo', workdir: meson.project_source_root(), timeout: 180, is_parallel: false)
test('cargo-test', cargo, args: ['test', '--profile', 'gate', '--workspace', '--locked', '--no-fail-fast'], env: {'SUPERLOOP_TEST_BINARY': pkg_superloop_sync_superloop[0].full_path(), 'SUPERLOOP_TEST_CLAUDE_HOOK': pkg_superloop_claude_hook_sync_adapter[0].full_path(), 'RUNTIME_TEST_BINARY': pkg_superloop_runtime_sync_superloop_runtime[0].full_path(), 'STEWARD_TEST_EXPORTER': meson.project_build_root() / 'versioned-infra-steward-transcript-export', 'PUBLIC_PACK_TEST_LINTER': pkg_superloop_lint_sync_linter[0].full_path(), 'SUPERLOOP_TEST_REQUESTS_HELPER': pkg_permission_triage_sync_requests[0].full_path()}, depends: [pkg_superloop_lint_sync_linter, pkg_permission_triage_sync_requests, pkg_superloop_sync_superloop, pkg_superloop_claude_hook_sync_adapter, pkg_superloop_runtime_sync_superloop_runtime, pkg_superloop_lane_sync_superloop_lane], suite: 'cargo', workdir: meson.project_source_root(), timeout: 1800, is_parallel: false)

# Machine-readable Meson ledger rows; build-sync checks their measured identities.











































dependency_ledger += ['''
{"kind":"installation-inputs","owner":"TOOLS","maps":[],"document_roots":["docs/spec"]}
{"kind":"admission","name":"clap","reason":"Typed argument grammar and help","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"libc","reason":"Unix descriptors and identities","owner":"LOOPHOME"}
{"kind":"admission","name":"minijinja","reason":"Embedded export templates","owner":"SUPERLOOPCHATEXPORT"}
{"kind":"admission","name":"nix","reason":"Unix process and namespace operations","owner":"LOOPHOME"}
{"kind":"admission","name":"petgraph","reason":"Hook state graphs and linter graph analysis","owner":"ORCHESTRATORHOOK"}
{"kind":"admission","name":"proc-macro2","reason":"Rust source locations","owner":"SUPERLOOPLINT"}
{"kind":"admission","name":"pulldown-cmark","reason":"Markdown event parsing","owner":"SUPERLOOPLINT"}
{"kind":"admission","name":"regex","reason":"Declared text matching","owner":"SUPERLOOPLINT"}
{"kind":"admission","name":"serde","reason":"Typed interchange","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"serde_json","reason":"JSON reports","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"sha2","reason":"Content identity and provenance","owner":"BUILDSYNC"}
{"kind":"admission","name":"syn","reason":"Rust syntax","owner":"SUPERLOOPLINT"}
{"kind":"admission","name":"tempfile","reason":"Bounded staging and isolated fixtures","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"textwrap","reason":"Wrapper presentation","owner":"SUPERLOOPEXECWRAP"}
{"kind":"admission","name":"thiserror","reason":"Typed library errors","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"toml","reason":"Configuration decoding","owner":"LOOPHOME"}
{"kind":"admission","name":"tracing","reason":"Structured diagnostics","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"tracing-subscriber","reason":"Diagnostic filtering","owner":"SUPERLOOPCLICOMMON"}
{"kind":"admission","name":"url","reason":"URL argument validation","owner":"SUPERLOOPCLICOMMON"}
{"kind":"closure","name":"aho-corasick","version":"1.1.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"c982642fa9e8606056828ee9a8505737230110bb1099153c79efe865c59d12ba","direct_roots":["regex","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON","SUPERLOOPLINT"]}
{"kind":"closure","name":"anstream","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"824a212faf96e9acacdbd09febd34438f8f711fb84e09a8916013cd7815ca28d","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"anstyle","version":"1.0.14","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"940b3a0ca603d1eade50a4846a2afffd5ef57a9feac2c0e2ec2e14f9ead76000","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"anstyle-parse","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"52ce7f38b242319f7cabaa6813055467063ecdc9d355bbb4ce0c68908cd8130e","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"anstyle-query","version":"1.1.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"40c48f72fd53cd289104fc64099abca73db4166ad86ea0b4341abe65af83dadc","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"anstyle-wincon","version":"3.0.11","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"291e6a250ff86cd4a820112fb8898808a366d8f9f58ce16d1f538353ad55747d","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"bitflags","version":"2.13.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da","direct_roots":["nix","pulldown-cmark","tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON","SUPERLOOPLINT","LOOPHOME"]}
{"kind":"closure","name":"block-buffer","version":"0.12.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"cfg-if","version":"1.0.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801","direct_roots":["nix","sha2","tempfile","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC","SUPERLOOPCLICOMMON","LOOPHOME"]}
{"kind":"closure","name":"cfg_aliases","version":"0.2.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f079e83a288787bcd14a6aea84cee5c87a67c5a3e660c30f557a3d24761b3527","direct_roots":["nix"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"clap","version":"4.6.6","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"473c7e07f409a8d772161724aa8db6a765a2532a70f9667eeb7b49d3d02fbdca","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"clap_builder","version":"4.6.6","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"7b48fea5a88e9ae728a2dcbedbfc0e730f7d60da42e1cb049a83c9fb8b789889","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"clap_derive","version":"4.6.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d012d2b9d65aca7f18f4d9878a045bc17899bba951561ba5ec3c2ba1eed9a061","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"clap_lex","version":"1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"c8d4a3bb8b1e0c1050499d1815f5ab16d04f0959b233085fb31653fbfc9d98f9","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"colorchoice","version":"1.0.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"1d07550c9036bf2ae0c684c4297d503f838287c83c53686d05370d0e139ae570","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"const-oid","version":"0.10.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"a6ef517f0926dd24a1582492c791b6a4818a4d94e789a334894aa15b0d12f55c","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"cpufeatures","version":"0.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"5ca28b0ae3115b884660db4118d803791fd6756b6e88f39c0f3f7859060d7566","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"crypto-common","version":"0.2.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"digest","version":"0.11.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"displaydoc","version":"0.2.7","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"c6232dd377dcc64799954cbd3a9bb882e9cdc1308ccd87b1c098f1fb2eaf82a8","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"equivalent","version":"1.0.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f","direct_roots":["petgraph","toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"errno","version":"0.3.14","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"fastrand","version":"2.5.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"da7c62ceae207dd37ea5b845da6a0696c799f85e97da1ab5b7910be3c1c80223","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"fixedbitset","version":"0.5.7","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"1d674e81391d1e1ab681a28d99df07927c6d4aa5b027d7da16ba32d1d21ecd99","direct_roots":["petgraph"],"reason":"Locked implementation dependency of the named direct roots","owners":["ORCHESTRATORHOOK"]}
{"kind":"closure","name":"foldhash","version":"0.1.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d9c4f5dac5e15c24eb999c26181a6ca40b39fe946cbe4c263c7209467bc83af2","direct_roots":["petgraph"],"reason":"Locked implementation dependency of the named direct roots","owners":["ORCHESTRATORHOOK"]}
{"kind":"closure","name":"form_urlencoded","version":"1.2.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"cb4cb245038516f5f85277875cdaa4f7d2c9a0fa0468de06ed190163b1581fcf","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"getrandom","version":"0.4.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"hashbrown","version":"0.15.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"9229cfe53dfd69f0609a49f65461bd93001ea1ef889cd5529dd176593f5338a1","direct_roots":["petgraph"],"reason":"Locked implementation dependency of the named direct roots","owners":["ORCHESTRATORHOOK"]}
{"kind":"closure","name":"hashbrown","version":"0.17.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a","direct_roots":["petgraph","toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"heck","version":"0.5.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"hybrid-array","version":"0.4.14","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"707114b52a152fa7bdb290cd7cd5912d9467273b6d74e21b8d81aca1f8533f6b","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"icu_collections","version":"2.3.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"fa68d21081c4a05d5a901a1c62add574c77048b6a1c67be3b50ce0b60d4ca513","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"icu_locale_core","version":"2.3.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d56e28588da92eee5c3201a6eff33fabdd49b62269c8938d4ff050ce4d900deb","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"icu_normalizer","version":"2.3.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"12f9cf5f235641ed274641dd81c3f28d870e276763d0797aeeab72317b1c646f","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"icu_normalizer_data","version":"2.3.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"1563da1ed3e0b3bf3d74c9b85917ac9c56464d2f57242270c09c9e752f8021a0","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"icu_properties","version":"2.3.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"7e7ca276ad3145661a65914e6daf131ca5120cd3dcee8f8f3214b8875184a148","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"icu_properties_data","version":"2.3.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"e590f038c1464a96894fd6d10127e90a8be4509f56ff7ecef851b15cee0b7caa","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"icu_provider","version":"2.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d27bbb9d3abbefac45d55f647c9de1d44aafcd1186eb91879afef17c396c3e73","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"idna","version":"1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"3b0875f23caa03898994f6ddc501886a45c7d3d62d04d2d90788d47be1b1e4de","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"idna_adapter","version":"1.2.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"cb68373c0d6620ef8105e855e7745e18b0d00d3bdb07fb532e434244cdb9a714","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"indexmap","version":"2.14.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d466e9454f08e4a911e14806c24e16fba1b4c121d1ea474396f396069cf949d9","direct_roots":["petgraph","toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"is_terminal_polyfill","version":"1.70.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"a6cb138bb79a146c1bd460005623e142ef0181e3d0219cb493e02f7d08a35695","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"itoa","version":"1.0.18","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682","direct_roots":["serde_json","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"lazy_static","version":"1.5.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"bbd2bcb4c963f2ddae06a2efc7e9f3591312473c50c6685e1f298068316e66fe","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"libc","version":"0.2.189","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2","direct_roots":["libc","nix","sha2","tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC","SUPERLOOPCLICOMMON","LOOPHOME"]}
{"kind":"closure","name":"linux-raw-sys","version":"0.12.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"litemap","version":"0.8.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"47d9d19d1d6efa0109d2f65ff4c85cddd50bd572e5a00127ab10987290bcefae","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"log","version":"0.4.34","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f9f8bd3e56ce4dfc153cf470fffbfa98c7620958b312ca5c3a4b8d5181fd13c6","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"matchers","version":"0.2.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d1525a2a28c7f4fa0fc98bb91ae755d1e2d1505079e05539e35bc876b5d65ae9","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"memchr","version":"2.8.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98","direct_roots":["pulldown-cmark","regex","serde_json","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON","SUPERLOOPLINT"]}
{"kind":"closure","name":"memo-map","version":"0.3.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"5449c8c750f1a07ea702bbd212bd999fceece9b3d1508b17023b3e174583124b","direct_roots":["minijinja"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT"]}
{"kind":"closure","name":"minijinja","version":"2.24.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"86886cf6dbf4e614b19c9a1eec9775f021869d7eadde0fc73921a81b90c9b4c9","direct_roots":["minijinja"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT"]}
{"kind":"closure","name":"nix","version":"0.31.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d","direct_roots":["nix"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"nu-ansi-term","version":"0.50.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"7957b9740744892f114936ab4a57b3f487491bbeafaf8083688b16841a4240e5","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"once_cell","version":"1.21.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50","direct_roots":["tempfile","tracing","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"once_cell_polyfill","version":"1.70.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"384b8ab6d37215f3c5301a95a4accb5d64aa607f1fcb26a11b5303878451b4fe","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"percent-encoding","version":"2.3.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"petgraph","version":"0.8.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"8701b58ea97060d5e5b155d383a69952a60943f0e6dfe30b04c287beb0b27455","direct_roots":["petgraph"],"reason":"Locked implementation dependency of the named direct roots","owners":["ORCHESTRATORHOOK"]}
{"kind":"closure","name":"pin-project-lite","version":"0.2.17","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd","direct_roots":["tracing","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"potential_utf","version":"0.1.6","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d83eb9bc6d8e5cf568e7a1101d60ee05e81ed50ea106026f3d18deeb046d7661","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"proc-macro2","version":"1.0.107","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9","direct_roots":["clap","minijinja","petgraph","proc-macro2","serde","serde_json","syn","thiserror","toml","tracing","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","SUPERLOOPLINT","LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"pulldown-cmark","version":"0.13.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"e9f068eba8e7071c5f9511831b44f32c740d5adf574e990f946ddb53db2f314e","direct_roots":["pulldown-cmark"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPLINT"]}
{"kind":"closure","name":"quote","version":"1.0.47","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001","direct_roots":["clap","minijinja","petgraph","serde","serde_json","syn","thiserror","toml","tracing","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","SUPERLOOPLINT","LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"r-efi","version":"6.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"regex","version":"1.13.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d","direct_roots":["regex"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPLINT"]}
{"kind":"closure","name":"regex-automata","version":"0.4.18","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ad8553b9b26413251cbf30e620595c7a41b3887f03da04579c0e6b0d6a06b4b2","direct_roots":["regex","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON","SUPERLOOPLINT"]}
{"kind":"closure","name":"regex-syntax","version":"0.8.11","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4","direct_roots":["regex","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON","SUPERLOOPLINT"]}
{"kind":"closure","name":"rustix","version":"1.1.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"serde","version":"1.0.229","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba","direct_roots":["minijinja","petgraph","serde","serde_json","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"serde_core","version":"1.0.229","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48","direct_roots":["minijinja","petgraph","serde","serde_json","toml","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"serde_derive","version":"1.0.229","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348","direct_roots":["minijinja","petgraph","serde","serde_json","toml","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"serde_json","version":"1.0.151","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14","direct_roots":["serde_json","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"serde_spanned","version":"1.1.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"6662b5879511e06e8999a8a235d848113e942c9124f211511b16466ee2995f26","direct_roots":["toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"sha2","version":"0.11.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"sharded-slab","version":"0.1.7","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f40ca3c46823713e0d4209592e8d6e826aa57e928f09752619fc696c499637f6","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"smallvec","version":"1.15.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90","direct_roots":["tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"smawk","version":"0.3.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"e8e2fb0f499abb4d162f2bedad68f5ef91a1682b5a03596ddb67efd37768d100","direct_roots":["textwrap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPEXECWRAP"]}
{"kind":"closure","name":"stable_deref_trait","version":"1.2.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"6ce2be8dc25455e1f91df71bfa12ad37d7af1092ae736f3a6cd0e37bc7810596","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"strsim","version":"0.11.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"7da8b5736845d9f2fcb837ea5d9e2628564b3b043a70948a3f0b778838c5fb4f","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"syn","version":"2.0.119","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297","direct_roots":["tracing","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"syn","version":"3.0.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3","direct_roots":["clap","minijinja","petgraph","serde","serde_json","syn","thiserror","toml","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","SUPERLOOPLINT","LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"synstructure","version":"0.13.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"728a70f3dbaf5bab7f0c4b1ac8d7ae5ea60a4b5549c8a5914361c99147a709d2","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tempfile","version":"3.27.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"32497e9a4c7b38532efcdebeef879707aa9f794296a4f0244f6f69e9bc8574bd","direct_roots":["tempfile"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"textwrap","version":"0.16.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"c13547615a44dc9c452a8a534638acdf07120d4b6847c8178705da06306a3057","direct_roots":["textwrap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPEXECWRAP"]}
{"kind":"closure","name":"thiserror","version":"2.0.20","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ec86235f5fcc2a73650310756d2ac5b138a5780bbbdfae3eeccec992c435ba4f","direct_roots":["thiserror"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"thiserror-impl","version":"2.0.20","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"bc04cd3e1236dd4a98afca4569f2deb3f120e5422a4023be2cb683f8486292af","direct_roots":["thiserror"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"thread_local","version":"1.1.10","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"1ad99c4c6d32803332c548b1af0540b357b3f5fc0be8f6c6bfe8b2e6ae784070","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tinystr","version":"0.8.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"b1e27c91459209c2986af3dcf603a5a74a4368754ce37414f59acc971167f643","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"toml","version":"1.1.4+spec-1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"3aace63f4bbcdfc2c965b059de67119c89c4017a70d633be6c104910f67056f5","direct_roots":["toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"toml_datetime","version":"1.1.1+spec-1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"3165f65f62e28e0115a00b2ebdd37eb6f3b641855f9d636d3cd4103767159ad7","direct_roots":["toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"toml_parser","version":"1.1.3+spec-1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"1d38ac1cf9b95face32296c0a3ede1fdc270627c9d9c02a7274dd6d960dc4d56","direct_roots":["toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"toml_writer","version":"1.1.2+spec-1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"7d56353a2a665ad0f41a421187180aab746c8c325620617ad883a99a1cbe66d2","direct_roots":["toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"tracing","version":"0.1.44","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100","direct_roots":["tracing","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tracing-attributes","version":"0.1.31","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"7490cfa5ec963746568740651ac6781f701c9c5ea257c58e057f3ba8cf69e8da","direct_roots":["tracing","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tracing-core","version":"0.1.36","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"db97caf9d906fbde555dd62fa95ddba9eecfd14cb388e4f491a66d74cd5fb79a","direct_roots":["tracing","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tracing-log","version":"0.2.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ee855f1f400bd0e5c02d150ae5de3840039a3f54b025156404e34c23c03f47c3","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tracing-serde","version":"0.2.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"704b1aeb7be0d0a84fc9828cae51dab5970fee5088f83d1dd7ee6f6246fc6ff1","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"tracing-subscriber","version":"0.3.23","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"cb7f578e5945fb242538965c2d0b04418d38ec25c79d160cd279bf0731c8d319","direct_roots":["tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"typenum","version":"1.20.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20","direct_roots":["sha2"],"reason":"Locked implementation dependency of the named direct roots","owners":["BUILDSYNC"]}
{"kind":"closure","name":"unicase","version":"2.9.0","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"dbc4bc3a9f746d862c45cb89d705aa10f187bb96c76001afab07a0d35ce60142","direct_roots":["pulldown-cmark"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPLINT"]}
{"kind":"closure","name":"unicode-ident","version":"1.0.24","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75","direct_roots":["clap","minijinja","petgraph","proc-macro2","serde","serde_json","syn","thiserror","toml","tracing","tracing-subscriber","url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCHATEXPORT","SUPERLOOPCLICOMMON","SUPERLOOPLINT","LOOPHOME","ORCHESTRATORHOOK"]}
{"kind":"closure","name":"unicode-linebreak","version":"0.1.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"3b09c83c3c29d37506a3e260c08c03743a6bb66a9cd432c6934ab501a190571f","direct_roots":["textwrap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPEXECWRAP"]}
{"kind":"closure","name":"unicode-width","version":"0.2.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"b4ac048d71ede7ee76d585517add45da530660ef4390e49b098733c6e897f254","direct_roots":["textwrap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPEXECWRAP"]}
{"kind":"closure","name":"url","version":"2.5.8","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"utf8_iter","version":"1.0.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"b6c140620e7ffbb22c2dee59cafe6084a59b5ffc27a8859a5f0d494b5d52b6be","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"utf8parse","version":"0.2.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"06abde3611657adf66d383f00b093d7faecc7fa57071cce2578660c9f1010821","direct_roots":["clap"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"valuable","version":"0.1.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ba73ea9cf16a25df0c8caa16c51acb937d5712a8429db78a3ee29d5dcacd3a65","direct_roots":["tracing","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"windows-link","version":"0.2.1","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5","direct_roots":["clap","tempfile","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"windows-sys","version":"0.61.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc","direct_roots":["clap","tempfile","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"winnow","version":"1.0.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"23b97319f7b8343df12cc98938e5c3eb436064524c8d2b4e30a1d3a36eecdf81","direct_roots":["toml"],"reason":"Locked implementation dependency of the named direct roots","owners":["LOOPHOME"]}
{"kind":"closure","name":"writeable","version":"0.6.4","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"3ad82d2a33cdc9674dc7465672f271e096168fcdbe0f799d9e6db8c5892679dc","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"yoke","version":"0.8.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"709fe23a0424b6a435d82152b1bd3fdfb0833487d5fa90d05d42762a9891fef5","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"yoke-derive","version":"0.8.2","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"de844c262c8848816172cef550288e7dc6c7b7814b4ee56b3e1553f275f1858e","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"zerofrom","version":"0.1.8","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"0ec05a11813ea801ff6d75110ad09cd0824ddba17dfe17128ea0d5f68e6c5272","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"zerofrom-derive","version":"0.1.7","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"11532158c46691caf0f2593ea8358fed6bbf68a0315e80aae9bd41fbade684a1","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"zerotrie","version":"0.2.5","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"4ea269c3bd32f0a32c321907a2ae912ba6f4649bb0fc764a15627e99a7095a3f","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"zerovec","version":"0.11.8","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"bb0464e17806c1d976d5cba29399c7f08e516e279e2ba493f63123b5fca67dd8","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"zerovec-derive","version":"0.11.6","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"34df6fc39dbd26ddc9c10e6a2984476e13acce22e64e4487636ef494369225da","direct_roots":["url"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"closure","name":"zmij","version":"1.0.23","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b","direct_roots":["serde_json","tracing-subscriber"],"reason":"Locked implementation dependency of the named direct roots","owners":["SUPERLOOPCLICOMMON"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`enter-loop`|`superloop`†|search path|","pending_bites":[],"installed_programs":["bin/superloop"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`superloop-lane`|stays `superloop-lane`|search path|","pending_bites":[],"installed_programs":["bin/superloop-lane"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`vendor-proxy`, `door-ssh`, `door-service`|stay in the lane release group|private directory|","pending_bites":[],"installed_programs":["libexec/vendor-proxy","libexec/door-ssh","libexec/door-service"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`requests-helper`|stays in the permission/request release group|private directory|","pending_bites":[],"installed_programs":["libexec/requests-helper"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`permission-triage-hook` binary|stays `hooks/permission-triage-hook`|private directory|","pending_bites":[],"installed_programs":["libexec/permission-triage-hook"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`superloop-claude-hook`|stays `hooks/superloop-claude-hook`|private directory|","pending_bites":[],"installed_programs":["libexec/superloop-claude-hook"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`superloop-lane-vendor@`, `superloop-lane-door@` unit templates|stay with the loop as instance|user unit directory|","pending_bites":[],"generated_units":[{"program":"bin/superloop-lane","source":"packages/superloop-lane/src/install.rs","anchor":"superloop-lane-vendor@{}.service","destination":"user-unit-directory/superloop-lane-vendor@LOOP.service"},{"program":"bin/superloop-lane","source":"packages/superloop-lane/src/install_door.rs","anchor":"superloop-lane-door@{}.service","destination":"user-unit-directory/superloop-lane-door@LOOP.service"}]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`claude-lane`, `codex-lane`|`superloop-lane driver start\\|resume --backend claude\\|codex`|search path|","installed_programs":["bin/superloop-lane"],"pending_bites":[]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`lane-watch`, `worker-monitor`|`superloop-lane driver status`, `superloop-lane driver follow [--save-offset]`|search path|","installed_programs":["bin/superloop-lane"],"pending_bites":[]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`lane-verify`|`superloop-gate-submit`†|search path|","pending_bites":[],"installed_programs":["bin/superloop-gate-submit"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`run-worker`|private `worker-run`†; `superloop-lane launch`†|private directory; search path|","pending_bites":[],"installed_programs":["bin/superloop-lane","libexec/worker-run"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`lane-gateway`, `gateway-runner`|private `gateway-service`†, `gateway-runner`; `superloop-lane gateway`†|private directory; search path|","pending_bites":[],"installed_programs":["libexec/gateway-service","libexec/gateway-runner","bin/superloop-lane"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`LOOP-gpg`, `LOOP-ssh`|generated `LOOP-gpg`, `LOOP-ssh`|user private directory|","pending_bites":[],"generated_programs":[{"program":"bin/superloop","source":"packages/superloop/src/bridges.rs","anchor":"format!(\"{name}-{kind}\")","destination":"@libexecdir@/superloop/LOOP-gpg"},{"program":"bin/superloop","source":"packages/superloop/src/bridges.rs","anchor":"format!(\"{name}-{kind}\")","destination":"@libexecdir@/superloop/LOOP-ssh"}]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`loop-gh`|`superloop run-bridge gh`†|search path|","pending_bites":[],"installed_programs":["bin/superloop"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`loop-codex-home`|`superloop-lane prepare-signin-home\\|check-signin-home --backend codex`†|search path|","pending_bites":[],"installed_programs":["bin/superloop-lane"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`loop-keygen`, `staff-provision`|private `account`†; `superloop account keygen\\|check\\|create\\|admit-key`†|private directory; search path|","pending_bites":[],"installed_programs":["bin/superloop","libexec/account"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`heartbeat-guard`, `superloop`, `heartbeat`|private `hooks/superloop-claude-hook stop\\|pre-tool-use`†; `superloop heartbeat on\\|off\\|status`†|private directory; search path|","pending_bites":[],"installed_programs":["bin/superloop","libexec/superloop-claude-hook"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`orchestrator-hook`, `orchestrator`|private `hooks/superloop-claude-hook session-start\\|user-prompt-submit`†; `superloop orchestrator on\\|off\\|status`†|private directory; search path|","pending_bites":[],"installed_programs":["bin/superloop","libexec/superloop-claude-hook"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`permission-triage` wrapper and old hook destination|private `hooks/superloop-claude-hook pre-tool-use`†; private `hooks/permission-triage-hook`|private directory|","pending_bites":[],"installed_programs":["libexec/superloop-claude-hook","libexec/permission-triage-hook"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`permission-triage-review`, `-topology`, `-assemble`|private `requests-helper`†; `superloop-lane requests status\\|list\\|triage\\|review\\|adjudicate`†; private fixture and registration steps|private directory; search path|","pending_bites":[],"installed_programs":["libexec/requests-helper","libexec/permission-triage-topology","libexec/permission-triage-assemble","bin/superloop-lane"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|``correspondence-feed.sh``, ``correspondence-watch.sh``|`superloop-correspondence poll\\|watch [--advance-cursor]`|search path|","pending_bites":[],"installed_programs":["bin/superloop-correspondence"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|``steward-send.sh``, ``steward-transcript-feed.sh``, ``steward-transcript-watch.sh``|`superloop-steward send\\|transcript poll\\|transcript watch [--advance-cursor]`|search path|","pending_bites":[],"installed_programs":["bin/superloop-steward"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`steward-runner`, `steward-spool-append`, `steward-transcript-export`|`steward-runner`, `steward-spool-append`, `transcript-export`†|server private directory|","pending_bites":[],"installed_programs":["infra/steward/transcript-export","infra/steward/steward-runner","infra/steward/steward-spool-append"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`correspondence-scan`, `cargo-clean-home`|`correspondence-scan`, `target-clean`|server private directory|","pending_bites":[],"installed_programs":["infra/correspondence-watch/correspondence-scan","infra/cargo-clean/target-clean"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|``steward.service``, `.timer`|``superloop-steward.service``, `.timer`|server system unit directory|","pending_bites":[],"generated_units":[{"program":"infra/steward/steward-runner","source":"infra/steward/superloop-steward.service","anchor":"[Service]","destination":"@system_unitdir@/superloop-steward.service"},{"program":"infra/steward/steward-runner","source":"infra/steward/superloop-steward.timer","anchor":"[Timer]","destination":"@system_unitdir@/superloop-steward.timer"}]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|``correspondence-watch.service``, `.timer`|``superloop-correspondence-scan.service``, `.timer`|server system unit directory|","pending_bites":[],"generated_units":[{"program":"infra/correspondence-watch/correspondence-scan","source":"infra/correspondence-watch/superloop-correspondence-scan.service","anchor":"[Service]","destination":"@system_unitdir@/superloop-correspondence-scan.service"},{"program":"infra/correspondence-watch/correspondence-scan","source":"infra/correspondence-watch/superloop-correspondence-scan.timer","anchor":"[Timer]","destination":"@system_unitdir@/superloop-correspondence-scan.timer"}]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|``cargo-clean@.service``, `.timer`|``superloop-target-clean@.service``, `.timer` with the account as instance|server system unit directory|","pending_bites":[],"generated_units":[{"program":"infra/cargo-clean/target-clean","source":"infra/cargo-clean/superloop-target-clean@.service","anchor":"[Service]","destination":"@system_unitdir@/superloop-target-clean@.service"},{"program":"infra/cargo-clean/target-clean","source":"infra/cargo-clean/superloop-target-clean@.timer","anchor":"[Timer]","destination":"@system_unitdir@/superloop-target-clean@.timer"}]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`codex-rt`, `codex`, `codex-rt-create`, `codex-host`, `claude-in-loops`|`superloop-runtime exec\\|create\\|run-host\\|run-toolbox`; `codex` retires|search path|","pending_bites":[],"installed_programs":["bin/superloop-runtime"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`rulebook-install`, `public-pack`|`superloop-install`, `superloop-pack`|search path|","pending_bites":[],"installed_programs":["bin/superloop-install","bin/superloop-pack"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`linter`, deployed `orchestration-linter`|`superloop-lint`|search path|","pending_bites":[],"installed_programs":["bin/superloop-lint"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`build-sync`|`build-sync`|private directory|","pending_bites":[],"installed_programs":["libexec/build-sync"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`run-report`|`superloop-run-report`|build tree only; not installed by this move|","pending_bites":[],"build_programs":["build/superloop-run-report"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`chat-export`, `node-load`|`superloop-chat-export`, `superloop-node-status`†|search path|","pending_bites":[],"installed_programs":["bin/superloop-node-status","bin/superloop-chat-export"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|`ccd-groups-sync`, `ccd-session-merge`|`superloop-claude-desktop sync-groups\\|merge-sessions`†|search path|","pending_bites":[],"installed_programs":["bin/superloop-claude-desktop"]}
{"kind":"successor","record":"tab:toolnames:successors","row":"|the `execwrap` binary|not shipped|none|","pending_bites":[],"absent_binary":"execwrap"}
{"kind":"program","identity":"infra/cargo-clean/target-clean","source":"infra/cargo-clean/target-clean","output":"versioned-infra-cargo-clean-target-clean","package":"cargo-clean","version_authority":"meson.build:script_version_roster","release_group":"cargo-clean","form":"shell","installation_class":"infra","callers":["cargo-clean","release-suite"]}
{"kind":"program","identity":"infra/gate/run-slot.sh","source":"infra/gate/run-slot.sh","output":"versioned-infra-gate-run-slot.sh","package":"gate-slot","version_authority":"meson.build:script_version_roster","release_group":"gate-slot","form":"shell","installation_class":"infra","callers":["release-suite"]}
{"kind":"external-program","identity":"external:sh","selector":"sh","contract":"POSIX shell command execution with the supplied arguments, streams and exit status","callers":["permission-triage","superloop","superloop-chat-export","superloop-lane"]}
{"kind":"external-program","identity":"external:/bin/sh","selector":"/bin/sh","contract":"POSIX shell command execution with the supplied arguments, streams and exit status","callers":["lane-gateway","loop-home","permission-triage","run-worker","superloop-lane","superloop-runtime"]}
{"kind":"external-program","identity":"external:sleep","selector":"sleep","contract":"Block for the specified duration until completion or signal","callers":["lane-gateway","permission-triage","release-suite","superloop-correspondence","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:/bin/true","selector":"/bin/true","contract":"Successful no-effect process fixture","callers":["lane-gateway","superloop-claude-hook"]}
{"kind":"external-program","identity":"external:python3","selector":"python3","contract":"Python 3 payload execution; the caller supplies the program and its bounded input/output contract","callers":["gate-slot","meson:build-sync","permission-triage","release-suite","superloop","superloop-claude-desktop","superloop-claude-hook","superloop-correspondence","superloop-lane","superloop-lint","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:git","selector":"git","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation","callers":["build-sync","lane-gateway","meson:build-sync","permission-triage","superloop","superloop-cli-common","superloop-gate-submit","superloop-install","superloop-lane","superloop-lint","superloop-pack","superloop-runtime"]}
{"kind":"external-program","identity":"external:mknod","selector":"mknod","contract":"Create the specified device fixture or refuse without privilege","callers":["lane-gateway"]}
{"kind":"external-program","identity":"external:mkfifo","selector":"mkfifo","contract":"Create the specified FIFO for a process fixture","callers":["lane-gateway"]}
{"kind":"external-program","identity":"external:date","selector":"date","contract":"Format wall-clock time in the requested machine-readable form","callers":["cargo-clean","gate-slot","lane-lifecycle","superloop-correspondence","superloop-gate-submit","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:/usr/bin/sleep","selector":"/usr/bin/sleep","contract":"Block for the specified duration until completion or signal","callers":["lane-lifecycle","superloop-lane"]}
{"kind":"external-program","identity":"external:ssh","selector":"ssh","contract":"SSH noninteractive remote command transport using the declared alias and configuration","callers":["lane-gateway","superloop-correspondence","superloop-gate-submit","superloop-node-status","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:/usr/bin/git","selector":"/usr/bin/git","contract":"Git repository, index and object operations; exact arguments and status remain owned by the calling operation","callers":["loop-home","superloop-gate-submit","superloop-lane"]}
{"kind":"external-program","identity":"external:/bin/bash","selector":"/bin/bash","contract":"Bash script or command execution with the supplied arguments, streams and exit status","callers":["superloop-gate-submit","superloop-lane","superloop-runtime"]}
{"kind":"external-program","identity":"external:bash","selector":"bash","contract":"Bash script or command execution with the supplied arguments, streams and exit status","callers":["lane-gateway","meson:build-sync","release-suite","superloop-correspondence","superloop-gate-submit","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:timeout","selector":"timeout","contract":"Bound child wall time and propagate the specified timeout status","callers":["cargo-clean","lane-gateway","loop-home","superloop-correspondence","superloop-node-status","superloop-steward","superloop-pack"]}
{"kind":"external-program","identity":"external:/usr/bin/timeout","selector":"/usr/bin/timeout","contract":"Bound child wall time and propagate the specified timeout status","callers":["loop-home","superloop-lane"]}
{"kind":"external-program","identity":"external:/bin/kill","selector":"/bin/kill","contract":"Send the named signal to the selected process or process group","callers":["permission-triage"]}
{"kind":"external-program","identity":"external:kill","selector":"kill","contract":"Send the named signal to the selected process or process group","callers":["permission-triage","superloop-lane"]}
{"kind":"external-program","identity":"external:/bin/sleep","selector":"/bin/sleep","contract":"Block for the specified duration until completion or signal","callers":["permission-triage","superloop-lane"]}
{"kind":"external-program","identity":"external:unzip","selector":"unzip","contract":"Read the explicitly named ZIP archive","callers":["superloop-pack"]}
{"kind":"external-program","identity":"external:df","selector":"df","contract":"Report available filesystem capacity in the requested numeric form","callers":["superloop-run-report"]}
{"kind":"external-program","identity":"external:tar","selector":"tar","contract":"Create or read the explicitly named archive","callers":["superloop-claude-desktop"]}
{"kind":"external-program","identity":"external:/usr/bin/date","selector":"/usr/bin/date","contract":"Format wall-clock time in the requested machine-readable form","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/curl","selector":"/usr/bin/curl","contract":"HTTP transfer with explicit arguments and response status","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/python3","selector":"/usr/bin/python3","contract":"Python 3 payload execution; the caller supplies the program and its bounded input/output contract","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/cat","selector":"/usr/bin/cat","contract":"Copy the named file or standard input to standard output","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/sha256sum","selector":"/usr/bin/sha256sum","contract":"SHA-256 content digest in the requested checksum form","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/cc","selector":"/usr/bin/cc","contract":"C compilation and linking of the supplied source into the requested shared object, with the supplied flags, streams and exit status","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/systemctl","selector":"/usr/bin/systemctl","contract":"Read or reconcile the selected systemd unit","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/systemd-run","selector":"/usr/bin/systemd-run","contract":"Execute the supplied command in a transient systemd unit","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/false","selector":"/usr/bin/false","contract":"Unsuccessful no-effect process fixture","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/true","selector":"/usr/bin/true","contract":"Successful no-effect process fixture","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:configured-cargo","selector":"--cargo","contract":"Cargo metadata --format-version 1, locked when a lockfile exists; otherwise resolve the consumer chain; nonzero status refuses the census","callers":["build-sync","cargo-clean","release-suite","superloop-pack"]}
{"kind":"external-program","identity":"external:build-version-provider","selector":"producer/cargo/rustc","contract":"Cargo, rustc or configured producer version query; read plain version text or the installed-name control-plane record","callers":["build-sync"]}
{"kind":"external-program","identity":"external:codex-runtime-argv","selector":"run-directory runtime.argv","contract":"Run the validated NUL-delimited backend argv and environment published for this run","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:wrapped-command","selector":"ExecConfig argv","contract":"Execute the supplied program and arguments; relay bounded process streams and preserve the wrapper status contract","callers":["superloop-execwrap"]}
{"kind":"external-program","identity":"fixture:superloop-execwrap:self","selector":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation","callers":["superloop-execwrap"]}
{"kind":"external-program","identity":"fixture:lane-gateway:self","selector":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation","callers":["lane-gateway"]}
{"kind":"external-program","identity":"external:lane-backend","selector":"LANE_BACKEND_ARGV","contract":"Validated backend_argv selected by claude or codex; retain settings evidence and resolved executable before allocating run state","callers":["lane-lifecycle"]}
{"kind":"external-program","identity":"fixture:lane-watch:self","selector":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation","callers":["superloop-lane"]}
{"kind":"external-program","identity":"fixture:loop-home:self","selector":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation","callers":["loop-home","superloop"]}
{"kind":"external-program","identity":"external:permission-classifier","selector":"classifier executable configuration","contract":"Isolated classifier arguments, nesting guard, bounded request framing, deadline and process-group cleanup","callers":["permission-triage"]}
{"kind":"external-program","identity":"external:process-group-signal","selector":"signal_process_group_with program","contract":"Signal a selected process group with optional KILL; capture no output and preserve process failure","callers":["permission-triage"]}
{"kind":"external-program","identity":"fixture:superloop-lane:self","selector":"current_exe","contract":"Reexecute the same test binary with exact fixture selection and explicit environment markers for process isolation","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:container-engine","selector":"configured or pinned Podman path","contract":"Podman CLI executes the caller-declared inspection, build, namespace and container operations","callers":["superloop-lane"]}
{"kind":"external-program","identity":"fixture:heartbeat-guard:retained-entries","selector":"CARGO_BIN_EXE_superloop or CARGO_BIN_EXE_heartbeat-guard","contract":"Exercise the retained toggle and hook entries with controlled payload and home","callers":[]}
{"kind":"external-program","identity":"fixture:lane-gateway:runner","selector":"fixture runner_prefix","contract":"Exercise runner process-group identity, recovery and cleanup with controlled completion markers","callers":["lane-gateway"]}
{"kind":"external-program","identity":"external:loop-home-command-plan","selector":"RunRequest.argv","contract":"Execute a validated home operation plan; explicit argv, environment, stdin and measured wall/status","callers":["loop-home"]}
{"kind":"external-program","identity":"fixture:loop-home:podman","selector":"ENTER_LOOP_PODMAN","contract":"Fixture Podman receives the operation plan and captures argv under the isolated home","callers":["superloop"]}
{"kind":"external-program","identity":"fixture:orchestrator-hook:retained-entries","selector":"retained hook or adapter fixture binary","contract":"Exercise event translation and context replies with bounded fixture input","callers":[]}
{"kind":"external-program","identity":"external:topology-probe","selector":"topology executable selector","contract":"Probe the configured harness executable with controlled cwd/environment and bounded capture/deadline","callers":["permission-triage"]}
{"kind":"external-program","identity":"fixture:permission-triage:model","selector":"fake_cli()","contract":"Model fixture supplies deterministic classifier replies and deadlines without an ambient model","callers":["permission-triage"]}
{"kind":"external-program","identity":"fixture:permission-triage:hook-entries","selector":"Cargo hook binary selection","contract":"Compare retained and private permission-hook arguments, payloads and exact reply bytes","callers":["permission-triage"]}
{"kind":"external-program","identity":"fixture:permission-triage:topology","selector":"topology fixture binary or generated real-hook-driver","contract":"Exercise topology assembly and audit faults against the real hook with isolated fake classifier","callers":["permission-triage"]}
{"kind":"external-program","identity":"external:account-command-plan","selector":"RunRequest.argv","contract":"Execute a validated account operation plan with LC_ALL=C, explicit stdin and captured status","callers":["staff-provision"]}
{"kind":"external-program","identity":"external:lane-build-command-plan","selector":"CommandSpec.program","contract":"Execute owner-pinned build or version-probe program with exact argv, cleared environment and process-group cleanup","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:pinned-container-vector","selector":"command_for_request vector","contract":"Execute the validated pinned container vector with explicit environment and owner home","callers":["superloop-lane"]}
{"kind":"external-program","identity":"fixture:superloop-lane:compute","selector":"fixture self.program","contract":"Fake node protocol emits the selected compute completion detail","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/ssh","selector":"transport command template","contract":"SSH with explicit no-config mode, registered key/host and exact remote command framing","callers":["superloop-lane"]}
{"kind":"external-program","identity":"fixture:superloop-lane:exec-races","selector":"fixture script","contract":"Test SSH fixture execution while an executable writer is held and released","callers":["superloop-lane"]}
{"kind":"external-program","identity":"fixture:superloop-lane:retire-node","selector":"fixture self.program","contract":"Fake node retirement transport emits the selected success, failure or interruption state","callers":["superloop-lane"]}
{"kind":"external-program","identity":"fixture:superloop-lane:rubric-entry","selector":"fixture.runner.entry","contract":"Run the production sign-in ancestor predicate through the fixture entry and isolated Python","callers":["superloop-lane"]}
{"kind":"payload","path":"ci/test_docstring_carrier.py","form":"python","sha256":"53da731214e66ffd4e356735fee2a40b0df3ac39bf4a226c12e3282994650100","owner":"release-suite","interpreter":"python3","execution_host":"test build host","version_authority":"packages/superloop-lint/Cargo.toml","contract":"Execute the live Python docstring carrier under its declared linter partition and verify its claim and test identity","calls":[]}
{"kind":"payload","path":"packages/lane-gateway/gateway-runner","form":"script","sha256":"662ef5b8603d28e6bd4d3d0bd281d4bd13113d9efa5707afc712a980691e7458","owner":"lane-gateway","interpreter":"/usr/bin/env bash","execution_host":"install host","version_authority":"packages/lane-gateway/Cargo.toml","contract":"Dispatch the approved gateway request argv using the configured runner environment","calls":[{"callee":"external:basename","selector":"basename","anchor":"basename \"$checkout\"","contract":"Derive the registered lane name from its checkout","lookup":"configured-external","execution_host":"host"},{"callee":"external:ssh","selector":"GATEWAY_RUNNER_SSH","anchor":"ssh -o ServerAliveInterval","contract":"Send the bounded checkout/argv script over the configured node transport","lookup":"configured-external","execution_host":"host"},{"callee":"external:server-report-wrapper","selector":"GATEWAY_RUNNER_REMOTE_WRAPPER","anchor":"\"$remote_wrapper bash -s\"","contract":"Separately provisioned wrapper reports the remote command status and wall","lookup":"configured-external","execution_host":"registered compute node"},{"callee":"external:bash","selector":"bash","anchor":"bash -s","contract":"Run the fixed remote checkout and approved-argv script","lookup":"configured-external","execution_host":"registered compute node"},{"callee":"external:git","selector":"git","anchor":"git fetch -q","contract":"Refresh the registered mirror commit, force checkout and clean before the approved command","lookup":"configured-external","execution_host":"registered compute node"},{"callee":"external:timeout","selector":"timeout","anchor":"timeout $(printf","contract":"Bound the approved command with the gateway wall budget","lookup":"configured-external","execution_host":"registered compute node"},{"callee":"external:gateway-approved-argv","selector":"gateway approved argv","anchor":"timeout $(printf '%q' \"$budget\")$quoted","contract":"Execute only the gateway-supplied argv vector after registered mirror preparation","lookup":"configured-external","execution_host":"registered compute node"}]}
{"kind":"payload","path":"infra/steward/transcript-export","form":"script","sha256":"6c245ef2ad75d433b842a6152589047b648d8d8e2b03924754cac25b9abbc808","owner":"superloop-steward","interpreter":"/usr/bin/env bash","execution_host":"selected steward server","version_authority":"packages/superloop-steward/Cargo.toml","contract":"Serve the list/read transcript protocol to the steward SSH client","calls":[{"callee":"external:rm","selector":"rm","anchor":"rm -f --","contract":"Remove only allocated transcript census files on exit","lookup":"public-command"},{"callee":"external:realpath","selector":"realpath","anchor":"realpath -e --","contract":"Resolve the exporter root and refuse transcript paths or links outside it","lookup":"public-command"},{"callee":"external:mktemp","selector":"mktemp","anchor":"symlink_file=$(mktemp","contract":"Allocate bounded-lifetime path census files","lookup":"public-command"},{"callee":"external:find","selector":"find","anchor":"find -P","contract":"Enumerate links without following them and regular JSONL transcripts after validating their resolved roots","lookup":"public-command"},{"callee":"external:stat","selector":"stat","anchor":"stat -Lc '%s %d:%i %Y:%Z'","contract":"Publish transcript byte size, device/inode identity and modification/change times","lookup":"public-command"},{"callee":"external:sort","selector":"sort","anchor":"sort -zu","contract":"Deduplicate and sort NUL-terminated transcript paths","lookup":"public-command"},{"callee":"external:dd","selector":"dd","anchor":"dd if=","contract":"Read bounded raw transcript bytes at the requested byte offset","lookup":"public-command"}]}
{"kind":"payload","path":"infra/cargo-clean/target-clean","form":"script","sha256":"13abd959793f21307769edcf5715b37225d89bc651732527ca6c0f8f5c7f13da","owner":"cargo-clean","interpreter":"/usr/bin/env bash","execution_host":"kit server","version_authority":"meson.build:script_version_roster","contract":"Clean eligible Cargo build outputs beneath the selected account home","calls":[{"callee":"external:id","selector":"id","anchor":"id -u","contract":"Refuse root invocation and establish the owning account","lookup":"public-command"},{"callee":"external:realpath","selector":"realpath","anchor":"realpath -m -s","contract":"Normalize candidate paths without following symbolic links","lookup":"public-command"},{"callee":"external:stat","selector":"stat","anchor":"stat -c %u","contract":"Verify root, lock and target ownership","lookup":"public-command"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir -p","contract":"Create the owning account lock directory","lookup":"public-command"},{"callee":"external:flock","selector":"flock","anchor":"flock -n 9","contract":"Refuse concurrent cleaners","lookup":"public-command"},{"callee":"external:date","selector":"date","anchor":"date +%s%3N","contract":"Measure action and invocation durations","lookup":"public-command"},{"callee":"external:du","selector":"du","anchor":"du -sb","contract":"Measure target bytes before and after cleanup","lookup":"public-command"},{"callee":"external:find","selector":"find","anchor":"find -P","contract":"Inventory manifests, cache tags and recent writes without following links","lookup":"public-command"},{"callee":"external:sort","selector":"sort","anchor":"sort -z -n","contract":"Process NUL-separated candidates in depth order","lookup":"public-command"},{"callee":"external:timeout","selector":"timeout","anchor":"timeout \"$CMD_TIMEOUT\"","contract":"Bound Cargo metadata and clean invocations","lookup":"public-command"},{"callee":"external:jq","selector":"jq","anchor":"jq -er '.target_directory | strings'","contract":"Read the Cargo target directory when jq is available","lookup":"public-command"},{"callee":"external:sed","selector":"sed","anchor":"sed -n 's/.*","contract":"Retained target-directory parser when jq is unavailable","lookup":"public-command"},{"callee":"external:rm","selector":"rm","anchor":"rm -rf -- \"$target\"","contract":"Remove only an owned, idle, validated standalone Cargo target","lookup":"public-command"},{"callee":"external:configured-cargo","selector":"CARGO_CLEAN_CARGO","anchor":"\"$CARGO\" metadata","contract":"Configured Cargo supplies offline target metadata and cleans the validated manifest target","lookup":"configured-external"},{"callee":"external:logger","selector":"CARGO_CLEAN_LOGGER","anchor":"\"$LOGGER\" -t cargo-clean","contract":"Publish cleanup classifications and duration evidence to the journal","lookup":"configured-external"}]}
{"kind":"payload","path":"infra/cargo-clean/superloop-target-clean@.service","form":"unit","sha256":"2f82baa4817d01e6a15ec9bfcf25c524cd1ab0935d160cde685594f243f7ace7","owner":"cargo-clean","interpreter":"systemd user manager","execution_host":"kit server","version_authority":"meson.build:script_version_roster","contract":"Kit unit scheduling its family program with the server account and declared paths","calls":[{"callee":"infra/cargo-clean/target-clean","selector":"configured private directory","anchor":"ExecStart=@PRIVATE_DIR@/target-clean","contract":"Run the kit cleaner as the selected staff account","lookup":"unit-install-path"}]}
{"kind":"payload","path":"infra/cargo-clean/superloop-target-clean@.timer","form":"unit","sha256":"fefa4f05d1de4caddf1da68a6394ea2a3faf0f5deff1565f68cc34bca75089be","owner":"cargo-clean","interpreter":"systemd user manager","execution_host":"kit server","version_authority":"meson.build:script_version_roster","contract":"Kit unit scheduling its family program with the server account and declared paths","calls":[]}
{"kind":"payload","path":"infra/cargo-clean/tests/run.sh","form":"shell","sha256":"14919c1654a55e038ad96f67de8b1af4c9b81bb2a809c8545aa2a88a2c105eca","owner":"cargo-clean","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build:script_version_roster","contract":"Kit install and state transition fixture; not installed","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:date","selector":"date","anchor":"date","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:realpath","selector":"realpath","anchor":"realpath","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:stat","selector":"stat","anchor":"stat","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:id","selector":"id","anchor":"id","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:find","selector":"find","anchor":"find","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:sed","selector":"sed","anchor":"sed","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:ln","selector":"ln","anchor":"ln","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:touch","selector":"touch","anchor":"touch","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:readlink","selector":"readlink","anchor":"readlink","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:sha256sum","selector":"sha256sum","anchor":"sha256sum","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:sort","selector":"sort","anchor":"sort","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:cmp","selector":"cmp","anchor":"cmp","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:awk","selector":"awk","anchor":"awk","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:flock","selector":"flock","anchor":"flock","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:wc","selector":"wc","anchor":"wc","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"external:env","selector":"env","anchor":"env","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","lookup":"test-executable"},{"callee":"infra/cargo-clean/target-clean","selector":"TARGET_CLEAN_TEST_BINARY","anchor":"TARGET_CLEAN_TEST_BINARY","contract":"Run the kit cleaner with synthetic Cargo/logger tools and private fixture home roots","lookup":"test-executable","binding":"TARGET_CLEAN_TEST_BINARY"},{"callee":"external:date","selector":"date","anchor":"date -u +%s","contract":"Compute fixture ages from explicit UTC epoch seconds","lookup":"public-command"}]}
{"kind":"payload","path":"infra/correspondence-watch/correspondence-scan","form":"script","sha256":"951b90f005cecd21d528f57b8c8abf684ad821a454197f7f24b31f03c7e4c8d2","owner":"superloop-correspondence","interpreter":"/usr/bin/env bash","execution_host":"kit server","version_authority":"packages/superloop-correspondence/Cargo.toml","contract":"Scan correspondence state and publish journal records consumed by the correspondence client","calls":[{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir -p","contract":"Create the scanner state directory","lookup":"public-command"},{"callee":"external:date","selector":"date","anchor":"date +%s%3N","contract":"Measure scan duration and timestamp spool events","lookup":"public-command"},{"callee":"external:touch","selector":"touch","anchor":"touch \"$NEXT\"","contract":"Prepare the next scan watermark","lookup":"public-command"},{"callee":"external:basename","selector":"basename","anchor":"basename \"$h\"","contract":"Derive the home account label","lookup":"public-command"},{"callee":"external:stat","selector":"stat","anchor":"stat -c %u","contract":"Read account/file ownership and file size","lookup":"public-command"},{"callee":"external:sha256sum","selector":"sha256sum","anchor":"sha256sum \"$f\"","contract":"Hash the observed correspondence file","lookup":"public-command"},{"callee":"external:cut","selector":"cut","anchor":"cut -c1-12","contract":"Select the journal short hash","lookup":"public-command"},{"callee":"external:find","selector":"find","anchor":"find \"$d\"","contract":"Enumerate changed regular correspondence files","lookup":"public-command"},{"callee":"external:mv","selector":"mv","anchor":"mv \"$NEXT\" \"$STAMP\"","contract":"Publish the completed scan watermark","lookup":"public-command"},{"callee":"external:logger","selector":"CORRESPONDENCE_WATCH_LOGGER","anchor":"\"$LOGGER\" -t correspondence-watch","contract":"Publish classified correspondence events and scan duration","lookup":"configured-external"},{"callee":"infra/steward/steward-spool-append","selector":"CORRESPONDENCE_WATCH_STEWARD_SPOOL_APPEND","anchor":"@PRIVATE_DIR@/steward-spool-append","contract":"When enabled, append source, relative file, digest, classification and timestamp before advancing the scan watermark","lookup":"configured-external"}]}
{"kind":"payload","path":"infra/correspondence-watch/superloop-correspondence-scan.service","form":"unit","sha256":"31beb182cdea0980ac088e6f6afdd4f1db880aca15455b02ef9f7fafd234b8be","owner":"superloop-correspondence","interpreter":"systemd user manager","execution_host":"kit server","version_authority":"packages/superloop-correspondence/Cargo.toml","contract":"Kit unit scheduling its family program with the server account and declared paths","calls":[{"callee":"infra/correspondence-watch/correspondence-scan","selector":"configured private directory","anchor":"ExecStart=@PRIVATE_DIR@/correspondence-scan","contract":"Run the server journal scanner","lookup":"unit-install-path"}]}
{"kind":"payload","path":"infra/correspondence-watch/superloop-correspondence-scan.timer","form":"unit","sha256":"9662a1389626d6eeb9b3f2f85ab9ccd6b42dcbd629ff2b1aca2313888c7b3562","owner":"superloop-correspondence","interpreter":"systemd user manager","execution_host":"kit server","version_authority":"packages/superloop-correspondence/Cargo.toml","contract":"Kit unit scheduling its family program with the server account and declared paths","calls":[]}
{"kind":"payload","path":"infra/correspondence-watch/tests/run.sh","form":"shell","sha256":"fda40f6b0d19f828ad44c6233780992d06f4bb18052951357c07522625f852c2","owner":"superloop-correspondence","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"packages/superloop-correspondence/Cargo.toml","contract":"Kit install and state transition fixture; not installed","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:stat","selector":"stat","anchor":"stat","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:sed","selector":"sed","anchor":"sed","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:sha256sum","selector":"sha256sum","anchor":"sha256sum","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:cut","selector":"cut","anchor":"cut","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:wc","selector":"wc","anchor":"wc","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"external:sleep","selector":"sleep","anchor":"sleep","contract":"Prepare disposable correspondence homes and instrumented tools; assert journal events, classification and idempotent cursor publication","lookup":"test-executable"},{"callee":"infra/correspondence-watch/correspondence-scan","selector":"CORRESPONDENCE_TEST_SCAN","anchor":"CORRESPONDENCE_TEST_SCAN","contract":"Run the kit scanner against fixture roots with synthetic stat, logger and spool append implementations","lookup":"test-executable","binding":"CORRESPONDENCE_TEST_SCAN"}]}
{"kind":"payload","path":"infra/gate/run-slot.sh","form":"shell","sha256":"ca26d699574982f92a91d483a4cc710150a1773c6e8c12e1c11eb97c0181cf04","owner":"gate-slot","interpreter":"/usr/bin/env bash","execution_host":"kit server","version_authority":"meson.build:script_version_roster","contract":"Acquire the configured gate slot before executing the supplied gate argv","calls":[{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir -p","contract":"Create the declared gate slot and scratch roots","lookup":"public-command"},{"callee":"external:flock","selector":"flock","anchor":"flock -w 120","contract":"Hold an exclusive persistent slot lock for the full gate","lookup":"public-command"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp -d","contract":"Allocate one scratch directory inside the selected slot root","lookup":"public-command"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod -R u+rwX","contract":"Restore scratch access before removal","lookup":"public-command"},{"callee":"external:rm","selector":"rm","anchor":"rm -rf --","contract":"Remove slot scratch and stale result projection","lookup":"public-command"},{"callee":"external:rustc","selector":"rustc","anchor":"rustc --version --verbose","contract":"Record the compiler used by the completed gate","lookup":"public-command"},{"callee":"external:python3","selector":"python3","anchor":"python3 -","contract":"Write the compiler, target directory and exit-code result using the embedded standard-library JSON program","lookup":"public-command"},{"callee":"external:gate-command","selector":"positional gate argv","anchor":"\"$@\" || status=$?","contract":"Execute the supplied gate argv inside the exclusively held slot and preserve its status","lookup":"configured-external"},{"callee":"external:getconf","selector":"getconf","anchor":"getconf","contract":"Read process-accounting clock ticks per second","lookup":"public-command"},{"callee":"external:awk","selector":"awk","anchor":"awk","contract":"Compute own CPU and complete resource deltas","lookup":"public-command"},{"callee":"external:date","selector":"date","anchor":"date","contract":"Sample wall time at battery boundaries","lookup":"public-command"}]}
{"kind":"payload","path":"infra/steward/steward-runner","form":"script","sha256":"fd869e7dbbf1f6cbe358f306284119b16c5579610b790fb035216fd9c42fea42","owner":"superloop-steward","interpreter":"/usr/bin/env bash","execution_host":"kit server","version_authority":"packages/superloop-steward/Cargo.toml","contract":"Run the configured Claude worker and append the steward spool with preserved status","calls":[{"callee":"external:rm","selector":"rm","anchor":"rm -f --","contract":"Remove allocated batch and unfinished capture files","lookup":"public-command"},{"callee":"external:id","selector":"id","anchor":"id -u","contract":"Refuse root/owner and require the configured steward account","lookup":"public-command"},{"callee":"external:grep","selector":"grep","anchor":"grep -Eq","contract":"Validate configured numeric fields and disposition identifiers","lookup":"public-command"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir -p --","contract":"Prepare private state and invocation directories","lookup":"public-command"},{"callee":"external:sync","selector":"sync","anchor":"sync -d","contract":"Make batch, dispositions, output and ledger writes durable before acknowledgement","lookup":"public-command"},{"callee":"external:dirname","selector":"dirname","anchor":"dirname --","contract":"Select the ledger directory for durability","lookup":"public-command"},{"callee":"external:flock","selector":"flock","anchor":"flock -n 9","contract":"Refuse overlapping runner invocations","lookup":"public-command"},{"callee":"external:realpath","selector":"realpath","anchor":"realpath -e --","contract":"Keep every source file below its declared visible source root","lookup":"public-command"},{"callee":"external:mktemp","selector":"mktemp","anchor":"BATCH=$(mktemp","contract":"Create private batch and capture files","lookup":"public-command"},{"callee":"external:cat","selector":"cat","anchor":"cat --","contract":"Frame source bytes as untrusted batch evidence","lookup":"public-command"},{"callee":"external:date","selector":"date","anchor":"date +%s%N","contract":"Record invocation identity, wall and completion timestamp","lookup":"public-command"},{"callee":"external:timeout","selector":"timeout","anchor":"timeout -k","contract":"Bound Claude invocation and termination grace","lookup":"public-command"},{"callee":"external:mv","selector":"mv","anchor":"mv --","contract":"Publish completed invocation output","lookup":"public-command"},{"callee":"external:stat","selector":"stat","anchor":"stat -c %u","contract":"Require disposition ownership before recording completion","lookup":"public-command"},{"callee":"external:sha256sum","selector":"sha256sum","anchor":"sha256sum --","contract":"Verify full disposition digest","lookup":"public-command"},{"callee":"external:cut","selector":"cut","anchor":"cut -d ' ' -f 1","contract":"Select the digest field for the disposition comparison","lookup":"public-command"},{"callee":"external:steward-claude","selector":"STEWARD_CLAUDE_COMMAND","anchor":"\"$CLAUDE_COMMAND\" --print","contract":"Run the configured Claude with the standing charter and bounded pending-case batch","lookup":"configured-external"},{"callee":"external:logger","selector":"STEWARD_LOGGER","anchor":"\"$LOGGER\" -t steward-runner","contract":"Publish invocation and per-case state transitions","lookup":"configured-external"}]}
{"kind":"payload","path":"infra/steward/steward-spool-append","form":"script","sha256":"50dabede670111a459a46cf34461ad6ed8ad7736068838270ff1044b5e675d27","owner":"superloop-steward","interpreter":"/usr/bin/env bash","execution_host":"kit server","version_authority":"packages/superloop-steward/Cargo.toml","contract":"Append bounded transcript records to the steward spool","calls":[{"callee":"external:grep","selector":"grep","anchor":"grep -Eq","contract":"Validate event digest framing","lookup":"public-command"},{"callee":"external:id","selector":"id","anchor":"id -u","contract":"Require the configured spool writer UID","lookup":"public-command"},{"callee":"external:stat","selector":"stat","anchor":"stat -c %u","contract":"Require spool ownership","lookup":"public-command"},{"callee":"external:sha256sum","selector":"sha256sum","anchor":"sha256sum","contract":"Derive the stable case identity from NUL-separated event fields","lookup":"public-command"},{"callee":"external:cut","selector":"cut","anchor":"cut -d ' ' -f 1","contract":"Select the case digest","lookup":"public-command"},{"callee":"external:flock","selector":"flock","anchor":"flock -x 9","contract":"Serialize spool producers","lookup":"public-command"},{"callee":"external:awk","selector":"awk","anchor":"awk -F '\\t'","contract":"Detect an already appended case without rewriting it","lookup":"public-command"},{"callee":"external:sync","selector":"sync","anchor":"sync -d","contract":"Synchronize appended spool bytes and its directory","lookup":"public-command"},{"callee":"external:dirname","selector":"dirname","anchor":"dirname --","contract":"Select the spool directory for durability","lookup":"public-command"},{"callee":"external:date","selector":"date","anchor":"date -u -d","contract":"Validate the explicit whole-second UTC instant and its calendar before opening the spool lock","lookup":"public-command"}]}
{"kind":"payload","path":"infra/steward/superloop-steward.service","form":"unit","sha256":"789f1d6519fb7fc10626c1cf4cb7f4b4a38cfd1f2f9b1f143b19e73bddf5f1c2","owner":"superloop-steward","interpreter":"systemd user manager","execution_host":"kit server","version_authority":"packages/superloop-steward/Cargo.toml","contract":"Kit unit scheduling its family program with the server account and declared paths","calls":[{"callee":"infra/steward/steward-runner","selector":"configured private directory","anchor":"ExecStart=@PRIVATE_DIR@/steward-runner","contract":"Run the server steward under the kit identity","lookup":"unit-install-path"}]}
{"kind":"payload","path":"infra/steward/superloop-steward.timer","form":"unit","sha256":"fe161541425cad2f175c128e571637567c465eac8ae466727a26c66f2f2ff56c","owner":"superloop-steward","interpreter":"systemd user manager","execution_host":"kit server","version_authority":"packages/superloop-steward/Cargo.toml","contract":"Kit unit scheduling its family program with the server account and declared paths","calls":[]}
{"kind":"payload","path":"infra/steward/tests/run.sh","form":"shell","sha256":"3db733d0c7298179faa64068ebbb6166330c5f50294fc6c21294da58380772a1","owner":"superloop-steward","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"packages/superloop-steward/Cargo.toml","contract":"Kit install and state transition fixture; not installed","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:id","selector":"id","anchor":"id","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:stat","selector":"stat","anchor":"stat","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:date","selector":"date","anchor":"date","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:sleep","selector":"sleep","anchor":"sleep","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:sha256sum","selector":"sha256sum","anchor":"sha256sum","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:cut","selector":"cut","anchor":"cut","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:wc","selector":"wc","anchor":"wc","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:bash","selector":"bash","anchor":"bash","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:find","selector":"find","anchor":"find","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"external:seq","selector":"seq","anchor":"seq","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","lookup":"test-executable"},{"callee":"infra/steward/steward-spool-append","selector":"STEWARD_TEST_APPEND","anchor":"STEWARD_TEST_APPEND","contract":"Append a fixture correspondence case with explicit UID, spool and lock paths","lookup":"test-executable","binding":"STEWARD_TEST_APPEND"},{"callee":"infra/steward/steward-runner","selector":"STEWARD_TEST_RUNNER","anchor":"STEWARD_TEST_RUNNER","contract":"Run the kit against a fake Claude and logger with explicit fixture state and identity","lookup":"test-executable","binding":"STEWARD_TEST_RUNNER"}]}
{"kind":"payload","path":"tests/conductor-fake-notify","form":"script","sha256":"c79f72490ff5e63d19f23927be0177137d55711cbd320bf23dd395d364642ebc","owner":"release-suite","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[]}
{"kind":"payload","path":"tests/fake-ssh","form":"script","sha256":"598a3d22f952574f2bf6f3c7494fbcfc3e548920f6398e0503c969599658e803","owner":"release-suite","interpreter":"/bin/bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:sleep","selector":"sleep","anchor":"exec sleep","contract":"Simulate a nonresponsive SSH peer","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/gate-slot-run.sh","form":"shell","sha256":"a20571de3d1293364882c94088089755b9b9a68e27b4d93cbc344b5e0d4a4c55","owner":"release-suite","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:touch","selector":"touch","anchor":"touch","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"external:python3","selector":"python3","anchor":"python3","contract":"Prepare and inspect a disposable gate slot; generated compiler and gate children prove target reuse, result publication and cleanup","lookup":"test-executable"},{"callee":"infra/gate/run-slot.sh","selector":"runner source path","anchor":"\"$runner\"","contract":"Execute the slot wrapper with generated fixture check commands and controlled failure statuses","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/gate-sample-run.sh","form":"shell","sha256":"df3818ce98c40927a38ce2cc95d0ca2a187cc3648d4c2323e202959cbcfdec56","owner":"release-suite","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","lookup":"test-executable"},{"callee":"external:python3","selector":"python3","anchor":"python3","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","lookup":"test-executable"},{"callee":"infra/gate/run-slot.sh","selector":"runner source path","anchor":"source \"$ROOT/infra/gate/run-slot.sh\"","contract":"Assert complete gate samples, resource deltas, scope and missing-counter evidence against a scratch cgroup","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/gateway-runner-run.sh","form":"shell","sha256":"6b756000853cdaaa9aa779cc32eaae0e3f2a758029c747b933e2599e93da0b76","owner":"lane-gateway","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:sed","selector":"sed","anchor":"sed","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:sleep","selector":"sleep","anchor":"sleep","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:env","selector":"env","anchor":"env","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:awk","selector":"awk","anchor":"awk","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"external:cmp","selector":"cmp","anchor":"cmp","contract":"Prepare a synthetic SSH executable and compare exact gateway argv, input script, output, signal forwarding and statuses without transport","lookup":"test-executable"},{"callee":"libexec/gateway-runner","selector":"RUNNER source path","anchor":"\"$RUNNER\" \"$checkout\"","contract":"Invoke the runner with synthetic SSH and isolated checkout inputs","lookup":"test-executable"},{"callee":"libexec/gateway-runner","selector":"GATEWAY_RUNNER_TEST_BINARY","anchor":"GATEWAY_RUNNER_TEST_BINARY","binding":"GATEWAY_RUNNER_TEST_BINARY","lookup":"test-executable","contract":"Exercise the configured private runner with fake SSH and explicit node settings"}]}
{"kind":"payload","path":"tests/loop-codex-home-run.sh","form":"shell","sha256":"f94f9f6ab68d14eca0e2de8533486cbb23d3888bf97166638574f51fca6b1a84","owner":"superloop-lane","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:date","selector":"date","anchor":"date","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:cp","selector":"cp","anchor":"cp","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:ln","selector":"ln","anchor":"ln","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:stat","selector":"stat","anchor":"stat","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:readlink","selector":"readlink","anchor":"readlink","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:cmp","selector":"cmp","anchor":"cmp","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:tail","selector":"tail","anchor":"tail","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:cksum","selector":"cksum","anchor":"cksum","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:rmdir","selector":"rmdir","anchor":"rmdir","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:sed","selector":"sed","anchor":"sed","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:python3","selector":"python3","anchor":"python3","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:mv","selector":"mv","anchor":"mv","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"external:env","selector":"env","anchor":"env","contract":"Prepare disposable sign-in homes and injected publication failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","lookup":"test-executable"},{"callee":"bin/superloop-runtime","selector":"RUNTIME_TEST_BINARY","anchor":"RUNTIME_TEST_BINARY","contract":"Probe configured runtime wrapper argv and refusal before a synthetic host portal","lookup":"test-executable","binding":"RUNTIME_TEST_BINARY"},{"callee":"bin/superloop-lane","selector":"SIGNIN_TEST_BINARY","anchor":"SIGNIN_TEST_BINARY","binding":"SIGNIN_TEST_BINARY","lookup":"test-executable","contract":"Built lane sign-in preparation and inspection with readonly and reconciliation fixtures"},{"callee":"bin/superloop","selector":"SUPERLOOP_TEST_BINARY","anchor":"SUPERLOOP_TEST_BINARY","binding":"SUPERLOOP_TEST_BINARY","lookup":"test-executable","contract":"Public forge bridge exact argv and named configuration refusals"}]}
{"kind":"payload","path":"tests/run.sh","form":"shell","sha256":"0f9a5de9e430e4b4fd8d3fe96219de8eed748c1e44a1008a11b01b5ce422c604","owner":"release-suite","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:ln","selector":"ln","anchor":"ln","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:sed","selector":"sed","anchor":"sed","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:tail","selector":"tail","anchor":"tail","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:awk","selector":"awk","anchor":"awk","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"external:wc","selector":"wc","anchor":"wc","contract":"Prepare synthetic correspondence SSH replies and inspect delivered events, timing bounds and cursor bytes","lookup":"test-executable"},{"callee":"bin/superloop-correspondence","selector":"CORRESPONDENCE_TEST_BINARY","anchor":"\"$CLIENT\"","contract":"Run poll and watch against the built client supplied by the suite environment","lookup":"test-executable"},{"callee":"external:cmp","selector":"cmp","anchor":"cmp","contract":"Compare prepared transport replies before arming the production client deadline","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/steward-fake-claude","form":"script","sha256":"297739c6c8d2a6d5f4de87ac130a0bb5093c24c6227e67edf81957f71c642b3c","owner":"release-suite","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[]}
{"kind":"payload","path":"tests/steward-fake-exporter","form":"script","sha256":"3b2e73f4a03c23a4cc7aff187d483fb508a7796460bf10929319d006e6f73605","owner":"release-suite","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:stat","selector":"stat","anchor":"stat -Lc '%s %d:%i %Y:%Z'","contract":"Report fixture transcript identity and length","lookup":"test-executable"},{"callee":"external:find","selector":"find","anchor":"find -P","contract":"Enumerate fixture JSONL transcripts without following links","lookup":"test-executable"},{"callee":"external:sort","selector":"sort","anchor":"sort -z","contract":"Return stable NUL-separated fixture paths","lookup":"test-executable"},{"callee":"external:realpath","selector":"realpath","anchor":"realpath -e","contract":"Refuse fixture reads outside the selected server root","lookup":"test-executable"},{"callee":"external:dd","selector":"dd","anchor":"dd if=","contract":"Read the requested raw fixture byte range","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/steward-fake-ssh","form":"script","sha256":"e38c868c42b6fecb78c6ef1091aa01386e98c6c2d090a132dfca53b70df531e0","owner":"release-suite","interpreter":"/bin/bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:sleep","selector":"sleep","anchor":"exec sleep","contract":"Simulate a nonresponsive steward peer","lookup":"test-executable"},{"callee":"external:bash","selector":"bash","anchor":"exec bash -c","contract":"Run live send discovery or fake Claude commands; poll and watch snapshot commands are checked by untimed exporter replay in steward-run.sh","lookup":"test-executable"},{"callee":"external:dd","selector":"dd","anchor":"exec dd","contract":"Seek to the requested snapshot offset and copy only the requested byte count, observed before client deadlines","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/steward-run.sh","form":"shell","sha256":"b846a7e16b401254ec54423d83529e01ecf5d48d00fbe5309bf629dd41469ca8","owner":"superloop-steward","interpreter":"/usr/bin/env bash","execution_host":"test build host","version_authority":"meson.build","contract":"Release suite fixture or checker; its declared tool bindings select the programs under test","calls":[{"callee":"external:dirname","selector":"dirname","anchor":"dirname","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:mktemp","selector":"mktemp","anchor":"mktemp","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:rm","selector":"rm","anchor":"rm","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:mkdir","selector":"mkdir","anchor":"mkdir","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:ln","selector":"ln","anchor":"ln","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:sed","selector":"sed","anchor":"sed","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:cat","selector":"cat","anchor":"cat","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:chmod","selector":"chmod","anchor":"chmod","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:grep","selector":"grep","anchor":"grep","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:tail","selector":"tail","anchor":"tail","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:wc","selector":"wc","anchor":"wc","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:cp","selector":"cp","anchor":"cp","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:cmp","selector":"cmp","anchor":"cmp","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:mv","selector":"mv","anchor":"mv","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:awk","selector":"awk","anchor":"awk","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:date","selector":"date","anchor":"date","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"external:touch","selector":"touch","anchor":"touch","contract":"Prepare synthetic transcript, SSH and Claude fixtures; inspect protocol bytes, cursor transitions and bounded transport behavior","lookup":"test-executable"},{"callee":"bin/superloop-steward","selector":"STEWARD_TEST_BINARY","anchor":"\"$CLIENT\"","contract":"Run transcript polling, watching and session send through the built client supplied by the suite environment","lookup":"test-executable"},{"callee":"infra/steward/transcript-export","selector":"STEWARD_TEST_EXPORTER","anchor":"STEWARD_TEST_EXPORTER","contract":"Exercise the exporter protocol against a disposable root with lexical and symlink containment probes","lookup":"test-executable","binding":"STEWARD_TEST_EXPORTER"},{"callee":"external:bash","selector":"bash","anchor":"bash -c","contract":"Replay every logged poll and watch command through the original fake exporter after the client exits and compare snapshot bytes","lookup":"test-executable"}]}
{"kind":"payload","path":"tests/version-smoke.py","form":"python","sha256":"aabb9142f97002bd9d9e560b9932891bc4d815662ae925c11da93d88e27f5e4f","owner":"release-suite","interpreter":"Python 3 standard library","execution_host":"test build host","version_authority":"meson.build","contract":"Verify every installed-name control-plane version record and full ledger-owned build provenance","calls":[{"callee":"bin/superloop","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-chat-export","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-claude-desktop","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-correspondence","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-gate-submit","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-install","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-lane","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-lint","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-node-status","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-pack","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-runtime","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"bin/superloop-steward","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"build/superloop-run-report","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"infra/cargo-clean/target-clean","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"infra/correspondence-watch/correspondence-scan","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"infra/gate/run-slot.sh","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"infra/steward/steward-runner","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"infra/steward/steward-spool-append","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"infra/steward/transcript-export","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/account","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/build-sync","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/door-service","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/door-ssh","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/gateway-runner","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/gateway-service","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/permission-triage-assemble","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/permission-triage-hook","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/permission-triage-topology","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/requests-helper","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/superloop-claude-hook","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/vendor-proxy","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"},{"callee":"libexec/worker-run","selector":"--binary supplied by Meson version roster","anchor":"[str(args.binary), \"--version\"]","contract":"Measure the declared installed-name JSON version contract against its manifest or Meson version authority","lookup":"test-executable"}]}
{"kind":"installation","route":"native","source":"build:packages/superloop-chat-export/superloop-chat-export","destination":"@bindir@/superloop-chat-export","owner":"superloop-chat-export"}
{"kind":"installation","route":"native","source":"build:packages/superloop-chat-export/superloop-chat-export.build.json","destination":"@datadir@/superloop/build-records/superloop-chat-export.build.json","owner":"superloop-chat-export"}
{"kind":"installation","route":"native","source":"build:packages/superloop-gate-submit/superloop-gate-submit","destination":"@bindir@/superloop-gate-submit","owner":"superloop-gate-submit"}
{"kind":"installation","route":"native","source":"build:packages/superloop-gate-submit/superloop-gate-submit.build.json","destination":"@datadir@/superloop/build-records/superloop-gate-submit.build.json","owner":"superloop-gate-submit"}
{"kind":"installation","route":"native","source":"build:packages/superloop-correspondence/superloop-correspondence","destination":"@bindir@/superloop-correspondence","owner":"superloop-correspondence"}
{"kind":"installation","route":"native","source":"build:packages/superloop-correspondence/superloop-correspondence.build.json","destination":"@datadir@/superloop/build-records/superloop-correspondence.build.json","owner":"superloop-correspondence"}
{"kind":"installation","route":"native","source":"build:packages/superloop-steward/superloop-steward","destination":"@bindir@/superloop-steward","owner":"superloop-steward"}
{"kind":"installation","route":"native","source":"build:packages/superloop-steward/superloop-steward.build.json","destination":"@datadir@/superloop/build-records/superloop-steward.build.json","owner":"superloop-steward"}
{"kind":"installation","route":"native","source":"build:packages/superloop-node-status/superloop-node-status","destination":"@bindir@/superloop-node-status","owner":"superloop-node-status"}
{"kind":"installation","route":"native","source":"build:packages/superloop-node-status/superloop-node-status.build.json","destination":"@datadir@/superloop/build-records/superloop-node-status.build.json","owner":"superloop-node-status"}
{"kind":"installation","route":"native","source":"build:packages/superloop-claude-desktop/superloop-claude-desktop","destination":"@bindir@/superloop-claude-desktop","owner":"superloop-claude-desktop"}
{"kind":"installation","route":"native","source":"build:packages/superloop-claude-desktop/superloop-claude-desktop.build.json","destination":"@datadir@/superloop/build-records/superloop-claude-desktop.build.json","owner":"superloop-claude-desktop"}
{"kind":"installation","route":"native","source":"build:packages/superloop-claude-hook/superloop-claude-hook","destination":"@libexecdir@/superloop/hooks/superloop-claude-hook","owner":"superloop-claude-hook"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/permission-triage-hook","destination":"@libexecdir@/superloop/hooks/permission-triage-hook","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/requests-helper","destination":"@libexecdir@/superloop/requests-helper","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/vendor-proxy","destination":"@libexecdir@/superloop/vendor-proxy","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/door-ssh","destination":"@libexecdir@/superloop/door-ssh","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/door-service","destination":"@libexecdir@/superloop/door-service","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/Containerfile","destination":"@datadir@/superloop/lane/Containerfile","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/box-init","destination":"@datadir@/superloop/lane/box-init","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/claude-settings.json","destination":"@datadir@/superloop/lane/claude-settings.json","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/vendor-proxy.service.in","destination":"@datadir@/superloop/lane/vendor-proxy.service.in","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/worker.service.in","destination":"@datadir@/superloop/lane/worker.service.in","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/codex-config.toml","destination":"@datadir@/superloop/lane/codex-config.toml","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"source:packages/superloop-lane/data/worker-AGENTS.md","destination":"@datadir@/superloop/lane/worker-AGENTS.md","owner":"superloop-lane"}
{"kind":"data","identity":"driver-run-directory","writer":"lane-lifecycle","readers":["loop-home","run-worker","superloop-lane"],"format_authority":"packages/lane-lifecycle/README.md","format_contract":"Configured durable runs root; exclusive fresh directory, driver PID then optional child PID lock, step/event/start markers, event JSONL, message and archived step history; one working lane step per loop","sites":[{"path":"packages/lane-lifecycle/src/lib.rs","anchor":".step-name"},{"path":"packages/superloop-lane/src/driver/status/mod.rs","anchor":"select_driver_lock"},{"path":"packages/superloop-lane/src/driver/follow/mod.rs","anchor":".feed-offset"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"driver-run-report","writer":"lane-lifecycle","readers":["run-worker","superloop-lane"],"format_authority":"packages/lane-lifecycle/README.md","format_contract":"Atomically published run-report.txt settles the current step; ordered RUN-REPORT fields include lane, exit, wall, budget, verdict, directory and optional settings evidence; pre-allocation refusal uses dir=unknown","sites":[{"path":"packages/lane-lifecycle/src/lib.rs","anchor":"run-report.txt"},{"path":"packages/superloop-lane/src/driver/status/mod.rs","anchor":"run-report.txt"},{"path":"packages/superloop-lane/src/driver/follow/mod.rs","anchor":"run-report.txt"},{"path":"packages/run-worker/src/watch.rs","anchor":"run-report.txt"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"driver-monitor-sidecar","writer":"lane-lifecycle","readers":["superloop-lane"],"format_authority":"packages/superloop-lane/src/driver/follow/README.md","format_contract":"Driver-owned .monitor-PID-SEQUENCE line contains quiet, wall, event_size, boot, awake and ordered optional awaiting, context and budget suffixes; readers choose the valid live-driver record","sites":[{"path":"packages/lane-lifecycle/src/lib.rs","anchor":".monitor-"},{"path":"packages/superloop-lane/src/driver/status/mod.rs","anchor":".monitor-"},{"path":"packages/superloop-lane/src/driver/follow/mod.rs","anchor":".monitor-"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"driver-feed-offset","writer":"superloop-lane","readers":["lane-lifecycle","superloop-lane"],"format_authority":"packages/superloop-lane/src/driver/follow/README.md","format_contract":"Nonnegative ASCII decimal byte offset plus LF; saved only after complete output flush; lifecycle archives it when resuming the step","sites":[{"path":"packages/superloop-lane/src/driver/follow/mod.rs","anchor":".feed-offset"},{"path":"packages/lane-lifecycle/src/lib.rs","anchor":".feed-offset"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"driver-backend-settings","writer":"lane-lifecycle","readers":["external:orchestrator"],"format_authority":"packages/lane-lifecycle/README.md","format_contract":"backend-settings.json retains the resolved backend path, exact selected argv and settings evidence; report includes backend_program, settings and settings_sha256; resume archives the prior record","sites":[{"path":"packages/lane-lifecycle/src/lib.rs","anchor":"backend-settings.json"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"owner-worker-settings","writer":"external:operator","readers":["loop-home","run-worker","superloop-lane"],"format_authority":"packages/loop-home/README.md","format_contract":"Owner-maintained workers.toml carries durable roots, per-backend driver_argv and backend_argv and compute environment; trusted entry transports selectors and settings evidence before allocation","sites":[{"path":"packages/loop-home/src/driver_launch.rs","anchor":"driver_argv"},{"path":"packages/run-worker/src/app.rs","anchor":"driver_argv"},{"path":"packages/superloop-lane/src/settings.rs","anchor":"workers.toml"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"gateway-registrations","writer":"lane-gateway","readers":["lane-gateway","lane-lifecycle"],"format_authority":"packages/lane-gateway/README.md","format_contract":"registrations/LANE.toml is the gateway-owned registration projection; lifecycle reads its approved or registered in-flight evidence without importing gateway implementation","sites":[{"path":"packages/lane-gateway/src/gateway.rs","anchor":"registrations"},{"path":"packages/lane-lifecycle/src/lib.rs","anchor":"registrations"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"steward-export-protocol","writer":"infra/steward/transcript-export","readers":["superloop-steward"],"format_authority":"packages/superloop-steward/README.md","format_contract":"Configured server exporter serves list and bounded read requests over SSH; transcript identity, offsets and tail checks retain replacement, truncation and rewrite evidence","sites":[{"path":"infra/steward/transcript-export","anchor":"read RELATIVE_PATH OFFSET MAX_BYTES"},{"path":"packages/superloop-steward/src/main.rs","anchor":"/usr/local/libexec/superloop/transcript-export"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"steward-cursor","writer":"superloop-steward","readers":["superloop-steward"],"format_authority":"packages/superloop-steward/README.md","format_contract":"cursor-SERVER V1 canary and tab-separated transcript identity/offset fields; changing polls save only after publication, bare polls preserve bytes and metadata","sites":[{"path":"packages/superloop-steward/src/protocol.rs","anchor":"V1\\tcanary=1"},{"path":"packages/superloop-steward/src/main.rs","anchor":"cursor-"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"correspondence-journal","writer":"infra/correspondence-watch/correspondence-scan","readers":["superloop-correspondence"],"format_authority":"packages/superloop-correspondence/README.md","format_contract":"Server scanner publishes correspondence-watch journal records; client consumes sudo journalctl with the prior opaque cursor and show-cursor framing","sites":[{"path":"infra/correspondence-watch/correspondence-scan","anchor":"correspondence-watch"},{"path":"packages/superloop-correspondence/src/main.rs","anchor":"sudo journalctl"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"correspondence-cursor","writer":"superloop-correspondence","readers":["superloop-correspondence"],"format_authority":"packages/superloop-correspondence/README.md","format_contract":"Opaque cursor-ALIAS per host; descriptor-held changing-poll lock and atomic save only after successful publication; bare poll preserves bytes and metadata","sites":[{"path":"packages/superloop-correspondence/src/main.rs","anchor":"cursor-"},{"path":"packages/superloop-correspondence/src/cursor.rs","anchor":".cursor-"}],"owner":"LOOPHOME"}
{"kind":"external-program","identity":"external:flatpak-spawn","selector":"flatpak-spawn","contract":"Host portal forwards the selected toolbox command and streams","callers":["superloop","superloop-runtime"]}
{"kind":"external-program","identity":"external:toolbox","selector":"CLAUDE_TOOLBOX","contract":"Selected toolbox executes env and the declared agent command","callers":["superloop","superloop-runtime"]}
{"kind":"external-program","identity":"external:env","selector":"env","contract":"Set the declared agent configuration variables and execute the remaining argv","callers":["cargo-clean","lane-gateway","meson:build-sync","meson:lane-gateway","meson:permission-triage","meson:run-worker","meson:staff-provision","meson:superloop","meson:superloop-chat-export","meson:superloop-claude-desktop","meson:superloop-claude-hook","meson:superloop-correspondence","meson:superloop-gate-submit","meson:superloop-install","meson:superloop-lane","meson:superloop-lint","meson:superloop-node-status","meson:superloop-pack","meson:superloop-run-report","meson:superloop-runtime","meson:superloop-steward","superloop","superloop-gate-submit","superloop-lane","superloop-runtime"]}
{"kind":"external-program","identity":"external:gh","selector":"gh","contract":"Agent command receives the original argument vector and selected configuration","callers":["superloop"]}
{"kind":"external-program","identity":"external:claude","selector":"claude","contract":"Agent command receives the original argument vector and selected configuration","callers":["superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:true","selector":"true","contract":"No-effect host portal availability probe","callers":[]}
{"kind":"external-program","identity":"external:runtime-codex","selector":"CODEX_REAL_BIN","contract":"Configured or retained standalone Codex receives exact passthrough arguments","callers":["superloop-runtime"]}
{"kind":"external-program","identity":"external:podman","selector":"podman","contract":"Container inspect, start, create or exec operations are selected by this runtime adapter","callers":["superloop-runtime"]}
{"kind":"external-program","identity":"external:id","selector":"id","contract":"Read the caller UID and GID for container identity mapping","callers":["cargo-clean","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:awk","selector":"awk","contract":"Render the measured wall duration","callers":["cargo-clean","gate-slot","lane-gateway","release-suite","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:getconf","selector":"getconf","contract":"Read the kernel process-accounting clock frequency","callers":["gate-slot"]}
{"kind":"external-program","identity":"external:grep","selector":"grep","contract":"Inspect the selected account and mount records","callers":["cargo-clean","release-suite","superloop-correspondence","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:useradd","selector":"useradd","contract":"Create the selected runtime account when absent","callers":["superloop-runtime"]}
{"kind":"external-program","identity":"external:dnf","selector":"dnf","contract":"Install the explicit runtime package set inside the new container","callers":["superloop-runtime"]}
{"kind":"external-program","identity":"external:chmod","selector":"chmod","contract":"Set the runtime profile file mode","callers":["cargo-clean","gate-slot","lane-gateway","release-suite","superloop-correspondence","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:head","selector":"head","contract":"Bound the runtime SSH version display","callers":["permission-triage"]}
{"kind":"external-program","identity":"external:bwrap","selector":"bwrap","contract":"Verify the installed runtime sandbox executable","callers":["superloop-runtime"]}
{"kind":"external-program","identity":"external:ls","selector":"ls","contract":"Inspect runtime temporary directory metadata","callers":[]}
{"kind":"external-program","identity":"external:basename","selector":"basename","contract":"Derive the registered lane name from its checkout","callers":["lane-gateway","superloop-correspondence","superloop-gate-submit"]}
{"kind":"external-program","identity":"external:server-report-wrapper","selector":"GATEWAY_RUNNER_REMOTE_WRAPPER","contract":"Separately provisioned wrapper reports the remote command status and wall","callers":["lane-gateway","superloop-lane"]}
{"kind":"external-program","identity":"external:gateway-approved-argv","selector":"gateway approved argv","contract":"Execute only the gateway-supplied argv vector after registered mirror preparation","callers":["lane-gateway"]}
{"kind":"external-program","identity":"external:configured-codex-agent","selector":"program argument","contract":"Pinned agent path receives tool-free Codex exec JSON arguments with bounded streams and process-group cleanup","callers":["loop-home"]}
{"kind":"external-program","identity":"external:image-claude","selector":"/usr/libexec/superloop/claude","contract":"Measure pinned image Claude version and help without sign-in or network","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:elf-interpreter","selector":"ELF PT_INTERP","contract":"ELF-declared loader lists the pinned executable runtime libraries for digest measurement","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:door-compute-argv","selector":"validated compute words","contract":"Validated compute argv runs in the bound clean checkout with the explicitly configured environment","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:stat","selector":"stat","contract":"Check the runtime directory owner and mode","callers":["cargo-clean","release-suite","superloop-correspondence","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:find","selector":"find","contract":"Refuse a nonempty runtime directory","callers":["cargo-clean","release-suite","superloop-correspondence","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:socat","selector":"socat","contract":"Bridge the loopback vendor listener to the declared Unix socket","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:box-worker-argv","selector":"container entry argv","contract":"Execute the recorded worker command vector after runtime directory validation","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/podman","selector":"/usr/bin/podman","contract":"Start the retained runtime container with the user session","callers":[]}
{"kind":"external-program","identity":"external:rm","selector":"rm","contract":"Remove only allocated transcript census files on exit","callers":["cargo-clean","gate-slot","lane-gateway","permission-triage","release-suite","superloop-correspondence","superloop-gate-submit","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:realpath","selector":"realpath","contract":"Resolve the exporter root and refuse transcript paths or links outside it","callers":["cargo-clean","release-suite","superloop-steward"]}
{"kind":"external-program","identity":"external:mktemp","selector":"mktemp","contract":"Allocate bounded-lifetime path census files","callers":["cargo-clean","gate-slot","lane-gateway","release-suite","superloop-correspondence","superloop-gate-submit","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:sort","selector":"sort","contract":"Deduplicate and sort NUL-terminated transcript paths","callers":["cargo-clean","release-suite","superloop-steward"]}
{"kind":"external-program","identity":"external:dd","selector":"dd","contract":"Read bounded raw transcript bytes at the requested byte offset","callers":["release-suite","superloop-steward"]}
{"kind":"external-program","identity":"external:mkdir","selector":"mkdir","contract":"Create the declared gate slot and scratch roots","callers":["cargo-clean","gate-slot","lane-gateway","release-suite","superloop-correspondence","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:flock","selector":"flock","contract":"Hold an exclusive persistent slot lock for the full gate","callers":["cargo-clean","gate-slot","superloop-steward"]}
{"kind":"external-program","identity":"external:rustc","selector":"rustc","contract":"Record the compiler used by the completed gate","callers":["gate-slot"]}
{"kind":"external-program","identity":"external:gate-command","selector":"positional gate argv","contract":"Execute the supplied gate argv inside the exclusively held slot and preserve its status","callers":["gate-slot"]}
{"kind":"external-program","identity":"external:du","selector":"du","contract":"Measure target bytes before and after cleanup","callers":["cargo-clean"]}
{"kind":"external-program","identity":"external:jq","selector":"jq","contract":"Read the Cargo target directory when jq is available","callers":["cargo-clean"]}
{"kind":"external-program","identity":"external:sed","selector":"sed","contract":"Retained target-directory parser when jq is unavailable","callers":["cargo-clean","lane-gateway","release-suite","superloop-correspondence","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:logger","selector":"CARGO_CLEAN_LOGGER","contract":"Publish cleanup classifications and duration evidence to the journal","callers":["cargo-clean","superloop-correspondence","superloop-steward"]}
{"kind":"external-program","identity":"external:touch","selector":"touch","contract":"Prepare the next scan watermark","callers":["cargo-clean","release-suite","superloop-correspondence","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:sha256sum","selector":"sha256sum","contract":"Hash the observed correspondence file","callers":["cargo-clean","superloop-correspondence","superloop-steward"]}
{"kind":"external-program","identity":"external:cut","selector":"cut","contract":"Select the journal short hash","callers":["superloop-correspondence","superloop-node-status","superloop-steward"]}
{"kind":"external-program","identity":"external:mv","selector":"mv","contract":"Publish the completed scan watermark","callers":["permission-triage","superloop-correspondence","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:sync","selector":"sync","contract":"Make batch, dispositions, output and ledger writes durable before acknowledgement","callers":["superloop-steward"]}
{"kind":"external-program","identity":"external:dirname","selector":"dirname","contract":"Select the ledger directory for durability","callers":["cargo-clean","lane-gateway","release-suite","superloop-correspondence","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:cat","selector":"cat","contract":"Frame source bytes as untrusted batch evidence","callers":["cargo-clean","lane-gateway","permission-triage","release-suite","superloop-correspondence","superloop-lane","superloop-runtime","superloop-steward"]}
{"kind":"external-program","identity":"external:steward-claude","selector":"STEWARD_CLAUDE_COMMAND","contract":"Run the configured Claude with the standing charter and bounded pending-case batch","callers":["superloop-steward"]}
{"kind":"external-program","identity":"external:readlink","selector":"readlink","contract":"Compare custody link destinations without reading key bytes","callers":["cargo-clean","superloop-lane"]}
{"kind":"external-program","identity":"external:ln","selector":"ln","contract":"Create the declared custody and charter links","callers":["cargo-clean","release-suite","superloop-lane","superloop-steward"]}
{"kind":"delegated-call","identity":"steward-transcript-remote","caller":"superloop-steward","callee":"infra/steward/transcript-export","path":"packages/superloop-steward/src/transcript.rs","anchor":"ssh::quote(self.exporter)","selector":"--exporter","lookup":"configured-external","execution_host":"selected steward server","contract":"List and read exact transcript byte ranges through the configured SSH transport"}
{"kind":"delegated-call","identity":"steward-sessions-remote","caller":"superloop-steward","callee":"infra/steward/transcript-export","path":"packages/superloop-steward/src/main.rs","anchor":"ssh::quote(&args.connection.exporter)","selector":"--exporter","lookup":"configured-external","execution_host":"selected steward server","contract":"List transcripts for the sessions command through the configured SSH transport"}
{"kind":"delegated-call","identity":"steward-send-remote","caller":"superloop-steward","callee":"external:claude","path":"packages/superloop-steward/src/main.rs","anchor":"claude --resume {} --print -- {}","selector":"claude","lookup":"public-command","execution_host":"selected steward server","contract":"Resume the selected session with the quoted message and preserve SSH exit status"}
{"kind":"delegated-call","identity":"correspondence-remote-sudo","caller":"superloop-correspondence","callee":"external:sudo","path":"packages/superloop-correspondence/src/main.rs","anchor":"sudo journalctl -t correspondence-watch","selector":"sudo journalctl","lookup":"public-command","execution_host":"selected correspondence server","contract":"Read correspondence-watch journal events after the selected cursor and return the new cursor without writing local state"}
{"kind":"delegated-call","identity":"correspondence-remote-journalctl","caller":"superloop-correspondence","callee":"external:journalctl","path":"packages/superloop-correspondence/src/main.rs","anchor":"sudo journalctl -t correspondence-watch","selector":"sudo journalctl","lookup":"public-command","execution_host":"selected correspondence server","contract":"Read correspondence-watch journal events after the selected cursor and return the new cursor without writing local state"}
{"kind":"delegated-call","identity":"node-status-remote-nproc","caller":"superloop-node-status","callee":"external:nproc","path":"packages/superloop-node-status/src/main.rs","anchor":"/proc/loadavg","selector":"nproc","lookup":"public-command","execution_host":"selected node","contract":"Read visible processor count and three load averages for the status display"}
{"kind":"delegated-call","identity":"node-status-remote-cut","caller":"superloop-node-status","callee":"external:cut","path":"packages/superloop-node-status/src/main.rs","anchor":"/proc/loadavg","selector":"cut","lookup":"public-command","execution_host":"selected node","contract":"Read visible processor count and three load averages for the status display"}
{"kind":"delegated-call","identity":"vendor-proxy-unshare-install","caller":"superloop-lane","callee":"libexec/vendor-proxy","path":"packages/superloop-lane/src/install.rs","anchor":"\"unshare\", proxy_word.as_str(), \"--socket\"","selector":"pinned proxy_bin","lookup":"private-exact-path","execution_host":"host Podman user namespace","contract":"Run the verified private proxy with pinned socket and owner-controlled policy inputs"}
{"kind":"delegated-call","identity":"vendor-proxy-unshare-launch","caller":"superloop-lane","callee":"libexec/vendor-proxy","path":"packages/superloop-lane/src/launch.rs","anchor":"\"unshare\", proxy_word.as_str(), \"--socket\"","selector":"pinned proxy_bin","lookup":"private-exact-path","execution_host":"host Podman user namespace","contract":"Run the verified private proxy with pinned socket and owner-controlled policy inputs"}
{"kind":"delegated-call","identity":"container-helper-unshare","caller":"superloop-lane","callee":"bin/superloop-lane","path":"packages/superloop-lane/src/launch.rs","anchor":".args(helper_argv(","selector":"pinned lane_bin","lookup":"private-exact-path","execution_host":"host Podman user namespace","contract":"Run the lane private container helper with the inherited private input stream and pinned run state"}
{"kind":"delegated-call","identity":"door-service-unit","caller":"superloop-lane","callee":"libexec/door-service","path":"packages/superloop-lane/src/install_door.rs","anchor":"ExecStart={service_word} %i","selector":"configured door-service generation","lookup":"unit-install-path","execution_host":"host user service manager","contract":"Run the installed private door-service generation for the template loop instance"}
{"kind":"external-program","identity":"external:sudo","selector":"sudo","contract":"Read correspondence journal events on the selected server or run the two provisioned custody-test accounts on the test host","callers":["superloop-correspondence","superloop"]}
{"kind":"external-program","identity":"external:journalctl","selector":"sudo journalctl","contract":"Read correspondence-watch journal events after the selected cursor and return the new cursor without writing local state","callers":["superloop-correspondence"]}
{"kind":"external-program","identity":"external:nproc","selector":"nproc","contract":"Read visible processor count and three load averages for the status display","callers":["superloop-node-status"]}
{"kind":"external-program","identity":"external:/bin/cat","selector":"/bin/cat","contract":"Capture the exact driver input","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/env","selector":"/usr/bin/env","contract":"Capture the child environment","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/usr/bin/sort","selector":"/usr/bin/sort","contract":"Normalize the captured environment order","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:/bin/mkdir","selector":"/bin/mkdir","contract":"Create the requested fixture obstruction after launch","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:cmp","selector":"cmp","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","callers":["cargo-clean","lane-gateway","release-suite","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:wc","selector":"wc","contract":"Prepare disposable Cargo targets and instrumented tools; assert ownership, containment, idle thresholds, lock refusal and unchanged surrounding content","callers":["cargo-clean","release-suite","superloop-correspondence","superloop-steward"]}
{"kind":"external-program","identity":"external:seq","selector":"seq","contract":"Prepare disposable spool and disposition state and generated tools; assert durable pending-case transitions, identity, replay and deadlines","callers":["superloop-steward"]}
{"kind":"external-program","identity":"external:cp","selector":"cp","contract":"Prepare disposable sign-in homes and injected Python failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","callers":["superloop-gate-submit","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:tail","selector":"tail","contract":"Prepare disposable sign-in homes and injected Python failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","callers":["release-suite","superloop-gate-submit","superloop-lane","superloop-steward"]}
{"kind":"external-program","identity":"external:cksum","selector":"cksum","contract":"Prepare disposable sign-in homes and injected Python failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:rmdir","selector":"rmdir","contract":"Prepare disposable sign-in homes and injected Python failures; assert exact configuration, no-write verification, reconciliation and runtime wrapper argv","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:tee","selector":"tee","contract":"Retained driver reference prepares fixture runs, measures child progress and publishes parity reports","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:codex-oracle-program","selector":"ORACLE_PROGRAM","contract":"Execute the explicitly selected synthetic backend for reference capture","callers":["superloop-lane"]}
{"kind":"external-program","identity":"external:nice","selector":"nice","contract":"Retained submitter reference builds synthetic snapshots and renders the remote verification script for parity capture","callers":["superloop-gate-submit"]}
{"kind":"external-program","identity":"external:cargo","selector":"cargo","contract":"Build and test workspaces, including fresh public consumer resolutions and synthetic verification snapshots","callers":["meson:build-sync","superloop-gate-submit","superloop-pack"]}
{"kind":"external-program","identity":"external:gate-report-wrapper","selector":"LANE_VERIFY_REMOTE_RUNNER","contract":"Selected remote wrapper runs the reference verification script during manual capture","callers":["superloop-gate-submit"]}
{"kind":"external-program","identity":"external:tr","selector":"tr","contract":"Synthetic classifier drains or stalls input, creates descendants and emits bounded or deliberately oversized replies","callers":["permission-triage"]}
{"kind":"external-program","identity":"external:setsid","selector":"setsid_program","contract":"Construct the double-fork fixture using the available setsid executable","callers":["permission-triage"]}
{"kind":"external-program","identity":"external:triage-sentinel-fixture","selector":"fixture bin/triage-sentinel","contract":"Publish the disposable sentinel when the synthetic topology permits execution","callers":["permission-triage"],"fixture_source":"packages/permission-triage/tests/topology/bin/triage-sentinel"}
{"kind":"meson-call","site":"meson.build:find_program#1","sha256":"8e1a0f021668f8ee28eab5395cb03b2dc204543ada96ff5bdb39cbc4926c6b27","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"public-command","contract":"Resolve the required git executable during configuration and refuse if unavailable","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#1","sha256":"d4bb7a2c8acb2efadd22ceab23fef7f93a6722f388635f68504ef80eb32ceb98","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"public-command","contract":"Verify the requested release tag resolves to the selected commit","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#2","sha256":"9604fed367afc712861a042c0b02e5296bb9d64e7f7633ee9e976ef128216233","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"public-command","contract":"Read the checkout commit for release identity","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#3","sha256":"31092fe0a28606fd93402b4d9387e5269be8bb85ba365bdc6211c7ffed8352b4","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"public-command","contract":"Refuse a dirty tagged release","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:find_program#2","sha256":"7ad558bebc3ceae1a553c6da0bf92564a3a459c06daf1f38cca61eabafb64054","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo"],"lookup":"public-command","contract":"Resolve the required cargo executable during configuration and refuse if unavailable","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:find_program#3","sha256":"4d566952032738858aac7bd6a1c8b489043e84d83a25549deac97425c03bcd88","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo-fmt"],"lookup":"public-command","contract":"Resolve the required cargo-fmt executable during configuration and refuse if unavailable","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:find_program#4","sha256":"6762c80d9e1c0b3ae1c7c9c65c27ad65d972d57c33ab8cb771807bb8224f91d4","caller":"meson:build-sync","owner":"build-sync","callees":["external:bash"],"lookup":"public-command","contract":"Resolve the required bash executable during configuration and refuse if unavailable","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:find_program#5","sha256":"c1336bba06799a117e954d6d2d67a1d41eb4293a076d1e2c518487bdb5c0efce","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3"],"lookup":"public-command","contract":"Resolve the required python3 executable during configuration and refuse if unavailable","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:find_program#6","sha256":"ae2bd64df97db98c5d374d8c5c1611f3009a13d6aa1cb7b935eea6cb9c679959","caller":"meson:build-sync","owner":"build-sync","callees":["external:meson"],"lookup":"public-command","contract":"Resolve the required meson executable during configuration and refuse if unavailable","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:find_program#7","sha256":"b62d20523b3020eda924514b28e44088ad53c63f5119c0cbe311ef37a405f3ac","caller":"meson:build-sync","owner":"build-sync","callees":["external:env"],"lookup":"build-artifact","contract":"Resolve env to invoke the already-built private stamp probe","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:custom_target#2","sha256":"29ffdf963d8e4c782e46577d9bcf9c7dc0aaf7ccd605e8e0d7a00a6a269e19c7","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Check repository declarations and write the report and success stamp","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:custom_target#3","sha256":"a9f5d90b9d89e84800b3e7cfa4c8efc46ca0ac60f27cd541bcb2bc179d280239","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Check package project declarations and write the report and success stamp","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:custom_target#4","sha256":"5515cf9231e580e30ad3fdfd972711e1add92236adf8b8517f0c894a898b0b80","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Check declared prose formatting and write the report and success stamp","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:custom_target#5","sha256":"6db939d80ee89092d5aa6c7ce1ec16cf9e4f502a57b321cfb33c493594e94bd7","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Compare declared files with the repository file census and write the report and stamp","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_target#1","sha256":"145e4861255d29049b50ffb24a29e29687d5711c13244c99df68debd23cb1751","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Write package project declarations through the registered linter","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_target#2","sha256":"60c71ae5cc57b237213bb9c88325d3a475177da8b14e4bd3feb93cf6d8d99811","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Format the declared prose inputs through the registered linter","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#1","sha256":"b00becfd5ea29b43d9ab3149e8a8c0e14858380ac06b5f8889935cfd59f261de","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo","libexec/build-sync"],"lookup":"build-artifact","contract":"Probe the completed lint target stamps through the built helper","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#2","sha256":"1cd745887a565c02c6e2c2b85776c2c089cf4f022c165c132f2fcfe7bce8baee","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo"],"lookup":"public-command","contract":"Run the explicitly selected slow route-transfer library fixture","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#3","sha256":"8301df2ed7f7afe5ff6967ee586c42ee6e0c6f12deb650b158b131fb2a89bcc7","caller":"meson:build-sync","owner":"build-sync","callees":["external:bash"],"lookup":"public-command","contract":"Syntax-check each declared shell source without executing it","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#4","sha256":"8cbea66c6a33c3e76aae0583554783c03f3432e2fe15d6ebf6e16778bd3e7039","caller":"meson:build-sync","owner":"build-sync","callees":["external:bash"],"lookup":"public-command","contract":"Run each declared release harness with the built client bindings","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#5","sha256":"ecd7f5113060b4ebbba4d829dcd40bd86747b00e98f011c343fba338de3785b4","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Run the release declaration check through the synced linter","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#7","sha256":"2acceecf55e8ab5101f90953d0f827d5919af0a71680f9a21b2af71f7e890bca","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-lint"],"lookup":"build-artifact","contract":"Run the release declared-file census through the synced linter","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#8","sha256":"8f952e058c06b2c671a11c6bde8258e4c4396b4cbd7f10ee7b91d75f23da8602","caller":"meson:build-sync","owner":"build-sync","callees":["bin/superloop-runtime","external:python3"],"lookup":"public-command","contract":"Run the version checker for each Rust roster identity with its manifest and optional source commit","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#10","sha256":"423ffd288559af245237034f2c1e076c26dedc2e92dee483f29f9283d91d8586","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3"],"lookup":"public-command","contract":"Resolve the owning manifest version including workspace inheritance for configured shell programs","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:custom_target#6","sha256":"7f624b3c7c170abe6b3948368e710c0e64bdb9a53dca4d2e9e3e8d92347da6df","caller":"meson:build-sync","owner":"build-sync","callees":["libexec/build-sync"],"lookup":"build-artifact","contract":"Record the configured shell output digest and producer version; resolve installed identity, owner version and release group from the configured ledger and record the supplied repository and full source commit","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#9","sha256":"0f3d291f790f816417f0d80384c54a62c0b95f9e026cf69095737280d9afc96d","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3"],"lookup":"public-command","contract":"Run the version checker for each configured shell program with its Meson-resolved version; compare installed name, version, release group, repository, source commit and full digest with its build record","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#10","sha256":"12e7fa87edf6073739c70152e5e8007beb4c41e031d4caffc1cb9c2141ee98ae","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo-fmt"],"lookup":"public-command","contract":"Check all workspace Rust formatting without invoking Cargo argument dispatch","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#11","sha256":"d8c3f243e67ca05647ba738867dce0bf86b643b40bdfa5833ccffa28807d0ba3","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo"],"lookup":"public-command","contract":"Run locked workspace all-target Clippy with warnings denied","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:test#12","sha256":"52f9a604748f212a63f5a2cb4608192d9c789c951a8bcacae19c0a90914cf446","caller":"meson:build-sync","owner":"build-sync","callees":["external:cargo"],"lookup":"public-command","contract":"Run locked workspace tests with the real linter and private requests helper bound from their declared build targets in the suite environment","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"external-program","identity":"external:cargo-fmt","selector":"cargo-fmt","contract":"Resolve the required cargo-fmt executable during configuration and refuse if unavailable","callers":["meson:build-sync"]}
{"kind":"external-program","identity":"external:meson","selector":"meson","contract":"Resolve the required meson executable during configuration and refuse if unavailable","callers":["meson:build-sync","superloop-pack"]}
{"kind":"data","identity":"steward-pending-spool","writer":"infra/steward/steward-spool-append","readers":["infra/steward/steward-runner"],"format_authority":"infra/steward/README.md","format_contract":"Locked append-only TSV with stable case identity, source root, relative file, event digest, classification and timestamp; runner subtracts durable dispositions before constructing a pending batch","sites":[{"path":"infra/steward/steward-spool-append","anchor":"\"$CASE_ID\" \"$SOURCE\" \"$RELATIVE\" \"$EVENT_SHA\" \"$CLASSIFICATION\" \"$EVENT_TIMESTAMP\""},{"path":"infra/steward/steward-runner","anchor":"STEWARD_SPOOL_FILE"}],"owner":"SUPERLOOPSTEWARD"}
{"kind":"data","identity":"trusted-loop-registry","writer":"external:operator","readers":["loop-home","superloop","superloop-chat-export","superloop-claude-hook","superloop-lane"],"format_authority":"packages/loop-home/README.md","format_contract":"Owner-controlled registry rows carry loop identity, custody, launch, session and runs-root grants; readers validate rows without deriving the runs root from a home prefix","sites":[{"path":"packages/loop-home/src/registry.rs","anchor":"pub struct LoopRecord"},{"path":"packages/superloop-lane/src/plan.rs","anchor":"registry"}],"owner":"LOOPHOME"}
{"kind":"data","identity":"heartbeat-session-state","writer":"session-core","readers":["superloop","superloop-claude-hook"],"format_authority":"packages/session-core/README.md","format_contract":"Existing per-project heartbeat toggle and per-session count, warning and prompt marker identities are shared by the retained hook and the harness adapter through the neutral core; no registration switch is inferred from the common format","sites":[{"path":"packages/session-core/src/heartbeat.rs","anchor":"guard-count-"},{"path":"packages/session-core/src/heartbeat_toggle.rs","anchor":"heartbeat{}"},{"path":"packages/session-core/src/pre_tool.rs","anchor":"prompt_marker_file"}],"owner":"SESSIONCORE"}
{"kind":"data","identity":"orchestrator-session-state","writer":"session-core","readers":["superloop","superloop-claude-hook"],"format_authority":"packages/session-core/README.md","format_contract":"Existing global/project toggle, session scope, rulebook snapshots and observation state retain their identities across the retained hook and harness adapter","sites":[{"path":"packages/session-core/src/orchestrator.rs","anchor":"orchestrator-scope-"},{"path":"packages/session-core/src/orchestrator_toggle.rs","anchor":"orchestrator-disabled-GLOBAL"}],"owner":"SESSIONCORE"}
{"kind":"data","identity":"permission-request-envelope","writer":"permission-triage","readers":["external:request-reviewer","permission-triage"],"format_authority":"packages/request-core/README.md","format_contract":"Schema-one request collection, monotone review and answer envelopes; permission authority, verdict journal and effect consumption remain owned by permission-triage","sites":[{"path":"packages/request-core/src/model.rs","anchor":"pub struct Collection"},{"path":"packages/request-core/src/review.rs","anchor":"pub struct Review"}],"owner":"PERMISSIONTRIAGE"}
{"kind":"data","identity":"door-request-envelope","writer":"superloop-lane","readers":["external:request-reviewer","superloop-lane"],"format_authority":"packages/request-core/README.md","format_contract":"Schema-one request collection, monotone review and answer envelopes; door identity, custody, effect evidence and service execution remain owned by the lane","sites":[{"path":"packages/request-core/src/model.rs","anchor":"pub struct Collection"},{"path":"packages/request-core/src/transaction.rs","anchor":"pub struct Transaction"}],"owner":"SUPERLOOPLANE"}
{"kind":"data","identity":"synced-build-record","writer":"build-sync","readers":["external:release-suite","superloop-install"],"format_authority":"packages/build-sync/README.md","format_contract":"JSON build records bind bytes to installed identity, package, version, release group, source repository and full commit, execution domain and toolchain; native records install under the data directory","sites":[{"path":"packages/build-sync/src/lib.rs","anchor":"struct BuildRecord"},{"path":"packages/superloop-install/src/lib.rs","anchor":"parse_build_record"},{"path":"tests/version-smoke.py","anchor":"hashlib.sha256(args.binary.read_bytes()).hexdigest()"}],"owner":"BUILDSYNC"}
{"kind":"test-tool","consumer":"build-sync","binding":"CARGO_BIN_EXE_build-sync","provider":"cargo-target","callee":"libexec/build-sync","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-chat-export","binding":"CARGO_BIN_EXE_superloop-chat-export","provider":"cargo-target","callee":"bin/superloop-chat-export","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"lane-gateway","binding":"CARGO_BIN_EXE_gateway-service","provider":"cargo-target","callee":"libexec/gateway-service","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-gate-submit","binding":"CARGO_BIN_EXE_superloop-gate-submit","provider":"cargo-target","callee":"bin/superloop-gate-submit","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-lint","binding":"CARGO_BIN_EXE_superloop-lint","provider":"cargo-target","callee":"bin/superloop-lint","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop","binding":"CARGO_BIN_EXE_superloop","provider":"cargo-target","callee":"bin/superloop","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"permission-triage","binding":"CARGO_BIN_EXE_permission-triage-topology","provider":"cargo-target","callee":"libexec/permission-triage-topology","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"permission-triage","binding":"CARGO_BIN_EXE_permission-triage-assemble","provider":"cargo-target","callee":"libexec/permission-triage-assemble","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"permission-triage","binding":"CARGO_BIN_EXE_requests-helper","provider":"cargo-target","callee":"libexec/requests-helper","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-pack","binding":"CARGO_BIN_EXE_superloop-pack","provider":"cargo-target","callee":"bin/superloop-pack","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-install","binding":"CARGO_BIN_EXE_superloop-install","provider":"cargo-target","callee":"bin/superloop-install","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-run-report","binding":"CARGO_BIN_EXE_superloop-run-report","provider":"cargo-target","callee":"build/superloop-run-report","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-claude-hook","binding":"CARGO_BIN_EXE_superloop-claude-hook","provider":"cargo-target","callee":"libexec/superloop-claude-hook","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-correspondence","binding":"CARGO_BIN_EXE_superloop-correspondence","provider":"cargo-target","callee":"bin/superloop-correspondence","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-lane","binding":"CARGO_BIN_EXE_superloop-lane","provider":"cargo-target","callee":"bin/superloop-lane","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-node-status","binding":"CARGO_BIN_EXE_superloop-node-status","provider":"cargo-target","callee":"bin/superloop-node-status","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-steward","binding":"CARGO_BIN_EXE_superloop-steward","provider":"cargo-target","callee":"bin/superloop-steward","suite":"cargo-test","contract":"Cargo supplies the declared binary target to its own package integration tests"}
{"kind":"test-tool","consumer":"superloop-pack","binding":"PUBLIC_PACK_TEST_LINTER","provider":"meson-environment","callee":"bin/superloop-lint","suite":"cargo-test","contract":"The superloop-pack policy fixtures receive the built real linter from the suite environment; absence refuses by name"}
{"kind":"test-tool","consumer":"superloop-lane","binding":"SUPERLOOP_TEST_REQUESTS_HELPER","provider":"meson-environment","callee":"libexec/requests-helper","suite":"cargo-test","contract":"Request fixtures receive the built private helper from the suite environment without building another package"}
{"kind":"installation","route":"native","source":"build:packages/superloop-claude-hook/superloop-claude-hook.build.json","destination":"@datadir@/superloop/build-records/superloop-claude-hook.build.json","owner":"superloop-claude-hook"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/permission-triage-hook.build.json","destination":"@datadir@/superloop/build-records/permission-triage-hook.build.json","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/requests-helper.build.json","destination":"@datadir@/superloop/build-records/requests-helper.build.json","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/vendor-proxy.build.json","destination":"@datadir@/superloop/build-records/vendor-proxy.build.json","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/door-ssh.build.json","destination":"@datadir@/superloop/build-records/door-ssh.build.json","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/door-service.build.json","destination":"@datadir@/superloop/build-records/door-service.build.json","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/superloop-lane","destination":"@bindir@/superloop-lane","owner":"superloop-lane"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lane/superloop-lane.build.json","destination":"@datadir@/superloop/build-records/superloop-lane.build.json","owner":"superloop-lane"}
{"kind":"meson-call","site":"meson.build:run_command#5","sha256":"9604fed367afc712861a042c0b02e5296bb9d64e7f7633ee9e976ef128216233","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"public-command","contract":"Resolve the checkout source commit for every build record and the lane version record unless the reviewed source commit is explicitly configured","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#6","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"build-artifact","contract":"Resolve the actual Git HEAD file for source-commit rebuild tracking","sha256":"c59b7764e5ff2eb8d87aa9e296611d4f37600da9dddf8cf5df37068509ab2632","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#7","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"build-artifact","contract":"Resolve the optional symbolic HEAD ref for source-commit rebuild tracking","sha256":"7c5d962dac0a3f72193203f4b7a63d4f5ce41d76976b74df019a0fce09436626","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#8","caller":"meson:build-sync","owner":"build-sync","callees":["external:git"],"lookup":"build-artifact","contract":"Resolve the symbolic ref file for source-commit rebuild tracking","sha256":"ea8768a1e2ab74e67af92e2f2e89c46f6a7d6e9d86901222774f37c232275bc6","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:run_command#9","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3"],"lookup":"build-artifact","contract":"Enumerate Cargo binary outputs through the declared workspace producer","sha256":"a138a69550742066db0542f4da2de74fe2d0e798e83d51fed50681f3e929c3b6","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"meson-call","site":"meson.build:custom_target#1","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3","external:cargo"],"lookup":"build-artifact","contract":"Build the release workspace once through workspace.py using its lockfile when present with the configured compile environment; publish each declared artifact and the aggregate feature and source-commit record","sha256":"ae10560a78c6dfda27684d6a61ac0d898029837c2ee9a96ec92616593af9e6e9","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"payload","path":"packages/build-sync/workspace.py","form":"python","sha256":"a03a535045e1f9287606bc50aefa7c7d4d627d2d3373890b5e62de00744b1bdc","owner":"build-sync","interpreter":"python3","execution_host":"build host","version_authority":"packages/build-sync/Cargo.toml","contract":"Enumerate and build the workspace once using its lockfile when present, stage declared artifacts, record aggregate features and compile wall, and write source dependencies","calls":[{"callee":"external:git","selector":"git","anchor":"[\"git\", \"-C\"","contract":"Resolve the source commit when not supplied","lookup":"public-command"},{"callee":"external:configured-cargo","selector":"cargo","anchor":"[cargo, \"build\"","contract":"Build the release workspace using its lockfile when present with JSON artifacts and the configured shared environment","lookup":"configured-external"}]}
{"kind":"installation","route":"native","source":"build:packages/superloop-lint/superloop-lint","destination":"@bindir@/superloop-lint","owner":"superloop-lint"}
{"kind":"installation","route":"native","source":"build:packages/superloop-lint/superloop-lint.build.json","destination":"@datadir@/superloop/build-records/superloop-lint.build.json","owner":"superloop-lint"}
{"kind":"installation","route":"native","source":"build:packages/superloop-install/superloop-install","destination":"@bindir@/superloop-install","owner":"superloop-install"}
{"kind":"installation","route":"native","source":"build:packages/superloop-install/superloop-install.build.json","destination":"@datadir@/superloop/build-records/superloop-install.build.json","owner":"superloop-install"}
{"kind":"installation","route":"native","source":"build:packages/superloop-pack/superloop-pack","destination":"@bindir@/superloop-pack","owner":"superloop-pack"}
{"kind":"installation","route":"native","source":"build:packages/superloop-pack/superloop-pack.build.json","destination":"@datadir@/superloop/build-records/superloop-pack.build.json","owner":"superloop-pack"}
{"kind":"installation","route":"native","source":"build:packages/build-sync/build-sync","destination":"@libexecdir@/superloop/build-sync","owner":"build-sync"}
{"kind":"installation","route":"native","source":"build:packages/build-sync/build-sync.build.json","destination":"@datadir@/superloop/build-records/build-sync.build.json","owner":"build-sync"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/permission-triage-topology","destination":"@libexecdir@/superloop/permission-triage-topology","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/permission-triage-topology.build.json","destination":"@datadir@/superloop/build-records/permission-triage-topology.build.json","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/permission-triage-assemble","destination":"@libexecdir@/superloop/permission-triage-assemble","owner":"permission-triage"}
{"kind":"installation","route":"native","source":"build:packages/permission-triage/permission-triage-assemble.build.json","destination":"@datadir@/superloop/build-records/permission-triage-assemble.build.json","owner":"permission-triage"}
{"kind":"data","identity":"permission-adapter-registration","writer":"permission-triage","readers":["external:claude-harness"],"format_authority":"packages/permission-triage/deploy/settings-fragment.md","format_contract":"Assembler replaces the template command with the quoted absolute PERMISSION_TRIAGE_ADAPTER_BIN and pre-tool-use; the fragment never selects bypass or installs live settings","sites":[{"path":"packages/permission-triage/src/bin/permission-triage-assemble.rs","anchor":"fn settings_for_adapter("}],"owner":"PERMISSIONTRIAGE"}
{"kind":"test-tool","consumer":"permission-triage","binding":"CARGO_BIN_EXE_permission-triage-hook","provider":"cargo-target","callee":"libexec/permission-triage-hook","suite":"cargo-test","contract":"Cargo supplies the private hook binary for its permission, journal and topology integration fixtures"}
{"kind":"installation","route":"native","source":"build:versioned-infra-steward-transcript-export","destination":"@libexecdir@/superloop/transcript-export","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:versioned-infra-steward-transcript-export.build.json","destination":"@datadir@/superloop/build-records/versioned-infra-steward-transcript-export.build.json","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"test-tool","consumer":"superloop-steward","binding":"STEWARD_TEST_EXPORTER","provider":"meson-environment","callee":"infra/steward/transcript-export","suite":"cargo-test","contract":"The fixture receives the configured server program from the declared suite environment; absence refuses by name"}
{"kind":"installation","route":"native","source":"build:versioned-infra-steward-steward-runner","destination":"@libexecdir@/superloop/steward-runner","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:versioned-infra-steward-steward-runner.build.json","destination":"@datadir@/superloop/build-records/versioned-infra-steward-steward-runner.build.json","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"test-tool","consumer":"superloop-steward","binding":"STEWARD_TEST_RUNNER","provider":"meson-environment","callee":"infra/steward/steward-runner","suite":"release-harness-infra-steward-tests-run-sh","contract":"The fixture receives the configured server program from the declared suite environment; absence refuses by name"}
{"kind":"installation","route":"native","source":"build:versioned-infra-steward-steward-spool-append","destination":"@libexecdir@/superloop/steward-spool-append","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:versioned-infra-steward-steward-spool-append.build.json","destination":"@datadir@/superloop/build-records/versioned-infra-steward-steward-spool-append.build.json","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"test-tool","consumer":"superloop-steward","binding":"STEWARD_TEST_APPEND","provider":"meson-environment","callee":"infra/steward/steward-spool-append","suite":"release-harness-infra-steward-tests-run-sh","contract":"The fixture receives the configured server program from the declared suite environment; absence refuses by name"}
{"kind":"installation","route":"native","source":"build:versioned-infra-correspondence-watch-correspondence-scan","destination":"@libexecdir@/superloop/correspondence-scan","owner":"superloop-correspondence","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:versioned-infra-correspondence-watch-correspondence-scan.build.json","destination":"@datadir@/superloop/build-records/versioned-infra-correspondence-watch-correspondence-scan.build.json","owner":"superloop-correspondence","when_option":"server_kits"}
{"kind":"test-tool","consumer":"superloop-correspondence","binding":"CORRESPONDENCE_TEST_SCAN","provider":"meson-environment","callee":"infra/correspondence-watch/correspondence-scan","suite":"release-harness-infra-correspondence-watch-tests-run-sh","contract":"The fixture receives the configured server program from the declared suite environment; absence refuses by name"}
{"kind":"installation","route":"native","source":"build:versioned-infra-cargo-clean-target-clean","destination":"@libexecdir@/superloop/target-clean","owner":"cargo-clean","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:versioned-infra-cargo-clean-target-clean.build.json","destination":"@datadir@/superloop/build-records/versioned-infra-cargo-clean-target-clean.build.json","owner":"cargo-clean","when_option":"server_kits"}
{"kind":"test-tool","consumer":"cargo-clean","binding":"TARGET_CLEAN_TEST_BINARY","provider":"meson-environment","callee":"infra/cargo-clean/target-clean","suite":"release-harness-infra-cargo-clean-tests-run-sh","contract":"The fixture receives the configured server program from the declared suite environment; absence refuses by name"}
{"kind":"installation","route":"native","source":"build:superloop-steward.service","destination":"@system_unitdir@/superloop-steward.service","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:superloop-steward.timer","destination":"@system_unitdir@/superloop-steward.timer","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:superloop-correspondence-scan.service","destination":"@system_unitdir@/superloop-correspondence-scan.service","owner":"superloop-correspondence","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:superloop-correspondence-scan.timer","destination":"@system_unitdir@/superloop-correspondence-scan.timer","owner":"superloop-correspondence","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:superloop-target-clean@.service","destination":"@system_unitdir@/superloop-target-clean@.service","owner":"cargo-clean","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"build:superloop-target-clean@.timer","destination":"@system_unitdir@/superloop-target-clean@.timer","owner":"cargo-clean","when_option":"server_kits"}
{"kind":"installation","route":"native","source":"source:infra/steward/charter.md","destination":"@sysconfdir@/steward/charter.md","owner":"superloop-steward","when_option":"server_kits"}
{"kind":"test-tool","consumer":"staff-provision","binding":"CARGO_BIN_EXE_account","provider":"cargo-target","callee":"libexec/account","suite":"cargo-test","contract":"The suite supplies the declared built program; fixtures refuse a missing binding by name"}
{"kind":"test-tool","consumer":"superloop","binding":"SUPERLOOP_TEST_CLAUDE_HOOK","provider":"meson-environment","callee":"libexec/superloop-claude-hook","suite":"cargo-test","contract":"The suite supplies the declared built program; fixtures refuse a missing binding by name"}
{"kind":"test-tool","consumer":"superloop-claude-hook","binding":"SUPERLOOP_TEST_BINARY","provider":"meson-environment","callee":"bin/superloop","suite":"cargo-test","contract":"The suite supplies the declared built program; fixtures refuse a missing binding by name"}
{"kind":"test-tool","consumer":"superloop-lane","binding":"SUPERLOOP_TEST_BINARY","provider":"meson-environment","callee":"bin/superloop","suite":"cargo-test","contract":"The suite supplies the declared built program; fixtures refuse a missing binding by name"}
{"kind":"test-tool","consumer":"superloop-lane","binding":"SIGNIN_TEST_BINARY","provider":"meson-environment","callee":"bin/superloop-lane","suite":"release-harness-tests-loop-codex-home-run-sh","contract":"The suite supplies the declared built program; fixtures refuse a missing binding by name"}
{"kind":"test-tool","consumer":"superloop-lane","binding":"RUNTIME_TEST_BINARY","provider":"meson-environment","callee":"bin/superloop-runtime","suite":"release-harness-tests-loop-codex-home-run-sh","contract":"The suite supplies the declared built program; fixtures refuse a missing binding by name"}
{"kind":"meson-call","site":"meson.build:test#6","sha256":"3941cba17d625f69bb83d84782d8316e52e5834f61e3131a29b4dcc231391a53","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3"],"lookup":"test-executable","contract":"Execute the live ci Python docstring carrier with isolated unittest discovery after staging the candidate linter"}
''']

dependency_ledger += ['''
{"kind":"test-tool","consumer":"lane-gateway","binding":"GATEWAY_RUNNER_TEST_BINARY","provider":"meson-environment","callee":"libexec/gateway-runner","suite":"release-harness-tests-gateway-runner-run-sh","contract":"Run the configured shell output supplied by the release suite"}
{"kind":"data","identity":"gateway-common-proposals","writer":"permission-triage","readers":["lane-gateway","superloop-lane"],"format_authority":"packages/request-core/README.md","format_contract":"Gateway proposal bodies, decisions, claims and service results share the calling loop journal; the service retains execution and worker projection evidence","sites":[{"path":"packages/lane-gateway/src/channel.rs","anchor":"--owner-read"},{"path":"packages/permission-triage/src/journal/owner.rs","anchor":"gateway-proposal"},{"path":"packages/request-core/src/gateway.rs","anchor":"gateway-proposal"}],"owner":"LANEGATEWAY"}
{"kind":"data","identity":"gateway-execution-budget","writer":"lane-gateway","readers":["lane-lifecycle"],"format_authority":"packages/lane-gateway/README.md","format_contract":"execution-budgets/LANE/SEQ.json contains schema, lane, seq and timeout_seconds; the service publishes it before the exclusive execution resolution so lifecycle credits only bounded approved work","sites":[{"path":"packages/lane-gateway/src/proposal.rs","anchor":"execution-budgets"},{"path":"packages/lane-lifecycle/src/lib.rs","anchor":"execution-budgets"}],"owner":"LANEGATEWAY"}
''']

dependency_ledger += ['''
{"kind":"call","site":"packages/lane-gateway/src/tests.rs:std :: env :: var_os (\"SUPERLOOP_TEST_REQUESTS_HELPER\") . expect (\"built helper\")#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"std :: env :: var_os (\"SUPERLOOP_TEST_REQUESTS_HELPER\") . expect (\"built helper\")","callee":"libexec/requests-helper","lookup":"test-executable","binding":"SUPERLOOP_TEST_REQUESTS_HELPER","contract":"Exercise the declared built binary with isolated loop settings and assert exact command streams and status"}
{"kind":"call","site":"packages/lane-gateway/tests/command_surface.rs:env ! (\"CARGO_BIN_EXE_gateway-service\")#1","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"env ! (\"CARGO_BIN_EXE_gateway-service\")","callee":"libexec/gateway-service","lookup":"test-executable","binding":"CARGO_BIN_EXE_gateway-service","contract":"Exercise the declared built binary with isolated loop settings and assert exact command streams and status"}
{"kind":"call","site":"packages/lane-gateway/tests/command_surface.rs:env ! (\"CARGO_BIN_EXE_gateway-service\")#2","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"env ! (\"CARGO_BIN_EXE_gateway-service\")","callee":"libexec/gateway-service","lookup":"test-executable","binding":"CARGO_BIN_EXE_gateway-service","contract":"Exercise the declared built binary with isolated loop settings and assert exact command streams and status"}
{"kind":"call","site":"packages/lane-gateway/tests/command_surface.rs:env ! (\"CARGO_BIN_EXE_gateway-service\")#3","caller":"lane-gateway","owner":"LANEGATEWAY","selector":"env ! (\"CARGO_BIN_EXE_gateway-service\")","callee":"libexec/gateway-service","lookup":"test-executable","binding":"CARGO_BIN_EXE_gateway-service","contract":"Exercise the declared built binary with isolated loop settings and assert exact command streams and status"}
{"kind":"call","site":"packages/superloop-lane/tests/private_dispatch.rs:env ! (\"CARGO_BIN_EXE_superloop-lane\")#2","caller":"superloop-lane","owner":"LOOPHOME","selector":"env ! (\"CARGO_BIN_EXE_superloop-lane\")","callee":"bin/superloop-lane","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-lane","contract":"Exercise the declared built binary with isolated loop settings and assert exact command streams and status"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"meson.build:test#13","caller":"meson:build-sync","owner":"build-sync","callees":["libexec/build-sync"],"lookup":"build-artifact","contract":"Measure the configured dependency ledger against the source graph in every release suite","sha256":"7d966b9319384a438978abca08a76f120dfa683c737126b5b8e0bad94d5ffb2d","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"meson.build:test#14","caller":"release-suite","owner":"superloop-pack","callees":["external:python3","bin/superloop-pack","bin/superloop-lint","external:configured-cargo"],"lookup":"test-executable","contract":"Build and stage-verify a fixture pack, then compile its isolated library consumer offline with HOME unset","sha256":"0ab5fb262d41a9695a5efd2d5a9fecd881f314b8f54a5df77e7ec9c032e0c75e","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"payload","path":"packages/superloop-pack/tests/consumer.py","form":"python","sha256":"2f6041833e78ce4039dc8ba1c63844f747729ce3ac66c3e31ec26d0d716436e3","owner":"superloop-pack","interpreter":"python3","execution_host":"build node","version_authority":"packages/superloop-pack/Cargo.toml","contract":"Built-binary public pack round trip and isolated library consumer","calls":[{"callee":"external:git","selector":"git","anchor":"run(['git'","contract":"Invoke the declared fixture tool and require success with captured diagnostics","lookup":"test-executable"},{"callee":"bin/superloop-pack","selector":"--pack","anchor":"run([args.pack","contract":"Invoke the declared fixture tool and require success with captured diagnostics","lookup":"test-executable"},{"callee":"bin/superloop-lint","selector":"--linter","anchor":"'--linter', args.linter","contract":"Invoke the declared fixture tool and require success with captured diagnostics","lookup":"test-executable"},{"callee":"external:configured-cargo","selector":"--cargo","anchor":"run([args.cargo","contract":"Invoke the declared fixture tool and require success with captured diagnostics","lookup":"test-executable"}]}
''']


dependency_ledger += ['''
{"kind":"call","site":"packages/superloop/tests/command_contract.rs:env ! (\"CARGO_BIN_EXE_superloop\")#1","caller":"superloop","owner":"SUPERLOOP","selector":"env ! (\"CARGO_BIN_EXE_superloop\")","callee":"bin/superloop","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop","contract":"Refuse unknown envelopes and caller-selected loop identity through the built public entry; journal transitions are separately exercised as unit protocol fixtures"}
''']

dependency_ledger += ['''
''']

dependency_ledger += ['''
{"kind":"installation","route":"native","source":"source:docs/public/README.md","destination":"@datadir@/superloop-tools/docs/public/README.md","owner":"TOOLS"}
{"kind":"installation","route":"native","source":"source:docs/spec/deployment.md","destination":"@datadir@/superloop-tools/docs/spec/deployment.md","owner":"TOOLS"}
{"kind":"installation","route":"native","source":"source:docs/spec/linter-conformance.md","destination":"@datadir@/superloop-tools/docs/spec/linter-conformance.md","owner":"TOOLS"}
{"kind":"installation","route":"native","source":"source:docs/spec/output.md","destination":"@datadir@/superloop-tools/docs/spec/output.md","owner":"TOOLS"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"meson.build:run_command#4","sha256":"5d598151996fa29c837bbe6ee2232ee6abee35a39ecdc360ed60d7833c4386f9","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149","caller":"meson:build-sync","owner":"build-sync","callees":["external:python3","external:git"],"lookup":"public-command","contract":"Classify tracked files against the public manifest for shared declarations and public document installation"}
''']

dependency_ledger += ['''
{"kind":"meson-call","site":"meson.build:test#15","caller":"release-suite","owner":"superloop-pack","callees":["external:python3","bin/superloop-pack","bin/superloop-lint"],"lookup":"test-executable","contract":"Prove committed public cut and archive configuration with built tools under a shared wall bound","sha256":"df654a0eeae7b8cfdb759dcdb020eeebe25057217fdf0e5464b7b691af08e179","scope_sha256":"dd52fc5a1363e0077b2bc3f653f176cdda61f3aaa92cc6acef8e924dd7816149"}
{"kind":"payload","path":"packages/superloop-pack/tests/cut_acceptance.py","form":"python","sha256":"78535f6b34ec2bf9371cda9100531de3f4f519f4fb2d76f265cd21be2c448ab8","owner":"superloop-pack","interpreter":"python3","execution_host":"build node","version_authority":"packages/superloop-pack/Cargo.toml","contract":"Bounded cut, citation resolution and history-free archive acceptance","calls":[{"callee":"external:git","selector":"git","anchor":"run(['git'","contract":"Invoke the declared built tool and require successful acceptance","lookup":"test-executable"},{"callee":"external:meson","selector":"meson","anchor":"run(['meson'","contract":"Invoke the declared built tool and require successful acceptance","lookup":"test-executable"},{"callee":"bin/superloop-pack","selector":"--pack","anchor":"run([args.pack","contract":"Invoke the declared built tool and require successful acceptance","lookup":"test-executable"},{"callee":"bin/superloop-lint","selector":"--linter","anchor":"run([args.linter","contract":"Invoke the declared built tool and require successful acceptance","lookup":"test-executable"},{"callee":"external:timeout","selector":"timeout","anchor":"['timeout'","contract":"Bound each command and its process group by the remaining shared acceptance budget","lookup":"public-command"},{"callee":"external:cargo","selector":"cargo","anchor":"run(['cargo'","contract":"Build the public workspace with a fresh consumer resolution","lookup":"public-command"}]}
''']

ledger_configuration = configuration_data()
dependency_ledger += ['''
{"kind":"accountable-owner","package":"build-sync","owner":"BUILDSYNC"}
{"kind":"accountable-owner","package":"execute-command","owner":"PERMISSIONTRIAGE"}
{"kind":"accountable-owner","package":"superloop-chat-export","owner":"SUPERLOOPCHATEXPORT"}
{"kind":"accountable-owner","package":"superloop-cli-common","owner":"SUPERLOOPCLICOMMON"}
{"kind":"accountable-owner","package":"superloop-execwrap","owner":"SUPERLOOPEXECWRAP"}
{"kind":"accountable-owner","package":"lane-gateway","owner":"LANEGATEWAY"}
{"kind":"accountable-owner","package":"lane-lifecycle","owner":"LANELIFECYCLE"}
{"kind":"accountable-owner","package":"superloop-gate-submit","owner":"SUPERLOOPGATESUBMIT"}
{"kind":"accountable-owner","package":"superloop-lint","owner":"SUPERLOOPLINT"}
{"kind":"accountable-owner","package":"loop-home","owner":"LOOPHOME"}
{"kind":"accountable-owner","package":"permission-triage","owner":"PERMISSIONTRIAGE"}
{"kind":"accountable-owner","package":"superloop-pack","owner":"SUPERLOOPPACK"}
{"kind":"accountable-owner","package":"pulldown-cmark-to-cmark","owner":"PULLDOWNCMARKTOCMARK"}
{"kind":"accountable-owner","package":"request-core","owner":"PERMISSIONTRIAGE"}
{"kind":"accountable-owner","package":"superloop-install","owner":"SUPERLOOPINSTALL"}
{"kind":"accountable-owner","package":"superloop-run-report","owner":"SUPERLOOPRUNREPORT"}
{"kind":"accountable-owner","package":"run-worker","owner":"RUNWORKER"}
{"kind":"accountable-owner","package":"session-core","owner":"ORCHESTRATORHOOK"}
{"kind":"accountable-owner","package":"staff-provision","owner":"STAFFPROVISION"}
{"kind":"accountable-owner","package":"superloop-claude-desktop","owner":"SUPERLOOPCLAUDEDESKTOP"}
{"kind":"accountable-owner","package":"superloop-claude-hook","owner":"SUPERLOOPCLAUDEHOOK"}
{"kind":"accountable-owner","package":"superloop-correspondence","owner":"SUPERLOOPCORRESPONDENCE"}
{"kind":"accountable-owner","package":"superloop-lane","owner":"SUPERLOOPLANE"}
{"kind":"call","site":"packages/superloop-lane/tests/signin_home_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-lane\")#1","caller":"superloop-lane","owner":"SUPERLOOPLANE","selector":"env ! (\"CARGO_BIN_EXE_superloop-lane\")","callee":"bin/superloop-lane","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-lane","contract":"Exercise pinned home creation and parent replacement, old and explicit location reports, charter publication, sign-in links and distinct source, fresh and existing owner UID comparisons through production commands"}
{"kind":"call","site":"packages/superloop-lane/tests/signin_home_contract.rs:env ! (\"CARGO_BIN_EXE_superloop-lane\")#2","caller":"superloop-lane","owner":"SUPERLOOPLANE","selector":"env ! (\"CARGO_BIN_EXE_superloop-lane\")","callee":"bin/superloop-lane","lookup":"test-executable","binding":"CARGO_BIN_EXE_superloop-lane","contract":"Exercise exact canonical modes and namespace-mapped group reporting without host-side chown through production prepare"}
{"kind":"accountable-owner","package":"superloop-node-status","owner":"SUPERLOOPNODESTATUS"}
{"kind":"accountable-owner","package":"superloop-steward","owner":"SUPERLOOPSTEWARD"}
{"kind":"accountable-owner","package":"superloop-runtime","owner":"SUPERLOOPRUNTIME"}
{"kind":"accountable-owner","package":"superloop","owner":"SUPERLOOP"}
{"kind":"call","site":"packages/superloop-lane/src/door/concurrent_tests.rs:std :: env :: current_exe () . expect (\"concurrency test executable\")#1","caller":"superloop-lane","owner":"SUPERLOOPLANE","selector":"std :: env :: current_exe () . expect (\"concurrency test executable\")","callee":"fixture:superloop-lane:self","lookup":"test-executable","binding":"current_exe","contract":"Run separate production-handler processes to verify shared admission, root refusal, independent boxes, journal evidence and the allow-agent publication window"}
{"kind":"call","site":"packages/superloop/src/command/agent.rs:\"/usr/bin/python3\"#1","caller":"superloop","owner":"SUPERLOOP","selector":"\"/usr/bin/python3\"","callee":"external:python3","lookup":"public-command","contract":"Run the shared bounded door profile under the authenticated loop identity with retained cleanup ownership"}
{"kind":"data","identity":"direct-command-policy-snapshot","writer":"superloop-lane","readers":["superloop"],"format_authority":"packages/superloop-lane/README.md","format_contract":"Schema-one owner-held loop-group snapshot in policy/snapshot.json; source revisions and digests select policy independently of request text; source writers publish under the door store lock","sites":[{"path":"packages/superloop-lane/src/requests/store/snapshot.rs","anchor":"snapshot.json"},{"path":"packages/superloop/src/command/policy.rs","anchor":"snapshot.json"}],"owner":"SUPERLOOPLANE"}
{"kind":"data","identity":"direct-command-journal","writer":"superloop","readers":["superloop"],"format_authority":"packages/superloop/README.md","format_contract":"Schema-one command requests, answers, single-use claims and outcomes in the loop-owned direct tier, bound to the snapshot digest used for judgement; owner-side readers do not open the journal","sites":[{"path":"packages/superloop/src/command/store.rs","anchor":"command-requests.jsonl"}],"owner":"SUPERLOOP"}
''']
ledger_configuration.set('ROWS', '\n'.join(dependency_ledger))
configure_file(
  input: 'packages/build-sync/dependency-ledger.jsonl.in',
  output: 'dependency-ledger.jsonl',
  configuration: ledger_configuration,
)

test('release-dependency-census', pkg_build_sync_sync_build_sync[0], args: ['census', '--root', meson.project_source_root(), '--ledger', meson.project_build_root() / 'dependency-ledger.jsonl', '--report', meson.project_build_root() / 'dependency-census.json'], depends: pkg_build_sync_sync_build_sync, suite: 'release', timeout: 120)

test('release-pack-consumer', python, args: [files('packages/superloop-pack/tests/consumer.py'), '--root', meson.project_source_root(), '--pack', pkg_superloop_pack_sync_public_pack[0], '--linter', pkg_superloop_lint_sync_linter[0], '--cargo', cargo.full_path()], depends: [pkg_superloop_pack_sync_public_pack, pkg_superloop_lint_sync_linter], suite: 'release', timeout: 180)

test('cut-tree-acceptance', python,
  args: [files('packages/superloop-pack/tests/cut_acceptance.py'), '--root', meson.project_source_root(), '--pack', pkg_superloop_pack_sync_public_pack[0], '--linter', pkg_superloop_lint_sync_linter[0]],
  depends: [pkg_superloop_pack_sync_public_pack, pkg_superloop_lint_sync_linter],
  suite: 'slow', timeout: 1805, is_parallel: false)
