//! Bound sources are inspected privately; boxed access probes run from the host launcher.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::plan::Plan;

const CANARY: &str = r"
import errno, json, os, shutil, socket, stat, subprocess, tempfile, sys, time
request = json.loads(sys.argv[1])
results = {}
for row in request['rows']:
    target = row['target']
    result = {'accessible': False, 'operation': row['operation']}
    try:
        if row['operation'] == 'connect':
            channel = socket.socket(socket.AF_UNIX)
            channel.settimeout(2)
            try:
                channel.connect(target)
            finally:
                channel.close()
        else:
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if row['operation'] == 'traverse':
                flags |= os.O_DIRECTORY
            descriptor = os.open(target, flags)
            try:
                kind = os.fstat(descriptor).st_mode
                if row['operation'] == 'traverse':
                    if not stat.S_ISDIR(kind):
                        raise OSError(errno.EINVAL, 'wrong-type')
                    os.listdir(descriptor)
                else:
                    if not stat.S_ISREG(kind):
                        raise OSError(errno.EINVAL, 'wrong-type')
                    os.read(descriptor, 64)
                    result['read_performed'] = True
            finally:
                os.close(descriptor)
        result['accessible'] = True
    except OSError as error:
        result['error'] = error.errno
        result['error_kind'] = errno.errorcode.get(error.errno, 'UNKNOWN')
    try:
        info = os.stat(target, follow_symlinks=False)
        result['uid'] = info.st_uid
        result['gid'] = info.st_gid
        result['mode'] = format(stat.S_IMODE(info.st_mode), '04o')
    except OSError as error:
        result['metadata_error'] = errno.errorcode.get(error.errno, 'UNKNOWN')
    results[row['name']] = result
if request['role'] == 'worker' and request['full']:
    guard = '/home/worker/.local/inbox/.matrix-guard'
    renamed = guard + '.renamed'
    protected = {}
    def check_guard(label):
        try:
            info = os.stat(guard, follow_symlinks=False)
            protected[label + '_guard_exists'] = stat.S_ISREG(info.st_mode)
            protected[label + '_guard_uid'] = info.st_uid
            protected[label + '_guard_gid'] = info.st_gid
            protected[label + '_guard_mode'] = format(stat.S_IMODE(info.st_mode), '04o')
            if not stat.S_ISREG(info.st_mode):
                protected[label + '_error_kind'] = 'wrong-type'
            return stat.S_ISREG(info.st_mode)
        except OSError as error:
            protected[label + '_guard_exists'] = False
            protected[label + '_error_kind'] = errno.errorcode.get(error.errno, 'UNKNOWN')
            return False
    if check_guard('rename'):
        try:
            os.rename(guard, renamed)
            protected['rename_denied'] = False
            os.rename(renamed, guard)
        except OSError as error:
            protected['rename_denied'] = True
            protected['rename_error_kind'] = errno.errorcode.get(error.errno, 'UNKNOWN')
    if check_guard('unlink'):
        try:
            os.unlink(guard)
            protected['unlink_denied'] = False
        except OSError as error:
            protected['unlink_denied'] = True
            protected['unlink_error_kind'] = errno.errorcode.get(error.errno, 'UNKNOWN')
    results['inbox_protection'] = protected
if request['role'] in ('worker', 'git-test') and request['full']:
    scratch = request.get('scratch', '/home/worker/.cache/work')
    begun = time.monotonic()
    site = None
    record = {'ordinary_git_directory': False, 'add_remove': False, 'steps_performed': [], 'effective_uid': os.geteuid(), 'effective_gid': os.getegid(), 'home': None, 'site': None}
    def tail(data):
        if isinstance(data, str):
            data = data.encode('utf-8', 'replace')
        return (data or b'')[-384:].decode('utf-8', 'replace').encode('utf-8')[-384:].decode('utf-8', 'ignore')
    try:
        site = tempfile.mkdtemp(prefix='matrix-', dir=scratch)
        record['home'] = site
        site_info = os.stat(site, follow_symlinks=False)
        record['site'] = {'path': site, 'uid': site_info.st_uid, 'gid': site_info.st_gid, 'mode': format(stat.S_IMODE(site_info.st_mode), '04o')}
        main = os.path.join(site, 'main')
        branch = os.path.join(site, 'branch')
        global_config = os.path.join(site, 'global.gitconfig')
        os.mkdir(main)
        with open(global_config, 'x', encoding='utf-8'):
            pass
        environment = {'PATH': '/usr/bin:/bin', 'HOME': site, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': global_config, 'GIT_TERMINAL_PROMPT': '0', 'GIT_PAGER': '', 'PAGER': '', 'GIT_EDITOR': '/usr/bin/true', 'GIT_SEQUENCE_EDITOR': '/usr/bin/true', 'LC_ALL': 'C'}
        record['home'] = environment['HOME']
        prefix = [request.get('git_program', '/usr/bin/git'), '--no-pager', '-c', 'safe.directory=' + site, '-c', 'safe.directory=' + main, '-c', 'safe.directory=' + branch, '-c', 'user.name=worker', '-c', 'user.email=worker@example.invalid']
        steps = [('init', ['init', '-q']), ('commit', ['commit', '-q', '--allow-empty', '-m', 'canary']), ('worktree-add', ['worktree', 'add', '-q', '--detach', branch]), ('worktree-remove', ['worktree', 'remove', '--force', branch])]
        for name, args in steps:
            argv = prefix + args
            step_begun = time.monotonic()
            try:
                completed = subprocess.run(argv, cwd=main, env=environment, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
                step = {'name': name, 'argv': argv, 'exit_status': completed.returncode, 'wall_seconds': time.monotonic() - step_begun}
                if completed.returncode != 0:
                    step['stderr_tail'] = tail(completed.stderr)
                    step['error_kind'] = 'exit-status'
                    record['failed_step'] = step
                    break
                record['steps_performed'].append(step)
            except subprocess.TimeoutExpired as error:
                record['failed_step'] = {'name': name, 'argv': argv, 'exit_status': None, 'wall_seconds': time.monotonic() - step_begun, 'stderr_tail': tail(error.stderr), 'error_kind': 'timeout'}
                break
            except OSError as error:
                record['failed_step'] = {'name': name, 'argv': argv, 'exit_status': None, 'wall_seconds': time.monotonic() - step_begun, 'stderr_tail': None, 'error_kind': errno.errorcode.get(error.errno, 'spawn-error'), 'local_diagnostic': tail(str(error))}
                break
        record['ordinary_git_directory'] = os.path.isdir(os.path.join(main, '.git'))
        if 'failed_step' not in record:
            record['add_remove'] = not os.path.exists(branch)
            if not record['ordinary_git_directory'] or not record['add_remove']:
                record['failed_step'] = {'name': 'verify-worktree', 'argv': [], 'exit_status': None, 'wall_seconds': 0, 'stderr_tail': None, 'error_kind': 'verification', 'local_diagnostic': 'Git directory or worktree state differed'}
    except OSError as error:
        record['failed_step'] = {'name': 'site-setup', 'argv': [], 'exit_status': None, 'wall_seconds': time.monotonic() - begun, 'stderr_tail': None, 'error_kind': errno.errorcode.get(error.errno, 'site-error'), 'local_diagnostic': tail(str(error))}
    finally:
        if site is not None:
            try:
                shutil.rmtree(site)
            except OSError as error:
                record['add_remove'] = False
                record['cleanup_error_kind'] = 'cleanup'
                record['cleanup_local_diagnostic'] = tail(str(error))
                if 'failed_step' not in record:
                    record['failed_step'] = {'name': 'site-cleanup', 'argv': [], 'exit_status': None, 'wall_seconds': time.monotonic() - begun, 'stderr_tail': None, 'error_kind': 'cleanup', 'local_diagnostic': record['cleanup_local_diagnostic']}
        record['wall_seconds'] = time.monotonic() - begun
        results['git_worktree'] = record
print(json.dumps(results, sort_keys=True))
";

fn source_for(plan: &Plan, target: &str) -> Result<(PathBuf, String), LaneError> {
    let mounts = plan.document["mounts"]
        .as_array()
        .ok_or_else(|| LaneError::input("bound-source", "mount table is absent"))?;
    let selected = mounts
        .iter()
        .filter_map(|mount| {
            let mount_target = mount["target"].as_str()?;
            let suffix = target.strip_prefix(mount_target)?;
            if !suffix.is_empty() && !suffix.starts_with('/') {
                return None;
            }
            (mount["kind"] == "bind").then_some((mount_target.len(), mount, suffix))
        })
        .max_by_key(|(length, _, _)| *length)
        .ok_or_else(|| LaneError::input("bound-source", format!("{target} has no bind")))?;
    let source = selected.1["source"]
        .as_str()
        .ok_or_else(|| LaneError::input("bound-source", "bind source is absent"))?;
    let access = selected.1["access"]
        .as_str()
        .ok_or_else(|| LaneError::input("bound-source", "bind access is absent"))?;
    let source = if selected.2.is_empty() {
        PathBuf::from(source)
    } else {
        Path::new(source).join(selected.2.trim_start_matches('/'))
    };
    Ok((source, access.into()))
}

fn specifications(plan: &Plan) -> Vec<(&'static str, String, &'static str, u32)> {
    let socket_name = plan.document["vendor_socket"]
        .as_str()
        .unwrap_or("proxy.sock");
    let mut targets = vec![
        (
            "pinned-executable",
            "/home/worker/.local/bin/codex",
            "read",
            0o550,
        ),
        (
            "pinned-companion",
            "/home/worker/.local/bin/codex-code-mode-host",
            "read",
            0o550,
        ),
        (
            "helper-directory",
            "/home/worker/.local/libexec/superloop",
            "traverse",
            0o550,
        ),
        (
            "helper-box-init",
            "/home/worker/.local/libexec/superloop/box-init",
            "read",
            0o440,
        ),
        (
            "charter-overlay",
            "/home/worker/.codex/AGENTS.md",
            "read",
            0o440,
        ),
        (
            "policy-overlay",
            "/home/worker/.codex/config.toml",
            "read",
            0o440,
        ),
        ("inbox", "/home/worker/.local/inbox", "traverse", 0o750),
        ("outbox", "/home/worker/.local/outbox", "traverse", 0o750),
        (
            "letter",
            "/home/worker/.local/inbox/dispatch.md",
            "read",
            0o640,
        ),
        (
            "vendor-directory",
            "/home/worker/.local/vendor",
            "traverse",
            0o750,
        ),
    ];
    targets.push((
        "vendor-socket",
        "/home/worker/.local/vendor/SOCKET",
        "connect",
        0o660,
    ));
    if plan.document["door"].is_object() {
        targets.push((
            "door-directory",
            "/home/worker/.local/door",
            "traverse",
            0o750,
        ));
        targets.push((
            "door-socket",
            "/home/worker/.local/door/capability.sock",
            "connect",
            0o660,
        ));
    }
    targets
        .into_iter()
        .map(|(name, target, operation, mode)| {
            (
                name,
                if name == "vendor-socket" {
                    format!("/home/worker/.local/vendor/{socket_name}")
                } else {
                    target.to_owned()
                },
                operation,
                mode,
            )
        })
        .collect()
}

fn door_row() -> Value {
    json!({"name":"door-socket","target":"/home/worker/.local/door","state":"not-applicable","reason":"door bind is not installed in this launch mode"})
}

const OBSERVING_SOCKET_REASON: &str = "per-run observing socket is created by the observer after preparation; would probe after observer starts";

fn observing(plan: &Plan) -> bool {
    plan.document["vendor_mode"].is_string()
}

/// Preview source rows from the pinned plan without opening an uncreated home.
///
/// # Errors
///
/// Refuses a plan without its bound source or owner declaration.
pub(super) fn preview(plan: &Plan) -> Result<Value, LaneError> {
    let owner_uid = plan.document["paths"][0]["uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("bound-source", "owner UID is absent"))?;
    let group_gid = u64::from(crate::plan::loop_uid(&plan.document)?);
    let mut rows = Vec::new();
    for (name, target, operation, mode) in specifications(plan) {
        let (source, bind) = source_for(plan, &target)?;
        let expected_uid = if name == "outbox" {
            plan.document["worker_uid"]
                .as_u64()
                .ok_or_else(|| LaneError::input("bound-source", "worker UID is absent"))?
        } else {
            owner_uid
        };
        let mut row = json!({"name":name,"source":source,"target":target,"operation":operation,"owner_uid":expected_uid,"group_gid":group_gid,"mode":format!("{mode:04o}"),"bind":bind,"state":"would-probe"});
        if name == "vendor-socket" && observing(plan) {
            row["state"] = json!("deferred");
            row["reason"] = json!(OBSERVING_SOCKET_REASON);
        }
        rows.push(row);
    }
    if !plan.document["door"].is_object() {
        rows.push(door_row());
    }
    Ok(
        json!({"rows":rows,"worker":"read, traverse or connect from the selected worker UID","sibling":"permission denial without the loop group","inbox":"guard owner and mode are measured; rename and unlink require EROFS under a read-only bind or EACCES/EPERM from the guard","git_worktree":"ordinary .git, worktree add and remove in worker scratch"}),
    )
}

fn matrix_rows(plan: &Plan) -> Result<Vec<Value>, LaneError> {
    let mut rows = Vec::new();
    for (name, target, operation, mode) in specifications(plan) {
        if name == "vendor-socket" && observing(plan) {
            let mut row = preview(plan)?["rows"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["name"] == name))
                .cloned()
                .ok_or_else(|| {
                    LaneError::input("bound-source", "vendor-socket preview is absent")
                })?;
            row["state"] = json!("deferred");
            rows.push(row);
        } else {
            rows.push(bound_row(plan, name, &target, operation, mode)?);
        }
    }
    if !plan.document["door"].is_object() {
        rows.push(door_row());
    }
    Ok(rows)
}

fn bound_row(
    plan: &Plan,
    name: &str,
    target: &str,
    operation: &str,
    mode: u32,
) -> Result<Value, LaneError> {
    let (source, bind) = source_for(plan, target)?;
    let meta = fs::symlink_metadata(&source).map_err(|error| {
        LaneError::input(
            "bound-source",
            format!("{name}: source metadata unavailable ({:?})", error.kind()),
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(LaneError::input(
            "bound-source",
            format!("{} is a link", source.display()),
        ));
    }
    let expected_type = match operation {
        "read" => meta.file_type().is_file(),
        "traverse" => meta.file_type().is_dir(),
        "connect" => meta.file_type().is_socket(),
        _ => false,
    };
    if !expected_type {
        return Err(LaneError::input(
            "bound-source",
            format!("{name}: source has wrong type for {operation}"),
        ));
    }
    let owner_uid = plan.document["paths"][0]["uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("bound-source", "owner UID is absent"))?;
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let expected_uid = if name == "outbox" {
        plan.document["worker_uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .ok_or_else(|| LaneError::input("bound-source", "worker UID is absent"))?
    } else {
        owner_uid
    };
    if meta.uid() != expected_uid
        || meta.gid() != loop_uid
        || meta.permissions().mode() & 0o7777 != mode
    {
        return Err(LaneError::input(
            "bound-source",
            format!(
                "{} differs from owner {expected_uid}, loop group {loop_uid}, mode {mode:04o}",
                source.display()
            ),
        ));
    }
    Ok(
        json!({"name":name,"source":source,"target":target,"operation":operation,"owner_uid":meta.uid(),"group_gid":meta.gid(),"mode":format!("{:04o}",meta.permissions().mode() & 0o7777),"bind":bind,"state":"pending"}),
    )
}

fn canary_vector(
    plan: &Plan,
    rows: &[Value],
    role: &str,
    sibling: u32,
    full: bool,
) -> Result<Vec<String>, LaneError> {
    let mut vector = plan.document["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("bound-source", "runtime vector is absent"))?
        .iter()
        .map(|word| {
            word.as_str()
                .map(str::to_owned)
                .ok_or_else(|| LaneError::input("bound-source", "runtime word is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let image = plan.document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("bound-source", "image digest is absent"))?;
    let image_index = vector
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("bound-source", "runtime image is absent"))?;
    if vector.get(1).is_none_or(|word| word != "run")
        || !vector[..image_index]
            .iter()
            .any(|word| word == "--userns=host")
    {
        return Err(LaneError::input(
            "bound-source",
            "rootless run mapping is absent",
        ));
    }
    vector.truncate(image_index + 1);
    vector.retain(|word| !word.starts_with("--cidfile="));
    let name = vector
        .iter_mut()
        .find(|word| word.starts_with("--name="))
        .ok_or_else(|| LaneError::input("bound-source", "container name is absent"))?;
    write!(name, "-matrix-{role}")
        .map_err(|error| LaneError::operation("bound-source", error.to_string()))?;
    if role == "sibling" {
        vector.retain(|word| !word.starts_with("--group-add="));
        let user = vector
            .iter_mut()
            .find(|word| word.starts_with("--user="))
            .ok_or_else(|| LaneError::input("bound-source", "container user is absent"))?;
        *user = format!("--user={sibling}:{sibling}");
        let workdir = vector
            .iter()
            .position(|word| word == "--workdir")
            .ok_or_else(|| LaneError::input("bound-source", "workdir is absent"))?;
        vector[workdir + 1] = "/tmp".into();
    }
    let image_index = vector
        .iter()
        .position(|word| word == image)
        .ok_or_else(|| LaneError::input("bound-source", "runtime image moved"))?;
    vector.insert(image_index, "--rm".into());
    let request = json!({"role":role,"rows":rows,"full":full});
    vector.extend([
        "/usr/bin/python3".into(),
        "-c".into(),
        CANARY.into(),
        request.to_string(),
    ]);
    Ok(vector)
}

fn evaluate_rows(rows: &mut [Value], worker: &Value, sibling: &Value) -> Result<(), LaneError> {
    let mut first_refusal = None;
    for row in rows.iter_mut() {
        if row["state"] == "not-applicable" || row["state"] == "deferred" {
            continue;
        }
        let name = row["name"]
            .as_str()
            .ok_or_else(|| LaneError::input("bound-source", "row name absent"))?
            .to_owned();
        let works = worker[&name]["accessible"] == true
            && (row["operation"] != "read" || worker[&name]["read_performed"] == true);
        let sibling_kind = sibling[&name]["error_kind"]
            .as_str()
            .unwrap_or("missing-result");
        let denied =
            sibling[&name]["accessible"] == false && matches!(sibling_kind, "EACCES" | "EPERM");
        let identity_matches = worker[&name]["uid"] == row["owner_uid"]
            && worker[&name]["gid"] == row["group_gid"]
            && worker[&name]["mode"] == row["mode"];
        row["worker"] = worker[&name].clone();
        row["sibling"] = sibling[&name].clone();
        row["state"] = json!(if works && denied && identity_matches {
            "passed"
        } else {
            "failed"
        });
        let refusal = if !works {
            let kind = worker[&name]["error_kind"]
                .as_str()
                .unwrap_or("missing-result");
            Some(LaneError::input(
                "bound-source",
                format!("{name}: worker probe unavailable ({kind})"),
            ))
        } else if !identity_matches {
            Some(LaneError::input(
                "bound-source",
                format!("{name}: bound identity differs from source"),
            ))
        } else if !denied {
            Some(LaneError::input(
                "bound-source",
                format!("{name}: sibling probe did not prove permission denial ({sibling_kind})"),
            ))
        } else {
            None
        };
        if first_refusal.is_none() {
            first_refusal = refusal;
        }
    }
    first_refusal.map_or(Ok(()), Err)
}

fn evaluate(rows: &mut [Value], worker: &Value, sibling: &Value) -> (Value, Option<LaneError>) {
    let mut first_refusal = evaluate_rows(rows, worker, sibling).err();
    let inbox_index = rows.iter().position(|row| row["name"] == "inbox");
    let bind = inbox_index
        .and_then(|index| rows[index]["bind"].as_str())
        .unwrap_or("missing-bind");
    let owner_uid = inbox_index.map(|index| rows[index]["owner_uid"].clone());
    let mut protection = worker["inbox_protection"].clone();
    let mut guard_failed = false;
    for action in ["rename", "unlink"] {
        let guard_exists = format!("{action}_guard_exists");
        let denied = format!("{action}_denied");
        let error_kind = format!("{action}_error_kind");
        let guard_uid = format!("{action}_guard_uid");
        let guard_mode = format!("{action}_guard_mode");
        let kind = protection[&error_kind]
            .as_str()
            .unwrap_or("missing-result")
            .to_owned();
        let denied_by = match (bind, kind.as_str()) {
            ("ro", "EROFS") => Some("read-only-mount"),
            ("ro" | "rw", "EACCES" | "EPERM") => Some("guard"),
            _ => None,
        };
        let metadata_matches = protection[&guard_exists] == true
            && owner_uid
                .as_ref()
                .is_some_and(|uid| protection[&guard_uid] == *uid)
            && protection[&guard_mode] == "0640";
        protection[format!("{action}_denied_by")] = denied_by.map_or(Value::Null, |by| json!(by));
        if !metadata_matches || protection[&denied] != true || denied_by.is_none() {
            guard_failed = true;
            if first_refusal.is_none() {
                first_refusal = Some(LaneError::input(
                    "bound-source",
                    format!("inbox-guard {action}: permission denial unavailable ({kind})"),
                ));
            }
        }
    }
    protection["denied_by"] = if protection["rename_denied_by"] == protection["unlink_denied_by"] {
        protection["rename_denied_by"].clone()
    } else {
        json!("mixed")
    };
    if let Some(index) = inbox_index {
        rows[index]["inbox_protection"] = protection.clone();
        if guard_failed {
            rows[index]["state"] = json!("failed");
        }
    }
    if (worker["git_worktree"]["ordinary_git_directory"] != true
        || worker["git_worktree"]["add_remove"] != true)
        && first_refusal.is_none()
    {
        first_refusal = Some(LaneError::input(
            "git-worktree",
            "ordinary Git directory or worktree canary failed",
        ));
    }
    (
        json!({"rows":rows,"inbox_protection":protection,"git_worktree":worker["git_worktree"],"worker_view":"boxed runtime","sibling_view":"boxed runtime without loop group"}),
        first_refusal,
    )
}

/// Inspect sources and leave pending rows for host-launched access probes.
///
/// # Errors
///
/// Refuses a missing or incorrectly owned source or an unavailable inbox guard.
pub(super) fn prepare(plan: &Plan) -> Result<Value, LaneError> {
    let worker = plan.document["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("bound-source", "worker UID is absent"))?;
    let sibling = if worker == 3000 { 3001 } else { 3000 };
    if sibling == worker {
        return Err(LaneError::input(
            "bound-source",
            "sibling UID equals worker UID",
        ));
    }
    let guard = plan.home.join(".local/inbox/.matrix-guard");
    let _guard = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&guard)
        .map_err(|error| {
            LaneError::operation("bound-source", format!("{}: {error}", guard.display()))
        })?;
    Ok(json!({"rows":matrix_rows(plan)?,"state":"pending"}))
}

/// Inspect the observing socket after the observer makes it ready.
///
/// # Errors
///
/// Refuses a missing socket or one with an unexpected owner, type or mode.
pub(super) fn prepare_deferred(plan: &Plan) -> Result<Value, LaneError> {
    if !observing(plan) {
        return Err(LaneError::input(
            "bound-source",
            "vendor-socket: no observing row",
        ));
    }
    let (name, target, operation, mode) = specifications(plan)
        .into_iter()
        .find(|(name, _, _, _)| *name == "vendor-socket")
        .ok_or_else(|| LaneError::input("bound-source", "vendor-socket: row absent"))?;
    bound_row(plan, name, &target, operation, mode)
}

/// Publish the socket's source identity after the observer creates it.
///
/// # Errors
///
/// Refuses evidence without exactly one deferred vendor socket row.
pub(super) fn publish_prepared_deferred(
    owner_home: &Path,
    path: &Path,
    owner_uid: u32,
    row: &Value,
) -> Result<(), LaneError> {
    let bytes = crate::pinned::read_private(owner_home, path, owner_uid, 0o600, 262_144)?;
    let mut evidence: Value = serde_json::from_slice(&bytes).map_err(|error| {
        LaneError::input(
            "bound-source",
            format!("vendor-socket: evidence invalid ({error})"),
        )
    })?;
    let matrix = &mut evidence["bound_source_matrix"];
    if row["name"] != "vendor-socket"
        || row["state"] != "pending"
        || !matrix["deferred_source_row"].is_null()
        || matrix["state"] != "measured"
        || matrix["rows"].as_array().is_none_or(|rows| {
            rows.iter()
                .filter(|entry| entry["name"] == "vendor-socket" && entry["state"] == "deferred")
                .count()
                != 1
        })
    {
        return Err(LaneError::input(
            "bound-source",
            "vendor-socket: deferred evidence absent",
        ));
    }
    matrix["deferred_source_row"] = row.clone();
    let bytes = serde_json::to_vec(&evidence)
        .map_err(|error| LaneError::operation("bound-source", error.to_string()))?;
    build::publish(path, &bytes)
}

fn handoff_path(evidence_path: &Path, deferred: bool) -> Result<PathBuf, LaneError> {
    let parent = evidence_path
        .parent()
        .ok_or_else(|| LaneError::input("bound-source", "protected evidence has no parent"))?;
    Ok(parent.join(if deferred {
        "matrix-deferred-results.json"
    } else {
        "matrix-primary-results.json"
    }))
}

/// Run the prepared vector from the launcher's rootless host identity.
///
/// # Errors
///
/// Refuses a differing prepared plan or an unavailable boxed result.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn probe_on_host(
    plan: &Plan,
    reservation: &Path,
    owner_home: &Path,
    evidence_path: &Path,
    owner_uid: u32,
    podman: &Path,
    environment: &BTreeMap<String, String>,
    deferred: bool,
) -> Result<Value, LaneError> {
    let bytes = crate::pinned::read_private(owner_home, evidence_path, owner_uid, 0o600, 262_144)?;
    let evidence: Value = serde_json::from_slice(&bytes).map_err(|error| {
        LaneError::input(
            "bound-source",
            format!("prepared evidence invalid ({error})"),
        )
    })?;
    if evidence["runtime_argv"] != plan.document["runtime_argv"] {
        return Err(LaneError::input(
            "bound-source",
            "prepared runtime vector differs from plan",
        ));
    }
    let rows = if deferred {
        let row = &evidence["bound_source_matrix"]["deferred_source_row"];
        if evidence["bound_source_matrix"]["rows"]
            .as_array()
            .is_none_or(|rows| {
                !rows
                    .iter()
                    .any(|entry| entry["name"] == "vendor-socket" && entry["state"] == "deferred")
            })
            || row["name"] != "vendor-socket"
            || row["state"] != "pending"
        {
            return Err(LaneError::input(
                "bound-source",
                "vendor-socket: prepared row is absent",
            ));
        }
        vec![row.clone()]
    } else {
        if evidence["bound_source_matrix"]["state"] != "pending" {
            return Err(LaneError::input(
                "bound-source",
                "primary prepared rows are absent",
            ));
        }
        evidence["bound_source_matrix"]["rows"]
            .as_array()
            .ok_or_else(|| LaneError::input("bound-source", "primary rows are absent"))?
            .iter()
            .filter(|row| row["state"] == "pending")
            .cloned()
            .collect::<Vec<_>>()
    };
    if rows.is_empty() {
        return Err(LaneError::input(
            "bound-source",
            "prepared probe rows are empty",
        ));
    }
    let worker = plan.document["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("bound-source", "worker UID is absent"))?;
    let sibling = if worker == 3000 { 3001 } else { 3000 };
    let started = Instant::now();
    let phase = if deferred { "deferred" } else { "primary" };
    let mut results = Vec::new();
    for role in ["worker", "sibling"] {
        let vector = canary_vector(plan, &rows, role, sibling, !deferred)?;
        if vector
            .first()
            .is_none_or(|word| word != podman.to_string_lossy().as_ref())
        {
            return Err(LaneError::input(
                "bound-source",
                "probe program differs from plan",
            ));
        }
        let name = vector
            .iter()
            .find_map(|word| word.strip_prefix("--name="))
            .ok_or_else(|| LaneError::input("bound-source", "probe container name is absent"))?;
        super::record_probe_start(reservation, phase, role, name)?;
        let output = build::run_checked_with_pid(
            podman,
            vector[1..].to_vec(),
            environment,
            owner_home,
            if deferred { 20 } else { 60 },
            "bound-source",
            &mut build::ChildEnd::default(),
            |pid| super::record_probe_process(reservation, phase, role, pid),
        )
        .map_err(|error| {
            LaneError::operation(
                "bound-source",
                format!("{role} probe unavailable: {}", error.line()),
            )
        })?;
        super::record_probe_end(reservation, phase, role)?;
        results.push(
            serde_json::from_str::<Value>(output.trim()).map_err(|error| {
                LaneError::input(
                    "bound-source",
                    format!("{role} probe output invalid ({error})"),
                )
            })?,
        );
    }
    let handoff = json!({"phase":if deferred {"deferred"} else {"primary"},"rows":rows,"runtime_argv":plan.document["runtime_argv"],"worker":results[0],"sibling":results[1],"probe_wall_seconds":started.elapsed().as_secs_f64()});
    let bytes = serde_json::to_vec(&handoff)
        .map_err(|error| LaneError::operation("bound-source", error.to_string()))?;
    build::publish(&handoff_path(evidence_path, deferred)?, &bytes)?;
    Ok(
        json!({"phase":handoff["phase"],"state":"probed","probe_wall_seconds":handoff["probe_wall_seconds"]}),
    )
}

/// Evaluate host probe results inside owner-protected custody and replace pending rows.
///
/// # Errors
///
/// Refuses missing, malformed, stale or unsuccessful probe results.
// The pinned handoff check and both phase rewrites precede one protected publication.
#[allow(clippy::too_many_lines)]
pub(super) fn publish_results(
    plan: &Plan,
    owner_home: &Path,
    evidence_path: &Path,
    owner_uid: u32,
    deferred: bool,
) -> Result<Value, LaneError> {
    let bytes = crate::pinned::read_private(owner_home, evidence_path, owner_uid, 0o600, 262_144)?;
    let mut evidence: Value = serde_json::from_slice(&bytes).map_err(|error| {
        LaneError::input(
            "bound-source",
            format!("prepared evidence invalid ({error})"),
        )
    })?;
    let handoff = handoff_path(evidence_path, deferred)?;
    let bytes = crate::pinned::read_private(owner_home, &handoff, owner_uid, 0o600, 262_144)
        .map_err(|error| {
            LaneError::input(
                "bound-source",
                format!("probe result unavailable: {}", error.line()),
            )
        })?;
    let results: Value = serde_json::from_slice(&bytes).map_err(|error| {
        LaneError::input("bound-source", format!("probe result malformed ({error})"))
    })?;
    let phase = if deferred { "deferred" } else { "primary" };
    if results["phase"] != phase
        || results["runtime_argv"] != plan.document["runtime_argv"]
        || evidence["runtime_argv"] != plan.document["runtime_argv"]
        || !results["worker"].is_object()
        || !results["sibling"].is_object()
        || !results["probe_wall_seconds"].is_number()
    {
        return Err(LaneError::input(
            "bound-source",
            format!("{phase}: probe result differs from prepared plan"),
        ));
    }
    let matrix = &mut evidence["bound_source_matrix"];
    let refusal = if deferred {
        let row = &matrix["deferred_source_row"];
        if row["name"] != "vendor-socket"
            || row["state"] != "pending"
            || results["rows"] != json!([row])
        {
            return Err(LaneError::input(
                "bound-source",
                "vendor-socket: prepared row differs from result",
            ));
        }
        let mut rows = vec![row.clone()];
        let refusal = evaluate_rows(&mut rows, &results["worker"], &results["sibling"]).err();
        let mut measured = rows.remove(0);
        measured["probe_wall_seconds"] = results["probe_wall_seconds"].clone();
        let entries = matrix["rows"].as_array_mut().ok_or_else(|| {
            LaneError::input("bound-source", "vendor-socket: evidence rows absent")
        })?;
        let deferred_rows = entries
            .iter_mut()
            .filter(|entry| entry["name"] == "vendor-socket" && entry["state"] == "deferred")
            .collect::<Vec<_>>();
        if deferred_rows.len() != 1 {
            return Err(LaneError::input(
                "bound-source",
                "vendor-socket: deferred evidence absent",
            ));
        }
        *deferred_rows.into_iter().next().ok_or_else(|| {
            LaneError::input("bound-source", "vendor-socket: deferred evidence absent")
        })? = measured;
        matrix["deferred_source_row"] = Value::Null;
        matrix["deferred_probe_wall_seconds"] = results["probe_wall_seconds"].clone();
        if refusal.is_some() {
            matrix["state"] = json!("failed");
        }
        refusal
    } else {
        if matrix["state"] != "pending" {
            return Err(LaneError::input(
                "bound-source",
                "primary prepared rows are absent",
            ));
        }
        let mut rows = matrix["rows"]
            .as_array()
            .ok_or_else(|| LaneError::input("bound-source", "primary rows are absent"))?
            .clone();
        let active = rows
            .iter()
            .filter(|row| row["state"] == "pending")
            .cloned()
            .collect::<Vec<_>>();
        if results["rows"] != json!(active) {
            return Err(LaneError::input(
                "bound-source",
                "primary prepared rows differ from result",
            ));
        }
        let (evaluated, refusal) = evaluate(&mut rows, &results["worker"], &results["sibling"]);
        *matrix = evaluated;
        matrix["state"] = json!(if refusal.is_some() {
            "failed"
        } else {
            "measured"
        });
        matrix["probe_wall_seconds"] = results["probe_wall_seconds"].clone();
        refusal
    };
    let bytes = serde_json::to_vec(&evidence)
        .map_err(|error| LaneError::operation("bound-source", error.to_string()))?;
    build::publish(evidence_path, &bytes)?;
    if let Some(error) = refusal {
        return Err(error);
    }
    Ok(json!({"phase":phase,"state":"measured","probe_wall_seconds":results["probe_wall_seconds"]}))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use serde_json::{Value, json};

    use super::{
        bound_row, canary_vector, evaluate, evaluate_rows, preview, publish_prepared_deferred,
        publish_results,
    };
    use crate::plan::Plan;

    fn isolated_git_canary(name: &str) -> bool {
        if std::env::var_os("SUPERLOOP_ISOLATED_GIT_CANARY").is_some() {
            return false;
        }
        let output = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", name, "--test-threads=1"])
            .env("SUPERLOOP_ISOLATED_GIT_CANARY", "1")
            .output()
            .expect("isolated git canary test process");
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    fn git_canary(scratch: &Path, git_program: &Path) -> Value {
        let request = json!({"role":"git-test","rows":[],"full":true,"scratch":scratch,"git_program":git_program});
        let output = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(super::CANARY)
            .arg(request.to_string())
            .env("PATH", "/absent/parent-bin")
            .env("HOME", "/absent/parent-home")
            .env("GIT_CONFIG_NOSYSTEM", "0")
            .env("GIT_CONFIG_GLOBAL", "/absent/parent-config")
            .env("GIT_CONFIG_COUNT", "4")
            .env("GIT_TERMINAL_PROMPT", "1")
            .output()
            .expect("boxed canary fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("canary result")
    }

    /// ´test:unit:git-canary-records-failing-step-and-hermetic-invocation´
    #[test]
    fn git_canary_records_failing_step_and_hermetic_invocation() {
        if isolated_git_canary(
            "launch::matrix::tests::git_canary_records_failing_step_and_hermetic_invocation",
        ) {
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let bin = fixture.path().join("bin");
        fs::create_dir(&bin).expect("fixture executable directory");
        let git = bin.join("git");
        crate::fixture_exec::write_executable(&git, r#"#!/bin/sh
printf '%s\n' "$HOME" "$GIT_CONFIG_NOSYSTEM" "$GIT_CONFIG_GLOBAL" "$GIT_TERMINAL_PROMPT" "$GIT_PAGER" "$GIT_EDITOR" "$GIT_CONFIG_COUNT" "$PATH" > "${0%/*}/environment"
printf '%s\n' "$@" > "${0%/*}/arguments"
test -f "$GIT_CONFIG_GLOBAL" || exit 19
test ! -s "$GIT_CONFIG_GLOBAL" || exit 20
printf '%0500d\nfixture-git-failure' 0 >&2
exit 17
"#.as_bytes()).expect("closed and synced fixture git");
        let result = git_canary(fixture.path(), &git);
        let record = &result["git_worktree"];
        let failure = &record["failed_step"];
        assert_eq!(failure["name"], "init");
        assert_eq!(failure["exit_status"], 17);
        assert!(
            failure["argv"]
                .as_array()
                .is_some_and(|words| words.iter().any(|word| word == "init"))
        );
        let tail = failure["stderr_tail"].as_str().expect("stderr tail");
        assert!(tail.len() <= 384);
        assert!(tail.ends_with("fixture-git-failure"));
        assert_eq!(
            record["effective_uid"],
            nix::unistd::Uid::effective().as_raw()
        );
        assert_eq!(
            record["effective_gid"],
            nix::unistd::Gid::effective().as_raw()
        );
        assert_eq!(record["site"]["uid"], record["effective_uid"]);
        assert_eq!(record["site"]["mode"], "0700");
        let home = record["home"].as_str().expect("step home");
        assert!(home.starts_with(fixture.path().to_str().expect("fixture path")));
        assert!(!Path::new(home).exists(), "canary site is removed");
        let invocation = fs::read_to_string(bin.join("environment")).expect("received environment");
        let lines = invocation.lines().collect::<Vec<_>>();
        assert_eq!(lines[0], home);
        assert_eq!(lines[1], "1");
        assert_eq!(lines[2], format!("{home}/global.gitconfig"));
        assert_eq!(lines[3], "0");
        assert_eq!(lines[4], "");
        assert_eq!(lines[5], "/usr/bin/true");
        assert_eq!(lines[6], "");
        assert_eq!(lines[7], "/usr/bin:/bin");
        let argv = fs::read_to_string(bin.join("arguments")).expect("received argv");
        assert!(argv.contains(&format!("safe.directory={home}/main")));
        assert!(argv.contains("user.name=worker"));
    }

    /// ´test:unit:git-canary-records-successful-steps-and-wall´
    #[test]
    fn git_canary_records_successful_steps_and_wall() {
        if isolated_git_canary(
            "launch::matrix::tests::git_canary_records_successful_steps_and_wall",
        ) {
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let result = git_canary(fixture.path(), Path::new("/usr/bin/git"));
        let record = &result["git_worktree"];
        assert_eq!(record["ordinary_git_directory"], true, "{record}");
        assert_eq!(record["add_remove"], true, "{record}");
        assert!(record["failed_step"].is_null());
        assert_eq!(record["steps_performed"].as_array().map(Vec::len), Some(4));
        assert_eq!(record["steps_performed"][0]["name"], "init");
        assert_eq!(record["steps_performed"][1]["name"], "commit");
        assert_eq!(record["steps_performed"][2]["name"], "worktree-add");
        assert_eq!(record["steps_performed"][3]["name"], "worktree-remove");
        assert!(
            record["steps_performed"]
                .as_array()
                .expect("steps")
                .iter()
                .all(|step| step["exit_status"] == 0
                    && step["wall_seconds"]
                        .as_f64()
                        .is_some_and(|wall| wall >= 0.0))
        );
        assert!(
            record["wall_seconds"]
                .as_f64()
                .is_some_and(|wall| wall > 0.0)
        );
        assert!(!Path::new(record["home"].as_str().expect("step home")).exists());
    }

    /// ´test:unit:git-canary-spawn-failure-has-no-git-stderr´
    #[test]
    fn git_canary_spawn_failure_has_no_git_stderr() {
        if isolated_git_canary("launch::matrix::tests::git_canary_spawn_failure_has_no_git_stderr")
        {
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let result = git_canary(fixture.path(), &fixture.path().join("missing-git"));
        let failure = &result["git_worktree"]["failed_step"];
        assert_eq!(failure["name"], "init");
        assert_eq!(failure["error_kind"], "ENOENT");
        assert!(failure["stderr_tail"].is_null());
        assert!(failure["local_diagnostic"].as_str().is_some());
    }

    /// ´test:unit:git-canary-setup-failure-has-no-git-stderr´
    #[test]
    fn git_canary_setup_failure_has_no_git_stderr() {
        if isolated_git_canary("launch::matrix::tests::git_canary_setup_failure_has_no_git_stderr")
        {
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let result = git_canary(
            &fixture.path().join("missing-scratch"),
            Path::new("/usr/bin/git"),
        );
        let failure = &result["git_worktree"]["failed_step"];
        assert_eq!(failure["name"], "site-setup");
        assert_eq!(failure["error_kind"], "ENOENT");
        assert!(failure["stderr_tail"].is_null());
        assert!(failure["local_diagnostic"].as_str().is_some());
    }

    /// ´test:unit:git-canary-verification-failure-has-no-git-stderr´
    #[test]
    fn git_canary_verification_failure_has_no_git_stderr() {
        if isolated_git_canary(
            "launch::matrix::tests::git_canary_verification_failure_has_no_git_stderr",
        ) {
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let git = fixture.path().join("no-op-git");
        crate::fixture_exec::write_executable(&git, b"#!/bin/sh\nexit 0\n")
            .expect("closed and synced fixture git");
        let result = git_canary(fixture.path(), &git);
        let failure = &result["git_worktree"]["failed_step"];
        assert_eq!(failure["name"], "verify-worktree");
        assert_eq!(failure["error_kind"], "verification");
        assert!(failure["stderr_tail"].is_null());
        assert!(failure["local_diagnostic"].as_str().is_some());
    }

    /// ´test:unit:git-canary-cleanup-failure-has-no-git-stderr´
    #[test]
    fn git_canary_cleanup_failure_has_no_git_stderr() {
        if isolated_git_canary(
            "launch::matrix::tests::git_canary_cleanup_failure_has_no_git_stderr",
        ) {
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let git = fixture.path().join("git-with-locked-site");
        crate::fixture_exec::write_executable(
            &git,
            r#"#!/bin/sh
/usr/bin/git "$@"
status=$?
case " $* " in
  *" worktree remove "*)
    : > "$HOME/main/held"
    chmod 0500 "$HOME/main"
    ;;
esac
exit "$status"
"#
            .as_bytes(),
        )
        .expect("closed and synced fixture git");
        let result = git_canary(fixture.path(), &git);
        let record = &result["git_worktree"];
        let home = Path::new(record["home"].as_str().expect("site path"));
        fs::set_permissions(home.join("main"), fs::Permissions::from_mode(0o700))
            .expect("restore fixture mode");
        fs::remove_dir_all(home).expect("remove fixture site");
        let failure = &record["failed_step"];
        assert_eq!(failure["name"], "site-cleanup");
        assert_eq!(failure["error_kind"], "cleanup");
        assert!(failure["stderr_tail"].is_null());
        assert!(failure["local_diagnostic"].as_str().is_some());
    }

    fn guard_probe(owner: u32, rename: &str, unlink: &str) -> serde_json::Value {
        json!({"rename_guard_exists":true,"rename_guard_uid":owner,"rename_guard_gid":41001,"rename_guard_mode":"0640","rename_denied":true,"rename_error_kind":rename,"unlink_guard_exists":true,"unlink_guard_uid":owner,"unlink_guard_gid":41001,"unlink_guard_mode":"0640","unlink_denied":true,"unlink_error_kind":unlink})
    }

    /// ´test:unit:bound-source-preview-expects-worker-owned-group-listable-outbox´
    #[test]
    fn bound_source_preview_expects_worker_owned_group_listable_outbox() {
        let mut plan = Plan {
            home: PathBuf::from("/home/owner/home-R"),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"home":"/home/owner/home-R","driver_dir":"~/runs/R","worker_uid":3000,"paths":[{"path":"/home/owner/home-R","uid":41001,"gid":41001},{"path":"~/runs/R","kind":"directory","uid":41001,"gid":41001}],"mounts":[{"kind":"bind","source":"/home/owner/home-R","target":"/home/worker","access":"ro"}]}),
        };
        let rows = preview(&plan).expect("preview")["rows"]
            .as_array()
            .expect("rows")
            .clone();
        let outbox = rows
            .iter()
            .find(|row| row["name"] == "outbox")
            .expect("outbox row");
        assert_eq!(outbox["owner_uid"], 3000);
        assert_eq!(outbox["group_gid"], 41001);
        assert_eq!(outbox["mode"], "0750");
        assert_eq!(outbox["operation"], "traverse");
        plan.document["paths"][1]["uid"] = json!(3001);
        assert_eq!(
            preview(&plan).expect_err("conflicting driver owner").kind,
            "loop-identity"
        );
    }

    /// ´test:unit:probe-vectors-use-rootless-run-and-distinct-mapped-uids´
    #[test]
    fn probe_vectors_use_rootless_run_and_distinct_mapped_uids() {
        let plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"worker_uid":3000,"image_digest":"sha256:fixture","runtime_argv":["/usr/bin/podman","run","--userns=host","--user=3000:3000","--group-add=41001","--workdir","/home/worker","--name=fixture","--cidfile=/tmp/fixture.id","sha256:fixture","ignored"]}),
        };
        let rows = vec![
            json!({"name":"letter","state":"pending","target":"/home/worker/.local/inbox/dispatch.md","operation":"read"}),
        ];
        let worker = canary_vector(&plan, &rows, "worker", 3001, true).expect("worker vector");
        let sibling = canary_vector(&plan, &rows, "sibling", 3001, true).expect("sibling vector");
        for vector in [&worker, &sibling] {
            assert_eq!(&vector[..2], ["/usr/bin/podman", "run"]);
            assert!(vector.iter().any(|word| word == "--userns=host"));
            assert!(!vector.iter().any(|word| word == "unshare"));
            assert!(!vector.iter().any(|word| word.starts_with("--cidfile=")));
        }
        assert!(worker.iter().any(|word| word == "--user=3000:3000"));
        assert!(sibling.iter().any(|word| word == "--user=3001:3001"));
        assert!(!sibling.iter().any(|word| word.starts_with("--group-add=")));
    }

    /// ´test:unit:result-handoff-rewrites-pending-evidence´
    #[test]
    fn result_handoff_rewrites_pending_evidence() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let owner = nix::unistd::Uid::effective().as_raw();
        let worker_uid = if owner == 3000 { 3001 } else { 3000 };
        assert_ne!(owner, worker_uid);
        let plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"runtime_argv":["/usr/bin/podman","run","--userns=host"],"worker_uid":worker_uid}),
        };
        let row = json!({"name":"letter","operation":"read","state":"pending","owner_uid":owner,"group_gid":owner,"mode":"0640"});
        let inbox = json!({"name":"inbox","operation":"traverse","state":"pending","owner_uid":owner,"group_gid":owner,"mode":"0750","bind":"rw"});
        let evidence_path = fixture.path().join("launch-evidence.json");
        fs::write(&evidence_path, json!({"runtime_argv":plan.document["runtime_argv"],"bound_source_matrix":{"state":"pending","rows":[row,inbox,{"name":"door-socket","state":"not-applicable"}]}}).to_string()).expect("evidence");
        fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o600))
            .expect("evidence mode");
        let handoff = json!({"phase":"primary","runtime_argv":plan.document["runtime_argv"],"rows":[row,inbox],"worker":{"letter":{"accessible":true,"read_performed":true,"uid":owner,"gid":owner,"mode":"0640"},"inbox":{"accessible":true,"uid":owner,"gid":owner,"mode":"0750"},"inbox_protection":guard_probe(owner,"EACCES","EPERM"),"git_worktree":{"ordinary_git_directory":true,"add_remove":true}},"sibling":{"letter":{"accessible":false,"error_kind":"EACCES"},"inbox":{"accessible":false,"error_kind":"EACCES"}},"probe_wall_seconds":0.25});
        let handoff_path = fixture.path().join("matrix-primary-results.json");
        fs::write(&handoff_path, handoff.to_string()).expect("handoff");
        fs::set_permissions(&handoff_path, fs::Permissions::from_mode(0o600))
            .expect("handoff mode");
        publish_results(&plan, fixture.path(), &evidence_path, owner, false).expect("publication");
        let published: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_path).expect("evidence bytes"))
                .expect("json");
        assert_eq!(published["bound_source_matrix"]["state"], "measured");
        assert_eq!(
            published["bound_source_matrix"]["rows"][0]["state"],
            "passed"
        );
        assert_eq!(published["bound_source_matrix"]["probe_wall_seconds"], 0.25);
        assert_eq!(
            published["bound_source_matrix"]["rows"][2]["state"],
            "not-applicable"
        );
        assert_eq!(
            publish_results(&plan, fixture.path(), &evidence_path, owner, false)
                .expect_err("no replay")
                .kind,
            "bound-source"
        );
    }

    /// ´test:unit:refused-evaluation-publishes-all-measured-rows´
    #[test]
    fn refused_evaluation_publishes_all_measured_rows() {
        for failing in ["letter", "guard"] {
            let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
            fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
                .expect("private directory");
            let owner = nix::unistd::Uid::effective().as_raw();
            let worker_uid = if owner == 3000 { 3001 } else { 3000 };
            assert_ne!(owner, worker_uid);
            let plan = Plan {
                home: PathBuf::new(),
                driver_dir: PathBuf::new(),
                letter: PathBuf::new(),
                document: json!({"runtime_argv":["/usr/bin/podman","run","--userns=host"],"worker_uid":worker_uid}),
            };
            let letter = json!({"name":"letter","operation":"read","state":"pending","owner_uid":owner,"group_gid":owner,"mode":"0640","bind":"ro"});
            let inbox = json!({"name":"inbox","operation":"traverse","state":"pending","owner_uid":owner,"group_gid":owner,"mode":"0750","bind":"rw"});
            let evidence_path = fixture.path().join("launch-evidence.json");
            fs::write(&evidence_path, json!({"runtime_argv":plan.document["runtime_argv"],"bound_source_matrix":{"state":"pending","rows":[letter,inbox]}}).to_string()).expect("evidence");
            fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o600))
                .expect("evidence mode");
            let mut worker = json!({"letter":{"accessible":true,"read_performed":true,"uid":owner,"gid":owner,"mode":"0640"},"inbox":{"accessible":true,"uid":owner,"gid":owner,"mode":"0750"},"inbox_protection":guard_probe(owner,"EACCES","EPERM"),"git_worktree":{"ordinary_git_directory":true,"add_remove":true}});
            if failing == "letter" {
                worker["letter"]["accessible"] = json!(false);
                worker["letter"]["error_kind"] = json!("EACCES");
            } else {
                worker["inbox_protection"] = guard_probe(owner, "EROFS", "EROFS");
            }
            let handoff = json!({"phase":"primary","runtime_argv":plan.document["runtime_argv"],"rows":[letter,inbox],"worker":worker,"sibling":{"letter":{"accessible":false,"error_kind":"EACCES"},"inbox":{"accessible":false,"error_kind":"EPERM"}},"probe_wall_seconds":0.35});
            let handoff_path = fixture.path().join("matrix-primary-results.json");
            fs::write(&handoff_path, handoff.to_string()).expect("handoff");
            fs::set_permissions(&handoff_path, fs::Permissions::from_mode(0o600))
                .expect("handoff mode");
            let error = publish_results(&plan, fixture.path(), &evidence_path, owner, false)
                .expect_err("measured failure");
            assert_eq!(error.kind, "bound-source");
            assert!(error.line().contains(if failing == "letter" {
                "letter:"
            } else {
                "inbox-guard rename:"
            }));
            let published: serde_json::Value =
                serde_json::from_slice(&fs::read(&evidence_path).expect("evidence bytes"))
                    .expect("evidence json");
            assert_eq!(published["bound_source_matrix"]["state"], "failed");
            assert_eq!(published["bound_source_matrix"]["probe_wall_seconds"], 0.35);
            assert_eq!(
                published["bound_source_matrix"]["rows"][0]["state"],
                if failing == "letter" {
                    "failed"
                } else {
                    "passed"
                }
            );
            assert_eq!(
                published["bound_source_matrix"]["rows"][1]["state"],
                if failing == "guard" {
                    "failed"
                } else {
                    "passed"
                }
            );
            assert_eq!(
                published["bound_source_matrix"]["rows"][1]["inbox_protection"]["rename_guard_uid"],
                owner
            );
        }
    }

    /// ´test:unit:missing-or-malformed-handoff-refuses-by-name´
    #[test]
    fn missing_or_malformed_handoff_refuses_by_name() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let owner = nix::unistd::Uid::effective().as_raw();
        let plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"runtime_argv":["/usr/bin/podman","run"]}),
        };
        let evidence_path = fixture.path().join("launch-evidence.json");
        fs::write(&evidence_path, json!({"runtime_argv":plan.document["runtime_argv"],"bound_source_matrix":{"state":"pending","rows":[]}}).to_string()).expect("evidence");
        fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o600)).expect("mode");
        let missing = publish_results(&plan, fixture.path(), &evidence_path, owner, false)
            .expect_err("missing");
        assert_eq!(missing.kind, "bound-source");
        assert!(missing.line().contains("probe result unavailable"));
        let path = fixture.path().join("matrix-primary-results.json");
        fs::write(&path, b"not json").expect("malformed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let malformed = publish_results(&plan, fixture.path(), &evidence_path, owner, false)
            .expect_err("malformed");
        assert_eq!(malformed.kind, "bound-source");
        assert!(malformed.line().contains("probe result malformed"));
    }

    /// ´test:unit:bound-source-requires-worker-access-and-sibling-denial´
    #[test]
    fn bound_source_requires_worker_access_and_sibling_denial() {
        let mut rows = vec![
            json!({"name":"letter","operation":"read","state":"pending","owner_uid":41001,"group_gid":41001,"mode":"0640"}),
            json!({"name":"inbox","operation":"traverse","state":"pending","owner_uid":41001,"group_gid":41001,"mode":"0750","bind":"rw"}),
            json!({"name":"door-socket","state":"not-applicable"}),
        ];
        let worker = json!({"letter":{"accessible":true,"read_performed":true,"uid":41001,"gid":41001,"mode":"0640"},"inbox":{"accessible":true,"uid":41001,"gid":41001,"mode":"0750"},"inbox_protection":guard_probe(41001,"EACCES","EPERM"),"git_worktree":{"ordinary_git_directory":true,"add_remove":true}});
        let sibling = json!({"letter":{"accessible":false,"error_kind":"EACCES"},"inbox":{"accessible":false,"error_kind":"EPERM"}});
        let (result, refusal) = evaluate(&mut rows, &worker, &sibling);
        assert!(refusal.is_none(), "distinct worker and sibling views");
        assert_eq!(result["rows"][0]["state"], "passed");
        assert_eq!(result["rows"][2]["state"], "not-applicable");
        assert!(evaluate(&mut rows, &worker, &worker).1.is_some());
        let wrong_mode = json!({"letter":{"accessible":true,"read_performed":true,"uid":41001,"gid":41001,"mode":"0660"},"inbox":{"accessible":true,"uid":41001,"gid":41001,"mode":"0750"},"inbox_protection":guard_probe(41001,"EACCES","EPERM"),"git_worktree":{"ordinary_git_directory":true,"add_remove":true}});
        assert!(evaluate(&mut rows, &wrong_mode, &sibling).1.is_some());
        let mut no_read = worker;
        no_read["letter"]["read_performed"] = json!(false);
        assert!(evaluate(&mut rows, &no_read, &sibling).1.is_some());
    }

    /// ´test:unit:bound-source-refuses-a-nonpermission-socket-error´
    #[test]
    fn bound_source_refuses_a_nonpermission_socket_error() {
        let mut rows = vec![
            json!({"name":"vendor-socket","operation":"connect","state":"pending","owner_uid":41001,"group_gid":41001,"mode":"0660"}),
        ];
        let worker = json!({"vendor-socket":{"accessible":true,"uid":41001,"gid":41001,"mode":"0660"},"inbox_protection":{"rename_guard_exists":true,"rename_denied":true,"rename_error_kind":"EACCES","unlink_guard_exists":true,"unlink_denied":true,"unlink_error_kind":"EPERM"},"git_worktree":{"ordinary_git_directory":true,"add_remove":true}});
        let sibling = json!({"vendor-socket":{"accessible":false,"error_kind":"ECONNREFUSED"}});
        let error = evaluate(&mut rows, &worker, &sibling)
            .1
            .expect("socket unavailable is not denial");
        assert_eq!(error.kind, "bound-source");
        assert!(error.line().contains("vendor-socket"));
        assert!(error.line().contains("ECONNREFUSED"));
    }

    /// ´test:unit:bound-source-refuses-a-missing-inbox-guard´
    #[test]
    fn bound_source_refuses_a_missing_inbox_guard() {
        let mut rows = vec![
            json!({"name":"inbox","operation":"traverse","state":"pending","owner_uid":41001,"group_gid":41001,"mode":"0750"}),
        ];
        let worker = json!({"inbox":{"accessible":true,"uid":41001,"gid":41001,"mode":"0750"},"inbox_protection":{"rename_guard_exists":false,"rename_error_kind":"ENOENT","unlink_guard_exists":false,"unlink_error_kind":"ENOENT"},"git_worktree":{"ordinary_git_directory":true,"add_remove":true}});
        let sibling = json!({"inbox":{"accessible":false,"error_kind":"EPERM"}});
        let error = evaluate(&mut rows, &worker, &sibling)
            .1
            .expect("missing guard is not denial");
        assert_eq!(error.kind, "bound-source");
        assert!(error.line().contains("inbox-guard rename"));
        assert!(error.line().contains("ENOENT"));
    }

    /// ´test:unit:inbox-verdict-records-the-applicable-mount-or-guard-layer´
    #[test]
    fn inbox_verdict_records_the_applicable_mount_or_guard_layer() {
        let owner = 41001;
        let worker_uid = 3000;
        assert_ne!(owner, worker_uid);
        let sibling = json!({"inbox":{"accessible":false,"error_kind":"EACCES"}});
        for (bind, rename, unlink, expected_layer, accepted) in [
            ("ro", "EROFS", "EROFS", "read-only-mount", true),
            ("rw", "EROFS", "EROFS", "", false),
            ("rw", "EACCES", "EPERM", "guard", true),
        ] {
            let mut rows = vec![
                json!({"name":"inbox","operation":"traverse","state":"pending","owner_uid":owner,"group_gid":owner,"mode":"0750","bind":bind}),
            ];
            let worker = json!({"inbox":{"accessible":true,"uid":owner,"gid":owner,"mode":"0750"},"inbox_protection":guard_probe(owner,rename,unlink),"git_worktree":{"ordinary_git_directory":true,"add_remove":true}});
            let (measured, refusal) = evaluate(&mut rows, &worker, &sibling);
            assert_eq!(refusal.is_none(), accepted, "bind {bind}, error {rename}");
            assert_eq!(
                measured["rows"][0]["state"],
                if accepted { "passed" } else { "failed" }
            );
            assert_eq!(measured["inbox_protection"]["rename_guard_exists"], true);
            assert_eq!(measured["inbox_protection"]["rename_guard_uid"], owner);
            assert_eq!(measured["inbox_protection"]["rename_guard_mode"], "0640");
            assert_eq!(
                measured["rows"][0]["inbox_protection"],
                measured["inbox_protection"]
            );
            if accepted {
                assert_eq!(measured["inbox_protection"]["denied_by"], expected_layer);
            } else {
                let error = refusal.expect("writable bind refuses EROFS");
                assert_eq!(error.kind, "bound-source");
                assert!(error.line().contains("inbox-guard rename"));
                assert!(error.line().contains("EROFS"));
            }
        }
    }

    /// ´test:unit:bound-source-uses-distinct-owner-and-worker-uids´
    #[test]
    fn bound_source_uses_distinct_owner_and_worker_uids() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let source = fixture.path().join("dispatch.md");
        fs::write(&source, b"fixture letter").expect("letter");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).expect("mode");
        let owner_uid = nix::unistd::Uid::effective().as_raw();
        let loop_group = nix::unistd::Gid::effective().as_raw();
        let worker_uid = if owner_uid == 3000 { 3001 } else { 3000 };
        assert_ne!(owner_uid, worker_uid);
        let mut plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"home":"~/home-R","driver_dir":"~/runs/R","worker_uid":worker_uid,"paths":[{"path":"~/home-R","uid":owner_uid,"gid":loop_group},{"path":"~/runs/R","kind":"directory","uid":loop_group,"gid":loop_group}],"mounts":[{"target":"/home/worker/.local/inbox/dispatch.md","source":source,"kind":"bind","access":"ro"}]}),
        };
        let row = bound_row(
            &plan,
            "letter",
            "/home/worker/.local/inbox/dispatch.md",
            "read",
            0o640,
        )
        .expect("owner source");
        assert_eq!(row["owner_uid"], owner_uid);
        assert_eq!(row["bind"], "ro");
        assert!(
            bound_row(
                &plan,
                "letter",
                "/home/worker/.local/inbox/dispatch.md",
                "read",
                0o660
            )
            .is_err()
        );
        plan.document["paths"][1]["uid"] = json!(worker_uid);
        assert_eq!(
            bound_row(
                &plan,
                "letter",
                "/home/worker/.local/inbox/dispatch.md",
                "read",
                0o640,
            )
            .expect_err("conflicting driver owner")
            .kind,
            "loop-identity"
        );
    }

    /// ´test:unit:bound-source-refuses-a-missing-input-by-row-and-kind´
    #[test]
    fn bound_source_refuses_a_missing_input_by_row_and_kind() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let source = fixture.path().join("missing-letter");
        let owner_uid = nix::unistd::Uid::effective().as_raw();
        let group_gid = nix::unistd::Gid::effective().as_raw();
        let worker_uid = if owner_uid == 3000 { 3001 } else { 3000 };
        assert_ne!(owner_uid, worker_uid);
        let plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"worker_uid":worker_uid,"paths":[{"uid":owner_uid,"gid":group_gid}],"mounts":[{"target":"/home/worker/.local/inbox/dispatch.md","source":source,"kind":"bind","access":"ro"}]}),
        };
        let error = bound_row(
            &plan,
            "letter",
            "/home/worker/.local/inbox/dispatch.md",
            "read",
            0o640,
        )
        .expect_err("missing source");
        assert_eq!(error.kind, "bound-source");
        assert!(error.line().contains("letter"));
        assert!(error.line().contains("NotFound"));
    }

    /// ´test:unit:bound-source-preview-lists-rows-without-opening-home´
    #[test]
    fn bound_source_preview_lists_rows_without_opening_home() {
        let mut plan = Plan {
            home: PathBuf::from("/absent/home"),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"home":"/absent/home","driver_dir":"~/runs/R","worker_uid":3000,"paths":[{"path":"/absent/home","uid":41001,"gid":2010},{"path":"~/runs/R","kind":"directory","uid":2010,"gid":2010}],"mounts":[
                {"target":"/home/worker","source":"/absent/home","kind":"bind","access":"ro"},
                {"target":"/home/worker/.local/bin","source":"/absent/template/bin","kind":"bind","access":"ro"},
                {"target":"/home/worker/.local/libexec/superloop","source":"/absent/template/libexec","kind":"bind","access":"ro"},
                {"target":"/home/worker/.codex/AGENTS.md","source":"/absent/template/AGENTS.md","kind":"bind","access":"ro"},
                {"target":"/home/worker/.codex/config.toml","source":"/absent/template/config.toml","kind":"bind","access":"ro"},
                {"target":"/home/worker/.local/vendor","source":"/absent/vendor","kind":"bind","access":"ro"}
            ]}),
        };
        let enforcing = preview(&plan).expect("path-only preview");
        assert_eq!(enforcing["rows"][0]["owner_uid"], 41001);
        assert_eq!(enforcing["rows"][0]["mode"], "0550");
        assert_eq!(enforcing["rows"][0]["bind"], "ro");
        assert_eq!(enforcing["rows"][10]["state"], "would-probe");
        assert_eq!(enforcing["rows"][11]["state"], "not-applicable");
        plan.document["vendor_mode"] = json!("observe");
        let observing = preview(&plan).expect("observing preview");
        assert_eq!(observing["rows"][10]["state"], "deferred");
        assert_eq!(
            observing["rows"][10]["reason"],
            super::OBSERVING_SOCKET_REASON
        );
    }

    /// ´test:unit:observing-socket-evidence-replaces-only-deferred-row´
    #[test]
    fn observing_socket_evidence_replaces_only_deferred_row() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let path = fixture.path().join("launch-evidence.json");
        let owner = nix::unistd::Uid::effective().as_raw();
        let worker_uid = if owner == 3000 { 3001 } else { 3000 };
        assert_ne!(owner, worker_uid);
        let plan = Plan {
            home: PathBuf::new(),
            driver_dir: PathBuf::new(),
            letter: PathBuf::new(),
            document: json!({"worker_uid":worker_uid,"runtime_argv":["/usr/bin/podman","run","--userns=host"]}),
        };
        fs::write(&path, json!({"runtime_argv":plan.document["runtime_argv"],"bound_source_matrix":{"state":"measured","rows":[{"name":"letter","state":"passed"},{"name":"vendor-socket","state":"deferred"}]}}).to_string())
            .expect("synthetic evidence");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let row = json!({"name":"vendor-socket","operation":"connect","state":"pending","owner_uid":owner,"group_gid":owner,"mode":"0660"});
        publish_prepared_deferred(fixture.path(), &path, owner, &row).expect("prepared source");
        let handoff = json!({"phase":"deferred","rows":[row],"runtime_argv":plan.document["runtime_argv"],"worker":{"vendor-socket":{"accessible":true,"uid":owner,"gid":owner,"mode":"0660"}},"sibling":{"vendor-socket":{"accessible":false,"error_kind":"EPERM"}},"probe_wall_seconds":0.25});
        let handoff_path = fixture.path().join("matrix-deferred-results.json");
        fs::write(&handoff_path, handoff.to_string()).expect("handoff");
        fs::set_permissions(&handoff_path, fs::Permissions::from_mode(0o600))
            .expect("handoff mode");
        publish_results(&plan, fixture.path(), &path, owner, true).expect("rewrite");
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read evidence")).expect("json");
        assert_eq!(written["bound_source_matrix"]["rows"][0]["state"], "passed");
        assert_eq!(written["bound_source_matrix"]["rows"][1]["state"], "passed");
        assert_eq!(
            written["bound_source_matrix"]["deferred_probe_wall_seconds"],
            0.25
        );
    }

    /// ´test:unit:deferred-socket-probe-refuses-unavailable-connect´
    #[test]
    fn deferred_socket_probe_refuses_unavailable_connect() {
        let mut rows = vec![
            json!({"name":"vendor-socket","operation":"connect","state":"pending","owner_uid":41001,"group_gid":41001,"mode":"0660"}),
        ];
        let worker = json!({"vendor-socket":{"accessible":false,"error_kind":"ECONNREFUSED"}});
        let sibling = json!({"vendor-socket":{"accessible":false,"error_kind":"EACCES"}});
        let error = evaluate_rows(&mut rows, &worker, &sibling).expect_err("unavailable");
        assert_eq!(error.kind, "bound-source");
        assert!(error.line().contains("vendor-socket"));
        assert!(error.line().contains("ECONNREFUSED"));
    }
}
