//! # `loop-home` library test matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Entry planning | 15 | Exact scripts, custody derivation, home resolution, quoting, fixed bridge command, argv0 dispatch, private report file, and settings-aware private dispatch |
//! | Registry and refusals | 26 | Whole-file TOML grammar, identity names and paths, unknown row keys, UID uniqueness, custody pinning, command, podman, and provision planning |
//! | Worker blocks | 2 | Allocation grammar, overlap, absent tables, inclusive runs, and secure bounded reading |
//! | Verification | 16 | Scripted runner responses, account UID, env drift, declared runs root, sorted JSON, and required ensure wall |
//! | Ensure step | 12 | Table rows, creation order, idempotence, mode and group checks, syscall counts, refusals, custody tier, and private-root widening |
//! | Driver launch | 5 | Run grammar, ordinary dispatch, positional argv, settings, driver, and selected run directory refusals |

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::app::{
    Action, ReportFile, argv0_bridge, caller_home, entry_custody, inspect_system_program_from,
    parse_invocation, resolve_podman, resolve_verify_podman_in, resolve_verify_podman_with,
    trusted_system_component,
};
use crate::driver_launch::run_paths::{pin_run_directory, pin_runs_root, pin_runs_root_with_hook};
use crate::driver_launch::{
    valid_run_name, validate_driver_launch, validate_driver_launch_for_owner,
};
use crate::ensure::{
    EnsureClass, RootAction, RootOwner, StandardRoot, begin_prepare_trace, deny_inspection_noatime,
    end_prepare_trace, inspect_roots, reset_syscall_counts, standard_roots, syscall_counts,
};
use crate::planner::{
    BridgeKind, Custody, IoMode, bridge_command, custody_tier, driver_launch_plan, shell_word,
};
use crate::verify::{
    EnsureReport, account_uid, inspect_runs_root, inspect_runs_root_for_owner, registry_drift,
};
use crate::{
    CommandOutput, CommandSpec, LoopRecord, RunError, Runner, assemble_verify, bind_custody_entry,
    cleanup_probe_plan, load_registry, pin_custody, provision_plan, registry_path, validate_name,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn entry_plan(
    record: &LoopRecord,
    custody: Option<&Custody>,
    podman: &[String],
    command: &[String],
    term: &str,
    lang: &str,
    io: IoMode,
) -> crate::EntryPlan {
    crate::entry_plan(
        record,
        Path::new("/fixture/superloop"),
        Path::new("/caller"),
        Path::new("/fixture/report"),
        custody,
        podman,
        command,
        term,
        lang,
        io,
    )
}

fn verify_probe_plan(
    record: &LoopRecord,
    custody: Option<&Custody>,
    podman: &[String],
    term: &str,
    lang: &str,
) -> crate::EntryPlan {
    crate::verify_probe_plan(
        record,
        Path::new("/fixture/superloop"),
        Path::new("/caller"),
        Path::new("/fixture/report"),
        custody,
        podman,
        term,
        lang,
    )
}

fn ensure_roots<W: std::io::Write>(
    rows: &[StandardRoot],
    owner_uid: u32,
    loop_uid: u32,
    report: &mut W,
) -> Result<crate::EnsureCounts, crate::EnsureFailure> {
    let gid = fs::metadata(&rows[0].path).expect("class gid").gid();
    crate::ensure_roots(rows, (owner_uid, gid), (loop_uid, gid), report)
}

/// ´claim:loophome:the-registry-path-defaults-beneath-the-caller-home´
/// ´test:crate:registry-path-uses-the-override-or-caller-home´
#[test]
fn registry_path_uses_the_override_or_caller_home() {
    let home = PathBuf::from("/fixture/loop-home");
    assert_eq!(
        registry_path(None, &home),
        PathBuf::from("/fixture/loop-home/.config/loops/registry.toml"),
    );
    assert_eq!(
        registry_path(Some(OsStr::new("")), &home),
        registry_path(None, &home)
    );
    assert_eq!(
        registry_path(Some(OsStr::new("/fixture/selected.toml")), &home),
        PathBuf::from("/fixture/selected.toml")
    );
}

/// ´claim:loophome:every-entry-requires-a-nonempty-utf8-caller-home´
/// ´test:crate:unset-empty-and-non-utf8-home-are-refused-by-name´
#[test]
fn unset_empty_and_non_utf8_home_are_refused_by_name() {
    use std::os::unix::ffi::OsStrExt as _;
    for home in [
        None,
        Some(OsStr::new("")),
        Some(OsStr::from_bytes(b"/bad\xff")),
    ] {
        let failure = caller_home(home).expect_err("HOME is required");
        assert_eq!(failure.status(), 2);
        assert_eq!(failure.message(), "HOME must be a nonempty UTF-8 path");
        let failure = parse_invocation(
            OsStr::new("superloop"),
            ["enter", "alpha", "true"],
            Some(OsStr::new("/fixture/registry.toml")),
            home,
        )
        .expect_err("HOME is required despite registry override");
        assert_eq!(failure.status(), 2);
        assert_eq!(failure.message(), "HOME must be a nonempty UTF-8 path");
    }
}

pub struct TestDir {
    pub(crate) path: PathBuf,
}

impl TestDir {
    pub(crate) fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "loop-home-test-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self { path }
    }

    fn new_safe(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let name = format!("loop-home-test-{}-{sequence}-{label}", std::process::id());
        let owner = (
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
        );
        let mut attempts = Vec::new();
        for base in [
            std::env::temp_dir(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ] {
            if !base.is_absolute() {
                attempts.push(format!("{} is not absolute", base.display()));
                continue;
            }
            let path = base.join(&name);
            if let Err(error) = fs::create_dir(&path) {
                attempts.push(format!("{}: {error}", path.display()));
                continue;
            }
            if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o711)) {
                attempts.push(format!("{}: cannot set mode 0711: {error}", path.display()));
                fs::remove_dir(&path).expect("remove rejected safe-path fixture");
                continue;
            }
            let checked = pin_runs_root(&path, owner, true);
            if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
                attempts.push(format!("{}: cannot set mode 0700: {error}", path.display()));
                fs::remove_dir(&path).expect("remove rejected safe-path fixture");
                continue;
            }
            match checked {
                Ok(_pinned) => return Self { path },
                Err(failure) => {
                    attempts.push(format!("{}: {}", failure.path.display(), failure.reason));
                    fs::remove_dir(&path).expect("remove rejected safe-path fixture");
                }
            }
        }
        panic!(
            "safe-path fixture prerequisite: no writable temporary base with trusted, link-free ancestors and owner UID/GID: {}",
            attempts.join("; ")
        );
    }

    fn write_registry(&self, content: &str) {
        fs::write(self.path.join("registry.toml"), content).expect("write registry fixture");
    }

    fn registry(&self) -> PathBuf {
        self.path.join("registry.toml")
    }
}

fn private_parents(path: &Path, base: &Path) {
    let mut cursor = path.parent();
    while let Some(parent) = cursor {
        if !parent.starts_with(base) {
            break;
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .expect("private fixture ancestor");
        cursor = parent.parent();
    }
}

fn write_allocation(home: &Path, source: &str) {
    let path = crate::allocations::allocations_path(home);
    fs::create_dir_all(path.parent().expect("allocation parent")).expect("allocation directory");
    private_parents(&path, home);
    let registry = path.with_file_name("registry.toml");
    if !registry.exists() {
        fs::write(&registry, registry_source("{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }, { name = \"beta\", uid = 41002, launch = \"dev/beta\" }")).expect("allocation registry fixture");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    }
    fs::write(&path, source).expect("allocation fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("allocation mode");
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove test directory");
    }
}

fn record(name: &str, uid: u32, home: &str) -> LoopRecord {
    LoopRecord {
        name: name.to_owned(),
        uid,
        home: PathBuf::from(home),
        launch: PathBuf::from("/fixture/dev/alpha"),
        session: None,
        door_floor: None,
    }
}

struct Reply {
    label: &'static str,
    status: i32,
    stdout: Vec<u8>,
}

#[derive(Default)]
struct ScriptedRunner {
    replies: VecDeque<Reply>,
    commands: Vec<CommandSpec>,
}

impl Runner for ScriptedRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RunError> {
        let reply = self.replies.pop_front().expect("scripted reply");
        assert_eq!(command.label, reply.label);
        self.commands.push(command.clone());
        Ok(CommandOutput {
            status: reply.status,
            stdout: reply.stdout,
            stderr: Vec::new(),
            wall: Duration::from_millis(5),
        })
    }
}

/// The planner pins complete two-layer script bytes, including the no-tier keyring choice, and one podman invocation.
///
/// ´claim:loophome:a-valid-entry-has-one-outer-command-and-one-nested-mount-namespace´
/// ´test:crate:a-valid-registry-produces-the-exact-outer-and-inner-scripts´
#[test]
fn a_valid_registry_produces_the_exact_outer_and_inner_scripts() {
    let plan = entry_plan(
        &record("alpha", 41001, "/srv/alpha"),
        None,
        &[String::from("podman")],
        &[String::from("printf"), String::from("ok")],
        "vt100",
        "C.UTF-8",
        IoMode::Inherit,
    );
    let expected_inner = r#"set -e
t=$1
h=$2
mount --bind "$t/passwd" /etc/passwd
mount --bind "$t/group" /etc/group
mount --bind "$t/ssh_config.d" /etc/ssh/ssh_config.d
gpg_dir="$h"/.config/gpg-loops/alpha
gpg_environment=
if [ -d "$gpg_dir" ]; then gpg_environment="GNUPGHOME=$gpg_dir"; fi
mail_group=$(/fixture/superloop _mail-group /caller alpha)
group_option=--clear-groups
if [ -n "$mail_group" ]; then group_option=--groups=$mail_group; fi
exec setpriv --reuid=41001 --regid=41001 "$group_option" env -i HOME="$h" USER=alpha LOGNAME=alpha SHELL=/bin/bash PATH="$h/.local/bin:/usr/local/bin:/usr/bin:/bin:/fixture" TERM=vt100 LANG=C.UTF-8 TMPDIR=/caller/.cache/loops/alpha/tmp XDG_RUNTIME_DIR="$h/.run" XDG_CONFIG_HOME="$h/.config" XDG_CACHE_HOME=/caller/.cache/loops/alpha XDG_DATA_HOME="$h/.local/share" XDG_STATE_HOME="$h/.local/state" ${gpg_environment:+"$gpg_environment"} printf ok"#;
    let expected_outer = r#"set -e
h=/srv/alpha
/fixture/superloop ensure-roots 41001 alpha /caller /fixture/report
if [ -d "$h/private" ]; then h="$h/private"; fi
t=$(mktemp -d /tmp/superloop.XXXXXX)
cleanup() {
    rm -rf "$t"
}
trap cleanup EXIT
cat /etc/passwd > "$t/passwd"
printf '%s\n' 'alpha:x:41001:41001:alpha superloop:'"$h"':/bin/bash' >> "$t/passwd"
cat /etc/group > "$t/group"
printf '%s\n' 'alpha:x:41001:' >> "$t/group"
mkdir -p "$t/ssh_config.d"
set +e
child=
signal=
forward() {
    signal=$1
    interrupted=yes
    if [ -n "$child" ]; then kill -s "$signal" "$child" 2>/dev/null || :; fi
}
trap 'forward TERM' TERM
trap 'forward INT' INT
trap 'forward HUP' HUP
trap 'forward QUIT' QUIT
exec 9<&0
/fixture/superloop _supervise-command "$ENTER_LOOP_WATCHED_SIGNALS" /fixture/report.signals/stop unshare -m sh -c 'set -e
t=$1
h=$2
mount --bind "$t/passwd" /etc/passwd
mount --bind "$t/group" /etc/group
mount --bind "$t/ssh_config.d" /etc/ssh/ssh_config.d
gpg_dir="$h"/.config/gpg-loops/alpha
gpg_environment=
if [ -d "$gpg_dir" ]; then gpg_environment="GNUPGHOME=$gpg_dir"; fi
mail_group=$(/fixture/superloop _mail-group /caller alpha)
group_option=--clear-groups
if [ -n "$mail_group" ]; then group_option=--groups=$mail_group; fi
exec setpriv --reuid=41001 --regid=41001 "$group_option" env -i HOME="$h" USER=alpha LOGNAME=alpha SHELL=/bin/bash PATH="$h/.local/bin:/usr/local/bin:/usr/bin:/bin:/fixture" TERM=vt100 LANG=C.UTF-8 TMPDIR=/caller/.cache/loops/alpha/tmp XDG_RUNTIME_DIR="$h/.run" XDG_CONFIG_HOME="$h/.config" XDG_CACHE_HOME=/caller/.cache/loops/alpha XDG_DATA_HOME="$h/.local/share" XDG_STATE_HOME="$h/.local/state" ${gpg_environment:+"$gpg_environment"} printf ok' sh "$t" "$h" <&9 9<&- &
child=$!
exec 9<&-
if [ -n "$signal" ]; then forward "$signal"; fi
while :; do
    interrupted=
    wait "$child"
    rc=$?
    [ -n "$interrupted" ] || break
done
set -e
rm -rf "$t"
trap - EXIT
exit "$rc""#;
    let expected_outer = expected_outer.replace(
        "\"$ENTER_LOOP_WATCHED_SIGNALS\"",
        &crate::runner::watched_literal(),
    );
    assert_eq!(plan.inner_script, expected_inner);
    assert_eq!(plan.outer_script, expected_outer);
    assert_eq!(
        plan.command.argv,
        ["podman", "unshare", "sh", "-c"]
            .into_iter()
            .map(String::from)
            .chain([expected_outer])
            .collect::<Vec<_>>()
    );
}

/// The outer namespace resolves the entry home before composing passwd and the nested call.
///
/// ´claim:loophome:the-entry-home-is-private-when-the-loop-home-carries-it´
/// ´test:crate:the-outer-script-resolves-private-before-the-passwd-line´
#[test]
fn the_outer_script_resolves_private_before_the_passwd_line() {
    let plan = entry_plan(
        &record("alpha", 41001, "/srv/alpha"),
        None,
        &[String::from("podman")],
        &[String::from("true")],
        "vt100",
        "C.UTF-8",
        IoMode::Inherit,
    );
    let resolution = plan
        .outer_script
        .find("if [ -d \"$h/private\" ]; then h=\"$h/private\"; fi")
        .expect("outer home resolution");
    let passwd = plan
        .outer_script
        .find("printf '%s\\n' 'alpha:x:41001:41001:alpha superloop:'\"$h\"':/bin/bash' >> \"$t/passwd\"")
        .expect("passwd uses resolved home between literals");
    assert!(resolution < passwd);
    assert_eq!(
        plan.outer_script.lines().nth(2),
        Some("/fixture/superloop ensure-roots 41001 alpha /caller /fixture/report")
    );
    assert!(plan.outer_script.contains("sh \"$t\" \"$h\" <&9 9<&- &"));
    assert_eq!(plan.outer_script.matches("/srv/alpha").count(), 1);
    assert!(
        plan.inner_script
            .contains("gpg_dir=\"$h\"/.config/gpg-loops/alpha\n")
    );
}

/// The validated row name selects custody beneath the caller home.
///
/// ´claim:loophome:the-custody-tier-derives-from-caller-home-and-validated-name´
/// ´test:crate:custody-tier-derives-from-the-caller-home-and-name´
#[test]
fn custody_tier_derives_from_the_caller_home_and_name() {
    let directory = TestDir::new("custody-name");
    directory.write_registry(
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n",
    );
    let record = load_registry(&directory.registry())
        .expect("valid registry")
        .row("alpha", &directory.path)
        .expect("valid row");
    let caller_home = PathBuf::from("/caller with space");
    assert_eq!(
        custody_tier(&caller_home, &record.name),
        PathBuf::from("/caller with space/.config/loops/alpha/private")
    );
    assert_ne!(
        custody_tier(&caller_home, &record.name),
        custody_tier(&caller_home, "decoy")
    );
}

/// Custody changes only the embedded inner script, and those bytes name one pinned step.
///
/// ´claim:loophome:the-entry-binds-custody-and-selects-its-keyring-and-forge-config´
/// ´test:crate:a-custody-tier-produces-the-exact-custody-inner-script´
#[test]
fn a_custody_tier_produces_the_exact_custody_inner_script() {
    let custody = Custody {
        tier: PathBuf::from("/caller/.config/loops/alpha/private"),
        executable: PathBuf::from("/fixture/superloop"),
    };
    let plan = entry_plan(
        &record("alpha", 41001, "/srv/alpha"),
        Some(&custody),
        &[String::from("podman")],
        &[String::from("printf"), String::from("ok")],
        "vt100",
        "C.UTF-8",
        IoMode::Inherit,
    );
    let expected_inner = r#"set -e
t=$1
h=$2
/fixture/superloop bind-custody 41001 /srv/alpha "$h" /caller/.config/loops/alpha/private
mount --bind "$t/passwd" /etc/passwd
mount --bind "$t/group" /etc/group
mount --bind "$t/ssh_config.d" /etc/ssh/ssh_config.d
mail_group=$(/fixture/superloop _mail-group /caller alpha)
group_option=--clear-groups
if [ -n "$mail_group" ]; then group_option=--groups=$mail_group; fi
exec setpriv --reuid=41001 --regid=41001 "$group_option" env -i HOME="$h" USER=alpha LOGNAME=alpha SHELL=/bin/bash PATH="$h/.local/bin:/usr/local/bin:/usr/bin:/bin:/fixture" TERM=vt100 LANG=C.UTF-8 TMPDIR=/caller/.cache/loops/alpha/tmp XDG_RUNTIME_DIR="$h/.run" XDG_CONFIG_HOME="$h/.config" XDG_CACHE_HOME=/caller/.cache/loops/alpha XDG_DATA_HOME="$h/.local/share" XDG_STATE_HOME="$h/.local/state" GNUPGHOME="$h/.config/custody/gpg" GH_CONFIG_DIR="$h/.config/custody/gh" /bin/sh -c 'if [ ! -x "$HOME/.config/custody" ]; then reason=forge-config-inaccessible; elif [ ! -e "$GH_CONFIG_DIR" ]; then reason=forge-config-absent; elif [ ! -d "$GH_CONFIG_DIR" ]; then reason=forge-config-not-directory; elif [ ! -r "$GH_CONFIG_DIR" ] || [ ! -w "$GH_CONFIG_DIR" ] || [ ! -x "$GH_CONFIG_DIR" ]; then reason=forge-config-inaccessible; else exec "$@"; fi; printf '\''superloop: %s: GH_CONFIG_DIR; run superloop provision LOOP\n'\'' "$reason" >&2; exit 1' forge-entry printf ok"#;
    assert_eq!(plan.inner_script, expected_inner);
    assert!(!plan.inner_script.contains("gpg_dir="));
    let baseline = entry_plan(
        &record("alpha", 41001, "/srv/alpha"),
        None,
        &[String::from("podman")],
        &[String::from("printf"), String::from("ok")],
        "vt100",
        "C.UTF-8",
        IoMode::Inherit,
    );
    assert_eq!(
        plan.outer_script,
        baseline.outer_script.replacen(
            &shell_word(&baseline.inner_script),
            &shell_word(expected_inner),
            1
        )
    );
}

/// A missing target is refused during pinning before any bind can start.
///
/// ´claim:loophome:missing-custody-bind-targets-refuse-before-mounts´
/// ´test:crate:a-custody-tier-without-a-bind-target-is-refused-before-any-mount´
#[test]
fn a_custody_tier_without_a_bind_target_is_refused_before_any_mount() {
    let directory = TestDir::new("custody-targets");
    let home = directory.path.join("home");
    let custody = directory.path.join(".config/loops/alpha/private");
    fs::create_dir_all(&home).expect("create entered home");
    fs::create_dir_all(&custody).expect("create custody tier");
    fs::create_dir(custody.join("ssh")).expect("create custody ssh");
    let uid = fs::metadata(&home).expect("home metadata").uid();
    for target in [".config/custody", ".ssh"] {
        let other = if target == ".ssh" {
            ".config/custody"
        } else {
            ".ssh"
        };
        fs::create_dir_all(home.join(other)).expect("create other bind target");
        let failure = pin_custody(uid, &home, &home, &custody).expect_err("missing target");
        assert_eq!(failure.path, home.join(target));
        assert_eq!(failure.reason, "ENOENT");
        fs::remove_dir(home.join(other)).expect("remove other bind target");
    }
}

/// Home and command words survive both shell parsing layers without becoming executable syntax.
///
/// ´claim:loophome:every-substituted-entry-value-is-shell-quoted´
/// ´test:crate:space-home-and-single-quote-command-are-quoted´
#[test]
fn space_home_and_single_quote_command_are_quoted() {
    let plan = entry_plan(
        &record("spacey", 2006, "/srv/with space"),
        None,
        &[String::from("podman")],
        &[String::from("that's-fine")],
        "xterm",
        "C.UTF-8",
        IoMode::Inherit,
    );
    assert!(plan.outer_script.contains("h='/srv/with space'"));
    assert!(plan.inner_script.contains("HOME=\"$h\""));
    assert!(plan.inner_script.ends_with("'that'\\''s-fine'"));
    assert!(
        plan.outer_script
            .contains("'spacey:x:2006:2006:spacey superloop:'\"$h\"':/bin/bash'")
    );
    assert!(
        plan.outer_script
            .contains("'\\''that'\\''\\'\\'''\\''s-fine'\\'''")
    );
}

/// Unsafe command words are shell literals, so shell parsing preserves their bytes exactly.
///
/// ´claim:loophome:command-words-are-forwarded-byte-for-byte-through-shell-composition´
/// ´test:crate:shell-word-round-trips-every-byte-through-sh´
#[test]
fn shell_word_round_trips_every_byte_through_sh() {
    for word in [
        "a\nb",
        "a\tb",
        "-n",
        "it's",
        "\"q\"",
        "$HOME",
        "back\\slash",
        "two words",
        "",
        "ünï",
        "a\n\nb\n",
        "x; rm -rf /",
    ] {
        let script = format!("printf '%s' {}", shell_word(word));
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .expect("shell round trip runs");
        assert!(
            output.status.success(),
            "shell failed for {word:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, word.as_bytes(), "word {word:?}");
    }

    assert_eq!(shell_word("plain-word.1"), "plain-word.1");
}

///
/// # Panics
/// Panics only if fixture setup fails or the generated entry cannot resolve its sibling.
/// ´claim:entry:entry-path-resolves-the-deployed-keygen-sibling´
/// ´test:crate:entry-path-resolves-the-deployed-keygen-sibling´
#[test]
fn entry_path_resolves_the_deployed_keygen_sibling() {
    let directory = TestDir::new("keygen-path");
    let bin = directory.path.join("deployed tools");
    fs::create_dir(&bin).expect("tool directory");
    for (name, script) in [
        ("mount", "#!/bin/sh\nexit 0\n"),
        ("superloop", "#!/bin/sh\ntest \"$1\" = _mail-group\n"),
        ("setpriv", "#!/bin/sh\nshift 3\nexec \"$@\"\n"),
        (
            "fixture-sibling-tool",
            "#!/bin/sh\nprintf 'keygen sibling\\n'\n",
        ),
        ("true", "#!/bin/sh\nexit 77\n"),
    ] {
        let path = bin.join(name);
        fs::write(&path, script).expect("fixture command");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable");
    }
    for (command, expected) in [
        ("fixture-sibling-tool", &b"keygen sibling\n"[..]),
        ("true", &b""[..]),
    ] {
        let plan = crate::entry_plan(
            &record("alpha", 41001, "/unused"),
            &bin.join("superloop"),
            &directory.path,
            &directory.path.join("report"),
            None,
            &["podman".into()],
            &[command.into()],
            "dumb",
            "C",
            IoMode::Inherit,
        );
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &plan.inner_script, "sh"])
            .arg(&directory.path)
            .arg(&directory.path)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .output()
            .expect("generated entry script");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, expected);
    }
}

/// The `GnuPG` bridge names the fixed system executable, while SSH stays direct and both preserve caller arguments.
///
/// ´claim:loophome:bridges-are-ordinary-entries-with-fixed-first-command-words´
/// ´test:crate:gpg-and-ssh-bridge-plans-preserve-arguments´
#[test]
fn gpg_and_ssh_bridge_plans_preserve_arguments() {
    assert_eq!(
        bridge_command(BridgeKind::Gpg, &[String::from("--version")]),
        ["/usr/bin/gpg", "--version"].map(String::from)
    );
    assert_eq!(
        bridge_command(BridgeKind::Ssh, &[String::from("host")]),
        ["ssh", "host"].map(String::from)
    );
}

/// The `GnuPG` executable stays in the entered command line while the registry home stays in the outer home assignment.
///
/// ´claim:loophome:the-gpg-bridge-uses-the-custody-keyring-through-the-entry´
/// ´test:crate:the-gpg-bridge-command-line-is-fixed-gpg-and-the-caller-words´
#[test]
fn the_gpg_bridge_command_line_is_fixed_gpg_and_the_caller_words() {
    let record = record("alpha", 41001, "/srv/alpha");
    let command = bridge_command(BridgeKind::Gpg, &[String::from("--version")]);
    assert!(command.iter().all(|word| !word.contains("/srv/alpha")));

    let plan = entry_plan(
        &record,
        None,
        &[String::from("podman")],
        &command,
        "vt100",
        "C.UTF-8",
        IoMode::Inherit,
    );
    assert!(plan.inner_script.ends_with("/usr/bin/gpg --version"));
    assert_eq!(plan.outer_script.matches("/srv/alpha").count(), 1);
    assert!(!plan.inner_script.contains("/srv/alpha"));
}

/// Symlink names dispatch only the documented `GnuPG` and SSH suffixes.
///
/// ´claim:loophome:bridge-symlink-names-carry-loop-and-bridge-identity´
/// ´test:crate:argv0-dispatch-recognizes-both-bridge-forms´
#[test]
fn argv0_dispatch_recognizes_both_bridge_forms() {
    assert_eq!(
        argv0_bridge(OsStr::new("/usr/bin/alpha-gpg")),
        Some((String::from("alpha"), BridgeKind::Gpg))
    );
    assert_eq!(
        argv0_bridge(OsStr::new("alpha-ssh")),
        Some((String::from("alpha"), BridgeKind::Ssh))
    );
    assert_eq!(argv0_bridge(OsStr::new("superloop")), None);
    for name in ["/usr/bin/alpha-gpg", "alpha-ssh"] {
        let invocation = parse_invocation(
            OsStr::new(name),
            ["--version"],
            None,
            Some(OsStr::new("/caller")),
        )
        .expect("bridge version is forwarded");
        assert!(matches!(
            invocation.action,
            Action::Bridge { arguments, .. } if arguments == ["--version"]
        ));
    }
}

/// Each explicit command accept report selection beside their own arguments.
///
/// ´claim:loophome:every-subcommand-can-select-json-reporting´
/// ´test:crate:json-report-selection-is-accepted-by-every-command-form´
#[test]
fn json_report_selection_is_accepted_by_every_command_form() {
    let cases = [
        vec!["enter", "--json", "alpha", "true"],
        vec!["enter", "alpha", "--json", "true"],
        vec!["provision", "--json", "alpha"],
        vec!["provision", "alpha", "--json"],
        vec!["run-bridge", "--json", "gpg", "alpha"],
        vec!["run-bridge", "ssh", "alpha", "--json"],
        vec!["verify", "--json", "alpha"],
        vec!["verify", "alpha", "--json"],
    ];
    for arguments in cases {
        let invocation = parse_invocation(
            OsStr::new("superloop"),
            arguments,
            Some(OsStr::new("/fixture/root")),
            Some(OsStr::new("/fixture/caller")),
        )
        .expect("JSON option is accepted");
        assert!(invocation.json);
    }
}

/// Identity names admit command words; command dispatch is a separate concern.
///
/// ´claim:loophome:loop-names-use-the-mail-identity-production´
/// ´test:crate:identity-names-follow-the-mail-production´
#[test]
fn identity_names_follow_the_mail_production() {
    for name in ["", "Bad", "under_score", "-leading", "a.b", "a+b", "é"] {
        let failure = validate_name(name).expect_err("invalid name");
        assert_eq!(failure.status(), 2);
        assert_eq!(failure.message(), format!("bad loop name: {name}"));
    }
    for name in [
        "enter",
        "provision",
        "run-bridge",
        "verify",
        "bind-custody",
        "show",
        "ensure-roots",
        "inspect-roots",
        "driver-launch",
        "letters-private",
        "letters-group",
    ] {
        validate_name(name).expect("command word is a lexical identity");
    }
}

fn registry_source(rows: &str) -> String {
    format!(
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{rows}]\n"
    )
}

fn registry_refusal(label: &str, source: &str, message: &str) {
    let directory = TestDir::new(label);
    directory.write_registry(source);
    let failure = load_registry(&directory.registry()).expect_err("invalid registry");
    assert_eq!(failure.status(), 2);
    assert_eq!(failure.message(), message);
}

/// A selected name is resolved only after the whole file has passed validation.
///
/// ´claim:loophome:an-unregistered-loop-is-refused-before-entry-planning´
/// ´test:crate:unknown-loop-is-a-status-two-refusal´
#[test]
fn unknown_loop_is_a_status_two_refusal() {
    let directory = TestDir::new("unknown");
    directory.write_registry(&registry_source(
        "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }",
    ));
    let failure = load_registry(&directory.registry())
        .expect("valid registry")
        .row("ghost", &directory.path)
        .expect_err("unknown row");
    assert_eq!(failure.status(), 2);
    assert_eq!(failure.message(), "unknown loop: ghost");
}

/// Unreadable bytes and invalid TOML are distinct whole-file refusals.
///
/// ´claim:loophome:malformed-registry-files-are-atomic-refusals´
/// ´test:crate:unreadable-and-malformed-toml-are-refused´
#[test]
fn unreadable_and_malformed_toml_are_refused() {
    let directory = TestDir::new("unreadable");
    let failure = load_registry(&directory.registry()).expect_err("missing file");
    assert_eq!(failure.status(), 2);
    assert_eq!(
        failure.message(),
        format!(
            "could not read loop registry: {}",
            directory.registry().display()
        )
    );
    registry_refusal(
        "malformed-toml",
        "namespace = [\n",
        "malformed loop registry",
    );
    registry_refusal(
        "malformed-loops",
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = 1\n",
        "malformed loop registry loops",
    );
}

/// The namespace and major version are fixed while newer minor and patch versions read.
///
/// ´claim:loophome:the-registry-version-contract-fixes-namespace-and-major-only´
/// ´test:crate:namespace-and-version-refusals-are-exact´
#[test]
fn namespace_and_version_refusals_are_exact() {
    registry_refusal(
        "namespace",
        "namespace = \"elsewhere\"\nversion = [1, 0, 0]\nloops = []\n",
        "wrong loop registry namespace",
    );
    registry_refusal(
        "version-form",
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0]\nloops = []\n",
        "malformed loop registry version",
    );
    registry_refusal(
        "major",
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [2, 0, 0]\nloops = []\n",
        "unsupported loop registry major version",
    );
    let directory = TestDir::new("future-minor");
    directory.write_registry(
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 9, 8]\nloops = []\n",
    );
    assert!(load_registry(&directory.registry()).is_ok());
}

/// Root, row and nested worker tables reject unknown keys.
///
/// ´claim:loophome:every-registry-table-has-a-closed-key-grammar´
/// ´test:crate:unknown-keys-at-every-level-are-refused´
#[test]
fn unknown_keys_at_every_level_are_refused() {
    registry_refusal(
        "root-key",
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = []\nextra = 1\n",
        "unknown registry key: extra",
    );
    registry_refusal(
        "row-key",
        &registry_source("{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", extra = 1 }"),
        "unknown loop row key: extra",
    );
    registry_refusal(
        "legacy-key",
        &registry_source(
            "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", legacy = { home = \"loops/alpha\", uid = 41001 } }",
        ),
        "unknown loop row key: legacy",
    );
}

/// Missing and malformed names refuse before a row can be selected.
///
/// ´claim:loophome:every-registry-row-has-a-valid-name´
/// ´test:crate:missing-and-malformed-row-names-are-refused´
#[test]
fn missing_and_malformed_row_names_are_refused() {
    registry_refusal(
        "missing-name",
        &registry_source("{ uid = 41001, launch = \"dev/alpha\" }"),
        "missing name in loop row 1",
    );
    registry_refusal(
        "malformed-name",
        &registry_source("{ name = 1, uid = 41001, launch = \"dev/alpha\" }"),
        "malformed name in loop row 1",
    );
}

/// UID syntax and the subordinate range are validated for every row.
///
/// ´claim:loophome:registry-uids-are-decimal-and-within-the-subordinate-range´
/// ´test:crate:every-uid-refusal-is-covered´
#[test]
fn every_uid_refusal_is_covered() {
    for (label, row, message) in [
        (
            "missing",
            "{ name = \"alpha\", launch = \"dev/alpha\" }",
            "missing uid for loop: alpha",
        ),
        (
            "malformed",
            "{ name = \"alpha\", uid = \"41001\", launch = \"dev/alpha\" }",
            "malformed uid for loop: alpha",
        ),
        (
            "low",
            "{ name = \"alpha\", uid = 999, launch = \"dev/alpha\" }",
            "uid out of range for loop: alpha",
        ),
        (
            "high",
            "{ name = \"alpha\", uid = 65536, launch = \"dev/alpha\" }",
            "uid out of range for loop: alpha",
        ),
    ] {
        registry_refusal(label, &registry_source(row), message);
    }
}

/// Launch directories are relative, nonempty and have no dot component.
///
/// ´claim:loophome:registry-launch-paths-stay-beneath-the-caller-home´
/// ´test:crate:missing-malformed-absolute-and-dotted-launches-are-refused´
#[test]
fn missing_malformed_absolute_and_dotted_launches_are_refused() {
    for (label, row, message) in [
        (
            "missing",
            "{ name = \"alpha\", uid = 41001 }",
            "missing launch for loop: alpha",
        ),
        (
            "malformed",
            "{ name = \"alpha\", uid = 41001, launch = 7 }",
            "malformed launch for loop: alpha",
        ),
        (
            "empty",
            "{ name = \"alpha\", uid = 41001, launch = \"\" }",
            "invalid launch for loop: alpha",
        ),
        (
            "absolute",
            "{ name = \"alpha\", uid = 41001, launch = \"/dev/alpha\" }",
            "invalid launch for loop: alpha",
        ),
        (
            "current",
            "{ name = \"alpha\", uid = 41001, launch = \"dev/./alpha\" }",
            "invalid launch for loop: alpha",
        ),
        (
            "parent",
            "{ name = \"alpha\", uid = 41001, launch = \"dev/../alpha\" }",
            "invalid launch for loop: alpha",
        ),
    ] {
        registry_refusal(label, &registry_source(row), message);
    }
}

/// A declared runs root is absolute and retains its spelling; an absent one is valid.
///
/// ´claim:loophome:registry-runs-roots-are-optional-absolute-and-undotted´
/// ´test:crate:registry-runs-root-grammar-and-refusals´
#[test]
fn registry_runs_root_grammar_and_refusals() {
    let base = "name = \"alpha\", uid = 41001, launch = \"dev/alpha\"";
    for (label, value, message) in [
        (
            "type",
            "1",
            "malformed runs_root for loop alpha: must be an absolute path string with no . or .. components",
        ),
        (
            "empty",
            "\"\"",
            "invalid runs_root for loop alpha: must be an absolute path with no . or .. components",
        ),
        (
            "relative",
            "\"runs\"",
            "invalid runs_root for loop alpha: must be an absolute path with no . or .. components",
        ),
        (
            "dot",
            "\"/runs/./alpha\"",
            "invalid runs_root for loop alpha: must be an absolute path with no . or .. components",
        ),
        (
            "parent",
            "\"/runs/../alpha\"",
            "invalid runs_root for loop alpha: must be an absolute path with no . or .. components",
        ),
    ] {
        registry_refusal(
            label,
            &registry_source(&format!("{{ {base}, runs_root = {value} }}")),
            message,
        );
    }
    let directory = TestDir::new("runs-root-optional");
    directory.write_registry(&registry_source(&format!("{{ {base} }}")));
    assert!(load_registry(&directory.registry()).is_ok());
}

/// An optional closed door floor survives both pathname and descriptor registry reads.
/// ´claim:entry:registry-door-floor-is-optional-and-closed´
/// ´test:crate:registry-door-floor-is-optional-and-closed´
#[test]
fn registry_door_floor_is_optional_and_closed() {
    let directory = TestDir::new("door-floor");
    directory.write_registry(&registry_source(
        "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }",
    ));
    let absent = load_registry(&directory.registry()).expect("absent floor");
    assert_eq!(
        absent
            .row("alpha", &directory.path)
            .expect("row")
            .door_floor,
        None
    );
    for (spelling, floor) in [
        ("audit", crate::registry::DoorFloor::Audit),
        ("enforce", crate::registry::DoorFloor::Enforce),
        ("allow", crate::registry::DoorFloor::Allow),
    ] {
        directory.write_registry(&registry_source(&format!(
            "{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", door_floor = \"{spelling}\" }}"
        )));
        let registry = load_registry(&directory.registry()).expect("floor");
        assert_eq!(
            registry
                .row("alpha", &directory.path)
                .expect("row")
                .door_floor,
            Some(floor)
        );
        let mut file = std::fs::File::open(directory.registry()).expect("descriptor");
        assert_eq!(
            crate::registry::load_registry_from_file(&mut file)
                .expect("descriptor parser")
                .row("alpha", &directory.path)
                .expect("row")
                .door_floor,
            Some(floor)
        );
    }
    for value in ["\"unknown\"", "1"] {
        registry_refusal(
            "invalid-door-floor",
            &registry_source(&format!(
                "{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", door_floor = {value} }}"
            )),
            "malformed door_floor for loop: alpha",
        );
    }
}

/// Former worker fields are refused as unknown registry row keys.
/// ´claim:entry:legacy-worker-keys-are-refused´
/// ´test:crate:legacy-worker-keys-are-refused´
#[test]
fn legacy_worker_keys_are_refused() {
    for field in ["workers", "claude_argv", "codex_argv", "default_driver"] {
        registry_refusal(
            field,
            &registry_source(&format!(
                "{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", {field} = 1 }}"
            )),
            &format!("unknown loop row key: {field}"),
        );
    }
}

/// Every helper used by the inner probe is resolved outside the entered search path.
///
/// ´claim:entry:verify-probe-ignores-loop-path-shadows´
/// ´test:crate:verify-probe-ignores-loop-path-shadows´
#[test]
fn verify_probe_ignores_loop_path_shadows() {
    let directory = TestDir::new("shadowed-verify-probe");
    let bin = directory.path.join(".local/bin");
    fs::create_dir_all(&bin).expect("loop-local bin");
    fs::create_dir(directory.path.join("alpha")).expect("git probe directory");
    for tool in [
        "id", "env", "sort", "sed", "git", "grep", "stat", "od", "sh",
    ] {
        let marker = bin.join(format!("{tool}.marker"));
        fs::write(
            bin.join(tool),
            format!(
                "#!/bin/sh\nprintf shadow > {}\n",
                shell_word(&marker.to_string_lossy())
            ),
        )
        .expect("shadow fixture");
        fs::set_permissions(bin.join(tool), fs::Permissions::from_mode(0o755))
            .expect("shadow mode");
    }
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(crate::verify::verification_script())
        .env("HOME", &directory.path)
        .env("USER", "alpha")
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .expect("fixed probe");
    assert!(output.status.success());
    assert!(output.stdout.starts_with(b"user="));
    assert!(output.stdout.ends_with(&[0]));
    for tool in [
        "id", "env", "sort", "sed", "git", "grep", "stat", "od", "sh",
    ] {
        assert!(!bin.join(format!("{tool}.marker")).exists());
    }
}

/// Fixed command paths do not rewrite command-shaped text inside quoted home data.
///
/// ´claim:entry:verify-scaffold-preserves-command-shaped-path-data´
/// ´test:crate:verify-scaffold-preserves-command-shaped-path-data´
#[test]
fn verify_scaffold_preserves_command_shaped_path_data() {
    let home = "/fixture/alpha\ncat /fixture/named";
    let tier = PathBuf::from("/fixture/tier\nmount --bind named");
    let row = record("alpha", 41001, home);
    let custody = Custody {
        tier: tier.clone(),
        executable: PathBuf::from("/fixture/superloop"),
    };
    let plan = verify_probe_plan(
        &row,
        Some(&custody),
        &[String::from("/usr/bin/podman")],
        "vt100",
        "C.UTF-8",
    );
    assert!(
        plan.outer_script
            .contains(&format!("h={}", shell_word(home)))
    );
    assert!(
        plan.inner_script
            .contains(&shell_word(&tier.to_string_lossy()))
    );
    assert!(!plan.outer_script.contains("/usr/bin/cat /fixture/named"));
    assert!(!plan.inner_script.contains("/usr/bin/mount --bind named"));
}

/// Checkout-controlled filters and search-path copies never run during the probe.
///
/// ´claim:entry:verify-probe-ignores-checkout-programs-and-leaves-home-unchanged´
/// ´test:crate:verify-probe-ignores-checkout-programs-and-leaves-home-unchanged´
#[test]
#[allow(clippy::too_many_lines)]
fn verify_probe_ignores_checkout_programs_and_leaves_home_unchanged() {
    let directory = TestDir::new("verify-git-read-only");
    let checkout = directory.path.join("alpha");
    let initialized = std::process::Command::new("/usr/bin/git")
        .args(["init", "-q"])
        .arg(&checkout)
        .env("HOME", &directory.path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("fixture checkout");
    assert!(initialized.status.success());
    fs::write(checkout.join("tracked"), "fixture\n").expect("tracked fixture");
    let added = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&checkout)
        .args(["add", "--", "tracked"])
        .output()
        .expect("fixture index");
    assert!(added.status.success());
    fs::write(checkout.join("processed"), "fixture\n").expect("process fixture");
    let added = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&checkout)
        .args(["add", "--", "processed"])
        .output()
        .expect("process fixture index");
    assert!(added.status.success());
    fs::write(
        checkout.join(".gitattributes"),
        "tracked filter=cleaned\nprocessed filter=process\n",
    )
    .expect("fixture attributes");
    let filter_marker = checkout.join("filter-ran");
    let filter = directory.path.join("clean-filter");
    fs::write(
        &filter,
        format!(
            "#!/bin/sh\nprintf ran > {}\n/usr/bin/cat\n",
            shell_word(&filter_marker.to_string_lossy())
        ),
    )
    .expect("clean filter");
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o755)).expect("filter mode");
    let configured = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&checkout)
        .args(["config", "filter.cleaned.clean"])
        .arg(&filter)
        .output()
        .expect("clean filter config");
    assert!(configured.status.success());
    let process_marker = checkout.join("process-ran");
    let process_filter = directory.path.join("process-filter");
    fs::write(
        &process_filter,
        format!(
            "#!/bin/sh\nprintf ran > {}\n/usr/bin/sleep 30\n",
            shell_word(&process_marker.to_string_lossy())
        ),
    )
    .expect("process filter");
    fs::set_permissions(&process_filter, fs::Permissions::from_mode(0o755))
        .expect("process filter mode");
    let configured = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&checkout)
        .args(["config", "filter.process.process"])
        .arg(&process_filter)
        .output()
        .expect("process filter config");
    assert!(configured.status.success());
    let planted = directory.path.join(".local/bin");
    fs::create_dir_all(&planted).expect("planted commands directory");
    let planted_marker = checkout.join("planted-ran");
    for program in ["git", "id", "env", "sort", "sed", "grep"] {
        let copy = planted.join(program);
        fs::write(
            &copy,
            format!(
                "#!/bin/sh\nprintf ran > {}\nexit 77\n",
                shell_word(&planted_marker.to_string_lossy())
            ),
        )
        .expect("planted command");
        fs::set_permissions(copy, fs::Permissions::from_mode(0o755)).expect("planted command mode");
    }
    let hook = directory.path.join("fsmonitor-hook");
    let marker = directory.path.join("fsmonitor-ran");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf ran > {}\n",
            shell_word(&marker.to_string_lossy())
        ),
    )
    .expect("fixture fsmonitor hook");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("hook mode");
    let configured = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&checkout)
        .args(["config", "core.fsmonitor"])
        .arg(&hook)
        .output()
        .expect("fixture fsmonitor config");
    assert!(configured.status.success());
    stale_atime(&checkout);
    stale_atime(&checkout.join("tracked"));
    stale_atime(&checkout.join("processed"));
    let before = root_tree_snapshot(&directory.path);
    let output = std::process::Command::new("/usr/bin/timeout")
        .args(["5", "/bin/sh", "-c"])
        .arg(crate::verify::verification_script())
        .env("HOME", &directory.path)
        .env("USER", "alpha")
        .env(
            "PATH",
            format!("{}/.local/bin:/usr/bin:/bin", directory.path.display()),
        )
        .output()
        .expect("checkout probe");
    assert!(output.status.success());
    assert!(
        !output
            .stdout
            .windows(b"git_warnings=".len())
            .any(|window| window == b"git_warnings=")
    );
    assert_eq!(before, root_tree_snapshot(&directory.path));
    assert!(!marker.exists());
    assert!(!filter_marker.exists());
    assert!(!process_marker.exists());
    assert!(!planted_marker.exists());
    assert!(!checkout.join(".git/index.lock").exists());
}

/// A newline in loop-visible data stays inside one framed field.
///
/// ´claim:entry:verify-probe-frames-loop-data-containing-report-lines´
/// ´test:crate:verify-probe-frames-loop-data-containing-report-lines´
#[test]
fn verify_probe_frames_loop_data_containing_report_lines() {
    let directory = TestDir::new("verify-framed-data");
    let planted = "vt100\nuid=9999\nuser=planted";
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(crate::verify::verification_script())
        .env("HOME", &directory.path)
        .env("USER", "alpha")
        .env("TERM", planted)
        .output()
        .expect("framed probe");
    assert!(output.status.success());
    let verification = assemble_verify(
        &output.stdout,
        b"mounts_left=0\ntmp_left=0\n",
        b"inspection 0 0 0\n[]\n",
        None,
        None,
    )
    .expect("framed fields");
    assert_eq!(
        verification.env.get("TERM").map(String::as_str),
        Some(planted)
    );
    assert_ne!(verification.uid, 9999);
    assert_ne!(verification.user, "planted");
}

/// Session, when present, must be a nonempty string.
///
/// ´claim:loophome:a-declared-session-is-nonempty´
/// ´test:crate:empty-and-malformed-sessions-are-refused´
#[test]
fn empty_and_malformed_sessions_are_refused() {
    for row in [
        "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", session = \"\" }",
        "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", session = 1 }",
    ] {
        registry_refusal(
            "session",
            &registry_source(row),
            "malformed session for loop: alpha",
        );
    }
}

/// Duplicate names and UIDs are refused even when the requested row is otherwise valid.
///
/// ´claim:loophome:no-two-loop-registry-records-share-one-uid´
/// ´test:crate:duplicate-names-and-uids-are-refused´
#[test]
fn duplicate_names_and_uids_are_refused() {
    registry_refusal(
        "duplicate-name",
        &registry_source(
            "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }, { name = \"alpha\", uid = 41002, launch = \"dev/alpha\" }",
        ),
        "duplicate loop name: alpha",
    );
    registry_refusal(
        "duplicate-uid",
        &registry_source(
            "{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }, { name = \"beta\", uid = 41001, launch = \"dev/beta\" }",
        ),
        "duplicate loop uid: 41001",
    );
}

/// Allocations are complete, bounded runs and every table is validated.
/// ´claim:entry:allocations-validate-all-ranges-and-overlaps´
/// ´test:crate:allocations-validate-all-ranges-and-overlaps´
#[test]
fn allocations_validate_all_ranges_and_overlaps() {
    use crate::allocations::Allocations;
    let allocations = Allocations::parse("[alpha]\nuids = { base = 40000, count = 256 }\n")
        .expect("valid allocations");
    let block = allocations.require("alpha").expect("alpha block");
    assert_eq!(block.top(), 40255);
    assert_eq!(block.uids().count(), 256);
    assert!(allocations.require("beta").is_err());
    assert_eq!(
        allocations.next_block().expect("first free block").base,
        3000
    );
    let occupied = Allocations::parse("[alpha]\nuids = { base = 3000, count = 64 }\n")
        .expect("occupied block");
    assert_eq!(occupied.next_block().expect("next free block").base, 3064);
    for source in [
        "[alpha]\nuids = { base = 999, count = 1 }\n",
        "[alpha]\nuids = { base = 65535, count = 2 }\n",
        "[alpha]\nuids = { base = 3000, count = 0 }\n",
        "[alpha]\nuids = { count = 2 }\n",
        "[alpha]\nuids = { base = 3000, count = 2, extra = 1 }\n",
        "[alpha]\nuids = { base = 3000, count = 2 }\n[beta]\nuids = { base = 3001, count = 2 }\n",
    ] {
        assert!(Allocations::parse(source).is_err(), "{source}");
    }
}

/// The reader pins and bounds its private file before parsing.
/// ´claim:entry:allocations-reader-refuses-unsafe-file-shapes´
/// ´test:crate:allocations-reader-refuses-unsafe-file-shapes´
#[test]
fn allocations_reader_refuses_unsafe_file_shapes() {
    use crate::allocations::{Allocations, allocations_path};
    let directory = TestDir::new_safe("allocation-custody");
    let path = allocations_path(&directory.path);
    write_allocation(
        &directory.path,
        "[alpha]\nuids = { base = 3000, count = 64 }\n",
    );
    assert_eq!(
        Allocations::read(&path)
            .expect("private ledger")
            .require("alpha")
            .expect("block")
            .base,
        3000
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose mode");
    assert!(Allocations::read(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
    fs::write(&path, "x".repeat(65_537)).expect("oversize fixture");
    assert!(Allocations::read(&path).is_err());
    fs::remove_file(&path).expect("remove ledger");
    assert!(Allocations::read(&path).is_err());
    assert!(Allocations::read_or_empty(&path).is_ok());
}

/// A worker block cannot contain the UID of its own loop or a peer loop.
/// ´claim:entry:allocations-reader-and-placement-exclude-every-registry-uid´
/// ´test:crate:allocations-reader-and-placement-exclude-every-registry-uid´
#[test]
fn allocations_reader_and_placement_exclude_every_registry_uid() {
    use crate::allocations::{Allocations, allocations_path};
    let directory = TestDir::new_safe("allocation-registry-uids");
    let path = allocations_path(&directory.path);
    write_allocation(
        &directory.path,
        "[alpha]\nuids = { base = 3000, count = 64 }\n",
    );
    let registry = path.with_file_name("registry.toml");
    fs::write(&registry, registry_source("{ name = \"alpha\", uid = 3000, launch = \"dev/alpha\" }, { name = \"beta\", uid = 4000, launch = \"dev/beta\" }")).expect("registry UIDs");
    assert!(
        Allocations::read(&path)
            .expect_err("own UID collision")
            .message()
            .contains("alpha")
    );
    fs::write(&path, "[alpha]\nuids = { base = 4000, count = 64 }\n").expect("peer collision");
    assert!(
        Allocations::read(&path)
            .expect_err("peer UID collision")
            .message()
            .contains("beta")
    );
    fs::write(&path, "").expect("empty ledger");
    assert_eq!(
        Allocations::read(&path)
            .expect("validated registry UIDs")
            .next_block()
            .expect("free block")
            .base,
        3001
    );
}

/// Vendor names belong to settings, while only the durable root is compared with the row.
/// ´claim:entry:workers-settings-grant-uses-settings-vendors´
/// ´test:crate:workers-settings-grant-uses-settings-vendors´
#[test]
fn workers_settings_grant_uses_settings_vendors() {
    use crate::workers_settings::{validate_workers_grant, validate_workers_settings};
    let row = record("alpha", 41001, "/fixture");
    let path = Path::new("workers.toml");
    let source = "backend_argv = { codex = [\"/usr/bin/codex\"] }\nvendor_hosts = { claude = [\"api.example.com\"] }\ndriver_argv = [\"/usr/bin/codex\"]\n";
    let settings = validate_workers_settings(source, path).expect("settings");
    validate_workers_grant(&settings, &row, None).expect("settings configure both vendors");
    let missing =
        validate_workers_settings("driver_argv = [\"/usr/bin/codex\"]\n", path).expect("settings");
    validate_workers_grant(&missing, &row, None)
        .expect("driver and backend are separate selectors");
    let widened = validate_workers_settings("runs_root = \"/outside\"\n", path).expect("settings");
    assert!(validate_workers_grant(&widened, &row, Some(Path::new("/fixture/runs"))).is_err());
}

/// ´claim:entry:workers-retention-accepts-only-keep´
/// ´test:crate:workers-retention-accepts-only-keep´
#[test]
fn workers_retention_accepts_only_keep() {
    use crate::workers_settings::validate_workers_settings;
    let path = Path::new("workers.toml");
    assert!(validate_workers_settings("retention = \"keep\"\n", path).is_ok());
    for source in ["retention = \"prune\"\n", "retention = 7\n"] {
        assert!(
            validate_workers_settings(source, path)
                .expect_err("unsupported retention")
                .message()
                .contains("retention-policy")
        );
    }
}

/// ´claim:entry:workers-retired-settings-name-the-complete-replacement´
/// ´test:crate:workers-retired-settings-name-the-complete-replacement´
#[test]
fn workers_retired_settings_name_the_complete_replacement() {
    use crate::workers_settings::validate_workers_settings;

    let path = Path::new("workers.toml");
    let replacement = "retired-setting: driver_bin; set driver_argv = [PATH, \"driver\", \"start\", \"--backend\", \"codex\"]";
    for source in [
        "driver_bin = '/retired/codex-lane'",
        "driver_bin = 42",
        "driver_bin = '/old'\nnever_valid = true",
    ] {
        assert_eq!(
            validate_workers_settings(source, path)
                .expect_err("retired setting")
                .message(),
            replacement
        );
    }
    assert_eq!(
        validate_workers_settings("never_valid = true", path)
            .expect_err("unknown setting")
            .message(),
        "unknown-setting: workers.toml: never_valid"
    );
}

/// Row order, derived paths and compact JSON are stable for other readers.
///
/// ´claim:loophome:validated-rows-derive-home-and-launch-in-file-order´
/// ´test:crate:rows-derive-paths-and-render-key-sorted-json´
#[test]
fn rows_derive_paths_and_render_key_sorted_json() {
    let directory = TestDir::new("row-order");
    directory.write_registry(&registry_source(
        "{ name = \"beta\", uid = 41002, launch = \"dev/beta\" }, { name = \"alpha\", uid = 41001, launch = \"dev/alpha\", runs_root = \"/fixture/runs//alpha/\", session = \"SESSION-ID\" }",
    ));
    let registry = load_registry(&directory.registry()).expect("valid registry");
    let home = PathBuf::from("/fixture");
    let rows = registry.rows(&home);
    assert_eq!(
        rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
        ["beta", "alpha"]
    );
    assert_eq!(rows[1].home, home.join(".var/loops/alpha"));
    assert_eq!(rows[1].launch, home.join("dev/alpha"));
    assert_eq!(
        registry.runs_root("alpha"),
        Some(Path::new("/fixture/runs//alpha/"))
    );
    assert_eq!(registry.runs_root("beta"), None);
    assert_eq!(
        rows[1].to_registry_json_with_runs_root(registry.runs_root("alpha")),
        "{\"launch\":\"/fixture/dev/alpha\",\"name\":\"alpha\",\"session\":\"SESSION-ID\",\"runs_root\":\"/fixture/runs//alpha/\",\"uid\":41001}"
    );
    assert_eq!(
        rows[0].to_registry_json(),
        "{\"launch\":\"/fixture/dev/beta\",\"name\":\"beta\",\"session\":null,\"uid\":41002}"
    );
}

/// The registry command accepts one name and has no report-selection option.
///
/// ´claim:loophome:registry-command-accepts-no-json-option´
/// ´test:crate:registry-command-refuses-json-report-selection´
#[test]
fn registry_command_refuses_json_report_selection() {
    for arguments in [
        vec!["--json", "show", "alpha"],
        vec!["show", "alpha", "--json"],
    ] {
        let failure = parse_invocation(
            OsStr::new("superloop"),
            arguments,
            None,
            Some(OsStr::new("/fixture")),
        )
        .expect_err("registry has no report option");
        assert_eq!(failure.status(), 2);
        assert!(failure.message().starts_with("usage: superloop "));
    }
}

/// Entry parsing diagnoses an empty command before any runner can be reached.
///
/// ´claim:loophome:every-entry-names-at-least-one-command-word´
/// ´test:crate:no-command-is-a-status-two-refusal´
#[test]
fn no_command_is_a_status_two_refusal() {
    let failure = parse_invocation(
        OsStr::new("superloop"),
        [OsString::from("enter"), OsString::from("alpha")],
        Some(OsStr::new("/fixture/root")),
        Some(OsStr::new("/fixture/caller")),
    )
    .expect_err("no command");
    assert_eq!(failure.status(), 2);
    assert_eq!(failure.message(), "no command for loop: alpha");
}

/// Resolution refuses before planning when neither native nor host-spawned podman is available.
///
/// ´claim:loophome:podman-resolution-has-two-fallbacks-and-fails-closed´
/// ´test:crate:missing-podman-is-a-status-two-refusal´
#[test]
fn missing_podman_is_a_status_two_refusal() {
    let failure = resolve_podman(None, Some(OsStr::new(""))).expect_err("missing podman");
    assert_eq!(failure.status(), 2);
    assert_eq!(failure.message(), "podman not found");
}

/// Verify chooses a fixed native executable before a fixed host launcher.
///
/// ´claim:entry:verify-resolver-prefers-system-podman´
/// ´test:crate:verify-resolver-prefers-system-podman´
#[test]
fn verify_resolver_prefers_system_podman() {
    let mut looked = Vec::new();
    let route = resolve_verify_podman_with(|path| {
        looked.push(path.to_path_buf());
        Ok(path == Path::new("/bin/podman"))
    })
    .expect("native route");
    assert_eq!(route, ["/bin/podman"]);
    assert_eq!(
        looked,
        ["/usr/bin/podman", "/bin/podman"].map(PathBuf::from)
    );
}

/// A host launcher keeps its own and the host Podman paths fixed.
///
/// ´claim:entry:verify-resolver-uses-fixed-host-route´
/// ´test:crate:verify-resolver-uses-fixed-host-route´
#[test]
fn verify_resolver_uses_fixed_host_route() {
    let route = resolve_verify_podman_with(|path| Ok(path == Path::new("/usr/bin/flatpak-spawn")))
        .expect("host route");
    assert_eq!(
        route,
        ["/usr/bin/flatpak-spawn", "--host", "/usr/bin/podman"]
    );
}

/// An installation with neither route fails before inspection with status one.
///
/// ´claim:entry:verify-resolver-names-missing-system-routes´
/// ´test:crate:verify-resolver-names-missing-system-routes´
#[test]
fn verify_resolver_names_missing_system_routes() {
    let mut looked = Vec::new();
    let failure = resolve_verify_podman_with(|path| {
        looked.push(path.to_path_buf());
        Ok(false)
    })
    .expect_err("no route");
    assert_eq!(failure.status(), 1);
    assert_eq!(
        failure.message(),
        "verify has no system container route; looked for podman and flatpak-spawn in /usr/bin, /bin, /usr/local/bin"
    );
    assert_eq!(
        looked,
        [
            "/usr/bin/podman",
            "/bin/podman",
            "/usr/local/bin/podman",
            "/usr/bin/flatpak-spawn",
            "/bin/flatpak-spawn",
            "/usr/local/bin/flatpak-spawn",
        ]
        .map(PathBuf::from)
    );
}

fn system_program_fixture(label: &str) -> (TestDir, PathBuf, PathBuf, u32) {
    let directory = TestDir::new(label);
    let bin = directory.path.join("bin");
    let libexec = directory.path.join("libexec");
    fs::create_dir(&bin).expect("fixture bin");
    fs::create_dir(&libexec).expect("fixture libexec");
    for path in [&directory.path, &bin, &libexec] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("trusted directory mode");
    }
    (
        directory,
        bin,
        libexec,
        nix::unistd::Uid::effective().as_raw(),
    )
}

/// The same no-follow check accepts regular files and both lengths of trusted link chain.
///
/// ´claim:entry:verify-system-program-accepts-regular-and-linked-executables´
/// ´test:crate:verify-system-program-accepts-regular-and-linked-executables´
#[test]
fn verify_system_program_accepts_regular_and_linked_executables() {
    let (directory, bin, libexec, owner) = system_program_fixture("system-program-links");
    let target = libexec.join("program");
    fs::write(&target, b"#!/bin/sh\nexit 0\n").expect("fixture executable");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("executable mode");
    assert_eq!(
        inspect_system_program_from(&target, &directory.path, owner),
        Ok(true)
    );
    symlink("../libexec/program", bin.join("podman")).expect("first link");
    symlink("podman", bin.join("flatpak-spawn")).expect("second link");
    for name in ["podman", "flatpak-spawn"] {
        assert_eq!(
            inspect_system_program_from(&bin.join(name), &directory.path, owner),
            Ok(true)
        );
    }
    let route = resolve_verify_podman_in(&[&bin], |path| {
        inspect_system_program_from(path, &directory.path, owner)
    })
    .expect("linked native route");
    assert_eq!(route, [bin.join("podman").to_string_lossy().into_owned()]);
    fs::remove_file(bin.join("podman")).expect("remove native candidate");
    fs::remove_file(bin.join("flatpak-spawn")).expect("replace two-link candidate");
    symlink("../libexec/program", bin.join("flatpak-spawn")).expect("host route link");
    let route = resolve_verify_podman_in(&[&bin], |path| {
        inspect_system_program_from(path, &directory.path, owner)
    })
    .expect("linked host route");
    assert_eq!(
        route,
        [
            bin.join("flatpak-spawn").to_string_lossy().into_owned(),
            String::from("--host"),
            String::from("/usr/bin/podman"),
        ]
    );
}

/// A missing target, a nonexecutable target, and excessive links each state the fault.
///
/// ´claim:entry:verify-system-program-refuses-broken-and-long-link-chains´
/// ´test:crate:verify-system-program-refuses-broken-and-long-link-chains´
#[test]
fn verify_system_program_refuses_broken_and_long_link_chains() {
    let (directory, bin, libexec, owner) = system_program_fixture("system-program-refusals");
    symlink("../libexec/absent", bin.join("dangling")).expect("dangling link");
    let reason = inspect_system_program_from(&bin.join("dangling"), &directory.path, owner)
        .expect_err("missing target");
    assert!(reason.contains("dangling link"), "{reason}");
    symlink("bin", directory.path.join("bin-alias")).expect("directory link");
    assert_eq!(
        inspect_system_program_from(
            &directory.path.join("bin-alias/absent"),
            &directory.path,
            owner
        ),
        Ok(false)
    );
    let target = libexec.join("not-executable");
    fs::write(&target, b"fixture").expect("fixture file");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("nonexecutable mode");
    symlink("../libexec/not-executable", bin.join("nonexecutable")).expect("nonexecutable link");
    let reason = inspect_system_program_from(&bin.join("nonexecutable"), &directory.path, owner)
        .expect_err("nonexecutable target");
    assert!(reason.contains("not executable"), "{reason}");
    let links = directory.path.join("links");
    fs::create_dir(&links).expect("links directory");
    fs::set_permissions(&links, fs::Permissions::from_mode(0o755)).expect("links mode");
    for index in 0..=crate::app::MAX_SYSTEM_PROGRAM_LINKS {
        let next = if index == crate::app::MAX_SYSTEM_PROGRAM_LINKS {
            String::from("../libexec/not-executable")
        } else {
            format!("link-{}", index + 1)
        };
        symlink(next, links.join(format!("link-{index}"))).expect("chain link");
    }
    symlink("../links/link-0", bin.join("overlong")).expect("entry link");
    let reason = inspect_system_program_from(&bin.join("overlong"), &directory.path, owner)
        .expect_err("bounded link chain");
    assert!(reason.contains("link chain exceeds"), "{reason}");
}

/// Directory and target write access are refused; link mode alone is not write access.
///
/// ´claim:entry:verify-system-program-refuses-untrusted-ownership-and-write-modes´
/// ´test:crate:verify-system-program-refuses-untrusted-ownership-and-write-modes´
#[test]
fn verify_system_program_refuses_untrusted_ownership_and_write_modes() {
    let (directory, bin, libexec, owner) = system_program_fixture("system-program-trust");
    let target = libexec.join("program");
    fs::write(&target, b"fixture").expect("fixture file");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o775)).expect("writable target");
    symlink("../libexec/program", bin.join("podman")).expect("trusted link");
    let reason = inspect_system_program_from(&bin.join("podman"), &directory.path, owner)
        .expect_err("writable target");
    assert!(reason.contains("permits group or other writes"), "{reason}");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("secure target");
    fs::set_permissions(&libexec, fs::Permissions::from_mode(0o777)).expect("writable directory");
    let reason = inspect_system_program_from(&bin.join("podman"), &directory.path, owner)
        .expect_err("writable holding directory");
    assert!(reason.contains("permits group or other writes"), "{reason}");
    assert!(trusted_system_component(41001, 0o755, 0, false).is_err());
    assert!(trusted_system_component(0, 0o777, 0, false).is_err());
    assert!(trusted_system_component(0, 0o777, 0, true).is_ok());
}

/// The base no-route words remain, followed by candidate-specific refusal reasons.
///
/// ´claim:entry:verify-resolver-reports-present-refused-candidates´
/// ´test:crate:verify-resolver-reports-present-refused-candidates´
#[test]
fn verify_resolver_reports_present_refused_candidates() {
    let (directory, bin, libexec, owner) = system_program_fixture("system-route-reasons");
    let target = libexec.join("program");
    fs::write(&target, b"fixture").expect("fixture file");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("nonexecutable mode");
    symlink("../libexec/program", bin.join("podman")).expect("native link");
    symlink("../libexec/missing", bin.join("flatpak-spawn")).expect("host link");
    let failure = resolve_verify_podman_in(&[&bin], |path| {
        inspect_system_program_from(path, &directory.path, owner)
    })
    .expect_err("neither route is usable");
    assert_eq!(failure.status(), 1);
    assert!(failure.message().starts_with("verify has no system container route; looked for podman and flatpak-spawn in /usr/bin, /bin, /usr/local/bin\nrefused system candidates:"));
    assert!(
        failure
            .message()
            .contains(&format!("{}: ", bin.join("podman").display()))
    );
    assert!(failure.message().contains("not executable"));
    assert!(
        failure
            .message()
            .contains(&format!("{}: ", bin.join("flatpak-spawn").display()))
    );
    assert!(failure.message().contains("dangling link"));
}

/// Provisioning runs exactly the private ensure step in one namespace-root command.
///
/// ´claim:loophome:provision-is-the-ensure-step-alone´
/// ´test:crate:provision-plan-is-one-exact-ensure-command´
#[test]
fn provision_plan_is_one_exact_ensure_command() {
    let record = record("alpha", 41001, "/srv/alpha");
    let plan = provision_plan(
        &record,
        Path::new("/fixture/superloop"),
        Path::new("/caller"),
        Path::new("/fixture/report"),
        &[String::from("podman")],
    );
    assert_eq!(
        plan.command.argv,
        [
            "podman",
            "unshare",
            "sh",
            "-c",
            "set -e\n\n/fixture/superloop ensure-roots 41001 alpha /caller /fixture/report\n/fixture/superloop _mail-provision /caller alpha"
        ]
        .map(String::from)
    );
    assert_eq!(plan.command.label, "provision");
}

/// The verify command consumes only scripted runner responses and emits a deterministic object.
///
/// ´claim:loophome:verification-combines-inside-identity-environment-and-post-entry-leak-counts´
/// ´test:crate:verify-json-assembles-from-scripted-runner-output´
#[test]
fn verify_json_assembles_from_scripted_runner_output() {
    let record = record("alpha", 41001, "/srv/alpha");
    let entry = verify_probe_plan(&record, None, &[String::from("podman")], "vt100", "C.UTF-8");
    let cleanup = cleanup_probe_plan(&record, &[String::from("podman")]);
    let mut runner = ScriptedRunner {
        replies: VecDeque::from([
            Reply {
                label: "verify-entry",
                status: 0,
                stdout: b"user=alpha\0uid=41001\0groups=41001\0home=/srv/alpha\0env=USER=alpha\0env=HOME=/srv/alpha\0env=GNUPGHOME=/srv/alpha/.config/custody/gpg\0env=GH_CONFIG_DIR=/srv/alpha/.config/custody/gh\0".to_vec(),
            },
            Reply {
                label: "verify-cleanup",
                status: 0,
                stdout: b"mounts_left=0\ntmp_left=0\n".to_vec(),
            },
        ]),
        commands: Vec::new(),
    };
    let inside = runner.run(&entry.command).expect("scripted entry");
    let after = runner.run(&cleanup).expect("scripted cleanup");
    let verification = assemble_verify(
        &inside.stdout,
        &after.stdout,
        b"inspection 3 1 1\n[{\"action\":\"create\"},{\"action\":\"correct\"}]\n",
        Some(41001),
        Some(vec![String::from("LOOP_UID: env=41002 row=41001")]),
    )
    .expect("valid probes");
    assert_eq!(
        verification.to_json(),
        "{\"account_uid\":41001,\"env\":{\"GH_CONFIG_DIR\":\"/srv/alpha/.config/custody/gh\",\"GNUPGHOME\":\"/srv/alpha/.config/custody/gpg\",\"HOME\":\"/srv/alpha\",\"USER\":\"alpha\"},\"groups\":[41001],\"home\":\"/srv/alpha\",\"mounts_left\":0,\"probe\":{\"made\":true},\"registry_drift\":[\"LOOP_UID: env=41002 row=41001\"],\"roots\":[{\"action\":\"create\"},{\"action\":\"correct\"}],\"tmp_left\":0,\"uid\":41001,\"user\":\"alpha\",\"would_correct\":1,\"would_create\":1}"
    );
    let script = &cleanup.argv[4];
    assert!(script.contains(
        "/etc/passwd /etc/group /etc/ssh/ssh_config.d \"$h/.config/custody\" \"$h/.ssh\""
    ));
    assert_eq!(script.matches("for target ").count(), 1);
    assert_eq!(runner.commands, [entry.command, cleanup]);
}

/// An empty root inspection report cannot prove that the step completed.
///
/// ´claim:loophome:verify-requires-a-root-inspection-summary´
/// ´test:crate:verify-refuses-a-missing-root-inspection-report´
#[test]
fn verify_refuses_a_missing_root_inspection_report() {
    let failure = assemble_verify(b"", b"", b"", None, None).expect_err("missing inspection");
    assert_eq!(failure.status(), 1);
    assert!(
        failure
            .message()
            .contains("root inspection report omitted summary")
    );
}

/// The summary's new statuses require matching rows and per-row counts.
///
/// ´claim:entry:verify-refuses-root-status-without-matching-decisions´
/// ´test:crate:verify-refuses-root-status-without-matching-decisions´
#[test]
fn verify_refuses_root_status_without_matching_decisions() {
    for report in [
        "inspection 3 0 0\n[]\n",
        "inspection 4 0 0\n[]\n",
        "inspection 0 1 0\n[{\"action\":\"create\"}]\n",
        "inspection 3 2 0\n[{\"action\":\"create\"}]\n",
    ] {
        let failure = crate::verify::RootAudit::parse(report.as_bytes())
            .expect_err("inconsistent root inspection");
        assert_eq!(failure.status(), 1);
        assert_eq!(
            failure.message(),
            "root inspection summary differs from rows"
        );
    }
}

/// A complete inspection with no decisions gives the verify object empty rows.
///
/// ´claim:loophome:verify-assembles-an-empty-root-inspection-report´
/// ´test:crate:verify-assembles-an-empty-root-inspection-report´
#[test]
fn verify_assembles_an_empty_root_inspection_report() {
    let verification = assemble_verify(
        b"user=alpha\0uid=41001\0groups=41001\0home=/fixture\0",
        b"mounts_left=0\ntmp_left=0\n",
        b"inspection 0 0 0\n[]\n",
        None,
        None,
    )
    .expect("empty inspection report");
    assert_eq!(
        verification.roots,
        crate::verify::RootAudit {
            status: 0,
            would_create: 0,
            would_correct: 0,
            rows_json: String::from("[]"),
        }
    );
    assert!(verification.to_json().contains("\"roots\":[]"));
}

/// ´claim:entry:verify-refuses-missing-empty-and-malformed-groups´
/// ´test:crate:verify-refuses-missing-empty-and-malformed-groups´
#[test]
fn verify_refuses_missing_empty_and_malformed_groups() {
    for (field, expected) in [
        ("", "verify probe omitted groups"),
        ("groups=\0", "verify probe has empty groups"),
        ("groups=  \0", "verify probe has empty groups"),
        ("groups=unknown\0", "verify probe has invalid groups"),
    ] {
        let probe = format!("user=alpha\0uid=41001\0{field}home=/fixture\0");
        let failure = assemble_verify(
            probe.as_bytes(),
            b"mounts_left=0\ntmp_left=0\n",
            b"inspection 0 0 0\n[]\n",
            None,
            None,
        )
        .expect_err("unmeasured groups are not empty measured groups");
        assert_eq!(failure.status(), 1);
        assert_eq!(failure.message(), expected);
    }
}

fn account_path(directory: &TestDir) -> PathBuf {
    directory.path.join(".claude/superloop/accounts/alpha/uid")
}

/// A loop can have a row before its owner-run pod account exists.
///
/// ´claim:loophome:verify-reports-an-absent-account-uid-as-null´
/// ´test:crate:missing-account-uid-is-null´
#[test]
fn missing_account_uid_is_null() {
    let directory = TestDir::new("account-absent");
    assert_eq!(
        account_uid(&record("alpha", 41001, "/fixture"), &directory.path).expect("absent account"),
        None
    );
}

/// Surrounding whitespace does not change a valid decimal account UID.
///
/// ´claim:loophome:verify-reads-the-owner-account-uid-at-composition´
/// ´test:crate:matching-account-uid-is-read´
#[test]
fn matching_account_uid_is_read() {
    let directory = TestDir::new("account-equal");
    let path = account_path(&directory);
    fs::create_dir_all(path.parent().expect("account parent")).expect("account parent");
    fs::write(&path, b" 41001 \n").expect("account uid");
    assert_eq!(
        account_uid(&record("alpha", 41001, "/fixture"), &directory.path).expect("account uid"),
        Some(41001)
    );
}

/// A different valid account UID remains visible for the entry's status-one check.
///
/// ´claim:loophome:verify-observes-account-uid-disagreement´
/// ´test:crate:different-account-uid-is-read´
#[test]
fn different_account_uid_is_read() {
    let directory = TestDir::new("account-different");
    let path = account_path(&directory);
    fs::create_dir_all(path.parent().expect("account parent")).expect("account parent");
    fs::write(&path, b"41002\n").expect("account uid");
    assert_eq!(
        account_uid(&record("alpha", 41001, "/fixture"), &directory.path).expect("account uid"),
        Some(41002)
    );
}

/// A present malformed or linked account file names its path in a runtime error.
///
/// ´claim:loophome:verify-refuses-malformed-or-linked-account-uid-files´
/// ´test:crate:malformed-account-uid-is-a-runtime-error´
#[test]
fn malformed_account_uid_is_a_runtime_error() {
    let directory = TestDir::new("account-malformed");
    let path = account_path(&directory);
    fs::create_dir_all(path.parent().expect("account parent")).expect("account parent");
    for bytes in [b"999\n".as_slice(), b"65536\n", b"uid\n", b"41001\n41002\n"] {
        fs::write(&path, bytes).expect("account uid");
        let failure = account_uid(&record("alpha", 41001, "/fixture"), &directory.path)
            .expect_err("malformed account uid");
        assert_eq!(failure.status(), 1);
        assert!(
            failure
                .message()
                .contains(&path.to_string_lossy().to_string())
        );
    }
    fs::remove_file(&path).expect("remove account file");
    let target = directory.path.join("target");
    fs::write(&target, b"41001\n").expect("target");
    symlink(&target, &path).expect("linked account file");
    assert!(account_uid(&record("alpha", 41001, "/fixture"), &directory.path).is_err());
}

fn env_path(directory: &TestDir) -> PathBuf {
    directory
        .path
        .join(".local/share/superloop-tools/loops.d/alpha.env")
}

fn drift_record(directory: &TestDir) -> LoopRecord {
    let mut selected = record("alpha", 41001, "/fixture");
    selected.launch = directory.path.join("dev/alpha");
    selected.session = Some(String::from("SESSION-ID"));
    selected
}

fn write_env(directory: &TestDir, content: &str) {
    let path = env_path(directory);
    fs::create_dir_all(path.parent().expect("env parent")).expect("env parent");
    fs::write(path, content).expect("env file");
}

/// A loop can have no legacy env file while migration is in progress.
///
/// ´claim:loophome:verify-reports-an-absent-env-file-as-null´
/// ´test:crate:missing-env-file-has-null-drift´
#[test]
fn missing_env_file_has_null_drift() {
    let directory = TestDir::new("env-absent");
    assert_eq!(
        registry_drift(&drift_record(&directory), &directory.path).expect("absent env"),
        None
    );
}

/// Equal mapped fields yield a present empty drift list, including quoted assignments.
///
/// ´claim:loophome:verify-compares-all-four-mapped-env-fields´
/// ´test:crate:matching-env-file-has-empty-drift´
#[test]
fn matching_env_file_has_empty_drift() {
    let directory = TestDir::new("env-equal");
    write_env(
        &directory,
        &format!(
            "# old reader format\nexport LOOP_NAME='alpha'\nLOOP_UID=41001\nLOOP_CWD=\"{}\"\nLOOP_SID=SESSION-ID\nLOOP_HOME=ignored\n",
            directory.path.join("dev/alpha").display()
        ),
    );
    assert_eq!(
        registry_drift(&drift_record(&directory), &directory.path).expect("matching env"),
        Some(Vec::new())
    );
}

/// One changed mapped field is reported without making verification a refusal.
///
/// ´claim:loophome:verify-names-a-differing-env-field´
/// ´test:crate:one-differing-env-field-is-reported´
#[test]
fn one_differing_env_field_is_reported() {
    let directory = TestDir::new("env-different");
    write_env(
        &directory,
        &format!(
            "LOOP_NAME=alpha\nLOOP_UID=41002\nLOOP_CWD={}\nLOOP_SID=SESSION-ID\n",
            directory.path.join("dev/alpha").display()
        ),
    );
    assert_eq!(
        registry_drift(&drift_record(&directory), &directory.path).expect("different env"),
        Some(vec![String::from("LOOP_UID: env=41002 row=41001")])
    );
}

/// Missing values on either side say absent in schema order.
///
/// ´claim:loophome:verify-names-env-fields-absent-on-either-side´
/// ´test:crate:env-fields-absent-on-either-side-are-reported´
#[test]
fn env_fields_absent_on_either_side_are_reported() {
    let directory = TestDir::new("env-missing-field");
    let mut selected = drift_record(&directory);
    selected.session = None;
    write_env(
        &directory,
        &format!(
            "LOOP_NAME=alpha\nLOOP_CWD={}\nLOOP_SID=STALE\n",
            directory.path.join("dev/alpha").display()
        ),
    );
    assert_eq!(
        registry_drift(&selected, &directory.path).expect("missing fields"),
        Some(vec![
            String::from("LOOP_UID: env=absent row=41001"),
            String::from("LOOP_SID: env=STALE row=absent"),
        ])
    );
    let path = env_path(&directory);
    fs::remove_file(&path).expect("remove env file");
    symlink(directory.path.join("target"), &path).expect("linked env file");
    assert!(registry_drift(&selected, &directory.path).is_err());
}

/// The entry's report file has private mode and is removed when its guard ends.
///
/// ´claim:loophome:entry-report-is-private-and-removed-after-reading´
/// ´test:crate:entry-report-file-has-mode-0600-and-is-removed´
#[test]
fn entry_report_file_has_mode_0600_and_is_removed() {
    let directory = TestDir::new("report-file");
    let path;
    {
        let report = ReportFile::create_in(&directory.path).expect("create report");
        path = report.path.clone();
        assert_eq!(
            fs::metadata(&path).expect("report metadata").mode() & 0o777,
            0o600
        );
        fs::write(&path, b"created /fixture/new 0700\nwall 42\n").expect("write report");
        let parsed =
            EnsureReport::parse(&report.read().expect("read report")).expect("parse report");
        assert_eq!(parsed.created, ["/fixture/new"]);
        assert_eq!(parsed.micros, Some(42));
    }
    assert!(!path.exists());
}

/// The composition-time tier test never follows the tier's own symbolic link.
///
/// ´claim:loophome:composition-refuses-a-nondirectory-custody-tier´
/// ´test:crate:entry-custody-follows-no-symbolic-link-at-the-tier´
#[test]
fn entry_custody_follows_no_symbolic_link_at_the_tier() {
    let directory = TestDir::new("tier-type");
    let record = record("alpha", 41001, "/srv/alpha");
    let tier = custody_tier(&directory.path, "alpha");
    assert_eq!(
        entry_custody(&directory.path, &record, Path::new("/fixture/superloop"))
            .expect("absent tier"),
        None
    );
    fs::create_dir_all(&tier).expect("create tier");
    assert_eq!(
        entry_custody(&directory.path, &record, Path::new("/fixture/superloop"))
            .expect("directory tier")
            .expect("custody")
            .tier,
        tier
    );
    fs::remove_dir(&tier).expect("remove tier");
    let elsewhere = directory.path.join("elsewhere");
    fs::create_dir(&elsewhere).expect("create destination");
    symlink(&elsewhere, &tier).expect("link tier");
    let failure = entry_custody(&directory.path, &record, Path::new("/fixture/superloop"))
        .expect_err("link refused");
    assert_eq!(failure.status(), 2);
    assert_eq!(
        failure.message(),
        format!("custody tier is not a directory: {}", tier.display())
    );
    fs::remove_file(&tier).expect("remove link");
    fs::write(&tier, b"file").expect("write file");
    assert_eq!(
        entry_custody(&directory.path, &record, Path::new("/fixture/superloop"))
            .expect_err("file refused")
            .status(),
        2
    );
}

fn custody_fixture(directory: &TestDir, private: bool) -> (PathBuf, PathBuf, PathBuf, u32) {
    let home = directory.path.join("home");
    let entered = if private {
        home.join("private")
    } else {
        home.clone()
    };
    let tier = directory.path.join("tier");
    fs::create_dir_all(entered.join(".config/custody")).expect("create custody target");
    fs::create_dir(entered.join(".ssh")).expect("create ssh target");
    fs::create_dir_all(tier.join("ssh")).expect("create ssh source");
    let uid = fs::metadata(&home).expect("home metadata").uid();
    (home, entered, tier, uid)
}

/// Pinning returns exactly the directories opened in either entered-home form.
///
/// ´claim:loophome:pinning-holds-the-checked-bind-endpoints´
/// ´test:crate:pinning-accepts-loop-owned-directories-and-holds-what-it-checked´
#[test]
fn pinning_accepts_loop_owned_directories_and_holds_what_it_checked() {
    use nix::sys::stat::fstat;
    for private in [false, true] {
        let directory = TestDir::new(if private { "pin-private" } else { "pin-base" });
        let (home, entered, tier, uid) = custody_fixture(&directory, private);
        let pinned = pin_custody(uid, &home, &entered, &tier).expect("loop-owned directories");
        let custody_target = entered.join(".config/custody");
        let ssh_source = tier.join("ssh");
        let ssh_target = entered.join(".ssh");
        for (fd, path) in [
            (&pinned.tier, tier.as_path()),
            (&pinned.custody_target, custody_target.as_path()),
            (&pinned.ssh_source, ssh_source.as_path()),
            (&pinned.ssh_target, ssh_target.as_path()),
        ] {
            let stat = fstat(fd).expect("pinned stat");
            let metadata = fs::metadata(path).expect("fixture stat");
            assert_eq!((stat.st_dev, stat.st_ino), (metadata.dev(), metadata.ino()));
        }
    }
}

/// Every loop-controlled directory component refuses a planted symbolic link at open.
///
/// ´claim:loophome:pinning-never-follows-loop-controlled-symbolic-links´
/// ´test:crate:pinning-refuses-a-symbolic-link-at-every-loop-controlled-component´
#[test]
fn pinning_refuses_a_symbolic_link_at_every_loop_controlled_component() {
    for component in ["private", ".config", ".config/custody", ".ssh", "tier/ssh"] {
        let directory = TestDir::new("pin-link");
        let (home, entered, tier, uid) = custody_fixture(&directory, true);
        let path = if component == "private" {
            entered.clone()
        } else if component == "tier/ssh" {
            tier.join("ssh")
        } else {
            entered.join(component)
        };
        let moved = directory.path.join("moved");
        fs::rename(&path, &moved).expect("move component");
        symlink(&moved, &path).expect("plant link");
        let failure = pin_custody(uid, &home, &entered, &tier).expect_err("symbolic link refused");
        assert!(matches!(failure.reason.as_str(), "ELOOP" | "ENOTDIR"));
        assert!(failure.path.starts_with(&path) || path.starts_with(&failure.path));
    }
}

/// Ownership is checked on every opened descriptor before either bind.
///
/// ´claim:loophome:pinning-requires-loop-ownership-of-every-directory´
/// ´test:crate:pinning-refuses-a-directory-the-loop-uid-does-not-own´
#[test]
fn pinning_refuses_a_directory_the_loop_uid_does_not_own() {
    let directory = TestDir::new("pin-owner");
    let (home, entered, tier, uid) = custody_fixture(&directory, false);
    let failure = pin_custody(uid + 1, &home, &entered, &tier).expect_err("wrong uid");
    assert_eq!(failure.path, home);
    assert_eq!(
        failure.reason,
        format!("not a directory owned by uid {}", uid + 1)
    );
}

/// The private step has one argument form and refuses all alternatives with status two.
///
/// ´claim:loophome:bind-custody-accepts-only-its-four-validated-arguments´
/// ´test:crate:bind-custody-refuses-every-other-argument-form´
#[test]
fn bind_custody_refuses_every_other_argument_form() {
    for args in [
        vec!["41001", "/home", "/home"],
        vec!["999", "/home", "/home", "/tier"],
        vec!["word", "/home", "/home", "/tier"],
        vec!["41001", "home", "/home", "/tier"],
    ] {
        let mut error = Vec::new();
        assert_eq!(bind_custody_entry(args, &mut error), 2);
        assert_eq!(
            error,
            b"usage: superloop bind-custody UID LOOP_HOME ENTERED TIER\n"
        );
    }
    let mut error = Vec::new();
    assert_eq!(
        bind_custody_entry(["41001", "/home", "/wrong", "/tier"], &mut error),
        1
    );
    assert_eq!(
        error,
        b"custody bind refused: /wrong: not the registry home or its private tier\n"
    );
    let mut error = Vec::new();
    assert_eq!(
        bind_custody_entry(["41001", "/home", "/home/.", "/tier"], &mut error),
        1
    );
    assert_eq!(
        error,
        b"custody bind refused: /home/.: not the registry home or its private tier\n"
    );
}

fn ensure_fixture(label: &str) -> (TestDir, PathBuf, Vec<StandardRoot>, u32) {
    let directory = TestDir::new(label);
    let home = directory.path.join("home");
    fs::create_dir(&home).expect("fixture home");
    for (name, mode) in [(".var", 0o711), (".cache", 0o711), (".config", 0o700)] {
        let path = home.join(name);
        fs::create_dir(&path).expect("fixture class root");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("class mode");
    }
    let uid = fs::metadata(&home).expect("fixture owner").uid();
    let rows = standard_roots(&home, "alpha");
    (directory, home, rows, uid)
}

fn run_fixture(rows: &[StandardRoot], uid: u32) -> (crate::ensure::EnsureCounts, String) {
    let mut report = Vec::new();
    let counts = ensure_roots(rows, uid, uid, &mut report).expect("ensure fixture");
    (counts, String::from_utf8(report).expect("UTF-8 report"))
}

/// ´claim:entry:ordinary-roots-preserve-inert-legacy-stores-without-provisioning-them´
/// ´test:crate:ordinary-roots-preserve-inert-legacy-stores-without-provisioning-them´
#[test]
fn ordinary_roots_preserve_inert_legacy_stores_without_provisioning_them() {
    let (_directory, home, rows, uid) = ensure_fixture("ordinary roots");
    run_fixture(&rows, uid);
    let old = home.join(".var/loops/alpha/inbox/new");
    assert!(!old.exists());
    fs::create_dir_all(&old).expect("inert migration source");
    fs::write(old.join("retained"), b"opaque\0history").expect("history");
    assert_eq!(run_fixture(&rows, uid).0, crate::EnsureCounts::default());
    assert_eq!(
        fs::read(old.join("retained")).expect("unchanged history"),
        b"opaque\0history"
    );
    assert!(!home.join(".config/loops/allocations.toml").exists());
}

/// ´claim:entry:shared-group-correction-reports-old-and-new-gid´
/// ´test:crate:shared-group-correction-reports-old-and-new-gid´
#[test]
fn shared_group_correction_reports_old_and_new_gid() {
    assert_eq!(
        crate::ensure::correction_line(
            Path::new("/fixture/inbox"),
            0o710,
            0o710,
            Some((41001, 3001))
        ),
        "corrected /fixture/inbox 0710 0710 gid 41001 3001"
    );
    assert_eq!(
        crate::ensure::correction_line(Path::new("/fixture/inbox"), 0o700, 0o710, None),
        "corrected /fixture/inbox 0700 0710"
    );
    let (_directory, home, mut rows, uid) = ensure_fixture("group correction gid report");
    let gid = fs::metadata(&home).expect("owner metadata").gid();
    rows.push(StandardRoot {
        path: home.join(".var/loops/alpha/inbox"),
        owner: RootOwner::Shared(gid),
        mode: 0o710,
        ensure: EnsureClass::Created,
    });
    run_fixture(&rows, uid);
    let inbox = home.join(".var/loops/alpha/inbox");
    let metadata = fs::metadata(&inbox).expect("inbox metadata");
    let old_gid = if gid == 2899 { 2989 } else { 2899 };
    // Other fixture roots retain the real process group. Only the inbox's
    // observed group is injected; ensure still executes the correction syscall.
    for row in &mut rows {
        if matches!(row.owner, RootOwner::Loop | RootOwner::Policy) {
            row.owner = RootOwner::Owner;
        }
    }
    crate::ensure::OBSERVED_GROUP.with(|group| {
        group.set(Some((metadata.dev(), metadata.ino(), old_gid)));
    });
    let mut bytes = Vec::new();
    let result = crate::ensure_roots(&rows, (uid, gid), (uid, old_gid), &mut bytes);
    crate::ensure::OBSERVED_GROUP.with(|group| group.set(None));
    let counts = result.expect("group correction through ensure");
    assert_eq!(counts.created, 0);
    assert_eq!(counts.corrected, 1);
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("report text"),
        format!(
            "corrected {} 0710 0710 gid {old_gid} {gid}\n",
            inbox.display()
        )
    );
    let report = EnsureReport::parse(&bytes).expect("parse actual correction report");
    assert_eq!(report.corrected, [inbox.to_string_lossy().into_owned()]);
    assert_eq!(report.created, Vec::<String>::new());
    assert_eq!(fs::metadata(&inbox).expect("corrected inbox").gid(), gid);
}

/// ´claim:entry:ensure-report-parses-decimal-group-suffix-and-refuses-malformed-groups´
/// ´test:crate:ensure-report-parses-decimal-group-suffix-and-refuses-malformed-groups´
#[test]
fn ensure_report_parses_decimal_group_suffix_and_refuses_malformed_groups() {
    for line in [
        "corrected /fixture/path with spaces 0700 0710 gid 2899 3988\n",
        "corrected /fixture/path with spaces 0700 0710\n",
    ] {
        let parsed = EnsureReport::parse(line.as_bytes()).expect("valid correction");
        assert_eq!(parsed.corrected, ["/fixture/path with spaces"]);
    }
    for suffix in [
        "x 3988",
        "2899 x",
        "+2899 3988",
        "2899 -1",
        "4294967296 3988",
        "2899 4294967296",
        " 3988",
        "2899 ",
        "2899",
    ] {
        let line = format!("corrected /fixture/inbox 0710 0710 gid {suffix}\n");
        let error = EnsureReport::parse(line.as_bytes()).expect_err("invalid decimal suffix");
        assert_eq!(error.status(), 1);
        assert_eq!(error.message(), "malformed corrected report line");
    }
}

/// The fixture derivation pins every path and all three table columns in order.
///
/// ´claim:loophome:standard-roots-follow-the-estate-loop-roots-table´
/// ´test:crate:standard-roots-pin-all-table-rows´
#[test]
fn standard_roots_pin_all_table_rows() {
    use EnsureClass::{Checked, Created, CreatedWhenParentPresent, WhenPresent};
    use RootOwner::{Loop, Owner};
    let (_directory, home, rows, _uid) = ensure_fixture("rows");
    let expected = [
        (".var", Owner, 0o711, Checked),
        (".cache", Owner, 0o711, Checked),
        (".var/loops", Owner, 0o711, Created),
        (".var/loops/alpha", Owner, 0o711, Created),
        (".var/loops/alpha/private", Loop, 0o700, Created),
        (".var/loops/alpha/private/.run", Loop, 0o700, Created),
        (".var/loops/alpha/private/.config", Loop, 0o700, Created),
        (
            ".var/loops/alpha/private/.config/custody",
            Loop,
            0o700,
            Created,
        ),
        (".var/loops/alpha/private/.ssh", Loop, 0o700, Created),
        (".var/loops/alpha/private/.local", Loop, 0o700, Created),
        (".var/loops/alpha/private/.local/bin", Loop, 0o700, Created),
        (
            ".var/loops/alpha/private/.local/share",
            Loop,
            0o700,
            Created,
        ),
        (
            ".var/loops/alpha/private/.local/state",
            Loop,
            0o700,
            Created,
        ),
        (".var/loops/alpha/shared", Loop, 0o750, Created),
        (".var/loops/alpha/src", Loop, 0o700, Created),
        (".var/loops/alpha/direct", Loop, 0o700, Created),
        (
            ".var/loops/alpha/policy",
            RootOwner::Policy,
            0o2750,
            Created,
        ),
        (".var/loops/alpha/runs", Owner, 0o711, Created),
        (".config/loops", Owner, 0o700, Created),
        (".config/loops/alpha", Owner, 0o700, Created),
        (".config/loops/alpha/lanes", Owner, 0o700, Created),
        (".config/loops/alpha/lanes/keys", Owner, 0o700, Created),
        (".config/loops/alpha/private", Loop, 0o700, WhenPresent),
        (".config/loops/alpha/private/ssh", Loop, 0o700, WhenPresent),
        (".config/loops/alpha/private/gpg", Loop, 0o700, WhenPresent),
        (
            ".config/loops/alpha/private/gh",
            Loop,
            0o700,
            CreatedWhenParentPresent,
        ),
        (".cache/loops", Owner, 0o711, Created),
        (".cache/loops/alpha", Loop, 0o700, Created),
        (".cache/loops/alpha/tmp", Loop, 0o700, Created),
    ];
    assert_eq!(rows.len(), expected.len());
    assert_eq!(
        rows,
        expected
            .into_iter()
            .map(|(path, owner, mode, ensure)| StandardRoot {
                path: home.join(path),
                owner,
                mode,
                ensure
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row.ensure, Checked | Created))
            .count(),
        25
    );
    assert!(!rows.iter().any(|row| row.path == home.join(".config")));
}

/// Empty partitions acquire every created row with its final owner and mode.
///
/// ´claim:loophome:ensure-creates-every-missing-standard-root-in-table-order´
/// ´test:crate:ensure-creates-all-required-rows-and-reports-in-order´
#[test]
fn ensure_creates_all_required_rows_and_reports_in_order() {
    let (_directory, _home, rows, uid) = ensure_fixture("create");
    let (counts, report) = run_fixture(&rows, uid);
    assert_eq!(counts.created, 23);
    assert_eq!(counts.corrected, 0);
    let mut expected = String::new();
    for row in rows.iter().filter(|row| row.ensure == EnsureClass::Created) {
        writeln!(
            &mut expected,
            "created {} {:04o}",
            row.path.display(),
            row.mode
        )
        .expect("format expected report");
    }
    assert_eq!(report, expected);
    for row in rows
        .iter()
        .filter(|row| matches!(row.ensure, EnsureClass::Checked | EnsureClass::Created))
    {
        let metadata = fs::metadata(&row.path).expect("created row");
        assert!(metadata.is_dir(), "{}", row.path.display());
        assert_eq!(metadata.uid(), uid, "{}", row.path.display());
        assert_eq!(metadata.mode() & 0o7777, row.mode, "{}", row.path.display());
    }
    for row in rows.iter().filter(|row| {
        matches!(
            row.ensure,
            EnsureClass::WhenPresent | EnsureClass::CreatedWhenParentPresent
        )
    }) {
        assert!(!row.path.exists(), "{}", row.path.display());
    }
}

/// A second run has no filesystem work to report.
///
/// ´claim:loophome:ensure-is-idempotent-on-a-complete-tree´
/// ´test:crate:ensure-leaves-a-complete-tree-unchanged´
#[test]
fn ensure_leaves_a_complete_tree_unchanged() {
    let (_directory, _home, rows, uid) = ensure_fixture("idempotent");
    run_fixture(&rows, uid);
    let (counts, report) = run_fixture(&rows, uid);
    assert_eq!(counts, crate::ensure::EnsureCounts::default());
    assert_eq!(report, "");
}

/// Each complete row contributes one descriptor open and one stat, plus the caller's config root.
///
/// ´claim:loophome:complete-ensure-costs-one-open-and-stat-per-row´
/// ´test:crate:complete-ensure-counts-one-open-and-stat-per-row´
#[test]
fn complete_ensure_counts_one_open_and_stat_per_row() {
    let (_directory, _home, rows, uid) = ensure_fixture("syscall-cost");
    run_fixture(&rows, uid);
    reset_syscall_counts();
    run_fixture(&rows, uid);
    let required = rows
        .iter()
        .filter(|row| matches!(row.ensure, EnsureClass::Checked | EnsureClass::Created))
        .count()
        + 1;
    assert_eq!(syscall_counts(), (required, required));
    for row in &rows[22..26] {
        fs::create_dir(&row.path).expect("custody row");
        fs::set_permissions(&row.path, fs::Permissions::from_mode(row.mode)).expect("custody mode");
    }
    reset_syscall_counts();
    run_fixture(&rows, uid);
    assert_eq!(syscall_counts(), (rows.len() + 1, rows.len() + 1));
}

#[derive(Debug, PartialEq, Eq)]
struct SnapshotEntry {
    path: PathBuf,
    kind: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
    atime: (i64, i64),
    content: Vec<u8>,
}

#[allow(unsafe_code)]
fn snapshot_children(path: &Path) -> Vec<PathBuf> {
    use std::os::fd::IntoRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let fd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME | libc::O_DIRECTORY)
        .open(path)
        .expect("snapshot directory without atime update")
        .into_raw_fd();
    // SAFETY: fdopendir owns fd; each entry name is copied before the next readdir.
    unsafe {
        let directory = libc::fdopendir(fd);
        assert!(!directory.is_null(), "snapshot fdopendir");
        let mut children = Vec::new();
        loop {
            *libc::__errno_location() = 0;
            let entry = libc::readdir(directory);
            if entry.is_null() {
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(0));
                break;
            }
            let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
            if name != b"." && name != b".." {
                children.push(path.join(OsStr::from_bytes(name)));
            }
        }
        assert_eq!(libc::closedir(directory), 0);
        children.sort();
        children
    }
}

fn root_tree_snapshot(home: &Path) -> Vec<SnapshotEntry> {
    fn visit(home: &Path, path: &Path, entries: &mut Vec<SnapshotEntry>) {
        use std::io::Read as _;
        let metadata = fs::symlink_metadata(path).expect("snapshot entry");
        let kind = if metadata.is_dir() {
            "directory"
        } else if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        let mut content = Vec::new();
        if metadata.is_file() {
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOATIME)
                .open(path)
                .expect("snapshot file without atime update")
                .read_to_end(&mut content)
                .expect("snapshot content");
        }
        entries.push(SnapshotEntry {
            path: path
                .strip_prefix(home)
                .expect("inside fixture")
                .to_path_buf(),
            kind,
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            atime: (metadata.atime(), metadata.atime_nsec()),
            content,
        });
        if metadata.is_dir() {
            for child in snapshot_children(path) {
                visit(home, &child, entries);
            }
        }
    }
    let mut entries = Vec::new();
    visit(home, home, &mut entries);
    entries
}

fn stale_atime(path: &Path) {
    let metadata = fs::metadata(path).expect("stale atime metadata");
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME)
        .open(path)
        .expect("stale atime descriptor");
    file.set_times(
        fs::FileTimes::new()
            .set_accessed(std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000))
            .set_modified(metadata.modified().expect("fixture modification time")),
    )
    .expect("stale atime");
}

fn prepare_inspection_case(rows: &[StandardRoot], uid: u32, case: &str) {
    if case != "missing" {
        run_fixture(rows, uid);
    }
    if case == "mode" {
        fs::set_permissions(&rows[13].path, fs::Permissions::from_mode(0o700))
            .expect("wrong fixture mode");
    }
}

/// Each observation leaves every fixture entry unchanged and predicts the mutating step.
///
/// ´claim:entry:verify-root-observations-match-ensure-on-copies-without-changing-fixtures´
/// ´test:crate:verify-root-observations-match-ensure-on-copies-without-changing-fixtures´
#[test]
#[allow(clippy::print_stdout)] // An opt-in report capture makes each fixture's JSON auditable.
fn verify_root_observations_match_ensure_on_copies_without_changing_fixtures() {
    for (case, expected_status) in [("missing", 3), ("mode", 3), ("owner", 4), ("complete", 0)] {
        let (_observed_dir, observed_home, observed_rows, uid) = ensure_fixture(case);
        let (_copy_dir, _copy_home, copy_rows, copy_uid) = ensure_fixture(case);
        prepare_inspection_case(&observed_rows, uid, case);
        prepare_inspection_case(&copy_rows, copy_uid, case);
        let gid = fs::metadata(&observed_rows[0].path)
            .expect("fixture class")
            .gid();
        let loop_id = (uid + u32::from(case == "owner"), gid);
        if observed_rows[3].path.is_dir() {
            stale_atime(&observed_rows[3].path);
        }
        let before = root_tree_snapshot(&observed_home);
        let inspection = inspect_roots(&observed_rows, (uid, gid), loop_id);
        let after = root_tree_snapshot(&observed_home);
        assert_eq!(before, after, "{case}: verify changed a fixture entry");
        assert_eq!(inspection.status(), expected_status, "{case}: status");
        assert_eq!(inspection.observations.len(), observed_rows.len() + 1);
        assert_eq!(
            inspection.to_json().matches("\"path\":").count(),
            observed_rows.len() + 1
        );
        if std::env::var_os("LOOP_HOME_SHOW_FIXTURE_REPORTS").is_some() {
            let counts = inspection.would_counts();
            let rows_json = inspection.to_json();
            let bytes = format!(
                "inspection {} {} {}\n{rows_json}\n",
                inspection.status(),
                counts.created,
                counts.corrected
            );
            let audit = crate::verify::RootAudit::parse(bytes.as_bytes())
                .expect("fixture inspection report");
            let report = if expected_status == 0 {
                let entry = format!(
                    "user=alpha\0uid=41001\0groups=41001\0home={}\0",
                    observed_rows[4].path.display()
                );
                assemble_verify(
                    entry.as_bytes(),
                    b"mounts_left=0\ntmp_left=0\n",
                    bytes.as_bytes(),
                    None,
                    None,
                )
                .expect("complete fixture report")
                .to_json()
            } else {
                let reason = if expected_status == 4 {
                    "the ensure step would refuse a home entry"
                } else {
                    "the ensure step would create or correct a home entry"
                };
                audit.skipped_json(reason, None, None)
            };
            println!("FIXTURE-REPORT case={case} status={expected_status} {report}");
        }
        let mut report = Vec::new();
        let other_group_id = fs::metadata(&copy_rows[0].path).expect("copy class").gid();
        let result = crate::ensure_roots(
            &copy_rows,
            (copy_uid, other_group_id),
            (copy_uid + u32::from(case == "owner"), other_group_id),
            &mut report,
        );
        if case == "owner" {
            let failure = result.expect_err("owner mismatch must refuse");
            assert_eq!(failure.path, copy_rows[4].path);
            assert!(inspection.observations.iter().any(|row| {
                row.path == observed_rows[4].path && matches!(row.action, RootAction::Refuse(_))
            }));
            assert_eq!(report, Vec::<u8>::new());
        } else {
            let actual = result.expect("ensure the copied fixture");
            assert_eq!(inspection.would_counts(), actual, "{case}: would-do");
        }
        if case == "missing" {
            assert!(
                inspection
                    .observations
                    .iter()
                    .any(|row| row.kind == "missing" && row.action == RootAction::Create)
            );
        }
    }
}

/// A refused class root does not make its descendants appear observable or creatable.
///
/// ´claim:entry:verify-names-unseen-descendants-of-a-refused-class-root´
/// ´test:crate:verify-names-unseen-descendants-of-a-refused-class-root´
#[test]
fn verify_names_unseen_descendants_of_a_refused_class_root() {
    let (_directory, home, rows, uid) = ensure_fixture("missing-class-root");
    fs::remove_dir(home.join(".var")).expect("remove fixture class root");
    let gid = fs::metadata(&rows[1].path).expect("cache class").gid();
    let before = root_tree_snapshot(&home);
    let inspection = inspect_roots(&rows, (uid, gid), (uid, gid));
    assert_eq!(inspection.status(), 4);
    assert!(inspection.would_counts().created > 0);
    assert_eq!(before, root_tree_snapshot(&home));
    assert!(inspection.observations.iter().any(|row| {
        row.path == rows[2].path
            && row.kind == "unseen"
            && matches!(row.action, RootAction::Unseen(_))
    }));
    assert!(inspection.observations.iter().any(|row| {
        row.path == rows[0].path
            && row.kind == "missing"
            && matches!(row.action, RootAction::Refuse(_))
    }));
}

/// Opening failures precede row checks; row checks precede population checks.
///
/// ´claim:entry:ensure-retains-first-refusal-for-multiple-home-faults´
/// ´test:crate:ensure-retains-first-refusal-for-multiple-home-faults´
#[test]
fn ensure_retains_first_refusal_for_multiple_home_faults() {
    let (_directory, home, rows, uid) = ensure_fixture("opening-before-mode");
    fs::set_permissions(&rows[0].path, fs::Permissions::from_mode(0o700)).expect("wrong var mode");
    fs::remove_dir(&rows[1].path).expect("missing cache root");
    let failure = ensure_roots(&rows, uid, uid, &mut Vec::new()).expect_err("missing class root");
    assert_eq!(failure.path, rows[1].path);
    assert_eq!(failure.reason, "ENOENT: No such file or directory");

    let (_directory, _home, rows, uid) = ensure_fixture("linked-before-mode");
    fs::set_permissions(&rows[0].path, fs::Permissions::from_mode(0o700)).expect("wrong var mode");
    symlink("/fixture/elsewhere", &rows[2].path).expect("linked durable root");
    let failure = ensure_roots(&rows, uid, uid, &mut Vec::new()).expect_err("linked row");
    assert_eq!(failure.path, rows[2].path);
    assert_eq!(failure.reason, "a symbolic link");

    let (_directory, _home, rows, uid) = ensure_fixture("mode-before-owner");
    run_fixture(&rows, uid);
    fs::set_permissions(&rows[0].path, fs::Permissions::from_mode(0o700)).expect("wrong var mode");
    let failure = ensure_roots(&rows, uid, uid + 1, &mut Vec::new()).expect_err("multiple faults");
    assert_eq!(failure.path, rows[0].path);
    assert_eq!(failure.reason, "mode 0700, no search permission for others");

    let (_directory, _home, rows, uid) = ensure_fixture("mode-before-population");
    fs::create_dir(&rows[2].path).expect("durable root");
    fs::create_dir(&rows[3].path).expect("loop root");
    fs::write(rows[3].path.join("foreign"), "fixture").expect("populated loop root");
    fs::set_permissions(&rows[0].path, fs::Permissions::from_mode(0o700)).expect("wrong var mode");
    let failure = ensure_roots(&rows, uid, uid, &mut Vec::new()).expect_err("multiple faults");
    assert_eq!(failure.path, rows[0].path);
    assert_eq!(failure.reason, "mode 0700, no search permission for others");
    assert!(home.is_dir());
}

fn complete_trace_fixture(label: &str) -> (TestDir, PathBuf, Vec<StandardRoot>, u32) {
    let fixture = ensure_fixture(label);
    run_fixture(&fixture.2, fixture.3);
    for row in fixture.2.iter().filter(|row| {
        matches!(
            row.ensure,
            EnsureClass::WhenPresent | EnsureClass::CreatedWhenParentPresent
        )
    }) {
        fs::create_dir(&row.path).expect("optional fixture row");
        fs::set_permissions(&row.path, fs::Permissions::from_mode(row.mode))
            .expect("optional fixture mode");
    }
    fixture
}

fn expected_base_opening_trace(rows: &[StandardRoot], home: &Path) -> Vec<(String, PathBuf)> {
    let mut trace = Vec::new();
    for row in rows.iter().filter(|row| row.ensure == EnsureClass::Checked) {
        trace.push((
            String::from("open O_PATH|O_CLOEXEC|O_NOFOLLOW"),
            row.path.clone(),
        ));
        trace.push((String::from("fstat"), row.path.clone()));
    }
    let config = home.join(".config");
    trace.push((
        String::from("open O_PATH|O_CLOEXEC|O_NOFOLLOW"),
        config.clone(),
    ));
    trace.push((String::from("fstat"), config));
    for row in rows.iter().filter(|row| row.ensure != EnsureClass::Checked) {
        let operation = if row
            .path
            .parent()
            .is_some_and(|parent| parent.ends_with(".var/loops"))
        {
            "openat2 O_RDONLY"
        } else {
            "openat2 O_PATH"
        };
        trace.push((operation.to_owned(), row.path.clone()));
    }
    trace
}

/// Every table row pins the base preparing order, flags and first failed open.
///
/// ´claim:entry:prepare-walk-matches-base-opens-for-complete-home-and-each-table-refusal´
/// ´test:crate:prepare-walk-matches-base-opens-for-complete-home-and-each-table-refusal´
#[test]
fn prepare_walk_matches_base_opens_for_complete_home_and_each_table_refusal() {
    let (_directory, home, rows, uid) = complete_trace_fixture("prepare-complete-trace");
    let mut expected = expected_base_opening_trace(&rows, &home);
    expected.extend(
        rows.iter()
            .filter(|row| row.ensure != EnsureClass::Checked)
            .map(|row| (String::from("fstat"), row.path.clone())),
    );
    begin_prepare_trace();
    run_fixture(&rows, uid);
    assert_eq!(end_prepare_trace(), expected, "complete home trace");

    for target in 0..rows.len() {
        let (_directory, home, rows, uid) = complete_trace_fixture("prepare-refusal-trace");
        fs::remove_dir_all(&rows[target].path).expect("remove refused fixture row");
        symlink("/fixture/elsewhere", &rows[target].path).expect("refused linked row");
        let mut expected = Vec::new();
        for row in rows.iter().filter(|row| row.ensure == EnsureClass::Checked) {
            expected.push((
                String::from("open O_PATH|O_CLOEXEC|O_NOFOLLOW"),
                row.path.clone(),
            ));
            expected.push((String::from("fstat"), row.path.clone()));
            if row.path == rows[target].path {
                break;
            }
        }
        if rows[target].ensure != EnsureClass::Checked {
            let config = home.join(".config");
            expected.push((
                String::from("open O_PATH|O_CLOEXEC|O_NOFOLLOW"),
                config.clone(),
            ));
            expected.push((String::from("fstat"), config));
            for row in rows.iter().filter(|row| row.ensure != EnsureClass::Checked) {
                let operation = if row
                    .path
                    .parent()
                    .is_some_and(|parent| parent.ends_with(".var/loops"))
                {
                    "openat2 O_RDONLY"
                } else {
                    "openat2 O_PATH"
                };
                expected.push((operation.to_owned(), row.path.clone()));
                if row.path == rows[target].path {
                    break;
                }
            }
        }
        begin_prepare_trace();
        let gid = fs::metadata(&home).expect("fixture group").gid();
        let failure = crate::ensure_roots(&rows, (uid, gid), (uid, gid), &mut Vec::new())
            .expect_err("linked row");
        assert_eq!(failure.path, rows[target].path);
        assert_eq!(end_prepare_trace(), expected, "table row {target}");
    }
}

/// A check failure ends after the base opening pass, without reading a later row.
///
/// ´claim:entry:prepare-walk-returns-at-first-check-failure´
/// ´test:crate:prepare-walk-returns-at-first-check-failure´
#[test]
fn prepare_walk_returns_at_first_check_failure() {
    let (_directory, home, rows, uid) = complete_trace_fixture("prepare-check-refusal");
    fs::set_permissions(&rows[0].path, fs::Permissions::from_mode(0o700))
        .expect("checked root mode");
    begin_prepare_trace();
    let failure = ensure_roots(&rows, uid, uid + 1, &mut Vec::new()).expect_err("mode refusal");
    assert_eq!(failure.path, rows[0].path);
    assert_eq!(
        end_prepare_trace(),
        expected_base_opening_trace(&rows, &home)
    );

    let (_directory, home, rows, uid) = complete_trace_fixture("prepare-owner-refusal");
    begin_prepare_trace();
    let failure = ensure_roots(&rows, uid, uid + 1, &mut Vec::new()).expect_err("owner refusal");
    assert_eq!(
        failure.path,
        rows.iter()
            .find(|row| row.owner == RootOwner::Loop)
            .expect("loop row")
            .path
    );
    let mut expected = expected_base_opening_trace(&rows, &home);
    for row in &rows {
        if row.ensure != EnsureClass::Checked {
            expected.push((String::from("fstat"), row.path.clone()));
        }
        if matches!(row.owner, RootOwner::Loop | RootOwner::Policy) {
            break;
        }
    }
    assert_eq!(end_prepare_trace(), expected);
}

/// Every table-derived opening fault takes precedence over a checked-root mode fault.
///
/// ´claim:entry:prepare-walk-prioritizes-table-opening-faults-over-checked-modes´
/// ´test:crate:prepare-walk-prioritizes-table-opening-faults-over-checked-modes´
#[test]
fn prepare_walk_prioritizes_table_opening_faults_over_checked_modes() {
    let (_directory, _home, rows, _uid) = ensure_fixture("prepare-pair-table");
    let checked = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (row.ensure == EnsureClass::Checked).then_some(index))
        .collect::<Vec<_>>();
    let opened = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (row.ensure != EnsureClass::Checked).then_some(index))
        .collect::<Vec<_>>();
    let mut cases = 0;
    for class_index in &checked {
        for row_index in &opened {
            let (_directory, home, rows, uid) = complete_trace_fixture("prepare-pair");
            fs::set_permissions(&rows[*class_index].path, fs::Permissions::from_mode(0o700))
                .expect("checked mode fault");
            fs::remove_dir_all(&rows[*row_index].path).expect("remove linked row");
            symlink("/fixture/elsewhere", &rows[*row_index].path).expect("linked row");
            let gid = fs::metadata(&home).expect("fixture group").gid();
            let failure = crate::ensure_roots(&rows, (uid, gid), (uid, gid), &mut Vec::new())
                .expect_err("opening fault wins");
            assert_eq!(failure.path, rows[*row_index].path);
            assert_eq!(failure.reason, "a symbolic link");
            cases += 1;
        }
    }
    assert_eq!(cases, checked.len() * opened.len());
}

/// A denied no-atime open falls back to a readable open and names the row.
///
/// ´claim:entry:verify-marks-a-row-when-noatime-is-refused´
/// ´test:crate:verify-marks-a-row-when-noatime-is-refused´
#[test]
fn verify_marks_a_row_when_noatime_is_refused() {
    let (_directory, _home, rows, uid) = complete_trace_fixture("verify-noatime-denied");
    let gid = fs::metadata(&rows[0].path).expect("class group").gid();
    deny_inspection_noatime(true);
    let inspection = inspect_roots(&rows, (uid, gid), (uid, gid));
    deny_inspection_noatime(false);
    let loop_row = rows
        .iter()
        .find(|row| {
            row.path
                .parent()
                .is_some_and(|parent| parent.ends_with(".var/loops"))
        })
        .expect("readable loop row");
    let observed = inspection
        .observations
        .iter()
        .find(|row| row.path == loop_row.path)
        .expect("observed loop row");
    assert!(observed.atime_may_have_changed);
    assert_eq!(observed.action, RootAction::Nothing);
    assert!(
        inspection
            .to_json()
            .contains("\"atime_may_have_changed\":true")
    );
}

/// The actual process runner pins the child search path for all verify commands.
///
/// ´claim:entry:process-runner-pins-verification-search-path´
/// ´test:crate:process-runner-pins-verification-search-path´
#[test]
fn process_runner_pins_verification_search_path() {
    for label in ["verify-roots", "verify-entry", "verify-cleanup"] {
        let request = crate::planner::CommandSpec::new(
            label,
            vec![String::from("/usr/bin/env")],
            IoMode::Capture,
        );
        let output = crate::ProcessRunner
            .run(&request)
            .expect("fixed system env");
        assert_eq!(output.status, 0);
        assert!(
            output
                .stdout
                .windows(b"PATH=/usr/local/bin:/usr/bin:/bin\n".len())
                .any(|part| part == b"PATH=/usr/local/bin:/usr/bin:/bin\n")
        );
    }
}

/// An existing row's mode is corrected without replacing its directory.
///
/// ´claim:loophome:ensure-corrects-an-existing-mode-and-reports-both-modes´
/// ´test:crate:ensure-corrects-a-differing-mode´
#[test]
fn ensure_corrects_a_differing_mode() {
    let (_directory, _home, rows, uid) = ensure_fixture("mode");
    run_fixture(&rows, uid);
    let row = &rows[13];
    fs::set_permissions(&row.path, fs::Permissions::from_mode(0o700)).expect("change mode");
    let (counts, report) = run_fixture(&rows, uid);
    assert_eq!(counts.created, 0);
    assert_eq!(counts.corrected, 1);
    assert_eq!(
        report,
        format!("corrected {} 0700 0750\n", row.path.display())
    );
    assert_eq!(fs::metadata(&row.path).expect("row").mode() & 0o7777, 0o750);
}

/// A foreign owner stops the first pass before any mode correction.
///
/// ´claim:loophome:ensure-refuses-a-foreign-owned-row-before-changes´
/// ´test:crate:ensure-refuses-a-wrong-loop-uid-without-changing-any-row´
#[test]
fn ensure_refuses_a_wrong_loop_uid_without_changing_any_row() {
    let (_directory, _home, rows, uid) = ensure_fixture("owner");
    run_fixture(&rows, uid);
    fs::set_permissions(&rows[13].path, fs::Permissions::from_mode(0o700)).expect("mode drift");
    let mut report = Vec::new();
    let failure = ensure_roots(&rows, uid, uid + 1, &mut report).expect_err("owner refusal");
    assert_eq!(failure.path, rows[4].path);
    assert_eq!(
        failure.reason,
        format!("owned by uid {uid}, expected uid {}", uid + 1)
    );
    assert_eq!(report, Vec::<u8>::new());
    assert_eq!(
        fs::metadata(&rows[13].path).expect("drift").mode() & 0o7777,
        0o700
    );
}

/// A differing group refuses the row before a later mode could be corrected.
///
/// ´claim:loophome:ensure-checks-each-row-group-with-its-owner´
/// ´test:crate:ensure-refuses-a-wrong-loop-gid-without-changing-any-row´
#[test]
fn ensure_refuses_a_wrong_loop_gid_without_changing_any_row() {
    let (_directory, _home, rows, uid) = ensure_fixture("group");
    run_fixture(&rows, uid);
    fs::set_permissions(&rows[13].path, fs::Permissions::from_mode(0o700)).expect("mode drift");
    let gid = fs::metadata(&rows[0].path).expect("class gid").gid();
    let mut report = Vec::new();
    let failure = crate::ensure_roots(&rows, (uid, gid), (uid, gid + 1), &mut report)
        .expect_err("group refusal");
    assert_eq!(failure.path, rows[4].path);
    assert_eq!(
        failure.reason,
        format!("owned by gid {gid}, expected gid {}", gid + 1)
    );
    assert_eq!(report, Vec::<u8>::new());
    assert_eq!(
        fs::metadata(&rows[13].path).expect("mode drift").mode() & 0o7777,
        0o700
    );
}

/// A file and a link at a required row are refused before missing rows are made.
///
/// ´claim:loophome:ensure-refuses-nondirectories-and-symbolic-links-without-changes´
/// ´test:crate:ensure-refuses-a-file-and-a-symbolic-link-by-path´
#[test]
fn ensure_refuses_a_file_and_a_symbolic_link_by_path() {
    for symbolic in [false, true] {
        let (_directory, home, rows, uid) = ensure_fixture("type");
        let path = &rows[2].path;
        if symbolic {
            symlink(&home, path).expect("plant link");
        } else {
            fs::write(path, b"file").expect("plant file");
        }
        let mut report = Vec::new();
        let failure = ensure_roots(&rows, uid, uid, &mut report).expect_err("type refusal");
        assert_eq!(failure.path, *path);
        assert_eq!(
            failure.reason,
            if symbolic {
                "a symbolic link"
            } else {
                "not a directory"
            }
        );
        assert_eq!(report, Vec::<u8>::new());
        assert!(!rows[16].path.exists());
    }
}

/// A populated root without private cannot silently become a different home.
///
/// ´claim:loophome:ensure-refuses-root-content-without-private´
/// ´test:crate:ensure-refuses-a-populated-loop-root-without-private´
#[test]
fn ensure_refuses_a_populated_loop_root_without_private() {
    let (_directory, _home, rows, uid) = ensure_fixture("root-content");
    fs::create_dir(&rows[2].path).expect("durable partition");
    fs::set_permissions(&rows[2].path, fs::Permissions::from_mode(0o711)).expect("partition mode");
    fs::create_dir(&rows[3].path).expect("loop root");
    fs::write(rows[3].path.join("old"), b"old").expect("root content");
    let mut report = Vec::new();
    let failure = ensure_roots(&rows, uid, uid, &mut report).expect_err("root refusal");
    assert_eq!(failure.path, rows[3].path);
    assert_eq!(failure.reason, "holds entries without private/");
    assert_eq!(report, Vec::<u8>::new());
    assert!(!rows[4].path.exists());
}

/// An existing private tier makes widening the loop root safe.
///
/// ´claim:loophome:ensure-widens-the-loop-root-only-with-private-present´
/// ´test:crate:ensure-accepts-a-private-only-root-and-widens-it´
#[test]
fn ensure_accepts_a_private_only_root_and_widens_it() {
    let (_directory, _home, rows, uid) = ensure_fixture("private-only");
    fs::create_dir(&rows[2].path).expect("durable partition");
    fs::set_permissions(&rows[2].path, fs::Permissions::from_mode(0o711)).expect("partition mode");
    fs::create_dir(&rows[3].path).expect("loop root");
    fs::set_permissions(&rows[3].path, fs::Permissions::from_mode(0o700)).expect("closed root");
    fs::create_dir(&rows[4].path).expect("private tier");
    fs::set_permissions(&rows[4].path, fs::Permissions::from_mode(0o700)).expect("private mode");
    let (counts, report) = run_fixture(&rows, uid);
    assert_eq!(counts.corrected, 1);
    assert!(report.contains(&format!("corrected {} 0700 0711\n", rows[3].path.display())));
    assert_eq!(
        fs::metadata(&rows[3].path).expect("root").mode() & 0o7777,
        0o711
    );
}

/// The optional custody tier is checked when supplied and never made when absent.
///
/// ´claim:loophome:ensure-checks-custody-when-present-without-creating-it´
/// ´test:crate:ensure-corrects-present-custody-and-never-creates-absent-custody´
#[test]
fn ensure_corrects_present_custody_and_never_creates_absent_custody() {
    let (_directory, _home, rows, uid) = ensure_fixture("custody-optional");
    run_fixture(&rows, uid);
    assert!(!rows[22].path.exists());
    for row in &rows[22..26] {
        fs::create_dir(&row.path).expect("custody row");
        fs::set_permissions(&row.path, fs::Permissions::from_mode(0o755)).expect("custody drift");
    }
    let (counts, report) = run_fixture(&rows, uid);
    assert_eq!(counts.created, 0);
    assert_eq!(counts.corrected, 4);
    let mut expected = String::new();
    for row in &rows[22..26] {
        writeln!(&mut expected, "corrected {} 0755 0700", row.path.display())
            .expect("format expected report");
    }
    assert_eq!(report, expected);
}

/// An existing custody tier supplies the forge directory visible through the bind.
///
/// # Panics
/// Panics only if fixture preparation or a provisioning assertion fails.
///
/// ´claim:loophome:forge-provisioning-creates-the-child-of-an-existing-custody-tier´
/// ´test:crate:forge-provisioning-creates-only-the-existing-tier-child´
#[test]
fn forge_provisioning_creates_only_the_existing_tier_child() {
    let (_directory, home, rows, uid) = ensure_fixture("custody-forge");
    run_fixture(&rows, uid);
    let tier = home.join(".config/loops/alpha/private");
    assert!(!tier.exists());
    fs::create_dir(&tier).expect("existing custody tier");
    fs::set_permissions(&tier, fs::Permissions::from_mode(0o700)).expect("tier mode");
    let forge = tier.join("gh");
    let inspection = inspect_roots(&rows, (uid, uid), (uid, uid));
    assert_eq!(inspection.would_counts().created, 1);
    assert!(
        inspection
            .observations
            .iter()
            .any(|row| row.path == forge && row.action == RootAction::Create)
    );
    let (counts, _) = run_fixture(&rows, uid);
    assert_eq!(counts.created, 1);
    let metadata = fs::metadata(&forge).expect("backing forge");
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert_eq!(fs::read_dir(&forge).expect("empty forge").count(), 0);
    fs::write(forge.join("hosts.yml"), "fixture login").expect("retained login");
    let (counts, _) = run_fixture(&rows, uid);
    assert_eq!(counts.created, 0);
    assert_eq!(counts.corrected, 0);
    assert_eq!(
        fs::read_to_string(forge.join("hosts.yml")).expect("login"),
        "fixture login"
    );
    assert!(!tier.join("ssh").exists());
    assert!(!tier.join("gpg").exists());
}

/// ´claim:loophome:driver-launch-run-names-have-one-closed-grammar´
/// ´test:crate:driver-launch-run-name-grammar-is-bounded´
#[test]
fn driver_launch_run_name_grammar_is_bounded() {
    for valid in ["R", "20260929T023200Z-readback", "a_b.c", &"x".repeat(64)] {
        assert!(valid_run_name(valid), "{valid}");
    }
    for invalid in [
        "",
        "-bad",
        "_bad",
        ".bad",
        "a/b",
        "a b",
        "é",
        &"x".repeat(65),
    ] {
        assert!(!valid_run_name(invalid), "{invalid}");
    }
}

/// ´claim:loophome:driver-launch-requires-an-explicit-separator-and-arguments´
/// ´test:crate:driver-launch-parser-keeps-the-ordinary-command-form´
#[test]
fn driver_launch_parser_keeps_the_ordinary_command_form() {
    let ordinary = parse_invocation(
        OsStr::new("superloop"),
        ["enter", "alpha", "--", "driver-launch", "one"],
        None,
        Some(OsStr::new("/fixture")),
    )
    .expect("ordinary command");
    assert!(
        matches!(ordinary.action, Action::Enter { command, .. } if command == ["driver-launch", "one"])
    );
    let missing_separator = parse_invocation(
        OsStr::new("superloop"),
        [
            "driver-launch",
            "alpha",
            "R",
            "--driver-bin",
            "/bin/true",
            "--run-dir",
            "/runs/R",
            "arg",
        ],
        None,
        Some(OsStr::new("/fixture")),
    )
    .expect_err("missing separator");
    assert_eq!(
        missing_separator.message(),
        "driver-launch requires -- before arguments"
    );
    assert_eq!(missing_separator.status(), 2);
    let empty = parse_invocation(
        OsStr::new("superloop"),
        [
            "driver-launch",
            "alpha",
            "R",
            "--driver-bin",
            "/bin/true",
            "--run-dir",
            "/runs/R",
            "--",
        ],
        None,
        Some(OsStr::new("/fixture")),
    )
    .expect_err("empty argv");
    assert_eq!(
        empty.message(),
        "driver-launch requires a nonempty argument vector"
    );
    assert_eq!(empty.status(), 2);
}

fn ordinary_entry_fixture(settings_present: bool, words: &[&str]) -> (TestDir, crate::EntryPlan) {
    let directory = TestDir::new_safe("ordinary-entry");
    let home = &directory.path;
    let runs = home.join("runs");
    let row = record("alpha", 41001, "/srv/alpha");
    if settings_present {
        let settings = home.join(".config/loops/alpha/workers.toml");
        fs::create_dir_all(settings.parent().expect("settings parent"))
            .expect("settings directory");
        private_parents(&settings, home);
        fs::write(
            &settings,
            format!(
                "driver_argv = [\"/fixture/driver\", \"fixed word\"]\nbackend_argv = {{ codex = [\"/fixture/codex\"] }}\nruns_root = \"{}\"\n",
                runs.display()
            ),
        )
        .expect("workers settings");
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    }
    let invocation = parse_invocation(
        OsStr::new("superloop"),
        ["enter", "alpha", "--"]
            .into_iter()
            .chain(words.iter().copied()),
        None,
        Some(home.as_os_str()),
    )
    .expect("ordinary entry invocation");
    let Action::Enter { command, .. } = invocation.action else {
        panic!("ordinary entry action");
    };
    let plan = crate::app::ordinary_entry_plan(
        &row,
        Some(&runs),
        Path::new("/fixture/superloop"),
        home,
        Path::new("/fixture/report"),
        None,
        &[String::from("podman")],
        &command,
        ("vt100", "C.UTF-8"),
    )
    .expect("ordinary entry plan");
    (directory, plan)
}

/// ´claim:loophome:ordinary-entry-with-settings-does-not-intercept-former-mail-words´
/// ´test:crate:ordinary-entry-with-settings-does-not-intercept-former-mail-words´
#[test]
fn ordinary_entry_with_settings_does_not_intercept_former_mail_words() {
    for command in ["letters", "letters-private", "letters-group"] {
        let (_directory, plan) = ordinary_entry_fixture(true, &[command, "list"]);
        let execution = plan
            .inner_script
            .lines()
            .last()
            .expect("ordinary execution");
        assert!(execution.starts_with("exec setpriv "), "{execution}");
        assert!(
            execution.ends_with(&format!("{command} list")),
            "{execution}"
        );
        assert!(!execution.contains("exec /fixture/superloop letters-private"));
    }
}

/// ´claim:loophome:ordinary-entry-settings-preserve-the-command-environment´
/// ´test:crate:ordinary-entry-with-settings-keeps-the-non-private-command´
#[test]
fn ordinary_entry_with_settings_keeps_the_non_private_command() {
    let words = ["printf", "%s", "a b", "$(touch nope)", ""];
    let (directory, plan) = ordinary_entry_fixture(true, &words);
    let home = &directory.path;
    let settings = home.join(".config/loops/alpha/workers.toml");
    let evidence = serde_json::json!({
        "path": settings,
        "driver_argv": ["/fixture/driver", "fixed word"],
        "backend_argv": {"codex": ["/fixture/codex"]},
    });
    let command = [
        String::from("/usr/bin/env"),
        String::from("LANE_DRIVER_ARGV=[\"/fixture/driver\",\"fixed word\"]"),
        String::from("LANE_BACKEND_ARGV={\"codex\":[\"/fixture/codex\"]}"),
        format!("LANE_SETTINGS_EVIDENCE={evidence}"),
        format!("LANE_RUNS_ROOT={}", home.join("runs").display()),
    ]
    .into_iter()
    .chain(words.map(String::from))
    .collect::<Vec<_>>();
    let expected = crate::entry_plan(
        &record("alpha", 41001, "/srv/alpha"),
        Path::new("/fixture/superloop"),
        home,
        Path::new("/fixture/report"),
        None,
        &[String::from("podman")],
        &command,
        "vt100",
        "C.UTF-8",
        IoMode::Inherit,
    );
    assert_eq!(plan.inner_script, expected.inner_script);
    assert_eq!(plan.command.argv, expected.command.argv);
}

/// ´claim:loophome:ordinary-entry-without-settings-does-not-intercept-former-mail-words´
/// ´test:crate:ordinary-entry-without-settings-does-not-intercept-former-mail-words´
#[test]
fn ordinary_entry_without_settings_does_not_intercept_former_mail_words() {
    for command in ["letters", "letters-private", "letters-group"] {
        let (_directory, plan) = ordinary_entry_fixture(false, &[command, "list"]);
        let execution = plan
            .inner_script
            .lines()
            .last()
            .expect("ordinary execution");
        assert!(execution.starts_with("exec setpriv "), "{execution}");
        assert!(
            execution.ends_with(&format!("{command} list")),
            "{execution}"
        );
        assert!(!execution.contains("exec /fixture/superloop letters-private"));
    }
}

/// ´claim:loophome:driver-launch-forwards-positional-words-without-reparsing´
/// ´test:crate:driver-launch-plan-forwards-exact-argv´
#[test]
fn driver_launch_plan_forwards_exact_argv() {
    let command = [
        "/fixture/driver",
        "driver-launch",
        "a b",
        "$(touch nope)",
        "\"x\"\n",
    ]
    .map(String::from);
    let plan = driver_launch_plan(
        &record("alpha", 41001, "/srv/alpha"),
        Path::new("/fixture/superloop"),
        Path::new("/caller"),
        Path::new("/fixture/report"),
        None,
        &[String::from("podman")],
        &command,
        "vt100",
        "C.UTF-8",
    );
    assert_eq!(
        &plan.command.argv[5..],
        &[
            "sh",
            "/fixture/driver",
            "driver-launch",
            "a b",
            "$(touch nope)",
            "\"x\"\n"
        ]
    );
    assert!(plan.outer_script.contains("unshare -m sh -c "));
    assert!(plan.outer_script.contains("sh \"$t\" \"$h\" \"$@\""));
    assert!(plan.inner_script.contains("h=$2\nshift 2\n"));
    assert!(plan.inner_script.ends_with(" \"$@\""));
    assert!(!plan.outer_script.contains("touch nope"));
    assert_eq!(plan.command.io, IoMode::Inherit);
}

/// ´claim:loophome:driver-launch-refuses-unsafe-settings-and-run-paths´
/// ´test:crate:driver-launch-validation-refuses-settings-driver-and-links´
#[test]
#[allow(clippy::too_many_lines)]
fn driver_launch_validation_refuses_settings_driver_and_links() {
    let directory = TestDir::new_safe("driver-validation");
    let home = &directory.path;
    let settings_dir = home.join(".config/loops/alpha");
    let runs = home.join(".var/loops/alpha/runs");
    fs::create_dir_all(&settings_dir).expect("settings directory");
    private_parents(&settings_dir.join("workers.toml"), home);
    write_allocation(home, "[alpha]\nuids = { base = 40000, count = 2 }\n");
    fs::create_dir_all(&runs).expect("runs root");
    private_parents(&runs, home);
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o711)).expect("runs mode");
    let run_dir = runs.join("R");
    fs::create_dir(&run_dir).expect("run directory");
    let driver = home.join("driver");
    fs::write(&driver, "#!/bin/sh\nexit 0\n").expect("driver file");
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("executable driver");
    let record = record(
        "alpha",
        41001,
        &home.join(".var/loops/alpha").to_string_lossy(),
    );
    let settings = settings_dir.join("workers.toml");
    let check = |run: &str, driver: &Path, run_dir: &Path| {
        validate_driver_launch(home, &record, Some(&runs), run, driver, run_dir)
    };
    assert!(check("R", &driver, &run_dir).is_err());
    fs::write(
        settings_dir.join("box.toml"),
        "driver_argv = [\"/bin/true\"]\n",
    )
    .expect("prior setting");
    let prior = check("R", &driver, &run_dir).expect_err("prior name");
    assert!(
        prior.message().contains("rename box.toml to workers.toml"),
        "{prior:?}"
    );
    fs::write(
        &settings,
        format!("driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nfuture_key = 1\n", driver.display()),
    )
    .expect("workers settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings file mode");
    let unknown = check("R", &driver, &run_dir).expect_err("unknown setting");
    assert!(unknown.message().contains("future_key"));
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n",
            driver.display(),
            runs.display()
        ),
    )
    .expect("valid settings");
    check("R", &driver, &run_dir).expect("valid worker settings");
    for (setting, refusal) in [
        ("attempt_wall_seconds = 1", None),
        ("attempt_wall_seconds = 9223372036854775807", None),
        ("attempt_wall_seconds = 0", Some("attempt-wall")),
        ("attempt_wall_seconds = -1", Some("attempt-wall")),
        ("attempt_wall_seconds = 1.5", Some("attempt-wall")),
        ("attempt_wall_seconds = \"12\"", Some("attempt-wall")),
        ("context_threshold = 0.8", None),
        ("context_threshold = 0.0", Some("context-threshold")),
        ("context_threshold = 1.0", Some("context-threshold")),
        ("context_threshold = -0.1", Some("context-threshold")),
        ("context_threshold = inf", Some("context-threshold")),
        ("context_threshold = nan", Some("context-threshold")),
        ("context_threshold = 1", Some("context-threshold")),
        ("context_threshold = \"0.8\"", Some("context-threshold")),
    ] {
        fs::write(
            &settings,
            format!(
                "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n{setting}\n",
                driver.display(),
                runs.display()
            ),
        )
        .expect("policy settings");
        let result = check("R", &driver, &run_dir);
        if let Some(name) = refusal {
            let error = result.expect_err(setting);
            assert!(
                error.message().starts_with(&format!("{name}:")),
                "{error:?}"
            );
        } else {
            result.expect(setting);
        }
    }
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n",
            driver.display(),
            runs.display()
        ),
    )
    .expect("restore valid settings");
    write_allocation(home, "[beta]\nuids = { base = 40000, count = 2 }\n");
    let refusal = validate_driver_launch(home, &record, Some(&runs), "R", &driver, &run_dir)
        .expect_err("missing worker identities");
    assert!(
        refusal
            .message()
            .contains("missing worker uid allocation for loop: alpha")
    );
    write_allocation(home, "[alpha]\nuids = { base = 40000, count = 2 }\n");
    assert_eq!(
        check("bad/run", &driver, &run_dir)
            .expect_err("bad run")
            .message(),
        "bad run name: bad/run"
    );
    assert!(
        check("R", Path::new("relative"), &run_dir)
            .expect_err("relative driver")
            .message()
            .starts_with("driver path is not absolute:")
    );
    assert!(
        check("R", Path::new("/different"), &run_dir)
            .expect_err("mismatched driver")
            .message()
            .starts_with("driver path differs from workers settings:")
    );
    assert!(
        check("R", &driver, &runs.join("other/R"))
            .expect_err("outside root")
            .message()
            .starts_with("run directory is outside")
    );
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o644)).expect("nonexecutable driver");
    assert!(
        check("R", &driver, &run_dir)
            .expect_err("nonexecutable")
            .message()
            .starts_with("driver is not a regular executable file:")
    );
    fs::remove_file(&driver).expect("remove driver");
    assert!(
        check("R", &driver, &run_dir)
            .expect_err("missing driver")
            .message()
            .starts_with("could not inspect driver")
    );
    fs::remove_file(&settings).expect("remove settings");
    symlink(&driver, &settings).expect("linked settings");
    assert!(
        check("R", &driver, &run_dir)
            .expect_err("linked settings")
            .message()
            .starts_with("could not read workers settings")
    );
}

/// ´claim:entry:trusted-runs-root-checks-source-owner-mode-and-links´
/// ´test:crate:trusted-runs-root-checks-source-owner-mode-and-links´
#[test]
#[allow(clippy::too_many_lines)]
fn trusted_runs_root_checks_source_owner_mode_and_links() {
    use crate::workers_settings::{read_runs_root, read_runs_root_for_owner};
    let fixture = TestDir::new_safe("trusted-runs-root");
    let home = &fixture.path;
    let directory = home.join(".config/loops/alpha");
    fs::create_dir_all(&directory).expect("settings directory");
    let settings = directory.join("workers.toml");
    private_parents(&settings, home);
    let root = home.join("durable-runs");
    let owner = nix::unistd::Uid::effective().as_raw();
    let worker = if owner == 41001 { 41002 } else { 41001 };
    let row = record("alpha", worker, &home.join("loop").to_string_lossy());
    let read = || read_runs_root(home, &row, Some(&root));
    assert!(
        read()
            .expect_err("absent source")
            .message()
            .contains("workers settings")
    );
    fs::write(directory.join("box.toml"), "runs_root = \"/wrong\"\n").expect("old source");
    assert!(
        read()
            .expect_err("old name")
            .message()
            .contains("rename box.toml")
    );
    fs::write(&settings, "driver_argv = [\"/usr/bin/true\"]\n").expect("missing root");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    assert!(
        read()
            .expect_err("missing setting")
            .message()
            .contains("runs_root_required")
    );
    for text in [
        "runs_root = \"relative\"\n",
        "runs_root = \"/wrong\"\n",
        "runs_root = 4\n",
    ] {
        fs::write(&settings, text).expect("invalid setting");
        assert!(read().is_err());
    }
    fs::write(&settings, format!("runs_root = \"{}\"\n", root.display())).expect("root setting");
    assert_eq!(read().expect("owner source"), root);
    for (setting, refusal) in [
        ("attempt_wall_seconds = 1", None),
        ("attempt_wall_seconds = 9223372036854775807", None),
        ("attempt_wall_seconds = 0", Some("attempt-wall")),
        ("attempt_wall_seconds = -1", Some("attempt-wall")),
        ("attempt_wall_seconds = 1.5", Some("attempt-wall")),
        ("attempt_wall_seconds = \"12\"", Some("attempt-wall")),
        ("context_threshold = 0.8", None),
        ("context_threshold = 0.0", Some("context-threshold")),
        ("context_threshold = 1.0", Some("context-threshold")),
        ("context_threshold = -0.1", Some("context-threshold")),
        ("context_threshold = inf", Some("context-threshold")),
        ("context_threshold = nan", Some("context-threshold")),
        ("context_threshold = 1", Some("context-threshold")),
        ("context_threshold = \"0.8\"", Some("context-threshold")),
    ] {
        fs::write(
            &settings,
            format!("runs_root = \"{}\"\n{setting}\n", root.display()),
        )
        .expect("policy settings");
        let result = read();
        if let Some(name) = refusal {
            let error = result.expect_err(setting);
            assert!(
                error.message().starts_with(&format!("{name}:")),
                "{error:?}"
            );
        } else {
            assert_eq!(result.expect(setting), root);
        }
    }
    fs::write(&settings, format!("runs_root = \"{}\"\n", root.display()))
        .expect("restore root setting");
    assert_ne!(owner, row.uid);
    assert!(read_runs_root_for_owner(home, &row, Some(&root), worker).is_err());
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    assert!(read().expect_err("file mode").message().contains("0600"));
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("restore mode");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("unsafe parent");
    assert!(read().expect_err("parent mode").message().contains("0700"));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("restore parent");
    let source = directory.join("saved.toml");
    fs::rename(&settings, &source).expect("save settings");
    symlink(&source, &settings).expect("file link");
    assert!(
        read()
            .expect_err("file link")
            .message()
            .contains("could not read workers settings")
    );
    fs::remove_file(&settings).expect("remove link");
    fs::rename(&source, &settings).expect("restore settings");
    let saved = directory.with_file_name("saved");
    fs::rename(&directory, &saved).expect("save directory");
    symlink(&saved, &directory).expect("directory link");
    assert!(
        read()
            .expect_err("directory link")
            .message()
            .contains("could not open workers settings directory")
    );
}

/// A declared root selects the durable run directory even away from the loop home.
///
/// ´claim:loophome:driver-launch-uses-the-declared-runs-root´
/// ´test:crate:driver-launch-uses-registry-runs-root-when-present´
#[test]
fn driver_launch_uses_registry_runs_root_when_present() {
    let directory = TestDir::new_safe("driver-runs-root");
    let home = &directory.path;
    let settings = home.join(".config/loops/alpha/workers.toml");
    fs::create_dir_all(settings.parent().expect("settings parent")).expect("settings directory");
    private_parents(&settings, home);
    write_allocation(home, "[alpha]\nuids = { base = 40000, count = 2 }\n");
    let driver = home.join("driver");
    fs::write(&driver, "#!/bin/sh\nexit 0\n").expect("driver file");
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("executable driver");
    let selected = home.join("owner-selected/runs");
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n",
            driver.display(),
            selected.display()
        ),
    )
    .expect("workers settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings file mode");
    let selected_run = selected.join("R");
    fs::create_dir_all(&selected_run).expect("selected run directory");
    private_parents(&selected, home);
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o711)).expect("selected mode");
    let old_run = home.join(".var/loops/alpha/runs/R");
    fs::create_dir_all(&old_run).expect("old run directory");
    let record = record(
        "alpha",
        41001,
        &home.join(".var/loops/alpha").to_string_lossy(),
    );
    assert!(
        validate_driver_launch(home, &record, Some(&selected), "R", &driver, &selected_run).is_ok()
    );
    let failure = validate_driver_launch(home, &record, Some(&selected), "R", &driver, &old_run)
        .expect_err("old derivation differs from declared root");
    assert_eq!(failure.status(), 2);
    assert!(
        failure
            .message()
            .starts_with("run directory is outside the loop runs root")
    );
}

/// ´claim:loophome:absent-runs-root-refuses-launch-by-name´
/// ´test:crate:driver-launch-refuses-missing-root-setting´
#[test]
fn driver_launch_refuses_missing_root_setting() {
    let directory = TestDir::new_safe("derived-runs-root");
    let home = &directory.path;
    let settings = home.join(".config/loops/alpha/workers.toml");
    fs::create_dir_all(settings.parent().expect("settings parent")).expect("settings directory");
    private_parents(&settings, home);
    write_allocation(home, "[alpha]\nuids = { base = 40000, count = 2 }\n");
    let driver = home.join("driver");
    fs::write(&driver, "#!/bin/sh\nexit 0\n").expect("driver file");
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("driver mode");
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\n",
            driver.display()
        ),
    )
    .expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings file mode");
    let root = home.join(".var/loops/alpha/runs");
    let run = root.join("R");
    fs::create_dir_all(&run).expect("run directory");
    fs::set_permissions(home.join(".var"), fs::Permissions::from_mode(0o777))
        .expect("replaceable standard ancestor");
    let record = record(
        "alpha",
        41001,
        &home.join(".var/loops/alpha").to_string_lossy(),
    );
    assert!(
        validate_driver_launch(home, &record, Some(&root), "R", &driver, &run)
            .expect_err("missing settings root cannot fall back to the registry")
            .message()
            .contains("runs_root_required")
    );
    assert!(
        inspect_runs_root(&record, None)
            .expect("absent field")
            .is_none()
    );
}

/// Verify reports an owner-owned directory and refuses missing, linked or file roots.
///
/// ´claim:loophome:verify-inspects-every-runs-root-component-and-owner´
/// ´test:crate:verify-inspects-declared-runs-root´
#[test]
fn verify_inspects_declared_runs_root() {
    let directory = TestDir::new_safe("verify-runs-root");
    let home = &directory.path;
    let root = home.join("durable/runs");
    let record = record("alpha", 41001, "/fixture/alpha");
    let missing = inspect_runs_root(&record, Some(&root)).expect_err("missing root");
    assert_eq!(missing.status(), 1);
    assert!(
        missing
            .message()
            .contains("runs_root for loop alpha cannot inspect")
    );
    fs::create_dir_all(&root).expect("runs root");
    private_parents(&root, home);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o711)).expect("runs mode");
    let report = inspect_runs_root(&record, Some(&root))
        .expect("inspect root")
        .expect("declared root");
    let metadata = fs::metadata(&root).expect("runs metadata");
    assert_eq!(report.path, root);
    assert_eq!((report.uid, report.gid), (metadata.uid(), metadata.gid()));
    assert_eq!(report.mode, 0o711);
    let file = home.join("ordinary-file");
    fs::write(&file, b"not a directory").expect("file");
    let nondirectory = inspect_runs_root(&record, Some(&file)).expect_err("file root");
    assert_eq!(nondirectory.status(), 1);
    assert!(nondirectory.message().contains("nondirectory component"));
    let linked = home.join("linked");
    symlink(home.join("durable"), &linked).expect("linked parent");
    let link = inspect_runs_root(&record, Some(&linked.join("runs"))).expect_err("linked parent");
    assert_eq!(link.status(), 1);
    assert!(link.message().contains("reached through a link"));
}

/// ´claim:loophome:declared-runs-root-owner-and-mode-bound-launch-and-verify´
/// ´test:crate:declared-runs-root-refuses-owner-group-and-mode-mismatch´
#[test]
fn declared_runs_root_refuses_owner_group_and_mode_mismatch() {
    let directory = TestDir::new_safe("runs-root-identity");
    let home = &directory.path;
    let settings = home.join(".config/loops/alpha/workers.toml");
    fs::create_dir_all(settings.parent().expect("settings parent")).expect("settings directory");
    private_parents(&settings, home);
    write_allocation(home, "[alpha]\nuids = { base = 40000, count = 2 }\n");
    let driver = home.join("driver");
    fs::write(&driver, "#!/bin/sh\nexit 0\n").expect("driver file");
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("driver mode");
    let root = home.join("durable/runs");
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n",
            driver.display(),
            root.display()
        ),
    )
    .expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings file mode");
    let run = root.join("R");
    fs::create_dir_all(&run).expect("run directory");
    private_parents(&root, home);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o711)).expect("root mode");
    let record = record(
        "alpha",
        41001,
        &home.join(".var/loops/alpha").to_string_lossy(),
    );
    let metadata = fs::metadata(&root).expect("root metadata");
    for (owner, word) in [
        ((metadata.uid().wrapping_add(1), metadata.gid()), "uid"),
        ((metadata.uid(), metadata.gid().wrapping_add(1)), "gid"),
    ] {
        let launch =
            validate_driver_launch_for_owner(home, &record, Some(&root), "R", &driver, &run, owner)
                .expect_err("mismatched launch identity");
        assert_eq!(launch.status(), 2);
        assert!(launch.message().contains("runs_root for loop alpha"));
        assert!(launch.message().contains(word));
        let verify = inspect_runs_root_for_owner(&record, Some(&root), owner)
            .expect_err("mismatched verify identity");
        assert_eq!(verify.status(), 1);
        assert!(verify.message().contains("runs_root for loop alpha"));
        assert!(verify.message().contains(word));
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("wrong root mode");
    let mode = validate_driver_launch(home, &record, Some(&root), "R", &driver, &run)
        .expect_err("root mode mismatch");
    assert_eq!(mode.status(), 2);
    assert!(mode.message().contains("expected mode 0711"));
}

/// ´claim:loophome:declared-runs-root-refuses-replaceable-ancestor´
/// ´test:crate:declared-runs-root-rejects-replaceable-ancestor´
#[test]
fn declared_runs_root_rejects_replaceable_ancestor() {
    let directory = TestDir::new_safe("runs-root-ancestor");
    let home = &directory.path;
    let ancestor = home.join("replaceable");
    let root = ancestor.join("runs");
    let run = root.join("R");
    fs::create_dir_all(&run).expect("run directory");
    private_parents(&ancestor, home);
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).expect("ancestor mode");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o711)).expect("root mode");
    let settings = home.join(".config/loops/alpha/workers.toml");
    fs::create_dir_all(settings.parent().expect("settings parent")).expect("settings directory");
    private_parents(&settings, home);
    write_allocation(home, "[alpha]\nuids = { base = 40000, count = 2 }\n");
    let driver = home.join("driver");
    fs::write(&driver, "#!/bin/sh\nexit 0\n").expect("driver file");
    fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("driver mode");
    fs::write(
        &settings,
        format!(
            "driver_argv = [\"{}\"]\nbackend_argv = {{ codex = [\"/usr/bin/codex\"] }}\nruns_root = \"{}\"\n",
            driver.display(),
            root.display()
        ),
    )
    .expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings file mode");
    let record = record(
        "alpha",
        41001,
        &home.join(".var/loops/alpha").to_string_lossy(),
    );
    let launch = validate_driver_launch(home, &record, Some(&root), "R", &driver, &run)
        .expect_err("replaceable launch ancestor");
    assert_eq!(launch.status(), 2);
    assert!(
        launch
            .message()
            .contains("runs_root for loop alpha has a replaceable ancestor")
    );
    let verify = inspect_runs_root(&record, Some(&root)).expect_err("replaceable verify ancestor");
    assert_eq!(verify.status(), 1);
    assert!(
        verify
            .message()
            .contains("runs_root for loop alpha has a replaceable ancestor")
    );
}

/// ´claim:loophome:opened-run-path-survives-ancestor-substitution´
/// ´test:crate:descriptor-run-path-stays-on-opened-ancestor-after-substitution´
#[test]
fn descriptor_run_path_stays_on_opened_ancestor_after_substitution() {
    let directory = TestDir::new_safe("runs-root-swap");
    let home = &directory.path;
    let safe = home.join("safe");
    let moved = home.join("moved");
    let decoy = home.join("decoy");
    fs::create_dir_all(safe.join("runs/R")).expect("safe run");
    fs::create_dir_all(decoy.join("runs/R")).expect("decoy run");
    private_parents(&safe.join("runs"), home);
    private_parents(&decoy.join("runs"), home);
    fs::set_permissions(safe.join("runs"), fs::Permissions::from_mode(0o711))
        .expect("safe root mode");
    fs::set_permissions(decoy.join("runs"), fs::Permissions::from_mode(0o711))
        .expect("decoy root mode");
    let root = safe.join("runs");
    let owner = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    let pinned = pin_runs_root_with_hook(&root, owner, true, |opened| {
        if opened == safe {
            fs::rename(&safe, &moved).expect("move opened ancestor");
            symlink(&decoy, &safe).expect("replace ancestor with link");
        }
    })
    .expect("descriptor traversal stays on opened ancestor");
    let pinned = pin_run_directory(pinned, "R").expect("open original run under pinned root");
    let opened = nix::sys::stat::fstat(&pinned.run).expect("opened run stat");
    assert_eq!(
        opened.st_ino,
        fs::metadata(moved.join("runs/R"))
            .expect("original run")
            .ino()
    );
    assert_ne!(
        opened.st_ino,
        fs::metadata(decoy.join("runs/R")).expect("decoy run").ino()
    );
}
