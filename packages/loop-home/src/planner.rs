use std::path::{Path, PathBuf};

use crate::LoopRecord;

/// How the process runner connects a command's standard streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoMode {
    /// Pass standard input, output, and error through unchanged.
    Inherit,
    /// Capture standard output and error for verification assembly.
    Capture,
}

/// One exact external command request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    /// Stable step label used by scripted runners.
    pub label: String,
    /// Exact argv including the executable.
    pub argv: Vec<String>,
    /// Standard-stream handling.
    pub io: IoMode,
}

impl CommandSpec {
    pub(crate) fn new(label: &str, argv: Vec<String>, io: IoMode) -> Self {
        Self {
            label: label.to_owned(),
            argv,
            io,
        }
    }
}

/// Exact entry command plus its independently inspectable scripts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryPlan {
    /// Script run inside the nested mount namespace.
    pub inner_script: String,
    /// Script run by the single outer podman invocation.
    pub outer_script: String,
    /// Exact podman argv.
    pub command: CommandSpec,
    /// Private stop-provenance file shared by the owner and namespace relay.
    pub stop_report: PathBuf,
}

/// Custody selected while composing an entry as its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custody {
    /// The loop's private custody tier.
    pub tier: PathBuf,
    /// The currently running entry executable.
    pub executable: PathBuf,
}

/// Derive a loop's private custody tier from the caller and validated name.
#[must_use]
pub fn custody_tier(caller_home: &std::path::Path, name: &str) -> PathBuf {
    caller_home.join(".config/loops").join(name).join("private")
}

/// The single namespace-root command that ensures a loop's roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionPlan {
    /// Exact podman command.
    pub command: CommandSpec,
}

/// Supported public-checkout bridges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeKind {
    /// Fixed system `GnuPG` executable.
    Gpg,
    /// OpenSSH client.
    Ssh,
}

pub(crate) fn shell_word(value: &str) -> String {
    if value.is_empty() {
        return String::from("''");
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        return value.to_owned();
    }
    single_literal(value)
}

fn single_literal(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    quoted.push_str(&value.replace('\'', "'\\''"));
    quoted.push('\'');
    quoted
}

fn home_text(record: &LoopRecord) -> String {
    record.home.to_string_lossy().into_owned()
}

fn prefixed(podman: &[String], arguments: impl IntoIterator<Item = String>) -> Vec<String> {
    podman.iter().cloned().chain(arguments).collect()
}

/// Produce the one-podman entry plan.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn entry_plan(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    custody: Option<&Custody>,
    podman: &[String],
    command: &[String],
    term: &str,
    lang: &str,
    io: IoMode,
) -> EntryPlan {
    entry_plan_inner(
        record,
        executable,
        caller_home,
        report_path,
        custody,
        podman,
        command,
        term,
        lang,
        io,
        false,
        true,
    )
}

/// Compose the existing entry boundary without its preparing step.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_entry_plan(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    custody: Option<&Custody>,
    podman: &[String],
    command: &[String],
    term: &str,
    lang: &str,
) -> EntryPlan {
    entry_plan_inner(
        record,
        executable,
        caller_home,
        report_path,
        custody,
        podman,
        command,
        term,
        lang,
        IoMode::Capture,
        false,
        false,
    )
}

/// Produce an entry plan that carries the driver's argv as positional words.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(crate) fn driver_launch_plan(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    custody: Option<&Custody>,
    podman: &[String],
    command: &[String],
    term: &str,
    lang: &str,
) -> EntryPlan {
    entry_plan_inner(
        record,
        executable,
        caller_home,
        report_path,
        custody,
        podman,
        command,
        term,
        lang,
        IoMode::Inherit,
        true,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn entry_plan_inner(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    custody: Option<&Custody>,
    podman: &[String],
    command: &[String],
    term: &str,
    lang: &str,
    io: IoMode,
    direct_argv: bool,
    ensure: bool,
) -> EntryPlan {
    let home = home_text(record);
    let custody_step = custody.map_or_else(String::new, |custody| {
        format!(
            "{} bind-custody {} {} \"$h\" {}\n",
            shell_word(&custody.executable.to_string_lossy()),
            record.uid,
            shell_word(&home),
            shell_word(&custody.tier.to_string_lossy()),
        )
    });
    let pre_custody_selection = if custody.is_none() {
        format!(
            "gpg_dir=\"$h\"/.config/gpg-loops/{}\ngpg_environment=\nif [ -d \"$gpg_dir\" ]; then gpg_environment=\"GNUPGHOME=$gpg_dir\"; fi\n",
            shell_word(&record.name),
        )
    } else {
        String::new()
    };
    let custody_environment = custody.map_or(
        "${gpg_environment:+\"$gpg_environment\"} ",
        |_| "GNUPGHOME=\"$h/.config/custody/gpg\" GH_CONFIG_DIR=\"$h/.config/custody/gh\" ",
    );
    let command_line = if direct_argv {
        String::from("\"$@\"")
    } else {
        command
            .iter()
            .map(|word| shell_word(word))
            .collect::<Vec<_>>()
            .join(" ")
    };
    // Custody readiness is a prerequisite for every entry, including bridges,
    // driver launches and verify probes, rather than a gh-only command check.
    let command_line = if custody.is_some() {
        let check = "if [ ! -x \"$HOME/.config/custody\" ]; then reason=forge-config-inaccessible; elif [ ! -e \"$GH_CONFIG_DIR\" ]; then reason=forge-config-absent; elif [ ! -d \"$GH_CONFIG_DIR\" ]; then reason=forge-config-not-directory; elif [ ! -r \"$GH_CONFIG_DIR\" ] || [ ! -w \"$GH_CONFIG_DIR\" ] || [ ! -x \"$GH_CONFIG_DIR\" ]; then reason=forge-config-inaccessible; else exec \"$@\"; fi; printf 'superloop: %s: GH_CONFIG_DIR; run superloop provision LOOP\\n' \"$reason\" >&2; exit 1";
        format!(
            "/bin/sh -c {} forge-entry {command_line}",
            shell_word(check)
        )
    } else {
        command_line
    };
    let argv_setup = if direct_argv { "shift 2\n" } else { "" };
    let mount = if ensure { "mount" } else { "/usr/bin/mount" };
    let setpriv = if ensure {
        "setpriv"
    } else {
        "/usr/bin/setpriv"
    };
    let env_program = if ensure { "env" } else { "/usr/bin/env" };
    let entered_path = if ensure {
        format!(
            "$h/.local/bin:/usr/local/bin:/usr/bin:/bin:{}",
            executable
                .parent()
                .unwrap_or_else(|| Path::new("/usr/local/bin"))
                .to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`")
        )
    } else {
        String::from("/usr/bin:/bin")
    };
    let cache_home = shell_word(
        &caller_home
            .join(".cache/loops")
            .join(&record.name)
            .to_string_lossy(),
    );
    let command_uid = record.uid;
    let command_name = &record.name;
    let execution = format!(
        "mail_group=$({} _mail-group {} {})\ngroup_option=--clear-groups\nif [ -n \"$mail_group\" ]; then group_option=--groups=$mail_group; fi\nexec {setpriv} --reuid={} --regid={} \"$group_option\" {env_program} -i HOME=\"$h\" USER={} LOGNAME={} SHELL=/bin/bash PATH=\"{entered_path}\" TERM={} LANG={} TMPDIR={cache_home}/tmp XDG_RUNTIME_DIR=\"$h/.run\" XDG_CONFIG_HOME=\"$h/.config\" XDG_CACHE_HOME={cache_home} XDG_DATA_HOME=\"$h/.local/share\" XDG_STATE_HOME=\"$h/.local/state\" {}{}",
        shell_word(&executable.to_string_lossy()),
        shell_word(&caller_home.to_string_lossy()),
        shell_word(&record.name),
        command_uid,
        command_uid,
        shell_word(command_name),
        shell_word(command_name),
        shell_word(term),
        shell_word(lang),
        custody_environment,
        command_line
    );
    let inner_script = format!(
        "set -e\nt=$1\nh=$2\n{argv_setup}{custody_step}{mount} --bind \"$t/passwd\" /etc/passwd\n{mount} --bind \"$t/group\" /etc/group\n{mount} --bind \"$t/ssh_config.d\" /etc/ssh/ssh_config.d\n{pre_custody_selection}{execution}"
    );
    let passwd_prefix = format!(
        "{}:x:{}:{}:{} superloop:",
        record.name, record.uid, record.uid, record.name
    );
    let group = format!("{}:x:{}:", record.name, record.uid);
    let forwarded_argv = if direct_argv { " \"$@\"" } else { "" };
    let ensure_line = if ensure {
        format!(
            "{} ensure-roots {} {} {} {}\n",
            shell_word(&executable.to_string_lossy()),
            record.uid,
            shell_word(&record.name),
            shell_word(&caller_home.to_string_lossy()),
            shell_word(&report_path.to_string_lossy()),
        )
    } else {
        String::new()
    };
    let mktemp = if ensure { "mktemp" } else { "/usr/bin/mktemp" };
    let rm = if ensure { "rm" } else { "/usr/bin/rm" };
    let cat = if ensure { "cat" } else { "/usr/bin/cat" };
    let mkdir = if ensure { "mkdir" } else { "/usr/bin/mkdir" };
    let unshare = if ensure {
        "unshare"
    } else {
        "/usr/bin/unshare"
    };
    let shell = if ensure { "sh" } else { "/bin/sh" };
    let watched = crate::runner::watched_literal();
    let stop_report = report_path.with_extension("signals").join("stop");
    let stop_argument = shell_word(&stop_report.to_string_lossy());
    let outer_script = format!(
        "set -e\nh={}\n{}if [ -d \"$h/private\" ]; then h=\"$h/private\"; fi\nt=$({mktemp} -d /tmp/superloop.XXXXXX)\ncleanup() {{\n    {rm} -rf \"$t\"\n}}\ntrap cleanup EXIT\n{cat} /etc/passwd > \"$t/passwd\"\nprintf '%s\\n' {}\"$h\"{} >> \"$t/passwd\"\n{cat} /etc/group > \"$t/group\"\nprintf '%s\\n' {} >> \"$t/group\"\n{mkdir} -p \"$t/ssh_config.d\"\nset +e\nchild=\nsignal=\nforward() {{\n    signal=$1\n    interrupted=yes\n    if [ -n \"$child\" ]; then kill -s \"$signal\" \"$child\" 2>/dev/null || :; fi\n}}\ntrap 'forward TERM' TERM\ntrap 'forward INT' INT\ntrap 'forward HUP' HUP\ntrap 'forward QUIT' QUIT\nexec 9<&0\n{} _supervise-command {watched} {stop_argument} {unshare} -m {shell} -c {} {shell} \"$t\" \"$h\"{} <&9 9<&- &\nchild=$!\nexec 9<&-\nif [ -n \"$signal\" ]; then forward \"$signal\"; fi\nwhile :; do\n    interrupted=\n    wait \"$child\"\n    rc=$?\n    [ -n \"$interrupted\" ] || break\ndone\nset -e\n{rm} -rf \"$t\"\ntrap - EXIT\nexit \"$rc\"",
        shell_word(&home),
        ensure_line,
        single_literal(&passwd_prefix),
        single_literal(":/bin/bash"),
        single_literal(&group),
        shell_word(&executable.to_string_lossy()),
        single_literal(&inner_script),
        forwarded_argv,
    );
    let mut argv = prefixed(
        podman,
        [
            String::from("unshare"),
            String::from(shell),
            String::from("-c"),
            outer_script.clone(),
        ],
    );
    if direct_argv {
        argv.push(String::from("sh"));
        argv.extend_from_slice(command);
    }
    EntryPlan {
        stop_report,
        inner_script,
        outer_script,
        command: if ensure {
            CommandSpec::new("enter", argv, io)
        } else {
            CommandSpec::new("verify-entry", argv, io)
        },
    }
}

/// Produce the one-command provisioning plan.
#[must_use]
pub fn provision_plan(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    podman: &[String],
) -> ProvisionPlan {
    let script = format!(
        "set -e\n\n{} ensure-roots {} {} {} {}\n{} _mail-provision {} {}",
        shell_word(&executable.to_string_lossy()),
        record.uid,
        shell_word(&record.name),
        shell_word(&caller_home.to_string_lossy()),
        shell_word(&report_path.to_string_lossy()),
        shell_word(&executable.to_string_lossy()),
        shell_word(&caller_home.to_string_lossy()),
        shell_word(&record.name),
    );
    ProvisionPlan {
        command: CommandSpec::new(
            "provision",
            prefixed(
                podman,
                [
                    String::from("unshare"),
                    String::from("sh"),
                    String::from("-c"),
                    script,
                ],
            ),
            IoMode::Inherit,
        ),
    }
}

/// Select the command executed by a bridge entry.
#[must_use]
pub fn bridge_command(kind: BridgeKind, arguments: &[String]) -> Vec<String> {
    let mut command = Vec::with_capacity(arguments.len() + 1);
    match kind {
        BridgeKind::Gpg => command.push(String::from("/usr/bin/gpg")),
        BridgeKind::Ssh => command.push(String::from("ssh")),
    }
    command.extend_from_slice(arguments);
    command
}
