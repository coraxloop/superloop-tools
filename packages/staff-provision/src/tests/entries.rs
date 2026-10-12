use std::path::PathBuf;

use crate::config::LoopOptions;
use crate::loop_keygen::{LoopOutputInput, SshRecord, SshRoute, run_loop_keygen_with_input};
use crate::{LOOP_KEYGEN_HELP, loop_keygen_entry, staff_provision_entry};

use super::{Reply, ScriptedRunner, guarded_account_replies, missing_surface_replies};

const KEY: &str = "ssh-ed25519 AAAA test@host\n";

fn fictional_loop_output() -> LoopOutputInput {
    LoopOutputInput {
        coordinator: String::from("Example Coordinator"),
        client_config: PathBuf::from("/home/example/.ssh/config"),
        routes: ["sagofink-orchestration", "mondreiher-analysis"]
            .into_iter()
            .map(|alias| SshRoute {
                alias: alias.into(),
                address: "192.0.2.1".into(),
                port: "2222".into(),
                host_key: None,
            })
            .collect(),
        ssh_records: vec![
            SshRecord {
                alias: String::from("sagofink-orchestration"),
                user: String::from("example-loop"),
                identity_file: PathBuf::from("/keys/example-loop-codex_ed25519"),
            },
            SshRecord {
                alias: String::from("mondreiher-analysis"),
                user: String::from("example-loop"),
                identity_file: PathBuf::from("/keys/example-loop-codex_ed25519"),
            },
        ],
    }
}

/// ´test:crate:loop-keygen-existing-file-refusal-uses-runner-probe´
#[test]
fn loop_keygen_existing_file_refusal_uses_runner_probe() {
    let path = "/keys/example-loop_ed25519";
    let replies = vec![Reply::success(
        format!("probe-key-path--e-{path}"),
        Vec::new(),
    )];
    let mut runner = ScriptedRunner::new(replies);
    let mut output = Vec::new();
    let options = LoopOptions {
        loop_name: String::from("example-loop"),
        directory: PathBuf::from("/keys"),
    };
    let error =
        run_loop_keygen_with_input(&options, &fictional_loop_output(), &mut runner, &mut output)
            .expect_err("existing key path is refused");
    assert_eq!(error.status(), 3);
    assert!(error.diagnostic("account keygen").contains(path));
    assert!(runner.commands.iter().all(|command| !command.mutation));
    runner.assert_done();
}

/// ´test:crate:malformed-stdin-key-refuses-before-any-remote-command´
#[test]
fn malformed_stdin_key_refuses_before_any_remote_command() {
    let mut runner = ScriptedRunner::default();
    let mut input = b"ssh-ed25519 bad!\n".as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = staff_provision_entry(
        [
            "--server",
            "sagofink",
            "--ssh-alias",
            "sagofink-root",
            "admit-key",
            "example-loop",
        ],
        &mut runner,
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(status, 3);
    assert!(
        String::from_utf8(error)
            .expect("UTF-8 diagnostic")
            .contains("public_key_malformed")
    );
    assert_eq!(runner.commands, Vec::new());
}

/// ´test:crate:sudo-noninteractive-failure-is-classed-and-never-retried´
#[test]
fn sudo_noninteractive_failure_is_classed_and_never_retried() {
    let replies = vec![Reply::failure(
        "sudo-preflight-example-loop",
        b"sudo: a password is required\n".to_vec(),
    )];
    let mut runner = ScriptedRunner::new(replies);
    let mut input = KEY.as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = staff_provision_entry(
        [
            "--server",
            "sagofink",
            "--ssh-alias",
            "sagofink-root",
            "admit-key",
            "example-loop",
        ],
        &mut runner,
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(status, 3);
    assert!(
        String::from_utf8(error)
            .expect("UTF-8 diagnostic")
            .contains("sudo_refused")
    );
    assert_eq!(runner.commands.len(), 1);
    runner.assert_done();
}

/// ´test:crate:admit-dry-run-executes-zero-mutations´
#[test]
fn admit_dry_run_executes_zero_mutations() {
    let mut runner = ScriptedRunner::new(guarded_account_replies("example-loop", 1201));
    let mut input = KEY.as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = staff_provision_entry(
        [
            "--server",
            "sagofink",
            "--ssh-alias",
            "sagofink-root",
            "admit-key",
            "example-loop",
            "--dry-run",
        ],
        &mut runner,
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&error));
    assert!(runner.commands.iter().all(|command| !command.mutation));
    let report = String::from_utf8(output).expect("UTF-8 report");
    assert!(report.contains("plan=MUTATE"));
    assert!(report.contains("zero mutations executed"));
    assert!(report.contains("account=example-loop added standard input line 1"));
    runner.assert_done();
}

/// ´test:crate:explicit-alias-uses-registered-management-alias´
#[test]
fn explicit_alias_uses_registered_management_alias() {
    let mut runner = ScriptedRunner::new(guarded_account_replies("example-loop", 1201));
    let mut input = KEY.as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = staff_provision_entry(
        [
            "--server",
            "mondreiher",
            "--ssh-alias",
            "mondreiher-root",
            "admit-key",
            "example-loop",
            "--dry-run",
        ],
        &mut runner,
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&error));
    assert_eq!(runner.commands[0].argv[1], "mondreiher-root");
    runner.assert_done();
}

/// ´test:crate:check-missing-account-exits-zero-with-report´
#[test]
fn check_missing_account_exits_zero_with_report() {
    let replies = vec![
        Reply::success("sudo-preflight-missing", Vec::new()),
        Reply::status("probe-missing-account", 2),
    ];
    let mut runner = ScriptedRunner::new(replies);
    let mut input = &b""[..];
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = staff_provision_entry(
        [
            "--server",
            "sagofink",
            "--ssh-alias",
            "sagofink-root",
            "check",
            "missing",
        ],
        &mut runner,
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(status, 0);
    assert!(
        String::from_utf8(output)
            .expect("UTF-8 report")
            .contains("exists: no")
    );
    assert_eq!(error, Vec::new());
    runner.assert_done();
}

/// ´test:crate:check-reports-explicit-inherited-and-missing-mapping-sources´
#[test]
fn check_reports_explicit_inherited_and_missing_mapping_sources() {
    for (table, expected) in [
        (
            "Login Name SELinux User MLS/MCS Range Service\n\
             __default__ staff_u s0-s0:c0.c1023 *\n\
             example-loop unconfined_u s0-s0:c0.c1023 *\n",
            "  selinux-login: unconfined_u (explicit)\n",
        ),
        (
            "Login Name SELinux User MLS/MCS Range Service\n\
             __default__ staff_u s0-s0:c0.c1023 *\n",
            "  selinux-login: __default__ staff_u (no explicit row)\n",
        ),
        (
            "Login Name SELinux User MLS/MCS Range Service\n",
            "  selinux-login: missing (no explicit or __default__ row)\n",
        ),
    ] {
        let mut replies = vec![
            Reply::success("sudo-preflight-example-loop", Vec::new()),
            Reply::success(
                "probe-example-loop-account",
                b"example-loop:x:1201:1201::/var/home/example-loop:/bin/bash\n".to_vec(),
            ),
            Reply::success("probe-example-loop-groups", b"example-loop\n".to_vec()),
            Reply::success(
                "probe-example-loop-selinux-login",
                table.as_bytes().to_vec(),
            ),
        ];
        replies.extend(missing_surface_replies("example-loop"));
        let mut runner = ScriptedRunner::new(replies);
        let mut input = &b""[..];
        let mut output = Vec::new();
        let mut error = Vec::new();
        let status = staff_provision_entry(
            [
                "--server",
                "sagofink",
                "--ssh-alias",
                "sagofink-root",
                "check",
                "example-loop",
            ],
            &mut runner,
            &mut input,
            &mut output,
            &mut error,
        );
        assert_eq!(status, 0, "{}", String::from_utf8_lossy(&error));
        assert!(
            String::from_utf8(output)
                .expect("UTF-8 report")
                .contains(expected)
        );
        runner.assert_done();
    }
}

/// ´test:crate:loop-keygen-help-is-stable-and-runs-no-commands´
#[test]
fn loop_keygen_help_is_stable_and_runs_no_commands() {
    let mut runner = ScriptedRunner::default();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = loop_keygen_entry(["--help"], &mut runner, &mut output, &mut error);
    assert_eq!(status, 0);
    assert_eq!(output, LOOP_KEYGEN_HELP.as_bytes());
    for variable in [
        "LOOP_KEYGEN_COORDINATOR",
        "LOOP_KEYGEN_CLIENT_CONFIG",
        "LOOP_KEYGEN_SSH_RECORDS",
        "LOOP_KEYGEN_ROUTES",
    ] {
        assert!(String::from_utf8_lossy(&output).contains(variable));
    }
    assert_eq!(error, Vec::new());
    assert_eq!(runner.commands, Vec::new());
}

/// ´test:crate:loop-keygen-happy-path-uses-only-scripted-commands´
#[test]
fn loop_keygen_happy_path_uses_only_scripted_commands() {
    let paths = [
        "/keys/example-loop_ed25519",
        "/keys/example-loop_ed25519.pub",
        "/keys/example-loop-codex_ed25519",
        "/keys/example-loop-codex_ed25519.pub",
    ];
    let mut replies = Vec::new();
    for path in paths {
        replies.push(Reply::status(format!("probe-key-path--e-{path}"), 1));
        replies.push(Reply::status(format!("probe-key-path--L-{path}"), 1));
    }
    replies.extend([
        Reply::success("generate-loop-master-key", Vec::new()),
        Reply::success("generate-codex-worker-key", Vec::new()),
        Reply::success(
            "read-loop-master-public-key",
            b"ssh-ed25519 AAAA example-loop@workstation\n".to_vec(),
        ),
        Reply::success(
            "read-codex-worker-public-key",
            b"ssh-ed25519 AAAA example-loop-codex@workstation\n".to_vec(),
        ),
    ]);
    let mut runner = ScriptedRunner::new(replies);
    let mut output = Vec::new();
    let options = LoopOptions {
        loop_name: String::from("example-loop"),
        directory: PathBuf::from("/keys"),
    };
    run_loop_keygen_with_input(&options, &fictional_loop_output(), &mut runner, &mut output)
        .expect("configured key generation succeeds");
    let report = String::from_utf8(output).expect("UTF-8 report");
    let master = report
        .find("ssh-ed25519 AAAA example-loop@workstation")
        .expect("master key");
    let worker = report
        .find("ssh-ed25519 AAAA example-loop-codex@workstation")
        .expect("worker key");
    let request = report
        .find("provisioning request for Example Coordinator")
        .expect("request");
    let snippet = report
        .find("Host sagofink-orchestration")
        .expect("SSH snippet");
    assert!(master < worker && worker < request && request < snippet);
    assert_eq!(
        runner
            .commands
            .iter()
            .filter(|command| command.mutation)
            .count(),
        2
    );
    runner.assert_done();
}
