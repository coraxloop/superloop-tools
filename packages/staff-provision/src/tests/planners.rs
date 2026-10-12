use std::ffi::OsString;
use std::path::PathBuf;

use crate::config::{AccountClass, LoopOptions, parse_staff_args};
use crate::keys::{merge_keys, parse_key_text};
use crate::loop_keygen::{
    LoopOutputInput, SshRecord, SshRoute, output_input_from_environment, plan_loop_keygen,
    render_request_and_ssh, run_loop_keygen_with_input,
};
use crate::planner::{create_setup_plan, validate_create_prestate};
use crate::probe::mapping_for;
use crate::runner::{CommandSpec, render_argv};
use crate::state::{AccountState, SurfaceState, guard_account};

fn guarded_state() -> AccountState {
    AccountState {
        name: String::from("example-loop"),
        exists: true,
        uid: Some(1201),
        gid: Some(1201),
        home: Some(String::from("/var/home/example-loop")),
        groups: vec![String::from("example-loop")],
        mapping: Some(String::from("staff_u")),
        default_mapping: None,
        ssh: SurfaceState::default(),
        authorized_keys: SurfaceState::default(),
        git: SurfaceState::default(),
        loops: SurfaceState::default(),
        correspondence: SurfaceState::default(),
        authorized_text: String::new(),
    }
}

fn fictional_ssh_records() -> Vec<SshRecord> {
    vec![
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
    ]
}

fn fictional_routes() -> Vec<SshRoute> {
    fictional_ssh_records()
        .into_iter()
        .enumerate()
        .map(|(index, record)| SshRoute {
            alias: record.alias,
            address: format!("192.0.2.{}", index + 1),
            port: "2222".into(),
            host_key: None,
        })
        .collect()
}

fn fictional_output_input(records: &str) -> Result<LoopOutputInput, crate::ProvisionError> {
    let routes = records
        .lines()
        .enumerate()
        .map(|(index, record)| {
            format!(
                "{}\t192.0.2.{}\t2222",
                record.split('\t').next().unwrap_or_default(),
                index + 1
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    output_input_from_environment(|name| {
        let value = match name {
            "LOOP_KEYGEN_COORDINATOR" => "Example Coordinator",
            "LOOP_KEYGEN_CLIENT_CONFIG" => "/home/example/.ssh/config",
            "LOOP_KEYGEN_SSH_RECORDS" => records,
            "LOOP_KEYGEN_ROUTES" => &routes,
            _ => return None,
        };
        Some(OsString::from(value))
    })
}

/// ´test:crate:well-formed-public-key-accepts-optional-comment´
#[test]
fn well_formed_public_key_accepts_optional_comment() {
    let keys =
        parse_key_text("stdin", "ssh-ed25519 AAAA example-loop@host\n").expect("valid key line");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].number, 1);
}

/// ´test:crate:malformed-public-key-names-offending-line´
#[test]
fn malformed_public_key_names_offending_line() {
    let error = parse_key_text(
        "standard input",
        "ssh-ed25519 AAAA first\nssh-ed25519 !!! second\n",
    )
    .expect_err("bad base64 is refused");
    assert_eq!(error.class(), "public_key_malformed");
    assert!(
        error
            .diagnostic("account")
            .contains("standard input line 2")
    );
}

/// ´test:crate:blank-public-key-line-is-malformed´
#[test]
fn blank_public_key_line_is_malformed() {
    let error = parse_key_text("stdin", "\n").expect_err("blank input is refused");
    assert_eq!(error.class(), "public_key_malformed");
}

/// ´test:crate:duplicate-key-is-skipped-by-exact-line´
#[test]
fn duplicate_key_is_skipped_by_exact_line() {
    let keys = parse_key_text("stdin", "ssh-ed25519 AAAA same\n").expect("valid key line");
    let merged = merge_keys("ssh-ed25519 AAAA same\n", &keys);
    assert_eq!(merged.content, "ssh-ed25519 AAAA same\n");
    assert!(!merged.lines[0].added);
}

/// ´test:crate:different-comment-is-not-an-exact-duplicate´
#[test]
fn different_comment_is_not_an_exact_duplicate() {
    let keys = parse_key_text("stdin", "ssh-ed25519 AAAA new\n").expect("valid key line");
    let merged = merge_keys("ssh-ed25519 AAAA old\n", &keys);
    assert!(merged.lines[0].added);
    assert!(merged.content.ends_with("ssh-ed25519 AAAA new\n"));
}

/// ´test:crate:guard-accepts-explicit-staff-mapping-over-nonstaff-default´
#[test]
fn guard_accepts_explicit_staff_mapping_over_nonstaff_default() {
    let mut state = guarded_state();
    state.default_mapping = Some(String::from("unconfined_u"));
    guard_account(&state).expect("explicit staff_u mapping wins");
}

/// ´test:crate:guard-refuses-explicit-nonstaff-mapping-regardless-of-default´
#[test]
fn guard_refuses_explicit_nonstaff_mapping_regardless_of_default() {
    let mut state = guarded_state();
    state.mapping = Some(String::from("unconfined_u"));
    state.default_mapping = Some(String::from("staff_u"));
    let error = guard_account(&state).expect_err("wrong mapping is refused");
    assert_eq!(error.class(), "guard_mapping");
    assert!(
        error
            .diagnostic("account")
            .contains("explicit mapping is unconfined_u")
    );
}

/// ´test:crate:guard-accepts-inherited-staff-default´
#[test]
fn guard_accepts_inherited_staff_default() {
    let mut state = guarded_state();
    state.mapping = None;
    state.default_mapping = Some(String::from("staff_u"));
    guard_account(&state).expect("staff_u default is inherited");
}

/// ´test:crate:guard-refuses-inherited-nonstaff-default´
#[test]
fn guard_refuses_inherited_nonstaff_default() {
    let mut state = guarded_state();
    state.mapping = None;
    state.default_mapping = Some(String::from("unconfined_u"));
    let error = guard_account(&state).expect_err("wrong default is refused");
    assert_eq!(error.class(), "guard_mapping");
    assert!(
        error
            .diagnostic("account")
            .contains("inherited __default__ mapping is unconfined_u")
    );
}

/// ´test:crate:guard-refuses-absent-explicit-and-default-rows´
#[test]
fn guard_refuses_absent_explicit_and_default_rows() {
    let mut state = guarded_state();
    state.mapping = None;
    let error = guard_account(&state).expect_err("unknown mapping is refused");
    assert_eq!(error.class(), "guard_mapping");
    assert!(
        error
            .diagnostic("account")
            .contains("has no explicit or __default__ mapping")
    );
}

/// ´test:crate:semanage-table-parser-reads-explicit-and-default-rows´
#[test]
fn semanage_table_parser_reads_explicit_and_default_rows() {
    let table = b"\
Login Name                SELinux User              MLS/MCS Range             Service\n\
__default__               staff_u                   s0-s0:c0.c1023            *\n\
administrator             unconfined_u              s0-s0:c0.c1023            *\n\
root                      unconfined_u              s0-s0:c0.c1023            *\n";
    let (mapping, default_mapping) =
        mapping_for("administrator", table).expect("valid semanage table");
    assert_eq!(mapping.as_deref(), Some("unconfined_u"));
    assert_eq!(default_mapping.as_deref(), Some("staff_u"));

    let (mapping, default_mapping) =
        mapping_for("example-loop", table).expect("valid semanage table");
    assert_eq!(mapping, None);
    assert_eq!(default_mapping.as_deref(), Some("staff_u"));
}

/// ´test:crate:guard-refuses-wheel-group´
#[test]
fn guard_refuses_wheel_group() {
    let mut state = guarded_state();
    state.groups.push(String::from("wheel"));
    let error = guard_account(&state).expect_err("wheel is refused");
    assert_eq!(error.class(), "guard_wheel");
}

/// ´test:crate:guard-refuses-uid-at-boundary´
#[test]
fn guard_refuses_uid_at_boundary() {
    let mut state = guarded_state();
    state.uid = Some(1000);
    let error = guard_account(&state).expect_err("uid 1000 is refused");
    assert_eq!(error.class(), "guard_uid");
}

/// ´test:crate:guard-refuses-missing-account´
#[test]
fn guard_refuses_missing_account() {
    let state = AccountState {
        name: String::from("missing"),
        ..AccountState::default()
    };
    let error = guard_account(&state).expect_err("missing account is refused");
    assert_eq!(error.class(), "account_missing");
}

/// ´test:crate:create-refuses-existing-account´
#[test]
fn create_refuses_existing_account() {
    let state = guarded_state();
    let error = validate_create_prestate(&state, 1201, None)
        .expect_err("existing create target is refused");
    assert_eq!(error.class(), "account_exists");
}

/// ´test:crate:create-refuses-taken-uid´
#[test]
fn create_refuses_taken_uid() {
    let state = AccountState {
        name: String::from("newloop"),
        ..AccountState::default()
    };
    let error = validate_create_prestate(&state, 1202, Some("somebody"))
        .expect_err("assigned uid is refused");
    assert_eq!(error.class(), "uid_taken");
}

/// ´test:crate:create-refuses-low-requested-uid´
#[test]
fn create_refuses_low_requested_uid() {
    let state = AccountState {
        name: String::from("newloop"),
        ..AccountState::default()
    };
    let error =
        validate_create_prestate(&state, 999, None).expect_err("low requested uid is refused");
    assert_eq!(error.class(), "guard_uid");
}

/// ´test:crate:loop-create-requires-explicit-showcase´
#[test]
fn loop_create_requires_explicit_showcase() {
    let error = parse_staff_args([
        "--server",
        "sagofink",
        "create",
        "newloop",
        "--class",
        "loop",
        "--uid",
        "1202",
        "--key",
        "/tmp/fake.pub",
    ])
    .expect_err("missing showcase is refused");
    assert_eq!(error.class(), "showcase_required");
}

/// ´test:crate:create-plan-maps-and-locks-before-installing-keys´
#[test]
fn create_plan_maps_and_locks_before_installing_keys() {
    let keys = parse_key_text("fixture", "ssh-ed25519 AAAA loop\n").expect("valid key line");
    let plan = create_setup_plan("sagofink-root", "newloop", AccountClass::Loop, 1202, &keys);
    assert_eq!(plan[0].argv[4], "'useradd'");
    assert_eq!(plan[1].argv[4], "'semanage'");
    assert_eq!(plan[2].argv[4], "'passwd'");
    assert_eq!(plan[4].label, "install-newloop-authorized-keys");
}

/// ´test:crate:remote-command-quotes-every-metacharacter-bearing-argument´
#[test]
fn remote_command_quotes_every_metacharacter_bearing_argument() {
    let command = CommandSpec::remote(
        "sagofink-root",
        "quote-metacharacters",
        false,
        [
            String::from("printf"),
            String::from("pipe | space"),
            String::from("it's"),
            String::from("$HOME"),
            String::from("*.pub"),
        ],
        Vec::new(),
        false,
    );
    assert_eq!(
        command.argv,
        vec![
            String::from("ssh"),
            String::from("sagofink-root"),
            String::from("'printf'"),
            String::from("'pipe | space'"),
            String::from("'it'\\''s'"),
            String::from("'$HOME'"),
            String::from("'*.pub'"),
        ]
    );
}

/// ´test:crate:remote-command-quotes-plain-tokens-including-sudo´
#[test]
fn remote_command_quotes_plain_tokens_including_sudo() {
    let command = CommandSpec::remote(
        "sagofink-root",
        "quote-plain-tokens",
        true,
        [String::from("true")],
        Vec::new(),
        false,
    );
    assert_eq!(
        command.argv,
        vec![
            String::from("ssh"),
            String::from("sagofink-root"),
            String::from("'sudo'"),
            String::from("'-n'"),
            String::from("'true'"),
        ]
    );
    assert_eq!(
        render_argv(&command.argv),
        r#"["ssh", "sagofink-root", "'sudo'", "'-n'", "'true'"]"#
    );
}

/// ´test:crate:loop-keygen-planner-refuses-any-existing-destination´
#[test]
fn loop_keygen_planner_refuses_any_existing_destination() {
    let options = LoopOptions {
        loop_name: String::from("example-loop"),
        directory: PathBuf::from("/safe/keys"),
    };
    let error = plan_loop_keygen(&options, [false, false, true, false])
        .expect_err("existing worker private key is refused");
    assert_eq!(error.class(), "path_exists");
    assert!(
        error
            .diagnostic("account keygen")
            .contains("example-loop-codex_ed25519")
    );
}

/// ´test:crate:loop-output-environment-has-no-defaults´
#[test]
fn loop_output_environment_has_no_defaults() {
    for missing in [
        "LOOP_KEYGEN_COORDINATOR",
        "LOOP_KEYGEN_CLIENT_CONFIG",
        "LOOP_KEYGEN_SSH_RECORDS",
        "LOOP_KEYGEN_ROUTES",
    ] {
        let error = output_input_from_environment(|name| {
            if name == missing {
                return None;
            }
            let value = match name {
                "LOOP_KEYGEN_COORDINATOR" => "Example Coordinator",
                "LOOP_KEYGEN_CLIENT_CONFIG" => "/home/example/.ssh/config",
                "LOOP_KEYGEN_SSH_RECORDS" | "LOOP_KEYGEN_ROUTES" => "",
                _ => return None,
            };
            Some(OsString::from(value))
        })
        .expect_err("every output environment field is required");
        assert_eq!(error.class(), "usage_error");
        assert!(error.diagnostic("account keygen").contains(missing));
    }
}

/// ´test:crate:ssh-record-environment-accepts-arbitrary-cardinality´
#[test]
fn ssh_record_environment_accepts_arbitrary_cardinality() {
    let one = "sagofink-orchestration\texample-loop\t/keys/example-loop-codex_ed25519";
    let many =
        format!("{one}\nmondreiher-analysis\texample-loop\t/keys/example-loop-codex_ed25519");
    for (records, expected) in [("", 0), (one, 1), (many.as_str(), 2)] {
        let input = fictional_output_input(records).expect("valid configured output");
        assert_eq!(input.ssh_records.len(), expected);
        let rendered = render_request_and_ssh(
            &input,
            "example-loop",
            "ssh-ed25519 AAAA example-loop@workstation",
            "ssh-ed25519 AAAA example-loop-codex@workstation",
        )
        .expect("valid configured rendering");
        assert_eq!(rendered.matches("\nHost ").count(), expected);
    }
}

/// ´test:crate:configured-output-preserves-complete-request-and-ssh-framing´
#[test]
fn configured_output_preserves_complete_request_and_ssh_framing() {
    let input = LoopOutputInput {
        coordinator: String::from("Example Coordinator"),
        client_config: PathBuf::from("/home/example/.ssh/config"),
        ssh_records: fictional_ssh_records(),
        routes: fictional_routes(),
    };
    let rendered = render_request_and_ssh(
        &input,
        "example-loop",
        "ssh-ed25519 AAAA example-loop@workstation",
        "ssh-ed25519 AAAA example-loop-codex@workstation",
    )
    .expect("valid configured rendering");
    assert_eq!(
        rendered,
        concat!(
            "--- provisioning request for Example Coordinator ---\n",
            "To: Example Coordinator\n",
            "loop: example-loop\n",
            "requested account: example-loop\n",
            "loop master public key: ssh-ed25519 AAAA example-loop@workstation\n",
            "Codex worker public key: ssh-ed25519 AAAA example-loop-codex@workstation\n",
            "--- end provisioning request ---\n",
            "Include /home/example/.ssh/config\n",
            "\n",
            "Host sagofink-orchestration\n",
            "    HostName 192.0.2.1\n    Port 2222\n",
            "    User example-loop\n",
            "    IdentityFile /keys/example-loop-codex_ed25519\n",
            "    IdentitiesOnly yes\n",
            "    StrictHostKeyChecking accept-new\n",
            "# Note: SSH route sagofink-orchestration is unpinned\n",
            "\n",
            "Host mondreiher-analysis\n",
            "    HostName 192.0.2.2\n    Port 2222\n",
            "    User example-loop\n",
            "    IdentityFile /keys/example-loop-codex_ed25519\n",
            "    IdentitiesOnly yes\n",
            "    StrictHostKeyChecking accept-new\n",
            "# Note: SSH route mondreiher-analysis is unpinned\n",
        )
    );
}

/// ´test:crate:ssh-record-environment-refuses-extra-fields´
#[test]
fn ssh_record_environment_refuses_extra_fields() {
    for forbidden in ["HostName", "Port"] {
        let records = format!(
            "sagofink-orchestration\texample-loop\t/keys/example-loop-codex_ed25519\t{forbidden}=unexpected"
        );
        let error = fictional_output_input(&records).expect_err("extra fields are refused");
        assert_eq!(error.class(), "usage_error");
        assert!(
            error
                .diagnostic("account keygen")
                .contains("exactly alias, user, and identity_file")
        );
    }
}

/// ´test:crate:ssh-record-alias-and-user-refuse-endpoint-values´
#[test]
fn ssh_record_alias_and_user_refuse_endpoint_values() {
    let endpoint_values = [
        ["192", "0", "2", "1"].join("."),
        ["2001", "db8", "", "1"].join(":"),
        ["sagofink-orchestration", "22"].join(":"),
    ];
    for field in ["alias", "user"] {
        for value in &endpoint_values {
            let mut record = fictional_ssh_records().remove(0);
            if field == "alias" {
                record.alias.clone_from(value);
            } else {
                record.user.clone_from(value);
            }
            let input = LoopOutputInput {
                coordinator: String::from("Example Coordinator"),
                client_config: PathBuf::from("/home/example/.ssh/config"),
                ssh_records: vec![record],
                routes: fictional_routes(),
            };
            let error = render_request_and_ssh(&input, "example-loop", "master", "worker")
                .expect_err("endpoint-shaped values are refused");
            assert_eq!(error.class(), "alias_only_addressing");
            assert_eq!(error.status(), 3);
            assert!(error.diagnostic("account keygen").contains(field));
        }
    }
}

/// ´test:crate:invalid-ssh-record-refuses-before-key-commands´
#[test]
fn invalid_ssh_record_refuses_before_key_commands() {
    let options = LoopOptions {
        loop_name: String::from("example-loop"),
        directory: PathBuf::from("/keys"),
    };
    let mut input = LoopOutputInput {
        coordinator: String::from("Example Coordinator"),
        client_config: PathBuf::from("/home/example/.ssh/config"),
        ssh_records: fictional_ssh_records(),
        routes: fictional_routes(),
    };
    input.ssh_records[0].alias = ["sagofink-orchestration", "22"].join(":");
    let mut runner = super::ScriptedRunner::default();
    let mut output = Vec::new();
    let error = run_loop_keygen_with_input(&options, &input, &mut runner, &mut output)
        .expect_err("invalid configuration is refused before commands");
    assert_eq!(error.class(), "alias_only_addressing");
    assert_eq!(runner.commands, Vec::new());
    assert_eq!(output, Vec::new());
}

/// ´test:crate:rendered-hostnames-are-explicit-route-addresses´
#[test]
fn rendered_hostnames_are_explicit_route_addresses() {
    let input = LoopOutputInput {
        coordinator: String::from("Example Coordinator"),
        client_config: PathBuf::from("/home/example/.ssh/config"),
        ssh_records: fictional_ssh_records(),
        routes: fictional_routes(),
    };
    let rendered = render_request_and_ssh(&input, "example-loop", "master", "worker")
        .expect("valid configured rendering");
    let hostnames: Vec<_> = rendered
        .lines()
        .filter_map(|line| line.strip_prefix("    HostName "))
        .collect();
    assert_eq!(hostnames, vec!["192.0.2.1", "192.0.2.2"]);
}
