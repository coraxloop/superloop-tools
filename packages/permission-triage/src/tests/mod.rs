use std::time::Duration;

use serde_json::{Value, json};

use crate::command_checks::{HYGIENE_RULE_COUNT, HygieneRuleId, hygiene_rule};
use crate::{
    DecodeResult, FastLane, HAS_MODEL_RUN_PATH, HYGIENE_RULES, PermissionRequest, READ_ONLY_TABLE,
    classify, decode_request, matching_read_only_entry,
};

mod topology;

/// Bound for work whose cost is dominated by a fixture launch, scaled by a measured run.
///
/// The floor is the bound on an idle machine, where the value the test pinned still holds. The
/// measured term takes over once load makes the same spawn, kill and reap cost more wall, and the
/// cap keeps the bound below the hang the fixture itself stages, past which the assertion would
/// stop discriminating between a runner that returned at its deadline and one that waited for its
/// child. A sample large enough to reach the cap is a machine too loaded for the bound to mean
/// anything, and the assertion should say so rather than pass.
fn load_scaled_bound(floor: Duration, sample_ms: u64, multiple: u64, cap: Duration) -> Duration {
    floor
        .max(Duration::from_millis(sample_ms.saturating_mul(multiple)))
        .min(cap.max(floor))
}

/// ´test:crate:load-scaled-bound-holds-its-floor-scales-and-caps´
#[test]
fn load_scaled_bound_holds_its_floor_scales_and_caps() {
    let floor = Duration::from_secs(1);
    let cap = Duration::from_secs(8);
    assert_eq!(load_scaled_bound(floor, 0, 4, cap), floor);
    assert_eq!(load_scaled_bound(floor, 250, 4, cap), floor);
    assert_eq!(
        load_scaled_bound(floor, 400, 4, cap),
        Duration::from_millis(1_600)
    );
    assert_eq!(load_scaled_bound(floor, 5_000, 4, cap), cap);
    assert_eq!(
        load_scaled_bound(Duration::from_secs(12), 0, 4, cap),
        Duration::from_secs(12)
    );
}

fn input(tool: &str, tool_input: Value) -> Value {
    let mut value = json!({
        "session_id": "session-example",
        "cwd": "/project",
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_use_id": "use-example"
    });
    value["tool_input"] = tool_input;
    value
}

fn decode(value: &Value) -> DecodeResult {
    decode_request(&serde_json::to_vec(value).expect("fixture JSON serializes"))
}

fn decoded(tool: &str, tool_input: Value) -> PermissionRequest {
    match decode(&input(tool, tool_input)) {
        DecodeResult::Decoded(request) => *request,
        DecodeResult::Unclassifiable { reason } => panic!("fixture did not decode: {reason}"),
    }
}

fn bash(command: &str, timeout: Option<Value>, background: Option<Value>) -> PermissionRequest {
    let mut tool_input = json!({ "command": command });
    if let Some(timeout) = timeout {
        tool_input["timeout"] = timeout;
    }
    if let Some(background) = background {
        tool_input["run_in_background"] = background;
    }
    decoded("Bash", tool_input)
}

fn bash_in_cwd(command: &str, cwd: &str) -> PermissionRequest {
    let mut value = input("Bash", json!({ "command": command }));
    value["cwd"] = json!(cwd);
    match decode(&value) {
        DecodeResult::Decoded(request) => *request,
        DecodeResult::Unclassifiable { reason } => panic!("fixture did not decode: {reason}"),
    }
}

fn assert_rule(request: &PermissionRequest, expected: &str) {
    match classify(request) {
        FastLane::AgentError { rule, .. } => assert_eq!(rule, expected),
        verdict => panic!("expected {expected}, received {verdict:?}"),
    }
}

/// ´test:crate:complete-hook-request-decodes-and-exposes-typed-fields´
#[test]
fn complete_hook_request_decodes_and_exposes_typed_fields() {
    let mut value = input(
        "Bash",
        json!({
            "command": "pwd",
            "description": "observe the project",
            "timeout": 3000,
            "run_in_background": false,
            "future_bash_field": [1, 2, 3]
        }),
    );
    value["future_hook_field"] = json!({ "ignored": true });
    let DecodeResult::Decoded(request) = decode(&value) else {
        panic!("complete fixture must decode");
    };
    assert_eq!(request.session_id(), "session-example");
    assert_eq!(request.cwd(), "/project");
    assert_eq!(request.permission_mode(), "manual");
    assert_eq!(request.hook_event_name(), "PreToolUse");
    assert_eq!(request.tool_name(), "Bash");
    assert_eq!(request.tool_use_id(), "use-example");
    let bash = request.bash().expect("Bash adapter is present");
    assert_eq!(bash.command(), "pwd");
    assert_eq!(bash.description(), Some("observe the project"));
    assert_eq!(bash.timeout_ms(), Some(3000));
    assert_eq!(bash.run_in_background(), Some(false));
}

/// ´test:crate:optional-role-signal-fields-decode-without-tightening-input´
#[test]
fn optional_role_signal_fields_decode_without_tightening_input() {
    let absent = decode(&input("Read", json!({ "file_path": "README.md" })));
    let absent_debug = format!("{absent:?}");
    assert!(
        absent_debug.contains("transcript_path: None"),
        "absent optional role signals must remain absent after decoding"
    );
    assert!(absent_debug.contains("agent_id: None"));

    let mut present = input("Read", json!({ "file_path": "README.md" }));
    present["transcript_path"] = json!("/run/subagents/agent.jsonl");
    present["agent_id"] = json!("agent-7");
    present["future_hook_field"] = json!({ "still": "ignored" });
    let present_debug = format!("{:?}", decode(&present));
    assert!(present_debug.contains("/run/subagents/agent.jsonl"));
    assert!(present_debug.contains("agent-7"));

    for (field, value) in [
        ("transcript_path", json!(7)),
        ("agent_id", json!(["agent"])),
    ] {
        let mut wrong = input("Read", json!({ "file_path": "README.md" }));
        wrong[field] = value;
        assert!(matches!(decode(&wrong), DecodeResult::Decoded(_)));
    }
}

/// ´test:crate:malformed-json-and-non-object-are-unclassifiable´
#[test]
fn malformed_json_and_non_object_are_unclassifiable() {
    for bytes in [b"{".as_slice(), b"[]".as_slice()] {
        assert!(matches!(
            decode_request(bytes),
            DecodeResult::Unclassifiable { .. }
        ));
    }
}

/// ´test:crate:missing-and-wrong-typed-hook-fields-are-unclassifiable´
#[test]
fn missing_and_wrong_typed_hook_fields_are_unclassifiable() {
    let fields = [
        "session_id",
        "cwd",
        "permission_mode",
        "hook_event_name",
        "tool_name",
        "tool_input",
        "tool_use_id",
    ];
    for field in fields {
        let mut missing = input("Read", json!({ "file_path": "README.md" }));
        missing
            .as_object_mut()
            .expect("object fixture")
            .remove(field);
        assert!(matches!(
            decode(&missing),
            DecodeResult::Unclassifiable { .. }
        ));

        let mut wrong = input("Read", json!({ "file_path": "README.md" }));
        wrong[field] = Value::Bool(false);
        assert!(matches!(
            decode(&wrong),
            DecodeResult::Unclassifiable { .. }
        ));
    }
}

/// ´test:crate:wrong-event-and-bash-field-types-are-unclassifiable´
#[test]
fn wrong_event_and_bash_field_types_are_unclassifiable() {
    let mut wrong_event = input("Read", json!({ "file_path": "README.md" }));
    wrong_event["hook_event_name"] = json!("PostToolUse");
    assert!(matches!(
        decode(&wrong_event),
        DecodeResult::Unclassifiable { .. }
    ));

    let fixtures = [
        json!({}),
        json!({ "command": 7 }),
        json!({ "command": "pwd", "description": false }),
        json!({ "command": "pwd", "run_in_background": "yes" }),
        json!({ "command": "pwd", "timeout": -1 }),
        json!({ "command": "pwd", "timeout": 1.5 }),
        json!({ "command": "pwd", "timeout": 600_001 }),
    ];
    for fixture in fixtures {
        assert!(matches!(
            decode(&input("Bash", fixture)),
            DecodeResult::Unclassifiable { .. }
        ));
    }
}

/// ´test:crate:timeout-number-string-and-absence-have-distinct-results´
#[test]
fn timeout_number_string_and_absence_have_distinct_results() {
    assert!(matches!(
        decode(&input("Bash", json!({ "command": "pwd", "timeout": 1 }))),
        DecodeResult::Decoded(_)
    ));
    assert!(matches!(
        decode(&input("Bash", json!({ "command": "pwd", "timeout": "1" }))),
        DecodeResult::Unclassifiable { .. }
    ));
    let DecodeResult::Decoded(request) = decode(&input("Bash", json!({ "command": "pwd" }))) else {
        panic!("absent optional timeout must decode");
    };
    assert_eq!(request.bash().expect("Bash input").timeout_ms(), None);
}

/// ´test:crate:every-read-only-claim-has-a-positive-and-negative-twin´
#[test]
fn every_read_only_claim_has_a_positive_and_negative_twin() {
    let twins = [
        (
            "native-read",
            decoded(
                "Read",
                json!({ "file_path": "docs/guide.md", "offset": 0, "limit": 20 }),
            ),
            decoded("Read", json!({ "file_path": "/etc/passwd" })),
        ),
        (
            "native-glob",
            decoded("Glob", json!({ "pattern": "**/*.rs", "path": "packages" })),
            decoded("Glob", json!({ "pattern": "**/*", "path": "../outside" })),
        ),
        (
            "native-grep",
            decoded("Grep", json!({ "pattern": "timeout", "path": "packages" })),
            decoded("Grep", json!({ "pattern": "key", "path": ".ssh" })),
        ),
        (
            "native-web-search",
            decoded("WebSearch", json!({ "query": "Rust shell tokenization" })),
            decoded("WebSearch", json!({ "query": "lookup token=sample" })),
        ),
        (
            "native-get-web-fetch",
            decoded(
                "WebFetch",
                json!({ "url": "https://example.invalid/guide", "method": "GET" }),
            ),
            decoded(
                "WebFetch",
                json!({ "url": "https://example.invalid/", "method": "POST", "body": "x" }),
            ),
        ),
        (
            "bash-filesystem-observation",
            bash("stat packages/README.md", None, None),
            bash("stat /etc/passwd", None, None),
        ),
        (
            "bash-source-observation",
            bash("sed -n '1,4p' packages/README.md", None, None),
            bash("sed -i 's/a/b/' packages/README.md", None, None),
        ),
        (
            "bash-repository-observation",
            bash("git status --short", None, None),
            bash("git fetch origin", None, None),
        ),
    ];

    assert_eq!(twins.len(), READ_ONLY_TABLE.len());
    for (expected, positive, negative) in twins {
        assert_eq!(
            matching_read_only_entry(&positive).map(|entry| entry.entry),
            Some(expected)
        );
        assert_eq!(classify(&positive), FastLane::ToModel);
        assert!(matching_read_only_entry(&negative).is_none());
        assert_eq!(classify(&negative), FastLane::ToModel);
    }
}

/// ´test:crate:every-read-only-claim-is-disabled-and-has-an-exact-grammar´
#[test]
fn every_read_only_claim_is_disabled_and_has_an_exact_grammar() {
    assert_eq!(HYGIENE_RULES.len(), 8);
    assert_eq!(
        READ_ONLY_TABLE
            .iter()
            .map(|entry| entry.entry)
            .collect::<Vec<_>>(),
        [
            "native-read",
            "native-glob",
            "native-grep",
            "native-web-search",
            "native-get-web-fetch",
            "bash-filesystem-observation",
            "bash-source-observation",
            "bash-repository-observation",
        ]
    );
    for entry in READ_ONLY_TABLE {
        assert!(!entry.accepted);
        assert_ne!(entry.grammar, "");
    }
}

/// ´test:crate:remote-timeout-check-has-positive-and-negative-twins´
#[test]
fn remote_timeout_check_has_positive_and_negative_twins() {
    let commands = [
        "ssh worker-alias 'stat /srv/report'",
        "scp report.txt worker-alias:/srv/report.txt",
        "sftp worker-alias:/srv/report.txt",
        "rsync report.txt worker-alias:/srv/report.txt",
    ];
    for command in commands {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[0].rule);
        assert_eq!(
            classify(&bash(command, Some(json!(20_000)), None)),
            FastLane::ToModel
        );
    }
    assert_eq!(
        classify(&bash(
            "timeout 20 ssh worker-alias 'stat /srv/report'",
            None,
            None,
        )),
        FastLane::ToModel
    );
    for command in [
        "timeout -k 5 30 ssh worker-alias 'stat /srv/report'",
        "timeout --signal=TERM --foreground 30 ssh worker-alias 'stat /srv/report'",
        "timeout --preserve-status 30 ssh worker-alias 'stat /srv/report' | tail -1",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    assert_rule(
        &bash(
            "timeout -k 5 30 ssh worker-alias 'stat /srv/report' && echo complete",
            None,
            None,
        ),
        HYGIENE_RULES[0].rule,
    );
}

/// ´test:crate:remote-timeout-credit-is-confined-to-its-pipeline-stage´
#[test]
fn remote_timeout_credit_is_confined_to_its_pipeline_stage() {
    assert_rule(
        &bash(
            "timeout 20 printf payload | ssh worker-alias 'cat > report'",
            None,
            None,
        ),
        HYGIENE_RULES[0].rule,
    );
    assert_eq!(
        classify(&bash(
            "printf payload | timeout 20 ssh worker-alias 'cat > report'",
            None,
            None,
        )),
        FastLane::ToModel
    );
}

/// ´test:crate:background-contract-check-has-positive-and-negative-twins´
#[test]
fn background_contract_check_has_positive_and_negative_twins() {
    let malformed = bash(
        "worker --job-id job-7 >> logs/job-7.log",
        Some(json!(5000)),
        Some(json!(true)),
    );
    assert_rule(&malformed, HYGIENE_RULES[1].rule);

    let complete = bash(
        "worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status >> logs/job-7.log",
        Some(json!(5000)),
        Some(json!(true)),
    );
    assert_eq!(classify(&complete), FastLane::ToModel);
}

/// ´test:crate:execution-timing-check-has-positive-and-negative-twins´
#[test]
fn execution_timing_check_has_positive_and_negative_twins() {
    let twins = [
        ("cargo build -p widget", "time cargo build -p widget"),
        ("cargo test -p widget", "time cargo test -p widget"),
        ("cargo clippy -p widget", "time cargo clippy -p widget"),
        ("pip install widget", "/usr/bin/time pip install widget"),
        ("docker build .", "time docker build ."),
        ("ninja check", "time nice -n19 ninja check"),
    ];
    for (malformed, timed) in twins {
        assert_rule(&bash(malformed, None, None), HYGIENE_RULES[2].rule);
        assert_eq!(classify(&bash(timed, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:one-objective-check-has-positive-and-negative-twins´
#[test]
fn one_objective_check_has_positive_and_negative_twins() {
    let batched = bash(
        "touch config/generated && time cargo test -p widget",
        None,
        None,
    );
    assert_rule(&batched, HYGIENE_RULES[3].rule);
    assert_eq!(
        classify(&bash("touch config/generated", None, None)),
        FastLane::ToModel
    );
}

/// ´test:crate:pipeline-status-check-has-positive-and-negative-twins´
#[test]
fn pipeline_status_check_has_positive_and_negative_twins() {
    let hidden = bash("time cargo test -p widget | tail -1", None, None);
    assert_rule(&hidden, HYGIENE_RULES[4].rule);
    let preserved = bash(
        "set -o pipefail && time cargo test -p widget | tail -1",
        None,
        None,
    );
    assert_eq!(classify(&preserved), FastLane::ToModel);
}

/// ´test:crate:destructive-operand-check-rejects-every-unbounded-shape´
#[test]
fn destructive_operand_check_rejects_every_unbounded_shape() {
    let malformed = [
        "rm -rf $TARGET",
        "rm -rf build/*",
        "rm -rf $(target)",
        "rm -rf ../build",
        "rm -rf .",
        "rm -rf /",
        "rm -rf ''",
    ];
    for command in malformed {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
    assert_eq!(
        classify(&bash("rm -rf build/generated", None, None)),
        FastLane::ToModel
    );
}

/// ´test:crate:remote-privilege-check-has-positive-and-negative-twins´
#[test]
fn remote_privilege_check_has_positive_and_negative_twins() {
    let malformed = bash(
        "ssh 192.0.2.1 'sudo stat /root/report'",
        Some(json!(20_000)),
        None,
    );
    assert_rule(&malformed, HYGIENE_RULES[6].rule);

    let complete = bash(
        "ssh -o BatchMode=yes worker-alias 'sudo -u root -n stat /root/report'",
        Some(json!(20_000)),
        None,
    );
    assert_eq!(classify(&complete), FastLane::ToModel);
}

/// ´test:crate:parseable-syntax-check-has-positive-and-negative-twins´
#[test]
fn parseable_syntax_check_has_positive_and_negative_twins() {
    let malformed = [
        "echo 'unterminated",
        "echo $(unterminated",
        "run <command>",
        "cat <<EOF\nunterminated body",
        "echo left &&",
    ];
    for command in malformed {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[7].rule);
    }
    let valid = [
        "printf '%s\\n' 'a b' escaped\\ value",
        "echo \"$(pwd)\"",
        "echo '<<'",
        "pwd | wc -l",
        "(pwd && stat packages/README.md)",
    ];
    for command in valid {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:valid-heredoc-is-conservatively-model-routed´
#[test]
fn valid_heredoc_is_conservatively_model_routed() {
    let request = bash("cat <<EOF\nbody\nEOF", None, None);
    assert_eq!(classify(&request), FastLane::ToModel);
}

/// ´test:crate:arithmetic-commands-are-ambiguous-not-executable-heads´
#[test]
fn arithmetic_commands_are_ambiguous_not_executable_heads() {
    for command in ["((count += 1))", "((rm))"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:arithmetic-commands-do-not-hide-later-destructive-operands´
#[test]
fn arithmetic_commands_do_not_hide_later_destructive_operands() {
    assert_rule(
        &bash("foo && ((i++)) && rm -rf /", None, None),
        HYGIENE_RULES[5].rule,
    );
}

/// ´test:crate:arithmetic-masking-still-sees-substituted-destructive-commands´
#[test]
fn arithmetic_masking_still_sees_substituted_destructive_commands() {
    for command in [
        "((x = $(rm -rf /)))",
        "foo && (( $(rm -rf /) ))",
        "((x = `rm -rf /`))",
        "((x = \"$(rm -rf /)\"))",
        "((x = $( $(rm -rf /) )))",
        "((x = $(( $(rm -rf /) ))))",
        "((x = '$(rm -rf /)'))",
        "$((x = '$(rm -rf /)'))",
        "$((x = $(rm -rf /)))",
        "echo $((x = $(rm -rf /)))",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
}

/// A quoted parenthesis inside the arithmetic must not cost the rest of the command.
///
/// Losing the closing `))` makes the whole arithmetic unmaskable, and the fallback keeps only the
/// prefix before it — which for a command that opens with `((` is nothing at all, so every later
/// command would go unexamined.
///
/// ´test:crate:quoted-parenthesis-in-arithmetic-keeps-the-rest-of-the-command´
#[test]
fn quoted_parenthesis_in_arithmetic_keeps_the_rest_of_the_command() {
    for command in [
        "((n = $(grep -c '(' f))) ; rm -rf /",
        "((n = $(grep -c ')' f))) && rm -rf /",
        "foo && ((n = $(grep -c '(' f))) ; rm -rf /",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
}

/// ´test:crate:arithmetic-substitutions-add-no-allow-and-stay-opaque´
#[test]
fn arithmetic_substitutions_add_no_allow_and_stay_opaque() {
    for command in [
        "((x = $(git rev-parse HEAD)))",
        "$((x = $(git rev-parse HEAD)))",
        "echo '$((x = $(rm -rf /)))'",
        "((count += 1))",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:trailing-command-terminators-are-ordinary´
#[test]
fn trailing_command_terminators_are_ordinary() {
    for command in [
        "echo ok ",
        "echo ok\n",
        "echo ok  \n",
        "echo ok;",
        "echo ok; \n",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    for command in ["echo ok;;", "echo ok &&"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[7].rule);
    }
}

/// ´test:crate:placeholder-detection-does-not-reserve-program-names´
#[test]
fn placeholder_detection_does_not_reserve_program_names() {
    for command in [
        "(command -v cargo) && echo ok",
        "(replace old new) && echo ok",
        "(insert row) && echo ok",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    for command in ["run replace_me", "run ...", "run <command>", "read <path>"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[7].rule);
    }
}

/// ´test:crate:function-definitions-and-array-assignments-are-ambiguous´
#[test]
fn function_definitions_and_array_assignments_are_ambiguous() {
    for command in ["f() { echo ok; }", "arr=(1 2)"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    assert_rule(
        &bash("f() { rm -rf $TARGET; }", None, None),
        HYGIENE_RULES[5].rule,
    );
}

/// ´test:crate:unmodelled-redirection-constructs-preserve-destructive-prefixes´
#[test]
fn unmodelled_redirection_constructs_preserve_destructive_prefixes() {
    for command in ["rm -rf $HOME <(true)", "rm -rf $HOME <<EOF\nbody\nEOF"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
    for command in ["cat <(true)", "cat <<EOF\nbody\nEOF"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:ambiguous-prefixes-receive-the-full-hygiene-set´
#[test]
fn ambiguous_prefixes_receive_the_full_hygiene_set() {
    let fixtures = [
        (
            bash("ssh worker-alias 'stat report' <(true)", None, None),
            HYGIENE_RULES[0].rule,
        ),
        (
            bash("setsid worker <(true)", Some(json!(5000)), None),
            HYGIENE_RULES[1].rule,
        ),
        (
            bash("cargo test <(true)", None, None),
            HYGIENE_RULES[2].rule,
        ),
        (
            bash("touch one && touch two <(true)", None, None),
            HYGIENE_RULES[3].rule,
        ),
        (
            bash("time cargo test | tail -1 <(true)", None, None),
            HYGIENE_RULES[4].rule,
        ),
        (
            bash(
                "ssh 192.0.2.1 'sudo stat /root/report' <(true)",
                Some(json!(20_000)),
                None,
            ),
            HYGIENE_RULES[6].rule,
        ),
    ];
    for (request, rule) in fixtures {
        assert_rule(&request, rule);
    }
}

/// ´test:crate:trailing-pipelines-report-incomplete-syntax´
#[test]
fn trailing_pipelines_report_incomplete_syntax() {
    for command in ["(touch marker) |", "bash -c '(touch x) |'"] {
        match classify(&bash(command, None, None)) {
            FastLane::AgentError {
                rule, correction, ..
            } => {
                assert_eq!(rule, HYGIENE_RULES[7].rule);
                assert!(correction.contains("trailing connector has a consumer"));
            }
            verdict => panic!("expected incomplete-syntax denial, received {verdict:?}"),
        }
    }
}

/// ´test:crate:unmodelled-heads-route-ambiguously-after-destructive-checks´
#[test]
fn unmodelled_heads_route_ambiguously_after_destructive_checks() {
    for command in [
        "! test -f marker",
        "eval 'echo ok'",
        "exec echo ok",
        "source script.sh",
        ". script.sh",
        "[[ -f marker ]]",
        "select value in one two",
        "coproc echo ok",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    for command in ["! rm -rf $HOME", "exec rm -rf $HOME", "eval 'rm -rf $HOME'"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
}

/// ´test:crate:nested-shell-and-xargs-payloads-receive-hygiene-checks´
#[test]
fn nested_shell_and_xargs_payloads_receive_hygiene_checks() {
    for command in [
        "sh -c 'cargo test -p widget'",
        "bash -lc 'cargo test -p widget'",
        "xargs cargo test -p widget",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[2].rule);
    }
    for command in [
        "sh -c 'time cargo test -p widget'",
        "bash -lc 'time cargo test -p widget'",
        "xargs time cargo test -p widget",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:bash-rcfile-options-do-not-hide-command-payloads´
#[test]
fn bash_rcfile_options_do_not_hide_command_payloads() {
    for command in [
        "bash --rcfile config/bashrc -c 'cargo test -p widget'",
        "bash --rcfile=config/bashrc -c 'cargo test -p widget'",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[2].rule);
    }
    assert_eq!(
        classify(&bash(
            "bash --init-file config/bashrc -c 'time cargo test -p widget'",
            None,
            None,
        )),
        FastLane::ToModel
    );
}

/// ´test:crate:nested-wrapper-timing-and-redirect-share-the-payload-objective´
#[test]
fn nested_wrapper_timing_and_redirect_share_the_payload_objective() {
    for command in [
        "bash -c 'time cargo test -p widget' > logs/test.log",
        "time bash -c 'cargo test -p widget' > logs/test.log",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    assert_rule(
        &bash(
            "bash -c 'time touch first && touch second' > logs/test.log",
            None,
            None,
        ),
        HYGIENE_RULES[3].rule,
    );
}

/// ´test:crate:redirect-descriptors-are-not-destructive-operands´
#[test]
fn redirect_descriptors_are_not_destructive_operands() {
    assert_rule(
        &bash("rm -rf 2>/dev/null", None, None),
        HYGIENE_RULES[5].rule,
    );
    assert_eq!(
        classify(&bash("rm -rf build/generated 2>/dev/null", None, None)),
        FastLane::ToModel
    );
}

/// ´test:crate:fully-modelled-subshells-receive-all-hygiene-checks´
#[test]
fn fully_modelled_subshells_receive_all_hygiene_checks() {
    assert_rule(
        &bash("(cargo test -p widget)", None, None),
        HYGIENE_RULES[2].rule,
    );
    assert_eq!(
        classify(&bash("(time cargo test -p widget)", None, None)),
        FastLane::ToModel
    );
}

/// ´test:crate:redirect-on-closed-subshell-remains-in-the-shell-shape´
#[test]
fn redirect_on_closed_subshell_remains_in_the_shell_shape() {
    let complete = bash(
        "(setsid worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status) >> logs/job-7.log",
        Some(json!(5000)),
        Some(json!(true)),
    );
    assert_eq!(classify(&complete), FastLane::ToModel);
}

/// ´test:crate:angle-placeholders-win-over-redirect-tokenization´
#[test]
fn angle_placeholders_win_over_redirect_tokenization() {
    for command in ["run <command>", "read <path>"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[7].rule);
    }
    for command in ["run '<command>'", "read \"<path>\""] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    assert_rule(&bash("cat <", None, None), HYGIENE_RULES[7].rule);
}

/// ´test:crate:compound-read-commands-do-not-enter-the-simple-read-lane´
#[test]
fn compound_read_commands_do_not_enter_the_simple_read_lane() {
    let request = bash("pwd && git status --short", None, None);
    assert!(matching_read_only_entry(&request).is_none());
    assert_eq!(classify(&request), FastLane::ToModel);
}

/// ´test:crate:timing-a-pipeline-consumer-does-not-time-the-gate´
#[test]
fn timing_a_pipeline_consumer_does_not_time_the_gate() {
    let request = bash("cargo test -p widget | time tail -1", None, None);
    assert_rule(&request, HYGIENE_RULES[2].rule);
}

/// ´test:crate:command-arguments-are-not-mistaken-for-executables´
#[test]
fn command_arguments_are_not_mistaken_for_executables() {
    for command in ["echo ssh", "echo cargo test", "echo rm /"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    let decoy = bash(
        "echo pipefail && time cargo test -p widget | tail -1",
        None,
        None,
    );
    assert_rule(&decoy, HYGIENE_RULES[4].rule);
}

/// ´test:crate:command-builtin-query-is-informational´
#[test]
fn command_builtin_query_is_informational() {
    assert_eq!(
        classify(&bash("command -v rm", None, None)),
        FastLane::ToModel
    );
    assert_rule(&bash("command -v rm /", None, None), HYGIENE_RULES[5].rule);
    assert_rule(
        &bash("command -v cargo test", None, None),
        HYGIENE_RULES[2].rule,
    );
}

/// ´test:crate:type-which-and-hash-remain-ordinary-model-queries´
#[test]
fn type_which_and_hash_remain_ordinary_model_queries() {
    for command in ["type rm", "which rm", "hash rm"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:nested-remote-shell-receives-parse-and-timing-checks´
#[test]
fn nested_remote_shell_receives_parse_and_timing_checks() {
    let malformed = bash(
        "ssh worker-alias 'echo \"unterminated'",
        Some(json!(20_000)),
        None,
    );
    assert_rule(&malformed, HYGIENE_RULES[7].rule);

    let untimed = bash(
        "ssh worker-alias 'cargo test -p widget'",
        Some(json!(20_000)),
        None,
    );
    assert_rule(&untimed, HYGIENE_RULES[2].rule);
    let timed = bash(
        "ssh worker-alias 'time cargo test -p widget'",
        Some(json!(20_000)),
        None,
    );
    assert_eq!(classify(&timed), FastLane::ToModel);
}

/// ´test:crate:descriptor-and-null-redirects-are-nonmutating´
#[test]
fn descriptor_and_null_redirects_are_nonmutating() {
    for command in [
        "ls -l 2>&1 | grep foo",
        "ls a 2>/dev/null && ls b 2>/dev/null",
        "ls -l >&2",
        "ls -l 3>&4",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    assert_rule(
        &bash("ls > report.txt && ls >> report.txt", None, None),
        HYGIENE_RULES[3].rule,
    );
    assert_rule(
        &bash("ls >| report.txt | tail -1", None, None),
        HYGIENE_RULES[4].rule,
    );
}

/// ´test:crate:subshell-followed-by-connector-receives-hygiene-checks´
#[test]
fn subshell_followed_by_connector_receives_hygiene_checks() {
    let request = bash("(cd packages && time cargo test) | tail -1", None, None);
    assert_rule(&request, HYGIENE_RULES[4].rule);
}

/// ´test:crate:closed-subshell-redirects-can-precede-connectors´
#[test]
fn closed_subshell_redirects_can_precede_connectors() {
    assert_rule(
        &bash("(echo ok) > report && touch marker", None, None),
        HYGIENE_RULES[3].rule,
    );
    assert_rule(
        &bash("(time cargo test) > report | tail -1", None, None),
        HYGIENE_RULES[4].rule,
    );
}

/// ´test:crate:combined-stream-pipe-is-a-pipeline´
#[test]
fn combined_stream_pipe_is_a_pipeline() {
    assert_rule(
        &bash("time cargo test |& tail -1", None, None),
        HYGIENE_RULES[4].rule,
    );
    assert_eq!(
        classify(&bash(
            "set -o pipefail; time cargo test |& tail -1",
            None,
            None,
        )),
        FastLane::ToModel
    );
}

/// ´test:crate:shell-keywords-are-ambiguous-but-destructive-operands-still-run´
#[test]
fn shell_keywords_are_ambiguous_but_destructive_operands_still_run() {
    for command in [
        "for f in stale; do rm -rf $f; done",
        "{ rm -rf $X; }",
        "case $kind in stale) rm -rf $X;; esac",
        "function clean { rm -rf $X; }",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
    for command in [
        "while true; do make; done",
        "until test -f marker; do stat marker; done",
        "if test -f marker; then time cargo test; fi",
        "case $kind in read) stat file;; esac",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:broad-root-calculus-covers-depth-home-and-project-root´
#[test]
fn broad_root_calculus_covers_depth_home_and_project_root() {
    for operand in ["/etc", "/usr/lib", "/var/log", "/srv", "~", "~/one"] {
        assert_rule(
            &bash(&format!("rm -rf {operand}"), None, None),
            HYGIENE_RULES[5].rule,
        );
    }
    assert_rule(
        &bash_in_cwd("rm -rf /workspace/project/repo", "/workspace/project/repo"),
        HYGIENE_RULES[5].rule,
    );
    for operand in ["/var/log/archive", "~/one/two", "build/generated"] {
        assert_eq!(
            classify(&bash(&format!("rm -rf {operand}"), None, None)),
            FastLane::ToModel
        );
    }
}

/// ´test:crate:canonical-remote-privileged-shape-needs-no-host-key-option´
#[test]
fn canonical_remote_privileged_shape_needs_no_host_key_option() {
    let canonical = bash(
        "timeout 20 ssh -o BatchMode=yes -o ConnectTimeout=5 worker-alias 'sudo -u root -n head -c 1000 /srv/records/notice.md'",
        None,
        None,
    );
    assert_eq!(classify(&canonical), FastLane::ToModel);
    let no_deadline = bash(
        "ssh -o BatchMode=yes worker-alias 'sudo -u root -n stat /root/report'",
        None,
        None,
    );
    assert_rule(&no_deadline, HYGIENE_RULES[0].rule);
    let interactive = bash(
        "ssh -o BatchMode=yes worker-alias 'sudo -u root stat /root/report'",
        Some(json!(20_000)),
        None,
    );
    assert_rule(&interactive, HYGIENE_RULES[6].rule);
}

/// ´test:crate:quoted-placeholder-literals-are-not-pseudocode´
#[test]
fn quoted_placeholder_literals_are_not_pseudocode() {
    for command in ["rg -n 'replace_me' packages/", "rg '<path>' docs/"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
        assert_eq!(
            matching_read_only_entry(&bash(command, None, None)).map(|entry| entry.entry),
            Some("bash-source-observation")
        );
    }
    assert_rule(
        &bash("run (replace this value)", None, None),
        HYGIENE_RULES[7].rule,
    );
}

/// ´test:crate:keyword-recovery-checks-command-heads-not-arguments´
#[test]
fn keyword_recovery_checks_command_heads_not_arguments() {
    assert_eq!(
        classify(&bash(
            "while grep -q rm marker; do sleep 1; done",
            None,
            None,
        )),
        FastLane::ToModel
    );
    assert_rule(
        &bash("while true; do rm -rf $HOME; done", None, None),
        HYGIENE_RULES[5].rule,
    );
}

/// ´test:crate:git-mutation-detection-uses-the-subcommand-position´
#[test]
fn git_mutation_detection_uses_the_subcommand_position() {
    assert_eq!(
        classify(&bash("git show tag && git status", None, None)),
        FastLane::ToModel
    );
    assert_rule(
        &bash("git tag release && git commit -m release", None, None),
        HYGIENE_RULES[3].rule,
    );
}

/// ´test:crate:git-read-grammar-rejects-writing-relocation-and-outside-operands´
#[test]
fn git_read_grammar_rejects_writing_relocation_and_outside_operands() {
    let positive = bash("git log -- README.md", None, None);
    assert_eq!(
        matching_read_only_entry(&positive).map(|entry| entry.entry),
        Some("bash-repository-observation")
    );
    for command in [
        "git diff --output=report.txt",
        "git log --output=x",
        "git --git-dir=../other log",
        "git log /etc/passwd",
        "git show ../other",
    ] {
        assert!(matching_read_only_entry(&bash(command, None, None)).is_none());
    }
}

/// ´test:crate:pipeline-status-preservation-is-position-sensitive´
#[test]
fn pipeline_status_preservation_is_position_sensitive() {
    assert_rule(
        &bash("time cargo test | tail -1; set -o pipefail", None, None),
        HYGIENE_RULES[4].rule,
    );
    for command in [
        "set -o pipefail; time cargo test | tail -1",
        "time cargo test | tail -1; result=${PIPESTATUS[0]}",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:expanded-gate-roster-requires-execution-boundary-timing´
#[test]
fn expanded_gate_roster_requires_execution_boundary_timing() {
    let commands = [
        "go build ./...",
        "go test ./...",
        "go vet ./...",
        "cmake --build build",
        "gradle build",
        "mvn test",
        "tsc",
        "dnf install widget",
        "apt-get install widget",
        "apt install widget",
        "pip install widget",
        "npm install",
        "npm ci",
        "npm test",
        "npm run build",
        "npm run lint:all",
        "cargo bench",
        "cargo doc",
        "cargo run",
        "cargo nextest run",
        "meson compile -C build",
        "meson setup build",
        "meson test -C build",
        "ninja",
        "make",
    ];
    for command in commands {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[2].rule);
        assert_eq!(
            classify(&bash(&format!("time {command}"), None, None)),
            FastLane::ToModel
        );
    }
}

/// ´test:crate:promoted-gates-contribute-one-objective-per-simple-command´
#[test]
fn promoted_gates_contribute_one_objective_per_simple_command() {
    for command in [
        "bash -c 'time npm run build' > logs/npm.log",
        "bash -c 'time meson compile -C build' > logs/meson.log",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    assert_rule(
        &bash("time npm run build && time meson test -C build", None, None),
        HYGIENE_RULES[3].rule,
    );
}

/// ´test:crate:gate-information-shapes-do-not-require-timing´
#[test]
fn gate_information_shapes_do_not_require_timing() {
    for command in [
        "tsc --version",
        "mvn -version",
        "gradle --help",
        "gradle tasks",
        "cargo run --release -- --help",
        "cargo test -- --list",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    for command in ["tsc", "mvn test", "gradle build", "cargo run --release"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[2].rule);
    }
    for command in [
        "cargo test widget -- --list",
        "cargo run tool -- --help",
        "tsc src/main.ts --version",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[2].rule);
    }
}

/// ´test:crate:npm-run-help-is-informational-but-scripts-remain-gates´
#[test]
fn npm_run_help_is_informational_but_scripts_remain_gates() {
    assert_eq!(
        classify(&bash("npm run --help", None, None)),
        FastLane::ToModel
    );
    assert_rule(
        &bash("npm run build", None, None),
        hygiene_rule(HygieneRuleId::ExecutionTiming).rule,
    );
}

/// ´test:crate:scheduling-wrappers-never-hide-gates´
#[test]
fn scheduling_wrappers_never_hide_gates() {
    for command in [
        "nice -n 19 cargo build -p widget",
        "chrt -r 1 cargo build -p widget",
        "ionice -c 2 -n 7 cargo build -p widget",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[2].rule);
    }
    for command in [
        "nice -n 19 time cargo build -p widget",
        "chrt -r 1 time cargo build -p widget",
        "ionice -c 2 -n 7 time cargo build -p widget",
    ] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:crate:background-contract-needs-explicit-option-value-and-sees-wrappers´
#[test]
fn background_contract_needs_explicit_option_value_and_sees_wrappers() {
    for command in [
        "worker --job-id job-7 state/job-7.done >> logs/job-7.log; git status",
        "worker --job-id job-7 --completion-marker >> logs/job-7.log",
    ] {
        assert_rule(
            &bash(command, Some(json!(5000)), Some(json!(true))),
            HYGIENE_RULES[1].rule,
        );
    }
    let complete = bash(
        "env MODE=once nohup worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status >> logs/job-7.log",
        Some(json!(5000)),
        Some(json!(true)),
    );
    assert_eq!(classify(&complete), FastLane::ToModel);
}

/// ´test:crate:background-contract-requires-both-observers-and-a-real-log´
#[test]
fn background_contract_requires_both_observers_and_a_real_log() {
    for command in [
        "worker --job-id job-7 --completion-marker state/job-7.done >> logs/job-7.log",
        "worker --job-id job-7 --status-cmd worker-status >> logs/job-7.log",
        "worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status >> /dev/null",
    ] {
        assert_rule(
            &bash(command, Some(json!(5000)), Some(json!(true))),
            HYGIENE_RULES[1].rule,
        );
    }
    assert_rule(
        &bash(
            "setsid worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status >> logs/job-7.log",
            Some(json!(5000)),
            None,
        ),
        HYGIENE_RULES[1].rule,
    );
    let complete = bash(
        "setsid worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status >> logs/job-7.log",
        Some(json!(5000)),
        Some(json!(true)),
    );
    assert_eq!(classify(&complete), FastLane::ToModel);
}

/// ´test:crate:git-clean-dry-runs-are-not-destructive´
#[test]
fn git_clean_dry_runs_are_not_destructive() {
    for command in ["git clean -n", "git clean -n -d", "git clean --dry-run"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
    for command in [
        "git clean -f",
        "git clean -nd",
        "git clean -rn",
        "git clean -fn",
    ] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
}

/// ´test:crate:table-lookups-retain-declared-name-order´
#[test]
fn table_lookups_retain_declared_name_order() {
    assert_eq!(HYGIENE_RULES.len(), 8);
    assert_eq!(READ_ONLY_TABLE.len(), 8);
    for entry in READ_ONLY_TABLE {
        assert_eq!(
            matching_read_only_entry(&match entry.entry {
                "native-read" => decoded("Read", json!({ "file_path": "README.md" })),
                "native-glob" => decoded("Glob", json!({ "pattern": "*.rs" })),
                "native-grep" => decoded("Grep", json!({ "pattern": "needle" })),
                "native-web-search" => decoded("WebSearch", json!({ "query": "needle" })),
                "native-get-web-fetch" =>
                    decoded("WebFetch", json!({ "url": "https://example.invalid/" }),),
                "bash-filesystem-observation" => bash("pwd", None, None),
                "bash-source-observation" => bash("rg needle", None, None),
                "bash-repository-observation" => bash("git status", None, None),
                unexpected => panic!("unexpected table row: {unexpected}"),
            })
            .map(|matched| matched.entry),
            Some(entry.entry)
        );
    }
}

/// ´test:crate:hygiene-rule-identities-and-order-are-literal-pinned´
#[test]
fn hygiene_rule_identities_and_order_are_literal_pinned() {
    let declared = [
        (HygieneRuleId::RemoteTimeout, "remote-whole-request-timeout"),
        (
            HygieneRuleId::BackgroundContract,
            "background-observation-contract",
        ),
        (HygieneRuleId::ExecutionTiming, "execution-boundary-timing"),
        (HygieneRuleId::OneObjective, "one-mutating-objective"),
        (HygieneRuleId::PipelineStatus, "pipeline-producer-status"),
        (
            HygieneRuleId::DestructiveOperands,
            "bounded-destructive-operands",
        ),
        (
            HygieneRuleId::RemotePrivilege,
            "remote-privilege-noninteractive-alias",
        ),
        (
            HygieneRuleId::ParseableSyntax,
            "parseable-executable-syntax",
        ),
    ];
    assert_eq!(declared.len(), HYGIENE_RULES.len());
    for ((id, expected), rule) in declared.into_iter().zip(HYGIENE_RULES) {
        assert_eq!(hygiene_rule(id).rule, expected);
        assert_eq!(rule.rule, expected);
    }
}

/// ´test:crate:hygiene-table-length-is-counted-over-the-rule-enum´
#[test]
fn hygiene_table_length_is_counted_over_the_rule_enum() {
    let mut walked = Vec::new();
    let mut current = Some(HygieneRuleId::FIRST);
    while let Some(id) = current {
        walked.push(id);
        current = id.successor();
    }
    assert_eq!(walked.len(), HYGIENE_RULE_COUNT);
    assert_eq!(walked.len(), HYGIENE_RULES.len());
    for (walked, exported) in walked.iter().zip(HYGIENE_RULES) {
        assert_eq!(hygiene_rule(*walked).rule, exported.rule);
    }
}

/// ´test:crate:dollar-forms-and-sensitive-basenames-are-uniformly-conservative´
#[test]
fn dollar_forms_and_sensitive_basenames_are_uniformly_conservative() {
    for command in ["rm -rf $TARGET", "rm -rf ${TARGET}"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
    for path in [
        "docs/client_secret.txt",
        "docs/app.env.local",
        "docs/id_rsa.pub",
        "docs/id_ed25519.pub",
        "docs/release_key.txt",
        "docs/access_token.txt",
        "docs/account-password.txt",
    ] {
        assert!(matching_read_only_entry(&decoded("Read", json!({ "file_path": path }))).is_none());
    }
    assert_eq!(
        matching_read_only_entry(&decoded("Read", json!({ "file_path": "docs/guide.md" })))
            .map(|entry| entry.entry),
        Some("native-read")
    );
}

/// ´test:crate:sensitive-basename-matching-observes-token-boundaries´
#[test]
fn sensitive_basename_matching_observes_token_boundaries() {
    for path in [
        "src/tokenizer.rs",
        "src/hot_keys.rs",
        "docs/.environment",
        "docs/client_secret_backup",
    ] {
        assert_eq!(
            matching_read_only_entry(&decoded("Read", json!({ "file_path": path })))
                .map(|entry| entry.entry),
            Some("native-read")
        );
    }
    for path in [
        "docs/token.txt",
        "docs/access-token.txt",
        "docs/app.env.local",
        "docs/.env",
        "keys/id_rsa.pub",
        "config/secrets",
        "config/api_keys.json",
        "config/token_file",
    ] {
        assert!(matching_read_only_entry(&decoded("Read", json!({ "file_path": path }))).is_none());
    }
}

/// ´test:crate:unit-test-result-evidence-has-a-unit-suite-marker´
#[test]
fn unit_test_result_evidence_has_a_unit_suite_marker() {
    assert!(module_path!().ends_with("tests"));
    assert_eq!(HYGIENE_RULES.len(), READ_ONLY_TABLE.len());
}

/// ´test:crate:model-runner-and-process-launch-are-absent-from-bite-one´
#[test]
fn model_runner_and_process_launch_are_absent_from_bite_one() {
    let command_marker = concat!("Command", "::");
    let include_marker = concat!("include", "_str");
    const { assert!(!HAS_MODEL_RUN_PATH) };
    let library = include_str!("../lib.rs");
    let library_body = library
        .strip_prefix("#![doc = include_str!(\"../README.md\")]\n")
        .expect("library starts with its permitted crate-doc inclusion");
    let forbidden = [
        concat!("std", "::fs"),
        concat!("std", "::net"),
        concat!("std", "::env"),
        concat!("std", "::process"),
        concat!("core", "::fs"),
        concat!("core", "::net"),
        concat!("core", "::env"),
        concat!("core", "::process"),
        command_marker,
        concat!("un", "safe"),
        concat!("System", "Time"),
        concat!("Inst", "ant"),
        include_marker,
    ];
    for (name, source) in [
        ("lib.rs", library_body),
        ("request.rs", include_str!("../request.rs")),
        ("command_checks.rs", include_str!("../command_checks.rs")),
        ("proc.rs", include_str!("../proc.rs")),
        ("tests/mod.rs", include_str!("mod.rs")),
    ] {
        for marker in forbidden {
            if name == "tests/mod.rs" && marker == include_marker {
                continue;
            }
            assert!(
                !forbidden_marker_present(source, marker),
                "forbidden marker in {name}: {marker}"
            );
        }
    }
}

/// ´test:crate:one-proc-stat-reader-serves-every-caller´
#[test]
fn one_proc_stat_reader_serves_every_caller() {
    let awkward = b"4242 (comm ) with (spaces)) Z 77 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1200 0\n";
    assert_eq!(crate::proc::state(awkward), Some(b'Z'));
    assert_eq!(crate::proc::start_time(awkward), Some(1200));
    let both = crate::proc::parent_and_start_time(awkward).expect("both fields parse");
    assert_eq!(both.parent_pid, 77);
    assert_eq!(both.start_time, 1200);

    for short in [
        b"4242 (comm) R 77 0".as_slice(),
        b"4242 (comm)".as_slice(),
        b"".as_slice(),
    ] {
        assert_eq!(crate::proc::start_time(short), None, "short {short:?}");
        assert_eq!(
            crate::proc::parent_and_start_time(short),
            None,
            "short {short:?}"
        );
    }
    assert_eq!(crate::proc::state(b"4242 (comm) R 77 0"), Some(b'R'));
    assert_eq!(crate::proc::state(b"4242 (comm)"), None);
}

fn forbidden_marker_present(source: &str, marker: &str) -> bool {
    if marker != concat!("Command", "::") {
        return source.contains(marker);
    }
    source.match_indices(marker).any(|(index, _)| {
        source[..index]
            .chars()
            .next_back()
            .is_none_or(|previous| !previous.is_ascii_alphanumeric() && previous != '_')
    })
}

/// ´test:crate:process-guard-observes-token-boundaries´
#[test]
fn process_guard_observes_token_boundaries() {
    assert!(forbidden_marker_present(
        concat!("Command", "::new(program)"),
        concat!("Command", "::")
    ));
    assert!(!forbidden_marker_present(
        "SimpleCommand::default()",
        concat!("Command", "::")
    ));
    assert!(forbidden_marker_present(
        concat!("core", "::process::abort()"),
        concat!("core", "::process")
    ));
}
mod hook;
mod journal;
mod review;
mod rubric_model;
