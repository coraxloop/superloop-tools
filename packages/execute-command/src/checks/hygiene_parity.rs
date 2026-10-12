//! Inputs and caller outcomes copied from the permission hook unit fixtures
//! at 074c78c (read claims, eight hygiene twins and shell grammar regressions).
//! The local adapter asserts the complete common verdict for each caller denial;
//! caller `ToModel` stays a miss. No caller code is linked or included.

#[path = "../../tests/support/mod.rs"]
mod support;

use super::hygiene::HYGIENE_RULES;
use crate::checks::{self, READ_ONLY_TABLE, ReadOnlyEntry};
use crate::request::{HygieneObservation, Request};
use serde_json::{Value, json};

/// Pin the crate table to the copied caller outcomes, including their order.
///
/// # Panics
/// Panics only if a rule name, defect, correction or table order differs from the caller copy.
/// ´test:unit:hygiene-table-matches-copied-caller-outcomes´
#[test]
fn hygiene_table_matches_copied_caller_outcomes() {
    let expected = [
        (
            "remote-whole-request-timeout",
            "remote execution or transfer has no finite positive whole-request timeout",
            "set a finite positive Bash timeout or wrap the complete request with leading timeout N",
        ),
        (
            "background-observation-contract",
            "background execution lacks a complete bounded observation contract",
            "declare background execution with a finite startup timeout, stable job identity, append-only log, completion marker, and supervised status command",
        ),
        (
            "execution-boundary-timing",
            "a build, test, linter, installation, image build, or long gate is not timed at its execution boundary",
            "wrap the gate process itself with time so elapsed wall time and child status are emitted",
        ),
        (
            "one-mutating-objective",
            "one mutating batch contains multiple operational objectives or failure domains",
            "split independent mutations, publication, configuration, and verification into separate requests",
        ),
        (
            "pipeline-producer-status",
            "a pipeline after a mutation or gate can hide the producer's failure status",
            "enable pipeline failure propagation and preserve the producer status explicitly",
        ),
        (
            "bounded-destructive-operands",
            "a destructive operand is unresolved, implicit, traversing, wildcarded, substituted, empty, or broadly rooted",
            "name and validate one explicit bounded target before submitting the destructive command",
        ),
        (
            "remote-privilege-noninteractive-alias",
            "a remote privileged command can prompt or addresses an endpoint instead of a configured alias",
            "use a configured alias with non-interactive SSH host authentication and non-interactive privilege flags",
        ),
        (
            "parseable-executable-syntax",
            "the command is plainly malformed shell or contains an unevaluated prose placeholder",
            "submit complete executable shell where every trailing connector has a consumer and quotes, substitutions, subshells, and heredocs are closed",
        ),
    ];
    let actual: Vec<_> = HYGIENE_RULES
        .iter()
        .map(|rule| (rule.rule, rule.defect, rule.correction))
        .collect();
    assert_eq!(actual, expected);
}

#[derive(Debug, PartialEq, Eq)]
enum FastLane {
    ToModel,
    AgentError {
        rule: &'static str,
        correction: &'static str,
    },
}

struct Fixture {
    request: Request,
    tool: String,
    fields: Value,
}

impl Fixture {
    fn observation(&self) -> HygieneObservation<'_> {
        if self.tool == "Bash" {
            HygieneObservation::Shell {
                timeout_ms: self.fields["timeout"].as_u64(),
                declared_background: self.fields["run_in_background"].as_bool(),
            }
        } else if self.tool == "Monitor" && self.fields["command"].is_string() {
            HygieneObservation::Shell {
                timeout_ms: self.fields["timeout_ms"].as_u64(),
                declared_background: self.fields["persistent"].as_bool(),
            }
        } else {
            HygieneObservation::Native {
                tool: &self.tool,
                fields: self.fields.as_object().unwrap(),
            }
        }
    }
}

fn decoded(tool: &str, fields: Value) -> Fixture {
    Fixture {
        request: support::request(
            fields["command"].as_str().unwrap_or("native observation"),
            "/project",
        ),
        tool: tool.to_owned(),
        fields,
    }
}

fn bash(command: &str, timeout: Option<Value>, background: Option<Value>) -> Fixture {
    let mut fields = json!({"command":command});
    if let Some(timeout) = timeout {
        fields["timeout"] = timeout;
    }
    if let Some(background) = background {
        fields["run_in_background"] = background;
    }
    decoded("Bash", fields)
}

fn bash_in_cwd(command: &str, cwd: &str) -> Fixture {
    let mut fixture = bash(command, None, None);
    fixture.request = support::request(command, cwd);
    fixture
}

fn classify(fixture: &Fixture) -> FastLane {
    let Some(verdict) =
        checks::hygiene(&fixture.request, &fixture.observation(), "estate").unwrap()
    else {
        return FastLane::ToModel;
    };
    verdict.validate().unwrap();
    let actual = serde_json::to_value(&verdict).unwrap();
    let rule = HYGIENE_RULES
        .iter()
        .find(|rule| actual["correction"]["rule"] == rule.rule)
        .unwrap();
    assert_eq!(
        actual,
        json!({
            "binding":{"request_id":"request-1","context_digest":"context-1"},
            "judgement":"refuse", "tier":"deterministic-checks", "scope":"estate",
            "reason":rule.defect, "evidence":[], "status":"valid",
            "correction":{"rule":rule.rule,"changes":rule.correction,
                "revalidation":"resubmit the corrected request through the same checks before any effect"},
            "escalation":null
        })
    );
    FastLane::AgentError {
        rule: rule.rule,
        correction: rule.correction,
    }
}

fn assert_rule(fixture: &Fixture, expected: &str) {
    match classify(fixture) {
        FastLane::AgentError { rule, .. } => assert_eq!(rule, expected),
        verdict @ FastLane::ToModel => panic!("expected {expected}, received {verdict:?}"),
    }
}

fn matching_read_only_entry(fixture: &Fixture) -> Option<&'static ReadOnlyEntry> {
    checks::matching_read_only_entry(&fixture.request, &fixture.observation())
}

/// ´test:unit:monitor-command-and-observation-fields´
#[test]
fn monitor_command_and_observation_fields() {
    // Copied from the permission hook integration fixtures monitor_shell_routing_body
    // and monitor_schema_routing_body; harness field decoding stays in this adapter.
    assert_rule(
        &decoded(
            "Monitor",
            json!({"command":"cargo test", "description":"gate output", "timeout_ms":300_000, "persistent":false}),
        ),
        HYGIENE_RULES[2].rule,
    );
    assert_eq!(
        classify(&decoded(
            "Monitor",
            json!({"command":"ssh build-host 'time make check'", "description":"remote gate", "timeout_ms":3_600_000, "persistent":false})
        )),
        FastLane::ToModel
    );
    assert_rule(
        &decoded(
            "Monitor",
            json!({"command":"ssh build-host 'time make check'", "description":"remote gate", "persistent":false}),
        ),
        HYGIENE_RULES[0].rule,
    );
    assert_rule(
        &decoded(
            "Monitor",
            json!({"command":"tail -f build.log", "description":"build log", "timeout_ms":300_000, "persistent":true}),
        ),
        HYGIENE_RULES[1].rule,
    );
}

/// ´test:unit:every-read-only-claim-has-a-positive-and-negative-twin´
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

/// ´test:unit:every-read-only-claim-is-disabled-and-has-an-exact-grammar´
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

/// ´test:unit:remote-timeout-check-has-positive-and-negative-twins´
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

/// ´test:unit:remote-timeout-credit-is-confined-to-its-pipeline-stage´
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

/// ´test:unit:background-contract-check-has-positive-and-negative-twins´
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

/// ´test:unit:execution-timing-check-has-positive-and-negative-twins´
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

/// ´test:unit:one-objective-check-has-positive-and-negative-twins´
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

/// ´test:unit:pipeline-status-check-has-positive-and-negative-twins´
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

/// ´test:unit:destructive-operand-check-rejects-every-unbounded-shape´
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

/// ´test:unit:remote-privilege-check-has-positive-and-negative-twins´
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

/// ´test:unit:parseable-syntax-check-has-positive-and-negative-twins´
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

/// ´test:unit:valid-heredoc-is-conservatively-model-routed´
#[test]
fn valid_heredoc_is_conservatively_model_routed() {
    let request = bash("cat <<EOF\nbody\nEOF", None, None);
    assert_eq!(classify(&request), FastLane::ToModel);
}

/// ´test:unit:arithmetic-commands-are-ambiguous-not-executable-heads´
#[test]
fn arithmetic_commands_are_ambiguous_not_executable_heads() {
    for command in ["((count += 1))", "((rm))"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:unit:arithmetic-commands-do-not-hide-later-destructive-operands´
#[test]
fn arithmetic_commands_do_not_hide_later_destructive_operands() {
    assert_rule(
        &bash("foo && ((i++)) && rm -rf /", None, None),
        HYGIENE_RULES[5].rule,
    );
}

/// ´test:unit:arithmetic-masking-still-sees-substituted-destructive-commands´
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
/// ´test:unit:quoted-parenthesis-in-arithmetic-keeps-the-rest-of-the-command´
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

/// ´test:unit:arithmetic-substitutions-add-no-allow-and-stay-opaque´
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

/// ´test:unit:trailing-command-terminators-are-ordinary´
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

/// ´test:unit:placeholder-detection-does-not-reserve-program-names´
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

/// ´test:unit:function-definitions-and-array-assignments-are-ambiguous´
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

/// ´test:unit:unmodelled-redirection-constructs-preserve-destructive-prefixes´
#[test]
fn unmodelled_redirection_constructs_preserve_destructive_prefixes() {
    for command in ["rm -rf $HOME <(true)", "rm -rf $HOME <<EOF\nbody\nEOF"] {
        assert_rule(&bash(command, None, None), HYGIENE_RULES[5].rule);
    }
    for command in ["cat <(true)", "cat <<EOF\nbody\nEOF"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:unit:ambiguous-prefixes-receive-the-full-hygiene-set´
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

/// ´test:unit:trailing-pipelines-report-incomplete-syntax´
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
            verdict @ FastLane::ToModel => {
                panic!("expected incomplete-syntax denial, received {verdict:?}")
            }
        }
    }
}

/// ´test:unit:unmodelled-heads-route-ambiguously-after-destructive-checks´
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

/// ´test:unit:nested-shell-and-xargs-payloads-receive-hygiene-checks´
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

/// ´test:unit:bash-rcfile-options-do-not-hide-command-payloads´
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

/// ´test:unit:nested-wrapper-timing-and-redirect-share-the-payload-objective´
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

/// ´test:unit:redirect-descriptors-are-not-destructive-operands´
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

/// ´test:unit:fully-modelled-subshells-receive-all-hygiene-checks´
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

/// ´test:unit:redirect-on-closed-subshell-remains-in-the-shell-shape´
#[test]
fn redirect_on_closed_subshell_remains_in_the_shell_shape() {
    let complete = bash(
        "(setsid worker --job-id job-7 --completion-marker state/job-7.done --status-cmd worker-status) >> logs/job-7.log",
        Some(json!(5000)),
        Some(json!(true)),
    );
    assert_eq!(classify(&complete), FastLane::ToModel);
}

/// ´test:unit:angle-placeholders-win-over-redirect-tokenization´
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

/// ´test:unit:compound-read-commands-do-not-enter-the-simple-read-lane´
#[test]
fn compound_read_commands_do_not_enter_the_simple_read_lane() {
    let request = bash("pwd && git status --short", None, None);
    assert!(matching_read_only_entry(&request).is_none());
    assert_eq!(classify(&request), FastLane::ToModel);
}

/// ´test:unit:timing-a-pipeline-consumer-does-not-time-the-gate´
#[test]
fn timing_a_pipeline_consumer_does_not_time_the_gate() {
    let request = bash("cargo test -p widget | time tail -1", None, None);
    assert_rule(&request, HYGIENE_RULES[2].rule);
}

/// ´test:unit:command-arguments-are-not-mistaken-for-executables´
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

/// ´test:unit:command-builtin-query-is-informational´
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

/// ´test:unit:type-which-and-hash-remain-ordinary-model-queries´
#[test]
fn type_which_and_hash_remain_ordinary_model_queries() {
    for command in ["type rm", "which rm", "hash rm"] {
        assert_eq!(classify(&bash(command, None, None)), FastLane::ToModel);
    }
}

/// ´test:unit:nested-remote-shell-receives-parse-and-timing-checks´
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

/// ´test:unit:descriptor-and-null-redirects-are-nonmutating´
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

/// ´test:unit:subshell-followed-by-connector-receives-hygiene-checks´
#[test]
fn subshell_followed_by_connector_receives_hygiene_checks() {
    let request = bash("(cd packages && time cargo test) | tail -1", None, None);
    assert_rule(&request, HYGIENE_RULES[4].rule);
}

/// ´test:unit:closed-subshell-redirects-can-precede-connectors´
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

/// ´test:unit:combined-stream-pipe-is-a-pipeline´
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

/// ´test:unit:shell-keywords-are-ambiguous-but-destructive-operands-still-run´
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

/// ´test:unit:broad-root-calculus-covers-depth-home-and-project-root´
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

/// ´test:unit:canonical-remote-privileged-shape-needs-no-host-key-option´
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

/// ´test:unit:quoted-placeholder-literals-are-not-pseudocode´
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

/// ´test:unit:keyword-recovery-checks-command-heads-not-arguments´
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

/// ´test:unit:git-mutation-detection-uses-the-subcommand-position´
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

/// ´test:unit:git-read-grammar-rejects-writing-relocation-and-outside-operands´
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

/// ´test:unit:pipeline-status-preservation-is-position-sensitive´
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

/// ´test:unit:expanded-gate-roster-requires-execution-boundary-timing´
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

/// ´test:unit:promoted-gates-contribute-one-objective-per-simple-command´
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

/// ´test:unit:gate-information-shapes-do-not-require-timing´
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

/// ´test:unit:npm-run-help-is-informational-but-scripts-remain-gates´
#[test]
fn npm_run_help_is_informational_but_scripts_remain_gates() {
    assert_eq!(
        classify(&bash("npm run --help", None, None)),
        FastLane::ToModel
    );
    assert_rule(
        &bash("npm run build", None, None),
        "execution-boundary-timing",
    );
}

/// ´test:unit:scheduling-wrappers-never-hide-gates´
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

/// ´test:unit:background-contract-needs-explicit-option-value-and-sees-wrappers´
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

/// ´test:unit:background-contract-requires-both-observers-and-a-real-log´
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

/// ´test:unit:git-clean-dry-runs-are-not-destructive´
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

/// ´test:unit:table-lookups-retain-declared-name-order´
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

/// ´test:unit:hygiene-table-declares-the-counted-length-and-drops-the-vestigial-layout´
#[test]
fn hygiene_table_declares_the_counted_length_and_drops_the_vestigial_layout() {
    let source = include_str!("hygiene.rs");
    assert!(source.contains("pub const HYGIENE_RULES: &[HygieneRule; HYGIENE_RULE_COUNT]"));
    assert!(!source.contains(concat!("#[repr(", "usize)]")));
}
