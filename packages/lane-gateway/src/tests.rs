//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`validates_all_three_request_operations`] |  | — |
//! | [`refuses_an_unknown_request_field`] |  | — |
//! | [`refuses_an_unsupported_request_schema`] |  | — |
//! | [`refuses_a_sequence_replay`] |  | — |
//! | [`refuses_a_sequence_regression`] |  | — |
//! | [`refuses_an_unknown_roster_command`] |  | — |
//! | [`refuses_run_argv_shape_tampering`] |  | — |
//! | [`refuses_a_proposal_without_a_reason`] |  | — |
//! | [`refuses_an_unregistered_lane_with_an_audit_record`] |  | — |
//! | [`appends_an_identical_audit_event_as_a_new_record`] |  | — |
//! | [`rejects_a_duplicate_registration_lane_name`] |  | — |
//! | [`rejects_relative_registration_paths`] |  | — |
//! | [`refuses_registration_naming_an_unreachable_local_mirror_path`] |  | — |
//! | [`accepts_registration_naming_a_reachable_local_mirror_path`] |  | — |
//! | [`refuses_registration_naming_an_unreachable_remote_mirror_spec`] |  | — |
//! | [`accepts_registration_naming_a_reachable_remote_mirror_spec`] |  | — |
//! | [`status_reports_stray_toml_files_outside_the_registrations_directory`] |  | — |
//! | [`rejects_an_empty_command_roster`] |  | — |
//! | [`rejects_an_unknown_registration_field`] |  | — |
//! | [`rejects_null_operation_fields`] |  | — |
//! | [`derives_budget_consumption_from_result_records`] |  | — |
//! | [`applies_the_ratified_registration_defaults`] |  | — |
//! | [`snapshot_captures_tracked_and_untracked_without_mutating_lane_git_state`] |  | — |
//! | [`snapshot_excludes_lane_transport_before_push_and_run`] |  | — |
//! | [`push_installs_exact_snapshot_at_lane_mirror_ref`] |  | — |
//! | [`push_admits_whole_worktree_and_annotates_out_of_scope_paths`] |  | — |
//! | [`push_resolves_new_package_first_introduced_by_the_snapshot`] |  | — |
//! | [`refuses_push_naming_absent_package_with_near_miss_candidates`] |  | — |
//! | [`run_executes_fixed_roster_argv_in_mirror_checkout`] |  | — |
//! | [`run_cap_exhaustion_directs_worker_to_final_verify`] |  | — |
//! | [`refuses_run_during_registered_cooldown`] |  | — |
//! | [`timeout_kills_runner_and_records_partial_output`] |  | — |
//! | [`runner_transport_exit_is_refused_as_a_lost_connection`] |  | — |
//! | [`runner_exit_other_than_the_transport_code_is_the_command_status`] |  | — |
//! | [`unspawnable_runner_is_still_a_runner_failure`] |  | — |
//! | [`failed_push_invalidates_older_mirror_snapshot`] |  | — |
//! | [`serve_loop_pushes_writes_result_and_appends_audit`] |  | — |
//! | [`oversized_run_output_is_published_in_order`] |  | — |
//! | [`serve_loop_keeps_one_run_in_flight_per_lane`] |  | — |
//! | [`refuses_run_with_no_snapshot`] |  | — |
//! | [`proposal_intake_parks_pending_and_audits`] |  | — |
//! | [`proposals_lists_pending_and_deny_delivers_reason`] |  | — |
//! | [`run_audit_records_configured_target_root_derivation`] |  | — |
//! | [`approve_executes_exact_parked_argv`] |  | — |
//! | [`promotion_extends_roster_with_auditable_exact_argv`] |  | — |
//! | [`proposal_timeout_parks_without_terminal_resolution`] |  | — |
//! | [`parked_proposal_survives_gateway_restart_and_is_approvable`] |  | — |
//! | [`proposal_queue_lists_pending_and_parked`] |  | — |
//! | [`restart_repairs_park_projection_without_replay_refusal`] |  | — |
//! | [`explicit_abandon_expires_open_proposal`] |  | — |
//! | [`deregister_refuses_open_proposals`] |  | — |
//! | [`timed_out_verdict_state_refuses_as_unknown_decision`] |  | — |
//! | [`proposal_result_verdicts_are_distinct`] |  | — |
//! | [`schema_two_proposal_result_json_is_exact`] |  | — |
//! | [`push_result_projection_stamps_schema_two`] |  | — |
//! | [`run_result_projection_stamps_schema_two`] |  | — |
//! | [`proposal_result_projections_stamp_schema_two`] |  | — |
//! | [`denied_verdict_is_not_retryable_timeout`] |  | — |
//! | [`expired_verdict_allows_fresh_sequence_when_lane_remains_open`] |  | — |
//! | [`parked_verdict_keeps_original_sequence_open`] |  | — |
//! | [`refusal_with_tier_refuses_in_audit`] |  | — |
//! | [`unserved_refusal_rule_refuses_in_audit`] |  | — |
//! | [`nested_refusal_schema_refuses_in_audit`] |  | — |
//! | [`result_without_verdict_refuses_in_audit`] |  | — |
//! | [`result_without_stdout_refuses_in_audit`] |  | — |
//! | [`result_without_stderr_refuses_in_audit`] |  | — |
//! | [`gateway_actor_refuses_in_audit`] |  | — |
//! | [`stored_verdict_without_wall_refuses`] |  | — |
//! | [`schema_one_audit_line_refuses_with_file_line_and_invariant`] |  | — |
//! | [`schema_one_proposal_body_remains_readable`] |  | — |
//! | [`withdraw_repairs_worker_result_projection_and_serve_continues`] |  | — |
//! | [`startup_reconcile_repairs_schema_one_result_projection`] |  | — |
//! | [`nested_refusal_schema_repairs_worker_projection`] |  | — |
//! | [`registration_change_without_actor_refuses`] |  | — |
//! | [`verdict_without_actor_refuses`] |  | — |
//! | [`corrupt_audit_line_writes_enriched_crash_report`] |  | — |
//! | [`write_result_rejects_wrong_in_memory_schema`] |  | — |
//! | [`per_proposal_status_survives_later_push_and_run_results`] |  | — |
//! | [`unknown_proposal_verdicts_refuse_cleanly`] |  | — |
//! | [`serve_loop_writes_malformed_request_refusal`] |  | — |
//! | [`serve_continues_after_worker_file_faults`] |  | — |
//! | [`worker_file_failure_keeps_the_failing_operation`] |  | — |
//! | [`oversized_worker_request_names_defect`] |  | — |
//! | [`unfinished_request_is_served_without_a_refusal`] |  | — |
//! | [`unfinished_request_is_refused_once_after_the_repoll_bound`] |  | — |
//! | [`partial_json_prefix_waits_like_an_empty_request_file`] |  | — |
//! | [`startup_seeding_defers_an_unfinished_request_file`] |  | — |
//! | [`serve_loop_shuts_down_promptly`] |  | — |
//! | [`acquisition_reaps_dead_pid_lock_and_retries_once`] |  | — |
//! | [`alive_pid_lock_refusal_names_holder_and_path`] |  | — |
//! | [`acquisition_refuses_malformed_lock_with_diagnostic`] |  | — |
//! | [`serve_startup_reaps_dead_pid_lock`] |  | — |
//! | [`serve_startup_reaps_malformed_lock`] |  | — |
//! | [`serve_startup_reports_stray_toml_files`] |  | — |
//! | [`serve_writes_pid_and_last_activity_heartbeat`] |  | — |
//! | [`heartbeat_stays_fresh_during_long_runner`] |  | — |
//! | [`shutdown_flag_waits_for_the_cycle_executing_a_runner`] |  | — |
//! | [`clean_shutdown_marks_heartbeat_stopped`] |  | — |
//! | [`heartbeat_liveness_judges_a_dead_pid_and_a_stale_beat`] |  | — |
//! | [`serve_error_writes_crash_report`] |  | — |
//! | [`serve_panic_writes_crash_report`] |  | — |
//! | [`heartbeat_write_failure_is_fatal`] |  | — |
//! | [`restart_consumes_request_written_while_serve_was_down`] |  | — |
//! | [`approve_watchdog_types_command_exits`] |  | — |
//! | [`approve_watchdog_reconciles_interrupted_approval_once`] |  | — |
//! | [`approve_watchdog_bounds_output_collection`] |  | — |
//! | [`withdraw_proposal_closes_only_the_original_sequence`] |  | — |
//! | [`withdraw_proposal_refuses_a_different_lane`] |  | — |
//! | [`withdraw_proposal_rejects_invalid_shapes`] |  | — |
//! | [`withdraw_proposal_through_serve_request_channel`] |  | — |
//! | [`runner_group_timeout_forwards_term_to_descendants`] |  | — |
//! | [`runner_group_timeout_escalates_after_grace`] |  | — |
//! | [`runner_group_restart_reaps_abandoned_approval`] |  | — |
//! | [`runner_group_restart_reaps_roster_run`] |  | — |
//! | [`runner_group_recovery_requires_the_recorded_leader`] |  | — |
//! | [`runner_group_recovery_requires_the_recording_boot`] |  | — |
//! | [`runner_group_recovery_discards_a_record_without_a_boot`] |  | — |
//! | [`process_group_child_rejects_zero_selected_tests`] |  | — |
//! | [`withdrawal_result_measures_elapsed_wall`] |  | — |
//! | [`withdrawal_recovery_measures_elapsed_wall`] |  | — |
//! | [`approve_margin_zero_refuses_serve`] |  | — |
//! | [`approve_margin_zero_refuses_request`] |  | — |
//! | [`approve_margin_zero_refuses_approval`] |  | — |
//! | [`approve_margin_environment_requires_positive_value`] |  | — |
//! | [`gateway_common_migration_preserves_pending_and_parked_projections`] |  | — |
//! | [`gateway_common_decision_executes_once_across_claim_and_restart`] |  | — |
//! | [`gateway_check_and_status_leave_missing_and_existing_state_unchanged`] |  | — |
//! | [`gateway_common_refusals_and_withdrawal_publish_one_terminal_result`] |  | — |

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::types::ResultProjectionReplacementReason;
use crate::{
    AuditActor, AuditEvent, BudgetPolicy, CommandSpec, Gateway, GatewayError, Operation,
    OutputChunk, OutputStream, ParkedProposal, ProposalExpiryReason, ProposalPark, ProposalState,
    ProposalVerdict, RefusalRule, Registration, RegistrationRule, RequestValidationResult,
    ResultVerdict, ServeActivity, ServeConfig, ServeCrashReport, ServeDeathReason,
    ServeFailureKind, ServeHeartbeat, ServeLiveness, ServeProcessState, ServeStopReason,
    ValidationOutcome, VerdictDecision, heartbeat_liveness,
};

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lane-gateway-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory is created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

fn configured_gateway(state: impl Into<PathBuf>) -> Gateway {
    use std::os::unix::fs::PermissionsExt as _;
    let state = state.into();
    let base = state
        .parent()
        .expect("gateway parent")
        .join("request-owner");
    let registry = base.join("registry");
    let journal = base.join("journal");
    for path in [&base, &registry, &journal] {
        fs::create_dir_all(path).expect("private request fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
    }
    let row = registry.join("fixture.env");
    fs::write(
        &row,
        format!(
            "LOOP_NAME=fixture\nLOOP_SID=fixture\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            base.display(),
            journal.display()
        ),
    )
    .expect("request registry");
    fs::set_permissions(&row, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let helper = std::env::var_os("SUPERLOOP_TEST_REQUESTS_HELPER")
        .map(PathBuf::from)
        .expect("SUPERLOOP_TEST_REQUESTS_HELPER names the built helper");
    Gateway::new(state).with_request_channel(
        crate::RequestChannel::new(helper, registry, "fixture".into()).expect("request binding"),
    )
}

struct Fixture {
    _directory: TestDirectory,
    gateway: Gateway,
    registration: Registration,
}

impl Fixture {
    fn registered() -> Self {
        let directory = TestDirectory::new();
        let state = directory.path().join("state");
        let worktree = directory.path().join("worktree");
        fs::create_dir_all(&worktree).expect("worktree is created");
        // A registration must name a reachable mirror; a plausible-looking
        // but nonexistent placeholder path is refused as of entry 27b, so
        // every non-Git fixture gets a real (unused) bare repository too.
        let mirror = directory.path().join("mirror.git");
        let mirror_text = mirror.to_str().expect("test mirror path is UTF-8");
        git(
            directory.path(),
            &["init", "--bare", "--quiet", mirror_text],
        );
        let gateway = configured_gateway(state);
        let mut registration = registration(&worktree);
        registration.mirror_remote = mirror_text.to_owned();
        gateway
            .register(&registration)
            .expect("registration succeeds");
        Self {
            _directory: directory,
            gateway,
            registration,
        }
    }
}

fn registration(worktree: &Path) -> Registration {
    let mut commands = BTreeMap::new();
    for (name, argv) in [
        ("fmt-check", vec!["cargo", "fmt", "--check"]),
        ("fmt-diff", vec!["run-report.sh", "fmt-diff"]),
        ("clippy", vec!["cargo", "clippy"]),
        ("test", vec!["cargo", "test", "--package", "lane-gateway"]),
        ("corpus-names", vec!["run-report.sh", "corpus-names"]),
        ("clippy-fix-diff", vec!["run-report.sh", "clippy-fix-diff"]),
    ] {
        commands.insert(
            name.to_owned(),
            CommandSpec {
                argv: argv.into_iter().map(str::to_owned).collect(),
                wall_budget_seconds: 60,
            },
        );
    }

    Registration {
        schema: 1,
        lane: "lane-031".to_owned(),
        worktree: worktree.to_path_buf(),
        packages: vec!["lane-gateway".to_owned()],
        base_commit: "0".repeat(40),
        mirror_remote: "/srv/lanes/lane-031".to_owned(),
        mirror_checkout: worktree.join("mirror-checkout"),
        commands,
        budgets: BudgetPolicy::default(),
        proposal_timeout_seconds: 600,
    }
}

struct GitFixture {
    directory: TestDirectory,
    gateway: Gateway,
    registration: Registration,
    mirror: PathBuf,
    checkout: PathBuf,
}

impl GitFixture {
    fn registered() -> Self {
        let directory = TestDirectory::new();
        let worktree = directory.path().join("worktree");
        let mirror = directory.path().join("mirror.git");
        let checkout = directory.path().join("mirror-checkout");
        fs::create_dir(&worktree).expect("worktree is created");
        git(&worktree, &["init", "--quiet"]);

        let package = worktree.join("packages/lane-gateway");
        fs::create_dir_all(&package).expect("package directory is created");
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"lane-gateway\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("package manifest is written");
        fs::write(package.join("tracked.txt"), "base\n").expect("tracked file is written");
        fs::write(worktree.join("README.md"), "base\n").expect("outside file is written");
        git(&worktree, &["add", "--all"]);
        git(
            &worktree,
            &[
                "-c",
                "user.name=lane-gateway-test",
                "-c",
                "user.email=lane-gateway-test@localhost",
                "commit",
                "--quiet",
                "-m",
                "base",
            ],
        );
        let base_commit = git_text(&worktree, &["rev-parse", "HEAD"]);
        let mirror_text = mirror.to_str().expect("test mirror path is UTF-8");
        git(
            directory.path(),
            &["init", "--bare", "--quiet", mirror_text],
        );
        let checkout_text = checkout.to_str().expect("test checkout path is UTF-8");
        git(directory.path(), &["init", "--quiet", checkout_text]);
        git(&checkout, &["remote", "add", "origin", mirror_text]);

        let gateway = configured_gateway(directory.path().join("state"));
        let mut registration = registration(&worktree);
        registration.base_commit = base_commit;
        registration.mirror_remote = mirror_text.to_owned();
        registration.mirror_checkout = checkout.clone();
        gateway
            .register(&registration)
            .expect("Git fixture registration succeeds");
        Self {
            directory,
            gateway,
            registration,
            mirror,
            checkout,
        }
    }

    fn request_path(&self) -> PathBuf {
        self.registration.worktree.join(".lane/request.json")
    }

    fn result_path(&self) -> PathBuf {
        self.registration.worktree.join(".lane/result.json")
    }

    fn configure_clippy(
        &mut self,
        argv: Vec<String>,
        wall_budget_seconds: u64,
        budgets: BudgetPolicy,
    ) {
        self.gateway
            .deregister(&self.registration.lane)
            .expect("run fixture registration is removed");
        let command = self
            .registration
            .commands
            .get_mut("clippy")
            .expect("clippy roster entry exists");
        command.argv = argv;
        command.wall_budget_seconds = wall_budget_seconds;
        self.registration.budgets = budgets;
        self.gateway
            .register(&self.registration)
            .expect("run fixture registration is restored");
    }

    fn write_package_script(&self, name: &str, source: &str) -> String {
        let relative = format!("packages/lane-gateway/{name}");
        fs::write(self.registration.worktree.join(&relative), source)
            .expect("run command script is written");
        relative
    }

    fn runner_config(&self, result_size_limit_bytes: usize) -> (ServeConfig, PathBuf) {
        let runner = self.directory.path().join("runner-stub.sh");
        let record = self.directory.path().join("runner-record.txt");
        fs::write(&runner, RUNNER_STUB).expect("runner stub is written");
        let prefix = vec![
            "/bin/sh".to_owned(),
            runner.to_string_lossy().into_owned(),
            record.to_string_lossy().into_owned(),
            self.registration.lane.clone(),
        ];
        (
            ServeConfig::for_gateway(&self.gateway)
                .with_runner_prefix(prefix)
                .with_result_size_limit_bytes(result_size_limit_bytes),
            record,
        )
    }
}

const RUNNER_STUB: &str = r#"record=$1
lane=$2
shift 2
{
    printf 'budget=%s\n' "$LANE_GATEWAY_WALL_BUDGET_SECONDS"
    printf 'commit=%s\n' "$LANE_GATEWAY_MIRROR_COMMIT"
    printf 'remote=%s\n' "$LANE_GATEWAY_MIRROR_REMOTE"
    printf 'target=%s\n' "$CARGO_TARGET_DIR"
    for argument in "$@"; do
        printf 'argument=%s\n' "$argument"
    done
} > "$record"
checkout=$1
shift
git -C "$checkout" fetch --quiet --force origin "refs/lanes/gateway/$lane" || exit 91
git -C "$checkout" reset --hard --quiet "$LANE_GATEWAY_MIRROR_COMMIT" || exit 92
cd "$checkout" || exit 93
exec "$@"
"#;

fn git(directory: &Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("LC_ALL", "C")
        .output()
        .expect("Git test subprocess starts");
    assert!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn git_text(directory: &Path, arguments: &[&str]) -> String {
    String::from_utf8(git(directory, arguments).stdout)
        .expect("Git test output is UTF-8")
        .trim()
        .to_owned()
}

/// How long a wait on a fixture's side effect runs before it is a failure.
///
/// Every wait below stands on something a serve loop does — a file it writes, a
/// heartbeat it publishes, a thread that returns once it has been asked to stop
/// — and the cycles these tests configure are milliseconds long. The deadline is
/// there to turn a loop that is stuck into one failing test instead of a hung
/// binary, and it costs nothing when the event arrives, so it is set far above
/// any cycle: a node under load stretches the arrival without changing what a
/// case asserts, and a deadline tight enough to notice that load is a deadline
/// that reports the machine rather than the code.
const FIXTURE_WAIT: Duration = Duration::from_secs(20);

// These event-driven fixtures run on shared 256-core nodes, with observed load
// above 270. Allow 120 seconds to distinguish a hang from scheduling delay;
// every wait returns as soon as its event is visible, without a minimum delay.
const LOADED_FIXTURE_WAIT: Duration = Duration::from_secs(120);

fn wait_for_result(path: &Path) -> crate::OperationResult {
    // Fixture-side-effect wait: the result document a serve cycle publishes.
    let started = Instant::now();
    loop {
        if let Ok(source) = fs::read_to_string(path)
            && let Ok(result) = serde_json::from_str(&source)
        {
            return result;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "no result document at {} after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_result_seq(path: &Path, seq: u64) -> crate::OperationResult {
    wait_for_result_seq_with_limit(path, seq, FIXTURE_WAIT)
}

fn wait_for_result_seq_with_limit(
    path: &Path,
    seq: u64,
    limit: Duration,
) -> crate::OperationResult {
    // Fixture-side-effect wait: the result document a given request answers with.
    let started = Instant::now();
    loop {
        if let Ok(source) = fs::read_to_string(path)
            && let Ok(result) = serde_json::from_str::<crate::OperationResult>(&source)
            && result.seq == Some(seq)
        {
            return result;
        }
        assert!(
            started.elapsed() < limit,
            "no result for sequence {seq} at {} after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_result_verdict(
    path: &Path,
    seq: u64,
    verdict: ResultVerdict,
) -> crate::OperationResult {
    // Fixture-side-effect wait: a request's result reaching one verdict.
    let started = Instant::now();
    loop {
        if let Ok(source) = fs::read_to_string(path)
            && let Ok(result) = serde_json::from_str::<crate::OperationResult>(&source)
            && result.seq == Some(seq)
            && result.verdict == verdict
        {
            return result;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "sequence {seq} at {} was not {verdict:?} after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_text(path: &Path, expected: &str) {
    wait_for_text_with_limit(path, expected, FIXTURE_WAIT);
}

fn wait_for_text_with_limit(path: &Path, expected: &str, limit: Duration) {
    // Fixture-side-effect wait: text a runner writes to a marker file.
    let started = Instant::now();
    loop {
        if fs::read_to_string(path).is_ok_and(|source| source.contains(expected)) {
            return;
        }
        assert!(
            started.elapsed() < limit,
            "{} never contained {expected:?} after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_json(path: &Path) {
    // Fixture-side-effect wait: a complete JSON state document published atomically.
    let started = Instant::now();
    loop {
        if let Ok(source) = fs::read_to_string(path)
            && serde_json::from_str::<serde_json::Value>(&source).is_ok()
        {
            return;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "no JSON document at {} after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// Start time from a recorded stat line, or nothing while that line is still torn.
///
/// A read landing mid-write can see a line that is past its comm field and
/// short of the twenty-second, and a truncated integer parses as a smaller
/// one, so the field counts only once the field after it proves the write
/// reached past its end.
fn recorded_start_ticks(path: &Path) -> Option<u64> {
    let stat = fs::read_to_string(path).ok()?;
    let mut fields = stat.rsplit_once(") ")?.1.split_whitespace();
    let start_ticks = fields.nth(19)?;
    fields.next()?;
    start_ticks.parse().ok()
}

/// Wait for a runner's recorded stat line to carry its start time whole.
///
/// The stub writes its ready marker from a backgrounded child and its own stat
/// line afterwards, so the marker does not say the identity is there yet: the
/// redirect creates the stat file before `cat` fills it, and a read landing
/// between the two sees a file with no fields at all. Waiting on the field
/// separator alone does not settle it either — that only says the comm field
/// has closed, while the caller goes on to take a field twenty places further
/// in, and a line torn between them clears the wait and panics in the parse.
/// The wait is therefore on the parse itself.
fn wait_for_start_ticks(path: &Path) -> u64 {
    // Fixture-side-effect wait: the stat line a runner writes, through its start time.
    let started = Instant::now();
    loop {
        if let Some(start_ticks) = recorded_start_ticks(path) {
            return start_ticks;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "{} carried no runner start time after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_heartbeat(
    gateway: &Gateway,
    predicate: impl Fn(&ServeHeartbeat) -> bool,
) -> ServeHeartbeat {
    wait_for_heartbeat_with_limit(gateway, predicate, FIXTURE_WAIT)
}

fn wait_for_heartbeat_with_limit(
    gateway: &Gateway,
    predicate: impl Fn(&ServeHeartbeat) -> bool,
    limit: Duration,
) -> ServeHeartbeat {
    let path = gateway.state_dir().join("serve-heartbeat.json");
    // Fixture-side-effect wait: a published heartbeat the case's predicate accepts.
    let started = Instant::now();
    loop {
        if let Ok(source) = fs::read_to_string(&path)
            && let Ok(heartbeat) = serde_json::from_str::<ServeHeartbeat>(&source)
            && predicate(&heartbeat)
        {
            return heartbeat;
        }
        assert!(
            started.elapsed() < limit,
            "no heartbeat at {} satisfied the case's predicate after {:?}",
            path.display(),
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn read_lane_lock(path: &Path) -> Result<Option<u32>, String> {
    match fs::read_to_string(path) {
        Ok(source) => source
            .trim()
            .parse::<u32>()
            .map(Some)
            .map_err(|error| format!("lane lock holder is not a PID: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("lane lock is not readable: {error}")),
    }
}

/// Wait for a reaped lane lock to settle at absent or held by this process.
///
/// A reap is announced on the heartbeat, and the heartbeat is published from a
/// snapshot by its own thread, so the announcement says the lock was reaped and
/// nothing about what live serving has done since. Serving re-acquires the lane
/// on every poll, and acquiring creates the lock file before writing the holder
/// into it, so a single read taken after the announcement can land on a file
/// that exists and is still empty — which is this process taking the lane, not
/// the dead holder surviving, yet reads as neither a PID nor an absent lock.
/// The window is one write wide and recurs every poll, so a case that judges
/// its first read can fail on a loaded host and pass alone. The window is
/// argued from the code and was not observed to fire: the flake recorded for
/// this case was an earlier absence assertion, since replaced. Waiting for a
/// settled holder keeps the guard exact: a dead holder that really survived
/// never settles, and the wait fails naming what it found.
fn wait_for_reaped_lane_lock(path: &Path) {
    // Fixture-side-effect wait: a reaped lane lock, absent or re-taken here.
    let started = Instant::now();
    loop {
        if let Ok(holder) = read_lane_lock(path)
            && holder.is_none_or(|pid| pid == std::process::id())
        {
            return;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "lane lock at {} was not reaped after {:?}: {:?}",
            path.display(),
            started.elapsed(),
            read_lane_lock(path)
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn read_crash_report(gateway: &Gateway) -> ServeCrashReport {
    let source = fs::read_to_string(gateway.state_dir().join("serve-crash.json"))
        .expect("serve crash report is readable");
    serde_json::from_str(&source).expect("serve crash report is strict JSON")
}

fn read_heartbeat(gateway: &Gateway) -> ServeHeartbeat {
    let source = fs::read_to_string(gateway.state_dir().join("serve-heartbeat.json"))
        .expect("serve heartbeat is readable");
    serde_json::from_str(&source).expect("serve heartbeat is strict JSON")
}

fn start_server(
    gateway: Gateway,
    config: ServeConfig,
) -> thread::JoinHandle<Result<(), GatewayError>> {
    thread::spawn(move || gateway.serve(&config))
}

/// Join a serve thread within a deadline instead of waiting on it forever.
///
/// A serve that has been asked to stop returns at the end of its current cycle,
/// and the cycles these tests configure are milliseconds long, so the bound only
/// has to separate a loop that is stuck from one that is merely slow on a loaded
/// host: [`FIXTURE_WAIT`] sits far above any cycle and costs nothing once the
/// thread finishes. Without the bound a stuck loop hangs the whole test binary
/// rather than failing the one test that can explain it.
fn join_server_bounded(
    server: thread::JoinHandle<Result<(), GatewayError>>,
) -> Result<(), GatewayError> {
    join_server_with_limit(server, FIXTURE_WAIT)
}

fn join_server_with_limit(
    server: thread::JoinHandle<Result<(), GatewayError>>,
    limit: Duration,
) -> Result<(), GatewayError> {
    // Fixture-side-effect wait: a serve thread returning after its stop request.
    let started = Instant::now();
    while !server.is_finished() {
        assert!(
            started.elapsed() < limit,
            "serve thread had not stopped after {:?}",
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(5));
    }
    server.join().expect("serve thread joins")
}

fn serve_config(gateway: &Gateway) -> ServeConfig {
    ServeConfig::for_gateway(gateway).with_runner_prefix(vec!["/bin/false".to_owned()])
}

fn refusal(result: &RequestValidationResult) -> RefusalRule {
    match &result.outcome {
        ValidationOutcome::Refused { refusal } => refusal.rule,
        ValidationOutcome::Accepted { .. } => panic!("request was unexpectedly accepted"),
    }
}

fn audit_lines(gateway: &Gateway, lane: &str) -> Vec<String> {
    fs::read_to_string(
        gateway
            .state_dir()
            .join("audit")
            .join(format!("{lane}.jsonl")),
    )
    .expect("audit file is readable")
    .lines()
    .map(str::to_owned)
    .collect()
}

fn audit_records(gateway: &Gateway, lane: &str) -> Vec<crate::AuditRecord> {
    audit_lines(gateway, lane)
        .into_iter()
        .map(|line| serde_json::from_str(&line).expect("audit record is machine-readable"))
        .collect()
}

/// Byte counts of every unfinished-request record the lane audit carries.
///
/// The audit file is absent until the first record and a final line may be
/// half-appended while the loop runs, so both are read as "nothing yet".
fn unfinished_request_bytes(gateway: &Gateway, lane: &str) -> Vec<usize> {
    let path = gateway
        .state_dir()
        .join("audit")
        .join(format!("{lane}.jsonl"));
    let Ok(source) = fs::read_to_string(path) else {
        return Vec::new();
    };
    source
        .lines()
        .filter_map(|line| serde_json::from_str::<crate::AuditRecord>(line).ok())
        .filter_map(|record| match record.event {
            AuditEvent::RequestUnfinished { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect()
}

fn wait_for_unfinished_request(gateway: &Gateway, lane: &str) -> Vec<usize> {
    // Fixture-side-effect wait: an unfinished-request record in the lane audit.
    let started = Instant::now();
    loop {
        let observed = unfinished_request_bytes(gateway, lane);
        if !observed.is_empty() {
            return observed;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "no unfinished-request record for {lane} in its audit after {:?}",
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn action_lock_path(gateway: &Gateway, lane: &str) -> PathBuf {
    gateway.state_dir().join("locks").join(lane)
}

fn assert_action_lock_reap_record(
    record: &crate::AuditRecord,
    lane: &str,
    pid: Option<u32>,
    reason: &str,
) {
    let mut event = serde_json::json!({
        "kind": "action_lock_reaped",
        "lane": lane,
        "reason": reason,
    });
    if let Some(pid) = pid {
        event["pid"] = serde_json::json!(pid);
    }
    assert_eq!(
        serde_json::to_value(record).expect("reap audit record serializes"),
        serde_json::json!({
            "schema": 2,
            "timestamp_unix_ms": record.timestamp_unix_ms,
            "event": event,
        })
    );
}

fn proposal_request(seq: u64, reason: &str) -> String {
    format!(
        r#"{{"schema":1,"seq":{seq},"op":"propose","argv":["cargo","metadata"],"reason":"{reason}"}}"#
    )
}

fn write_park_marker(gateway: &Gateway, lane: &str, seq: u64, timeout_seconds: u64) {
    let path = gateway.proposal_park_path(lane, seq);
    fs::create_dir_all(path.parent().expect("park marker has a parent"))
        .expect("park marker directory is created");
    let park = ProposalPark {
        schema: 1,
        lane: lane.to_owned(),
        seq,
        parked_unix_ms: 123,
        attention_timeout_seconds: timeout_seconds,
    };
    fs::write(
        path,
        serde_json::to_vec(&park).expect("park marker serializes"),
    )
    .expect("park marker is written");
}

fn assert_ratified_environment_defaults() {
    // An empty explicit override uses the non-empty XDG state directory.
    let gateway = Gateway::from_environment_values(
        Some(PathBuf::new()),
        Some(PathBuf::from("/var/state/example-user")),
        Some(PathBuf::from("/var/home/example-user")),
    )
    .expect("XDG state default resolves");

    assert_eq!(
        gateway.state_dir(),
        Path::new("/var/state/example-user/lane-gateway")
    );

    // Without XDG state configuration, the default is below HOME.
    let gateway =
        Gateway::from_environment_values(None, None, Some(PathBuf::from("/var/home/example-user")))
            .expect("home state default resolves");

    assert_eq!(
        gateway.state_dir(),
        Path::new("/var/home/example-user/.local/state/lane-gateway")
    );

    // Empty XDG state configuration follows the same HOME fallback.
    let gateway = Gateway::from_environment_values(
        None,
        Some(PathBuf::new()),
        Some(PathBuf::from("/var/home/example-user")),
    )
    .expect("empty XDG state falls back to home");

    assert_eq!(
        gateway.state_dir(),
        Path::new("/var/home/example-user/.local/state/lane-gateway")
    );

    // A non-empty override preserves the former estate-shaped location.
    let former_state = PathBuf::from("/var/home/example-user")
        .join("dev")
        .join("codex")
        .join("gateway");
    let gateway = Gateway::from_environment_values(
        Some(former_state.clone()),
        Some(PathBuf::from("/var/state/example-user")),
        Some(PathBuf::from("/var/home/example-user")),
    )
    .expect("explicit gateway state resolves");

    assert_eq!(gateway.state_dir(), former_state);

    // HOME absent or empty retains the existing typed failure.
    for home in [None, Some(PathBuf::new())] {
        let error = Gateway::from_environment_values(None, None, home)
            .expect_err("unavailable home is refused");
        assert!(matches!(error, GatewayError::HomeUnavailable));
    }
}

/// Push, registered run, and proposed argv all validate in sequence, while an
/// offline run consumes no execution budget.
///
/// ´test:unit:validates-all-three-request-operations´
#[test]
fn validates_all_three_request_operations() {
    let fixture = Fixture::registered();
    let push = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":1,"op":"push"}"#,
        )
        .expect("push validation completes");
    assert!(push.is_accepted());
    fixture
        .gateway
        .append_audit(
            "lane-031",
            AuditEvent::Result {
                result: Box::new(crate::OperationResult::success(
                    1,
                    Operation::Push,
                    1,
                    Some("a".repeat(40)),
                    String::new(),
                    String::new(),
                )),
            },
        )
        .expect("successful push result is recorded");

    for request in [
        r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
        r#"{"schema":1,"seq":3,"op":"propose","argv":["cargo","metadata"],"reason":"metadata is needed"}"#,
    ] {
        let result = fixture
            .gateway
            .validate_request(&fixture.registration.lane, request)
            .expect("validation completes");
        assert!(result.is_accepted());
    }

    let status = fixture.gateway.status().expect("status is readable");
    assert_eq!(status.lanes.len(), 1);
    assert_eq!(status.lanes[0].seq_watermark, Some(3));
    assert_eq!(status.lanes[0].runs_consumed, 0);
    assert_eq!(status.lanes[0].runs_remaining, 20);
}

/// A field outside schema one is refused by name and both request and refusal
/// remain in the audit trail.
///
/// ´test:unit:refuses-an-unknown-request-field´
#[test]
fn refuses_an_unknown_request_field() {
    let fixture = Fixture::registered();
    let result = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":1,"op":"push","surprise":true}"#,
        )
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::UnknownRequestField);
    let ValidationOutcome::Refused { refusal } = result.outcome else {
        panic!("request was unexpectedly accepted");
    };
    assert_eq!(refusal.field.as_deref(), Some("surprise"));
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 2);
}

/// A request from another schema is rejected without moving the watermark.
///
/// ´test:unit:refuses-an-unsupported-request-schema´
#[test]
fn refuses_an_unsupported_request_schema() {
    let fixture = Fixture::registered();
    let result = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":2,"seq":4,"op":"push"}"#,
        )
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::UnsupportedRequestSchema);
    let status = fixture.gateway.status().expect("status is readable");
    assert_eq!(status.lanes[0].seq_watermark, None);
}

/// Reusing the current watermark is distinguished from a lower sequence.
///
/// ´test:unit:refuses-a-sequence-replay´
#[test]
fn refuses_a_sequence_replay() {
    let fixture = Fixture::registered();
    fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":7,"op":"push"}"#,
        )
        .expect("first request validates");
    let replay = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":7,"op":"push"}"#,
        )
        .expect("replay is refused");

    assert_eq!(refusal(&replay), RefusalRule::SequenceReplay);
}

/// A sequence below the current watermark receives the regression rule.
///
/// ´test:unit:refuses-a-sequence-regression´
#[test]
fn refuses_a_sequence_regression() {
    let fixture = Fixture::registered();
    fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":10,"op":"push"}"#,
        )
        .expect("first request validates");
    let regression = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":9,"op":"push"}"#,
        )
        .expect("regression is refused");

    assert_eq!(refusal(&regression), RefusalRule::SequenceRegression);
}

/// A run can choose only one name from the registered fixed roster.
///
/// ´test:unit:refuses-an-unknown-roster-command´
#[test]
fn refuses_an_unknown_roster_command() {
    let fixture = Fixture::registered();
    let result = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":1,"op":"run","command":"shell"}"#,
        )
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::UnknownRosterCommand);
}

/// Supplying argv beside a valid run name cannot alter its registered vector.
///
/// ´test:unit:refuses-run-argv-shape-tampering´
#[test]
fn refuses_run_argv_shape_tampering() {
    let fixture = Fixture::registered();
    let result = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":1,"op":"run","command":"clippy","argv":["cargo","test"]}"#,
        )
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::RunArgvForbidden);
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 2);
}

/// Proposed argv without non-blank approval context is refused explicitly.
///
/// ´test:unit:refuses-a-proposal-without-a-reason´
#[test]
fn refuses_a_proposal_without_a_reason() {
    let fixture = Fixture::registered();
    let result = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":1,"op":"propose","argv":["cargo","metadata"]}"#,
        )
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::ProposeReasonRequired);
}

/// An unregistered lane still receives machine-readable request and refusal
/// records rather than silence.
///
/// ´test:unit:refuses-an-unregistered-lane-with-an-audit-record´
#[test]
fn refuses_an_unregistered_lane_with_an_audit_record() {
    let directory = TestDirectory::new();
    let gateway = configured_gateway(directory.path().join("state"));
    let result = gateway
        .validate_request("lane-404", r#"{"schema":1,"seq":1,"op":"push"}"#)
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::UnregisteredLane);
    assert_eq!(audit_lines(&gateway, "lane-404").len(), 2);
}

/// Appending the same event twice creates two complete JSONL records and never
/// replaces the first.
///
/// ´test:unit:appends-an-identical-audit-event-as-a-new-record´
#[test]
fn appends_an_identical_audit_event_as_a_new_record() {
    let fixture = Fixture::registered();
    let event = AuditEvent::Verdict {
        actor: AuditActor::Orchestrator,
        verdict: ProposalVerdict {
            seq: 4,
            decision: VerdictDecision::Denied,
            reason: Some("not pre-cleared".to_owned()),
            expiry_reason: None,
            wall_millis: 0,
        },
    };
    fixture
        .gateway
        .append_audit("lane-031", event.clone())
        .expect("first append succeeds");
    fixture
        .gateway
        .append_audit("lane-031", event)
        .expect("second append succeeds");

    let lines = audit_lines(&fixture.gateway, "lane-031");
    assert_eq!(lines.len(), 2);
    for line in lines {
        let record: crate::AuditRecord =
            serde_json::from_str(&line).expect("record is machine-readable");
        assert!(matches!(record.event, AuditEvent::Verdict { .. }));
    }
}

/// Atomic create-new storage makes a repeated lane name a refusal instead of
/// an overwrite.
///
/// ´test:unit:rejects-a-duplicate-registration-lane-name´
#[test]
fn rejects_a_duplicate_registration_lane_name() {
    let fixture = Fixture::registered();
    let error = fixture
        .gateway
        .register(&fixture.registration)
        .expect_err("duplicate is refused");
    let GatewayError::Registration(refusal) = error else {
        panic!("unexpected gateway error");
    };
    assert_eq!(refusal.rule, RegistrationRule::DuplicateLane);
}

/// The host worktree stays absolute, while push data needs a full base object
/// identifier and a non-empty opaque mirror remote.
///
/// ´test:unit:rejects-relative-registration-paths´
#[test]
fn rejects_relative_registration_paths() {
    let fixture = Fixture::registered();
    let mut relative_worktree = fixture.registration.clone();
    relative_worktree.worktree = PathBuf::from("worktree");
    assert_eq!(
        relative_worktree
            .validate()
            .expect_err("relative worktree")
            .rule,
        RegistrationRule::WorktreeMustBeAbsolute
    );

    let mut invalid_base = fixture.registration.clone();
    invalid_base.base_commit = "HEAD".to_owned();
    assert_eq!(
        invalid_base.validate().expect_err("symbolic base").rule,
        RegistrationRule::InvalidBaseCommit
    );

    let mut empty_mirror = fixture.registration;
    empty_mirror.mirror_remote = "  ".to_owned();
    assert_eq!(
        empty_mirror
            .validate()
            .expect_err("empty mirror remote")
            .rule,
        RegistrationRule::EmptyMirrorRemote
    );

    let mut relative_checkout = registration(Path::new("/worktree"));
    relative_checkout.mirror_checkout = PathBuf::from("mirror-checkout");
    assert_eq!(
        relative_checkout
            .validate()
            .expect_err("relative mirror checkout")
            .rule,
        RegistrationRule::MirrorCheckoutMustBeAbsolute
    );
}

/// Entry 27b: registering a local mirror path that is not a reachable Git
/// repository is refused up front, instead of letting the lane's first push
/// die with `mirror_push_failed`.
///
/// ´test:unit:refuses-registration-naming-an-unreachable-local-mirror-path´
#[test]
fn refuses_registration_naming_an_unreachable_local_mirror_path() {
    let directory = TestDirectory::new();
    let worktree = directory.path().join("worktree");
    fs::create_dir_all(&worktree).expect("worktree is created");
    let gateway = configured_gateway(directory.path().join("state"));
    let mut registration = registration(&worktree);
    registration.mirror_remote = directory
        .path()
        .join("never-provisioned.git")
        .to_str()
        .expect("test mirror path is UTF-8")
        .to_owned();

    let error = gateway
        .register(&registration)
        .expect_err("unreachable mirror is refused");
    let GatewayError::Registration(refusal) = error else {
        panic!("unexpected gateway error");
    };
    assert_eq!(refusal.rule, RegistrationRule::MirrorRemoteUnreachable);
}

/// Entry 27b: a mirror path that is a reachable local bare repository still
/// registers.
///
/// ´test:unit:accepts-registration-naming-a-reachable-local-mirror-path´
#[test]
fn accepts_registration_naming_a_reachable_local_mirror_path() {
    let directory = TestDirectory::new();
    let worktree = directory.path().join("worktree");
    fs::create_dir_all(&worktree).expect("worktree is created");
    let mirror = directory.path().join("provisioned.git");
    let mirror_text = mirror.to_str().expect("test mirror path is UTF-8");
    git(
        directory.path(),
        &["init", "--bare", "--quiet", mirror_text],
    );
    let gateway = configured_gateway(directory.path().join("state"));
    let mut registration = registration(&worktree);
    registration.mirror_remote = mirror_text.to_owned();

    gateway
        .register(&registration)
        .expect("reachable mirror registers");
}

/// Entry 27b: the reachability check must also cover opaque non-local specs
/// — in practice the scp-like SSH form every real registration actually
/// uses — not just an absolute local path. `file://` is used here as a
/// deterministic, network-free stand-in: its string shape is not an
/// absolute path (so it takes the same `git ls-remote` branch a real SSH
/// spec would), while its transport is local filesystem access, so the test
/// never risks a real network hang.
///
/// ´test:unit:refuses-registration-naming-an-unreachable-remote-mirror-spec´
#[test]
fn refuses_registration_naming_an_unreachable_remote_mirror_spec() {
    let directory = TestDirectory::new();
    let worktree = directory.path().join("worktree");
    fs::create_dir_all(&worktree).expect("worktree is created");
    let gateway = configured_gateway(directory.path().join("state"));
    let mut registration = registration(&worktree);
    registration.mirror_remote = format!(
        "file://{}",
        directory.path().join("never-provisioned.git").display()
    );
    assert!(!Path::new(&registration.mirror_remote).is_absolute());

    let error = gateway
        .register(&registration)
        .expect_err("unreachable remote spec is refused");
    let GatewayError::Registration(refusal) = error else {
        panic!("unexpected gateway error");
    };
    assert_eq!(refusal.rule, RegistrationRule::MirrorRemoteUnreachable);
}

/// Entry 27b: an opaque remote spec naming a reachable (even empty) bare
/// repository still registers. Plain `git ls-remote`, not `--exit-code`, is
/// what makes an empty mirror pass.
///
/// ´test:unit:accepts-registration-naming-a-reachable-remote-mirror-spec´
#[test]
fn accepts_registration_naming_a_reachable_remote_mirror_spec() {
    let directory = TestDirectory::new();
    let worktree = directory.path().join("worktree");
    fs::create_dir_all(&worktree).expect("worktree is created");
    let mirror = directory.path().join("provisioned.git");
    let mirror_text = mirror.to_str().expect("test mirror path is UTF-8");
    git(
        directory.path(),
        &["init", "--bare", "--quiet", mirror_text],
    );
    let gateway = configured_gateway(directory.path().join("state"));
    let mut registration = registration(&worktree);
    registration.mirror_remote = format!("file://{}", mirror.display());
    assert!(!Path::new(&registration.mirror_remote).is_absolute());

    gateway
        .register(&registration)
        .expect("reachable remote spec registers");
}

/// Entry 27a: a `.toml` dropped directly into the state directory without
/// ever running `register` is loudly surfaced by `status`, rather than
/// staying invisible to `serve` — but a registered lane's own source TOML,
/// which legitimately sits beside its `registrations/<lane>.toml` copy, is
/// not mislabeled as stray.
///
/// ´test:unit:status-reports-stray-toml-files-outside-the-registrations-directory´
#[test]
fn status_reports_stray_toml_files_outside_the_registrations_directory() {
    let fixture = Fixture::registered();
    fs::write(
        fixture.gateway.state_dir().join("dropped-lane.toml"),
        b"never registered\n",
    )
    .expect("stray toml is written");
    fs::write(
        fixture
            .gateway
            .state_dir()
            .join(format!("{}.toml", fixture.registration.lane)),
        b"source copy of a still-registered lane\n",
    )
    .expect("registered lane's source toml is written");

    let status = fixture.gateway.status().expect("status is readable");
    assert_eq!(
        status.unregistered_toml_files,
        vec!["dropped-lane.toml".to_owned()]
    );
}

/// A registration cannot leave the pre-cleared command policy empty.
///
/// ´test:unit:rejects-an-empty-command-roster´
#[test]
fn rejects_an_empty_command_roster() {
    let fixture = Fixture::registered();
    let mut registration = fixture.registration;
    registration.commands.clear();

    assert_eq!(
        registration.validate().expect_err("empty roster").rule,
        RegistrationRule::EmptyCommandRoster
    );
}

/// Strict TOML parsing refuses a registration field the version-one schema
/// does not name.
///
/// ´test:unit:rejects-an-unknown-registration-field´
#[test]
fn rejects_an_unknown_registration_field() {
    let fixture = Fixture::registered();
    let mut source = toml::to_string(&fixture.registration).expect("registration serializes");
    source.push_str("unknown_field = true\n");

    assert_eq!(
        Registration::from_toml(&source)
            .expect_err("unknown field is refused")
            .rule,
        RegistrationRule::MalformedToml
    );
}

/// The request type refuses JSON null for optional fields, so presence cannot
/// be disguised as omission.
///
/// ´test:unit:rejects-null-operation-fields´
#[test]
fn rejects_null_operation_fields() {
    let fixture = Fixture::registered();
    let result = fixture
        .gateway
        .validate_request(
            &fixture.registration.lane,
            r#"{"schema":1,"seq":1,"op":"push","command":null}"#,
        )
        .expect("validation completes");

    assert_eq!(refusal(&result), RefusalRule::MalformedRequest);
}

/// Completed run result records, rather than offline validations, consume the
/// run count and wall totals reported by status.
///
/// ´test:unit:derives-budget-consumption-from-result-records´
#[test]
fn derives_budget_consumption_from_result_records() {
    let fixture = Fixture::registered();
    fixture
        .gateway
        .append_audit(
            "lane-031",
            AuditEvent::Result {
                result: Box::new(crate::OperationResult {
                    schema: crate::types::RESULT_SCHEMA,
                    seq: Some(8),
                    operation: Some(Operation::Run),
                    command: Some("clippy".to_owned()),
                    exit_code: 0,
                    wall_millis: 1250,
                    queue_wait_ms: Some(15),
                    verdict: ResultVerdict::Success,
                    commit_id: Some("a".repeat(40)),
                    cargo_target_dir: Some(PathBuf::from("/mirror/checkout/target")),
                    refusal: None,
                    proposal_timeout_seconds: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    output_chunks: Vec::new(),
                }),
            },
        )
        .expect("result append succeeds");

    let status = fixture.gateway.status().expect("status is readable");
    assert_eq!(status.lanes[0].runs_consumed, 1);
    assert_eq!(status.lanes[0].runs_remaining, 19);
    assert_eq!(
        status.lanes[0].commands["clippy"].wall_millis_consumed,
        1250
    );
}

/// Omitted lane-wide budgets, proposal timeout, and gateway state environment
/// values receive their ratified defaults.
///
/// ´test:unit:applies-the-ratified-registration-defaults´
#[test]
fn applies_the_ratified_registration_defaults() {
    assert_ratified_environment_defaults();

    let fixture = Fixture::registered();
    let mut value =
        toml::Value::try_from(&fixture.registration).expect("registration converts to TOML");
    let table = value.as_table_mut().expect("registration is a table");
    assert!(table.remove("budgets").is_some());
    assert!(table.remove("proposal_timeout_seconds").is_some());
    let source = toml::to_string(&value).expect("registration serializes");

    let parsed = Registration::from_toml(&source).expect("defaults are accepted");
    assert_eq!(parsed.budgets.run_cap, 20);
    assert_eq!(parsed.budgets.cooldown_seconds, 5);
    assert_eq!(parsed.proposal_timeout_seconds, 600);
}

/// A temporary-index snapshot includes tracked edits and untracked files while
/// preserving the lane's index and HEAD bytes.
///
/// ´test:unit:snapshot-captures-tracked-and-untracked-without-mutating-lane-git-state´
#[test]
fn snapshot_captures_tracked_and_untracked_without_mutating_lane_git_state() {
    let fixture = GitFixture::registered();
    let config = ServeConfig::for_gateway(&fixture.gateway);
    let git_dir = fixture.registration.worktree.join(".git");
    let index_before = fs::read(git_dir.join("index")).expect("index is readable");
    let head_before = fs::read(git_dir.join("HEAD")).expect("HEAD is readable");
    let refs_before = git_text(&fixture.registration.worktree, &["show-ref"]);
    let package = fixture.registration.worktree.join("packages/lane-gateway");
    fs::write(package.join("tracked.txt"), "changed\n").expect("tracked edit is written");
    fs::write(package.join("untracked.txt"), "new\n").expect("untracked file is written");

    let result = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("push processing completes");
    assert_eq!(result.verdict, ResultVerdict::Success);
    let commit = result.commit_id.expect("push returns a commit");
    let tracked = format!("{commit}:packages/lane-gateway/tracked.txt");
    let untracked = format!("{commit}:packages/lane-gateway/untracked.txt");
    assert_eq!(git_text(&fixture.mirror, &["show", &tracked]), "changed");
    assert_eq!(git_text(&fixture.mirror, &["show", &untracked]), "new");
    assert_eq!(
        fs::read(git_dir.join("index")).expect("index remains readable"),
        index_before
    );
    assert_eq!(
        fs::read(git_dir.join("HEAD")).expect("HEAD remains readable"),
        head_before
    );
    assert_eq!(
        git_text(&fixture.registration.worktree, &["show-ref"]),
        refs_before
    );
    snapshot_excludes_sandbox_placeholders();
    snapshot_without_placeholders_keeps_ordinary_empty_files();
}

/// A sandbox's special path and empty untracked dotfiles are omitted before
/// Git stages the temporary index, and the result states how many were skipped.
///
fn snapshot_excludes_sandbox_placeholders() {
    let fixture = GitFixture::registered();
    let worktree = &fixture.registration.worktree;
    let special = worktree.join("masked-device");
    let device_created = Command::new("mknod")
        .arg(&special)
        .args(["c", "1", "3"])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("device probe starts")
        .success();
    if !device_created {
        assert!(
            Command::new("mkfifo")
                .arg(&special)
                .status()
                .expect("FIFO fallback starts")
                .success(),
            "special-file fixture could not be created"
        );
    }
    assert!(
        crate::push::is_special_file(
            fs::metadata("/dev/null")
                .expect("system character device exists")
                .file_type()
        ),
        "character devices satisfy the same snapshot predicate"
    );
    fs::write(worktree.join(".bashrc"), []).expect("empty masked dotfile exists");
    fs::create_dir(worktree.join(".claude")).expect("masked dot directory exists");
    fs::write(worktree.join(".claude/settings.json"), [])
        .expect("empty masked nested dotfile exists");
    let hidden_nested_dir = worktree.join("packages/lane-gateway/.fixture");
    fs::create_dir(&hidden_nested_dir).expect("hidden nested fixture directory exists");
    fs::write(hidden_nested_dir.join("empty.txt"), [])
        .expect("empty untracked file below hidden nested directory exists");

    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":1,"op":"push"}"#,
            &ServeConfig::for_gateway(&fixture.gateway),
        )
        .expect("placeholder snapshot completes");
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert!(
        result
            .stdout
            .contains("omitted 3 sandbox placeholder path(s)"),
        "unexpected push note: {}",
        result.stdout
    );
    let commit = result.commit_id.expect("placeholder snapshot has a commit");
    let tree = git_text(&fixture.mirror, &["ls-tree", "-r", "--name-only", &commit]);
    assert!(
        !tree
            .lines()
            .any(|path| { matches!(path, "masked-device" | ".bashrc" | ".claude/settings.json") })
    );
    assert!(
        tree.lines()
            .any(|path| path == "packages/lane-gateway/.fixture/empty.txt")
    );
}

/// With no masked paths, an ordinary empty untracked file is still staged and
/// no omission note changes the push result.
///
fn snapshot_without_placeholders_keeps_ordinary_empty_files() {
    let fixture = GitFixture::registered();
    fs::write(fixture.registration.worktree.join("empty.txt"), [])
        .expect("ordinary empty file exists");
    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":1,"op":"push"}"#,
            &ServeConfig::for_gateway(&fixture.gateway),
        )
        .expect("ordinary snapshot completes");
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert!(!result.stdout.contains("sandbox placeholder"));
    let commit = result.commit_id.expect("ordinary snapshot has a commit");
    let tree = git_text(&fixture.mirror, &["ls-tree", "-r", "--name-only", &commit]);
    assert!(tree.lines().any(|path| path == "empty.txt"));
}

/// A synthetic snapshot excludes every live transport path while the mirror
/// remains usable by the next registered run.
///
/// ´test:unit:snapshot-excludes-lane-transport-before-push-and-run´
#[test]
fn snapshot_excludes_lane_transport_before_push_and_run() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "transport-free-run.sh",
        "test ! -e .lane || exit 51\nprintf 'snapshot clean\\n'\n",
    );
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir_all(lane_dir.join("proposals")).expect("live transport directories are created");
    fs::write(
        lane_dir.join("request.json"),
        r#"{"schema":1,"seq":1,"op":"push"}"#,
    )
    .expect("live request transport is written");
    fs::write(lane_dir.join("result.json"), b"live result\n")
        .expect("live result transport is written");
    fs::write(lane_dir.join("proposals/7.json"), b"live proposal\n")
        .expect("live proposal transport is written");
    let (config, _record) = fixture.runner_config(512 * 1_024);

    let push = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("transport-free push completes");
    assert_eq!(push.verdict, ResultVerdict::Success);
    let commit = push
        .commit_id
        .expect("transport-free push returns a commit");
    let tree_paths = git_text(&fixture.mirror, &["ls-tree", "-r", "--name-only", &commit]);
    assert!(
        tree_paths
            .lines()
            .all(|path| !Path::new(path).starts_with(".lane"))
    );

    let run = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("registered run uses transport-free snapshot");
    assert_eq!(run.verdict, ResultVerdict::Success);
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "snapshot clean\n");
    assert!(!fixture.checkout.join(".lane").exists());
}

/// A successful push installs exactly the reported snapshot commit at the
/// lane's fixed mirror ref.
///
/// ´test:unit:push-installs-exact-snapshot-at-lane-mirror-ref´
#[test]
fn push_installs_exact_snapshot_at_lane_mirror_ref() {
    let fixture = GitFixture::registered();
    let config = ServeConfig::for_gateway(&fixture.gateway);
    let result = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("push processing completes");

    assert_eq!(result.verdict, ResultVerdict::Success);
    assert_eq!(
        git_text(
            &fixture.mirror,
            &["rev-parse", "refs/lanes/gateway/lane-031"]
        ),
        result.commit_id.expect("push returns a commit")
    );
}

/// Entry 24: push is always allowed and unscoped — a snapshot touching paths
/// outside the registered package allowlist still installs at the mirror in
/// full, with the out-of-scope paths only annotated (not refused) in the
/// push result. Scope enforcement moved to run admission and the
/// orchestrator's own diff audit.
///
/// ´test:unit:push-admits-whole-worktree-and-annotates-out-of-scope-paths´
#[test]
fn push_admits_whole_worktree_and_annotates_out_of_scope_paths() {
    let fixture = GitFixture::registered();
    let config = ServeConfig::for_gateway(&fixture.gateway);
    fs::write(fixture.registration.worktree.join("README.md"), "changed\n")
        .expect("outside tracked edit is written");
    let outside = fixture.registration.worktree.join("outside");
    fs::create_dir(&outside).expect("outside directory is created");
    fs::write(outside.join("new.txt"), "new\n").expect("outside file is written");

    let result = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("push completes");
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert!(result.refusal.is_none());
    let commit = result.commit_id.expect("push returns a commit");
    assert_eq!(
        git_text(&fixture.mirror, &["show", &format!("{commit}:README.md")]),
        "changed"
    );
    assert_eq!(
        git_text(
            &fixture.mirror,
            &["show", &format!("{commit}:outside/new.txt")]
        ),
        "new"
    );
    assert!(result.stdout.contains("README.md"));
    assert!(result.stdout.contains("outside/new.txt"));
}

/// Entry 23: a lane whose deliverable is a brand-new package can push, even
/// though the package cannot possibly exist at the registered base commit —
/// the allowlist resolves against the pushed snapshot, not the stale base.
///
/// ´test:unit:push-resolves-new-package-first-introduced-by-the-snapshot´
#[test]
fn push_resolves_new_package_first_introduced_by_the_snapshot() {
    let mut fixture = GitFixture::registered();
    let new_package = fixture.registration.worktree.join("packages/new-pkg");
    fs::create_dir_all(&new_package).expect("new package directory is created");
    fs::write(
        new_package.join("Cargo.toml"),
        "[package]\nname = \"new-pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("new package manifest is written");

    fixture
        .gateway
        .deregister(&fixture.registration.lane)
        .expect("registration is removed for amendment");
    fixture.registration.packages.push("new-pkg".to_owned());
    fixture
        .registration
        .commands
        .get_mut("test")
        .expect("test roster entry exists")
        .argv = vec![
        "cargo".to_owned(),
        "test".to_owned(),
        "--package".to_owned(),
        "lane-gateway".to_owned(),
        "--package".to_owned(),
        "new-pkg".to_owned(),
    ];
    fixture
        .gateway
        .register(&fixture.registration)
        .expect("amended registration succeeds");

    let config = ServeConfig::for_gateway(&fixture.gateway);
    let result = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("push completes");
    assert_eq!(
        result.verdict,
        ResultVerdict::Success,
        "push refused: {:?} / stderr: {}",
        result.refusal,
        result.stderr
    );
}

/// Entry 23 (near miss): a registered package name absent from the pushed
/// snapshot is diagnosed with the cargo package names actually found under
/// the closest-matching directory, so a directory-name/package-name mismatch
/// does not cost a blind resume round trip.
///
/// ´test:unit:refuses-push-naming-absent-package-with-near-miss-candidates´
#[test]
fn refuses_push_naming_absent_package_with_near_miss_candidates() {
    let mut fixture = GitFixture::registered();
    let near_miss = fixture.registration.worktree.join("packages/project-a");
    fs::create_dir_all(&near_miss).expect("near-miss package directory is created");
    fs::write(
        near_miss.join("Cargo.toml"),
        "[package]\nname = \"example-project-a\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("near-miss package manifest is written");

    fixture
        .gateway
        .deregister(&fixture.registration.lane)
        .expect("registration is removed for amendment");
    fixture.registration.packages = vec!["project-a".to_owned()];
    fixture
        .registration
        .commands
        .get_mut("test")
        .expect("test roster entry exists")
        .argv = vec![
        "cargo".to_owned(),
        "test".to_owned(),
        "--package".to_owned(),
        "project-a".to_owned(),
    ];
    fixture
        .gateway
        .register(&fixture.registration)
        .expect("amended registration succeeds");

    let config = ServeConfig::for_gateway(&fixture.gateway);
    let result = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("push processing completes");
    assert_eq!(result.verdict, ResultVerdict::Refused);
    let refusal = result.refusal.expect("package refusal is present");
    assert_eq!(refusal.rule, RefusalRule::PackageAllowlistUnresolved);
    assert!(result.stderr.contains("example-project-a"));
}

/// The configured runner receives the registered checkout followed by the
/// fixed roster argv, executes there, and reports tool status and mirror data.
///
/// ´test:unit:run-executes-fixed-roster-argv-in-mirror-checkout´
#[test]
fn run_executes_fixed_roster_argv_in_mirror_checkout() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "run-command.sh",
        "sleep 0.02\nprintf 'cwd=%s\\n' \"$PWD\"\nprintf 'head='\ngit rev-parse HEAD\nprintf 'first=%s\\n' \"$1\"\nprintf 'second=%s\\n' \"$2\"\nexit 7\n",
    );
    let argv = vec![
        "/bin/sh".to_owned(),
        script,
        "fixed value".to_owned(),
        "--fixed".to_owned(),
    ];
    fixture.configure_clippy(
        argv.clone(),
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let (config, record) = fixture.runner_config(512 * 1_024);
    let push = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("run fixture push completes");
    let commit = push.commit_id.expect("run fixture push returns a commit");

    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("fixed run completes");

    assert_eq!(result.verdict, ResultVerdict::Success);
    assert_eq!(result.exit_code, 7);
    assert_ne!(result.wall_millis, 0);
    assert!(result.queue_wait_ms.is_some());
    assert_eq!(result.commit_id.as_deref(), Some(commit.as_str()));
    assert_eq!(
        result.stdout,
        format!(
            "cwd={}\nhead={commit}\nfirst=fixed value\nsecond=--fixed\n",
            fixture.checkout.display(),
        )
    );
    assert_eq!(result.stderr, "");
    let expected_target = fixture.checkout.join("target");
    assert_eq!(
        result.cargo_target_dir.as_deref(),
        Some(expected_target.as_path())
    );
    let mut expected_record = vec![
        "budget=60".to_owned(),
        format!("commit={commit}"),
        format!("remote={}", fixture.mirror.display()),
        format!("target={}/target", fixture.checkout.display()),
        format!("argument={}", fixture.checkout.display()),
    ];
    expected_record.extend(
        argv.into_iter()
            .map(|argument| format!("argument={argument}")),
    );
    let actual_record: Vec<_> = fs::read_to_string(record)
        .expect("runner record is readable")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(actual_record, expected_record);
    let records = audit_records(&fixture.gateway, "lane-031");
    assert_eq!(records.len(), 4);
    let audit_value = serde_json::to_value(records.last().expect("run audit record exists"))
        .expect("run audit record serializes");
    assert_eq!(
        audit_value["event"]["result"]["cargo_target_dir"],
        serde_json::json!(expected_target)
    );
    let status = fixture.gateway.status().expect("run status is readable");
    assert_eq!(status.lanes[0].runs_consumed, 1);
    assert_eq!(
        status.lanes[0].commands["clippy"].wall_millis_consumed,
        result.wall_millis
    );
}

/// Every accepted run consumes the lane cap; the next request receives the
/// final verify-direction refusal and does not invoke the runner.
///
/// ´test:unit:run-cap-exhaustion-directs-worker-to-final-verify´
#[test]
fn run_cap_exhaustion_directs_worker_to_final_verify() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script("quick-run.sh", "exit 0\n");
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 2,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("cap fixture push completes");
    for seq in [2, 3] {
        let source = format!(r#"{{"schema":1,"seq":{seq},"op":"run","command":"clippy"}}"#);
        let result = fixture
            .gateway
            .process_request("lane-031", &source, &config)
            .expect("budgeted run completes");
        assert_eq!(result.verdict, ResultVerdict::Success);
    }

    let exhausted = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":4,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("cap refusal completes");
    assert_eq!(exhausted.verdict, ResultVerdict::CapRefused);
    let refusal = exhausted.refusal.expect("cap refusal is present");
    assert_eq!(refusal.rule, RefusalRule::RunBudgetExhausted);
    assert_eq!(refusal.cap, Some(crate::RefusalCap::RunCap));
    assert_eq!(refusal.cap_limit, Some(2));
    assert_eq!(refusal.count_reached, Some(2));
    assert_eq!(
        refusal.message,
        "registered run cap has been consumed; continue with READY FOR VERIFY"
    );
    let status = fixture.gateway.status().expect("cap status is readable");
    assert_eq!(status.lanes[0].runs_consumed, 2);
    assert_eq!(status.lanes[0].runs_remaining, 0);
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 8);
    approved_proposal_cap_refusal_has_own_verdict();
}

/// A proposal approved after the run cap is consumed reports budget refusal
/// instead of implying that its candidate command ran and failed.
///
fn approved_proposal_cap_refusal_has_own_verdict() {
    let mut fixture = GitFixture::registered();
    fixture.configure_clippy(
        vec!["/bin/true".to_owned()],
        60,
        BudgetPolicy {
            run_cap: 1,
            cooldown_seconds: 0,
        },
    );
    let (config, record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("cap fixture push completes");
    fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("first run consumes the cap");
    let runner_before = fs::read(&record).expect("first runner record exists");
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":3,"op":"propose","argv":["/bin/false"],"reason":"verify cap verdict"}"#, &config)
        .expect("proposal is queued");
    let result = fixture
        .gateway
        .approve_proposal("lane-031", 3, false, None, &config)
        .expect("cap refusal is terminal");
    let encoded = serde_json::to_value(&result).expect("cap result serializes");
    assert_eq!(encoded["verdict"], "cap-refused");
    assert_eq!(encoded["refusal"]["rule"], "run_budget_exhausted");
    assert_eq!(encoded["refusal"]["cap"], "run_cap");
    assert_eq!(encoded["refusal"]["cap_limit"], 1);
    assert_eq!(encoded["refusal"]["count_reached"], 1);
    assert_eq!(
        fs::read(record).expect("runner record is readable"),
        runner_before
    );
    assert_eq!(
        wait_for_result_seq(
            &fixture.registration.worktree.join(".lane/proposals/3.json"),
            3
        )
        .verdict,
        ResultVerdict::CapRefused
    );
}

/// The registered cooldown is measured from every accepted run result and
/// refuses an immediate follow-up without consuming another run.
///
/// ´test:unit:refuses-run-during-registered-cooldown´
#[test]
fn refuses_run_during_registered_cooldown() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script("cooldown-run.sh", "exit 0\n");
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 60,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("cooldown fixture push completes");
    fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("first cooldown run completes");
    let refused = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":3,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("cooldown refusal completes");

    assert_eq!(refused.verdict, ResultVerdict::Refused);
    assert_eq!(
        refused.refusal.expect("cooldown refusal is present").rule,
        RefusalRule::RunCooldownActive
    );
    let status = fixture
        .gateway
        .status()
        .expect("cooldown status is readable");
    assert_eq!(status.lanes[0].runs_consumed, 1);
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 6);
}

/// Exceeding the registered wall budget kills the runner and retains output
/// emitted before the typed over-budget result.
///
/// ´test:unit:timeout-kills-runner-and-records-partial-output´
#[test]
fn timeout_kills_runner_and_records_partial_output() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "timeout-run.sh",
        "printf 'partial-out\\n'\nprintf 'partial-error\\n' >&2\nexec sleep 5\n",
    );
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        1,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let (config, record) = fixture.runner_config(512 * 1_024);
    let push = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("timeout fixture push completes");
    let commit = push.commit_id.expect("timeout push returns a commit");

    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("timeout run completes");

    assert_eq!(result.verdict, ResultVerdict::OverBudget);
    assert_eq!(result.stdout, "partial-out\n");
    assert_eq!(result.stderr, "partial-error\n");
    assert_eq!(result.commit_id.as_deref(), Some(commit.as_str()));
    assert!(result.wall_millis >= 900);
    assert!(result.wall_millis <= 4_500);
    assert_eq!(
        fs::read_to_string(record)
            .expect("timeout runner record is readable")
            .lines()
            .next(),
        Some("budget=1")
    );
    let status = fixture
        .gateway
        .status()
        .expect("timeout status is readable");
    assert_eq!(status.lanes[0].runs_consumed, 1);
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 4);
}

/// A runner that exits with the transport's reserved code is refused as a lost
/// connection rather than reported as a command that ran and failed.
///
/// ´test:unit:runner-transport-exit-is-refused-as-a-lost-connection´
#[test]
fn runner_transport_exit_is_refused_as_a_lost_connection() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "transport-loss.sh",
        "printf 'partial-out\\n'\nprintf 'client_loop: send disconnect: Broken pipe\\n' >&2\nexit 255\n",
    );
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    let push = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("transport-loss fixture push completes");
    let commit = push
        .commit_id
        .expect("transport-loss push returns a commit");

    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("transport-loss run completes");

    assert_eq!(result.verdict, ResultVerdict::Refused);
    let refusal = result
        .refusal
        .as_ref()
        .expect("transport loss carries a typed refusal");
    assert_eq!(refusal.rule, RefusalRule::RunnerConnectionLost);
    assert_eq!(refusal.seq, Some(2));
    assert_eq!(result.seq, Some(2));
    assert_eq!(result.exit_code, 255);
    assert_eq!(result.commit_id.as_deref(), Some(commit.as_str()));
    assert_eq!(result.stdout, "partial-out\n");
    assert!(result.stderr.contains("Broken pipe"));
}

/// Every runner exit other than the transport's reserved code stays the
/// command's own status, so a tool that fails is not reported as a lost lane.
///
/// ´test:unit:runner-exit-other-than-the-transport-code-is-the-command-status´
#[test]
fn runner_exit_other_than_the_transport_code_is_the_command_status() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "failing-command.sh",
        "printf 'error: lint failed\\n' >&2\nexit 1\n",
    );
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("failing-command fixture push completes");

    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("failing-command run completes");

    assert_eq!(result.verdict, ResultVerdict::Success);
    assert_eq!(result.exit_code, 1);
    assert_eq!(result.refusal, None);
    assert!(result.stderr.contains("lint failed"));
}

/// A runner that cannot be executed at all is still the older, wider runner
/// failure, which the transport rule narrows rather than replaces.
///
/// ´test:unit:unspawnable-runner-is-still-a-runner-failure´
#[test]
fn unspawnable_runner_is_still_a_runner_failure() {
    let fixture = GitFixture::registered();
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("unspawnable-runner fixture push completes");
    let broken = config.with_runner_prefix(vec![
        fixture
            .directory
            .path()
            .join("no-such-runner")
            .to_string_lossy()
            .into_owned(),
    ]);

    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &broken,
        )
        .expect("unspawnable runner completes as a typed result");

    assert_eq!(result.verdict, ResultVerdict::Refused);
    assert_eq!(
        result
            .refusal
            .as_ref()
            .expect("unspawnable runner carries a typed refusal")
            .rule,
        RefusalRule::RunnerFailed
    );
}

/// A later accepted push failure invalidates an older mirror commit, so the
/// gateway never silently runs stale state.
///
/// ´test:unit:failed-push-invalidates-older-mirror-snapshot´
#[test]
fn failed_push_invalidates_older_mirror_snapshot() {
    let fixture = GitFixture::registered();
    let config = serve_config(&fixture.gateway);
    let pushed = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("initial push completes");
    assert_eq!(pushed.verdict, ResultVerdict::Success);
    // Entry 24 made push admit the whole worktree unconditionally, so an
    // out-of-scope edit no longer fails a push; remove the mirror itself to
    // force a later push failure (mirror_push_failed) instead.
    fs::remove_dir_all(&fixture.mirror).expect("mirror is removed to force a push failure");
    let failed = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":2,"op":"push"}"#, &config)
        .expect("later push refusal completes");
    assert_eq!(failed.verdict, ResultVerdict::Refused);
    assert_eq!(
        failed.refusal.expect("push failure is present").rule,
        RefusalRule::MirrorPushFailed
    );

    let run = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":3,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("stale run refusal completes");
    assert_eq!(run.verdict, ResultVerdict::Refused);
    assert_eq!(
        run.refusal.expect("stale refusal is present").rule,
        RefusalRule::NoSnapshot
    );
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 6);
}

/// The watcher consumes a push request, publishes its worker result, appends
/// request/result audit records, and touches no other protocol file.
///
/// ´test:unit:serve-loop-pushes-writes-result-and-appends-audit´
#[test]
fn serve_loop_pushes_writes_result_and_appends_audit() {
    let fixture = GitFixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("protocol directory is created");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":1,"op":"push"}"#,
    )
    .expect("request is written");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let result = wait_for_result(&fixture.result_path());
    assert_eq!(result.seq, Some(1));
    assert_eq!(result.verdict, ResultVerdict::Success);
    let commit = result.commit_id.expect("serve push returns a commit");
    assert_eq!(
        git_text(
            &fixture.mirror,
            &["rev-parse", "refs/lanes/gateway/lane-031"]
        ),
        commit
    );
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 2);
    let mut protocol_files: Vec<_> = fs::read_dir(&lane_dir)
        .expect("protocol directory is readable")
        .map(|entry| {
            entry
                .expect("protocol entry is readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    protocol_files.sort();
    assert_eq!(protocol_files, vec!["request.json", "result.json"]);

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// Output above the configured payload limit is published as ordered stream
/// chunks while the immutable audit result retains both complete streams.
///
/// ´test:unit:oversized-run-output-is-published-in-order´
#[test]
fn oversized_run_output_is_published_in_order() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "chunked-run.sh",
        "printf 'abcdefgh'\nprintf 'ijklmnop' >&2\n",
    );
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(4);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("chunk fixture push completes");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("chunk protocol directory is created");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
    )
    .expect("chunk run request is written");
    let config = config.with_poll_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let result = wait_for_result_seq(&fixture.result_path(), 2);
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert_eq!(result.stdout, "");
    assert_eq!(result.stderr, "");
    assert_eq!(result.output_chunks.len(), 4);
    let mut chunks = Vec::new();
    for reference in &result.output_chunks {
        let source =
            fs::read_to_string(lane_dir.join(&reference.file)).expect("output chunk is readable");
        let chunk: OutputChunk =
            serde_json::from_str(&source).expect("output chunk is machine-readable");
        assert_eq!(chunk.index, reference.index);
        assert_eq!(chunk.stream, reference.stream);
        assert_eq!(chunk.seq, Some(2));
        chunks.push(chunk);
    }
    let payloads: Vec<_> = chunks.iter().map(|chunk| chunk.data.as_str()).collect();
    assert_eq!(payloads, vec!["abcd", "efgh", "ijkl", "mnop"]);
    let streams: Vec<_> = chunks.iter().map(|chunk| chunk.stream).collect();
    assert_eq!(
        streams,
        vec![
            OutputStream::Stdout,
            OutputStream::Stdout,
            OutputStream::Stderr,
            OutputStream::Stderr,
        ]
    );

    let lines = audit_lines(&fixture.gateway, "lane-031");
    assert_eq!(lines.len(), 4);
    let record: crate::AuditRecord =
        serde_json::from_str(lines.last().expect("run audit record exists"))
            .expect("run audit record is machine-readable");
    let AuditEvent::Result { result: audited } = record.event else {
        panic!("last audit event was not a result");
    };
    assert_eq!(audited.stdout, "abcdefgh");
    assert_eq!(audited.stderr, "ijklmnop");
    assert_eq!(audited.output_chunks, Vec::new());

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// A single serve loop finishes one lane run before observing the next request
/// bytes, preserving the one-in-flight structural limit.
///
/// ´test:unit:serve-loop-keeps-one-run-in-flight-per-lane´
#[test]
fn serve_loop_keeps_one_run_in_flight_per_lane() {
    let mut fixture = GitFixture::registered();
    let trace = fixture.directory.path().join("run-trace.txt");
    let script = fixture.write_package_script(
        "serial-run.sh",
        "trace=$1\nif [ -e \"$trace.lock\" ]; then printf 'overlap\\n' >> \"$trace\"; fi\n: > \"$trace.lock\"\nprintf 'start\\n' >> \"$trace\"\nsleep 0.15\nprintf 'end\\n' >> \"$trace\"\nrm -f \"$trace.lock\"\n",
    );
    fixture.configure_clippy(
        vec![
            "/bin/sh".to_owned(),
            script,
            trace.to_string_lossy().into_owned(),
        ],
        60,
        BudgetPolicy {
            run_cap: 3,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("serial fixture push completes");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("serial protocol directory is created");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
    )
    .expect("first serial request is written");
    let config = config.with_poll_interval_millis(5);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    wait_for_text(&trace, "start\n");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":3,"op":"run","command":"clippy"}"#,
    )
    .expect("second serial request is written");
    let result = wait_for_result_seq(&fixture.result_path(), 3);
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert_eq!(
        fs::read_to_string(trace).expect("serial trace is readable"),
        "start\nend\nstart\nend\n"
    );
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 6);

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// A run before any successful push receives the typed freshness refusal and
/// records both the request and refusal.
///
/// ´test:unit:refuses-run-with-no-snapshot´
#[test]
fn refuses_run_with_no_snapshot() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":1,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("freshness refusal completes");

    assert_eq!(result.verdict, ResultVerdict::Refused);
    assert_eq!(
        result.refusal.expect("freshness refusal is present").rule,
        RefusalRule::NoSnapshot
    );
    assert_eq!(audit_lines(&fixture.gateway, "lane-031").len(), 2);
}

/// Intake parks exact proposal data, acknowledges the registered timeout, and
/// retains explicit queue and result audit events.
///
/// ´test:unit:proposal-intake-parks-pending-and-audits´
#[test]
fn proposal_intake_parks_pending_and_audits() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("proposal protocol directory is created");
    fs::write(
        lane_dir.join("request.json"),
        r#"{"schema":1,"seq":1,"op":"propose","argv":["cargo","metadata","--no-deps"],"reason":"inspect metadata"}"#,
    )
    .expect("proposal request is written");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let result = wait_for_result_seq(&lane_dir.join("result.json"), 1);
    assert_eq!(result.verdict, ResultVerdict::Pending);
    assert_eq!(result.operation, Some(Operation::Propose));
    assert_eq!(result.proposal_timeout_seconds, Some(600));
    let proposal = fixture
        .gateway
        .load_open_proposal("lane-031", 1)
        .expect("common proposal is readable");
    assert_eq!(
        proposal.argv,
        vec![
            "cargo".to_owned(),
            "metadata".to_owned(),
            "--no-deps".to_owned()
        ]
    );
    assert_eq!(proposal.reason, "inspect metadata");
    assert_eq!(proposal.timeout_seconds, 600);
    let queue = fixture
        .gateway
        .proposals()
        .expect("proposal queue is readable");
    assert_eq!(queue.proposals.len(), 1);
    assert_eq!(queue.proposals[0].lane, "lane-031");
    assert_eq!(queue.proposals[0].seq, 1);

    let records = audit_records(&fixture.gateway, "lane-031");
    assert_eq!(records.len(), 3);
    let AuditEvent::ProposalQueued { proposal: audited } = &records[1].event else {
        panic!("second audit event is not proposal intake");
    };
    assert_eq!(audited, &proposal);
    let AuditEvent::Result { result: audited } = &records[2].event else {
        panic!("third audit event is not the pending result");
    };
    assert_eq!(audited.verdict, ResultVerdict::Pending);

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// Listing omits a denied proposal, while its exact reason reaches the worker
/// and its orchestrator-authored verdict remains auditable.
///
/// ´test:unit:proposals-lists-pending-and-deny-delivers-reason´
#[test]
fn proposals_lists_pending_and_deny_delivers_reason() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    for (seq, reason) in [(1, "first reason"), (2, "second reason")] {
        let source = format!(
            r#"{{"schema":1,"seq":{seq},"op":"propose","argv":["cargo","metadata","--no-deps"],"reason":"{reason}"}}"#
        );
        let result = fixture
            .gateway
            .process_request("lane-031", &source, &config)
            .expect("proposal intake completes");
        assert_eq!(result.verdict, ResultVerdict::Pending);
    }
    let before = fixture
        .gateway
        .proposals()
        .expect("proposal queue is readable");
    let before_sequences: Vec<_> = before.proposals.iter().map(|item| item.seq).collect();
    assert_eq!(before_sequences, vec![1, 2]);

    let denied = fixture
        .gateway
        .deny_proposal("lane-031", 1, "outside the lane contract")
        .expect("proposal denial succeeds");
    assert_eq!(denied.verdict, ResultVerdict::Denied);
    assert_eq!(denied.operation, Some(Operation::Propose));
    let refusal = denied.refusal.expect("denial refusal is present");
    assert_eq!(refusal.rule, RefusalRule::ProposalDenied);
    assert_eq!(refusal.reason.as_deref(), Some("outside the lane contract"));
    let published: crate::OperationResult = serde_json::from_str(
        &fs::read_to_string(fixture.registration.worktree.join(".lane/result.json"))
            .expect("denial result is published"),
    )
    .expect("denial result is machine-readable");
    assert_eq!(published.seq, Some(1));
    assert_eq!(published.refusal, Some(refusal));

    let after = fixture
        .gateway
        .proposals()
        .expect("proposal queue is readable");
    assert_eq!(after.proposals.len(), 1);
    assert_eq!(after.proposals[0].seq, 2);
    let records = audit_records(&fixture.gateway, "lane-031");
    records
        .iter()
        .find(|record| {
            matches!(
                &record.event,
                AuditEvent::Verdict {
                    actor: AuditActor::Orchestrator,
                    verdict: ProposalVerdict {
                        seq: 1,
                        decision: VerdictDecision::Denied,
                        reason: Some(reason),
                        ..
                    },
                } if reason == "outside the lane contract"
            )
        })
        .expect("orchestrator denial is audited");
}

/// A configured target root is reflected in both the runner environment and
/// the immutable run audit field using the per-checkout hashed derivation.
///
/// ´test:unit:run-audit-records-configured-target-root-derivation´
#[test]
fn run_audit_records_configured_target_root_derivation() {
    let mut fixture = GitFixture::registered();
    fixture.configure_clippy(
        vec!["/bin/true".to_owned()],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let target_root = fixture.directory.path().join("cargo-targets");
    let (config, record) = fixture.runner_config(512 * 1_024);
    let config = config.with_cargo_target_root(&target_root);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("target-root fixture push completes");
    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
            &config,
        )
        .expect("target-root run completes");

    let canonical_checkout = fixture
        .checkout
        .canonicalize()
        .expect("mirror checkout canonicalizes");
    let digest = crate::sha256::digest_hex(canonical_checkout.as_os_str().as_bytes());
    let expected_target = target_root.join(format!("lane-gateway-{}", &digest[..16]));
    assert_eq!(
        result.cargo_target_dir.as_deref(),
        Some(expected_target.as_path())
    );
    assert!(
        fs::read_to_string(record)
            .expect("runner record is readable")
            .lines()
            .any(|line| line == format!("target={}", expected_target.display()))
    );
    let records = audit_records(&fixture.gateway, "lane-031");
    let audit_value = serde_json::to_value(records.last().expect("run audit record exists"))
        .expect("run audit record serializes");
    assert_eq!(
        audit_value["event"]["result"]["cargo_target_dir"],
        serde_json::json!(expected_target)
    );
}

/// Approval sends the exact immutable argv through the tier-two runner once,
/// consumes one run slot, publishes the proposal sequence to the worker, and
/// uses the roster runner's exact target-directory derivation for absent and
/// configured roots instead of an inherited Cargo target.
///
/// ´test:unit:approve-executes-exact-parked-argv´
#[test]
fn approve_executes_exact_parked_argv() {
    const CHILD_ENVIRONMENT: &str = "LANE_GATEWAY_PROPOSAL_TARGET_PIN_CHILD";
    const INHERITED_TARGET: &str = "/shared/cargo-target";

    if std::env::var_os(CHILD_ENVIRONMENT).is_none() {
        let output = Command::new(std::env::current_exe().expect("test executable is available"))
            .arg("--exact")
            .arg("tests::approve_executes_exact_parked_argv")
            .arg("--nocapture")
            .env(CHILD_ENVIRONMENT, "1")
            .env("CARGO_TARGET_DIR", INHERITED_TARGET)
            .output()
            .expect("isolated proposal target-directory test starts");
        assert!(
            output.status.success(),
            "isolated proposal target-directory test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    assert_eq!(
        std::env::var_os("CARGO_TARGET_DIR").as_deref(),
        Some(Path::new(INHERITED_TARGET).as_os_str())
    );
    assert_approved_proposal_target_dir(false, INHERITED_TARGET);
    assert_approved_proposal_target_dir(true, INHERITED_TARGET);
    approval_result_measures_queue_wait_to_runner_start();
}

/// An approval reports the interval from proposal intake to runner start,
/// within the clock observations bracketing queueing and the completed result.
///
/// # Panics
/// Panics only if fixture setup fails or queue and runner evidence disagree,
/// which a correctly recorded approval cannot arrange.
fn approval_result_measures_queue_wait_to_runner_start() {
    let fixture = GitFixture::registered();
    let (config, _) = fixture.runner_config(512 * 1_024);
    let config = config.with_poll_interval_millis(50);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("queue fixture push completes");
    let before_queue_unix_ms =
        crate::gateway::timestamp_unix_ms().expect("clock before queueing is readable");
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":2,"op":"propose","argv":["/bin/date","+%s%3N"],"reason":"measure runner start"}"#, &config)
        .expect("timed proposal enters the queue");
    let after_queue_unix_ms =
        crate::gateway::timestamp_unix_ms().expect("clock after queueing is readable");
    let proposal = fixture
        .gateway
        .load_open_proposal("lane-031", 2)
        .expect("common proposal is readable");
    assert!(
        proposal.queued_unix_ms <= after_queue_unix_ms,
        "queued clock {} exceeds clock after queueing {after_queue_unix_ms}",
        proposal.queued_unix_ms
    );
    // The queued proposal above is the publication event. Retain at least 120 ms
    // of residence on the program's clock so the minimum-wait assertion separates
    // an intake anchor from an approval anchor; load can only extend residence.
    let waiting = Instant::now();
    while crate::gateway::timestamp_unix_ms().expect("queue clock is readable")
        < after_queue_unix_ms + 120
    {
        assert!(
            waiting.elapsed() < LOADED_FIXTURE_WAIT,
            "queue clock did not advance"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let before_approval_unix_ms =
        crate::gateway::timestamp_unix_ms().expect("clock before approval is readable");
    let result = fixture
        .gateway
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect("timed approval completes");
    let after_result_unix_ms =
        crate::gateway::timestamp_unix_ms().expect("clock after result is readable");
    assert_eq!(result.verdict, ResultVerdict::Ok);
    let runner_unix_ms: u64 = result
        .stdout
        .trim()
        .parse()
        .expect("runner reports its start clock");
    let expected = runner_unix_ms.saturating_sub(proposal.queued_unix_ms);
    let observed_wait_ms = after_result_unix_ms.saturating_sub(before_queue_unix_ms);
    let minimum_wait_ms = before_approval_unix_ms.saturating_sub(proposal.queued_unix_ms);
    let queue_wait_ms = result.queue_wait_ms.expect("run carries queue wait");
    assert!(
        minimum_wait_ms <= queue_wait_ms,
        "minimum wait {minimum_wait_ms} exceeds recorded queue wait {queue_wait_ms}"
    );
    assert!(
        before_queue_unix_ms <= proposal.queued_unix_ms,
        "clock before queueing {before_queue_unix_ms} exceeds queued clock {}",
        proposal.queued_unix_ms
    );
    assert!(
        queue_wait_ms <= expected,
        "recorded queue wait {queue_wait_ms} exceeds runner observation {expected}"
    );
    assert!(
        expected <= observed_wait_ms,
        "runner observation {expected} exceeds observed bracket {observed_wait_ms}"
    );
    let audited = audit_records(&fixture.gateway, "lane-031")
        .into_iter()
        .find_map(|record| match record.event {
            AuditEvent::Result { result }
                if result.seq == Some(2) && result.operation == Some(Operation::Run) =>
            {
                Some(result)
            }
            _ => None,
        })
        .expect("run result is audited");
    assert_eq!(audited.queue_wait_ms, Some(queue_wait_ms));
}

fn assert_approved_proposal_target_dir(configured_root: bool, inherited_target: &str) {
    let fixture = GitFixture::registered();
    let script = fixture.write_package_script(
        "proposal-run.sh",
        "printf 'first=%s\\n' \"$1\"\nprintf 'second=%s\\n' \"$2\"\nexit 9\n",
    );
    let (config, record) = fixture.runner_config(512 * 1_024);
    let target_root = fixture.directory.path().join("cargo-targets");
    let (config, expected_target) = if configured_root {
        let canonical_checkout = fixture
            .checkout
            .canonicalize()
            .expect("proposal mirror checkout canonicalizes");
        let digest = crate::sha256::digest_hex(canonical_checkout.as_os_str().as_bytes());
        (
            config.with_cargo_target_root(&target_root),
            target_root.join(format!("lane-gateway-{}", &digest[..16])),
        )
    } else {
        (config, fixture.checkout.join("target"))
    };
    let push = fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("proposal fixture push completes");
    let commit = push
        .commit_id
        .expect("proposal fixture push returns a commit");
    let request = format!(
        r#"{{"schema":1,"seq":2,"op":"propose","argv":["/bin/sh","{script}","fixed value","--literal"],"reason":"exercise exact argv"}}"#
    );
    fixture
        .gateway
        .process_request("lane-031", &request, &config)
        .expect("proposal intake completes");
    write_park_marker(&fixture.gateway, "lane-031", 2, 600);
    fixture
        .gateway
        .reconcile_open_proposals(config.result_size_limit_bytes())
        .expect("proposal parking reconciles");
    let queue = fixture
        .gateway
        .proposals()
        .expect("parked proposal queue is readable");
    assert_eq!(queue.proposals.len(), 1);
    assert_eq!(queue.proposals[0].state, ProposalState::Parked);

    let result = fixture
        .gateway
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect("proposal approval executes");
    assert_approved_proposal_evidence(
        &fixture,
        &record,
        &expected_target,
        inherited_target,
        &commit,
        &script,
        &result,
    );
    let error = fixture
        .gateway
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect_err("a resolved proposal cannot execute twice");
    let GatewayError::ProposalNotPending = error else {
        panic!("repeat approval returned the wrong error");
    };
}

fn assert_approved_proposal_evidence(
    fixture: &GitFixture,
    record: &Path,
    expected_target: &Path,
    inherited_target: &str,
    commit: &str,
    script: &str,
    result: &crate::OperationResult,
) {
    assert_eq!(result.seq, Some(2));
    assert_eq!(result.operation, Some(Operation::Run));
    assert_eq!(result.verdict, ResultVerdict::Failed);
    assert_eq!(result.exit_code, 9);
    assert_eq!(result.stdout, "first=fixed value\nsecond=--literal\n");
    assert_eq!(result.commit_id.as_deref(), Some(commit));
    assert_eq!(result.cargo_target_dir.as_deref(), Some(expected_target));
    assert_ne!(
        result.cargo_target_dir.as_deref(),
        Some(Path::new(inherited_target))
    );
    let actual_record: Vec<_> = fs::read_to_string(record)
        .expect("proposal runner record is readable")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        actual_record,
        vec![
            "budget=600".to_owned(),
            format!("commit={commit}"),
            format!("remote={}", fixture.mirror.display()),
            format!("target={}", expected_target.display()),
            format!("argument={}", fixture.checkout.display()),
            "argument=/bin/sh".to_owned(),
            format!("argument={script}"),
            "argument=fixed value".to_owned(),
            "argument=--literal".to_owned(),
        ]
    );
    let published: crate::OperationResult = serde_json::from_str(
        &fs::read_to_string(fixture.result_path()).expect("approval result is published"),
    )
    .expect("approval result is machine-readable");
    assert_eq!(&published, result);
    assert_eq!(
        fixture
            .gateway
            .status()
            .expect("approval status is readable")
            .lanes[0]
            .runs_consumed,
        1
    );
    let records = audit_records(&fixture.gateway, "lane-031");
    records
        .iter()
        .find(|record| {
            matches!(
                &record.event,
                AuditEvent::Verdict {
                    actor: AuditActor::Orchestrator,
                    verdict: ProposalVerdict {
                        seq: 2,
                        decision: VerdictDecision::Approved,
                        ..
                    },
                }
            )
        })
        .expect("orchestrator approval is audited");
    let audited_result = records
        .iter()
        .find_map(|record| match &record.event {
            AuditEvent::Result { result }
                if result.seq == Some(2) && result.operation == Some(Operation::Run) =>
            {
                Some(result)
            }
            _ => None,
        })
        .expect("approved proposal result is audited");
    assert_eq!(
        audited_result.cargo_target_dir.as_deref(),
        Some(expected_target)
    );
}

/// Promotion derives a conservative name, preserves parked history, records
/// the registration change, and makes the exact argv immediately runnable.
/// A later derived-name collision leaves its proposal pending for `--as`.
///
/// ´test:unit:promotion-extends-roster-with-auditable-exact-argv´
#[test]
fn promotion_extends_roster_with_auditable_exact_argv() {
    let mut fixture = GitFixture::registered();
    let script =
        fixture.write_package_script("promoted-command.sh", "printf '%s=%s\\n' \"$1\" \"$2\"\n");
    fixture.registration.budgets = BudgetPolicy {
        run_cap: 20,
        cooldown_seconds: 0,
    };
    fixture
        .gateway
        .replace_registration(&fixture.registration)
        .expect("promotion fixture registration is updated");
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("promotion fixture push completes");
    let request = format!(
        r#"{{"schema":1,"seq":2,"op":"propose","argv":["/bin/sh","{script}","promoted","exact"],"reason":"reuse the exact formatter probe"}}"#
    );
    fixture
        .gateway
        .process_request("lane-031", &request, &config)
        .expect("promotable proposal is parked");
    let parked_before = fixture
        .gateway
        .proposal_bodies(Some("lane-031"))
        .expect("common proposal bodies");

    let approved = fixture
        .gateway
        .approve_proposal("lane-031", 2, true, None, &config)
        .expect("derived-name promotion succeeds");
    assert_eq!(approved.command.as_deref(), Some("bin-sh"));
    assert_eq!(approved.stdout, "promoted=exact\n");
    let registration = fixture
        .gateway
        .load_registration("lane-031")
        .expect("promoted registration is readable");
    let promoted = &registration.commands["bin-sh"];
    assert_eq!(
        promoted.argv,
        vec![
            "/bin/sh".to_owned(),
            script.clone(),
            "promoted".to_owned(),
            "exact".to_owned()
        ]
    );
    assert_eq!(promoted.wall_budget_seconds, 600);
    assert_eq!(
        fixture
            .gateway
            .proposal_bodies(Some("lane-031"))
            .expect("immutable common bodies"),
        parked_before
    );

    let rerun = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":3,"op":"run","command":"bin-sh"}"#,
            &config,
        )
        .expect("promoted command runs immediately");
    assert_eq!(rerun.verdict, ResultVerdict::Success);
    assert_eq!(rerun.stdout, "promoted=exact\n");

    let records = audit_records(&fixture.gateway, "lane-031");
    let first_change = records.iter().find_map(|record| match &record.event {
        AuditEvent::RegistrationChange {
            actor: AuditActor::Orchestrator,
            change,
        } if change.proposal_seq == 2 => Some(change),
        _ => None,
    });
    let first_change = first_change.expect("promotion change is audited");
    assert_eq!(first_change.command, "bin-sh");
    assert_eq!(first_change.argv, promoted.argv);

    assert_promotion_name_collision_requires_as(&fixture, &script, &config);
}

fn assert_promotion_name_collision_requires_as(
    fixture: &GitFixture,
    script: &str,
    config: &ServeConfig,
) {
    let colliding_request = format!(
        r#"{{"schema":1,"seq":4,"op":"propose","argv":["/bin/sh","{script}","copy","exact"],"reason":"second fixed probe"}}"#
    );
    fixture
        .gateway
        .process_request("lane-031", &colliding_request, config)
        .expect("colliding proposal is parked");
    let collision = fixture
        .gateway
        .approve_proposal("lane-031", 4, true, None, config)
        .expect_err("derived roster collision is refused");
    let GatewayError::PromotionNameCollision = collision else {
        panic!("derived-name collision returned the wrong error");
    };
    let pending = fixture
        .gateway
        .proposals()
        .expect("proposal queue is readable");
    assert_eq!(pending.proposals.len(), 1);
    assert_eq!(pending.proposals[0].seq, 4);
    let supplied = fixture
        .gateway
        .approve_proposal("lane-031", 4, true, Some("shell-copy"), config)
        .expect("explicit promotion name resolves the collision");
    assert_eq!(supplied.command.as_deref(), Some("shell-copy"));
    assert_eq!(supplied.stdout, "copy=exact\n");
    assert_eq!(
        fixture
            .gateway
            .proposals()
            .expect("resolved queue is readable")
            .proposals
            .len(),
        0
    );
}

/// The serve loop turns an elapsed attention window into durable parked state
/// without writing a terminal verdict or requiring a replacement sequence.
///
/// ´test:unit:proposal-timeout-parks-without-terminal-resolution´
#[test]
fn proposal_timeout_parks_without_terminal_resolution() {
    let mut fixture = Fixture::registered();
    fixture.registration.proposal_timeout_seconds = 1;
    fixture
        .gateway
        .replace_registration(&fixture.registration)
        .expect("timeout fixture registration is updated");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("timeout protocol directory is created");
    let request_path = lane_dir.join("request.json");
    let result_path = lane_dir.join("result.json");
    fs::write(
        &request_path,
        r#"{"schema":1,"seq":1,"op":"propose","argv":["cargo","metadata"],"reason":"first attempt"}"#,
    )
    .expect("timeout proposal is written");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let pending = wait_for_result_verdict(&result_path, 1, ResultVerdict::Pending);
    assert_eq!(pending.proposal_timeout_seconds, Some(1));
    let parked = wait_for_result_verdict(&result_path, 1, ResultVerdict::Parked);
    assert_eq!(parked.proposal_timeout_seconds, Some(1));
    let canonical =
        wait_for_result_verdict(&lane_dir.join("proposals/1.json"), 1, ResultVerdict::Parked);
    assert_eq!(canonical, parked);
    let queue = fixture
        .gateway
        .proposals()
        .expect("parked queue is readable");
    assert_eq!(queue.proposals.len(), 1);
    assert_eq!(queue.proposals[0].seq, 1);
    assert_eq!(queue.proposals[0].state, ProposalState::Parked);
    assert!(queue.proposals[0].parked_unix_ms.is_some());
    assert!(
        fixture
            .gateway
            .state_dir()
            .join("proposal-parks/lane-031/1.json")
            .is_file()
    );
    assert!(
        !fixture
            .gateway
            .state_dir()
            .join("proposal-verdicts/lane-031/1.json")
            .exists()
    );
    audit_records(&fixture.gateway, "lane-031")
        .iter()
        .find(|record| {
            matches!(
                &record.event,
                AuditEvent::ProposalParked { park } if park.seq == 1
            )
        })
        .expect("gateway park transition is audited");

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// A parked proposal survives recreation of the gateway value, repairs its
/// projection, and executes its original sequence no more than once.
///
/// ´test:unit:parked-proposal-survives-gateway-restart-and-is-approvable´
#[test]
fn parked_proposal_survives_gateway_restart_and_is_approvable() {
    let fixture = GitFixture::registered();
    let script = fixture.write_package_script("restart-proposal.sh", "printf 'restarted\\n'\n");
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("restart fixture push completes");
    let request = format!(
        r#"{{"schema":1,"seq":2,"op":"propose","argv":["/bin/sh","{script}"],"reason":"survive restart"}}"#
    );
    fixture
        .gateway
        .process_request("lane-031", &request, &config)
        .expect("restart fixture proposal is accepted");
    write_park_marker(&fixture.gateway, "lane-031", 2, 600);

    let restarted = configured_gateway(fixture.gateway.state_dir().to_path_buf());
    restarted
        .reconcile_open_proposals(config.result_size_limit_bytes())
        .expect("restart reconciliation succeeds");
    let parked_path = fixture.registration.worktree.join(".lane/proposals/2.json");
    let parked = wait_for_result_verdict(&parked_path, 2, ResultVerdict::Parked);
    assert_eq!(parked.schema, 2);
    let parked_bytes = fs::read(&parked_path).expect("parked projection bytes are readable");

    let approved = restarted
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect("restarted gateway approves the original sequence");
    assert_eq!(approved.seq, Some(2));
    assert_eq!(approved.verdict, ResultVerdict::Ok);
    assert_eq!(approved.stdout, "restarted\n");
    assert_eq!(wait_for_result_seq(&parked_path, 2), approved);
    let repeated = restarted
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect_err("the original sequence cannot execute twice");
    assert!(matches!(repeated, GatewayError::ProposalNotPending));

    restarted
        .process_request("lane-031", &proposal_request(3, "deny bytes"), &config)
        .expect("denial acceptance proposal is accepted");
    restarted
        .deny_proposal("lane-031", 3, "outside lane scope")
        .expect("denial acceptance proposal is denied");
    let denied_bytes = fs::read(fixture.registration.worktree.join(".lane/proposals/3.json"))
        .expect("denied projection bytes are readable");
    restarted
        .process_request("lane-031", &proposal_request(4, "expiry bytes"), &config)
        .expect("expiry acceptance proposal is accepted");
    restarted
        .abandon_proposal("lane-031", 4, "different approach")
        .expect("expiry acceptance proposal is abandoned");
    let expired_bytes = fs::read(fixture.registration.worktree.join(".lane/proposals/4.json"))
        .expect("expired projection bytes are readable");
    let parked_verdict: &[u8] = b"\"verdict\":\"parked\"";
    let denied_verdict: &[u8] = b"\"verdict\":\"denied\"";
    let expired_verdict: &[u8] = b"\"verdict\":\"expired\"";
    assert!(
        parked_bytes
            .windows(parked_verdict.len())
            .any(|bytes| bytes == parked_verdict)
    );
    assert!(
        denied_bytes
            .windows(denied_verdict.len())
            .any(|bytes| bytes == denied_verdict)
    );
    assert!(
        expired_bytes
            .windows(expired_verdict.len())
            .any(|bytes| bytes == expired_verdict)
    );
    assert_ne!(parked_bytes, denied_bytes);
    assert_ne!(denied_bytes, expired_bytes);
}

/// Queue output preserves lane-and-sequence ordering while distinguishing an
/// inside-window pending entry from an explicitly marked parked entry.
///
/// ´test:unit:proposal-queue-lists-pending-and-parked´
#[test]
fn proposal_queue_lists_pending_and_parked() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    for (seq, reason) in [(1, "park this"), (2, "still pending")] {
        fixture
            .gateway
            .process_request("lane-031", &proposal_request(seq, reason), &config)
            .expect("queue proposal is accepted");
    }
    write_park_marker(&fixture.gateway, "lane-031", 1, 600);

    let queue = fixture
        .gateway
        .proposals()
        .expect("mixed queue is readable");
    assert_eq!(queue.schema, 2);
    assert_eq!(queue.proposals.len(), 2);
    assert_eq!(queue.proposals[0].seq, 1);
    assert_eq!(queue.proposals[0].state, ProposalState::Parked);
    assert_eq!(queue.proposals[0].parked_unix_ms, Some(123));
    assert_eq!(queue.proposals[1].seq, 2);
    assert_eq!(queue.proposals[1].state, ProposalState::Pending);
    assert_eq!(queue.proposals[1].parked_unix_ms, None);
}

/// Restart reconciliation repairs a marker whose audit and projections were
/// interrupted, then seeds the accepted request instead of publishing replay.
///
/// ´test:unit:restart-repairs-park-projection-without-replay-refusal´
#[test]
fn restart_repairs_park_projection_without_replay_refusal() {
    let fixture = Fixture::registered();
    let source = proposal_request(1, "repair after crash");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(10);
    fixture
        .gateway
        .process_request("lane-031", &source, &config)
        .expect("repair proposal is accepted");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("repair protocol directory is created");
    fs::write(lane_dir.join("request.json"), source).expect("accepted request remains present");
    write_park_marker(&fixture.gateway, "lane-031", 1, 600);
    assert!(!lane_dir.join("proposals/1.json").exists());

    let restarted = configured_gateway(fixture.gateway.state_dir().to_path_buf());
    let restart_config = serve_config(&restarted).with_poll_interval_millis(10);
    let shutdown = restart_config.shutdown_file().to_path_buf();
    let server = start_server(restarted.clone(), restart_config);
    let parked =
        wait_for_result_verdict(&lane_dir.join("proposals/1.json"), 1, ResultVerdict::Parked);
    assert_eq!(
        wait_for_result_verdict(&lane_dir.join("result.json"), 1, ResultVerdict::Parked),
        parked
    );
    thread::sleep(Duration::from_millis(30));
    assert!(!audit_records(&restarted, "lane-031").iter().any(|record| {
        matches!(
            &record.event,
            AuditEvent::Refusal { refusal }
                if refusal.rule == RefusalRule::SequenceReplay
        )
    }));
    fs::write(shutdown, b"stop\n").expect("repair server shutdown is written");
    server
        .join()
        .expect("repair serve thread joins")
        .expect("repair serve loop shuts down");
    restarted
        .reconcile_open_proposals(512 * 1_024)
        .expect("repeat reconciliation remains idempotent");
    let park_events = audit_records(&restarted, "lane-031")
        .iter()
        .filter(
            |record| matches!(&record.event, AuditEvent::ProposalParked { park } if park.seq == 1),
        )
        .count();
    assert_eq!(park_events, 1);
}

/// Explicit abandonment is the only ordinary terminal expiry path and emits
/// its typed reason to state, audit, and both worker projections.
///
/// ´test:unit:explicit-abandon-expires-open-proposal´
#[test]
fn explicit_abandon_expires_open_proposal() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "try once"), &config)
        .expect("abandonment proposal is accepted");
    let expired = fixture
        .gateway
        .abandon_proposal("lane-031", 1, "lane chose a different approach")
        .expect("explicit abandonment succeeds");
    assert_eq!(expired.verdict, ResultVerdict::Expired);
    let refusal = expired.refusal.as_ref().expect("expiry refusal is present");
    assert_eq!(refusal.rule, RefusalRule::ProposalExpired);
    assert_eq!(refusal.expiry_reason, Some(ProposalExpiryReason::Abandoned));
    assert_eq!(
        refusal.reason.as_deref(),
        Some("lane chose a different approach")
    );
    assert_eq!(
        fixture
            .gateway
            .proposals()
            .expect("queue is readable")
            .proposals
            .len(),
        0
    );
    assert_eq!(
        wait_for_result_verdict(
            &fixture.registration.worktree.join(".lane/proposals/1.json"),
            1,
            ResultVerdict::Expired,
        ),
        expired
    );
}

/// Deregistration preserves the live queue until a trusted explicit action
/// resolves every pending or parked proposal.
///
/// ´test:unit:deregister-refuses-open-proposals´
#[test]
fn deregister_refuses_open_proposals() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "must resolve"), &config)
        .expect("guard proposal is accepted");
    let error = fixture
        .gateway
        .deregister("lane-031")
        .expect_err("open proposal blocks deregistration");
    assert!(matches!(error, GatewayError::OpenProposals));
    let closed = fixture
        .gateway
        .abandon_proposal("lane-031", 1, "lane closed")
        .expect("explicit closeout abandonment succeeds");
    assert_eq!(
        closed
            .refusal
            .expect("closeout refusal is present")
            .expiry_reason,
        Some(ProposalExpiryReason::LaneClosed)
    );
    fixture
        .gateway
        .deregister("lane-031")
        .expect("resolved lane deregisters");
}

/// A stored timeout decision is outside the current verdict vocabulary and
/// refuses when the proposal queue reads the recorded resolution.
///
/// ´test:unit:timed-out-verdict-state-refuses-as-unknown-decision´
#[test]
fn timed_out_verdict_state_refuses_as_unknown_decision() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "verdict shape"), &config)
        .expect("proposal is accepted");
    let path = fixture
        .gateway
        .state_dir()
        .join("proposal-verdicts/lane-031/1.json");
    fs::create_dir_all(path.parent().expect("verdict has a parent"))
        .expect("verdict directory is created");
    let source = r#"{"schema":1,"actor":"gateway","verdict":{"seq":1,"decision":"timed_out","wall_millis":1000},"resolved_unix_ms":123}"#;
    fs::write(&path, source).expect("verdict is written");

    let error = fixture
        .gateway
        .proposals()
        .expect_err("timed_out decision is refused by the queue reader");
    assert!(matches!(
        error,
        GatewayError::CorruptState("proposal_verdict")
    ));
}

/// Pending, parked, denied, and expired proposal statuses remain separate
/// top-level worker verdicts rather than prose or generic refusal variants.
///
/// ´test:unit:proposal-result-verdicts-are-distinct´
#[test]
fn proposal_result_verdicts_are_distinct() {
    let pending = crate::OperationResult::pending_proposal(17, 1, 1_800);
    let parked = crate::OperationResult::parked_proposal(17, 1, 1_800);
    let denied = crate::OperationResult::denied_proposal(17, 1, "outside lane scope");
    let expired = crate::OperationResult::expired_proposal(
        17,
        1,
        "lane chose a different approach",
        ProposalExpiryReason::Abandoned,
    );
    assert_eq!(pending.verdict, ResultVerdict::Pending);
    assert_eq!(parked.verdict, ResultVerdict::Parked);
    assert_eq!(denied.verdict, ResultVerdict::Denied);
    assert_eq!(expired.verdict, ResultVerdict::Expired);
    assert_eq!(pending.exit_code, 0);
    assert_eq!(parked.exit_code, 0);
    assert_eq!(denied.exit_code, 1);
    assert_eq!(expired.exit_code, 1);
}

/// Schema-two serialization emits the ratified parked, denied, and expired
/// projection shapes byte for byte for fixed measured values.
///
/// ´test:unit:schema-two-proposal-result-json-is-exact´
#[test]
fn schema_two_proposal_result_json_is_exact() {
    let parked = crate::OperationResult::parked_proposal(17, 1, 1_800);
    assert_eq!(
        serde_json::to_string(&parked).expect("parked result serializes"),
        r#"{"schema":2,"seq":17,"operation":"propose","exit_code":0,"wall_millis":1,"verdict":"parked","proposal_timeout_seconds":1800,"stdout":"","stderr":""}"#
    );
    let denied = crate::OperationResult::denied_proposal(17, 1, "outside lane scope");
    assert_eq!(
        serde_json::to_string(&denied).expect("denied result serializes"),
        r#"{"schema":2,"seq":17,"operation":"propose","exit_code":1,"wall_millis":1,"verdict":"denied","refusal":{"schema":2,"rule":"proposal_denied","message":"orchestrator denied the proposed command","seq":17,"reason":"outside lane scope"},"stdout":"","stderr":""}"#
    );
    let expired = crate::OperationResult::expired_proposal(
        17,
        1,
        "lane chose a different approach",
        ProposalExpiryReason::Abandoned,
    );
    assert_eq!(
        serde_json::to_string(&expired).expect("expired result serializes"),
        r#"{"schema":2,"seq":17,"operation":"propose","exit_code":1,"wall_millis":1,"verdict":"expired","refusal":{"schema":2,"rule":"proposal_expired","message":"proposal was explicitly expired","seq":17,"reason":"lane chose a different approach","expiry_reason":"abandoned"},"stdout":"","stderr":""}"#
    );
}

/// A push projection carries the schema-two stamp in its exact serialized
/// worker-facing shape.
///
/// ´test:unit:push-result-projection-stamps-schema-two´
#[test]
fn push_result_projection_stamps_schema_two() {
    let directory = TestDirectory::new();
    let result = crate::OperationResult::success(
        17,
        Operation::Push,
        1,
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
        String::new(),
        String::new(),
    );
    crate::serve::write_result(directory.path(), &result, 512 * 1_024)
        .expect("push projection is written");
    let bytes = fs::read(directory.path().join(".lane/result.json"))
        .expect("push projection bytes are readable");
    assert!(
        bytes
            .windows(b"\"schema\":2".len())
            .any(|window| window == b"\"schema\":2")
    );
    assert_eq!(
        bytes,
        br#"{"schema":2,"seq":17,"operation":"push","exit_code":0,"wall_millis":1,"verdict":"success","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","stdout":"","stderr":""}
"#
    );
}

/// A registered-run projection carries the schema-two stamp in its exact
/// serialized worker-facing shape.
///
/// ´test:unit:run-result-projection-stamps-schema-two´
#[test]
fn run_result_projection_stamps_schema_two() {
    let directory = TestDirectory::new();
    let mut result = crate::OperationResult::completed_run(
        18,
        2,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        0,
        "green\n".to_owned(),
        String::new(),
    );
    result.command = Some("test".to_owned());
    result.queue_wait_ms = Some(7);
    crate::serve::write_result(directory.path(), &result, 512 * 1_024)
        .expect("run projection is written");
    let bytes = fs::read(directory.path().join(".lane/result.json"))
        .expect("run projection bytes are readable");
    assert!(
        bytes
            .windows(b"\"schema\":2".len())
            .any(|window| window == b"\"schema\":2")
    );
    assert_eq!(
        bytes,
        br#"{"schema":2,"seq":18,"operation":"run","command":"test","exit_code":0,"wall_millis":2,"queue_wait_ms":7,"verdict":"success","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","stdout":"green\n","stderr":""}
"#
    );
}

/// Proposal acknowledgement and verdict projections carry the schema-two
/// stamp in both the current and sequence-stable result channels.
///
/// ´test:unit:proposal-result-projections-stamp-schema-two´
#[test]
fn proposal_result_projections_stamp_schema_two() {
    let directory = TestDirectory::new();
    let results = [
        crate::OperationResult::pending_proposal(19, 3, 1_800),
        crate::OperationResult::parked_proposal(19, 4, 1_800),
        crate::OperationResult::denied_proposal(19, 5, "outside lane scope"),
        crate::OperationResult::expired_proposal(
            19,
            6,
            "lane closed",
            ProposalExpiryReason::LaneClosed,
        ),
    ];
    for result in results {
        crate::serve::write_result(directory.path(), &result, 512 * 1_024)
            .expect("current proposal projection is written");
        crate::serve::write_proposal_result(directory.path(), 19, &result, 512 * 1_024)
            .expect("stable proposal projection is written");
        for path in [
            directory.path().join(".lane/result.json"),
            directory.path().join(".lane/proposals/19.json"),
        ] {
            let bytes = fs::read(path).expect("proposal projection bytes are readable");
            assert!(
                bytes
                    .windows(b"\"schema\":2".len())
                    .any(|window| window == b"\"schema\":2")
            );
        }
    }
}

/// A policy denial has a terminal denied verdict and no timeout or expiry
/// companion that could invite a blind retry.
///
/// ´test:unit:denied-verdict-is-not-retryable-timeout´
#[test]
fn denied_verdict_is_not_retryable_timeout() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "policy check"), &config)
        .expect("denial proposal is accepted");
    let denied = fixture
        .gateway
        .deny_proposal("lane-031", 1, "outside lane scope")
        .expect("policy denial succeeds");
    assert_eq!(denied.verdict, ResultVerdict::Denied);
    assert_eq!(denied.proposal_timeout_seconds, None);
    let refusal = denied.refusal.expect("denial refusal is present");
    assert_eq!(refusal.rule, RefusalRule::ProposalDenied);
    assert_eq!(refusal.timeout_seconds, None);
    assert_eq!(refusal.expiry_reason, None);
}

/// An explicitly expired sequence is terminal while the still-registered lane
/// may submit a genuinely fresh proposal sequence for the same argv.
///
/// ´test:unit:expired-verdict-allows-fresh-sequence-when-lane-remains-open´
#[test]
fn expired_verdict_allows_fresh_sequence_when_lane_remains_open() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "first approach"), &config)
        .expect("first proposal is accepted");
    let expired = fixture
        .gateway
        .abandon_proposal("lane-031", 1, "different approach")
        .expect("first proposal is abandoned");
    assert_eq!(expired.verdict, ResultVerdict::Expired);
    let fresh = fixture
        .gateway
        .process_request("lane-031", &proposal_request(2, "fresh approach"), &config)
        .expect("fresh proposal is accepted");
    assert_eq!(fresh.verdict, ResultVerdict::Pending);
    let queue = fixture
        .gateway
        .proposals()
        .expect("fresh queue is readable");
    assert_eq!(queue.proposals.len(), 1);
    assert_eq!(queue.proposals[0].seq, 2);
}

/// Parking preserves the original open sequence, which remains directly
/// deniable without a replacement request.
///
/// ´test:unit:parked-verdict-keeps-original-sequence-open´
#[test]
fn parked_verdict_keeps_original_sequence_open() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "keep open"), &config)
        .expect("parkable proposal is accepted");
    write_park_marker(&fixture.gateway, "lane-031", 1, 600);
    fixture
        .gateway
        .reconcile_open_proposals(512 * 1_024)
        .expect("parked proposal reconciles");
    let parked = wait_for_result_verdict(
        &fixture.registration.worktree.join(".lane/proposals/1.json"),
        1,
        ResultVerdict::Parked,
    );
    assert_eq!(parked.seq, Some(1));
    let denied = fixture
        .gateway
        .deny_proposal("lane-031", 1, "reviewed policy choice")
        .expect("the original parked sequence remains deniable");
    assert_eq!(denied.seq, Some(1));
    assert_eq!(denied.verdict, ResultVerdict::Denied);
}

fn mutated_writer_audit_refuses(event_kind: &str, mutate: impl FnOnce(&mut serde_json::Value)) {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    let result = fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":1,"op":"run","command":"missing-roster-entry"}"#,
            &config,
        )
        .expect("production request reader records a refusal");
    fixture
        .gateway
        .append_audit(
            "lane-031",
            AuditEvent::Result {
                result: Box::new(result),
            },
        )
        .expect("production audit writer records the returned result");
    let path = fixture.gateway.state_dir().join("audit/lane-031.jsonl");
    let source = fs::read_to_string(&path).expect("writer audit is readable");
    let mut rows: Vec<serde_json::Value> = source
        .lines()
        .map(|line| serde_json::from_str(line).expect("writer line is JSON"))
        .collect();
    let index = rows
        .iter()
        .position(|row| row["event"]["kind"] == event_kind)
        .expect("writer emitted the chosen event");
    mutate(&mut rows[index]["event"]);
    let mut changed = rows
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    changed.push('\n');
    fs::write(&path, changed).expect("mutated audit is written");

    let error = fixture
        .gateway
        .audit_records("lane-031")
        .expect_err("obsolete event shape is refused");
    let GatewayError::CorruptAudit {
        path: failed_path,
        line,
        invariant,
    } = &error
    else {
        panic!("audit reader returned the wrong error: {error:?}");
    };
    assert_eq!(failed_path, &path);
    assert_eq!(*line, index + 1);
    assert_eq!(
        *invariant,
        "line is not valid JSON for the audit record schema"
    );
}

/// The current refusal shape has no later-tier marker.
///
/// ´test:unit:refusal-with-tier-refuses-in-audit´
#[test]
fn refusal_with_tier_refuses_in_audit() {
    mutated_writer_audit_refuses("refusal", |event| {
        event["refusal"]["tier"] = serde_json::json!("tier2_run");
    });
}

/// The retired unserved rule is outside the current refusal vocabulary.
///
/// ´test:unit:unserved-refusal-rule-refuses-in-audit´
#[test]
fn unserved_refusal_rule_refuses_in_audit() {
    mutated_writer_audit_refuses("refusal", |event| {
        event["refusal"]["rule"] = serde_json::json!("not_yet_served");
    });
}

/// A nested refusal schema outside the current result schema is refused by
/// the immutable audit reader.
///
/// ´test:unit:nested-refusal-schema-refuses-in-audit´
#[test]
fn nested_refusal_schema_refuses_in_audit() {
    mutated_writer_audit_refuses("result", |event| {
        event["result"]["refusal"]["schema"] = serde_json::json!(1);
    });
}

/// The result writer's verdict is required when an audit result is read.
///
/// ´test:unit:result-without-verdict-refuses-in-audit´
#[test]
fn result_without_verdict_refuses_in_audit() {
    mutated_writer_audit_refuses("result", |event| {
        event["result"]
            .as_object_mut()
            .expect("writer result is an object")
            .remove("verdict");
    });
}

/// The result writer's stdout is required when an audit result is read.
///
/// ´test:unit:result-without-stdout-refuses-in-audit´
#[test]
fn result_without_stdout_refuses_in_audit() {
    mutated_writer_audit_refuses("result", |event| {
        event["result"]
            .as_object_mut()
            .expect("writer result is an object")
            .remove("stdout");
    });
}

/// The result writer's stderr is required when an audit result is read.
///
/// ´test:unit:result-without-stderr-refuses-in-audit´
#[test]
fn result_without_stderr_refuses_in_audit() {
    mutated_writer_audit_refuses("result", |event| {
        event["result"]
            .as_object_mut()
            .expect("writer result is an object")
            .remove("stderr");
    });
}

/// Only the lane or orchestrator can author a verdict audit event.
///
/// ´test:unit:gateway-actor-refuses-in-audit´
#[test]
fn gateway_actor_refuses_in_audit() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "actor shape"), &config)
        .expect("proposal is queued");
    fixture
        .gateway
        .deny_proposal("lane-031", 1, "policy")
        .expect("verdict writer succeeds");
    let path = fixture.gateway.state_dir().join("audit/lane-031.jsonl");
    let source = fs::read_to_string(&path).expect("writer audit is readable");
    let mut rows: Vec<serde_json::Value> = source
        .lines()
        .map(|line| serde_json::from_str(line).expect("writer line is JSON"))
        .collect();
    let index = rows
        .iter()
        .position(|row| row["event"]["kind"] == "verdict")
        .expect("writer emitted a verdict");
    rows[index]["event"]["actor"] = serde_json::json!("gateway");
    let mut changed = rows
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    changed.push('\n');
    fs::write(&path, changed).expect("actor-mutated audit is written");
    let error = fixture
        .gateway
        .audit_records("lane-031")
        .expect_err("gateway actor is refused");
    assert!(matches!(
        error,
        GatewayError::CorruptAudit {
            line,
            invariant: "line is not valid JSON for the audit record schema",
            ..
        } if line == index + 1
    ));
}

/// The stored verdict writer always records its wall measurement.
///
/// ´test:unit:stored-verdict-without-wall-refuses´
#[test]
fn stored_verdict_without_wall_refuses() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "wall shape"), &config)
        .expect("proposal is queued");
    fixture
        .gateway
        .deny_proposal("lane-031", 1, "policy")
        .expect("verdict writer succeeds");
    let path = fixture
        .gateway
        .state_dir()
        .join("proposal-verdicts/lane-031/1.json");
    let mut row: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("writer verdict is readable"))
            .expect("writer verdict is JSON");
    row["verdict"]
        .as_object_mut()
        .expect("writer verdict is an object")
        .remove("wall_millis");
    fs::write(&path, row.to_string()).expect("verdict without wall is written");
    let error = fixture
        .gateway
        .proposals()
        .expect_err("stored verdict without wall is refused");
    assert!(matches!(
        error,
        GatewayError::CorruptState("proposal_verdict")
    ));
}

/// A schema-one line appended to a real audit is refused with its file,
/// one-based line number, and audit-schema invariant.
///
/// ´test:unit:schema-one-audit-line-refuses-with-file-line-and-invariant´
#[test]
fn schema_one_audit_line_refuses_with_file_line_and_invariant() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "audit shape"), &config)
        .expect("real audit is written");
    let audit_path = fixture.gateway.state_dir().join("audit/lane-031.jsonl");
    let mut source = fs::read_to_string(&audit_path).expect("new audit is readable");
    let offending_line = source.lines().count() + 1;
    let first = source.lines().next().expect("real audit has a line");
    let mut record: serde_json::Value = serde_json::from_str(first).expect("real line is JSON");
    record["schema"] = serde_json::json!(1);
    source.push_str(&record.to_string());
    source.push('\n');
    fs::write(&audit_path, source).expect("schema-one audit line is appended");

    let error = fixture
        .gateway
        .audit_records("lane-031")
        .expect_err("schema-one audit line is refused");
    let GatewayError::CorruptAudit {
        path,
        line,
        invariant,
    } = &error
    else {
        panic!("schema-one audit returned the wrong error: {error:?}");
    };
    assert_eq!(path, &audit_path);
    assert_eq!(*line, offending_line);
    assert_eq!(*invariant, "audit schema is not the current schema");
    assert!(
        error
            .to_string()
            .contains(&format!("{}:{offending_line}", audit_path.display()))
    );
}

/// Immutable proposal bodies keep their current schema-one shape.
///
/// ´test:unit:schema-one-proposal-body-remains-readable´
#[test]
fn schema_one_proposal_body_remains_readable() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "proposal shape"), &config)
        .expect("proposal is accepted");
    let bodies = fixture
        .gateway
        .proposal_bodies(Some("lane-031"))
        .expect("current proposal body is readable");
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0].schema, 1);
    assert_eq!(bodies[0].seq, 1);
}

/// A worker's malformed, schema-less, non-UTF-8, or unreadable projection is
/// replaced from terminal evidence when withdrawal reaches the live serve.
///
/// ´test:unit:withdraw-repairs-worker-result-projection-and-serve-continues´
#[test]
fn withdraw_repairs_worker_result_projection_and_serve_continues() {
    #[derive(Clone, Copy)]
    enum ProjectionDefect {
        InvalidJson,
        MissingSchema,
        InvalidUtf8,
        Unreadable,
    }

    for defect in [
        ProjectionDefect::InvalidJson,
        ProjectionDefect::MissingSchema,
        ProjectionDefect::InvalidUtf8,
        ProjectionDefect::Unreadable,
    ] {
        let fixture = Fixture::registered();
        let config = serve_config(&fixture.gateway).with_poll_interval_millis(5);
        fixture
            .gateway
            .process_request(
                "lane-031",
                &proposal_request(1, "withdraw after projection tampering"),
                &config,
            )
            .expect("proposal is queued");
        let directory = fixture.registration.worktree.join(".lane");
        let result_path = directory.join("result.json");
        let gateway = fixture.gateway;
        let server = start_server(gateway.clone(), config.clone());
        let pending = wait_for_result_seq(&result_path, 1);
        assert_eq!(pending.verdict, ResultVerdict::Pending);
        let expected_reason = match defect {
            ProjectionDefect::InvalidJson => {
                fs::write(&result_path, b"{invalid").expect("invalid JSON is written");
                ResultProjectionReplacementReason::InvalidShape
            }
            ProjectionDefect::MissingSchema => {
                let mut value = serde_json::to_value(&pending).expect("pending result encodes");
                value
                    .as_object_mut()
                    .expect("result is an object")
                    .remove("schema");
                fs::write(
                    &result_path,
                    serde_json::to_vec(&value).expect("schema-less result encodes"),
                )
                .expect("schema-less result is written");
                ResultProjectionReplacementReason::InvalidShape
            }
            ProjectionDefect::InvalidUtf8 => {
                fs::write(&result_path, [0xff, 0xfe]).expect("non-UTF-8 result is written");
                ResultProjectionReplacementReason::InvalidShape
            }
            ProjectionDefect::Unreadable => {
                fs::set_permissions(&result_path, fs::Permissions::from_mode(0o000))
                    .expect("result is made unreadable");
                if fs::read(&result_path).is_ok() {
                    std::io::stderr().write_all(b"SKIP withdraw_repairs_worker_result_projection_and_serve_continues: root can read mode-000 projection\n")
                        .expect("named skip is printed");
                    fs::set_permissions(&result_path, fs::Permissions::from_mode(0o600))
                        .expect("result permissions are restored");
                    fs::write(config.shutdown_file(), b"stop").expect("shutdown is requested");
                    join_server_bounded(server).expect("serve stops cleanly");
                    continue;
                }
                ResultProjectionReplacementReason::Unreadable
            }
        };
        fs::write(
            directory.join("request.json"),
            r#"{"schema":1,"seq":2,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#,
        )
        .expect("withdraw request is published");

        let acknowledgement = wait_for_result_seq(&result_path, 2);
        assert_eq!(acknowledgement.verdict, ResultVerdict::Withdrawn);
        let terminal = wait_for_result_verdict(
            &directory.join("proposals/1.json"),
            1,
            ResultVerdict::Withdrawn,
        );
        assert_eq!(terminal.schema, crate::types::RESULT_SCHEMA);
        fs::write(config.shutdown_file(), b"stop").expect("shutdown is requested");
        join_server_bounded(server).expect("serve continues and stops cleanly");
        let repairs = audit_records(&gateway, "lane-031")
            .into_iter()
            .filter(|record| {
                matches!(
                    &record.event,
                    AuditEvent::ResultProjectionReplaced { seq: 1, reason }
                        if reason == &expected_reason
                )
            })
            .count();
        assert_eq!(repairs, 1);
    }
}

/// Startup reconciliation replaces a worker's wrong-schema projection from
/// the terminal audit and continues to serve a later request.
///
/// ´test:unit:startup-reconcile-repairs-schema-one-result-projection´
#[test]
fn startup_reconcile_repairs_schema_one_result_projection() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(5);
    fixture
        .gateway
        .process_request(
            "lane-031",
            &proposal_request(1, "terminal evidence"),
            &config,
        )
        .expect("proposal is queued");
    fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#,
            &config,
        )
        .expect("proposal is withdrawn");
    let directory = fixture.registration.worktree.join(".lane");
    let result_path = directory.join("result.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&result_path).expect("terminal result is readable"))
            .expect("terminal result is JSON");
    value["schema"] = serde_json::json!(1);
    fs::write(
        &result_path,
        serde_json::to_vec(&value).expect("row encodes"),
    )
    .expect("schema-one projection is written");

    let restarted = configured_gateway(fixture.gateway.state_dir().to_path_buf());
    let server = start_server(restarted.clone(), config.clone());
    let started = Instant::now();
    loop {
        if let Ok(source) = fs::read_to_string(&result_path)
            && let Ok(result) = serde_json::from_str::<crate::OperationResult>(&source)
            && result.schema == crate::types::RESULT_SCHEMA
            && result.seq == Some(1)
        {
            break;
        }
        assert!(
            started.elapsed() < FIXTURE_WAIT,
            "startup did not repair projection"
        );
        thread::sleep(Duration::from_millis(5));
    }
    fs::write(
        directory.join("request.json"),
        proposal_request(3, "serve continues"),
    )
    .expect("later request is published");
    let later = wait_for_result_seq(&result_path, 3);
    assert_eq!(later.verdict, ResultVerdict::Pending);
    fs::write(config.shutdown_file(), b"stop").expect("shutdown is requested");
    join_server_bounded(server).expect("restarted serve stops cleanly");
    let repairs = audit_records(&restarted, "lane-031")
        .into_iter()
        .filter(|record| {
            matches!(
                &record.event,
                AuditEvent::ResultProjectionReplaced { seq: 1, reason }
                    if reason == &ResultProjectionReplacementReason::WrongSchema
            )
        })
        .count();
    assert_eq!(repairs, 1);
}

/// A wrong nested refusal schema cannot decode as a worker projection, so
/// terminal reconciliation restores the current result and audits the repair.
///
/// ´test:unit:nested-refusal-schema-repairs-worker-projection´
#[test]
fn nested_refusal_schema_repairs_worker_projection() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "nested shape"), &config)
        .expect("proposal is queued");
    fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#,
            &config,
        )
        .expect("proposal is withdrawn");
    let path = fixture.registration.worktree.join(".lane/result.json");
    let writer_result = crate::OperationResult::denied_proposal(1, 1, "policy");
    crate::serve::write_result(&fixture.registration.worktree, &writer_result, 512 * 1_024)
        .expect("production projection writer succeeds");
    let mut row: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("writer projection is readable"))
            .expect("writer projection is JSON");
    row["refusal"]["schema"] = serde_json::json!(1);
    fs::write(&path, row.to_string()).expect("wrong nested schema is written");
    assert!(
        serde_json::from_slice::<crate::OperationResult>(
            &fs::read(&path).expect("worker projection is readable")
        )
        .is_err()
    );

    fixture
        .gateway
        .reconcile_open_proposals(512 * 1_024)
        .expect("terminal reconciliation repairs worker projection");
    let repaired = wait_for_result_verdict(&path, 1, ResultVerdict::Withdrawn);
    assert_eq!(repaired.schema, crate::types::RESULT_SCHEMA);
    let repairs = audit_records(&fixture.gateway, "lane-031")
        .into_iter()
        .filter(|record| {
            matches!(
                record.event,
                AuditEvent::ResultProjectionReplaced {
                    seq: 1,
                    reason: crate::types::ResultProjectionReplacementReason::InvalidShape,
                }
            )
        })
        .count();
    assert_eq!(repairs, 1);
}

/// A registration-change audit line must name its actor.
///
/// ´test:unit:registration-change-without-actor-refuses´
#[test]
fn registration_change_without_actor_refuses() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "actor shape"), &config)
        .expect("current audit is written");
    let audit_path = fixture.gateway.state_dir().join("audit/lane-031.jsonl");
    let mut source = fs::read_to_string(&audit_path).expect("current-schema audit is readable");
    let offending_line = source.lines().count() + 1;
    source.push_str(
        r#"{"schema":2,"timestamp_unix_ms":150,"event":{"kind":"registration_change","change":{"proposal_seq":4,"command":"bin-sh","argv":["/bin/sh"],"wall_budget_seconds":600}}}"#,
    );
    source.push('\n');
    fs::write(&audit_path, &source).expect("actor-free registration change is appended");

    let error = fixture
        .gateway
        .audit_records("lane-031")
        .expect_err("registration change without actor is refused");
    let GatewayError::CorruptAudit {
        path,
        line,
        invariant,
    } = &error
    else {
        panic!("actor-free audit returned the wrong error: {error:?}");
    };
    assert_eq!(path, &audit_path);
    assert_eq!(*line, offending_line);
    assert_eq!(
        *invariant,
        "line is not valid JSON for the audit record schema"
    );
}

/// A verdict audit event without an actor refuses when read from a real log.
///
/// ´test:unit:verdict-without-actor-refuses´
#[test]
fn verdict_without_actor_refuses() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "verdict actor"), &config)
        .expect("current audit is written");
    let audit_path = fixture.gateway.state_dir().join("audit/lane-031.jsonl");
    let mut source = fs::read_to_string(&audit_path).expect("current audit is readable");
    let offending_line = source.lines().count() + 1;
    source.push_str(
        r#"{"schema":2,"timestamp_unix_ms":150,"event":{"kind":"verdict","verdict":{"seq":1,"decision":"denied","wall_millis":1}}}"#,
    );
    source.push('\n');
    fs::write(&audit_path, source).expect("actor-free verdict is appended");

    let error = fixture
        .gateway
        .audit_records("lane-031")
        .expect_err("verdict without actor is refused");
    let GatewayError::CorruptAudit {
        path,
        line,
        invariant,
    } = &error
    else {
        panic!("actor-free verdict returned the wrong error: {error:?}");
    };
    assert_eq!(path, &audit_path);
    assert_eq!(*line, offending_line);
    assert_eq!(
        *invariant,
        "line is not valid JSON for the audit record schema"
    );
}

/// A genuinely malformed audit line — not merely a legacy schema — fails
/// with a diagnostic naming the audit file, the offending one-based line
/// number, and the specific violated invariant, and that failure reaches
/// the same crash-report path as any other supervised serve failure.
///
/// ´test:unit:corrupt-audit-line-writes-enriched-crash-report´
#[test]
fn corrupt_audit_line_writes_enriched_crash_report() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_heartbeat_interval_millis(10);
    fixture
        .gateway
        .process_request(
            "lane-031",
            &proposal_request(1, "seed a real audit line"),
            &config,
        )
        .expect("seed proposal is accepted");
    let audit_path = fixture.gateway.state_dir().join("audit/lane-031.jsonl");
    let mut source = fs::read_to_string(&audit_path).expect("seeded audit is readable");
    let corrupt_line = source.lines().count() + 1;
    source.push_str("not json at all\n");
    fs::write(&audit_path, &source).expect("corrupt audit line is appended");

    let error = crate::serve::supervise_serve(&fixture.gateway, &config, |_publisher| {
        fixture.gateway.audit_records("lane-031")?;
        Ok(())
    })
    .expect_err("corrupt audit content remains fatal");
    let GatewayError::CorruptAudit {
        path,
        line,
        invariant,
    } = &error
    else {
        panic!("corrupt audit failure is not the enriched variant: {error:?}");
    };
    assert_eq!(path, &audit_path);
    assert_eq!(*line, corrupt_line);
    assert_eq!(
        *invariant,
        "line is not valid JSON for the audit record schema"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "gateway audit state is invalid: line is not valid JSON for the audit record \
             schema at {}:{corrupt_line}",
            audit_path.display()
        )
    );

    let report = read_crash_report(&fixture.gateway);
    assert_eq!(report.failure_kind, ServeFailureKind::Error);
    assert_eq!(report.message, error.to_string());
}

/// Projection writers reject legacy or corrupt in-memory result schemas before
/// creating any worker-owned protocol path.
///
/// ´test:unit:write-result-rejects-wrong-in-memory-schema´
#[test]
fn write_result_rejects_wrong_in_memory_schema() {
    let directory = TestDirectory::new();
    let mut result = crate::OperationResult::pending_proposal(1, 0, 600);
    result.schema = 1;
    let error = crate::serve::write_result(directory.path(), &result, 512 * 1_024)
        .expect_err("legacy in-memory result is rejected");
    assert!(matches!(error, GatewayError::CorruptState("result_schema")));
    assert!(!directory.path().join(".lane").exists());
}

/// A proposal's sequence-stable status remains pending while later push and
/// registered-run results replace only the lane's current result slot.
///
/// ´test:unit:per-proposal-status-survives-later-push-and-run-results´
#[test]
fn per_proposal_status_survives_later_push_and_run_results() {
    let mut fixture = GitFixture::registered();
    let script = fixture.write_package_script("pending-run.sh", "printf 'ran while pending\\n'\n");
    fixture.configure_clippy(
        vec!["/bin/sh".to_owned(), script],
        60,
        BudgetPolicy {
            run_cap: 20,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("pending fixture initial push completes");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("pending protocol directory is created");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":2,"op":"propose","argv":["cargo","metadata"],"reason":"keep waiting"}"#,
    )
    .expect("pending proposal is written");
    let config = config.with_poll_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);
    let pending = wait_for_result_verdict(&fixture.result_path(), 2, ResultVerdict::Pending);
    assert_eq!(pending.operation, Some(Operation::Propose));
    let proposal_result = lane_dir.join("proposals/2.json");
    assert_eq!(
        wait_for_result_verdict(&proposal_result, 2, ResultVerdict::Pending),
        pending
    );

    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":3,"op":"push"}"#,
    )
    .expect("push while pending is written");
    let push = wait_for_result_verdict(&fixture.result_path(), 3, ResultVerdict::Success);
    assert_eq!(push.operation, Some(Operation::Push));
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":4,"op":"run","command":"clippy"}"#,
    )
    .expect("run while pending is written");
    let run = wait_for_result_verdict(&fixture.result_path(), 4, ResultVerdict::Success);
    assert_eq!(run.operation, Some(Operation::Run));
    assert_eq!(run.stdout, "ran while pending\n");
    assert_eq!(
        wait_for_result_verdict(&proposal_result, 2, ResultVerdict::Pending),
        pending
    );
    let queue = fixture
        .gateway
        .proposals()
        .expect("pending queue is readable");
    assert_eq!(queue.proposals.len(), 1);
    assert_eq!(queue.proposals[0].seq, 2);

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// Verdict commands distinguish an unknown lane from an unknown or resolved
/// proposal without panicking or invoking the configured runner.
///
/// ´test:unit:unknown-proposal-verdicts-refuse-cleanly´
#[test]
fn unknown_proposal_verdicts_refuse_cleanly() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    let unknown_lane = fixture
        .gateway
        .approve_proposal("lane-404", 1, false, None, &config)
        .expect_err("unknown lane is refused");
    let GatewayError::UnregisteredLane = unknown_lane else {
        panic!("unknown lane returned the wrong error");
    };
    let unknown_approval = fixture
        .gateway
        .approve_proposal("lane-031", 99, false, None, &config)
        .expect_err("unknown proposal approval is refused");
    let GatewayError::ProposalNotPending = unknown_approval else {
        panic!("unknown approval returned the wrong error");
    };
    let unknown_denial = fixture
        .gateway
        .deny_proposal("lane-031", 99, "not approved")
        .expect_err("unknown proposal denial is refused");
    let GatewayError::ProposalNotPending = unknown_denial else {
        panic!("unknown denial returned the wrong error");
    };
}

/// Malformed worker JSON still yields a typed result file through the polling
/// path instead of leaving the worker silent.
///
/// ´test:unit:serve-loop-writes-malformed-request-refusal´
#[test]
fn serve_loop_writes_malformed_request_refusal() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("protocol directory is created");
    fs::write(lane_dir.join("request.json"), b"{not-json\n").expect("malformed request is written");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway, config);

    let result = wait_for_result(&lane_dir.join("result.json"));
    assert_eq!(result.seq, None);
    assert_eq!(result.verdict, ResultVerdict::Refused);
    assert_eq!(
        result.refusal.expect("malformed refusal is present").rule,
        RefusalRule::MalformedJson
    );
    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// Worker path faults are audited while the same serve accepts the next request.
///
/// ´test:unit:serve-continues-after-worker-file-faults´
#[test]
#[allow(clippy::too_many_lines)]
fn serve_continues_after_worker_file_faults() {
    use crate::types::{WorkerPathClass, WorkerPathDefect};

    for (name, path_class, defect) in [
        (
            "result_directory",
            WorkerPathClass::Result,
            WorkerPathDefect::Directory,
        ),
        (
            "result_fifo",
            WorkerPathClass::Result,
            WorkerPathDefect::Fifo,
        ),
        (
            "request_fifo",
            WorkerPathClass::Request,
            WorkerPathDefect::Fifo,
        ),
        (
            "unwritable_lane",
            WorkerPathClass::Result,
            WorkerPathDefect::UnwritableDirectory,
        ),
    ] {
        let fixture = Fixture::registered();
        let lane_dir = fixture.registration.worktree.join(".lane");
        fs::create_dir(&lane_dir).expect("protocol directory is created");
        let request_path = lane_dir.join("request.json");
        let result_path = lane_dir.join("result.json");
        match name {
            "result_directory" => fs::create_dir(&result_path).expect("bad result directory"),
            "result_fifo" => {
                assert!(
                    Command::new("mkfifo")
                        .arg(&result_path)
                        .status()
                        .expect("mkfifo runs")
                        .success()
                );
            }
            "request_fifo" => {
                assert!(
                    Command::new("mkfifo")
                        .arg(&request_path)
                        .status()
                        .expect("mkfifo runs")
                        .success()
                );
            }
            "unwritable_lane" => {
                fs::write(&request_path, proposal_request(1, "bad worker path"))
                    .expect("first request written");
                fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o500))
                    .expect("lane made unwritable");
                let probe = lane_dir.join("root-probe");
                if fs::write(&probe, b"probe").is_ok() {
                    fs::remove_file(probe).expect("probe removed");
                    fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o700))
                        .expect("permissions restored");
                    std::io::stderr().write_all(b"SKIP serve_continues_after_worker_file_faults/unwritable_lane: root can write mode-500 directory\n")
                        .expect("named skip is printed");
                    continue;
                }
            }
            _ => unreachable!(),
        }
        let config = serve_config(&fixture.gateway).with_poll_interval_millis(5);
        let gateway = fixture.gateway;
        let server = start_server(gateway.clone(), config.clone());
        if name != "request_fifo" && name != "unwritable_lane" {
            fs::write(&request_path, proposal_request(1, "bad worker path"))
                .expect("first request written");
        }
        let started = Instant::now();
        loop {
            if gateway.state_dir().join("audit/lane-031.jsonl").exists()
                && audit_records(&gateway, "lane-031").iter().any(|record| {
                    matches!(&record.event, AuditEvent::WorkerFileRefused {
                    path_class: actual_path, defect: actual_defect, seq, unpublishable, ..
                } if *actual_path == path_class
                    && *actual_defect == defect
                    && *seq == (name != "request_fifo").then_some(1)
                    && *unpublishable == (name != "request_fifo"))
                })
            {
                break;
            }
            assert!(started.elapsed() < FIXTURE_WAIT, "no {name} audit event");
            thread::sleep(Duration::from_millis(5));
        }
        if name == "request_fifo" {
            let refusal = wait_for_result(&result_path);
            assert_eq!(refusal.seq, None);
            assert_eq!(
                refusal
                    .refusal
                    .expect("request path refusal is published")
                    .rule,
                RefusalRule::RequestPathInvalid
            );
            assert!(audit_records(&gateway, "lane-031").iter().any(|record| {
                matches!(&record.event, AuditEvent::Refusal { refusal }
                    if refusal.rule == RefusalRule::RequestPathInvalid)
            }));
        }
        if name == "unwritable_lane" {
            fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o700))
                .expect("permissions restored");
        } else if name == "request_fifo" {
            fs::remove_file(&request_path).expect("request FIFO removed");
        } else if name == "result_directory" {
            fs::remove_dir(&result_path).expect("result directory removed");
        } else {
            fs::remove_file(&result_path).expect("result FIFO removed");
        }
        fs::write(&request_path, proposal_request(2, "serve continues"))
            .expect("second request written");
        let later = wait_for_result_seq(&result_path, 2);
        assert_eq!(later.verdict, ResultVerdict::Pending);
        fs::write(config.shutdown_file(), b"stop").expect("shutdown requested");
        join_server_bounded(server).expect("serve continues and stops");
    }
}

/// A chunk failure names the chunk actually inspected, and a schema error
/// remains an internal gateway error.
///
/// ´test:unit:worker-file-failure-keeps-the-failing-operation´
#[test]
fn worker_file_failure_keeps_the_failing_operation() {
    use crate::types::{WorkerPathClass, WorkerPathDefect};

    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("protocol directory is created");
    fs::create_dir(lane_dir.join("result-5-0000.json")).expect("chunk path is a directory");
    let mut result = crate::OperationResult::refused(
        Some(5),
        None,
        1,
        crate::Refusal::new(RefusalRule::RequestPathInvalid),
        String::new(),
        String::new(),
    );
    result.stdout = "x".repeat(1024);
    assert!(matches!(
        crate::serve::write_result(&fixture.registration.worktree, &result, 512),
        Err(crate::GatewayError::WorkerFile(failure))
            if failure.path_class == WorkerPathClass::OutputChunk
                && failure.defect == WorkerPathDefect::Directory
    ));
    result.schema = 1;
    assert!(matches!(
        crate::serve::write_result(&fixture.registration.worktree, &result, 512),
        Err(crate::GatewayError::CorruptState("result_schema"))
    ));
}

/// An oversized request reports its defect and publishes normal serve activity.
///
/// ´test:unit:oversized-worker-request-names-defect´
#[test]
fn oversized_worker_request_names_defect() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("protocol directory is created");
    fs::write(lane_dir.join("request.json"), vec![b'x'; 1024 * 1024 + 1])
        .expect("oversized request written");
    let config = serve_config(&fixture.gateway)
        .with_poll_interval_millis(5)
        .with_heartbeat_interval_millis(10);
    let server = start_server(fixture.gateway.clone(), config.clone());
    let result = wait_for_result(&lane_dir.join("result.json"));
    assert_eq!(result.seq, None);
    assert_eq!(result.stderr, "too_large");
    assert_eq!(
        result.refusal.expect("path refusal is published").rule,
        RefusalRule::RequestPathInvalid
    );
    let heartbeat = wait_for_heartbeat(&fixture.gateway, |heartbeat| {
        heartbeat.activity == ServeActivity::ResultPublished
            && heartbeat.lane.as_deref() == Some("lane-031")
    });
    assert_eq!(heartbeat.seq, None);
    fs::write(config.shutdown_file(), b"stop").expect("shutdown requested");
    join_server_bounded(server).expect("serve stops cleanly");
}

/// A request file observed at creation and completed a cycle later is served
/// normally: the writer's unfinished bytes cost the ledger one waiting record
/// and no refusal at all.
///
/// ´test:unit:unfinished-request-is-served-without-a-refusal´
#[test]
fn unfinished_request_is_served_without_a_refusal() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("unfinished protocol directory is created");
    let request_path = lane_dir.join("request.json");
    fs::write(&request_path, b"").expect("request file is created before its content");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(100);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    assert_eq!(
        wait_for_unfinished_request(&fixture.gateway, "lane-031"),
        [0]
    );
    fs::write(
        &request_path,
        proposal_request(1, "completed between two polls"),
    )
    .expect("request file is completed by its writer");

    let result = wait_for_result_verdict(&lane_dir.join("result.json"), 1, ResultVerdict::Pending);
    assert_eq!(result.operation, Some(Operation::Propose));
    let records = audit_records(&fixture.gateway, "lane-031");
    assert_eq!(unfinished_request_bytes(&fixture.gateway, "lane-031"), [0]);
    assert!(
        !records
            .iter()
            .any(|record| matches!(record.event, AuditEvent::Refusal { .. })),
        "a completed request must not leave a refusal behind"
    );

    fs::write(shutdown, b"stop\n").expect("unfinished server shutdown is written");
    server
        .join()
        .expect("unfinished serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// A request file that stays unfinished across the re-poll bound is refused
/// exactly once, and further cycles neither repeat the waiting record nor
/// reopen the episode.
///
/// ´test:unit:unfinished-request-is-refused-once-after-the-repoll-bound´
#[test]
fn unfinished_request_is_refused_once_after_the_repoll_bound() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("bounded protocol directory is created");
    fs::write(lane_dir.join("request.json"), b"").expect("request file stays empty");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(20);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let result = wait_for_result(&lane_dir.join("result.json"));
    assert_eq!(result.verdict, ResultVerdict::Refused);
    assert_eq!(
        result.refusal.expect("bounded refusal is present").rule,
        RefusalRule::MalformedJson
    );
    thread::sleep(Duration::from_millis(200));
    assert_eq!(unfinished_request_bytes(&fixture.gateway, "lane-031"), [0]);
    let refusals = audit_records(&fixture.gateway, "lane-031")
        .into_iter()
        .filter_map(|record| match record.event {
            AuditEvent::Refusal { refusal } => Some(refusal.rule),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(refusals, [RefusalRule::MalformedJson]);

    fs::write(shutdown, b"stop\n").expect("bounded server shutdown is written");
    server
        .join()
        .expect("bounded serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// A truncated JSON prefix is a partial write, not a malformed document, so it
/// waits for its writer exactly as an empty file does.
///
/// ´test:unit:partial-json-prefix-waits-like-an-empty-request-file´
#[test]
fn partial_json_prefix_waits_like_an_empty_request_file() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("partial protocol directory is created");
    let request_path = lane_dir.join("request.json");
    let prefix = r#"{"schema":1,"seq":1,"op":"pro"#;
    fs::write(&request_path, prefix).expect("request file is created truncated");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(100);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    assert_eq!(
        wait_for_unfinished_request(&fixture.gateway, "lane-031"),
        [prefix.len()]
    );
    fs::write(&request_path, proposal_request(1, "prefix completed"))
        .expect("truncated request file is completed");

    let result = wait_for_result_verdict(&lane_dir.join("result.json"), 1, ResultVerdict::Pending);
    assert_eq!(result.operation, Some(Operation::Propose));
    assert!(
        !audit_records(&fixture.gateway, "lane-031")
            .iter()
            .any(|record| matches!(record.event, AuditEvent::Refusal { .. })),
        "a completed prefix must not leave a refusal behind"
    );

    fs::write(shutdown, b"stop\n").expect("partial server shutdown is written");
    server
        .join()
        .expect("partial serve thread joins")
        .expect("serve loop shuts down cleanly");
}

/// Startup seeding cannot read a sequence out of a prefix, so it defers the
/// decision to the first complete read instead of letting an already accepted
/// request return through the loop as a replay.
///
/// ´test:unit:startup-seeding-defers-an-unfinished-request-file´
#[test]
fn startup_seeding_defers_an_unfinished_request_file() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("deferred protocol directory is created");
    let request_path = lane_dir.join("request.json");
    let accepted = proposal_request(1, "accepted before the restart");
    fs::write(&request_path, &accepted).expect("accepted request is written");
    let first = serve_config(&fixture.gateway).with_poll_interval_millis(10);
    let first_shutdown = first.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), first);
    wait_for_result_verdict(&lane_dir.join("result.json"), 1, ResultVerdict::Pending);
    fs::write(&first_shutdown, b"stop\n").expect("first server shutdown is written");
    server
        .join()
        .expect("first serve thread joins")
        .expect("first serve loop shuts down cleanly");
    fs::remove_file(&first_shutdown).expect("first shutdown flag is removed");

    fs::write(&request_path, r#"{"schema":1,"seq":1,"#).expect("request file is truncated");
    let restarted = configured_gateway(fixture.gateway.state_dir().to_path_buf());
    let config = serve_config(&restarted).with_poll_interval_millis(100);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(restarted.clone(), config);
    wait_for_unfinished_request(&restarted, "lane-031");
    fs::write(&request_path, &accepted).expect("accepted request is completed again");
    thread::sleep(Duration::from_millis(300));

    assert!(
        !audit_records(&restarted, "lane-031").iter().any(|record| {
            matches!(
                &record.event,
                AuditEvent::Refusal { refusal } if refusal.rule == RefusalRule::SequenceReplay
            )
        }),
        "a deferred seed must not replay-refuse its own accepted request"
    );

    fs::write(shutdown, b"stop\n").expect("deferred server shutdown is written");
    server
        .join()
        .expect("deferred serve thread joins")
        .expect("restarted serve loop shuts down cleanly");
}

/// An idle serve loop stops on its shutdown flag within a loaded-node allowance.
///
/// ´test:unit:serve-loop-shuts-down-promptly´
#[test]
fn serve_loop_shuts_down_promptly() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    assert_eq!(config.poll_interval_millis(), 500);
    let config = config.with_poll_interval_millis(25);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);
    // A running heartbeat proves serve started; a 30 ms sleep cannot do so.
    wait_for_heartbeat_with_limit(
        &fixture.gateway,
        |heartbeat| heartbeat.process_state == ServeProcessState::Running,
        LOADED_FIXTURE_WAIT,
    );
    // Allow 5 s, twenty times the former 250 ms bound, for scheduling and
    // filesystem delays on shared 256-core nodes whose load can exceed 270.
    // This bounds shutdown completion, not the configured 25 ms polling window;
    // the separate 120 s join deadline only guards a hang before this assertion.
    let stopping = Instant::now();
    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    let outcome = join_server_with_limit(server, LOADED_FIXTURE_WAIT);
    assert!(outcome.is_ok());
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "idle shutdown exceeded the loaded-node promptness allowance"
    );
    let heartbeat = read_heartbeat(&fixture.gateway);
    assert_eq!(heartbeat.process_state, ServeProcessState::Stopped);
    assert_eq!(heartbeat.stop_reason, Some(ServeStopReason::ShutdownFlag));
}

/// An acquisition reaps a lock held by a dead PID, audits the recovery, and
/// retries once so the requested action can proceed.
///
/// ´test:unit:acquisition-reaps-dead-pid-lock-and-retries-once´
#[test]
fn acquisition_reaps_dead_pid_lock_and_retries_once() {
    let fixture = Fixture::registered();
    let lock_path = action_lock_path(&fixture.gateway, &fixture.registration.lane);
    let dead_pid = u32::MAX;
    assert!(!Path::new("/proc").join(dead_pid.to_string()).exists());
    fs::write(&lock_path, format!("{dead_pid}\n")).expect("dead holder lock is written");

    fixture
        .gateway
        .deregister(&fixture.registration.lane)
        .expect("stale lock is reaped and deregistration acquires the lane");

    assert!(!lock_path.exists());
    let records = audit_records(&fixture.gateway, &fixture.registration.lane);
    assert_eq!(records.len(), 1);
    assert_action_lock_reap_record(
        &records[0],
        &fixture.registration.lane,
        Some(dead_pid),
        "dead_pid",
    );
}

/// A live recorded PID keeps the action lock and produces an operator-ready
/// diagnostic naming both the holder and the exact lock path.
///
/// ´test:unit:alive-pid-lock-refusal-names-holder-and-path´
#[test]
fn alive_pid_lock_refusal_names_holder_and_path() {
    let fixture = Fixture::registered();
    let lock_path = action_lock_path(&fixture.gateway, &fixture.registration.lane);
    let pid = std::process::id();
    fs::write(&lock_path, format!("{pid}\n")).expect("live holder lock is written");

    let error = fixture
        .gateway
        .deregister(&fixture.registration.lane)
        .expect_err("live holder keeps the lane busy");
    assert_eq!(
        error.to_string(),
        format!(
            "lane already has an action in flight (held by pid {pid}, {})",
            lock_path.display()
        )
    );
    assert!(matches!(
        error,
        GatewayError::LaneBusy {
            pid: Some(holder),
            path,
        } if holder == pid && path == lock_path
    ));
    assert!(lock_path.exists());
}

/// A malformed lock remains conservatively busy during acquisition and the
/// refusal identifies the malformed record and its exact path.
///
/// ´test:unit:acquisition-refuses-malformed-lock-with-diagnostic´
#[test]
fn acquisition_refuses_malformed_lock_with_diagnostic() {
    let fixture = Fixture::registered();
    let lock_path = action_lock_path(&fixture.gateway, &fixture.registration.lane);
    fs::write(&lock_path, b"not-a-pid\n").expect("malformed lock is written");

    let error = fixture
        .gateway
        .deregister(&fixture.registration.lane)
        .expect_err("malformed lock keeps the lane busy outside startup");
    assert_eq!(
        error.to_string(),
        format!(
            "lane already has an action in flight (malformed or unreadable lock record: no pid parseable, {})",
            lock_path.display()
        )
    );
    assert!(matches!(
        error,
        GatewayError::LaneBusy { pid: None, path } if path == lock_path
    ));
    assert_eq!(
        fs::read_to_string(&lock_path).expect("malformed lock remains readable"),
        "not-a-pid\n"
    );
    assert!(
        !fixture
            .gateway
            .state_dir()
            .join("audit")
            .join("lane-031.jsonl")
            .exists()
    );
}

/// Startup reaps a dead-PID lock before polling, records the exact recovery,
/// and publishes the typed activity even if live serving reacquires the lock.
///
/// ´test:unit:serve-startup-reaps-dead-pid-lock´
#[test]
fn serve_startup_reaps_dead_pid_lock() {
    let fixture = Fixture::registered();
    let lock_path = action_lock_path(&fixture.gateway, &fixture.registration.lane);
    let dead_pid = u32::MAX;
    fs::write(&lock_path, format!("{dead_pid}\n")).expect("dead holder lock is written");
    let config = serve_config(&fixture.gateway)
        .with_poll_interval_millis(25)
        .with_heartbeat_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let heartbeat = wait_for_heartbeat(&fixture.gateway, |heartbeat| {
        heartbeat.activity == ServeActivity::ActionLockReaped
    });
    assert_eq!(heartbeat.lane.as_deref(), Some("lane-031"));
    wait_for_reaped_lane_lock(&lock_path);
    let records = audit_records(&fixture.gateway, &fixture.registration.lane);
    assert_eq!(records.len(), 1);
    assert_action_lock_reap_record(&records[0], "lane-031", Some(dead_pid), "dead_pid");

    fs::write(shutdown, b"stop\n").expect("startup-reap shutdown is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop exits cleanly");
}

/// Startup alone treats a malformed lock as stale, records the distinct
/// reason, and continues even if live serving reacquires the lock.
///
/// ´test:unit:serve-startup-reaps-malformed-lock´
#[test]
fn serve_startup_reaps_malformed_lock() {
    let fixture = Fixture::registered();
    let lock_path = action_lock_path(&fixture.gateway, &fixture.registration.lane);
    fs::write(&lock_path, b"not-a-pid\n").expect("malformed lock is written");
    let config = serve_config(&fixture.gateway)
        .with_poll_interval_millis(25)
        .with_heartbeat_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let heartbeat = wait_for_heartbeat(&fixture.gateway, |heartbeat| {
        heartbeat.activity == ServeActivity::ActionLockReaped
    });
    assert_eq!(heartbeat.lane.as_deref(), Some("lane-031"));
    wait_for_reaped_lane_lock(&lock_path);
    let records = audit_records(&fixture.gateway, &fixture.registration.lane);
    assert_eq!(records.len(), 1);
    assert_action_lock_reap_record(&records[0], "lane-031", None, "malformed_or_unreadable");

    fs::write(shutdown, b"stop\n").expect("malformed-reap shutdown is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop exits cleanly");
}

/// Entry 27a: the serve loop also surfaces a stray unregistered `.toml` at
/// startup, refreshing a typed report file rather than staying silent — and,
/// as with `status`, a registered lane's own source TOML beside its
/// `registrations/<lane>.toml` copy is not flagged.
///
/// ´test:unit:serve-startup-reports-stray-toml-files´
#[test]
fn serve_startup_reports_stray_toml_files() {
    let fixture = Fixture::registered();
    fs::write(
        fixture.gateway.state_dir().join("dropped-lane.toml"),
        b"never registered\n",
    )
    .expect("stray toml is written");
    fs::write(
        fixture
            .gateway
            .state_dir()
            .join(format!("{}.toml", fixture.registration.lane)),
        b"source copy of a still-registered lane\n",
    )
    .expect("registered lane's source toml is written");
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(25);
    let shutdown = config.shutdown_file().to_path_buf();
    let report_path = fixture
        .gateway
        .state_dir()
        .join("unregistered-registrations.json");
    let gateway = fixture.gateway;
    let server = start_server(gateway, config);
    wait_for_text(&report_path, "dropped-lane.toml");
    let report = fs::read_to_string(&report_path).expect("report is readable");
    assert!(
        !report.contains(&format!("{}.toml", fixture.registration.lane)),
        "registered lane's source toml was mislabeled as stray: {report}"
    );

    fs::write(shutdown, b"stop\n").expect("shutdown flag is written");
    server
        .join()
        .expect("serve thread joins")
        .expect("serve loop exits cleanly");
}

/// A served request advances the fixed heartbeat from process start through
/// result publication while retaining only the typed lane and sequence.
///
/// ´test:unit:serve-writes-pid-and-last-activity-heartbeat´
#[test]
fn serve_writes_pid_and_last_activity_heartbeat() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("heartbeat protocol directory is created");
    fs::write(
        lane_dir.join("request.json"),
        proposal_request(1, "observe typed heartbeat activity"),
    )
    .expect("heartbeat request is written");
    let config = serve_config(&fixture.gateway)
        .with_poll_interval_millis(5)
        .with_heartbeat_interval_millis(10);
    assert_eq!(
        ServeConfig::for_gateway(&fixture.gateway).heartbeat_interval_millis(),
        5_000
    );
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    let result = wait_for_result_verdict(&lane_dir.join("result.json"), 1, ResultVerdict::Pending);
    assert_eq!(result.seq, Some(1));
    let heartbeat = wait_for_heartbeat(&fixture.gateway, |heartbeat| {
        heartbeat.activity == ServeActivity::ResultPublished && heartbeat.seq == Some(1)
    });
    assert_eq!(heartbeat.schema, 1);
    assert_eq!(heartbeat.pid, std::process::id());
    assert!(heartbeat.started_unix_ms <= heartbeat.last_activity_unix_ms);
    assert!(heartbeat.last_activity_unix_ms <= heartbeat.heartbeat_unix_ms);
    assert_eq!(heartbeat.process_state, ServeProcessState::Running);
    assert_eq!(heartbeat.lane.as_deref(), Some("lane-031"));
    assert_eq!(heartbeat.seq, Some(1));

    fs::write(shutdown, b"stop\n").expect("heartbeat server shutdown is written");
    server
        .join()
        .expect("heartbeat serve thread joins")
        .expect("heartbeat serve loop shuts down");
}

// Release a held fixture runner and request shutdown even if an assertion fails.
struct HeldRunnerRelease {
    release: PathBuf,
    shutdown: PathBuf,
}

impl Drop for HeldRunnerRelease {
    fn drop(&mut self) {
        let _ignored = fs::write(&self.release, b"release\n");
        let _ignored = fs::write(&self.shutdown, b"stop\n");
    }
}

/// The dedicated publisher advances heartbeat time during a synchronous
/// runner wait without changing the request's last-activity timestamp.
///
/// # Panics
/// Panics only if fixture setup fails or heartbeat and runner evidence disagree,
/// which a live publisher and an event-held runner cannot arrange.
///
/// ´test:unit:heartbeat-stays-fresh-during-long-runner´
#[test]
fn heartbeat_stays_fresh_during_long_runner() {
    let mut fixture = GitFixture::registered();
    let marker = fixture.directory.path().join("long-run.marker");
    let release = fixture.directory.path().join("long-run.release");
    // The release file replaces the 200 ms window: the runner cannot complete
    // until both heartbeat observations have happened. The shell's 120-second
    // deadline is only a hang guard; its 180-second runner budget leaves cleanup
    // headroom on a loaded node and does not delay a released runner.
    let script = fixture.write_package_script(
        "long-run.sh",
        "marker=$1\nrelease=$2\nprintf 'started\\n' > \"$marker\"\nSECONDS=0\nwhile [ ! -f \"$release\" ]; do\n    [ \"$SECONDS\" -lt 120 ] || exit 124\n    sleep 0.01\ndone\nprintf 'finished\\n' > \"$marker\"\n",
    );
    fixture.configure_clippy(
        vec![
            "/bin/bash".to_owned(),
            script,
            marker.to_string_lossy().into_owned(),
            release.to_string_lossy().into_owned(),
        ],
        180,
        BudgetPolicy {
            run_cap: 2,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("long-run fixture push completes");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("long-run protocol directory is created");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
    )
    .expect("long-run request is written");
    let config = config
        .with_poll_interval_millis(5)
        .with_heartbeat_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let held = HeldRunnerRelease {
        release,
        shutdown: shutdown.clone(),
    };
    let server = start_server(fixture.gateway.clone(), config);

    wait_for_text_with_limit(&marker, "started", LOADED_FIXTURE_WAIT);
    let first = wait_for_heartbeat_with_limit(
        &fixture.gateway,
        |heartbeat| heartbeat.activity == ServeActivity::RequestStarted && heartbeat.seq == Some(2),
        LOADED_FIXTURE_WAIT,
    );
    let second = wait_for_heartbeat_with_limit(
        &fixture.gateway,
        |heartbeat| {
            heartbeat.activity == ServeActivity::RequestStarted
                && heartbeat.heartbeat_unix_ms > first.heartbeat_unix_ms
        },
        LOADED_FIXTURE_WAIT,
    );
    assert_eq!(second.last_activity_unix_ms, first.last_activity_unix_ms);
    assert_eq!(
        fs::read_to_string(&marker).expect("runner marker is readable"),
        "started\n"
    );
    fs::write(&held.release, b"release\n").expect("heartbeat observations release the runner");
    let result = wait_for_result_seq_with_limit(&fixture.result_path(), 2, LOADED_FIXTURE_WAIT);
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert_eq!(
        fs::read_to_string(&marker).expect("finished marker"),
        "finished\n"
    );

    fs::write(shutdown, b"stop\n").expect("long-run server shutdown is written");
    join_server_with_limit(server, LOADED_FIXTURE_WAIT).expect("long-run serve loop shuts down");
}

/// A shutdown flag written while a runner is executing takes effect at the end
/// of that cycle, not within one polling interval: the cycle owns the loop
/// until its command returns, which is what the reader contract has to say.
///
/// ´test:unit:shutdown-flag-waits-for-the-cycle-executing-a-runner´
#[test]
fn shutdown_flag_waits_for_the_cycle_executing_a_runner() {
    let mut fixture = GitFixture::registered();
    let marker = fixture.directory.path().join("mid-run.marker");
    let script = fixture.write_package_script(
        "mid-run.sh",
        "marker=$1\nprintf 'started\\n' > \"$marker\"\nsleep 0.5\nprintf 'finished\\n' > \"$marker\"\n",
    );
    fixture.configure_clippy(
        vec![
            "/bin/sh".to_owned(),
            script,
            marker.to_string_lossy().into_owned(),
        ],
        60,
        BudgetPolicy {
            run_cap: 2,
            cooldown_seconds: 0,
        },
    );
    let (config, _record) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("mid-run fixture push completes");
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("mid-run protocol directory is created");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
    )
    .expect("mid-run request is written");
    let config = config
        .with_poll_interval_millis(5)
        .with_heartbeat_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(fixture.gateway.clone(), config);

    wait_for_text(&marker, "started");
    let flagged = Instant::now();
    fs::write(&shutdown, b"stop\n").expect("mid-run shutdown flag is written");
    // Five polling intervals after the flag, the runner is still executing and
    // the loop has not reached a stop check, so the flag has not stopped it.
    thread::sleep(Duration::from_millis(100));
    assert!(
        !server.is_finished(),
        "serve stopped while its cycle was still executing a runner"
    );

    let result = wait_for_result_seq(&fixture.result_path(), 2);
    assert_eq!(result.verdict, ResultVerdict::Success);
    assert!(
        flagged.elapsed() >= Duration::from_millis(300),
        "the flagged cycle did not run its command to completion"
    );
    join_server_bounded(server).expect("mid-run serve loop shuts down after its cycle");
    let heartbeat = read_heartbeat(&fixture.gateway);
    assert_eq!(heartbeat.process_state, ServeProcessState::Stopped);
    assert_eq!(heartbeat.stop_reason, Some(ServeStopReason::ShutdownFlag));
}

/// Clean shutdown emits the final stopped heartbeat and leaves an older crash
/// report untouched as distinguishable prior-generation evidence.
///
/// ´test:unit:clean-shutdown-marks-heartbeat-stopped´
#[test]
fn clean_shutdown_marks_heartbeat_stopped() {
    let fixture = Fixture::registered();
    let old_crash = concat!(
        "{\"schema\":1,\"pid\":7,\"started_unix_ms\":11,\"failed_unix_ms\":13,",
        "\"last_activity_unix_ms\":12,\"failure_kind\":\"error\",",
        "\"message\":\"older generation\"}\n"
    );
    let crash_path = fixture.gateway.state_dir().join("serve-crash.json");
    fs::write(&crash_path, old_crash).expect("old crash report is seeded");
    let config = serve_config(&fixture.gateway).with_heartbeat_interval_millis(10);
    fs::write(config.shutdown_file(), b"stop\n").expect("clean shutdown flag is written");
    fixture
        .gateway
        .serve(&config)
        .expect("serve exits cleanly with a preexisting shutdown flag");

    let source = fs::read_to_string(fixture.gateway.state_dir().join("serve-heartbeat.json"))
        .expect("stopped heartbeat is readable");
    let heartbeat: ServeHeartbeat =
        serde_json::from_str(&source).expect("stopped heartbeat is strict JSON");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&source).expect("heartbeat JSON value parses"),
        serde_json::json!({
            "schema": 1,
            "pid": heartbeat.pid,
            "started_unix_ms": heartbeat.started_unix_ms,
            "heartbeat_unix_ms": heartbeat.heartbeat_unix_ms,
            "heartbeat_interval_millis": 10,
            "last_activity_unix_ms": heartbeat.last_activity_unix_ms,
            "process_state": "stopped",
            "stop_reason": "shutdown_flag",
            "activity": "clean_shutdown"
        })
    );
    assert_eq!(heartbeat.pid, std::process::id());
    assert_ne!(heartbeat.started_unix_ms, 11);
    assert_eq!(heartbeat.process_state, ServeProcessState::Stopped);
    assert_eq!(heartbeat.stop_reason, Some(ServeStopReason::ShutdownFlag));
    assert_eq!(heartbeat.activity, ServeActivity::CleanShutdown);
    assert_eq!(
        fs::read_to_string(crash_path).expect("old crash report remains readable"),
        old_crash
    );
}

/// A reader judges a heartbeat it did not write: a gone process and a beat
/// older than twice its own cadence are both a dead serve, while a fresh beat
/// from a live process is alive.
///
/// ´test:unit:heartbeat-liveness-judges-a-dead-pid-and-a-stale-beat´
#[test]
fn heartbeat_liveness_judges_a_dead_pid_and_a_stale_beat() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_heartbeat_interval_millis(10);
    fs::write(config.shutdown_file(), b"stop\n").expect("liveness shutdown flag is written");
    fixture
        .gateway
        .serve(&config)
        .expect("serve exits cleanly with a preexisting shutdown flag");
    let source = fs::read_to_string(fixture.gateway.state_dir().join("serve-heartbeat.json"))
        .expect("published heartbeat is readable");
    let published: ServeHeartbeat =
        serde_json::from_str(&source).expect("published heartbeat is strict JSON");
    assert_eq!(published.heartbeat_interval_millis, 10);
    assert_eq!(
        heartbeat_liveness(&published, published.heartbeat_unix_ms),
        ServeLiveness::Stopped
    );

    let mut running = published;
    running.process_state = ServeProcessState::Running;
    running.stop_reason = None;
    assert_eq!(
        heartbeat_liveness(&running, running.heartbeat_unix_ms + 20),
        ServeLiveness::Alive
    );
    assert_eq!(
        heartbeat_liveness(&running, running.heartbeat_unix_ms + 21),
        ServeLiveness::Dead(ServeDeathReason::HeartbeatStale)
    );

    let dead_pid = u32::MAX;
    assert!(!Path::new("/proc").join(dead_pid.to_string()).exists());
    let mut gone = running;
    gone.pid = dead_pid;
    assert_eq!(
        heartbeat_liveness(&gone, gone.heartbeat_unix_ms),
        ServeLiveness::Dead(ServeDeathReason::ProcessGone)
    );
}

/// An ordinary serve error writes an exact safe crash report, while failure
/// to replace the crash path preserves both failure diagnostics.
///
/// ´test:unit:serve-error-writes-crash-report´
#[test]
fn serve_error_writes_crash_report() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_heartbeat_interval_millis(10);
    let error = crate::serve::supervise_serve(&fixture.gateway, &config, |_publisher| {
        Err(GatewayError::CorruptState("test_serve"))
    })
    .expect_err("returned serve error remains fatal");
    assert!(matches!(error, GatewayError::CorruptState("test_serve")));

    let report = read_crash_report(&fixture.gateway);
    let source = fs::read_to_string(fixture.gateway.state_dir().join("serve-crash.json"))
        .expect("serve error report source is readable");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&source).expect("crash JSON value parses"),
        serde_json::json!({
            "schema": 1,
            "pid": report.pid,
            "started_unix_ms": report.started_unix_ms,
            "failed_unix_ms": report.failed_unix_ms,
            "last_activity_unix_ms": report.last_activity_unix_ms,
            "failure_kind": "error",
            "message": "gateway test_serve state is invalid"
        })
    );
    assert_eq!(report.pid, std::process::id());
    assert_eq!(report.failure_kind, ServeFailureKind::Error);

    let crash_path = fixture.gateway.state_dir().join("serve-crash.json");
    fs::remove_file(&crash_path).expect("first crash report is removed for fault injection");
    fs::create_dir(&crash_path).expect("crash report path is blocked by a directory");
    let write_error = crate::serve::supervise_serve(&fixture.gateway, &config, |_publisher| {
        Err(GatewayError::CorruptState("test_serve"))
    })
    .expect_err("crash report publication failure remains fatal");
    assert_eq!(
        write_error.to_string(),
        "gateway test_serve state is invalid; serve crash report write failed"
    );
    assert!(matches!(
        write_error,
        GatewayError::CrashReportWriteFailed { .. }
    ));
}

/// The private supervision seam catches string and non-string panic payloads,
/// writes only their safe contract messages, marks the generation's own
/// heartbeat stopped with the panic reason, and returns a fatal error.
///
/// ´test:unit:serve-panic-writes-crash-report´
#[test]
fn serve_panic_writes_crash_report() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_heartbeat_interval_millis(10);
    let error = crate::serve::supervise_serve(
        &fixture.gateway,
        &config,
        |_publisher| -> Result<(), GatewayError> { panic!("controlled serve panic") },
    )
    .expect_err("serve panic is caught as a fatal error");
    assert!(matches!(
        error,
        GatewayError::ServePanicked(message) if message == "controlled serve panic"
    ));
    let report = read_crash_report(&fixture.gateway);
    assert_eq!(report.failure_kind, ServeFailureKind::Panic);
    assert_eq!(report.message, "controlled serve panic");
    let heartbeat = read_heartbeat(&fixture.gateway);
    assert_eq!(heartbeat.process_state, ServeProcessState::Stopped);
    assert_eq!(heartbeat.stop_reason, Some(ServeStopReason::Panic));

    let error = crate::serve::supervise_serve(
        &fixture.gateway,
        &config,
        |_publisher| -> Result<(), GatewayError> { std::panic::panic_any(17_u8) },
    )
    .expect_err("non-string serve panic is caught as a fatal error");
    assert!(matches!(
        error,
        GatewayError::ServePanicked(message) if message == "non-string panic payload"
    ));
    assert_eq!(
        read_crash_report(&fixture.gateway).message,
        "non-string panic payload"
    );
}

/// Failure of the initial atomic heartbeat replacement is a supervised serve
/// error with a crash report, not a silently unmonitored loop.
///
/// ´test:unit:heartbeat-write-failure-is-fatal´
#[test]
fn heartbeat_write_failure_is_fatal() {
    let fixture = Fixture::registered();
    let heartbeat_path = fixture.gateway.state_dir().join("serve-heartbeat.json");
    fs::create_dir(&heartbeat_path).expect("heartbeat path is blocked by a directory");
    let config = serve_config(&fixture.gateway).with_heartbeat_interval_millis(10);
    let error = fixture
        .gateway
        .serve(&config)
        .expect_err("heartbeat publication failure is fatal");
    assert!(matches!(error, GatewayError::HeartbeatPublisherFailed));
    let report = read_crash_report(&fixture.gateway);
    assert_eq!(report.failure_kind, ServeFailureKind::Error);
    assert_eq!(report.message, "serve heartbeat publisher failed");
    assert!(
        fs::read_dir(fixture.gateway.state_dir())
            .expect("state root is readable")
            .all(|entry| !entry
                .expect("state entry is readable")
                .file_name()
                .to_string_lossy()
                .starts_with(".serve-heartbeat."))
    );
}

/// A request whose sequence is above the durable watermark and is written
/// while no daemon runs is consumed by the replacement serve generation.
///
/// ´test:unit:restart-consumes-request-written-while-serve-was-down´
#[test]
fn restart_consumes_request_written_while_serve_was_down() {
    let fixture = Fixture::registered();
    let lane_dir = fixture.registration.worktree.join(".lane");
    fs::create_dir(&lane_dir).expect("restart protocol directory is created");
    fs::write(
        lane_dir.join("request.json"),
        proposal_request(1, "written while serve is absent"),
    )
    .expect("restart request is written while no serve loop exists");
    let restarted = configured_gateway(fixture.gateway.state_dir().to_path_buf());
    let config = serve_config(&restarted)
        .with_poll_interval_millis(5)
        .with_heartbeat_interval_millis(10);
    let shutdown = config.shutdown_file().to_path_buf();
    let server = start_server(restarted.clone(), config);

    let result = wait_for_result_verdict(&lane_dir.join("result.json"), 1, ResultVerdict::Pending);
    assert_eq!(result.operation, Some(Operation::Propose));
    assert_eq!(
        restarted
            .request_watermark("lane-031")
            .expect("restart watermark is readable"),
        Some(1)
    );
    assert!(!audit_records(&restarted, "lane-031").iter().any(|record| {
        matches!(
            &record.event,
            AuditEvent::Refusal { refusal } if refusal.rule == RefusalRule::SequenceReplay
        )
    }));

    fs::write(shutdown, b"stop\n").expect("restart server shutdown is written");
    server
        .join()
        .expect("restart serve thread joins")
        .expect("replacement serve loop shuts down");
}

/// Wall budget the watchdog fixture's proposal carries, in seconds.
///
/// The deadline an approval is held to is this budget plus the serve-side
/// transport margin, so a case bounding that deadline derives it from both
/// rather than restating a total that moves when either of them moves.
const WATCHDOG_PROPOSAL_TIMEOUT_SECONDS: u64 = 1;

fn watchdog_fixture() -> (GitFixture, ServeConfig) {
    let fixture = GitFixture::registered();
    let mut registration = fixture.registration.clone();
    registration.proposal_timeout_seconds = WATCHDOG_PROPOSAL_TIMEOUT_SECONDS;
    fixture
        .gateway
        .replace_registration(&registration)
        .expect("short proposal budget is stored");
    let (config, _) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("snapshot is pushed");
    fixture
        .gateway
        .process_request(
            "lane-031",
            r#"{"schema":1,"seq":2,"op":"propose","argv":["/bin/true"],"reason":"watchdog"}"#,
            &config,
        )
        .expect("proposal is queued");
    (fixture, config)
}

/// Approval publishes exactly one typed terminal result for either command exit.
///
/// ´test:unit:approve-watchdog-types-command-exits´
#[test]
fn approve_watchdog_types_command_exits() {
    for (code, expected) in [(0, "ok"), (7, "failed"), (255, "failed")] {
        let (fixture, config) = watchdog_fixture();
        let config =
            config.with_runner_prefix(vec!["/bin/sh".into(), "-c".into(), format!("exit {code}")]);
        let result = fixture
            .gateway
            .approve_proposal("lane-031", 2, false, None, &config)
            .expect("approval returns a terminal result");
        assert_eq!(
            serde_json::to_value(&result).expect("result encodes")["verdict"],
            expected
        );
        assert_eq!(result.exit_code, code);
        fixture
            .gateway
            .reconcile_open_proposals(usize::MAX)
            .expect("completed approval reconciles");
        let results: Vec<_> = audit_records(&fixture.gateway, "lane-031")
            .into_iter()
            .filter_map(|record| match record.event {
                AuditEvent::Result { result }
                    if result.seq == Some(2) && result.operation == Some(Operation::Run) =>
                {
                    Some(*result)
                }
                _ => None,
            })
            .collect();
        assert_eq!(results, vec![result.clone()]);
        assert_eq!(
            wait_for_result_seq(
                &fixture.registration.worktree.join(".lane/proposals/2.json"),
                2
            ),
            result
        );
    }
}

/// Restart abandons an approval whose predecessor recorded a decision but no result.
///
/// ´test:unit:approve-watchdog-reconciles-interrupted-approval-once´
#[test]
fn approve_watchdog_reconciles_interrupted_approval_once() {
    let (fixture, _) = watchdog_fixture();
    let root = fixture
        .gateway
        .state_dir()
        .join("proposal-verdicts/lane-031");
    fs::create_dir_all(&root).expect("verdict directory exists");
    fs::write(root.join("2.json"), r#"{"schema":1,"actor":"orchestrator","verdict":{"seq":2,"decision":"approved","wall_millis":0},"resolved_unix_ms":1}"#).expect("interrupted approval is stored");
    for _ in 0..2 {
        fixture
            .gateway
            .reconcile_open_proposals(usize::MAX)
            .expect("restart reconciles");
    }
    let result: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture.result_path()).expect("abandoned approval is published"),
    )
    .expect("result decodes");
    assert_eq!(result["verdict"], "abandoned");
    let count = audit_records(&fixture.gateway, "lane-031").iter().filter(|record| matches!(&record.event, AuditEvent::Result { result } if result.seq == Some(2) && result.operation == Some(Operation::Run))).count();
    assert_eq!(count, 1);
}

/// A descendant retaining output pipes cannot hold approval beyond budget plus margin.
///
/// ´test:unit:approve-watchdog-bounds-output-collection´
#[test]
fn approve_watchdog_bounds_output_collection() {
    const MARKER: &str = "LANE_GATEWAY_WATCHDOG_TEST_CHILD";
    if std::env::var_os(MARKER).is_none() {
        let output = Command::new(std::env::current_exe().expect("test executable exists"))
            .args([
                "--exact",
                "tests::approve_watchdog_bounds_output_collection",
                "--nocapture",
            ])
            .env(MARKER, "1")
            .env("LANE_GATEWAY_APPROVE_MARGIN_SECONDS", "1")
            .env(
                "LANE_GATEWAY_RUNNER_ARGV",
                r#"["/bin/sh","-c","sleep 4 & printf partial; exit 0"]"#,
            )
            .output()
            .expect("isolated environment test runs");
        assert_process_group_child_test(&output);
        return;
    }
    let (fixture, _) = watchdog_fixture();
    let config = ServeConfig::from_environment(&fixture.gateway)
        .expect("margin environment is valid")
        .with_runner_termination_grace(Duration::from_millis(50));
    let started = Instant::now();
    let result = fixture
        .gateway
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect("hung output has a terminal result");
    let elapsed = started.elapsed();
    let deadline = Duration::from_secs(
        WATCHDOG_PROPOSAL_TIMEOUT_SECONDS + config.approve_deadline_margin_seconds(),
    );
    // The deadline is the proposal's wall budget plus the configured transport margin, and the
    // bound adds a second for the spawn, the termination grace and the scheduling around them.
    // Both come from the values the fixture set, so the message cannot drift from what is asserted.
    let bound = deadline + Duration::from_secs(1);
    assert!(
        elapsed < bound,
        "approval took {elapsed:?}, past the {bound:?} allowed for its {deadline:?} deadline"
    );
    assert_eq!(
        serde_json::to_value(&result).expect("result encodes")["verdict"],
        "timed-out"
    );
}

/// The proposing lane withdraws either open state while advancing its request sequence.
///
/// ´test:unit:withdraw-proposal-closes-only-the-original-sequence´
#[test]
fn withdraw_proposal_closes_only_the_original_sequence() {
    for parked in [false, true] {
        let fixture = Fixture::registered();
        let config = serve_config(&fixture.gateway);
        fixture
            .gateway
            .process_request("lane-031", &proposal_request(1, "withdraw me"), &config)
            .expect("proposal is queued");
        fixture
            .gateway
            .process_request("lane-031", &proposal_request(2, "keep me"), &config)
            .expect("second proposal is queued");
        if parked {
            write_park_marker(&fixture.gateway, "lane-031", 1, 600);
            fixture
                .gateway
                .reconcile_open_proposals(usize::MAX)
                .expect("park marker reconciles");
        }
        let result = fixture.gateway.process_request("lane-031", r#"{"schema":1,"seq":3,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#, &config).expect("withdrawal is handled");
        assert_eq!(
            serde_json::to_value(&result).expect("result encodes")["verdict"],
            "withdrawn"
        );
        assert_eq!(result.seq, Some(3));
        let queue = fixture.gateway.proposals().expect("queue is readable");
        assert_eq!(
            queue
                .proposals
                .iter()
                .map(|proposal| proposal.seq)
                .collect::<Vec<_>>(),
            vec![2]
        );
        let path = fixture.registration.worktree.join(".lane/proposals/1.json");
        let terminal = wait_for_result_seq(&path, 1);
        assert_eq!(
            serde_json::to_value(&terminal).expect("terminal encodes")["verdict"],
            "withdrawn"
        );
        fs::remove_file(&path).expect("projection loss is simulated");
        for _ in 0..2 {
            fixture
                .gateway
                .reconcile_open_proposals(usize::MAX)
                .expect("withdrawal reconciles");
        }
        assert_eq!(wait_for_result_seq(&path, 1), terminal);
        let count = audit_records(&fixture.gateway, "lane-031").iter().filter(|record| matches!(&record.event, AuditEvent::Result { result } if result.seq == Some(1) && serde_json::to_value(result).expect("result encodes")["verdict"] == "withdrawn")).count();
        assert_eq!(count, 1);
        let repeat = fixture.gateway.process_request("lane-031", r#"{"schema":1,"seq":4,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#, &config).expect("repeat is refused");
        assert_eq!(
            serde_json::to_value(repeat).expect("refusal encodes")["refusal"]["rule"],
            "proposal_not_open"
        );
        assert!(
            fixture
                .gateway
                .approve_proposal("lane-031", 1, false, None, &config)
                .is_err()
        );
    }
}

/// An authenticated request channel cannot withdraw another lane's proposal.
///
/// ´test:unit:withdraw-proposal-refuses-a-different-lane´
#[test]
fn withdraw_proposal_refuses_a_different_lane() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "owned proposal"), &config)
        .expect("proposal is queued");
    let mut other = fixture.registration.clone();
    other.lane = "lane-other".to_owned();
    other.worktree = fixture
        .registration
        .worktree
        .with_file_name("other-worktree");
    fs::create_dir(&other.worktree).expect("other worktree exists");
    fixture
        .gateway
        .register(&other)
        .expect("other lane is registered");
    let result = fixture
        .gateway
        .process_request(
            "lane-other",
            r#"{"schema":1,"seq":1,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#,
            &config,
        )
        .expect("foreign withdrawal is refused");
    assert_eq!(
        serde_json::to_value(result).expect("refusal encodes")["refusal"]["rule"],
        "withdraw_not_owner"
    );
    let queue = fixture.gateway.proposals().expect("queue survives");
    assert_eq!(queue.proposals.len(), 1);
    assert_eq!(queue.proposals[0].lane, "lane-031");
    assert_eq!(
        fixture
            .gateway
            .request_watermark("lane-other")
            .expect("watermark is readable"),
        None
    );
}

/// Withdrawal target fields are exclusive to the new operation and strictly typed.
///
/// ´test:unit:withdraw-proposal-rejects-invalid-shapes´
#[test]
fn withdraw_proposal_rejects_invalid_shapes() {
    let fixture = Fixture::registered();
    for source in [
        r#"{"schema":1,"seq":1,"op":"withdraw"}"#,
        r#"{"schema":1,"seq":1,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1,"argv":["true"]}"#,
        r#"{"schema":1,"seq":1,"op":"push","proposal_lane":"lane-031","proposal_seq":1}"#,
    ] {
        let result = fixture
            .gateway
            .validate_request("lane-031", source)
            .expect("shape validation completes");
        let encoded = serde_json::to_value(result).expect("validation encodes");
        assert_eq!(
            encoded["outcome"]["refusal"]["rule"],
            "withdraw_shape_invalid"
        );
    }
}

/// Serve publishes withdrawal acknowledgement separately from the proposal's terminal result.
///
/// ´test:unit:withdraw-proposal-through-serve-request-channel´
#[test]
fn withdraw_proposal_through_serve_request_channel() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_poll_interval_millis(5);
    fixture
        .gateway
        .process_request(
            "lane-031",
            &proposal_request(1, "withdraw through serve"),
            &config,
        )
        .expect("proposal is queued");
    let directory = fixture.registration.worktree.join(".lane");
    fs::create_dir_all(&directory).expect("protocol directory exists");
    fs::write(
        directory.join("request.json"),
        r#"{"schema":1,"seq":2,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#,
    )
    .expect("withdrawal request is published");
    let server = start_server(fixture.gateway, config.clone());
    let result = wait_for_result_seq(&directory.join("result.json"), 2);
    fs::write(config.shutdown_file(), b"stop").expect("shutdown flag is written");
    join_server_bounded(server).expect("serve exits cleanly");
    assert_eq!(
        serde_json::to_value(result).expect("result encodes")["verdict"],
        "withdrawn"
    );
    assert_eq!(
        serde_json::to_value(wait_for_result_seq(&directory.join("proposals/1.json"), 1))
            .expect("proposal encodes")["verdict"],
        "withdrawn"
    );
}

fn runner_tree_config(
    fixture: &GitFixture,
    config: ServeConfig,
    ignore_term: bool,
) -> (ServeConfig, RunnerTreeGuard) {
    let script = fixture.directory.path().join("runner-tree.sh");
    let record = fixture.directory.path().join("runner-tree");
    let source = if ignore_term {
        r#"record=$1
trap '' TERM
sleep 300 >/dev/null 2>&1 &
printf '%s\n' "$!" > "$record.child"
printf '%s\n' "$$" > "$record.parent"
cat /proc/$$/stat > "$record.stat"
wait
"#
    } else {
        r#"record=$1
trap 'wait; exit 0' TERM
/bin/sh -c 'trap '\''printf term > "$1.term"; exit 0'\'' TERM; printf ready > "$1.ready"; while :; do sleep 0.05; done' sh "$record" >/dev/null 2>&1 &
printf '%s\n' "$!" > "$record.child"
printf '%s\n' "$$" > "$record.parent"
cat /proc/$$/stat > "$record.stat"
wait
"#
    };
    fs::write(&script, source).expect("runner process tree script is written");
    let config = config.with_runner_prefix(vec![
        "/bin/sh".into(),
        script.to_string_lossy().into_owned(),
        record.to_string_lossy().into_owned(),
    ]);
    (config, RunnerTreeGuard::new(record))
}

struct RunnerTreeGuard {
    record: PathBuf,
    armed: bool,
}

impl RunnerTreeGuard {
    fn new(record: PathBuf) -> Self {
        Self {
            record,
            armed: true,
        }
    }

    fn clean(&mut self) {
        if self.armed {
            clean_runner_tree(&self.record);
            self.armed = false;
        }
    }
}

impl std::ops::Deref for RunnerTreeGuard {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.record
    }
}

impl Drop for RunnerTreeGuard {
    fn drop(&mut self) {
        self.clean();
    }
}

fn runner_tree_pid(record: &Path, extension: &str) -> i32 {
    fs::read_to_string(record.with_extension(extension))
        .expect("runner pid was recorded")
        .trim()
        .parse()
        .expect("runner pid is numeric")
}

fn runner_tree_alive(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|source| {
        source
            .rsplit_once(") ")
            .is_some_and(|(_, fields)| !fields.starts_with("Z "))
    })
}

fn clean_runner_tree(record: &Path) {
    for extension in ["child", "parent"] {
        if let Ok(source) = fs::read_to_string(record.with_extension(extension))
            && let Ok(pid) = source.trim().parse()
        {
            let _ignored = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

/// Timeout addresses the isolated runner group so descendants receive TERM too.
///
/// # Panics
/// Panics if descendant readiness is never observed or group termination violates the contract.
///
/// ´test:unit:runner-group-timeout-forwards-term-to-descendants´
#[test]
fn runner_group_timeout_forwards_term_to_descendants() {
    for attempt in 1..=3 {
        if runner_group_timeout_after_descendant_ready(attempt) {
            return;
        }
    }
    panic!("descendant TERM-trap readiness was never observed in three attempts");
}

fn runner_group_timeout_after_descendant_ready(attempt: usize) -> bool {
    let (fixture, config) = watchdog_fixture();
    let (config, mut record) = runner_tree_config(&fixture, config, false);
    let started = Instant::now();
    let (result, ready) = thread::scope(|scope| {
        let approval = scope.spawn(|| {
            fixture
                .gateway
                .approve_proposal("lane-031", 2, false, None, &config)
                .expect("timeout returns a result")
        });
        // The marker follows trap installation. Observe it while approval runs;
        // a timeout before startup cannot establish the TERM-forwarding claim.
        while !record.with_extension("ready").exists()
            && !approval.is_finished()
            && started.elapsed() < FIXTURE_WAIT
        {
            thread::sleep(Duration::from_millis(5));
        }
        let ready = record.with_extension("ready").exists();
        (approval.join().expect("approval joins"), ready)
    });
    writeln!(
        std::io::stderr().lock(),
        "runner-tree-precondition attempt={attempt} ready={ready} wall={:?}",
        started.elapsed()
    )
    .expect("readiness observation is written");
    if !ready {
        return false;
    }
    let child_alive = runner_tree_alive(runner_tree_pid(&record, "child"));
    let term_forwarded = record.with_extension("term").exists();
    let stat =
        fs::read_to_string(record.with_extension("stat")).expect("runner identity was recorded");
    let (_, fields) = stat.rsplit_once(") ").expect("process stat has fields");
    let pgid: i32 = fields
        .split_whitespace()
        .nth(2)
        .expect("group field exists")
        .parse()
        .expect("group is numeric");
    let parent = runner_tree_pid(&record, "parent");
    record.clean();
    assert_eq!(pgid, parent, "runner must lead its own process group");
    assert!(term_forwarded, "descendant never received TERM");
    assert!(!child_alive, "descendant survived abandonment");
    assert_eq!(result.verdict, ResultVerdict::TimedOut);
    true
}

/// A runner ignoring TERM gets the ten-second grace before its entire group is killed.
///
/// ´test:unit:runner-group-timeout-escalates-after-grace´
#[test]
fn runner_group_timeout_escalates_after_grace() {
    let (fixture, config) = watchdog_fixture();
    // A loaded shared node may deschedule the observer after KILL. Keep the
    // one-second budget and ten-second grace, but give observation 120 seconds:
    // 1 + 129 - 10. This remains below the descendant's 300-second natural exit.
    let config = config.with_approve_deadline_margin_seconds(129);
    let (config, mut record) = runner_tree_config(&fixture, config, true);
    let started = Instant::now();
    let result = fixture
        .gateway
        .approve_proposal("lane-031", 2, false, None, &config)
        .expect("escalation returns a result");
    let published = wait_for_result_seq(
        &fixture.registration.worktree.join(".lane/proposals/2.json"),
        2,
    );
    // Serve reserves one termination grace before the approval deadline for
    // output cleanup. The ceiling is the same instant: 1 s runner budget +
    // 129 s approval margin - 10 s grace = 120 s, allowing loaded-node scheduling.
    let approval_deadline = Duration::from_secs(
        WATCHDOG_PROPOSAL_TIMEOUT_SECONDS + config.approve_deadline_margin_seconds(),
    );
    let bound = approval_deadline.saturating_sub(config.runner_termination_grace());
    let child = runner_tree_pid(&record, "child");
    // Serve reaps the group leader; the KILLed descendant dies asynchronously.
    while runner_tree_alive(child) && started.elapsed() < bound {
        thread::sleep(Duration::from_millis(5));
    }
    let child_alive = runner_tree_alive(child);
    let elapsed = started.elapsed();
    // The descendant ignores TERM and sleeps for 300 seconds, beyond the
    // approval deadline and test ceiling. Its death with TimedOut proves KILL.
    assert!(
        !child_alive,
        "TERM-resistant descendant survived abandonment"
    );
    assert_eq!(result.verdict, ResultVerdict::TimedOut);
    assert_eq!(published, result, "escalation result was not published");
    // The lower bound includes the one-second budget and ten-second grace.
    assert!(
        elapsed >= Duration::from_secs(11),
        "KILL skipped the termination grace"
    );
    assert!(
        elapsed < bound,
        "termination exceeded its bounded grace: observed death and result after {elapsed:?}, bound {bound:?}"
    );
    record.clean();
}

/// A replacement serve reaps the runner left by a killed approver before publishing abandonment.
///
/// ´test:unit:runner-group-restart-reaps-abandoned-approval´
#[test]
fn runner_group_restart_reaps_abandoned_approval() {
    const MARKER: &str = "LANE_GATEWAY_REAP_TEST_STATE";
    if let Some(state) = std::env::var_os(MARKER) {
        let gateway = configured_gateway(PathBuf::from(state));
        let config = ServeConfig::from_environment(&gateway).expect("child runner config is valid");
        gateway
            .approve_proposal("lane-031", 2, false, None, &config)
            .expect("child approval executes");
        return;
    }
    let (fixture, config) = watchdog_fixture();
    let (config, mut record) = runner_tree_config(&fixture, config, false);
    let mut approver = Command::new(std::env::current_exe().expect("test executable exists"))
        .args([
            "--exact",
            "tests::runner_group_restart_reaps_abandoned_approval",
        ])
        .env(MARKER, fixture.gateway.state_dir())
        .env(
            "LANE_GATEWAY_RUNNER_ARGV",
            serde_json::to_string(config.runner_prefix()).expect("runner prefix encodes"),
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("approver subprocess starts");
    wait_for_text(&record.with_extension("ready"), "ready");
    let group_path = fixture
        .gateway
        .state_dir()
        .join("runner-groups/lane-031/2.json");
    wait_for_json(&group_path);
    approver.kill().expect("predecessor is killed");
    approver.wait().expect("predecessor is reaped");
    fs::write(config.shutdown_file(), b"stop").expect("replacement will stop after reconciliation");
    let reconciled = fixture.gateway.serve(&config);
    let child_alive = runner_tree_alive(runner_tree_pid(&record, "child"));
    let term_forwarded = record.with_extension("term").exists();
    record.clean();
    reconciled.expect("replacement reconciles cleanly");
    assert!(!child_alive, "replacement left predecessor's runner alive");
    assert!(term_forwarded, "replacement skipped TERM forwarding");
    assert_eq!(
        wait_for_result_seq(
            &fixture.registration.worktree.join(".lane/proposals/2.json"),
            2
        )
        .verdict,
        ResultVerdict::Abandoned
    );
}

/// Restart reaps an interrupted roster runner even when no proposal body exists.
///
/// The group record is written after the runner is spawned, so observing it is
/// the precondition for killing the predecessor. A kill placed before that
/// record tests no persisted runner for the replacement to reap.
///
/// ´test:unit:runner-group-restart-reaps-roster-run´
#[test]
fn runner_group_restart_reaps_roster_run() {
    const MARKER: &str = "LANE_GATEWAY_ROSTER_REAP_TEST_STATE";
    if let Some(state) = std::env::var_os(MARKER) {
        let gateway = configured_gateway(PathBuf::from(state));
        let config = ServeConfig::from_environment(&gateway).expect("child runner config is valid");
        gateway.serve(&config).expect("child serves roster run");
        return;
    }
    let fixture = GitFixture::registered();
    let (config, _) = fixture.runner_config(512 * 1_024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("snapshot is pushed");
    let (config, mut record) = runner_tree_config(&fixture, config, false);
    fs::create_dir_all(fixture.registration.worktree.join(".lane"))
        .expect("request directory exists");
    fs::write(
        fixture.request_path(),
        r#"{"schema":1,"seq":2,"op":"run","command":"clippy"}"#,
    )
    .expect("roster request is written");
    let mut server = Command::new(std::env::current_exe().expect("test executable exists"))
        .args(["--exact", "tests::runner_group_restart_reaps_roster_run"])
        .env(MARKER, fixture.gateway.state_dir())
        .env(
            "LANE_GATEWAY_RUNNER_ARGV",
            serde_json::to_string(config.runner_prefix()).expect("runner prefix encodes"),
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("serve subprocess starts");
    wait_for_text(&record.with_extension("ready"), "ready");
    let group_path = fixture
        .gateway
        .state_dir()
        .join("runner-groups/lane-031/2.json");
    wait_for_json(&group_path);
    server.kill().expect("predecessor is killed");
    server.wait().expect("predecessor is reaped");
    assert!(group_path.exists(), "interrupted runner record exists");
    assert_eq!(
        fixture
            .gateway
            .proposals()
            .expect("queue is readable")
            .proposals
            .len(),
        0
    );
    fs::write(config.shutdown_file(), b"stop").expect("replacement stops after reconciliation");
    let reconciled = fixture.gateway.serve(&config);
    let child_alive = runner_tree_alive(runner_tree_pid(&record, "child"));
    let term_forwarded = record.with_extension("term").exists();
    record.clean();
    reconciled.expect("replacement reconciles cleanly");
    assert!(!child_alive, "replacement left roster runner alive");
    assert!(term_forwarded, "replacement skipped TERM forwarding");
    assert!(!group_path.exists(), "reaped runner record is removed");
    assert!(!fixture.gateway.state_dir().join("locks/lane-031").exists());
}

/// Recovery removes stale records without signalling an absent or replaced leader.
///
/// ´test:unit:runner-group-recovery-requires-the-recorded-leader´
#[test]
fn runner_group_recovery_requires_the_recorded_leader() {
    for absent in [true, false] {
        let fixture = GitFixture::registered();
        let (config, _) = fixture.runner_config(512 * 1_024);
        let (config, mut record) = runner_tree_config(&fixture, config, false);
        let mut leader = Command::new(&config.runner_prefix()[0])
            .args(&config.runner_prefix()[1..])
            .process_group(0)
            .spawn()
            .expect("recorded runner starts");
        wait_for_text(&record.with_extension("ready"), "ready");
        let start_ticks = wait_for_start_ticks(&record.with_extension("stat"));
        let group = leader.id();
        if absent {
            leader.kill().expect("recorded leader exits");
            leader.wait().expect("recorded leader is reaped");
        }
        let path = fixture
            .gateway
            .state_dir()
            .join("runner-groups/lane-031/2.json");
        fs::create_dir_all(path.parent().expect("record has parent"))
            .expect("runner record directory exists");
        fs::write(
            &path,
            serde_json::json!({
                "group": group,
                "start_ticks": if absent { start_ticks } else { start_ticks + 1 }
            })
            .to_string(),
        )
        .expect("stale identity is recorded");
        let reaped = fixture.gateway.reap_runner_group("lane-031", 2);
        let child_alive = runner_tree_alive(runner_tree_pid(&record, "child"));
        let term_forwarded = record.with_extension("term").exists();
        record.clean();
        leader.wait().expect("test leader is reaped");
        reaped.expect("stale record reconciles");
        assert!(child_alive, "stale identity signalled an unrelated group");
        assert!(!term_forwarded, "stale identity delivered TERM");
        assert!(!path.exists(), "stale record is removed");
    }
}

/// What one reconciliation did to the group a stale record names.
struct RecordedBootOutcome {
    child_alive: bool,
    term_forwarded: bool,
    record_present: bool,
}

/// Reconcile one record naming a live leader, recorded under `boot_id`.
///
/// The recorded pid and start ticks are the running leader's own, so the boot
/// identity is the only thing that can hold the signal back: a group that
/// survives this reconciliation survived it on the boot identity alone. A
/// record without the field is written by passing `None`.
///
/// # Panics
///
/// Panics if the fixture cannot start or record its runner, or if
/// reconciliation fails, neither of which a passing run can arrange.
fn reconcile_recorded_boot(boot_id: Option<&str>) -> RecordedBootOutcome {
    let fixture = GitFixture::registered();
    let (config, _) = fixture.runner_config(512 * 1_024);
    let (config, mut record) = runner_tree_config(&fixture, config, false);
    let mut leader = Command::new(&config.runner_prefix()[0])
        .args(&config.runner_prefix()[1..])
        .process_group(0)
        .spawn()
        .expect("recorded runner starts");
    wait_for_text(&record.with_extension("ready"), "ready");
    let start_ticks = wait_for_start_ticks(&record.with_extension("stat"));
    let path = fixture
        .gateway
        .state_dir()
        .join("runner-groups/lane-031/2.json");
    fs::create_dir_all(path.parent().expect("record has parent"))
        .expect("runner record directory exists");
    let mut body = serde_json::json!({"group": leader.id(), "start_ticks": start_ticks});
    if let Some(boot_id) = boot_id {
        body["boot_id"] = serde_json::Value::from(boot_id);
    }
    fs::write(&path, body.to_string()).expect("foreign identity is recorded");
    let reaped = fixture.gateway.reap_runner_group("lane-031", 2);
    let outcome = RecordedBootOutcome {
        child_alive: runner_tree_alive(runner_tree_pid(&record, "child")),
        term_forwarded: record.with_extension("term").exists(),
        record_present: path.exists(),
    };
    record.clean();
    leader.wait().expect("test leader is reaped");
    reaped.expect("record from another boot reconciles");
    outcome
}

/// Recovery removes a record from another boot without signalling the group the
/// kernel has since handed that pid to.
///
/// ´test:unit:runner-group-recovery-requires-the-recording-boot´
#[test]
fn runner_group_recovery_requires_the_recording_boot() {
    let outcome = reconcile_recorded_boot(Some("00000000-0000-0000-0000-000000000000"));

    assert!(
        outcome.child_alive,
        "a record from another boot signalled a live group"
    );
    assert!(
        !outcome.term_forwarded,
        "a record from another boot delivered TERM"
    );
    assert!(
        !outcome.record_present,
        "a record from another boot is removed"
    );
}

/// A record predating the boot identity names no boot, so it is discarded on the
/// same conservative terms rather than matched on its pid alone.
///
/// ´test:unit:runner-group-recovery-discards-a-record-without-a-boot´
#[test]
fn runner_group_recovery_discards_a_record_without_a_boot() {
    let outcome = reconcile_recorded_boot(None);

    assert!(
        outcome.child_alive,
        "a record naming no boot signalled a live group"
    );
    assert!(
        !outcome.term_forwarded,
        "a record naming no boot delivered TERM"
    );
    assert!(
        !outcome.record_present,
        "a record naming no boot is removed"
    );
}

fn assert_process_group_child_test(output: &Output) {
    assert!(
        output.status.success(),
        "output deadline child failed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| line == "running 1 test")
            && stdout
                .lines()
                .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;")),
        "process-group child must run exactly one test: {output:?}"
    );
}

/// A successful child exit cannot hide an empty exact test selection.
///
/// ´test:unit:process-group-child-rejects-zero-selected-tests´
#[test]
#[should_panic(expected = "process-group child must run exactly one test")]
fn process_group_child_rejects_zero_selected_tests() {
    let output = Command::new(std::env::current_exe().expect("test executable exists"))
        .args(["--exact", "tests::missing_process_group_regression"])
        .output()
        .expect("empty-selection child runs");
    assert_process_group_child_test(&output);
}

/// A withdrawal's proposal projection includes the operation's measured wall.
///
/// ´test:unit:withdrawal-result-measures-elapsed-wall´
#[test]
fn withdrawal_result_measures_elapsed_wall() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "withdraw timing"), &config)
        .expect("proposal is queued");
    let request = crate::types::parse_request(
        r#"{"schema":1,"seq":2,"op":"withdraw","proposal_lane":"lane-031","proposal_seq":1}"#,
    )
    .expect("withdrawal request is valid");
    let _lock = fixture
        .gateway
        .lock_lane("lane-031")
        .expect("withdrawal owns its lane lock");
    let started = Instant::now()
        .checked_sub(Duration::from_millis(50))
        .expect("test start time is representable");
    let acknowledgement = fixture
        .gateway
        .withdraw_proposal_locked(&fixture.registration, &request, &config, started)
        .expect("withdrawal completes");
    let terminal = wait_for_result_seq(
        &fixture.registration.worktree.join(".lane/proposals/1.json"),
        1,
    );
    assert!(
        terminal.wall_millis >= 50,
        "withdrawal result discarded elapsed wall"
    );
    assert!(terminal.wall_millis <= acknowledgement.wall_millis);
}

/// Recovery measures from the durable withdrawal decision and preserves audited wall.
///
/// ´test:unit:withdrawal-recovery-measures-elapsed-wall´
#[test]
fn withdrawal_recovery_measures_elapsed_wall() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway);
    fixture
        .gateway
        .process_request("lane-031", &proposal_request(1, "recover timing"), &config)
        .expect("proposal is queued");
    let root = fixture
        .gateway
        .state_dir()
        .join("proposal-verdicts/lane-031");
    fs::create_dir_all(&root).expect("verdict directory exists");
    let resolved = crate::gateway::timestamp_unix_ms().expect("clock is readable") - 250;
    fs::write(
        root.join("1.json"),
        serde_json::json!({
            "schema": 1, "actor": "lane",
            "verdict": { "seq": 1, "decision": "withdrawn", "wall_millis": 50 },
            "resolved_unix_ms": resolved
        })
        .to_string(),
    )
    .expect("interrupted withdrawal is recorded");
    fixture
        .gateway
        .reconcile_open_proposals(usize::MAX)
        .expect("withdrawal reconciles");
    let path = fixture.registration.worktree.join(".lane/proposals/1.json");
    let terminal = wait_for_result_seq(&path, 1);
    assert!(
        terminal.wall_millis >= 300,
        "recovery discarded elapsed wall"
    );
    fs::remove_file(&path).expect("projection loss is simulated");
    fixture
        .gateway
        .reconcile_open_proposals(usize::MAX)
        .expect("audited withdrawal repairs");
    assert_eq!(wait_for_result_seq(&path, 1), terminal);
}

/// A zero builder margin is refused before a serve generation can start.
///
/// ´test:unit:approve-margin-zero-refuses-serve´
#[test]
fn approve_margin_zero_refuses_serve() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_approve_deadline_margin_seconds(0);
    fs::write(config.shutdown_file(), b"stop").expect("serve will stop after validation");
    assert!(matches!(
        fixture.gateway.serve(&config),
        Err(GatewayError::InvalidServeConfig)
    ));
}

/// A zero builder margin cannot consume a request sequence through the direct API.
///
/// ´test:unit:approve-margin-zero-refuses-request´
#[test]
fn approve_margin_zero_refuses_request() {
    let fixture = Fixture::registered();
    let config = serve_config(&fixture.gateway).with_approve_deadline_margin_seconds(0);
    assert!(matches!(
        fixture.gateway.process_request(
            "lane-031",
            &proposal_request(1, "invalid margin"),
            &config
        ),
        Err(GatewayError::InvalidServeConfig)
    ));
    assert_eq!(
        fixture
            .gateway
            .request_watermark("lane-031")
            .expect("watermark is readable"),
        None
    );
}

/// A zero builder margin cannot claim an approval through the direct API.
///
/// ´test:unit:approve-margin-zero-refuses-approval´
#[test]
fn approve_margin_zero_refuses_approval() {
    let (fixture, config) = watchdog_fixture();
    let config = config.with_approve_deadline_margin_seconds(0);
    assert!(matches!(
        fixture
            .gateway
            .approve_proposal("lane-031", 2, false, None, &config),
        Err(GatewayError::InvalidServeConfig)
    ));
    assert_eq!(
        fixture
            .gateway
            .proposals()
            .expect("proposal remains open")
            .proposals
            .len(),
        1
    );
}

/// The environment margin shares the builder's positive-only boundary.
///
/// ´test:unit:approve-margin-environment-requires-positive-value´
#[test]
fn approve_margin_environment_requires_positive_value() {
    const MARKER: &str = "LANE_GATEWAY_MARGIN_TEST_CHILD";
    if let Ok(value) = std::env::var(MARKER) {
        let fixture = Fixture::registered();
        let config = ServeConfig::from_environment(&fixture.gateway);
        if value == "0" {
            assert!(matches!(config, Err(GatewayError::InvalidServeConfig)));
        } else {
            assert_eq!(
                config
                    .expect("positive margin is valid")
                    .approve_deadline_margin_seconds(),
                1
            );
        }
        return;
    }
    for value in ["0", "1"] {
        let output = Command::new(std::env::current_exe().expect("test executable exists"))
            .args([
                "--exact",
                "tests::approve_margin_environment_requires_positive_value",
            ])
            .env(MARKER, value)
            .env("LANE_GATEWAY_APPROVE_MARGIN_SECONDS", value)
            .env("LANE_GATEWAY_RUNNER_ARGV", r#"["/bin/true"]"#)
            .output()
            .expect("isolated margin test runs");
        assert_process_group_child_test(&output);
    }
}

fn decide_common(gateway: &Gateway, seq: u64, answer: &serde_json::Value) {
    use std::process::Stdio;
    let base = gateway
        .state_dir()
        .parent()
        .expect("parent")
        .join("request-owner");
    let context = base.join("orchestrator.json");
    fs::write(
        &context,
        serde_json::json!({"hook_event_name":"PreToolUse","permission_mode":"default",
        "session_id":"fixture","cwd":base,"transcript_path":base.join("transcript.jsonl"),
        "tool_name":"Bash","tool_use_id":"review","tool_input":{"command":"review"}})
        .to_string(),
    )
    .expect("caller context");
    let id = gateway
        .common_proposal_id("lane-031", seq)
        .expect("common id");
    let document = serde_json::json!({"schema":1,"items":[{"id":id,"decision":{"answer":answer,"reason":"fixture review"}}]});
    let mut child =
        Command::new(std::env::var_os("SUPERLOOP_TEST_REQUESTS_HELPER").expect("built helper"))
            .args(["triage", "--loop", "fixture"])
            .env_clear()
            .env("PERMISSION_TRIAGE_LOOP_REGISTRY", base.join("registry"))
            .env("PERMISSION_TRIAGE_REQUEST_CONTEXT", context)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("review helper");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(document.to_string().as_bytes())
        .expect("decision input");
    let output = child.wait_with_output().expect("decision status");
    assert!(
        output.status.success(),
        "triage status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// ´test:unit:gateway-common-migration-preserves-pending-and-parked-projections´
#[test]
fn gateway_common_migration_preserves_pending_and_parked_projections() {
    let fixture = Fixture::registered();
    let root = fixture.gateway.state_dir().join("proposals/lane-031");
    fs::create_dir_all(&root).expect("predecessor queue");
    let projections = fixture.registration.worktree.join(".lane/proposals");
    fs::create_dir_all(&projections).expect("worker projections");
    let now = crate::gateway::timestamp_unix_ms().expect("clock");
    for (seq, queued) in [(1, now), (2, 0)] {
        let proposal = ParkedProposal::new(
            "lane-031",
            seq,
            vec!["/bin/true".into()],
            "migration".into(),
            queued,
            600,
        );
        fs::write(
            root.join(format!("{seq}.json")),
            serde_json::to_vec(&proposal).expect("body"),
        )
        .expect("old body");
        let result = if seq == 1 {
            crate::OperationResult::pending_proposal(seq, 0, 600)
        } else {
            crate::OperationResult::parked_proposal(seq, 0, 600)
        };
        fs::write(
            projections.join(format!("{seq}.json")),
            serde_json::to_vec(&result).expect("projection"),
        )
        .expect("old projection");
    }
    let previous: Vec<_> = [1, 2]
        .map(|seq| fs::read(projections.join(format!("{seq}.json"))).expect("projection bytes"))
        .into();
    assert_eq!(
        fixture.gateway.migrate_proposals().expect("migrate")["migrated"],
        2
    );
    assert_eq!(
        fixture.gateway.migrate_proposals().expect("repeat")["migrated"],
        0
    );
    for (index, seq) in [1, 2].iter().enumerate() {
        assert_eq!(
            fs::read(projections.join(format!("{seq}.json"))).expect("projection retained"),
            previous[index]
        );
        assert!(!root.join(format!("{seq}.json")).exists());
        assert!(
            fixture
                .gateway
                .state_dir()
                .join(format!("migrated-proposals/lane-031/{seq}.json"))
                .exists()
        );
    }
    let restarted = configured_gateway(fixture.gateway.state_dir());
    restarted
        .reconcile_open_proposals(1024 * 1024)
        .expect("restart");
    let queue = restarted.proposals().expect("common pending queue");
    assert_eq!(queue.proposals.len(), 2);
    assert_eq!(queue.proposals[0].state, ProposalState::Pending);
    assert_eq!(queue.proposals[1].state, ProposalState::Parked);
    // Recreate the interrupted predecessor after journal publication. Admission
    // must compare it, retain the same common ID and finish retirement.
    fs::copy(
        fixture
            .gateway
            .state_dir()
            .join("migrated-proposals/lane-031/1.json"),
        root.join("1.json"),
    )
    .expect("interrupted predecessor");
    assert_eq!(
        restarted.migrate_proposals().expect("resume migration")["migrated"],
        1
    );
    assert_eq!(restarted.common_proposals().expect("common rows").len(), 2);
}

/// ´test:unit:gateway-common-decision-executes-once-across-claim-and-restart´
#[test]
fn gateway_common_decision_executes_once_across_claim_and_restart() {
    let fixture = GitFixture::registered();
    let (config, _) = fixture.runner_config(1024 * 1024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("snapshot");
    let count = fixture.directory.path().join("executions");
    let argv = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "printf '%s\\n' \"$2\" >> \"$1\"".to_owned(),
        "fixture".to_owned(),
        count.to_string_lossy().into_owned(),
        "exact argument".to_owned(),
    ];
    let request =
        serde_json::json!({"schema":1,"seq":2,"op":"propose","argv":argv,"reason":"execute once"});
    fixture
        .gateway
        .process_request("lane-031", &request.to_string(), &config)
        .expect("file proposal");
    decide_common(
        &fixture.gateway,
        2,
        &serde_json::json!({"outcome":"approve"}),
    );
    let id = fixture
        .gateway
        .common_proposal_id("lane-031", 2)
        .expect("id");
    fixture
        .gateway
        .request_channel()
        .expect("channel")
        .change(
            "claim",
            &[],
            Some(serde_json::json!({"schema":1,"id":id,"claim":id})),
        )
        .expect("claim before restart");
    let restarted = configured_gateway(fixture.gateway.state_dir());
    restarted
        .service_common_proposals(&config)
        .expect("consume inherited claim");
    assert_eq!(
        fs::read(&count).expect("execution bytes"),
        b"exact argument\n"
    );
    restarted
        .service_common_proposals(&config)
        .expect("repeat service");
    configured_gateway(fixture.gateway.state_dir())
        .service_common_proposals(&config)
        .expect("second restart");
    assert_eq!(
        fs::read(&count).expect("one execution"),
        b"exact argument\n"
    );
    let rows = restarted.common_proposals().expect("common result");
    let budget: serde_json::Value = serde_json::from_slice(
        &fs::read(
            restarted
                .state_dir()
                .join("execution-budgets/lane-031/2.json"),
        )
        .expect("lifecycle execution budget"),
    )
    .expect("budget JSON");
    assert_eq!(
        budget["timeout_seconds"],
        rows[0].body["proposal"]["timeout_seconds"]
    );
    assert_eq!(budget["lane"], "lane-031");
    assert_eq!(budget["seq"], 2);
    assert_eq!(rows[0].state, request_core::State::Completed);
    assert_eq!(rows[0].body["proposal"]["argv"], serde_json::json!(argv));
    assert_eq!(
        rows[0].service_result.as_ref().expect("result")["exit_code"],
        0
    );
}

/// ´test:unit:gateway-check-and-status-leave-missing-and-existing-state-unchanged´
#[test]
fn gateway_check_and_status_leave_missing_and_existing_state_unchanged() {
    use std::os::unix::fs::MetadataExt as _;
    let directory = TestDirectory::new();
    let missing = directory.path().join("absent");
    let gateway = configured_gateway(&missing);
    gateway.status().expect("empty status");
    gateway
        .check_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#)
        .expect("unregistered refusal");
    assert!(!missing.exists());
    let fixture = Fixture::registered();
    fixture
        .gateway
        .validate_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#)
        .expect("intake");
    let paths = [
        fixture.gateway.state_dir().join("audit/lane-031.jsonl"),
        fixture.gateway.state_dir().join("watermarks/lane-031"),
    ];
    let snapshot = || {
        paths
            .iter()
            .map(|path| {
                let metadata = fs::metadata(path).expect("evidence metadata");
                (
                    fs::read(path).expect("evidence"),
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                )
            })
            .collect::<Vec<_>>()
    };
    let before = snapshot();
    fixture
        .gateway
        .check_request("lane-031", r#"{"schema":1,"seq":2,"op":"push"}"#)
        .expect("valid preview");
    fixture
        .gateway
        .check_request("lane-031", "malformed")
        .expect("invalid preview");
    fixture.gateway.status().expect("existing status");
    assert_eq!(snapshot(), before);
}

/// ´test:unit:gateway-common-refusals-and-withdrawal-publish-one-terminal-result´
#[test]
fn gateway_common_refusals_and_withdrawal_publish_one_terminal_result() {
    let fixture = GitFixture::registered();
    let (config, _) = fixture.runner_config(1024 * 1024);
    fixture
        .gateway
        .process_request("lane-031", r#"{"schema":1,"seq":1,"op":"push"}"#, &config)
        .expect("snapshot");
    for (seq, answer, verdict) in [
        (
            2,
            serde_json::json!({"outcome":"approve","promote":"fmt-check"}),
            ResultVerdict::Failed,
        ),
        (
            3,
            serde_json::json!({"outcome":"deny"}),
            ResultVerdict::Denied,
        ),
        (
            4,
            serde_json::json!({"outcome":"abandon"}),
            ResultVerdict::Expired,
        ),
    ] {
        let request = serde_json::json!({"schema":1,"seq":seq,"op":"propose","argv":["/bin/false"],"reason":"refusal fixture"});
        fixture
            .gateway
            .process_request("lane-031", &request.to_string(), &config)
            .expect("file");
        decide_common(&fixture.gateway, seq, &answer);
        fixture
            .gateway
            .service_common_proposals(&config)
            .expect("consume decision");
        let projection = fixture
            .registration
            .worktree
            .join(format!(".lane/proposals/{seq}.json"));
        let before = fs::read(&projection).expect("terminal bytes");
        assert_eq!(
            serde_json::from_slice::<crate::OperationResult>(&before)
                .expect("result")
                .verdict,
            verdict
        );
        configured_gateway(fixture.gateway.state_dir())
            .service_common_proposals(&config)
            .expect("restart");
        assert_eq!(fs::read(projection).expect("same terminal result"), before);
    }
    fixture.gateway.process_request("lane-031", r#"{"schema":1,"seq":5,"op":"propose","argv":["/bin/false"],"reason":"withdraw fixture"}"#, &config).expect("file withdrawal target");
    let id = fixture
        .gateway
        .common_proposal_id("lane-031", 5)
        .expect("id");
    fixture
        .gateway
        .request_channel()
        .expect("channel")
        .change(
            "withdraw",
            &[],
            Some(serde_json::json!({"schema":1,"id":id})),
        )
        .expect("departure before projection");
    let restarted = configured_gateway(fixture.gateway.state_dir());
    restarted
        .service_common_proposals(&config)
        .expect("recover departure");
    restarted
        .service_common_proposals(&config)
        .expect("repeat recovery");
    let projection = fs::read(fixture.registration.worktree.join(".lane/proposals/5.json"))
        .expect("withdrawal projection");
    assert_eq!(
        serde_json::from_slice::<crate::OperationResult>(&projection)
            .expect("result")
            .verdict,
        ResultVerdict::Withdrawn
    );
    let results = restarted.audit_records("lane-031").expect("audit").into_iter().filter(|row| {
        matches!(&row.event, AuditEvent::Result { result } if result.seq == Some(5) && result.verdict == ResultVerdict::Withdrawn)
    }).count();
    assert_eq!(results, 1);
}
