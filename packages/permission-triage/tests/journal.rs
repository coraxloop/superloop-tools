#[path = "support/temporary_root.rs"]
mod temporary_root;

mod support;

use support::SerializedCommand as _;

use std::collections::HashSet;
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use permission_triage::rubric::{GENERAL_RUBRIC_DIGEST, sha256_digest};
use permission_triage::{Journal, MAX_JOURNAL_RECORD_BYTES, load_registry, request_digest};
use serde_json::{Value, json};

use support::write_payload;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new(name: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = temporary_root::temporary_root().join(format!(
            "permission-triage-journal-integration-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique journal fixture directory is created");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn state_root(&self) -> PathBuf {
        let registry = self.0.join("loops.d");
        let mut entries = fs::read_dir(registry)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        entries.sort();
        if let Some(root) = entries
            .iter()
            .filter_map(|path| fs::read_to_string(path).ok())
            .find_map(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("LOOP_STATE_ROOT=").map(PathBuf::from))
            })
        {
            return root;
        }
        fs::create_dir_all(self.0.join("local")).expect("fixture private tree");
        self.0.join("local/state")
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _permissions = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn fake_cli() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-cli.sh")
}

fn hook_command(capture: &Path, response: &str, state_root: Option<&Path>) -> Command {
    let root = state_root.map(Path::to_path_buf);
    let checkout = root
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| capture.parent().expect("fixture parent"));
    let registry = capture.with_extension("defaults.d");
    fs::create_dir_all(&registry).expect("default registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).expect("private registry");
    if let Some(root) = root.as_deref() {
        if root.is_absolute()
            && !root.exists()
            && root.parent().is_some_and(Path::exists)
            && fs::create_dir(root).is_ok()
        {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("private root");
        }
        let entry = registry.join("fixture.env");
        fs::write(
            &entry,
            format!(
                "LOOP_NAME=fixture\nLOOP_SID=session-journal-sentinel\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                checkout.display(),
                root.display()
            ),
        )
        .expect("default entry");
        fs::set_permissions(entry, fs::Permissions::from_mode(0o600)).expect("private entry");
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_permission-triage-hook"));
    command
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PERMISSION_TRIAGE_MODE", "enforce")
        .env_remove("PERMISSION_TRIAGE_NESTED")
        .env_remove("PERMISSION_TRIAGE_OWNER_RUBRIC")
        .env_remove("PERMISSION_TRIAGE_MODEL")
        .env_remove("PERMISSION_TRIAGE_ISOLATION")
        .env_remove("PERMISSION_TRIAGE_MODEL_DEADLINE_MS")
        .env_remove("PERMISSION_TRIAGE_STATE_ROOT")
        .env("PERMISSION_TRIAGE_LOOP_REGISTRY", registry)
        .env("TRIAGE_TEST_CHECKOUT", checkout)
        .env("PERMISSION_TRIAGE_FAKE_SCOPE", "loop")
        .env("PERMISSION_TRIAGE_CLI", fake_cli())
        .env("PERMISSION_TRIAGE_FAKE_CAPTURE", capture)
        .env("PERMISSION_TRIAGE_FAKE_RESPONSE", response)
        .env("PERMISSION_TRIAGE_MODEL_DEADLINE_MS", "2000");
    if let Some(root) = state_root {
        command.env("PERMISSION_TRIAGE_STATE_ROOT", root);
    }
    command
}

fn review_registry(state_root: &Path) -> PathBuf {
    let checkout = state_root
        .parent()
        .and_then(Path::parent)
        .expect("review fixture checkout");
    state_root
        .ancestors()
        .take(4)
        .map(|path| path.join("loops.d"))
        .find(|path| path.is_dir())
        .unwrap_or_else(|| {
            let registry = checkout.join("review-loops.d");
            fs::create_dir_all(&registry).expect("review registry");
            fs::set_permissions(&registry, fs::Permissions::from_mode(0o700))
                .expect("private review registry");
            let entry = registry.join("fixture.env");
            fs::write(
                &entry,
                format!(
                    "LOOP_NAME=fixture\nLOOP_SID=session-journal-sentinel\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                    checkout.display(),
                    state_root.display()
                ),
            )
            .expect("review entry");
            fs::set_permissions(entry, fs::Permissions::from_mode(0o600))
                .expect("private review entry");
            registry
        })
}

fn review_loop(root: &Path) -> String {
    let registry = load_registry(Some(review_registry(root).into_os_string()))
        .expect("registry")
        .expect("registered loop");
    registry
        .validate_deployment_for_review()
        .expect("review deployment");
    let entry = registry
        .entries()
        .iter()
        .find(|entry| entry.state_root() == Some(root))
        .expect("selected loop");
    let journal = Journal::from_registered_descriptor_for_review(
        entry
            .validated_state_root_for_review()
            .expect("review descriptor"),
        root,
        permission_triage::request::Scope::Loop,
    );
    permission_triage::review::load_selected_review(&journal)
        .expect("loop review")
        .render()
}

fn mark_loop(
    root: &Path,
    registry: &Path,
    input: &[u8],
    event_id: &str,
    outcome: permission_triage::DispositionOutcome,
    detail: permission_triage::DispositionDetail,
) -> Result<(), permission_triage::JournalError> {
    let registry = load_registry(Some(registry.as_os_str().to_owned()))
        .expect("registry")
        .expect("registered loop");
    registry.validate_deployment().expect("deployment");
    let entry = registry
        .entries()
        .iter()
        .find(|entry| entry.state_root() == Some(root))
        .expect("selected loop");
    let journal = Journal::from_registered_descriptor(
        entry.validated_state_root().expect("state descriptor"),
        root,
        permission_triage::request::Scope::Loop,
        permission_triage::journal::RootShape::Private,
    )?;
    let caller = match permission_triage::decode_request(input) {
        permission_triage::DecodeResult::Decoded(request) => permission_triage::resolve_role(
            Some(&registry),
            permission_triage::role::effective_uid().expect("uid"),
            request.session_id(),
            request.cwd(),
            request.transcript_path(),
            request.agent_id_truthy(),
        ),
        permission_triage::DecodeResult::Unclassifiable { .. } => {
            permission_triage::CallerRole::Unknown
        }
    };
    journal.append_disposition(&caller, event_id, outcome, detail)
}

fn request(command: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "session_id": "session-journal-sentinel",
        "transcript_path": "transcript-journal-sentinel",
        "agent_id": "agent-journal-sentinel",
        "cwd": "/workspace/project",
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
            "description": "description-journal-sentinel",
            "future_output": "tool-output-journal-sentinel"
        },
        "tool_use_id": "use-journal"
    }))
    .expect("request fixture serializes")
}

fn role_request(
    session: &str,
    cwd: &Path,
    command: &str,
    tool_use_id: &str,
    transcript_path: Option<&str>,
) -> Vec<u8> {
    let mut value = json!({
        "session_id": session,
        "cwd": cwd,
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": tool_use_id
    });
    if let Some(path) = transcript_path {
        value["transcript_path"] = json!(path);
    }
    serde_json::to_vec(&value).expect("role request serializes")
}

fn registry(directory: &FixtureDirectory, entries: &[(&str, &str, &Path)]) -> PathBuf {
    registry_at(&directory.path().join("loops.d"), entries)
}

fn registry_at(root: &Path, entries: &[(&str, &str, &Path)]) -> PathBuf {
    fs::create_dir(root).expect("registry root is created");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("registry root is private");
    for (name, session, checkout) in entries {
        fs::create_dir_all(checkout.join("local/permissions")).expect("loop checkout is created");
        let state = checkout.join("local/state");
        fs::create_dir_all(&state).expect("registered root exists");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("private registered root");
        let entry = root.join(format!("{name}.env"));
        fs::write(
            &entry,
            format!(
                "LOOP_NAME={name}\nLOOP_SID={session}\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                checkout.display(),
                state.display()
            ),
        )
        .expect("registry entry is written");
        fs::set_permissions(entry, fs::Permissions::from_mode(0o600))
            .expect("registry entry is private");
    }
    root.to_path_buf()
}

fn role_hook_command(
    directory: &FixtureDirectory,
    name: &str,
    response: &str,
    registry: &Path,
) -> (PathBuf, Command) {
    let capture = directory.path().join(name);
    let mut command = hook_command(&capture, response, Some(&directory.state_root()));
    command
        .env("PERMISSION_TRIAGE_LOOP_REGISTRY", registry)
        .env("PERMISSION_TRIAGE_FAKE_SCOPE", "loop");
    (capture, command)
}

fn run(mut command: Command, input: &[u8]) -> Output {
    let checkout = command
        .get_envs()
        .find_map(|(name, value)| (name == "TRIAGE_TEST_CHECKOUT").then_some(value).flatten())
        .map(PathBuf::from);
    let mut parsed = serde_json::from_slice::<Value>(input).ok();
    if let (Some(value), Some(checkout)) = (&mut parsed, checkout)
        && value["cwd"] == "/workspace/project"
    {
        value["cwd"] = json!(checkout);
    }
    let input = parsed
        .and_then(|value| serde_json::to_vec(&value).ok())
        .unwrap_or_else(|| input.to_vec());
    let mut child = command.spawn_serialized().expect("fixture binary starts");
    write_payload(
        child.stdin.take().expect("fixture stdin is piped"),
        &input,
        "fixture input is written",
    );
    child.wait_with_output().expect("fixture binary exits")
}

fn spawn_hook(mut command: Command, input: &[u8]) -> Child {
    let checkout = command
        .get_envs()
        .find_map(|(name, value)| (name == "TRIAGE_TEST_CHECKOUT").then_some(value).flatten())
        .map(PathBuf::from);
    let mut value: Value = serde_json::from_slice(input).expect("concurrent request");
    if value["cwd"] == "/workspace/project"
        && let Some(checkout) = checkout
    {
        value["cwd"] = json!(checkout);
    }
    let input = serde_json::to_vec(&value).expect("concurrent input");
    let mut child = command.spawn_serialized().expect("hook binary starts");
    write_payload(
        child.stdin.take().expect("hook stdin is piped"),
        &input,
        "hook input is written",
    );
    child
}

fn hook_reason(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stderr,
        [] as [u8; 0],
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("hook response is JSON");
    value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("hook reason is a string")
        .to_owned()
}

fn journal_values(root: &Path) -> Vec<Value> {
    let mut records = Vec::new();
    for filename in ["escalations.jsonl", "estate-escalations.jsonl"] {
        let bytes = fs::read(root.join(filename)).unwrap_or_default();
        records.extend(
            bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    serde_json::from_slice::<Value>(line).expect("journal line is valid JSON")
                }),
        );
    }
    if root.join("escalations.jsonl").exists() && root.join("estate-escalations.jsonl").exists() {
        records.sort_by(|a, b| a["recorded_at"].as_str().cmp(&b["recorded_at"].as_str()));
    }
    records
}

fn append_journal_value(root: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec(value).expect("journal fixture serializes");
    bytes.push(b'\n');
    OpenOptions::new()
        .append(true)
        .open(root.join("escalations.jsonl"))
        .expect("journal fixture opens")
        .write_all(&bytes)
        .expect("journal fixture appends");
}

fn append_one(directory: &FixtureDirectory, response: &str, command: &str) -> Output {
    let root = directory.state_root();
    run(
        hook_command(&directory.path().join(response), response, Some(&root)),
        &request(command),
    )
}

fn assert_state_root_refusal(output: &Output, capture: &Path) {
    let reason = hook_reason(output);
    assert_eq!(
        reason,
        "infrastructure-failure: verdict journal failed: journal-degraded evidence could not be retained; the evidence journal is degraded, and the request must be sent to the superloop orchestrator agent for adjudication",
        "\ntest result: PTCLS1-FAIL-BEFORE state-root-precondition"
    );
    assert!(!PathBuf::from(format!("{}.argv", capture.display())).exists());
}

fn assert_named_state_root_refusal(output: &Output, capture: &Path, detail: &str) {
    let reason = hook_reason(output);
    assert!(reason.starts_with("infrastructure-failure: state routing"));
    assert!(reason.contains("registry entry fixture"));
    assert!(
        reason.contains(detail),
        "expected detail {detail:?} in {reason:?}"
    );
    assert!(!PathBuf::from(format!("{}.argv", capture.display())).exists());
}

/// ´test:integration:suspicious-response-appends-one-minimal-escalation-record´
#[test]
fn suspicious_response_appends_one_minimal_escalation_record() {
    let directory = FixtureDirectory::new("minimal");
    let command = "printf journal-command-sentinel";
    let capture = directory.path().join("suspicious-stderr");
    let mut invocation = hook_command(&capture, "suspicious-stderr", Some(&directory.state_root()));
    invocation.env("PERMISSION_TRIAGE_MODEL", "environment-journal-sentinel");
    let output = run(invocation, &request(command));
    assert!(hook_reason(&output).starts_with("escalation:"));
    let root = directory.state_root();
    let bytes = fs::read(root.join("estate-escalations.jsonl")).expect("journal is readable");
    let records = journal_values(&root);
    assert_eq!(records.len(), 1);
    let record = records[0].as_object().expect("journal record is an object");
    assert_eq!(record.len(), 24);
    assert_eq!(record["schema"], 2);
    assert_eq!(record["event"], "escalated");
    assert_eq!(record["tool_use_id"], "use-journal");
    assert_eq!(record["tool"], "Bash");
    assert_eq!(record["cwd"], json!(directory.path()));
    assert_eq!(record["command"], command);
    assert!(!record.contains_key("action"));
    assert_eq!(record["classification"], "suspicious");
    assert_eq!(record["model_status"], "success");
    assert_eq!(record["owner_rubric_digest"], Value::Null);
    for field in ["event_id", "request_digest", "general_rubric_digest"] {
        assert_eq!(record[field].as_str().expect("digest field").len(), 64);
    }
    assert!(
        record["recorded_at"]
            .as_str()
            .expect("timestamp")
            .ends_with('Z')
    );
    assert!(
        record["reason"]
            .as_str()
            .expect("reason")
            .starts_with("escalation:")
    );
    for sentinel in [
        "session-journal-sentinel",
        "transcript-journal-sentinel",
        "agent-journal-sentinel",
        "/registry-journal-sentinel",
        "environment-journal-sentinel",
        "description-journal-sentinel",
        "tool-output-journal-sentinel",
        "fake-cli-stderr-sentinel",
    ] {
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes())
        );
    }
    assert_eq!(record["role"], "orchestrator-subagent");
    assert_eq!(record["loop_name"], "fixture");
    assert_eq!(record["stale_session"], false);
    assert_eq!(record["domain_rubric_digest"], Value::Null);
    assert_eq!(record["scope"], "estate");
    assert_eq!(record["mode"], "enforce");
    assert_eq!(record["would_be_decision"], "deny");
    assert_eq!(record["emitted_decision"], "deny");
    assert!(record["wall_ms"].as_u64().is_some());
    assert!(record["model_wall_ms"].as_u64().is_some());
}

/// ´test:integration:rotated-session-is-unknown-and-false-in-the-journal´
#[test]
fn rotated_session_is_unknown_and_false_in_the_journal() {
    let directory = FixtureDirectory::new("stale-session");
    let checkout = directory.path().join("loop");
    let registry = registry(&directory, &[("orchestration", "old-session", &checkout)]);
    let (_, command) = role_hook_command(&directory, "stale-session", "suspicious", &registry);
    let output = run(
        command,
        &role_request(
            "fresh-session",
            &checkout,
            "printf stale-session",
            "use-stale-session",
            None,
        ),
    );
    let reason = hook_reason(&output);
    assert!(reason.contains("infrastructure-failure: caller identity"));
    let records = journal_values(&directory.state_root());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["role"], "unknown");
    assert!(records[0]["loop_name"].is_null());
    assert_eq!(records[0]["stale_session"], false);
}

/// ´test:integration:review-is-write-free-under-owner-read-only-state-root´
#[test]
fn review_is_write_free_under_owner_read_only_state_root() {
    let directory = FixtureDirectory::new("review-owner-read-only");
    let first = append_one(&directory, "suspicious", "printf first");
    assert!(hook_reason(&first).starts_with("escalation:"));
    let root = directory.state_root();
    let journal = root.join("escalations.jsonl");
    let before = fs::read(&journal).expect("journal is readable before review");
    let owner = fs::metadata(directory.path())
        .expect("fixture owner is readable")
        .uid();
    assert_eq!(
        fs::metadata(&root)
            .expect("state-root owner is readable")
            .uid(),
        owner
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o500))
        .expect("state root becomes owner-read-only");

    let review = review_loop(&root);
    let append_capture = directory.path().join("read-only-append");
    let append = run(
        hook_command(&append_capture, "suspicious", Some(&root)),
        &request("printf second"),
    );

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("state-root mode is restored");
    assert_ne!(review, "");
    let append_reason = hook_reason(&append);
    assert!(append_reason.starts_with("infrastructure-failure: state routing"));
    assert!(append_reason.contains("registry entry fixture"));
    assert!(!PathBuf::from(format!("{}.argv", append_capture.display())).exists());
    assert_eq!(
        fs::read(&journal).expect("journal remains readable"),
        before
    );
}

/// ´test:integration:registered-journal-reuses-validated-root-descriptor´
#[test]
fn registered_journal_reuses_validated_root_descriptor() {
    let directory = FixtureDirectory::new("registered-descriptor");
    let checkout = directory.path().join("loop");
    let registry_path = registry(&directory, &[("loop", "loop-session", &checkout)]);
    let registry = load_registry(Some(registry_path.into_os_string()))
        .expect("registry loads")
        .expect("registry exists");
    let entry = registry.entries().first().expect("registered loop");
    let root = entry
        .state_root()
        .expect("registered root path")
        .to_path_buf();
    let validated = entry
        .validated_state_root()
        .expect("registered root validates");
    let journal_path = root.join("escalations.jsonl");
    fs::write(&journal_path, b"validated descriptor\n").expect("validated journal fixture");
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600))
        .expect("validated journal is private");
    let moved = checkout.join("local/validated-state");
    fs::rename(&root, &moved).expect("validated root moves");
    fs::create_dir(&root).expect("replacement root exists");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("replacement root is private");
    let replacement = root.join("escalations.jsonl");
    fs::write(&replacement, b"replacement path\n").expect("replacement journal fixture");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
        .expect("replacement journal is private");

    let journal = Journal::from_registered_descriptor(
        validated,
        &root,
        permission_triage::request::Scope::Loop,
        permission_triage::journal::RootShape::Private,
    )
    .expect("journal binds validated root");
    assert_eq!(
        journal.read().expect("validated journal reads"),
        b"validated descriptor\n"
    );
}

/// ´test:integration:first-classification-creates-private-classifier-directory-and-verdict-stream´
#[test]
fn first_classification_creates_private_classifier_directory_and_verdict_stream() {
    let directory = FixtureDirectory::new("non-suspicious");
    let root = directory.state_root();
    let output = append_one(&directory, "safe", "printf safe");
    assert!(hook_reason(&output).starts_with("safe:"));
    assert!(
        root.exists(),
        "\ntest result: PTCLS1-FAIL-BEFORE first-classification-state"
    );
    assert_eq!(
        fs::metadata(&root)
            .expect("state root exists")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    let mut entries = fs::read_dir(&root)
        .expect("state root is readable")
        .map(|entry| entry.expect("state-root entry is readable").file_name())
        .collect::<Vec<_>>();
    entries.sort_unstable();
    assert_eq!(entries, ["classifier-cwd", "escalations.jsonl"]);
    let classifier_cwd = root.join("classifier-cwd");
    assert_eq!(
        fs::metadata(&classifier_cwd)
            .expect("classifier cwd exists")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::read_dir(classifier_cwd)
            .expect("classifier cwd is readable")
            .count(),
        0
    );
    let records = journal_values(&root);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "verdict");
    assert_eq!(records[0]["classification"], "safe");
}

/// ´test:integration:journal-configuration-and-filesystem-failures-deny-closed´
#[test]
fn journal_configuration_and_filesystem_failures_deny_closed() {
    let directory = FixtureDirectory::new("failures");
    let input = request("printf suspicious");

    let unset_capture = directory.path().join("unset");
    let unset = run(hook_command(&unset_capture, "suspicious", None), &input);
    assert_state_root_refusal(&unset, &unset_capture);

    let relative_capture = directory.path().join("relative");
    let relative = run(
        hook_command(
            &relative_capture,
            "suspicious",
            Some(Path::new("relative-state")),
        ),
        &input,
    );
    assert_named_state_root_refusal(
        &relative,
        &relative_capture,
        "loop state root: root must be absolute without dot components",
    );

    let checkout = directory.path().join("root-refusals");
    let local = checkout.join("local");
    fs::create_dir_all(&local).expect("private tree for registered roots");

    let file_root = local.join("state-file");
    fs::write(&file_root, b"file").expect("state-root file fixture");
    let file_capture = directory.path().join("file");
    assert_named_state_root_refusal(
        &run(
            hook_command(&file_capture, "suspicious", Some(&file_root)),
            &input,
        ),
        &file_capture,
        "loop registry metadata failed: Not a directory",
    );

    let wide_root = local.join("wide-state");
    fs::create_dir(&wide_root).expect("wide state root is created");
    fs::set_permissions(&wide_root, fs::Permissions::from_mode(0o755)).expect("wide mode is set");
    let wide_capture = directory.path().join("wide");
    assert_named_state_root_refusal(
        &run(
            hook_command(&wide_capture, "suspicious", Some(&wide_root)),
            &input,
        ),
        &wide_capture,
        "loop registry is not a private directory",
    );

    let link_root = local.join("link-state");
    let target = local.join("link-target");
    fs::create_dir(&target).expect("link target root is created");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
        .expect("link target mode is set");
    symlink(&target, &link_root).expect("state-root symlink is created");
    let symlink_capture = directory.path().join("symlink");
    assert_named_state_root_refusal(
        &run(
            hook_command(&symlink_capture, "suspicious", Some(&link_root)),
            &input,
        ),
        &symlink_capture,
        "loop state root: root contains a symlink",
    );

    // This arm measures an absent root, not an unwritable one: the parent is locked so the hook
    // cannot create the root on the way past, and the walk stops at ENOENT. It needs its own
    // checkout because a registered root is always the second component below one, so nesting it
    // deeper would only re-measure the private-tree refusal. There is deliberately no separate
    // arm for a root that exists at mode 0500: production refuses that as
    // `loop registry is not a private directory`, the string the wide-mode arm already pins, so a
    // sixth arm would assert nothing the fifth does not.
    let locked_parent = directory.path().join("absent-root-checkout/local");
    fs::create_dir_all(&locked_parent).expect("locked private tree is created");
    fs::set_permissions(&locked_parent, fs::Permissions::from_mode(0o500))
        .expect("locked parent mode is set");
    let absent_root = locked_parent.join("state");
    let absent_capture = directory.path().join("absent-root");
    assert_named_state_root_refusal(
        &run(
            hook_command(&absent_capture, "suspicious", Some(&absent_root)),
            &input,
        ),
        &absent_capture,
        "loop registry metadata failed: No such file or directory",
    );
    fs::set_permissions(&locked_parent, fs::Permissions::from_mode(0o700))
        .expect("locked parent mode is restored");
}

/// ´test:integration:journal-degraded-response-preserves-model-wall-time´
#[test]
fn journal_degraded_response_preserves_model_wall_time() -> Result<(), Box<dyn std::error::Error>> {
    let directory = FixtureDirectory::new("degraded-timing");
    let delayed_cli = directory.path().join("delayed-cli.sh");
    support::write_executable(
        &delayed_cli,
        b"#!/bin/sh\ncat >/dev/null\nsleep 0.05\nprintf '%s\\n' '{\"structured_output\":{\"classification\":\"suspicious\",\"reason\":\"fixture reason\"}}'\n",
        0o700,
    )?;
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let target = directory.path().join("timing-journal-target");
    fs::write(&target, b"")?;
    symlink(&target, root.join("escalations.jsonl"))?;
    let mut command = hook_command(&directory.path().join("timing"), "suspicious", Some(&root));
    command.env("PERMISSION_TRIAGE_CLI", delayed_cli);
    let output = run(command, &request("printf suspicious"));
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let context = value
        .pointer("/hookSpecificOutput/additionalContext")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("additional context is missing"))?;
    let (_, model_wall_ms) = context
        .rsplit_once(" model_wall_ms=")
        .ok_or_else(|| std::io::Error::other("model wall time is missing"))?;
    assert!(model_wall_ms.parse::<u128>()? >= 20, "context: {context}");
    assert!(
        root.join("classifier-cwd").is_dir(),
        "\ntest result: PTCLS1-FAIL-BEFORE degraded-wall-valid-state"
    );
    Ok(())
}

/// ´test:integration:sixteen-process-identical-appends-produce-distinct-event-identifiers´
#[test]
fn sixteen_process_identical_appends_produce_distinct_event_identifiers() {
    let directory = FixtureDirectory::new("process-concurrency");
    let root = directory.state_root();
    fs::create_dir(&root).expect("shared state root is created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("shared root mode is set");
    let mut children = Vec::new();
    for index in 0..16 {
        children.push(spawn_hook(
            hook_command(
                &directory.path().join(format!("capture-{index}")),
                "suspicious",
                Some(&root),
            ),
            &request("printf identical-process-command"),
        ));
    }
    for child in children {
        let output = child.wait_with_output().expect("hook process exits");
        assert!(hook_reason(&output).starts_with("escalation:"));
    }
    let records = journal_values(&root);
    assert_eq!(records.len(), 16);
    let mut identifiers = records
        .iter()
        .map(|record| record["event_id"].as_str().expect("event id"))
        .collect::<Vec<_>>();
    identifiers.sort_unstable();
    identifiers.dedup();
    assert_eq!(identifiers.len(), 16);
}

/// ´test:integration:concurrent-processes-claim-one-stale-lock-without-losing-records´
#[test]
fn concurrent_processes_claim_one_stale_lock_without_losing_records()
-> Result<(), Box<dyn std::error::Error>> {
    const CONTENDERS: usize = 8;
    let directory = FixtureDirectory::new("stale-process-concurrency");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let lock = root.join("escalations.lock");
    fs::write(&lock, format!("{}\n", u32::MAX))?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    File::options()
        .write(true)
        .open(&lock)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH))?;

    // Every contender checks recovery on its first collision with the planted stale lock.
    let mut children = Vec::new();
    for index in 0..CONTENDERS {
        children.push(spawn_hook(
            hook_command(
                &directory.path().join(format!("stale-capture-{index}")),
                "suspicious",
                Some(&root),
            ),
            &request(&format!("printf stale-process-{index}")),
        ));
    }
    for child in children {
        let output = child.wait_with_output()?;
        let reason = hook_reason(&output);
        assert!(reason.starts_with("escalation:"), "reason: {reason}");
    }

    let bytes = fs::read(root.join("escalations.jsonl"))?;
    let mut parsed_bytes = 0_usize;
    let mut parsed_records = 0_usize;
    let mut separator_lines = 0_usize;
    let mut event_ids = HashSet::new();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let payload = line
            .strip_suffix(b"\n")
            .ok_or_else(|| std::io::Error::other("journal line is not terminated"))?;
        if payload.is_empty() {
            separator_lines += 1;
            continue;
        }
        let record: Value = serde_json::from_slice(payload)?;
        if record.get("schema").and_then(Value::as_u64) != Some(2)
            || record.get("event").and_then(Value::as_str) != Some("escalated")
        {
            return Err(std::io::Error::other("journal record shape is invalid").into());
        }
        let event_id = record
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| std::io::Error::other("journal event id is missing"))?;
        event_ids.insert(event_id.to_owned());
        parsed_records += 1;
        parsed_bytes += payload.len() + 1;
    }
    assert_eq!(parsed_records, CONTENDERS);
    assert_eq!(event_ids.len(), CONTENDERS);
    assert!(separator_lines <= 1);
    assert_eq!(bytes.len(), parsed_bytes + separator_lines);

    let mut steal_claims = 0_usize;
    for entry in fs::read_dir(&root)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        steal_claims += usize::from(name.starts_with("escalations.lock.steal."));
    }
    assert!(!lock.exists());
    assert_eq!(steal_claims, 0);
    Ok(())
}

/// ´test:integration:a-zombie-lock-holder-is-dead-for-stale-recovery´
#[test]
fn a_zombie_lock_holder_is_dead_for_stale_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let directory = FixtureDirectory::new("zombie-holder");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut zombie = Command::new("sh")
        .args(["-c", "exit 0"])
        .spawn_serialized()?;
    let zombie_pid = zombie.id();
    let started = Instant::now();
    loop {
        let stat = fs::read_to_string(format!("/proc/{zombie_pid}/stat"))?;
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, suffix)| suffix.bytes().next());
        if state == Some(b'Z') {
            break;
        }
        // WAIT: the spawned shell has to exit and stay unreaped before the state reads Z, which a
        // loaded machine defers; the window costs nothing once the transition happens.
        if started.elapsed() >= Duration::from_secs(10) {
            zombie.kill()?;
            zombie.wait()?;
            return Err(std::io::Error::other("fixture child did not become a zombie").into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    let lock = root.join("escalations.lock");
    fs::write(&lock, format!("{zombie_pid}\n"))?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    File::options()
        .write(true)
        .open(&lock)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH))?;

    let output = run(
        hook_command(
            &directory.path().join("zombie-capture"),
            "suspicious",
            Some(&root),
        ),
        &request("printf zombie-recovered"),
    );
    zombie.wait()?;

    assert!(hook_reason(&output).starts_with("escalation:"));
    assert_eq!(journal_values(&root).len(), 1);
    assert!(!lock.exists());
    Ok(())
}

/// ´test:integration:review-recovers-torn-tail-groups-and-renders-candidate-row´
#[test]
fn review_recovers_torn_tail_groups_and_renders_candidate_row() {
    let directory = FixtureDirectory::new("review");
    let first = append_one(&directory, "suspicious", "printf  worker-alias  status");
    let second = append_one(&directory, "suspicious", "printf worker-alias status");
    assert!(hook_reason(&first).starts_with("escalation:"));
    assert!(hook_reason(&second).starts_with("escalation:"));
    OpenOptions::new()
        .append(true)
        .open(directory.state_root().join("escalations.jsonl"))
        .expect("journal opens for torn fixture")
        .write_all(b"{\"schema\":1")
        .expect("torn tail is appended");
    let rendered = review_loop(&directory.state_root());
    assert!(rendered.starts_with("WARNING: command text may contain credentials."));
    assert!(rendered.contains("Torn trailing records skipped: 1"));
    assert!(rendered.contains("occurrences=2 outcomes=escalated"));
    assert!(rendered.contains("|<rule-id>|routine-superloop|"));
    let first_position = rendered.find("id=").expect("first event is rendered");
    let second_position = rendered[first_position + 3..]
        .find("id=")
        .expect("second event is rendered");
    assert!(second_position > 0);
}

/// ´test:integration:append-separates-a-torn-tail-before-writing-the-next-record´
#[test]
fn append_separates_a_torn_tail_before_writing_the_next_record()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = FixtureDirectory::new("tail-repair");
    let first = append_one(&directory, "suspicious", "printf first");
    assert!(hook_reason(&first).starts_with("escalation:"));
    let journal = directory.state_root().join("escalations.jsonl");
    OpenOptions::new()
        .append(true)
        .open(&journal)?
        .write_all(b"{\"schema\":1")?;

    let second = append_one(&directory, "suspicious", "printf second");
    assert!(hook_reason(&second).starts_with("escalation:"));
    let rendered = review_loop(&directory.state_root());
    assert_eq!(rendered.match_indices("- id=").count(), 2);
    assert!(rendered.contains("Torn trailing records skipped: 0"));
    assert!(rendered.contains("Malformed complete lines skipped: 1"));
    let bytes = fs::read(journal)?;
    let parseable = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter(|line| serde_json::from_slice::<Value>(line).is_ok())
        .count();
    assert_eq!(parseable, 2);
    Ok(())
}

/// ´test:integration:review-mark-forms-cover-outcomes-and-duplicate-refusals´
#[test]
fn review_mark_forms_cover_outcomes_and_duplicate_refusals() {
    use permission_triage::{DispositionDetail as Detail, DispositionOutcome as Outcome};
    for (outcome, expected) in [
        (Outcome::AdjudicatedRuleAdded, "adjudicated-rule-added"),
        (Outcome::AdjudicatedRejected, "adjudicated-rejected"),
        (Outcome::CorrectedAndRerun, "corrected-and-rerun"),
        (Outcome::AdjudicatedApproved, "adjudicated-approved"),
    ] {
        let fixture = ScopeFixture::new("mark-outcome");
        let event = fixture.escalation("printf mark");
        let detail = match outcome {
            Outcome::AdjudicatedRuleAdded => Detail::Rule("owner.rule-1".to_owned()),
            Outcome::AdjudicatedRejected => Detail::Rejection("outside authority".to_owned()),
            Outcome::CorrectedAndRerun => Detail::CorrectedRequestDigest("a".repeat(64)),
            Outcome::AdjudicatedApproved => Detail::ApprovedRequestDigest(
                event["request_digest"].as_str().expect("digest").to_owned(),
            ),
        };
        let id = event["event_id"].as_str().expect("event id");
        mark_loop(
            &fixture.directory.state_root(),
            &fixture.registry,
            &fixture.input("printf review"),
            id,
            outcome,
            detail,
        )
        .expect("disposition");
        let records = journal_values(&fixture.directory.state_root());
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["event"], "disposition");
        assert_eq!(records[1]["outcome"], expected);
        let duplicate = mark_loop(
            &fixture.directory.state_root(),
            &fixture.registry,
            &fixture.input("printf review"),
            id,
            Outcome::AdjudicatedRejected,
            Detail::Rejection("duplicate".to_owned()),
        );
        assert!(
            duplicate
                .expect_err("duplicate disposition")
                .to_string()
                .contains("already adjudicated")
        );
    }
}

/// ´test:integration:approved-digest-allows-one-identical-orchestrator-request-and-records-consumption´
#[test]
fn approved_digest_allows_one_identical_orchestrator_request_and_records_consumption() {
    let directory = FixtureDirectory::new("approved-once");
    let checkout = directory.path().join("loop");
    let scratch = checkout.join("scratch");
    let registry = registry(&directory, &[("orchestration", "session-main", &checkout)]);
    let domain_text = "approval domain fixture\n";
    fs::write(checkout.join("local/permissions/domain.md"), domain_text)
        .expect("domain rubric is written");
    let input = role_request(
        "session-main",
        &scratch,
        "printf approved-once",
        "use-first",
        None,
    );
    let (_, first_command) = role_hook_command(&directory, "first", "suspicious", &registry);
    let first = run(first_command, &input);
    let first_reason = hook_reason(&first);
    assert!(first_reason.contains("role=orchestrator"));
    assert!(first_reason.contains("adjudicated-approved"));
    let records = journal_values(&directory.state_root());
    assert_eq!(records[0]["role"], "orchestrator");
    assert_eq!(records[0]["loop_name"], "orchestration");
    assert_eq!(
        records[0]["domain_rubric_digest"],
        sha256_digest(domain_text.as_bytes())
    );
    let event_id = records[0]["event_id"].as_str().expect("event id");
    let digest = records[0]["request_digest"]
        .as_str()
        .expect("request digest");
    mark_loop(
        &directory.state_root(),
        &registry,
        &input,
        event_id,
        permission_triage::DispositionOutcome::AdjudicatedApproved,
        permission_triage::DispositionDetail::ApprovedRequestDigest(digest.to_owned()),
    )
    .expect("approval disposition");

    let (second_capture, second_command) =
        role_hook_command(&directory, "second", "suspicious", &registry);
    let second_input = role_request(
        "session-main",
        &scratch,
        "printf approved-once",
        "use-second",
        None,
    );
    let second = run(second_command, &second_input);
    let second_reason = hook_reason(&second);
    assert!(second_reason.starts_with("adjudicated:"));
    assert!(PathBuf::from(format!("{}.argv", second_capture.display())).exists());

    let (_, third_command) = role_hook_command(&directory, "third", "suspicious", &registry);
    let third_input = role_request(
        "session-main",
        &scratch,
        "printf approved-once",
        "use-third",
        None,
    );
    let third = run(third_command, &third_input);
    assert!(hook_reason(&third).starts_with("escalation:"));
    let records = journal_values(&directory.state_root());
    assert_eq!(records.len(), 5);
    assert_eq!(records[0]["event"], "escalated");
    assert_eq!(records[1]["outcome"], "adjudicated-approved");
    assert_eq!(records[2]["event"], "approval-consumed");
    assert_eq!(records[2]["tool_use_id"], "use-second");
    assert_eq!(records[3]["event"], "verdict");
    assert_eq!(records[3]["classification"], "routine-superloop");
    assert_eq!(records[4]["event"], "escalated");
    for record in records {
        assert_eq!(record["role"], "orchestrator");
        assert_eq!(record["loop_name"], "orchestration");
        assert_eq!(record["stale_session"], false);
        assert_eq!(
            record["domain_rubric_digest"],
            sha256_digest(domain_text.as_bytes())
        );
    }
}

/// ´test:integration:unrelated-orphan-disposition-does-not-break-approval-lookup´
#[test]
fn unrelated_orphan_disposition_does_not_break_approval_lookup() {
    let fixture = ScopeFixture::new("approval-unrelated-orphan");
    let event = fixture.escalation("printf orphan-is-unrelated");
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    let records = journal_values(&fixture.directory.state_root());
    let mut orphan = records[1].clone();
    orphan["event_id"] = json!("f".repeat(64));
    append_journal_value(&fixture.directory.state_root(), &orphan);

    let output = run(
        fixture.hook("approval-after-orphan", "suspicious", "loop"),
        &fixture.input("printf orphan-is-unrelated"),
    );
    let reason = hook_reason(&output);
    assert!(reason.starts_with("adjudicated:"), "{reason}");
    assert_eq!(
        journal_values(&fixture.directory.state_root())
            .iter()
            .filter(|record| record["event"] == "approval-consumed")
            .count(),
        1
    );
}

/// ´test:integration:duplicate-candidate-disposition-fails-approval-lookup-closed´
#[test]
fn duplicate_candidate_disposition_fails_approval_lookup_closed() {
    let fixture = ScopeFixture::new("approval-duplicate-disposition");
    let event = fixture.escalation("printf duplicate-disposition");
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    let records = journal_values(&fixture.directory.state_root());
    append_journal_value(&fixture.directory.state_root(), &records[1]);

    let output = run(
        fixture.hook("approval-after-duplicate", "suspicious", "loop"),
        &fixture.input("printf duplicate-disposition"),
    );
    assert!(hook_reason(&output).starts_with("infrastructure-failure: adjudication journal"));
    assert!(
        journal_values(&fixture.directory.state_root())
            .iter()
            .all(|record| record["event"] != "approval-consumed")
    );
}

/// ´test:integration:earlier-valid-approval-ignores-later-anomalous-candidate´
#[test]
fn earlier_valid_approval_ignores_later_anomalous_candidate() {
    let fixture = ScopeFixture::new("approval-before-anomalous-candidate");
    let event = fixture.escalation("printf approval-before-anomaly");
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    let records = journal_values(&fixture.directory.state_root());
    let later_event_id = "e".repeat(64);
    let mut later_source = records[0].clone();
    later_source["event_id"] = json!(&later_event_id);
    let mut later_disposition = records[1].clone();
    later_disposition["event_id"] = json!(&later_event_id);
    append_journal_value(&fixture.directory.state_root(), &later_source);
    append_journal_value(&fixture.directory.state_root(), &later_disposition);
    append_journal_value(&fixture.directory.state_root(), &later_disposition);

    let output = run(
        fixture.hook("approval-before-anomaly", "suspicious", "loop"),
        &fixture.input("printf approval-before-anomaly"),
    );
    let reason = hook_reason(&output);
    assert!(reason.starts_with("adjudicated:"), "{reason}");
    let records = journal_values(&fixture.directory.state_root());
    let consumption = records
        .iter()
        .find(|record| record["event"] == "approval-consumed")
        .expect("approval is consumed");
    assert_eq!(consumption["event_id"], event["event_id"]);
}

/// ´test:integration:audit-lookup-never-consumes-a-matching-approval´
#[test]
fn audit_lookup_never_consumes_a_matching_approval() {
    let directory = FixtureDirectory::new("audit-does-not-consume");
    let checkout = directory.path().join("loop");
    let registry = registry(&directory, &[("orchestration", "session-main", &checkout)]);
    let input = role_request(
        "session-main",
        &checkout,
        "printf audit-approval",
        "use-original",
        None,
    );
    let (_, first_command) =
        role_hook_command(&directory, "audit-approval-first", "suspicious", &registry);
    let first = run(first_command, &input);
    assert!(hook_reason(&first).starts_with("escalation:"));
    let records = journal_values(&directory.state_root());
    let event_id = records[0]["event_id"].as_str().expect("event id");
    let digest = records[0]["request_digest"].as_str().expect("digest");
    mark_loop(
        &directory.state_root(),
        &registry,
        &input,
        event_id,
        permission_triage::DispositionOutcome::AdjudicatedApproved,
        permission_triage::DispositionDetail::ApprovedRequestDigest(digest.to_owned()),
    )
    .expect("approval disposition");

    let (audit_capture, mut audit_command) =
        role_hook_command(&directory, "audit-approval-probe", "suspicious", &registry);
    audit_command.env("PERMISSION_TRIAGE_MODE", "audit");
    let audit = run(
        audit_command,
        &role_request(
            "session-main",
            &checkout,
            "printf audit-approval",
            "use-audit",
            None,
        ),
    );
    assert_eq!(audit.status.code(), Some(0));
    assert_eq!(audit.stdout, [] as [u8; 0]);
    assert_eq!(audit.stderr, [] as [u8; 0]);
    assert!(PathBuf::from(format!("{}.argv", audit_capture.display())).exists());
    let records = journal_values(&directory.state_root());
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record["event"] != "approval-consumed")
    );
    assert_eq!(records[2]["mode"], "audit");
    assert_eq!(records[2]["emitted_decision"], Value::Null);

    let (enforce_capture, enforce_command) = role_hook_command(
        &directory,
        "audit-approval-enforce",
        "suspicious",
        &registry,
    );
    let enforce = run(
        enforce_command,
        &role_request(
            "session-main",
            &checkout,
            "printf audit-approval",
            "use-enforce",
            None,
        ),
    );
    assert!(hook_reason(&enforce).starts_with("adjudicated:"));
    assert!(PathBuf::from(format!("{}.argv", enforce_capture.display())).exists());
    let records = journal_values(&directory.state_root());
    assert_eq!(records.len(), 5);
    assert_eq!(records[3]["event"], "approval-consumed");
    assert_eq!(records[4]["event"], "verdict");
}

/// ´test:integration:legacy-schema-one-approval-cannot-be-consumed´
#[test]
fn legacy_schema_one_approval_cannot_be_consumed() {
    let directory = FixtureDirectory::new("legacy-approval");
    let checkout = directory.path().join("loop");
    let registry = registry(&directory, &[("orchestration", "session-main", &checkout)]);
    let root = directory.state_root();
    fs::create_dir_all(&root).expect("legacy state root is created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("legacy state root is private");
    let command_text = "printf legacy-approved";
    let digest = request_digest(
        "Bash",
        checkout.to_str().expect("checkout is UTF-8"),
        command_text,
    );
    let source = json!({
        "schema": 1,
        "event": "escalated",
        "event_id": "legacy-approved-event",
        "recorded_at": "2026-09-03T00:00:00.000000000Z",
        "tool_use_id": "legacy-use",
        "request_digest": digest,
        "tool": "Bash",
        "cwd": checkout,
        "command": command_text,
        "classification": "suspicious",
        "reason": "legacy escalation",
        "general_rubric_digest": GENERAL_RUBRIC_DIGEST,
        "owner_rubric_digest": null,
        "role": "orchestrator",
        "loop_name": "orchestration",
        "stale_session": false,
        "domain_rubric_digest": null,
        "model_status": "success"
    });
    let mut disposition = source.clone();
    disposition["event"] = json!("disposition");
    disposition["recorded_at"] = json!("2026-09-03T00:01:00.000000000Z");
    disposition["reason"] = json!("approved legacy request");
    disposition["model_status"] = json!("owner-mark");
    disposition["outcome"] = json!("adjudicated-approved");
    let mut bytes = Vec::new();
    for value in [source, disposition] {
        bytes.extend(serde_json::to_vec(&value).expect("legacy record serializes"));
        bytes.push(b'\n');
    }
    let journal = root.join("escalations.jsonl");
    fs::write(&journal, bytes).expect("legacy journal is written");
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))
        .expect("legacy journal is private");

    let (capture, command) =
        role_hook_command(&directory, "legacy-approval-probe", "suspicious", &registry);
    let output = run(
        command,
        &role_request("session-main", &checkout, command_text, "current-use", None),
    );
    assert!(hook_reason(&output).starts_with("escalation:"));
    assert!(PathBuf::from(format!("{}.argv", capture.display())).exists());
    let records = journal_values(&root);
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record["event"] != "approval-consumed")
    );
    assert_eq!(records[2]["schema"], 2);
}

/// ´test:integration:approval-does-not-match-a-different-digest-subagent-or-loop´
#[test]
fn approval_does_not_match_a_different_digest_subagent_or_loop() {
    let directory = FixtureDirectory::new("approval-bounds");
    let one = directory.path().join("one");
    let two = directory.path().join("two");
    let scratch = one.join("scratch");
    let registry = registry(
        &directory,
        &[
            ("one", "session-one", one.as_path()),
            ("two", "session-two", two.as_path()),
        ],
    );
    let original = role_request(
        "session-one",
        &scratch,
        "printf bounded-approval",
        "use-original",
        None,
    );
    let (_, original_command) =
        role_hook_command(&directory, "bounds-original", "suspicious", &registry);
    let first = run(original_command, &original);
    assert!(hook_reason(&first).starts_with("escalation:"));
    let records = journal_values(&directory.state_root());
    let event_id = records[0]["event_id"].as_str().expect("event id");
    let digest = records[0]["request_digest"].as_str().expect("digest");
    mark_loop(
        &directory.state_root(),
        &registry,
        &original,
        event_id,
        permission_triage::DispositionOutcome::AdjudicatedApproved,
        permission_triage::DispositionDetail::ApprovedRequestDigest(digest.to_owned()),
    )
    .expect("approval disposition");

    let mismatches = [
        role_request(
            "session-one",
            &scratch,
            "printf different-digest",
            "use-different",
            None,
        ),
        role_request(
            "session-one",
            &scratch,
            "printf bounded-approval",
            "use-subagent",
            Some("/run/subagents/agent.jsonl"),
        ),
        role_request(
            "session-two",
            &two.join("scratch"),
            "printf bounded-approval",
            "use-other-loop",
            None,
        ),
    ];
    for (index, mismatch) in mismatches.iter().enumerate() {
        let (_, command) = role_hook_command(
            &directory,
            &format!("bounds-mismatch-{index}"),
            "suspicious",
            &registry,
        );
        let output = run(command, mismatch);
        assert!(hook_reason(&output).starts_with("escalation:"));
    }

    let (_, matching_command) =
        role_hook_command(&directory, "bounds-match", "suspicious", &registry);
    let matching = run(
        matching_command,
        &role_request(
            "session-one",
            &scratch,
            "printf bounded-approval",
            "use-match",
            None,
        ),
    );
    assert!(hook_reason(&matching).starts_with("adjudicated:"));
}

/// ´test:integration:orchestrator-request-without-prior-escalation-does-not-bypass-model´
#[test]
fn orchestrator_request_without_prior_escalation_does_not_bypass_model() {
    let directory = FixtureDirectory::new("approval-missing-escalation");
    let checkout = directory.path().join("loop");
    let registry = registry(&directory, &[("orchestration", "session-main", &checkout)]);
    let (_, command) = role_hook_command(&directory, "missing-escalation", "suspicious", &registry);
    let output = run(
        command,
        &role_request(
            "session-main",
            &checkout,
            "printf no-prior-escalation",
            "use-missing",
            None,
        ),
    );
    assert!(hook_reason(&output).starts_with("escalation:"));
}

/// ´test:integration:journal-record-cap-and-created-modes-are-enforced´
#[test]
fn journal_record_cap_and_created_modes_are_enforced() {
    let directory = FixtureDirectory::new("cap-and-modes");
    let command = "é".repeat(7_000);
    let mut invocation = hook_command(
        &directory.path().join("cap"),
        "suspicious",
        Some(&directory.state_root()),
    );
    invocation.env("PERMISSION_TRIAGE_FAKE_SCOPE", "estate");
    let output = run(invocation, &request(&command));
    assert!(hook_reason(&output).starts_with("escalation:"));
    let root = directory.state_root();
    let bytes = fs::read(root.join("estate-escalations.jsonl")).expect("journal reads");
    assert!(bytes.len() <= MAX_JOURNAL_RECORD_BYTES);
    let value: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("record parses");
    assert_eq!(value["truncated"], true);
    assert!(value["command"].as_str().expect("command").len() < command.len());
    assert_eq!(
        fs::metadata(&root)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("estate-escalations.jsonl"))
            .expect("journal metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

struct ScopeFixture {
    directory: FixtureDirectory,
    checkout: PathBuf,
    peer: PathBuf,
    registry: PathBuf,
}

impl ScopeFixture {
    fn new(name: &str) -> Self {
        let directory = FixtureDirectory::new(name);
        let checkout = directory.path().join("one");
        let peer = directory.path().join("two");
        let registry = registry(
            &directory,
            &[
                ("one", "session-one", &checkout),
                ("two", "session-two", &peer),
            ],
        );
        fs::write(checkout.join("local/permissions/domain.md"), format!("This loop owns its checkout, scratchpad `{}/scratch/`, and uses provisioned alias `own-worker` beneath `/srv/loops/loop-a/` for domain work. Account and service configuration is outside the domain.\n", directory.path().display())).expect("domain fixture");
        Self {
            directory,
            checkout,
            peer,
            registry,
        }
    }

    fn input(&self, command: &str) -> Vec<u8> {
        role_request("session-one", &self.checkout, command, "scope-use", None)
    }

    fn hook(&self, capture: &str, class: &str, scope: &str) -> Command {
        let (_, mut command) =
            role_hook_command(&self.directory, capture, "scope-fixture", &self.registry);
        command.env("PERMISSION_TRIAGE_FAKE_ENVELOPE", json!({"structured_output": {"classification": class, "reason": "scope fixture", "scope": scope}}).to_string());
        command
    }

    fn mark(&self, event: &Value, caller: &[u8]) -> Result<(), permission_triage::JournalError> {
        mark_loop(
            &self.directory.state_root(),
            &self.registry,
            caller,
            event["event_id"].as_str().expect("event id"),
            permission_triage::DispositionOutcome::AdjudicatedApproved,
            permission_triage::DispositionDetail::ApprovedRequestDigest(
                event["request_digest"].as_str().expect("digest").to_owned(),
            ),
        )
    }

    fn escalation(&self, command: &str) -> Value {
        let output = run(
            self.hook("original", "suspicious", "loop"),
            &self.input(command),
        );
        assert!(hook_reason(&output).starts_with("escalation:"));
        let event = journal_values(&self.directory.state_root()).remove(0);
        assert_eq!(event["scope"], "loop");
        event
    }
}

/// ´test:integration:scope-hook-distinguishes-local-peer-authorization-and-account-effects´
#[test]
fn scope_hook_distinguishes_local_peer_authorization_and_account_effects() {
    let fixture = ScopeFixture::new("scope-effects");
    let cases = [
        ("Bash", json!({"command": "printf '/etc/hosts'"}), "loop"),
        ("Read", json!({"file_path": "src/main.rs"}), "loop"),
        (
            "Write",
            json!({"file_path": "src/main.rs", "content": "body omitted"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.directory.path().join("scratch/note.md"), "content": "body omitted"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.checkout.join("hooks/x"), "content": "x"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.checkout.join(".cargo/config.toml"), "content": "x"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.checkout.join(".gitconfig"), "content": "x"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.checkout.join("general.md"), "content": "x"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.checkout.join("SKILL.md"), "content": "x"}),
            "loop",
        ),
        (
            "Write",
            json!({"file_path": fixture.checkout.join("AGENTS.md"), "content": "x"}),
            "loop",
        ),
        (
            "Bash",
            json!({"timeout": 20000, "command": "time timeout 20 ssh own-worker 'time timeout 10 git -C /srv/loops/loop-a/repo status'"}),
            "loop",
        ),
    ];
    for (index, (tool, input, scope)) in cases.into_iter().enumerate() {
        let mut request: Value =
            serde_json::from_slice(&fixture.input("printf fixture")).expect("request");
        request["tool_name"] = json!(tool);
        request["tool_input"] = input;
        let output = run(
            fixture.hook(&format!("effect-{index}"), "suspicious", scope),
            &serde_json::to_vec(&request).expect("request"),
        );
        assert!(
            hook_reason(&output).starts_with("escalation:"),
            "{tool}: {}",
            hook_reason(&output)
        );
        assert_eq!(
            journal_values(&fixture.directory.state_root())
                .last()
                .expect("event")["scope"],
            scope
        );
    }
}

fn assert_estate_target_floor(
    fixture: &ScopeFixture,
    index: usize,
    target: &Path,
    registry: Option<&Path>,
    owner_rubric: Option<&Path>,
) {
    let mut request: Value =
        serde_json::from_slice(&fixture.input("printf fixture")).expect("request");
    request["tool_name"] = json!("Write");
    request["tool_input"] = json!({"file_path": target, "content": "x"});
    let mut hook = fixture.hook(&format!("floor-{index}"), "safe", "loop");
    if let Some(registry) = registry {
        hook.env("PERMISSION_TRIAGE_LOOP_REGISTRY", registry);
    }
    if let Some(owner_rubric) = owner_rubric {
        hook.env("PERMISSION_TRIAGE_OWNER_RUBRIC", owner_rubric);
    }
    let output = run(hook, &serde_json::to_vec(&request).expect("request"));
    assert!(hook_reason(&output).starts_with("infrastructure-failure: scope validation"));
    let records = journal_values(&fixture.directory.state_root());
    let event = records.last().expect("event");
    assert_eq!(event["scope"], "estate");
    assert_eq!(event["classification"], Value::Null);
    assert_eq!(event["model_status"], "scope-invalid");
}

fn assert_estate_operation_floor(fixture: &ScopeFixture, index: usize, command: &str) {
    let input = if command.contains("ssh own-worker") {
        let mut request: Value = serde_json::from_slice(&fixture.input(command)).expect("request");
        request["tool_input"]["timeout"] = json!(20000);
        serde_json::to_vec(&request).expect("request")
    } else {
        fixture.input(command)
    };
    let output = run(
        fixture.hook(&format!("operation-floor-{index}"), "safe", "loop"),
        &input,
    );
    let reason = hook_reason(&output);
    assert!(
        reason.starts_with("infrastructure-failure: scope validation"),
        "{command}: {reason}"
    );
    let records = journal_values(&fixture.directory.state_root());
    let event = records.last().expect("event");
    assert_eq!(event["scope"], "estate");
    assert_eq!(event["classification"], Value::Null);
    assert_eq!(event["model_status"], "scope-invalid");
}

/// ´test:integration:scope-hook-rejects-estate-targets-labeled-loop´
#[test]
fn scope_hook_rejects_estate_targets_labeled_loop() {
    let fixture = ScopeFixture::new("scope-floor");
    let checkout_registry = registry_at(
        &fixture.checkout.join("local/permissions/auth-sources"),
        &[
            ("one", "session-one", fixture.checkout.as_path()),
            ("two", "session-two", fixture.peer.as_path()),
        ],
    );
    let owner_rubric = fixture.checkout.join("local/permissions/owner-source.txt");
    fs::write(&owner_rubric, []).expect("owner rubric is written");
    for (index, (target, registry, owner_rubric)) in [
        (fixture.peer.join("file"), None, None),
        (
            fixture.checkout.join("local/permissions/domain.md"),
            None,
            None,
        ),
        (fixture.registry.join("one.env"), None, None),
        (
            checkout_registry.join("one.env"),
            Some(checkout_registry.as_path()),
            None,
        ),
        (owner_rubric.clone(), None, Some(owner_rubric.as_path())),
        (fixture.checkout.join(".claude/settings.json"), None, None),
        (
            fixture.checkout.join(".claude/settings.local.json"),
            None,
            None,
        ),
        (PathBuf::from("/etc/hosts"), None, None),
        (
            PathBuf::from("/home/user/.claude/settings.json"),
            None,
            None,
        ),
        (fixture.peer.join("hooks/x"), None, None),
        (fixture.peer.join(".cargo/config.toml"), None, None),
        (fixture.peer.join(".gitconfig"), None, None),
        (fixture.peer.join("general.md"), None, None),
        (fixture.peer.join("SKILL.md"), None, None),
        (fixture.directory.path().join("home/hooks/x"), None, None),
        (
            fixture.directory.path().join("home/.cargo/config.toml"),
            None,
            None,
        ),
        (fixture.directory.path().join("home/.gitconfig"), None, None),
        (fixture.directory.path().join("home/general.md"), None, None),
        (fixture.directory.path().join("home/SKILL.md"), None, None),
    ]
    .into_iter()
    .enumerate()
    {
        assert_estate_target_floor(&fixture, index, &target, registry, owner_rubric);
    }
    for (index, command) in [
        "time timeout 20 ssh own-worker 'time timeout 10 usermod -s /bin/bash account'",
        "time timeout 20 systemctl restart shared-hub",
        "time cargo install cargo-nextest",
        "time npm -g install fixture",
        "time npm install -g fixture",
        "time npm i -g fixture",
        "time npm install --global fixture",
        "time pip install fixture",
        "time pip3 install fixture",
        "time podman ps",
        "time docker ps",
        "time toolbox enter",
        "time flatpak install fixture",
        "time gh auth status",
        "time crontab -l",
        "time chsh -s shell-name",
        "time ssh-keygen -t ed25519",
    ]
    .iter()
    .enumerate()
    {
        assert_estate_operation_floor(&fixture, index, command);
    }
}

/// ´test:integration:nested-peer-checkout-refuses-deployment-layout´
#[test]
fn nested_peer_checkout_refuses_deployment_layout() {
    let directory = FixtureDirectory::new("scope-model-error-peer");
    let checkout = directory.path().join("one");
    let peer = checkout.join("nested-peer");
    let registry = registry(
        &directory,
        &[
            ("one", "session-one", &checkout),
            ("two", "session-two", &peer),
        ],
    );
    fs::write(
        checkout.join("local/permissions/domain.md"),
        "The loop owns its checkout, except for registered peer checkouts.\n",
    )
    .expect("domain fixture");
    let (_, command) = role_hook_command(&directory, "model-error-peer", "nonzero", &registry);
    let output = run(
        command,
        &role_request(
            "session-one",
            &checkout,
            &format!("touch '{}'", peer.join("file").display()),
            "model-error-peer",
            None,
        ),
    );
    assert!(hook_reason(&output).contains("LOOP_CWD"));
    assert_eq!(journal_values(&directory.state_root()), [] as [Value; 0]);
}

/// ´test:integration:registered-peer-home-and-own-run-tree-set-scope-floor´
#[test]
fn registered_peer_home_and_own_run_tree_set_scope_floor() {
    let directory = FixtureDirectory::new("scope-home-roots");
    let checkout = directory.path().join("one");
    let peer = directory.path().join("two");
    let registry = registry(
        &directory,
        &[
            ("one", "session-one", &checkout),
            ("two", "session-two", &peer),
        ],
    );
    let own_home = directory.path().join("homes/one");
    let peer_home = directory.path().join("homes/two");
    for (name, home) in [("one", &own_home), ("two", &peer_home)] {
        fs::create_dir_all(home.join("runs")).expect("run tree");
        let entry = registry.join(format!("{name}.env"));
        let text = fs::read_to_string(&entry).expect("registry entry");
        fs::write(&entry, format!("{text}LOOP_HOME={}\n", home.display()))
            .expect("registered home");
    }
    fs::create_dir(own_home.join("private")).expect("private tree");
    fs::write(
        checkout.join("local/permissions/domain.md"),
        "The loop owns its checkout and run tree.\n",
    )
    .expect("domain rubric");
    symlink(own_home.join("runs"), checkout.join("runs-link")).expect("run tree link");
    symlink(peer_home.join("runs"), own_home.join("runs/peer-link")).expect("peer run tree link");
    for (index, (target, expected)) in [
        (peer_home.join("runs/peer.txt"), "estate"),
        (own_home.join("runs/own.txt"), "loop"),
        (own_home.join("private/own.txt"), "estate"),
        (checkout.join("runs-link/own.txt"), "loop"),
        (own_home.join("runs/peer-link/peer.txt"), "estate"),
    ]
    .into_iter()
    .enumerate()
    {
        let use_id = format!("home-scope-{index}");
        let (_, command) = role_hook_command(&directory, &use_id, "nonzero", &registry);
        let output = run(
            command,
            &role_request(
                "session-one",
                &checkout,
                &format!("cat '{}'", target.display()),
                &use_id,
                None,
            ),
        );
        assert!(hook_reason(&output).starts_with("infrastructure-failure: model runner"));
        let record = journal_values(&checkout.join("local/state"))
            .into_iter()
            .find(|record| record["tool_use_id"] == use_id)
            .expect("scoped event");
        assert_eq!(record["scope"], expected, "{}", target.display());
    }
    fs::write(
        checkout.join("local/permissions/domain.md"),
        format!(
            "The loop owns `{}/`.\n",
            directory.path().join("homes").display()
        ),
    )
    .expect("quoted homes root");
    let use_id = "peer-home-contradiction";
    let (_, command) = role_hook_command(&directory, use_id, "safe", &registry);
    let output = run(
        command,
        &role_request(
            "session-one",
            &checkout,
            &format!("cat '{}'", peer_home.join("runs/peer.txt").display()),
            use_id,
            None,
        ),
    );
    assert!(hook_reason(&output).starts_with("infrastructure-failure: scope validation"));
    let record = journal_values(&checkout.join("local/state"))
        .into_iter()
        .find(|record| record["tool_use_id"] == use_id)
        .expect("contradiction event");
    assert_eq!(record["scope"], "estate");
}

/// ´test:integration:nested-loop-cross-write-refuses-deployment-layout´
#[test]
fn nested_loop_cross_write_refuses_deployment_layout() {
    let directory = FixtureDirectory::new("nested-child-floor");
    let parent = directory.path().join("estate");
    let child = parent.join("child");
    let registry = registry(
        &directory,
        &[
            ("estate", "estate-session", &parent),
            ("nested", "nested-session", &child),
        ],
    );
    fs::write(
        child.join("local/permissions/domain.md"),
        format!(
            "The nested loop owns its checkout and reviewed scratchpad `{}/shared/`.\n",
            parent.display()
        ),
    )
    .expect("nested domain fixture");

    let mut request: Value = serde_json::from_slice(&role_request(
        "nested-session",
        &child,
        "printf nested-scope",
        "nested-scope-use",
        None,
    ))
    .expect("nested request");
    request["tool_name"] = json!("Write");
    request["tool_input"] =
        json!({"file_path": parent.join("shared/parent-owned.md"), "content": "x"});
    let (_, mut command) = role_hook_command(&directory, "nested-scope", "safe", &registry);
    command.env("PERMISSION_TRIAGE_FAKE_SCOPE", "loop");
    let output = run(command, &serde_json::to_vec(&request).expect("request"));
    assert!(hook_reason(&output).contains("LOOP_CWD"));
    assert_eq!(
        journal_values(&parent.join("local/state")),
        [] as [Value; 0]
    );
    assert_eq!(journal_values(&child.join("local/state")), [] as [Value; 0]);
}

/// ´test:integration:scope-quoted-domain-roots-cannot-lower-host-configuration-floor´
#[test]
fn scope_quoted_domain_roots_cannot_lower_host_configuration_floor() {
    let fixture = ScopeFixture::new("scope-host-floor");
    std::os::unix::fs::symlink("/etc", fixture.checkout.join("host-link"))
        .expect("host configuration symlink fixture");
    fs::write(
        fixture.checkout.join("local/permissions/domain.md"),
        "Domain candidates include `/etc/` and `/`; host configuration remains estate-owned.\n",
    )
    .expect("domain fixture");
    for (index, target) in [
        PathBuf::from("/etc/hosts"),
        fixture.checkout.join("host-link/hosts"),
        PathBuf::from("/proc/sys/kernel/hostname"),
    ]
    .iter()
    .enumerate()
    {
        let mut request: Value =
            serde_json::from_slice(&fixture.input("printf fixture")).expect("request");
        request["tool_name"] = json!("Write");
        request["tool_input"] = json!({"file_path": target, "content": "x"});
        let output = run(
            fixture.hook(&format!("host-floor-{index}"), "safe", "loop"),
            &serde_json::to_vec(&request).expect("request"),
        );
        assert!(
            hook_reason(&output).starts_with("infrastructure-failure: scope validation"),
            "{}: {}",
            target.display(),
            hook_reason(&output)
        );
        let records = journal_values(&fixture.directory.state_root());
        let event = records.last().expect("event");
        assert_eq!(event["scope"], "estate");
        assert_eq!(event["classification"], Value::Null);
    }
}

/// ´test:integration:scope-hook-computes-deterministic-and-diagnostic-scope´
#[test]
fn scope_hook_computes_deterministic_and_diagnostic_scope() {
    let fixture = ScopeFixture::new("scope-deterministic");
    for (index, command, scope) in [
        (0, "cargo test", "loop"),
        (1, "cargo test --manifest-path /etc/Cargo.toml", "estate"),
    ] {
        let output = run(
            fixture.hook(&format!("deterministic-{index}"), "safe", "loop"),
            &fixture.input(command),
        );
        assert!(hook_reason(&output).starts_with("correction:"));
        assert_eq!(
            journal_values(&fixture.directory.state_root())
                .last()
                .expect("event")["scope"],
            scope
        );
    }
    let (_, command) = role_hook_command(
        &fixture.directory,
        "diagnostic",
        "nonzero",
        &fixture.registry,
    );
    let output = run(command, &fixture.input("printf diagnostic"));
    assert!(hook_reason(&output).starts_with("infrastructure-failure:"));
    assert_eq!(
        journal_values(&fixture.directory.state_root())
            .last()
            .expect("event")["scope"],
        "loop"
    );
}

/// ´test:integration:scope-unknown-and-ambiguous-effects-cannot-gain-loop-authority´
#[test]
fn scope_unknown_and_ambiguous_effects_cannot_gain_loop_authority() {
    let fixture = ScopeFixture::new("scope-unknown");
    let unknown = role_request(
        "outside",
        Path::new("/outside"),
        "printf fixture",
        "unknown",
        None,
    );
    let output = run(fixture.hook("unknown", "safe", "loop"), &unknown);
    assert!(hook_reason(&output).starts_with("infrastructure-failure: caller identity"));
    let mut ambiguous: Value =
        serde_json::from_slice(&fixture.input("printf fixture")).expect("request");
    ambiguous["tool_name"] = json!("Write");
    ambiguous["tool_input"] = json!({"file_path": "$TARGET", "content": "x"});
    let output = run(
        fixture.hook("ambiguous", "safe", "loop"),
        &serde_json::to_vec(&ambiguous).expect("request"),
    );
    assert!(hook_reason(&output).starts_with("infrastructure-failure: scope validation"));
}

/// ´test:integration:scope-marks-reject-cross-loop-unknown-workers-and-estate-sources´
#[test]
fn scope_marks_reject_cross_loop_unknown_workers_and_estate_sources() {
    let fixture = ScopeFixture::new("scope-authority");
    let event = fixture.escalation("printf marked");
    for caller in [
        role_request(
            "session-two",
            &fixture.peer,
            "printf review",
            "review",
            None,
        ),
        role_request(
            "session-one",
            &fixture.checkout,
            "printf review",
            "review",
            Some("/run/subagents/worker.jsonl"),
        ),
        role_request(
            "unknown",
            Path::new("/outside"),
            "printf review",
            "review",
            None,
        ),
    ] {
        assert!(fixture.mark(&event, &caller).is_err());
    }
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    let estate = run(
        fixture.hook("estate", "suspicious", "estate"),
        &fixture.input("printf estate-mark"),
    );
    assert!(hook_reason(&estate).starts_with("escalation:"));
    let records = journal_values(&fixture.directory.state_root());
    assert!(
        fixture
            .mark(
                records.last().expect("estate event"),
                &fixture.input("printf review")
            )
            .is_err()
    );
}

/// ´test:integration:scope-approval-is-single-use-under-concurrent-enforce-retries´
#[test]
fn scope_approval_is_single_use_under_concurrent_enforce_retries() {
    let fixture = ScopeFixture::new("scope-concurrent");
    let event = fixture.escalation("printf concurrent");
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    let children: Vec<_> = (0..4)
        .map(|index| {
            spawn_hook(
                fixture.hook(&format!("retry-{index}"), "suspicious", "loop"),
                &fixture.input("printf concurrent"),
            )
        })
        .collect();
    // All children must start before waiting; a lazy iterator would serialize the retries.
    assert_eq!(children.len(), 4);
    let approved = children
        .into_iter()
        .map(|child| child.wait_with_output().expect("retry exits"))
        .filter(|output| hook_reason(output).starts_with("adjudicated:"))
        .count();
    assert_eq!(approved, 1);
    let records = journal_values(&fixture.directory.state_root());
    assert_eq!(
        records
            .iter()
            .filter(|event| event["event"] == "approval-consumed")
            .count(),
        1
    );
    assert!(records.iter().all(|event| event["scope"] == "loop"));
}

/// ´test:integration:scope-estate-and-infrastructure-failures-beat-loop-approval´
#[test]
fn scope_estate_and_infrastructure_failures_beat_loop_approval() {
    let fixture = ScopeFixture::new("scope-approval-floors");
    let event = fixture.escalation("printf approval-floor");
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    let (_, failing) = role_hook_command(
        &fixture.directory,
        "failed-model",
        "nonzero",
        &fixture.registry,
    );
    assert!(
        hook_reason(&run(failing, &fixture.input("printf approval-floor")))
            .starts_with("infrastructure-failure:")
    );
    let estate = run(
        fixture.hook("estate-retry", "suspicious", "estate"),
        &fixture.input("printf approval-floor"),
    );
    assert!(hook_reason(&estate).starts_with("escalation:"));
    let records = journal_values(&fixture.directory.state_root());
    assert!(
        records
            .iter()
            .all(|event| event["event"] != "approval-consumed")
    );
    let approved = run(
        fixture.hook("loop-retry", "suspicious", "loop"),
        &fixture.input("printf approval-floor"),
    );
    assert!(hook_reason(&approved).starts_with("adjudicated:"));
}

/// ´test:integration:scope-approval-binds-authorization-digests-and-rejects-legacy´
#[test]
fn scope_approval_binds_authorization_digests_and_rejects_legacy() {
    let fixture = ScopeFixture::new("scope-digests");
    let event = fixture.escalation("printf digest-bound");
    assert!(
        fixture
            .mark(&event, &fixture.input("printf review"))
            .is_ok()
    );
    fs::write(
        fixture.checkout.join("local/permissions/domain.md"),
        "Changed reviewed domain\n",
    )
    .expect("changed domain");
    let retry = run(
        fixture.hook("changed-domain", "suspicious", "loop"),
        &fixture.input("printf digest-bound"),
    );
    assert!(hook_reason(&retry).starts_with("escalation:"));
    assert!(
        journal_values(&fixture.directory.state_root())
            .iter()
            .all(|event| event["event"] != "approval-consumed")
    );
    legacy_schema_one_approval_cannot_be_consumed();
}
