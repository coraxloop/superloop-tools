#[path = "support/temporary_root.rs"]
mod temporary_root;

mod support;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

fn invoke(arguments: &[&str], input: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_requests-helper"))
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start requests helper");
    support::write_payload(
        child.stdin.take().expect("stdin"),
        input.to_string().as_bytes(),
        "helper input",
    );
    child.wait_with_output().expect("helper completes")
}

fn evaluate(collection: &Value, action: &str, document: Value, id: Value) -> Output {
    let mut envelope = json!({"schema":1,"collection":collection,"document":null,"id":null,"pending":false,"now_ns":100});
    envelope["document"] = document;
    envelope["id"] = id;
    invoke(&["--snapshot", action], &envelope)
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_reader(std::io::Cursor::new(output.stdout)).expect("JSON output")
}

/// ´test:integration:requests-helper-dispatches-collection-transitions´
#[test]
fn requests_helper_dispatches_collection_transitions() {
    let id = "a".repeat(64);
    let second = "b".repeat(64);
    let rows = [&id, &second].map(|id| {
        request_core::Request::filed(
            id.clone(),
            "door-after-effect".to_owned(),
            json!({"source_id":id,"record":{"id":id}}),
            "worker".to_owned(),
            "run".to_owned(),
            0,
        )
    });
    let original = json!({"schema":1,"revision":0,"requests":rows});
    let listed = success(evaluate(&original, "list", Value::Null, Value::Null));
    assert_eq!(listed["collection"], original);
    assert_eq!(
        listed["result"]["requests"]
            .as_array()
            .expect("summaries")
            .len(),
        2
    );
    let status = success(evaluate(&original, "status", Value::Null, Value::Null));
    assert_eq!(status["collection"], original);
    assert_eq!(status["result"]["counts"][0]["count"], 2);
    let rejected = evaluate(
        &original,
        "triage",
        json!({"schema":1,"items":[{"id":id,"mark_for_review":true},{"id":second,"decision":{"answer":{"outcome":"invalid"},"reason":"bad"}}]}),
        Value::Null,
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert_eq!(rejected.stdout, b"");
    let marked = success(evaluate(
        &original,
        "triage",
        json!({"schema":1,"items":[{"id":id,"mark_for_review":true},{"id":second,"decision":{"answer":{"outcome":"refuse"},"reason":"ordinary"}}]}),
        Value::Null,
    ));
    assert_eq!(
        marked["result"],
        json!({"applied":2,"marked":1,"decided":1})
    );
    assert_eq!(
        evaluate(&marked["collection"], "review", Value::Null, json!(second))
            .status
            .code(),
        Some(2)
    );
    let first = success(evaluate(
        &marked["collection"],
        "review",
        Value::Null,
        json!(id),
    ));
    let latest = success(evaluate(
        &first["collection"],
        "review",
        Value::Null,
        json!(id),
    ));
    assert_ne!(first["result"]["review"], latest["result"]["review"]);
    let mut document = json!({"schema":1,"id":id,"review_id":first["result"]["review"]["review_id"],"decision":{"answer":{"outcome":"allow"},"reason":"reviewed"}});
    assert_eq!(
        evaluate(
            &latest["collection"],
            "adjudicate",
            document.clone(),
            Value::Null
        )
        .status
        .code(),
        Some(2)
    );
    document["review_id"] = latest["result"]["review"]["review_id"].clone();
    let final_state = success(evaluate(
        &latest["collection"],
        "adjudicate",
        document.clone(),
        Value::Null,
    ));
    assert_eq!(final_state["result"]["state"], "adjudicated");
    assert_eq!(
        evaluate(
            &final_state["collection"],
            "adjudicate",
            document,
            Value::Null
        )
        .status
        .code(),
        Some(2)
    );
}

/// ´test:integration:requests-helper-rejects-unknown-authority-and-answers-version´
#[test]
fn requests_helper_rejects_unknown_authority_and_answers_version() {
    let output = invoke(
        &["triage", "--loop", "unknown"],
        &json!({"schema":1,"items":[]}),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    let version = invoke(&["--version"], &Value::Null);
    assert!(version.status.success());
    assert_eq!(version.stdout, b"");
    let record: Value = serde_json::from_slice(&version.stderr).expect("version JSON");
    assert_eq!(record["command"], "requests-helper");
}

/// ´test:integration:requests-helper-keeps-before-effect-judgement-pending´
#[test]
fn requests_helper_keeps_before_effect_judgement_pending() {
    let id = "c".repeat(64);
    let request = request_core::Request::filed(
        id.clone(),
        "door-before-effect".to_owned(),
        json!({"source_id":id,"record":{"id":id}}),
        "worker".to_owned(),
        "run".to_owned(),
        0,
    );
    let collection = json!({"schema":1,"revision":0,"requests":[request]});
    let result = success(evaluate(
        &collection,
        "triage",
        json!({"schema":1,"items":[{"id":id,"decision":{"answer":{"outcome":"allow"},"reason":"approved"}}]}),
        Value::Null,
    ));
    let saved: request_core::Collection =
        serde_json::from_value(result["collection"].clone()).expect("saved collection");
    assert_eq!(saved.requests[0].state, request_core::State::ServicePending);
    assert_eq!(saved.requests[0].answer(), None);
}

struct OwnerFixture(std::path::PathBuf);

/// The private helper selects only its loop journal, even when estate evidence is nearby.
/// ´test:integration:requests-helper-never-reads-estate-journals-or-outboxes´
#[test]
fn requests_helper_never_reads_estate_journals_or_outboxes() {
    use std::os::unix::fs::MetadataExt as _;
    let fixture = OwnerFixture::new();
    let estate = fixture.0.join("state/estate-escalations.jsonl");
    let outbox = fixture.0.join("outboxes/fixture");
    std::fs::create_dir_all(&outbox).expect("outbox");
    let outbox = outbox.join("unread.json");
    for path in [&estate, &outbox] {
        std::fs::write(path, b"malformed estate evidence must not be read\n")
            .expect("foreign evidence");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))
            .expect("unreadable evidence");
    }
    let before: Vec<_> = [&estate, &outbox]
        .iter()
        .map(|path| {
            let metadata = std::fs::metadata(path).expect("metadata");
            (
                metadata.ino(),
                metadata.len(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            )
        })
        .collect();
    for action in ["status", "list", "--owner-read"] {
        let output = Command::new(env!("CARGO_BIN_EXE_requests-helper"))
            .args([action, "--loop", "fixture"])
            .env_clear()
            .env(
                "PERMISSION_TRIAGE_LOOP_REGISTRY",
                fixture.0.join("registry"),
            )
            .env(
                "PERMISSION_TRIAGE_STATE_ROOT",
                fixture.0.join("foreign-state"),
            )
            .output()
            .expect("helper");
        assert!(
            output.status.success(),
            "{action}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("malformed estate evidence"));
    }
    let refused = Command::new(env!("CARGO_BIN_EXE_requests-helper"))
        .args(["list", "--loop", "fixture", "--scope", "estate"])
        .env_clear()
        .env(
            "PERMISSION_TRIAGE_LOOP_REGISTRY",
            fixture.0.join("registry"),
        )
        .output()
        .expect("removed scope refuses");
    assert_eq!(refused.status.code(), Some(2));
    assert!(!fixture.0.join("state/escalations.jsonl").exists());
    for (path, expected) in [&estate, &outbox].iter().zip(before) {
        let metadata = std::fs::metadata(path).expect("unchanged metadata");
        assert_eq!(
            (
                metadata.ino(),
                metadata.len(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec()
            ),
            expected
        );
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restore fixture mode");
        assert_eq!(
            std::fs::read(path).expect("retained evidence"),
            b"malformed estate evidence must not be read\n"
        );
    }
}

impl OwnerFixture {
    fn new() -> Self {
        Self::at(&temporary_root::temporary_root())
    }

    fn at(base: &std::path::Path) -> Self {
        let path = base.join(format!(
            "requests-owner-{}-{}",
            std::process::id(),
            request_core::now_ns().expect("clock")
        ));
        for directory in [&path, &path.join("registry"), &path.join("state")] {
            std::fs::create_dir(directory).expect("fixture directory");
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("private directory");
        }
        let row = path.join("registry/fixture.env");
        std::fs::write(
            &row,
            format!(
                "LOOP_NAME=fixture\nLOOP_SID=fixture\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                path.display(),
                path.join("state").display()
            ),
        )
        .expect("registry row");
        std::fs::set_permissions(row, std::fs::Permissions::from_mode(0o600)).expect("private row");
        Self(path)
    }

    fn invoke(&self, phase: &str, action: &str, input: &Value) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_requests-helper"));
        command.arg(phase);
        if phase != "--owner-read" {
            command.arg(action);
        }
        let mut child = command
            .args(["--loop", "fixture"])
            .env_clear()
            .env("PERMISSION_TRIAGE_LOOP_REGISTRY", self.0.join("registry"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("owner helper");
        support::write_payload(
            child.stdin.take().expect("stdin"),
            input.to_string().as_bytes(),
            "owner input",
        );
        child.wait_with_output().expect("owner output")
    }

    fn commit(&self, action: &str, input: &mut Value) -> Value {
        input["expected"] = Value::Null;
        let preview = success(self.invoke("--owner-preview", action, input));
        input["expected"] = preview["before"].clone();
        let committed = success(self.invoke("--owner-commit", action, input));
        assert_eq!(committed, preview);
        committed
    }
}

/// ´test:integration:request-helper-refuses-foreign-registry-and-state-owners´
#[test]
#[ignore = "requires provisioned namespace root with UIDs 41001 and 41002 mapped"]
fn request_helper_refuses_foreign_registry_and_state_owners() {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::unistd::{Uid, chown};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    assert!(
        Uid::effective().is_root(),
        "provisioned namespace root required"
    );
    // Only tiny custody records use /tmp; execute the held build artifact
    // through its inherited descriptor without copying a binary into tmpfs.
    let fixture = OwnerFixture::at(std::path::Path::new("/tmp"));
    let binary = std::fs::File::open(env!("CARGO_BIN_EXE_requests-helper")).expect("built helper");
    fcntl(&binary, FcntlArg::F_SETFD(FdFlag::empty())).expect("inherit executable descriptor");
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o711))
        .expect("searchable fixture");
    let run = |uid, action: &str| {
        Command::new(format!("/proc/self/fd/{}", binary.as_raw_fd()))
            .args([action, "--loop", "fixture"])
            .env_clear()
            .env(
                "PERMISSION_TRIAGE_LOOP_REGISTRY",
                fixture.0.join("registry"),
            )
            .uid(uid)
            .gid(uid)
            .output()
            .expect("helper under mapped uid")
    };
    let own = |name: &str, uid| {
        chown(&fixture.0.join(name), Some(Uid::from_raw(uid)), None).expect("fixture ownership");
    };
    for caller in [41001, 41002] {
        let other = if caller == 41001 { 41002 } else { 41001 };
        own("registry", caller);
        own("registry/fixture.env", caller);
        own("state", caller);
        for action in ["status", "list"] {
            assert!(
                run(caller, action).status.success(),
                "same-account acceptance"
            );
            own("state", other);
            let refusal = run(caller, action);
            assert_eq!(refusal.status.code(), Some(2));
            assert_eq!(refusal.stdout, b"");
            assert_ne!(refusal.stderr, b"");
            own("state", caller);
            own("registry", other);
            let refusal = run(caller, action);
            assert_eq!(refusal.status.code(), Some(2));
            assert_eq!(refusal.stdout, b"");
            assert_ne!(refusal.stderr, b"");
            own("registry", caller);
        }
    }
}

/// ´test:integration:requests-helper-decodes-worker-context-before-permission-mutation´
#[test]
fn requests_helper_decodes_worker_context_before_permission_mutation() {
    let fixture = OwnerFixture::new();
    let context = fixture.0.join("worker-context.json");
    std::fs::write(&context, json!({"hook_event_name":"PreToolUse","permission_mode":"default","session_id":"fixture","cwd":fixture.0,"agent_id":"worker","transcript_path":"/fixture/subagents/agent-worker.jsonl","tool_name":"Bash","tool_use_id":"worker-use","tool_input":{"command":"true"}}).to_string()).expect("worker-shaped request");
    let mut child = Command::new(env!("CARGO_BIN_EXE_requests-helper"))
        .args(["triage", "--loop", "fixture"])
        .env_clear()
        .env(
            "PERMISSION_TRIAGE_LOOP_REGISTRY",
            fixture.0.join("registry"),
        )
        .env("PERMISSION_TRIAGE_REQUEST_CONTEXT", &context)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("worker context helper");
    support::write_payload(
        child.stdin.take().expect("stdin"),
        b"{\"schema\":1,\"items\":[]}",
        "worker document",
    );
    let output = child.wait_with_output().expect("worker refusal");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    let refusal: Value = serde_json::from_slice(&output.stderr).expect("refusal JSON");
    assert!(
        refusal["detail"]
            .as_str()
            .expect("detail")
            .contains("no registered loop authority"),
        "{refusal}"
    );
    assert_eq!(
        std::fs::read_dir(fixture.0.join("state"))
            .expect("unchanged state")
            .count(),
        0
    );
}

impl Drop for OwnerFixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

/// ´test:integration:requests-owner-preview-commit-and-service-claims´
#[test]
#[allow(clippy::too_many_lines)]
fn requests_owner_preview_commit_and_service_claims() {
    let fixture = OwnerFixture::new();
    let id = "e".repeat(64);
    let row = request_core::Request::filed(
        id.clone(),
        "door-before-effect".to_owned(),
        json!({"source_id":"run:e","record":{"id":"run:e"}}),
        "worker".to_owned(),
        "run".to_owned(),
        0,
    );
    let mut input = json!({"schema":1,"records":[row],"document":{"schema":1,"items":[{"id":id,"decision":{"answer":{"outcome":"allow"},"reason":"fixture decision"}}]},"id":null,"pending":false,"now_ns":100,"expected":null,"publication":null});
    let preview = success(fixture.invoke("--owner-preview", "triage", &input));
    assert!(!fixture.0.join("state/escalations.jsonl").exists());
    input["expected"] = preview["before"].clone();
    input["publication"] = preview["collection"].clone();
    input["publication"]["requests"][0]["decision"]["answer"]["outcome"] = json!("refuse");
    assert_eq!(
        fixture
            .invoke("--owner-commit", "triage", &input)
            .status
            .code(),
        Some(2)
    );
    assert!(!fixture.0.join("state/escalations.jsonl").exists());
    input["publication"] = Value::Null;
    let applied = success(fixture.invoke("--owner-commit", "triage", &input));
    assert_eq!(
        applied["collection"]["requests"][0]["state"],
        "service-pending"
    );
    let bytes = std::fs::read(fixture.0.join("state/escalations.jsonl")).expect("durable journal");
    assert_eq!(
        fixture
            .invoke("--owner-commit", "triage", &input)
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        std::fs::read(fixture.0.join("state/escalations.jsonl")).expect("unchanged journal"),
        bytes
    );
    input["records"] = json!([]);
    input["document"] = json!({"schema":1,"id":id,"claim":"service-e"});
    let claimed = fixture.commit("claim", &mut input);
    assert_eq!(claimed["result"]["claimed"], true);
    assert_eq!(
        fixture.commit("claim", &mut input)["result"]["claimed"],
        false
    );
    input["document"]["result"] = json!({"outcome":"completed","performed":true});
    fixture.commit("complete", &mut input);
    let exported = success(fixture.invoke("--owner-read", "", &Value::Null));
    assert_eq!(exported["requests"][0]["state"], "completed");
    let collection: request_core::Collection =
        serde_json::from_value(exported).expect("collection");
    assert!(collection.requests[0].answer().is_some());
    let gone_id = "f".repeat(64);
    let gone = request_core::Request::filed(
        gone_id.clone(),
        "door-before-effect".to_owned(),
        json!({"source_id":"run:f","record":{"id":"run:f"}}),
        "worker".to_owned(),
        "run".to_owned(),
        0,
    );
    input["records"] = json!([gone]);
    input["document"] = json!({"schema":1,"id":gone_id});
    fixture.commit("withdraw", &mut input);
    input["records"] = json!([]);
    input["document"] = json!({"schema":1,"items":[{"id":gone_id,"decision":{"answer":{"outcome":"allow"},"reason":"late judgement"}}]});
    fixture.commit("triage", &mut input);
    input["document"] = json!({"schema":1,"id":gone_id,"claim":"service-f"});
    let gone_result = fixture.commit("claim", &mut input);
    assert_eq!(gone_result["result"]["claimed"], false);
    let gone_row = &gone_result["collection"]["requests"][1];
    assert_eq!(gone_row["state"], "completed");
    assert_eq!(gone_row["service_result"]["performed"], false);
}

/// ´test:integration:gateway-filing-cannot-supply-judgement-or-another-loop´
#[test]
fn gateway_filing_cannot_supply_judgement_or_another_loop() {
    let fixture = OwnerFixture::new();
    let id = request_core::request_id(b"gateway-fixture");
    let body = json!({"schema":1,"loop_name":"fixture","gateway_id":"a".repeat(64),
        "registration_digest":"b".repeat(64),"proposal":{"schema":1,"lane":"lane",
        "seq":1,"argv":["/bin/true"],"reason":"fixture","queued_unix_ms":1,"timeout_seconds":60}});
    let mut row = request_core::Request::filed(
        id.clone(),
        "gateway-proposal".into(),
        body,
        "lane".into(),
        "1".into(),
        1_000_000,
    );
    let envelope = |row: &request_core::Request| {
        json!({"schema":1,"records":[row],"document":null,"id":null,
        "pending":false,"now_ns":100,"expected":null,"publication":null})
    };
    let original = row.clone();
    row.state = request_core::State::ServicePending;
    row.decision_state = Some(request_core::State::TriageDecided);
    row.decision = Some(request_core::Decision {
        answer: json!({"outcome":"approve"}),
        reason: "forged".into(),
    });
    assert_eq!(
        fixture
            .invoke("--owner-preview", "file", &envelope(&row))
            .status
            .code(),
        Some(2)
    );
    row = original.clone();
    row.body["loop_name"] = json!("another-loop");
    assert_eq!(
        fixture
            .invoke("--owner-preview", "file", &envelope(&row))
            .status
            .code(),
        Some(2)
    );
    let mut input = envelope(&original);
    fixture.commit("file", &mut input);
    let saved = success(fixture.invoke("--owner-read", "", &json!(null)));
    let mut repeated = envelope(&original);
    fixture.commit("file", &mut repeated);
    assert_eq!(
        success(fixture.invoke("--owner-read", "", &json!(null))),
        saved
    );
    for document in [
        json!({"schema":1,"items":[{"id":id,"mark_for_review":true}]}),
        json!({"schema":1,"items":[{"id":id,"decision":{"answer":{"outcome":"approve"},"reason":"forged"}}]}),
    ] {
        let input = json!({"schema":1,"records":[],"document":document,"id":null,"pending":false,
            "now_ns":100,"expected":null,"publication":null});
        assert_eq!(
            fixture
                .invoke("--owner-preview", "triage", &input)
                .status
                .code(),
            Some(2)
        );
        assert_eq!(
            success(fixture.invoke("--owner-read", "", &json!(null))),
            saved
        );
    }
    let mut obsolete = envelope(&original);
    obsolete
        .as_object_mut()
        .expect("envelope")
        .remove("records");
    obsolete["doors"] = json!([]);
    assert_eq!(
        fixture
            .invoke("--owner-preview", "file", &obsolete)
            .status
            .code(),
        Some(2)
    );
}
