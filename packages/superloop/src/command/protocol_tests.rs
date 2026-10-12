//! Protocol state tests use explicit policy observations; these are not UID authentication acceptance.

use super::*;
use execute_command::snapshot::{PolicySnapshot, Source};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("protocol fixture");
        fs::create_dir(root.path().join("state")).expect("journal root");
        fs::set_permissions(root.path().join("state"), fs::Permissions::from_mode(0o700))
            .expect("journal mode");
        write(&root.path().join("policy-version"), "original-policy");
        Self { root }
    }

    fn call(&self, action: &str, input: &Value) -> Result<Value, Error> {
        validate_input(action, input)?;
        let request = if action == "judge" {
            let request = Request::from_json(
                &serde_json::to_vec(&input["request"]).map_err(|_| Error::shape())?,
            )
            .map_err(|_| Error::shape())?;
            if !binding_valid(&request) {
                return Err(Error::shape());
            }
            Some(request)
        } else {
            None
        };
        let directory = File::open(self.root.path().join("state")).map_err(Error::storage)?;
        let metadata = directory.metadata().map_err(Error::storage)?;
        let authority = Authority {
            schema: 1,
            loop_name: "fixture".into(),
            root: self.root.path().join("state"),
            device: metadata.dev(),
            inode: metadata.ino(),
            principal: "fixture-loop".into(),
            registration: "registered-fixture".into(),
            snapshot_digest: execute_command::rubric::sha256_digest(
                &fs::read(self.root.path().join("policy-version")).expect("policy version"),
            ),
            role: "orchestrator".into(),
            cwd: self.root.path().to_string_lossy().into_owned(),
            scope: Some("estate".into()),
        };
        let source = |value| Source::new("fixture".into(), value).expect("source");
        let mut groups = serde_json::Map::new();
        if let Some(request) = &request {
            let key = judgement::key(request)?;
            if input["request"]["command"]["bytes"]
                .as_array()
                .is_some_and(|bytes| {
                    bytes.starts_with(&[
                        json!(112),
                        json!(114),
                        json!(105),
                        json!(110),
                        json!(116),
                        json!(102),
                    ])
                })
            {
                groups.insert(
                    json!([key.class, key.operation, key.shape_key]).to_string(),
                    json!({"allow":1,"refuse":0,"citations":["fixture-review"]}),
                );
            }
        }
        let policy = PolicySnapshot {
            schema: 1,
            loop_name: "fixture".into(),
            loop_uid: 41001,
            written_at: "1".into(),
            door: true,
            registry: source(json!({"floor":"audit"})),
            modes: source(json!({"ledger":{"loop_settings":[],"classes":[]},"effective":{}})),
            learned: source(json!({"groups":groups})),
            rubric: source(json!({"agent":null})),
        };
        execute(action, input, request, &authority, &policy, &directory)
    }

    fn ok(&self, action: &str, input: &Value) -> Value {
        self.call(action, input).expect("protocol result")
    }

    fn refused(&self, action: &str, input: &Value, rule: &str) {
        assert_eq!(self.call(action, input).expect_err("refusal").rule, rule);
    }

    fn request(&self, command: &str) -> Value {
        let context =
            self.ok("status", &json!({"schema":1,"binding":null,"resolve":null}))["context"]
                .clone();
        let mut request = json!({"schema":1,"command":{"representation":"bytes","bytes":command.as_bytes()},"context":{
            "cwd":self.root.path(),"requester":context["principal"],"loop_id":"fixture","lane":null,"run":null,"purpose":"fixture command",
            "deadline_unix_ms":4_102_444_800_000_u64,"snapshot":"fixture","registration":context["registration"],"resources":[],"authority":"caller-loop",
            "checks":[],"rubric":"no direct vendor configured","mode":"enforce","floor":"enforce","policy":"review required after deterministic miss"},
            "implications":{"effects":[],"resources":[],"principals":[],"reversibility":"unknown","scope_uncertainty":"fixture observation","evidence":[]}});
        request["binding"] = json!({"request_id":request_core::request_id(request.to_string().as_bytes()),"context_digest":request_core::request_id(request["context"].to_string().as_bytes())});
        request
    }

    fn approve(&self, request: &Value, judged: &Value) -> Value {
        let principal = self.ok("status", &json!({"schema":1,"binding":null,"resolve":null}))["context"]["principal"].clone();
        self.ok("answer", &json!({"schema":1,"answer":{"binding":request["binding"],"review":judged["review"],"answer":"approve","adjudicator":principal,"reason":"reviewed exact fixture"}}))
    }
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).expect("fixture bytes");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private fixture file");
}

/// Current review grants one claim; lost acknowledgements and completion retries never grant another effect.
/// # Panics
/// Panics only if the fixed fixture cannot be prepared or a protocol operation violates the asserted protocol.
/// ´claim:command:direct-command-review-claim-and-completion-use-one-registered-record´
/// ´test:unit:direct-command-review-claim-and-completion-use-one-registered-record´
#[test]
fn direct_command_review_claim_and_completion_use_one_registered_record() {
    let fixture = Fixture::new();
    let request = fixture.request("printf fixture");
    let absent = fixture.ok(
        "status",
        &json!({"schema":1,"binding":request["binding"],"resolve":"unpublished-judge"}),
    );
    assert_eq!(absent["resolution"]["committed"], false);
    assert_eq!(absent["verdict"], Value::Null);
    let judged = fixture.ok("judge", &json!({"schema":1,"request":request}));
    assert_eq!(judged["verdict"]["judgement"], "refer");
    assert_eq!(judged["verdict"]["scope"], "loop");
    let path = fixture.root.path().join("state/command-requests.jsonl");
    let bytes = fs::read(&path).expect("registered journal");
    assert_eq!(
        fixture.ok("judge", &json!({"schema":1,"request":request})),
        judged
    );
    assert_eq!(fs::read(&path).expect("unchanged retry"), bytes);
    let principal = request["context"]["requester"].clone();
    fixture.refused("answer", &json!({"schema":1,"answer":{"binding":request["binding"],"review":"stale","answer":"approve","adjudicator":principal,"reason":"stale review"}}), "execute-command-escalation-shape");
    fixture.refused("answer", &json!({"schema":1,"answer":{"binding":request["binding"],"review":judged["review"],"answer":"approve","adjudicator":"forged","reason":"forged sender"}}), "execute-command-persistence-authority");
    let approved = fixture.approve(&request, &judged);
    assert_eq!(approved["verdict"]["judgement"], "allow");
    fixture.refused("answer", &json!({"schema":1,"answer":{"binding":request["binding"],"review":judged["review"],"answer":"approve","adjudicator":principal,"reason":"duplicate delivery"}}), "execute-command-record-transition");
    let claimed = fixture.ok("claim", &json!({"schema":1,"binding":request["binding"]}));
    assert_eq!(claimed["fresh_claim"], true);
    assert_eq!(claimed["outcome"]["outcome"], "outcome-unknown");
    let recovered = fixture.ok("status", &json!({"schema":1,"binding":request["binding"],"resolve":claimed["claim"]["operation_id"]}));
    assert_eq!(recovered["fresh_claim"], false);
    assert_eq!(recovered["claim"], claimed["claim"]);
    assert_eq!(recovered["resolution"]["committed"], true);
    write(&fixture.root.path().join("effect"), "one effect\n");
    fixture.refused(
        "claim",
        &json!({"schema":1,"binding":request["binding"]}),
        "execute-command-claim-used",
    );
    let outcome = json!({"binding":request["binding"],"outcome":"completed","rationale":"fixture effect observed","queue_wall_ms":null,"judgement_wall_ms":null,"execution_wall_ms":1});
    let complete = json!({"schema":1,"binding":request["binding"],"outcome":outcome});
    let completed = fixture.ok("complete", &complete);
    assert_eq!(completed["outcome"], outcome);
    let before = fs::read(&path).expect("completed bytes");
    assert_eq!(fixture.ok("complete", &complete), completed);
    assert_eq!(fs::read(&path).expect("identical completion"), before);
    let resolved = fixture.ok("status", &json!({"schema":1,"binding":request["binding"],"resolve":claimed["claim"]["operation_id"]}));
    assert_eq!(resolved["resolution"]["committed"], true);
    let stored: Value = serde_json::from_slice(&before).expect("retained evidence");
    assert_eq!(
        stored["rows"][0]["answer"]["adjudicator"],
        request["context"]["requester"]
    );
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("effect")).expect("counter"),
        "one effect\n"
    );
    assert!(!fixture.root.path().join("unused-home").exists());
    let mut conflict = complete;
    conflict["outcome"]["outcome"] = json!("failed");
    fixture.refused("complete", &conflict, "execute-command-record-transition");
}

/// Hygiene refusals and unavailable estate authority retain structured remedies and no effect.
/// # Panics
/// Panics only if the fixed fixture cannot be prepared or a protocol operation violates the asserted protocol.
/// ´claim:command:direct-command-hygiene-and-unprovisioned-estate-route-have-no-effects´
/// ´test:unit:direct-command-hygiene-and-unprovisioned-estate-route-have-no-effects´
#[test]
fn direct_command_hygiene_and_unprovisioned_estate_route_have_no_effects() {
    let fixture = Fixture::new();
    let request = fixture.request("rm -rf \"$TARGET\"");
    let verdict = fixture.ok("judge", &json!({"schema":1,"request":request}));
    assert_eq!(verdict["verdict"]["judgement"], "refuse");
    assert!(verdict["verdict"]["correction"].is_object());
    assert_eq!(verdict["outcome"]["outcome"], "refused-before-effect");
    fixture.refused(
        "claim",
        &json!({"schema":1,"binding":request["binding"]}),
        "execute-command-record-transition",
    );
    let request = fixture.request("systemctl status fixture");
    let judged = fixture.ok("judge", &json!({"schema":1,"request":request}));
    assert_eq!(judged["verdict"]["scope"], "estate");
    assert!(
        judged["verdict"]["escalation"]["resume_conditions"]
            .as_str()
            .expect("provisioning remedy")
            .contains("operations")
    );
    fixture.refused("answer", &json!({"schema":1,"answer":{"binding":request["binding"],"review":judged["review"],"answer":"approve","adjudicator":request["context"]["requester"],"reason":"no estate authority"}}), "execute-command-route-unprovisioned");
    assert!(
        !fixture
            .root
            .path()
            .join("state/command-escalations.jsonl")
            .exists()
    );
}

/// Unknown schemas and changed command context refuse before a journal is created.
/// # Panics
/// Panics only if the fixed fixture cannot be prepared or a protocol operation violates the asserted protocol.
/// ´claim:command:direct-command-unknown-shapes-and-changed-bindings-refuse-before-publication´
/// ´test:unit:direct-command-unknown-shapes-and-changed-bindings-refuse-before-publication´
#[test]
fn direct_command_unknown_shapes_and_changed_bindings_refuse_before_publication() {
    let fixture = Fixture::new();
    fixture.refused(
        "status",
        &json!({"schema":2,"binding":null,"resolve":null}),
        "execute-command-request-shape",
    );
    let mut request = fixture.request("printf fixture");
    request["schema"] = json!(2);
    fixture.refused(
        "judge",
        &json!({"schema":1,"request":request}),
        "execute-command-request-shape",
    );
    request["schema"] = json!(1);
    request["context"]["purpose"] = json!("changed after digest");
    fixture.refused(
        "judge",
        &json!({"schema":1,"request":request}),
        "execute-command-request-shape",
    );
    assert!(
        !fixture
            .root
            .path()
            .join("state/command-requests.jsonl")
            .exists()
    );
}

/// Policy drift and malformed stored records refuse without an implicit conversion.
/// # Panics
/// Panics only if the fixed fixture cannot be prepared or a protocol operation violates the asserted protocol.
/// ´claim:command:direct-command-policy-drift-and-stored-shapes-refuse-without-rewrite´
/// ´test:unit:direct-command-policy-drift-and-stored-shapes-refuse-without-rewrite´
#[test]
fn direct_command_policy_drift_and_stored_shapes_refuse_without_rewrite() {
    let fixture = Fixture::new();
    let request = fixture.request("printf fixture");
    let judged = fixture.ok("judge", &json!({"schema":1,"request":request}));
    fixture.approve(&request, &judged);
    let path = fixture.root.path().join("state/command-requests.jsonl");
    let original = fs::read(&path).expect("journal");
    let registry = fixture.root.path().join("policy-version");
    let registered = fs::read_to_string(&registry).expect("registration");
    write(&registry, &(registered.clone() + "changed-policy"));
    fixture.refused(
        "claim",
        &json!({"schema":1,"binding":request["binding"]}),
        "execute-command-persistence-authority",
    );
    assert_eq!(fs::read(&path).expect("no publication"), original);
    write(&registry, &registered);
    let mut database: Value = serde_json::from_slice(&original).expect("snapshot");
    database["schema"] = json!(2);
    write(&path, &database.to_string());
    let changed = fs::read(&path).expect("predecessor");
    fixture.refused(
        "status",
        &json!({"schema":1,"binding":request["binding"],"resolve":null}),
        "execute-command-record-shape",
    );
    assert_eq!(fs::read(&path).expect("no conversion"), changed);
    database["schema"] = json!(1);
    database["rows"][0]
        .as_object_mut()
        .expect("row")
        .remove("claim");
    write(&path, &database.to_string());
    fixture.refused(
        "status",
        &json!({"schema":1,"binding":request["binding"],"resolve":null}),
        "execute-command-record-shape",
    );
}

/// Denied, expired and symlink-custody requests cannot grant an execution claim.
/// # Panics
/// Panics only if the fixed fixture cannot be prepared or a protocol operation violates the asserted protocol.
/// ´claim:command:direct-command-denial-deadline-and-symlink-never-grant-an-effect´
/// ´test:unit:direct-command-denial-deadline-and-symlink-never-grant-an-effect´
#[test]
fn direct_command_denial_deadline_and_symlink_never_grant_an_effect() {
    let fixture = Fixture::new();
    let request = fixture.request("printf denied");
    let judged = fixture.ok("judge", &json!({"schema":1,"request":request}));
    let denied = fixture.ok("answer", &json!({"schema":1,"answer":{"binding":request["binding"],"review":judged["review"],"answer":"deny","adjudicator":request["context"]["requester"],"reason":"deny exact request"}}));
    assert_eq!(denied["outcome"]["outcome"], "refused-before-effect");
    fixture.refused(
        "claim",
        &json!({"schema":1,"binding":request["binding"]}),
        "execute-command-record-transition",
    );
    let mut expired = fixture.request("printf expired");
    expired["context"]["deadline_unix_ms"] = json!(1);
    expired.as_object_mut().expect("request").remove("binding");
    expired["binding"] = json!({"request_id":request_core::request_id(expired.to_string().as_bytes()),"context_digest":request_core::request_id(expired["context"].to_string().as_bytes())});
    let judged = fixture.ok("judge", &json!({"schema":1,"request":expired}));
    fixture.approve(&expired, &judged);
    fixture.refused(
        "claim",
        &json!({"schema":1,"binding":expired["binding"]}),
        "execute-command-record-transition",
    );
    let path = fixture.root.path().join("state/command-requests.jsonl");
    let retained = fixture.root.path().join("retained");
    fs::rename(&path, &retained).expect("retain bytes");
    std::os::unix::fs::symlink(&retained, &path).expect("unsafe journal");
    fixture.refused(
        "status",
        &json!({"schema":1,"binding":request["binding"],"resolve":null}),
        "execute-command-persistence-storage",
    );
}

/// Caller preflight may record no effect after a durable claim without reopening that claim.
/// # Panics
/// Panics only if the fixed fixture cannot be prepared or a protocol operation violates the asserted protocol.
/// ´claim:command:direct-command-preflight-refusal-keeps-claim-consumed´
/// ´test:unit:direct-command-preflight-refusal-keeps-claim-consumed´
#[test]
fn direct_command_preflight_refusal_keeps_claim_consumed() {
    let fixture = Fixture::new();
    let request = fixture.request("printf preflight");
    let judged = fixture.ok("judge", &json!({"schema":1,"request":request}));
    fixture.approve(&request, &judged);
    fixture.ok("claim", &json!({"schema":1,"binding":request["binding"]}));
    let outcome = json!({"binding":request["binding"],"outcome":"refused-before-effect","rationale":"execution adapter refused before spawning","queue_wall_ms":null,"judgement_wall_ms":null,"execution_wall_ms":null});
    let completed = fixture.ok(
        "complete",
        &json!({"schema":1,"binding":request["binding"],"outcome":outcome}),
    );
    assert_eq!(completed["outcome"], outcome);
    fixture.refused(
        "claim",
        &json!({"schema":1,"binding":request["binding"]}),
        "execute-command-claim-used",
    );
}
