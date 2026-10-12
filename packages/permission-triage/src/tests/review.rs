use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::review::{
    COMMAND_CREDENTIAL_WARNING, ReviewError, ReviewEscalation, load_outbox_review,
    review_from_bytes,
};

static NEXT_OUTBOX_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct OutboxFixture(PathBuf);

impl OutboxFixture {
    fn new(name: &str) -> Self {
        let sequence = NEXT_OUTBOX_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "permission-triage-review-outbox-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique outbox fixture");
        Self(path)
    }

    fn outbox(&self, name: &str) -> PathBuf {
        self.0.join("outboxes").join(name)
    }

    fn create_outbox(&self, name: &str) -> PathBuf {
        let path = self.outbox(name);
        fs::create_dir_all(&path).expect("outbox directory");
        path
    }
}

impl Drop for OutboxFixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn write_outbox_value(outbox: &Path, value: &Value) {
    let id = value["event_id"].as_str().expect("event identifier");
    let mut bytes = serde_json::to_vec(value).expect("outbox JSON");
    bytes.push(b'\n');
    let path = outbox.join(id);
    fs::write(&path, bytes).expect("outbox event");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("outbox event mode");
}

fn escalation(id: &str, recorded_at: &str, command: &str) -> Value {
    json!({
        "schema": 1,
        "event": "escalated",
        "event_id": id,
        "recorded_at": recorded_at,
        "tool_use_id": format!("use-{id}"),
        "request_digest": format!("digest-{id}"),
        "tool": "Bash",
        "cwd": "/workspace/project",
        "command": command,
        "classification": "suspicious",
        "reason": "fixture reason",
        "general_rubric_digest": "general-digest",
        "owner_rubric_digest": null,
        "role": "orchestrator",
        "loop_name": "orchestration",
        "stale_session": false,
        "domain_rubric_digest": "domain-digest",
        "model_status": "success"
    })
}

fn disposition(source: &Value, outcome: &str) -> Value {
    let mut value = source.clone();
    value["event"] = json!("disposition");
    value["recorded_at"] = json!("2026-09-03T12:00:00.000000000Z");
    value["reason"] = json!("owner mark");
    value["model_status"] = json!("owner-mark");
    value["outcome"] = json!(outcome);
    if outcome == "corrected-and-rerun" {
        value["request_digest"] = json!("corrected-digest");
    }
    if source["schema"] == 2 {
        value["adjudicator_role"] = json!("estate-orchestrator");
        value["adjudicator_loop_name"] = source["loop_name"].clone();
        value["source_scope"] = json!("estate");
    }
    value
}

fn schema_2(mut value: Value, mode: &str) -> Value {
    value["schema"] = json!(2);
    value["scope"] = json!("estate");
    value["mode"] = json!(mode);
    value["would_be_decision"] = json!("deny");
    value["emitted_decision"] = if mode == "audit" {
        Value::Null
    } else {
        json!("deny")
    };
    value["wall_ms"] = json!(7);
    value["model_wall_ms"] = json!(3);
    value
}

fn stream(values: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend(serde_json::to_vec(value).expect("fixture serializes"));
        bytes.push(b'\n');
    }
    bytes
}

/// ´test:crate:outbox-review-orders-two-loops-by-time-then-event-id´
#[test]
fn outbox_review_orders_two_loops_by_time_then_event_id() {
    let fixture = OutboxFixture::new("two-loops");
    let alpha = fixture.create_outbox("alpha");
    let beta = fixture.create_outbox("beta");
    let later_id = "c".repeat(64);
    let first_id = "a".repeat(64);
    let second_id = "b".repeat(64);
    let mut later = schema_2(
        escalation(&later_id, "2026-09-03T11:00:00.000000000Z", "printf later"),
        "audit",
    );
    later["loop_name"] = json!("alpha");
    let mut first = schema_2(
        escalation(&first_id, "2026-09-03T10:00:00.000000000Z", "printf first"),
        "audit",
    );
    first["loop_name"] = json!("beta");
    let mut second = schema_2(
        escalation(
            &second_id,
            "2026-09-03T10:00:00.000000000Z",
            "printf second",
        ),
        "audit",
    );
    second["loop_name"] = json!("alpha");
    write_outbox_value(&alpha, &later);
    write_outbox_value(&alpha, &second);
    write_outbox_value(&beta, &first);
    let review = load_outbox_review(&[("alpha".to_owned(), alpha), ("beta".to_owned(), beta)])
        .expect("two outboxes load");
    assert_eq!(
        review
            .events()
            .iter()
            .map(|item| item.escalation().event_id())
            .collect::<Vec<_>>(),
        [first_id.as_str(), second_id.as_str(), later_id.as_str()]
    );
    assert_eq!(review.events()[0].escalation().loop_name(), Some("beta"));
    assert_eq!(review.events()[1].escalation().loop_name(), Some("alpha"));
    assert_eq!(review.groups().len(), 3);
    let rendered = review.render();
    let first_label = format!("id={first_id}");
    let second_label = format!("id={second_id}");
    assert!(
        rendered.find(first_label.as_str()).expect("first event")
            < rendered.find(second_label.as_str()).expect("second event")
    );
    assert!(rendered.contains("Caller loop: \"alpha\""));
    assert!(rendered.contains("Caller loop: \"beta\""));
    assert!(rendered.contains("Candidate owner-rubric rows for outbox events"));
    assert_eq!(rendered.matches("|<rule-id>|").count(), 3);
    assert!(rendered.contains("Outbox events cannot be marked in this bite."));
}

/// ´test:crate:outbox-review-reports-record-loop-mismatch-and-uses-path´
#[test]
fn outbox_review_reports_record_loop_mismatch_and_uses_path() {
    let fixture = OutboxFixture::new("loop-mismatch");
    let outbox = fixture.create_outbox("alpha");
    let id = "d".repeat(64);
    let mut value = schema_2(
        escalation(&id, "2026-09-03T10:00:00.000000000Z", "printf mismatch"),
        "audit",
    );
    value["loop_name"] = json!("claimed-peer");
    write_outbox_value(&outbox, &value);
    let review = load_outbox_review(&[("alpha".to_owned(), outbox)])
        .expect("mismatched claim is reviewable");
    assert_eq!(review.events()[0].escalation().loop_name(), Some("alpha"));
    assert_eq!(
        review.events()[0].recorded_loop_name(),
        Some("claimed-peer")
    );
    assert!(review.events()[0].loop_mismatch());
    assert!(review.render().contains("caller_loop=\"alpha\""));
    assert!(
        review
            .render()
            .contains("loop_name_mismatch=record:\"claimed-peer\"")
    );
}

/// ´test:crate:outbox-review-skips-malformed-and-symlink-files´
#[test]
fn outbox_review_skips_malformed_and_symlink_files() {
    let fixture = OutboxFixture::new("malformed");
    let outbox = fixture.create_outbox("alpha");
    let valid_id = "e".repeat(64);
    let routine_id = "f".repeat(64);
    let mut valid = schema_2(
        escalation(&valid_id, "2026-09-03T10:00:00.000000000Z", "printf valid"),
        "audit",
    );
    valid["loop_name"] = json!("alpha");
    write_outbox_value(&outbox, &valid);
    let mut routine = schema_2(
        escalation(
            &routine_id,
            "2026-09-03T11:00:00.000000000Z",
            "printf routine",
        ),
        "audit",
    );
    routine["loop_name"] = json!("alpha");
    routine["event"] = json!("verdict");
    routine["classification"] = json!("safe");
    routine["would_be_decision"] = json!("allow");
    write_outbox_value(&outbox, &routine);
    let malformed = outbox.join("a".repeat(64));
    fs::write(&malformed, b"{broken}\n").expect("malformed event");
    fs::set_permissions(&malformed, fs::Permissions::from_mode(0o644))
        .expect("malformed event mode");
    symlink(outbox.join(&valid_id), outbox.join("linked")).expect("symlinked event fixture");
    let review = load_outbox_review(&[("alpha".to_owned(), outbox)])
        .expect("malformed files are recoverable");
    assert_eq!(review.events().len(), 1);
    assert_eq!(review.events()[0].escalation().event_id(), valid_id);
    assert_eq!(review.malformed_files().len(), 2);
    assert!(
        review
            .malformed_files()
            .iter()
            .any(|path| path == &malformed)
    );
    assert!(
        review
            .render()
            .contains("Malformed outbox files skipped: 2")
    );
}

/// ´test:crate:outbox-review-reports-noncanonical-event-filename´
#[test]
fn outbox_review_reports_noncanonical_event_filename() {
    let fixture = OutboxFixture::new("noncanonical-id");
    let outbox = fixture.create_outbox("alpha");
    let mut value = schema_2(
        escalation("short-id", "2026-09-03T10:00:00.000000000Z", "printf short"),
        "audit",
    );
    value["loop_name"] = json!("alpha");
    write_outbox_value(&outbox, &value);
    let path = outbox.join("short-id");
    let review = load_outbox_review(&[("alpha".to_owned(), outbox)])
        .expect("noncanonical file is reportable");
    assert_eq!(review.events(), []);
    assert_eq!(review.malformed_files(), [path]);
}

/// ´test:crate:outbox-review-reports-absent-directory´
#[test]
fn outbox_review_reports_absent_directory() {
    let fixture = OutboxFixture::new("absent");
    let missing = fixture.outbox("alpha");
    let review = load_outbox_review(&[("alpha".to_owned(), missing.clone())])
        .expect("missing outbox is reportable");
    assert_eq!(review.events(), []);
    assert_eq!(
        review.absent_directories(),
        &[("alpha".to_owned(), missing)]
    );
    assert!(review.render().contains("Absent outboxes: 1"));
}

/// ´test:crate:review-skips-one-torn-trailing-record-with-a-warning´
#[test]
fn review_skips_one_torn_trailing_record_with_a_warning() {
    let first = escalation("one", "2026-09-03T10:00:00.000000000Z", "printf one");
    let mut bytes = stream(&[first]);
    bytes.extend_from_slice(b"{\"schema\":1");
    let review = review_from_bytes(&bytes).expect("torn tail is recoverable");
    assert_eq!(review.warning_count(), 1);
    assert_eq!(review.blank_lines(), 0);
    assert_eq!(review.malformed_lines(), 0);
    assert_eq!(review.escalations().len(), 1);
    assert!(review.render().contains("Torn trailing records skipped: 1"));
    assert!(
        review
            .render()
            .contains("scope=legacy-unscoped mode=legacy")
    );
    assert!(
        review
            .render()
            .contains("Malformed complete lines skipped: 0")
    );
}

/// ´test:crate:review-retains-schema-one-as-legacy-and-reads-schema-two-verdict-streams´
#[test]
fn review_retains_schema_one_as_legacy_and_reads_schema_two_verdict_streams() {
    let legacy = escalation("legacy", "2026-09-03T09:00:00.000000000Z", "printf legacy");
    let current = schema_2(
        escalation(
            "current",
            "2026-09-03T10:00:00.000000000Z",
            "printf current",
        ),
        "audit",
    );
    let mut routine = schema_2(
        escalation(
            "routine",
            "2026-09-03T11:00:00.000000000Z",
            "printf routine",
        ),
        "audit",
    );
    routine["event"] = json!("verdict");
    routine["classification"] = json!("safe");
    routine["would_be_decision"] = json!("allow");
    let marked = disposition(&current, "adjudicated-rejected");

    let review = review_from_bytes(&stream(&[legacy, current, routine, marked]))
        .expect("mixed history remains reviewable");
    assert_eq!(review.malformed_lines(), 0);
    assert_eq!(review.escalations().len(), 2);
    assert_eq!(review.escalations()[0].scope(), None);
    assert_eq!(review.escalations()[0].mode(), None);
    assert_eq!(review.escalations()[1].scope(), Some("estate"));
    assert_eq!(review.escalations()[1].mode(), Some("audit"));
    assert_eq!(
        review.escalations()[1].outcome(),
        Some("adjudicated-rejected")
    );
    let rendered = review.render();
    assert!(rendered.contains("scope=legacy-unscoped mode=legacy"));
}

/// ´test:crate:review-counts-blank-separator-lines-separately´
#[test]
fn review_counts_blank_separator_lines_separately() {
    let value = escalation(
        "blank-lines",
        "2026-09-03T10:00:00.000000000Z",
        "printf blank",
    );
    let mut bytes = stream(&[value]);
    bytes.extend_from_slice(b"\n\n");
    let review = review_from_bytes(&bytes).expect("blank separators are recoverable");
    assert_eq!(review.warning_count(), 0);
    assert_eq!(review.blank_lines(), 2);
    assert_eq!(review.malformed_lines(), 0);
    assert_eq!(review.escalations().len(), 1);
    assert!(review.render().contains("Blank separator lines skipped: 2"));
}

/// ´test:crate:review-correlates-every-outcome-and-lists-unadjudicated-oldest-first´
#[test]
fn review_correlates_every_outcome_and_lists_unadjudicated_oldest_first() {
    let rejected = escalation(
        "rejected",
        "2026-09-03T10:00:00.000000000Z",
        "ssh   worker-alias   status",
    );
    let open_old = escalation(
        "open-old",
        "2026-09-03T09:00:00.000000000Z",
        "printf oldest",
    );
    let open_new = escalation(
        "open-new",
        "2026-09-03T11:00:00.000000000Z",
        "ssh worker-alias status",
    );
    let rule = escalation("rule", "2026-09-03T08:00:00.000000000Z", "printf rule");
    let corrected = escalation(
        "corrected",
        "2026-09-03T12:00:00.000000000Z",
        "printf corrected",
    );
    let values = vec![
        rejected.clone(),
        open_new,
        disposition(&rejected, "adjudicated-rejected"),
        corrected.clone(),
        rule.clone(),
        open_old,
        disposition(&rule, "adjudicated-rule-added"),
        disposition(&corrected, "corrected-and-rerun"),
    ];
    let review = review_from_bytes(&stream(&values)).expect("event stream reconstructs");
    assert_eq!(
        review
            .unadjudicated()
            .map(ReviewEscalation::event_id)
            .collect::<Vec<_>>(),
        ["open-old", "open-new"]
    );
    let grouped = review
        .groups()
        .iter()
        .find(|group| group.command() == "ssh worker-alias status")
        .expect("whitespace-normalized group exists");
    assert_eq!(grouped.occurrence_count(), 2);
    assert_eq!(grouped.outcomes(), ["adjudicated-rejected", "escalated"]);
    assert!(review.groups().iter().any(|group| {
        group
            .outcomes()
            .iter()
            .any(|outcome| outcome == "adjudicated-rule-added")
    }));
    assert!(review.groups().iter().any(|group| {
        group
            .outcomes()
            .iter()
            .any(|outcome| outcome == "corrected-and-rerun")
    }));
}

/// ´test:crate:review-groups-identical-actions-separately-by-role-and-loop´
#[test]
fn review_groups_identical_actions_separately_by_role_and_loop() {
    let one = escalation(
        "group-one",
        "2026-09-03T10:00:00.000000000Z",
        "printf grouped",
    );
    let mut two = escalation(
        "group-two",
        "2026-09-03T11:00:00.000000000Z",
        "printf grouped",
    );
    two["role"] = json!("orchestrator-subagent");
    let mut three = escalation(
        "group-three",
        "2026-09-03T12:00:00.000000000Z",
        "printf grouped",
    );
    three["loop_name"] = json!("sibling");
    let review = review_from_bytes(&stream(&[one, two, three])).expect("groups reconstruct");
    assert_eq!(review.groups().len(), 3);
    assert!(review.groups().iter().any(|group| {
        group.role() == "orchestrator" && group.loop_name() == Some("orchestration")
    }));
    assert!(review.groups().iter().any(|group| {
        group.role() == "orchestrator-subagent" && group.loop_name() == Some("orchestration")
    }));
    assert!(
        review.groups().iter().any(|group| {
            group.role() == "orchestrator" && group.loop_name() == Some("sibling")
        })
    );
}

/// ´test:crate:review-renders-fixed-warning-and-owner-placeholder-row´
#[test]
fn review_renders_fixed_warning_and_owner_placeholder_row() {
    let value = escalation(
        "candidate",
        "2026-09-03T10:00:00.000000000Z",
        "timeout 20 ssh worker 'status | tail -1'",
    );
    let review = review_from_bytes(&stream(&[value])).expect("review reconstructs");
    let rendered = review.render();
    assert!(rendered.starts_with(COMMAND_CREDENTIAL_WARNING));
    assert!(
        rendered.contains("|Rule|Class|Role|"),
        "candidate row header must include the caller role column"
    );
    assert!(rendered.contains("role=orchestrator"));
    assert!(rendered.contains("loop=\"orchestration\""));
    for placeholder in [
        "<rule-id>",
        "<alias>",
        "<account>",
        "<path>",
        "<allowed-operands>",
        "<deadline>",
        "<timing>",
        "<forbidden-expansions>",
    ] {
        assert!(rendered.contains(placeholder));
    }
    assert!(rendered.contains("status \\| tail -1"));
}

/// ´test:crate:review-markdown-cell-escapes-backslash-before-pipe´
#[test]
fn review_markdown_cell_escapes_backslash_before_pipe() {
    let value = escalation(
        "backslash-pipe",
        "2026-09-03T10:00:00.000000000Z",
        r"printf status \| tail -1",
    );
    let review = review_from_bytes(&stream(&[value])).expect("review reconstructs");
    let row = review
        .groups()
        .first()
        .expect("request group exists")
        .candidate_row();
    assert!(row.contains(r"status \\\| tail -1"), "row: {row}");
}

/// ´test:crate:review-rejects-orphan-and-duplicate-events-and-skips-malformed-lines´
#[test]
fn review_rejects_orphan_and_duplicate_events_and_skips_malformed_lines() {
    for stamp in [
        "2026-09-03T12:00:00.000000000",
        "2026-09-03T14:00:00.000000000+02:00",
        "2026-02-29T12:00:00.000000000Z",
        "2026-09-03T12:00:00Z",
    ] {
        let event = escalation(&"a".repeat(64), stamp, "printf invalid");
        let review = review_from_bytes(&stream(&[event])).expect("malformed record counted");
        assert_eq!(review.malformed_lines(), 1, "{stamp}");
        assert!(review.escalations().is_empty(), "{stamp}");
        let source = escalation(
            &"a".repeat(64),
            "2026-09-03T10:00:00.000000000Z",
            "printf valid",
        );
        let mut marked = disposition(&source, "adjudicated-rejected");
        marked["recorded_at"] = json!(stamp);
        let review = review_from_bytes(&stream(&[source, marked])).expect("invalid mark skipped");
        assert_eq!(review.malformed_lines(), 1, "{stamp}");
        assert_eq!(review.escalations().len(), 1);
        assert_eq!(review.escalations()[0].outcome(), None);
    }
    let value = escalation("duplicate", "2026-09-03T10:00:00.000000000Z", "x");
    let middle = escalation("distinct", "2026-09-03T11:00:00.000000000Z", "y");
    let mut separated_duplicate = value.clone();
    separated_duplicate["recorded_at"] = json!("2026-09-03T12:00:00.000000000Z");
    assert!(matches!(
        review_from_bytes(&stream(&[value.clone(), middle, separated_duplicate])),
        Err(ReviewError::DuplicateEscalation)
    ));
    assert!(matches!(
        review_from_bytes(&stream(&[disposition(&value, "adjudicated-rejected")])),
        Err(ReviewError::OrphanDisposition)
    ));
    let valid = escalation("valid", "2026-09-03T13:00:00.000000000Z", "z");
    let mut malformed = stream(&[valid]);
    malformed.extend_from_slice(b"{not-json}\n{}\n");
    let review = review_from_bytes(&malformed).expect("malformed lines are warnings");
    assert_eq!(review.malformed_lines(), 2);
    assert_eq!(review.escalations().len(), 1);
    assert!(
        review
            .render()
            .contains("Malformed complete lines skipped: 2")
    );
}

/// ´test:crate:scope-review-separates-identical-shapes-by-scope-loop-and-role´
#[test]
fn scope_review_separates_identical_shapes_by_scope_loop_and_role() {
    let mut values = Vec::new();
    for (id, scope, role, loop_name) in [
        ("one", "loop", "orchestrator", "one"),
        ("two", "estate", "orchestrator", "one"),
        ("three", "loop", "orchestrator-subagent", "one"),
        ("four", "loop", "orchestrator", "two"),
    ] {
        let mut event = schema_2(
            escalation(id, "2026-09-03T10:00:00.000000000Z", "printf identical"),
            "enforce",
        );
        event["scope"] = json!(scope);
        event["role"] = json!(role);
        event["loop_name"] = json!(loop_name);
        values.push(event);
    }
    let review = review_from_bytes(&stream(&values)).expect("scoped stream is valid");
    assert_eq!(review.malformed_lines(), 0);
    assert_eq!(review.groups().len(), 4);
    assert!(review.render().contains("scope=loop"));
}
