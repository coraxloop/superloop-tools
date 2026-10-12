use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::plan::Plan;

use super::{MAX_LAUNCH_REPORT_BYTES, finish, finish_with_fallback, name, read_bound, round_dir};

fn first() -> Value {
    json!({"schema":1,"command":"launch","dry_run":false,"observe":false,"enforcing":true,"observed":null,"home":"/home/run","driver_dir":"/runs/R","round_dir":"/runs/R/first-dispatch","preparation":"ready","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"RUN-REPORT lane=dispatch","settlement":{},"evidence":"driver directory outside home","wall_seconds":1.5})
}

fn resumed() -> Value {
    json!({"schema":1,"command":"launch","dry_run":false,"round":"review","round_dir":"/runs/R/first-dispatch","budget_seconds":3600,"letter":"review.md","letter_reconciliation":[],"thread_id":"thread","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"RUN-REPORT lane=review","settlement":{},"wall_seconds":2.5})
}

/// # Panics
/// Panics only if the strict reader accepts absent or malformed publication evidence.
/// ´test:unit:launch-report-requires-measured-credential-publication´
#[test]
fn launch_report_requires_measured_credential_publication() {
    let (fixture, runs) = held();
    for (step, original) in [(None, first()), (Some("review"), resumed())] {
        let mut old = original.clone();
        old.as_object_mut()
            .expect("report")
            .remove("credential_publication");
        replace(&fixture, step, old.to_string().as_bytes());
        let error =
            read_bound(&runs, "R", step, Uid::effective().as_raw()).expect_err("old report");
        assert_eq!(error.kind, "read-launch-report");
        assert!(error.detail.contains("credential_publication is absent"));
        assert!(
            error
                .detail
                .contains("rewrite-launch-reports LOOP --dry-run")
        );
        for evidence in [
            json!(null),
            json!({"source_inode":42}),
            json!({"source_inode":0,"published_unix_ns":100}),
            json!({"source_inode":42,"published_unix_ns":"100"}),
            json!({"source_inode":42,"published_unix_ns":100,"extra":true}),
        ] {
            let mut invalid = original.clone();
            invalid["credential_publication"] = evidence;
            replace(&fixture, step, invalid.to_string().as_bytes());
            assert_eq!(
                read_bound(&runs, "R", step, Uid::effective().as_raw())
                    .expect_err("malformed publication")
                    .kind,
                "read-launch-report"
            );
        }
    }
}

fn held() -> (tempfile::TempDir, OwnedFd) {
    let fixture = tempfile::tempdir().expect("runs root");
    let runs = File::open(fixture.path()).expect("held runs root").into();
    (fixture, runs)
}

/// # Panics
/// Panics only if the explicit conversion invents measurements or admits a malformed marker.
/// ´test:unit:launch-report-rewrite-keeps-unmeasured-evidence-distinct´
#[test]
fn launch_report_rewrite_keeps_unmeasured_evidence_distinct() {
    let (fixture, runs) = held();
    for (step, mut old) in [(None, first()), (Some("review"), resumed())] {
        old.as_object_mut()
            .expect("report object")
            .remove("credential_publication");
        let after = super::converted_report(&old, step)
            .expect("known predecessor")
            .expect("conversion");
        replace(&fixture, step, after.to_string().as_bytes());
        assert_eq!(
            read_bound(&runs, "R", step, Uid::effective().as_raw())
                .expect("strict rewritten reader"),
            after
        );
        assert!(
            super::converted_report(&after, step)
                .expect("repeat conversion")
                .is_none()
        );
        let record = json!({"rounds":[{"credential_publication":after["credential_publication"]}]});
        assert!(super::credential_publication(&record).is_err());
        let mut invalid = after;
        invalid["credential_publication"]["reason"] = json!("unknown");
        assert!(super::converted_report(&invalid, step).is_err());
        invalid["credential_publication"] = json!({"state":"unmeasured","reason":"written before publication evidence existed","source_inode":42,"published_unix_ns":null});
        assert!(super::converted_report(&invalid, step).is_err());
    }
}

fn replace(fixture: &tempfile::TempDir, step: Option<&str>, bytes: &[u8]) {
    let path = fixture.path().join(name("R", step).expect("report name"));
    fs::write(&path, bytes).expect("replace report");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private report mode");
}

/// ´test:unit:launch-report-is-durable-before-return-and-rounds-retain-their-own-bytes´
#[test]
fn launch_report_is_durable_before_return_and_rounds_retain_their_own_bytes() {
    let (fixture, runs) = held();
    let first = first();
    let returned = finish(&runs, "R", None, first.clone()).expect("first return");
    let first_path = fixture.path().join(name("R", None).expect("first name"));
    assert_eq!(
        fs::read(&first_path).expect("first persisted before return"),
        returned.to_string().as_bytes()
    );
    assert_eq!(
        read_bound(&runs, "R", None, Uid::effective().as_raw()).expect("first reader"),
        returned
    );
    let returned_round = finish(&runs, "R", Some("review"), resumed()).expect("round return");
    let round_path = fixture
        .path()
        .join(name("R", Some("review")).expect("round name"));
    assert_eq!(
        fs::read(&round_path).expect("round persisted before return"),
        returned_round.to_string().as_bytes()
    );
    assert_eq!(
        fs::read(&first_path).expect("first retained"),
        first.to_string().as_bytes()
    );
    assert_eq!(
        read_bound(&runs, "R", Some("review"), Uid::effective().as_raw()).expect("round reader"),
        returned_round
    );
}

/// ´test:unit:launch-report-round-directory-matches-recorded-rows-after-readback´
#[test]
fn launch_report_round_directory_matches_recorded_rows_after_readback() {
    let (_fixture, runs) = held();
    let plan = Plan {
        home: "/home/run".into(),
        driver_dir: "/runs/R".into(),
        letter: PathBuf::default(),
        document: json!({}),
    };
    let record = json!({"rounds":[
        {"step":"dispatch","phase":"settled","driver_dir":"/runs/R/first-dispatch"},
        {"step":"review","phase":"settled","driver_dir":"/runs/R/later-review"}
    ]});
    assert_ne!(
        record["rounds"][0]["driver_dir"],
        record["rounds"][1]["driver_dir"]
    );
    let mut first_report = first();
    first_report["round_dir"] =
        json!(round_dir(&plan, &record, Some("dispatch")).expect("first directory"));
    let mut resumed_report = resumed();
    resumed_report["round_dir"] =
        json!(round_dir(&plan, &record, Some("review")).expect("resumed directory"));
    finish(&runs, "R", None, first_report).expect("first report");
    finish(&runs, "R", Some("review"), resumed_report).expect("resumed report");
    let owner = Uid::effective().as_raw();
    for (step, index) in [(None, 0), (Some("review"), 1)] {
        let readback = read_bound(&runs, "R", step, owner).expect("strict readback");
        assert_eq!(readback["round_dir"], record["rounds"][index]["driver_dir"]);
        if step.is_none() {
            assert_eq!(readback["driver_dir"], "/runs/R");
        }
    }
}

/// ´test:unit:launch-report-reader-refuses-unknown-missing-and-wrong-round-keys´
#[test]
fn launch_report_reader_refuses_unknown_missing_and_wrong_round_keys() {
    let (fixture, runs) = held();
    let owner = Uid::effective().as_raw();
    let mut first_report = first();
    first_report["surprise"] = json!(true);
    replace(&fixture, None, first_report.to_string().as_bytes());
    let error = read_bound(&runs, "R", None, owner).expect_err("extra key refused");
    assert_eq!(error.kind, "read-launch-report");
    assert!(error.line().contains(".report=R.json"));
    first_report
        .as_object_mut()
        .expect("object")
        .remove("surprise");
    first_report
        .as_object_mut()
        .expect("object")
        .remove("settlement");
    replace(&fixture, None, first_report.to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", None, owner)
            .expect_err("missing key refused")
            .kind,
        "read-launch-report"
    );
    let mut missing_round_dir = first();
    missing_round_dir
        .as_object_mut()
        .expect("object")
        .remove("round_dir");
    replace(&fixture, None, missing_round_dir.to_string().as_bytes());
    let error = read_bound(&runs, "R", None, owner).expect_err("missing round_dir refused");
    assert_eq!(error.kind, "read-launch-report");
    assert!(error.detail.contains("round_dir is absent"));
    let mut round = resumed();
    round["round"] = json!("other");
    replace(&fixture, Some("review"), round.to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", Some("review"), owner)
            .expect_err("wrong step refused")
            .kind,
        "read-launch-report"
    );
    replace(&fixture, Some("review"), first().to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", Some("review"), owner)
            .expect_err("first shape refused for round")
            .kind,
        "read-launch-report"
    );
}

/// ´test:unit:launch-report-reader-refuses-oversize-garble-and-missing-file-by-name´
#[test]
fn launch_report_reader_refuses_oversize_garble_and_missing_file_by_name() {
    let (fixture, runs) = held();
    let owner = Uid::effective().as_raw();
    let missing = read_bound(&runs, "R", None, owner).expect_err("missing report refused");
    assert!(missing.line().contains(".report=R.json"));
    replace(&fixture, None, b"{garbled");
    let garbled = read_bound(&runs, "R", None, owner).expect_err("garbled report refused");
    assert!(garbled.line().contains(".report=R.json"));
    replace(
        &fixture,
        None,
        &vec![b'x'; usize::try_from(MAX_LAUNCH_REPORT_BYTES + 1).expect("bound fits usize")],
    );
    let oversized = read_bound(&runs, "R", None, owner).expect_err("oversized report refused");
    assert!(oversized.line().contains(".report=R.json"));
}

/// ´test:unit:launch-report-names-distinguish-hyphenated-run-from-resumed-step´
#[test]
fn launch_report_names_distinguish_hyphenated_run_from_resumed_step() {
    let (_fixture, runs) = held();
    let round = resumed();
    let launch = first();
    finish(&runs, "R", Some("review"), round.clone()).expect("resumed report");
    finish(&runs, "R-review", None, launch.clone()).expect("other launch report");
    let owner = Uid::effective().as_raw();
    assert_eq!(
        read_bound(&runs, "R", Some("review"), owner).expect("resumed readback"),
        round
    );
    assert_eq!(
        read_bound(&runs, "R-review", None, owner).expect("launch readback"),
        launch
    );
    assert_ne!(
        name("R", Some("review")).expect("round name"),
        name("R-review", None).expect("launch name")
    );
    assert_ne!(
        name("report-R.json", None).expect("identity collision name"),
        ".launch-report-R.json"
    );
}

/// ´test:unit:launch-report-reader-refuses-wrong-owner-mode-and-link-count´
#[test]
fn launch_report_reader_refuses_wrong_owner_mode_and_link_count() {
    let (fixture, runs) = held();
    let owner = Uid::effective().as_raw();
    let path = fixture.path().join(name("R", None).expect("report name"));
    finish(&runs, "R", None, first()).expect("report file");
    assert_eq!(
        read_bound(&runs, "R", None, owner + 1)
            .expect_err("wrong owner")
            .kind,
        "read-launch-report"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("public mode");
    assert_eq!(
        read_bound(&runs, "R", None, owner)
            .expect_err("public mode")
            .kind,
        "read-launch-report"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    fs::hard_link(&path, fixture.path().join("other-link")).expect("second link");
    assert_eq!(
        read_bound(&runs, "R", None, owner)
            .expect_err("hard link")
            .kind,
        "read-launch-report"
    );
}

/// ´test:unit:interrupted-settlement-report-has-its-own-strict-shape´
#[test]
fn interrupted_settlement_report_has_its_own_strict_shape() {
    let (fixture, runs) = held();
    let launch_recovery = json!({"state":"completed-interrupted-settlement","phase":"settled","ended_by":"by-report","attempt_evidence":{"state":"complete","attempts":[{"attempt":1,"status":0,"removal":"removed","error_free":true,"capacity_evidence":false}],"container_absence_checked":false},"observer_socket":{"state":"not-applicable"}});
    let report = json!({"schema":1,"command":"launch","dry_run":false,"interrupted_settlement":launch_recovery,"home":"/home/run","driver_dir":"/runs/R","round_dir":"/runs/R/first-dispatch","wall_seconds":1.0});
    finish(&runs, "R", None, report.clone()).expect("recovery report");
    let owner = Uid::effective().as_raw();
    assert_eq!(
        read_bound(&runs, "R", None, owner).expect("recovery readback"),
        report
    );
    let mut failed_launch = report.clone();
    failed_launch["interrupted_settlement"]["phase"] = json!("failed");
    failed_launch["interrupted_settlement"]["ended_by"] = Value::Null;
    failed_launch["interrupted_settlement"]["attempt_evidence"]["state"] =
        json!("absence-confirmed-with-missing-evidence");
    failed_launch["interrupted_settlement"]["attempt_evidence"]["attempts"] = json!([]);
    failed_launch["interrupted_settlement"]["attempt_evidence"]["container_absence_checked"] =
        json!(true);
    replace(&fixture, None, failed_launch.to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", None, owner).expect("failed launch recovery readback"),
        failed_launch
    );
    let mut extra = report.clone();
    extra["extra"] = json!(true);
    replace(&fixture, None, extra.to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", None, owner)
            .expect_err("unknown key")
            .kind,
        "read-launch-report"
    );
    let settle_recovery = json!({"state":"completed-settle-round","preview_sha256":"a".repeat(64),"phase":"complete","detail":null});
    let resumed_recovery = json!({"schema":1,"command":"launch","dry_run":false,"interrupted_settlement":settle_recovery,"home":"/home/run","driver_dir":"/runs/R","round_dir":"/runs/R/first-dispatch","wall_seconds":2.0});
    finish(&runs, "R", Some("review"), resumed_recovery.clone()).expect("resumed recovery report");
    assert_eq!(
        read_bound(&runs, "R", Some("review"), owner).expect("resumed recovery readback"),
        resumed_recovery
    );
    let mut extra = resumed_recovery.clone();
    extra["round"] = json!("review");
    replace(&fixture, Some("review"), extra.to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", Some("review"), owner)
            .expect_err("extra resumed recovery key")
            .kind,
        "read-launch-report"
    );
    let mut false_launch = report;
    false_launch["interrupted_settlement"]["attempt_evidence"] =
        json!({"preview_sha256":"a".repeat(64),"phase":"complete","detail":null});
    replace(&fixture, None, false_launch.to_string().as_bytes());
    assert_eq!(
        read_bound(&runs, "R", None, owner)
            .expect_err("settle journal cannot pass as launch attempt evidence")
            .kind,
        "read-launch-report"
    );
    let mut false_settle = resumed_recovery;
    false_settle["interrupted_settlement"]["attempt_evidence"] =
        json!({"state":"complete","attempts":[],"container_absence_checked":false});
    replace(
        &fixture,
        Some("review"),
        false_settle.to_string().as_bytes(),
    );
    assert_eq!(
        read_bound(&runs, "R", Some("review"), owner)
            .expect_err("launch attempt evidence cannot pass as settle journal")
            .kind,
        "read-launch-report"
    );
}

/// ´test:unit:occupied-valid-report-refuses-replacement-and-delivers-unsaved-value´
#[test]
fn occupied_valid_report_refuses_replacement_and_delivers_unsaved_value() {
    let (fixture, runs) = held();
    let first = first();
    finish(&runs, "R", None, first.clone()).expect("first publication");
    let path = fixture.path().join(name("R", None).expect("first name"));
    let bytes = fs::read(&path).expect("first bytes");
    let mut later = first.clone();
    later["driver_report"] = json!("later report");
    let mut delivered = None;
    let error = finish_with_fallback(&runs, "R", None, later.clone(), &mut |report| {
        delivered = Some(report.clone());
    })
    .expect_err("occupied report refuses publication");
    assert_eq!(error.kind, "launch-report");
    assert!(error.line().contains(".report=R.json"));
    assert_eq!(delivered, Some(later));
    assert_eq!(fs::read(path).expect("first bytes retained"), bytes);
    assert_eq!(
        read_bound(&runs, "R", None, Uid::effective().as_raw()).expect("first readback"),
        first
    );
}

/// ´test:unit:publication-refusal-delivers-unsaved-report-before-returning-refusal´
#[test]
fn publication_refusal_delivers_unsaved_report_before_returning_refusal() {
    let (fixture, runs) = held();
    replace(&fixture, None, b"{garbled");
    let report = first();
    let mut delivered = None;
    let error = finish_with_fallback(&runs, "R", None, report.clone(), &mut |value| {
        delivered = Some(value.clone());
    })
    .expect_err("occupied report refuses publication");
    assert_eq!(error.kind, "launch-report");
    assert_eq!(delivered, Some(report));
}

/// ´test:unit:failed-report-archive-refuses-a-replaced-inode-with-equal-bytes´
#[test]
fn failed_report_archive_refuses_a_replaced_inode_with_equal_bytes() {
    let (fixture, runs) = held();
    finish(&runs, "R", None, first()).expect("report");
    let (held, preview, bytes) = super::archive_source(&runs, "R", None).expect("archive source");
    let source = fixture.path().join(name("R", None).expect("name"));
    fs::remove_file(&source).expect("remove name");
    replace(&fixture, None, &bytes);
    let error = super::rename_archive(&runs, &held, &preview).expect_err("replacement");
    assert_eq!(error.kind, "launch-report");
    assert_eq!(error.detail, "failed recovery report identity changed");
    assert_eq!(fs::read(source).expect("replacement retained"), bytes);
    assert!(
        !fixture
            .path()
            .join(preview["target"].as_str().expect("target"))
            .exists()
    );
}
