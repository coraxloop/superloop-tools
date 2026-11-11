//! Refusal-only tests for the fixture admission; no round or periodic pass is run.
use crate::runtime_admission::{
    RuntimeAdmission,
    fixture::{self, Declaration, FixtureRoot},
};
use crate::settings::BoxBackend;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Fixture {
    root: Arc<FixtureRoot>,
    live: tempfile::TempDir,
    pub(crate) owner: PathBuf,
    pub(crate) runs: PathBuf,
    worker: PathBuf,
    digest: String,
    _home: crate::home::PrivateHomeGuard,
    _programs: crate::container_entry::ExecutableGuard,
    _configuration: crate::runtime_entry::ConfigurationGuard,
}
fn directory(path: &Path) {
    fs::create_dir_all(path).expect("fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("fixture mode");
}
fn settings(owner: &Path, runs: &Path) {
    let text = format!(
        concat!(
            "runs_root = {runs:?}\nentry_bin = \"/usr/bin/true\"\n",
            "driver_argv = [\"/usr/bin/true\"]\n",
            "backend_argv = {{ claude = [\"/fixture/claude\"] }}\n",
            "image_digest = \"sha256:{}\"\ntemplate_dir = {:?}\nsocket_dir = {:?}\n",
            "resources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n"
        ),
        "a".repeat(64),
        owner.join("template"),
        owner.join("sockets"),
        runs = runs
    );
    let path = owner.join(".config/loops/alpha/workers.toml");
    fs::write(&path, text).expect("synthetic settings");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("settings mode");
}
impl Fixture {
    pub(crate) fn new() -> Self {
        use std::fmt::Write as _;
        let live = tempfile::tempdir().expect("modeled configured runs");
        let root = FixtureRoot::create(live.path()).expect("created root");
        let owner = root.path().join("owner");
        let runs = root.path().join("runs");
        let worker = owner.join(".cache/tmp/lane-alpha-R");
        for path in [
            &owner,
            &runs,
            &owner.join(".cache"),
            &owner.join(".cache/tmp"),
            &worker,
        ] {
            directory(path);
        }
        let configuration = crate::runtime_entry::fixture_configuration(&owner);
        settings(&owner, &runs);
        let bundle = crate::container_entry::fixture_claude_helper_bundle(&owner, &runs);
        let (sender, input) = std::os::unix::net::UnixStream::pair().expect("rights pair");
        loop_home::anchor::transport::send(&sender, &bundle.descriptors).expect("rights");
        let (_, mut anchors) = crate::container_entry::receive_for(
            &bundle.manifest,
            &input,
            "container-helper",
            Some("alpha"),
        )
        .expect("production receiver");
        let _configuration_role = anchors.pop().expect("configuration");
        let (_runtime, programs) =
            crate::container_entry::take_support_programs(&mut anchors, BoxBackend::Claude)
                .expect("Claude program roles");
        let home = crate::home::activate_private_launch(
            &owner,
            &anchors[0],
            &runs,
            &anchors[1],
            None,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("held roots");
        let programs = crate::container_entry::activate_program_map("container-helper", programs);
        let mut digest = String::new();
        for byte in Sha256::digest(fs::read("/usr/bin/true").expect("public stand-in")) {
            write!(&mut digest, "{byte:02x}").expect("digest");
        }
        Self {
            root,
            live,
            owner,
            runs,
            worker,
            digest,
            _home: home,
            _programs: programs,
            _configuration: configuration,
        }
    }
    fn declaration(&self) -> Declaration {
        Declaration {
            owner_home: self.owner.clone(),
            runs: self.runs.clone(),
            plan_home: self.worker.clone(),
            loop_name: "alpha".into(),
            run: "R".into(),
            worker_uid: 3000,
            backend: BoxBackend::Claude,
            stand_in: "/usr/bin/true".into(),
            digest: self.digest.clone(),
        }
    }
    pub(crate) fn admission(&self) -> RuntimeAdmission {
        fixture::construct(Arc::clone(&self.root), self.declaration()).expect("scoped constructor")
    }
    pub(crate) fn plan(&self) -> Value {
        json!({"loop":"alpha", "run":"R", "home":self.worker, "worker_uid":3000,
            "backend":"claude", "driver_dir":self.runs.join("R")})
    }
}
fn refused(error: crate::error::LaneError, field: &str) {
    assert_eq!(error.status, 2);
    assert_eq!(error.kind, "fixture-scope");
    assert_eq!(
        error.detail,
        format!("{}: refuses {field}", fixture::SENTINEL)
    );
    drop(error);
}

/// ´test:crate:fixture-admission-constructor-never-unlocks-live-authority´
#[test]
fn fixture_admission_constructor_never_unlocks_live_authority() {
    let f = Fixture::new();
    let account = crate::caller_home().expect("account home");
    for (target, path, reason) in [
        ("home", PathBuf::from("/outside-fixture"), "outside root"),
        ("runs", PathBuf::from("/outside-fixture"), "outside root"),
        ("home", account.clone(), "account home"),
        ("runs", account, "account home"),
        ("home", f.live.path().into(), "configured live runs"),
        ("runs", f.live.path().into(), "configured live runs"),
    ] {
        let mut d = f.declaration();
        if target == "home" {
            d.owner_home = path;
        } else {
            d.runs = path;
        }
        refused(
            fixture::construct(Arc::clone(&f.root), d)
                .err()
                .expect("refusal"),
            reason,
        );
    }
    let mut d = f.declaration();
    d.backend = BoxBackend::Codex;
    refused(
        fixture::construct(Arc::clone(&f.root), d)
            .err()
            .expect("Codex"),
        "Codex backend",
    );
    let mut d = f.declaration();
    d.digest = crate::credential::CLAUDE_SCHEMA_PROGRAM_SHA256.into();
    refused(
        fixture::construct(Arc::clone(&f.root), d)
            .err()
            .expect("schema"),
        "reviewed vendor digest",
    );
    for program in [
        "/usr/bin/false",
        "/usr/bin/claude",
        "/fixture/owned-program",
    ] {
        let mut d = f.declaration();
        d.stand_in = program.into();
        refused(
            fixture::construct(Arc::clone(&f.root), d)
                .err()
                .expect("program"),
            "stand-in name",
        );
    }
    let mut d = f.declaration();
    d.digest = "0".repeat(64);
    assert_eq!(
        fixture::construct(Arc::clone(&f.root), d)
            .err()
            .expect("digest")
            .kind,
        "credential-program-pin"
    );
    assert_eq!(f.admission().program_binding().required_sha256(), f.digest);
    assert_eq!(
        RuntimeAdmission::Gate
            .check(BoxBackend::Claude)
            .expect_err("gate")
            .kind,
        "backend-unavailable"
    );
}

/// ´test:crate:fixture-admission-scope-refuses-foreign-consumers´
#[test]
fn fixture_admission_scope_refuses_foreign_consumers() {
    let f = Fixture::new();
    let admission = f.admission();
    admission
        .scope_plan(&f.plan())
        .expect("scope-only positive control");
    for (key, value, reason) in [
        ("loop", json!("beta"), "loop"),
        ("run", json!("S"), "run"),
        ("home", json!("/outside"), "plan home"),
        ("worker_uid", json!(3001), "worker uid"),
        ("driver_dir", json!("/outside/R"), "driver directory"),
    ] {
        let mut plan = f.plan();
        plan[key] = value;
        refused(
            crate::plan::verify_box_attestation_admitted(&plan, &admission)
                .expect_err("before attestation"),
            reason,
        );
    }
    let mut plan = f.plan();
    plan["backend"] = json!("codex");
    refused(
        crate::plan::verify_box_attestation_admitted(&plan, &admission).expect_err("backend"),
        "backend",
    );
    refused(
        crate::credential::publish_round_admitted(
            &f.owner,
            "alpha",
            &f.worker,
            3001,
            BoxBackend::Claude,
            &admission,
        )
        .expect_err("before pin"),
        "worker uid",
    );
    let mut cache = std::collections::BTreeMap::new();
    refused(
        crate::credential::refresh_live_admitted(
            &f.owner,
            "alpha",
            Path::new("/outside"),
            &mut cache,
            BoxBackend::Claude,
            "unused",
            &admission,
        )
        .expect_err("before periodic pin"),
        "runs root",
    );
    let mut record = json!({"plan":f.plan()});
    record["plan"]["worker_uid"] = json!(3001);
    let before = record.clone();
    refused(
        crate::container_helper::publish_round_credential_admitted(
            &f.owner,
            "alpha",
            &mut record,
            &admission,
        )
        .expect_err("helper round scope"),
        "worker uid",
    );
    assert_eq!(record, before);
    record["plan"] = f.plan();
    record["worker_uid"] = json!(3001);
    refused(
        crate::container_helper::publish_round_credential_admitted(
            &f.owner,
            "alpha",
            &mut record,
            &admission,
        )
        .expect_err("record uid scope"),
        "worker uid",
    );
    assert!(cache.is_empty());
    refused(
        admission
            .scope_periodic(&f.owner, "alpha", &f.runs)
            .expect_err("run authority"),
        "run proof at periodic",
    );
    refused(
        admission
            .scope_recipient(&f.owner)
            .expect_err("owner recipient"),
        "recipient",
    );
    assert!(!f.worker.join(".claude").exists());
}

/// ´test:crate:fixture-admission-thread-part-is-one-shot-and-periodic-only´
#[test]
fn fixture_admission_thread_part_is_one_shot_and_periodic_only() {
    let f = Fixture::new();
    let admission = f.admission();
    let custody = crate::container_helper::CredentialThreadCustody::capture_admitted(
        BoxBackend::Claude,
        &admission,
    )
    .expect("one capture");
    refused(
        crate::container_helper::CredentialThreadCustody::capture_admitted(
            BoxBackend::Claude,
            &admission,
        )
        .err()
        .expect("second capture"),
        "thread already transferred",
    );
    std::thread::spawn(move || {
        let guard = custody.activate().expect("rechecked activation");
        refused(
            guard
                .fixture_admission()
                .scope_plan(&json!({"backend":"claude"}))
                .expect_err("periodic proof cannot admit a run"),
            "periodic proof at run",
        );
    })
    .join()
    .expect("joined authority-only thread");
    admission
        .scope_plan(&f.plan())
        .expect("run authority retained");
    assert_eq!(
        RuntimeAdmission::Gate
            .check(BoxBackend::Claude)
            .expect_err("public gate")
            .kind,
        "backend-unavailable"
    );
}

/// ´test:crate:fixture-admission-rechecks-anchor-and-root-identity´
#[test]
fn fixture_admission_rechecks_anchor_and_root_identity() {
    let f = Fixture::new();
    let admission = f.admission();
    let old = f.owner.join("old-configuration");
    fs::rename(f.owner.join(".config/loops"), &old).expect("move held configuration");
    directory(&f.owner.join(".config/loops"));
    refused(
        admission.scope_plan(&f.plan()).expect_err("replacement"),
        "anchor identity",
    );
    fs::remove_dir(f.owner.join(".config/loops")).expect("remove own empty replacement");
    fs::rename(&old, f.owner.join(".config/loops")).expect("restore held directory");
    admission.scope_plan(&f.plan()).expect("restored");
    let link = f.root.path().join("linked-home");
    std::os::unix::fs::symlink(&f.owner, &link).expect("fixture link");
    let mut d = f.declaration();
    d.owner_home = link;
    refused(
        fixture::construct(Arc::clone(&f.root), d)
            .err()
            .expect("no links"),
        "directory containment",
    );
}

/// ´test:crate:fixture-admission-activation-refuses-replaced-root´
#[test]
fn fixture_admission_activation_refuses_replaced_root() {
    let f = Fixture::new();
    let admission = f.admission();
    let custody = crate::container_helper::CredentialThreadCustody::capture_admitted(
        BoxBackend::Claude,
        &admission,
    )
    .expect("captured fixture");
    let original = f.root.path().to_path_buf();
    let displaced = original.with_extension("retained");
    fs::rename(&original, &displaced).expect("move fixture root");
    directory(&original);
    let result = std::thread::spawn(move || custody.activate().err())
        .join()
        .expect("joined");
    // Restore host-created identities before asserting, so an assertion cannot leave a root behind.
    fs::remove_dir(&original).expect("remove own empty replacement");
    fs::rename(&displaced, &original).expect("restore fixture root");
    refused(result.expect("activation refusal"), "root creation custody");
    admission.scope_plan(&f.plan()).expect("restored scope");
}

/// ´test:crate:fixture-admission-readers-refuse-foreign-run-before-plan-read´
#[test]
fn fixture_admission_readers_refuse_foreign_run_before_plan_read() {
    let f = Fixture::new();
    let admission = f.admission();
    refused(
        crate::load_launch_plan_admitted(
            &f.owner,
            "alpha",
            "S",
            (0, 0),
            Some(BoxBackend::Claude),
            &admission,
        )
        .expect_err("loader scope"),
        "run",
    );
    refused(
        crate::launch::pinned_plan_from_record_admitted(
            &f.owner,
            "alpha",
            "S",
            Path::new("/usr/bin/podman"),
            &json!({"plan":f.plan()}),
            &admission,
        )
        .expect_err("reader scope"),
        "run",
    );
    refused(
        admission
            .scope_evidence(&f.owner)
            .expect_err("foreign evidence"),
        "evidence directory",
    );
    assert_eq!(fs::read_dir(&f.runs).expect("runs inventory").count(), 0);
}

/// ´test:crate:fixture-admission-constructor-refuses-host-owned-program´
#[test]
fn fixture_admission_constructor_refuses_host_owned_program() {
    use loop_home::anchor::{
        HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement, Transport,
    };
    let f = Fixture::new();
    let path = f.root.path().join("host-owned-stand-in");
    fs::copy("/usr/bin/true", &path).expect("synthetic copy; never executed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
    let policy = Policy {
        kind: Kind::File,
        owner: Owner::Host,
        mode: ModePolicy::Executable,
    };
    let pin = HostVerifier::current()
        .expect("host")
        .for_operation("container-helper")
        .pin(&path, "credential-claude", 0, policy)
        .expect("host-owned pin");
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: "container-helper".into(),
        loop_name: "alpha".into(),
        records: vec![pin.record()],
    };
    let mut anchors = Receiver::current()
        .expect("receiver")
        .validate(
            &manifest,
            vec![pin.into_fd()],
            "container-helper",
            "alpha",
            Transport::Rights,
            &[Requirement {
                purpose: "credential-claude".into(),
                policy,
                alias_group: None,
            }],
        )
        .expect("held host file");
    let mut programs = crate::container_entry::credential_programs(BoxBackend::Claude)
        .expect("program map")
        .expect("active map");
    programs.insert(
        "/usr/bin/claude".into(),
        Arc::new(anchors.pop().expect("host anchor")),
    );
    let _foreign = crate::container_entry::activate_program_map("container-helper", programs);
    refused(
        fixture::construct(Arc::clone(&f.root), f.declaration())
            .err()
            .expect("non-root"),
        "root-owned stand-in",
    );
}

/// ´test:crate:fixture-admission-rejects-replaced-program-anchor´
#[test]
fn fixture_admission_rejects_replaced_program_anchor() {
    let f = Fixture::new();
    let admission = f.admission();
    let mut programs = crate::container_entry::credential_programs(BoxBackend::Claude)
        .expect("programs")
        .expect("held programs");
    let clock = Arc::clone(programs.get(Path::new("/usr/bin/date")).expect("clock"));
    programs.insert("/usr/bin/claude".into(), clock);
    let _foreign = crate::container_entry::activate_program_map("container-helper", programs);
    refused(
        admission
            .scope_plan(&f.plan())
            .expect_err("changed program"),
        "anchor identity",
    );
    refused(
        fixture::construct(Arc::clone(&f.root), f.declaration())
            .err()
            .expect("foreign program"),
        "held stand-in",
    );
}
