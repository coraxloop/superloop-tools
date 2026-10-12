use super::*;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct FakeNode {
    pub(super) root: PathBuf,
    program: PathBuf,
    pub(super) mode: &'static str,
    pub(super) calls: AtomicUsize,
}

impl node::Runner for FakeNode {
    fn spawn(
        &self,
        _: &crate::door::Registration,
        _: crate::door::RetirementOperation,
    ) -> io::Result<Child> {
        Err(io::Error::other("retirement must use its own operation"))
    }

    fn spawn_retirement(&self, run: &str, loop_name: &str, seconds: f64) -> io::Result<Child> {
        let runs = fs::File::open(&self.root)?;
        let allocation = nix::fcntl::Flock::lock(runs, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect("node cleanup must release the allocation lock");
        drop(allocation);
        assert_eq!((run, loop_name), ("R", "alpha"));
        assert!(seconds > 0.0 && seconds <= 120.0);
        assert!(
            !reservation_path(&self.root, run).exists(),
            "node execution preceded host retirement"
        );
        let archived = fs::read_dir(&self.root)
            .expect("runs")
            .filter_map(Result::ok)
            .find(|entry| super::super::census::retired_name(&entry.file_name().to_string_lossy()))
            .expect("archived record");
        let record = read_reservation(&archived.path())
            .expect("read archived")
            .expect("record");
        assert_eq!(record["phase"], "retired");
        assert_eq!(record["node_retirement"]["outcome"]["owed"], true);
        assert_eq!(
            record["node_retirement"]["outcome"]["reason"],
            "node-retirement-in-progress"
        );
        assert!(record["node_retirement"]["outcome"]["host_wall_seconds"].is_null());
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode == "interrupt" {
            nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGKILL)
                .expect("interrupt fixture process");
            unreachable!("SIGKILL returned");
        }
        if self.mode == "unreachable" {
            return Err(io::Error::other("fixture node unreachable"));
        }
        crate::fixture_exec::spawn(
            Command::new(&self.program)
                .arg(self.mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0),
        )
    }

    fn owns_process_group(&self) -> bool {
        true
    }
}

pub(super) fn fixture(
    worker: u32,
    registered: bool,
    mode: &'static str,
) -> (tempfile::TempDir, RetireRequest, FakeNode) {
    let (home, root, request) = super::tests::public_fixture();
    assert_ne!(worker, Uid::effective().as_raw());
    drop(lock_run_preparation(&root, "R", Uid::effective().as_raw()).expect("lease"));
    let runtime = home.path().join("runtime");
    crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n").expect("runtime");
    let driver = root.join("R");
    fs::create_dir(&driver).expect("driver");
    let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,"imports":[],"harvest_agreement":null,"collection":null,
        "plan":{"home":home.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":driver,"runtime_argv":[runtime]},
        "launcher_pid":u32::MAX,"launcher_start":1,"driver_entry_pid":u32::MAX,"driver_entry_start":1,"helper_pid":u32::MAX,"helper_start":1,"helper_parent_pid":u32::MAX,"helper_parent_start":1,"observer_pid":u32::MAX,"observer_start":1,"observer_state":"ended"});
    publish_reservation(&reservation_path(&root, "R"), &record).expect("record");
    if registered {
        route(home.path(), "fixture");
    }
    let program = home.path().join("node");
    crate::fixture_exec::write_executable(&program, br"#!/usr/bin/python3
import json,sys,time
mode=sys.argv[1]
if mode=='deadline': time.sleep(20)
if mode=='tools':
    print('NODE-RETIREMENT-TOOL-REFUSAL',file=sys.stderr)
    sys.exit(127)
if mode=='malformed':
    print('NODE-RETIREMENT {}')
    sys.exit(0)
paths=['/node/lanes/R', '/srv/loops/loop-a/lanes/R-build', '/srv/loops/loop-a/lanes/R-tmp', '/node/lanes/R.lock']
before=[dict(path=p,exists=True,entries=2,bytes=4096) for p in paths]
after=[dict(path=p,exists=False,entries=0,bytes=0) for p in paths]
partial=mode=='partial'
if partial: after[1]=before[1]
e=dict(schema=1,run='R',loop='alpha',before=before,after=after,bytes_freed=12288 if partial else 16384,wall_seconds=0.25,helper_exit=125 if partial else 0,reason='node-retirement-removal-failed' if partial else 'node-retirement-complete',marker=True)
print('NODE-RETIREMENT '+json.dumps(e))
sys.exit(e['helper_exit'])
").expect("node program");
    (
        home,
        request,
        FakeNode {
            root,
            program,
            mode,
            calls: AtomicUsize::new(0),
        },
    )
}

fn route(home: &Path, alias: &str) {
    let config = home.join(".config/loops/alpha");
    let registration = json!({"schema":1,"loop":"alpha","alias":alias,"mirror_root":"~/mirrors","node_root":"/srv/loops/loop-a","key_path":config.join("door-key")});
    for (name, bytes) in [
        ("door-compute-registration.json", registration.to_string()),
        ("door-ssh_config", format!("Host {alias}\n")),
    ] {
        let path = config.join(name);
        fs::write(&path, bytes).expect("route");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("route mode");
    }
    crate::door_node::fixture_for(&config, alias);
}

pub(super) fn execute(
    home: &Path,
    request: &RetireRequest,
    runner: &FakeNode,
) -> Result<Value, LaneError> {
    run_with(
        home,
        request,
        Some(runner),
        if runner.mode == "deadline" {
            Duration::from_millis(30)
        } else {
            node::DEADLINE
        },
    )
}

/// # Panics
/// Panics only if a worker configuration substitutes for the registered node derivatives.
/// ´test:unit:node-retirement-requires-derived-node-ssh-configuration´
#[test]
fn node_retirement_requires_derived_node_ssh_configuration() {
    let (home, mut request, mut runner) = fixture(3000, true, "unreachable");
    let config = home.path().join(".config/loops/alpha");
    let mut settings =
        Settings::read_beneath(&config.join("workers.toml"), home.path()).expect("settings");
    settings
        .backend_argv
        .insert("codex".into(), vec!["/usr/bin/true".into()]);
    fs::create_dir_all(home.path().join(".cache/tmp")).expect("home parent");
    for path in [home.path().join(".cache"), home.path().join(".cache/tmp")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private parent");
    }
    let caller = (
        Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    let plan = crate::plan::Plan::build(
        home.path(),
        "alpha",
        "Generated",
        &settings,
        &json!({"name":"alpha","uid":2001,"runs_root":runner.root}),
        loop_home::registry::WorkerBlock {
            base: 3000,
            count: 2,
        },
        caller,
    )
    .expect("home plan");
    crate::home::make_home(&plan, &settings, b"Fixture letter.\n", caller)
        .expect("production home generator");
    let generated = fs::read(plan.home.join(".ssh/config")).expect("generated SSH configuration");
    assert!(String::from_utf8_lossy(&generated).contains("BatchMode yes"));
    fs::write(config.join("door-ssh_config"), generated).expect("register generated configuration");
    let refused = execute(home.path(), &request, &runner).expect("unmeasured host preview");
    assert_eq!(
        refused["retirement"]["node_retirement"]["plan"]["reason"],
        "node-retirement-registration-refusal"
    );
    crate::door_node::fixture(&config);
    let preview = execute(home.path(), &request, &runner).expect("host preview");
    assert_eq!(
        preview["retirement"]["node_retirement"]["plan"]["reason"],
        "node-retirement-pending"
    );
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    request.dry_run = false;
    request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
    let retired = execute(home.path(), &request, &runner).expect("host retirement");
    assert_eq!(
        retired["retirement"]["node_retirement"]["outcome"]["reason"],
        "node-retirement-unreachable"
    );
    request.node = true;
    request.dry_run = true;
    request.expect_digest = None;
    let preview = execute(home.path(), &request, &runner).expect("node preview");
    assert_eq!(preview["node_plan"]["reason"], "node-retirement-pending");
    request.dry_run = false;
    request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
    runner.mode = "success";
    let completed = execute(home.path(), &request, &runner).expect("node completion");
    assert_eq!(completed["node_retirement"]["outcome"]["owed"], false);
    assert_eq!(
        completed["node_retirement"]["outcome"]["reason"],
        "node-retirement-complete"
    );
}

fn predecessor_fixture() -> (tempfile::TempDir, RetireRequest, FakeNode, PathBuf, Value) {
    predecessor_with_outcome("unreachable")
}

fn predecessor_with_outcome(
    mode: &'static str,
) -> (tempfile::TempDir, RetireRequest, FakeNode, PathBuf, Value) {
    let (home, mut request, runner) = fixture(3000, true, mode);
    let preview = execute(home.path(), &request, &runner).expect("preview");
    request.dry_run = false;
    request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
    let result = execute(home.path(), &request, &runner).expect("archive debt");
    let path = PathBuf::from(result["retirement"]["record"].as_str().expect("archive"));
    let mut record = read_reservation(&path).expect("reader").expect("record");
    let plan = &mut record["node_retirement"]["plan"];
    plan["route"]
        .as_object_mut()
        .expect("route")
        .remove("node_root");
    plan["paths"][1] = json!("~/lanes/R-build");
    plan["paths"][2] = json!("~/lanes/R-tmp");
    if mode == "success" {
        assert_eq!(record["node_retirement"]["outcome"]["state"], "complete");
        for listing in ["before", "after"] {
            for row in record["node_retirement"]["outcome"]["evidence"][listing]
                .as_array_mut()
                .expect("measured listing")
            {
                row["path"] = json!(
                    row["path"]
                        .as_str()
                        .expect("path")
                        .replace("/srv/loops/loop-a/lanes/", "/node/lanes/")
                );
            }
        }
    }
    record["node_retirement"]["attempts"] = json!([{
        "plan":record["node_retirement"]["plan"],
        "outcome":record["node_retirement"]["outcome"]
    }]);
    publish_reservation(&path, &record).expect("base-shaped record");
    request.node = true;
    request.dry_run = true;
    request.expect_digest = None;
    (home, request, runner, path, record)
}

fn large_predecessor(record: &mut Value) {
    let outcome = &mut record["node_retirement"]["outcome"];
    let evidence = &mut outcome["evidence"];
    evidence["error"] = json!("e".repeat(4096));
    for row in evidence["before"].as_array_mut().expect("listing") {
        row["entries"] = json!(u64::MAX);
        row["bytes"] = json!(u64::MAX / 4);
    }
    evidence["bytes_freed"] = json!((u64::MAX / 4) * 4);
    // Fill the helper's 16 KiB output allowance with absolute evidence paths.
    let available = 16_384 - "NODE-RETIREMENT \n".len() - evidence.to_string().len();
    let prefix = "/p".repeat(available / 16);
    for listing in ["before", "after"] {
        for row in evidence[listing].as_array_mut().expect("listing") {
            row["path"] = json!(format!("{prefix}{}", row["path"].as_str().expect("path")));
        }
    }
    assert!(evidence.to_string().len() + "NODE-RETIREMENT \n".len() <= 16_384);
    record["node_retirement"]["attempts"] = json!(vec![
        json!({
            "plan":record["node_retirement"]["plan"],
            "outcome":record["node_retirement"]["outcome"]
        });
        4
    ]);
}

/// ´test:unit:retirement-root-conversion-measures-journal-headroom´
#[test]
fn retirement_root_conversion_measures_journal_headroom() {
    for mode in ["unreachable", "success", "largest"] {
        let (home, _, _, path, mut record) = predecessor_with_outcome(if mode == "unreachable" {
            mode
        } else {
            "success"
        });
        if mode == "largest" {
            large_predecessor(&mut record);
            publish_reservation(&path, &record).expect("large predecessor");
        }
        let preview = full_conversion(home.path(), &["alpha".into(), "--dry-run".into()])
            .expect("measured preview");
        let row = &preview["plan"]["files"][0];
        let journal = json!({"schema":1,"phase":"pending","digest":preview["preview_sha256"],"plan":preview["plan"]});
        let row_bytes = row.to_string().len();
        let journal_bytes = journal.to_string().len();
        writeln!(io::stdout().lock(),
            "JOURNAL-MEASUREMENT mode={mode} before={} after={} row={row_bytes} journal={journal_bytes} bound={} headroom={} overflow_records={}",
            row["before"].to_string().len(),
            row["after"].to_string().len(),
            MAX_RESERVATION_BYTES,
            MAX_RESERVATION_BYTES - journal_bytes as u64,
            (usize::try_from(MAX_RESERVATION_BYTES).expect("bound") - (journal_bytes - row_bytes)) / (row_bytes + 1) + 1
        ).expect("measurement output");
        assert!(journal_bytes as u64 <= MAX_RESERVATION_BYTES);
        assert!((row_bytes * 4090) as u64 > MAX_RESERVATION_BYTES);
    }
}

fn batched_predecessors() -> (tempfile::TempDir, FakeNode, Value) {
    let (home, _, runner, path, mut record) = predecessor_with_outcome("success");
    large_predecessor(&mut record);
    publish_reservation(&path, &record).expect("large original");
    for index in 0..39 {
        let path = runner.root.join(format!(".retired-R-20-1-{index}"));
        record["current_retirement"]["reservation_path"]["target"] = json!(path);
        publish_reservation(&path, &record).expect("large historical archive");
    }
    let preview =
        full_conversion(home.path(), &["alpha".into(), "--dry-run".into()]).expect("batch preview");
    (home, runner, preview)
}

fn apply_conversion(home: &Path, preview: &Value) -> Result<Value, LaneError> {
    full_conversion(
        home,
        &[
            "alpha".into(),
            "--expect-digest".into(),
            preview["preview_sha256"].as_str().expect("digest").into(),
        ],
    )
}

/// ´test:unit:retirement-root-conversion-batches-preserve-dry-run-parity´
#[test]
fn retirement_root_conversion_batches_preserve_dry_run_parity() {
    let (home, runner, preview) = batched_predecessors();
    let old_journal = json!({"schema":1,"phase":"pending","digest":preview["preview_sha256"],"plan":preview["plan"]});
    assert!(old_journal.to_string().len() as u64 > MAX_RESERVATION_BYTES);
    assert_eq!(preview["changed"], 40);
    assert_eq!(preview["batch_count"], 3);
    assert!(preview["journal_bytes"].as_u64().expect("size") <= MAX_RESERVATION_BYTES);
    assert!(!runner.root.join(".retire-node-rewrite.json").exists());
    for row in preview["plan"]["files"].as_array().expect("files") {
        let bytes = fs::read(row["path"].as_str().expect("path")).expect("original bytes");
        assert_eq!(absences::hash(&bytes), row["before_sha256"]);
    }
    let result = apply_conversion(home.path(), &preview).expect("batch conversion");
    for key in [
        "plan",
        "preview_sha256",
        "changed",
        "batch_count",
        "journal_bytes",
    ] {
        assert_eq!(result[key], preview[key], "{key}");
    }
    for row in result["plan"]["files"].as_array().expect("files") {
        assert_eq!(
            read_reservation(Path::new(row["path"].as_str().expect("path")))
                .expect("converted reader")
                .expect("record"),
            row["after"]
        );
    }
    let journal: Value = serde_json::from_slice(
        &fs::read(runner.root.join(".retire-node-rewrite.json")).expect("journal bytes"),
    )
    .expect("journal");
    assert_eq!(journal["phase"], "complete");
    assert_eq!(journal["digest"], preview["preview_sha256"]);
    assert_eq!(journal["batch_index"], 2);
    assert_eq!(
        full_conversion(home.path(), &["alpha".into(), "--dry-run".into()])
            .expect("idempotent preview")["changed"],
        0
    );
}

/// ´test:unit:retirement-root-conversion-resumes-between-batches´
#[test]
fn retirement_root_conversion_resumes_between_batches() {
    use std::os::unix::fs::MetadataExt as _;
    for partial in [false, true] {
        let (home, runner, preview) = batched_predecessors();
        let journals = node_rewrite::batches(
            &preview["plan"],
            preview["preview_sha256"].as_str().expect("digest"),
        )
        .expect("batches");
        let journal_path = runner.root.join(".retire-node-rewrite.json");
        publish_reservation(&journal_path, &journals[0]).expect("first batch journal");
        for row in journals[0]["plan"]["files"].as_array().expect("files") {
            publish_reservation(
                Path::new(row["path"].as_str().expect("path")),
                &row["after"],
            )
            .expect("first batch completed");
        }
        // Both crash boundaries: the next journal has not yet been published,
        // or it is durable and the next batch is only partly converted.
        if partial {
            publish_reservation(&journal_path, &journals[1]).expect("next journal");
            let row = &journals[1]["plan"]["files"][0];
            publish_reservation(
                Path::new(row["path"].as_str().expect("path")),
                &row["after"],
            )
            .expect("partial second batch");
        }
        let resumed = full_conversion(home.path(), &["alpha".into(), "--dry-run".into()])
            .expect("resumed preview");
        assert_eq!(resumed["resuming"], true);
        for key in ["plan", "preview_sha256", "changed", "batch_count"] {
            assert_eq!(resumed[key], preview[key], "{key}");
        }
        let untouched = &journals[2]["plan"]["files"][0];
        let path = Path::new(untouched["path"].as_str().expect("path"));
        let mut changed = untouched["before"].clone();
        changed["worker_uid"] = json!(3001);
        publish_reservation(path, &changed).expect("change later batch");
        let journal_before = fs::read(&journal_path).expect("journal before refusal");
        let snapshots: Vec<_> = preview["plan"]["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|row| {
                let path = PathBuf::from(row["path"].as_str().expect("path"));
                let bytes = fs::read(&path).expect("record before refusal");
                (path, bytes)
            })
            .collect();
        let first_inodes: Vec<_> = journals[0]["plan"]["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|row| {
                let path = PathBuf::from(row["path"].as_str().expect("path"));
                let inode = fs::metadata(&path).expect("completed batch metadata").ino();
                (path, inode)
            })
            .collect();
        let error = apply_conversion(home.path(), &preview).expect_err("changed later batch");
        assert!(
            error.detail.contains("record changed since preview"),
            "{}",
            error.line()
        );
        assert_eq!(
            fs::read(&journal_path).expect("journal after refusal"),
            journal_before
        );
        for (path, bytes) in snapshots {
            assert_eq!(fs::read(path).expect("record after refusal"), bytes);
        }
        publish_reservation(path, &untouched["before"]).expect("restore later batch");
        let result = apply_conversion(home.path(), &preview).expect("resume all batches");
        for (path, inode) in first_inodes {
            assert_eq!(
                fs::metadata(path).expect("completed batch retained").ino(),
                inode
            );
        }
        assert_eq!(result["preview_sha256"], preview["preview_sha256"]);
        for row in result["plan"]["files"].as_array().expect("files") {
            assert_eq!(
                read_reservation(Path::new(row["path"].as_str().expect("path")))
                    .expect("reader")
                    .expect("record"),
                row["after"]
            );
        }
    }
}

/// ´test:unit:retirement-root-conversion-refuses-oversized-single-file-before-write´
#[test]
fn retirement_root_conversion_refuses_oversized_single_file_before_write() {
    let (home, _, runner, path, mut before) = predecessor_fixture();
    before["retained_history"] =
        json!("x".repeat(usize::try_from(MAX_RESERVATION_BYTES).expect("bound") / 2));
    publish_reservation(&path, &before).expect("bounded individual record");
    let original = fs::read(&path).expect("original");
    let error = full_conversion(home.path(), &["alpha".into(), "--dry-run".into()])
        .expect_err("one row cannot be split across files");
    assert!(error.detail.contains("one conversion file"));
    assert!(!runner.root.join(".retire-node-rewrite.json").exists());
    assert_eq!(fs::read(path).expect("unchanged"), original);
}

/// ´test:unit:retirement-root-conversion-measures-reservation-reader-ceiling´
#[test]
fn retirement_root_conversion_measures_reservation_reader_ceiling() {
    let (home, _, runner, path, mut before) = predecessor_with_outcome("success");
    large_predecessor(&mut before);
    // The historical reservation reader does not reapply the helper's 16 KiB
    // output limit. Measure that separate ceiling too, using all eight listing
    // paths in each of the current outcome and four retained attempts.
    let available =
        usize::try_from(MAX_RESERVATION_BYTES).expect("bound") - before.to_string().len();
    let prefix = "/p".repeat(available / 80);
    let evidence = &mut before["node_retirement"]["outcome"]["evidence"];
    for listing in ["before", "after"] {
        for row in evidence[listing].as_array_mut().expect("listing") {
            row["path"] = json!(format!("{prefix}{}", row["path"].as_str().expect("path")));
        }
    }
    before["node_retirement"]["attempts"] = json!(vec![
        json!({
            "plan":before["node_retirement"]["plan"],
            "outcome":before["node_retirement"]["outcome"]
        });
        4
    ]);
    publish_reservation(&path, &before).expect("reader ceiling predecessor");
    super::super::read_reservation_checked(&path, false).expect("bounded predecessor reader");
    let after = node_rewrite::convert(&before).expect("valid conversion shape");
    let row = json!({"path":path,"before":before,"before_sha256":absences::hash(&fs::read(&path).expect("bytes")),"after":after});
    writeln!(
        io::stdout().lock(),
        "JOURNAL-MEASUREMENT mode=reservation-reader-ceiling before={} after={} row={} bound={}",
        row["before"].to_string().len(),
        row["after"].to_string().len(),
        row.to_string().len(),
        MAX_RESERVATION_BYTES
    )
    .expect("measurement output");
    assert!(row["before"].to_string().len() as u64 <= MAX_RESERVATION_BYTES);
    assert!(row["after"].to_string().len() as u64 > MAX_RESERVATION_BYTES);
    let before_bytes = fs::read(&path).expect("original bytes");
    let error = full_conversion(home.path(), &["alpha".into(), "--dry-run".into()])
        .expect_err("converted record itself exceeds reader bound");
    assert!(
        error
            .detail
            .contains("converted record exceeds the reader bound"),
        "{}",
        error.line()
    );
    assert!(error.detail.contains(path.to_str().expect("path")));
    assert!(error.detail.contains(&MAX_RESERVATION_BYTES.to_string()));
    assert_eq!(
        fs::read(&path).expect("unchanged oversized record"),
        before_bytes
    );
    assert!(!runner.root.join(".retire-node-rewrite.json").exists());
}

/// ´test:unit:retirement-root-conversion-preserves-complete-evidence´
#[test]
fn retirement_root_conversion_preserves_complete_evidence() {
    let (home, request, runner, path, before) = predecessor_with_outcome("success");
    let preview =
        full_conversion(home.path(), &["alpha".into(), "--dry-run".into()]).expect("preview");
    let result = full_conversion(
        home.path(),
        &[
            "alpha".into(),
            "--expect-digest".into(),
            preview["preview_sha256"].as_str().expect("digest").into(),
        ],
    )
    .expect("conversion");
    assert_eq!(result["changed"], preview["changed"]);
    let converted = read_reservation(&path).expect("reader").expect("record");
    assert_eq!(
        converted["node_retirement"]["outcome"],
        before["node_retirement"]["outcome"]
    );
    assert_eq!(
        converted["node_retirement"]["attempts"][0]["outcome"],
        before["node_retirement"]["attempts"][0]["outcome"]
    );
    assert_eq!(
        converted["node_retirement"]["outcome"]["evidence"]["before"]
            .as_array()
            .expect("listing")
            .len(),
        4
    );
    super::super::census::run(home.path(), "alpha").expect("converted census");
    assert_eq!(
        execute(home.path(), &request, &runner)
            .expect_err("nothing owed")
            .kind,
        "retire-node-not-owed"
    );

    let mut unproven = converted;
    unproven
        .as_object_mut()
        .expect("record")
        .remove("node_retirement_rewrite");
    let error = node_record::read(&unproven).expect_err("relative root requires provenance");
    assert_eq!(error.kind, "retire-node-record");
    assert!(error.detail.contains("node_retirement_rewrite"));
    unproven["node_retirement"]["plan"]["route"]["node_root"] = json!("/node");
    assert!(
        node_record::read(&unproven)
            .expect_err("relative attempt requires provenance")
            .detail
            .contains("node_retirement_rewrite")
    );
}

/// ´test:unit:retirement-root-conversion-restores-census-and-completion´
#[test]
fn retirement_root_conversion_restores_census_and_completion() {
    let (home, mut request, mut runner, path, before) = predecessor_fixture();
    for error in [
        super::super::census::run(home.path(), "alpha").expect_err("census refuses predecessor"),
        execute(home.path(), &request, &runner).expect_err("completion refuses predecessor"),
    ] {
        assert!(error.line().contains("retire-node-rewrite-required"));
        assert!(error.line().contains("retire rewrite-node alpha --dry-run"));
    }
    let args = vec!["alpha".into(), "--dry-run".into()];
    let preview = full_conversion(home.path(), &args).expect("conversion preview");
    assert_eq!(preview["changed"], 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&path).expect("bytes")).expect("JSON"),
        before
    );
    assert!(!runner.root.join(".retire-node-rewrite.json").exists());
    let apply = vec![
        "alpha".into(),
        "--expect-digest".into(),
        preview["preview_sha256"].as_str().expect("digest").into(),
    ];
    let result = full_conversion(home.path(), &apply).expect("convert");
    assert_eq!(result["changed"], preview["changed"]);
    assert_eq!(result["plan"], preview["plan"]);
    let converted = read_reservation(&path)
        .expect("reader")
        .expect("converted record");
    assert_eq!(
        converted["node_retirement"]["plan"]["route"]["node_root"],
        "~"
    );
    assert_eq!(
        converted["node_retirement"]["plan"]["paths"],
        before["node_retirement"]["plan"]["paths"]
    );
    super::super::census::run(home.path(), "alpha").expect("census after conversion");
    assert_eq!(
        full_conversion(home.path(), &args).expect("repeat")["changed"],
        0
    );
    let program = fs::read_to_string(&runner.program)
        .expect("program")
        .replace("/srv/loops/loop-a/lanes/", "/node/lanes/");
    crate::fixture_exec::write_executable(&runner.program, program.as_bytes())
        .expect("legacy paths");
    runner.mode = "success";
    route(home.path(), "changed");
    assert_eq!(
        execute(home.path(), &request, &runner)
            .expect_err("changed destination")
            .kind,
        "retire-node-route"
    );
    route(home.path(), "fixture");
    let preview = execute(home.path(), &request, &runner).expect("completion preview");
    assert_eq!(preview["node_plan"]["route"]["node_root"], "~");
    request.dry_run = false;
    request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
    assert_eq!(
        execute(home.path(), &request, &runner).expect("complete old debt")["node_retirement"]["outcome"]
            ["state"],
        "complete"
    );
    super::super::census::run(home.path(), "alpha").expect("completed census");
}

/// ´test:unit:retirement-root-conversion-refuses-unknown-before-any-write´
#[test]
fn retirement_root_conversion_refuses_unknown_before_any_write() {
    let (home, _, runner, path, before) = predecessor_fixture();
    let mut malformed = before.clone();
    malformed["node_retirement"]["plan"]["paths"][1] = json!("~/other/R-build");
    let other = runner.root.join(".reservation-S.json");
    malformed["run"] = json!("S");
    publish_reservation(&other, &malformed).expect("unknown record");
    for args in [
        vec!["alpha".into(), "--dry-run".into()],
        vec!["alpha".into(), "--expect-digest".into(), "0".repeat(64)],
    ] {
        full_conversion(home.path(), &args).expect_err("reject inventory");
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).expect("bytes")).expect("JSON"),
            before
        );
        assert!(!runner.root.join(".retire-node-rewrite.json").exists());
    }
}

/// ´test:unit:retirement-root-conversion-resumes-and-preserves-retiring-phase´
#[test]
fn retirement_root_conversion_resumes_and_preserves_retiring_phase() {
    for published in [false, true] {
        let (home, _, runner, archived, mut before) = predecessor_fixture();
        let path = reservation_path(&runner.root, "R");
        before["phase"] = json!("retiring");
        publish_reservation(&path, &before).expect("retiring predecessor");
        fs::remove_file(&archived).expect("move fixture back to active inventory");
        assert_eq!(
            read_reservation(&path)
                .expect_err("refuse predecessor")
                .kind,
            "retire-node-rewrite-required"
        );
        let args = vec!["alpha".into(), "--dry-run".into()];
        let preview = full_conversion(home.path(), &args).expect("preview");
        publish_reservation(&runner.root.join(".retire-node-rewrite.json"), &json!({"schema":1,"phase":"pending","digest":preview["preview_sha256"],"plan":preview["plan"]})).expect("interrupted journal");
        if published {
            publish_reservation(&path, &preview["plan"]["files"][0]["after"])
                .expect("published target");
        }
        let resumed = full_conversion(home.path(), &args).expect("resume preview");
        assert_eq!(resumed["changed"], 1);
        assert_eq!(resumed["preview_sha256"], preview["preview_sha256"]);
        let apply = vec![
            "alpha".into(),
            "--expect-digest".into(),
            preview["preview_sha256"].as_str().expect("digest").into(),
        ];
        full_conversion(home.path(), &apply).expect("resume conversion");
        assert_eq!(
            read_reservation(&path).expect("reader").expect("record")["phase"],
            "retiring"
        );
        super::super::census::run(home.path(), "alpha").expect("retiring census");
    }
}

/// ´test:unit:public-node-retirement-outcomes-and-durable-debt´
#[test]
fn public_node_retirement_outcomes_and_durable_debt() {
    for worker in [3000, 3001] {
        for (registered, mode, reason, owed) in [
            (false, "success", "node-retirement-no-registration", false),
            (true, "unreachable", "node-retirement-unreachable", true),
            (true, "tools", "node-retirement-tools-absent", true),
            (true, "deadline", "node-retirement-deadline", true),
            (true, "malformed", "node-retirement-evidence-refusal", true),
            (true, "partial", "node-retirement-removal-failed", true),
            (true, "success", "node-retirement-complete", false),
        ] {
            let (home, mut request, runner) = fixture(worker, registered, mode);
            let preview = execute(home.path(), &request, &runner).expect("preview");
            assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
            assert!(
                preview["retirement"]["node_retirement"]["outcome"]["host_wall_seconds"].is_null()
            );
            assert_eq!(
                preview["retirement"]["node_retirement"]["plan"]["deadline_seconds"],
                120
            );
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let result =
                execute(home.path(), &request, &runner).expect("host retires regardless of node");
            assert_eq!(result["worker_uid_released"], worker);
            let node = &result["retirement"]["node_retirement"];
            assert_eq!(node["outcome"]["reason"], reason);
            assert_eq!(node["outcome"]["owed"], owed);
            assert_eq!(node["attempts"], json!([]));
            assert_eq!(node["outcome"]["host_wall_seconds"].is_null(), !registered);
            if registered {
                let mut missing_wall = node["outcome"].clone();
                missing_wall["host_wall_seconds"] = Value::Null;
                assert!(!node::valid_outcome(&missing_wall, &node["plan"]));
            }
            assert_eq!(runner.calls.load(Ordering::SeqCst), usize::from(registered));
            let archived = Path::new(result["retirement"]["record"].as_str().expect("path"));
            let record = read_reservation(archived).expect("read").expect("archived");
            assert_eq!(&record["node_retirement"], node);
            let census = super::super::census::run(home.path(), "alpha").expect("census");
            assert_eq!(&census["retired_records"][0]["node_retirement"], node);
            if mode == "success" && registered {
                assert_eq!(node["outcome"]["evidence"]["bytes_freed"], 16384);
                assert_eq!(node["outcome"]["helper_exit"], 0);
            }
            if mode == "deadline" {
                assert_eq!(node["outcome"]["remote_completion"], "unknown");
                assert!(node["outcome"]["helper_exit"].is_null());
            }
        }
    }
}

/// ´test:unit:public-node-completion-digest-history-and-route-refusals´
#[test]
fn public_node_completion_digest_history_and_route_refusals() {
    for worker in [3000, 3001] {
        let (home, mut request, mut runner) = fixture(worker, true, "unreachable");
        request.dry_run = false;
        let result = execute(home.path(), &request, &runner).expect("retire host");
        let path = PathBuf::from(result["retirement"]["record"].as_str().expect("path"));
        request.node = true;
        request.dry_run = true;
        let preview = execute(home.path(), &request, &runner).expect("completion preview");
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        request.dry_run = false;
        request.expect_digest = Some("0".repeat(64));
        assert_eq!(
            execute(home.path(), &request, &runner)
                .expect_err("digest mismatch")
                .kind,
            "retire-digest"
        );
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        route(home.path(), "changed");
        assert_eq!(
            execute(home.path(), &request, &runner)
                .expect_err("changed route")
                .kind,
            "retire-node-route"
        );
        route(home.path(), "fixture");
        for _ in 0..6 {
            execute(home.path(), &request, &runner).expect("owed retry");
        }
        let record = read_reservation(&path).expect("read").expect("record");
        assert_eq!(
            record["node_retirement"]["attempts"]
                .as_array()
                .map(Vec::len),
            Some(4)
        );
        assert!(
            record["node_retirement"]["attempts_omitted"]
                .as_u64()
                .expect("omitted")
                > 0
        );
        runner.mode = "success";
        let completed = execute(home.path(), &request, &runner).expect("complete node");
        assert_eq!(completed["node_retirement"]["outcome"]["state"], "complete");
        assert!(completed["worker_uid_released"].is_null());
        let count = runner.calls.load(Ordering::SeqCst);
        assert_eq!(
            execute(home.path(), &request, &runner)
                .expect_err("nothing owed")
                .kind,
            "retire-node-not-owed"
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), count);
        let mut prior = read_reservation(&path).expect("read").expect("record");
        prior
            .as_object_mut()
            .expect("object")
            .remove("node_retirement");
        publish_reservation(&path, &prior).expect("historical record");
        request.dry_run = true;
        request.expect_digest = None;
        let historical = execute(home.path(), &request, &runner).expect("old record");
        assert_eq!(
            historical["node_retirement"]["reason"],
            "retired before node retirement existed"
        );
        let census = super::super::census::run(home.path(), "alpha").expect("old census");
        assert_eq!(
            census["retired_records"][0]["node_retirement"]["reason"],
            "retired before node retirement existed"
        );
        request.dry_run = false;
        request.expect_digest = historical["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            execute(home.path(), &request, &runner).expect("complete historical node")["node_retirement"]
                ["outcome"]["state"],
            "complete"
        );
        request.dry_run = true;
        request.expect_digest = None;
        prior["node_retirement"] = Value::Null;
        publish_reservation(&path, &prior).expect("malformed present");
        assert_eq!(
            execute(home.path(), &request, &runner)
                .expect_err("malformed")
                .kind,
            "retire-node-record"
        );
    }
}

/// ´test:unit:public-retirement-preview-binds-host-and-node-inputs´
#[test]
fn public_retirement_preview_binds_host_and_node_inputs() {
    let (home, mut request, runner) = fixture(3000, true, "success");
    let preview = execute(home.path(), &request, &runner).expect("preview");
    request.dry_run = false;
    request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
    route(home.path(), "different");
    assert_eq!(
        execute(home.path(), &request, &runner)
            .expect_err("route digest")
            .kind,
        "retire-digest"
    );
    route(home.path(), "fixture");
    let path = reservation_path(&runner.root, "R");
    let mut record = read_reservation(&path).expect("read").expect("record");
    record["worker_uid"] = json!(3001);
    publish_reservation(&path, &record).expect("other uid");
    assert_eq!(
        execute(home.path(), &request, &runner)
            .expect_err("identity digest")
            .kind,
        "retire-digest"
    );
    record["worker_uid"] = json!(3000);
    publish_reservation(&path, &record).expect("restore");
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    // Atomic publication can change the inode and its retirement target.
    request.dry_run = true;
    request.expect_digest = None;
    let refreshed = execute(home.path(), &request, &runner).expect("new custody preview");
    request.expect_digest = refreshed["preview_sha256"].as_str().map(str::to_owned);
    request.dry_run = false;
    let result = execute(home.path(), &request, &runner).expect("matching digest");
    let archived = PathBuf::from(result["retirement"]["record"].as_str().expect("archive"));
    request.node = true;
    request.dry_run = true;
    request.expect_digest = None;
    publish_reservation(&path, &record).expect("same name active");
    assert_eq!(
        execute(home.path(), &request, &runner)
            .expect_err("active")
            .kind,
        "retire-node-active-run"
    );
    fs::remove_file(path).expect("remove fixture active");
    let mut duplicate = read_reservation(&archived).expect("read").expect("record");
    let second = runner.root.join(".retired-R-20-1-2");
    duplicate["current_retirement"]["reservation_path"]["target"] = json!(second);
    publish_reservation(&second, &duplicate).expect("duplicate archive");
    assert_eq!(
        execute(home.path(), &request, &runner)
            .expect_err("ambiguous")
            .kind,
        "retire-node-ambiguous"
    );
}

/// ´test:unit:public-node-retirement-invalid-registration-remains-owed´
#[test]
fn public_node_retirement_invalid_registration_remains_owed() {
    let (home, mut request, runner) = fixture(3000, true, "success");
    fs::write(
        home.path().join(".config/loops/alpha/door-ssh_config"),
        "Host fixture\nProxyCommand forbidden\n",
    )
    .expect("invalid route");
    request.dry_run = false;
    let result = execute(home.path(), &request, &runner).expect("host retirement");
    assert_eq!(result["retirement"]["state"], "retired");
    assert_eq!(
        result["retirement"]["node_retirement"]["outcome"]["reason"],
        "node-retirement-registration-refusal"
    );
    assert_eq!(
        result["retirement"]["node_retirement"]["outcome"]["owed"],
        true
    );
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        result["retirement"]["node_retirement"]["attempts"],
        json!([])
    );
    assert!(result["retirement"]["node_retirement"]["outcome"]["host_wall_seconds"].is_null());
}

/// ´test:unit:interrupted-node-retirement-keeps-unknown-host-wall´
#[test]
fn interrupted_node_retirement_keeps_unknown_host_wall() {
    const TEST: &str =
        "launch::retire::node_tests::interrupted_node_retirement_keeps_unknown_host_wall";
    const HOME: &str = "LANE_RETIRE_INTERRUPT_FIXTURE";
    if let Some(home) = std::env::var_os(HOME) {
        let home = PathBuf::from(home);
        let request = RetireRequest::parse(&["alpha".into(), "R".into()]).expect("request");
        let runner = FakeNode {
            root: home.join("runs"),
            program: home.join("node"),
            mode: "interrupt",
            calls: AtomicUsize::new(0),
        };
        execute(&home, &request, &runner).expect("interrupted before return");
        panic!("fixture survived interruption");
    }
    for worker in [3000, 3001] {
        let (home, mut request, runner) = fixture(worker, true, "success");
        let child = Command::new(std::env::current_exe().expect("test binary"))
            .args([TEST, "--exact", "--nocapture"])
            .env(HOME, home.path())
            .output()
            .expect("interrupt child");
        assert_eq!(
            child.status.signal(),
            Some(9),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(!reservation_path(&runner.root, "R").exists());
        let census = super::super::census::run(home.path(), "alpha").expect("census");
        let outcome = &census["retired_records"][0]["node_retirement"]["outcome"];
        assert_eq!(outcome["reason"], "node-retirement-in-progress");
        assert!(outcome["host_wall_seconds"].is_null());
        assert_eq!(outcome["remote_completion"], "unknown");
        assert_eq!(outcome["owed"], true);
        request.node = true;
        request.dry_run = false;
        let completed = execute(home.path(), &request, &runner).expect("retry interrupted attempt");
        assert_eq!(completed["node_retirement"]["outcome"]["state"], "complete");
        assert_eq!(
            completed["node_retirement"]["attempts"][0]["outcome"],
            *outcome
        );
    }
}

/// ´test:unit:host-retirement-recovers-with-changed-node-route´
#[test]
fn host_retirement_recovers_with_changed_node_route() {
    for worker in [3000, 3001] {
        let (home, mut request, runner) = fixture(worker, true, "success");
        let preview = execute(home.path(), &request, &runner).expect("initial preview");
        let path = reservation_path(&runner.root, "R");
        let mut record = read_reservation(&path).expect("read").expect("record");
        record["phase"] = json!("retiring");
        record["current_retirement"] = preview["retirement"]["journal"].clone();
        record["node_retirement"] = preview["retirement"]["node_retirement"].clone();
        publish_reservation(&path, &record).expect("interrupted custody");
        route(home.path(), "changed");
        let refreshed = execute(home.path(), &request, &runner).expect("recovery preview");
        request.expect_digest = refreshed["preview_sha256"].as_str().map(str::to_owned);
        request.dry_run = false;
        let result = execute(home.path(), &request, &runner).expect("finish host custody");
        assert_eq!(result["worker_uid_released"], worker);
        assert_eq!(result["retirement"]["state"], "retired");
        let node = &result["retirement"]["node_retirement"];
        assert_eq!(node["plan"], record["node_retirement"]["plan"]);
        assert_eq!(node["outcome"]["reason"], "node-retirement-route-changed");
        assert_eq!(node["attempts"], json!([]));
        assert_eq!(node["attempts_omitted"], 0);
        assert_eq!(node["outcome"]["owed"], true);
        assert!(node["outcome"]["host_wall_seconds"].is_null());
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        let census = super::super::census::run(home.path(), "alpha").expect("census");
        assert_eq!(&census["retired_records"][0]["node_retirement"], node);
        request.node = true;
        request.dry_run = true;
        request.expect_digest = None;
        assert_eq!(
            execute(home.path(), &request, &runner)
                .expect_err("changed route")
                .kind,
            "retire-node-route"
        );
        route(home.path(), "fixture");
        let retry = execute(home.path(), &request, &runner).expect("restored route preview");
        request.expect_digest = retry["preview_sha256"].as_str().map(str::to_owned);
        request.dry_run = false;
        assert_eq!(
            execute(home.path(), &request, &runner).expect("restored route completion")["node_retirement"]
                ["outcome"]["state"],
            "complete"
        );
    }
}

/// ´test:unit:retired-node-evidence-readers-refuse-malformed-present-fields´
#[test]
fn retired_node_evidence_readers_refuse_malformed_present_fields() {
    let (home, mut request, runner) = fixture(3000, true, "success");
    request.dry_run = false;
    let result = execute(home.path(), &request, &runner).expect("retire");
    let path = Path::new(result["retirement"]["record"].as_str().expect("record"));
    let record = read_reservation(path).expect("read").expect("record");
    for (pointer, replacement) in [
        ("/node_retirement/outcome/owed", json!(true)),
        ("/node_retirement/outcome/host_wall_seconds", json!(-1)),
        ("/node_retirement/outcome/host_wall_seconds", Value::Null),
        ("/node_retirement/outcome/evidence/bytes_freed", json!(1)),
        (
            "/node_retirement/outcome/evidence/before/0/entries",
            json!(0),
        ),
        (
            "/node_retirement/outcome",
            json!({"state":"unmeasured","reason":"node-retirement-no-registration","owed":false,"host_wall_seconds":0.0,"helper_exit":null,"remote_completion":"unknown","evidence":null}),
        ),
        (
            "/node_retirement/outcome/evidence/after/0/path",
            json!("/another/lanes/R"),
        ),
        ("/node_retirement/plan/paths/0", json!("~/other/R")),
        ("/node_retirement/attempts", json!([{}])),
    ] {
        let mut malformed = record.clone();
        *malformed.pointer_mut(pointer).expect("field") = replacement;
        publish_reservation(path, &malformed).expect("fixture mutation");
        assert_eq!(
            read_reservation(path)
                .expect_err("shared reader refuses")
                .kind,
            "retire-node-record"
        );
        assert_eq!(
            super::super::census::run(home.path(), "alpha")
                .expect_err("census refuses")
                .kind,
            "census-record"
        );
        request.node = true;
        request.dry_run = true;
        assert_eq!(
            execute(home.path(), &request, &runner)
                .expect_err("completion refuses")
                .kind,
            "retire-node-record"
        );
    }
}

/// ´test:unit:retire-node-and-preview-digest-command-forms´
#[test]
fn retire_node_and_preview_digest_command_forms() {
    for node in [false, true] {
        let mut words = vec!["alpha".to_owned(), "R".to_owned()];
        if node {
            words.push("--node".into());
        }
        words.extend(["--expect-digest".into(), "a".repeat(64)]);
        let parsed = RetireRequest::parse(&words).expect("digest form");
        assert_eq!(parsed.node, node);
        assert_eq!(parsed.expect_digest, Some("a".repeat(64)));
    }
    for words in [
        vec!["alpha", "R", "--node", "--confirm-uncertain"],
        vec!["alpha", "R", "--expect-digest", "bad"],
        vec!["alpha", "--generations", "--node"],
    ] {
        assert_eq!(
            RetireRequest::parse(&words.into_iter().map(str::to_owned).collect::<Vec<_>>())
                .expect_err("invalid form")
                .kind,
            "retire-usage"
        );
    }
}

fn full_conversion(home: &Path, args: &[String]) -> Result<Value, LaneError> {
    let mut full = args.to_vec();
    full.push("--full-plan".into());
    node_rewrite::run(home, &full)
}
