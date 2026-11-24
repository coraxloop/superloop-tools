use super::*;
use execute_command::workspace::{
    Blacklist, Classification, Grant, QuickPolicy, QuickRule, WorkspaceEffect, canonical_digest,
    classify, learned_key,
};
use serde_json::json;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

struct Fixture {
    root: tempfile::TempDir,
    grant: Grant,
    identity: crate::placement::RootIdentity,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("work");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("sub")).unwrap();
        let mut grant =
            Grant::decode(crate::plan::fixture_workspace_snapshot()["grant"].clone()).unwrap();
        grant.workspace = workspace.to_str().unwrap().into();
        grant.baseline_env = vec![("PATH".into(), "/usr/bin".into())];
        grant.shells = vec!["/bin/sh".into()];
        let identity = crate::placement::read_identity(&File::open(&workspace).unwrap()).unwrap();
        Self {
            root,
            grant,
            identity,
        }
    }
    fn envelope(&self, execution: Execution) -> Envelope {
        Envelope {
            schema: 3,
            grant_digest: self.grant.digest().unwrap(),
            cwd: vec!["sub".into()],
            execution,
            env_additions: vec![],
            deadline_ms: 10_000,
        }
    }
    fn record(&self) -> Value {
        json!({"loop":self.grant.loop_name,"run":self.grant.run,"plan":{
            "loop":self.grant.loop_name,"run":self.grant.run,
            "compute_workspace":{"grant":self.grant,"digest":self.grant.digest().unwrap()},
            "compute_placement":{"schema":1,"placement":"1".repeat(32),"loop":self.grant.loop_name,
            "run":self.grant.run,"node":self.grant.node,"grant_digest":self.grant.digest().unwrap(),
            "mode":"own-path","root":self.grant.workspace,"root_identity":self.identity,"seed":null}}})
    }
    fn prepare(&self, envelope: &Envelope) -> PreparedExecution {
        PreparedExecution::from_reservation(&self.record(), &self.grant.node, envelope).unwrap()
    }
    fn run(&self, prepared: PreparedExecution) -> (ExecutionMeasurements, Vec<u8>, Vec<u8>) {
        self.run_with_cancel(prepared, &AtomicBool::new(false))
    }
    fn run_with_cancel(
        &self,
        prepared: PreparedExecution,
        cancel: &AtomicBool,
    ) -> (ExecutionMeasurements, Vec<u8>, Vec<u8>) {
        let out = self.root.path().join("stdout");
        let err = self.root.path().join("stderr");
        let result = prepared.run_admitted(
            &File::create(&out).unwrap(),
            &File::create(&err).unwrap(),
            cancel,
        );
        (result, fs::read(out).unwrap(), fs::read(err).unwrap())
    }
    fn reader(&self, envelope: &Envelope, measured: &ExecutionMeasurements) {
        let key = learned_key("compute", envelope, &self.grant, "fixture-policy").unwrap();
        let value = json!({"envelope":envelope,"grant":self.grant,
            "policy_revision":"fixture-policy","blacklist_revision":"fixture-blacklist",
            "execution_digest":canonical_digest(&envelope.execution).unwrap(),"context_digest":key[2],
            "result":measured.result,"admission_wall_seconds":null,"steps":measured.steps});
        WorkspaceEffect::decode(value, "compute", &self.grant.loop_name, &self.grant.run)
            .expect("landed reader accepts executor evidence without new members");
    }
}
fn words(values: &[&str]) -> Vec<Vec<u8>> {
    values.iter().map(|v| v.as_bytes().to_vec()).collect()
}
fn shell(text: &str) -> Execution {
    Execution::Shell {
        shell: "/bin/sh".into(),
        text: text.into(),
    }
}

/// ´test:unit:workspace-executor-exact-argv-environment-and-path´
#[test]
fn workspace_executor_exact_argv_environment_and_path() {
    let mut f = Fixture::new();
    let execution = Execution::Argv {
        words: vec![
            b"printf".to_vec(),
            b"%s".to_vec(),
            b"\xff $(touch forbidden); quoted".to_vec(),
        ],
    };
    let policy = QuickPolicy {
        revision: "fixture-policy".into(),
        rules: vec![QuickRule {
            id: "literal".into(),
            execution: execution.clone(),
            path: "/usr/bin".into(),
            programs: vec!["/usr/bin/printf".into()],
            env_additions: vec![],
            workspace_operands: vec![],
        }],
    };
    let blacklist = Blacklist {
        revision: "fixture-blacklist".into(),
        entries: vec![],
    };
    f.grant.quick_policy_digest = canonical_digest(&policy).unwrap();
    f.grant.blacklist_digest = canonical_digest(&blacklist).unwrap();
    let envelope = f.envelope(execution);
    assert!(matches!(
        classify(&envelope, &f.grant, &policy, &blacklist).unwrap(),
        Classification::QuickAllow(_)
    ));
    let (measured, out, err) = f.run(f.prepare(&envelope));
    assert_eq!(out, b"\xff $(touch forbidden); quoted");
    assert_eq!(err, [] as [u8; 0]);
    assert!(!Path::new(&f.grant.workspace).join("sub/forbidden").exists());
    assert_eq!(measured.result.outcome, Outcome::Exited { code: 0 });
    f.reader(&envelope, &measured);
    let mut changed = envelope.clone();
    changed
        .env_additions
        .push(("PATH".into(), "/different".into()));
    assert!(matches!(
        classify(&changed, &f.grant, &policy, &blacklist).unwrap(),
        Classification::Miss { .. }
    ));
    let mut changed = envelope;
    changed.env_additions.push(("EXTRA".into(), "value".into()));
    assert!(matches!(
        classify(&changed, &f.grant, &policy, &blacklist).unwrap(),
        Classification::Miss { .. }
    ));
    let mut envelope = f.envelope(Execution::Argv {
        words: words(&["/usr/bin/env", "-0"]),
    });
    envelope.env_additions = vec![
        ("TEST_VALUE".into(), "first".into()),
        ("TEST_VALUE".into(), "last".into()),
    ];
    let (measured, out, _) = f.run(f.prepare(&envelope));
    let mut rows: Vec<_> = out.split(|b| *b == 0).filter(|v| !v.is_empty()).collect();
    rows.sort_unstable();
    assert!(
        rows == vec![b"PATH=/usr/bin".as_slice(), b"TEST_VALUE=last".as_slice()],
        "child environment differs from the two public declared entries"
    );
    f.reader(&envelope, &measured);
}

/// ´test:unit:workspace-executor-retains-cwd-and-never-provisions´
#[test]
fn workspace_executor_retains_cwd_and_never_provisions() {
    let f = Fixture::new();
    let envelope = f.envelope(Execution::Argv {
        words: words(&["/usr/bin/cat", "marker"]),
    });
    fs::write(
        Path::new(&f.grant.workspace).join("sub/marker"),
        b"retained",
    )
    .unwrap();
    let prepared = f.prepare(&envelope);
    fs::rename(&f.grant.workspace, f.root.path().join("old")).unwrap();
    fs::create_dir_all(Path::new(&f.grant.workspace).join("sub")).unwrap();
    fs::write(
        Path::new(&f.grant.workspace).join("sub/marker"),
        b"replacement",
    )
    .unwrap();
    let (measured, out, _) = f.run(prepared);
    assert_eq!(out, b"retained");
    f.reader(&envelope, &measured);
    fs::remove_dir_all(&f.grant.workspace).unwrap();
    assert!(PreparedExecution::from_reservation(&f.record(), &f.grant.node, &envelope).is_err());
    assert!(!Path::new(&f.grant.workspace).exists());
    symlink(f.root.path().join("old"), &f.grant.workspace).unwrap();
    assert!(PreparedExecution::from_reservation(&f.record(), &f.grant.node, &envelope).is_err());
    fs::remove_file(&f.grant.workspace).unwrap();
    fs::create_dir(&f.grant.workspace).unwrap();
    symlink(
        f.root.path().join("old/sub"),
        Path::new(&f.grant.workspace).join("sub"),
    )
    .unwrap();
    assert!(PreparedExecution::from_reservation(&f.record(), &f.grant.node, &envelope).is_err());
}

/// ´test:unit:workspace-executor-refuses-stale-or-foreign-context´
#[test]
fn workspace_executor_refuses_stale_or_foreign_context() {
    let f = Fixture::new();
    let envelope = f.envelope(shell("exit 0"));
    assert!(PreparedExecution::from_reservation(&f.record(), &f.grant.node, &envelope).is_ok());
    assert_eq!(
        PreparedExecution::from_reservation(&f.record(), "other-node", &envelope)
            .err()
            .unwrap()
            .kind,
        "door-workspace-context-differs"
    );
    let mut foreign = f.record();
    foreign["run"] = json!("other-run");
    assert_eq!(
        PreparedExecution::from_reservation(&foreign, &f.grant.node, &envelope)
            .err()
            .unwrap()
            .kind,
        "door-workspace-context-differs"
    );
    let mut changed = f.grant.clone();
    changed.quick_policy_digest = "c".repeat(64);
    let mut foreign = f.record();
    foreign["plan"]["compute_workspace"] =
        json!({"grant":changed,"digest":changed.digest().unwrap()});
    assert_eq!(
        PreparedExecution::from_reservation(&foreign, &f.grant.node, &envelope)
            .err()
            .unwrap()
            .kind,
        "door-workspace-context-differs"
    );
    let mut record = f.record();
    record["plan"]
        .as_object_mut()
        .unwrap()
        .remove("compute_workspace");
    let error = PreparedExecution::from_reservation(&record, &f.grant.node, &envelope)
        .err()
        .unwrap();
    assert_eq!(error.kind, "door-workspace-context-differs");
    record["plan"]
        .as_object_mut()
        .unwrap()
        .remove("compute_placement");
    assert_eq!(
        PreparedExecution::from_reservation(&record, &f.grant.node, &envelope)
            .err()
            .unwrap()
            .kind,
        "door-workspace-unregistered"
    );
    let mut record = f.record();
    record["plan"]["compute_workspace"]["grant"]["workspace"] = json!("/other");
    assert_eq!(
        PreparedExecution::from_reservation(&record, &f.grant.node, &envelope)
            .err()
            .unwrap()
            .kind,
        "door-workspace-context-differs"
    );
    let sibling = f.root.path().join("work-neighbour");
    fs::create_dir(&sibling).unwrap();
    let mut prefix = envelope.clone();
    prefix.cwd = vec![sibling.to_str().unwrap().into()];
    assert_eq!(
        PreparedExecution::from_reservation(&f.record(), &f.grant.node, &prefix)
            .err()
            .unwrap()
            .kind,
        "door-workspace-protocol-refusal"
    );
    let mut invalid = envelope;
    invalid.cwd = vec!["..".into()];
    assert_eq!(
        PreparedExecution::from_reservation(&f.record(), &f.grant.node, &invalid)
            .err()
            .unwrap()
            .kind,
        "door-workspace-protocol-refusal"
    );
}

/// ´test:unit:workspace-executor-does-not-recheck-shell-declaration´
#[test]
fn workspace_executor_does_not_recheck_shell_declaration() {
    let mut alternate = Fixture::new();
    alternate.grant.shells.clear();
    let undeclared = alternate.envelope(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "exit 0".into(),
    });
    let (measured, _, _) = alternate.run(alternate.prepare(&undeclared));
    assert_eq!(measured.result.outcome, Outcome::Exited { code: 0 });
}

/// ´test:unit:workspace-executor-sequence-stops-with-explicit-unknown´
#[test]
fn workspace_executor_sequence_stops_with_explicit_unknown() {
    let f = Fixture::new();
    let success = f.envelope(Execution::Sequence {
        steps: vec![
            words(&["/bin/sh", "-c", "printf first"]),
            words(&["/bin/sh", "-c", "printf second"]),
        ],
    });
    let (measured, out, _) = f.run(f.prepare(&success));
    assert_eq!(out, b"firstsecond");
    assert_eq!(measured.steps.len(), 2);
    assert_eq!(measured.result.outcome, Outcome::Exited { code: 0 });
    f.reader(&success, &measured);
    for (second, outcome) in [
        (
            words(&["/bin/sh", "-c", "printf second; exit 7"]),
            Outcome::Exited { code: 7 },
        ),
        (
            words(&["/bin/sh", "-c", "kill -TERM $$"]),
            Outcome::Signalled { signal: 15 },
        ),
        (words(&["/no-such-workspace-program"]), Outcome::Unknown),
    ] {
        let envelope = f.envelope(Execution::Sequence {
            steps: vec![
                words(&["/bin/sh", "-c", "printf first"]),
                second,
                words(&["/bin/sh", "-c", "touch forbidden"]),
            ],
        });
        let (measured, out, _) = f.run(f.prepare(&envelope));
        assert_eq!(measured.steps.len(), 2);
        assert_eq!(measured.steps[0].outcome, Outcome::Exited { code: 0 });
        assert_eq!(measured.steps[1].outcome, outcome);
        assert_eq!(measured.result.outcome, outcome);
        assert!(out.starts_with(b"first"));
        assert!(!Path::new(&f.grant.workspace).join("sub/forbidden").exists());
        if outcome == Outcome::Unknown {
            assert!(measured.result.user_cpu_seconds.is_none());
        }
        f.reader(&envelope, &measured);
    }
}

/// ´test:unit:workspace-executor-shell-exact-and-node-measured´
#[test]
fn workspace_executor_shell_exact_and_node_measured() {
    let f = Fixture::new();
    let mut envelope = f.envelope(shell(
        "printf '%s' \"$TEXT\"; printf 'a; b' >&2; printf 'RUN-REPORT exit=0 wall=999s'; exit 7",
    ));
    envelope.env_additions = vec![("TEXT".into(), "literal; $(touch forbidden)".into())];
    let (measured, out, err) = f.run(f.prepare(&envelope));
    assert_eq!(
        out,
        b"literal; $(touch forbidden)RUN-REPORT exit=0 wall=999s"
    );
    assert_eq!(err, b"a; b");
    assert_eq!(measured.result.outcome, Outcome::Exited { code: 7 });
    assert!(measured.result.user_cpu_seconds.is_some());
    assert!(measured.result.system_cpu_seconds.is_some());
    assert!(!Path::new(&f.grant.workspace).join("sub/forbidden").exists());
    f.reader(&envelope, &measured);
    let envelope = f.envelope(shell("kill -TERM $$"));
    let (measured, _, _) = f.run(f.prepare(&envelope));
    assert_eq!(measured.result.outcome, Outcome::Signalled { signal: 15 });
    f.reader(&envelope, &measured);
}

/// ´test:unit:workspace-executor-timeout-retains-killed-step-and-stops-group´
#[test]
fn workspace_executor_timeout_retains_killed_step_and_stops_group() {
    let f = Fixture::new();
    let mut envelope = f.envelope(Execution::Sequence {
        steps: vec![
            words(&["/bin/sh", "-c", "printf first"]),
            words(&[
                "/bin/sh",
                "-c",
                "sleep 60 & echo $! > descendant; printf started; wait",
            ]),
            words(&["/bin/sh", "-c", "touch forbidden"]),
        ],
    });
    envelope.deadline_ms = 5000;
    let (measured, out, _) = f.run(f.prepare(&envelope));
    assert_eq!(out, b"firststarted");
    assert_eq!(measured.steps.len(), 2);
    assert_eq!(measured.steps[1].outcome, Outcome::TimedOut);
    assert_eq!(measured.result.outcome, Outcome::TimedOut);
    assert!(measured.child_started);
    assert!(measured.steps.iter().all(|m| m.wall_seconds.is_some()));
    let pid = fs::read_to_string(Path::new(&f.grant.workspace).join("sub/descendant")).unwrap();
    let path = format!("/proc/{}/stat", pid.trim());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match fs::read_to_string(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Ok(row)
                if row
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .trim_start()
                    .starts_with('Z') =>
            {
                break;
            }
            _ => assert!(Instant::now() < deadline, "descendant still executing"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!Path::new(&f.grant.workspace).join("sub/forbidden").exists());
    f.reader(&envelope, &measured);
}

/// ´test:unit:workspace-executor-expiry-before-and-between-steps´
#[test]
fn workspace_executor_expiry_before_and_between_steps() {
    let f = Fixture::new();
    let envelope = f.envelope(Execution::Sequence {
        steps: vec![
            words(&["/bin/sh", "-c", "printf first"]),
            words(&["/bin/sh", "-c", "printf second"]),
        ],
    });
    let mut prepared = f.prepare(&envelope);
    prepared.deadline = Instant::now();
    let (measured, out, _) = f.run(prepared);
    assert_eq!(out, [] as [u8; 0]);
    assert_eq!(measured.steps, [] as [Measurement; 0]);
    assert_eq!(measured.result.outcome, Outcome::TimedOut);
    assert!(!measured.child_started);
    f.reader(&envelope, &measured);
    let mut prepared = f.prepare(&envelope);
    prepared.after_step = Some(|p, _| p.deadline = Instant::now());
    let (measured, out, _) = f.run(prepared);
    assert_eq!(out, b"first");
    assert_eq!(measured.steps.len(), 1);
    assert_eq!(measured.steps[0].outcome, Outcome::Exited { code: 0 });
    assert_eq!(measured.result.outcome, Outcome::TimedOut);
    f.reader(&envelope, &measured);
}

/// ´test:unit:workspace-executor-caller-cancellation-revokes-budget´
#[test]
fn workspace_executor_caller_cancellation_revokes_budget() {
    let f = Fixture::new();
    let envelope = f.envelope(Execution::Sequence {
        steps: vec![
            words(&["/bin/sh", "-c", "printf started; touch ready; sleep 60"]),
            words(&["/bin/sh", "-c", "touch forbidden"]),
        ],
    });
    let cancelled = AtomicBool::new(true);
    let (measured, out, _) = f.run_with_cancel(f.prepare(&envelope), &cancelled);
    assert_eq!(out, [] as [u8; 0]);
    assert_eq!(measured.steps, [] as [Measurement; 0]);
    assert_eq!(measured.result.outcome, Outcome::TimedOut);
    f.reader(&envelope, &measured);
    cancelled.store(false, Ordering::Release);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let ready = Path::new(&f.grant.workspace).join("sub/ready");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            cancelled.store(true, Ordering::Release);
            assert!(ready.exists(), "child reached cancellation witness");
        });
        let (measured, out, _) = f.run_with_cancel(f.prepare(&envelope), &cancelled);
        assert_eq!(out, b"started");
        assert_eq!(measured.steps.len(), 1);
        assert_eq!(measured.steps[0].outcome, Outcome::TimedOut);
        assert_eq!(measured.result.outcome, Outcome::TimedOut);
        assert!(measured.child_started);
        assert!(!Path::new(&f.grant.workspace).join("sub/forbidden").exists());
        f.reader(&envelope, &measured);
    });
}

/// ´test:unit:workspace-quiet-child-carries-start-evidence´
#[test]
fn workspace_quiet_child_carries_start_evidence() {
    let f = Fixture::new();
    let envelope = f.envelope(Execution::Argv {
        words: words(&["/bin/sh", "-c", "touch ready; exec sleep 60"]),
    });
    let cancelled = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let ready = Path::new(&f.grant.workspace).join("sub/ready");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            cancelled.store(true, Ordering::Release);
            assert!(ready.exists(), "quiet child reached cancellation witness");
        });
        let (measured, out, err) = f.run_with_cancel(f.prepare(&envelope), &cancelled);
        assert!(measured.child_started);
        assert_eq!(measured.steps, [] as [Measurement; 0]);
        assert!(out.is_empty() && err.is_empty());
        assert_eq!(measured.result.outcome, Outcome::TimedOut);
    });
}

/// ´test:unit:workspace-executor-binds-placement-before-cwd-or-spawn´
#[test]
fn workspace_executor_binds_placement_before_cwd_or_spawn() {
    let f = Fixture::new();
    let envelope = f.envelope(shell("touch forbidden"));
    let record = f.record();
    PreparedExecution::from_reservation(&record, &f.grant.node, &envelope).unwrap();
    let mut missing = record.clone();
    missing["plan"]
        .as_object_mut()
        .unwrap()
        .remove("compute_placement");
    fs::remove_dir(Path::new(&f.grant.workspace).join("sub")).unwrap();
    let error = PreparedExecution::from_reservation(&missing, &f.grant.node, &envelope)
        .err()
        .unwrap();
    assert_eq!(error.kind, "door-workspace-context-differs");
    assert_eq!(error.detail, "workspace placement is required");
    fs::remove_dir(&f.grant.workspace).unwrap();
    fs::create_dir(&f.grant.workspace).unwrap();
    let error = PreparedExecution::from_reservation(&record, &f.grant.node, &envelope)
        .err()
        .unwrap();
    assert_eq!(error.detail, "placement root identity differs");
    assert!(!Path::new(&f.grant.workspace).join("forbidden").exists());
}
