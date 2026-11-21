use super::*;
use crate::policy::DoorMode;

fn execution(words: &[&str]) -> Execution {
    Execution::Argv {
        words: words.iter().map(|w| w.as_bytes().to_vec()).collect(),
    }
}
fn fixture() -> (Envelope, Grant, QuickPolicy, Blacklist) {
    let execution = execution(&["cargo", "test", "--locked"]);
    let policy = QuickPolicy {
        revision: "quick-1".into(),
        rules: vec![QuickRule {
            id: "locked-test".into(),
            execution: execution.clone(),
            path: "/usr/bin".into(),
            programs: vec!["/usr/bin/cargo".into()],
            env_additions: vec![],
            workspace_operands: vec![],
        }],
    };
    let blacklist = Blacklist {
        revision: "black-1".into(),
        entries: vec![],
    };
    let grant = Grant {
        schema: 1,
        loop_name: "example".into(),
        run: "R".into(),
        node: "node-fingerprint".into(),
        workspace: "/work/R".into(),
        baseline_env: vec![("PATH".into(), "/usr/bin".into())],
        resources: BTreeMap::new(),
        shells: vec!["/bin/sh".into()],
        quick_policy_digest: canonical_digest(&policy).unwrap(),
        blacklist_digest: canonical_digest(&blacklist).unwrap(),
        executor_protocol: 1,
    };
    let envelope = Envelope {
        schema: 3,
        grant_digest: grant.digest().unwrap(),
        cwd: vec!["checkout".into()],
        execution,
        env_additions: vec![],
        deadline_ms: 1000,
    };
    (envelope, grant, policy, blacklist)
}
fn rebind(e: &mut Envelope, g: &mut Grant, p: &QuickPolicy, b: &Blacklist) {
    g.quick_policy_digest = canonical_digest(p).unwrap();
    g.blacklist_digest = canonical_digest(b).unwrap();
    e.grant_digest = g.digest().unwrap();
}
fn is_miss(e: &Envelope, g: &Grant, p: &QuickPolicy, b: &Blacklist) {
    assert!(matches!(
        classify(e, g, p, b).unwrap(),
        Classification::Miss { .. }
    ));
}

/// ´test:unit:workspace-envelope-exact-bounds-and-encoding´
#[test]
fn workspace_envelope_exact_bounds_and_encoding() {
    let (e, _, _, _) = fixture();
    assert_eq!(Envelope::decode(json!(e)).unwrap(), e);
    for (key, value) in [
        ("schema", json!(2)),
        ("cwd", json!([".."])),
        ("cwd", json!([""])),
        ("cwd", json!(["."])),
        ("cwd", json!(["/work/R2"])),
        ("deadline_ms", json!(0)),
        ("extra", json!(true)),
    ] {
        let mut row = json!(e);
        row[key] = value;
        assert_eq!(
            Envelope::decode(row).unwrap_err().kind,
            "door-workspace-protocol-refusal"
        );
    }
    for words in [
        vec![],
        vec![vec![b'x']; 257],
        vec![vec![0]],
        vec![vec![b'x'; 65_537]],
    ] {
        let mut bad = e.clone();
        bad.execution = Execution::Argv { words };
        assert_eq!(
            bad.validate().unwrap_err().kind,
            "door-workspace-protocol-refusal"
        );
    }
    let mut bound = e.clone();
    bound.execution = Execution::Argv {
        words: vec![vec![b'x'; 65_536]],
    };
    bound.validate().unwrap();
    let mut sequence = e.clone();
    sequence.execution = Execution::Sequence {
        steps: vec![vec![b"x".to_vec()]; 8],
    };
    sequence.validate().unwrap();
    if let Execution::Sequence { steps } = &mut sequence.execution {
        steps.push(vec![b"x".to_vec()]);
    }
    assert_eq!(
        sequence.validate().unwrap_err().kind,
        "door-workspace-protocol-refusal"
    );
    let mut duplicate_env = e.clone();
    duplicate_env.env_additions = vec![("X".into(), "1".into()), ("X".into(), "2".into())];
    duplicate_env.validate().unwrap();
    duplicate_env
        .env_additions
        .push(("X=invalid".into(), "value".into()));
    assert_eq!(
        duplicate_env.validate().unwrap_err().kind,
        "door-workspace-protocol-refusal"
    );
    let mut bad = json!(e);
    bad["execution"] = json!({"kind":"Shell","shell":"/bin/sh","text":[255]});
    assert_eq!(
        Envelope::decode(bad).unwrap_err().kind,
        "door-workspace-protocol-refusal"
    );
}
/// ´test:unit:workspace-quick-misses-never-deny´
#[test]
fn workspace_quick_misses_never_deny() {
    let (mut e, g, p, b) = fixture();
    assert!(matches!(
        classify(&e, &g, &p, &b).unwrap(),
        Classification::QuickAllow(_)
    ));
    for words in [
        &["unknown", "test"][..],
        &["cargo", "test"][..],
        &["cargo", "test", "--locked", "extra"][..],
    ] {
        e.execution = execution(words);
        is_miss(&e, &g, &p, &b);
    }
    let forged = json!({"id":"x","execution":e.execution,"path":"/usr/bin","programs":["/usr/bin/cargo"],"env_additions":[],"workspace_operands":[],"deny":true});
    assert!(serde_json::from_value::<QuickRule>(forged).is_err());
}
/// ´test:unit:workspace-shell-never-quick-and-blacklist-is-published´
#[test]
fn workspace_shell_never_quick_and_blacklist_is_published() {
    let (mut e, mut g, mut p, mut b) = fixture();
    e.execution = Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf '%s' 'quoted text'".into(),
    };
    p.rules[0].execution = e.execution.clone();
    rebind(&mut e, &mut g, &p, &b);
    is_miss(&e, &g, &p, &b);
    b.entries.push(BlacklistEntry {
        id: "published-shell".into(),
        execution_digest: canonical_digest(&e.execution).unwrap(),
        reason: "owner policy".into(),
    });
    assert_eq!(
        classify(&e, &g, &p, &b).unwrap_err().kind,
        "door-workspace-context-differs"
    );
    rebind(&mut e, &mut g, &p, &b);
    let Classification::Deny(denial) = classify(&e, &g, &p, &b).unwrap() else {
        panic!("published blacklist must block");
    };
    assert_eq!(
        denial.evidence(),
        json!({"blacklist_rule":"published-shell","revision":"black-1","reason":"owner policy"})
    );
    let deny = Classification::Deny(denial);
    let key = learned_key("compute", &e, &g, &p.revision).unwrap();
    for mode in [DoorMode::Allow, DoorMode::Audit, DoorMode::Enforce] {
        assert_eq!(
            disposition(mode, &deny, &e, &g, &p.revision, Some(&key)).unwrap(),
            Disposition::Block
        );
    }
}
/// ´test:unit:workspace-path-operands-and-env-miss-without-blacklist´
#[test]
fn workspace_path_operands_and_env_miss_without_blacklist() {
    let (mut e, mut g, mut p, b) = fixture();
    for (path, allowed) in [
        ("target", true),
        ("/work/R/target", true),
        ("/work/R2/target", false),
        ("../other", false),
    ] {
        e.execution = execution(&["cargo", "test", "--locked", "--target-dir", path]);
        p.rules[0].execution = e.execution.clone();
        p.rules[0].workspace_operands = vec![(0, 4)];
        rebind(&mut e, &mut g, &p, &b);
        assert_eq!(
            matches!(
                classify(&e, &g, &p, &b).unwrap(),
                Classification::QuickAllow(_)
            ),
            allowed
        );
        if !allowed {
            is_miss(&e, &g, &p, &b);
        }
    }
    let (mut e, mut g, mut p, b) = fixture();
    p.rules[0].programs[0] = "/foreign/cargo".into();
    rebind(&mut e, &mut g, &p, &b);
    is_miss(&e, &g, &p, &b);
    let (mut e, mut g, mut p, b) = fixture();
    e.env_additions = vec![("EXTRA".into(), "value".into())];
    p.rules[0].env_additions = e.env_additions.clone();
    rebind(&mut e, &mut g, &p, &b);
    assert!(matches!(
        classify(&e, &g, &p, &b).unwrap(),
        Classification::QuickAllow(_)
    ));
    for path in ["", "bin", ".:/usr/bin"] {
        let (mut e, mut g, mut p, b) = fixture();
        g.baseline_env[0].1 = path.into();
        p.rules[0].path = path.into();
        rebind(&mut e, &mut g, &p, &b);
        is_miss(&e, &g, &p, &b);
        e.execution = execution(&["/usr/bin/cargo", "test", "--locked"]);
        p.rules[0].execution = e.execution.clone();
        rebind(&mut e, &mut g, &p, &b);
        assert!(matches!(
            classify(&e, &g, &p, &b).unwrap(),
            Classification::QuickAllow(_)
        ));
    }
    let (mut repeated, grant, policy, blacklist) = fixture();
    repeated.env_additions = vec![
        ("name-with-dash".into(), "one".into()),
        ("name-with-dash".into(), "two".into()),
    ];
    repeated.validate().unwrap();
    is_miss(&repeated, &grant, &policy, &blacklist);
    let (mut e, g, p, b) = fixture();
    e.env_additions.push(("EXTRA".into(), "value".into()));
    is_miss(&e, &g, &p, &b);
    let (e, mut g, p, b) = fixture();
    g.baseline_env[0].1 = "/other/bin".into();
    let mut e = e;
    e.grant_digest = g.digest().unwrap();
    is_miss(&e, &g, &p, &b);
}
/// ´test:unit:workspace-clean-then-build-is-an-exact-sequence´
#[test]
fn workspace_clean_then_build_is_an_exact_sequence() {
    let (mut e, mut g, mut p, b) = fixture();
    let clean = vec![
        b"git".to_vec(),
        b"clean".to_vec(),
        b"--".to_vec(),
        b"scratch".to_vec(),
    ];
    let build = vec![b"cargo".to_vec(), b"test".to_vec(), b"--locked".to_vec()];
    e.execution = Execution::Sequence {
        steps: vec![clean.clone(), build.clone()],
    };
    p.rules[0].execution = e.execution.clone();
    p.rules[0].programs = vec!["/usr/bin/git".into(), "/usr/bin/cargo".into()];
    p.rules[0].workspace_operands = vec![(0, 3)];
    rebind(&mut e, &mut g, &p, &b);
    assert!(matches!(
        classify(&e, &g, &p, &b).unwrap(),
        Classification::QuickAllow(_)
    ));
    for execution in [
        Execution::Sequence {
            steps: vec![build.clone()],
        },
        Execution::Sequence {
            steps: vec![build, clean],
        },
        Execution::Shell {
            shell: "/bin/sh".into(),
            text: "git clean -- scratch || cargo test --locked".into(),
        },
    ] {
        e.execution = execution;
        is_miss(&e, &g, &p, &b);
    }
}
/// ´test:unit:workspace-identity-refusals-precede-classification´
#[test]
fn workspace_identity_refusals_precede_classification() {
    let (e, g, _, _) = fixture();
    admit(&e, Some(&g), "example", "R", "node-fingerprint").unwrap();
    assert_eq!(
        admit(&e, None, "example", "R", "node-fingerprint")
            .unwrap_err()
            .kind,
        "door-workspace-unregistered"
    );
    for (l, r, n) in [
        ("other", "R", "node-fingerprint"),
        ("example", "S", "node-fingerprint"),
        ("example", "R", "foreign"),
    ] {
        assert_eq!(
            admit(&e, Some(&g), l, r, n).unwrap_err().kind,
            "door-workspace-context-differs"
        );
    }
    let mut bad = e;
    bad.execution = Execution::Shell {
        shell: "/bin/foreign".into(),
        text: "true".into(),
    };
    assert_eq!(
        admit(&bad, Some(&g), "example", "R", "node-fingerprint")
            .unwrap_err()
            .kind,
        "door-workspace-protocol-refusal"
    );
}
/// ´test:unit:workspace-learned-context-and-mode-do-not-import-legacy-labels´
#[test]
fn workspace_learned_context_and_mode_do_not_import_legacy_labels() {
    let (e, g, p, b) = fixture();
    let key = learned_key("compute", &e, &g, &p.revision).unwrap();
    let miss = Classification::Miss {
        reasons: vec!["unknown command".into()],
    };
    let old = json!(["compute", "compute", "compute:cargo test"]);
    for mode in [DoorMode::Allow, DoorMode::Audit, DoorMode::Enforce] {
        assert_eq!(
            disposition(mode, &miss, &e, &g, &p.revision, None).unwrap(),
            Disposition::WaitForJudgement
        );
        assert_eq!(
            disposition(mode, &miss, &e, &g, &p.revision, Some(&old)).unwrap(),
            Disposition::WaitForJudgement
        );
    }
    assert_eq!(
        disposition(DoorMode::Allow, &miss, &e, &g, &p.revision, Some(&key)).unwrap(),
        Disposition::Immediate
    );
    assert_eq!(
        disposition(
            DoorMode::Allow,
            &classify(&e, &g, &p, &b).unwrap(),
            &e,
            &g,
            &p.revision,
            None
        )
        .unwrap(),
        Disposition::Immediate
    );
    for slot in 0..8 {
        let (mut e, mut g, _, _) = fixture();
        let mut revision = p.revision.clone();
        let mut class = "compute";
        match slot {
            0 => e.cwd.push("more".into()),
            1 => e.execution = execution(&["cargo", "test"]),
            2 => e.env_additions.push(("X".into(), "1".into())),
            3 => {
                g.workspace = "/work/S".into();
                e.grant_digest = g.digest().unwrap();
            }
            4 => revision = "quick-2".into(),
            5 => {
                g.quick_policy_digest = "d".repeat(64);
                e.grant_digest = g.digest().unwrap();
            }
            6 => {
                g.blacklist_digest = "e".repeat(64);
                e.grant_digest = g.digest().unwrap();
            }
            _ => class = "foreign",
        }
        assert_ne!(
            learned_key(class, &e, &g, &revision).unwrap(),
            key,
            "context component {slot}"
        );
    }
}
/// ´test:unit:workspace-agent-input-is-lossless-and-flags-code-points´
#[test]
fn workspace_agent_input_is_lossless_and_flags_code_points() {
    let (mut e, g, _, _) = fixture();
    e.execution = Execution::Argv {
        words: vec![
            b"program".to_vec(),
            vec![255, 254],
            "a\u{2028}\u{2029}\u{202e}\n\u{200b}".as_bytes().to_vec(),
        ],
    };
    let input = agent_input(&e, &g, &["unknown".into()]).unwrap();
    assert_eq!(input["execution"], json!(e.execution));
    assert_eq!(input["execution"]["words"][1], json!([255, 254]));
    assert_eq!(input["flagged_code_points"].as_array().unwrap().len(), 5);
    assert!(input["flagged_code_points"].to_string().contains("U+2028"));
    assert!(input["flagged_code_points"].to_string().contains("U+2029"));
    e.execution = Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf '\u{2066}x\u{2069}'".into(),
    };
    let input = agent_input(&e, &g, &[]).unwrap();
    assert_eq!(input["execution"], json!(e.execution));
    assert_eq!(input["flagged_code_points"].as_array().unwrap().len(), 2);
}
/// ´test:unit:workspace-agent-input-pairs-readable-execution-with-exact-bytes´
#[test]
fn workspace_agent_input_pairs_readable_execution_with_exact_bytes() {
    let (mut envelope, grant, _, _) = fixture();
    envelope.execution = Execution::Sequence {
        steps: vec![
            vec![b"/usr/bin/printf".to_vec(), b"hello\nworld".to_vec()],
            vec![b"/usr/bin/cat".to_vec(), vec![255, b'x']],
        ],
    };
    let input = agent_input(&envelope, &grant, &["no rule".into()]).unwrap();
    assert_eq!(input["execution"], json!(envelope.execution));
    assert_eq!(input["execution"]["steps"][1][1], json!([255, 120]));
    assert_eq!(
        input["execution_readable_display_only"]["steps"][0][1],
        "hello\\nworld"
    );
    assert_eq!(input["miss_reasons"], json!(["no rule"]));
    envelope.execution = Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf hello\u{2028}world".into(),
    };
    let input = agent_input(&envelope, &grant, &[]).unwrap();
    assert_eq!(input["execution"], json!(envelope.execution));
    assert_eq!(input["execution_readable_display_only"]["kind"], "shell");
    assert_eq!(input["flagged_code_points"][0]["code_point"], "U+2028");
    assert_eq!(input["flagged_code_points"][0]["field"], "execution.text");
}
/// ´test:unit:workspace-grant-snapshot-binds-every-field´
#[test]
fn workspace_grant_snapshot_binds_every_field() {
    let (_, g, _, _) = fixture();
    let snapshot = json!({"grant":g,"digest":g.digest().unwrap()});
    assert_eq!(
        GrantSnapshot::decode(snapshot.clone(), "example", "R")
            .unwrap()
            .grant,
        g
    );
    let mut bad = snapshot.clone();
    bad["grant"]["workspace"] = json!("/work/R2");
    assert_eq!(
        GrantSnapshot::decode(bad, "example", "R").unwrap_err().kind,
        "door-workspace-context-differs"
    );
    assert!(GrantSnapshot::decode(snapshot, "example", "S").is_err());
    let mut root = g;
    root.workspace = "/".into();
    root.validate().unwrap();
}
/// ´test:unit:workspace-sequence-evidence-stops-and-keeps-unknown-explicit´
#[test]
fn workspace_sequence_evidence_stops_and_keeps_unknown_explicit() {
    let (mut e, g, p, _) = fixture();
    e.execution = Execution::Sequence {
        steps: vec![vec![b"one".to_vec()], vec![b"two".to_vec()]],
    };
    let unknown = Measurement {
        outcome: Outcome::Unknown,
        wall_seconds: None,
        user_cpu_seconds: None,
        system_cpu_seconds: None,
    };
    let mut effect = WorkspaceEffect {
        execution_digest: canonical_digest(&e.execution).unwrap(),
        context_digest: learned_key("compute", &e, &g, &p.revision).unwrap()[2]
            .as_str()
            .unwrap()
            .into(),
        envelope: e,
        grant: g,
        policy_revision: p.revision,
        blacklist_revision: "black-1".into(),
        result: unknown,
        admission_wall_seconds: None,
        steps: vec![],
    };
    WorkspaceEffect::decode(json!(effect), "compute", "example", "R").unwrap();
    let failed = Measurement {
        outcome: Outcome::Exited { code: 2 },
        wall_seconds: Some(0.2),
        user_cpu_seconds: Some(0.1),
        system_cpu_seconds: None,
    };
    effect.result = failed.clone();
    effect.steps = vec![failed.clone()];
    WorkspaceEffect::decode(json!(effect), "compute", "example", "R").unwrap();
    effect.steps.push(failed);
    assert_eq!(
        WorkspaceEffect::decode(json!(effect), "compute", "example", "R")
            .unwrap_err()
            .kind,
        "door-workspace-protocol-refusal"
    );
}

/// ´test:unit:workspace-sequence-one-deadline-and-stop-contract´
#[test]
fn workspace_sequence_one_deadline_and_stop_contract() {
    let (mut e, _, _, _) = fixture();
    e.execution = Execution::Sequence {
        steps: vec![vec![b"one".to_vec()], vec![b"two".to_vec()]],
    };
    let mut m = Measurement {
        outcome: Outcome::Exited { code: 0 },
        wall_seconds: Some(0.1),
        user_cpu_seconds: None,
        system_cpu_seconds: None,
    };
    assert_eq!(e.next_step(&[], 0), Some(0));
    assert_eq!(e.next_step(&[m.clone()], 100), Some(1));
    assert_eq!(e.next_step(&[m.clone()], 1000), None);
    for outcome in [
        Outcome::Exited { code: 1 },
        Outcome::Signalled { signal: 15 },
        Outcome::TimedOut,
        Outcome::Unknown,
    ] {
        m.outcome = outcome;
        assert_eq!(e.next_step(&[m.clone()], 100), None);
    }
}
/// ´test:unit:workspace-wire-decoder-refuses-lossy-and-duplicate-fields´
#[test]
fn workspace_wire_decoder_refuses_lossy_and_duplicate_fields() {
    let (e, _, _, _) = fixture();
    let bytes = serde_json::to_vec(&e).unwrap();
    assert_eq!(Envelope::from_bytes(&bytes).unwrap(), e);
    let mut duplicate = bytes.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"schema\":3}");
    assert_eq!(
        Envelope::from_bytes(&duplicate).unwrap_err().kind,
        "door-workspace-protocol-refusal"
    );
    let mut invalid = bytes;
    invalid[0] = 255;
    assert_eq!(
        Envelope::from_bytes(&invalid).unwrap_err().kind,
        "door-workspace-protocol-refusal"
    );
}

/// ´test:unit:workspace-sequence-timeout-retains-a-successful-prefix´
#[test]
fn workspace_sequence_timeout_retains_a_successful_prefix() {
    let (mut e, g, p, _) = fixture();
    e.execution = Execution::Sequence {
        steps: vec![vec![b"one".to_vec()], vec![b"two".to_vec()]],
    };
    let success = Measurement {
        outcome: Outcome::Exited { code: 0 },
        wall_seconds: Some(0.1),
        user_cpu_seconds: Some(0.0),
        system_cpu_seconds: None,
    };
    let timed_out = Measurement {
        outcome: Outcome::TimedOut,
        wall_seconds: Some(0.2),
        user_cpu_seconds: None,
        system_cpu_seconds: None,
    };
    let mut effect = WorkspaceEffect {
        execution_digest: canonical_digest(&e.execution).unwrap(),
        context_digest: learned_key("compute", &e, &g, &p.revision).unwrap()[2]
            .as_str()
            .unwrap()
            .into(),
        envelope: e,
        grant: g,
        policy_revision: p.revision,
        blacklist_revision: "black-1".into(),
        result: timed_out,
        admission_wall_seconds: Some(0.1),
        steps: vec![],
    };
    for prefix in [vec![], vec![success.clone()]] {
        effect.steps = prefix;
        assert_eq!(
            effect
                .envelope
                .next_step(&effect.steps, effect.envelope.deadline_ms),
            None
        );
        assert_eq!(
            WorkspaceEffect::decode(json!(effect), "compute", "example", "R").unwrap(),
            effect
        );
    }
    for mutation in 0..5 {
        let mut bad = effect.clone();
        match mutation {
            0 => bad.steps.push(success.clone()),
            1 => bad.steps[0].outcome = Outcome::Exited { code: 1 },
            2 => bad.steps[0].outcome = Outcome::Unknown,
            3 => bad.result.wall_seconds = None,
            _ => {
                bad.steps.clear();
                bad.result.outcome = Outcome::Exited { code: 0 };
            }
        }
        assert!(
            WorkspaceEffect::decode(json!(bad), "compute", "example", "R").is_err(),
            "mutation {mutation}"
        );
    }
}

/// ´test:unit:workspace-quick-evidence-cannot-be-replayed-for-another-context´
#[test]
fn workspace_quick_evidence_cannot_be_replayed_for_another_context() {
    let (e, g, p, b) = fixture();
    let allow = classify(&e, &g, &p, &b).unwrap();
    let Classification::QuickAllow(evidence) = &allow else {
        panic!("positive control");
    };
    assert_eq!(evidence.evidence()["rule"], p.rules[0].id);
    assert_eq!(
        disposition(DoorMode::Allow, &allow, &e, &g, &p.revision, None).unwrap(),
        Disposition::Immediate
    );
    for mutation in 0..5 {
        let mut changed = e.clone();
        let mut grant = g.clone();
        let mut revision = p.revision.clone();
        match mutation {
            0 => changed.cwd.push("other".into()),
            1 => changed.env_additions.push(("X".into(), "1".into())),
            2 => changed.execution = execution(&["other"]),
            3 => {
                grant.workspace = "/other".into();
                changed.grant_digest = grant.digest().unwrap();
            }
            _ => revision.push_str("-next"),
        }
        assert_eq!(
            disposition(DoorMode::Allow, &allow, &changed, &grant, &revision, None)
                .unwrap_err()
                .kind,
            "door-workspace-context-differs",
            "mutation {mutation}"
        );
    }
}
/// ´test:unit:workspace-canonical-digest-has-a-known-answer´
#[test]
fn workspace_canonical_digest_has_a_known_answer() {
    // SHA-256 probe of compact UTF-8 {"a":[{"c":3,"d":4},2],"z":1}.
    let value: Value = serde_json::from_str(r#"{"z":1,"a":[{"d":4,"c":3},2]}"#).unwrap();
    assert_eq!(
        canonical_digest(&value).unwrap(),
        "c52fa640e0203480d46869c34fd45289aaae10b217ddf945cd6ff2217458801d"
    );
    let reordered: Value = serde_json::from_str(r#"{"a":[{"c":3,"d":4},2],"z":1}"#).unwrap();
    assert_eq!(
        canonical_digest(&value).unwrap(),
        canonical_digest(&reordered).unwrap()
    );
}
