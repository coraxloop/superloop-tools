use super::*;
use crate::launch::tests::Fixture;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
fn fixture() -> Fixture {
    let mut f = Fixture::new();
    add_images(&mut f);
    f
}
pub(in crate::launch) fn add_images(f: &mut Fixture) {
    let current = std::env::current_exe().unwrap();
    let image = current
        .ancestors()
        .take(8)
        .map(|p| p.join("examples/custody-manager-test"))
        .find(|p| p.is_file())
        .unwrap();
    let bytes = fs::read(image).unwrap();
    for (name, role) in [
        ("manager-start", "manager-start"),
        ("manager-query", "manager-query"),
    ] {
        let path = f.dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        f.value["artifacts"].as_array_mut().unwrap().push(
            serde_json::json!({"id":name,"role":role,"path":path,"expected_sha256":hash(&bytes)}),
        );
    }
    f.value["limits"]["diagnostic_bytes"] = 16_384.into();
    f.value["limits"]["artifact_bytes"] = (64 * 1024 * 1024).into();
    f.value["limits"]["case_ms"] = 600_000.into();
    f.value["limits"]["campaign_ms"] = 600_000.into();
}

pub(in crate::launch) fn reply(admission: &Admission) -> Vec<u8> {
    reply_case(admission, 0)
}
pub(in crate::launch) fn reply_case(admission: &Admission, index: usize) -> Vec<u8> {
    let policy = admission.policy();
    let case = &policy.cases[index];
    let mut values = BTreeMap::from([
        ("Id", case.generator_unit.clone()),
        ("InvocationID", "1234567890abcdef1234567890abcdef".into()),
        ("MainPID", "123".into()),
        ("ActiveState", "activating".into()),
        ("SubState", "start".into()),
        ("Result", "success".into()),
        ("ExecMainCode", "0".into()),
        ("ExecMainStatus", "0".into()),
        ("LoadState", "loaded".into()),
        ("ConditionResult", "yes".into()),
        ("AssertResult", "yes".into()),
        ("ExecMainPID", "123".into()),
        ("ExecMainStartTimestampMonotonic", "100".into()),
        ("ExecMainExitTimestampMonotonic", "0".into()),
        ("NoNewPrivileges", "yes".into()),
        ("CapabilityBoundingSet", String::new()),
        ("AmbientCapabilities", String::new()),
        ("ProtectSystem", "strict".into()),
        ("PrivateUsers", "no".into()),
        ("PrivatePIDs", "no".into()),
        ("DynamicUser", "yes".into()),
        ("StandardInput", "null".into()),
        ("StandardOutput", "null".into()),
        ("StandardError", "null".into()),
        ("ReadWritePaths", String::new()),
    ]);
    values.insert(
        "InaccessiblePaths",
        format!(
            "{} {}",
            policy.manager_sockets[0].display(),
            policy.manager_sockets[1].display()
        ),
    );
    for (key, value) in [
        ("Type", "oneshot"),
        ("RemainAfterExit", "yes"),
        ("Slice", "synthetic.slice"),
        ("TimeoutStartUSec", "10min"),
        ("TimeoutStopUSec", "5s"),
        ("KillMode", "control-group"),
        ("SendSIGKILL", "yes"),
    ] {
        values.insert(key, value.into());
    }
    let mut out = values
        .into_iter()
        .fold(String::new(), |mut out, (key, value)| {
            writeln!(out, "{key}={value}").unwrap();
            out
        })
        .into_bytes();
    for (name, stream) in ["left.fifo", "right.fifo"].into_iter().zip(&case.streams) {
        out.extend_from_slice(
            format!(
                "OpenFile={}:{}:append\n",
                policy.roots.runtime.join(&case.id).join(name).display(),
                stream.name
            )
            .as_bytes(),
        );
    }
    out
}
/// ´test:unit:manager-held-cli-uses-closed-vectors-and-empty-child-table´
#[test]
fn manager_held_cli_uses_closed_vectors_and_empty_child_table() {
    let _case = crate::launch::test_support::case_guard();
    let fixture = fixture();
    let admission = fixture.admit();
    let manager = Manager::new(&admission, 0).unwrap();
    let root = &admission.policy().roots.runtime;
    let paths = [
        root.join("sample/left.fifo"),
        root.join("sample/right.fifo"),
    ];
    let ambient = tempfile::tempfile().unwrap();
    nix::fcntl::fcntl(
        &ambient,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    manager.start(&paths).unwrap();
    let args: Vec<String> =
        serde_json::from_slice(&fs::read(fixture.dir.path().join("manager-argv.json")).unwrap())
            .unwrap();
    let expected = expected_start(fixture.dir.path(), &paths);
    assert_eq!(args, expected);
    assert_eq!(
        args.iter()
            .filter(|a| a.starts_with("--property=OpenFile=") && a.ends_with(":append"))
            .count(),
        2
    );
    assert!(args.contains(&"--expand-environment=no".into()));
    assert!(args.contains(&"--remain-after-exit".into()));
    let bytes = reply(&admission);
    fs::write(fixture.dir.path().join("manager-reply"), &bytes).unwrap();
    let snapshot = manager.snapshot(None).unwrap();
    assert_eq!(snapshot.pid, 123);
    assert_eq!(snapshot.raw_sha256, hash(&bytes));
    assert_eq!(snapshot.configuration_sha256.len(), 64);
    assert_eq!(snapshot.active, "activating");
    assert_eq!(snapshot.sub, "start");
    assert_eq!(snapshot.result, "success");
    assert_eq!((snapshot.code, snapshot.status), (0, 0));
    assert_eq!(
        snapshot.properties,
        serde_json::to_vec(&crate::launch::policy::Role::Fixture.properties()).unwrap()
    );
    manager.stop(&snapshot.invocation).unwrap();
    let args: Vec<String> =
        serde_json::from_slice(&fs::read(fixture.dir.path().join("manager-argv.json")).unwrap())
            .unwrap();
    assert_eq!(
        args,
        [
            "--system",
            "stop",
            "--",
            &admission.policy().cases[0].generator_unit
        ]
    );
    assert_eq!(
        manager.stop("ffffffffffffffffffffffffffffffff"),
        Err("manager-invocation-binding")
    );
    let args: Vec<String> =
        serde_json::from_slice(&fs::read(fixture.dir.path().join("manager-argv.json")).unwrap())
            .unwrap();
    assert_eq!(args[1], "show");
    assert_eq!(
        manager.start(&[paths[1].clone(), paths[0].clone()]),
        Err("manager-fifo-binding")
    );
    let other = Fixture::new();
    assert_eq!(
        Manager::new(&other.admit(), 0).err(),
        Some("manager-artifact-roster")
    );
}
/// ´test:unit:manager-reply-requires-complete-invocation-bound-properties´
#[test]
fn manager_reply_requires_complete_invocation_bound_properties() {
    let _case = crate::launch::test_support::case_guard();
    let fixture = fixture();
    let admission = fixture.admit();
    let bytes = reply(&admission);
    let text = String::from_utf8(bytes.clone()).unwrap();
    let unit = &admission.policy().cases[0].generator_unit;
    let sockets = &admission.policy().manager_sockets;
    for key in FIELDS {
        let missing = text
            .lines()
            .filter(|line| !line.starts_with(&format!("{key}=")))
            .fold(String::new(), |mut out, line| {
                writeln!(out, "{line}").unwrap();
                out
            });
        assert_eq!(
            parse(missing.as_bytes(), unit, None, sockets).err(),
            Some("manager-reply-shape"),
            "{key}"
        );
        let line = text
            .lines()
            .find(|l| l.starts_with(&format!("{key}=")))
            .unwrap();
        assert_eq!(
            parse(format!("{text}{line}\n").as_bytes(), unit, None, sockets).err(),
            Some("manager-reply-shape"),
            "{key}"
        );
    }
    for (from, to, class) in [
        ("MainPID=123", "MainPID=bad", "manager-pid"),
        (
            "ActiveState=activating",
            "ActiveState=SECRET BYTES",
            "manager-state",
        ),
        ("ExecMainStatus=0", "ExecMainStatus=999", "manager-status"),
        ("ExecMainCode=0", "ExecMainCode=x", "manager-status"),
        (
            "InvocationID=1234567890abcdef1234567890abcdef",
            "InvocationID=00000000000000000000000000000000",
            "manager-invocation-binding",
        ),
    ] {
        assert_eq!(
            parse(text.replace(from, to).as_bytes(), unit, None, sockets).err(),
            Some(class)
        );
    }
    assert_eq!(
        parse(&bytes, "other.service", None, sockets).err(),
        Some("manager-unit-binding")
    );
    assert_eq!(
        parse(&vec![b'x'; 65537], unit, None, sockets).err(),
        Some("manager-reply-size")
    );
    assert_eq!(
        parse(b"\xff\n", unit, None, sockets).err(),
        Some("manager-reply-shape")
    );
    assert_eq!(
        parse(text.trim_end().as_bytes(), unit, None, sockets).err(),
        Some("manager-reply-shape")
    );
    assert_eq!(
        parse(
            format!("{text}Unknown=no\n").as_bytes(),
            unit,
            None,
            sockets
        )
        .err(),
        Some("manager-reply-shape")
    );
    for key in &FIELDS[14..] {
        let line = text
            .lines()
            .find(|l| l.starts_with(&format!("{key}=")))
            .unwrap();
        assert_eq!(
            parse(
                text.replace(line, &format!("{key}=foreign")).as_bytes(),
                unit,
                None,
                sockets
            )
            .err(),
            Some("manager-property-drift"),
            "{key}"
        );
    }
}

/// ´test:unit:manager-transport-refuses-unexpected-output-and-replaced-image´
#[test]
fn manager_transport_refuses_unexpected_output_and_replaced_image() {
    let _case = crate::launch::test_support::case_guard();
    let fixture = fixture();
    let admission = fixture.admit();
    let manager = Manager::new(&admission, 0).unwrap();
    let root = &admission.policy().roots.runtime;
    let paths = [
        root.join("sample/left.fifo"),
        root.join("sample/right.fifo"),
    ];
    fs::write(
        fixture.dir.path().join("manager-start-output"),
        b"foreign diagnostic",
    )
    .unwrap();
    assert_eq!(manager.start(&paths), Err("manager-start-output"));
    fs::write(fixture.dir.path().join("manager-reply"), reply(&admission)).unwrap();
    fs::write(
        fixture.dir.path().join("manager-stop-output"),
        b"foreign diagnostic",
    )
    .unwrap();
    assert_eq!(
        manager.stop("1234567890abcdef1234567890abcdef"),
        Err("manager-stop-output")
    );
    let query = fixture.dir.path().join("manager-query");
    let other = fixture.dir.path().join("new-query");
    fs::copy(&query, &other).unwrap();
    fs::rename(other, &query).unwrap();
    assert_eq!(
        manager.snapshot(None).err(),
        Some("launch-artifact-changed")
    );
}

/// ´test:unit:manager-deadline-is-one-absolute-case-budget´
#[test]
fn manager_deadline_is_one_absolute_case_budget() {
    let _case = crate::launch::test_support::case_guard();
    let fixture = fixture();
    let admission = fixture.admit();
    let mut manager = Manager::new(&admission, 0).unwrap();
    manager.deadline = Instant::now();
    let root = &admission.policy().roots.runtime;
    assert_eq!(
        manager.start(&[
            root.join("sample/left.fifo"),
            root.join("sample/right.fifo")
        ]),
        Err("manager-deadline")
    );
    assert!(!fixture.dir.path().join("manager-argv.json").exists());
}

fn parse(
    bytes: &[u8],
    unit: &str,
    expected: Option<&str>,
    sockets: &[PathBuf; 2],
) -> Result<Snapshot> {
    let root = sockets[0].parent().unwrap();
    let wire = Expected {
        unit,
        sockets,
        slice: "synthetic.slice",
        case_ms: 600_000,
        openfiles: [
            format!(
                "{}:left:append",
                root.join("runtime/sample/left.fifo").display()
            ),
            format!(
                "{}:right:append",
                root.join("runtime/sample/right.fifo").display()
            ),
        ],
    };
    super::parse(bytes, &wire, expected)
}
/// ´test:unit:manager-open-files-and-service-bounds-are-observed´
#[test]
fn manager_open_files_and_service_bounds_are_observed() {
    let _case = crate::launch::test_support::case_guard();
    let fixture = fixture();
    let admission = fixture.admit();
    let bytes = reply(&admission);
    let text = String::from_utf8(bytes).unwrap();
    let unit = &admission.policy().cases[0].generator_unit;
    let sockets = &admission.policy().manager_sockets;
    let lines: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("OpenFile="))
        .collect();
    for invalid in [
        text.replace(lines[0], lines[1]),
        text.replace(":append", ":read-only"),
        text.replace(&format!("{}\n", lines[0]), ""),
        format!("{text}{}\n", lines[0]),
    ] {
        assert_eq!(
            parse(invalid.as_bytes(), unit, None, sockets).err(),
            Some("manager-open-files")
        );
    }
    for (value, expected) in [
        ("10min", Some(600_000_000)),
        ("1min 2s 3ms 4us", Some(62_003_004)),
        ("infinity", None),
        ("1s 2s", None),
        ("1.5s", None),
        ("", None),
        ("18446744073709551615min", None),
    ] {
        assert_eq!(duration_us(value), expected);
    }
}
/// ´test:unit:manager-version-refuses-before-start-and-cleanup-has-a-budget´
#[test]
fn manager_version_refuses_before_start_and_cleanup_has_a_budget() {
    let _case = crate::launch::test_support::case_guard();
    let fixture = fixture();
    let admission = fixture.admit();
    let mut manager = Manager::new(&admission, 0).unwrap();
    let root = &admission.policy().roots.runtime;
    let paths = [
        root.join("sample/left.fifo"),
        root.join("sample/right.fifo"),
    ];
    fs::write(fixture.dir.path().join("manager-version"), b"256\n").unwrap();
    assert_eq!(manager.start(&paths), Err("manager-version"));
    let args: Vec<String> =
        serde_json::from_slice(&fs::read(fixture.dir.path().join("manager-argv.json")).unwrap())
            .unwrap();
    assert!(!args.contains(&"--no-block".into()));
    fs::remove_file(fixture.dir.path().join("manager-version")).unwrap();
    fs::write(fixture.dir.path().join("manager-reply"), reply(&admission)).unwrap();
    manager.deadline = Instant::now();
    manager.stop("1234567890abcdef1234567890abcdef").unwrap();
}

fn expected_start(base: &std::path::Path, paths: &[PathBuf; 2]) -> Vec<String> {
    let mut expected: Vec<String> = [
        "--system",
        "--no-block",
        "--quiet",
        "--unit=synthetic-sample.service",
        "--service-type=oneshot",
        "--remain-after-exit",
        "--expand-environment=no",
        "--slice=synthetic.slice",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=ProtectSystem=strict",
        "--property=PrivateUsers=no",
        "--property=PrivatePIDs=no",
        "--property=DynamicUser=yes",
        "--property=ReadWritePaths=",
        "--property=TimeoutStopSec=5s",
        "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes",
        "--property=StandardInput=null",
        "--property=StandardOutput=null",
        "--property=StandardError=null",
        "--property=TimeoutStartSec=600000ms",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    expected.extend([
        format!(
            "--property=InaccessiblePaths={} {}",
            base.join("bus.sock").display(),
            base.join("manager.sock").display()
        ),
        format!("--property=OpenFile={}:left:append", paths[0].display()),
        format!("--property=OpenFile={}:right:append", paths[1].display()),
        "--".into(),
        base.join("fixture").display().to_string(),
        "emit".into(),
        "--case-record".into(),
        base.join("public.json").display().to_string(),
    ]);
    expected
}
