use super::*;
use crate::anchor::Record;
use std::io::{Read as _, Seek as _};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn frame(operation: Operation) -> Manifest {
    Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.name().into(),
        loop_name: "alpha".into(),
        records: PURPOSES
            .iter()
            .enumerate()
            .map(|(slot, purpose)| Record {
                purpose: (*purpose).into(),
                slot: u32::try_from(slot).unwrap(),
                kind: if matches!(slot, 0 | 2 | 3) {
                    Kind::Directory
                } else {
                    Kind::File
                },
                device: 1,
                inode: slot as u64 + 1,
                verifier_uid: 1000,
                owner_uid: 1000,
            })
            .collect(),
    }
}

/// ´claim:loophome:door-frame-fixes-local-entry-custody´
/// ´test:unit:door-frame-fixes-roles-per-operation´
#[test]
fn door_frame_fixes_roles_per_operation() {
    for operation in [Operation::Rubric, Operation::Agent, Operation::Metadata] {
        let good = frame(operation);
        operation.check_frame("alpha", &good).unwrap();
        let required = operation
            .requirements(41001, Owner::RootFile, Owner::Host)
            .unwrap();
        let expected = [
            (Kind::Directory, Owner::Host, ModePolicy::Exact(0o700)),
            (Kind::File, Owner::RootFile, ModePolicy::Executable),
            (Kind::Directory, Owner::Host, ModePolicy::Exact(0o711)),
            (
                Kind::Directory,
                Owner::Mapped(41001),
                ModePolicy::Exact(0o700),
            ),
            (Kind::File, Owner::RootFile, ModePolicy::Executable),
            (Kind::File, Owner::Host, ModePolicy::Executable),
            (Kind::File, Owner::Host, ModePolicy::Exact(0o400)),
        ];
        for (index, (kind, owner, mode)) in expected.into_iter().enumerate() {
            assert_eq!(required[index].purpose, PURPOSES[index]);
            assert_eq!(required[index].policy, Policy { kind, owner, mode });
            assert!(required[index].alias_group.is_none());
            let mut bad = good.clone();
            bad.records[index].purpose = "other".into();
            assert!(
                operation.check_frame("alpha", &bad).is_err(),
                "purpose {index}"
            );
            let mut bad = good.clone();
            let other = (index + 1) % PURPOSES.len();
            bad.records[index].slot = u32::try_from(other).unwrap();
            bad.records[other].slot = u32::try_from(index).unwrap();
            assert!(
                operation.check_frame("alpha", &bad).is_err(),
                "slot {index}"
            );
            let mut bad = good.clone();
            bad.records[index].kind = if kind == Kind::File {
                Kind::Directory
            } else {
                Kind::File
            };
            assert!(
                operation.check_frame("alpha", &bad).is_err(),
                "kind {index}"
            );
        }
        let mut unbound = good.clone();
        unbound.loop_name.clear();
        assert!(
            operation.check_frame("", &unbound).is_err(),
            "loop is required"
        );
        let mut bad = good.clone();
        bad.records.pop();
        assert!(operation.check_frame("alpha", &bad).is_err(), "count");
        let mut excess = good.clone();
        let mut extra = good.records[6].clone();
        extra.purpose = "extra".into();
        extra.slot = 7;
        extra.inode = 8;
        excess.records.push(extra);
        assert!(
            operation.check_frame("alpha", &excess).is_err(),
            "excess count"
        );
        assert!(operation.check_frame("beta", &good).is_err(), "loop");
        assert!(
            operation
                .requirements(41001, Owner::Mapped(65534), Owner::Host)
                .is_err()
        );
        assert!(
            operation
                .requirements(41001, Owner::Host, Owner::Mapped(65534))
                .is_err()
        );
    }
}

/// ´claim:loophome:door-operation-comes-from-private-word´
/// ´test:unit:door-operation-comes-from-private-word´
#[test]
fn door_operation_comes_from_private_word() {
    let words = [
        ("_door-rubric", Operation::Rubric),
        ("_door-agent", Operation::Agent),
        ("_door-metadata", Operation::Metadata),
    ];
    for (word, operation) in words {
        assert_eq!(Operation::from_private(word).unwrap(), operation);
        let mut malformed = frame(operation);
        malformed.version = 2;
        let error = operation.check_frame("alpha", &malformed).unwrap_err();
        assert!(
            error
                .message()
                .contains(&format!("operation={}", operation.name()))
        );
        for (_, other) in words {
            let result = operation.check_frame("alpha", &frame(other));
            assert_eq!(
                result.is_ok(),
                operation == other,
                "{word} / {}",
                other.name()
            );
        }
    }
    for word in ["enter", "_serve", "_door-agent-extra", "door-agent", ""] {
        assert!(Operation::from_private(word).is_err(), "{word}");
    }
}

fn raw(bytes: &[u8], mode: u32, wanted: SealFlag, readonly: bool) -> OwnedFd {
    let fd = memfd_create(
        "door-frame-test",
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
    )
    .unwrap();
    let mut file = File::from(fd);
    file.write_all(bytes).unwrap();
    fchmod(&file, Mode::from_bits_truncate(mode)).unwrap();
    fcntl(&file, FcntlArg::F_ADD_SEALS(wanted)).unwrap();
    if readonly {
        File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .unwrap()
            .into()
    } else {
        file.into()
    }
}

/// ´claim:loophome:door-invocation-requires-sealed-readonly-memfd´
/// ´test:unit:door-invocation-requires-sealed-readonly-memfd´
#[test]
fn door_invocation_requires_sealed_readonly_memfd() {
    let operation = Operation::Agent;
    let bytes = b"{\"request\":\"opaque invocation, not a rubric snapshot\"}";
    let verifier = HostVerifier::current()
        .unwrap()
        .for_operation(operation.name());
    let pin = pin_invocation(&verifier, operation, bytes).unwrap();
    assert_eq!(pin.record().slot, 6);
    assert_eq!(pin.record().purpose, "invocation");
    assert_eq!(read_invocation(operation, &pin).unwrap(), bytes);
    let fd = invocation(operation, bytes).unwrap();
    assert!(
        verifier
            .retain_private_file(&fd, "unchanged-private", 0)
            .is_err()
    );
    let writable = raw(bytes, 0o400, seals(), false);
    assert!(
        verifier
            .retain_readonly_file(&writable, "invocation", 6)
            .is_err()
    );
    let private = raw(bytes, 0o600, seals(), true);
    assert!(
        verifier
            .retain_private_file(&private, "unchanged-private", 0)
            .is_ok()
    );
    assert!(
        verifier
            .retain_readonly_file(&private, "invocation", 6)
            .is_err()
    );
    assert_eq!(read_invocation(operation, &fd).unwrap(), bytes);
    assert_eq!(
        read_invocation(operation, &fd).unwrap(),
        bytes,
        "independent of shared offsets"
    );
    for missing in [
        SealFlag::F_SEAL_WRITE,
        SealFlag::F_SEAL_GROW,
        SealFlag::F_SEAL_SHRINK,
        SealFlag::F_SEAL_SEAL,
    ] {
        let fd = raw(bytes, 0o400, seals() & !missing, true);
        assert!(
            read_invocation(operation, &fd).is_err(),
            "missing {missing:?}"
        );
    }
    for (mode, readonly) in [(0o600, true), (0o400, false)] {
        let fd = raw(bytes, mode, seals(), readonly);
        assert!(
            read_invocation(operation, &fd).is_err(),
            "mode {mode:o} readonly {readonly}"
        );
    }
    let boundary = vec![b'x'; INVOCATION_LIMIT];
    assert_eq!(
        read_invocation(operation, &invocation(operation, &boundary).unwrap()).unwrap(),
        boundary
    );
    let too_large = vec![b'x'; INVOCATION_LIMIT + 1];
    assert!(invocation(operation, &too_large).is_err(), "sender bound");
    assert!(
        read_invocation(operation, &raw(&too_large, 0o400, seals(), true)).is_err(),
        "receiver bound"
    );
}

/// ´claim:loophome:door-frame-refuses-registry-override´
/// ´test:unit:door-frame-refuses-registry-override´
#[test]
fn door_frame_refuses_registry_override() {
    if std::env::var_os("LOOP_HOME_DOOR_OVERRIDE_CHILD").is_some() {
        for operation in [Operation::Rubric, Operation::Agent, Operation::Metadata] {
            let error = operation
                .check_frame("alpha", &frame(operation))
                .unwrap_err();
            assert!(
                error.message().contains("purpose=registry-override"),
                "{error}"
            );
        }
        return;
    }
    for value in ["", "/fixture/.config/loops/registry.toml"] {
        let output = override_child(value);
        assert!(output.0.success(), "{output:?}");
        assert!(
            output.1.contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
    }
}

fn override_child(value: &str) -> (std::process::ExitStatus, String) {
    let mut output = File::from(memfd_create("door-frame-output", MFdFlags::MFD_CLOEXEC).unwrap());
    let mut child = Command::new(std::env::current_exe().expect("door frame test executable"))
        .args([
            "--exact",
            "door_frame::tests::door_frame_refuses_registry_override",
            "--nocapture",
        ])
        .env("LOOP_HOME_DOOR_OVERRIDE_CHILD", "1")
        .env("ENTER_LOOP_REGISTRY", value)
        .stdin(Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(output.try_clone().unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("door override child deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    output.rewind().unwrap();
    let mut text = String::new();
    output.take(65_536).read_to_string(&mut text).unwrap();
    (status, text)
}
