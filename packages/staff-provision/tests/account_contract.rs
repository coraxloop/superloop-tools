use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::process::Command;

/// ´test:integration:account-check-pins-first-contact-without-writing-trust´
#[test]
fn account_check_pins_first_contact_without_writing_trust() {
    let fixture = tempfile::tempdir().expect("fixture");
    let home = fixture.path().join("home");
    fs::create_dir(&home).expect("home");
    let hosts = home.join("known_hosts");
    fs::write(&hosts, "fixture pinned-host-key\n").expect("pinned hosts");
    fs::set_permissions(&hosts, fs::Permissions::from_mode(0o400)).expect("read-only hosts");
    let before = fs::metadata(&hosts).expect("metadata");
    let bin = fixture.path().join("bin");
    fs::create_dir(&bin).expect("bin");
    let ssh = bin.join("ssh");
    fs::write(
        &ssh,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CALL\"\nexit 255\n",
    )
    .expect("ssh fixture");
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).expect("executable");
    let call = fixture.path().join("call");
    let output = Command::new(env!("CARGO_BIN_EXE_account"))
        .args(["check", "--server", "fixture", "alpha"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", &bin)
        .env("SUPERLOOP_ACCOUNT_KNOWN_HOSTS", &hosts)
        .env("CALL", &call)
        .output()
        .expect("account check");
    assert!(
        !output.status.success(),
        "failed first contact must remain a failure"
    );
    let argv = fs::read_to_string(call).expect("SSH invoked");
    for option in [
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "ControlMaster=no",
        "ControlPath=none",
        "GlobalKnownHostsFile=/dev/null",
        "PermitLocalCommand=no",
        "KnownHostsCommand=none",
    ] {
        assert!(
            argv.lines().any(|line| line == option),
            "missing {option}: {argv}"
        );
    }
    assert!(
        argv.lines()
            .any(|line| line == format!("UserKnownHostsFile={}", hosts.display()))
    );
    let after = fs::metadata(&hosts).expect("metadata");
    assert_eq!(
        (
            before.ino(),
            before.mode(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (after.ino(), after.mode(), after.mtime(), after.mtime_nsec())
    );
    assert_eq!(
        fs::read(&hosts).expect("hosts"),
        b"fixture pinned-host-key\n"
    );
    assert!(!home.join(".ssh").exists());
}
