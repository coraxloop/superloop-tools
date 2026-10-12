use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

///
/// # Panics
/// Panics only if fixture setup fails or the client omits the expected diagnostic.
/// ´test:integration:configuration-failures-name-the-resolved-input´
#[test]
fn configuration_failures_name_the_resolved_input() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    let keys = root.path().join("keys");
    fs::write(&config, "Host alpha-loop\n").unwrap();
    fs::write(&keys, "fixture\n").unwrap();
    for (nodes, path, expected) in [
        ("alpha-loop", keys, "alias=alpha-loop-loop"),
        ("alpha", root.path().join("missing-keys"), "known-hosts="),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-node-status"))
            .args(["loop", "--ssh-config"])
            .arg(&config)
            .arg("--known-hosts")
            .arg(&path)
            .env("NODES", nodes)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("NODE-STATUS-FAILED configuration"));
        assert!(error.contains(expected));
        assert!(error.contains(if nodes == "alpha" {
            path.to_str().unwrap()
        } else {
            config.to_str().unwrap()
        }));
        assert!(String::from_utf8_lossy(&output.stdout).contains("NODE-STATUS-DURATION-MS"));
    }
}

/// # Panics
/// Panics only if fixture setup fails or the client misreports signal termination.
/// ´test:integration:transport-signal-is-reported-without-an-exit-code´
#[test]
fn transport_signal_is_reported_without_an_exit_code() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    let keys = root.path().join("keys");
    fs::write(&config, "Host alpha-loop\n").unwrap();
    fs::write(&keys, "fixture\n").unwrap();
    let wrapper = root.path().join("timeout");
    fs::write(&wrapper, "#!/bin/sh\nkill -TERM $$\n").unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-node-status"))
        .args(["loop", "--ssh-config"])
        .arg(&config)
        .arg("--known-hosts")
        .arg(&keys)
        .env("NODES", "alpha")
        .env("PATH", format!("{}:/usr/bin:/bin", root.path().display()))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("transport alias=alpha-loop ssh_signal=15"));
    assert!(!error.contains("ssh_exit="));
}

/// ´test:integration:load-comparison-first-contact-and-duration´
#[test]
fn load_comparison_first_contact_and_duration() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    let keys = root.path().join("keys");
    fs::write(&config, "Host alpha-* beta-*\n HostName fixture.invalid\n").unwrap();
    fs::write(&keys, "fixture key\n").unwrap();
    let script = root.path().join("ssh");
    fs::write(&script, r"#!/usr/bin/env python3
import os, sys, time
a=sys.argv
for option in ['StrictHostKeyChecking=yes','UpdateHostKeys=no','GlobalKnownHostsFile=/dev/null','KnownHostsCommand=none','ControlPath=none']:
    assert option in a
assert any(v.startswith('UserKnownHostsFile=') for v in a)
mode=os.environ.get('MODE','normal')
if mode=='deadline': time.sleep(5)
if mode.startswith('wrapper'): sys.exit(int(mode[7:]))
if mode=='failed' or (mode=='partial' and a[-2].startswith('alpha-')):
    print('earlier detail\nfixture transport failed', file=sys.stderr)
    sys.exit(255)
if mode=='invalid': print('0 nan 1 2')
elif mode=='tie': print('8 4 3 2')
elif a[-2].startswith('alpha-'): print('8 4 3 2')
else: print('16 2 3 4')
").unwrap();
    fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
    for loop_name in ["first", "second", "third"] {
        for (mode, expected) in [
            ("normal", Some("beta")),
            ("single", Some("alpha")),
            ("tie", Some("alpha")),
            ("partial", Some("beta")),
            ("failed", None),
            ("invalid", None),
            ("deadline", None),
            ("wrapper125", None),
            ("wrapper126", None),
            ("wrapper127", None),
            ("wrapper137", None),
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_superloop-node-status"))
                .arg(loop_name)
                .arg("--ssh-config")
                .arg(&config)
                .arg("--known-hosts")
                .arg(&keys)
                .env(
                    "NODES",
                    if mode == "single" {
                        "alpha"
                    } else {
                        "alpha beta"
                    },
                )
                .env("MODE", mode)
                .env(
                    "NODE_STATUS_TIMEOUT_MS",
                    if mode == "deadline" { "100" } else { "8000" },
                )
                .env("HOME", root.path())
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        root.path().display(),
                        std::env::var("PATH").unwrap()
                    ),
                )
                .output()
                .unwrap();
            assert_eq!(output.status.success(), expected.is_some());
            let error = String::from_utf8_lossy(&output.stderr);
            assert_failure(mode, loop_name, &error);
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("NODE-STATUS-DURATION-MS "));
            if let Some(node) = expected {
                assert!(text.contains(&format!("LIGHTER={node}\n")));
            }
            if mode == "normal" {
                assert!(text.contains("alpha cores=8 load=4 3 2 ratio=0.500"));
                assert!(text.contains("beta cores=16 load=2 3 4 ratio=0.125"));
            }
            assert_eq!(fs::read(&keys).unwrap(), b"fixture key\n");
            assert!(!root.path().join(".ssh/known_hosts").exists());
        }
    }
}

fn assert_failure(mode: &str, loop_name: &str, error: &str) {
    if mode == "failed" {
        assert!(error.contains(&format!("transport alias=alpha-{loop_name}")));
        assert!(error.contains("ssh_exit=255"));
        assert!(!error.contains("exit status:"));
        assert!(error.contains("stderr_last=\"fixture transport failed\""));
        assert!(!error.contains("earlier detail"));
    }
    if mode == "deadline" || mode == "wrapper137" {
        assert!(error.contains("deadline_ms="));
        assert!(error.contains(" expired"));
        assert!(!error.contains("ssh_exit="));
    } else if let Some(code) = mode.strip_prefix("wrapper") {
        assert!(error.contains(&format!("wrapper_exit={code}")));
        assert!(!error.contains("ssh_exit="));
    }
    if mode == "invalid" {
        assert!(error.contains(&format!("load alias=alpha-{loop_name}")));
        assert!(error.contains("0 nan 1 2"));
    }
}
