use super::*;
use crate::launch::{
    keeper::release::tests::{captured, evidence, setup},
    measure::Admission,
    sealer::{Completion, Exit},
    startup::RootStartup,
    store::Store,
    tests::Fixture,
};
use std::fs;
use std::os::{
    fd::AsRawFd as _,
    unix::fs::{MetadataExt as _, PermissionsExt as _},
};

fn field(f: &Fixture, key: &str, value: &str) {
    let path = f.dir.path().join("manager-reply");
    let text = fs::read_to_string(&path).unwrap();
    let text = text
        .lines()
        .map(|line| {
            if line.split_once('=').unwrap().0 == key {
                format!("{key}={value}")
            } else {
                line.into()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(path, text).unwrap();
}
fn terminal_reply(f: &Fixture, status: i32) {
    for (key, value) in [
        ("MainPID", "0"),
        ("ActiveState", if status == 0 { "active" } else { "failed" }),
        ("SubState", if status == 0 { "exited" } else { "failed" }),
        ("ExecMainCode", "1"),
        ("ExecMainExitTimestampMonotonic", "200"),
        ("Result", if status == 0 { "success" } else { "exit-code" }),
    ] {
        field(f, key, value);
    }
    field(f, "ExecMainStatus", &status.to_string());
}
fn released(f: &Fixture, admission: &Admission, keeper: &mut Keeper<'_>) -> i32 {
    let mut child = captured(f, admission, keeper);
    let digest = keeper.inventory().unwrap();
    let exit = keeper.process.as_ref().unwrap().duplicate().unwrap();
    keeper.release(&digest).unwrap();
    let mut event = nix::libc::pollfd {
        fd: exit.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    crate::launch::channel::poll(std::slice::from_mut(&mut event), 600_000).unwrap();
    assert_ne!(event.revents & nix::libc::POLLIN, 0);
    child.child.wait().unwrap().code().unwrap()
}
fn retained(f: &Fixture) -> serde_json::Value {
    assert!(evidence(f).join("state-07.json").is_file());
    serde_json::from_slice(&fs::read(evidence(f).join("state-07.json")).unwrap()).unwrap()
}
fn observe_keeper(f: &Fixture, keeper: &mut Keeper<'_>) {
    use crate::launch::control::completion_client::{Binding, Observation, receive};
    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("runtime/sample/control-manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["schema"], 2);
    assert_eq!(manifest["policy_sha256"], keeper.admission.policy_sha256());
    assert_eq!(manifest["case_sha256"], keeper.admission.cases()[0].sha256);
    assert_eq!(
        manifest["captured"],
        serde_json::to_value(keeper.process.as_ref().unwrap().invocation()).unwrap()
    );
    let mut request = manifest.clone();
    request.as_object_mut().unwrap().remove("image");
    request.as_object_mut().unwrap().remove("socket");
    request["schema"] = 1.into();
    for key in ["policy_sha256", "case_sha256", "captured"] {
        request.as_object_mut().unwrap().remove(key);
    }
    request["operation"] = "completion".into();
    request["nonce"] = "0123456789abcdef0123456789abcdef".into();
    let mut bytes = serde_json::to_vec(&request).unwrap();
    bytes.push(b'\n');
    let mut command = std::process::Command::new(f.dir.path().join("launcher"));
    command
        .arg("--control-client")
        .arg(f.dir.path().join("runtime/sample/control.sock"))
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let stdout = child.stdout.as_mut().unwrap();
    let mut event = nix::libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    crate::launch::channel::poll(std::slice::from_mut(&mut event), 600_000).unwrap();
    assert_ne!(event.revents & nix::libc::POLLIN, 0);
    let mut ready = [0; 10];
    stdout.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"connected\n");
    keeper.serve_completion(keeper.manager.deadline()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&output.stdout).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    let binding = Binding {
        case: "sample",
        keeper_pid: std::process::id(),
        keeper_birth: manifest["keeper_birth"].as_u64().unwrap(),
        keeper_uid: nix::unistd::geteuid().as_raw(),
        invocation: keeper.process.as_ref().unwrap().invocation(),
        sealed_limit: keeper.admission.policy().limits.sealed_bytes,
    };
    assert_eq!(
        receive(
            &mut reader,
            &binding,
            "0123456789abcdef0123456789abcdef",
            keeper.manager.deadline()
        ),
        Ok(Observation::Complete)
    );
}
fn no_completion(f: &Fixture) {
    assert!(!evidence(f).join("completion.json").exists());
}

/// ´test:unit:completion-retains-an-observation-before-late-expiry-cleanup´
#[test]
fn completion_retains_an_observation_before_late_expiry_cleanup() {
    let _case = crate::launch::test_support::case_guard();
    for failed in [false, true] {
        let f = setup(if failed {
            "fail-after-output"
        } else {
            "normal"
        });
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        let status = released(&f, &admission, &mut keeper);
        assert_eq!(status != 0, failed);
        terminal_reply(&f, status);
        fs::write(f.dir.path().join("manager-require-retained"), b"").unwrap();
        let before = Instant::now();
        let deadline = before + std::time::Duration::from_secs(600);
        let mut instants = [before, deadline].into_iter();
        assert_eq!(
            keeper.capture_generator_with_clock(deadline, || instants.next().unwrap()),
            Err("completion-deadline")
        );
        assert!(evidence(&f).join("state-07.json").is_file());
        let result = retained(&f);
        assert_eq!(result["generator"]["status"], status);
        assert_eq!(result["generator"]["successful"], status == 0);
        assert!(f.dir.path().join("manager-stopped").is_file());
        assert_eq!(keeper.phase(), Phase::Uncertain);
        no_completion(&f);
    }
}

/// ´test:unit:completion-start-identity-is-captured-before-release´
#[test]
fn completion_start_identity_is_captured_before_release() {
    let _case = crate::launch::test_support::case_guard();
    for (key, value) in [
        ("LoadState", "not-found"),
        ("ConditionResult", "no"),
        ("AssertResult", "no"),
        ("ExecMainPID", "1"),
        ("ExecMainStartTimestampMonotonic", "0"),
        ("ExecMainExitTimestampMonotonic", "200"),
    ] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        fs::set_permissions(
            f.dir.path().join("public.json"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        keeper.submit().unwrap();
        let writers = keeper
            .pipes
            .paths()
            .each_ref()
            .map(|p| fs::OpenOptions::new().append(true).open(p).unwrap());
        let (child, _pin) = crate::launch::inventory::tests::start(&f, &writers);
        let text = String::from_utf8(crate::launch::manager::tests::reply(&admission))
            .unwrap()
            .replace("MainPID=123", &format!("MainPID={}", child.child.id()));
        fs::write(f.dir.path().join("manager-reply"), text).unwrap();
        field(&f, key, value);
        assert_eq!(
            keeper.capture_with(
                |_| Ok(writers.each_ref().map(|f| f.try_clone().unwrap())),
                crate::launch::control::Control::test_bind
            ),
            Err("keeper-execution"),
            "{key}"
        );
        assert_eq!(keeper.phase(), Phase::Uncertain);
        no_completion(&f);
    }
}

/// ´test:unit:completion-compares-captured-configuration-identity´
#[test]
fn completion_compares_captured_configuration_identity() {
    let _case = crate::launch::test_support::case_guard();
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    released(&f, &admission, &mut keeper);
    terminal_reply(&f, 0);
    keeper.execution.as_mut().unwrap().1 = "0".repeat(64);
    assert_eq!(keeper.capture_generator(), Err("completion-configuration"));
    assert_eq!(keeper.phase(), Phase::Uncertain);
    no_completion(&f);
}

/// ´test:unit:completion-expired-budget-never-publishes-success´
#[test]
fn completion_expired_budget_never_publishes_success() {
    let _case = crate::launch::test_support::case_guard();
    for finish in [false, true] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        released(&f, &admission, &mut keeper);
        terminal_reply(&f, 0);
        if finish {
            keeper.capture_generator().unwrap();
            assert_eq!(
                keeper.finish_completion_at(Instant::now()),
                Err("completion-deadline")
            );
        } else {
            assert_eq!(
                keeper.capture_generator_at(Instant::now()),
                Err("completion-deadline")
            );
        }
        assert_eq!(keeper.phase(), Phase::Uncertain);
        no_completion(&f);
    }
}

/// ´test:unit:completion-retains-before-cleanup-and-accepts-only-two-sealers´
#[test]
fn completion_retains_before_cleanup_and_accepts_only_two_sealers() {
    let _case = crate::launch::test_support::case_guard();
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    assert_eq!(released(&f, &admission, &mut keeper), 0);
    // Kernel exit arrived first; the manager's complete starting reply is late.
    assert_eq!(keeper.capture_generator(), Ok(false));
    assert_eq!(keeper.phase(), Phase::Released);
    assert_eq!(keeper.finish_completion(), Err("completion-order"));
    assert!(!evidence(&f).join("state-07.json").exists());
    no_completion(&f);
    terminal_reply(&f, 0);
    fs::write(f.dir.path().join("manager-require-retained"), b"").unwrap();
    fs::write(f.dir.path().join("manager-unload-after-stop"), b"").unwrap();
    assert_eq!(keeper.capture_generator(), Ok(true));
    assert!(!f.dir.path().join("manager-stopped").exists());
    let generator = retained(&f);
    assert_eq!(generator["generator"]["successful"], true);
    assert_eq!(generator["generator"]["started"], 100);
    assert_eq!(generator["generator"]["exited"], 200);
    keeper.finish_completion().unwrap();
    assert_eq!(keeper.phase(), Phase::Complete);
    observe_keeper(&f, &mut keeper);
    assert!(!f.dir.path().join("manager-reply").exists()); // cleanup can unload the unit
    assert_eq!(keeper.finish_completion(), Err("completion-order"));
    let path = evidence(&f).join("completion.json");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o400);
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(receipt["phase"], "complete");
    assert_eq!(receipt["generator"], generator["generator"]);
    assert_eq!(receipt["sealers"]["eof"], serde_json::json!([true, true]));
    assert_eq!(
        receipt["sealers"]["exits"],
        serde_json::json!([{"Code":0},{"Code":0}])
    );
    for name in ["left.sealed", "right.sealed"] {
        assert_eq!(
            fs::metadata(f.dir.path().join("sealed/sample").join(name))
                .unwrap()
                .mode()
                & 0o7777,
            0o400
        );
    }
}

/// ´test:unit:completion-terminal-metadata-refusals-latch´
#[test]
fn completion_terminal_metadata_refusals_latch() {
    let _case = crate::launch::test_support::case_guard();
    for (key, value, class) in [
        ("LoadState", "not-found", "completion-unloaded"),
        ("ConditionResult", "no", "completion-condition"),
        ("AssertResult", "no", "completion-assertion"),
        ("ExecMainPID", "1", "completion-execution-binding"),
        (
            "ExecMainStartTimestampMonotonic",
            "0",
            "completion-start-binding",
        ),
        (
            "ExecMainStartTimestampMonotonic",
            "99",
            "completion-start-binding",
        ),
        (
            "ExecMainExitTimestampMonotonic",
            "0",
            "completion-exit-time",
        ),
        (
            "ExecMainExitTimestampMonotonic",
            "99",
            "completion-exit-time",
        ),
        ("ExecMainCode", "0", "completion-exit-code"),
        ("MainPID", "2", "completion-holder"),
        ("ActiveState", "inactive", "completion-holder"),
        ("Result", "unknown", "completion-result"),
        ("ExecMainCode", "", "manager-status"),
        ("ConditionResult", "", "manager-condition"),
        ("ExecMainExitTimestampMonotonic", "", "manager-execution"),
        (
            "InvocationID",
            "00000000000000000000000000000000",
            "manager-invocation-binding",
        ),
        ("NoNewPrivileges", "no", "manager-property-drift"),
    ] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        assert_eq!(released(&f, &admission, &mut keeper), 0);
        terminal_reply(&f, 0);
        field(&f, key, value);
        assert_eq!(keeper.capture_generator(), Err(class), "{key}={value}");
        assert_eq!(keeper.phase(), Phase::Uncertain, "{key}");
        terminal_reply(&f, 0);
        assert_eq!(keeper.capture_generator(), Err("completion-order"));
        no_completion(&f);
    }
}

/// ´test:unit:completion-rejects-stale-success-while-process-is-live´
#[test]
fn completion_rejects_stale_success_while_process_is_live() {
    let _case = crate::launch::test_support::case_guard();
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let _child = captured(&f, &admission, &mut keeper);
    keeper.inventory().unwrap();
    // Inject a released state without continuing: the independently held pidfd
    // must contradict a stale manager success, regardless of the state label.
    keeper
        .session
        .store()
        .advance(Phase::ReleaseIntent)
        .unwrap();
    keeper.session.store().advance(Phase::Released).unwrap();
    terminal_reply(&f, 0);
    assert_eq!(keeper.capture_generator(), Err("completion-process-live"));
    no_completion(&f);
}

/// ´test:unit:completion-retains-full-output-generator-failure´
#[test]
fn completion_retains_full_output_generator_failure() {
    let _case = crate::launch::test_support::case_guard();
    let f = setup("fail-after-output");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let status = released(&f, &admission, &mut keeper);
    assert_ne!(status, 0);
    // Both real sealers have consumed the complete fixture output successfully.
    let result = keeper
        .session
        .wait_until(keeper.manager.deadline())
        .unwrap();
    assert_eq!(result.exits, [Exit::Code(0); 2]);
    assert!(result.sealed_bytes.iter().all(|n| *n > 0));
    terminal_reply(&f, status);
    assert_eq!(
        keeper.capture_generator(),
        Err("completion-generator-failed")
    );
    assert_eq!(retained(&f)["generator"]["status"], status);
    assert_eq!(retained(&f)["generator"]["successful"], false);
    assert_eq!(retained(&f)["generator"]["result"], "exit-code");
    assert_eq!(keeper.phase(), Phase::Uncertain);
    no_completion(&f);
}

/// ´test:unit:completion-missing-events-and-disconnect-never-recover´
#[test]
fn completion_missing_events_and_disconnect_never_recover() {
    let _case = crate::launch::test_support::case_guard();
    for missing in [true, false] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        released(&f, &admission, &mut keeper);
        terminal_reply(&f, 0);
        let path = f.dir.path().join("manager-reply");
        let text = fs::read_to_string(&path).unwrap();
        if missing {
            fs::write(
                &path,
                text.lines()
                    .filter(|l| !l.starts_with("ExecMainCode="))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            )
            .unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        assert_eq!(
            keeper.capture_generator(),
            Err(if missing {
                "manager-reply-shape"
            } else {
                "child-failed"
            })
        );
        fs::write(path, text).unwrap();
        assert_eq!(keeper.capture_generator(), Err("completion-order"));
        no_completion(&f);
    }
}

/// ´test:unit:completion-publication-and-stop-failure-stay-uncertain´
#[test]
fn completion_publication_and_stop_failure_stay_uncertain() {
    let _case = crate::launch::test_support::case_guard();
    for fault in ["retention", "stop", "publication"] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        released(&f, &admission, &mut keeper);
        terminal_reply(&f, 0);
        if fault == "retention" {
            fs::write(evidence(&f).join("state-07.json"), b"occupied").unwrap();
            fs::write(f.dir.path().join("manager-require-retained"), b"").unwrap();
            assert_eq!(keeper.capture_generator(), Err("receipt-no-replace"));
            assert!(!f.dir.path().join("manager-stopped").exists());
        } else {
            keeper.capture_generator().unwrap();
            if fault == "stop" {
                fs::write(f.dir.path().join("manager-stop-output"), b"unexpected").unwrap();
            } else {
                fs::write(evidence(&f).join("completion.json"), b"occupied").unwrap();
            }
            let result = keeper.finish_completion();
            if fault == "stop" {
                assert_eq!(result, Err("manager-stop-output"));
            } else {
                assert_eq!(result, Err("receipt-no-replace"));
                assert_eq!(
                    fs::read(evidence(&f).join("completion.json")).unwrap(),
                    b"occupied"
                );
            }
        }
        assert_eq!(keeper.phase(), Phase::Uncertain, "{fault}");
        assert_eq!(keeper.finish_completion(), Err("completion-order"));
        if fault != "publication" {
            no_completion(&f);
        }
    }
}

/// ´test:unit:completion-sealer-evidence-requires-every-eof-and-exit´
#[test]
fn completion_sealer_evidence_requires_every_eof_and_exit() {
    let _case = crate::launch::test_support::case_guard();
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    released(&f, &admission, &mut keeper);
    terminal_reply(&f, 0);
    keeper.capture_generator().unwrap();
    keeper.stop_holder().unwrap();
    keeper
        .session
        .store()
        .advance(Phase::HolderReleased)
        .unwrap();
    for index in 0..2 {
        let mut result = Completion {
            sealed_bytes: [4; 2],
            eof: [true; 2],
            exits: [Exit::Code(0); 2],
        };
        result.eof[index] = false;
        assert_eq!(
            keeper.session.store().retain_sealers(result),
            Err("completion-sealers")
        );
        let mut result = Completion {
            sealed_bytes: [4; 2],
            eof: [true; 2],
            exits: [Exit::Code(0); 2],
        };
        result.exits[index] = Exit::Code(7);
        assert_eq!(
            keeper.session.store().retain_sealers(result),
            Err("completion-sealers")
        );
    }
    no_completion(&f);
}
