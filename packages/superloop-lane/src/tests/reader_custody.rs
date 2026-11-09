//! Private exercise readers retain configuration through the real namespace entry.
use super::{helper_service, runtime_preparation};
use crate::launch::{exercise, reader_entry};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

/// # Panics
/// Panics if the real reader entry reopens replaced configuration or accepts a changed capability.
/// ´claim:superlooplane:private-exercise-readers-retain-configuration´
/// ´test:crate:private-exercise-readers-retain-configuration´
#[test]
fn private_exercise_readers_retain_configuration() {
    runtime_preparation::proof("SUPERLOOP_READER_PROOF", "PRIVATE-READERS-MEASURED");
}

/// # Panics
/// Panics if report or lock reads lose their received custody or named refusals.
/// (´claim:superlooplane:private-reports-retain-received-custody´)
/// ´test:crate:private-reports-retain-received-custody´
#[test]
fn private_reports_retain_received_custody() {
    runtime_preparation::proof("SUPERLOOP_REPORT_PROOF", "PRIVATE-READERS-MEASURED");
}

/// # Panics
/// Panics if harvest or recovery reopens replaced configuration or loses a bundle check.
/// (´claim:superlooplane:harvest-entry-retains-configuration´)
/// ´test:crate:harvest-entry-retains-configuration´
#[test]
fn harvest_entry_retains_configuration() {
    runtime_preparation::proof("SUPERLOOP_HARVEST_PROOF", "PRIVATE-READERS-MEASURED");
}

/// # Panics
/// Panics if import marking loses configuration custody or a named bundle refusal.
/// (´claim:superlooplane:import-entry-retains-configuration´)
/// ´test:crate:import-entry-retains-configuration´
#[test]
fn import_entry_retains_configuration() {
    runtime_preparation::proof("SUPERLOOP_IMPORT_PROOF", "PRIVATE-READERS-MEASURED");
}

/// # Panics
/// Panics if checkpoint custody or its pre-receipt owner-home refusal is lost.
/// (´claim:superlooplane:checkpoint-entry-retains-configuration´)
/// ´test:crate:checkpoint-entry-retains-configuration´
#[test]
fn checkpoint_entry_retains_configuration() {
    runtime_preparation::proof("SUPERLOOP_CHECKPOINT_PROOF", "PRIVATE-READERS-MEASURED");
}

/// # Panics
/// Panics if checkout loses configuration or external destination-parent custody.
/// (´claim:superlooplane:checkout-entry-retains-custody´)
/// ´test:crate:checkout-entry-retains-custody´
#[test]
fn checkout_entry_retains_custody() {
    runtime_preparation::proof("SUPERLOOP_CHECKOUT_PROOF", "PRIVATE-READERS-MEASURED");
}

/// # Panics
/// Panics if the fixture home has no containing temporary directory.
fn checkout_parent(home: &Path) -> std::path::PathBuf {
    home.parent().expect("fixture root").join("destination")
}

fn selected_readers() -> &'static [&'static str] {
    if std::env::var_os("SUPERLOOP_CHECKOUT_PROOF").is_some() {
        &["checkout"]
    } else if std::env::var_os("SUPERLOOP_CHECKPOINT_PROOF").is_some() {
        &["checkpoint"]
    } else if std::env::var_os("SUPERLOOP_IMPORT_PROOF").is_some() {
        &["import"]
    } else if std::env::var_os("SUPERLOOP_REPORT_PROOF").is_some() {
        &["report", "locks"]
    } else if std::env::var_os("SUPERLOOP_HARVEST_PROOF").is_some() {
        &["private-harvest", "harvest-recover"]
    } else {
        &["harvest", "home-layout", "measure", "observed"]
    }
}

/// # Panics
/// Panics if either production reader loses its operation, configuration or reservation binding.
pub(super) fn exercise(home: &Path, runs: &Path, program: &Path) {
    let mut record = helper_service::prepare(home, runs, program);
    let _storage = runtime_preparation::MappedStorage(
        home.to_path_buf(),
        record["plan"]["home"]
            .as_str()
            .expect("worker home")
            .to_owned(),
    );
    record["rounds"] = json!([]);
    let path = runs.join(".reservation-R.json");
    crate::launch::publish_reservation(&path, &record).expect("reader reservation");
    let stat = fs::metadata(&path).expect("record identity");
    let digest = crate::build::sha256_bytes(&fs::read(path).expect("record bytes"), home)
        .expect("record digest");
    let identity = format!("{}:{}:{digest}", stat.dev(), stat.ino());
    // Recorded from Observation::note/publish by the real proxy writer probe.
    let observation = runs.join(".observed-R.txt");
    fs::write(
        &observation,
        "mode=observing run=R enforcing=false\napi.example.com:443 connected=1\n",
    )
    .expect("recorded proxy output");
    fs::set_permissions(observation, fs::Permissions::from_mode(0o600)).expect("observation mode");
    let destination = checkout_parent(home);
    fs::create_dir(&destination).expect("external destination parent");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).expect("parent mode");
    for &kind in selected_readers() {
        if matches!(
            kind,
            "checkout" | "checkpoint" | "private-harvest" | "harvest-recover" | "import"
        ) {
            for name in [".prepare-R.lock", ".letter-R.lock"] {
                let path = runs.join(name);
                fs::write(&path, b"").expect("checkpoint lock");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("checkpoint lock mode");
            }
        }
        for case in [
            "plain",
            "replaced",
            "mode",
            "identity",
            "program-owner",
            "git-owner",
            "parent-identity",
            "parent-mode",
            "ancestor-mode",
            "short-frame",
            "excess-frame",
            "count",
            "surplus-count",
            "operation",
            "record",
            "override",
            "missing",
            "vector",
            "relative-home",
            "source-mode",
            "source-link",
            "source-large",
        ] {
            if (case == "relative-home" && !matches!(kind, "checkpoint" | "checkout"))
                || (matches!(case, "parent-identity" | "parent-mode" | "ancestor-mode")
                    && kind != "checkout")
                || (case == "git-owner"
                    && !matches!(
                        kind,
                        "checkout"
                            | "checkpoint"
                            | "private-harvest"
                            | "import"
                            | "harvest"
                            | "home-layout"
                    ))
            {
                continue;
            }
            if (matches!(
                kind,
                "checkout" | "checkpoint" | "private-harvest" | "harvest-recover" | "import"
            ) && case != "record"
                && !case.starts_with("source-"))
                || (kind == "measure" && case != "record")
                || (kind == "observed" && case != "record" && !case.starts_with("source-"))
                || (matches!(kind, "harvest" | "home-layout" | "report" | "locks")
                    && !case.starts_with("source-"))
            {
                measure(home, runs, &identity, kind, case);
            }
        }
    }
    if std::env::var_os("SUPERLOOP_READER_PROOF").is_some() {
        live_measure(home, runs, &mut record);
        follow_round(home, runs, &mut record);
    }
    if std::env::var_os("SUPERLOOP_CHECKOUT_PROOF").is_some() {
        settled_readers(home, runs, &mut record);
    }
    writeln!(std::io::stdout().lock(), "PRIVATE-READERS-MEASURED").expect("measured marker");
}

/// # Panics
/// Panics if the fixture cannot compose the production descriptor transfer.
fn request(home: &Path, runs: &Path, identity: &str, kind: &str) -> loop_home::CommandSpec {
    let home_fd = fs::File::open(home).expect("home").into();
    let runs_fd = fs::File::open(runs).expect("runs").into();
    let body = if kind == "checkout" {
        crate::launch::checkout::private_checkout_argv(
            &crate::launch::checkout::CheckoutRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                repo: "tools".into(),
                into: checkout_parent(home).join("checkout"),
                dry_run: true,
                invocation_token: None,
            },
            home,
            None,
        )
    } else if kind == "import" {
        crate::launch::imports::private_import_argv(
            &crate::launch::imports::MarkImportedRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                object: "a".repeat(40),
            },
            home,
        )
    } else if matches!(kind, "private-harvest" | "harvest-recover") {
        private_harvest_words(home, kind == "harvest-recover")
    } else if kind == "checkpoint" {
        exercise_checkpoint_words(home)
    } else if kind == "measure" {
        Ok(vec![
            "_exercise-measure".into(),
            "alpha".into(),
            "all".into(),
            "--backend".into(),
            "codex".into(),
            "--owner-home".into(),
            home.display().to_string(),
        ])
    } else if kind == "observed" {
        Ok(vec![
            "_observed-hosts".into(),
            "alpha".into(),
            "R".into(),
            "--owner-home".into(),
            home.display().to_string(),
        ])
    } else if matches!(kind, "follow" | "context") {
        let mut words = crate::launch::follow::private_follow_argv(
            home,
            "alpha",
            "R",
            "dispatch",
            &runs.join("R/dispatch"),
            identity,
        )
        .expect("follow vector");
        if kind == "context" {
            words[0] = "_exercise-context-private".into();
        }
        Ok(words)
    } else if matches!(kind, "report" | "locks") {
        let mut words = vec![
            "_driver-report".into(),
            "alpha".into(),
            "R".into(),
            "--owner-home".into(),
            home.display().to_string(),
            "--expect-record".into(),
            identity.into(),
        ];
        if kind == "locks" {
            words.push("--locks".into());
        }
        Ok(words)
    } else if kind == "harvest" {
        exercise::harvest_private_argv("alpha", "R", identity, home)
    } else {
        exercise::home_layout_private_argv("alpha", "R", identity, home)
    }
    .expect("private vector");
    let mut argv = vec![
        "unshare".into(),
        runtime_preparation::binary().display().to_string(),
    ];
    argv.extend(body);
    let destination = checkout_parent(home);
    let held_destination = fs::File::open(&destination).expect("destination").into();
    reader_entry::command(
        Path::new("/usr/bin/podman"),
        &argv,
        home,
        &home_fd,
        runs,
        &runs_fd,
        (kind == "checkout").then_some((destination.as_path(), &held_destination)),
    )
    .expect("production reader composer")
}

fn exercise_checkpoint_words(home: &Path) -> Result<Vec<String>, crate::LaneError> {
    let request = crate::launch::checkpoint::CheckpointRequest {
        loop_name: "alpha".into(),
        run: "R".into(),
        dry_run: true,
        invocation_token: None,
    };
    crate::launch::checkpoint::private_checkpoint_argv(&request, home, None)
}

fn private_harvest_words(home: &Path, recovery: bool) -> Result<Vec<String>, crate::LaneError> {
    let request = crate::launch::harvest::HarvestRequest {
        loop_name: "alpha".into(),
        run: "R".into(),
        gate_object: "a".repeat(40),
        dry_run: !recovery,
    };
    crate::launch::harvest::private_harvest_argv(&request, home, recovery)
}

/// # Panics
/// Panics if a composer transfers unused or missing capabilities.
fn assert_roles(manifest: &Value, kind: &str) {
    assert_eq!(
        manifest["records"].as_array().expect("roles").len(),
        if kind == "checkout" {
            7
        } else if matches!(kind, "report" | "locks") {
            4
        } else if matches!(
            kind,
            "observed" | "follow" | "context" | "measure" | "harvest-recover"
        ) {
            5
        } else {
            6
        }
    );
    if kind == "checkout" {
        let roles: Vec<_> = manifest["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|record| record["purpose"].as_str().expect("purpose"))
            .collect();
        assert_eq!(
            roles,
            [
                "owner-home",
                "runs-root",
                "entry-executable",
                "hash-executable",
                "git-executable",
                "configuration",
                "destination-parent"
            ]
        );
    }
    if matches!(kind, "measure" | "harvest-recover") {
        let roles: Vec<_> = manifest["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|record| record["purpose"].as_str().expect("purpose"))
            .collect();
        assert_eq!(
            roles,
            [
                "owner-home",
                "runs-root",
                "entry-executable",
                "hash-executable",
                "configuration"
            ]
        );
    }
}

/// # Panics
/// Panics if the private vector or its observation departs from the named reader contract.
fn measure(home: &Path, runs: &Path, identity: &str, kind: &str, case: &str) {
    let mut request = request(
        home,
        runs,
        if case == "record" {
            "changed"
        } else {
            identity
        },
        kind,
    );
    alter_bundle(&mut request, home, runs, kind, case);
    let config = home.join(".config/loops");
    let retained = home.join(".config/retained-loops");
    if case == "replaced" {
        fs::rename(&config, &retained).expect("retain configuration");
        fs::create_dir(&config).expect("replacement");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        fs::write(config.join("registry.toml"), "replacement must not be read")
            .expect("replacement registry");
    }
    if case == "mode" {
        fs::set_permissions(
            if matches!(kind, "report" | "locks") {
                runs
            } else {
                &config
            },
            fs::Permissions::from_mode(if matches!(kind, "report" | "locks") {
                0o770
            } else {
                0o750
            }),
        )
        .expect("widen configuration");
    }
    if case == "missing" {
        request.argv.truncate(request.argv.len() - 4);
    }
    if case == "vector" {
        request.argv.insert(4, "surplus".into());
    }
    if case == "relative-home" {
        let option = request
            .argv
            .iter()
            .position(|word| word == "--owner-home")
            .expect("home");
        request.argv[option + 1] = "relative-home".into();
        // No descriptor channel: this must refuse before attempting receipt.
        request.descriptors = loop_home::CommandDescriptors::default();
    }
    let widened = match case {
        "parent-mode" => Some(checkout_parent(home)),
        "ancestor-mode" => Some(home.parent().expect("fixture root").to_path_buf()),
        _ => None,
    };
    if let Some(path) = &widened {
        fs::set_permissions(path, fs::Permissions::from_mode(0o770)).expect("widen parent");
    }
    let source = change_source(home, case);
    let output =
        runtime_preparation::run_with_registry(&request, (case == "override").then_some(""));
    if let Some(path) = &widened {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("restore parent");
    }
    if let Some(bytes) = source {
        let path = home.join(".config/loops/alpha/lanes/codex/auth.json");
        fs::remove_file(&path).expect("remove changed source");
        fs::write(&path, bytes).expect("restore source");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("source mode");
    }
    if case == "replaced" {
        assert_eq!(
            fs::read_to_string(config.join("registry.toml")).expect("replacement"),
            "replacement must not be read"
        );
        fs::remove_dir_all(&config).expect("remove replacement");
        fs::rename(&retained, &config).expect("restore held configuration");
    }
    fs::set_permissions(runs, fs::Permissions::from_mode(0o711)).expect("restore runs mode");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("restore mode");
    observation(&output, kind, case);
}

/// # Panics
/// Panics if a refusal fixture cannot alter the production request's bundle.
fn alter_bundle(
    request: &mut loop_home::CommandSpec,
    home: &Path,
    runs: &Path,
    kind: &str,
    case: &str,
) {
    if matches!(case, "program-owner" | "git-owner") {
        replace_tool(
            request,
            home,
            runs,
            kind,
            if case == "git-owner" { 4 } else { 3 },
            false,
        );
    }
    let source = request.argv.last_mut().expect("manifest");
    let mut manifest: Value = serde_json::from_str(source).expect("manifest JSON");
    assert_roles(&manifest, kind);
    match case {
        "identity" => manifest["records"][0]["inode"] = json!(0),
        "parent-identity" => manifest["records"][6]["inode"] = json!(0),
        "count" => {
            manifest["records"].as_array_mut().expect("records").pop();
        }
        "surplus-count" => {
            let records = manifest["records"].as_array_mut().expect("records");
            let mut extra = records.last().expect("configuration").clone();
            extra["slot"] = json!(records.len());
            extra["purpose"] = json!("surplus-configuration");
            records.push(extra);
        }
        "operation" => manifest["operation"] = json!("foreign-operation"),
        _ => {}
    }
    *source = manifest.to_string();
    if matches!(case, "short-frame" | "excess-frame") {
        replace_frame(
            request,
            manifest["records"].as_array().expect("roles").len(),
            case,
        );
    }
}

/// # Panics
/// Panics if a host-owned tool cannot be declared honestly to the real receiver.
fn replace_tool(
    request: &mut loop_home::CommandSpec,
    home: &Path,
    runs: &Path,
    kind: &str,
    slot: usize,
    root_program: bool,
) {
    use loop_home::anchor::{HostVerifier, Manifest, Owner};
    let operation = match kind {
        "harvest" => "exercise-harvest",
        "home-layout" => "exercise-home-layout",
        "measure" => "exercise-measure",
        "observed" => "observed-hosts",
        "follow" => "follow",
        "context" => "exercise-context",
        "checkpoint" => "checkpoint",
        "checkout" => "checkout",
        "import" => "mark-imported",
        "private-harvest" => "harvest",
        "harvest-recover" => "harvest-recover",
        _ => "driver-report",
    };
    let home_fd = fs::File::open(home).expect("home").into();
    let runs_fd = fs::File::open(runs).expect("runs").into();
    let destination = checkout_parent(home);
    let held_destination = fs::File::open(&destination).expect("destination").into();
    let mut bundle = crate::container_entry::pin_reader(
        operation,
        "alpha",
        (home, &home_fd),
        (runs, &runs_fd),
        &runtime_preparation::binary(),
        (kind == "checkout").then_some((destination.as_path(), &held_destination)),
    )
    .expect("reader pins");
    let path = if root_program {
        std::path::PathBuf::from("/usr/bin/false")
    } else {
        let path = home.join("host-hashing-program");
        fs::copy("/usr/bin/sha256sum", &path).expect("native tool copy");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("host tool mode");
        path
    };
    let pin = HostVerifier::current()
        .expect("host verifier")
        .for_operation(operation)
        .pin(
            &path,
            if slot == 3 {
                "hash-executable"
            } else {
                "git-executable"
            },
            u32::try_from(slot).expect("slot"),
            crate::container_entry::executable_policy(if root_program {
                Owner::RootFile
            } else {
                Owner::Host
            }),
        )
        .expect("honest host-owned tool");
    let mut manifest = Manifest::parse(&bundle.manifest).expect("manifest");
    manifest.records[slot] = pin.record();
    bundle.descriptors[slot] = pin.into_fd();
    *request.argv.last_mut().expect("manifest argument") =
        serde_json::to_string(&manifest).expect("declaration");
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("tool channel");
    loop_home::anchor::transport::send(&sender, &bundle.descriptors).expect("host tool frame");
    request.descriptors = loop_home::CommandDescriptors::default().with_input(input.into());
}

/// # Panics
/// Panics if the malformed frame cannot reach the production receiver.
fn replace_frame(request: &mut loop_home::CommandSpec, count: usize, case: &str) {
    let count = if case == "short-frame" {
        count - 1
    } else {
        count + 1
    };
    let descriptors: Vec<_> = (0..count)
        .map(|_| {
            fs::File::open("/dev/null")
                .expect("frame descriptor")
                .into()
        })
        .collect();
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("frame channel");
    loop_home::anchor::transport::send(&sender, &descriptors).expect("malformed count frame");
    request.descriptors = loop_home::CommandDescriptors::default().with_input(input.into());
}

/// # Panics
/// Panics if a synthetic source cannot be changed for one refusal measurement.
fn change_source(home: &Path, case: &str) -> Option<Vec<u8>> {
    if !case.starts_with("source-") {
        return None;
    }
    let path = home.join(".config/loops/alpha/lanes/codex/auth.json");
    let bytes = fs::read(&path).expect("original source");
    match case {
        "source-mode" => {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("source mode");
        }
        "source-link" => {
            fs::remove_file(&path).expect("remove source");
            std::os::unix::fs::symlink("/dev/null", &path).expect("linked source");
        }
        "source-large" => fs::write(&path, vec![b' '; 65_537]).expect("oversized source"),
        _ => unreachable!("known source case"),
    }
    Some(bytes)
}

/// # Panics
/// Panics if the reader fails before its intended audit boundary or loses a named refusal.
fn observation(output: &std::process::Output, kind: &str, case: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if case == "relative-home" {
        assert_eq!(output.status.code(), Some(2));
        assert!(
            stderr.contains(
                "verified-prefix: private launch has duplicate or non-absolute owner home"
            ),
            "{stderr}"
        );
        return;
    }
    if kind == "checkout" && matches!(case, "plain" | "replaced" | "ancestor-mode") {
        assert!(!output.status.success(), "unsettled checkout accepted");
        assert!(
            stderr.contains("checkout-record: reservation is not this settled run"),
            "{stderr}"
        );
        return;
    }
    if matches!(kind, "private-harvest" | "harvest-recover") && matches!(case, "plain" | "replaced")
    {
        assert!(!output.status.success(), "unsettled harvest accepted");
        assert!(
            stderr.contains("harvest-record: phase is preparing; expected settled"),
            "{stderr}"
        );
        return;
    }
    if kind == "import" && matches!(case, "plain" | "replaced") {
        assert!(!output.status.success(), "unsettled import accepted");
        assert!(
            stderr.contains("import-round: run is not settled for import marking"),
            "{stderr}"
        );
        return;
    }
    if kind == "checkpoint" && matches!(case, "plain" | "replaced") {
        assert!(!output.status.success(), "unsettled checkpoint accepted");
        assert!(
            stderr.contains("checkpoint-round: run has no settled final round"),
            "{stderr}"
        );
        return;
    }
    if matches!(case, "plain" | "replaced") {
        assert!(output.status.success(), "{kind}/{case}: {stderr}{stdout}");
        successful_observation(output, kind);
    } else {
        assert!(!output.status.success(), "{kind}/{case} accepted");
        let expected = match case {
            "missing" => "anchor-missing",
            "mode" | "source-mode" | "parent-mode" => "anchor-mode",
            "source-link" => "anchor-escape",
            "source-large" => "exercise-path",
            "identity" | "parent-identity" => "anchor-identity",
            "program-owner" | "git-owner" => "anchor-owner",
            "short-frame" | "excess-frame" => "anchor-transport",
            "record" => {
                if matches!(kind, "report" | "locks") {
                    "reservation differs from public report request"
                } else if kind == "follow" {
                    "follow-private-record"
                } else if kind == "context" {
                    "exercise-context-record"
                } else if kind == "harvest" {
                    "exercise-harvest-record"
                } else {
                    "exercise-home-layout-record"
                }
            }
            _ => "anchor-declaration",
        };
        assert!(stderr.contains(expected), "{kind}/{case}: {stderr}{stdout}");
        let boundary = match case {
            "parent-mode" | "parent-identity" => "purpose=destination-parent",
            "program-owner" => "purpose=hash-executable",
            "git-owner" => "purpose=git-executable",
            "count" | "surplus-count" => "purpose=count",
            "operation" => "purpose=bundle",
            "override" => "purpose=registry-override",
            "vector" => "purpose=vector",
            "short-frame" | "excess-frame" => "purpose=rights check=rights-frame",
            _ => "",
        };
        assert!(stderr.contains(boundary), "{kind}/{case}: {stderr}{stdout}");
    }
}

/// # Panics
/// Panics if a successful reader changes its public output or evidence boundary.
fn successful_observation(output: &std::process::Output, kind: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    if kind == "follow" {
        let lines: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).expect("raw follow line"))
            .collect();
        assert_eq!(lines.len(), 2, "{stdout}");
        assert_eq!(lines[0]["kind"], "round-status");
        assert_eq!(lines[1]["kind"], "event-delta");
        assert_eq!(lines[1]["events"][0]["type"], "turn.completed");
        assert!(stdout.ends_with('\n'));
        return;
    }
    let report: Value = serde_json::from_slice(&output.stdout).expect("reader report");
    if kind == "context" {
        assert_eq!(report["state"], "measured");
        assert_eq!(report["source"], "test-field");
        assert_eq!(report["used"], 50);
        assert_eq!(report["window"], 100);
        assert_eq!(report["turn"], 1);
        return;
    }
    if matches!(kind, "report" | "locks") {
        assert_eq!(
            report["refusal"]["kind"],
            if kind == "report" {
                "repin-door-state"
            } else {
                "retire-uncertain"
            },
            "{report}"
        );
        return;
    }
    if kind == "observed" {
        assert_eq!(report["mode"], "observing");
        assert_eq!(report["enforcing"], false);
        assert_eq!(report["connected_hosts"], json!(["api.example.com"]));
        assert_eq!(
            report["attempted_connect_hosts"],
            json!({"api.example.com":true})
        );
        return;
    }
    if kind == "measure" {
        assert!(
            report["custody"]["digest"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64),
            "{report}"
        );
        assert_eq!(report["runs"], json!([]), "{report}");
        return;
    }
    let reason = if kind == "harvest" {
        "complete checkpoint is absent"
    } else {
        "run is not settled"
    };
    assert_eq!(report["reason"], reason, "{report}");
}

/// # Panics
/// Panics if the complete private measurement reads replaced roots or loses helper evidence.
fn live_measure(home: &Path, runs: &Path, record: &mut Value) {
    let script = r"
import os,json,sys
from pathlib import Path
h=Path(sys.argv[1]);w=Path(sys.argv[2]);os.chmod(w,0o750)
s=json.loads((h/'.config/loops/alpha/lanes/codex/auth.json').read_text())
t=dict(s['tokens']);t['refresh_token']=''
p={'auth_mode':'chatgptAuthTokens','OPENAI_API_KEY':None,
   'tokens':t,'last_refresh':s['last_refresh']}
a=w/'.codex/auth.json'
a.write_text(json.dumps(p,sort_keys=True,separators=(',',':'))+'\n')
os.chmod(a,0o600);os.chown(a,3000,3000)
";
    let output = helper_service::namespace_python(
        home,
        script,
        record["plan"]["home"].as_str().expect("worker"),
    )
    .expect("worker fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    record["phase"] = json!("started");
    record["helper_pid"] = json!(std::process::id());
    record["helper_start"] = json!(
        crate::container_helper::process_start(std::process::id()).expect("live fixture process")
    );
    crate::launch::publish_reservation(&runs.join(".reservation-R.json"), record)
        .expect("live reservation");
    let evidence = runs.join(".launch-R/credential-refresh.json");
    fs::write(
        &evidence,
        r#"{"state":"published","host":"fixture.invalid"}"#,
    )
    .expect("helper evidence");
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o600)).expect("evidence mode");
    let composed = request(home, runs, "", "measure");
    let held = runs.with_file_name("retained-runs");
    fs::rename(runs, &held).expect("retain runs");
    fs::create_dir(runs).expect("replacement runs");
    fs::write(runs.join(".reservation-R.json"), "invalid replacement").expect("replacement record");
    let output = runtime_preparation::run(&composed);
    fs::remove_dir_all(runs).expect("remove replacement");
    fs::rename(&held, runs).expect("restore runs");
    assert!(
        !output.status.success(),
        "replaced runs root accepted at receipt"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("socket-dir-handoff"));
    let output = runtime_preparation::run(&request(home, runs, "", "measure"));
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("measurement");
    assert_eq!(
        report["runs"].as_array().expect("runs").len(),
        1,
        "{report}"
    );
    assert_eq!(
        report["runs"][0]["comparison"]["worker_matches_projection"], true,
        "{report}"
    );
    assert_eq!(
        report["runs"][0]["helper_evidence"]["state"], "published",
        "{report}"
    );
}

/// # Panics
/// Panics if production follow or context receipt reopens configuration or loses bounded evidence.
fn follow_round(home: &Path, runs: &Path, record: &mut Value) {
    record["rounds"] = json!([{"step":"dispatch","phase":"failed",
        "settlement_error":"fixture-only","driver_dir":runs.join("R/dispatch")}]);
    crate::launch::publish_reservation(&runs.join(".reservation-R.json"), record)
        .expect("follow reservation");
    let step = runs.join("R/dispatch");
    fs::create_dir_all(&step).expect("round directory");
    // Recorded by ContextTracker::observe_durable on kranich with TestBackend values.
    // Only the reader runs under the namespace; the unit-probe event input is retained.
    let context = concat!(
        r#"{"state":"measured","used":50,"window":100,"fraction":0.5,"source":"test-field","#,
        r#""reason":"measured","turn":1,"event_end":26,"at":"2026-11-08T22:14:56Z"}"#,
        "\n",
    );
    for (name, data) in [
        ("events.jsonl", "{\"type\":\"turn.completed\"}\n"),
        ("context.jsonl", context),
        (".event-start", "0\n"),
    ] {
        fs::write(step.join(name), data).expect("recorded round evidence");
    }
    let script = r"
import os,sys,tomllib
from pathlib import Path
home=Path(sys.argv[1]);runs=Path(sys.argv[2]);root=runs/'R';step=root/'dispatch'
uid=tomllib.loads((home/'.config/loops/registry.toml').read_text())['loops'][0]['uid']
for p in [root,step]: os.chown(p,uid,uid);os.chmod(p,0o700)
for name in ['events.jsonl','context.jsonl','.event-start']:
 p=step/name;os.chown(p,uid,uid);os.chmod(p,0o600)
";
    let output = helper_service::namespace_python(home, script, runs.to_str().expect("runs"))
        .expect("loop evidence");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = runs.join(".reservation-R.json");
    let stat = fs::metadata(&path).expect("record identity");
    let digest = crate::build::sha256_bytes(&fs::read(path).expect("record bytes"), home)
        .expect("record digest");
    let identity = format!("{}:{}:{digest}", stat.dev(), stat.ino());
    for kind in ["follow", "context"] {
        for case in [
            "plain",
            "replaced",
            "mode",
            "identity",
            "count",
            "operation",
            "record",
            "override",
            "missing",
            "vector",
            "short-frame",
            "excess-frame",
            "program-owner",
        ] {
            measure(home, runs, &identity, kind, case);
        }
    }
}

// The seed and all reported Git objects come from this real program probe.
const SETTLED_BARE: &str = r"
import os,sys,json,subprocess,time
from pathlib import Path
home=Path(sys.argv[1]);inputs=json.loads(sys.argv[2]);record=inputs['record']
worker=int(record['worker_uid']);loop_uid=int(inputs['loop_uid'])
p=Path(record['plan']['home']);run=Path(record['plan']['driver_dir'])
def directory(path,uid,mode):
 path.mkdir(parents=True,exist_ok=True);os.chown(path,uid,uid);os.chmod(path,mode)
directory(run,loop_uid,0o700)
directory(p,0,0o750);directory(p/'.local',0,0o750)
for name,uid,mode in [('inbox',0,0o750),('outbox',worker,0o750),('sources',worker,0o700)]:
 directory(p/'.local'/name,uid,mode)
bare=p/'.local/sources/tools.git';work=home/'seed-work'
def git(path,*args):
 return subprocess.check_output(['/usr/bin/git','-c','safe.directory=*',
  '-c','user.name=Synthetic fixture','-c','user.email=fixture@localhost',*args],
  cwd=path,stderr=subprocess.PIPE).decode().strip()
git(home,'init',str(work));(work/'letter').write_text('synthetic settled source\n')
git(work,'add','letter');git(work,'commit','-m','synthetic seed')
seed=git(work,'rev-parse','HEAD');git(home,'init','--bare',str(bare))
git(work,'push',str(bare),'HEAD:refs/heads/lane/R','HEAD:refs/seeds/tools')
git(bare,'symbolic-ref','HEAD','refs/heads/lane/R')
for root,dirs,files in os.walk(bare):
 for item in [Path(root),*[Path(root)/name for name in dirs]]:
  os.chown(item,worker,worker);os.chmod(item,0o700)
 for name in files:
  item=Path(root)/name;os.chown(item,worker,worker);os.chmod(item,0o600)
st=os.stat(bare)
print(json.dumps({'name':'tools','seed':seed,'seeded_at_unix_ns':time.time_ns(),
 'source_identity':{'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,
 'gid':st.st_gid,'mode':st.st_mode&0o7777}}))
";

/// # Panics
/// Panics if a settled bare cannot exercise the production checkpoint, checkout and import entries.
fn settled_readers(home: &Path, runs: &Path, record: &mut Value) {
    let inputs = json!({"record":record,
        "loop_uid":crate::plan::loop_uid(&record["plan"]).expect("loop identity")});
    let output = helper_service::namespace_python(home, SETTLED_BARE, &inputs.to_string())
        .expect("seeded bare probe");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source: Value = serde_json::from_slice(&output.stdout).expect("measured seed identity");
    let object = source["seed"].as_str().expect("seed object").to_owned();
    record["phase"] = json!("settled");
    record["rounds"] = json!([{"step":"dispatch","phase":"settled","ended_by":"by-report"}]);
    record["declared_sources"] = json!([source]);
    for key in [
        "checkpoints",
        "checkpoint_attempts",
        "checkouts",
        "checkout_attempts",
        "imports",
    ] {
        record[key] = json!([]);
    }
    record["harvest_agreement"] = Value::Null;
    record["collection"] = Value::Null;
    record["attempts_omitted"] = json!(0);
    record["checkouts_omitted"] = json!(0);
    record["checkout_next_index"] = json!(1);
    for key in ["checkpoint_pending", "checkout_pending"] {
        record.as_object_mut().expect("record").remove(key);
    }
    crate::launch::publish_reservation(&runs.join(".reservation-R.json"), record)
        .expect("settled reservation");
    for operation in ["checkpoint", "checkout", "mark-imported", "harvest"] {
        assert_settled_tools(home, runs, operation, &object);
        let request = settled_request(home, runs, operation, &object, false);
        let output = runtime_preparation::run(&request);
        assert!(
            output.status.success(),
            "{operation}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("production report");
        assert_eq!(report["command"], operation);
        if operation == "checkout" {
            assert_eq!(
                fs::read(checkout_parent(home).join("checkout/letter")).expect("checkout"),
                b"synthetic settled source\n"
            );
        }
    }
    let record: Value = serde_json::from_slice(
        &fs::read(runs.join(".reservation-R.json")).expect("final reservation"),
    )
    .expect("record");
    assert_eq!(record["checkpoints"][0]["bares"][0]["object"], object);
    assert_eq!(record["checkouts"][0]["object"], object);
    assert_eq!(record["imports"][0]["object"], object);
}

/// # Panics
/// Panics if a complete production request cannot be composed for the settled fixture.
fn settled_request(
    home: &Path,
    runs: &Path,
    operation: &str,
    object: &str,
    preview: bool,
) -> loop_home::CommandSpec {
    let token = "a".repeat(32);
    let body = match operation {
        "checkpoint" => crate::launch::checkpoint::private_checkpoint_argv(
            &crate::launch::checkpoint::CheckpointRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                dry_run: preview,
                invocation_token: Some(token.clone()),
            },
            home,
            (!preview).then_some(token.as_str()),
        ),
        "checkout" => crate::launch::checkout::private_checkout_argv(
            &crate::launch::checkout::CheckoutRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                repo: "tools".into(),
                into: checkout_parent(home).join("checkout"),
                dry_run: preview,
                invocation_token: Some(token.clone()),
            },
            home,
            (!preview).then_some(token.as_str()),
        ),
        "mark-imported" => crate::launch::imports::private_import_argv(
            &crate::launch::imports::MarkImportedRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                object: object.into(),
            },
            home,
        ),
        "harvest" => crate::launch::harvest::private_harvest_argv(
            &crate::launch::harvest::HarvestRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                gate_object: object.into(),
                dry_run: true,
            },
            home,
            false,
        ),
        _ => unreachable!("settled operation"),
    }
    .expect("production vector");
    let mut argv = vec![
        "unshare".into(),
        runtime_preparation::binary().display().to_string(),
    ];
    argv.extend(body);
    let home_fd = fs::File::open(home).expect("home").into();
    let runs_fd = fs::File::open(runs).expect("runs").into();
    let destination = checkout_parent(home);
    let destination_fd = fs::File::open(&destination).expect("destination").into();
    reader_entry::command(
        Path::new("/usr/bin/podman"),
        &argv,
        home,
        &home_fd,
        runs,
        &runs_fd,
        (operation == "checkout").then_some((destination.as_path(), &destination_fd)),
    )
    .expect("production settled composer")
}

/// # Panics
/// Panics if a settled operation ignores either received executable or mutates on its refusal.
fn assert_settled_tools(home: &Path, runs: &Path, operation: &str, object: &str) {
    let kind = match operation {
        "mark-imported" => "import",
        "harvest" => "private-harvest",
        other => other,
    };
    let path = runs.join(".reservation-R.json");
    let before = fs::read(&path).expect("before executable refusal");
    for slot in [3, 4] {
        let mut request = settled_request(home, runs, operation, object, true);
        replace_tool(&mut request, home, runs, kind, slot, true);
        let output = runtime_preparation::run(&request);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{operation} ignored held tool {slot}"
        );
        assert!(
            !stderr.contains("anchor-"),
            "tool refused before execution: {stderr}"
        );
        assert_eq!(fs::read(&path).expect("after executable refusal"), before);
    }
}
