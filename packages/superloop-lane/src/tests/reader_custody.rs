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
    for kind in ["harvest", "home-layout"] {
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
        ] {
            measure(home, runs, &identity, kind, case);
        }
    }
    writeln!(std::io::stdout().lock(), "PRIVATE-READERS-MEASURED").expect("measured marker");
}

/// # Panics
/// Panics if the private vector or its observation departs from the named reader contract.
fn measure(home: &Path, runs: &Path, identity: &str, kind: &str, case: &str) {
    let home_fd = fs::File::open(home).expect("home").into();
    let runs_fd = fs::File::open(runs).expect("runs").into();
    let identity = if case == "record" {
        "changed"
    } else {
        identity
    };
    let body = if kind == "harvest" {
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
    let mut request = reader_entry::command(
        Path::new("/usr/bin/podman"),
        &argv,
        home,
        &home_fd,
        runs,
        &runs_fd,
    )
    .expect("production reader composer");
    let source = request.argv.last_mut().expect("manifest");
    let mut manifest: Value = serde_json::from_str(source).expect("manifest JSON");
    assert_eq!(manifest["records"].as_array().expect("roles").len(), 6);
    match case {
        "identity" => manifest["records"][0]["inode"] = json!(0),
        "count" => {
            manifest["records"].as_array_mut().expect("records").pop();
        }
        "operation" => manifest["operation"] = json!("foreign-operation"),
        _ => {}
    }
    *source = manifest.to_string();
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
        fs::set_permissions(&config, fs::Permissions::from_mode(0o750))
            .expect("widen configuration");
    }
    if case == "missing" {
        request.argv.truncate(request.argv.len() - 4);
    }
    if case == "vector" {
        request.argv.insert(4, "surplus".into());
    }
    let output =
        runtime_preparation::run_with_registry(&request, (case == "override").then_some(""));
    if case == "replaced" {
        assert_eq!(
            fs::read_to_string(config.join("registry.toml")).expect("replacement"),
            "replacement must not be read"
        );
        fs::remove_dir_all(&config).expect("remove replacement");
        fs::rename(&retained, &config).expect("restore held configuration");
    }
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("restore mode");
    observation(&output, kind, case);
}

/// # Panics
/// Panics if the reader fails before its intended audit boundary or loses a named refusal.
fn observation(output: &std::process::Output, kind: &str, case: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if matches!(case, "plain" | "replaced") {
        assert!(output.status.success(), "{kind}/{case}: {stderr}{stdout}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("reader report");
        let reason = if kind == "harvest" {
            "complete checkpoint is absent"
        } else {
            "run is not settled"
        };
        assert_eq!(report["reason"], reason, "{report}");
    } else {
        assert!(!output.status.success(), "{kind}/{case} accepted");
        let expected = match case {
            "missing" => "anchor-missing",
            "mode" => "anchor-mode",
            "identity" => "anchor-identity",
            "record" => {
                if kind == "harvest" {
                    "exercise-harvest-record"
                } else {
                    "exercise-home-layout-record"
                }
            }
            _ => "anchor-declaration",
        };
        assert!(stderr.contains(expected), "{kind}/{case}: {stderr}{stdout}");
        let boundary = match case {
            "count" => "purpose=count",
            "operation" => "purpose=bundle",
            "override" => "purpose=registry-override",
            "vector" => "purpose=vector",
            _ => "",
        };
        assert!(stderr.contains(boundary), "{kind}/{case}: {stderr}{stdout}");
    }
}
