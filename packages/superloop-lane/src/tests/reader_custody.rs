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
    // Recorded from Observation::note/publish by the real proxy writer probe.
    let observation = runs.join(".observed-R.txt");
    fs::write(
        &observation,
        "mode=observing run=R enforcing=false\napi.example.com:443 connected=1\n",
    )
    .expect("recorded proxy output");
    fs::set_permissions(observation, fs::Permissions::from_mode(0o600)).expect("observation mode");
    for kind in ["harvest", "home-layout", "measure", "observed"] {
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
            "source-mode",
            "source-link",
            "source-large",
        ] {
            if (kind == "measure" && case != "record")
                || (kind == "observed" && case != "record" && !case.starts_with("source-"))
                || (matches!(kind, "harvest" | "home-layout") && !case.starts_with("source-"))
            {
                measure(home, runs, &identity, kind, case);
            }
        }
    }
    live_measure(home, runs, &mut record);
    writeln!(std::io::stdout().lock(), "PRIVATE-READERS-MEASURED").expect("measured marker");
}

/// # Panics
/// Panics if the fixture cannot compose the production descriptor transfer.
fn request(home: &Path, runs: &Path, identity: &str, kind: &str) -> loop_home::CommandSpec {
    let home_fd = fs::File::open(home).expect("home").into();
    let runs_fd = fs::File::open(runs).expect("runs").into();
    let body = if matches!(kind, "measure" | "observed") {
        Ok(vec![
            if kind == "measure" {
                "_exercise-measure"
            } else {
                "_observed-hosts"
            }
            .into(),
            "alpha".into(),
            if kind == "measure" { "all" } else { "R" }.into(),
            "--owner-home".into(),
            home.display().to_string(),
        ])
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
    reader_entry::command(
        Path::new("/usr/bin/podman"),
        &argv,
        home,
        &home_fd,
        runs,
        &runs_fd,
    )
    .expect("production reader composer")
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
    let source = request.argv.last_mut().expect("manifest");
    let mut manifest: Value = serde_json::from_str(source).expect("manifest JSON");
    assert_eq!(
        manifest["records"].as_array().expect("roles").len(),
        if kind == "observed" { 5 } else { 6 }
    );
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
    let source = change_source(home, case);
    let output =
        runtime_preparation::run_with_registry(&request, (case == "override").then_some(""));
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
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("restore mode");
    observation(&output, kind, case);
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
    if matches!(case, "plain" | "replaced") {
        assert!(output.status.success(), "{kind}/{case}: {stderr}{stdout}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("reader report");
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
    } else {
        assert!(!output.status.success(), "{kind}/{case} accepted");
        let expected = match case {
            "missing" => "anchor-missing",
            "mode" | "source-mode" => "anchor-mode",
            "source-link" => "anchor-escape",
            "source-large" => "exercise-path",
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
