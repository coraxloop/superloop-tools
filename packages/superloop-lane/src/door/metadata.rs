//! Inspect the agent's inputs under the identity that will execute it.

use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Stdio};

fn metadata_program() -> String {
    format!(
        "{}\n{}",
        loop_home::runner::SIGN_IN_POLICY,
        include_str!("agent_metadata.py")
    )
}

/// Metadata only; failure to inspect is reported, never translated to absence.
#[must_use]
pub fn inspect(entry: &Path, owner_home: &Path, loop_name: &str, executable: &Path) -> Value {
    let measured = measure(entry, owner_home, loop_name, executable);
    measured.unwrap_or_else(|detail| {
        let unknown = json!({"path":null,"exists":null,"owner_uid":null,"mode":null,
            "loop_uid":null,"usable":null,"inspection_error":detail});
        let mut sign_in = unknown.clone();
        sign_in["remedy"] = Value::Null;
        json!({"sign_in":sign_in,"executable_status":unknown})
    })
}

fn measure(
    entry: &Path,
    owner_home: &Path,
    loop_name: &str,
    executable: &Path,
) -> Result<Value, String> {
    crate::pinned::owner_executable(entry, nix::unistd::Uid::effective().as_raw())
        .map_err(|error| error.to_string())?;
    let registry = loop_home::load_registry(&loop_home::registry_path(None, owner_home))
        .map_err(|error| error.message().to_owned())?;
    let row = registry
        .row(loop_name, owner_home)
        .map_err(|error| error.message().to_owned())?;
    let output = crate::fixture_exec::spawn(
        Command::new("/usr/bin/timeout")
            .args(["--kill-after=1", "10"])
            .arg(entry)
            .args(["enter", loop_name, "--", "/usr/bin/python3", "-I", "-c"])
            .arg(metadata_program())
            .arg(executable)
            .arg(loop_name)
            .arg(row.uid.to_string())
            .env_clear()
            .env("HOME", owner_home)
            .env("PATH", "/usr/bin:/bin")
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{}/bus", nix::unistd::Uid::effective()),
            )
            .env(
                "XDG_RUNTIME_DIR",
                format!("/run/user/{}", nix::unistd::Uid::effective()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
    )
    .and_then(std::process::Child::wait_with_output)
    .map_err(|error| error.to_string())?;
    if !output.status.success() || output.stdout.len() > 16_384 {
        return Err(format!("door-agent-metadata-entry: {}", output.status));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    if value.as_object().is_none_or(|object| object.len() != 2)
        || !valid_metadata(&value["sign_in"], true)
        || !valid_metadata(&value["executable_status"], false)
    {
        return Err("door-agent-metadata-shape".into());
    }
    Ok(value)
}

fn valid_metadata(value: &Value, sign_in: bool) -> bool {
    const KEYS: [&str; 7] = [
        "path",
        "exists",
        "owner_uid",
        "mode",
        "loop_uid",
        "usable",
        "inspection_error",
    ];
    value.as_object().is_some_and(|object| {
        object.len() == KEYS.len() + usize::from(sign_in)
            && KEYS.iter().all(|key| object.contains_key(*key))
            && (!sign_in || object.contains_key("remedy"))
            && ["path", "mode", "inspection_error"]
                .iter()
                .all(|key| value[key].is_null() || value[key].is_string())
            && ["exists", "usable"]
                .iter()
                .all(|key| value[key].is_null() || value[key].is_boolean())
            && ["owner_uid", "loop_uid"]
                .iter()
                .all(|key| value[key].is_null() || value[key].is_u64())
            && (!sign_in || value["remedy"].is_null() || value["remedy"].is_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    /// ´test:unit:door-agent-metadata-distinguishes-absence-presence-and-inspection-failure´
    #[test]
    fn door_agent_metadata_distinguishes_absence_presence_and_inspection_failure() {
        let root = tempfile::tempdir().expect("fixture");
        let home = root.path();
        let auth = home.join(".codex/auth.json");
        let program = home.join("codex");
        fs::write(&program, b"must not execute").expect("inert program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o550)).expect("program mode");
        let uid = nix::unistd::Uid::effective().as_raw();
        let call = |expected: u32| {
            Command::new("/usr/bin/python3")
                .args(["-I", "-c", &metadata_program()])
                .arg(&program)
                .arg("alpha")
                .arg(expected.to_string())
                .env("HOME", home)
                .output()
                .expect("production inspector")
        };
        let absent: Value = serde_json::from_slice(&call(uid).stdout).expect("absence");
        assert_eq!(absent["sign_in"]["exists"], false);
        assert!(absent["sign_in"]["usable"].is_null());
        assert!(valid_metadata(&absent["sign_in"], true));
        assert!(!valid_metadata(&json!({}), true));
        assert!(absent["sign_in"]["owner_uid"].is_null());
        assert_eq!(absent["executable_status"]["usable"], true);
        assert!(
            absent["sign_in"]["remedy"]
                .as_str()
                .expect("remedy")
                .contains("door-sign-in alpha")
        );
        fs::create_dir(home.join(".codex")).expect("private config");
        fs::set_permissions(home.join(".codex"), fs::Permissions::from_mode(0o700)).expect("mode");
        fs::write(&auth, b"synthetic secret never emitted").expect("synthetic credential");
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).expect("auth mode");
        let output = call(uid);
        let present: Value = serde_json::from_slice(&output.stdout).expect("present");
        assert_eq!(present["sign_in"]["owner_uid"], uid);
        assert_eq!(present["sign_in"]["mode"], "0600");
        assert_eq!(present["sign_in"]["usable"], true);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic secret"));
        assert!(
            !call(uid + 1).status.success(),
            "different loop UID refuses"
        );
        fs::remove_file(&auth).expect("remove auth");
        symlink(&program, &auth).expect("unsafe auth");
        let unsafe_value: Value =
            serde_json::from_slice(&call(uid).stdout).expect("unsafe metadata");
        assert_eq!(unsafe_value["sign_in"]["exists"], true);
        assert_eq!(unsafe_value["sign_in"]["usable"], false);
        assert!(unsafe_value["sign_in"]["inspection_error"].is_string());
    }

    /// ´test:unit:door-agent-metadata-pins-parent-and-measures-execute-bits´
    #[test]
    fn door_agent_metadata_pins_parent_and_measures_execute_bits() {
        let root = tempfile::tempdir().expect("metadata fixture");
        let output = Command::new("/usr/bin/python3")
            .args(["-I", "-c", include_str!("agent_metadata_tests.py")])
            .arg(metadata_program())
            .arg(root.path())
            .output()
            .expect("metadata regression helper");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let unknown = inspect(
            Path::new("/missing-entry"),
            root.path(),
            "alpha",
            Path::new("/missing-program"),
        );
        assert!(unknown["sign_in"]["usable"].is_null());
        assert!(unknown["sign_in"]["remedy"].is_null());
        assert!(valid_metadata(&unknown["sign_in"], true));
        let mut bad = unknown["sign_in"].clone();
        bad.as_object_mut().expect("object").remove("remedy");
        assert!(!valid_metadata(&bad, true));
    }
}
