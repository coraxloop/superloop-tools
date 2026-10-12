//! Loop-maintained model configuration; registry grants remain unchanged.

use crate::error::LaneError;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const EFFORTS: [&str; 4] = ["low", "medium", "high", "xhigh"];

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("door-agent-configuration", detail)
}

/// Validate the loop's file and resolve paths without opening a sign-in.
///
/// # Errors
/// Refuses absent settings, unknown keys, unsafe paths or an invalid wall cap.
pub fn read(owner_home: &Path, loop_name: &str, entry: Option<&Path>) -> Result<Value, LaneError> {
    let path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("door.toml");
    let owner = nix::unistd::Uid::effective().as_raw();
    let bytes = crate::pinned::read_private(owner_home, &path, owner, 0o600, 65_536)?;
    let mut value = parse(&bytes)?;
    let entry = entry.ok_or_else(|| refusal("registered entry_bin is absent"))?;
    crate::pinned::owner_executable_word(entry, owner)?;
    let registry = loop_home::load_registry(&loop_home::registry_path(None, owner_home))
        .map_err(|e| refusal(e.message()))?;
    let row = registry
        .row(loop_name, owner_home)
        .map_err(|e| refusal(e.message()))?;
    value["source"] = json!(path);
    value["entry"] = json!(entry);
    value["loop_home"] = json!(row.home);
    Ok(value)
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, LaneError> {
    let text = std::str::from_utf8(bytes).map_err(|_| refusal("door.toml is not UTF-8"))?;
    let table: toml::Table = toml::from_str(text).map_err(|e| refusal(e.to_string()))?;
    if table.contains_key("instance_repository") {
        return Err(refusal(
            "instance_repository is retired; replace the key with rubric_root naming the publication directory",
        ));
    }
    if table.keys().any(|key| {
        !["rubric_root", "model", "effort", "cap_ms", "executable"].contains(&key.as_str())
    }) {
        return Err(refusal("unknown door.toml key"));
    }
    let absolute = |key: &str| -> Result<PathBuf, LaneError> {
        let value = table
            .get(key)
            .and_then(toml::Value::as_str)
            .ok_or_else(|| refusal(format!("{key} is absent")))?;
        let path = PathBuf::from(value);
        if !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(refusal(format!(
                "{key} must be an absolute normalized path"
            )));
        }
        Ok(path)
    };
    let instance = absolute("rubric_root")?;
    let executable = absolute("executable")?;
    let model = table
        .get("model")
        .and_then(toml::Value::as_str)
        .filter(|name| !name.trim().is_empty() && name.len() <= 256)
        .ok_or_else(|| refusal("model is absent or invalid"))?;
    let effort = match table.get("effort") {
        None => "medium",
        Some(value) => value
            .as_str()
            .filter(|value| EFFORTS.contains(value))
            .ok_or_else(|| refusal("effort must be low, medium, high or xhigh"))?,
    };
    let cap_ms = table
        .get("cap_ms")
        .map_or(Some(30_000), toml::Value::as_integer)
        .filter(|cap| (2_001..=120_000).contains(cap))
        .ok_or_else(|| refusal("cap_ms must be 2001..120000"))?;
    Ok(
        json!({"rubric_root":instance,"rubric_path":instance.join("permissions/door.md"),
        "executable":executable,"model":model,"effort":effort,"cap_ms":cap_ms}),
    )
}

/// Construct the runner solely from the installed service generation.
///
/// # Errors
/// Refuses a malformed installed configuration.
pub fn runner(
    value: &Value,
    owner_home: &Path,
    loop_name: &str,
) -> Result<super::agent::CodexRunner, LaneError> {
    const KEYS: [&str; 9] = [
        "source",
        "rubric_root",
        "rubric_path",
        "executable",
        "model",
        "effort",
        "cap_ms",
        "entry",
        "loop_home",
    ];
    if value.as_object().is_none_or(|object| {
        object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key))
    }) {
        return Err(refusal(
            "installed agent configuration shape differs; run install-door",
        ));
    }
    let path = |key: &str| {
        value[key]
            .as_str()
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| refusal(format!("installed {key} is invalid")))
    };
    for key in ["source", "rubric_root", "loop_home"] {
        let _validated = path(key)?;
    }
    Ok(super::agent::CodexRunner {
        entry: path("entry")?,
        owner_home: owner_home.into(),
        loop_name: loop_name.into(),
        executable: path("executable")?,
        rubric_path: path("rubric_path")?,
        model: value["model"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| refusal("installed model absent"))?
            .into(),
        effort: value["effort"]
            .as_str()
            .filter(|value| EFFORTS.contains(value))
            .ok_or_else(|| refusal("installed effort must be low, medium, high or xhigh"))?
            .into(),
        cap_ms: value["cap_ms"]
            .as_u64()
            .filter(|cap| (2_001..=120_000).contains(cap))
            .ok_or_else(|| refusal("installed cap invalid"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// ´test:unit:configuration-resolves-loop-paths-without-sign-in-bytes´
    #[test]
    fn configuration_resolves_loop_paths_without_sign_in_bytes() {
        let fixture = crate::requests::store::tests::Fixture::new();
        let program_root = tempfile::TempDir::new_in("/tmp").expect("protected executable root");
        std::fs::set_permissions(program_root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protected root mode");
        let entry = program_root.path().join("entry");
        crate::fixture_exec::write_executable(&entry, b"#!/bin/sh\nexit 99\n").expect("entry");
        let path = fixture.home.join(".config/loops/alpha/door.toml");
        let text =
            "rubric_root = '/instance'\nexecutable = '/loop/codex'\nmodel = 'configured-model'\n";
        std::fs::write(&path, text).expect("loop configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("private");
        let value = read(&fixture.home, "alpha", Some(&entry)).expect("configuration");
        assert_eq!(value["cap_ms"], 30_000);
        assert_eq!(value["effort"], "medium");
        let mut invalid = value.clone();
        invalid["effort"] = json!("ultra");
        assert!(runner(&invalid, &fixture.home, "alpha").is_err());
        invalid
            .as_object_mut()
            .expect("agent object")
            .remove("effort");
        assert!(runner(&invalid, &fixture.home, "alpha").is_err());
        assert_eq!(value["rubric_path"], "/instance/permissions/door.md");
        assert_eq!(
            runner(&value, &fixture.home, "alpha")
                .expect("runner")
                .model,
            "configured-model"
        );
        assert!(value.get("sign_in").is_none());
        let mut stale = value.clone();
        stale["sign_in"] = json!({});
        assert!(
            runner(&stale, &fixture.home, "alpha")
                .expect_err("stale block")
                .to_string()
                .contains("run install-door")
        );
        assert!(!value.to_string().contains("lanes/codex"));
        std::fs::write(&path, text.replace("model = 'configured-model'\n", ""))
            .expect("missing required model");
        assert!(read(&fixture.home, "alpha", Some(&entry)).is_err());
        std::fs::write(&path, text.replace("rubric_root", "instance_repository"))
            .expect("legacy configuration");
        let legacy = read(&fixture.home, "alpha", Some(&entry)).expect_err("legacy key");
        assert!(
            legacy
                .to_string()
                .contains("replace the key with rubric_root")
        );
        for effort in EFFORTS {
            std::fs::write(&path, format!("{text}effort = '{effort}'\n")).expect("effort");
            let value = read(&fixture.home, "alpha", Some(&entry)).expect("closed effort set");
            assert_eq!(
                runner(&value, &fixture.home, "alpha")
                    .expect("installed effort")
                    .effort,
                effort
            );
        }
        for suffix in [
            "cap_ms = 0\n",
            "cap_ms = '30000'\n",
            "unknown = true\n",
            "effort = 'ultra'\n",
            "effort = 3\n",
            "effort = ''\n",
            "effort = true\n",
        ] {
            std::fs::write(&path, format!("{text}{suffix}")).expect("invalid config");
            assert_eq!(
                read(&fixture.home, "alpha", Some(&entry))
                    .expect_err("invalid")
                    .kind,
                "door-agent-configuration"
            );
        }
    }
}
