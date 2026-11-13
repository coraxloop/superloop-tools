//! Loop-maintained model configuration; registry grants remain unchanged.

use crate::error::LaneError;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const EFFORTS: [&str; 4] = ["low", "medium", "high", "xhigh"];

#[derive(Clone, Debug)]
pub(super) struct ComputeDeadline {
    pub(super) words: Vec<String>,
    pub(super) deadline_ms: u64,
}

pub(super) fn compute_deadlines(value: &Value) -> Result<Vec<ComputeDeadline>, LaneError> {
    let Some(value) = value.get("compute_deadlines") else {
        return Ok(Vec::new());
    };
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 32)
        .ok_or_else(|| refusal("compute_deadlines must be an array of at most 32 exact forms"))?;
    let mut forms: Vec<ComputeDeadline> = Vec::new();
    for row in rows {
        if row.as_object().is_none_or(|row| {
            row.len() != 2 || !row.contains_key("words") || !row.contains_key("deadline_ms")
        }) {
            return Err(refusal(
                "compute_deadlines entry requires only words and deadline_ms",
            ));
        }
        let words = row["words"]
            .as_array()
            .and_then(|words| {
                words
                    .iter()
                    .map(|word| word.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| refusal("compute_deadlines words must be an argv array"))?;
        execute_command::checks::compute::validate_words(&words)
            .map_err(|cause| refusal(format!("compute_deadlines words: {cause}")))?;
        let deadline_ms = row["deadline_ms"]
            .as_u64()
            .filter(|ms| {
                (super::compute::DEADLINE_MS + 1..=super::compute::MAX_DEADLINE_MS).contains(ms)
            })
            .ok_or_else(|| refusal("compute_deadlines deadline_ms must be 1800001..86400000"))?;
        if forms.iter().any(|form| form.words == words) {
            return Err(refusal("compute_deadlines contains a duplicate exact form"));
        }
        forms.push(ComputeDeadline { words, deadline_ms });
    }
    Ok(forms)
}

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
        ![
            "rubric_root",
            "model",
            "effort",
            "cap_ms",
            "executable",
            "compute_deadlines",
        ]
        .contains(&key.as_str())
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
    let mut result = json!({"rubric_root":instance,"rubric_path":instance.join("permissions/door.md"),
        "executable":executable,"model":model,"effort":effort,"cap_ms":cap_ms});
    if let Some(forms) = table.get("compute_deadlines") {
        result["compute_deadlines"] =
            serde_json::to_value(forms).map_err(|error| refusal(error.to_string()))?;
    }
    let _validated = compute_deadlines(&result)?;
    Ok(result)
}

/// Construct the runner solely from the installed service generation.
///
/// # Errors
/// Refuses a malformed installed configuration.
pub fn runner(
    value: &Value,
    owner_home: &Path,
    loop_name: &str,
    loop_uid: Option<u32>,
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
        object.len() != KEYS.len() + usize::from(object.contains_key("compute_deadlines"))
            || KEYS.iter().any(|key| !object.contains_key(*key))
    }) {
        return Err(refusal(
            "installed agent configuration shape differs; run install-door",
        ));
    }
    let _validated = compute_deadlines(value)?;
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
        loop_uid,
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

    /// ´test:unit:configuration-bounds-exact-compute-deadline-forms´
    #[test]
    fn configuration_bounds_exact_compute_deadline_forms() {
        let prefix = "rubric_root = '/fixture'\nexecutable = '/fixture/codex'\nmodel = 'fixture'\n";
        let text = format!(
            "{prefix}[[compute_deadlines]]\nwords = ['cargo', 'test', '--locked', '-p', 'fixture']\ndeadline_ms = 3_600_000\n"
        );
        let mut value = parse(text.as_bytes()).expect("registered form");
        let forms = compute_deadlines(&value).expect("installed forms");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].deadline_ms, 3_600_000);
        assert_eq!(
            forms[0].words,
            ["cargo", "test", "--locked", "-p", "fixture"]
        );
        value["source"] = json!("/fixture/door.toml");
        value["entry"] = json!("/fixture/entry");
        value["loop_home"] = json!("/fixture/loop");
        runner(&value, Path::new("/fixture"), "fixture", Some(41001))
            .expect("installed configuration");
        for bound in [1_800_001, 86_400_000] {
            let mut valid = value.clone();
            valid["compute_deadlines"][0]["deadline_ms"] = json!(bound);
            runner(&valid, Path::new("/fixture"), "fixture", Some(41001))
                .expect("inclusive registered range");
        }
        let form = value["compute_deadlines"][0].clone();
        for invalid in [
            json!(null),
            json!({}),
            json!([form.clone(), form.clone()]),
            json!([{"words":["cargo","test"],"deadline_ms":3_600_000}]),
            json!([{"words":["sh","-c","true"],"deadline_ms":3_600_000}]),
            json!([{"words":["cargo","test","--locked"],"deadline_ms":3_600_000,"extra":true}]),
            json!(vec![form; 33]),
        ] {
            let mut invalid_value = value.clone();
            invalid_value["compute_deadlines"] = invalid;
            let error = runner(
                &invalid_value,
                Path::new("/fixture"),
                "fixture",
                Some(41001),
            )
            .expect_err("invalid policy");
            assert_eq!(error.kind, "door-agent-configuration");
            assert!(error.detail.contains("compute_deadlines"));
        }
        for bound in [
            json!(0),
            json!(1_800_000),
            json!(86_400_001),
            json!(-1),
            json!("3600000"),
            json!(1.5),
        ] {
            let mut invalid = value.clone();
            invalid["compute_deadlines"][0]["deadline_ms"] = bound;
            assert!(runner(&invalid, Path::new("/fixture"), "fixture", Some(41001)).is_err());
        }
        assert!(
            compute_deadlines(&parse(prefix.as_bytes()).expect("ordinary config"))
                .expect("default policy")
                .is_empty()
        );
    }

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
        assert!(runner(&invalid, &fixture.home, "alpha", Some(41001)).is_err());
        invalid
            .as_object_mut()
            .expect("agent object")
            .remove("effort");
        assert!(runner(&invalid, &fixture.home, "alpha", Some(41001)).is_err());
        assert_eq!(value["rubric_path"], "/instance/permissions/door.md");
        assert_eq!(
            runner(&value, &fixture.home, "alpha", Some(41001))
                .expect("runner")
                .model,
            "configured-model"
        );
        assert!(value.get("sign_in").is_none());
        let mut stale = value.clone();
        stale["sign_in"] = json!({});
        assert!(
            runner(&stale, &fixture.home, "alpha", Some(41001))
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
                runner(&value, &fixture.home, "alpha", Some(41001))
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
