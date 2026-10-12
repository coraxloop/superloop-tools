//! Keep launch admission in owner custody under the loop configuration lock.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::{build, home, install};

fn path(config: &Path) -> std::path::PathBuf {
    config.join("launch-admission.json")
}

fn initial() -> Value {
    json!({"schema":1,"state":"running","paused_wall_unix_seconds":null,"resumed_wall_unix_seconds":null})
}

pub(crate) fn read(config: &Path, owner: u32) -> Result<Value, LaneError> {
    let _directory = home::pin_parent(config, owner)?;
    let name = path(config);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&name)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(initial()),
        Err(error) => {
            return Err(LaneError::input(
                "launch-admission",
                format!("{}: {error}", name.display()),
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("launch-admission", error.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > 4096
    {
        return Err(LaneError::input(
            "launch-admission",
            format!(
                "{} is not a bounded owner record at mode 0600",
                name.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("launch-admission", error.to_string()))?;
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("launch-admission", error.to_string()))?;
    if record.as_object().is_none_or(|object| {
        object.len() != 4
            || ![
                "schema",
                "state",
                "paused_wall_unix_seconds",
                "resumed_wall_unix_seconds",
            ]
            .iter()
            .all(|key| object.contains_key(*key))
    }) || record["schema"] != 1
        || !["running", "paused"].contains(&record["state"].as_str().unwrap_or_default())
        || !(record["paused_wall_unix_seconds"].is_null()
            || record["paused_wall_unix_seconds"].is_u64())
        || !(record["resumed_wall_unix_seconds"].is_null()
            || record["resumed_wall_unix_seconds"].is_u64())
        || (record["state"] == "paused" && !record["paused_wall_unix_seconds"].is_u64())
    {
        return Err(LaneError::input(
            "launch-admission",
            format!("{} has an invalid admission record", name.display()),
        ));
    }
    Ok(record)
}

pub(crate) fn ensure_open(config: &Path, owner: u32) -> Result<Value, LaneError> {
    let record = read(config, owner)?;
    if record["state"] == "paused" {
        return Err(LaneError::input(
            "launch-paused",
            format!("{} has paused launch admission", config.display()),
        ));
    }
    Ok(record)
}

/// Pause or resume new launches while holding the loop configuration lock.
///
/// # Errors
///
/// Refuses an unsafe configuration, invalid record, or contended lock.
pub fn set(owner_home: &Path, loop_name: &str, paused: bool) -> Result<Value, LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let begun = Instant::now();
    let config = owner_home.join(".config/loops").join(loop_name);
    let _lock = install::lock_loop_config(&config, false)?;
    let owner = Uid::effective().as_raw();
    let mut record = read(&config, owner)?;
    let next = if paused { "paused" } else { "running" };
    let changed = record["state"] != next;
    if changed {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| LaneError::operation("launch-admission", error.to_string()))?
            .as_secs();
        record["state"] = json!(next);
        record[if paused {
            "paused_wall_unix_seconds"
        } else {
            "resumed_wall_unix_seconds"
        }] = json!(wall);
        build::publish(
            &path(&config),
            &serde_json::to_vec(&record)
                .map_err(|error| LaneError::operation("launch-admission", error.to_string()))?,
        )?;
        fs::File::open(&config)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| LaneError::operation("launch-admission", error.to_string()))?;
    }
    Ok(
        json!({"schema":1,"command":if paused {"pause"} else {"resume"},"loop":loop_name,"admission":record,"changed":changed,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:pause-resume-records-walls-and-refuses-new-admission´
    #[test]
    fn pause_resume_records_walls_and_refuses_new_admission() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = fixture.path().join(".config/loops/alpha");
        fs::create_dir_all(&config).expect("configuration");
        for directory in [
            fixture.path().join(".config"),
            fixture.path().join(".config/loops"),
            config.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("configuration mode");
        }
        let owner = Uid::effective().as_raw();
        assert_eq!(
            read(&config, owner).expect("initial state")["state"],
            "running"
        );
        let paused = set(fixture.path(), "alpha", true).expect("pause");
        assert_eq!(paused["admission"]["state"], "paused");
        assert!(paused["admission"]["paused_wall_unix_seconds"].is_u64());
        assert_eq!(
            ensure_open(&config, owner).expect_err("pause gate").kind,
            "launch-paused"
        );
        let request = super::super::LaunchRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            letter: fixture.path().join("letter"),
            round: None,
            budget: 3600,
            dry_run: true,
            expect_digest: None,
            observe: true,
            podman_bin: "/usr/bin/true".into(),
            proxy_bin: None,
            model: Some("gpt-6-sol".into()),
            effort: Some("high".into()),
            door_scope: crate::door::Scope::Work,
            rotation_source: None,
        };
        assert_eq!(
            super::super::run_with_host_root(fixture.path(), &request, fixture.path(), 0)
                .expect_err("public launch gate")
                .kind,
            "launch-paused"
        );
        assert_eq!(
            set(fixture.path(), "alpha", true).expect("repeat pause")["changed"],
            false
        );
        let resumed = set(fixture.path(), "alpha", false).expect("resume");
        assert!(resumed["admission"]["resumed_wall_unix_seconds"].is_u64());
        assert_eq!(
            ensure_open(&config, owner).expect("resumed gate")["state"],
            "running"
        );
        fs::write(
            path(&config),
            br#"{"schema":1,"state":"running","paused_wall_unix_seconds":null,"extra":null}"#,
        )
        .expect("malformed record");
        assert_eq!(
            read(&config, owner)
                .expect_err("missing admission field")
                .kind,
            "launch-admission"
        );
    }
}
