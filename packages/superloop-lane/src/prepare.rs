//! Create the tool-owned settings and worker allocation before a first build.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::error::LaneError;
use crate::install::{install_allocation, lock_loop_config};
use crate::settings::Settings;

static NEXT_PREPARE_TEMP: AtomicU64 = AtomicU64::new(0);
const DEFAULT_RESOURCES: &str = "{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }";

fn verified_driver(entry: &Path) -> Result<std::path::PathBuf, LaneError> {
    let owner = nix::unistd::Uid::effective().as_raw();
    crate::pinned::owner_executable(entry, owner)?;
    let driver = entry
        .parent()
        .ok_or_else(|| LaneError::input("owner-program", "entry program has no parent"))?
        .join("superloop-lane");
    crate::pinned::owner_executable(&driver, owner)?;
    Ok(driver)
}

fn driver_arguments(driver: &Path) -> Vec<toml::Value> {
    [
        driver.to_string_lossy().into_owned(),
        "driver".into(),
        "start".into(),
        "--backend".into(),
        "codex".into(),
    ]
    .into_iter()
    .map(toml::Value::String)
    .collect()
}

fn seed_existing_settings(
    settings: &Settings,
    fallback_entry: &Path,
) -> Result<(String, Vec<&'static str>), LaneError> {
    let mut parsed: toml::Value = toml::from_str(&settings.source)
        .map_err(|error| LaneError::input("prepare-write", error.to_string()))?;
    let table = parsed
        .as_table_mut()
        .ok_or_else(|| LaneError::input("prepare-write", "settings root is not a table"))?;
    let mut written = Vec::new();
    if settings.driver_bin.is_none() {
        let entry = settings.entry_bin.as_deref().unwrap_or(fallback_entry);
        let driver = verified_driver(entry)?;
        table.insert(
            "driver_argv".into(),
            toml::Value::Array(driver_arguments(&driver)),
        );
        written.push("driver_argv");
    }
    if settings.resources.is_none() {
        let defaults: toml::Value = toml::from_str(&format!("resources = {DEFAULT_RESOURCES}"))
            .map_err(|error| LaneError::input("prepare-write", error.to_string()))?;
        table.insert("resources".into(), defaults["resources"].clone());
        written.push("resources");
    }
    let source = toml::to_string_pretty(&parsed)
        .map_err(|error| LaneError::input("prepare-write", error.to_string()))?;
    Ok((source, written))
}

/// Prepare one loop from a registry row, without overwriting its settings.
///
/// # Errors
///
/// Refuses an unsafe registry, directory, setting, or allocation ledger.
pub fn run(home: &Path, loop_name: &str, dry_run: bool) -> Result<Value, LaneError> {
    let current = std::env::current_exe()
        .map_err(|error| LaneError::operation("prepare-program", error.to_string()))?;
    let entry = current
        .parent()
        .ok_or_else(|| LaneError::operation("prepare-program", "program has no parent"))?
        .join("superloop");
    run_with_entry_bin(home, loop_name, dry_run, &entry)
}

pub(crate) fn run_with_entry_bin(
    home: &Path,
    loop_name: &str,
    dry_run: bool,
    entry: &Path,
) -> Result<Value, LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let registry_path =
        loop_home::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let row = registry
        .row(loop_name, home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let runs_root = registry.runs_root(loop_name).ok_or_else(|| {
        LaneError::input("registry-row", "runs_root is absent from the registry row")
    })?;
    let root = home.join(".config/loops");
    let _root_lock = lock_loop_config(&root, dry_run)?;
    let directory = root.join(loop_name);
    let settings_path = directory.join("workers.toml");
    let _settings_lock = directory
        .exists()
        .then(|| lock_loop_config(&directory, dry_run))
        .transpose()?;
    let settings_exists = settings_path.exists();
    let mut settings_written = Vec::new();
    if settings_exists {
        let settings = Settings::read(&settings_path)?;
        settings.validate_grant(home, loop_name)?;
        if crate::build::payload::configured(&settings).is_empty() {
            return Err(LaneError::input(
                "missing-setting",
                "no vendor is named in backend_argv or vendor_hosts",
            ));
        }
        let (source, written) = seed_existing_settings(&settings, entry)?;
        settings_written = written;
        if !settings_written.is_empty() && !dry_run {
            write_settings_source(&directory, &settings_path, &source)?;
        }
    } else if directory.exists() {
        let driver = verified_driver(entry)?;
        settings_written.extend([
            "runs_root",
            "entry_bin",
            "driver_argv",
            "resources",
            "vendor_hosts.codex",
        ]);
        if !dry_run {
            write_settings(&directory, &settings_path, runs_root, entry, &driver)?;
        }
    } else {
        let driver = verified_driver(entry)?;
        settings_written.extend([
            "runs_root",
            "entry_bin",
            "driver_argv",
            "resources",
            "vendor_hosts.codex",
        ]);
        if !dry_run {
            let stage = new_directory(&root, loop_name)?;
            let stage_settings = stage.join("workers.toml");
            if let Err(error) = write_settings(&stage, &stage_settings, runs_root, entry, &driver)
                .and_then(|()| {
                    fs::rename(&stage, &directory).map_err(|error| {
                        LaneError::input(
                            "prepare-write",
                            format!("{}: {error}", directory.display()),
                        )
                    })
                })
            {
                let _removed = fs::remove_dir_all(&stage);
                return Err(error);
            }
        }
    }
    let allocation = install_allocation(home, loop_name, true, dry_run)?;
    let sign_in = crate::sign_in::prepare_metadata(home, loop_name, row.uid, dry_run);
    let settings_change = !settings_written.is_empty();
    Ok(
        json!({"schema":1,"command":"prepare","loop":loop_name,"dry_run":dry_run,"changed":u64::from(settings_change && !dry_run) + u64::from(allocation["allocated"] == true) + sign_in["changed"].as_u64().unwrap_or(0),"would_write_settings":settings_change && dry_run,"settings_written":if dry_run { Vec::new() } else { settings_written.clone() },"would_seed_settings":if dry_run { settings_written } else { Vec::new() },"settings":settings_path,"allocation":allocation,"sign_in_metadata":sign_in}),
    )
}

fn new_directory(root: &Path, loop_name: &str) -> Result<std::path::PathBuf, LaneError> {
    loop {
        let suffix = NEXT_PREPARE_TEMP.fetch_add(1, Ordering::Relaxed);
        let stage = root.join(format!(
            ".prepare-{loop_name}-{}-{suffix}.tmp",
            std::process::id()
        ));
        match DirBuilder::new().mode(0o700).create(&stage) {
            Ok(()) => {
                fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        LaneError::input("prepare-write", format!("{}: {error}", stage.display()))
                    },
                )?;
                return Ok(stage);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(LaneError::input(
                    "prepare-write",
                    format!("{}: {error}", stage.display()),
                ));
            }
        }
    }
}

fn write_settings(
    directory: &Path,
    path: &Path,
    runs_root: &Path,
    entry: &Path,
    driver: &Path,
) -> Result<(), LaneError> {
    let source = format!(
        "runs_root = {}\nentry_bin = {}\ndriver_argv = {}\nresources = {DEFAULT_RESOURCES}\nvendor_hosts = {{ codex = [] }}\n",
        toml::Value::String(runs_root.to_string_lossy().into_owned()),
        toml::Value::String(entry.to_string_lossy().into_owned()),
        toml::Value::Array(driver_arguments(driver))
    );
    write_settings_source(directory, path, &source)
}

fn write_settings_source(directory: &Path, path: &Path, source: &str) -> Result<(), LaneError> {
    loop {
        let suffix = NEXT_PREPARE_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = directory.join(format!(".workers-{}-{suffix}.tmp", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary);
        let Ok(mut file) = file else {
            let error = file.expect_err("file creation failed");
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(LaneError::input(
                "prepare-write",
                format!("{}: {error}", temporary.display()),
            ));
        };
        let result = file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(source.as_bytes()))
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&temporary, path));
        if let Err(error) = result {
            let _removed = fs::remove_file(&temporary);
            return Err(LaneError::input(
                "prepare-write",
                format!("{}: {error}", path.display()),
            ));
        }
        return Ok(());
    }
}
