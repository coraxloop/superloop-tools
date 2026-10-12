use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::fstat;

use crate::error::LaneError;
use crate::home::{pin_parent, pin_parent_beneath};

pub const MAX_SETTINGS: u64 = 65_536;

#[derive(Clone, Debug)]
pub struct Settings {
    pub runs_root: Option<PathBuf>,
    pub backend_argv: std::collections::BTreeMap<String, Vec<String>>,
    pub driver_argv: Vec<String>,
    pub entry_bin: Option<PathBuf>,
    pub driver_bin: Option<PathBuf>,
    pub image_digest: Option<String>,
    pub template_dir: Option<PathBuf>,
    pub resources: Option<Resources>,
    pub socket_dir: Option<PathBuf>,
    pub vendor_hosts: std::collections::BTreeMap<String, Vec<String>>,
    pub sandbox_mode: String,
    pub context_threshold: Option<f64>,
    pub retention: String,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct Resources {
    pub memory_bytes: u64,
    pub pids_max: u32,
    pub cpu_shares: u32,
}

impl Resources {
    /// Return the cgroup v2 weight requested through the runtime's CPU shares conversion.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn cpu_weight_requested(&self) -> u32 {
        let logarithm = f64::from(self.cpu_shares).log2();
        (10_f64
            .powf(logarithm.mul_add(125.0, logarithm * logarithm) / 612.0 - 7.0 / 34.0)
            .ceil() as u32)
            .clamp(1, 10_000)
    }
}

fn absolute(value: &str, key: &'static str) -> Result<PathBuf, LaneError> {
    let path = Path::new(value);
    if !path.is_absolute()
        || value.contains(',')
        || value.split('/').any(|part| part == "." || part == "..")
    {
        return Err(LaneError::input(
            "bad-setting",
            format!("{key} must be an absolute path without dotted components or commas: {value}"),
        ));
    }
    Ok(path.to_path_buf())
}

fn number(table: &toml::Table, key: &'static str) -> Result<u32, LaneError> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| LaneError::input("bad-setting", format!("missing or invalid {key}")))
}

fn page_aligned_memory(memory_bytes: u64) -> Result<u64, LaneError> {
    // The kernel stores memory.max in whole pages, so a requested value must round-trip.
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .and_then(|size| u64::try_from(size).ok())
        .filter(|size| *size > 0)
        .ok_or_else(|| LaneError::input("bad-setting", "system page size is unavailable"))?;
    if !memory_bytes.is_multiple_of(page_size) {
        return Err(LaneError::input(
            "bad-setting",
            format!("resources.memory_bytes must be a multiple of page size {page_size}"),
        ));
    }
    Ok(memory_bytes)
}

fn bounded_cpu_shares(resources: &toml::Table) -> Result<u32, LaneError> {
    let shares = number(resources, "cpu_shares")?;
    if !(2..=262_144).contains(&shares) {
        return Err(LaneError::input(
            "bad-setting",
            "resources.cpu_shares must be between 2 and 262144",
        ));
    }
    Ok(shares)
}

fn optional_path(table: &toml::Table, key: &'static str) -> Result<Option<PathBuf>, LaneError> {
    table
        .get(key)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| LaneError::input("bad-setting", format!("{key} must be a string")))
                .and_then(|text| absolute(text, key))
        })
        .transpose()
}

fn vendor_table(
    table: &toml::Table,
    key: &'static str,
    paths: bool,
) -> Result<std::collections::BTreeMap<String, Vec<String>>, LaneError> {
    let Some(value) = table.get(key) else {
        return Ok(std::collections::BTreeMap::new());
    };
    let entries = value
        .as_table()
        .ok_or_else(|| LaneError::input("bad-setting", format!("{key} must be an inline table")))?;
    let mut result = std::collections::BTreeMap::new();
    for (vendor, values) in entries {
        if !["codex", "claude"].contains(&vendor.as_str()) {
            return Err(LaneError::input(
                "bad-setting",
                format!("{key} has unknown vendor {vendor}"),
            ));
        }
        let list = values.as_array().ok_or_else(|| {
            LaneError::input("bad-setting", format!("{key}.{vendor} must be an array"))
        })?;
        let mut parsed = Vec::new();
        for value in list {
            let text = value.as_str().ok_or_else(|| {
                LaneError::input(
                    "bad-setting",
                    format!("{key}.{vendor} must contain strings"),
                )
            })?;
            if paths && parsed.is_empty() {
                absolute(text, key)?;
            }
            if !paths && (!valid_host(text) || parsed.iter().any(|prior| prior == text)) {
                return Err(LaneError::input(
                    "bad-setting",
                    format!("{key}.{vendor} has an invalid or repeated hostname: {text}"),
                ));
            }
            parsed.push(text.to_owned());
        }
        if paths && parsed.is_empty() {
            return Err(LaneError::input(
                "bad-setting",
                format!("{key}.{vendor} must be nonempty"),
            ));
        }
        result.insert(vendor.clone(), parsed);
    }
    Ok(result)
}

fn valid_host(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_lowercase()
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn grant_refusal(error: &loop_home::LoopError) -> LaneError {
    let message = error.message();
    let detail = message.strip_prefix("settings-grant: ").unwrap_or(message);
    LaneError::input("settings-grant", detail)
}

fn attempt_wall_seconds(table: &toml::Table) -> Result<Option<u64>, LaneError> {
    table
        .get("attempt_wall_seconds")
        .map(|value| {
            value
                .as_integer()
                .and_then(|seconds| u64::try_from(seconds).ok())
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| {
                    LaneError::input(
                        "attempt-wall",
                        "attempt_wall_seconds must be a positive integer",
                    )
                })
        })
        .transpose()
}

pub(crate) fn split_local_policies(
    source: &str,
) -> Result<(String, Option<f64>, String), LaneError> {
    let mut table: toml::Table = toml::from_str(source)
        .map_err(|error| LaneError::input("settings-toml", error.to_string()))?;
    attempt_wall_seconds(&table)?;
    table.remove("attempt_wall_seconds");
    let threshold = table
        .remove("context_threshold")
        .map(|value| {
            value
                .as_float()
                .filter(|fraction| fraction.is_finite() && *fraction > 0.0 && *fraction < 1.0)
                .ok_or_else(|| {
                    LaneError::input(
                        "context-threshold",
                        "context_threshold must be a finite fraction above zero and below one",
                    )
                })
        })
        .transpose()?;
    let retention = table
        .remove("retention")
        .map(|value| {
            if value.as_str() == Some("keep") {
                Ok(String::from("keep"))
            } else {
                Err(LaneError::input(
                    "retention-policy",
                    "retention must be keep",
                ))
            }
        })
        .transpose()?
        .unwrap_or_else(|| String::from("keep"));
    let validated_source = toml::to_string(&table)
        .map_err(|error| LaneError::input("settings-toml", error.to_string()))?;
    Ok((validated_source, threshold, retention))
}

impl Settings {
    /// Read the optional positive attempt wall from the local worker policy.
    ///
    /// # Errors
    /// Refuses malformed settings or an invalid explicit wall.
    pub(crate) fn attempt_wall_seconds(&self) -> Result<Option<u64>, LaneError> {
        let table = toml::from_str(&self.source)
            .map_err(|error| LaneError::input("settings-toml", error.to_string()))?;
        attempt_wall_seconds(&table)
    }

    /// Report whether the settings name a vendor in either supported map.
    #[must_use]
    pub fn configures(&self, vendor: &str) -> bool {
        self.backend_argv.contains_key(vendor) || self.vendor_hosts.contains_key(vendor)
    }

    /// Check that the settings do not widen the selected registry runs root.
    ///
    /// # Errors
    ///
    /// Refuses a widened runs root or an unconfigured default driver.
    pub fn validate_grant(&self, home: &Path, loop_name: &str) -> Result<(), LaneError> {
        let registry_path =
            loop_home::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
        let registry = loop_home::load_registry(&registry_path)
            .map_err(|error| LaneError::input("registry-row", error.message()))?;
        let row = registry
            .row(loop_name, home)
            .map_err(|error| LaneError::input("registry-row", error.message()))?;
        let (validated_source, _, _) = split_local_policies(&self.source)?;
        let table = loop_home::workers_settings::validate_workers_settings(
            &validated_source,
            Path::new("workers.toml"),
        )
        .map_err(|error| grant_refusal(&error))?;
        loop_home::workers_settings::validate_workers_grant(
            &table,
            &row,
            registry.runs_root(loop_name),
        )
        .map_err(|error| grant_refusal(&error))
    }

    /// Read one bounded, regular, link-free settings file and validate every key.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable file, invalid values, or any unknown setting.
    pub fn read(path: &Path) -> Result<Self, LaneError> {
        Self::read_with_prefix(path, None)
    }

    /// Read private settings beneath a prefix verified by the host owner.
    ///
    /// # Errors
    ///
    /// Refuses an unsafe descendant or invalid settings file.
    pub fn read_beneath(path: &Path, verified_prefix: &Path) -> Result<Self, LaneError> {
        Self::read_with_prefix(path, Some(verified_prefix))
    }

    #[allow(clippy::too_many_lines)]
    fn read_with_prefix(path: &Path, verified_prefix: Option<&Path>) -> Result<Self, LaneError> {
        let owner = nix::unistd::Uid::effective().as_raw();
        let parent_path = path.parent().ok_or_else(|| {
            LaneError::input("settings-read", format!("{} has no parent", path.display()))
        })?;
        let parent = if let Some(prefix) = verified_prefix {
            pin_parent_beneath(parent_path, prefix, owner)?
        } else {
            pin_parent(parent_path, owner)?
        };
        let parent_stat = fstat(&parent).map_err(|error| {
            LaneError::input(
                "settings-read",
                format!("{}: {error}", parent_path.display()),
            )
        })?;
        if parent_stat.st_mode & 0o7777 != 0o700 {
            return Err(LaneError::input(
                "settings-owner",
                format!("{}: expected mode 0700", parent_path.display()),
            ));
        }
        let name = path.file_name().ok_or_else(|| {
            LaneError::input("settings-read", format!("{} has no name", path.display()))
        })?;
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        let file = File::from(openat2(&parent, name, how).map_err(|error| {
            if error == Errno::ENOENT
                && path.file_name().is_some_and(|name| name == "workers.toml")
                && std::fs::symlink_metadata(parent_path.join("box.toml")).is_ok()
            {
                return LaneError::input(
                    "settings-read",
                    format!(
                        "{} is missing; rename box.toml to workers.toml",
                        path.display()
                    ),
                );
            }
            LaneError::input("settings-read", format!("{}: {error}", path.display()))
        })?);
        let meta = file.metadata().map_err(|error| {
            LaneError::input("settings-read", format!("{}: {error}", path.display()))
        })?;
        if !meta.is_file() {
            return Err(LaneError::input(
                "settings-kind",
                format!("{} is not a regular file", path.display()),
            ));
        }
        if meta.uid() != owner || meta.mode() & 0o7777 != 0o600 {
            return Err(LaneError::input(
                "settings-owner",
                format!(
                    "{}: uid {} mode {:04o}; expected uid {owner} mode 0600",
                    path.display(),
                    meta.uid(),
                    meta.mode() & 0o7777
                ),
            ));
        }
        if meta.len() > MAX_SETTINGS {
            return Err(LaneError::input(
                "settings-size",
                format!("{} exceeds {MAX_SETTINGS} bytes", path.display()),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_SETTINGS + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                LaneError::input("settings-read", format!("{}: {error}", path.display()))
            })?;
        if bytes.len() as u64 > MAX_SETTINGS {
            return Err(LaneError::input(
                "settings-size",
                format!("{} exceeds {MAX_SETTINGS} bytes", path.display()),
            ));
        }
        Self::from_private_bytes(bytes, path)
    }

    /// Parse bytes already read from one pinned private settings inode.
    ///
    /// # Errors
    ///
    /// Refuses oversized, malformed, or unknown settings.
    pub(crate) fn from_private_bytes(bytes: Vec<u8>, path: &Path) -> Result<Self, LaneError> {
        if bytes.len() as u64 > MAX_SETTINGS {
            return Err(LaneError::input(
                "settings-size",
                format!("{} exceeds {MAX_SETTINGS} bytes", path.display()),
            ));
        }
        let source = String::from_utf8(bytes).map_err(|_| {
            LaneError::input("settings-utf8", format!("{} is not UTF-8", path.display()))
        })?;
        let (validated_source, context_threshold, retention) = split_local_policies(&source)?;
        let table = loop_home::workers_settings::validate_workers_settings(&validated_source, path)
            .map_err(|error| {
                let (kind, detail) = error
                    .message()
                    .split_once(": ")
                    .unwrap_or_else(|| ("bad-setting", error.message()));
                LaneError::input(
                    match kind {
                        "settings-toml" => "settings-toml",
                        "unknown-setting" => "unknown-setting",
                        "retired-setting" => "retired-setting",
                        _ => "bad-setting",
                    },
                    detail,
                )
            })?;
        let image_digest = table
            .get("image_digest")
            .map(|value| {
                let image_digest = value.as_str().ok_or_else(|| {
                    LaneError::input("bad-setting", "image_digest must be a string")
                })?;
                if image_digest.len() != 71
                    || !image_digest.starts_with("sha256:")
                    || !image_digest[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(LaneError::input(
                        "bad-setting",
                        "image_digest must be sha256: followed by 64 lowercase hex digits",
                    ));
                }
                Ok(image_digest.to_owned())
            })
            .transpose()?;
        let resources = table
            .get("resources")
            .map(|value| {
                let resources = value.as_table().ok_or_else(|| {
                    LaneError::input("bad-setting", "resources must be an inline table")
                })?;
                if let Some(key) = resources
                    .keys()
                    .find(|key| !["memory_bytes", "pids_max", "cpu_shares"].contains(&key.as_str()))
                {
                    return Err(LaneError::input(
                        "unknown-setting",
                        format!("resources.{key}"),
                    ));
                }
                let memory_bytes = resources
                    .get("memory_bytes")
                    .and_then(toml::Value::as_integer)
                    .and_then(|value| u64::try_from(value).ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        LaneError::input("bad-setting", "missing or invalid resources.memory_bytes")
                    })?;
                Ok(Resources {
                    memory_bytes: page_aligned_memory(memory_bytes)?,
                    pids_max: number(resources, "pids_max")?,
                    cpu_shares: bounded_cpu_shares(resources)?,
                })
            })
            .transpose()?;
        let driver_argv = configured_driver(&table)?;
        let driver_bin = driver_argv.first().map(PathBuf::from);
        Ok(Self {
            runs_root: optional_path(&table, "runs_root")?,
            backend_argv: vendor_table(&table, "backend_argv", true)?,
            driver_argv,
            entry_bin: optional_path(&table, "entry_bin")?,
            driver_bin,
            image_digest,
            template_dir: optional_path(&table, "template_dir")?,
            resources,
            socket_dir: optional_path(&table, "socket_dir")?,
            vendor_hosts: vendor_table(&table, "vendor_hosts", false)?,
            sandbox_mode: table
                .get("sandbox_mode")
                .and_then(toml::Value::as_str)
                .unwrap_or("danger-full-access")
                .to_owned(),
            context_threshold,
            retention,
            source,
        })
    }
}

fn configured_driver(table: &toml::Table) -> Result<Vec<String>, LaneError> {
    table
        .get("driver_argv")
        .map(|value| {
            loop_home::workers_settings::executable_argv(Some(value), "driver_argv")
                .map_err(|error| LaneError::input("bad-setting", error.message()))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

#[cfg(test)]
mod tests {
    use super::{Resources, bounded_cpu_shares, page_aligned_memory, split_local_policies};

    /// ´test:unit:cpu-weight-conversion-preserves-runtime-boundaries´
    #[test]
    fn cpu_weight_conversion_preserves_runtime_boundaries() {
        let mut resources = Resources {
            memory_bytes: 2_147_483_648,
            pids_max: 128,
            cpu_shares: 2,
        };
        assert_eq!(resources.cpu_weight_requested(), 1);
        resources.cpu_shares = 512;
        assert_eq!(resources.cpu_weight_requested(), 59);
        resources.cpu_shares = 1024;
        assert_eq!(resources.cpu_weight_requested(), 100);
        resources.cpu_shares = 262_144;
        assert_eq!(resources.cpu_weight_requested(), 10_000);
    }

    /// ´test:unit:resource-setting-refusals-name-invalid-limits´
    #[test]
    fn resource_setting_refusals_name_invalid_limits() {
        let unaligned = page_aligned_memory(2_147_483_649).expect_err("unaligned memory");
        assert_eq!(unaligned.kind, "bad-setting");
        assert!(unaligned.line().contains("resources.memory_bytes"));
        assert_eq!(
            page_aligned_memory(2_147_483_648).expect("aligned memory"),
            2_147_483_648
        );
        for shares in [1, 262_145] {
            let table: toml::Table = format!("cpu_shares = {shares}")
                .parse()
                .expect("fixture settings table");
            let invalid = bounded_cpu_shares(&table).expect_err("shares outside runtime range");
            assert_eq!(invalid.kind, "bad-setting");
            assert!(invalid.line().contains("resources.cpu_shares"));
        }
    }

    /// ´test:unit:context-threshold-stays-below-window´
    #[test]
    fn context_threshold_stays_below_window() {
        let (source, threshold, retention) =
            split_local_policies("context_threshold = 0.8\n").expect("bounded threshold");
        assert_eq!(threshold, Some(0.8));
        assert_eq!(retention, "keep");
        assert!(!source.contains("context_threshold"));
        for value in ["0.0", "1.0", "-0.2", "2", "\"0.8\""] {
            let source = format!("context_threshold = {value}\n");
            assert_eq!(
                split_local_policies(&source)
                    .expect_err("invalid threshold")
                    .kind,
                "context-threshold"
            );
        }
    }

    /// ´test:unit:retention-defaults-to-keep-and-refuses-other-policies´
    #[test]
    fn retention_defaults_to_keep_and_refuses_other_policies() {
        let (source, _, retention) =
            split_local_policies("retention = \"keep\"\n").expect("keep policy");
        assert_eq!(retention, "keep");
        assert!(!source.contains("retention"));
        for value in ["\"prune\"", "2", "true"] {
            assert_eq!(
                split_local_policies(&format!("retention = {value}\n"))
                    .expect_err("unsupported policy")
                    .kind,
                "retention-policy"
            );
        }
    }
}
