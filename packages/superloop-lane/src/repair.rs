//! Reconcile the installed box inputs and report the boundary they define.

use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::build::{self, BuildRequest};
use crate::error::LaneError;
use crate::install::{self, InstallRequest};

pub struct RepairRequest {
    pub loop_name: String,
    pub dry_run: bool,
}

impl RepairRequest {
    /// Parse one loop and an optional preview flag.
    ///
    /// # Errors
    ///
    /// Refuses a missing loop or an extra argument.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let (loop_name, dry_run) = match args {
            [loop_name] => (loop_name, false),
            [loop_name, option] if option == "--dry-run" => (loop_name, true),
            _ => return Err(LaneError::input("repair-usage", "repair LOOP [--dry-run]")),
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        Ok(Self {
            loop_name: loop_name.clone(),
            dry_run,
        })
    }
}

fn report_text<'a>(report: &'a Value, key: &str) -> Result<&'a str, LaneError> {
    report[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LaneError::input("repair-build-report", format!("{key} is absent")))
}

fn pinned_build(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    let path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("image-build.json");
    let bytes = crate::pinned::read_private(
        owner_home,
        &path,
        Uid::effective().as_raw(),
        0o600,
        1_048_576,
    )?;
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("repair-build-report", error.to_string()))?;
    if report["schema"] != 1 || report["command"] != "build" {
        return Err(LaneError::input(
            "repair-build-report",
            "pinned image build report has an unknown form",
        ));
    }
    if report.get("codex_sha256").is_some() || report.get("claude_sha256").is_none() {
        build::image_program_from_report(&report)
            .map_err(|error| LaneError::input("repair-build-report", error.detail))?;
    }
    build::payload::check_claude_report(&report, false)?;
    let image = report_text(&report, "image_digest")?;
    if image.strip_prefix("sha256:").is_none_or(|hash| {
        hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err(LaneError::input(
            "repair-build-report",
            "pinned image ID is not a lowercase sha256 value",
        ));
    }
    Ok(report)
}

pub(crate) fn build_request(
    request: &RepairRequest,
    report: &Value,
) -> Result<BuildRequest, LaneError> {
    let environment = &report["build_environment"];
    let codex = |source: &Value, key: &str| -> Result<String, LaneError> {
        if report.get("codex_sha256").is_some() {
            Ok(report_text(source, key)?.to_owned())
        } else {
            Ok(String::new())
        }
    };
    build::payload::check_claude_report(report, report.get("codex_sha256").is_none())?;
    let claude = if report.get("claude_sha256").is_some() {
        Some(build::payload::ProgramInput {
            bin: PathBuf::from(report_text(environment, "claude_bin")?),
            version: report_text(report, "claude_version")?.to_owned(),
            sha256: report_text(report, "claude_sha256")?.to_owned(),
            source: report_text(report, "claude_source")?.to_owned(),
        })
    } else {
        None
    };
    Ok(BuildRequest {
        loop_name: request.loop_name.clone(),
        claude,
        base_image: report_text(report, "base_image")?.to_owned(),
        codex_bin: PathBuf::from(codex(environment, "codex_bin")?),
        codex_host_bin: PathBuf::from(codex(environment, "codex_host_bin")?),
        codex_version: codex(report, "codex_version")?,
        codex_sha256: codex(report, "codex_sha256")?,
        codex_host_sha256: codex(report, "codex_host_sha256")?,
        codex_source: codex(report, "codex_source")?,
        podman_bin: PathBuf::from(report_text(environment, "podman_bin")?),
        template_dir: PathBuf::from(report_text(environment, "template_dir")?),
        dry_run: request.dry_run,
    })
}

/// Hash only mount fields that are invariant across run paths and owner numbering.
///
/// # Errors
///
/// Refuses an absent entry set or a failed serialization.
pub(crate) fn inventory_entry_digest(inventory: &Value) -> Result<String, LaneError> {
    let projected = inventory["entries"]
        .as_array()
        .ok_or_else(|| LaneError::input("repair-boundary", "mount entries are absent"))?
        .iter()
        .map(|entry| {
            let mut row = serde_json::Map::new();
            for key in [
                "target",
                "kind",
                "access",
                "presence",
                "source_role",
                "mode",
            ] {
                row.insert(
                    key.to_owned(),
                    entry.get(key).cloned().unwrap_or(Value::Null),
                );
            }
            Value::Object(row)
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&projected)
        .map_err(|error| LaneError::operation("repair-boundary", error.to_string()))?;
    build::sha256_bytes(&bytes, Path::new("/"))
}

pub(crate) fn boundary_from_plan(document: &Value) -> Result<Value, LaneError> {
    crate::plan::verify_box_attestation(document)?;
    let inventory = &document["mount_inventory"];
    if inventory["version"] != 1 || !inventory["entries"].is_array() {
        return Err(LaneError::input(
            "repair-boundary",
            "version one mount entries are absent",
        ));
    }
    let digest = inventory_entry_digest(inventory)?;
    let resources = &document["resources"];
    for key in [
        "memory_bytes",
        "pids_max",
        "cpu_shares",
        "cpu_weight_requested",
    ] {
        if resources[key].as_u64().is_none_or(|value| value == 0) {
            return Err(LaneError::input(
                "repair-boundary",
                format!("recorded {key} is absent"),
            ));
        }
    }
    let options = document["box_gate"]["container_options"]
        .as_array()
        .ok_or_else(|| {
            LaneError::input("repair-boundary", "attested container options are absent")
        })?;
    let selected = |source: &[Value], prefixes: &[&str]| -> Vec<Value> {
        source
            .iter()
            .filter(|option| {
                option
                    .as_str()
                    .is_some_and(|word| prefixes.iter().any(|prefix| word.starts_with(prefix)))
            })
            .cloned()
            .collect()
    };
    let runtime = document["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("repair-boundary", "attested runtime vector is absent"))?;
    let image = document["image_digest"]
        .as_str()
        .ok_or_else(|| LaneError::input("repair-boundary", "attested image is absent"))?;
    let image_index = runtime
        .iter()
        .position(|word| word.as_str() == Some(image))
        .ok_or_else(|| LaneError::input("repair-boundary", "runtime image boundary is absent"))?;
    Ok(json!({
        "basis":"planned boundary of a new run",
        "mount_inventory":inventory,
        "mount_inventory_entries_sha256":digest,
        "limits":resources,
        "writable_leaves":document["box_gate"]["writable_leaves"],
        "namespaces":selected(&runtime[..image_index], &["--userns=", "--network=", "--pid=", "--ipc=", "--uts=", "--cgroupns="]),
        "capabilities":selected(options, &["--cap-drop=", "--security-opt=no-new-privileges"]),
        "root":document["box_gate"]["root"],
        "container_options":options
    }))
}

fn actions(build: &Value, install: &Value) -> Vec<Value> {
    let mut rows = Vec::new();
    if build["action"] == "repair-pin" {
        rows.push(json!({"component":"settings","action":"restore pinned image ID"}));
    }
    if build["would_seed_settings"]
        .as_array()
        .is_some_and(|settings| !settings.is_empty())
    {
        rows.push(json!({"component":"settings","action":"seed pinned backend program"}));
    }
    if build["would_backfill_exec_probe"] == true {
        rows.push(json!({"component":"build-report","action":"record measured exec probe"}));
    }
    if let Some(destinations) = install["destinations"].as_array() {
        for destination in destinations {
            if destination["action"] == "deferred" {
                continue;
            }
            if destination["complete"] == false
                || destination["exists"] == false
                || destination["would_update"] == true
                || destination["action"] == "retire"
            {
                rows.push(json!({"component":"installed-input","path":destination["path"],"action":if destination["action"] == "retire" {"retire"} else {"reconcile"}}));
            }
        }
    }
    rows
}

/// Compare and reconcile pinned image, template and units, then report the box boundary.
///
/// # Errors
///
/// Refuses an invalid build report, unsafe installed path or unrecoverable image ID.
pub fn run(owner_home: &Path, request: &RepairRequest) -> Result<Value, LaneError> {
    let lane_bin = std::env::current_exe()
        .map_err(|error| LaneError::operation("repair-program", error.to_string()))?;
    run_with_lane_bin(owner_home, request, &lane_bin, Path::new("/"), 0)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_with_lane_bin(
    owner_home: &Path,
    request: &RepairRequest,
    lane_bin: &Path,
    host_root: &Path,
    host_root_uid: u32,
) -> Result<Value, LaneError> {
    let began = Instant::now();
    let pinned = pinned_build(owner_home, &request.loop_name)?;
    let generation_path = owner_home
        .join(".config/loops")
        .join(&request.loop_name)
        .join("install-generation.json");
    let generation_bytes = crate::pinned::read_private(
        owner_home,
        &generation_path,
        Uid::effective().as_raw(),
        0o600,
        65_536,
    )?;
    let generation: Value = serde_json::from_slice(&generation_bytes)
        .map_err(|error| LaneError::input("repair-generation", error.to_string()))?;
    build::payload::check_claude_generation(&generation)?;
    if generation["schema"] != 1 {
        return Err(LaneError::input(
            "repair-generation",
            "installed generation has an unknown form",
        ));
    }
    if generation["phase"] != "complete" {
        return Err(LaneError::input(
            "repair-generation",
            "installed generation is not complete",
        ));
    }
    let proxy_bin = generation["proxy_bin"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LaneError::input("repair-generation", "proxy_bin is absent"))?;
    let unit_dir = generation["unit_dir"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            LaneError::input(
                "repair-generation",
                "unit directory is not recorded; run install --pilot",
            )
        })?;
    let settings =
        crate::settings::Settings::read(&generation_path.with_file_name("workers.toml"))?;
    let boundary = if settings.configures("codex") {
        let (plan, _) = crate::load_plan(owner_home, &request.loop_name, "repair", (0, 0))?;
        boundary_from_plan(&plan.document)?
    } else {
        json!({"basis":"unmeasured","reason":"Claude worker launch belongs to a later lane"})
    };
    let install_request = InstallRequest {
        loop_name: request.loop_name.clone(),
        pilot: true,
        scope: crate::install::InstallScope::Full,
        dry_run: request.dry_run,
        repair: true,
        podman_bin: None,
        data_dir: PathBuf::from(report_text(&pinned["build_environment"], "template_dir")?),
        proxy_bin: PathBuf::from(proxy_bin),
        unit_dir: Some(PathBuf::from(unit_dir)),
    };
    let mut install_preflight = install_request.clone();
    install_preflight.dry_run = true;
    let observed_install = install::run_repair_with_lane_bin(
        owner_home,
        &install_preflight,
        &pinned,
        &generation,
        lane_bin,
        host_root,
        host_root_uid,
    )?;
    if observed_install["blocked"] == true {
        let busy = observed_install["busy"].clone();
        if request.dry_run {
            return Ok(
                json!({"schema":1,"command":"repair","loop":request.loop_name,"dry_run":true,"blocked":true,"busy":busy,"would_change":[],"wall_seconds":began.elapsed().as_secs_f64()}),
            );
        }
        let holders = busy.as_array().map_or_else(
            || "an install lock holder".into(),
            |rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );
        return Err(LaneError::input("install-busy", holders));
    }
    let image = build::run_repair(
        owner_home,
        &build_request(request, &pinned)?,
        &pinned,
        &generation,
    )?;
    let installed = if request.dry_run {
        observed_install
    } else {
        install::run_repair_with_lane_bin(
            owner_home,
            &install_request,
            &pinned,
            &generation,
            lane_bin,
            host_root,
            host_root_uid,
        )?
    };
    let would_change = actions(&image, &installed);
    let image_changed = if request.dry_run {
        image["would_repair_image_pin"] == true
            || image["would_seed_settings"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
            || image["would_backfill_exec_probe"] == true
    } else {
        image["changed"] == true
    };
    let changed = u64::from(image_changed) + installed["changed"].as_u64().unwrap_or(0);
    Ok(
        json!({"schema":1,"command":"repair","loop":request.loop_name,"dry_run":request.dry_run,"changed":changed,"would_change":would_change,"image":{"action":image["action"],"pin":pinned["image_digest"],"local_image_available":image["local_image_available"]},"install":{"changed":installed["changed"],"destinations":installed["destinations"],"activation":installed["activation"]},"boundary":boundary,"wall_seconds":began.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    /// ´test:unit:repair-refuses-an-unrecorded-unit-directory-before-change´
    #[test]
    fn repair_refuses_an_unrecorded_unit_directory_before_change() {
        let fixture = tempfile::tempdir().expect("fixture");
        let home = fixture.path();
        let config = home.join(".config/loops/alpha");
        fs::create_dir_all(&config).expect("config");
        for directory in [
            home,
            &home.join(".config"),
            &home.join(".config/loops"),
            &config,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("directory mode");
        }
        let report = config.join("image-build.json");
        let generation = config.join("install-generation.json");
        fs::write(&report, serde_json::to_vec(&json!({"schema":1,"command":"build","image_digest":format!("sha256:{}", "a".repeat(64))})).expect("report JSON")).expect("report");
        fs::write(
            &generation,
            serde_json::to_vec(
                &json!({"schema":1,"phase":"complete","proxy_bin":"/fixture/proxy"}),
            )
            .expect("generation JSON"),
        )
        .expect("generation");
        for path in [&report, &generation] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("record mode");
        }
        let absent_program = run(
            home,
            &RepairRequest {
                loop_name: "alpha".into(),
                dry_run: true,
            },
        )
        .expect_err("repair refuses old build report");
        assert_eq!(absent_program.kind, "repair-build-report");
        assert_eq!(absent_program.detail, "codex_image_program is absent");
        fs::write(&report, serde_json::to_vec(&json!({"schema":1,"command":"build","image_digest":format!("sha256:{}", "a".repeat(64)),"codex_image_program":"/usr/libexec/superloop/codex"})).expect("current report JSON")).expect("current report");
        assert_eq!(
            run(
                home,
                &RepairRequest {
                    loop_name: "alpha".into(),
                    dry_run: true
                }
            )
            .expect_err("preview refuses old generation")
            .kind,
            "repair-generation"
        );
        let error = run(
            home,
            &RepairRequest {
                loop_name: "alpha".into(),
                dry_run: false,
            },
        )
        .expect_err("unrecorded unit directory");
        assert_eq!(error.kind, "repair-generation");
        assert!(error.detail.contains("unit directory is not recorded"));
        assert!(!home.join(".config/systemd").exists());
    }

    /// ´test:unit:repair-argument-shape-refuses-extra-options´
    #[test]
    fn repair_argument_shape_refuses_extra_options() {
        assert!(RepairRequest::parse(&["alpha".into()]).is_ok());
        assert!(RepairRequest::parse(&["alpha".into(), "--dry-run".into()]).is_ok());
        assert_eq!(
            RepairRequest::parse(&["alpha".into(), "--pilot".into()])
                .err()
                .expect("invalid option")
                .kind,
            "repair-usage"
        );
    }

    /// ´test:unit:repair-boundary-prints-the-pinned-entry-digest-and-controls´
    #[test]
    fn repair_boundary_prints_the_pinned_entry_digest_and_controls() {
        let plan: Value = serde_json::from_str(include_str!("../tests/fixtures/plan.json"))
            .expect("fixture plan");
        let report = boundary_from_plan(&plan).expect("boundary");
        assert_eq!(report["mount_inventory"]["version"], 1);
        assert_eq!(report["limits"]["cpu_weight_requested"], 59);
        assert!(
            report["capabilities"]
                .as_array()
                .expect("capabilities")
                .contains(&json!("--cap-drop=ALL"))
        );
        assert!(
            report["namespaces"]
                .as_array()
                .expect("namespaces")
                .contains(&json!("--network=none"))
        );
        assert!(
            report["namespaces"]
                .as_array()
                .expect("namespaces")
                .contains(&json!("--cgroupns=private"))
        );
        assert_eq!(
            report["writable_leaves"].as_array().expect("leaves").len(),
            4
        );
        assert_eq!(
            report["mount_inventory_entries_sha256"],
            "07eb7c692be74b1f59c7894857e79edf2cf535193e716e9cc46b93727327b812"
        );
        let mut another_run = plan["mount_inventory"].clone();
        another_run["entries"][1]["owner"] = json!(3001);
        another_run["entries"][1]["source"] = json!("~/another-run");
        assert_eq!(
            inventory_entry_digest(&another_run).expect("run-independent digest"),
            report["mount_inventory_entries_sha256"]
        );
    }
}
