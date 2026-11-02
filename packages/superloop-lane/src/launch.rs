use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{SFlag, fstat};
use nix::unistd::{Gid, Uid, fchownat};
use serde_json::{Value, json};

use crate::build::{self, executable, sha256};
use crate::container_helper::ProcessPresence;
use crate::error::LaneError;
use crate::home;
use crate::plan::{Plan, protected_identifier_path, protected_identity_dir};
use crate::settings::Settings;
use crate::{load_plan, valid_run_name};

pub mod admission;
pub mod bound_roots;
pub mod census;
pub mod checkout;
pub mod checkpoint;
pub mod driver_report;
pub mod exercise;
pub(crate) mod exercise_resources;
pub mod follow;
pub mod harvest;
pub mod imports;
pub mod letters;
pub mod matrix;
pub mod network_evidence;
pub(crate) mod probe;
pub mod reaping;
pub mod repin_door;
pub mod replies;
pub mod report;
pub mod retire;
pub mod rotation;
pub mod rounds;
pub(crate) mod seed;
pub mod settle;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeclaredSource {
    pub name: String,
    pub seed: Option<String>,
}

/// Read the validated loop identity from a reservation's plan.
///
/// # Errors
///
/// Refuses a missing plan or conflicting owner rows.
pub(crate) fn recorded_loop_uid(record: &Value) -> Result<u32, LaneError> {
    let document = record
        .get("plan")
        .ok_or_else(|| LaneError::input("loop-identity", "plan is absent"))?;
    crate::plan::loop_uid(document)
}

/// Read bounded source names from the opening declarations of a dispatch letter.
///
/// # Errors
///
/// Refuses a repeated declaration, duplicate name, or a word outside the lane grammar.
pub(crate) fn declared_sources(letter: &[u8]) -> Result<Vec<DeclaredSource>, LaneError> {
    let text = std::str::from_utf8(letter)
        .map_err(|_| LaneError::input("letter-sources", "letter is not UTF-8"))?;
    let mut sources = None;
    for line in text.lines().take(16) {
        let line = line.trim().trim_start_matches("- ");
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("sources") {
            continue;
        }
        if sources.is_some() {
            return Err(LaneError::input("letter-sources", "Sources is repeated"));
        }
        let names = value.split_ascii_whitespace().collect::<Vec<_>>();
        if names.len() > 16 {
            return Err(LaneError::input(
                "letter-sources",
                "Sources exceeds 16 names",
            ));
        }
        let mut unique = BTreeSet::new();
        let mut parsed = Vec::new();
        for word in names {
            let (name, seed) = match word.split_once('@') {
                Some((name, seed)) => (name, Some(seed)),
                None => (word, None),
            };
            if !valid_run_name(name) || !unique.insert(name) {
                return Err(LaneError::input(
                    "letter-sources",
                    format!("{name} is not a distinct plain lane word"),
                ));
            }
            if let Some(seed) = seed
                && (seed.len() != 40 || !seed.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(LaneError::input(
                    "letter-sources",
                    format!("{name}: seed is not a full forty-character object ID"),
                ));
            }
            parsed.push(DeclaredSource {
                name: name.to_owned(),
                seed: seed.map(str::to_ascii_lowercase),
            });
        }
        sources = Some(parsed);
    }
    Ok(sources.unwrap_or_default())
}

fn driver_report_for_reader(output: &str) -> String {
    let mut delivered = BTreeSet::new();
    let mut shown = String::new();
    for line in output.split_inclusive('\n') {
        if line.starts_with("LETTER ")
            && let Some(id) = line
                .split_ascii_whitespace()
                .find_map(|field| field.strip_prefix("id="))
            && !delivered.insert(id.to_owned())
        {
            continue;
        }
        shown.push_str(line);
    }
    shown
}

#[derive(Debug)]
pub struct LaunchRequest {
    pub loop_name: String,
    pub run: String,
    pub letter: PathBuf,
    pub round: Option<String>,
    pub budget: u64,
    pub dry_run: bool,
    pub expect_digest: Option<String>,
    pub observe: bool,
    pub podman_bin: PathBuf,
    pub proxy_bin: Option<PathBuf>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub door_scope: crate::door::Scope,
    pub(crate) rotation_source: Option<RotationSource>,
}

#[derive(Debug)]
pub(crate) struct RotationSource {
    pub descriptor: OwnedFd,
    pub digest: String,
}

fn rotation_source_bytes(
    descriptor: &OwnedFd,
    expected: &str,
    cwd: &Path,
    owner: u32,
) -> Result<Vec<u8>, LaneError> {
    let file = File::from(nix::unistd::dup(descriptor).map_err(|error| {
        LaneError::input("rotate-source", format!("source descriptor: {error}"))
    })?);
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("rotate-source", error.to_string()))?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.permissions().mode() & 0o7777 != 0o600
        || meta.len() > home::MAX_LETTER
    {
        return Err(LaneError::input(
            "rotate-source",
            "source descriptor is not a bounded owner-private regular file",
        ));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read_at(&mut buffer, bytes.len() as u64)
            .map_err(|error| LaneError::input("rotate-source", error.to_string()))?;
        if count == 0 {
            break;
        }
        let limit = usize::try_from(home::MAX_LETTER)
            .map_err(|error| LaneError::input("rotate-source", error.to_string()))?;
        if bytes.len() + count > limit {
            return Err(LaneError::input(
                "rotate-source",
                "source exceeds letter bound",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let actual = build::sha256_bytes(&bytes, cwd)?;
    if actual != expected {
        return Err(LaneError::input(
            "rotate-source",
            format!("expected digest {expected} differs from source digest {actual}"),
        ));
    }
    Ok(bytes)
}

fn rotation_child_refusal(error: LaneError) -> LaneError {
    if matches!(error.kind, "prepare-home" | "prepare-runtime")
        && let Some((_, detail)) = error.detail.split_once("rotate-source: expected digest ")
    {
        let detail = detail
            .split_once(" wall_seconds=")
            .map_or(detail, |(before, _)| before);
        return LaneError::input("rotate-source", format!("expected digest {detail}"));
    }
    error
}

pub(crate) fn pin_rotation_source_at(
    parent: &File,
    name: &str,
    expected: &str,
    owner_home: &Path,
    owner: u32,
) -> Result<RotationSource, LaneError> {
    let descriptor = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("rotate-source", format!("{name}: {error}")))?;
    rotation_source_bytes(&descriptor, expected, owner_home, owner)?;
    Ok(RotationSource {
        descriptor,
        digest: expected.to_owned(),
    })
}

impl LaunchRequest {
    /// Parse the one-run launch form.
    ///
    /// # Errors
    ///
    /// Refuses an absent or repeated option and extra positional arguments.
    #[allow(clippy::too_many_lines)]
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "usage",
                "launch LOOP RUN {--letter FILE|--round STEP} [--budget SECONDS] [--model MODEL] [--effort EFFORT] [--door-scope {work|review}] [--dry-run] [--expect-digest HEX] [--observe] [--proxy-bin FILE]",
            ));
        };
        let mut letter = None;
        let mut round = None;
        let mut budget = None;
        let mut dry_run = false;
        let mut observe = false;
        let mut podman_bin = None;
        let mut proxy_bin = None;
        let mut model = None;
        let mut effort = None;
        let mut door_scope = None;
        let mut expect_digest = None;
        let mut index = 0;
        while index < rest.len() {
            match rest[index].as_str() {
                "--dry-run" if !dry_run => dry_run = true,
                "--observe" if !observe => observe = true,
                "--letter" | "--round" | "--budget" | "--podman-bin" | "--proxy-bin"
                | "--model" | "--effort" | "--door-scope" | "--expect-digest" => {
                    let option = rest[index].as_str();
                    let value = rest.get(index + 1).ok_or_else(|| {
                        LaneError::input("usage", format!("{option} needs a value"))
                    })?;
                    let slot = match option {
                        "--letter" => &mut letter,
                        "--round" => &mut round,
                        "--budget" => &mut budget,
                        "--podman-bin" => &mut podman_bin,
                        "--proxy-bin" => &mut proxy_bin,
                        "--model" => &mut model,
                        "--door-scope" => &mut door_scope,
                        "--expect-digest" => &mut expect_digest,
                        _ => &mut effort,
                    };
                    if slot.replace(value.clone()).is_some() {
                        return Err(LaneError::input("usage", format!("{option} repeated")));
                    }
                    index += 1;
                }
                other => {
                    return Err(LaneError::input(
                        "usage",
                        format!("unexpected launch argument {other}"),
                    ));
                }
            }
            index += 1;
        }
        if expect_digest.as_ref().is_some_and(|digest: &String| {
            digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) || (dry_run && expect_digest.is_some())
        {
            return Err(LaneError::input(
                "settlement-digest",
                "use a 64-digit preview digest on apply, not with --dry-run",
            ));
        }
        if letter.is_some() == round.is_some() {
            return Err(LaneError::input(
                "usage",
                "select exactly one of --letter and --round",
            ));
        }
        if let Some(step) = round.as_deref() {
            letters::valid_step(step)?;
            if model.is_some() || effort.is_some() || observe || door_scope.is_some() {
                return Err(LaneError::input(
                    "round-selection",
                    "resume uses the recorded model, effort and observation mode",
                ));
            }
        }
        let budget = budget.map_or(Ok(3600), |value: String| {
            value
                .parse::<u64>()
                .ok()
                .filter(|seconds| (1..=10_800).contains(seconds))
                .ok_or_else(|| {
                    LaneError::input("round-budget", "budget must be 1 through 10800 seconds")
                })
        })?;
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            letter: letter.map_or_else(PathBuf::new, PathBuf::from),
            round,
            budget,
            dry_run,
            expect_digest,
            observe,
            podman_bin: podman_bin.map_or_else(|| PathBuf::from("/usr/bin/podman"), PathBuf::from),
            proxy_bin: proxy_bin.map(PathBuf::from),
            model,
            effort,
            door_scope: match door_scope.as_deref() {
                Some("work") => crate::door::Scope::Work,
                None | Some("review") => crate::door::Scope::Review,
                Some(_) => {
                    return Err(LaneError::input(
                        "door-scope",
                        "scope must be work or review",
                    ));
                }
            },
            rotation_source: None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct LaunchModel {
    model: String,
    effort: String,
    model_source: &'static str,
    effort_source: &'static str,
}

impl LaunchModel {
    fn select(
        letter: &[u8],
        model_flag: Option<&str>,
        effort_flag: Option<&str>,
    ) -> Result<Self, LaneError> {
        let text = std::str::from_utf8(letter)
            .map_err(|_| LaneError::input("letter-model", "letter is not UTF-8"))?;
        let mut declared_model = None;
        let mut declared_effort = None;
        for line in text.lines().take(16) {
            let line = line.trim().trim_start_matches("- ");
            let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) else {
                continue;
            };
            let key = key.trim();
            let slot = if key.eq_ignore_ascii_case("model") {
                Some(&mut declared_model)
            } else if key.eq_ignore_ascii_case("effort")
                || key.eq_ignore_ascii_case("reasoning effort")
            {
                Some(&mut declared_effort)
            } else {
                None
            };
            if let Some(slot) = slot
                && slot.replace(value.trim().to_owned()).is_some()
            {
                return Err(LaneError::input(
                    "letter-model",
                    format!("{key} is repeated in the opening declaration"),
                ));
            }
        }
        let model_source = if declared_model.is_some() {
            "letter"
        } else {
            "launch-flag"
        };
        let effort_source = if declared_effort.is_some() {
            "letter"
        } else {
            "launch-flag"
        };
        let model = declared_model
            .or_else(|| model_flag.map(str::to_owned))
            .ok_or_else(|| {
                LaneError::input("letter-model", "model is absent from letter and --model")
            })?;
        let effort = declared_effort
            .or_else(|| effort_flag.map(str::to_owned))
            .ok_or_else(|| {
                LaneError::input("letter-model", "effort is absent from letter and --effort")
            })?;
        if model.is_empty()
            || model.len() > 80
            || !model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        {
            return Err(LaneError::input(
                "letter-model",
                "model is not a bounded slug",
            ));
        }
        if !["low", "medium", "high", "xhigh", "max", "ultra"].contains(&effort.as_str()) {
            return Err(LaneError::input(
                "letter-model",
                "effort is not a supported level",
            ));
        }
        Ok(Self {
            model,
            effort,
            model_source,
            effort_source,
        })
    }

    fn record(&self) -> Value {
        json!({"model":self.model,"effort":self.effort,"model_source":self.model_source,"effort_source":self.effort_source})
    }
}

pub struct RecordHostsRequest {
    pub loop_name: String,
    pub run: String,
    pub hosts: Vec<String>,
    pub reviewed_pool: bool,
    pub dry_run: bool,
    pub list: bool,
    pub podman_bin: PathBuf,
}

impl RecordHostsRequest {
    /// Parse selected observed hosts for one loop.
    ///
    /// # Errors
    ///
    /// Refuses an empty selection or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "usage",
                "record-hosts LOOP RUN {--list|--host HOST [--host HOST...] [--reviewed-pool]} [--dry-run]",
            ));
        };
        let mut hosts = Vec::new();
        let mut reviewed_pool = false;
        let mut dry_run = false;
        let mut list = false;
        let mut podman_bin = None;
        let mut index = 0;
        while index < rest.len() {
            match rest[index].as_str() {
                "--dry-run" if !dry_run => dry_run = true,
                "--list" if !list => list = true,
                "--reviewed-pool" if !reviewed_pool => reviewed_pool = true,
                "--host" | "--podman-bin" => {
                    let option = rest[index].as_str();
                    let value = rest.get(index + 1).ok_or_else(|| {
                        LaneError::input("usage", format!("{option} needs a value"))
                    })?;
                    if option == "--host" {
                        if hosts.contains(value) {
                            return Err(LaneError::input(
                                "host-list",
                                format!("{value} is repeated"),
                            ));
                        }
                        hosts.push(value.clone());
                    } else if podman_bin.replace(value.clone()).is_some() {
                        return Err(LaneError::input("usage", "--podman-bin repeated"));
                    }
                    index += 1;
                }
                other => {
                    return Err(LaneError::input(
                        "usage",
                        format!("unexpected record-hosts argument {other}"),
                    ));
                }
            }
            index += 1;
        }
        if hosts.is_empty() && !list {
            return Err(LaneError::input(
                "host-list",
                "at least one --host is required",
            ));
        }
        if list && (!hosts.is_empty() || dry_run || reviewed_pool) {
            return Err(LaneError::input(
                "usage",
                "--list cannot select hosts or use --dry-run",
            ));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            hosts,
            reviewed_pool,
            dry_run,
            list,
            podman_bin: podman_bin.map_or_else(|| PathBuf::from("/usr/bin/podman"), PathBuf::from),
        })
    }
}

fn settings_path(owner_home: &Path, loop_name: &str) -> PathBuf {
    owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("workers.toml")
}

fn installed_generation(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    let path = settings_path(owner_home, loop_name).with_file_name("install-generation.json");
    let record = crate::install::read_generation(&path)?.ok_or_else(|| {
        LaneError::input(
            "install-generation",
            format!("{} is absent", path.display()),
        )
    })?;
    if record["phase"] != "complete" {
        return Err(LaneError::input(
            "install-generation",
            "pilot generation is incomplete",
        ));
    }
    Ok(record)
}

fn installed_proxy(owner_home: &Path, request: &LaunchRequest) -> Result<PathBuf, LaneError> {
    let record = installed_generation(owner_home, &request.loop_name)?;
    let recorded = record["proxy_bin"].as_str().ok_or_else(|| {
        LaneError::input(
            "install-generation",
            "proxy_bin is absent; repeat install --pilot",
        )
    })?;
    let digest = record["proxy_sha256"].as_str().ok_or_else(|| {
        LaneError::input(
            "install-generation",
            "proxy_sha256 is absent; repeat install --pilot",
        )
    })?;
    let selected = request
        .proxy_bin
        .as_deref()
        .unwrap_or_else(|| Path::new(recorded));
    crate::pinned::owner_executable_word(selected, Uid::effective().as_raw())?;
    if sha256(selected)? != digest {
        return Err(LaneError::input(
            "proxy-program",
            "proxy executable differs from the pilot generation",
        ));
    }
    Ok(selected.to_path_buf())
}

pub(crate) fn launch_environment(owner_home: &Path) -> Result<BTreeMap<String, String>, LaneError> {
    let mut environment = build::podman_environment(owner_home)?;
    if let Some(registry) = std::env::var_os("ENTER_LOOP_REGISTRY") {
        let path = PathBuf::from(registry);
        if !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(LaneError::input(
                "registry-path",
                format!(
                    "{} is not an absolute link-free registry path",
                    path.display()
                ),
            ));
        }
        environment.insert(
            "ENTER_LOOP_REGISTRY".into(),
            crate::pinned::path_word(&path, "registry-path")?,
        );
    }
    Ok(environment)
}

fn driver_runtime_contract(
    driver: &Path,
    owner_home: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<&'static str, LaneError> {
    let answer = build::run_checked(
        driver,
        [
            "driver",
            "start",
            "--backend",
            "codex",
            "--runtime-contract",
        ]
        .map(str::to_owned)
        .to_vec(),
        environment,
        owner_home,
        5,
        "driver-contract",
    )
    .map_err(|error| {
        LaneError::input(
            "driver-contract",
            format!("{}: {}", driver.display(), error.detail),
        )
    })?;
    if answer.trim() != "boxed-runtime 1" {
        return Err(LaneError::input(
            "driver-contract",
            format!("{} does not implement boxed-runtime 1", driver.display()),
        ));
    }
    Ok("boxed-runtime 1")
}

pub(crate) fn private_podman_environment_from(
    owner_home: &Path,
    configured: Option<&str>,
    rootless_uid: Option<&str>,
) -> Result<BTreeMap<String, String>, LaneError> {
    let configured = configured
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| {
            LaneError::input(
                "namespace-environment",
                "_CONTAINERS_USERNS_CONFIGURED is absent or invalid",
            )
        })?;
    let rootless_uid = rootless_uid
        .filter(|value| value.parse::<u32>().is_ok())
        .ok_or_else(|| {
            LaneError::input(
                "namespace-environment",
                "_CONTAINERS_ROOTLESS_UID is absent or invalid",
            )
        })?;
    let mut environment = launch_environment(owner_home)?;
    environment.insert("_CONTAINERS_USERNS_CONFIGURED".into(), configured.into());
    environment.insert("_CONTAINERS_ROOTLESS_UID".into(), rootless_uid.into());
    Ok(environment)
}

pub(crate) fn private_podman_environment(
    owner_home: &Path,
) -> Result<BTreeMap<String, String>, LaneError> {
    private_podman_environment_from(
        owner_home,
        std::env::var("_CONTAINERS_USERNS_CONFIGURED")
            .ok()
            .as_deref(),
        std::env::var("_CONTAINERS_ROOTLESS_UID").ok().as_deref(),
    )
}

pub(crate) fn worker_range(owner_home: &Path, loop_name: &str) -> Result<(u32, u32), LaneError> {
    let block = home::read_allocations(owner_home)?
        .require(loop_name)
        .map_err(|error| LaneError::input("allocations", error.message()))?;
    let (base, count) = (block.base, block.count);
    if u64::from(base) + u64::from(count) - 1 > 65_535 {
        return Err(LaneError::input(
            "allocations",
            "worker UID range exceeds 65535",
        ));
    }
    Ok((base, count))
}

/// Resolve one live run from a peer UID through protected reservation inodes.
///
/// # Errors
///
/// Refuses a duplicate UID, changed reservation, or missing external scope.
pub(crate) fn door_registration(
    runs: &std::os::fd::OwnedFd,
    row: &Value,
    loop_name: &str,
    peer_uid: u32,
    block: (u32, u32),
    owner: u32,
) -> Result<crate::door::Registration, LaneError> {
    use nix::dir::Dir;
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;

    if peer_uid < block.0 || peer_uid >= block.0.saturating_add(block.1) {
        return Err(LaneError::input(
            "door-peer",
            "peer is outside the allocated block",
        ));
    }
    let mut names = Dir::openat(
        runs,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| LaneError::input("door-registration", error.to_string()))?;
    let mut selected = None;
    for entry in names.iter() {
        let entry =
            entry.map_err(|error| LaneError::input("door-registration", error.to_string()))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|error| LaneError::input("door-registration", error.to_string()))?;
        let Some(run) = name
            .strip_prefix(".reservation-")
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        if !crate::valid_run_name(run) {
            return Err(LaneError::input(
                "door-registration",
                "reservation name is invalid",
            ));
        }
        let (record, _) = checkout::read_record_bound(runs, run, owner)?;
        if record["worker_uid"] != peer_uid || record["phase"] != "started" {
            continue;
        }
        let registration = door_registration_from_record(row, loop_name, run, peer_uid, &record)?;
        if selected.is_some() {
            return Err(LaneError::input(
                "door-registration",
                "peer has two live runs",
            ));
        }
        selected = Some(registration);
    }
    selected.ok_or_else(|| LaneError::input("door-peer", "peer has no live registered run"))
}

pub(crate) fn door_registration_from_record(
    row: &Value,
    loop_name: &str,
    run: &str,
    peer_uid: u32,
    record: &Value,
) -> Result<crate::door::Registration, LaneError> {
    if record["loop"] != loop_name || record["run"] != run || record["worker_uid"] != peer_uid {
        return Err(LaneError::input(
            "door-registration",
            "reservation identity differs",
        ));
    }
    let scope = match record["door_scope"].as_str() {
        Some("work") => crate::door::Scope::Work,
        Some("review") => crate::door::Scope::Review,
        _ => {
            return Err(LaneError::input(
                "door-registration",
                "external scope is absent",
            ));
        }
    };
    crate::door::Registration::from_row(row, loop_name, run, peer_uid, scope)
}

pub(crate) fn door_probe_registration(
    runs: &std::os::fd::OwnedFd,
    row: &Value,
    loop_name: &str,
    run: &str,
    peer_uid: u32,
    block: (u32, u32),
    owner: u32,
) -> Result<crate::door::Registration, LaneError> {
    if peer_uid < block.0 || peer_uid >= block.0.saturating_add(block.1) {
        return Err(LaneError::input(
            "door-peer",
            "peer is outside the allocated block",
        ));
    }
    if !crate::valid_run_name(run) {
        return Err(LaneError::input(
            "door-registration",
            "probe run is invalid",
        ));
    }
    let (record, _) = checkout::read_record_bound(runs, run, owner)?;
    door_registration_from_record(row, loop_name, run, peer_uid, &record)
}

pub(crate) fn lock_runs_root(
    root: &Path,
    exclusive: bool,
    owner_uid: u32,
) -> Result<Flock<std::os::fd::OwnedFd>, LaneError> {
    let fd = home::pin_parent(root, owner_uid)?;
    let operation = if exclusive {
        FlockArg::LockExclusive
    } else {
        FlockArg::LockShared
    };
    Flock::lock(fd, operation).map_err(|(_fd, error)| {
        LaneError::operation("uid-lock", format!("{}: {error}", root.display()))
    })
}

pub(crate) fn lock_run_preparation(
    root: &Path,
    run: &str,
    owner_uid: u32,
) -> Result<Flock<fs::File>, LaneError> {
    let parent = home::pin_parent(root, owner_uid)?;
    let path = root.join(format!(".prepare-{run}.lock"));
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("launch-lease", "lock name is absent"))?;
    let file = openat2(
        &parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map(fs::File::from)
    .map_err(|error| LaneError::input("launch-lease", format!("{}: {error}", path.display())))?;
    let metadata = file.metadata().map_err(|error| {
        LaneError::input("launch-lease", format!("{}: {error}", path.display()))
    })?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(LaneError::input(
            "launch-lease",
            format!(
                "{} is not an owner-controlled preparation lock",
                path.display()
            ),
        ));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_file, error)| {
        LaneError::input("launch-busy", format!("{}: {error}", path.display()))
    })
}

pub(crate) fn lock_mailbox(
    root: &Path,
    run: &str,
    owner_uid: u32,
) -> Result<Flock<fs::File>, LaneError> {
    let parent = home::pin_parent(root, owner_uid)?;
    let path = root.join(format!(".letter-{run}.lock"));
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("letter-lock", "lock name is absent"))?;
    let file = openat2(
        &parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map(fs::File::from)
    .map_err(|error| LaneError::input("letter-lock", format!("{}: {error}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("letter-lock", error.to_string()))?;
    if !meta.is_file() || meta.uid() != owner_uid || meta.permissions().mode() & 0o7777 != 0o600 {
        return Err(LaneError::input(
            "letter-lock",
            "mailbox lock has foreign owner or mode",
        ));
    }
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_file, error)| LaneError::operation("letter-lock", error.to_string()))
}

pub(crate) fn lock_mailbox_at(
    root: &std::os::fd::OwnedFd,
    run: &str,
    owner_uid: u32,
) -> Result<Flock<fs::File>, LaneError> {
    let name = format!(".letter-{run}.lock");
    let file = openat2(
        root,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map(fs::File::from)
    .map_err(|error| LaneError::input("letter-lock", format!("{name}: {error}")))?;
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("letter-lock", error.to_string()))?;
    if !meta.is_file() || meta.uid() != owner_uid || meta.permissions().mode() & 0o7777 != 0o600 {
        return Err(LaneError::input(
            "letter-lock",
            "mailbox lock has foreign owner or mode",
        ));
    }
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_file, error)| LaneError::operation("letter-lock", error.to_string()))
}

pub(crate) fn reservation_path(root: &Path, run: &str) -> PathBuf {
    root.join(format!(".reservation-{run}.json"))
}

#[cfg(test)]
fn retire_dead_helper_sockets(
    driver_dir: &Path,
    record: &Value,
    owner_uid: u32,
) -> Result<Vec<PathBuf>, LaneError> {
    retire_dead_helper_sockets_with(
        driver_dir,
        record,
        owner_uid,
        crate::container_helper::process_presence,
    )
}

#[cfg(test)]
fn retire_dead_helper_sockets_with(
    driver_dir: &Path,
    record: &Value,
    owner_uid: u32,
    presence: impl FnOnce(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Vec<PathBuf>, LaneError> {
    let stale = inspect_dead_helper_sockets_with(driver_dir, record, owner_uid, presence)?;
    for (path, slot) in &stale {
        slot.remove().map_err(|error| {
            LaneError::operation("helper-socket", format!("{}: {error}", path.display()))
        })?;
    }
    Ok(stale.into_iter().map(|(path, _)| path).collect())
}

fn inspect_dead_helper_sockets_with(
    driver_dir: &Path,
    record: &Value,
    owner_uid: u32,
    presence: impl FnOnce(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Vec<(PathBuf, crate::SocketSlot)>, LaneError> {
    let helper_identity = match (
        record["helper_pid"].as_u64(),
        record["helper_start"].as_u64(),
    ) {
        (Some(pid), Some(start)) => Some((
            u32::try_from(pid)
                .map_err(|_| LaneError::input("helper-socket", "helper PID is invalid"))?,
            start,
        )),
        (None, None) => None,
        _ => {
            return Err(LaneError::input(
                "helper-socket",
                "helper identity is incomplete",
            ));
        }
    };
    if let Some((pid, start)) = helper_identity {
        match presence(pid, start) {
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "launch-busy",
                    "the earlier helper is still alive",
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "helper-socket",
                    "the earlier helper's absence cannot be established",
                ));
            }
            crate::container_helper::ProcessPresence::Absent => {}
        }
    }
    let sockets = [
        crate::container_helper::socket_path(driver_dir)?,
        crate::container_helper::control_socket_path(driver_dir)?,
    ];
    let mut stale = Vec::new();
    for path in sockets {
        let slot = crate::SocketSlot::pinned(&path, owner_uid)?;
        let meta = match slot.metadata() {
            Ok(Some(meta)) => meta,
            Ok(None) => continue,
            Err(error) => {
                return Err(LaneError::input(
                    "helper-socket",
                    format!("{}: {error}", path.display()),
                ));
            }
        };
        if helper_identity.is_none()
            || meta.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || meta.st_uid != owner_uid
        {
            return Err(LaneError::input(
                "helper-socket",
                format!("{} is not a socket of the dead helper", path.display()),
            ));
        }
        stale.push((path, slot));
    }
    Ok(stale)
}

pub(crate) const MAX_RESERVATION_BYTES: u64 = 4_194_304;

pub(crate) fn read_reservation(path: &Path) -> Result<Option<Value>, LaneError> {
    read_reservation_checked(path, true)
}

fn read_reservation_checked(path: &Path, check_node: bool) -> Result<Option<Value>, LaneError> {
    let opened = if home::private_is_active() {
        let parent = path
            .parent()
            .ok_or_else(|| LaneError::input("uid-table", "reservation parent is absent"))?;
        let pinned = home::pin_parent(parent, Uid::effective().as_raw())?;
        let name = path
            .file_name()
            .ok_or_else(|| LaneError::input("uid-table", "reservation name is absent"))?;
        openat2(
            &pinned,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map(fs::File::from)
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
    } else {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    };
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "uid-table",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("uid-table", format!("{}: {error}", path.display())))?;
    if !metadata.is_file()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > MAX_RESERVATION_BYTES
    {
        return Err(LaneError::input(
            "uid-table",
            format!("{} is not a private bounded reservation", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RESERVATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("uid-table", format!("{}: {error}", path.display())))?;
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("uid-table", format!("{}: {error}", path.display())))?;
    if record["schema"] != 1
        || ![
            "preparing",
            "started",
            "settled",
            "failed",
            "retiring",
            "retired",
        ]
        .contains(&record["phase"].as_str().unwrap_or_default())
        || record["worker_uid"].as_u64().is_none()
    {
        return Err(LaneError::input(
            "uid-table",
            format!("{} has an invalid reservation", path.display()),
        ));
    }
    if check_node && record.get("node_retirement").is_some() {
        retire::node_record::read(&record)?;
    }
    retire::absences::validate(&record)?;
    retire::rewrite::validate(&record)?;
    repin_door::validate(&record)?;
    Ok(Some(record))
}

pub(crate) fn publish_reservation(path: &Path, record: &Value) -> Result<(), LaneError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| LaneError::operation("uid-table", error.to_string()))?;
    let size = u64::try_from(bytes.len())
        .map_err(|error| LaneError::input("reservation-size", error.to_string()))?;
    if size > MAX_RESERVATION_BYTES {
        return Err(LaneError::input(
            "reservation-size",
            format!(
                "serialized reservation is {size} bytes; reader limit is {MAX_RESERVATION_BYTES} bytes"
            ),
        ));
    }
    if !home::private_is_active() {
        build::publish(path, &bytes)?;
        return fs::File::open(
            path.parent()
                .ok_or_else(|| LaneError::operation("uid-table", "reservation has no parent"))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            LaneError::operation("uid-table", format!("{}: {error}", path.display()))
        });
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| LaneError::operation("uid-table", "reservation has no parent"))?;
    let parent = home::pin_parent(parent_path, Uid::effective().as_raw())?;
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::operation("uid-table", "reservation has no name"))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| LaneError::operation("uid-table", error.to_string()))?
        .as_nanos();
    let temporary = format!(".reservation-{}-{nanos}.tmp", std::process::id());
    let output = openat2(
        &parent,
        temporary.as_str(),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("uid-table", format!("{}: {error}", path.display())))?;
    let mut file = fs::File::from(output);
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            LaneError::operation("uid-table", format!("{}: {error}", path.display()))
        })?;
    renameat(&parent, temporary.as_str(), &parent, name).map_err(|error| {
        LaneError::operation("uid-table", format!("{}: {error}", path.display()))
    })?;
    fs::File::from(
        nix::unistd::dup(&parent)
            .map_err(|error| LaneError::operation("uid-table", error.to_string()))?,
    )
    .sync_all()
    .map_err(|error| LaneError::operation("uid-table", format!("{}: {error}", path.display())))
}

#[cfg(test)]
fn retire_partial(path: &Path, label: &str) -> Result<Option<PathBuf>, LaneError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "launch-recover",
                format!("{}: {error}", path.display()),
            ));
        }
        Ok(_) => {}
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| LaneError::operation("launch-recover", error.to_string()))?
        .as_nanos();
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::operation("launch-recover", "partial path has no parent"))?;
    let retired = parent.join(format!(".retired-{label}-{}-{nanos}", std::process::id()));
    fs::rename(path, &retired).map_err(|error| {
        LaneError::operation("launch-recover", format!("{}: {error}", path.display()))
    })?;
    Ok(Some(retired))
}

pub(crate) fn select_free_uid(
    root: &Path,
    run: &str,
    base: u32,
    count: u32,
) -> Result<u32, LaneError> {
    select_free_uid_with_census(root, run, base, count).map(|(uid, _skipped)| uid)
}

fn census_reservation(path: &Path) -> Result<Option<Value>, LaneError> {
    read_reservation(path).map_err(|error| {
        LaneError::input(
            "launch-reservation",
            format!("{}: {}", path.display(), error.detail),
        )
    })
}

fn select_free_uid_with_census(
    root: &Path,
    run: &str,
    base: u32,
    count: u32,
) -> Result<(u32, Vec<String>), LaneError> {
    let own_reservation = census_reservation(&reservation_path(root, run))?;
    let pending_uid = if let Some(record) = &own_reservation
        && (record["phase"] == "preparing"
            || (record["phase"] == "failed" && record["pre_driver_failure"].is_string()))
    {
        Some(
            record["worker_uid"]
                .as_u64()
                .and_then(|uid| u32::try_from(uid).ok())
                .filter(|uid| *uid >= base && *uid < base + count)
                .ok_or_else(|| {
                    LaneError::input("uid-table", "pending worker UID is outside the grant")
                })?,
        )
    } else {
        None
    };
    if pending_uid.is_none()
        && (own_reservation.is_some() || fs::symlink_metadata(root.join(run)).is_ok())
    {
        return Err(LaneError::input(
            "already-exists",
            format!("{} already exists", root.join(run).display()),
        ));
    }
    let driver_dir = root.join(run);
    let identity_dir = protected_identity_dir(&driver_dir)?;
    if pending_uid.is_none()
        && (fs::symlink_metadata(&identity_dir).is_ok()
            || (1..=4).any(|attempt| {
                protected_identifier_path(&driver_dir, attempt)
                    .is_ok_and(|path| fs::symlink_metadata(path).is_ok())
            }))
    {
        return Err(LaneError::input(
            "already-exists",
            format!("{} has protected launch inputs", driver_dir.display()),
        ));
    }
    let mut used = std::collections::BTreeSet::new();
    let mut skipped = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| LaneError::input("runs-root", format!("{}: {error}", root.display())))?
    {
        let entry = entry.map_err(|error| LaneError::input("runs-root", error.to_string()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".reservation-") && name.ends_with(".json") {
            let record = census_reservation(&entry.path())?.ok_or_else(|| {
                LaneError::input(
                    "launch-reservation",
                    "reservation disappeared during census",
                )
            })?;
            let uid = record["worker_uid"]
                .as_u64()
                .and_then(|uid| u32::try_from(uid).ok())
                .ok_or_else(|| LaneError::input("uid-table", "reservation has no worker UID"))?;
            used.insert(uid);
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|error| {
            LaneError::input("runs-root", format!("{}: {error}", path.display()))
        })?;
        if !meta.is_dir() {
            continue;
        }
        let Some(saved) = census_reservation(&reservation_path(root, &name))? else {
            skipped.push(name.into_owned());
            continue;
        };
        let uid = saved["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                LaneError::input("uid-table", format!("{} has no worker UID", path.display()))
            })?;
        used.insert(uid);
    }
    skipped.sort();
    pending_uid
        .or_else(|| (base..base + count).find(|uid| !used.contains(uid)))
        .map(|uid| (uid, skipped))
        .ok_or_else(|| {
            LaneError::input(
                "uid-range",
                format!("{} has no free worker identity", root.display()),
            )
        })
}

/// Read one free identity while holding the runs-root lock without changing disk.
///
/// # Errors
///
/// Refuses an existing run, malformed prior record, or exhausted range.
pub fn choose_worker_uid(owner_home: &Path, loop_name: &str, run: &str) -> Result<u32, LaneError> {
    let (plan, _settings) = load_plan(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?;
    let _lock = lock_runs_root(root, false, nix::unistd::Uid::effective().as_raw())?;
    let (base, count) = worker_range(owner_home, loop_name)?;
    select_free_uid(root, run, base, count)
}

fn parse_observation(
    source: &str,
    run: &str,
    path: &Path,
) -> Result<BTreeMap<String, bool>, LaneError> {
    let mut lines = source.lines();
    if lines.next() != Some(format!("mode=observing run={run} enforcing=false").as_str()) {
        return Err(LaneError::input(
            "host-observation",
            format!("{} lacks the named observing marker", path.display()),
        ));
    }
    let mut hosts = BTreeMap::new();
    for line in lines {
        if hosts.len() >= 128 {
            return Err(LaneError::input(
                "host-observation",
                format!("{} exceeds 128 attempted hosts", path.display()),
            ));
        }
        let (target, connected) = line.split_once(" connected=").ok_or_else(|| {
            LaneError::input(
                "host-observation",
                format!("{} has a malformed host line", path.display()),
            )
        })?;
        let host = target.strip_suffix(":443").ok_or_else(|| {
            LaneError::input(
                "host-observation",
                format!("{} has a malformed host line", path.display()),
            )
        })?;
        if host.is_empty()
            || host.bytes().any(|byte| {
                !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'.' && byte != b'-'
            })
        {
            return Err(LaneError::input(
                "host-observation",
                format!("{} has an invalid host {host}", path.display()),
            ));
        }
        let connected = match connected {
            "0" => false,
            "1" => true,
            _ => {
                return Err(LaneError::input(
                    "host-observation",
                    format!("{} has a malformed connection mark", path.display()),
                ));
            }
        };
        if hosts.insert(host.to_owned(), connected).is_some() {
            return Err(LaneError::input(
                "host-observation",
                format!("{} repeats host {host}", path.display()),
            ));
        }
    }
    Ok(hosts)
}

fn observation_path(plan: &Plan, run: &str) -> Result<PathBuf, LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("host-observation", "run has no protected root"))?;
    Ok(root.join(format!(".observed-{run}.txt")))
}

fn observation_reservation(root: &Path, loop_name: &str, run: &str) -> Result<(), LaneError> {
    let path = reservation_path(root, run);
    let record = read_reservation(&path)?.ok_or_else(|| {
        LaneError::input("host-observation", format!("{} is absent", path.display()))
    })?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "host-observation",
            format!("{} belongs to another loop or run", path.display()),
        ));
    }
    Ok(())
}

/// Read the one-run observation record from the protected runs root.
///
/// # Errors
///
/// Refuses an absent, oversized, or malformed observation.
pub fn private_observed_hosts(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<Value, LaneError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let (plan, _settings) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let path = observation_path(&plan, run)?;
    let root = path
        .parent()
        .ok_or_else(|| LaneError::input("host-observation", "observation has no parent"))?;
    let _protected_root = home::pin_parent(root, 0)?;
    observation_reservation(root, loop_name, run)?;
    let bytes = crate::pinned::read_private(root, &path, 0, 0o600, 32_768)?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| LaneError::input("host-observation", error.to_string()))?;
    let hosts = parse_observation(source, run, &path)?;
    let connected = hosts
        .iter()
        .filter_map(|(host, reached)| reached.then_some(host))
        .collect::<Vec<_>>();
    Ok(
        json!({"schema":1,"command":"observed-hosts","loop":loop_name,"run":run,"mode":"observing","enforcing":false,"source":path,"attempted_connect_hosts":hosts,"connected_hosts":connected}),
    )
}

/// Record a reviewed subset of hosts observed by one named run.
///
/// # Errors
///
/// Refuses unobserved names, a conflicting prior list, or a failed settings check.
#[allow(clippy::too_many_lines)]
pub fn record_hosts(owner_home: &Path, request: &RecordHostsRequest) -> Result<Value, LaneError> {
    let lane_bin = std::env::current_exe()
        .map_err(|error| LaneError::operation("record-program", error.to_string()))?;
    record_hosts_with_lane_bin(owner_home, request, &lane_bin)
}

fn read_observation_private(
    owner_home: &Path,
    request: &RecordHostsRequest,
    lane_bin: &Path,
    environment: &BTreeMap<String, String>,
    verified_home: &OwnedFd,
    runs_root: &Path,
    verified_runs: &OwnedFd,
) -> Result<String, LaneError> {
    let lane_word = crate::pinned::owner_executable_word(lane_bin, Uid::effective().as_raw())?;
    let argv = vec![
        "unshare".into(),
        lane_word,
        "_observed-hosts".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ];
    build::run_checked_with_private_launch(
        &request.podman_bin,
        argv,
        environment,
        owner_home,
        30,
        "host-observation",
        verified_home,
        runs_root,
        verified_runs,
        None,
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn record_hosts_with_lane_bin(
    owner_home: &Path,
    request: &RecordHostsRequest,
    lane_bin: &Path,
) -> Result<Value, LaneError> {
    record_hosts_with_lane_bin_from(owner_home, request, lane_bin, Path::new("/"), 0)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn record_hosts_with_lane_bin_from(
    owner_home: &Path,
    request: &RecordHostsRequest,
    lane_bin: &Path,
    host_root: &Path,
    root_uid: u32,
) -> Result<Value, LaneError> {
    let started = Instant::now();
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    let _settings_lock =
        crate::install::lock_loop_config(&config, request.dry_run || request.list)?;
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    crate::pinned::owner_executable(&request.podman_bin, Uid::effective().as_raw())?;
    let environment = launch_environment(owner_home)?;
    let verified_home =
        home::verify_host_prefix_from(host_root, owner_home, Uid::effective().as_raw(), root_uid)?;
    let runs_root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?;
    let verified_runs = home::verify_host_launch_root(
        host_root,
        owner_home,
        runs_root,
        Uid::effective().as_raw(),
        root_uid,
    )?;
    let output = read_observation_private(
        owner_home,
        request,
        lane_bin,
        &environment,
        &verified_home,
        runs_root,
        &verified_runs,
    )?;
    let observation: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::input("host-observation", error.to_string()))?;
    if observation["source"]
        != plan
            .driver_dir
            .parent()
            .ok_or_else(|| LaneError::input("host-observation", "run has no protected root"))?
            .join(format!(".observed-{}.txt", request.run))
            .display()
            .to_string()
        || observation["enforcing"] != false
    {
        return Err(LaneError::input(
            "host-observation",
            "observation does not name this run and its unenforced mode",
        ));
    }
    if request.list {
        return Ok(
            json!({"schema":1,"command":"record-hosts","loop":request.loop_name,"run":request.run,"changed":false,"observation":observation,"wall_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    let observed = observation["connected_hosts"]
        .as_array()
        .ok_or_else(|| LaneError::input("host-observation", "host array is absent"))?;
    if request.reviewed_pool
        && !request
            .hosts
            .iter()
            .any(|host| observed.iter().any(|value| value == host))
    {
        return Err(LaneError::input(
            "host-list",
            "reviewed pool must include an observed connected host",
        ));
    }
    for host in &request.hosts {
        if !request.reviewed_pool && !observed.iter().any(|value| value == host) {
            return Err(LaneError::input(
                "host-list",
                format!("{host} was not observed for run {}", request.run),
            ));
        }
    }
    let previous = settings
        .vendor_hosts
        .get("codex")
        .cloned()
        .unwrap_or_default();
    if !previous.is_empty() && previous != request.hosts {
        return Err(LaneError::input(
            "host-list",
            "vendor_hosts.codex already differs; a separate reviewed update is required",
        ));
    }
    let changed = previous.is_empty();
    let settings_path = settings_path(owner_home, &request.loop_name);
    let mut parsed: toml::Value = toml::from_str(&settings.source)
        .map_err(|error| LaneError::input("settings-toml", error.to_string()))?;
    let table = parsed
        .as_table_mut()
        .ok_or_else(|| LaneError::input("settings-toml", "root is not a table"))?;
    let mut vendor_hosts = table
        .get("vendor_hosts")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    vendor_hosts.insert(
        "codex".into(),
        toml::Value::Array(
            request
                .hosts
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    table.insert("vendor_hosts".into(), toml::Value::Table(vendor_hosts));
    let updated = toml::to_string_pretty(&parsed)
        .map_err(|error| LaneError::operation("settings-write", error.to_string()))?;
    let (validated_source, _, _) = crate::settings::split_local_policies(&updated)?;
    loop_home::workers_settings::validate_workers_settings(&validated_source, &settings_path)
        .map_err(|error| LaneError::input("host-list", error.message()))?;
    if !request.dry_run && changed {
        build::publish(&settings_path, updated.as_bytes())?;
        let check = Settings::read(&settings_path)?;
        check.validate_grant(owner_home, &request.loop_name)?;
        if check.vendor_hosts.get("codex") != Some(&request.hosts) {
            return Err(LaneError::operation(
                "settings-write",
                "host list check differs",
            ));
        }
    }
    Ok(
        json!({"schema":1,"command":"record-hosts","loop":request.loop_name,"run":request.run,"source":observation["source"],"observed":observed,"prior":previous,"selected":request.hosts,"reviewed_pool":request.reviewed_pool,"dry_run":request.dry_run,"changed":changed && !request.dry_run,"settings":settings_path,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

pub(crate) fn check_mount_roots(
    plan: &Plan,
    settings: &Settings,
    owner_home: &Path,
) -> Result<(), LaneError> {
    let template = settings
        .template_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "template_dir is absent"))?;
    let socket = settings
        .socket_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "socket_dir is absent"))?;
    let loop_name = plan.document["loop"]
        .as_str()
        .ok_or_else(|| LaneError::operation("plan-json", "loop is absent"))?;
    let image_hash = settings
        .image_digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or_else(|| LaneError::input("missing-setting", "image_digest is absent"))?;
    let loop_root = owner_home.join(".var/loops").join(loop_name);
    if template != loop_root.join("runner-templates/codex").join(image_hash)
        || socket != loop_root.join("sockets")
    {
        return Err(LaneError::input(
            "mount-source",
            "template_dir or socket_dir differs from the loop's installed roots",
        ));
    }
    let identity_dir = protected_identity_dir(&plan.driver_dir)?;
    let sources = plan.document["mounts"]
        .as_array()
        .ok_or_else(|| LaneError::operation("plan-json", "mounts are absent"))?;
    for mount in sources.iter().filter(|mount| mount["kind"] == "bind") {
        let source = mount["source"]
            .as_str()
            .ok_or_else(|| LaneError::operation("plan-json", "mount source is absent"))?;
        let source = Path::new(source);
        if !source.is_absolute()
            || source.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || ![
                plan.home.as_path(),
                identity_dir.as_path(),
                template,
                socket,
            ]
            .iter()
            .any(|root| source.starts_with(root))
        {
            return Err(LaneError::input(
                "mount-source",
                format!(
                    "{} is outside the loop's roots and installed data",
                    source.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn image_check(podman: &Path, image: &str, owner_home: &Path) -> Result<(), LaneError> {
    executable(podman, "container program")?;
    let actual = build::inspect_image(podman, image, owner_home)
        .map_err(|error| LaneError::input("image-identity", error.line()))?;
    if actual != image {
        return Err(LaneError::input(
            "image-identity",
            format!("recorded image {image} resolves to {actual}"),
        ));
    }
    Ok(())
}

fn private_image_check(podman: &Path, image: &str, owner_home: &Path) -> Result<(), LaneError> {
    let environment = private_podman_environment(owner_home)?;
    image_check_with_environment(podman, image, owner_home, &environment)
}

pub(crate) fn image_check_with_environment(
    podman: &Path,
    image: &str,
    owner_home: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<(), LaneError> {
    executable(podman, "container program")?;
    let actual = build::inspect_image_with_environment(podman, image, owner_home, environment)
        .map_err(|error| LaneError::input("image-identity", error.line()))?;
    if actual != image {
        return Err(LaneError::input(
            "image-identity",
            format!("recorded image {image} resolves to {actual}"),
        ));
    }
    Ok(())
}

fn private_argv(
    exe_word: &str,
    podman_word: &str,
    owner_home: &Path,
    request: &LaunchRequest,
    worker_uid: u32,
    selection: &LaunchModel,
) -> Result<Vec<String>, LaneError> {
    let mut argv = vec![
        "unshare".into(),
        exe_word.into(),
        "_make-home".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--letter".into(),
        crate::pinned::path_word(&request.letter, "letter-path")?,
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--worker-uid".into(),
        worker_uid.to_string(),
        "--podman-bin".into(),
        podman_word.into(),
        "--model".into(),
        selection.model.clone(),
        "--effort".into(),
        selection.effort.clone(),
        "--model-source".into(),
        selection.model_source.into(),
        "--effort-source".into(),
        selection.effort_source.into(),
        "--door-scope".into(),
        request.door_scope.name().into(),
    ];
    if let Some(source) = &request.rotation_source {
        argv.extend(["--rotation-sha256".into(), source.digest.clone()]);
    }
    if request.observe {
        argv.push("--observe".into());
    }
    Ok(argv)
}

fn runtime_prepare_argv(
    exe_word: &str,
    podman_word: &str,
    owner_home: &Path,
    request: &LaunchRequest,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "unshare".into(),
        exe_word.into(),
        "_prepare-runtime".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--podman-bin".into(),
        podman_word.into(),
    ])
}

fn entry_argv(
    driver: &Path,
    plan: &Plan,
    request: &LaunchRequest,
    directory: &Path,
) -> Result<Vec<String>, LaneError> {
    entry_argv_round(
        driver,
        plan,
        &request.loop_name,
        &request.run,
        "dispatch",
        request.budget,
        Some(directory),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn entry_argv_round(
    driver: &Path,
    plan: &Plan,
    loop_name: &str,
    run: &str,
    step: &str,
    budget: u64,
    fresh_dir: Option<&Path>,
    resume: Option<(&str, &Path, &LaunchModel)>,
) -> Result<Vec<String>, LaneError> {
    let run_dir = crate::pinned::path_word(&plan.driver_dir, "run-directory")?;
    let mut argv = vec![
        "driver-launch".into(),
        loop_name.into(),
        run.into(),
        "--driver-bin".into(),
        crate::pinned::path_word(driver, "driver-program")?,
        "--run-dir".into(),
        run_dir.clone(),
        "--".into(),
        "-t".into(),
        budget.to_string(),
        "-n".into(),
        step.into(),
        "-C".into(),
        run_dir,
        "-s".into(),
        "workspace-write".into(),
    ];
    if let Some(directory) = fresh_dir {
        argv.extend([
            "-d".into(),
            crate::pinned::path_word(directory, "round-directory")?,
        ]);
    }
    if let Some((thread_id, prior_dir, selection)) = resume {
        argv.extend([
            "-r".into(),
            thread_id.into(),
            "-d".into(),
            crate::pinned::path_word(prior_dir, "round-directory")?,
            "-m".into(),
            selection.model.clone(),
            "-e".into(),
            selection.effort.clone(),
        ]);
    }
    argv.extend([
        "--step-letter".into(),
        crate::pinned::path_word(
            &plan.home.join(".local/inbox").join(format!("{step}.md")),
            "letter-path",
        )?,
        format!("Read /home/worker/.local/inbox/{step}.md."),
    ]);
    Ok(argv)
}

fn planned_step_dir(plan: &Plan, step: &str) -> Result<PathBuf, LaneError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| LaneError::operation("round-directory", error.to_string()))?;
    Ok(plan.driver_dir.join(format!(
        "{}-{}-{}-{step}",
        now.as_secs(),
        now.subsec_nanos(),
        std::process::id()
    )))
}

fn record_fresh_step_directory(plan: &Plan, run: &str, output: &str) -> Result<(), LaneError> {
    let exit = output.lines().last().and_then(|line| {
        line.split_whitespace()
            .find_map(|field| field.strip_prefix("exit="))
    });
    if exit != Some("0") {
        return Err(LaneError::input(
            "round-record",
            "fresh driver terminal report is not successful",
        ));
    }
    rounds::record_step_directory(plan, run, "dispatch", output)
}

/// Preview or start one supervised worker round.
///
/// # Errors
///
/// Refuses missing grants and pins before creating a home or running a container.
#[allow(clippy::too_many_lines)]
pub fn run(owner_home: &Path, request: &LaunchRequest) -> Result<Value, LaneError> {
    run_with_host_root(owner_home, request, Path::new("/"), 0)
}

/// Run a launch and hand an unsaved report to the caller if publication refuses.
///
/// # Errors
///
/// Refuses failed preflight, launch, settlement, or report publication.
#[allow(clippy::too_many_lines)]
pub fn run_with_failure_report(
    owner_home: &Path,
    request: &LaunchRequest,
    on_failure: &mut dyn FnMut(&Value),
) -> Result<Value, LaneError> {
    run_with_host_root_and_proxy_with_fallback(
        owner_home,
        request,
        Path::new("/"),
        0,
        reaping::systemctl_show,
        on_failure,
    )
}

fn image_report(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    let path = settings_path(owner_home, loop_name).with_file_name("image-build.json");
    let report: Value = serde_json::from_slice(&fs::read(&path).map_err(|error| {
        LaneError::input("build-report", format!("{}: {error}", path.display()))
    })?)
    .map_err(|error| LaneError::input("build-report", format!("{}: {error}", path.display())))?;
    build::image_program_from_report(&report)?;
    Ok(report)
}

fn box_route_probe(report: &Value, settings: &Settings) -> Result<Value, LaneError> {
    let inventory = report["package_inventory"]
        .as_array()
        .ok_or_else(|| LaneError::input("box-gate", "image report has no package inventory"))?;
    let has_bwrap = inventory.iter().filter_map(Value::as_str).any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|name| name == "bwrap" || name == "bubblewrap")
    });
    let template = settings
        .template_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("box-gate", "installed template is absent"))?;
    let bundled = [
        template.join("codex-resources/bwrap"),
        template.join("libexec/codex-resources/bwrap"),
        template.join("bin/bwrap"),
    ];
    for path in &bundled {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(LaneError::input(
                    "box-gate",
                    format!(
                        "{} provides an unexpected inner sandbox route",
                        path.display()
                    ),
                ));
            }
            Err(error) => {
                return Err(LaneError::input(
                    "box-gate",
                    format!("{}: {error}", path.display()),
                ));
            }
        }
    }
    if has_bwrap {
        return Err(LaneError::input(
            "box-gate",
            "image package inventory contains bubblewrap",
        ));
    }
    Ok(
        json!({"verdict":"passed","image_package_inventory":"bwrap and bubblewrap absent","installed_template":"codex-resources/bwrap and bin/bwrap absent","reason":"no inner bubblewrap route; outer box enforces the mount table"}),
    )
}

fn check_backend_image_program(settings: &Settings, generation: &Value) -> Result<(), LaneError> {
    let backend = settings
        .backend_argv
        .get("codex")
        .and_then(|words| words.first())
        .ok_or_else(|| LaneError::input("missing-setting", "backend_argv.codex is absent"))?;
    let measured = generation["codex_image_program"].as_str().ok_or_else(|| {
        LaneError::input(
            "install-generation",
            "codex_image_program is absent; repeat install --pilot",
        )
    })?;
    let measured = build::validate_image_program(measured)?;
    if backend != &measured {
        return Err(LaneError::input(
            "backend-program",
            "backend_argv.codex differs from the measured image program",
        ));
    }
    Ok(())
}

fn persist_settlement_field(path: &Path, field: &str, value: Value) -> Result<Value, LaneError> {
    persist_settlement_field_with(path, field, value, false)
}

fn persist_recovery_field(path: &Path, field: &str, value: Value) -> Result<Value, LaneError> {
    persist_settlement_field_with(path, field, value, true)
}

fn persist_settlement_field_with(
    path: &Path,
    field: &str,
    value: Value,
    recovering: bool,
) -> Result<Value, LaneError> {
    let root = path
        .parent()
        .ok_or_else(|| LaneError::input("launch-reservation", "runs root is absent"))?;
    let run = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(".reservation-"))
        .and_then(|name| name.strip_suffix(".json"))
        .ok_or_else(|| LaneError::input("launch-reservation", "reservation name is malformed"))?;
    let _mailbox = lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut record = read_reservation(path)?
        .ok_or_else(|| LaneError::input("launch-reservation", "protected reservation is absent"))?;
    if record["phase"] != "started"
        && record["phase"] != "preparing"
        && !(recovering && failed_driver_recovery(&record))
    {
        return Err(LaneError::input(
            "launch-reservation",
            "reservation is not active",
        ));
    }
    record[field] = value;
    if field == "observer_end" && record[field]["state"] != "not-started" {
        record["observer_state"] = json!("ended");
    }
    publish_reservation(path, &record)?;
    Ok(record)
}

fn observer_socket_disposition(slot: &crate::SocketSlot, owner: u32) -> Value {
    match slot.metadata() {
        Ok(None) => json!({"state":"absent"}),
        Ok(Some(meta)) if meta.st_mode & libc::S_IFMT == libc::S_IFSOCK && meta.st_uid == owner => {
            match slot.remove() {
                Ok(()) => json!({"state":"removed"}),
                Err(error) => {
                    json!({"state":"uncertain","error":LaneError::operation("observer-socket", error.to_string()).line()})
                }
            }
        }
        Ok(Some(_)) => {
            json!({"state":"failed","error":"observer-socket: socket changed type or owner"})
        }
        Err(error) => {
            json!({"state":"uncertain","error":LaneError::input("observer-socket", error.to_string()).line()})
        }
    }
}

fn container_absent_by_label(
    request: &LaunchRequest,
    owner_home: &Path,
) -> Result<bool, LaneError> {
    container_absent_for_run(
        &request.podman_bin,
        owner_home,
        &request.loop_name,
        &request.run,
    )
}

pub(crate) fn container_absent_for_run(
    podman_bin: &Path,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<bool, LaneError> {
    crate::pinned::owner_executable(podman_bin, Uid::effective().as_raw())?;
    let output = build::run_checked(
        podman_bin,
        vec![
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--format".into(),
            "{{.ID}}".into(),
            "--filter".into(),
            format!("label=org.superloop.loop={loop_name}"),
            "--filter".into(),
            format!("label=org.superloop.run={run}"),
        ],
        &build::podman_environment(owner_home)?,
        owner_home,
        30,
        "settlement-container",
    )?;
    Ok(output.trim().is_empty())
}

fn recovery_containers(
    request: &LaunchRequest,
    owner_home: &Path,
) -> Result<Vec<Value>, LaneError> {
    proved_exited_containers(
        &request.podman_bin,
        owner_home,
        &request.loop_name,
        &request.run,
    )
}

fn proved_exited_containers(
    program: &Path,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<Vec<Value>, LaneError> {
    crate::pinned::owner_executable(program, Uid::effective().as_raw())?;
    let environment = build::podman_environment(owner_home)?;
    let listed = build::run_checked(
        program,
        vec![
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--format".into(),
            "{{.ID}}".into(),
            "--filter".into(),
            format!("label=org.superloop.loop={loop_name}"),
            "--filter".into(),
            format!("label=org.superloop.run={run}"),
        ],
        &environment,
        owner_home,
        30,
        "settlement-container",
    )?;
    let mut ids = BTreeSet::new();
    for id in listed.lines() {
        if id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !ids.insert(id)
            || ids.len() > 8
        {
            return Err(LaneError::input(
                "settlement-container",
                "label listing is not at most eight distinct full container IDs",
            ));
        }
    }
    ids.into_iter()
        .map(|id| {
            let inspected = build::run_checked(
                program,
                vec!["container".into(), "inspect".into(), id.into()],
                &environment,
                owner_home,
                30,
                "settlement-container",
            )?;
            exited_inspection(&inspected, id, loop_name, run)
        })
        .collect()
}

fn exited_inspection(
    inspected: &str,
    id: &str,
    loop_name: &str,
    run: &str,
) -> Result<Value, LaneError> {
    let refuse = |detail| LaneError::input("settlement-container", detail);
    if inspected.len() > 1_048_576 {
        return Err(refuse(format!("inspection for {id} exceeds 1 MiB")));
    }
    let response: Value = serde_json::from_str(inspected)
        .map_err(|error| refuse(format!("invalid inspection for {id}: {error}")))?;
    let inspection = response
        .as_array()
        .filter(|rows| rows.len() == 1)
        .and_then(|rows| rows.first())
        .filter(|row| row.is_object())
        .ok_or_else(|| {
            refuse(format!(
                "inspection for {id} is not an array of exactly one object"
            ))
        })?;
    if inspection["Id"] != id
        || inspection["Name"].as_str().is_none_or(str::is_empty)
        || inspection["Config"]["Labels"]["org.superloop.loop"] != loop_name
        || inspection["Config"]["Labels"]["org.superloop.run"] != run
    {
        return Err(refuse(format!(
            "container {id} identity or loop/run labels differ"
        )));
    }
    let state = &inspection["State"];
    if state["Status"] != "exited"
        || state["Running"] != false
        || state["Paused"] != false
        || state["Restarting"] != false
        || state["Pid"] != 0
        || state["ExitCode"].as_u64().is_none()
        || state["FinishedAt"].as_str().is_none_or(str::is_empty)
    {
        return Err(refuse(format!(
            "container {id} is live or its exited state is unproved"
        )));
    }
    Ok(
        json!({"id":inspection["Id"],"name":inspection["Name"],"labels":inspection["Config"]["Labels"],"state":state}),
    )
}

fn interrupted_recovery_preview(
    record: &Value,
    plan: &Plan,
    letter: &Path,
    request: &LaunchRequest,
    owner_home: &Path,
    presence: impl FnMut(u32, u64) -> ProcessPresence,
) -> Result<Value, LaneError> {
    // Admission proves the recorded processes absent before any container cleanup is proposed.
    // The provisional true defers only the label measurement, never process or attempt checks.
    let mut preview = interrupted_settlement_with(
        record,
        plan,
        letter,
        presence,
        || Ok(true),
        |record| driver_report::read(owner_home, record),
    )?;
    let containers = recovery_containers(request, owner_home)?;
    if !containers.is_empty()
        && preview["attempt_evidence"]["state"] == "absence-confirmed-with-missing-evidence"
    {
        preview["attempt_evidence"]["state"] = json!("would-confirm-absence-with-missing-evidence");
        preview["attempt_evidence"]["container_absence_checked"] = json!(false);
    }
    preview["containers_to_remove"] = json!(containers);
    let input = serde_json::to_vec(
        &json!({"reservation":record,"decision":preview,"owner_uid":Uid::effective().as_raw()}),
    )
    .map_err(|error| LaneError::input("settlement-digest", error.to_string()))?;
    preview["preview_sha256"] = json!(build::sha256_bytes(&input, owner_home)?);
    Ok(preview)
}

fn apply_recovery_containers(
    request: &LaunchRequest,
    owner_home: &Path,
    reservation: &Path,
    preview: &Value,
) -> Result<(), LaneError> {
    let containers = preview["containers_to_remove"]
        .as_array()
        .ok_or_else(|| LaneError::input("settlement-container", "cleanup preview is absent"))?;
    if (!containers.is_empty() || request.expect_digest.is_some())
        && request.expect_digest.as_deref() != preview["preview_sha256"].as_str()
    {
        return Err(LaneError::input(
            "settlement-digest",
            "cleanup requires the matching interrupted_settlement.preview_sha256; repeat launch --dry-run and apply with --expect-digest HEX",
        ));
    }
    let environment = build::podman_environment(owner_home)?;
    if !containers.is_empty() {
        persist_recovery_field(
            reservation,
            "interrupted_container_cleanup",
            json!({
                "state":"pending", "preview_sha256":preview["preview_sha256"], "containers":containers
            }),
        )?;
    }
    for container in containers {
        let id = container["id"]
            .as_str()
            .ok_or_else(|| LaneError::input("settlement-container", "preview ID is absent"))?;
        build::run_checked(
            &request.podman_bin,
            vec!["rm".into(), "--ignore".into(), id.into()],
            &environment,
            owner_home,
            30,
            "settlement-container",
        )?;
    }
    if !container_absent_by_label(request, owner_home)? {
        return Err(LaneError::input(
            "settlement-uncertain",
            "container absence is not established by label after cleanup; repeat launch --dry-run",
        ));
    }
    if !containers.is_empty() {
        persist_recovery_field(
            reservation,
            "interrupted_container_cleanup",
            json!({
                "state":"confirmed-absent", "preview_sha256":preview["preview_sha256"], "containers":containers
            }),
        )?;
    } else if let Some(record) = read_reservation(reservation)? {
        let mut prior = record["interrupted_container_cleanup"].clone();
        if prior["state"] == "pending" {
            prior["state"] = json!("confirmed-absent");
            persist_recovery_field(reservation, "interrupted_container_cleanup", prior)?;
        }
    }
    Ok(())
}

fn record_probe_start(
    reservation: &Path,
    phase: &str,
    role: &str,
    name: &str,
) -> Result<(), LaneError> {
    let mut record = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("bound-source", "probe reservation is absent"))?;
    let starts = record["probe_starts"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("bound-source", "probe journal is absent"))?;
    if starts
        .iter()
        .any(|entry| entry["phase"] == phase && entry["role"] == role)
    {
        return Err(LaneError::input(
            "bound-source",
            "probe start is already journaled",
        ));
    }
    starts.push(json!({"phase":phase,"role":role,"container_name":name,"state":"starting","pid":null,"start_tick":null}));
    record["probe_absence_proof"] = Value::Null;
    publish_reservation(reservation, &record)
}

fn record_probe_process(
    reservation: &Path,
    phase: &str,
    role: &str,
    pid: u32,
) -> Result<(), LaneError> {
    let start = crate::container_helper::process_start(pid)?;
    let mut record = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("bound-source", "probe reservation is absent"))?;
    let entry = record["probe_starts"]
        .as_array_mut()
        .and_then(|items| {
            items.iter_mut().find(|entry| {
                entry["phase"] == phase && entry["role"] == role && entry["state"] == "starting"
            })
        })
        .ok_or_else(|| LaneError::input("bound-source", "journaled probe start is absent"))?;
    entry["pid"] = json!(pid);
    entry["start_tick"] = json!(start);
    entry["state"] = json!("running");
    publish_reservation(reservation, &record)
}

fn record_probe_end(reservation: &Path, phase: &str, role: &str) -> Result<(), LaneError> {
    let mut record = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("bound-source", "probe reservation is absent"))?;
    let entry = record["probe_starts"]
        .as_array_mut()
        .and_then(|items| {
            items.iter_mut().find(|entry| {
                entry["phase"] == phase && entry["role"] == role && entry["state"] == "running"
            })
        })
        .ok_or_else(|| LaneError::input("bound-source", "running probe is absent"))?;
    entry["state"] = json!("ended");
    publish_reservation(reservation, &record)
}

fn prove_probe_absence_with(
    record: &Value,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    mut labelled_absent: impl FnMut() -> Result<bool, LaneError>,
) -> Result<Value, LaneError> {
    let starts = match &record["probe_starts"] {
        Value::Null => Vec::new(),
        Value::Array(items) => items.clone(),
        _ => {
            return Err(LaneError::input(
                "launch-reservation",
                "probe journal is invalid",
            ));
        }
    };
    for entry in &starts {
        let phase = entry["phase"].as_str().unwrap_or("unknown");
        let role = entry["role"].as_str().unwrap_or("unknown");
        let pid = entry["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok());
        let tick = entry["start_tick"].as_u64();
        let (Some(pid), Some(tick)) = (pid, tick) else {
            return Err(LaneError::input(
                "launch-reservation",
                format!("{phase}/{role} probe process identity is absent"),
            ));
        };
        match presence(pid, tick) {
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "launch-busy",
                    format!("{phase}/{role} probe process is present"),
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "launch-reservation",
                    format!("{phase}/{role} probe process absence is uncertain"),
                ));
            }
            crate::container_helper::ProcessPresence::Absent => {}
        }
    }
    match labelled_absent() {
        Ok(true) => Ok(
            json!({"labelled_containers":"absent","probe_starts":starts,"probe_processes":"absent","source":"rootless-podman-ps-all-two-run-labels"}),
        ),
        Ok(false) => Err(LaneError::input(
            "launch-busy",
            "a labelled probe or worker container is present",
        )),
        Err(error) => Err(LaneError::input(
            "launch-reservation",
            format!("labelled container absence is uncertain: {}", error.line()),
        )),
    }
}

fn require_probe_absence_proof(
    record: &Value,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<(), LaneError> {
    let starts = match &record["probe_starts"] {
        Value::Null => Vec::new(),
        Value::Array(items) => items.clone(),
        _ => {
            return Err(LaneError::input(
                "launch-reservation",
                "probe journal is invalid",
            ));
        }
    };
    let proof = &record["probe_absence_proof"];
    if proof["labelled_containers"] != "absent"
        || proof["probe_starts"] != json!(starts)
        || proof["probe_processes"] != "absent"
        || proof["source"] != "rootless-podman-ps-all-two-run-labels"
    {
        return Err(LaneError::input(
            "launch-reservation",
            "probe absence proof is absent or differs from the journal",
        ));
    }
    for entry in &starts {
        let (Some(pid), Some(tick)) = (
            entry["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok()),
            entry["start_tick"].as_u64(),
        ) else {
            return Err(LaneError::input(
                "launch-reservation",
                "probe process identity is absent",
            ));
        };
        if presence(pid, tick) != crate::container_helper::ProcessPresence::Absent {
            return Err(LaneError::input(
                "launch-reservation",
                "probe process absence changed after the label check",
            ));
        }
    }
    Ok(())
}

fn attempt_belongs_to_round(marker: &Value, record: &Value) -> bool {
    if marker.get("launcher_pid").is_some() || marker.get("launcher_start").is_some() {
        return marker["launcher_pid"].is_number()
            && marker["launcher_start"].is_number()
            && marker["launcher_pid"] == record["launcher_pid"]
            && marker["launcher_start"] == record["launcher_start"];
    }
    // Untagged custody can only belong unambiguously to the first round.
    record["rounds"]
        .as_array()
        .is_some_and(|rounds| rounds.len() == 1)
}

#[allow(clippy::too_many_lines)]
fn attempt_evidence_complete(
    driver_dir: &Path,
    record: &Value,
    mut container_absent: impl FnMut() -> Result<bool, LaneError>,
) -> Result<Value, LaneError> {
    let custody = protected_identity_dir(driver_dir)?;
    let owner = Uid::effective().as_raw();
    let directory = home::pin_parent(&custody, owner)?;
    let directory_meta = fstat(&directory)
        .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
    if directory_meta.st_uid != owner || directory_meta.st_mode & 0o7777 != 0o700 {
        return Err(LaneError::input(
            "settlement-attempt",
            "attempt custody is not owner-private",
        ));
    }
    let mut attempts = Vec::new();
    let mut missing = false;
    let mut gap = false;
    let mut unfinished_start = false;
    let mut last_retry_eligible = false;
    for number in 1..=4 {
        let start_name = format!("container-attempt-{number}.start.json");
        let start_path = custody.join(&start_name);
        let start = match openat2(
            &directory,
            start_name.as_str(),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(file) => Some(std::fs::File::from(file)),
            Err(nix::errno::Errno::ENOENT) => None,
            Err(error) => {
                return Err(LaneError::input(
                    "settlement-attempt",
                    format!("{}: {error}", start_path.display()),
                ));
            }
        };
        let started = if let Some(file) = start {
            let meta = file
                .metadata()
                .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
            if !meta.is_file()
                || meta.uid() != owner
                || meta.permissions().mode() & 0o7777 != 0o600
                || meta.len() > 65_536
            {
                return Err(LaneError::input(
                    "settlement-attempt",
                    format!("{} is not bounded start evidence", start_path.display()),
                ));
            }
            let mut bytes = Vec::new();
            file.take(65_537)
                .read_to_end(&mut bytes)
                .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
            let marker: Value = serde_json::from_slice(&bytes)
                .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
            if !attempt_belongs_to_round(&marker, record) {
                missing = true;
                continue;
            }
            if marker["schema"] != 1
                || marker["attempt"] != number
                || marker["state"] != "started"
                || !marker["container_name"].is_string()
            {
                return Err(LaneError::input(
                    "settlement-attempt",
                    format!("{} is incomplete", start_path.display()),
                ));
            }
            true
        } else {
            false
        };
        let name = format!("container-attempt-{number}.status.json");
        let path = custody.join(&name);
        let file = match openat2(
            &directory,
            name.as_str(),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(file) => std::fs::File::from(file),
            Err(nix::errno::Errno::ENOENT) => {
                missing = true;
                unfinished_start |= started;
                continue;
            }
            Err(error) => {
                return Err(LaneError::input(
                    "settlement-attempt",
                    format!("{}: {error}", path.display()),
                ));
            }
        };
        if !started {
            return Err(LaneError::input(
                "settlement-attempt",
                format!("{} has no protected start", path.display()),
            ));
        }
        if missing {
            gap = true;
        }
        let meta = file
            .metadata()
            .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
        if !meta.is_file()
            || meta.uid() != owner
            || meta.permissions().mode() & 0o7777 != 0o600
            || meta.len() > 65_536
        {
            return Err(LaneError::input(
                "settlement-attempt",
                format!("{} is not bounded run evidence", path.display()),
            ));
        }
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
        let evidence: Value = serde_json::from_slice(&bytes)
            .map_err(|error| LaneError::input("settlement-attempt", error.to_string()))?;
        if !attempt_belongs_to_round(&evidence, record) {
            missing = true;
            unfinished_start = true;
            continue;
        }
        if evidence["schema"] != 1
            || evidence["attempt"] != number
            || evidence["bounded"] != true
            || evidence["status"].as_i64().is_none()
            || !evidence["stream_errors"].is_array()
            || ![
                "stream_error",
                "wait_error",
                "stop_error",
                "thread_error",
                "post_start_error",
            ]
            .iter()
            .all(|key| evidence.get(*key).is_some())
        {
            return Err(LaneError::input(
                "settlement-attempt",
                format!("{} is incomplete", path.display()),
            ));
        }
        match evidence["removal"]["state"].as_str() {
            Some("removed" | "absent") => {}
            Some("pending" | "failed") => unfinished_start = true,
            _ => {
                return Err(LaneError::input(
                    "settlement-uncertain",
                    format!("{} has no recognized removal evidence", path.display()),
                ));
            }
        }
        let clean = evidence["stream_errors"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && [
                "stream_error",
                "wait_error",
                "stop_error",
                "thread_error",
                "post_start_error",
            ]
            .iter()
            .all(|key| evidence[*key].is_null());
        last_retry_eligible = evidence["status"] != 0 && evidence["capacity_evidence"] == true;
        attempts.push(json!({"attempt":number,"status":evidence["status"],"removal":evidence["removal"]["state"],"error_free":clean,"capacity_evidence":evidence["capacity_evidence"]}));
    }
    let incomplete = attempts.is_empty() || gap || unfinished_start || last_retry_eligible;
    if incomplete
        && !container_absent()
            .map_err(|error| LaneError::input("settlement-uncertain", error.line()))?
    {
        return Err(LaneError::input(
            "settlement-uncertain",
            "container absence is not established by label",
        ));
    }
    Ok(
        json!({"state":if incomplete { "absence-confirmed-with-missing-evidence" } else { "complete" },"attempts":attempts,"container_absence_checked":incomplete}),
    )
}

fn driver_identity(record: &Value) -> Result<Option<(u32, u64)>, LaneError> {
    match (
        record["driver_entry_pid"].as_u64(),
        record["driver_entry_start"].as_u64(),
    ) {
        (Some(pid), Some(start)) => Ok(Some((
            u32::try_from(pid)
                .map_err(|_| LaneError::input("settlement-identity", "driver PID is invalid"))?,
            start,
        ))),
        (None, None) => Ok(None),
        _ => Err(LaneError::input(
            "settlement-identity",
            "driver identity is incomplete",
        )),
    }
}

fn differing_plan_keys(recorded: &Value, current: &Value) -> String {
    let mut keys = std::collections::BTreeSet::new();
    if let Some(object) = recorded.as_object() {
        keys.extend(object.keys());
    }
    if let Some(object) = current.as_object() {
        keys.extend(object.keys());
    }
    let changed = keys
        .into_iter()
        .filter(|key| recorded[key.as_str()] != current[key.as_str()])
        .map(String::as_str)
        .collect::<Vec<_>>();
    if changed.is_empty() {
        "none".to_owned()
    } else {
        changed.join(", ")
    }
}

fn compare_pinned_plan(recorded: &Value, current: &Value) -> Result<(), LaneError> {
    if current != recorded {
        let differing = differing_plan_keys(recorded, current);
        let route = if recorded["door"] == current["door"] {
            "reconcile the named pinned inputs with the protected plan before repeating the ordinary resume dry run; do not rewrite the protected plan to bypass the mismatch".into()
        } else {
            let non_door = differing.split(", ").any(|key| key != "door");
            format!(
                "{}preview launch LOOP RUN --repin-door --dry-run; review both door objects and preview_sha256; apply launch LOOP RUN --repin-door --expect-digest HEX; then repeat the ordinary resume dry run",
                if non_door {
                    "first reconcile the named non-door pinned inputs; repinning refuses non-door drift; then "
                } else {
                    ""
                }
            )
        };
        return Err(LaneError::input(
            "plan-read",
            format!(
                "protected plan differs from the current pinned plan; differing keys: {differing}; {route}"
            ),
        ));
    }
    Ok(())
}

fn failed_driver_recovery(record: &Value) -> bool {
    record["phase"] == "failed"
        && record.get("pre_driver_failure").is_none()
        && driver_identity(record).is_ok_and(|identity| identity.is_some())
        && (record["driver_end"]["state"] != "completed"
            || record["helper_end"]["state"] != "completed")
}

fn completed_recovery_guidance(record: &Value) -> &'static str {
    if record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .is_some_and(|round| round["phase"] == "settled")
    {
        "place send-letter LOOP RUN --step NEW --letter FILE, then launch LOOP RUN --round NEW"
    } else {
        "preview settle LOOP RUN --round STEP --dry-run, then place a new letter and launch --round NEW"
    }
}

fn interrupted_settlement_with(
    record: &Value,
    plan: &Plan,
    letter: &Path,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    container_absent: impl FnMut() -> Result<bool, LaneError>,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    if reaping::recovery_verdict(record).is_ok() {
        return Err(LaneError::input(
            "launch-report",
            format!(
                "interrupted settlement already completed; {}",
                completed_recovery_guidance(record)
            ),
        ));
    }
    if record["phase"] != "started"
        && !failed_driver_recovery(record)
        && !record["active_round"]
            .as_str()
            .is_some_and(|step| rounds::interrupted_round(record, step))
    {
        return Err(LaneError::input(
            "launch-reservation",
            "reservation is not a started settlement",
        ));
    }
    if record["model_selection"].is_null() {
        return Err(LaneError::input(
            "launch-reservation",
            "older started reservation has no model selection",
        ));
    }
    if record["plan"] != plan.document || record["letter_source"] != json!(letter) {
        return Err(LaneError::input(
            "launch-reservation",
            format!(
                "started reservation differs from this plan or letter; differing plan keys: {}",
                differing_plan_keys(&record["plan"], &plan.document)
            ),
        ));
    }
    let launcher = launcher_identity(record)?
        .ok_or_else(|| LaneError::input("settlement-identity", "launcher identity is absent"))?;
    let driver = driver_identity(record)?
        .ok_or_else(|| LaneError::input("settlement-identity", "driver identity is absent"))?;
    let helper = helper_identity(record)?
        .ok_or_else(|| LaneError::input("settlement-identity", "helper identity is absent"))?;
    let helper_parent = helper_parent_identity(record)?.ok_or_else(|| {
        LaneError::input("settlement-identity", "helper parent identity is absent")
    })?;
    let observer = observer_identity(record)?;
    let observing = plan.document["vendor_mode"].is_string();
    if observing != observer.is_some() {
        return Err(LaneError::input(
            "settlement-identity",
            "observer identity differs from launch mode",
        ));
    }
    for (name, (pid, start)) in [
        ("launcher", launcher),
        ("driver", driver),
        ("helper", helper),
        ("helper-parent", helper_parent),
    ]
    .into_iter()
    .chain(observer.map(|identity| ("observer", identity)))
    {
        match presence(pid, start) {
            crate::container_helper::ProcessPresence::Absent => {}
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "launch-busy",
                    format!("{name} is still alive"),
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "settlement-uncertain",
                    format!("{name} absence cannot be established"),
                ));
            }
        }
    }
    let attempts = attempt_evidence_complete(&plan.driver_dir, record, container_absent)?;
    let sockets = inspect_dead_helper_sockets_with(
        &plan.driver_dir,
        record,
        Uid::effective().as_raw(),
        &mut presence,
    )?;
    let mut preview = json!({"state":"would-complete-interrupted-settlement","identities":{"launcher":launcher,"driver":driver,"helper":helper,"helper_parent":helper_parent,"observer":observer},"presence":"all-absent","attempt_evidence":attempts,"existing_ends":{"driver":record["driver_end"],"helper":record["helper_end"],"observer":record["observer_end"],"observation":record["observation_end"],"readback":record["readback_end"]}});
    if let Some(end) = interrupted_driver_end(record, &mut presence, read_report)? {
        preview["recovered_driver_end"] = end;
    }
    if !sockets.is_empty() {
        preview["helper_sockets_to_remove"] = json!(
            sockets
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>()
        );
    }
    Ok(preview)
}

fn interrupted_driver_end(
    record: &Value,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Option<Value>, LaneError> {
    if record["driver_end"].is_null()
        && record["phase"] == "started"
        && record["reaping_recovery"].is_null()
    {
        let evidence = match repin_door::missing_driver_evidence(record, presence, read_report) {
            Ok(evidence) => evidence,
            Err(error) if error.kind == "repin-door-state" => return Ok(None),
            Err(error) if error.kind == "driver-report-private" => return Err(error),
            Err(error) => {
                return Err(LaneError::input(
                    if error.kind == "repin-door-live" {
                        "launch-busy"
                    } else {
                        "settlement-uncertain"
                    },
                    error.detail,
                ));
            }
        };
        let successful =
            evidence["run_report"]["exit"] == "0" && evidence["run_report"]["verdict"] == "ok";
        return Ok(Some(json!({"state":"completed","successful":successful,
            "source":{"record":"run-report","driver":"measured-absent"},"evidence":evidence})));
    }
    Ok(None)
}

fn interrupted_report_step(record: &Value) -> Result<Option<&str>, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .filter(|rounds| !rounds.is_empty())
        .ok_or_else(|| LaneError::input("launch-reservation", "started round is absent"))?;
    if rounds.len() == 1 {
        return Ok(None);
    }
    rounds
        .last()
        .and_then(|round| round["step"].as_str())
        .map(Some)
        .ok_or_else(|| LaneError::input("launch-reservation", "last round has no step"))
}

fn journal_interrupted_reaping(
    reservation: &Path,
    current: &Value,
    decision: &Value,
    reap: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<(Value, Option<LaneError>), LaneError> {
    let mut reaping = match reap(current) {
        Ok(report) => report,
        Err(error) => {
            json!({"state":"unmeasured","error":error.line(),"container_payload":{"state":"unmeasured"}})
        }
    };
    if reaping["state"] == "collected" {
        reaping["identities"] = decision["identities"].clone();
        reaping["presence"] = decision["presence"].clone();
        reaping["attempt_evidence"] = decision["attempt_evidence"].clone();
        reaping["scope"] = current["run_scope"].clone();
        let prior_clear = reaping::reaping_verdict(&current["reaping"]).is_ok()
            && reaping["container_payload"]["state"] == "absent";
        let current = persist_recovery_field(reservation, "reaping_recovery", reaping)?;
        let error = (!prior_clear && reaping::recovery_verdict(&current).is_err()).then(|| {
            LaneError::operation(
                "run-reaping",
                "collected scope lacks prior verified-empty measurement or absent payload",
            )
        });
        return Ok((current, error));
    }
    let error = reaping::reaping_verdict(&reaping).err();
    let current = persist_recovery_field(reservation, "reaping", reaping)?;
    Ok((current, error))
}

fn interrupted_settlement_success(current: &Value, evidence: &Value) -> bool {
    let last_status = evidence["attempts"]
        .as_array()
        .and_then(|items| items.last())
        .and_then(|item| item["status"].as_i64());
    let attempts_clean = evidence["state"] == "complete"
        && evidence["attempts"]
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item["error_free"] == true));
    let socket = current["observer_end"]["socket"]["state"]
        .as_str()
        .unwrap_or_default();
    let completed_attempt = attempts_clean
        && last_status == Some(0)
        && current["driver_end"]["state"] == "completed"
        && current["helper_end"]["state"] == "completed";
    let recovered_report = reaping::recovery_verdict(current).is_ok()
        && current["rounds"]
            .as_array()
            .and_then(|rounds| rounds.last())
            .is_some_and(|round| round["phase"] == "settled" && round["ended_by"] == "by-report");
    (completed_attempt || recovered_report)
        && current["driver_end"]["successful"] != false
        && current["helper_end"]["successful"] != false
        && current["readback_end"] == "completed"
        && current["observation_end"] == "completed"
        && ["stopped", "not-started"].contains(
            &current["observer_end"]["state"]
                .as_str()
                .unwrap_or_default(),
        )
        && ["removed", "absent", "not-applicable"].contains(&socket)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn finish_interrupted_settlement_with(
    reservation: &Path,
    plan: &Plan,
    letter: &Path,
    owner: u32,
    observe: impl FnOnce() -> Result<Value, LaneError>,
    settle: impl FnOnce() -> Result<Value, LaneError>,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    container_absent: impl FnMut() -> Result<bool, LaneError>,
    reap: impl FnOnce(&Value) -> Result<Value, LaneError>,
    read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let record = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("launch-reservation", "protected reservation is absent"))?;
    let decision = interrupted_settlement_with(
        &record,
        plan,
        letter,
        &mut presence,
        container_absent,
        read_report,
    )?;
    let stale = inspect_dead_helper_sockets_with(&plan.driver_dir, &record, owner, &mut presence)?;
    let helper = &decision["identities"]["helper"];
    let mut removed_helper_sockets = if record["interrupted_settlement"]["helper"] == *helper
        && record["interrupted_settlement"]["round"] == record["active_round"]
    {
        record["interrupted_settlement"]["removed_helper_sockets"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut intended = if record["interrupted_settlement"]["helper"] == *helper
        && record["interrupted_settlement"]["round"] == record["active_round"]
    {
        record["interrupted_settlement"]["helper_sockets_to_remove"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    for (path, _) in &stale {
        let path = json!(path);
        if !intended.contains(&path) {
            intended.push(path);
        }
    }
    if !intended.is_empty() {
        persist_recovery_field(
            reservation,
            "interrupted_settlement",
            json!({"round":record["active_round"],"helper":helper,"helper_sockets_to_remove":intended,"removed_helper_sockets":removed_helper_sockets,"socket_removal_state":"pending"}),
        )?;
        for (path, slot) in stale {
            slot.remove().map_err(|error| {
                LaneError::operation("helper-socket", format!("{}: {error}", path.display()))
            })?;
            let path = json!(path);
            if !removed_helper_sockets.contains(&path) {
                removed_helper_sockets.push(path);
            }
            persist_recovery_field(
                reservation,
                "interrupted_settlement",
                json!({"round":record["active_round"],"helper":helper,"helper_sockets_to_remove":intended,"removed_helper_sockets":removed_helper_sockets,"socket_removal_state":"pending"}),
            )?;
        }
        persist_recovery_field(
            reservation,
            "interrupted_settlement",
            json!({"round":record["active_round"],"helper":helper,"helper_sockets_to_remove":intended,"removed_helper_sockets":removed_helper_sockets,"socket_removal_state":"confirmed-absent"}),
        )?;
    }
    if record["driver_end"].is_null() {
        persist_recovery_field(
            reservation,
            "driver_end",
            decision
                .get("recovered_driver_end")
                .cloned()
                .unwrap_or_else(|| json!({"state":"absent-on-recovery"})),
        )?;
    }
    if record["helper_end"].is_null() {
        persist_recovery_field(
            reservation,
            "helper_end",
            json!({"state":"absent-on-recovery","pid":record["helper_pid"],"start":record["helper_start"]}),
        )?;
    }
    if record["observer_end"].is_null() {
        let end = if plan.document["vendor_mode"].is_string() {
            json!({"state":"absent-on-recovery","pid":record["observer_pid"],"start":record["observer_start"],"socket":{"state":"pending"}})
        } else {
            json!({"state":"not-started","socket":{"state":"not-applicable"}})
        };
        persist_recovery_field(reservation, "observer_end", end)?;
    }
    let mut current = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("launch-reservation", "protected reservation is absent"))?;
    if current["observer_end"]["socket"]["state"] == "pending" {
        let socket = recorded_observer_socket(&current)?.ok_or_else(|| {
            LaneError::input("observer-socket", "observing socket is absent from plan")
        })?;
        let disposition = match crate::SocketSlot::pinned(&socket, owner) {
            Ok(slot) => observer_socket_disposition(&slot, owner),
            Err(error) => json!({"state":"uncertain","error":error.line()}),
        };
        let mut end = current["observer_end"].clone();
        end["socket"] = disposition;
        current = persist_recovery_field(reservation, "observer_end", end)?;
    }
    if current["observation_end"].is_null() {
        let result = observe();
        current = persist_recovery_field(
            reservation,
            "observation_end",
            json!(
                result
                    .as_ref()
                    .map_or_else(LaneError::line, |_| "completed".into())
            ),
        )?;
    }
    if current["readback_end"].is_null() {
        let result = settle();
        current = persist_recovery_field(
            reservation,
            "readback_end",
            json!(
                result
                    .as_ref()
                    .map_or_else(LaneError::line, |_| "completed".into())
            ),
        )?;
    }
    let (new_current, reaping_error) =
        journal_interrupted_reaping(reservation, &current, &decision, reap)?;
    current = new_current;
    let evidence = &decision["attempt_evidence"];
    let success = interrupted_settlement_success(&current, evidence);
    current = publish_interrupted_phase(
        reservation,
        &current,
        success && reaping_error.is_none(),
        evidence,
        owner,
    )?;
    if let Some(error) = reaping_error {
        return Err(error);
    }
    let mut completed = json!({"state":"completed-interrupted-settlement","phase":current["phase"],"ended_by":current["rounds"].as_array().and_then(|rounds| rounds.last()).map_or(Value::Null, |round| round["ended_by"].clone()),"attempt_evidence":decision["attempt_evidence"],"observer_socket":current["observer_end"]["socket"]});
    if !removed_helper_sockets.is_empty() {
        completed["removed_helper_sockets"] = json!(removed_helper_sockets);
    }
    Ok(completed)
}

fn publish_interrupted_phase(
    reservation: &Path,
    expected: &Value,
    success: bool,
    evidence: &Value,
    owner: u32,
) -> Result<Value, LaneError> {
    let root = reservation
        .parent()
        .ok_or_else(|| LaneError::input("launch-reservation", "runs root is absent"))?;
    let run = expected["run"]
        .as_str()
        .ok_or_else(|| LaneError::input("launch-reservation", "run is absent"))?;
    let _mailbox = lock_mailbox(root, run, owner)?;
    let mut current = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("launch-reservation", "protected reservation is absent"))?;
    if current["phase"] != expected["phase"]
        || current["loop"] != expected["loop"]
        || current["run"] != expected["run"]
        || current["plan"] != expected["plan"]
    {
        return Err(LaneError::input(
            "launch-reservation",
            "reservation changed before interrupted settlement",
        ));
    }
    let readback_end = current["readback_end"].clone();
    let round_complete = current["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        .is_none_or(|round| {
            if round["phase"] == "running" || round["phase"] == "awaiting-settlement" {
                round["phase"] = json!("failed");
                round["settlement_error"] = json!(format!(
                    "round-recovery: interrupted settlement left no completed round: {}",
                    readback_end
                ));
            }
            round["phase"] == "settled"
        });
    current["phase"] = json!(if success && round_complete {
        "settled"
    } else {
        "failed"
    });
    current["settlement_uncertain"] = json!(
        current["observer_end"]["socket"]["state"] == "uncertain"
            || current["observer_end"]["state"] == "uncertain"
            || (evidence["state"] != "complete" && reaping::recovery_verdict(&current).is_err())
    );
    publish_reservation(reservation, &current)?;
    Ok(current)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn complete_interrupted_launch(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    plan: &Plan,
    saved: &Value,
    lane_bin: &Path,
    started: Instant,
    on_failure: &mut dyn FnMut(&Value),
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    reap: impl FnOnce(&Value) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("launch-reservation", "runs root is absent"))?;
    let reservation = reservation_path(root, &request.run);
    let letter = saved["letter_source"]
        .as_str()
        .map(Path::new)
        .ok_or_else(|| {
            LaneError::input("launch-reservation", "recorded letter source is absent")
        })?;
    let exe_word = crate::pinned::path_word(lane_bin, "owner-program")?;
    let environment = launch_environment(owner_home)?;
    let report_step = interrupted_report_step(saved)?;
    let round_dir = report::round_dir(plan, saved, report_step)?;
    let _lease = lock_run_preparation(root, &request.run, owner)?;
    if read_reservation(&reservation)?.as_ref() != Some(saved) {
        return Err(LaneError::input(
            "launch-reservation",
            "reservation changed before recovery; repeat the launch dry run",
        ));
    }
    let verified_home = home::verify_host_prefix_from(host_root, owner_home, owner, root_uid)?;
    let verified_runs =
        home::verify_host_launch_root(host_root, owner_home, root, owner, root_uid)?;
    let cleanup =
        interrupted_recovery_preview(saved, plan, letter, request, owner_home, &mut presence)?;
    apply_recovery_containers(request, owner_home, &reservation, &cleanup)?;
    let private_observe = || -> Result<Value, LaneError> {
        if !saved["plan"]["vendor_mode"].is_string() {
            return Ok(Value::Null);
        }
        let argv = vec![
            "unshare".into(),
            exe_word.clone(),
            "_observed-hosts".into(),
            request.loop_name.clone(),
            request.run.clone(),
            "--owner-home".into(),
            crate::pinned::path_word(owner_home, "owner-home")?,
        ];
        crate::pinned::owner_executable(Path::new(&exe_word), owner)?;
        let output = build::run_checked_with_private_launch(
            &request.podman_bin,
            argv,
            &environment,
            owner_home,
            30,
            "host-observation",
            &verified_home,
            root,
            &verified_runs,
            None,
        )?;
        serde_json::from_str::<Value>(&output)
            .map_err(|error| LaneError::input("host-observation", error.to_string()))
    };
    let private_settle = || -> Result<Value, LaneError> {
        let argv = vec![
            "unshare".into(),
            exe_word.clone(),
            "_settle-evidence".into(),
            request.loop_name.clone(),
            request.run.clone(),
            "--owner-home".into(),
            crate::pinned::path_word(owner_home, "owner-home")?,
        ];
        crate::pinned::owner_executable(Path::new(&exe_word), owner)?;
        let output = build::run_checked_with_private_launch(
            &request.podman_bin,
            argv,
            &environment,
            owner_home,
            60,
            "settle-evidence",
            &verified_home,
            root,
            &verified_runs,
            None,
        )?;
        settlement_document(&output)
    };
    let completed = finish_interrupted_settlement_with(
        &reservation,
        plan,
        letter,
        owner,
        private_observe,
        private_settle,
        presence,
        || container_absent_by_label(request, owner_home),
        reap,
        |record| driver_report::read(owner_home, record),
    )?;
    let report = json!({"schema":1,"command":"launch","dry_run":false,"interrupted_settlement":completed,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":round_dir,"wall_seconds":started.elapsed().as_secs_f64()});
    report::finish_with_fallback(
        &verified_runs,
        &request.run,
        report_step,
        report,
        on_failure,
    )
}

pub(crate) fn settlement_document(text: &str) -> Result<Value, LaneError> {
    let document: Value = serde_json::from_str(text)
        .map_err(|error| LaneError::input("settle-evidence", error.to_string()))?;
    if document["command"] != "settle-evidence"
        || !matches!(
            document["ended_by"].as_str(),
            Some("by-report" | "by-report-after-stop" | "by-budget")
        )
    {
        return Err(LaneError::input(
            "settle-evidence",
            "settlement has no valid round end reason",
        ));
    }
    Ok(document)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_with_host_root(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
) -> Result<Value, LaneError> {
    run_with_host_root_and_proxy(
        owner_home,
        request,
        host_root,
        root_uid,
        reaping::systemctl_show,
    )
}

fn proxy_service_for_launch(
    loop_name: &str,
    observe: bool,
    recovering: bool,
    mut proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
) -> Result<Value, LaneError> {
    if observe || recovering {
        return Ok(json!({"verdict":"not-applicable"}));
    }
    let (unit, invocation) = reaping::require_proxy_invocation_with(loop_name, &mut proxy_state)?;
    Ok(json!({"verdict":"passed","unit":unit,"active_state":"active","invocation":invocation}))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_with_host_root_and_proxy(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
) -> Result<Value, LaneError> {
    run_with_host_root_and_proxy_with_fallback(
        owner_home,
        request,
        host_root,
        root_uid,
        proxy_state,
        &mut |_| {},
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_with_host_root_and_proxy_with_fallback(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
    on_failure: &mut dyn FnMut(&Value),
) -> Result<Value, LaneError> {
    let lane_bin = std::env::current_exe()
        .map_err(|error| LaneError::operation("launch-program", error.to_string()))?;
    run_with_program(
        owner_home,
        request,
        host_root,
        root_uid,
        proxy_state,
        on_failure,
        &lane_bin,
    )
}

#[cfg(test)]
type HelperParentHook = fn(&Path) -> Result<(), LaneError>;

#[cfg(test)]
thread_local! {
    static BEFORE_HELPER_PARENT: std::cell::Cell<Option<HelperParentHook>> = const { std::cell::Cell::new(None) };
    static BEFORE_PRE_DRIVER_SAVE: std::cell::Cell<Option<HelperParentHook>> = const { std::cell::Cell::new(None) };
    static LAUNCH_IDENTITY_FAILURE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn fixture_before_helper_parent(hook: HelperParentHook) {
    BEFORE_HELPER_PARENT.with(|slot| slot.set(Some(hook)));
}

#[cfg(test)]
pub(crate) fn fixture_before_pre_driver_save(hook: HelperParentHook, scope: Option<bool>) {
    BEFORE_PRE_DRIVER_SAVE.with(|slot| slot.set(Some(hook)));
    LAUNCH_IDENTITY_FAILURE.with(|slot| slot.set(scope));
}

fn launch_process_start(pid: u32) -> Result<u64, LaneError> {
    #[cfg(test)]
    if LAUNCH_IDENTITY_FAILURE.with(|slot| slot.get() == Some(false)) {
        LAUNCH_IDENTITY_FAILURE.with(|slot| slot.set(None));
        return crate::container_helper::process_start(u32::MAX);
    }
    crate::container_helper::process_start(pid)
}

fn launch_run_scope(loop_name: &str) -> Result<Option<Value>, LaneError> {
    #[cfg(test)]
    {
        if LAUNCH_IDENTITY_FAILURE.with(|slot| slot.take() == Some(true)) {
            return Err(LaneError::input(
                "run-scope",
                "fixture scope identity unavailable",
            ));
        }
        let _ = loop_name;
        Ok(None)
    }
    #[cfg(not(test))]
    reaping::current_scope(loop_name).map(Some)
}

#[cfg(test)]
pub(crate) fn fixture_run_with_program(
    owner_home: &Path,
    request: &LaunchRequest,
    lane_bin: &Path,
) -> Result<Value, LaneError> {
    run_with_program(
        owner_home,
        request,
        owner_home,
        nix::unistd::Uid::effective().as_raw(),
        |_| Ok(("active".into(), "fixture-invocation".into())),
        &mut |_| {},
        lane_bin,
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_with_program(
    owner_home: &Path,
    request: &LaunchRequest,
    host_root: &Path,
    root_uid: u32,
    mut proxy_state: impl FnMut(&str) -> Result<(String, String), LaneError>,
    on_failure: &mut dyn FnMut(&Value),
    lane_bin: &Path,
) -> Result<Value, LaneError> {
    if request.round.is_some() {
        return rounds::resume_with_host_root(
            owner_home,
            request,
            host_root,
            root_uid,
            proxy_state,
            on_failure,
            lane_bin,
        );
    }
    let started = Instant::now();
    let caller = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    let (_admission, mut generation_guard) =
        crate::install::lock_launch_generation(&config, request.dry_run)?;
    admission::ensure_open(&config, caller.0)?;
    let (mut plan, settings) = load_plan(owner_home, &request.loop_name, &request.run, (0, 0))?;
    plan.select_container_program(&request.podman_bin)?;
    if settings.sandbox_mode != "danger-full-access" {
        return Err(LaneError::input(
            "box-gate",
            "sandbox_mode must be danger-full-access inside the confined box",
        ));
    }
    let backend = settings
        .backend_argv
        .get("codex")
        .and_then(|words| words.first())
        .ok_or_else(|| LaneError::input("missing-setting", "backend_argv.codex is absent"))?;
    if !Path::new(backend).is_absolute() {
        return Err(LaneError::input(
            "missing-setting",
            "backend_argv.codex program is not absolute",
        ));
    }
    if request.observe {
        if settings
            .vendor_hosts
            .get("codex")
            .is_some_and(|hosts| !hosts.is_empty())
        {
            return Err(LaneError::input(
                "observe-conflict",
                "vendor_hosts.codex is already set; use an enforcing launch",
            ));
        }
        plan.observe_vendor()?;
    } else if settings.vendor_hosts.get("codex").is_none_or(Vec::is_empty) {
        return Err(LaneError::input(
            "missing-setting",
            "vendor_hosts.codex is empty; use --observe for one named first run",
        ));
    }
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?
        .to_path_buf();
    let reservation = reservation_path(&root, &request.run);
    let saved_reservation = read_reservation(&reservation)?;
    // An interrupted reservation settles without a new worker or vendor proxy.
    let recovering = saved_reservation
        .as_ref()
        .is_some_and(|saved| saved["phase"] == "started" || failed_driver_recovery(saved));
    let proxy_service = proxy_service_for_launch(
        &request.loop_name,
        request.observe,
        recovering,
        &mut proxy_state,
    )?;
    check_mount_roots(&plan, &settings, owner_home)?;
    let exe_word = crate::pinned::path_word(lane_bin, "owner-program")?;
    let podman_word = crate::pinned::path_word(&request.podman_bin, "owner-program")?;
    #[cfg(not(test))]
    crate::pinned::owner_executable(Path::new(&exe_word), caller.0)?;
    let driver = settings
        .driver_bin
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "driver_bin is absent"))?;
    let entry = settings
        .entry_bin
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "entry_bin is absent"))?;
    let letter = if let Some(source) = &request.rotation_source {
        rotation_source_bytes(&source.descriptor, &source.digest, owner_home, caller.0)?
    } else {
        home::read_letter(&request.letter, caller.0)?
    };
    let stop = letters::stop_declaration(&letter)?;
    let declared_sources = declared_sources(&letter)?;
    let selection =
        LaunchModel::select(&letter, request.model.as_deref(), request.effort.as_deref())?;
    plan.select_launch_model(&selection.record())?;
    let image = settings
        .image_digest
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "image_digest is absent"))?;
    let fresh_dir = planned_step_dir(&plan, "dispatch")?;
    let launch_argv = entry_argv(driver, &plan, request, &fresh_dir)?;
    let setup_argv = runtime_prepare_argv(&exe_word, &podman_word, owner_home, request)?;
    let mut checks = vec![
        "box gate: container options, read-only root and template, worker-owned writable leaves, proxy route",
        "worker UID allocation",
        "backend_argv.codex program",
        "bound mount roots",
        "installed template hashes",
        "recorded image identifier",
        "letter size and protected parent",
        "run reservation and worker UID table",
    ];
    let mut checks_on_launch = vec![
        "reservation recheck under exclusive lock",
        "private bound source inspection and pending evidence",
        "launcher host identity rootless worker and sibling probes",
        "private matrix result evaluation and publication",
    ];
    if request.observe {
        checks_on_launch.push("observing proxy socket readiness");
        checks_on_launch.push("private deferred vendor-socket source inspection");
        checks_on_launch.push("launcher host identity deferred worker and sibling connect probes");
        checks_on_launch.push("private deferred matrix result publication");
    } else {
        checks.push("enforcing vendor socket");
        checks.push("vendor proxy unit has an active invocation");
    }
    checks_on_launch.push("helper readiness");
    checks_on_launch.push("readback settlement");
    let environment = launch_environment(owner_home)?;
    crate::pinned::owner_executable(Path::new(&podman_word), Uid::effective().as_raw())?;
    crate::pinned::owner_executable(entry, caller.0)?;
    executable(driver, "lane driver")?;
    let driver_contract = driver_runtime_contract(driver, owner_home, &environment)?;
    let driver_sha256 = sha256(driver)?;
    checks.push("driver boxed-runtime contract");
    let report = image_report(owner_home, &request.loop_name)?;
    if report["image_digest"] != image {
        return Err(LaneError::input(
            "build-report",
            "image-build.json differs from workers.toml",
        ));
    }
    build::check_exec_probe(&report, &plan.document["runtime_argv"])?;
    let box_probe = box_route_probe(&report, &settings)?;
    checks.push("pinned Codex exec help and runtime options");
    checks.push("image and template have no inner bubblewrap route");
    check_pins(&plan, &settings, owner_home, request.observe, false)?;
    check_backend_image_program(
        &settings,
        &installed_generation(owner_home, &request.loop_name)?,
    )?;
    image_check(&request.podman_bin, image, owner_home)?;
    let proxy_bin = installed_proxy(owner_home, request)?;
    if let Some(saved) = saved_reservation
        && (saved["phase"] == "started" || failed_driver_recovery(&saved))
    {
        let runs = home::verify_host_launch_root(host_root, owner_home, &root, caller.0, root_uid)?;
        let report_step = if saved["rounds"]
            .as_array()
            .is_some_and(|rounds| !rounds.is_empty())
        {
            interrupted_report_step(&saved)?
        } else {
            None
        };
        report::require_unoccupied(&runs, &request.run, report_step).map_err(|mut error| {
            if error.kind == "launch-report" {
                error.detail.push_str("; ");
                error.detail.push_str(completed_recovery_guidance(&saved));
            }
            error
        })?;
        let selected_uid = saved["worker_uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .ok_or_else(|| {
                LaneError::input("launch-reservation", "started worker UID is invalid")
            })?;
        plan.select_worker_uid(selected_uid)?;
        plan.retain_attempt_wall(&saved["plan"])?;
        let preview = interrupted_recovery_preview(
            &saved,
            &plan,
            &request.letter,
            request,
            owner_home,
            crate::container_helper::process_presence,
        )?;
        if request.dry_run {
            checks.push("interrupted settlement process identities and complete attempt evidence");
            return Ok(
                json!({"schema":1,"command":"launch","dry_run":true,"plan":plan.document,"proxy_service":proxy_service,"bound_source_matrix":{"state":"not-applicable","reason":"interrupted settlement starts no new container"},"interrupted_settlement":preview,"checks_performed":checks,"changed":false,"wall_seconds":started.elapsed().as_secs_f64()}),
            );
        }
        return complete_interrupted_launch(
            owner_home,
            request,
            host_root,
            root_uid,
            &plan,
            &saved,
            lane_bin,
            started,
            on_failure,
            crate::container_helper::process_presence,
            |record| reaping::reap_interrupted_scope(record, owner_home),
        );
    }
    if request.expect_digest.is_some() {
        return Err(LaneError::input(
            "settlement-digest",
            "--expect-digest applies only to interrupted recovery",
        ));
    }
    if !request.dry_run && !cfg!(test) {
        reaping::ensure_scoped_new_launch()?;
    }
    let (worker_uid, skipped_runs) = {
        let _lock = lock_runs_root(&root, false, caller.0)?;
        let (base, count) = worker_range(owner_home, &request.loop_name)?;
        select_free_uid_with_census(&root, &request.run, base, count)?
    };
    let reservation_census =
        json!({"skipped_count":skipped_runs.len(),"skipped_names":skipped_runs});
    plan.select_worker_uid(worker_uid)?;
    crate::plan::verify_box_attestation(&plan.document)?;
    let box_gate = plan.document["box_gate"].clone();
    let dry_recovery = if request.dry_run {
        preview_dead_preparation(
            &root,
            &plan,
            &request.run,
            &request.letter,
            &skipped_runs,
            || {
                container_absent_for_run(
                    &request.podman_bin,
                    owner_home,
                    &request.loop_name,
                    &request.run,
                )
            },
        )?
    } else {
        Value::Null
    };
    if read_reservation(&reservation_path(&root, &request.run))?.is_none()
        && fs::symlink_metadata(&plan.home).is_ok()
    {
        return Err(LaneError::input(
            "already-exists",
            format!("{} already exists", plan.home.display()),
        ));
    }
    let verified_home = home::verify_host_prefix_from(host_root, owner_home, caller.0, root_uid)?;
    let verified_runs =
        home::verify_host_launch_root(host_root, owner_home, &root, caller.0, root_uid)?;
    let letter_dir = request
        .letter
        .parent()
        .ok_or_else(|| LaneError::input("letter-path", "letter has no parent directory"))?;
    let verified_letter =
        home::verify_host_launch_root(host_root, owner_home, letter_dir, caller.0, root_uid)?;
    let prepare_argv = private_argv(
        &exe_word,
        &podman_word,
        owner_home,
        request,
        worker_uid,
        &selection,
    )?;
    if request.dry_run {
        checks.push("dead preparation identity, absence, attempt evidence, plan comparison and retirement journal");
        let bound_source_matrix = matrix::preview(&plan)?;
        let mut preview_plan = plan.document.clone();
        preview_plan["declared_sources"] = json!(
            declared_sources
                .iter()
                .map(|source| json!({"name":source.name,"seed":source.seed}))
                .collect::<Vec<_>>()
        );
        preview_plan["reservation_census"] = reservation_census;
        let template = settings
            .template_dir
            .as_deref()
            .ok_or_else(|| LaneError::input("missing-setting", "template_dir is absent"))?;
        let hash_checks = [template.join("bin/codex"), template.join("bin/codex-code-mode-host"), template.join("config.toml"), template.join("AGENTS.md"), template.join("libexec/box-init")]
            .iter().map(|path| json!({"input":path,"spec":build::hash_preview(path.parent().unwrap_or_else(|| Path::new("/")))})).collect::<Vec<_>>();
        let prepare_preview = build::private_launch_preview(
            &request.podman_bin,
            prepare_argv,
            &environment,
            owner_home,
            60,
            "prepare-home",
            &verified_home,
            &root,
            &verified_runs,
            Some((letter_dir, &verified_letter)),
        )?;
        let setup_preview = build::private_launch_preview(
            &request.podman_bin,
            setup_argv,
            &environment,
            owner_home,
            60,
            "prepare-runtime",
            &verified_home,
            &root,
            &verified_runs,
            None,
        )?;
        let helper_preview = json!({"program":request.podman_bin,"argv":helper_argv(&exe_word, &plan.driver_dir, owner_home, &root)?});
        return Ok(
            json!({"schema":1,"command":"launch","dry_run":true,"observe":request.observe,"enforcing":!request.observe,"plan":preview_plan,"proxy_service":proxy_service,"box_gate":box_gate,"box_probe":box_probe,"bound_source_matrix":bound_source_matrix,"bound_source_probe_identity":"launcher host identity runs rootless Podman with --userns=host; worker and fixed sibling UIDs are selected inside separate probe containers","dead_preparation":dry_recovery,"checks_performed":checks,"checks_on_launch":checks_on_launch,"driver_sha256":driver_sha256,"driver_contract":driver_contract,"selection":{"worker_uid":worker_uid,"model":selection.record(),"method":"in-process read-only runs-root snapshot under shared lock"},"children_executed":[build::image_inspect_preview(&request.podman_bin, image, owner_home)?],"hash_checks_executed":hash_checks,"prepare_argv":prepare_preview,"setup_argv":setup_preview,"helper_argv":helper_preview,"invocation":{"program":entry,"argv":launch_argv},"environment":environment,"changed":false,"wall_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    let _preparation_lease = lock_run_preparation(&root, &request.run, caller.0)?;
    if let Some(mut old) = read_reservation(&reservation)? {
        let proof =
            prove_probe_absence_with(&old, crate::container_helper::process_presence, || {
                container_absent_for_run(
                    &request.podman_bin,
                    owner_home,
                    &request.loop_name,
                    &request.run,
                )
            })?;
        old["probe_absence_proof"] = proof;
        publish_reservation(&reservation, &old)?;
    }
    crate::pinned::owner_executable(Path::new(&exe_word), caller.0)?;
    let preparation = if let Some(source) = &request.rotation_source {
        build::run_checked_with_private_rotation(
            &request.podman_bin,
            prepare_argv,
            &environment,
            owner_home,
            60,
            "prepare-home",
            &verified_home,
            &root,
            &verified_runs,
            (letter_dir, &verified_letter),
            &source.descriptor,
        )
    } else {
        build::run_checked_with_private_launch(
            &request.podman_bin,
            prepare_argv,
            &environment,
            owner_home,
            60,
            "prepare-home",
            &verified_home,
            &root,
            &verified_runs,
            Some((letter_dir, &verified_letter)),
        )
    };
    let preparation = match preparation {
        Ok(preparation) => preparation,
        Err(error) => {
            let error = if request.rotation_source.is_some() {
                rotation_child_refusal(error)
            } else {
                error
            };
            let reservation = reservation_path(&root, &request.run);
            if read_reservation(&reservation)?.is_some() {
                let saved =
                    record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
                return Err(retain_startup_refusal(error, saved));
            }
            return Err(error);
        }
    };
    let reservation = reservation_path(&root, &request.run);
    {
        let _mailbox = lock_mailbox(&root, &request.run, caller.0)?;
        let mut record = read_reservation(&reservation)?.ok_or_else(|| {
            LaneError::input("helper-session", "protected run reservation is absent")
        })?;
        let placed_at = letters::unix_ns()?;
        record_dispatch_letter(
            &mut record,
            request.budget,
            &letter,
            stop,
            placed_at,
            owner_home,
            &fresh_dir,
        )?;
        record["driver_sha256"] = json!(driver_sha256);
        record["driver_contract"] = json!(driver_contract);
        publish_reservation(&reservation, &record)?;
    }
    if let Err(error) = crate::pinned::owner_executable(Path::new(&exe_word), caller.0) {
        let saved = record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
        return Err(retain_startup_refusal(error, saved));
    }
    let setup = build::run_checked_with_private_launch(
        &request.podman_bin,
        setup_argv.clone(),
        &environment,
        owner_home,
        60,
        "prepare-runtime",
        &verified_home,
        &root,
        &verified_runs,
        None,
    );
    if let Err(error) = setup {
        let error = if request.rotation_source.is_some() {
            rotation_child_refusal(error)
        } else {
            error
        };
        let saved = record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
        return Err(retain_startup_refusal(error, saved));
    }
    let evidence_path = protected_identity_dir(&plan.driver_dir)?.join("launch-evidence.json");
    let primary = matrix::probe_on_host(
        &plan,
        &reservation,
        owner_home,
        &evidence_path,
        caller.0,
        &request.podman_bin,
        &environment,
        false,
    );
    if let Err(error) = primary {
        let saved = record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
        return Err(retain_startup_refusal(error, saved));
    }
    let mut primary_environment = environment.clone();
    primary_environment.insert("SUPERLOOP_MATRIX_STAGE".into(), "publish-primary".into());
    if let Err(error) = build::run_checked_with_private_launch(
        &request.podman_bin,
        setup_argv.clone(),
        &primary_environment,
        owner_home,
        60,
        "bound-source",
        &verified_home,
        &root,
        &verified_runs,
        None,
    ) {
        let saved = record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
        return Err(retain_startup_refusal(error, saved));
    }
    let mut record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("helper-session", "protected run reservation is absent"))?;
    let launcher_pid = std::process::id();
    let launcher_start = match launch_process_start(launcher_pid) {
        Ok(start) => start,
        Err(error) => {
            let saved = record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
            return Err(retain_startup_refusal(error, saved));
        }
    };
    record["launcher_pid"] = json!(launcher_pid);
    record["launcher_start"] = json!(launcher_start);
    match launch_run_scope(&request.loop_name) {
        Ok(Some(scope)) => record["run_scope"] = scope,
        Ok(None) => {}
        Err(error) => {
            let saved = record_failed_pre_driver(&reservation, &mut None, &error, caller.0, false);
            return Err(retain_startup_refusal(error, saved));
        }
    }
    publish_reservation(&reservation, &record)?;
    let mut proxy = if request.observe {
        let mut observer_absence_proved = true;
        record["observer_state"] = json!("starting");
        publish_reservation(&reservation, &record)?;
        let started = start_observer(
            request,
            &plan,
            owner_home,
            &environment,
            &proxy_bin,
            &verified_runs,
            &mut observer_absence_proved,
            |pid, start| {
                record["observer_pid"] = json!(pid);
                record["observer_start"] = json!(start);
                record["observer_state"] = json!("running");
                publish_reservation(&reservation, &record)
            },
        );
        match started {
            Ok(child) => Some(child),
            Err(mut error) => {
                let saved = record_failed_pre_driver(
                    &reservation,
                    &mut None,
                    &error,
                    caller.0,
                    !observer_absence_proved,
                );
                error = retain_startup_refusal(error, saved);
                error.detail.push_str("; relaunch the same run with the same plan, letter and worker UID to retire the partial preparation");
                return Err(error);
            }
        }
    } else {
        None
    };
    if request.observe {
        let mut deferred_environment = environment.clone();
        deferred_environment.insert("SUPERLOOP_MATRIX_STAGE".into(), "prepare-deferred".into());
        let deferred = build::run_checked_with_private_launch(
            &request.podman_bin,
            setup_argv.clone(),
            &deferred_environment,
            owner_home,
            60,
            "bound-source",
            &verified_home,
            &root,
            &verified_runs,
            None,
        );
        if let Err(error) = deferred {
            let saved = record_failed_pre_driver(&reservation, &mut proxy, &error, caller.0, false);
            return Err(retain_startup_refusal(error, saved));
        }
        if let Err(error) = matrix::probe_on_host(
            &plan,
            &reservation,
            owner_home,
            &evidence_path,
            caller.0,
            &request.podman_bin,
            &environment,
            true,
        ) {
            let saved = record_failed_pre_driver(&reservation, &mut proxy, &error, caller.0, false);
            return Err(retain_startup_refusal(error, saved));
        }
        deferred_environment.insert("SUPERLOOP_MATRIX_STAGE".into(), "publish-deferred".into());
        if let Err(error) = build::run_checked_with_private_launch(
            &request.podman_bin,
            setup_argv,
            &deferred_environment,
            owner_home,
            60,
            "bound-source",
            &verified_home,
            &root,
            &verified_runs,
            None,
        ) {
            let saved = record_failed_pre_driver(&reservation, &mut proxy, &error, caller.0, false);
            return Err(retain_startup_refusal(error, saved));
        }
    }
    record["helper_spawn_state"] = json!("starting");
    publish_reservation(&reservation, &record)?;
    let (mut helper, helper_parent_start, helper_stderr) = match start_helper_with_program(
        request,
        &plan,
        owner_home,
        &environment,
        &verified_home,
        &root,
        &verified_runs,
        lane_bin,
        |pid, start| {
            let mut saved = read_reservation(&reservation)?.ok_or_else(|| {
                LaneError::input(
                    "helper-start",
                    "reservation vanished before parent identity",
                )
            })?;
            saved["helper_parent_pid"] = json!(pid);
            saved["helper_parent_start"] = json!(start);
            saved["helper_spawn_state"] = json!("running");
            publish_reservation(&reservation, &saved)
        },
    ) {
        Ok(helper) => helper,
        Err(error) => {
            let saved = record_failed_pre_driver(&reservation, &mut proxy, &error, caller.0, false);
            return Err(retain_startup_refusal(error, saved));
        }
    };
    let mut record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("helper-session", "protected run reservation is absent"))?;
    record["helper_parent_pid"] = json!(helper.id());
    record["helper_parent_start"] = json!(helper_parent_start);
    record["helper_spawn_state"] = json!("running");
    publish_reservation(&reservation, &record)?;
    let mut driver_started = false;
    let mut child_end = build::ChildEnd::default();
    let result = crate::container_helper::host_launch_bound(&record).and_then(|bound| {
        build::run_checked_with_pid(
            entry,
            launch_argv,
            &environment,
            owner_home,
            bound,
            "driver-launch",
            &mut child_end,
            |pid| {
                let path = reservation_path(&root, &request.run);
                let mut record = read_reservation(&path)?.ok_or_else(|| {
                    LaneError::input("helper-session", "protected run reservation is absent")
                })?;
                if record["phase"] != "preparing"
                    || record["loop"] != request.loop_name
                    || record["run"] != request.run
                {
                    return Err(LaneError::input(
                        "helper-session",
                        "reservation changed before driver start",
                    ));
                }
                record["driver_entry_pid"] = json!(pid);
                record["driver_entry_start"] = json!(crate::container_helper::process_start(pid)?);
                publish_reservation(&path, &record)?;
                driver_started = true;
                drop(generation_guard.take());
                Ok(())
            },
        )
    });
    let step_directory = result.as_ref().map_or(Ok(()), |output| {
        record_fresh_step_directory(&plan, &request.run, output)
    });
    persist_settlement_field(
        &reservation,
        "driver_end",
        driver_completion(&result, driver_started, &child_end),
    )?;
    let helper_stop = stop_helper(&mut helper, &plan, &verified_runs);
    if let Some(status) = helper
        .try_wait()
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?
    {
        persist_settlement_field(
            &reservation,
            "helper_end",
            helper_parent_end(
                helper.id(),
                helper_parent_start,
                status,
                helper_stop.as_ref().err(),
            ),
        )?;
    }
    let observer_stop = if let Some((child, _)) = proxy.as_mut() {
        Some(stop_observer(child)?)
    } else {
        None
    };
    helper_stop_with_stderr(helper_stop, &mut helper, helper_stderr)?;
    let observer_end = if let Some((child, slot)) = proxy.as_mut() {
        let mut end = observer_stop.unwrap_or_default();
        end["pid"] = json!(child.id());
        end["start"] = record["observer_start"].clone();
        end["socket"] = json!({"state":"pending"});
        persist_settlement_field(&reservation, "observer_end", end.clone())?;
        end["socket"] = observer_socket_disposition(slot, caller.0);
        persist_settlement_field(&reservation, "observer_end", end.clone())?;
        end
    } else {
        json!({"state":"not-started","socket":{"state":"not-applicable"}})
    };
    if !request.observe {
        persist_settlement_field(&reservation, "observer_end", observer_end.clone())?;
    }
    let observed = if request.observe {
        let argv = vec![
            "unshare".into(),
            exe_word.clone(),
            "_observed-hosts".into(),
            request.loop_name.clone(),
            request.run.clone(),
            "--owner-home".into(),
            crate::pinned::path_word(owner_home, "owner-home")?,
        ];
        crate::pinned::owner_executable(Path::new(&exe_word), caller.0)?;
        let output = build::run_checked_with_private_launch(
            &request.podman_bin,
            argv,
            &environment,
            owner_home,
            30,
            "host-observation",
            &verified_home,
            &root,
            &verified_runs,
            None,
        );
        output.and_then(|text| {
            serde_json::from_str::<Value>(&text)
                .map_err(|error| LaneError::input("host-observation", error.to_string()))
        })
    } else {
        Ok(Value::Null)
    };
    persist_settlement_field(
        &reservation,
        "observation_end",
        json!(
            observed
                .as_ref()
                .map_or_else(LaneError::line, |_| "completed".into())
        ),
    )?;
    let settle_argv = vec![
        "unshare".into(),
        exe_word.clone(),
        "_settle-evidence".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
    ];
    crate::pinned::owner_executable(Path::new(&exe_word), caller.0)?;
    let settlement = build::run_checked_with_private_launch(
        &request.podman_bin,
        settle_argv,
        &environment,
        owner_home,
        60,
        "settle-evidence",
        &verified_home,
        &root,
        &verified_runs,
        None,
    );
    persist_settlement_field(
        &reservation,
        "readback_end",
        json!(
            settlement
                .as_ref()
                .map_or_else(LaneError::line, |_| "completed".into())
        ),
    )?;
    let reaping = reaping::reap_scope(&record, owner_home);
    persist_settlement_field(
        &reservation,
        "reaping",
        reaping.as_ref().map_or_else(
            |error| json!({"state":"failed","detail":error.line()}),
            Clone::clone,
        ),
    )?;
    let socket_good = ["removed", "absent", "not-applicable"]
        .contains(&observer_end["socket"]["state"].as_str().unwrap_or_default());
    let observer_good = !request.observe || observer_end["state"] == "stopped";
    let phase = if result.is_ok()
        && step_directory.is_ok()
        && observed.is_ok()
        && settlement.is_ok()
        && settlement_observer_ready(
            &observer_end,
            if request.observe {
                "ended"
            } else {
                "not-started"
            },
            false,
        )
        && reaping
            .as_ref()
            .is_ok_and(|report| reaping::reaping_verdict(report).is_ok())
    {
        "settled"
    } else {
        "failed"
    };
    let _mailbox = lock_mailbox(&root, &request.run, caller.0)?;
    let mut record = read_reservation(&reservation)?.ok_or_else(|| {
        LaneError::input(
            "launch-reservation",
            "protected reservation vanished before settlement",
        )
    })?;
    if phase == "failed" {
        let round = record["rounds"]
            .as_array_mut()
            .and_then(|rounds| rounds.last_mut())
            .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
        round["phase"] = json!("failed");
        if let Some(line) = reaping.as_ref().err().map(LaneError::line).or_else(|| {
            reaping.as_ref().ok().and_then(|report| {
                reaping::reaping_verdict(report)
                    .err()
                    .map(|error| error.line())
            })
        }) {
            round["settlement_error"] = json!(line);
        }
    }
    record["phase"] = json!(phase);
    record["observer_state"] = json!(if request.observe {
        "ended"
    } else {
        "not-started"
    });
    record["settlement_uncertain"] = json!(
        observer_end["socket"]["state"] == "uncertain" || observer_end["state"] == "uncertain"
    );
    let round_dir = report::round_dir(&plan, &record, None)?;
    publish_reservation(&reservation, &record)?;
    if !socket_good {
        return Err(LaneError::operation(
            "observer-socket",
            format!("observer socket disposition: {}", observer_end["socket"]),
        ));
    }
    if !observer_good {
        return Err(LaneError::operation(
            "proxy-stop",
            "observer exited before its requested stop",
        ));
    }
    step_directory?;
    reaping::reaping_verdict(&reaping?)?;
    let output = result?;
    let observed = observed?;
    let settlement = settlement_document(&settlement?)?;
    let publication = report::credential_publication(&record)?;
    let report = json!({"schema":1,"command":"launch","dry_run":false,"observe":request.observe,"enforcing":!request.observe,"observed":observed,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":round_dir,"preparation":preparation.trim_end(),"driver_report":driver_report_for_reader(output.trim_end()),"settlement":settlement,"credential_publication":publication,"evidence":"driver directory outside home","wall_seconds":started.elapsed().as_secs_f64()});
    report::finish_with_fallback(&verified_runs, &request.run, None, report, on_failure)
}

fn record_failed_pre_driver(
    reservation: &Path,
    proxy: &mut Option<(Child, crate::SocketSlot)>,
    reason: &LaneError,
    owner_uid: u32,
    uncertain_observer_start: bool,
) -> Result<(), LaneError> {
    #[cfg(test)]
    if let Some(hook) = BEFORE_PRE_DRIVER_SAVE.with(std::cell::Cell::take) {
        hook(reservation)?;
    }
    let mut record = read_reservation(reservation)?.ok_or_else(|| {
        LaneError::input(
            "launch-reservation",
            "protected reservation vanished before failure record",
        )
    })?;
    let observer_end = if let Some((child, slot)) = proxy.as_mut() {
        let stopped = stop_observer(child);
        let socket = if stopped.is_ok() {
            observer_socket_disposition(slot, owner_uid)
        } else {
            json!({"state":"uncertain","detail":stopped.as_ref().err().map(LaneError::line)})
        };
        let mut end =
            stopped.unwrap_or_else(|error| json!({"state":"uncertain","detail":error.line()}));
        end["pid"] = json!(child.id());
        end["start"] = record["observer_start"].clone();
        end["socket"] = socket;
        end
    } else if uncertain_observer_start {
        json!({"state":"uncertain","socket":{"state":"uncertain"}})
    } else {
        json!({"state":"not-started","socket":{"state":"not-applicable"}})
    };
    record["phase"] = json!("failed");
    record["pre_driver_failure"] = json!(reason.line());
    record["driver_end"] = json!({"state":"not-started"});
    if record["helper_end"]["state"] != "completed" {
        record["helper_end"] = if record["helper_spawn_state"] == "not-started" {
            json!({"state":"not-started"})
        } else {
            json!({"state":"failed","detail":reason.line()})
        };
    }
    if let Some(round) = record["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
    {
        round["phase"] = json!("failed");
        round["ended_by"] = json!("failed-at-start");
        round["settlement_error"] = json!(reason.line());
    }
    record["observer_end"] = observer_end;
    record["observer_state"] = json!(if record["observer_pid"].is_number()
        || uncertain_observer_start
        || reason.kind == "proxy-start"
    {
        "failed"
    } else {
        "not-started"
    });
    record["settlement_uncertain"] = json!(
        record["observer_end"]["socket"]["state"] == "uncertain"
            || record["observer_end"]["state"] == "uncertain"
    );
    publish_reservation(reservation, &record)
}

/// Verify the driver directory and record the worker reply outside its home.
///
/// # Errors
///
/// Refuses a linked or foreign run directory and an invalid worker reply.
pub fn private_settle(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let (plan, _settings) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let root = plan.driver_dir.clone();
    verify_settlement_driver_dir(&root, loop_uid)?;
    let (_, letter_reconciliation) = letters::reconcile_run(&plan, run, owner_home, 0, true)?;
    if let Err(error) = rounds::recover_step_directory(&plan, run) {
        rounds::record_failed_settlement(&plan, run, &error)?;
        return Err(error);
    }
    let readback = match record_readback(&plan, loop_name, run, true) {
        Ok(readback) => readback,
        Err(error) => {
            rounds::record_failed_settlement(&plan, run, &error)?;
            return Err(error);
        }
    };
    rounds::record_settlement(&plan, loop_name, run, &readback)?;
    let runs_root = root
        .parent()
        .ok_or_else(|| LaneError::input("round-end", "runs root is absent"))?;
    let settled = read_reservation(&reservation_path(runs_root, run))?
        .ok_or_else(|| LaneError::input("round-end", "settled reservation is absent"))?;
    let ended_by = rounds::settled_round_end(&settled)?;
    Ok(
        json!({"schema":1,"command":"settle-evidence","driver_dir":root,"owner_uid":loop_uid,"mode":"0700","paths_changed":0,"letter_reconciliation":letter_reconciliation,"readback":readback,"ended_by":ended_by}),
    )
}

pub(super) fn verify_settlement_driver_dir(root: &Path, loop_uid: u32) -> Result<(), LaneError> {
    let meta = fs::symlink_metadata(root)
        .map_err(|error| LaneError::input("driver-dir", format!("{}: {error}", root.display())))?;
    if !meta.is_dir() || meta.uid() != loop_uid || meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(LaneError::input(
            "driver-dir",
            format!(
                "{} differs from loop UID {loop_uid} mode 0700",
                root.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn settlement_observer_ready(
    observer_end: &Value,
    observer_state: &str,
    settlement_uncertain: bool,
) -> bool {
    !settlement_uncertain
        && ["removed", "absent", "not-applicable"]
            .contains(&observer_end["socket"]["state"].as_str().unwrap_or_default())
        && match observer_state {
            "ended" => observer_end["state"] == "stopped",
            "not-started" => observer_end["state"] == "not-started",
            _ => false,
        }
}

#[allow(clippy::too_many_lines)]
fn record_readback(
    plan: &Plan,
    loop_name: &str,
    run: &str,
    persist: bool,
) -> Result<Value, LaneError> {
    record_readback_with_owner(plan, loop_name, run, persist, 0)
}

#[allow(clippy::too_many_lines)]
fn record_readback_with_owner(
    plan: &Plan,
    loop_name: &str,
    run: &str,
    persist: bool,
    owner_uid: u32,
) -> Result<Value, LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("readback-plan", "run has no protected root"))?;
    let _protected_root = home::pin_parent(root, owner_uid)?;
    let saved = read_reservation(&reservation_path(root, run))?
        .ok_or_else(|| LaneError::input("readback-plan", "protected reservation is absent"))?;
    if saved["loop"] != loop_name
        || saved["run"] != run
        || saved["plan"]["home"] != plan.home.display().to_string()
        || saved["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "readback-plan",
            "saved run plan differs from the selected home",
        ));
    }
    let worker_uid = saved["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("readback-plan", "saved worker UID is absent"))?;
    let step = saved["active_round"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-record", "active round is absent"))?;
    letters::valid_step(step)?;
    let mut readback = inspect_readback(
        &plan.home.join(format!(".local/outbox/{step}.md")),
        worker_uid,
    )?;
    let launch_evidence_path =
        protected_identity_dir(&plan.driver_dir)?.join("launch-evidence.json");
    let launch_evidence: Value = serde_json::from_slice(&crate::pinned::read_private(
        root,
        &launch_evidence_path,
        Uid::effective().as_raw(),
        0o600,
        65_536,
    )?)
    .map_err(|error| LaneError::input("readback-evidence", error.to_string()))?;
    if launch_evidence["bound_source_matrix"]["git_worktree"]["add_remove"] != true {
        return Err(LaneError::input(
            "readback-evidence",
            "Git worktree launch canary is absent",
        ));
    }
    readback["git_worktree_canary"] =
        launch_evidence["bound_source_matrix"]["git_worktree"].clone();
    let readback_path = plan
        .driver_dir
        .join(format!("readback-evidence-{step}.json"));
    if let Ok(existing) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&readback_path)
    {
        let meta = existing
            .metadata()
            .map_err(|error| LaneError::input("readback-evidence", error.to_string()))?;
        if !meta.is_file()
            || meta.uid() != Uid::effective().as_raw()
            || meta.permissions().mode() & 0o7777 != 0o600
            || meta.len() > 65_536
        {
            return Err(LaneError::input(
                "readback-evidence",
                "saved readback is not bounded owner evidence",
            ));
        }
        let mut bytes = Vec::new();
        existing
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|error| LaneError::input("readback-evidence", error.to_string()))?;
        let saved: Value = serde_json::from_slice(&bytes)
            .map_err(|error| LaneError::input("readback-evidence", error.to_string()))?;
        if saved != readback {
            return Err(LaneError::input(
                "readback-evidence",
                "saved readback differs from the worker reply",
            ));
        }
        return Ok(readback);
    }
    if !persist {
        return Ok(readback);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&readback_path)
        .map_err(|error| {
            LaneError::operation(
                "readback-evidence",
                format!("{}: {error}", readback_path.display()),
            )
        })?;
    serde_json::to_writer(&mut file, &readback)
        .map_err(|error| LaneError::operation("readback-evidence", error.to_string()))?;
    file.write_all(b"\n")
        .and_then(|()| file.sync_all())
        .map_err(|error| LaneError::operation("readback-evidence", error.to_string()))?;
    Ok(readback)
}

fn inspect_readback(path: &Path, worker_uid: u32) -> Result<Value, LaneError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| LaneError::input("readback", format!("{}: {error}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("readback", format!("{}: {error}", path.display())))?;
    if !meta.is_file() || meta.uid() != worker_uid || meta.permissions().mode() & 0o022 != 0 {
        return Err(LaneError::input(
            "readback",
            format!(
                "{} is not a regular worker-owned reply without group or other write",
                path.display()
            ),
        ));
    }
    if meta.len() == 0 || meta.len() > 1_048_576 {
        return Err(LaneError::input(
            "readback",
            format!(
                "{} has {} bytes; expected 1 through 1048576",
                path.display(),
                meta.len()
            ),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("readback", format!("{}: {error}", path.display())))?;
    if bytes.len() != usize::try_from(meta.len()).unwrap_or(0) {
        return Err(LaneError::input(
            "readback",
            format!("{} changed while reading", path.display()),
        ));
    }
    Ok(
        json!({"path":path,"bytes":bytes.len(),"sha256":build::sha256_bytes(&bytes, path.parent().unwrap_or_else(|| Path::new("/")))?,"worker_uid":worker_uid}),
    )
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn start_observer(
    request: &LaunchRequest,
    plan: &Plan,
    owner_home: &Path,
    environment: &BTreeMap<String, String>,
    proxy_bin: &Path,
    verified_runs: &OwnedFd,
    observer_absence_proved: &mut bool,
    on_spawn: impl FnOnce(u32, u64) -> Result<(), LaneError>,
) -> Result<(Child, crate::SocketSlot), LaneError> {
    let socket = plan.document["vendor_socket"]
        .as_str()
        .ok_or_else(|| LaneError::operation("plan-json", "observing socket is absent"))?;
    let socket_dir = plan.document["mounts"]
        .as_array()
        .and_then(|mounts| {
            mounts
                .iter()
                .find(|mount| mount["target"] == "/home/worker/.local/vendor")
        })
        .and_then(|mount| mount["source"].as_str())
        .ok_or_else(|| LaneError::operation("plan-json", "vendor source is absent"))?;
    let socket_path = Path::new(socket_dir).join(socket);
    let socket_slot = crate::SocketSlot::pinned(&socket_path, Uid::effective().as_raw())?;
    let socket_directory_fd = socket_slot.directory_fd();
    let loop_uid = u64::from(crate::plan::loop_uid(&plan.document)?);
    crate::pinned::owner_executable(&request.podman_bin, Uid::effective().as_raw())?;
    let proxy_word = crate::pinned::owner_executable_word(proxy_bin, Uid::effective().as_raw())?;
    let inherited_fd = verified_runs.as_raw_fd();
    let mut child = Command::new(&request.podman_bin);
    child
        .args(["unshare", proxy_word.as_str(), "--socket"])
        .arg(&socket_path)
        .args([
            "--group",
            &loop_uid.to_string(),
            "--observe",
            &request.run,
            "--observed-file",
        ])
        .arg(observation_path(plan, &request.run)?)
        .args(["--verified-runs-root-fd", &inherited_fd.to_string()])
        .args(["--verified-socket-dir-fd", &socket_directory_fd.to_string()])
        .arg("--owner-home")
        .arg(owner_home)
        .env_clear()
        .envs(environment)
        .current_dir(owner_home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    #[allow(unsafe_code)]
    // SAFETY: only the async-signal-safe fcntl syscall runs between fork and exec.
    unsafe {
        child.pre_exec(move || {
            let flags = libc::fcntl(inherited_fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(inherited_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(socket_directory_fd, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(
                    socket_directory_fd,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    reaping::attach_command(&mut child)?;
    let mut child = crate::fixture_exec::spawn(&mut child)
        .map_err(|error| LaneError::operation("proxy-start", error.to_string()))?;
    identify_started_observer(
        &mut child,
        observer_absence_proved,
        crate::container_helper::process_start,
        on_spawn,
        |child| stop_observer(child).map(|_| ()),
    )?;
    let Some(stderr) = child.stderr.take() else {
        stop_observer(&mut child)?;
        *observer_absence_proved = true;
        return Err(LaneError::operation(
            "proxy-start",
            "observer stderr pipe is absent",
        ));
    };
    let stderr_drain = std::thread::spawn(move || bounded_observer_stderr(stderr));
    let began = Instant::now();
    while began.elapsed() < Duration::from_secs(10) {
        if socket_slot.metadata().is_ok_and(|meta| {
            meta.is_some_and(|meta| {
                meta.st_mode & libc::S_IFMT == libc::S_IFSOCK && meta.st_mode & 0o7777 == 0o660
            })
        }) {
            return Ok((child, socket_slot));
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| LaneError::operation("proxy-start", error.to_string()))?
        {
            *observer_absence_proved = true;
            let last = stderr_drain.join().unwrap_or_default();
            return Err(LaneError::operation(
                "proxy-start",
                observer_exit_detail(status, &last),
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    stop_observer(&mut child)?;
    *observer_absence_proved = true;
    Err(LaneError::operation(
        "proxy-start",
        format!("{} did not become ready", socket_path.display()),
    ))
}

fn identify_started_observer(
    child: &mut Child,
    observer_absence_proved: &mut bool,
    process_start: impl FnOnce(u32) -> Result<u64, LaneError>,
    on_spawn: impl FnOnce(u32, u64) -> Result<(), LaneError>,
    stop: impl FnOnce(&mut Child) -> Result<(), LaneError>,
) -> Result<(), LaneError> {
    *observer_absence_proved = false;
    let start = match process_start(child.id()) {
        Ok(start) => start,
        Err(error) => {
            stop(child)?;
            *observer_absence_proved = true;
            return Err(error);
        }
    };
    if let Err(error) = on_spawn(child.id(), start) {
        stop(child)?;
        *observer_absence_proved = true;
        return Err(error);
    }
    Ok(())
}

fn bounded_observer_stderr(mut stderr: impl std::io::Read) -> Vec<u8> {
    let mut tail = VecDeque::with_capacity(4096);
    let mut buffer = [0_u8; 1024];
    while let Ok(count) = stderr.read(&mut buffer) {
        if count == 0 {
            break;
        }
        for byte in &buffer[..count] {
            if tail.len() == 4096 {
                tail.pop_front();
            }
            tail.push_back(*byte);
        }
    }
    tail.into_iter().collect()
}

fn observer_exit_detail(status: std::process::ExitStatus, stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let last = text.lines().rev().find(|line| !line.is_empty());
    last.map_or_else(
        || format!("observer exited {status}"),
        |line| format!("observer exited {status}: {line}"),
    )
}

fn reservation_differences(record: &Value, next: &Value) -> Vec<&'static str> {
    [
        ("phase", "phase"),
        ("loop", "loop"),
        ("run", "run"),
        ("worker_uid", "worker UID"),
        ("plan", "plan document"),
        ("letter_source", "letter source"),
    ]
    .into_iter()
    .filter_map(|(key, label)| (record[key] != next[key]).then_some(label))
    .collect()
}

fn prior_attempt_started(driver_dir: &Path) -> Result<bool, LaneError> {
    for attempt in 1..=4 {
        let path = protected_identifier_path(driver_dir, attempt)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(LaneError::input(
                    "launch-reservation",
                    format!("{}: {error}", path.display()),
                ));
            }
        }
    }
    let custody = protected_identity_dir(driver_dir)?;
    let metadata = match fs::symlink_metadata(&custody) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LaneError::input(
                "launch-reservation",
                format!("{}: {error}", custody.display()),
            ));
        }
    };
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(LaneError::input(
            "launch-reservation",
            format!("{} is not owner-private attempt custody", custody.display()),
        ));
    }
    for attempt in 1..=4 {
        for suffix in ["start", "status"] {
            let path = custody.join(format!("container-attempt-{attempt}.{suffix}.json"));
            match fs::symlink_metadata(&path) {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(LaneError::input(
                        "launch-reservation",
                        format!("{}: {error}", path.display()),
                    ));
                }
            }
        }
    }
    Ok(false)
}

fn launcher_identity(record: &Value) -> Result<Option<(u32, u64)>, LaneError> {
    match (
        record["launcher_pid"].as_u64(),
        record["launcher_start"].as_u64(),
    ) {
        (None, None) => Ok(None),
        (Some(pid), Some(start)) => Ok(Some((
            u32::try_from(pid).map_err(|_| {
                LaneError::input("launch-reservation", "recorded launcher PID is invalid")
            })?,
            start,
        ))),
        _ => Err(LaneError::input(
            "launch-reservation",
            "recorded launcher identity is incomplete",
        )),
    }
}

fn observer_identity(record: &Value) -> Result<Option<(u32, u64)>, LaneError> {
    match (
        record["observer_pid"].as_u64(),
        record["observer_start"].as_u64(),
    ) {
        (None, None) => Ok(None),
        (Some(pid), Some(start)) => Ok(Some((
            u32::try_from(pid).map_err(|_| {
                LaneError::input("launch-reservation", "recorded observer PID is invalid")
            })?,
            start,
        ))),
        _ => Err(LaneError::input(
            "launch-reservation",
            "recorded observer identity is incomplete",
        )),
    }
}

fn helper_identity(record: &Value) -> Result<Option<(u32, u64)>, LaneError> {
    match (
        record["helper_pid"].as_u64(),
        record["helper_start"].as_u64(),
    ) {
        (None, None) => Ok(None),
        (Some(pid), Some(start)) => Ok(Some((
            u32::try_from(pid).map_err(|_| {
                LaneError::input("launch-reservation", "recorded helper PID is invalid")
            })?,
            start,
        ))),
        _ => Err(LaneError::input(
            "launch-reservation",
            "recorded helper identity is incomplete",
        )),
    }
}

fn helper_parent_identity(record: &Value) -> Result<Option<(u32, u64)>, LaneError> {
    match (
        record["helper_parent_pid"].as_u64(),
        record["helper_parent_start"].as_u64(),
    ) {
        (None, None) => Ok(None),
        (Some(pid), Some(start)) => Ok(Some((
            u32::try_from(pid).map_err(|_| {
                LaneError::input(
                    "launch-reservation",
                    "recorded helper parent PID is invalid",
                )
            })?,
            start,
        ))),
        _ => Err(LaneError::input(
            "launch-reservation",
            "recorded helper parent identity is incomplete",
        )),
    }
}

fn helper_parent_absence_evidence(record: &Value) -> Option<&'static str> {
    if record["phase"] == "settled" && record["settlement_uncertain"] != true {
        return Some("recorded-settlement");
    }
    if record["helper_end"]["state"] == "completed"
        && record["helper_end"]["parent_pid"].as_u64().is_some()
        && record["helper_end"]["parent_start"].as_u64().is_some()
        && record["helper_end"]["status"].as_str().is_some()
    {
        return Some("completed-parent-end");
    }
    if record["phase"] != "started"
        && record["helper_spawn_state"] == "not-started"
        && record["helper_pid"].is_null()
    {
        return Some("helper-never-spawned");
    }
    None
}

pub(crate) fn terminal_before_launcher(record: &Value) -> bool {
    record["phase"] == "failed"
        && record["pre_driver_failure"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
        && record["settlement_uncertain"] == false
        && record["observer_state"] == "not-started"
        && record["helper_spawn_state"] == "not-started"
        && record["driver_end"]["state"] == "not-started"
        && record["helper_end"]["state"] == "not-started"
        && record["observer_end"]["state"] == "not-started"
        && record["observer_end"]["socket"]["state"] == "not-applicable"
        && [
            "launcher_pid",
            "launcher_start",
            "driver_entry_pid",
            "driver_entry_start",
            "helper_pid",
            "helper_start",
            "helper_parent_pid",
            "helper_parent_start",
            "observer_pid",
            "observer_start",
        ]
        .iter()
        .all(|field| record[*field].is_null())
        && ["driver_end", "helper_end", "observer_end"]
            .iter()
            .all(|field| {
                ["pid", "start", "parent_pid", "parent_start", "status"]
                    .iter()
                    .all(|key| record[*field][*key].is_null())
            })
}

fn recorded_observer_socket(record: &Value) -> Result<Option<PathBuf>, LaneError> {
    if !record["plan"]["vendor_mode"].is_string() {
        return Ok(None);
    }
    let name = record["plan"]["vendor_socket"].as_str().ok_or_else(|| {
        LaneError::input("launch-reservation", "old observer socket name is absent")
    })?;
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(LaneError::input(
            "launch-reservation",
            "old observer socket name is invalid",
        ));
    }
    let parent = record["plan"]["mounts"]
        .as_array()
        .and_then(|mounts| {
            mounts
                .iter()
                .find(|mount| mount["target"] == "/home/worker/.local/vendor")
        })
        .and_then(|mount| mount["source"].as_str())
        .ok_or_else(|| {
            LaneError::input(
                "launch-reservation",
                "old vendor socket directory is absent",
            )
        })?;
    Ok(Some(Path::new(parent).join(name)))
}

#[allow(clippy::too_many_lines)]
fn recovery_record_with(
    record: &Value,
    next: &Value,
    root: &Path,
    driver_dir: &Path,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Option<Value>, LaneError> {
    let different = reservation_differences(record, next);
    let dead_pre_driver = record["phase"] == "failed"
        && record["pre_driver_failure"].is_string()
        && record["driver_entry_pid"].is_null()
        && record["driver_end"]["state"] == "not-started";
    if record["phase"] != "preparing" && !dead_pre_driver
        || record["loop"] != next["loop"]
        || record["run"] != next["run"]
    {
        return Err(LaneError::input(
            "launch-reservation",
            format!(
                "reservation differs from this run in: {}",
                different.join(", ")
            ),
        ));
    }
    let launcher = launcher_identity(record)?;
    let liveness = launcher.map_or(
        crate::container_helper::ProcessPresence::Unknown,
        |(pid, start)| presence(pid, start),
    );
    match liveness {
        crate::container_helper::ProcessPresence::Present => {
            return Err(LaneError::input(
                "launch-busy",
                "the earlier launcher is still alive",
            ));
        }
        crate::container_helper::ProcessPresence::Unknown if launcher.is_some() => {
            return Err(LaneError::input(
                "launch-reservation",
                "the earlier launcher's absence cannot be established",
            ));
        }
        _ => {}
    }
    if prior_attempt_started(driver_dir)? {
        return Err(LaneError::input(
            "launch-reservation",
            "an earlier container attempt may have started; the run is retained; for a dead resumed round retry launch LOOP RUN --round STEP --dry-run with its active step, then apply that recovery; after a by-report settlement place send-letter LOOP RUN --step NEW --letter FILE and launch LOOP RUN --round NEW; use settle LOOP RUN --round STEP --dry-run only while the selected round remains failed",
        ));
    }
    let observer_state = record["observer_state"].as_str().ok_or_else(|| {
        LaneError::input(
            "launch-reservation",
            "the earlier reservation did not state its observer",
        )
    })?;
    if !["not-started", "starting", "running", "failed"].contains(&observer_state) {
        return Err(LaneError::input(
            "launch-reservation",
            "the earlier observer state is invalid",
        ));
    }
    if observer_state == "starting" && observer_identity(record)?.is_none() {
        return Err(LaneError::input(
            "launch-reservation",
            "the earlier observer may have started without a recorded identity",
        ));
    }
    if record["settlement_uncertain"] == true && observer_identity(record)?.is_none() {
        return Err(LaneError::input(
            "launch-reservation",
            "the earlier observer may have started without a recorded identity",
        ));
    }
    let observer = observer_identity(record)?;
    if (observer_state == "running" && observer.is_none())
        || (observer_state == "not-started" && observer.is_some())
    {
        return Err(LaneError::input(
            "launch-reservation",
            "the earlier observer state and identity disagree",
        ));
    }
    if let Some((pid, start)) = observer {
        match presence(pid, start) {
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "launch-busy",
                    "the earlier observer is still alive",
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "launch-reservation",
                    "the earlier observer's absence cannot be established",
                ));
            }
            crate::container_helper::ProcessPresence::Absent => {}
        }
    }
    if let Some((pid, start)) = helper_identity(record)? {
        match presence(pid, start) {
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "launch-busy",
                    "the earlier helper is still alive",
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "launch-reservation",
                    "the earlier helper's absence cannot be established",
                ));
            }
            crate::container_helper::ProcessPresence::Absent => {}
        }
    }
    match helper_parent_identity(record)? {
        Some((pid, start)) => match presence(pid, start) {
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "launch-busy",
                    "the earlier helper parent is still alive",
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "launch-reservation",
                    "the earlier helper parent's absence cannot be established",
                ));
            }
            crate::container_helper::ProcessPresence::Absent => {}
        },
        None if helper_parent_absence_evidence(record).is_some() => {}
        None => {
            return Err(LaneError::input(
                "launch-reservation",
                "the earlier helper parent's absence has no recorded proof",
            ));
        }
    }
    if let Some(path) = recorded_observer_socket(record)? {
        let slot = crate::SocketSlot::pinned(&path, Uid::effective().as_raw())?;
        if observer.is_none()
            && observer_state != "failed"
            && slot
                .metadata()
                .map_err(|error| {
                    LaneError::input("launch-reservation", format!("{}: {error}", path.display()))
                })?
                .is_some()
        {
            return Err(LaneError::input(
                "launch-reservation",
                "old observer socket exists without a recorded observer identity",
            ));
        }
    }
    if different.is_empty() {
        return Ok(None);
    }
    let Some((pid, start)) = launcher else {
        if terminal_before_launcher(record) {
            let old_plan = serde_json::to_vec(&record["plan"])
                .map_err(|error| LaneError::operation("launch-reservation", error.to_string()))?;
            return Ok(Some(
                json!({"state":"retiring","old_plan_sha256":build::sha256_bytes(&old_plan, root)?,"different_fields":different,"launcher_pid":null,"launcher_start":null,"observer_pid":null,"observer_start":null,"absence_basis":"recorded-terminal-pre-driver-failure"}),
            ));
        }
        return Err(LaneError::input(
            "launch-reservation",
            format!(
                "reservation differs from this run in: {}; launcher identity is absent",
                different.join(", ")
            ),
        ));
    };
    if liveness != crate::container_helper::ProcessPresence::Absent {
        return Err(LaneError::input(
            "launch-reservation",
            "the earlier launcher's absence cannot be established",
        ));
    }
    let old_plan = serde_json::to_vec(&record["plan"])
        .map_err(|error| LaneError::operation("launch-reservation", error.to_string()))?;
    let digest = build::sha256_bytes(&old_plan, root)?;
    Ok(Some(
        json!({"state":"retiring","old_plan_sha256":digest,"different_fields":different,"launcher_pid":pid,"launcher_start":start,"observer_pid":observer.map(|(pid, _)| pid),"observer_start":observer.map(|(_, start)| start)}),
    ))
}

fn preview_dead_preparation(
    root: &Path,
    plan: &Plan,
    run: &str,
    letter: &Path,
    skipped: &[String],
    mut labelled_absent: impl FnMut() -> Result<bool, LaneError>,
) -> Result<Value, LaneError> {
    let Some(mut record) = read_reservation(&reservation_path(root, run))? else {
        return Ok(json!({"state":"none","retirement_to_journal":null}));
    };
    let proof = prove_probe_absence_with(
        &record,
        crate::container_helper::process_presence,
        &mut labelled_absent,
    )?;
    record["probe_absence_proof"] = proof.clone();
    let next = json!({"schema":1,"phase":"preparing","loop":plan.document["loop"],"run":run,"worker_uid":plan.document["worker_uid"],"plan":plan.document,"letter_source":letter,"observer_state":"not-started","helper_spawn_state":"not-started","reservation_census":{"skipped_count":skipped.len(),"skipped_names":skipped}});
    let mut staged = next.clone();
    stage_preparation_retirement_with(
        &record,
        &mut staged,
        &reservation_path(root, run),
        root,
        &plan.driver_dir,
        &plan.home,
        &observation_path(plan, run)?,
        run,
        true,
        crate::container_helper::process_presence,
    )?;
    let identities = json!({
        "launcher": launcher_identity(&record)?,
        "observer": observer_identity(&record)?,
        "helper": helper_identity(&record)?,
        "helper_parent": helper_parent_identity(&record)?,
        "driver": driver_identity(&record)?,
    });
    let process_presence_label = |identity: Option<(u32, u64)>| {
        identity.map_or_else(
            || "not-recorded".to_owned(),
            |(pid, start)| {
                format!(
                    "{:?}",
                    crate::container_helper::process_presence(pid, start)
                )
                .to_ascii_lowercase()
            },
        )
    };
    let never_spawned = terminal_before_launcher(&record);
    let presence = |identity: Option<(u32, u64)>| {
        if never_spawned && identity.is_none() {
            "never-spawned".to_owned()
        } else {
            process_presence_label(identity)
        }
    };
    let absence = json!({"launcher":presence(launcher_identity(&record)?),"observer":presence(observer_identity(&record)?),"helper":presence(helper_identity(&record)?),"helper_parent":presence(helper_parent_identity(&record)?),"driver":presence(driver_identity(&record)?)});
    Ok(
        json!({"state":"would-retire-dead-preparation","identities":identities,"presence":absence,"probe_absence":proof,"attempt_evidence":{"prior_attempt_started":false},"plan_comparison":{"different_fields":reservation_differences(&record,&next)},"retirement_to_journal":staged["current_retirement"]}),
    )
}

const RETIREMENT_NAME_LIMIT: usize = 4096;

fn planned_retirement(path: &Path, run: &str, index: usize) -> Result<Option<Value>, LaneError> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "launch-recover",
                format!("{}: {error}", path.display()),
            ));
        }
        Ok(metadata) => metadata,
    };
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::input("launch-recover", "partial path has no parent"))?;
    let name = format!(
        ".retired-{run}-{index}-{}-{}",
        metadata.dev(),
        metadata.ino()
    );
    for suffix in 0..RETIREMENT_NAME_LIMIT {
        let target = parent.join(if suffix == 0 {
            name.clone()
        } else {
            format!("{name}.{suffix}")
        });
        match fs::symlink_metadata(&target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some(json!({"source":path,"target":target})));
            }
            Ok(occupant) => {
                if (occupant.dev(), occupant.ino()) == (metadata.dev(), metadata.ino()) {
                    return Err(LaneError::input(
                        "launch-recover",
                        format!("{} is the source itself", target.display()),
                    ));
                }
                if !occupant.is_file() {
                    return Err(LaneError::input(
                        "launch-recover",
                        format!("{} is occupied by a non-regular entry", target.display()),
                    ));
                }
                // Only a different regular file can be a report whose rewrite
                // released the inode encoded by this retained name.
            }
            Err(error) => {
                return Err(LaneError::input(
                    "launch-recover",
                    format!("{}: {error}", target.display()),
                ));
            }
        }
    }
    Err(LaneError::input(
        "launch-recover",
        format!("retirement name search reached its {RETIREMENT_NAME_LIMIT} candidate bound"),
    ))
}

fn apply_retirement_paths(record: &Value) -> Result<Vec<PathBuf>, LaneError> {
    let paths = record["current_retirement"]["planned_paths"]
        .as_array()
        .ok_or_else(|| LaneError::input("launch-recover", "planned retirement paths are absent"))?;
    let mut retired = Vec::new();
    for pair in paths {
        let source =
            Path::new(pair["source"].as_str().ok_or_else(|| {
                LaneError::input("launch-recover", "retirement source is absent")
            })?);
        let target =
            Path::new(pair["target"].as_str().ok_or_else(|| {
                LaneError::input("launch-recover", "retirement target is absent")
            })?);
        if source.parent() != target.parent()
            || !target
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".retired-"))
        {
            return Err(LaneError::input(
                "launch-recover",
                "retirement target is outside its source directory",
            ));
        }
        let exists = |path: &Path| -> Result<bool, LaneError> {
            match fs::symlink_metadata(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(LaneError::input(
                    "launch-recover",
                    format!("{}: {error}", path.display()),
                )),
            }
        };
        match (exists(source)?, exists(target)?) {
            (true, false) => {
                fs::rename(source, target).map_err(|error| {
                    LaneError::operation("launch-recover", format!("{}: {error}", source.display()))
                })?;
                fs::File::open(source.parent().ok_or_else(|| {
                    LaneError::input("launch-recover", "retired path has no parent")
                })?)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    LaneError::operation("launch-recover", format!("{}: {error}", target.display()))
                })?;
            }
            (false, true) => {}
            _ => {
                return Err(LaneError::input(
                    "launch-recover",
                    format!(
                        "{} and {} have an incomplete retirement",
                        source.display(),
                        target.display()
                    ),
                ));
            }
        }
        retired.push(target.to_path_buf());
    }
    Ok(retired)
}

fn remove_retired_observer_socket(record: &Value) -> Result<Value, LaneError> {
    let Some(path) = record["current_retirement"]["observer_socket"].as_str() else {
        return Ok(json!({"state":"none"}));
    };
    let slot = crate::SocketSlot::pinned(Path::new(path), Uid::effective().as_raw())?;
    match slot
        .metadata()
        .map_err(|error| LaneError::input("launch-recover", format!("{path}: {error}")))?
    {
        None => Ok(json!({"state":"absent", "path":path})),
        Some(_) if record["current_retirement"]["observer_socket_present"] != true => {
            Err(LaneError::input(
                "launch-recover",
                format!("{path} appeared after the retirement record"),
            ))
        }
        Some(metadata)
            if metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
                && metadata.st_uid == Uid::effective().as_raw() =>
        {
            slot.remove().map_err(|error| {
                LaneError::operation("launch-recover", format!("{path}: {error}"))
            })?;
            Ok(json!({"state":"removed","path":path}))
        }
        Some(_) => Err(LaneError::input(
            "launch-recover",
            format!("{path} is not the old owner socket"),
        )),
    }
}

fn finish_preparation_retirement(
    record: &mut Value,
    reservation: &Path,
    driver_dir: &Path,
) -> Result<Vec<PathBuf>, LaneError> {
    let helper = json!({"helper_pid":record["current_retirement"]["helper_pid"],"helper_start":record["current_retirement"]["helper_start"]});
    let stale = inspect_dead_helper_sockets_with(
        driver_dir,
        &helper,
        Uid::effective().as_raw(),
        crate::container_helper::process_presence,
    )?;
    let mut intended = record["current_retirement"]["helper_sockets_to_remove"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for (path, _) in &stale {
        let path = json!(path);
        if !intended.contains(&path) {
            intended.push(path);
        }
    }
    record["current_retirement"]["helper_sockets_to_remove"] = json!(intended);
    publish_reservation(reservation, record)?;
    let socket = remove_retired_observer_socket(record)?;
    record["current_retirement"]["observer_socket_disposition"] = socket;
    publish_reservation(reservation, record)?;
    let mut removed_helper_sockets: Vec<PathBuf> = serde_json::from_value(
        record["current_retirement"]
            .get("removed_helper_sockets")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .map_err(|error| LaneError::input("launch-recover", error.to_string()))?;
    for (path, slot) in stale {
        slot.remove()
            .map_err(|error| LaneError::operation("helper-socket", error.to_string()))?;
        if !removed_helper_sockets.contains(&path) {
            removed_helper_sockets.push(path);
        }
        record["current_retirement"]["removed_helper_sockets"] = json!(removed_helper_sockets);
        publish_reservation(reservation, record)?;
    }
    let mut retired = apply_retirement_paths(record)?;
    record["current_retirement"]["removed_helper_sockets"] = json!(removed_helper_sockets);
    record["current_retirement"]["retired_paths"] = json!(retired);
    record["current_retirement"]["state"] = json!("retired-dead-preparation");
    let completed = record["current_retirement"].take();
    if record["dead_preparation_retired"].is_null() {
        record["dead_preparation_retired"] = completed;
    } else {
        record["retry_retirements"]
            .as_array_mut()
            .ok_or_else(|| {
                LaneError::input("launch-recover", "prior retirement history is invalid")
            })?
            .push(completed);
    }
    publish_reservation(reservation, record)?;
    retired.extend(removed_helper_sockets);
    Ok(retired)
}

#[allow(clippy::too_many_arguments)]
fn stage_preparation_retirement_with(
    record: &Value,
    next: &mut Value,
    reservation: &Path,
    root: &Path,
    driver_dir: &Path,
    worker_home: &Path,
    observed_file: &Path,
    run: &str,
    dry_run: bool,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<(), LaneError> {
    require_probe_absence_proof(record, &mut presence)?;
    if record["current_retirement"]["state"] == "retiring" {
        if !reservation_differences(record, next).is_empty() || prior_attempt_started(driver_dir)? {
            return Err(LaneError::input(
                "launch-reservation",
                "pending retirement differs from this run or has an attempt",
            ));
        }
        *next = record.clone();
        return Ok(());
    }
    let mut recovery = recovery_record_with(record, next, root, driver_dir, presence)?
        .unwrap_or_else(|| json!({"state":"retiring","different_fields":[]}));
    let old_plan = serde_json::to_vec(&record["plan"])
        .map_err(|error| LaneError::operation("launch-recover", error.to_string()))?;
    recovery["old_plan_sha256"] = json!(build::sha256_bytes(&old_plan, root)?);
    let old_socket = recorded_observer_socket(record)?;
    let socket_present = if let Some(path) = old_socket.as_ref() {
        crate::SocketSlot::pinned(path, Uid::effective().as_raw())?
            .metadata()
            .map_err(|error| {
                LaneError::input("launch-recover", format!("{}: {error}", path.display()))
            })?
            .is_some()
    } else {
        false
    };
    let mut paths = Vec::new();
    let identity_dir = protected_identity_dir(driver_dir)?;
    for (index, path) in [
        driver_dir,
        worker_home,
        identity_dir.as_path(),
        observed_file,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(pair) = planned_retirement(path, run, index)? {
            paths.push(pair);
        }
    }
    recovery["planned_paths"] = json!(paths);
    recovery["observer_socket"] = json!(old_socket);
    recovery["observer_socket_present"] = json!(socket_present);
    recovery["helper_pid"] = record["helper_pid"].clone();
    recovery["helper_start"] = record["helper_start"].clone();
    recovery["retained_preparation_lock"] = json!(root.join(format!(".prepare-{run}.lock")));
    next["dead_preparation_retired"] = record["dead_preparation_retired"].clone();
    next["retry_retirements"] = record["retry_retirements"]
        .as_array()
        .map_or_else(|| json!([]), |items| json!(items));
    next["current_retirement"] = recovery;
    if !dry_run {
        publish_reservation(reservation, next)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replace_preparation_with(
    record: &Value,
    next: &mut Value,
    reservation: &Path,
    root: &Path,
    driver_dir: &Path,
    worker_home: &Path,
    observed_file: &Path,
    run: &str,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Vec<PathBuf>, LaneError> {
    stage_preparation_retirement_with(
        record,
        next,
        reservation,
        root,
        driver_dir,
        worker_home,
        observed_file,
        run,
        false,
        presence,
    )?;
    finish_preparation_retirement(next, reservation, driver_dir)
}

fn helper_argv(
    exe_word: &str,
    run_dir: &Path,
    owner_home: &Path,
    runs_root: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "unshare".into(),
        exe_word.into(),
        "_container-helper".into(),
        "--run-dir".into(),
        crate::pinned::path_word(run_dir, "run-directory")?,
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--verified-home-fd".into(),
        "0".into(),
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs_root, "runs-root")?,
        "--verified-runs-root-fd".into(),
        "1".into(),
    ])
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn start_helper_with_program(
    request: &LaunchRequest,
    plan: &Plan,
    owner_home: &Path,
    environment: &BTreeMap<String, String>,
    verified_home: &OwnedFd,
    runs_root: &Path,
    verified_runs: &OwnedFd,
    lane_bin: &Path,
    mut record_parent: impl FnMut(u32, u64) -> Result<(), LaneError>,
) -> Result<(Child, u64, JoinHandle<Vec<u8>>), LaneError> {
    let reservation = reservation_path(runs_root, &request.run);
    let prepared = (|| {
        let exe_word = crate::pinned::owner_executable_word(lane_bin, Uid::effective().as_raw())?;
        let socket = crate::container_helper::socket_path(&plan.driver_dir)?;
        let control = crate::container_helper::control_socket_path(&plan.driver_dir)?;
        let socket_slot = crate::SocketSlot::beneath(
            verified_runs,
            socket
                .file_name()
                .ok_or_else(|| LaneError::input("socket-path", "socket name absent"))?,
        )
        .map_err(|error| LaneError::input("socket-path", error.to_string()))?;
        let control_slot = crate::SocketSlot::beneath(
            verified_runs,
            control
                .file_name()
                .ok_or_else(|| LaneError::input("socket-path", "control name absent"))?,
        )
        .map_err(|error| LaneError::input("socket-path", error.to_string()))?;
        crate::pinned::owner_executable(&request.podman_bin, Uid::effective().as_raw())?;
        let (transfer, private_stdin) = UnixStream::pair()
            .map_err(|error| LaneError::operation("helper-start", error.to_string()))?;
        let mut child = Command::new(&request.podman_bin);
        child
            .args(helper_argv(
                &exe_word,
                &plan.driver_dir,
                owner_home,
                runs_root,
            )?)
            .env_clear()
            .envs(environment)
            .current_dir(owner_home)
            .stdin(Stdio::from(OwnedFd::from(private_stdin)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        reaping::attach_command(&mut child)?;
        let child = crate::fixture_exec::spawn(&mut child)
            .map_err(|error| LaneError::operation("helper-start", error.to_string()))?;
        Ok((child, transfer, socket_slot, control_slot, socket))
    })();
    let (mut child, transfer, socket_slot, control_slot, socket) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let saved =
                persist_settlement_field(&reservation, "helper_spawn_state", json!("not-started"));
            return Err(retain_startup_refusal(error, saved.map(|_| ())));
        }
    };
    // Measure before any wait reaps the parent: even an exited child retains its tick.
    let parent_start = crate::container_helper::process_start(child.id());
    let startup = (|| {
        let parent_start = *parent_start
            .as_ref()
            .map_err(|error| LaneError::operation("helper-start", error.line()))?;
        #[cfg(test)]
        if let Some(hook) = BEFORE_HELPER_PARENT.with(std::cell::Cell::take) {
            hook(&reservation)?;
        }
        record_parent(child.id(), parent_start)?;
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| LaneError::operation("helper-start", "helper stderr pipe is absent"))?;
        let stderr_reader = std::thread::spawn(move || {
            let mut tail = Vec::new();
            let mut chunk = [0_u8; 1024];
            while let Ok(count) = stderr_pipe.read(&mut chunk) {
                if count == 0 {
                    break;
                }
                tail.extend_from_slice(&chunk[..count]);
                if tail.len() > 4096 {
                    tail.drain(..tail.len() - 4096);
                }
            }
            tail
        });
        home::send_private_descriptors(
            &transfer,
            &[verified_home.as_raw_fd(), verified_runs.as_raw_fd()],
        )?;
        let began = Instant::now();
        while began.elapsed() < Duration::from_secs(30) {
            if socket_slot.metadata().is_ok_and(|meta| {
                meta.is_some_and(|meta| {
                    meta.st_mode & libc::S_IFMT == libc::S_IFSOCK && meta.st_mode & 0o7777 == 0o660
                })
            }) && control_slot.metadata().is_ok_and(|meta| {
                meta.is_some_and(|meta| {
                    meta.st_mode & libc::S_IFMT == libc::S_IFSOCK && meta.st_mode & 0o7777 == 0o600
                })
            }) {
                return Ok((parent_start, stderr_reader));
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|error| LaneError::operation("helper-start", error.to_string()))?
            {
                let stderr = stderr_reader.join().unwrap_or_default();
                return Err(LaneError::operation(
                    "helper-start",
                    format!(
                        "helper exited {status}{}",
                        build::bounded_diagnostic_lines(&stderr)
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        stop_observer(&mut child)?;
        let stderr = stderr_reader.join().unwrap_or_default();
        Err(LaneError::operation(
            "helper-start",
            format!(
                "{} did not become ready (client socket mode 0660 and control socket mode 0600 readiness barrier){}",
                socket.display(),
                build::bounded_diagnostic_lines(&stderr)
            ),
        ))
    })();
    match startup {
        Ok((start, stderr)) => Ok((child, start, stderr)),
        Err(error) => {
            drop(child.kill());
            let saved = (|| {
                let status = child.wait().map_err(|wait| {
                    LaneError::operation("helper-start", format!("parent wait: {wait}"))
                })?;
                if let Ok(start) = parent_start {
                    let mut saved = read_reservation(&reservation)?.ok_or_else(|| {
                        LaneError::input("helper-start", "reservation vanished before parent end")
                    })?;
                    saved["helper_parent_pid"] = json!(child.id());
                    saved["helper_parent_start"] = json!(start);
                    saved["helper_spawn_state"] = json!("running");
                    saved["helper_end"] =
                        helper_parent_end(child.id(), start, status, Some(&error));
                    publish_reservation(&reservation, &saved)?;
                }
                Ok(())
            })();
            Err(retain_startup_refusal(error, saved))
        }
    }
}

fn retain_startup_refusal(mut error: LaneError, saved: Result<(), LaneError>) -> LaneError {
    use std::fmt::Write as _;
    if let Err(save) = saved {
        let _written = write!(error.detail, "; failure record save: {}", save.line());
    }
    error
}

fn driver_completion(
    result: &Result<String, LaneError>,
    started: bool,
    child: &build::ChildEnd,
) -> Value {
    let mut end = json!({"state":if started { "completed" } else { "not-started" },"successful":result.is_ok(),"detail":result.as_ref().err().map(LaneError::line)});
    if let Some(wall) = child.wall {
        end["cause"] = json!("launch-wall");
        end["bound_seconds"] = json!(wall.bound_seconds);
        end["attempt_elapsed_seconds"] = json!(wall.wall_seconds);
    }
    end
}

fn helper_parent_end(
    parent_pid: u32,
    parent_start: u64,
    status: std::process::ExitStatus,
    detail: Option<&LaneError>,
) -> Value {
    json!({"state":"completed","successful":detail.is_none() && status.success(),"parent_pid":parent_pid,"parent_start":parent_start,"status":status.to_string(),"detail":detail.map(LaneError::line)})
}

fn helper_stop_with_stderr(
    result: Result<(), LaneError>,
    helper: &mut Child,
    stderr: JoinHandle<Vec<u8>>,
) -> Result<(), LaneError> {
    if let Err(mut error) = result {
        if helper.try_wait().ok().flatten().is_some() {
            let bytes = stderr.join().unwrap_or_default();
            error
                .detail
                .push_str(&build::bounded_diagnostic_lines(&bytes));
        }
        return Err(error);
    }
    Ok(())
}

fn stop_helper(child: &mut Child, plan: &Plan, verified_runs: &OwnedFd) -> Result<(), LaneError> {
    if let Some(status) = child
        .try_wait()
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?
    {
        return if status.success() {
            Ok(())
        } else {
            Err(LaneError::operation(
                "helper-stop",
                format!("helper exited {status}"),
            ))
        };
    }
    let control = crate::container_helper::control_socket_path(&plan.driver_dir)?;
    let slot = crate::SocketSlot::beneath(
        verified_runs,
        control
            .file_name()
            .ok_or_else(|| LaneError::input("socket-path", "control name absent"))?,
    )
    .map_err(|error| LaneError::input("socket-path", error.to_string()))?;
    let mut stream = std::os::unix::net::UnixStream::connect(slot.address()).map_err(|error| {
        LaneError::operation("helper-stop", format!("{}: {error}", control.display()))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?;
    stream
        .write_all(b"C")
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?;
    let mut acknowledgement = [0_u8];
    stream
        .read_exact(&mut acknowledgement)
        .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?;
    if acknowledgement != *b"K" {
        return Err(LaneError::operation(
            "helper-stop",
            "helper did not acknowledge cancellation",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| LaneError::operation("helper-stop", error.to_string()))?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(LaneError::operation(
                    "helper-stop",
                    format!("helper exited {status}"),
                ))
            };
        }
        if Instant::now() >= deadline {
            return Err(LaneError::operation(
                "helper-stop",
                "helper did not finish bounded container cancellation within 90 seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stop_observer(child: &mut Child) -> Result<Value, LaneError> {
    let prior = child
        .try_wait()
        .map_err(|error| LaneError::operation("proxy-stop", error.to_string()))?;
    let pid = i32::try_from(child.id())
        .map_err(|error| LaneError::operation("proxy-stop", error.to_string()))?;
    let group = nix::unistd::Pid::from_raw(pid);
    let presence = || match nix::sys::signal::kill(nix::unistd::Pid::from_raw(-pid), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => ProcessPresence::Present,
        Err(nix::errno::Errno::ESRCH) => ProcessPresence::Absent,
        Err(_) => ProcessPresence::Unknown,
    };
    if let Some(status) = prior.filter(|_| presence() == ProcessPresence::Absent) {
        return Ok(
            json!({"state":"failed-before-stop","already_exited":true,"stop_signals":[],"group_presence":"absent","status":status.to_string()}),
        );
    }
    let mut signals = Vec::new();
    if presence() == ProcessPresence::Present {
        nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGTERM)
            .map_err(|error| LaneError::operation("proxy-stop", error.to_string()))?;
        signals.push("SIGTERM");
    }
    let began = Instant::now();
    while began.elapsed() < Duration::from_secs(10) {
        let status = child
            .try_wait()
            .map_err(|error| LaneError::operation("proxy-stop", error.to_string()))?;
        if presence() == ProcessPresence::Absent {
            return Ok(
                json!({"state":if prior.is_some() {"failed-before-stop"} else {"stopped"},"already_exited":prior.is_some(),"stop_signals":signals,"group_presence":"absent","status":status.or(prior).map(|status| status.to_string())}),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if presence() == ProcessPresence::Present {
        nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL)
            .map_err(|error| LaneError::operation("proxy-stop", error.to_string()))?;
        signals.push("SIGKILL");
    }
    let status = match prior {
        Some(status) => status,
        None => child
            .wait()
            .map_err(|error| LaneError::operation("proxy-stop", error.to_string()))?,
    };
    let group_presence = presence();
    Ok(
        json!({"state":if group_presence == ProcessPresence::Absent {if prior.is_some() {"failed-before-stop"} else {"stopped"}} else {"uncertain"},"already_exited":prior.is_some(),"stop_signals":signals,"group_presence":format!("{group_presence:?}").to_lowercase(),"status":status.to_string()}),
    )
}

/// Construct the initial protected record from the selected launch plan and declarations.
fn declared_source_rows(sources: &[DeclaredSource]) -> Vec<Value> {
    sources.iter().map(|source| json!({"name":source.name,"seed":source.seed,"source_identity":null,"seeded_at_unix_ns":null})).collect()
}

#[allow(clippy::too_many_arguments)]
fn initial_reservation(
    plan: &Plan,
    loop_name: &str,
    run: &str,
    worker_uid: u32,
    selection: &Value,
    sources: &[DeclaredSource],
    letter: &Path,
    rotation_digest: Option<&str>,
    skipped_runs: &[String],
    door_scope: crate::door::Scope,
) -> Value {
    let declared = declared_source_rows(sources);
    json!({"schema":1,"phase":"preparing","loop":loop_name,"run":run,"worker_uid":worker_uid,"door_scope":door_scope.name(),"plan":plan.document,"model_selection":selection,"declared_sources":declared,"letter_source":letter,"rotation_source_sha256":rotation_digest,"observer_state":"not-started","helper_spawn_state":"not-started","probe_starts":[],"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":1,"imports":[],"harvest_agreement":null,"collection":null,"reservation_census":{"skipped_count":skipped_runs.len(),"skipped_names":skipped_runs}})
}

/// Record the first round and its placed letter in the launch reservation.
///
/// # Errors
///
/// Refuses a letter whose digest cannot be measured.
fn record_dispatch_letter(
    record: &mut Value,
    budget: u64,
    letter: &[u8],
    stop: bool,
    placed_at: u64,
    owner_home: &Path,
    directory: &Path,
) -> Result<(), LaneError> {
    record["active_round"] = json!("dispatch");
    record["rounds"] = json!([{"step":"dispatch","budget_seconds":budget,"letter":"dispatch.md","phase":"running","driver_dir":directory,"ended_by":null,"placed_at_unix_ns":placed_at,"in_round_letters":[]}]);
    record["letters"] = json!([{"step":"dispatch","name":"dispatch.md","in_round":false,"stop":stop,"bytes":letter.len(),"sha256":build::sha256_bytes(letter, owner_home)?,"placed_at_unix_ns":placed_at,"state":"placed"}]);
    Ok(())
}

/// Create a planned home after the rootless namespace has mapped its identities.
///
/// # Errors
///
/// Refuses a different namespace identity, settings, letter, or destination.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn private_make(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    letter: &Path,
    observe: bool,
    requested_uid: u32,
    podman: &Path,
    expected_selection: &Value,
    rotation_digest: Option<&str>,
    door_scope: crate::door::Scope,
) -> Result<Value, LaneError> {
    let (mut plan, settings) = load_plan(owner_home, loop_name, run, (0, 0))?;
    plan.select_container_program(podman)?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?
        .to_path_buf();
    let _lock = lock_runs_root(&root, true, 0)?;
    let (base, count) = worker_range(owner_home, loop_name)?;
    exercise_resources::verify_worker_block(base, count)?;
    let (available, skipped_runs) = select_free_uid_with_census(&root, run, base, count)?;
    if available != requested_uid {
        return Err(LaneError::input(
            "uid-race",
            format!(
                "worker UID {requested_uid} is no longer the first available identity; dry-run again"
            ),
        ));
    }
    plan.select_worker_uid(requested_uid)?;
    if observe {
        plan.observe_vendor()?;
    }
    let bytes = if let Some(expected) = rotation_digest {
        let source = home::private_rotation_source()?;
        rotation_source_bytes(&source, expected, owner_home, 0)?
    } else {
        home::read_letter(letter, 0)?
    };
    let selection = LaunchModel::select(
        &bytes,
        expected_selection["model"].as_str(),
        expected_selection["effort"].as_str(),
    )?;
    let declared_sources = declared_sources(&bytes)?;
    if selection.record() != *expected_selection {
        return Err(LaneError::input(
            "letter-model",
            "letter selection differs from the public launch plan",
        ));
    }
    plan.select_launch_model(expected_selection)?;
    check_mount_roots(&plan, &settings, owner_home)?;
    check_pins(&plan, &settings, owner_home, observe, false)?;
    private_image_check(
        podman,
        settings
            .image_digest
            .as_deref()
            .ok_or_else(|| LaneError::input("missing-setting", "image_digest is absent"))?,
        owner_home,
    )?;
    check_backend_image_program(&settings, &installed_generation(owner_home, loop_name)?)?;
    crate::credential::preflight(owner_home, loop_name)?;
    let reservation = reservation_path(&root, run);
    let mut next = initial_reservation(
        &plan,
        loop_name,
        run,
        requested_uid,
        expected_selection,
        &declared_sources,
        letter,
        rotation_digest,
        &skipped_runs,
        door_scope,
    );
    let prior = read_reservation(&reservation)?;
    let retired = if let Some(record) = prior {
        replace_preparation_with(
            &record,
            &mut next,
            &reservation,
            &root,
            &plan.driver_dir,
            &plan.home,
            &observation_path(&plan, run)?,
            run,
            crate::container_helper::process_presence,
        )?
    } else {
        publish_reservation(&reservation, &next)?;
        Vec::new()
    };
    let mut result =
        match home::make_home_in_namespace(&plan, &settings, &bytes, owner_home, loop_name) {
            Ok(report) => report,
            Err(error) => {
                if error.kind.starts_with("source-seed") {
                    next["source_seed_attempts"] = json!([{"refusal":error.line()}]);
                    publish_reservation(&reservation, &next)?;
                }
                return Err(error);
            }
        };
    next["declared_sources"] = result["declared_sources"].clone();
    publish_reservation(&reservation, &next)?;
    if let Some(expected) = rotation_digest {
        let inbox = plan.home.join(".local/inbox/dispatch.md");
        let placed = home::read_letter(&inbox, Uid::effective().as_raw())?;
        let actual = build::sha256_bytes(&placed, owner_home)?;
        if actual != expected {
            return Err(LaneError::input(
                "rotate-source",
                format!("expected digest {expected} differs from inbox digest {actual}"),
            ));
        }
    }
    crate::credential::prepare_run(owner_home, loop_name, &plan.home, requested_uid)?;
    result["reservation"] = json!(reservation);
    result["retired_partial"] = json!(retired);
    Ok(result)
}

fn pin_runtime_dir(
    driver_dir: &Path,
    owner_uid: u32,
    loop_uid: u32,
) -> Result<(OwnedFd, OwnedFd), LaneError> {
    let root = driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("runtime-dir", "runs root is absent"))?;
    let root_fd = home::pin_parent(root, owner_uid)?;
    let how = || {
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS)
    };
    let run_name = driver_dir
        .file_name()
        .ok_or_else(|| LaneError::input("runtime-dir", "run name is absent"))?;
    let run_fd = openat2(&root_fd, run_name, how())
        .map_err(|error| LaneError::input("runtime-dir", error.to_string()))?;
    let runtime_fd = openat2(&run_fd, "launch", how())
        .map_err(|error| LaneError::input("runtime-dir", error.to_string()))?;
    for fd in [&run_fd, &runtime_fd] {
        let stat = fstat(fd).map_err(|error| LaneError::input("runtime-dir", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
            || stat.st_uid != loop_uid
            || stat.st_mode & 0o7777 != 0o700
        {
            return Err(LaneError::input(
                "runtime-dir",
                format!("{} has a foreign owner or mode", driver_dir.display()),
            ));
        }
    }
    Ok((root_fd, runtime_fd))
}

fn create_runtime_file(parent: &OwnedFd, name: &str, mode: u32) -> Result<fs::File, LaneError> {
    nix::fcntl::openat(
        parent,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::from_bits_truncate(mode),
    )
    .map(fs::File::from)
    .map_err(|error| LaneError::input("runtime-file", format!("{name}: {error}")))
}

fn refreshed_client_environment(
    bytes: &[u8],
    device: u64,
    inode: u64,
) -> Result<Vec<u8>, LaneError> {
    let invalid = || LaneError::input("runtime-client", "saved client environment is invalid");
    if bytes.is_empty() || bytes.len() > 65_536 || bytes.last() != Some(&0) {
        return Err(invalid());
    }
    let mut refreshed = Vec::with_capacity(bytes.len());
    let mut seen = [false; 2];
    for entry in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        let replacement = [
            (b"SUPERLOOP_CLIENT_ROOT_DEV=".as_slice(), device),
            (b"SUPERLOOP_CLIENT_ROOT_INO=".as_slice(), inode),
        ];
        if let Some((index, (key, value))) = replacement
            .iter()
            .enumerate()
            .find(|(_, (key, _))| entry.starts_with(key))
        {
            if seen[index] {
                return Err(invalid());
            }
            seen[index] = true;
            refreshed.extend_from_slice(key);
            refreshed.extend_from_slice(value.to_string().as_bytes());
        } else {
            refreshed.extend_from_slice(entry);
        }
        refreshed.push(0);
    }
    if !seen.into_iter().all(|present| present) || refreshed.len() > 65_536 {
        return Err(invalid());
    }
    Ok(refreshed)
}

fn prepare_client_environment(
    driver_dir: &Path,
    runs_root: &OwnedFd,
    runtime_dir: &OwnedFd,
    loop_uid: u32,
    initial: bool,
) -> Result<(), LaneError> {
    let owner = Uid::effective().as_raw();
    let stat =
        fstat(runs_root).map_err(|error| LaneError::input("runtime-client", error.to_string()))?;
    let bytes = if initial {
        let socket = crate::container_helper::socket_path(driver_dir)?;
        let name = socket
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| LaneError::input("runtime-client", "client socket name is absent"))?;
        format!("HOME={}\0SUPERLOOP_CLIENT_ROOT_DEV={}\0SUPERLOOP_CLIENT_ROOT_INO={}\0SUPERLOOP_CLIENT_SOCKET_NAME={}\0",
            driver_dir.display(), stat.st_dev, stat.st_ino, name).into_bytes()
    } else {
        let file = nix::fcntl::openat(
            runtime_dir,
            "runtime.env",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|error| LaneError::input("runtime-client", error.to_string()))?;
        let meta = file
            .metadata()
            .map_err(|error| LaneError::input("runtime-client", error.to_string()))?;
        if !meta.is_file()
            || meta.uid() != owner
            || meta.gid() != loop_uid
            || meta.mode() & 0o7777 != 0o440
        {
            return Err(LaneError::input(
                "runtime-client",
                "saved client environment has foreign ownership or protection",
            ));
        }
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|error| LaneError::input("runtime-client", error.to_string()))?;
        refreshed_client_environment(&bytes, stat.st_dev, stat.st_ino)?
    };
    let temporary = format!(
        ".runtime.env-{}-{}",
        std::process::id(),
        letters::unix_ns()?
    );
    let mut file = create_runtime_file(runtime_dir, &temporary, 0o440)?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
        fchownat(
            &file,
            "",
            Some(Uid::from_raw(owner)),
            Some(Gid::from_raw(loop_uid)),
            AtFlags::AT_EMPTY_PATH,
        )
        .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
        file.set_permissions(fs::Permissions::from_mode(0o440))
            .and_then(|()| file.sync_all())
            .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
        renameat(runtime_dir, temporary.as_str(), runtime_dir, "runtime.env")
            .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
        nix::unistd::fsync(runtime_dir)
            .map_err(|error| LaneError::operation("runtime-client", error.to_string()))
    })();
    if result.is_err() {
        let _removed = nix::unistd::unlinkat(
            runtime_dir,
            temporary.as_str(),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        );
    }
    result
}

/// Rebuild every post-load selection from the protected reservation and its letter.
///
/// # Errors
///
/// Refuses changed declarations, allocation, runtime program, or selected plan.
pub(crate) fn pinned_plan_from_record(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    podman: &Path,
    record: &Value,
) -> Result<(Plan, Settings), LaneError> {
    let (mut plan, settings) = load_plan(owner_home, loop_name, run, (0, 0))?;
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "plan-read",
            "protected plan names another run",
        ));
    }
    let worker_uid = record["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("plan-read", "worker UID is absent"))?;
    let (base, count) = worker_range(owner_home, loop_name)?;
    if worker_uid < base || worker_uid >= base + count {
        return Err(LaneError::input(
            "plan-read",
            "worker UID is outside the allocation range",
        ));
    }
    plan.select_worker_uid(worker_uid)?;
    plan.select_container_program(podman)?;
    if record["plan"]["vendor_mode"].is_string() {
        plan.observe_vendor()?;
    }
    let letter = record["letter_source"]
        .as_str()
        .ok_or_else(|| LaneError::input("letter-model", "recorded letter source is absent"))?;
    let bytes = if let Some(expected) = record["rotation_source_sha256"].as_str() {
        let inbox = plan.home.join(".local/inbox/dispatch.md");
        let bytes = home::read_letter(&inbox, Uid::effective().as_raw())?;
        let actual = build::sha256_bytes(&bytes, owner_home)?;
        if actual != expected {
            return Err(LaneError::input(
                "rotate-source",
                format!("expected digest {expected} differs from inbox digest {actual}"),
            ));
        }
        bytes
    } else {
        home::read_letter(Path::new(letter), Uid::effective().as_raw())?
    };
    let selection = LaunchModel::select(
        &bytes,
        record["model_selection"]["model"].as_str(),
        record["model_selection"]["effort"].as_str(),
    )?;
    let selection_matches = if record["active_round"] == "dispatch" {
        selection.record() == record["model_selection"]
    } else {
        selection.model == record["model_selection"]["model"]
            && selection.effort == record["model_selection"]["effort"]
    };
    if !selection_matches {
        return Err(LaneError::input(
            "letter-model",
            "letter declaration differs from the recorded model selection",
        ));
    }
    plan.select_launch_model(&record["model_selection"])?;
    plan.retain_attempt_wall(&record["plan"])?;
    compare_pinned_plan(&record["plan"], &plan.document)?;
    Ok((plan, settings))
}

/// Validate installed inputs and write the exact runtime invocation before any container starts.
///
/// # Errors
///
/// Refuses a differing mount, input digest, image identifier, proxy socket, or backend.
#[allow(clippy::too_many_lines)]
pub fn private_prepare_runtime(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    podman: &Path,
) -> Result<Value, LaneError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    if !valid_run_name(run) {
        return Err(LaneError::input("run-name", format!("bad run name: {run}")));
    }
    crate::pinned::owner_executable(podman, Uid::effective().as_raw())?;
    let (initial, _) = load_plan(owner_home, loop_name, run, (0, 0))?;
    let driver_dir = initial.driver_dir;
    let reservation = reservation_path(
        driver_dir
            .parent()
            .ok_or_else(|| LaneError::input("plan-read", "run has no runs root"))?,
        run,
    );
    let record = read_reservation(&reservation)?.ok_or_else(|| {
        LaneError::input(
            "launch-reservation",
            format!("{} is absent", reservation.display()),
        )
    })?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "launch-reservation",
            "reservation names another run",
        ));
    }
    let (plan, settings) = pinned_plan_from_record(owner_home, loop_name, run, podman, &record)?;
    let observed = plan.document["vendor_mode"].is_string();
    if observed
        && settings
            .vendor_hosts
            .get("codex")
            .is_some_and(|hosts| !hosts.is_empty())
    {
        return Err(LaneError::input(
            "observe-conflict",
            "vendor_hosts.codex is already set",
        ));
    }
    crate::plan::verify_box_attestation(&plan.document)?;
    check_mount_roots(&plan, &settings, owner_home)?;
    check_pins(&plan, &settings, owner_home, observed, true)?;
    if let Ok(stage) = std::env::var("SUPERLOOP_MATRIX_STAGE") {
        let evidence_path = protected_identity_dir(&driver_dir)?.join("launch-evidence.json");
        let owner_uid = Uid::effective().as_raw();
        return match stage.as_str() {
            "publish-primary" => {
                matrix::publish_results(&plan, owner_home, &evidence_path, owner_uid, false)
            }
            "publish-deferred" if observed => {
                matrix::publish_results(&plan, owner_home, &evidence_path, owner_uid, true)
            }
            "prepare-deferred" if observed => {
                let row = matrix::prepare_deferred(&plan)?;
                matrix::publish_prepared_deferred(owner_home, &evidence_path, owner_uid, &row)?;
                Ok(
                    json!({"schema":1,"command":"deferred-bound-source","row":"vendor-socket","state":"pending"}),
                )
            }
            _ => Err(LaneError::input(
                "bound-source",
                "matrix publication stage is not applicable",
            )),
        };
    }
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let (runs_root_fd, runtime_dir) = pin_runtime_dir(&driver_dir, 0, loop_uid)?;
    let image = settings
        .image_digest
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "image_digest is absent"))?;
    private_image_check(podman, image, owner_home)?;
    let loop_name = plan.document["loop"]
        .as_str()
        .ok_or_else(|| LaneError::input("plan-read", "loop is absent"))?;
    check_backend_image_program(&settings, &installed_generation(owner_home, loop_name)?)?;
    let argv = plan.document["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("plan-read", "runtime_argv is absent"))?;
    if argv.first().and_then(Value::as_str) != podman.to_str() {
        return Err(LaneError::input(
            "plan-read",
            "runtime_argv has no container program",
        ));
    }
    let mut bytes = Vec::new();
    for arg in argv {
        let word = arg
            .as_str()
            .ok_or_else(|| LaneError::input("plan-read", "runtime argument is not a string"))?;
        if word.is_empty() || word.as_bytes().contains(&0) {
            return Err(LaneError::input(
                "plan-read",
                "runtime argument is empty or contains NUL",
            ));
        }
        bytes.extend_from_slice(word.as_bytes());
        bytes.push(0);
    }
    let mut file = create_runtime_file(&runtime_dir, "container.argv", 0o600)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| LaneError::operation("runtime-argv", error.to_string()))?;
    let environment = launch_environment(owner_home)?;
    let mut environment_bytes = Vec::new();
    for (key, value) in &environment {
        environment_bytes.extend_from_slice(key.as_bytes());
        environment_bytes.push(b'=');
        environment_bytes.extend_from_slice(value.as_bytes());
        environment_bytes.push(0);
    }
    if environment_bytes.len() > 65_536 {
        return Err(LaneError::input(
            "runtime-env",
            "container environment exceeds 65536 bytes",
        ));
    }
    let mut environment_file = create_runtime_file(&runtime_dir, "container.env", 0o600)?;
    environment_file
        .write_all(&environment_bytes)
        .and_then(|()| environment_file.sync_all())
        .map_err(|error| LaneError::operation("runtime-env", error.to_string()))?;
    let client = std::env::current_exe()
        .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
    let client_words = [
        crate::pinned::path_word(&client, "runtime-client")?,
        "_container-client".into(),
        "--run-dir".into(),
        crate::pinned::path_word(&driver_dir, "run-directory")?,
    ];
    let mut client_bytes = Vec::new();
    for word in client_words {
        client_bytes.extend_from_slice(word.as_bytes());
        client_bytes.push(0);
    }
    let mut client_file = create_runtime_file(&runtime_dir, "runtime.argv", 0o440)?;
    client_file
        .write_all(&client_bytes)
        .and_then(|()| client_file.sync_all())
        .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
    fchownat(
        &client_file,
        "",
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(loop_uid)),
        AtFlags::AT_EMPTY_PATH,
    )
    .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
    client_file
        .set_permissions(fs::Permissions::from_mode(0o440))
        .map_err(|error| LaneError::operation("runtime-client", error.to_string()))?;
    prepare_client_environment(&driver_dir, &runs_root_fd, &runtime_dir, loop_uid, true)?;
    let driver_contract = record["driver_contract"]
        .as_str()
        .filter(|value| *value == "boxed-runtime 1")
        .ok_or_else(|| {
            LaneError::input(
                "driver-contract",
                "protected reservation has no boxed-runtime 1 contract",
            )
        })?;
    let driver_sha256 = record["driver_sha256"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            LaneError::input(
                "driver-contract",
                "protected reservation has no driver digest",
            )
        })?;
    let bound_source_matrix = matrix::prepare(&plan)?;
    let evidence = json!({"schema":1,"command":"launch","loop":loop_name,"run":run,"round":record["active_round"],"budget_seconds":record["rounds"][0]["budget_seconds"],"observe":observed,"enforcing":!observed,"image_digest":image,"model_selection":record["model_selection"],"driver_sha256":driver_sha256,"driver_contract":driver_contract,"box_gate":plan.document["box_gate"],"bound_source_matrix":bound_source_matrix,"reservation_census":record["reservation_census"],"dead_preparation_retired":record["dead_preparation_retired"],"retry_retirements":record["retry_retirements"],"runtime_argv":argv,"runtime_environment":environment,"worker_home":plan.home,"driver_dir":driver_dir,"checks":if observed { "mount roots, installed pins, backend, and image identifier passed; observing socket checked before worker start" } else { "mount roots, installed pins, backend, vendor socket, and image identifier passed" }});
    let evidence_path = protected_identity_dir(&driver_dir)?.join("launch-evidence.json");
    let mut evidence_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&evidence_path)
        .map_err(|error| LaneError::operation("launch-evidence", error.to_string()))?;
    serde_json::to_writer(&mut evidence_file, &evidence)
        .map_err(|error| LaneError::operation("launch-evidence", error.to_string()))?;
    evidence_file
        .write_all(b"\n")
        .and_then(|()| evidence_file.sync_all())
        .map_err(|error| LaneError::operation("launch-evidence", error.to_string()))?;
    Ok(evidence)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn check_pins(
    plan: &Plan,
    settings: &Settings,
    owner_home: &Path,
    observed: bool,
    identity_created: bool,
) -> Result<(), LaneError> {
    let template = settings
        .template_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "template_dir is absent"))?;
    let owner_uid = Uid::effective().as_raw();
    let manifest_path = template.join("manifest");
    let manifest: Value = serde_json::from_slice(&crate::pinned::read_private(
        owner_home,
        &manifest_path,
        owner_uid,
        0o440,
        65_536,
    )?)
    .map_err(|error| LaneError::input("template-pin", error.to_string()))?;
    if manifest["image_digest"] != settings.image_digest.as_deref().unwrap_or_default() {
        return Err(LaneError::input(
            "template-pin",
            "manifest image identifier differs from workers.toml",
        ));
    }
    for (file, key, mode) in [
        ("bin/codex", "codex_sha256", 0o550),
        ("bin/codex-code-mode-host", "codex_host_sha256", 0o550),
        ("config.toml", "config_sha256", 0o440),
        ("AGENTS.md", "charter_sha256", 0o440),
    ] {
        let source = template.join(file);
        let fd = crate::pinned::open_protected(owner_home, &source, owner_uid)?;
        let metadata = nix::sys::stat::fstat(&fd)
            .map_err(|error| LaneError::input("template-pin", error.to_string()))?;
        if nix::sys::stat::SFlag::from_bits_truncate(metadata.st_mode)
            & nix::sys::stat::SFlag::S_IFMT
            != nix::sys::stat::SFlag::S_IFREG
            || metadata.st_uid != owner_uid
            || metadata.st_mode & 0o7777 != mode
        {
            return Err(LaneError::input(
                "template-pin",
                format!(
                    "{} differs from owner uid {owner_uid} and mode {mode:04o}",
                    source.display()
                ),
            ));
        }
        let expected = manifest[key]
            .as_str()
            .ok_or_else(|| LaneError::input("template-pin", format!("manifest lacks {key}")))?;
        if sha256(&source)? != expected {
            return Err(LaneError::input(
                "template-pin",
                format!("{} differs from manifest {key}", source.display()),
            ));
        }
    }
    let loop_name = plan.document["loop"]
        .as_str()
        .ok_or_else(|| LaneError::input("plan-read", "loop is absent"))?;
    let report_path = settings_path(owner_home, loop_name).with_file_name("image-build.json");
    let report: Value = serde_json::from_slice(
        &fs::read(&report_path)
            .map_err(|error| LaneError::input("build-report", error.to_string()))?,
    )
    .map_err(|error| LaneError::input("build-report", error.to_string()))?;
    build::image_program_from_report(&report)?;
    if report["image_digest"] != manifest["image_digest"]
        || report["codex_sha256"] != manifest["codex_sha256"]
        || report["codex_host_sha256"] != manifest["codex_host_sha256"]
    {
        return Err(LaneError::input(
            "template-pin",
            "image-build.json differs from installed manifest",
        ));
    }
    let generation = installed_generation(owner_home, loop_name)?;
    if generation["image_digest"] != manifest["image_digest"]
        || generation["codex_sha256"] != manifest["codex_sha256"]
        || generation["codex_host_sha256"] != manifest["codex_host_sha256"]
        || generation["codex_image_program"] != report["codex_image_program"]
    {
        return Err(LaneError::input(
            "template-pin",
            "pilot generation differs from the installed manifest or image-build.json",
        ));
    }
    if generation["init_sha256"] != report["init_sha256"] {
        return Err(LaneError::input(
            "template-pin",
            "pilot generation private init differs from image-build.json",
        ));
    }
    let init_path = template.join("libexec/box-init");
    let init_bytes = crate::pinned::read_private(owner_home, &init_path, owner_uid, 0o440, 65_536)?;
    if build::sha256_bytes(&init_bytes, template)? != report["init_sha256"] {
        return Err(LaneError::input(
            "template-pin",
            "installed private init differs from image-build.json",
        ));
    }
    let mounts = plan.document["mounts"]
        .as_array()
        .ok_or_else(|| LaneError::input("plan-read", "mounts are absent"))?;
    let identity_dir = protected_identity_dir(&plan.driver_dir)?;
    if identity_created {
        let root = plan
            .driver_dir
            .parent()
            .ok_or_else(|| LaneError::input("runs-root", "run has no parent"))?;
        let worker = plan.document["worker_uid"]
            .as_u64()
            .ok_or_else(|| LaneError::input("plan-read", "worker_uid is absent"))?;
        let loop_uid = u64::from(crate::plan::loop_uid(&plan.document)?);
        for (name, expected) in [
            (
                "passwd",
                format!("worker:x:{worker}:{worker}::/home/worker:/bin/sh\n"),
            ),
            (
                "group",
                format!("worker:x:{worker}:\nloop:x:{loop_uid}:worker\n"),
            ),
        ] {
            let source = identity_dir.join(name);
            let fd = crate::pinned::open_protected(root, &source, owner_uid)?;
            let stat = nix::sys::stat::fstat(&fd)
                .map_err(|error| LaneError::input("identity-pin", error.to_string()))?;
            if u64::from(stat.st_gid) != loop_uid {
                return Err(LaneError::input(
                    "identity-pin",
                    format!("{} differs from loop group {loop_uid}", source.display()),
                ));
            }
            let bytes = crate::pinned::read_private(root, &source, owner_uid, 0o440, 4096)?;
            if bytes != expected.as_bytes() {
                return Err(LaneError::input(
                    "identity-pin",
                    format!("{} differs from the plan", source.display()),
                ));
            }
        }
    }
    for mount in mounts.iter().filter(|mount| mount["kind"] == "bind") {
        let source = PathBuf::from(
            mount["source"]
                .as_str()
                .ok_or_else(|| LaneError::input("plan-read", "mount source is absent"))?,
        );
        if !source.exists() && (source.starts_with(&plan.home) || source.starts_with(&identity_dir))
        {
            continue;
        }
        let canonical = fs::canonicalize(&source).map_err(|error| {
            LaneError::input("mount-source", format!("{}: {error}", source.display()))
        })?;
        if canonical != source {
            return Err(LaneError::input(
                "mount-source",
                format!("{} follows a link", source.display()),
            ));
        }
    }
    let vendor_dir = settings
        .socket_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "socket_dir is absent"))?
        .join("vendor");
    let socket_name = if observed {
        plan.document["vendor_socket"]
            .as_str()
            .ok_or_else(|| LaneError::input("plan-read", "observing socket is absent"))?
    } else {
        "proxy.sock"
    };
    let socket = vendor_dir.join(socket_name);
    if !observed
        && !fs::symlink_metadata(&socket).is_ok_and(|meta| {
            meta.file_type().is_socket() && meta.permissions().mode() & 0o7777 == 0o660
        })
    {
        return Err(LaneError::input(
            "vendor-socket",
            format!("{} is missing or differs from mode 0660", socket.display()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// # Panics
    /// Panics only if fixture creation fails or retirement accepts unsafe occupancy.
    /// ´test:unit:retirement-name-refuses-source-links-and-nonregular-occupants´
    #[test]
    fn retirement_name_refuses_source_links_and_nonregular_occupants() {
        use std::os::unix::fs::MetadataExt as _;
        for kind in ["hard-link", "symlink", "directory"] {
            for at_suffix in [false, true] {
                let root = tempfile::tempdir().expect("fixture");
                let source = root.path().join("source");
                std::fs::write(&source, b"reservation").expect("source");
                let metadata = std::fs::metadata(&source).expect("metadata");
                let base = root.path().join(format!(
                    ".retired-R-20-{}-{}",
                    metadata.dev(),
                    metadata.ino()
                ));
                let target = if at_suffix {
                    std::fs::write(&base, b"rewritten report").expect("different occupant");
                    root.path().join(format!(
                        "{}.1",
                        base.file_name().expect("name").to_string_lossy()
                    ))
                } else {
                    base
                };
                match kind {
                    "hard-link" => std::fs::hard_link(&source, &target).expect("hard link"),
                    "symlink" => std::os::unix::fs::symlink(&source, &target).expect("symlink"),
                    _ => std::fs::create_dir(&target).expect("directory"),
                }
                let error =
                    super::planned_retirement(&source, "R", 20).expect_err("unsafe occupant");
                assert_eq!(error.kind, "launch-recover");
                assert!(error.detail.contains(target.to_str().expect("path")));
                assert!(error.detail.contains(if kind == "hard-link" {
                    "is the source itself"
                } else {
                    "is occupied by a non-regular entry"
                }));
                assert_eq!(
                    std::fs::read(&source).expect("unchanged source"),
                    b"reservation"
                );
            }
        }
    }

    /// # Panics
    /// Panics only if fixture creation fails or retirement exceeds its candidate bound.
    /// ´test:unit:retirement-name-search-is-bounded´
    #[test]
    fn retirement_name_search_is_bounded() {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().expect("fixture");
        let source = root.path().join("source");
        std::fs::write(&source, b"source").expect("source");
        let metadata = std::fs::metadata(&source).expect("metadata");
        let name = format!(".retired-R-20-{}-{}", metadata.dev(), metadata.ino());
        for suffix in 0..super::RETIREMENT_NAME_LIMIT {
            let target = if suffix == 0 {
                name.clone()
            } else {
                format!("{name}.{suffix}")
            };
            std::fs::write(root.path().join(target), b"occupant").expect("occupant");
        }
        let error = super::planned_retirement(&source, "R", 20).expect_err("bounded search");
        assert_eq!(error.kind, "launch-recover");
        assert!(error.detail.contains("4096 candidate bound"));
        let last = root
            .path()
            .join(format!("{name}.{}", super::RETIREMENT_NAME_LIMIT - 1));
        std::fs::remove_file(&last).expect("free last candidate");
        let plan = super::planned_retirement(&source, "R", 20)
            .expect("plan")
            .expect("present source");
        assert_eq!(plan["target"], serde_json::json!(last));
    }

    /// ´test:unit:changed-plan-detail-names-the-door-repin-route-and-other-pinned-inputs´
    #[test]
    fn changed_plan_detail_names_the_door_repin_route_and_other_pinned_inputs() {
        let saved = serde_json::json!({"door":{"stub_sha256":"old"},"door_floor":"audit"});
        let door = serde_json::json!({"door":{"stub_sha256":"new"},"door_floor":"audit"});
        let other = serde_json::json!({"door":{"stub_sha256":"old"},"door_floor":"enforce"});
        let mixed = serde_json::json!({"door":{"stub_sha256":"new"},"door_floor":"enforce"});
        for current in [&door, &mixed] {
            let error = super::compare_pinned_plan(&saved, current).expect_err("drift");
            assert_eq!(error.kind, "plan-read");
            for text in [
                "launch LOOP RUN --repin-door --dry-run",
                "both door objects and preview_sha256",
                "launch LOOP RUN --repin-door --expect-digest HEX",
                "ordinary resume dry run",
            ] {
                assert!(error.detail.contains(text), "{} lacks {text}", error.detail);
            }
        }
        let error = super::compare_pinned_plan(&saved, &other).expect_err("other drift");
        assert_eq!(error.kind, "plan-read");
        assert!(
            error
                .detail
                .contains("differing keys: door_floor; reconcile the named pinned inputs")
        );
        assert!(!error.detail.contains("--repin-door"));
        let error = super::compare_pinned_plan(&saved, &mixed).expect_err("mixed drift");
        assert!(error.detail.contains(
            "differing keys: door, door_floor; first reconcile the named non-door pinned inputs"
        ));
        assert!(super::compare_pinned_plan(&saved, &saved).is_ok());
    }

    /// ´test:unit:changed-plan-detail-names-door-floor´
    #[test]
    fn changed_plan_detail_names_door_floor() {
        let saved = serde_json::json!({"schema":1,"door_floor":null,"loop":"alpha"});
        let current = serde_json::json!({"schema":1,"door_floor":"allow","loop":"alpha"});
        assert_eq!(super::differing_plan_keys(&saved, &current), "door_floor");
    }

    /// ´test:unit:reservation-loop-identity-refuses-conflicting-driver-owner´
    #[test]
    fn reservation_loop_identity_refuses_conflicting_driver_owner() {
        let mut record = serde_json::json!({"plan":{"home":"~/home-R","driver_dir":"~/runs/R","worker_uid":3000,"paths":[{"path":"~/home-R","uid":41001,"gid":41001},{"path":"~/runs/R","kind":"directory","uid":41001,"gid":41001}]}});
        assert_eq!(
            super::recorded_loop_uid(&record).expect("shared owner"),
            41001
        );
        record["plan"]["paths"][1]["uid"] = serde_json::json!(3001);
        assert_eq!(
            super::recorded_loop_uid(&record)
                .expect_err("conflicting driver owner")
                .kind,
            "loop-identity"
        );
    }
    /// # Panics
    /// Panics only if an exited helper's own refusal is lost or renamed.
    /// ´test:unit:helper-stop-retains-helper-refusal-text´
    #[test]
    fn helper_stop_retains_helper_refusal_text() {
        let mut helper = std::process::Command::new("/usr/bin/false")
            .spawn()
            .expect("helper");
        helper.wait().expect("helper exit");
        let stderr = std::thread::spawn(|| b"helper-pin: fixture refusal\n".to_vec());
        let error = super::helper_stop_with_stderr(
            Err(crate::error::LaneError::operation(
                "helper-stop",
                "helper exited exit status: 2",
            )),
            &mut helper,
            stderr,
        )
        .expect_err("helper refusal");
        assert_eq!(error.kind, "helper-stop");
        assert!(error.detail.contains("helper-pin: fixture refusal"));
    }

    /// # Panics
    /// Panics only if the asserted generation binding fails.
    /// ´test:unit:container-attempt-evidence-is-bound-to-launcher-generation´
    #[test]
    fn container_attempt_evidence_is_bound_to_launcher_generation() {
        let mut record = serde_json::json!({"launcher_pid":42,"launcher_start":100,"rounds":[{}]});
        let marker = serde_json::json!({"launcher_pid":42,"launcher_start":100});
        assert!(super::attempt_belongs_to_round(&marker, &record));
        record["launcher_start"] = serde_json::json!(101);
        assert!(!super::attempt_belongs_to_round(&marker, &record));
        assert!(super::attempt_belongs_to_round(
            &serde_json::json!({}),
            &record
        ));
        record["rounds"] = serde_json::json!([{}, {}]);
        assert!(!super::attempt_belongs_to_round(
            &serde_json::json!({}),
            &record
        ));
    }

    use std::collections::BTreeMap;
    /// # Panics
    /// Panics only if completed-process evidence loses the unsuccessful outcome.
    /// ´test:unit:helper-completion-retains-unsuccessful-exit´
    #[test]
    fn helper_completion_retains_unsuccessful_exit() {
        use std::os::unix::process::ExitStatusExt as _;
        let end = super::helper_parent_end(42, 100, std::process::ExitStatus::from_raw(256), None);
        assert_eq!(end["state"], "completed");
        assert_eq!(end["successful"], false);
    }

    /// # Panics
    /// Panics only if a driver failure loses whether a child started.
    /// ´test:unit:driver-completion-distinguishes-runtime-and-start-failure´
    #[test]
    fn driver_completion_distinguishes_runtime_and_start_failure() {
        let result = Err(crate::error::LaneError::operation(
            "driver-launch",
            "runtime failure",
        ));
        for (started, state) in [(false, "not-started"), (true, "completed")] {
            let end =
                super::driver_completion(&result, started, &crate::build::ChildEnd::default());
            assert_eq!(end["state"], state);
            assert_eq!(end["successful"], false);
            assert_eq!(end["detail"], "driver-launch: runtime failure");
        }
    }

    /// # Panics
    /// Panics only if a launch site stops using the shared outer guard.
    /// ´test:unit:both-driver-launch-sites-use-the-shared-outer-guard´
    #[test]
    fn both_driver_launch_sites_use_the_shared_outer_guard() {
        for (source, function) in [
            (include_str!("launch.rs"), "fn run_with_program("),
            (include_str!("launch/rounds.rs"), "fn resume_with_program("),
        ] {
            let body = source
                .split_once(function)
                .expect("launch function")
                .1
                .split("\nfn ")
                .next()
                .expect("function body");
            assert!(body.contains("crate::container_helper::host_launch_bound(&record)"));
            assert!(!body.contains("crate::container_helper::attempt_wall_bound(&record)"));
        }
    }

    /// # Panics
    /// Panics only if fixture setup or the host wall's reportless failure contract fails.
    /// ´test:unit:driver-launch-wall-retains-ordinary-failed-settlement´
    #[test]
    fn driver_launch_wall_retains_ordinary_failed_settlement() {
        let (fixture, plan, _, mut record) = settlement_fixture(false);
        let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
        fs::create_dir(&directory).expect("step directory");
        fs::write(directory.join("events.jsonl"), b"").expect("events");
        fs::write(directory.join(".event-start"), b"0\n").expect("event boundary");
        record["active_round"] = json!("dispatch");
        record["letters"] = json!([]);
        record["rounds"] = json!([{"step":"dispatch","phase":"running","budget_seconds":1,"driver_dir":directory}]);
        let path = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&path, &record).expect("reservation");
        let mut end = crate::build::ChildEnd::default();
        let mut started = false;
        // A short runner bound exercises the host stop without waiting for the outer margin.
        let result = crate::build::run_checked_with_pid(
            Path::new("/usr/bin/sleep"),
            vec!["30".into()],
            &std::collections::BTreeMap::new(),
            fixture.path(),
            1,
            "driver-launch",
            &mut end,
            |_| {
                started = true;
                Ok(())
            },
        );
        assert!(result.is_err());
        let completion = super::driver_completion(&result, started, &end);
        assert_eq!(completion["state"], "completed");
        assert_eq!(completion["successful"], false);
        assert_eq!(completion["cause"], "launch-wall");
        assert_eq!(completion["bound_seconds"], 1);
        assert!(
            completion["attempt_elapsed_seconds"]
                .as_u64()
                .expect("elapsed")
                >= 1
        );
        super::persist_settlement_field(&path, "driver_end", completion.clone())
            .expect("driver end");
        super::rounds::record_failed_settlement(
            &plan,
            "R",
            result.as_ref().expect_err("wall stop"),
        )
        .expect("ordinary failed settlement");
        let saved = super::read_reservation(&path)
            .expect("read")
            .expect("reservation");
        assert_eq!(saved["driver_end"], completion);
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert!(saved["rounds"][0]["ended_by"].is_null());
        assert!(saved["rounds"][0]["attempt_end"].is_null());
        assert!(!directory.join("run-report.txt").exists());
    }

    /// # Panics
    /// Panics only if a natural child exit is misclassified as a wall stop.
    /// ´test:unit:driver-natural-failure-has-no-wall-cause´
    #[test]
    fn driver_natural_failure_has_no_wall_cause() {
        let fixture = tempfile::tempdir().expect("fixture");
        let mut end = crate::build::ChildEnd::default();
        let result = crate::build::run_checked_with_pid(
            Path::new("/usr/bin/false"),
            Vec::new(),
            &std::collections::BTreeMap::new(),
            fixture.path(),
            1,
            "driver-launch",
            &mut end,
            |_| Ok(()),
        );
        assert!(result.is_err());
        let completion = super::driver_completion(&result, true, &end);
        assert_eq!(completion["state"], "completed");
        assert_eq!(completion["successful"], false);
        assert!(completion.get("cause").is_none());
        assert!(completion.get("bound_seconds").is_none());
    }
    use std::fmt::Write as _;
    use std::fs;
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;

    use serde_json::{Value, json};

    use super::{
        LaunchRequest, RecordHostsRequest, bounded_observer_stderr, create_runtime_file,
        driver_runtime_contract, helper_parent_end, identify_started_observer, inspect_readback,
        lock_run_preparation, lock_runs_root, observation_reservation, observer_exit_detail,
        parse_observation, pin_runtime_dir, private_podman_environment_from, publish_reservation,
        read_observation_private, record_failed_pre_driver, recovery_record_with,
        replace_preparation_with, reservation_differences, reservation_path,
        retire_dead_helper_sockets, retire_dead_helper_sockets_with, retire_partial,
        select_free_uid, stage_preparation_retirement_with, stop_observer,
    };

    /// # Panics
    ///
    /// Panics only if recovery admits a state outside failed post-driver incompletion.
    /// ´test:unit:failed-driver-recovery-admission-is-narrow´
    #[test]
    fn failed_driver_recovery_admission_is_narrow() {
        let record = json!({"phase":"failed","driver_entry_pid":4_000_000,"driver_entry_start":1});
        assert!(super::failed_driver_recovery(&record));
        for (key, value) in [
            ("phase", json!("started")),
            ("phase", json!("preparing")),
            ("phase", json!("settled")),
            ("driver_entry_pid", Value::Null),
            ("driver_entry_start", Value::Null),
            ("pre_driver_failure", json!("failure before driver")),
            ("pre_driver_failure", Value::Null),
        ] {
            let mut changed = record.clone();
            changed[key] = value;
            assert!(!super::failed_driver_recovery(&changed), "{key}");
        }
        for (driver, helper, admitted) in [
            ("completed", "completed", false),
            ("completed", "failed", true),
            ("failed", "completed", true),
        ] {
            let mut changed = record.clone();
            changed["driver_end"] = json!({"state":driver});
            changed["helper_end"] = json!({"state":helper});
            assert_eq!(super::failed_driver_recovery(&changed), admitted);
        }
    }

    /// # Panics
    ///
    /// Panics only if failed recovery loses the existing process refusal names.
    /// ´test:unit:failed-driver-recovery-retains-process-refusals´
    #[test]
    fn failed_driver_recovery_retains_process_refusals() {
        let (_fixture, plan, letter, mut record) = settlement_fixture(false);
        record["phase"] = json!("failed");
        for (name, pid) in [
            ("launcher", 321),
            ("driver", 322),
            ("helper", 323),
            ("helper-parent", 325),
        ] {
            for (state, kind, detail) in [
                (
                    ProcessPresence::Present,
                    "launch-busy",
                    format!("{name} is still alive"),
                ),
                (
                    ProcessPresence::Unknown,
                    "settlement-uncertain",
                    format!("{name} absence cannot be established"),
                ),
            ] {
                let error = super::interrupted_settlement_with(
                    &record,
                    &plan,
                    &letter,
                    |candidate, _| {
                        if candidate == pid {
                            state
                        } else {
                            ProcessPresence::Absent
                        }
                    },
                    || panic!("identity refusal precedes container inspection"),
                    crate::launch::driver_report::fixture_read,
                )
                .expect_err("unproven process absence");
                assert_eq!(error.kind, kind);
                assert_eq!(error.detail, detail);
            }
        }
    }

    /// # Panics
    /// Panics only if stale status evidence is accepted as current completion.
    /// ´test:unit:current-attempt-start-rejects-prior-generation-status´
    #[test]
    fn current_attempt_start_rejects_prior_generation_status() {
        let (_fixture, plan, _letter, record) = settlement_fixture(false);
        let custody = crate::plan::protected_identity_dir(&plan.driver_dir).expect("custody");
        let path = custody.join("container-attempt-1.status.json");
        let mut status: Value =
            serde_json::from_slice(&fs::read(&path).expect("status")).expect("status JSON");
        status["launcher_start"] = json!(87);
        fs::write(&path, serde_json::to_vec(&status).expect("encode")).expect("stale status");
        let mut measured = false;
        let evidence = super::attempt_evidence_complete(&plan.driver_dir, &record, &mut || {
            measured = true;
            Ok(true)
        })
        .expect("measured absence");
        assert!(measured);
        assert_eq!(evidence["state"], "absence-confirmed-with-missing-evidence");
        assert_eq!(evidence["attempts"], json!([]));
        let error = super::attempt_evidence_complete(&plan.driver_dir, &record, &mut || Ok(false))
            .expect_err("absence required");
        assert_eq!(error.kind, "settlement-uncertain");
    }

    /// # Panics
    ///
    /// Panics only if ordinary settlement writes admit a failed dispatch without recovery.
    /// ´test:unit:failed-driver-recovery-keeps-ordinary-writer-refusal´
    #[test]
    fn failed_driver_recovery_keeps_ordinary_writer_refusal() {
        let (fixture, _plan, _letter, mut record) = settlement_fixture(false);
        record["phase"] = json!("failed");
        let path = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&path, &record).expect("failed record");
        let before = fs::read(&path).expect("original bytes");
        let error =
            super::persist_settlement_field(&path, "driver_end", json!({"state":"completed"}))
                .expect_err("ordinary writer remains restricted");
        assert_eq!(error.kind, "launch-reservation");
        assert_eq!(error.detail, "reservation is not active");
        assert_eq!(fs::read(&path).expect("unchanged bytes"), before);
    }

    /// ´test:unit:reservation-writer-refuses-a-document-the-reader-would-refuse´
    #[test]
    fn reservation_writer_refuses_a_document_the_reader_would_refuse() {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let path = super::reservation_path(root.path(), "R");
        let small = json!({"schema":1,"phase":"settled","worker_uid":3000});
        super::publish_reservation(&path, &small).expect("small reservation");
        let before = fs::read(&path).expect("original bytes");
        let large =
            json!({"schema":1,"phase":"settled","worker_uid":3000,"padding":"x".repeat(4_194_304)});
        let size = serde_json::to_vec(&large)
            .expect("serialized oversized reservation")
            .len();
        let refusal = super::publish_reservation(&path, &large).expect_err("writer bound");
        assert_eq!(refusal.kind, "reservation-size");
        assert!(refusal.detail.contains(&size.to_string()));
        assert!(refusal.detail.contains("4194304"));
        assert_eq!(fs::read(&path).expect("bytes after refusal"), before);
        assert_eq!(
            super::read_reservation(&path)
                .expect("reader")
                .expect("present"),
            small
        );
    }

    /// ´test:unit:source-declarations-bound-and-validate-local-bare-names´
    #[test]
    fn source_declarations_bound_and_validate_local_bare_names() {
        let names = super::declared_sources(
            b"Model: gpt-6-sol\nEffort: high\nSources: tools notes\n\nWork.\n",
        )
        .expect("declared sources");
        assert_eq!(
            names
                .iter()
                .map(|source| source.name.as_str())
                .collect::<Vec<_>>(),
            ["tools", "notes"]
        );
        assert!(names.iter().all(|source| source.seed.is_none()));
        let seed = "a".repeat(40);
        let seeded = super::declared_sources(format!("Sources: tools@{seed} notes\n").as_bytes())
            .expect("seeded source");
        assert_eq!(seeded[0].seed.as_deref(), Some(seed.as_str()));
        assert_eq!(seeded[1].seed, None);
        let rows = super::declared_source_rows(&seeded);
        assert_eq!(
            rows,
            vec![
                json!({"name":"tools","seed":seed,"source_identity":null,"seeded_at_unix_ns":null}),
                json!({"name":"notes","seed":null,"source_identity":null,"seeded_at_unix_ns":null}),
            ]
        );
        assert_eq!(
            super::declared_sources(b"Model: gpt-6-sol\n\nWork.\n").expect("no declaration"),
            Vec::<super::DeclaredSource>::new()
        );
        for letter in [
            "Sources: tools tools\n",
            "Sources: ../tools\n",
            "Sources: tools\nSources: notes\n",
            "Sources: tools@a\n",
            "Sources: tools@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa tools\n",
        ] {
            assert_eq!(
                super::declared_sources(letter.as_bytes())
                    .expect_err("invalid sources")
                    .kind,
                "letter-sources"
            );
        }
    }

    /// ´test:unit:rotation-private-refusal-keeps-the-source-name-and-digests´
    #[test]
    fn rotation_private_refusal_keeps_the_source_name_and_digests() {
        let expected = "a".repeat(64);
        let actual = "b".repeat(64);
        for phase in ["prepare-home", "prepare-runtime"] {
            let child = crate::error::LaneError::operation(
                phase,
                format!(
                    "private step exited 2: rotate-source: expected digest {expected} differs from inbox digest {actual} wall_seconds=0.125000"
                ),
            );
            let refusal = super::rotation_child_refusal(child);
            assert_eq!(refusal.kind, "rotate-source");
            assert!(refusal.detail.contains(&expected));
            assert!(refusal.detail.contains(&actual));
            assert!(!refusal.detail.contains("wall_seconds"));
        }
    }

    /// ´test:unit:launch-report-collapses-replayed-letter-identity´
    #[test]
    fn launch_report_collapses_replayed_letter_identity() {
        let output = "LETTER box=inbox name=dispatch.md bytes=4 at=2026-10-07T00:00:00Z id=AB\nLETTER box=inbox name=dispatch.md bytes=4 at=2026-10-07T00:00:00Z id=AB replay=1\nRUN-REPORT lane=dispatch exit=0\n";
        let shown = super::driver_report_for_reader(output);
        assert_eq!(shown.matches("LETTER box=").count(), 1);
        assert!(shown.contains("RUN-REPORT lane=dispatch exit=0"));
    }

    fn prove_empty_probe_journal(record: &mut Value) {
        record["probe_absence_proof"] = super::prove_probe_absence_with(
            record,
            |_, _| panic!("fixture has no probe process"),
            || Ok(true),
        )
        .expect("empty labelled query");
    }

    /// ´test:unit:private-runtime-vector-never-runs-a-container´
    #[test]
    fn private_runtime_vector_never_runs_a_container() {
        let request = LaunchRequest::parse(&[
            "alpha".into(),
            "fixture-1".into(),
            "--letter".into(),
            "/home/owner/dispatch.md".into(),
        ])
        .expect("request");
        let vector = super::runtime_prepare_argv(
            "/opt/lane",
            "/usr/bin/podman",
            Path::new("/home/owner"),
            &request,
        )
        .expect("private vector");
        assert_eq!(&vector[..3], ["unshare", "/opt/lane", "_prepare-runtime"]);
        assert!(!vector.iter().any(|word| word == "run"));
        assert_eq!(vector.last().map(String::as_str), Some("/usr/bin/podman"));
    }

    /// ´test:unit:letter-model-overrides-flags-and-missing-values-refuse´
    #[test]
    fn letter_model_overrides_flags_and_missing_values_refuse() {
        let selection = super::LaunchModel::select(
            b"Model: gpt-6-sol\nReasoning effort: high\n\nRead back.\n",
            Some("gpt-5.6-sol"),
            Some("low"),
        )
        .expect("opening declaration");
        assert_eq!(
            selection.record(),
            json!({"model":"gpt-6-sol","effort":"high","model_source":"letter","effort_source":"letter"})
        );
        let fallback =
            super::LaunchModel::select(b"Read back.\n", Some("gpt-6-sol"), Some("xhigh"))
                .expect("recorded flags");
        assert_eq!(fallback.record()["model_source"], "launch-flag");
        assert_eq!(fallback.record()["effort_source"], "launch-flag");
        assert_eq!(
            super::LaunchModel::select(b"Read back.\n", None, Some("high"))
                .expect_err("model absent")
                .kind,
            "letter-model"
        );
    }
    use crate::container_helper::ProcessPresence;
    use crate::plan::Plan;

    /// ´test:unit:interrupted-completion-requires-successful-process-ends´
    #[test]
    fn interrupted_completion_requires_successful_process_ends() {
        let mut record = json!({"driver_end":{"state":"completed"},"helper_end":{"state":"completed"},"readback_end":"completed","observation_end":"completed","observer_end":{"state":"not-started","socket":{"state":"not-applicable"}}});
        let evidence = json!({"state":"complete","attempts":[{"status":0,"error_free":true}]});
        assert!(super::interrupted_settlement_success(&record, &evidence));
        for end in ["driver_end", "helper_end"] {
            record[end]["successful"] = json!(false);
            assert!(!super::interrupted_settlement_success(&record, &evidence));
            record[end]["successful"] = json!(true);
            assert!(super::interrupted_settlement_success(&record, &evidence));
        }
    }

    /// ´test:unit:retired-observer-missing-socket-is-absent-not-removed´
    #[test]
    fn retired_observer_missing_socket_is_absent_not_removed() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let held = fs::File::open(root.path()).expect("held root");
        let _guard = crate::home::activate_handed_home(
            root.path(),
            &held,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("private fixture");
        let path = root.path().join("observer.sock");
        let record =
            json!({"current_retirement":{"observer_socket":path,"observer_socket_present":true}});
        assert_eq!(
            super::remove_retired_observer_socket(&record).expect("absent"),
            json!({"state":"absent","path":path})
        );
    }

    /// ´test:unit:helper-start-refusal-records-terminal-dead-preparation´
    #[test]
    fn helper_start_refusal_records_terminal_dead_preparation() {
        let root = tempfile::tempdir().expect("runs root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let reservation = super::reservation_path(root.path(), "R");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"launcher_pid":321,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"running","helper_parent_pid":322,"helper_parent_start":89,"rounds":[{"step":"work","phase":"running"}]});
        super::publish_reservation(&reservation, &record).expect("preparation");
        let refusal = crate::error::LaneError::operation("helper-start", "helper pin differed");
        super::record_failed_pre_driver(&reservation, &mut None, &refusal, 41001, false)
            .expect("terminal failure record");
        let saved = super::read_reservation(&reservation)
            .expect("read record")
            .expect("retained record");
        assert_eq!(saved["phase"], "failed");
        assert_eq!(saved["pre_driver_failure"], refusal.line());
        assert_eq!(saved["rounds"][0]["phase"], "failed");
        assert_eq!(saved["rounds"][0]["ended_by"], "failed-at-start");
        assert_eq!(saved["driver_end"]["state"], "not-started");
        assert_eq!(saved["helper_end"]["state"], "failed");
        assert_eq!(saved["observer_end"]["socket"]["state"], "not-applicable");
        let next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"observer_state":"not-started"});
        super::recovery_record_with(
            &saved,
            &next,
            root.path(),
            &root.path().join("R"),
            |_, _| ProcessPresence::Absent,
        )
        .expect("terminal pre-driver failure is a dead preparation");
    }

    /// ´test:unit:dead-preparation-refuses-unrecorded-helper-parent´
    #[test]
    fn dead_preparation_refuses_unrecorded_helper_parent() {
        let root = tempfile::tempdir().expect("runs root");
        let old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"launcher_pid":321,"launcher_start":88,"observer_state":"not-started","helper_pid":323,"helper_start":90,"helper_spawn_state":"starting"});
        let error =
            super::recovery_record_with(&old, &old, root.path(), &root.path().join("R"), |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("missing parent proof refuses dead preparation");
        assert_eq!(error.kind, "launch-reservation");
        assert!(error.detail.contains("helper parent"));
    }

    /// ´test:unit:journaled-probe-without-absence-proof-refuses-retirement´
    #[test]
    fn journaled_probe_without_absence_proof_refuses_retirement() {
        let root = tempfile::tempdir_in("/tmp").expect("runs root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let worker = if owner == 3000 { 3001 } else { 3000 };
        assert_ne!(owner, worker);
        let old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":worker,"plan":{"old":true},"launcher_pid":u32::MAX,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"not-started","probe_starts":[{"phase":"primary","role":"worker","container_name":"fixture-matrix-worker","state":"running","pid":u32::MAX,"start_tick":89}]});
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":worker,"plan":{"new":true}});
        let reservation = super::reservation_path(root.path(), "R");
        let error = super::stage_preparation_retirement_with(
            &old,
            &mut next,
            &reservation,
            root.path(),
            &root.path().join("R"),
            &root.path().join("home-R"),
            &root.path().join(".observed-R.txt"),
            "R",
            true,
            |_, _| ProcessPresence::Absent,
        )
        .expect_err("unproven probe prevents retirement");
        assert_eq!(error.kind, "launch-reservation");
        assert!(error.line().contains("probe absence proof"));
    }

    /// ´test:unit:empty-probe-journal-still-requires-a-matching-public-proof´
    #[test]
    fn empty_probe_journal_still_requires_a_matching_public_proof() {
        let record = json!({"schema":1,"phase":"preparing"});
        let error = super::require_probe_absence_proof(&record, |_, _| {
            panic!("empty journal has no processes")
        })
        .expect_err("missing proof refuses even without a journal");
        assert_eq!(error.kind, "launch-reservation");
        let proof = super::prove_probe_absence_with(
            &record,
            |_, _| panic!("empty journal has no processes"),
            || Ok(true),
        )
        .expect("fresh empty-label proof");
        assert_eq!(proof["probe_starts"], json!([]));
        let mut proved = record;
        proved["probe_absence_proof"] = proof;
        super::require_probe_absence_proof(&proved, |_, _| {
            panic!("empty journal has no processes")
        })
        .expect("same verification path accepts the public proof");
        proved["probe_absence_proof"]["source"] = json!("unverified");
        let error = super::require_probe_absence_proof(&proved, |_, _| {
            panic!("empty journal has no processes")
        })
        .expect_err("changed proof source refuses");
        assert_eq!(error.kind, "launch-reservation");
    }

    /// ´test:unit:labelled-container-absence-and-dead-probe-allow-retirement´
    #[test]
    fn labelled_container_absence_and_dead_probe_allow_retirement() {
        let root = tempfile::tempdir_in("/tmp").expect("runs root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let worker = if owner == 3000 { 3001 } else { 3000 };
        assert_ne!(owner, worker);
        let driver = root.path().join("R");
        fs::create_dir(&driver).expect("old run");
        let home = root.path().join("home-R");
        fs::create_dir(&home).expect("old home");
        let mut old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":worker,"plan":{"old":true},"launcher_pid":u32::MAX,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"not-started","probe_starts":[{"phase":"primary","role":"worker","container_name":"fixture-matrix-worker","state":"running","pid":u32::MAX,"start_tick":89}]});
        let mut queried = false;
        let present = super::prove_probe_absence_with(
            &old,
            |_, _| ProcessPresence::Absent,
            || {
                queried = true;
                Ok(false)
            },
        )
        .expect_err("present labelled container refuses");
        assert!(queried);
        assert_eq!(present.kind, "launch-busy");
        let proof =
            super::prove_probe_absence_with(&old, |_, _| ProcessPresence::Absent, || Ok(true))
                .expect("empty labelled query proves absence");
        assert_eq!(proof["labelled_containers"], "absent");
        old["probe_absence_proof"] = proof;
        let reservation = super::reservation_path(root.path(), "R");
        super::publish_reservation(&reservation, &old).expect("old reservation");
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":worker,"plan":{"new":true},"observer_state":"not-started","helper_spawn_state":"not-started"});
        let retired = super::replace_preparation_with(
            &old,
            &mut next,
            &reservation,
            root.path(),
            &driver,
            &home,
            &root.path().join(".observed-R.txt"),
            "R",
            |_, _| ProcessPresence::Absent,
        )
        .expect("dead probe and empty labelled query allow retirement");
        assert!(retired.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".retired-R-"))
        }));
        assert!(!driver.exists());
        assert!(!home.exists());
    }

    fn settlement_fixture(observe: bool) -> (tempfile::TempDir, Plan, std::path::PathBuf, Value) {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let driver_dir = fixture.path().join("R");
        fs::create_dir(&driver_dir).expect("run directory");
        fs::set_permissions(&driver_dir, fs::Permissions::from_mode(0o700)).expect("run mode");
        let letter = fixture.path().join("letter");
        let vendor = fixture.path().join("vendor");
        fs::create_dir(&vendor).expect("vendor directory");
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o700)).expect("vendor mode");
        let mut document = json!({"loop":"alpha","run":"R","worker_uid":3000,"home":fixture.path().join("home-R"),"driver_dir":driver_dir});
        if observe {
            document["vendor_mode"] = json!("observing");
            document["vendor_socket"] = json!("observe-R.sock");
            document["mounts"] = json!([{"target":"/home/worker/.local/vendor","source":vendor}]);
        }
        let plan = Plan {
            home: fixture.path().join("home-R"),
            driver_dir: driver_dir.clone(),
            letter: letter.clone(),
            document: document.clone(),
        };
        let custody = crate::plan::protected_identity_dir(&driver_dir).expect("custody path");
        fs::create_dir(&custody).expect("custody directory");
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
        let evidence = custody.join("container-attempt-1.status.json");
        let start = custody.join("container-attempt-1.start.json");
        fs::write(&start, b"{\"schema\":1,\"attempt\":1,\"state\":\"started\",\"launcher_pid\":321,\"launcher_start\":88,\"container_name\":\"superloop-lane-alpha-R-attempt-1\"}\n").expect("protected attempt start");
        fs::set_permissions(&start, fs::Permissions::from_mode(0o600)).expect("start mode");
        fs::write(&evidence, b"{\"schema\":1,\"attempt\":1,\"launcher_pid\":321,\"launcher_start\":88,\"bounded\":true,\"status\":0,\"stream_errors\":[],\"stream_error\":null,\"wait_error\":null,\"stop_error\":null,\"thread_error\":null,\"post_start_error\":null,\"removal\":{\"state\":\"removed\"}}\n").expect("complete attempt");
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o600)).expect("attempt mode");
        assert_ne!(
            std::os::unix::fs::MetadataExt::uid(&fs::metadata(&evidence).expect("evidence owner")),
            3000
        );
        let mut record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":document,"model_selection":{"model":"gpt-6-sol","effort":"high","model_source":"launch-flag","effort_source":"launch-flag"},"letter_source":letter,"launcher_pid":321,"launcher_start":88,"driver_entry_pid":322,"driver_entry_start":89,"helper_pid":323,"helper_start":90,"helper_parent_pid":325,"helper_parent_start":92,"observer_state":if observe { "running" } else { "not-started" }});
        if observe {
            record["observer_pid"] = json!(324);
            record["observer_start"] = json!(91);
        }
        let reservation = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&reservation, &record).expect("started reservation");
        (fixture, plan, letter, record)
    }

    /// ´test:unit:interrupted-collected-scope-records-measured-quiescence´
    #[test]
    fn interrupted_collected_scope_records_measured_quiescence() {
        for worker in [3000, 3001] {
            for live in [false, true] {
                let (fixture, mut plan, letter, mut record) = settlement_fixture(false);
                assert_ne!(nix::unistd::Uid::effective().as_raw(), worker);
                plan.document["worker_uid"] = json!(worker);
                record["worker_uid"] = json!(worker);
                record["plan"] = plan.document.clone();
                record["rounds"] = json!([{"step":"dispatch","phase":"running"}]);
                record["run_scope"] = json!({"unit":"superloop-lane-run-fixture.service","cgroup":"/user.slice/superloop-lane-run-fixture.service/work","device":1,"inode":2,"proxy_unit":"proxy.service","proxy_invocation":"fixture"});
                let path = super::reservation_path(fixture.path(), "R");
                super::publish_reservation(&path, &record).expect("record");
                fs::remove_file(
                    crate::plan::protected_identity_dir(&plan.driver_dir)
                        .expect("custody")
                        .join("container-attempt-1.status.json"),
                )
                .expect("missing history");
                let result = super::finish_interrupted_settlement_with(
                    &path,
                    &plan,
                    &letter,
                    nix::unistd::Uid::effective().as_raw(),
                    || Ok(Value::Null),
                    || Ok(Value::Null),
                    |pid, _| {
                        if live && pid == 321 {
                            ProcessPresence::Present
                        } else {
                            ProcessPresence::Absent
                        }
                    },
                    || Ok(true),
                    |current| {
                        Ok(
                            json!({"state":"collected","cgroup":current["run_scope"]["cgroup"],"container_payload":{"state":"absent","by":"loop-and-run-label"}}),
                        )
                    },
                    crate::launch::driver_report::fixture_read,
                );
                if live {
                    let error = result.expect_err("live launcher");
                    assert_eq!(error.kind, "launch-busy");
                    assert_eq!(error.detail, "launcher is still alive");
                } else {
                    let output = result.expect("collected recovery");
                    assert_eq!(output["state"], "completed-interrupted-settlement");
                    assert_eq!(output["phase"], "failed");
                    assert_eq!(
                        output["attempt_evidence"]["state"],
                        "absence-confirmed-with-missing-evidence"
                    );
                    let saved = super::read_reservation(&path)
                        .expect("read")
                        .expect("saved");
                    super::reaping::recovery_verdict(&saved).expect("persisted proof");
                    assert_eq!(saved["settlement_uncertain"], false);
                }
            }
        }
    }

    /// The first running row and the driver argument carry the same reserved name.
    /// ´test:unit:dispatch-row-names-the-directory-handed-to-the-driver´
    #[test]
    fn dispatch_row_names_the_directory_handed_to_the_driver() {
        let (fixture, plan, _letter, mut record) = settlement_fixture(false);
        let directory = super::planned_step_dir(&plan, "dispatch").expect("planned directory");
        let argv = super::entry_argv_round(
            Path::new("/fixture/driver"),
            &plan,
            "alpha",
            "R",
            "dispatch",
            3600,
            Some(&directory),
            None,
        )
        .expect("driver arguments");
        super::record_dispatch_letter(
            &mut record,
            3600,
            b"ask",
            false,
            1,
            fixture.path(),
            &directory,
        )
        .expect("running row");
        let supplied = argv
            .windows(2)
            .find(|pair| pair[0] == "-d")
            .expect("explicit directory argument");
        assert_eq!(record["rounds"][0]["driver_dir"], json!(supplied[1]));
        assert!(!directory.exists());
    }

    /// A refused fresh driver report cannot settle the running row's directory.
    /// ´test:unit:fresh-settlement-refuses-driver-report-with-unknown-directory´
    #[test]
    fn fresh_settlement_refuses_driver_report_with_unknown_directory() {
        let (fixture, plan, _letter, mut record) = settlement_fixture(false);
        let directory = super::planned_step_dir(&plan, "dispatch").expect("planned directory");
        super::record_dispatch_letter(
            &mut record,
            3600,
            b"ask",
            false,
            1,
            fixture.path(),
            &directory,
        )
        .expect("running row");
        let path = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&path, &record).expect("publish running row");
        let output =
            "RUN-REPORT lane=dispatch exit=2 wall=0s budget=3600s verdict=FAILED dir=unknown\n";
        let error = super::record_fresh_step_directory(&plan, "R", output)
            .expect_err("fresh refusal cannot settle a directory");
        assert_eq!(
            error.line(),
            "round-record: fresh driver terminal report is not successful"
        );
        assert_eq!(error.status, 2);
        let saved = super::read_reservation(&path)
            .expect("read")
            .expect("record");
        assert_eq!(saved["rounds"][0]["phase"], "running");
        assert_eq!(saved["rounds"][0]["driver_dir"], json!(directory));
    }

    /// ´test:unit:launch-settlement-document-carries-each-recorded-round-end´
    #[test]
    fn launch_settlement_document_carries_each_recorded_round_end() {
        for reason in ["by-report", "by-report-after-stop", "by-budget"] {
            let record =
                json!({"rounds":[{"step":"dispatch","phase":"settled","ended_by":reason}]});
            let ended_by = super::rounds::settled_round_end(&record).expect("recorded end");
            let private =
                json!({"schema":1,"command":"settle-evidence","readback":{},"ended_by":ended_by});
            let settlement =
                super::settlement_document(&private.to_string()).expect("launch settlement object");
            assert_eq!(settlement["ended_by"], reason);
            assert!(settlement.is_object());
        }
        assert_eq!(
            super::settlement_document(r#"{"command":"settle-evidence","readback":{}}"#)
                .expect_err("missing end reason")
                .kind,
            "settle-evidence"
        );
    }

    /// ´test:unit:launch-report-finish-seam-persists-before-returning-value´
    #[test]
    fn launch_report_finish_seam_persists_before_returning_value() {
        let (fixture, plan, _letter, mut record) = settlement_fixture(false);
        record["rounds"] = json!([{"step":"dispatch","phase":"settled","driver_dir":plan.driver_dir.join("20261007T043545Z-dispatch")}]);
        let held: OwnedFd = fs::File::open(fixture.path())
            .expect("held runs root")
            .into();
        let settlement = json!({"ended_by":"by-report","readback":{}});
        let round_dir = super::report::round_dir(&plan, &record, None).expect("recorded directory");
        let report = json!({"schema":1,"command":"launch","dry_run":false,"observe":false,"enforcing":true,"observed":null,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":round_dir,"preparation":"ready","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"RUN-REPORT lane=dispatch","settlement":settlement,"evidence":"driver directory outside home","wall_seconds":1.0});
        let returned = super::report::finish(&held, "R", None, report).expect("launch return");
        let persisted = fs::read(fixture.path().join(".report=R.json"))
            .expect("report is present before return");
        assert_eq!(persisted, returned.to_string().as_bytes());
    }

    /// ´test:unit:resumed-interrupted-settlement-keeps-first-report-readable´
    #[test]
    fn resumed_interrupted_settlement_keeps_first_report_readable() {
        let (fixture, plan, letter, mut record) = settlement_fixture(false);
        let round_dir = plan.driver_dir.join("20261007T043545Z-dispatch");
        record["rounds"] = json!([
            {"step":"dispatch","phase":"settled","driver_dir":round_dir},
            {"step":"review","phase":"settled","driver_dir":round_dir,"ended_by":"by-report"}
        ]);
        record["active_round"] = json!("review");
        record["driver_end"] = json!({"state":"completed"});
        record["helper_end"] = json!({"state":"completed"});
        record["observer_end"] = json!({"state":"not-started","socket":{"state":"not-applicable"}});
        record["observation_end"] = json!("completed");
        record["readback_end"] = json!("completed");
        record["reaping"] =
            json!({"state":"verified-empty","container_payload":{"state":"absent"}});
        let reservation = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&reservation, &record).expect("resumed settlement started");
        let held: OwnedFd = fs::File::open(fixture.path())
            .expect("held runs root")
            .into();
        let first = json!({"schema":1,"command":"launch","dry_run":false,"observe":false,"enforcing":true,"observed":null,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":round_dir,"preparation":"ready","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"first","settlement":{},"evidence":"driver directory outside home","wall_seconds":1.0});
        super::report::publish(&held, "R", None, &first).expect("first report");
        let first_path = fixture.path().join(".report=R.json");
        let first_bytes = fs::read(&first_path).expect("first bytes");
        let completed = super::finish_interrupted_settlement_with(
            &reservation,
            &plan,
            &letter,
            nix::unistd::Uid::effective().as_raw(),
            || Ok(Value::Null),
            || Ok(Value::Null),
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
            crate::launch::driver_report::fixture_read,
        )
        .expect("resumed settlement recovery");
        assert_eq!(completed["phase"], "settled");
        let step = super::interrupted_report_step(&record).expect("last round");
        assert_eq!(step, Some("review"));
        let recovered = json!({"schema":1,"command":"launch","dry_run":false,"interrupted_settlement":completed,"home":plan.home,"driver_dir":plan.driver_dir,"round_dir":round_dir,"wall_seconds":2.0});
        super::report::finish_with_fallback(&held, "R", step, recovered.clone(), &mut |_| {})
            .expect("recovery report under resumed round");
        let owner = nix::unistd::Uid::effective().as_raw();
        assert_eq!(
            super::report::read_bound(&held, "R", None, owner).expect("first readback"),
            first
        );
        assert_eq!(
            super::report::read_bound(&held, "R", Some("review"), owner)
                .expect("recovered round readback"),
            recovered
        );
        assert_eq!(
            fs::read(first_path).expect("first bytes retained"),
            first_bytes
        );
        assert_eq!(
            super::interrupted_report_step(&json!({"rounds":[{"step":"dispatch"}]}))
                .expect("first round"),
            None
        );
    }

    /// ´test:unit:interrupted-settlement-verifies-already-settled-round´
    #[test]
    fn interrupted_settlement_verifies_already_settled_round() {
        for changed in [None, Some(false), Some(true)] {
            let (fixture, plan, letter, mut record) = settlement_fixture(false);
            record["active_round"] = json!("dispatch");
            record["letters"] = json!([]);
            let directory = plan.driver_dir.join("20261007T043545Z-dispatch");
            record["rounds"] =
                json!([{"step":"dispatch","phase":"running","driver_dir":directory}]);
            record["driver_end"] = json!({"state":"completed"});
            record["helper_end"] = json!({"state":"completed"});
            record["observer_end"] =
                json!({"state":"not-started","socket":{"state":"not-applicable"}});
            record["observation_end"] = json!("completed");
            let reservation = super::reservation_path(fixture.path(), "R");
            super::publish_reservation(&reservation, &record).expect("round started");
            fs::create_dir(&directory).expect("step directory");
            fs::write(directory.join("thread-id.txt"), b"thread-1\n").expect("thread");
            fs::write(
                directory.join("events.jsonl"),
                b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n",
            )
            .expect("step thread event");
            fs::write(directory.join(".event-start"), b"0\n").expect("step event boundary");
            let report = format!(
                "RUN-REPORT lane=dispatch exit=0 wall=80s budget=3600s verdict=OK dir={}\n",
                directory.display()
            );
            fs::write(directory.join("run-report.txt"), &report).expect("terminal report");
            super::rounds::record_step_directory(&plan, "R", "dispatch", &report)
                .expect("record step");
            let reply_path = fixture.path().join("reply");
            fs::write(&reply_path, b"good").expect("reply");
            let reply = json!({"path":reply_path,"bytes":4,"sha256":crate::build::sha256_bytes(b"good", fixture.path()).expect("digest"),"worker_uid":3000});
            super::rounds::record_settlement(&plan, "alpha", "R", &reply)
                .expect("round settled before interruption");
            match changed {
                Some(false) => fs::remove_file(&reply_path).expect("missing reply"),
                Some(true) => fs::write(&reply_path, b"changed").expect("changed reply"),
                None => {}
            }
            let completed = super::finish_interrupted_settlement_with(
                &reservation,
                &plan,
                &letter,
                nix::unistd::Uid::effective().as_raw(),
                || Ok(Value::Null),
                || {
                    let bytes = fs::read(&reply_path).map_err(|error| {
                        crate::error::LaneError::input("readback", error.to_string())
                    })?;
                    let actual = json!({"path":reply_path,"bytes":bytes.len(),"sha256":crate::build::sha256_bytes(&bytes, fixture.path())?,"worker_uid":3000});
                    super::rounds::recover_step_directory(&plan, "R")?;
                    super::rounds::record_settlement(&plan, "alpha", "R", &actual)?;
                    Ok(actual)
                },
                |_, _| ProcessPresence::Absent,
                || panic!("complete custody evidence needs no container listing"),
                |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})), crate::launch::driver_report::fixture_read)
            .expect("interrupted settlement finishes");
            let saved = super::read_reservation(&reservation)
                .expect("read")
                .expect("record");
            assert_eq!(saved["rounds"][0]["phase"], "settled");
            assert_eq!(saved["rounds"][0]["reply"], reply);
            assert_eq!(saved["rounds"][0]["driver_dir"], json!(directory));
            if changed.is_none() {
                assert_eq!(completed["phase"], "settled");
                assert_eq!(saved["readback_end"], "completed");
            } else {
                assert_eq!(completed["phase"], "failed");
                assert!(
                    saved["readback_end"]
                        .as_str()
                        .expect("named failure")
                        .contains(if changed == Some(false) {
                            "readback"
                        } else {
                            "round-reply"
                        })
                );
            }
        }
    }

    /// ´test:unit:interrupted-settlement-probes-helper-parent´
    #[test]
    fn interrupted_settlement_probes_helper_parent() {
        let (_fixture, plan, letter, mut record) = settlement_fixture(false);
        record["driver_end"] = json!({"state":"completed"});
        record["helper_end"] = json!({"state":"completed"});
        record["observer_end"] = json!({"state":"not-started","socket":{"state":"not-applicable"}});
        record["observation_end"] = json!("completed");
        record["readback_end"] = json!("completed");
        let error = super::interrupted_settlement_with(
            &record,
            &plan,
            &letter,
            |pid, _| {
                if pid == 325 {
                    ProcessPresence::Present
                } else {
                    ProcessPresence::Absent
                }
            },
            || panic!("parent presence precedes attempt inspection"),
            crate::launch::driver_report::fixture_read,
        )
        .expect_err("live parent refuses settlement");
        assert_eq!(error.kind, "launch-busy");
    }

    /// ´test:unit:interrupted-phase-keeps-letter-placed-after-last-end´
    #[test]
    fn interrupted_phase_keeps_letter_placed_after_last_end() {
        let (fixture, _plan, _letter, mut stale) = settlement_fixture(false);
        let path = super::reservation_path(fixture.path(), "R");
        stale["observer_end"] = json!({"state":"not-started","socket":{"state":"not-applicable"}});
        stale["letters"] = json!([]);
        publish_reservation(&path, &stale).expect("last end update");
        let mut placed = stale.clone();
        placed["letters"] = json!([{"step":"review","name":"review.md","state":"placed","bytes":4,"sha256":"fixture","placed_at_unix_ns":1}]);
        publish_reservation(&path, &placed).expect("placement after last end update");
        let final_record = super::publish_interrupted_phase(
            &path,
            &stale,
            true,
            &json!({"state":"complete"}),
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("locked terminal update");
        assert_eq!(final_record["phase"], "settled");
        assert_eq!(final_record["letters"], placed["letters"]);
        assert_eq!(
            super::read_reservation(&path)
                .expect("read")
                .expect("record")["letters"],
            placed["letters"]
        );
    }

    /// ´test:unit:interrupted-settlement-dry-run-and-same-run-completion´
    #[test]
    fn interrupted_settlement_dry_run_and_same_run_completion() {
        for (prior_verified, payload_absent) in [(true, true), (false, true), (true, false)] {
            let (fixture, plan, letter, mut record) = settlement_fixture(false);
            record["driver_end"] = json!({"state":"completed"});
            record["helper_end"] = json!({"state":"completed","pid":323,"start":90});
            record["observer_end"] =
                json!({"state":"not-started","socket":{"state":"not-applicable"}});
            record["observation_end"] = json!("completed");
            record["readback_end"] = json!("completed");
            if prior_verified {
                record["reaping"] =
                    json!({"state":"verified-empty","container_payload":{"state":"absent"}});
            }
            let reservation = super::reservation_path(fixture.path(), "R");
            super::publish_reservation(&reservation, &record)
                .expect("all ends before terminal write");
            let mut unit_reads = 0;
            let proxy_service = super::proxy_service_for_launch("alpha", false, true, |_| {
                unit_reads += 1;
                Ok(("inactive".into(), String::new()))
            })
            .expect("interrupted settlement does not need the inactive vendor unit");
            assert_eq!(proxy_service["verdict"], "not-applicable");
            assert_eq!(unit_reads, 0);
            let preview = super::interrupted_settlement_with(
                &record,
                &plan,
                &letter,
                |_, _| ProcessPresence::Absent,
                || panic!("complete custody evidence needs no container listing"),
                crate::launch::driver_report::fixture_read,
            )
            .expect("same-run dry run");
            assert_eq!(preview["state"], "would-complete-interrupted-settlement");
            assert_eq!(
                super::read_reservation(&reservation)
                    .expect("read")
                    .expect("record")["phase"],
                "started"
            );
            let completed = super::finish_interrupted_settlement_with(
                &reservation,
                &plan,
                &letter,
                nix::unistd::Uid::effective().as_raw(),
                || Ok(Value::Null),
                || Ok(Value::Null),
                |_, _| ProcessPresence::Absent,
                || panic!("complete custody evidence needs no container listing"),
                |_| {
                    Ok(
                        json!({"state":"collected","container_payload":{"state": if payload_absent { "absent" } else { "present" }}}),
                    )
                },
                crate::launch::driver_report::fixture_read,
            );
            let saved = super::read_reservation(&reservation)
                .expect("read")
                .expect("record");
            assert_eq!(saved["reaping_recovery"]["state"], "collected");
            assert_eq!(saved["reaping"], record["reaping"]);
            assert_eq!(saved["helper_end"], record["helper_end"]);
            if prior_verified && payload_absent {
                assert_eq!(
                    completed.expect("prior measurement settles")["phase"],
                    "settled"
                );
                assert_eq!(saved["phase"], "settled");
            } else {
                assert_eq!(
                    completed.expect_err("missing prior refuses").kind,
                    "run-reaping"
                );
                assert_eq!(saved["phase"], "failed");
            }
        }
    }

    /// ´test:unit:interrupted-settlement-requires-affirmative-driver-and-helper-ends´
    #[test]
    fn interrupted_settlement_requires_affirmative_driver_and_helper_ends() {
        for failed_helper in [false, true] {
            let (fixture, plan, letter, mut record) = settlement_fixture(false);
            if failed_helper {
                record["driver_end"] = json!({"state":"completed"});
                record["helper_end"] =
                    json!({"state":"failed","pid":323,"start":90,"status":"exit status: 1"});
            } else {
                record["helper_end"] = json!({"state":"completed","pid":323,"start":90});
            }
            record["observer_end"] =
                json!({"state":"not-started","socket":{"state":"not-applicable"}});
            record["observation_end"] = json!("completed");
            record["readback_end"] = json!("completed");
            let reservation = super::reservation_path(fixture.path(), "R");
            super::publish_reservation(&reservation, &record).expect("interrupted record");
            let completed = super::finish_interrupted_settlement_with(
                &reservation,
                &plan,
                &letter,
                nix::unistd::Uid::effective().as_raw(),
                || Ok(Value::Null),
                || Ok(Value::Null),
                |_, _| ProcessPresence::Absent,
                || panic!("complete custody needs no listing"),
                |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
                crate::launch::driver_report::fixture_read,
            )
            .expect("failed settlement is recorded");
            assert_eq!(completed["phase"], "failed");
            let saved = super::read_reservation(&reservation)
                .expect("read")
                .expect("reservation");
            assert_eq!(saved["phase"], "failed");
            if !failed_helper {
                assert_eq!(saved["driver_end"]["state"], "absent-on-recovery");
            }
        }
    }

    /// ´test:unit:worker-replacement-cannot-supply-attempt-custody´
    #[test]
    fn worker_replacement_cannot_supply_attempt_custody() {
        let (fixture, plan, letter, record) = settlement_fixture(false);
        let custody = crate::plan::protected_identity_dir(&plan.driver_dir).expect("custody");
        fs::remove_file(custody.join("container-attempt-1.status.json"))
            .expect("remove authoritative attempt");
        fs::write(
            plan.driver_dir.join("container-attempt-1.status.json"),
            b"{\"schema\":1,\"attempt\":1,\"bounded\":true,\"status\":0,\"removal\":{\"state\":\"removed\"}}\n",
        )
        .expect("worker replacement");
        let uncertain = super::interrupted_settlement_with(
            &record,
            &plan,
            &letter,
            |_, _| ProcessPresence::Absent,
            || Ok(false),
            crate::launch::driver_report::fixture_read,
        )
        .expect_err("live container cannot be settled from worker file");
        assert_eq!(uncertain.kind, "settlement-uncertain");
        let preview = super::interrupted_settlement_with(
            &record,
            &plan,
            &letter,
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            crate::launch::driver_report::fixture_read,
        )
        .expect("label scan establishes absence");
        assert_eq!(
            preview["attempt_evidence"]["state"],
            "absence-confirmed-with-missing-evidence"
        );
        assert_eq!(preview["attempt_evidence"]["attempts"], json!([]));
        assert_eq!(
            super::read_reservation(&super::reservation_path(fixture.path(), "R"))
                .expect("read")
                .expect("record")["phase"],
            "started"
        );
    }

    /// ´test:unit:trailing-attempt-start-requires-container-absence´
    #[test]
    fn trailing_attempt_start_requires_container_absence() {
        let (fixture, plan, letter, record) = settlement_fixture(false);
        let custody = crate::plan::protected_identity_dir(&plan.driver_dir).expect("custody");
        let first = custody.join("container-attempt-1.status.json");
        let mut evidence: Value =
            serde_json::from_slice(&fs::read(&first).expect("first status")).expect("status JSON");
        evidence["status"] = json!(1);
        evidence["capacity_evidence"] = json!(true);
        fs::write(&first, serde_json::to_vec(&evidence).expect("status JSON"))
            .expect("retry eligible status");
        let second = custody.join("container-attempt-2.start.json");
        fs::write(&second, b"{\"schema\":1,\"attempt\":2,\"state\":\"started\",\"container_name\":\"superloop-lane-alpha-R-attempt-2\"}\n").expect("second start");
        fs::set_permissions(&second, fs::Permissions::from_mode(0o600)).expect("start mode");
        let calls = std::cell::Cell::new(0);
        let error = super::interrupted_settlement_with(
            &record,
            &plan,
            &letter,
            |_, _| ProcessPresence::Absent,
            || {
                calls.set(calls.get() + 1);
                Ok(false)
            },
            crate::launch::driver_report::fixture_read,
        )
        .expect_err("unknown second container refuses settlement");
        assert_eq!(error.kind, "settlement-uncertain");
        assert_eq!(calls.get(), 1);
        let preview = super::interrupted_settlement_with(
            &record,
            &plan,
            &letter,
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            crate::launch::driver_report::fixture_read,
        )
        .expect("confirmed absence permits failed terminal decision");
        assert_eq!(
            preview["attempt_evidence"]["state"],
            "absence-confirmed-with-missing-evidence"
        );
        let reservation = super::reservation_path(fixture.path(), "R");
        let completed = super::finish_interrupted_settlement_with(
            &reservation,
            &plan,
            &letter,
            nix::unistd::Uid::effective().as_raw(),
            || Ok(Value::Null),
            || Ok(Value::Null),
            |_, _| ProcessPresence::Absent,
            || Ok(true),
            |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
            crate::launch::driver_report::fixture_read,
        )
        .expect("confirmed absence finishes as failed");
        assert_eq!(completed["phase"], "failed");
        let saved = super::read_reservation(&reservation)
            .expect("read")
            .expect("record");
        assert_eq!(saved["settlement_uncertain"], true);
    }

    /// ´test:unit:attempt-error-field-prevents-settlement´
    #[test]
    fn attempt_error_field_prevents_settlement() {
        let (fixture, plan, letter, mut record) = settlement_fixture(false);
        let custody = crate::plan::protected_identity_dir(&plan.driver_dir).expect("custody");
        let path = custody.join("container-attempt-1.status.json");
        let mut evidence: Value =
            serde_json::from_slice(&fs::read(&path).expect("attempt")).expect("attempt JSON");
        evidence["post_start_error"] = json!("container-start: failed");
        fs::write(&path, serde_json::to_vec(&evidence).expect("attempt JSON"))
            .expect("replace attempt");
        record["driver_end"] = json!({"state":"completed"});
        record["helper_end"] = json!({"state":"completed"});
        record["observer_end"] = json!({"state":"not-started","socket":{"state":"not-applicable"}});
        record["observation_end"] = json!("completed");
        record["readback_end"] = json!("completed");
        let reservation = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&reservation, &record).expect("interrupted record");
        let completed = super::finish_interrupted_settlement_with(
            &reservation,
            &plan,
            &letter,
            nix::unistd::Uid::effective().as_raw(),
            || Ok(Value::Null),
            || Ok(Value::Null),
            |_, _| ProcessPresence::Absent,
            || panic!("complete custody needs no listing"),
            |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
            crate::launch::driver_report::fixture_read,
        )
        .expect("failed settlement is recorded");
        assert_eq!(completed["phase"], "failed");
        assert_eq!(
            completed["attempt_evidence"]["attempts"][0]["error_free"],
            false
        );
    }

    /// ´test:unit:observer-socket-removal-failure-records-terminal-disposition´
    #[test]
    fn observer_socket_removal_failure_records_terminal_disposition() {
        let (fixture, plan, letter, record) = settlement_fixture(true);
        let socket = fixture.path().join("vendor/observe-R.sock");
        fs::create_dir(&socket).expect("foreign directory in socket slot");
        let reservation = super::reservation_path(fixture.path(), "R");
        let complete = super::finish_interrupted_settlement_with(
            &reservation,
            &plan,
            &letter,
            nix::unistd::Uid::effective().as_raw(),
            || Ok(Value::Null),
            || Ok(Value::Null),
            |_, _| ProcessPresence::Absent,
            || panic!("complete custody evidence needs no container listing"),
            |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
            crate::launch::driver_report::fixture_read,
        )
        .expect("failed removal is journaled");
        assert_eq!(complete["phase"], "failed");
        let saved = super::read_reservation(&reservation)
            .expect("read")
            .expect("record");
        assert_eq!(saved["observer_end"]["socket"]["state"], "failed");
        assert_eq!(saved["observer_state"], "ended");
        assert_eq!(saved["worker_uid"], record["worker_uid"]);
    }

    /// ´test:unit:retirement-preview-equals-fresh-and-pending-journals´
    #[test]
    fn retirement_preview_equals_fresh_and_pending_journals() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let driver_dir = fixture.path().join("R");
        fs::create_dir(&driver_dir).expect("partial run");
        let home = fixture.path().join("home-R");
        let letter = fixture.path().join("letter");
        let plan = Plan {
            home: home.clone(),
            driver_dir: driver_dir.clone(),
            letter: letter.clone(),
            document: json!({"loop":"alpha","run":"R","worker_uid":3000,"home":home,"driver_dir":driver_dir}),
        };
        let mut old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"old":true},"letter_source":letter,"launcher_pid":u32::MAX,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"not-started"});
        prove_empty_probe_journal(&mut old);
        let reservation = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&reservation, &old).expect("old reservation");
        let preview =
            super::preview_dead_preparation(fixture.path(), &plan, "R", &letter, &[], || Ok(true))
                .expect("fresh preview");
        assert_eq!(preview["probe_absence"]["labelled_containers"], "absent");
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":plan.document,"letter_source":letter,"observer_state":"not-started","reservation_census":{"skipped_count":0,"skipped_names":[]}});
        super::stage_preparation_retirement_with(
            &old,
            &mut next,
            &reservation,
            fixture.path(),
            &driver_dir,
            &home,
            &fixture.path().join(".observed-R.txt"),
            "R",
            false,
            |_, _| ProcessPresence::Absent,
        )
        .expect("fresh journal");
        assert_eq!(preview["retirement_to_journal"], next["current_retirement"]);
        let pending =
            super::preview_dead_preparation(fixture.path(), &plan, "R", &letter, &[], || Ok(true))
                .expect("pending preview");
        assert_eq!(pending["retirement_to_journal"], next["current_retirement"]);
    }

    /// ´test:unit:driver-contract-refuses-old-and-silent-drivers´
    #[test]
    fn driver_contract_refuses_old_and_silent_drivers() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture parent");
        let driver = fixture.path().join("driver");
        for (script, accepted) in [
            ("#!/bin/sh\nprintf 'boxed-runtime 0\\n'\n", false),
            ("#!/bin/sh\nexit 0\n", false),
            ("#!/bin/sh\nprintf 'boxed-runtime 1\\n'\n", true),
        ] {
            crate::fixture_exec::write_executable(&driver, script.as_bytes())
                .expect("closed and synced driver stub");
            let result = driver_runtime_contract(&driver, fixture.path(), &BTreeMap::new());
            assert_eq!(result.is_ok(), accepted, "{script}: {result:?}");
            if !accepted {
                assert_eq!(result.expect_err("old contract").kind, "driver-contract");
            }
        }
    }

    /// ´test:unit:failed-driver-refusal-includes-published-diagnostic´
    #[test]
    fn failed_driver_refusal_includes_published_diagnostic() {
        let lines = crate::build::bounded_diagnostic_lines(
            b"codex-lane: runtime_failure: lane execution failed\ncodex-lane: runtime_failure: spawn /missing/codex: No such file or directory\n",
        );
        assert!(lines.contains("runtime_failure"));
        assert!(lines.contains("spawn /missing/codex: No such file or directory"));
        assert!(lines.len() < 4096);
    }

    /// ´test:unit:failed-observer-reports-its-last-bounded-stderr-line´
    #[test]
    fn failed_observer_reports_its_last_bounded_stderr_line() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut output = vec![b'x'; 8192];
        output.extend_from_slice(b"\nproxy-fail: verified runs root refused\n");
        let tail = bounded_observer_stderr(std::io::Cursor::new(output));
        assert!(tail.len() <= 4096);
        let detail = observer_exit_detail(std::process::ExitStatus::from_raw(1 << 8), &tail);
        assert_eq!(
            detail,
            "observer exited exit status: 1: proxy-fail: verified runs root refused"
        );
    }

    /// ´test:unit:stale-preparation-names-each-differing-run-field´
    #[test]
    fn stale_preparation_names_each_differing_run_field() {
        let old = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":41001,"plan":{"x":1},"letter_source":"/letter-a"});
        let next = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":41002,"plan":{"x":2},"letter_source":"/letter-b"});
        assert_eq!(
            reservation_differences(&old, &next),
            ["worker UID", "plan document", "letter source"]
        );
    }

    /// ´test:unit:dead-preparation-with-new-plan-retires-partials-and-records-old-identity´
    #[test]
    fn dead_preparation_with_new_plan_retires_partials_and_records_old_identity() {
        let fixture = tempfile::tempdir_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let root = fixture.path();
        let run = "R";
        let driver = root.join(run);
        let home = root.join("home-R");
        let identity = root.join(".launch-R");
        let observed = root.join(".observed-R.txt");
        for path in [&driver, &home, &identity] {
            fs::create_dir(path).expect("partial directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("partial mode");
        }
        fs::write(&observed, b"synthetic\n").expect("partial observation");
        let lease = root.join(".prepare-R.lock");
        fs::write(&lease, b"").expect("stable lease");
        let mut old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":run,"worker_uid":3000,"plan":{"socket":"old"},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"not-started"});
        prove_empty_probe_journal(&mut old);
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":run,"worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started"});
        let reservation = reservation_path(root, run);
        publish_reservation(&reservation, &old).expect("old reservation");
        let retired = replace_preparation_with(
            &old,
            &mut next,
            &reservation,
            root,
            &driver,
            &home,
            &observed,
            run,
            |pid, start| {
                assert_eq!((pid, start), (321, 88));
                ProcessPresence::Absent
            },
        )
        .expect("dead preparation is recoverable");
        assert_eq!(retired.len(), 4);
        for path in [&driver, &home, &identity, &observed] {
            assert!(!path.exists(), "old partial retired: {}", path.display());
        }
        assert!(
            lease.exists(),
            "the held advisory lease keeps its stable name"
        );
        let saved = super::read_reservation(&reservation)
            .expect("reservation readable")
            .expect("replacement reservation");
        let recovery = &saved["dead_preparation_retired"];
        assert_eq!(recovery["state"], "retired-dead-preparation");
        assert_eq!(recovery["different_fields"], json!(["plan document"]));
        assert_eq!(recovery["launcher_pid"], 321);
        assert_eq!(recovery["launcher_start"], 88);
        assert_eq!(recovery["old_plan_sha256"].as_str().map(str::len), Some(64));
        assert_eq!(recovery["retired_paths"].as_array().map(Vec::len), Some(4));
    }

    /// ´test:unit:terminal-pre-driver-failure-replaces-partials-without-a-launcher´
    #[test]
    fn terminal_pre_driver_failure_replaces_partials_without_a_launcher() {
        let fixture = tempfile::tempdir_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let root = fixture.path();
        let driver = root.join("R");
        let home = root.join("home-R");
        let identity = root.join(".launch-R");
        for path in [&driver, &home, &identity] {
            fs::create_dir(path).expect("partial directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("protected partial mode");
        }
        fs::write(identity.join("passwd"), b"fixture account\n").expect("passwd");
        fs::write(identity.join("group"), b"fixture group\n").expect("group");
        let lease = root.join(".prepare-R.lock");
        fs::write(&lease, b"").expect("lease");
        let mut old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"old":true},"letter_source":"/synthetic/letter","observer_state":"not-started","helper_spawn_state":"not-started"});
        prove_empty_probe_journal(&mut old);
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"new":true},"letter_source":"/synthetic/letter","observer_state":"not-started","helper_spawn_state":"not-started"});
        let reservation = reservation_path(root, "R");
        publish_reservation(&reservation, &old).expect("preparation reservation");
        record_failed_pre_driver(
            &reservation,
            &mut None,
            &super::LaneError::operation("bound-source", "vendor socket is absent"),
            nix::unistd::Uid::effective().as_raw(),
            false,
        )
        .expect("record failure before launcher identity");
        let old = super::read_reservation(&reservation)
            .expect("read failure")
            .expect("failed reservation");
        assert!(super::terminal_before_launcher(&old));
        assert_eq!(old["helper_end"]["state"], "not-started");
        let retired = replace_preparation_with(
            &old,
            &mut next,
            &reservation,
            root,
            &driver,
            &home,
            &root.join(".observed-R.txt"),
            "R",
            |_, _| panic!("no process identity was recorded"),
        )
        .expect("terminal failure is replaced");
        assert_eq!(retired.len(), 3);
        for path in [&driver, &home, &identity] {
            assert!(!path.exists(), "partial path moved");
        }
        assert!(lease.exists(), "held lease keeps its stable name");
        let saved = super::read_reservation(&reservation)
            .expect("read replacement")
            .expect("replacement reservation");
        assert_eq!(saved["phase"], "preparing");
        assert_eq!(saved["worker_uid"], 3000);
        assert_eq!(
            saved["dead_preparation_retired"]["absence_basis"],
            "recorded-terminal-pre-driver-failure"
        );
        assert_eq!(
            saved["dead_preparation_retired"]["retired_paths"]
                .as_array()
                .map(Vec::len),
            Some(3)
        );
    }

    /// ´test:unit:live-preparing-launcher-refuses-recovery-even-with-a-matching-plan´
    #[test]
    fn live_preparing_launcher_refuses_recovery_even_with_a_matching_plan() {
        let root = tempfile::tempdir().expect("runs root");
        let old = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"not-started"});
        let error =
            recovery_record_with(&old, &old, root.path(), &root.path().join("R"), |_, _| {
                ProcessPresence::Present
            })
            .expect_err("live launcher owns the preparation");
        assert_eq!(error.kind, "launch-busy");
    }

    /// ´test:unit:failed-observer-start-publishes-recoverable-state´
    #[test]
    fn failed_observer_start_publishes_recoverable_state() {
        let root = tempfile::tempdir().expect("runs root");
        let reservation = reservation_path(root.path(), "R");
        let old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"starting","helper_spawn_state":"not-started"});
        publish_reservation(&reservation, &old).expect("starting state");
        record_failed_pre_driver(
            &reservation,
            &mut None,
            &super::LaneError::operation("proxy-start", "observer refused"),
            41001,
            false,
        )
        .expect("terminal failure");
        let saved = super::read_reservation(&reservation)
            .expect("read state")
            .expect("reservation");
        assert_eq!(saved["observer_state"], "failed");
        assert_eq!(saved["phase"], "failed");
        assert!(
            recovery_record_with(
                &saved,
                &saved,
                root.path(),
                &root.path().join("R"),
                |_, _| ProcessPresence::Absent,
            )
            .expect("same-run retry")
            .is_none()
        );
    }

    /// ´test:unit:observer-identity-and-stop-failures-keep-starting-state´
    #[test]
    fn observer_identity_and_stop_failures_keep_starting_state() {
        let root = tempfile::tempdir().expect("runs root");
        let reservation = reservation_path(root.path(), "R");
        let old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"starting"});
        publish_reservation(&reservation, &old).expect("starting reservation");
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .spawn()
            .expect("observer stand-in");
        let mut absence_proved = true;
        let result = identify_started_observer(
            &mut child,
            &mut absence_proved,
            |_| {
                Err(super::LaneError::operation(
                    "proxy-start",
                    "start tick unavailable",
                ))
            },
            |_, _| panic!("identity did not complete"),
            |_| Err(super::LaneError::operation("proxy-stop", "stop failed")),
        );
        drop(child.kill());
        drop(child.wait());
        assert_eq!(result.expect_err("both failures").kind, "proxy-stop");
        assert!(!absence_proved);
        record_failed_pre_driver(
            &reservation,
            &mut None,
            &super::LaneError::operation("proxy-start", "observer stop failed"),
            41001,
            !absence_proved,
        )
        .expect("uncertain start remains pending");
        let saved = super::read_reservation(&reservation)
            .expect("read reservation")
            .expect("saved reservation");
        assert_eq!(saved["observer_state"], "failed");
        assert_eq!(saved["phase"], "failed");
        assert_eq!(saved["settlement_uncertain"], true);
        let error = recovery_record_with(
            &saved,
            &saved,
            root.path(),
            &root.path().join("R"),
            |_, _| ProcessPresence::Absent,
        )
        .expect_err("retry cannot prove that observer died");
        assert_eq!(error.kind, "launch-reservation");
        assert!(error.detail.contains("may have started"));
    }

    /// ´test:unit:unstated-observer-refuses-recovery-after-socket-unlink´
    #[test]
    fn unstated_observer_refuses_recovery_after_socket_unlink() {
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                drop(self.0.kill());
                drop(self.0.wait());
            }
        }
        let root = tempfile::tempdir().expect("runs root");
        let socket =
            crate::fixture_exec::fixture_socket_path(root.path().join("old-observer.sock"));
        let listener = UnixListener::bind(&socket).expect("old observer listener");
        let _client = UnixStream::connect(&socket).expect("accepted client connection");
        let (_accepted, _) = listener.accept().expect("accepted client");
        fs::remove_file(&socket).expect("socket unlinked while observer remains");
        let observer = OwnedChild(
            std::process::Command::new("/usr/bin/sleep")
                .arg("5")
                .spawn()
                .expect("live observer stand-in"),
        );
        assert!(observer.0.id() > 0);
        let old = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88});
        let error =
            recovery_record_with(&old, &old, root.path(), &root.path().join("R"), |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("unstated observer remains uncertain");
        assert_eq!(error.kind, "launch-reservation");
        assert!(error.detail.contains("did not state its observer"));
    }

    /// ´test:unit:dead-launcher-with-live-observer-refuses-changed-plan´
    #[test]
    fn dead_launcher_with_live_observer_refuses_changed_plan() {
        let root = tempfile::tempdir().expect("runs root");
        let old = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"old"},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_pid":654,"observer_start":99,"observer_state":"running"});
        let next = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started"});
        let error = recovery_record_with(
            &old,
            &next,
            root.path(),
            &root.path().join("R"),
            |pid, start| match (pid, start) {
                (321, 88) => ProcessPresence::Absent,
                (654, 99) => ProcessPresence::Present,
                other => panic!("unexpected process {other:?}"),
            },
        )
        .expect_err("live observer retains the old run");
        assert_eq!(error.kind, "launch-busy");
        assert!(error.detail.contains("observer"));
    }

    /// ´test:unit:retirement-record-precedes-renames-and-retry-finishes-it´
    #[test]
    fn retirement_record_precedes_renames_and_retry_finishes_it() {
        let fixture = tempfile::tempdir_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let root = fixture.path();
        let driver = root.join("R");
        let home = root.join("home-R");
        fs::create_dir(&driver).expect("partial driver");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o700)).expect("driver mode");
        fs::create_dir(&home).expect("partial home");
        let observed = root.join(".observed-R.txt");
        let reservation = reservation_path(root, "R");
        let mut old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"old"},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"not-started"});
        prove_empty_probe_journal(&mut old);
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started","helper_spawn_state":"not-started"});
        publish_reservation(&reservation, &old).expect("old reservation");
        stage_preparation_retirement_with(
            &old,
            &mut next,
            &reservation,
            root,
            &driver,
            &home,
            &observed,
            "R",
            false,
            |_, _| ProcessPresence::Absent,
        )
        .expect("durable retirement intent");
        let mut pending = super::read_reservation(&reservation)
            .expect("read intent")
            .expect("pending record");
        prove_empty_probe_journal(&mut pending);
        assert_eq!(pending["current_retirement"]["state"], "retiring");
        let pairs = pending["current_retirement"]["planned_paths"]
            .as_array()
            .expect("planned paths");
        assert_eq!(pairs.len(), 2);
        for pair in pairs {
            assert!(Path::new(pair["source"].as_str().expect("source")).exists());
            assert!(!Path::new(pair["target"].as_str().expect("target")).exists());
        }
        fs::rename(
            pairs[0]["source"].as_str().expect("first source"),
            pairs[0]["target"].as_str().expect("first target"),
        )
        .expect("one rename before the interrupted run stops");
        let retired = replace_preparation_with(
            &pending,
            &mut next,
            &reservation,
            root,
            &driver,
            &home,
            &observed,
            "R",
            |_, _| panic!("already checked"),
        )
        .expect("retry finishes recorded retirement");
        assert_eq!(retired.len(), 2);
        assert!(retired.iter().all(|path| path.exists()));
        assert_eq!(
            super::read_reservation(&reservation)
                .expect("read completion")
                .expect("record")["dead_preparation_retired"]["state"],
            "retired-dead-preparation"
        );
    }

    /// ´test:unit:completed-retirement-survives-another-retry-before-home-creation´
    #[test]
    fn completed_retirement_survives_another_retry_before_home_creation() {
        let fixture = tempfile::tempdir_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let root = fixture.path();
        let driver = root.join("R");
        fs::create_dir(&driver).expect("old partial driver");
        let home = root.join("home-R");
        let observed = root.join(".observed-R.txt");
        let reservation = reservation_path(root, "R");
        let mut old = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"old"},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"not-started","helper_spawn_state":"not-started"});
        prove_empty_probe_journal(&mut old);
        let mut next = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started","helper_spawn_state":"not-started"});
        publish_reservation(&reservation, &old).expect("old reservation");
        replace_preparation_with(
            &old,
            &mut next,
            &reservation,
            root,
            &driver,
            &home,
            &observed,
            "R",
            |_, _| ProcessPresence::Absent,
        )
        .expect("first retirement");
        let mut first = super::read_reservation(&reservation)
            .expect("read")
            .expect("first record");
        prove_empty_probe_journal(&mut first);
        assert_eq!(first["helper_spawn_state"], "not-started", "{first}");
        let first_history = first["dead_preparation_retired"].clone();
        assert_eq!(first_history["different_fields"], json!(["plan document"]));
        let mut repeated = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started","helper_spawn_state":"not-started"});
        replace_preparation_with(
            &first,
            &mut repeated,
            &reservation,
            root,
            &driver,
            &home,
            &observed,
            "R",
            |_, _| panic!("no identity remains"),
        )
        .expect("retry before home creation");
        let saved = super::read_reservation(&reservation)
            .expect("read")
            .expect("retry record");
        assert_eq!(saved["dead_preparation_retired"], first_history);
        assert_eq!(saved["retry_retirements"].as_array().map(Vec::len), Some(1));
    }

    /// ´test:unit:started-reservation-with-a-new-plan-refuses-recovery´
    #[test]
    fn started_reservation_with_a_new_plan_refuses_recovery() {
        let root = tempfile::tempdir().expect("runs root");
        let old = json!({"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"old"},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88});
        let next = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started"});
        let error =
            recovery_record_with(&old, &next, root.path(), &root.path().join("R"), |_, _| {
                ProcessPresence::Absent
            })
            .expect_err("started plan is immutable");
        assert_eq!(error.kind, "launch-reservation");
    }

    /// ´test:unit:dead-preparation-with-attempt-status-refuses-recovery´
    #[test]
    fn dead_preparation_with_attempt_status_refuses_recovery() {
        let root = tempfile::tempdir().expect("runs root");
        let driver = root.path().join("R");
        fs::create_dir(&driver).expect("partial run");
        let custody = crate::plan::protected_identity_dir(&driver).expect("custody path");
        fs::create_dir(&custody).expect("owner custody");
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
        fs::write(custody.join("container-attempt-1.status.json"), b"{}\n")
            .expect("attempt record");
        let old = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"old"},"letter_source":"/synthetic/letter","launcher_pid":321,"launcher_start":88,"observer_state":"not-started"});
        let next = json!({"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{"socket":"new"},"letter_source":"/synthetic/letter","observer_state":"not-started"});
        let error = recovery_record_with(&old, &next, root.path(), &driver, |_, _| {
            ProcessPresence::Absent
        })
        .expect_err("attempt has begun");
        assert_eq!(error.kind, "launch-reservation");
        assert!(error.detail.contains("container attempt"));
    }

    /// ´test:unit:private-image-inspect-carries-podman-namespace-environment´
    #[test]
    fn private_image_inspect_carries_podman_namespace_environment() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let program = fixture.path().join("podman-stand-in");
        let marker = fixture.path().join("namespace-environment");
        let image = format!("sha256:{}", "a".repeat(64));
        fs::write(&program, format!("#!/bin/sh\nprintf '%s %s\\n' \"$_CONTAINERS_USERNS_CONFIGURED\" \"$_CONTAINERS_ROOTLESS_UID\" > '{}'\nprintf '{}\\n'\n", marker.display(), "a".repeat(64))).expect("stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("stand-in mode");
        let environment = private_podman_environment_from(fixture.path(), Some("1"), Some("41001"))
            .expect("configured namespace");
        let observed = crate::build::inspect_image_with_environment(
            &program,
            &image,
            fixture.path(),
            &environment,
        )
        .expect("private image check");
        assert_eq!(observed, image);
        assert_eq!(
            fs::read_to_string(marker).expect("namespace marker"),
            "1 41001\n"
        );
        assert_eq!(
            private_podman_environment_from(Path::new("/home/owner"), None, Some("41001"))
                .expect_err("missing namespace flag")
                .kind,
            "namespace-environment"
        );
    }

    /// ´test:unit:record-hosts-rechecks-replaced-lane-binary-before-private-read´
    #[test]
    fn record_hosts_rechecks_replaced_lane_binary_before_private_read() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let lane_bin = fixture.path().join("lane");
        fs::write(&lane_bin, b"#!/bin/sh\nexit 0\n").expect("lane binary");
        fs::set_permissions(&lane_bin, fs::Permissions::from_mode(0o700))
            .expect("lane binary mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        crate::pinned::owner_executable(&lane_bin, owner).expect("initial invocation");
        fs::remove_file(&lane_bin).expect("remove initial binary");
        symlink("/usr/bin/true", &lane_bin).expect("replace with link");
        let podman = fixture.path().join("container");
        let marker = fixture.path().join("private-read");
        fs::write(
            &podman,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .expect("container stand-in");
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o700))
            .expect("container stand-in mode");
        let request = RecordHostsRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            hosts: Vec::new(),
            reviewed_pool: false,
            dry_run: false,
            list: true,
            podman_bin: podman,
        };
        let verified_home = crate::home::pin_parent_beneath(fixture.path(), fixture.path(), owner)
            .expect("home descriptor");
        let error = read_observation_private(
            fixture.path(),
            &request,
            &lane_bin,
            &BTreeMap::new(),
            &verified_home,
            fixture.path(),
            &verified_home,
        )
        .expect_err("replacement refused before private read");
        assert_eq!(error.kind, "owner-program");
        assert!(!marker.exists());
    }

    /// ´test:unit:record-hosts-refuses-a-lossy-writable-twin-before-private-read´
    #[test]
    fn record_hosts_refuses_a_lossy_writable_twin_before_private_read() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let raw_name = std::ffi::OsString::from_vec(b"trusted-\xff".to_vec());
        let raw_dir = fixture.path().join(&raw_name);
        let twin_dir = fixture.path().join(raw_name.to_string_lossy().as_ref());
        fs::create_dir(&raw_dir).expect("checked directory");
        fs::create_dir(&twin_dir).expect("converted-name twin");
        fs::set_permissions(&raw_dir, fs::Permissions::from_mode(0o700))
            .expect("checked directory mode");
        fs::set_permissions(&twin_dir, fs::Permissions::from_mode(0o777))
            .expect("loop-writable twin mode");
        let lane_bin = raw_dir.join("lane");
        let twin_bin = twin_dir.join("lane");
        for path in [&lane_bin, &twin_bin] {
            fs::write(path, b"#!/bin/sh\nexit 0\n").expect("program");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("program mode");
        }
        assert_ne!(lane_bin, twin_bin);
        assert_eq!(
            std::path::Path::new(lane_bin.to_string_lossy().as_ref()),
            twin_bin
        );
        let owner = nix::unistd::Uid::effective().as_raw();
        crate::pinned::owner_executable(&lane_bin, owner).expect("raw path passes old walk");
        assert_eq!(
            crate::pinned::owner_executable(&twin_bin, owner)
                .expect_err("twin is loop writable")
                .kind,
            "owner-program"
        );
        let podman = fixture.path().join("container");
        let marker = fixture.path().join("private-read");
        fs::write(
            &podman,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .expect("container stand-in");
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o700))
            .expect("container stand-in mode");
        let request = RecordHostsRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            hosts: Vec::new(),
            reviewed_pool: false,
            dry_run: false,
            list: true,
            podman_bin: podman,
        };
        let verified_home = crate::home::pin_parent_beneath(fixture.path(), fixture.path(), owner)
            .expect("home descriptor");
        let error = read_observation_private(
            fixture.path(),
            &request,
            &lane_bin,
            &BTreeMap::new(),
            &verified_home,
            fixture.path(),
            &verified_home,
        )
        .expect_err("converted-name twin cannot run");
        assert_eq!(error.kind, "owner-program");
        assert!(!marker.exists());
    }

    /// ´test:unit:overlapping-launches-of-one-name-refuse-before-container-start´
    #[test]
    fn overlapping_launches_of_one_name_refuse_before_container_start() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected runs root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let first = lock_run_preparation(fixture.path(), "R", owner).expect("first launcher");
        let second = std::thread::scope(|scope| {
            scope
                .spawn(|| lock_run_preparation(fixture.path(), "R", owner))
                .join()
                .expect("second launcher thread")
        });
        assert_eq!(
            second.expect_err("same-name overlap refuses").kind,
            "launch-busy"
        );
        drop(first);
        let lease = fixture.path().join(".prepare-R.lock");
        assert!(
            lease.is_file(),
            "an advisory lease may remain after refusal"
        );
        lock_run_preparation(fixture.path(), "R", owner).expect("retry after first launcher exits");
    }

    /// ´test:unit:helper-parent-exit-and-inner-helper-identities-stay-distinct´
    #[test]
    fn helper_parent_exit_and_inner_helper_identities_stay_distinct() {
        let mut parent = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .spawn()
            .expect("parent fixture");
        let mut helper = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .spawn()
            .expect("inner helper fixture");
        let parent_start =
            crate::container_helper::process_start(parent.id()).expect("parent tick");
        let helper_start =
            crate::container_helper::process_start(helper.id()).expect("helper tick");
        parent.kill().expect("stop parent");
        let status = parent.wait().expect("parent status");
        let record = json!({"helper_pid":helper.id(),"helper_start":helper_start,"helper_parent_pid":parent.id(),"helper_parent_start":parent_start,"helper_end":helper_parent_end(parent.id(),parent_start,status,None)});
        assert_ne!(record["helper_pid"], record["helper_parent_pid"]);
        assert_eq!(
            record["helper_end"]["parent_pid"],
            record["helper_parent_pid"]
        );
        assert_eq!(
            record["helper_end"]["parent_start"],
            record["helper_parent_start"]
        );
        assert_eq!(
            record["helper_start"],
            crate::container_helper::process_start(helper.id()).expect("same helper tick")
        );
        helper.kill().expect("stop helper");
        helper.wait().expect("helper status");
    }

    /// ´test:unit:observer-stop-distinguishes-prior-exit-from-requested-signal´
    #[test]
    fn observer_stop_distinguishes_prior_exit_from_requested_signal() {
        let mut exited = std::process::Command::new("/usr/bin/false")
            .process_group(0)
            .spawn()
            .expect("exited observer");
        exited.wait().expect("prior status");
        let prior = stop_observer(&mut exited).expect("prior exit record");
        assert_eq!(prior["state"], "failed-before-stop");
        assert_eq!(prior["already_exited"], true);
        assert_eq!(prior["stop_signals"], json!([]));
        let mut running = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .process_group(0)
            .spawn()
            .expect("running observer");
        let stopped = stop_observer(&mut running).expect("requested stop");
        assert_eq!(stopped["state"], "stopped");
        assert_eq!(stopped["already_exited"], false);
        assert_eq!(stopped["stop_signals"], json!(["SIGTERM"]));
        assert!(stopped["status"].is_string());
    }

    /// ´test:unit:observer-stop-checks-live-group-after-parent-exit´
    #[test]
    fn observer_stop_checks_live_group_after_parent_exit() {
        let mut parent = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 5 & exit 0"])
            .process_group(0)
            .spawn()
            .expect("observer parent");
        parent.wait().expect("parent exits before stop");
        let end = stop_observer(&mut parent).expect("group disposition");
        assert_eq!(end["already_exited"], true);
        assert_eq!(end["stop_signals"][0], "SIGTERM");
        assert_ne!(end["state"], "stopped");
    }

    /// ´test:unit:killed-ready-helper-sockets-are-retired-for-the-same-run´
    #[test]
    fn killed_ready_helper_sockets_are_retired_for_the_same_run() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected runs root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let driver = fixture.path().join("R");
        let socket = crate::container_helper::socket_path(&driver).expect("request socket");
        let control =
            crate::container_helper::control_socket_path(&driver).expect("control socket");
        let _request_listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("ready request");
        let _control_listener =
            std::os::unix::net::UnixListener::bind(&control).expect("ready control");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).expect("request mode");
        fs::set_permissions(&control, fs::Permissions::from_mode(0o600)).expect("control mode");
        let mut helper = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .spawn()
            .expect("helper stand-in");
        let record = json!({"helper_pid":helper.id(),"helper_start":crate::container_helper::process_start(helper.id()).expect("helper start")});
        let _lock = lock_runs_root(fixture.path(), true, owner).expect("protected run lock");
        assert_eq!(
            retire_dead_helper_sockets(&driver, &record, owner)
                .expect_err("live helper retains sockets")
                .kind,
            "launch-busy"
        );
        helper.kill().expect("kill ready helper");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while crate::container_helper::process_alive(
            helper.id(),
            record["helper_start"].as_u64().expect("recorded start"),
        ) && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let retired = retire_dead_helper_sockets(&driver, &record, owner)
            .expect("dead helper residue retired");
        assert_eq!(retired.len(), 2);
        assert!(!socket.exists() && !control.exists());
        assert_eq!(
            retire_dead_helper_sockets(&driver, &record, owner).expect("unchanged retry"),
            Vec::<std::path::PathBuf>::new()
        );
        helper.wait().expect("reap stand-in");
    }

    /// ´test:unit:unreadable-live-helper-record-preserves-both-sockets´
    #[test]
    fn unreadable_live_helper_record_preserves_both_sockets() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected runs root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let driver = fixture.path().join("R");
        let socket = crate::container_helper::socket_path(&driver).expect("request socket");
        let control =
            crate::container_helper::control_socket_path(&driver).expect("control socket");
        let _request_listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("ready request");
        let _control_listener =
            std::os::unix::net::UnixListener::bind(&control).expect("ready control");
        let pid = std::process::id();
        let start = crate::container_helper::process_start(pid).expect("live helper start");
        assert!(crate::container_helper::process_alive(pid, start));
        let record = json!({"helper_pid":pid,"helper_start":start});
        let _lock = lock_runs_root(fixture.path(), true, owner).expect("protected run lock");
        let error = retire_dead_helper_sockets_with(&driver, &record, owner, |pid, start| {
            crate::container_helper::process_presence_with(pid, start, |_| {
                Err(crate::error::LaneError::input(
                    "helper-session",
                    "injected process-record read error",
                ))
            })
        })
        .expect_err("unknown helper liveness refuses retirement");
        assert_eq!(error.kind, "helper-socket");
        assert!(socket.exists() && control.exists());
    }

    /// ´test:unit:runtime-file-creation-stays-on-pinned-directory-after-link-swap´
    #[test]
    fn runtime_file_creation_stays_on_pinned_directory_after_link_swap() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        let owner = nix::unistd::Uid::effective().as_raw();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("runs root mode");
        let driver = fixture.path().join("R");
        let runtime = driver.join("launch");
        let outside = fixture.path().join("outside");
        fs::create_dir(&driver).expect("driver directory");
        fs::create_dir(&runtime).expect("runtime directory");
        fs::create_dir(&outside).expect("outside directory");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o700)).expect("driver mode");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("runtime mode");
        let (_root, pinned) =
            pin_runtime_dir(&driver, owner, owner).expect("pinned runtime directory");
        let retired = driver.join("retired-launch");
        fs::rename(&runtime, &retired).expect("move pinned directory");
        symlink(&outside, &runtime).expect("replace with link");
        let mut file = create_runtime_file(&pinned, "runtime.argv", 0o600).expect("pinned file");
        file.write_all(b"pinned\n").expect("write pinned file");
        assert_eq!(
            fs::read(retired.join("runtime.argv")).expect("pinned bytes"),
            b"pinned\n"
        );
        assert!(!outside.join("runtime.argv").exists());
    }

    /// ´test:unit:launch-refuses-argument-repetition-and-keeps-one-letter´
    #[test]
    fn launch_refuses_argument_repetition_and_keeps_one_letter() {
        let args = [
            "alpha",
            "R",
            "--letter",
            "/fixture/letter",
            "--observe",
            "--dry-run",
        ]
        .map(String::from);
        let parsed = LaunchRequest::parse(&args).expect("launch form");
        assert!(parsed.observe && parsed.dry_run);
        assert_eq!(parsed.door_scope, crate::door::Scope::Review);
        assert_eq!(parsed.letter.to_string_lossy(), "/fixture/letter");
        let review = [
            "alpha",
            "R",
            "--letter",
            "/fixture/letter",
            "--door-scope",
            "review",
        ]
        .map(String::from);
        assert_eq!(
            LaunchRequest::parse(&review)
                .expect("review form")
                .door_scope,
            crate::door::Scope::Review
        );
        let invalid = [
            "alpha",
            "R",
            "--letter",
            "/fixture/letter",
            "--door-scope",
            "all",
        ]
        .map(String::from);
        assert_eq!(
            LaunchRequest::parse(&invalid)
                .expect_err("scope refusal")
                .kind,
            "door-scope"
        );
        let repeated = [
            "alpha",
            "R",
            "--letter",
            "/fixture/letter",
            "--letter",
            "/fixture/other",
        ]
        .map(String::from);
        assert_eq!(
            LaunchRequest::parse(&repeated).expect_err("repeat").status,
            2
        );
    }

    /// ´test:unit:uid-table-skips-driver-runs-and-refuses-malformed-reservations´
    #[test]
    fn uid_table_skips_driver_runs_and_refuses_malformed_reservations() {
        let root = tempfile::tempdir().expect("runs root");
        let driver_run = "20260101T000000Z-driver-run";
        fs::create_dir(root.path().join(driver_run)).expect("driver run directory");
        assert_eq!(
            select_free_uid(root.path(), "R1", 3000, 3).expect("first"),
            3000
        );
        let prior = root.path().join("R1");
        fs::create_dir(&prior).expect("prior run");
        publish_reservation(&reservation_path(root.path(), "R1"), &json!({"schema":1,"phase":"started","loop":"alpha","run":"R1","worker_uid":3000,"plan":{}})).expect("reservation");
        assert_eq!(
            select_free_uid(root.path(), "R2", 3000, 3).expect("second"),
            3001
        );
        assert_eq!(
            super::select_free_uid_with_census(root.path(), "R2", 3000, 3)
                .expect("driver run skipped"),
            (3001, vec![driver_run.to_owned()])
        );
        assert_eq!(
            select_free_uid(root.path(), "R1", 3000, 3)
                .expect_err("repeat")
                .status,
            2
        );
        fs::remove_file(reservation_path(root.path(), "R1")).expect("retire reservation");
        fs::write(reservation_path(root.path(), "R1"), b"not JSON").expect("malformed reservation");
        fs::set_permissions(
            reservation_path(root.path(), "R1"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private malformed reservation");
        assert_eq!(
            select_free_uid(root.path(), "R2", 3000, 3)
                .expect_err("malformed protected reservation refuses")
                .kind,
            "launch-reservation"
        );
    }

    /// ´test:unit:observation-requires-the-reservations-loop-even-with-a-shared-root´
    #[test]
    fn observation_requires_the_reservations_loop_even_with_a_shared_root() {
        let root = tempfile::tempdir().expect("shared runs root");
        publish_reservation(&reservation_path(root.path(), "R"), &json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":{}})).expect("alpha reservation");
        assert!(observation_reservation(root.path(), "alpha", "R").is_ok());
        let refusal = observation_reservation(root.path(), "beta", "R")
            .expect_err("beta cannot select alpha's observation");
        assert_eq!(refusal.kind, "host-observation");
    }

    /// ´test:unit:protected-launch-residue-refuses-an-unreserved-run-name´
    #[test]
    fn protected_launch_residue_refuses_an_unreserved_run_name() {
        let root = tempfile::tempdir().expect("runs root");
        let identity = root.path().join(".launch-R");
        fs::create_dir(&identity).expect("identity directory");
        let refusal = select_free_uid(root.path(), "R", 3000, 2).expect_err("protected residue");
        assert_eq!(refusal.kind, "already-exists");
        fs::remove_dir(&identity).expect("remove identity directory");
        fs::write(root.path().join(".container-R-attempt-1.id"), b"id\n").expect("identifier file");
        let refusal = select_free_uid(root.path(), "R", 3000, 2).expect_err("identifier residue");
        assert_eq!(refusal.kind, "already-exists");
    }

    /// ´test:unit:pending-run-reservation-survives-each-creation-boundary´
    #[test]
    fn pending_run_reservation_survives_each_creation_boundary() {
        let fixture = tempfile::tempdir().expect("runs root");
        let root = fixture.path();
        let reservation = reservation_path(root, "R");
        publish_reservation(&reservation, &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":{}})).expect("durable reservation before paths");
        assert_eq!(
            select_free_uid(root, "R", 3000, 2).expect("retry before home"),
            3000
        );
        let run = root.join("R");
        fs::create_dir(&run).expect("partial driver directory");
        fs::write(run.join("partial"), "kept on retirement\n").expect("partial evidence");
        assert_eq!(
            select_free_uid(root, "R", 3000, 2).expect("retry before plan"),
            3000
        );
        assert_eq!(
            select_free_uid(root, "other", 3000, 2).expect("other run proceeds"),
            3001
        );
        let retired = retire_partial(&run, "R").expect("retire").expect("path");
        assert_eq!(
            fs::read_to_string(retired.join("partial")).expect("kept"),
            "kept on retirement\n"
        );
        assert_eq!(
            select_free_uid(root, "R", 3000, 2).expect("retry after retirement"),
            3000
        );
        publish_reservation(&reservation, &json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":{}})).expect("started");
        assert_eq!(
            select_free_uid(root, "R", 3000, 2)
                .expect_err("same run started")
                .kind,
            "already-exists"
        );
    }

    /// ´test:unit:observed-host-record-needs-one-run-marker-and-only-host-ports´
    #[test]
    fn observed_host_record_needs_one_run_marker_and_only_host_ports() {
        let path = std::path::Path::new("/fixture/observed-hosts.txt");
        let hosts = parse_observation("mode=observing run=R enforcing=false\napi.example.com:443 connected=1\nauth.example.com:443 connected=0\n", "R", path).expect("observed hosts");
        assert_eq!(hosts.get("api.example.com"), Some(&true));
        assert_eq!(hosts.get("auth.example.com"), Some(&false));
        assert_eq!(
            parse_observation(
                "mode=enforcing run=R enforcing=true\napi.example.com:443 connected=1\n",
                "R",
                path
            )
            .expect_err("enforced")
            .status,
            2
        );
        assert_eq!(
            parse_observation(
                "mode=observing run=other enforcing=false\napi.example.com:443 connected=1\n",
                "R",
                path
            )
            .expect_err("other run")
            .status,
            2
        );
        assert_eq!(
            parse_observation(
                "mode=observing run=R enforcing=false\napi.example.com:8443 connected=1\n",
                "R",
                path
            )
            .expect_err("other port")
            .status,
            2
        );
        let args = ["alpha", "R", "--host", "api.example.com"].map(String::from);
        assert_eq!(
            RecordHostsRequest::parse(&args).expect("selection").hosts,
            ["api.example.com"]
        );
        let pool = [
            "alpha",
            "R",
            "--host",
            "api.example.com",
            "--host",
            "api.eu.example.com",
            "--reviewed-pool",
        ]
        .map(String::from);
        assert!(
            RecordHostsRequest::parse(&pool)
                .expect("reviewed pool")
                .reviewed_pool
        );
        let listed = RecordHostsRequest::parse(&["alpha", "R", "--list"].map(String::from))
            .expect("list only");
        assert!(listed.list && listed.hosts.is_empty());
        let mut many = String::from("mode=observing run=R enforcing=false\n");
        for index in 0..129 {
            writeln!(&mut many, "host{index}.example.com:443 connected=1").expect("host line");
        }
        assert_eq!(
            parse_observation(&many, "R", path)
                .expect_err("reader shares writer's host bound")
                .kind,
            "host-observation"
        );
    }

    /// ´test:unit:readback-evidence-refuses-an-empty-or-linked-reply´
    #[test]
    fn readback_evidence_refuses_an_empty_or_linked_reply() {
        let fixture = tempfile::tempdir().expect("reply fixture");
        let path = fixture.path().join("dispatch.md");
        let uid = nix::unistd::Uid::effective().as_raw();
        assert_eq!(
            inspect_readback(&path, uid)
                .expect_err("absent reply")
                .status,
            2
        );
        fs::write(&path, b"").expect("empty reply");
        assert_eq!(
            inspect_readback(&path, uid)
                .expect_err("empty reply")
                .status,
            2
        );
        fs::write(&path, b"Read back the first letter.\n").expect("reply");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("reply mode");
        let report = inspect_readback(&path, uid).expect("reply evidence");
        assert_eq!(report["bytes"], 28);
        assert_eq!(report["sha256"].as_str().expect("digest").len(), 64);
        let link = fixture.path().join("linked.md");
        std::os::unix::fs::symlink(&path, &link).expect("linked reply");
        assert_eq!(
            inspect_readback(&link, uid)
                .expect_err("linked reply")
                .status,
            2
        );
    }

    /// ´test:unit:readback-evidence-accepts-0600-and-refuses-0660´
    #[test]
    fn readback_evidence_accepts_0600_and_refuses_0660() {
        let fixture = tempfile::tempdir().expect("reply fixture");
        let path = fixture.path().join("dispatch.md");
        let uid = nix::unistd::Uid::effective().as_raw();
        fs::write(&path, b"Read back the first letter.\n").expect("reply");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private reply");
        assert_eq!(
            inspect_readback(&path, uid).expect("private reply evidence")["bytes"],
            28
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))
            .expect("group-writable reply");
        let refusal = inspect_readback(&path, uid).expect_err("group-writable reply refused");
        assert_eq!(refusal.kind, "readback");
        assert!(refusal.detail.contains("without group or other write"));
    }

    /// ´test:unit:door-registration-uses-two-worker-uids-and-names-every-refusal´
    #[test]
    fn door_registration_uses_two_worker_uids_and_names_every_refusal() {
        use std::os::fd::OwnedFd;
        let row = json!({"name":"alpha","uid":41001});
        let owner = nix::unistd::Uid::effective().as_raw();
        let block = (3000, 2);
        let fixture = tempfile::tempdir_in("/tmp").expect("reservation fixture");
        let root = fixture.path();
        let runs: OwnedFd = fs::File::open(root).expect("held runs").into();
        let record = |run: &str, uid: u32, phase: &str, scope: Option<&str>, loop_name: &str| {
            let mut value = json!({"schema":1,"phase":phase,"loop":loop_name,
                "run":run,"worker_uid":uid,"plan":{}});
            if let Some(scope) = scope {
                value["door_scope"] = json!(scope);
            }
            value
        };
        let refusal = super::door_registration(&runs, &row, "alpha", 4000, block, owner)
            .expect_err("outside block");
        assert_eq!(refusal.kind, "door-peer");
        assert_eq!(refusal.detail, "peer is outside the allocated block");
        super::publish_reservation(
            &super::reservation_path(root, "R"),
            &record("R", 3000, "settled", Some("work"), "alpha"),
        )
        .expect("settled reservation");
        let refusal = super::door_registration(&runs, &row, "alpha", 3000, block, owner)
            .expect_err("no live run");
        assert_eq!(refusal.kind, "door-peer");
        assert_eq!(refusal.detail, "peer has no live registered run");
        assert_eq!(
            super::door_probe_registration(&runs, &row, "alpha", "R", 3000, block, owner)
                .expect("settled shape probe")
                .mirror_ref,
            "refs/heads/lane/R"
        );
        fs::remove_file(super::reservation_path(root, "R")).expect("fixture reset");
        super::publish_reservation(
            &super::reservation_path(root, "R"),
            &record("R", 3000, "started", None, "alpha"),
        )
        .expect("absent scope");
        let refusal = super::door_registration(&runs, &row, "alpha", 3000, block, owner)
            .expect_err("absent scope");
        assert_eq!(refusal.kind, "door-registration");
        assert_eq!(refusal.detail, "external scope is absent");
        fs::remove_file(super::reservation_path(root, "R")).expect("fixture reset");
        super::publish_reservation(
            &super::reservation_path(root, "R"),
            &record("R", 3000, "started", Some("work"), "beta"),
        )
        .expect("differing identity");
        let refusal = super::door_registration(&runs, &row, "alpha", 3000, block, owner)
            .expect_err("differing identity");
        assert_eq!(refusal.kind, "door-registration");
        assert_eq!(refusal.detail, "reservation identity differs");
        fs::remove_file(super::reservation_path(root, "R")).expect("fixture reset");
        super::publish_reservation(
            &super::reservation_path(root, "R"),
            &record("R", 3000, "started", Some("work"), "alpha"),
        )
        .expect("work reservation");
        super::publish_reservation(
            &super::reservation_path(root, "S"),
            &record("S", 3001, "started", Some("review"), "alpha"),
        )
        .expect("review reservation");
        assert_eq!(
            super::door_registration(&runs, &row, "alpha", 3001, block, owner)
                .expect("review grant")
                .scope,
            crate::door::Scope::Review
        );
        assert_eq!(
            super::door_registration(&runs, &row, "alpha", 3000, block, owner)
                .expect("work grant")
                .scope,
            crate::door::Scope::Work
        );
        fs::remove_file(super::reservation_path(root, "S")).expect("fixture reset");
        super::publish_reservation(
            &super::reservation_path(root, "T"),
            &record("T", 3000, "started", Some("work"), "alpha"),
        )
        .expect("duplicate uid");
        let refusal = super::door_registration(&runs, &row, "alpha", 3000, block, owner)
            .expect_err("two live runs");
        assert_eq!(refusal.kind, "door-registration");
        assert_eq!(refusal.detail, "peer has two live runs");
    }
}
