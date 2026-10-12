//! Install the pinned door input and service alongside the vendor generation.

#[cfg(test)]
use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, SFlag, fstat, fstatat, mkdirat};
use nix::unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat};
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::{build, home, install, pinned, settings::Settings};

const FILE_LIMIT: usize = 64 * 1024 * 1024;
#[cfg(test)]
thread_local! {
    static BEFORE_OLD_STUB_OPEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    static CHANGE_METADATA_AFTER_SET: Cell<bool> = const { Cell::new(false) };
    static FAIL_GENERATION_WRITE: Cell<bool> = const { Cell::new(false) };
}
const PRIVATE_REFUSAL_KINDS: &[&str] = &[
    "bad-setting",
    "build-snapshot",
    "context-threshold",
    "hash-pin",
    "home-owner",
    "inode-owner",
    "install-door-conflict",
    "install-door-destination",
    "install-door-mkdir",
    "install-door-mode",
    "install-door-owner",
    "install-door-path",
    "install-door-private",
    "install-door-replace",
    "install-door-row",
    "install-door-setting",
    "install-door-source",
    "install-door-sync",
    "install-door-template",
    "install-door-verify",
    "install-door-write",
    "owner-program",
    "protected-file",
    "protected-path",
    "registry-row",
    "retention-policy",
    "settings-grant",
    "settings-kind",
    "settings-owner",
    "settings-read",
    "settings-toml",
    "settings-utf8",
    "sha256sum",
    "unsafe-path",
];

/// Inputs passed to the owner namespace after the host pins the configuration.
#[derive(Debug)]
pub struct PrivateDoorRequest {
    pub loop_name: String,
    pub owner_home: PathBuf,
    pub stub: PathBuf,
    pub row_uid: u32,
    pub stub_sha256: String,
    pub old_stub_sha256: Option<String>,
    pub apply: bool,
    pub dry_run: bool,
}

impl PrivateDoorRequest {
    /// Parse the closed private command form.
    ///
    /// # Errors
    ///
    /// Refuses a missing field, changed mode or invalid digest.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [
            loop_name,
            owner_home,
            stub,
            row_uid,
            digest,
            old_digest,
            mode,
            home_flag,
            home_index,
            lock_flag,
            lock_index,
            source_flag,
            source_index,
            template_flag,
            template_index,
            libexec_flag,
            libexec_index,
            sockets_flag,
            sockets_index,
        ] = args
        else {
            return Err(LaneError::input(
                "install-door-private",
                "private form is incomplete",
            ));
        };
        if home_flag != "--verified-home-fd"
            || home_index != "0"
            || lock_flag != "--verified-install-lock-fd"
            || lock_index != "1"
            || source_flag != "--verified-stub-fd"
            || source_index != "2"
            || template_flag != "--verified-template-fd"
            || template_index != "3"
            || libexec_flag != "--verified-libexec-fd"
            || libexec_index != "4"
            || sockets_flag != "--verified-socket-root-fd"
            || sockets_index != "5"
        {
            return Err(LaneError::input(
                "install-door-private",
                "verified descriptors are absent",
            ));
        }
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("install-door-private", error.message()))?;
        let row_uid = row_uid
            .parse::<u32>()
            .map_err(|_| LaneError::input("install-door-private", "row uid is invalid"))?;
        let valid_digest = |word: &str| {
            word.len() == 64
                && word
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        };
        if !valid_digest(digest) || (old_digest != "-" && !valid_digest(old_digest)) {
            return Err(LaneError::input(
                "install-door-private",
                "stub digest is invalid",
            ));
        }
        let (apply, dry_run) = match mode.as_str() {
            "dry-run" => (false, true),
            "preview" => (false, false),
            "apply" => (true, false),
            _ => {
                return Err(LaneError::input(
                    "install-door-private",
                    "private mode is invalid",
                ));
            }
        };
        Ok(Self {
            loop_name: loop_name.clone(),
            owner_home: PathBuf::from(owner_home),
            stub: PathBuf::from(stub),
            row_uid,
            stub_sha256: digest.clone(),
            old_stub_sha256: (old_digest != "-").then(|| old_digest.clone()),
            apply,
            dry_run,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn private_stage(
    owner_home: &Path,
    template: &Path,
    sockets: &Path,
    libexec_fd: &OwnedFd,
    sockets_fd: &OwnedFd,
    owner: u32,
    group: u32,
    stub_bytes: &[u8],
    old_digest: Option<&str>,
    apply: bool,
    fixture_view: Option<(u32, u32)>,
) -> Result<Value, LaneError> {
    let libexec = template.join("libexec");
    let stat = fstat(libexec_fd)
        .map_err(|error| LaneError::input("install-door-template", error.to_string()))?;
    let (actual_owner, actual_group) = fixture_view.unwrap_or((stat.st_uid, stat.st_gid));
    if !libexec_matches(stat.st_mode, actual_owner, actual_group, owner, group) {
        return Err(LaneError::input(
            "install-door-template",
            "template libexec differs",
        ));
    }
    let door_path = sockets.join("door");
    let dir_exists = inspect_directory_beneath(sockets_fd, &door_path, owner, group, 0o750)?;
    let stub_path = libexec.join("ssh");
    let stub_exists = if let Some(old_digest) = old_digest {
        let installed = read_checked_beneath(libexec_fd, &stub_path, (owner, group, 0o550))?;
        let installed_digest = build::sha256_bytes(&installed, owner_home)?;
        let new_digest = build::sha256_bytes(stub_bytes, owner_home)?;
        if installed_digest != old_digest && installed_digest != new_digest {
            return Err(LaneError::input(
                "install-door-conflict",
                "old program differs from its generation",
            ));
        }
        installed == stub_bytes
    } else {
        inspect_file_beneath(libexec_fd, &stub_path, (owner, group, 0o550), stub_bytes)?
    };
    if apply {
        if !dir_exists {
            create_directory_beneath(sockets_fd, &door_path, owner, group, 0o750)?;
        }
        if !stub_exists {
            let destination = Destination {
                path: stub_path,
                bytes: stub_bytes.to_vec(),
                uid: owner,
                gid: group,
                mode: 0o550,
                exists: false,
            };
            set_directory_metadata(libexec_fd, owner, group, 0o750)?;
            let outcome = if old_digest.is_some() {
                replace_file_beneath(libexec_fd, &destination)
            } else {
                write_file_beneath(libexec_fd, &destination)
            };
            let restore = set_directory_metadata(libexec_fd, owner, group, 0o550);
            outcome?;
            restore?;
        }
    }
    Ok(json!({"schema":1,"dir_exists":dir_exists,"stub_exists":stub_exists}))
}

fn libexec_matches(mode: u32, uid: u32, gid: u32, owner: u32, group: u32) -> bool {
    SFlag::from_bits_truncate(mode) & SFlag::S_IFMT == SFlag::S_IFDIR
        && (uid, gid, mode & 0o7777) == (owner, group, 0o550)
}

fn pin_directory_beneath(
    home_fd: &impl AsFd,
    owner_home: &Path,
    path: &Path,
    owner: u32,
) -> Result<OwnedFd, LaneError> {
    let relative = path.strip_prefix(owner_home).map_err(|_| {
        LaneError::input(
            "install-door-path",
            "directory is outside handed owner home",
        )
    })?;
    if relative.as_os_str().is_empty() {
        return Err(LaneError::input(
            "install-door-path",
            "directory is the handed owner home",
        ));
    }
    let mut fd = nix::unistd::dup(home_fd)
        .map_err(|error| LaneError::input("install-door-path", error.to_string()))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LaneError::input(
                "install-door-path",
                "dotted directory component",
            ));
        };
        let parent =
            fstat(&fd).map_err(|error| LaneError::input("install-door-path", error.to_string()))?;
        if parent.st_uid != owner || parent.st_mode & 0o022 != 0 {
            return Err(LaneError::input(
                "install-door-path",
                "directory parent differs from handed owner",
            ));
        }
        fd = openat2(
            &fd,
            Path::new(name),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| LaneError::input("install-door-path", error.to_string()))?;
        let stat =
            fstat(&fd).map_err(|error| LaneError::input("install-door-path", error.to_string()))?;
        if stat.st_uid != owner || stat.st_mode & 0o022 != 0 {
            return Err(LaneError::input(
                "install-door-path",
                "directory differs from handed owner",
            ));
        }
    }
    Ok(fd)
}

fn compare_handed_directory(
    home_fd: &impl AsFd,
    owner_home: &Path,
    path: &Path,
    handed: &impl AsFd,
    owner: u32,
) -> Result<(), LaneError> {
    let reopened = pin_directory_beneath(home_fd, owner_home, path, owner)?;
    let actual = fstat(&reopened)
        .map_err(|error| LaneError::input("install-door-path", error.to_string()))?;
    let recorded =
        fstat(handed).map_err(|error| LaneError::input("install-door-path", error.to_string()))?;
    if (actual.st_dev, actual.st_ino) != (recorded.st_dev, recorded.st_ino) {
        return Err(LaneError::input(
            "install-door-path",
            "handed directory identity differs",
        ));
    }
    Ok(())
}

/// Enter template and socket work through the six descriptors pinned on the host.
///
/// # Errors
///
/// Refuses a non-root namespace identity, malformed arguments or a changed handed descriptor.
pub fn run_private_entry(args: &[String], stream: &impl AsFd) -> Result<Value, LaneError> {
    let request = PrivateDoorRequest::parse(args)?;
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "install-door-private",
            "rootless namespace root is required",
        ));
    }
    run_private_entry_handed(&request, stream, 0, None)
}

#[cfg(test)]
fn run_private_entry_fixture(
    args: &[String],
    stream: &impl AsFd,
    namespace_owner: u32,
    fixture_view: (u32, u32),
) -> Result<Value, LaneError> {
    let request = PrivateDoorRequest::parse(args)?;
    if Uid::effective().as_raw() != namespace_owner {
        return Err(LaneError::input(
            "install-door-private",
            "rootless namespace root is required",
        ));
    }
    run_private_entry_handed(&request, stream, namespace_owner, Some(fixture_view))
}

fn run_private_entry_handed(
    request: &PrivateDoorRequest,
    stream: &impl AsFd,
    namespace_owner: u32,
    fixture_view: Option<(u32, u32)>,
) -> Result<Value, LaneError> {
    let mut transferred = home::receive_private_descriptors(stream, 6)?;
    let sockets = transferred.pop().ok_or_else(|| {
        LaneError::input("install-door-private", "socket root descriptor is absent")
    })?;
    let libexec = transferred
        .pop()
        .ok_or_else(|| LaneError::input("install-door-private", "libexec descriptor is absent"))?;
    let template = transferred
        .pop()
        .ok_or_else(|| LaneError::input("install-door-private", "template descriptor is absent"))?;
    let stub_source = transferred.pop().ok_or_else(|| {
        LaneError::input("install-door-private", "stub source descriptor is absent")
    })?;
    let lock = transferred.pop().ok_or_else(|| {
        LaneError::input("install-door-private", "install lock descriptor is absent")
    })?;
    let home_fd = transferred.pop().ok_or_else(|| {
        LaneError::input("install-door-private", "owner home descriptor is absent")
    })?;
    let _verified_home =
        home::activate_handed_home(&request.owner_home, &home_fd, namespace_owner)?;
    let config = request
        .owner_home
        .join(".config/loops")
        .join(&request.loop_name);
    let _guard = install::InstallGuard::from_handed_mode(
        &config,
        &request.owner_home,
        namespace_owner,
        lock,
        request.dry_run,
    )?;
    let result = private_run_with_handed_identity(
        request,
        &home_fd,
        stub_source,
        &template,
        &libexec,
        &sockets,
        namespace_owner,
        fixture_view,
    );
    Ok(match result {
        Ok(report) => report,
        Err(error) => {
            json!({"schema":1,"error":{"status":error.status,"kind":error.kind,"detail":error.detail}})
        }
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn private_run_with_handed_identity(
    request: &PrivateDoorRequest,
    home_fd: &OwnedFd,
    stub_source: OwnedFd,
    template_fd: &OwnedFd,
    libexec_fd: &OwnedFd,
    sockets_fd: &OwnedFd,
    namespace_owner: u32,
    fixture_view: Option<(u32, u32)>,
) -> Result<Value, LaneError> {
    if Uid::effective().as_raw() != namespace_owner {
        return Err(LaneError::input(
            "install-door-private",
            "rootless namespace root is required",
        ));
    }
    let owner_home = &request.owner_home;
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry_bytes =
        pinned::read_private(owner_home, &registry_path, namespace_owner, 0o600, 65_536)?;
    let mut registry_file = build::executable_snapshot(&registry_bytes)?;
    registry_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| LaneError::input("install-door-row", error.to_string()))?;
    let registry = loop_home::registry::load_registry_from_file(&mut registry_file)
        .map_err(|error| LaneError::input("install-door-row", error.message()))?;
    let row = registry
        .row(&request.loop_name, owner_home)
        .map_err(|error| LaneError::input("install-door-row", error.message()))?;
    if row.uid != request.row_uid {
        return Err(LaneError::input(
            "install-door-row",
            "namespace row uid differs",
        ));
    }
    let settings = Settings::read_beneath(
        &owner_home
            .join(".config/loops")
            .join(&request.loop_name)
            .join("workers.toml"),
        owner_home,
    )?;
    let (source, _, _) = crate::settings::split_local_policies(&settings.source)?;
    let table =
        loop_home::workers_settings::validate_workers_settings(&source, Path::new("workers.toml"))
            .map_err(|error| LaneError::input("settings-grant", error.message()))?;
    loop_home::workers_settings::validate_workers_grant(
        &table,
        &row,
        registry.runs_root(&request.loop_name),
    )
    .map_err(|error| LaneError::input("settings-grant", error.message()))?;
    let template = settings
        .template_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("install-door-setting", "template_dir is absent"))?;
    let sockets = settings
        .socket_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("install-door-setting", "socket_dir is absent"))?;
    if template.parent() != Some(row.home.join("runner-templates/codex").as_path())
        || sockets != row.home.join("sockets")
    {
        return Err(LaneError::input(
            "install-door-setting",
            "template or socket root differs from row",
        ));
    }
    compare_handed_directory(home_fd, owner_home, template, template_fd, namespace_owner)?;
    compare_handed_directory(
        home_fd,
        owner_home,
        &template.join("libexec"),
        libexec_fd,
        namespace_owner,
    )?;
    compare_handed_directory(home_fd, owner_home, sockets, sockets_fd, namespace_owner)?;
    let stub_stat = fstat(&stub_source)
        .map_err(|error| LaneError::input("install-door-source", error.to_string()))?;
    if SFlag::from_bits_truncate(stub_stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(LaneError::input(
            "install-door-source",
            "transferred stub is not a regular file",
        ));
    }
    let mut stub_bytes = Vec::new();
    let mut stub_file = File::from(stub_source);
    stub_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| LaneError::input("install-door-source", error.to_string()))?;
    stub_file
        .take((FILE_LIMIT + 1) as u64)
        .read_to_end(&mut stub_bytes)
        .map_err(|error| LaneError::input("install-door-source", error.to_string()))?;
    if stub_bytes.len() > FILE_LIMIT {
        return Err(LaneError::input(
            "install-door-source",
            "stub exceeds byte limit",
        ));
    }
    if build::sha256_bytes(&stub_bytes, owner_home)? != request.stub_sha256 {
        return Err(LaneError::input(
            "install-door-source",
            "stub changed after host preflight",
        ));
    }
    private_stage(
        owner_home,
        template,
        sockets,
        libexec_fd,
        sockets_fd,
        namespace_owner,
        row.uid,
        &stub_bytes,
        request.old_stub_sha256.as_deref(),
        request.apply,
        fixture_view,
    )
}

#[cfg(test)]
fn private_run_with_identity(
    request: &PrivateDoorRequest,
    stub_source: OwnedFd,
    namespace_owner: u32,
    fixture_view: Option<(u32, u32)>,
) -> Result<Value, LaneError> {
    let owner_home = &request.owner_home;
    let owner = Uid::effective().as_raw();
    let home_fd: OwnedFd = File::open(owner_home)
        .map_err(|error| LaneError::input("install-door-path", error.to_string()))?
        .into();
    let template = owner_home
        .join(".var/loops")
        .join(&request.loop_name)
        .join("runner-templates/codex/pin");
    let sockets = owner_home
        .join(".var/loops")
        .join(&request.loop_name)
        .join("sockets");
    let template_fd = pin_directory_beneath(&home_fd, owner_home, &template, owner)?;
    let libexec_fd = pin_directory_beneath(&home_fd, owner_home, &template.join("libexec"), owner)?;
    let sockets_fd = pin_directory_beneath(&home_fd, owner_home, &sockets, owner)?;
    private_run_with_handed_identity(
        request,
        &home_fd,
        stub_source,
        &template_fd,
        &libexec_fd,
        &sockets_fd,
        namespace_owner,
        fixture_view,
    )
}

fn decode_namespace_report(report: Value) -> Result<Value, LaneError> {
    if let Some(error) = report.get("error") {
        let kind = error["kind"]
            .as_str()
            .and_then(|word| {
                PRIVATE_REFUSAL_KINDS
                    .iter()
                    .copied()
                    .find(|known| *known == word)
            })
            .ok_or_else(|| {
                LaneError::operation("install-door-private", "private refusal kind differs")
            })?;
        let detail = error["detail"].as_str().ok_or_else(|| {
            LaneError::operation("install-door-private", "private refusal detail is absent")
        })?;
        let status = error["status"].as_u64().ok_or_else(|| {
            LaneError::operation("install-door-private", "private refusal status is absent")
        })?;
        if report.as_object().is_none_or(|fields| fields.len() != 2)
            || report["schema"] != 1
            || (status != 1 && status != 2)
            || error.as_object().is_none_or(|fields| fields.len() != 3)
        {
            return Err(LaneError::operation(
                "install-door-private",
                "private refusal shape differs",
            ));
        }
        return Err(LaneError {
            status: u8::try_from(status).unwrap_or(1),
            kind,
            detail: detail.into(),
        });
    }
    if report.as_object().is_none_or(|object| {
        object.len() != 3
            || !object.contains_key("schema")
            || !object.contains_key("dir_exists")
            || !object.contains_key("stub_exists")
    }) || report["schema"] != 1
        || !report["dir_exists"].is_boolean()
        || !report["stub_exists"].is_boolean()
    {
        return Err(LaneError::operation(
            "install-door-private",
            "private report shape differs",
        ));
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn namespace_step(
    owner_home: &Path,
    podman_bin: &Path,
    loop_name: &str,
    template: &Path,
    sockets: &Path,
    stub: &Path,
    stub_bytes: &[u8],
    stub_digest: &str,
    old_digest: Option<&str>,
    row_uid: u32,
    guard: &install::InstallGuard,
    fixture_group: Option<u32>,
    apply: bool,
) -> Result<Value, LaneError> {
    let owner = Uid::effective().as_raw();
    let verified_home: OwnedFd = if fixture_group.is_some() {
        File::open(owner_home)
            .map_err(|error| LaneError::input("install-door-path", error.to_string()))?
            .into()
    } else {
        home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?
    };
    let template_fd = pin_directory_beneath(&verified_home, owner_home, template, owner)?;
    let libexec_fd =
        pin_directory_beneath(&verified_home, owner_home, &template.join("libexec"), owner)?;
    let sockets_fd = pin_directory_beneath(&verified_home, owner_home, sockets, owner)?;
    let report = if let Some(mapped_group) = fixture_group {
        private_stage(
            owner_home,
            template,
            sockets,
            &libexec_fd,
            &sockets_fd,
            owner,
            mapped_group,
            stub_bytes,
            old_digest,
            apply,
            None,
        )?
    } else {
        let lane_bin = std::env::current_exe()
            .map_err(|error| LaneError::operation("install-door-private", error.to_string()))?;
        let lane_word = pinned::owner_executable_word(&lane_bin, owner)?;
        let owner_word = pinned::path_word(owner_home, "owner-home")?;
        let stub_word = pinned::path_word(stub, "door-stub")?;
        let args = vec![
            "unshare".into(),
            lane_word,
            "_install-door-private".into(),
            loop_name.into(),
            owner_word,
            stub_word,
            row_uid.to_string(),
            stub_digest.into(),
            old_digest.unwrap_or("-").into(),
            private_mode_word(apply, guard.is_writable()).into(),
        ];
        let source = build::executable_snapshot(stub_bytes)?;
        let spec = build::child(
            podman_bin,
            args,
            &build::podman_environment(owner_home)?,
            owner_home,
            120,
            "install-door-private",
        )
        .with_private_door_directories(
            &verified_home,
            guard,
            &source,
            &template_fd,
            &libexec_fd,
            &sockets_fd,
        )?;
        let output = build::checked_output(&spec, None)?;
        serde_json::from_str(&output)
            .map_err(|error| LaneError::operation("install-door-private", error.to_string()))?
    };
    decode_namespace_report(report)
}

const fn private_mode_word(apply: bool, writable: bool) -> &'static str {
    if apply {
        "apply"
    } else if writable {
        "preview"
    } else {
        "dry-run"
    }
}

#[derive(Clone)]
pub struct DoorRequest {
    pub loop_name: String,
    pub dry_run: bool,
    /// Explicit selection; an empty path means the option was omitted.
    pub podman_bin: PathBuf,
}

impl DoorRequest {
    /// Parse the exact public command form.
    ///
    /// # Errors
    ///
    /// Refuses extra or misplaced arguments.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, rest @ ..] = args else {
            return Err(LaneError::input(
                "install-door-usage",
                "install-door LOOP [--dry-run] [--podman-bin FILE]",
            ));
        };
        let mut dry_run = false;
        let mut podman_bin = None;
        let mut words = rest.iter();
        while let Some(word) = words.next() {
            match word.as_str() {
                "--dry-run" if !dry_run => dry_run = true,
                "--podman-bin" => {
                    let value =
                        words
                            .next()
                            .filter(|value| !value.is_empty())
                            .ok_or_else(|| {
                                LaneError::input(
                                    "install-door-usage",
                                    "--podman-bin needs a nonempty value",
                                )
                            })?;
                    if podman_bin.replace(PathBuf::from(value)).is_some() {
                        return Err(LaneError::input(
                            "install-door-usage",
                            "--podman-bin repeated",
                        ));
                    }
                }
                other => {
                    return Err(LaneError::input(
                        "install-door-usage",
                        format!("unexpected install-door argument {other}"),
                    ));
                }
            }
        }
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("install-door-usage", error.message()))?;
        Ok(Self {
            loop_name: loop_name.clone(),
            dry_run,
            podman_bin: podman_bin.unwrap_or_default(),
        })
    }

    fn selected_program(&self) -> Option<&Path> {
        (!self.podman_bin.as_os_str().is_empty()).then_some(self.podman_bin.as_path())
    }

    fn program(&self) -> &Path {
        self.selected_program()
            .unwrap_or_else(|| Path::new("/usr/bin/podman"))
    }
}

#[derive(Clone)]
struct Destination {
    path: PathBuf,
    bytes: Vec<u8>,
    uid: u32,
    gid: u32,
    mode: u32,
    exists: bool,
}

fn inspect_file(
    _owner_home: &Path,
    path: &Path,
    identity: (u32, u32, u32),
    bytes: &[u8],
) -> Result<bool, LaneError> {
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::input("install-door-path", "file parent is absent"))?;
    let fd = home::pin_parent(parent, identity.0)?;
    inspect_file_beneath(&fd, path, identity, bytes)
}

fn inspect_file_beneath(
    fd: &OwnedFd,
    path: &Path,
    identity: (u32, u32, u32),
    bytes: &[u8],
) -> Result<bool, LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("install-door-path", "file name is absent"))?;
    match fstatat(fd, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(LaneError::input(
            "install-door-destination",
            format!("{}: {error}", path.display()),
        )),
        Ok(stat) => {
            if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
                || (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777) != identity
            {
                return Err(LaneError::input(
                    "install-door-conflict",
                    format!("{} differs in type, owner or mode", path.display()),
                ));
            }
            let opened = openat2(
                fd,
                Path::new(name),
                OpenHow::new()
                    .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            )
            .map_err(|error| LaneError::input("install-door-destination", error.to_string()))?;
            let opened_stat = fstat(&opened)
                .map_err(|error| LaneError::input("install-door-destination", error.to_string()))?;
            if (opened_stat.st_dev, opened_stat.st_ino) != (stat.st_dev, stat.st_ino) {
                return Err(LaneError::input(
                    "install-door-conflict",
                    "destination identity changed",
                ));
            }
            let mut found = Vec::new();
            File::from(opened)
                .take((FILE_LIMIT + 1) as u64)
                .read_to_end(&mut found)
                .map_err(|error| LaneError::input("install-door-destination", error.to_string()))?;
            if found.len() > FILE_LIMIT {
                return Err(LaneError::input(
                    "install-door-conflict",
                    "destination exceeds byte limit",
                ));
            }
            if found != bytes {
                return Err(LaneError::input(
                    "install-door-conflict",
                    format!("{} differs in bytes", path.display()),
                ));
            }
            Ok(true)
        }
    }
}

fn read_checked_beneath(
    fd: &OwnedFd,
    path: &Path,
    identity: (u32, u32, u32),
) -> Result<Vec<u8>, LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("install-door-path", "file name is absent"))?;
    let recorded = fstatat(fd, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| LaneError::input("install-door-conflict", error.to_string()))?;
    if SFlag::from_bits_truncate(recorded.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || (recorded.st_uid, recorded.st_gid, recorded.st_mode & 0o7777) != identity
    {
        return Err(LaneError::input(
            "install-door-conflict",
            "old stub identity differs",
        ));
    }
    #[cfg(test)]
    BEFORE_OLD_STUB_OPEN.with(|slot| {
        if let Some(change) = slot.borrow_mut().take() {
            change();
        }
    });
    let opened = openat2(
        fd,
        Path::new(name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("install-door-conflict", error.to_string()))?;
    let actual = fstat(&opened)
        .map_err(|error| LaneError::input("install-door-conflict", error.to_string()))?;
    if (actual.st_dev, actual.st_ino) != (recorded.st_dev, recorded.st_ino) {
        return Err(LaneError::input(
            "install-door-conflict",
            "old stub identity changed",
        ));
    }
    let mut bytes = Vec::new();
    File::from(opened)
        .take((FILE_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("install-door-conflict", error.to_string()))?;
    if bytes.len() > FILE_LIMIT {
        return Err(LaneError::input(
            "install-door-conflict",
            "old stub exceeds byte limit",
        ));
    }
    Ok(bytes)
}

fn inspect_directory_beneath(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    group: u32,
    mode: u32,
) -> Result<bool, LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("install-door-path", "directory name is absent"))?;
    match fstatat(fd, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(LaneError::input(
            "install-door-destination",
            format!("{}: {error}", path.display()),
        )),
        Ok(stat)
            if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR
                && (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777) == (owner, group, mode) =>
        {
            Ok(true)
        }
        Ok(_) => Err(LaneError::input(
            "install-door-conflict",
            format!("{} differs in type, owner or mode", path.display()),
        )),
    }
}

fn write_file(_owner_home: &Path, destination: &Destination) -> Result<(), LaneError> {
    let parent = destination
        .path
        .parent()
        .ok_or_else(|| LaneError::operation("install-door-path", "file parent is absent"))?;
    let fd = home::pin_parent(parent, destination.uid)?;
    write_file_beneath(&fd, destination)
}

fn write_file_beneath(fd: &OwnedFd, destination: &Destination) -> Result<(), LaneError> {
    let name = destination
        .path
        .file_name()
        .ok_or_else(|| LaneError::operation("install-door-path", "file name is absent"))?;
    let mut output = File::from(
        openat2(
            fd,
            Path::new(name),
            OpenHow::new()
                .flags(
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_CLOEXEC
                        | OFlag::O_NOFOLLOW,
                )
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| {
            LaneError::operation(
                "install-door-write",
                format!("{}: {error}", destination.path.display()),
            )
        })?,
    );
    output
        .write_all(&destination.bytes)
        .map_err(|error| LaneError::operation("install-door-write", error.to_string()))?;
    fchown(
        &output,
        Some(Uid::from_raw(destination.uid)),
        Some(Gid::from_raw(destination.gid)),
    )
    .map_err(|error| LaneError::operation("install-door-owner", error.to_string()))?;
    output
        .set_permissions(fs::Permissions::from_mode(destination.mode))
        .map_err(|error| LaneError::operation("install-door-mode", error.to_string()))?;
    output
        .sync_all()
        .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))?;
    let copy = nix::unistd::dup(fd)
        .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))?;
    File::from(copy)
        .sync_all()
        .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))?;
    if !inspect_file_beneath(
        fd,
        &destination.path,
        (destination.uid, destination.gid, destination.mode),
        &destination.bytes,
    )? {
        return Err(LaneError::operation(
            "install-door-verify",
            "written file is absent",
        ));
    }
    Ok(())
}

pub(crate) fn publish_node_file(config: &Path, name: &str, bytes: &[u8]) -> Result<(), LaneError> {
    replace_file(
        config,
        &Destination {
            path: config.join(name),
            bytes: bytes.to_vec(),
            uid: Uid::effective().as_raw(),
            gid: Gid::effective().as_raw(),
            mode: 0o600,
            exists: false,
        },
    )
}

fn replace_file(_owner_home: &Path, destination: &Destination) -> Result<(), LaneError> {
    let parent = destination
        .path
        .parent()
        .ok_or_else(|| LaneError::operation("install-door-path", "file parent is absent"))?;
    let directory = home::pin_parent(parent, destination.uid)?;
    replace_file_beneath(&directory, destination)
}

fn replace_file_beneath(directory: &OwnedFd, destination: &Destination) -> Result<(), LaneError> {
    let parent = destination
        .path
        .parent()
        .ok_or_else(|| LaneError::operation("install-door-path", "file parent is absent"))?;
    let name = destination
        .path
        .file_name()
        .ok_or_else(|| LaneError::operation("install-door-path", "file name is absent"))?;
    let temporary = format!(
        ".door-install-{}.tmp",
        crate::launch::checkpoint::random_token()?
    );
    let mut staged = destination.clone();
    staged.path = parent.join(&temporary);
    write_file_beneath(directory, &staged)?;
    renameat(directory, temporary.as_str(), directory, name)
        .map_err(|error| LaneError::operation("install-door-replace", error.to_string()))?;
    let checked = (|| {
        let copy = nix::unistd::dup(directory)
            .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))?;
        File::from(copy)
            .sync_all()
            .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))?;
        if !inspect_file_beneath(
            directory,
            &destination.path,
            (destination.uid, destination.gid, destination.mode),
            &destination.bytes,
        )? {
            return Err(LaneError::operation(
                "install-door-verify",
                "replaced file is absent",
            ));
        }
        Ok(())
    })();
    if let Err(error) = checked {
        if name == "door-install-generation.json" {
            unlinkat(directory, name, UnlinkatFlags::NoRemoveDir).map_err(|withdraw| {
                LaneError::operation(
                    "install-door-withdraw",
                    format!("{}; generation withdrawal failed: {withdraw}", error.line()),
                )
            })?;
            let copy = nix::unistd::dup(directory)
                .map_err(|sync| LaneError::operation("install-door-withdraw", sync.to_string()))?;
            File::from(copy).sync_all().map_err(|sync| {
                LaneError::operation(
                    "install-door-withdraw",
                    format!("{}; withdrawal sync failed: {sync}", error.line()),
                )
            })?;
        }
        return Err(error);
    }
    Ok(())
}

fn set_directory_metadata(
    fd: &OwnedFd,
    owner: u32,
    group: u32,
    mode: u32,
) -> Result<(), LaneError> {
    fchown(fd, Some(Uid::from_raw(owner)), Some(Gid::from_raw(group)))
        .map_err(|error| LaneError::operation("install-door-owner", error.to_string()))?;
    let duplicate = nix::unistd::dup(fd)
        .map_err(|error| LaneError::operation("install-door-mode", error.to_string()))?;
    File::from(duplicate)
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| LaneError::operation("install-door-mode", error.to_string()))?;
    #[cfg(test)]
    if CHANGE_METADATA_AFTER_SET.with(|slot| slot.replace(false)) {
        let duplicate = nix::unistd::dup(fd)
            .map_err(|error| LaneError::operation("install-door-mode", error.to_string()))?;
        File::from(duplicate)
            .set_permissions(fs::Permissions::from_mode(mode ^ 0o010))
            .map_err(|error| LaneError::operation("install-door-mode", error.to_string()))?;
    }
    let stat =
        fstat(fd).map_err(|error| LaneError::operation("install-door-mode", error.to_string()))?;
    if (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777) != (owner, group, mode) {
        return Err(LaneError::operation(
            "install-door-mode",
            "directory metadata differs",
        ));
    }
    Ok(())
}

fn create_directory_beneath(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    group: u32,
    mode: u32,
) -> Result<(), LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::operation("install-door-path", "directory name is absent"))?;
    mkdirat(fd, name, Mode::S_IRWXU).map_err(|error| {
        LaneError::operation("install-door-mkdir", format!("{}: {error}", path.display()))
    })?;
    let opened = openat2(
        fd,
        Path::new(name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("install-door-mkdir", error.to_string()))?;
    set_directory_metadata(&opened, owner, group, mode)?;
    if !inspect_directory_beneath(fd, path, owner, group, mode)? {
        return Err(LaneError::operation(
            "install-door-verify",
            "door directory is absent",
        ));
    }
    let duplicate = nix::unistd::dup(fd)
        .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))?;
    File::from(duplicate)
        .sync_all()
        .map_err(|error| LaneError::operation("install-door-sync", error.to_string()))
}

fn installed_program(name: &str, compile_time: Option<&str>) -> Result<PathBuf, LaneError> {
    if let Some(path) = compile_time {
        return Ok(PathBuf::from(path));
    }
    Ok(std::env::current_exe()
        .map_err(|error| LaneError::input("install-door-program", error.to_string()))?
        .with_file_name(name))
}

/// Preview or install the door beside the completed vendor generation.
///
/// # Errors
///
/// Refuses all named source and destination conflicts before its first write.
pub fn run(owner_home: &Path, request: &DoorRequest) -> Result<Value, LaneError> {
    let stub = installed_program(
        "superloop-lane-door-ssh",
        option_env!("SUPERLOOP_LANE_DOOR_STUB_BIN"),
    )?;
    let service = installed_program(
        "superloop-lane-door-service",
        option_env!("SUPERLOOP_LANE_DOOR_SERVICE_BIN"),
    )?;
    run_with(owner_home, request, &stub, &service, None)
}

fn host_door_group(owner_home: &Path, door_path: &Path, owner: u32) -> Result<u32, LaneError> {
    let directory = pinned::open_protected(owner_home, door_path, owner)?;
    let stat = fstat(&directory)
        .map_err(|error| LaneError::input("install-door-generation", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o750
    {
        return Err(LaneError::input(
            "install-door-generation",
            "registered socket directory differs",
        ));
    }
    Ok(stat.st_gid)
}

fn door_launcher_presence(record: &Value) -> crate::container_helper::ProcessPresence {
    use crate::container_helper::{ProcessPresence, process_presence};
    match (
        record["launcher_pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok()),
        record["launcher_start"].as_u64(),
    ) {
        (Some(pid), Some(start)) => process_presence(pid, start),
        (None, None) if crate::launch::terminal_before_launcher(record) => ProcessPresence::Absent,
        _ => ProcessPresence::Unknown,
    }
}

#[derive(Default)]
struct DoorInventory {
    busy: Vec<String>,
    settled: Vec<SettledDoor>,
    reservations: Vec<(String, Value)>,
    repin_unmeasured_runs: Vec<Value>,
    container_states: Vec<Value>,
}

fn container_states(
    program: &Path,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<Vec<String>, LaneError> {
    pinned::owner_executable(program, Uid::effective().as_raw())?;
    let output = build::run_checked(
        program,
        vec![
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--format".into(),
            "{{.State}}".into(),
            "--filter".into(),
            format!("label=org.superloop.loop={loop_name}"),
            "--filter".into(),
            format!("label=org.superloop.run={run}"),
        ],
        &build::podman_environment(owner_home)?,
        owner_home,
        30,
        "install-door-presence",
    )?;
    output
        .lines()
        .map(|line| {
            let state = line.trim();
            if matches!(
                state,
                "created"
                    | "initialized"
                    | "running"
                    | "stopped"
                    | "paused"
                    | "exited"
                    | "removing"
                    | "stopping"
            ) {
                Ok(state.to_owned())
            } else {
                Err(LaneError::input(
                    "install-door-presence",
                    format!("unknown container state: {state}"),
                ))
            }
        })
        .collect()
}

struct SettledDoor {
    run: String,
    stub_sha256: Value,
}

impl SettledDoor {
    fn new(
        run: &str,
        record: &Value,
        read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
    ) -> Result<Option<Self>, LaneError> {
        Self::with_presence(
            run,
            record,
            read_report,
            crate::container_helper::process_presence,
        )
    }

    fn with_presence(
        run: &str,
        record: &Value,
        read_report: impl FnOnce(&Value) -> Result<Value, LaneError>,
        presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    ) -> Result<Option<Self>, LaneError> {
        let door = &record["plan"]["door"];
        if !crate::launch::repin_door::door_shape(door, record) {
            return Ok(None);
        }
        match crate::launch::repin_door::boundary_with(record, presence, read_report) {
            Ok(_) => {}
            Err(error) if matches!(error.kind, "repin-door-state" | "repin-door-live") => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        Ok(Some(Self {
            run: run.to_owned(),
            stub_sha256: door["stub_sha256"].clone(),
        }))
    }
}

impl DoorInventory {
    fn measure_repins(
        &mut self,
        previous: Option<&Value>,
        next_stub: &str,
        mut read_report: impl FnMut(&Value) -> Result<Value, LaneError>,
    ) -> Result<(), LaneError> {
        let Some(_) = previous.filter(|old| old["stub_sha256"] != next_stub) else {
            return Ok(());
        };
        for (run, record) in std::mem::take(&mut self.reservations) {
            if record["plan"]["door"]["stub_sha256"] != next_stub {
                self.record_candidate(&run, SettledDoor::new(&run, &record, &mut read_report))?;
            }
        }
        self.repin_unmeasured_runs
            .sort_by(|left, right| left["run"].as_str().cmp(&right["run"].as_str()));
        Ok(())
    }

    fn record_candidate(
        &mut self,
        run: &str,
        candidate: Result<Option<SettledDoor>, LaneError>,
    ) -> Result<(), LaneError> {
        match candidate {
            Ok(candidate) => self.settled.extend(candidate),
            Err(error)
                if matches!(error.kind, "repin-door-uncertain" | "driver-report-private") =>
            {
                self.repin_unmeasured_runs
                    .push(json!({"run":run,"kind":error.kind}));
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn repin_required_runs(&self, previous: Option<&Value>, next_stub: &str) -> Vec<String> {
        let Some(_) = previous.filter(|old| old["stub_sha256"] != next_stub) else {
            return Vec::new();
        };
        let mut runs = self
            .settled
            .iter()
            .filter(|pin| pin.stub_sha256 != next_stub)
            .map(|pin| pin.run.clone())
            .collect::<Vec<_>>();
        runs.sort();
        runs
    }
}

fn inventory_program<'a>(
    record: &Value,
    selected: Option<&'a Path>,
    default_program: &'a Path,
) -> Result<&'a Path, LaneError> {
    if let Some(program) = selected {
        return Ok(program);
    }
    let program = default_program;
    let recorded = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("install-door-presence", "container program is absent"))?;
    if Path::new(recorded) != program {
        return Err(LaneError::input(
            "install-door-presence",
            format!(
                "recorded container program {recorded} differs from default {}",
                program.display()
            ),
        ));
    }
    Ok(program)
}

#[allow(clippy::too_many_lines)]
fn door_inventory(
    owner_home: &Path,
    loop_name: &str,
    podman_bin: Option<&Path>,
    default_program: &Path,
) -> Result<DoorInventory, LaneError> {
    use crate::container_helper::ProcessPresence;
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("install-door-presence", error.message()))?;
    let Some(root) = registry.runs_root(loop_name) else {
        return Ok(DoorInventory::default());
    };
    let entries = fs::read_dir(root).map_err(|error| {
        LaneError::input(
            "install-door-presence",
            format!("reservations unreadable: {error}"),
        )
    })?;
    let mut holders = Vec::new();
    let mut inventory = DoorInventory::default();
    let mut observed = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= 4096 {
            return Err(LaneError::input(
                "install-door-presence",
                "reservation inventory exceeds bound",
            ));
        }
        let entry =
            entry.map_err(|error| LaneError::input("install-door-presence", error.to_string()))?;
        let name = entry.file_name();
        let Some(run) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".reservation-"))
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|run| crate::valid_run_name(run))
        else {
            continue;
        };
        let record = crate::launch::read_reservation(&entry.path())?.ok_or_else(|| {
            LaneError::input(
                "install-door-presence",
                format!("run {run} reservation vanished"),
            )
        })?;
        if record["loop"] != loop_name || record["run"] != run {
            return Err(LaneError::input(
                "install-door-presence",
                format!("run {run} identity differs"),
            ));
        }
        let phase = record["phase"].as_str().ok_or_else(|| {
            LaneError::input(
                "install-door-presence",
                format!("run {run} phase is absent"),
            )
        })?;
        inventory
            .reservations
            .push((run.to_owned(), record.clone()));
        let launcher = door_launcher_presence(&record);
        if launcher == ProcessPresence::Present {
            continue;
        }
        let states = inventory_program(&record, podman_bin, default_program).and_then(|program| {
            container_states(program, owner_home, loop_name, run).map(|states| (program, states))
        });
        let absent = states.map(|(program, states)| {
            let idle = states
                .iter()
                .all(|state| matches!(state.as_str(), "exited" | "stopped"));
            observed.push(json!({"run":run,"states":states,"program":program}));
            idle
        });
        match (launcher, absent) {
            (ProcessPresence::Absent, Ok(false)) => holders.push(format!(
                "run {run} ({phase}; container alive, launcher gone)"
            )),
            (ProcessPresence::Unknown, Ok(false)) => holders.push(format!(
                "run {run} ({phase}; container alive, launcher unknown)"
            )),
            (ProcessPresence::Unknown, Ok(true)) => holders.push(format!(
                "run {run} ({phase}; container absent, launcher unknown)"
            )),
            (_, Err(error)) => holders.push(format!(
                "run {run} ({phase}; container unknown, launcher {}; {})",
                if launcher == ProcessPresence::Absent {
                    "gone"
                } else {
                    "unknown"
                },
                error.line()
            )),
            (ProcessPresence::Absent, Ok(true)) | (ProcessPresence::Present, _) => {}
        }
    }
    holders.sort();
    inventory.busy = holders;
    inventory.container_states = observed;
    inventory
        .repin_unmeasured_runs
        .sort_by(|left, right| left["run"].as_str().cmp(&right["run"].as_str()));
    Ok(inventory)
}

pub(crate) fn busy_holder_with_program(
    owner_home: &Path,
    loop_name: &str,
    config: &Path,
    podman_bin: Option<&Path>,
    default_program: &Path,
) -> Vec<String> {
    let Ok(_reader) = install::lock_loop_config(config, true) else {
        return vec!["an exclusive configuration change (install-door, install, repair, build, retire, record-hosts, pause/resume, or prepare)".into()];
    };
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let Some(root) = loop_home::load_registry(&registry_path)
        .ok()
        .and_then(|registry| registry.runs_root(loop_name).map(Path::to_path_buf))
    else {
        return vec!["a shared configuration reader (reservations unreadable)".into()];
    };
    let Ok(entries) = fs::read_dir(root) else {
        return vec!["a shared configuration reader (reservations unreadable)".into()];
    };
    let mut holders = Vec::new();
    for entry in entries.take(4096).flatten() {
        let name = entry.file_name();
        let Some(run) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".reservation-"))
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|run| crate::valid_run_name(run))
        else {
            continue;
        };
        let Ok(Some(record)) = crate::launch::read_reservation(&entry.path()) else {
            continue;
        };
        let Some(phase) = record["phase"].as_str() else {
            continue;
        };
        let Some(pid) = record["launcher_pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            continue;
        };
        let Some(start) = record["launcher_start"].as_u64() else {
            continue;
        };
        if record["loop"] == loop_name
            && record["run"] == run
            && crate::container_helper::process_alive(pid, start)
        {
            holders.push(format!("run {run} ({phase})"));
        }
    }
    match door_inventory(owner_home, loop_name, podman_bin, default_program) {
        Ok(inventory) => {
            holders.extend(inventory.busy.into_iter().map(|holder| match podman_bin {
                Some(program) => format!("{holder}; container program: {}", program.display()),
                None => holder,
            }));
        }
        Err(error) => holders.push(format!("reservations unreadable: {}", error.line())),
    }
    holders.sort();
    if holders.is_empty() {
        vec!["a shared configuration reader (launch planning, a starting round, census, exercise, install --pilot --refresh-proxy, record-hosts --list, or a dry run)".into()]
    } else {
        holders
    }
}

/// Observe exclusive availability without retaining the probe or changing files.
pub(crate) fn configuration_blocked_with_program(
    owner_home: &Path,
    loop_name: &str,
    config: &Path,
    podman_bin: Option<&Path>,
    default_program: &Path,
) -> Result<Option<Vec<String>>, LaneError> {
    match install::lock_loop_config(config, false) {
        Ok(probe) => {
            drop(probe);
            Ok(None)
        }
        Err(error) if error.kind == "install-busy" => Ok(Some(busy_holder_with_program(
            owner_home,
            loop_name,
            config,
            podman_bin,
            default_program,
        ))),
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_with(
    owner_home: &Path,
    request: &DoorRequest,
    stub: &Path,
    service: &Path,
    fixture_group: Option<u32>,
) -> Result<Value, LaneError> {
    const ATTEMPT_KEYS: [&str; 5] = ["schema", "phase", "loop", "from", "to"];
    let started = Instant::now();
    let owner = Uid::effective().as_raw();
    let group = nix::unistd::Gid::effective().as_raw();
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    if request.dry_run
        && let Some(holder) = configuration_blocked_with_program(
            owner_home,
            &request.loop_name,
            &config,
            request.selected_program(),
            Path::new("/usr/bin/podman"),
        )?
    {
        return Ok(
            json!({"schema":1,"command":"install-door","loop":request.loop_name,"dry_run":true,"blocked":true,"busy":holder,"actions":[],"changed":0,"wall_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    let lock = match install::lock_loop_config(&config, request.dry_run) {
        Ok(lock) => lock,
        Err(error) if error.kind == "install-busy" => {
            let holder = busy_holder_with_program(
                owner_home,
                &request.loop_name,
                &config,
                request.selected_program(),
                Path::new("/usr/bin/podman"),
            );
            if request.dry_run {
                return Ok(
                    json!({"schema":1,"command":"install-door","loop":request.loop_name,"dry_run":true,"blocked":true,"busy":holder,"actions":[],"changed":0,"wall_seconds":started.elapsed().as_secs_f64()}),
                );
            }
            return Err(LaneError::input(
                "install-busy",
                format!("{}: {}", config.display(), holder.join(", ")),
            ));
        }
        Err(error) => return Err(error),
    };
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("install-door-row", error.message()))?;
    let mut inventory = door_inventory(
        owner_home,
        &request.loop_name,
        request.selected_program(),
        Path::new("/usr/bin/podman"),
    )?;
    let orphaned = &inventory.busy;
    if !orphaned.is_empty() {
        if request.dry_run {
            return Ok(
                json!({"schema":1,"command":"install-door","loop":request.loop_name,"dry_run":true,"blocked":true,"busy":orphaned,"repin_unmeasured_runs":inventory.repin_unmeasured_runs,"container_states":inventory.container_states,"actions":[],"changed":0,"wall_seconds":started.elapsed().as_secs_f64()}),
            );
        }
        return Err(LaneError::input("install-busy", orphaned.join(", ")));
    }
    let row = registry
        .row(&request.loop_name, owner_home)
        .map_err(|error| LaneError::input("install-door-row", error.message()))?;
    let config_directory = pinned::open_protected(owner_home, &config, owner)?;
    let node_root = crate::door::registered_node_root(&config_directory, &config, owner)?;
    let node_plan = crate::door_node::plan(&config_directory, &config, &request.loop_name, owner)?;
    let settings = Settings::read(&config.join("workers.toml"))?;
    let agent_configuration = if fixture_group.is_some() && !config.join("door.toml").exists() {
        json!({"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"entry":"/fixture/entry","loop_home":"/fixture/home"})
    } else {
        let configuration = crate::door::config::read(
            owner_home,
            &request.loop_name,
            settings.entry_bin.as_deref(),
        )?;
        crate::door::agent::check_rubric(
            Path::new(configuration["entry"].as_str().unwrap_or_default()),
            owner_home,
            &request.loop_name,
            Path::new(configuration["rubric_path"].as_str().unwrap_or_default()),
            row.uid,
        )?;
        configuration
    };
    let agent_metadata = crate::door::metadata::inspect(
        std::path::Path::new(agent_configuration["entry"].as_str().unwrap_or_default()),
        owner_home,
        &request.loop_name,
        std::path::Path::new(
            agent_configuration["executable"]
                .as_str()
                .unwrap_or_default(),
        ),
    );
    settings.validate_grant(owner_home, &request.loop_name)?;
    let template = settings
        .template_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("install-door-setting", "template_dir is absent"))?;
    let sockets = settings
        .socket_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("install-door-setting", "socket_dir is absent"))?;
    if template.parent() != Some(row.home.join("runner-templates/codex").as_path())
        || sockets != row.home.join("sockets")
    {
        return Err(LaneError::input(
            "install-door-setting",
            "template or socket root differs from row",
        ));
    }
    let vendor_generation_path = config.join("install-generation.json");
    let vendor_bytes =
        pinned::read_private(owner_home, &vendor_generation_path, owner, 0o600, 65_536)?;
    let vendor: Value = serde_json::from_slice(&vendor_bytes)
        .map_err(|error| LaneError::input("install-door-generation", error.to_string()))?;
    crate::build::payload::check_claude_generation(&vendor)?;
    if vendor["phase"] != "complete"
        || vendor["template_dir"].as_str() != template.to_str()
        || vendor["socket_dir"].as_str() != sockets.to_str()
    {
        return Err(LaneError::input(
            "install-door-generation",
            "vendor generation is not complete for these roots",
        ));
    }
    let generation_path = config.join("door-install-generation.json");
    let old_generation =
        pinned::read_private_optional(owner_home, &generation_path, owner, 0o600, 65_536)?
            .map(|bytes| {
                serde_json::from_slice::<Value>(&bytes)
                    .map_err(|error| LaneError::input("install-door-generation", error.to_string()))
            })
            .transpose()?;
    if let Some(old) = &old_generation {
        const KEYS: [&str; 10] = [
            "schema",
            "phase",
            "loop",
            "template_dir",
            "socket_dir",
            "stub_sha256",
            "service_sha256",
            "unit_dir",
            "registered",
            "host_door_gid",
        ];
        if old.as_object().is_none_or(|object| {
            (object.len() != KEYS.len() + usize::from(object.contains_key("agent")))
                || KEYS.iter().any(|key| !object.contains_key(*key))
        }) || !matches!(old["schema"].as_u64(), Some(1 | 2))
            || (old["schema"] == 2 && old.get("agent").is_none())
            || old["phase"] != "complete"
            || old["loop"] != request.loop_name
            || old["registered"] != json!(["ssh"])
            || old["host_door_gid"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .is_none()
        {
            return Err(LaneError::input(
                "install-door-generation",
                "door generation shape differs",
            ));
        }
    }
    pinned::owner_executable_word(stub, owner)?;
    pinned::owner_executable_word(service, owner)?;
    let service_destination = config.join("door-service");
    let service_word = pinned::path_word(&service_destination, "door-service")?;
    let unit_dir =
        PathBuf::from(vendor["unit_dir"].as_str().ok_or_else(|| {
            LaneError::input("install-door-generation", "unit directory is absent")
        })?);
    if !unit_dir.starts_with(owner_home.join(".config")) {
        return Err(LaneError::input(
            "install-door-unit",
            "unit directory is outside owner configuration",
        ));
    }
    let unit_meta = pinned::open_protected(owner_home, &unit_dir, owner)?;
    let stat = fstat(&unit_meta)
        .map_err(|error| LaneError::input("install-door-unit", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777) != (owner, group, 0o700)
    {
        return Err(LaneError::input(
            "install-door-unit",
            "unit directory differs",
        ));
    }
    let libexec = template.join("libexec");
    let door_path = sockets.join("door");
    let unit_bytes = format!("[Unit]\nDescription=Superloop lane capability door for %i\n\n[Service]\nType=simple\nExecStart={service_word} %i\nRestart=on-failure\nRestartSec=2s\n\n[Install]\nWantedBy=default.target\n").into_bytes();
    let stub_bytes = build::source_bytes(stub, "door stub", FILE_LIMIT as u64, true)?;
    let service_bytes = build::source_bytes(service, "door service", FILE_LIMIT as u64, true)?;
    let stub_digest = build::sha256_bytes(&stub_bytes, owner_home)?;
    let service_digest = build::sha256_bytes(&service_bytes, owner_home)?;
    inventory.measure_repins(old_generation.as_ref(), &stub_digest, |record| {
        crate::launch::driver_report::read(owner_home, record)
    })?;
    let repin_required_runs = inventory.repin_required_runs(old_generation.as_ref(), &stub_digest);
    let supersede = old_generation.as_ref().is_some_and(|old| {
        old["schema"] != 2
            || old["template_dir"].as_str() != template.to_str()
            || old["socket_dir"].as_str() != sockets.to_str()
            || old["stub_sha256"] != stub_digest
            || old["service_sha256"] != service_digest
            || old["agent"] != agent_configuration
    });
    let old_stub_digest = old_generation.as_ref().and_then(|old| {
        (supersede && old["template_dir"].as_str() == template.to_str())
            .then(|| old["stub_sha256"].as_str())
            .flatten()
    });
    let private = namespace_step(
        owner_home,
        request.program(),
        &request.loop_name,
        template,
        sockets,
        stub,
        &stub_bytes,
        &stub_digest,
        old_stub_digest,
        row.uid,
        &lock,
        fixture_group,
        false,
    )?;
    let dir_exists = private["dir_exists"] == true;
    if !dir_exists
        && !supersede
        && old_generation
            .as_ref()
            .is_some_and(|old| old["unit_dir"].as_str() != unit_dir.to_str())
    {
        return Err(LaneError::input(
            "install-door-conflict",
            "old unit directory differs from the generation",
        ));
    }
    let preflight_host_group = dir_exists
        .then(|| host_door_group(owner_home, &door_path, owner))
        .transpose()?;
    let destinations = [
        Destination {
            path: libexec.join("ssh"),
            bytes: stub_bytes,
            uid: owner,
            gid: fixture_group.unwrap_or(row.uid),
            mode: 0o550,
            exists: private["stub_exists"] == true,
        },
        Destination {
            path: service_destination,
            bytes: service_bytes,
            uid: owner,
            gid: group,
            mode: 0o700,
            exists: false,
        },
        Destination {
            path: unit_dir.join(format!("superloop-lane-door@{}.service", request.loop_name)),
            bytes: unit_bytes,
            uid: owner,
            gid: group,
            mode: 0o644,
            exists: false,
        },
    ];
    let mut destinations = destinations
        .into_iter()
        .map(|mut destination| {
            if destination.path == libexec.join("ssh") {
                return Ok(destination);
            }
            let previous_program = supersede && destination.path == config.join("door-service");
            if previous_program {
                let old = old_generation.as_ref().ok_or_else(|| {
                    LaneError::input("install-door-generation", "old generation is absent")
                })?;
                let installed = pinned::read_checked(
                    owner_home,
                    &destination.path,
                    owner,
                    (destination.uid, destination.gid, destination.mode),
                    FILE_LIMIT,
                )?;
                let installed_digest = build::sha256_bytes(&installed, owner_home)?;
                let expected = &old["service_sha256"];
                let new_digest = &service_digest;
                if expected != &installed_digest && &installed_digest != new_digest {
                    return Err(LaneError::input(
                        "install-door-conflict",
                        "old program differs from its generation",
                    ));
                }
                destination.exists = installed == destination.bytes;
            } else {
                destination.exists = inspect_file(
                    owner_home,
                    &destination.path,
                    (destination.uid, destination.gid, destination.mode),
                    &destination.bytes,
                )?;
            }
            Ok(destination)
        })
        .collect::<Result<Vec<_>, LaneError>>()?;
    let generation = |host_door_gid| json!({"schema":2,"phase":"complete","loop":request.loop_name,"template_dir":template,"socket_dir":sockets,"stub_sha256":stub_digest,"service_sha256":service_digest,"unit_dir":unit_dir,"registered":["ssh"],"host_door_gid":host_door_gid,"agent":agent_configuration});
    let preflight_generation_bytes = preflight_host_group
        .map(|host_group| {
            serde_json::to_vec_pretty(&generation(host_group))
                .map_err(|error| LaneError::operation("install-door-generation", error.to_string()))
        })
        .transpose()?;
    let generation_exists = if supersede {
        false
    } else if let Some(bytes) = &preflight_generation_bytes {
        inspect_file(owner_home, &generation_path, (owner, group, 0o600), bytes)?
    } else {
        false
    };
    let attempt_path = config.join("door-install-attempt.json");
    let prior_attempt = if let Some(bytes) =
        pinned::read_private_optional(owner_home, &attempt_path, owner, 0o600, 65_536)?
    {
        let prior: Value = serde_json::from_slice(&bytes)
            .map_err(|error| LaneError::input("install-door-attempt", error.to_string()))?;
        if prior.as_object().is_none_or(|object| {
            object.len() != ATTEMPT_KEYS.len()
                || ATTEMPT_KEYS.iter().any(|key| !object.contains_key(*key))
        }) || prior["schema"] != 1
            || prior["loop"] != request.loop_name
            || !matches!(prior["phase"].as_str(), Some("attempted" | "complete"))
        {
            return Err(LaneError::input(
                "install-door-attempt",
                "old attempt shape differs",
            ));
        }
        Some(prior)
    } else {
        None
    };
    let planned_changes = node_plan
        .as_ref()
        .map_or(0, crate::door_node::Plan::changed)
        + u64::from(!dir_exists)
        + destinations.iter().filter(|row| !row.exists).count() as u64
        + u64::from(!generation_exists);
    let record_attempt = planned_changes > 0;
    let complete_legacy_attempt = !record_attempt
        && generation_exists
        && prior_attempt
            .as_ref()
            .is_some_and(|prior| prior["phase"] == "attempted" && prior["to"] == json!(template));
    let changed = planned_changes + u64::from(record_attempt || complete_legacy_attempt);
    let stub_replaces = supersede
        && old_generation
            .as_ref()
            .is_some_and(|old| old["template_dir"].as_str() == template.to_str());
    let mut actions = json!([{"path":door_path,"action":if dir_exists { "unchanged" } else { "create" }},{"path":destinations[0].path,"action":if destinations[0].exists { "unchanged" } else if stub_replaces { "replace" } else { "create" }},{"path":destinations[1].path,"action":if destinations[1].exists { "unchanged" } else if supersede { "replace" } else { "create" }},{"path":destinations[2].path,"action":if destinations[2].exists { "unchanged" } else { "create" }},{"path":generation_path,"action":if generation_exists { "unchanged" } else if old_generation.is_some() { "replace" } else { "create" }}]);
    if record_attempt || complete_legacy_attempt {
        actions
            .as_array_mut()
            .ok_or_else(|| LaneError::operation("install-door-actions", "actions are absent"))?
            .push(json!({"path":attempt_path,"action":if record_attempt { "record" } else { "complete" }}));
    }
    if let Some(node_plan) = &node_plan {
        actions
            .as_array_mut()
            .ok_or_else(|| LaneError::operation("install-door-actions", "actions are absent"))?
            .extend(node_plan.actions.iter().cloned());
    }
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"install-door","loop":request.loop_name,"dry_run":true,"changed":changed,"actions":actions,"repin_required_runs":repin_required_runs,"repin_unmeasured_runs":inventory.repin_unmeasured_runs,"container_states":inventory.container_states,"agent":agent_configuration,"agent_metadata":agent_metadata,"node_root":node_root,"stub_sha256":stub_digest,"service_sha256":service_digest,"unit_activation_performed":false,"activation":["systemctl --user daemon-reload",format!("systemctl --user start superloop-lane-door@{}.service",request.loop_name)],"wall_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    let attempted = if record_attempt {
        Some(
            json!({"schema":1,"phase":"attempted","loop":request.loop_name,
            "from":old_generation.as_ref().map(|previous| previous["template_dir"].clone()),
            "to":template}),
        )
    } else if complete_legacy_attempt {
        prior_attempt
    } else {
        None
    };
    if record_attempt {
        let destination = Destination {
            path: attempt_path.clone(),
            bytes: serde_json::to_vec_pretty(attempted.as_ref().ok_or_else(|| {
                LaneError::operation("install-door-attempt", "attempt is absent")
            })?)
            .map_err(|error| LaneError::operation("install-door-attempt", error.to_string()))?,
            uid: owner,
            gid: group,
            mode: 0o600,
            exists: false,
        };
        replace_file(owner_home, &destination)?;
    }
    if !dir_exists || !destinations[0].exists {
        let applied = namespace_step(
            owner_home,
            request.program(),
            &request.loop_name,
            template,
            sockets,
            stub,
            &destinations[0].bytes,
            &stub_digest,
            old_stub_digest,
            row.uid,
            &lock,
            fixture_group,
            true,
        )?;
        if applied != private {
            return Err(LaneError::operation(
                "install-door-private",
                "namespace actions changed after preflight",
            ));
        }
    }
    let installed_host_group = host_door_group(owner_home, &door_path, owner)?;
    if preflight_host_group.is_some_and(|group| group != installed_host_group) {
        return Err(LaneError::input(
            "install-door-generation",
            "registered socket group changed after preflight",
        ));
    }
    let generation_bytes = serde_json::to_vec_pretty(&generation(installed_host_group))
        .map_err(|error| LaneError::operation("install-door-generation", error.to_string()))?;
    for destination in destinations.iter_mut().skip(1) {
        if !destination.exists {
            if supersede && destination.path == config.join("door-service") {
                replace_file(owner_home, destination)?;
            } else {
                write_file(owner_home, destination)?;
            }
        }
    }
    if let Some(node_plan) = &node_plan {
        node_plan.apply(&config)?;
    }
    if !generation_exists {
        let row = Destination {
            path: generation_path,
            bytes: generation_bytes,
            uid: owner,
            gid: group,
            mode: 0o600,
            exists: false,
        };
        #[cfg(test)]
        if FAIL_GENERATION_WRITE.with(|fault| fault.replace(false)) {
            return Err(LaneError::operation(
                "install-door-generation",
                "fixture generation write failed",
            ));
        }
        replace_file(owner_home, &row)?;
    }
    if let Some(mut completed) = attempted {
        completed["phase"] = json!("complete");
        let destination = Destination {
            path: attempt_path,
            bytes: serde_json::to_vec_pretty(&completed)
                .map_err(|error| LaneError::operation("install-door-attempt", error.to_string()))?,
            uid: owner,
            gid: group,
            mode: 0o600,
            exists: false,
        };
        replace_file(owner_home, &destination)?;
    }
    Ok(
        json!({"schema":1,"command":"install-door","loop":request.loop_name,"dry_run":false,"changed":changed,"actions":actions,"repin_required_runs":repin_required_runs,"repin_unmeasured_runs":inventory.repin_unmeasured_runs,"container_states":inventory.container_states,"agent":agent_configuration,"agent_metadata":agent_metadata,"node_root":node_root,"stub_sha256":stub_digest,"service_sha256":service_digest,"socket_dir":door_path,"unit_dir":unit_dir,"unit_activation_performed":false,"activation":["systemctl --user daemon-reload",format!("systemctl --user start superloop-lane-door@{}.service",request.loop_name)],"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::{
        BEFORE_OLD_STUB_OPEN, CHANGE_METADATA_AFTER_SET, DoorRequest, FAIL_GENERATION_WRITE,
        PRIVATE_REFUSAL_KINDS, PrivateDoorRequest, create_directory_beneath,
        decode_namespace_report, inspect_directory_beneath, libexec_matches, namespace_step,
        pin_directory_beneath, private_mode_word, private_run_with_handed_identity,
        private_run_with_identity, read_checked_beneath, run_private_entry_fixture, run_with,
        set_directory_metadata,
    };

    fn directory(path: &std::path::Path, mode: u32) {
        fs::create_dir_all(path).expect("fixture directory");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
    }

    fn file(path: &std::path::Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).expect("fixture file");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture file mode");
    }

    fn reviewed_rubric(home: &std::path::Path) {
        file(
            &home.join("permissions/door.md"),
            b"Reviewed fixture rubric.",
            0o644,
        );
    }

    #[allow(clippy::type_complexity)]
    fn install_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        u32,
    ) {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = home.join(".config/loops/alpha");
        directory(&home.join(".config"), 0o700);
        directory(&home.join(".config/loops"), 0o700);
        directory(&config, 0o700);
        file(
            &config.join("door-compute-registration.json"),
            json!({"schema":1,"loop":"alpha","alias":"fixture","mirror_root":"~/mirrors","key_path":config.join("door-key"),"node_root":"/srv/loops/loop-a"}).to_string().as_bytes(),
            0o600,
        );
        crate::door_node::fixture(&config);
        let unit_dir = home.join(".config/systemd/user");
        directory(&home.join(".config/systemd"), 0o700);
        directory(&unit_dir, 0o700);
        file(&home.join(".config/loops/registry.toml"), b"namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n", 0o600);
        let loop_home = home.join(".var/loops/alpha");
        directory(&home.join(".var"), 0o700);
        directory(&home.join(".var/loops"), 0o700);
        directory(&loop_home, 0o700);
        let template = loop_home.join("runner-templates/codex/pin");
        directory(&loop_home.join("runner-templates"), 0o700);
        directory(&loop_home.join("runner-templates/codex"), 0o700);
        directory(&template, 0o700);
        directory(&template.join("libexec"), 0o550);
        let sockets = loop_home.join("sockets");
        directory(&sockets, 0o700);
        file(
            &config.join("workers.toml"),
            format!(
                "template_dir = \"{}\"\nsocket_dir = \"{}\"\n",
                template.display(),
                sockets.display()
            )
            .as_bytes(),
            0o600,
        );
        file(&config.join("install-generation.json"), &serde_json::to_vec(&json!({"phase":"complete","template_dir":template,"socket_dir":sockets,"unit_dir":unit_dir})).expect("generation"), 0o600);
        let stub = home.join("door-stub-fixture");
        let service = home.join("door-service-fixture");
        file(&stub, b"#!/bin/sh\nexit 125\n", 0o750);
        file(&service, b"#!/bin/sh\nexit 125\n", 0o750);
        let group = nix::unistd::Gid::effective().as_raw();
        (
            fixture, config, unit_dir, template, sockets, stub, service, group,
        )
    }

    /// # Panics
    /// Panics only if a production command violates the node replacement contract.
    /// ´test:unit:door-node-registration-install-replacement´
    #[test]
    fn door_node_registration_install_replacement() {
        let (fixture, config, _, _, _, stub, service, group) = install_fixture();
        let home = fixture.path();
        let request = |dry_run| DoorRequest {
            loop_name: "alpha".into(),
            dry_run,
            podman_bin: PathBuf::new(),
        };
        let invoke =
            |args: &[String]| crate::door_node::run(home, args).expect("registration command");
        let held = fs::File::open(&config).expect("held config");
        let owner = nix::unistd::Uid::effective().as_raw();
        let route = || crate::door::registered_route(&held, &config, "alpha", owner);
        let initial =
            run_with(home, &request(false), &stub, &service, Some(group)).expect("initial install");
        assert!(initial["changed"].as_u64().expect("count") > 0);
        let old_config = fs::read(config.join("door-ssh_config")).expect("old config");
        let mut args = [
            "alpha",
            "--alias",
            "fixture",
            "--address",
            "2001:db8::2",
            "--port",
            "2200",
            "--user",
            "replacement",
            "--host-key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "--dry-run",
        ]
        .map(str::to_owned)
        .to_vec();
        let preview = invoke(&args);
        assert_eq!(
            fs::read(config.join("door-ssh_config")).expect("preview unchanged"),
            old_config
        );
        args.pop();
        args.extend([
            "--expect-digest".into(),
            preview["preview_sha256"].as_str().expect("digest").into(),
        ]);
        invoke(&args);
        assert_eq!(
            route().expect_err("install required").kind,
            "door-node-derived-drift"
        );
        let planned =
            run_with(home, &request(true), &stub, &service, Some(group)).expect("install preview");
        for name in ["door-ssh_config", "door-known_hosts"] {
            let row = planned["actions"]
                .as_array()
                .expect("actions")
                .iter()
                .find(|row| row["path"] == json!(config.join(name)))
                .expect("derived action");
            assert_eq!(row["action"], "replace");
            assert_ne!(row["before"], row["after"]);
        }
        run_with(home, &request(false), &stub, &service, Some(group)).expect("replacement install");
        route().expect("matching derivatives");
        assert!(
            fs::read_to_string(config.join("door-known_hosts"))
                .expect("host key")
                .starts_with("[2001:db8::2]:2200 ssh-ed25519 ")
        );
        assert_eq!(
            run_with(home, &request(true), &stub, &service, Some(group)).expect("idempotent")["changed"],
            0
        );
        assert_eq!(
            crate::door_node::run(home, &args)
                .expect_err("old preview refuses")
                .kind,
            "door-node-digest"
        );
        fs::remove_file(config.join("door-node-registration.json")).expect("remove registration");
        let error = run_with(home, &request(true), &stub, &service, Some(group))
            .expect_err("legacy pair refused");
        assert_eq!(error.kind, "door-node-unregistered-files");
        assert!(
            error.detail.contains("door-ssh_config") && error.detail.contains("door-known_hosts")
        );
        for name in ["door-ssh_config", "door-known_hosts"] {
            fs::remove_file(config.join(name)).expect("remove derivative");
        }
        assert_eq!(
            run_with(home, &request(true), &stub, &service, Some(group))
                .expect_err("missing node")
                .kind,
            "door-node-missing"
        );
    }

    /// ´test:unit:door-parser-selects-program-and-refuses-invalid-options´
    #[test]
    fn door_parser_selects_program_and_refuses_invalid_options() {
        let default = DoorRequest::parse(&["alpha".into()]).expect("default form");
        assert_eq!(default.selected_program(), None);
        assert_eq!(default.program(), Path::new("/usr/bin/podman"));
        assert!(!default.dry_run);
        for words in [
            vec!["alpha", "--dry-run", "--podman-bin", "/selected/podman"],
            vec!["alpha", "--podman-bin", "/selected/podman", "--dry-run"],
        ] {
            let words = words.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let request = DoorRequest::parse(&words).expect("named program");
            assert_eq!(
                request.selected_program(),
                Some(Path::new("/selected/podman"))
            );
            assert!(request.dry_run);
        }
        for words in [
            vec![],
            vec!["alpha", "--podman-bin"],
            vec!["alpha", "--podman-bin", ""],
            vec!["alpha", "--podman-bin", "/one", "--podman-bin", "/two"],
            vec!["alpha", "--dry-run", "--dry-run"],
            vec!["alpha", "--unknown"],
            vec!["alpha", "extra"],
        ] {
            let words = words.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                DoorRequest::parse(&words).err().expect("invalid form").kind,
                "install-door-usage"
            );
        }
    }

    /// ´test:unit:door-absent-selected-program-keeps-presence-unknown´
    #[test]
    fn door_absent_selected_program_keeps_presence_unknown() {
        let (fixture, config, _, _, _, stub, service, group) = install_fixture();
        let home = fixture.path();
        let runs = home.join(".var/loops/alpha/runs");
        directory(&runs, 0o700);
        file(&home.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display()).as_bytes(), 0o600);
        let runtime = home.join("recorded-runtime");
        crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n")
            .expect("recorded program");
        let record = json!({"schema":1,"loop":"alpha","run":"R","phase":"started","worker_uid":3000,"launcher_pid":u32::MAX,"launcher_start":1,"plan":{"runtime_argv":[runtime]}});
        crate::launch::publish_reservation(&crate::launch::reservation_path(&runs, "R"), &record)
            .expect("reservation");
        let absent = home.join("absent-selected-program");
        let mut request = DoorRequest::parse(&[
            "alpha".into(),
            "--podman-bin".into(),
            absent.to_str().expect("fixture path").into(),
            "--dry-run".into(),
        ])
        .expect("absent program form");
        for held in [false, true] {
            let _reader = held
                .then(|| crate::install::lock_loop_config(&config, true).expect("shared reader"));
            request.dry_run = true;
            let preview =
                run_with(home, &request, &stub, &service, Some(group)).expect("blocked preview");
            assert_eq!(preview["blocked"], true);
            assert_eq!(preview["actions"], json!([]));
            let detail = preview["busy"][0].as_str().expect("busy detail");
            assert!(
                detail.contains("container unknown, launcher gone"),
                "{detail}"
            );
            assert!(
                detail.contains(absent.to_str().expect("fixture path")),
                "{detail}"
            );
            assert!(
                detail.contains("owner-program:") && detail.contains("ENOENT"),
                "{detail}"
            );
            request.dry_run = false;
            let refusal = run_with(home, &request, &stub, &service, Some(group))
                .expect_err("unknown blocks install");
            assert_eq!(refusal.kind, "install-busy");
            assert!(refusal.detail.contains(detail), "{}", refusal.detail);
            assert!(!config.join("door-install-generation.json").exists());
        }
    }

    fn private_words() -> Vec<String> {
        [
            "alpha",
            "/owner",
            "/stub",
            "41001",
            "aabbccdd".repeat(8).as_str(),
            "-",
            "preview",
            "--verified-home-fd",
            "0",
            "--verified-install-lock-fd",
            "1",
            "--verified-stub-fd",
            "2",
            "--verified-template-fd",
            "3",
            "--verified-libexec-fd",
            "4",
            "--verified-socket-root-fd",
            "5",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    /// ´test:unit:door-private-parser-refuses-each-changed-form´
    #[test]
    fn door_private_parser_refuses_each_changed_form() {
        let valid = private_words();
        let preview = PrivateDoorRequest::parse(&valid).expect("preview form");
        assert!(!preview.apply);
        assert!(!preview.dry_run);
        let mut dry_run = valid.clone();
        dry_run[6] = "dry-run".into();
        let dry_run = PrivateDoorRequest::parse(&dry_run).expect("dry-run form");
        assert!(dry_run.dry_run);
        assert!(!dry_run.apply);
        let mut applied = valid.clone();
        applied[6] = "apply".into();
        let applied = PrivateDoorRequest::parse(&applied).expect("apply form");
        assert!(applied.apply);
        assert!(!applied.dry_run);
        assert_eq!(private_mode_word(false, false), "dry-run");
        assert_eq!(private_mode_word(false, true), "preview");
        assert_eq!(private_mode_word(true, true), "apply");
        let cases = [
            (None, "private form is incomplete"),
            (Some((7, "--wrong")), "verified descriptors are absent"),
            (Some((13, "--wrong")), "verified descriptors are absent"),
            (Some((16, "7")), "verified descriptors are absent"),
            (Some((18, "6")), "verified descriptors are absent"),
            (Some((0, "BAD")), "bad loop name"),
            (Some((3, "uid")), "row uid is invalid"),
            (Some((4, "not-a-digest")), "stub digest is invalid"),
            (Some((5, "not-a-digest")), "stub digest is invalid"),
            (Some((6, "unknown")), "private mode is invalid"),
        ];
        for (change, detail) in cases {
            let mut words = valid.clone();
            if let Some((index, value)) = change {
                words[index] = value.into();
            } else {
                words.pop();
            }
            let error = PrivateDoorRequest::parse(&words).expect_err("invalid private form");
            assert_eq!(error.kind, "install-door-private");
            assert!(error.detail.contains(detail), "{}", error.detail);
        }
    }

    /// ´test:unit:door-private-report-preserves-every-child-refusal-kind´
    #[test]
    fn door_private_report_preserves_every_child_refusal_kind() {
        for &kind in PRIVATE_REFUSAL_KINDS {
            let error = decode_namespace_report(
                json!({"schema":1,"error":{"status":2,"kind":kind,"detail":"detail"}}),
            )
            .expect_err("typed refusal");
            assert_eq!(error.kind, kind);
            assert_eq!(error.detail, "detail");
        }
        for report in [
            json!({"schema":1,"error":{"status":2,"kind":"settings-read"}}),
            json!({"schema":1,"error":{"kind":"settings-read","detail":"detail"}}),
            json!({"schema":1,"error":{"status":3,"kind":"settings-read","detail":"detail"}}),
            json!({"schema":1,"error":{"status":2,"kind":"settings-read","detail":"detail","extra":1}}),
            json!({"schema":1,"error":{"status":2,"kind":"settings-read","detail":"detail"},"extra":1}),
            json!({"schema":1,"error":{"status":2,"detail":"detail"}}),
            json!({"schema":1,"error":{"status":2,"kind":"Other","detail":"detail"}}),
            json!({"schema":1,"dir_exists":false,"stub_exists":"false"}),
            json!({"schema":2,"dir_exists":false,"stub_exists":false}),
            json!({"schema":1,"dir_exists":false,"stub_exists":false,"extra":1}),
        ] {
            let error = decode_namespace_report(report).expect_err("changed report shape");
            assert_eq!(error.kind, "install-door-private");
        }
        assert_eq!(
            decode_namespace_report(json!({"schema":1,"dir_exists":false,"stub_exists":false}))
                .expect("report")["dir_exists"],
            false
        );
    }

    /// ´test:unit:install-door-decoder-preserves-three-child-refusals´
    #[test]
    fn install_door_decoder_preserves_three_child_refusals() {
        for kind in ["install-door-verify", "build-snapshot", "hash-pin"] {
            let refusal = decode_namespace_report(
                json!({"schema":1,"error":{"status":2,"kind":kind,"detail":"measured child refusal"}}),
            )
            .expect_err("child refusal retains its kind");
            assert_eq!(refusal.kind, kind);
            assert_eq!(refusal.detail, "measured child refusal");
        }
        let malformed = decode_namespace_report(
            json!({"schema":1,"error":{"status":2,"kind":"Hash-Pin","detail":"changed"}}),
        )
        .expect_err("malformed kind refuses");
        assert_eq!(malformed.kind, "install-door-private");
        assert_eq!(malformed.detail, "private refusal kind differs");
    }

    /// ´test:unit:door-private-body-uses-handed-roots-beneath-overflow-ancestor´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_private_body_uses_handed_roots_beneath_overflow_ancestor() {
        let fixture = tempfile::tempdir().expect("fixture");
        let home = fixture.path();
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = 41001;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = home.join(".config/loops/alpha");
        for path in [
            home.join(".config"),
            home.join(".config/loops"),
            config.clone(),
            home.join(".var"),
            home.join(".var/loops"),
            home.join(".var/loops/alpha"),
            home.join(".var/loops/alpha/runner-templates"),
            home.join(".var/loops/alpha/runner-templates/codex"),
            home.join(".var/loops/alpha/runner-templates/codex/pin"),
            home.join(".var/loops/alpha/sockets"),
        ] {
            directory(&path, 0o700);
        }
        let libexec = home.join(".var/loops/alpha/runner-templates/codex/pin/libexec");
        directory(&libexec, 0o550);
        let registry = home.join(".config/loops/registry.toml");
        file(&registry, b"namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n", 0o600);
        let settings = config.join("workers.toml");
        file(
            &settings,
            format!(
                "template_dir = \"{}\"\nsocket_dir = \"{}\"\n",
                libexec.parent().expect("template").display(),
                home.join(".var/loops/alpha/sockets").display()
            )
            .as_bytes(),
            0o600,
        );
        let stub = home.join("stub");
        file(&stub, b"#!/bin/sh\nexit 125\n", 0o750);
        let bytes = fs::read(&stub).expect("stub bytes");
        let digest = crate::build::sha256_bytes(&bytes, home).expect("digest");
        let mut request = PrivateDoorRequest {
            loop_name: "alpha".into(),
            owner_home: home.into(),
            stub: stub.clone(),
            row_uid: group,
            stub_sha256: digest,
            old_stub_sha256: None,
            apply: false,
            dry_run: false,
        };
        let source = || -> OwnedFd { fs::File::open(&stub).expect("stub source").into() };
        for (fd, expected_owner) in [
            (source(), owner),
            (fs::File::open(home).expect("foreign home").into(), 3001),
        ] {
            let error = crate::home::activate_handed_home(home, &fd, expected_owner)
                .err()
                .expect("invalid handed home");
            assert_eq!(error.kind, "verified-prefix");
        }
        let writable_home = home.join("writable-home");
        directory(&writable_home, 0o770);
        let writable: OwnedFd = fs::File::open(&writable_home).expect("writable fd").into();
        let error = crate::home::activate_handed_home(home, &writable, owner)
            .err()
            .expect("writable handed home");
        assert_eq!(error.kind, "verified-prefix");
        let error =
            private_run_with_identity(&request, source(), 0, None).expect_err("non-root namespace");
        assert_eq!(error.kind, "install-door-private");
        assert_eq!(error.detail, "rootless namespace root is required");
        assert!(libexec_matches(libc::S_IFDIR | 0o550, 0, group, 0, group));
        assert!(!libexec_matches(
            libc::S_IFDIR | 0o550,
            owner,
            owner,
            0,
            group
        ));
        let view = Some((owner, group));
        let held = fs::File::open(home).expect("home descriptor");
        let template = libexec.parent().expect("template");
        let sockets = home.join(".var/loops/alpha/sockets");
        let home_fd: OwnedFd = fs::File::open(home).expect("handed home").into();
        let template_fd =
            pin_directory_beneath(&home_fd, home, template, owner).expect("handed template");
        let libexec_fd =
            pin_directory_beneath(&home_fd, home, &libexec, owner).expect("handed libexec");
        let sockets_fd =
            pin_directory_beneath(&home_fd, home, &sockets, owner).expect("handed socket root");
        let through_handoff = crate::home::with_fixture_root_identity(65534, || {
            let overflow =
                crate::home::verify_host_prefix_from(std::path::Path::new("/"), home, owner, 0)
                    .expect_err("an overflow root cannot start an absolute walk");
            assert_eq!(overflow.kind, "unsafe-path");
            let _anchor = crate::home::activate_handed_home(home, &held, owner)
                .expect("private anchor beneath handed home");
            private_run_with_handed_identity(
                &request,
                &home_fd,
                source(),
                &template_fd,
                &libexec_fd,
                &sockets_fd,
                owner,
                view,
            )
            .expect("overflow root is irrelevant to handed roots")
        });
        assert_eq!(through_handoff["stub_exists"], false);
        let _live_run = crate::install::lock_loop_config(&config, true).expect("live shared lock");
        let stub_fd = source();
        let mut words = private_words();
        words[1] = home.display().to_string();
        words[2] = stub.display().to_string();
        words[4] = request.stub_sha256.clone();
        for (apply, writable) in [(false, false), (false, true), (true, true)] {
            let (sender, receiver) = UnixStream::pair().expect("entry descriptor channel");
            let lock_fd =
                crate::install::lock_loop_config(&config, true).expect("handed shared lock");
            crate::home::send_private_descriptors(
                &sender,
                &[
                    home_fd.as_raw_fd(),
                    lock_fd.as_fd().as_raw_fd(),
                    stub_fd.as_raw_fd(),
                    template_fd.as_raw_fd(),
                    libexec_fd.as_raw_fd(),
                    sockets_fd.as_raw_fd(),
                ],
            )
            .expect("six handed descriptors");
            words[6] = private_mode_word(apply, writable).into();
            let entry = crate::home::with_fixture_root_identity(65_534, || {
                run_private_entry_fixture(&words, &receiver, owner, (owner, group))
            });
            if writable {
                let error = entry.expect_err("changing entry needs an exclusive lock");
                assert_eq!(error.kind, "install-lock");
            } else {
                let report = entry.expect("shared dry run beneath overflow root");
                assert_eq!(report["dir_exists"], false);
                assert_eq!(report["stub_exists"], false);
            }
        }
        assert!(!sockets.join("door").exists());
        assert!(!libexec.join("ssh").exists());
        let _anchor = crate::home::activate_private_home(home, &held, owner)
            .expect("private anchor for remaining fixture refusals");
        let foreign_owner = set_directory_metadata(&libexec_fd, 3001, owner, 0o550)
            .expect_err("foreign owner cannot change handed directory");
        assert_eq!(foreign_owner.kind, "install-door-owner");
        let actual_group = nix::sys::stat::fstat(&libexec_fd)
            .expect("libexec identity")
            .st_gid;
        CHANGE_METADATA_AFTER_SET.with(|slot| slot.set(true));
        let metadata = set_directory_metadata(&libexec_fd, owner, actual_group, 0o550)
            .expect_err("changed metadata after setter");
        assert_eq!(metadata.kind, "install-door-mode");
        assert_eq!(metadata.detail, "directory metadata differs");
        fs::set_permissions(&libexec, fs::Permissions::from_mode(0o550))
            .expect("restore libexec mode");
        let installed_stub = libexec.join("ssh");
        let missing = read_checked_beneath(&libexec_fd, &installed_stub, (owner, owner, 0o550))
            .expect_err("absent old stub");
        assert_eq!(missing.kind, "install-door-conflict");
        fs::set_permissions(&libexec, fs::Permissions::from_mode(0o750))
            .expect("open fixture directory for old stub");
        file(&installed_stub, b"old stub", 0o550);
        assert_eq!(
            read_checked_beneath(&libexec_fd, &installed_stub, (owner, owner, 0o550))
                .expect("old stub beneath descriptor"),
            b"old stub"
        );
        let replacement = libexec.join("replacement");
        file(&replacement, b"replacement stub", 0o550);
        let raced_name = installed_stub.clone();
        BEFORE_OLD_STUB_OPEN.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::rename(&replacement, &raced_name).expect("swap old stub after metadata read");
            }));
        });
        let swapped = read_checked_beneath(&libexec_fd, &installed_stub, (owner, owner, 0o550))
            .expect_err("changed old stub inode");
        assert_eq!(swapped.kind, "install-door-conflict");
        assert_eq!(swapped.detail, "old stub identity changed");
        fs::set_permissions(&installed_stub, fs::Permissions::from_mode(0o700))
            .expect("wrong stub mode");
        let wrong_mode = read_checked_beneath(&libexec_fd, &installed_stub, (owner, owner, 0o550))
            .expect_err("old stub mode differs");
        assert_eq!(wrong_mode.detail, "old stub identity differs");
        fs::remove_file(&installed_stub).expect("remove old stub fixture");
        let oversized_old = fs::File::create(&installed_stub).expect("oversized old stub");
        oversized_old
            .set_len((super::FILE_LIMIT + 1) as u64)
            .expect("sparse old stub length");
        oversized_old
            .set_permissions(fs::Permissions::from_mode(0o550))
            .expect("old stub mode");
        let oversized = read_checked_beneath(&libexec_fd, &installed_stub, (owner, owner, 0o550))
            .expect_err("oversized old stub");
        assert_eq!(oversized.detail, "old stub exceeds byte limit");
        fs::remove_file(&installed_stub).expect("remove oversized old stub");
        std::os::unix::fs::symlink(&stub, &installed_stub).expect("linked old stub");
        let linked = read_checked_beneath(&libexec_fd, &installed_stub, (owner, owner, 0o550))
            .expect_err("linked old stub");
        assert_eq!(linked.detail, "old stub identity differs");
        fs::remove_file(&installed_stub).expect("remove linked old stub");
        fs::set_permissions(&libexec, fs::Permissions::from_mode(0o550))
            .expect("restore fixture libexec");
        let occupied = sockets.join("occupied");
        directory(&occupied, 0o700);
        let conflict = inspect_directory_beneath(&sockets_fd, &occupied, owner, owner, 0o750)
            .expect_err("occupied directory mode differs");
        assert_eq!(conflict.kind, "install-door-conflict");
        let create = create_directory_beneath(&sockets_fd, &occupied, owner, owner, 0o750)
            .expect_err("occupied directory cannot be created");
        assert_eq!(create.kind, "install-door-mkdir");
        fs::remove_dir(&occupied).expect("remove occupied fixture");
        for (wrong_template, wrong_libexec, wrong_sockets) in [
            (&sockets_fd, &libexec_fd, &sockets_fd),
            (&template_fd, &sockets_fd, &sockets_fd),
            (&template_fd, &libexec_fd, &template_fd),
        ] {
            let error = private_run_with_handed_identity(
                &request,
                &home_fd,
                source(),
                wrong_template,
                wrong_libexec,
                wrong_sockets,
                owner,
                view,
            )
            .expect_err("changed handed directory");
            assert_eq!(error.kind, "install-door-path");
            assert_eq!(error.detail, "handed directory identity differs");
        }
        let dotted = home.join("../escape");
        for bad_path in [std::path::Path::new("/outside"), &dotted] {
            let error = pin_directory_beneath(&home_fd, home, bad_path, owner)
                .expect_err("untrusted directory name");
            assert_eq!(error.kind, "install-door-path");
        }
        let error =
            pin_directory_beneath(&home_fd, home, home, owner).expect_err("empty relative path");
        assert_eq!(error.detail, "directory is the handed owner home");
        let error = pin_directory_beneath(&home_fd, home, &home.join("missing"), owner)
            .expect_err("missing child");
        assert_eq!(error.kind, "install-door-path");
        let error =
            pin_directory_beneath(&home_fd, home, template, 3001).expect_err("foreign parent");
        assert_eq!(error.detail, "directory parent differs from handed owner");
        let error = pin_directory_beneath(&home_fd, home, &writable_home, owner)
            .expect_err("writable child");
        assert_eq!(error.detail, "directory differs from handed owner");
        fs::set_permissions(home.join(".var"), fs::Permissions::from_mode(0o770))
            .expect("writable parent");
        let error =
            pin_directory_beneath(&home_fd, home, template, owner).expect_err("writable ancestor");
        assert_eq!(error.kind, "install-door-path");
        fs::set_permissions(home.join(".var"), fs::Permissions::from_mode(0o700))
            .expect("restore parent");
        let report =
            private_run_with_identity(&request, source(), owner, view).expect("namespace preview");
        assert_eq!(report["stub_exists"], false);
        assert!(!libexec.join("ssh").exists());
        let error = private_run_with_identity(&request, source(), owner, Some((owner, 3001)))
            .expect_err("namespace group differs");
        assert_eq!(error.kind, "install-door-template");
        assert_eq!(error.detail, "template libexec differs");
        request.row_uid = 3000;
        let error =
            private_run_with_identity(&request, source(), owner, view).expect_err("changed row");
        assert_eq!(error.kind, "install-door-row");
        request.row_uid = group;
        file(
            &settings,
            b"template_dir = \"/wrong\"\nsocket_dir = \"/wrong\"\n",
            0o600,
        );
        let error =
            private_run_with_identity(&request, source(), owner, view).expect_err("changed roots");
        assert_eq!(error.kind, "install-door-setting");
        let settings_bytes = format!(
            "template_dir = \"{}\"\nsocket_dir = \"{}\"\n",
            libexec.parent().expect("template").display(),
            home.join(".var/loops/alpha/sockets").display()
        );
        for (source_text, detail) in [
            ("", "template_dir is absent"),
            ("template_dir = \"/tmp\"\n", "socket_dir is absent"),
        ] {
            file(&settings, source_text.as_bytes(), 0o600);
            let error = private_run_with_identity(&request, source(), owner, view)
                .expect_err("missing root setting");
            assert_eq!(error.kind, "install-door-setting");
            assert_eq!(error.detail, detail);
        }
        file(&settings, settings_bytes.as_bytes(), 0o600);
        fs::remove_file(&settings).expect("remove settings");
        let error = private_run_with_identity(&request, source(), owner, view)
            .expect_err("missing settings");
        assert_eq!(error.kind, "settings-read");
        file(&settings, settings_bytes.as_bytes(), 0o600);
        file(&registry, b"not toml = [", 0o600);
        let error = private_run_with_identity(&request, source(), owner, view)
            .expect_err("malformed registry");
        assert_eq!(error.kind, "install-door-row");
        file(&registry, b"namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n", 0o600);
        let error = private_run_with_identity(
            &request,
            fs::File::open(&libexec).expect("directory fd").into(),
            owner,
            view,
        )
        .expect_err("non-file source");
        assert_eq!(error.kind, "install-door-source");
        let write_only = fs::OpenOptions::new()
            .write(true)
            .open(&stub)
            .expect("write-only source");
        let error = private_run_with_identity(&request, write_only.into(), owner, view)
            .expect_err("unreadable source");
        assert_eq!(error.kind, "install-door-source");
        request.stub_sha256 = "0".repeat(64);
        let error =
            private_run_with_identity(&request, source(), owner, view).expect_err("changed digest");
        assert_eq!(error.kind, "install-door-source");
        assert_eq!(error.detail, "stub changed after host preflight");
        let oversized = home.join("oversized");
        let oversized_file = fs::File::create(&oversized).expect("oversized file");
        oversized_file
            .set_len((super::FILE_LIMIT + 1) as u64)
            .expect("sparse length");
        let oversized_source = fs::File::open(&oversized).expect("oversized source");
        let error = private_run_with_identity(&request, oversized_source.into(), owner, view)
            .expect_err("oversized source");
        assert_eq!(error.kind, "install-door-source");
        assert_eq!(error.detail, "stub exceeds byte limit");
        assert!(!home.join(".var/loops/alpha/sockets/door").exists());
    }

    /// ´test:unit:door-template-is-checked-in-the-namespace-view´
    #[test]
    fn door_template_is_checked_in_the_namespace_view() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = home.join(".config/loops/alpha");
        directory(&home.join(".config"), 0o700);
        directory(&home.join(".config/loops"), 0o700);
        directory(&config, 0o700);
        let template = home.join("runner-templates/codex/pin");
        directory(&home.join("runner-templates"), 0o700);
        directory(&home.join("runner-templates/codex"), 0o700);
        directory(&template, 0o700);
        directory(&template.join("libexec"), 0o550);
        let sockets = home.join("sockets");
        directory(&sockets, 0o700);
        let group = nix::unistd::Gid::effective().as_raw();
        let row_uid = if group == 41001 { 41002 } else { 41001 };
        assert_ne!(row_uid, group, "host-view comparison must fail");
        let lock = crate::install::lock_loop_config(&config, false).expect("owner lock");
        let stub = home.join("stub");
        file(&stub, b"#!/bin/sh\nexit 125\n", 0o750);
        let bytes = fs::read(&stub).expect("stub bytes");
        let digest = crate::build::sha256_bytes(&bytes, home).expect("digest");
        let preview = namespace_step(
            home,
            Path::new("/usr/bin/podman"),
            "alpha",
            &template,
            &sockets,
            &stub,
            &bytes,
            &digest,
            None,
            row_uid,
            &lock,
            Some(group),
            false,
        )
        .expect("namespace preview");
        assert_eq!(preview["dir_exists"], false);
        assert_eq!(preview["stub_exists"], false);
        assert!(!sockets.join("door").exists());
        let applied = namespace_step(
            home,
            Path::new("/usr/bin/podman"),
            "alpha",
            &template,
            &sockets,
            &stub,
            &bytes,
            &digest,
            None,
            row_uid,
            &lock,
            Some(group),
            true,
        )
        .expect("namespace apply");
        assert_eq!(applied, preview);
        assert!(sockets.join("door").is_dir());
        assert!(template.join("libexec/ssh").is_file());
    }

    /// ´test:unit:door-namespace-child-refusal-reaches-owner-without-a-write´
    #[test]
    fn door_namespace_child_refusal_reaches_owner_without_a_write() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = home.join(".config/loops/alpha");
        directory(&home.join(".config"), 0o700);
        directory(&home.join(".config/loops"), 0o700);
        directory(&config, 0o700);
        let template = home.join("runner-templates/codex/pin");
        directory(&home.join("runner-templates"), 0o700);
        directory(&home.join("runner-templates/codex"), 0o700);
        directory(&template, 0o700);
        directory(&template.join("libexec"), 0o750);
        let sockets = home.join("sockets");
        directory(&sockets, 0o700);
        let lock = crate::install::lock_loop_config(&config, false).expect("owner lock");
        let stub = home.join("stub");
        file(&stub, b"#!/bin/sh\nexit 125\n", 0o750);
        let bytes = fs::read(&stub).expect("stub bytes");
        let digest = crate::build::sha256_bytes(&bytes, home).expect("digest");
        let error = namespace_step(
            home,
            Path::new("/usr/bin/podman"),
            "alpha",
            &template,
            &sockets,
            &stub,
            &bytes,
            &digest,
            None,
            41001,
            &lock,
            Some(nix::unistd::Gid::effective().as_raw()),
            true,
        )
        .expect_err("child refusal");
        assert_eq!(error.kind, "install-door-template");
        assert_eq!(error.detail, "template libexec differs");
        let delivered = decode_namespace_report(json!({"schema":1,"error":{"status":error.status,"kind":error.kind,"detail":error.detail}}))
            .expect_err("typed child refusal");
        assert_eq!(delivered.kind, "install-door-template");
        assert_eq!(delivered.detail, "template libexec differs");
        assert!(!sockets.join("door").exists());
        assert!(!template.join("libexec/ssh").exists());
        assert!(!config.join("door-install-generation.json").exists());
    }

    /// ´test:unit:door-preview-shares-a-live-run-lock-and-change-names-its-holder´
    #[test]
    fn door_preview_shares_a_live_run_lock_and_change_names_its_holder() {
        let (fixture, config, _unit_dir, template, sockets, stub, service, group) =
            install_fixture();
        let home = fixture.path();
        let runs = home.join(".var/loops/alpha/runs");
        directory(&runs, 0o700);
        file(
            &home.join(".config/loops/registry.toml"),
            format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display()).as_bytes(),
            0o600,
        );
        file(
            &config.join("workers.toml"),
            format!(
                "template_dir = \"{}\"\nsocket_dir = \"{}\"\nruns_root = \"{}\"\n",
                template.display(),
                sockets.display(),
                runs.display()
            )
            .as_bytes(),
            0o600,
        );
        let held = [
            crate::fixture_exec::SharedLauncher::start(&config),
            crate::fixture_exec::SharedLauncher::start(&config),
        ];
        for ((run, worker), launcher) in [("R", 3000), ("S", 3001)].into_iter().zip(&held) {
            let (pid, start) = launcher.identity();
            file(
                &crate::launch::reservation_path(&runs, run),
                &serde_json::to_vec(&json!({"schema":1,"loop":"alpha","run":run,"phase":"started","worker_uid":worker,"launcher_pid":pid,"launcher_start":start})).expect("reservation"),
                0o600,
            );
        }
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: true,
        };
        let preview =
            run_with(home, &request, &stub, &service, Some(group)).expect("shared dry run");
        assert_eq!(preview["blocked"], true);
        assert_eq!(preview["changed"], 0);
        assert_eq!(preview["actions"], json!([]));
        assert_eq!(
            preview["busy"],
            json!(["run R (started)", "run S (started)"])
        );
        assert!(!sockets.join("door").exists());
        request.dry_run = false;
        let busy = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("live run blocks change");
        assert_eq!(busy.kind, "install-busy");
        assert!(busy.detail.contains("run R (started)"), "{busy:?}");
        assert!(busy.detail.contains("run S (started)"), "{busy:?}");
        drop(held);
        for run in ["R", "S"] {
            fs::remove_file(crate::launch::reservation_path(&runs, run))
                .expect("remove settled reservation");
        }
        let reader = crate::install::lock_loop_config(&config, true).expect("shared reader");
        let shared = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("shared configuration reader blocks change");
        assert_eq!(shared.kind, "install-busy");
        assert!(
            shared
                .detail
                .contains("launch planning, a starting round, census, exercise, install --pilot --refresh-proxy, record-hosts --list, or a dry run"),
            "{shared:?}"
        );
        drop(reader);
        let installing = crate::install::lock_loop_config(&config, false).expect("install lock");
        request.dry_run = true;
        let exclusive = run_with(home, &request, &stub, &service, Some(group))
            .expect("exclusive configuration change blocks preview");
        assert_eq!(exclusive["blocked"], true);
        assert!(
            exclusive["busy"][0]
                .as_str().expect("holder")
                .contains("install-door, install, repair, build, retire, record-hosts, pause/resume, or prepare"),
            "{exclusive:?}"
        );
        drop(installing);
        let idle_preview =
            run_with(home, &request, &stub, &service, Some(group)).expect("idle preview");
        request.dry_run = false;
        let changed = run_with(home, &request, &stub, &service, Some(group)).expect("idle install");
        assert_eq!(changed["actions"], idle_preview["actions"]);
        assert_eq!(changed["changed"], idle_preview["changed"]);
    }

    /// ´test:unit:door-orphan-preflight-blocks-change-and-reports-preview-without-lock-holder´
    #[test]
    fn door_orphan_preflight_blocks_change_and_reports_preview_without_lock_holder() {
        for worker in [3000, 3001] {
            let (fixture, config, _, _, _, stub, service, group) = install_fixture();
            let home = fixture.path();
            assert_ne!(nix::unistd::Uid::effective().as_raw(), worker);
            let runs = home.join(".var/loops/alpha/runs");
            directory(&runs, 0o700);
            file(&home.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display()).as_bytes(), 0o600);
            let runtime = home.join("runtime-fixture");
            crate::fixture_exec::write_executable(
                &runtime,
                b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nprintf 'running\\n'\n",
            )
            .expect("fixture executable");
            let record = json!({"schema":1,"loop":"alpha","run":"R","phase":"started","worker_uid":worker,"launcher_pid":u32::MAX,"launcher_start":1,"plan":{"runtime_argv":[home.join("absent-recorded-program")]}});
            crate::launch::publish_reservation(
                &crate::launch::reservation_path(&runs, "R"),
                &record,
            )
            .expect("orphan");
            let mut request = DoorRequest::parse(&[
                "alpha".into(),
                "--podman-bin".into(),
                runtime.to_str().expect("fixture path").into(),
                "--dry-run".into(),
            ])
            .expect("named program form");
            let preview =
                run_with(home, &request, &stub, &service, Some(group)).expect("orphan preview");
            assert_eq!(preview["blocked"], true);
            assert_eq!(
                preview["busy"],
                json!(["run R (started; container alive, launcher gone)"])
            );
            request.dry_run = false;
            let refusal = run_with(home, &request, &stub, &service, Some(group))
                .expect_err("orphan blocks free configuration lock");
            assert_eq!(refusal.kind, "install-busy");
            assert_eq!(
                refusal.detail,
                "run R (started; container alive, launcher gone)"
            );
            let held = crate::install::lock_loop_config(&config, true).expect("other reader");
            let busy =
                run_with(home, &request, &stub, &service, Some(group)).expect_err("busy detail");
            assert!(busy.detail.contains("container alive, launcher gone"));
            drop(held);
            crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 9\n")
                .expect("unknown runtime");
            let unknown = run_with(home, &request, &stub, &service, Some(group))
                .expect_err("unknown container blocks change");
            assert!(unknown.detail.contains("container unknown, launcher gone"));
            request.dry_run = true;
            let preview =
                run_with(home, &request, &stub, &service, Some(group)).expect("unknown preview");
            assert_eq!(preview["blocked"], true);
            assert!(
                preview["busy"][0]
                    .as_str()
                    .expect("detail")
                    .contains("container unknown, launcher gone")
            );
            request.dry_run = false;
            crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nprintf 'exited\\n'\n")
                .expect("exited runtime");
            request.dry_run = true;
            let exited = run_with(home, &request, &stub, &service, Some(group))
                .expect("exited storage is not live");
            assert_eq!(
                exited["container_states"],
                json!([{"run":"R","states":["exited"],"program":runtime}])
            );
            assert_ne!(exited["blocked"], true);
            request.dry_run = false;
            let installed = run_with(home, &request, &stub, &service, Some(group))
                .expect("absent orphan permits change");
            assert_eq!(installed["changed"], 6);
        }
    }

    /// ´test:unit:door-preflight-admits-terminal-pre-driver-failure-but-refuses-unknown-launcher´
    #[test]
    fn door_preflight_admits_terminal_pre_driver_failure_but_refuses_unknown_launcher() {
        for worker in [3000, 3001] {
            let (fixture, _, _, _, _, stub, service, group) = install_fixture();
            let home = fixture.path();
            assert_ne!(nix::unistd::Uid::effective().as_raw(), worker);
            let runs = home.join(".var/loops/alpha/runs");
            directory(&runs, 0o700);
            file(&home.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display()).as_bytes(), 0o600);
            let runtime = home.join("runtime-fixture");
            crate::fixture_exec::write_executable(
                &runtime,
                b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nexit 0\n",
            )
            .expect("absent container");
            let record = json!({"schema":1,"loop":"alpha","run":"R","phase":"failed","worker_uid":worker,"plan":{"runtime_argv":[runtime]},"pre_driver_failure":"launch: before driver","settlement_uncertain":false,"observer_state":"not-started","helper_spawn_state":"not-started","driver_end":{"state":"not-started"},"helper_end":{"state":"not-started"},"observer_end":{"state":"not-started","socket":{"state":"not-applicable"}}});
            let path = crate::launch::reservation_path(&runs, "R");
            let mut request = DoorRequest {
                podman_bin: runtime.clone(),
                loop_name: "alpha".into(),
                dry_run: true,
            };
            for (key, value) in [
                ("pre_driver_failure", json!(null)),
                ("launcher_start", json!(1)),
                ("settlement_uncertain", json!(true)),
            ] {
                let mut unknown = record.clone();
                unknown[key] = value;
                crate::launch::publish_reservation(&path, &unknown).expect("unknown launcher");
                let preview = run_with(home, &request, &stub, &service, Some(group))
                    .expect("unknown preview");
                assert_eq!(preview["blocked"], true);
                assert_eq!(
                    preview["busy"],
                    json!(["run R (failed; container absent, launcher unknown)"])
                );
                request.dry_run = false;
                let refused = run_with(home, &request, &stub, &service, Some(group))
                    .expect_err("unknown blocks change");
                assert_eq!(refused.kind, "install-busy");
                assert_eq!(
                    refused.detail,
                    "run R (failed; container absent, launcher unknown)"
                );
                request.dry_run = true;
            }
            crate::launch::publish_reservation(&path, &record)
                .expect("terminal pre-driver failure");
            crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nprintf 'running\\n'\n")
                .expect("present container");
            request.dry_run = false;
            let refused = run_with(home, &request, &stub, &service, Some(group))
                .expect_err("present container still blocks");
            assert_eq!(refused.kind, "install-busy");
            assert_eq!(
                refused.detail,
                "run R (failed; container alive, launcher gone)"
            );
            crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n")
                .expect("absent container");
            request.dry_run = true;
            let preview =
                run_with(home, &request, &stub, &service, Some(group)).expect("terminal preview");
            assert_ne!(preview["blocked"], true);
            assert_eq!(preview["changed"], 6);
            request.dry_run = false;
            let installed = run_with(home, &request, &stub, &service, Some(group))
                .expect("terminal failure permits install");
            assert_eq!(installed["actions"], preview["actions"]);
            assert_eq!(installed["changed"], 6);
        }
    }

    /// ´test:unit:door-repin-candidates-share-settled-boundary´
    #[test]
    fn door_repin_candidates_share_settled_boundary() {
        use super::SettledDoor;
        let record = json!({"run":"R","phase":"settled","worker_uid":3000,
            "active_round":"work","rounds":[{"step":"work","phase":"settled"}],
            "plan":{"door":{"schema":1,"socket":"/home/worker/.local/door/capability.sock",
                "stub":"/home/worker/.local/libexec/superloop/ssh","stub_sha256":"a".repeat(64),
                "registered":["ssh"],"peer_uid":3000,"mirror_ref":"refs/heads/lane/R"}}});
        assert!(
            SettledDoor::new("R", &record, crate::launch::driver_report::fixture_read)
                .expect("measured candidate")
                .is_some()
        );
        let mut interrupted = record.clone();
        interrupted["phase"] = json!("started");
        interrupted["rounds"][0]["phase"] = json!("running");
        assert_eq!(
            SettledDoor::new(
                "R",
                &interrupted,
                crate::launch::driver_report::fixture_read
            )
            .err()
            .map(|error| error.kind),
            Some("repin-door-uncertain")
        );
        interrupted["driver_end"] = json!({"state":"completed"});
        assert!(
            SettledDoor::new(
                "R",
                &interrupted,
                crate::launch::driver_report::fixture_read
            )
            .expect("measured candidate")
            .is_some()
        );
        interrupted["reaping_recovery"] = json!({"state":"collected"});
        assert!(
            SettledDoor::new(
                "R",
                &interrupted,
                crate::launch::driver_report::fixture_read
            )
            .expect("measured boundary")
            .is_none()
        );
        for (key, value) in [
            ("phase", json!("started")),
            ("rotation", json!({"old_run":"R"})),
            ("rotation_intent", json!({})),
            ("rounds", json!([])),
            ("rounds", json!([{"step":"work","phase":"running"}])),
            ("active_round", json!("other")),
        ] {
            let mut invalid = record.clone();
            invalid[key] = value;
            assert!(
                SettledDoor::new("R", &invalid, crate::launch::driver_report::fixture_read)
                    .expect("measured boundary")
                    .is_none()
            );
            assert_eq!(
                crate::launch::repin_door::settled_boundary(
                    &invalid,
                    crate::launch::driver_report::fixture_read
                )
                .expect_err("same repin refusal")
                .kind,
                "repin-door-state"
            );
        }
        for first in [false, true] {
            let directory = tempfile::tempdir().expect("report directory");
            let mut captured = crate::launch::repin_door::tests::captured_record(first);
            captured["run"] = json!("R");
            captured["worker_uid"] = record["worker_uid"].clone();
            captured["plan"] = record["plan"].clone();
            captured["driver_entry_pid"] = json!(u32::MAX);
            captured["driver_entry_start"] = json!(1);
            captured["rounds"][0]["driver_dir"] = json!(directory.path());
            let step = captured["active_round"].as_str().expect("step");
            std::fs::write(
                directory.path().join("run-report.txt"),
                format!(
                    "RUN-REPORT lane={step} exit=1 verdict=FAILED dir={}\n",
                    directory.path().display()
                ),
            )
            .expect("report");
            assert!(
                SettledDoor::new("R", &captured, crate::launch::driver_report::fixture_read)
                    .expect("measured candidate")
                    .is_some()
            );
        }
        let mut failed = record;
        failed["rounds"][0]["phase"] = json!("failed");
        assert!(
            SettledDoor::new("R", &failed, crate::launch::driver_report::fixture_read)
                .expect("measured candidate")
                .is_some()
        );
    }

    fn repin_inventory_record() -> serde_json::Value {
        let mut record = crate::launch::repin_door::tests::captured_record(true);
        record["run"] = json!("R");
        record["worker_uid"] = json!(3000);
        record["plan"] = json!({"door":{"schema":1,"socket":"/home/worker/.local/door/capability.sock","stub":"/home/worker/.local/libexec/superloop/ssh","stub_sha256":"a".repeat(64),"registered":["ssh"],"peer_uid":3000,"mirror_ref":"refs/heads/lane/R"}});
        record["driver_entry_pid"] = json!(u32::MAX);
        record["driver_entry_start"] = json!(1);
        record
    }

    fn unmeasured_repin_fixture(kind: &'static str, unknown_presence: bool) {
        use crate::{container_helper::ProcessPresence, error::LaneError};
        let record = repin_inventory_record();
        let candidate = super::SettledDoor::with_presence(
            "R",
            &record,
            |_| {
                assert!(
                    !unknown_presence,
                    "unknown process must refuse before reading the report"
                );
                Err(LaneError::input(kind, "fixture report refusal"))
            },
            |_, _| {
                if unknown_presence {
                    ProcessPresence::Unknown
                } else {
                    ProcessPresence::Absent
                }
            },
        );
        let mut inventory = super::DoorInventory::default();
        inventory
            .record_candidate("R", candidate)
            .expect("typed measurement");
        assert!(inventory.settled.is_empty());
        assert_eq!(
            inventory.repin_unmeasured_runs,
            vec![json!({"run":"R","kind":kind})]
        );
    }

    /// ´test:unit:door-repin-list-retains-uncertain-report´
    #[test]
    fn door_repin_list_retains_uncertain_report() {
        unmeasured_repin_fixture("repin-door-uncertain", false);
    }

    /// ´test:unit:door-repin-list-retains-private-start-failure´
    #[test]
    fn door_repin_list_retains_private_start_failure() {
        unmeasured_repin_fixture("driver-report-private", false);
    }

    /// ´test:unit:door-repin-list-retains-unknown-process´
    #[test]
    fn door_repin_list_retains_unknown_process() {
        unmeasured_repin_fixture("repin-door-uncertain", true);
    }

    /// ´test:unit:door-repin-live-run-is-measured-not-unmeasured´
    #[test]
    fn door_repin_live_run_is_measured_not_unmeasured() {
        let record = repin_inventory_record();
        let candidate = super::SettledDoor::with_presence(
            "R",
            &record,
            |_| panic!("live driver must not read report"),
            |_, _| crate::container_helper::ProcessPresence::Present,
        );
        let mut inventory = super::DoorInventory::default();
        inventory
            .record_candidate("R", candidate)
            .expect("live candidate");
        assert_eq!(
            inventory.repin_unmeasured_runs,
            Vec::<serde_json::Value>::new()
        );
        assert!(inventory.settled.is_empty());
    }

    /// ´test:unit:door-repin-doorless-run-never-measures´
    #[test]
    fn door_repin_doorless_run_never_measures() {
        let mut record = repin_inventory_record();
        record["plan"]["door"] = serde_json::Value::Null;
        let candidate = super::SettledDoor::with_presence(
            "R",
            &record,
            |_| panic!("doorless run must not read report"),
            |_, _| panic!("doorless run must not measure presence"),
        );
        let mut inventory = super::DoorInventory::default();
        inventory
            .record_candidate("R", candidate)
            .expect("doorless candidate");
        assert_eq!(
            inventory.repin_unmeasured_runs,
            Vec::<serde_json::Value>::new()
        );
    }

    /// ´test:unit:door-repin-changed-install-measures-previous-stub´
    #[test]
    fn door_repin_changed_install_measures_previous_stub() {
        let mut inventory = super::DoorInventory::default();
        inventory
            .reservations
            .push(("R".into(), repin_inventory_record()));
        let mut reads = 0;
        inventory
            .measure_repins(
                Some(&json!({"stub_sha256":"a".repeat(64)})),
                &"b".repeat(64),
                |_| {
                    reads += 1;
                    Err(crate::error::LaneError::input(
                        "driver-report-private",
                        "fixture startup failure",
                    ))
                },
            )
            .expect("scoped inventory");
        assert_eq!(reads, 1);
        assert_eq!(
            inventory.repin_unmeasured_runs,
            vec![json!({"run":"R","kind":"driver-report-private"})]
        );
    }

    /// ´test:unit:door-repin-changed-install-measures-older-stub´
    #[test]
    fn door_repin_changed_install_measures_older_stub() {
        let mut inventory = super::DoorInventory::default();
        inventory
            .reservations
            .push(("R".into(), repin_inventory_record()));
        let mut reads = 0;
        inventory
            .measure_repins(
                Some(&json!({"stub_sha256":"b".repeat(64)})),
                &"c".repeat(64),
                |_| {
                    reads += 1;
                    Err(crate::error::LaneError::input(
                        "driver-report-private",
                        "fixture startup failure",
                    ))
                },
            )
            .expect("older pin inventory");
        assert_eq!(reads, 1);
        assert_eq!(
            inventory.repin_unmeasured_runs,
            vec![json!({"run":"R","kind":"driver-report-private"})]
        );
    }

    /// ´test:unit:door-repin-changed-install-lists-older-stub´
    #[test]
    fn door_repin_changed_install_lists_older_stub() {
        let mut inventory = super::DoorInventory::default();
        let mut record = repin_inventory_record();
        record["phase"] = json!("settled");
        record["rounds"][0]["phase"] = json!("settled");
        inventory.reservations.push(("R".into(), record));
        let previous = json!({"stub_sha256":"b".repeat(64)});
        let next = "c".repeat(64);
        inventory
            .measure_repins(Some(&previous), &next, |_| {
                panic!("settled run must not read report")
            })
            .expect("older settled pin inventory");
        assert_eq!(inventory.repin_required_runs(Some(&previous), &next), ["R"]);
        assert_eq!(
            inventory.repin_unmeasured_runs,
            Vec::<serde_json::Value>::new()
        );
        assert_eq!(
            inventory.repin_required_runs(None, &next),
            Vec::<String>::new()
        );
        assert_eq!(
            inventory.repin_required_runs(Some(&previous), &"b".repeat(64)),
            Vec::<String>::new()
        );
        assert_eq!(
            inventory.repin_required_runs(Some(&previous), &"a".repeat(64)),
            Vec::<String>::new()
        );
    }

    /// ´test:unit:door-repin-unchanged-install-and-current-pin-never-measure´
    #[test]
    fn door_repin_unchanged_install_and_current_pin_never_measure() {
        for (previous, next) in [(Some("a"), "a"), (Some("b"), "a"), (None, "c")] {
            let previous = previous.map(|stub| json!({"stub_sha256":stub.repeat(64)}));
            let mut inventory = super::DoorInventory::default();
            inventory
                .reservations
                .push(("R".into(), repin_inventory_record()));
            inventory
                .measure_repins(previous.as_ref(), &next.repeat(64), |_| {
                    panic!("unaffected run must not read report")
                })
                .expect("unaffected inventory");
            assert_eq!(
                inventory.repin_unmeasured_runs,
                Vec::<serde_json::Value>::new()
            );
            assert!(inventory.settled.is_empty());
        }
    }

    /// ´test:unit:door-busy-holder-names-unreadable-registry´
    #[test]
    fn door_busy_holder_names_unreadable_registry() {
        let (fixture, config, _, _, _, stub, service, group) = install_fixture();
        let home = fixture.path();
        fs::remove_file(home.join(".config/loops/registry.toml")).expect("remove registry");
        let _reader = crate::install::lock_loop_config(&config, true).expect("shared reader");
        let request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        let refusal = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("shared reader blocks install");
        assert_eq!(refusal.kind, "install-busy");
        assert_eq!(refusal.status, 2);
        assert!(
            refusal.detail.contains("reservations unreadable"),
            "{refusal:?}"
        );
    }

    /// ´test:unit:door-busy-holder-names-unreadable-runs-root´
    #[test]
    fn door_busy_holder_names_unreadable_runs_root() {
        let (fixture, config, _, _, _, stub, service, group) = install_fixture();
        let home = fixture.path();
        let missing_runs = home.join(".var/loops/alpha/absent-runs");
        file(
            &home.join(".config/loops/registry.toml"),
            format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", missing_runs.display()).as_bytes(),
            0o600,
        );
        let _reader = crate::install::lock_loop_config(&config, true).expect("shared reader");
        let request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        let refusal = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("shared reader blocks install");
        assert_eq!(refusal.kind, "install-busy");
        assert_eq!(refusal.status, 2);
        assert!(
            refusal.detail.contains("reservations unreadable"),
            "{refusal:?}"
        );
    }

    /// ´test:unit:door-install-reports-root-without-changing-registration´
    #[test]
    fn door_install_reports_root_without_changing_registration() {
        let (fixture, config, _, _, sockets, stub, service, group) = install_fixture();
        let home = fixture.path();
        let path = config.join("door-compute-registration.json");
        let original = fs::read(&path).expect("registration");
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: true,
        };
        let preview = run_with(home, &request, &stub, &service, Some(group)).expect("preview");
        assert_eq!(preview["node_root"], "/srv/loops/loop-a");
        assert_eq!(fs::read(&path).expect("unchanged registration"), original);
        assert!(!sockets.join("door").exists());
        request.dry_run = false;
        let changed = run_with(home, &request, &stub, &service, Some(group)).expect("install");
        assert_eq!(changed["node_root"], preview["node_root"]);
        assert_eq!(changed["actions"], preview["actions"]);
        assert_eq!(fs::read(&path).expect("unchanged registration"), original);
        let repeated = run_with(home, &request, &stub, &service, Some(group)).expect("repeat");
        assert_eq!(repeated["changed"], 0);
        assert_eq!(repeated["node_root"], preview["node_root"]);
        fs::remove_file(&path).expect("remove compute route");
        for dry_run in [true, false] {
            request.dry_run = dry_run;
            let report =
                run_with(home, &request, &stub, &service, Some(group)).expect("no compute route");
            assert!(report["node_root"].is_null());
            assert!(!path.exists());
        }
    }

    /// ´test:unit:door-install-refuses-absent-and-malformed-node-root´
    #[test]
    fn door_install_refuses_absent_and_malformed_node_root() {
        let (fixture, config, _, _, sockets, stub, service, group) = install_fixture();
        let path = config.join("door-compute-registration.json");
        for root in [
            None,
            Some(json!("relative")),
            Some(json!("")),
            Some(json!(null)),
            Some(json!(17)),
        ] {
            let mut value = json!({"schema":1,"loop":"alpha"});
            if let Some(root) = &root {
                value["node_root"] = root.clone();
            }
            let bytes = serde_json::to_vec(&value).expect("registration bytes");
            file(&path, &bytes, 0o600);
            for dry_run in [true, false] {
                let request = DoorRequest {
                    podman_bin: PathBuf::new(),
                    loop_name: "alpha".into(),
                    dry_run,
                };
                let error = run_with(fixture.path(), &request, &stub, &service, Some(group))
                    .expect_err("root refusal");
                assert_eq!(error.kind, "door-compute-root-refusal");
                assert!(error.detail.contains(path.to_str().expect("path")));
                if let Some(root) = &root {
                    assert!(error.detail.contains(&root.to_string()));
                }
                assert_eq!(fs::read(&path).expect("registration"), bytes);
                assert!(!sockets.join("door").exists());
            }
        }
    }

    /// ´test:unit:preview-and-change-count-identical-actions´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn preview_and_change_count_identical_actions() {
        let (fixture, config, unit_dir, template, sockets, stub, service, group) =
            install_fixture();
        let home = fixture.path();
        let loop_home = home.join(".var/loops/alpha");
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: true,
        };
        let preview = run_with(home, &request, &stub, &service, Some(group)).expect("dry run");
        assert_eq!(preview["changed"], 6);
        assert!(!sockets.join("door").exists());
        request.dry_run = false;
        let changed = run_with(home, &request, &stub, &service, Some(group)).expect("change");
        assert_eq!(changed["changed"], preview["changed"]);
        assert_eq!(changed["actions"], preview["actions"]);
        let repeated = run_with(home, &request, &stub, &service, Some(group)).expect("repeat");
        assert_eq!(repeated["changed"], 0);
        fs::remove_dir(sockets.join("door")).expect("remove fixture door directory");
        let generation_path = config.join("door-install-generation.json");
        let saved_generation = fs::read(&generation_path).expect("saved generation");
        let mut differing_unit: serde_json::Value =
            serde_json::from_slice(&saved_generation).expect("generation document");
        differing_unit["unit_dir"] = json!(home.join("other-units"));
        fs::write(
            &generation_path,
            serde_json::to_vec(&differing_unit).expect("changed generation"),
        )
        .expect("changed generation file");
        let conflict = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("missing directory cannot hide unit conflict");
        assert_eq!(conflict.kind, "install-door-conflict");
        assert_eq!(
            conflict.detail,
            "old unit directory differs from the generation"
        );
        fs::write(&generation_path, saved_generation).expect("restore generation");
        request.dry_run = true;
        let absent_directory_preview =
            run_with(home, &request, &stub, &service, Some(group)).expect("missing door preview");
        assert_eq!(absent_directory_preview["actions"][4]["action"], "replace");
        request.dry_run = false;
        let restored_directory =
            run_with(home, &request, &stub, &service, Some(group)).expect("restore door");
        assert_eq!(
            restored_directory["actions"],
            absent_directory_preview["actions"]
        );
        fs::write(&stub, b"#!/bin/sh\nexit 124\n").expect("rebuilt stub fixture");
        fs::write(&service, b"#!/bin/sh\nexit 124\n").expect("rebuilt service fixture");
        request.dry_run = true;
        let rebuilt_preview =
            run_with(home, &request, &stub, &service, Some(group)).expect("rebuilt preview");
        request.dry_run = false;
        let rebuilt =
            run_with(home, &request, &stub, &service, Some(group)).expect("rebuilt install");
        assert_eq!(rebuilt["changed"], rebuilt_preview["changed"]);
        assert_eq!(rebuilt["actions"], rebuilt_preview["actions"]);
        assert_eq!(rebuilt["actions"][1]["action"], "replace");
        assert_eq!(rebuilt["actions"][2]["action"], "replace");
        let owner = nix::unistd::Uid::effective().as_raw();
        assert!(
            crate::plan::door_pin(home, "alpha", &template, &sockets, owner, group)
                .expect("host pin")
                .is_some()
        );
        {
            let held = fs::File::open(home).expect("held home");
            let _private =
                crate::home::activate_private_home(home, &held, owner).expect("private anchor");
            assert!(
                crate::plan::door_pin(home, "alpha", &template, &sockets, owner, group)
                    .expect("private pin")
                    .is_some()
            );
            if group != 41001 {
                assert_eq!(
                    crate::plan::door_pin(home, "alpha", &template, &sockets, owner, 41001)
                        .expect_err("private group mismatch")
                        .kind,
                    "protected-file"
                );
            }
        }
        let next_template = loop_home.join("runner-templates/codex/next");
        directory(&next_template, 0o700);
        directory(&next_template.join("libexec"), 0o550);
        file(
            &config.join("workers.toml"),
            format!(
                "template_dir = \"{}\"\nsocket_dir = \"{}\"\n",
                next_template.display(),
                sockets.display()
            )
            .as_bytes(),
            0o600,
        );
        file(
            &config.join("install-generation.json"),
            &serde_json::to_vec(&json!({"phase":"complete","template_dir":next_template,
                "socket_dir":sockets,"unit_dir":unit_dir}))
            .expect("new generation"),
            0o600,
        );
        assert!(
            crate::plan::door_pin(home, "alpha", &next_template, &sockets, owner, group)
                .expect("stale roots do not refuse plan")
                .is_none()
        );
        request.dry_run = true;
        let next_preview =
            run_with(home, &request, &stub, &service, Some(group)).expect("next preview");
        request.dry_run = false;
        let next_changed =
            run_with(home, &request, &stub, &service, Some(group)).expect("supersede");
        assert_eq!(next_changed["changed"], next_preview["changed"]);
        assert_eq!(next_changed["actions"], next_preview["actions"]);
        assert_eq!(next_changed["actions"][1]["action"], "create");
        assert!(
            crate::plan::door_pin(home, "alpha", &next_template, &sockets, owner, group)
                .expect("new pin")
                .is_some()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(config.join("door-install-attempt.json")).expect("attempt")
            )
            .expect("attempt json")["phase"],
            "complete"
        );
        let generation_path = config.join("door-install-generation.json");
        let generation_bytes = fs::read(&generation_path).expect("completed generation");
        let mut wrong_keys: serde_json::Value =
            serde_json::from_slice(&generation_bytes).expect("generation json");
        wrong_keys
            .as_object_mut()
            .expect("generation object")
            .remove("unit_dir");
        wrong_keys["unused"] = json!("same count");
        fs::write(
            &generation_path,
            serde_json::to_vec(&wrong_keys).expect("wrong keys"),
        )
        .expect("replace fixture generation");
        assert_eq!(
            crate::plan::door_pin(home, "alpha", &next_template, &sockets, owner, group)
                .expect_err("same-count wrong key")
                .kind,
            "door-generation"
        );
        fs::write(&generation_path, generation_bytes).expect("restore fixture generation");
        let unit = unit_dir.join("superloop-lane-door@alpha.service");
        fs::remove_file(&unit).expect("fixture unit removal");
        fs::write(config.join("door-service"), b"changed").expect("fixture conflict");
        assert_eq!(
            run_with(home, &request, &stub, &service, Some(group))
                .expect_err("preflight refusal")
                .kind,
            "install-door-conflict"
        );
        assert!(!unit.exists());
    }

    /// ´test:unit:door-installer-reports-entry-metadata-without-generation-drift´
    #[test]
    fn door_installer_reports_entry_metadata_without_generation_drift() {
        let (fixture, config, _unit_dir, template, sockets, stub, service, group) =
            install_fixture();
        let home = fixture.path();
        directory(&home.join("permissions"), 0o755);
        reviewed_rubric(home);
        let uid = nix::unistd::Uid::effective().as_raw();
        let private = home.join(".var/loops/alpha/private");
        directory(&private, 0o700);
        let entry = home.join("entry");
        file(&entry, format!("#!/usr/bin/python3\nimport os,sys\nassert sys.argv[1:4] == ['enter','alpha','--']\nos.environ['HOME'] = {}\nos.execv(sys.argv[4],sys.argv[4:])\n", json!(private)).as_bytes(), 0o700);
        file(
            &config.join("workers.toml"),
            format!(
                "template_dir = '{}'\nsocket_dir = '{}'\nentry_bin = '{}'\n",
                template.display(),
                sockets.display(),
                entry.display()
            )
            .as_bytes(),
            0o600,
        );
        file(&config.parent().expect("loops").join("registry.toml"), format!("namespace = 'org.superloop-tools.loophome.registry'\nversion = [1,0,0]\nloops = [{{name='alpha',uid={uid},launch='src'}}]\n").as_bytes(), 0o600);
        file(
            &config.join("door.toml"),
            format!(
                "rubric_root = '{}'\nexecutable = '{}'\nmodel = 'fixture'\n",
                home.display(),
                entry.display()
            )
            .as_bytes(),
            0o600,
        );
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: true,
        };
        let preview =
            run_with(home, &request, &stub, &service, Some(group)).expect("preview through entry");
        assert_eq!(preview["agent_metadata"]["sign_in"]["exists"], false);
        assert_eq!(
            preview["agent_metadata"]["executable_status"]["usable"],
            true
        );
        request.dry_run = false;
        let changed = run_with(home, &request, &stub, &service, Some(group))
            .expect("install with absent sign-in");
        assert_eq!(changed["agent_metadata"]["sign_in"]["exists"], false);
        let generation_path = config.join("door-install-generation.json");
        let generation_bytes = fs::read(&generation_path).expect("generation bytes");
        let generation: serde_json::Value =
            serde_json::from_slice(&generation_bytes).expect("generation");
        assert!(generation["agent"].get("sign_in").is_none());
        assert!(generation["agent"].get("executable_status").is_none());
        assert!(generation.get("agent_metadata").is_none());
        directory(&private.join(".codex"), 0o755);
        file(
            &private.join(".codex/auth.json"),
            b"synthetic fixture credential",
            0o400,
        );
        request.dry_run = true;
        let preview = run_with(home, &request, &stub, &service, Some(group))
            .expect("preview after credential placement");
        assert_eq!(preview["changed"], 0);
        assert_eq!(preview["agent_metadata"]["sign_in"]["owner_uid"], uid);
        assert_eq!(preview["agent_metadata"]["sign_in"]["usable"], true);
        request.dry_run = false;
        let changed = run_with(home, &request, &stub, &service, Some(group))
            .expect("unchanged configuration");
        assert_eq!(changed["changed"], 0);
        assert_eq!(changed["agent_metadata"]["sign_in"]["mode"], "0400");
        file(&home.join("permissions/door.md"), &[0xff], 0o644);
        for dry_run in [true, false] {
            request.dry_run = dry_run;
            let refused = run_with(home, &request, &stub, &service, Some(group))
                .expect_err("reinstall repeats rubric admission");
            assert_eq!(refused.kind, "door-rubric-unavailable");
            assert!(refused.detail.contains("file-utf8"));
            assert_eq!(
                fs::read(&generation_path).expect("generation"),
                generation_bytes
            );
        }
        reviewed_rubric(home);
        file(&entry, b"#!/bin/sh\nexit 99\n", 0o700);
        request.dry_run = true;
        let failed = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("rubric admission requires a working entry");
        assert_eq!(failed.kind, "door-rubric-unavailable");
        assert_eq!(
            fs::read(generation_path).expect("retained generation"),
            generation_bytes
        );
    }

    /// ´test:unit:door-installer-alone-supersedes-pre-agent-generation´
    #[test]
    fn door_installer_alone_supersedes_pre_agent_generation() {
        let (fixture, config, _unit_dir, template, sockets, stub, service, group) =
            install_fixture();
        let home = fixture.path();
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        run_with(home, &request, &stub, &service, Some(group)).expect("install");
        let path = config.join("door-install-generation.json");
        let mut old: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("bytes")).expect("generation");
        old["schema"] = json!(1);
        old.as_object_mut().expect("object").remove("agent");
        let bytes = serde_json::to_vec(&old).expect("legacy bytes");
        file(&path, &bytes, 0o600);
        assert_eq!(
            crate::plan::door_pin(
                home,
                "alpha",
                &template,
                &sockets,
                nix::unistd::Uid::effective().as_raw(),
                group
            )
            .expect_err("legacy reader refusal")
            .kind,
            "door-generation-upgrade-required"
        );
        request.dry_run = true;
        run_with(home, &request, &stub, &service, Some(group)).expect("upgrade dry run");
        assert_eq!(fs::read(&path).expect("unchanged legacy"), bytes);
        request.dry_run = false;
        run_with(home, &request, &stub, &service, Some(group)).expect("upgrade");
        let new: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("new bytes")).expect("new generation");
        assert_eq!(new["schema"], 2);
        assert!(new["agent"].is_object());
    }

    /// ´test:unit:door-generation-records-host-group-and-refuses-old-shape´
    #[test]
    fn door_generation_records_host_group_and_refuses_old_shape() {
        let (fixture, config, _unit_dir, template, sockets, stub, service, group) =
            install_fixture();
        let home = fixture.path();
        let owner = nix::unistd::Uid::effective().as_raw();
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        run_with(home, &request, &stub, &service, Some(group)).expect("first install");
        let path = config.join("door-install-generation.json");
        let current_bytes = fs::read(&path).expect("current generation bytes");
        let mut generation: serde_json::Value =
            serde_json::from_slice(&current_bytes).expect("generation json");
        let observed = fs::metadata(sockets.join("door"))
            .expect("host door directory")
            .gid();
        assert_eq!(generation["host_door_gid"], observed);
        generation
            .as_object_mut()
            .expect("generation fields")
            .remove("host_door_gid");
        file(
            &path,
            &serde_json::to_vec(&generation).expect("old generation"),
            0o600,
        );
        let old_shape = crate::plan::door_pin(home, "alpha", &template, &sockets, owner, group)
            .expect_err("old shape refuses launch");
        assert_eq!(old_shape.kind, "door-generation");
        assert_eq!(old_shape.detail, "door generation shape differs");
        let old_bytes = fs::read(&path).expect("old generation bytes");
        let attempt_path = config.join("door-install-attempt.json");
        let attempt_before = fs::read(&attempt_path).expect("completed attempt bytes");
        request.dry_run = true;
        let refusal = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("old shape refuses dry run");
        assert_eq!(refusal.kind, "install-door-generation");
        assert_eq!(refusal.detail, "door generation shape differs");
        request.dry_run = false;
        let refusal = run_with(home, &request, &stub, &service, Some(group))
            .expect_err("old shape refuses changing run");
        assert_eq!(refusal.kind, "install-door-generation");
        assert_eq!(refusal.detail, "door generation shape differs");
        assert_eq!(fs::read(&path).expect("unchanged old record"), old_bytes);
        assert_eq!(
            fs::read(&attempt_path).expect("unchanged attempt"),
            attempt_before
        );
        file(&path, &current_bytes, 0o600);
        let mut generation: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("current generation"))
                .expect("current json");
        assert_eq!(generation["host_door_gid"], observed);
        assert_eq!(
            run_with(home, &request, &stub, &service, Some(group)).expect("repeat")["changed"],
            0
        );
        generation["host_door_gid"] = json!(observed.wrapping_add(1));
        file(
            &path,
            &serde_json::to_vec(&generation).expect("wrong group generation"),
            0o600,
        );
        let refusal = crate::plan::door_pin(home, "alpha", &template, &sockets, owner, group)
            .expect_err("recorded group must match directory");
        assert_eq!(refusal.kind, "door-generation");
        assert_eq!(refusal.detail, "registered socket directory differs");
        generation["host_door_gid"] = json!("bad");
        generation["template_dir"] = json!(home.join("other-template"));
        file(
            &path,
            &serde_json::to_vec(&generation).expect("malformed other-root generation"),
            0o600,
        );
        let malformed_other_root =
            crate::plan::door_pin(home, "alpha", &template, &sockets, owner, group)
                .expect_err("malformed group refuses before other roots");
        assert_eq!(malformed_other_root.kind, "door-generation");
        assert_eq!(
            malformed_other_root.detail,
            "recorded host door group is absent"
        );
    }

    /// ´test:unit:install-door-attempt-finishes-with-generation´
    #[test]
    fn install_door_attempt_finishes_with_generation() {
        let (fixture, config, _unit_dir, _template, _sockets, stub, service, group) =
            install_fixture();
        let request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        let result = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect("changing install");
        assert_eq!(result["changed"], 6);
        assert_eq!(result["unit_activation_performed"], false);
        assert!(result.get("units_active").is_none());
        let attempt: serde_json::Value = serde_json::from_slice(
            &fs::read(config.join("door-install-attempt.json")).expect("attempt"),
        )
        .expect("attempt json");
        let generation: serde_json::Value = serde_json::from_slice(
            &fs::read(config.join("door-install-generation.json")).expect("generation"),
        )
        .expect("generation json");
        assert_eq!(attempt["phase"], "complete");
        assert_eq!(generation["phase"], "complete");
        assert_eq!(attempt["to"], generation["template_dir"]);
    }

    /// ´test:unit:install-door-repeat-keeps-completed-attempt´
    #[test]
    fn install_door_repeat_keeps_completed_attempt() {
        let (fixture, config, _unit_dir, _template, _sockets, stub, service, group) =
            install_fixture();
        let mut request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        run_with(fixture.path(), &request, &stub, &service, Some(group)).expect("install");
        let attempt_path = config.join("door-install-attempt.json");
        let completed_bytes = fs::read(&attempt_path).expect("completed attempt");
        let repeat = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect("unchanged repeat");
        assert_eq!(repeat["changed"], 0);
        assert_eq!(
            fs::read(&attempt_path).expect("repeat attempt"),
            completed_bytes
        );

        let mut legacy: serde_json::Value =
            serde_json::from_slice(&completed_bytes).expect("attempt json");
        legacy["phase"] = json!("attempted");
        fs::write(
            &attempt_path,
            serde_json::to_vec_pretty(&legacy).expect("legacy json"),
        )
        .expect("legacy attempt");
        request.dry_run = true;
        let preview = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect("legacy preview");
        assert_eq!(preview["changed"], 1);
        assert_eq!(preview["actions"][5]["action"], "complete");
        assert_eq!(
            fs::read(&attempt_path).expect("dry attempt"),
            serde_json::to_vec_pretty(&legacy).expect("legacy bytes")
        );
        request.dry_run = false;
        let completed = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect("legacy completion");
        assert_eq!(completed["changed"], preview["changed"]);
        assert_eq!(completed["actions"], preview["actions"]);
        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(&attempt_path).expect("repaired attempt"))
                .expect("repaired json");
        assert_eq!(repaired["phase"], "complete");
        let repeat = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect("completed repeat");
        assert_eq!(repeat["changed"], 0);
    }

    /// ´test:unit:install-door-failed-generation-keeps-attempted´
    #[test]
    fn install_door_failed_generation_keeps_attempted() {
        let (fixture, config, _unit_dir, _template, _sockets, stub, service, group) =
            install_fixture();
        let request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        FAIL_GENERATION_WRITE.with(|fault| fault.set(true));
        let refusal = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect_err("generation publication fails after attempted write");
        assert_eq!(refusal.kind, "install-door-generation");
        assert_eq!(refusal.detail, "fixture generation write failed");
        let attempt_path = config.join("door-install-attempt.json");
        let attempt: serde_json::Value =
            serde_json::from_slice(&fs::read(&attempt_path).expect("attempted record"))
                .expect("attempt json");
        assert_eq!(attempt["phase"], "attempted");
        assert!(!config.join("door-install-generation.json").exists());
        run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect("retry finishes installation");
        let completed: serde_json::Value =
            serde_json::from_slice(&fs::read(&attempt_path).expect("completed record"))
                .expect("completed json");
        assert_eq!(completed["phase"], "complete");
    }

    /// ´test:unit:install-door-unknown-attempt-phase-refuses´
    #[test]
    fn install_door_unknown_attempt_phase_refuses() {
        let (fixture, config, _unit_dir, _template, _sockets, stub, service, group) =
            install_fixture();
        let request = DoorRequest {
            podman_bin: PathBuf::new(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        run_with(fixture.path(), &request, &stub, &service, Some(group)).expect("install");
        let attempt_path = config.join("door-install-attempt.json");
        let mut attempt: serde_json::Value =
            serde_json::from_slice(&fs::read(&attempt_path).expect("attempt record"))
                .expect("attempt json");
        attempt["phase"] = json!("unknown");
        let bytes = serde_json::to_vec_pretty(&attempt).expect("changed attempt json");
        fs::write(&attempt_path, &bytes).expect("changed attempt");
        let refusal = run_with(fixture.path(), &request, &stub, &service, Some(group))
            .expect_err("unknown phase refuses");
        assert_eq!(refusal.kind, "install-door-attempt");
        assert_eq!(refusal.detail, "old attempt shape differs");
        assert_eq!(fs::read(&attempt_path).expect("unchanged attempt"), bytes);
    }
}
