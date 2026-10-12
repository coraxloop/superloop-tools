use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Value, json};

use crate::build::payload::{CODEX, InstallPayload, Vendor};
use crate::build::{MAX_CODEX_BYTES, hash_preview, sha256, sha256_bytes, source_bytes};
use crate::error::LaneError;
use crate::pinned;

pub struct PrivateRequest<'a> {
    pub loop_name: &'a str,
    pub owner_home: &'a Path,
    pub data_dir: &'a Path,
    pub codex_bin: &'a Path,
    pub codex_host_bin: &'a Path,
    pub image_digest: &'a str,
    pub codex_sha256: &'a str,
    pub tools_commit: &'a str,
    pub expected_source: Option<&'a str>,
    pub dry_run: bool,
    pub shared_lock: bool,
    pub repair: bool,
}

/// Combine template operations with sign-in metadata operations in both preview and act.
///
/// # Errors
/// Refuses missing counts or sign-in changes, including an unaccounted directory creation.
pub fn with_sign_in(mut report: Value, sign_in: Value) -> Result<Value, LaneError> {
    let refusal = || {
        LaneError::operation(
            "install-private",
            "private change accounting is absent or invalid",
        )
    };
    let templates = report["changed"].as_u64().ok_or_else(refusal)?;
    let destinations = report["destinations"].as_array().ok_or_else(refusal)?;
    let changes = sign_in["changes"].as_array().ok_or_else(refusal)?;
    let mut convergence = 0_u64;
    for change in changes {
        if change["action"] == "create-directory" {
            // The template writer creates this destination before convergence in the act.
            if !destinations
                .iter()
                .any(|row| row["path"] == change["path"] && row["complete"] == false)
            {
                return Err(refusal());
            }
        } else {
            convergence += 1;
        }
    }
    report["changed"] = json!(templates.checked_add(convergence).ok_or_else(refusal)?);
    report["sign_in"] = sign_in;
    Ok(report)
}

impl<'a> PrivateRequest<'a> {
    /// Parse the private entry's forwarded form.
    ///
    /// # Errors
    ///
    /// Refuses missing or extra fields before private work.
    pub fn parse(args: &'a [String]) -> Result<Self, LaneError> {
        let [
            loop_name,
            owner_home,
            data_dir,
            codex_bin,
            codex_host_bin,
            image_digest,
            codex_sha256,
            tools_commit,
            rest @ ..,
        ] = args
        else {
            return Err(LaneError::input(
                "install-private",
                "private install needs eight arguments",
            ));
        };
        let mut words = rest.iter().map(String::as_str).collect::<Vec<_>>();
        let repair_option = words.iter().position(|word| *word == "--repair");
        if let Some(index) = repair_option {
            words.remove(index);
        }
        let repair = repair_option.is_some();
        let shared_option = words
            .iter()
            .position(|word| *word == "--shared-install-lock");
        if let Some(index) = shared_option {
            words.remove(index);
        }
        let shared_lock = shared_option.is_some();
        let (dry_run, expected_source) = match words.as_slice() {
            [
                "--dry-run",
                "--verified-home-fd",
                "0",
                "--verified-install-lock-fd",
                "1",
            ] => (true, None),
            [
                "--expected-source-sha256",
                expected,
                "--verified-home-fd",
                "0",
                "--verified-install-lock-fd",
                "1",
            ] if expected.len() == 64
                && expected
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
            {
                (false, Some(*expected))
            }
            _ => {
                return Err(LaneError::input(
                    "install-lock",
                    "private install requires a measured source and transferred home and install-lock descriptors",
                ));
            }
        };
        if shared_lock && !dry_run {
            return Err(LaneError::input(
                "install-lock",
                "shared install lock is only valid for preflight",
            ));
        }
        Ok(Self {
            loop_name,
            owner_home: Path::new(owner_home),
            data_dir: Path::new(data_dir),
            codex_bin: Path::new(codex_bin),
            codex_host_bin: Path::new(codex_host_bin),
            image_digest,
            codex_sha256,
            tools_commit,
            expected_source,
            dry_run,
            shared_lock,
            repair,
        })
    }
}

enum Material {
    Directory,
    Copy { bytes: Vec<u8>, digest: String },
    Bytes(Vec<u8>),
}

struct Expected {
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    material: Material,
}

fn expected_file(
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    source: &Path,
) -> Result<Expected, LaneError> {
    let bytes = source_bytes(
        source,
        "installed input",
        MAX_CODEX_BYTES,
        mode & 0o111 != 0,
    )
    .map_err(|error| LaneError::input("install-source", error.detail))?;
    let digest = sha256_bytes(&bytes, source.parent().unwrap_or_else(|| Path::new("/")))?;
    Ok(Expected {
        path,
        uid,
        gid,
        mode,
        material: Material::Copy { bytes, digest },
    })
}

fn copied_digest(row: &Expected) -> Result<&str, LaneError> {
    match &row.material {
        Material::Copy { digest, .. } => Ok(digest),
        _ => Err(LaneError::operation(
            "install-manifest",
            "source row has no copied digest",
        )),
    }
}

fn source_fingerprint(
    rows: &[Expected],
    owner_home: &Path,
    expected: usize,
) -> Result<String, LaneError> {
    let digests = rows
        .iter()
        .filter_map(|row| match &row.material {
            Material::Copy { digest, .. } => Some(digest.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if digests.len() != expected {
        return Err(LaneError::operation(
            "install-source",
            "private install needs the complete selected source set",
        ));
    }
    sha256_bytes(digests.join("\n").as_bytes(), owner_home)
}

fn named_source_digest<'a>(rows: &'a [Expected], name: &str) -> Result<&'a str, LaneError> {
    let row = rows
        .iter()
        .find(|row| {
            row.path
                .file_name()
                .is_some_and(|file_name| file_name == name)
                && matches!(&row.material, Material::Copy { .. })
        })
        .ok_or_else(|| {
            LaneError::operation("install-source", format!("{name} source is absent"))
        })?;
    copied_digest(row)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn expected_rows(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    codex_bin: &Path,
    codex_host_bin: &Path,
    image_digest: &str,
    codex_sha256: &str,
    tools_commit: &str,
    after_snapshot: impl FnOnce(),
) -> Result<Vec<Expected>, LaneError> {
    let payload = InstallPayload {
        vendor: CODEX,
        bin: codex_bin.into(),
        sha256: codex_sha256.into(),
        image_program: String::new(),
        companion: Some((codex_host_bin.into(), String::new())),
    };
    expected_payload_rows(
        owner_home,
        loop_name,
        loop_uid,
        namespace_owner,
        data_dir,
        image_digest,
        tools_commit,
        &[payload],
        after_snapshot,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn expected_payload_rows(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    image_digest: &str,
    tools_commit: &str,
    payloads: &[InstallPayload],
    after_snapshot: impl FnOnce(),
) -> Result<Vec<Expected>, LaneError> {
    let hash = image_digest
        .strip_prefix("sha256:")
        .filter(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| {
            LaneError::input(
                "install-image",
                "image_digest is not a lowercase sha256 value",
            )
        })?;
    let loop_root = owner_home.join(".var/loops").join(loop_name);
    let sockets = loop_root.join("sockets");
    let directory = |path, gid, mode| Expected {
        path,
        uid: namespace_owner.0,
        gid,
        mode,
        material: Material::Directory,
    };
    // Snapshot every selected source before checking pins or constructing a
    // manifest. The checkpoint lets tests replace paths at this exact boundary.
    let mut snapshots = Vec::new();
    for payload in payloads {
        let vendor = payload.vendor;
        let template = payload.template(&loop_root, hash);
        let program = expected_file(
            template.join("bin").join(vendor.name),
            namespace_owner.0,
            loop_uid,
            0o550,
            &payload.bin,
        )?;
        let config = expected_file(
            template.join(vendor.config),
            namespace_owner.0,
            loop_uid,
            0o440,
            &payload.config_source(data_dir),
        )?;
        let charter = expected_file(
            template.join(vendor.charter),
            namespace_owner.0,
            loop_uid,
            0o440,
            &data_dir.join("worker-AGENTS.md"),
        )?;
        let init = expected_file(
            template.join("libexec/box-init"),
            namespace_owner.0,
            loop_uid,
            0o440,
            &data_dir.join("box-init"),
        )?;
        let companion = if let Some((path, _)) = &payload.companion {
            let companion = expected_file(
                template.join("bin/codex-code-mode-host"),
                namespace_owner.0,
                loop_uid,
                0o550,
                path,
            )?;
            Some(companion)
        } else {
            None
        };
        snapshots.push((program, companion, config, charter, init));
    }
    after_snapshot();
    let mut rows = Vec::new();
    for ((index, payload), (program, companion, config, charter, init)) in
        payloads.iter().enumerate().zip(snapshots)
    {
        let vendor = payload.vendor;
        let template = payload.template(&loop_root, hash);
        if index == 0 {
            rows.push(directory(
                loop_root.join("runner-templates"),
                namespace_owner.1,
                0o711,
            ));
        }
        rows.extend([
            directory(
                loop_root.join("runner-templates").join(vendor.name),
                namespace_owner.1,
                0o711,
            ),
            directory(template.clone(), loop_uid, 0o550),
            directory(template.join("bin"), loop_uid, 0o550),
            directory(template.join("libexec"), loop_uid, 0o550),
        ]);
        if index == 0 {
            rows.extend([
                directory(sockets.clone(), namespace_owner.1, 0o700),
                directory(sockets.join("vendor"), loop_uid, 0o750),
            ]);
        }
        if vendor == CODEX {
            rows.push(directory(
                owner_home
                    .join(".config/loops")
                    .join(loop_name)
                    .join("lanes/codex"),
                loop_uid,
                0o700,
            ));
        }
        let measured = copied_digest(&program)?;
        if measured != payload.sha256 {
            return Err(LaneError::input(
                "install-source",
                format!(
                    "{} sha256 differs: expected {}, found {measured}",
                    if vendor == CODEX { "Codex" } else { "Claude" },
                    payload.sha256
                ),
            ));
        }
        let mut manifest = json!({"schema":1,"image_digest":image_digest,"config_sha256":copied_digest(&config)?,"charter_sha256":copied_digest(&charter)?,"tools_commit":tools_commit});
        manifest[vendor.hash_key] = json!(payload.sha256);
        rows.push(program);
        if let Some((companion, (_, expected))) = companion.zip(payload.companion.as_ref()) {
            let measured = copied_digest(&companion)?;
            if !expected.is_empty() && measured != expected {
                return Err(LaneError::input(
                    "install-source",
                    format!(
                        "Codex code-mode host sha256 differs: expected {expected}, found {measured}"
                    ),
                ));
            }
            manifest["codex_host_sha256"] = json!(measured);
            rows.push(companion);
        }
        rows.extend([config, charter, init]);
        rows.push(Expected {
            path: template.join("manifest"),
            uid: namespace_owner.0,
            gid: loop_uid,
            mode: 0o440,
            material: Material::Bytes(
                serde_json::to_vec_pretty(&manifest)
                    .map_err(|error| LaneError::operation("install-manifest", error.to_string()))?,
            ),
        });
    }
    Ok(rows)
}

fn inspect(
    expected: &Expected,
    resume: bool,
    namespace_owner: (u32, u32),
    repair: bool,
) -> Result<bool, LaneError> {
    let meta = match fs::symlink_metadata(&expected.path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LaneError::input(
                "install-destination",
                format!("{}: {error}", expected.path.display()),
            ));
        }
    };
    let proper_type = match &expected.material {
        Material::Directory => meta.is_dir(),
        _ => meta.is_file(),
    };
    if expected.path.ends_with("lanes/codex") && proper_type {
        return Ok(true);
    }
    let creation_mode = match &expected.material {
        Material::Directory => 0o700,
        _ => 0o600,
    };
    if proper_type
        && pending_metadata(
            expected,
            resume,
            namespace_owner,
            (meta.uid(), meta.gid(), meta.mode() & 0o7777),
            creation_mode,
        )
    {
        if (meta.uid(), meta.gid()) == (expected.uid, expected.gid)
            && (meta.uid(), meta.gid()) != namespace_owner
        {
            inspect_bytes(expected)?;
        }
        return Ok(false);
    }
    if !proper_type
        || meta.uid() != expected.uid
        || meta.gid() != expected.gid
        || meta.mode() & 0o7777 != expected.mode
    {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "{} differs: expected uid={}, gid={}, mode={:04o}",
                expected.path.display(),
                expected.uid,
                expected.gid,
                expected.mode
            ),
        ));
    }
    if repair {
        let parent = expected
            .path
            .parent()
            .ok_or_else(|| LaneError::input("repair-template", "template file has no parent"))?;
        let max_bytes = usize::try_from(MAX_CODEX_BYTES).map_err(|_| {
            LaneError::input(
                "repair-template",
                "template size limit exceeds address space",
            )
        })?;
        let matches = match &expected.material {
            Material::Directory => true,
            Material::Copy { digest, .. } => {
                let observed = pinned::read_private(
                    parent,
                    &expected.path,
                    expected.uid,
                    expected.mode,
                    max_bytes,
                )
                .map_err(|error| LaneError::input("repair-template", error.detail))?;
                sha256_bytes(&observed, parent)? == *digest
            }
            Material::Bytes(bytes) => {
                pinned::read_private(
                    parent,
                    &expected.path,
                    expected.uid,
                    expected.mode,
                    max_bytes,
                )
                .map_err(|error| LaneError::input("repair-template", error.detail))?
                    == *bytes
            }
        };
        return Ok(matches);
    }
    inspect_bytes(expected)?;
    Ok(true)
}

fn pending_metadata(
    expected: &Expected,
    resume: bool,
    namespace_owner: (u32, u32),
    found: (u32, u32, u32),
    creation_mode: u32,
) -> bool {
    resume
        && found.2 == creation_mode
        && ((found.0, found.1) == namespace_owner
            || (found.0, found.1) == (expected.uid, expected.gid))
        && found != (expected.uid, expected.gid, expected.mode)
}

fn inspect_bytes(expected: &Expected) -> Result<(), LaneError> {
    match &expected.material {
        Material::Directory => {}
        Material::Copy { digest, .. } => {
            let found = sha256(&expected.path)?;
            if found != *digest {
                return Err(LaneError::input(
                    "install-conflict",
                    format!(
                        "{} differs: sha256 expected {digest}, found {found}",
                        expected.path.display()
                    ),
                ));
            }
        }
        Material::Bytes(bytes) => {
            if fs::read(&expected.path).map_err(|error| {
                LaneError::input(
                    "install-conflict",
                    format!("{}: {error}", expected.path.display()),
                )
            })? != *bytes
            {
                return Err(LaneError::input(
                    "install-conflict",
                    format!("{} differs from the pinned bytes", expected.path.display()),
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn refreshable_charter(
    rows: &[Expected],
    resume: bool,
    vendor: Vendor,
    template: &Path,
) -> Result<Option<[PathBuf; 2]>, LaneError> {
    let charter = rows
        .iter()
        .find(|row| row.path == template.join(vendor.charter))
        .ok_or_else(|| LaneError::operation("install-manifest", "charter row is absent"))?;
    let manifest = rows
        .iter()
        .find(|row| row.path == template.join("manifest"))
        .ok_or_else(|| LaneError::operation("install-manifest", "manifest row is absent"))?;
    let manifest_meta = match fs::symlink_metadata(&manifest.path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "install-conflict",
                format!("{}: {error}", manifest.path.display()),
            ));
        }
    };
    if !manifest_meta.is_file()
        || (
            manifest_meta.uid(),
            manifest_meta.gid(),
            manifest_meta.mode() & 0o7777,
        ) != (manifest.uid, manifest.gid, manifest.mode)
    {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "{} has altered type, owner or mode",
                manifest.path.display()
            ),
        ));
    }
    let old_bytes = fs::read(&manifest.path).map_err(|error| {
        LaneError::input(
            "install-conflict",
            format!("{}: {error}", manifest.path.display()),
        )
    })?;
    let Material::Bytes(new_bytes) = &manifest.material else {
        return Err(LaneError::operation(
            "install-manifest",
            "manifest material is absent",
        ));
    };
    if old_bytes == *new_bytes {
        return Ok(None);
    }
    let meta = fs::symlink_metadata(&charter.path).map_err(|error| {
        LaneError::input(
            "install-conflict",
            format!("{}: {error}", charter.path.display()),
        )
    })?;
    if !meta.is_file()
        || (meta.uid(), meta.gid(), meta.mode() & 0o7777)
            != (charter.uid, charter.gid, charter.mode)
    {
        return Err(LaneError::input(
            "install-conflict",
            format!("{} has altered type, owner or mode", charter.path.display()),
        ));
    }
    if old_bytes.len() > 65_536 {
        return Err(LaneError::input(
            "install-conflict",
            format!("{} exceeds 65536 bytes", manifest.path.display()),
        ));
    }
    let mut old: Value = serde_json::from_slice(&old_bytes).map_err(|error| {
        LaneError::input(
            "install-conflict",
            format!("{}: {error}", manifest.path.display()),
        )
    })?;
    let new: Value = serde_json::from_slice(new_bytes)
        .map_err(|error| LaneError::operation("install-manifest", error.to_string()))?;
    let old_hash = old["charter_sha256"]
        .as_str()
        .ok_or_else(|| {
            LaneError::input(
                "install-conflict",
                format!("{} has no charter hash", manifest.path.display()),
            )
        })?
        .to_owned();
    old["charter_sha256"] = new["charter_sha256"].clone();
    if old != new {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "{} differs beyond its charter hash",
                manifest.path.display()
            ),
        ));
    }
    let installed_hash = sha256(&charter.path)?;
    let Material::Copy {
        digest: new_hash, ..
    } = &charter.material
    else {
        return Err(LaneError::operation(
            "install-manifest",
            "charter material is absent",
        ));
    };
    if installed_hash != old_hash && !(resume && installed_hash == *new_hash) {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "{} differs from its installed manifest",
                charter.path.display()
            ),
        ));
    }
    Ok(Some([charter.path.clone(), manifest.path.clone()]))
}

fn generation_pending(
    owner_home: &Path,
    loop_name: &str,
    image_digest: &str,
    payloads: &[InstallPayload],
    tools_commit: &str,
    expected_source: Option<&str>,
) -> Result<bool, LaneError> {
    let path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("install-generation.json");
    let Some(bytes) = pinned::read_private_optional(
        owner_home,
        &path,
        nix::unistd::Uid::effective().as_raw(),
        0o600,
        65_536,
    )?
    else {
        return Ok(false);
    };
    let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
        LaneError::input("install-generation", format!("{}: {error}", path.display()))
    })?;
    crate::build::payload::check_claude_generation(&record)?;
    if expected_source.is_some() {
        for payload in payloads
            .iter()
            .filter(|payload| payload.vendor == crate::build::payload::CLAUDE)
        {
            let hash = image_digest.strip_prefix("sha256:").unwrap_or_default();
            let template = payload.template(&owner_home.join(".var/loops").join(loop_name), hash);
            if record[payload.vendor.hash_key] != payload.sha256
                || record[payload.vendor.program_key] != payload.image_program
                || record["claude_template_dir"] != template.display().to_string()
                || expected_source.is_some_and(|source| record["source_fingerprint"] != source)
            {
                return Err(LaneError::input(
                    "install-generation",
                    "Claude generation differs from the selected payload or source snapshot",
                ));
            }
        }
    }
    if record["phase"] != "preparing" {
        return Ok(false);
    }
    if record["image_digest"] != image_digest
        || payloads
            .iter()
            .any(|payload| record[payload.vendor.hash_key] != payload.sha256)
        || record["tools_commit"] != tools_commit
    {
        return Err(LaneError::input(
            "install-generation",
            format!("{} names another generation", path.display()),
        ));
    }
    if expected_source.is_some_and(|source| record["source_fingerprint"] != source) {
        return Err(LaneError::input(
            "install-generation",
            format!("{} names another source snapshot", path.display()),
        ));
    }
    Ok(true)
}

fn create(expected: &Expected) -> Result<(), LaneError> {
    match &expected.material {
        Material::Directory => DirBuilder::new()
            .mode(0o700)
            .create(&expected.path)
            .map_err(|error| {
                LaneError::operation(
                    "install-create",
                    format!("{}: {error}", expected.path.display()),
                )
            })?,
        Material::Copy { bytes, .. } => {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&expected.path)
                .map_err(|error| {
                    LaneError::operation(
                        "install-create",
                        format!("{}: {error}", expected.path.display()),
                    )
                })?;
            output
                .write_all(bytes)
                .and_then(|()| output.sync_all())
                .map_err(|error| {
                    LaneError::operation(
                        "install-create",
                        format!("{}: {error}", expected.path.display()),
                    )
                })?;
        }
        Material::Bytes(bytes) => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&expected.path)
                .map_err(|error| {
                    LaneError::operation(
                        "install-create",
                        format!("{}: {error}", expected.path.display()),
                    )
                })?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| {
                    LaneError::operation(
                        "install-create",
                        format!("{}: {error}", expected.path.display()),
                    )
                })?;
        }
    }
    Ok(())
}

fn replace_refresh(
    expected: &Expected,
    owner_home: &Path,
    namespace_owner: (u32, u32),
) -> Result<(), LaneError> {
    let parent = expected
        .path
        .parent()
        .ok_or_else(|| LaneError::operation("install-recover", "replacement has no parent"))?;
    let name = expected
        .path
        .file_name()
        .ok_or_else(|| LaneError::operation("install-recover", "replacement has no name"))?;
    let bytes = match &expected.material {
        Material::Copy { bytes, .. } | Material::Bytes(bytes) => bytes,
        Material::Directory => {
            return Err(LaneError::operation(
                "install-recover",
                "directory cannot be replaced",
            ));
        }
    };
    for attempt in 0..64 {
        let temporary = parent.join(format!(
            ".{}-refresh-{}-{attempt}.tmp",
            name.to_string_lossy(),
            std::process::id()
        ));
        let mut output = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(LaneError::operation(
                    "install-recover",
                    format!("{}: {error}", temporary.display()),
                ));
            }
        };
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| {
                LaneError::operation(
                    "install-recover",
                    format!("{}: {error}", temporary.display()),
                )
            })?;
        pinned::set_metadata(
            owner_home,
            &temporary,
            namespace_owner.0,
            expected.uid,
            expected.gid,
            expected.mode,
        )?;
        output.sync_all().map_err(|error| {
            LaneError::operation(
                "install-recover",
                format!("{}: {error}", temporary.display()),
            )
        })?;
        fs::rename(&temporary, &expected.path).map_err(|error| {
            LaneError::operation(
                "install-recover",
                format!("{}: {error}", expected.path.display()),
            )
        })?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                LaneError::operation("install-recover", format!("{}: {error}", parent.display()))
            })?;
        return Ok(());
    }
    Err(LaneError::operation(
        "install-recover",
        format!("{} has no free replacement name", expected.path.display()),
    ))
}

fn finalize(
    expected: &Expected,
    owner_home: &Path,
    namespace_owner: (u32, u32),
) -> Result<(), LaneError> {
    pinned::set_metadata(
        owner_home,
        &expected.path,
        namespace_owner.0,
        expected.uid,
        expected.gid,
        expected.mode,
    )
}

fn sync_private_init<F>(
    libexec: &Path,
    opening_existing_template: bool,
    checkpoint: RefreshCheckpoint,
    mut sync: F,
) -> Result<(), LaneError>
where
    F: FnMut(&Path) -> Result<(), LaneError>,
{
    sync(&libexec.join("box-init"))?;
    if checkpoint == RefreshCheckpoint::AfterInitSync {
        return Err(LaneError::operation(
            "install-interrupted",
            "after private init inode sync",
        ));
    }
    if opening_existing_template {
        fs::set_permissions(libexec, fs::Permissions::from_mode(0o550)).map_err(|error| {
            LaneError::operation("install-mode", format!("{}: {error}", libexec.display()))
        })?;
    }
    if checkpoint == RefreshCheckpoint::AfterLibexecModeRestore {
        return Err(LaneError::operation(
            "install-interrupted",
            "after private directory mode restore",
        ));
    }
    sync(libexec)
}

fn sync_opened_private(path: &Path) -> Result<(), LaneError> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            LaneError::operation("install-mode", format!("{}: {error}", path.display()))
        })
}

fn finalize_and_sync_rows<F>(
    rows: &[Expected],
    existing: &[bool],
    owner_home: &Path,
    namespace_owner: (u32, u32),
    resume: bool,
    mut sync: F,
) -> Result<(), LaneError>
where
    F: FnMut(&Path) -> Result<(), LaneError>,
{
    for (row, exists) in rows.iter().zip(existing).rev() {
        if !exists {
            finalize(row, owner_home, namespace_owner)?;
        }
        if !exists || resume {
            sync(&row.path)?;
            let parent = row.path.parent().ok_or_else(|| {
                LaneError::operation("install-mode", "installed path has no parent")
            })?;
            sync(parent)?;
        }
    }
    Ok(())
}

/// Inspect or prepare protected runtime inputs and the loop's sign-in place.
///
/// # Errors
///
/// Refuses a conflicting destination before creating any planned path.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn run(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    codex_bin: &Path,
    codex_host_bin: &Path,
    image_digest: &str,
    codex_sha256: &str,
    tools_commit: &str,
    expected_source: Option<&str>,
    dry_run: bool,
    install_guard: &crate::install::InstallGuard,
) -> Result<Value, LaneError> {
    run_with_checkpoint(
        owner_home,
        loop_name,
        loop_uid,
        namespace_owner,
        data_dir,
        codex_bin,
        codex_host_bin,
        image_digest,
        codex_sha256,
        tools_commit,
        expected_source,
        dry_run,
        install_guard,
        RefreshCheckpoint::None,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshCheckpoint {
    None,
    AfterMode,
    AfterCharter,
    AfterManifest,
    AfterInitMetadata,
    AfterInitSync,
    AfterLibexecModeRestore,
    AfterModeRestore,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn run_with_checkpoint(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    codex_bin: &Path,
    codex_host_bin: &Path,
    image_digest: &str,
    codex_sha256: &str,
    tools_commit: &str,
    expected_source: Option<&str>,
    dry_run: bool,
    install_guard: &crate::install::InstallGuard,
    checkpoint: RefreshCheckpoint,
) -> Result<Value, LaneError> {
    run_inner(
        owner_home,
        loop_name,
        loop_uid,
        namespace_owner,
        data_dir,
        &[InstallPayload {
            vendor: CODEX,
            bin: codex_bin.into(),
            sha256: codex_sha256.into(),
            image_program: String::new(),
            companion: Some((codex_host_bin.into(), String::new())),
        }],
        image_digest,
        tools_commit,
        expected_source,
        dry_run,
        false,
        install_guard,
        checkpoint,
    )
}

/// Reconcile verified private template files under the transferred install lock.
///
/// # Errors
///
/// Refuses unsafe metadata, changed sources or a missing pending generation.
#[allow(clippy::too_many_arguments)]
pub fn run_with_repair(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    codex_bin: &Path,
    codex_host_bin: &Path,
    image_digest: &str,
    codex_sha256: &str,
    tools_commit: &str,
    expected_source: Option<&str>,
    dry_run: bool,
    install_guard: &crate::install::InstallGuard,
) -> Result<Value, LaneError> {
    run_inner(
        owner_home,
        loop_name,
        loop_uid,
        namespace_owner,
        data_dir,
        &[InstallPayload {
            vendor: CODEX,
            bin: codex_bin.into(),
            sha256: codex_sha256.into(),
            image_program: String::new(),
            companion: Some((codex_host_bin.into(), String::new())),
        }],
        image_digest,
        tools_commit,
        expected_source,
        dry_run,
        true,
        install_guard,
        RefreshCheckpoint::None,
    )
}

/// Install every selected vendor through the shared protected row writer.
///
/// # Errors
/// Refuses changed sources, conflicting destinations or an invalid generation.
#[allow(clippy::too_many_arguments)]
pub fn run_payloads(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    payloads: &[InstallPayload],
    image_digest: &str,
    tools_commit: &str,
    expected_source: Option<&str>,
    dry_run: bool,
    repair: bool,
    install_guard: &crate::install::InstallGuard,
) -> Result<Value, LaneError> {
    run_inner(
        owner_home,
        loop_name,
        loop_uid,
        namespace_owner,
        data_dir,
        payloads,
        image_digest,
        tools_commit,
        expected_source,
        dry_run,
        repair,
        install_guard,
        RefreshCheckpoint::None,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_inner(
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_owner: (u32, u32),
    data_dir: &Path,
    payloads: &[InstallPayload],
    image_digest: &str,
    tools_commit: &str,
    expected_source: Option<&str>,
    dry_run: bool,
    repair: bool,
    install_guard: &crate::install::InstallGuard,
    checkpoint: RefreshCheckpoint,
) -> Result<Value, LaneError> {
    let started = Instant::now();
    install_guard.verify(&owner_home.join(".config/loops").join(loop_name), dry_run)?;
    let rows = expected_payload_rows(
        owner_home,
        loop_name,
        loop_uid,
        namespace_owner,
        data_dir,
        image_digest,
        tools_commit,
        payloads,
        || {},
    )?;
    let measured_source = source_fingerprint(
        &rows,
        owner_home,
        payloads
            .iter()
            .map(|p| if p.companion.is_some() { 5 } else { 4 })
            .sum(),
    )?;
    let mut source_sha256 = json!({});
    for payload in payloads {
        let vendor = payload.vendor;
        source_sha256[vendor.name] = json!(named_source_digest(&rows, vendor.name)?);
        if vendor == CODEX {
            source_sha256["codex_host"] =
                json!(named_source_digest(&rows, "codex-code-mode-host")?);
            source_sha256["config"] = json!(named_source_digest(&rows, vendor.config)?);
            source_sha256["charter"] = json!(named_source_digest(&rows, vendor.charter)?);
        } else {
            source_sha256["claude_config"] = json!(named_source_digest(&rows, vendor.config)?);
            source_sha256["claude_charter"] = json!(named_source_digest(&rows, vendor.charter)?);
        }
    }
    source_sha256["init"] = json!(named_source_digest(&rows, "box-init")?);
    if !dry_run && expected_source != Some(measured_source.as_str()) {
        return Err(LaneError::input(
            "install-source",
            "private source differs from the public preflight snapshot",
        ));
    }
    let resume = generation_pending(
        owner_home,
        loop_name,
        image_digest,
        payloads,
        tools_commit,
        if dry_run { None } else { expected_source },
    )?;
    let image_hash = image_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| LaneError::input("install-image", "image digest is invalid"))?;
    let loop_root = owner_home.join(".var/loops").join(loop_name);
    let mut refreshed = Vec::new();
    if !repair {
        for payload in payloads {
            if let Some(paths) = refreshable_charter(
                &rows,
                resume,
                payload.vendor,
                &payload.template(&loop_root, image_hash),
            )? {
                refreshed.extend(paths);
            }
        }
    }
    let refresh = (!refreshed.is_empty()).then_some(refreshed);
    let existing = rows
        .iter()
        .map(|row| {
            if refresh
                .as_ref()
                .is_some_and(|paths| paths.contains(&row.path))
            {
                return Ok(false);
            }
            inspect(row, resume, namespace_owner, repair)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !dry_run && existing.iter().any(|complete| !complete) && !resume {
        return Err(LaneError::input(
            "install-generation",
            "private install needs a matching pending generation before mutation",
        ));
    }
    let destinations = rows.iter().zip(&existing).map(|(row, complete)| json!({"path":row.path,"owner_uid":row.uid,"group_gid":row.gid,"owner_view":"rootless namespace","mode":format!("{:04o}", row.mode),"exists":row.path.exists(),"complete":complete})).collect::<Vec<_>>();
    if !dry_run {
        let mut states = Vec::new();
        for payload in payloads {
            let libexec = payload.template(&loop_root, image_hash).join("libexec");
            let template = libexec
                .parent()
                .ok_or_else(|| LaneError::operation("install-mode", "template path is absent"))?;
            let bin = template.join("bin");
            let opening_existing_bin = bin.exists()
                && rows
                    .iter()
                    .zip(&existing)
                    .any(|(row, complete)| !complete && row.path.starts_with(&bin));
            let opening_existing_template = libexec.exists()
                && rows
                    .iter()
                    .zip(&existing)
                    .any(|(row, complete)| !complete && row.path.starts_with(&libexec));
            let refreshing_template = refresh
                .as_ref()
                .is_some_and(|paths| paths.iter().any(|path| path.starts_with(template)))
                || (repair
                    && template.exists()
                    && rows
                        .iter()
                        .zip(&existing)
                        .any(|(row, complete)| !complete && row.path.starts_with(template)));
            if refreshing_template {
                fs::set_permissions(template, fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        LaneError::operation(
                            "install-mode",
                            format!("{}: {error}", template.display()),
                        )
                    },
                )?;
                if checkpoint == RefreshCheckpoint::AfterMode {
                    return Err(LaneError::operation(
                        "install-interrupted",
                        "after template mode change",
                    ));
                }
            }
            if opening_existing_template {
                fs::set_permissions(&libexec, fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        LaneError::operation(
                            "install-mode",
                            format!("{}: {error}", libexec.display()),
                        )
                    },
                )?;
            }
            if opening_existing_bin {
                fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    LaneError::operation("install-mode", format!("{}: {error}", bin.display()))
                })?;
            }
            states.push((
                libexec.clone(),
                opening_existing_template,
                opening_existing_bin,
                refreshing_template,
            ));
        }
        for (row, exists) in rows.iter().zip(&existing) {
            if !exists {
                if row.path.exists() {
                    if matches!(&row.material, Material::Directory) {
                        continue;
                    }
                    if repair
                        || refresh
                            .as_ref()
                            .is_some_and(|paths| paths.contains(&row.path))
                    {
                        replace_refresh(row, owner_home, namespace_owner)?;
                        if (checkpoint == RefreshCheckpoint::AfterCharter
                            && row
                                .path
                                .file_name()
                                .is_some_and(|name| name == "AGENTS.md" || name == "CLAUDE.md"))
                            || (checkpoint == RefreshCheckpoint::AfterManifest
                                && row.path.file_name().is_some_and(|name| name == "manifest"))
                        {
                            return Err(LaneError::operation(
                                "install-interrupted",
                                "after refresh rename",
                            ));
                        }
                        continue;
                    }
                    fs::remove_file(&row.path).map_err(|error| {
                        LaneError::operation(
                            "install-recover",
                            format!("{}: {error}", row.path.display()),
                        )
                    })?;
                }
                create(row)?;
            }
        }
        finalize_and_sync_rows(
            &rows,
            &existing,
            owner_home,
            namespace_owner,
            resume,
            sync_opened_private,
        )?;
        if checkpoint == RefreshCheckpoint::AfterInitMetadata {
            return Err(LaneError::operation(
                "install-interrupted",
                "after private init final metadata",
            ));
        }
        for (libexec, opening_existing_template, opening_existing_bin, refreshing_template) in
            states
        {
            let template = libexec
                .parent()
                .ok_or_else(|| LaneError::operation("install-mode", "template path is absent"))?;
            let bin = template.join("bin");
            sync_private_init(
                &libexec,
                opening_existing_template,
                checkpoint,
                sync_opened_private,
            )?;
            if opening_existing_bin {
                fs::set_permissions(&bin, fs::Permissions::from_mode(0o550)).map_err(|error| {
                    LaneError::operation("install-mode", format!("{}: {error}", bin.display()))
                })?;
                sync_opened_private(&bin)?;
            }
            if refreshing_template {
                fs::set_permissions(template, fs::Permissions::from_mode(0o550)).map_err(
                    |error| {
                        LaneError::operation(
                            "install-mode",
                            format!("{}: {error}", template.display()),
                        )
                    },
                )?;
            }
            if checkpoint == RefreshCheckpoint::AfterModeRestore {
                return Err(LaneError::operation(
                    "install-interrupted",
                    "after restored template mode",
                ));
            }
            fs::File::open(template)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    LaneError::operation("install-mode", format!("{}: {error}", template.display()))
                })?;
        }
        for row in &rows {
            inspect(row, false, namespace_owner, false)?;
        }
    }
    let mut probes = Vec::new();
    for payload in payloads {
        let config = payload.config_source(data_dir);
        let charter = data_dir.join("worker-AGENTS.md");
        let init = data_dir.join("box-init");
        for path in [
            &payload.bin,
            &config,
            &charter,
            &init,
            &payload.bin,
            &config,
            &charter,
            &init,
        ] {
            probes.push(json!({"input":path,"spec":hash_preview(path.parent().unwrap_or_else(|| Path::new("/")))}));
        }
    }
    Ok(
        json!({"schema":1,"command":"install-private","dry_run":dry_run,"changed":existing.iter().filter(|exists| !**exists).count(),"charter_refresh":refresh.is_some(),"source_fingerprint":measured_source,"source_sha256":source_sha256,"destinations":destinations,"hash_checks":probes,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Expected, Material, RefreshCheckpoint, create, expected_file, expected_rows, finalize,
        finalize_and_sync_rows, inspect, pending_metadata, sync_opened_private, sync_private_init,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    /// ´test:unit:private-repair-flag-keeps-descriptor-form´
    #[test]
    fn private_repair_flag_keeps_descriptor_form() {
        let args = [
            "alpha",
            "/home/owner",
            "/data",
            "/bin/codex",
            "/bin/host",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "commit",
            "--dry-run",
            "--repair",
            "--verified-home-fd",
            "0",
            "--verified-install-lock-fd",
            "1",
        ]
        .map(str::to_owned);
        let parsed = super::PrivateRequest::parse(&args).expect("repair form");
        assert!(parsed.dry_run);
        assert!(parsed.repair);
    }

    /// ´test:unit:repair-template-accepts-byte-drift-and-refuses-unsafe-mode´
    #[test]
    fn repair_template_accepts_byte_drift_and_refuses_unsafe_mode() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let path = fixture.path().join("config.toml");
        fs::write(&path, b"drift").expect("drifted file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("safe mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        let expected = Expected {
            path: path.clone(),
            uid: owner,
            gid: group,
            mode: 0o600,
            material: Material::Bytes(b"pinned".to_vec()),
        };
        assert!(!inspect(&expected, false, (owner, group), true).expect("repairable drift"));
        assert_eq!(
            inspect(&expected, false, (owner, group), false)
                .expect_err("ordinary install refuses drift")
                .kind,
            "install-conflict"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
        assert_eq!(
            inspect(&expected, false, (owner, group), true)
                .expect_err("repair refuses widened mode")
                .kind,
            "install-conflict"
        );
    }

    /// ´test:unit:fresh-install-syncs-final-files-and-parent-directories-before-completion´
    #[test]
    fn fresh_install_syncs_final_files_and_parent_directories_before_completion() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        let template = fixture.path().join("template");
        let charter = template.join("AGENTS.md");
        let rows = [
            Expected {
                path: template.clone(),
                uid: owner,
                gid: group,
                mode: 0o550,
                material: Material::Directory,
            },
            Expected {
                path: charter.clone(),
                uid: owner,
                gid: group,
                mode: 0o440,
                material: Material::Bytes(b"worker charter\n".to_vec()),
            },
        ];
        for row in &rows {
            create(row).expect("fresh installed row");
        }
        let expected = vec![
            charter.clone(),
            template.clone(),
            template.clone(),
            fixture.path().to_path_buf(),
        ];
        let mut synced = Vec::new();
        finalize_and_sync_rows(
            &rows,
            &[false, false],
            fixture.path(),
            (owner, group),
            false,
            |path| {
                synced.push(path.to_path_buf());
                sync_opened_private(path)
            },
        )
        .expect("final metadata and containing entries synced");
        assert_eq!(synced, expected);
        assert_eq!(
            fs::metadata(&charter)
                .expect("charter")
                .permissions()
                .mode()
                & 0o777,
            0o440
        );
        assert_eq!(
            fs::metadata(&template)
                .expect("template")
                .permissions()
                .mode()
                & 0o777,
            0o550
        );
        synced.clear();
        finalize_and_sync_rows(
            &rows,
            &[true, true],
            fixture.path(),
            (owner, group),
            true,
            |path| {
                synced.push(path.to_path_buf());
                sync_opened_private(path)
            },
        )
        .expect("pending retry repeats the durability syncs");
        assert_eq!(synced, expected);
    }

    /// ´test:unit:existing-private-directory-syncs-final-init-before-restored-directory´
    #[test]
    fn existing_private_directory_syncs_final_init_before_restored_directory() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let libexec = fixture.path().join("libexec");
        fs::create_dir(&libexec).expect("existing private directory");
        fs::set_permissions(&libexec, fs::Permissions::from_mode(0o700))
            .expect("directory opened for backfill");
        let init = libexec.join("box-init");
        fs::write(&init, "installed init\n").expect("backfilled init");
        fs::set_permissions(&init, fs::Permissions::from_mode(0o550))
            .expect("finalized init metadata");
        let mut synced = Vec::new();
        sync_private_init(&libexec, true, RefreshCheckpoint::None, |path| {
            synced.push(path.to_path_buf());
            sync_opened_private(path)
        })
        .expect("sync final metadata and directory entry");
        assert_eq!(synced, vec![init, libexec.clone()]);
        assert_eq!(
            fs::metadata(libexec)
                .expect("restored directory")
                .permissions()
                .mode()
                & 0o777,
            0o550
        );
    }

    /// ´test:unit:claude-and-codex-manifests-use-all-copied-source-snapshots´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn claude_and_codex_manifests_use_all_copied_source_snapshots() {
        use super::{expected_payload_rows, sha256};
        use crate::build::payload::{CLAUDE, CODEX, InstallPayload};
        use serde_json::Value;

        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let home = fixture.path();
        let data = home.join("data");
        fs::create_dir(&data).expect("data directory");
        let uid = nix::unistd::Uid::effective().as_raw();
        let image = format!("sha256:{}", "a".repeat(64));
        let sources = [
            (home.join("codex"), b"original Codex\n".as_slice()),
            (home.join("claude"), b"original Claude\n".as_slice()),
            (home.join("host"), b"original companion\n".as_slice()),
            (
                data.join("codex-config.toml"),
                b"model = 'original'\n".as_slice(),
            ),
            (
                data.join("claude-settings.json"),
                b"{\"model\":\"original\"}\n".as_slice(),
            ),
            (
                data.join("worker-AGENTS.md"),
                b"Original charter.\n".as_slice(),
            ),
            (data.join("box-init"), b"original init\n".as_slice()),
        ];
        for (path, bytes) in &sources {
            fs::write(path, bytes).expect("source");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("source mode");
        }
        let payloads: Vec<_> = [CODEX, CLAUDE]
            .into_iter()
            .map(|vendor| InstallPayload {
                vendor,
                bin: home.join(vendor.name),
                sha256: sha256(&home.join(vendor.name)).expect("program hash"),
                image_program: String::new(),
                companion: (vendor == CODEX).then(|| {
                    (
                        home.join("host"),
                        sha256(&home.join("host")).expect("companion hash"),
                    )
                }),
            })
            .collect();
        let mut wrong_pin = payloads.clone();
        wrong_pin[0].sha256 = "0".repeat(64);
        let mut checkpoint_reached = false;
        let error = expected_payload_rows(
            home,
            "alpha",
            uid,
            (uid, uid),
            &data,
            &image,
            "fixture",
            &wrong_pin,
            || {
                checkpoint_reached = true;
            },
        )
        .err()
        .expect("wrong pin refuses");
        assert!(
            checkpoint_reached,
            "checkpoint must precede the first pin check"
        );
        assert_eq!(
            error.line(),
            format!(
                "install-source: Codex sha256 differs: expected {}, found {}",
                wrong_pin[0].sha256, payloads[0].sha256
            )
        );
        let rows = expected_payload_rows(
            home,
            "alpha",
            uid,
            (uid, uid),
            &data,
            &image,
            "fixture",
            &payloads,
            || {
                // Replace every pathname after the final snapshot, before any pin
                // comparison or manifest construction. A later path read must fail.
                for (path, bytes) in &sources {
                    let replacement = path.with_extension("replacement");
                    fs::write(&replacement, b"replaced after snapshot\n").expect("replacement");
                    fs::rename(replacement, path).expect("replace source path");
                    assert_ne!(fs::read(path).expect("changed source"), *bytes);
                }
            },
        )
        .expect("copied evidence survives pathname replacement");
        for payload in &payloads {
            let template = payload.template(&home.join(".var/loops/alpha"), &"a".repeat(64));
            let manifest = rows
                .iter()
                .find(|row| row.path == template.join("manifest"))
                .expect("manifest row");
            let Material::Bytes(bytes) = &manifest.material else {
                panic!("manifest bytes");
            };
            let manifest: Value = serde_json::from_slice(bytes).expect("manifest JSON");
            for (relative, source, key) in [
                (
                    format!("bin/{}", payload.vendor.name),
                    payload.bin.clone(),
                    payload.vendor.hash_key,
                ),
                (
                    payload.vendor.config.into(),
                    payload.config_source(&data),
                    "config_sha256",
                ),
                (
                    payload.vendor.charter.into(),
                    data.join("worker-AGENTS.md"),
                    "charter_sha256",
                ),
            ] {
                let row = rows
                    .iter()
                    .find(|row| row.path == template.join(&relative))
                    .expect("copied row");
                let Material::Copy { bytes, digest } = &row.material else {
                    panic!("source snapshot");
                };
                let original = sources
                    .iter()
                    .find(|(path, _)| *path == source)
                    .expect("original source")
                    .1;
                assert_eq!(bytes, original);
                assert_eq!(manifest[key], digest.as_str());
                if key == payload.vendor.hash_key {
                    assert_eq!(digest, &payload.sha256);
                }
                assert_ne!(sha256(&source).expect("changed hash"), *digest);
            }
        }
    }

    /// ´test:unit:manifest-and-codex-check-use-the-copied-source-snapshot´
    #[test]
    fn manifest_and_codex_check_use_the_copied_source_snapshot() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let home = fixture.path();
        let data = home.join("data");
        fs::create_dir(&data).expect("data directory");
        let charter = data.join("worker-AGENTS.md");
        fs::write(&charter, b"Original charter.\n").expect("charter");
        fs::write(data.join("codex-config.toml"), b"model = 'fixture'\n").expect("config");
        fs::write(data.join("box-init"), b"private init\n").expect("init");
        let codex = home.join("codex");
        fs::write(&codex, b"#!/bin/sh\nexit 0\n").expect("codex");
        fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).expect("codex mode");
        let codex_host = home.join("codex-code-mode-host");
        fs::write(&codex_host, b"#!/bin/sh\nexit 0\n").expect("host");
        fs::set_permissions(&codex_host, fs::Permissions::from_mode(0o700)).expect("host mode");
        let codex_hash = crate::build::sha256(&codex).expect("codex hash");
        let uid = nix::unistd::Uid::effective().as_raw();
        let rows = expected_rows(
            home,
            "alpha",
            uid,
            (uid, uid),
            &data,
            &codex,
            &codex_host,
            &format!("sha256:{}", "a".repeat(64)),
            &codex_hash,
            "fixture",
            || {
                let replacement = data.join("charter-replacement");
                fs::write(&replacement, b"Later charter.\n").expect("replacement charter");
                fs::rename(replacement, &charter).expect("replace charter pathname");
                let replacement = home.join("codex-replacement");
                fs::write(&replacement, b"#!/bin/sh\nexit 1\n").expect("replacement codex");
                fs::rename(replacement, &codex).expect("replace codex pathname");
            },
        )
        .expect("source snapshot");
        let installed_charter = rows
            .iter()
            .find(|row| row.path.file_name().is_some_and(|name| name == "AGENTS.md"))
            .expect("charter row");
        let Material::Copy { bytes, digest } = &installed_charter.material else {
            panic!("charter must be copied");
        };
        assert_eq!(bytes, b"Original charter.\n");
        let manifest = rows
            .iter()
            .find(|row| row.path.file_name().is_some_and(|name| name == "manifest"))
            .expect("manifest row");
        let Material::Bytes(manifest_bytes) = &manifest.material else {
            panic!("manifest must be bytes");
        };
        let manifest: serde_json::Value =
            serde_json::from_slice(manifest_bytes).expect("manifest JSON");
        assert_eq!(manifest["charter_sha256"], digest.as_str());
        assert_eq!(manifest["codex_sha256"], codex_hash);
        assert_eq!(
            fs::read(&charter).expect("changed source"),
            b"Later charter.\n"
        );
    }

    /// ´test:unit:pending-install-recognizes-owner-before-mode-with-distinct-ids´
    #[test]
    fn pending_install_recognizes_owner_before_mode_with_distinct_ids() {
        let expected = Expected {
            path: PathBuf::from("/fixture/alpha/bin/codex"),
            uid: 41001,
            gid: 41001,
            mode: 0o550,
            material: Material::Bytes(Vec::new()),
        };
        assert!(pending_metadata(
            &expected,
            true,
            (0, 0),
            (0, 0, 0o600),
            0o600
        ));
        assert!(pending_metadata(
            &expected,
            true,
            (0, 0),
            (41001, 41001, 0o600),
            0o600
        ));
        assert!(!pending_metadata(
            &expected,
            false,
            (0, 0),
            (41001, 41001, 0o600),
            0o600
        ));
        assert!(!pending_metadata(
            &expected,
            true,
            (0, 0),
            (3001, 3001, 0o600),
            0o600
        ));
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let path = fixture.path().join("codex");
        fs::write(&path, b"measured bytes").expect("staged bytes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("creation mode");
        let staged = Expected {
            path,
            uid: nix::unistd::Uid::effective().as_raw(),
            gid: nix::unistd::Gid::effective().as_raw(),
            mode: 0o550,
            material: Material::Bytes(b"measured bytes".to_vec()),
        };
        assert_ne!(staged.uid, 0, "fixture needs a distinct namespace owner");
        assert!(!inspect(&staged, true, (0, 0), false).expect("owner set before mode"));
        assert_eq!(
            inspect(&staged, false, (0, 0), false)
                .expect_err("complete generation rejects mixed metadata")
                .kind,
            "install-conflict"
        );
    }

    /// ´test:unit:private-finalization-refuses-a-replaced-link-without-changing-its-target´
    #[test]
    fn private_finalization_refuses_a_replaced_link_without_changing_its_target() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        let parent = fixture.path().join("runner-templates");
        fs::create_dir(&parent).expect("protected parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("protected parent mode");
        let path = parent.join("codex");
        fs::write(&path, b"staged").expect("staged inode");
        let foreign = fixture.path().join("foreign");
        fs::write(&foreign, b"foreign").expect("foreign inode");
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).expect("foreign mode");
        let expected = Expected {
            path: path.clone(),
            uid: owner,
            gid: group,
            mode: 0o440,
            material: Material::Bytes(b"staged".to_vec()),
        };
        fs::rename(&path, parent.join("retired")).expect("concurrent replacement");
        symlink(&foreign, &path).expect("replacement link");
        assert_eq!(
            finalize(&expected, fixture.path(), (owner, group))
                .expect_err("link refused")
                .kind,
            "protected-path"
        );
        assert_eq!(
            fs::metadata(&foreign)
                .expect("foreign metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    /// ´test:unit:private-copy-uses-measured-source-after-replacement´
    #[test]
    fn private_copy_uses_measured_source_after_replacement() {
        let fixture = tempfile::tempdir().expect("fixture");
        let source = fixture.path().join("source");
        let destination = fixture.path().join("installed");
        let foreign = fixture.path().join("foreign");
        fs::write(&source, b"measured program").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).expect("source mode");
        let expected = expected_file(destination.clone(), 41001, 41001, 0o550, &source)
            .expect("measured source");
        fs::write(&foreign, b"replacement program").expect("foreign");
        fs::remove_file(&source).expect("remove source");
        symlink(&foreign, &source).expect("replace source by link");
        create(&expected).expect("copy measured snapshot");
        assert_eq!(
            fs::read(destination).expect("installed"),
            b"measured program"
        );
    }
}
