//! A pinned, reviewed deployment controller owns session stop and restoration.
//!
//! The migration command verifies installed artifact bytes and kernel identities;
//! controller success alone never grants activation or proves a quiet worker.
use super::{
    io,
    journal::{MailError, Result, digest},
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Implementation bound for deployment plans and controller evidence.
pub(super) const MAX_BYTES: u64 = 16 * 1024 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub path: PathBuf,
    pub current: Artifact,
    pub previous: Artifact,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Retirement {
    pub requirement: String,
    pub revision: String,
    pub review: Artifact,
    pub installed_digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub controller: Artifact,
    pub native_lane: Artifact,
    pub artifacts: Vec<Installed>,
    pub retirements: Vec<Retirement>,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
impl Artifact {
    /// Open the reviewed inode, refusing writable deployment inputs or changed bytes.
    ///
    /// # Errors
    /// Every artifact is namespace-root owned, single-link, regular and not group/world writable.
    pub fn open(&self) -> Result<File> {
        let file = io::absolute(&self.path, false)?;
        let info = file.metadata()?;
        if info.uid() != nix::unistd::Uid::effective().as_raw() || info.mode() & 0o022 != 0 {
            return Err(invalid("unsafe-storage: migration artifact custody"));
        }
        if digest(&bounded(&file, 512 * 1024 * 1024)?) != self.sha256 {
            return Err(invalid("changed-source: migration artifact digest differs"));
        }
        Ok(file)
    }
}
impl Deployment {
    fn verify_images(&self, previous: bool) -> Result<()> {
        let mut paths = std::collections::BTreeSet::new();
        for item in &self.artifacts {
            if !paths.insert(item.path.clone()) {
                return Err(invalid("invalid-directory: duplicate deployment artifact"));
            }
            let current = item.current.open()?;
            let previous_image = item.previous.open()?;
            let installed = io::absolute(&item.path, false)?;
            let installed_info = installed.metadata()?;
            for archive in [&current, &previous_image] {
                let archived = archive.metadata()?;
                if (archived.dev(), archived.ino()) == (installed_info.dev(), installed_info.ino())
                {
                    return Err(invalid(
                        "unsafe-storage: rollback artifacts must be retained independently of installed paths",
                    ));
                }
            }
            let actual = Artifact {
                path: item.path.clone(),
                sha256: if previous {
                    item.previous.sha256.clone()
                } else {
                    item.current.sha256.clone()
                },
            };
            actual.open()?;
        }
        Ok(())
    }
    /// Bind reviewed retirement evidence to the complete installed program projection.
    ///
    /// # Errors
    /// Missing linker images, duplicate destinations or a review for another artifact set refuse.
    pub fn verify(&self, previous: bool) -> Result<()> {
        self.verify_images(previous)?;
        for name in [
            "superloop",
            "superloop-install",
            "superloop-lane",
            "superloop-mail",
            "door-service",
            "door-ssh",
            "permission-triage-assemble",
            "permission-triage-hook",
            "superloop-claude-hook",
            "vendor-proxy",
            "worker-run",
        ] {
            if !self
                .artifacts
                .iter()
                .any(|item| item.path.file_name().is_some_and(|leaf| leaf == name))
            {
                return Err(invalid(
                    "invalid-directory: migration deployment lacks a loop-home linker",
                ));
            }
        }
        let projection = serde_json::to_vec(&self.artifacts)
            .map_err(|_| invalid("invalid-directory: artifact projection"))?;
        let expected = digest(&projection);
        for requirement in [
            "req:mail:legacy-entry-retirement",
            "req:mail:round-transport",
        ] {
            let matches = self
                .retirements
                .iter()
                .filter(|evidence| evidence.requirement == requirement)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(invalid(
                    "invalid-directory: missing or duplicate reviewed retirement evidence",
                ));
            }
            let evidence = matches[0];
            if evidence.installed_digest != expected
                || evidence.revision.len() != 40
                || !evidence
                    .revision
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(invalid(
                    "invalid-directory: retirement evidence is not bound to installed artifacts",
                ));
            }
            evidence.review.open()?;
        }
        let lane = self
            .artifacts
            .iter()
            .find(|item| {
                item.path
                    .file_name()
                    .is_some_and(|name| name == "superloop-lane")
            })
            .ok_or_else(|| invalid("invalid-directory: native census image missing"))?;
        if self.native_lane.path != lane.current.path
            || self.native_lane.sha256 != lane.current.sha256
        {
            return Err(invalid(
                "invalid-directory: census must use the reviewed installed lane image",
            ));
        }
        self.controller.open()?;
        self.native_lane.open()?;
        Ok(())
    }
}
fn output(root: &File, label: &str, stream: &str) -> Result<(String, File)> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    loop {
        let number = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("action-{label}-{}-{number}.{stream}", std::process::id());
        match nix::fcntl::openat2(
            root,
            name.as_str(),
            nix::fcntl::OpenHow::new()
                .flags(
                    nix::fcntl::OFlag::O_RDWR
                        | nix::fcntl::OFlag::O_CREAT
                        | nix::fcntl::OFlag::O_EXCL
                        | nix::fcntl::OFlag::O_CLOEXEC,
                )
                .mode(nix::sys::stat::Mode::from_bits_truncate(0o600))
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        ) {
            Ok(file) => return Ok((name, File::from(file))),
            Err(nix::errno::Errno::EEXIST) => (),
            Err(error) => return Err(error.into()),
        }
    }
}
pub(super) fn bounded(file: &File, limit: u64) -> Result<Vec<u8>> {
    io::bounded(file, limit).map_err(|error| match error {
        MailError::Invalid(reason) if reason.starts_with("oversize:") => {
            invalid("invalid-directory: migration metadata exceeds its implementation bound")
        }
        error => error,
    })
}
/// Execute the held executable inode with a cleared environment and retained output.
///
/// # Errors
/// Failure, oversized output or modified image refuses the transition. Each attempt keeps both streams.
pub(super) fn invoke(
    artifact: &Artifact,
    arguments: &[std::ffi::OsString],
    home: &Path,
    state: &Path,
    label: &str,
) -> Result<Vec<u8>> {
    let image = artifact.open()?;
    if image.metadata()?.mode() & 0o111 == 0 {
        return Err(invalid(
            "unsafe-storage: controller artifact is not executable",
        ));
    }
    let directory = io::absolute(state, true)?;
    let (name, mut file) = output(&directory, label, "out")?;
    let (error_name, error_file) = output(&directory, label, "err")?;
    let program = format!("/proc/{}/fd/{}", std::process::id(), image.as_raw_fd());
    let status = Command::new(&program)
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(error_file.try_clone()?)
        .status()?;
    file.flush()?;
    file.sync_all()?;
    error_file.sync_all()?;
    directory.sync_all()?;
    artifact.open()?;
    let result = io::child(&directory, Path::new(&name), false)?;
    bounded(
        &io::child(&directory, Path::new(&error_name), false)?,
        MAX_BYTES,
    )?;
    if !status.success() {
        return Err(invalid(
            "changed-source: reviewed deployment action refused; inspect retained output",
        ));
    }
    bounded(&result, MAX_BYTES)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    /// ´claim:loophome:migration-controller-executes-only-the-reviewed-inode-and-retains-output´
    /// ´test:unit:migration-controller-executes-only-the-reviewed-inode-and-retains-output´
    #[test]
    fn migration_controller_executes_only_the_reviewed_inode_and_retains_output() {
        let root =
            std::env::temp_dir().join(format!("migration-controller-{}", std::process::id()));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("custody");
        let path = root.join("controller");
        let bytes = b"#!/bin/sh\nprintf '{\"complete\":true}\\n'\n";
        fs::write(&path, bytes).expect("controller");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable");
        let artifact = Artifact {
            path: path.clone(),
            sha256: digest(bytes),
        };
        let output = invoke(&artifact, &[], &root, &root, "probe").expect("reviewed controller");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).expect("JSON")["complete"],
            true
        );
        assert!(fs::read_dir(&root).expect("outputs").any(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("action-probe-")
        }));
        fs::write(path, b"#!/bin/sh\nexit 0\n").expect("replace executable bytes");
        assert!(invoke(&artifact, &[], &root, &root, "changed").is_err());
        assert!(!fs::read_dir(&root).expect("outputs").any(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("action-changed-")
        }));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
