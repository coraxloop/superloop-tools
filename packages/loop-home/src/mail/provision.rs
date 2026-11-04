//! Explicit loop-birth provisioning through namespace and loop identity entry.
use super::journal::{Journal, MailError, Result};
use super::{acl, configuration_store::ConfigurationStore, io};
use crate::allocations::Allocations;
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{Mode, fchmod, mkdirat};
use nix::unistd::{Gid, Uid, fchown};
use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn failure(error: impl std::fmt::Display) -> MailError {
    MailError::Io(std::io::Error::other(error.to_string()))
}
fn owned(file: &File, uid: u32) -> Result<()> {
    if file.metadata()?.uid() != uid {
        return Err(MailError::Invalid("unsafe-storage: provisioning owner"));
    }
    Ok(())
}
pub(super) fn directory(
    parent: &File,
    name: &str,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(File, bool)> {
    let created = match mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
        Ok(()) => true,
        Err(nix::errno::Errno::EEXIST) => false,
        Err(error) => return Err(error.into()),
    };
    let file = io::child(parent, Path::new(name), true)?;
    if created {
        fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
        fchmod(&file, Mode::from_bits_truncate(mode))?;
        file.sync_all()?;
        parent.sync_all()?;
    }
    let info = file.metadata()?;
    if info.uid() != uid || info.gid() != gid || info.mode() & 0o7777 != mode {
        return Err(MailError::Invalid(
            "unsafe-storage: existing provisioned directory differs",
        ));
    }
    Ok((file, created))
}
/// Finish only an empty directory left at a protected creation boundary.
pub(super) fn staged_directory(
    parent: &File,
    name: &str,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(File, bool)> {
    match io::child(parent, Path::new(name), true) {
        Ok(file) => {
            let info = file.metadata()?;
            if info.mode() & 0o7777 == 0o700
                && ((info.uid() == 0 && info.gid() == 0)
                    || (mode != 0o700 && info.uid() == uid && info.gid() == gid))
                && io::names(&file)?.is_empty()
            {
                acl::transport(&file)?;
                fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
                fchmod(&file, Mode::from_bits_truncate(mode))?;
                file.sync_all()?;
                parent.sync_all()?;
                return Ok((file, true));
            }
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    directory(parent, name, uid, gid, mode)
}

fn atomic(parent: &File, name: &str, bytes: &[u8], service: Option<u32>) -> Result<()> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temporary = format!(
        ".mail-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut file = File::from(openat2(
        parent,
        temporary.as_str(),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    file.write_all(bytes)?;
    if let Some(service) = service {
        acl::install(&file, service, false)?;
    }
    file.sync_all()?;
    nix::fcntl::renameat(parent, temporary.as_str(), parent, name)?;
    parent.sync_all()?;
    Ok(())
}
fn reserve(home: &Path, name: &str) -> Result<(u32, u32)> {
    let parent = io::absolute(&home.join(".config/loops"), true)?;
    owned(&parent, 0)?;
    let directory_lock = Flock::lock(parent, FlockArg::LockExclusive)
        .map_err(|(_, error)| MailError::from(error))?;
    let file_lock = match io::child(&directory_lock, Path::new("allocations.toml"), false) {
        Ok(file) => Some(
            Flock::lock(file, FlockArg::LockExclusive)
                .map_err(|(_, error)| MailError::from(error))?,
        ),
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut allocations = Allocations::read_or_empty(&home.join(".config/loops/allocations.toml"))
        .map_err(failure)?;
    if let Some(file_lock) = &file_lock {
        let named = io::child(&directory_lock, Path::new("allocations.toml"), false)?;
        let held = file_lock.metadata()?;
        let current = named.metadata()?;
        if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
            return Err(MailError::Invalid("changed-source: allocation replacement"));
        }
    }
    let registry =
        crate::load_registry(&home.join(".config/loops/registry.toml")).map_err(failure)?;
    let uids = registry
        .rows(home)
        .into_iter()
        .map(|row| row.uid)
        .collect::<Vec<_>>();
    if allocations.get(name).is_none() {
        let block = allocations.next_block().ok_or(MailError::Invalid(
            "unsafe-storage: worker identity range exhausted",
        ))?;
        allocations.insert(name, block).map_err(failure)?;
    }
    let service = allocations.ensure_mail_uid(&uids).map_err(failure)?;
    allocations
        .ensure_mail_groups(name, &uids)
        .map_err(failure)?;
    let group = allocations.mail_group(name, None).map_err(failure)?;
    let bytes = allocations.to_toml();
    if bytes.len() as u64 > crate::allocations::MAX_ALLOCATIONS {
        return Err(MailError::Invalid("invalid-directory: allocations size"));
    }
    atomic(
        &directory_lock,
        "allocations.toml",
        bytes.as_bytes(),
        Some(service),
    )?;
    Ok((service, group))
}
fn host_access(home: &Path, service: u32) -> Result<()> {
    let configuration_root = io::absolute(&home.join(".config/loops"), true)?;
    owned(&configuration_root, 0)?;
    let _configuration_lock = Flock::lock(configuration_root, FlockArg::LockExclusive)
        .map_err(|(_, error)| MailError::from(error))?;
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
    ] {
        let file = io::absolute(&path, true)?;
        owned(&file, 0)?;
        let mode = file.metadata()?.mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(MailError::Invalid(
                "unsafe-storage: writable host configuration ancestor",
            ));
        }
        let base = if path == home.join(".config/loops") {
            0o700
        } else {
            acl::base_mode(&file)?
        };
        acl::grant_ancestor(&file, service, 1, base)?;
    }
    let root = io::absolute(&home.join(".var/loops"), true)?;
    owned(&root, 0)?;
    acl::grant_ancestor(&root, service, 5, 0o711)?;
    let registry = io::absolute(&home.join(".config/loops/registry.toml"), false)?;
    owned(&registry, 0)?;
    acl::ensure_private(&registry, service, false)?;
    let parent = io::absolute(&home.join(".config/loops"), true)?;
    match io::child(&parent, Path::new("mail-service.toml"), false) {
        Ok(_file) => {
            if super::command::settings(home)?.uid != service {
                return Err(MailError::Invalid(
                    "unsafe-storage: service identity changed",
                ));
            }
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic(
                &parent,
                "mail-service.toml",
                format!(
                    "version=1\nuid={service}\ncrash_consistent_rename=false\ndurable_sync=false\n"
                )
                .as_bytes(),
                Some(service),
            )?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
/// Pin the executing image and enter the target cwd before dropping credentials.
#[allow(unsafe_code)]
pub(super) fn spawn_identity(
    uid: u32,
    group: u32,
    cwd: Option<&Path>,
    arguments: &[OsString],
) -> Result<()> {
    let image = File::open("/proc/self/exe")?;
    let descriptor = image.as_raw_fd();
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={uid}"))
        .arg(format!("--groups={group}"))
        .arg("--no-new-privs")
        .arg(format!("/proc/self/fd/{descriptor}"))
        .args(arguments);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    // The parent keeps the image descriptor live through status(). Only the
    // forked child clears CLOEXEC, using the async-signal-safe fcntl syscall.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(descriptor, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status()?;
    if !status.success() {
        return Err(MailError::Invalid(
            "unsafe-storage: identity provisioning step refused",
        ));
    }
    Ok(())
}
fn child(uid: u32, group: u32, mode: &str, path: &Path, service: u32) -> Result<()> {
    let entered = mode == "_mail-configure";
    let arguments = [
        OsString::from(mode),
        if entered {
            OsString::from(".")
        } else {
            path.as_os_str().to_owned()
        },
        OsString::from(service.to_string()),
    ];
    spawn_identity(uid, group, entered.then_some(path), &arguments)
}

pub(super) fn tree(
    parent: &File,
    name: &str,
    actor: u32,
    service: u32,
    group: u32,
) -> Result<File> {
    let staged = name == ".mail-provisioning";
    let ensure_directory = if staged { staged_directory } else { directory };
    let (mail, created) = ensure_directory(parent, name, service, group, 0o750)?;
    let expected = ["draft", "inbox", "outbox", "read", "sent"].map(OsString::from);
    let mut names = io::names(&mail)?;
    names.sort();
    if (!staged && !created && names != expected)
        || names.iter().any(|name| !expected.contains(name))
    {
        return Err(MailError::Invalid(
            "unsafe-storage: existing mailbox is partial or foreign",
        ));
    }
    acl::transport(&mail)?;
    for name in ["inbox", "sent"] {
        let (folder, _) = ensure_directory(&mail, name, service, group, 0o770)?;
        acl::transport(&folder)?;
    }
    for name in ["draft", "outbox", "read"] {
        let desired = if name == "outbox" {
            match io::child(&mail, Path::new(name), true) {
                Ok(folder) if folder.metadata()?.mode() & 0o7777 == 0o770 => 0o770,
                Ok(_) if staged => 0o700,
                Ok(_) => return Err(MailError::Invalid("unsafe-storage: existing outbox mode")),
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => 0o700,
                Err(error) => return Err(error),
            }
        } else {
            0o700
        };
        let (folder, made) = ensure_directory(&mail, name, actor, actor, desired)?;
        if name == "outbox" {
            if made || (staged && desired == 0o700) {
                acl::transport(&folder)?;
                acl::grant_outbox(&folder, service)?;
            }
            acl::outbox(&folder, service)?;
        } else {
            acl::transport(&folder)?;
            if name == "draft" {
                acl::grant_draft_default(&folder, service)?;
            }
        }
    }
    mail.sync_all()?;
    Ok(mail)
}
fn provision(home: &Path, name: &str) -> Result<()> {
    if Uid::effective().as_raw() != 0 {
        return Err(MailError::Invalid(
            "unsafe-storage: namespace-root provisioning required",
        ));
    }
    crate::registry::validate_name(name).map_err(failure)?;
    let registry =
        crate::load_registry(&home.join(".config/loops/registry.toml")).map_err(failure)?;
    let row = registry.row(name, home).map_err(failure)?;
    let (service, group) = reserve(home, name)?;
    host_access(home, service)?;
    let root = io::absolute(&row.home, true)?;
    owned(&root, 0)?;
    if root.metadata()?.mode() & 0o022 != 0 {
        return Err(MailError::Invalid(
            "unsafe-storage: loop ancestor is actor-replaceable",
        ));
    }
    let loops = io::absolute(&home.join(".var/loops"), true)?;
    directory(&loops, ".mail-service", service, service, 0o700)?;
    directory(&root, ".mail-staging", service, service, 0o700)?;
    let existing = match io::child(&root, Path::new("mail"), true) {
        Ok(_) => true,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let staging = if existing {
        "mail"
    } else {
        ".mail-provisioning"
    };
    tree(&root, staging, row.uid, service, group)?;
    child(
        row.uid,
        group,
        "_mail-configure",
        &row.home.join("private"),
        service,
    )?;
    child(service, service, "_mail-journal", home, service)?;
    if !existing {
        renameat2(&root, staging, &root, "mail", RenameFlags::RENAME_NOREPLACE)?;
        root.sync_all()?;
    }
    Ok(())
}
fn run(arguments: &[OsString]) -> Result<()> {
    let [mode, path, value] = arguments else {
        return Err(MailError::Invalid(
            "usage: private mail provisioning MODE PATH VALUE",
        ));
    };
    let path = PathBuf::from(path);
    if mode == "_mail-provision" {
        let name = value
            .to_str()
            .ok_or(MailError::Invalid("invalid-name: loop encoding"))?;
        return provision(&path, name);
    }
    let service = value
        .to_str()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|uid| (1000..=65535).contains(uid) && *uid != 65534)
        .ok_or(MailError::Invalid(
            "unsafe-storage: mapped service identity",
        ))?;
    if mode == "_mail-configure" {
        if Uid::effective().as_raw() == service {
            return Err(MailError::Invalid(
                "unsafe-storage: loop and service identity collision",
            ));
        }
        ConfigurationStore::open(&path, service)?;
        return Ok(());
    }
    if mode == "_mail-journal" && Uid::effective().as_raw() == service {
        let root = io::absolute(&path.join(".var/loops/.mail-service"), true)?;
        if io::names(&root)?.is_empty() {
            Journal::create(root)?;
        } else {
            Journal::open(root)?;
        }
        return Ok(());
    }
    Err(MailError::Invalid(
        "unsafe-storage: private mail entry identity or mode",
    ))
}
/// Execute only explicit private provisioning forms; never enable a service.
pub fn entry(
    arguments: &[OsString],
    output: &mut dyn std::io::Write,
    report: &mut dyn std::io::Write,
) -> u8 {
    let result = if let [mode, home, name] = arguments
        && mode == "_mail-group"
    {
        (|| {
            let home = PathBuf::from(home);
            let name = name
                .to_str()
                .ok_or(MailError::Invalid("invalid-name: loop encoding"))?;
            crate::registry::validate_name(name).map_err(failure)?;
            let path = home.join(".config/loops/allocations.toml");
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            if let Some(group) = Allocations::read_mail_group(&path, name).map_err(failure)? {
                writeln!(output, "{group}")?;
            }
            Ok(())
        })()
    } else {
        run(arguments)
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _written = writeln!(report, "{error}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    struct Fixture {
        path: PathBuf,
        parent: File,
        uid: u32,
        gid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "mail-layout-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("fixture custody");
            let parent = File::open(&path).expect("parent");
            Self {
                path,
                parent,
                uid: Uid::effective().as_raw(),
                gid: Gid::effective().as_raw(),
            }
        }
        // This filesystem fixture checks layout operations, not UID separation.
        fn tree(&self, name: &str) -> Result<File> {
            tree(&self.parent, name, self.uid, self.uid, self.gid)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.path);
        }
    }

    /// ´claim:loophome:mail-layout-retry-preserves-queued-and-read-bytes´
    /// ´test:unit:mail-layout-retry-preserves-queued-and-read-bytes´
    #[test]
    fn mail_layout_retry_preserves_queued_and_read_bytes() {
        let fixture = Fixture::new();
        fixture.tree(".mail-provisioning").expect("staged tree");
        let root = fixture.path.join(".mail-provisioning");
        for name in ["outbox/alpha.01.letter", "read/opaque"] {
            fs::write(root.join(name), b"queued\0opaque\xff").expect("retained bytes");
        }
        fixture.tree(".mail-provisioning").expect("staged retry");
        fs::rename(&root, fixture.path.join("mail")).expect("publish complete folder");
        fixture.tree("mail").expect("complete retry");
        for name in ["outbox/alpha.01.letter", "read/opaque"] {
            assert_eq!(
                fs::read(fixture.path.join("mail").join(name)).expect("preserved bytes"),
                b"queued\0opaque\xff"
            );
        }
    }

    /// ´claim:loophome:mail-layout-finishes-staging-but-refuses-partial-public-folders´
    /// ´test:unit:mail-layout-finishes-staging-but-refuses-partial-public-folders´
    #[test]
    fn mail_layout_finishes_staging_but_refuses_partial_public_folders() {
        let fixture = Fixture::new();
        fixture.tree(".mail-provisioning").expect("initial stage");
        fs::remove_dir(fixture.path.join(".mail-provisioning/read")).expect("interrupted stage");
        fixture.tree(".mail-provisioning").expect("finish stage");
        fs::rename(
            fixture.path.join(".mail-provisioning"),
            fixture.path.join("mail"),
        )
        .expect("publish");
        fs::remove_dir(fixture.path.join("mail/read")).expect("damaged public folder");
        assert!(fixture.tree("mail").is_err());
        assert!(!fixture.path.join("mail/read").exists());
    }

    /// ´claim:loophome:mail-layout-refuses-cross-actor-folder-permissions´
    /// ´test:unit:mail-layout-refuses-cross-actor-folder-permissions´
    #[test]
    fn mail_layout_refuses_cross_actor_folder_permissions() {
        for folder in [
            "mail",
            "mail/inbox",
            "mail/outbox",
            "mail/read",
            "mail/draft",
        ] {
            let fixture = Fixture::new();
            fixture.tree("mail").expect("complete tree");
            fs::set_permissions(fixture.path.join(folder), fs::Permissions::from_mode(0o777))
                .expect("foreign grant");
            assert!(fixture.tree("mail").is_err(), "{folder}");
        }
    }
}
