//! Kernel change hints; every admission still verifies its own filesystem objects.
use super::journal::{MailError, Result};
use super::{Address, io};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_ATTRIB
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;

fn resource_exhausted(error: &MailError) -> bool {
    matches!(error, MailError::Io(error) if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM)))
}

fn quota_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSPC | libc::EMFILE | libc::ENFILE | libc::ENOMEM)
    )
}
fn notification_reason(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::ENOSPC) => format!(
            "inotify-watch-limit: fs.inotify.max_user_watches exhausted (shared host-owner budget): {error}"
        ),
        Some(libc::EMFILE) => format!(
            "inotify-instance-or-descriptor-limit: fs.inotify.max_user_instances or descriptor limit exhausted (shared host-owner budget): {error}"
        ),
        _ => format!("inotify-unavailable: {error}"),
    }
}
#[cfg(test)]
thread_local! {
    pub(super) static INIT_ERROR: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    pub(super) static ADD_ERROR: std::cell::RefCell<Option<(PathBuf, i32)>> = const { std::cell::RefCell::new(None) };
}
#[allow(unsafe_code)]
fn open_instance() -> std::io::Result<File> {
    #[cfg(test)]
    if let Some(error) = INIT_ERROR.with(std::cell::Cell::get) {
        return Err(std::io::Error::from_raw_os_error(error));
    }
    // A successful syscall transfers one owned descriptor to File.
    let descriptor = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}
#[allow(unsafe_code)]
fn register(descriptor: &File, held: &CString, path: &Path) -> std::io::Result<i32> {
    #[cfg(not(test))]
    let _ = path;
    #[cfg(test)]
    if let Some(error) = ADD_ERROR.with(|injected| {
        let mut injected = injected.borrow_mut();
        if injected.as_ref().is_some_and(|(wanted, _)| wanted == path) {
            injected.take().map(|(_, error)| error)
        } else {
            None
        }
    }) {
        return Err(std::io::Error::from_raw_os_error(error));
    }
    let id = unsafe { libc::inotify_add_watch(descriptor.as_raw_fd(), held.as_ptr(), MASK) };
    if id < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(id)
    }
}

struct Watch {
    path: PathBuf,
    identity: (u64, u64),
    sender: Option<Address>,
}

pub(super) enum Change {
    Outbox(PathBuf, Address, OsString),
    Reconcile,
    Timer,
}

pub(super) struct Notifications {
    descriptor: Option<File>,
    watches: BTreeMap<i32, Watch>,
    paths: BTreeMap<PathBuf, i32>,
    reconcile: bool,
    uncovered: BTreeSet<PathBuf>,
    instance_failure: Option<String>,
}
impl Notifications {
    pub fn new() -> Self {
        let mut notifications = Self {
            descriptor: None,
            watches: BTreeMap::new(),
            paths: BTreeMap::new(),
            reconcile: false,
            uncovered: BTreeSet::new(),
            instance_failure: None,
        };
        notifications.begin_scan();
        notifications
    }
    pub fn begin_scan(&mut self) {
        if self.descriptor.is_none() {
            match open_instance() {
                Ok(file) => {
                    self.descriptor = Some(file);
                    if self.instance_failure.take().is_some() {
                        tracing::info!("mail notification instance restored");
                    }
                }
                Err(error) => {
                    let reason = notification_reason(&error);
                    if self.instance_failure.as_ref() != Some(&reason) {
                        tracing::warn!(
                            reason,
                            interval_seconds = 5,
                            "mail notifications unavailable; periodic scan fallback"
                        );
                    }
                    self.instance_failure = Some(reason);
                }
            }
        }
    }
    pub fn finish_scan(&mut self) {
        self.uncovered.retain(|path| {
            !std::fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        });
    }
    pub fn degraded(&self) -> bool {
        self.descriptor.is_none() || !self.uncovered.is_empty()
    }
    /// Register a held inode, never retain its descriptor merely to keep a watch alive.
    #[allow(unsafe_code)]
    pub fn add(&mut self, path: &Path, file: &File, sender: Option<Address>) -> Result<()> {
        let Some(descriptor) = &self.descriptor else {
            return Ok(());
        };
        let info = file.metadata()?;
        let identity = (info.dev(), info.ino());
        if let Some(previous) = self.paths.get(path).copied() {
            if self
                .watches
                .get(&previous)
                .is_some_and(|watch| watch.identity == identity)
            {
                return Ok(());
            }
            // Queued events for the replaced inode can no longer name the current path.
            self.reconcile = true;
            // The kernel can have already invalidated this registration.
            unsafe {
                libc::inotify_rm_watch(descriptor.as_raw_fd(), previous);
            }
            self.watches.remove(&previous);
            self.paths.remove(path);
        }
        let held = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| MailError::Invalid("notification descriptor spelling"))?;
        // The proc descriptor link resolves the held inode, not an untrusted original path.
        let id = match register(descriptor, &held, path) {
            Ok(id) => id,
            Err(error) => {
                if self.uncovered.insert(path.to_owned()) {
                    tracing::warn!(path = %path.display(), reason = notification_reason(&error), interval_seconds = 5, "mail watch unavailable; periodic scan fallback");
                }
                // A quota cannot invalidate an otherwise verified mailbox. Poll it instead.
                if quota_error(&error) {
                    return Ok(());
                }
                return Err(error.into());
            }
        };
        if self.uncovered.remove(path) {
            tracing::info!(path = %path.display(), "mail watch restored");
        }
        self.watches.insert(
            id,
            Watch {
                path: path.to_owned(),
                identity,
                sender,
            },
        );
        self.paths.insert(path.to_owned(), id);
        Ok(())
    }
    pub const fn reconcile(&mut self) {
        self.reconcile = true;
    }
    pub fn current(&mut self, path: &Path, held: &File, directory: bool) -> Result<()> {
        let expected = held.metadata()?;
        let matches = match io::absolute(path, directory) {
            Ok(file) => {
                let observed = file.metadata()?;
                (observed.dev(), observed.ino()) == (expected.dev(), expected.ino())
            }
            Err(error) if resource_exhausted(&error) => return Err(error),
            Err(_) => false,
        };
        if !matches {
            self.reconcile();
        }
        Ok(())
    }
    pub fn hint(&mut self, path: &Path, file: &File) {
        if let Err(error) = self.add(path, file, None) {
            tracing::debug!(path = %path.display(), reason = %error, "notification hint registration unavailable");
        }
    }
    pub fn path(&mut self, path: &Path, directory: bool) -> Result<()> {
        match io::absolute(path, directory) {
            Ok(file) => match self.add(path, &file, None) {
                Ok(()) => self.current(path, &file, directory),
                Err(error) => {
                    tracing::debug!(path = %path.display(), reason = %error, "notification hint registration unavailable");
                    Ok(())
                }
            },
            Err(error) if resource_exhausted(&error) => Err(error),
            Err(error) => {
                // An advisory path can be absent or untrusted. Inventory and admission
                // still issue their own refusals; this must not stop unrelated mail.
                tracing::debug!(path = %path.display(), reason = %error, "notification hint path unavailable");
                Ok(())
            }
        }
    }
    #[allow(unsafe_code)]
    pub fn wait(&mut self, timeout: Duration) -> Result<Vec<Change>> {
        if std::mem::take(&mut self.reconcile) {
            return Ok(vec![Change::Reconcile]);
        }
        let Some(descriptor) = &self.descriptor else {
            std::thread::sleep(timeout);
            return Ok(vec![Change::Timer]);
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let millis = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            let mut poll = libc::pollfd {
                fd: descriptor.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // One live pollfd, with a finite maintenance deadline and no periodic scan clock.
            let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
            if ready == 0 {
                return Ok(vec![Change::Timer]);
            }
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            let mut bytes = [0_u8; 16384];
            let length = unsafe {
                libc::read(
                    descriptor.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if length < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error.into());
            }
            return self.decode(
                &bytes[..usize::try_from(length)
                    .map_err(|_| MailError::Invalid("notification length"))?],
            );
        }
    }
    fn decode(&mut self, bytes: &[u8]) -> Result<Vec<Change>> {
        let mut changes = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let header = bytes
                .get(offset..offset + 16)
                .ok_or(MailError::Invalid("short notification"))?;
            let id = i32::from_ne_bytes(
                header[..4]
                    .try_into()
                    .map_err(|_| MailError::Invalid("notification id"))?,
            );
            let mask = u32::from_ne_bytes(
                header[4..8]
                    .try_into()
                    .map_err(|_| MailError::Invalid("notification mask"))?,
            );
            let length = u32::from_ne_bytes(
                header[12..16]
                    .try_into()
                    .map_err(|_| MailError::Invalid("notification name length"))?,
            ) as usize;
            let name = bytes
                .get(offset + 16..offset + 16 + length)
                .ok_or(MailError::Invalid("short notification name"))?;
            offset += 16 + length;
            if mask & libc::IN_Q_OVERFLOW != 0 {
                tracing::warn!("mail notification overflow; reconciling before admission");
                changes.push(Change::Reconcile);
            } else if mask & libc::IN_IGNORED != 0 {
                if let Some(watch) = self.watches.remove(&id) {
                    self.paths.remove(&watch.path);
                    changes.push(Change::Reconcile);
                }
            } else if let Some(watch) = self.watches.get(&id) {
                if let Some(sender) = &watch.sender
                    && let Some(end) = name.iter().position(|byte| *byte == 0)
                    && end != 0
                {
                    changes.push(Change::Outbox(
                        watch.path.clone(),
                        sender.clone(),
                        OsString::from_vec(name[..end].to_vec()),
                    ));
                } else {
                    changes.push(Change::Reconcile);
                }
            }
        }
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// ´claim:loophome:mail-notifications-wake-for-rename-without-a-scan´
    /// ´test:unit:mail-notifications-wake-for-rename-without-a-scan´
    #[test]
    fn mail_notifications_wake_for_rename_without_a_scan() {
        let root = std::env::temp_dir().join(format!("mail-notify-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let outbox = root.join("outbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let mut notifications = Notifications::new();
        let file = File::open(&outbox).expect("held directory");
        notifications
            .add(
                &outbox,
                &file,
                Some(Address::parse("alpha").expect("address")),
            )
            .expect("watch");
        drop(file);
        let draft = root.join("draft");
        std::fs::write(&draft, b"opaque").expect("draft");
        std::fs::rename(draft, outbox.join("beta.01.letter")).expect("submit");
        let changes = notifications.wait(Duration::ZERO).expect("queued event");
        assert!(changes.iter().any(|change| matches!(change, Change::Outbox(_, sender, name) if sender.to_string() == "alpha" && name == "beta.01.letter")));
        assert_eq!(notifications.watches.len(), 1);
        std::fs::remove_dir_all(root).expect("cleanup");
    }
    /// ´claim:loophome:mail-notification-overflow-and-invalidation-reconcile´
    /// ´test:unit:mail-notification-overflow-and-invalidation-reconcile´
    #[test]
    fn mail_notification_overflow_and_invalidation_reconcile() {
        let mut notifications = Notifications::new();
        let mut bytes = (-1_i32).to_ne_bytes().to_vec();
        bytes.extend(libc::IN_Q_OVERFLOW.to_ne_bytes());
        bytes.extend([0_u8; 8]);
        assert!(matches!(
            notifications.decode(&bytes).expect("overflow").as_slice(),
            [Change::Reconcile]
        ));
        assert!(notifications.decode(&bytes[..15]).is_err());
        let root =
            std::env::temp_dir().join(format!("mail-notify-invalidate-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        notifications
            .add(&root, &File::open(&root).expect("directory"), None)
            .expect("watch");
        let id = *notifications.paths.get(&root).expect("registration");
        let mut ignored = id.to_ne_bytes().to_vec();
        ignored.extend(libc::IN_IGNORED.to_ne_bytes());
        ignored.extend([0_u8; 8]);
        assert!(matches!(
            notifications
                .decode(&ignored)
                .expect("invalidation")
                .as_slice(),
            [Change::Reconcile]
        ));
        assert_eq!(notifications.paths.len(), 0);
        assert_eq!(notifications.watches.len(), 0);
        std::fs::remove_dir(root).expect("cleanup");
    }
    /// ´claim:loophome:mail-watch-registration-rechecks-replaced-inodes´
    /// ´test:unit:mail-watch-registration-rechecks-replaced-inodes´
    #[test]
    fn mail_watch_registration_rechecks_replaced_inodes() {
        let root =
            std::env::temp_dir().join(format!("mail-notify-replaced-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let path = root.join("outbox");
        std::fs::create_dir(&path).expect("old directory");
        let held = File::open(&path).expect("held old directory");
        std::fs::rename(&path, root.join("old")).expect("replace before arming");
        std::fs::create_dir(&path).expect("replacement");
        let mut notifications = Notifications::new();
        notifications
            .add(&path, &held, None)
            .expect("watch old inode");
        notifications
            .current(&path, &held, true)
            .expect("check identity");
        assert!(matches!(
            notifications
                .wait(Duration::ZERO)
                .expect("reconcile")
                .as_slice(),
            [Change::Reconcile]
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }
    /// ´claim:loophome:mail-untrusted-hint-path-does-not-stop-other-mailboxes´
    /// ´test:unit:mail-untrusted-hint-path-does-not-stop-other-mailboxes´
    #[test]
    fn mail_untrusted_hint_path_does_not_stop_other_mailboxes() {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("mail-notify-untrusted-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let target = root.join("private-file");
        std::fs::write(&target, b"untrusted configuration").expect("file");
        let path = root.join("loop.toml");
        symlink(&target, &path).expect("invalid configuration link");
        let mut notifications = Notifications::new();
        notifications
            .path(&path, false)
            .expect("an unavailable hint is not service authority");
        assert_eq!(
            notifications.watches.len(),
            0,
            "never follow the untrusted link"
        );
        assert!(
            io::absolute(&path, false).is_err(),
            "the actual read still refuses the link"
        );
        let outbox = root.join("outbox");
        std::fs::create_dir(&outbox).expect("unrelated mailbox");
        notifications
            .add(
                &outbox,
                &File::open(&outbox).expect("outbox"),
                Some(Address::parse("beta").expect("address")),
            )
            .expect("unrelated watch");
        std::fs::write(outbox.join("alpha.01.letter"), b"opaque").expect("unrelated arrival");
        assert!(notifications.wait(Duration::ZERO).expect("arrival").iter().any(|change| matches!(change, Change::Outbox(_, sender, _) if sender.to_string() == "beta")));
        std::fs::remove_dir_all(root).expect("cleanup");
    }
    /// ´claim:loophome:mail-hint-registration-errors-do-not-stop-other-watches´
    /// ´test:unit:mail-hint-registration-errors-do-not-stop-other-watches´
    #[test]
    fn mail_hint_registration_errors_do_not_stop_other_watches() {
        let root = std::env::temp_dir().join(format!("mail-notify-hint-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let hint = root.join("loop.toml");
        std::fs::write(&hint, b"configuration").expect("hint");
        let mut notifications = Notifications::new();
        ADD_ERROR.with(|error| *error.borrow_mut() = Some((hint.clone(), libc::EACCES)));
        notifications
            .path(&hint, false)
            .expect("optional registration failure");
        assert!(notifications.degraded());
        notifications
            .add(
                &root,
                &File::open(&root).expect("directory"),
                Some(Address::parse("beta").expect("address")),
            )
            .expect("unrelated watch");
        std::fs::write(root.join("alpha.01.letter"), b"opaque").expect("arrival");
        assert!(notifications.wait(Duration::ZERO).expect("event").iter().any(|change| matches!(change, Change::Outbox(_, _, name) if name == "alpha.01.letter")));
        std::fs::remove_file(&hint).expect("removed hint needs no watch");
        notifications.finish_scan();
        assert!(!notifications.degraded());
        std::fs::remove_dir_all(root).expect("cleanup");
    }
    /// ´claim:loophome:mail-reregistered-configuration-forces-reconciliation´
    /// ´test:unit:mail-reregistered-configuration-forces-reconciliation´
    #[test]
    fn mail_reregistered_configuration_forces_reconciliation() {
        let root = std::env::temp_dir().join(format!("mail-notify-config-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let path = root.join("loop.toml");
        std::fs::write(&path, b"old").expect("old configuration");
        let mut notifications = Notifications::new();
        notifications.path(&path, false).expect("initial watch");
        std::fs::write(root.join("replacement"), b"new").expect("replacement");
        std::fs::rename(root.join("replacement"), &path).expect("replace during inventory");
        notifications
            .path(&path, false)
            .expect("re-registration after inventory");
        assert!(matches!(
            notifications
                .wait(Duration::ZERO)
                .expect("forced reconciliation")
                .as_slice(),
            [Change::Reconcile]
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }
    /// ´claim:loophome:mail-watch-quota-diagnostics-name-the-shared-budget´
    /// ´test:unit:mail-watch-quota-diagnostics-name-the-shared-budget´
    #[test]
    fn mail_watch_quota_diagnostics_name_the_shared_budget() {
        for (error, setting) in [
            (libc::ENOSPC, "fs.inotify.max_user_watches"),
            (libc::EMFILE, "fs.inotify.max_user_instances"),
        ] {
            let reason = notification_reason(&std::io::Error::from_raw_os_error(error));
            assert!(reason.contains(setting));
            assert!(reason.contains("shared host-owner budget"));
        }
    }
}
