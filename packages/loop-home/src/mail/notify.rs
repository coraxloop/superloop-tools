//! Kernel change hints; every admission still verifies its own filesystem objects.
use super::journal::{MailError, Result};
use super::{Address, io};
use std::collections::BTreeMap;
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

struct Watch {
    path: PathBuf,
    identity: (u64, u64),
    sender: Option<Address>,
}

pub(super) enum Change {
    Outbox(PathBuf, Address, OsString),
    Reconcile,
}

pub(super) struct Notifications {
    descriptor: File,
    watches: BTreeMap<i32, Watch>,
    paths: BTreeMap<PathBuf, i32>,
    reconcile: bool,
}
impl Notifications {
    #[allow(unsafe_code)]
    pub fn new() -> Result<Self> {
        // A successful syscall transfers one owned descriptor to File.
        let descriptor = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            descriptor: unsafe { File::from_raw_fd(descriptor) },
            watches: BTreeMap::new(),
            paths: BTreeMap::new(),
            reconcile: false,
        })
    }
    /// Register a held inode, never retain its descriptor merely to keep a watch alive.
    #[allow(unsafe_code)]
    pub fn add(&mut self, path: &Path, file: &File, sender: Option<Address>) -> Result<()> {
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
            // The kernel can have already invalidated this registration.
            unsafe {
                libc::inotify_rm_watch(self.descriptor.as_raw_fd(), previous);
            }
            self.watches.remove(&previous);
            self.paths.remove(path);
        }
        let held = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| MailError::Invalid("notification descriptor spelling"))?;
        // The proc descriptor link resolves the held inode, not an untrusted original path.
        let id =
            unsafe { libc::inotify_add_watch(self.descriptor.as_raw_fd(), held.as_ptr(), MASK) };
        if id < 0 {
            return Err(std::io::Error::last_os_error().into());
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
    pub fn path(&mut self, path: &Path, directory: bool) -> Result<()> {
        match io::absolute(path, directory) {
            Ok(file) => {
                self.add(path, &file, None)?;
                self.current(path, &file, directory)
            }
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
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let millis = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            let mut poll = libc::pollfd {
                fd: self.descriptor.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // One live pollfd, with a finite maintenance deadline and no periodic scan clock.
            let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
            if ready == 0 {
                return Ok(vec![Change::Reconcile]);
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
                    self.descriptor.as_raw_fd(),
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
        let mut notifications = Notifications::new().expect("inotify");
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
        let mut notifications = Notifications::new().expect("inotify");
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
        let mut notifications = Notifications::new().expect("inotify");
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
        let mut notifications = Notifications::new().expect("inotify");
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
}
