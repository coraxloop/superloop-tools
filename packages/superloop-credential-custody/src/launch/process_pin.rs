//! Retained process identity at the fixture's stop barrier; no release operation.
use super::{Result, channel, measure::ObjectIdentity, require, store::Invocation};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

pub(super) struct ProcessPin {
    pidfd: OwnedFd,
    directory: File,
    image: File,
    invocation: Invocation,
    stopped: bool,
}
// The receiving side deliberately has no resume, raw-fd or duplication API.
pub(super) struct ObservationPin(ProcessPin);
impl ObservationPin {
    pub fn matches(&self, expected: &Invocation) -> Result<()> {
        self.0.matches(expected)
    }
    pub fn verify(&self) -> Result<()> {
        self.0.verify()
    }
    #[cfg(test)]
    pub fn close_on_exec(&self) -> bool {
        nix::fcntl::fcntl(&self.0.pidfd, nix::fcntl::FcntlArg::F_GETFD)
            .is_ok_and(|f| f & nix::libc::FD_CLOEXEC != 0)
    }
}
impl ProcessPin {
    pub fn capture(
        pid: u32,
        unit: &str,
        id: &str,
        image: ObjectIdentity,
        argv: &[&Path],
    ) -> Result<Self> {
        require(pid > 1, "keeper-pid")?;
        let pidfd = pidfd(pid)?;
        let directory = File::open(format!("/proc/{pid}")).map_err(|_| "keeper-process")?;
        require(
            nix::sys::statfs::fstatfs(&directory)
                .map_err(|_| "keeper-procfs")?
                .filesystem_type()
                == nix::sys::statfs::PROC_SUPER_MAGIC,
            "keeper-procfs",
        )?;
        let executable = File::from(
            openat(
                &directory,
                "exe",
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "keeper-image")?,
        );
        // /proc/PID/exe is deliberately followed only under the verified procfs
        // directory while a pidfd binds liveness; ordinary input links still refuse.
        let (birth, stopped) = stat(&directory)?;
        let uid = directory.metadata().map_err(|_| "keeper-process")?.uid();
        require(uid > 0 && stopped, "keeper-barrier")?;
        require(ObjectIdentity::of(&executable)? == image, "keeper-image")?;
        let expected = argv
            .iter()
            .flat_map(|p| p.as_os_str().as_encoded_bytes().iter().copied().chain([0]))
            .collect::<Vec<_>>();
        require(
            read(&directory, "cmdline", 16 * 1024)? == expected,
            "keeper-command",
        )?;
        let pin = Self {
            pidfd,
            directory,
            image: executable,
            stopped: true,
            invocation: Invocation {
                id: id.to_owned(),
                unit: unit.to_owned(),
                pid,
                birth,
                uid,
                image,
            },
        };
        pin.verify()?;
        Ok(pin)
    }
    pub fn verify(&self) -> Result<()> {
        let mut item = nix::libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        channel::poll(std::slice::from_mut(&mut item), 0)?;
        require(item.revents == 0, "keeper-process-exited")?;
        verify_pidfd(&self.pidfd, self.invocation.pid)?;
        let (birth, stopped) = stat(&self.directory)?;
        require(
            birth == self.invocation.birth && (!self.stopped || stopped),
            "keeper-barrier",
        )?;
        require(
            self.directory
                .metadata()
                .map_err(|_| "keeper-process")?
                .uid()
                == self.invocation.uid,
            "keeper-process-identity",
        )?;
        let current = File::from(
            openat(
                &self.directory,
                "exe",
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "keeper-image")?,
        );
        require(
            ObjectIdentity::of(&current)? == self.invocation.image
                && ObjectIdentity::of(&self.image)? == self.invocation.image,
            "keeper-image",
        )
    }
    #[allow(unsafe_code)]
    pub fn resume(&mut self) -> Result<()> {
        require(self.stopped, "release-duplicate")?;
        self.verify()?;
        // Consume authority before the syscall. An interrupted/failed attempt
        // is uncertain and must never be retried through a numeric PID.
        self.stopped = false;
        // SAFETY: retained live pidfd, SIGCONT, null siginfo, zero flags.
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                nix::libc::SIGCONT,
                std::ptr::null::<nix::libc::siginfo_t>(),
                0,
            )
        };
        require(result == 0, "release-signal")
    }
    pub fn observer_role(&self) -> Result<()> {
        self.verify()?;
        let status = super::child_status::ChildStatus::read(&self.directory)?;
        require(
            status.pid == self.invocation.pid
                && status.birth == self.invocation.birth
                && status.uids == [self.invocation.uid; 4],
            "handoff-peer-identity",
        )?;
        status.observer_role()?;
        self.verify()
    }
    pub fn duplicate(&self) -> Result<OwnedFd> {
        self.verify()?;
        self.pidfd.try_clone().map_err(|_| "handoff-duplicate")
    }
    pub fn transferred(pidfd: OwnedFd, invocation: Invocation) -> Result<ObservationPin> {
        let mut event = nix::libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        channel::poll(std::slice::from_mut(&mut event), 0)?;
        require(event.revents == 0, "keeper-process-exited")?;
        verify_pidfd(&pidfd, invocation.pid)?;
        let directory =
            File::open(format!("/proc/{}", invocation.pid)).map_err(|_| "keeper-process")?;
        require(
            nix::sys::statfs::fstatfs(&directory)
                .map_err(|_| "keeper-procfs")?
                .filesystem_type()
                == nix::sys::statfs::PROC_SUPER_MAGIC,
            "keeper-procfs",
        )?;
        let image = File::from(
            openat(
                &directory,
                "exe",
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "keeper-image")?,
        );
        let pin = Self {
            pidfd,
            directory,
            image,
            invocation,
            stopped: true,
        };
        pin.verify()?;
        Ok(ObservationPin(pin))
    }
    pub fn matches(&self, expected: &Invocation) -> Result<()> {
        require(&self.invocation == expected, "keeper-invocation-binding")?;
        self.verify()
    }
    pub const fn directory(&self) -> &File {
        &self.directory
    }
    pub const fn invocation(&self) -> &Invocation {
        &self.invocation
    }
    pub fn peer(pid: u32, owner: u32, image: ObjectIdentity) -> Result<Self> {
        require(pid > 1, "keeper-pid")?;
        let pidfd = pidfd(pid)?;
        let directory = File::open(format!("/proc/{pid}")).map_err(|_| "keeper-process")?;
        require(
            nix::sys::statfs::fstatfs(&directory)
                .map_err(|_| "keeper-procfs")?
                .filesystem_type()
                == nix::sys::statfs::PROC_SUPER_MAGIC,
            "keeper-procfs",
        )?;
        let executable = File::from(
            openat(
                &directory,
                "exe",
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "keeper-image")?,
        );
        let (birth, _stopped) = stat(&directory)?;
        let uid = directory.metadata().map_err(|_| "keeper-process")?.uid();
        require(uid == owner, "keeper-peer-owner")?;
        require(ObjectIdentity::of(&executable)? == image, "keeper-image")?;
        let pin = Self {
            pidfd,
            directory,
            image: executable,
            stopped: false,
            invocation: Invocation {
                id: String::new(),
                unit: String::new(),
                pid,
                birth,
                uid,
                image,
            },
        };
        pin.verify()?;
        Ok(pin)
    }
    #[allow(unsafe_code)]
    pub fn writers(&self) -> Result<[File; 2]> {
        self.verify()?;
        let duplicate = |slot: i32| -> Result<File> {
            // SAFETY: scalar pidfd_getfd; success transfers a new CLOEXEC fd.
            let fd = unsafe {
                nix::libc::syscall(nix::libc::SYS_pidfd_getfd, self.pidfd.as_raw_fd(), slot, 0)
            };
            require(fd >= 0, "keeper-descriptor-copy")?;
            Ok(unsafe {
                File::from_raw_fd(i32::try_from(fd).map_err(|_| "keeper-descriptor-copy")?)
            })
        };
        let writers = [duplicate(3)?, duplicate(4)?];
        self.verify()?;
        Ok(writers)
    }
}
#[allow(unsafe_code)]
fn pidfd(pid: u32) -> Result<OwnedFd> {
    // SAFETY: scalar query and ownership of a newly returned descriptor.
    let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    require(fd >= 0, "keeper-pidfd")?;
    Ok(unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).map_err(|_| "keeper-pidfd")?) })
}
pub(super) fn read(directory: &File, name: &str, limit: u64) -> Result<Vec<u8>> {
    let file = File::from(
        openat(
            directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "keeper-process-read")?,
    );
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "keeper-process-read")?;
    require(bytes.len() as u64 <= limit, "keeper-process-size")?;
    Ok(bytes)
}
pub(super) fn stat(directory: &File) -> Result<(u64, bool)> {
    let bytes = read(directory, "stat", 4096)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "keeper-process-stat")?;
    let (_, fields) = text.rsplit_once(") ").ok_or("keeper-process-stat")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    require(fields.len() >= 20, "keeper-process-stat")?;
    let birth = fields[19]
        .parse::<u64>()
        .map_err(|_| "keeper-process-stat")?;
    require(birth > 0, "keeper-process-stat")?;
    Ok((birth, fields[0] == "T"))
}

pub(super) fn verify_pidfd(fd: &impl AsRawFd, expected: u32) -> Result<()> {
    let directory = File::open("/proc/self").map_err(|_| "keeper-pidfd-info")?;
    let bytes = read(&directory, &format!("fdinfo/{}", fd.as_raw_fd()), 4096)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "keeper-pidfd-info")?;
    let mut values = text.lines().filter_map(|l| l.strip_prefix("Pid:"));
    let value = values.next().ok_or("keeper-pidfd-info")?.trim();
    require(
        values.next().is_none() && value.parse::<u32>().ok() == Some(expected),
        "keeper-pidfd-binding",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    /// ´test:unit:process-pin-refuses-stale-identities-and-images´
    #[test]
    fn process_pin_refuses_stale_identities_and_images() {
        let f = crate::launch::inventory::tests::fixture("normal");
        let (_readers, writers) = crate::launch::inventory::tests::pipes();
        let (mut guard, mut pin) = crate::launch::inventory::tests::start(&f, &writers);
        for field in 0..5 {
            let mut other = pin.invocation.clone();
            match field {
                0 => other.pid += 1,
                1 => other.birth += 1,
                2 => other.id = "ffffffffffffffffffffffffffffffff".into(),
                3 => other.uid += 1,
                4 => other.image.inode += 1,
                _ => unreachable!(),
            }
            assert_eq!(pin.matches(&other), Err("keeper-invocation-binding"));
        }
        assert_eq!(
            verify_pidfd(&pin.pidfd, pin.invocation.pid + 1),
            Err("keeper-pidfd-binding")
        );
        let old = std::mem::replace(&mut pin.image, File::open("/usr/bin/true").unwrap());
        assert_eq!(pin.verify(), Err("keeper-image"));
        let original = pin.invocation.image;
        pin.invocation.image = ObjectIdentity::of(&pin.image).unwrap();
        assert_eq!(pin.verify(), Err("keeper-image"));
        pin.invocation.image = original;
        pin.image = old;
        let saved = pin.invocation.birth;
        pin.invocation.birth += 1;
        assert_eq!(pin.verify(), Err("keeper-barrier"));
        pin.invocation.birth = saved;
        guard.child.kill().unwrap();
        guard.child.wait().unwrap();
        assert_eq!(pin.verify(), Err("keeper-process-exited"));
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    /// ´test:unit:resumed-fixture-cannot-supply-stopped-inventory´
    #[test]
    fn resumed_fixture_cannot_supply_stopped_inventory() {
        let f = crate::launch::inventory::tests::fixture("normal");
        let path = f.dir.path().join("public.json");
        let mut case: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for stream in case["streams"].as_array_mut().unwrap() {
            stream["length"] = 1_048_576.into();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, serde_json::to_vec(&case).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let (readers, writers) = crate::launch::inventory::tests::pipes();
        for reader in &readers {
            nix::fcntl::fcntl(reader, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).unwrap();
        }
        let (guard, pin) = crate::launch::inventory::tests::start(&f, &writers);
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(guard.child.id()).unwrap()),
            nix::sys::signal::Signal::SIGCONT,
        )
        .unwrap();
        let mut item = nix::libc::pollfd {
            fd: readers[0].as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        crate::launch::channel::poll(std::slice::from_mut(&mut item), 600_000).unwrap();
        assert_ne!(item.revents & nix::libc::POLLIN, 0);
        // The large output cannot fit. Nobody drains it, so it remains live
        // until its own fixture budget; the test observes an event, not a delay.
        assert_eq!(pin.verify(), Err("keeper-barrier"));
    }
}
