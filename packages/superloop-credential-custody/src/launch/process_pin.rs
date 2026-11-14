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
fn read(directory: &File, name: &str, limit: u64) -> Result<Vec<u8>> {
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
fn stat(directory: &File) -> Result<(u64, bool)> {
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
