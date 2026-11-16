//! A retained pipe read end with readiness metadata only: deliberately no `Read` or `AsFd`.
use super::{Result, require};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::stat::{SFlag, fstat};
use std::os::fd::{AsRawFd, OwnedFd};

pub(super) struct Input {
    reader: OwnedFd,
    object: (u64, u64),
}
impl Input {
    pub fn admit(reader: OwnedFd) -> Result<Self> {
        let stat = fstat(&reader).map_err(|_| "sealer-input-stat")?;
        let flags = fcntl(&reader, FcntlArg::F_GETFL).map_err(|_| "sealer-input-flags")?;
        require(
            SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFIFO)
                && flags & OFlag::O_ACCMODE.bits() == OFlag::O_RDONLY.bits()
                && flags & OFlag::O_NONBLOCK.bits() == 0,
            "sealer-input-kind",
        )?;
        Ok(Self {
            reader,
            object: (stat.st_dev, stat.st_ino),
        })
    }
    pub fn pair(readers: [OwnedFd; 2]) -> Result<[Self; 2]> {
        let [left, right] = readers;
        let pair = [Self::admit(left)?, Self::admit(right)?];
        require(pair[0].object != pair[1].object, "sealer-input-alias")?;
        Ok(pair)
    }
    pub fn split(self) -> Result<(OwnedFd, EofProbe)> {
        let probe = EofProbe(
            self.reader
                .try_clone()
                .map_err(|_| "sealer-input-duplicate")?,
        );
        Ok((self.reader, probe))
    }
}

pub(super) struct EofProbe(OwnedFd);
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PipeState {
    Open,
    Buffered,
    ClosedAndDrained,
}
impl EofProbe {
    pub fn observe(&self) -> Result<PipeState> {
        let mut item = nix::libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        poll(std::slice::from_mut(&mut item), 0)?;
        classify(item.revents)
    }
}
fn classify(events: i16) -> Result<PipeState> {
    require(
        events & (nix::libc::POLLERR | nix::libc::POLLNVAL) == 0,
        "sealer-input-poll",
    )?;
    Ok(if events & nix::libc::POLLIN != 0 {
        PipeState::Buffered
    } else if events & nix::libc::POLLHUP != 0 {
        PipeState::ClosedAndDrained
    } else {
        PipeState::Open
    })
}
// Only readiness is exposed. No read/readv/splice/tee/ioctl path exists here.
#[allow(unsafe_code)]
pub(super) fn poll(items: &mut [nix::libc::pollfd], timeout: i32) -> Result<bool> {
    // SAFETY: poll receives the live slice pointer/length, never owns descriptors.
    let result = unsafe { nix::libc::poll(items.as_mut_ptr(), items.len() as _, timeout) };
    if result < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            return Ok(true); // Caller rechecks state/deadline, rather than restarting its budget.
        }
        return Err("sealer-poll");
    }
    Ok(result != 0)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    fn wait_for_hangup(probe: &EofProbe) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        loop {
            let timeout = super::super::sealer::remaining_timeout(
                std::time::Instant::now(),
                deadline,
                deadline,
            )
            .unwrap();
            let mut item = nix::libc::pollfd {
                fd: probe.0.as_raw_fd(),
                events: 0,
                revents: 0,
            };
            poll(std::slice::from_mut(&mut item), timeout).unwrap();
            if item.revents & nix::libc::POLLHUP != 0 {
                break;
            }
        }
        assert_eq!(probe.observe().unwrap(), PipeState::ClosedAndDrained);
    }
    /// ´test:unit:sealer-eof-is-readiness-not-a-read´
    #[test]
    fn sealer_eof_is_readiness_not_a_read() {
        let _case = crate::launch::test_support::case_guard();
        let (r, w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (_, probe) = Input::admit(r).unwrap().split().unwrap();
        // No writer task is ever started. A read here would block forever.
        assert_eq!(probe.observe().unwrap(), PipeState::Open);
        let mut writer = std::fs::File::from(w);
        writer.write_all(b"synthetic").unwrap();
        assert_eq!(probe.observe().unwrap(), PipeState::Buffered);
        drop(writer);
        // HUP does not certify drainage; the observer cannot consume the bytes.
        assert_eq!(probe.observe().unwrap(), PipeState::Buffered);
        assert_eq!(probe.observe().unwrap(), PipeState::Buffered);
        let (r, w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (_, empty) = Input::admit(r).unwrap().split().unwrap();
        drop(w);
        wait_for_hangup(&empty);
        assert_eq!(classify(nix::libc::POLLERR), Err("sealer-input-poll"));
        assert_eq!(classify(nix::libc::POLLNVAL), Err("sealer-input-poll"));
    }
    /// ´test:unit:sealer-input-requires-two-distinct-blocking-read-pipes´
    #[test]
    fn sealer_input_requires_two_distinct_blocking_read_pipes() {
        let _case = crate::launch::test_support::case_guard();
        let (r, w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        assert_eq!(Input::admit(w).err(), Some("sealer-input-kind"));
        let duplicate = r.try_clone().unwrap();
        assert_eq!(
            Input::pair([r, duplicate]).err(),
            Some("sealer-input-alias")
        );
        let regular = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            Input::admit(std::fs::File::open(regular.path()).unwrap().into()).err(),
            Some("sealer-input-kind")
        );
        let (r, _w) = nix::unistd::pipe2(OFlag::O_NONBLOCK).unwrap();
        assert_eq!(Input::admit(r).err(), Some("sealer-input-kind"));
    }
    /// ´test:unit:sealer-probe-accepts-an-already-open-fifo´
    #[test]
    fn sealer_probe_accepts_an_already_open_fifo() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _case = crate::launch::test_support::case_guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stream");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        fcntl(&reader, FcntlArg::F_SETFL(OFlag::empty())).unwrap();
        let (_, probe) = Input::admit(reader.into()).unwrap().split().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(probe.observe().unwrap(), PipeState::Open);
        drop(writer);
        wait_for_hangup(&probe);
    }
}
