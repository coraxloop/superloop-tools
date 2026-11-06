//! One bounded rights frame followed by EOF; every received descriptor is owned.

use std::io::Read as _;
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::{Error, MAX_ANCHORS, Result};

fn refusal(check: &str) -> Error {
    Error::new("anchor-transport", "entry", "rights").because(check, "rights handoff refused")
}

fn storage(count: usize) -> Result<Vec<usize>> {
    if count > MAX_ANCHORS {
        return Err(refusal("ancillary-size"));
    }
    let bytes = u32::try_from(count * std::mem::size_of::<libc::c_int>())
        .map_err(|_| refusal("ancillary-size"))?;
    #[allow(unsafe_code)]
    // The argument is bounded by MAX_ANCHORS and cannot overflow CMSG_SPACE.
    let length = unsafe { libc::CMSG_SPACE(bytes) } as usize;
    Ok(vec![0; length.div_ceil(std::mem::size_of::<usize>())])
}

/// Send one exact-count rights array and close its write direction.
///
/// # Errors
/// Refuses excessive descriptors, short sends or a failed EOF handoff.
pub fn send(socket: &UnixStream, descriptors: &[OwnedFd]) -> Result<()> {
    send_frame(socket, descriptors)?;
    socket
        .shutdown(Shutdown::Write)
        .map_err(|cause| refusal("send-eof").because("shutdown", cause))
}

#[allow(unsafe_code, clippy::borrow_as_ptr)]
pub(super) fn send_frame(socket: &UnixStream, descriptors: &[OwnedFd]) -> Result<()> {
    let raw: Vec<_> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
    let mut control = storage(raw.len())?;
    let mut byte = [1_u8];
    let mut data = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Aligned owned storage outlives sendmsg; header lengths are bounded and all
    // descriptor owners remain live throughout the syscall.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut data;
        message.msg_iovlen = 1;
        if !raw.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control.len() * std::mem::size_of::<usize>();
            let header = libc::CMSG_FIRSTHDR(&message);
            let bytes = u32::try_from(std::mem::size_of_val(raw.as_slice()))
                .map_err(|cause| refusal("transport-io").because("socket", cause))?;
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(bytes) as usize;
            std::ptr::copy_nonoverlapping(raw.as_ptr(), libc::CMSG_DATA(header).cast(), raw.len());
        }
        if libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(refusal("sendmsg").because("sendmsg", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Receive exactly the declared bounded array, with close-on-exec set atomically.
///
/// The sender must end its write direction; additional bytes or messages refuse.
/// # Errors
/// Refuses absent, truncated or extra control data and a missing bounded EOF.
#[allow(unsafe_code, clippy::borrow_as_ptr)]
pub fn receive(socket: &UnixStream, count: usize, deadline: Duration) -> Result<Vec<OwnedFd>> {
    let mut control = storage(count)?;
    if deadline.is_zero() || deadline > Duration::from_secs(30) {
        return Err(refusal("deadline-range"));
    }
    let start = Instant::now();
    socket
        .set_read_timeout(Some(deadline))
        .map_err(|cause| refusal("transport-io").because("socket", cause))?;
    let mut byte = [0_u8; 2];
    let mut data = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut fds = Vec::new();
    let mut malformed = false;
    // recvmsg fills aligned storage. Parse and own every delivered rights FD even
    // on truncation, so rejection closes it. The kernel closes undelivered rights.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut data;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() * std::mem::size_of::<usize>();
        let length = libc::recvmsg(
            socket.as_fd().as_raw_fd(),
            &mut message,
            libc::MSG_CMSG_CLOEXEC,
        );
        if length < 0 {
            return Err(refusal("recvmsg").because("recvmsg", std::io::Error::last_os_error()));
        }
        let mut header = libc::CMSG_FIRSTHDR(&message);
        let mut messages = 0;
        while !header.is_null() {
            let minimum = libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && (*header).cmsg_len >= minimum
            {
                messages += 1;
                let bytes = (*header).cmsg_len - minimum;
                malformed |= !bytes.is_multiple_of(std::mem::size_of::<libc::c_int>());
                let values = std::slice::from_raw_parts(libc::CMSG_DATA(header), bytes);
                for chunk in values
                    .as_chunks::<{ std::mem::size_of::<libc::c_int>() }>()
                    .0
                {
                    let fd = libc::c_int::from_ne_bytes(*chunk);
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        malformed |= messages != usize::from(count != 0)
            || length != 1
            || byte[0] != 1
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    }
    if malformed || fds.len() != count {
        return Err(refusal("frame-count-or-shape").because(
            "rights-frame",
            format_args!(
                "expected={count} received={} malformed={malformed}",
                fds.len()
            ),
        ));
    }
    let remaining = deadline
        .checked_sub(start.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| refusal("eof-deadline"))?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|cause| refusal("transport-io").because("socket", cause))?;
    let mut extra = [0_u8];
    match (&*socket).read(&mut extra) {
        Ok(0) => Ok(fds),
        Ok(_) => Err(refusal("extra-frame")),
        Err(cause) => Err(refusal("receive-eof").because("eof-read", cause)),
    }
}
