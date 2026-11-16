//! One bounded metadata transaction on a protected per-case administrative socket.
use super::{
    Result, channel,
    fifo::Pipes,
    measure::{Admission, ObjectIdentity},
    policy::ArtifactRole,
    process_pin::ProcessPin,
    require,
    startup::RootStartup,
    state::Phase,
    store::{Directory, Invocation},
};
use crate::receipt;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::{Deserialize, Serialize};
use std::fs::{File, Permissions};
use std::io::{Read as _, Write as _};
use std::os::{
    fd::{AsRawFd, FromRawFd as _, OwnedFd},
    unix::{
        fs::{MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
};
use std::time::Instant;
const REQUEST_LIMIT: usize = 4096;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    case: String,
    keeper_pid: u32,
    keeper_birth: u64,
    invocation: String,
    operation: Operation,
    nonce: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Operation {
    Status,
    Pidfd,
    Completion,
    Inventory,
    Release { inventory_sha256: String },
    Observed,
}
pub(super) struct Control {
    directory: Directory,
    listener: UnixListener,
    object: ObjectIdentity,
    case: String,
    invocation: String,
    keeper: ProcessPin,
    image: ObjectIdentity,
    owner: u32,
    deadline: Instant,
}
impl Control {
    pub fn bind(
        startup: &RootStartup,
        pipes: &Pipes,
        admission: &Admission,
        index: usize,
        invocation: &Invocation,
    ) -> Result<Self> {
        let owner = startup.owner();
        let image = admission
            .artifacts()
            .iter()
            .find(|a| a.role == ArtifactRole::Launcher)
            .ok_or("control-image")?;
        image.unchanged()?;
        let keeper = ProcessPin::peer(std::process::id(), owner, image.object)?;
        Self::bind_pinned(
            pipes,
            admission,
            index,
            invocation,
            keeper,
            image.object,
            owner,
        )
    }
    fn bind_pinned(
        pipes: &Pipes,
        admission: &Admission,
        index: usize,
        invocation: &Invocation,
        keeper: ProcessPin,
        image: ObjectIdentity,
        owner: u32,
    ) -> Result<Self> {
        let directory = pipes.directory().try_clone()?;
        directory.verify()?;
        let path = format!(
            "/proc/self/fd/{}/control.sock",
            directory.file().as_raw_fd()
        );
        // Bind beneath the retained directory, avoiding sockaddr_un path limits.
        // This is our own held directory capability, never a caller-supplied link.
        let listener = UnixListener::bind(&path).map_err(|_| "control-exclusive")?;
        std::fs::set_permissions(&path, Permissions::from_mode(0o600))
            .map_err(|_| "control-mode")?;
        listener.set_nonblocking(true).map_err(|_| "control-mode")?;
        set_backlog(&listener, admission.policy().limits.event_queue)?;
        let object = ObjectIdentity::of(&socket_file(&directory)?)?;
        let case = admission
            .policy()
            .cases
            .get(index)
            .ok_or("launch-case-binding")?
            .id
            .clone();
        let control = Self {
            directory,
            listener,
            object,
            case,
            invocation: invocation.id.clone(),
            keeper,
            image,
            owner,
            deadline: Instant::now()
                + std::time::Duration::from_millis(admission.policy().limits.case_ms),
        };
        control.verify()?;
        let manifest=serde_json::to_vec(&serde_json::json!({"schema":2,"case":control.case,"invocation":control.invocation,"keeper_pid":control.keeper.invocation().pid,"keeper_birth":control.keeper.invocation().birth,"image":control.image,"socket":control.object,"policy_sha256":admission.policy_sha256(),"case_sha256":admission.cases()[index].sha256,"captured":invocation})).map_err(|_|"control-encoding")?;
        receipt::publish_held(control.directory.file(), "control-manifest.json", &manifest)?;
        Ok(control)
    }
    // The ordinary-user harness has a large Rust test runner and a distinct,
    // small native client image. Production bind above never takes this path.
    #[cfg(test)]
    pub(super) fn test_bind(
        startup: &RootStartup,
        pipes: &Pipes,
        admission: &Admission,
        index: usize,
        invocation: &Invocation,
    ) -> Result<Self> {
        let image = admission
            .artifacts()
            .iter()
            .find(|a| a.role == ArtifactRole::Launcher)
            .ok_or("control-image")?;
        image.unchanged()?;
        let own = std::fs::File::open("/proc/self/exe").map_err(|_| "keeper-image")?;
        let keeper = ProcessPin::peer(
            std::process::id(),
            startup.owner(),
            ObjectIdentity::of(&own)?,
        )?;
        Self::bind_pinned(
            pipes,
            admission,
            index,
            invocation,
            keeper,
            image.object,
            startup.owner(),
        )
    }
    fn verify(&self) -> Result<()> {
        self.directory.verify()?;
        self.keeper.verify()?;
        let file = socket_file(&self.directory)?;
        let m = file.metadata().map_err(|_| "control-binding")?;
        require(
            ObjectIdentity::of(&file)? == self.object
                && m.mode() & 0o170_000 == 0o140_000
                && m.mode() & 0o7777 == 0o600
                && m.uid() == self.owner
                && m.nlink() == 1,
            "control-binding",
        )
    }
    pub fn serve_once(&self, phase: Phase, deadline: Instant) -> Result<()> {
        self.serve(phase, deadline, None, None)
    }
    pub fn serve_pidfd(
        &self,
        phase: Phase,
        deadline: Instant,
        pin: &ProcessPin,
        digest: &str,
    ) -> Result<()> {
        require(phase == Phase::InventoryComplete, "handoff-phase")?;
        require(pin.invocation().id == self.invocation, "handoff-invocation")?;
        pin.verify()?;
        self.serve(phase, deadline, Some((pin, digest)), None)
    }
    pub fn serve_completion(
        &self,
        view: &completion_client::View,
        deadline: Instant,
    ) -> Result<()> {
        self.serve(view.phase, deadline, None, Some(view))
    }
    fn serve(
        &self,
        phase: Phase,
        deadline: Instant,
        handoff: Option<(&ProcessPin, &str)>,
        completion: Option<&completion_client::View>,
    ) -> Result<()> {
        let mut transaction = self.accept(deadline)?;
        match transaction.operation() {
            Operation::Pidfd => {
                let (pin, digest) = handoff.ok_or("control-operation")?;
                transaction.reply_pidfd(pin, digest)
            }
            Operation::Completion => {
                transaction.reply_completion(completion.ok_or("control-operation")?)
            }
            Operation::Status => transaction.reply_status(phase),
            _ => Err("control-operation"),
        }
    }
    pub(super) fn accept(&self, deadline: Instant) -> Result<actions::Transaction> {
        let deadline = deadline.min(self.deadline);
        self.verify()?;
        let (mut stream, _address) = loop {
            budget(deadline)?;
            match self.listener.accept() {
                Ok(value) => break value,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait(self.listener.as_raw_fd(), nix::libc::POLLIN, deadline)?;
                }
                Err(_) => return Err("control-accept"),
            }
        };
        stream.set_nonblocking(true).map_err(|_| "control-mode")?;
        let credentials = peer_credentials(&stream)?;
        let peer = self.authenticate(
            &stream,
            credentials.uid,
            u32::try_from(credentials.pid).map_err(|_| "control-peer")?,
        )?;
        let bytes = read_request(&mut stream, deadline)?;
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| "control-record")?;
        require(
            ((request.schema == 1
                && matches!(
                    request.operation,
                    Operation::Status | Operation::Pidfd | Operation::Completion
                ))
                || (request.schema == 2
                    && matches!(
                        request.operation,
                        Operation::Inventory | Operation::Release { .. } | Operation::Observed
                    )))
                && request.case == self.case
                && request.invocation == self.invocation
                && request.keeper_pid == self.keeper.invocation().pid
                && request.keeper_birth == self.keeper.invocation().birth,
            "control-transaction",
        )?;
        require(
            request.nonce.len() == 32
                && request
                    .nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "control-nonce",
        )?;
        peer.verify()?;
        self.verify()?;
        budget(deadline)?;
        let transaction = actions::Transaction {
            stream,
            peer,
            request,
            owner: self.owner,
            deadline,
        };
        transaction.authorize()?;
        Ok(transaction)
    }
    pub(super) fn ready(&self, interval_ms: u64, deadline: Instant) -> Result<bool> {
        self.verify()?;
        let timeout =
            budget(deadline)?.min(i32::try_from(interval_ms).map_err(|_| "control-poll-bound")?);
        let mut event = nix::libc::pollfd {
            fd: self.listener.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        channel::poll(std::slice::from_mut(&mut event), timeout)?;
        require(
            event.revents & (nix::libc::POLLERR | nix::libc::POLLNVAL | nix::libc::POLLHUP) == 0,
            "control-poll",
        )?;
        Ok(event.revents & nix::libc::POLLIN != 0)
    }

    fn authenticate(&self, stream: &UnixStream, owner: u32, pid: u32) -> Result<ProcessPin> {
        require(owner == self.owner, "control-peer-owner")?;
        let handle = peer_pidfd(stream)?;
        ProcessPin::peer_handle(handle, pid, self.owner, self.image)
    }
    pub fn cleanup(&self) -> Result<()> {
        self.verify()?;
        unlinkat(
            self.directory.file(),
            "control.sock",
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|_| "control-unlink")?;
        self.directory.file().sync_all().map_err(|_| "control-sync")
    }
}
fn socket_file(directory: &Directory) -> Result<File> {
    Ok(File::from(
        openat(
            directory.file(),
            "control.sock",
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "control-binding")?,
    ))
}
fn budget(deadline: Instant) -> Result<i32> {
    super::sealer::remaining_timeout(Instant::now(), deadline, deadline)
        .map_err(|_| "control-deadline")
}
fn wait(fd: i32, events: i16, deadline: Instant) -> Result<()> {
    let timeout = budget(deadline)?;
    let mut item = nix::libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    channel::poll(std::slice::from_mut(&mut item), timeout)?;
    require(
        item.revents & (nix::libc::POLLNVAL | nix::libc::POLLERR) == 0,
        "control-poll",
    )
}
fn write_record(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    require(bytes.len() <= REQUEST_LIMIT, "control-response-size")?;
    let mut remaining = bytes;
    while !remaining.is_empty() {
        budget(deadline)?;
        match stream.write(remaining) {
            Ok(0) => return Err("control-write"),
            Ok(n) => remaining = &remaining[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(stream.as_raw_fd(), nix::libc::POLLOUT, deadline)?;
            }
            Err(_) => return Err("control-write"),
        }
    }
    Ok(())
}

pub(super) fn read_request(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        budget(deadline)?;
        match stream.read(&mut chunk) {
            Ok(0) => {
                require(!bytes.is_empty(), "control-closed")?;
                require(
                    bytes.iter().position(|b| *b == b'\n') == Some(bytes.len() - 1),
                    "control-record",
                )?;
                return Ok(bytes);
            }
            Ok(n) => {
                require(bytes.len() + n <= REQUEST_LIMIT, "control-size")?;
                bytes.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(stream.as_raw_fd(), nix::libc::POLLIN, deadline)?;
            }
            Err(_) => return Err("control-read"),
        }
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
pub(super) mod tests;

#[allow(unsafe_code)]
fn set_backlog(listener: &UnixListener, count: u64) -> Result<()> {
    let count = i32::try_from(count).map_err(|_| "control-backlog")?;
    // SAFETY: listen receives a live owned Unix listener and a checked scalar.
    require(
        unsafe { nix::libc::listen(listener.as_raw_fd(), count) } == 0,
        "control-backlog",
    )
}
#[allow(unsafe_code)]
pub(super) fn peer_credentials(stream: &UnixStream) -> Result<nix::libc::ucred> {
    let mut value = nix::libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = nix::libc::socklen_t::try_from(std::mem::size_of_val(&value))
        .map_err(|_| "control-peer")?;
    // SAFETY: SO_PEERCRED fills the sized, initialized ucred on a live socket.
    let status = unsafe {
        nix::libc::getsockopt(
            stream.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_PEERCRED,
            std::ptr::from_mut(&mut value).cast(),
            &raw mut length,
        )
    };
    require(
        status == 0 && usize::try_from(length).ok() == Some(std::mem::size_of_val(&value)),
        "control-peer",
    )?;
    Ok(value)
}

#[allow(unsafe_code)]
pub(super) fn peer_pidfd(stream: &UnixStream) -> Result<OwnedFd> {
    let mut fd: i32 = -1;
    let mut length = nix::libc::socklen_t::try_from(std::mem::size_of_val(&fd))
        .map_err(|_| "control-peer-pidfd")?;
    // SAFETY: initialized, exactly sized output. On success the kernel gives
    // us one owned CLOEXEC descriptor tied to the connection's original peer.
    let status = unsafe {
        nix::libc::getsockopt(
            stream.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_PEERPIDFD,
            std::ptr::from_mut(&mut fd).cast(),
            &raw mut length,
        )
    };
    require(status == 0 && fd >= 0, "control-peer-pidfd")?;
    let handle = unsafe { OwnedFd::from_raw_fd(fd) };
    require(
        usize::try_from(length).ok() == Some(std::mem::size_of_val(&fd)),
        "control-peer-pidfd",
    )?;
    Ok(handle)
}

#[path = "completion_client.rs"]
pub(super) mod completion_client;

#[path = "control_client.rs"]
pub(super) mod client;

#[path = "control_actions.rs"]
pub(super) mod actions;
