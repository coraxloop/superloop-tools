//! Protected opening of the existing keeper's read-only completion transaction.
use super::{Result, completion_client, peer_credentials, peer_pidfd, require, wait};
use crate::launch::{
    measure::{Admission, ObjectIdentity},
    policy::ArtifactRole,
    process_pin,
};
use crate::receipt;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::{fs::MetadataExt as _, net::UnixStream},
    },
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub schema: u32,
    pub case: String,
    pub invocation: String,
    pub keeper_pid: u32,
    pub keeper_birth: u64,
    pub image: ObjectIdentity,
    pub socket: ObjectIdentity,
    pub policy_sha256: String,
    pub case_sha256: String,
    pub captured: crate::launch::store::Invocation,
}

struct Expected<'a> {
    case: &'a str,
    policy: &'a str,
    public_case: &'a str,
    image: ObjectIdentity,
    owner: u32,
    unit: &'a str,
    fixture: ObjectIdentity,
    sealed_limit: u64,
}
struct Opened {
    root: PathBuf,
    directory: File,
    record: File,
    record_bytes: Vec<u8>,
    manifest: Manifest,
    stream: UnixStream,
    owner: u32,
    sealed_limit: u64,
}
fn file(directory: &File, name: &str, flags: OFlag) -> Result<File> {
    openat(
        directory,
        name,
        flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| "client-object")
}
impl Opened {
    fn open(root: &Path, expected: &Expected<'_>, deadline: Instant) -> Result<Self> {
        super::budget(deadline)?;
        let directory = receipt::sealed_directory(root)?;
        let record = file(&directory, "control-manifest.json", OFlag::O_RDONLY)?;
        let bytes = receipt::read_file(
            record.try_clone().map_err(|_| "client-record")?,
            16 * 1024,
            true,
        )?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| "client-manifest")?;
        require(
            manifest.schema == 2
                && manifest.case == expected.case
                && manifest.policy_sha256 == expected.policy
                && manifest.case_sha256 == expected.public_case
                && manifest.image == expected.image
                && manifest.keeper_pid > 1
                && manifest.keeper_birth > 0
                && manifest.invocation.len() == 32
                && manifest
                    .invocation
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && manifest.invocation != "0".repeat(32)
                && manifest.captured.id == manifest.invocation
                && manifest.captured.unit == expected.unit
                && manifest.captured.image == expected.fixture
                && manifest.captured.pid > 1
                && manifest.captured.uid > 0
                && manifest.captured.birth > 0,
            "client-binding",
        )?;
        verify_socket(&directory, &manifest, expected.owner)?;
        let path = format!("/proc/self/fd/{}/control.sock", directory.as_raw_fd());
        let stream = connect(&path, deadline)?;
        let opened = Self {
            root: root.into(),
            directory,
            record,
            record_bytes: bytes,
            manifest,
            stream,
            owner: expected.owner,
            sealed_limit: expected.sealed_limit,
        };
        opened.verify()?;
        Ok(opened)
    }
    fn verify(&self) -> Result<()> {
        let credentials = peer_credentials(&self.stream)?;
        require(
            credentials.uid == self.owner
                && u32::try_from(credentials.pid).ok() == Some(self.manifest.keeper_pid),
            "client-peer",
        )?;
        let handle = peer_pidfd(&self.stream)?;
        completion_client::live(&handle)?;
        process_pin::verify_pidfd(&handle, self.manifest.keeper_pid)?;
        let process =
            File::open(format!("/proc/{}", self.manifest.keeper_pid)).map_err(|_| "client-stat")?;
        let (birth, _) = process_pin::stat(&process)?;
        completion_client::live(&handle)?;
        require(birth == self.manifest.keeper_birth, "client-birth")?;
        let current = receipt::sealed_directory(&self.root)?;
        require(
            ObjectIdentity::of(&current)? == ObjectIdentity::of(&self.directory)?,
            "client-directory-binding",
        )?;
        let record = file(&self.directory, "control-manifest.json", OFlag::O_RDONLY)?;
        require(
            ObjectIdentity::of(&record)? == ObjectIdentity::of(&self.record)?,
            "client-record-binding",
        )?;
        let bytes = receipt::read_file(record, 16 * 1024, true)?;
        require(bytes == self.record_bytes, "client-record-binding")?;
        verify_socket(&self.directory, &self.manifest, self.owner)
    }
    fn completion(&mut self, deadline: Instant) -> Result<completion_client::Observation> {
        self.verify()?;
        let result = completion_client::request(
            &mut self.stream,
            &completion_client::Binding {
                case: &self.manifest.case,
                invocation: &self.manifest.captured,
                keeper_pid: self.manifest.keeper_pid,
                keeper_birth: self.manifest.keeper_birth,
                keeper_uid: self.owner,
                sealed_limit: self.sealed_limit,
            },
            deadline,
        )?;
        self.verify()?;
        Ok(result)
    }
}
fn verify_socket(directory: &File, manifest: &Manifest, owner: u32) -> Result<()> {
    let socket = file(directory, "control.sock", OFlag::O_PATH)?;
    let m = socket.metadata().map_err(|_| "client-object")?;
    require(
        ObjectIdentity::of(&socket)? == manifest.socket
            && m.mode() & 0o170_000 == 0o140_000
            && m.mode() & 0o7777 == 0o600
            && m.uid() == owner
            && m.nlink() == 1,
        "client-socket-binding",
    )
}
pub(in crate::launch) fn completion(
    admission: &Admission,
    index: usize,
    deadline: Instant,
) -> Result<completion_client::Observation> {
    opened(admission, index, deadline)?.completion(deadline)
}
fn opened(admission: &Admission, index: usize, deadline: Instant) -> Result<Opened> {
    let case = admission
        .policy()
        .cases
        .get(index)
        .ok_or("launch-case-binding")?;
    let image = admission
        .artifacts()
        .iter()
        .find(|a| a.role == ArtifactRole::Launcher)
        .ok_or("client-image")?;
    image.unchanged()?;
    let expected = Expected {
        case: &case.id,
        policy: admission.policy_sha256(),
        public_case: &admission.cases()[index].sha256,
        image: image.object,
        owner: admission.owner(),
        unit: &case.generator_unit,
        fixture: admission.fixture_image(),
        sealed_limit: admission.policy().limits.sealed_bytes,
    };
    Opened::open(
        &admission.policy().roots.runtime.join(&case.id),
        &expected,
        deadline,
    )
}

#[cfg(test)]
#[path = "control_client_tests.rs"]
mod tests;

// This transport uses the already admitted libc surface; it does not add the
// optional nix socket feature or a second dependency closure.
#[allow(unsafe_code)]
fn connect(path: &str, deadline: Instant) -> Result<UnixStream> {
    // SAFETY: sockaddr_un has only integer fields; the zeroed path is terminated.
    let mut address: nix::libc::sockaddr_un = unsafe { std::mem::zeroed() };
    require(path.len() < address.sun_path.len(), "client-address")?;
    address.sun_family =
        nix::libc::sa_family_t::try_from(nix::libc::AF_UNIX).map_err(|_| "client-address")?;
    for (slot, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
        *slot = nix::libc::c_char::try_from(byte).map_err(|_| "client-address")?;
    }
    // SAFETY: scalar socket arguments; successful return transfers one owned fd.
    let fd = unsafe {
        nix::libc::socket(
            nix::libc::AF_UNIX,
            nix::libc::SOCK_STREAM | nix::libc::SOCK_CLOEXEC | nix::libc::SOCK_NONBLOCK,
            0,
        )
    };
    require(fd >= 0, "client-socket")?;
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    let length = nix::libc::socklen_t::try_from(std::mem::size_of_val(&address))
        .map_err(|_| "client-address")?;
    // SAFETY: exactly sized initialized address, live owned nonblocking socket.
    let result = unsafe {
        nix::libc::connect(
            descriptor.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            length,
        )
    };
    if result != 0 {
        require(
            nix::errno::Errno::last() == nix::errno::Errno::EINPROGRESS,
            "client-connect",
        )?;
        wait(descriptor.as_raw_fd(), nix::libc::POLLOUT, deadline)?;
        super::budget(deadline)?;
        socket_error(&descriptor)?;
    }
    Ok(UnixStream::from(descriptor))
}
#[allow(unsafe_code)]
fn socket_error(descriptor: &OwnedFd) -> Result<()> {
    let mut error: i32 = 0;
    let mut length = nix::libc::socklen_t::try_from(std::mem::size_of_val(&error))
        .map_err(|_| "client-connect")?;
    // SAFETY: initialized, sized SO_ERROR output on a live socket descriptor.
    let result = unsafe {
        nix::libc::getsockopt(
            descriptor.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_ERROR,
            std::ptr::from_mut(&mut error).cast(),
            &raw mut length,
        )
    };
    require(
        result == 0
            && error == 0
            && usize::try_from(length).ok() == Some(std::mem::size_of_val(&error)),
        "client-connect",
    )
}

#[path = "control_client_actions.rs"]
mod actions;
pub(in crate::launch) fn descriptors(
    admission: &Admission,
    index: usize,
    deadline: Instant,
) -> Result<String> {
    let mut client = opened(admission, index, deadline)?;
    let super::actions::Outcome::Inventory { inventory_sha256 } =
        client.action(super::Operation::Inventory, deadline)?
    else {
        return Err("client-action-outcome");
    };
    client.reconnect(deadline)?;
    let pin = client.observation(&inventory_sha256, deadline)?;
    pin.verify()?;
    Ok(inventory_sha256)
}
pub(in crate::launch) fn release(
    admission: &Admission,
    index: usize,
    deadline: Instant,
) -> Result<String> {
    let mut client = opened(admission, index, deadline)?;
    let path = admission
        .policy()
        .roots
        .evidence
        .join(&client.manifest.case)
        .join("inventory.json");
    let bytes = crate::receipt::protected_read(&path, 64 * 1024, true)?;
    let digest = crate::identity::hash(&bytes);
    let outcome = client.action(
        super::Operation::Release {
            inventory_sha256: digest.clone(),
        },
        deadline,
    )?;
    require(
        matches!(outcome, super::actions::Outcome::Released { .. }),
        "client-action-outcome",
    )?;
    Ok(digest)
}
pub(in crate::launch) fn wait_completion(
    admission: &Admission,
    index: usize,
    deadline: Instant,
) -> Result<()> {
    let mut client = opened(admission, index, deadline)?;
    loop {
        if client.completion(deadline)? == completion_client::Observation::Complete {
            client.reconnect(deadline)?;
            return client.observed(deadline);
        }
        let timeout = super::budget(deadline)?.min(
            i32::try_from(admission.policy().limits.poll_ms).map_err(|_| "client-poll-bound")?,
        );
        super::channel::poll(&mut [], timeout)?;
        client.reconnect(deadline)?;
    }
}
