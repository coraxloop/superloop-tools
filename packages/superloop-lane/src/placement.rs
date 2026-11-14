//! Own-path placement facts, descriptor identity and explicit owner commands.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

use execute_command::workspace::GrantSnapshot;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::LaneError;

pub mod commands;
mod reader;
#[cfg(test)]
mod tests;

pub use reader::plan_bytes;
pub(crate) use reader::{journal_bytes, reservation_bytes};

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("door-workspace-context-differs", detail)
}

fn hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Persistent identity supplied by the filesystem for one opened directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootIdentity {
    pub filesystem_uuid: String,
    pub handle_type: i32,
    pub handle: String,
}

impl RootIdentity {
    fn validate(&self) -> Result<(), LaneError> {
        if !hex(&self.filesystem_uuid, 16)
            || !(1..=128).contains(&(self.handle.len() / 2))
            || !hex(&self.handle, self.handle.len() / 2)
        {
            return Err(refusal("placement root identity shape differs"));
        }
        Ok(())
    }
}

/// Immutable own-path facts. No door execution caller is selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub schema: u8,
    pub placement: String,
    #[serde(rename = "loop")]
    pub loop_name: String,
    pub run: String,
    pub node: String,
    /// Full owner-held grant binding against a substituted requester context;
    /// see proto:superlooplane:workspace-placement-reader.
    pub grant_digest: String,
    pub mode: String,
    pub root: String,
    pub root_identity: RootIdentity,
    #[serde(deserialize_with = "required_seed")]
    pub seed: Option<String>,
}

fn required_seed<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(decoder)
}

impl Placement {
    /// Decode an already parsed member; byte readers must check duplicates first.
    /// # Errors
    /// Refuses malformed fields or facts not bound to the owner's grant.
    pub fn decode(value: Value, grant: &GrantSnapshot) -> Result<Self, LaneError> {
        if value
            .as_object()
            .is_none_or(|o| o.len() != 10 || !o.contains_key("seed"))
        {
            return Err(refusal("placement fields differ"));
        }
        let record: Self = serde_json::from_value(value).map_err(|e| refusal(e.to_string()))?;
        if record.schema != 1 || !hex(&record.placement, 16) || record.mode != "own-path" {
            return Err(refusal("placement schema, identifier or mode differs"));
        }
        if record.loop_name != grant.grant.loop_name
            || record.run != grant.grant.run
            || record.node != grant.grant.node
            || record.grant_digest != grant.digest
            || record.root != grant.grant.workspace
            || !std::path::Path::new(&record.root).is_absolute()
        {
            return Err(refusal("placement and workspace grant differ"));
        }
        if record
            .seed
            .as_ref()
            .is_some_and(|s| !crate::valid_run_name(s))
        {
            return Err(refusal("placement seed identifier shape differs"));
        }
        record.root_identity.validate()?;
        Ok(record)
    }

    /// Compare an observed identity, preserving failure to read it as a refusal.
    /// # Errors
    /// Refuses unreadable, invalid or unequal root identities.
    pub fn bind(&self, observed: Result<RootIdentity, LaneError>) -> Result<(), LaneError> {
        self.root_identity.validate()?;
        let actual = observed.map_err(|error| {
            refusal(format!(
                "placement root identity cannot be read: {}",
                error.detail
            ))
        })?;
        actual.validate()?;
        if actual != self.root_identity {
            return Err(refusal("placement root identity differs"));
        }
        Ok(())
    }
}

pub(crate) fn snapshot(
    document: &Value,
    grant: Option<&GrantSnapshot>,
) -> Result<Option<Placement>, LaneError> {
    document
        .get("compute_placement")
        .map(|value| {
            let grant = grant.ok_or_else(|| refusal("placement has no workspace grant"))?;
            Placement::decode(value.clone(), grant)
        })
        .transpose()
}

fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _written = write!(result, "{byte:02x}");
    }
    result
}

// The generic Linux ioctl encoding is shared by these supported targets.
// Refuse other ABIs rather than issuing an architecture-dependent request.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
const FS_IOC_GETFSUUID: libc::c_ulong = 0x8011_1500;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
const FS_IOC_GETFSUUID: libc::c_ulong = 0;

#[repr(C)]
struct KernelHandle {
    length: u32,
    kind: i32,
    bytes: [u8; 128],
}

fn uuid_from_links(device: u64) -> io::Result<String> {
    let directory = std::fs::metadata("/dev/disk/by-uuid")?;
    if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o022 != 0 {
        return Err(io::Error::other("filesystem UUID directory is not trusted"));
    }
    let mut found = None;
    for entry in std::fs::read_dir("/dev/disk/by-uuid")? {
        let entry = entry?;
        let link = std::fs::symlink_metadata(entry.path())?;
        if link.uid() != 0 || !link.file_type().is_symlink() {
            return Err(io::Error::other(
                "filesystem UUID entry is not a trusted link",
            ));
        }
        let metadata = std::fs::metadata(entry.path())?;
        if metadata.file_type().is_block_device() && metadata.rdev() == device {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("UUID is not UTF-8"))?;
            let normalized = name.replace('-', "");
            if !hex(&normalized, 16) || found.replace(normalized).is_some() {
                return Err(io::Error::other("filesystem UUID is invalid or ambiguous"));
            }
        }
    }
    found.ok_or_else(|| io::Error::other("filesystem UUID unavailable"))
}

/// Read a root identity from the caller's held directory, never from its path.
/// # Errors
/// Refuses a non-directory, unsupported handle, unavailable UUID or syscall failure.
pub fn read_identity(root: &File) -> Result<RootIdentity, LaneError> {
    let metadata = root.metadata().map_err(|e| refusal(e.to_string()))?;
    if !metadata.is_dir() {
        return Err(refusal("placement root is not a directory"));
    }
    let mut uuid = [0_u8; 17];
    let mut handle = KernelHandle {
        length: 128,
        kind: 0,
        bytes: [0; 128],
    };
    let mut mount_id = 0_i32;
    if FS_IOC_GETFSUUID == 0 {
        return Err(refusal("filesystem UUID ioctl ABI is unsupported"));
    }
    // SAFETY: root holds the live fd; uuid is writable fsuuid2 storage (length
    // byte plus sixteen bytes). The synchronous ioctl retains no pointer.
    #[allow(unsafe_code)]
    let uuid_code = unsafe { libc::ioctl(root.as_raw_fd(), FS_IOC_GETFSUUID, uuid.as_mut_ptr()) };
    let uuid_result = if uuid_code == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    // SAFETY: root is live, the C string is empty and terminated, KernelHandle
    // has the C layout and a writable 128-byte tail matching its advertised
    // capacity. mount_id is writable i32 storage. No pointer escapes the call.
    #[allow(unsafe_code)]
    let handle_code = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            root.as_raw_fd(),
            c"".as_ptr(),
            &raw mut handle,
            &raw mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    let handle_result = if handle_code == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    handle_result.map_err(|e| refusal(format!("root file handle: {e}")))?;
    let length = usize::try_from(handle.length).map_err(|e| refusal(e.to_string()))?;
    if !(1..=128).contains(&length) {
        return Err(refusal("root file handle length differs"));
    }
    let filesystem_uuid = match uuid_result {
        Ok(()) if uuid[0] == 16 => encode(&uuid[1..]),
        Ok(()) => return Err(refusal("filesystem UUID length differs")),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::ENOSYS)
            ) =>
        {
            uuid_from_links(metadata.dev()).map_err(|e| refusal(format!("filesystem UUID: {e}")))?
        }
        Err(e) => return Err(refusal(format!("filesystem UUID: {e}"))),
    };
    Ok(RootIdentity {
        filesystem_uuid,
        handle_type: handle.kind,
        handle: encode(&handle.bytes[..length]),
    })
}
