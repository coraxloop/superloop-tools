//! Bounded external descriptor metadata; never open a target descriptor or read its bytes.
use super::{
    Result,
    measure::ObjectIdentity,
    process_pin::{self, ProcessPin},
    require,
};
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fstatat};
use serde::Serialize;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Descriptor {
    pub slot: u32,
    pub kind: u32,
    pub flags: u32,
    pub object: ObjectIdentity,
    pub device: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Inventory {
    pub boot: String,
    pub descriptors: Vec<Descriptor>,
}
impl Inventory {
    pub fn observe(pin: &ProcessPin, expected: [ObjectIdentity; 2], ceiling: u64) -> Result<Self> {
        pin.verify()?;
        require((5..=64).contains(&ceiling), "inventory-ceiling")?;
        let directory = File::from(
            openat(
                pin.directory(),
                "fd",
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "inventory-directory")?,
        );
        // This self path refers only to our retained procfs directory capability.
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| "inventory-directory")?;
        let mut descriptors = Vec::new();
        for entry in entries {
            require((descriptors.len() as u64) < ceiling, "inventory-ceiling")?;
            let name = entry.map_err(|_| "inventory-directory")?.file_name();
            let slot = name
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or("inventory-slot")?;
            let stat = fstatat(&directory, name.as_os_str(), AtFlags::empty())
                .map_err(|_| "inventory-descriptor")?;
            let info = process_pin::read(pin.directory(), &format!("fdinfo/{slot}"), 4096)?;
            let flags = flags(&info)?;
            descriptors.push(Descriptor {
                slot,
                kind: stat.st_mode & SFlag::S_IFMT.bits(),
                flags,
                object: ObjectIdentity {
                    device: stat.st_dev,
                    inode: stat.st_ino,
                },
                device: stat.st_rdev,
            });
        }
        descriptors.sort_by_key(|d| d.slot);
        validate(&descriptors, expected)?;
        pin.verify()?;
        let mut boot = String::new();
        File::open("/proc/sys/kernel/random/boot_id")
            .map_err(|_| "inventory-boot")?
            .take(65)
            .read_to_string(&mut boot)
            .map_err(|_| "inventory-boot")?;
        let boot = boot.trim_end_matches('\n');
        require(
            boot.len() == 36
                && boot.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                }),
            "inventory-boot",
        )?;
        Ok(Self {
            boot: boot.into(),
            descriptors,
        })
    }
}
fn flags(bytes: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(bytes).map_err(|_| "inventory-fdinfo")?;
    let mut values = text.lines().filter_map(|l| l.strip_prefix("flags:"));
    let value = values.next().ok_or("inventory-fdinfo")?.trim();
    require(values.next().is_none(), "inventory-fdinfo")?;
    u32::from_str_radix(value, 8).map_err(|_| "inventory-fdinfo")
}
fn validate(rows: &[Descriptor], expected: [ObjectIdentity; 2]) -> Result<()> {
    require(rows.len() == 5, "inventory-count")?;
    require(expected[0] != expected[1], "inventory-alias")?;
    for (slot, row) in (0..5).zip(rows) {
        require(row.slot == slot, "inventory-slot")?;
        let access = row.flags & nix::libc::O_ACCMODE as u32;
        require(
            row.flags & nix::libc::O_NONBLOCK as u32 == 0,
            "inventory-flags",
        )?;
        if let Some(stream) = super::policy::FIXTURE_STANDARD_STREAMS.get(slot as usize) {
            require(
                row.kind == stream.kind && row.device == stream.device && access == stream.access,
                if slot == 0 {
                    "inventory-stdin"
                } else {
                    "inventory-output"
                },
            )?;
        } else {
            require(
                row.kind == SFlag::S_IFIFO.bits()
                    && access == nix::libc::O_WRONLY as u32
                    && row.object == expected[(slot - 3) as usize],
                "inventory-stream",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
pub(super) mod tests;
