//! Ancestor ownership resolved through the calling user namespace's UID map.

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use nix::sys::statfs::{PROC_SUPER_MAGIC, fstatfs};
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

/// Python map foundation, embedded by readers when their caller migration lands.
pub const PYTHON_ANCESTOR_OWNERS: &str = include_str!("ancestor_owners.py");

fn kernel_text(root: &std::os::fd::OwnedFd, path: &Path) -> Result<String, String> {
    let fd = openat(
        root,
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| format!("ancestor kernel metadata unavailable: {error}"))?;
    if fstatfs(&fd)
        .map_err(|error| error.to_string())?
        .filesystem_type()
        != PROC_SUPER_MAGIC
    {
        return Err("ancestor metadata is not procfs".into());
    }
    let mut text = String::new();
    File::from(fd)
        .take(65_537)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    if text.len() > 65_536 {
        return Err("ancestor kernel metadata exceeds bound".into());
    }
    Ok(text)
}

/// A per-walk snapshot of the kernel UID map and the expected namespace owner.
#[derive(Debug)]
pub struct Owners {
    ranges: Vec<(u64, u64, u64)>,
    owner: u32,
    overflow: u32,
    complete: bool,
}

impl Owners {
    /// Read the calling namespace's map without caching across namespace changes.
    ///
    /// # Errors
    /// Refuses unreadable or malformed kernel metadata and an unmapped owner.
    pub fn current(owner: u32) -> Result<Self, String> {
        let root = open(
            Path::new("/proc"),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("ancestor procfs unavailable: {error}"))?;
        if fstatfs(&root)
            .map_err(|error| error.to_string())?
            .filesystem_type()
            != PROC_SUPER_MAGIC
        {
            return Err("ancestor metadata is not procfs".into());
        }
        let source = kernel_text(&root, Path::new("self/uid_map"))?;
        let overflow = kernel_text(&root, Path::new("sys/kernel/overflowuid"))?
            .trim()
            .parse::<u32>()
            .map_err(|error| format!("ancestor overflowuid invalid: {error}"))?;
        Self::parse(&source, owner, overflow)
    }

    pub(crate) fn parse(source: &str, owner: u32, overflow: u32) -> Result<Self, String> {
        let invalid = || "ancestor uid_map invalid".to_owned();
        let mut ranges: Vec<(u64, u64, u64)> = Vec::new();
        for line in source.lines().filter(|line| !line.trim().is_empty()) {
            if line
                .split_whitespace()
                .any(|word| !word.bytes().all(|byte| byte.is_ascii_digit()))
            {
                return Err(invalid());
            }
            let values = line
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| invalid())?;
            let [inside, outside, count] = values.as_slice() else {
                return Err(invalid());
            };
            let limit = u64::from(u32::MAX);
            if *count == 0
                || *inside >= limit
                || *outside >= limit
                || *count > limit - inside
                || *count > limit - outside
                || ranges.iter().any(|&(old_in, old_out, old_count)| {
                    (*inside < old_in + old_count && old_in < inside + count)
                        || (*outside < old_out + old_count && old_out < outside + count)
                })
            {
                return Err(invalid());
            }
            ranges.push((*inside, *outside, *count));
        }
        if ranges.is_empty() || overflow == u32::MAX {
            return Err(invalid());
        }
        let complete = ranges.iter().map(|range| range.2).sum::<u64>() == u64::from(u32::MAX);
        let owners = Self {
            ranges,
            owner,
            overflow,
            complete,
        };
        owners.parent_uid(owner)?;
        Ok(owners)
    }

    pub(crate) fn parent_uid(&self, uid: u32) -> Result<u64, String> {
        // A partial map cannot distinguish a mapped overflow UID from an
        // unmapped inode reported with that same UID. Refuse that ambiguity.
        if uid != self.overflow || self.complete {
            let uid = u64::from(uid);
            if let Some(&(inside, outside, _)) = self
                .ranges
                .iter()
                .find(|&&(start, _, count)| uid >= start && uid - start < count)
            {
                return Ok(outside + uid - inside);
            }
        }
        Err(format!(
            "unmapped or ambiguous ancestor uid {uid} in /proc/self/uid_map"
        ))
    }

    pub(crate) fn is_initial(&self) -> bool {
        self.ranges.as_slice() == [(0, 0, u64::from(u32::MAX))]
    }

    pub(crate) const fn overflow_uid(&self) -> u32 {
        self.overflow
    }

    pub(crate) fn inside_uid(&self, initial: u32) -> Option<u32> {
        let initial = u64::from(initial);
        self.ranges.iter().find_map(|&(inside, outside, count)| {
            if initial >= outside && initial - outside < count {
                let uid = u32::try_from(inside + initial - outside).ok()?;
                self.parent_uid(uid).ok().map(|_| uid)
            } else {
                None
            }
        })
    }

    /// Require a mapped namespace root, parent root, or expected caller.
    ///
    /// # Errors
    /// Names an unmapped, ambiguous, or unrelated ancestor owner.
    pub fn check(&self, uid: u32) -> Result<(), String> {
        let parent = self.parent_uid(uid)?;
        if uid == 0 || parent == 0 || uid == self.owner {
            Ok(())
        } else {
            Err(format!(
                "ancestor uid {uid} maps to unrelated uid {parent}; expected mapped root or owner uid {}",
                self.owner
            ))
        }
    }

    /// Whether a mapped UID is namespace root or maps to parent root.
    #[must_use]
    pub fn is_root(&self, uid: u32) -> bool {
        self.parent_uid(uid)
            .is_ok_and(|parent| uid == 0 || parent == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::Owners;
    use std::os::unix::fs::MetadataExt as _;

    /// # Panics
    /// Panics if the fixture violates the ownership contract.
    /// ´claim:loophome:ancestor-map-binds-root-and-caller´
    /// ´test:unit:ancestor-map-binds-root-and-caller´
    #[test]
    fn ancestor_map_binds_root_and_caller() {
        let map = Owners::parse("0 1000 1\n42 0 1\n7 2000 1\n8 3000 1\n", 7, 65534).expect("map");
        assert_eq!(map.check(7), Ok(()));
        assert_eq!(map.check(42), Ok(()));
        assert!(map.is_root(42));
        assert!(map.is_root(0));
        assert_eq!(map.check(0), Ok(()));
        assert!(map.check(8).is_err());
        let no_root = Owners::parse("7 2000 1\n", 7, 65534).expect("caller only");
        assert!(
            no_root
                .check(0)
                .expect_err("unmapped root")
                .contains("unmapped")
        );
        assert!(map.check(65534).expect_err("unmapped").contains("unmapped"));
    }

    /// # Panics
    /// Panics if the fixture violates the ownership contract.
    /// ´claim:loophome:ancestor-map-refuses-ambiguous-overflow´
    /// ´test:unit:ancestor-map-refuses-ambiguous-overflow´
    #[test]
    fn ancestor_map_refuses_ambiguous_overflow() {
        let map = Owners::parse("0 1000 1\n65534 0 1\n", 0, 65534).expect("map");
        assert!(
            map.check(65534)
                .expect_err("ambiguous")
                .contains("ambiguous")
        );
        let map = Owners::parse("0 0 4294967295\n", 65534, 65534).expect("full map");
        assert_eq!(map.check(65534), Ok(()));
        assert_eq!(map.check(0), Ok(()));
    }

    /// # Panics
    /// Panics if the fixture violates the ownership contract.
    /// ´claim:loophome:ancestor-map-refuses-invalid-ranges´
    /// ´test:unit:ancestor-map-refuses-invalid-ranges´
    #[test]
    fn ancestor_map_refuses_invalid_ranges() {
        for source in [
            "",
            "0 0",
            "0 x 1",
            "0 0 0",
            "0 0 4294967296",
            "4294967295 0 1",
            "0 4294967295 1",
            "0 0 2\n1 10 1",
            "0 0 2\n10 1 1",
            "1 1 1",
        ] {
            assert!(Owners::parse(source, 0, 65534).is_err(), "{source}");
        }
    }

    /// Exercise this same test outside and inside a real user namespace.
    /// # Panics
    /// Panics if the fixture violates the ownership contract.
    /// ´claim:loophome:ancestor-map-checks-live-kernel-ownership´
    /// ´test:unit:ancestor-map-checks-live-kernel-ownership´
    #[test]
    fn ancestor_map_checks_live_kernel_ownership() {
        let owner = nix::unistd::Uid::effective().as_raw();
        let map = Owners::current(owner).expect("kernel UID map");
        assert_eq!(map.check(owner), Ok(()));
        let root = std::fs::metadata("/").expect("root metadata").uid();
        if root == map.overflow && !map.complete {
            assert!(
                map.check(root)
                    .expect_err("unmapped root")
                    .contains("unmapped")
            );
        } else {
            assert_eq!(map.check(root), Ok(()));
            assert!(map.is_root(root));
        }
    }
    /// # Panics
    /// Panics if the embedded rubric policy disagrees with the namespace contract.
    /// ´claim:loophome:ancestor-map-embedded-rubric-parity´
    /// ´test:unit:ancestor-map-embedded-rubric-parity´
    #[test]
    fn ancestor_map_embedded_rubric_parity() {
        let source = concat!(
            include_str!("ancestor_owners.py"),
            r#"
owners = AncestorOwners('0 1000 1\n42 0 1\n7 2000 1\n8 3000 1\n', 7, 65534)
for uid in (0, 7, 42):
    owners.check(uid)
untrusted = ((owners, 8), (owners, 65534), (AncestorOwners('7 2000 1\n', 7, 65534), 0),
             (AncestorOwners('0 1000 1\n65534 0 1\n', 0, 65534), 65534))
for owners, uid in untrusted:
    try:
        owners.check(uid)
    except ValueError:
        pass
    else:
        raise AssertionError('untrusted owner accepted')
owners = AncestorOwners('0 0 4294967295\n', 65534, 65534)
owners.check(65534)
owners.check(0)
for invalid in ('', '0 0', '0 x 1', '0 0 0', '0 0 4294967296', '4294967295 0 1',
                '0 4294967295 1', '0 0 2\n1 10 1', '0 0 2\n10 1 1', '1 1 1'):
    try:
        AncestorOwners(invalid, 0, 65534)
    except ValueError:
        pass
    else:
        raise AssertionError(invalid)
owners = AncestorOwners.current(os.geteuid())
owners.check(os.geteuid())
root = os.stat('/').st_uid
if root == owners.overflow and not owners.complete:
    try:
        owners.check(root)
    except ValueError:
        pass
    else:
        raise AssertionError('unmapped root accepted')
else:
    owners.check(root)
"#
        );
        let output = std::process::Command::new("python3")
            .args(["-c", source])
            .output()
            .expect("embedded Python policy");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// # Panics
    /// Panics if ordinary files can stand in for kernel metadata.
    /// ´claim:loophome:ancestor-kernel-metadata-requires-procfs´
    /// ´test:unit:ancestor-kernel-metadata-requires-procfs´
    #[test]
    fn ancestor_kernel_metadata_requires_procfs() {
        let path = std::env::temp_dir().join(format!("ancestor-fake-proc-{}", std::process::id()));
        std::fs::create_dir(&path).expect("directory");
        std::fs::write(path.join("uid_map"), "0 0 4294967295").expect("fake map");
        let root: std::os::fd::OwnedFd = std::fs::File::open(&path).expect("root").into();
        let result = super::kernel_text(&root, std::path::Path::new("uid_map"));
        std::fs::remove_dir_all(path).expect("cleanup");
        assert!(result.expect_err("not procfs").contains("not procfs"));
    }
}
