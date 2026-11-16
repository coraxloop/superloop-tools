//! Observed child status, distinct from a declared unit template.
use super::{Result, process_pin, require};
use serde::Serialize;
use std::fs::File;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ChildStatus {
    pub pid: u32,
    pub birth: u64,
    pub uids: [u32; 4],
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub ambient: u64,
    pub bounding: u64,
    pub no_new_privileges: u32,
    pub seccomp: u32,
}
impl ChildStatus {
    pub fn read(directory: &File) -> Result<Self> {
        require(
            nix::sys::statfs::fstatfs(directory)
                .map_err(|_| "sealer-status-procfs")?
                .filesystem_type()
                == nix::sys::statfs::PROC_SUPER_MAGIC,
            "sealer-status-procfs",
        )?;
        let bytes = process_pin::read(directory, "status", 16 * 1024)?;
        let (birth, _) = process_pin::stat(directory)?;
        Self::parse(&bytes, birth)
    }
    fn parse(bytes: &[u8], birth: u64) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| "sealer-status-format")?;
        let field = |key: &str| -> Result<&str> {
            let mut found = text.lines().filter_map(|l| l.strip_prefix(key));
            let value = found.next().ok_or("sealer-status-field")?.trim();
            require(found.next().is_none(), "sealer-status-field")?;
            Ok(value)
        };
        let number =
            |key| -> Result<u32> { field(key)?.parse().map_err(|_| "sealer-status-format") };
        let capability = |key| -> Result<u64> {
            u64::from_str_radix(field(key)?, 16).map_err(|_| "sealer-status-format")
        };
        let uids = field("Uid:")?
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<Vec<u32>, _>>()
            .map_err(|_| "sealer-status-format")?;
        let uids = uids.try_into().map_err(|_| "sealer-status-format")?;
        let pid = number("Pid:")?;
        require(
            pid > 1 && number("Tgid:")? == pid && birth > 0,
            "sealer-status-identity",
        )?;
        Ok(Self {
            pid,
            birth,
            uids,
            inheritable: capability("CapInh:")?,
            permitted: capability("CapPrm:")?,
            effective: capability("CapEff:")?,
            ambient: capability("CapAmb:")?,
            bounding: capability("CapBnd:")?,
            no_new_privileges: number("NoNewPrivs:")?,
            seccomp: number("Seccomp:")?,
        })
    }
    pub const fn observer_role(&self) -> Result<()> {
        const CAP_KILL: u64 = 1 << 5;
        require(
            (self.inheritable | self.permitted | self.effective | self.ambient | self.bounding)
                & CAP_KILL
                == 0,
            "handoff-peer-signalling",
        )
    }
    pub fn verify(&self, pid: u32, owner: u32, bounding: u64) -> Result<()> {
        require(
            self.pid == pid && self.uids == [owner; 4],
            "sealer-status-identity",
        )?;
        require(
            self.inheritable == 0
                && self.permitted == 0
                && self.effective == 0
                && self.ambient == 0,
            "sealer-status-capabilities",
        )?;
        require(self.bounding == bounding, "sealer-status-bounding")?;
        require(self.no_new_privileges == 1, "sealer-status-privileges")?;
        require(self.seccomp == 2, "sealer-status-seccomp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// ´test:unit:observer-role-refuses-signalling-in-every-capability-set´
    #[test]
    fn observer_role_refuses_signalling_in_every_capability_set() {
        let _case = crate::launch::test_support::case_guard();
        let clean = TEXT.replace("CapBnd:\tff", "CapBnd:\t0");
        ChildStatus::parse(clean.as_bytes(), 99)
            .unwrap()
            .observer_role()
            .unwrap();
        for field in ["CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd"] {
            let bytes = clean.replace(&format!("{field}:\t0"), &format!("{field}:\t20"));
            assert_eq!(
                ChildStatus::parse(bytes.as_bytes(), 99)
                    .unwrap()
                    .observer_role(),
                Err("handoff-peer-signalling"),
                "{field}"
            );
        }
    }
    const TEXT: &str = "Pid:\t123\nTgid:\t123\nUid:\t2000 2000 2000 2000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nCapBnd:\tff\nNoNewPrivs:\t1\nSeccomp:\t2\n";
    /// ´test:unit:child-status-requires-complete-observed-fields´
    #[test]
    fn child_status_requires_complete_observed_fields() {
        let _case = crate::launch::test_support::case_guard();
        let status = ChildStatus::parse(TEXT.as_bytes(), 99).unwrap();
        status.verify(123, 2000, 255).unwrap();
        assert_eq!(status.verify(124, 2000, 255), Err("sealer-status-identity"));
        for line in TEXT.lines() {
            assert_eq!(
                ChildStatus::parse(TEXT.replace(&format!("{line}\n"), "").as_bytes(), 99).err(),
                Some("sealer-status-field")
            );
            assert_eq!(
                ChildStatus::parse(format!("{TEXT}{line}\n").as_bytes(), 99).err(),
                Some("sealer-status-field")
            );
        }
        for (key, value, class) in [
            ("Pid", "124", "sealer-status-identity"),
            ("Uid", "2001 2000 2000 2000", "sealer-status-identity"),
            ("CapInh", "1", "sealer-status-capabilities"),
            ("CapPrm", "1", "sealer-status-capabilities"),
            ("CapEff", "1", "sealer-status-capabilities"),
            ("CapAmb", "1", "sealer-status-capabilities"),
            ("CapBnd", "0", "sealer-status-bounding"),
            ("NoNewPrivs", "0", "sealer-status-privileges"),
            ("Seccomp", "0", "sealer-status-seccomp"),
        ] {
            let text = TEXT
                .lines()
                .map(|l| {
                    if l.starts_with(&format!("{key}:")) {
                        format!("{key}:\t{value}")
                    } else {
                        l.into()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let result =
                ChildStatus::parse(text.as_bytes(), 99).and_then(|s| s.verify(123, 2000, 255));
            assert_eq!(result, Err(class), "{key}");
        }
    }
}
