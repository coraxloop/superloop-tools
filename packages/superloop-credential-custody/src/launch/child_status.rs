//! Observed child status, distinct from a declared unit template.
use super::{Result, process_pin, require};
use serde::Serialize;
use std::fs::File;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ChildStatus {
    pub pid: u32,
    pub birth: u64,
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub groups: Vec<u32>,
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
        let gids = field("Gid:")?
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<Vec<u32>, _>>()
            .map_err(|_| "sealer-status-format")?;
        let gids = gids.try_into().map_err(|_| "sealer-status-format")?;
        let groups = field("Groups:")?
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<Vec<u32>, _>>()
            .map_err(|_| "sealer-status-format")?;
        let pid = number("Pid:")?;
        require(
            pid > 1 && number("Tgid:")? == pid && birth > 0,
            "sealer-status-identity",
        )?;
        Ok(Self {
            pid,
            birth,
            uids,
            gids,
            groups,
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
    pub fn launcher_role(&self, role: super::policy::Role) -> Result<()> {
        use super::policy::{Capability, Role};
        require(role != Role::Fixture, "launch-role-command")?;
        let mask = role
            .properties()
            .capability_bounding_set
            .iter()
            .fold(0_u64, |mask, cap| {
                mask | match cap {
                    Capability::SysPtrace => 1 << 19,
                    Capability::Kill => 1 << 5,
                }
            });
        require(self.uids == [0; 4], "launch-role-identity")?;
        require(
            self.permitted == mask
                && self.effective == mask
                && self.bounding == mask
                && self.inheritable == 0
                && self.ambient == 0,
            "launch-role-capabilities",
        )?;
        require(self.no_new_privileges == 1, "launch-role-privileges")
    }
    pub fn verify_groups(&self, gids: &[u32; 4], groups: &[u32]) -> Result<()> {
        require(&self.gids == gids, "sealer-status-gids")?;
        require(self.groups == groups, "sealer-status-groups")
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
    const TEXT: &str = "Pid:\t123\nTgid:\t123\nUid:\t2000 2000 2000 2000\nGid:\t2000 2000 2000 2000\nGroups:\t2000 2001\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nCapBnd:\tff\nNoNewPrivs:\t1\nSeccomp:\t2\n";
    /// ´test:unit:child-status-compares-all-gids-and-supplementary-groups´
    #[test]
    fn child_status_compares_all_gids_and_supplementary_groups() {
        let good = ChildStatus::parse(TEXT.as_bytes(), 99).unwrap();
        good.verify_groups(&[2000; 4], &[2000, 2001]).unwrap();
        for slot in 0..4 {
            let mut changed = good.clone();
            changed.gids[slot] = 2002;
            assert_eq!(
                changed.verify_groups(&[2000; 4], &[2000, 2001]),
                Err("sealer-status-gids")
            );
        }
        for groups in [vec![], vec![2000], vec![2000, 2001, 2002], vec![2001, 2000]] {
            let mut changed = good.clone();
            changed.groups = groups;
            assert_eq!(
                changed.verify_groups(&[2000; 4], &[2000, 2001]),
                Err("sealer-status-groups")
            );
        }
        let empty = TEXT.replace("Groups:\t2000 2001", "Groups:\t");
        ChildStatus::parse(empty.as_bytes(), 99)
            .unwrap()
            .verify_groups(&[2000; 4], &[])
            .unwrap();
    }
    /// ´test:unit:child-status-requires-complete-observed-fields´
    #[test]
    fn child_status_requires_complete_observed_fields() {
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

#[cfg(test)]
mod role_tests {
    use super::*;
    use crate::launch::policy::Role;
    /// ´test:unit:launcher-role-admission-requires-observed-identity-and-capabilities´
    #[test]
    fn launcher_role_admission_requires_observed_identity_and_capabilities() {
        for (role, mask) in [
            (Role::Completion, 0),
            (Role::CalibrationRun, 0x80020),
            (Role::Descriptors, 0x80000),
            (Role::BarrierRelease, 0),
        ] {
            let good = ChildStatus {
                pid: 123,
                birth: 456,
                uids: [0; 4],
                gids: [0; 4],
                groups: vec![0],
                inheritable: 0,
                permitted: mask,
                effective: mask,
                ambient: 0,
                bounding: mask,
                no_new_privileges: 1,
                seccomp: 0,
            };
            good.launcher_role(role).unwrap();
            for field in [
                "uid",
                "permitted",
                "effective",
                "bounding",
                "inheritable",
                "ambient",
                "nnp",
            ] {
                let mut bad = good.clone();
                let class = match field {
                    "uid" => {
                        bad.uids[1] = 1234;
                        "launch-role-identity"
                    }
                    "nnp" => {
                        bad.no_new_privileges = 0;
                        "launch-role-privileges"
                    }
                    _ => {
                        match field {
                            "permitted" => bad.permitted ^= 1,
                            "effective" => bad.effective ^= 1,
                            "bounding" => bad.bounding ^= 1,
                            "inheritable" => bad.inheritable = 1,
                            "ambient" => bad.ambient = 1,
                            _ => unreachable!(),
                        }
                        "launch-role-capabilities"
                    }
                };
                assert_eq!(bad.launcher_role(role), Err(class), "{role:?}/{field}");
            }
            assert_eq!(
                good.launcher_role(Role::Fixture),
                Err("launch-role-command")
            );
        }
    }
}
