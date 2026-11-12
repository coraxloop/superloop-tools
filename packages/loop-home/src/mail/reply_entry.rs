//! Host composition of the complete reply capability frame.
use super::journal::{MailError, Result};
use super::steering::{
    REPLY_PURPOSES, reply_io, reply_override, reply_refusal, reply_requirements,
};
use crate::anchor::{self, HostPin, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy};
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

/// Pin all eight roles, checking the caller's already-held home and runs identities.
/// No lifetime repair or service identity transition occurs during composition.
/// # Errors
/// Refuses overrides, invalid grants, unavailable programs or changed directory custody.
pub fn pins(
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    scope: &str,
) -> Result<Vec<HostPin>> {
    reply_override()?;
    let host = HostVerifier::current()?.for_operation("mail-binding");
    let configuration = host.pin(
        &home.0.join(".config/loops"),
        "configuration",
        3,
        Policy {
            kind: Kind::Directory,
            owner: Owner::Host,
            mode: ModePolicy::Exact(0o700),
        },
    )?;
    let mut bootstrap = configuration.record();
    bootstrap.slot = 0;
    let manifest = Manifest {
        version: 1,
        operation: "mail-binding".into(),
        loop_name: scope.into(),
        transport: anchor::Transport::Rights,
        records: vec![bootstrap],
    };
    let config = anchor::Receiver::current()?.configuration(
        &manifest,
        &[configuration
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| reply_io("configuration", "duplicate", error))?],
        anchor::Entry {
            operation: "mail-binding",
            loop_name: scope,
            transport: anchor::Transport::Rights,
        },
        home.0,
        false,
    )?;
    let row = config
        .registry
        .row(scope, home.0)
        .map_err(|_| reply_refusal("loop"))?;
    let service = config
        .allocations
        .mail_uid()
        .ok_or_else(|| reply_refusal("service"))?;
    let mut required = reply_requirements(row.uid, service);
    for (slot, fd) in [home.1, runs.1].into_iter().enumerate() {
        let stat = nix::sys::stat::fstat(fd)
            .map_err(|error| reply_io(REPLY_PURPOSES[slot], "fstat", error))?;
        let mode = stat.st_mode & 0o7777;
        if mode & 0o7022 != 0 || mode & 0o700 != 0o700 {
            return Err(MailError::Entry(format!(
                "anchor-mode: operation=mail-binding purpose={} check=directory-mode",
                REPLY_PURPOSES[slot]
            )));
        }
        required[slot].policy.mode = ModePolicy::Exact(mode);
    }
    let paths = [
        home.0.to_owned(),
        runs.0.to_owned(),
        entry.to_owned(),
        home.0.join(".config/loops"),
        row.home.clone(),
        row.home.join("private"),
        "/usr/bin/setpriv".into(),
        home.0.join(".var/loops/.mail-service"),
    ];
    let mut pins = Vec::new();
    let mut configuration = Some(configuration);
    for (slot, (path, requirement)) in paths.iter().zip(required).enumerate() {
        let slot = u32::try_from(slot).map_err(|_| reply_refusal("slot"))?;
        if slot == 3 {
            pins.push(
                configuration
                    .take()
                    .ok_or_else(|| reply_refusal("configuration"))?,
            );
            continue;
        }
        let pin = host
            .pin(path, &requirement.purpose, slot, requirement.policy)
            .or_else(|error| {
                if slot == 2 && error.kind == "anchor-owner" {
                    host.pin(
                        path,
                        &requirement.purpose,
                        slot,
                        Policy {
                            owner: Owner::RootFile,
                            ..requirement.policy
                        },
                    )
                } else {
                    Err(error)
                }
            })?;
        pins.push(pin);
    }
    matching_roots(&pins, home.1, runs.1)?;
    Ok(pins)
}

fn matching_roots(pins: &[HostPin], home: &OwnedFd, runs: &OwnedFd) -> Result<()> {
    for (slot, held) in [home, runs].into_iter().enumerate() {
        let stat = nix::sys::stat::fstat(held)
            .map_err(|error| reply_io(REPLY_PURPOSES[slot], "fstat", error))?;
        let record = pins[slot].record();
        if (record.device, record.inode) != (stat.st_dev, stat.st_ino) {
            return Err(MailError::Entry(format!(
                "anchor-identity: operation=mail-binding purpose={}",
                REPLY_PURPOSES[slot]
            )));
        }
    }
    if (pins[0].record().device, pins[0].record().inode)
        == (pins[1].record().device, pins[1].record().inode)
    {
        return Err(reply_refusal("runs-root"));
    }
    Ok(())
}
