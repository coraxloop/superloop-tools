//! Host composition of the complete reply capability frame.
use super::journal::{MailError, Result};
use super::steering::{BindingSelection, REPLY_PURPOSES, reply_requirements};
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
    pins_for(home, runs, entry, scope, BindingSelection::Reply)
}

/// Pin the same roles for a selected binding operation, without admitting a lifetime.
///
/// # Errors
/// Refuses overrides, invalid grants, programs or directory custody.
pub fn pins_for(
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    scope: &str,
    selection: BindingSelection,
) -> Result<Vec<HostPin>> {
    selection.check_override()?;
    let operation = selection.operation();
    let host = HostVerifier::current()?.for_operation(operation);
    let (configuration, config) = pin_configuration(&host, home.0, scope, selection)?;
    let row = config
        .registry
        .row(scope, home.0)
        .map_err(|_| selection.refusal("loop"))?;
    let service = config
        .allocations
        .mail_uid()
        .ok_or_else(|| selection.refusal("service"))?;
    let mut required = reply_requirements(row.uid, service);
    for (slot, fd) in [home.1, runs.1].into_iter().enumerate() {
        let stat = nix::sys::stat::fstat(fd)
            .map_err(|error| selection.io(REPLY_PURPOSES[slot], "fstat", error))?;
        let mode = stat.st_mode & 0o7777;
        if mode & 0o7022 != 0 || mode & 0o700 != 0o700 {
            return Err(MailError::Entry(format!(
                "anchor-mode: operation={operation} purpose={} check=directory-mode",
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
        let slot = u32::try_from(slot).map_err(|_| selection.refusal("slot"))?;
        if slot == 3 {
            pins.push(
                configuration
                    .take()
                    .ok_or_else(|| selection.refusal("configuration"))?,
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
    matching_roots(&pins, home.1, runs.1, selection)?;
    Ok(pins)
}

fn pin_configuration(
    host: &HostVerifier,
    home: &Path,
    scope: &str,
    selection: BindingSelection,
) -> Result<(HostPin, anchor::Configuration)> {
    let operation = selection.operation();
    let configuration = host.pin(
        &home.join(".config/loops"),
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
        operation: operation.into(),
        loop_name: scope.into(),
        transport: anchor::Transport::Rights,
        records: vec![bootstrap],
    };
    let config = anchor::Receiver::current()?.configuration(
        &manifest,
        &[configuration
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| selection.io("configuration", "duplicate", error))?],
        anchor::Entry {
            operation,
            loop_name: scope,
            transport: anchor::Transport::Rights,
        },
        home,
        false,
    )?;
    Ok((configuration, config))
}

fn matching_roots(
    pins: &[HostPin],
    home: &OwnedFd,
    runs: &OwnedFd,
    selection: BindingSelection,
) -> Result<()> {
    let operation = selection.operation();
    for (slot, held) in [home, runs].into_iter().enumerate() {
        let stat = nix::sys::stat::fstat(held)
            .map_err(|error| selection.io(REPLY_PURPOSES[slot], "fstat", error))?;
        let record = pins[slot].record();
        if (record.device, record.inode) != (stat.st_dev, stat.st_ino) {
            return Err(MailError::Entry(format!(
                "anchor-identity: operation={operation} purpose={}",
                REPLY_PURPOSES[slot]
            )));
        }
    }
    if (pins[0].record().device, pins[0].record().inode)
        == (pins[1].record().device, pins[1].record().inode)
    {
        return Err(selection.refusal("runs-root"));
    }
    Ok(())
}
