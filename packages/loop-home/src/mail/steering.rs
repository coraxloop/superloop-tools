//! Service-authenticated own-loop steering with a durable reservation pin.
use super::{
    Address,
    birth::Identity,
    command,
    directory::Directory,
    instant::Instant,
    io,
    journal::{self, MAX_LETTER_BYTES, MailError, Record, Result},
    publication::Durability,
    worker_provision,
};
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// Resolve one delivery under namespace-root entry, then drop permanently to
/// the service identity before journal verification and pin publication.
///
/// This function belongs in a short-lived trusted launcher child.
///
/// # Errors
/// Refuses a changed worker, non-principal sender, absent/moved/forged inbox
/// entry, incomplete delivery, concurrent compaction or failed durable pin.
pub fn bind(
    home: &Path,
    loop_name: &str,
    identity: &Identity,
    step: &str,
    delivery: &Instant,
) -> Result<(Record, Vec<u8>)> {
    bind_direction(home, loop_name, identity, step, delivery, false, false)
}

/// Bind a selected worker-to-loop reply as data, without granting steering authority.
///
/// # Errors
/// Refuses a changed worker, missing delivery or unverified recipient inode.
pub fn reply(
    home: &Path,
    loop_name: &str,
    identity: &Identity,
    step: &str,
    delivery: &Instant,
) -> Result<(Record, Vec<u8>)> {
    bind_direction(home, loop_name, identity, step, delivery, true, false)
}
/// Verify an existing steering binding without publishing its pin again.
///
/// # Errors
/// Refuses changed delivery evidence or an absent reservation pin.
pub fn verify(
    home: &Path,
    loop_name: &str,
    identity: &Identity,
    step: &str,
    delivery: &Instant,
) -> Result<(Record, Vec<u8>)> {
    bind_direction(home, loop_name, identity, step, delivery, false, true)
}
fn bind_direction(
    home: &Path,
    loop_name: &str,
    identity: &Identity,
    step: &str,
    delivery: &Instant,
    reply: bool,
    verify_only: bool,
) -> Result<(Record, Vec<u8>)> {
    if step.is_empty()
        || step.len() > 64
        || !step
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MailError::Invalid("invalid-name: round step"));
    }
    let _lifetime = worker_provision::hold_active(home, loop_name, identity, verify_only)?;
    let settings = command::settings(home)?;
    command::enter(home, &settings)?;
    let directory = Directory {
        home: home.to_owned(),
        service: settings.uid,
        owner: io::search_directory(home)?.metadata()?.uid(),
        durability: Durability {
            crash_consistent_rename: settings.crash_consistent_rename,
            durable_sync: settings.durable_sync,
        },
    };
    bind_service(
        &directory,
        loop_name,
        identity,
        step,
        delivery,
        reply,
        verify_only,
    )
}
fn bind_service(
    directory: &Directory,
    loop_name: &str,
    identity: &Identity,
    step: &str,
    delivery: &Instant,
    reply: bool,
    verify_only: bool,
) -> Result<(Record, Vec<u8>)> {
    let worker = Address::parse(&format!("{loop_name}+{}", identity.name))
        .map_err(|_| MailError::Invalid("invalid-name: worker address"))?;
    let inventory = directory.inventory()?;
    inventory
        .actors
        .get(&worker)
        .filter(|actor| actor.active && actor.uid == identity.uid)
        .ok_or(MailError::Invalid(
            "invalid-directory: worker endpoint unavailable",
        ))?;
    let principal =
        Address::parse(loop_name).map_err(|_| MailError::Invalid("invalid-name: loop"))?;
    let (sender, recipient) = if reply {
        (&worker, &principal)
    } else {
        (&principal, &worker)
    };
    let actor = inventory
        .actors
        .get(recipient)
        .filter(|actor| actor.active)
        .ok_or(MailError::Invalid(
            "invalid-directory: recipient endpoint unavailable",
        ))?;
    let root = io::absolute(&directory.home.join(".var/loops/.mail-service"), true)?;
    let resolve = if verify_only {
        journal::verify_reservation
    } else {
        journal::bind_reservation
    };
    resolve(
        &root,
        &identity.pin_family(loop_name),
        &format!("{}:{step}", if reply { "reply" } else { "steering" }),
        delivery,
        |record: &Record| {
            verified_payload(
                actor,
                directory.service,
                &sender.to_string(),
                recipient,
                record,
            )
        },
    )
}

pub(super) fn verified_payload(
    actor: &super::directory::Actor,
    service: u32,
    loop_name: &str,
    recipient: &Address,
    record: &Record,
) -> Result<(Record, Vec<u8>)> {
    if record.sender != loop_name || record.recipient != recipient.to_string() {
        return Err(MailError::Invalid(
            "invalid-file: delivery principals differ from the selected worker binding",
        ));
    }
    if actor.endpoint.witness(record)? != journal::Witness::Absent {
        return Err(MailError::Invalid(
            "pending-delivery: publication witness remains",
        ));
    }
    let file = io::child(&actor.inbox, Path::new(&record.inbox_name), false)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != service
        || meta.gid() != actor.group
        || meta.mode() & 0o7777 != 0o640
        || meta.dev() != record.recipient_temporary.identity.device
        || meta.ino() != record.recipient_temporary.identity.inode
    {
        return Err(MailError::Invalid("invalid-file: forged local inbox entry"));
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_LETTER_BYTES + 1).read_to_end(&mut bytes)?;
    let current = io::child(&actor.inbox, Path::new(&record.inbox_name), false)?.metadata()?;
    if current.dev() != meta.dev()
        || current.ino() != meta.ino()
        || bytes.len() as u64 != record.bytes
        || journal::digest(&bytes) != record.digest
    {
        return Err(MailError::Invalid(
            "changed-source: steering inbox entry changed",
        ));
    }
    Ok((record.clone(), bytes))
}
