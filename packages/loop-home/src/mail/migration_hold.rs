//! Hold the journal writer across a cutover operation and bind rollback to its baseline.
use super::{
    io,
    journal::{MailError, Result},
    migration_tree,
};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    device: u64,
    inode: u64,
    digest: String,
}
/// The service cannot start another journal writer while this guard exists.
/// The deploy hold also keeps launchers, producers and pin owners quiescent.
pub struct DeliveryHold {
    root: File,
    writer: Flock<File>,
    service: u32,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn custody(file: &File, service: u32, directory: bool) -> Result<()> {
    let info = file.metadata()?;
    if info.uid() != service
        || info.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !info.is_dir()
        } else {
            !info.is_file() || info.nlink() != 1
        }
    {
        return Err(invalid("unsafe-storage: migration journal custody"));
    }
    Ok(())
}
impl DeliveryHold {
    /// Hold an already provisioned journal without creating or resetting its state.
    ///
    /// # Errors
    /// Refuses an active service writer, missing history or unsafe custody.
    pub fn acquire(root: File, service: u32) -> Result<Self> {
        custody(&root, service, true)?;
        let writer = io::child(&root, Path::new("writer.lock"), false)?;
        custody(&writer, service, false)?;
        let writer = Flock::lock(writer, FlockArg::LockExclusiveNonblock)
            .map_err(|_| invalid("changed-source: stop the mail service before migration"))?;
        let result = Self {
            root,
            writer,
            service,
        };
        result.current()?;
        Ok(result)
    }
    fn current(&self) -> Result<()> {
        custody(&self.root, self.service, true)?;
        let named = io::child(&self.root, Path::new("writer.lock"), false)?;
        custody(&named, self.service, false)?;
        let held = self.writer.metadata()?;
        let named = named.metadata()?;
        if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            return Err(invalid("changed-source: migration journal lock replaced"));
        }
        Ok(())
    }
    /// Refuse a legacy cutover once the durable journal has accepted any new delivery.
    ///
    /// # Errors
    /// A watermark, compacted history or retained delivery closes the one-time migration window.
    pub fn require_no_delivery(&self) -> Result<()> {
        self.current()?;
        for name in ["state.toml", "checkpoint.toml"] {
            let file = io::child(&self.root, Path::new(name), false)?;
            custody(&file, self.service, false)?;
            let bytes = io::bounded(&file, super::journal::SUMMARY_MAX_BYTES)?;
            let state: toml::Value = toml::from_str(
                std::str::from_utf8(&bytes)
                    .map_err(|_| invalid("invalid-directory: journal state encoding"))?,
            )
            .map_err(|_| invalid("invalid-directory: journal state schema"))?;
            if state.get("version").and_then(toml::Value::as_integer) != Some(1)
                || state.get("greatest_reserved").is_some()
                || state.get("greatest_compacted").is_some()
                || state
                    .get("count")
                    .and_then(toml::Value::as_integer)
                    .is_some_and(|count| count != 0)
            {
                return Err(invalid(
                    "changed-source: new delivery closes legacy migration and rollback; use mail-journal reconciliation",
                ));
            }
        }
        if !io::names(&io::child(&self.root, Path::new("deliveries"), true)?)?.is_empty() {
            return Err(invalid(
                "changed-source: retained deliveries close legacy migration",
            ));
        }
        Ok(())
    }
    /// Capture a baseline only after the normal journal reader validates its state.
    /// The guard fingerprints all journal bytes, including its durable watermark.
    ///
    /// # Errors
    /// Refuses changed or unreadable state rather than claiming a rollback window.
    pub fn baseline(&self) -> Result<Baseline> {
        self.current()?;
        let info = self.root.metadata()?;
        Ok(Baseline {
            device: info.dev(),
            inode: info.ino(),
            digest: migration_tree::fingerprint(&self.root)?,
        })
    }
    /// Forbid legacy restoration after any new journal activity or replacement.
    ///
    /// # Errors
    /// Refuses a changed baseline; recovery then requires the mail journal.
    pub fn require_unchanged(&self, expected: &Baseline) -> Result<()> {
        if self.baseline()? != *expected {
            return Err(invalid(
                "changed-source: journal activity closes legacy rollback; use mail-journal reconciliation",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    /// ´claim:loophome:migration-hold-excludes-delivery-and-rejects-rollback-after-reservation´
    /// ´test:unit:migration-hold-excludes-delivery-and-rejects-rollback-after-reservation´
    #[test]
    fn migration_hold_excludes_delivery_and_rejects_rollback_after_reservation() {
        let root = std::env::temp_dir().join(format!("mail-migration-hold-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let open = || File::open(&root).expect("root descriptor");
        let journal = super::super::journal::Journal::create(open()).expect("journal");
        let uid = nix::unistd::Uid::effective().as_raw();
        assert!(DeliveryHold::acquire(open(), uid).is_err());
        drop(journal);
        let held = DeliveryHold::acquire(open(), uid).expect("delivery hold");
        let before = held.baseline().expect("baseline");
        held.require_no_delivery().expect("no new delivery");
        assert!(super::super::journal::Journal::open(open()).is_err());
        held.require_unchanged(&before).expect("rollback window");
        drop(held);
        let mut journal = super::super::journal::Journal::open(open()).expect("service begins");
        journal
            .reserve(
                super::super::instant::Instant::parse("2026-01-01T00:00:00.000Z")
                    .expect("actual instant"),
            )
            .expect("new submission reserves delivery");
        drop(journal);
        let held = DeliveryHold::acquire(open(), uid).expect("service stopped");
        assert!(held.require_no_delivery().is_err());
        assert!(
            matches!(held.require_unchanged(&before),Err(MailError::Invalid(reason)) if reason.contains("closes legacy rollback"))
        );
        drop(held);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
