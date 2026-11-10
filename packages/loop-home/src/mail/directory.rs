//! The host registry supplies loops; only the loop-owned mail file supplies workers.
use super::journal::{MailError, Result, digest};
use super::publication::{Durability, Endpoint};
use super::{
    Address, acl,
    configuration::{Configuration, WorkerState},
    io,
};
use crate::{LoopRecord, Registry, allocations::Allocations};
use nix::fcntl::{Flock, FlockArg};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Implementation bound on loop mail configuration; the specification declares no maximum.
pub(super) const MAX_CONFIGURATION_BYTES: u64 = 1_048_576;

fn directory_bound(error: MailError, reason: &'static str) -> MailError {
    match error {
        MailError::Invalid(found) if found.starts_with("oversize:") => MailError::Invalid(reason),
        error => error,
    }
}

pub(super) struct Snapshot {
    pub config: Configuration,
    pub digest: String,
    _lock: Flock<File>,
    path: PathBuf,
    held: Option<Arc<crate::anchor::Anchor>>,
    home: PathBuf,
    identity: (u64, u64),
    service: u32,
    owner: u32,
}
impl Snapshot {
    fn open(row: &LoopRecord, service: u32) -> Result<Self> {
        Self::open_with(row, service, None)
    }
    pub(super) fn open_with(
        row: &LoopRecord,
        service: u32,
        held: Option<Arc<crate::anchor::Anchor>>,
    ) -> Result<Self> {
        let mut path = row.home.join("private");
        for component in ["", ".config", "mail"] {
            path = path.join(component);
            let directory = snapshot_file(&path, &row.home, held.as_deref(), true)?;
            if directory.metadata()?.uid() != row.uid {
                return Err(MailError::Invalid(
                    "unsafe-storage: mail configuration ancestor owner",
                ));
            }
            acl::verify(&directory, service, true)?;
        }
        path = path.join("loop.toml");
        let file = snapshot_file(&path, &row.home, held.as_deref(), false)?;
        if file.metadata()?.uid() != row.uid {
            return Err(MailError::Invalid(
                "unsafe-storage: mail configuration owner",
            ));
        }
        acl::verify(&file, service, false)?;
        let lock = Flock::lock(file, FlockArg::LockSharedNonblock).map_err(|(_, error)| {
            // Refuse only this candidate; a loop writer cannot stall the service.
            if error == nix::errno::Errno::EWOULDBLOCK {
                MailError::Invalid("changed-source: configuration update in progress")
            } else {
                MailError::from(error)
            }
        })?;
        let bytes = io::bounded(&lock, MAX_CONFIGURATION_BYTES).map_err(|error| {
            directory_bound(
                error,
                "invalid-directory: mail configuration exceeds its bound",
            )
        })?;
        let info = lock.metadata()?;
        Ok(Self {
            config: Configuration::parse(&bytes)?,
            digest: digest(&bytes),
            _lock: lock,
            path,
            held,
            home: row.home.clone(),
            identity: (info.dev(), info.ino()),
            service,
            owner: row.uid,
        })
    }
    pub(super) fn current(&self) -> Result<()> {
        let file = snapshot_file(&self.path, &self.home, self.held.as_deref(), false)?;
        let info = file.metadata()?;
        acl::verify(&file, self.service, false)?;
        if (info.dev(), info.ino()) != self.identity
            || info.uid() != self.owner
            || digest(
                &io::bounded(&file, MAX_CONFIGURATION_BYTES).map_err(|error| {
                    directory_bound(
                        error,
                        "invalid-directory: mail configuration exceeds its bound",
                    )
                })?,
            ) != self.digest
        {
            return Err(MailError::Invalid(
                "changed-source: configuration replaced before acceptance",
            ));
        }
        Ok(())
    }
}
fn held_file(anchor: &crate::anchor::Anchor, path: &Path, search: bool) -> Result<File> {
    let (_, descriptor) = anchor.relay()?;
    let root = File::from(descriptor);
    if search {
        io::search_child(&root, path)
    } else {
        io::child(&root, path, true)
    }
}
fn snapshot_file(
    path: &Path,
    home: &Path,
    anchor: Option<&crate::anchor::Anchor>,
    search: bool,
) -> Result<File> {
    if let Some(anchor) = anchor {
        let relative = path
            .strip_prefix(home.join("private"))
            .map_err(|_| MailError::Invalid("anchor-escape: private snapshot"))?;
        let relative = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        let (_, descriptor) = anchor.relay()?;
        let root = File::from(descriptor);
        if search {
            io::search_child(&root, relative)
        } else {
            io::child(&root, relative, false)
        }
    } else if search {
        io::search_directory(path)
    } else {
        io::absolute(path, false)
    }
}
pub(super) struct LoopCustody {
    pub row: LoopRecord,
    pub storage: Arc<crate::anchor::Anchor>,
    pub private: Arc<crate::anchor::Anchor>,
}
impl LoopCustody {
    fn open(&self, path: &Path, search: bool) -> Result<File> {
        let relative = path
            .strip_prefix(&self.row.home)
            .map_err(|_| MailError::Invalid("anchor-escape: loop inventory"))?;
        held_file(
            &self.storage,
            if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative
            },
            search,
        )
    }
}
fn storage_file(path: &Path, custody: Option<&LoopCustody>, search: bool) -> Result<File> {
    custody.map_or_else(
        || {
            if search {
                io::search_directory(path)
            } else {
                io::absolute(path, true)
            }
        },
        |custody| custody.open(path, search),
    )
}

pub(super) struct Actor {
    pub endpoint: Endpoint,
    pub outbox: File,
    pub staging: File,
    pub inbox: File,
    pub uid: u32,
    pub group: u32,
    pub active: bool,
}
pub(super) struct Directory {
    pub configuration: Option<Arc<crate::anchor::Anchor>>,
    pub home: PathBuf,
    pub service: u32,
    pub owner: u32,
    pub durability: Durability,
}
pub(super) struct Inventory {
    /// Loop names from this inventory's fresh trusted registry read.
    pub loops: BTreeSet<String>,
    pub actors: BTreeMap<Address, Actor>,
    /// Endpoints excluded from this scan, each failing closed for itself only.
    pub failures: Vec<String>,
    /// A fresh trusted directory, independently of endpoint availability.
    pub retired: BTreeSet<Address>,
}
pub(super) struct Decision {
    configuration: Option<Arc<crate::anchor::Anchor>>,
    pub registry_digest: String,
    pub configs: Vec<Snapshot>,
    registry_path: PathBuf,
    registry_identity: (u64, u64),
}
impl Decision {
    pub fn current(&self) -> Result<()> {
        let file = configuration_file(&self.registry_path, self.configuration.as_deref())?;
        let info = file.metadata()?;
        if (info.dev(), info.ino()) != self.registry_identity
            || info.mode() & 0o022 != 0
            || digest(&io::bounded(&file, 65_536).map_err(|error| {
                directory_bound(error, "invalid-directory: loop registry exceeds its bound")
            })?) != self.registry_digest
        {
            return Err(MailError::Invalid(
                "changed-source: registry replaced before acceptance",
            ));
        }
        for config in &self.configs {
            config.current()?;
        }
        Ok(())
    }
    pub fn digests(&self) -> Vec<String> {
        self.configs
            .iter()
            .map(|config| config.digest.clone())
            .collect()
    }
}
fn configuration_file(path: &Path, anchor: Option<&crate::anchor::Anchor>) -> Result<File> {
    if let Some(anchor) = anchor {
        let name = path
            .file_name()
            .ok_or(MailError::Invalid("anchor-escape: configuration file name"))?;
        super::entry_anchors::configuration_file(anchor, Path::new(name))
    } else {
        io::absolute(path, false)
    }
}

impl Directory {
    fn registry(&self) -> Result<(Registry, Vec<u8>, File)> {
        let path = self.home.join(".config/loops/registry.toml");
        let file = configuration_file(&path, self.configuration.as_deref())?;
        let info = file.metadata()?;
        if info.uid() != self.owner || info.mode() & 0o022 != 0 {
            return Err(MailError::Invalid("unsafe-storage: registry custody"));
        }
        let bytes = io::bounded(&file, 65_536).map_err(|error| {
            directory_bound(error, "invalid-directory: loop registry exceeds its bound")
        })?;
        let mut reader = configuration_file(&path, self.configuration.as_deref())?;
        let registry = crate::registry::load_registry_from_file(&mut reader)
            .map_err(|_| MailError::Invalid("invalid-directory: global registry"))?;
        if reader.metadata()?.ino() != info.ino() || reader.metadata()?.dev() != info.dev() {
            return Err(MailError::Invalid("changed-source: registry replacement"));
        }
        Ok((registry, bytes, file))
    }
    pub fn decision(&self, sender: &Address, recipient: &Address) -> Result<Decision> {
        let (registry, bytes, file) = self.registry()?;
        let mut configs = Vec::new();
        for address in [sender, recipient] {
            let row = registry
                .row(address.loop_name(), &self.home)
                .map_err(|_| MailError::Invalid("unknown-recipient: loop is not registered"))?;
            if let Some(worker) = address.worker() {
                let snapshot = Snapshot::open(&row, self.service).map_err(|error| match error {
                    MailError::Io(_) => MailError::Invalid(
                        "invalid-directory: mail configuration is absent or unreadable",
                    ),
                    error => error,
                })?;
                snapshot.config.active(worker)?;
                if address == sender {
                    snapshot.config.authorize(sender, recipient)?;
                }
                configs.push(snapshot);
            }
        }
        let info = file.metadata()?;
        Ok(Decision {
            configuration: self.configuration.clone(),
            registry_digest: digest(&bytes),
            configs,
            registry_path: self.home.join(".config/loops/registry.toml"),
            registry_identity: (info.dev(), info.ino()),
        })
    }
    fn allocations(&self) -> Result<Allocations> {
        if let Some(anchor) = &self.configuration {
            let allocations = anchor.read_configuration(&self.home, false)?.allocations;
            if allocations.mail_uid() != Some(self.service) {
                return Err(MailError::Invalid(
                    "unsafe-storage: service identity reservation mismatch",
                ));
            }
            return Ok(allocations);
        }
        let allocation_file =
            io::absolute(&self.home.join(".config/loops/allocations.toml"), false)?;
        if allocation_file.metadata()?.uid() != self.owner
            || allocation_file.metadata()?.mode() & 0o022 != 0
        {
            return Err(MailError::Invalid("unsafe-storage: allocation owner"));
        }
        let allocation_bytes = io::bounded(&allocation_file, 65_536).map_err(|error| {
            directory_bound(
                error,
                "invalid-directory: allocations ledger exceeds its bound",
            )
        })?;
        let allocations = Allocations::parse(
            std::str::from_utf8(&allocation_bytes)
                .map_err(|_| MailError::Invalid("invalid-directory: allocation encoding"))?,
        )
        .map_err(|_| MailError::Invalid("invalid-directory: allocations"))?;
        if allocations.mail_uid() != Some(self.service) {
            return Err(MailError::Invalid(
                "unsafe-storage: service identity reservation mismatch",
            ));
        }
        Ok(allocations)
    }
    fn verify_credentials(&self, rows: &[LoopRecord], allocations: &Allocations) -> Result<()> {
        let private = rows
            .iter()
            .map(|row| row.uid)
            .chain(allocations.iter().flat_map(|(_, block)| block.uids()))
            .collect::<BTreeSet<_>>();
        if allocations
            .mail_group_ids()
            .any(|group| private.contains(&group))
            || private.contains(&self.service)
        {
            return Err(MailError::Invalid(
                "unsafe-storage: mail credential collides with actor identity",
            ));
        }
        if nix::unistd::getgroups()?
            .iter()
            .any(|group| private.contains(&group.as_raw()))
        {
            return Err(MailError::Invalid(
                "unsafe-storage: service holds an actor private credential",
            ));
        }
        Ok(())
    }
    pub fn inventory(&self) -> Result<Inventory> {
        let _span = tracing::debug_span!("mail.inventory", home = %self.home.display()).entered();
        let (registry, _, _) = self.registry()?;
        let allocations = self.allocations()?;
        self.inventory_with(&registry, &allocations, None)
    }
    pub(super) fn inventory_beneath(
        &self,
        configuration: &crate::anchor::Configuration,
        custody: &LoopCustody,
    ) -> Result<Inventory> {
        custody.storage.revalidate()?;
        custody.private.revalidate()?;
        self.inventory_with(
            &configuration.registry,
            &configuration.allocations,
            Some(custody),
        )
    }
    fn inventory_with(
        &self,
        registry: &Registry,
        allocations: &Allocations,
        custody: Option<&LoopCustody>,
    ) -> Result<Inventory> {
        let mut rows = registry.rows(&self.home);
        self.verify_credentials(&rows, allocations)?;
        if let Some(custody) = custody {
            rows.retain(|row| row.name == custody.row.name);
        }
        let loops: BTreeSet<_> = rows.iter().map(|row| row.name.clone()).collect();
        let mut actors = BTreeMap::new();
        let mut identities = BTreeSet::from([self.service, self.owner]);
        let mut failures = Vec::new();
        let mut retired = BTreeSet::new();
        for row in rows {
            let _span =
                tracing::debug_span!("mail.inventory.loop", loop_name = %row.name).entered();
            let address = Address::parse(&row.name)
                .map_err(|_| MailError::Invalid("invalid-name: registered loop"))?;
            let label = address.to_string();
            let added = allocations
                .mail_group(&row.name, None)
                .map_err(|_| {
                    MailError::Invalid("unsafe-storage: loop mailbox group is not reserved")
                })
                .and_then(|group| {
                    self.add_actor(
                        &mut actors,
                        &mut identities,
                        address,
                        (row.uid, group),
                        true,
                        custody,
                    )
                });
            observe_admission(&added, &row.name, &label, "loop");
            if let Err(error) = added {
                failures.push(format!("{label}: {error}"));
            }
            let config =
                Snapshot::open_with(&row, self.service, custody.map(|c| Arc::clone(&c.private)));
            if let Ok(snapshot) = &config {
                collect_retired(&row.name, snapshot, &mut retired)?;
            }
            let workers = match storage_file(&row.home.join("workers"), custody, false) {
                Ok(workers) => workers,
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    tracing::trace!(loop_name = %row.name, "no worker directory");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(loop_name = %row.name, reason = %error, "workers skipped");
                    failures.push(format!("{}: {error}", row.name));
                    continue;
                }
            };
            let names = match io::names(&workers) {
                Ok(names) => names,
                Err(error) => {
                    tracing::warn!(loop_name = %row.name, reason = %error, "workers skipped");
                    failures.push(format!("{}: {error}", row.name));
                    continue;
                }
            };
            for name in names {
                let label = format!("{}+{}", row.name, name.to_string_lossy());
                let _span =
                    tracing::debug_span!("mail.inventory.worker", worker = %label).entered();
                let added = (|| -> Result<()> {
                    let name = name
                        .to_str()
                        .ok_or(MailError::Invalid("unsafe-storage: worker folder encoding"))?;
                    let address = Address::parse(&format!("{}+{name}", row.name))
                        .map_err(|_| MailError::Invalid("unsafe-storage: worker folder name"))?;
                    let active = !retired.contains(&address);
                    let (uid, group) =
                        self.worker_identity(allocations, &row, &address, active, custody)?;
                    self.add_actor(
                        &mut actors,
                        &mut identities,
                        address,
                        (uid, group),
                        active,
                        custody,
                    )
                })();
                observe_admission(&added, &row.name, &label, "worker");
                if let Err(error) = added {
                    failures.push(format!("{label}: {error}"));
                }
            }
        }
        inventory_trace(loops.len(), actors.len(), failures.len(), retired.len());
        Ok(Inventory {
            loops,
            actors,
            failures,
            retired,
        })
    }
    fn worker_identity(
        &self,
        allocations: &Allocations,
        row: &LoopRecord,
        address: &Address,
        active: bool,
        custody: Option<&LoopCustody>,
    ) -> Result<(u32, u32)> {
        let outbox = storage_file(
            &self
                .home
                .join(".var/loops")
                .join(address.relative_mailbox())
                .join("outbox"),
            custody,
            false,
        )?;
        let uid = outbox.metadata()?.uid();
        let group = if active {
            if !allocations
                .get(&row.name)
                .is_some_and(|block| block.contains(uid))
            {
                return Err(MailError::Invalid(
                    "unsafe-storage: worker identity outside allocation",
                ));
            }
            allocations.mail_group(&row.name, Some(uid)).map_err(|_| {
                MailError::Invalid("unsafe-storage: worker mailbox group is not reserved")
            })?
        } else {
            if uid != self.service {
                return Err(MailError::Invalid("unsafe-storage: retired outbox custody"));
            }
            let inbox = storage_file(
                &self
                    .home
                    .join(".var/loops")
                    .join(address.relative_mailbox())
                    .join("inbox"),
                custody,
                false,
            )?;
            let group = inbox.metadata()?.gid();
            if !allocations.get(&row.name).is_some_and(|block| {
                block.uids().any(|worker| {
                    allocations
                        .mail_group(&row.name, Some(worker))
                        .is_ok_and(|reserved| reserved == group)
                })
            }) {
                return Err(MailError::Invalid(
                    "unsafe-storage: retired mailbox group is not reserved",
                ));
            }
            group
        };
        Ok((uid, group))
    }
    fn add_actor(
        &self,
        actors: &mut BTreeMap<Address, Actor>,
        identities: &mut BTreeSet<u32>,
        address: Address,
        identity: (u32, u32),
        active: bool,
        custody: Option<&LoopCustody>,
    ) -> Result<()> {
        let (uid, group) = identity;
        if active && !identities.insert(uid) {
            return Err(MailError::Invalid(
                "unsafe-storage: colliding actor identities",
            ));
        }
        let root = self.home.join(".var/loops");
        let path = root.join(address.relative_mailbox());
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            let info = storage_file(parent, custody, true)?.metadata()?;
            if ![self.owner, self.service].contains(&info.uid()) || info.mode() & 0o022 != 0 {
                return Err(MailError::Invalid(
                    "unsafe-storage: actor-replaceable mailbox ancestor",
                ));
            }
            if parent == custody.map_or(root.as_path(), |c| c.row.home.as_path()) {
                break;
            }
            ancestor = parent.parent();
        }
        let mailbox = storage_file(&path, custody, false)?;
        let mut names = io::names(&mailbox)?;
        names.sort();
        if names != ["draft", "inbox", "outbox", "read", "sent"].map(std::ffi::OsString::from) {
            return Err(MailError::Invalid(
                "unsafe-storage: incomplete mailbox folder",
            ));
        }
        for name in ["draft", "read"] {
            let folder = storage_file(&path.join(name), custody, true)?;
            let info = folder.metadata()?;
            if info.uid() != uid || info.gid() != uid || info.mode() & 0o777 != 0o700 {
                return Err(MailError::Invalid(
                    "unsafe-storage: actor private mail directory",
                ));
            }
            acl::transport(&folder)?;
        }
        let outbox = storage_file(&path.join("outbox"), custody, false)?;
        let info = outbox.metadata()?;
        if info.uid() != uid || info.gid() != uid || info.mode() & 0o007 != 0 {
            return Err(MailError::Invalid("unsafe-storage: actor outbox custody"));
        }
        if active {
            acl::outbox(&outbox, self.service)?;
        } else {
            if info.mode() & 0o7777 != 0o700 {
                return Err(MailError::Invalid("unsafe-storage: retired outbox mode"));
            }
            acl::transport(&outbox)?;
        }
        for directory in [&path, &path.join("inbox"), &path.join("sent")] {
            acl::transport(&storage_file(directory, custody, false)?)?;
        }
        let endpoint = if let Some(custody) = custody {
            Endpoint::open_held(
                &custody.storage,
                &custody.row,
                address.clone(),
                group,
                self.durability,
                !active,
            )?
        } else if active {
            Endpoint::open(&root, address.clone(), group, self.durability)?
        } else {
            Endpoint::open_retired(&root, address.clone(), group, self.durability)?
        };
        let staging = storage_file(
            &path
                .parent()
                .ok_or(MailError::Invalid("endpoint parent"))?
                .join(".mail-staging"),
            custody,
            false,
        )?;
        let inbox = storage_file(&path.join("inbox"), custody, false)?;
        actors.insert(
            address,
            Actor {
                endpoint,
                outbox,
                staging,
                inbox,
                uid,
                group,
                active,
            },
        );
        Ok(())
    }
}

fn collect_retired(name: &str, snapshot: &Snapshot, retired: &mut BTreeSet<Address>) -> Result<()> {
    for worker in &snapshot.config.workers {
        if worker.state == WorkerState::Retired {
            retired.insert(
                Address::parse(&format!("{name}+{}", worker.name))
                    .map_err(|_| MailError::Invalid("invalid-directory: retired worker address"))?,
            );
        }
    }
    Ok(())
}

fn inventory_trace(loops: usize, actors: usize, skipped: usize, retired: usize) {
    tracing::debug!(loops, actors, skipped, retired, "inventory refreshed");
}

fn observe_admission(result: &Result<()>, loop_name: &str, address: &str, kind: &str) {
    if let Err(error) = result {
        tracing::warn!(loop_name, address, reason = %error, "{kind} skipped");
    } else {
        tracing::debug!(loop_name, address, "{kind} admitted");
    }
}

#[cfg(test)]
#[path = "configuration_tests.rs"]
mod tests;
