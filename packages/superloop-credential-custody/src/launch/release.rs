//! Single-use release bound to an immutable, retained external inventory.
use super::{File, Keeper, Phase, ProcessPin, Result, Store, require};
use crate::launch::{
    child_status::ChildStatus,
    inventory::Inventory,
    measure::ObjectIdentity,
    store::{Directory, Invocation},
};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::MetadataExt as _;

pub(super) struct Evidence {
    directory: Directory,
    file: File,
    object: ObjectIdentity,
    digest: String,
    invocation: Invocation,
    inventory: Inventory,
    children: [ChildStatus; 2],
}
impl Evidence {
    fn publish(
        store: &Store,
        invocation: Invocation,
        inventory: Inventory,
        children: [ChildStatus; 2],
    ) -> Result<Self> {
        let directory = store.evidence()?;
        let bytes = serde_json::to_vec(&serde_json::json!({"schema":1,"command":"descriptors","outcome":"observed","context":store.inventory_context()?,"invocation":invocation,"inventory":inventory,"sealers":children})).map_err(|_| "inventory-encoding")?;
        require(bytes.len() <= 64 * 1024, "inventory-size")?;
        crate::receipt::publish_held(directory.file(), "inventory.json", &bytes)?;
        let file = Self::open(&directory)?;
        let object = ObjectIdentity::of(&file)?;
        Ok(Self {
            directory,
            file,
            object,
            digest: crate::identity::hash(&bytes),
            invocation,
            inventory,
            children,
        })
    }
    fn open(directory: &Directory) -> Result<File> {
        directory.verify()?;
        openat(
            directory.file(),
            "inventory.json",
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| crate::process::io_failure("inventory-receipt-binding", error))
    }
    fn verify(
        &mut self,
        digest: &str,
        invocation: &Invocation,
        inventory: &Inventory,
        children: &[ChildStatus; 2],
    ) -> Result<()> {
        require(digest == self.digest, "inventory-receipt-digest")?;
        require(invocation == &self.invocation, "inventory-invocation")?;
        require(inventory == &self.inventory, "inventory-changed")?;
        require(children == &self.children, "inventory-sealers-changed")?;
        let current = Self::open(&self.directory)?;
        let m = current
            .metadata()
            .map_err(|error| crate::process::io_failure("inventory-receipt-binding", error))?;
        require(
            ObjectIdentity::of(&current)? == self.object
                && ObjectIdentity::of(&self.file)? == self.object
                && m.is_file()
                && m.uid() == nix::unistd::geteuid().as_raw()
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o400
                && m.len() <= 64 * 1024,
            "inventory-receipt-binding",
        )?;
        self.file.rewind().map_err(|_| "inventory-receipt-read")?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "inventory-receipt-read")?;
        require(
            crate::identity::hash(&bytes) == self.digest,
            "inventory-receipt-digest",
        )
    }
}
impl Keeper<'_> {
    fn observations(&self) -> Result<(Invocation, Inventory, [ChildStatus; 2])> {
        for artifact in self.admission.artifacts() {
            artifact.unchanged()?;
        }
        let pin = self.process.as_ref().ok_or("keeper-not-captured")?;
        let inventory = Inventory::observe(
            pin,
            self.pipes.identities(),
            self.admission.policy().limits.observed_fds,
        )?;
        let children = self.session.statuses()?;
        pin.verify()?;
        Ok((pin.invocation().clone(), inventory, children))
    }
    pub fn inventory(&mut self) -> Result<String> {
        require(
            !self.terminal && self.session.store().phase() == Phase::Captured,
            "inventory-order",
        )?;
        let result = (|| {
            self.verify_capture()?;
            let (invocation, inventory, children) = self.observations()?;
            let evidence =
                Evidence::publish(self.session.store(), invocation, inventory, children)?;
            let digest = evidence.digest.clone();
            self.inventory = Some(evidence);
            self.session.store().inventory_complete(digest.clone())?;
            Ok(digest)
        })();
        self.release_result(result)
    }
    pub fn serve_pidfd(&mut self, deadline: std::time::Instant) -> Result<()> {
        require(
            !self.terminal && self.session.store().phase() == Phase::InventoryComplete,
            "handoff-phase",
        )?;
        let result = (|| {
            let digest = self.validated_inventory()?;
            self.control
                .as_ref()
                .ok_or("keeper-not-captured")?
                .serve_pidfd(
                    Phase::InventoryComplete,
                    deadline,
                    self.process.as_ref().ok_or("keeper-not-captured")?,
                    &digest,
                )
        })();
        self.release_result(result)
    }
    pub(super) fn validated_inventory(&mut self) -> Result<String> {
        require(
            !self.terminal && self.session.store().phase() == Phase::InventoryComplete,
            "handoff-phase",
        )?;
        self.verify_capture()?;
        let (invocation, inventory, children) = self.observations()?;
        let evidence = self.inventory.as_mut().ok_or("inventory-missing")?;
        let digest = evidence.digest.clone();
        evidence.verify(&digest, &invocation, &inventory, &children)?;
        Ok(digest)
    }
    pub fn release(&mut self, digest: &str) -> Result<()> {
        self.release_with(digest, ProcessPin::resume)
    }
    fn release_with(
        &mut self,
        digest: &str,
        signal: impl FnOnce(&mut ProcessPin) -> Result<()>,
    ) -> Result<()> {
        self.release_at(digest, signal, self.manager.deadline())
    }
    fn release_at(
        &mut self,
        digest: &str,
        signal: impl FnOnce(&mut ProcessPin) -> Result<()>,
        deadline: std::time::Instant,
    ) -> Result<()> {
        require(
            !self.terminal && self.session.store().phase() == Phase::InventoryComplete,
            "release-order",
        )?;
        let result = (|| {
            self.verify_capture()?;
            let (invocation, inventory, children) = self.observations()?;
            self.inventory.as_mut().ok_or("inventory-missing")?.verify(
                digest,
                &invocation,
                &inventory,
                &children,
            )?;
            self.session.store().advance(Phase::ReleaseIntent)?;
            require(std::time::Instant::now() < deadline, "release-deadline")?;
            signal(self.process.as_mut().ok_or("keeper-not-captured")?)?;
            self.session.store().advance(Phase::Released)
        })();
        self.release_result(result)
    }
    pub(super) fn release_result<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Err(class) = result {
            if !self.terminal {
                let _latched = self.session.store().uncertain(class);
                let _cancelled = self.fail(class);
            }
            return Err(class);
        }
        result
    }
}
#[cfg(test)]
#[path = "release_tests.rs"]
pub(super) mod tests;
