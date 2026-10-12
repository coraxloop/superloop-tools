//! The private, whole-file worker UID allocation ledger.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};

use crate::LoopError;
use crate::registry::{WorkerBlock, validate_name};

/// The maximum number of bytes in the allocation ledger.
pub const MAX_ALLOCATIONS: u64 = 65_536;

/// Derive the machine-managed allocation file from the session user's home.
#[must_use]
pub fn allocations_path(home: &Path) -> PathBuf {
    home.join(".config/loops/allocations.toml")
}

/// A fully validated allocation ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allocations {
    blocks: BTreeMap<String, WorkerBlock>,
    registry_uids: BTreeMap<String, u32>,
    letters_gid: Option<u32>,
}

impl Allocations {
    /// Parse and validate every loop table before any allocation is selected.
    ///
    /// # Errors
    ///
    /// Refuses malformed TOML, unknown keys, invalid ranges, and overlapping ranges.
    pub fn parse(source: &str) -> Result<Self, LoopError> {
        if source.is_empty() {
            return Ok(Self::default());
        }
        let root: toml::Table =
            toml::from_str(source).map_err(|_| LoopError::refusal("malformed allocations.toml"))?;
        let mut blocks = BTreeMap::new();
        let mut letters_gid = None;
        for (name, value) in root {
            if name == "letters_gid" {
                letters_gid = Some(
                    value
                        .as_integer()
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|n| (1000..=65_535).contains(n) && *n != 65_534)
                        .ok_or_else(|| {
                            LoopError::refusal("malformed letters_gid in allocations.toml")
                        })?,
                );
                continue;
            }
            validate_name(&name)?;
            let table = value.as_table().ok_or_else(|| {
                LoopError::refusal(format!("malformed allocation for loop: {name}"))
            })?;
            if let Some(key) = table.keys().find(|key| key.as_str() != "uids") {
                return Err(LoopError::refusal(format!(
                    "unknown allocation key for loop {name}: {key}"
                )));
            }
            let uids = table
                .get("uids")
                .and_then(toml::Value::as_table)
                .ok_or_else(|| {
                    LoopError::refusal(format!("missing or malformed uids for loop: {name}"))
                })?;
            if let Some(key) = uids
                .keys()
                .find(|key| !["base", "count"].contains(&key.as_str()))
            {
                return Err(LoopError::refusal(format!(
                    "unknown uids key for loop {name}: {key}"
                )));
            }
            let number = |key| {
                uids.get(key)
                    .and_then(toml::Value::as_integer)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| LoopError::refusal(format!("malformed uids for loop: {name}")))
            };
            let base = number("base")?;
            let count = number("count")?;
            if count == 0 || base < 1000 || u64::from(base) + u64::from(count) - 1 > 65_535 {
                return Err(LoopError::refusal(format!(
                    "uids out of range for loop: {name}"
                )));
            }
            let block = WorkerBlock { base, count };
            if let Some((other, _)) = blocks.iter().find(|(_, other)| block.overlaps(**other)) {
                return Err(LoopError::refusal(format!(
                    "worker uids overlap for loops {other} and {name}"
                )));
            }
            blocks.insert(name, block);
        }
        if letters_gid.is_some_and(|gid| blocks.values().any(|block| block.contains(gid))) {
            return Err(LoopError::refusal(
                "letters group conflicts with a worker group",
            ));
        }
        Ok(Self {
            blocks,
            registry_uids: BTreeMap::new(),
            letters_gid,
        })
    }

    /// Read a private, regular, bounded ledger through pinned path components.
    ///
    /// # Errors
    ///
    /// Refuses an absent or unsafe file, and any invalid table in the ledger.
    pub fn read(path: &Path) -> Result<Self, LoopError> {
        Self::read_with_source(path).map(|(allocations, _source)| allocations)
    }

    /// Read the ledger from an already pinned owner-private configuration root.
    ///
    /// # Errors
    ///
    /// Refuses a different parent, unsafe file, or invalid allocation table.
    pub fn read_beneath(
        path: &Path,
        configuration_root: &Path,
        pinned_root: &OwnedFd,
    ) -> Result<Self, LoopError> {
        if !path.is_absolute() || path.parent() != Some(configuration_root) {
            return Err(LoopError::refusal(format!(
                "allocations path is outside the pinned configuration root: {}",
                path.display()
            )));
        }
        let owner = nix::unistd::Uid::effective().as_raw();
        let stat = fstat(pinned_root).map_err(|error| {
            LoopError::refusal(format!("could not inspect allocations directory: {error}"))
        })?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
            || stat.st_uid != owner
            || stat.st_mode & 0o7777 != 0o700
        {
            return Err(LoopError::refusal(format!(
                "allocations directory must be owner-owned at mode 0700: {}",
                configuration_root.display()
            )));
        }
        let source = read_pinned_file(path, pinned_root, owner, false)?;
        Self::parse(&source)?.with_registry_uids(path)
    }

    /// Read the validated ledger and retain its exact bytes for a deployment digest.
    ///
    /// # Errors
    ///
    /// Refuses an absent or unsafe file, invalid tables, or a registry UID collision.
    pub fn read_with_source(path: &Path) -> Result<(Self, String), LoopError> {
        let source = read_source(path, false)?;
        let allocations = Self::parse(&source)?.with_registry_uids(path)?;
        Ok((allocations, source))
    }

    /// Read the ledger or an empty ledger before the first allocation is written.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths or any invalid table in a present file.
    pub fn read_or_empty(path: &Path) -> Result<Self, LoopError> {
        let source = read_source(path, true)?;
        Self::parse(&source)?.with_registry_uids(path)
    }

    fn with_registry_uids(mut self, path: &Path) -> Result<Self, LoopError> {
        let home = path
            .ancestors()
            .nth(3)
            .ok_or_else(|| LoopError::refusal("allocations path has no owner home"))?;
        let registry_path =
            crate::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
        let registry = crate::load_registry(&registry_path)?;
        self.registry_uids = registry
            .rows(home)
            .into_iter()
            .map(|row| (row.name, row.uid))
            .collect();
        for (name, block) in &self.blocks {
            if let Some((other, uid)) = self
                .registry_uids
                .iter()
                .find(|(_, uid)| block.contains(**uid))
            {
                return Err(LoopError::refusal(format!(
                    "worker uids for loop {name} contain registered uid {uid} of loop {other}"
                )));
            }
        }
        if self
            .letters_gid
            .is_some_and(|gid| self.registry_uids.values().any(|uid| *uid == gid))
        {
            return Err(LoopError::refusal(
                "letters group conflicts with a private group",
            ));
        }
        Ok(self)
    }

    /// Return a loop's block, or refuse the absent allocation by name.
    ///
    /// # Errors
    ///
    /// Refuses when the named loop has no allocation.
    pub fn require(&self, name: &str) -> Result<WorkerBlock, LoopError> {
        self.blocks.get(name).copied().ok_or_else(|| {
            LoopError::refusal(format!("missing worker uid allocation for loop: {name}"))
        })
    }

    /// Look up a block without requiring it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<WorkerBlock> {
        self.blocks.get(name).copied()
    }

    /// The tools-owned supplementary group for loop correspondence.
    #[must_use]
    pub const fn letters_gid(&self) -> Option<u32> {
        self.letters_gid
    }

    /// Select or validate a group distinct from private and worker groups.
    ///
    /// # Errors
    /// Refuses collisions and an exhausted subordinate group range.
    pub(crate) fn ensure_letters_gid(&mut self, uids: &[u32]) -> Result<u32, LoopError> {
        let available = |gid: u32| {
            gid != 65_534
                && !uids.contains(&gid)
                && self.blocks.values().all(|block| !block.contains(gid))
        };
        let gid = match self.letters_gid {
            Some(gid) if available(gid) => gid,
            Some(_) => {
                return Err(LoopError::refusal(
                    "letters group conflicts with a private or worker group",
                ));
            }
            None => (1000..=65_535)
                .rev()
                .find(|gid| available(*gid))
                .ok_or_else(|| LoopError::refusal("letters group range exhausted"))?,
        };
        self.letters_gid = Some(gid);
        Ok(gid)
    }

    /// Iterate all validated blocks.
    pub fn iter(&self) -> impl Iterator<Item = (&str, WorkerBlock)> {
        self.blocks
            .iter()
            .map(|(name, block)| (name.as_str(), *block))
    }

    /// Select the lowest free run of 64 UIDs at or above 3000.
    #[must_use]
    pub fn next_block(&self) -> Option<WorkerBlock> {
        (3000..=65_472)
            .map(|base| WorkerBlock { base, count: 64 })
            .find(|candidate| {
                self.blocks
                    .values()
                    .all(|block| !candidate.overlaps(*block))
                    && self
                        .registry_uids
                        .values()
                        .all(|uid| !candidate.contains(*uid))
                    && self.letters_gid.is_none_or(|gid| !candidate.contains(gid))
            })
    }

    /// Add a block to a validated ledger.
    ///
    /// # Errors
    ///
    /// Refuses duplicate names or overlapping blocks.
    pub fn insert(&mut self, name: &str, block: WorkerBlock) -> Result<(), LoopError> {
        validate_name(name)?;
        if block.count == 0
            || block.base < 1000
            || u64::from(block.base) + u64::from(block.count) - 1 > 65_535
        {
            return Err(LoopError::refusal(format!(
                "uids out of range for loop: {name}"
            )));
        }
        if self.blocks.contains_key(name)
            || self.blocks.values().any(|other| block.overlaps(*other))
            || self.registry_uids.values().any(|uid| block.contains(*uid))
            || self.letters_gid.is_some_and(|gid| block.contains(gid))
        {
            return Err(LoopError::refusal(format!(
                "worker uid allocation conflicts for loop: {name}"
            )));
        }
        self.blocks.insert(name.to_owned(), block);
        Ok(())
    }

    /// Render the complete ledger in stable TOML order.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut result = String::new();
        if let Some(gid) = self.letters_gid {
            use std::fmt::Write as _;
            let _written = writeln!(&mut result, "letters_gid = {gid}");
        }
        for (name, block) in &self.blocks {
            use std::fmt::Write as _;
            let _written = write!(
                &mut result,
                "[{name}]\nuids = {{ base = {}, count = {} }}\n",
                block.base, block.count
            );
        }
        result
    }
}

fn read_source(path: &Path, absent_ok: bool) -> Result<String, LoopError> {
    let owner = nix::unistd::Uid::effective().as_raw();
    let parent = path
        .parent()
        .ok_or_else(|| LoopError::refusal("allocations path has no parent"))?;
    if !path.is_absolute() {
        return Err(LoopError::refusal(format!(
            "allocations path is not absolute: {}",
            path.display()
        )));
    }
    let mut pinned = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| LoopError::refusal(format!("could not open allocations root: {error}")))?;
    let mut previous = fstat(&pinned).map_err(|error| {
        LoopError::refusal(format!("could not inspect allocations root: {error}"))
    })?;
    let mut prefix = PathBuf::from("/");
    for component in parent.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(LoopError::refusal(format!(
                "allocations path has a dotted component: {}",
                path.display()
            )));
        };
        prefix.push(name);
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        let next = openat2(&pinned, name, how).map_err(|error| {
            LoopError::refusal(format!(
                "could not open allocations directory {}: {error}",
                prefix.display()
            ))
        })?;
        let stat = fstat(&next).map_err(|error| {
            LoopError::refusal(format!(
                "could not inspect allocations directory {}: {error}",
                prefix.display()
            ))
        })?;
        let parent_mode = previous.st_mode & 0o7777;
        if (previous.st_uid != 0 && previous.st_uid != owner)
            || (parent_mode & 0o022 != 0
                && (parent_mode & 0o1000 == 0 || (stat.st_uid != 0 && stat.st_uid != owner)))
        {
            return Err(LoopError::refusal(format!(
                "allocations have a replaceable ancestor: {}",
                prefix.display()
            )));
        }
        previous = stat;
        pinned = next;
    }
    let stat = fstat(&pinned).map_err(|error| {
        LoopError::refusal(format!("could not inspect allocations directory: {error}"))
    })?;
    if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
        return Err(LoopError::refusal(format!(
            "allocations directory must be owner-owned at mode 0700: {}",
            parent.display()
        )));
    }
    read_pinned_file(path, &pinned, owner, absent_ok)
}

fn read_pinned_file(
    path: &Path,
    pinned: &OwnedFd,
    owner: u32,
    absent_ok: bool,
) -> Result<String, LoopError> {
    let name = path
        .file_name()
        .ok_or_else(|| LoopError::refusal("allocations path has no name"))?;
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    let file = match openat2(pinned, name, how) {
        Ok(file) => File::from(file),
        Err(Errno::ENOENT) if absent_ok => return Ok(String::new()),
        Err(error) => {
            return Err(LoopError::refusal(format!(
                "could not read allocations {}: {error}",
                path.display()
            )));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        LoopError::refusal(format!(
            "could not inspect allocations {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o600 {
        return Err(LoopError::refusal(format!(
            "allocations must be an owner-owned regular file at mode 0600: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_ALLOCATIONS {
        return Err(LoopError::refusal(format!(
            "allocations exceeds 65536 bytes: {}",
            path.display()
        )));
    }
    let mut source = String::new();
    file.take(MAX_ALLOCATIONS + 1)
        .read_to_string(&mut source)
        .map_err(|error| {
            LoopError::refusal(format!(
                "could not read allocations {}: {error}",
                path.display()
            ))
        })?;
    if source.len() as u64 > MAX_ALLOCATIONS {
        return Err(LoopError::refusal(format!(
            "allocations exceeds 65536 bytes: {}",
            path.display()
        )));
    }
    Ok(source)
}
