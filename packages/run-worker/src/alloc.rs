use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use loop_home::registry::WorkerBlock;

use crate::error::WorkerError;

/// The deployment account's subordinate UID and GID counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subordinate {
    /// Total subordinate UIDs mapped for the account.
    pub uid_count: u32,
    /// Total subordinate GIDs mapped for the account.
    pub gid_count: u32,
}

/// The account whose user namespace maps every subordinate identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// Passwd name of the account.
    pub name: String,
    /// Real UID of the running process.
    pub uid: u32,
}

/// One registered loop's reserved numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// Registry name of the loop.
    pub name: String,
    /// The loop's own subordinate UID.
    pub uid: u32,
    /// The loop's declared worker block, when it declares one.
    pub block: Option<WorkerBlock>,
}

/// Everything an allocation decides against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationRequest {
    /// The selected loop's declared block.
    pub block: WorkerBlock,
    /// UIDs already recorded as live in the run table.
    pub taken: Vec<u32>,
    /// Every other registered loop's reserved numbers.
    pub peers: Vec<Reservation>,
    /// The deployment account's own UID.
    pub deployment_uid: u32,
    /// The mapping the deployment account actually has.
    pub limits: Subordinate,
}

fn account_count(source: &str, account: &str) -> Option<u32> {
    let mut total: u32 = 0;
    let mut seen = false;
    for line in source.lines() {
        let mut fields = line.trim().split(':');
        if fields.next() != Some(account) {
            continue;
        }
        let count = fields.nth(1)?.parse::<u32>().ok()?;
        total = total.saturating_add(count);
        seen = true;
    }
    seen.then_some(total)
}

/// Read the account name of the running process's own real UID.
///
/// # Errors
///
/// Returns a status-four refusal when the process owner or its passwd entry cannot be read.
pub fn deployment_account(proc_self: &Path, passwd: &Path) -> Result<Account, WorkerError> {
    let uid = fs::metadata(proc_self)
        .map_err(|error| {
            WorkerError::refusal(format!("could not read {}: {error}", proc_self.display()))
        })?
        .uid();
    let source = fs::read_to_string(passwd).map_err(|error| {
        WorkerError::refusal(format!("could not read {}: {error}", passwd.display()))
    })?;
    let name = source
        .lines()
        .find_map(|line| {
            let mut fields = line.trim().split(':');
            let name = fields.next()?;
            (fields.nth(1)?.parse::<u32>().ok()? == uid).then(|| name.to_owned())
        })
        .ok_or_else(|| WorkerError::refusal(format!("no passwd entry for uid {uid}")))?;
    Ok(Account { name, uid })
}

/// Read the subordinate counts the deployment account's namespace actually maps.
///
/// # Errors
///
/// Returns a status-four refusal when either file is unreadable or names no mapping.
pub fn subordinate_counts(
    account: &str,
    uid_map: &Path,
    gid_map: &Path,
) -> Result<Subordinate, WorkerError> {
    let read = |path: &Path, kind: &str| -> Result<u32, WorkerError> {
        let source = fs::read_to_string(path).map_err(|error| {
            WorkerError::refusal(format!("could not read {}: {error}", path.display()))
        })?;
        account_count(&source, account).ok_or_else(|| {
            WorkerError::refusal(format!(
                "no subordinate {kind} mapping for account {account}"
            ))
        })
    };
    Ok(Subordinate {
        uid_count: read(uid_map, "uid")?,
        gid_count: read(gid_map, "gid")?,
    })
}

fn mapped(block: WorkerBlock, limits: Subordinate) -> Result<(), WorkerError> {
    for (count, kind) in [(limits.uid_count, "uid"), (limits.gid_count, "gid")] {
        if block.top() > count {
            return Err(WorkerError::refusal(format!(
                "worker block {}:{} tops {} beyond the subordinate {kind} count {count}",
                block.base,
                block.count,
                block.top()
            )));
        }
    }
    Ok(())
}

fn disjoint(request: &AllocationRequest) -> Result<(), WorkerError> {
    let block = request.block;
    if block.contains(request.deployment_uid) {
        return Err(WorkerError::refusal(format!(
            "worker block {}:{} contains the deployment uid {}",
            block.base, block.count, request.deployment_uid
        )));
    }
    for peer in &request.peers {
        if block.contains(peer.uid) {
            return Err(WorkerError::refusal(format!(
                "worker block {}:{} contains the registered uid {} of loop {}",
                block.base, block.count, peer.uid, peer.name
            )));
        }
        if peer
            .block
            .is_some_and(|peer_block| block.overlaps(peer_block))
        {
            return Err(WorkerError::refusal(format!(
                "worker block {}:{} overlaps the block of loop {}",
                block.base, block.count, peer.name
            )));
        }
    }
    Ok(())
}

/// Take the lowest free slot of a validated block.
///
/// # Errors
///
/// Returns a status-four refusal for an unmapped block, a block overlapping another
/// registered number, or a block whose every slot is live.
pub fn allocate(request: &AllocationRequest) -> Result<u32, WorkerError> {
    mapped(request.block, request.limits)?;
    disjoint(request)?;
    request
        .block
        .uids()
        .find(|uid| !request.taken.contains(uid))
        .ok_or_else(|| {
            WorkerError::refusal(format!(
                "worker block {}:{} is full with {} live lanes",
                request.block.base,
                request.block.count,
                request.taken.len()
            ))
        })
}
