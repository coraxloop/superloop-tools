use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use crate::clock::epoch_from_stamp;
use crate::error::WorkerError;

/// The run table's header row.
pub const HEADER: &str = "uid\tlane\tdriver\tcommit\tstarted\tclaimed";

const LOCK_ATTEMPTS: u32 = 100;
const LOCK_PAUSE: Duration = Duration::from_millis(20);

/// One live lane's row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The allocated worker UID.
    pub uid: u32,
    /// The lane the UID belongs to.
    pub lane: String,
    /// The driver word, empty until the lane launches.
    pub driver: String,
    /// The commit the lane's clone was prepared at.
    pub commit: String,
    /// The launch instant in UTC, empty until the lane launches.
    pub started: String,
    /// A durable per-preparation nanosecond claim stamp, retained across close.
    pub claimed: String,
}

impl Row {
    fn line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.uid, self.lane, self.driver, self.commit, self.started, self.claimed
        )
    }

    fn parse(source: &str) -> Option<Self> {
        let fields: Vec<_> = source.split('\t').collect();
        let [uid, lane, driver, commit, started, claimed] = fields.as_slice() else {
            return None;
        };
        if claimed.is_empty() || !claimed.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            uid: uid.parse().ok()?,
            lane: (*lane).to_owned(),
            driver: (*driver).to_owned(),
            commit: (*commit).to_owned(),
            started: (*started).to_owned(),
            claimed: (*claimed).to_owned(),
        })
    }
}

struct TableLock {
    path: PathBuf,
}

impl TableLock {
    fn take(table: &Path) -> Result<Self, WorkerError> {
        let path = table.with_extension("lock");
        for _attempt in 0..LOCK_ATTEMPTS {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let _written = writeln!(file, "{}", std::process::id());
                    return Ok(Self { path });
                }
                Err(_error) => sleep(LOCK_PAUSE),
            }
        }
        Err(WorkerError::runtime(format!(
            "run table stayed locked: {}",
            path.display()
        )))
    }
}

impl Drop for TableLock {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.path);
    }
}

fn validate_started(started: &str) -> Result<(), WorkerError> {
    if started.is_empty() || epoch_from_stamp(started).is_some() {
        return Ok(());
    }
    Err(WorkerError::refusal(format!(
        "run table started is not a valid UTC Z instant: {started:?}"
    )))
}

fn decode(source: &str) -> Result<Vec<Row>, WorkerError> {
    let mut lines = source.lines();
    let header = lines.next();
    if header == Some("uid\tlane\tdriver\tcommit\tstarted") && lines.clone().next().is_none() {
        return Ok(Vec::new());
    }
    if header != Some(HEADER) || !source.ends_with('\n') {
        return Err(WorkerError::refusal(
            "run table requires claimed-column reconciliation; close old prepared lanes with the retained deployment before cutover",
        ));
    }
    lines
        .map(|line| {
            let row = Row::parse(line).ok_or_else(|| {
                WorkerError::refusal(
                    "run table row has no valid claimed preparation; reconcile retained history",
                )
            })?;
            validate_started(&row.started)?;
            Ok(row)
        })
        .collect()
}

fn reserve_claim(table: &Path, now: u128) -> Result<String, WorkerError> {
    let result = (|| -> std::io::Result<String> {
        let parent = table
            .parent()
            .ok_or_else(|| std::io::Error::other("run table parent absent"))?;
        let path = parent.join("claimed");
        let prior = match fs::symlink_metadata(&path) {
            Ok(info) => {
                if !info.is_file()
                    || info.nlink() != 1
                    || info.uid() != fs::metadata(parent)?.uid()
                    || info.mode() & 0o7777 != 0o600
                {
                    return Err(std::io::Error::other("unsafe preparation claim watermark"));
                }
                let mut text = String::new();
                fs::File::open(&path)?.take(128).read_to_string(&mut text)?;
                text.trim_end()
                    .parse::<u128>()
                    .map_err(|_| std::io::Error::other("invalid preparation claim watermark"))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        let next = now.max(
            prior
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("preparation claims exhausted"))?,
        );
        // The table lock excludes another publisher; an interrupted temporary
        // file never replaces the durable watermark until its bytes are synced.
        let temporary = parent.join(".claimed.next");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        writeln!(file, "{next}")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(next.to_string())
    })();
    result.map_err(|error| WorkerError::runtime(format!("preparation claim: {error}")))
}

/// Read every live row, treating an absent table as an empty one.
///
/// # Errors
///
/// Returns a runtime failure when an existing table cannot be read, or a named
/// refusal when a nonempty start stamp is not a valid UTC Z instant.
pub fn read_rows(table: &Path) -> Result<Vec<Row>, WorkerError> {
    match fs::read_to_string(table) {
        Ok(source) => decode(&source),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(WorkerError::runtime(format!(
            "could not read {}: {error}",
            table.display()
        ))),
    }
}

fn write_rows(table: &Path, rows: &[Row]) -> Result<(), WorkerError> {
    let mut source = String::from(HEADER);
    for row in rows {
        validate_started(&row.started)?;
        source.push('\n');
        source.push_str(&row.line());
    }
    source.push('\n');
    fs::write(table, source).map_err(|error| {
        WorkerError::runtime(format!("could not write {}: {error}", table.display()))
    })?;
    fs::set_permissions(table, fs::Permissions::from_mode(0o644)).map_err(|error| {
        WorkerError::runtime(format!("could not mode {}: {error}", table.display()))
    })
}

fn guarded_push(rows: &mut Vec<Row>, row: &Row) -> Result<(), WorkerError> {
    if let Some(live) = rows.iter().find(|live| live.lane == row.lane) {
        return Err(WorkerError::refusal(format!(
            "lane {} is already live at uid {}",
            live.lane, live.uid
        )));
    }
    if let Some(live) = rows.iter().find(|live| live.uid == row.uid) {
        return Err(WorkerError::refusal(format!(
            "uid {} is already live as lane {}",
            live.uid, live.lane
        )));
    }
    rows.push(row.clone());
    Ok(())
}

/// Append one allocation row under an exclusive lock on the table.
///
/// # Errors
///
/// Returns a status-four refusal when the lane or the UID is already live, and a
/// runtime failure when the lock or the table itself cannot be taken.
pub fn append_row(table: &Path, row: &Row) -> Result<(), WorkerError> {
    let _lock = TableLock::take(table)?;
    let mut rows = read_rows(table)?;
    guarded_push(&mut rows, row)?;
    write_rows(table, &rows)
}

/// Claim the lowest free slot for one lane with the table locked throughout.
///
/// Reading the table, choosing a UID from what it holds, and writing the row back
/// happen inside one lock, because two callers that read the same snapshot would
/// otherwise choose the same UID and both append it — two lanes at one UID, which
/// is the kernel boundary this package exists to create.
///
/// # Errors
///
/// Returns whatever the chooser refuses, a status-four refusal when the lane or
/// the chosen UID is already live, and a runtime failure when the lock cannot be taken.
pub fn claim_slot<F>(table: &Path, lane: &str, choose: F) -> Result<Row, WorkerError>
where
    F: FnOnce(&[u32]) -> Result<u32, WorkerError>,
{
    let _lock = TableLock::take(table)?;
    let mut rows = read_rows(table)?;
    if let Some(live) = rows.iter().find(|live| live.lane == lane) {
        return Err(WorkerError::refusal(format!(
            "lane {} is already live at uid {}",
            live.lane, live.uid
        )));
    }
    let taken: Vec<u32> = rows.iter().map(|row| row.uid).collect();
    let claimed = Row {
        uid: choose(&taken)?,
        lane: lane.to_owned(),
        driver: String::new(),
        commit: String::new(),
        started: String::new(),
        claimed: reserve_claim(
            table,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| WorkerError::runtime(format!("preparation clock: {error}")))?
                .as_nanos(),
        )?,
    };
    guarded_push(&mut rows, &claimed)?;
    write_rows(table, &rows)?;
    Ok(claimed)
}

/// Fill a claimed row's commit under the same exclusive lock.
///
/// # Errors
///
/// Returns a status-four refusal when the lane has no claimed row.
pub fn fill_commit(table: &Path, lane: &str, commit: &str) -> Result<Row, WorkerError> {
    let _lock = TableLock::take(table)?;
    let mut rows = read_rows(table)?;
    let row = rows
        .iter_mut()
        .find(|row| row.lane == lane)
        .ok_or_else(|| WorkerError::refusal(format!("lane {lane} has no claimed row")))?;
    commit.clone_into(&mut row.commit);
    let filled = row.clone();
    write_rows(table, &rows)?;
    Ok(filled)
}

/// Drop one lane's row under the same exclusive lock, freeing its slot.
///
/// # Errors
///
/// Returns a runtime failure when the lock or the table cannot be taken.
pub fn remove_row(table: &Path, lane: &str) -> Result<(), WorkerError> {
    let _lock = TableLock::take(table)?;
    let mut rows = read_rows(table)?;
    rows.retain(|row| row.lane != lane);
    write_rows(table, &rows)
}

/// Fill a prepared row's driver and start instant under the same exclusive lock.
///
/// # Errors
///
/// Returns a status-four refusal when the lane has no prepared row or already
/// carries a start instant.
pub fn fill_launch(
    table: &Path,
    lane: &str,
    driver: &str,
    started: &str,
) -> Result<Row, WorkerError> {
    let _lock = TableLock::take(table)?;
    let mut rows = read_rows(table)?;
    let row = rows
        .iter_mut()
        .find(|row| row.lane == lane)
        .ok_or_else(|| WorkerError::refusal(format!("lane {lane} has no prepared row")))?;
    if !row.started.is_empty() {
        return Err(WorkerError::refusal(format!(
            "lane {lane} already launched at {}",
            row.started
        )));
    }
    driver.clone_into(&mut row.driver);
    started.clone_into(&mut row.started);
    let filled = row.clone();
    write_rows(table, &rows)?;
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// ´claim:runworker:preparation-claim-watermark-survives-clock-rollback´
    /// ´test:unit:preparation-claim-watermark-survives-clock-rollback´
    #[test]
    fn preparation_claim_watermark_survives_clock_rollback() {
        let root =
            std::env::temp_dir().join(format!("worker-claim-watermark-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let table = root.join("table.tsv");
        assert_eq!(reserve_claim(&table, 100).expect("first claim"), "100");
        assert_eq!(reserve_claim(&table, 1).expect("backward clock"), "101");
        assert_eq!(reserve_claim(&table, 101).expect("equal clock"), "102");
        fs::write(root.join(".claimed.next"), b"1").expect("interrupted temporary");
        assert_eq!(fs::read_to_string(root.join("claimed")).unwrap(), "102\n");
        assert_eq!(reserve_claim(&table, 1).expect("recover temporary"), "103");
        assert!(!root.join(".claimed.next").exists());
        assert_eq!(
            fs::metadata(root.join("claimed")).unwrap().mode() & 0o7777,
            0o600
        );
        fs::write(root.join("claimed"), b"").expect("corrupt watermark");
        assert!(reserve_claim(&table, 103).is_err());
        assert!(decode("uid\tlane\tdriver\tcommit\tstarted\n1\told\t\t\t\n").is_err());
        assert_eq!(
            decode("uid\tlane\tdriver\tcommit\tstarted\n").expect("empty migration table"),
            [] as [Row; 0]
        );
        fs::remove_dir_all(root).expect("cleanup");
    }
}
