//! Select the current driver lock for both read-only monitors.

use std::fs;
use std::path::Path;

pub type DriverLock = (&'static str, u32, Option<u32>, bool);

pub fn parse_lock(bytes: &[u8]) -> Option<(u32, Option<u32>)> {
    let mut lines = std::str::from_utf8(bytes).ok()?.lines();
    let driver = lines.next()?.parse().ok()?;
    let child = lines.next().map(str::parse).transpose().ok()?;
    lines.next().is_none().then_some((driver, child))
}

/// Prefer a live driver's lock; break ties by modification time and then name.
pub fn select_driver_lock(run_dir: &Path, is_live: impl Fn(u32) -> bool) -> Option<DriverLock> {
    [".codex-lane.lock", ".claude-lane.lock"]
        .into_iter()
        .filter_map(|name| {
            let path = run_dir.join(name);
            let metadata = fs::metadata(&path).ok()?;
            if !metadata.is_file() {
                return None;
            }
            let modified = metadata.modified().ok()?;
            let (pid, child) = parse_lock(&fs::read(path).ok()?)?;
            let live = is_live(pid);
            Some(((live, modified, name), (name, pid, child, live)))
        })
        .max_by_key(|(key, _)| *key)
        .map(|(_, selected)| selected)
}

pub fn pid_live_from_proc(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|record| {
            record
                .rsplit_once(") ")
                .map(|(_, fields)| fields.to_owned())
        })
        .and_then(|fields| fields.as_bytes().first().copied())
        .is_some_and(|state| !matches!(state, b'Z' | b'X'))
}
