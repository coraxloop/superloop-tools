#![deny(clippy::indexing_slicing)]

//! One process-free reader for the fields of a `/proc/<pid>/stat` buffer.
//!
//! The module never opens a path or launches a process: a caller supplies the bytes it already
//! read, and this module only skips the parenthesized comm field, which may itself contain spaces
//! and parentheses, and then names the fields that follow it.

/// State, parent, and start-time fields of one `/proc/<pid>/stat` buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcStat {
    /// Field 4: parent process identifier.
    pub parent_pid: u32,
    /// Field 22: start time in clock ticks since boot.
    pub start_time: u64,
}

/// Bytes after the comm field's closing parenthesis and separating space.
///
/// The comm field is the only field that may contain spaces and parentheses, so the last `") "`
/// is its terminator whatever the executable was called.
fn after_comm(stat: &[u8]) -> Option<&[u8]> {
    stat.windows(2)
        .rposition(|window| window == b") ")
        .and_then(|position| stat.get(position.saturating_add(2)..))
}

fn fields_after_comm(stat: &[u8]) -> Option<core::str::SplitAsciiWhitespace<'_>> {
    Some(
        core::str::from_utf8(after_comm(stat)?)
            .ok()?
            .split_ascii_whitespace(),
    )
}

/// Field 3: the first byte of the process state, without requiring any later field.
pub fn state(stat: &[u8]) -> Option<u8> {
    after_comm(stat)?.first().copied()
}

/// Field 22: the start time, without requiring any other field to parse.
pub fn start_time(stat: &[u8]) -> Option<u64> {
    fields_after_comm(stat)?.nth(19)?.parse().ok()
}

/// Fields 4 and 22 together; absent when either one is missing or unparseable.
pub fn parent_and_start_time(stat: &[u8]) -> Option<ProcStat> {
    let mut fields = fields_after_comm(stat)?;
    fields.next()?;
    let parent_pid = fields.next()?.parse().ok()?;
    let start_time = fields.nth(17)?.parse().ok()?;
    Some(ProcStat {
        parent_pid,
        start_time,
    })
}
