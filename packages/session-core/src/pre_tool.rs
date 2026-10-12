use crate::heartbeat::{parse_timestamp, prompt_marker_file, system_now};
use crate::heartbeat_toggle as toggle;
use std::fs;
use std::path::Path;
const MARKER_MAX_AGE_SECONDS: f64 = 15.0 * 60.0;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleDecision {
    Allow,
    Warn,
    Refuse,
}
#[must_use]
pub fn schedule_wakeup(
    state_dir: &Path,
    session: &str,
    cwd: &str,
    home: Option<&Path>,
) -> ScheduleDecision {
    let boundary = home.map(Path::to_path_buf);
    match toggle::enabled(state_dir, Path::new(cwd), boundary.as_deref()) {
        Ok(false) => ScheduleDecision::Warn,
        Err(_) => ScheduleDecision::Allow,
        Ok(true) if schedule_wakeup_allowed(state_dir, session) => ScheduleDecision::Allow,
        Ok(true) => ScheduleDecision::Refuse,
    }
}

fn schedule_wakeup_allowed(state_dir: &Path, session: &str) -> bool {
    match fs::metadata(state_dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) | Err(_) => return true,
    }
    let marker = state_dir.join(prompt_marker_file(session));
    match fs::read_to_string(&marker) {
        Ok(source) => consume_marker(&marker, &source),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

fn consume_marker(marker: &Path, source: &str) -> bool {
    let Some(timestamp) = parse_timestamp(source.trim()) else {
        return true;
    };
    let Some(now) = system_now() else {
        return true;
    };
    let stale = now - timestamp > MARKER_MAX_AGE_SECONDS;
    if fs::remove_file(marker).is_err() {
        return true;
    }
    !stale
}
