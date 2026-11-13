//! Bounded, content-free accounting for an exclusive request-lock hold.
use std::cell::RefCell;
use std::fmt::Write as _;
#[cfg(not(test))]
use std::io::Write as _;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

const NAMES: [&str; 18] = [
    "other",
    "inventory_before",
    "inventory_after",
    "shapes",
    "withdraw",
    "tombstone",
    "run_write",
    "shape_write",
    "learned",
    "policy",
    "helper_read",
    "helper_preview",
    "helper_commit",
    "helper_other",
    "mirror",
    "modes",
    "inventory_other",
    "attempt_journal",
];

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Phase {
    InventoryBefore = 1,
    InventoryAfter,
    Shapes,
    Withdraw,
    Tombstone,
    RunWrite,
    ShapeWrite,
    Learned,
    Policy,
    HelperRead,
    HelperPreview,
    HelperCommit,
    HelperOther,
    Mirror,
    Modes,
    InventoryOther,
    AttemptJournal,
}

#[derive(Debug)]
struct Hold {
    path: &'static str,
    request: [u8; 160],
    request_len: usize,
    started: Instant,
    checkpoint: Instant,
    current: usize,
    elapsed: [Duration; NAMES.len()],
    calls: [u64; NAMES.len()],
    publications: [u64; 8],
    publication_count: usize,
}

fn millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

impl Hold {
    fn new(request: Option<&str>) -> Self {
        let now = Instant::now();
        let mut hold = Self {
            path: "exclusive",
            request: [0; 160],
            request_len: 0,
            started: now,
            checkpoint: now,
            current: 0,
            elapsed: [Duration::ZERO; NAMES.len()],
            calls: [0; NAMES.len()],
            publications: [0; 8],
            publication_count: 0,
        };
        if let Some(id) = request.filter(|id| {
            id.len() <= 160
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        }) {
            hold.request[..id.len()].copy_from_slice(id.as_bytes());
            hold.request_len = id.len();
        }
        hold
    }

    fn switch(&mut self, next: usize, now: Instant) -> usize {
        self.elapsed[self.current] = self.elapsed[self.current]
            .saturating_add(now.saturating_duration_since(self.checkpoint));
        self.checkpoint = now;
        std::mem::replace(&mut self.current, next)
    }

    fn line(&self, wait: Duration, now: Instant) -> Line {
        let mut line = Line {
            bytes: [0; 4096],
            len: 0,
        };
        let request = std::str::from_utf8(&self.request[..self.request_len]).unwrap_or_default();
        let _written = write!(
            line,
            concat!(
                "door-request-lock {{\"operation\":\"write\",\"outcome\":\"released\",",
                "\"path\":\"{}\",\"request_id\":\"{}\",",
                "\"wait_ms\":{},\"hold_ms\":{},\"phases\":{{"
            ),
            self.path,
            request,
            millis(wait),
            millis(now.saturating_duration_since(self.started))
        );
        for (i, name) in NAMES.iter().enumerate() {
            let _written = write!(
                line,
                "{}\"{}\":{{\"ms\":{},\"calls\":{}}}",
                if i == 0 { "" } else { "," },
                name,
                millis(self.elapsed[i]),
                self.calls[i]
            );
        }
        let _written = write!(line, "}},\"policy_ms\":[");
        for (i, ms) in self
            .publications
            .iter()
            .take(self.publication_count.min(8))
            .enumerate()
        {
            let _written = write!(line, "{}{ms}", if i == 0 { "" } else { "," });
        }
        let _written = writeln!(
            line,
            "],\"policy_overflow\":{}}}",
            self.publication_count.saturating_sub(8)
        );
        line
    }
}

#[derive(Debug)]
struct Line {
    bytes: [u8; 4096],
    len: usize,
}
impl std::fmt::Write for Line {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(std::fmt::Error)?;
        if end > self.bytes.len() {
            return Err(std::fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

thread_local! { static ACTIVE: RefCell<Weak<Mutex<Hold>>> = const { RefCell::new(Weak::new()) }; }

/// Storage is allocated before flock; ownership permits a guard to be released
/// by another thread. Phase updates use only its fixed counters and a mutex.
#[derive(Debug)]
pub struct Guard {
    hold: Arc<Mutex<Hold>>,
    wait: Duration,
    acquired: bool,
    line: Option<Line>,
}
impl Guard {
    pub fn prepare(request: Option<&str>) -> Self {
        Self {
            hold: Arc::new(Mutex::new(Hold::new(request))),
            wait: Duration::ZERO,
            acquired: false,
            line: None,
        }
    }
    pub fn acquired(&mut self, acquired: Instant) {
        self.acquired = true;
        if let Ok(mut hold) = self.hold.lock() {
            hold.started = acquired;
            hold.checkpoint = hold.started;
        }
        ACTIVE.with(|slot| *slot.borrow_mut() = Arc::downgrade(&self.hold));
    }
    pub fn waited(&mut self, started: Instant) {
        if let Ok(hold) = self.hold.lock() {
            self.wait = hold.started.saturating_duration_since(started);
        }
    }
    pub fn releasing(&mut self) {
        if !self.acquired {
            return;
        }
        if let Ok(mut hold) = self.hold.lock() {
            let now = Instant::now();
            hold.switch(0, now);
            self.line = Some(hold.line(self.wait, now));
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        // StoreLock's file field has already closed. Journal backpressure must
        // not extend the request flock; the bounded line was prepared under it.
        if let Some(line) = &self.line {
            #[cfg(not(test))]
            let _logged = std::io::stderr().lock().write_all(&line.bytes[..line.len]);
            #[cfg(test)]
            #[allow(clippy::print_stderr)] // libtest captures the macro, not stderr().
            {
                eprint!("{}", String::from_utf8_lossy(&line.bytes[..line.len]));
            }
        }
    }
}

pub fn name(path: &'static str) {
    if path.len() > 64 || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return;
    }
    ACTIVE.with(|slot| {
        if let Some(hold) = slot.borrow().upgrade()
            && let Ok(mut hold) = hold.lock()
        {
            hold.path = path;
        }
    });
}

pub fn request(id: &str) {
    ACTIVE.with(|slot| {
        if let Some(hold) = slot.borrow().upgrade()
            && let Ok(mut hold) = hold.lock()
            && id.len() <= 160
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        {
            hold.request[..id.len()].copy_from_slice(id.as_bytes());
            hold.request_len = id.len();
        }
    });
}

pub struct Timer {
    previous: Option<(Arc<Mutex<Hold>>, usize)>,
    policy: Option<(usize, Instant)>,
}
pub fn inventory() -> Timer {
    let inside = ACTIVE.with(|slot| {
        slot.borrow().upgrade().is_some_and(|hold| {
            hold.lock().is_ok_and(|data| {
                data.current == Phase::InventoryBefore as usize
                    || data.current == Phase::InventoryAfter as usize
            })
        })
    });
    if inside {
        Timer {
            previous: None,
            policy: None,
        }
    } else {
        phase(Phase::InventoryOther)
    }
}

pub fn phase(phase: Phase) -> Timer {
    let mut policy = None;
    let previous = ACTIVE.with(|slot| {
        slot.borrow().upgrade().and_then(|hold| {
            let previous = {
                let mut data = hold.lock().ok()?;
                let next = phase as usize;
                if next == Phase::Policy as usize {
                    policy = Some((data.publication_count, Instant::now()));
                    data.publication_count = data.publication_count.saturating_add(1);
                }
                data.calls[next] = data.calls[next].saturating_add(1);
                data.switch(next, Instant::now())
            };
            Some((hold, previous))
        })
    });
    Timer { previous, policy }
}
impl Drop for Timer {
    fn drop(&mut self) {
        if let Some((hold, previous)) = &self.previous
            && let Ok(mut hold) = hold.lock()
        {
            hold.switch(*previous, Instant::now());
            if let Some((index, started)) = self.policy
                && let Some(ms) = hold.publications.get_mut(index)
            {
                *ms = millis(started.elapsed());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:exclusive-hold-line-is-bounded-and-content-free´
    #[test]
    fn exclusive_hold_line_is_bounded_and_content_free() {
        let secret = "recognisable request body /private/path\nforged-line";
        let mut hold = Hold::new(Some(secret));
        hold.path = "file";
        hold.elapsed.fill(Duration::MAX);
        hold.calls.fill(u64::MAX);
        hold.publications.fill(u64::MAX);
        hold.publication_count = usize::MAX;
        let line = hold.line(Duration::MAX, hold.started + Duration::from_secs(1));
        assert!(line.len < 4096);
        let text = std::str::from_utf8(&line.bytes[..line.len]).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(!text.contains(secret));
        assert!(!text.contains("private/path"));
        let value: serde_json::Value =
            serde_json::from_str(text.strip_prefix("door-request-lock ").unwrap()).unwrap();
        assert_eq!(value["request_id"], "");
        assert_eq!(value["path"], "file");
        assert_eq!(value["wait_ms"], u64::MAX);
        for phase in value["phases"].as_object().unwrap().values() {
            assert!(phase["ms"].is_u64());
            assert!(phase["calls"].is_u64());
        }
        assert_eq!(value["hold_ms"], 1000);
        assert_eq!(value["phases"].as_object().unwrap().len(), NAMES.len());
        hold.request.fill(b'R');
        hold.request_len = 160;
        hold.path = "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp";
        let maximum = hold.line(Duration::MAX, hold.started + Duration::from_secs(1));
        assert!(maximum.len < 4096);
        let text = std::str::from_utf8(&maximum.bytes[..maximum.len]).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(text.strip_prefix("door-request-lock ").unwrap()).unwrap();
        assert_eq!(value["request_id"].as_str().unwrap().len(), 160);
    }

    /// ´test:unit:exclusive-hold-nested-timers-count-publications-and-helpers´
    #[test]
    fn exclusive_hold_nested_timers_count_publications_and_helpers() {
        let mut guard = Guard::prepare(Some("R:1a"));
        guard.acquired(Instant::now());
        name("record_agent");
        for _ in 0..10 {
            let _policy = phase(Phase::Policy);
            let _helper = phase(Phase::HelperRead);
        }
        let hold = guard.hold.lock().unwrap();
        assert_eq!(hold.path, "record_agent");
        assert_eq!(hold.calls[Phase::Policy as usize], 10);
        assert_eq!(hold.calls[Phase::HelperRead as usize], 10);
        assert_eq!(hold.current, 0);
        let line = hold.line(Duration::ZERO, Instant::now());
        let text = std::str::from_utf8(&line.bytes[..line.len]).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(text.strip_prefix("door-request-lock ").unwrap()).unwrap();
        assert_eq!(value["policy_ms"].as_array().unwrap().len(), 8);
        assert_eq!(value["policy_overflow"], 2);
        drop(hold);
    }

    /// ´test:unit:exclusive-hold-phase-accounting-is-exclusive´
    #[test]
    fn exclusive_hold_phase_accounting_is_exclusive() {
        let mut hold = Hold::new(Some("R:1a"));
        let start = hold.started;
        assert_eq!(hold.switch(9, start + Duration::from_millis(3)), 0);
        assert_eq!(hold.switch(10, start + Duration::from_millis(8)), 9);
        assert_eq!(hold.switch(9, start + Duration::from_millis(15)), 10);
        hold.switch(0, start + Duration::from_millis(19));
        assert_eq!(hold.elapsed[0].as_millis(), 3);
        assert_eq!(hold.elapsed[9].as_millis(), 9);
        assert_eq!(hold.elapsed[10].as_millis(), 7);
        let line = hold.line(Duration::from_millis(2), start + Duration::from_millis(19));
        let text = std::str::from_utf8(&line.bytes[..line.len]).unwrap();
        assert!(text.contains("\"request_id\":\"R:1a\""));
        assert!(text.contains("\"wait_ms\":2"));
    }
}
