//! Non-authoritative, process-local service counters; quiet services do no work.
use serde::Serialize;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(60);
#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize)]
pub(super) struct Counters {
    pub scans_started: u64,
    pub candidate_attempts: u64,
    pub deliveries: u64,
    pub refusals_written: u64,
    pub refusals_unwritten: u64,
    pub due_retries: u64,
}
#[derive(Default)]
pub(super) struct Activity {
    pub counters: Counters,
    published: Counters,
    attempted: Option<Instant>,
    last_notice: Option<Instant>,
}
#[derive(Serialize)]
struct Snapshot {
    version: u8,
    pid: u32,
    observed: String,
    counters: Counters,
}

impl Activity {
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        (self.counters != self.published).then(|| {
            self.attempted.map_or(Duration::ZERO, |last| {
                INTERVAL.saturating_sub(now.saturating_duration_since(last))
            })
        })
    }
    pub fn publish(&mut self, journal: &super::journal::Journal, now: Instant) {
        if self.wait(now) != Some(Duration::ZERO) {
            return;
        }
        self.attempted = Some(now);
        let result = super::instant::Instant::now().and_then(|observed| {
            journal.activity(&Snapshot {
                version: 1,
                pid: std::process::id(),
                observed: observed.to_string(),
                counters: self.counters,
            })
        });
        match result {
            Ok(()) => self.published = self.counters,
            Err(error) => {
                tracing::info!(reason = %error, "mail activity counters could not be published");
            }
        }
    }
    pub fn unwritten(
        &mut self,
        now: Instant,
        sender: &super::Address,
        name: &std::ffi::OsStr,
        error: &super::journal::MailError,
    ) {
        self.counters.refusals_unwritten = self.counters.refusals_unwritten.saturating_add(1);
        if self.notice_due(now) {
            tracing::info!(%sender, letter = %name.to_string_lossy(), reason = %error, total = self.counters.refusals_unwritten, "mail refusal could not be written");
        }
    }
    fn notice_due(&mut self, now: Instant) -> bool {
        if self
            .last_notice
            .is_some_and(|last| now.saturating_duration_since(last) < INTERVAL)
        {
            return false;
        }
        self.last_notice = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// ´claim:loophome:mail-unwritten-refusal-notices-are-rate-limited´
    /// ´test:unit:mail-unwritten-refusal-notices-are-rate-limited´
    #[test]
    fn mail_unwritten_refusal_notices_are_rate_limited() {
        let mut activity = Activity::default();
        let now = Instant::now();
        assert!(activity.notice_due(now));
        for second in 0..60 {
            assert!(!activity.notice_due(now + Duration::from_secs(second)));
        }
        assert!(activity.notice_due(now + INTERVAL));
        assert!(!activity.notice_due(now + INTERVAL));
    }
}
