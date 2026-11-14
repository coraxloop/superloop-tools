//! A clock for known unfinished letters, independent of population discovery.
use super::{Address, instant::Instant};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::time::{Duration, Instant as Monotonic};

pub(super) type Key = (Address, OsString);
const FIRST: Duration = Duration::from_secs(1);
const CEILING: Duration = Duration::from_secs(30);
const BATCH: usize = 64;

#[derive(Clone)]
pub(super) enum Work {
    Source,
    Restoration(Address),
    Accepted(Instant),
}
pub(super) struct Entry {
    when: Monotonic,
    delay: Duration,
    pub work: Work,
}
#[derive(Default)]
pub(super) struct Queue {
    keys: BTreeMap<Key, Entry>,
    deadlines: BTreeSet<(Monotonic, Key)>,
}
impl Queue {
    pub fn schedule(&mut self, key: Key, work: Work, now: Monotonic) {
        if let Some(entry) = self.keys.get_mut(&key) {
            // A later accepted state supersedes a restored source, never the reverse.
            if matches!(work, Work::Accepted(_)) || matches!(entry.work, Work::Source) {
                entry.work = work;
            }
        } else {
            self.insert(key, work, FIRST, now);
        }
    }
    fn insert(&mut self, key: Key, work: Work, delay: Duration, now: Monotonic) {
        let when = now + delay;
        self.deadlines.insert((when, key.clone()));
        self.keys.insert(key, Entry { when, delay, work });
    }
    pub fn remove(&mut self, key: &Key) -> Option<Entry> {
        let entry = self.keys.remove(key)?;
        self.deadlines.remove(&(entry.when, key.clone()));
        Some(entry)
    }
    pub fn wait(&self, now: Monotonic) -> Option<Duration> {
        self.deadlines
            .first()
            .map(|(when, _)| when.saturating_duration_since(now))
    }
    pub fn due(&mut self, now: Monotonic) -> Vec<(Key, Entry)> {
        let mut due = Vec::new();
        while due.len() < BATCH {
            let Some((when, key)) = self.deadlines.first() else {
                break;
            };
            if *when > now {
                break;
            }
            let key = key.clone();
            if let Some(entry) = self.remove(&key) {
                due.push((key, entry));
            }
        }
        due
    }
    pub fn failed(&mut self, key: Key, entry: Entry, now: Monotonic) {
        let work = self.remove(&key).map_or(entry.work, |current| current.work);
        self.insert(key, work, (entry.delay * 2).min(CEILING), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(name: &str) -> Key {
        (Address::parse("alpha").expect("address"), name.into())
    }
    /// ´claim:loophome:mail-retries-back-off-without-unrelated-wakes´
    /// ´test:unit:mail-retries-back-off-without-unrelated-wakes´
    #[test]
    fn mail_retries_back_off_without_unrelated_wakes() {
        let mut queue = Queue::default();
        let mut now = Monotonic::now();
        queue.schedule(key("beta.01.letter"), Work::Source, now);
        for seconds in [1, 2, 4, 8, 16, 30, 30] {
            let wait = Duration::from_secs(seconds);
            assert_eq!(queue.wait(now), Some(wait));
            queue.schedule(key("beta.01.letter"), Work::Source, now);
            assert!(
                queue
                    .due(
                        (now + wait)
                            .checked_sub(Duration::from_nanos(1))
                            .expect("instant before deadline")
                    )
                    .is_empty()
            );
            now += wait;
            let (key, entry) = queue.due(now).pop().expect("retry without an event");
            queue.failed(key, entry, now);
        }
        queue.remove(&key("beta.01.letter"));
        assert_eq!(
            queue.wait(now),
            None,
            "success or withdrawal stops the clock"
        );
    }
    /// ´claim:loophome:mail-retry-clock-visits-only-a-bounded-due-set´
    /// ´test:unit:mail-retry-clock-visits-only-a-bounded-due-set´
    #[test]
    fn mail_retry_clock_visits_only_a_bounded_due_set() {
        let mut queue = Queue::default();
        let now = Monotonic::now();
        for n in 0..1000 {
            queue.schedule(key(&format!("beta.{n}.letter")), Work::Source, now);
        }
        queue.schedule(key("beta.later.letter"), Work::Source, now + CEILING);
        let due = queue.due(now + FIRST);
        assert_eq!(due.len(), BATCH);
        assert_eq!(queue.keys.len(), 1001 - BATCH);
        assert!(queue.keys.contains_key(&key("beta.later.letter")));
    }
}
