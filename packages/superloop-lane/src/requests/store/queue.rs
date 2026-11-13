//! Process-local arrival order; flock remains the cross-process authority.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

type Key = (u64, u64);
type Waiters = BTreeMap<Key, VecDeque<Arc<()>>>;

pub(super) struct Queue {
    waiters: Mutex<Waiters>,
    changed: Condvar,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            waiters: Mutex::new(BTreeMap::new()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Waiters> {
        // Retirement must work even after an unwinding owner poisoned the mutex.
        self.waiters.lock().unwrap_or_else(|error| {
            self.waiters.clear_poison();
            error.into_inner()
        })
    }

    pub fn join(&self, key: Key) -> Ticket<'_> {
        let token = Arc::new(());
        self.lock()
            .entry(key)
            .or_default()
            .push_back(Arc::clone(&token));
        Ticket {
            queue: self,
            key,
            token,
        }
    }
}

pub(super) struct Ticket<'a> {
    queue: &'a Queue,
    key: Key,
    token: Arc<()>,
}

impl Ticket<'_> {
    pub const fn key(&self) -> Key {
        self.key
    }

    fn first(&self, waiters: &Waiters) -> bool {
        waiters
            .get(&self.key)
            .and_then(VecDeque::front)
            .is_some_and(|token| Arc::ptr_eq(token, &self.token))
    }

    pub fn is_head(&self) -> bool {
        self.first(&self.queue.lock())
    }

    pub fn wait_turn(&self, bound: Duration) {
        // Checking while holding the mutex closes the notify-before-wait race.
        let waiters = self.queue.lock();
        let _waited = self
            .queue
            .changed
            .wait_timeout_while(waiters, bound, |rows| !self.first(rows))
            .unwrap_or_else(|error| {
                self.queue.waiters.clear_poison();
                error.into_inner()
            });
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        {
            let mut waiters = self.queue.lock();
            if let Some(rows) = waiters.get_mut(&self.key) {
                rows.retain(|token| !Arc::ptr_eq(token, &self.token));
                if rows.is_empty() {
                    waiters.remove(&self.key);
                }
            }
        }
        self.queue.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Store, tests::Fixture};
    use super::*;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::Instant;

    const HANG: Duration = Duration::from_secs(120);

    fn receive<T>(rx: &Receiver<T>) -> T {
        rx.recv_timeout(HANG)
            .expect("fixture event before hang bound")
    }

    fn contender(
        store: &Store,
        number: usize,
        arrived: Sender<()>,
        acquired: Sender<usize>,
        resume: Option<Receiver<()>>,
    ) -> std::thread::JoinHandle<()> {
        let store = store.for_request(Instant::now() + HANG).unwrap();
        std::thread::spawn(move || {
            super::super::AFTER_WRITER_LOCK_CONTENTION.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    arrived.send(()).unwrap();
                    if let Some(resume) = resume {
                        receive(&resume);
                    }
                }));
            });
            let _guard = store.fixture_exclusive_lock().expect("ordered acquisition");
            acquired.send(number).unwrap();
        })
    }

    /// ´test:unit:request-writer-queue-orders-siblings-and-reacquisition´
    #[test]
    fn request_writer_queue_orders_siblings_and_reacquisition() {
        let fixture = Fixture::new();
        let store = fixture
            .store()
            .for_request(Instant::now() + HANG)
            .unwrap()
            .with_request_id("R:same");
        let held = store.fixture_exclusive_lock().unwrap();
        let (arrived, arrival) = mpsc::channel();
        let (acquired, order) = mpsc::channel();
        let (resume, paused) = mpsc::channel();
        let first = contender(
            &fixture.store().with_request_id("R:same"),
            1,
            arrived.clone(),
            acquired.clone(),
            Some(paused),
        );
        receive(&arrival);
        // An unnamed writer and a sibling of the same request each get a ticket.
        let second = contender(&fixture.store(), 2, arrived.clone(), acquired.clone(), None);
        receive(&arrival);
        let third = contender(
            &fixture.store().with_request_id("R:same"),
            3,
            arrived,
            acquired.clone(),
            None,
        );
        receive(&arrival);
        drop(held);
        super::super::AFTER_WRITER_POLL.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |success| {
                assert!(!success, "releasing thread must not barge past paused head");
                resume.send(()).unwrap();
            }));
        });
        let again = store.fixture_exclusive_lock().unwrap();
        acquired.send(4).unwrap();
        drop(again);
        assert_eq!(
            (0..4).map(|_| receive(&order)).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        for thread in [first, second, third] {
            thread.join().unwrap();
        }
    }

    /// ´test:unit:request-writer-queue-drop-and-poison-retire-head´
    #[test]
    fn request_writer_queue_drop_and_poison_retire_head() {
        let queue = Queue::new();
        let first = queue.join((1, 1));
        let next = queue.join((1, 1));
        let independent = queue.join((1, 2));
        assert!(!next.is_head());
        assert!(independent.is_head(), "different inode has its own queue");
        std::thread::scope(|scope| {
            assert!(
                scope
                    .spawn(move || {
                        let _head = first;
                        panic!("owner unwinds with ticket");
                    })
                    .join()
                    .is_err()
            );
        });
        assert!(next.is_head(), "unwound head must retire");
        let last = queue.join((1, 1));
        assert!(
            std::panic::catch_unwind(|| {
                let _mutex = queue.lock();
                panic!("poison bookkeeping");
            })
            .is_err()
        );
        drop(next);
        assert!(last.is_head(), "poison must not prevent retirement");
        drop(last);
        drop(independent);
        assert!(queue.lock().is_empty(), "empty inode queues are removed");
    }

    /// ´test:unit:request-writer-queue-expiry-and-nesting-release-tickets´
    #[test]
    fn request_writer_queue_expiry_and_nesting_release_tickets() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let held = store.fixture_exclusive_lock().unwrap();
        let (arrived, arrival) = mpsc::channel();
        let (acquired, order) = mpsc::channel();
        let (resume, paused) = mpsc::channel();
        let first = contender(&fixture.store(), 1, arrived, acquired, Some(paused));
        receive(&arrival);
        // A non-head, nested caller expires independently of the paused head.
        super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(Some(Duration::ZERO)));
        let error = store.fixture_exclusive_lock().unwrap_err();
        super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(None));
        assert!(super::super::is_lock_contention(&error));
        drop(held);
        resume.send(()).unwrap();
        assert_eq!(receive(&order), 1);
        first.join().unwrap();
        drop(
            store
                .fixture_exclusive_lock()
                .expect("expired tail cannot wedge successor"),
        );
        // A head also expires while a separately opened lock is held.
        let held = store.fixture_exclusive_lock().unwrap();
        super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(Some(Duration::ZERO)));
        let error = store.fixture_exclusive_lock().unwrap_err();
        super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(None));
        assert!(super::super::is_lock_contention(&error));
        drop(held);
        drop(
            store
                .fixture_exclusive_lock()
                .expect("expired head cannot wedge successor"),
        );
    }

    /// ´test:unit:request-writer-queue-retains-ticket-across-attempts´
    #[test]
    fn request_writer_queue_retains_ticket_across_attempts() {
        let fixture = Fixture::new();
        let store = fixture.store().for_request(Instant::now() + HANG).unwrap();
        let held = store.fixture_exclusive_lock().unwrap();
        let first = fixture.store().for_request(Instant::now() + HANG).unwrap();
        let (expired, expiry) = mpsc::channel();
        let (resume, paused) = mpsc::channel();
        let (acquired, order) = mpsc::channel();
        let sender = acquired.clone();
        let thread = std::thread::spawn(move || {
            super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(Some(Duration::ZERO)));
            super::super::AFTER_WRITER_LOCK_TIMEOUT.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    expired.send(()).unwrap();
                    receive(&paused);
                }));
            });
            let _held = first.fixture_exclusive_lock().unwrap();
            sender.send(1).unwrap();
        });
        receive(&expiry);
        drop(held);
        super::super::AFTER_WRITER_POLL.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |success| {
                assert!(!success, "retrying head must retain its arrival order");
                resume.send(()).unwrap();
            }));
        });
        let held = store.fixture_exclusive_lock().unwrap();
        acquired.send(2).unwrap();
        drop(held);
        assert_eq!([receive(&order), receive(&order)], [1, 2]);
        thread.join().unwrap();
    }
    /// ´test:unit:request-writer-queue-reopen-errors-and-panics-retire-ticket´
    #[test]
    fn request_writer_queue_reopen_errors_and_panics_retire_ticket() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
        for fault in ["mode", "open", "identity", "panic"] {
            let fixture = Fixture::new();
            let store = fixture.store();
            let held = store.fixture_exclusive_lock().unwrap();
            let lock = std::path::PathBuf::from(format!(
                "/proc/self/fd/{}",
                store.state_dir().as_raw_fd()
            ))
            .join(super::super::LOCK_FILE);
            let stat = std::fs::metadata(&lock).unwrap();
            let key = (stat.dev(), stat.ino());
            let change = lock.clone();
            super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(Some(Duration::ZERO)));
            super::super::AFTER_WRITER_LOCK_TIMEOUT.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || match fault {
                    "mode" => {
                        std::fs::set_permissions(change, std::fs::Permissions::from_mode(0o644))
                            .unwrap();
                    }
                    "open" => {
                        std::fs::remove_file(&change).unwrap();
                        symlink("absent", change).unwrap();
                    }
                    "identity" => {
                        std::fs::remove_file(&change).unwrap();
                        std::fs::write(&change, b"").unwrap();
                        std::fs::set_permissions(change, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                    _ => panic!("unwind retry chain"),
                }));
            });
            let waiter = store.for_request(Instant::now() + HANG).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                waiter.fixture_exclusive_lock()
            }));
            super::super::WRITER_LOCK_WAIT_OVERRIDE.with(|v| v.set(None));
            if fault == "panic" {
                assert!(result.is_err());
            } else {
                let error = result.unwrap().unwrap_err();
                assert!(
                    !super::super::is_lock_contention(&error),
                    "{fault}: {error:?}"
                );
                if fault == "identity" {
                    assert_eq!(error.detail, "request lock identity changed during retry");
                }
            }
            assert!(
                !super::super::WRITER_QUEUE.lock().contains_key(&key),
                "{fault} stranded ticket"
            );
            drop(held);
            std::fs::remove_file(&lock).unwrap();
            drop(
                store
                    .fixture_exclusive_lock()
                    .expect("successor after refused reopen"),
            );
        }
    }
}
