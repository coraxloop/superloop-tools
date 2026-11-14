//! A door-only projection view scoped to one thread's held request lock.
use std::cell::RefCell;
use std::sync::{Arc, Mutex, Weak};

use request_core::Collection;

type Key = (u64, u64);
struct Slot {
    key: Key,
    active: bool,
    collection: Option<Arc<Collection>>,
}
thread_local! {
    static ACTIVE: RefCell<Vec<Weak<Mutex<Slot>>>> = const { RefCell::new(Vec::new()) };
}

/// Moving the guard cannot move the thread-local view. Dropping it anywhere
/// invalidates the original thread's slot before the file lock is released.
pub(super) struct Guard(Arc<Mutex<Slot>>);
impl std::fmt::Debug for Guard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectionView")
            .finish_non_exhaustive()
    }
}

impl Guard {
    pub(super) fn acquired(key: Key) -> Self {
        let slot = Arc::new(Mutex::new(Slot {
            key,
            active: true,
            collection: None,
        }));
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            active.retain(|slot| slot.strong_count() != 0);
            active.push(Arc::downgrade(&slot));
        });
        Self(slot)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.active = false;
        slot.collection = None;
    }
}

fn current(key: Key) -> Option<Arc<Mutex<Slot>>> {
    ACTIVE.with(|active| {
        active.borrow().iter().rev().find_map(|weak| {
            let slot = weak.upgrade()?;
            let matches = {
                let value = slot.lock().ok()?;
                value.active && value.key == key
            };
            matches.then_some(slot)
        })
    })
}

pub(super) fn get(key: Key) -> Option<Arc<Collection>> {
    current(key)?.lock().ok()?.collection.clone()
}

pub(super) fn replace(key: Key, collection: Option<Arc<Collection>>) {
    if let Some(slot) = current(key)
        && let Ok(mut slot) = slot.lock()
    {
        slot.collection = collection;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:collection-view-ends-with-its-hold-and-tracks-commits´
    #[test]
    fn collection_view_ends_with_its_hold_and_tracks_commits() {
        let key = (1, 1);
        let guard = Guard::acquired(key);
        assert!(get(key).is_none());
        let first = Arc::new(Collection::default());
        replace(key, Some(first.clone()));
        assert!(Arc::ptr_eq(&get(key).expect("first view"), &first));
        let next = Arc::new(Collection {
            revision: 2,
            ..Collection::default()
        });
        replace(key, Some(next.clone()));
        assert!(Arc::ptr_eq(&get(key).expect("committed view"), &next));
        drop(guard);
        assert!(get(key).is_none(), "released view must not escape its hold");
        let _next = Guard::acquired(key);
        assert!(get(key).is_none(), "a new hold must read the owner again");
    }

    /// ´test:unit:collection-view-is-separate-for-shared-holds-and-threads´
    #[test]
    fn collection_view_is_separate_for_shared_holds_and_threads() {
        let key = (2, 2);
        let first = Guard::acquired(key);
        replace(key, Some(Arc::new(Collection::default())));
        let other = Guard::acquired((2, 3));
        assert!(get((2, 3)).is_none(), "another lock has no view");
        assert_eq!(get(key).expect("first lock retained").revision, 0);
        drop(other);
        let second = Guard::acquired(key);
        assert!(get(key).is_none(), "each shared hold starts empty");
        replace(
            key,
            Some(Arc::new(Collection {
                revision: 7,
                ..Collection::default()
            })),
        );
        drop(second);
        assert_eq!(get(key).expect("first hold retained").revision, 0);
        std::thread::spawn(move || {
            assert!(get(key).is_none(), "a moved guard carries no view");
            drop(first);
        })
        .join()
        .expect("guard drop on another thread");
        assert!(get(key).is_none(), "cross-thread drop retires the view");
    }
}
