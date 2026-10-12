//! A small pool of threads for work over many files, so the number of files
//! read or written at once never grows with the number of files.

use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

/// The most transcript or output files scanned at once.
pub const SCAN_THREADS: usize = 16;

/// The most pages rendered at once, each holding its records' cut text.
pub const RENDER_THREADS: usize = 8;

/// Runs `work` over `0..count` on at most `limit` threads, never more than the
/// machine offers, and returns the results in index order; every index runs
/// whatever the others return.
pub fn run<T: Send>(count: usize, limit: usize, work: &(impl Fn(usize) -> T + Sync)) -> Vec<T> {
    let workers = thread::available_parallelism()
        .map_or(4, NonZero::get)
        .min(limit)
        .min(count)
        .max(1);
    let next = AtomicUsize::new(0);
    let done = Mutex::new(Vec::with_capacity(count));
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    let result = work(index);
                    done.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((index, result));
                }
            });
        }
    });
    let mut done = done.into_inner().unwrap_or_else(PoisonError::into_inner);
    done.sort_by_key(|(index, _)| *index);
    done.into_iter().map(|(_, result)| result).collect()
}
