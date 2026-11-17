//! Serialize retained admissions, stores and child cases, not pure parsers or small pipe controls.
static CASE: std::sync::Mutex<()> = std::sync::Mutex::new(());
thread_local! { static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
pub(super) struct CaseGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}
impl Drop for CaseGuard {
    fn drop(&mut self) {
        HELD.with(|held| held.set(false));
    }
}
pub(super) fn case_guard() -> CaseGuard {
    assert!(!HELD.with(std::cell::Cell::get), "nested case guard");
    let _threads = crate::process::test_threads();
    let lock = CASE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    HELD.with(|held| held.set(true));
    CaseGuard { _lock: lock }
}
pub(super) fn assert_owned() {
    assert!(
        HELD.with(std::cell::Cell::get),
        "case construction requires its thread's guard"
    );
}
/// ´test:unit:launch-case-guard-is-shared´
#[test]
fn launch_case_guard_is_shared() {
    let guard = case_guard();
    assert_owned();
    assert!(matches!(
        CASE.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    drop(guard);
    assert!(std::panic::catch_unwind(assert_owned).is_err());
    drop(case_guard());
}
/// ´test:unit:launch-admission-refuses-unguarded-case-construction´
#[test]
fn launch_admission_refuses_unguarded_case_construction() {
    let unguarded = std::panic::catch_unwind(|| {
        super::measure::admit_for_owner(b"{}", nix::unistd::geteuid().as_raw())
    });
    assert!(unguarded.is_err());
    let _guard = case_guard();
    assert!(super::measure::admit_for_owner(b"{}", nix::unistd::geteuid().as_raw()).is_err());
}

/// ´test:unit:retained-case-constructors-check-their-own-guard´
#[test]
fn retained_case_constructors_check_their_own_guard() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let _guard = case_guard();
    let fixture = super::tests::Fixture::new();
    let admission = fixture.admit();
    let mut store = super::store::Store::reserve(&admission, 0).unwrap();
    let (left, _left_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let (right, _right_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    // Keep the mutex locked, so this negative control does not itself exceed
    // the case budget. An invalid index stops each mutant before child effects.
    HELD.with(|held| held.set(false));
    let reserved = catch_unwind(|| super::store::Store::reserve(&admission, usize::MAX));
    let prepared = catch_unwind(AssertUnwindSafe(|| {
        super::keeper::Keeper::prepare(
            super::startup::RootStartup::test_owner(),
            &admission,
            usize::MAX,
            &mut store,
        )
        .map(|_| ())
    }));
    let started = catch_unwind(AssertUnwindSafe(|| {
        super::sealer::Session::start(&admission, usize::MAX, &mut store, [left, right]).map(|_| ())
    }));
    HELD.with(|held| held.set(true));
    assert!(reserved.is_err(), "store skipped its guard");
    assert!(prepared.is_err(), "keeper skipped its guard");
    assert!(started.is_err(), "session skipped its guard");
}
