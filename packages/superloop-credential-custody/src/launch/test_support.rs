//! One resident launch case across all in-process case controls.
static CASE: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn case_guard() -> std::sync::MutexGuard<'static, ()> {
    CASE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// ´test:unit:launch-case-guard-is-shared´
#[test]
fn launch_case_guard_is_shared() {
    let guard = case_guard();
    assert!(matches!(
        CASE.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    drop(guard);
    // Other tests may acquire it first; wait for ownership, never judge speed.
    drop(case_guard());
}
