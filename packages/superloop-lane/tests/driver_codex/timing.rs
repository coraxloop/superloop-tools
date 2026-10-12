use superloop_lane::driver::codex::{
    BudgetMonitor, ClockSample, MonitorDecision, STALL_WINDOW_SECONDS,
    SUSPEND_GAP_THRESHOLD_SECONDS, SuspendDetector,
};

/// Budget is only a reporting threshold.
/// ´test:integration:budget-is-only-a-reporting-threshold´
#[test]
fn budget_is_only_a_reporting_threshold() {
    let mut monitor = BudgetMonitor::new(10, 0, 0);
    assert_eq!(monitor.probe(11, 1), MonitorDecision::Continue);
}

/// Event growth resets only the stall basis.
/// ´test:integration:event-growth-resets-only-the-stall-basis´
#[test]
fn event_growth_resets_only_the_stall_basis() {
    let mut monitor = BudgetMonitor::new(100, 0, 4);
    assert_eq!(monitor.probe(101, 5), MonitorDecision::Continue);
    assert_eq!(monitor.probe(221, 5), MonitorDecision::Continue);
    assert_eq!(monitor.probe(222, 5), MonitorDecision::Stalled);
}

/// An awaited run resets only the stall basis.
/// ´test:integration:an-awaited-run-resets-only-the-stall-basis´
#[test]
fn an_awaited_run_resets_only_the_stall_basis() {
    let mut monitor = BudgetMonitor::new(100, 0, 0);
    monitor.observe_awaited(200);
    assert_eq!(monitor.probe(320, 0), MonitorDecision::Continue);
    assert_eq!(monitor.probe(321, 0), MonitorDecision::Stalled);
}

/// An awaited run never moves the runaway bound.
/// ´test:integration:an-awaited-run-never-moves-the-runaway-bound´
#[test]
fn an_awaited_run_never_moves_the_runaway_bound() {
    let mut monitor = BudgetMonitor::new(10, 0, 0);
    monitor.observe_awaited(41);
    assert_eq!(monitor.probe(41, 0), MonitorDecision::Runaway);
}

/// The stall window restarts when an awaited run lands.
/// ´test:integration:the-stall-window-restarts-when-the-awaited-run-lands´
#[test]
fn the_stall_window_restarts_when_the_awaited_run_lands() {
    let mut monitor = BudgetMonitor::new(5_400, 0, 0);
    assert_eq!(monitor.probe(5_300, 1), MonitorDecision::Continue);
    for now in [5_301, 5_600, 6_000, 6_613] {
        monitor.observe_awaited(now);
        assert_eq!(monitor.probe(now, 1), MonitorDecision::Continue);
    }
    assert_eq!(monitor.probe(6_733, 1), MonitorDecision::Continue);
    assert_eq!(monitor.probe(6_734, 1), MonitorDecision::Stalled);
}

/// Stall bounds are strict.
/// ´test:integration:stall-bounds-are-strict´
#[test]
fn stall_bounds_are_strict() {
    let mut monitor = BudgetMonitor::new(200, 0, 0);
    assert_eq!(monitor.probe(200, 0), MonitorDecision::Continue);
    assert_eq!(monitor.probe(201, 0), MonitorDecision::Stalled);
}

/// The runaway bound is strict.
/// ´test:integration:runaway-bound-is-strict´
#[test]
fn runaway_bound_is_strict() {
    let mut monitor = BudgetMonitor::new(10, 0, 0);
    assert_eq!(monitor.probe(40, 1), MonitorDecision::Continue);
    assert_eq!(monitor.probe(41, 2), MonitorDecision::Runaway);
}

/// Stall takes priority when both kill bounds cross.
/// ´test:integration:stall-takes-priority-when-both-kill-bounds-cross´
#[test]
fn stall_takes_priority_when_both_kill_bounds_cross() {
    let mut monitor = BudgetMonitor::new(10, 0, 0);
    assert_eq!(monitor.probe(121, 0), MonitorDecision::Stalled);
}

/// A monitor stop is always above the budget.
/// ´test:integration:a-monitor-stop-is-always-above-the-budget´
#[test]
fn a_monitor_stop_is_always_above_the_budget() {
    // Both bounds are read past the budget, so a child the monitor stops has
    // always spent more than its threshold. A finished child reaped at one of
    // them is therefore reported over budget, never `ok`, and the successful
    // classification it earns is the one a natural exit at that wall earns.
    let budget = 10;
    for now in [0, 1, 9, 10, 11, 40, 41, 130, 131, 1_000] {
        let mut monitor = BudgetMonitor::new(budget, 0, 0);
        if monitor.probe(now, 0) != MonitorDecision::Continue {
            assert!(now > budget, "a stop at {now} is within the budget");
        }
    }
}

/// Growth decides nothing once the region carries a result.
/// ´test:integration:growth-decides-nothing-once-the-region-carries-a-result´
#[test]
fn growth_decides_nothing_once_the_region_carries_a_result() {
    // A child that published its result and then idled looks exactly like one
    // that hung: the same quiet window, the same decision. Only the region can
    // tell the two apart, which is why the driver reads it before classifying.
    let mut hung = BudgetMonitor::new(100, 0, 0);
    let mut finished = BudgetMonitor::new(100, 0, 0);

    assert_eq!(hung.probe(101, 0), MonitorDecision::Continue);
    assert_eq!(finished.probe(101, 4_096), MonitorDecision::Continue);
    assert_eq!(hung.probe(222, 0), MonitorDecision::Stalled);
    assert_eq!(finished.probe(222, 4_096), MonitorDecision::Stalled);
}

/// Boot time elapsed includes suspend.
/// ´test:integration:boottime-elapsed-includes-suspend´
#[test]
fn boottime_elapsed_includes_suspend() {
    let started = ClockSample::new(40, 4_000);
    let resumed = ClockSample::new(42, 4_011);
    assert_eq!(resumed.boottime_elapsed_since(started), 11);
}

/// The suspend divergence threshold is strict.
/// ´test:integration:suspend-divergence-threshold-is-strict´
#[test]
fn suspend_divergence_threshold_is_strict() {
    let started = ClockSample::new(40, 4_000);
    let detector = SuspendDetector::new(started);
    let threshold = SUSPEND_GAP_THRESHOLD_SECONDS;
    assert_eq!(detector.gap(ClockSample::new(42, 4_002 + threshold)), 0);
    assert_eq!(
        detector.gap(ClockSample::new(42, 4_003 + threshold)),
        threshold + 1
    );
}

/// A suspend longer than the stall window does not kill.
/// ´test:integration:a-suspend-longer-than-the-stall-window-does-not-kill´
#[test]
fn a_suspend_longer_than_the_stall_window_does_not_kill() {
    let started = ClockSample::new(40, 4_000);
    let detector = SuspendDetector::new(started);
    let sleep = 10 * STALL_WINDOW_SECONDS;
    let woken = ClockSample::new(41, 4_001 + sleep);
    assert_eq!(detector.gap(woken), sleep);
    let mut monitor = BudgetMonitor::new(10, 0, 0);
    assert_eq!(
        monitor.probe(woken.awake_elapsed_since(started), 0),
        MonitorDecision::Continue
    );
}
