//! Public resumed-launch acceptance with production mail custody.
#[path = "support/resume_host_driver.rs"]
pub mod driver;
#[path = "../../loop-home/tests/reply_custody.rs"]
pub mod fixture;
#[path = "support/resume_host_fixture.rs"]
pub mod host;
#[path = "support/resume_host_install.rs"]
pub mod install;
#[path = "support/resume_host_refusals.rs"]
pub mod refusals;
#[path = "support/resume_host_retained.rs"]
pub mod retained;
#[path = "support/resume_host_scope.rs"]
pub mod scope;
use std::io::Write as _;

const PREVIEW: &str = "public_resumed_preview_uses_canonical_custody";

fn public_resumed_preview_uses_canonical_custody() {
    let fixture = host::Host::new();
    let before = fixture.reservation();
    let inventory = fixture.inventory();
    let report = fixture
        .launch(true)
        .expect("authentic public helper preflight");
    assert_eq!(report["helper_preflight"]["state"], "passed", "{report}");
    assert_eq!(report["helper_preflight"]["helper_started"], false);
    assert_eq!(report["helper_preflight"]["credential_published"], false);
    assert_eq!(report["changed"], false);
    assert_eq!(
        fixture.helper_preflights(),
        1,
        "real private helper preflight executed"
    );
    assert_eq!(
        fixture.reservation(),
        before,
        "preview preserves raw reservation"
    );
    assert_eq!(fixture.inventory(), inventory, "preview publishes nothing");
}

fn public_resumed_launch_uses_real_work_scope() {
    scope::run("success");
}

fn public_resumed_inspector_refusal_restores_and_retries() {
    for history in ["reply", "failed"] {
        scope::run(&format!("inspector:{history}"));
    }
}

fn public_resumed_helper_pin_refusal_restores_and_retries() {
    for history in ["reply", "failed"] {
        scope::run(&format!("helper-pin:{history}"));
    }
}

fn public_resumed_stale_socket_refusal_restores_and_retries() {
    for history in ["reply", "failed"] {
        scope::run(&format!("stale-socket:{history}"));
    }
}

fn public_resumed_credential_thread_start_refusal_restores_and_retries() {
    for history in ["reply", "failed"] {
        scope::run(&format!("credential:{history}"));
    }
}

fn public_resumed_helper_readiness_refusal_restores_and_retries() {
    for history in ["reply", "failed"] {
        scope::run(&format!("readiness:{history}"));
    }
}

fn public_resumed_rollback_retains_live_work_process() {
    scope::run("retained-live-process");
}

fn public_resumed_rollback_retains_changed_request() {
    scope::run("retained-changed-request");
}

fn public_resumed_rollback_retains_dispatch_intent() {
    scope::run("retained-intent");
}

fn main() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|s| s == "--fixture-scope") {
        return scope::child(&args[1..]);
    }
    if args.first().is_some_and(|s| s == "--fixture-driver") {
        return driver::child(&args[1..]);
    }
    if std::env::var_os("LOOP_HOME_REPLY_PHASE").is_some()
        || args.first().is_some_and(|a| a.starts_with("_mail-worker-"))
    {
        return fixture::main();
    }
    let selection = fixture::TestArguments::parse(&std::env::args_os().skip(1).collect::<Vec<_>>())
        .expect("supported test selection");
    let tests = cases();
    let mut passed = 0;
    let mut failed = 0;
    for (name, test) in tests {
        if !selection.selected_for(name) {
            continue;
        }
        let began = std::time::Instant::now();
        if selection.list {
            writeln!(std::io::stdout().lock(), "{name}: test").expect("list");
        } else if std::panic::catch_unwind(test).is_ok() {
            passed += 1;
            writeln!(std::io::stdout().lock(), "test {name} ... ok").expect("result");
        } else {
            failed += 1;
            writeln!(std::io::stdout().lock(), "test {name} ... FAILED").expect("result");
        }
        if !selection.list {
            writeln!(
                std::io::stdout().lock(),
                "CASE-WALL {name} wall_seconds={:.3}",
                began.elapsed().as_secs_f64()
            )
            .expect("case timing");
        }
    }
    if !selection.list {
        writeln!(
            std::io::stdout().lock(),
            "test result: {}. {passed} passed; {failed} failed; 0 ignored; {} filtered out",
            if failed == 0 { "ok" } else { "FAILED" },
            10 - passed - failed
        )
        .expect("summary");
    }
    if failed == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

fn cases() -> [(&'static str, fn()); 10] {
    [
        (
            "public_resumed_inspector_refusal_restores_and_retries",
            public_resumed_inspector_refusal_restores_and_retries,
        ),
        (
            "public_resumed_helper_pin_refusal_restores_and_retries",
            public_resumed_helper_pin_refusal_restores_and_retries,
        ),
        (
            "public_resumed_stale_socket_refusal_restores_and_retries",
            public_resumed_stale_socket_refusal_restores_and_retries,
        ),
        (
            "public_resumed_credential_thread_start_refusal_restores_and_retries",
            public_resumed_credential_thread_start_refusal_restores_and_retries,
        ),
        (
            "public_resumed_helper_readiness_refusal_restores_and_retries",
            public_resumed_helper_readiness_refusal_restores_and_retries,
        ),
        (
            "public_resumed_rollback_retains_live_work_process",
            public_resumed_rollback_retains_live_work_process,
        ),
        (
            "public_resumed_rollback_retains_changed_request",
            public_resumed_rollback_retains_changed_request,
        ),
        (
            "public_resumed_rollback_retains_dispatch_intent",
            public_resumed_rollback_retains_dispatch_intent,
        ),
        (PREVIEW, public_resumed_preview_uses_canonical_custody),
        (
            "public_resumed_launch_uses_real_work_scope",
            public_resumed_launch_uses_real_work_scope,
        ),
    ]
}
