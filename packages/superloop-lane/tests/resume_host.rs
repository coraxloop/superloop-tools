//! Public resumed-launch acceptance with production mail custody.
#[path = "support/resume_host_driver.rs"]
pub mod driver;
#[path = "../../loop-home/tests/reply_custody.rs"]
pub mod fixture;
#[path = "support/resume_host_fixture.rs"]
pub mod host;
#[path = "support/resume_host_install.rs"]
pub mod install;
#[path = "support/resume_host_scope.rs"]
pub mod scope;
use std::io::Write as _;

const PREVIEW: &str = "public_resumed_preview_uses_canonical_custody";

/// ´test:integration:public-resumed-preview-uses-canonical-custody´
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

/// ´test:integration:public-resumed-launch-uses-real-work-scope´
fn public_resumed_launch_uses_real_work_scope() {
    scope::run("success");
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
    let tests: [(&str, fn()); 2] = [
        (PREVIEW, public_resumed_preview_uses_canonical_custody),
        (
            "public_resumed_launch_uses_real_work_scope",
            public_resumed_launch_uses_real_work_scope,
        ),
    ];
    let mut passed = 0;
    for (name, test) in tests {
        if !selection.selected_for(name) {
            continue;
        }
        if selection.list {
            writeln!(std::io::stdout().lock(), "{name}: test").expect("list");
        } else {
            test();
            passed += 1;
            writeln!(std::io::stdout().lock(), "test {name} ... ok").expect("result");
        }
    }
    if !selection.list {
        writeln!(
            std::io::stdout().lock(),
            "test result: ok. {passed} passed; 0 failed; 0 ignored; {} filtered out",
            2 - passed
        )
        .expect("summary");
    }
    std::process::ExitCode::SUCCESS
}
