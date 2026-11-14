//! Public resumed-launch acceptance with production mail custody.
#[path = "../../loop-home/tests/reply_custody.rs"]
pub mod fixture;
#[path = "support/resume_host_fixture.rs"]
pub mod host;
#[path = "support/resume_host_install.rs"]
pub mod install;
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

fn main() -> std::process::ExitCode {
    if std::env::var_os("LOOP_HOME_REPLY_PHASE").is_some()
        || std::env::args()
            .nth(1)
            .is_some_and(|a| a.starts_with("_mail-worker-"))
    {
        return fixture::main();
    }
    let selection = fixture::TestArguments::parse(&std::env::args_os().skip(1).collect::<Vec<_>>())
        .expect("supported test selection");
    let selected = selection.selected_for(PREVIEW);
    if selection.list {
        if selected {
            writeln!(std::io::stdout().lock(), "{PREVIEW}: test").expect("test list");
        }
        return std::process::ExitCode::SUCCESS;
    }
    if selected {
        public_resumed_preview_uses_canonical_custody();
        writeln!(std::io::stdout().lock(), "test {PREVIEW} ... ok").expect("result");
    }
    writeln!(
        std::io::stdout().lock(),
        "test result: ok. {} passed; 0 failed; 0 ignored; {} filtered out",
        usize::from(selected),
        usize::from(!selected)
    )
    .expect("summary");
    std::process::ExitCode::SUCCESS
}
