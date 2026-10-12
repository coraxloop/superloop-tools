//! # `superloop-pack` subprocess contract matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Control paths | 2 | Help and usage end in one status-matching agent-text report |

use std::process::{Command, Output};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_superloop-pack"))
}

fn report_count(output: &Output) -> usize {
    output
        .stdout
        .windows(b"RUN-REPORT".len())
        .filter(|window| *window == b"RUN-REPORT")
        .count()
}

/// ´test:integration:help-is-agent-text-success-with-one-terminal-report´
#[test]
fn help_is_agent_text_success_with_one_terminal_report() {
    let output = command().arg("--help").output().expect("help subprocess");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output
            .stdout
            .starts_with(b"Build and verify provenance-bound")
    );
    assert!(output.stdout.ends_with(b"verdict=ok\n"));
    assert_eq!(report_count(&output), 1);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("stage-verify"));
    let old_form = command().arg("verify").output().expect("retired form");
    assert_eq!(old_form.status.code(), Some(2));
}

/// ´test:integration:usage-refusal-is-path-free-and-status-matched´
#[test]
fn usage_refusal_is_path_free_and_status_matched() {
    let output = command()
        .arg("--unknown=SHOULD_NOT_APPEAR")
        .output()
        .expect("usage subprocess");
    let text = String::from_utf8(output.stdout).expect("UTF-8 usage report");

    assert_eq!(output.status.code(), Some(2));
    assert!(text.starts_with("superloop-pack: usage_error:"));
    assert!(!text.contains("SHOULD_NOT_APPEAR"));
    assert!(text.ends_with("verdict=FAILED\n"));
    assert_eq!(text.matches("RUN-REPORT").count(), 1);
    assert_eq!(output.stderr, [] as [u8; 0]);
}
