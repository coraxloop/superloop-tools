//! # `worker-monitor` library test matrix
//!
//! | Matrix | Contract |
//! |---|---|
//! | Argument parsing | Cap, bounce, and wait spellings, shared integer grammar, defaults, and refusals |
//! | State documents | Lock and monitor parsing, missing evidence, liveness, and bounded wait |
//! | Delta documents | JSON line parsing, raw fallbacks, suffix selection, and offset acceptance |
//! | Debounce | Quiet age, fresh hold, cap/report preemption, metadata failure, future mtimes, and the heartbeat tail |
//! | Finished documents | Report, optional last message, and combined record ordering |
//! | Offset recovery | Missing, malformed, negative, huge, and regressed state |
//! | Failure boundaries | Partial documents, flush, source/report, and offset publication failures |

use std::cell::Cell;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::symlink;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use super::{
    Config, DEFAULT_BOUNCE, DEFAULT_CAP, FeedError, HEARTBEAT_PROBE, ParsedInteger, PollResult,
    StoredOffset, delta_is_ready, emit_failure_document, line_is_heartbeat, parse_args,
    parse_integer, parse_lock, parse_monitor, parse_utc_instant, poll_once, poll_once_at,
    read_offset, run, sample_state, tail_is_heartbeat, unread_tail_is_heartbeat, utc_instant,
};

#[path = "../../../../tests/driver_follow/support/mod.rs"]
pub mod support;

use support::TestDir;

fn config(directory: &TestDir, cap: u64) -> Config {
    Config {
        run_dir: directory.path().to_path_buf(),
        cap,
        bounce: 0,
        wait: 0,
        save_offset: true,
    }
}

fn bouncing_config(directory: &TestDir, cap: u64, bounce: u64) -> Config {
    Config {
        run_dir: directory.path().to_path_buf(),
        cap,
        bounce,
        wait: 0,
        save_offset: true,
    }
}

fn poll(directory: &TestDir, cap: u64) -> (Result<PollResult, FeedError>, Vec<u8>) {
    let mut output = Vec::new();
    let result = poll_once(&config(directory, cap), &mut output);
    (result, output)
}

fn poll_at(
    directory: &TestDir,
    cap: u64,
    bounce: u64,
    now: SystemTime,
) -> (Result<PollResult, FeedError>, Vec<u8>) {
    let mut output = Vec::new();
    let result = poll_once_at(&bouncing_config(directory, cap, bounce), &mut output, now);
    (result, output)
}

fn document(output: &[u8]) -> Value {
    let parsed: Value = serde_json::from_slice(output).expect("valid JSON document");
    assert_eq!(parsed["schema"], 2);
    assert_ne!(
        parsed["records"]
            .as_array()
            .expect("records array")
            .as_slice(),
        &[] as &[Value]
    );
    parsed
}

fn only_record(output: &[u8]) -> Value {
    let parsed = document(output);
    let records = parsed["records"].as_array().expect("records array");
    if records[0]["kind"] == "state" {
        assert_eq!(records.len(), 2);
        records[1].clone()
    } else {
        assert_eq!(records.len(), 1);
        records[0].clone()
    }
}

/// ´test:unit:arguments-default-to-cap-and-thirty-second-bounce´
#[test]
fn arguments_default_to_cap_and_thirty_second_bounce() {
    let directory = TestDir::new("args-default");
    let parsed = parse_args([directory.path().as_os_str()]).expect("valid run directory");

    assert_eq!(parsed.run_dir, directory.path());
    assert_eq!(parsed.cap, DEFAULT_CAP);
    assert_eq!(parsed.bounce, DEFAULT_BOUNCE);
    assert_eq!(parsed.wait, 0);
}

/// ´test:unit:arguments-accept-both-cap-spellings´
#[test]
fn arguments_accept_both_cap_spellings() {
    let directory = TestDir::new("args-cap-spellings");
    let separated = parse_args([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--cap"),
        OsString::from("17"),
    ])
    .expect("separated cap");
    let joined = parse_args([
        OsString::from("--cap=23"),
        directory.path().as_os_str().to_os_string(),
    ])
    .expect("joined cap");

    assert_eq!(separated.cap, 17);
    assert_eq!(joined.cap, 23);
}

/// ´test:unit:arguments-accept-both-bounce-spellings´
#[test]
fn arguments_accept_both_bounce_spellings() {
    let directory = TestDir::new("args-bounce-spellings");
    let separated = parse_args([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce"),
        OsString::from("17"),
    ])
    .expect("separated bounce");
    let joined = parse_args([
        OsString::from("--bounce=23"),
        directory.path().as_os_str().to_os_string(),
    ])
    .expect("joined bounce");

    assert_eq!(separated.bounce, 17);
    assert_eq!(joined.bounce, 23);
}

/// ´test:unit:arguments-accept-options-before-or-after-run-directory´
#[test]
fn arguments_accept_options_before_or_after_run_directory() {
    let directory = TestDir::new("args-order");
    let before = parse_args([
        OsString::from("--cap=5"),
        OsString::from("--bounce=7"),
        directory.path().as_os_str().to_os_string(),
    ])
    .expect("options before directory");
    let after = parse_args([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--cap=5"),
        OsString::from("--bounce=7"),
    ])
    .expect("options after directory");

    assert_eq!(before, after);
}

/// ´test:unit:arguments-accept-bounce-zero-for-immediate-mode´
#[test]
fn arguments_accept_bounce_zero_for_immediate_mode() {
    let directory = TestDir::new("args-bounce-zero");
    let parsed = parse_args([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--bounce=0"),
    ])
    .expect("zero bounce");

    assert_eq!(parsed.bounce, 0);
}

/// ´test:unit:cap-accepts-python-integer-grammar´
#[test]
fn cap_accepts_python_integer_grammar() {
    let directory = TestDir::new("args-cap-integers");
    for (text, expected) in [("0", 0), ("-0", 0), ("+7", 7), (" 9 ", 9), ("1_024", 1_024)] {
        let parsed = parse_args([
            directory.path().as_os_str().to_os_string(),
            OsString::from(format!("--cap={text}")),
        ])
        .expect("Python-compatible cap");
        assert_eq!(parsed.cap, expected, "cap spelling {text}");
    }
}

/// ´test:unit:bounce-accepts-the-same-python-integer-grammar-as-cap´
#[test]
fn bounce_accepts_the_same_python_integer_grammar_as_cap() {
    let directory = TestDir::new("args-bounce-integers");
    for (text, expected) in [("0", 0), ("-0", 0), ("+7", 7), (" 9 ", 9), ("1_024", 1_024)] {
        let parsed = parse_args([
            directory.path().as_os_str().to_os_string(),
            OsString::from(format!("--bounce={text}")),
        ])
        .expect("Python-compatible bounce");
        assert_eq!(parsed.bounce, expected, "bounce spelling {text}");
    }
}

/// ´test:unit:arguments-reject-negative-or-malformed-cap´
#[test]
fn arguments_reject_negative_or_malformed_cap() {
    let directory = TestDir::new("args-invalid-cap");
    for text in ["-1", "", "+", "_1", "1_", "1__0", "one"] {
        assert!(
            parse_args([
                directory.path().as_os_str().to_os_string(),
                OsString::from(format!("--cap={text}")),
            ])
            .is_err(),
            "cap spelling {text} must be rejected",
        );
    }
}

/// ´test:unit:arguments-reject-negative-or-malformed-bounce´
#[test]
fn arguments_reject_negative_or_malformed_bounce() {
    let directory = TestDir::new("args-invalid-bounce");
    for text in ["-1", "", "+", "_1", "1_", "1__0", "one"] {
        assert!(
            parse_args([
                directory.path().as_os_str().to_os_string(),
                OsString::from(format!("--bounce={text}")),
            ])
            .is_err(),
            "bounce spelling {text} must be rejected",
        );
    }
}

/// ´test:unit:arguments-reject-missing-option-values´
#[test]
fn arguments_reject_missing_option_values() {
    let directory = TestDir::new("args-missing-value");
    for option in ["--cap", "--bounce"] {
        assert!(
            parse_args([
                directory.path().as_os_str().to_os_string(),
                OsString::from(option),
            ])
            .is_err()
        );
    }
}

/// ´test:unit:arguments-reject-missing-or-nondirectory-run-path´
#[test]
fn arguments_reject_missing_or_nondirectory_run_path() {
    let directory = TestDir::new("args-path");
    directory.write("ordinary-file", b"not a directory");

    assert!(parse_args(Vec::<OsString>::new()).is_err());
    assert!(parse_args([directory.path().join("missing").into_os_string()]).is_err());
    assert!(parse_args([directory.path().join("ordinary-file").into_os_string()]).is_err());
}

/// ´test:unit:arguments-reject-unknown-flags-and-extra-positionals´
#[test]
fn arguments_reject_unknown_flags_and_extra_positionals() {
    let directory = TestDir::new("args-extra");
    assert!(
        parse_args([
            directory.path().as_os_str().to_os_string(),
            OsString::from("--unknown"),
        ])
        .is_err()
    );
    assert!(
        parse_args([
            directory.path().as_os_str().to_os_string(),
            directory.path().as_os_str().to_os_string(),
        ])
        .is_err()
    );
}

/// ´test:unit:arguments-saturate-positive-values-larger-than-the-host-range´
#[test]
fn arguments_saturate_positive_values_larger_than_the_host_range() {
    let directory = TestDir::new("args-huge");
    let parsed = parse_args([
        directory.path().as_os_str().to_os_string(),
        OsString::from("--cap=999999999999999999999999999999999999999"),
        OsString::from("--bounce=999999999999999999999999999999999999999"),
    ])
    .expect("Python accepts arbitrary precision positive integers");

    assert_eq!(parsed.cap, u64::MAX);
    assert_eq!(parsed.bounce, u64::MAX);
}

/// ´test:unit:arguments-accept-a-non-utf8-run-directory´
#[cfg(unix)]
#[test]
fn arguments_accept_a_non_utf8_run_directory() {
    use std::os::unix::ffi::OsStringExt as _;

    let parent = TestDir::new("args-non-utf8");
    let name = OsString::from_vec(vec![b'r', b'u', b'n', 0xff]);
    parent.mkdir(&name);
    let path = parent.path().join(name);
    let parsed = parse_args([path.clone().into_os_string()]).expect("non-UTF-8 directory path");

    assert_eq!(parsed.run_dir, path);
}

/// ´test:unit:plain-delta-is-a-json-document-and-advances-offset´
#[test]
fn plain_delta_is_a_json_document_and_advances_offset() {
    let directory = TestDir::new("delta-plain");
    directory.write("events.jsonl", b"abc\n");

    let (result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(record["kind"], "delta");
    assert_eq!(record["bytes"], 4);
    assert_eq!(record["truncated"], false);
    assert_eq!(record["events"], json!([{ "raw": "abc" }]));
    assert_eq!(directory.read(".feed-offset"), b"4\n");
}

/// ´test:unit:complete-payload-lines-are-parsed-as-json´
#[test]
fn complete_payload_lines_are_parsed_as_json() {
    let directory = TestDir::new("delta-json");
    directory.write("events.jsonl", b"{\"event\":\"one\"}\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["events"], json!([{ "event": "one" }]));
}

/// ´test:unit:event-lines-remain-in-file-order´
#[test]
fn event_lines_remain_in_file_order() {
    let directory = TestDir::new("delta-order");
    directory.write("events.jsonl", b"{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(
        record["events"],
        json!([{ "n": 1 }, { "n": 2 }, { "n": 3 }])
    );
}

/// ´test:unit:unparseable-line-is-represented-in-place-as-raw-text´
#[test]
fn unparseable_line_is_represented_in_place_as_raw_text() {
    let directory = TestDir::new("delta-raw-in-place");
    directory.write("events.jsonl", b"{\"n\":1}\nnot-json\n{\"n\":3}\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(
        record["events"],
        json!([{ "n": 1 }, { "raw": "not-json" }, { "n": 3 }])
    );
}

/// ´test:unit:capped-delta-selects-the-newest-suffix´
#[test]
fn capped_delta_selects_the_newest_suffix() {
    let directory = TestDir::new("delta-cap");
    directory.write("events.jsonl", b"0123456789");

    let (result, output) = poll(&directory, 5);
    let record = only_record(&output);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(record["bytes"], 5);
    assert_eq!(record["truncated"], true);
    assert_eq!(record["events"], json!([56789]));
    assert_eq!(directory.read(".feed-offset"), b"10\n");
}

/// ´test:unit:cap-truncation-can-leave-a-raw-partial-first-line´
#[test]
fn cap_truncation_can_leave_a_raw_partial_first_line() {
    let directory = TestDir::new("delta-cap-partial-line");
    directory.write("events.jsonl", b"discard{\"old\":1}\n{\"new\":2}\n");

    let (_result, output) = poll(&directory, 19);
    let record = only_record(&output);

    assert_eq!(record["truncated"], true);
    assert_eq!(record["events"][1], json!({ "new": 2 }));
    assert!(record["events"][0].get("raw").is_some());
}

/// ´test:unit:zero-cap-emits-an-empty-truncated-delta-for-growth´
#[test]
fn zero_cap_emits_an_empty_truncated_delta_for_growth() {
    let directory = TestDir::new("delta-zero-cap");
    directory.write("events.jsonl", b"growth");

    let (result, output) = poll(&directory, 0);
    let record = only_record(&output);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(record["bytes"], 0);
    assert_eq!(record["truncated"], true);
    assert_eq!(record["events"], json!([]));
    assert_eq!(directory.read(".feed-offset"), b"6\n");
}

/// ´test:unit:delta-starts-at-the-stored-offset´
#[test]
fn delta_starts_at_the_stored_offset() {
    let directory = TestDir::new("delta-offset");
    directory.write("events.jsonl", b"old-new");
    directory.write(".feed-offset", b"4\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["bytes"], 3);
    assert_eq!(record["events"], json!([{ "raw": "new" }]));
    assert_eq!(directory.read(".feed-offset"), b"7\n");
}

/// ´test:unit:delta-byte-count-is-not-a-unicode-character-count´
#[test]
fn delta_byte_count_is_not_a_unicode_character_count() {
    let directory = TestDir::new("delta-byte-count");
    directory.write("events.jsonl", "€".as_bytes());

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["bytes"], 3);
    assert_eq!(record["events"], json!([{ "raw": "€" }]));
}

/// ´test:unit:invalid-utf8-event-text-is-lossily-represented-in-raw-record´
#[test]
fn invalid_utf8_event_text_is_lossily_represented_in_raw_record() {
    let directory = TestDir::new("delta-non-utf8");
    directory.write("events.jsonl", &[0xff, 0x00]);

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["bytes"], 2);
    assert_eq!(record["events"], json!([{ "raw": "�\u{0}" }]));
}

/// ´test:unit:exact-cap-is-not-truncated´
#[test]
fn exact_cap_is_not_truncated() {
    let directory = TestDir::new("delta-exact-cap");
    directory.write("events.jsonl", b"12345");

    let (_result, output) = poll(&directory, 5);
    let record = only_record(&output);

    assert_eq!(record["bytes"], 5);
    assert_eq!(record["truncated"], false);
}

/// ´test:unit:terminal-payload-lf-does-not-create-an-extra-empty-event´
#[test]
fn terminal_payload_lf_does_not_create_an_extra_empty_event() {
    let directory = TestDir::new("delta-terminal-lf");
    directory.write("events.jsonl", b"{\"event\":1}\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["events"].as_array().expect("events array").len(), 1);
}

/// ´test:unit:an-empty-line-inside-the-payload-is-a-raw-event´
#[test]
fn an_empty_line_inside_the_payload_is_a_raw_event() {
    let directory = TestDir::new("delta-empty-line");
    directory.write("events.jsonl", b"{\"event\":1}\n\n{\"event\":2}\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["events"][1], json!({ "raw": "" }));
}

/// ´test:unit:delta-writes-no-run-directory-state-other-than-offset´
#[test]
fn delta_writes_no_run_directory_state_other_than_offset() {
    let directory = TestDir::new("delta-state-scope");
    directory.write("events.jsonl", b"event");
    let before = entry_names(directory.path());

    let (result, _output) = poll(&directory, DEFAULT_CAP);
    let after = entry_names(directory.path());

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(before, [String::from("events.jsonl")]);
    assert_eq!(
        after,
        [String::from(".feed-offset"), String::from("events.jsonl")]
    );
}

fn entry_names(path: &std::path::Path) -> Vec<String> {
    let mut names = std::fs::read_dir(path)
        .expect("read fixture directory")
        .map(|entry| {
            entry
                .expect("read fixture entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// ´test:unit:finished-without-last-message-uses-null´
#[test]
fn finished_without_last_message_uses_null() {
    let directory = TestDir::new("finished-report");
    directory.write("run-report.txt", b"RUN-REPORT exit=0\n");

    let (result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(result, Ok(PollResult::Finished));
    assert_eq!(record["kind"], "finished");
    assert_eq!(record["report"], "RUN-REPORT exit=0\n");
    assert_eq!(record["last_message"], Value::Null);
    assert!(!directory.exists(".feed-offset"));
}

/// ´test:unit:finished-preserves-report-and-last-message-text´
#[test]
fn finished_preserves_report_and_last_message_text() {
    let directory = TestDir::new("finished-last");
    directory.write("run-report.txt", b"REPORT");
    directory.write("last-message.txt", b"LAST\n");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["report"], "REPORT");
    assert_eq!(record["last_message"], "LAST\n");
}

/// ´test:unit:finished-empty-files-remain-empty-strings´
#[test]
fn finished_empty_files_remain_empty_strings() {
    let directory = TestDir::new("finished-empty");
    directory.write("run-report.txt", b"");
    directory.write("last-message.txt", b"");

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["report"], "");
    assert_eq!(record["last_message"], "");
}

/// ´test:unit:non-utf8-finished-payloads-are-lossily-encoded-as-json-text´
#[test]
fn non_utf8_finished_payloads_are_lossily_encoded_as_json_text() {
    let directory = TestDir::new("finished-binary");
    directory.write("run-report.txt", &[0xff, 0x00]);
    directory.write("last-message.txt", &[0xfe, b'\n', 0x01]);

    let (_result, output) = poll(&directory, DEFAULT_CAP);
    let record = only_record(&output);

    assert_eq!(record["report"], "�\u{0}");
    assert_eq!(record["last_message"], "�\n\u{1}");
}

/// ´test:unit:empty-event-source-allows-finished-document´
#[test]
fn empty_event_source_allows_finished_document() {
    let directory = TestDir::new("finished-empty-events");
    directory.write("events.jsonl", b"");
    directory.write("run-report.txt", b"REPORT");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Ok(PollResult::Finished));
    assert_eq!(only_record(&output)["kind"], "finished");
}

/// ´test:unit:absent-completion-is-pending-and-writes-nothing´
#[test]
fn absent_completion_is_pending_and_writes_nothing() {
    let directory = TestDir::new("finished-pending");
    directory.write("events.jsonl", b"");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Ok(PollResult::Pending));
    assert_eq!(output, [] as [u8; 0]);
    assert!(!directory.exists(".feed-offset"));
}

/// ´test:unit:pending-delta-and-settled-report-share-one-document-delta-first´
#[test]
fn pending_delta_and_settled_report_share_one_document_delta_first() {
    let directory = TestDir::new("combined");
    directory.write("events.jsonl", b"{\"event\":1}\n");
    directory.write("run-report.txt", b"REPORT\n");
    directory.write("last-message.txt", b"LAST");

    let (result, output) = poll(&directory, DEFAULT_CAP);
    let parsed = document(&output);
    let records = parsed["records"].as_array().expect("records array");

    assert_eq!(result, Ok(PollResult::DeltaAndFinished));
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["kind"], "state");
    assert_eq!(records[1]["kind"], "delta");
    assert_eq!(records[2]["kind"], "finished");
    assert_eq!(records[2]["report"], "REPORT\n");
    assert_eq!(records[2]["last_message"], "LAST");
    assert_eq!(directory.read(".feed-offset"), b"12\n");
}

/// ´test:unit:bounce-zero-serves-a-fresh-delta-immediately´
#[test]
fn bounce_zero_serves_a_fresh_delta_immediately() {
    let directory = TestDir::new("bounce-zero");
    directory.write("events.jsonl", b"fresh");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    directory.set_modified("events.jsonl", now);

    let (result, output) = poll_at(&directory, DEFAULT_CAP, 0, now);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(only_record(&output)["kind"], "delta");
}

/// ´test:unit:quiet-log-serves-immediately-on-call´
#[test]
fn quiet_log_serves_immediately_on_call() {
    let directory = TestDir::new("bounce-quiet");
    directory.write("events.jsonl", b"quiet");
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    directory.set_modified("events.jsonl", modified);

    let (result, output) = poll_at(
        &directory,
        DEFAULT_CAP,
        30,
        modified + Duration::from_secs(30),
    );

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(only_record(&output)["kind"], "delta");
}

/// ´test:unit:fresh-mtime-holds-then-serves-once-it-ages-past-window´
#[test]
fn fresh_mtime_holds_then_serves_once_it_ages_past_window() {
    let directory = TestDir::new("bounce-aging");
    directory.write("events.jsonl", b"aging");
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
    directory.set_modified("events.jsonl", modified);

    let (held, held_output) = poll_at(
        &directory,
        DEFAULT_CAP,
        30,
        modified + Duration::from_secs(29),
    );
    let (served, served_output) = poll_at(
        &directory,
        DEFAULT_CAP,
        30,
        modified + Duration::from_secs(30),
    );

    assert_eq!(held, Ok(PollResult::Pending));
    assert_eq!(held_output, [] as [u8; 0]);
    assert_eq!(served, Ok(PollResult::Delta));
    assert_eq!(only_record(&served_output)["kind"], "delta");
}

/// ´test:unit:cap-pressure-preempts-a-fresh-mtime´
#[test]
fn cap_pressure_preempts_a_fresh_mtime() {
    let directory = TestDir::new("bounce-cap");
    directory.write("events.jsonl", b"abc");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000);
    directory.set_modified("events.jsonl", now);

    let (result, output) = poll_at(&directory, 3, 30, now);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(only_record(&output)["bytes"], 3);
}

/// ´test:unit:settled-report-preempts-a-fresh-mtime-and-combines-records´
#[test]
fn settled_report_preempts_a_fresh_mtime_and_combines_records() {
    let directory = TestDir::new("bounce-report");
    directory.write("events.jsonl", b"fresh");
    directory.write("run-report.txt", b"DONE");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(4_000);
    directory.set_modified("events.jsonl", now);

    let (result, output) = poll_at(&directory, DEFAULT_CAP, 30, now);
    let parsed = document(&output);

    assert_eq!(result, Ok(PollResult::DeltaAndFinished));
    assert_eq!(parsed["records"][0]["kind"], "state");
    assert_eq!(parsed["records"][1]["kind"], "delta");
    assert_eq!(parsed["records"][2]["kind"], "finished");
}

/// ´test:unit:unreadable-mtime-fails-open´
#[test]
fn unreadable_mtime_fails_open() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(5_000);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(
        1,
        DEFAULT_CAP,
        30,
        false,
        &Err(io::Error::other("injected unreadable mtime")),
        now,
        || {
            probes.set(probes.get() + 1);
            false
        },
    );

    // Metadata that cannot be read is the fifth cheap release, and it is witnessed
    // like the other four: a release that consulted the probe and discarded its
    // answer would pass the release assertion alone while paying the read the
    // ordering exists to avoid.
    assert!(ready);
    assert_eq!(probes.get(), 0);
}

/// ´test:unit:future-mtime-counts-as-age-zero-and-holds´
#[test]
fn future_mtime_counts_as_age_zero_and_holds() {
    let directory = TestDir::new("bounce-future");
    directory.write("events.jsonl", b"future");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(6_000);
    directory.set_modified("events.jsonl", now + Duration::from_secs(60));

    let (result, output) = poll_at(&directory, DEFAULT_CAP, 30, now);

    assert_eq!(result, Ok(PollResult::Pending));
    assert_eq!(output, [] as [u8; 0]);
}

/// ´test:unit:cap-preemption-still-applies-to-a-future-mtime´
#[test]
fn cap_preemption_still_applies_to_a_future_mtime() {
    let directory = TestDir::new("bounce-future-cap");
    directory.write("events.jsonl", b"future");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(7_000);
    directory.set_modified("events.jsonl", now + Duration::from_secs(60));

    let (result, output) = poll_at(&directory, 6, 30, now);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(only_record(&output)["bytes"], 6);
}

/// ´test:unit:bounce-zero-releases-without-consulting-the-heartbeat-probe´
#[test]
fn bounce_zero_releases_without_consulting_the_heartbeat_probe() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(8_000);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(1, DEFAULT_CAP, 0, false, &Ok(now), now, || {
        probes.set(probes.get() + 1);
        false
    });

    assert!(ready);
    assert_eq!(probes.get(), 0);
}

/// ´test:unit:cap-pressure-releases-without-consulting-the-heartbeat-probe´
#[test]
fn cap_pressure_releases_without_consulting_the_heartbeat_probe() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(8_100);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(4, 4, 30, false, &Ok(now), now, || {
        probes.set(probes.get() + 1);
        false
    });

    assert!(ready);
    assert_eq!(probes.get(), 0);
}

/// ´test:unit:a-settled-report-releases-without-consulting-the-heartbeat-probe´
#[test]
fn a_settled_report_releases_without_consulting_the_heartbeat_probe() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(8_200);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(1, DEFAULT_CAP, 30, true, &Ok(now), now, || {
        probes.set(probes.get() + 1);
        false
    });

    assert!(ready);
    assert_eq!(probes.get(), 0);
}

/// ´test:unit:an-aged-modification-time-releases-without-consulting-the-heartbeat-probe´
#[test]
fn an_aged_modification_time_releases_without_consulting_the_heartbeat_probe() {
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(8_300);
    let now = modified + Duration::from_secs(30);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(1, DEFAULT_CAP, 30, false, &Ok(modified), now, || {
        probes.set(probes.get() + 1);
        false
    });

    assert!(ready);
    assert_eq!(probes.get(), 0);
}

/// ´test:unit:a-fresh-hold-consults-the-heartbeat-probe-once-and-releases-on-true´
#[test]
fn a_fresh_hold_consults_the_heartbeat_probe_once_and_releases_on_true() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(8_400);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(1, DEFAULT_CAP, 30, false, &Ok(now), now, || {
        probes.set(probes.get() + 1);
        true
    });

    assert!(ready);
    assert_eq!(probes.get(), 1);
}

/// ´test:unit:a-fresh-hold-consults-the-heartbeat-probe-once-and-holds-on-false´
#[test]
fn a_fresh_hold_consults_the_heartbeat_probe_once_and_holds_on_false() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(8_500);
    let probes = Cell::new(0_u32);

    let ready = delta_is_ready(1, DEFAULT_CAP, 30, false, &Ok(now), now, || {
        probes.set(probes.get() + 1);
        false
    });

    assert!(!ready);
    assert_eq!(probes.get(), 1);
}

const HEARTBEAT_LINE: &str = "{\"type\":\"tool_progress\",\"tool_use_id\":\"toolu-heartbeat-0\",\"tool_name\":\"Bash\",\"parent_tool_use_id\":\"toolu-parent\",\"elapsed_time_seconds\":30,\"heartbeat\":true,\"session_id\":\"session\",\"uuid\":\"uuid\"}";
const ASSISTANT_LINE: &str = "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\"}}";

/// ´test:unit:an-empty-region-has-no-heartbeat-tail´
#[test]
fn an_empty_region_has_no_heartbeat_tail() {
    assert!(!tail_is_heartbeat(b""));
}

/// ´test:unit:a-region-of-one-heartbeat-is-a-heartbeat-tail´
#[test]
fn a_region_of_one_heartbeat_is_a_heartbeat_tail() {
    assert!(tail_is_heartbeat(format!("{HEARTBEAT_LINE}\n").as_bytes()));
}

/// ´test:unit:an-assistant-line-after-a-heartbeat-ends-the-tail´
#[test]
fn an_assistant_line_after_a_heartbeat_ends_the_tail() {
    assert!(!tail_is_heartbeat(
        format!("{HEARTBEAT_LINE}\n{ASSISTANT_LINE}\n").as_bytes()
    ));
}

/// ´test:unit:a-tail-line-that-is-not-json-is-not-a-heartbeat´
#[test]
fn a_tail_line_that_is_not_json_is_not_a_heartbeat() {
    assert!(!tail_is_heartbeat(b"not json at all\n"));
}

/// The probe window in the units a fixture builder counts in.
fn probe_window() -> usize {
    usize::try_from(HEARTBEAT_PROBE).expect("probe window fits a host word")
}

/// ´test:unit:the-heartbeat-probe-window-is-eight-kibibytes´
#[test]
fn the_heartbeat_probe_window_is_eight_kibibytes() {
    // PIN: the literal is the point. Every probe fixture below sizes itself from
    // the constant, so a change to it moves the fixtures with it and leaves all
    // of them passing over a window nobody chose. The number is a claim about
    // event logs — a heartbeat line is a few hundred bytes, so eight kibibytes
    // hold the last complete line of any ordinary one — and a silent change to
    // that claim is what this case refuses.
    assert_eq!(HEARTBEAT_PROBE, 8_192);
}

/// Probe one fixture event source from `offset`, the way a poll does: the file
/// is opened fresh and its sampled size is its current length.
fn heartbeat_probe(directory: &TestDir, offset: u64) -> bool {
    let source_path = directory.path().join("events.jsonl");
    let mut source = File::open(source_path).expect("open fixture event source");
    let size = source.metadata().expect("sample the fixture size").len();
    unread_tail_is_heartbeat(&mut source, offset, size)
}

/// ´test:unit:a-long-region-reads-its-last-complete-line-through-a-torn-window´
#[test]
fn a_long_region_reads_its_last_complete_line_through_a_torn_window() {
    let directory = TestDir::new("probe-long-heartbeat");
    let leader = "f".repeat(2 * probe_window());
    directory.write(
        "events.jsonl",
        format!("{leader}\n{ASSISTANT_LINE}\n{HEARTBEAT_LINE}\n").as_bytes(),
    );

    assert!(heartbeat_probe(&directory, 0));
}

/// ´test:unit:a-long-regions-unterminated-heartbeat-is-not-its-last-complete-line´
#[test]
fn a_long_regions_unterminated_heartbeat_is_not_its_last_complete_line() {
    let directory = TestDir::new("probe-long-torn");
    let leader = "f".repeat(2 * probe_window());
    directory.write(
        "events.jsonl",
        format!("{leader}\n{ASSISTANT_LINE}\n{HEARTBEAT_LINE}").as_bytes(),
    );

    assert!(!heartbeat_probe(&directory, 0));
}

/// ´test:unit:a-probe-window-without-a-line-terminator-reports-no-heartbeat´
#[test]
fn a_probe_window_without_a_line_terminator_reports_no_heartbeat() {
    let directory = TestDir::new("probe-unterminated-window");
    let trailing = "f".repeat(2 * probe_window());
    directory.write(
        "events.jsonl",
        format!("{HEARTBEAT_LINE}\n{trailing}").as_bytes(),
    );

    assert!(!heartbeat_probe(&directory, 0));
}

/// ´test:unit:a-region-of-exactly-the-probe-window-keeps-its-first-line´
#[test]
fn a_region_of_exactly_the_probe_window_keeps_its_first_line() {
    let directory = TestDir::new("probe-exact-window");
    let trailing = "f".repeat(probe_window() - HEARTBEAT_LINE.len() - 1);
    let region = format!("{HEARTBEAT_LINE}\n{trailing}");
    assert_eq!(region.len(), probe_window());
    directory.write("events.jsonl", region.as_bytes());

    assert!(heartbeat_probe(&directory, 0));
}

/// ´test:unit:a-line-at-the-probe-boundary-is-discarded-as-possibly-torn´
#[test]
fn a_line_at_the_probe_boundary_is_discarded_as_possibly_torn() {
    let directory = TestDir::new("probe-boundary-line");
    let trailing = "f".repeat(probe_window() - HEARTBEAT_LINE.len() - 1);
    directory.write(
        "events.jsonl",
        format!("e{HEARTBEAT_LINE}\n{trailing}").as_bytes(),
    );

    assert!(!heartbeat_probe(&directory, 0));
}

/// ´test:unit:a-heartbeat-before-the-probe-window-does-not-decide-a-long-region´
#[test]
fn a_heartbeat_before_the_probe_window_does_not_decide_a_long_region() {
    let directory = TestDir::new("probe-offset-window");
    let accepted = format!("{ASSISTANT_LINE}\n");
    let trailing = "f".repeat(2 * probe_window());
    directory.write(
        "events.jsonl",
        format!("{accepted}{HEARTBEAT_LINE}\n{trailing}").as_bytes(),
    );
    let offset = u64::try_from(accepted.len()).expect("fixture offset fits a file position");

    assert!(!heartbeat_probe(&directory, offset));
}

/// ´test:unit:an-unread-region-inside-the-window-is-probed-from-the-offset´
#[test]
fn an_unread_region_inside_the_window_is_probed_from_the_offset() {
    let directory = TestDir::new("probe-offset-inside-window");
    // An accepted prefix carrying no terminator of its own, so the first line
    // terminator any window can find is the heartbeat's. The unread region fits
    // the probe window while the whole file does not, which is what separates a
    // probe measured from the offset from one measured from the file's size: the
    // second opens inside the accepted prefix and discards the heartbeat's own
    // terminator along with the torn line it lands in.
    let accepted = "f".repeat(probe_window());
    let trailing = "f".repeat(probe_window() / 2);
    let unread = HEARTBEAT_LINE.len() + 1 + trailing.len();
    // Both legs are asserted rather than one left to the fixture's construction:
    // the case separates a probe measured from the offset from one measured from
    // the size only while the unread region fits the window and the whole file
    // does not, and an edit to the accepted prefix that lost the second leg would
    // leave a case still passing on a file the two measurements agree about.
    assert!(unread < probe_window());
    assert!(accepted.len() + unread > probe_window());
    directory.write(
        "events.jsonl",
        format!("{accepted}{HEARTBEAT_LINE}\n{trailing}").as_bytes(),
    );
    let offset = u64::try_from(accepted.len()).expect("fixture offset fits a file position");

    assert!(heartbeat_probe(&directory, offset));
}

/// ´test:unit:a-false-heartbeat-field-is-not-a-heartbeat´
#[test]
fn a_false_heartbeat_field_is_not_a_heartbeat() {
    assert!(!line_is_heartbeat(
        br#"{"type":"tool_progress","heartbeat":false}"#
    ));
}

/// ´test:unit:a-string-heartbeat-field-is-not-a-heartbeat´
#[test]
fn a_string_heartbeat_field_is_not_a_heartbeat() {
    assert!(!line_is_heartbeat(
        br#"{"type":"tool_progress","heartbeat":"true"}"#
    ));
}

/// ´test:unit:a-numeric-heartbeat-field-is-not-a-heartbeat´
#[test]
fn a_numeric_heartbeat_field_is_not_a_heartbeat() {
    assert!(!line_is_heartbeat(
        br#"{"type":"tool_progress","heartbeat":1}"#
    ));
}

/// ´test:unit:a-missing-heartbeat-field-is-not-a-heartbeat´
#[test]
fn a_missing_heartbeat_field_is_not_a_heartbeat() {
    assert!(!line_is_heartbeat(br#"{"type":"tool_progress"}"#));
}

/// ´test:unit:a-heartbeat-flag-on-another-event-type-is-not-a-heartbeat´
#[test]
fn a_heartbeat_flag_on_another_event_type_is_not_a_heartbeat() {
    assert!(!line_is_heartbeat(
        br#"{"type":"assistant","heartbeat":true}"#
    ));
}

/// ´test:unit:missing-offset-recovers-to-zero´
#[test]
fn missing_offset_recovers_to_zero() {
    let directory = TestDir::new("offset-missing");
    assert_eq!(read_offset(directory.path()), StoredOffset::Value(0));
}

/// ´test:unit:malformed-offset-recovers-to-zero´
#[test]
fn malformed_offset_recovers_to_zero() {
    let directory = TestDir::new("offset-malformed");
    for raw in [b"not a number".as_slice(), b"1\n2", &[0xff, 0xfe]] {
        directory.write(".feed-offset", raw);
        assert_eq!(read_offset(directory.path()), StoredOffset::Value(0));
    }
}

/// ´test:unit:negative-offset-recovers-to-zero´
#[test]
fn negative_offset_recovers_to_zero() {
    let directory = TestDir::new("offset-negative");
    directory.write(".feed-offset", b"-7\n");
    directory.write("events.jsonl", b"abc");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(only_record(&output)["bytes"], 3);
}

/// ´test:unit:offset-accepts-python-integer-whitespace-plus-and-underscores´
#[test]
fn offset_accepts_python_integer_whitespace_plus_and_underscores() {
    let directory = TestDir::new("offset-python-int");
    directory.write(".feed-offset", b" +1_0 \n");

    assert_eq!(read_offset(directory.path()), StoredOffset::Value(10));
}

/// ´test:unit:positive-offset-overflow-is-retained-as-out-of-range´
#[test]
fn positive_offset_overflow_is_retained_as_out_of_range() {
    let directory = TestDir::new("offset-overflow");
    directory.write(
        ".feed-offset",
        b"999999999999999999999999999999999999999999\n",
    );

    assert_eq!(
        read_offset(directory.path()),
        StoredOffset::PositiveOverflow
    );
}

/// ´test:unit:offset-beyond-sampled-size-is-evidence-continuity-failure´
#[test]
fn offset_beyond_sampled_size_is_evidence_continuity_failure() {
    let directory = TestDir::new("offset-regression");
    directory.write("events.jsonl", b"abc");
    directory.write(".feed-offset", b"9\n");
    directory.write("run-report.txt", b"DONE\n");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Err(FeedError::EvidenceContinuity));
    assert_eq!(output, [] as [u8; 0]);
    assert_eq!(directory.read(".feed-offset"), b"9\n");
}

/// ´test:unit:positive-offset-with-missing-event-source-is-continuity-failure´
#[test]
fn positive_offset_with_missing_event_source_is_continuity_failure() {
    let directory = TestDir::new("offset-missing-source");
    directory.write(".feed-offset", b"1\n");
    directory.write("run-report.txt", b"DONE\n");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Err(FeedError::EvidenceContinuity));
    assert_eq!(output, [] as [u8; 0]);
}

struct BoundaryWriter {
    accepted: Vec<u8>,
    limit: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}

impl BoundaryWriter {
    fn bounded(limit: usize) -> Self {
        Self {
            accepted: Vec::new(),
            limit: Some(limit),
            fail_flush: false,
            flushes: 0,
        }
    }

    fn failing_flush() -> Self {
        Self {
            accepted: Vec::new(),
            limit: None,
            fail_flush: true,
            flushes: 0,
        }
    }
}

impl Write for BoundaryWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(limit) = self.limit else {
            self.accepted.extend_from_slice(bytes);
            return Ok(bytes.len());
        };
        if self.accepted.len() == limit {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected relay boundary",
            ));
        }
        let accepted = bytes.len().min(limit - self.accepted.len());
        self.accepted.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected flush boundary",
            ))
        } else {
            Ok(())
        }
    }
}

/// ´test:unit:relay-failure-preserves-the-document-prefix-and-prior-offset´
#[test]
fn relay_failure_preserves_the_document_prefix_and_prior_offset() {
    let directory = TestDir::new("failure-partial");
    directory.write("events.jsonl", b"abcdef");
    directory.write(".feed-offset", b"1\n");
    let mut writer = BoundaryWriter::bounded(12);

    let result = poll_once(&config(&directory, DEFAULT_CAP), &mut writer);

    assert_eq!(result, Err(FeedError::Relay));
    assert_eq!(writer.accepted.len(), 12);
    assert_eq!(directory.read(".feed-offset"), b"1\n");
}

/// ´test:unit:relay-failure-on-flush-retains-prior-offset´
#[test]
fn relay_failure_on_flush_retains_prior_offset() {
    let directory = TestDir::new("failure-flush");
    directory.write("events.jsonl", b"abcdef");
    directory.write(".feed-offset", b"2\n");
    let mut writer = BoundaryWriter::failing_flush();

    let result = poll_once(&config(&directory, DEFAULT_CAP), &mut writer);

    assert_eq!(result, Err(FeedError::Relay));
    let _parsed = document(&writer.accepted);
    assert_eq!(writer.flushes, 1);
    assert_eq!(directory.read(".feed-offset"), b"2\n");
}

/// ´test:unit:successful-delta-flushes-once-before-offset-advance´
#[test]
fn successful_delta_flushes_once_before_offset_advance() {
    let directory = TestDir::new("failure-successful-flush");
    directory.write("events.jsonl", b"abc");
    let mut writer = BoundaryWriter {
        accepted: Vec::new(),
        limit: None,
        fail_flush: false,
        flushes: 0,
    };

    let result = poll_once(&config(&directory, DEFAULT_CAP), &mut writer);

    assert_eq!(result, Ok(PollResult::Delta));
    assert_eq!(writer.flushes, 1);
    assert_eq!(directory.read(".feed-offset"), b"3\n");
}

/// ´test:unit:offset-target-failure-is-detected-before-document-publication´
#[test]
fn offset_target_failure_is_detected_before_document_publication() {
    let directory = TestDir::new("failure-offset-state");
    directory.write("events.jsonl", b"abc");
    directory.mkdir(".feed-offset");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Err(FeedError::OffsetState));
    assert_eq!(output, [] as [u8; 0]);
    assert!(directory.path().join(".feed-offset").is_dir());
}

/// ´test:unit:event-source-directory-is-a-pre-relay-failure´
#[test]
fn event_source_directory_is_a_pre_relay_failure() {
    let directory = TestDir::new("failure-event-source");
    directory.mkdir("events.jsonl");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Err(FeedError::EventSource));
    assert_eq!(output, [] as [u8; 0]);
}

/// ´test:unit:report-directory-is-a-pre-relay-failure´
#[test]
fn report_directory_is_a_pre_relay_failure() {
    let directory = TestDir::new("failure-report");
    directory.mkdir("run-report.txt");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Err(FeedError::ReportRead));
    assert_eq!(output, [] as [u8; 0]);
}

/// ´test:unit:last-message-directory-is-a-pre-relay-failure´
#[test]
fn last_message_directory_is_a_pre_relay_failure() {
    let directory = TestDir::new("failure-last-message");
    directory.write("run-report.txt", b"REPORT\n");
    directory.mkdir("last-message.txt");

    let (result, output) = poll(&directory, DEFAULT_CAP);

    assert_eq!(result, Err(FeedError::LastMessageRead));
    assert_eq!(output, [] as [u8; 0]);
}

/// ´test:unit:failure-document-is-valid-json-with-one-record´
#[test]
fn failure_document_is_valid_json_with_one_record() {
    let mut output = Vec::new();

    emit_failure_document(
        &mut output,
        FeedError::EventRead.kind(),
        FeedError::EventRead.diagnostic(),
    )
    .expect("failure document");
    let record = only_record(&output);

    assert_eq!(record["kind"], "event_read_failure");
    assert_eq!(record["message"], FeedError::EventRead.diagnostic());
}

/// ´test:unit:integer-parser-distinguishes-negative-overflow-and-value´
#[test]
fn integer_parser_distinguishes_negative_overflow_and_value() {
    assert_eq!(parse_integer("-1"), Some(ParsedInteger::Negative));
    assert_eq!(parse_integer("42"), Some(ParsedInteger::Value(42)));
    assert_eq!(
        parse_integer("999999999999999999999999999999999999"),
        Some(ParsedInteger::PositiveOverflow)
    );
    assert_eq!(parse_integer("malformed"), None);
}

/// ´test:unit:every-runtime-diagnostic-has-one-stable-class-and-no-path´
#[test]
fn every_runtime_diagnostic_has_one_stable_class_and_no_path() {
    let classes = [
        (FeedError::EventSource, "event_source_failure"),
        (FeedError::EvidenceContinuity, "evidence_continuity_failure"),
        (FeedError::EventRead, "event_read_failure"),
        (FeedError::ReportRead, "report_read_failure"),
        (FeedError::LastMessageRead, "last_message_read_failure"),
        (FeedError::Relay, "relay_failure"),
        (FeedError::OffsetState, "offset_state_failure"),
    ];

    for (error, class) in classes {
        let diagnostic = error.diagnostic();
        assert!(diagnostic.starts_with("superloop-lane: "));
        assert_eq!(error.kind(), class);
        assert!(diagnostic.contains(class));
        assert!(diagnostic.ends_with('\n'));
        assert_eq!(diagnostic.lines().count(), 1);
        assert!(!diagnostic.contains('/'));
    }
}

/// ´test:unit:display-uses-the-classed-diagnostic-without-its-lf´
#[test]
fn display_uses_the_classed_diagnostic_without_its_lf() {
    assert_eq!(
        FeedError::EvidenceContinuity.to_string(),
        "superloop-lane: evidence_continuity_failure: event source regressed behind follower offset"
    );
}

/// ´test:unit:lock-parser-accepts-driver-and-optional-child´
#[test]
fn lock_parser_accepts_driver_and_optional_child() {
    assert_eq!(parse_lock(b"42\n"), Some((42, None)));
    assert_eq!(parse_lock(b"42\n57\n"), Some((42, Some(57))));
}

/// ´test:unit:lock-parser-refuses-malformed-records´
#[test]
fn lock_parser_refuses_malformed_records() {
    for bytes in [b"bad\n".as_slice(), b"42\nbad\n", b"42\n57\n99\n", b""] {
        assert_eq!(parse_lock(bytes), None);
    }
}

/// ´test:unit:monitor-parser-accepts-optional-awaiting´
#[test]
fn monitor_parser_accepts_optional_awaiting() {
    let plain = parse_monitor(b"quiet=3s wall=20s event_size=91 boot=300s awake=19s\n")
        .expect("monitor without gateway wait");
    assert_eq!(
        (
            plain.quiet,
            plain.wall,
            plain.event_size,
            plain.boot,
            plain.awake
        ),
        (3, 20, 91, 300, 19)
    );
    assert_eq!(plain.awaiting, None);
    assert_eq!(plain.context, None);
    let awaiting =
        parse_monitor(b"quiet=3s wall=20s event_size=91 boot=300s awake=19s awaiting=gw:7\n")
            .expect("monitor with gateway wait");
    assert_eq!(awaiting.awaiting.as_deref(), Some("gw:7"));
    assert_eq!(awaiting.context, None);
}

/// ´test:unit:monitor-parser-carries-optional-context-fields´
#[test]
fn monitor_parser_carries_optional_context_fields() {
    let state = parse_monitor(b"quiet=3s wall=20s event_size=91 boot=300s awake=19s awaiting=gw:7 context_state=unknown context_used=unknown context_window=unknown context_fraction=unknown context_source=codex-exec-json context_reason=window-unreported context_turn=2 context_at=2026-10-07T00:00:00Z\n").expect("context suffix");
    let context = state.context.expect("context object");
    assert_eq!(context["state"], "unknown");
    assert_eq!(context["used"], Value::Null);
    assert_eq!(context["window"], Value::Null);
    assert_eq!(context["fraction"], Value::Null);
    assert_eq!(context["source"], "codex-exec-json");
    assert_eq!(context["reason"], "window-unreported");
    assert_eq!(context["turn"], 2);
    assert_eq!(context["at"], "2026-10-07T00:00:00Z");
}

/// ´test:unit:monitor-parser-refuses-retired-letter-count´
#[test]
fn monitor_parser_refuses_retired_letter_count() {
    assert!(
        parse_monitor(b"quiet=3s wall=20s event_size=91 boot=300s awake=19s letters_observed=3\n")
            .is_err()
    );
}

/// ´test:unit:budget-sidecar-parses-expiry-and-keeps-old-format´
#[test]
fn budget_sidecar_parses_expiry_and_keeps_old_format() {
    let old = parse_monitor(b"quiet=3s wall=20s event_size=91 boot=300s awake=19s\n")
        .expect("old sidecar");
    assert!(old.budget.is_none());
    let new = parse_monitor(b"quiet=4s wall=24s event_size=91 boot=300s awake=23s budget=20s last_growth=20s state=stalled expired_wall=21s expired_event_size=91 expired_last_growth=20s expired_quiet=1s expired_state=growing\n")
        .expect("budget sidecar");
    let budget = new.budget.expect("budget");
    assert_eq!(budget.seconds, 20);
    assert_eq!(budget.state.as_deref(), Some("stalled"));
    let expiry = budget.expiry.expect("latched expiry");
    assert_eq!(
        (
            expiry.wall,
            expiry.event_size,
            expiry.last_growth,
            expiry.quiet
        ),
        (21, 91, 20, 1)
    );
    assert_eq!(expiry.state, "growing");
    let combined = parse_monitor(b"quiet=4s wall=24s event_size=91 boot=300s awake=23s context_state=unknown context_used=unknown context_window=unknown context_fraction=unknown context_source=driver context_reason=field-absent context_turn=0 context_at=2026-10-07T00:00:00Z budget=20s last_growth=20s state=stalled expired_wall=21s expired_event_size=91 expired_last_growth=20s expired_quiet=1s expired_state=growing\n")
        .expect("context, letters, and budget on one line");
    assert_eq!(
        combined.context.as_ref().expect("context")["state"],
        "unknown"
    );
    assert_eq!(
        combined.budget.expect("budget").state.as_deref(),
        Some("stalled")
    );
    let before = parse_monitor(
        b"quiet=4s wall=19s event_size=91 boot=300s awake=18s budget=20s last_growth=0s\n",
    )
    .expect("pre-expiry sidecar");
    assert!(
        before
            .budget
            .as_ref()
            .is_some_and(|budget| budget.state.is_none() && budget.expiry.is_none())
    );
    let directory = TestDir::new("pre-expiry-budget-state");
    let pid = std::process::id();
    directory.write(".codex-lane.lock", format!("{pid}\n").as_bytes());
    directory.write(
        format!(".monitor-{pid}-0"),
        b"quiet=4s wall=19s event_size=91 boot=300s awake=18s budget=20s last_growth=0s\n",
    );
    let state: Value = serde_json::from_str(&sample_state(directory.path(), 0)).expect("state");
    assert_eq!(state["monitor"]["budget"], 20);
    assert_eq!(state["monitor"]["last_growth"], 0);
    assert!(state["monitor"].get("state").is_none());
    assert_eq!(parse_monitor(b"quiet=4s wall=24s event_size=91 boot=300s awake=23s budget=20s last_growth=20s state=killed\n").err(), Some("monitor-budget"));
}

/// ´test:unit:budget-cursor-refuses-nonregular-and-malformed-targets-before-publication´
#[test]
fn budget_cursor_refuses_nonregular_and_malformed_targets_before_publication() {
    for kind in ["directory", "symlink", "malformed"] {
        let directory = TestDir::new(kind);
        let target = directory.path().join("outside");
        directory.write("outside", b"untouched\n");
        directory.write("events.jsonl", b"event\n");
        match kind {
            "directory" => directory.mkdir(".budget-notice"),
            "symlink" => {
                symlink(&target, directory.path().join(".budget-notice")).expect("symlink");
            }
            _ => directory.write(".budget-notice", b"bad cursor\n"),
        }
        let (result, output) = poll(&directory, DEFAULT_CAP);
        assert_eq!(result, Err(FeedError::BudgetNotice), "{kind}");
        assert!(output.is_empty(), "{kind} published a document");
        assert_eq!(directory.read("outside"), b"untouched\n");
    }

    let directory = TestDir::new("noncanonical-budget-cursor");
    let pid = std::process::id();
    directory.write(".codex-lane.lock", format!("{pid}\n").as_bytes());
    directory.write(".step-name", b"dispatch\n");
    directory.write(
        format!(".monitor-{pid}-0"),
        b"quiet=1s wall=21s event_size=91 boot=300s awake=20s budget=20s last_growth=20s state=growing expired_wall=21s expired_event_size=91 expired_last_growth=20s expired_quiet=1s expired_state=growing\n",
    );
    let cursor = format!("+{pid} dispatch +20 021 growing\n");
    directory.write(".budget-notice", cursor.as_bytes());
    let (result, output) = poll(&directory, DEFAULT_CAP);
    assert_eq!(result, Ok(PollResult::Pending));
    assert!(
        output.is_empty(),
        "parsed cursor must suppress duplicate expiry"
    );
    assert_eq!(directory.read(".budget-notice"), cursor.as_bytes());
}

/// ´test:unit:budget-expiry-and-state-records-publish-once-per-transition´
#[test]
fn budget_expiry_and_state_records_publish_once_per_transition() {
    let directory = TestDir::new("budget-notices");
    let pid = std::process::id();
    directory.write(".codex-lane.lock", format!("{pid}\n").as_bytes());
    directory.write(".step-name", b"dispatch\n");
    let sidecar = format!(".monitor-{pid}-0");
    directory.write(&sidecar, b"quiet=1s wall=21s event_size=91 boot=300s awake=20s budget=20s last_growth=20s state=growing expired_wall=21s expired_event_size=91 expired_last_growth=20s expired_quiet=1s expired_state=growing\n");
    let (result, output) = poll(&directory, DEFAULT_CAP);
    assert_eq!(result, Ok(PollResult::Budget));
    let records = document(&output)["records"]
        .as_array()
        .expect("records")
        .clone();
    assert_eq!(records[1]["kind"], "budget_expired");
    assert_eq!(records[1]["budget"], 20);
    assert_eq!(records[1]["wall"], 21);
    assert_eq!(records[1]["event_size"], 91);
    assert_eq!(records[1]["last_growth"], 20);
    assert_eq!(records[1]["state"], "growing");
    assert_eq!(poll(&directory, DEFAULT_CAP).0, Ok(PollResult::Pending));
    directory.write(&sidecar, b"quiet=123s wall=143s event_size=91 boot=300s awake=142s budget=20s last_growth=20s state=stalled expired_wall=21s expired_event_size=91 expired_last_growth=20s expired_quiet=1s expired_state=growing\n");
    let (result, output) = poll(&directory, DEFAULT_CAP);
    assert_eq!(result, Ok(PollResult::Budget));
    assert_eq!(document(&output)["records"][1]["kind"], "budget_state");
    assert_eq!(document(&output)["records"][1]["state"], "stalled");
    assert_eq!(poll(&directory, DEFAULT_CAP).0, Ok(PollResult::Pending));
    directory.write(".step-name", b"review\n");
    let (result, output) = poll(&directory, DEFAULT_CAP);
    assert_eq!(result, Ok(PollResult::Budget));
    assert_eq!(document(&output)["records"][1]["kind"], "budget_expired");
}

/// ´test:unit:monitor-parser-refuses-malformed-records´
#[test]
fn monitor_parser_refuses_malformed_records() {
    for bytes in [
        b"quiet=x wall=20s event_size=91 boot=300s awake=19s\n".as_slice(),
        b"quiet=3s wall=20s event_size=91 boot=300s awake=19s awaiting=gw:x\n",
        b"quiet=3s wall=20s event_size=91 boot=300s awake=19s",
        b"quiet=3s wall=20s event_size=91 boot=300s awake=19s extra\n",
    ] {
        assert!(parse_monitor(bytes).is_err());
    }
    assert_eq!(parse_monitor(b"quiet=3s wall=20s event_size=91 boot=300s awake=19s context_state=unknown context_used=unknown\n").err(), Some("monitor-context"));
}

/// ´test:unit:state-uses-nulls-for-missing-evidence´
#[test]
fn state_uses_nulls_for_missing_evidence() {
    let directory = TestDir::new("state-missing");
    let state: Value =
        serde_json::from_str(&sample_state(directory.path(), 7)).expect("state JSON");
    assert_eq!(state["kind"], "state");
    for name in [
        "step",
        "started_at",
        "wall_seconds",
        "driver",
        "events",
        "monitor",
    ] {
        assert!(state[name].is_null(), "{name}");
    }
    assert_eq!(state["report"], false);
    assert_eq!(state["last_message"], false);
    assert_eq!(state["offset"], 7);
}

/// ´test:unit:state-reports-dead-driver-and-present-evidence´
#[test]
fn state_reports_dead_driver_and_present_evidence() {
    let directory = TestDir::new("state-present");
    directory.write(".step-name", b" work \n");
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    directory.write(
        ".started-at",
        format!("{}\n", utc_instant(now - 3)).as_bytes(),
    );
    directory.write(".codex-lane.lock", b"4294967295\n");
    directory.write("events.jsonl", b"one\n");
    directory.write(
        ".monitor-4294967295-0",
        b"quiet=3s wall=20s event_size=4 boot=300s awake=19s awaiting=gw:7\n",
    );
    directory.write("run-report.txt", b"done");
    directory.write("last-message.txt", b"last");
    let state: Value =
        serde_json::from_str(&sample_state(directory.path(), 2)).expect("state JSON");
    assert_eq!(state["step"], "work");
    assert_eq!(state["started_at"], utc_instant(now - 3));
    assert!(
        state["wall_seconds"]
            .as_i64()
            .is_some_and(|wall| (2..=5).contains(&wall))
    );
    assert_eq!(
        state["driver"],
        json!({"lock":".codex-lane.lock","pid":4_294_967_295_u64,"child":null,"alive":false})
    );
    assert_eq!(state["events"]["bytes"], 4);
    assert!(
        state["events"]["age_seconds"]
            .as_u64()
            .is_some_and(|age| age <= 3)
    );
    assert_eq!(
        state["monitor"],
        json!({"quiet":3,"wall":20,"event_size":4,"boot":300,"awake":19,"awaiting":"gw:7","context":null})
    );
    assert_eq!(state["report"], true);
    assert_eq!(state["last_message"], true);
    assert_eq!(state["offset"], 2);
}

/// ´test:unit:state-keeps-a-live-child-after-its-driver-exits´
#[test]
fn state_keeps_a_live_child_after_its_driver_exits() {
    let directory = TestDir::new("state-live-child");
    let child = std::process::id();
    directory.write(
        ".codex-lane.lock",
        format!("4294967295\n{child}\n").as_bytes(),
    );
    directory.write("run-report.txt", b"done");
    let mut output = Vec::new();
    run(&config(&directory, DEFAULT_CAP), &mut output).expect("state envelope");
    let document = document(&output);
    assert_eq!(document["schema"], 2);
    assert_eq!(document["records"][0]["kind"], "state");
    assert_eq!(
        document["records"][0]["driver"],
        json!({"lock":".codex-lane.lock","pid":4_294_967_295_u64,"child":child,"alive":true})
    );
}

/// ´test:unit:state-selects-the-latest-new-form-capture-for-the-driver´
#[test]
fn state_selects_the_latest_new_form_capture_for_the_driver() {
    let directory = TestDir::new("state-monitor-capture-selection");
    directory.write(".codex-lane.lock", b"4294967295\n");
    directory.write(
        ".monitor-4294967295-0",
        b"quiet=900s wall=900s event_size=1 boot=100s awake=900s\n",
    );
    directory.write(
        ".monitor-4294967295-1",
        b"quiet=3s wall=20s event_size=4 boot=300s awake=19s\n",
    );
    directory.write(
        ".monitor-4294967294-9",
        b"quiet=900s wall=900s event_size=1 boot=400s awake=900s\n",
    );
    let state: Value = serde_json::from_str(&sample_state(directory.path(), 0)).expect("state");
    assert_eq!(state["monitor"]["quiet"], 3);
    assert_eq!(state["monitor"]["boot"], 300);
}

/// ´test:unit:state-prefers-live-claude-lock-over-newer-stale-codex-lock´
#[test]
fn state_prefers_live_claude_lock_over_newer_stale_codex_lock() {
    let directory = TestDir::new("state-dual-lock-selection");
    let live = std::process::id();
    directory.write(".claude-lane.lock", format!("{live}\n").as_bytes());
    directory.write(".codex-lane.lock", b"4294967295\n");
    directory.set_modified(
        ".claude-lane.lock",
        std::time::UNIX_EPOCH + Duration::from_secs(2),
    );
    directory.set_modified(
        ".codex-lane.lock",
        std::time::UNIX_EPOCH + Duration::from_secs(3),
    );
    directory.write(
        format!(".monitor-{live}-1"),
        b"quiet=3s wall=20s event_size=4 boot=300s awake=19s\n",
    );
    directory.write(
        ".monitor-4294967295-1",
        b"quiet=900s wall=900s event_size=1 boot=400s awake=900s\n",
    );
    let state: Value = serde_json::from_str(&sample_state(directory.path(), 0)).expect("state");
    assert_eq!(state["driver"]["lock"], ".claude-lane.lock");
    assert_eq!(state["driver"]["pid"], live);
    assert_eq!(state["driver"]["alive"], true);
    assert_eq!(state["monitor"]["quiet"], 3);
}

/// ´test:unit:bounded-wait-publishes-state-without-offset-change´
#[test]
fn bounded_wait_publishes_state_without_offset_change() {
    let directory = TestDir::new("wait-state");
    directory.write(".feed-offset", b"0\n");
    let mut config = config(&directory, DEFAULT_CAP);
    config.wait = 1;
    let mut output = Vec::new();
    run(&config, &mut output).expect("bounded wait publishes state");
    let parsed = document(&output);
    let records = parsed["records"].as_array().expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "state");
    assert_eq!(records[0]["offset"], 0);
    assert_eq!(directory.read(".feed-offset"), b"0\n");
}

/// ´test:unit:wait-accepts-joined-and-separated-grammar´
#[test]
fn wait_accepts_joined_and_separated_grammar() {
    let directory = TestDir::new("args-wait");
    let separated = parse_args([
        directory.path().as_os_str(),
        std::ffi::OsStr::new("--wait"),
        std::ffi::OsStr::new("+1_2"),
    ])
    .expect("separated wait");
    let joined = parse_args([
        std::ffi::OsStr::new("--wait= 12 "),
        directory.path().as_os_str(),
    ])
    .expect("joined wait");
    assert_eq!(separated.wait, 12);
    assert_eq!(joined.wait, 12);
}

/// ´test:unit:wait-refuses-malformed-and-missing-values´
#[test]
fn wait_refuses_malformed_and_missing_values() {
    let directory = TestDir::new("args-wait-invalid");
    for value in ["-1", "", "1__2", "wrong"] {
        assert!(
            parse_args([
                directory.path().as_os_str(),
                std::ffi::OsStr::new(&format!("--wait={value}"))
            ])
            .is_err()
        );
    }
    assert!(parse_args([directory.path().as_os_str(), std::ffi::OsStr::new("--wait")]).is_err());
}

/// ´test:unit:utc-start-parser-checks-calendar-and-zone´
#[test]
fn utc_start_parser_checks_calendar_and_zone() {
    assert_eq!(parse_utc_instant("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_utc_instant("1970-01-01T00:00:01.250+00:00"), Some(1));
    assert_eq!(
        parse_utc_instant("2024-02-29T00:00:00Z"),
        Some(1_709_164_800)
    );
    for invalid in [
        "2023-02-29T00:00:00Z",
        "2024-01-01T00:00:00+01:00",
        "2024-01-01T24:00:00Z",
        "bad",
    ] {
        assert_eq!(parse_utc_instant(invalid), None);
    }
}
