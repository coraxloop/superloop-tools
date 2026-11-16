//! Markdown formatter integration tests.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`construct_fixtures_have_stable_bytes`] | fmt | Public Markdown constructs retain their expected bytes and are idempotent. |
//! | [`build_identity_survives_versions_results_and_refusals`] | identity | Both version spellings, findings, clean reports and startup refusals identify the same executable bytes without consulting a sidecar. |
//! | [`execute_only_linter_keeps_judging_with_named_digest_absence`] | identity | Execute-only installs retain version and formatter access while naming the unreadable image instead of taking either command away from their reader. |
//! | [`code_span_pipes_preserve_every_cell`] | fmt | Code-span pipes are cell text, so formatting retains all four columns and both literal pipe spellings without rewriting their code spans. |
//! | [`table_refusals_name_a_location_and_recovery`] | fmt | Ambiguous table refusals identify their category, source range and recovery action; an ambiguous table row names its line and retains the refused source. |
//! | [`refusal_locations_cross_overlay_slots`] | fmt | Refusals after one or more overlay slots retain original lines and byte offsets, including CRLF padding and a multibyte prefix, in both modes. |
//! | [`check_reports_an_unformatted_file_without_writing_it`] | fmt | Formatter check mode reports every path that would change, exits with the linter's findings status, and leaves the named file byte-for-byte alone. |
//! | [`check_continues_after_a_guard_rejection`] | fmt | Formatter check mode records a guard rejection for one file and still reports a later file that would reflow, so one unsafe source does not hide the rest of the requested paths. |
//! | [`records_every_non_guard_failure_in_check_and_write_modes`] | fmt | Both formatter modes record an unreadable file and invalid UTF-8 independently while retaining a good file's result; write mode formats that good file over the same tree. |
//! | [`traversal_failure_aborts_before_any_file_is_formatted`] | fmt | An unreadable directory aborts discovery before either formatter mode enters its per-file loop, so even an earlier reflowable file remains unchanged and no report is emitted. On uid 0 the test returns early because mode bits cannot make the directory unreadable. |
//! | [`leaves_block_quotes_byte_identical_in_check_and_write_modes`] | fmt | Formatter check mode reports no changes or rejections for ordinary, multi-paragraph, and list-item block quotes, and write mode leaves the fixture byte-identical. |
//! | [`leaves_reference_links_and_loose_lists_byte_identical_in_check_and_write_modes`] | fmt | Formatter check mode reports no changes or rejections for shortcut, collapsed, full-reference and image references beside loose, nested and quoted lists, and write mode leaves the fixture byte-identical. |
//! | [`write_mode_records_a_rejection_and_formats_the_remaining_file`] | fmt | Formatter write mode records a guard rejection for one file of a directory, formats the other, and reports both in one object with the findings status, so one unsafe source no longer costs the tree its formatting. |

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

/// Public Markdown constructs retain their expected bytes and are idempotent.
///
/// # Panics
/// Panics only if fixture IO fails or the formatter changes the construct.
///
/// ´claim:fmt:construct-fixtures-have-stable-bytes´
/// ´test:integration:construct-fixtures-have-stable-bytes´
#[test]
fn construct_fixtures_have_stable_bytes() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("construct.md");
    for (source, expected) in [
        "*[^a]*\n\n[^a]: note\n",
        "**see [^a]**\n\n[^a]: note\n",
        "[^a]: note\n\n*[^a]*\n",
        "[^a]: note\n\nplain [^a] &copy;\n",
        "*[^a]*\n\n[^a]: see [^b]\n\n[^b]: note\n",
        "*[^a]*\n\n[^a]: *note*\n",
        "[link][x]\n\n*[^a]*\n\n[^a]: [x]\n\n[x]: /target\n",
        "Before.\n\n*[^a]*\n\nBetween.\n\n[^a]: note\n\nAfter.\n",
        "|a|b|\n|-|-|\n|`\\|` *label*|x|\n",
    ].into_iter().map(|source| (source, source)).chain([
        (
            "*[^a]*\n\n[^a]: note\n\n|a|b|\n|-|-|\n|stray ` tick|x|\n|`a|b` *label*|x|\n\nAn &copy; authored \\*literal\\* stays text.\n\nA ``code`` span.\n",
            "*[^a]*\n\n[^a]: note\n\n|a|b|\n|-|-|\n|stray \\` tick|x|\n|`a|b` *label*|x|\n\nAn &copy; authored \\*literal\\* stays text.\n\nA ``code`` span.\n",
        ),
    ]) {
        fs::write(&path, source).expect("write construct");
        for (index, args) in [vec!["fmt"], vec!["fmt", "--check"]].into_iter().enumerate() {
            let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
                .args(args)
                .arg(&path)
                .output()
                .expect("production formatter");
            assert!(output.status.success(), "{output:?}");
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
            assert_eq!(report["files_rejected"], 0, "{report}");
            assert_eq!(report["files_changed"], usize::from(index == 0 && source != expected), "{report}");
            assert_eq!(fs::read_to_string(&path).expect("read construct"), expected);
        }
    }
}

/// Both version spellings, findings, clean reports and startup refusals identify
/// the same executable bytes without consulting a sidecar.
///
/// # Panics
/// Panics only if fixture IO fails or a publication loses its measured identity.
///
/// ´claim:identity:build-identity-survives-versions-results-and-refusals´
/// ´test:integration:build-identity-survives-versions-results-and-refusals´
#[test]
fn build_identity_survives_versions_results_and_refusals() {
    use sha2::{Digest, Sha256};
    let binary = env!("CARGO_BIN_EXE_superloop-lint");
    let digest: String = Sha256::digest(fs::read(binary).expect("binary bytes"))
        .iter()
        .flat_map(|byte| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect();
    let root = tempfile::tempdir().expect("fixture");
    let path = root.path().join("clean.md");
    fs::write(&path, "A paragraph.\n").expect("source");
    let mut held = None;
    for arguments in [
        vec!["--version"],
        vec!["-V"],
        vec!["--help"],
        vec!["--invalid"],
        vec!["fmt", "--check", path.to_str().expect("path")],
        vec!["check", "--root", root.path().to_str().expect("root")],
    ] {
        let output = Command::new(binary)
            .env("PATH", root.path())
            .args(&arguments)
            .output()
            .expect("linter");
        let records = output
            .stdout
            .split(|byte| *byte == b'\n')
            .chain(output.stderr.split(|byte| *byte == b'\n'))
            .filter(|line| !line.is_empty());
        let mut count = 0;
        for line in records {
            let value: serde_json::Value = serde_json::from_slice(line).expect("JSON record");
            let identity = &value["identity"];
            assert!(value.get("runtime").is_none());
            assert_eq!(
                identity["artifact_sha256"], digest,
                "{arguments:?}: {value}"
            );
            assert_eq!(identity["digest_absence"], serde_json::Value::Null);
            assert_eq!(identity["version"], env!("CARGO_PKG_VERSION"));
            if let Some(previous) = &held {
                assert_eq!(identity, previous);
            } else {
                held = Some(identity.clone());
            }
            if arguments == ["--version"] || arguments == ["-V"] {
                assert_eq!(
                    value["fields"]["version"],
                    concat!("superloop-lint ", env!("CARGO_PKG_VERSION"))
                );
                assert!(
                    value["message"]
                        .as_str()
                        .expect("message")
                        .contains(&digest)
                );
                assert_eq!(output.stdout, b"");
                assert!(output.status.success());
            }
            count += 1;
        }
        assert!(count > 0, "{arguments:?}");
    }
    fs::write(&path, "A paragraph that is\nhard wrapped.\n").expect("unformatted");
    let output = Command::new(binary)
        .args(["fmt", "--check"])
        .arg(&path)
        .output()
        .expect("finding");
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("finding report");
    assert_eq!(Some(report["identity"].clone()), held);
}

/// Execute-only installs retain version and formatter access while naming the
/// unreadable image instead of taking either command away from their reader.
///
/// # Panics
/// Panics only if fixture IO fails or execute-only publication loses its identity.
///
/// ´claim:identity:execute-only-linter-keeps-judging-with-named-digest-absence´
/// ´test:integration:execute-only-linter-keeps-judging-with-named-digest-absence´
#[test]
fn execute_only_linter_keeps_judging_with_named_digest_absence() {
    const COPY: &str = "SUPERLOOP_IDENTITY_COPY_FIXTURE";
    if let Some(path) = std::env::var_os(COPY) {
        fs::copy(env!("CARGO_BIN_EXE_superloop-lint"), &path).expect("copy");
        fs::set_permissions(path, fs::Permissions::from_mode(0o111)).expect("execute only");
        return;
    }
    let root = tempfile::tempdir().expect("fixture");
    let binary = root.path().join("linter");
    // A separate, reaped writer prevents parallel test spawns from inheriting
    // a writable image descriptor and making the later exec fail with ETXTBSY.
    let copied = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "execute_only_linter_keeps_judging_with_named_digest_absence",
        ])
        .env(COPY, &binary)
        .output()
        .expect("isolated copy writer");
    assert!(copied.status.success(), "{copied:?}");
    if fs::File::open(&binary).is_ok() {
        return;
    } // Privileged accounts can still read mode 0111.
    let path = root.path().join("source.md");
    fs::write(&path, "A paragraph.\n").expect("source");
    for arguments in [
        vec!["--version"],
        vec!["-V"],
        vec!["fmt", "--check", path.to_str().expect("path")],
    ] {
        let output = Command::new(&binary)
            .args(arguments)
            .output()
            .expect("linter");
        assert!(output.status.success(), "{output:?}");
        let bytes = if output.stdout.is_empty() {
            &output.stderr
        } else {
            &output.stdout
        };
        let record: serde_json::Value = serde_json::from_slice(bytes).expect("record");
        assert_eq!(
            record["identity"]["artifact_sha256"],
            serde_json::Value::Null
        );
        assert_eq!(record["identity"]["digest_absence"], "unreadable");
    }
}

/// Code-span pipes are cell text, so formatting retains all four columns and
/// both literal pipe spellings without rewriting their code spans.
///
/// # Panics
/// Panics only if fixture IO fails or the production formatter loses bytes.
///
/// ´claim:fmt:code-span-pipes-preserve-every-cell´
/// ´test:integration:code-span-pipes-preserve-every-cell´
#[test]
fn code_span_pipes_preserve_every_cell() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("pipes.md");
    for (code, stray) in [
        ("`dispatch|report`", ""),
        ("`dispatch\\|report`", ""),
        ("``a`|b``", ""),
        ("`\\|` *label*", ""),
        ("`\\|` **label**", ""),
        ("*label* `\\|`", ""),
        ("`a \\| b` *label*", ""),
        ("`\\|`", ""),
        ("\\| *label*", ""),
        ("``a \\| b`` **label**", ""),
        ("`a|b` *label*", ""),
        ("**label** `a|b`", ""),
        ("``a`|b`` *label*", ""),
        ("`dispatch|report`", "|404|stray ` tick|OPEN|linter|\n"),
    ] {
        let before = format!(
            "\n```text\n`fenced|pipe`\n```\n\n|Row|Text|State|Owner|\n|---|----|-----|-----|\n{stray}|405|{code}|OPEN|linter|\n"
        );
        let expected = before.replace("stray ` tick", "stray \\` tick");
        fs::write(&path, &before).expect("write fixture");
        for (args, changed) in [
            (vec!["fmt"], usize::from(!stray.is_empty())),
            (vec!["fmt", "--check"], 0),
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
                .args(args)
                .arg(&path)
                .output()
                .expect("production formatter");
            assert!(output.status.success(), "{output:?}");
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
            assert_eq!(report["files_changed"], changed, "{report}");
            assert_eq!(report["files_rejected"], 0, "{report}");
            assert_eq!(fs::read_to_string(&path).expect("read fixture"), expected);
        }
    }
    for (before, refusal) in [
        (
            "|Row|`Text|Code`|State|Owner|\n|---|---|---|---|---|\n|405|a|b|OPEN|linter|\n",
            "table-code-pipe-header",
        ),
        (
            "|Row|`Text|Code`|State|Owner|\n|---|---|---|---|\n|405|a|OPEN|linter|\n",
            "table-code-pipe-header",
        ),
        (
            "|Row|Text|State|Owner|\n|---|---|---|---|\n|405|a ` b|c ` d|linter|\n",
            "table-code-pipe-row",
        ),
        (
            "|Row|Text|State|Owner|\n|---|---|---|---|\n|405|`a|b`|OPEN|linter|extra|\n",
            "table-code-pipe-row",
        ),
        (
            "|Row|Text|State|Owner|\n|---|---|---|---|\n|405|a|OPEN|linter|extra|\n",
            "table-code-pipe-row",
        ),
    ] {
        fs::write(&path, before).expect("write unsafe table");
        for args in [vec!["fmt", "--check"], vec!["fmt"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
                .args(args)
                .arg(&path)
                .output()
                .expect("production formatter");
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
            assert_eq!(output.status.code(), Some(3), "{report}");
            assert_eq!(report["files_rejected"], 1, "{report}");
            assert!(report.to_string().contains(refusal), "{report}");
            assert_eq!(
                fs::read_to_string(&path).expect("read refused table"),
                before
            );
        }
    }
}

/// Ambiguous table refusals identify their category, source range and recovery action;
/// an ambiguous table row names its line and retains the refused source.
///
/// # Panics
/// Panics only if fixture IO fails or the production formatter violates the contract.
///
/// ´claim:fmt:table-refusals-name-a-location-and-recovery´
/// ´test:integration:table-refusals-name-a-location-and-recovery´
#[test]
fn table_refusals_name_a_location_and_recovery() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("refused.md");
    for (source, kind, location, action) in [
        (
            "Before.\n\n|a|`b|c`|\n|-|-|-|\n|x|y|z|\n",
            "source_parse_failure",
            "header at line 3",
            "make the header and delimiter describe the same cells",
        ),
        (
            "Before.\n\n|a|b|\n|-|-|\n|a|b|c|\n",
            "source_parse_failure",
            "row at line 5",
            "make the row match the header's column count",
        ),
    ] {
        fs::write(&path, source).expect("write fixture");
        for args in [vec!["fmt", "--check"], vec!["fmt"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
                .args(args)
                .arg(&path)
                .output()
                .expect("production formatter");
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
            assert_eq!(output.status.code(), Some(3), "{report}");
            assert_eq!(report["files_rejected"], 1, "{report}");
            let rejection = &report["rejected"][0];
            assert_eq!(rejection["kind"], kind, "{report}");
            let cause = rejection["cause"].as_str().expect("cause");
            assert!(cause.starts_with("the file was not changed;"), "{cause}");
            assert!(
                cause.contains(location) && cause.contains(action),
                "{cause}"
            );
            let row = if location.starts_with("header") {
                "|a|`b|c`|\n"
            } else {
                "|a|b|c|\n"
            };
            let start = source.find(row).expect("refused row");
            assert_eq!(
                rejection["input_range"],
                serde_json::json!({"start":start,"end":start + row.trim_end_matches('\n').len()})
            );
            assert_eq!(fs::read_to_string(&path).expect("read fixture"), source);
        }
    }
}

/// Refusals after one or more overlay slots retain original lines and byte
/// offsets, including CRLF padding and a multibyte prefix, in both modes.
///
/// # Panics
/// Panics only if fixture IO fails or the production formatter loses the location.
///
/// ´claim:fmt:refusal-locations-cross-overlay-slots´
/// ´test:integration:refusal-locations-cross-overlay-slots´
#[test]
fn refusal_locations_cross_overlay_slots() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("slots.md");
    for (prefix, first_line) in [
        ("", 1),
        ("Préface.\n{{overlay:body:test:first}}\n\n", 4),
        (
            "Préface.\n{{overlay:body:test:first}}\n\nMiddle.\n{{overlay:body:test:second}}\n\n",
            7,
        ),
    ] {
        for suffix in ["", "\n{{overlay:body:test:last}}\nAfter.\n"] {
            for newline in ["\n", "\r\n"] {
                let source =
                    format!("{prefix}|a|b|\n|-|-|\n|a|b|c|\n{suffix}").replace('\n', newline);
                let start = source.find("|a|b|c|").expect("refused row");
                let end = start + 7;
                fs::write(&path, &source).expect("write fixture");
                for args in [vec!["fmt", "--check"], vec!["fmt"]] {
                    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
                        .args(args)
                        .arg(&path)
                        .output()
                        .expect("production formatter");
                    let report: serde_json::Value =
                        serde_json::from_slice(&output.stdout).expect("report");
                    assert_eq!(output.status.code(), Some(3), "{report}");
                    assert_eq!(report["files_rejected"], 1, "{report}");
                    let rejection = &report["rejected"][0];
                    assert_eq!(rejection["kind"], "source_parse_failure", "{report}");
                    assert!(
                        rejection["cause"]
                            .as_str()
                            .expect("cause")
                            .contains(&format!("row at line {} has", first_line + 2)),
                        "{report}"
                    );
                    assert_eq!(
                        rejection["input_range"],
                        serde_json::json!({"start":start,"end":end})
                    );
                    assert_eq!(fs::read_to_string(&path).expect("read fixture"), source);
                }
            }
        }
    }
}

fn permissions_cannot_deny_access(path: &Path, reason: &str) -> bool {
    if fs::metadata(path)
        .expect("temporary directory metadata")
        .uid()
        != 0
    {
        return false;
    }

    let _ignored = writeln!(io::stderr(), "conditional early return: {reason}");
    true
}

/// Formatter check mode reports every path that would change, exits with the
/// linter's findings status, and leaves the named file byte-for-byte alone.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, read, written, or
/// executed, or when the command violates the asserted result contract.
///
/// ´claim:fmt:check-mode-reports-without-writing´
/// ´test:integration:check-reports-an-unformatted-file-without-writing-it´
#[test]
fn check_reports_an_unformatted_file_without_writing_it() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("unformatted.md");
    let before = "A paragraph that is\nhard wrapped.\n";
    fs::write(&path, before).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["fmt", "--check"])
        .arg(&path)
        .output()
        .expect("run formatter check");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(fs::read_to_string(&path).expect("read fixture"), before);

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");
    assert_eq!(report["check"], true);
    assert_eq!(report["files_scanned"], 1);
    assert_eq!(report["files_changed"], 1);
    assert_eq!(
        report["changed"][0]["path"],
        path.to_string_lossy().as_ref()
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(path.to_string_lossy().as_ref()),
        "the per-file diagnostic lists the path"
    );
}

/// Formatter check mode records a guard rejection for one file and still reports
/// a later file that would reflow, so one unsafe source does not hide the rest
/// of the requested paths.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, read, written, or
/// executed, or when the command violates the asserted result contract.
///
/// ´claim:fmt:check-mode-continues-after-a-guard-rejection´
/// ´test:integration:check-continues-after-a-guard-rejection´
#[test]
fn check_continues_after_a_guard_rejection() {
    let root = tempfile::tempdir().expect("temporary directory");
    let rejected = root.path().join("guard-rejected.md");
    let reflowable = root.path().join("reflowable.md");
    // Upstream now preserves escaped entities; a multiline reference still changes its ID.
    let rejected_before = "A [the\nparser].\n\n[the parser]: https://example.com\n";
    let reflowable_before = "A paragraph that is\nhard wrapped.\n";
    fs::write(&rejected, rejected_before).expect("write rejected fixture");
    fs::write(&reflowable, reflowable_before).expect("write reflowable fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["fmt", "--check"])
        .arg(&rejected)
        .arg(&reflowable)
        .output()
        .expect("run formatter check");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        fs::read_to_string(&rejected).expect("read rejected fixture"),
        rejected_before
    );
    assert_eq!(
        fs::read_to_string(&reflowable).expect("read reflowable fixture"),
        reflowable_before
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");
    assert_eq!(report["check"], true);
    assert_eq!(report["files_scanned"], 2);
    assert_eq!(report["files_changed"], 1);
    assert_eq!(report["files_rejected"], 1);
    assert_eq!(
        report["rejected"][0]["path"],
        rejected.to_string_lossy().as_ref()
    );
    assert_eq!(report["rejected"][0]["kind"], "integrity_guard");
    let cause = report["rejected"][0]["cause"].as_str().expect("cause");
    assert!(cause.starts_with("the file was not changed;"), "{cause}");
    assert!(cause.contains("at line 1"), "{cause}");
    assert!(
        cause.contains("reduce a copy to the smallest excerpt that still refuses"),
        "{cause}"
    );
    assert_eq!(report["rejected"][0]["event_index"], 2);
    assert!(
        report["rejected"][0]["difference"]
            .as_str()
            .expect("difference")
            .contains("attribute differs"),
        "the rejection names what differs"
    );
    assert_eq!(
        report["changed"][0]["path"],
        reflowable.to_string_lossy().as_ref()
    );
}

/// Both formatter modes record an unreadable file and invalid UTF-8
/// independently while retaining a good file's result; write mode formats that
/// good file over the same tree.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, inspected, read,
/// written, made unreadable, or executed, or when the command violates the
/// asserted result contract.
///
/// ´claim:fmt:every-non-guard-failure-is-recorded-in-both-modes´
/// ´test:integration:records-every-non-guard-failure-in-check-and-write-modes´
#[test]
fn records_every_non_guard_failure_in_check_and_write_modes() {
    let root = tempfile::tempdir().expect("temporary directory");
    if permissions_cannot_deny_access(
        root.path(),
        "uid 0 can read a mode-000 file, so this test cannot produce an unreadable file",
    ) {
        return;
    }

    let good = root.path().join("00-good.md");
    let unreadable = root.path().join("01-unreadable.md");
    let unparseable = root.path().join("02-unparseable.md");
    let good_before = "A paragraph that is\nhard wrapped.\n";
    let unreadable_before = "Unreadable prose.\n";
    let unparseable_before = b"Invalid UTF-8: \xff\n";
    fs::write(&good, good_before).expect("write good fixture");
    fs::write(&unreadable, unreadable_before).expect("write unreadable fixture");
    fs::write(&unparseable, unparseable_before).expect("write unparseable fixture");

    let mut permissions = fs::metadata(&unreadable)
        .expect("unreadable fixture metadata")
        .permissions();
    permissions.set_mode(0o000);
    fs::set_permissions(&unreadable, permissions).expect("make fixture unreadable");

    let check_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["fmt", "--check"])
        .arg(root.path())
        .output()
        .expect("run formatter check");
    let write_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .arg("fmt")
        .arg(root.path())
        .output()
        .expect("run formatter write");

    let mut permissions = fs::metadata(&unreadable)
        .expect("unreadable fixture metadata")
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&unreadable, permissions).expect("restore fixture permissions");

    assert_eq!(check_output.status.code(), Some(3));
    let report: serde_json::Value =
        serde_json::from_slice(&check_output.stdout).expect("one JSON object on stdout");
    assert_eq!(report["check"], true);
    assert_eq!(report["files_scanned"], 3);
    assert_eq!(report["files_changed"], 1);
    assert_eq!(report["files_rejected"], 2);
    assert_eq!(
        report["changed"][0]["path"],
        good.to_string_lossy().as_ref()
    );
    assert_eq!(
        report["rejected"][0]["path"],
        unreadable.to_string_lossy().as_ref()
    );
    assert_eq!(report["rejected"][0]["kind"], "read_failure");
    assert!(
        report["rejected"][0]["cause"]
            .as_str()
            .expect("read failure cause")
            .contains("could not read"),
        "the read rejection carries its cause"
    );
    assert_eq!(
        report["rejected"][1]["path"],
        unparseable.to_string_lossy().as_ref()
    );
    assert_eq!(report["rejected"][1]["kind"], "source_parse_failure");
    assert!(
        report["rejected"][1]["cause"]
            .as_str()
            .expect("source parse failure cause")
            .contains("valid UTF-8"),
        "the source-parse rejection carries its cause"
    );

    assert_eq!(write_output.status.code(), Some(3));
    let write_report: serde_json::Value =
        serde_json::from_slice(&write_output.stdout).expect("one JSON object on stdout");
    assert_eq!(write_report["check"], false);
    assert_eq!(write_report["files_scanned"], 3);
    assert_eq!(write_report["files_changed"], 1);
    assert_eq!(write_report["files_rejected"], 2);
    assert_eq!(
        write_report["rejected"][0]["kind"].as_str(),
        report["rejected"][0]["kind"].as_str(),
        "write mode records the read failure check mode recorded"
    );
    assert_eq!(
        write_report["rejected"][1]["kind"].as_str(),
        report["rejected"][1]["kind"].as_str(),
        "write mode records the source-parse failure check mode recorded"
    );
    assert_eq!(
        fs::read_to_string(&good).expect("read good fixture"),
        "A paragraph that is hard wrapped.\n"
    );
    assert_eq!(
        fs::read_to_string(&unreadable).expect("read unreadable fixture"),
        unreadable_before
    );
    assert_eq!(
        fs::read(&unparseable).expect("read unparseable fixture"),
        unparseable_before
    );
}

/// An unreadable directory aborts discovery before either formatter mode enters
/// its per-file loop, so even an earlier reflowable file remains unchanged and
/// no report is emitted. On uid 0 the test returns early because mode bits
/// cannot make the directory unreadable.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, inspected, read,
/// written, made unreadable, or executed, or when the command violates the
/// asserted result contract.
///
/// ´claim:fmt:a-traversal-failure-aborts-before-the-per-file-loop´
/// ´test:integration:traversal-failure-aborts-before-any-file-is-formatted´
#[test]
fn traversal_failure_aborts_before_any_file_is_formatted() {
    let root = tempfile::tempdir().expect("temporary directory");
    if permissions_cannot_deny_access(
        root.path(),
        "uid 0 can traverse a mode-000 directory, so this test cannot produce a traversal failure",
    ) {
        return;
    }

    let reflowable = root.path().join("00-hard-wrapped.md");
    let unreadable = root.path().join("01-unreadable");
    let before = "A paragraph that is\nhard wrapped.\n";
    fs::write(&reflowable, before).expect("write reflowable fixture");
    fs::create_dir(&unreadable).expect("create unreadable directory");

    let mut permissions = fs::metadata(&unreadable)
        .expect("unreadable directory metadata")
        .permissions();
    permissions.set_mode(0o000);
    fs::set_permissions(&unreadable, permissions).expect("make directory unreadable");

    let check_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["fmt", "--check"])
        .arg(&reflowable)
        .arg(&unreadable)
        .output()
        .expect("run formatter check");
    let write_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .arg("fmt")
        .arg(&reflowable)
        .arg(&unreadable)
        .output()
        .expect("run formatter write");

    let mut permissions = fs::metadata(&unreadable)
        .expect("unreadable directory metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&unreadable, permissions).expect("restore directory permissions");

    for (mode, output) in [("check", check_output), ("write", write_output)] {
        assert_eq!(output.status.code(), Some(1), "{mode} mode aborts");
        assert!(
            output.stdout.is_empty(),
            "{mode} mode emits no partial report"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(unreadable.to_string_lossy().as_ref()),
            "{mode} mode names the unreadable directory"
        );
        assert!(
            stderr.contains("could not read"),
            "{mode} mode names the traversal failure"
        );
    }

    assert_eq!(
        fs::read_to_string(&reflowable).expect("read reflowable fixture"),
        before,
        "write mode never reaches the earlier discovered file"
    );
}

/// Formatter check mode reports no changes or rejections for ordinary, multi-paragraph, and list-item block quotes, and write mode leaves the fixture byte-identical.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, read, written, or executed, or when the command violates the asserted result contract.
///
/// ´claim:fmt:block-quotes-are-byte-identical-in-check-and-write-modes´
/// ´test:integration:leaves-block-quotes-byte-identical-in-check-and-write-modes´
#[test]
fn leaves_block_quotes_byte_identical_in_check_and_write_modes() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("blockquotes.md");
    let before = include_str!("fixtures/fmt/blockquotes.md");
    fs::write(&path, before).expect("write fixture");

    let check_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["fmt", "--check"])
        .arg(&path)
        .output()
        .expect("run formatter check");

    assert_eq!(check_output.status.code(), Some(0));
    let check_report: serde_json::Value =
        serde_json::from_slice(&check_output.stdout).expect("one JSON object on stdout");
    assert_eq!(check_report["files_changed"], 0);
    assert_eq!(check_report["files_rejected"], 0);

    let write_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .arg("fmt")
        .arg(&path)
        .output()
        .expect("run formatter write");

    assert_eq!(write_output.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).expect("read fixture"), before);
}

/// Formatter check mode reports no changes or rejections for shortcut, collapsed, full-reference and image references beside loose, nested and quoted lists, and write mode leaves the fixture byte-identical.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, read, written, or executed, or when the command violates the asserted result contract.
///
/// ´claim:fmt:reference-links-and-loose-lists-are-byte-identical-in-check-and-write-modes´
/// ´test:integration:leaves-reference-links-and-loose-lists-byte-identical-in-check-and-write-modes´
#[test]
fn leaves_reference_links_and_loose_lists_byte_identical_in_check_and_write_modes() {
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("references-and-lists.md");
    let before = include_str!("fixtures/fmt/references-and-lists.md");
    fs::write(&path, before).expect("write fixture");

    let check_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["fmt", "--check"])
        .arg(&path)
        .output()
        .expect("run formatter check");

    assert_eq!(check_output.status.code(), Some(0));
    let check_report: serde_json::Value =
        serde_json::from_slice(&check_output.stdout).expect("one JSON object on stdout");
    assert_eq!(check_report["files_changed"], 0);
    assert_eq!(check_report["files_rejected"], 0);

    let write_output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .arg("fmt")
        .arg(&path)
        .output()
        .expect("run formatter write");

    assert_eq!(write_output.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).expect("read fixture"), before);
}

/// Formatter write mode records a guard rejection for one file of a directory, formats the other, and reports both in one object with the findings status, so one unsafe source no longer costs the tree its formatting.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, read, written, or executed, or when the command violates the asserted result contract.
///
/// ´claim:fmt:write-mode-records-a-rejection-and-formats-the-remaining-files´
/// ´test:integration:write-mode-records-a-rejection-and-formats-the-remaining-file´
#[test]
fn write_mode_records_a_rejection_and_formats_the_remaining_file() {
    let root = tempfile::tempdir().expect("temporary directory");
    let rejected = root.path().join("00-guard-rejected.md");
    let reflowable = root.path().join("01-hard-wrapped.md");
    // Upstream now preserves escaped entities; a multiline reference still changes its ID.
    let rejected_before = "A [the\nparser].\n\n[the parser]: https://example.com\n";
    let reflowable_before = "A paragraph that is\nhard wrapped.\n";
    fs::write(&rejected, rejected_before).expect("write rejected fixture");
    fs::write(&reflowable, reflowable_before).expect("write reflowable fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .arg("fmt")
        .arg(root.path())
        .output()
        .expect("run formatter write");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        fs::read_to_string(&rejected).expect("read rejected fixture"),
        rejected_before
    );
    assert_eq!(
        fs::read_to_string(&reflowable).expect("read reflowable fixture"),
        "A paragraph that is hard wrapped.\n"
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");
    assert_eq!(report["check"], false);
    assert_eq!(report["files_scanned"], 2);
    assert_eq!(report["files_changed"], 1);
    assert_eq!(report["files_rejected"], 1);
    assert_eq!(
        report["rejected"][0]["path"],
        rejected.to_string_lossy().as_ref()
    );
    assert_eq!(report["rejected"][0]["kind"], "integrity_guard");
    assert_eq!(
        report["changed"][0]["path"],
        reflowable.to_string_lossy().as_ref()
    );
}
