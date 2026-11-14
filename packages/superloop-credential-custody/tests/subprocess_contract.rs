//! Synthetic command-boundary tests; no secret, supervisor or host key.
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const PAYLOAD: &str = r"import base64, pathlib, sys
assert sys.flags.isolated == 1
root = pathlib.Path(sys.argv[1])
width, final = map(int, sys.argv[2:])
values = {}
for name in ('alpha', 'beta'):
    offsets = []
    for length in (3, 4, 5):
        for content in ('a', 'b'):
            raw = (root / name / f'{length}-{content}.sealed').read_bytes()
            if raw.endswith(b'\n') != bool(final): raise ValueError('form')
            body = raw[:-1] if final else raw
            lines = body.split(b'\n')
            if not all(lines): raise ValueError('empty')
            if width == 0 and len(lines) != 1: raise ValueError('wrap')
            if width and (any(len(x) != width for x in lines[:-1]) or len(lines[-1]) > width): raise ValueError('wrap')
            encoded = b''.join(lines)
            decoded = base64.b64decode(encoded, validate=True)
            if base64.b64encode(decoded) != encoded: raise ValueError('padding')
            offset = len(decoded) - length
            offsets.append(offset)
            print(name, length, content, 'file-bytes', len(raw), 'wrap', width, 'final-lf', final, 'base64-chars', len(encoded), 'padding', encoded.count(b'='), 'decoded', len(decoded), 'offset', offset)
    if len(set(offsets)) != 1: raise ValueError('constant')
    values[name] = offsets[0]
    print(name, 'constant', offsets[0])
print('pair', 'same-constant-both-names', values['alpha'] == values['beta'])
";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .flat_map(|b| {
            [
                char::from(b"0123456789abcdef"[usize::from(b >> 4)]),
                char::from(b"0123456789abcdef"[usize::from(b & 15)]),
            ]
        })
        .collect()
}
fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}
fn parameter_bytes(path: &Path, bytes: &[u8]) {
    if path.exists() {
        mode(path, 0o600);
    }
    fs::write(path, bytes).unwrap();
    mode(path, 0o400);
}
fn refused(output: &Output, class: &str) {
    refuse(output);
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["message"], class);
}
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_superloop-credential-custody"))
}
fn git(root: &Path, args: &[&str]) -> Output {
    let out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
struct Fixture {
    dir: TempDir,
    record: Value,
}
impl Fixture {
    fn new() -> Self {
        Self::payload(PAYLOAD)
    }
    fn payload(payload: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("sealed")).unwrap();
        mode(&root.join("sealed"), 0o700);
        fs::create_dir(root.join("evidence")).unwrap();
        mode(&root.join("evidence"), 0o700);
        fs::create_dir(root.join("source")).unwrap();
        let repo = root.join("source");
        git(&repo, &["init", "--quiet"]);
        fs::write(
            repo.join("procedure.md"),
            format!("```sh\npython3 -I - <<'BODY'\n{payload}BODY\n```\n"),
        )
        .unwrap();
        git(&repo, &["add", "procedure.md"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "Synthetic parser",
            ],
        );
        let commit = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
        fs::write(root.join("parser.py"), payload).unwrap();
        fs::write(root.join("sealer"), b"synthetic executable identity").unwrap();
        fs::write(root.join("library"), b"synthetic library identity").unwrap();
        let file = |path: &Path| json!({"path": path, "sha256": hash(&fs::read(path).unwrap())});
        let roles = [
            "boot",
            "deployment",
            "live-applied",
            "sealer-version",
            "sealer-package",
            "library-mapping",
            "interpreter-package",
        ];
        let identity = json!({"measure":"decoded-length", "computation":"3*(N/4)-P", "form":{"wrap":0,"final_lf":true},
            "source_commit":commit,
            "files":{"sealer":file(&root.join("sealer")), "library":file(&root.join("library")),
                "interpreter":file(Path::new("/usr/bin/python3")), "parser":file(&root.join("parser.py"))},
            "probes":roles.iter().map(|role| json!({"role":role,"bytes":b"synthetic-v1\n"})).collect::<Vec<_>>()});
        let mut samples = Vec::new();
        for name in ["alpha", "beta"] {
            fs::create_dir(root.join("sealed").join(name)).unwrap();
            mode(&root.join("sealed").join(name), 0o700);
            for length in 3..=5 {
                for content in ["a", "b"] {
                    // Synthetic padded base64: known decoded sizes 3, 4 and 5.
                    let bytes = match (length, content) {
                        (3, "a") => b"QUFB\n".as_slice(),
                        (3, _) => b"QkJC\n",
                        (4, "a") => b"QUFBQQ==\n",
                        (4, _) => b"QkJCQg==\n",
                        (5, "a") => b"QUFBQUE=\n",
                        _ => b"QkJCQkI=\n",
                    };
                    let path = root
                        .join("sealed")
                        .join(name)
                        .join(format!("{length}-{content}.sealed"));
                    fs::write(&path, bytes).unwrap();
                    mode(&path, 0o400);
                    samples.push(json!({"name":name,"input_length":length,"content":content,
                        "completion":{"case":"campaign","invocation":format!("{name}-{length}-{content}"),
                            "success":true,"distinct_content":true,"sealed_sha256":hash(bytes)}}));
                }
            }
        }
        let record = json!({"schema":1,"case":"campaign","config_digest":"a".repeat(64),"code_digest":"b".repeat(64),
            "sealed_root":root.join("sealed"),"evidence_root":root.join("evidence"),
            "payload":{"path":root.join("parser.py"),"sha256":hash(payload.as_bytes()),"repository":repo,"source_commit":commit,"document":"procedure.md"},
            "limits":{"file_bytes":1_048_576,"output_bytes":1_048_576,"timeout_ms":3000},"identity":identity,
            "probes":roles.iter().map(|role| json!({"role":role,"argv":["/usr/bin/printf","synthetic-v1\n"]})).collect::<Vec<_>>(),
            "names":["alpha","beta"],"lengths":[3,4,5],"contents":["a","b"],"samples":samples,
            "comparisons":[{"id":"pair","left":"alpha","right":"beta"}]});
        Self { dir, record }
    }
    fn save(&self) {
        parameter_bytes(
            &self.dir.path().join("parameters.json"),
            &serde_json::to_vec(&self.record).unwrap(),
        );
    }
    fn command(&self, identity: bool) -> Command {
        self.save();
        let mut cmd = binary();
        cmd.arg(if identity {
            "identity-check"
        } else {
            "length-observe"
        })
        .arg("--parameters")
        .arg(self.dir.path().join("parameters.json"))
        .arg("--receipt")
        .arg(if identity {
            "comparison"
        } else {
            "calibration"
        });
        if identity {
            cmd.arg("--calibration")
                .arg(self.dir.path().join("evidence/calibration"));
        } else {
            cmd.args(["--case", "campaign"]);
        }
        cmd
    }
    fn observe(&self) -> Output {
        self.command(false).output().unwrap()
    }
    fn check(&self) -> Output {
        self.command(true).output().unwrap()
    }
    fn malformed(&mut self, bytes: &[u8]) {
        let path = self.dir.path().join("sealed/alpha/3-a.sealed");
        mode(&path, 0o600);
        fs::write(&path, bytes).unwrap();
        mode(&path, 0o400);
        self.record["samples"][0]["completion"]["sealed_sha256"] = json!(hash(bytes));
    }
}
fn pass(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(output.stdout.ends_with(b"\n"));
    serde_json::from_slice(&output.stdout).unwrap()
}
fn refuse(output: &Output) {
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["kind"], "diagnostic");
}

/// ´test:integration:known-lengths-and-identity´
#[test]
fn known_lengths_and_identity() {
    let f = Fixture::new();
    let report = pass(&f.observe());
    assert_eq!(report["evidence"]["rows"].as_array().unwrap().len(), 12);
    assert_eq!(report["evidence"]["constants"][0]["constant"], 0);
    let calibration = f.dir.path().join("evidence/calibration");
    let before = fs::read(&calibration).unwrap();
    assert_eq!(pass(&f.check())["evidence"]["matches"], true);
    assert_eq!(fs::read(calibration).unwrap(), before);
}

/// ´test:integration:record-refusals-before-effects´
#[test]
fn record_refusals_before_effects() {
    for (pointer, value) in [
        ("/schema", json!(2)),
        ("/unexpected", json!(1)),
        ("/limits/timeout_ms", json!(0)),
        ("/identity/form/unknown", json!(0)),
        ("/payload/sha256", json!("")),
        ("/identity/source_commit", json!("0".repeat(40))),
        ("/contents", json!(["a", "a"])),
        ("/names", json!(["alpha", "alpha"])),
        ("/samples", json!([])),
        ("/samples/0/completion/success", json!(false)),
        ("/samples/0/completion/distinct_content", json!(false)),
        ("/samples/0/completion/case", json!("other")),
        ("/samples/0/completion/invocation", json!("")),
        ("/probes", json!([])),
        ("/identity/probes", json!([])),
        ("/identity/files/interpreter/path", json!("/bin/false")),
    ] {
        let mut f = Fixture::new();
        if let Some(slot) = f.record.pointer_mut(pointer) {
            *slot = value;
        } else if pointer == "/unexpected" {
            f.record["unexpected"] = value;
        } else {
            f.record["identity"]["form"]["unknown"] = value;
        }
        refuse(&f.observe());
        assert_eq!(
            fs::read_dir(f.dir.path().join("evidence")).unwrap().count(),
            0
        );
    }
}

/// ´test:integration:duplicate-and-excessive-records´
#[test]
fn duplicate_and_excessive_records() {
    for content in [
        "{\"schema\":1,\"schema\":1}".to_owned(),
        " ".repeat(262_145),
    ] {
        let f = Fixture::new();
        let mut command = f.command(false);
        parameter_bytes(&f.dir.path().join("parameters.json"), content.as_bytes());
        refuse(&command.output().unwrap());
    }
    let f = Fixture::new();
    let mut command = f.command(false);
    let text = serde_json::to_string(&f.record)
        .unwrap()
        .replace("\"wrap\":0", "\"wrap\":0,\"wrap\":0");
    parameter_bytes(&f.dir.path().join("parameters.json"), text.as_bytes());
    refuse(&command.output().unwrap());
}

/// ´test:integration:malformed-sealed-files´
#[test]
fn malformed_sealed_files() {
    for bytes in [
        b"QU FB\n".as_slice(),
        b"QU\nFB\n",
        b"QUFB",
        b"QUFB\r\n",
        b"QU?B\n",
        b"QU=F\n",
        b"QR==\n",
        b"QUFB===\n",
        b"\n",
        b"QUFB\n\n",
    ] {
        let mut f = Fixture::new();
        f.malformed(bytes);
        refuse(&f.observe());
    }
}

/// ´test:integration:missing-and-uncompleted-files´
#[test]
fn missing_and_uncompleted_files() {
    let f = Fixture::new();
    fs::remove_file(f.dir.path().join("sealed/alpha/3-a.sealed")).unwrap();
    refuse(&f.observe());
    let f = Fixture::new();
    mode(&f.dir.path().join("sealed/alpha/3-a.sealed"), 0o600);
    refuse(&f.observe());
    let f = Fixture::new();
    let p = f.dir.path().join("sealed/alpha/3-a.sealed");
    fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink("3-b.sealed", p).unwrap();
    refuse(&f.observe());
}

/// ´test:integration:inconsistent-content-constant´
#[test]
fn inconsistent_content_constant() {
    let mut f = Fixture::new();
    f.malformed(b"QUFBQQ==\n");
    refuse(&f.observe());
}

/// ´test:integration:payload-and-source-digest-refusals´
#[test]
fn payload_and_source_digest_refusals() {
    let f = Fixture::new();
    fs::write(f.dir.path().join("parser.py"), "raise SystemExit(0)\n").unwrap();
    refuse(&f.observe());
    let mut f = Fixture::new();
    f.record["payload"]["document"] = json!("missing.md");
    refuse(&f.observe());
    let mut f = Fixture::new();
    f.record["payload"]["source_commit"] = json!("0".repeat(40));
    f.record["identity"]["source_commit"] = json!("0".repeat(40));
    refuse(&f.observe());
}

/// ´test:integration:payload-complete-row-contract´
#[test]
fn payload_complete_row_contract() {
    for source in [
        "pass\n".to_owned(),
        PAYLOAD.replace("print(name, 'constant', offsets[0])", "pass"),
        PAYLOAD.replace("'decoded', len(decoded)", "'decoded', len(decoded) + 1"),
        PAYLOAD.replace("'file-bytes', len(raw)", "'file-bytes', len(raw) + 1"),
        format!("{PAYLOAD}print('unexpected row')\n"),
        PAYLOAD.replace("values['alpha'] == values['beta']", "False"),
    ] {
        refuse(&Fixture::payload(&source).observe());
    }
}

/// ´test:integration:discovery-never-accepts-length´
#[test]
fn discovery_never_accepts_length() {
    let mut f = Fixture::new();
    f.malformed(b"QU\nFB\n");
    let result = pass(
        &f.command(false)
            .args(["--discover", "alpha/3-a.sealed"])
            .output()
            .unwrap(),
    );
    assert_eq!(result["evidence"]["line_count"], 2);
    assert_eq!(result["evidence"]["wrap_width"], 2);
    assert_eq!(result["evidence"]["alphabet_conformity"], true);
    assert!(result["evidence"].get("decoded").is_none());
    refuse(&f.check());
}

/// ´test:integration:receipt-exclusivity-and-modes´
#[test]
fn receipt_exclusivity_and_modes() {
    let f = Fixture::new();
    pass(&f.observe());
    let path = f.dir.path().join("evidence/calibration");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    refuse(&f.observe());
    assert_eq!(fs::read(path).unwrap(), bytes);
    let f = Fixture::new();
    fs::write(
        f.dir.path().join("evidence/.calibration.partial"),
        b"partial",
    )
    .unwrap();
    refuse(&f.observe());
    assert!(!f.dir.path().join("evidence/calibration").exists());
}

/// ´test:integration:every-identity-member-drift´
#[test]
fn every_identity_member_drift() {
    for role in 0..7 {
        let mut f = Fixture::new();
        pass(&f.observe());
        f.record["probes"][role]["argv"][1] = json!("synthetic-v2\n");
        refuse(&f.check());
    }
    for member in ["sealer", "library", "parser"] {
        let f = Fixture::new();
        pass(&f.observe());
        let path = f.record["identity"]["files"][member]["path"]
            .as_str()
            .unwrap();
        fs::write(path, b"changed").unwrap();
        refuse(&f.check());
    }
    for pointer in [
        "/identity/files/interpreter/sha256",
        "/identity/computation",
        "/identity/measure",
    ] {
        let mut f = Fixture::new();
        pass(&f.observe());
        *f.record.pointer_mut(pointer).unwrap() = json!("changed");
        refuse(&f.check());
    }
    let mut f = Fixture::new();
    pass(&f.observe());
    f.record["identity"]["form"]["final_lf"] = json!(false);
    refuse(&f.check());
}

/// ´test:integration:missing-calibration-member´
#[test]
fn missing_calibration_member() {
    let f = Fixture::new();
    pass(&f.observe());
    let path = f.dir.path().join("evidence/calibration");
    let mut calibration: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    calibration["evidence"]["identity"]["files"]
        .as_object_mut()
        .unwrap()
        .remove("interpreter");
    mode(&path, 0o600);
    fs::write(&path, serde_json::to_vec(&calibration).unwrap()).unwrap();
    mode(&path, 0o400);
    refuse(&f.check());
}

/// ´test:integration:bounded-child-failure-and-redaction´
#[test]
fn bounded_child_failure_and_redaction() {
    for source in [
        "import time\ntime.sleep(10)\n",
        "raise RuntimeError('SENSITIVE_SENTINEL')\n",
        "print('x' * 2000000)\n",
    ] {
        let mut f = Fixture::payload(source);
        f.record["limits"]["timeout_ms"] = json!(500);
        let output = f.observe();
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SENSITIVE_SENTINEL"));
        refuse(&output);
    }
}

/// ´test:integration:control-plane-output´
#[test]
fn control_plane_output() {
    for arg in ["--help", "--version", "--unknown=SENSITIVE_SENTINEL"] {
        let out = binary().arg(arg).output().unwrap();
        assert_eq!(out.stdout, [] as [u8; 0]);
        assert!(!String::from_utf8_lossy(&out.stderr).contains("SENSITIVE_SENTINEL"));
        let _record: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(
            out.status.code(),
            Some(if arg.starts_with("--unknown") { 2 } else { 0 })
        );
    }
}

/// ´test:integration:interpreter-bytes-are-compared´
#[test]
fn interpreter_bytes_are_compared() {
    let mut f = Fixture::new();
    pass(&f.observe());
    f.record["identity"]["files"]["interpreter"]["sha256"] = json!("0".repeat(64));
    let path = f.dir.path().join("evidence/calibration");
    let mut calibration: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    calibration["evidence"]["identity"] = f.record["identity"].clone();
    mode(&path, 0o600);
    fs::write(&path, serde_json::to_vec(&calibration).unwrap()).unwrap();
    mode(&path, 0o400);
    let result = f.check();
    let diagnostic: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(diagnostic["message"], "identity-drift");
    refuse(&result);
}

/// ´test:integration:terminal-refusal-before-semantics´
#[test]
fn terminal_refusal_before_semantics() {
    use std::os::fd::OwnedFd;
    use std::process::Stdio;
    let terminal = nix::pty::openpty(None, None).unwrap();
    let slave: OwnedFd = terminal.slave;
    let output = binary()
        .args([
            "length-observe",
            "--parameters",
            "/nonexistent",
            "--case",
            "campaign",
            "--receipt",
            "result",
        ])
        .stdout(Stdio::from(slave))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["kind"], "tty_refusal");
}

/// ´test:integration:output-write-failure-is-not-success´
#[test]
fn output_write_failure_is_not_success() {
    let f = Fixture::new();
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = f.command(false).stdout(full).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["message"], "output-write");
}

/// ´test:integration:wrapped-format-is-frozen´
#[test]
fn wrapped_format_is_frozen() {
    let mut f = Fixture::new();
    f.record["identity"]["form"]["wrap"] = json!(4);
    f.record["identity"]["form"]["final_lf"] = json!(false);
    for sample in f.record["samples"].as_array_mut().unwrap() {
        let path = f
            .dir
            .path()
            .join("sealed")
            .join(sample["name"].as_str().unwrap())
            .join(format!(
                "{}-{}.sealed",
                sample["input_length"],
                sample["content"].as_str().unwrap()
            ));
        let bytes = fs::read(&path).unwrap();
        let bytes = bytes[..bytes.len() - 1]
            .chunks(4)
            .collect::<Vec<_>>()
            .join(&b'\n');
        mode(&path, 0o600);
        fs::write(&path, &bytes).unwrap();
        mode(&path, 0o400);
        sample["completion"]["sealed_sha256"] = json!(hash(&bytes));
    }
    pass(&f.observe());
}

/// ´test:integration:sealed-digest-custody-and-limits´
#[test]
fn sealed_digest_custody_and_limits() {
    let mut f = Fixture::new();
    f.record["samples"][0]["completion"]["sealed_sha256"] = json!("0".repeat(64));
    let output = f.observe();
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["message"], "sealed-completion-identity");
    refuse(&output);
    let mut f = Fixture::new();
    f.record["limits"]["file_bytes"] = json!(5);
    refuse(&f.observe());
    let f = Fixture::new();
    mode(&f.dir.path().join("evidence"), 0o755);
    refuse(&f.observe());
}

/// ´test:integration:inconsistent-invocation-refuses´
#[test]
fn inconsistent_invocation_refuses() {
    let mut f = Fixture::new();
    f.record["samples"][1]["completion"]["invocation"] =
        f.record["samples"][0]["completion"]["invocation"].clone();
    let output = f.observe();
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["message"], "record-invocation-identity");
    refuse(&output);
}

/// ´test:integration:identity-file-symlinks-refuse´
#[test]
fn identity_file_symlinks_refuse() {
    let f = Fixture::new();
    pass(&f.observe());
    let path = f.dir.path().join("sealer");
    fs::rename(&path, f.dir.path().join("other-sealer")).unwrap();
    std::os::unix::fs::symlink("other-sealer", &path).unwrap();
    refuse(&f.check());
}

/// ´test:integration:complete-partial-file-is-not-calibration´
#[test]
fn complete_partial_file_is_not_calibration() {
    let f = Fixture::new();
    pass(&f.observe());
    let partial = f.dir.path().join("evidence/.calibration.partial");
    fs::rename(f.dir.path().join("evidence/calibration"), &partial).unwrap();
    let output = binary()
        .arg("identity-check")
        .arg("--parameters")
        .arg(f.dir.path().join("parameters.json"))
        .arg("--calibration")
        .arg(partial)
        .args(["--receipt", "comparison"])
        .output()
        .unwrap();
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["message"], "calibration-path");
    refuse(&output);
}

/// ´test:integration:parameter-custody-before-probes´
#[test]
fn parameter_custody_before_probes() {
    let f = Fixture::new();
    let mut command = f.command(false);
    mode(f.dir.path(), 0o777);
    refused(&command.output().unwrap(), "directory-ancestor-custody");
    mode(f.dir.path(), 0o700);
    let f = Fixture::new();
    let mut command = f.command(false);
    mode(&f.dir.path().join("parameters.json"), 0o600);
    refused(&command.output().unwrap(), "parameter-custody");
    for permissions in [0o600, 0o440, 0o444, 0o2400] {
        let mut f = Fixture::new();
        let marker = f.dir.path().join("probe-ran");
        f.record["probes"][0]["argv"] = json!(["/usr/bin/touch", marker]);
        let mut command = f.command(false);
        mode(&f.dir.path().join("parameters.json"), permissions);
        refused(&command.output().unwrap(), "parameter-custody");
        assert!(!marker.exists());
    }
    let f = Fixture::new();
    let mut command = f.command(false);
    fs::hard_link(
        f.dir.path().join("parameters.json"),
        f.dir.path().join("alias.json"),
    )
    .unwrap();
    refused(&command.output().unwrap(), "parameter-custody");
    let f = Fixture::new();
    let mut command = f.command(false);
    fs::rename(
        f.dir.path().join("parameters.json"),
        f.dir.path().join("other.json"),
    )
    .unwrap();
    std::os::unix::fs::symlink("other.json", f.dir.path().join("parameters.json")).unwrap();
    refused(&command.output().unwrap(), "path-open");
}

/// ´test:integration:sealed-directory-custody-before-probes´
#[test]
fn sealed_directory_custody_before_probes() {
    let f = Fixture::new();
    mode(&f.dir.path().join("sealed"), 0o755);
    refused(&f.observe(), "sealed-directory-custody");
    for relative in ["sealed", "sealed/alpha", "sealed/beta"] {
        let mut f = Fixture::new();
        let marker = f.dir.path().join("probe-ran");
        f.record["probes"][0]["argv"] = json!(["/usr/bin/touch", marker]);
        mode(&f.dir.path().join(relative), 0o755);
        refused(&f.observe(), "sealed-directory-custody");
        assert!(!marker.exists());
    }
    let mut f = Fixture::new();
    let ancestor = f.dir.path().join("unsafe-parent");
    fs::create_dir(&ancestor).unwrap();
    mode(&ancestor, 0o777);
    fs::rename(f.dir.path().join("sealed"), ancestor.join("sealed")).unwrap();
    f.record["sealed_root"] = json!(ancestor.join("sealed"));
    refused(&f.observe(), "directory-ancestor-custody");
    mode(&ancestor, 0o1777);
    pass(&f.observe());
    let f = Fixture::new();
    fs::rename(
        f.dir.path().join("sealed/alpha"),
        f.dir.path().join("saved-alpha"),
    )
    .unwrap();
    std::os::unix::fs::symlink("../saved-alpha", f.dir.path().join("sealed/alpha")).unwrap();
    refused(&f.observe(), "path-open");
}
